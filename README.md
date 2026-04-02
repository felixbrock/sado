# sado

**Super Agent Do** — a privilege broker for AI agents. Unprivileged Claude Code agents submit privileged command requests to sado over a Unix socket. Sado evaluates each request against a policy file and the agent's full session context using an LLM judge, then either executes the command as root and returns the output, or denies it with a reason.

The agent never receives elevated privileges. It only ever receives the output of commands sado chose to run on its behalf.

---

## Features

- **Context-aware decisions.** The judge sees the full picture: the agent's conversation transcript, its reasoning steps, prior tool calls, and any sado decisions already made in the session. A command that would be suspicious in isolation can be correctly approved when the session context makes it coherent.
- **Natural-language policy.** Write allow/deny rules in plain Markdown. No DSL, no regex. The LLM interprets intent.
- **Zero per-agent configuration.** Session identity and transcript path are derived automatically from `CLAUDE_SESSION_ID`, which Claude Code sets in every tool invocation. Any number of agents running in parallel are isolated from each other without coordination.
- **Unix-native transport.** Communication happens over a Unix domain socket (`/run/sado/judge.sock`). No HTTP, no open ports. Access is enforced by standard file permissions — only members of the `sado` group can connect.
- **Fail closed.** Any error in the judge, executor, or daemon returns DENY. The agent never gets through on a malfunction.
- **Hot-reloadable policy.** Edit `policy.md` and the daemon picks up changes on the next request. No restart needed.
- **Systemd-native.** Ships with socket and service units. The socket exists at boot; the daemon starts on first use via socket activation.

---

## Sado vs sudo

|                       | sudo                                                         | sado                                                                          |
| --------------------- | ------------------------------------------------------------ | ----------------------------------------------------------------------------- |
| **Decision basis**    | Static rules (`/etc/sudoers`)                                | LLM judge + natural-language policy + full session context                    |
| **Context awareness** | None                                                         | Sees conversation transcript, prior tool calls, session goal                  |
| **Designed for**      | Human operators                                              | AI agents                                                                     |
| **Privilege model**   | Executes the command as root; requester receives output only | Same — executes the command as root; requester receives output only           |
| **Policy language**   | sudoers syntax                                               | Plain Markdown                                                                |
| **Transport**         | setuid binary, PAM                                           | Unix domain socket                                                            |
| **Ambiguous cases**   | Denied unless explicitly allowed                             | Judged against intent — a coherent session can unlock context-dependent rules |

The core difference: sudo asks _"is this user allowed to run this command?"_ Sado asks _"given everything happening in this session, should this command run right now?"_

---

## Architecture

```
┌──────────────────────────────────────┐
│  Claude Code agent (unprivileged)    │
│                                      │
│  sado systemctl restart nginx        │
└───────────────┬──────────────────────┘
                │ Unix socket  /run/sado/judge.sock
                │ JSON request: command, session ID,
                │   transcript path, tool log, goal
                ▼
┌──────────────────────────────────────┐
│  sado daemon  (root)                 │
│                                      │
│  1. Read session transcript          │
│  2. Load policy (cached)             │
│  3. Call LLM judge                   │
│       policy + transcript +          │
│       tool log + prior decisions     │
│       → ALLOW / DENY + reason        │
│  4. Execute or reject                │
└───────────────┬──────────────────────┘
                │ JSON response: verdict, reason,
                │   stdout, stderr, exit_code
                ▼
┌──────────────────────────────────────┐
│  Agent receives output               │
│  (never elevated privileges)         │
└──────────────────────────────────────┘
```

The daemon maintains per-session decision history in memory, so the judge can reason about what it has already approved or denied earlier in the same session.

---

## Quick start

**1. Install**

```bash
cd /path/to/sado
sudo cp -r . /usr/local/lib/sado
sudo python3 -m venv /usr/local/lib/sado/venv
sudo /usr/local/lib/sado/venv/bin/pip install -r /usr/local/lib/sado/daemon/requirements.txt
sudo install -m 755 client/sado /usr/local/bin/sado
```

**2. Create the `sado` system group and add agent users**

```bash
sudo groupadd --system sado
sudo usermod -aG sado <agent-username>  # the OS user that runs the agent (e.g. your own username, or a dedicated agent account)
```

> **Note:** Group membership changes take effect on the next login. To apply immediately without logging out, run `newgrp sado` in your current shell.

**3. Configure the daemon**

```bash
sudo mkdir -p /etc/sado
sudo tee /etc/sado/env <<'EOF'
SADO_POLICY=/usr/local/lib/sado/policy.md
ANTHROPIC_API_KEY=sk-ant-...
EOF
sudo chmod 600 /etc/sado/env
```

Edit `/usr/local/lib/sado/policy.md` to define your allow/deny rules.

**4. Start the daemon**

```bash
sudo cp systemd/sado.socket systemd/sado.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sado.socket
```

**5. Add the session logging hook**

In the agent's `.claude/settings.json`, add a PostToolUse hook to write per-session tool call logs that sado uses as context:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "python3 -c \"\nimport json, os, sys\npayload = json.load(sys.stdin)\nsession_id = os.environ.get('CLAUDE_SESSION_ID', 'unknown')\nlog_dir = '/tmp/sado-sessions'\nos.makedirs(log_dir, exist_ok=True)\nentry = json.dumps({'type': 'tool', 'tool': payload.get('tool_name',''), 'input': str(payload.get('tool_input','')), 'exit_code': payload.get('tool_response',{}).get('exit_code'), 'output': str(payload.get('tool_response',{}).get('output',''))[:500]})\nopen(f'{log_dir}/{session_id}.jsonl', 'a').write(entry + '\\n')\n\""
          }
        ]
      }
    ]
  }
}
```

**6. Set the socket path**

Add to `/etc/environment`:

```bash
echo 'SADO_SOCKET=/run/sado/judge.sock' | sudo tee -a /etc/environment
```

Or, for the agent user's shell profile only:

```bash
echo 'export SADO_SOCKET=/run/sado/judge.sock' >> ~/.bashrc
```

That's it. Agents call `sado <command> [args...]` wherever they would otherwise need `sudo`. Session identity, transcript path, and tool history are all resolved automatically from `CLAUDE_SESSION_ID`.

---

## Policy

`policy.md` has three sections:

- **Always DENY** — hard rules the judge cannot override, regardless of context (e.g. disabling firewalls, modifying `/etc/sudoers`)
- **Always ALLOW** — low-risk operations that never need justification (e.g. `systemctl status`, read-only queries)
- **Judge with context** — the LLM weighs the session goal and history against the risk (e.g. `apt install`, service restarts, network changes)

The file is watched by mtime. Save it and the next request picks up the new rules.
