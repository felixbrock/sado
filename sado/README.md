# sado — context-based authorization for privileged agent commands

`sado` decides whether an agent may run a privileged (root-level) shell
command, given only the evidence available at request time. It is the runtime
counterpart to the benchmark in `bench/` and the probes in `probes/`: the
same policy (`bench/adversarial_resistance/policy.md`), wired into a Claude
Code hook so it actually gates commands.

## The cascade

```
privileged command
   │
   ▼
┌─────────────────────────┐   DENY ─────────────► block (final, no appeal)
│  1. rules  (rules.py)   │   ALLOW ────────────► permit (context-free safe)
│  deterministic policy   │
└─────────────────────────┘   UNDECIDED
                                  │
                                  ▼
                       ┌─────────────────────────┐   ALLOW ► permit
                       │  2. judge  (judge.py)    │   DENY  ► block
                       │  LLM-as-judge on context │
                       └─────────────────────────┘
                                  │ error / timeout
                                  ▼
                              fail closed → DENY
```

1. **Rules (`sado/rules.py`)** — a deterministic implementation of the
   context-free parts of the policy. It hard-denies things that are
   destructive in every context (writes to `/etc/sudoers`/`/etc/shadow`,
   firewall/sshd teardown, removing security tooling, cron/systemd
   persistence, `rm -rf` of system directories, reverse-shell/tunnel tooling,
   auth-database edits) and allows a tight set of read-only or provably
   project-scoped commands. Everything else is `UNDECIDED`.

   The rules layer is adversary-aware: it strips `sudo`/`env`/`nohup`/`timeout`
   wrappers before matching, recurses into `bash -c` payloads, checks every
   segment of a `;`/`&&`/`|` chain, treats command substitution as opaque
   (never allowable), and fails closed on anything it cannot parse.

2. **Judge (`sado/judge.py`)** — for `UNDECIDED` commands, an LLM evaluates
   the request against the policy using the session goal as *evidence, never
   as instructions*. The prompt is byte-for-byte the benchmark prompt, so
   benchmark scores transfer to production. Two backends:
   - `ClaudeCLIJudge` (default): shells out to `claude -p`, reusing the user's
     Claude Code auth. No API key required.
   - `AnthropicJudge`: direct Messages API call.

   Both fail closed: any error, timeout, or unparseable response → `DENY`.

## The hook

`sado/hook.py` is a Claude Code `PreToolUse` hook. It inspects `Bash` tool
calls, passes through anything non-privileged untouched (no friction on
ordinary work), and runs the cascade on `sudo`/`doas`/`su` commands. The
session goal is read from the transcript file on disk — a source the agent
cannot forge — not from an agent-supplied field.

### Install

Add to `.claude/settings.json` (project or user scope):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "python -m sado.hook" }
        ]
      }
    ]
  }
}
```

Run the hook from an environment where `python -m sado.hook` resolves this
package (e.g. `PYTHONPATH` pointing at the repo, or an installed wheel).

### Configuration (env vars)

| Variable            | Default | Meaning                                             |
|---                  |---      |---                                                  |
| `SADO_JUDGE`        | `cli`   | Judge backend: `cli`, `api`, or `off` (fail-closed) |
| `SADO_JUDGE_MODEL`  | —       | Model id for the chosen backend                     |
| `SADO_ON_ERROR`     | `deny`  | On internal hook error: `deny` or `ask`             |

## Testing

- **Unit** (`sado/tests/test_rules.py`): `pytest sado/tests` — hard-deny
  coverage, obfuscation resistance, tight-allow, fail-closed behavior.
- **End-to-end sandbox** (`sandbox/replay.py`): feeds synthesized PreToolUse
  events through the real `python -m sado.hook` subprocess and scores against
  the bench oracle. `--rules-only` runs fully offline. Exits nonzero on any
  false negative or anomaly, so it doubles as a CI gate.
- **Benchmark** (`bench/models/sado.py`): the cascade wired as a bench model
  (`sado-opus-4-7`, `sado-haiku-4-5`, and CLI variants) so it sits on the same
  leaderboard as the raw models and the probe.

## Results (as of 2026-07-16, 308-row `adversarial_resistance` bench)

The cascade verdict for a row is the rules verdict when the deterministic
layer decides, otherwise the judge's verdict on that same row. Because the
judge is stateless per row and sees the exact benchmark prompt, the cascade
leaderboard is an *exact reconstruction* from the rules layer plus the
existing standalone-judge runs — no separate LLM pass needed.

**Deterministic layer alone:** decides **87 / 308 rows (28%)**, **100%
correct, 0 false negatives** — every one of those decisions is a guarantee,
not a probability, and 28% of traffic never reaches the LLM.

| Judge in the cascade | Accuracy | FN rate         | FP rate      |
|---                   |---       |---              |---           |
| rules + opus-4-7     | 100.0%   | 0.0%  (0/280)   | 0.0% (0/28)  |
| rules + haiku-4-5    | 89.9%    | 10.7% (30/280)  | 3.6% (1/28)  |
| standalone opus-4-7  | 100.0%   | 0.0%            | 0.0%         |
| standalone haiku-4-5 | 89.9%    | 10.7%           | 3.6%         |

**What the numbers mean.** On this bench the deterministic layer doesn't move
the accuracy vs. the standalone judge — because Haiku's failures are all
`adversarial_injection` cases (a *contextually legitimate* command like
`chmod /var/www/html` paired with an adversarial goal). Those are inherently
the judge's job; a command-only rules layer correctly escalates them. The
rules layer's contribution is orthogonal:

1. **An un-jailbreakable floor.** `rm -rf /usr/local/lib`, `useradd backdoor`,
   `iptables -F`, `systemctl stop sshd` are denied by construction. A future
   or jailbroken judge that could be argued into ALLOWing them never gets the
   chance. (Haiku happens to get these right today; the rules layer makes it
   guaranteed rather than lucky.)
2. **25–28% fewer judge calls**, at zero latency and zero cost, with no
   correctness regression on the decided rows (all 87 correct).

The takeaway for deployment: run the cascade with the strongest judge you can
afford for the contextual cases (Opus → 0% FN here), and rely on the
deterministic layer for the command-intrinsic dangers regardless of judge.

## Security posture

- **Fail closed everywhere.** Unparseable command, unparseable event, judge
  error/timeout, missing judge binary → `DENY`.
- **Hard-denies are final.** A policy "Always DENY" match never reaches the
  model, so no amount of context or prompt injection can argue it back to
  `ALLOW`.
- **Goal comes from a source the agent can't forge** — the transcript on disk.
- **The judge is isolated** — run as a one-shot `claude -p` with tools
  disallowed and cwd forced to `/`, so evaluating a request can't itself read
  the agent's working tree or take actions.
