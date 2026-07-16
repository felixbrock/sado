"""sado — context-based authorization for privileged agent commands.

Decision cascade:
  1. `sado.rules`  — deterministic layer. Hard-denies commands that are
     destructive in every context (policy.md "Always DENY"), allows a tight
     set of context-free read-only commands, and marks everything else
     UNDECIDED.
  2. `sado.judge`  — probabilistic layer. An LLM evaluates UNDECIDED
     commands against the policy using session context as evidence.
  3. `sado.hook`   — Claude Code PreToolUse hook that wires the cascade
     into the agent's permission flow.
"""

__version__ = "0.1.0"
