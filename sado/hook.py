"""Claude Code PreToolUse hook entrypoint.

Wire-up (in `.claude/settings.json`):

    {
      "hooks": {
        "PreToolUse": [
          {
            "matcher": "Bash",
            "hooks": [
              {"type": "command", "command": "python -m sado.hook"}
            ]
          }
        ]
      }
    }

Contract: Claude Code writes a JSON event to stdin and reads a JSON decision
from stdout. For PreToolUse we emit
`hookSpecificOutput.permissionDecision` ∈ {allow, deny, ask}.

sado's mandate is privileged (sudo/doas/su) Bash commands. Everything else is
outside scope and passed through untouched, so the hook adds no friction to
ordinary work. Privileged commands run the rules → judge cascade:

    rules DENY   → deny   (hard policy violation; final)
    rules ALLOW  → allow  (context-free safe; final)
    judge ALLOW  → allow
    judge DENY   → deny

Any internal failure denies (fail closed). Set SADO_ON_ERROR=ask to downgrade
internal errors to a human prompt instead of an outright deny.
"""

from __future__ import annotations

import json
import os
import sys
import traceback

from . import rules
from .engine import decide
from .transcript import extract_goal


def _emit(decision: str, reason: str) -> None:
    """Write a PreToolUse permission decision and exit 0."""
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,  # allow | deny | ask
            "permissionDecisionReason": reason,
        }
    }
    json.dump(out, sys.stdout)
    sys.stdout.write("\n")
    sys.stdout.flush()


def _passthrough() -> None:
    """Emit nothing and exit 0 — defers to normal permission flow."""
    sys.exit(0)


def run(event: dict) -> None:
    tool_name = event.get("tool_name", "")
    tool_input = event.get("tool_input") or {}

    if tool_name != "Bash":
        _passthrough()
        return

    command = (tool_input.get("command") or "").strip()
    if not command:
        _passthrough()
        return

    # Out of scope: non-privileged commands are not sado's concern.
    if not rules.is_privileged(command):
        _passthrough()
        return

    cwd = event.get("cwd") or tool_input.get("cwd") or "/"
    goal = extract_goal(event.get("transcript_path"))

    decision = decide(command=command, cwd=cwd, goal=goal)
    verdict = "allow" if decision.verdict == rules.ALLOW else "deny"
    tag = f"[sado/{decision.layer}"
    tag += f":{decision.rule}]" if decision.rule else "]"
    _emit(verdict, f"{tag} {decision.reason}")


def main() -> None:
    raw = sys.stdin.read()
    try:
        event = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        # Can't understand the event → fail closed on the tool call.
        _emit("deny", "[sado] fail-closed: unparseable hook event")
        return

    try:
        run(event)
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001
        on_error = os.environ.get("SADO_ON_ERROR", "deny").lower()
        detail = traceback.format_exc(limit=1).splitlines()[-1][:200]
        if on_error == "ask":
            _emit("ask", f"[sado] internal error, deferring to human: {detail}")
        else:
            _emit("deny", f"[sado] fail-closed on internal error: {detail}")


if __name__ == "__main__":
    main()
