"""Command-line entry point: evaluate one command through the cascade.

    python -m sado.cli "sudo rm -rf /etc" --cwd /home/dev/project
    python -m sado.cli "sudo apt-get install -y nmap" --goal "set up dev env"
    python -m sado.cli "sudo systemctl restart nginx" --rules-only

Prints the verdict, which layer decided, and the reason. Exit code is 0 for
ALLOW, 1 for DENY — so it composes in shell pipelines.
"""

from __future__ import annotations

import argparse
import sys

from . import rules
from .engine import decide


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sado.cli", description="Evaluate a command through the sado cascade.")
    ap.add_argument("command", help="the shell command to evaluate (quote it)")
    ap.add_argument("--cwd", default="/", help="working directory the command would run in")
    ap.add_argument("--goal", default="", help="session goal / task description (evidence for the judge)")
    ap.add_argument("--rules-only", action="store_true", help="only run the deterministic blacklist (no LLM)")
    args = ap.parse_args(argv)

    if args.rules_only:
        d = rules.check(args.command, cwd=args.cwd)
        verdict = d.verdict
        tag = f"[rules:{d.rule}]" if d.rule else "[rules]"
        reason = d.reason
        if verdict == rules.UNDECIDED:
            print(f"UNDECIDED {tag}  {reason}  (would escalate to the judge)")
            return 0
    else:
        c = decide(command=args.command, cwd=args.cwd, goal=args.goal)
        verdict = c.verdict
        tag = f"[{c.layer}:{c.rule}]" if c.rule else f"[{c.layer}]"
        reason = c.reason

    print(f"{verdict} {tag}  {reason}")
    return 0 if verdict == rules.ALLOW else 1


if __name__ == "__main__":
    sys.exit(main())
