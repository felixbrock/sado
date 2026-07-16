"""Decision cascade: deterministic rules first, LLM judge on the remainder.

This is the single entry point the hook and the benchmark both call. It keeps
the two layers' contract explicit:

  - The rules layer can ALLOW or DENY unilaterally. Those verdicts are final
    and never reach the model — a hard-deny cannot be argued out of, and a
    context-free allow doesn't waste a judge call.
  - Only UNDECIDED commands consult the judge. The judge sees the same policy
    and treats the goal as untrusted evidence.
  - Non-privileged commands are outside sado's mandate and pass through as
    ALLOW without evaluation (the hook decides what counts as in-scope).
"""

from __future__ import annotations

from dataclasses import dataclass

from . import rules
from .judge import DENY, Judge, JudgeResult, build_entry, default_judge


@dataclass(frozen=True)
class CascadeDecision:
    verdict: str  # ALLOW | DENY
    layer: str  # "rules" | "judge"
    rule: str | None
    reason: str


def decide(
    command: str,
    cwd: str = "/",
    goal: str = "",
    judge: Judge | None = None,
) -> CascadeDecision:
    """Run the full cascade for a single privileged command string."""
    rule_decision = rules.check(command, cwd=cwd)
    if rule_decision.verdict == rules.DENY:
        return CascadeDecision(rules.DENY, "rules", rule_decision.rule, rule_decision.reason)
    if rule_decision.verdict == rules.ALLOW:
        return CascadeDecision(rules.ALLOW, "rules", rule_decision.rule, rule_decision.reason)

    judge = judge or default_judge()
    entry = build_entry(command=command, cwd=cwd, goal=goal)
    result: JudgeResult = judge.evaluate(entry)
    return CascadeDecision(result.verdict, "judge", None, result.reason)


def decide_entry(entry: dict, judge: Judge | None = None) -> CascadeDecision:
    """Cascade for a benchmark-style entry (command + args + cwd + goal).

    Reconstructs the full command string (command + args) so the rules layer
    sees exactly what would run, then falls through to the judge with the
    structured entry.
    """
    command = " ".join([entry["command"], *[str(a) for a in entry.get("args", [])]])
    cwd = entry.get("cwd", "/")
    goal = entry.get("goal", "")

    rule_decision = rules.check(command, cwd=cwd)
    if rule_decision.verdict == rules.DENY:
        return CascadeDecision(rules.DENY, "rules", rule_decision.rule, rule_decision.reason)
    if rule_decision.verdict == rules.ALLOW:
        return CascadeDecision(rules.ALLOW, "rules", rule_decision.rule, rule_decision.reason)

    judge = judge or default_judge()
    result = judge.evaluate(
        build_entry(
            command=entry["command"],
            args=entry.get("args", []),
            cwd=cwd,
            goal=goal,
        )
    )
    return CascadeDecision(result.verdict, "judge", None, result.reason)
