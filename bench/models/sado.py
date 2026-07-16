"""Benchmark adapter for the sado rules→judge cascade.

The pipeline hands every model a rendered user message and expects raw text
back. sado's cascade needs the structured command/cwd/goal, so this adapter
parses them back out of the rendered message (the template is fixed and lives
in `bench/adversarial_resistance/prompt.py`), runs the deterministic rules,
and only calls the LLM judge for what the rules leave UNDECIDED.

The judge here is the Anthropic API backend (not the `claude -p` CLI): the
bench fans out ~300 rows concurrently and API calls thread far better than
spawning a subprocess per row. The decision logic is identical — same policy,
same prompt — so a row the rules resolve is never billed to the model, which
is the whole point of measuring the cascade rather than the raw judge.
"""

import asyncio
import re

from sado import rules
from sado.judge import AnthropicJudge, ClaudeCLIJudge, build_entry

from .base import Model

_CMD_RE = re.compile(r"## Requested command\s*\n\s*\n\s*(.+?)\n", re.DOTALL)
_CWD_RE = re.compile(r"Working directory:\s*(.+)")
_GOAL_RE = re.compile(r"<agent_task>\n(.*?)\n</agent_task>", re.DOTALL)


def _parse_user_message(user: str) -> tuple[str, str, str]:
    cmd_m = _CMD_RE.search(user)
    cwd_m = _CWD_RE.search(user)
    goal_m = _GOAL_RE.search(user)
    command = cmd_m.group(1).strip() if cmd_m else ""
    cwd = cwd_m.group(1).strip() if cwd_m else "/"
    goal = goal_m.group(1).strip() if goal_m else ""
    return command, cwd, goal


class SadoCascadeModel(Model):
    """rules → (LLM judge) cascade dressed up as a benchmark model.

    backend="api" uses the Anthropic Messages API (needs a valid key).
    backend="cli" uses `claude -p` — the exact judge the production hook runs,
    authenticated by the user's Claude Code session rather than an API key.
    """

    max_concurrency = 10

    def __init__(self, name: str, judge_model: str, backend: str = "api") -> None:
        self.name = name
        if backend == "cli":
            self._judge = ClaudeCLIJudge(model=judge_model, timeout=90.0)
            # `claude -p` cold-starts per call; fan out wide to amortize the
            # ~10 s startup across the ~230 undecided rows.
            self.max_concurrency = 14
        else:
            self._judge = AnthropicJudge(model=judge_model)

    async def complete(self, system: str, user: str) -> str:
        command, cwd, goal = _parse_user_message(user)

        decision = rules.check(command, cwd=cwd)
        if decision.verdict in (rules.ALLOW, rules.DENY):
            reason = f"[rules:{decision.rule}] {decision.reason}"
            return f'{{"verdict": "{decision.verdict}", "reason": {_json_str(reason)}}}'

        # UNDECIDED → judge. Run the sync client off the event loop.
        entry = build_entry(command=command, cwd=cwd, goal=goal)
        result = await asyncio.to_thread(self._judge.evaluate, entry)
        reason = f"[judge] {result.reason}"
        return f'{{"verdict": "{result.verdict}", "reason": {_json_str(reason)}}}'


def _json_str(s: str) -> str:
    import json

    return json.dumps(s)
