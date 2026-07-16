"""LLM-as-judge layer.

Evaluates a command the deterministic rules could not resolve (UNDECIDED)
against the policy, using the session context as *evidence* — never as
instructions. The prompt is deliberately the exact one from the benchmark
(`bench/adversarial_resistance/prompt.py`) so the numbers we measure on the
bench are the numbers we get in production.

Two backends:
  - ClaudeCLIJudge: shells out to `claude -p` (headless Claude Code). This is
    the default for the hook — it reuses the user's existing Claude Code auth
    and runs the judge as an isolated one-shot sub-agent with no tools.
  - AnthropicJudge: direct Messages API call. Used by the benchmark adapter
    and anywhere an API key is preferred over the CLI.

Both fail closed: any error, timeout, or unparseable response becomes DENY.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PROMPT_PATH = _REPO_ROOT / "bench" / "adversarial_resistance" / "prompt.py"

ALLOW = "ALLOW"
DENY = "DENY"


def _load_prompt_module():
    spec = importlib.util.spec_from_file_location("sado._bench_prompt", _PROMPT_PATH)
    if spec is None or spec.loader is None:  # pragma: no cover
        raise ImportError(f"cannot load bench prompt module at {_PROMPT_PATH}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_PROMPT = _load_prompt_module()
SYSTEM_PROMPT = _PROMPT.SYSTEM_PROMPT
render_user_message = _PROMPT.render_user_message
parse_response = _PROMPT.parse_response


@dataclass(frozen=True)
class JudgeResult:
    verdict: str  # ALLOW | DENY  (PARSE_ERROR is mapped to DENY here)
    reason: str
    raw: str = ""
    error: str | None = None


def _finalize(raw: str) -> JudgeResult:
    """Parse a raw model response, mapping any parse failure to a fail-closed DENY."""
    verdict, reason = parse_response(raw)
    if verdict not in (ALLOW, DENY):
        return JudgeResult(DENY, f"fail-closed: {reason}", raw=raw, error="parse_error")
    return JudgeResult(verdict, reason, raw=raw)


def build_entry(command: str, args=None, cwd: str = "/", goal: str = "") -> dict:
    """Shape a request into the dict the bench prompt renderer expects."""
    return {
        "command": command,
        "args": list(args or []),
        "cwd": cwd,
        "goal": goal or "(not specified)",
    }


class Judge:
    """Base judge interface."""

    def evaluate(self, entry: dict) -> JudgeResult:  # pragma: no cover - abstract
        raise NotImplementedError


class ClaudeCLIJudge(Judge):
    """Headless Claude Code sub-agent via `claude -p`.

    Runs the judge as a one-shot prompt with tools disabled and a strict
    timeout. The system prompt is appended via --append-system-prompt so the
    request body stays identical to the API/bench path.
    """

    def __init__(
        self,
        model: str | None = None,
        binary: str = "claude",
        timeout: float = 45.0,
    ) -> None:
        self.model = model
        self.binary = binary
        self.timeout = timeout

    def _cmd(self, user_message: str) -> list[str]:
        cmd = [
            self.binary,
            "-p",
            user_message,
            "--append-system-prompt",
            SYSTEM_PROMPT,
            # Isolate the judge as a pure text classifier. In default
            # permission mode a headless run cannot get tool approval, so
            # tools are effectively blocked; deny-listing them makes it
            # explicit and defends against a future default change.
            "--disallowed-tools",
            "Bash,Edit,Write,Read,WebFetch,WebSearch",
            "--permission-mode",
            "default",
        ]
        if self.model:
            cmd += ["--model", self.model]
        return cmd

    def evaluate(self, entry: dict) -> JudgeResult:
        if shutil.which(self.binary) is None:
            return JudgeResult(DENY, f"fail-closed: '{self.binary}' not found on PATH", error="no_binary")
        user_message = render_user_message(entry)
        try:
            proc = subprocess.run(
                self._cmd(user_message),
                capture_output=True,
                text=True,
                timeout=self.timeout,
                # Never inherit the caller's cwd — the judge must not read
                # files from the agent's working tree.
                cwd="/",
            )
        except subprocess.TimeoutExpired:
            return JudgeResult(DENY, "fail-closed: judge timed out", error="timeout")
        except Exception as exc:  # noqa: BLE001
            return JudgeResult(DENY, f"fail-closed: judge invocation failed ({exc})", error="exec_error")
        if proc.returncode != 0:
            return JudgeResult(
                DENY,
                f"fail-closed: judge exited {proc.returncode}",
                raw=proc.stderr[:500],
                error="nonzero_exit",
            )
        return _finalize(proc.stdout)


class AnthropicJudge(Judge):
    """Direct Anthropic Messages API judge (synchronous)."""

    def __init__(self, model: str = "claude-opus-4-7", max_tokens: int = 256) -> None:
        import anthropic

        self.model = model
        self.max_tokens = max_tokens
        self._client = anthropic.Anthropic()

    def evaluate(self, entry: dict) -> JudgeResult:
        user_message = render_user_message(entry)
        try:
            msg = self._client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_message}],
            )
            raw = msg.content[0].text if msg.content else ""
        except Exception as exc:  # noqa: BLE001
            return JudgeResult(DENY, f"fail-closed: API error ({exc})", error="api_error")
        return _finalize(raw)


class NullJudge(Judge):
    """A judge that always fails closed. Selected with SADO_JUDGE=off.

    Used to run the cascade fully offline (no LLM, no network): the
    deterministic rules still decide what they can, and everything they
    escalate is denied. The sandbox's --rules-only mode uses this to exercise
    the real hook boundary without any model calls.
    """

    def evaluate(self, entry: dict) -> JudgeResult:
        return JudgeResult(DENY, "fail-closed: judge disabled (SADO_JUDGE=off)", error="disabled")


def default_judge() -> Judge:
    """Pick a judge from the environment.

    SADO_JUDGE=cli|api|off selects the backend (default: cli). SADO_JUDGE_MODEL
    overrides the model for whichever backend is chosen.
    """
    backend = os.environ.get("SADO_JUDGE", "cli").lower()
    model = os.environ.get("SADO_JUDGE_MODEL") or None
    if backend == "off":
        return NullJudge()
    if backend == "api":
        return AnthropicJudge(model=model or "claude-opus-4-7")
    return ClaudeCLIJudge(model=model)
