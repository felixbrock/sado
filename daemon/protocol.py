import dataclasses
import json
from typing import Any


@dataclasses.dataclass
class Request:
    command: str
    args: list[str]
    cwd: str
    session_id: str        # identifies the agent session; used for per-session history
    agent_log: str         # formatted recent tool calls from the session log
    transcript_path: str   # absolute path to the Claude Code session JSONL transcript
    goal: str = ""         # optional: SADO_GOAL env var — high-level task description

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self))

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Request":
        return cls(
            command=d["command"],
            args=d["args"],
            cwd=d["cwd"],
            session_id=d["session_id"],
            agent_log=d.get("agent_log", ""),
            transcript_path=d.get("transcript_path", ""),
            goal=d.get("goal", ""),
        )


@dataclasses.dataclass
class Response:
    verdict: str          # "ALLOW" or "DENY"
    reason: str
    stdout: str
    stderr: str
    exit_code: int

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self))

    @classmethod
    def deny(cls, reason: str) -> "Response":
        return cls(verdict="DENY", reason=reason, stdout="", stderr="", exit_code=1)
