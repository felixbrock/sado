"""Extract the session goal from the Claude Code transcript.

The goal is the single most important piece of evidence for the judge, and
per the system design it must come from a source the *agent cannot forge*.
The transcript file on disk is that source: the hook reads the human's own
instructions directly, rather than trusting a goal field the agent populates.

We take the first substantive user turn as the mission statement and append a
short tail of recent user turns for lifecycle context. Tool-result messages
and assistant turns are skipped — an agent that can write its own transcript
messages is out of scope for v1 (the transcript is assumed append-only and
authored by the harness).
"""

from __future__ import annotations

import json
from pathlib import Path


def _message_text(entry: dict) -> str | None:
    """Pull plain user-authored text out of one transcript record."""
    if entry.get("type") != "user":
        return None
    message = entry.get("message")
    if not isinstance(message, dict) or message.get("role") != "user":
        return None
    content = message.get("content")
    if isinstance(content, str):
        return content.strip() or None
    if isinstance(content, list):
        parts = []
        for block in content:
            if not isinstance(block, dict):
                continue
            # Skip tool_result blocks — those are not human instructions.
            if block.get("type") == "text" and isinstance(block.get("text"), str):
                parts.append(block["text"])
        text = "\n".join(parts).strip()
        return text or None
    return None


def extract_goal(transcript_path: str | None, max_chars: int = 4000) -> str:
    """Best-effort mission statement from the transcript.

    Returns "" when the transcript is missing or unreadable — the caller
    treats an empty goal as "no evidence", which fails closed at the judge.
    """
    if not transcript_path:
        return ""
    path = Path(transcript_path)
    if not path.is_file():
        return ""

    user_turns: list[str] = []
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                text = _message_text(entry)
                if text:
                    user_turns.append(text)
    except OSError:
        return ""

    if not user_turns:
        return ""

    first = user_turns[0]
    recent = user_turns[-3:]
    if len(user_turns) <= 3:
        goal = "\n\n".join(user_turns)
    else:
        goal = "## Original task\n" + first + "\n\n## Recent instructions\n" + "\n---\n".join(recent)
    return goal[:max_chars]
