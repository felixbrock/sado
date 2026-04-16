"""Anthropic Claude Opus 4.6 — hosted via the Anthropic API."""

import anthropic

from .base import Model


class Opus46(Model):
    name = "opus-4-6"
    max_concurrency = 10

    _MODEL_ID = "claude-opus-4-6"
    _MAX_TOKENS = 256

    def __init__(self) -> None:
        self._client = anthropic.AsyncAnthropic()

    async def complete(self, system: str, user: str) -> str:
        message = await self._client.messages.create(
            model=self._MODEL_ID,
            max_tokens=self._MAX_TOKENS,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return message.content[0].text
