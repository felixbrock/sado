"""Anthropic Messages API adapter — shared across Claude models."""

import anthropic

from .base import Model


class AnthropicModel(Model):
    max_concurrency = 10

    _MAX_TOKENS = 256

    def __init__(self, name: str, model_id: str) -> None:
        self.name = name
        self._model_id = model_id
        self._client = anthropic.AsyncAnthropic()

    async def complete(self, system: str, user: str) -> str:
        message = await self._client.messages.create(
            model=self._model_id,
            max_tokens=self._MAX_TOKENS,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return message.content[0].text
