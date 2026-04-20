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
        # Prompt caching: the system prompt is always stable across calls,
        # and for the adversarial-resistance benchmark the first ~3 KB of
        # every user message is the identical policy. Mark both as ephemeral
        # cache breakpoints so multi-row runs pay 10% after the first call.
        # The split key "## Requested command" is tied to
        # bench/adversarial_resistance/prompt.py's USER_TEMPLATE; for
        # benchmarks that don't use that marker the user content falls back
        # to a single uncached block.
        system_blocks = [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]
        split_key = "## Requested command"
        if split_key in user:
            idx = user.index(split_key)
            user_blocks = [
                {"type": "text", "text": user[:idx], "cache_control": {"type": "ephemeral"}},
                {"type": "text", "text": user[idx:]},
            ]
        else:
            user_blocks = [{"type": "text", "text": user}]

        message = await self._client.messages.create(
            model=self._model_id,
            max_tokens=self._MAX_TOKENS,
            system=system_blocks,
            messages=[{"role": "user", "content": user_blocks}],
        )
        return message.content[0].text
