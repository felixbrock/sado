"""OpenAI Chat Completions adapter — shared across GPT models."""

from openai import AsyncOpenAI

from .base import Model


class OpenAIModel(Model):
    max_concurrency = 10

    _MAX_TOKENS = 256

    def __init__(self, name: str, model_id: str) -> None:
        self.name = name
        self._model_id = model_id
        self._client = AsyncOpenAI()

    async def complete(self, system: str, user: str) -> str:
        response = await self._client.chat.completions.create(
            model=self._model_id,
            max_completion_tokens=self._MAX_TOKENS,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return response.choices[0].message.content or ""
