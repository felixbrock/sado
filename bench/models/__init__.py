"""
Model registry for the benchmark pipeline.

Each entry in `REGISTRY` maps a canonical `--models` CLI name to a zero-arg
factory that returns a ready-to-use `Model`. Provider classes
(`AnthropicModel`, `OpenAIModel`) are parameterized by model id, so adding a
new model from an existing provider is one line here.
"""

from collections.abc import Callable

from .anthropic import AnthropicModel
from .base import Model
from .openai import OpenAIModel


# name → zero-arg factory. Factories keep import-time side effects minimal —
# models without implementations yet simply don't appear here.
REGISTRY: dict[str, Callable[[], Model]] = {
    "claude-opus-4-6": lambda: AnthropicModel("claude-opus-4-6", "claude-opus-4-6"),
    "claude-haiku-4-5": lambda: AnthropicModel("claude-haiku-4-5", "claude-haiku-4-5"),
    "gpt-5-4": lambda: OpenAIModel("gpt-5-4", "gpt-5.4"),
}


# Models named in bench/README.md but not yet implemented. Listed here so
# `--models all` can note what's pending instead of silently dropping them.
UNIMPLEMENTED: tuple[str, ...] = (
    "qwen-3-5",
    "gemma-4",
    "glm-5",
    "minimax-m2-5",
    "deepseek-v3-2",
    "gpt-oss-20b",
)


def load(name: str) -> Model:
    if name not in REGISTRY:
        available = ", ".join(sorted(REGISTRY)) or "(none)"
        pending = ", ".join(UNIMPLEMENTED)
        raise KeyError(
            f"Model '{name}' has no adapter. Implemented: {available}. "
            f"Pending: {pending}."
        )
    return REGISTRY[name]()


__all__ = ["Model", "REGISTRY", "UNIMPLEMENTED", "load"]
