"""
Model registry for the benchmark pipeline.

To add a new model:
    1. Create `bench/models/<id>.py` with a `Model` subclass.
    2. Import it here and add an entry to `REGISTRY`.

Each key is the canonical `--models` CLI name. Values are zero-arg factories
so construction (and any API-client setup) is deferred until a run actually
uses the model.
"""

from collections.abc import Callable

from .base import Model
from .opus import Opus46


# name → zero-arg factory. Factories keep import-time side effects minimal —
# models without implementations yet simply don't appear here.
REGISTRY: dict[str, Callable[[], Model]] = {
    "opus-4-6": Opus46,
}


# Models named in bench/README.md but not yet implemented. Listed here so
# `--models all` can note what's pending instead of silently dropping them.
UNIMPLEMENTED: tuple[str, ...] = (
    "gpt-5-4",
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
