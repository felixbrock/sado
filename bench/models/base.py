"""
Abstract model interface for the benchmark pipeline.

Each concrete model adapter (per provider or per local runtime) subclasses
`Model` and implements `complete()`. The pipeline depends only on this
interface and treats every model identically.
"""

from abc import ABC, abstractmethod


class Model(ABC):
    """One chat-completion backend (hosted API, local server, etc.).

    Subclasses set the class-level fields `name` and optionally
    `max_concurrency`, and implement `complete()`.
    """

    name: str = "unnamed"
    # Per-model concurrency ceiling. The pipeline uses this to size its
    # semaphore so rate-limited backends don't get hammered.
    max_concurrency: int = 5

    @abstractmethod
    async def complete(self, system: str, user: str) -> str:
        """Return the raw text completion for a single (system, user) turn.

        Implementations should return the assistant's text only — no
        JSON/regex parsing. Parsing is the benchmark's responsibility.
        """
        raise NotImplementedError
