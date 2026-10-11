from __future__ import annotations

from typing import Protocol

from .types import RuleMatch


class DetectionEngine(Protocol):
    """An engine-independent static scanning boundary."""

    def scan(self, data: bytes) -> list[RuleMatch]:
        """Return normalized matches without executing the input."""
        ...
