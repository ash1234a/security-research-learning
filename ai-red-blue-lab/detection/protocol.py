from __future__ import annotations

from typing import Protocol

from .yara_x_engine import RuleMatch


class DetectionEngine(Protocol):
    """Common interface for static detection engines."""

    def scan(self, data: bytes) -> list[RuleMatch]:
        """Scan bytes without executing them and return normalized matches."""
        ...
