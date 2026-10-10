"""Detection engines for AI Red vs Blue Lab.

``RuleMatch`` and ``DetectionEngine`` are engine-independent and importable
without any scanning backend installed. Concrete engines such as
``YaraXEngine`` are loaded lazily so that ``import detection`` (and therefore
``analyzer.core``) does not require ``yara_x``.
"""

from __future__ import annotations

from typing import Any

from .protocol import DetectionEngine
from .types import RuleMatch

__all__ = ["DetectionEngine", "RuleMatch", "YaraXEngine"]


def __getattr__(name: str) -> Any:
    if name == "YaraXEngine":
        from .yara_x_engine import YaraXEngine

        return YaraXEngine
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
