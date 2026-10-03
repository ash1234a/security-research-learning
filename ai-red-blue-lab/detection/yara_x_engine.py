from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yara_x


@dataclass(frozen=True)
class RuleMatch:
    """Engine-independent representation of one matching detection rule."""

    rule: str
    namespace: str
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class YaraXEngine:
    """Compile YARA-X source once and scan in-memory bytes without execution."""

    def __init__(self, source: str) -> None:
        self._rules = yara_x.compile(source)

    @classmethod
    def from_file(cls, path: str | Path) -> "YaraXEngine":
        return cls(Path(path).read_text(encoding="utf-8"))

    def scan(self, data: bytes) -> list[RuleMatch]:
        results = self._rules.scan(data)
        matches: list[RuleMatch] = []
        for rule in results.matching_rules:
            matches.append(
                RuleMatch(
                    rule=rule.identifier,
                    namespace=rule.namespace,
                    metadata={key: value for key, value in rule.metadata},
                )
            )
        return matches


def validate_rule_source(source: str) -> None:
    """Raise yara_x.CompileError when rule source is invalid."""

    yara_x.compile(source)
