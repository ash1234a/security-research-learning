from __future__ import annotations

from pathlib import Path

import yara_x

from .types import RuleMatch

__all__ = ["RuleMatch", "YaraXEngine", "validate_rule_source"]


class YaraXEngine:
    """Compile YARA-X source once and scan in-memory bytes without execution."""

    def __init__(self, source: str) -> None:
        self._rules = yara_x.compile(source)

    @classmethod
    def from_file(cls, path: str | Path) -> "YaraXEngine":
        return cls(Path(path).read_text(encoding="utf-8"))

    @classmethod
    def from_directory(cls, directory: str | Path) -> "YaraXEngine":
        """Load and compile all .yar rules recursively in stable path order.

        All files are compiled together, so invalid rules and duplicate rule
        identifiers fail at construction time rather than during scanning.
        """
        root = Path(directory)
        if not root.is_dir():
            raise NotADirectoryError(f"YARA rule directory does not exist: {root}")

        paths = sorted(path for path in root.rglob("*.yar") if path.is_file())
        if not paths:
            raise ValueError(f"YARA rule directory contains no .yar files: {root}")

        # Separate declarations even when a source file has no trailing newline.
        source = "\n".join(path.read_text(encoding="utf-8") for path in paths)
        return cls(source)

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
