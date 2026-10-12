"""Regression tests for recursive loading of benign, synthetic YARA rules."""

from pathlib import Path

import pytest
import yara_x

from detection.yara_x_engine import YaraXEngine


def test_nested_rules_are_loaded_and_non_yar_files_ignored(tmp_path: Path) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    (tmp_path / "z.yar").write_text(
        'rule Should_Not_Match { condition: false }', encoding="utf-8"
    )
    (nested / "a.yar").write_text(
        'rule Nested_Match { condition: true }', encoding="utf-8"
    )
    (tmp_path / "ignored.txt").write_text(
        'rule Ignored_Text { condition: true }', encoding="utf-8"
    )

    engine = YaraXEngine.from_directory(tmp_path)
    assert [match.rule for match in engine.scan(b"safe sample")] == ["Nested_Match"]


def test_directory_compiles_once_with_sorted_files_and_newline_separators(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "b.yar").write_text(
        "rule Rule_B { condition: false }", encoding="utf-8"
    )
    (tmp_path / "a.yar").write_text(
        "rule Rule_A { condition: true }", encoding="utf-8"
    )

    sources: list[str] = []
    actual_compile = yara_x.compile

    def tracked_compile(source: str):
        sources.append(source)
        return actual_compile(source)

    monkeypatch.setattr(yara_x, "compile", tracked_compile)
    engine = YaraXEngine.from_directory(tmp_path)
    assert sources == [
        "rule Rule_A { condition: true }\n"
        "rule Rule_B { condition: false }"
    ]
    assert [match.rule for match in engine.scan(b"anything")] == ["Rule_A"]


def test_directory_with_no_yar_files_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("not a rule", encoding="utf-8")
    with pytest.raises(ValueError, match="no .yar files"):
        YaraXEngine.from_directory(tmp_path)


def test_missing_or_regular_file_directory_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(NotADirectoryError):
        YaraXEngine.from_directory(tmp_path / "missing")

    regular_file = tmp_path / "one.yar"
    regular_file.write_text("rule R { condition: true }", encoding="utf-8")
    with pytest.raises(NotADirectoryError):
        YaraXEngine.from_directory(regular_file)


def test_nested_invalid_rule_fails_during_compilation(tmp_path: Path) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    (tmp_path / "good.yar").write_text(
        "rule Good { condition: true }", encoding="utf-8"
    )
    (nested / "bad.yar").write_text(
        "rule Broken { condition: }", encoding="utf-8"
    )
    with pytest.raises(yara_x.CompileError):
        YaraXEngine.from_directory(tmp_path)


def test_duplicate_identifiers_fail_at_compile_time(tmp_path: Path) -> None:
    (tmp_path / "a.yar").write_text(
        "rule Duplicated { condition: false }", encoding="utf-8"
    )
    (tmp_path / "b.yar").write_text(
        "rule Duplicated { condition: true }", encoding="utf-8"
    )
    with pytest.raises(yara_x.CompileError):
        YaraXEngine.from_directory(tmp_path)
