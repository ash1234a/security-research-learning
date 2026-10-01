import json
from pathlib import Path

from analyzer.cli import EXIT_INPUT_ERROR, EXIT_OK, main


def test_cli_missing_file_returns_error_without_traceback(tmp_path: Path, capsys):
    code = main([str(tmp_path / "missing.exe")])

    captured = capsys.readouterr()
    assert code == EXIT_INPUT_ERROR
    assert "file not found" in captured.err
    assert "Traceback" not in captured.err


def test_cli_rejects_negative_string_limit(tmp_path: Path, capsys):
    sample = tmp_path / "a.bin"
    sample.write_bytes(b"data")

    assert main([str(sample), "--string-limit", "-1"]) == EXIT_INPUT_ERROR


def test_cli_prints_json(tmp_path: Path, capsys):
    sample = tmp_path / "a.bin"
    sample.write_bytes(b"HELLO_WORLD")

    assert main([str(sample)]) == EXIT_OK
    report = json.loads(capsys.readouterr().out)
    assert report["name"] == "a.bin"


def test_cli_writes_json_file(tmp_path: Path, pe_builder):
    sample = tmp_path / "tiny.exe"
    sample.write_bytes(pe_builder())
    out = tmp_path / "results" / "tiny.json"

    assert main([str(sample), "--json", str(out)]) == EXIT_OK
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["file_type"] == "PE"
