from pathlib import Path

from analyzer.core import analyze_file


def test_analyze_non_pe_file(tmp_path: Path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"HELLO_TEST" * 32)

    report = analyze_file(sample)

    assert report["name"] == "sample.bin"
    assert report["file_type"] == "unknown"
    assert report["pe"] is None
    assert len(report["sha256"]) == 64
    assert report["size"] == len(b"HELLO_TEST" * 32)
