from __future__ import annotations

from pathlib import Path

from analyzer.core import analyze_bytes, analyze_file
from detection.yara_x_engine import RuleMatch


class SyntheticEngine:
    """A minimal alternate engine for verifying the public scan boundary."""

    def scan(self, data: bytes) -> list[RuleMatch]:
        if b"SAFE-PROTOCOL-MARKER" not in data:
            return []
        return [
            RuleMatch(
                rule="synthetic_marker",
                namespace="unit_tests",
                metadata={"source": "synthetic"},
            )
        ]


def test_analyze_bytes_accepts_an_alternate_detection_engine() -> None:
    engine = SyntheticEngine()
    report = analyze_bytes(b"SAFE-PROTOCOL-MARKER", detection_engine=engine)

    assert report["detections"] == [
        {
            "rule": "synthetic_marker",
            "namespace": "unit_tests",
            "metadata": {"source": "synthetic"},
        }
    ]
    assert report["errors"] == []


def test_alternate_detection_engine_reports_zero_matches() -> None:
    report = analyze_bytes(b"ordinary benign bytes", detection_engine=SyntheticEngine())

    assert report["detections"] == []


def test_analyze_file_accepts_an_alternate_detection_engine(tmp_path: Path) -> None:
    sample = tmp_path / "benign-synthetic.bin"
    sample.write_bytes(b"SAFE-PROTOCOL-MARKER")

    report = analyze_file(sample, detection_engine=SyntheticEngine())

    assert report["name"] == sample.name
    assert report["detections"][0]["rule"] == "synthetic_marker"
