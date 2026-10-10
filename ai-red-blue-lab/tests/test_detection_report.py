from __future__ import annotations

import json

from analyzer.core import analyze_bytes, report_to_json
from detection.yara_x_engine import YaraXEngine


RULE = r'''
rule report_marker {
    meta:
        purpose = "test"
    strings:
        $marker = "SAFE-DETECTION-MARKER"
    condition:
        $marker
}
'''


class FailingDetectionEngine:
    def scan(self, data: bytes) -> list[object]:
        raise RuntimeError("synthetic scan failure")


def test_report_marks_detection_as_not_run_without_engine() -> None:
    report = analyze_bytes(b"ordinary benign bytes")

    assert report["schema_version"] == 3
    assert report["detections"] is None


def test_report_has_empty_detections_after_zero_match_scan() -> None:
    engine = YaraXEngine(RULE)
    report = analyze_bytes(b"ordinary benign bytes", detection_engine=engine)

    assert report["detections"] == []


def test_report_serializes_engine_matches() -> None:
    engine = YaraXEngine(RULE)
    report = analyze_bytes(b"prefix SAFE-DETECTION-MARKER suffix", detection_engine=engine)

    assert report["detections"] == [
        {
            "rule": "report_marker",
            "namespace": "default",
            "metadata": {"purpose": "test"},
        }
    ]
    assert json.loads(report_to_json(report))["detections"] == report["detections"]


def test_report_is_preserved_when_detection_scan_fails() -> None:
    report = analyze_bytes(b"ordinary benign bytes", detection_engine=FailingDetectionEngine())  # type: ignore[arg-type]

    assert report["detections"] is None
    assert report["errors"] == ["detection error (RuntimeError): synthetic scan failure"]
    assert report["sha256"]
