from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pefile

from detection.protocol import DetectionEngine

from .entropy import shannon_entropy
from .pe_parser import parse_pe
from .strings import extract_strings

SCHEMA_VERSION = 3

# 압축·암호화된 데이터는 대체로 7.2 bits/byte 이상으로 나타난다.
# 정상 파일의 리소스(이미지 등)도 이 값을 넘을 수 있으므로 휴리스틱으로만 사용한다.
HIGH_ENTROPY_THRESHOLD = 7.2

SUSPICIOUS_IMPORTS = {
    "VirtualAlloc",
    "VirtualProtect",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "OpenProcess",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "CreateProcessA",
    "CreateProcessW",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _flatten_imports(pe_info: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    for entry in pe_info.get("imports", []):
        values.update(entry.get("functions", []))
    return values


def _risk_features(report: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    entropy = report["entropy"]
    if entropy >= HIGH_ENTROPY_THRESHOLD:
        findings.append({"severity": "medium", "feature": "high_file_entropy", "detail": f"entropy={entropy:.4f}"})

    pe_info = report.get("pe")
    if not pe_info:
        return findings

    for section in pe_info.get("sections", []):
        if section["entropy"] >= HIGH_ENTROPY_THRESHOLD:
            findings.append(
                {
                    "severity": "medium",
                    "feature": "high_section_entropy",
                    "detail": f"{section['name']} entropy={section['entropy']}",
                }
            )
        if section["executable"] and section["writable"]:
            findings.append(
                {
                    "severity": "medium",
                    "feature": "writable_executable_section",
                    "detail": section["name"],
                }
            )

    suspicious = sorted(_flatten_imports(pe_info) & SUSPICIOUS_IMPORTS)
    if suspicious:
        findings.append(
            {
                "severity": "info",
                "feature": "security_relevant_imports",
                "detail": ", ".join(suspicious),
            }
        )

    if not pe_info.get("has_authenticode_blob", False):
        findings.append({"severity": "info", "feature": "no_authenticode_blob", "detail": "No PE security directory present"})

    return findings


def analyze_bytes(
    data: bytes,
    name: str = "<memory>",
    string_limit: int = 200,
    detection_engine: DetectionEngine | None = None,
) -> dict[str, Any]:
    """Analyze raw bytes. The data is never executed.

    When a detection engine is supplied, rule matches are serialized into the
    report. ``detections`` is None when detection was not run or failed and a
    list when it completed, so downstream evaluation cannot mistake a skipped
    or failed scan for a true negative.
    """
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "name": name,
        "size": len(data),
        "sha256": _sha256(data),
        "entropy": round(shannon_entropy(data), 4),
        "file_type": "unknown",
        "strings": extract_strings(data, limit_each=string_limit),
        "pe": None,
        "errors": [],
        "detections": None,
    }

    if data.startswith(b"MZ"):
        # MZ 시그니처만으로는 유효한 PE라고 볼 수 없으므로 파싱에 성공했을 때만 "PE"로 표시한다.
        report["file_type"] = "MZ"
        try:
            report["pe"] = parse_pe(data)
            report["file_type"] = "PE"
        except pefile.PEFormatError as exc:
            report["errors"].append(f"PE parse error: {exc}")
        except Exception as exc:  # noqa: BLE001 — 손상·변조된 입력에서도 보고서는 끝까지 생성한다.
            report["errors"].append(f"PE parse error ({type(exc).__name__}): {exc}")

    report["risk_features"] = _risk_features(report)
    if detection_engine is not None:
        try:
            report["detections"] = [match.to_dict() for match in detection_engine.scan(data)]
        except Exception as exc:  # noqa: BLE001 — 한 샘플의 탐지 실패가 평가 배치를 중단시키지 않는다.
            report["errors"].append(f"detection error ({type(exc).__name__}): {exc}")
    return report


def analyze_file(
    path: str | Path,
    string_limit: int = 200,
    detection_engine: DetectionEngine | None = None,
) -> dict[str, Any]:
    """Analyze a file on disk without executing it.

    보고서에는 파일 이름만 기록하고 로컬 절대 경로는 남기지 않는다.
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(file_path)

    return analyze_bytes(
        file_path.read_bytes(),
        name=file_path.name,
        string_limit=string_limit,
        detection_engine=detection_engine,
    )


def report_to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2)
