from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pefile

from .entropy import shannon_entropy
from .pe_parser import parse_pe
from .strings import extract_strings

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
    if entropy >= 7.2:
        findings.append({"severity": "medium", "feature": "high_file_entropy", "detail": f"entropy={entropy:.4f}"})

    pe_info = report.get("pe")
    if not pe_info:
        return findings

    for section in pe_info.get("sections", []):
        if section["entropy"] >= 7.2:
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


def analyze_file(path: str | Path, string_limit: int = 200) -> dict[str, Any]:
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(file_path)

    data = file_path.read_bytes()
    report: dict[str, Any] = {
        "schema_version": 1,
        "file": str(file_path),
        "name": file_path.name,
        "size": len(data),
        "sha256": _sha256(data),
        "entropy": round(shannon_entropy(data), 4),
        "file_type": "PE" if data.startswith(b"MZ") else "unknown",
        "strings": extract_strings(data, limit_each=string_limit),
        "pe": None,
        "errors": [],
    }

    if report["file_type"] == "PE":
        try:
            report["pe"] = parse_pe(str(file_path))
        except pefile.PEFormatError as exc:
            report["errors"].append(f"PE parse error: {exc}")

    report["risk_features"] = _risk_features(report)
    return report


def report_to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2)
