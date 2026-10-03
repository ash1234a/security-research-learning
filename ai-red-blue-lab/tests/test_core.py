from pathlib import Path

from analyzer.core import analyze_bytes, analyze_file
from pe_builder import RW_DATA, RWX


def _features(report):
    return {f["feature"] for f in report["risk_features"]}


def test_analyze_non_pe_file(tmp_path: Path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"HELLO_TEST" * 32)

    report = analyze_file(sample)

    assert report["name"] == "sample.bin"
    assert report["file_type"] == "unknown"
    assert report["pe"] is None
    assert len(report["sha256"]) == 64
    assert report["size"] == len(b"HELLO_TEST" * 32)
    assert report["risk_features"] == []


def test_report_does_not_leak_local_path(tmp_path: Path):
    sample = tmp_path / "secret-dir" / "sample.bin"
    sample.parent.mkdir()
    sample.write_bytes(b"data")

    report = analyze_file(sample)

    assert "file" not in report
    assert str(tmp_path) not in str(report)


def test_valid_pe_is_identified(pe_builder):
    report = analyze_bytes(pe_builder(), name="tiny.exe")

    assert report["file_type"] == "PE"
    assert report["errors"] == []
    assert report["pe"]["entry_point"] == 0x1000
    assert report["pe"]["image_base"] == 0x400000
    assert report["pe"]["subsystem"] == 3


def test_mz_without_valid_pe_header_is_reported_not_crashed():
    data = b"MZ" + b"\x00" * 200

    report = analyze_bytes(data, name="broken.exe")

    assert report["file_type"] == "MZ"
    assert report["pe"] is None
    assert report["errors"], "parse failure must be recorded"


def test_truncated_pe_does_not_crash(pe_builder):
    data = pe_builder()[:0x150]

    report = analyze_bytes(data, name="truncated.exe")

    assert report["file_type"] in {"PE", "MZ"}
    assert "risk_features" in report


def test_benign_pe_has_only_unsigned_finding(pe_builder):
    report = analyze_bytes(pe_builder(), name="tiny.exe")

    assert _features(report) == {"no_authenticode_blob"}


def test_writable_executable_section_is_flagged(pe_builder):
    report = analyze_bytes(pe_builder(characteristics=RWX), name="rwx.exe")

    assert "writable_executable_section" in _features(report)


def test_high_entropy_section_is_flagged(pe_builder):
    # 0~255를 균등하게 담으면 섹션 엔트로피가 정확히 8.0이 된다.
    packed_like = bytes(range(256)) * 2
    report = analyze_bytes(pe_builder(packed_like, section_name=b"UPX0", characteristics=RW_DATA), name="p.exe")

    flagged = [f for f in report["risk_features"] if f["feature"] == "high_section_entropy"]
    assert flagged
    assert "UPX0" in flagged[0]["detail"]


def test_security_relevant_imports_are_flagged(pe_builder):
    data = pe_builder(imports=("KERNEL32.dll", ["VirtualAlloc", "ExitProcess", "CreateRemoteThread"]))

    report = analyze_bytes(data, name="imports.exe")
    finding = next(f for f in report["risk_features"] if f["feature"] == "security_relevant_imports")

    assert finding["detail"] == "CreateRemoteThread, VirtualAlloc"
    assert "ExitProcess" not in finding["detail"]


def test_authenticode_blob_suppresses_unsigned_finding(pe_builder):
    report = analyze_bytes(pe_builder(with_security_blob=True), name="signed.exe")

    assert report["pe"]["has_authenticode_blob"] is True
    assert "no_authenticode_blob" not in _features(report)
