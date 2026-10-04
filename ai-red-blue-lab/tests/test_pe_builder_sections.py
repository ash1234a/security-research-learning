"""다중 섹션 PE fixture 검증.

섹션이 여러 개일 때 분석기가 위험 특징을 *해당 섹션에만* 붙이는지 확인한다.
평가기가 특징 단위로 TP/FP를 셀 때 섹션 귀속이 틀리면 수치가 왜곡된다.
"""

import pytest

from analyzer.core import analyze_bytes
from analyzer.pe_parser import parse_pe
from pe_builder import MAX_SECTIONS, RW_DATA, RWX, RX, Section, build_pe

# 0x00..0xFF가 고르게 나오므로 Shannon 엔트로피가 정확히 8.0 bits/byte다.
HIGH_ENTROPY = bytes(range(256)) * 16
LOW_ENTROPY = b"\x90" * 64 + b"\xc3"


def _three_sections(**kwargs) -> bytes:
    return build_pe(
        sections=[
            Section(b".text", LOW_ENTROPY, RX),
            Section(b".data", HIGH_ENTROPY, RW_DATA),
            Section(b".rwx", b"\xc3", RWX),
        ],
        **kwargs,
    )


def _details(report, feature):
    return [f["detail"] for f in report["risk_features"] if f["feature"] == feature]


def test_sections_are_laid_out_in_order():
    info = parse_pe(_three_sections())

    assert info["headers"]["coff"]["number_of_sections"] == 3
    names = [s["name"] for s in info["sections"]]
    assert names == [".text", ".data", ".rwx"]
    rvas = [s["virtual_address"] for s in info["sections"]]
    assert rvas == sorted(rvas) and len(set(rvas)) == 3
    offsets = [s["raw_offset"] for s in info["sections"]]
    for prev, cur, sec in zip(offsets, offsets[1:], info["sections"]):
        assert cur == prev + sec["raw_size"]
    assert info["overlay"]["present"] is False


def test_entry_point_section_follows_entry_section_argument():
    assert parse_pe(_three_sections())["entry_point_section"] == ".text"
    assert parse_pe(_three_sections(entry_section=2))["entry_point_section"] == ".rwx"


def test_findings_are_attributed_to_the_right_section():
    report = analyze_bytes(_three_sections(), name="multi.exe")

    assert report["errors"] == []
    assert _details(report, "writable_executable_section") == [".rwx"]
    high = _details(report, "high_section_entropy")
    assert len(high) == 1 and high[0].startswith(".data ")


def test_clean_multi_section_pe_has_only_unsigned_finding():
    data = build_pe(
        sections=[
            Section(b".text", LOW_ENTROPY, RX),
            Section(b".data", b"config=1\x00" * 8, RW_DATA),
        ]
    )
    report = analyze_bytes(data, name="clean.exe")

    assert report["errors"] == []
    assert {f["feature"] for f in report["risk_features"]} == {"no_authenticode_blob"}


def test_imports_and_security_blob_work_with_multiple_sections():
    report = analyze_bytes(
        _three_sections(imports=("kernel32.dll", ["VirtualProtect"]), with_security_blob=True),
        name="multi-signed.exe",
    )

    assert report["errors"] == []
    assert report["pe"]["imports"][0]["functions"] == ["VirtualProtect"]
    assert report["pe"]["authenticode"]["blob_present"] is True
    features = {f["feature"] for f in report["risk_features"]}
    assert "security_relevant_imports" in features
    assert "no_authenticode_blob" not in features


@pytest.mark.parametrize(
    ("sections", "entry_section"),
    [
        ([], 0),
        ([Section(b".s", b"\x00", RW_DATA)] * (MAX_SECTIONS + 1), 0),
        ([Section(b".text", b"\xc3", RX)], 1),
    ],
)
def test_invalid_layout_is_rejected(sections, entry_section):
    with pytest.raises(ValueError):
        build_pe(sections=sections, entry_section=entry_section)


def test_max_sections_fit_in_headers():
    data = build_pe(sections=[Section(f".s{i}".encode(), b"\xc3", RX) for i in range(MAX_SECTIONS)])

    assert parse_pe(data)["headers"]["coff"]["number_of_sections"] == MAX_SECTIONS
