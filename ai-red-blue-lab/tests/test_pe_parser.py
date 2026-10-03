import json

from analyzer.core import analyze_bytes, report_to_json
from analyzer.pe_parser import (
    _decode_name,
    _directory_name,
    _overlay_info,
    _section_for_rva,
    _to_hex,
    parse_pe,
)


class _FakePe:
    def __init__(self, overlay_offset):
        self.overlay_offset = overlay_offset

    def get_overlay_data_start_offset(self):
        return self.overlay_offset


def test_decode_section_name():
    assert _decode_name(b".text\x00\x00\x00") == ".text"


def test_directory_name_resolves_known_index():
    assert _directory_name(1) == "IMAGE_DIRECTORY_ENTRY_IMPORT"


def test_section_for_rva_finds_entry_point_section():
    sections = [
        {
            "name": ".text",
            "virtual_address": 0x1000,
            "virtual_size": 0x600,
            "raw_size": 0x400,
        },
        {
            "name": ".data",
            "virtual_address": 0x2000,
            "virtual_size": 0x200,
            "raw_size": 0x200,
        },
    ]

    assert _section_for_rva(sections, 0x1100) == ".text"
    assert _section_for_rva(sections, 0x2050) == ".data"
    assert _section_for_rva(sections, 0x5000) is None


def test_overlay_info_without_overlay():
    assert _overlay_info(_FakePe(None), 1024) == {
        "present": False,
        "offset": None,
        "size": 0,
    }


def test_overlay_info_with_overlay():
    assert _overlay_info(_FakePe(768), 1024) == {
        "present": True,
        "offset": 768,
        "size": 256,
    }


# --- 아래는 PR #3 이식 시 추가: bytes 입력 경로를 실제 생성 PE로 검증한다. ---

def test_parse_pe_accepts_bytes_and_returns_extended_fields(pe_builder):
    info = parse_pe(pe_builder())

    assert info["entry_point_section"] == ".text"
    assert info["headers"]["coff"]["number_of_sections"] == 1
    assert info["headers"]["optional"]["magic"] == 0x10B
    assert len(info["data_directories"]) == 16
    assert info["tls"] is None
    assert info["delay_imports"] == []
    assert info["overlay"] == {"present": False, "offset": None, "size": 0}
    assert info["authenticode"]["blob_present"] is False
    assert info["authenticode"]["signature_verified"] is None


def test_overlay_size_is_computed_from_input_length(pe_builder):
    base = pe_builder()
    info = parse_pe(base + b"\x00" * 100)

    assert info["overlay"] == {"present": True, "offset": len(base), "size": 100}


def test_import_directory_is_marked_present(pe_builder):
    info = parse_pe(pe_builder(imports=("kernel32.dll", ["VirtualAlloc"])))

    directory = info["data_directories"][1]
    assert directory["present"] is True
    assert info["imports"][0]["functions"] == ["VirtualAlloc"]


def test_rich_header_key_bytes_become_hex():
    assert _to_hex(b"\x01\xab") == "01ab"
    assert _to_hex(None) is None


def test_extended_report_is_json_serializable(pe_builder):
    report = analyze_bytes(pe_builder(with_security_blob=True), name="tiny.exe")

    assert report["errors"] == []
    decoded = json.loads(report_to_json(report))
    assert decoded["pe"]["authenticode"]["blob_present"] is True
