from analyzer.pe_parser import (
    _decode_name,
    _directory_name,
    _overlay_info,
    _section_for_rva,
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
