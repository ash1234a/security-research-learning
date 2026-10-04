"""Minimal PE32 builder for tests.

실제 실행 파일을 저장소에 넣지 않기 위해, 테스트에 필요한 최소 PE32 바이너리를
코드로 직접 만든다. 만들어진 바이트는 실행 가능한 코드를 담고 있지 않다.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000
SECTION_RVA = 0x1000
HEADERS_SIZE = 0x200

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

RX = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
RWX = RX | IMAGE_SCN_MEM_WRITE
RW_DATA = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _import_table(dll: str, functions: list[str]) -> tuple[bytes, int]:
    """Build an import directory placed at the start of the section.

    Returns the raw bytes and the size of the descriptor array.
    """
    descriptors_size = 20 * 2  # 1 descriptor + null terminator
    ilt_offset = descriptors_size
    thunk_size = 4 * (len(functions) + 1)
    iat_offset = ilt_offset + thunk_size
    names_offset = iat_offset + thunk_size

    hint_names = b""
    name_rvas = []
    for func in functions:
        name_rvas.append(SECTION_RVA + names_offset + len(hint_names))
        entry = struct.pack("<H", 0) + func.encode("ascii") + b"\x00"
        if len(entry) % 2:
            entry += b"\x00"
        hint_names += entry

    dll_name_offset = names_offset + len(hint_names)
    thunks = b"".join(struct.pack("<I", rva) for rva in name_rvas) + struct.pack("<I", 0)

    descriptor = struct.pack(
        "<IIIII",
        SECTION_RVA + ilt_offset,  # OriginalFirstThunk
        0,  # TimeDateStamp
        0,  # ForwarderChain
        SECTION_RVA + dll_name_offset,  # Name
        SECTION_RVA + iat_offset,  # FirstThunk
    )
    table = descriptor + b"\x00" * 20 + thunks + thunks + hint_names + dll.encode("ascii") + b"\x00"
    return table, descriptors_size


@dataclass(frozen=True)
class Section:
    """여러 섹션을 가진 PE를 만들 때 쓰는 섹션 정의."""

    name: bytes
    data: bytes
    characteristics: int


# DOS(0x40) + "PE\0\0"(4) + COFF(20) + Optional(0xE0) 뒤에 섹션 헤더(40바이트씩)가
# HEADERS_SIZE 안에 들어가야 한다.
MAX_SECTIONS = (HEADERS_SIZE - (0x40 + 4 + 20 + 0xE0)) // 40


def build_pe(
    section_data: bytes = b"\xc3",
    *,
    section_name: bytes = b".text",
    characteristics: int = RX,
    imports: tuple[str, list[str]] | None = None,
    with_security_blob: bool = False,
    sections: list[Section] | None = None,
    entry_section: int = 0,
) -> bytes:
    """Return the bytes of a minimal PE32 image.

    ``sections``를 주지 않으면 기존처럼 ``section_data``/``section_name``/``characteristics``로
    섹션 하나를 만든다. ``sections``를 주면 그 순서대로 섹션을 배치하고, 이때 단일 섹션용
    인자는 쓰지 않는다. import 테이블은 첫 섹션 앞부분에, 진입점은 ``entry_section`` 번째
    섹션의 시작 RVA에 둔다.
    """
    if sections is None:
        sections = [Section(section_name, section_data, characteristics)]
    if not 1 <= len(sections) <= MAX_SECTIONS:
        raise ValueError(f"sections must contain 1..{MAX_SECTIONS} entries")
    if not 0 <= entry_section < len(sections):
        raise ValueError("entry_section is out of range")

    data_directories = [(0, 0)] * 16

    contents = [section.data for section in sections]
    if imports is not None:
        # import 테이블 내부 RVA는 SECTION_RVA(첫 섹션) 기준으로 계산된다.
        table, descriptors_size = _import_table(*imports)
        contents[0] = table + contents[0]
        data_directories[1] = (SECTION_RVA, descriptors_size)

    layout = []  # (rva, raw_offset, raw_size, virtual_size)
    rva = SECTION_RVA
    raw_offset = HEADERS_SIZE
    for content in contents:
        raw_size = _align(max(len(content), 1), FILE_ALIGNMENT)
        layout.append((rva, raw_offset, raw_size, len(content)))
        rva += _align(raw_size, SECTION_ALIGNMENT)
        raw_offset += raw_size
    size_of_image = rva
    raw_end = raw_offset

    size_of_code = sum(
        raw_size
        for section, (_, _, raw_size, _) in zip(sections, layout)
        if section.characteristics & IMAGE_SCN_CNT_CODE
    )
    code_rvas = [r for section, (r, _, _, _) in zip(sections, layout) if section.characteristics & IMAGE_SCN_CNT_CODE]
    base_of_code = code_rvas[0] if code_rvas else SECTION_RVA
    entry_point = layout[entry_section][0]

    security_blob = b""
    if with_security_blob:
        # WIN_CERTIFICATE 헤더만 있는 더미 블롭 (dwLength, wRevision, wCertificateType)
        security_blob = struct.pack("<IHH", 8, 0x0200, 0x0002)
        # 보안 디렉터리는 RVA가 아니라 파일 오프셋을 가리킨다.
        data_directories[4] = (raw_end, len(security_blob))

    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)
    coff_header = struct.pack(
        "<HHIIIHH",
        0x014C,  # Machine: i386
        len(sections),  # NumberOfSections
        0x65000000,  # TimeDateStamp
        0,
        0,
        0xE0,  # SizeOfOptionalHeader
        0x0102,  # EXECUTABLE_IMAGE | 32BIT_MACHINE
    )
    optional_header = struct.pack(
        "<HBBIIIIII",
        0x010B,  # PE32
        14,
        0,
        size_of_code,  # SizeOfCode
        0,
        0,
        entry_point,  # AddressOfEntryPoint
        base_of_code,  # BaseOfCode
        0,  # BaseOfData
    ) + struct.pack(
        "<IIIHHHHHHIIIIHHIIIIII",
        0x00400000,  # ImageBase
        SECTION_ALIGNMENT,
        FILE_ALIGNMENT,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        size_of_image,
        HEADERS_SIZE,
        0,  # CheckSum
        3,  # Subsystem: Windows CUI
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,  # NumberOfRvaAndSizes
    )
    optional_header += b"".join(struct.pack("<II", rva, size) for rva, size in data_directories)
    assert len(optional_header) == 0xE0

    section_headers = b""
    section_raws = b""
    for section, content, (rva, raw_offset, raw_size, virtual_size) in zip(sections, contents, layout):
        section_headers += struct.pack(
            "<8sIIIIIIHHI",
            section.name,
            virtual_size,  # VirtualSize
            rva,
            raw_size,
            raw_offset,  # PointerToRawData
            0,
            0,
            0,
            0,
            section.characteristics,
        )
        section_raws += content.ljust(raw_size, b"\x00")

    headers = (dos_header + b"PE\x00\x00" + coff_header + optional_header + section_headers).ljust(
        HEADERS_SIZE, b"\x00"
    )
    assert len(headers) == HEADERS_SIZE
    return headers + section_raws + security_blob
