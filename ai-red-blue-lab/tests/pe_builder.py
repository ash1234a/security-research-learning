"""Minimal PE32 builder for tests.

실제 실행 파일을 저장소에 넣지 않기 위해, 테스트에 필요한 최소 PE32 바이너리를
코드로 직접 만든다. 만들어진 바이트는 실행 가능한 코드를 담고 있지 않다.
"""

from __future__ import annotations

import struct

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


def build_pe(
    section_data: bytes = b"\xc3",
    *,
    section_name: bytes = b".text",
    characteristics: int = RX,
    imports: tuple[str, list[str]] | None = None,
    with_security_blob: bool = False,
) -> bytes:
    """Return the bytes of a minimal, single-section PE32 image."""
    data_directories = [(0, 0)] * 16

    if imports is not None:
        table, descriptors_size = _import_table(*imports)
        section_data = table + section_data
        data_directories[1] = (SECTION_RVA, descriptors_size)

    raw_size = _align(max(len(section_data), 1), FILE_ALIGNMENT)
    section_raw = section_data.ljust(raw_size, b"\x00")
    size_of_image = SECTION_RVA + _align(raw_size, SECTION_ALIGNMENT)

    security_blob = b""
    if with_security_blob:
        # WIN_CERTIFICATE 헤더만 있는 더미 블롭 (dwLength, wRevision, wCertificateType)
        security_blob = struct.pack("<IHH", 8, 0x0200, 0x0002)
        # 보안 디렉터리는 RVA가 아니라 파일 오프셋을 가리킨다.
        data_directories[4] = (HEADERS_SIZE + raw_size, len(security_blob))

    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)
    coff_header = struct.pack(
        "<HHIIIHH",
        0x014C,  # Machine: i386
        1,  # NumberOfSections
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
        raw_size,  # SizeOfCode
        0,
        0,
        SECTION_RVA,  # AddressOfEntryPoint
        SECTION_RVA,  # BaseOfCode
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

    section_header = struct.pack(
        "<8sIIIIIIHHI",
        section_name,
        len(section_data),  # VirtualSize
        SECTION_RVA,
        raw_size,
        HEADERS_SIZE,  # PointerToRawData
        0,
        0,
        0,
        0,
        characteristics,
    )

    headers = (dos_header + b"PE\x00\x00" + coff_header + optional_header + section_header).ljust(
        HEADERS_SIZE, b"\x00"
    )
    return headers + section_raw + security_blob

