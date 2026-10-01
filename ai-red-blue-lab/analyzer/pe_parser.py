from __future__ import annotations

from typing import Any

import pefile

from .entropy import shannon_entropy


def _decode_name(value: bytes) -> str:
    return value.rstrip(b"\x00").decode("utf-8", errors="replace")


def _to_hex(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    return value


def _directory_name(index: int) -> str:
    for name, value in pefile.DIRECTORY_ENTRY.items():
        if value == index:
            return name
    return f"directory_{index}"


def _section_for_rva(sections: list[dict[str, Any]], rva: int) -> str | None:
    for section in sections:
        start = section["virtual_address"]
        span = max(section["virtual_size"], section["raw_size"])
        if start <= rva < start + span:
            return section["name"]
    return None


def _parse_headers(pe: pefile.PE) -> dict[str, Any]:
    return {
        "dos": {
            "magic": int(pe.DOS_HEADER.e_magic),
            "pe_header_offset": int(pe.DOS_HEADER.e_lfanew),
        },
        "coff": {
            "machine": int(pe.FILE_HEADER.Machine),
            "number_of_sections": int(pe.FILE_HEADER.NumberOfSections),
            "timestamp": int(pe.FILE_HEADER.TimeDateStamp),
            "characteristics": int(pe.FILE_HEADER.Characteristics),
            "size_of_optional_header": int(pe.FILE_HEADER.SizeOfOptionalHeader),
        },
        "optional": {
            "magic": int(pe.OPTIONAL_HEADER.Magic),
            "entry_point": int(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": int(pe.OPTIONAL_HEADER.ImageBase),
            "section_alignment": int(pe.OPTIONAL_HEADER.SectionAlignment),
            "file_alignment": int(pe.OPTIONAL_HEADER.FileAlignment),
            "size_of_image": int(pe.OPTIONAL_HEADER.SizeOfImage),
            "size_of_headers": int(pe.OPTIONAL_HEADER.SizeOfHeaders),
            "subsystem": int(pe.OPTIONAL_HEADER.Subsystem),
            "dll_characteristics": int(pe.OPTIONAL_HEADER.DllCharacteristics),
            "checksum": int(pe.OPTIONAL_HEADER.CheckSum),
            "number_of_rva_and_sizes": int(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes),
        },
    }


def _parse_sections(pe: pefile.PE) -> list[dict[str, Any]]:
    sections: list[dict[str, Any]] = []
    for section in pe.sections:
        raw = section.get_data()
        sections.append(
            {
                "name": _decode_name(section.Name),
                "virtual_address": int(section.VirtualAddress),
                "virtual_size": int(section.Misc_VirtualSize),
                "raw_offset": int(section.PointerToRawData),
                "raw_size": int(section.SizeOfRawData),
                "entropy": round(shannon_entropy(raw), 4),
                "characteristics": int(section.Characteristics),
                "executable": bool(section.Characteristics & 0x20000000),
                "readable": bool(section.Characteristics & 0x40000000),
                "writable": bool(section.Characteristics & 0x80000000),
            }
        )
    return sections


def _parse_imports(pe: pefile.PE) -> list[dict[str, Any]]:
    imports: list[dict[str, Any]] = []
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return imports

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        functions: list[str] = []
        for imp in entry.imports:
            functions.append(
                imp.name.decode("utf-8", errors="replace") if imp.name else f"ordinal:{imp.ordinal}"
            )
        imports.append(
            {
                "dll": (entry.dll or b"").decode("utf-8", errors="replace"),
                "functions": functions,
            }
        )
    return imports


def _parse_delay_imports(pe: pefile.PE) -> list[dict[str, Any]]:
    imports: list[dict[str, Any]] = []
    if not hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
        return imports

    for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
        functions: list[str] = []
        for imp in entry.imports:
            functions.append(
                imp.name.decode("utf-8", errors="replace") if imp.name else f"ordinal:{imp.ordinal}"
            )
        imports.append(
            {
                "dll": (entry.dll or b"").decode("utf-8", errors="replace"),
                "functions": functions,
            }
        )
    return imports


def _parse_exports(pe: pefile.PE) -> list[str]:
    exports: list[str] = []
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return exports

    for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        exports.append(
            symbol.name.decode("utf-8", errors="replace") if symbol.name else f"ordinal:{symbol.ordinal}"
        )
    return exports


def _parse_data_directories(pe: pefile.PE) -> list[dict[str, Any]]:
    directories: list[dict[str, Any]] = []
    for index, directory in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
        directories.append(
            {
                "index": index,
                "name": getattr(directory, "name", _directory_name(index)),
                "virtual_address": int(directory.VirtualAddress),
                "size": int(directory.Size),
                "present": bool(directory.VirtualAddress and directory.Size),
            }
        )
    return directories


def _parse_tls(pe: pefile.PE) -> dict[str, Any] | None:
    if not hasattr(pe, "DIRECTORY_ENTRY_TLS"):
        return None

    tls = pe.DIRECTORY_ENTRY_TLS.struct
    return {
        "start_address_of_raw_data": int(tls.StartAddressOfRawData),
        "end_address_of_raw_data": int(tls.EndAddressOfRawData),
        "address_of_index": int(tls.AddressOfIndex),
        "address_of_callbacks": int(tls.AddressOfCallBacks),
        "size_of_zero_fill": int(tls.SizeOfZeroFill),
        "characteristics": int(tls.Characteristics),
    }


def _parse_debug(pe: pefile.PE) -> list[dict[str, Any]]:
    debug_entries: list[dict[str, Any]] = []
    if not hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        return debug_entries

    for entry in pe.DIRECTORY_ENTRY_DEBUG:
        struct = entry.struct
        debug_entries.append(
            {
                "type": int(struct.Type),
                "size_of_data": int(struct.SizeOfData),
                "address_of_raw_data": int(struct.AddressOfRawData),
                "pointer_to_raw_data": int(struct.PointerToRawData),
            }
        )
    return debug_entries


def _parse_relocations(pe: pefile.PE) -> dict[str, int]:
    if not hasattr(pe, "DIRECTORY_ENTRY_BASERELOC"):
        return {"block_count": 0, "entry_count": 0}

    blocks = pe.DIRECTORY_ENTRY_BASERELOC
    return {
        "block_count": len(blocks),
        "entry_count": sum(len(block.entries) for block in blocks),
    }


def _parse_resources(pe: pefile.PE) -> dict[str, Any]:
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return {"present": False, "top_level_entries": []}

    entries: list[dict[str, Any]] = []
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.name is not None:
            identifier = str(entry.name)
        else:
            identifier = int(entry.struct.Id)

        child_count = 0
        if hasattr(entry, "directory"):
            child_count = len(entry.directory.entries)

        entries.append(
            {
                "id_or_name": identifier,
                "child_count": child_count,
            }
        )

    return {"present": True, "top_level_entries": entries}


def _parse_rich_header(pe: pefile.PE) -> dict[str, Any] | None:
    try:
        rich = pe.parse_rich_header()
    except (AttributeError, pefile.PEFormatError):
        return None

    if not rich:
        return None

    values = rich.get("values", [])
    return {
        # pefile은 XOR 키를 bytes로 돌려주므로 JSON 직렬화를 위해 hex 문자열로 바꾼다.
        "key": _to_hex(rich.get("key")),
        "value_count": len(values),
        "values": values,
    }


def _overlay_info(pe: pefile.PE, data_size: int) -> dict[str, Any]:
    start = pe.get_overlay_data_start_offset()
    if start is None:
        return {"present": False, "offset": None, "size": 0}

    return {
        "present": True,
        "offset": int(start),
        "size": max(0, data_size - int(start)),
    }


def parse_pe(data: bytes) -> dict[str, Any]:
    """Parse defensive metadata from Windows PE bytes without executing them.

    The parser intentionally returns raw structural facts. Detection and risk
    scoring belong in the heuristic layer so parser correctness can be tested
    independently from security judgments.
    """
    pe = pefile.PE(data=data, fast_load=False)

    try:
        sections = _parse_sections(pe)
        imports = _parse_imports(pe)
        exports = _parse_exports(pe)

        security_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_index]
        has_authenticode_blob = bool(security_dir.VirtualAddress and security_dir.Size)

        entry_point = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

        return {
            # Top-level fields consumed by core.py (schema v2).
            "machine": int(pe.FILE_HEADER.Machine),
            "timestamp": int(pe.FILE_HEADER.TimeDateStamp),
            "subsystem": int(pe.OPTIONAL_HEADER.Subsystem),
            "entry_point": entry_point,
            "image_base": int(pe.OPTIONAL_HEADER.ImageBase),
            "sections": sections,
            "imports": imports,
            "exports": exports,
            "has_authenticode_blob": has_authenticode_blob,
            # Extended structural facts (ported from PR #3).
            "headers": _parse_headers(pe),
            "entry_point_section": _section_for_rva(sections, entry_point),
            "delay_imports": _parse_delay_imports(pe),
            "data_directories": _parse_data_directories(pe),
            "tls": _parse_tls(pe),
            "debug": _parse_debug(pe),
            "relocations": _parse_relocations(pe),
            "resources": _parse_resources(pe),
            "rich_header": _parse_rich_header(pe),
            "overlay": _overlay_info(pe, len(data)),
            "authenticode": {
                "directory_virtual_address": int(security_dir.VirtualAddress),
                "directory_size": int(security_dir.Size),
                "blob_present": has_authenticode_blob,
                "signature_verified": None,
            },
        }
    finally:
        pe.close()
