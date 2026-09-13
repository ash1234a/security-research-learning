from __future__ import annotations

from typing import Any

import pefile

from .entropy import shannon_entropy


def _decode_name(value: bytes) -> str:
    return value.rstrip(b"\x00").decode("utf-8", errors="replace")


def parse_pe(path: str) -> dict[str, Any]:
    """Parse defensive metadata from a Windows PE file without executing it."""
    pe = pefile.PE(path, fast_load=False)

    sections: list[dict[str, Any]] = []
    for section in pe.sections:
        raw = section.get_data()
        sections.append(
            {
                "name": _decode_name(section.Name),
                "virtual_address": int(section.VirtualAddress),
                "virtual_size": int(section.Misc_VirtualSize),
                "raw_size": int(section.SizeOfRawData),
                "entropy": round(shannon_entropy(raw), 4),
                "characteristics": int(section.Characteristics),
                "executable": bool(section.Characteristics & 0x20000000),
                "writable": bool(section.Characteristics & 0x80000000),
            }
        )

    imports: list[dict[str, Any]] = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            functions = []
            for imp in entry.imports:
                functions.append(
                    imp.name.decode("utf-8", errors="replace") if imp.name else f"ordinal:{imp.ordinal}"
                )
            imports.append(
                {
                    "dll": entry.dll.decode("utf-8", errors="replace"),
                    "functions": functions,
                }
            )

    exports: list[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exports.append(
                symbol.name.decode("utf-8", errors="replace") if symbol.name else f"ordinal:{symbol.ordinal}"
            )

    security_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_index]

    return {
        "machine": int(pe.FILE_HEADER.Machine),
        "timestamp": int(pe.FILE_HEADER.TimeDateStamp),
        "subsystem": int(pe.OPTIONAL_HEADER.Subsystem),
        "entry_point": int(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": int(pe.OPTIONAL_HEADER.ImageBase),
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "has_authenticode_blob": bool(security_dir.VirtualAddress and security_dir.Size),
    }
