from __future__ import annotations

import re

ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16LE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def extract_ascii_strings(data: bytes, limit: int = 200) -> list[str]:
    values = [m.group().decode("ascii", errors="ignore") for m in ASCII_RE.finditer(data)]
    return values[:limit]


def extract_utf16le_strings(data: bytes, limit: int = 200) -> list[str]:
    values = [m.group().decode("utf-16le", errors="ignore") for m in UTF16LE_RE.finditer(data)]
    return values[:limit]


def extract_strings(data: bytes, limit_each: int = 200) -> dict[str, list[str]]:
    return {
        "ascii": extract_ascii_strings(data, limit_each),
        "utf16le": extract_utf16le_strings(data, limit_each),
    }
