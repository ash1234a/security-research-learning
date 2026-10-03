from __future__ import annotations

import re
from itertools import islice

ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16LE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def extract_ascii_strings(data: bytes, limit: int = 200) -> list[str]:
    # islice로 limit개만 읽어 큰 파일에서도 모든 매치를 메모리에 쌓지 않는다.
    matches = islice(ASCII_RE.finditer(data), max(limit, 0))
    return [m.group().decode("ascii", errors="ignore") for m in matches]


def extract_utf16le_strings(data: bytes, limit: int = 200) -> list[str]:
    matches = islice(UTF16LE_RE.finditer(data), max(limit, 0))
    return [m.group().decode("utf-16le", errors="ignore") for m in matches]


def extract_strings(data: bytes, limit_each: int = 200) -> dict[str, list[str]]:
    return {
        "ascii": extract_ascii_strings(data, limit_each),
        "utf16le": extract_utf16le_strings(data, limit_each),
    }
