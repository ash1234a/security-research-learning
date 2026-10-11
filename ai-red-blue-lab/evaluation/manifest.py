"""데이터셋 매니페스트 로더.

매니페스트는 샘플 파일 없이 ``sha256,label,family,source`` 4개 열만 가진 CSV다
(이슈 #5 "프로젝트 방향" 우선순위 3, 안건 4 합의). 샘플 바이트는 레포에 커밋하지 않는다.
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass
from pathlib import Path

FIELDS: tuple[str, ...] = ("sha256", "label", "family", "source")
LABELS: frozenset[str] = frozenset({"malicious", "benign"})
# 안건 4에서 합의한 source 값 목록. 새 출처는 여기에 추가한다.
KNOWN_SOURCES: frozenset[str] = frozenset(
    {"synthetic", "pip-benign", "eicar", "amtso", "ember2018", "bodmas"}
)
# 발화 확인(pass/fail)만 하고 TP/FP/FN/TN 집계에서 빼는 출처.
SMOKE_SOURCES: frozenset[str] = frozenset({"eicar", "amtso"})

_SHA256 = re.compile(r"[0-9a-f]{64}")


class ManifestError(ValueError):
    """매니페스트 형식이 잘못되었을 때. 메시지에 줄 번호를 넣는다."""


@dataclass(frozen=True)
class ManifestEntry:
    sha256: str
    label: str
    family: str
    source: str

    @property
    def is_smoke(self) -> bool:
        return self.source in SMOKE_SOURCES


def parse_manifest(text: str) -> list[ManifestEntry]:
    """CSV 문자열을 검증해 항목 목록으로 돌려준다."""

    reader = csv.reader(io.StringIO(text))
    try:
        header = next(reader)
    except StopIteration:
        raise ManifestError("빈 매니페스트") from None
    if tuple(h.strip() for h in header) != FIELDS:
        raise ManifestError(f"1행: 헤더는 {','.join(FIELDS)} 이어야 함 (받은 값: {header})")

    entries: list[ManifestEntry] = []
    seen: set[str] = set()
    for lineno, row in enumerate(reader, start=2):
        if not row or all(not cell.strip() for cell in row):
            continue
        if len(row) != len(FIELDS):
            raise ManifestError(f"{lineno}행: 열이 {len(FIELDS)}개여야 함 (받은 개수: {len(row)})")
        sha256, label, family, source = (cell.strip() for cell in row)
        sha256 = sha256.lower()
        if not _SHA256.fullmatch(sha256):
            raise ManifestError(f"{lineno}행: sha256 형식 오류: {sha256!r}")
        if sha256 in seen:
            raise ManifestError(f"{lineno}행: 중복 sha256: {sha256}")
        if label not in LABELS:
            raise ManifestError(f"{lineno}행: label은 {sorted(LABELS)} 중 하나 (받은 값: {label!r})")
        if source not in KNOWN_SOURCES:
            raise ManifestError(
                f"{lineno}행: 알 수 없는 source {source!r} (허용: {sorted(KNOWN_SOURCES)})"
            )
        seen.add(sha256)
        entries.append(ManifestEntry(sha256=sha256, label=label, family=family, source=source))
    return entries


def load_manifest(path: str | Path) -> list[ManifestEntry]:
    return parse_manifest(Path(path).read_text(encoding="utf-8"))
