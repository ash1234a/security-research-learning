"""EMBER 2018/BODMAS 라벨과 외부 모델 점수를 해시로 연결한다.

특징 벡터는 예측값이 아니다. 이 모듈은 정답 라벨과 *별도 모델이 만든*
SHA-256별 점수를 결합할 뿐이며, 실행 파일이나 특징 벡터를 실행하지 않는다.
"""

from __future__ import annotations

import csv
import json
import math
import re
from collections.abc import Iterable, Mapping
from pathlib import Path

from .evaluator import evaluate
from .manifest import ManifestEntry

MODEL_RULE = "model_positive"
_SHA256 = re.compile(r"[0-9a-f]{64}")


class FeatureDataError(ValueError):
    """데이터 형식·행 정렬·예측 점수 오류."""


def _entry(sha256: object, label: object, family: object, source: str, where: str) -> ManifestEntry:
    if not isinstance(sha256, str) or not _SHA256.fullmatch(sha256.lower()):
        raise FeatureDataError(f"{where}: 잘못된 sha256: {sha256!r}")
    if type(label) is not int or label not in (0, 1):
        raise FeatureDataError(f"{where}: label은 0(정상) 또는 1(악성)이어야 함")
    if family is None:
        family = ""
    if not isinstance(family, str):
        raise FeatureDataError(f"{where}: family는 문자열이어야 함")
    return ManifestEntry(sha256.lower(), "malicious" if label else "benign", family, source)


def _append_unique(entries: list[ManifestEntry], seen: set[str], entry: ManifestEntry, where: str) -> None:
    if entry.sha256 in seen:
        raise FeatureDataError(f"{where}: 중복 sha256: {entry.sha256}")
    seen.add(entry.sha256)
    entries.append(entry)


def load_ember_jsonl(paths: Iterable[str | Path]) -> list[ManifestEntry]:
    """EMBER 원본 ``*_features_*.jsonl``에서 라벨 있는 행만 읽는다(-1 제외)."""

    entries: list[ManifestEntry] = []
    seen: set[str] = set()
    found = False
    for path in map(Path, paths):
        found = True
        with path.open(encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                where = f"{path}:{line_number}"
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise FeatureDataError(f"{where}: 잘못된 JSON: {exc.msg}") from exc
                if not isinstance(record, dict):
                    raise FeatureDataError(f"{where}: JSON 객체가 필요함")
                label = record.get("label")
                if type(label) is int and label == -1:
                    continue  # 미라벨 샘플은 성능 평가에서 제외한다.
                entry = _entry(record.get("sha256"), label, record.get("avclass"), "ember2018", where)
                _append_unique(entries, seen, entry, where)
    if not found:
        raise FeatureDataError("EMBER JSONL 입력 파일이 필요함")
    return entries


def load_bodmas(metadata: str | Path, labels_npz: str | Path) -> list[ManifestEntry]:
    """원본 메타데이터 CSV의 행 순서와 ``bodmas.npz['y']``를 연결한다.

    X 특징 배열은 읽지 않는다. NumPy는 이 경로에서만 지연 import한다.
    """

    try:
        import numpy as np
    except ImportError as exc:
        raise FeatureDataError("BODMAS 변환에는 numpy 설치가 필요함") from exc

    with np.load(labels_npz, allow_pickle=False) as archive:
        if "y" not in archive:
            raise FeatureDataError("BODMAS NPZ에 y 배열이 없음")
        labels = archive["y"]
    if labels.ndim != 1:
        raise FeatureDataError("BODMAS y는 1차원 배열이어야 함")

    rows: list[tuple[int, list[str]]] = []
    with Path(metadata).open(encoding="utf-8-sig", newline="") as stream:
        for number, row in enumerate(csv.reader(stream), 1):
            if number == 1 and row and row[0].strip().lower() == "sha256":
                continue  # 헤더가 있는 배포본도 허용하되 label 행 수에는 포함하지 않는다.
            if not row or not any(cell.strip() for cell in row):
                raise FeatureDataError(f"{metadata}:{number}: 빈 행은 NPZ 행 정렬을 깨뜨림")
            if len(row) != 3:
                raise FeatureDataError(f"{metadata}:{number}: SHA-256, 시점, family의 3개 열이 필요함")
            rows.append((number, row))

    if len(rows) != len(labels):
        raise FeatureDataError(
            f"BODMAS 메타데이터 {len(rows)}행과 NPZ y {len(labels)}개가 일치하지 않음"
        )
    entries: list[ManifestEntry] = []
    seen: set[str] = set()
    for (number, row), label in zip(rows, labels):
        where = f"{metadata}:{number}"
        # np.int64 등은 int로 변환하지만 부동소수점·문자열 형식은 거부한다.
        if not np.issubdtype(type(label), np.integer):
            raise FeatureDataError(f"{where}: NPZ y는 정수 라벨이어야 함")
        entry = _entry(row[0].strip(), int(label), row[2].strip(), "bodmas", where)
        _append_unique(entries, seen, entry, where)
    return entries


def load_score_csv(path: str | Path) -> dict[str, float]:
    """외부 모델의 ``sha256,score`` CSV. score는 악성 확률 [0,1]."""

    scores: dict[str, float] = {}
    with Path(path).open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.reader(stream)
        if next(reader, None) != ["sha256", "score"]:
            raise FeatureDataError(f"{path}: 헤더는 sha256,score 이어야 함")
        for number, row in enumerate(reader, 2):
            where = f"{path}:{number}"
            if len(row) != 2:
                raise FeatureDataError(f"{where}: 열 2개가 필요함")
            sha256 = row[0].strip().lower()
            if not _SHA256.fullmatch(sha256):
                raise FeatureDataError(f"{where}: 잘못된 sha256")
            if sha256 in scores:
                raise FeatureDataError(f"{where}: 중복 sha256: {sha256}")
            try:
                score = float(row[1])
            except ValueError as exc:
                raise FeatureDataError(f"{where}: 잘못된 score") from exc
            if not math.isfinite(score) or not 0.0 <= score <= 1.0:
                raise FeatureDataError(f"{where}: score는 0부터 1 사이의 유한수여야 함")
            scores[sha256] = score
    return scores


def evaluate_model_scores(
    manifest: Iterable[ManifestEntry], scores: Mapping[str, float], threshold: float = 0.5
) -> dict:
    """모델 점수를 기존 평가기 구조로 변환한다. 누락 점수는 TN/FN으로 세지 않는다."""

    if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
        raise FeatureDataError("threshold는 0부터 1 사이의 유한수여야 함")
    entries = list(manifest)
    known = {entry.sha256 for entry in entries}
    predictions = {
        sha: (frozenset({MODEL_RULE}) if score >= threshold else frozenset())
        for sha, score in scores.items()
        if sha in known
    }
    report = evaluate(entries, predictions, rules=[MODEL_RULE]).to_dict()
    report["inputs"] = {
        "dataset_sources": sorted({entry.source for entry in entries}),
        "manifest_entries": len(entries),
        "prediction_rows": len(scores),
        "unused_predictions": sum(sha not in known for sha in scores),
        "threshold": threshold,
        "model_rule": MODEL_RULE,
    }
    return report
