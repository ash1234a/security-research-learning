"""pip 내장 정상 PE로 분석기 견고성과 규칙 오탐(FP)을 확인한다.

규칙 디렉터리의 모든 .yar 규칙이 정상 PE에서 발화하지 않아야 한다.
새 규칙이 정상 런처에 걸리면 이 테스트가 실패해 오탐을 바로 드러낸다.
"""

import json
from pathlib import Path

import pytest

from analyzer.core import analyze_bytes, report_to_json
from benign_corpus import LABEL, SOURCE, collect_benign_pe
from detection.yara_x_engine import YaraXEngine

RULES_DIR = Path(__file__).parents[1] / "rules"
CORPUS = collect_benign_pe()


def _all_rules_source() -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in sorted(RULES_DIR.rglob("*.yar")))


def test_corpus_is_available() -> None:
    # distlib은 dev 의존성이므로 코퍼스가 비어 있으면 설치 문제다(건너뛰지 않고 실패시킨다).
    assert len(CORPUS) >= 4, [s.name for s in CORPUS]
    assert SOURCE == "pip-benign" and LABEL == "benign"


def test_corpus_covers_multiple_machine_types() -> None:
    machines = {analyze_bytes(s.path.read_bytes(), s.name)["pe"]["machine"] for s in CORPUS}
    assert len(machines) >= 2, machines


@pytest.mark.parametrize("sample", CORPUS, ids=lambda s: s.name)
def test_analyzer_parses_real_benign_pe(sample) -> None:
    data = sample.path.read_bytes()
    report = analyze_bytes(data, name=sample.path.name)

    assert report["file_type"] == "PE"
    assert report["errors"] == []
    assert report["sha256"] == sample.sha256
    assert report["pe"]["sections"], "실제 PE에는 섹션이 있어야 한다"
    json.loads(report_to_json(report))


@pytest.mark.parametrize("sample", CORPUS, ids=lambda s: s.name)
def test_repository_rules_do_not_fire_on_benign_pe(sample) -> None:
    engine = YaraXEngine(_all_rules_source())
    matches = engine.scan(sample.path.read_bytes())
    assert matches == [], [m.rule for m in matches]
