from pathlib import Path

import pytest
import yara_x

from detection.yara_x_engine import YaraXEngine, validate_rule_source


RULES_DIR = Path(__file__).parents[1] / "rules"
RULES = RULES_DIR / "smoke.yar"
EICAR_MARKER = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
# 표준 EICAR 테스트 파일(68바이트). 마커 부분 문자열은 오프셋 28에 있다.
EICAR_FILE = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + EICAR_MARKER + b"!$H+H*"
)


def test_eicar_file_is_standard_length() -> None:
    assert len(EICAR_FILE) == 68
    assert EICAR_FILE.index(EICAR_MARKER) == 28


@pytest.mark.parametrize(
    "data",
    [EICAR_FILE, EICAR_FILE + b"\r\n", EICAR_FILE + b" " * 60],
    ids=["exact", "crlf", "padded-128"],
)
def test_smoke_rule_matches_standard_eicar_file(data: bytes) -> None:
    engine = YaraXEngine.from_file(RULES)
    matches = engine.scan(data)

    assert len(matches) == 1
    assert matches[0].rule == "EICAR_Smoke_Test"
    assert matches[0].metadata["source"] == "eicar"


def test_smoke_rule_does_not_match_unrelated_data() -> None:
    engine = YaraXEngine.from_file(RULES)
    assert engine.scan(b"ordinary benign test data") == []


def test_smoke_rule_ignores_bare_marker() -> None:
    engine = YaraXEngine.from_file(RULES)
    assert engine.scan(EICAR_MARKER) == []


def test_smoke_rule_requires_eicar_at_start() -> None:
    engine = YaraXEngine.from_file(RULES)
    assert engine.scan(b"prefix " + EICAR_FILE) == []


def test_smoke_rule_rejects_files_over_128_bytes() -> None:
    engine = YaraXEngine.from_file(RULES)
    assert engine.scan(EICAR_FILE + b" " * 61) == []


def test_match_schema_is_json_serializable() -> None:
    import json

    engine = YaraXEngine.from_file(RULES)
    match = engine.scan(EICAR_FILE)[0]
    json.dumps(match.to_dict())


def test_invalid_rule_source_is_rejected() -> None:
    with pytest.raises(yara_x.CompileError):
        validate_rule_source("rule broken { condition: }")


@pytest.mark.parametrize("rule_path", sorted(RULES_DIR.rglob("*.yar")))
def test_repository_rules_compile(rule_path: Path) -> None:
    validate_rule_source(rule_path.read_text(encoding="utf-8"))
