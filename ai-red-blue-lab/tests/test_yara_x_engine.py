from pathlib import Path

import pytest
import yara_x

from detection.yara_x_engine import YaraXEngine, validate_rule_source


RULES_DIR = Path(__file__).parents[1] / "rules"
RULES = RULES_DIR / "smoke.yar"
EICAR_MARKER = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"


def test_smoke_rule_matches_safe_marker() -> None:
    engine = YaraXEngine.from_file(RULES)
    matches = engine.scan(EICAR_MARKER)

    assert len(matches) == 1
    assert matches[0].rule == "EICAR_Smoke_Test"
    assert matches[0].metadata["source"] == "eicar"


def test_smoke_rule_does_not_match_unrelated_data() -> None:
    engine = YaraXEngine.from_file(RULES)
    assert engine.scan(b"ordinary benign test data") == []


def test_smoke_rule_requires_marker_at_start() -> None:
    engine = YaraXEngine.from_file(RULES)
    assert engine.scan(b"prefix " + EICAR_MARKER) == []


def test_match_schema_is_json_serializable() -> None:
    import json

    engine = YaraXEngine.from_file(RULES)
    match = engine.scan(EICAR_MARKER)[0]
    json.dumps(match.to_dict())


def test_invalid_rule_source_is_rejected() -> None:
    with pytest.raises(yara_x.CompileError):
        validate_rule_source("rule broken { condition: }")


@pytest.mark.parametrize("rule_path", sorted(RULES_DIR.rglob("*.yar")))
def test_repository_rules_compile(rule_path: Path) -> None:
    validate_rule_source(rule_path.read_text(encoding="utf-8"))
