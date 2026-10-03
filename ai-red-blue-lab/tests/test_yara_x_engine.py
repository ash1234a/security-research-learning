from pathlib import Path

import pytest
import yara_x

from detection.yara_x_engine import YaraXEngine, validate_rule_source


RULES = Path(__file__).parents[1] / "rules" / "smoke.yar"


def test_smoke_rule_matches_safe_marker() -> None:
    engine = YaraXEngine.from_file(RULES)
    matches = engine.scan(b"prefix EICAR-STANDARD-ANTIVIRUS-TEST-FILE suffix")

    assert len(matches) == 1
    assert matches[0].rule == "EICAR_Smoke_Test"
    assert matches[0].metadata["source"] == "eicar"


def test_smoke_rule_does_not_match_unrelated_data() -> None:
    engine = YaraXEngine.from_file(RULES)
    assert engine.scan(b"ordinary benign test data") == []


def test_match_schema_is_json_serializable() -> None:
    import json

    engine = YaraXEngine.from_file(RULES)
    match = engine.scan(b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE")[0]
    json.dumps(match.to_dict())


def test_invalid_rule_source_is_rejected() -> None:
    with pytest.raises(yara_x.CompileError):
        validate_rule_source("rule broken { condition: }")
