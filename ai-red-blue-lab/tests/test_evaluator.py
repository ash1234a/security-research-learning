import json

import pytest

from evaluation.evaluator import ANY_RULE, evaluate, rule_names_from_source, scan_samples
from evaluation.manifest import ManifestEntry


def _e(n: int, label: str, source: str = "synthetic") -> ManifestEntry:
    return ManifestEntry(sha256=f"{n:064x}", label=label, family="", source=source)


def test_per_rule_confusion_matrix_and_ratios() -> None:
    m1, m2, m3, b1, b2 = _e(1, "malicious"), _e(2, "malicious"), _e(3, "malicious"), _e(4, "benign"), _e(5, "benign")
    preds = {
        m1.sha256: {"R1"},
        m2.sha256: {"R1", "R2"},
        m3.sha256: set(),
        b1.sha256: {"R2"},
        b2.sha256: [],
    }
    result = evaluate([m1, m2, m3, b1, b2], preds, rules=["R3"])

    r1, r2, r3, any_ = (result.rules[k] for k in ("R1", "R2", "R3", ANY_RULE))
    assert (r1.tp, r1.fp, r1.fn, r1.tn) == (2, 0, 1, 2)
    assert r1.precision == 1.0 and r1.recall == pytest.approx(2 / 3) and r1.benign_fp_rate == 0.0
    assert (r2.tp, r2.fp, r2.fn, r2.tn) == (1, 1, 2, 1)
    assert r2.precision == 0.5 and r2.benign_fp_rate == 0.5
    # 한 번도 발화하지 않은 규칙: precision은 분모 0이라 None, recall은 0
    assert (r3.tp, r3.fp, r3.fn, r3.tn) == (0, 0, 3, 2)
    assert r3.precision is None and r3.recall == 0.0
    assert (any_.tp, any_.fp, any_.fn, any_.tn) == (2, 1, 1, 1)
    assert (result.measured, result.positives, result.negatives) == (5, 3, 2)


def test_smoke_entries_are_excluded_from_metrics() -> None:
    eicar = _e(1, "malicious", "eicar")
    amtso = _e(2, "malicious", "amtso")
    benign = _e(3, "benign", "pip-benign")
    preds = {eicar.sha256: {"EICAR_Smoke_Test"}, amtso.sha256: set(), benign.sha256: set()}
    result = evaluate([eicar, amtso, benign], preds, rules=["EICAR_Smoke_Test"])

    smoke_rule = result.rules["EICAR_Smoke_Test"]  # smoke 발화는 집계에 들어가지 않는다
    assert (smoke_rule.tp, smoke_rule.fp, smoke_rule.fn, smoke_rule.tn) == (0, 0, 0, 1)
    any_ = result.rules[ANY_RULE]
    assert (any_.tp, any_.fp, any_.fn, any_.tn) == (0, 0, 0, 1)
    assert any_.recall is None  # 측정된 악성 샘플이 없으면 recall은 None
    assert [(s.source, s.criterion, s.passed) for s in result.smoke] == [
        ("eicar", "expected-rules", True),
        ("amtso", "any-rule", False),
    ]


def test_smoke_fails_when_only_an_unexpected_rule_fires() -> None:
    eicar = _e(1, "malicious", "eicar")
    result = evaluate([eicar], {eicar.sha256: {"Some_Other_Rule"}}, rules=[])
    check = result.smoke[0]
    assert check.criterion == "expected-rules" and check.expected_rules == ("EICAR_Smoke_Test",)
    assert not check.passed
    assert result.to_dict()["smoke"][0]["passed"] is False


def test_rules_must_be_a_list_of_names() -> None:
    with pytest.raises(TypeError):
        evaluate([], {}, rules="R1")
    with pytest.raises(TypeError):
        evaluate([], {})  # 규칙 목록은 필수


def test_rule_names_from_source_skips_comments_and_handles_modifiers() -> None:
    source = """
    // rule Commented_Out { condition: true }
    /* rule Also_Commented { condition: true } */
    rule First : tag { condition: true }
    private rule Helper { condition: false }
    global private rule Gate { condition: true }
    """
    assert rule_names_from_source(source) == ["First", "Helper", "Gate"]


def test_scan_failures_and_missing_are_counted_separately() -> None:
    ok, failed, absent = _e(1, "benign"), _e(2, "malicious"), _e(3, "malicious")
    smoke_failed = _e(4, "malicious", "eicar")
    preds = {ok.sha256: set(), failed.sha256: None, smoke_failed.sha256: None}
    result = evaluate([ok, failed, absent, smoke_failed], preds, rules=[])

    assert result.measured == 1
    # smoke 항목의 스캔 실패도 전체 실패 수에 포함한다
    assert result.scan_failures == [failed.sha256, smoke_failed.sha256]
    assert result.missing == [absent.sha256]
    assert result.smoke[0].fired_rules is None and not result.smoke[0].passed
    counts = json.loads(json.dumps(result.to_dict()))["counts"]
    assert counts == {"measured": 1, "positives": 0, "negatives": 1, "scan_failures": 2, "missing": 1, "smoke": 1}


class _Match:
    def __init__(self, rule: str) -> None:
        self.rule = rule


class _FlakyEngine:
    def scan(self, data: bytes):
        if data == b"boom":
            raise RuntimeError("scanner crashed")
        return [_Match("R")] if b"hit" in data else []


def test_scan_samples_isolates_engine_exceptions() -> None:
    outcome = scan_samples(_FlakyEngine(), [("a", b"hit"), ("b", b"boom"), ("c", b"miss")])
    assert outcome.predictions == {"a": frozenset({"R"}), "b": None, "c": frozenset()}
    assert outcome.errors == {"b": "RuntimeError: scanner crashed"}
    # 실패한 샘플을 포함해 모든 샘플의 scan 시간이 기록된다
    assert set(outcome.scan_seconds) == {"a", "b", "c"}
    assert all(t >= 0 for t in outcome.scan_seconds.values())
    assert outcome.total_scan_seconds == pytest.approx(sum(outcome.scan_seconds.values()))
