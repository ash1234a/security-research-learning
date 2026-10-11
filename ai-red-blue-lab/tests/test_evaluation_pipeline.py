"""매니페스트 → 실제 YARA-X 스캔 → 평가까지 파일 커밋 없이 끝까지 돌려 본다.

샘플: EICAR(로컬 생성, smoke), pip 내장 정상 PE(pip-benign), pe_builder 합성 PE(synthetic).
"""

import hashlib
from pathlib import Path

from benign_corpus import collect_benign_pe
from detection.yara_x_engine import YaraXEngine
from evaluation import ANY_RULE, evaluate, parse_manifest, rule_names_from_source, scan_samples
from pe_builder import build_pe

RULES_DIR = Path(__file__).parents[1] / "rules"
# 어떤 테스트 샘플에도 발화하지 않는 규칙. 미발화 규칙이 결과에 FN으로 남는지 확인한다.
NEVER_FIRES = """
rule Never_Fires_Test {
    strings:
        $x = "this-marker-is-not-in-any-test-sample-7f3a"
    condition:
        $x
}
"""
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_end_to_end_with_repository_rules() -> None:
    samples: dict[str, bytes] = {_sha(EICAR): EICAR}
    rows = [f"{_sha(EICAR)},malicious,EICAR,eicar"]
    for s in collect_benign_pe():
        samples[s.sha256] = s.path.read_bytes()
        rows.append(f"{s.sha256},benign,,pip-benign")
    synthetic = build_pe()
    samples[_sha(synthetic)] = synthetic
    rows.append(f"{_sha(synthetic)},benign,,synthetic")
    # 라벨만 악성으로 둔 합성 PE(실행 코드 없음). 미발화 규칙의 FN/recall 확인용.
    positive = build_pe(b"\x90\xc3")
    samples[_sha(positive)] = positive
    rows.append(f"{_sha(positive)},malicious,TestOnly,synthetic")

    manifest = parse_manifest("sha256,label,family,source\n" + "\n".join(rows) + "\n")
    repo_source = "\n".join(p.read_text(encoding="utf-8") for p in sorted(RULES_DIR.rglob("*.yar")))
    source = repo_source + NEVER_FIRES
    rules = rule_names_from_source(source)
    assert rules == rule_names_from_source(repo_source) + ["Never_Fires_Test"]

    outcome = scan_samples(YaraXEngine(source), samples.items())
    result = evaluate(manifest, outcome.predictions, rules)

    assert outcome.errors == {}
    assert set(outcome.scan_seconds) == set(samples)
    never = result.rules["Never_Fires_Test"]
    assert (never.tp, never.fp, never.fn) == (0, 0, 1) and never.recall == 0.0
    assert [(s.source, s.criterion, s.passed, s.fired_rules) for s in result.smoke] == [
        ("eicar", "expected-rules", True, ("EICAR_Smoke_Test",))
    ]
    any_ = result.rules[ANY_RULE]
    assert result.negatives == len(manifest) - 2 and result.positives == 1
    assert any_.fp == 0 and any_.benign_fp_rate == 0.0
    assert any_.tp == 0 and any_.precision is None and any_.recall == 0.0
