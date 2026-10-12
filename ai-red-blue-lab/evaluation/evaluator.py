"""규칙별 TP/FP/FN/TN, precision/recall, 정상 파일 오탐률 계산.

평가기는 데이터셋과 분리되어 있다(데이터 사용 방침 1번). 입력은
매니페스트 항목과 ``sha256 -> 발화한 규칙 이름 집합`` 예측뿐이다.
예측 값 ``None``은 스캔 실패를 뜻하며 집계에서 빼고 따로 센다.

- 양성(positive) = ``label == "malicious"``.
- ``source``가 SMOKE_SOURCES(eicar, amtso)인 항목은 집계에서 빼고
  발화 확인(pass/fail)으로만 보고한다(안건 4 합의).
- 분모가 0인 비율은 0이 아니라 ``None``으로 둔다(측정하지 않은 값을 숫자로 쓰지 않기 위해).
- 평가할 규칙 목록은 필수 입력이다. 발화 결과에서만 규칙을 모으면 한 번도
  발화하지 않은 규칙이 결과에서 빠져 FN/recall을 볼 수 없기 때문이다(PR #14 GPT 리뷰).
"""

from __future__ import annotations

import re
import time
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

from .manifest import ManifestEntry

ANY_RULE = "__any__"

# smoke 출처별로 반드시 발화해야 하는 규칙. 여기에 없는 출처는 "아무 규칙이나 발화"로만
# 판정하고 결과의 ``criterion``에 ``any-rule``로 그 한계를 표시한다.
SMOKE_EXPECTED_RULES: Mapping[str, frozenset[str]] = {"eicar": frozenset({"EICAR_Smoke_Test"})}

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_LINE_COMMENT = re.compile(r"//[^\n]*")
_RULE_DECL = re.compile(r"^\s*(?:(?:private|global)\s+)*rule\s+([A-Za-z_]\w*)", re.M)


def rule_names_from_source(source: str) -> list[str]:
    """YARA 규칙 소스에서 선언된 규칙 이름을 순서대로 뽑는다(주석 제외).

    yara-x Python API는 컴파일된 규칙 목록을 열거하지 않으므로 소스에서 읽는다.
    """

    text = _LINE_COMMENT.sub("", _BLOCK_COMMENT.sub("", source))
    return _RULE_DECL.findall(text)


class _Match(Protocol):
    rule: str


class _Engine(Protocol):
    def scan(self, data: bytes) -> list[Any]: ...


@dataclass
class ScanOutcome:
    predictions: dict[str, frozenset[str] | None]
    errors: dict[str, str]
    # 샘플별 scan() 소요 시간(초, time.perf_counter). 실패한 샘플도 기록한다.
    scan_seconds: dict[str, float] = field(default_factory=dict)

    @property
    def total_scan_seconds(self) -> float:
        return sum(self.scan_seconds.values())


def scan_samples(engine: _Engine, samples: Iterable[tuple[str, bytes]]) -> ScanOutcome:
    """엔진으로 샘플을 스캔한다. 예외는 샘플별로 격리해 ``None``으로 기록한다.

    실패 집계를 보고서 ``errors`` 문자열 파싱이 아니라 ``scan()``을 감싸서 센다
    (PR #11 리뷰에서 합의).
    """

    predictions: dict[str, frozenset[str] | None] = {}
    errors: dict[str, str] = {}
    seconds: dict[str, float] = {}
    for sha256, data in samples:
        start = time.perf_counter()
        try:
            matches = engine.scan(data)
        except Exception as exc:  # noqa: BLE001 - 샘플 하나의 실패가 평가 전체를 멈추면 안 된다
            predictions[sha256] = None
            errors[sha256] = f"{type(exc).__name__}: {exc}"
        else:
            predictions[sha256] = frozenset(m.rule for m in matches)
        finally:
            seconds[sha256] = time.perf_counter() - start
    return ScanOutcome(predictions=predictions, errors=errors, scan_seconds=seconds)


def _ratio(num: int, den: int) -> float | None:
    return None if den == 0 else num / den


@dataclass
class RuleMetrics:
    rule: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float | None:
        return _ratio(self.tp, self.tp + self.fp)

    @property
    def recall(self) -> float | None:
        return _ratio(self.tp, self.tp + self.fn)

    @property
    def benign_fp_rate(self) -> float | None:
        return _ratio(self.fp, self.fp + self.tn)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.update(
            precision=self.precision, recall=self.recall, benign_fp_rate=self.benign_fp_rate
        )
        return data


@dataclass(frozen=True)
class SmokeCheck:
    sha256: str
    source: str
    expected_fire: bool
    fired_rules: tuple[str, ...] | None  # None = 스캔 실패
    expected_rules: tuple[str, ...] = ()

    @property
    def criterion(self) -> str:
        """``expected-rules``: 기대 규칙이 모두 발화해야 통과. ``any-rule``: 발화 여부만 본다."""

        return "expected-rules" if self.expected_rules and self.expected_fire else "any-rule"

    @property
    def passed(self) -> bool:
        if self.fired_rules is None:
            return False
        if self.criterion == "expected-rules":
            return set(self.expected_rules) <= set(self.fired_rules)
        return bool(self.fired_rules) == self.expected_fire


@dataclass
class EvaluationResult:
    rules: dict[str, RuleMetrics]
    smoke: list[SmokeCheck]
    measured: int
    positives: int
    negatives: int
    scan_failures: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "counts": {
                "measured": self.measured,
                "positives": self.positives,
                "negatives": self.negatives,
                "scan_failures": len(self.scan_failures),
                "missing": len(self.missing),
                "smoke": len(self.smoke),
            },
            "rules": {name: m.to_dict() for name, m in sorted(self.rules.items())},
            "smoke": [
                {
                    "sha256": s.sha256,
                    "source": s.source,
                    "expected_fire": s.expected_fire,
                    "criterion": s.criterion,
                    "expected_rules": list(s.expected_rules),
                    "fired_rules": None if s.fired_rules is None else list(s.fired_rules),
                    "passed": s.passed,
                }
                for s in self.smoke
            ],
            "scan_failures": sorted(self.scan_failures),
            "missing": sorted(self.missing),
        }


def evaluate(
    manifest: Iterable[ManifestEntry],
    predictions: Mapping[str, Iterable[str] | None],
    rules: Iterable[str],
    *,
    smoke_expected_rules: Mapping[str, Iterable[str]] = SMOKE_EXPECTED_RULES,
) -> EvaluationResult:
    """매니페스트와 예측으로 규칙별 지표를 계산한다.

    ``rules``(필수)의 모든 규칙이 한 번도 발화하지 않아도 결과에 포함된다. YARA 소스라면
    ``rule_names_from_source()``로 얻는다. 목록에 없는 규칙이 발화하면 그 규칙도 더한다.
    ``ANY_RULE`` 항목은 "어느 규칙이든 하나라도 발화"를 탐지로 본 전체 지표다.
    smoke 항목의 스캔 실패도 ``scan_failures``에 포함한다.
    """

    if isinstance(rules, str):
        raise TypeError("rules는 규칙 이름 목록이어야 한다(문자열 하나가 아님)")

    entries = list(manifest)
    preds: dict[str, frozenset[str] | None] = {
        k: None if v is None else frozenset(v) for k, v in predictions.items()
    }

    rule_names: set[str] = set(rules)
    for e in entries:
        fired = preds.get(e.sha256)
        if fired and not e.is_smoke:
            rule_names |= fired
    metrics = {name: RuleMetrics(rule=name) for name in rule_names}
    metrics[ANY_RULE] = RuleMetrics(rule=ANY_RULE)

    smoke: list[SmokeCheck] = []
    failures: list[str] = []
    missing: list[str] = []
    measured = positives = negatives = 0

    for e in entries:
        if e.sha256 not in preds:
            missing.append(e.sha256)
            continue
        fired = preds[e.sha256]
        if e.is_smoke:
            smoke.append(
                SmokeCheck(
                    sha256=e.sha256,
                    source=e.source,
                    expected_fire=e.label == "malicious",
                    fired_rules=None if fired is None else tuple(sorted(fired)),
                    expected_rules=tuple(sorted(smoke_expected_rules.get(e.source, ()))),
                )
            )
            if fired is None:
                failures.append(e.sha256)
            continue
        if fired is None:
            failures.append(e.sha256)
            continue

        measured += 1
        positive = e.label == "malicious"
        if positive:
            positives += 1
        else:
            negatives += 1
        for name, m in metrics.items():
            hit = bool(fired) if name == ANY_RULE else name in fired
            if positive and hit:
                m.tp += 1
            elif positive:
                m.fn += 1
            elif hit:
                m.fp += 1
            else:
                m.tn += 1

    return EvaluationResult(
        rules=metrics,
        smoke=smoke,
        measured=measured,
        positives=positives,
        negatives=negatives,
        scan_failures=failures,
        missing=missing,
    )
