"""규칙별 TP/FP/FN/TN, precision/recall, 정상 파일 오탐률 계산.

평가기는 데이터셋과 분리되어 있다(데이터 사용 방침 1번). 입력은
매니페스트 항목과 ``sha256 -> 발화한 규칙 이름 집합`` 예측뿐이다.
예측 값 ``None``은 스캔 실패를 뜻하며 집계에서 빼고 따로 센다.

- 양성(positive) = ``label == "malicious"``.
- ``source``가 SMOKE_SOURCES(eicar, amtso)인 항목은 집계에서 빼고
  발화 확인(pass/fail)으로만 보고한다(안건 4 합의).
- 분모가 0인 비율은 0이 아니라 ``None``으로 둔다(측정하지 않은 값을 숫자로 쓰지 않기 위해).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

from .manifest import ManifestEntry

ANY_RULE = "__any__"


class _Match(Protocol):
    rule: str


class _Engine(Protocol):
    def scan(self, data: bytes) -> list[Any]: ...


@dataclass
class ScanOutcome:
    predictions: dict[str, frozenset[str] | None]
    errors: dict[str, str]


def scan_samples(engine: _Engine, samples: Iterable[tuple[str, bytes]]) -> ScanOutcome:
    """엔진으로 샘플을 스캔한다. 예외는 샘플별로 격리해 ``None``으로 기록한다.

    실패 집계를 보고서 ``errors`` 문자열 파싱이 아니라 ``scan()``을 감싸서 센다
    (PR #11 리뷰에서 합의).
    """

    predictions: dict[str, frozenset[str] | None] = {}
    errors: dict[str, str] = {}
    for sha256, data in samples:
        try:
            matches = engine.scan(data)
        except Exception as exc:  # noqa: BLE001 - 샘플 하나의 실패가 평가 전체를 멈추면 안 된다
            predictions[sha256] = None
            errors[sha256] = f"{type(exc).__name__}: {exc}"
        else:
            predictions[sha256] = frozenset(m.rule for m in matches)
    return ScanOutcome(predictions=predictions, errors=errors)


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

    @property
    def passed(self) -> bool:
        return self.fired_rules is not None and bool(self.fired_rules) == self.expected_fire


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
    rules: Iterable[str] = (),
) -> EvaluationResult:
    """매니페스트와 예측으로 규칙별 지표를 계산한다.

    ``rules``에 준 규칙은 한 번도 발화하지 않아도 결과에 포함된다(FN만 있는 규칙을 드러내기 위해).
    ``ANY_RULE`` 항목은 "어느 규칙이든 하나라도 발화"를 탐지로 본 전체 지표다.
    """

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
                )
            )
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
