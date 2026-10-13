"""평가 CLI: 매니페스트 + 규칙 디렉터리 + 샘플 디렉터리 → 지표 JSON.

샘플은 EICAR(로컬 생성), pe_builder 합성 PE, pip 내장 정상 PE만 쓴다(데이터 사용 방침).
"""

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from benign_corpus import collect_benign_pe
from evaluation.cli import (
    EXIT_INPUT_ERROR,
    EXIT_OK,
    EXIT_OUTPUT_ERROR,
    EXIT_SMOKE_FAILED,
    index_samples,
    main,
)
from pe_builder import build_pe

RULES_DIR = Path(__file__).parents[1] / "rules"
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
HEADER = "sha256,label,family,source\n"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def lab(tmp_path: Path) -> dict[str, Path]:
    samples = tmp_path / "samples"
    (samples / "nested").mkdir(parents=True)
    (samples / "eicar.com").write_bytes(EICAR)
    synthetic = build_pe()
    (samples / "nested" / "anything.bin").write_bytes(synthetic)
    (samples / "unlisted.bin").write_bytes(b"not in manifest")
    rows = [
        f"{_sha(EICAR)},malicious,EICAR,eicar",
        f"{_sha(synthetic)},benign,,synthetic",
        f"{'0' * 64},malicious,Absent,synthetic",
    ]
    manifest = _write(tmp_path / "manifest.csv", HEADER + "\n".join(rows) + "\n")
    rules = tmp_path / "rules"
    shutil.copytree(RULES_DIR, rules)
    _write(
        rules / "extra" / "never.yar",
        'rule Never_Fires_Test { strings: $x = "marker-not-in-any-sample-91c2" condition: $x }',
    )
    return {"manifest": manifest, "rules": rules, "samples": samples, "out": tmp_path / "out"}


def _args(lab: dict[str, Path], *extra: str) -> list[str]:
    return [
        "--manifest", str(lab["manifest"]),
        "--rules", str(lab["rules"]),
        "--samples", str(lab["samples"]),
        *extra,
    ]


def test_writes_metrics_json_matched_by_hash(lab: dict[str, Path]) -> None:
    out = lab["out"] / "metrics.json"
    assert main(_args(lab, "--json", str(out))) == EXIT_OK

    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["counts"] == {
        "measured": 1, "positives": 0, "negatives": 1,
        "scan_failures": 0, "missing": 1, "smoke": 1,
    }
    assert report["missing"] == ["0" * 64]
    assert report["inputs"]["sample_files"] == 3
    assert report["inputs"]["unlisted_files"] == 1
    # 규칙 디렉터리의 모든 규칙이 발화 여부와 상관없이 결과에 있다.
    assert {"EICAR_Smoke_Test", "Never_Fires_Test"} <= set(report["inputs"]["rules"])
    assert {"EICAR_Smoke_Test", "Never_Fires_Test", "__any__"} <= set(report["rules"])
    never = report["rules"]["Never_Fires_Test"]
    assert (never["fp"], never["tn"], never["benign_fp_rate"]) == (0, 1, 0.0)
    assert never["recall"] is None  # 측정된 양성이 없으면 숫자를 만들지 않는다
    assert [(s["source"], s["passed"]) for s in report["smoke"]] == [("eicar", True)]
    assert set(report["timing"]["per_sample_seconds"]) == {_sha(EICAR), _sha(build_pe())}
    assert report["scan_errors"] == {}


def test_prints_json_to_stdout(lab: dict[str, Path], capsys: pytest.CaptureFixture[str]) -> None:
    assert main(_args(lab)) == EXIT_OK
    assert json.loads(capsys.readouterr().out)["counts"]["smoke"] == 1


def test_fail_on_smoke(lab: dict[str, Path]) -> None:
    # EICAR 규칙을 뺀 규칙 디렉터리 → smoke 확인 실패.
    for path in lab["rules"].rglob("*.yar"):
        if "EICAR_Smoke_Test" in path.read_text(encoding="utf-8"):
            path.unlink()
    assert main(_args(lab)) == EXIT_OK
    assert main(_args(lab, "--fail-on-smoke")) == EXIT_SMOKE_FAILED


def test_benign_corpus_has_no_false_positives(tmp_path: Path) -> None:
    corpus = collect_benign_pe()
    samples = tmp_path / "samples"
    samples.mkdir()
    for s in corpus:
        shutil.copy(s.path, samples / f"{s.package}-{s.path.name}")
    manifest = _write(
        tmp_path / "m.csv", HEADER + "".join(f"{s.sha256},benign,,pip-benign\n" for s in corpus)
    )
    out = tmp_path / "m.json"
    argv = ["--manifest", str(manifest), "--rules", str(RULES_DIR), "--samples", str(samples)]
    assert main([*argv, "--json", str(out)]) == EXIT_OK
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["counts"]["negatives"] == len({s.sha256 for s in corpus})
    assert report["rules"]["__any__"]["fp"] == 0


@pytest.mark.parametrize(
    "broken, message",
    [
        ("manifest", "invalid manifest"),
        ("missing_manifest", "file not found"),
        ("rules", "does not exist"),
        ("empty_rules", "no .yar files"),
        ("bad_rule", "rule compilation failed"),
        ("samples", "sample directory does not exist"),
    ],
)
def test_input_errors(
    lab: dict[str, Path], tmp_path: Path, capsys: pytest.CaptureFixture[str], broken: str, message: str
) -> None:
    if broken == "manifest":
        _write(lab["manifest"], "sha256,label\n")
    elif broken == "missing_manifest":
        lab["manifest"] = tmp_path / "nope.csv"
    elif broken == "rules":
        lab["rules"] = tmp_path / "no-rules"
    elif broken == "empty_rules":
        lab["rules"] = tmp_path / "empty"
        lab["rules"].mkdir()
    elif broken == "bad_rule":
        _write(lab["rules"] / "bad.yar", "rule Broken { condition: }")
    elif broken == "samples":
        lab["samples"] = tmp_path / "no-samples"
    assert main(_args(lab)) == EXIT_INPUT_ERROR
    assert message in capsys.readouterr().err


def test_output_error(lab: dict[str, Path]) -> None:
    blocker = lab["out"]
    blocker.write_text("a file, not a directory", encoding="utf-8")
    assert main(_args(lab, "--json", str(blocker / "metrics.json"))) == EXIT_OUTPUT_ERROR


def test_index_samples_keeps_first_path_for_duplicate_content(tmp_path: Path) -> None:
    (tmp_path / "b").write_bytes(b"same")
    (tmp_path / "a").write_bytes(b"same")
    assert index_samples(tmp_path) == {_sha(b"same"): tmp_path / "a"}
