"""실제 샘플 다운로드 없이 EMBER/BODMAS 형식과 예측 결합을 시험한다."""

from __future__ import annotations

import csv
import json

import pytest

from evaluation.feature_cli import main
from evaluation.feature_data import (
    FeatureDataError,
    evaluate_model_scores,
    load_bodmas,
    load_ember_jsonl,
    load_score_csv,
)


def _hash(i: int) -> str:
    return f"{i:064x}"


def _write_ember(path, records) -> None:
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")


def _write_scores(path, rows) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["sha256", "score"])
        writer.writerows(rows)


def test_ember_reads_labels_and_skips_unlabeled_across_files(tmp_path) -> None:
    a, b = tmp_path / "train_features_0.jsonl", tmp_path / "test_features.jsonl"
    _write_ember(a, [
        {"sha256": _hash(1), "label": 1, "avclass": "test_family"},
        {"sha256": _hash(2), "label": -1},
    ])
    _write_ember(b, [{"sha256": _hash(3).upper(), "label": 0, "avclass": None}])
    entries = load_ember_jsonl([a, b])
    assert [(e.sha256, e.label, e.family, e.source) for e in entries] == [
        (_hash(1), "malicious", "test_family", "ember2018"),
        (_hash(3), "benign", "", "ember2018"),
    ]


@pytest.mark.parametrize("record", [
    {"sha256": "bad", "label": 1},
    {"sha256": _hash(1), "label": 2},
    {"sha256": _hash(1), "label": "1"},
    {"sha256": _hash(1), "label": True},
    {"sha256": _hash(1), "label": 1, "avclass": ["bad"]},
])
def test_ember_rejects_invalid_metadata(tmp_path, record) -> None:
    path = tmp_path / "bad.jsonl"
    _write_ember(path, [record])
    with pytest.raises(FeatureDataError):
        load_ember_jsonl([path])


def test_ember_rejects_duplicates_and_broken_json(tmp_path) -> None:
    path = tmp_path / "bad.jsonl"
    _write_ember(path, [{"sha256": _hash(1), "label": 0}] * 2)
    with pytest.raises(FeatureDataError, match="중복"):
        load_ember_jsonl([path])
    path.write_text("{broken\n", encoding="utf-8")
    with pytest.raises(FeatureDataError, match="JSON"):
        load_ember_jsonl([path])


@pytest.mark.parametrize("header", [True, False])
def test_bodmas_aligns_npz_y_with_metadata_rows(tmp_path, header) -> None:
    np = pytest.importorskip("numpy")
    metadata = tmp_path / "bodmas_metadata.csv"
    rows = [[_hash(1), "2020-01", ""], [_hash(2), "2020-02", "family1"]]
    with metadata.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        if header:
            writer.writerow(["sha256", "appeared", "family"])
        writer.writerows(rows)
    archive = tmp_path / "bodmas.npz"
    np.savez_compressed(archive, y=np.array([0, 1], dtype=np.int64), X=np.zeros((2, 3)))
    entries = load_bodmas(metadata, archive)
    assert [(e.label, e.family, e.source) for e in entries] == [
        ("benign", "", "bodmas"), ("malicious", "family1", "bodmas")
    ]


def test_bodmas_rejects_row_count_mismatch(tmp_path) -> None:
    np = pytest.importorskip("numpy")
    metadata = tmp_path / "meta.csv"
    metadata.write_text(f"{_hash(1)},2020-01,\n", encoding="utf-8")
    archive = tmp_path / "labels.npz"
    np.savez_compressed(archive, y=np.array([0, 1]))
    with pytest.raises(FeatureDataError, match="일치하지 않음"):
        load_bodmas(metadata, archive)


def test_bodmas_rejects_invalid_label_and_duplicate_hash(tmp_path) -> None:
    np = pytest.importorskip("numpy")
    metadata = tmp_path / "meta.csv"
    metadata.write_text(f"{_hash(1)},2020-01,\n{_hash(1)},2020-02,\n", encoding="utf-8")
    archive = tmp_path / "labels.npz"
    np.savez_compressed(archive, y=np.array([0, 1]))
    with pytest.raises(FeatureDataError, match="중복"):
        load_bodmas(metadata, archive)
    np.savez_compressed(archive, y=np.array([0, 7]))
    with pytest.raises(FeatureDataError, match="label"):
        load_bodmas(metadata, archive)


@pytest.mark.parametrize("value", ["nan", "inf", "-0.01", "1.01", "not-a-number"])
def test_scores_reject_invalid_numbers(tmp_path, value) -> None:
    path = tmp_path / "scores.csv"
    _write_scores(path, [[_hash(1), value]])
    with pytest.raises(FeatureDataError):
        load_score_csv(path)


def test_scores_reject_duplicate_hash(tmp_path) -> None:
    path = tmp_path / "scores.csv"
    _write_scores(path, [[_hash(1), "0.1"], [_hash(1), "0.9"]])
    with pytest.raises(FeatureDataError, match="중복"):
        load_score_csv(path)


def test_model_score_confusion_matrix_and_missing(tmp_path) -> None:
    raw, scores_file = tmp_path / "ember.jsonl", tmp_path / "predictions.csv"
    _write_ember(raw, [{"sha256": _hash(i), "label": int(i <= 3)} for i in range(1, 7)])
    _write_scores(scores_file, [
        [_hash(1), "0.9"], [_hash(2), "0.2"], [_hash(3), "0.5"],
        [_hash(4), "0.8"], [_hash(5), "0.1"], [_hash(9), "0.99"],
    ])
    result = evaluate_model_scores(load_ember_jsonl([raw]), load_score_csv(scores_file))
    model = result["rules"]["model_positive"]
    assert (model["tp"], model["fp"], model["fn"], model["tn"]) == (2, 1, 1, 1)
    assert result["counts"]["measured"] == 5
    assert result["missing"] == [_hash(6)]  # 예측 없음: TN으로 계산하지 않는다.
    assert result["inputs"]["unused_predictions"] == 1
    assert result["rules"]["__any__"] == {**model, "rule": "__any__"}


def test_feature_cli_writes_json_and_rejects_bad_input(tmp_path, capsys) -> None:
    raw, scores_file, output = tmp_path / "features.jsonl", tmp_path / "scores.csv", tmp_path / "metrics.json"
    _write_ember(raw, [{"sha256": _hash(1), "label": 1}])
    _write_scores(scores_file, [[_hash(1), "0.75"]])
    args = ["--dataset", "ember2018", "--metadata", str(raw), "--scores", str(scores_file)]
    assert main([*args, "--json", str(output)]) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["rules"]["model_positive"]["tp"] == 1
    assert main([*args, "--threshold", "nan"]) == 2
    assert "threshold" in capsys.readouterr().err
    assert main([*args, "--labels-npz", "unneeded.npz"]) == 2


def test_feature_cli_requires_bodmas_npz(tmp_path, capsys) -> None:
    scores = tmp_path / "scores.csv"
    _write_scores(scores, [])
    args = ["--dataset", "bodmas", "--metadata", str(tmp_path / "meta.csv"), "--scores", str(scores)]
    assert main(args) == 2
    assert "--labels-npz" in capsys.readouterr().err


def test_feature_cli_handles_corrupt_bodmas_archive(tmp_path, capsys) -> None:
    metadata, archive, scores = (tmp_path / name for name in ("meta.csv", "bad.npz", "scores.csv"))
    metadata.write_text(f"{_hash(1)},2020-01,\n", encoding="utf-8")
    archive.write_bytes(b"not an npz file")
    _write_scores(scores, [])
    args = ["--dataset", "bodmas", "--metadata", str(metadata), "--labels-npz", str(archive), "--scores", str(scores)]
    assert main(args) == 2
    assert "invalid input" in capsys.readouterr().err
