"""피처 데이터셋 정답과 별도 모델 점수를 연결해 성능을 평가하는 CLI."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from zipfile import BadZipFile
from pathlib import Path

from .feature_data import (
    FeatureDataError,
    evaluate_model_scores,
    load_bodmas,
    load_ember_jsonl,
    load_score_csv,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate EMBER/BODMAS model scores by SHA-256")
    parser.add_argument("--dataset", required=True, choices=("ember2018", "bodmas"))
    parser.add_argument(
        "--metadata", required=True, nargs="+",
        help="EMBER feature JSONL file(s), or one BODMAS metadata CSV",
    )
    parser.add_argument("--labels-npz", help="BODMAS bodmas.npz (reads only y, not X)")
    parser.add_argument("--scores", required=True, help="External model CSV: sha256,score")
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--json", dest="json_path", help="Save metrics JSON; default stdout")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.dataset == "ember2018":
            if args.labels_npz:
                raise FeatureDataError("EMBER에는 --labels-npz를 사용하지 않음")
            manifest = load_ember_jsonl(args.metadata)
        else:
            if len(args.metadata) != 1 or not args.labels_npz:
                raise FeatureDataError("BODMAS에는 --metadata CSV 하나와 --labels-npz가 필요함")
            manifest = load_bodmas(args.metadata[0], args.labels_npz)
        scores = load_score_csv(args.scores)
        report = evaluate_model_scores(manifest, scores, args.threshold)
    except (OSError, FeatureDataError, ValueError, KeyError, EOFError, BadZipFile, csv.Error) as exc:
        print(f"error: invalid input: {exc}", file=sys.stderr)
        return 2

    output = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.json_path:
        path = Path(args.json_path)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(output, encoding="utf-8")
        except OSError as exc:
            print(f"error: could not write metrics to {path}: {exc}", file=sys.stderr)
            return 3
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
