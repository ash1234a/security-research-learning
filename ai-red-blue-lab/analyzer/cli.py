from __future__ import annotations

import argparse
from pathlib import Path

from .core import analyze_file, report_to_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Defensive static analyzer for Windows PE files")
    parser.add_argument("file", help="Path to the file to analyze")
    parser.add_argument("--json", dest="json_path", help="Write JSON report to this path")
    parser.add_argument("--string-limit", type=int, default=200, help="Maximum ASCII/UTF-16 strings to record")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    report = analyze_file(args.file, string_limit=args.string_limit)
    output = report_to_json(report)

    if args.json_path:
        target = Path(args.json_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(output, encoding="utf-8")
        print(f"Report written to {target}")
    else:
        print(output)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
