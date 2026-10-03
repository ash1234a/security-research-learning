from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .core import analyze_file, report_to_json

EXIT_OK = 0
EXIT_INPUT_ERROR = 2
EXIT_OUTPUT_ERROR = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Defensive static analyzer for Windows PE files")
    parser.add_argument("file", help="Path to the file to analyze")
    parser.add_argument("--json", dest="json_path", help="Write JSON report to this path")
    parser.add_argument("--string-limit", type=int, default=200, help="Maximum ASCII/UTF-16 strings to record")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.string_limit < 0:
        print("error: --string-limit must be 0 or greater", file=sys.stderr)
        return EXIT_INPUT_ERROR

    try:
        report = analyze_file(args.file, string_limit=args.string_limit)
    except FileNotFoundError:
        print(f"error: file not found: {args.file}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    except PermissionError:
        print(f"error: permission denied: {args.file}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    output = report_to_json(report)

    if args.json_path:
        target = Path(args.json_path)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(output, encoding="utf-8")
        except OSError as exc:
            print(f"error: could not write report to {target}: {exc}", file=sys.stderr)
            return EXIT_OUTPUT_ERROR
        print(f"Report written to {target}")
    else:
        print(output)

    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
