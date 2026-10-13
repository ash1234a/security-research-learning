"""규칙 평가 CLI: 매니페스트 + 규칙 디렉터리 + 샘플 디렉터리 → 지표 JSON.

    redblue-evaluate --manifest data/manifest.csv --rules rules --samples /path/to/samples

- 샘플 디렉터리의 파일을 재귀로 찾아 SHA-256을 계산하고, 매니페스트에 있는 해시만 스캔한다.
  파일 이름은 보지 않는다. 매니페스트에 없는 파일은 읽지만 스캔하지 않는다(``unlisted_files``).
- ``sample_files``는 디스크의 파일 수, ``unique_samples``는 고유 SHA-256 수다.
- 매니페스트에 있지만 샘플 디렉터리에 없는 항목은 평가기의 ``missing``으로 보고한다.
- 평가할 규칙 목록은 규칙 소스에서 읽으므로 한 번도 발화하지 않은 규칙도 결과에 남는다.
- 샘플은 읽기만 하고 실행하지 않는다.

종료 코드: 0 성공, 1 ``--fail-on-smoke``이고 smoke 확인 실패, 2 입력 오류(읽기 권한 없음 등 ``OSError`` 포함), 3 출력 오류.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .evaluator import evaluate, rule_names_from_source, scan_samples
from .manifest import ManifestError, load_manifest

EXIT_OK = 0
EXIT_SMOKE_FAILED = 1
EXIT_INPUT_ERROR = 2
EXIT_OUTPUT_ERROR = 3

_CHUNK = 1 << 20


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate detection rules against a labelled sample manifest"
    )
    parser.add_argument("--manifest", required=True, help="CSV with sha256,label,family,source")
    parser.add_argument("--rules", required=True, help="Directory of .yar rules (recursive)")
    parser.add_argument("--samples", required=True, help="Directory of sample files (recursive)")
    parser.add_argument("--json", dest="json_path", help="Write the metrics JSON to this path")
    parser.add_argument(
        "--fail-on-smoke",
        action="store_true",
        help="Exit with 1 when any smoke check (eicar, amtso) fails",
    )
    return parser


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def hash_files(directory: Path) -> list[tuple[str, Path]]:
    """디렉터리의 모든 파일을 정렬 순서로 ``(sha256, 경로)`` 목록으로 만든다(중복 내용 포함)."""

    return [
        (_sha256_file(path), path)
        for path in sorted(p for p in directory.rglob("*") if p.is_file())
    ]


def _first_path_by_hash(files: list[tuple[str, Path]]) -> dict[str, Path]:
    index: dict[str, Path] = {}
    for sha256, path in files:
        index.setdefault(sha256, path)
    return index


def index_samples(directory: Path) -> dict[str, Path]:
    """``sha256 -> 경로``. 내용이 같은 파일이 여러 개면 정렬 순서상 첫 경로를 쓴다."""

    return _first_path_by_hash(hash_files(directory))


def _read_samples(paths: dict[str, Path]) -> Iterator[tuple[str, bytes]]:
    for sha256, path in sorted(paths.items()):
        yield sha256, path.read_bytes()


def run(manifest_path: Path, rules_dir: Path, samples_dir: Path) -> dict[str, Any]:
    """평가를 실행해 JSON으로 직렬화할 dict를 돌려준다. 입력 오류는 예외로 올린다."""

    # yara_x 로딩은 실제 실행 때만 한다(evaluation 패키지는 엔진에 의존하지 않는다).
    from detection.yara_x_engine import YaraXEngine, read_rule_directory

    entries = load_manifest(manifest_path)
    if not samples_dir.is_dir():
        raise NotADirectoryError(f"sample directory does not exist: {samples_dir}")
    source = read_rule_directory(rules_dir)
    rules = rule_names_from_source(source)
    engine = YaraXEngine(source)

    files = hash_files(samples_dir)
    index = _first_path_by_hash(files)
    wanted = {e.sha256 for e in entries}
    listed = {sha: path for sha, path in index.items() if sha in wanted}
    outcome = scan_samples(engine, _read_samples(listed))
    result = evaluate(entries, outcome.predictions, rules)

    report = result.to_dict()
    report["inputs"] = {
        "manifest_entries": len(entries),
        "rules": sorted(rules),
        # 디스크의 파일 수(내용이 같은 파일도 각각 센다)와 고유 SHA-256 수를 따로 둔다.
        "sample_files": len(files),
        "unique_samples": len(index),
        "unlisted_files": sum(1 for sha, _ in files if sha not in wanted),
    }
    report["scan_errors"] = dict(sorted(outcome.errors.items()))
    report["timing"] = {
        "total_scan_seconds": outcome.total_scan_seconds,
        "per_sample_seconds": dict(sorted(outcome.scan_seconds.items())),
    }
    return report


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    import yara_x

    try:
        report = run(Path(args.manifest), Path(args.rules), Path(args.samples))
    except FileNotFoundError as exc:
        print(f"error: file not found: {exc.filename or exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    except ManifestError as exc:
        print(f"error: invalid manifest: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    except (NotADirectoryError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    except yara_x.CompileError as exc:
        print(f"error: rule compilation failed: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    except OSError as exc:
        # 권한 없음 등 읽기 실패. 위의 FileNotFoundError·NotADirectoryError 다음에 둔다.
        where = f" {exc.filename}" if exc.filename else ""
        print(f"error: could not read input{where}: {exc.strerror or exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    output = json.dumps(report, ensure_ascii=False, indent=2)
    if args.json_path:
        target = Path(args.json_path)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(output + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"error: could not write metrics to {target}: {exc}", file=sys.stderr)
            return EXIT_OUTPUT_ERROR
        print(f"Metrics written to {target}")
    else:
        print(output)

    if args.fail_on_smoke and not all(s["passed"] for s in report["smoke"]):
        print("error: smoke check failed", file=sys.stderr)
        return EXIT_SMOKE_FAILED
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
