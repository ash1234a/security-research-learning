"""pip로 설치되는 패키지에 들어 있는 정상(benign) Windows PE 모음.

데이터 사용 방침 2번(테스트 파일)의 "pip 내장 정상 PE 코퍼스"를 구현한다.
파일은 레포에 커밋하지 않고, dev 의존성으로 설치된 패키지 안에서 찾는다.

- distlib: 스크립트 런처 t32/t64/w32/w64(-arm).exe (x86, x64, ARM64)

모든 파일은 읽기만 하고 실행하지 않는다. 매니페스트의 ``source`` 값은
이슈 #5 안건 4에서 합의한 ``pip-benign``이다.
"""

from __future__ import annotations

import hashlib
import importlib.util
from dataclasses import dataclass
from pathlib import Path

SOURCE = "pip-benign"
LABEL = "benign"

# (패키지 이름, 패키지 디렉터리 안의 glob 패턴)
_PROVIDERS: tuple[tuple[str, str], ...] = (("distlib", "*.exe"),)


@dataclass(frozen=True)
class BenignSample:
    path: Path
    package: str
    sha256: str

    @property
    def name(self) -> str:
        return f"{self.package}/{self.path.name}"


def _package_dir(package: str) -> Path | None:
    spec = importlib.util.find_spec(package)
    if spec is None or not spec.submodule_search_locations:
        return None
    return Path(next(iter(spec.submodule_search_locations)))


def collect_benign_pe() -> list[BenignSample]:
    """설치된 패키지에서 MZ로 시작하는 파일을 모아 sha256 기준으로 중복 제거해 돌려준다."""

    samples: dict[str, BenignSample] = {}
    for package, pattern in _PROVIDERS:
        base = _package_dir(package)
        if base is None:
            continue
        for path in sorted(base.glob(pattern)):
            data = path.read_bytes()
            if not data.startswith(b"MZ"):
                continue
            digest = hashlib.sha256(data).hexdigest()
            samples.setdefault(digest, BenignSample(path=path, package=package, sha256=digest))
    return sorted(samples.values(), key=lambda s: s.name)
