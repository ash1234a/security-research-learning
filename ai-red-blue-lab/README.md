# AI Red vs Blue Security Lab

격리된 환경에서 정적 분석과 탐지 자동화를 실험하기 위한 방어 연구 프로젝트입니다.

현재 상태: **Phase 1 — Static Analyzer MVP**

## 현재 구현 기능

- SHA-256 해시 계산
- 파일 크기 및 기본 형식 식별
- 전체 파일 Shannon entropy 계산
- ASCII / UTF-16LE 문자열 추출
- Windows PE 파싱
  - 섹션 정보
  - 섹션별 entropy
  - 실행/쓰기 권한
  - imports / exports
  - entry point / image base / subsystem
  - Authenticode 보안 디렉터리 존재 여부
- 간단한 위험 특징 표시
  - 높은 entropy
  - writable + executable 섹션
  - 보안상 주목할 import
  - Authenticode blob 부재
- 손상·변조된 PE 입력에서도 중단 없이 `errors`에 기록
- JSON 보고서 출력 (로컬 경로는 기록하지 않고 파일 이름만 기록)
- pytest 테스트 + GitHub Actions CI

> 이 도구는 파일을 실행하지 않는 정적 분석기입니다. 탐지 결과는 악성 여부의 확정 판정이 아니라 추가 분석을 위한 특징 정보입니다.

## 설치

Python 3.11 이상을 권장합니다.

```bash
cd ai-red-blue-lab
python -m venv .venv
```

Windows:

```powershell
.venv\Scripts\activate
pip install -e ".[dev]"
```

WSL / Linux:

```bash
source .venv/bin/activate
pip install -e '.[dev]'
```

## 사용법

화면에 JSON 출력:

```bash
redblue-analyze sample.exe
```

또는:

```bash
python -m analyzer.cli sample.exe
```

파일로 저장:

```bash
redblue-analyze sample.exe --json results/sample.json
```

문자열 저장 개수 제한:

```bash
redblue-analyze sample.exe --string-limit 50
```

종료 코드: `0` 성공, `2` 입력 오류(파일 없음·권한 없음·잘못된 옵션), `3` 보고서 저장 실패.

## 테스트

```bash
pytest -q
```

테스트에 필요한 PE 파일은 저장소에 넣지 않고 `tests/pe_builder.py`가 실행 코드 없는 최소 PE32 바이너리를 직접 만들어 사용합니다. 섹션 권한, 섹션 엔트로피, import, 서명 블롭 유무, 손상된 헤더를 각각 조작해 탐지 로직을 검증합니다.

## 보고서 예시

```json
{
  "schema_version": 2,
  "name": "sample.exe",
  "size": 123456,
  "sha256": "...",
  "entropy": 6.41,
  "file_type": "PE",
  "pe": {
    "entry_point": 4096,
    "sections": [],
    "imports": [],
    "has_authenticode_blob": false
  },
  "errors": [],
  "risk_features": []
}
```

`file_type` 값:

| 값 | 의미 |
| --- | --- |
| `PE` | PE 파싱 성공 |
| `MZ` | `MZ` 시그니처는 있지만 유효한 PE가 아님 (오류는 `errors`에 기록) |
| `unknown` | 그 외 |

`pe` 객체에는 위 필드 외에 헤더 구조, Delay Import, Data Directory, TLS, Debug, relocation, resource, Rich Header, overlay, Authenticode 디렉터리 정보가 들어갑니다. 필드 설명은 [`docs/pe-parser.md`](../docs/pe-parser.md)에 있습니다.

스키마 변경 이력: v2에서 로컬 절대 경로를 담던 `file` 필드를 제거하고 `file_type`에 `MZ`를 추가했습니다.

## 주의

- 실제 악성 샘플은 이 GitHub 저장소에 업로드하지 않습니다.
- 현재 버전은 정적 분석만 수행하며 샘플을 실행하지 않습니다.
- 향후 동적 분석 기능은 별도 격리 VM에서만 구현합니다.
- `risk_features`는 휴리스틱 정보이며 악성 판정기가 아닙니다.

## 다음 단계

1. YARA/YARA-X 연동
2. 테스트용 정상 파일 데이터셋 구성
3. 규칙별 탐지/오탐 평가기
4. AI 기반 분석 보고서 및 탐지 규칙 후보 생성
5. 격리형 블루팀/레드팀 시뮬레이션

전체 계획은 [`../docs/ai-red-blue-lab-plan.md`](../docs/ai-red-blue-lab-plan.md)를 참고하십시오.
