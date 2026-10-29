# AI Red vs Blue Security Lab

격리된 환경에서 정적 분석과 탐지 자동화를 실험하기 위한 방어 연구 프로젝트입니다.

현재 상태: **Phase 1 — Static Analyzer MVP + Phase 2 탐지 엔진 연결 진행 중**

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
- YARA-X 규칙 컴파일·스캔 및 엔진 독립 탐지 결과
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

## 규칙 평가 (매니페스트 + 평가기)

매니페스트는 샘플 파일 없이 `sha256,label,family,source` 4개 열만 기록하는 CSV입니다. `label`은 `malicious`/`benign`, `source`는 `synthetic`, `pip-benign`, `eicar`, `amtso`, `ember2018`, `bodmas` 중 하나입니다.

```python
from detection.yara_x_engine import YaraXEngine
from evaluation import evaluate, load_manifest, rule_names_from_source, scan_samples

manifest = load_manifest("manifest.csv")
outcome = scan_samples(YaraXEngine(rule_source), samples)  # samples: (sha256, bytes) 목록
result = evaluate(manifest, outcome.predictions, rule_names_from_source(rule_source))
print(result.to_dict())
```

- 규칙별 TP/FP/FN/TN, precision, recall, 정상 파일 오탐률(`benign_fp_rate`)과 "어느 규칙이든 발화"(`__any__`) 전체 지표를 냅니다.
- 규칙 목록은 필수 입력입니다. 한 번도 발화하지 않은 규칙도 결과에 남아 FN/recall을 볼 수 있습니다.
- `eicar`, `amtso` 출처는 집계에서 빼고 발화 확인(pass/fail)으로만 보고합니다. `eicar`는 `EICAR_Smoke_Test`가 발화해야 통과(`criterion: expected-rules`)이고, 기대 규칙이 정해지지 않은 출처(`amtso`)는 아무 규칙 발화 여부만 봅니다(`criterion: any-rule`).
- 스캔 예외는 샘플별로 격리해 `scan_failures`로(smoke 포함), 예측이 없는 항목은 `missing`으로 따로 셉니다.
- `scan_samples()`는 샘플별 `scan()` 소요 시간(`scan_seconds`, 초)을 기록합니다. 실패한 샘플도 포함합니다.
- 분모가 0인 비율은 `null`입니다(측정하지 않은 값을 0으로 쓰지 않음).
- 평가기는 (예측, 라벨) 쌍만 받으므로 피처 데이터셋(EMBER 등)의 예측도 같은 방식으로 평가할 수 있습니다.

### 평가 CLI

```bash
redblue-evaluate --manifest manifest.csv --rules rules --samples /path/to/samples --json results/metrics.json
```

- 샘플 디렉터리를 재귀로 훑어 파일마다 SHA-256을 계산하고, 매니페스트에 있는 해시만 스캔합니다. 파일 이름은 보지 않습니다. 샘플은 읽기만 하고 실행하지 않습니다.
- 규칙 목록은 `--rules` 디렉터리의 `.yar` 소스 전체에서 읽습니다(`YaraXEngine.from_directory()`와 같은 `read_rule_directory()` 사용).
- 출력 JSON은 평가기 결과에 `inputs`(매니페스트 항목 수, 규칙 목록, 디스크의 샘플 파일 수 `sample_files`, 고유 SHA-256 수 `unique_samples`, 매니페스트에 없는 파일 수 `unlisted_files`), `scan_errors`, `timing`(총·샘플별 스캔 시간)을 더합니다. 디렉터리에 없는 매니페스트 항목은 `missing`입니다.
- 종료 코드: `0` 성공, `1` `--fail-on-smoke`일 때 smoke 확인 실패, `2` 입력 오류(매니페스트 형식, 경로, 규칙 컴파일, 읽기 권한 없음 등 `OSError`), `3` 출력 파일 쓰기 실패.

### EMBER 2018 / BODMAS 모델 예측 평가

피처·라벨 데이터셋의 **정답 라벨**과 모델이 **별도로 산출한 예측 점수**를
SHA-256으로 결합해 기존 평가기의 TP/FP/FN/TN·정밀도·재현율·오탐률을 산출합니다.
원본 실행 파일은 필요하지 않습니다. 모델을 학습하거나 특징 벡터에서 예측을
만들어내는 명령은 아니며, 점수는 모델에서 별도로 내보내야 합니다.

추가 의존성(BODMAS의 `npz` 라벨을 읽는 경우만):

```bash
pip install -e '.[feature-datasets]'
```

모델 출력 CSV는 다음 **정확한 헤더**를 가집니다(점수는 0~1 악성 확률).

```csv
sha256,score
```

EMBER 2018 원본 `train_features_*.jsonl`, `test_features.jsonl` 등은
`sha256`, `label`(0=정상, 1=악성, -1=미라벨), `avclass`를 읽습니다.
미라벨(`-1`) 행은 집계에서 제외합니다.

```bash
redblue-feature-evaluate --dataset ember2018 --metadata data/ember2018/test_features.jsonl --scores model_scores.csv --threshold 0.5 --json results/ember_metrics.json
```

BODMAS는 공식 원본 `bodmas_metadata.csv`(SHA-256, 최초 관측 시점, 악성코드 계열 3열)와
`bodmas.npz`의 `y` 라벨을 **같은 행 순서**로 읽습니다. `X` 특징 배열이나 실행 파일은
읽지 않습니다. 행 개수가 다르면 평가를 중단합니다.

```bash
redblue-feature-evaluate --dataset bodmas --metadata data/bodmas_metadata.csv --labels-npz data/bodmas.npz --scores model_scores.csv --json results/bodmas_metrics.json
```

- `model_positive`: 점수가 임계값 이상인 경우만 양성으로 분류합니다. `__any__`는 기존 평가기와 동일한 전체 지표입니다.
- 매니페스트에 있지만 예측 CSV에 없는 해시는 `missing`으로 표시하며 TN/FN에 포함하지 않습니다.
- 데이터셋에 없는 해시의 예측은 `inputs.unused_predictions`로 별도 계수합니다.
- 입력 파일·모델 점수는 GitHub에 커밋하지 않습니다. 합성 데이터만 단위 테스트에 사용합니다.
- 출처: [EMBER 공식 저장소](https://github.com/elastic/ember), [BODMAS 공식 안내](https://whyisyoung.github.io/BODMAS/).

## 보고서 예시

```json
{
  "schema_version": 3,
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
  "risk_features": [],
  "detections": null
}
```

`detections`는 탐지 엔진을 실행하지 않았거나 탐지 단계가 오류로 완료되지 못했으면 `null`, 실행을 정상 완료했지만 일치 규칙이 없으면 `[]`, 규칙이 일치하면 규칙명·네임스페이스·메타데이터 객체 목록입니다. 탐지 오류의 원인은 `errors`에 기록합니다. 이 구분은 후속 평가기가 미실행·실패 샘플을 TN/FN으로 잘못 집계하지 않도록 유지합니다.

`file_type` 값:

| 값 | 의미 |
| --- | --- |
| `PE` | PE 파싱 성공 |
| `MZ` | `MZ` 시그니처는 있지만 유효한 PE가 아님 (오류는 `errors`에 기록) |
| `unknown` | 그 외 |

`pe` 객체에는 위 필드 외에 헤더 구조, Delay Import, Data Directory, TLS, Debug, relocation, resource, Rich Header, overlay, Authenticode 디렉터리 정보가 들어갑니다. 필드 설명은 [`docs/pe-parser.md`](../docs/pe-parser.md)에 있습니다.

스키마 변경 이력: v2에서 로컬 절대 경로를 담던 `file` 필드를 제거하고 `file_type`에 `MZ`를 추가했습니다. v3에서 `detections`를 추가해 탐지 미실행·실패(`null`)과 스캔 후 일치 없음(`[]`)을 구분합니다.

## 주의

- 실제 악성 샘플은 이 GitHub 저장소에 업로드하지 않습니다.
- 현재 버전은 정적 분석과 정적 탐지만 수행하며 샘플을 실행하지 않습니다.
- 향후 동적 분석 기능은 별도 격리 VM에서만 구현합니다.
- `risk_features`는 휴리스틱 정보이며 악성 판정기가 아닙니다.

## 다음 단계

1. YARA/YARA-X 탐지 결과 보고서 연결 완료
2. 테스트용 정상 파일 데이터셋 구성 완료 (pip 내장 정상 PE)
3. 규칙별 탐지/오탐 평가기 완료 (매니페스트 로더, 규칙 디렉터리 로딩, 샘플별 스캔 시간, `redblue-evaluate` CLI). EMBER/BODMAS 외부 모델 점수 평가 연결 구현
4. AI 기반 분석 보고서 및 탐지 규칙 후보 생성
5. 격리형 블루팀/레드팀 시뮬레이션

전체 계획은 [`../docs/ai-red-blue-lab-plan.md`](../docs/ai-red-blue-lab-plan.md)를 참고하십시오.
