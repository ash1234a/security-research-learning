# AI Red vs Blue Security Lab — 코드 리뷰 및 다음 개발 로드맵

작성 기준: `main` 브랜치의 `ai-red-blue-lab/` 실제 구현과 기존 개발 계획 문서

## 1. 결론

현재 프로젝트는 **Phase 1 — 정적 분석기 MVP가 실제 코드로 구현된 상태**다. 단순 계획 문서만 있는 프로젝트는 아니다.

현재 구현 범위:

- SHA-256 계산
- 파일 크기 및 기본 형식 표시
- 전체 파일 Shannon entropy 계산
- ASCII / UTF-16LE 문자열 추출
- Windows PE 파싱
  - 섹션 정보와 섹션별 entropy
  - 실행/쓰기 권한
  - imports / exports
  - entry point / image base / subsystem
  - Authenticode 보안 디렉터리 존재 여부
- 휴리스틱 위험 특징 생성
- JSON 보고서 출력
- pytest 기본 테스트

구조도 `core.py`, `pe_parser.py`, `strings.py`, `entropy.py`, `cli.py`로 나뉘어 있어 다음 단계로 확장하기 좋은 편이다.

다만 Phase 2로 바로 넘어가기 전에 **입력 검증, 스키마 안정화, PE 파서 테스트, 대용량 파일 처리**를 먼저 보강하는 것이 좋다.

---

## 2. 실제 코드에서 잘 된 부분

### 2.1 파일을 실행하지 않는 정적 분석 구조

현재 분석기는 입력 파일을 읽고 PE 메타데이터와 문자열을 분석하지만 실행하지 않는다. 초기 보안 연구 도구로서 안전한 출발점이다.

### 2.2 결과가 JSON 직렬화 가능한 구조

`analyze_file()` 결과가 사전 구조이고 `report_to_json()`으로 바로 직렬화된다. 이후 YARA 평가기, AI 분석기, 대시보드가 같은 결과 형식을 공유하기 쉽다.

### 2.3 `risk_features`가 이미 구조화되어 있음

현재 위험 특징은 단순 문자열이 아니라 다음과 같은 필드를 가진다.

```json
{
  "severity": "medium",
  "feature": "high_file_entropy",
  "detail": "entropy=7.5432"
}
```

즉 구조화를 새로 시작할 필요는 없다. 앞으로 식별자와 근거 필드만 확장하면 된다.

### 2.4 잘못된 PE에 대한 최소 방어가 존재함

파일이 `MZ`로 시작해 PE 후보로 분류되더라도 `pefile.PEFormatError`가 발생하면 프로그램 전체가 즉시 죽지 않고 `errors`에 기록한다.

### 2.5 기능별 모듈 분리가 적절함

```text
analyzer/
├─ core.py
├─ pe_parser.py
├─ strings.py
├─ entropy.py
└─ cli.py
```

현재 규모에서는 과도하게 복잡하지 않으면서도 확장하기 좋은 구조다.

---

## 3. 실제 코드에서 확인된 개선점

### P0-1. 파일 형식 판별이 `MZ` 두 바이트에 지나치게 의존함

현재 구현:

```python
"file_type": "PE" if data.startswith(b"MZ") else "unknown"
```

`MZ`로 시작하기만 하면 일단 PE로 표시된다. 잘린 파일이나 임의 데이터도 PE라고 표시된 뒤 파싱 오류가 붙을 수 있다.

권장 방식:

- `MZ`는 `PE candidate` 판별에만 사용
- 실제 `pefile.PE()` 파싱 성공 후 `file_type = "PE"`
- 파싱 실패 시 `file_type = "invalid_pe"` 또는 `unknown`

### P0-2. `--string-limit` 음수 입력 검증이 없음

현재 `argparse`에서 단순히 `type=int`만 지정되어 있다.

따라서 `--string-limit -1`처럼 음수를 주면 문자열 추출 코드의 `values[:limit]` 동작 때문에 의도와 다른 결과가 나온다.

권장 방식:

- CLI에서 0 이상의 정수만 허용
- 또는 `analyze_file()` 내부에서도 방어적으로 검사

### P0-3. 테스트에 PE 파서 검증이 없음

현재 테스트는 다음 세 파일뿐이다.

```text
tests/
├─ test_core.py
├─ test_entropy.py
└─ test_strings.py
```

`test_core.py`도 비-PE 파일 하나를 분석하는 수준이다. 즉 현재 프로젝트의 핵심인 `pe_parser.py`가 사실상 직접 테스트되지 않는다.

최소 추가 테스트:

- 정상 PE
- `MZ`만 있는 잘린 파일
- 잘못된 PE 헤더
- import가 없는 PE
- export가 없는 PE
- 0바이트 파일
- 비정상 섹션 이름
- 높은 entropy 섹션
- writable + executable 섹션

### P0-4. 전체 파일을 한 번에 메모리로 읽음

현재 `read_bytes()`로 전체 파일을 메모리에 올린 뒤 해시, entropy, 문자열 추출을 수행하고, PE 파서도 파일을 다시 읽는다.

작은 실행파일에서는 문제가 없지만 대형 파일 데이터셋을 돌릴 때 메모리와 처리시간이 불필요하게 커질 수 있다.

권장 방향:

- 파일 크기 상한 또는 경고 추가
- SHA-256은 스트리밍 계산 가능
- 문자열 추출은 향후 청크 방식 고려
- 분석 시간과 파일 크기를 결과 metadata에 기록

### P1-1. `risk_features`에 안정적인 식별자가 없음

현재 구조는 이미 괜찮지만 `feature` 문자열과 자유 형식 `detail`에 의존한다.

향후 자동 평가용으로 다음처럼 확장하는 것이 좋다.

```json
{
  "id": "PE_WX_SECTION",
  "severity": "medium",
  "feature": "writable_executable_section",
  "source": "pe",
  "evidence": {
    "section": ".text"
  }
}
```

이렇게 하면 규칙별 오탐률과 특징별 빈도를 안정적으로 집계할 수 있다.

### P1-2. Authenticode는 '존재 여부'만 확인함

현재 `has_authenticode_blob`는 PE 보안 디렉터리가 존재하는지만 확인한다.

이것은 실제 서명이 유효한지, 인증서가 신뢰되는지 검증하는 기능이 아니다.

따라서 현재 이름은 적절하다. 향후 별도 검증 기능을 추가할 때 다음처럼 분리하는 것이 좋다.

```json
{
  "has_authenticode_blob": true,
  "signature_verified": null
}
```

### P1-3. 예외 처리 범위를 조금 더 명확히 해야 함

현재 PE 분석부는 `pefile.PEFormatError`만 처리한다.

초기 단계에서는 괜찮지만 퍼징된 입력이나 비정상 파일을 대량 분석할 계획이라면 파서에서 발생 가능한 오류를 분류하고, 파일 하나의 오류가 전체 배치 작업을 멈추지 않도록 설계해야 한다.

권장 분류:

- 입력 파일 오류
- PE 형식 오류
- 분석기 내부 오류
- 자원 제한 초과

---

## 4. 결과 스키마 권장안

현재의 단순 JSON 구조를 버릴 필요는 없다. 기존 구조를 유지하면서 버전과 범주를 조금 더 명확하게 만드는 편이 좋다.

예시:

```json
{
  "schema_version": 1,
  "file": {
    "path": "sample.exe",
    "name": "sample.exe",
    "size": 123456,
    "sha256": "...",
    "file_type": "PE"
  },
  "analysis": {
    "entropy": 6.41,
    "strings": {
      "ascii": [],
      "utf16le": []
    },
    "pe": {}
  },
  "risk_features": [],
  "detections": {},
  "errors": [],
  "metadata": {
    "analysis_ms": 0
  }
}
```

중요한 것은 필드 배치 자체보다 **한번 공개한 스키마를 버전 없이 계속 바꾸지 않는 것**이다.

---

## 5. 바로 다음 개발 순서

### 1단계 — Phase 1 안정화

먼저 다음 항목을 끝낸다.

- [ ] `string_limit` 입력 검증
- [ ] PE 후보/정상 PE/잘못된 PE 구분
- [ ] PE 파서 테스트 추가
- [ ] 위험 특징 테스트 추가
- [ ] JSON 스키마 테스트 추가
- [ ] 대용량 파일 처리 정책 추가
- [ ] 분석 시간 기록

이 단계까지 완료하면 정적 분석기 MVP를 '작동하는 데모'가 아니라 '다음 모듈이 의존할 수 있는 기반'으로 볼 수 있다.

### 2단계 — YARA/YARA-X 탐지 엔진

권장 구조:

```text
detection/
├─ yara_engine.py
├─ evaluator.py
└─ rules/
   ├─ baseline/
   └─ generated/
```

최초 기능은 단순하게 유지한다.

- 규칙 로드
- 규칙 문법 검사
- 파일 스캔
- 매칭 규칙 기록
- 잘못된 규칙 오류 격리

### 3단계 — 정상/합성 테스트셋

```text
datasets/
├─ benign/
├─ synthetic/
└─ manifests/
```

실제 파일을 무작정 저장소에 올리기보다 해시, 출처, 분류, 예상 결과를 manifest로 관리한다.

### 4단계 — 평가기

최소 지표:

- True Positive
- False Positive
- True Negative
- False Negative
- Detection Rate
- False Positive Rate

이 단계부터 프로젝트가 단순 분석기에서 **탐지 연구 프레임워크**로 넘어간다.

### 5단계 — AI 분석 보조

AI는 탐지 결과의 최종 판정자가 아니라 규칙 후보 생성기로 둔다.

```text
Static Analyzer
      ↓
Analysis JSON
      ↓
AI Rule Proposal
      ↓
Syntax Check
      ↓
Dataset Evaluation
      ↓
Accept / Reject
```

AI가 만든 규칙은 생성 시점, 사용 모델, 프롬프트 버전, 평가 결과와 함께 기록한다.

### 6단계 — 블루팀 자동화

- Sigma 연동
- 이벤트 수집
- 탐지 성공/실패 저장
- 미탐 사례 분류
- 규칙 개선 후보 생성

### 7단계 — 격리형 레드팀 시뮬레이터

외부 시스템 공격 자동화가 아니라 별도 VM에서 사전 정의된 안전한 시나리오만 실행한다.

예시:

- 테스트 파일 생성
- 테스트 프로세스 실행
- 테스트 레지스트리 변경
- 테스트 스크립트 실행
- 격리 네트워크 이벤트 생성

시나리오는 데이터로 관리한다.

```json
{
  "id": "SIM-001",
  "name": "test_script_execution",
  "risk": "low",
  "requires_network": false,
  "expected_events": []
}
```

---

## 6. 권장 최종 구조

```text
ai-red-blue-lab/
├─ README.md
├─ pyproject.toml
├─ analyzer/
│  ├─ core.py
│  ├─ schema.py
│  ├─ pe_parser.py
│  ├─ strings.py
│  ├─ entropy.py
│  └─ cli.py
├─ detection/
│  ├─ yara_engine.py
│  ├─ evaluator.py
│  ├─ rules/
│  │  ├─ baseline/
│  │  └─ generated/
│  └─ sigma/
├─ datasets/
│  ├─ benign/
│  ├─ synthetic/
│  └─ manifests/
├─ agents/
│  ├─ blue_agent.py
│  ├─ red_agent.py
│  └─ judge_agent.py
├─ simulator/
│  ├─ runner.py
│  ├─ isolation_check.py
│  └─ scenarios/
├─ telemetry/
│  ├─ collector.py
│  └─ schema.py
├─ results/
├─ tests/
└─ dashboard/
```

---

## 7. 포트폴리오 관점에서의 핵심

이 프로젝트의 강점은 'AI가 보안을 한다'는 문구가 아니라 **개선 과정을 숫자로 증명할 수 있다는 점**이다.

최종적으로 실제 실험값으로 다음 변화를 보여주는 것이 목표다.

```text
Round 1
Detection Rate : 61%
False Positive : 14%

Round 20
Detection Rate : 89%
False Positive : 4%
```

위 숫자는 예시일 뿐이며 실제 측정 전에는 결과처럼 게시하지 않는다.

포트폴리오에서 보여줄 수 있는 기술:

- Python 모듈 설계
- Windows PE 구조 분석
- 파일 특징 추출
- 탐지 규칙 엔진
- 오탐/미탐 평가
- AI 생성 규칙 자동 검증
- 격리 VM 기반 실험 설계
- Red vs Blue 반복 평가
- 결과 시각화

---

## 8. 다음 커밋 권장 범위

한 번에 Phase 2 전체를 만들지 말고 다음 커밋은 아래 범위로 제한한다.

1. `string_limit` 검증
2. `file_type` 판별 개선
3. 잘못된 PE 테스트 추가
4. PE 파서 테스트 기반 추가
5. `risk_features` 테스트 추가

그 다음 커밋에서 `detection/yara_engine.py`를 추가한다.

이 순서가 현재 코드베이스에서 가장 자연스럽다.
