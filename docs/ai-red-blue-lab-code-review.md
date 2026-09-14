# AI Red vs Blue Security Lab — 코드 리뷰 및 다음 개발 로드맵

작성 기준: 현재 `ai-red-blue-lab/` 디렉터리와 프로젝트 계획 문서 기준

## 1. 현재 상태 요약

현재 프로젝트는 **Phase 1 — 정적 분석기 MVP** 단계다.

이미 구현된 것으로 확인되는 범위:

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
- JSON 보고서 출력
- pytest 기반 기본 테스트

현재 구조는 정적 분석기의 최소 골격으로는 적절하다. 특히 기능별로 `core.py`, `pe_parser.py`, `entropy.py`, `strings.py`, `cli.py`를 분리한 점은 향후 확장에 유리하다.

---

## 2. 지금 단계에서의 강점

### 2.1 정적 분석 중심의 안전한 출발점

파일을 실행하지 않고 분석하는 구조이므로 프로젝트 초기 단계에서 불필요한 위험을 줄일 수 있다.

### 2.2 JSON 중심 출력

추후 다음 구성요소가 동일한 결과를 공유하기 쉽다.

- AI 분석 보조
- YARA/YARA-X 평가기
- 웹 대시보드
- 탐지 결과 저장소
- 블루팀 에이전트

### 2.3 기능 분리 구조

분석 기능이 파일 단위로 분리되어 있어 다음 확장이 비교적 쉽다.

예:

```text
analyzer/
├─ core.py
├─ pe_parser.py
├─ strings.py
├─ entropy.py
└─ cli.py
```

이 구조를 유지하면서 기능을 추가하는 편이 좋다.

---

## 3. 현재 부족한 부분

### 3.1 분석 결과 스키마 고정 필요

현재 JSON 구조가 앞으로 계속 변경되면 이후 YARA 평가기, AI 분석기, 대시보드가 모두 영향을 받는다.

우선 다음처럼 명시적인 스키마를 고정하는 것이 좋다.

```json
{
  "schema_version": 1,
  "file": {},
  "static_analysis": {},
  "pe": {},
  "risk_features": [],
  "detections": {},
  "metadata": {}
}
```

권장 작업:

- `schema.py` 추가
- 필수 필드 정의
- 누락 필드 처리 방식 정의
- 스키마 버전 관리

### 3.2 위험도 판정 근거의 구조화

현재 `risk_features`가 단순 문자열 목록 형태라면 이후 평가가 어렵다.

권장 형태:

```json
{
  "id": "PE_WX_SECTION",
  "severity": "medium",
  "source": "pe",
  "evidence": {
    "section": ".text"
  }
}
```

이 구조를 사용하면 나중에 다음을 계산할 수 있다.

- 어떤 특징이 가장 자주 발생했는지
- 어떤 탐지 규칙이 어떤 특징을 사용했는지
- 오탐이 많이 발생하는 특징은 무엇인지

### 3.3 파일 형식 식별 강화

확장자만으로 형식을 판단하면 쉽게 틀릴 수 있다.

다음 우선순위를 권장한다.

1. 매직 바이트
2. PE 헤더 검증
3. MIME 또는 라이브러리 기반 식별
4. 확장자는 보조 정보로만 사용

### 3.4 Authenticode 판단 정밀화

보안 디렉터리 존재 여부와 실제 서명 검증은 다르다.

현재 단계에서는 다음 표현이 안전하다.

- `has_authenticode_blob`
- `signature_verified: null`

향후 Windows 검증 API 또는 별도 서명 검증 모듈을 추가한 뒤 실제 검증 상태를 넣는 편이 좋다.

### 3.5 테스트 범위 확대 필요

정상 입력만 테스트하면 파서 안정성을 평가하기 어렵다.

추가할 테스트 범위:

- 0바이트 파일
- 매우 작은 파일
- 잘린 PE 파일
- 잘못된 PE 헤더
- import가 없는 PE
- export가 없는 PE
- 비정상 섹션 이름
- 높은 엔트로피 파일
- UTF-16 문자열만 존재하는 파일
- 대용량 파일

---

## 4. 다음 구현 우선순위

### P0 — 분석기 안정화

먼저 Phase 1을 완성한다.

- [ ] 결과 스키마 고정
- [ ] 예외 처리 정리
- [ ] 잘못된 PE 처리
- [ ] 테스트 케이스 확대
- [ ] 대용량 파일 처리 제한
- [ ] 분석 시간 기록

완료 기준:

```bash
pytest -q
```

이 명령이 다양한 정상/비정상 테스트 파일에서 안정적으로 통과해야 한다.

---

### P1 — YARA/YARA-X 탐지 엔진

다음 단계의 핵심이다.

권장 구조:

```text
detection/
├─ yara_engine.py
├─ rules/
│  ├─ baseline/
│  └─ generated/
└─ evaluator.py
```

기능:

- 규칙 로드
- 규칙 문법 검사
- 파일 스캔
- 매칭 규칙 기록
- 오류 규칙 격리

JSON 예시:

```json
{
  "detections": {
    "yara": {
      "matches": [
        {
          "rule": "Suspicious_Test_Rule",
          "namespace": "baseline"
        }
      ]
    }
  }
}
```

---

### P2 — 정상 파일 데이터셋과 오탐 평가기

블루팀 프로젝트에서 매우 중요한 단계다.

악성 샘플만 탐지하면 성능을 제대로 평가할 수 없다.

최소한 다음 구성을 만든다.

```text
datasets/
├─ benign/
├─ synthetic/
└─ manifests/
```

실제 파일 자체를 GitHub에 모두 올리기보다는 해시와 출처, 분류 정보를 manifest로 관리하는 것이 좋다.

평가 지표:

- 탐지율
- 오탐률
- 미탐률
- 규칙별 탐지 수
- 규칙별 오탐 수

---

### P3 — 평가기 구현

권장 파일:

```text
detection/evaluator.py
```

예시 출력:

```json
{
  "total": 100,
  "true_positive": 42,
  "false_positive": 3,
  "true_negative": 50,
  "false_negative": 5,
  "detection_rate": 0.893,
  "false_positive_rate": 0.057
}
```

이 단계부터 프로젝트가 단순 분석기를 넘어 '탐지 연구 프레임워크'가 된다.

---

### P4 — AI 분석 보조

AI는 판정자가 아니라 후보 생성기로 제한하는 현재 설계를 유지한다.

권장 역할:

- 정적 분석 결과 요약
- 위험 특징 설명
- YARA 규칙 후보 생성
- 생성 규칙 문법 검사
- 테스트셋으로 자동 평가
- 기존 규칙보다 성능이 나쁘면 폐기

권장 흐름:

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

AI가 생성한 규칙은 별도 디렉터리에 저장한다.

```text
rules/generated/
```

그리고 생성 시점, 모델, 프롬프트 버전, 평가 결과를 같이 기록한다.

---

### P5 — 블루팀 자동화

이 단계에서 Sigma 로그 탐지를 추가한다.

권장 기능:

- 이벤트 수집
- Sigma 규칙 평가
- 탐지 성공/실패 저장
- 미탐 사례 자동 분류
- 규칙 개선 후보 생성

---

### P6 — 레드팀 시뮬레이터

실제 외부 공격 자동화가 아니라 격리된 VM에서 사전 정의된 안전한 시나리오를 실행하는 구조를 유지한다.

권장 시나리오 형태:

```json
{
  "id": "SIM-001",
  "name": "test_script_execution",
  "expected_events": [],
  "risk": "low",
  "requires_network": false
}
```

초기에는 단순 이벤트 생성 중심으로 시작한다.

예:

- 파일 생성
- 테스트 프로세스 실행
- 테스트 레지스트리 변경
- 테스트 스크립트 실행
- 로컬 네트워크 이벤트 생성

---

## 5. 권장 최종 구조

```text
ai-red-blue-lab/
├─ README.md
├─ pyproject.toml
│
├─ analyzer/
│  ├─ core.py
│  ├─ schema.py
│  ├─ pe_parser.py
│  ├─ strings.py
│  ├─ entropy.py
│  └─ cli.py
│
├─ detection/
│  ├─ yara_engine.py
│  ├─ evaluator.py
│  ├─ rules/
│  │  ├─ baseline/
│  │  └─ generated/
│  └─ sigma/
│
├─ datasets/
│  ├─ benign/
│  ├─ synthetic/
│  └─ manifests/
│
├─ agents/
│  ├─ blue_agent.py
│  ├─ red_agent.py
│  └─ judge_agent.py
│
├─ simulator/
│  ├─ runner.py
│  ├─ isolation_check.py
│  └─ scenarios/
│
├─ telemetry/
│  ├─ collector.py
│  └─ schema.py
│
├─ results/
├─ tests/
└─ dashboard/
```

---

## 6. 포트폴리오 관점에서 중요한 부분

이 프로젝트에서 가장 중요한 것은 코드 양이 아니라 **측정 가능한 개선 과정**이다.

최종적으로 다음 그래프나 숫자를 제시할 수 있어야 한다.

```text
Round 1
Detection Rate : 61%
False Positive : 14%

Round 20
Detection Rate : 89%
False Positive : 4%
```

단, 실제 실험 전에는 예시 수치를 실제 결과처럼 사용하지 않는다.

포트폴리오에서 특히 강조할 수 있는 부분:

- 정적 분석기 직접 구현
- Windows PE 구조 분석
- 탐지 규칙 엔진
- 오탐/미탐 평가
- AI 생성 규칙의 자동 검증
- 격리 VM 기반 보안 실험
- Red vs Blue 반복 평가 구조
- 성능 변화 시각화

---

## 7. 바로 다음 커밋에서 구현할 항목

다음 커밋은 범위를 좁혀 아래 4개만 처리하는 것을 권장한다.

1. `analyzer/schema.py` 추가
2. `risk_features` 구조화
3. 잘못된 PE 입력 테스트 추가
4. `detection/yara_engine.py` 골격 생성

그 다음 커밋에서 YARA 규칙 로딩 및 평가기를 붙인다.

이 순서를 지키면 프로젝트가 한꺼번에 복잡해지는 것을 피하면서도 Phase 2로 자연스럽게 넘어갈 수 있다.
