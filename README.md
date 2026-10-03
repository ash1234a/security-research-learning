# security-research-learning

[![analyzer tests](https://github.com/ash1234a/security-research-learning/actions/workflows/analyzer-tests.yml/badge.svg)](https://github.com/ash1234a/security-research-learning/actions/workflows/analyzer-tests.yml)

보안 연구를 공부하며 남기는 실습 기록과 프로젝트 저장소입니다.
웹 취약점 실습 리포트와, 격리 환경에서 탐지 규칙 개선을 실험하는 방어 연구 프로젝트를 함께 관리합니다.

## 구성

| 경로 | 내용 |
| --- | --- |
| [`ai-red-blue-lab/`](ai-red-blue-lab/) | 정적 분석기 MVP — Windows PE 파일을 실행하지 않고 특징을 추출해 JSON 보고서로 출력 |
| [`reports/port-swigger/`](reports/port-swigger/) | PortSwigger Web Security Academy 실습 리포트 |
| [`docs/`](docs/) | 프로젝트 계획 및 설계 문서 |

## AI Red vs Blue Security Lab

격리된 환경에서 AI 공격 시뮬레이터와 AI 방어 에이전트를 반복 경쟁시켜, 탐지 규칙이 실제로 개선되는지 측정하는 것이 최종 목표입니다.

| 단계 | 내용 | 상태 |
| --- | --- | --- |
| Phase 0 | 프로젝트 기반 (구조, 의존성, 테스트, CI) | 진행 중 |
| Phase 1 | 정적 분석기 MVP (해시, 엔트로피, 문자열, PE 파싱, JSON 보고서) | 대부분 완료 |
| Phase 2 | YARA/YARA-X 탐지 규칙 엔진 | 예정 |
| Phase 3 | AI 분석 보조 (보고서 요약, 규칙 후보 생성·검증) | 예정 |
| Phase 4–7 | 블루팀 자동화, 격리형 레드팀 시뮬레이터, 자동대전, 시각화 | 예정 |

- 사용법: [`ai-red-blue-lab/README.md`](ai-red-blue-lab/README.md)
- 전체 계획: [`docs/ai-red-blue-lab-plan.md`](docs/ai-red-blue-lab-plan.md)

## 실습 리포트

### PortSwigger Web Security Academy

| # | 실습 | 분류 | 난이도 | 날짜 |
| --- | --- | --- | --- | --- |
| 01 | [Unprotected admin functionality](reports/port-swigger/01-unprotected-admin-functionality.md) | Access Control | Apprentice | 2026-09-13 |
| 02 | [User ID controlled by request parameter](reports/port-swigger/02-user-id-controlled-by-request-parameter.md) | Access Control | Apprentice | 2026-09-13 |
| 03 | [Exploiting an API endpoint using documentation](reports/port-swigger/03-exploiting-api-endpoint-using-documentation.md) | API Testing | Apprentice | 2026-09-14 |

## 원칙

- 모든 실습은 의도적으로 취약하게 만든 실습 환경 또는 직접 소유한 격리 환경에서만 수행합니다.
- 실제 악성코드 샘플은 저장소에 올리지 않고, 해시와 분석 결과만 기록합니다.
- 측정하지 않은 수치를 결과처럼 게시하지 않습니다.
