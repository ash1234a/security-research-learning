# PE Parser Module

## 목적

`analyzer/pe_parser.py`는 Windows PE 파일을 실행하지 않고 구조적 사실만 추출하는 정적 분석 계층입니다.

탐지 판단과 위험도 평가는 이 모듈 밖에서 수행합니다. 이 분리를 통해 다음 두 문제를 별도로 검증할 수 있습니다.

1. PE 구조를 올바르게 읽었는가
2. 읽은 특징을 바탕으로 한 휴리스틱 판단이 올바른가

## 현재 출력 범위

- DOS / COFF / Optional Header
- Section metadata
  - RVA / raw offset / size
  - entropy
  - executable / readable / writable flags
- Imports / Delay Imports
- Exports
- Data Directories
- Entry Point 및 Entry Point Section
- TLS directory metadata
- Debug directory metadata
- Base relocation 요약
- Resource top-level summary
- Rich Header summary
- Overlay 존재 여부와 크기
- Authenticode security directory metadata

기존 `core.py`가 사용하던 최상위 필드는 유지합니다.

## 입력 인터페이스

`parse_pe(data: bytes)`는 파일 경로가 아니라 바이트를 받습니다. `analyze_file()`이 파일을 한 번만 읽어 `analyze_bytes()`로 넘기고, 파서는 `pefile.PE(data=...)`로 메모리에서 분석합니다. 테스트는 `tests/pe_builder.py`로 만든 PE 바이트를 바로 넣습니다.

- overlay 크기는 파일 크기 대신 입력 길이(`len(data)`)로 계산합니다.
- `rich_header.key`는 pefile이 `bytes`로 돌려주므로 JSON 직렬화를 위해 hex 문자열로 바꿉니다.
- `authenticode.signature_verified`는 아직 검증하지 않으므로 항상 `null`입니다.

## 설계 원칙

```text
PE file
  ↓
pe_parser.py
  ↓
raw structural facts
  ↓
heuristics / rules
  ↓
risk findings
```

PE 파서는 가능한 한 사실만 반환합니다.

예:

```json
{
  "name": ".text",
  "entropy": 7.42,
  "executable": true,
  "writable": false
}
```

이 정보가 의심스러운지 판단하는 로직은 별도 휴리스틱 계층에서 처리합니다.

## 다음 구현 후보

- TLS callback 실제 주소 목록 추출
- Resource tree 세부 분석
- Import ordinal 및 thunk 세부 정보
- Export RVA / ordinal 세부 정보
- Rich Header 세부 해석
- Authenticode 실제 서명 검증
- PE checksum 검증
- Section overlap / alignment 이상 탐지용 원시 지표
- Header / section boundary 검증
- Corkami PE corpus 기반 회귀 테스트
- 정상 PE corpus 기반 parser crash 및 오탐 통계

## 테스트 전략

`tests/test_pe_parser.py`는 헬퍼 함수 단위 테스트와, `pe_builder`로 만든 PE를 `parse_pe()`에 넣어 확장 필드(entry point section, data directories, overlay, authenticode, JSON 직렬화)를 확인하는 테스트로 구성됩니다.

이후 실제 PE corpus를 추가하면 다음 항목을 자동 측정합니다.

- parser crash 수
- PEFormatError 수
- JSON 직렬화 실패 수
- 비정상 구조 처리 결과
- 정상 샘플별 추출 특징 차이
