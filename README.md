# localkey

보안키(YubiKey 5C Nano, 펌웨어 5.7.4)의 외부 동작을 재현하는 소프트웨어 엔진입니다. Rust로 처음부터 새로
작성합니다. 지금은 **설계 단계**입니다. `docs/DESIGN.md`가 승인되면 단계별로 구현합니다.

- 엔진은 전송 계층과 분리된 동기식 상태 기계입니다. USB/HID 장치 등록, 데몬, UI는 이후 "프로그램화"
  단계에서 만듭니다.
- 다른 프로젝트의 코드는 쓰지 않습니다. 예외는 암호 원시 기능뿐이고, `lk-crypto` 한 곳에서만 씁니다.
  목록과 라이선스는 `THIRD_PARTY.md`에 있습니다.
- 제조사 증명 신뢰, 보안 칩, 물리 터치 센서는 소프트웨어로 재현할 수 없습니다.

## 구성

| 경로 | 내용 |
| --- | --- |
| `docs/DESIGN.md` | 설계 문서 (경계, 장치 모델, 크레이트, 저장, 암호 정책, 구현 순서, 미결 질문) |
| `crates/` | 워크스페이스 크레이트 15개 (현재는 경계 타입과 문서만 있는 뼈대) |
| `reference/` | 실물 키에서 읽은 공개 바이트, legacy 동작 카탈로그, 프로필 값 |
| `tools/license_check.py` | 의존성 라이선스와 "외부 의존은 `lk-crypto`에만" 규칙 검사 |
| `THIRD_PARTY.md` | 제3자 크레이트 목록 (자동 생성) |

## 빌드와 검사

```sh
CARGO_BUILD_JOBS=2 cargo check --workspace
CARGO_BUILD_JOBS=2 cargo test --workspace
python3 tools/license_check.py            # 정책 검사
python3 tools/license_check.py --write    # THIRD_PARTY.md 갱신
```

## 이전 구현

이전 구현은 `madeye/swpasskey` 포크와 Python 카드 모듈로 된 v0.64입니다. 태그 `legacy-v0.64.0`과 브랜치
`legacy/v0.64-tooling`에만 남아 있습니다. 새 엔진은 그 코드를 쓰지 않습니다. 동작 기록만
`reference/BEHAVIOR_CATALOG.md`로 참고합니다.
