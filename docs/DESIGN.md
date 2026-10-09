# localkey 엔진 설계

상태: **초안, 검토 요청** (2026-10-10). 이 문서가 승인되면 §10의 순서대로 구현합니다.

## 1. 목표와 비목표

**목표**

- 보안키(YubiKey 5C Nano, 펌웨어 5.7.4)의 외부에서 관찰되는 동작을 재현하는 **엔진**을 Rust로 처음부터
  만든다. 대상은 FIDO2/U2F, OTP, OATH, PIV, OpenPGP, YubiHSM Auth, Security Domain(SCP03/SCP11),
  Management다.
- 엔진은 순수한 프로토콜·상태 처리기다. USB/HID, OS API, 스레드, 파일, 시계에 직접 접근하지 않는다.
  나중에 만들 **프로그램**(데몬, 앱)이 엔진을 감싸 실제 장치처럼 노출한다.
- 같은 입력, 같은 시각, 같은 난수에서 항상 같은 출력을 낸다(결정론). 그래서 모든 동작을 OS 장치 없이
  테스트할 수 있다.
- 다른 프로젝트의 코드를 가져오지 않는다. 예외는 §8의 암호 원시 기능 하나뿐이다.

**비목표**

- 제조사 증명(attestation) 신뢰, 보안 칩의 키 추출 불가성, 물리 터치 센서. 소프트웨어로는 원천적으로
  재현할 수 없다.
- 엔진 단계에서의 OS 장치 등록. macOS 가상 HID 권한, Linux UHID/FunctionFS, PC/SC 드라이버는 §13
  프로그램화 단계에서 다룬다.
- 기존 v0.64(태그 `legacy-v0.64.0`, 브랜치 `legacy/v0.64-tooling`)와의 코드 호환. 기존 저장 상태
  파일의 마이그레이션도 하지 않는다.

## 2. 호환성 목표와 근거 자료

동작의 근거는 다음 순서로 판단한다.

1. **실물 측정값**: `reference/yubikey-5c-nano-5.7.4/`. 실물 키에서 공개 정보만 읽은 바이트들이다
   - CTAPHID INIT과 GetInfo
   - USB 디스크립터와 HID 리포트 디스크립터
   - OpenPGP 공개 객체와 알고리즘 정보
   - Security Domain SELECT, 인식 데이터, 키 정보 스키마
2. **공개 규격**:
   - FIDO CTAP 2.1과 U2F raw message
   - ISO/IEC 7816-4
   - USB CCID Rev 1.1, USB HID 1.11
   - NIST SP 800-73-4 / 800-78-4 (PIV)
   - OpenPGP Card 3.4
   - RFC 4226/6238 (HOTP/TOTP), RFC 8032 (Ed25519), RFC 7748 (X25519)
   - GlobalPlatform Card Spec 2.3.1과 Amendment D(SCP03), F(SCP11)
3. **Yubico 공개 문서**: YubiKey 5 기술 매뉴얼, YKOATH, OTP 프로토콜, PIV/OpenPGP/HSM Auth 확장 APDU
   설명.
4. **legacy 동작 카탈로그**: `reference/BEHAVIOR_CATALOG.md`. 기존 구현이 고른 경계 동작과 그 이유를
   모은 것이다.
   - 기대 동작 목록으로만 쓴다. 코드는 보지 않는다.
   - 규격과 충돌하면 규격이 우선이다.
   - 실물과 명령 단위로 비교해 확정한 것은 아니다.

문서끼리 충돌하는 지점(예: `reference/piv-printed-source-conflict.md`)은 하나를 골라 **모델 정책**으로
명시하고, 실물로 확인되기 전까지는 그 상태로 둔다.

## 3. 클린룸 원칙

- 새 코드는 §2의 규격과 문서를 보고 작성한다.
- legacy 저장소의 C++ 코드(MIT 포크)와 Python 코드는 읽거나 옮기지 않는다.
- 데이터는 가져온다. 실물 측정값, 동작 카탈로그의 서술, 공개 테스트 벡터가 여기에 해당한다. 사실과
  규격 데이터에는 코드 저작권이 걸리지 않는다.
- 각 크레이트 문서 주석에 근거한 규격 절을 적는다.

## 4. 엔진과 프로그램의 경계

이 경계는 나중에 바꾸기 가장 비싼 결정이라 처음부터 고정한다.

```text
            프로그램 (나중)                                  엔진 (지금)
┌─────────────────────────────────┐     Input     ┌──────────────────────────────┐
│ USB/HID/CCID 전송, 타이머,      │ ────────────▶ │ lk_device::Device             │
│ 터치 UI, 상태 파일, OS 난수,    │ ◀──────────── │  (동기식 상태 기계)           │
│ 저장 키 보관                    │     Output    │                              │
└─────────────────────────────────┘               └──────────────────────────────┘
      ▲ Entropy 트레이트, Store 트레이트, now: Millis 인자 ─────────────┘
```

- **입력** (`lk_device::Input`):
  - FIDO HID 64바이트 출력 리포트
  - OTP HID 8바이트 feature 리포트의 SET/GET
  - CCID bulk-out 메시지
  - 터치 눌림/뗌
  - `Tick` (시간 경과)
  - 버스 이벤트 (리셋, 서스펜드, 재개, 전원 재인가)
- **출력** (`lk_device::Output`):
  - FIDO 입력 리포트
  - OTP feature 값, OTP 키보드 리포트
  - CCID bulk-in 메시지, CCID interrupt 메시지
  - 터치 대기 표시
  - 재열거 요청과 새 인터페이스 조합
- **시간**: 엔진은 시계를 읽지 않는다. 모든 호출에 단조 시각 `now`(ms)를 인자로 받는다.
  - `next_deadline()`이 다음 처리 시각을 알려 주고, 프로그램은 그때까지 `Tick`을 보낸다.
  - 이 방식으로 KEEPALIVE, 터치 대기 시간 초과, CTAPHID 트랜잭션 시간 초과, OTP 버튼 길이를 처리한다.
  - TOTP는 호스트가 시간 단계를 챌린지로 보내므로 벽시계가 필요 없다.
  - 증명서 유효기간은 프로필의 고정 값을 쓴다.
- **난수**: `lk_core::Entropy`. 프로그램은 OS 난수를, 테스트는 고정 시드 스트림을 준다.
- **저장**: `lk_core::Store`. 앱별 레코드를 원자적으로 저장한다(§7). 저장소는 이미 봉인된 바이트만 본다.
- **스레드 없음**: 엔진 안에는 스레드도 대기도 없다. 터치 대기는 대기 상태와 마감 시각으로 표현하고,
  그 사이의 CANCEL, INIT, 다른 채널의 요청은 정상 입력으로 처리한다.

API 초안은 `crates/lk-core/src/lib.rs`와 `crates/lk-device/src/lib.rs`에 코드로 있다. Phase 0에서
`Device::open(profile, store, entropy, storage_key)` 생성자를 추가한다.

## 5. 장치 모델 (`lk-device`)

- **세 인터페이스**: FIDO HID (`lk-ctaphid` → `lk-fido`), OTP HID (`lk-otp`), CCID (`lk-ccid` →
  카드 세션).
  - Management 설정으로 켜고 끌 수 있다.
  - 바뀌면 `Output::Reenumerate`를 낸다.
- **카드 세션**: AID로 앱을 SELECT하고, 선택 상태, 명령/응답 체이닝, 보안 채널 래핑(`lk-sd`)을
  관리한다.
  - CCID 전원 차단, USB 리셋, 다른 AID 선택 시 각 앱의 휘발 상태를 규칙대로 지운다.
- **공유 상태**: 시리얼, 펌웨어 버전, 폼팩터, 전송별 지원/활성 앱, 설정 잠금. Management가 소유하고
  다른 앱은 읽기만 한다.
- **터치 중재**: 터치 한 번은 가장 먼저 대기 중인 요청 하나만 만족시킨다. 대기 요청이 없을 때의 짧게
  누름/길게 누름은 OTP 슬롯 1/2 출력이 된다. 터치를 요구하는 앱은 FIDO UP, OATH, PIV touch policy,
  OpenPGP UIF, HSM Auth다.
- **전원/리셋 의미**: `PowerCycle`은 모든 휘발 상태(PIN 토큰, 세션, 선택 상태, 보안 채널)를 지운다.
  `Reset`은 USB 수준만 초기화한다. 세부 규칙은 동작 카탈로그의 v0.52/v0.57 항목을 기대 동작으로 쓴다.

## 6. 크레이트 구성

| 크레이트 | 책임 | 의존 |
| --- | --- | --- |
| `lk-core` | 경계 타입과 트레이트 (`Millis`, `Entropy`, `Store`, `Record`) | 없음 |
| `lk-crypto` | 암호 원시 기능의 자체 API. **제3자 크레이트를 쓰는 유일한 곳** | core, RustCrypto |
| `lk-codec` | CTAP2 정규 CBOR, BER-TLV, ISO 7816-4 APDU(short/extended, 체이닝, GET RESPONSE) | core |
| `lk-ctaphid` | CTAPHID 패킷, 채널, 트랜잭션 중재, KEEPALIVE/CANCEL/WINK/LOCK | core |
| `lk-ccid` | CCID 메시지, 슬롯 상태, ATR, WTX, ABORT | core |
| `lk-fido` | CTAP 2.1과 U2F | core, crypto, codec |
| `lk-oath` | YKOATH (HOTP/TOTP) | core, crypto, codec |
| `lk-otp` | OTP 슬롯 4종, 접근 코드, HID 8바이트 프로토콜, 키보드 출력 | core, crypto, codec |
| `lk-piv` | PIV와 Yubico 확장 | core, crypto, codec |
| `lk-openpgp` | OpenPGP 카드 3.4 | core, crypto, codec |
| `lk-hsmauth` | YubiHSM Auth | core, crypto, codec |
| `lk-sd` | Security Domain, SCP03, SCP11a/b/c, 보안 메시징 | core, crypto, codec |
| `lk-mgmt` | Management (장치 정보, 설정, 재부팅) | core, codec |
| `lk-device` | 위 전부를 묶는 장치 모델과 공개 API | 전부 |
| `lk-testkit` | 결정론 테스트 하네스, 메모리 저장소, 고장 주입 | core, device |

규칙:
- 앱 크레이트끼리는 서로 의존하지 않는다. 공유가 필요하면 `lk-device`가 중재한다.
- `unsafe`는 워크스페이스 전체에서 금지한다(`forbid`).

## 7. 상태 저장 모델

- 앱마다 레코드 하나(`lk_core::Record`)를 둔다. 한 앱의 저장 실패가 다른 앱 상태를 되돌리지 않는다.
- **형식**: 자체 정의 이진 형식(버전 바이트 + TLV). 필드 추가는 새 태그로 하고, 모르는 태그는 보존한다.
- **봉인**: AES-256-GCM. 연관 데이터는 레코드 이름과 형식 버전이고, nonce는 저장할 때마다 새로 만든다.
  - 저장 키(32바이트)는 프로그램이 준다. 나중에 OS 키체인 등에 보관한다.
  - 엔진은 키를 파일에 쓰지 않는다.
- **커밋 규칙**: 명령 처리 → 새 상태 직렬화 → `Store::save` 순서다.
  - 저장이 성공해야 메모리 상태를 확정하고 성공 응답을 낸다.
  - 실패하면 메모리 상태를 이전으로 되돌리고 오류를 응답한다.
  - 카운터(서명 카운터, HOTP 카운터, PIN 재시도)는 응답 **전에** 저장한다.
- **휘발 상태**는 저장하지 않는다. PIN/UV 토큰, 보안 채널 세션, 선택 상태, 체이닝 버퍼가 여기에 해당한다.

## 8. 암호 정책

- 암호 원시 기능만 검증된 외부 구현을 쓴다. 직접 만든 암호는 버그와 부채널 위험이 더 크다.
- 그 밖의 모든 것(CBOR, TLV, APDU, 모든 프로토콜, 저장 형식, 테스트 하네스)은 직접 작성한다.
- 외부 크레이트는 **`lk-crypto`에서만** 쓴다. 다른 크레이트는 `lk-crypto`의 자체 타입만 본다. 그래서
  구현체 교체가 이 크레이트 하나로 끝난다.
- **사용 크레이트**: RustCrypto의 `p256`, `p384`, `aes`, `aes-gcm`, `cbc`, `cmac`, `sha1`, `sha2`, `hmac`,
  `hkdf`, `getrandom`, `zeroize`, 그리고 dalek의 `ed25519-dalek`, `x25519-dalek`과 `subtle`.
  - 모두 순수 Rust라 C 컴파일러가 필요 없다.
  - 2026-10-10 기준으로 실제 연결되는 제3자 크레이트는 macOS와 Linux 모두 53개다. 빌드 시에만 쓰는 매크로
    8개는 별도다.
- **라이선스**:
  - 허용 목록: MIT, Apache-2.0, BSD-2/3-Clause, ISC, Zlib, Unicode-3.0.
  - `python3 tools/license_check.py`가 허용 목록과 "외부 의존은 `lk-crypto`에만" 규칙을 검사한다.
  - `--write`로 `THIRD_PARTY.md`를 다시 만든다.
  - 바이너리를 배포할 때 필요한 것은 그 목록의 고지문을 함께 넣는 것뿐이다.
- **RSA는 PIV 단계에서 결정한다**.
  - `rsa` 0.9 (안정판): 다른 RustCrypto 크레이트보다 이전 세대라 해시 크레이트가 중복된다.
  - `rsa` 0.10 (현재 `0.10.0-rc.19`, 출시 전): 나머지와 같은 세대다.
  - 두 버전 모두 복호화 타이밍 공격(Marvin, RUSTSEC-2023-0071) 공지가 있다. 에뮬레이터 용도로는
    받아들일 수 있는 위험으로 보고 기록해 둔다.
- 비밀 값 비교는 `subtle`의 상수 시간 비교, 비밀 버퍼는 `zeroize`로 처리한다.

## 9. 장치 정체성 프로필

VID/PID, 제품 문자열, AAGUID, 펌웨어 버전, 시리얼, 증명서 체인은 `DeviceProfile` 값으로 주입한다.

- 기본값은 **자체 정체성**이다. 자체 AAGUID, 자체 증명서, 자체 제품명을 쓴다.
- 실물 5.7.4의 공개 값(VID 0x1050, AAGUID `ff4dac45-…`, 펌웨어 5.7.4)을 쓰는 호환 프로필은 옵션으로 둔다.
- 제조사 증명 서명은 어느 프로필에서도 재현하지 않는다.
- 호환 프로필은 라이선스가 아니라 상표·정체성 문제다. §12에 질문으로 남긴다.

## 10. 구현 순서

각 단계는 "완료 기준"의 테스트가 통과해야 끝난다.

| 단계 | 내용 | 완료 기준 |
| --- | --- | --- |
| 0 기반 | `lk-core` 확정; `lk-crypto` API와 테스트 벡터; `lk-codec`(CBOR/TLV/APDU); 저장 형식과 봉인; `lk-testkit`; `Device::open`과 라우팅 뼈대 | 코덱 정상/비정상 입력 테스트, 암호 벡터(NIST/RFC) 통과, 저장 실패 시 롤백 테스트 |
| 1 FIDO | `lk-ctaphid`; CTAP 2.1 전 명령; PIN 프로토콜 1/2; 확장 5종; 비상주 자격증명; U2F; 자체 증명 | 규격 예시와 실물 GetInfo 필드 일치, CTAPHID 경계 시나리오, 카탈로그 FIDO 항목 매핑 |
| 2 OTP·OATH·Management | `lk-otp`(HID 8바이트 프로토콜 포함), `lk-oath`, `lk-mgmt`; 터치 중재 | RFC 4226/6238 부록 벡터, OTP 프레임 CRC, 슬롯/접근 코드 경계 |
| 3 PIV | `lk-piv`; RSA 결정(§8); `lk-ccid` 완성 | SP 800-73-4 명령 시나리오, 용량·재시도·정책 경계 |
| 4 OpenPGP | `lk-openpgp` | 실물 공개 객체(`openpgp-reference-observation.json`) 일치, 알고리즘 43종 생성/가져오기 |
| 5 보안 채널 | `lk-sd`(SCP03, SCP11a/b/c), `lk-hsmauth`, 앱별 보안 메시징 | GP 규격 KDF/MAC 벡터, 실물 SD 공개 바이트 일치 |
| 6 정합성 | 동작 카탈로그 전체 대조, 결정론 검사, 선택적으로 퍼징(§12) | 카탈로그 항목별 테스트 또는 "의도적 차이" 기록 |

## 11. 테스트 전략

- `cargo test`만 쓴다. 테스트 프레임워크 의존은 없다.
- **벡터**: RFC 부록, NIST CAVP 공개 벡터, CTAP 규격 예시 바이트. 출처를 테스트 파일 주석에 적는다.
- **실물 골든 테스트**: `reference/yubikey-5c-nano-5.7.4/`의 공개 바이트와 같은 값이 나오는지 비교한다
  (호환 프로필 기준).
- **장치 시나리오**: `lk-testkit`이 64바이트 CTAPHID 리포트, CCID 메시지, 터치 이벤트를 실제 호스트처럼
  보내고 응답 바이트를 검사한다. OS 장치나 네트워크는 쓰지 않는다.
- **결정론**: 고정 시드 난수와 고정 시각으로 같은 결과가 나오는지 확인한다.
- **자원 제한**: 빌드와 테스트는 `CARGO_BUILD_JOBS=2` 수준에서 돌아가게 한다. 오래 걸리는 반복 테스트는
  별도 명령으로 분리한다.

## 12. 결정이 필요한 질문

1. **프로젝트 라이선스**: 새 코드에 붙일 라이선스(비공개 유지, MIT, Apache-2.0 등). 정해지기 전까지는
   LICENSE 파일을 두지 않는다. 기존 MIT 고지문은 legacy 포크와 함께 기록에만 남는다.
2. **호환 프로필(§9)**: YubiKey의 VID, 제품명, AAGUID를 쓰는 옵션을 둘지, 기본값을 무엇으로 할지.
3. **개발용 외부 도구**: python-fido2, yubikey-manager, pcscd 같은 도구로 상호운용을 확인해도 되는지.
   제품에는 포함되지 않고 개발 중 검사에만 쓴다. 허용하지 않으면 자체 테스트만으로 검증한다.
4. **퍼징**: `cargo-fuzz`(libFuzzer)는 개발 전용 의존을 추가한다. 쓸지 여부.
5. **브랜치**: 지금 작업은 `engine` 브랜치에 있다. `main`을 언제 새 엔진으로 바꿀지(승인 후 병합 제안).

## 13. 프로그램화 단계로 미루는 것

- Linux: UHID, FunctionFS/ConfigFS 복합 USB 장치, PC/SC IFD 드라이버.
- macOS: IOHIDUserDevice, IOUSBHost. Apple의 제한된 권한과 서명이 필요하다.
- 데몬, 상태 파일 위치, 저장 키 보관(키체인 등), 터치 UI, 설치 패키지.
- 실물 키와의 명령 단위 차분 비교. 실물을 쓰는 시험은 사용자의 명시적 허가가 있을 때만 한다.
