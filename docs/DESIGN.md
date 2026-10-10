# localkey 엔진 설계

상태: **결정됨** (2026-10-10). 사용자가 결정을 위임했고, §12의 결정 기록대로 §10 순서에 따라 구현했습니다.
진행 상황은 `docs/STATUS.md`에 있습니다. 모든 단계가 끝났습니다. 구현이 이 설계와 달라진 곳은 **as built**로
표시했고, 확정된 공개 API는 `docs/CONTRACTS.md`에 있습니다.

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
  - **as built**: CCID class 요청 ABORT(`Input::CcidControlAbort { slot, seq }`). 이 요청은 bulk 파이프가
    아니라 control 파이프로 오므로 CCID bulk-out 입력으로는 전달할 수 없다.
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
  - **as built**: 프로그램이 신뢰할 수 있는 벽시계를 가지고 있으면 `Device::set_unix_time`으로 알려 준다.
    이 값은 `Host::unix_time`으로 전달되어 Security Domain의 OCE 증명서 유효기간 검사에 쓰인다. 엔진은
    이 값을 스스로 증가시키지 않는다. 값이 없으면 프로필의 시작일을 하한으로 쓴다.
- **난수**: `lk_core::Entropy`. 프로그램은 OS 난수를, 테스트는 고정 시드 스트림을 준다.
- **저장**: `lk_core::Store`. 앱별 레코드를 원자적으로 저장한다(§7). 저장소는 이미 봉인된 바이트만 본다.
- **스레드 없음**: 엔진 안에는 스레드도 대기도 없다. 터치 대기는 대기 상태와 마감 시각으로 표현하고,
  그 사이의 CANCEL, INIT, 다른 채널의 요청은 정상 입력으로 처리한다.

API 초안은 `crates/lk-core/src/lib.rs`와 `crates/lk-device/src/lib.rs`에 코드로 있다. Phase 0에서
`Device::open(profile, store, entropy, storage_key)` 생성자를 추가한다.

**as built**: 생성자는 `Device::open`과 `Device::open_at(now, ...)` 두 가지다. `open_at`은 프로그램 시계의
다른 시각을 전원 투입 시각으로 지정한다. 프로그램이 장치를 노출하는 데 필요한 조회 함수도 있다.
- `usb_identity()`: VID/PID, 문자열, HID/CCID 디스크립터, 장치/구성 디스크립터.
- `interfaces()`, `profile()`.
- `unreadable_records()`: 열지 못한 레코드.
- `presence_pending()`: 터치 대기 중인지 여부.

목록 전체는 `docs/CONTRACTS.md` "Final integration (as built)"에 있다. `Device`는 `Send`가 아니다(저장소와
난수 트레이트 객체에 `Send` 경계가 없다). 그래서 프로그램은 장치를 구동하는 스레드 안에서 만든다.

## 5. 장치 모델 (`lk-device`)

- **세 인터페이스**: FIDO HID (`lk-ctaphid` → `lk-fido`), OTP HID (`lk-otp`), CCID (`lk-ccid` →
  카드 세션).
  - Management 설정으로 켜고 끌 수 있다.
  - 설정이 적용될 때(재부팅) `Output::Reenumerate`를 낸다.
  - **as built**: `REBOOT`가 있는 설정 쓰기만 곧바로 재열거한다. `REBOOT` 없이 쓴 설정은 인터페이스
    조합이 바뀌어도 다음 열거(재부팅 또는 `BusEvent::PowerCycle`)에 적용한다. ykman `config usb`가
    조합이 바뀔 때만 `REBOOT`를 붙이고 yubikit `set_mode`가 재삽입을 안내하는 것을 근거로 한 모델
    정책이다(`docs/CONTRACTS.md`).
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

**as built**: 의존 관계 두 곳이 표와 다르다.
- `lk-mgmt`는 `lk-crypto`도 쓴다. 설정 잠금 코드를 상수 시간으로 비교하기 위해서다(`ct_eq`).
- `lk-testkit`은 `lk-device`가 아니라 `core`와 `crypto`에 의존한다. 장치 시나리오 하네스는 `lk-device`의
  테스트(`crates/lk-device/tests/common`) 안에 있다.

규칙:
- 앱 크레이트끼리는 서로 의존하지 않는다. 공유가 필요하면 `lk-device`가 중재한다.
- `unsafe`는 워크스페이스 전체에서 금지한다(`forbid`).

## 7. 상태 저장 모델

- 앱마다 레코드 하나(`lk_core::Record`)를 둔다. 한 앱의 저장 실패가 다른 앱 상태를 되돌리지 않는다.
- **형식**: 자체 정의 이진 형식(버전 바이트 + TLV). 필드 추가는 새 태그로 하고, 모르는 태그는 보존한다.
  - **as built**: 모르는 태그를 보존할지 건너뛸지는 크레이트마다 다르다. 예를 들어 `lk-piv`, `lk-fido`,
    `lk-mgmt`는 보존하고 `lk-hsmauth`는 건너뛴다. 어느 쪽이든 읽기가 실패하지는 않는다
    (`docs/CONTRACTS.md`).
- **봉인**: AES-256-GCM. 연관 데이터는 레코드 이름과 형식 버전이고, nonce는 저장할 때마다 새로 만든다.
  - 저장 키(32바이트)는 프로그램이 준다. 나중에 OS 키체인 등에 보관한다.
  - 엔진은 키를 파일에 쓰지 않는다.
- **커밋 규칙**: 명령 처리 → 새 상태 직렬화 → `Store::save` 순서다.
  - 저장이 성공해야 메모리 상태를 확정하고 성공 응답을 낸다.
  - 실패하면 메모리 상태를 이전으로 되돌리고 오류를 응답한다.
  - 카운터(서명 카운터, HOTP 카운터, PIN 재시도)는 응답 **전에** 저장한다.
- **휘발 상태**는 저장하지 않는다. PIN/UV 토큰, 보안 채널 세션, 선택 상태, 체이닝 버퍼가 여기에 해당한다.
- **as built, 재시도 카운터**: PIN 등 비밀을 비교하기 **전에** 시도 횟수를 하나 줄여 저장하고, 맞으면
  되돌린다. 저장이 실패하면 비밀이 맞든 틀리든 저장 실패 상태를 응답하므로, 고장 난 저장소를 추측
  수단으로 쓸 수 없다. 그래서 맞는 VERIFY 한 번에 저장이 두 번 일어난다.
- **as built, 열 때의 저장**: 일부 앱은 첫 시작 때 생성자에서 자기 정체성을 만들어 저장한다(Security
  Domain, PIV, OpenPGP, OATH). 이 저장에는 다음 규칙이 붙는다.
  - 읽지 못한 기존 레코드는 덮어쓰지 않는다.
  - 열린 레코드가 하나도 없고 읽지 못한 레코드가 있으면, 저장 키가 틀렸을 수 있으므로 아무것도 쓰지
    않는다.
  - 저장소가 거절한 생성자 저장은 이후 입력마다 다시 시도한다.

## 8. 암호 정책

- 암호 원시 기능만 검증된 외부 구현을 쓴다. 직접 만든 암호는 버그와 부채널 위험이 더 크다.
- 그 밖의 모든 것(CBOR, TLV, APDU, 모든 프로토콜, 저장 형식, 테스트 하네스)은 직접 작성한다.
- 외부 크레이트는 **`lk-crypto`에서만** 쓴다. 다른 크레이트는 `lk-crypto`의 자체 타입만 본다. 그래서
  구현체 교체가 이 크레이트 하나로 끝난다.
- **사용 크레이트**: RustCrypto의 `p256`, `p384`, `aes`, `aes-gcm`, `cbc`, `cmac`, `sha1`, `sha2`, `hmac`,
  `hkdf`, `getrandom`, `zeroize`, `rsa`, `des`, 그리고 dalek의 `ed25519-dalek`, `x25519-dalek`과 `subtle`.
  - 모두 순수 Rust라 C 컴파일러가 필요 없다.
  - 2026-10-10 기준으로 실제 연결되는 제3자 크레이트는 macOS와 Linux 모두 56개다(`rsa`, `des` 포함, 중복 버전 없음). 빌드 시에만 쓰는 매크로
    등은 별도다.
  - **as built**: 곡선 크레이트 `p521`, `k256`, `bp256`, `bp384`를 추가했다. brainpool 서명에 필요한
    `ecdsa`, 그리고 `elliptic-curve`, `rfc6979`는 이미 의존 그래프에 있었고, 이제 직접 의존한다. 난수는
    언제나 호스트의 `Entropy`에서 오므로 `getrandom`은 쓰지 않는다(`rand_core`가 어댑터 역할을 한다).
    `python3 tools/license_check.py` 기준으로 실제 연결되는 제3자 크레이트는 68개, 빌드 시에만 쓰는 것은
    10개이고 중복 버전은 없다. brainpoolP512r1은 RustCrypto 크레이트가 없어 지원하지 않는다. 이 때문에
    OpenPGP 알고리즘 변형 4개가 `6A81`로 응답한다.
- **라이선스**:
  - 허용 목록: MIT, Apache-2.0, BSD-2/3-Clause, ISC, Zlib, Unicode-3.0.
  - `python3 tools/license_check.py`가 허용 목록과 "외부 의존은 `lk-crypto`에만" 규칙을 검사한다.
  - `--write`로 `THIRD_PARTY.md`를 다시 만든다.
  - 바이너리를 배포할 때 필요한 것은 그 목록의 고지문을 함께 넣는 것뿐이다.
- **RSA**: `rsa` 0.10(`=0.10.0-rc.19` 고정, §12-6). 복호화 타이밍 공격(Marvin, RUSTSEC-2023-0071)
  공지가 있지만, 에뮬레이터 용도로는 받아들일 수 있는 위험으로 보고 기록해 둔다. 3DES는 `des`를 쓴다.
- 비밀 값 비교는 `subtle`의 상수 시간 비교, 비밀 버퍼는 `zeroize`로 처리한다.
  - **as built**: 다른 크레이트는 `zeroize`를 직접 쓸 수 없으므로 `lk_crypto::SecretBytes`(drop 시 0으로
    지움)에 비밀을 담는다. 이 지우기는 부분적이다.
    - `lk-fido`, `lk-piv`, OpenPGP S2K는 `SecretBytes`를 쓴다.
    - `lk-hsmauth`, `lk-sd`, `lk-device`, OpenPGP 키 재료는 `Drop`에서 자체적으로 지운다(최선 노력).
    - `lk-oath`, `lk-otp`, `lk-mgmt`의 비밀과 `lk-codec`의 APDU 버퍼는 아직 지우지 않는다.

    목록은 `docs/STATUS.md`에 있다.

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

## 12. 결정 기록

2026-10-10에 사용자가 결정을 위임했습니다. 각 결정은 되돌리기 쉬운 쪽을 택했습니다.

1. **프로젝트 라이선스**: 지금은 붙이지 않는다(모든 권리 보유). 공개하기 전이면 언제든 바꿀 수 있는
   유일한 선택지다. 기존 MIT 고지문은 legacy 포크와 함께 기록에만 남는다.
2. **정체성 프로필(§9)**: `DeviceProfile::own()`(기본)과 `DeviceProfile::yubikey_5c_nano_5_7_4()`(옵션)
   두 가지를 둔다. 호환 프로필은 `reference/`의 실물 공개 바이트와 골든 테스트로 비교하려고 둔다.
   어느 프로필도 제조사 증명 서명을 재현하지 않는다.
3. **개발용 외부 도구**: 엔진 단계에서는 쓰지 않는다. 엔진 테스트는 자체 하네스와 공개 벡터로
   완결한다. 프로그램화 단계에서 다시 검토한다.
4. **퍼징**: `cargo-fuzz`는 쓰지 않는다. 대신 `lk-testkit`의 고정 시드 의사난수로 결정론적 무작위
   입력 테스트를 만든다.
5. **브랜치**: 모든 단계를 `engine` 브랜치에서 한다. 모든 단계가 통과하면 그때 `main`을 `engine`으로
   fast-forward한다. 태그 `legacy-v0.64.0`이 있어 되돌릴 수 있다.
6. **RSA(§8)**: `rsa = "=0.10.0-rc.19"`로 정확히 고정한다. 나머지 RustCrypto와 같은 세대라 해시
   크레이트가 중복되지 않는다. 출시 전 버전이라 정확한 버전을 고정하고, 정식판이 나오면 교체한다.
   PIV 관리 키의 3DES용으로 `des`도 같은 세대로 추가한다.

## 13. 프로그램화 단계로 미루는 것

- Linux: UHID, FunctionFS/ConfigFS 복합 USB 장치, PC/SC IFD 드라이버.
- macOS: IOHIDUserDevice, IOUSBHost. Apple의 제한된 권한과 서명이 필요하다.
- 데몬, 상태 파일 위치, 저장 키 보관(키체인 등), 터치 UI, 설치 패키지.
- 실물 키와의 명령 단위 차분 비교. 실물을 쓰는 시험은 사용자의 명시적 허가가 있을 때만 한다.
