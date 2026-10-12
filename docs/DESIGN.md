# localkey 엔진 설계

상태: **결정됨** (2026-10-10). 사용자가 결정을 위임했고, §12의 결정 기록대로 §10 순서에 따라 구현했습니다.
진행 상황은 `docs/STATUS.md`에 있습니다. 모든 단계가 끝났습니다. 구현이 이 설계와 달라진 곳은 **as built**로
표시했고, 확정된 공개 API는 `docs/CONTRACTS.md`에 있습니다. 목표와 동작 판단 순서는 2026-10-12에 사용자가
다시 정했습니다(§12 결정 8). 이 문서에서 그와 다른 옛 표현은 결정 8이 우선합니다.

## 1. 목표와 비목표

**목표**

- 사용자 자신의 소프트웨어 보안키를 Rust로 처음부터 만든다. 그 핵심이 이 문서의 **엔진**이다. 대상은
  FIDO2/U2F, OTP, OATH, PIV, OpenPGP, YubiHSM Auth, Security Domain(SCP03/SCP11), Management다.
- YubiKey 5C Nano(펌웨어 5.7.4)는 복제 대상이 아니라 비교 기준인 **기준 키**다(§2, §12 결정 8). 공개
  규격이 정한 동작은 규격을 따르고, 규격이 열어 둔 동작은 기준 키를 따른다. 기본 정체성은 자체 정체성이다.
- 엔진은 순수한 프로토콜·상태 처리기다. USB/HID, OS API, 스레드, 파일, 시계에 직접 접근하지 않는다.
  나중에 만들 **프로그램**(데몬, 앱)이 엔진을 감싸 실제 장치처럼 노출한다.
- 같은 입력, 같은 시각, 같은 난수에서 항상 같은 출력을 낸다(결정론). 그래서 모든 동작을 OS 장치 없이
  테스트할 수 있다.
- 다른 프로젝트의 코드를 가져오지 않는다. 예외는 §8의 암호 원시 기능 하나뿐이다.

**비목표**

- 기준 키의 복제. 기준 키와 바이트 단위로 같아지는 것은 목표가 아니다. 규격이 정한 곳에서 기준 키가
  다르면 규격을 따르고, 기준 키의 결함과 정체성(Yubico 이름, 문자열, AAGUID, 부품 번호)은 따르지 않는다
  (§12 결정 8).
- 제조사 증명(attestation) 신뢰, 보안 칩의 키 추출 불가성, 물리 터치 센서. 소프트웨어로는 원천적으로
  제공할 수 없다.
- 엔진 단계에서의 OS 장치 등록. macOS 가상 HID 권한, Linux UHID/FunctionFS, PC/SC 드라이버는 §13
  프로그램화 단계에서 다룬다.
- 기존 v0.64(태그 `legacy-v0.64.0`, 브랜치 `legacy/v0.64-tooling`)와의 코드 호환. 기존 저장 상태
  파일의 마이그레이션도 하지 않는다.

## 2. 기준 키와 근거 자료

기준 키는 YubiKey 5C Nano(펌웨어 5.7.4)다. localkey는 기준 키의 복제품이 아니다. 기준 키는 잘 만든 실물
키여서 비교 대상으로 삼는다(§12 결정 8). 외부에서 관찰되는 동작은 다음 순서로 정한다.

1. **공개 규격**이 정한 동작은 기준 키와 달라도 규격을 따른다. 기준 키의 동작은 알려진 차이로 기록한다.
   - FIDO CTAP 2.1/2.2, CTAPHID, U2F raw message
   - ISO/IEC 7816-4
   - USB CCID Rev 1.1, USB HID 1.11
   - NIST SP 800-73-4 / 800-78-4 (PIV)
   - OpenPGP Card 3.4
   - RFC 4226/6238 (HOTP/TOTP), RFC 8032 (Ed25519), RFC 7748 (X25519)
   - GlobalPlatform Card Spec 2.3.1과 Amendment D(SCP03), F(SCP11)
   - **호환 예외**: 널리 쓰는 호스트 스택이 기준 키의 비규격 동작에 실제로 의존하면 기준 키를 따르고,
     어느 호스트가 왜 그런지 적는다(호스트 목록은 §12 결정 8).
2. **기준 키**: 규격이 열어 둔 동작(허용된 상태 워드 중 무엇을 쓸지, 한도 안의 타이밍, 선택 기능, 장치가
   정하는 최대 크기)은 기준 키를 따른다. 호스트 소프트웨어가 기준 키에 맞춰져 있기 때문이다. 근거는 다음과
   같다.
   - `reference/yubikey-5c-nano-5.7.4/`: 기준 키에서 공개 정보만 읽은 바이트
     - CTAPHID INIT과 GetInfo
     - USB 디스크립터와 HID 리포트 디스크립터
     - OpenPGP 공개 객체와 알고리즘 정보
     - Security Domain SELECT, 인식 데이터, 키 정보 스키마
   - `docs/MEASUREMENT.md`: 기준 키와 엔진에 같은 읽기 전용 요청을 보내 명령 단위로 비교한 결과(2026-10-11)
   - Yubico 공개 문서
3. **Yubico 독자 프로토콜**(Management, OTP HID 프레임, YKOATH, YubiHSM Auth, Yubico PIV/OpenPGP 확장):
   Yubico 공개 문서(YubiKey 5 기술 매뉴얼, YKOATH, OTP 프로토콜, PIV/OpenPGP/HSM Auth 확장 APDU 설명)와
   yubikit의 동작이 규격이다. 기준 키는 그 최선의 증거다.
4. 기준 키의 **결함**은 따르지 않는다. 멈춤, 응답 누락, 설명 없는 특이 동작, 타이밍의 클록 오차가 여기에
   해당한다. 타이밍은 기준 키가 뜻한 설계값을 쓴다.
5. **정체성**은 자체다(§9).
6. **legacy 동작 카탈로그**: `reference/BEHAVIOR_CATALOG.md`. 기존 구현이 고른 경계 동작과 그 이유를
   모은 것이다.
   - 기대 동작 목록으로만 쓴다. 코드는 보지 않는다.
   - 위의 근거와 충돌하면 위의 근거가 우선이다.
   - 실물과 명령 단위로 비교해 확정한 것은 아니다.

규격도 기준 키도 정하지 않은 동작은 엔진이 하나를 골라 **모델 정책**으로 명시한다. 규격이 열어 두었고
기준 키에서 측정하지 않았거나 관찰할 수 없는 동작이 여기에 해당한다. 문서끼리 충돌하는 지점(예:
`reference/piv-printed-source-conflict.md`)도 같다. 나중에 기준 키를 측정하면 2번(결함이면 4번)에 따라
정한다.

**변경 기록**: 2026-10-12 전에는 이 절의 제목이 "호환성 목표와 근거 자료"였고, 실물 측정값이 첫째 근거,
공개 규격이 둘째 근거였다. 2811c86의 측정 정렬은 그 순서를 따랐다. §12 결정 8이 지금 순서로 바꿨다.

## 3. 클린룸 원칙

- 새 코드는 §2의 규격과 문서를 보고 작성한다.
- legacy 저장소의 C++ 코드(MIT 포크)와 Python 코드는 읽거나 옮기지 않는다.
- 데이터는 가져온다. 기준 키의 측정값, 동작 카탈로그의 서술, 공개 테스트 벡터가 여기에 해당한다. 사실과
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
  - **as built (프로그램 단계)**: CCID와 CTAPHID로 받은 `REBOOT`는 응답 직후 재부팅한다. OTP HID로 받은
    쓰기는 호스트가 다음 상태를 읽은 직후, 읽지 않으면 1초(`OTP_REBOOT_DELAY_MS`) 뒤에 재부팅한다.
    yubikit은 쓰기가 성공했는지 그 상태 읽기로 확인하기 때문이다.
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
  공지가 있지만, 키가 프로세스 메모리에 있는 소프트웨어 보안키 용도로는 받아들일 수 있는 위험으로 보고
  기록해 둔다. 3DES는 `des`를 쓴다.
- 비밀 값 비교는 `subtle`의 상수 시간 비교, 비밀 버퍼는 `zeroize`로 처리한다.
  - **as built**: 다른 크레이트는 `zeroize`를 직접 쓸 수 없으므로 `lk_crypto::SecretBytes`(drop 시 0으로
    지움)나 `lk_crypto::wipe`/`wipe_vec`로 비밀을 지운다.
    - `lk-fido`, `lk-piv`, `lk-oath`, OpenPGP S2K는 `SecretBytes`를 쓴다.
    - `lk-hsmauth`, `lk-sd`, `lk-device`, `lk-otp`, `lk-mgmt`, OpenPGP 키 재료는 `Drop`에서 지운다.
    - `lk-codec`의 `Command`, `CommandChain`, `ResponseQueue`는 다 쓰거나 버릴 때 지운다. `lk-codec`은
      `lk-crypto`에 의존하지 않으므로 `black_box`로 지키는 0 쓰기를 쓴다(최선 노력).
    - 남은 것: 크레이트 밖으로 나간 복사본(`lk_otp::Ticket`은 `Copy`, 키보드 리포트, `Management::to_record`,
      `lk-codec`이 호출자에게 넘긴 바이트), 프로그램 전송 계층의 버퍼, 컴파일러가 만드는 고정 크기 값의
      복사본. 목록은 `docs/STATUS.md`에 있다.

## 9. 장치 정체성 프로필

VID/PID, 제품 문자열, AAGUID, 펌웨어 버전, 시리얼, 증명서 체인은 `DeviceProfile` 값으로 주입한다.

- 기본값은 **자체 정체성**이다. 자체 AAGUID, 자체 증명서, 자체 제품명을 쓴다. Yubico 이름, 문자열,
  AAGUID, 부품 번호 같은 식별자는 넣지 않는다(§12 결정 8). 호스트 도구가 파싱하는 Yubico 프로토콜 메시지
  형식(Management SELECT 문구, DeviceInfo 배치)은 그대로 쓴다.
- 기준 키의 공개 값(VID 0x1050, AAGUID `ff4dac45-…`, 펌웨어 5.7.4)을 쓰는 호환 프로필은 시험용 옵션이다.
  Yubico 장치만 받는 호스트 도구(ykman, libccid의 리더 목록)로 시험할 때와 기준 키와 비교할 때(`reference/`
  골든 테스트, `tools/measure/`)만 쓴다.
- Yubico의 제조사 증명 서명은 어느 프로필에서도 쓰지 않는다. 증명은 엔진 자체 키로 서명한다.
- 호환 프로필은 라이선스가 아니라 상표·정체성 문제다. §12에 질문으로 남긴다.

## 10. 구현 순서

각 단계는 "완료 기준"의 테스트가 통과해야 끝난다.

| 단계 | 내용 | 완료 기준 |
| --- | --- | --- |
| 0 기반 | `lk-core` 확정; `lk-crypto` API와 테스트 벡터; `lk-codec`(CBOR/TLV/APDU); 저장 형식과 봉인; `lk-testkit`; `Device::open`과 라우팅 뼈대 | 코덱 정상/비정상 입력 테스트, 암호 벡터(NIST/RFC) 통과, 저장 실패 시 롤백 테스트 |
| 1 FIDO | `lk-ctaphid`; CTAP 2.1 전 명령; PIN 프로토콜 1/2; 확장 5종; 비상주 자격증명; U2F; 자체 증명 | 규격 예시와 기준 키 GetInfo 필드 일치, CTAPHID 경계 시나리오, 카탈로그 FIDO 항목 매핑 |
| 2 OTP·OATH·Management | `lk-otp`(HID 8바이트 프로토콜 포함), `lk-oath`, `lk-mgmt`; 터치 중재 | RFC 4226/6238 부록 벡터, OTP 프레임 CRC, 슬롯/접근 코드 경계 |
| 3 PIV | `lk-piv`; RSA 결정(§8); `lk-ccid` 완성 | SP 800-73-4 명령 시나리오, 용량·재시도·정책 경계 |
| 4 OpenPGP | `lk-openpgp` | 기준 키 공개 객체(`openpgp-reference-observation.json`) 일치, 알고리즘 43종 생성/가져오기 |
| 5 보안 채널 | `lk-sd`(SCP03, SCP11a/b/c), `lk-hsmauth`, 앱별 보안 메시징 | GP 규격 KDF/MAC 벡터, 기준 키 SD 공개 바이트 일치 |
| 6 정합성 | 동작 카탈로그 전체 대조, 결정론 검사, 선택적으로 퍼징(§12) | 카탈로그 항목별 테스트 또는 "의도적 차이" 기록 |

## 11. 테스트 전략

- `cargo test`만 쓴다. 테스트 프레임워크 의존은 없다.
- **벡터**: RFC 부록, NIST CAVP 공개 벡터, CTAP 규격 예시 바이트. 출처를 테스트 파일 주석에 적는다.
- **기준 키 골든 테스트**: `reference/yubikey-5c-nano-5.7.4/`의 공개 바이트와 같은 값이 나오는지 비교한다
  (호환 프로필 기준). 규격 때문에 일부러 다른 곳(예: Security Domain SELECT 응답의 `9F65`)은 기준 키의
  바이트를 알려진 차이로 테스트에 남긴다.
- **장치 시나리오**: `lk-testkit`이 64바이트 CTAPHID 리포트, CCID 메시지, 터치 이벤트를 실제 호스트처럼
  보내고 응답 바이트를 검사한다. OS 장치나 네트워크는 쓰지 않는다.
- **결정론**: 고정 시드 난수와 고정 시각으로 같은 결과가 나오는지 확인한다.
- **자원 제한**: 빌드와 테스트는 `CARGO_BUILD_JOBS=2` 수준에서 돌아가게 한다. 오래 걸리는 반복 테스트는
  별도 명령으로 분리한다.

## 12. 결정 기록

2026-10-10에 사용자가 결정을 위임했습니다. 각 결정은 되돌리기 쉬운 쪽을 택했습니다. 결정 8(목표와 판단 순서)은
2026-10-12에 사용자가 직접 정했고, 그와 다른 앞의 결정 내용보다 우선합니다.

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
7. **프로그램 단계의 외부 도구 (2026-10-11, 3번을 다시 검토)**: 실제 호스트 소프트웨어(libfido2,
   python-fido2, ykman, pcscd/libccid, OpenSC, GnuPG)를 **블랙박스 클라이언트로만** 쓴다. 이 도구들은
   네트워크가 없는(`-nic none`) 일회용 QEMU 게스트 안에서만 돌고, 게스트는 `--network none` Docker
   컨테이너 안에서 돈다. 호스트의 USB/HID/PCSC/키체인과 실물 키는 건드리지 않는다. 도구의 코드는
   가져오지 않는다. 도구가 보내는 요청과 기대하는 응답은 프로토콜 사실로 인용할 수 있다(엔진 단계의
   2차 검토도 yubikit, libfido2 등의 요청 형태를 그렇게 썼다). 저장소에는 게스트를 만드는 스크립트
   (`tools/linux-guest/`)만 둔다. 프로그램 크레이트도 엔진과 같이 표준 라이브러리만 쓰고 `unsafe`를 쓰지
   않는다(`docs/PROGRAM.md`).
   - **결과 (2026-10-11)**: 게스트 커널은 Ubuntu 26.04의 7.0.0-38이고, 배포판 커널에 없는 `dummy_hcd`만
     같은 소스 패키지에서 빌드했다. 도구 버전은 libfido2 1.16.0, python-fido2 2.0.0, ykman 5.8.0,
     pcsc-lite 2.4.1, OpenSC 0.27.0rc1, GnuPG 2.4.8, vsmartcard-vpcd 3.3, pyscard이다. 게스트는 NIC이 없고
     루프백만 켠다(vpcd가 127.0.0.1로 연결을 받는다). 실제 도구가 결함 7개를 찾았고(`lk-uhid` 3,
     `lk-gadget` 3, 엔진 1) 모두 고쳤다. 엔진 변경은 하나로, ykman이 OTP HID로 `config usb`를 실패로
     보고한 것을 근거로 OTP HID 재부팅 시점을 상태 읽기 뒤로 옮겼다(§5).
8. **목표와 판단 순서 (2026-10-12, 사용자가 직접 정함)**: localkey는 사용자 **자신의** 소프트웨어
   보안키다. YubiKey 5C Nano의 복제품이 아니다. YubiKey 5C Nano 5.7.4는 **기준 키**다. 잘 만든 실물 키라서
   비교 대상으로 삼는다. 외부에서 관찰되는 모든 동작은 다음 순서로 정한다.
   1. **규격**: 공개 규격(CTAP 2.1/2.2, CTAPHID, U2F raw message, ISO/IEC 7816-4, NIST SP 800-73-4/-78,
      OpenPGP 카드 3.4, GlobalPlatform 2.3과 Amendment D/F, USB CCID 1.1, USB HID)이 정한 동작은 기준 키와
      달라도 규격을 따른다. 기준 키의 동작은 알려진 차이로 기록한다.
      **호환 예외**: 널리 쓰는 호스트 스택(libfido2, python-fido2, Chromium/Firefox WebAuthn, Windows
      webauthn, yubikit/ykman, OpenSC, GnuPG scdaemon, yubico-piv-tool, pcsc-lite/libccid)이 기준 키의
      비규격 동작에 실제로 의존하면 기준 키를 따르고, 어느 호스트가 왜 그런지 적는다.
   2. **규격이 열어 둔 곳은 기준 키**: 허용된 상태 워드 중 무엇을 쓸지, 한도 안의 타이밍, 선택 기능, 장치가
      정하는 최대 크기처럼 규격이 열어 둔 동작은 기준 키를 따른다(`docs/MEASUREMENT.md`의 측정값이나 Yubico
      문서). 호스트 소프트웨어가 기준 키에 맞춰져 있기 때문이다.
   3. **Yubico 독자 프로토콜**(Management, OTP HID 프레임, YKOATH, YubiHSM Auth, Yubico PIV/OpenPGP 확장):
      Yubico 공개 문서와 yubikit의 동작이 규격이고, 기준 키는 그 최선의 증거다.
   4. **결함은 따르지 않는다**: 멈춤, 응답 누락, 규격을 따르는 호스트가 오류로 볼 설명 없는 특이 동작,
      타이밍의 클록 오차를 따르지 않는다. 타이밍은 기준 키가 뜻한 설계값을 쓴다. 예를 들어 KEEPALIVE가
      95 ms로 측정된 것은 그대로 둔다(CTAP은 "at least every 100ms"를 요구한다). 빠른 발진기에서 30 s
      타이머가 28.45 s로 측정된 시간 초과는 30 s로 한다.
   5. **정체성은 자체**: 기본 프로필(`DeviceProfile::own`)에는 Yubico 이름, 문자열, AAGUID, 부품 번호 같은
      식별자를 넣지 않는다. YubiKey 호환 프로필(`yubikey_5c_nano_5_7_4`)은 시험용으로만 남긴다: Yubico
      장치만 받는 호스트 도구(ykman, libccid의 리더 목록)로 시험할 때와 기준 키와 비교할 때. 호스트 도구가
      파싱하는 Yubico 프로토콜 메시지 형식(Management SELECT 문구, DeviceInfo 배치, 증명 확장 OID)은 그대로
      둔다.
   - 용어: **모델 정책**은 규격도 기준 키도 정하지 않은 동작에 대한 엔진의 선택이다. **알려진 차이**는 규칙
     1, 4, 5에 따라 일부러 따르지 않은 기준 키의 동작이다. 카탈로그에서는 `intentional difference`로 적고
     이유("spec over reference", "reference defect not copied", "own identity")를 붙인다.
   - 이 결정은 §2의 근거 순서(전에는 실물 측정값이 첫째였다)를 바꾸고, 결정 2의 호환 프로필 용도를 좁힌다.
     앞의 결정들은 기록으로 남긴다. 영문 계약은 `docs/CONTRACTS.md` "Reference, not replica"에 있다.
   - **결과 (2026-10-12)**: 2811c86에서 측정값에 맞춘 변경을 이 순서로 다시 검토했다.
     - 되돌린 것 다섯 개: 빈 `CTAPHID_CBOR`의 멈춤(규칙 4, 다시 `ERR_INVALID_LEN`), FIDO 사용자 확인 시간
       초과 28.5 s(규칙 4, 30 s로), clientPIN getUVRetries의 `33`(규칙 1, CTAP 2.1 §8.1의 `3E`로), PIV
       VERIFY P2 `81`의 `6A80`(규칙 1, SP 800-73-4 §3.2.1의 `6A88`로), OpenPGP 공장 증명 키 상태 `02`(규칙 1,
       OpenPGP 카드 §4.4.3.8의 `01`로).
     - 규격에 따라 고친 것 다섯 개: Security Domain SELECT 응답의 `9F65`(GP Table 11-82), GlobalPlatform
       클래스 GET DATA의 전체 데이터 객체(§11.3.3.1), OCE CA 공개키의 키 정보 `B0 40`(§11.3.3.1.1), 다른
       논리 채널의 SELECT는 `6881`(ISO/IEC 7816-4 §5.5), 빈 DF 이름의 SELECT는 Security Domain 선택
       (GP §11.9.2.3). 기준 키와 비교된 것은 이 중 `9F65` 하나이고, 나머지는 기준 키에서 측정하지 않았다.
     - 자체 프로필의 폼팩터는 `00`(UNKNOWN)이 됐다(규칙 5). 호환 프로필은 `04`를 유지한다.
     - 나머지 측정 변경(KEEPALIVE 95 ms, 메시지 시간 초과 470 ms, 1536바이트 한도, LOCK 미구현, CLA `80`,
       유휴 GET RESPONSE의 상태 워드, Management SELECT 문구와 DeviceInfo 등)은 규칙 2나 3으로 유지했다.
     - 목록과 테스트는 `docs/CONTRACTS.md` "Reference, not replica"와 `docs/MEASUREMENT.md` "Revised by
       principle"에 있다.

## 13. 프로그램화 단계

계약과 as-built 기록은 `docs/PROGRAM.md`에 있다.

- **완료 (2026-10-11)**:
  - 데몬 `localkeyd`: 상태 디렉터리, 저장 키 파일 또는 사용자 명령, 실행 루프, 제어 소켓.
  - 전송: 비공개 유닉스 소켓(`wire`), Linux UHID(`uhid`), Linux FunctionFS/ConfigFS 복합 USB
    장치(`gadget`), vsmartcard `vpcd`를 통한 PC/SC(`vpcd`). `uhid,vpcd` 조합은 USB 장치 컨트롤러 없이
    장치 전체를 노출한다.
  - 제어 소켓의 `shutdown`(서비스 관리자용 깨끗한 종료), systemd 유닛과 udev 규칙 예시(`tools/service/`).
  - Linux 전송과 vpcd는 네트워크 없는 QEMU 게스트에서 실제 호스트 도구로 검증했다(§12 결정 7).
- **남은 것**:
  - 자체 PC/SC IFD 드라이버: `vpcd`(vsmartcard)를 거치지 않는 드라이버는 C ABI라 `unsafe`가 필요하다.
  - macOS: IOHIDUserDevice, IOUSBHost. Apple의 제한된 권한과 서명이 필요하다. macOS에서 vpcd 경로는
    시험하지 않았다.
  - 키체인 직접 연동: 지금은 `--key-command`로 사용자가 연결한다.
  - 터치 UI, 설치 패키지.
  - 기준 키를 더 재는 일. 명령 단위 차분 비교는 2026-10-11에 읽기 전용으로 한 번 했다
    (`docs/MEASUREMENT.md`, `tools/measure/`). 그때 잴 수 없던 것이 남았다: 기준 키에서 꺼져 있던 OTP와
    OATH, 카드 터치 시간 초과, U2F 요청 창과 래치, raw CCID. 기준 키를 쓰는 시험은 사용자의 명시적 허가가
    있을 때만 한다.
