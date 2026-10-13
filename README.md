# localkey

사용자 자신의 소프트웨어 보안키입니다. Rust로 처음부터 새로 작성했습니다. 실물 보안키를 **기준 키**로 삼아 비교합니다. 기준 키는 복제 대상이 아니라 잘 만든 실물 키로서의 비교 기준입니다. 기본
정체성(pid.codes 시험용 USB VID/PID, 제품 문자열, AAGUID, 증명서)은 localkey 자신의 것입니다. YubiKey 호환
프로필은 Yubico 장치만 받는 호스트 도구로 시험할 때를 위해 있습니다.

핵심은 **엔진**이고, 엔진 단계는 끝났습니다. **프로그램** 단계에서는 데몬 `localkeyd`와
전송 네 가지를 만들었습니다: 비공개 유닉스 소켓, Linux UHID, Linux USB 가젯, vsmartcard `vpcd`를 통한 PC/SC.
`uhid,vpcd` 조합은 USB 장치 컨트롤러 없이 장치 전체를 노출합니다. Linux 전송과 vpcd는 네트워크가 없는
QEMU 게스트에서 실제 호스트 소프트웨어로 검증했습니다.

Linux 데스크톱 배포 준비: `tools/linux/README.md`. 사용자 권한 터치 창, 관리자 인증 도우미,
키·상태를 보존하는 설치/제거 도구와 체크섬·라이선스가 포함된 묶음 생성기를 제공합니다.
Debian 13 데스크톱 VM의 aarch64·x86_64에서 실제 systemd 설치·업그레이드·복구와
Chromium·Firefox 등록·로그인·PIN·상주 키·계정 선택·취소·시간 초과와
동일 RP 기록을 유지한 전체 재부팅 후 로그인까지 통과했습니다(아키텍처별 43개 검증).
실제 비활성 로컬 세션·SSH 세션의 polkit 거부와 인증 만료 후 재인증도 확인했습니다.
환경과 증거는 [Linux 데스크톱 검증 기록](docs/LINUX_DESKTOP_VERIFICATION.md)에 있습니다.
현재 `1209:0001`은 내부 시험용 PID이며, 자체 PID 배정과 서명된 릴리스 전에는 공개 바이너리로 배포하지
않습니다. [자체 PID 신청](https://github.com/pidcodes/pidcodes.github.com/pull/1310)은 제출했고 배정을 기다립니다.
태그 기반 빌드·서명된 빌드 증명·초안 릴리스 절차는 [릴리스 준비 문서](docs/RELEASE.md)에 있습니다.
프로젝트 라이선스는 Apache-2.0(`LICENSE`)입니다.

- 엔진은 전송 계층과 분리된 동기식 결정론 상태 기계입니다. 스레드, 시계, 파일, OS 호출이 없습니다. 같은
  입력, 같은 시각, 같은 난수에서 항상 같은 출력을 냅니다.
- 대상: FIDO2/U2F(CTAP 2.1), OTP, OATH, PIV, OpenPGP, YubiHSM Auth, Security Domain(SCP03/SCP11),
  Management. 세 인터페이스(FIDO HID, OTP HID, CCID)를 하나의 `lk_device::Device`가 묶습니다.
- 다른 프로젝트의 코드는 쓰지 않습니다. 예외는 암호 원시 기능뿐이고, `lk-crypto` 한 곳에서만 씁니다.
  목록과 라이선스는 `THIRD_PARTY.md`에 있습니다. 프로그램 크레이트도 표준 라이브러리만 씁니다.
- 제조사 증명 신뢰, 보안 칩의 키 보호, 물리 터치 센서는 소프트웨어로 제공할 수 없습니다.

**기준 키와 같다고 주장하지 않고, 같아지는 것이 목표도 아닙니다.** 외부에서 보이는 동작은 다음 순서로
정합니다(`docs/DESIGN.md` §2, §12 결정 8).

1. 공개 규격이 정한 동작은 기준 키와 달라도 규격을 따릅니다. 다만 널리 쓰는 호스트 도구가 기준 키의
   비규격 동작에 실제로 의존하면 기준 키를 따르고, 어느 도구가 왜 그런지 적습니다.
2. 규격이 열어 둔 동작(상태 워드 선택, 한도 안의 타이밍, 장치가 정하는 최대 크기)은 기준 키를 따릅니다.
3. Yubico 독자 프로토콜(Management, OTP, YKOATH, YubiHSM Auth, PIV/OpenPGP 확장)은 Yubico 공개 문서와
   yubikit의 동작을 규격으로 삼습니다.
4. 기준 키의 결함(멈춤, 응답 누락, 타이밍의 클록 오차)은 따르지 않습니다.
5. 기본 정체성에는 Yubico 식별자를 넣지 않습니다.

근거 자료는 공개 규격, 공개 테스트 벡터, 기준 키에서 공개 정보만 읽은 바이트
(`reference/physical-key/`), 그리고 2026-10-11에 기준 키와 엔진에 같은 읽기 전용 요청을 보내
명령 단위로 비교한 결과(`docs/MEASUREMENT.md`)입니다. 규격도 기준 키도 정하지 않은 상태 워드와 타이밍은
**모델 정책**입니다. 모델 정책과 기준 키와 일부러 다르게 한 동작(알려진 차이)은 크레이트별 카탈로그 파일에
근거와 함께 기록했습니다.

## 현재 상태

- 단계별 결과, 테스트 수, 남은 차이와 미룬 항목: `docs/STATUS.md`
- 기준 키와의 비교, 그에 따른 엔진 변경, 알려진 차이: `docs/MEASUREMENT.md`
- 프로그램 계약과 as-built 기록: `docs/PROGRAM.md`
- legacy 동작 카탈로그 대조표(tested / intentional difference / deferred): `docs/CATALOG_STATUS.md`

## 구성

| 경로 | 내용 |
| --- | --- |
| `crates/lk-core` | 경계 타입과 트레이트: `Millis`, `Entropy`, `Store`, `Record`, `DeviceProfile`, `Host`, `CardApplet` |
| `crates/lk-crypto` | 암호 원시 기능의 자체 API. 제3자 크레이트(RustCrypto, dalek)를 쓰는 유일한 곳. `Hasher`, `SecretBytes` 포함 |
| `crates/lk-codec` | CTAP2 정규 CBOR, BER-TLV, ISO 7816-4 APDU(체이닝, GET RESPONSE), DER/X.509 |
| `crates/lk-ctaphid` | CTAPHID 패킷, 채널, 트랜잭션 중재, KEEPALIVE/CANCEL/WINK/LOCK |
| `crates/lk-ccid` | CCID 메시지, 슬롯 상태, ATR, 파라미터, 시간 연장, ABORT |
| `crates/lk-fido` | CTAP 2.1 전체 명령, PIN/UV 프로토콜 1·2, 확장, U2F, 자체 증명 |
| `crates/lk-otp` | OTP 슬롯(Yubico OTP, HMAC-SHA1, HOTP, 정적 비밀번호), HID 8바이트 프로토콜, CCID, 키보드 출력 |
| `crates/lk-oath` | YKOATH (HOTP/TOTP, 접근 키) |
| `crates/lk-mgmt` | Management (장치 정보, 설정, 잠금, 재부팅), CCID·OTP HID·CTAPHID 세 경로 |
| `crates/lk-piv` | PIV (SP 800-73-4)와 Yubico 확장, F9 증명 |
| `crates/lk-openpgp` | OpenPGP 카드 3.4 (알고리즘 변형 43종 중 39종, 증명, KDF) |
| `crates/lk-hsmauth` | YubiHSM Auth |
| `crates/lk-sd` | Security Domain, SCP03, SCP11a/b/c, 보안 메시징 |
| `crates/lk-device` | 위 전부를 묶는 장치 모델과 공개 API (`Device`), 저장 봉인(AES-256-GCM), 터치 중재, 타이머 |
| `crates/lk-testkit` | 결정론 난수, 메모리 저장소, 고장 주입 |
| `crates/lk-host` | (프로그램) 상태 디렉터리, 원자적 레코드 저장, 프로세스 잠금, OS 난수, 저장 키 |
| `crates/lk-run` | (프로그램) `Device`를 소유하는 실행 스레드: 시계, 마감 시각, 터치, 서스펜드 큐 |
| `crates/lk-wire` | (프로그램) 비공개 유닉스 소켓 전송과 제어 소켓 |
| `crates/lk-uhid` | (프로그램) Linux `/dev/uhid`로 FIDO HID와 OTP HID 노출 |
| `crates/lk-gadget` | (프로그램) Linux ConfigFS + FunctionFS 복합 USB 가젯(OTP, FIDO, CCID) |
| `crates/lk-vpcd` | (프로그램) vsmartcard `vpcd` 리더의 가상 카드로 CCID 노출(PC/SC) |
| `crates/localkeyd` | (프로그램) 데몬 바이너리: `keygen`, `run`, `ctl` |
| `tools/service/` | systemd 유닛과 udev 규칙 예시(설치하지 않음) |
| `tools/linux/`, `tools/package_linux.py` | Linux 데스크톱 터치 UI·제한된 polkit 도우미·설치/제거와 배포 묶음 생성(현재 내부 시험용) |
| `.github/workflows/linux-preview.yml` | Linux x86_64·aarch64 빌드, 기존 검사, 헤드리스 UI·설치 스테이징 검사(게시하지 않음) |
| `tools/linux-guest/` | 네트워크 없는 QEMU Linux 게스트를 만들고 실제 호스트 도구로 전송을 시험하는 스크립트 |
| `tools/linux-desktop/` | systemd·실제 사용자 세션·실제 브라우저로 설치와 WebAuthn을 검증하는 aarch64·x86_64 VM |
| `docs/` | 설계(`DESIGN.md`), 공개 API 계약(`CONTRACTS.md`), 프로그램 계약(`PROGRAM.md`), 상태(`STATUS.md`), 기준 키 비교(`MEASUREMENT.md`), 카탈로그 대조(`CATALOG_STATUS.md`, `catalog/`) |
| `reference/` | 기준 키에서 읽은 공개 바이트, legacy 동작 카탈로그, 프로필 값 |
| `tools/measure/` | 기준 키와 엔진에 같은 읽기 전용 요청을 보내 비교하는 도구(`docs/MEASUREMENT.md`) |
| `tools/license_check.py` | 의존성 라이선스와 "외부 의존은 `lk-crypto`에만" 규칙 검사 |
| `tools/catalog_status.py` | 카탈로그 대조표 집계와 검사 |
| `THIRD_PARTY.md` | 제3자 크레이트 목록 (자동 생성) |

## 빌드와 검사

```sh
CARGO_BUILD_JOBS=2 cargo test --workspace                 # 전체 테스트
CARGO_BUILD_JOBS=2 cargo clippy --workspace --all-targets  # 경고 없음이 기준
CARGO_BUILD_JOBS=2 cargo test -p lk-fido --lib -- --ignored   # 오래 걸리는 반복 테스트(약 50초)
python3 tools/license_check.py            # 라이선스 정책 검사
python3 tools/license_check.py --write    # THIRD_PARTY.md 갱신
python3 tools/catalog_status.py --check   # 카탈로그 대조표 검사 (--write로 갱신)
python3 -m unittest discover -s tools/linux -p 'test_*.py'  # 배포·권한 경계 검사 (UI는 Xvfb에서)
```

`cargo test`에는 OS 장치, 네트워크, 실물 키를 쓰는 테스트가 없습니다. 장치 시나리오는
`crates/lk-device/tests/`의 하네스가 CTAPHID 리포트, CCID 메시지, OTP feature 리포트, 터치 이벤트를 호스트처럼
보내고 응답 바이트를 검사합니다. `lk-uhid`와 `lk-gadget`은 가짜 커널(소켓 쌍)로 시험하고, 실제 커널 시험은
아래 게스트에서만 합니다.

## 데몬 실행

```sh
cargo build --release -p localkeyd
localkeyd keygen --key-file ~/.localkey.key                   # 0600, 덮어쓰지 않음
localkeyd run --state ~/.localkey --key-file ~/.localkey.key  # 기본 전송: 비공개 소켓
localkeyd ctl --control ~/.localkey/control.sock status       # tap, tap long, watch 등
```

- 저장 키는 `--key-command`로 키체인이나 비밀번호 관리자에서 가져올 수도 있습니다(예:
  `security find-generic-password -w -s localkey`).
- Linux에서는 `--transport uhid`(FIDO·OTP HID, `/dev/uhid` 권한 필요), `--transport uhid,vpcd`(여기에
  pcscd의 vpcd 리더로 CCID까지), `--transport gadget --udc NAME`(USB 장치 컨트롤러, root 필요)으로 실제
  장치처럼 노출합니다. 터치는 `localkeyd ctl ... tap`입니다.
- `localkeyd ctl ... shutdown`은 데몬을 깨끗하게 멈추고, 끝나면 `stopped`를 출력합니다(서비스 관리자의
  `ExecStop`용). 예시는 `tools/service/`에 있습니다.
- 열지 못한 레코드가 있으면(저장 키가 틀렸을 수 있음) 기본으로 시작을 거부합니다(종료 코드 3).

## Linux 게스트 시험

`tools/linux-guest/README.md`에 따릅니다. Docker 안에서 QEMU 게스트(NIC 없음, 컨테이너도
`--network none`)를 띄워 libfido2, python-fido2, ykman, pcscd(libccid, vsmartcard-vpcd), OpenSC, GnuPG로
`uhid`, `gadget`, `vpcd` 전송을 시험합니다(`smoke.sh`, `uhid.sh`, `gadget.sh`, `vpcd.sh`). 이 Mac의
USB/HID/PCSC와 실물 키는 건드리지 않습니다.

## 프로그램에서 `Device` 구동하기

프로그램은 `Device` 하나를 소유하고 다음을 맡습니다.

- 실제(또는 가상) 전송에서 받은 입력을 `Device::handle`에 넘깁니다.
- 돌려받은 출력을 순서대로 처리합니다.
- `next_deadline()` 시각까지 `Input::Tick`을 보냅니다.
- 저장소, 난수, 저장 키를 공급합니다.

```rust
use lk_core::{DeviceProfile, Entropy, Record, Store, StoreError};
use lk_device::{BusEvent, Device, Input, Output, TouchEdge};

struct FileStore { /* 레코드마다 원자적으로 쓰는 파일 */ }
impl Store for FileStore {
    fn load(&mut self, record: Record) -> Result<Option<Vec<u8>>, StoreError> { todo!() }
    fn save(&mut self, record: Record, sealed: &[u8]) -> Result<(), StoreError> { todo!() }
}
struct OsEntropy;
impl Entropy for OsEntropy {
    fn fill(&mut self, out: &mut [u8]) { /* OS 난수 */ }
}

// 저장 키(32바이트)는 프로그램이 키체인 등에 보관합니다. 엔진은 키를 저장하지 않습니다.
let mut dev = Device::open(DeviceProfile::own(12345678), Box::new(FileStore {}), Box::new(OsEntropy), storage_key);
if !dev.unreadable_records().is_empty() {
    // 저장 키가 틀렸거나 레코드가 손상됨: 그 앱은 공장 상태로 시작했다.
    // 그대로 쓰면 첫 변경 명령이 그 레코드를 덮어쓰므로, 먼저 확인할 것.
}

// USB로 노출할 정체성: VID/PID, 문자열, 장치/구성 디스크립터, HID 리포트 디스크립터, CCID 클래스 디스크립터.
let usb = dev.usb_identity();
let (device_desc, config_desc) = (usb.device_descriptor(), usb.configuration_descriptor());

loop {
    // `now`는 프로그램의 단조 시계(ms)입니다. 엔진은 시계를 읽지 않습니다.
    let input = wait_for_input_or(dev.next_deadline()); // 전송 입력이 없으면 Input::Tick
    for output in dev.handle(now(), input) {
        match &output {
            Output::FidoReport(report) => { /* FIDO HID IN 리포트 */ }
            Output::OtpFeature(report) => { /* 다음 GET_REPORT 값 */ }
            Output::OtpKeyboard(report) => { /* 키보드 IN 리포트 */ }
            Output::Ccid(message) => { /* CCID bulk-in */ }
            Output::CcidInterrupt(message) => { /* CCID interrupt-in */ }
            Output::PresenceIndicator(waiting) => { /* 터치 대기 표시 */ }
            Output::Reenumerate(interfaces) => { /* dev.usb_identity()로 다시 열거 */ }
        }
    }
}
```

- **입력**:
  - `Input::FidoReport(&[u8; 64])`, `Input::OtpSetFeature(&[u8; 8])`, `Input::OtpGetFeature`
  - `Input::Ccid(bulk-out 메시지)`, `Input::CcidControlAbort { slot, seq }`
  - `Input::Touch(TouchEdge::Down | Up)`, `Input::Tick`
  - `Input::Bus(BusEvent::Reset | Suspend | Resume | PowerCycle)`
- **시간**: 마감 시각이 지난 일은 다음 `handle` 호출의 입력보다 먼저 처리됩니다. KEEPALIVE(95 ms),
  CCID 시간 연장(500 ms), 터치 대기 시간 초과가 여기에 해당합니다.
- **벽시계**: 신뢰할 수 있는 벽시계가 있으면 `dev.set_unix_time(Some(초))`를 시계가 움직일 때마다 다시
  부릅니다. Security Domain의 증명서 유효기간 검사에만 쓰입니다.
- **스레드**: `Device`는 `Send`가 아닙니다. 장치를 구동할 스레드 안에서 만듭니다(`lk-run`이 그렇게 합니다).
- **USB 문자열 디스크립터**: LANGID와 UTF-16LE 변환은 프로그램이 `UsbIdentity`의 문자열로 만듭니다.
- **목록 전체**: 공개 API 전체와 프로그램이 맡을 일은 `docs/CONTRACTS.md` "Final integration (as built)"에
  있습니다.

## 이전 구현

이전 구현은 `madeye/swpasskey` 포크와 Python 카드 모듈로 된 v0.64입니다. 태그 `legacy-v0.64.0`과 브랜치
`legacy/v0.64-tooling`에만 남아 있습니다. 새 엔진은 그 코드를 쓰지 않습니다. 동작 기록만
`reference/BEHAVIOR_CATALOG.md`로 참고합니다.
