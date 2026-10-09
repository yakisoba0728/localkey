# Crate contracts

This file fixes the public API each crate must provide, so that crates can be built in
parallel and then integrated by `lk-device`. `docs/DESIGN.md` explains why; this file says
what. If a contract proves wrong while implementing, keep the crate compiling against it
and record the proposed change under "Contract change requests" at the end of this file.
Do not silently diverge.

## Rules for every crate

- Clean room: write from the specifications listed in `docs/DESIGN.md` §2.
  - Do not read or copy the legacy implementation (Git tag `legacy-v0.64.0`, branch
    `legacy/v0.64-tooling`).
  - `reference/BEHAVIOR_CATALOG.md` describes expected behaviour in prose and may be used.
  - `reference/yubikey-5c-nano-5.7.4/*.json` holds public bytes read from a real device.
- No third-party crates outside `lk-crypto`. No `unsafe`. No threads, clocks, files or OS calls.
- Build and test with `CARGO_BUILD_JOBS=2 nice -n 10 cargo test -p <crate>`. Other agents may be
  building at the same time; cargo serialises on its lock, so wait instead of deleting `target/`.
- Never edit another crate's files unless the task says so. `lk-core` and `lk-crypto` are
  frozen during application work. Request changes through "Contract change requests".
- Tests:
  - Put them next to the code (`#[cfg(test)]`) or in `crates/<crate>/tests/`.
  - Cite the source of every test vector (RFC section, spec table, reference file).
  - Use `lk_testkit` for deterministic entropy and an in-memory host when it exists. Until
    then, each crate's tests may define a small test `Host`.
- Status words are `u16` constants in `lk_codec::apdu::sw`. A response is `data || SW1 SW2`.
- Persisted state:
  - Each application serializes its own state to bytes: version byte `0x01`, then
    BER-TLV fields from `lk_codec::tlv`.
  - It calls `Host::persist(Record::<App>, &bytes)` before reporting success. On error it
    keeps its previous in-memory state and answers with `sw::MEMORY_FAILURE` (`0x6581`) or
    `CTAP1_ERR_OTHER` for CTAP.
  - Unknown fields are skipped when loading. Unreadable state means factory state.
- Every application crate maintains its section of `docs/CATALOG_STATUS.md`. Each relevant
  bullet of `reference/BEHAVIOR_CATALOG.md` becomes one of:
  - `tested` (name the test);
  - `intentional difference` (say why);
  - `deferred` (say what is missing).

## lk-core (fixed)

`Millis`, `Entropy`, `Store`, `Record`, `StoreError`, `DeviceProfile` (`own`,
`yubikey_5c_nano_5_7_4`), `Version`, `Capabilities`, `UsbInterfaces`, `ProductIds`, and the
application contract in `applet.rs`:

- `Host: Entropy` with `now()`, `profile()` and `persist()`;
- `Outcome<T>` (`Done` / `NeedTouch { timeout_ms }`);
- `ResetKind`;
- `CardApplet`.

## lk-crypto (fixed API, tests being added)

- Hashes: `sha1/256/384/512`, `digest(HashAlg, _)`.
- MAC and KDF: `hmac(HashAlg, key, data)`, `hmac_sha1`, `hmac_sha256`, `aes_cmac(key16/24/32, data)`,
  `hkdf_sha256(salt, ikm, info, len)`, `ct_eq`.
- Ciphers: `aes_ecb_{en,de}crypt_block`, `aes_cbc_{en,de}crypt(key, iv, data)` (no padding),
  `aes_gcm_seal/open(key32, nonce12, aad, data)`, `tdes_ecb_{en,de}crypt_block(key24, block8)`.
- EC: `Curve::{P256,P384}` and `EcPrivateKey`:
  - `generate(curve, entropy)`, `from_scalar`, `scalar`, `public_uncompressed`;
  - `sign_prehash`, `sign_message(HashAlg, msg)`, `ecdh(peer_point)`.
  - Signatures are `EcdsaSignature { r, s }` with `to_der()` and `to_raw()`.
  - `ec_public_is_valid`, `ecdsa_verify_prehash(curve, point, digest, der_or_raw)`.
- Edwards:
  - `Ed25519Key`: `generate`, `from_seed`, `public`, `sign`; plus `ed25519_verify`.
  - `X25519Key`: `generate`, `from_bytes`, `public`, `dh`.
- RSA: `RsaPrivateKey` with `generate(bits, entropy)`, `from_primes(p, q, e)`, `size`, `modulus`,
  `public_exponent`, `primes`, and `raw_private(input, entropy)` (blinded, no padding). Also
  `rsa_public_op(n, e, input)`.

## lk-codec

`cbor`:
- `enum Value { Unsigned(u64), Negative(u64) /* -1-n */, Bytes(Vec<u8>), Text(String),
  Array(Vec<Value>), Map(Vec<(Value, Value)>), Bool(bool), Null, Undefined, Float(u64 /* raw bits */, u8 /* size 2|4|8 */), Tag(u64, Box<Value>) }`.
- `encode(&Value) -> Vec<u8>` sorts map keys in CTAP2 canonical order: shorter encoding first,
  then bytewise.
- `decode(&[u8]) -> Result<Value, CborError>` decodes exactly one item and rejects trailing bytes.
  - Definite lengths only. Maximum nesting depth 8. Duplicate map keys are rejected.
  - Non-canonical integer encodings are rejected.
  - Floats are accepted (the device ignores unknown float fields; see the catalog).
- `decode_prefix(&[u8]) -> Result<(Value, usize), CborError>`.
- Helpers:
  - `Value::map_get(&self, key: &Value)`, `Value::int_key(i64)`;
  - `as_u64`, `as_i64`, `as_bytes`, `as_text`, `as_array`, `as_map`, `as_bool`;
  - a `MapBuilder` that emits canonical order.

`tlv` (BER-TLV, ISO 7816-4 §5.2):
- `struct Tlv<'a> { tag: u32, value: &'a [u8], raw: &'a [u8] }`.
- `parse_one(&[u8]) -> Result<(Tlv, rest), TlvError>`, `parse_all(&[u8]) -> Result<Vec<Tlv>, TlvError>`.
  Tags are 1–3 bytes; lengths use short form or `81`/`82`/`83`.
- `encode(tag: u32, value: &[u8]) -> Vec<u8>`, `encode_len(len) -> Vec<u8>`, `find(&[Tlv], tag)`.

`apdu` (ISO 7816-4 §5.1):
- `struct Command { cla: u8, ins: u8, p1: u8, p2: u8, data: Vec<u8>, le: Option<u32> /* 0 means 256 or 65536 */, extended: bool }`.
- `Command::parse(&[u8]) -> Result<Command, ApduError>` handles cases 1–4 in short and extended
  form. `ApduError` maps to `sw::WRONG_LENGTH`.
- `Command::is_chained()` (CLA bit `0x10`), `Command::secure_messaging()` (CLA bits `0x0C`).
- `sw` module constants:
  - `OK 9000`, `WRONG_LENGTH 6700`, `SECURITY_STATUS 6982`, `AUTH_BLOCKED 6983`,
    `DATA_INVALID 6984`, `CONDITIONS 6985`;
  - `INCORRECT_DATA 6A80`, `FUNC_NOT_SUPPORTED 6A81`, `FILE_NOT_FOUND 6A82`, `NO_SPACE 6A84`,
    `INCORRECT_P1P2 6A86`, `REF_NOT_FOUND 6A88`;
  - `INS_NOT_SUPPORTED 6D00`, `CLA_NOT_SUPPORTED 6E00`, `UNKNOWN 6F00`, `MEMORY_FAILURE 6581`;
  - helpers `more_data(n) 61xx` and `retries(n) 63Cx`.
- `response(data: &[u8], sw: u16) -> Vec<u8>`, `status(sw) -> Vec<u8>`.
- `CommandChain` accumulates chained command data. It has a configurable limit and reports an
  error when the header changes mid-chain.
- `ResponseQueue` holds remaining response data. It serves it in `max` chunks with `61xx`, and an
  applet uses it for GET RESPONSE (`INS C0`) or its own continuation command.

`der` (DER encoder, X.690):
- Builders for `SEQUENCE`, `SET`, `INTEGER` (from unsigned big-endian bytes), `BIT STRING`,
  `OCTET STRING`, `OID` (from dotted arcs), `UTF8String`, `PrintableString`, `GeneralizedTime`,
  `UTCTime`, `BOOLEAN`, `NULL`, and context tags (explicit and implicit).
- A small reader: `parse_der(&[u8]) -> Result<(tag, value, rest), DerError>`.
- `x509::TbsCertificate` builder:
  - serial, issuer and subject names (CN, O, OU, C);
  - validity (GeneralizedTime strings);
  - SubjectPublicKeyInfo for EC P-256/P-384, Ed25519, X25519 and RSA;
  - extensions (raw OID plus DER value, critical flag);
  - signature algorithm (ecdsa-with-SHA256/384, Ed25519, sha256WithRSAEncryption).
- `x509::assemble(tbs_der, sig_alg, signature) -> Vec<u8>`. Signing is the caller's job via
  `lk-crypto`.

## lk-ctaphid (CTAP 2.1 §11.2)

- `Ctaphid::new(version: Version, capabilities: u8)`. Capabilities: WINK `0x01`, CBOR `0x04`,
  NMSG `0x08`.
- `fn report(&mut self, now: Millis, report: &[u8; 64]) -> Vec<Event>`.
  - It handles INIT (broadcast and per channel), PING, WINK, LOCK, CANCEL, CONT sequencing,
    channel allocation, the busy rules and the transaction timeout itself.
  - It returns events, and reports to send, in order.
- `enum Event { Send([u8; 64]), Request { cid: u32, cmd: u8, payload: Vec<u8> }, Cancel { cid: u32 }, Abort { cid: u32 }, Wink }`.
  - `Request` carries CBOR (`0x10`), MSG (`0x03`) or vendor commands (`0x40..=0x7F`) for the
    application layer.
  - While one request is outstanding, the framer itself answers `ERR_CHANNEL_BUSY` to other
    channels and to PING/WINK on the same channel.
  - `Abort` means the outstanding request was discarded (INIT resynchronisation on its channel).
- `fn respond(&mut self, cid: u32, cmd: u8, payload: &[u8]) -> Vec<[u8; 64]>` ends the
  outstanding request.
- `fn keepalive(&self, cid: u32, status: u8) -> [u8; 64]` (PROCESSING 1, UPNEEDED 2).
- `fn tick(&mut self, now) -> Vec<Event>` expires partial messages with `ERR_MSG_TIMEOUT` and
  expires locks.
- `fn next_deadline(&self) -> Option<Millis>`, `fn reset(&mut self)` for USB reset.

## lk-ccid (CCID Rev 1.1)

- `Ccid::new(atr: Vec<u8>)`.
- `fn message(&mut self, msg: &[u8]) -> CcidAction`, where
  `enum CcidAction { Reply(Vec<u8>), Apdu { seq: u8, apdu: Vec<u8> }, PowerOff(Vec<u8> /* reply */) }`.
  - It handles IccPowerOn (returns the ATR), IccPowerOff, GetSlotStatus, GetParameters,
    SetParameters, ResetParameters, XfrBlock (short and extended APDU level), Abort, and
    unsupported messages with the CCID error codes.
- `fn apdu_response(&mut self, seq: u8, response: &[u8]) -> Vec<u8>`.
- `fn time_extension(&self, seq: u8) -> Vec<u8>` (`bStatus` `0x80`).
- `fn slot_change(&self, present: bool) -> Vec<u8>` (interrupt message).
- `fn reset(&mut self)`.

## Application crates

Each provides `new(stored: Option<&[u8]>, host: &mut dyn Host) -> Self` and implements
`CardApplet` where it lives on CCID.

| Crate | Type | AID / interface | Extra API used by `lk-device` |
| --- | --- | --- | --- |
| `lk-fido` | `Authenticator` | CTAPHID CBOR and MSG | see below |
| `lk-oath` | `Oath` | `A0 00 00 05 27 21 01` | none |
| `lk-otp` | `Otp`, `OtpApplet`, `OtpHid` | `A0 00 00 05 27 20 01` plus HID | see below |
| `lk-mgmt` | `Management`, `MgmtApplet` | `A0 00 00 05 27 47 11 17` plus OTP HID and CTAPHID vendor | see below |
| `lk-piv` | `Piv` | `A0 00 00 03 08` | none |
| `lk-openpgp` | `OpenPgp` | `D2 76 00 01 24 01` | none |
| `lk-hsmauth` | `HsmAuth` | `A0 00 00 05 27 21 07 01` | none |
| `lk-sd` | `SecurityDomain` | `A0 00 00 01 51 00 00 00` | secure channel, see below |

`lk-fido::Authenticator`:
- `cbor(&mut self, request: &[u8], host) -> Outcome<Vec<u8>>`. The response is the status byte
  followed by CBOR.
- `presence_resolved(&mut self, granted: bool, host) -> Vec<u8>` finishes a pending CBOR command.
- `cancel(&mut self, host) -> Option<Vec<u8>>` returns `CTAP2_ERR_KEEPALIVE_CANCEL` if a command
  was pending.
- `u2f(&mut self, apdu: &[u8], user_present: bool, host) -> (Vec<u8>, U2fPresence)` with
  `enum U2fPresence { NotNeeded, Consumed, Requested }`.
  - `Requested` means the response was `6985` and the device should latch the next touch for
    later U2F requests.
- `power_cycle(&mut self, host)` clears PIN tokens and soft blocks and records the power-up time
  for the reset window.
- `is_pending(&self) -> bool`.

`lk-otp`:
- `Otp` holds both slots and their logic.
- `OtpHid::set_feature(&mut self, report: &[u8; 8], otp: &mut Otp, mgmt: Option<&mut dyn MgmtBridge>, host) -> Outcome<()>`.
- `OtpHid::get_feature(&mut self, otp: &Otp) -> [u8; 8]`.
- `Otp::button(&mut self, press: Press /* Short | Long */, host) -> Vec<[u8; 8]>` returns keyboard
  reports.
- `OtpApplet` wraps `Otp` for CCID. The serial and device-info read slots go through a small
  `MgmtBridge` trait that `lk-otp` defines and `lk-device` implements with `lk-mgmt`.

`lk-mgmt::Management`:
- `device_info(&self, host) -> Vec<u8>` (TLV).
- `write_config(&mut self, data: &[u8], host) -> Result<ConfigEffect, u16>` with
  `enum ConfigEffect { None, Reboot }`.
- `enabled_usb(&self, host) -> Capabilities`.
- `MgmtApplet` provides the CCID view.

`lk-sd`:
- `SecurityDomain` implements `CardApplet` (key information, card recognition data, CPLC, key
  put/delete, SCP11 keys, certificates, allowlists, reset).
- `is_handshake(apdu) -> bool` covers INITIALIZE UPDATE `50`, EXTERNAL AUTHENTICATE `82`,
  INTERNAL AUTHENTICATE `88`, MUTUAL AUTHENTICATE `82`, and PERFORM SECURITY OPERATION `2A` for
  OCE certificates. The device sends these to the SD whatever applet is selected.
- `handshake(&mut self, apdu, host) -> (Vec<u8>, Option<SecureChannel>)`.
- `SecureChannel`:
  - `unwrap_command(&mut self, apdu) -> Result<Vec<u8>, u16>` verifies the C-MAC and decrypts;
  - `wrap_response(&mut self, response) -> Vec<u8>` adds R-MAC and encryption.

## lk-device (integration)

It owns the applets, `Ctaphid`, `Ccid`, the OTP HID state, touch arbitration and sealing:
- AES-256-GCM per `Record`;
- AAD is `b"localkey" || record id || format version`;
- nonce from host entropy;
- sealed layout `version || nonce || ciphertext||tag`.

Public API: `Device::open(profile, store, entropy, storage_key) -> Device`, `handle`,
`next_deadline` (see `crates/lk-device/src/lib.rs`).

## Contract change requests

(none yet)
