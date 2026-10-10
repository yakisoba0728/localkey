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

## Phase 0 as implemented (binding for later phases)

The frozen crates' sources are the authority; these are the points other crates must know.

- **lk-crypto**
  - Device-visible ECDSA signatures must use `EcPrivateKey::sign_prehash_hedged(digest, entropy)`
    or `sign_message_hedged(alg, msg, entropy)`. These implement RFC 6979 §3.6 with host
    entropy, so repeated signatures differ, as on hardware with a random nonce. The
    deterministic `sign_prehash`/`sign_message` exist for known-answer tests.
  - `sign_prehash(&[])` is an error.
  - `rsa_public_op` rejects input >= n.
  - `ed25519_verify` is strict and rejects small-order keys and R.
  - `hkdf_sha256` rejects `len > 8160`.
  - `RsaPrivateKey::from_primes` checks consistency but not primality.
- **lk-codec::cbor**
  - Canonical encoding order is CTAP 2.1 §8: lower major type, then shorter encoding, then bytewise.
  - Minimal encodings are enforced for integers, lengths and tag numbers.
  - Depth 8 counts arrays, maps and tags.
  - Tags are decoded as `Value::Tag`; lk-fido must reject them (CTAP 2.1 §8 forbids tags).
  - The decoder accepts map keys that are not in canonical order and keeps the received order.
  - `MapBuilder` never emits duplicate keys.
- **lk-codec::apdu**
  - `Command::parse` stores `le = Some(0)` for short `00` and for extended `00 00`.
    `expected_len()` gives Ne (256 or 65536). Also `Command::new(..).with_data(..).with_le(..)`
    and `to_bytes()`.
  - `secure_messaging()` and `sm_indication()` apply to interindustry CLA `0x00..=0x1F` only.
  - `ApduError::sw()` is always `6700`.
  - `CommandChain::new(max)`. `push(cmd)` returns `Ok(None)` while more parts follow and
    `Ok(Some(cmd))` for the assembled or unchained command. `ChainError::sw()`: a header
    change mid-chain is `6883` (LAST_COMMAND_EXPECTED) and the chain is dropped. Le and the
    length form of intermediate parts are ignored.
  - `ResponseQueue::start(data, sw, max)` returns the first chunk with `61xx`, or the final SW.
    `next(max)` returns `None` when nothing is pending.
  - Extra `sw` constants: `6881`, `6882`, `6883`, `6884`, `6986`, `6987`, `6988`, `6B00`,
    `wrong_le(n)` (6Cxx); and `split_response`.
- **lk-codec::tlv**
  - `TlvError {Truncated, TagTooLong, IndefiniteLength, UnsupportedLength}`.
  - Non-minimal long lengths are accepted on input; `encode` is minimal.
  - `00`/`FF` padding between objects is not skipped.
  - Also `Tlv::children()`, `is_constructed()`, `encode_into`, `encode_tag`.
- **lk-codec::der / x509**
  - Single-octet tags (`der::tag::*`).
  - Builders: `sequence`, `set`, `set_of`, `integer` (unsigned BE), `integer_u64`, `boolean`,
    `null`, `bit_string`, `named_bit_string`, `octet_string`, `oid(&[u64])`, `oid_dotted`,
    the string types, `generalized_time`/`utc_time`, `explicit`/`implicit`/`implicit_constructed`.
  - Readers: `parse_der`, `split_der`, `expect`, `expect_only`, `parse_all`, `decode_oid`,
    `decode_unsigned`, `decode_bit_string`.
  - `x509::TbsCertificate` is a struct literal plus `to_der()`. It uses `Name` (builder),
    `Validity::rfc5280(..)` (UTCTime through 2049, GeneralizedTime after),
    `PublicKey::{EcP256, EcP384, Ed25519, X25519, Rsa}` and `SignatureAlgorithm`.
  - `x509::assemble(tbs_der, sig_alg, signature)`. ECDSA signatures are passed DER-encoded.
- **lk-ctaphid**
  - Command codes in `Event::Request.cmd` are 7-bit (`0x10` CBOR, `0x03` MSG); `respond`
    accepts either form.
  - Empty CBOR/MSG requests are answered with INVALID_LEN by the framer and never reach lk-fido.
  - CIDs are allocated sequentially from 1.
  - `reset()` emits no events: lk-device must check `outstanding()` first and drop its pending
    operation itself.
  - A vendor request the device does not handle must still get an answer (for example
    `respond(cid, cmd::ERROR, &[err::INVALID_CMD])`), or the channel stays busy.
  - `respond` addresses a channel. After an INIT resync (`Event::Abort`), lk-device must
    discard the aborted request's late reply instead of sending it.
- **lk-ccid**
  - `CcidAction::PowerOff(reply)` is also returned for IccPowerOn while active (warm reset):
    end the card session.
  - A bulk Abort of an outstanding APDU is detected by `pending_seq()` changing across
    `message()`. lk-device then cancels the pending applet operation.
  - `control_abort(slot, seq)` covers the class-specific ABORT control request.
  - `apdu_response` returns an empty Vec for "send nothing" (the sequence was aborted or the
    card was reset).
  - Extras: `is_active()`, `atr()`, `parameters_in_force()`, `descriptor::YUBIKEY_5C_NANO`,
    `message` constants.
- **lk-testkit**
  - `SeededEntropy::new(seed)` (frozen stream) and `bytes(n)`.
  - `ScriptedEntropy::new(seed, chunks)`, `push`.
  - `TestHost::new()` (profile `DeviceProfile::own(12345678)`), `with_profile`, `seeded`,
    `set_now`, `advance`, `profile_mut`, `push_entropy`, `fail_next_saves(n)`, `fail_all`,
    `persisted(record)`, `persist_count`, `persist_attempts`, `set_persisted`, `clear_persisted`.
  - `MemoryStore` has `fail_next_saves`, `fail_all`, `fail_loads`, `save_count`, `get`,
    `insert` and `remove`. Clones share storage.
- **lk-device::storage**
  - `seal(key, record, plaintext, entropy) -> Vec<u8>` and `open(key, record, sealed)`.
  - Layout `0x01 || nonce(12) || ciphertext || tag(16)`.
  - AAD `b"localkey" || record_id || 0x01`.
  - Record ids: Device 1, Fido 2, Oath 3, Otp 4, Piv 5, OpenPgp 6, HsmAuth 7, SecurityDomain 8.

## Applications A as implemented (binding for lk-device)

- Catalog mapping lives in `docs/catalog/<app>.md`, one file per crate. It replaces the
  per-section rule above. `docs/CATALOG_STATUS.md` is assembled from those files at the end.
- **SELECT detection**: only `xx A4 04 xx` is SELECT. `00 A4 00 0x` is OATH CALCULATE ALL and
  goes to the selected applet's `process()`.
- **Secure messaging**: after `lk_sd::SecureChannel::unwrap_command`, the applet receives the
  command with the CLA secure-messaging bits cleared. Plaintext continuation commands
  (SEND REMAINING, GET RESPONSE) are delivered as received.
- **Touch timeouts**: applets return `NeedTouch { timeout_ms }` (OATH 15000, FIDO 30000).
  lk-device calls `touch_resolved(false)` / `presence_resolved(false)` on timeout, cancel,
  abort or session end.
- **lk-fido**
  - `cbor()` while a command waits answers `CTAP1_ERR_CHANNEL_BUSY` and keeps the waiting
    command.
  - `presence_resolved()` with nothing waiting returns an error status. `RESET_WINDOW_MS = 10000`.
  - The attestation O/C are constants ("localkey", "ZZ") until `DeviceProfile` gains fields.
- **lk-otp**
  - CCID APDUs to the OTP AID must use `OtpApplet::process_with(apdu, Option<&mut dyn MgmtBridge>, host)`.
  - HID: `OtpHid::set_feature(..)`, `OtpHid::get_feature_at(otp, now)` (the countdown needs
    time), `OtpHid::touch_resolved(touched, otp, host)`, `OtpHid::is_waiting_for_touch()`.
  - Touch model: `Otp::touch_down(host)` / `Otp::touch_up(host)` return keyboard reports.
    `Otp::is_touch_active()`. `Otp::is_challenge_waiting(now)` means the touch belongs to the
    pending OTP request, not to a button press.
  - `MgmtBridge` mapping (see `lk-otp` and `lk-mgmt` docs):
    - `serial` -> `Management::serial`;
    - `device_info(page)` -> `Management::device_info_page(page, host)`;
    - `write_device_info(len||TLVs)` -> `Management::write_config` (lk-device must apply the
      returned `ConfigEffect` itself);
    - `write_device_config` -> `Management::legacy_set_mode` (always `6D00`);
    - `challenge_response_timeout_s` -> `Management::challenge_response_timeout_secs`.
- **lk-mgmt**
  - `write_config(data)` takes the wire form `len || TLVs`.
  - CCID: call `MgmtApplet::take_effect()` right after sending the WRITE CONFIG response.
  - CTAPHID vendor commands go through `ctaphid_vendor(..)`, which returns a ready `VendorReply`.
  - Read-only entry points take `&dyn Host`.
- **lk-oath**: the factory salt (device id) is persisted only at the first mutating command.
  Until then it changes per power cycle. This is a known gap for the final review.

## Contract change requests

Phase 0 requests are resolved in the section above.
