# Crate contracts

This file fixes the public API each crate must provide, so that crates can be built in
parallel and then integrated by `lk-device`. `docs/DESIGN.md` explains why; this file says
what. If a contract proves wrong while implementing, keep the crate compiling against it
and record the proposed change under "Contract change requests" at the end of this file.
Do not silently diverge.

Status (final integration, 2026-10-10): every crate is implemented and every section
below describes the as-built API. Sections were written in phase order; where a later
section refines an earlier one, the later section wins. "Final integration (as built)"
near the end lists the last additions: the new curves, `Hasher` and `SecretBytes`, the
complete `lk-device` API and the remaining known gaps. Public APIs grow only by
addition; nothing that another crate uses has been renamed or removed.

## Rules for every crate

- Clean room: write from the specifications listed in `docs/DESIGN.md` §2.
  - Do not read or copy the legacy implementation (Git tag `legacy-v0.64.0`, branch
    `legacy/v0.64-tooling`).
  - `reference/BEHAVIOR_CATALOG.md` describes expected behaviour in prose and may be used.
  - `reference/yubikey-5c-nano-5.7.4/*.json` holds public bytes read from a real device.
- No third-party crates outside `lk-crypto`. No `unsafe`. No threads, clocks, files or OS calls.
- Build and test with `CARGO_BUILD_JOBS=2 nice -n 10 cargo test -p <crate>`. Other agents may be
  building at the same time; cargo serialises on its lock, so wait instead of deleting `target/`.
- Never edit another crate's files unless the task says so. `lk-core` and `lk-crypto` were
  frozen during application work; changes go through "Contract change requests". The
  final integration extended both by addition only ("Final integration (as built)").
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
- Every application crate maintains its mapping in `docs/catalog/<app>.md` (see
  "Applications A as implemented"). Each relevant bullet of
  `reference/BEHAVIOR_CATALOG.md` becomes one of:
  - `tested` (name the test);
  - `intentional difference` (say why);
  - `deferred` (say what is missing).

  `docs/CATALOG_STATUS.md` holds the summary, counted by
  `python3 tools/catalog_status.py --write`; `--check` fails on an unlabelled bullet or a
  stale summary.

## lk-core (fixed)

`Millis`, `Entropy`, `Store`, `Record`, `StoreError`, `DeviceProfile` (`own`,
`yubikey_5c_nano_5_7_4`), `Version`, `Capabilities`, `UsbInterfaces`, `ProductIds`, and the
application contract in `applet.rs`:

- `DeviceProfile` fields as built: `firmware`, `serial`, `form_factor`, `usb_vendor_id`,
  `usb_product_ids`, `usb_device_release`, `manufacturer`, `product`, `aaguid`,
  `supported_usb`, `default_enabled_usb`, `attestation_common_name`,
  `attestation_organization`, `attestation_country`, `atr`, `openpgp_manufacturer`,
  `cert_not_before`, `cert_not_after` (see "Applications B" for the later fields);
- `Host: Entropy` with `now()`, `profile()`, `persist()` and `unix_time()` (default
  `None`);
- `Outcome<T>` (`Done` / `NeedTouch { timeout_ms }`);
- `ResetKind`;
- `CardApplet`.

## lk-crypto (as built)

- Hashes: `sha1/256/384/512`, `digest(HashAlg, _)`, `HashAlg::output_len`, and the
  incremental `Hasher` (`new(alg)`, `alg()`, `update(data)`, `finalize(self) -> Vec<u8>`;
  `Clone`; its `Debug` prints only the algorithm).
- Secrets: `SecretBytes`, a buffer that is zeroized on drop: `new(Vec<u8>)`,
  `from_slice`, `zeroed(len)`, `as_slice`, `as_mut_slice`, `Deref`/`DerefMut` to `[u8]`,
  `AsRef<[u8]>`, `From<Vec<u8>>`, a constant-time `PartialEq`/`Eq` and a redacted
  `Debug`. Other crates hold their secrets in it, because they may not depend on
  `zeroize` themselves.
- MAC and KDF: `hmac(HashAlg, key, data)`, `hmac_sha1`, `hmac_sha256`, `aes_cmac(key16/24/32, data)`,
  `hkdf_sha256(salt, ikm, info, len)`, `ct_eq`.
- Ciphers: `aes_ecb_{en,de}crypt_block`, `aes_cbc_{en,de}crypt(key, iv, data)` (no padding),
  `aes_gcm_seal/open(key32, nonce12, aad, data)`, `tdes_ecb_{en,de}crypt_block(key24, block8)`.
- EC: `Curve::{P256, P384, P521, Secp256k1, BrainpoolP256r1, BrainpoolP384r1}` (with
  `Curve::ALL`, `field_len`, `point_len` and `nonce_hash`) and `EcPrivateKey`:
  - `generate(curve, entropy)`, `from_scalar`, `curve`, `scalar`, `public_uncompressed`;
  - `sign_prehash`, `sign_message(HashAlg, msg)`, `sign_prehash_hedged`,
    `sign_message_hedged`, and `ecdh(peer_point) -> Result<SecretBytes>`. The return type
    was `Vec<u8>` before the final integration; every caller compiles unchanged through
    `Deref`.
  - Signatures are `EcdsaSignature { r, s }` with `to_der()` and `to_raw()`.
  - `ec_public_is_valid`, `ecdsa_verify_prehash(curve, point, digest, der_or_raw)`.
  - brainpoolP512r1 is absent: RustCrypto publishes no crate for it.
- Edwards:
  - `Ed25519Key`: `generate`, `from_seed`, `seed`, `public`, `sign`; plus `ed25519_verify`.
  - `X25519Key`: `generate`, `from_bytes`, `secret`, `public`, `dh`.
- RSA: `RsaPrivateKey` with `generate(bits, entropy)`, `from_primes(p, q, e)`, `size`, `modulus`,
  `public_exponent`, `primes`, and `raw_private(input, entropy)` (blinded, no padding). Also
  `rsa_public_op(n, e, input)`.
- `RsaPrivateKey::primes` and `X25519Key::dh` return `zeroize::Zeroizing` values. Callers
  use them through `Deref` and never name the type.
- Errors: `CryptoError::{InvalidKey, InvalidInput, VerificationFailed}` and
  `lk_crypto::Result<T>`.

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
  - SubjectPublicKeyInfo for EC P-256/P-384/P-521, secp256k1, brainpoolP256r1/P384r1,
    Ed25519, X25519 and RSA;
  - extensions (raw OID plus DER value, critical flag);
  - signature algorithm (ecdsa-with-SHA256/384/512, Ed25519, sha256WithRSAEncryption).
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
- While one channel holds a `CTAPHID_LOCK`, every other channel (broadcast INIT included)
  gets `ERR_CHANNEL_BUSY` (`0x06`), not `ERR_LOCK_REQUIRED` (as built, see "Final
  integration").
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
`next_deadline` (see `crates/lk-device/src/lib.rs`). The complete as-built API is listed
under "Final integration (as built)".

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
    `PublicKey::{EcP256, EcP384, Ed25519, X25519, Rsa}` and `SignatureAlgorithm`. The final
    integration added `PublicKey::{EcP521, EcSecp256k1, EcBrainpoolP256r1, EcBrainpoolP384r1}`,
    `PublicKey::named_curve()`, `SignatureAlgorithm::EcdsaWithSha512` and
    `oid::{SECP521R1, SECP256K1, BRAINPOOL_P256R1, BRAINPOOL_P384R1, ECDSA_WITH_SHA512}`.
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
  - The attestation subject comes from `DeviceProfile::attestation_common_name`,
    `attestation_organization` and `attestation_country`. A value that RFC 5280
    Appendix A.1 does not allow falls back to the own-profile value, or is cut to 64
    characters (final review).
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
- **lk-oath**: `Oath::new(None, host)` persists the factory state at construction, so the
  device id (SELECT tag `71`) is stable across restarts (final review; a rejected save is
  retried by lk-device and any later commit stores the whole state). An existing record
  that does not decode still gives factory state and is not overwritten at open.

## Applications B and orchestrator changes (binding)

- **Retry counters (all applications)**: spend the try and persist it *before* comparing the
  presented secret. Restore it after a match. A failed save answers the storage-failure
  status whatever the secret was, so a failing store is never a guessing oracle.
  lk-openpgp, lk-piv, lk-fido and lk-hsmauth follow this (lk-hsmauth fixed in response to
  a security review). A correct VERIFY therefore costs two saves.
- **Unknown persisted fields**: crates may preserve them (lk-piv, lk-fido) or skip them
  (lk-hsmauth). Either is allowed; loading must never fail because of them.
- **Constructors may persist**, for example when lk-piv creates its own F9 attestation
  material in `new()`.
- **APDU conventions**:
  - Applets serve at most Ne bytes, using `61xx` with GET RESPONSE (or their own continuation
    command) for the rest.
  - Data-less forms `CLA INS P1 P2 00` (T=0) and `CLA INS P1 P2 00 00 00` (extended) are
    accepted where an explicit Le is otherwise rejected.
  - Applets answer `6882` for secure-messaging CLA bits and `6E00` for CLA >= `0x80`.
    lk-device must deliver unwrapped commands with those bits cleared.
  - As built, every card applet also answers `6881` for a logical-channel number in the
    CLA (ISO/IEC 7816-4 §5.1.1); the order of the checks is in each crate's docs.
  - lk-piv also accepts Le `00` after command data (yubico-piv-tool on T=1 sends it).
    Other applets keep their own rules for an explicit Le, recorded in their catalog
    files.
- **lk-device duties raised by the applets**:
  - A SELECT of the already selected AID goes to `select()` without `deselect()`. SP 800-73-4
    §3.1.1 keeps the PIV security status.
  - `OpenPgp::select()` answers `6285` while terminated. Treat `62xx` as a successful
    selection and keep routing to it.
  - Reassemble ISO-chained secure-messaging commands before `SecureChannel::unwrap_command`.
  - Touch timeouts: OATH, PIV, OpenPGP and HSM Auth use 15000 ms; FIDO uses 30000 ms.
- **lk-core additions**:
  - `DeviceProfile` has `attestation_organization`, `attestation_country`, `atr` and
    `openpgp_manufacturer`. As built, lk-fido takes its attestation subject from them and
    lk-openpgp takes the AID manufacturer bytes from `openpgp_manufacturer` (own profile
    `FF00`, YubiKey profile `0006`).
  - `Host::unix_time() -> Option<u64>` (default `None`) for certificate validity. lk-device
    exposes it as `Device::set_unix_time`; lk-sd checks OCE certificate validity against
    it when it is `Some`, and against the profile start date otherwise.
- **Known gaps for the final phase** (status after the final integration):
  - Closed: lk-crypto has P-521, secp256k1, brainpoolP256r1 and brainpoolP384r1. Only the
    4 brainpoolP512r1 OpenPGP variants remain unusable (`6A81`), because RustCrypto has no
    crate for that curve.
  - Closed: `lk_crypto::Hasher` streams the OpenPGP KDF, so its count is no longer capped.
  - Closed: lk-fido secrets (wrapping secret, attestation scalar, PIN/UV secrets and
    tokens, PIN hash, credBlob, largeBlobKey) are held in `SecretBytes`. Remaining
    zeroization gaps are listed under "Final integration (as built)".

## Final integration (as built, binding)

The last additions, and the rules that the parallel reviews fixed. All of them are
additions; existing callers compile unchanged.

- **lk-crypto**
  - Curves: `Curve::{P521, Secp256k1, BrainpoolP256r1, BrainpoolP384r1}` next to P-256 and
    P-384. One code path serves all six curves. Also `Curve::ALL` and
    `Curve::nonce_hash`; `Hasher`, `SecretBytes`, and `EcPrivateKey::ecdh` returning
    `SecretBytes` (see "lk-crypto (as built)").
  - Signing: secp256k1 signatures are low-S (k256, BIP 62). Verification accepts `s` and
    `n - s` on every curve, as SEC 1 §4.1.4 defines ECDSA.
  - Key generation: P-521 draws exactly 521 bits before the range check (FIPS 186-5
    A.2.2).
  - P-521 digests of 66 bytes or more: the RFC 6979 nonce uses the full digest and z is
    its leftmost 521 bits (FIPS 186-5 §6.4.1). This works around ecdsa 0.17, whose
    `bytes2scalar` keeps the low bits; that disagreement would reveal the key through
    repeated nonces.
  - Dependencies: `p521`, `k256`, `bp256`, `bp384`, plus direct `ecdsa`, `elliptic-curve`
    and `rfc6979` (all three were already in the graph). `cargo tree -d` lists no crate
    twice. `python3 tools/license_check.py` reports 68 linked and 10 build-time-only
    third-party crates and no problems.
- **lk-codec x509**: `PublicKey::{EcP521, EcSecp256k1, EcBrainpoolP256r1,
  EcBrainpoolP384r1}`, `PublicKey::named_curve()`, `SignatureAlgorithm::EcdsaWithSha512`,
  and `oid::{SECP521R1, SECP256K1, BRAINPOOL_P256R1, BRAINPOOL_P384R1, ECDSA_WITH_SHA512}`.
  EC attestation issuers (OpenPGP) still sign with ecdsa-with-SHA256 on every curve
  (catalog: "SHA256 RSA/EC signatures").
- **lk-ctaphid**: a channel kept out by another channel's `CTAPHID_LOCK` gets
  `ERR_CHANNEL_BUSY` (`0x06`), the only code Chromium and python-fido2 retry on (CTAP 2.1
  §11.2.9.1.6). `err::LOCK_REQUIRED` stays for source compatibility and is never sent.
- **lk-mgmt**: CCID responses honour Ne with `61xx` and GET RESPONSE (`ins::GET_RESPONSE`
  = `C0`), like every other applet. Under a secure channel lk-device collects a `61xx`
  response with `00 C0 00 00 00`, so every applet that can answer `61xx` implements
  `C0`. OATH continues with its own SEND REMAINING `A5` instead.
- **lk-oath**: the constructor persists the factory state (see "Applications A").
- **lk-otp**: the CCID applet follows the APDU conventions above (CLA checks, Ne with
  `61xx` and GET RESPONSE).
- **lk-sd**: `SecurityDomain::handshake` discards plaintext response data still waiting
  for GET RESPONSE (ISO/IEC 7816-4 §7.6.1). lk-device also sends unwrapped commands for the
  selected Security Domain to `process_secure`, the only path that authorizes PUT KEY,
  DELETE KEY, GENERATE EC KEY and STORE DATA (GP 2.3.1 §11.8.1, §11.2.1, §11.11.1). It
  calls `end_session` on SELECT, power-off and reset. `SecureChannel::is_open` tells lk-device when to drop a channel.
- **lk-device public API** (`crates/lk-device/src/lib.rs`):
  - Opening:
    - `Device::open(profile, store, entropy, storage_key)` is a power-up at time 0, and
      `Device::open_at(now, ...)` a power-up at another time of the program's clock.
    - Every record is loaded and opened. A record that cannot be read gives that
      application its factory state; `Device::unreadable_records()` names such records.
    - Constructor saves never overwrite a record that exists but cannot be read. When
      no record opens and at least one is unreadable, the storage key is unconfirmed
      and nothing at all is written at open.
    - A constructor save that the store rejects is retried before every later input
      until the store takes it.
  - Running:
    - `Device::handle(now, Input) -> Vec<Output>`: a `now` smaller than one seen before is
      treated as that earlier value, expired deadlines run before the input, and outputs
      come in order.
    - `Device::next_deadline() -> Option<Millis>` is the latest time for the next
      `Input::Tick`.
  - Inputs: `Input::{FidoReport(&[u8; 64]), OtpSetFeature(&[u8; 8]), OtpGetFeature,
    Ccid(&[u8]), CcidControlAbort { slot, seq }, Touch(TouchEdge), Tick, Bus(BusEvent)}`.
    `CcidControlAbort` was added because the CCID class request ABORT (USB CCID Rev 1.1
    §5.3.1) travels on the control pipe, which `Input::Ccid` cannot carry.
  - Bus events: `BusEvent::{Reset, Suspend, Resume, PowerCycle}`. `Resume` ends the card
    session and sends one `50 03` slot change.
  - Outputs: `Output::{FidoReport, OtpFeature, OtpKeyboard, Ccid, CcidInterrupt,
    PresenceIndicator(bool), Reenumerate(UsbInterfaces)}`.
  - Inspecting the device:
    - `Device::usb_identity() -> UsbIdentity` gives `vendor_id`, `product_id`,
      `device_release`, `manufacturer`, `product`, `serial` (`None` unless an OTP slot
      sets `EXTFLAG_SERIAL_USB_VISIBLE`), `interfaces`, `fido_report_descriptor`,
      `otp_report_descriptor` and `ccid_class_descriptor`.
    - `UsbIdentity::device_descriptor()` returns the 18-byte device descriptor, and
      `UsbIdentity::configuration_descriptor()` the full configuration descriptor for the
      enabled interfaces. For FIDO+CCID it is byte for byte the reference observation.
    - `Device::interfaces()`, `Device::profile()`, and `Device::presence_pending()` (the
      last `PresenceIndicator` state).
    - `Device::set_unix_time(Option<u64>)` backs `Host::unix_time`. The device never
      advances it.
  - Constants: `KEEPALIVE_INTERVAL_MS` (100), `WTX_INTERVAL_MS` (500),
    `U2F_REQUEST_WINDOW_MS` and `U2F_LATCH_MS` (3000), `OTP_REBOOT_DELAY_MS` (1000),
    `FIDO_REPORT_DESCRIPTOR`, `OTP_REPORT_DESCRIPTOR`.
  - `lk_device::storage`: `seal`, `open`, `record_id`, `SealError`, `FORMAT_VERSION`,
    `NONCE_LEN`, `TAG_LEN`, `OVERHEAD` (layout in "Phase 0 as implemented").
  - `Device` is `!Send`, because it holds `Box<dyn Store>` and `Box<dyn Entropy>` without
    `+ Send`. A program builds it inside the thread that drives it. Making it `Send`
    would mean tightening the `open`/`open_at` bounds; every store and entropy in the
    workspace is already `Send`. This is open for the program phase.
- **Program duties** (stated in the lk-device docs, binding on the program):
  - After open, check `unreadable_records()`. An application's first mutating command
    replaces an unreadable record, so a device opened with a wrong key loses what it
    replaces.
  - Call `set_unix_time` again whenever the program's trusted clock moves.
  - Queue or drop the outputs produced while the bus is suspended (keepalives, time
    extensions, timeout answers, keyboard reports).
  - Build the USB string descriptors (LANGID, UTF-16LE) from `UsbIdentity`.
- **Configuration changes apply at the next enumeration** (model policy, decided):
  only a Management write with `REBOOT` emits `Output::Reenumerate` and power-cycles
  volatile state (`settle_management`). A write without it, also one that changes the
  enabled interface set, takes effect at the next reboot or `BusEvent::PowerCycle`;
  until then the interfaces, `usb_identity` and application gating stay as enumerated.
  Source: ykman `config usb` asks for `REBOOT` exactly when the set changes, and yubikit
  `set_mode` writes without it and tells the user to re-insert the key; neither would
  be needed if the firmware re-enumerated by itself. Unmeasured on a physical 5.7.4
  (`docs/catalog/mgmt.md`, `device.md`; test
  `management::interface_change_without_reboot_waits_for_the_next_enumeration`).
  - **When the reboot happens** (added in the program phase, found with ykman on a real
    kernel): a write with `REBOOT` over CCID or CTAPHID reboots right after its response.
    Over OTP HID the write ends with the frame's last feature report, and yubikit then
    reads the status (programming sequence) to see the write succeed; rebooting at once
    made that read fail and ykman report a failed write. The device therefore reboots
    right after the next OTP status read (GET_REPORT), or `OTP_REBOOT_DELAY_MS` (1 s,
    model policy) after the write if the host reads nothing; a power cycle first takes
    the owed reboot over. Tests: `management::otp_hid_write_config_reboots_after_the_host_read_the_status`,
    `management::otp_hid_write_config_reboots_after_a_delay_without_a_status_read`,
    `management::a_power_cycle_before_the_status_read_takes_the_owed_reboot_over`.
- **Remaining known gaps** (also in `docs/STATUS.md`):
  - brainpoolP512r1 (4 OpenPGP variants, 5 deferred catalog lines).
  - Zeroization is partial (DESIGN §8):
    - lk-fido, lk-piv and lk-openpgp's S2K hold their secrets in `SecretBytes`.
    - lk-hsmauth, lk-sd, lk-device and lk-openpgp's key material wipe their own
      buffers in `Drop`, as a best effort.
    - lk-oath (credential and access keys), lk-otp (slot secrets and access codes) and
      lk-mgmt (lock code) keep plain buffers.
    - lk-codec's `Command`, `CommandChain` and `ResponseQueue`, which carry PINs and key
      material, are not wiped.
    - Copies the compiler makes of fixed-size values returned by lk-crypto cannot be
      wiped without `zeroize`, which only lk-crypto may use.
  - Every status word, timing and cadence that no public source fixes is a model policy,
    recorded in the crate's catalog file and unmeasured against a physical 5.7.4.

## Contract change requests

Phase 0 requests are resolved in "Phase 0 as implemented". The requests raised by the
application reviews (lk-device clearing applet authorization when a secure channel ends,
the extra `DeviceProfile` fields, `Host::unix_time`, the new curves, `Hasher`) are
resolved in the sections above. None is open.
