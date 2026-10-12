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
addition; nothing that another crate uses has been renamed or removed. Zeroization
requires exceptions: `lk_codec::apdu::Command` and now `lk_device::Output` implement
`Drop` (see "Program phase changes to the engine" and the transport maintenance contract
in `docs/PROGRAM.md`).

Goal (restated by the user on 2026-10-12): localkey is its own software security key, and
the YubiKey 5C Nano 5.7.4 is the reference it is compared against, not a device to clone.
"Reference, not replica" near the end of this file gives the binding decision order for
every externally visible behaviour; it overrides earlier wording here that treats the
reference key as the target.

## Rules for every crate

- Clean room: write from the specifications listed in `docs/DESIGN.md` §2.
- Externally visible behaviour follows the decision order of "Reference, not replica
  (2026-10-12, binding)": the specification first (with the host compatibility exception),
  the reference key where the specification is open, Yubico's documentation and yubikit
  for Yubico-proprietary protocols, never a reference defect, and the own identity in the
  default profile.
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
  `cert_not_before`, `cert_not_after` (see "Applications B" for the later fields, and
  "Measurement changes to the engine" for `part_number`);
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
  integration"). Superseded by the measurement: LOCK is `ERR_INVALID_CMD` and no lock
  exists ("Measurement changes to the engine").
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
    Between the measurement and the revision by principle of 2026-10-12 an empty CBOR request
    stalled the device instead ("Measurement changes to the engine").
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
- **Touch timeouts**: applets return `NeedTouch { timeout_ms }` (OATH 15000, FIDO 30000;
  FIDO was 28500 between the measurement and the revision by principle of 2026-10-12).
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
  - Applets answer `6882` for secure-messaging CLA bits and `6E00` for CLA >= `0x80`
    (since the measurement Management, HSM Auth, PIV and OpenPGP serve CLA `80` like `00`).
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
  - Touch timeouts: OATH, PIV, OpenPGP and HSM Auth use 15000 ms; FIDO uses 30000 ms
    (28500 ms between the measurement and the revision by principle of 2026-10-12).
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
  Superseded by the measurement: LOCK is `ERR_INVALID_CMD` and no lock exists.
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
  - Constants: `KEEPALIVE_INTERVAL_MS` (100; 95 since the measurement), `WTX_INTERVAL_MS` (500),
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
  - Zeroization (DESIGN §8; completed in the program phase, see below): every engine
    crate now wipes the secrets it holds. What is left: copies that leave a crate (an
    `lk_otp::Ticket` is `Copy`; raw byte copies made by output consumers;
    `Management::to_record` returns a plain copy; the bytes lk-codec hands to callers),
    lk-codec's best-effort wipe, and compiler copies of fixed-size values.
  - Every status word, timing and cadence that no public source fixes is a model policy,
    recorded in the crate's catalog file and unmeasured against a physical 5.7.4. (Refined
    on 2026-10-12, "Reference, not replica": a model policy is a choice where neither a
    specification nor the reference fixes the behaviour.)

## Program phase changes to the engine (as built, binding)

The program phase (`docs/PROGRAM.md`) changed the engine only where a real host tool or a
known gap required it.

- **lk-device, OTP HID reboot timing** (found with ykman on a real kernel): see
  "Configuration changes apply at the next enumeration" above; `OTP_REBOOT_DELAY_MS`.
- **lk-crypto**: `wipe(&mut [u8])` (zeroize's volatile wipe) and `wipe_vec(&mut Vec<u8>)`
  (zeroes the whole allocation, capacity included, and leaves the `Vec` empty with its
  capacity kept). `extend_secret(&mut Vec<u8>, &[u8])` appends bytes and wipes the
  previous allocation when growth is required.
- **lk-codec `apdu`** (zeroization):
  - `Command` wipes its data on drop. This changes field ownership:
    moving `cmd.data` out is now error E0509, and `..Default::default()` construction no
    longer compiles. `Command::into_data(self) -> Vec<u8>` hands the data over without a
    copy. Its `Debug` shows `data_len` instead of bytes.
  - `CommandChain` wipes on completion, clear, error and drop, and wipes the old buffer
    when it grows. `ResponseQueue` wipes when replaced, cleared, fully served or dropped.
    Both have a redacted `Debug`.
  - lk-codec does not depend on lk-crypto; its wipe is zero stores kept alive with
    `std::hint::black_box`, the same best effort as lk-sd and lk-hsmauth.
- **lk-oath**: credential keys, the access key, the saved record, HMAC outputs and the
  VALIDATE / SET CODE proofs are `SecretBytes`; records and code answers are allocated at
  their final size so they never reallocate.
- **lk-otp**: `SlotConfig` wipes `fixed`, `uid`, `key` and the access code on drop (all its
  fields are `Copy`, so callers compile unchanged); the record is `SecretBytes`; encrypted
  tickets, HID buffers, pending challenges and keyboard report buffers (allocated at full
  size) are wiped. `Ticket` and `Reply` have a `Debug` without the private ID or data.
- **lk-mgmt**: the lock code is wiped on drop; the record is saved from `SecretBytes`.
- **Security Domain device check**: `crates/lk-device/tests/secure_channel_scp11.rs` runs
  SCP11a and SCP11c with PIV behind the channel (protected PSO valid, failed and complete,
  MUTUAL AUTHENTICATE handover, wrapped signatures verified, plaintext ending the channel
  and the PIV PIN). The last deferred SD device line is tested.

## Measurement changes to the engine (as built, binding)

A read-only command-by-command measurement of a YubiKey 5C Nano 5.7.4 (`docs/MEASUREMENT.md`)
replaced these model policies. The sections above keep the values they were written with and
point here where they changed; `docs/MEASUREMENT.md` "Engine changes" lists every change with
its tests and probe. On 2026-10-12 every change below was reviewed under the decision order
of "Reference, not replica" (next section): each bullet says whether it was kept and by which
rule, and lines marked **Superseded (2026-10-12)** no longer describe the engine.

- **lk-core**: `DeviceProfile::part_number: String` (DeviceInfo tag `13`): empty in `own`,
  a 12-character placeholder in `yubikey_5c_nano_5_7_4`, never a real key's part number
  (kept, rules 3 and 5).
- **lk-ctaphid**:
  - `MAX_MESSAGE_LEN` (1536): a longer request gets `ERR_INVALID_LEN` at its initialization
    packet and its remaining packets are ignored; `MAX_PAYLOAD` (7609) stays the response
    limit (kept, rule 2).
  - `TRANSACTION_TIMEOUT_MS` is 470 (kept, rule 2).
  - `CTAPHID_LOCK` is answered `ERR_INVALID_CMD` and reserves nothing; `tick` no longer
    expires locks. `MAX_LOCK_SECONDS`, `cmd::LOCK` and `err::LOCK_REQUIRED` stay for source
    compatibility (kept, rule 2).
  - **Superseded (2026-10-12):** a `CTAPHID_CBOR` request with BCNT 0 was never answered
    here: the device stayed busy until INIT on that channel or `reset()`. Revised by rule 4
    (the stall is a reference defect, CTAP 2.1 §11.2.4 and §11.2.5.2): it is
    `ERR_INVALID_LEN` at the initialization packet again, like an empty MSG request
    (§11.2.9.1.2, §11.2.9.1.6), and holds nothing. No event reaches the application either
    way. The internal `Transaction::Stalled` is gone.
- **lk-device**: `KEEPALIVE_INTERVAL_MS` is 95, and the first KEEPALIVE is due one interval
  after the request (none at once) (kept, rule 2). A SELECT whose DF name starts with no
  enabled applet's AID selects the first enabled applet, in `AppId::ALL` order, whose AID
  starts with the DF name (a partial DF name; kept, rule 1: ISO/IEC 7816-4 §6.11 allows a
  right-truncated DF name and the ATR announces it). An empty DF name is the separate case
  of "Reference, not replica".
- **lk-fido**:
  - **Superseded (2026-10-12):** `TOUCH_TIMEOUT_MS` was 28 500 (300 KEEPALIVE intervals).
    It is 30 000 again by rule 4 (CTAP 2.1 §5 user action timeout; the key's 28.45 s is that
    value on a fast clock).
  - getPINRetries omits `powerCycleState` unless the PIN is soft-blocked (kept, rule 2:
    the field is optional in CTAP 2.1 §6.5.5).
  - **Superseded (2026-10-12):** getUVRetries answered `CTAP2_ERR_PIN_AUTH_INVALID` as on
    the key. It answers `CTAP2_ERR_INVALID_SUBCOMMAND` again by rule 1 (CTAP 2.1 §8.1).
- **lk-mgmt**: the SELECT text is `Virtual mgr - FW version <major>.<minor>.<patch>`;
  DeviceInfo is two fixed pages (new tag constants `FPS_VERSION` `0x20`, `STM_VERSION`
  `0x21`; `PAGE_LIMIT` stays as an upper bound); the factory challenge-response timeout
  byte is 15 (kept, rule 3; the SELECT text and the DeviceInfo layout are message formats
  yubikit parses, rule 5).
- **Card applets**: CLA `80` is served like `00` in Management, HSM Auth, PIV and OpenPGP;
  other classes `>= 0x80` keep `6E00`. GET RESPONSE with nothing pending answers `6D00`
  (Management, HSM Auth, OpenPGP), `6A80` (PIV) or `6982` (Security Domain) instead of
  `6985` (kept, rule 2: ISO/IEC 7816-4 leaves both open).
- **Revised by principle, 2026-10-12**: the card-side changes of that day, and the three
  FIDO revisions above, are listed in the table of "Reference, not replica" below.

## Reference, not replica (2026-10-12, binding)

localkey is the user's own software security key. The YubiKey 5C Nano 5.7.4 is the
**reference**: a well-made real key to compare against (`docs/MEASUREMENT.md`), not a device
to clone. This section is binding for every engine and program crate. It overrides older
wording in this file, in `docs/DESIGN.md` and in the catalog files that treats the reference
key as the target or ranks its measurement first (`docs/DESIGN.md` §2 and §12 decision 8
record the decision in Korean).

Decision order for every externally visible behaviour:

1. **Specification.** Where a public specification defines the behaviour (CTAP 2.1/2.2,
   CTAPHID, U2F raw messages, ISO/IEC 7816-4, NIST SP 800-73-4/-78, OpenPGP card 3.4,
   GlobalPlatform 2.3 with Amendments D and F, USB CCID 1.1, USB HID), follow the
   specification, even where the reference differs, and record the reference's behaviour
   as a known difference.
   **Compatibility exception:** where a widely used host stack (libfido2, python-fido2,
   Chromium/Firefox WebAuthn, Windows webauthn, yubikit/ykman, OpenSC, GnuPG scdaemon,
   yubico-piv-tool, pcsc-lite/libccid) demonstrably depends on the reference's non-spec
   behaviour, follow the reference and name the host and the reason.
2. **Reference where the specification is open.** Where the specification leaves the
   behaviour open (a status word among the allowed ones, a timing within its limits, an
   optional feature, a maximum size the device chooses), follow the reference key, as
   measured in `docs/MEASUREMENT.md` or documented by Yubico, because host software is
   tuned to it.
3. **Yubico-proprietary protocols** (Management, OTP HID frames, YKOATH, YubiHSM Auth, the
   Yubico PIV and OpenPGP extensions): Yubico's public documentation and yubikit's
   behaviour are the specification; the reference key is the best evidence of them.
4. **No defects.** Never copy the reference's defects: hangs or stalls, missing answers,
   unexplained quirks that a specification-conforming host would treat as errors, and
   clock-drift artefacts in timings. For a timing, use the design value the reference
   evidently intends: the KEEPALIVE measured at 95 ms stays 95 ms, because CTAP asks for
   "at least every 100ms", but a timeout that measures 28.45 s because a 30 s timer runs on
   a fast oscillator is 30 s.
5. **Own identity.** The default profile, `DeviceProfile::own`, carries no Yubico names,
   strings, AAGUID, part numbers or similar identifiers. The compatibility profile,
   `DeviceProfile::yubikey_5c_nano_5_7_4`, stays only for testing: with host tools that
   accept nothing else (ykman, libccid's reader list) and for the comparisons with the
   reference (`reference/` golden tests, `tools/measure/`). Yubico-protocol message
   formats stay where host tools parse them (the Management SELECT text, the DeviceInfo
   layout, the attestation extension OIDs).

Terms, as used in `docs/STATUS.md`, `docs/MEASUREMENT.md` and the catalog files:

- **model policy**: the engine's own choice where neither a specification nor the
  reference fixes the behaviour: the specification leaves it open and the reference was not
  measured, or its answer could not be observed. A later measurement decides it by rule 2
  (or rule 4, if what it shows is a defect).
- **known difference**: a behaviour of the reference that the engine deliberately does not
  follow, by rule 1, 4 or 5. The catalog line says `intentional difference` with the reason
  ("spec over reference", "reference defect not copied", "own identity"), and a probe that
  covers it differs by design. A rule-1 choice cites the section; a compatibility
  exception names the host.

Behaviours changed on 2026-10-12 (`docs/MEASUREMENT.md` "Revised by principle" lists the
tests and probes):

| Crate | Behaviour | Before | Now | Rule |
| --- | --- | --- | --- | --- |
| lk-ctaphid | `CTAPHID_CBOR` with BCNT 0 | never answered: the device stays busy (other channels `ERR_CHANNEL_BUSY`, CANCEL ignored, no timeout) until INIT on that channel or a USB reset; internal `Transaction::Stalled` (since 2811c86, as on the key) | `ERR_INVALID_LEN` at the initialization packet, nothing held; `Transaction::Stalled` removed | 4: "A request always triggers a response" (CTAP 2.1 §11.2.4), §11.2.5.2; the request is "BCNT 1..(n + 1)" (§11.2.9.1.2) |
| lk-fido | `TOUCH_TIMEOUT_MS`, every waiting CTAP2 command | 28 500 (300 × 95 ms; since 2811c86) | 30 000: 315 KEEPALIVEs, the last at 29 925 ms, then the answer alone | 4: clock drift (28 451.8 / 30 000 = 0.9484, the KEEPALIVE ratio); CTAP 2.1 §5 "Thirty seconds is a reasonable value" |
| lk-fido | clientPIN getUVRetries (`07`) | `CTAP2_ERR_PIN_AUTH_INVALID` (`33`; since 2811c86, as on the key) | `CTAP2_ERR_INVALID_SUBCOMMAND` (`3E`), like `06`; the engine has no built-in UV | 1: CTAP 2.1 §8.1, §6.5.5.3; no listed host depends on `33` |
| lk-piv | VERIFY with P2 `81` | `6A80` (since 2811c86, as on the key) | `6A88`, with or without data, Le or P1 `FF`; no retry spent | 1: SP 800-73-4 Part 2 §3.2.1 |
| lk-openpgp | `FACTORY_ISSUER_STATUS`, key information `DE` for ref `81` | `02`, imported (since 2811c86, as on the key) | `01`, generated on the device; stored `02` values are not migrated | 1: OpenPGP card 3.4.1 §4.4.3.8 |
| lk-sd | SELECT response (FCI) | 25 bytes without `9F65` (as on the key) | 29 bytes, `9F65 01 FF` inside `A5`, both profiles | 1: GP 2.3.1 §11.9.3.1 Table 11-82; `FF` is the 255-byte limit of §11.1.5 |
| lk-sd | GlobalPlatform-class GET DATA (`80`, and `84` unwrapped from SCP03/SCP11) | whole object only for plaintext `80 CA 00 66`; bare values otherwise | the whole BER-TLV data object for `66`, `E0`, `9F7F`, `BF21`, `FF33`/`FF34`; CLA `00` and `04` unchanged | 1: GP 2.3.1 §11.3.3.1 (unmeasured on the key beyond plaintext `80 CA 00 66`) |
| lk-sd | key information of an OCE CA public key | `B0 41` | `B0 40` | 1: GP 2.3.1 §11.3.3.1.1 (unmeasured) |
| lk-device, lk-sd | SELECT whose (unwrapped) class codes a logical channel other than 0 | changed the basic channel's selection and ended a secure channel | `6881`, selection and secure channel unchanged; CLA `FF` answers `6E00`; lk-sd closes its channel only on a basic-channel SELECT | 1: ISO/IEC 7816-4:1995 §5.5, Table 16; the ATR says "no logical channel" (unmeasured) |
| lk-device | SELECT by DF name with an empty name | `6A82` | selects the Security Domain | 1: GP 2.3.1 §11.9.2.3 (unmeasured) |
| lk-core | `DeviceProfile::own` form factor | `04`, USB-C Nano | `00` (new `form_factor::UNKNOWN`, additive); `yubikey_5c_nano_5_7_4` sets `04` explicitly | 5 |

Kept after the same review (no change):

- rule 2: the KEEPALIVE cadence (95 ms, the first one an interval after the request); the
  470 ms message timeout (one sample; a repeated series that shows the 0.9486 clock ratio
  would make 500 ms the design value under rule 4); the 1536-byte request limit;
  `CTAPHID_LOCK` not implemented; getPINRetries without `powerCycleState`; CLA `80` served
  like `00`; the statuses of an idle GET RESPONSE; the Security Domain's `6982` for an
  unknown instruction; PIV GET DATA `6A82` for a wrong P1-P2 and a cut-short tag list;
  OpenPGP GET DATA under CLA `10`.
- rule 1: SELECT by a partial DF name; the CTAPHID framing errors, CANCEL rules and
  timeout status mapping (already as specified).
- rule 3: the Management SELECT text, DeviceInfo pages, READ CONFIG P1/P2 and the factory
  challenge-response timeout (15 s, Yubico's documented default); PIV GET METADATA ignoring
  P1. OTP and OATH, which are disabled on the measured key, were reviewed against YKOATH,
  ykdef.h, yubikit and Yubico's OTP documentation; nothing changed.
- compatibility exception (known deviations from SP 800-73-4 Part 2 §2.4.3): a PIV PIN may
  hold any byte other than `FF`, because ykman documents and sends alphanumeric PINs; a new
  PUK must be 6 to 8 non-`FF` bytes padded with `FF`, so `FF`×8 is never a PUK, because
  yubikit's `PivSession.reset()` blocks the PUK by sending it and needs `63CX`.
- rule 5: the own profile keeps firmware version 5.7.4, a vendor-defined number that
  yubikit uses to gate PIV, OpenPGP, OATH and Management features, not a Yubico
  identifier. Its AAGUID, USB strings, ATR historical bytes, OpenPGP manufacturer (`FF00`)
  and attestation subjects were already its own.

## Contract change requests

Phase 0 requests are resolved in "Phase 0 as implemented". The requests raised by the
application reviews (lk-device clearing applet authorization when a secure channel ends,
the extra `DeviceProfile` fields, `Host::unix_time`, the new curves, `Hasher`) are
resolved in the sections above. None is open.

## Transport maintenance change to the engine (2026-10-12, binding)

`lk_device::Output` wipes every report and CCID payload on drop. Variant shapes and the
`Device::handle` API stay the same. Non-Copy payloads must be borrowed or transferred with
`std::mem::take`; moving a vector directly out of an Output is now E0509. The program
payloads and I/O buffers follow the same cleanup contract (`docs/PROGRAM.md`, "Transport
maintenance"). No third-party dependency was added outside `lk-crypto`.
