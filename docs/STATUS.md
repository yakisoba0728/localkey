# Implementation status

Updated 2026-10-10 at the final integration. Every phase of `docs/DESIGN.md` §10 is done, so
the engine is complete. The program phase (`docs/DESIGN.md` §13) has not started.

What "done" means here: behaviour is tested against the public specifications, published
test vectors and the public bytes read from a real key (`reference/yubikey-5c-nano-5.7.4/`).
It has **not** been compared command by command with a physical YubiKey 5C Nano. Every status
word, timing and cadence that no public source fixes is a model policy, recorded with its
reasoning in the crate's catalog file (`docs/catalog/`). Nothing in this repository claims
parity with the physical device.

## Phases

| Phase | Scope | State |
| --- | --- | --- |
| 0 | lk-core contract, lk-crypto, lk-codec, lk-ctaphid, lk-ccid, lk-testkit, sealing | done (935b4f1): 523 tests at the time, 24 bugs fixed by reviewers |
| 1 | lk-fido: CTAP 2.1 commands, PIN/UV protocols 1 and 2, extensions, U2F, self attestation | done (b43c96b), second review in the final integration |
| 2 | lk-otp, lk-oath, lk-mgmt | done (b43c96b, 2978875), second reviews in the final integration |
| 3 | lk-piv | done (b18de5b), second review in the final integration |
| 4 | lk-openpgp: 39 of the 43 advertised algorithm variants (all except brainpoolP512r1) | done (b18de5b); P-521, secp256k1 and brainpoolP256r1/P384r1 added in the final integration |
| 5 | lk-sd (SCP03, SCP11a/b/c), lk-hsmauth | done (b18de5b, 77ed6c3), second reviews in the final integration |
| 6 | lk-device integration, end-to-end scenarios, adversarial verification, catalog closure | done (ac7ad99, 8d6aa06, final integration) |

The final integration made these changes; none of them is committed yet:

- curve work in lk-crypto, lk-codec and lk-openpgp;
- second independent reviews of every crate, which fixed bugs and added interop tests
  replaying yubikit/ykman, python-fido2, libfido2, Chromium, yubico-piv-tool, OpenSC,
  GnuPG, ykhsmauth and libccid request shapes byte for byte;
- the cross-application reset scenario (`crates/lk-device/tests/scenario_cross_app.rs`);
- `tools/catalog_status.py`;
- this documentation.

## Verification at the final integration

- `CARGO_BUILD_JOBS=2 cargo test --workspace`: **1701 passed, 0 failed, 1 ignored**. The
  ignored test is lk-fido
  `tests::make_credential::ten_thousand_and_one_non_resident_registrations_leave_the_store_unchanged`,
  a long repeat test. It passes with `cargo test -p lk-fido --lib -- --ignored` (48 s).

  | Crate | Tests |
  | --- | ---: |
  | lk-core | 2 |
  | lk-crypto | 127 |
  | lk-codec | 153 |
  | lk-ctaphid | 96 |
  | lk-ccid | 91 |
  | lk-testkit | 57 |
  | lk-fido | 165 (+1 ignored) |
  | lk-otp | 98 |
  | lk-oath | 76 |
  | lk-mgmt | 75 |
  | lk-piv | 155 |
  | lk-openpgp | 197 |
  | lk-hsmauth | 93 |
  | lk-sd | 109 |
  | lk-device | 207 |

- `cargo clippy --workspace --all-targets`: no warnings.
- `python3 tools/license_check.py`: no problems. 68 linked third-party crates, 10
  build-time only, all permissive, all reached only through lk-crypto. `cargo tree -d`
  shows no duplicate versions.
- `python3 tools/catalog_status.py --check`: every catalog bullet is labelled. The mapping
  has 451 lines across the per-crate files: 374 tested (8 of them with a part deferred
  or different), 31 intentional differences and 46 deferred. Details are in
  `docs/CATALOG_STATUS.md`.
- No rule enforces rustfmt, and the tree has never been rustfmt-clean (files untouched
  since Phase 0 differ too). Formatting was left as written.

## Known gaps and deferred items

Behaviour the engine does not have:

- **brainpoolP512r1**: RustCrypto publishes no crate for it, so the 4 OpenPGP variants
  answer `6A81`. This accounts for 5 deferred catalog lines.
- **OTP static tickets**: the `STRONG_PW1`/`STRONG_PW2` character transforms are stored but
  not applied, because the public sources do not give the positions. `MAN_UPDATE` manual
  regeneration is not implemented.
- **Security Domain**: the GP role policy identifiers, the `BF20` element and the critical
  subject-ID extension are not in the available sources. A certificate carrying them is
  refused as having an unknown critical extension.
- **Security Domain checks not written at device level** (deferred in `docs/catalog/sd.md`):
  - the OATH access state after a secure channel ends;
  - an SCP11 PSO followed by PIV commands;
  - a malformed plaintext SELECT revoking the PIV PIN.

  lk-device does clear the selected applet's authorization when a channel ends, and the
  PIV case is tested.
- **Zeroization is partial** (DESIGN §8):
  - lk-fido, lk-piv and the OpenPGP S2K use `lk_crypto::SecretBytes`;
  - lk-hsmauth, lk-sd, lk-device and the OpenPGP key material wipe their own buffers in
    `Drop`;
  - lk-oath (credential and access keys), lk-otp (slot secrets, access codes), lk-mgmt
    (lock code) and lk-codec's APDU buffers are not wiped.
- **Management flags**: touch-eject, remote-wakeup and auto-eject are stored and reported,
  but nothing acts on them.

Interop gaps the reviews found and left unchanged, because no public source shows the
physical answer:

- OpenPGP rejects RSA attributes with a 32-bit exponent length (`01 nnnn 0020 00`) with
  `6A80`. GnuPG sends this when it switches a slot from ECC back to RSA, and OpenSC sends it
  before every RSA key generation, so both fail there. yubikit is unaffected.
- OpenSC's PIV GET CHALLENGE (GENERAL AUTHENTICATE with P1 `00`, P2 `9B`) answers `6A86`,
  so `pkcs11-tool --generate-random` may fail. This comes from the reviewer's recollection
  of `card-piv.c`, which was not checked.
- PIV refuses ECDSA digests longer than the field (`6A80`); host stacks truncate them
  themselves.
- When a Management write without `REBOOT` changes the interface set, lk-device
  re-enumerates at once. ykman and yubikit behaviour suggests the firmware waits for
  re-insertion. This is recorded as an open model-policy question in `docs/CONTRACTS.md`.
- Smaller edges, each documented in its crate:
  - a CTAPHID INIT with BCNT other than 8 on a busy channel does not abort the transaction;
  - a late control ABORT that arrives after a newer bulk Abort leaves lk-ccid waiting;
  - lk-ccid SetParameters is strict about the convention bit;
  - an OTP HID response longer than 221 bytes is dropped;
  - the OTP programming sequence goes 255 → 1;
  - SCAN_MAP ignores the trailing access code;
  - fast trigger needs slot 2 empty;
  - OTP and CCID status words differ for a past-the-end info page and for a 64-byte
    length byte;
  - one large-blob sequence edge answers `INVALID_SEQ`;
  - the OpenPGP KDF lock lifts once every user key is deleted.

Model policies (unmeasured, documented in each catalog file):

- every status word no source fixes;
- the KEEPALIVE cadence (100 ms) and the CCID time-extension cadence (500 ms);
- the U2F request window and latch (3 s each);
- the touch timeouts (15 s for card applets, 30 s for FIDO);
- the OTP button windows;
- the CTAPHID lock answer (`ERR_CHANNEL_BUSY`).

Upstream note: ecdsa 0.17 disagrees with rfc6979 on how to truncate P-521 digests of 66
bytes or more, which can reveal the key. lk-crypto works around this, with tests. Filing
it upstream (RustCrypto/signatures) is still to do.

## What the program phase needs

From `docs/DESIGN.md` §13 and the duties the lk-device docs state
(`docs/CONTRACTS.md` "Final integration"):

- **Transports.**
  - Linux: UHID or a FunctionFS/ConfigFS composite gadget, and a PC/SC IFD handler.
  - macOS: IOHIDUserDevice/IOUSBHost, which need Apple entitlements and signing.
  - On every platform the program routes control and endpoint traffic and builds the USB
    string descriptors (LANGID, UTF-16LE) from `Device::usb_identity()`. It also handles
    HID class requests (SET_IDLE, SET_PROTOCOL, LED output) and a Report ID prefix, and
    re-enumerates on `Output::Reenumerate`.
- **The run loop.**
  - One thread owns the `Device` (it is `!Send`; making it `Send` is an open decision)
    and feeds it inputs with a monotonic `now`.
  - It delivers `Input::Tick` by `next_deadline()` and acts on every output in order.
  - It queues or drops outputs produced while the bus is suspended, and calls
    `set_unix_time` again whenever a trusted clock moves.
- **Storage.**
  - A `Store` with atomic per-record writes, a 0600 state file and a process lock.
  - The 32-byte storage key kept in the OS keychain.
  - After open, check `unreadable_records()` before serving, because the first
    mutating command of an application replaces its unreadable record.
- **Entropy**: an `Entropy` backed by OS randomness.
- **Touch UI**: touch edges in, `PresenceIndicator` out; OTP keyboard reports to a real
  keyboard interface.
- **Measurement**: a command-by-command comparison with a physical key, only with the
  user's explicit permission (DESIGN §13). It is the only way to turn the model policies
  above into measured behaviour.
- **Decisions left open in DESIGN §12**:
  - the project licence;
  - the trademark and identity question of the compatibility profile;
  - fast-forwarding `main` to `engine` after review.
