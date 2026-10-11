# Implementation status

Updated 2026-10-11. Every engine phase of `docs/DESIGN.md` §10 is done. The program phase
(`docs/DESIGN.md` §13, contract in `docs/PROGRAM.md`) has a working daemon with four
transports; see "Program phase" below. The engine sections describe the state at the final
engine integration (2026-10-10), plus the engine changes the program phase made (OTP HID
reboot timing, complete zeroization, the SCP11 device check; `docs/CONTRACTS.md` "Program
phase changes to the engine").

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
| 4 | lk-openpgp: 39 of the 43 advertised algorithm variants (all except brainpoolP512r1) | done (b18de5b); P-521, secp256k1 and brainpoolP256r1/P384r1 added in the final integration (57f3ede) |
| 5 | lk-sd (SCP03, SCP11a/b/c), lk-hsmauth | done (b18de5b, 77ed6c3), second reviews in the final integration |
| 6 | lk-device integration, end-to-end scenarios, adversarial verification, catalog closure | done (ac7ad99, 8d6aa06, 57f3ede, 1042fab) |

The final integration (57f3ede) added:

- curve work in lk-crypto, lk-codec and lk-openpgp;
- second independent reviews of every crate, which fixed bugs and added interop tests
  replaying yubikit/ykman, python-fido2, libfido2, Chromium, yubico-piv-tool, OpenSC,
  GnuPG, ykhsmauth and libccid request shapes byte for byte;
- the cross-application reset scenario (`crates/lk-device/tests/scenario_cross_app.rs`);
- `tools/catalog_status.py`;
- this documentation.

The closing commit (1042fab) then decided two model policies the reviews had left open: OpenPGP
accepts RSA attributes with a 17- to 32-bit exponent length, and Management configuration
changes apply at the next enumeration. It also added the device-level tests for OATH
access and a malformed plaintext SELECT after a secure channel ends.

## Verification at the final integration

- `CARGO_BUILD_JOBS=2 cargo test --workspace`: **1704 passed, 0 failed, 1 ignored**. The
  ignored test is lk-fido
  `tests::make_credential::ten_thousand_and_one_non_resident_registrations_leave_the_store_unchanged`,
  a long repeat test. It passes with `cargo test -p lk-fido --lib -- --ignored` (49 s, re-run
  after the final reviews).

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
  | lk-device | 210 |

- `cargo clippy --workspace --all-targets`: no warnings.
- `python3 tools/license_check.py`: no problems. 68 linked third-party crates, 10
  build-time only, all permissive, all reached only through lk-crypto. `cargo tree -d`
  shows no duplicate versions.
- `python3 tools/catalog_status.py --check`: every catalog bullet is labelled. The mapping
  has 451 lines across the per-crate files: 376 tested (8 of them with a part deferred
  or different), 31 intentional differences and 44 deferred. Details are in
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
- **Zeroization** (DESIGN §8, completed in the program phase): every engine crate wipes
  the secrets it holds. Left: copies that leave a crate (`lk_otp::Ticket` is `Copy`,
  keyboard reports, `Management::to_record`, bytes lk-codec hands to callers), lk-codec's
  best-effort wipe (no `zeroize` there), the program transports' own buffers, and
  compiler copies of fixed-size values.
- **Management flags**: touch-eject, remote-wakeup and auto-eject are stored and reported,
  but nothing acts on them.

Interop gaps the reviews found and left unchanged, because no public source shows the
physical answer:

- OpenSC's PIV GET CHALLENGE (GENERAL AUTHENTICATE with P1 `00`, P2 `9B`) answers `6A86`,
  so `pkcs11-tool --generate-random` may fail. This comes from the reviewer's recollection
  of `card-piv.c`, which was not checked.
- PIV refuses ECDSA digests longer than the field (`6A80`); host stacks truncate them
  themselves.
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
- Management configuration changes apply at the next enumeration; only `REBOOT`
  re-enumerates at once (ykman `config usb`, yubikit `set_mode`); over OTP HID the reboot
  follows the host's status read, or comes 1 s later (`OTP_REBOOT_DELAY_MS`, added in the
  program phase);
- OpenPGP RSA attributes accept exponent lengths of 17 to 32 bits (GnuPG and OpenSC write
  `0020`; FA lists `0011`);
- the touch timeouts (15 s for card applets, 30 s for FIDO);
- the OTP button windows;
- the CTAPHID lock answer (`ERR_CHANNEL_BUSY`).

Upstream note: ecdsa 0.17 disagrees with rfc6979 on how to truncate P-521 digests of 66
bytes or more, which can reveal the key. lk-crypto works around this, with tests. Filing
it upstream (RustCrypto/signatures) is still to do.

## Program phase

Commits 31dd38b … (2026-10-11), in three steps: the program core, the Linux transports, and
PC/SC through vpcd with transport combinations. Each crate was implemented against
`docs/PROGRAM.md`, reviewed adversarially by an independent agent and fixed; the Linux
transports and vpcd were then run on a real kernel with real host tools.

| Crate | Role | Tests |
| --- | --- | ---: |
| `lk-host` | state directory (0700, process lock, atomic per-record saves), OS entropy, storage key file or user command, serial | 51 |
| `lk-run` | runner thread that owns the `Device` (clock, deadlines, taps, suspend queue, presence watchers); `Fanout` | 34 |
| `lk-wire` | private Unix-socket transport (framed `Input`/`Output`) and the line control socket (incl. `shutdown`) | 99 |
| `lk-uhid` | Linux FIDO HID and OTP HID through `/dev/uhid` | 72 |
| `lk-gadget` | Linux ConfigFS + FunctionFS composite USB gadget (OTP, FIDO, CCID) | 156 |
| `lk-vpcd` | CCID as a card in pcscd's vsmartcard `vpcd` reader, with peer authentication | 121 |
| `localkeyd` | the daemon: `keygen`, `run --transport wire\|uhid\|gadget\|vpcd\|uhid,vpcd`, `ctl` | 88 |

All program crates are std only, without `unsafe`, like the engine. `tools/service/` holds
a systemd unit and a udev rule as examples.

### Verification (2026-10-11)

- macOS: `cargo test --workspace` **2350 passed, 0 failed, 1 ignored** (the lk-fido long
  repeat test). `cargo clippy --workspace --all-targets`: no warnings.
  `tools/license_check.py` (78 third-party crates, all through lk-crypto) and
  `tools/catalog_status.py --check` (451 lines: 378 tested, 31 intentional differences,
  42 deferred): clean.
- Linux (Docker, offline, `--network none`): **2351 passed, 0 failed, 1 ignored** (Linux
  runs the real `/proc` peer-check tests and skips the macOS-only refusal tests); clippy
  clean. Linux runs found two defects, both fixed: a control connection reset by unread
  input (0dfdebd) and a too-tight timing bound in an lk-vpcd test.
- Real kernel: `tools/linux-guest/` builds an Ubuntu 26.04 arm64 guest (its own 7.0.0-38
  kernel plus `dummy_hcd` built from the matching source) that runs under QEMU with no NIC
  inside a `--network none` container. Results at the final commit (all four scenarios
  re-run after the vpcd peer check), all PASS:
  - `smoke.sh`: modules, `dummy_udc.0`, vpcd driver, both USB transports enumerate and tear
    down cleanly.
  - `uhid.sh`: report descriptors byte-equal; libfido2 (`fido2-token`, `fido2-cred`,
    `fido2-assert` with a PIN); python-fido2 2.0.0 make/get with attestation verified; ykman
    info, OTP challenge-response (HMAC matches), static password typed as
    `Hello1World\n` on the kernel's keyboard device; `ykman config usb` re-enumeration both
    ways; `kill -9` and restart with every credential kept.
  - `gadget.sh`: descriptors byte-equal except the controller-assigned fields below; the
    same HID checks; CCID through pcscd/libccid: ATR, ykman info, OATH code (RFC 6238),
    PIV key and certificate generation, OpenPGP info, `gpg --card-status`; multi-packet
    CCID messages both ways (zero-length packet confirmed); suspend, resume, port reset and
    `authorized` 0/1; re-enumeration over CCID, OTP HID and FIDO HID; `kill -9` and the
    leftover-gadget reclaim.
  - `vpcd.sh`: `--transport vpcd` with pcscd and vsmartcard-vpcd 3.3: ATR, ykman info, OATH
    with touch, PIV keys and certificates (a 2907-byte certificate round trip, a 4007-byte
    extended APDU), OpenPGP, `gpg --card-status`, a touch-policy-ALWAYS signature completed
    by `ctl tap`, `ctl shutdown`; `--transport uhid,vpcd` as the whole device (libfido2 and
    ykman over all three connections, CCID disabled and re-enabled, `ykman config mode` plus
    `ctl power-cycle`, `kill -9` and restart); `systemd-analyze verify` and `udevadm verify`
    of the service examples.
- Defects the real tools found, all fixed with macOS regression tests: three in lk-uhid
  and three in lk-gadget (replies and outputs lost at re-enumeration, the kernel failing a
  reply followed at once by DESTROY, a SUSPEND of the ending session reaching the rebooted
  device), one in lk-vpcd (pcscd missed the card removal on an immediate re-plug; now a
  1.5 s pause), and one in the engine (an OTP HID `REBOOT` now waits for the host's status
  read, `OTP_REBOOT_DELAY_MS`, a new unmeasured model policy).

### Known gaps of the program

- **Gadget differences from the reference key that user space cannot fix** (dummy_hcd):
  endpoint addresses are the controller's, `iSerialNumber` is 3 with an empty string, and
  `bcdUSB`/DEVICE_QUALIFIER/BOS follow the controller. Other controllers (dwc2, dwc3, musb,
  chipidea) are untested.
- **uhid**: HID only (CCID comes from `vpcd` or the gadget). The OTP hidraw node needs a
  udev rule for desktop users (`tools/service/70-localkey.rules`). A device whose HID
  driver was unbound by someone else leaks one reader thread per re-enumeration (needs
  `poll`).
- **vpcd**: the link has no authentication of its own; localkeyd refuses non-loopback
  addresses unless told otherwise and, on Linux only, checks that the peer socket belongs
  to root, `pcscd` or itself (`docs/PROGRAM.md`). ykman needs the reader renamed to contain
  "Yubico YubiKey" (vpcd's `FRIENDLYNAME`); vpcd itself listens on every IPv4 interface; a `ctl power-cycle` without
  an interface change leaves the card in the reader; pcscd's `--auto-exit` drops the card
  between clients; vpcd on macOS is untested.
- **macOS**: only `wire` runs here (and `vpcd` if the user installs vpcd); virtual HID/USB
  needs Apple entitlements and signing. A PC/SC driver of our own would need a C ABI and
  therefore `unsafe`.
- **Keychain**: not integrated; `--key-command` lets the user connect one (`security
  find-generic-password -w ...`, `secret-tool`, `pass`).
- No signal handling (std cannot catch signals without `unsafe`): the daemon stops on
  `ctl shutdown`, on stdin EOF with `--exit-on-stdin-eof`, or when killed. Every save is
  atomic, so a kill loses nothing acknowledged; a killed gadget is reclaimed at the next
  start.
- The program transports do not wipe their own APDU/CTAP buffers.
- The guest image pins Ubuntu's kernel 7.0.0-38; it must be bumped when Ubuntu supersedes it.

## What is still open

- **Measurement**: a command-by-command comparison with a physical key, only with the
  user's explicit permission (DESIGN §13). It is the only way to turn the model policies
  above into measured behaviour.
- **macOS transports** (see "Known gaps of the program").
- `Device` is `!Send`; `lk-run` builds it on its own thread, so nothing needs it to be
  `Send` now.
- **Decisions to revisit before any public release** (DESIGN §12 records the current
  choices):
  - the project licence (none for now, all rights reserved);
  - whether the compatibility profile's Yubico VID/PID, strings and AAGUID may be
    shipped, a trademark and identity question (the default profile is the engine's own).
