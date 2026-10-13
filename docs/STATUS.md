# Implementation status

Updated 2026-10-13. localkey is its own software security key; a physical security key
serves as its comparison reference (`docs/DESIGN.md` §2 and §12
decision 8, `docs/CONTRACTS.md` "Reference, not replica"). Every engine phase of
`docs/DESIGN.md` §10 is done. The program phase (`docs/DESIGN.md` §13, contract in
`docs/PROGRAM.md`) has a working daemon with four transports; see "Program phase" below. The
engine sections describe the state at the final engine integration (2026-10-10), plus the
engine changes the program phase made (OTP HID reboot timing, complete zeroization, the
SCP11 device check; `docs/CONTRACTS.md` "Program phase changes to the engine") and those
that followed the comparison with the reference key ("Reference comparison" below).

What "done" means here: behaviour is tested against the public specifications, published
test vectors and the public bytes read from the reference key
(`reference/physical-key/`). Where a specification defines a behaviour, the engine
follows the specification, even where the reference differs (unless a widely used host stack
depends on the reference's behaviour); where the specification leaves it open, the engine
follows the reference; it never copies the reference's defects, and its default identity is
its own. A **model policy** is a choice where neither a specification nor the reference fixes
the behaviour; each one is recorded with its reasoning in the crate's catalog file
(`docs/catalog/`). Nothing in this repository claims that the engine is identical to the
reference key, and being identical is not the goal.

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

  These per-crate counts are those of the final integration; the current workspace totals
  are under "Program phase", "Verification (2026-10-12, after the revision by principle)".

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
  raw keyboard-report copies, `Management::to_record`, bytes lk-codec hands to callers), lk-codec's
  best-effort wipe (no `zeroize` there), raw bytes handed to callers, and compiler
  copies of fixed-size values. Owned device outputs and program transport buffers now
  have cleanup (see the maintenance section below).
- **Management flags**: touch-eject, remote-wakeup and auto-eject are stored and reported,
  but nothing acts on them.

Interop gaps the reviews found and left unchanged, because neither a specification nor the
reference key shows the answer:

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

Model policies (neither a specification nor the reference fixes them; each is documented in
its catalog file):

- every status word that neither a specification nor the measurement of the reference
  fixes;
- the CCID time-extension cadence (500 ms);
- the U2F request window and latch (3 s each);
- the restart of the CTAPHID message timeout on every accepted packet;
- Management configuration changes apply at the next enumeration; only `REBOOT`
  re-enumerates at once (ykman `config usb`, yubikit `set_mode`); over OTP HID the reboot
  follows the host's status read, or comes 1 s later (`OTP_REBOOT_DELAY_MS`, added in the
  program phase);
- OpenPGP RSA attributes accept exponent lengths of 17 to 32 bits (GnuPG and OpenSC write
  `0020`; FA lists `0011`);
- the card touch timeouts (15 s);
- the OTP button windows.

Upstream note: ecdsa 0.17 disagrees with rfc6979 on how to truncate P-521 digests of 66
bytes or more, which can reveal the key. lk-crypto works around this, with tests. Filing
it upstream (RustCrypto/signatures) is still to do.

## Reference comparison

The engine is compared with the reference key, not built to be identical to it. One
read-only, command-by-command comparison was made on 2026-10-11: 116 probes, the same ones
sent to the reference key and to the engine. `docs/MEASUREMENT.md` holds the method,
the data, every difference and what was decided about it; `docs/CONTRACTS.md` "Reference,
not replica" holds the binding decision order and the table of the 2026-10-12 changes.

- **Adopted from the reference** (the specification leaves it open, rule 2, or the protocol
  is Yubico's own, rule 3): the KEEPALIVE cadence (95 ms, the first one an interval after
  the request), the CTAPHID message timeout (470 ms), the 1536-byte request limit,
  `CTAPHID_LOCK` not implemented (`ERR_INVALID_CMD`), getPINRetries without
  `powerCycleState`, the Management SELECT text and DeviceInfo pages, CLA `80` in
  Management, HSM Auth, PIV and OpenPGP, the statuses of an idle GET RESPONSE, and the other
  card status words of `docs/MEASUREMENT.md` "Engine changes". SELECT by a partial DF name,
  also adopted, is what ISO/IEC 7816-4 §6.11 allows (rule 1).
- **Intentional differences decided on 2026-10-12** (`docs/MEASUREMENT.md` "Revised by
  principle"):
  - measured on the key, and now different by design:
    - an empty `CTAPHID_CBOR` gets `ERR_INVALID_LEN` and holds nothing; the key stalls the
      whole device (rule 4; CTAP 2.1 §11.2.4, §11.2.5.2);
    - the FIDO user-presence timeout is 30 s, with 315 KEEPALIVEs; the key's 28.45 s and
      300 KEEPALIVEs are a 30 s timer on a fast clock (rule 4; CTAP 2.1 §5);
    - clientPIN getUVRetries answers `CTAP2_ERR_INVALID_SUBCOMMAND` (`3E`); the key `33`
      (rule 1; CTAP 2.1 §8.1);
    - PIV VERIFY with P2 `81` answers `6A88`; the key `6A80` (rule 1; SP 800-73-4 Part 2
      §3.2.1);
    - OpenPGP reports the factory attestation key as generated, `DE … 81 01`; the key `02`
      (rule 1; OpenPGP card 3.4.1 §4.4.3.8);
    - the Security Domain's SELECT response carries `9F65 01 FF` (29 bytes); the key's 25
      bytes omit it (rule 1; GP 2.3.1 Table 11-82).
  - required by the specification, not measured on the key (rule 1):
    - GlobalPlatform-class GET DATA (`80`, and `84` through a secure channel) returns the
      whole data object (GP 2.3.1 §11.3.3.1);
    - an OCE CA public key's key information is `B0 40` (§11.3.3.1.1);
    - a SELECT on a logical channel other than 0 answers `6881` and changes nothing; CLA
      `FF` answers `6E00` (ISO/IEC 7816-4 §5.5);
    - an empty DF name selects the Security Domain (GP 2.3.1 §11.9.2.3).
  - identity (rule 5): the own profile reports form factor `00` (UNKNOWN); the
    compatibility profile keeps the reference's `04`.
- **Kept under the compatibility exception** (known deviations from SP 800-73-4 Part 2
  §2.4.3): a PIV PIN may hold any byte other than `FF` (ykman offers alphanumeric PINs), and
  `FF`×8 is never a valid PUK (yubikit's PIV reset relies on it).
- **Against the recorded physical runs** (`docs/MEASUREMENT.md` "Comparison after the
  revision"): 27 of 116 probes differ and 89 are identical (13 and 103 before the revision).
  The 27 are key state (6 probes), unclear cases of CLA `0C` and of SELECT with odd P2
  (5), one host artefact, and 15 probes that show the intentional differences above (one
  of them, `cla-variants-sd`, also contains the unclear CLA `0C` case). `selection-no-touch`
  compares as identical only within the tool's timing tolerances; by design it answers at
  30 s, the key at 28.45 s.

## Program phase

Commits 31dd38b … (2026-10-11), in three steps: the program core, the Linux transports, and
PC/SC through vpcd with transport combinations. Each crate was implemented against
`docs/PROGRAM.md`, reviewed adversarially by an independent agent and fixed; the Linux
transports and vpcd were then run on a real kernel with real host tools.

| Crate | Role | Tests |
| --- | --- | ---: |
| `lk-host` | state directory (0700, process lock, atomic per-record saves), OS entropy, storage key file or user command, serial | 51 |
| `lk-run` | runner thread that owns the `Device` (clock, deadlines, taps, suspend queue, presence watchers); `Fanout` | 38 |
| `lk-wire` | private Unix-socket transport (framed `Input`/`Output`) and the line control socket (incl. `shutdown`, `tap pending`) | 101 |
| `lk-uhid` | Linux FIDO HID and OTP HID through `/dev/uhid` | 74 |
| `lk-gadget` | Linux ConfigFS + FunctionFS composite USB gadget (OTP, FIDO, CCID) | 156 |
| `lk-vpcd` | CCID as a card in pcscd's vsmartcard `vpcd` reader, with peer authentication | 121 |
| `localkeyd` | the daemon: `keygen`, `run --transport wire\|uhid\|gadget\|vpcd\|uhid,vpcd`, `ctl` | 88 |

All program crates are std only, without `unsafe`, like the engine. `tools/service/` holds
a systemd unit and a udev rule as examples.

### Linux desktop distribution preparation (2026-10-12)

The user selected Linux first (CLI, touch UI and installable bundle), public
source/binary distribution and Apache-2.0. The workspace now inherits that license;
`LICENSE` and `NOTICE` are present. This is a desktop preview, not a public release.

- `tools/linux/`: user-session Tk touch window, an isolated root helper with only
  `status`, `watch`, `tap`, `tap long` on a fixed private socket, and a polkit action
  requiring administrator authentication from an active local session. UI exit
  closes the helper's watch through its stdin pipe even while presence stays idle.
  The UI never touches automatically, and enables touch only for pending presence.
  The helper's short tap uses `tap pending`; expiry/check/edge share a runner timestamp
  so late authentication or cancellation cannot produce an idle OTP tap.
- A separate HID-only `localkeyd.service` and installer/uninstaller. The installer
  reuses existing keys, refuses to create a new key for existing state, and leaves
  keys/state on uninstall. `--destdir` only stages program files; symlink escapes
  are refused. Optional PC/SC remains the manual `tools/service/` setup.
- `tools/package_linux.py`: validates static ELF architecture, includes original
  dependency, Rust standard-library and static musl notices, a source/binary
  manifest and checksums, and normalizes archive metadata. Only an explicit private-test bundle can use the current `1209:0001`
  PID. No automatic publication. The checksum is integrity, not signed provenance.
- Eight helper/packager/policy tests and three Tk tests passed on Linux under Xvfb;
  shellcheck, desktop-file validation and local polkit DTD validation passed.
  A disk-output preflight regression also passed: repository/root paths are rejected
  before any permission change (12 desktop tests in CI, including this check).
  Relevant Rust suites (`lk-run`, `lk-wire`, `localkeyd`): 227 passed, including
  idle/cancelled/expired and held-sensor conditional touch regression cases.
  Measurement-harness tests: 31 passed. Workspace Clippy with `-D warnings`: clean.
  All 22 workspace manifests inherit Apache-2.0; the dependency policy and catalog checks remain clean.
- Offline/no-NIC aarch64 guest `desktop.sh`: rc=0. Verified bundle checksums,
  explicit test opt-in, staging, uninstall preserving key/state markers, reinstall,
  symlink refusal, service/udev syntax, installed helper rejecting shutdown, own HID
  enumeration, libfido2 credential/attestation verification and assertion/signature
  verification after daemon restart. The guest runs a custom PID 1, so this does
  **not** validate the unit's runtime sandbox or systemd install/start lifecycle.
- Real Debian 13 systemd/LightDM/Xfce desktop VMs, fresh disks on aarch64 and
  x86_64: **26 checks passed each**. Own-profile Chromium/Firefox registration,
  login, required PIN/resident keys and UV, cancellation and 30-second presence
  timeout, conditional late-touch refusal, actual administrator authentication,
  user key/state/helper denial and polkit denial outside a desktop session all
  passed. Actual install, upgrade, uninstall preserving key/state, missing-key
  reinstall refusal, wrong-key startup exit 3 without record modification, and
  recent matched backup restoration with both PIN logins also passed. The RP
  verifies real signatures, own attestation/AAGUID, origin/RP/challenge/UP/UV and
  increasing counters. Versions, selected JSON/screenshots, reproduction and
  explicit limits: `docs/LINUX_DESKTOP_VERIFICATION.md`.
- `.github/workflows/linux-preview.yml` checks engines, licenses, catalog, UI and
  private-test build/staging on Ubuntu 24.04 x86_64/aarch64 runners. Current runs:
  <https://github.com/yakisoba0728/localkey/actions/workflows/linux-preview.yml>.
  On 2026-10-13, fresh VMs passed **43 checks each (86 total)**, including actual
  inactive-local/SSH denial after administrator authentication, Chromium/Firefox
  discoverable-account selection, retained-grant expiry and native reauthentication,
  and a full reboot preserving the same RP public credentials/counters. Both
  allow-list and discoverable logins passed after reboot with increasing counters.
  The fixture now waits for user HID access and native Firefox prompts, and saves
  RP public state atomically; a self-test rejects repeated/zero counter rollback.
  Physical and stock Ubuntu desktops remain outside this preview's coverage;
  an assigned PID and a reviewed signed release remain publication gates.
- Ubuntu 26.04.1 GDM/GNOME/Wayland with signed Snapd 2.78 candidate passed all
  **46 aarch64 checks including recovery and both boots**; x86_64 is in progress. See
  `docs/UBUNTU_DESKTOP_VERIFICATION.md`. Stable Snapd 2.77.1 refuses the own UHID
  node despite FIDO/uaccess tags and connected browser plugs. Signed 2.78
  candidate checks keep confinement enabled and are separate from stable support.
  Actual browser processes retain the official Snap WebDriver AppArmor profiles
  in enforce mode and use native Wayland. Candidate coverage does not establish
  default/stable Ubuntu support or an interactive ISO/physical desktop installation.
- Both static musl preview bundles were generated locally. x86_64 cross-build
  succeeded and its keygen/wire-status/conditional-touch/shutdown CLI lifecycle
  passed under emulation; aarch64 HID execution is covered by the guest above.
  The x86_64 binary also passed the real systemd desktop VM flow above.
- The Linux CI run for `1a2de8d` passed on 2026-10-13 on both architectures:
  2,390 Rust tests per native job, Clippy, license/catalog checks, measurement tests,
  desktop/installer tests and static-musl bundle staging.
  <https://github.com/yakisoba0728/localkey/actions/runs/38323529249>.
- `tools/pidcodes/`: request for `1209:4C4B` submitted on 2026-10-13 as
  <https://github.com/pidcodes/pidcodes.github.com/pull/1310>. The complete upstream
  tree and open PRs had no conflict; the public source/license/evidence were readable
  without authentication. Allocation is pending; the candidate is not used or reserved.
  Public source is Apache-2.0; `1209:0001` continues to block public binary packaging.
- `.github/workflows/linux-release.yml` prepares both static-musl bundles from a clean
  version tag on main. It requires a matching upstream PID allocation, reruns checks,
  signs/verifies build provenance and creates only a draft prerelease. It has no push
  trigger. `docs/RELEASE.md` records the remaining desktop verification and publication
  steps. No public binaries or release tags have been created.

### Transport maintenance (2026-10-12)

- Closed the UHID reader/file leak when a driver unbind leaves DESTROY without STOP:
  nonblocking reads and a 20 ms idle retry preserve partial events and notice the writer
  ended. Regression tests cover repeated re-enumeration without STOP and split events
  across read timeouts.
- Owned reports, APDU/CTAP payloads, serialized queues and scratch buffers now have
  cleanup on release or reuse, including queue failure, partial-message discard and
  buffer growth. The public Drop/ownership changes and remaining copy boundaries are
  recorded in `docs/PROGRAM.md` "Transport maintenance".
- Reconciled the catalog: file modes and process locking have program tests, and the
  obsolete "SCP11 PSO then PIV not written" note is removed. Current counts are 451
  mapping lines: 374 tested (13 partly deferred or different), 37 intentional differences,
  40 deferred. Deferred legacy fixture coverage is not an implementation-task count.
- macOS: `cargo test --workspace --locked -- --include-ignored`: **2389 passed, 0 failed,
  0 ignored**, including the 10,001-registration FIDO repeat test. Clippy with
  `--workspace --all-targets --locked -- -D warnings`: clean. License policy and catalog
  checks: clean. Measurement-harness unit tests: 31 passed (fake backends only).
- Offline, no-NIC Linux guest: `uhid.sh`, `gadget.sh` and `vpcd.sh` all rc=0. UHID shutdown
  after driver unbind completed in 310 ms, exit 0, without a reader timeout. The guest
  run now asserts clean shutdown and no reader left behind. `gadget.sh` and `vpcd.sh`
  used the final rebuilt static binary, including scratch-buffer cleanup; no physical
  reference key or host HID/PCSC device was used.

### Verification (2026-10-12, after the revision by principle)

- macOS: `cargo test --workspace` **2378 passed, 0 failed, 1 ignored** (the lk-fido long
  repeat test). `cargo clippy --workspace --all-targets`: no warnings.
  `tools/license_check.py` (78 third-party crates, all through lk-crypto) and
  `tools/catalog_status.py --check` (451 lines: 372 tested, 13 of them partly deferred or
  different, 37 intentional differences, 42 deferred): clean.
- Linux (Docker, offline, `--network none`): **2379 passed, 0 failed, 1 ignored**; clippy clean.
- Engine against the recorded physical runs (`docs/MEASUREMENT.md`, "Comparison after the
  revision"): 27 of 116 probes differ, each explained as key state, host artefact, unclear,
  or an intentional difference of the revision.
- Guest scenarios (`uhid.sh`, `gadget.sh`, `vpcd.sh`, compatibility profile): rc=0 each.
  The first `uhid.sh` attempt lost the head of the evdev key stream in step 4 under host
  load (the hidraw reports were complete and correct); the re-run passed.

### Verification (2026-10-12, after the measurement alignment)

- macOS: `cargo test --workspace` **2369 passed, 0 failed, 1 ignored** (the lk-fido long
  repeat test). `cargo clippy --workspace --all-targets`: no warnings.
  `tools/license_check.py` (78 third-party crates, all through lk-crypto) and
  `tools/catalog_status.py --check` (451 lines: 374 tested, 35 intentional differences,
  42 deferred): clean.
- Linux (Docker, offline, `--network none`): **2370 passed, 0 failed, 1 ignored**; clippy clean.
- Guest scenarios re-run after the alignment (`uhid.sh`, `gadget.sh`, `vpcd.sh`): all PASS.

### Verification (2026-10-11)

- macOS: `cargo test --workspace` **2350 passed, 0 failed, 1 ignored**.
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
  udev rule for desktop users (`tools/service/70-localkey.rules`). Readers now use
  nonblocking I/O and a 20 ms idle retry, so an unbound HID driver no longer leaves a
  reader behind when DESTROY produces no STOP event.
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
- Owned program APDU/CTAP buffers are wiped on release; compiler copies and buffers
  outside this process are not covered (see the maintenance section below).
- The guest image pins Ubuntu's kernel 7.0.0-38; it must be bumped when Ubuntu supersedes it.

## What is still open

- **Further measurement of the reference key**, only with the user's explicit permission
  (DESIGN §13): what the comparison of 2026-10-11 could not reach (OTP and OATH, which are
  disabled on the measured key; the card touch timeouts; the U2F window and latch; raw
  CCID; SELECT with P2 other than `00` while PIV is selected; a broadcast INIT during a
  touch wait; a repeated series for the message timeout). A result decides a model policy
  by rule 2, or shows a design value by rule 4.
- **macOS transports** (see "Known gaps of the program").
- `Device` is `!Send`; `lk-run` builds it on its own thread, so nothing needs it to be
  `Send` now.
- **Decisions to revisit before any public release** (DESIGN §12 records the current
  choices):
  - the project licence is now Apache-2.0; include original dependency notices in every binary bundle;
  - whether the compatibility profile's Yubico VID/PID, strings and AAGUID may be
    shipped, a trademark and identity question (the default profile is the engine's own).
