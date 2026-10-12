# Behaviour catalog status

Every relevant bullet of `reference/BEHAVIOR_CATALOG.md` (the behaviour list recorded by
the legacy v0.64 implementation) is mapped, in the file of the crate that owns it, to one
label:

- `tested`: the named tests pass and exercise what the engine can show of the bullet;
- `intentional difference`: the engine deliberately behaves or verifies differently from
  the bullet, or from the reference key, and the line says why. The reasons follow the
  decision order of `docs/CONTRACTS.md` "Reference, not replica" (`docs/DESIGN.md` §2 and
  §12 decision 8): a specification that defines the behaviour ("spec over reference", rule
  1, or the host compatibility exception), the reference key where the specification is
  open and the bullet says otherwise (rule 2), a reference defect not copied (rule 4), the
  own identity (rule 5), or something the engine does not have by design (a program-phase
  transport, legacy state, a legacy release artifact);
- `deferred`: something the bullet needs is missing, and the line says what.

"Tested" means tested against the specifications, published vectors and the public bytes
read from the reference key (`reference/physical-key/`).
It does not mean that the engine is identical to that key, which is not the goal. One
read-only command-by-command comparison with the reference was made
(`docs/MEASUREMENT.md`): the lines it settled say "measured on the reference key"
with the probe; where a specification defines the answer and the key differs, the key's
answer is recorded as an intentional difference (a known difference). A **model policy** is
a choice where neither a specification nor the reference fixes the behaviour (the
specification leaves it open and the reference was not measured, or its answer could not be
observed); each one is recorded with its reasoning in the crate's file.

## Summary

Counted by `python3 tools/catalog_status.py --write`; `--check` fails when a bullet has no
label or this table is stale. The rule is the same for every file:

- every `## ` section that maps catalog bullets counts, including "related rows",
  "appendix B rows" and bullets of other sections a crate took over; note sections
  (model policies or decisions, review notes, interop notes) do not;
- each top-level bullet is one line with one label: the first `tested`,
  `intentional difference` or `deferred` after `—` or `:`;
- "of which partly deferred or different" counts `tested` lines that name a part still
  deferred or deliberately different (usually a program-phase transport);
- "not a ... item" lines in `device.md` (bullets of the device section that another
  crate owns) are not counted.

<!-- BEGIN tools/catalog_status.py -->
| Area | Crate | Tested | of which partly deferred or different | Intentional difference | Deferred | Lines | Mapping |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| FIDO2 / U2F | `lk-fido` | 42 | 1 | 3 | 0 | 45 | [catalog/fido.md](catalog/fido.md) |
| OTP | `lk-otp` | 37 | 0 | 5 | 2 | 44 | [catalog/otp.md](catalog/otp.md) |
| OATH | `lk-oath` | 22 | 1 | 3 | 0 | 25 | [catalog/oath.md](catalog/oath.md) |
| Management | `lk-mgmt` | 8 | 2 | 2 | 0 | 10 | [catalog/mgmt.md](catalog/mgmt.md) |
| PIV | `lk-piv` | 29 | 1 | 3 | 0 | 32 | [catalog/piv.md](catalog/piv.md) |
| OpenPGP | `lk-openpgp` | 50 | 0 | 5 | 5 | 60 | [catalog/openpgp.md](catalog/openpgp.md) |
| YubiHSM Auth | `lk-hsmauth` | 17 | 3 | 0 | 0 | 17 | [catalog/hsmauth.md](catalog/hsmauth.md) |
| Security Domain / SCP03 / SCP11 | `lk-sd` | 98 | 0 | 11 | 11 | 120 | [catalog/sd.md](catalog/sd.md) |
| Device / transports / storage | `lk-device` | 71 | 5 | 5 | 22 | 98 | [catalog/device.md](catalog/device.md) |
| **All files** | | **374** | **13** | **37** | **40** | **451** | |

Bullets owned by another crate's file (not counted above): 3. Unlabelled bullets: 0.
<!-- END tools/catalog_status.py -->

Reading the totals:

- They count mapping lines across files, not distinct catalog bullets. A few bullets
  appear in two files, once for each crate's part. For example the FIDO CTAPHID bullets
  are in `fido.md` and in `device.md`, which own the CTAP and the framing and
  integration parts. Appendix B `usb_management_reboot_reenumeration` is in `mgmt.md` and
  in `device.md`. The YubiHSM Auth bullet filed under the catalog's FIDO section is in
  `hsmauth.md` and in `otp.md`, because of its FunctionFS half.
- Some files quote the totals of their primary section only (`oath.md`, `mgmt.md`,
  `piv.md`, `device.md`); each now also states the count above.
- The counts come from the files as they are, not from the reviewers' reports. Some
  reviewers counted a secondary label inside a `tested` line separately. The YubiHSM
  Auth review reported 17 / 2 / 1, while its file has 17 `tested` lines, 3 of them
  partly deferred or different.

## What is deferred

The table is a mapping of legacy fixture coverage, not a count of implementation tasks or
a completion percentage. Program transports are implemented and have host-tool coverage
(`docs/STATUS.md`, "Program phase"); deferred legacy AIO, IFD and browser fixtures do not
imply those transports are absent. File modes and process locks are now mapped to their
program tests. The SCP11 PSO/PIV device check is also implemented and mapped in `sd.md`.

Grouped from the current `deferred` lines (`python3 tools/catalog_status.py --list deferred`):

- **brainpoolP512r1** (OpenPGP, 5 lines): no RustCrypto crate exists for the curve, so
  its 4 algorithm-attribute variants answer `6A81`. The other 39 advertised variants are
  generated, imported and used.
- **OTP static-ticket details** (2 lines): the `STRONG_PW1`/`STRONG_PW2` character
  transforms are stored but not applied, because the public sources do not give the
  character positions. `MAN_UPDATE` manual regeneration is not implemented.
- **Security Domain** (11 lines):
  - GP elements that are not in the available sources: the role policy identifiers, the
    `BF20` element and the subject-ID extension;
  - exact legacy SDK socket/IFD fixtures, logical-channel and GP transaction coverage.
    SCP11 PSO followed by wrapped PIV signing is tested in
    `lk-device/tests/secure_channel_scp11.rs` (SCP11a and SCP11c).
- **Device** (22 lines): unreplayed legacy native fixtures and unimplemented platform
  work, including AIO, IOUSBHost, the own IFD handler, browsers and detailed kernel power
  management cases (`docs/DESIGN.md` §13), plus the catalog's "all firmware edge cases
  and timing" row: every device timing that neither a specification nor the measurement of
  the reference fixes stays model policy.

The intentional differences are mostly the same kind of program-phase or legacy item:
legacy state migration, legacy release-artifact checks, SDK socket and IFD fixtures, and
the separate legacy backend process. The rest are behaviour choices, each with its
source in the crate's file:

- choices against the legacy bullet: OATH accepts an only-increasing challenge equal to the
  last one; PIV accepts an explicit Le on GENERAL AUTHENTICATE (SP 800-73-4 allows it); the
  Security Domain deletes a key at zero tries; `Input::FidoReport` is exactly 64 bytes;
- the reference key where the specification is open (rule 2), against the legacy bullet:
  requests over 1536 bytes are refused (no 7609-byte PING), OpenPGP GET RESPONSE during an
  unfinished chain answers `6D00`, OpenPGP GET DATA accepts chaining CLA `10`;
- known differences from the reference key (2026-10-12): the Security Domain's SELECT
  response carries `9F65` (spec over reference). Others are recorded inside `tested` lines
  or in the note sections, which are not counted: the empty `CTAPHID_CBOR` and the 30 s
  presence timeout (reference defects not copied), getUVRetries `3E`, PIV VERIFY `81`
  `6A88` and the OpenPGP factory attestation key status `01` (spec over reference), and the
  own profile's form factor `00` (own identity).

## Per-crate mapping

| Area | File | Owner |
| --- | --- | --- |
| FIDO2 / U2F (CTAP 2.1, U2F) | [catalog/fido.md](catalog/fido.md) | `lk-fido` |
| OTP (slots, HID frames, CCID) | [catalog/otp.md](catalog/otp.md) | `lk-otp` |
| OATH (YKOATH) | [catalog/oath.md](catalog/oath.md) | `lk-oath` |
| Management | [catalog/mgmt.md](catalog/mgmt.md) | `lk-mgmt` |
| PIV | [catalog/piv.md](catalog/piv.md) | `lk-piv` |
| OpenPGP card 3.4 | [catalog/openpgp.md](catalog/openpgp.md) | `lk-openpgp` |
| YubiHSM Auth | [catalog/hsmauth.md](catalog/hsmauth.md) | `lk-hsmauth` |
| Security Domain, SCP03, SCP11 | [catalog/sd.md](catalog/sd.md) | `lk-sd` |
| Device, transports, storage | [catalog/device.md](catalog/device.md) | `lk-device` (with `lk-ctaphid`, `lk-ccid`) |

Each file also records the model policies of its crate (status words, timings and other
choices that neither a specification nor the reference key fixes), the known differences
from the reference, and the findings of its reviews.
