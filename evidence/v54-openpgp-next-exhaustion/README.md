# OpenPGP GET NEXT DATA exhaustion candidate (published v0.53 base)

Source patch: `source.patch` (SHA-256 `985dc2da855386499ca96faf18d005c0855b8ea3799d18e9d116e3f744e1612b`). Published `emucard/core.py` baseline SHA-256: `3ece45f45d268df3f2696d209bd72deaad33161209c3baf11a690fd304fc2c74`. Candidate core SHA-256: `d686c23aadfbfaf0b6154f2c4897dfed22438d6a3458b49baab50d2025269da1`. The source patch changes only the OpenPGP INS `CC` branch. Published outputs and shared staging were not edited.

## Protocol basis and observed defect

OpenPGP Smart Card Application 3.4.1 §7.2.5 says successful SELECT DATA establishes the current data-object pointer for subsequent GET DATA and PUT DATA. §7.2.7 defines GET NEXT DATA as selecting the next valid 7F21 occurrence. §7.2.8 says PUT DATA replaces the current occurrence if a pointer is defined; otherwise it writes the first occurrence. The emulator additionally models Yubico's fourth attestation certificate occurrence, as exercised by its unmodified YubiKit interoperability regression.

On the v0.53 emulator, after SDK certificate import and valid AUT → DEC → SIG → ATT iteration, one more GET NEXT DATA returns `6A88` but assigns `None` to the volatile occurrence pointer before raising. A subsequent SDK GET DATA 7F21 returns empty, and SDK PUT DATA 7F21 writes a persistent, unreachable `certificateNone` object. The previously selected ATT certificate remains unchanged after restart. This is inconsistent with the specification's defined current-occurrence or first-occurrence write destinations. The patch validates the next slot before committing the pointer, retaining the `6A88` result while keeping the last valid occurrence selected.

Primary specification: https://www.gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf (§§7.2.5, 7.2.7, 7.2.8). Unmodified YubiKit `OpenPgpSession` is used for certificate import, selection, GET DATA, and PUT DATA. Raw `send_apdu` sends the standard GET NEXT DATA command because YubiKit does not expose a dedicated high-level method.

## Evidence

`results/before-socket.json` and `before-ifd.json`: `6A88`; selected last occurrence lost; `certificateNone` created; wrong write destination survives restart. `results/after-socket.json` and `after-ifd.json`: same `6A88`; last occurrence retained; `certificateNone` absent; intended ATT write survives restart. In both transports, normal SDK selection and all four valid certificate occurrences passed.

Regression reports in `results/` all passed: GET NEXT DATA malformed-Lc socket/IFD (2), OpenPGP APDU headers socket/IFD (21 checks each), OpenPGP object/profile socket/IFD (119 checks each), and OpenPGP extensions socket (28 checks). The object/profile checks used the published saved read-only reference JSON; no physical device was accessed.

These tests establish software behavior and published reference-profile compatibility only. The exact YubiKey 5C Nano firmware 5.7.4 status and pointer behavior after an exhausted GET NEXT DATA were not measured against a physical key. No host PC/SC, USB/HID, Keychain, or physical security key was accessed.
