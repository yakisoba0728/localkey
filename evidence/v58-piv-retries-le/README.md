# v0.58 isolated PIV SET PIN RETRIES Le candidate

Published v0.57.0 source baseline: `outputs/security-key-emulator/emucard/core.py`, SHA-256 `b104af76f876607a6d46bb9ab8066c768a2b6449d3633023c1dc51773723ebd4`. The isolated patch changes only PIV `INS FA` handling in `emucard/core.py`; published outputs and shared staging were not edited.

Yubico's [SET PIN RETRIES APDU table](https://docs.yubico.com/yesdk/users-manual/application-piv/apdu/set-pin-retries.html) specifies `CLA=00`, `INS=FA`, retry counts in P1/P2, and no Lc, command data, or Le. Its sample command is the four-byte `00 FA 05 05`. The unmodified Python YubiKit `PivSession.set_pin_attempts(6, 7)` likewise emits `00 FA 06 07` in a private socket observation. Published v0.57 checks authentication and data but ignores Le, allowing malformed commands to reset PIN/PUK to their defaults and change retry counts.

The candidate rejects an explicit Le before changing PIV state, while retaining the emulator's established acceptance of an ambiguous fifth `00` byte. This ambiguity and exact malformed-input status words on physical firmware 5.7.4 are unmeasured; `6700` is the candidate's rejection status, not a physical-device observation.

| Command | Published v0.57, socket and direct IFD | Candidate, socket and direct IFD |
| --- | --- | --- |
| `00 FA 05 05 01` (short Le=1) | 9000; PIN/PUK reset, retry counts changed | 6700; encrypted state byte-identical |
| `00 FA 05 05 00 01 00` (extended Le=256) | 9000; PIN/PUK reset, retry counts changed | 6700; encrypted state byte-identical |

`baseline/tools/verify_piv_set_retries_le.py` and `candidate/tools/verify_piv_set_retries_le.py` use the same test: provision custom PIN/PUK through unmodified YubiKit, authenticate management key and PIN, send malformed APDU through the private CCID socket or direct compiled IFD ABI, compare encrypted state bytes, restart service, verify the expected PIN/PUK through YubiKit, and successfully issue a valid SDK `set_pin_attempts`. It separately checks a valid SDK command over SCP03 with restart persistence. No physical device or host PCSC reader is accessed.

Evidence: `results/before-{socket,ifd}.json` and `results/after-{socket,ifd}.json` (both malformed cases and normal SDK/SCP03 path pass per transport). Candidate broad regression: `results/smartcard-{socket,ifd}.json` (97/97 each), `results/piv-profile-{socket,ifd}.json` (60/60 each), `results/f9-{socket,ifd}.json` (6/6 each). `source.patch` SHA-256 `290a316a82f7b2f22fdc8107dc019cf395aa05a444cfdbbc8db21caea3631cc1`, dry-run applies cleanly to the copied baseline.

This confirms an official-format and independent-SDK mismatch in the software emulator. It does not establish complete YubiKey 5C Nano 5.7.4 equivalence or its exact tolerance for malformed APDUs.
