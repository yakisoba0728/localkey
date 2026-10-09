# v0.57 isolated PIV RESET APDU candidate

Published v0.56 baseline: `outputs/security-key-emulator/emucard/core.py`, SHA-256 `0c8dd5be2fc21f2cb07e9eec4f90690c5a61c5e207c7c50c020ac4a5071bf61b`. The candidate changes only the PIV `INS FB` branch of `emucard/core.py`; `source.patch` applies cleanly to the copied baseline. Published outputs and shared staging were not edited.

Yubico's [RESET PIV APDU table](https://docs.yubico.com/yesdk/users-manual/application-piv/apdu/reset-piv.html) specifies `00 FB 00 00`, with Lc, data, and Le absent. The [Yubico PIV extensions](https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html) independently specify P1=P2=00 and both PIN and PUK blocked as the reset precondition. The published emulator checked only the blocked precondition before erasing PIV state. The candidate checks P1/P2 and command data/Le before any state change. It permits the ambiguous five-byte `00` tail as an existing APDU-decoder compatibility convention; unmodified YubiKit 00 FB 00 00 is four bytes. The error SW choices for malformed headers are emulator behavior, not measured claims about firmware 5.7.4.

`candidate/tools/verify_piv_reset_header.py` provisions an ECC PIV key through unmodified YubiKit, blocks PIN and PUK, sends malformed raw APDUs, compares encrypted state file bytes, restarts the private card service, verifies key/retry preservation, then runs normal unmodified `PivSession.reset()`. It also checks normal SDK SCP03 reset and restart persistence. No system PCSC reader or physical key is used. The compiled macOS IFD driver points only at the private software socket.

| APDU | Published v0.56 socket and direct IFD | Candidate socket and direct IFD |
| --- | --- | --- |
| `00 FB 01 00` (P1) | 9000, key erased | 6A86, state byte-identical |
| `00 FB 00 01` (P2) | 9000, key erased | 6A86, state byte-identical |
| `00 FB 00 00 01 AA` (data) | 9000, key erased | 6700, state byte-identical |
| `00 FB 00 00 01` (Le=1) | 9000, key erased | 6700, state byte-identical |

Evidence: `results/before-{socket,ifd}.json`, `results/after-{socket,ifd}.json`. The same test driver is present in `baseline/tools` and `candidate/tools`. Candidate regression reports: `results/smartcard-{socket,ifd}.json` (97/97 each), `results/piv-profile-{socket,ifd}.json` (60/60 each), `results/f9-{socket,ifd}.json` (6/6 each). The focused before/after runs pass 4/4 malformed APDUs plus plaintext and SCP03 SDK reset per transport. `source.patch` SHA-256: `7c93ff3be760846382feeae3b845ab130c222ae06987988f6e5d953b3872c0ac`.

Physical YubiKey 5C Nano firmware 5.7.4 tolerance for malformed RESET APDUs, including exact error status words and the five-byte zero-tail ambiguity, is unmeasured. This is an official-format and SDK-compatible correction, not proof of complete device equivalence.
