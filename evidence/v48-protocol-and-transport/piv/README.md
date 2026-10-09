# v0.48 isolated PIV PIN-command header candidate

This directory is a copy of published v0.47 `emucard` and `tools` plus a focused independent test. Only `emucard/core.py` differs among emulator source files. `source.patch` is the minimal source change and dry-runs cleanly against published v0.47.

## Evidence and change

Yubico's APDU references give P1 `00` and absent Le for [VERIFY PIN](https://docs.yubico.com/yesdk/users-manual/application-piv/apdu/verify.html) (`20 00 80`), [CHANGE REFERENCE DATA](https://docs.yubico.com/yesdk/users-manual/application-piv/apdu/change-ref.html) (`24 00 80/81`), and [RESET RETRY](https://docs.yubico.com/yesdk/users-manual/application-piv/apdu/reset-retry.html) (`2C 00 80`). Published v0.47 checked neither P1 nor Le for these commands and also accepted P2 `81` for RESET RETRY. For example, `00 2C 00 81` with the default PUK changed the PIN and returned `9000`, although that header is outside the published command format. A wrong-P1 VERIFY with the correct PIN authorized the session; one with a wrong PIN consumed a retry.

The candidate checks P1/P2 and Le before authenticating or changing state. This model returns `6A86` for unsupported P1/P2 and `6700` for explicit Le, consistent with nearby guards. These are emulator choices: the actual rejection status, precedence, and possible tolerance in YubiKey 5C Nano firmware 5.7.4 have not been measured.

`verify_piv_pin_headers.py` uses YubiKit `PivSession` and `SmartCardProtocol` over an in-memory software card and a private Unix CCID socket. It checks eight malformed APDUs for rejection and unchanged persistent PIN/retry state, four normal high-level SDK operations (PIN verify, PIN change, PUK change, PIN recovery), and a malformed/normal socket sequence.

| Suite | Published v0.47 | Candidate |
| --- | ---: | ---: |
| Focused independent checks | 5/14 | 14/14 |
| PIV profile, private CCID socket | — | 60/60 |
| PIV profile, direct in-process IFD ABI | — | 60/60 |
| OATH profile, private CCID socket | — | 107/107 |
| Smart-card regression, private CCID socket | — | 97/97 |
| Button regression, in-memory card | — | 44/44 |

JSON reports and console logs are adjacent to this file. The baseline intentionally exits nonzero because its malformed APDUs are accepted. Reproduce from the workspace root with the bundled Python environment:

```sh
PYTHONDONTWRITEBYTECODE=1 outputs/security-key-emulator/.venv/bin/python work/v48-card-otp-piv-candidate/verify_piv_pin_headers.py --root outputs/security-key-emulator --result /tmp/v48-piv-baseline.json
PYTHONDONTWRITEBYTECODE=1 outputs/security-key-emulator/.venv/bin/python work/v48-card-otp-piv-candidate/verify_piv_pin_headers.py --root work/v48-card-otp-piv-candidate --result /tmp/v48-piv-candidate.json
```

The v0.47 status records broader remaining boundaries: OATH maximum key/challenge lengths, challenge ordering and error precedence, OTP timing/FAST_TRIG and HID edges, PIV replacement-certificate constraints, and physical error statuses still need differential validation. This candidate closes only the documented PIV PIN-command header gap. No physical key, host PC/SC reader, or USB/HID/keyboard device was accessed. Published output was read as the baseline and was not modified; the IFD check directly invoked the packaged bridge as a private software fixture.
