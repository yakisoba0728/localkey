# v0.47 isolated OATH binary-name candidate

This candidate starts from published v0.46. The sole changed emulator source file is `emucard/core.py`; `source.patch` applies that change without touching the published tree.

## Protocol basis and observed failure

The [YKOATH protocol](https://developers.yubico.com/OATH/YKOATH_Protocol.html) specifies credential names as byte data (up to 64 bytes), uses tag `0x71` to identify the name in CALCULATE, and uses tag `0x78` for the touch property. It does not explicitly state a character encoding. [YubiKit's OATH API](https://developers.yubico.com/yubikey-manager/API_Documentation/autoapi/yubikit/oath/index.html) accepts `credential_id: bytes` in `OathSession.calculate`. Together these support treating credential names as byte identifiers; acceptance of every possible byte sequence by firmware 5.7.4 remains unmeasured.

Published v0.46 accepts `b"\xff\x00binary"` in PUT and returns it in LIST. CALCULATE with touch enabled then decodes the name as UTF-8 solely to construct the touch prompt. The decode raises `UnicodeDecodeError`, mapped to `SW=6A80`, before the touch callback or HMAC calculation. The candidate escapes invalid UTF-8 and nonprintable characters in that prompt. The credential bytes used for lookup and HMAC are unchanged. A normal Unicode prompt remains unchanged.

## Independent software evidence

`verify_oath_binary_name.py` sends YubiKit APDUs through an in-memory `EmulatorConnection` and a private Unix CCID socket. It checks PUT/LIST, raw and high-level YubiKit CALCULATE, the SHA-1 HMAC against Python's independent `hmac.digest`, the prompt label, and touch denial status.

| Run | Result | Key observation |
| --- | --- | --- |
| Published v0.46 baseline | 2/7 | Binary-name CALCULATE returns `SW=6A80`; touch callback is skipped. |
| Candidate | 7/7 | Matching digest; escaped label `OATH \\xff\\x00binary`; touch denial returns `SW=6985`. |

The exact records are `baseline-result.json` and `candidate-result.json`, with corresponding console logs. Existing candidate regressions passed: `oath-profile-result.json` 107/107, `smartcard-result.json` 97/97, and `buttons-result.json` 44/44.

From the workspace root, repeat the focused check with:

```sh
python3 work/v47-otp-candidate/verify_oath_binary_name.py --root outputs/security-key-emulator --result /tmp/v47-oath-baseline.json
python3 work/v47-otp-candidate/verify_oath_binary_name.py --root work/v47-otp-candidate --result /tmp/v47-oath-candidate.json
```

The first command intentionally exits nonzero on the five documented baseline failures. The fixture requires the locally installed YubiKit Python package.

The private socket service runs with `--testing` for successful touch. The in-memory denial check forces the callback to return false. These tests did not access a physical YubiKey or any host USB/HID/keyboard device. They do not establish exact firmware 5.7.4 behavior, timing, or UI prompt text.
