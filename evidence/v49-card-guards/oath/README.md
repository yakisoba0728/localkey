# v0.49 isolated OATH PUT key-length candidate

Published v0.47 is the read-only baseline. `source.patch` changes only the OATH PUT branch of `emucard/core.py` in this isolated copy. It also dry-runs against the separate v0.48 integration stage without modifying it.

Yubico's [OATH commands and APDUs](https://docs.yubico.com/yesdk/users-manual/application-oath/oath-commands.html) specifies a maximum 64-byte name and says PUT secret data has a minimum length of 14 bytes, with shorter source secrets padded with zero bytes. The independent [YubiKit OATH source](https://developers.yubico.com/yubikey-manager/API_Documentation/_modules/yubikit/oath.html) defines `HMAC_MINIMUM_KEY_SIZE = 14` and pads before sending PUT. Published v0.47 accepted a raw 13-byte secret without padding and durably created the credential. The candidate requires at least 14 secret bytes in the APDU before writing state, returning the documented wrong-syntax model status `6A80` for a shorter raw PUT. The behavior of a physical 5.7.4 key for an unpadded PUT has not been measured; the published documentation and SDK establish the transmitted APDU shape, not its exact firmware error precedence.

`verify_oath_key_minimum.py` uses YubiKit `OathSession` and `SmartCardProtocol` over an in-memory software card and a private Unix CCID socket. It checks the 13/14-byte boundary, unchanged state after rejection, 64/65-byte name boundary, high-level SDK padding of a one-byte source secret, independent SHA-1 HMACs, and zero/64-byte calculation challenges. The challenge cases are preservation checks: Yubico's protocol gives their length as variable and this candidate does not introduce a challenge limit.

| Run | Passed |
| --- | ---: |
| Published v0.47 focused baseline | 9/11 |
| Candidate focused | 11/11 |
| Existing OATH profile, private CCID socket | 107/107 |
| Existing OATH profile, direct IFD ABI | 107/107 |
| Existing smart-card regression | 97/97 |
| Existing button regression | 44/44 |

JSON reports and console logs are adjacent. Repeat the focused comparison from the workspace root with the bundled Python environment:

```sh
PYTHONDONTWRITEBYTECODE=1 outputs/security-key-emulator/.venv/bin/python work/v49-oath-candidate/verify_oath_key_minimum.py --root outputs/security-key-emulator --result /tmp/v49-oath-baseline.json
PYTHONDONTWRITEBYTECODE=1 outputs/security-key-emulator/.venv/bin/python work/v49-oath-candidate/verify_oath_key_minimum.py --root work/v49-oath-candidate --result /tmp/v49-oath-candidate.json
```

The baseline intentionally exits nonzero on two boundary checks. No physical key, host USB/HID/keyboard device or host PC/SC reader was accessed. The published output and v0.48 stage were not modified. Exact physical firmware tolerance, error status, other key maxima and rejection order remain unverified.
