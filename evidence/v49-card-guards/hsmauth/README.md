# v0.49 YubiHSM Auth RESET command-shape candidate

[Yubico's YubiHSM Auth Reset application command](https://docs.yubico.com/yesdk/users-manual/application-yubihsm-auth/commands/reset-application.html) specifies `CLA=00 INS=06 P1=DE P2=AD` with Lc, data, and Le absent. The published v0.47 emulator checks only P1/P2 and resets all HSM Auth credentials and the management key even when a valid extra TLV or explicit Le is supplied.

`source.patch` adds two guards before the state reset. It rejects nonempty data and explicit Le with model status `6700`, while accepting the ambiguous five-byte trailing `00` that could be emitted by a no-data short APDU formatter. The unmodified YubiKit `HsmAuthSession.reset()` sends the four-byte command and continues to work. Only `emucard/core.py` changes among copied production source files; the patch dry-runs cleanly on both published v0.47 and the separate v0.48 combined staging source, without changing either. Published core SHA-256: `4f8fa1def2c7709cc4dfb0250222dcc210c86141e802c9981c2792d71b8fd1d2`; candidate: `a9273a47bd18aebca19af954a2ea59cb186773639df84b29d9afefe3dbda32c0`.

The independent `tools/verify_hsmauth_reset_shape.py` creates an HSM Auth credential with unmodified YubiKit, then sends RESET with an extra TLV, Le=1, or extended Le=256 through a private CCID socket and direct IFD ABI. Published v0.47 returns `9000`, changes encrypted state bytes, and loses the credential after restart. The candidate returns `6700`, leaves the encrypted state bytes identical, and retains the credential after restart. Both versions still accept the normal SDK four-byte reset and the ambiguous five-byte `00` encoding.

| Report in `results/` | Private socket | Direct IFD |
| --- | ---: | ---: |
| Published v0.47 before reproduction | 24/24 | 24/24 |
| Guarded candidate | 24/24 | 24/24 |
| Existing smartcard SDK regression | 97/97 | 97/97 |

The focused reports include the executed core hash and record `physical_key_accessed: false`. No physical key or host PC/SC/USB device was used. The exact response status and malformed-APDU tolerance of physical firmware 5.7.4 remain unmeasured; `6700` is this emulator's status choice. This patch does not change the separate credential password exhaustion behavior implemented in the v0.48 staging candidate.
