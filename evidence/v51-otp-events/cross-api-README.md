# Prevent duplicate OTP button output during an explicit touch

Base: `work/security-key-emulator-v51-staging/security-key-emulator`. The only emulator source change is `emucard/core.py`; `source.patch` passes `patch --dry-run -p1` against that staging tree. Published `outputs/` is untouched.

The v51 private socket supports `touch_down()` and `touch_up(duration_ms)` to represent a registered contact and its release. [Yubico's FAST_TRIG documentation](https://developers.yubico.com/yubikey-personalization/Manuals/ykpersonalize.1.html) says a lone slot 1 triggers quickly, while the [Personalization Tool guide](https://downloads.yubico.com/support/YubiKeyPersonalizationToolUserGuideMarch2016.pdf) describes output when touch registers. The exclusivity rule here is a software API invariant: a caller representing one ongoing touch must not issue another ticket from the legacy software button opcodes before that touch ends. It is not a physical firmware 5.7.4 observation.

## Reproduction and patch

The `verify_touch_cross_api.py` script configures the emulator with independent YubiKit over a private Unix socket. On v51 staging, after `touch_down()` it can still invoke legacy `hold(3500)` and `press(1)`, both returning more keyboard reports. In a YubiOTP slot, these extra calls consume two additional tickets; independent AES decryption and CRC show the next explicit press at usage counter 3 instead of 1. Baseline: 13/20 expectations matched, with seven mismatches.

The patch adds a guard to `otp_keyboard_events()` and `otp_button_events()`: while `otp_touch_mode` is active, legacy opcodes 3 and 6 return SW=6985 before changing state. The explicit `touch_down()` path invokes `otp_keyboard_events()` before it marks the mode active. The explicit `touch_up()` path clears the mode before invoking the duration selector. Existing standalone opcode 3/6 behavior therefore stays available when no touch is active.

Candidate: 20/20 cross-API checks pass, including single-slot immediate output, two-slot deferred output, denial of legacy calls during both modes, normal legacy calls after release, and YubiOTP AES/CRC proving the usage counter advances once per explicit press. The earlier press/release focused suite also passes 30/30. Existing regressions pass: buttons 44/44, keyboard bridge with compiled native `--wire-test` 11/11, dual-slot timing 5/5, OTP commit boundaries 22/22, smartcard 97/97, HMAC boundary 12/12 (191/191).

The patch concerns only the private software keyboard request sequence. It does not modify OTP HID feature reports, host USB/HID devices, the physical key, or any native touch sensor. Whether actual firmware permits or suppresses analogous concurrent requests remains unmeasured.
