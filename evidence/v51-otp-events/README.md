# Explicit OTP touch events, isolated candidate

Base: `work/security-key-emulator-v50-staging/security-key-emulator`. Only `emucard/core.py`, `emucard/client.py`, and `emucard/service.py` change. `source.patch` applies with `patch --dry-run -p1` against that staging source. Published `outputs/` is untouched.

## Evidence and interpretation

Yubico's [ykpersonalize manual](https://developers.yubico.com/yubikey-personalization/Manuals/ykpersonalize.1.html) says FAST_TRIG is always in effect on firmware 3.0 and above when only configuration 1 is available. Its [Personalization Tool User Guide](https://downloads.yubico.com/support/YubiKeyPersonalizationToolUserGuideMarch2016.pdf), printed page 41, describes that configuration's output being generated as soon as the key registers a touch. The [Touch-Triggered OTP guide](https://developers.yubico.com/Developer_Program/Guides/Touch_triggered_OTP.html) gives the ordinary two-slot short and long release windows. The older GUI guide's introduction also mentions disabling fast triggering, which conflicts with the firmware-scoped manual; this candidate follows the explicit firmware 3+ statement for the target firmware 5.7.4 and does not claim a physical differential result.

A single completed-duration call cannot return output at touch registration: the caller only supplies the duration after release. This candidate adds private software `touch_down()` and `touch_up(duration_ms)` calls. Down immediately returns keyboard reports when only active slot 1 is programmed (irrespective of its FAST_TRIG configuration bit); up returns no duplicate. With two programmed slots, down returns no reports and up uses the existing duration selection. The pre-existing `press(slot)` and `hold(duration_ms)` calls, packet opcodes 3 and 6, retain their behavior. New private Unix-socket opcodes 10 and 11 carry the same 9-byte packet and keyboard-report response shape; they do not alter USB OTP HID reports or the native bridge's existing wire protocol. The touch state belongs to the socket's Card session and is cleared on its reset or close.

The legacy manual static-password update branch remains deferred for an explicit touch; a 10-second release arms it and a later short release confirms it. This is software-model compatibility, not a claim that YubiKey 5.7.4 implements this legacy feature.

## Software verification

`verify_press_release.py` configures slots through independent YubiKit and calls the private keyboard socket. On v50 staging, the legacy hold request succeeds, but new touch-down is unsupported (1/2 checks). On the candidate, 30/30 checks pass: immediate slot-1 output; no release duplicate; duplicate/cross-session request guards; two-slot short/long selection; unchanged legacy hold; independent AES decryption and CRC of two YubiOTP tickets showing the usage counter advances on the next press, not release; manual-update deferral; both FAST_TRIG bit values, and a challenge-response-only slot that emits no keyboard reports. The JSON and console logs are alongside the script.

Existing candidate regressions pass: buttons 44/44, keyboard bridge including compiled native `ske-otpd --wire-test` 11/11, dual-slot timing 5/5, OTP commit boundaries 22/22, smartcard 97/97, and HMAC boundary 12/12; total 191/191.

## Boundary

A new software call represents an already-registered touch. This work does not model electrical contact debounce, exact output latency, long-hold physical behavior, or a physical 5.7.4 key. No native bridge or OS keyboard injector produces the new event pair yet; external hardware-like timing requires a producer to call `touch_down` when touch registers and `touch_up` on release. Tests use a private Unix socket and never register OS HID, use host PC/SC, or access a physical key.
