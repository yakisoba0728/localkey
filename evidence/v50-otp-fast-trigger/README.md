# OTP single-slot FAST_TRIG candidate

Base: locally published v0.49 `outputs/security-key-emulator`. The only emulator source change is `emucard/core.py`. `source.patch` is a unified patch against that base and passes `patch --dry-run -p1`.

## Primary basis and scope

- Yubico's [ykpersonalize manual](https://developers.yubico.com/yubikey-personalization/Manuals/ykpersonalize.1.html) says `fast-trig` makes triggering faster when only configuration 1 is available and is always in effect on firmware 3.0 and above.
- Yubico's [ExtendedFlags SDK reference](https://docs.yubico.com/yesdk/yubikey-api/Yubico.YubiKey.Otp.ExtendedFlags.html) says FAST_TRIG applies only with one written configuration and has no effect when both slots are configured.
- Yubico's [Touch-Triggered OTP guide](https://developers.yubico.com/Developer_Program/Guides/Touch_triggered_OTP.html) describes ordinary two-slot short (1–2.5 s) and long (3–5 s) touch windows.
- The [Personalization Tool User Guide](https://downloads.yubico.com/support/YubiKeyPersonalizationToolUserGuideMarch2016.pdf) describes FAST_TRIG slot 1 output at registered contact when slot 1 alone is programmed (printed page 41). Applying that description to firmware 5.7.4 is an inference from the documented firmware 3+ always-on behavior, not a physical-key measurement. The older GUI guide also mentions a fast-trigger disable control in its introduction; that wording conflicts with the later firmware 3+ always-on statement, so the bit-independent behavior here follows the explicit firmware-scoped manual and still needs physical confirmation.

The existing model chooses an output at release. A 2750 ms or 3500 ms modeled hold of one programmed slot 1 previously returned SW=6985, even though a fast-triggered slot 1 should already have emitted at touch registration. This patch returns slot 1 output for that one-slot configuration across its existing 300–5000 ms modeled hold range. It makes no changes to two-slot windows, only-slot-2 handling, the FAST_TRIG configuration bit, or the existing manual-update arm branch. No timing constant was added or changed.

## Independent software evidence

`verify_fast_trigger_release.py` programs OTP through YubiKit `YubiOtpSession` over the emulator's in-memory connection, then checks the software-generated keyboard events. It also uses the private OTP HID socket and published `ske-otpd --wire-test` to cover external software paths. Neither path registers an OS HID keyboard or accesses a physical key.

| Run | Matched expectations | Divergence |
|---|---:|---|
| Published v0.49 | 8/14 | Single slot 1 at 2750 and 3500 ms with FAST_TRIG bit on or off; private socket and native wire-test at 3500 ms return SW=6985 |
| Candidate | 14/14 | None in tested cases |

The test includes the unchanged two-slot 2000/2750/3500 ms selection and only-slot-2 500/3500 ms boundaries. `baseline-result.json` and `candidate-result.json` contain all cases and observations.

Candidate regression reports: `buttons-result.json` 44/44, `dual-timing-result.json` 5/5, `smartcard-result.json` 97/97, `otp-commit-result.json` 22/22, `hmac-result.json` 12/12, and `keyboard-bridge-result.json` 11/11, for 191/191 checks. The related console logs are alongside these JSON files.

## Limits

The API accepts a completed hold duration, so this test proves output presence after modeled release, not the exact emission time, contact debounce, or physical 5.7.4 behavior. Durations beyond the existing 300–5000 ms normal touch range were not changed; the 8000–15000 ms manual-update arm branch remains separate. No claim of full YubiKey equivalence follows from these checks. No host USB/HID/keyboard, physical key, or published output was modified or accessed.
