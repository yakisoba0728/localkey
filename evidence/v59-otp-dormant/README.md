# v59 isolated OTP dormant/update candidate

The v0.58 staging source was copied into `baseline` and `fixed` before the
stage was promoted. The captured baseline `emucard/core.py` is byte-identical
to published v0.58.0, SHA-256
`9342cf1bd73fa0435a08e10d4d6ca172287a15dd0f70cbedc1d062d09ea8d8df`.
The fixed core SHA-256 is
`bd2c706c2d4c25b835c0568e2f8b603ba754df1fe542f8f2719f1a878fcbc7d2`.
`source.patch` is the complete core and regression-test change; outputs and
shared staging were not modified.

Yubico's current [Update slot command reference](https://docs.yubico.com/yesdk/users-manual/application-otp/commands-update-slot.html)
says a slot is updateable when it has **Allow Update or Dormant**, and lists
**Dormant** among the flags that can be set by UPDATE. The [SDK update guide](https://docs.yubico.com/yesdk/users-manual/application-otp/how-to-update-slot-settings.html)
shows `SetDormant()` in an `UpdateSlot()` operation. The captured v0.58 core
required prior Allow Update and refused setting Dormant if it was not already
set. The patch changes that prerequisite to either bit and permits the Dormant
toggle. All other flag syntax and access-code checks remain in place.

An unmodified YubiKit 5.9.2 `YubiOtpSession` over the emulator's private Unix
CCID socket supplied three independent cases on both macOS and no-network
Linux. With an active updatable HMAC slot, baseline refused `dormant(True)`
with `6985`; fixed accepted it, advanced sequence 1→2, and blocked a later
challenge. With a dormant HMAC slot whose Allow Update bit was clear, baseline
refused `dormant(False)` with `6985`; fixed accepted it, advanced sequence
1→2, and produced an independently verified HMAC-SHA1 response using the
original key. An active slot with neither bit remained rejected (`6985`) and
unchanged on both versions. `verify_update.py` and the four `baseline/fixed`
Mac/Linux JSON files retain the inputs and observations. The test deliberately
retains the HMAC_LT64 / pacing-10ms shared configuration bit across UPDATE so
that the same short challenge can be checked before and after.

The existing `verify_buttons.py` expectation that dormant cannot be restored
after activation contradicted the Yubico command reference; its updated check
now verifies that the slot actually becomes dormant. Fixed-source regressions
on both platforms: smartcard/SDK 97/97, private button 44/44, OTP
commit/rollback 22/22, touch status 6/6. Linux used an ARM64 container with
`--network none`, read-only root, no device passthrough, no privileges; its
Dockerfile is included for reproducibility.

No physical key, host USB/HID/PCSC/keyboard, or Keychain was accessed. The
exact status and sequencing of a physical 5.7.4 key for these transitions
remain unmeasured; the `6985` rejection is the existing model behavior, not a
physical-firmware claim.
