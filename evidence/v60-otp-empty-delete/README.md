# v60 isolated OTP empty-slot deletion candidate

Published v0.59.0 `emucard/core.py` and `baseline/emucard/core.py` have the
same SHA-256:
`9ec868235c409c57d3699a32ba14e87c86d2b81c4c134391b923df0ff0fd3760`.
The fixed core SHA-256 is
`90ad9d55e316a1eee78c1fdcf060d49b45c4df2c244b91b71ab3ef1f31d4decd`.
`source.patch` contains the only source change, a one-line guard in the OTP
slot-deletion path. Published outputs and shared staging were not modified.

Yubico's current [slot deletion guide](https://docs.yubico.com/yesdk/users-manual/application-otp/how-to-delete-a-slot-configuration.html)
states that both `DeleteSlot()` and `DeleteSlotConfiguration()` fail when the
target slot is not configured. In published v0.59.0, the zeroed configuration
used for deletion reached `slots.pop(n, None)` and returned success even for
an empty slot. If the other slot existed, the emulator also incremented its
configuration sequence number despite leaving the slots unchanged.

`verify_delete.py` uses an unmodified YubiKit 5.9.2 `YubiOtpSession` over a
private Unix CCID socket. With only slot 1 or only slot 2 configured, its
attempt to delete the empty peer succeeded on baseline and advanced the
sequence 1→2. The fixed source returns `6985`, retains sequence 1, and keeps
the configured slot's HMAC-SHA1 response correct against an independent HMAC
calculation. A direct APDU with both slots empty exposes baseline `9000`
versus fixed `6985` without any state change. Deleting a genuinely configured
slot still succeeds with both sources, advances sequence 2→3, and preserves
the other slot's verified HMAC. Mac and Linux A/B records are the four
`baseline/fixed-{mac,linux}.json` files, each with 4/4 passing checks.

Fixed-source regressions pass on both platforms: smartcard/SDK 97/97,
private button 44/44, OTP commit/rollback 22/22, touch status 6/6. Linux
used an ARM64 container with `--network none`, read-only root, no device
passthrough and no privileges; `Dockerfile.linux-test` records its SDK
dependencies. The container image was built before offline test execution.

No physical key or host USB/HID/PCSC/keyboard/Keychain was accessed. Yubico
documents the failure but not its exact status; `6985` is a model choice,
not a measured firmware 5.7.4 response.
