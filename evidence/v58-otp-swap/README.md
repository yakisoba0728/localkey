# v58 isolated OTP swap boundary candidate

Published v0.57.0 source was copied byte-for-byte to `baseline/emucard` and
`fixed/emucard`; `outputs/` was not modified. Published and baseline `core.py`
SHA-256: `b104af76f876607a6d46bb9ab8066c768a2b6449d3633023c1dc51773723ebd4`.
Fixed `core.py` SHA-256: `1237db7a30c7a8ede9b6c91509951898bfa4f44734a86af446c8f2650af184d9`.
Within `emucard`, only `core.py` differs; `source.patch` is the complete source
change. The fixed `tools` copy includes extra unchanged regression runners.

## Evidence and scope

Yubico's current [.NET SDK swap guide](https://docs.yubico.com/yesdk/users-manual/application-otp/how-to-swap-slot-configs.html)
states that swap fails if **at least one** slot is unconfigured; it also
requires no access code on either slot. The [SDK API reference](https://docs.yubico.com/yesdk/yubikey-api/Yubico.YubiKey.Otp.OtpSession.html)
states the same access-code limitation. Published v0.57.0 allowed a lone
configured slot to move to the empty slot and incremented the OTP sequence.
The patch enforces both slots configured after the existing access-code check,
preserving that check's `6982` error priority. `6985` for a missing slot is a
model choice: current public documentation specifies failure but does not
specify exact status for that case.

The older [ykpersonalize manpage](https://developers.yubico.com/yubikey-personalization/Manuals/ykpersonalize.1.html)
also says both slots must have `allow-update`; current .NET SDK docs do not
state that condition. No change to the `allow-update` policy is proposed.

An unmodified YubiKit 5.9.2 `YubiOtpSession` was used through the emulator's
private Unix CCID socket. With only slot 1 or only slot 2 programmed, the
baseline SDK swap succeeded, moved the HMAC credential, and increased the
sequence from 1 to 2. The fixed SDK swap returns `6985`, keeps the slot status
and sequence at 1, and independently recomputes the HMAC response from the
original slot. With both slots programmed, the swap succeeds and both HMAC
secrets are verified in their new slots. A raw, documented no-data swap APDU
with both slots empty also exposes the difference (`9000` baseline, `6985`
fixed), without altering status. These four checks pass on macOS and Linux;
raw records are `baseline-{mac,linux}.json` and
`fixed-{mac,linux}.json`.

Focused regressions on fixed source: smartcard/SDK 97/97, private button
44/44, OTP commit/rollback 22/22 and touch-status 6/6 on **each** platform.
Linux runs in an ARM64 Docker container with `--network none`, a read-only
root, no passed host devices and no privileges. Its test image was built with
the same YubiKit, cryptography and yubihsm versions as the macOS venv. The
Dockerfile and individual JSON reports are retained here.

No physical YubiKey, host USB/HID/PCSC/keyboard, or macOS virtual device was
accessed. Exact firmware 5.7.4 status, timing and error ordering for an empty
slot have **not** been measured; software SDK/docs plus private transport prove
the emulator discrepancy, not physical equivalence.
