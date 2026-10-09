# v0.56 OTP / OATH / YubiHSM Auth audit (no source patch)

Published v0.55 was copied read-only into `baseline/`. The copy's `emucard/core.py` SHA-256 is `0d2404fb7d003ae2e3d22f82cbdcc1395672a4646f5b6587defd90471696723f` and `emucard/otp_hid.py` SHA-256 is `c7a5f9c73cdb1c506b99343785436b25cf85f772602f8a1727aa0b71e9756136`, both byte-identical to the published files at audit time.

No new patch is proposed. No 5.7.4 behavior mismatch was established with both a non-conflicting Yubico primary source and an independent SDK/private software test. Applying any of the leads below would be speculative.

Evidence reviewed:

- Yubico OATH APDUs: <https://docs.yubico.com/yesdk/users-manual/application-oath/oath-commands.html>. The published code implements the documented PUT minimum 14-byte secret, 64-byte names, HOTP exclusion from CALCULATE ALL, and full/truncated response tags.
- Yubico 5.7.x OATH capacity: <https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-firmware-5.7.html>. The 64-seed limit is implemented.
- Yubico YubiHSM Auth overview and credential semantics: <https://docs.yubico.com/yesdk/users-manual/application-yubihsm-auth/yubihsm-auth-overview.html> and <https://docs.yubico.com/yesdk/users-manual/application-yubihsm-auth/objects/credential.html>. The published code covers 16-byte passwords, eight retries/deletion, symmetric and asymmetric SDK paths.
- Yubico CLI's credential password change explicitly says it was added in firmware 5.9: <https://docs.yubico.com/software/yubikey/tools/ykman/HSMauth_Commands.html>. Its absence in a 5.7.4 profile is not a defect.
- Yubico personalization manual says FAST_TRIG is always in effect on firmware 3.0 and above: <https://developers.yubico.com/yubikey-personalization/Manuals/ykpersonalize.1.html>. The published lone-slot behavior is therefore not contradicted by a cleared flag on the target firmware.
- YubiHSM Auth capacity sources differ (the .NET ADD command says 30, the YubiHSM 2 guide says 32); no capacity change is justified without physical differential.

Software-only regression on the copied baseline using the bundled unmodified YubiKit and independent HMAC/RFC/crypto checks: `smartcard.json` 97/97, `oath.json` 107/107, `otp.json` 12/12. Raw logs are adjacent. Commands are in `reproduce.sh`. No host PC/SC/HID/keyboard, physical key, or QEMU device was accessed. These successes confirm modeled software workflows, not physical firmware equivalence. Remaining limits include exact 5.7.4 malformed-input behavior, duplicate TLV handling, maximum HMAC challenge/key lengths, timing, and a physical differential.
