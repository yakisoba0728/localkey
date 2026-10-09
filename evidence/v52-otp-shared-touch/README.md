# Shared OTP touch ownership across private socket clients

Base: locally published v0.51 `outputs/security-key-emulator`. The emulator source changes are `emucard/core.py`, `emucard/management.py`, and `emucard/service.py`; `source.patch` applies with `patch --dry-run -p1`. Published outputs were read only.

Yubico describes [one physical touch contact triggering OTP output](https://developers.yubico.com/Developer_Program/Guides/Touch_triggered_OTP.html), with one of two configurations selected by touch duration. It also documents the encrypted OTP session and usage counters. The mapping from multiple private software clients to that one button is an emulator design inference, not a measurement of concurrent requests on firmware 5.7.4.

## Demonstrated v0.51 mismatch

Each Unix-socket handler creates its own `Card`, so v0.51 stored `otp_touch_mode` separately in each Card. With client A's `touch_down()` still active, client B could call `press(1)`, `hold(3500)`, or another `touch_down()` and receive extra keyboard reports. In the YubiOTP case, two B calls consumed two additional tickets. Independent YubiKit configuration, AES decryption, and CRC checking showed the next explicit press at usage counter **3**, where the single ongoing button model expects **1**.

`verify_shared_touch.py` tests two simultaneously connected private socket clients. Baseline v0.51 matches 16/24 expectations; candidate matches 24/24. It checks both clients' output, non-owner release rejection, that closing a non-owner does not free the touch, that closing the owner does, and that a committed management reboot releases the touch. A second test, `verify_touch_reboot_rollback.py`, injects a failed flush and verifies that a simulated management RPC flush failure preserves the owner, a successful reboot clears it, and a power cycle through another Card instance clears it (9/9).

## Change

Volatile touch owner and mode live in shared `EncryptedState`, alongside the existing shared OTP power-session counters. The owner Card alone can release the touch. Other clients' legacy `press(slot)`, `hold(duration_ms)`, and `touch_down()` requests return SW=6985 while it remains active. The owner is released on touch-up, owner socket close/session reset, successful management reboot, or explicit power cycle. A management RPC flush failure keeps the touch until a successful commit; APDU transport failures may separately reset their session. Disconnect cleanup is serialized with other socket button requests using the service lock. Normal legacy opcode 3/6 and explicit touch behavior remain unchanged when no touch is active.

Existing candidate regressions: press/release 30/30, same-session cross-API 20/20, buttons 44/44, compiled native keyboard bridge 11/11, dual-slot timing 5/5, OTP commit boundaries 22/22, smartcard 97/97, HMAC boundary 12/12. Including reboot/rollback 9/9, that is **250/250** independent regression checks, in addition to 24/24 focused two-client checks.

The socket server serializes requests with its device lock. This work does not add a physical touch sensor or verify the exact timing, simultaneous-request arbitration, or other undocumented behavior of a real 5.7.4 YubiKey. No host USB/HID/PCSC device or physical key was used.
