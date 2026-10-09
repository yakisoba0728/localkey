# v0.57 card APDU state audit — no source patch

The baseline copy of published v0.56 `emucard/core.py` has SHA-256 `0c8dd5be2fc21f2cb07e9eec4f90690c5a61c5e207c7c50c020ac4a5071bf61b`, identical to the published source at audit time. Only this isolated copy was executed; no published or shared staging file was changed.

The independent private-CCID test `verify_state.py` passed 11/11 checks, with raw results in `state.json`. It uses unmodified YubiKit `OathSession` and `HsmAuthSession`. It confirms OATH authentication is cleared after app deselection and requires a fresh SELECT challenge/validation, while YubiHSM Auth password retries persist through app switching and an unknown-AID SELECT. The behavior agrees with Yubico's [OATH session description](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-cspn-specifics.html) and [YubiHSM Auth retry documentation](https://docs.yubico.com/yesdk/users-manual/application-yubihsm-auth/yubihsm-auth-overview.html).

No input-validation or app-transition difference was established against a non-conflicting primary source and independent SDK. Accordingly there is **no candidate source patch**. HSM Auth GET_CHALLENGE touch timing and ephemeral state after reset remain unmeasured against physical 5.7.4; the published docs do not specify their exact cross-command behavior. Tests used only a private Unix CCID socket, no host PC/SC, HID, keyboard, or physical device. Passing software checks do not prove firmware equivalence.

Reproduce from workspace root with `PYTHONDONTWRITEBYTECODE=1 outputs/security-key-emulator/.venv/bin/python -B work/v57-card-state-audit/verify_state.py`.
