# Continue the security-key emulator in a new session

Workspace: `/Users/yakisoba0728/Documents/Codex/2026-10-07/new-chat`. User objective: full YubiKey 5C Nano firmware 5.7.4 external protocol and OS-device compatibility on macOS and Linux. Goal status is active; full equivalence is **not** proven. Do not modify the real inserted key, its credentials/settings, or host USB/HID/PCSC/Keychain/keyboard/kernel. Continue with private software sockets and the owned no-NIC USB guest.

Current published version: **0.64.0** in `outputs/security-key-emulator/`. Published ZIP: `outputs/security-key-emulator.zip`; SHA-256 `4ad6f2b91996c025cd9bbfbe5b71a8326de91c8a273d82011b080ac05291d960`. The ZIP and its source folder must be kept together. Read `outputs/security-key-emulator/CONTINUE_HERE.md` if the published version is 0.64; otherwise read `work/security-key-emulator-v64-staging/security-key-emulator/CONTINUE_HERE.md` for the active candidate and the published `implementation-status.json` for release claims.

v0.64 integration report passed: **True**. v0.64 clean ZIP re-extraction passed: **True**. The pre-promotion stage was `work/security-key-emulator-v64-staging/security-key-emulator/`; after promotion, that tree is `outputs/security-key-emulator/`. Version 0.64 contains FIDO same-CID, YubiHSM Auth symmetric challenge and SCP03 Le/retry patches and the source handoff. Its first combined USB guest attempt failed after ten successful markers and is preserved; an identical-image retry passed all twelve. Check the guest handoff and final integration result for both attempts. Do not present an unsealed candidate as published.

Read in order:

1. `outputs/security-key-emulator/manifest.json` and `outputs/security-key-emulator.zip.sha256` for the exact release and file hashes.
2. `outputs/security-key-emulator/implementation-status.json` and `compatibility-matrix.json` for exhaustive implemented/verified scope and remaining gaps.
3. The current release's `CONTINUE_HERE.md`, `docs/PROGRESS_HISTORY.md`, `docs/EVIDENCE_INDEX.md`, `docs/OPEN_GAPS.md`, and `docs/REPRODUCE_VALIDATION.md` (under stage if 0.64 is not yet published).
4. `work/v64-integration-build/HANDOFF.md`, `work/v64-integration-cards/HANDOFF.md`, and `work/v64-integrated-guest/HANDOFF.md` for exact v0.64 build/card/guest reproduction and logs.

Next action: v0.64 is published and ZIP-re-extracted. Review the first-failed/second-passed USB guest evidence, then choose the next documented gap while preserving isolated baseline/fixed evidence and exact hashes. The Apple protected HID signing/profile and physical/production host checks remain external prerequisites. Software cannot reproduce manufacturer trust or secure-element properties. Do not mark the goal complete without resolving or explicitly revising those criteria.

Disk note: four reproducible old v45 guest `guest-initramfs.gz` images were removed after verifying their recorded SHA-256. Their raw consoles, inputs, preparation scripts and result remain; the exact paths/hashes are in `work/v64-disk-recovery.json`. Old unused Docker build cache was pruned to make room for the v0.64 ZIP; running containers and tagged images were not removed. To replay a removed historical image, regenerate it from its preserved preparation script and base image.
