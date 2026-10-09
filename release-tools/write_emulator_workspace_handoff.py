"""Write a stable workspace entry point for the next Codex session."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


base = Path(__file__).resolve().parent.parent
published = base / "outputs/security-key-emulator"
archive = base / "outputs/security-key-emulator.zip"
stage = base / "work/security-key-emulator-v64-staging/security-key-emulator"
integration_root = stage if stage.exists() else published
report_path = integration_root / "evidence/v64-integration/result.json"
reextract_path = base / "work/v64-reextract-validation/result.json"
manifest = json.loads((published / "manifest.json").read_text())
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
stage_passed = report_path.exists() and json.loads(report_path.read_text()).get("passed") is True
reextract_passed = reextract_path.exists() and json.loads(reextract_path.read_text()).get("passed") is True
assert not manifest["complete_yubikey_equivalence"]
next_action = (
    "v0.64 is published and ZIP-re-extracted. Review the first-failed/second-passed USB guest evidence, then choose the next documented gap while preserving isolated baseline/fixed evidence and exact hashes."
    if manifest["version"] == "0.64.0" and stage_passed and reextract_passed
    else "Inspect the guest attempts and current release/stage report; finish v0.64 package, clean re-extraction and promotion only if all gates pass. Then choose the next documented gap while preserving isolated baseline/fixed evidence and exact hashes."
)

target = base / "outputs/CONTINUE_SECURITY_KEY_EMULATOR.md"
target.write_text(f"""# Continue the security-key emulator in a new session

Workspace: `{base}`. User objective: full YubiKey 5C Nano firmware 5.7.4 external protocol and OS-device compatibility on macOS and Linux. Goal status is active; full equivalence is **not** proven. Do not modify the real inserted key, its credentials/settings, or host USB/HID/PCSC/Keychain/keyboard/kernel. Continue with private software sockets and the owned no-NIC USB guest.

Current published version: **{manifest['version']}** in `outputs/security-key-emulator/`. Published ZIP: `outputs/security-key-emulator.zip`; SHA-256 `{digest}`. The ZIP and its source folder must be kept together. Read `outputs/security-key-emulator/CONTINUE_HERE.md` if the published version is 0.64; otherwise read `work/security-key-emulator-v64-staging/security-key-emulator/CONTINUE_HERE.md` for the active candidate and the published `implementation-status.json` for release claims.

v0.64 integration report passed: **{stage_passed}**. v0.64 clean ZIP re-extraction passed: **{reextract_passed}**. The pre-promotion stage was `work/security-key-emulator-v64-staging/security-key-emulator/`; after promotion, that tree is `outputs/security-key-emulator/`. Version 0.64 contains FIDO same-CID, YubiHSM Auth symmetric challenge and SCP03 Le/retry patches and the source handoff. Its first combined USB guest attempt failed after ten successful markers and is preserved; an identical-image retry passed all twelve. Check the guest handoff and final integration result for both attempts. Do not present an unsealed candidate as published.

Read in order:

1. `outputs/security-key-emulator/manifest.json` and `outputs/security-key-emulator.zip.sha256` for the exact release and file hashes.
2. `outputs/security-key-emulator/implementation-status.json` and `compatibility-matrix.json` for exhaustive implemented/verified scope and remaining gaps.
3. The current release's `CONTINUE_HERE.md`, `docs/PROGRESS_HISTORY.md`, `docs/EVIDENCE_INDEX.md`, `docs/OPEN_GAPS.md`, and `docs/REPRODUCE_VALIDATION.md` (under stage if 0.64 is not yet published).
4. `work/v64-integration-build/HANDOFF.md`, `work/v64-integration-cards/HANDOFF.md`, and `work/v64-integrated-guest/HANDOFF.md` for exact v0.64 build/card/guest reproduction and logs.

Next action: {next_action} The Apple protected HID signing/profile and physical/production host checks remain external prerequisites. Software cannot reproduce manufacturer trust or secure-element properties. Do not mark the goal complete without resolving or explicitly revising those criteria.

Disk note: four reproducible old v45 guest `guest-initramfs.gz` images were removed after verifying their recorded SHA-256. Their raw consoles, inputs, preparation scripts and result remain; the exact paths/hashes are in `work/v64-disk-recovery.json`. Old unused Docker build cache was pruned to make room for the v0.64 ZIP; running containers and tagged images were not removed. To replay a removed historical image, regenerate it from its preserved preparation script and base image.
""")
print(target)
