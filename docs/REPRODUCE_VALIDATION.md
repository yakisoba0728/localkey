# Reproduce the released validation

Run these commands from `/Users/yakisoba0728/Documents/Codex/2026-10-07/new-chat`. The published folder is `outputs/security-key-emulator`; the staged folder used for v0.64 before promotion is `work/security-key-emulator-v64-staging/security-key-emulator`. Check `outputs/security-key-emulator/manifest.json` first to determine which one is current. The commands use only private software sockets, direct test IFD libraries or an owned no-NIC virtual USB guest. They do not connect to the inserted physical key or host USB/HID/PCSC services.

## Verify the release archive without running a device

```sh
shasum -a 256 outputs/security-key-emulator.zip
cat outputs/security-key-emulator.zip.sha256
python3 - <<'PY'
import hashlib, json, zipfile
from pathlib import Path
archive = Path('outputs/security-key-emulator.zip')
with zipfile.ZipFile(archive) as packed:
    assert packed.testzip() is None
    manifest = json.loads(packed.read('security-key-emulator/manifest.json'))
    for name, record in manifest['files'].items():
        assert hashlib.sha256(packed.read('security-key-emulator/' + name)).hexdigest() == record['sha256'], name
print(manifest['version'], len(manifest['files']), manifest['complete_yubikey_equivalence'])
PY
```

The independent re-extraction gate used before v0.64 promotion is `python3 work/verify_emulator_v64_zip.py`; its output is `work/v64-reextract-validation/result.json`. It extracts the archive, checks every manifest hash, and runs representative FIDO, OTP/OATH, PIV, SCP03 and YubiHSM Auth SDK flows from the extracted files. The extraction directory may be removed after the JSON report, logs and digest are preserved.

## Run the full local regression

The workspace's existing private Python environment is `outputs/security-key-emulator/.venv/bin/python`; it is intentionally not included in the release ZIP. Given an installed matching Python environment:

```sh
outputs/security-key-emulator/.venv/bin/python \
  outputs/security-key-emulator/emulator.py test \
  --binary-dir outputs/security-key-emulator/bin/macos-arm64 \
  --legacy-binary work/swpasskey-build/swpasskeyd
```

This command writes individual JSON reports under `outputs/security-key-emulator/results/`. The v0.64 integration run used the staged root and logged stdout/stderr to `evidence/v64-integration/main-test.log`. The expected gate is 59 Python reports with 5,889 checks plus the 140-case Mac C++ suite. Linux C++ must independently pass 140 cases and 13,748 assertions; independent Linux python-fido2 must pass 82 checks. The latest `evidence/v64-integration/result.json` ties these counts to the exact source/binary hashes. These counts measure the test suite, not the fraction of all possible firmware behaviors.

`evidence/v64-integration/build/HANDOFF.md` records the exact offline Mac/Linux CMake and Docker build commands, the 15 installed binary hashes, and all build/test logs. `evidence/v64-integration/cards/HANDOFF.md` records the Mac/Linux private CCID/direct IFD focused probes and the associated SHA-256 manifest. `evidence/v64-integration/guest/HANDOFF.md` records the QEMU invocation, frozen base image/kernel hashes and raw console markers. If a handoff subdirectory is absent, the corresponding gate was not sealed; do not present it as completed.

The v0.64 focused scripts can also be run from the package's `evidence/v64-*` directories. In particular, `v64-fido-same-cid/verify_same_cid_socket.py` takes `<daemon> fixed <result.json>`; `v64-scp03-init-le/verify_scp03_init_le.py` takes `--root <package> --fixed --report <result.json>` with optional `--ifd <driver>`; and the YubiHSM Auth script expects a sibling `fixed` symlink pointing to the package root, as shown in `work/verify_emulator_v64_zip.py`. Each probe writes only disposable state under `/tmp`.

## Build and guest isolation

The native Linux build uses `ske-linux-native:0.36` with `--network none` and a read-only stage source mount; details and exact flags are in the build handoff. The v0.64 USB integration uses a frozen Linux ARM64 QEMU image, a guest with no NIC and an own `dummy_hcd` controller, with no host device passthrough. Its result requires 12 distinct zero-exit markers and no observed kernel panic; `console.log`, `inputs.json`, `result.json`, and the guest handoff are packaged. This verifies a particular isolated virtual UDC and native USB client path. It does not verify a production USB controller, external host, physical touch or a modified macOS virtual device.

## Release procedure for the next version

1. Freeze the published manifest/ZIP digests. Clone the published folder into a new `work/security-key-emulator-vNN-staging/security-key-emulator` directory, excluding its local `.venv`. Apply reviewable patches to the stage only.
2. Verify each patch with an isolated baseline/fixed fixture. Run the relevant Mac/Linux SDK and native C++ checks, then the no-NIC guest if the change is device-visible. Preserve raw logs, exact source/binary SHA-256 hashes and a statement of unmeasured physical behavior.
3. Update the status/matrix with precise claims, prepare current `evidence/vNN-integration/`, and run a new versioned packaging script based on `work/package_emulator_v64_stage.py`. Ensure its manifest covers the handoff documents and all packaged evidence; keep `complete_yubikey_equivalence: false` while gaps remain.
4. Re-extract the ZIP to a clean location, verify every file against the manifest and rerun representative SDK flows. Promote only a passed archive while preserving the prior published folder and ZIP. The v0.64 transaction is recorded in `work/promote_emulator_v64.py`.

Do not silently substitute historical logs for a new run. If a gate fails, keep the published release at its last verified version and record the failed stage and exact blocker in the handoff.
