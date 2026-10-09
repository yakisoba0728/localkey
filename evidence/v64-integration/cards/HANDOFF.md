# v64 merged card stage: Python integration handoff

The merged stage at `work/security-key-emulator-v64-staging/security-key-emulator` passed 12 focused reports: HSM Auth, SCP03, and PIV GENERAL AUTHENTICATE Le on both Mac and Linux through a private CCID socket and direct IFD ABI. The stage's 97-check smart-card SDK suite also passed on each of those four platform/transport routes (388 checks total). Raw stdout/stderr is in `logs/`; structured reports and source/driver hashes are in `results/` and `validation.json`.

| Focus | Four-route result |
| --- | --- |
| HSM Auth symmetric GET CHALLENGE | Touch-required credential returns `9000` and an eight-byte challenge without a touch approval; CALCULATE still returns `6985` without touch. With software touch approval, unmodified YubiKit derives three 16-byte keys. |
| SCP03 INITIALIZE UPDATE explicit Le=1 | Returns `6700`, leaves encrypted Domain state and the default key's 64 retries unchanged. Unmodified YubiKit SCP03 authentication and CPLC retrieval pass; valid short Le=00 also passes. |
| PIV GENERAL AUTHENTICATE explicit Le=1 | Returns `6700` without spending PIN_ALWAYS authorization. Unmodified YubiKit signs with the original key immediately afterward, verifies the signature, and signs after restart. |

The stage Python source SHA-256 values held throughout this run: `emucard/core.py` `29a132b08225043620c95142a5ebc40e6a212969f432f3a0e641f6c30730042d`, `emucard/secure_channel.py` `40cd0713d623722b418d3d67ca20025eb33d4da15583df8058545c25e5b82073`, and `emucard/piv_objects.py` `b3c656f90d3f5ba5aeb7129529a4e2f0a86887e8a2ece2837e67e715e568d0ba`. During validation, another agent rebuilt both IFD drivers. The original 12 focus reports and 388 smart-card checks used the earlier drivers; they remain preserved. The rebuilt Mac and Linux direct IFD drivers then passed all six focus reports and 97 smart-card checks each (194 checks). `validation.json` records both driver generations and all report/log hashes. Rebuilt driver SHA-256: Mac `9185c64187b5fc8c6b8440b766480558c7f4b40086b1f09f97ac7d4de5fa6d01`, Linux `0c64e9c59144a7c0a287110e8f91d9f14b9509571a36feecbde35924d8c50219`.

From the workspace root, repeat a Mac socket report with the published Python environment:

```sh
PYTHONDONTWRITEBYTECODE=1 outputs/security-key-emulator/.venv/bin/python \
  work/v64-integration-cards/verify_hsmauth_challenge_touch_portable.py \
  --variant fixed --platform mac \
  --root work/security-key-emulator-v64-staging/security-key-emulator \
  --result work/v64-integration-cards/results/hsmauth-mac-socket.json

PYTHONDONTWRITEBYTECODE=1 outputs/security-key-emulator/.venv/bin/python \
  work/v64-card-candidate/verify_scp03_init_le.py \
  --root work/security-key-emulator-v64-staging/security-key-emulator --fixed \
  --report work/v64-integration-cards/results/scp03-mac-socket.json

PYTHONDONTWRITEBYTECODE=1 outputs/security-key-emulator/.venv/bin/python \
  work/v63-card-candidate/verify_piv_auth_le.py \
  --root work/security-key-emulator-v64-staging/security-key-emulator --fixed \
  --report work/v64-integration-cards/results/piv-le-mac-socket.json
```

For Mac direct IFD, add `--ifd-driver work/security-key-emulator-v64-staging/security-key-emulator/bin/macos-arm64/ifd-ske.bundle/Contents/MacOS/ske-ifd.dylib` to the HSM script; the SCP03 and PIV scripts use `--ifd` with the same path. Use `--report` or `--result` names ending `mac-ifd.json`. The smart-card regression command is `PYTHONDONTWRITEBYTECODE=1 outputs/security-key-emulator/.venv/bin/python work/security-key-emulator-v64-staging/security-key-emulator/tools/verify_smartcard.py --work-dir /tmp --report work/v64-integration-cards/results/smartcard-mac-socket.json`, with `--ifd-driver` for the direct IFD route.

For Linux, run the same three scripts in the local `ske-v58-otp-test:local` image, mounting only the stage read-only, this evidence directory writable, and the two original probe scripts read-only. The run used `docker run --rm --network none --cap-drop ALL -e PYTHONDONTWRITEBYTECODE=1`, with stage at `/stage` and evidence at `/out`. A complete direct-IFD HSM command from the workspace root is:

```sh
docker run --rm --network none --cap-drop ALL \
  -e PYTHONDONTWRITEBYTECODE=1 \
  -v "$PWD/work/security-key-emulator-v64-staging/security-key-emulator:/stage:ro" \
  -v "$PWD/work/v64-integration-cards:/out" \
  --entrypoint python3 ske-v58-otp-test:local \
  /out/verify_hsmauth_challenge_touch_portable.py \
  --variant fixed --platform linux --root /stage \
  --ifd-driver /stage/bin/linux-arm64/ifd-ske.bundle/Contents/Linux/ske-ifd.so \
  --result /out/results/rebuilt-hsmauth-linux-ifd.json
```

For the SCP03 and PIV Linux probes, also mount `work/v64-card-candidate/verify_scp03_init_le.py` as `/scp03.py:ro` and `work/v63-card-candidate/verify_piv_auth_le.py` as `/piv.py:ro`. Invoke `/scp03.py --root /stage --fixed --ifd /stage/bin/linux-arm64/ifd-ske.bundle/Contents/Linux/ske-ifd.so --report /out/results/rebuilt-scp03-linux-ifd.json`, then `/piv.py` with the same options and report name `rebuilt-piv-le-linux-ifd.json`. Omit `--ifd` for socket runs. The Linux smart-card regression uses `/stage/tools/verify_smartcard.py --work-dir /tmp --report /out/results/smartcard-linux-socket.json`, adding `--ifd-driver` for direct IFD.

This run accessed no physical key or host PC/SC/USB/HID/keyboard/Keychain device. It verifies the current stage's Python behavior through private transports, including the rebuilt IFD drivers after their hashes changed. It does not establish physical YubiKey 5.7.4 equivalence or validate rebuilt v64 FIDO/USB guest behavior; those are separate release gates.
