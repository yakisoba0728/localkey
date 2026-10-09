# v0.58 cumulative PIV command-header candidate

This isolated candidate starts from published v0.57.0 `emucard/core.py` (SHA-256 `b104af76f876607a6d46bb9ab8066c768a2b6449d3633023c1dc51773723ebd4`). `source.patch` contains both the earlier SET PIN RETRIES Le guard and a SET MANAGEMENT KEY P1/P2/Le guard. It changes only PIV branches of `emucard/core.py`; the patch dry-runs cleanly against the copied baseline. Candidate core SHA-256 is `4f6c71325b35550afc1530b39c811d1c2e44f090a8f489e9c1ee1b0fd4de19f1`; patch SHA-256 is `3a24977d9aa6ee0947688aecc9e9702e6a79df7a7f4ac44b77a42b2850a66e48`.

Official Yubico APDU tables:

- [SET PIN RETRIES](https://docs.yubico.com/yesdk/users-manual/application-piv/apdu/set-pin-retries.html): `00 FA P1 P2` with Lc, data, and Le absent.
- [SET MANAGEMENT KEY](https://docs.yubico.com/yesdk/users-manual/application-piv/apdu/set-mgmt-key.html): `00 FF FF P2`, with P2 in `FF/FE/FD`, 27 bytes of TDES key data, and Le absent.

On published v0.57.0, malformed SET PIN RETRIES APDUs with short Le=1 or extended Le=256 returned `9000`, reset custom PIN/PUK to defaults, and changed retry limits. Malformed SET MANAGEMENT KEY APDUs with P1=00, P2=00, or Le=1 returned `9000` and replaced the management key. After each command, a restarted private card accepted the new credential and rejected the old one through unmodified YubiKit. The candidate rejects these five cases with `6700` or `6A86` before mutation; encrypted state files are byte-identical before/after and the original credentials work after restart.

The A/B scripts are `baseline/tools/verify_piv_set_retries_le.py`, `baseline/tools/verify_piv_management_header.py`, and identical candidate-side scripts. They also exercise valid unmodified YubiKit commands over plaintext and SCP03, including successful restart authentication/persistence. `results/summary.json` checks all 28 individual JSON reports: five malformed cases per transport/environment on baseline and candidate, plus candidate smartcard 97/97, PIV profile 60/60, and F9 6/6 per transport/environment.

The four tested execution paths are macOS private CCID socket, macOS direct IFD, Linux ARM64 private CCID socket, and Linux ARM64 direct IFD. Linux ran in `ske-linux-native:0.36` Docker with `--network none`, read-only candidate source, a private `/tmp`, and no host device passthrough. The Linux IFD driver was the published ARM64 `ske-ifd.so` (SHA-256 `a9b16d7a3112b96af8261f1f307418eebcd6285ab6225e8f9def93d76522fe50`), pointed only at the test socket. These Linux runs are software/card and IFD ABI evidence, not kernel USB/PCSC guest evidence. Published outputs, physical key, and host PCSC/USB/Keychain were not modified or accessed.

The emulator retains its existing acceptance of an ambiguous fifth zero byte on no-data SET PIN RETRIES. SET MANAGEMENT KEY permits P2=FD according to the official syntax; exact cached-touch behavior is outside this patch. Physical YubiKey 5C Nano firmware 5.7.4 tolerance for malformed APDUs and exact error status words remain unmeasured, so this does not establish full device equivalence.
