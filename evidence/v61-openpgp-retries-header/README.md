# v0.61 isolated OpenPGP SET PIN RETRIES header candidate

Published v0.60.0 `emucard/core.py` is copied byte-for-byte to `baseline/`. The only production change in `candidate/` checks P1/P2 and Le in the OpenPGP `INS F2` branch before durable retry limits are changed. `source.patch` dry-runs cleanly against the baseline. File hashes and per-route results are in `results/summary.json`.

Yubico's [OpenPGP PIN retry APDU example](https://developers.yubico.com/ykneo-openpgp/PinRetries.html) is `00 F2 00 00 03 05 05 05` (P1/P2 zero, three data bytes, no Le). The [current YubiKit OpenPGP SDK source](https://developers.yubico.com/yubikey-manager/API_Documentation/_modules/yubikit/openpgp.html) sends the same command shape through `OpenPgpSession.set_pin_attempts` on modern YubiKeys. The former page describes the NEO applet; the unmodified Python YubiKit 5.9.2 call supplies the modern SDK interoperability evidence. Neither source measures firmware 5.7.4's exact malformed-header status or tolerance.

On the published emulator, four malformed commands returned `9000` and durably changed the user/reset/admin retry counts from 3/3/3 to 4/5/6:

| Malformed APDU | Before | Candidate |
| --- | --- | --- |
| `00 F2 01 00 03 04 05 06` (P1) | `9000`, state changed | `6A86`, state unchanged |
| `00 F2 00 01 03 04 05 06` (P2) | `9000`, state changed | `6A86`, state unchanged |
| `00 F2 00 00 03 04 05 06 01` (short Le=1) | `9000`, state changed | `6700`, state unchanged |
| `00 F2 00 00 00 00 03 04 05 06 01 00` (extended Le=256) | `9000`, state changed | `6700`, state unchanged |

The same A/B driver ran over a fresh private CCID Unix socket and directly through the compiled native IFD ABI on macOS and Linux ARM64. Every malformed candidate request left both the decrypted OpenPGP state and encrypted state bytes unchanged. After service restart, unmodified YubiKit sent a valid zero-P1/P2, no-Le `set_pin_attempts(7, 8, 9)` command; its retry counts persisted after another restart. Four cases passed on each of the four platform/route combinations for both baseline and candidate.

The candidate additionally passed 97 general smartcard checks on socket and IFD, 119 OpenPGP object checks on socket and IFD, 21 OpenPGP APDU-header checks on socket and IFD, and 28 OpenPGP KDF/extension checks on socket, on each platform (1,004 successful regression checks in total). Linux used an ARM64 container with `--network none`, read-only source, read-only root, a private `/tmp`, no added devices, and no privileges. All card/IFD traffic stayed inside private software fixtures. No physical key, host USB/HID/PCSC, or Keychain was accessed; published outputs and shared staging were not modified.

`6A86` and `6700` are conservative emulator rejection choices. The physical YubiKey 5C Nano firmware 5.7.4's response to these malformed APDUs remains unmeasured, so this patch does not establish complete firmware equivalence.
