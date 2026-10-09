# v0.47 OpenPGP lifecycle APDU candidate

The published v0.46 OpenPGP implementation executes `TERMINATE DF` (`00 E6 00 00`) and `ACTIVATE FILE` (`00 44 00 00`) even when an explicit response length is supplied. The [OpenPGP Smart Card Application 3.4.1, sections 7.2.16–7.2.17](https://www.gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf) specifies an empty Le for both commands. Yubico's pinned `OpenPgpSession.reset()` sends both commands without Le after blocking the PINs.

`source.patch` adds an Le guard before either command changes application state. The guard accepts the ambiguous five-byte `00` tail (which can mean short Le=256 or a no-data formatter placeholder), as the existing VERIFY guard does. The error `6700` is this emulator's choice; the physical 5.7.4 firmware's rejection status and tolerance have not been measured. The candidate intentionally leaves the existing lifecycle authorization and operational-state behavior unchanged.

Only `emucard/core.py` differs from published v0.46 among copied production source. Baseline SHA-256: `b72a424c36befae4cb0323d6bc1833201d48aec1d935f9e729a8db954e3ba386`; candidate SHA-256: `aedb7626b42db647cb73bc8d4f21445bd2157db87b15761d8e533736ca9c620d`. `patch --dry-run -p1` against published v0.46 succeeds.

Independent `tools/verify_pgp_lifecycle_le.py` drives the unmodified Yubico OpenPGP SDK and explicit APDU envelopes over private CCID socket and direct IFD. With blocked PINs, v0.46 returns `9000` for explicit Le=1 and extended Le=256 on each lifecycle command and changes persistent state. The candidate returns `6700`, preserves exact encrypted state bytes, and permits a subsequent valid lifecycle command to recover. The ordinary SDK reset sends four-byte `00 E6 00 00` / `00 44 00 00`, succeeds, and restores default PIN retries. Both transports also accept a five-byte `00` tail.

Results in `results/`:

| Suite | Private socket | Direct IFD |
| --- | ---: | ---: |
| v0.46 before reproduction | 24/24 | 24/24 |
| Guarded candidate | 28/28 | 28/28 |
| Existing VERIFY/CHANGE header regression | 21/21 | 21/21 |
| Existing RESET RETRY COUNTER Le regression | 36/36 | 36/36 |

The reports identify source hashes and record `physical_key_accessed: false`. No physical key, host PC/SC, USB/HID device, published output, or ZIP was modified. These software transport results do not establish exact YubiKey 5C Nano 5.7.4 behavior.
