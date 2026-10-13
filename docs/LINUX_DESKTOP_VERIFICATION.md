# Linux desktop verification — 2026-10-12

**Passed: 26 checks per architecture**, using fresh Debian 13 desktop VM disks,
real systemd PID 1, a LightDM/PAM/logind local user session, Xfce, the installed
private-test musl bundle, actual Chromium and Firefox, and the own UHID identity.
The software key was reached through the guest kernel's HID stack. No browser
virtual authenticator, injected signature or physical reference key was used.
The VM and its container had no external network or host-device passthrough.

| Environment | aarch64 | x86_64 |
| --- | --- | --- |
| Userland | Debian 13 | Debian 13 |
| Kernel | Ubuntu `7.0.0-38-generic` | Debian `6.12.111+deb13-amd64` |
| systemd | `257.13-1~deb13u1` | same |
| LightDM | `1.32.0-6+b2` | same |
| Chromium | `154.0.8037.92-1~deb13u1` | same |
| Firefox ESR | `153.4.0esr-1~deb13u1` | same |
| python-fido2 | `1.2.0-2` | same |
| geckodriver | `0.37.1` | same |

The version files and binary hashes are under
[`reference/linux-desktop-2026-10-12`](../reference/linux-desktop-2026-10-12/).
These locally built binaries predate the publication commit and are private-test
artifacts from a dirty development tree, not signed release provenance.

| Flow | Result on both architectures |
| --- | --- |
| Fresh install | Unit installed/enabled, sandboxed daemon running, user sees only the own HID device through uaccess |
| Privilege boundary | Actual polkit administrator dialog; direct user helper/key/state access denied; a service process outside a local session denied by polkit |
| Registration/login | Both real browsers; own AAGUID and mathematical packed-attestation signature checked; RP validates challenge, origin, RP ID, UP and assertion signature |
| PIN/resident keys | Both browsers request required resident keys and UV, native PIN dialogs used; UV flags verified on registration and login |
| Cancellation | Both browser requests reject and presence retires; late limited-helper tap is refused (Chromium reports AbortError, Firefox NotAllowedError) |
| Presence timeout | No touch; authenticator request expires at about 30 s; late tap refused; browser request rejected after dismissing Chromium's retry/cancel dialog |
| Upgrade | Installer stops/replaces/restarts unit, original storage key hash preserved; both PIN logins verified afterward |
| Uninstall | Service disabled/removed, original key and sealed records preserved |
| Missing/wrong storage key | Missing key refuses reinstall without creating a replacement; a wrong key refuses daemon startup with exit 3 and identical sealed-record hashes |
| Recovery | Recent matched key/state backup taken while stopped, restored with original ownership; both browsers log in with UV and increasing RP counters |

The loopback relying party checks each actual browser response using python-fido2
and also requires the own AAGUID and increasing signature counters. The backup
is refreshed after acknowledged logins; this does not prove an old backup can
recover an account. Old state can rewind counters or omit newer credentials, and
a site can reject it or report a possible clone. Keep independent account recovery.

Evidence:

- [aarch64 result JSON](../reference/linux-desktop-2026-10-12/aarch64/result.json)
- [x86_64 result JSON](../reference/linux-desktop-2026-10-12/x86_64/result.json)
- [Actual polkit dialog](../reference/linux-desktop-2026-10-12/x86_64/polkit-authentication.png)
- [Chromium login after restore](../reference/linux-desktop-2026-10-12/x86_64/chromium-after-restore-login-verified.png)
- [Firefox login after restore](../reference/linux-desktop-2026-10-12/x86_64/firefox-after-restore-login-verified.png)

Reproduce with [`tools/linux-desktop/README.md`](../tools/linux-desktop/README.md).
The Firefox permission button uses calibrated English 1280×800 coordinates;
package versions are recorded, while apt inputs are not snapshot-pinned.
No disk, storage key, sealed record or complete browser log is published here.

Still outside this verification: a stock Ubuntu/physical desktop, live inactive
and SSH polkit sessions, discoverable-account selection in the browser, and a
full VM reboot with the same RP's saved public credentials. Restart/update/restore
persistence is covered. Other sites' origin and attestation policies may differ.
The touch window has no requesting-app identity. This software key has no
hardware isolation, physical sensor or manufacturer-trusted attestation.

Public source uses Apache-2.0. Public binaries remain blocked on an assigned own
PID and a reviewed, signed release from clean source. `1209:0001` is private-test
only; the request was submitted on 2026-10-13 as
[pid.codes #1310](https://github.com/pidcodes/pidcodes.github.com/pull/1310).
Submission does not allocate the candidate `1209:4C4B`.
