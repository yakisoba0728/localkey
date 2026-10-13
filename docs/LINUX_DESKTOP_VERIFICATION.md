# Linux desktop verification — 2026-10-13

**Passed: 43 checks per architecture (86 total)**, using fresh Debian 13 desktop VM disks,
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
| Chromium | `155.0.8059.39-1~deb13u1` | same |
| Firefox ESR | `153.4.0esr-1~deb13u1` | same |
| python-fido2 | `1.2.0-2` | same |
| geckodriver | `0.37.1` | same |

The version files and binary hashes are under
[`reference/linux-desktop-2026-10-13`](../reference/linux-desktop-2026-10-13/).
The private-test binaries were built/packaged from clean committed source
`0b8e2330765be1265e49a88e5c41c53554aae9f9`; the manifests include their hashes
and `1209:0001` identity. They are local test artifacts, not signed release
provenance. The guest clock is a fixed 2026-10-12 fixture, so screenshots show
that date rather than the host's verification date.

| Flow | Result on both architectures |
| --- | --- |
| Fresh install | Unit installed/enabled, sandboxed daemon running, user sees only the own HID device through uaccess |
| Privilege boundary | Actual polkit administrator dialog, including reauthentication after its retained grant expires; direct user helper/key/state access denied; non-session, inactive local and real SSH remote processes denied |
| Registration/login | Both real browsers; own AAGUID and mathematical packed-attestation signature checked; RP validates challenge, origin, RP ID, UP and assertion signature |
| PIN/resident keys | Both browsers request required resident keys and UV, native PIN dialogs used; UV flags verified on registration and login |
| Discoverable login | Empty allow-list, two resident accounts offered by the actual browser picker; RP identifies the selected account from userHandle and verifies its signature, UV and counter |
| Cancellation | Both browser requests reject and presence retires; late limited-helper tap is refused (Chromium reports AbortError, Firefox NotAllowedError) |
| Presence timeout | No touch; authenticator request expires at about 30 s; late tap refused; browser request rejected after dismissing Chromium's retry/cancel dialog |
| Upgrade | Installer stops/replaces/restarts unit, original storage key hash preserved; both PIN logins verified afterward |
| Uninstall | Service disabled/removed, original key and sealed records preserved |
| Missing/wrong storage key | Missing key refuses reinstall without creating a replacement; a wrong key refuses daemon startup with exit 3 and identical sealed-record hashes |
| Recovery | Recent matched key/state backup taken while stopped, restored with original ownership; both browsers log in with UV and increasing RP counters |
| Full reboot | New kernel boot ID; identical original key, sealed-record and saved RP public-credential/counter hashes; automatic service startup, fresh administrator authentication and both allow-list/discoverable browser logins |

The loopback relying party checks each actual browser response using python-fido2
and also requires the own AAGUID and strictly increasing signature counters,
including rejection of a counter that falls to zero. RP public keys, counters
and completed verification records are saved atomically and loaded after reboot;
pending challenges are discarded. A fixture self-test checks this persistence,
repeated/zero-counter rejection and discoverable user-handle selection. The backup
is refreshed after acknowledged logins; this does not prove an old backup can
recover an account. Old state can rewind counters or omit newer credentials, and
a site can reject it or report a possible clone. Keep independent account recovery.

Evidence:

- [aarch64 result JSON](../reference/linux-desktop-2026-10-13/aarch64/result.json)
- [x86_64 result JSON](../reference/linux-desktop-2026-10-13/x86_64/result.json)
- [Actual polkit dialog](../reference/linux-desktop-2026-10-13/x86_64/polkit-authentication.png)
- [Chromium account picker](../reference/linux-desktop-2026-10-13/x86_64/chromium-account-account-picker.png)
- [Firefox account picker](../reference/linux-desktop-2026-10-13/x86_64/firefox-account-account-picker.png)
- [Chromium discoverable login after reboot](../reference/linux-desktop-2026-10-13/x86_64/chromium-account-after-reboot-login-verified.png)
- [Firefox discoverable login after reboot](../reference/linux-desktop-2026-10-13/x86_64/firefox-account-after-reboot-login-verified.png)

The earlier 2026-10-12 results (26 checks per architecture, older dirty-tree
private binaries) remain under `reference/linux-desktop-2026-10-12/`.

Reproduce with [`tools/linux-desktop/README.md`](../tools/linux-desktop/README.md).
The Firefox permission/account buttons use calibrated English 1280×800 coordinates
and screenshot-based readiness checks;
package versions are recorded, while apt inputs are not snapshot-pinned.
No disk, storage key, sealed record or complete browser log is published here.

Still outside this verification: a stock Ubuntu or physical desktop. SSH ran
through an actual loopback-only sshd/PAM/logind session inside the NIC-free VM.
Inactive denial was tested by switching the real local session's virtual terminal
after administrator authentication; the recorded session is local, on seat0 and
Active=no. Other sites' origin and attestation policies may differ.
The touch window has no requesting-app identity. This software key has no
hardware isolation, physical sensor or manufacturer-trusted attestation.

Ubuntu GNOME/Wayland and official Snap browser checks are tracked separately in
[Ubuntu desktop verification](UBUNTU_DESKTOP_VERIFICATION.md). Stable Snapd
2.77.1 blocks the own UHID device; candidate 2.78 coverage does not establish
default stable Ubuntu support.

Public source uses Apache-2.0. Public binaries remain blocked on an assigned own
PID and a reviewed, signed release from clean source. `1209:0001` is private-test
only; the request was submitted on 2026-10-13 as
[pid.codes #1310](https://github.com/pidcodes/pidcodes.github.com/pull/1310).
Submission does not allocate the candidate `1209:4C4B`.
