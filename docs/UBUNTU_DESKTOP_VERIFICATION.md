# Ubuntu desktop verification — 2026-10-13–14

**aarch64 passed all 46 checks with signed Snapd 2.78 candidate, including both
boots; x86_64 is in progress.** The default stable Snapd configuration fails to
expose the own UHID key to the confined browsers. Candidate coverage is separate
from stable/default Ubuntu support.

The fixture uses Ubuntu 26.04.1 LTS packages, its `7.0.0-38-generic` kernel,
systemd `259.5`, GDM `50.1`, GNOME Shell `50.1` and the native Wayland session.
Official Chromium `155.0.8059.39` and Firefox `157.0.1` Snaps run as the desktop
user with their AppArmor profiles enforcing. The image is assembled from official
packages; this is not an interactive ISO installation or a physical desktop test.
The VM has no NIC, host-device passthrough or privileged container. Its virtual
keyboard, mouse and display are fixture facilities, never part of a release.

## Stable Snapd: failed access check

The aarch64 run uses signed stable Snapd `2.77.1` (revision `28255`). Both
browsers' `u2f-devices` plugs are connected. The desktop user can discover the
own `1209:0001` FIDO node, and udev sets `ID_FIDO_TOKEN=1`,
`ID_SECURITY_TOKEN=1` and `uaccess`. Inside the actual Snap profile the FIDO
report descriptor is readable, but opening that node read/write fails with
`Operation not permitted`. Chromium waits for a key; registration does not finish.

Snapd [2.77.1's interface](https://raw.githubusercontent.com/canonical/snapd/2.77.1/interfaces/builtin/u2f_devices.go)
uses USB ancestor VID/PID rules. A software UHID device has no USB ancestor.
The [2.78 interface](https://raw.githubusercontent.com/canonical/snapd/2.78/interfaces/builtin/u2f_devices.go)
uses systemd's `ID_SECURITY_TOKEN=1` rule on systemd 244 or newer instead.
PID assignment alone cannot fix the older rule. Confinement was not disabled,
generated profiles were not edited, and another vendor's identity was not used.

Selected [stable aarch64 evidence](../reference/ubuntu-desktop-2026-10-13/stable-aarch64/)
includes the **failed** result JSON, versions, connections, udev properties,
sanitized access diagnostic and the actual Chromium waiting screen. The eight
passed setup/session checks in that JSON do not constitute browser-flow success.

## Candidate Snapd: aarch64 passed; x86_64 in progress

As checked on 2026-10-14 (Korea time), the official stable channel still provides `2.77.1`
(amd64 revision `28254`, arm64 `28255`); candidate provides signed `2.78`
(amd64 `28332`, arm64 `28331`). The fixture acknowledges Canonical's assertions,
installs the signed package offline and reconnects the ordinary browser plugs.
These packages are test inputs and are not included in a localkey bundle.
Files installed offline show `Tracking: -`; the recorded version/revision and
downloaded channel identify the input, rather than an ongoing channel subscription.

The fresh aarch64 run completed 46 checks and emitted `LK-DESKTOP-END rc=0`
with `result.json` containing `passed: true`. It verified:

- Actual systemd installation, user HID access, local administrator authentication,
  inactive-local/SSH denial and renewed administrator authentication for a verified touch.
- Both browsers' registration, PIN verification, native account selection,
  cancellation, presence timeout and rejection of a late touch.
- Upgrade preserving the key, refusal with a missing/wrong key, unchanged sealed
  records after wrong-key startup, matched backup restore and both browser logins.
- A different full-reboot boot ID with identical key, sealed-record and RP-state
  hashes, automatic service startup and both PIN/account-selection logins using
  the same RP credentials and increasing counters.

The actual browser processes use official Snap WebDrivers and native Wayland;
their verified AppArmor labels are `snap.chromium.chromedriver (enforce)` and
`snap.firefox.geckodriver (enforce)`. Selenium does not supply authenticator
responses. The RP verifies the own AAGUID, signatures, UP/UV flags, account user
handles and counters. The completed fixture revision is
`e61940b7394bbe7743dfded7ecdd03784a8f4e4d`; its native window selection follows
visible running Dock buttons by name/position, and waits for Firefox's focused
native PIN field before typing. Both Linux CI jobs passed for that revision.

Selected [candidate aarch64 evidence](../reference/ubuntu-desktop-2026-10-14/candidate-aarch64/)
includes the final result, versions, connected plugs, sanitized HID access,
bundle provenance/checksums and native PIN/account-selection/reboot screenshots.
x86_64 must complete its own recovery and both boots before being reported as
passed. Aborted runs, timeouts and an intermediate reboot are not a final pass.

The private test bundle was packaged from clean source
`392ad39acbd3111a60b2a93aa1fc6f2843222389`; its manifest and both checksum layers
are recorded with the stable evidence. Runtime identity remains private-test
`1209:0001`. This is local test provenance, not a signed release attestation.
The guest uses a fixed 2026-10-12 test clock, with 2026-10-13 during signed Snap
installation, so screenshot dates differ from the host's verification time.

Reproduce with [the desktop fixture guide](../tools/linux-desktop/README.md).
No VM disk, storage key, sealed record or complete browser log is published.
The completed Debian results remain in
[Linux desktop verification](LINUX_DESKTOP_VERIFICATION.md).

Public binaries remain gated on actual own PID allocation, revalidation with
that identity and the signed release procedure. Before claiming default Ubuntu
Snap support, confirm the generic FIDO fix is available in the stable channel
and repeat actual browser access. The submitted
[PID request #1310](https://github.com/pidcodes/pidcodes.github.com/pull/1310)
does not allocate candidate `1209:4C4B`.
