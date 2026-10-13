# Real Linux desktop verification

This boots a disposable Debian systemd/LightDM/Xfce or Ubuntu GDM/GNOME/Wayland
desktop with actual Chromium and Firefox, native HID clients and the packaged daemon. Selenium operates ordinary
pages; it does not install virtual authenticators or supply WebAuthn responses.
The local relying party verifies challenge, origin, RP ID, signatures, attestation,
the own AAGUID, UP/UV flags, selected account user handles and increasing signature
counters. Completed registrations and counters survive a full guest reboot; pending
challenges do not. The second boot compares the previous key, sealed-record and RP
state hashes before logging in again through both browsers.

The VM has no NIC or host-device passthrough. Its container has `--network none`,
no privileged mode and no host `/dev` or `/sys` mounts. Two CPUs, 6 GiB container
memory, 3 GiB guest memory and a 30-minute timeout bound each Debian run. Ubuntu
uses four CPUs, 7 GiB container memory, 6 GiB guest memory, a 32 GiB sparse disk
and a 60-minute timeout; allocate at least 8 GiB to Docker. This meets Ubuntu
26.04's [6 GB RAM / 25 GB storage guidance](https://documentation.ubuntu.com/release-notes/26.04/).
Run one VM at
a time. Image construction uses the network for distro packages and signed Snap downloads. Package versions
are recorded with every run; apt inputs are not pinned to a snapshot.

Fixture accounts are `lkdesktop` / `localkey-test-only` and root /
`localkey-root-test-only`; the authenticator PIN is `12345678`. These are deliberate
test credentials. Never connect or redistribute the VM disk, or use its keys in
real accounts. Only selected result JSON, versions and screenshots belong in a
public verification report, never the disk, storage key or sealed records.
The SSH check uses a fixture key and a loopback-only sshd with real PAM/logind;
the inactive check switches the actual local session to another virtual terminal.
Both run after desktop administrator authentication, including its retained grant.
Reconnects handle a new native administrator prompt when that grant expires.

## Build and run

Build `localkey-guest-build:1` as described in `../linux-guest/README.md` and
generate both current private-test bundles in `work/releases/` using
`../package_linux.py`. Build the desktop images on the arm64 Docker host used for
these checks:

```sh
docker build -t localkey-desktop-build:1 tools/linux-desktop
docker build --build-arg DESKTOP_PLATFORM=linux/amd64 --build-arg DESKTOP_ARCH=x86_64 \
  -t localkey-desktop-x86-build:1 tools/linux-desktop
```

aarch64 reuses the Ubuntu kernel/module pair from the transport guest. x86_64 uses
Debian's `linux-image-amd64` and its initramfs. Both have Debian 13 userland; this
does not validate a stock Ubuntu desktop or physical hardware.

For Ubuntu 26.04, build the default Ubuntu GNOME session with its own kernel and
official stable Firefox/Chromium Snaps, including their signed base/content
providers. Snap packages are installed offline inside the guest; AppArmor and
Snap confinement stay enabled. The image is assembled from official packages,
not installed with the interactive ISO installer.

```sh
docker build --build-context kernel-tools=tools/linux-guest \
  -f tools/linux-desktop/Dockerfile.ubuntu \
  -t localkey-ubuntu-desktop-arm:1 tools/linux-desktop
docker build --build-context kernel-tools=tools/linux-guest \
  --build-arg DESKTOP_PLATFORM=linux/amd64 --build-arg DESKTOP_ARCH=x86_64 \
  -f tools/linux-desktop/Dockerfile.ubuntu \
  -t localkey-ubuntu-desktop-x86:1 tools/linux-desktop
```

Set `LK_DESKTOP_DISTRO=ubuntu` before the build/run commands below; no separate
geckodriver archive is needed. Firefox uses the Snap's own geckodriver and binary
paths, as required by [Mozilla's guide](https://firefox-source-docs.mozilla.org/testing/geckodriver/Usage.html).
Wayland input and screenshots use QEMU's native virtual keyboard/mouse/display
via a private guest virtio QMP port. A read-only 9p mount shares only generated
display images; no host source, device, Docker socket or home directory is exposed.
This management port is a disposable test-fixture facility, never a release
component. The RP and authenticator still communicate through the actual guest HID stack.

Snapd 2.77.1's `u2f-devices` interface uses USB ancestor VID/PID rules and rejects
the own UHID device even with a connected plug and `ID_SECURITY_TOKEN=1`.
The official [2.78 source](https://raw.githubusercontent.com/canonical/snapd/2.78/interfaces/builtin/u2f_devices.go)
uses systemd's FIDO identification instead on systemd 244+. As of 2026-10-13,
2.78 is in the candidate channel, so candidate coverage must be reported separately
from stable/default Ubuntu coverage. Do not change the identity or generated
security profiles to conceal this restriction.

For a candidate verification, download the matching architecture's signed
`snapd.snap` and `snapd.assert` with `snap download snapd --channel=candidate
--basename=snapd`, put them in a private directory, and set
`LK_SNAPD_CANDIDATE_DIR` to it before `build-disk.sh`. The guest acknowledges
the assertions, installs the signed file and reconnects the browsers' ordinary
`u2f-devices` plugs; AppArmor and device mediation remain enabled. This test-only
input is optional and is never included in the localkey bundle.

Download geckodriver v0.37.1 from its official release:
<https://github.com/mozilla/geckodriver/releases/tag/v0.37.1>.
The archives used on 2026-10-12 had SHA-256:

| File | SHA-256 |
| --- | --- |
| `geckodriver-v0.37.1-linux-aarch64.tar.gz` | `8fd90b951422fbad5b56539fb344dff66eb3f986d615d8d6fde9f1f62dad610c` |
| `geckodriver-v0.37.1-linux64.tar.gz` | `e815130ea95983e162ae91843b48d3a3ce991735635fce83a647afde21e09f7e` |

Select one architecture and a new private directory outside the repository:

```sh
export LK_DESKTOP_ARCH=aarch64     # or x86_64
export LK_DESKTOP_DISTRO=debian    # or ubuntu
export LK_DESKTOP_DIR=/tmp/localkey-desktop-test
export LK_GECKODRIVER_TAR=/tmp/geckodriver-v0.37.1-linux-aarch64.tar.gz
# Optional: use a fresh bundle outside work/releases without replacing older evidence.
export LK_DESKTOP_BUNDLE=/tmp/localkey-bundles/localkey-0.1.0-dev-aarch64-unknown-linux-musl.tar.gz
tools/linux-desktop/build-disk.sh  # refuses an existing root.img
tools/linux-desktop/run.sh
```

The run succeeds only if the guest emits `LK-DESKTOP-END rc=0`. The guest always
records `result.json`, individual checks, logs, versions and screenshots under
`/localkey/results`, reboots once after the first phase, and powers off after the
second phase (or any failure). The final success marker covers both boots;
the intermediate reboot marker is not success. After poweroff, extract without mounting the
disk (use the matching desktop image):

```sh
mkdir -p "$LK_DESKTOP_DIR/export"
docker run --rm --network none -v "$LK_DESKTOP_DIR":/out localkey-desktop-build:1 \
  debugfs -R 'rdump /localkey/results /out/export' /out/root.img
```

For Ubuntu extraction, select `localkey-ubuntu-desktop-arm:1` or
`localkey-ubuntu-desktop-x86:1`. Do not modify or extract the disk while QEMU is running. To retry with changed
fixtures, build a new disk. Debian's Firefox direct-attestation and account-selection buttons are
calibrated for English 1280×800 screenshots, with screenshot-based prompt
readiness checks. Ubuntu selects GNOME's actual window previews and Firefox's
visible native accessibility buttons. Browser active-state flags can remain set
behind another Wayland window, and QEMU's virtual-clock key-release timers can
lag during emulation; the fixture sends explicit key press/release events.
Chromium keeps a retry/cancel dialog after the device's 30-second presence
timeout; the test dismisses it before checking the page's rejection.
