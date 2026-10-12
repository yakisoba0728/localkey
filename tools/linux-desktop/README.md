# Real Linux desktop verification

This boots a disposable systemd/LightDM/Xfce desktop with actual Chromium and
Firefox, native HID clients and the packaged daemon. Selenium operates ordinary
pages; it does not install virtual authenticators or supply WebAuthn responses.
The local relying party verifies challenge, origin, RP ID, signatures, attestation,
the own AAGUID, UP/UV flags and increasing signature counters.

The VM has no NIC or host-device passthrough. Its container has `--network none`,
no privileged mode and no host `/dev` or `/sys` mounts. Two CPUs, 6 GiB container
memory, 3 GiB guest memory and a 30-minute timeout bound each run. Run one VM at
a time. Image construction uses the network for Debian packages. Package versions
are recorded with every run; apt inputs are not pinned to a snapshot.

Fixture accounts are `lkdesktop` / `localkey-test-only` and root /
`localkey-root-test-only`; the authenticator PIN is `12345678`. These are deliberate
test credentials. Never connect or redistribute the VM disk, or use its keys in
real accounts. Only selected result JSON, versions and screenshots belong in a
public verification report, never the disk, storage key or sealed records.

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
export LK_DESKTOP_DIR=/tmp/localkey-desktop-test
export LK_GECKODRIVER_TAR=/tmp/geckodriver-v0.37.1-linux-aarch64.tar.gz
tools/linux-desktop/build-disk.sh  # refuses an existing root.img
tools/linux-desktop/run.sh
```

The run succeeds only if the guest emits `LK-DESKTOP-END rc=0`. The guest always
records `result.json`, individual checks, logs, versions and screenshots under
`/localkey/results` and powers off. After poweroff, extract without mounting the
disk (use the matching desktop image):

```sh
mkdir -p "$LK_DESKTOP_DIR/export"
docker run --rm --network none -v "$LK_DESKTOP_DIR":/out localkey-desktop-build:1 \
  debugfs -R 'rdump /localkey/results /out/export' /out/root.img
```

Do not modify or extract the disk while QEMU is running. To retry with changed
fixtures, build a new disk. The Firefox direct-attestation permission button is
calibrated for these English 1280×800 screenshots; recalibrate after browser UI
changes. Chromium keeps a retry/cancel dialog after the device's 30-second presence
timeout; the test dismisses it before checking the page's rejection.
