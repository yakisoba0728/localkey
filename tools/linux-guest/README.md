# Linux test guest

A disposable arm64 Linux guest for exercising `localkeyd`'s Linux transports (`lk-uhid`,
`lk-gadget`) against a real kernel and its PC/SC transport (`lk-vpcd`) against the real
vsmartcard `vpcd`, with real host-side clients (python-fido2, libfido2, ykman, pcscd +
libccid, pcsc-tools, OpenSC, GnuPG, pyscard) as black boxes. The guest is QEMU (TCG, no KVM) inside
a Docker container; it boots from a single initramfs, runs one test script, prints the result
on the serial console and powers off.

## Safety properties

The guest exists so that nothing touches the machine it runs on.

- **No host devices.** The container is never `--privileged` and gets no `--device`, no
  `/dev` or `/sys` mount and no USB pass-through. The kernel under test is the guest's own
  kernel inside QEMU (`qemu-system-aarch64 -M virt`): `/dev/uhid`, `dummy_hcd`, ConfigFS,
  hidraw, usbfs and pcscd all live in the guest. The host's USB/HID/PC/SC stack, keyboard,
  keychain, kernel and any physically inserted security key are out of reach.
- **No network while a guest runs.** `guest-run.sh` starts the container with
  `--network none`, and QEMU gets `-nic none` (no NIC at all). Inside the guest `/init`
  brings up the loopback interface only, for `lk-vpcd`'s TCP connection to vpcd on
  `127.0.0.1` (vpcd listens on the guest's `0.0.0.0:35963`; with no NIC nothing can reach
  it from outside the guest). The network is used only while
  building the images (`docker build`: apt and rustup downloads). The `localkeyd` build runs
  offline (`--network none`, `cargo --offline` against a vendored crate directory).
- **Bounded resources.** Every container is `--cpus 2 --memory 6g`; the guest is
  `-smp 2 -m 2048`; host-side builds use `nice -n 10` and `CARGO_BUILD_JOBS=2`. A run has a
  hard timeout (`timeout` around QEMU, default 900 s) and the test inside the guest a softer
  one. Only one guest runs at a time (the runner refuses while its container exists).
- **Contained artifacts.** Everything large (kernel, initramfs, binaries, cargo target,
  logs) goes to `$LK_GUEST_DIR`, which must be outside the repository; the repository is
  mounted read-only into the build container.
- **Own names only.** Images `localkey-guest-build:1` and `localkey-rust-musl:1`, containers
  `localkey-guest-run`, `localkey-guest-export`, `localkey-musl-build`. The scripts never
  remove or change any other image or container.

## Files

| File | Purpose |
| --- | --- |
| `Dockerfile` | `localkey-guest-build:1`: QEMU, the kernel `Image`, the guest root filesystem `base.cpio.gz` (with `vsmartcard-vpcd`; the build fails if its reader entry or driver is missing) |
| `extract-image.py` | Ubuntu's arm64 `vmlinuz` (EFI stub + zstd zboot) to a raw `Image` for `qemu -kernel` |
| `Dockerfile.rust` | `localkey-rust:1.98-clippy`: `rust:1.98-slim` plus clippy (base of the musl image; also runs the offline Linux test and clippy pass) |
| `Dockerfile.musl` | `localkey-rust-musl:1`: the project's Rust image plus `aarch64-unknown-linux-musl` |
| `env.sh` | shared settings (image names, resource caps, `$LK_GUEST_DIR` checks) |
| `build-image.sh` | builds `localkey-guest-build:1` and copies its artifacts to `$LK_GUEST_DIR` |
| `build-localkeyd.sh` | builds a static `localkeyd` offline into `$LK_GUEST_DIR/bin/` |
| `guest-run.sh` | boots the guest once and runs one test script |
| `guest/init` | PID 1 of the guest |
| `guest/lib.sh` | helpers for test scripts (start/stop/kill/resume `localkeyd`, hex dumps, waits, hidraw lookup) |
| `guest/py/*.py` | Python helpers for test scripts, copied to `/localkey/py/` (see below) |
| `tests/*.sh` | test scripts; `smoke.sh` is the smoke test, `uhid.sh` the uhid scenario, `gadget.sh` the gadget scenario, `vpcd.sh` the vpcd scenario |

## Building

One-time preparation (network):

```sh
cargo vendor --locked /path/to/vendor > /dev/null           # crates for the offline builds
docker build -t localkey-rust:1.98-clippy -f tools/linux-guest/Dockerfile.rust tools/linux-guest
```

Then:

```sh
export LK_GUEST_DIR=/path/outside/the/repo/guest           # artifacts and logs
export LK_VENDOR_DIR=/path/to/vendor                        # `cargo vendor` output for this workspace

tools/linux-guest/build-image.sh       # network: apt; ~3 minutes the first time
tools/linux-guest/build-localkeyd.sh   # network only for the first `rustup target add`; the cargo build is offline
```

`build-localkeyd.sh` needs the image `localkey-rust:1.98-clippy` (override with
`LK_RUST_BASE_IMAGE`); the vendor directory is mounted at `/vendor` and selected with
`cargo --config`, so no cargo configuration file is needed. Rebuild `localkeyd` after every
change to the Rust code; the guest image only needs rebuilding when the Dockerfile changes.

After the two builds `$LK_GUEST_DIR` holds `Image` (the kernel), `base.cpio.gz` (the guest
root filesystem), `config` and `kernel-release` (the kernel's), `modules.list` (the modules
in the guest), `rootfs-size`, `bin/localkeyd`, `target/` (cargo) and `logs/`.

## The offline Linux test and clippy pass

Not a guest run: the whole workspace's `cargo test` and `cargo clippy` on Linux, in a
container without network, with the repository read-only.

```sh
mkdir -p "$LK_GUEST_DIR/linux-target" "$LK_GUEST_DIR/linux-home"
printf '[source.crates-io]\nreplace-with = "vendored-sources"\n[source.vendored-sources]\ndirectory = "/vendor"\n' \
  > "$LK_GUEST_DIR/linux-home/config.toml"
docker run --rm --network none --cpus 2 --memory 6g --user "$(id -u):$(id -g)" \
  -e HOME=/home/u -e CARGO_HOME=/home/u -e CARGO_TARGET_DIR=/target -e CARGO_BUILD_JOBS=2 \
  -v "$PWD":/src:ro -v "$LK_VENDOR_DIR":/vendor:ro -v "$LK_GUEST_DIR/linux-home":/home/u \
  -v "$LK_GUEST_DIR/linux-target":/target -w /src localkey-rust:1.98-clippy \
  sh -c 'cargo test --offline --locked --workspace && cargo clippy --offline --locked --workspace --all-targets'
```

## Running a test

```sh
tools/linux-guest/guest-run.sh smoke.sh                     # a script in tests/
tools/linux-guest/guest-run.sh -t 600 path/to/mytest.sh     # any script
tools/linux-guest/guest-run.sh -k loglevel=7 -f some/dir smoke.sh
tools/linux-guest/guest-run.sh -t 1500 -f tools/service vpcd.sh   # the service examples for step E
```

- `-t SECONDS` hard timeout of the whole run (default 900; the test gets 60 s less).
- `-k ARGS` extra kernel command-line words: `loglevel=N`, `lk.udev=0` (no udevd).
- `-f PATH` copy a file or directory into the guest at `/localkey/extra/`.

The console output is shown and saved to `$LK_GUEST_DIR/logs/<test>-<time>.log`. The test's
output sits between `===== LK-TEST-BEGIN <test> =====` and
`===== LK-TEST-END <test> rc=<n> =====`. The runner exits with the test's code, 124 on
timeout, 125 if the guest never reached the end marker.

### Inside the guest

- Root filesystem: Ubuntu 26.04 arm64 userland in RAM (an initramfs; nothing persists).
  `/localkey/bin/localkeyd`, `/localkey/lib.sh`, `/localkey/tests/`, `/localkey/extra/`.
- `/init` mounts proc, sysfs, devtmpfs, devpts, tmpfs (`/run`, `/tmp`, `/dev/shm`), ConfigFS
  (`/sys/kernel/config`) and debugfs (`/sys/kernel/debug`, for usbmon), brings `lo` up
  (`busybox ifconfig`; the image has no iproute2, and a connect to `127.0.0.1` fails with
  `ENETUNREACH` while `lo` is down), loads `uhid`,
  `dummy_hcd`, `libcomposite`, `usb_f_fs`, `usbhid`, `hid_generic`, `usbmon`, starts
  `systemd-udevd` (so hidraw/hiddev/input nodes get their udev properties and libudev
  enumeration works for libfido2, pcscd and ykman), then runs the test with `bash` from
  `/localkey` and powers off.
- The test runs as root. The dummy UDC is `dummy_udc.0`; its host side is USB bus 1.
- `lib.sh` (source it with `. /localkey/lib.sh`):
  - `lk_start NAME ARGS...` starts `localkeyd run --state /run/lk/NAME/state --key-file
    /run/lk/key --exit-on-stdin-eof ARGS...` in the background (stderr in
    `/run/lk/NAME/log`; `/run` is a tmpfs); `lk_stop NAME` closes its stdin (a clean
    shutdown), waits, prints the exit code and the log (only its path with
    `LK_LOG_QUIET=1`); `lk_kill NAME` kills it with SIGKILL; `lk_resume NAME ARGS...`
    starts it again on the state it had; `lk_alive NAME` tells whether it still runs;
    `lk_ctl NAME ARGS...` is `localkeyd ctl` for it; `lk_tap NAME [ARGS]` runs
    `py/lk_tap.py` against its control socket. `lk_start` creates the shared storage key
    `/run/lk/key` first (`lk_keygen`).
  - `wait_for SECONDS CMD...`, `hex FILE`, `usb_dev VID PID`, `usb_gone VID PID`,
    `hidraw_report`, `hidraw_of fido|otp` (the node whose report descriptor is the
    engine's FIDO or OTP one), `hid_id NODE`, `hidraw_count`, `section`, `note`.
- `py/` (run with `python3 /localkey/py/NAME.py`):
  - `lk_tap.py SOCKET [--count N] [--long]`: watches the presence indicator and sends
    `tap` whenever the device waits for a touch (start it in the background before the
    client that needs the touch).
  - `wire_identity.py SOCKET`: the engine's USB identity and descriptors from the wire
    transport's IDENTITY frame, as `key=value` lines.
  - `hidraw_info.py NODE [--get-feature LEN]`: what the hidraw ioctls report
    (`HIDIOCGRAWINFO`, names, report descriptor) and raw `HIDIOCGFEATURE` calls.
  - `evdev_keys.py --event NODE [--hidraw NODE]`: the key events (and raw input
    reports) a keyboard produces, decoded to text on a US layout.
  - `fido2_flow.py --control SOCKET [--pin PIN] [--vendor HEX --product HEX]`:
    python-fido2 list, getInfo, make_credential and get_assertion (`Ctap2`, and
    `Fido2Client` with `Fido2Server`), touching from the keepalive callback.
  - `desc_diff.py [--allow FIELD]... EXPECTED ACTUAL`: two USB descriptor sequences (hex)
    compared byte for byte, every difference named by descriptor and field; exit 0 when
    only `--allow`ed fields differ.
  - `usbfs.py NODE reset | control TYPE REQ VALUE INDEX LENGTH [DATA]`: a port reset
    (`USBDEVFS_RESET`) or one control transfer (`USBDEVFS_CONTROL`) on a host-side device
    node; a stall prints `error 32 (EPIPE)`.
  - `ffs_virtual.py --config HEX --udc NAME [--flags N]`: presents a configuration as a
    FunctionFS gadget of its own with chosen descriptor flags (default
    `FUNCTIONFS_VIRTUAL_ADDR`) and prints the endpoint files, what the host sees and the
    kernel log, then removes it.
  - `pcsc_big_apdu.py READER SIZE`: one extended SELECT of SIZE bytes through pcscd with
    pyscard (answered `6A82`), then SELECT OATH (`9000`); ykman and OpenSC never send an
    APDU longer than one CCID message, pyscard does.
  - `certs.py large OUT-PEM OUT-DER MIN MAX` (a self-signed certificate of MIN..MAX DER
    bytes, padded with subjectAltName names) and `certs.py verify PEM` (checks a
    self-signed certificate's signature, e.g. one a PIV key signed on the device).
  - `yk_connections.py`: what ykman reaches through SmartCardConnection, OtpConnection and
    FidoConnection separately (`ykman.device.list_all_devices`), one line each, with the
    serial; ykman's log records are counted, not printed.
- pcscd is not started by `/init`; the tests start it. Every pcscd in the guest loads the
  vpcd driver (`/etc/reader.conf.d/vpcd`, as packaged: `FRIENDLYNAME "Virtual PCD"`,
  `DEVICENAME /dev/null:0x8C7B`), so `opensc-tool -l` lists "Virtual PCD 00 00" and
  "Virtual PCD 00 01" (no card unless something connects to vpcd) before any libccid
  reader. OpenSC and GnuPG pick the reader with a card and `gadget.sh` names its reader
  `yubico`, so the gadget scenario is unaffected.
- The guest's clock starts at 1970-01-01 (no RTC is read): TOTP checks compute the
  expected codes with the guest's own `time.time()`, and a step before 0 does not exist.
- Userland: python3 with python-fido2 and pyscard, fido2-tools (libfido2), pcscd + libccid,
  vsmartcard-vpcd, pcsc-tools, OpenSC, yubikey-manager, GnuPG + scdaemon, usbutils, kmod,
  udev (with systemd's `systemd-analyze`), procps, evtest, strace, busybox-static.

## The uhid scenario (`tests/uhid.sh`)

`guest-run.sh uhid.sh` (about 85–95 s) runs `localkeyd run --transport uhid` against the
guest kernel and real host software, with tmpfs state directories and touches through
`localkeyd ctl tap`:

1. enumeration: two hidraw nodes, `HID_ID`, `HID_NAME`, `HID_UNIQ`, the hidraw ioctls,
   and both report descriptors byte for byte against the engine's (read from the wire
   transport's IDENTITY frame); `UHID_START` `dev_flags` from the `-vv` log;
2. libfido2: `fido2-token -L`, `-I`, `-S` (set a PIN), `fido2-cred -M`/`-V`,
   `fido2-assert -G`/`-V`;
3. python-fido2: `CtapHidDevice.list_devices()`, `Ctap2.get_info()`,
   make_credential/get_assertion with PIN tokens, `Fido2Client` + `Fido2Server`;
4. ykman with `--profile yubikey`: `list`, `info`, `otp info`, HMAC-SHA1
   challenge-response in slot 2 (checked against the generated key), a static password
   in slot 1 typed through the kernel's input layer (evdev) on a tap;
5. re-enumeration: `ykman config usb --disable OTP` (over OTP HID) and `--enable OTP`
   (over FIDO HID);
6. `kill -9` and restart: nothing left behind, state kept;

then extra experiments: the report-number rule with raw hidraw calls, a udev rule for the
OTP node, driver unbind and bind, and a hidraw flood. Every step prints `STEP <n> PASS`
or `STEP <n> FAIL`; the exit code is 1 if any failed. What it established is recorded in
`crates/lk-uhid/src/lib.rs` ("Settled on a real kernel").

## The gadget scenario (`tests/gadget.sh`)

`guest-run.sh -t 1800 gadget.sh` (about 2.5 minutes) runs `localkeyd run --transport gadget
--udc dummy_udc.0 --profile yubikey` against the guest's own USB host stack
(dummy_hcd's host side is bus 1), with real host software and touches through
`localkeyd ctl tap`:

1. enumeration: `lsusb -v`, the host's device and configuration descriptors
   (`/sys/bus/usb/devices/<dev>/descriptors`) against the engine's (from the wire
   transport's IDENTITY frame) with every difference named, the string descriptors,
   DEVICE_QUALIFIER, OTHER_SPEED_CONFIGURATION and BOS through usbfs;
2. HID: the hidraw nodes, libfido2 (`fido2-token -L/-I`, `fido2-cred -M/-V`,
   `fido2-assert -G/-V`), python-fido2, `ykman otp info`, HMAC-SHA1 challenge-response
   (GET_REPORT/SET_REPORT(feature) on `ep0`), a static password typed through evdev;
3. CCID: pcscd + libccid, the ATR against the profile's, raw APDUs (`opensc-tool -s`),
   `ykman info`, OATH with touch (the code checked against RFC 6238), PIV key and
   certificate generation, OpenPGP, `gpg --card-status` (scdaemon through pcscd), and
   CCID messages of whole 64-byte packets in both directions (PIV objects of 678 and 624
   bytes; usbmon shows the bulk URBs);
4. bus events: runtime suspend and resume (usbhid unbound first), `USBDEVFS_RESET`,
   `authorized` 0/1;
5. re-enumeration: `ykman config usb --disable/--enable OTP` over CCID, OTP HID and FIDO
   HID, the FIDO+CCID configuration against the reference key's
   (`reference/physical-key/usb-reference-observation.json`, copied into the
   script), strace of the daemon's `ep0` opens and `UDC` writes;
6. `kill -9` and restart: the leftover gadget is reclaimed, the state kept;

then extra experiments: an external unbind and bind, GET_STATUS and stalled CCID class
requests through usbfs, `FUNCTIONFS_VIRTUAL_ADDR` with `ffs_virtual.py`, and dummy_hcd
reloaded as a full-speed-only (`is_high_speed=0`) and a SuperSpeed (`is_super_speed=1`)
controller. Every step prints `STEP <n> PASS` or `STEP <n> FAIL`; the exit code is 1 if
any failed. What it established is recorded in `crates/lk-gadget/src/lib.rs` ("Settled on
a real kernel").

## The vpcd scenario (`tests/vpcd.sh`)

`guest-run.sh -t 1500 -f tools/service vpcd.sh` (about 3.5 minutes) runs `localkeyd run
--transport vpcd` and `--transport uhid,vpcd` with `--profile yubikey`
against Ubuntu's vsmartcard-vpcd 3.3 and pcsc-lite 2.4.1 in the guest, with real host
software, tmpfs state directories and touches through the control socket:

1. insertion: `localkeyd` first (nothing listens yet: one "cannot connect" line, retried
   every second, `attached=false`), then pcscd; "Virtual PCD 00 00" with a card in
   `opensc-tool -l` and `pcsc_scan`, the profile's ATR (`opensc-tool -a`), vpcd listening
   on `0.0.0.0:35963` and the card's connection from `127.0.0.1` (`/proc/net/tcp`),
   `attached=true`; pcscd runs here as the packaged `pcscd.service` runs it, as the
   sysusers user `pcscd` (`User=pcscd`; uid 990 in this image; `setpriv --reuid=pcscd
   --regid=pcscd --init-groups`, `/run/pcscd` owned by that user), and the peer check
   accepted vpcd's end of the connection, owned by that uid (`/proc/net/tcp` field 8,
   against `/proc/<pid>/status`; the `-v` log names the uid);
   then step 1b, the peer check against an impostor: pcscd stopped, a listener on
   `127.0.0.1:35963` as uid 65534 (`setpriv --reuid=65534 --regid=65534 --clear-groups
   python3`, the socket made after the drop): every connection `localkeyd` makes to it
   (one a second) is closed with 0 bytes received, the log says once "the peer on
   127.0.0.1:35963 is owned by uid 65534, not an allowed uid (0, 990); refusing the
   connection, retrying every second", no card is inserted, `attached=false`; pcscd started
   again as `pcscd`: the card is back. From step 2 on pcscd runs as root (as before),
   accepted as uid 0;
2. CCID clients: the reader renamed to "Yubico YubiKey OTP+FIDO+CCID" (pcscd restarted; the
   card leaves and comes back by itself), ykman info, OATH with touch (the code checked
   against RFC 6238), PIV key and certificate generation (the device's signature
   verified), `ykman openpgp info`, `gpg --card-status` (scdaemon through pcscd);
3. large transfers: a 2.9 KB PIV certificate imported and exported byte for byte (one
   APDU of about 2930 bytes each way), an extended APDU of 4007 bytes with pyscard (one
   vpcd message, more than one CCID message);
4. a PIV key with `--touch-policy ALWAYS` signs a certificate once `localkeyd ctl tap`
   touches (sent when `ctl status` says `presence=waiting`); the signature verifies;
5. `localkeyd ctl shutdown`: prints `ok`, then `stopped`, exits 0 once the daemon has
   exited 0; the card leaves the reader (pcscd logs "Card Removed"), the sockets are
   removed;
6. `--transport uhid,vpcd`: two hidraw nodes (1050:0407) and the card; `fido2-token -L/-I`,
   `fido2-cred -M/-V` through UHID; ykman reaches the same serial through
   SmartCardConnection, OtpConnection and FidoConnection (`py/yk_connections.py`);
   `ykman list` shows one compatibility device with OTP+FIDO+CCID, `ykman info` all three
   interfaces;
7. CCID off and on with `ykman config usb` (REBOOT): disabling OATH, PIV, OPENPGP and
   HSMAUTH over CCID removes the card (the transport closes its connection and makes no
   new one) and turns the HID devices into 1050:0403; enabling them over HID brings the
   card back (pcscd logs the removal and the insertion);
8. CCID off and on with `ykman config mode` (no REBOOT on a YubiKey 5): nothing changes
   until `localkeyd ctl power-cycle`, the virtual re-plug, after which the device
   re-enumerates with the new interfaces;
9. `kill -9` and restart: the hidraw nodes and the card go, come back, the state is kept
   (OATH account, configuration, the FIDO credential of step 6);
10. `localkeyd ctl shutdown` with `uhid,vpcd`: the HID devices destroyed, the card out,
    exit 0;

then E: `systemd-analyze verify` of `tools/service/localkeyd-uhid-vpcd.service` (with
`/usr/local/bin/localkeyd` linked to the guest's binary) and `udevadm verify` of
`70-localkey.rules`, when `-f tools/service` is given. Every step prints `STEP <n> PASS` or
`STEP <n> FAIL`; the exit code is 1 if any failed. The protocol facts the real vpcd
settled are in `crates/lk-vpcd/src/lib.rs` ("Checked against the real vpcd").

Found with the real clients (none of them a transport defect):

- **ykman needs the reader name.** ykman treats only a reader whose name contains "yubico
  yubikey" as a YubiKey, and takes the USB interfaces it assumes from the name
  (`_pid_from_name`, `ykman/pcsc/__init__.py`). With vpcd's packaged name every ykman
  command fails with "Failed to connect to YubiKey."; the script sets `FRIENDLYNAME "Yubico
  YubiKey OTP+FIDO+CCID"` in `/etc/reader.conf.d/vpcd` and restarts pcscd. The image keeps
  the packaged file.
- **The second slot.** vpcd always offers two slots; ykman opens the empty
  "... 00 01" too and prints "WARNING: Failed opening device" for it. Harmless.
- **ykman counts devices by PID without opening them** (`scan_devices`,
  `ykman/device.py`). With `uhid,vpcd` and all interfaces enabled, the HID PID (0407) and
  the reader name's PID agree and ykman sees one key. With CCID disabled the HID devices
  are 0403 while the reader's static name still says 0407, so a plain `ykman info` says
  "Multiple YubiKeys detected"; `ykman --device SERIAL ...` works.
- **ykman 5.8's `config usb` has no CCID switch** (it takes applications); the CCID
  interface goes when every CCID application is disabled over USB. `ykman config mode`
  writes without REBOOT and asks for a re-plug, exactly as on a YubiKey 5.

## How it is put together, and why

- **Kernel**: Ubuntu's `linux-image-<abi>-generic` for arm64 (7.0.0-38 when this was
  written; `KABI`, `KFLAVOUR`, `KSRC_VERSION` in the Dockerfile select it). Ubuntu 26.04
  ships it as a "Stubble" EFI application (a PE file with a `.linux` section holding an
  EFI zboot image whose payload is the zstd-compressed `Image`). Given that file,
  `qemu -kernel` prints nothing at all: QEMU neither runs the EFI stub without firmware nor
  unpacks a zstd zboot payload. `extract-image.py` takes the raw `Image` out, which QEMU
  boots directly (no UEFI firmware, so a faster boot).
- **dummy_hcd**: Ubuntu builds the kernel with `# CONFIG_USB_DUMMY_HCD is not set`. The
  Dockerfile compiles `drivers/usb/gadget/udc/dummy_hcd.c` out of tree from the very
  `linux-source` package of that kernel, against its headers, with the same gcc release
  (15.2.0-16ubuntu1), and checks that its vermagic matches Ubuntu's modules. The module is
  unsigned; Ubuntu's kernel does not force signatures outside secure boot, so it loads and
  taints the kernel (`tainted=12288`: out-of-tree and unsigned module). Every other module
  (`uhid`, `libcomposite`, `usb_f_fs`, `usbhid`, `hid-generic`, `usbmon`, `hid`, `udc-core`)
  is Ubuntu's own build; hidraw (part of `hid`), hiddev (part of `usbhid`), evdev and
  ConfigFS are configured `=y`.
- **Root filesystem**: the `guest` stage installs the userland on `ubuntu:26.04`, removes
  docs, man pages, locales and apt state, and adds only the module closure computed by
  `modprobe --show-depends` (the full module tree is 186 MB). The `pack` stage writes it as
  one gzip cpio (`base.cpio.gz`, about 88 MB; 291 MB unpacked).
- **Per-run overlay**: `guest-run.sh` stages `/init`, `lib.sh`, the tests and `localkeyd`,
  and inside the run container packs them as a second cpio (owner root, plus a
  `/dev/console` node) appended to `base.cpio.gz`; the kernel unpacks concatenated
  archives in order, so the overlay wins. Changing a test or `localkeyd` therefore needs no
  image rebuild.
- **vpcd**: Ubuntu's `vsmartcard-vpcd` package in the guest stage. It installs the IFD
  handler (`/usr/lib/pcsc/drivers/serial/libifdvpcd.so`) and `/etc/reader.conf.d/vpcd`
  (`DEVICENAME /dev/null:0x8C7B`, `CHANNELID 0x8C7B`: vpcd's port 35963, slot *n* on
  35963 + *n*), which pcscd reads at start; a `RUN` after the install checks both, so a
  package that moved them fails the build instead of a test.
- **localkeyd**: a static `aarch64-unknown-linux-musl` release build, so it runs whatever
  the guest's C library.
- **Console**: QEMU's `-nographic` serial (`ttyAMA0`) on stdout, carriage returns removed
  in the container with a line-buffered `sed` so the log streams.

## Timing (Apple Silicon host, TCG)

A smoke run takes about 16–25 s wall time: the kernel reaches `/init` after about 6–8 s
(about 4.5 s of that is unpacking the initramfs), udev settles about 5 s later, and the smoke
test itself takes about 5–8 s.
