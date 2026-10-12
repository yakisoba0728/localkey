# Linux desktop preview

The first distribution target is a single-user Linux desktop with systemd and
systemd-logind. `localkeyd.service` exposes FIDO and OTP through UHID; no PC/SC,
network listener or USB device controller is needed. The optional PC/SC setup is
still documented in `tools/service/README.md` in the source repository.

**Current bundles are for private testing only.** The own profile still uses
`1209:0001`, a pid.codes private-test PID that must not be used for distribution:
<https://pid.codes/1209/0001/>. Public release packaging is blocked until an
assigned identity is implemented and tested. The optional Yubico compatibility
profile is not the installed default.

## Install and use

Prerequisites: Linux UHID, systemd, udev/logind, Python 3.11 or newer with Tk,
polkit's `pkexec`, and a desktop polkit authentication agent. On Debian/Ubuntu,
the additional packages are `python3-tk` and `pkexec`; your desktop normally
provides the agent. The installer does not install OS packages itself.

Verify the archive checksum against a trusted release channel before unpacking.
The bundled checksum verifies file integrity; it is not a publisher signature.

```sh
sha256sum --check localkey-*.tar.gz.sha256
tar -xzf localkey-0.1.0-dev-aarch64-unknown-linux-musl.tar.gz
cd localkey-0.1.0-dev-aarch64-unknown-linux-musl
sudo ./install.sh install --development
systemctl status localkeyd.service
localkey-touch                         # desktop user, without sudo
```

Use the bundle matching your CPU (`x86_64` or `aarch64`). Installation starts the
service and creates a storage key on first install. Open **localkey Touch** from
the application menu, press **Connect**, and authenticate as an administrator.
When an app requests presence, the window enables **Touch**. Check the request
in that app first: the current presence protocol has no app name or relying
party identity. The UI runs as your user; only a fixed, isolated Python helper
runs through polkit. It permits `status`, `watch`, `tap` and `tap long` on the
root-owned control socket. It cannot change paths, run a shell, reset the device
or shut down the daemon. `/dev/uhid`, the key, state and control socket remain
root-only. Active local sessions need administrator authentication; inactive
and remote sessions are denied. polkit may retain authentication briefly:
<https://polkit.pages.freedesktop.org/polkit/polkit.8.html>.

The helper's short `tap` sends `tap pending`: the runner checks expiry and applies
the edge at the same timestamp. If authentication took too long or the app
cancelled, it returns an error without an idle OTP tap. An ordinary root
`localkeyd ctl ... tap` remains available for explicitly requested OTP typing.

The window does not touch automatically. Closing it closes its privileged watch
connection; closing it does not stop the key. After a service restart, press
**Connect** again. CLI equivalents in an active desktop session:

```sh
pkexec /usr/local/libexec/localkey-control status
pkexec /usr/local/libexec/localkey-control tap
pkexec /usr/local/libexec/localkey-control tap long
sudo localkeyd ctl --control /var/lib/localkey/control.sock shutdown
journalctl -u localkeyd.service
```

The UI's button and helper's short tap are for pending presence requests. Idle OTP slot typing is a root CLI
operation; put focus in the intended app before sending a tap. Tools that
require Yubico USB IDs will not discover the own-profile OTP device. Standard
FIDO clients can use the own HID identity. Real Chromium/Firefox registration,
login, PIN/resident keys, cancellation, timeout, upgrade and recent matched backup
restore passed in Debian 13 desktop VMs on aarch64 and x86_64. See
`docs/LINUX_DESKTOP_VERIFICATION.md` in the source repository for versions and
selected evidence. Physical desktops and other distro/version combinations are
not covered by those results.

## Update, backup, restore and remove

Before an update, stop the service and back up **both** `/etc/localkey/storage.key`
and `/var/lib/localkey` to private, encrypted storage. Keep the backup outside the
release directory. Never share either with a bug report. Without the original
storage key, the records cannot be opened. Installing the next reviewed bundle
with the same command stops the existing service, replaces program files and
restarts it; it leaves the storage key and state alone. It refuses to generate
a replacement key for existing state. Restoring a backup means stopping the
service and restoring that matched key/state pair with directories root-owned
0700 and files root-owned 0600, then starting the service again. Verify login
after restoring; acknowledged credentials must survive a restart and update.
Use a recent backup: restoring older FIDO state can rewind signature counters and
lose credentials created since that backup. A relying party may then warn about
cloning or reject login. Recovery cannot rewind the site's stored counter. Keep
an independent login/recovery method, and never test by restoring someone else's
state or by mixing a key with another backup.

```sh
sudo systemctl stop localkeyd.service
# Back up the key and state together before updating.
sudo ./install.sh install --development
sudo ./install.sh uninstall
```

Uninstall disables the service and removes its program files, unit, rules,
policy and launcher. It preserves `/etc/localkey` and `/var/lib/localkey`.
Removing those directories is a separate, irreversible action. The existing
`localkeyd-uhid-vpcd.service` must be stopped before installation, since both
units use the same state directory.

## Build and stage

Use Rust 1.98.1 (the version used for the current checks), `Cargo.lock`, and a
static musl target. Install `musl-tools` and Python 3.11+ on a matching Linux build
machine, using a Git checkout of the source. Preview CI uses Ubuntu 24.04 runners
for each native architecture; current results are at
<https://github.com/yakisoba0728/localkey/actions/workflows/linux-preview.yml>.

```sh
rustup target add x86_64-unknown-linux-musl
CARGO_BUILD_JOBS=2 cargo build --release --locked -p localkeyd --target x86_64-unknown-linux-musl
python3 tools/package_linux.py --binary target/x86_64-unknown-linux-musl/release/localkeyd \
  --target x86_64-unknown-linux-musl --output /tmp/localkey-bundles --development
python3 -m unittest discover -s tools/linux -p 'test_*.py'
```

The packager validates ELF architecture and absence of a dynamic loader, checks
the dependency policy, and includes original dependency license/notice files,
Apache-2.0, NOTICE, a manifest, per-file checksums and an archive checksum. It
never includes state or storage keys, executes the input binary, installs or
publishes anything. It includes build-only dependency licenses conservatively.
It also includes the selected Rust toolchain's standard-library copyright page
and license texts, and musl 1.2.5's original COPYRIGHT from its upstream release:
<https://musl.libc.org/releases/musl-1.2.5.tar.gz>. Rust's bundled musl targets use
that version: <https://blog.rust-lang.org/2025/12/05/Updating-musl-1.2.5/>.
Packaging is pinned to Rust 1.98.1; refresh runtime notices on a toolchain update.
For the same inputs its archive metadata is deterministic. The manifest records
the source revision and whether the working tree had changes; it does not prove
that the supplied binary was built from that source. Public release mode also
requires a clean committed source tree. Build and sign in trusted release CI
before claiming provenance.

`./install.sh install --development --destdir /tmp/localkey-stage` stages the
files without creating keys, installing OS packages, running systemctl/udev or
starting a daemon. `uninstall --destdir` removes only those staged program files.

## Release gates

1. Assigned own USB PID, updated profile/udev fixtures, no test identity in the
   installed profile. License is Apache-2.0; include the bundled third-party
   notices in every binary distribution.
   pid.codes requires a public source repository and may ask a software-only
   project to justify its shared PID: <https://pid.codes/howto/>. Allocation is
   an external decision; never invent an unassigned production PID.
2. Clean install, stop/start, upgrade, uninstall and recent matched backup/restore
   passed on real systemd desktop VMs on both architectures, along with polkit
   administrator authentication and denial outside a desktop session. Inactive
   and remote denial defaults and watch EOF are checked by tests; live inactive
   and SSH sessions and physical desktop smoke checks remain before a release.
3. Chromium and Firefox: real WebAuthn registration and login using the own
   profile, resident keys/PIN, cancellation, presence timeout and restart
   persistence: passed in the recorded VMs. The discoverable account-selection
   UI and a reboot with the same RP records remain smoke checks. The generic touch
   UI cannot tell the app/origin; retain that limitation in the release notes.
4. Signed/checksummed release artifacts from a clean tag and trusted CI. Start
   with this preview scope; add PC/SC setup and management screens only after the
   basic desktop flow works.

This is a software key: it has no hardware isolation, physical presence sensor
or manufacturer-trusted attestation. A compromised host can access its keys and
drive it. Keep an independent recovery method while testing.
