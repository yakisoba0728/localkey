# Service examples

Example files for running `localkeyd` as a system service on a Linux machine with
`--transport uhid,vpcd`: the whole device without a USB device controller. FIDO and OTP
reach the kernel as HID devices through `/dev/uhid` (`lk-uhid`); CCID reaches pcscd as a
card in the vsmartcard `vpcd` reader (`lk-vpcd`). See `docs/PROGRAM.md`, "PC/SC through
vpcd, transport combinations, clean shutdown (third step)".

**These are examples. Nothing in this repository installs them, and no test uses them.**
Installing them changes the machine's systemd, udev and PC/SC configuration; do it by hand,
on a machine meant to use the virtual key, after reading the safety notes below.

| File | What it is |
| --- | --- |
| `localkeyd-uhid-vpcd.service` | systemd system unit: `localkeyd run --transport uhid,vpcd` as root in a sandbox, state in `/var/lib/localkey`, a clean stop through `localkeyd ctl ... shutdown` |
| `70-localkey.rules` | udev rule: `uaccess` (the logged-in user at the seat) on the OTP and FIDO hidraw nodes of localkeyd's UHID devices, for both profiles; a note on `/dev/uhid` |
| `README.md` | this file |

Checked for syntax only, with the systemd 259 of the test guest's Ubuntu 26.04 userland
(`tools/linux-guest`) in a container without network: `systemd-analyze verify` passes for
the unit and for its commented credential variant, `udevadm verify` for the rule, and
`systemd-analyze security --offline=true` rates the unit's exposure 1.9 ("OK").

## What each file does

### `localkeyd-uhid-vpcd.service`

- `ExecStart=` runs `localkeyd run --state /var/lib/localkey --key-file
  /etc/localkey/storage.key --transport uhid,vpcd -v`. The storage key is a root-only file;
  a commented alternative takes it from an encrypted systemd credential with
  `--key-command`. Logs go to the journal (`journalctl -u localkeyd-uhid-vpcd`); `-v` adds
  connections, enumerations, presence and the vpcd card's comings and goings, never APDU or
  report bytes.
- `ExecStop=localkeyd ctl --control /var/lib/localkey/control.sock shutdown`: the control
  socket's `shutdown` answers `ok`, and the daemon then does exactly what
  `--exit-on-stdin-eof` does at EOF: control socket closed, runner shut down, device
  dropped, UHID devices destroyed, vpcd connection closed (pcscd sees the card removed),
  sockets removed, exit 0. `ctl` returns only once the daemon has done all that, so systemd
  does not kill it half way, and prints how it ended: `stopped` (exit 0) or `error
  <reason>` when the daemon failed while shutting down (it exits non-zero, `ctl` exits 1).
  A daemon that already ended makes `ctl` fail; the `-` prefix lets the stop go on, and
  the daemon's own exit status is what marks the unit failed.
- `StateDirectory=localkey` with `StateDirectoryMode=0700`: `lk-host` refuses a state
  directory that grants group or other access, and systemd would create it 0755 by
  default. The control socket is `/var/lib/localkey/control.sock`.
- `Wants=`/`After=pcscd.socket`: vpcd is a pcscd driver and listens while pcscd runs. The
  transport retries every second until vpcd listens, so the ordering only saves a few
  retries. `Wants=` rather than `Requires=`: with `Requires=`, stopping or restarting
  `pcscd.socket` (an admin, a package upgrade's maintainer scripts) would stop or restart
  localkeyd too, destroying the UHID FIDO and OTP devices under the programs using them,
  and the unit would not start at all where `pcscd.socket` is masked or missing. With
  `Wants=`, FIDO and OTP come up without pcscd, and the card enters the reader whenever
  vpcd listens.
  `Wants=`/`After=modprobe@uhid.service` loads the `uhid` module before the start.
- `Restart=on-failure` with `RestartPreventExitStatus=2 3`: exit 1 (a runtime failure)
  restarts; exit 2 (usage, lock, key, permissions, no `/dev/uhid`) and 3 (records the key
  cannot open, refused) need a person.
- Hardening: no capabilities (`CapabilityBoundingSet=` empty: root owns `/dev/uhid`, the
  key file and the state directory, so none is needed), `DevicePolicy=closed` with
  `DeviceAllow=/dev/uhid rw` (the pseudo devices such as `/dev/urandom` stay available;
  `PrivateDevices=` must stay off, a private `/dev` has no `/dev/uhid`), a read-only file
  system except the state directory (`ProtectSystem=strict`), no home directories, IP
  traffic to loopback only (`IPAddressAllow=localhost`; vpcd is on `127.0.0.1:35963`),
  Unix and IP sockets only, `@system-service` system calls, and the usual `Protect*=` and
  `Restrict*=` settings. `systemd-analyze security localkeyd-uhid-vpcd` shows what is left.
  `ProtectProc=invisible` hides other users' processes only: `/proc/net/tcp`, which the
  vpcd peer check reads, stays readable. Do not add `ProcSubset=pid`, which hides
  `/proc/net`; every vpcd peer would then be refused.
- The vpcd peer check: before the card talks to whatever accepted its connection, localkeyd
  looks up the owner of vpcd's end of the connection in `/proc/net/tcp` and closes the
  connection unused unless that uid is allowed. By default root, the local user `pcscd`
  (looked up in `/etc/passwd`) and the daemon's own user (root here) are. Ubuntu 26.04's
  pcscd 2.4.1-1 runs pcscd, and vpcd inside it, as the user `pcscd` (its
  `pcscd.service` has `User=pcscd` and `PrivateUsers=identity`; the user is a locked
  sysusers account, `u! pcscd`, so its uid differs between machines: 990 in the test
  guest, `tools/linux-guest/tests/vpcd.sh` step 1), which the default covers without a
  number in the unit. Where pcscd runs as some other user of its own, add
  `--vpcd-peer-uid 0,UID` with that user's uid to `ExecStart=` (it replaces the default
  set). A refused peer is logged once (`vpcd: the peer on 127.0.0.1:35963 is owned by uid
  ..., not an allowed uid (0, 990); refusing the connection, retrying every second`), and
  the daemon keeps trying every second, so the card enters the reader as soon as the real
  vpcd listens.

### `70-localkey.rules`

A UHID device has no USB ancestor: its hidraw node is under
`/devices/virtual/misc/uhid/0003:<VID>:<PID>.<n>/`, so the usual YubiKey rules (keyed on
USB attributes) never match it. systemd's `fido_id` tags the FIDO node `uaccess` by itself
(`60-fido-id.rules`); nothing tags the OTP node, which `ykman otp` and challenge-response
need. The rule tags both, matching the device path:

- `--profile own` (the default): `0003:1209:0001.*`;
- `--profile yubikey-5c-nano-5.7.4`: `0003:1050:0401` to `0407` except `0404` (CCID only,
  no HID node).

It sorts before `73-seat-late.rules`, which turns the `uaccess` tag into an ACL for the user
at the seat. The pattern was checked in the test guest (`tools/linux-guest/tests/uhid.sh`).
`/dev/uhid` itself is left root-only; see the safety notes.

## Installing by hand

On the Linux machine, as root. Package names are Debian's and Ubuntu's; other
distributions have the same software under similar names.

1. **pcscd and vpcd**: `apt install pcscd vsmartcard-vpcd`. vpcd's reader configuration is
   `/etc/reader.conf.d/vpcd` (`DEVICENAME /dev/null:0x8C7B`, vpcd's port 35963). ykman
   treats only a reader whose name contains "Yubico YubiKey" as a YubiKey; for ykman over
   CCID set `FRIENDLYNAME "Yubico YubiKey OTP+FIDO+CCID"` there (OpenSC and GnuPG work
   with either name; `lk-vpcd`'s crate docs, "Checked against the real vpcd"). Restart
   pcscd: `systemctl restart pcscd`.

   pcscd is socket-activated and, as packaged, exits when idle (`--auto-exit`); vpcd's
   listener goes with it, so the card leaves the reader and comes back about a second
   after the next client starts pcscd again, which a client that looks at once may miss.
   To keep pcscd running, override its `ExecStart=` without `--auto-exit`
   (`systemctl edit pcscd.service`; copy the line from `systemctl cat pcscd.service`).

2. **The binary**: build `localkeyd` (`cargo build --release -p localkeyd`) and install it:
   `install -m 0755 target/release/localkeyd /usr/local/bin/localkeyd`.

3. **The storage key**:

   ```sh
   install -d -m 0700 -o root -g root /etc/localkey
   localkeyd keygen --key-file /etc/localkey/storage.key    # 0600, never overwritten
   ```

   Keep a copy somewhere safe: without the key the state in `/var/lib/localkey` cannot be
   opened. For the encrypted-credential variant instead: `localkeyd keygen --print |
   systemd-creds encrypt --name=localkey-key - /etc/localkey/storage.key.cred`, then switch
   the unit to the commented `ExecStart=` and `LoadCredentialEncrypted=`.

4. **The unit**:

   ```sh
   install -m 0644 localkeyd-uhid-vpcd.service /etc/systemd/system/
   systemd-analyze verify /etc/systemd/system/localkeyd-uhid-vpcd.service
   systemctl daemon-reload
   systemctl enable --now localkeyd-uhid-vpcd.service
   ```

5. **The udev rule**:

   ```sh
   install -m 0644 70-localkey.rules /etc/udev/rules.d/
   udevadm control --reload
   systemctl restart localkeyd-uhid-vpcd.service    # new devices get the tag
   ```

6. **Check**: `localkeyd ctl --control /var/lib/localkey/control.sock status` (as root)
   shows `attached=true` once a UHID device runs or the card is in the reader;
   `pcsc_scan` shows the card; `fido2-token -L` and `ykman list` (as the desktop user) see
   the key. A touch is `localkeyd ctl --control /var/lib/localkey/control.sock tap` (`tap
   long` for OTP slot 2). The control socket is root's (a 0600 socket in a 0700
   directory), so a desktop user touches the key with `sudo localkeyd ctl ...`.

To remove: `systemctl disable --now localkeyd-uhid-vpcd.service`, delete the unit and the
rule, `systemctl daemon-reload`, `udevadm control --reload`. The state in
`/var/lib/localkey` and the key in `/etc/localkey` stay until deleted.

## Safety notes

- **This machine only.** Never install these on a machine where they could reach real
  hardware you care about: the unit creates HID devices system-wide and inserts a card
  into pcscd. The rule's device path pattern matches only devices made through
  `/dev/uhid`, never a physical YubiKey, whose nodes sit under a USB host controller.
- **The YubiKey profile looks like a YubiKey.** With `--profile yubikey-5c-nano-5.7.4`
  every program on the machine sees Yubico's USB IDs and ATR. Attestation stays the
  engine's own; relying parties that check attestation are not fooled.
- **`/dev/uhid` stays root-only.** Whoever can write it can create any HID device, a
  keyboard that types into the logged-in session among them. That is why the unit runs as
  root (without capabilities) instead of opening `/dev/uhid` to a group. The rules file
  shows the group rule for a dedicated system user, commented out.
- **vpcd listens on every IPv4 interface.** vpcd binds `0.0.0.0:35963` and `35964` (see
  `lk-vpcd`), and any program that connects becomes the card in its reader. Block those
  ports from the network (firewall). On a shared machine any local user can connect while
  localkeyd's connection is down (pcscd restarting) and present a card of their own.
- **Nothing authenticates vpcd to localkeyd either.** 35963 is not a privileged port:
  while vpcd does not listen (pcscd stopped, restarting, or exited with `--auto-exit`),
  any local user can, and whoever accepts localkeyd's connection drives the card (PIN
  retry counters, OATH codes without an access key). localkeyd checks the owner of the
  listening end on Linux (see the unit's description above) and refuses anything not
  owned by an allowed uid; keep the default set, or name pcscd's uid exactly with
  `--vpcd-peer-uid`. On other systems (macOS has no `/proc`) no such check exists.
- **APDUs are not encrypted** between localkeyd and vpcd, and a remote peer cannot be
  checked. localkeyd refuses to start with a `--vpcd-addr` that is not a loopback address
  (exit 2) unless `--vpcd-allow-remote` is given, and then logs a warning;
  `IPAddressAllow=localhost` blocks other addresses in the unit anyway. Keep the default.
- **The storage key** is the only thing that protects the state at rest. Keep the file
  root-only (`localkeyd` refuses a key file that grants group or other access) or use the
  encrypted credential; never pass `--allow-unreadable` in a unit.
- **Stopping** with `systemctl stop` is a clean shutdown; a kill (`systemctl kill`, a
  crash) loses nothing that was acknowledged either, because every save is atomic, and the
  next start replaces leftover sockets.
