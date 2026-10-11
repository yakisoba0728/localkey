# Program phase contract

The engine (`docs/DESIGN.md`, `docs/CONTRACTS.md`) is a pure state machine. This file fixes
the program around it: the crates that give the engine storage, randomness, a clock, a run
loop and transports. It is binding for the program crates the way `docs/CONTRACTS.md` is
binding for the engine crates. Where a later "as built" section refines an earlier one, the
later section wins.

## Scope and boundary

In scope:

- `lk-host`: file storage, OS randomness, the storage key, the state directory;
- `lk-run`: the run loop that owns the `Device`;
- `lk-wire`: a private Unix-socket transport and the control socket;
- `localkeyd`: the daemon binary;
- as a second step, Linux transports: `lk-uhid` (UHID) and `lk-gadget` (FunctionFS/ConfigFS
  composite gadget);
- as a third step, `lk-vpcd` (PC/SC through vsmartcard's `vpcd`), transport combinations,
  the control `shutdown` and service examples.

Out of scope until the user widens the safety boundary:

- macOS virtual HID/USB (IOHIDUserDevice, IOUSBHost need Apple entitlements, signing and FFI);
- talking to the OS keychain from our code or tests;
- anything that touches the host's USB/HID/PCSC stack, keyboard, kernel, or the physical
  YubiKey.

On this macOS host only the wire transport runs end to end. It carries the full
`Input`/`Output` set, so a bridge process can sit on the other side. The Linux transports are
exercised inside a disposable no-NIC QEMU guest (`tools/linux-guest/`, DESIGN §12 decision 7).

## Rules for program crates

These replace the engine-only rules of `docs/CONTRACTS.md` "Rules for every crate" for
`lk-host`, `lk-run`, `lk-wire`, `localkeyd` and the later transport crates:

- **Allowed:** std threads, `std::time`, files, sockets, processes, environment. Program
  crates are the only place where the engine meets the OS.
- **Still forbidden:** third-party crates (std only; `tools/license_check.py` enforces this),
  `unsafe` (workspace `forbid`), and reading the legacy implementation.
- Workspace lints apply: `unwrap_used` and `missing_debug_implementations` warn, and the bar
  is zero clippy warnings for `--all-targets`. Use `?` with real error types; `expect` only for
  true invariants with a message that states the invariant.
- Unix only (`cfg(unix)`): macOS and Linux. Linux-only code is `cfg(target_os = "linux")` and
  must keep the macOS build and clippy clean.
- Tests never touch the host's devices, keychain or the user's real directories. They use
  fresh directories under `std::env::temp_dir()` with short names (a Unix socket path must
  fit in 104 bytes on macOS) and remove them at the end. No network; the one exception is
  lk-vpcd (and localkeyd's vpcd tests), which talk TCP to a fake vpcd on `127.0.0.1` with
  ephemeral ports.
- Build with `CARGO_BUILD_JOBS=2 nice -n 10 cargo ...`. Other agents may build at the same
  time; wait on cargo's lock instead of deleting `target/`.
- Secrets: the storage key travels as `[u8; 32]` only where the engine API demands it;
  elsewhere hold it in `lk_crypto::SecretBytes`. Never log key bytes, record contents,
  APDUs or CTAP payloads above the `-vv` trace level, and never key bytes at all.

## lk-host

Depends on `lk-core`, `lk-crypto` (for `SecretBytes`), `lk-device` (for `storage::record_id`
only if useful). Modules and API:

### State directory (`state`)

```text
<state>/            mode 0700, created if missing
  lock              process lock (File::try_lock, held for the store's lifetime); holds the pid
  identity          plaintext, "serial=<decimal>\n", written once on first run
  device.rec  fido.rec  oath.rec  otp.rec  piv.rec  openpgp.rec  hsmauth.rec  sd.rec
                    sealed record bytes, mode 0600
  *.tmp             leftovers of an interrupted save; removed at open
```

- An existing state directory whose mode grants any group/other permission is refused
  (`HostError::Permissions`), as is a state path that is a symlink or not a directory.
- Record file names are fixed by `Record`: `Device` → `device`, `Fido` → `fido`, `Oath` →
  `oath`, `Otp` → `otp`, `Piv` → `piv`, `OpenPgp` → `openpgp`, `HsmAuth` → `hsmauth`,
  `SecurityDomain` → `sd`.

### `FileStore`

- `FileStore::open(dir: &Path) -> Result<FileStore, HostError>`: creates or checks the
  directory, takes the lock (`HostError::Locked` if another process holds it, with the pid
  read from the lock file when available), removes `*.tmp`.
- `impl lk_core::Store`:
  - `load`: a missing file is `Ok(None)`; any other I/O error is `Err(StoreError)`.
  - `save`: write `<name>.rec.tmp` (create, truncate, mode 0600), `write_all`, `sync_all`,
    rename over `<name>.rec`, then `sync_all` on the directory. Any failure is
    `Err(StoreError)` and leaves the previous record intact. On macOS `sync_all` is
    `fsync`, not `F_FULLFSYNC` (that needs `fcntl`, which needs `unsafe`); documented, accepted.
- `FileStore` is `Send` and `Debug` (the debug output names the directory only).
- `FileStore::dir(&self) -> &Path`.

### Identity

- `load_or_create_serial(dir: &Path, entropy: &mut dyn Entropy) -> Result<u32, HostError>`:
  reads `identity`; if missing, draws a serial uniformly in `10_000_000..=99_999_999`
  (rejection sampling, no modulo bias), writes the file atomically (tmp + rename, 0600) and
  returns it. A malformed file is an error, never silently replaced.

### `OsEntropy`

- Reads `/dev/urandom` through `std::fs::File` (opened once). `fill` reads exactly
  `out.len()` bytes; on any error it panics with a message. It never returns partial or zero
  bytes (`Entropy::fill` cannot report an error). `Send`, `Debug`.

### Storage key (`key`)

- Text format: exactly 64 hex digits (either case), optionally followed by one `\n`.
- `generate_key(entropy: &mut dyn Entropy) -> SecretBytes` (32 bytes).
- `write_key_file(path: &Path, key: &SecretBytes) -> Result<(), HostError>`: `create_new`
  with mode 0600 (refuses to overwrite), lowercase hex plus `\n`, `sync_all`.
- `read_key_file(path: &Path) -> Result<SecretBytes, HostError>`: refuses a file whose mode
  grants group/other access (`HostError::Permissions`), or that is not the text format.
- `key_from_command(command: &str) -> Result<SecretBytes, HostError>`: runs `/bin/sh -c
  command` with stdin null and stderr inherited; a non-zero exit, or stdout that is not the
  text format (surrounding whitespace allowed), is an error. This is how a user wires the
  macOS Keychain (`security find-generic-password -w -s localkey`), `secret-tool`, `pass`
  or a password manager without our code touching any of them.
- `to_array(key: &SecretBytes) -> [u8; 32]` for `Device::open`.

### Errors

`HostError` (enum, `Debug`, `Display`, `std::error::Error`): `Io { path, source }`,
`Permissions { path, mode }`, `Locked { path, pid: Option<u32> }`, `Format { path, reason }`,
`Command { reason }`. Messages name paths, never contents.

## lk-run

Depends on `lk-core`, `lk-device`. The code skeleton in `crates/lk-run/src/lib.rs` fixes the
public types; the implementation must keep them.

- `Runner::spawn(factory, config)` starts the runner thread. The thread calls `factory()` to
  build the `Device` (the device is `!Send`, so it is built and dropped on that thread), then
  sends back a `Ready` (unreadable records, the `UsbIdentity`, the serial, the profile's
  product name) and waits. `spawn` returns once `Ready` arrives, or the factory's error.
- `Runner::serve(transport)` attaches the one bus transport. The runner calls
  `transport.enumerate(&identity)` first, then starts feeding inputs. Before `serve`, inputs
  are not accepted (nothing can send them: transports get their `Sender` from
  `Runner::sender()` and are attached by `serve`). Control commands (`Status`, `Watch`,
  `Shutdown`) work before `serve`.
- `Runner::shutdown(self) -> Result<(), RunError>` sends `Command::Shutdown` and joins.
  Dropping the last `Sender` also ends the loop.
- **Clock**: an `Instant` taken when the thread starts is time 0, and the device is opened
  with `Device::open` there (power-up at 0). `now` is whole milliseconds since then.
- **Loop**: wait on the channel with `recv_timeout` until the earliest of
  `device.next_deadline()` and the runner's own tap release. On timeout, deliver
  `Input::Tick` (or the tap's `Touch(Up)`). On a command, handle it. Outputs go to the
  transport in the order the device returned them.
- **Taps**: `Command::Tap { hold_ms }` sends `Touch(Down)` now and `Touch(Up)` at `now +
  hold_ms`. A tap or a raw `Touch(Down)` while the sensor is already held is ignored, and so
  is a raw `Touch(Up)` while it is not held. `TAP_SHORT_MS` = 500 (within the OTP slot 1
  window 300–1500 ms), `TAP_LONG_MS` = 3000 (slot 2 window 2500–5000 ms).
- **Suspend**: after passing `Bus(Suspend)` to the device the runner is suspended. While
  suspended, every output except `PresenceIndicator` and `Reenumerate` is queued, at most
  `config.suspend_queue_limit` (oldest dropped first, counted in `Status::dropped`). On
  `Bus(Resume)` the queued outputs go out first, then the outputs of the resume itself (the
  data sat in the device's endpoints before the host resumed). `Bus(Reset)` or
  `Bus(PowerCycle)` while suspended discards the queue (counted as dropped) and ends the
  suspension.
- **Re-enumeration**: on `Output::Reenumerate`, the runner calls
  `transport.enumerate(&device.usb_identity())`; it does not pass the output to `deliver`.
- **Wall clock**: with `config.wall_clock`, the runner calls
  `set_unix_time(Some(SystemTime::now() seconds))` at start and whenever the whole-second
  value changed before an input. Without it, it never calls `set_unix_time` (a physical key
  has no clock).
- **Presence watchers**: `Command::Watch(Sender<bool>)` registers a watcher; it gets the
  current state at once and every change after (`PresenceIndicator` outputs), and is dropped
  when its receiver is gone.
- **Panics**: a panic in the device or the entropy source ends the thread; `shutdown` and
  `join` report it as `RunError::Panicked`. The process should exit; the store is consistent
  because every save is atomic and happens before the response.

## lk-wire

Depends on `lk-core`, `lk-device`, `lk-run`. Unix sockets only (`std::os::unix::net`).

### Socket placement

- The daemon binds the socket path given to it. Its parent directory must exist and grant no
  group/other permission (checked; the default paths live in the state directory, which is
  0700). Ownership is not compared: std has no `getuid` without `unsafe`, and a 0700
  directory of another user cannot be written to anyway. The socket file is set to 0600 after `bind`.
- An existing path is removed before `bind` only if it is a socket; anything else is an
  error. The socket file is removed again on clean shutdown.

### Frame format

```text
frame   = length:u32be  type:u8  payload
length  = 1 + payload length, at most 1 + 1_048_576
```

Host → device:

| Type | Name | Payload | Device input |
| --- | --- | --- | --- |
| `0x01` | FIDO_OUT | 64 bytes | `Input::FidoReport` |
| `0x02` | OTP_SET_FEATURE | 8 bytes | `Input::OtpSetFeature` |
| `0x03` | OTP_GET_FEATURE | empty | `Input::OtpGetFeature` (answer: `0x83`) |
| `0x04` | CCID_BULK_OUT | the message, at least 10 bytes | `Input::Ccid` |
| `0x05` | CCID_ABORT | `slot, seq` | `Input::CcidControlAbort` |
| `0x06` | TOUCH | `0x00` up, `0x01` down | `Input::Touch` |
| `0x07` | BUS | `0x00` reset, `0x01` suspend, `0x02` resume, `0x03` power cycle | `Input::Bus` |

Device → host:

| Type | Name | Payload |
| --- | --- | --- |
| `0x80` | IDENTITY | see below; sent first on every connection and after every re-enumeration |
| `0x81` | FIDO_IN | 64 bytes (`Output::FidoReport`) |
| `0x82` | OTP_KEYBOARD | 8 bytes (`Output::OtpKeyboard`) |
| `0x83` | OTP_FEATURE | 8 bytes (`Output::OtpFeature`) |
| `0x84` | CCID_BULK_IN | message (`Output::Ccid`) |
| `0x85` | CCID_INTERRUPT | message (`Output::CcidInterrupt`) |
| `0x86` | PRESENCE | `0x00` / `0x01` (`Output::PresenceIndicator`) |
| `0xFF` | ERROR | UTF-8 reason; the server closes the connection after it |

IDENTITY payload: `vendor_id:u16be product_id:u16be device_release:u16be interfaces:u8`
(bit 0 OTP, bit 1 FIDO, bit 2 CCID), then seven fields, each `len:u16be bytes`:
manufacturer (UTF-8), product (UTF-8), serial (UTF-8, empty when `None`), device
descriptor (18 bytes), configuration descriptor, FIDO report descriptor, OTP report
descriptor.

### Connection semantics

- One client at a time: the client is the USB host the key is plugged into. A second
  connection gets `ERROR "busy"` and is closed; the first is unaffected.
- On accept the server sends IDENTITY, then delivers `Input::Bus(BusEvent::PowerCycle)`
  (plugging in powers the key).
- On disconnect the device keeps running; outputs produced while no client is connected are
  dropped. Reconnecting is a new plug-in.
- A malformed frame (unknown type, wrong payload size, length out of range) gets `ERROR` with
  the reason and the connection is closed. It never reaches the device.
- `WireTransport` implements `lk_run::Transport`; `deliver` writes frames to the current
  client (a write error drops that client). Reader and accept loops run on their own threads
  and send `Command::Input` through the runner's `Sender`.

### Client library

`lk_wire::Client` for tests and bridges: `connect(path)`, `send(&HostInput)`,
`recv(timeout) -> Result<Option<Frame>, WireError>`, `identity()` helpers to parse IDENTITY,
and `Frame` as a typed enum mirroring the table.

### Control socket

A second socket for the user side (touch, status), line based, one command per connection:

- Request: one line. Reply: zero or more lines, then `ok` or `error <reason>`, then close.
- `tap` (short hold), `tap long`, `down`, `up`, `power-cycle`, `status`, `watch`.
- `status` replies `key=value` lines: `serial`, `product`, `interfaces` (e.g. `otp,fido,ccid`),
  `presence` (`waiting`/`idle`), `attached` (whether a wire client is connected, when the
  transport is wire), `suspended`, `queued`, `dropped`, `unreadable` (comma list or empty),
  `uptime_ms`.
- `watch` replies `presence waiting` / `presence idle` lines as the state changes until the
  client disconnects (no `ok`).
- Same placement rules as the wire socket.

## localkeyd

The daemon binary (`crates/localkeyd`). Argument parsing by hand (no third-party crates).

```text
localkeyd keygen (--key-file PATH | --print)
localkeyd run --state DIR (--key-file PATH | --key-command CMD) [TRANSPORT]
              [--profile own|yubikey-5c-nano-5.7.4] [--control PATH]
              [--wall-clock] [--allow-unreadable] [--exit-on-stdin-eof] [-v | -vv]
localkeyd ctl --control PATH (tap [long] | down | up | power-cycle | status | watch
                              | shutdown)

TRANSPORT (default wire):
  [--transport wire] [--wire PATH]
  --transport uhid [--uhid-path PATH]                      (Linux)
  --transport gadget --udc NAME [--gadget-name NAME]
                     [--configfs DIR] [--ffs-dir DIR]      (Linux, root)
  --transport vpcd [--vpcd-addr HOST:PORT] [--vpcd-allow-remote]
                   [--vpcd-peer-uid UID[,UID...]]          (needs vsmartcard vpcd)
  --transport uhid,vpcd [--uhid-path PATH] [vpcd options]  (Linux)
```

- **as built**: transport defaults `--uhid-path /dev/uhid`, `--gadget-name localkey`,
  `--configfs /sys/kernel/config/usb_gadget`, `--ffs-dir /dev/ffs-<gadget name>`. An option
  of another transport is a usage error. The control socket is served with every transport;
  with uhid and gadget, `ctl tap` is how a touch reaches the device. `uhid` and `gadget` on
  a non-Linux system exit 2 before anything is opened; the gadget configuration is checked
  (read-only) before the state directory is opened.

- `run` defaults: `--profile own`, `--wire <state>/wire.sock`, `--control
  <state>/control.sock`.
- Startup order: open `FileStore` (fails fast with exit code 2 and the pid if locked), load
  the key, `load_or_create_serial`, spawn the runner. If `Ready` lists unreadable records and
  `--allow-unreadable` is absent, print which records and why it matters (the first mutating
  command of that application replaces the record), shut the runner down and exit with code
  3 without binding any socket. Then bind the control socket and the wire socket and serve.
- Exit codes: 0 clean, 1 runtime failure, 2 startup failure (usage, lock, key, permissions),
  3 unreadable records refused.
  - **as built**: exit 2 also covers uhid or gadget on a non-Linux system, a gadget
    configuration lk-gadget refuses, and any failure the transport reports during its first
    enumeration (then the control socket is removed and the runner shut down). If the runner
    stops during the first enumeration the code is 1. Failures of later enumerations are
    logged and the device stays absent until the next one.
- Clean shutdown: with `--exit-on-stdin-eof` (used by tests and supervisors) the daemon shuts
  down cleanly when stdin reaches EOF (runner shut down, device dropped, sockets removed);
  otherwise it runs until killed. No signal handling (std cannot catch
  signals without `unsafe`); every save is atomic, so a kill loses nothing that was
  acknowledged. Leftover sockets are replaced at the next start.
- Logging to stderr: default startup and errors; `-v` adds connections, enumeration and
  presence; `-vv` adds frame types and sizes (never payload bytes).

## Program core as built (binding)

`lk-host`, `lk-run`, `lk-wire` and `localkeyd` were implemented, adversarially reviewed and
fixed. Each crate's root doc (or `localkeyd/src/run.rs`, `log.rs`, `args.rs`) keeps an
"As built" list; the points that refine the sections above:

- **lk-host**
  - `HostError::Permissions { path, mode, refusal }`: `Refusal::{SymbolicLink,
    GroupOrOtherAccess, NotADirectory, NotARegularFile}` says why, because the mode alone
    cannot.
  - The state path is normalised (`components()`) before any check; a symlinked state path,
    `lock` or `<name>.rec` is refused, never followed. A `.rec` that is a symlink or not a
    regular file loads as `Err` (lk-device then reports it unreadable and the daemon refuses
    to serve), not as `Ok(None)`.
  - `save` removes a leftover `<name>.rec.tmp` and creates the new one with `create_new`, so
    it never writes through a planted link. The parent of a newly created state directory is
    synced.
  - **Decided**: when the directory sync after the rename fails, `save` still returns `Err`
    although the new bytes are in place. This fails closed: the engine answers with a
    storage failure and keeps its old state, and a retry counter on disk can only be ahead
    of memory (spent), never behind. Returning `Ok` would acknowledge a write that a power
    loss could undo.
  - `key_from_command` reads at most `MAX_OUTPUT_LEN` (1024) bytes and kills a command that
    prints more. `OsEntropy::open` refuses a `/dev/urandom` that is not a character device.
    Only canonical 8-digit serials are accepted in `identity`.
- **lk-run**
  - `HostInput`'s `Debug` shows the variant and payload size only (no PINs or payloads).
  - `Command::Tap` before `serve` is ignored, like inputs.
  - `Output::Reenumerate` discards the suspend queue (counted as dropped), ends the
    suspension and releases a held sensor. `Bus(PowerCycle)` also releases a held sensor
    (without `Touch(Up)`) and cancels a pending tap release; `Bus(Reset)` keeps it.
  - `Runner::shutdown` and `Drop` raise a stop flag first, so commands queued behind the
    shutdown are dropped instead of processed.
  - Dead presence watchers are also probed when a registration finds the list at its limit
    (64, then twice the survivors); a live watcher may hear its unchanged state again.
  - An attached transport holds a `Sender` clone, so after `serve` the loop ends only on
    `Shutdown` (not when the other senders are dropped).
- **lk-wire**
  - **Backpressure**: the reader sends a `Command::Status` marker after every 64 frames or
    256 KiB and waits for the previous marker's answer, so at most two windows of one
    client's inputs sit in the runner's unbounded channel; the rest waits in the socket.
  - Accepting starts at the first `enumerate`. The write queue holds 4096 frames; a full
    queue drops the client. After a malformed frame the client has 1 s in total to receive
    what was queued plus the `ERROR`, then the socket is shut down.
  - A server remembers its socket file's device and inode and removes the path (or wakes
    its accept loop) only while the path still holds that file.
  - Control: a request line is at most 256 bytes and must arrive within 10 s in total;
    `attached` is omitted from `status` when the transport cannot tell; `watch` writes no
    line for a repeated state, and a client that half-closes its socket keeps watching.
  - `Client::recv` / `connect_timeout` with a timeout too large to represent wait without a
    deadline.
- **localkeyd**
  - Logging never blocks: a 1024-line queue drained by one writer thread; dropped lines are
    counted and reported; exit waits at most 5 s for the queue.
  - The wire and control sockets must be two different files: compared by spelling before
    the state directory is opened, and by resolved parent plus file name right after.
  - A device that fails to open on the runner thread exits 2 (a startup failure). `keygen`
    and `ctl` failures exit 1; usage errors exit 2 for every command; `help` after a
    command prints the usage.
  - After `Device::open` the daemon overwrites its own `[u8; 32]` copy of the key (best
    effort; compiler copies cannot be wiped).

## Linux transports (second step)

Two transport crates for Linux. The Docker Desktop VM kernel has no `UHID`, no `DUMMY_HCD`
and no USB gadget support, so they are built as byte-level logic over generic I/O and tested
on every Unix with fakes (socket pairs, temporary directories). Real-kernel runs happen in a
QEMU guest inside Docker (`tools/linux-guest/`: `smoke.sh`, `uhid.sh`, `gadget.sh`); both
transports pass there with libfido2, python-fido2, ykman, pcscd/libccid, OpenSC and GnuPG.
Each crate's docs keep a "Settled on a real kernel" section with the observations.

Both use only files and processes (no `ioctl`, no `unsafe`), so they compile and their tests
run on every Unix; `localkeyd` refuses to start them on a non-Linux OS at run time.

Structure, so the logic is testable without a kernel:

- a pure core (event and descriptor encoding and parsing, the control-request state
  machine) with exhaustive unit tests;
- an I/O trait for opening the device files (`/dev/uhid`; FunctionFS `ep0` and `epN`), whose
  real implementation opens files and whose test implementation hands out
  `UnixStream::pair()` halves, so a test plays the kernel side byte for byte;
- the transport (`lk_run::Transport`) on top, with its reader/writer threads.

ConfigFS writes go to a root directory given as a parameter, so tests point it at a
temporary directory and inspect the files. The `mount` step is behind the same I/O trait.

Kernel ABI facts (structure layouts, constants) come from the kernel's UAPI headers and its
documentation (`Documentation/hid/uhid.rst`, `Documentation/usb/functionfs.rst`,
`Documentation/usb/gadget_configfs.rst`). Those are interface definitions, not legacy code;
use them for facts and do not copy their text. Every constant in the code cites its source.

### lk-uhid (FIDO HID and OTP HID through `/dev/uhid`)

- One UHID device per enabled HID interface: FIDO (the FIDO report descriptor) and OTP (the
  boot-keyboard report descriptor with its feature report). CCID is not available through
  UHID; with this transport the CCID interface is simply not presented.
- `UHID_CREATE2` with `bus` = `BUS_USB`, the identity's vendor, product and release, `name`
  = the product string, `uniq` = the serial string or empty, `phys` = `"localkey"`.
- Events in: `UHID_START`, `UHID_STOP`, `UHID_OPEN`, `UHID_CLOSE`, `UHID_OUTPUT`,
  `UHID_GET_REPORT`, `UHID_SET_REPORT`. Events out: `UHID_INPUT2`,
  `UHID_GET_REPORT_REPLY`, `UHID_SET_REPORT_REPLY`, `UHID_DESTROY`.
- Report ID prefix: the descriptors use no report IDs, but the kernel's raw report paths
  (hidraw writes and feature ioctls) carry the report number as a leading byte, and
  `UHID_START`'s `dev_flags` (`UHID_DEV_NUMBERED_*`) describe numbering. Check the
  semantics against `uhid.rst` and the kernel's `drivers/hid/uhid.c` / `hidraw.c` (read
  for interface behaviour only). Accept FIDO output of 65 bytes with a leading `00` (strip
  it) or exactly 64 bytes; accept OTP feature SET_REPORT data of 9 bytes with a leading
  `00` or exactly 8; answer GET_REPORT(feature) with the report number, then the 8 bytes.
  **Confirmed on a real kernel**: libfido2, python-fido2 and ykman write `00` + 64 bytes,
  which arrives as a 65-byte output (a raw 64-byte write arrives as 64); `HIDIOCSFEATURE`
  of 9 bytes arrives as 9, of 8 as 8 with report number 0; `HIDIOCGFEATURE(9)` returns
  `00` + the 8 bytes verbatim; hidraw reads carry no prefix; `UHID_START` has
  `dev_flags` 0.
- FIDO input reports go out as `UHID_INPUT2` with 64 bytes; OTP keyboard reports as
  `UHID_INPUT2` with 8 bytes.
- Re-enumeration destroys the devices and creates the ones the new identity enables.
- Bus events: creating the devices is a plug-in (`BusEvent::PowerCycle`); UHID has no
  suspend, resume or reset.
- The device path defaults to `/dev/uhid` and is a parameter (tests pass a fake).

### lk-gadget (ConfigFS + FunctionFS composite gadget)

The faithful transport: one USB device with the engine's descriptors (OTP keyboard, FIDO HID
and CCID interfaces), for a Linux machine with a USB device controller (a board plugged into
a computer, or `dummy_hcd` in a test guest). It needs root.

**Measured exceptions** (dummy_hcd, `gadget.sh`), none fixable from user space: endpoint
addresses are assigned by the controller (0407: `81/02/85/07/86/8a` where the engine has
`81/04/84/02/82/83`; `FUNCTIONFS_VIRTUAL_ADDR` keeps the engine's addresses but then the
host cannot configure the device); `iSerialNumber` is 3 with an empty string (ConfigFS
always indexes the serial once a language exists); `bcdUSB`, DEVICE_QUALIFIER and BOS follow
the controller, not `max_speed` (0x0200 and a DEVICE_QUALIFIER on high-speed dummy_hcd,
0x0210 plus BOS on a SuperSpeed one). Only a full-speed-only controller matches the
reference key's speed descriptors. Everything else is byte-identical.

- **ConfigFS** (`/sys/kernel/config/usb_gadget/<name>`, root path a parameter): `idVendor`,
  `idProduct`, `bcdDevice`, `bcdUSB` from the device descriptor; `max_speed` =
  `full-speed` (the engine's descriptors are full-speed: 64-byte bulk packets);
  `strings/0x409/{manufacturer,product,serialnumber}`; one configuration `c.1` with
  `bmAttributes` and `MaxPower` from the configuration descriptor; one FunctionFS function
  `ffs.<name>` linked into `c.1`; `UDC` written last to bind, emptied to unbind.
- **FunctionFS**: mounted with `mount -t functionfs <name> <dir>` (a `Command`; the mount
  point is a parameter). Write the descriptors (`FUNCTIONFS_DESCRIPTORS_MAGIC_V2`,
  full-speed only) and the strings blob to `ep0`, then open the endpoint files in descriptor
  order. The interface, class and endpoint descriptors are the engine's configuration
  descriptor minus its 9-byte configuration header, in the same order, so the host sees the
  engine's bytes.
- **ep0 events** (12-byte `usb_functionfs_event`): `BIND`, `UNBIND`, `ENABLE`, `DISABLE`,
  `SETUP`, `SUSPEND`, `RESUME`. `ENABLE` → `BusEvent::Reset` (the host configured the
  device after a bus reset), `SUSPEND` → `BusEvent::Suspend`, `RESUME` → `BusEvent::Resume`.
  The first `ENABLE` after the gadget is bound is a plug-in → `BusEvent::PowerCycle`.
- **Control requests** (`SETUP`; interface numbers as in our descriptors):
  - HID interfaces: GET_DESCRIPTOR for the HID report descriptor (`0x22`) and the HID
    descriptor (`0x21`); SET_IDLE, GET_IDLE, SET_PROTOCOL, GET_PROTOCOL (state kept per
    interface, no effect on the engine); OTP GET_REPORT(feature) → `Input::OtpGetFeature`
    answered with the resulting `Output::OtpFeature`; OTP SET_REPORT(feature) →
    `Input::OtpSetFeature`; SET_REPORT(output) on the keyboard (LEDs) acknowledged and
    ignored; FIDO SET_REPORT(output) of 64 bytes → `Input::FidoReport`.
  - CCID interface: ABORT (`bRequest 01`, `wValue = bSeq << 8 | bSlot`) →
    `Input::CcidControlAbort`. GET_CLOCK_FREQUENCIES and GET_DATA_RATES are stalled,
    because the class descriptor has `bNumClockSupported = 0` and
    `bNumDataRatesSupported = 0` (CCID Rev 1.1 §5.3.2, §5.3.3).
  - Anything else is stalled (an IN request is stalled by reading `ep0`, an OUT request by
    writing to it, per `functionfs.rst`).
- **Endpoints**: FIDO interrupt OUT (64-byte reads) and IN; OTP keyboard interrupt IN; CCID
  bulk OUT, bulk IN and interrupt IN. A CCID bulk-out message is read packet by packet: the
  first 64-byte packet gives `dwLength`, then the rest is read until the message is complete
  (a host does not send a zero-length packet after a message that fills whole packets).
  Each IN endpoint has a writer thread with a queue, so `deliver` never blocks the runner.
- **GET_REPORT needs an answer inside the control transfer**: the ep0 thread sends
  `Input::OtpGetFeature` and waits (bounded, 1 s) for the matching `Output::OtpFeature`
  that `deliver` hands back through a channel; on timeout it stalls.
- **Re-enumeration**: unbind (`UDC` = empty), close the endpoints and `ep0`, rewrite
  `idProduct` and strings, reopen `ep0` with the descriptors for the new interface set,
  reopen the endpoints, bind again.
- Teardown on drop: unbind, close files, unmount, remove the ConfigFS directories in
  reverse order of creation (a failure is logged, not fatal).

## Linux transports as built (binding)

Both crates were implemented, adversarially reviewed against the kernel sources (UAPI
headers, `uhid.c`, `hidraw.c`, `hid-core.c`, `f_fs.c`, `composite.c`, `configfs.c`,
`proc_namespace.c`) and fixed. Their crate docs list the settled kernel facts with sources
and the items only a real kernel can settle. The points that refine the sections above:

- **Both**: the reader threads pace themselves exactly like lk-wire (a `Command::Status`
  marker every 64 inputs, lk-gadget also every 256 KiB; at most two windows per producer in
  the runner's channel). Every wait for a marker gives up when the device or session stops,
  except an OTP feature request in flight across a re-enumeration: lk-uhid lets it finish
  (up to 1 s), and lk-gadget's drain lets it take the answer the runner already delivered.
- **Both, re-enumeration (found on a real kernel)**: the response to the command that
  caused the reboot, and the reply to the host's status read before an OTP HID reboot, are
  written to the old device before it goes away. lk-uhid writes queued outputs and owed
  replies before `UHID_DESTROY`, and the DESTROY waits `DESTROY_AFTER_REPLY` (100 ms) after
  the last reply, because the kernel fails a request whose reply is followed at once by a
  DESTROY. lk-gadget drains FIDO IN and CCID bulk-in data and a pending GET_REPORT for at
  most `DRAIN_TIMEOUT` (1 s) before it unbinds, and a session it is stopping passes no bus
  events (dummy_hcd reports SUSPEND before UNBIND). Dropping either transport does not
  wait for owed replies.
- **lk-uhid**
  - Report-number rule, from the driver code (`hidraw_send_report`, `hidraw_get_report`,
    `uhid_hid_output_raw`, `uhid_hid_set_report`): FIDO output arrives as 64 bytes or 65
    with a leading `00`; OTP SET_REPORT(feature) as 8 or 9 bytes with `00`; the
    GET_REPORT(feature) reply is `00` followed by the 8 bytes. `hidraw.rst` describes
    unnumbered GET_FEATURE differently; the code wins.
  - `UHID_CREATE2`'s name is cut to 127 bytes at a character boundary. A non-character
    `--uhid-path` is refused. Unsupported GET/SET_REPORT get `EIO` at once; the feature read
    has a 1 s budget (the kernel waits 5 s).
  - Re-enumeration: each new device gets a new file; the writer waits for its
    predecessor's `UHID_DESTROY`; outputs are dropped until a fence marker queued behind the
    old inputs is answered, so nothing from before the reboot reaches the new devices.
    Inputs queued before the reboot are still handled by the rebooted device before the
    plug-in `PowerCycle`.
  - `attached` = `UHID_CREATE2` accepted, not destroyed, and no `-EINVAL` on `UHID_INPUT2`
    since (the kernel's only sign of a failed `hid_add_device`). `UhidNotice::NotRunning`
    reports it once.
  - Observed: the kernel's keyboard and SysRq handlers open the OTP device themselves; a
    flood overflows the kernel's 32-event queue, which logs every dropped report (not rate
    limited). A device with no bound driver gets no `UHID_STOP` after DESTROY, so its
    reader thread and file stay until the process exits (accepted: waking a blocked read
    needs `poll`, which std lacks); shutdown then takes about 1.1 s.
  - udev: the FIDO node gets `uaccess` through `fido_id`. The OTP node lives under
    `/devices/virtual/misc/uhid/`, so USB-attribute rules cannot match it; a desktop user
    needs a rule such as `SUBSYSTEM=="hidraw", DEVPATH=="/devices/virtual/misc/uhid/0003:1209:0001.*", TAG+="uaccess"`
    (vendor and product of the profile in use).
- **lk-gadget**
  - The strings blob is the bare 16-byte header with both counts 0 (`__ffs_data_got_strings`
    requires both counts zero or both non-zero, and the engine's interfaces use no
    strings).
  - ConfigFS `MaxPower` is written in mA (2 × `bMaxPower`; the kernel halves it below
    SuperSpeed). Unbind writes `"\n"`. The function link is made after the ep0 blobs, with an
    absolute target. `bcdUSB` is written but `composite.c` overwrites it on every
    GET_DESCRIPTOR(device) (`0x0200` on `dummy_hcd`).
  - ENABLE: only a not-enabled → enabled change counts (`set_alt` reports one ENABLE per
    interface); the first is the plug-in `PowerCycle`, later ones `Reset`. SUSPEND is passed
    once until RESUME.
  - CCID: one 64-byte packet per read; `dwMaxCCIDMessageLength` counts the 10-byte header
    (CCID Rev 1.1 §5.1); a longer message is dropped without an answer; a zero-length packet
    follows a bulk-in message that fills whole packets. Endpoint-directed requests are
    stalled.
  - ep0: calls interrupted by `EINTR` are repeated (at most 16 times), and a read is taken as
    events only if it is whole events with the zero padding the kernel writes; anything
    else is host data of a data stage and is discarded.
  - An UNBIND the transport did not cause (or 20 failed ep0 reads) ends the session and
    closes every FunctionFS file, so f_fs resets; the gadget stays unbound until the next
    `Output::Reenumerate` or a restart.
  - The leftover of a killed process (`UDC` empty, only the directories and links this
    transport creates) is reclaimed at the next start: unmount wherever
    `/proc/self/mounts` shows the instance, tear the tree down, create it again. Anything
    else at the gadget path is refused and left alone. Residual risk, documented: two
    daemons with different state directories and the same gadget name.
  - If the unmount fails at teardown, the ConfigFS tree is left in place and reported,
    because removing the function directory under a live mount detaches it.
  - Observed on dummy_hcd: the zero-length packet after a bulk-in message of whole packets
    reaches the host (libccid reads with 65556-byte URBs and would hang without it); with
    `O_NONBLOCK`, writes before the host configures the device fail at once with `EAGAIN`;
    the controller answers interface GET_STATUS itself; `ep0` reopens at once after a
    session; reclaiming a killed process's leftover works; an outside bind after an outside
    unbind is refused by f_fs.


## PC/SC through vpcd, transport combinations, clean shutdown (third step)

### lk-vpcd

A CCID path that needs no USB device controller: the `vpcd` IFD handler of the vsmartcard
project (packaged as `vsmartcard-vpcd` in Debian and Ubuntu, also available for macOS)
makes pcscd show a "Virtual PCD" reader and waits for a virtual card to connect to it over
TCP. `lk-vpcd` is that card: a std-only TCP client. No vsmartcard code is used; the wire
protocol is taken from the project's documentation (cite it) and checked against the real
`vpcd` in the guest.

- Connects to `--vpcd-addr HOST:PORT` (default `127.0.0.1:35963`, the documented default
  of vpcd; check). Loopback only by default; a non-loopback address is allowed but logged as
  a warning, because the APDUs are unencrypted. While vpcd is not listening the transport
  retries every second; a lost connection is retried the same way (card removed, then
  inserted again).
- Protocol (verify every detail against the docs and the real vpcd): each message is a
  2-byte big-endian length followed by that many bytes. A 1-byte message from vpcd is a
  control command: power off, power on, reset, get ATR (answered with the ATR bytes). Any
  longer message is a command APDU, answered with the response APDU.
- Mapping to the engine (the transport is a small CCID host): power on →
  `PC_to_RDR_IccPowerOn` (keep the ATR from the `RDR_to_PC_DataBlock`); power off →
  `PC_to_RDR_IccPowerOff`; reset → power off then power on; get ATR → the ATR from the last
  power on, powering on first if needed; APDU → `PC_to_RDR_XfrBlock` with the next `bSeq`,
  and the answer is the `abData` of the matching `RDR_to_PC_DataBlock`. Time-extension
  replies (`bStatus` bit 7, `0x80`) are skipped, so a command waiting for a touch simply
  takes longer. An error reply (slot error, card absent) answers the APDU with `6F00` and
  powers the slot on again before the next APDU. Exactly one command is in flight (vpcd is
  synchronous).
- Outputs other than `Output::Ccid` are ignored. `Output::CcidInterrupt` is ignored (vpcd has
  no slot-change message). It sends no bus events: the device is powered when it opens.
- Enumeration: when the identity's interfaces include CCID the transport connects; when
  CCID is disabled it disconnects (the reader shows no card) and stays disconnected until an
  enumeration enables CCID again.
- Same structure as the other transports: pure protocol module with unit tests, an I/O seam
  (connect function), and tests against a fake vpcd on `127.0.0.1` with an ephemeral port
  (loopback only; this is the one place program tests use TCP).

### Transport combinations

- `lk_run::Fanout` (new public type in `lk-run`): a `Transport` made of several transports.
  `enumerate` goes to every member in order; `deliver` gives every member a clone of the
  output, and each member ignores what it does not carry; `attached` is `Some(true)` if any
  member says so, `Some(false)` if all that know say false, else `None`.
- `localkeyd run --transport` takes a comma-separated set: `wire`, `uhid`, `gadget`, `vpcd`.
  Valid sets: any single transport, and `uhid,vpcd` (the whole device on a Linux machine
  without a device controller: FIDO and OTP through UHID, CCID through pcscd). `wire` and
  `gadget` present the whole device and combine with nothing. Each transport keeps its own
  options (`--vpcd-addr` belongs to `vpcd`). `vpcd` alone runs on every Unix; on macOS it
  needs vpcd installed into the system's PC/SC by the user (not done or tested here).

### Clean shutdown from the control socket

- Control request `shutdown`: replies `ok`, then the daemon does exactly what
  `--exit-on-stdin-eof` does at EOF (control socket closed, runner shut down, device
  dropped, transports torn down, sockets removed) and exits 0. `localkeyd ctl ... shutdown`
  sends it. This gives supervisors (systemd `ExecStop`, launchd) a clean stop without
  signal handling.

### Service examples

`tools/service/` (examples, not installed by anything): a systemd system unit for
`--transport uhid,vpcd` (with `ExecStop=localkeyd ctl --control ... shutdown`, the storage
key through `--key-command` or a root-only key file, `StateDirectory=`), a udev rule giving
the logged-in user access to the OTP hidraw node, and a short README. They are checked for
syntax only (`systemd-analyze verify` in the guest if available).

## Third step as built (binding)

Implemented, adversarially reviewed and fixed like the earlier steps, then run in the guest
(`tools/linux-guest/tests/vpcd.sh`, every step PASS) against vsmartcard-vpcd 3.3 and
pcsc-lite 2.4.1 with OpenSC, ykman, pyscard and GnuPG.

- **vpcd protocol facts** (vsmartcard docs, confirmed on the real vpcd; details and
  sources in `crates/lk-vpcd/src/lib.rs`): the card connects to vpcd over TCP; vpcd binds
  `0.0.0.0:35963` and `:35964` (two readers, "Virtual PCD 00 00" and "00 01"), although its
  README says localhost; every message is a 2-byte big-endian length plus payload (at most
  0xFFFF); a 1-byte payload is a control command (off 0, on 1, reset 2, GET ATR 4; only GET
  ATR is answered); anything longer is an APDU answered with the response APDU. vpcd has
  no error message: an empty answer or a failed read makes it close the connection, so
  every APDU gets a non-empty answer. Its presence check is a GET ATR about every 450 ms.
- **lk-vpcd as built**:
  - GET ATR is answered from the last power-on of the current connection and powers on
    only when there is none yet (powering on at every poll would undo pcscd's idle
    power-down). The slot is powered on before an APDU whenever it is not known to be
    powered (after an error reply, vpcd's power off, a new connection).
  - A dropped command (the runner answered the marker and 5 s, `REPLY_SILENCE`, passed
    without a time extension) is answered `6F00`. Commands and responses longer than one
    CCID message are chained (3062 data bytes for the engine); a response over 65535 bytes
    gets `6F00`.
  - Every enumeration with CCID is a re-plug: the reply that caused it is written, the
    connection closed, and remade after `REPLUG_PAUSE` (1.5 s, longer than two of pcscd's
    polls; without it pcscd never saw the removal after `ykman config usb`). Disabling CCID
    disconnects after the same pause.
  - A connection lost while a command waits (checked every `PEER_CHECK`, 200 ms, with a
    non-consuming peek) aborts the command with the CCID abort pair; `bSeq` runs on across
    connections. Connection attempts are 1 s apart; only the first failure of a streak is
    reported. IPv4 is preferred; a non-loopback address is warned about once.
- **lk-run `Fanout`**: `new`, `push`, `len`, `is_empty`, `From<Vec<_>>`, `Default`; the last
  member gets the original output, the others clones. localkeyd orders `uhid` before `vpcd`,
  so the uhid plug-in power cycle reaches the device before vpcd's first power-on.
- **Control `shutdown`**: `ControlServer::bind_with_shutdown(path, runner, hook)`; `bind`
  answers `error shutdown not available`. The reply is `ok`, then, once the daemon has shut
  down, one last line: `stopped` (exit 0) or `error <reason>`. `ctl shutdown` exits 0 only
  on `stopped` and gives up after 30 s.
- **localkeyd**: the transport set is kept in a fixed order and startup failures name the
  member. The daemon refuses to start (exit 2) when the chosen transports present none of
  the device's enabled interfaces (for example `vpcd` with CCID disabled), and warns at the
  default level when a later re-enumeration leaves nothing presented. `--vpcd-addr` is
  resolved before the state directory is opened.
- **Interop notes for users** (also in `tools/service/README.md`): ykman accepts a PC/SC
  reader only if its name contains "Yubico YubiKey", so with the YubiKey profile set
  `FRIENDLYNAME "Yubico YubiKey OTP+FIDO+CCID"` in vpcd's `/etc/reader.conf.d/vpcd`; vpcd's
  empty second slot makes ykman print a harmless "Failed opening device"; with `uhid,vpcd`
  and CCID disabled, ykman counts the reader (fixed name) and the HID devices as two keys,
  so use `ykman --device SERIAL`. Any local user can connect a card to vpcd while localkeyd
  is not connected (vpcd listens on every IPv4 interface).
- **Service examples** (`tools/service/`): `systemd-analyze verify` and `udevadm verify`
  pass on systemd 259; `systemd-analyze security` exposure 1.9. Examples only.
- **Peer authentication** (after a security review): the vpcd link itself has no
  authentication, and whoever listens on the address drives the card (PIN retry counters,
  OATH codes without an access key). So:
  - a `--vpcd-addr` that does not resolve to loopback is a startup failure (exit 2, before
    the state directory) unless `--vpcd-allow-remote` is given; then it is warned about
    once and its owner is not checked. lk-vpcd cannot build a transport for a remote
    address without that flag (`check_addr`, `RemoteRefused`).
  - On Linux, after each connect and before any byte, the owner of the peer socket is read
    from `/proc/net/tcp` and `/proc/net/tcp6` (only ESTABLISHED and SYN_RECV lines; TIME_WAIT
    lines print uid 0; every matching line must be allowed; format from
    `net/ipv4/tcp_ipv4.c` `get_tcp4_sock` and the IPv6 counterpart). Allowed by default:
    root, the uid of the local `pcscd` user from `/etc/passwd` (only root can create it;
    Ubuntu 26.04's pcsc-lite 2.4.1-1 runs pcscd with `User=pcscd`, uid 990 in the guest)
    and the daemon's own real uid. `--vpcd-peer-uid` replaces that set (numeric). A refused
    peer is closed with nothing sent, reported once per series at the default level, and
    the transport keeps retrying every second. Guest: an impostor listening as uid 65534
    while pcscd was down got four connections in 4.5 s, each closed with 0 bytes; pcscd as
    uid 990 and as root were accepted.
  - macOS has no `/proc`, so the owner is not checked there (reported once at `-v`).
  - A service unit must not use `ProcSubset=pid` (it hides `/proc/net`);
    `ProtectProc=invisible` is fine.
- **Still open**: a `ctl power-cycle` without an interface change leaves the vpcd card in
  the reader (the next APDU gets `6F00`, then the card is powered on again); pcscd's
  `--auto-exit` (Debian packaging) drops the card between clients; vpcd on macOS with a
  real pcscd is untested; the program transports' own APDU/CTAP buffers are not wiped.

