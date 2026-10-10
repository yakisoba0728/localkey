# Program phase contract

The engine (`docs/DESIGN.md`, `docs/CONTRACTS.md`) is a pure state machine. This file fixes
the program around it: the crates that give the engine storage, randomness, a clock, a run
loop and transports. It is binding for the program crates the way `docs/CONTRACTS.md` is
binding for the engine crates. Where a later "as built" section refines an earlier one, the
later section wins.

## Scope and boundary

In scope now:

- `lk-host`: file storage, OS randomness, the storage key, the state directory;
- `lk-run`: the run loop that owns the `Device`;
- `lk-wire`: a private Unix-socket transport and the control socket;
- `localkeyd`: the daemon binary.

Later, as a separate step: Linux transports (UHID; FunctionFS/ConfigFS composite gadget).

Out of scope until the user widens the safety boundary:

- macOS virtual HID/USB (IOHIDUserDevice, IOUSBHost need Apple entitlements, signing and FFI);
- talking to the OS keychain from our code or tests;
- anything that touches the host's USB/HID/PCSC stack, keyboard, kernel, or the physical
  YubiKey.

The wire transport is the only transport that can be exercised end to end here. It carries the
full `Input`/`Output` set, so a bridge process (for example a gadget relay inside a guest)
can sit on the other side later.

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
  fit in 104 bytes on macOS) and remove them at the end. No network.
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
localkeyd run --state DIR (--key-file PATH | --key-command CMD)
              [--profile own|yubikey-5c-nano-5.7.4] [--wire PATH] [--control PATH]
              [--wall-clock] [--allow-unreadable] [--exit-on-stdin-eof] [-v | -vv]
localkeyd ctl --control PATH (tap [long] | down | up | power-cycle | status | watch)
```

- `run` defaults: `--profile own`, `--wire <state>/wire.sock`, `--control
  <state>/control.sock`.
- Startup order: open `FileStore` (fails fast with exit code 2 and the pid if locked), load
  the key, `load_or_create_serial`, spawn the runner. If `Ready` lists unreadable records and
  `--allow-unreadable` is absent, print which records and why it matters (the first mutating
  command of that application replaces the record), shut the runner down and exit with code
  3 without binding any socket. Then bind the control socket and the wire socket and serve.
- Exit codes: 0 clean, 1 runtime failure, 2 startup failure (usage, lock, key, permissions),
  3 unreadable records refused.
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

Two transport crates for Linux. Neither can be exercised against a real kernel here: the
Docker Desktop VM kernel has no `UHID`, no `DUMMY_HCD` and no USB gadget support, and there
is no other Linux guest. They are therefore built as byte-level logic over generic I/O,
tested on macOS with fakes (temporary files, FIFOs, socket pairs), and reported as
**unverified on a real kernel** until a Linux guest is available.

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
  for interface behaviour only). Until a real kernel confirms it, accept FIDO output of 65
  bytes with a leading `00` (strip it) or exactly 64 bytes; accept OTP feature SET_REPORT
  data of 9 bytes with a leading `00` or exactly 8; answer GET_REPORT(feature) in the form
  the kernel copies back to a hidraw caller (report number, then the 8 bytes, if that is
  what the source shows). Record the conclusion and its source in the crate docs.
- FIDO input reports go out as `UHID_INPUT2` with 64 bytes; OTP keyboard reports as
  `UHID_INPUT2` with 8 bytes.
- Re-enumeration destroys the devices and creates the ones the new identity enables.
- Bus events: creating the devices is a plug-in (`BusEvent::PowerCycle`); UHID has no
  suspend, resume or reset.
- The device path defaults to `/dev/uhid` and is a parameter (tests pass a fake).

### lk-gadget (ConfigFS + FunctionFS composite gadget)

The faithful transport: one USB device with exactly the engine's descriptors (OTP keyboard,
FIDO HID and CCID interfaces), for a Linux machine with a USB device controller (a board
plugged into a computer, or `dummy_hcd` in a test guest). It needs root.

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
