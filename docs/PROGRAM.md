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
