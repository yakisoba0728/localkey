//! `localkeyd run`: the daemon (`docs/PROGRAM.md` "localkeyd").
//!
//! Startup order:
//!
//! 1. open the state directory ([`FileStore::open`]); a lock held by another process fails
//!    fast, naming its pid;
//! 2. load the storage key (`--key-file` or `--key-command`);
//! 3. read or create the serial ([`load_or_create_serial`]) and build the profile with it;
//! 4. spawn the runner, which opens the device on its own thread;
//! 5. if records are unreadable and `--allow-unreadable` is absent: name them, say why it
//!    matters, shut the runner down and exit 3 without binding any socket;
//! 6. bind the control socket, set up the transport (bind the wire socket, or prepare the
//!    UHID or gadget transport), attach it and wait for its first enumeration ([`attach`]);
//!    a failure there exits 2; then serve.
//!
//! Before step 1, `--transport uhid` and `--transport gadget` are refused with exit code 2
//! on any system other than Linux (`docs/PROGRAM.md` "Linux transports": both compile and
//! are tested everywhere, but `localkeyd` refuses to start them elsewhere), and on Linux
//! the gadget configuration is checked as far as reading the file system can
//! ([`gadget_config`]).
//!
//! The daemon then runs until the runner stops, or with `--exit-on-stdin-eof` until stdin
//! reaches EOF. There is no signal handling (std cannot catch signals without `unsafe`):
//! every save is atomic and happens before its response, so a kill loses nothing that was
//! acknowledged, and leftover sockets are replaced at the next start; so is the gadget a
//! killed daemon leaves (`lk_gadget::ConfigFs::leftover`).
//!
//! # As built
//!
//! - The transport (`docs/PROGRAM.md` "lk-wire", "lk-uhid", "lk-gadget"):
//!   - `wire`: `lk_wire::WireTransport` on the wire socket.
//!   - `uhid`: `lk_uhid::UhidTransport` over `lk_uhid::DevUhid` at `--uhid-path`. Nothing
//!     is opened before the runner enumerates; a device file that cannot be opened then
//!     (missing, no permission) is a startup failure ([`attach`]).
//!   - `gadget`: `lk_gadget::GadgetTransport` with `lk_gadget::KernelIo`: gadget and
//!     FunctionFS instance both named `--gadget-name`, ConfigFS root `--configfs`,
//!     FunctionFS mounted at `--ffs-dir`, bound to `--udc`. Both directories are made
//!     absolute against the working directory first ([`std::path::absolute`], which reads
//!     no file): the function's link in `configs/c.1` points into the ConfigFS root, and
//!     configfs resolves a relative link target against the working directory, not the
//!     link (`lk_gadget::ConfigFs::link`). A configuration `lk_gadget` refuses (a
//!     ConfigFS root that is not a directory, a gadget directory that exists and is not
//!     the leftover of an earlier run) is a startup failure found before step 1
//!     ([`gadget_config`], `lk_gadget::GadgetConfig::precheck`, which only reads), so a
//!     bad `--configfs` costs no key command and no device open; `with_io` checks again
//!     in step 6. A failure of the first enumeration (removing an earlier run's
//!     leftover, ConfigFS writes, `mount`, `ep0`, the endpoints, the bind) is a startup
//!     failure too ([`attach`]); the shutdown that follows unmounts FunctionFS and
//!     removes what was created. The leftover of a killed daemon (unbound, nothing in it
//!     that `lk_gadget` does not make) is removed by the first enumeration and logged
//!     (always), so a supervisor can restart a killed daemon.
//!   - The refusal on a system other than Linux uses `cfg!(target_os = "linux")` at run
//!     time, so every transport's code is compiled, and its use checked, on macOS too.
//!     That flag and the kernel interfaces come in a [`Platform`], so tests run the uhid
//!     and gadget paths of `serve` with fakes on any system.
//!   - The control socket is served with every transport: with uhid and gadget it is the
//!     only way a touch reaches the device. `status` shows `attached` from the transport
//!     (`lk_run::Transport::attached`): the wire's client is connected; a UHID device was
//!     created and the kernel runs it; the host has the gadget's function configured.
//! - **First enumeration** ([`attach`], [`StartupCheck`], [`Checked`]): the transport is
//!   attached wrapped in [`Checked`], which collects the failures the transport reports
//!   on the runner thread during its first `enumerate` and hands them to the main
//!   thread once `enumerate` returns. Any such failure, with every transport, exits 2
//!   before the `serving:` line, naming each failure once (in the startup message, not
//!   also in the log). Nothing would retry that enumeration: the device asks for one only
//!   after a Management reboot or a power cycle that changes its interfaces, neither of
//!   which can happen with no device presented, and `ctl power-cycle` and `ctl tap` do
//!   not enumerate. Failures the transport's own threads report are logged as before,
//!   whenever they come, so the outcome does not depend on timing. Not covered: a
//!   `UHID_CREATE2` the kernel refuses (written by the device's writer thread after
//!   `enumerate` returned; `lk_uhid` reports it, the device stays absent) and failures of
//!   later enumerations (logged; the device or gadget stays absent until the next one).
//!   `Status::attached` is no signal here: with uhid it turns true when the device's
//!   writer thread has had `UHID_CREATE2` accepted, after `enumerate` returned; with
//!   gadget only once a host configures the device, which may be much later.
//! - Logging of transport events by level (never report or frame bytes): the wire's
//!   frames, UHID events and gadget control requests and transfers with their sizes at
//!   `-vv`; connections, enumerations, device lifecycle, binds, bus events and refused
//!   host reports at `-v`; failures and the removal of a leftover gadget always. The
//!   `serving:` line names the transport.
//! - The wire and control sockets must be two files: the second bind would replace the
//!   first socket (the placement rules replace a socket), and every `localkeyd ctl` would
//!   then plug a USB host into the device. Before step 1 their spellings are compared;
//!   right after step 1, once the state directory (the default sockets' parent) exists,
//!   so are the files they name: each parent directory resolved (symlinks, `..`, a
//!   relative path) joined with the file name ([`socket_file`]). A parent that cannot be
//!   resolved is left to the bind, which fails on it.
//! - Exit code 2 covers everything that fails before serving: a Linux transport on
//!   another system, the socket paths, the lock, the state directory, the key, the
//!   identity file, OS randomness, opening the device on the runner thread (a panic in
//!   `Device::open`, or no thread), socket placement, a gadget configuration
//!   `lk_gadget` refuses, and a failure of the transport's first enumeration. Exit code 1
//!   is a failure while serving: the runner could not be attached or stopped during that
//!   enumeration, or it stopped on its own (a panic in the device or the entropy source).
//! - Logging never blocks (see `log`); every way out of [`run`] waits at most
//!   [`FLUSH_LIMIT`] for the queued lines to reach stderr.
//! - The main thread registers a presence watcher with the runner. It logs presence
//!   changes at `-v`, and its end (the runner thread dropped it) tells the main thread
//!   that the runner has stopped; the daemon then joins the runner, logs the panic and
//!   exits 1.
//! - Clean shutdown closes the control socket first (no new user commands), then shuts
//!   the runner down, which drops the device and the transport: the wire transport
//!   removes its socket, the UHID transport destroys its devices, the gadget transport
//!   unbinds, unmounts and removes its ConfigFS tree.
//! - The storage key leaves its `SecretBytes` only on the runner thread, as the array
//!   `Device::open` takes; that copy is overwritten once the device has it (best effort:
//!   copies the compiler makes cannot be reached).

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, ThreadId};

use lk_core::{DeviceProfile, Record};
use lk_crypto::SecretBytes;
use lk_device::{Device, Output, UsbIdentity};
use lk_host::{FileStore, HostError, OsEntropy, key_from_command, load_or_create_serial, read_key_file, record_name, to_array};
use lk_gadget::{GadgetConfig, GadgetEvent, GadgetIo, GadgetTransport, KernelIo};
use lk_run::{Command, Runner, RunnerConfig, Transport};
use lk_uhid::{DevUhid, UhidIo, UhidNotice, UhidTransport};
use lk_wire::{ControlServer, WireEvent, WireTransport};

use crate::args::{
    CONTROL_SOCKET, GadgetOptions, KeySource, Profile, RunOptions, TransportKind, TransportOptions, WIRE_SOCKET,
};
use crate::log::{self, FLUSH_LIMIT, Log};
use crate::{EXIT_RUNTIME, EXIT_STARTUP, EXIT_UNREADABLE};

/// How `run` ended, other than cleanly.
#[derive(Debug)]
enum Failure {
    /// Before serving (exit code 2).
    Startup(String),
    /// Unreadable records refused (exit code 3); already explained on stderr.
    Unreadable,
    /// The runner failed (exit code 1).
    Runtime(String),
}

/// What the main thread waits for while the daemon serves.
#[derive(Debug)]
enum Event {
    /// A presence watcher update: whether the device waits for a touch.
    Presence(bool),
    /// The runner thread dropped the watcher: it has stopped.
    RunnerStopped,
    /// stdin reached EOF (`--exit-on-stdin-eof`).
    StdinEof,
}

/// What `serve` takes from the system besides the options: whether it is Linux, and how
/// the Linux transports open the kernel's files (`docs/PROGRAM.md` "Linux transports": the
/// I/O traits). [`Platform::host`] is the real one; tests pass fakes, so they can run the
/// uhid and gadget paths of `serve` on any system without opening a device.
struct Platform {
    linux: bool,
    uhid: OpenUhid,
    gadget: OpenGadget,
}

/// Makes the [`UhidIo`] for a `--uhid-path`.
type OpenUhid = Box<dyn Fn(&Path) -> Box<dyn UhidIo>>;
/// Makes the [`GadgetIo`] of the gadget transport.
type OpenGadget = Box<dyn Fn() -> Box<dyn GadgetIo>>;

impl std::fmt::Debug for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Platform").field("linux", &self.linux).finish_non_exhaustive()
    }
}

impl Platform {
    /// This system: `cfg!(target_os = "linux")`, `lk_uhid::DevUhid`, `lk_gadget::KernelIo`.
    fn host() -> Platform {
        Platform {
            linux: cfg!(target_os = "linux"),
            uhid: Box::new(|path| Box::new(DevUhid::new(path))),
            gadget: Box::new(|| Box::new(KernelIo)),
        }
    }
}

pub fn run(options: &RunOptions) -> ExitCode {
    let log = match Log::start(options.verbosity) {
        Ok(log) => log,
        Err(error) => {
            log::line(format!("cannot start the log thread: {error}"));
            return ExitCode::from(EXIT_STARTUP);
        }
    };
    let code = match serve(options, &log, &Platform::host()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Startup(message)) => {
            log.info(message);
            ExitCode::from(EXIT_STARTUP)
        }
        Err(Failure::Unreadable) => ExitCode::from(EXIT_UNREADABLE),
        Err(Failure::Runtime(message)) => {
            log.info(message);
            ExitCode::from(EXIT_RUNTIME)
        }
    };
    log.flush(FLUSH_LIMIT);
    code
}

fn serve(options: &RunOptions, log: &Log, platform: &Platform) -> Result<(), Failure> {
    let kind = options.transport.kind();
    if kind != TransportKind::Wire && !platform.linux {
        return Err(Failure::Startup(format!(
            "--transport {} runs on Linux only, and this system is {}; use --transport wire",
            kind.name(),
            std::env::consts::OS
        )));
    }
    // What can be checked of the gadget by reading the file system, before the key command
    // runs and the device opens; `GadgetTransport::with_io` checks it again in step 6.
    if let TransportOptions::Gadget(gadget) = &options.transport {
        gadget_config(gadget)?;
    }
    // The state path as `FileStore::open` normalises it (no trailing `/`, no `.`), so the
    // default socket paths read as cleanly as the state path in the log.
    let state: PathBuf = options.state.components().collect();
    let wire_path = match &options.transport {
        TransportOptions::Wire { socket } => Some(wire_socket(socket.as_deref(), &state)),
        TransportOptions::Uhid { .. } | TransportOptions::Gadget(_) => None,
    };
    let control_path = options.control.clone().unwrap_or_else(|| state.join(CONTROL_SOCKET));
    if wire_path.as_ref() == Some(&control_path) {
        return Err(Failure::Startup(format!(
            "the wire and control sockets cannot share the path {}",
            control_path.display()
        )));
    }
    let store = FileStore::open(&state).map_err(|error| match error {
        HostError::Locked { .. } => {
            Failure::Startup(format!("{error}; is another localkeyd running on this state directory?"))
        }
        error => Failure::Startup(format!("state directory: {error}")),
    })?;
    if let Some(wire_path) = &wire_path
        && let (Some(wire), Some(control)) = (socket_file(wire_path), socket_file(&control_path))
        && wire == control
    {
        return Err(Failure::Startup(format!(
            "the wire socket {} and the control socket {} are the same file {}",
            wire_path.display(),
            control_path.display(),
            wire.display()
        )));
    }
    let key = match &options.key {
        KeySource::File(path) => read_key_file(path),
        KeySource::Command(command) => key_from_command(command),
    }
    .map_err(|error| Failure::Startup(format!("storage key: {error}")))?;
    let mut entropy = OsEntropy::open().map_err(|error| Failure::Startup(format!("randomness: {error}")))?;
    let serial = load_or_create_serial(&state, &mut entropy)
        .map_err(|error| Failure::Startup(format!("identity: {error}")))?;
    let profile = match options.profile {
        Profile::Own => DeviceProfile::own(serial),
        Profile::YubiKey5cNano574 => DeviceProfile::yubikey_5c_nano_5_7_4(serial),
    };
    let config = RunnerConfig { wall_clock: options.wall_clock, ..RunnerConfig::default() };
    let runner = Runner::spawn(move || Ok(open_device(profile, store, entropy, key)), config)
        .map_err(|error| Failure::Startup(error.to_string()))?;

    let ready = runner.ready();
    log.info(format!(
        "state {}, serial {}, profile {} ({}), transport {}",
        state.display(),
        ready.serial,
        options.profile.name(),
        ready.identity.product,
        kind.name()
    ));
    if !ready.unreadable.is_empty() {
        if !options.allow_unreadable {
            refuse_unreadable(&state, &ready.unreadable, log);
            if let Err(error) = runner.shutdown() {
                log.info(error);
            }
            return Err(Failure::Unreadable);
        }
        log.info("--allow-unreadable: these applications start from their factory state:");
        list_records(&state, &ready.unreadable, log);
        log.info("the first mutating command of each replaces its record, and what the record held is lost");
    }

    let control = ControlServer::bind(&control_path, runner.sender())
        .map_err(|error| Failure::Startup(format!("control socket: {error}")))?;
    let check = Arc::new(StartupCheck::default());
    let (transport, serving) = transport(&options.transport, &state, &runner, log, &check, platform)?;
    let (events, wait) = mpsc::channel();
    watch_runner(&runner, events.clone())?;
    if let Err(failure) = attach(&runner, transport, &check, kind) {
        control.close();
        // The runner drops the transport on its thread, which undoes what the enumeration
        // did (the gadget unmounts FunctionFS and removes its ConfigFS tree).
        return Err(match (failure, runner.shutdown()) {
            (Failure::Runtime(_), Err(error)) => Failure::Runtime(error.to_string()),
            (failure, Err(error)) => {
                log.info(error);
                failure
            }
            (failure, Ok(())) => failure,
        });
    }
    if options.exit_on_stdin_eof {
        watch_stdin(events).map_err(|error| Failure::Runtime(format!("cannot watch stdin: {error}")))?;
    }
    log.info(format!("serving: {serving}, control socket {}", control_path.display()));

    let mut waiting = false;
    let stdin_eof = loop {
        match wait.recv() {
            Ok(Event::Presence(now)) => {
                if now != waiting {
                    waiting = now;
                    log.verbose(if now { "presence: waiting for a touch" } else { "presence: idle" });
                }
            }
            Ok(Event::StdinEof) => break true,
            Ok(Event::RunnerStopped) | Err(_) => break false,
        }
    };
    if stdin_eof {
        log.info("stdin closed; shutting down");
    }
    control.close();
    match runner.shutdown() {
        Ok(()) if stdin_eof => {
            log.info("stopped");
            Ok(())
        }
        Ok(()) => Err(Failure::Runtime("the runner stopped unexpectedly".into())),
        Err(error) => Err(Failure::Runtime(error.to_string())),
    }
}

/// The wire socket: `--wire`, or [`WIRE_SOCKET`] in the (normalised) state directory.
fn wire_socket(socket: Option<&Path>, state: &Path) -> PathBuf {
    socket.map_or_else(|| state.join(WIRE_SOCKET), Path::to_path_buf)
}

/// Set up the transport the options name, with its observer, and describe it for the
/// `serving:` line. Failures the transport reports while it enumerates the first time go
/// to `check` instead of the log ([`attach`]).
fn transport(
    options: &TransportOptions,
    state: &Path,
    runner: &Runner,
    log: &Log,
    check: &Arc<StartupCheck>,
    platform: &Platform,
) -> Result<(Box<dyn Transport>, String), Failure> {
    match options {
        TransportOptions::Wire { socket } => {
            let path = wire_socket(socket.as_deref(), state);
            let observer = wire_observer(log.clone(), Arc::clone(check));
            let wire = WireTransport::bind_with_observer(&path, runner.sender(), Some(observer))
                .map_err(|error| Failure::Startup(format!("wire socket: {error}")))?;
            Ok((Box::new(wire), format!("wire socket {}", path.display())))
        }
        TransportOptions::Uhid { path } => {
            let uhid = uhid_transport((platform.uhid)(path), runner, log, check);
            Ok((Box::new(uhid), format!("uhid devices through {}", path.display())))
        }
        TransportOptions::Gadget(gadget) => {
            let config = gadget_config(gadget)?;
            let description = format!(
                "gadget {} on UDC {} (ConfigFS {}, FunctionFS {})",
                config.gadget_name,
                config.udc,
                config.configfs_root.join(&config.gadget_name).display(),
                config.mount_point.display()
            );
            let transport = gadget_transport(config, (platform.gadget)(), runner, log, check)?;
            Ok((Box::new(transport), description))
        }
    }
}

/// The UHID transport over `io` (`DevUhid` at `--uhid-path`; a fake in tests).
fn uhid_transport(io: Box<dyn UhidIo>, runner: &Runner, log: &Log, check: &Arc<StartupCheck>) -> UhidTransport {
    UhidTransport::with_observer(io, runner.sender(), Some(uhid_observer(log.clone(), Arc::clone(check))))
}

/// The gadget transport over `io` (`KernelIo`; a fake in tests). `with_io` repeats the
/// checks of [`gadget_config`].
fn gadget_transport(
    config: GadgetConfig,
    io: Box<dyn GadgetIo>,
    runner: &Runner,
    log: &Log,
    check: &Arc<StartupCheck>,
) -> Result<GadgetTransport, Failure> {
    let observer = Some(gadget_observer(log.clone(), Arc::clone(check)));
    GadgetTransport::with_io(config, runner.sender(), io, observer)
        .map_err(|error| Failure::Startup(format!("gadget: {error}")))
}

/// The gadget configuration of the options, checked by `lk_gadget::GadgetConfig::precheck`
/// (names, the ConfigFS root is a directory, the gadget directory is absent or a leftover
/// of an earlier run), which reads the file system and changes nothing. Both directories
/// are made absolute against the working directory first ([`std::path::absolute`], which
/// reads no file; see the module's "As built" notes).
fn gadget_config(options: &GadgetOptions) -> Result<GadgetConfig, Failure> {
    let GadgetOptions { udc, name, configfs, ffs_dir } = options;
    let absolute = |path: &Path| {
        std::path::absolute(path).map_err(|error| Failure::Startup(format!("gadget: {}: {error}", path.display())))
    };
    let config = GadgetConfig {
        configfs_root: absolute(configfs)?,
        gadget_name: name.clone(),
        function_name: name.clone(),
        mount_point: absolute(ffs_dir)?,
        udc: udc.clone(),
    };
    config.precheck().map_err(|error| Failure::Startup(format!("gadget: {error}")))?;
    Ok(config)
}

/// Attach `transport` to the runner and wait until it has enumerated the first time (on
/// the runner thread). A failure it reported meanwhile ([`StartupCheck`]) is a startup
/// failure: nothing would retry that enumeration. The device asks for another only after
/// a Management reboot or a power cycle that changes its interfaces
/// (`Output::Reenumerate`, `crates/lk-device/src/lib.rs`), and neither can happen while
/// the host has no device to talk to; the control socket's `power-cycle` and `tap` do not
/// enumerate. The daemon would keep running with nothing presented.
fn attach(
    runner: &Runner,
    transport: Box<dyn Transport>,
    check: &Arc<StartupCheck>,
    kind: TransportKind,
) -> Result<(), Failure> {
    let (report, first) = mpsc::channel();
    let checked = Checked { inner: transport, check: Arc::clone(check), first: Some(report) };
    runner.serve(Box::new(checked)).map_err(|error| Failure::Runtime(error.to_string()))?;
    let failures =
        first.recv().map_err(|_| Failure::Runtime("the runner stopped while the transport enumerated".into()))?;
    if failures.is_empty() {
        return Ok(());
    }
    Err(Failure::Startup(format!("cannot set up the {} transport: {}", kind.name(), failures.join("; "))))
}

/// The failures a transport reports while it enumerates the first time, on the thread
/// that enumerates (the runner thread, see [`Checked`]). The transport's own threads
/// report through the same observer at any time; a failure of theirs is logged as usual,
/// whenever it comes, so what makes startup fail does not depend on timing.
#[derive(Debug, Default)]
struct StartupCheck {
    window: Mutex<Option<(ThreadId, Vec<String>)>>,
}

impl StartupCheck {
    fn window(&self) -> MutexGuard<'_, Option<(ThreadId, Vec<String>)>> {
        // One assignment or push per update: a panic elsewhere cannot leave it inconsistent.
        self.window.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Start collecting the failures this thread reports.
    fn open(&self) {
        *self.window() = Some((thread::current().id(), Vec::new()));
    }

    /// Keep `reason` if collecting is on and this is the thread that turned it on; false
    /// otherwise, and the caller logs it.
    fn keep(&self, reason: &str) -> bool {
        match self.window().as_mut() {
            Some((owner, failures)) if *owner == thread::current().id() => {
                failures.push(reason.to_owned());
                true
            }
            _ => false,
        }
    }

    /// Stop collecting; the failures kept.
    fn close(&self) -> Vec<String> {
        self.window().take().map(|(_, failures)| failures).unwrap_or_default()
    }
}

/// The transport, with its first enumeration watched by a [`StartupCheck`] and its
/// failures sent to [`attach`]. Everything else passes straight through.
#[derive(Debug)]
struct Checked {
    inner: Box<dyn Transport>,
    check: Arc<StartupCheck>,
    /// Until the first enumeration: where its failures go.
    first: Option<Sender<Vec<String>>>,
}

impl Transport for Checked {
    fn enumerate(&mut self, identity: &UsbIdentity) {
        let Some(report) = self.first.take() else {
            self.inner.enumerate(identity);
            return;
        };
        self.check.open();
        self.inner.enumerate(identity);
        // A panic in `enumerate` drops `report`, which `attach` sees as the runner ending.
        let _ = report.send(self.check.close());
    }

    fn deliver(&mut self, output: Output) {
        self.inner.deliver(output);
    }

    fn attached(&self) -> Option<bool> {
        self.inner.attached()
    }
}

/// Open the device on the runner thread (see the module's "As built" notes for the key).
fn open_device(profile: DeviceProfile, store: FileStore, entropy: OsEntropy, key: SecretBytes) -> Device {
    let mut storage_key = to_array(&key);
    drop(key);
    let device = Device::open(profile, Box::new(store), Box::new(entropy), storage_key);
    storage_key.fill(0);
    std::hint::black_box(&storage_key);
    device
}

/// Explain why the daemon refuses to start (`docs/PROGRAM.md` "localkeyd", startup order;
/// `docs/CONTRACTS.md` "Program duties": an application's first mutating command
/// replaces an unreadable record).
fn refuse_unreadable(state: &Path, unreadable: &[Record], log: &Log) {
    log.info(format!(
        "{} record(s) cannot be read, or cannot be opened with this storage key:",
        unreadable.len()
    ));
    list_records(state, unreadable, log);
    log.info(
        "refusing to start: each of these applications would run from its factory state, and its first \
         mutating command would replace the record, losing what it held for good",
    );
    log.info("if the key is wrong, start again with the right one; to start anyway, pass --allow-unreadable");
}

fn list_records(state: &Path, records: &[Record], log: &Log) {
    for &record in records {
        let file = state.join(format!("{}.rec", record_name(record)));
        log.info(format!("  {} ({})", file.display(), application(record)));
    }
}

/// The application whose state a record holds.
fn application(record: Record) -> &'static str {
    match record {
        Record::Device => "device configuration",
        Record::Fido => "FIDO",
        Record::Oath => "OATH",
        Record::Otp => "OTP",
        Record::Piv => "PIV",
        Record::OpenPgp => "OpenPGP",
        Record::HsmAuth => "YubiHSM Auth",
        Record::SecurityDomain => "Security Domain",
    }
}

/// Log wire events by level: frames at `-vv`, connections and enumerations at `-v`,
/// malformed frames and transport failures always (a failure of the first enumeration
/// goes to `check`).
fn wire_observer(log: Log, check: Arc<StartupCheck>) -> lk_wire::Observer {
    Arc::new(move |event: &WireEvent| match event {
        WireEvent::Received { .. } | WireEvent::Sent { .. } => log.trace(event),
        WireEvent::Connected | WireEvent::Refused | WireEvent::Disconnected | WireEvent::Enumerated { .. } => {
            log.verbose(event)
        }
        WireEvent::Failed(reason) if check.keep(reason) => {}
        WireEvent::Malformed(_) | WireEvent::Failed(_) => log.info(event),
    })
}

/// Log UHID notices by level: events in and out with their sizes at `-vv`; enumeration,
/// device lifecycle and refused host reports at `-v` (a refused report is the host's
/// mistake, and one per report); a device the kernel does not run, a file that ended and
/// failures always (a failure of the first enumeration goes to `check`). No notice
/// carries report bytes (`lk_uhid::UhidNotice`).
fn uhid_observer(log: Log, check: Arc<StartupCheck>) -> lk_uhid::Observer {
    Arc::new(move |notice: &UhidNotice| match notice {
        UhidNotice::Received { .. } | UhidNotice::Sent { .. } => log.trace(notice),
        UhidNotice::Enumerated { .. }
        | UhidNotice::Created { .. }
        | UhidNotice::Destroyed { .. }
        | UhidNotice::Started { .. }
        | UhidNotice::Stopped { .. }
        | UhidNotice::Opened { .. }
        | UhidNotice::Closed { .. }
        | UhidNotice::Refused { .. } => log.verbose(notice),
        UhidNotice::Failed(reason) if check.keep(reason) => {}
        UhidNotice::NotRunning { .. } | UhidNotice::Ended { .. } | UhidNotice::Failed(_) => log.info(notice),
    })
}

/// Log gadget events by level: control requests and transfers with their sizes at `-vv`;
/// enumeration, binds, bus events and dropped data at `-v`; the removal of an earlier
/// run's leftover gadget and failures always (a failure of the first enumeration goes to
/// `check`). No event carries payload bytes (`lk_gadget::GadgetEvent`).
fn gadget_observer(log: Log, check: Arc<StartupCheck>) -> lk_gadget::Observer {
    Arc::new(move |event: &GadgetEvent| match event {
        GadgetEvent::Setup { .. } | GadgetEvent::Received { .. } | GadgetEvent::Sent { .. } => log.trace(event),
        GadgetEvent::Enumerated { .. }
        | GadgetEvent::Bound { .. }
        | GadgetEvent::Unbound
        | GadgetEvent::Bus(_)
        | GadgetEvent::Dropped { .. } => log.verbose(event),
        GadgetEvent::Failed(reason) if check.keep(reason) => {}
        GadgetEvent::Reclaimed { .. } | GadgetEvent::Failed(_) => log.info(event),
    })
}

/// The file a socket path names: its parent directory resolved (symlinks, `..`, a relative
/// path) joined with its file name. `None` when the path has no file name or its parent
/// cannot be resolved (it does not exist, for example).
///
/// The socket file itself may not exist yet, so the path as a whole cannot be resolved. A
/// symbolic link at the socket path cannot alias another socket either: the placement
/// rules refuse anything at the path that is not a socket.
fn socket_file(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?;
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    Some(parent.canonicalize().ok()?.join(name))
}

/// Register a presence watcher and forward its updates as [`Event::Presence`]; when the
/// runner drops it, send [`Event::RunnerStopped`].
fn watch_runner(runner: &Runner, events: Sender<Event>) -> Result<(), Failure> {
    let (watcher, presence) = mpsc::channel();
    runner
        .sender()
        .send(Command::Watch(watcher))
        .map_err(|_| Failure::Runtime("the runner stopped before serving".into()))?;
    thread::Builder::new()
        .name("presence".into())
        .spawn(move || {
            for waiting in presence {
                if events.send(Event::Presence(waiting)).is_err() {
                    return;
                }
            }
            let _ = events.send(Event::RunnerStopped);
        })
        .map_err(|error| Failure::Runtime(format!("cannot watch the runner: {error}")))?;
    Ok(())
}

/// Read stdin to its end, then send [`Event::StdinEof`]. A read error counts as the end.
fn watch_stdin(events: Sender<Event>) -> io::Result<()> {
    thread::Builder::new().name("stdin".into()).spawn(move || {
        let mut stdin = io::stdin().lock();
        let mut discard = [0; 512];
        loop {
            match stdin.read(&mut discard) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        let _ = events.send(Event::StdinEof);
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use lk_device::BusEvent;
    use lk_gadget::{Ep0File, Role};
    use lk_host::{generate_key, write_key_file};
    use lk_run::{HostInput, TAP_SHORT_MS};
    use lk_uhid::event::{UHID_CREATE2, UHID_EVENT_SIZE};
    use lk_uhid::{HidInterface, UhidHalves};

    use crate::log::{TRACE, VERBOSE};

    /// The lines `observe` logs at each verbosity: default, `-v`, `-vv`.
    fn by_level(observe: impl Fn(&Log)) -> [Vec<String>; 3] {
        [0, VERBOSE, TRACE].map(|verbosity| {
            let log = Log::unwritten(verbosity);
            observe(&log);
            log.take_lines()
        })
    }

    #[test]
    fn uhid_notices_are_logged_by_level() {
        let notices = [
            UhidNotice::Received { interface: HidInterface::Fido, event: "OUTPUT", size: 64 },
            UhidNotice::Created { interface: HidInterface::Otp, product_id: 0x0407 },
            UhidNotice::Refused { interface: HidInterface::Fido, event: "OUTPUT", size: 3, reason: "wrong size" },
            UhidNotice::Failed("otp: cannot open a UHID device".into()),
        ];
        let [default, verbose, trace] = by_level(|log| {
            let observer = uhid_observer(log.clone(), Arc::default());
            for notice in &notices {
                observer(notice);
            }
        });
        let text = |notice: &UhidNotice| notice.to_string();
        assert_eq!(default, [text(&notices[3])], "failures always");
        assert_eq!(verbose, [text(&notices[1]), text(&notices[2]), text(&notices[3])], "lifecycle at -v");
        assert_eq!(trace, notices.iter().map(text).collect::<Vec<_>>(), "events and sizes at -vv");
    }

    #[test]
    fn gadget_events_are_logged_by_level() {
        let events = [
            GadgetEvent::Setup { request_type: 0x21, request: 0x0A, value: 0, index: 1, length: 0, outcome: "ack" },
            GadgetEvent::Sent { endpoint: Role::FidoIn, size: 64 },
            GadgetEvent::Bound { udc: "dummy_udc.0".into() },
            GadgetEvent::Bus(BusEvent::Reset),
            GadgetEvent::Failed("mount /dev/ffs-localkey: permission denied".into()),
        ];
        let [default, verbose, trace] = by_level(|log| {
            let observer = gadget_observer(log.clone(), Arc::default());
            for event in &events {
                observer(event);
            }
        });
        let text = |event: &GadgetEvent| event.to_string();
        assert_eq!(default, [text(&events[4])], "failures always");
        assert_eq!(verbose, [text(&events[2]), text(&events[3]), text(&events[4])], "binds and bus events at -v");
        assert_eq!(trace, events.iter().map(text).collect::<Vec<_>>(), "requests and transfers at -vv");
    }

    #[test]
    fn the_wire_socket_defaults_to_the_state_directory() {
        let state = Path::new("/s");
        assert_eq!(wire_socket(None, state), PathBuf::from("/s/wire.sock"));
        assert_eq!(wire_socket(Some(Path::new("/w")), state), PathBuf::from("/w"));
    }

    /// How long a test waits for something that must happen (generous: a loaded machine).
    const WAIT: Duration = Duration::from_secs(30);

    /// A fresh directory under the temporary directory with a short name, removed on drop.
    #[derive(Debug)]
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> TempDir {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let n = NEXT.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!("lkdr{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).expect("the test directory can be created");
            TempDir(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A runner with the `own` profile (FIDO and OTP HID, CCID) on a new state directory,
    /// as `serve` builds it.
    fn runner(state: &Path) -> Runner {
        let store = FileStore::open(state).expect("the state directory can be opened");
        let mut entropy = OsEntropy::open().expect("OS randomness is available");
        let key = generate_key(&mut entropy);
        let profile = DeviceProfile::own(12_345_678);
        Runner::spawn(move || Ok(open_device(profile, store, entropy, key)), RunnerConfig::default())
            .expect("the runner starts")
    }

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(PoisonError::into_inner)
    }

    #[test]
    fn the_startup_check_keeps_only_failures_of_the_enumerating_thread_while_it_enumerates() {
        let check = StartupCheck::default();
        assert!(!check.keep("before"), "not collecting yet");
        check.open();
        let elsewhere =
            thread::scope(|scope| scope.spawn(|| check.keep("elsewhere")).join().expect("the thread runs"));
        assert!(!elsewhere, "another thread's failure is logged instead");
        assert!(check.keep("here"));
        assert_eq!(check.close(), ["here"]);
        assert!(!check.keep("after"), "collecting ended");
        assert!(check.close().is_empty());
    }

    /// `docs/PROGRAM.md` "localkeyd", exit codes: "2 startup failure (usage, lock, key,
    /// permissions)". A `--uhid-path` that cannot be opened (no `/dev/uhid`, or no
    /// permission for it: the usual case for a user who is not root) is one: the daemon
    /// stops before `serving:` instead of running with no device presented. (Found by
    /// review: the open happens in the runner's first enumeration, after `serve` had
    /// attached the transport.)
    #[test]
    fn a_uhid_path_that_cannot_be_opened_is_a_startup_failure() {
        let dir = TempDir::new();
        let state = dir.join("s");
        let runner = runner(&state);
        let log = Log::unwritten(TRACE);
        let check = Arc::new(StartupCheck::default());
        let missing = dir.join("no-uhid");
        let options = TransportOptions::Uhid { path: missing.clone() };
        let (uhid, serving) = transport(&options, &state, &runner, &log, &check, &Platform::host())
            .expect("nothing is opened before the enumeration");
        assert_eq!(serving, format!("uhid devices through {}", missing.display()));
        let attached = attach(&runner, uhid, &check, TransportKind::Uhid);
        let stopped = runner.shutdown();
        let Err(Failure::Startup(message)) = attached else {
            panic!("{} cannot be opened, yet attaching gave {attached:?}", missing.display());
        };
        assert!(message.starts_with("cannot set up the uhid transport: "), "{message}");
        for interface in ["fido", "otp"] {
            let expected = format!("{interface}: cannot open a UHID device: cannot open {}", missing.display());
            assert!(message.contains(&expected), "{expected} in {message}");
        }
        let lines = log.take_lines();
        assert!(!lines.iter().any(|line| line.contains("cannot open")), "said once, in the message: {lines:#?}");
        assert!(stopped.is_ok(), "{stopped:?}");
    }

    /// Why a failed first enumeration must end the startup: nothing retries it. The
    /// control socket's `power-cycle` and `tap` (the only inputs a user has without a
    /// presented device) do not enumerate; the device asks for an enumeration only after
    /// a Management reboot or a power cycle that changes its interfaces
    /// (`crates/lk-device/src/lib.rs`), and neither can happen with no device presented.
    /// (Kept from the review that found it; it builds the transport without `attach`.)
    #[test]
    fn a_failed_first_uhid_enumeration_is_not_retried_by_a_power_cycle_or_a_tap() {
        let dir = TempDir::new();
        let state = dir.join("s");
        let runner = runner(&state);
        let notices: Arc<Mutex<Vec<String>>> = Arc::default();
        let seen = Arc::clone(&notices);
        let observer: lk_uhid::Observer = Arc::new(move |notice: &UhidNotice| lock(&seen).push(notice.to_string()));
        let io = Box::new(DevUhid::new(dir.join("no-uhid")));
        let uhid = UhidTransport::with_observer(io, runner.sender(), Some(observer));
        runner.serve(Box::new(uhid)).expect("the runner takes the transport");
        // What `localkeyd ctl power-cycle` and `localkeyd ctl tap` send (lk-wire control).
        let sender = runner.sender();
        sender.send(Command::Input(HostInput::Bus(BusEvent::PowerCycle))).expect("the runner is running");
        sender.send(Command::Tap { hold_ms: TAP_SHORT_MS }).expect("the runner is running");
        // The runner handles commands in order: once this answers, everything above is done.
        let status = runner.status().expect("the runner answers");
        let stopped = runner.shutdown();
        let notices = lock(&notices).clone();
        let enumerations = notices.iter().filter(|line| line.contains("enumerat")).count();
        let failures = notices.iter().filter(|line| line.contains("cannot open")).count();
        assert_eq!(status.attached, Some(false), "no device is presented");
        assert_eq!(enumerations, 1, "only the attach enumerated: {notices:#?}");
        assert_eq!(failures, 2, "one failed open per HID interface, never retried: {notices:#?}");
        assert!(stopped.is_ok(), "{stopped:?}");
    }

    /// A fake `/dev/uhid`: every open is a socket pair whose other half the test keeps, to
    /// play the kernel.
    #[derive(Debug, Default)]
    struct PairUhid {
        kernel: Arc<Mutex<Vec<UnixStream>>>,
    }

    impl UhidIo for PairUhid {
        fn open(&mut self) -> io::Result<UhidHalves> {
            let (ours, kernel) = UnixStream::pair()?;
            lock(&self.kernel).push(kernel);
            Ok((Box::new(ours.try_clone()?), Box::new(ours)))
        }
    }

    #[test]
    fn a_uhid_transport_whose_devices_open_passes_the_startup_check() {
        let dir = TempDir::new();
        let state = dir.join("s");
        let runner = runner(&state);
        let log = Log::unwritten(TRACE);
        let check = Arc::new(StartupCheck::default());
        let kernel: Arc<Mutex<Vec<UnixStream>>> = Arc::default();
        let uhid = uhid_transport(Box::new(PairUhid { kernel: Arc::clone(&kernel) }), &runner, &log, &check);
        let attached = attach(&runner, Box::new(uhid), &check, TransportKind::Uhid);
        assert!(attached.is_ok(), "{attached:?}");
        let mut halves = std::mem::take(&mut *lock(&kernel));
        assert_eq!(halves.len(), 2, "one device per HID interface");
        for half in &mut halves {
            half.set_read_timeout(Some(WAIT)).expect("a timeout can be set");
            let mut event = vec![0; UHID_EVENT_SIZE];
            half.read_exact(&mut event).expect("the kernel side gets an event");
            let kind = u32::from_ne_bytes([event[0], event[1], event[2], event[3]]);
            assert_eq!(kind, UHID_CREATE2, "each device is created first");
        }
        assert!(runner.status().expect("the runner answers").serving);
        // The kernel goes away: the readers end, and the shutdown does not wait for them.
        drop(halves);
        let stopped = runner.shutdown();
        assert!(stopped.is_ok(), "{stopped:?}");
        let lines = log.take_lines();
        assert!(!lines.iter().any(|line| line.contains("cannot open")), "{lines:#?}");
    }

    /// A fake gadget kernel: `mount` works, `ep0` cannot be opened (no FunctionFS there).
    /// It records what it was asked to do.
    #[derive(Debug, Default, Clone)]
    struct NoEp0 {
        calls: Arc<Mutex<Vec<&'static str>>>,
    }

    impl NoEp0 {
        fn record(&self, call: &'static str) {
            lock(&self.calls).push(call);
        }
    }

    impl GadgetIo for NoEp0 {
        fn mount(&mut self, _instance: &str, _mount_point: &Path) -> io::Result<()> {
            self.record("mount");
            Ok(())
        }

        fn unmount(&mut self, _mount_point: &Path) -> io::Result<()> {
            self.record("umount");
            Ok(())
        }

        fn functionfs_mounts(&mut self, _instance: &str) -> io::Result<Vec<PathBuf>> {
            Ok(Vec::new())
        }

        fn open_ep0(&mut self, _mount_point: &Path) -> io::Result<Box<dyn Ep0File>> {
            self.record("open ep0");
            Err(io::Error::from(io::ErrorKind::NotFound))
        }

        fn open_out(&mut self, _mount_point: &Path, _index: usize) -> io::Result<Box<dyn Read + Send>> {
            self.record("open out");
            Err(io::Error::from(io::ErrorKind::NotFound))
        }

        fn open_in(&mut self, _mount_point: &Path, _index: usize) -> io::Result<Box<dyn io::Write + Send>> {
            self.record("open in");
            Err(io::Error::from(io::ErrorKind::NotFound))
        }

        fn bind(&mut self, _udc_file: &Path, _udc: &str) -> io::Result<()> {
            self.record("bind");
            Err(io::Error::from(io::ErrorKind::NotFound))
        }

        fn unbind(&mut self, _udc_file: &Path) -> io::Result<()> {
            self.record("unbind");
            Ok(())
        }
    }

    fn gadget_options(dir: &TempDir) -> GadgetOptions {
        GadgetOptions {
            udc: "dummy_udc.0".into(),
            name: "lkd".into(),
            configfs: dir.join("cfg"),
            ffs_dir: dir.join("ffs"),
        }
    }

    #[test]
    fn a_gadget_whose_ep0_cannot_be_opened_is_a_startup_failure_and_is_taken_down() {
        let dir = TempDir::new();
        fs::create_dir(dir.join("cfg")).expect("the ConfigFS root can be created");
        let state = dir.join("s");
        let runner = runner(&state);
        let log = Log::unwritten(TRACE);
        let check = Arc::new(StartupCheck::default());
        let config = gadget_config(&gadget_options(&dir)).expect("the configuration passes the precheck");
        let kernel = NoEp0::default();
        let gadget = gadget_transport(config, Box::new(kernel.clone()), &runner, &log, &check).expect("valid");
        let attached = attach(&runner, Box::new(gadget), &check, TransportKind::Gadget);
        let stopped = runner.shutdown();
        let Err(Failure::Startup(message)) = attached else {
            panic!("ep0 cannot be opened, yet attaching gave {attached:?}");
        };
        assert!(message.starts_with("cannot set up the gadget transport: open ep0: "), "{message}");
        let calls = lock(&kernel.calls).clone();
        assert_eq!(calls.first(), Some(&"mount"), "{calls:?}");
        assert_eq!(calls.last(), Some(&"umount"), "the shutdown unmounted FunctionFS again: {calls:?}");
        assert!(!calls.contains(&"bind"), "{calls:?}");
        assert!(stopped.is_ok(), "{stopped:?}");
    }

    #[test]
    fn the_gadget_configuration_is_checked_without_changing_anything() {
        let dir = TempDir::new();
        let missing = gadget_config(&gadget_options(&dir)).err();
        let Some(Failure::Startup(message)) = missing else {
            panic!("a missing ConfigFS root is refused: {missing:?}");
        };
        assert!(message.starts_with("gadget: ") && message.contains("cfg"), "{message}");
        fs::create_dir_all(dir.join("cfg/lkd/functions/hid.usb0")).expect("another gadget can be planted");
        let foreign = gadget_config(&gadget_options(&dir)).err();
        let Some(Failure::Startup(message)) = foreign else {
            panic!("another gadget under the name is refused: {foreign:?}");
        };
        assert!(message.contains("is not a leftover"), "{message}");
        assert!(dir.join("cfg/lkd/functions/hid.usb0").is_dir(), "left alone");
        fs::remove_dir(dir.join("cfg/lkd/functions/hid.usb0")).expect("the planted function can be removed");
        let config = gadget_config(&gadget_options(&dir)).expect("an earlier run's leftover passes");
        assert!(config.configfs_root.is_absolute() && config.mount_point.is_absolute());
        assert_eq!((config.gadget_name.as_str(), config.function_name.as_str()), ("lkd", "lkd"));
        assert!(dir.join("cfg/lkd/functions").is_dir(), "the leftover is removed by the first enumeration only");
        assert!(!dir.join("ffs").exists(), "nothing is mounted or created");
    }

    /// A Linux platform whose kernel interfaces are `uhid` and `gadget`.
    fn linux(
        uhid: impl Fn() -> Box<dyn UhidIo> + 'static,
        gadget: impl Fn() -> Box<dyn GadgetIo> + 'static,
    ) -> Platform {
        Platform { linux: true, uhid: Box::new(move |_| uhid()), gadget: Box::new(gadget) }
    }

    /// `run` options on state directory `dir/s` with a new key file `dir/key`, the control
    /// socket in the state directory, and `transport`.
    fn run_options(dir: &TempDir, transport: TransportOptions) -> RunOptions {
        let key = dir.join("key");
        let mut entropy = OsEntropy::open().expect("OS randomness is available");
        write_key_file(&key, &generate_key(&mut entropy)).expect("the key file can be written");
        RunOptions {
            state: dir.join("s"),
            key: KeySource::File(key),
            profile: Profile::Own,
            transport,
            control: None,
            wall_clock: false,
            allow_unreadable: false,
            exit_on_stdin_eof: false,
            verbosity: TRACE,
        }
    }

    /// The whole `serve` with `--transport uhid` on a path that cannot be opened: exit 2
    /// before `serving:`, with the control socket removed again.
    #[test]
    fn serving_uhid_on_a_path_that_cannot_be_opened_stops_before_serving_and_removes_the_control_socket() {
        let dir = TempDir::new();
        let missing = dir.join("no-uhid");
        let options = run_options(&dir, TransportOptions::Uhid { path: missing.clone() });
        let log = Log::unwritten(TRACE);
        let host = Platform::host();
        let platform = linux(move || (host.uhid)(&missing), || Box::new(NoEp0::default()));
        let served = serve(&options, &log, &platform);
        let Err(Failure::Startup(message)) = served else {
            panic!("serving gave {served:?}");
        };
        assert!(message.starts_with("cannot set up the uhid transport: "), "{message}");
        let lines = log.take_lines();
        assert!(lines.iter().any(|line| line.contains("transport uhid")), "the startup line: {lines:#?}");
        assert!(!lines.iter().any(|line| line.starts_with("serving:")), "{lines:#?}");
        assert!(!dir.join("s").join(CONTROL_SOCKET).exists(), "the control socket was removed");
    }

    #[test]
    fn serving_a_gadget_whose_ep0_cannot_be_opened_stops_before_serving_and_unmounts_again() {
        let dir = TempDir::new();
        fs::create_dir(dir.join("cfg")).expect("the ConfigFS root can be created");
        let options = run_options(&dir, TransportOptions::Gadget(gadget_options(&dir)));
        let log = Log::unwritten(TRACE);
        let kernel = NoEp0::default();
        let opened = kernel.clone();
        let platform = linux(|| Box::new(PairUhid::default()), move || Box::new(opened.clone()));
        let served = serve(&options, &log, &platform);
        let Err(Failure::Startup(message)) = served else {
            panic!("serving gave {served:?}");
        };
        assert!(message.starts_with("cannot set up the gadget transport: open ep0: "), "{message}");
        assert_eq!(lock(&kernel.calls).last(), Some(&"umount"), "the shutdown unmounted FunctionFS again");
        let lines = log.take_lines();
        assert!(!lines.iter().any(|line| line.starts_with("serving:")), "{lines:#?}");
        assert!(!dir.join("s").join(CONTROL_SOCKET).exists(), "the control socket was removed");
    }

    /// A gadget configuration `lk_gadget` refuses is found before the state directory is
    /// opened and the key loaded (a key command may prompt; a supervisor restarts).
    #[test]
    fn a_refused_gadget_configuration_stops_serve_before_the_state_directory_and_the_key() {
        let dir = TempDir::new();
        fs::create_dir_all(dir.join("cfg/lkd/functions/hid.usb0")).expect("another gadget can be planted");
        let mut options = run_options(&dir, TransportOptions::Gadget(gadget_options(&dir)));
        options.key = KeySource::Command("exit 1".into());
        let log = Log::unwritten(TRACE);
        let kernel = NoEp0::default();
        let opened = kernel.clone();
        let platform = linux(|| Box::new(PairUhid::default()), move || Box::new(opened.clone()));
        let served = serve(&options, &log, &platform);
        let Err(Failure::Startup(message)) = served else {
            panic!("serving gave {served:?}");
        };
        assert!(message.starts_with("gadget: ") && message.contains("is not a leftover"), "{message}");
        assert!(!dir.join("s").exists(), "the state directory was not created");
        assert!(lock(&kernel.calls).is_empty(), "the kernel was not asked for anything");
    }
}
