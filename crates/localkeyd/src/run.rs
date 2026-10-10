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
//! 6. bind the control socket, bind the wire socket, and serve.
//!
//! The daemon then runs until the runner stops, or with `--exit-on-stdin-eof` until stdin
//! reaches EOF. There is no signal handling (std cannot catch signals without `unsafe`):
//! every save is atomic and happens before its response, so a kill loses nothing that was
//! acknowledged, and leftover sockets are replaced at the next start.
//!
//! # As built
//!
//! - The wire and control sockets must be two files: the second bind would replace the
//!   first socket (the placement rules replace a socket), and every `localkeyd ctl` would
//!   then plug a USB host into the device. Before step 1 their spellings are compared;
//!   right after step 1, once the state directory (the default sockets' parent) exists,
//!   so are the files they name: each parent directory resolved (symlinks, `..`, a
//!   relative path) joined with the file name ([`socket_file`]). A parent that cannot be
//!   resolved is left to the bind, which fails on it.
//! - Exit code 2 covers everything that fails before serving: the socket paths, the lock,
//!   the state directory, the key, the identity file, OS randomness, opening the device
//!   on the runner thread (a panic in `Device::open`, or no thread), and socket
//!   placement. Exit code 1 is a failure while serving: the runner could not be attached,
//!   or it stopped on its own (a panic in the device or the entropy source).
//! - Logging never blocks (see `log`); every way out of [`run`] waits at most
//!   [`FLUSH_LIMIT`] for the queued lines to reach stderr.
//! - The main thread registers a presence watcher with the runner. It logs presence
//!   changes at `-v`, and its end (the runner thread dropped it) tells the main thread
//!   that the runner has stopped; the daemon then joins the runner, logs the panic and
//!   exits 1.
//! - Clean shutdown closes the control socket first (no new user commands), then shuts
//!   the runner down, which drops the device and the wire transport; the transport
//!   removes its socket.
//! - The storage key leaves its `SecretBytes` only on the runner thread, as the array
//!   `Device::open` takes; that copy is overwritten once the device has it (best effort:
//!   copies the compiler makes cannot be reached).

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::mpsc::{self, Sender};
use std::thread;

use lk_core::{DeviceProfile, Record};
use lk_crypto::SecretBytes;
use lk_device::Device;
use lk_host::{FileStore, HostError, OsEntropy, key_from_command, load_or_create_serial, read_key_file, record_name, to_array};
use lk_run::{Command, Runner, RunnerConfig};
use lk_wire::{ControlServer, Observer, WireEvent, WireTransport};

use crate::args::{CONTROL_SOCKET, KeySource, Profile, RunOptions, WIRE_SOCKET};
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

pub fn run(options: &RunOptions) -> ExitCode {
    let log = match Log::start(options.verbosity) {
        Ok(log) => log,
        Err(error) => {
            log::line(format!("cannot start the log thread: {error}"));
            return ExitCode::from(EXIT_STARTUP);
        }
    };
    let code = match serve(options, &log) {
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

fn serve(options: &RunOptions, log: &Log) -> Result<(), Failure> {
    // The state path as `FileStore::open` normalises it (no trailing `/`, no `.`), so the
    // default socket paths read as cleanly as the state path in the log.
    let state: PathBuf = options.state.components().collect();
    let wire_path = options.wire.clone().unwrap_or_else(|| state.join(WIRE_SOCKET));
    let control_path = options.control.clone().unwrap_or_else(|| state.join(CONTROL_SOCKET));
    if wire_path == control_path {
        return Err(Failure::Startup(format!(
            "the wire and control sockets cannot share the path {}",
            wire_path.display()
        )));
    }
    let store = FileStore::open(&state).map_err(|error| match error {
        HostError::Locked { .. } => {
            Failure::Startup(format!("{error}; is another localkeyd running on this state directory?"))
        }
        error => Failure::Startup(format!("state directory: {error}")),
    })?;
    if let (Some(wire), Some(control)) = (socket_file(&wire_path), socket_file(&control_path))
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
        "state {}, serial {}, profile {} ({})",
        state.display(),
        ready.serial,
        options.profile.name(),
        ready.identity.product
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
    let wire = WireTransport::bind_with_observer(&wire_path, runner.sender(), Some(wire_observer(log.clone())))
        .map_err(|error| Failure::Startup(format!("wire socket: {error}")))?;
    let (events, wait) = mpsc::channel();
    watch_runner(&runner, events.clone())?;
    runner.serve(Box::new(wire)).map_err(|error| Failure::Runtime(error.to_string()))?;
    if options.exit_on_stdin_eof {
        watch_stdin(events).map_err(|error| Failure::Runtime(format!("cannot watch stdin: {error}")))?;
    }
    log.info(format!("serving: wire socket {}, control socket {}", wire_path.display(), control_path.display()));

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
/// malformed frames and transport failures always.
fn wire_observer(log: Log) -> Observer {
    Arc::new(move |event: &WireEvent| match event {
        WireEvent::Received { .. } | WireEvent::Sent { .. } => log.trace(event),
        WireEvent::Connected | WireEvent::Refused | WireEvent::Disconnected | WireEvent::Enumerated { .. } => {
            log.verbose(event)
        }
        WireEvent::Malformed(_) | WireEvent::Failed(_) => log.info(event),
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
