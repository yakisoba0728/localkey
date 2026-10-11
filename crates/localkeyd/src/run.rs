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
//!    matters, shut the runner down and exit 3 without binding any socket; if the set
//!    presents none of the device's enabled interfaces ([`nothing_presented`]), say so,
//!    shut the runner down and exit 2 without binding any socket;
//! 6. bind the control socket, set up the transports (bind the wire socket, or prepare the
//!    UHID, gadget or vpcd transport; several in a [`lk_run::Fanout`]), attach them and
//!    wait for their first enumeration ([`attach`]); a failure there exits 2; then serve.
//!
//! Before step 1 ([`plan`]), a set with `uhid` or `gadget` is refused with exit code 2 on
//! any system other than Linux (`docs/PROGRAM.md` "Linux transports": both compile and
//! are tested everywhere, but `localkeyd` refuses to start them elsewhere), on Linux the
//! gadget configuration is checked as far as reading the file system can
//! ([`gadget_config`]), and `--vpcd-addr` is resolved and checked against the loopback
//! rule ([`vpcd_plan`]).
//!
//! The daemon then runs until the runner stops, until a control client sends `shutdown`,
//! or with `--exit-on-stdin-eof` until stdin reaches EOF. There is no signal handling (std
//! cannot catch signals without `unsafe`): every save is atomic and happens before its
//! response, so a kill loses nothing that was acknowledged, and leftover sockets are
//! replaced at the next start; so is the gadget a killed daemon leaves
//! (`lk_gadget::ConfigFs::leftover`).
//!
//! # As built
//!
//! - The transports (`docs/PROGRAM.md` "lk-wire", "lk-uhid", "lk-gadget", "lk-vpcd"):
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
//!   - `vpcd`: `lk_vpcd::VpcdTransport` with `lk_vpcd::TcpConnector` to `--vpcd-addr`,
//!     resolved once before step 1 (`lk_vpcd::resolve`, IPv4 preferred; a name that does
//!     not resolve exits 2 before the state directory is touched). Nothing is opened
//!     before the runner enumerates; then the transport connects, and retries every
//!     second while vpcd does not listen, which is not a failure: pcscd (and with it
//!     vpcd) may start later.
//!   - vpcd's link has no authentication, so ([`vpcd_plan`], `lk_vpcd::VpcdConfig`): an
//!     address that does not resolve to a loopback address is refused before step 1 (exit
//!     2) unless `--vpcd-allow-remote` is given, and then logged as a warning at the
//!     default level; and every connection's peer goes through the peer check before a
//!     byte is exchanged: on Linux the owner of vpcd's end of the connection, from
//!     `/proc/net/tcp` (`lk_vpcd::ProcNetPeerCheck`), must be root, the local user `pcscd`
//!     (the packaged pcscd's own user on Ubuntu 26.04) or the daemon's real uid, or one of
//!     `--vpcd-peer-uid`, which replaces that set. A refused peer's connection is
//!     closed unused, said once per series at the default level, and retried every
//!     second. On other systems nothing is checked (macOS has no `/proc`; `-v` says so
//!     once), and `--vpcd-peer-uid` is refused there (exit 2), as it is with a remote
//!     address, whose owner no `/proc` of this machine shows.
//!   - `uhid,vpcd` (`docs/PROGRAM.md` "Transport combinations"): both transports, in that
//!     order, in an [`lk_run::Fanout`]; the `serving:` line names both.
//!   - The refusal on a system other than Linux uses `cfg!(target_os = "linux")` at run
//!     time, so every transport's code is compiled, and its use checked, on macOS too.
//!     That flag and the kernel interfaces come in a [`Platform`], so tests run the uhid
//!     and gadget paths of `serve` with fakes on any system. vpcd runs on every Unix.
//!   - The control socket is served with every transport: with uhid, gadget and vpcd it
//!     is the only way a touch reaches the device. `status` shows `attached` from the
//!     transport (`lk_run::Transport::attached`): the wire's client is connected; a UHID
//!     device was created and the kernel runs it; the host has the gadget's function
//!     configured; the vpcd connection is open (the card is in the reader). For
//!     `uhid,vpcd` it is the fanout's: true when either is.
//! - **First enumeration** ([`attach`], [`StartupCheck`], [`Checked`]): the transport is
//!   attached wrapped in [`Checked`], which collects the failures the transport reports
//!   on the runner thread during its first `enumerate` and hands them to the main
//!   thread once `enumerate` returns. Any such failure, with every transport, exits 2
//!   before the `serving:` line, naming each failure once (in the startup message, not
//!   also in the log). Nothing would retry that enumeration: the device asks for one only
//!   after a Management reboot or a power cycle that changes its interfaces, neither of
//!   which can happen with no device presented, and `ctl power-cycle` and `ctl tap` do
//!   not enumerate. With a set, [`Checked`] wraps the fanout, whose `enumerate` runs
//!   every member's on the runner thread, and every member's observer reports to the
//!   same [`StartupCheck`]: a failure of any member stops the startup, each failure is
//!   named with its member (`uhid: fido: cannot open ...`), and the shutdown that follows
//!   drops every member. vpcd's first enumeration only starts its connection thread; a
//!   vpcd that does not listen is reported (and retried) on that thread, so it never
//!   fails the startup. Failures the transport's own threads report are logged as before,
//!   whenever they come, so the outcome does not depend on timing. Not covered: a
//!   `UHID_CREATE2` the kernel refuses (written by the device's writer thread after
//!   `enumerate` returned; `lk_uhid` reports it, the device stays absent) and failures of
//!   later enumerations (logged; the device or gadget stays absent until the next one).
//!   `Status::attached` is no signal here: with uhid it turns true when the device's
//!   writer thread has had `UHID_CREATE2` accepted, after `enumerate` returned; with
//!   gadget only once a host configures the device, which may be much later.
//! - **Nothing presented** ([`nothing_presented`]; found by review): a set whose members
//!   present none of the device's enabled interfaces (wire and gadget carry all three,
//!   uhid OTP and FIDO, vpcd CCID) would present nothing for good, for the same reason a
//!   failed first enumeration would: interfaces change only on a Management write, which
//!   needs a presented interface. In practice `--transport vpcd` with CCID disabled and
//!   `--transport uhid` with only CCID enabled. The daemon refuses to start then (exit 2,
//!   step 5, from `Ready::identity`, which is the identity the first enumeration gets:
//!   the runner takes no input before `serve`), naming the set's interfaces and the
//!   enabled ones and how to recover (start once with wire, or uhid,vpcd on Linux, and
//!   enable one). A later enumeration that leaves nothing presented (a Management write
//!   over vpcd that disables CCID, with REBOOT) is logged at the default level as a
//!   `warning: nothing presented: ...` by [`Checked`]; the daemon keeps running (status
//!   and shutdown work, and a supervisor that restarts it then gets the startup refusal).
//! - Logging of transport events by level (never report or frame bytes): the wire's
//!   frames, UHID events and gadget control requests and transfers with their sizes at
//!   `-vv`; connections, enumerations, device lifecycle, binds, bus events and refused
//!   host reports at `-v`; failures and the removal of a leftover gadget always. vpcd
//!   ([`vpcd_observer`]): messages by kind and size at `-vv`; enumerations, the card
//!   inserted and removed, the peer's owner allowed or not checked, and ignored messages
//!   at `-v`; an allowed non-loopback address, the first failed connection of a series,
//!   the first refused peer of a series, APDUs answered `6F00` and failures always. The
//!   `serving:` line names the transports; an enumeration after which the set presents
//!   nothing is a default-level warning (see "Nothing presented").
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
//!   `lk_gadget` refuses, a `--vpcd-addr` that does not resolve, or resolves to a remote
//!   address without `--vpcd-allow-remote`, `--vpcd-peer-uid` where it cannot be applied,
//!   a set that presents none of the device's enabled interfaces, and a failure of the
//!   first enumeration of any member of the set. Exit code 1
//!   is a failure while serving: the runner could not be attached or stopped during that
//!   enumeration, or it stopped on its own (a panic in the device or the entropy source).
//! - Logging never blocks (see `log`); every way out of [`run`] waits at most
//!   [`FLUSH_LIMIT`] for the queued lines to reach stderr.
//! - The main thread registers a presence watcher with the runner. It logs presence
//!   changes at `-v`, and its end (the runner thread dropped it) tells the main thread
//!   that the runner has stopped; the daemon then joins the runner, logs the panic and
//!   exits 1.
//! - Clean shutdown, at stdin's EOF (`--exit-on-stdin-eof`) or on a control client's
//!   `shutdown` (`docs/PROGRAM.md` "Clean shutdown from the control socket"), is one and
//!   the same: it closes the control socket first (no new user commands), then shuts
//!   the runner down, which drops the device and the transports: the wire transport
//!   removes its socket, the UHID transport destroys its devices, the gadget transport
//!   unbinds, unmounts and removes its ConfigFS tree, the vpcd transport closes its
//!   connection (vpcd sees the card removed). Exit code 0.
//! - `shutdown`: the control server answers `ok` and hands over the client's connection
//!   (`lk_wire::ShutdownRequest`), which the daemon holds ([`Shutdowns`]) until it is about
//!   to exit, after the last log line was flushed: `localkeyd ctl ... shutdown` returns
//!   once the daemon is gone, so a supervisor's stop command (systemd `ExecStop=`) does
//!   not race the clean shutdown with its own kill. Then every held connection is told
//!   how the daemon ended ([`Outcome`]), in one line before the close: `stopped` for exit
//!   0, `error <the message the log ends with>` for any other exit code, so `ctl` exits 0
//!   only for a clean stop (found by review: the bare close looked the same either way).
//!   A request that arrives during startup is acted on once the daemon serves; if the
//!   startup fails instead, it gets that failure (`error cannot set up ...`). One that
//!   arrives while the daemon already shuts down is answered `ok` too and gets the same
//!   outcome as the others, and one that arrives once the outcome is known gets it at
//!   once. A `shutdown` whose `runner.shutdown()` reports a panic gets `error` and the
//!   panic, and the daemon exits 1.
//! - The storage key leaves its `SecretBytes` only on the runner thread, as the array
//!   `Device::open` takes; that copy is overwritten once the device has it (best effort:
//!   copies the compiler makes cannot be reached).

use std::io::{self, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, ThreadId};

use lk_core::{DeviceProfile, Record, UsbInterfaces};
use lk_crypto::SecretBytes;
use lk_device::{Device, Output, UsbIdentity};
use lk_host::{FileStore, HostError, OsEntropy, key_from_command, load_or_create_serial, read_key_file, record_name, to_array};
use lk_gadget::{GadgetConfig, GadgetEvent, GadgetIo, GadgetTransport, KernelIo};
use lk_run::{Command, Fanout, Runner, RunnerConfig, Transport};
use lk_uhid::{DevUhid, UhidIo, UhidNotice, UhidTransport};
use lk_vpcd::{Connector, PeerCheck, ProcNetPeerCheck, TcpConnector, VpcdConfig, VpcdNotice, VpcdTransport};
use lk_wire::{ControlServer, ShutdownHook, ShutdownRequest, WireEvent, WireTransport};

use crate::args::{
    CONTROL_SOCKET, GadgetOptions, KeySource, Profile, RunOptions, TransportKind, TransportOptions, Transports,
    VpcdOptions, WIRE_SOCKET,
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
    /// A control client sent `shutdown`; its connection waits in [`Shutdowns`].
    Shutdown,
}

/// Why the daemon stopped serving.
#[derive(Debug)]
enum Stop {
    /// stdin reached EOF.
    StdinEof,
    /// `shutdown` on the control socket.
    Requested,
    /// The runner thread ended on its own.
    RunnerStopped,
}

/// A transport of the set, with what could be checked before the state directory is
/// opened ([`plan`]).
#[derive(Debug)]
enum Member {
    /// The wire socket's path.
    Wire(PathBuf),
    /// `--uhid-path`.
    Uhid(PathBuf),
    /// The gadget configuration, through `lk_gadget::GadgetConfig::precheck`.
    Gadget(GadgetConfig),
    /// The vpcd options, the address resolved and checked ([`vpcd_plan`]).
    Vpcd(VpcdPlan),
}

/// The vpcd member of a plan: what [`vpcd_plan`] made of `args::VpcdOptions`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct VpcdPlan {
    /// `--vpcd-addr`, resolved; a loopback address unless `allow_remote`.
    addr: SocketAddr,
    /// `--vpcd-allow-remote`.
    allow_remote: bool,
    /// `--vpcd-peer-uid`; `None` for the default check.
    peer_uids: Option<Vec<u32>>,
}

/// What `serve` takes from the system besides the options: whether it is Linux, how the
/// Linux transports open the kernel's files (`docs/PROGRAM.md` "Linux transports": the
/// I/O traits), and how the vpcd transport connects and checks its peer.
/// [`Platform::host`] is the real one; tests pass fakes, so they can run the uhid and
/// gadget paths of `serve` on any system without opening a device, and the vpcd path
/// with a connector that names a remote address but dials a fake vpcd on loopback.
struct Platform {
    linux: bool,
    uhid: OpenUhid,
    gadget: OpenGadget,
    vpcd: OpenVpcd,
    peer_check: MakePeerCheck,
}

/// Makes the [`UhidIo`] for a `--uhid-path`.
type OpenUhid = Box<dyn Fn(&Path) -> Box<dyn UhidIo>>;
/// Makes the [`GadgetIo`] of the gadget transport.
type OpenGadget = Box<dyn Fn() -> Box<dyn GadgetIo>>;
/// Makes the vpcd transport's [`Connector`] for the resolved `--vpcd-addr`.
type OpenVpcd = Box<dyn Fn(SocketAddr) -> Box<dyn Connector>>;
/// Makes the vpcd transport's [`PeerCheck`] for `--vpcd-peer-uid` (`None`: not given).
type MakePeerCheck = Box<dyn Fn(Option<&[u32]>) -> Arc<dyn PeerCheck>>;

impl std::fmt::Debug for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Platform").field("linux", &self.linux).finish_non_exhaustive()
    }
}

impl Platform {
    /// This system: `cfg!(target_os = "linux")`, `lk_uhid::DevUhid`, `lk_gadget::KernelIo`,
    /// `lk_vpcd::TcpConnector`, [`peer_check`].
    fn host() -> Platform {
        Platform {
            linux: cfg!(target_os = "linux"),
            uhid: Box::new(|path| Box::new(DevUhid::new(path))),
            gadget: Box::new(|| Box::new(KernelIo)),
            vpcd: Box::new(|addr| Box::new(TcpConnector::new(addr))),
            peer_check: Box::new(peer_check),
        }
    }
}

/// The vpcd peer check: `lk_vpcd::ProcNetPeerCheck` with exactly the `--vpcd-peer-uid`
/// set when it is given (only on Linux, [`vpcd_plan`]), else `lk_vpcd::default_peer_check`
/// (on Linux root, the local user `pcscd` and this process's real uid; elsewhere no
/// check).
fn peer_check(uids: Option<&[u32]>) -> Arc<dyn PeerCheck> {
    match uids {
        Some(uids) => Arc::new(ProcNetPeerCheck::new(uids.iter().copied())),
        None => lk_vpcd::default_peer_check(),
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
    // The `shutdown` clients' connections, held until the last log line is out.
    let shutdowns = Arc::new(Shutdowns::default());
    let (code, outcome) = match serve(options, &log, &Platform::host(), &shutdowns) {
        Ok(()) => (ExitCode::SUCCESS, Outcome::Stopped),
        Err(Failure::Startup(message)) => {
            log.info(&message);
            (ExitCode::from(EXIT_STARTUP), Outcome::Failed(message))
        }
        Err(Failure::Unreadable) => {
            (ExitCode::from(EXIT_UNREADABLE), Outcome::Failed("unreadable records refused".into()))
        }
        Err(Failure::Runtime(message)) => {
            log.info(&message);
            (ExitCode::from(EXIT_RUNTIME), Outcome::Failed(message))
        }
    };
    log.flush(FLUSH_LIMIT);
    shutdowns.answer(outcome);
    code
}

fn serve(options: &RunOptions, log: &Log, platform: &Platform, shutdowns: &Arc<Shutdowns>) -> Result<(), Failure> {
    let set = options.transport.name();
    // The state path as `FileStore::open` normalises it (no trailing `/`, no `.`), so the
    // default socket paths read as cleanly as the state path in the log.
    let state: PathBuf = options.state.components().collect();
    // Linux only, the gadget configuration, the vpcd address: before the key command runs
    // and the device opens.
    let members = plan(&options.transport, &state, platform)?;
    let wire_path = members.iter().find_map(|member| match member {
        Member::Wire(path) => Some(path.clone()),
        _ => None,
    });
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
        "state {}, serial {}, profile {} ({}), transport {set}",
        state.display(),
        ready.serial,
        options.profile.name(),
        ready.identity.product,
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
    let kinds: Vec<TransportKind> = members.iter().map(Member::kind).collect();
    if let Some(absent) = nothing_presented(ready.identity.interfaces, &kinds) {
        if let Err(error) = runner.shutdown() {
            log.info(error);
        }
        return Err(Failure::Startup(format!(
            "refusing to start: {absent}. Nothing would be presented, and no command could reach the device \
             to enable {carried} again; start once with a transport that presents {enabled} (wire, or uhid,vpcd \
             on Linux) and enable {carried} there",
            carried = absent.carried(),
            enabled = absent.enabled(),
        )));
    }

    let (events, wait) = mpsc::channel();
    let hook = shutdown_hook(events.clone(), Arc::clone(shutdowns));
    let control = ControlServer::bind_with_shutdown(&control_path, runner.sender(), hook)
        .map_err(|error| Failure::Startup(format!("control socket: {error}")))?;
    let check = Arc::new(StartupCheck::default());
    let (transport, serving) = transport(members, &runner, log, &check, platform)?;
    watch_runner(&runner, events.clone())?;
    if let Err(failure) = attach(&runner, transport, &check, &kinds, log) {
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
    let stop = loop {
        match wait.recv() {
            Ok(Event::Presence(now)) => {
                if now != waiting {
                    waiting = now;
                    log.verbose(if now { "presence: waiting for a touch" } else { "presence: idle" });
                }
            }
            Ok(Event::StdinEof) => break Stop::StdinEof,
            Ok(Event::Shutdown) => break Stop::Requested,
            Ok(Event::RunnerStopped) | Err(_) => break Stop::RunnerStopped,
        }
    };
    match stop {
        Stop::StdinEof => log.info("stdin closed; shutting down"),
        Stop::Requested => log.info("shutdown requested on the control socket; shutting down"),
        Stop::RunnerStopped => {}
    }
    control.close();
    match (stop, runner.shutdown()) {
        (Stop::StdinEof | Stop::Requested, Ok(())) => {
            log.info("stopped");
            Ok(())
        }
        (Stop::RunnerStopped, Ok(())) => Err(Failure::Runtime("the runner stopped unexpectedly".into())),
        (_, Err(error)) => Err(Failure::Runtime(error.to_string())),
    }
}

/// The control socket's [`ShutdownHook`]: a `shutdown` request's connection is held in
/// `shutdowns`, and the main thread is told with [`Event::Shutdown`]. If the main thread no
/// longer listens (the daemon is already on its way out), the connection is held all the
/// same and gets the daemon's outcome with the others.
fn shutdown_hook(events: Sender<Event>, shutdowns: Arc<Shutdowns>) -> ShutdownHook {
    Arc::new(move |request: ShutdownRequest| {
        shutdowns.hold(request);
        let _ = events.send(Event::Shutdown);
    })
}

/// How the daemon ended, for the `shutdown` clients it holds.
#[derive(Debug, Clone)]
enum Outcome {
    /// A clean stop (exit code 0): `stopped`.
    Stopped,
    /// A failure (a non-zero exit code), with the message the log has: `error <message>`.
    Failed(String),
}

impl Outcome {
    fn tell(&self, request: ShutdownRequest) {
        match self {
            Outcome::Stopped => request.stopped(),
            Outcome::Failed(message) => request.failed(message),
        }
    }
}

/// The connections of `shutdown` requests (`lk_wire::ShutdownRequest`), held until the
/// daemon is about to exit and then told how it ended ([`Outcome`]): `localkeyd ctl ...
/// shutdown` returns once the daemon is gone and exits 0 only for a clean stop. A request
/// that arrives once the outcome is known is told at once.
#[derive(Debug, Default)]
struct Shutdowns {
    held: Mutex<(Vec<ShutdownRequest>, Option<Outcome>)>,
}

impl Shutdowns {
    fn held(&self) -> MutexGuard<'_, (Vec<ShutdownRequest>, Option<Outcome>)> {
        // One push or one take per update: a panic elsewhere cannot leave it inconsistent.
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Hold `request` until [`Shutdowns::answer`]; afterwards, tell it the outcome at once.
    fn hold(&self, request: ShutdownRequest) {
        let mut held = self.held();
        match &held.1 {
            Some(outcome) => {
                let outcome = outcome.clone();
                drop(held);
                outcome.tell(request);
            }
            None => held.0.push(request),
        }
    }

    /// Tell every held request, and every later one, the daemon's `outcome`.
    fn answer(&self, outcome: Outcome) {
        let requests = {
            let mut held = self.held();
            held.1 = Some(outcome.clone());
            std::mem::take(&mut held.0)
        };
        for request in requests {
            outcome.tell(request);
        }
    }
}

/// The interfaces a transport presents when the device has them enabled
/// (`docs/PROGRAM.md`: the wire and the gadget carry the whole device; "lk-uhid": "CCID is
/// not available through UHID"; "lk-vpcd": the CCID path).
fn carries(kind: TransportKind) -> UsbInterfaces {
    match kind {
        TransportKind::Wire | TransportKind::Gadget => UsbInterfaces { otp: true, fido: true, ccid: true },
        TransportKind::Uhid => UsbInterfaces { otp: true, fido: true, ccid: false },
        TransportKind::Vpcd => UsbInterfaces { otp: false, fido: false, ccid: true },
    }
}

/// `otp,fido,ccid` (as `status` lists them), naming the interfaces that are on, or `none`.
fn interface_list(interfaces: UsbInterfaces) -> String {
    let names: Vec<&str> = [(interfaces.otp, "otp"), (interfaces.fido, "fido"), (interfaces.ccid, "ccid")]
        .into_iter()
        .filter_map(|(on, name)| on.then_some(name))
        .collect();
    if names.is_empty() { "none".into() } else { names.join(",") }
}

/// A set of transports that presents none of the device's enabled interfaces
/// ([`nothing_presented`]). It shows as `--transport SET presents the ... interface(s)
/// only, and the device's enabled interfaces are ...`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NothingPresented {
    /// The set as `--transport` names it.
    set: String,
    /// What the set's members present when it is enabled ([`carries`]).
    carried: UsbInterfaces,
    /// What the device has enabled.
    enabled: UsbInterfaces,
}

impl NothingPresented {
    /// What the set presents, as `status` lists interfaces.
    fn carried(&self) -> String {
        interface_list(self.carried)
    }

    /// What the device has enabled, as `status` lists interfaces.
    fn enabled(&self) -> String {
        interface_list(self.enabled)
    }
}

impl std::fmt::Display for NothingPresented {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = [self.carried.otp, self.carried.fido, self.carried.ccid].into_iter().filter(|&on| on).count();
        let noun = if count == 1 { "interface" } else { "interfaces" };
        write!(
            f,
            "--transport {} presents the {} {noun} only, and the device's enabled interfaces are {}",
            self.set,
            self.carried(),
            self.enabled()
        )
    }
}

/// Whether a device with `enabled` interfaces would have nothing presented by the set
/// `kinds`: `None` when some member presents one of them.
///
/// Nothing can change that while the daemon runs: a device changes its interfaces only on
/// a Management write (then a reboot or a power cycle), which reaches it only through a
/// presented interface, and the control socket's `power-cycle` and `tap` change no
/// configuration. So `--transport vpcd` with CCID disabled, and `--transport uhid` with
/// only CCID enabled, would present nothing for good. (Found by review: the daemon served,
/// and said so only at `-v`.)
fn nothing_presented(enabled: UsbInterfaces, kinds: &[TransportKind]) -> Option<NothingPresented> {
    let carried = kinds.iter().fold(UsbInterfaces { otp: false, fido: false, ccid: false }, |all, &kind| {
        let one = carries(kind);
        UsbInterfaces { otp: all.otp || one.otp, fido: all.fido || one.fido, ccid: all.ccid || one.ccid }
    });
    if (enabled.otp && carried.otp) || (enabled.fido && carried.fido) || (enabled.ccid && carried.ccid) {
        return None;
    }
    let set = kinds.iter().map(|kind| kind.name()).collect::<Vec<_>>().join(",");
    Some(NothingPresented { set, carried, enabled })
}

/// Everything about the transports that can be checked before the state directory is
/// opened, so a bad option costs no key command and no device open:
///
/// - a set with `uhid` or `gadget` on a system other than Linux is refused;
/// - the gadget configuration passes [`gadget_config`] (it reads the file system only);
/// - the vpcd options pass [`vpcd_plan`] (the address resolves to a loopback address, or
///   a remote one is allowed);
/// - the wire socket's path is settled ([`wire_socket`]).
fn plan(transports: &Transports, state: &Path, platform: &Platform) -> Result<Vec<Member>, Failure> {
    let set = transports.name();
    if let Some(kind) = transports.kinds().into_iter().find(|kind| kind.linux_only())
        && !platform.linux
    {
        let os = std::env::consts::OS;
        let what = if transports.members().len() == 1 { set } else { format!("{set}: {}", kind.name()) };
        return Err(Failure::Startup(format!(
            "--transport {what} runs on Linux only, and this system is {os}; use --transport wire or vpcd"
        )));
    }
    transports
        .members()
        .iter()
        .map(|member| match member {
            TransportOptions::Wire { socket } => Ok(Member::Wire(wire_socket(socket.as_deref(), state))),
            TransportOptions::Uhid { path } => Ok(Member::Uhid(path.clone())),
            TransportOptions::Gadget(gadget) => gadget_config(gadget).map(Member::Gadget),
            TransportOptions::Vpcd(vpcd) => vpcd_plan(vpcd, platform).map(Member::Vpcd),
        })
        .collect()
}

/// The vpcd options checked before the state directory is opened: `--vpcd-addr` resolved
/// (`lk_vpcd::resolve`) and held to the loopback rule (`lk_vpcd::check_addr`: refused
/// unless `--vpcd-allow-remote`), and `--vpcd-peer-uid` only where it can be applied: on
/// Linux (the owner is looked up in `/proc/net/tcp`) with a loopback address (a socket on
/// another machine has no line there). A security option that silently did nothing would
/// mislead, so both are startup failures.
fn vpcd_plan(options: &VpcdOptions, platform: &Platform) -> Result<VpcdPlan, Failure> {
    let VpcdOptions { addr: given, allow_remote, peer_uids } = options;
    let addr = lk_vpcd::resolve(given).map_err(|error| Failure::Startup(format!("--vpcd-addr {given}: {error}")))?;
    lk_vpcd::check_addr(addr, *allow_remote).map_err(|refused| {
        Failure::Startup(format!("--vpcd-addr {given}: {refused}; pass --vpcd-allow-remote to use it anyway"))
    })?;
    if peer_uids.is_some() {
        if !platform.linux {
            return Err(Failure::Startup(format!(
                "--vpcd-peer-uid: the owner of vpcd's socket is looked up in /proc/net/tcp, which only Linux has, \
                 and this system is {}",
                std::env::consts::OS
            )));
        }
        if !lk_vpcd::is_loopback(&addr) {
            return Err(Failure::Startup(format!(
                "--vpcd-peer-uid: {addr} is not a loopback address, and the owner of a socket on another machine \
                 cannot be looked up"
            )));
        }
    }
    Ok(VpcdPlan { addr, allow_remote: *allow_remote, peer_uids: peer_uids.clone() })
}

impl Member {
    fn kind(&self) -> TransportKind {
        match self {
            Member::Wire(_) => TransportKind::Wire,
            Member::Uhid(_) => TransportKind::Uhid,
            Member::Gadget(_) => TransportKind::Gadget,
            Member::Vpcd(_) => TransportKind::Vpcd,
        }
    }
}

/// The wire socket: `--wire`, or [`WIRE_SOCKET`] in the (normalised) state directory.
fn wire_socket(socket: Option<&Path>, state: &Path) -> PathBuf {
    socket.map_or_else(|| state.join(WIRE_SOCKET), Path::to_path_buf)
}

/// Set up the transports of the plan, each with its observer, and describe them for the
/// `serving:` line. One member is the transport itself; several go into an
/// [`lk_run::Fanout`] in plan order (uhid before vpcd). Failures a member reports while it
/// enumerates the first time go to `check` instead of the log ([`attach`]).
fn transport(
    members: Vec<Member>,
    runner: &Runner,
    log: &Log,
    check: &Arc<StartupCheck>,
    platform: &Platform,
) -> Result<(Box<dyn Transport>, String), Failure> {
    let mut built: Vec<Box<dyn Transport>> = Vec::with_capacity(members.len());
    let mut descriptions = Vec::with_capacity(members.len());
    for member in members {
        let (transport, description) = member_transport(member, runner, log, check, platform)?;
        built.push(transport);
        descriptions.push(description);
    }
    // A set has at least one member (`args::Transports`); one needs no fanout.
    let transport: Box<dyn Transport> = match built.len() {
        1 => built.remove(0),
        _ => Box::new(Fanout::new(built)),
    };
    Ok((transport, descriptions.join("; ")))
}

/// One member's transport and its description.
fn member_transport(
    member: Member,
    runner: &Runner,
    log: &Log,
    check: &Arc<StartupCheck>,
    platform: &Platform,
) -> Result<(Box<dyn Transport>, String), Failure> {
    match member {
        Member::Wire(path) => {
            let observer = wire_observer(log.clone(), Arc::clone(check));
            let wire = WireTransport::bind_with_observer(&path, runner.sender(), Some(observer))
                .map_err(|error| Failure::Startup(format!("wire socket: {error}")))?;
            Ok((Box::new(wire), format!("wire socket {}", path.display())))
        }
        Member::Uhid(path) => {
            let uhid = uhid_transport((platform.uhid)(&path), runner, log, check);
            Ok((Box::new(uhid), format!("uhid devices through {}", path.display())))
        }
        Member::Gadget(config) => {
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
        Member::Vpcd(plan) => {
            let description = format!("vpcd card for {}", plan.addr);
            let vpcd = vpcd_transport(plan, runner, log, check, platform)?;
            Ok((Box::new(vpcd), description))
        }
    }
}

/// The vpcd transport of `plan` (`docs/PROGRAM.md` "lk-vpcd"), connecting through the
/// platform's connector and checking peers with the platform's peer check. The address
/// rule holds here too (`VpcdTransport::with_config`); [`vpcd_plan`] has already applied
/// it.
fn vpcd_transport(
    plan: VpcdPlan,
    runner: &Runner,
    log: &Log,
    check: &Arc<StartupCheck>,
    platform: &Platform,
) -> Result<VpcdTransport, Failure> {
    let config = VpcdConfig {
        observer: Some(vpcd_observer(log.clone(), Arc::clone(check))),
        allow_remote: plan.allow_remote,
        peer_check: (platform.peer_check)(plan.peer_uids.as_deref()),
    };
    VpcdTransport::with_config((platform.vpcd)(plan.addr), runner.sender(), config)
        .map_err(|refused| Failure::Startup(format!("vpcd: {refused}")))
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
///
/// `kinds` are the members of the set: with several, each failure names its member. Every
/// later enumeration after which the set presents nothing is logged at the default level
/// ([`Checked`]).
fn attach(
    runner: &Runner,
    transport: Box<dyn Transport>,
    check: &Arc<StartupCheck>,
    kinds: &[TransportKind],
    log: &Log,
) -> Result<(), Failure> {
    let (report, first) = mpsc::channel();
    let checked = Checked {
        inner: transport,
        check: Arc::clone(check),
        first: Some(report),
        kinds: kinds.to_vec(),
        log: log.clone(),
    };
    runner.serve(Box::new(checked)).map_err(|error| Failure::Runtime(error.to_string()))?;
    let failures =
        first.recv().map_err(|_| Failure::Runtime("the runner stopped while the transport enumerated".into()))?;
    if failures.is_empty() {
        return Ok(());
    }
    let named: Vec<String> = failures
        .into_iter()
        .map(|(kind, reason)| if kinds.len() > 1 { format!("{}: {reason}", kind.name()) } else { reason })
        .collect();
    let set = kinds.iter().map(|kind| kind.name()).collect::<Vec<_>>().join(",");
    Err(Failure::Startup(format!("cannot set up the {set} transport: {}", named.join("; "))))
}

/// The failures a transport reports while it enumerates the first time, on the thread
/// that enumerates (the runner thread, see [`Checked`]). The transport's own threads
/// report through the same observer at any time; a failure of theirs is logged as usual,
/// whenever it comes, so what makes startup fail does not depend on timing.
#[derive(Debug, Default)]
struct StartupCheck {
    window: Mutex<Option<(ThreadId, Vec<Failed>)>>,
}

/// A failure kept by [`StartupCheck`], with the member that reported it.
type Failed = (TransportKind, String);

impl StartupCheck {
    fn window(&self) -> MutexGuard<'_, Option<(ThreadId, Vec<Failed>)>> {
        // One assignment or push per update: a panic elsewhere cannot leave it inconsistent.
        self.window.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Start collecting the failures this thread reports.
    fn open(&self) {
        *self.window() = Some((thread::current().id(), Vec::new()));
    }

    /// Keep `reason`, reported by the `member` transport, if collecting is on and this is
    /// the thread that turned it on; false otherwise, and the caller logs it.
    fn keep(&self, member: TransportKind, reason: &str) -> bool {
        match self.window().as_mut() {
            Some((owner, failures)) if *owner == thread::current().id() => {
                failures.push((member, reason.to_owned()));
                true
            }
            _ => false,
        }
    }

    /// Stop collecting; the failures kept.
    fn close(&self) -> Vec<Failed> {
        self.window().take().map(|(_, failures)| failures).unwrap_or_default()
    }
}

/// The transport, with its first enumeration watched by a [`StartupCheck`] and its
/// failures sent to [`attach`], and every enumeration after which the set presents
/// nothing ([`nothing_presented`]) logged at the default level: the device stays absent
/// until the daemon is restarted with another set. (The first cannot be one: `serve`
/// refuses to start then.) Everything else passes straight through.
#[derive(Debug)]
struct Checked {
    inner: Box<dyn Transport>,
    check: Arc<StartupCheck>,
    /// Until the first enumeration: where its failures go.
    first: Option<Sender<Vec<Failed>>>,
    /// The members of the set.
    kinds: Vec<TransportKind>,
    log: Log,
}

impl Transport for Checked {
    fn enumerate(&mut self, identity: &UsbIdentity) {
        if let Some(absent) = nothing_presented(identity.interfaces, &self.kinds) {
            self.log.info(format!(
                "warning: nothing presented: {absent}; no command can reach the device to change that, so it \
                 stays absent until localkeyd is restarted with a transport that presents {} (wire, or \
                 uhid,vpcd on Linux)",
                absent.enabled()
            ));
        }
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
        WireEvent::Failed(reason) if check.keep(TransportKind::Wire, reason) => {}
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
        UhidNotice::Failed(reason) if check.keep(TransportKind::Uhid, reason) => {}
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
        GadgetEvent::Failed(reason) if check.keep(TransportKind::Gadget, reason) => {}
        GadgetEvent::Reclaimed { .. } | GadgetEvent::Failed(_) => log.info(event),
    })
}

/// Log vpcd notices by level: messages from vpcd and answers by kind and size at `-vv`;
/// enumerations, the card inserted and removed, the peer's owner allowed (with its uid)
/// or not checked, and messages no card answers at `-v`; an allowed non-loopback address
/// (APDUs travel unencrypted), the first failed connection of a series and the first
/// refused peer of a series (`lk_vpcd` reports one per series, then retries every
/// second), APDUs answered with `6F00` and failures always (a failure of the first
/// enumeration goes to `check`). No notice carries APDU or ATR bytes
/// (`lk_vpcd::VpcdNotice`).
fn vpcd_observer(log: Log, check: Arc<StartupCheck>) -> lk_vpcd::Observer {
    Arc::new(move |notice: &VpcdNotice| match notice {
        VpcdNotice::Received { .. } | VpcdNotice::Sent { .. } => log.trace(notice),
        VpcdNotice::Enumerated { .. }
        | VpcdNotice::PeerAllowed { .. }
        | VpcdNotice::PeerUnchecked { .. }
        | VpcdNotice::Connected { .. }
        | VpcdNotice::Disconnected { .. }
        | VpcdNotice::Ignored { .. } => log.verbose(notice),
        VpcdNotice::Failed(reason) if check.keep(TransportKind::Vpcd, reason) => {}
        VpcdNotice::NotLoopback { .. }
        | VpcdNotice::PeerRefused { .. }
        | VpcdNotice::Unreachable { .. }
        | VpcdNotice::ErrorResponse { .. }
        | VpcdNotice::Failed(_) => log.info(notice),
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
    use std::io::{BufRead, BufReader, Write};
    use std::net::{TcpListener, TcpStream};
    use std::time::{Duration, Instant};

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
    fn vpcd_notices_are_logged_by_level() {
        let addr: SocketAddr = "127.0.0.1:35963".parse().expect("a valid address");
        let remote: SocketAddr = "192.0.2.1:35963".parse().expect("a valid address");
        let notices = [
            VpcdNotice::Received { message: "APDU", size: 12 },
            VpcdNotice::Sent { message: "APDU", size: 2 },
            VpcdNotice::Enumerated { ccid: true },
            VpcdNotice::PeerAllowed { addr, uid: 0 },
            VpcdNotice::PeerUnchecked { addr, reason: "only Linux has /proc/net/tcp".into() },
            VpcdNotice::Connected { addr },
            VpcdNotice::Ignored { message: "empty message", size: 0 },
            VpcdNotice::Disconnected { reason: "vpcd closed the connection".into() },
            VpcdNotice::NotLoopback { addr: remote },
            VpcdNotice::PeerRefused {
                addr,
                refusal: lk_vpcd::PeerRefusal::NotAllowed { uid: 1001, allowed: vec![0, 1000] },
            },
            VpcdNotice::Unreachable { addr, reason: "connection refused".into() },
            VpcdNotice::ErrorResponse { reason: "the device dropped the command".into() },
            VpcdNotice::Failed("cannot start the connection thread".into()),
        ];
        let [default, verbose, trace] = by_level(|log| {
            let observer = vpcd_observer(log.clone(), Arc::default());
            for notice in &notices {
                observer(notice);
            }
        });
        let text = |notice: &VpcdNotice| notice.to_string();
        assert_eq!(default, notices[8..].iter().map(text).collect::<Vec<_>>(), "warnings and failures always");
        assert_eq!(verbose, notices[2..].iter().map(text).collect::<Vec<_>>(), "the card's comings and goings at -v");
        assert_eq!(trace, notices.iter().map(text).collect::<Vec<_>>(), "messages and sizes at -vv");
    }

    /// A failure a vpcd notice reports on the enumerating thread goes to the startup check,
    /// named with its member, instead of the log.
    #[test]
    fn a_vpcd_failure_during_the_first_enumeration_goes_to_the_startup_check() {
        let log = Log::unwritten(TRACE);
        let check = Arc::new(StartupCheck::default());
        let observer = vpcd_observer(log.clone(), Arc::clone(&check));
        check.open();
        observer(&VpcdNotice::Failed("cannot start the connection thread".into()));
        assert_eq!(check.close(), [(TransportKind::Vpcd, "cannot start the connection thread".to_owned())]);
        assert!(log.take_lines().is_empty());
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
        assert!(!check.keep(TransportKind::Uhid, "before"), "not collecting yet");
        check.open();
        let elsewhere = thread::scope(|scope| {
            scope.spawn(|| check.keep(TransportKind::Vpcd, "elsewhere")).join().expect("the thread runs")
        });
        assert!(!elsewhere, "another thread's failure is logged instead");
        assert!(check.keep(TransportKind::Uhid, "here"));
        assert!(check.keep(TransportKind::Vpcd, "there"));
        assert_eq!(check.close(), [(TransportKind::Uhid, "here".to_owned()), (TransportKind::Vpcd, "there".to_owned())]);
        assert!(!check.keep(TransportKind::Uhid, "after"), "collecting ended");
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
        let (uhid, serving) = transport(vec![Member::Uhid(missing.clone())], &runner, &log, &check, &Platform::host())
            .expect("nothing is opened before the enumeration");
        assert_eq!(serving, format!("uhid devices through {}", missing.display()));
        let attached = attach(&runner, uhid, &check, &[TransportKind::Uhid], &log);
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
        let attached = attach(&runner, Box::new(uhid), &check, &[TransportKind::Uhid], &log);
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
        let attached = attach(&runner, Box::new(gadget), &check, &[TransportKind::Gadget], &log);
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
        Platform { linux: true, uhid: Box::new(move |_| uhid()), gadget: Box::new(gadget), ..Platform::host() }
    }

    /// `run` options on state directory `dir/s` with a new key file `dir/key`, the control
    /// socket in the state directory, and `transport`.
    fn run_options(dir: &TempDir, transport: TransportOptions) -> RunOptions {
        run_options_with(dir, vec![transport])
    }

    /// [`run_options`] with the set `members` (valid, in order).
    fn run_options_with(dir: &TempDir, members: Vec<TransportOptions>) -> RunOptions {
        let key = dir.join("key");
        let mut entropy = OsEntropy::open().expect("OS randomness is available");
        write_key_file(&key, &generate_key(&mut entropy)).expect("the key file can be written");
        RunOptions {
            state: dir.join("s"),
            key: KeySource::File(key),
            profile: Profile::Own,
            transport: Transports::of(members),
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
        let served = serve(&options, &log, &platform, &Arc::default());
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
        let served = serve(&options, &log, &platform, &Arc::default());
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
        let served = serve(&options, &log, &platform, &Arc::default());
        let Err(Failure::Startup(message)) = served else {
            panic!("serving gave {served:?}");
        };
        assert!(message.starts_with("gadget: ") && message.contains("is not a leftover"), "{message}");
        assert!(!dir.join("s").exists(), "the state directory was not created");
        assert!(lock(&kernel.calls).is_empty(), "the kernel was not asked for anything");
    }
    /// `uhid` (default path) and `vpcd` (default address).
    fn uhid_vpcd(vpcd: SocketAddr) -> Vec<TransportOptions> {
        vec![
            TransportOptions::Uhid { path: PathBuf::from(lk_uhid::DEFAULT_UHID_PATH) },
            TransportOptions::Vpcd(VpcdOptions::at(vpcd.to_string())),
        ]
    }

    /// `docs/PROGRAM.md` "Transport combinations": a set with uhid is refused on a system
    /// other than Linux, naming the member, before anything is resolved or opened.
    #[test]
    fn a_set_with_uhid_is_refused_elsewhere_than_linux_naming_the_member() {
        let elsewhere = Platform { linux: false, ..Platform::host() };
        let addr: SocketAddr = "127.0.0.1:1".parse().expect("a valid address");
        let refused = plan(&Transports::of(uhid_vpcd(addr)), Path::new("/s"), &elsewhere).err();
        let Some(Failure::Startup(message)) = refused else {
            panic!("uhid,vpcd was not refused: {refused:?}");
        };
        let os = std::env::consts::OS;
        assert_eq!(
            message,
            format!("--transport uhid,vpcd: uhid runs on Linux only, and this system is {os}; use --transport wire or vpcd")
        );
        let vpcd = Transports::of(vec![TransportOptions::Vpcd(VpcdOptions::at("127.0.0.1:35963"))]);
        let planned = plan(&vpcd, Path::new("/s"), &elsewhere).expect("vpcd runs on every Unix");
        assert!(matches!(planned.as_slice(), [Member::Vpcd(plan)] if plan.addr.port() == 35963), "{planned:?}");
    }

    /// A listener on an ephemeral loopback port, the fake vpcd (`docs/PROGRAM.md`
    /// "lk-vpcd": tests against a fake vpcd on `127.0.0.1`).
    fn fake_vpcd() -> TcpListener {
        let listener = TcpListener::bind("127.0.0.1:0").expect("an ephemeral loopback port");
        listener.set_nonblocking(true).expect("the listener can be non-blocking");
        listener
    }

    /// The next connection to the fake vpcd within [`WAIT`], if any.
    fn accept(listener: &TcpListener) -> Option<TcpStream> {
        let deadline = Instant::now() + WAIT;
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).expect("the connection can block");
                    stream.set_read_timeout(Some(WAIT)).expect("a timeout can be set");
                    return Some(stream);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("accept failed: {error}"),
            }
        }
        None
    }

    /// vpcd's `GET ATR` (a 1-byte message `04` with its 2-byte big-endian length,
    /// vsmartcard api.html) and the card's answer.
    fn get_atr(vpcd: &mut TcpStream) -> io::Result<Vec<u8>> {
        vpcd.write_all(&[0x00, 0x01, 0x04])?;
        let mut length = [0; 2];
        vpcd.read_exact(&mut length)?;
        let mut atr = vec![0; usize::from(u16::from_be_bytes(length))];
        vpcd.read_exact(&mut atr)?;
        Ok(atr)
    }

    /// One control request; the reply lines read so far, up to and including `ok` or
    /// `error ...` (the connection of a `shutdown` stays open after its `ok`).
    fn control_request(path: &Path, request: &str) -> io::Result<(Vec<String>, UnixStream)> {
        let mut stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(WAIT))?;
        stream.write_all(format!("{request}\n").as_bytes())?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 {
                break;
            }
            let line = line.trim_end().to_owned();
            let last = line == "ok" || line.starts_with("error");
            lines.push(line);
            if last {
                break;
            }
        }
        Ok((lines, stream))
    }

    /// The whole `serve` with `--transport uhid,vpcd` (a fake `/dev/uhid` and a fake vpcd):
    /// both members enumerate in one fanout, `status` shows the fanout's `attached`, and
    /// the control socket's `shutdown` ends `serve` cleanly, with the client's connection
    /// held in [`Shutdowns`] until the caller answers it, the control socket removed and
    /// vpcd's card removed.
    #[test]
    fn serving_uhid_and_vpcd_together_presents_both_and_stops_on_a_control_shutdown() {
        let dir = TempDir::new();
        let vpcd = fake_vpcd();
        let addr = vpcd.local_addr().expect("bound");
        let options = run_options_with(&dir, uhid_vpcd(addr));
        let control = dir.join("s").join(CONTROL_SOCKET);
        let kernel: Arc<Mutex<Vec<UnixStream>>> = Arc::default();
        let devices = Arc::clone(&kernel);
        let log = Log::unwritten(TRACE);
        let served_log = log.clone();
        let shutdowns = Arc::new(Shutdowns::default());
        let held_by_serve = Arc::clone(&shutdowns);
        let served = thread::spawn(move || {
            let platform = linux(move || Box::new(PairUhid { kernel: Arc::clone(&devices) }), || Box::new(NoEp0::default()));
            serve(&options, &served_log, &platform, &held_by_serve)
        });

        let mut card = accept(&vpcd).expect("the vpcd member connects");
        assert_eq!(get_atr(&mut card).expect("the card answers"), DeviceProfile::own(0).atr);
        let deadline = Instant::now() + WAIT;
        while lock(&kernel).len() < 2 {
            assert!(Instant::now() < deadline, "the uhid member did not create its two devices");
            thread::sleep(Duration::from_millis(10));
        }
        let (status, _) = control_request(&control, "status").expect("the control socket answers");
        // Either member makes this true (the uhid member once the fake kernel took
        // `UHID_CREATE2`); that the vpcd member's `attached` reaches `status` on its own is
        // the next test's.
        assert!(status.contains(&"attached=true".to_owned()), "a member is attached: {status:?}");
        assert!(status.contains(&"interfaces=otp,fido,ccid".to_owned()), "{status:?}");

        let (reply, mut held) = control_request(&control, "shutdown").expect("the control socket answers");
        assert_eq!(reply, ["ok"]);
        let served = served.join().expect("serve does not panic");
        assert!(served.is_ok(), "{served:?}");
        assert!(!control.exists(), "the control socket was removed");
        let mut rest = [0; 1];
        assert_eq!(card.read(&mut rest).ok(), Some(0), "vpcd saw the card removed");
        held.set_read_timeout(Some(Duration::from_millis(300))).expect("a timeout can be set");
        let waiting = held.read(&mut rest).map_err(|error| error.kind());
        assert!(
            matches!(waiting, Err(io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)),
            "the shutdown client's connection is held until the outcome is known: {waiting:?}"
        );
        held.set_read_timeout(Some(WAIT)).expect("a timeout can be set");
        shutdowns.answer(Outcome::Stopped);
        let mut end = String::new();
        held.read_to_string(&mut end).expect("the shutdown client reads to the end");
        assert_eq!(end, "stopped\n", "the shutdown client learns of the clean stop, then sees the end");
        let lines = log.take_lines();
        for expected in [
            "transport uhid,vpcd",
            "serving: uhid devices through /dev/uhid; vpcd card for ",
            "shutdown requested on the control socket; shutting down",
            "stopped",
        ] {
            assert!(lines.iter().any(|line| line.contains(expected)), "{expected:?} in {lines:#?}");
        }
    }

    /// A fake `/dev/uhid` whose kernel refuses every `UHID_CREATE2` (as `uhid_dev_create2`
    /// does with `-EINVAL`): the uhid member opens its files but never runs a device, so
    /// its `attached` stays false.
    #[derive(Debug, Default)]
    struct RefusingUhid {
        kernel: Arc<Mutex<Vec<UnixStream>>>,
    }

    impl UhidIo for RefusingUhid {
        fn open(&mut self) -> io::Result<UhidHalves> {
            let (ours, kernel) = UnixStream::pair()?;
            lock(&self.kernel).push(kernel);
            Ok((Box::new(ours), Box::new(Refusing)))
        }
    }

    /// The write half of [`RefusingUhid`].
    #[derive(Debug)]
    struct Refusing;

    impl io::Write for Refusing {
        fn write(&mut self, _event: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::InvalidInput))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// The `attached` value of a `status` reply.
    fn attached(control: &Path) -> Option<String> {
        let (status, _) = control_request(control, "status").expect("the control socket answers");
        status.iter().find_map(|line| line.strip_prefix("attached=").map(str::to_owned))
    }

    /// Wait until `status` shows `attached=value`.
    fn wait_attached(control: &Path, value: &str) {
        let deadline = Instant::now() + WAIT;
        loop {
            let now = attached(control);
            if now.as_deref() == Some(value) {
                return;
            }
            assert!(Instant::now() < deadline, "attached={value} within {WAIT:?}; it is {now:?}");
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// Whether the lines logged so far, added to `seen`, have `count` lines with `part`.
    fn logged(log: &Log, seen: &mut Vec<String>, part: &str, count: usize) -> bool {
        seen.extend(log.take_lines());
        seen.iter().filter(|line| line.contains(part)).count() >= count
    }

    /// The vpcd member's `attached` reaches `status` through the fanout and the daemon on
    /// its own: with the uhid member not running (its kernel refuses `UHID_CREATE2`),
    /// `attached` is false while vpcd does not listen, true once the card is in the reader,
    /// and false again once vpcd has gone. (Found by review: in the test above, the uhid
    /// member alone makes `attached` true, so it would pass if the daemon or the fanout
    /// lost the vpcd member's answer.)
    #[test]
    fn with_the_uhid_member_not_running_status_shows_whether_the_vpcd_card_is_in_the_reader() {
        let dir = TempDir::new();
        // A free loopback port: bound, then let go; vpcd "starts" later on it.
        let addr = fake_vpcd().local_addr().expect("bound");
        let options = run_options_with(&dir, uhid_vpcd(addr));
        let control = dir.join("s").join(CONTROL_SOCKET);
        let kernel: Arc<Mutex<Vec<UnixStream>>> = Arc::default();
        let devices = Arc::clone(&kernel);
        let log = Log::unwritten(TRACE);
        let served_log = log.clone();
        let shutdowns = Arc::new(Shutdowns::default());
        let held_by_serve = Arc::clone(&shutdowns);
        let served = thread::spawn(move || {
            let uhid = move || -> Box<dyn UhidIo> { Box::new(RefusingUhid { kernel: Arc::clone(&devices) }) };
            let platform = linux(uhid, || Box::new(NoEp0::default()));
            serve(&options, &served_log, &platform, &held_by_serve)
        });

        // Both devices were refused, and vpcd's absence was noticed.
        let mut seen = Vec::new();
        let deadline = Instant::now() + WAIT;
        while !(logged(&log, &mut seen, "writing CREATE2 failed", 2)
            && logged(&log, &mut seen, &format!("vpcd: cannot connect to {addr}"), 1))
        {
            assert!(Instant::now() < deadline, "the uhid member was refused and vpcd not reached: {seen:#?}");
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(attached(&control).as_deref(), Some("false"), "no member is attached");

        let vpcd = {
            let deadline = Instant::now() + WAIT;
            loop {
                match TcpListener::bind(addr) {
                    Ok(listener) => break listener,
                    Err(error) => assert!(Instant::now() < deadline, "{addr} cannot be bound again: {error}"),
                }
                thread::sleep(Duration::from_millis(20));
            }
        };
        vpcd.set_nonblocking(true).expect("the listener can be non-blocking");
        let mut card = accept(&vpcd).expect("the vpcd member connects once vpcd listens");
        assert_eq!(get_atr(&mut card).expect("the card answers"), DeviceProfile::own(0).atr);
        assert_eq!(attached(&control).as_deref(), Some("true"), "the card is in the reader");

        // vpcd goes away: no listener to reconnect to, then the connection closes.
        drop(vpcd);
        drop(card);
        wait_attached(&control, "false");

        let (reply, _held) = control_request(&control, "shutdown").expect("the control socket answers");
        assert_eq!(reply, ["ok"]);
        let served = served.join().expect("serve does not panic");
        assert!(served.is_ok(), "{served:?}");
        shutdowns.answer(Outcome::Stopped);
        assert_eq!(lock(&kernel).len(), 2, "one file per HID interface was opened");
    }

    /// A fake `/dev/uhid` that cannot be opened, and whose first open waits until the test
    /// lets it fail (drops the sender), so a test can act while the daemon starts.
    #[derive(Debug)]
    struct GatedUhid {
        gate: Arc<Mutex<mpsc::Receiver<()>>>,
    }

    impl UhidIo for GatedUhid {
        fn open(&mut self) -> io::Result<UhidHalves> {
            let _ = lock(&self.gate).recv_timeout(WAIT);
            Err(io::Error::from(io::ErrorKind::NotFound))
        }
    }

    /// A `shutdown` accepted while the daemon starts is held across a startup that then
    /// fails, and its client learns of the failure: `error` and the startup message, not
    /// the bare end of the stream that also follows a clean stop. (Found by review: the
    /// request was dropped with the event channel, and `ctl` exited 0 while the daemon
    /// exited 2.)
    #[test]
    fn a_shutdown_accepted_during_a_startup_that_then_fails_is_told_of_the_failure() {
        let dir = TempDir::new();
        let options = run_options(&dir, TransportOptions::Uhid { path: PathBuf::from("/dev/uhid") });
        let control = dir.join("s").join(CONTROL_SOCKET);
        let (release, gate) = mpsc::channel();
        let gate = Arc::new(Mutex::new(gate));
        let log = Log::unwritten(TRACE);
        let served_log = log.clone();
        let shutdowns = Arc::new(Shutdowns::default());
        let held_by_serve = Arc::clone(&shutdowns);
        let served = thread::spawn(move || {
            let uhid = move || -> Box<dyn UhidIo> { Box::new(GatedUhid { gate: Arc::clone(&gate) }) };
            let platform = linux(uhid, || Box::new(NoEp0::default()));
            serve(&options, &served_log, &platform, &held_by_serve)
        });

        let deadline = Instant::now() + WAIT;
        while !control.exists() {
            assert!(Instant::now() < deadline, "the control socket was not bound");
            thread::sleep(Duration::from_millis(10));
        }
        let (reply, held) = control_request(&control, "shutdown").expect("the control socket answers");
        assert_eq!(reply, ["ok"], "accepted while the first enumeration waits");
        drop(release);
        let served = served.join().expect("serve does not panic");
        let Err(Failure::Startup(message)) = served else {
            panic!("the uhid devices cannot be opened, yet serving gave {served:?}");
        };
        // What `run` does with the outcome, once its log is flushed.
        shutdowns.answer(Outcome::Failed(message.clone()));
        let mut rest = String::new();
        BufReader::new(held).read_to_string(&mut rest).expect("the client reads to the end");
        assert_eq!(rest, format!("error {message}\n"));
        assert!(message.starts_with("cannot set up the uhid transport: "), "{message}");
    }

    /// Held requests get the outcome once it is known; a request that comes later gets it
    /// at once.
    #[test]
    fn held_shutdowns_are_told_the_outcome_and_later_ones_at_once() {
        let dir = TempDir::new();
        let shutdowns = Arc::new(Shutdowns::default());
        let (events, _wait) = mpsc::channel();
        let runner = runner(&dir.join("s"));
        // In the state directory: the control socket's parent must be private (lk-wire).
        let control = dir.join("s").join(CONTROL_SOCKET);
        let hook = shutdown_hook(events, Arc::clone(&shutdowns));
        let server = ControlServer::bind_with_shutdown(&control, runner.sender(), hook);
        let server = server.expect("the control socket can be bound");
        let (reply, early) = control_request(&control, "shutdown").expect("the control socket answers");
        assert_eq!(reply, ["ok"]);
        // The hook runs after `ok` is out; wait until it has handed the request over.
        let deadline = Instant::now() + WAIT;
        while lock(&shutdowns.held).0.is_empty() {
            assert!(Instant::now() < deadline, "the request was not held");
            thread::sleep(Duration::from_millis(10));
        }
        shutdowns.answer(Outcome::Failed("the runner stopped:\nit panicked".into()));
        let mut rest = String::new();
        BufReader::new(early).read_to_string(&mut rest).expect("the client reads to the end");
        assert_eq!(rest, "error the runner stopped: it panicked\n", "one line, then the end");

        let mut late = UnixStream::connect(&control).expect("the control socket still answers");
        late.set_read_timeout(Some(WAIT)).expect("a timeout can be set");
        late.write_all(b"shutdown\n").expect("the request can be sent");
        let mut reply = String::new();
        late.read_to_string(&mut reply).expect("the client reads to the end");
        assert_eq!(reply, "ok\nerror the runner stopped: it panicked\n", "told at once");
        server.close();
        assert!(runner.shutdown().is_ok());
    }

    /// `docs/PROGRAM.md`: wire and gadget carry the whole device, uhid only the HID
    /// interfaces ("CCID is not available through UHID"), vpcd only CCID. Only a set that
    /// carries none of the enabled interfaces presents nothing.
    #[test]
    fn a_set_that_presents_none_of_the_enabled_interfaces_is_found() {
        let interfaces = |otp, fido, ccid| UsbInterfaces { otp, fido, ccid };
        let all = interfaces(true, true, true);
        let whole = [&[TransportKind::Wire][..], &[TransportKind::Gadget], &[TransportKind::Uhid, TransportKind::Vpcd]];
        let some = [all, interfaces(false, false, true), interfaces(true, false, false), interfaces(false, true, false)];
        for kinds in whole {
            for enabled in some {
                assert_eq!(nothing_presented(enabled, kinds), None, "{kinds:?} presents {enabled:?}");
            }
        }
        assert_eq!(nothing_presented(all, &[TransportKind::Vpcd]), None);
        assert_eq!(nothing_presented(interfaces(false, true, true), &[TransportKind::Uhid]), None);
        let shown = |enabled, kinds: &[TransportKind]| nothing_presented(enabled, kinds).map(|it| it.to_string());
        assert_eq!(
            shown(interfaces(true, true, false), &[TransportKind::Vpcd]).as_deref(),
            Some("--transport vpcd presents the ccid interface only, and the device's enabled interfaces are otp,fido")
        );
        assert_eq!(
            shown(interfaces(false, false, true), &[TransportKind::Uhid]).as_deref(),
            Some("--transport uhid presents the otp,fido interfaces only, and the device's enabled interfaces are ccid")
        );
        assert_eq!(interface_list(interfaces(false, false, false)), "none");
    }

    /// `--vpcd-addr` options with `allow_remote` and `peer_uids`.
    fn vpcd_options(addr: &str, allow_remote: bool, peer_uids: Option<Vec<u32>>) -> VpcdOptions {
        VpcdOptions { addr: addr.to_owned(), allow_remote, peer_uids }
    }

    /// The loopback rule and `--vpcd-peer-uid`'s preconditions, before the state directory
    /// (`lk_vpcd::check_addr`): a remote address needs `--vpcd-allow-remote`, which a
    /// loopback address does not; the peer uids need Linux and a loopback address.
    #[test]
    fn the_vpcd_plan_holds_the_address_to_loopback_and_the_peer_uids_to_linux() {
        let linux = Platform { linux: true, ..Platform::host() };
        let elsewhere = Platform { linux: false, ..Platform::host() };
        let message = |options: VpcdOptions, platform: &Platform| match vpcd_plan(&options, platform) {
            Err(Failure::Startup(message)) => message,
            other => panic!("{options:?} gave {other:?}"),
        };
        assert_eq!(
            message(vpcd_options("192.0.2.1:35963", false, None), &linux),
            "--vpcd-addr 192.0.2.1:35963: 192.0.2.1:35963 is not a loopback address: APDUs (PINs and keys among \
             them) would travel to it unencrypted, and whatever listens there would drive the card unchecked; pass \
             --vpcd-allow-remote to use it anyway"
        );
        assert!(message(vpcd_options("[::ffff:192.0.2.1]:1", false, None), &linux).contains("--vpcd-allow-remote"));
        let remote = vpcd_plan(&vpcd_options("192.0.2.1:35963", true, None), &elsewhere).expect("allowed");
        assert_eq!(remote, VpcdPlan { addr: "192.0.2.1:35963".parse().expect("valid"), allow_remote: true, peer_uids: None });
        for loopback in ["127.0.0.1:35963", "[::1]:35963", "localhost:35963", "[::ffff:127.0.0.1]:35963"] {
            for allow_remote in [false, true] {
                let plan = vpcd_plan(&vpcd_options(loopback, allow_remote, None), &elsewhere).expect("loopback");
                assert!(lk_vpcd::is_loopback(&plan.addr), "{loopback}: {plan:?}");
            }
        }
        let uids = Some(vec![0, 110]);
        let plan = vpcd_plan(&vpcd_options("127.0.0.1:35963", false, uids.clone()), &linux).expect("Linux, loopback");
        assert_eq!(plan.peer_uids, uids);
        let os = std::env::consts::OS;
        assert_eq!(
            message(vpcd_options("127.0.0.1:35963", false, uids.clone()), &elsewhere),
            format!(
                "--vpcd-peer-uid: the owner of vpcd's socket is looked up in /proc/net/tcp, which only Linux has, and \
                 this system is {os}"
            )
        );
        assert_eq!(
            message(vpcd_options("192.0.2.1:35963", true, uids), &linux),
            "--vpcd-peer-uid: 192.0.2.1:35963 is not a loopback address, and the owner of a socket on another \
             machine cannot be looked up"
        );
    }

    /// A connector that names one address (`named`, what the transport and the log see) and
    /// dials another (`dial`, a fake vpcd on loopback): a remote address without anything
    /// leaving the machine, like `Harness::disguised` in lk-vpcd's tests.
    #[derive(Debug)]
    struct Disguised {
        named: SocketAddr,
        dial: SocketAddr,
    }

    impl Connector for Disguised {
        fn connect(&mut self) -> io::Result<TcpStream> {
            TcpConnector::new(self.dial).connect()
        }

        fn addr(&self) -> SocketAddr {
            self.named
        }
    }

    /// A peer check that records each connection's (local, peer) addresses and allows the
    /// peer as uid 4242, or refuses it as owned by uid 1001.
    #[derive(Debug)]
    struct Recording {
        allow: bool,
        seen: Mutex<Vec<(SocketAddr, SocketAddr)>>,
    }

    impl Recording {
        fn new(allow: bool) -> Arc<Recording> {
            Arc::new(Recording { allow, seen: Mutex::default() })
        }
    }

    impl PeerCheck for Recording {
        fn check(&self, local: SocketAddr, peer: SocketAddr) -> lk_vpcd::PeerVerdict {
            lock(&self.seen).push((local, peer));
            if self.allow {
                lk_vpcd::PeerVerdict::Allowed { uid: 4242 }
            } else {
                lk_vpcd::PeerVerdict::Refused(lk_vpcd::PeerRefusal::NotAllowed { uid: 1001, allowed: vec![4242] })
            }
        }
    }

    /// The host platform with the vpcd connector dialling `dial` whatever the address, and
    /// `check` as the peer check.
    fn vpcd_platform(dial: SocketAddr, check: Arc<Recording>) -> Platform {
        Platform {
            vpcd: Box::new(move |named| Box::new(Disguised { named, dial })),
            peer_check: Box::new(move |_| Arc::clone(&check) as Arc<dyn PeerCheck>),
            ..Platform::host()
        }
    }

    /// Without `--vpcd-allow-remote` a remote address stops `serve` before the state
    /// directory is created and the key loaded, and nothing is dialled.
    #[test]
    fn a_remote_vpcd_address_without_allow_remote_stops_serve_before_the_state_directory() {
        let dir = TempDir::new();
        let vpcd = fake_vpcd();
        let dial = vpcd.local_addr().expect("bound");
        let mut options = run_options(&dir, TransportOptions::Vpcd(vpcd_options("192.0.2.1:35963", false, None)));
        options.key = KeySource::Command("exit 1".into());
        let log = Log::unwritten(TRACE);
        let served = serve(&options, &log, &vpcd_platform(dial, Recording::new(true)), &Arc::default());
        let Err(Failure::Startup(message)) = served else {
            panic!("serving gave {served:?}");
        };
        assert!(message.starts_with("--vpcd-addr 192.0.2.1:35963: 192.0.2.1:35963 is not a loopback address"), "{message}");
        assert!(!dir.join("s").exists(), "the state directory was not created");
        assert!(accept_now(&vpcd).is_none(), "nothing was dialled");
    }

    /// The fake vpcd's next connection if one is waiting.
    fn accept_now(listener: &TcpListener) -> Option<TcpStream> {
        listener.accept().ok().map(|(stream, _)| stream)
    }

    /// With `--vpcd-allow-remote` the remote address is used, warned about once at the
    /// default level, and the peer check still gets the connection's real addresses (here
    /// the fake vpcd on loopback behind the disguise).
    #[test]
    fn a_remote_vpcd_address_allowed_explicitly_is_warned_about_once_and_serves() {
        let dir = TempDir::new();
        let vpcd = fake_vpcd();
        let dial = vpcd.local_addr().expect("bound");
        let mut options = run_options(&dir, TransportOptions::Vpcd(vpcd_options("192.0.2.1:35963", true, None)));
        options.verbosity = 0;
        let control = dir.join("s").join(CONTROL_SOCKET);
        let check = Recording::new(true);
        let seen = Arc::clone(&check);
        let log = Log::unwritten(0);
        let served_log = log.clone();
        let shutdowns = Arc::new(Shutdowns::default());
        let held_by_serve = Arc::clone(&shutdowns);
        let served = thread::spawn(move || serve(&options, &served_log, &vpcd_platform(dial, check), &held_by_serve));

        let mut card = accept(&vpcd).expect("the transport connects through the disguise");
        assert_eq!(get_atr(&mut card).expect("the card answers"), DeviceProfile::own(0).atr);
        let local = card.peer_addr().expect("connected");
        assert_eq!(lock(&seen.seen).clone(), [(local, dial)], "the check saw the connection's own addresses");
        drop(card);
        let mut again = accept(&vpcd).expect("the card comes back after vpcd dropped it");
        assert_eq!(get_atr(&mut again).expect("the card answers"), DeviceProfile::own(0).atr);

        let (reply, _held) = control_request(&control, "shutdown").expect("the control socket answers");
        assert_eq!(reply, ["ok"]);
        let served = served.join().expect("serve does not panic");
        assert!(served.is_ok(), "{served:?}");
        shutdowns.answer(Outcome::Stopped);
        let lines = log.take_lines();
        let warning = "vpcd: warning: 192.0.2.1:35963 is not a loopback address; APDUs (PINs and keys among them) \
                       travel to it unencrypted, and whatever listens there is not checked";
        assert_eq!(lines.iter().filter(|line| line.contains(warning)).count(), 1, "{lines:#?}");
        assert!(lines.iter().any(|line| line.contains("serving: vpcd card for 192.0.2.1:35963")), "{lines:#?}");
    }

    /// A refused peer at the default log level: said once for the series, its connections
    /// closed without a byte, the card never in the reader.
    #[test]
    fn a_refused_vpcd_peer_is_logged_once_at_the_default_level_and_gets_no_bytes() {
        let dir = TempDir::new();
        let vpcd = fake_vpcd();
        let dial = vpcd.local_addr().expect("bound");
        let mut options = run_options(&dir, TransportOptions::Vpcd(VpcdOptions::at(dial.to_string())));
        options.verbosity = 0;
        let control = dir.join("s").join(CONTROL_SOCKET);
        let log = Log::unwritten(0);
        let served_log = log.clone();
        let shutdowns = Arc::new(Shutdowns::default());
        let held_by_serve = Arc::clone(&shutdowns);
        let platform_check = Recording::new(false);
        let served =
            thread::spawn(move || serve(&options, &served_log, &vpcd_platform(dial, platform_check), &held_by_serve));

        for _ in 0..2 {
            let mut refused = accept(&vpcd).expect("the transport connects");
            let mut rest = Vec::new();
            refused.read_to_end(&mut rest).expect("the connection is closed");
            assert!(rest.is_empty(), "a refused peer gets no byte: {rest:02X?}");
        }
        assert_eq!(attached(&control).as_deref(), Some("false"), "no card in the reader");
        let (reply, _held) = control_request(&control, "shutdown").expect("the control socket answers");
        assert_eq!(reply, ["ok"]);
        let served = served.join().expect("serve does not panic");
        assert!(served.is_ok(), "{served:?}");
        shutdowns.answer(Outcome::Stopped);
        let lines = log.take_lines();
        let refusal = format!(
            "vpcd: the peer on {dial} is owned by uid 1001, not an allowed uid (4242); refusing the connection, \
             retrying every second"
        );
        assert_eq!(lines.iter().filter(|line| line.contains(&refusal)).count(), 1, "{lines:#?}");
    }

    /// "First-enumeration failure handling must cover every member": a uhid member that
    /// cannot open its devices stops a `uhid,vpcd` startup with exit 2, the failure named
    /// with its member, and the shutdown drops the vpcd member too (its card, if it got
    /// in, is removed again).
    #[test]
    fn a_failing_uhid_member_stops_a_uhid_vpcd_startup_and_takes_the_vpcd_member_down() {
        let dir = TempDir::new();
        let vpcd = fake_vpcd();
        let addr = vpcd.local_addr().expect("bound");
        let missing = dir.join("no-uhid");
        let options = run_options_with(
            &dir,
            vec![TransportOptions::Uhid { path: missing.clone() }, TransportOptions::Vpcd(VpcdOptions::at(addr.to_string()))],
        );
        let log = Log::unwritten(TRACE);
        let host = Platform::host();
        let platform = linux(move || (host.uhid)(&missing), || Box::new(NoEp0::default()));
        let served = serve(&options, &log, &platform, &Arc::default());
        let Err(Failure::Startup(message)) = served else {
            panic!("serving gave {served:?}");
        };
        assert!(message.starts_with("cannot set up the uhid,vpcd transport: uhid: "), "{message}");
        assert!(message.contains("uhid: fido: cannot open a UHID device") && message.contains("uhid: otp: "), "{message}");
        assert!(!dir.join("s").join(CONTROL_SOCKET).exists(), "the control socket was removed");
        // The vpcd member may have connected before the shutdown; then the card is gone.
        if let Ok((mut card, _)) = vpcd.accept() {
            card.set_nonblocking(false).expect("the connection can block");
            card.set_read_timeout(Some(WAIT)).expect("a timeout can be set");
            let mut rest = [0; 1];
            assert_eq!(card.read(&mut rest).ok(), Some(0), "the vpcd member was dropped");
        }
        thread::sleep(lk_vpcd::RETRY_INTERVAL * 2);
        assert!(vpcd.accept().is_err(), "nothing connects again after the shutdown");
        let lines = log.take_lines();
        assert!(!lines.iter().any(|line| line.starts_with("serving:")), "{lines:#?}");
    }
}
