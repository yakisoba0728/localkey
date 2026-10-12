//! The gadget transport (`docs/PROGRAM.md` "lk-gadget"): the runner's [`Transport`] on a
//! ConfigFS + FunctionFS composite gadget.
//!
//! Threads:
//!
//! - the runner thread calls [`Transport::enumerate`] (ConfigFS, mount, `ep0` blobs,
//!   endpoint files, bind; at re-enumeration first the teardown of the session) and
//!   [`Transport::deliver`], which only queues;
//! - the `ep0` thread reads events and answers control requests through [`Control`];
//! - one reader per OUT endpoint (FIDO interrupt OUT, CCID bulk OUT through the
//!   [`Reassembler`]) sends inputs to the runner;
//! - one writer per IN endpoint drains a bounded queue, so `deliver` never blocks.
//!
//! A session is one binding of the gadget: it starts with the UDC bind and ends with the
//! unbind. The unbind is what ends the threads: f_fs reports `UNBIND` on `ep0`, which
//! ends the `ep0` thread, and disables the endpoints, which fails their transfers in
//! flight (`ffs_func_unbind`). Closing a file from another thread would not interrupt a
//! read in progress, and closing the last one while bound makes f_fs unregister the
//! gadget itself (`ffs_closed` → `unregister_gadget_item`), so files are closed only after
//! the unbind, by the threads that own them as they end.
//!
//! Whoever unbound, `UNBIND` ends the whole session: after an unbind the transport did
//! not cause (an administrator, or the UDC going away) the `ep0` thread raises the
//! session's stop flag and closes the IN queues, so every thread ends and closes its
//! file. With the last file closed f_fs resets (`ffs_data_closed` → `ffs_data_reset`;
//! `ffs_closed` clears `desc_ready`), so a bind from outside fails with `ENODEV`
//! (`ffs_do_functionfs_bind`) instead of presenting a function nobody serves. Keeping
//! `ep0` open to wait for such a bind would not work: a blocked `ep0` read ends only on
//! an event, an unbound gadget has none, so the transport's next stop could not end that
//! thread, its file would stay open and f_fs would never return to "read descriptors".
//!
//! A re-enumeration ends the session in two phases. First it drains: the threads keep
//! running until the host has taken what the runner handed over before the reboot, the
//! queued FIDO IN and CCID bulk IN data (the response to the command that caused it) and
//! the answer to an OTP GET_REPORT in progress (the status read `lk_device` answers right
//! before an OTP HID Management reboot), at most [`DRAIN_TIMEOUT`]. The runner is inside
//! [`Transport::enumerate`] meanwhile and answers no marker, so a GET_REPORT in progress
//! takes what the runner delivered (see [`OtpWait`]). Then the stop flag and the unbind
//! end it as above. From the stop flag on, the session passes no bus event (`dummy_hcd`
//! reports `SUSPEND` on every unbind), so nothing of the old session reaches the rebooted
//! device as a bus event.
//!
//! Each OUT reader and the `ep0` thread pace their inputs as the wire transport does
//! (`docs/PROGRAM.md` "Program core as built", lk-wire Backpressure): after every
//! [`INPUT_WINDOW_FRAMES`] inputs or [`INPUT_WINDOW_BYTES`] it sends a `Command::Status`
//! marker and first waits for the previous marker's answer. At most two windows per
//! producer (six in all) wait in the runner's unbounded channel; the rest waits in the
//! endpoint, where the UDC NAKs the host.

use std::fmt;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use lk_core::UsbInterfaces;
use lk_device::{BusEvent, Output, UsbIdentity};
use lk_run::{Command, HostInput, Status, Transport};

use crate::ccid::{Assembled, Reassembler};
use crate::configfs::{ConfigFs, first_udc};
use crate::control::{Action, BusTracker, Control};
use crate::descriptor::{Layout, Role};
use crate::ffs::{self, CtrlRequest, Event};
use crate::io::{Ep0, Ep0File, GadgetIo, KernelIo};

/// How long the `ep0` thread waits for the runner's answer to an OTP GET_REPORT before it
/// stalls the request (`docs/PROGRAM.md`: "bounded, 1 s").
pub const OTP_REPORT_TIMEOUT: Duration = Duration::from_secs(1);
/// How long ending a session may take, in total, for its threads to stop after the
/// unbind. A thread still running then is left behind (with the file it holds).
pub const STOP_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a re-enumeration waits, at most, before its unbind for the host to take what
/// the runner handed the session before the reboot: queued FIDO IN and CCID bulk IN data
/// and the answer to an OTP GET_REPORT in progress (see the module docs). What is still
/// owed then is dropped and reported.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
/// The slice in which an OTP GET_REPORT waits for the runner's marker, so that it notices
/// a drain (the runner answers no marker during one).
const MARKER_SLICE: Duration = Duration::from_millis(10);
/// Reports queued per interrupt IN endpoint (FIDO, OTP keyboard, CCID interrupt). A full
/// queue drops the output: the host is not reading.
pub const IN_QUEUE_REPORTS: usize = 1024;
/// Messages queued for the CCID bulk IN endpoint.
pub const IN_QUEUE_MESSAGES: usize = 64;
/// How long an endpoint thread waits after a failed transfer (the endpoint is disabled,
/// or being disabled and enabled again) before it tries again, unless the host's
/// configuration changes first.
const RETRY_WAIT: Duration = Duration::from_millis(50);
/// How often `ep0` may fail in a row before its thread gives up (a FunctionFS instance
/// that is no longer active).
const EP0_ERROR_LIMIT: u32 = 20;
/// How long opening `ep0` is retried: right after the last file of the previous session
/// is closed f_fs may still be resetting (`ffs_ep0_open` refuses with `EBUSY` while
/// closing).
const EP0_OPEN_RETRY: Duration = Duration::from_millis(500);
/// Inputs per window of one producer (an OUT reader or the `ep0` thread), as lk-wire's
/// `INPUT_WINDOW_FRAMES`: the producer asks the runner to confirm that it has handled
/// the previous window before it sends more than one more (see the module docs).
pub const INPUT_WINDOW_FRAMES: usize = 64;
/// Payload bytes per window of one producer, as lk-wire's `INPUT_WINDOW_BYTES`: a window
/// also ends once its inputs carry this much.
pub const INPUT_WINDOW_BYTES: usize = 256 * 1024;

/// The ConfigFS gadget root of [`GadgetConfig::new`] (`Documentation/usb/gadget_configfs.rst`:
/// ConfigFS mounted at `/sys/kernel/config`, gadgets under `usb_gadget`).
pub const DEFAULT_CONFIGFS_ROOT: &str = "/sys/kernel/config/usb_gadget";
/// The gadget and FunctionFS instance name of [`GadgetConfig::new`].
pub const DEFAULT_NAME: &str = "localkey";

/// The default FunctionFS mount point for instance `function_name`: `/dev/ffs-<name>`, the
/// naming of the examples in `Documentation/usb/functionfs.rst` (`mount -t functionfs mtp
/// /dev/ffs-mtp`).
pub fn default_mount_point(function_name: &str) -> PathBuf {
    PathBuf::from(format!("/dev/ffs-{function_name}"))
}

/// Where the gadget lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GadgetConfig {
    /// The ConfigFS gadget root (`/sys/kernel/config/usb_gadget`).
    pub configfs_root: PathBuf,
    /// The gadget directory name.
    pub gadget_name: String,
    /// The FunctionFS instance: `functions/ffs.<name>` and the `mount` source.
    pub function_name: String,
    /// Where FunctionFS is mounted (created with its parents if missing, and left in
    /// place; the default is [`default_mount_point`]).
    pub mount_point: PathBuf,
    /// The USB device controller to bind to (a name in `/sys/class/udc`).
    pub udc: String,
}

/// Names that go into paths: 1 to 32 of `[A-Za-z0-9_-]` (a function directory name must
/// stay below 40 bytes, `drivers/usb/gadget/configfs.c`).
const MAX_NAME_LEN: usize = 32;

impl GadgetConfig {
    /// The defaults: gadget and function [`DEFAULT_NAME`], mounted at
    /// [`default_mount_point`] (`/dev/ffs-localkey`), under [`DEFAULT_CONFIGFS_ROOT`],
    /// bound to `udc`.
    pub fn new(udc: impl Into<String>) -> GadgetConfig {
        GadgetConfig {
            configfs_root: PathBuf::from(DEFAULT_CONFIGFS_ROOT),
            gadget_name: DEFAULT_NAME.into(),
            function_name: DEFAULT_NAME.into(),
            mount_point: default_mount_point(DEFAULT_NAME),
            udc: udc.into(),
        }
    }

    /// The checks that read the file system but change nothing: the names, that the
    /// ConfigFS root is a directory, and that the gadget directory is absent or the
    /// leftover of an earlier process of this transport ([`ConfigFs::leftover`]), which
    /// the first enumeration removes before it creates the gadget. A daemon calls this
    /// before anything expensive; [`GadgetTransport::with_io`] calls it again.
    pub fn precheck(&self) -> Result<(), GadgetError> {
        self.check()?;
        let root = &self.configfs_root;
        match std::fs::metadata(root) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => {
                let source = io::Error::other("not a directory");
                return Err(GadgetError::Io { path: root.clone(), source });
            }
            Err(source) => return Err(GadgetError::Io { path: root.clone(), source }),
        }
        match ConfigFs::leftover(root, &self.gadget_name, &self.function_name) {
            Ok(_) => Ok(()),
            Err(reason) => Err(GadgetError::Exists { path: root.join(&self.gadget_name), reason }),
        }
    }

    /// The defaults with the first controller in `/sys/class/udc`, if there is one.
    pub fn with_first_udc() -> io::Result<Option<GadgetConfig>> {
        Ok(first_udc(Path::new("/sys/class/udc"))?.map(GadgetConfig::new))
    }

    fn check(&self) -> Result<(), GadgetError> {
        let valid = |name: &str| {
            !name.is_empty()
                && name.len() <= MAX_NAME_LEN
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        };
        if !valid(&self.gadget_name) {
            return Err(GadgetError::Config(format!(
                "gadget name {:?} is not 1-32 of [A-Za-z0-9_-]",
                self.gadget_name
            )));
        }
        if !valid(&self.function_name) {
            return Err(GadgetError::Config(format!(
                "function name {:?} is not 1-32 of [A-Za-z0-9_-]",
                self.function_name
            )));
        }
        if self.udc.is_empty() || self.udc.contains(['\n', '/']) {
            return Err(GadgetError::Config(format!("UDC name {:?} is empty or has a newline or slash", self.udc)));
        }
        Ok(())
    }
}

/// Why the transport cannot be set up.
#[derive(Debug)]
pub enum GadgetError {
    /// An invalid name in [`GadgetConfig`].
    Config(String),
    /// The ConfigFS root cannot be used.
    Io { path: PathBuf, source: io::Error },
    /// The gadget directory exists and is not a leftover of this transport (it is bound,
    /// or holds something this transport does not create; see [`ConfigFs::leftover`]);
    /// it is left alone.
    Exists { path: PathBuf, reason: String },
}

impl fmt::Display for GadgetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GadgetError::Config(reason) => f.write_str(reason),
            GadgetError::Io { path, source } => write!(f, "{}: {source}", path.display()),
            GadgetError::Exists { path, reason } => write!(
                f,
                "{}: exists and is not a leftover of this transport ({reason}); choose another name, or remove that \
                 gadget (write an empty line to UDC, umount its FunctionFS, remove the links in configs/*, then rmdir \
                 configs/*/strings/*, configs/*, functions/*, strings/*, and the gadget)",
                path.display()
            ),
        }
    }
}

impl std::error::Error for GadgetError {}

/// Receives [`GadgetEvent`]s, for the daemon's log. It runs on the transport's threads,
/// so it must be quick and must not call into the transport.
pub type Observer = Arc<dyn Fn(&GadgetEvent) + Send + Sync>;

/// What happened on the gadget. Never carries payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GadgetEvent {
    /// The gadget is being presented with this product ID and interface set.
    Enumerated { product_id: u16, interfaces: UsbInterfaces },
    /// The gadget was bound to the UDC.
    Bound { udc: String },
    /// The session ended (unbind).
    Unbound,
    /// The first enumeration found the leftover of an earlier process of this transport
    /// (one killed before its teardown) and removed it: FunctionFS unmounted where it was
    /// mounted, the ConfigFS tree taken apart (see [`ConfigFs::leftover`]).
    Reclaimed { gadget: PathBuf, unmounted: Vec<PathBuf> },
    /// A bus event went to the runner.
    Bus(BusEvent),
    /// A control request and what was done with it (`reply`, `ack`, `receive`, `stall`).
    Setup { request_type: u8, request: u8, value: u16, index: u16, length: u16, outcome: &'static str },
    /// Data from the host went to the runner.
    Received { endpoint: Role, size: usize },
    /// Data was written to an IN endpoint.
    Sent { endpoint: Role, size: usize },
    /// An output or input was dropped (queue full, endpoint disabled, malformed).
    Dropped { endpoint: Role, reason: String },
    /// Something failed; the transport carries on as far as it can.
    Failed(String),
}

impl fmt::Display for GadgetEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GadgetEvent::Enumerated { product_id, interfaces } => {
                let names: Vec<&str> = [(interfaces.otp, "otp"), (interfaces.fido, "fido"), (interfaces.ccid, "ccid")]
                    .into_iter()
                    .filter_map(|(on, name)| on.then_some(name))
                    .collect();
                write!(f, "gadget: enumerating as product 0x{product_id:04x} ({})", names.join(","))
            }
            GadgetEvent::Bound { udc } => write!(f, "gadget: bound to {udc}"),
            GadgetEvent::Unbound => f.write_str("gadget: unbound"),
            GadgetEvent::Reclaimed { gadget, unmounted } => {
                let unmounted: Vec<String> = unmounted.iter().map(|path| path.display().to_string()).collect();
                write!(f, "gadget: removed the leftover gadget {} of an earlier process", gadget.display())?;
                if unmounted.is_empty() {
                    f.write_str(" (FunctionFS was not mounted)")
                } else {
                    write!(f, " (unmounted FunctionFS at {})", unmounted.join(", "))
                }
            }
            GadgetEvent::Bus(event) => write!(f, "gadget: bus {event:?}"),
            GadgetEvent::Setup { request_type, request, value, index, length, outcome } => write!(
                f,
                "gadget: setup {request_type:02x} {request:02x} value 0x{value:04x} index {index} length {length}: {outcome}"
            ),
            GadgetEvent::Received { endpoint, size } => write!(f, "gadget: <- {}, {size} bytes", endpoint.name()),
            GadgetEvent::Sent { endpoint, size } => write!(f, "gadget: -> {}, {size} bytes", endpoint.name()),
            GadgetEvent::Dropped { endpoint, reason } => write!(f, "gadget: {} dropped: {reason}", endpoint.name()),
            GadgetEvent::Failed(reason) => write!(f, "gadget: {reason}"),
        }
    }
}

/// The ConfigFS + FunctionFS gadget transport.
///
/// - [`GadgetTransport::new`] checks the configuration; nothing is created until the
///   runner calls [`Transport::enumerate`].
/// - `enumerate` removes a leftover of an earlier process ([`ConfigFs::leftover`]),
///   creates the ConfigFS tree and mounts FunctionFS (first time) or rewrites
///   the IDs and strings (re-enumeration, after ending the session), writes the
///   descriptors and strings to `ep0`, opens the endpoint files in descriptor order,
///   links the function into `configs/c.1`, binds the UDC and starts the threads.
/// - `deliver` queues IN data; `Output::OtpFeature` answers a pending GET_REPORT.
/// - Dropping the transport ends the session (unbind), unmounts FunctionFS and removes
///   the ConfigFS tree in reverse order of creation; failures are reported, not fatal.
pub struct GadgetTransport {
    config: GadgetConfig,
    io: Box<dyn GadgetIo>,
    shared: Arc<Shared>,
    gadget: Option<Gadget>,
    session: Option<Session>,
}

impl fmt::Debug for GadgetTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GadgetTransport")
            .field("gadget", &self.config.gadget_name)
            .field("udc", &self.config.udc)
            .field("created", &self.gadget.is_some())
            .field("bound", &self.session.is_some())
            .field("configured", &self.configured())
            .finish_non_exhaustive()
    }
}

/// The ConfigFS tree and the mount, which outlive sessions.
#[derive(Debug)]
struct Gadget {
    configfs: ConfigFs,
    mounted: bool,
    linked: bool,
}

/// State shared by the runner thread and the transport's threads.
struct Shared {
    runner: Sender<Command>,
    observer: Option<Observer>,
    /// The last `Output::OtpFeature` delivered, for the GET_REPORT in progress.
    otp_feature: Mutex<Option<lk_crypto::SecretBytes>>,
}

impl Shared {
    fn notify(&self, event: GadgetEvent) {
        if let Some(observer) = &self.observer {
            observer(&event);
        }
    }

    fn send(&self, input: HostInput) -> bool {
        self.runner.send(Command::Input(input)).is_ok()
    }

    fn otp_feature(&self) -> MutexGuard<'_, Option<lk_crypto::SecretBytes>> {
        // One assignment per update: a panic elsewhere cannot leave it inconsistent.
        self.otp_feature.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One binding of the gadget.
struct Session {
    udc_file: PathBuf,
    state: Arc<SessionState>,
    workers: Vec<Worker>,
}

/// What the session's threads share: the stop flag, whether the host has the function
/// configured, a counter of configuration changes that endpoint threads wait on after a
/// failed transfer, the IN queues, and what the session owes the host for a drain.
///
/// `configured` is per session, so a thread of a session that is ending (or was left
/// behind) can never change what a later session reports.
#[derive(Debug, Default)]
struct SessionState {
    stopping: AtomicBool,
    configured: AtomicBool,
    generation: Mutex<u64>,
    changed: Condvar,
    /// The IN queues by endpoint role. Closing them (dropping the senders) ends the
    /// writer threads once they are idle.
    queues: Mutex<Vec<(Role, SyncSender<lk_crypto::SecretBytes>)>>,
    /// Raised when a re-enumeration starts draining the session (see the module docs).
    draining: AtomicBool,
    owed: Mutex<Owed>,
    /// Signalled whenever `owed` shrinks.
    settled: Condvar,
}

/// What a session owes the host: responses queued and not yet written, and whether the
/// `ep0` thread is answering a request that waits for the runner.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Owed {
    /// FIDO IN and CCID bulk IN items queued and not yet written (or failed).
    responses: usize,
    /// An OTP GET_REPORT is between its SETUP and its reply or stall.
    control: bool,
}

impl Owed {
    fn is_settled(&self) -> bool {
        self.responses == 0 && !self.control
    }
}

/// Whether the items queued for an endpoint with `role` are responses that a drain waits
/// for: FIDO IN and CCID bulk IN. The interrupt endpoints (keyboard, CCID slot change)
/// carry no responses, and the host may not be reading them at all.
fn is_response(role: Role) -> bool {
    matches!(role, Role::FidoIn | Role::CcidBulkIn)
}

impl SessionState {
    fn stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }

    fn configured(&self) -> bool {
        self.configured.load(Ordering::SeqCst)
    }

    fn queues(&self) -> MutexGuard<'_, Vec<(Role, SyncSender<lk_crypto::SecretBytes>)>> {
        // Pushes and a clear only: a panic elsewhere cannot leave it inconsistent.
        self.queues.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Drop the IN queues: a writer ends after the items already queued, at the first
    /// one it finds the stop flag raised.
    fn close_queues(&self) {
        self.queues().clear();
    }

    fn generation(&self) -> u64 {
        *self.generation.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The host's configuration changed (or the session is stopping): wake the waiters.
    fn bump(&self) {
        *self.generation.lock().unwrap_or_else(PoisonError::into_inner) += 1;
        self.changed.notify_all();
    }

    fn stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        self.bump();
    }

    /// Wait until the generation moves past `seen`, the session stops, or `timeout`.
    fn wait_change(&self, seen: u64, timeout: Duration) {
        let guard = self.generation.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = self
            .changed
            .wait_timeout_while(guard, timeout, |generation| *generation == seen && !self.stopping())
            .unwrap_or_else(PoisonError::into_inner);
    }

    fn draining(&self) -> bool {
        self.draining.load(Ordering::SeqCst)
    }

    fn owed(&self) -> MutexGuard<'_, Owed> {
        // Counter updates only: a panic elsewhere cannot leave it inconsistent.
        self.owed.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// One more response is queued (counted before it is queued, so the writer can never
    /// pay it first).
    fn owe_response(&self) {
        self.owed().responses += 1;
    }

    /// A response was written, failed, or not queued after all.
    fn paid_response(&self) {
        let mut owed = self.owed();
        owed.responses = owed.responses.saturating_sub(1);
        drop(owed);
        self.settled.notify_all();
    }

    /// The `ep0` thread starts (true) or ends (false) answering a request that waits for
    /// the runner.
    fn answering(&self, busy: bool) {
        self.owed().control = busy;
        self.settled.notify_all();
    }

    /// Start draining and wait until nothing is owed or `timeout`; what is still owed.
    fn drain(&self, timeout: Duration) -> Owed {
        self.draining.store(true, Ordering::SeqCst);
        self.bump();
        let guard = self.owed();
        let (owed, _) = self
            .settled
            .wait_timeout_while(guard, timeout, |owed| !owed.is_settled())
            .unwrap_or_else(PoisonError::into_inner);
        *owed
    }
}

/// A thread with a signal that it ended, so it can be joined within a deadline.
struct Worker {
    name: String,
    handle: JoinHandle<()>,
    done: Receiver<()>,
}

impl Worker {
    fn spawn(name: String, body: impl FnOnce() + Send + 'static) -> io::Result<Worker> {
        let (signal, done) = mpsc::channel::<()>();
        let handle = thread::Builder::new().name(name.clone()).spawn(move || {
            // Dropped when the body returns or unwinds: `done` then disconnects.
            let _signal = signal;
            body();
        })?;
        Ok(Worker { name, handle, done })
    }

    /// Join if the thread ends by `deadline`; false if it is left running.
    fn join_by(self, deadline: Instant) -> bool {
        match self.done.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                let _ = self.handle.join();
                true
            }
            Err(RecvTimeoutError::Timeout) => false,
        }
    }
}

impl GadgetTransport {
    /// The transport with the real kernel interface ([`KernelIo`]). Inputs go to the
    /// runner through `runner` (`lk_run::Runner::sender`).
    pub fn new(config: GadgetConfig, runner: Sender<Command>) -> Result<GadgetTransport, GadgetError> {
        GadgetTransport::with_io(config, runner, Box::new(KernelIo), None)
    }

    /// The transport with another I/O implementation and an observer.
    ///
    /// Makes the checks of [`GadgetConfig::precheck`]: the names, that the ConfigFS root
    /// is a directory, and that the gadget directory is absent or a leftover of this
    /// transport. Nothing is changed before the first enumeration.
    pub fn with_io(
        config: GadgetConfig,
        runner: Sender<Command>,
        io: Box<dyn GadgetIo>,
        observer: Option<Observer>,
    ) -> Result<GadgetTransport, GadgetError> {
        config.precheck()?;
        let shared = Shared { runner, observer, otp_feature: Mutex::new(None) };
        Ok(GadgetTransport { config, io, shared: Arc::new(shared), gadget: None, session: None })
    }

    /// Whether the host has the current session's function configured.
    fn configured(&self) -> bool {
        self.session.as_ref().is_some_and(|session| session.state.configured())
    }

    /// End the session: with `drain` (a re-enumeration) first let the host take what is
    /// owed (see the module docs; at most [`DRAIN_TIMEOUT`]), then stop flag, unbind (the
    /// kernel ends `ep0` and the transfers in flight), close the IN queues, and join the
    /// threads within [`STOP_TIMEOUT`]. The threads close their files as they end. Taking
    /// the session first is what makes [`Transport::attached`] false from here on,
    /// whatever its threads still do. A session that ended itself (an unbind by someone
    /// else) has nothing to drain.
    fn stop_session(&mut self, drain: bool) {
        let Some(session) = self.session.take() else {
            return;
        };
        if drain && !session.state.stopping() {
            let owed = session.state.drain(DRAIN_TIMEOUT);
            if owed.responses > 0 {
                self.shared.notify(GadgetEvent::Failed(format!(
                    "re-enumeration: the host did not read {} queued response(s) within {DRAIN_TIMEOUT:?}; dropped",
                    owed.responses
                )));
            }
            if owed.control {
                self.shared.notify(GadgetEvent::Failed(format!(
                    "re-enumeration: the OTP GET_REPORT in progress was not answered within {DRAIN_TIMEOUT:?}"
                )));
            }
        }
        session.state.stop();
        if let Err(error) = self.io.unbind(&session.udc_file) {
            // ENODEV: the gadget was unbound already (externally, or by f_fs itself).
            self.shared.notify(GadgetEvent::Failed(format!("unbind: {error}")));
        }
        session.state.close_queues();
        let deadline = Instant::now() + STOP_TIMEOUT;
        for worker in session.workers {
            let name = worker.name.clone();
            if !worker.join_by(deadline) {
                self.shared.notify(GadgetEvent::Failed(format!("thread {name} did not stop; its file stays open")));
            }
        }
        self.shared.notify(GadgetEvent::Unbound);
    }

    /// Remove the leftover of an earlier process of this transport, if the gadget
    /// directory holds one ([`ConfigFs::leftover`]; anything else is refused and left
    /// alone): unmount the FunctionFS instance wherever it is mounted, then take the tree
    /// apart in reverse order of creation. A FunctionFS that cannot be unmounted (a file
    /// still open: a process still serves it) leaves everything in place, because
    /// removing the function directory under a live mount is unsafe (see [`Drop`]).
    fn reclaim(&mut self) -> Result<(), String> {
        let config = &self.config;
        let gadget_dir = config.configfs_root.join(&config.gadget_name);
        let leftover = ConfigFs::leftover(&config.configfs_root, &config.gadget_name, &config.function_name)
            .map_err(|reason| {
                format!("{}: exists and is not a leftover of this transport ({reason})", gadget_dir.display())
            })?;
        let Some(mut leftover) = leftover else {
            return Ok(());
        };
        let unmounted = self.io.functionfs_mounts(&config.function_name).map_err(|error| {
            format!(
                "leftover gadget {}: cannot tell where FunctionFS {} is mounted: {error}",
                gadget_dir.display(),
                config.function_name
            )
        })?;
        for mount_point in unmounted.iter().rev() {
            self.io.unmount(mount_point).map_err(|error| {
                format!(
                    "leftover gadget {}: umount {}: {error}; is another process serving it? Left in place",
                    gadget_dir.display(),
                    mount_point.display()
                )
            })?;
        }
        // Every step is attempted; a missing entry is gone already.
        let failed = leftover.teardown().into_iter().find_map(|step| match step.result {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Some((step.removed, error)),
            _ => None,
        });
        if let Some((removed, error)) = failed {
            return Err(format!("leftover gadget {}: remove {removed:?}: {error}", gadget_dir.display()));
        }
        self.shared.notify(GadgetEvent::Reclaimed { gadget: gadget_dir, unmounted });
        Ok(())
    }

    /// Remove a leftover of this transport ([`GadgetTransport::reclaim`]), create the
    /// ConfigFS tree and mount FunctionFS; on failure undo what was done.
    fn create_gadget(&mut self, identity: &UsbIdentity, layout: &Layout) -> Result<(), String> {
        self.reclaim()?;
        let mut configfs =
            ConfigFs::new(&self.config.configfs_root, &self.config.gadget_name, &self.config.function_name);
        if let Err(error) = configfs.create(identity, &layout.config.header) {
            self.remove_tree(&mut configfs);
            return Err(format!("configfs: {error}"));
        }
        if let Err(error) = self.io.mount(&self.config.function_name, &self.config.mount_point) {
            self.remove_tree(&mut configfs);
            return Err(format!("mount {}: {error}", self.config.mount_point.display()));
        }
        self.gadget = Some(Gadget { configfs, mounted: true, linked: false });
        Ok(())
    }

    fn remove_tree(&self, configfs: &mut ConfigFs) {
        for step in configfs.teardown() {
            if let Err(error) = step.result {
                self.shared.notify(GadgetEvent::Failed(format!("remove {:?}: {error}", step.removed)));
            }
        }
    }

    /// Open `ep0`, retrying for [`EP0_OPEN_RETRY`].
    fn open_ep0(&mut self) -> io::Result<Box<dyn Ep0File>> {
        let deadline = Instant::now() + EP0_OPEN_RETRY;
        loop {
            match self.io.open_ep0(&self.config.mount_point) {
                Ok(file) => return Ok(file),
                Err(error) if Instant::now() >= deadline => return Err(error),
                Err(_) => thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    /// Write the blobs, open the endpoints, link, bind, start the threads.
    fn start_session(&mut self, layout: &Layout) -> Result<(), String> {
        let mut ep0 = Ep0::new(self.open_ep0().map_err(|e| format!("open ep0: {e}"))?);
        ep0.write_blob(&ffs::descriptors_blob(&layout.config)).map_err(|e| format!("ep0 descriptors: {e}"))?;
        let strings = ffs::strings_blob(ffs::LANG_EN_US, &[]).unwrap_or_default();
        ep0.write_blob(&strings).map_err(|e| format!("ep0 strings: {e}"))?;
        let mount_point = self.config.mount_point.clone();
        let mut readers = Vec::new();
        let mut writers = Vec::new();
        for endpoint in &layout.endpoints {
            let index = endpoint.file_index;
            if endpoint.role.is_in() {
                let file = self.io.open_in(&mount_point, index).map_err(|e| format!("open ep{index}: {e}"))?;
                writers.push((*endpoint, file));
            } else {
                let file = self.io.open_out(&mount_point, index).map_err(|e| format!("open ep{index}: {e}"))?;
                readers.push((*endpoint, file));
            }
        }
        let gadget = self.gadget.as_mut().ok_or("no gadget")?;
        if !gadget.linked {
            gadget.configfs.link().map_err(|e| format!("configfs: {e}"))?;
            gadget.linked = true;
        }
        let udc_file = gadget.configfs.udc_file();
        self.io.bind(&udc_file, &self.config.udc).map_err(|e| format!("bind {}: {e}", self.config.udc))?;
        self.shared.notify(GadgetEvent::Bound { udc: self.config.udc.clone() });
        let state = Arc::new(SessionState::default());
        let mut session = Session { udc_file, state: Arc::clone(&state), workers: Vec::new() };
        let started = self.spawn_threads(&mut session, layout, ep0, readers, writers);
        self.session = Some(session);
        if let Err(error) = started {
            self.stop_session(false);
            return Err(format!("cannot start a thread: {error}"));
        }
        Ok(())
    }

    fn spawn_threads(
        &self,
        session: &mut Session,
        layout: &Layout,
        ep0: Ep0<Box<dyn Ep0File>>,
        readers: Vec<(crate::descriptor::EndpointLayout, Box<dyn Read + Send>)>,
        writers: Vec<(crate::descriptor::EndpointLayout, Box<dyn Write + Send>)>,
    ) -> io::Result<()> {
        for (endpoint, file) in writers {
            let capacity = if endpoint.role == Role::CcidBulkIn { IN_QUEUE_MESSAGES } else { IN_QUEUE_REPORTS };
            let (queue, items) = mpsc::sync_channel(capacity);
            session.state.queues().push((endpoint.role, queue));
            // A CCID message that fills whole packets needs a zero-length packet so the
            // host's larger bulk read completes (USB 2.0 §5.8.3).
            let zlp = (endpoint.role == Role::CcidBulkIn).then_some(usize::from(endpoint.max_packet_size));
            let (shared, state) = (Arc::clone(&self.shared), Arc::clone(&session.state));
            let name = format!("lkg-{}", endpoint.role.name());
            session.workers.push(Worker::spawn(name, move || {
                write_loop(file, &items, endpoint.role, zlp, &shared, &state);
            })?);
        }
        for (endpoint, file) in readers {
            let (shared, state) = (Arc::clone(&self.shared), Arc::clone(&session.state));
            let name = format!("lkg-{}", endpoint.role.name());
            let packet = usize::from(endpoint.max_packet_size);
            // dwMaxCCIDMessageLength: the whole message, header included (see [`crate::ccid`]).
            let ccid_max = layout.ccid_max_message_length;
            let worker = if endpoint.role == Role::CcidBulkOut {
                Worker::spawn(name, move || ccid_read_loop(file, Reassembler::new(packet, ccid_max), &shared, &state))?
            } else {
                Worker::spawn(name, move || fido_read_loop(file, &shared, &state))?
            };
            session.workers.push(worker);
        }
        let (shared, state) = (Arc::clone(&self.shared), Arc::clone(&session.state));
        let control = Control::new(layout);
        session.workers.push(Worker::spawn("lkg-ep0".into(), move || {
            let (bus, otp, pacer) = (BusTracker::default(), OtpWait::default(), Pacer::default());
            Ep0Loop { ep0, control, bus, otp, pacer, shared, state }.run();
        })?);
        Ok(())
    }

    /// Queue IN data for the endpoint with `role`; dropped without a session, without
    /// that endpoint, after the session ended, or when its queue is full. A response
    /// ([`is_response`]) is owed from here until its writer has handled it.
    fn queue(&self, role: Role, data: Vec<u8>) {
        let data = lk_crypto::SecretBytes::new(data);
        let Some(session) = &self.session else {
            return;
        };
        let state = &session.state;
        let full = {
            let queues = state.queues();
            let Some((_, queue)) = queues.iter().find(|(r, _)| *r == role) else {
                return;
            };
            if is_response(role) {
                state.owe_response();
            }
            let result = queue.try_send(data);
            if result.is_err() && is_response(role) {
                state.paid_response();
            }
            matches!(result, Err(TrySendError::Full(_)))
        };
        if full {
            self.shared.notify(GadgetEvent::Dropped { endpoint: role, reason: "queue full".into() });
        }
    }
}

impl Transport for GadgetTransport {
    /// End the session if there is one (draining it first, see the module docs), then
    /// present `identity`: ConfigFS (created the first time, IDs and strings rewritten
    /// after), FunctionFS mounted once, `ep0` blobs, endpoint files, bind, threads. A
    /// failure is reported to the observer and leaves the gadget unbound until the next
    /// enumeration.
    fn enumerate(&mut self, identity: &UsbIdentity) {
        self.stop_session(true);
        let layout = match Layout::from_identity(identity) {
            Ok(layout) => layout,
            Err(error) => {
                self.shared.notify(GadgetEvent::Failed(format!("descriptor: {error}")));
                return;
            }
        };
        self.shared
            .notify(GadgetEvent::Enumerated { product_id: identity.product_id, interfaces: layout.interface_set() });
        let prepared = match self.gadget.as_mut() {
            None => self.create_gadget(identity, &layout),
            Some(gadget) => gadget.configfs.update(identity).map_err(|e| format!("configfs: {e}")),
        };
        if let Err(reason) = prepared.and_then(|()| self.start_session(&layout)) {
            self.shared.notify(GadgetEvent::Failed(reason));
        }
    }

    fn deliver(&mut self, mut output: Output) {
        match &mut output {
            Output::FidoReport(report) => self.queue(Role::FidoIn, report.to_vec()),
            Output::OtpKeyboard(report) => self.queue(Role::OtpIn, report.to_vec()),
            Output::Ccid(message) => self.queue(Role::CcidBulkIn, std::mem::take(message)),
            Output::CcidInterrupt(message) => self.queue(Role::CcidInterruptIn, std::mem::take(message)),
            Output::OtpFeature(report) => *self.shared.otp_feature() = Some(lk_crypto::SecretBytes::from_slice(report)),
            Output::PresenceIndicator(_) | Output::Reenumerate(_) => {}
        }
    }

    /// Whether the host has the current session's function configured.
    fn attached(&self) -> Option<bool> {
        Some(self.configured())
    }
}

impl Drop for GadgetTransport {
    /// Ends the session without draining: the runner is shutting down and delivers
    /// nothing more.
    fn drop(&mut self) {
        self.stop_session(false);
        let Some(mut gadget) = self.gadget.take() else {
            return;
        };
        if gadget.mounted
            && let Err(error) = self.io.unmount(&self.config.mount_point)
        {
            // Removing the function directory under a live mount is asking for trouble;
            // the tree is left for the user to remove.
            self.shared.notify(GadgetEvent::Failed(format!(
                "umount {}: {error}; {} left in place",
                self.config.mount_point.display(),
                gadget.configfs.gadget_dir().display()
            )));
            return;
        }
        self.remove_tree(&mut gadget.configfs);
    }
}

/// The `ep0` thread.
struct Ep0Loop {
    ep0: Ep0<Box<dyn Ep0File>>,
    control: Control,
    bus: BusTracker,
    otp: OtpWait,
    pacer: Pacer,
    shared: Arc<Shared>,
    state: Arc<SessionState>,
}

impl Ep0Loop {
    /// Read events until `UNBIND` (the session is over, whoever unbound), the stop flag,
    /// or [`EP0_ERROR_LIMIT`] failed reads in a row; then end the session.
    fn run(mut self) {
        let mut errors = 0u32;
        let reason = 'session: loop {
            if self.state.stopping() {
                break "stopped";
            }
            let events = match self.ep0.read_events() {
                Ok(events) => events,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    if error.kind() == io::ErrorKind::InvalidData {
                        self.shared.notify(GadgetEvent::Failed(error.to_string()));
                    }
                    errors += 1;
                    if errors >= EP0_ERROR_LIMIT {
                        break "ep0 keeps failing";
                    }
                    self.state.wait_change(self.state.generation(), RETRY_WAIT);
                    continue;
                }
            };
            errors = 0;
            for event in events {
                if !self.event(event) {
                    break 'session "unbound by someone else";
                }
            }
        };
        self.end(reason);
    }

    /// The thread is ending: the host no longer has this session configured. Unless the
    /// transport is stopping the session itself (it closes the queues after its unbind),
    /// end the whole session, so every thread closes its file and f_fs can reset (see
    /// the module docs). After [`EP0_ERROR_LIMIT`] failures the gadget may still be
    /// bound; closing the last file then makes f_fs unregister it (`ffs_closed`).
    fn end(&self, reason: &str) {
        self.state.configured.store(false, Ordering::SeqCst);
        self.state.bump();
        if self.state.stopping() {
            return;
        }
        self.shared.notify(GadgetEvent::Failed(format!(
            "{reason}: the session ends and its FunctionFS files are closed; the gadget stays unbound until the next \
             enumeration"
        )));
        self.state.stop();
        self.state.close_queues();
    }

    /// Handle one event; false at `UNBIND`.
    fn event(&mut self, event: Event) -> bool {
        if let Event::Setup(request) = event {
            self.setup(&request);
            return true;
        }
        let was_enabled = self.bus.enabled();
        // Once the transport ends the session, its events are artefacts of the unbind
        // (`dummy_hcd` reports SUSPEND before UNBIND) and must not reach the device, which
        // is the rebooted one by the time the runner reads its channel again.
        if let Some(bus_event) = self.bus.event(&event)
            && !self.state.stopping()
        {
            if matches!(bus_event, BusEvent::Reset | BusEvent::PowerCycle) {
                self.control.reset();
            }
            self.shared.notify(GadgetEvent::Bus(bus_event));
            self.shared.send(HostInput::Bus(bus_event));
        }
        if self.bus.enabled() != was_enabled {
            self.state.configured.store(self.bus.enabled(), Ordering::SeqCst);
            self.state.bump();
        }
        event != Event::Unbind
    }

    /// Answer one control request; exactly one data-stage operation on `ep0` (repeated
    /// only after `EINTR`, see [`Ep0`]). An input sent to the runner is counted into the
    /// pacing window once the control transfer is over.
    fn setup(&mut self, request: &CtrlRequest) {
        let mut sent = None;
        let outcome = match self.control.setup(request) {
            Action::Reply(data) => {
                let _ = self.ep0.reply(&data, request.length);
                "reply"
            }
            Action::Ack(input) => {
                if let Some(input) = input {
                    self.shared.send(input);
                    sent = Some(0);
                }
                let _ = self.ep0.receive(0);
                "ack"
            }
            Action::Receive { length, then } => {
                if let Ok(data) = self.ep0.receive(length).map(lk_crypto::SecretBytes::new)
                    && let Some(input) = then.input(&data)
                {
                    self.shared.send(input);
                    sent = Some(data.len());
                }
                "receive"
            }
            Action::OtpGetFeature { length } => {
                self.state.answering(true);
                let outcome = match self.otp.fetch(&self.shared, &self.state) {
                    Some(report) => {
                        let end = report.len().min(usize::from(length));
                        let _ = self.ep0.reply(&report[..end], length);
                        "reply"
                    }
                    None => {
                        self.ep0.stall(request);
                        "stall (no answer)"
                    }
                };
                self.state.answering(false);
                outcome
            }
            Action::Stall => {
                self.ep0.stall(request);
                "stall"
            }
        };
        self.shared.notify(GadgetEvent::Setup {
            request_type: request.request_type,
            request: request.request,
            value: request.value,
            index: request.index,
            length: request.length,
            outcome,
        });
        if let Some(size) = sent {
            // False only when the runner is gone or the session stops; `run` sees the
            // latter, and with the former every later send fails anyway.
            let _ = self.pacer.sent(size, &self.shared, &self.state);
        }
    }
}

/// Paces one producer's inputs (an OUT reader or the `ep0` thread), as lk-wire's reader
/// does (see the module docs): after every window of [`INPUT_WINDOW_FRAMES`] inputs or
/// [`INPUT_WINDOW_BYTES`] it sends a `Command::Status` marker, after waiting for the
/// answer to the previous one. The runner handles commands in order, so an answer means
/// every input sent before its marker was handled.
///
/// Unlike lk-wire's reader it waits in slices of [`RETRY_WAIT`] and gives up when the
/// session stops: the transport ends a session on the runner thread, which cannot answer
/// a marker while it waits for this thread to end.
#[derive(Debug, Default)]
struct Pacer {
    frames: usize,
    bytes: usize,
    /// The answer to the last marker, until the producer has waited for it.
    marker: Option<Receiver<Status>>,
}

impl Pacer {
    /// Count one input of `size` payload bytes that was sent. False when the runner is
    /// gone (it drops an unanswered marker when it stops) or the session stops while
    /// waiting.
    fn sent(&mut self, size: usize, shared: &Shared, state: &SessionState) -> bool {
        self.frames += 1;
        self.bytes = self.bytes.saturating_add(size);
        if self.frames < INPUT_WINDOW_FRAMES && self.bytes < INPUT_WINDOW_BYTES {
            return true;
        }
        if let Some(marker) = self.marker.take() {
            loop {
                match marker.recv_timeout(RETRY_WAIT) {
                    Ok(_) => break,
                    Err(RecvTimeoutError::Disconnected) => return false,
                    Err(RecvTimeoutError::Timeout) if state.stopping() => return false,
                    Err(RecvTimeoutError::Timeout) => {}
                }
            }
        }
        let (reply, marker) = mpsc::channel();
        if shared.runner.send(Command::Status(reply)).is_err() {
            return false;
        }
        *self = Pacer { frames: 0, bytes: 0, marker: Some(marker) };
        true
    }
}

/// The OTP GET_REPORT rendezvous with the runner.
///
/// The `ep0` thread sends `Input::OtpGetFeature` and right after it a `Command::Status`
/// as a marker. The runner handles commands in order and hands every output to
/// `deliver` before it takes the next command, so when the marker is answered the
/// answer to this request, if the device gave one, is the last `Output::OtpFeature`
/// delivered. The slot is cleared only after the markers of earlier, timed-out requests
/// were answered, so a late answer to one of them is never taken for this one.
///
/// During a drain (a re-enumeration, see the module docs) the runner is inside
/// [`Transport::enumerate`] and answers no marker, but it has delivered every output of
/// the input that rebooted the device, and delivers nothing more until the drain is
/// over: the slot then holds this request's answer if the device gave one before the
/// reboot (the status read `lk_device` answers right before an OTP HID Management
/// reboot), and the request takes it without waiting for the marker.
#[derive(Debug, Default)]
struct OtpWait {
    /// The marker of a request that timed out and may still be on its way.
    previous: Option<Receiver<Status>>,
}

impl OtpWait {
    fn fetch(&mut self, shared: &Shared, state: &SessionState) -> Option<lk_crypto::SecretBytes> {
        let deadline = Instant::now() + OTP_REPORT_TIMEOUT;
        if let Some(previous) = self.previous.take() {
            // During a drain the runner answers no marker: the earlier answer may still
            // come later, so this request gets none.
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                match previous.recv_timeout(left.min(MARKER_SLICE)) {
                    Ok(_) | Err(RecvTimeoutError::Disconnected) => break,
                    Err(RecvTimeoutError::Timeout) if left.is_zero() || state.draining() => {
                        self.previous = Some(previous);
                        return None;
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                }
            }
        }
        *shared.otp_feature() = None;
        if !shared.send(HostInput::OtpGetFeature) {
            return None;
        }
        let (reply, marker) = mpsc::channel();
        shared.runner.send(Command::Status(reply)).ok()?;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                self.previous = Some(marker);
                return None;
            }
            match marker.recv_timeout(left.min(MARKER_SLICE)) {
                Ok(_) => return shared.otp_feature().take(),
                Err(RecvTimeoutError::Disconnected) => return None,
                Err(RecvTimeoutError::Timeout) if state.draining() => {
                    self.previous = Some(marker);
                    return shared.otp_feature().take();
                }
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
    }
}

/// The FIDO interrupt OUT reader: one 64-byte report per read. A shorter packet is padded
/// with zeros to the report size (the report descriptor fixes 64 bytes); a zero-length
/// read is ignored. Inputs are paced ([`Pacer`]).
fn fido_read_loop(mut file: Box<dyn Read + Send>, shared: &Shared, state: &SessionState) {
    let mut buffer = lk_crypto::SecretBytes::zeroed(crate::control::FIDO_REPORT_LEN);
    let mut pacer = Pacer::default();
    while !state.stopping() {
        let generation = state.generation();
        match file.read(&mut buffer) {
            Ok(0) => state.wait_change(generation, RETRY_WAIT),
            Ok(count) => {
                let mut report = [0u8; crate::control::FIDO_REPORT_LEN];
                report[..count].copy_from_slice(&buffer[..count]);
                shared.notify(GadgetEvent::Received { endpoint: Role::FidoOut, size: count });
                if !shared.send(HostInput::FidoReport(report)) || !pacer.sent(report.len(), shared, state) {
                    break;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => state.wait_change(generation, RETRY_WAIT),
        }
        lk_crypto::wipe(&mut buffer);
    }
}

/// The CCID bulk OUT reader: one packet per read into the [`Reassembler`]. Inputs are
/// paced ([`Pacer`]).
fn ccid_read_loop(mut file: Box<dyn Read + Send>, mut reassembler: Reassembler, shared: &Shared, state: &SessionState) {
    let mut buffer = lk_crypto::SecretBytes::zeroed(reassembler.read_len());
    let mut pacer = Pacer::default();
    while !state.stopping() {
        let generation = state.generation();
        match file.read(&mut buffer) {
            Ok(count) => {
                let idle = count == 0 && reassembler.is_idle();
                match reassembler.push(&buffer[..count]) {
                    Assembled::Pending => {}
                    Assembled::Message(message) => {
                        let size = message.len();
                        shared.notify(GadgetEvent::Received { endpoint: Role::CcidBulkOut, size });
                        if !shared.send(HostInput::Ccid(message)) || !pacer.sent(size, shared, state) {
                            break;
                        }
                    }
                    Assembled::Dropped(reason) => {
                        shared.notify(GadgetEvent::Dropped {
                            endpoint: Role::CcidBulkOut,
                            reason: format!("{reason:?}"),
                        });
                    }
                }
                if idle {
                    // A zero-length packet between messages, or a peer that is gone.
                    state.wait_change(generation, RETRY_WAIT);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => {
                if let Some(reason) = reassembler.reset() {
                    shared.notify(GadgetEvent::Dropped { endpoint: Role::CcidBulkOut, reason: format!("{reason:?}") });
                }
                state.wait_change(generation, RETRY_WAIT);
            }
        }
        lk_crypto::wipe(&mut buffer);
    }
}

/// An IN endpoint writer: writes queued items in order until the queue is dropped or the
/// session stops. An item that cannot be written (the endpoint is disabled) is dropped.
fn write_loop(
    mut file: Box<dyn Write + Send>,
    items: &Receiver<lk_crypto::SecretBytes>,
    role: Role,
    zlp: Option<usize>,
    shared: &Shared,
    state: &SessionState,
) {
    for item in items {
        if state.stopping() {
            break;
        }
        let result = write_item(&mut *file, &item, zlp);
        if is_response(role) {
            state.paid_response();
        }
        match result {
            Ok(()) => shared.notify(GadgetEvent::Sent { endpoint: role, size: item.len() }),
            Err(error) => {
                if state.stopping() {
                    break;
                }
                shared.notify(GadgetEvent::Dropped { endpoint: role, reason: error.kind().to_string() });
            }
        }
    }
}

/// Write one item. With `zlp` (the bulk `wMaxPacketSize`), an item that fills whole
/// packets is followed by a zero-length write, which f_fs sends as a zero-length packet
/// (`ffs_epfile_io` queues a request of the written length; `req->zero` is set only by
/// the `FUNCTIONFS_ENDPOINT_ENABLE_ZLP` ioctl, which this crate cannot use).
pub(crate) fn write_item(file: &mut dyn Write, item: &[u8], zlp: Option<usize>) -> io::Result<()> {
    file.write_all(item)?;
    if let Some(packet) = zlp
        && packet > 0
        && item.len().is_multiple_of(packet)
    {
        // Nothing to count: the call is the packet.
        file.write(&[]).map(|_| ())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
