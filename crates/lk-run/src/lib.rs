//! The program's run loop: one thread owns the [`Device`], gives it a monotonic clock and
//! its deadlines, and connects it to one bus [`Transport`] (`docs/PROGRAM.md` "lk-run").
//!
//! The device is `!Send`, so [`Runner::spawn`] builds it on the runner thread from a
//! `Send` factory and drops it there. Everything else talks to the thread through
//! [`Command`]s on an `mpsc` channel.
//!
//! # As built
//!
//! Choices where `docs/PROGRAM.md` leaves room:
//!
//! - Before each command the loop first serves what fell due while the command waited in
//!   the channel (the tap release, then `Input::Tick`), so a command never overtakes an
//!   earlier deadline.
//! - A tap's `Touch(Up)` is handed to the device at the time it was due, not when the
//!   loop got to it, so the device measures exactly `hold_ms` (the OTP slot windows
//!   depend on it). `Device::handle` clamps the time if it has already seen a later one.
//! - `Command::Tap` is a bus input like `Command::Input`: ignored before [`Runner::serve`].
//! - `Bus(Reset)`/`Bus(PowerCycle)` while suspended: the outputs of that same call (timers
//!   that fell due before the reset) still join the queue and are discarded with it.
//! - A second `Command::Attach` replaces the transport and enumerates the new one.
//! - Outputs produced with no transport attached are dropped; watchers still hear
//!   presence changes.
//! - `Output::Reenumerate` is the device's own reboot (`Device::restart`, which also
//!   clears the device's suspend state). While suspended it discards the queue (counted
//!   as dropped) and ends the suspension, as `Bus(PowerCycle)` does: data that sat in the
//!   endpoints does not survive a reboot. Outputs after it go to the new enumeration.
//! - `Bus(PowerCycle)` and `Output::Reenumerate` let go of the sensor without a
//!   `Touch(Up)` (a pending tap release is cancelled): `Device::restart` forgets the
//!   touch, so a raw press held across them would otherwise block every later tap.
//!   `Bus(Reset)` keeps the touch on both sides.
//! - `HostInput`'s `Debug` names the input and the size of its payload, never the bytes
//!   (`docs/PROGRAM.md` "Rules for program crates": no APDUs or CTAP payloads in logs).
//! - Presence watchers: `std::sync::mpsc` notices a gone receiver only by sending to it.
//!   Besides every change, the list is checked when a registration finds it at its
//!   bound (64, then twice the watchers left after a check): every watcher is sent the
//!   current state again and the gone ones are dropped, so dead watchers cannot pile up
//!   while presence does not change. A live watcher may thus hear the unchanged state
//!   repeated, never a wrong one; a new watcher is not part of the check.
//! - [`Runner::shutdown`] (and dropping the [`Runner`]) raises a stop flag before it
//!   sends `Command::Shutdown`: the loop ends after the command it is handling, and
//!   commands still queued behind it are dropped, like frames in flight when a key is
//!   unplugged. A `Command::Shutdown` sent through a [`Runner::sender`] waits its turn.

use std::any::Any;
use std::collections::VecDeque;
use std::fmt;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lk_core::{Millis, Record, UsbInterfaces};
use lk_device::{BusEvent, Device, Input, Output, TouchEdge, UsbIdentity};

/// Hold time of a short tap: inside the OTP slot 1 window (300–1500 ms,
/// `lk_otp::SHORT_TOUCH_MS`).
pub const TAP_SHORT_MS: Millis = 500;
/// Hold time of a long tap: inside the OTP slot 2 window (2500–5000 ms,
/// `lk_otp::LONG_TOUCH_MS`).
pub const TAP_LONG_MS: Millis = 3_000;
/// Default [`RunnerConfig::suspend_queue_limit`].
pub const DEFAULT_SUSPEND_QUEUE_LIMIT: usize = 256;
/// How many presence watchers the runner holds before a registration checks which of
/// them are still listening (see the crate's "As built" notes).
const WATCHER_CHECK_AT: usize = 64;

/// An owned [`Input`], so it can cross threads. `Input::Tick` is the runner's own business
/// and has no counterpart here.
///
/// `Debug` shows the size of a payload, never its bytes: a CCID message can carry a PIN,
/// an OTP feature report a slot key, a FIDO report a CTAP payload (`docs/PROGRAM.md`
/// "Rules for program crates").
#[derive(Clone, PartialEq, Eq)]
pub enum HostInput {
    FidoReport([u8; 64]),
    OtpSetFeature([u8; 8]),
    OtpGetFeature,
    Ccid(Vec<u8>),
    CcidControlAbort { slot: u8, seq: u8 },
    Touch(TouchEdge),
    Bus(BusEvent),
}

impl HostInput {
    /// The borrowed engine input.
    pub fn as_input(&self) -> Input<'_> {
        match self {
            HostInput::FidoReport(report) => Input::FidoReport(report),
            HostInput::OtpSetFeature(report) => Input::OtpSetFeature(report),
            HostInput::OtpGetFeature => Input::OtpGetFeature,
            HostInput::Ccid(message) => Input::Ccid(message),
            HostInput::CcidControlAbort { slot, seq } => Input::CcidControlAbort { slot: *slot, seq: *seq },
            HostInput::Touch(edge) => Input::Touch(*edge),
            HostInput::Bus(event) => Input::Bus(*event),
        }
    }
}

impl fmt::Debug for HostInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let payload = |name: &str, len: usize, f: &mut fmt::Formatter<'_>| {
            f.debug_tuple(name).field(&format_args!("{len} bytes")).finish()
        };
        match self {
            HostInput::FidoReport(report) => payload("FidoReport", report.len(), f),
            HostInput::OtpSetFeature(report) => payload("OtpSetFeature", report.len(), f),
            HostInput::OtpGetFeature => f.write_str("OtpGetFeature"),
            HostInput::Ccid(message) => payload("Ccid", message.len(), f),
            HostInput::CcidControlAbort { slot, seq } => {
                f.debug_struct("CcidControlAbort").field("slot", slot).field("seq", seq).finish()
            }
            HostInput::Touch(edge) => f.debug_tuple("Touch").field(edge).finish(),
            HostInput::Bus(event) => f.debug_tuple("Bus").field(event).finish(),
        }
    }
}

/// Everything the runner thread accepts.
pub enum Command {
    /// A bus input from the attached transport.
    Input(HostInput),
    /// Press the sensor now and release it `hold_ms` later ([`TAP_SHORT_MS`],
    /// [`TAP_LONG_MS`]).
    Tap { hold_ms: Millis },
    /// Reply with the current [`Status`].
    Status(Sender<Status>),
    /// Register a presence watcher: it gets the current state at once, then every change.
    Watch(Sender<bool>),
    /// Attach the bus transport ([`Runner::serve`]).
    Attach(Box<dyn Transport>),
    /// Stop the loop and drop the device.
    Shutdown,
}

impl fmt::Debug for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Command::Input(input) => f.debug_tuple("Input").field(input).finish(),
            Command::Tap { hold_ms } => f.debug_struct("Tap").field("hold_ms", hold_ms).finish(),
            Command::Status(_) => f.write_str("Status"),
            Command::Watch(_) => f.write_str("Watch"),
            Command::Attach(transport) => f.debug_tuple("Attach").field(transport).finish(),
            Command::Shutdown => f.write_str("Shutdown"),
        }
    }
}

/// The bus side of the program. Every method runs on the runner thread and must not
/// block for long; a transport that writes to a slow peer buffers on its own threads.
pub trait Transport: Send + fmt::Debug {
    /// Present the device with this identity: at attach, and after every
    /// `Output::Reenumerate`.
    fn enumerate(&mut self, identity: &UsbIdentity);
    /// One device output, in order. `Output::Reenumerate` never arrives here (the runner
    /// calls [`Transport::enumerate`] instead).
    fn deliver(&mut self, output: Output);
    /// Whether a host is connected, for transports that know (`Status::attached`).
    fn attached(&self) -> Option<bool> {
        None
    }
}

/// What the runner reports once the device is open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ready {
    /// `Device::unreadable_records()` at open.
    pub unreadable: Vec<Record>,
    /// `Device::usb_identity()` at open.
    pub identity: UsbIdentity,
    /// `DeviceProfile::serial`.
    pub serial: u32,
    /// `DeviceProfile::product`.
    pub product: String,
}

/// A snapshot of the runner and device state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub serial: u32,
    pub product: String,
    /// `Device::interfaces()`.
    pub interfaces: UsbInterfaces,
    /// `Device::presence_pending()`.
    pub presence_pending: bool,
    /// Whether a transport is attached ([`Runner::serve`] was called).
    pub serving: bool,
    /// [`Transport::attached`] of the attached transport.
    pub attached: Option<bool>,
    /// Between `Bus(Suspend)` and `Bus(Resume)`/`Reset`/`PowerCycle` or a Management
    /// reboot (`Output::Reenumerate`).
    pub suspended: bool,
    /// Outputs held while suspended.
    pub queued: usize,
    /// Outputs discarded by the suspend queue limit, or by a reset, power cycle or
    /// Management reboot while suspended.
    pub dropped: u64,
    /// `Device::unreadable_records()` now.
    pub unreadable: Vec<Record>,
    /// Milliseconds since the runner started (the device's `now`).
    pub uptime_ms: Millis,
}

/// Runner options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunnerConfig {
    /// Tell the device the system wall-clock time (`Device::set_unix_time`).
    pub wall_clock: bool,
    /// Maximum outputs held while the bus is suspended.
    pub suspend_queue_limit: usize,
}

impl Default for RunnerConfig {
    fn default() -> Self {
        RunnerConfig { wall_clock: false, suspend_queue_limit: DEFAULT_SUSPEND_QUEUE_LIMIT }
    }
}

/// Why the runner could not start or stopped abnormally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunError {
    /// The device factory failed; its message.
    Factory(String),
    /// The runner thread panicked; the panic message when it was a string.
    Panicked(String),
    /// The runner thread is gone (a command could not be delivered).
    Stopped,
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunError::Factory(reason) => write!(f, "device could not be opened: {reason}"),
            RunError::Panicked(reason) => write!(f, "runner thread panicked: {reason}"),
            RunError::Stopped => f.write_str("runner thread has stopped"),
        }
    }
}

impl std::error::Error for RunError {}

/// The handle to the runner thread. Dropping it shuts the runner down and joins it.
#[derive(Debug)]
pub struct Runner {
    sender: Sender<Command>,
    ready: Ready,
    /// Raised by [`Runner::stop`]: the loop ends without handling the commands queued
    /// behind the one in hand.
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Runner {
    /// Start the runner thread, build the device there with `factory`, and wait for it to
    /// be open.
    ///
    /// The thread takes its `Instant` (time 0 of the device clock) before it calls
    /// `factory`, so the factory's `Device::open` is the power-up at time 0
    /// (`docs/PROGRAM.md` "lk-run", Clock). A factory error is [`RunError::Factory`]; a
    /// panic in the factory ends the thread and is [`RunError::Panicked`]. Failing to
    /// start the thread at all is also reported as [`RunError::Factory`].
    pub fn spawn<F>(factory: F, config: RunnerConfig) -> Result<Runner, RunError>
    where
        F: FnOnce() -> Result<Device, String> + Send + 'static,
    {
        let (sender, commands) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<Ready, String>>();
        let stopping = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stopping);
        let thread = thread::Builder::new()
            .name("lk-run".into())
            .spawn(move || {
                let start = Instant::now();
                let device = match factory() {
                    Ok(device) => device,
                    Err(reason) => {
                        let _ = ready_tx.send(Err(reason));
                        return;
                    }
                };
                let mut state = RunLoop::new(device, start, config);
                if ready_tx.send(Ok(state.ready())).is_ok() {
                    drop(ready_tx);
                    state.run(&commands, &stop_flag);
                }
            })
            .map_err(|error| RunError::Factory(format!("cannot start the runner thread: {error}")))?;
        match ready_rx.recv() {
            Ok(Ok(ready)) => Ok(Runner { sender, ready, stopping, thread: Some(thread) }),
            Ok(Err(reason)) => {
                let _ = thread.join();
                Err(RunError::Factory(reason))
            }
            // The thread ended without a word: it panicked before `Ready`.
            Err(_) => Err(join(thread).err().unwrap_or(RunError::Stopped)),
        }
    }

    /// What the device reported at open.
    pub fn ready(&self) -> &Ready {
        &self.ready
    }

    /// A sender for transports and control clients.
    pub fn sender(&self) -> Sender<Command> {
        self.sender.clone()
    }

    /// Attach the bus transport. Inputs are fed to the device from now on.
    pub fn serve(&self, transport: Box<dyn Transport>) -> Result<(), RunError> {
        self.sender.send(Command::Attach(transport)).map_err(|_| RunError::Stopped)
    }

    /// The current status (round trip through the runner thread). [`RunError::Stopped`]
    /// once the thread is gone, also after a panic (only [`Runner::shutdown`] can join
    /// the thread and report [`RunError::Panicked`]).
    pub fn status(&self) -> Result<Status, RunError> {
        let (reply, answer) = mpsc::channel();
        self.sender.send(Command::Status(reply)).map_err(|_| RunError::Stopped)?;
        answer.recv().map_err(|_| RunError::Stopped)
    }

    /// Stop the loop, drop the device and join the thread. [`RunError::Panicked`] if the
    /// thread panicked (the device or the entropy source), at any time before.
    ///
    /// The loop ends once the command it is handling is done; commands still queued
    /// behind it (a flood of inputs from a peer, for example) are dropped unhandled, as
    /// frames in flight are when a key is unplugged.
    pub fn shutdown(mut self) -> Result<(), RunError> {
        self.stop()
    }

    /// Raise the stop flag, send `Shutdown` (it wakes a loop that waits on the channel)
    /// and join, once: the join handle is taken, so the `Drop` that follows
    /// [`Runner::shutdown`] has nothing left to do.
    fn stop(&mut self) -> Result<(), RunError> {
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        self.stopping.store(true, Ordering::SeqCst);
        // The thread may already be gone after a panic; the join reports that.
        let _ = self.sender.send(Command::Shutdown);
        join(thread)
    }
}

impl Drop for Runner {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Join the runner thread; a panic becomes [`RunError::Panicked`].
fn join(thread: JoinHandle<()>) -> Result<(), RunError> {
    thread.join().map_err(|payload| RunError::Panicked(panic_message(&*payload)))
}

/// The message of a `panic!` with a string literal or a formatted message.
fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "(no message)".to_owned()
    }
}

/// Seconds since the Unix epoch, `None` for a system clock set before it.
fn unix_seconds() -> Option<u64> {
    SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|elapsed| elapsed.as_secs())
}

/// Everything the runner thread owns (`docs/PROGRAM.md` "lk-run"). It lives and dies on
/// that thread, so the `!Send` device is dropped there. No `Debug`: the queue holds
/// device outputs (CCID responses, typed OTP reports).
struct RunLoop {
    device: Device,
    /// Time 0 of the device clock.
    start: Instant,
    config: RunnerConfig,
    transport: Option<Box<dyn Transport>>,
    /// The sensor as the runner last pressed or released it (taps and raw edges).
    held: bool,
    /// When the current tap lets go of the sensor.
    release_at: Option<Millis>,
    suspended: bool,
    queue: VecDeque<Output>,
    dropped: u64,
    watchers: Vec<Sender<bool>>,
    /// The watcher count at which a registration checks which watchers are still
    /// listening (see the crate's "As built" notes).
    check_watchers_at: usize,
    /// The last value given to `Device::set_unix_time`.
    unix_time: Option<u64>,
}

impl RunLoop {
    /// Wrap a freshly opened device. With `wall_clock`, the device learns the time now.
    fn new(device: Device, start: Instant, config: RunnerConfig) -> RunLoop {
        let mut state = RunLoop {
            device,
            start,
            config,
            transport: None,
            held: false,
            release_at: None,
            suspended: false,
            queue: VecDeque::new(),
            dropped: 0,
            watchers: Vec::new(),
            check_watchers_at: WATCHER_CHECK_AT,
            unix_time: None,
        };
        if config.wall_clock {
            state.unix_time = unix_seconds();
            state.device.set_unix_time(state.unix_time);
        }
        state
    }

    fn ready(&self) -> Ready {
        let profile = self.device.profile();
        Ready {
            unreadable: self.device.unreadable_records().to_vec(),
            identity: self.device.usb_identity(),
            serial: profile.serial,
            product: profile.product.clone(),
        }
    }

    /// Whole milliseconds since time 0.
    fn now(&self) -> Millis {
        Millis::try_from(self.start.elapsed().as_millis()).unwrap_or(Millis::MAX)
    }

    /// Wait for commands until the earliest of the device's deadline and the tap release,
    /// and serve both on time. Ends on `Shutdown`, on a command that arrives once
    /// `stopping` is raised ([`Runner::shutdown`]), or when every `Sender` is gone.
    fn run(&mut self, commands: &Receiver<Command>, stopping: &AtomicBool) {
        loop {
            self.catch_up();
            let wake = [self.device.next_deadline(), self.release_at].into_iter().flatten().min();
            let received = match wake {
                Some(at) => commands.recv_timeout(Duration::from_millis(at).saturating_sub(self.start.elapsed())),
                None => commands.recv().map_err(RecvTimeoutError::from),
            };
            match received {
                Ok(command) => {
                    // `Runner::shutdown` does not wait for the commands queued before
                    // its `Shutdown`.
                    if stopping.load(Ordering::SeqCst) {
                        return;
                    }
                    // The command may have waited in the channel past a due time; what
                    // was due first happens first.
                    self.catch_up();
                    if self.command(command).is_break() {
                        return;
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
        }
    }

    /// Release the tap and deliver `Input::Tick` for everything due by now.
    fn catch_up(&mut self) {
        loop {
            let now = self.now();
            match self.release_at {
                Some(at) if at <= now => self.release(at),
                _ if self.device.next_deadline().is_some_and(|at| at <= now) => {
                    let outputs = self.feed(now, Input::Tick);
                    self.dispatch(outputs);
                }
                _ => return,
            }
        }
    }

    fn command(&mut self, command: Command) -> ControlFlow<()> {
        match command {
            Command::Input(input) => self.input(&input),
            Command::Tap { hold_ms } => self.tap(hold_ms),
            Command::Status(reply) => {
                let _ = reply.send(self.status());
            }
            Command::Watch(watcher) => {
                let lit = self.device.presence_pending();
                if watcher.send(lit).is_ok() {
                    if self.watchers.len() >= self.check_watchers_at {
                        // Only a send tells whether a receiver is gone; without this,
                        // watchers of finished `watch` clients would pile up until the
                        // next presence change.
                        self.tell_watchers(lit);
                    }
                    self.watchers.push(watcher);
                }
            }
            Command::Attach(mut transport) => {
                // A second attach replaces the first transport (there is one bus).
                transport.enumerate(&self.device.usb_identity());
                self.transport = Some(transport);
            }
            Command::Shutdown => return ControlFlow::Break(()),
        }
        ControlFlow::Continue(())
    }

    /// A bus input. Ignored before [`Runner::serve`]; raw touch edges that do not change
    /// the sensor are ignored too, and a raw release ends a tap early.
    fn input(&mut self, input: &HostInput) {
        if self.transport.is_none() {
            return;
        }
        match input {
            HostInput::Touch(TouchEdge::Down) => {
                if self.held {
                    return;
                }
                self.held = true;
            }
            HostInput::Touch(TouchEdge::Up) => {
                if !self.held {
                    return;
                }
                self.held = false;
                self.release_at = None;
            }
            HostInput::Bus(event) => return self.bus(*event),
            _ => {}
        }
        let outputs = self.feed(self.now(), input.as_input());
        self.dispatch(outputs);
    }

    /// Bus events and the suspend queue (`docs/PROGRAM.md` "lk-run", Suspend). A power
    /// cycle also lets go of the sensor ([`RunLoop::forget_touch`]).
    fn bus(&mut self, event: BusEvent) {
        let outputs = self.feed(self.now(), Input::Bus(event));
        if event == BusEvent::PowerCycle {
            self.forget_touch();
        }
        match event {
            BusEvent::Suspend => {
                self.dispatch(outputs);
                self.suspended = true;
            }
            BusEvent::Resume if self.suspended => {
                // The queued data sat in the endpoints before the host resumed.
                self.suspended = false;
                for output in std::mem::take(&mut self.queue) {
                    self.deliver(output);
                }
                self.dispatch(outputs);
            }
            BusEvent::Reset | BusEvent::PowerCycle if self.suspended => {
                // Still suspended here: data the call produced (timers due before the
                // reset) joins the queue and is lost with it.
                self.dispatch(outputs);
                self.lose_queue();
            }
            _ => self.dispatch(outputs),
        }
    }

    /// End a suspension by losing what it held (counted in `dropped`): a bus reset, a
    /// power cycle or the device's own reboot while suspended.
    fn lose_queue(&mut self) {
        self.dropped = self.dropped.saturating_add(self.queue.len() as u64);
        self.queue.clear();
        self.suspended = false;
    }

    /// The device forgot the touch (`Device::restart`, on `Bus(PowerCycle)` and before
    /// `Output::Reenumerate`): the sensor counts as released and a pending tap release is
    /// cancelled, without a `Touch(Up)` (the device would ignore it).
    fn forget_touch(&mut self) {
        self.held = false;
        self.release_at = None;
    }

    /// Press the sensor now and schedule its release (`docs/PROGRAM.md` "lk-run", Taps).
    /// Ignored before [`Runner::serve`] and while the sensor is held.
    fn tap(&mut self, hold_ms: Millis) {
        if self.transport.is_none() || self.held {
            return;
        }
        let now = self.now();
        self.held = true;
        self.release_at = Some(now.saturating_add(hold_ms));
        let outputs = self.feed(now, Input::Touch(TouchEdge::Down));
        self.dispatch(outputs);
    }

    /// The tap's `Touch(Up)`, at the time it was due even when the loop is late, so the
    /// device measures exactly the hold time (the OTP slot windows depend on it).
    fn release(&mut self, at: Millis) {
        self.held = false;
        self.release_at = None;
        let outputs = self.feed(at, Input::Touch(TouchEdge::Up));
        self.dispatch(outputs);
    }

    /// One `Device::handle` call, after telling the device the wall-clock time if its
    /// whole second changed (`docs/PROGRAM.md` "lk-run", Wall clock).
    fn feed(&mut self, now: Millis, input: Input<'_>) -> Vec<Output> {
        if self.config.wall_clock {
            let seconds = unix_seconds();
            if seconds != self.unix_time {
                self.unix_time = seconds;
                self.device.set_unix_time(seconds);
            }
        }
        self.device.handle(now, input)
    }

    /// Act on outputs in order: re-enumerate, tell the watchers, queue while suspended,
    /// or deliver. Without a transport the outputs are dropped (watchers still hear).
    fn dispatch(&mut self, outputs: Vec<Output>) {
        for output in outputs {
            match output {
                Output::Reenumerate(_) => {
                    // The device rebooted (`Device::restart`): like a power cycle, that
                    // loses what sat in the endpoints, ends a suspension and forgets the
                    // touch. What follows belongs to the new enumeration.
                    self.lose_queue();
                    self.forget_touch();
                    let identity = self.device.usb_identity();
                    if let Some(transport) = self.transport.as_mut() {
                        transport.enumerate(&identity);
                    }
                }
                Output::PresenceIndicator(lit) => {
                    self.tell_watchers(lit);
                    self.deliver(output);
                }
                _ if self.suspended => {
                    self.queue.push_back(output);
                    while self.queue.len() > self.config.suspend_queue_limit {
                        self.queue.pop_front();
                        self.dropped = self.dropped.saturating_add(1);
                    }
                }
                _ => self.deliver(output),
            }
        }
    }

    /// Send `lit` to every watcher, drop those whose receiver is gone, and set the next
    /// registration check at twice the watchers left (at least `WATCHER_CHECK_AT`).
    fn tell_watchers(&mut self, lit: bool) {
        self.watchers.retain(|watcher| watcher.send(lit).is_ok());
        self.check_watchers_at = WATCHER_CHECK_AT.max(self.watchers.len().saturating_mul(2));
    }

    fn deliver(&mut self, output: Output) {
        if let Some(transport) = self.transport.as_mut() {
            transport.deliver(output);
        }
    }

    fn status(&self) -> Status {
        let profile = self.device.profile();
        Status {
            serial: profile.serial,
            product: profile.product.clone(),
            interfaces: self.device.interfaces(),
            presence_pending: self.device.presence_pending(),
            serving: self.transport.is_some(),
            attached: self.transport.as_ref().and_then(|transport| transport.attached()),
            suspended: self.suspended,
            queued: self.queue.len(),
            dropped: self.dropped,
            unreadable: self.device.unreadable_records().to_vec(),
            uptime_ms: self.now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lk_core::DeviceProfile;
    use lk_testkit::{MemoryStore, SeededEntropy};

    fn state() -> RunLoop {
        state_with(RunnerConfig::default())
    }

    fn state_with(config: RunnerConfig) -> RunLoop {
        let device = Device::open(
            DeviceProfile::own(12_345_678),
            Box::new(MemoryStore::new()),
            Box::new(SeededEntropy::new(1)),
            [0x5A; 32],
        );
        RunLoop::new(device, Instant::now(), config)
    }

    /// `Host::unix_time` as the device's `Debug` output shows it (lk-device has no
    /// getter for it).
    fn device_unix_time(device: &Device) -> Option<u64> {
        let shown = format!("{device:?}");
        let (_, rest) = shown.split_once("unix_time: ").expect("the device's Debug output shows unix_time");
        let digits = rest.strip_prefix("Some(")?;
        let end = digits.find(')').expect("Some(..) is closed");
        Some(digits[..end].parse().expect("unix_time is whole seconds"))
    }

    fn now_seconds() -> u64 {
        unix_seconds().expect("the system clock is after 1970")
    }

    /// `docs/PROGRAM.md` "lk-run", Presence watchers: a watcher whose receiver is gone
    /// is dropped at the next change; the others keep hearing.
    #[test]
    fn a_watcher_whose_receiver_is_gone_is_dropped_at_the_next_change() {
        let mut state = state();
        let (kept, kept_rx) = mpsc::channel();
        let (gone, gone_rx) = mpsc::channel();
        assert!(state.command(Command::Watch(kept)).is_continue());
        assert!(state.command(Command::Watch(gone)).is_continue());
        assert_eq!(state.watchers.len(), 2);
        drop(gone_rx);
        state.dispatch(vec![Output::PresenceIndicator(true)]);
        assert_eq!(state.watchers.len(), 1);
        assert_eq!(kept_rx.try_iter().collect::<Vec<_>>(), [false, true]);
    }

    /// Dead watchers do not pile up while presence stays the same: a registration that
    /// finds the list at its bound drops the gone ones (only a send can tell). A live
    /// watcher meanwhile hears the current state repeated, never anything else, and
    /// still hears the next change.
    #[test]
    fn watchers_whose_receivers_are_gone_do_not_pile_up_without_a_presence_change() {
        let mut state = state();
        let (live, live_rx) = mpsc::channel();
        assert!(state.command(Command::Watch(live)).is_continue());
        // 1000 `watch` clients come and go; presence never changes.
        for _ in 0..1_000 {
            let (watcher, watched) = mpsc::channel();
            assert!(state.command(Command::Watch(watcher)).is_continue());
            drop(watched);
            assert!(state.watchers.len() <= WATCHER_CHECK_AT, "{} watchers held", state.watchers.len());
        }
        let heard: Vec<bool> = live_rx.try_iter().collect();
        assert!(heard.len() > 1 && heard.iter().all(|lit| !lit), "{heard:?}");
        state.dispatch(vec![Output::PresenceIndicator(true)]);
        assert_eq!(live_rx.try_iter().collect::<Vec<_>>(), [true]);
        assert_eq!(state.watchers.len(), 1);
    }

    /// Live watchers do not hear a repeat at every registration: after a check, the next
    /// one waits until the list has doubled.
    #[test]
    fn the_next_watcher_check_waits_until_the_list_has_doubled() {
        let mut state = state();
        let receivers: Vec<Receiver<bool>> = (0..100)
            .map(|_| {
                let (watcher, watched) = mpsc::channel();
                assert!(state.command(Command::Watch(watcher)).is_continue());
                watched
            })
            .collect();
        // The 65th registration checked the 64 before it; the next check is at 128.
        assert_eq!(state.check_watchers_at, 2 * WATCHER_CHECK_AT);
        let heard: Vec<usize> = receivers.iter().map(|watched| watched.try_iter().count()).collect();
        assert!(heard[..WATCHER_CHECK_AT].iter().all(|&count| count == 2), "{heard:?}");
        assert!(heard[WATCHER_CHECK_AT..].iter().all(|&count| count == 1), "{heard:?}");
    }

    /// A watcher that is gone before it registers is never kept.
    #[test]
    fn a_watcher_gone_at_registration_is_not_kept() {
        let mut state = state();
        let (gone, gone_rx) = mpsc::channel();
        drop(gone_rx);
        assert!(state.command(Command::Watch(gone)).is_continue());
        assert!(state.watchers.is_empty());
    }

    /// `docs/PROGRAM.md` "Rules for program crates": no APDU or CTAP payload in a log, so
    /// `Debug` shows a payload's size, never its bytes. The CCID message is a
    /// PC_to_RDR_XfrBlock carrying VERIFY (`00 20 00 80 08`) with the PIN "123456".
    #[test]
    fn debug_output_shows_payload_sizes_never_the_bytes() {
        let mut verify = vec![0x6F, 13, 0, 0, 0, 0, 0x07, 0, 0, 0];
        verify.extend_from_slice(&[0x00, 0x20, 0x00, 0x80, 0x08, b'1', b'2', b'3', b'4', b'5', b'6', 0xFF, 0xFF]);
        assert_eq!(format!("{:?}", Command::Input(HostInput::Ccid(verify))), "Input(Ccid(23 bytes))");
        assert_eq!(format!("{:?}", HostInput::FidoReport([0x31; 64])), "FidoReport(64 bytes)");
        assert_eq!(format!("{:?}", HostInput::OtpSetFeature([0x31; 8])), "OtpSetFeature(8 bytes)");
        // Inputs without a payload show as they are.
        let abort = HostInput::CcidControlAbort { slot: 0, seq: 9 };
        assert_eq!(format!("{abort:?}"), "CcidControlAbort { slot: 0, seq: 9 }");
        assert_eq!(format!("{:?}", HostInput::OtpGetFeature), "OtpGetFeature");
        assert_eq!(format!("{:?}", HostInput::Touch(TouchEdge::Down)), "Touch(Down)");
        assert_eq!(format!("{:?}", Command::Input(HostInput::Bus(BusEvent::PowerCycle))), "Input(Bus(PowerCycle))");
    }

    /// `docs/PROGRAM.md` "lk-run", Wall clock: with `wall_clock` the device learns the
    /// time at start, and again before an input once the whole second has changed.
    #[test]
    fn the_wall_clock_is_set_at_start_and_when_its_second_changes() {
        let before = now_seconds();
        let mut state = state_with(RunnerConfig { wall_clock: true, ..RunnerConfig::default() });
        let at_start = device_unix_time(&state.device).expect("set at start");
        assert!((before..=now_seconds()).contains(&at_start), "{at_start}");
        assert_eq!(state.unix_time, Some(at_start));
        // The second last given is long gone: the next input sets the time again.
        state.unix_time = Some(1);
        state.device.set_unix_time(Some(1));
        let before = now_seconds();
        let _ = state.feed(state.now(), Input::Tick);
        let fed = device_unix_time(&state.device).expect("set before the input");
        assert!((before..=now_seconds()).contains(&fed), "{fed}");
        assert_eq!(state.unix_time, Some(fed));
    }

    /// Without `wall_clock` the runner never calls `set_unix_time` (a physical key has no
    /// clock): the device starts without a time, and a value it has is left alone.
    #[test]
    fn without_the_wall_clock_the_device_time_is_never_set() {
        let mut state = state();
        assert_eq!(device_unix_time(&state.device), None);
        state.device.set_unix_time(Some(7));
        for _ in 0..3 {
            let _ = state.feed(state.now(), Input::Tick);
        }
        assert_eq!(device_unix_time(&state.device), Some(7));
    }

    #[test]
    fn panic_messages_are_read_from_str_and_string_payloads() {
        let literal: Box<dyn Any + Send> = Box::new("literal");
        let formatted: Box<dyn Any + Send> = Box::new(format!("formatted {}", 1));
        let other: Box<dyn Any + Send> = Box::new(7u8);
        assert_eq!(panic_message(&*literal), "literal");
        assert_eq!(panic_message(&*formatted), "formatted 1");
        assert_eq!(panic_message(&*other), "(no message)");
    }
}
