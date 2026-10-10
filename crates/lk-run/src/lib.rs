//! The program's run loop: one thread owns the [`Device`], gives it a monotonic clock and
//! its deadlines, and connects it to one bus [`Transport`] (`docs/PROGRAM.md` "lk-run").
//!
//! The device is `!Send`, so [`Runner::spawn`] builds it on the runner thread from a
//! `Send` factory and drops it there. Everything else talks to the thread through
//! [`Command`]s on an `mpsc` channel.

use std::fmt;
use std::sync::mpsc::Sender;
use std::thread::JoinHandle;

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

/// An owned [`Input`], so it can cross threads. `Input::Tick` is the runner's own business
/// and has no counterpart here.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Between `Bus(Suspend)` and `Bus(Resume)`/`Reset`/`PowerCycle`.
    pub suspended: bool,
    /// Outputs held while suspended.
    pub queued: usize,
    /// Outputs discarded by the suspend queue limit or by a reset while suspended.
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
    thread: Option<JoinHandle<()>>,
}

impl Runner {
    /// Start the runner thread, build the device there with `factory`, and wait for it to
    /// be open.
    pub fn spawn<F>(factory: F, config: RunnerConfig) -> Result<Runner, RunError>
    where
        F: FnOnce() -> Result<Device, String> + Send + 'static,
    {
        let _ = (factory, config);
        todo!("docs/PROGRAM.md lk-run")
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

    /// The current status (round trip through the runner thread).
    pub fn status(&self) -> Result<Status, RunError> {
        todo!("docs/PROGRAM.md lk-run")
    }

    /// Stop the loop, drop the device and join the thread.
    pub fn shutdown(mut self) -> Result<(), RunError> {
        let _ = &mut self.thread;
        todo!("docs/PROGRAM.md lk-run")
    }
}
