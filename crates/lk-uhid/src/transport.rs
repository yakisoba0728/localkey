//! The UHID bus transport (`docs/PROGRAM.md` "lk-uhid").
//!
//! One UHID device per enabled HID interface, each with its own open file and two threads:
//!
//! - the runner thread calls [`Transport::enumerate`] and [`Transport::deliver`]; both only
//!   build events and queue them, so they never wait for the kernel;
//! - a writer thread per device writes the queued events in order, one whole
//!   `struct uhid_event` per `write` (`Documentation/hid/uhid.rst`);
//! - a reader thread per device reads the kernel's events, one per `read`, and turns them
//!   into `Command::Input` for the runner, answering GET_REPORT and SET_REPORT through the
//!   writer's queue.
//!
//! # Unplugging
//!
//! A re-enumeration is an unplug and a new plug-in: every device is retired (it gets
//! `UHID_DESTROY` and its file is closed), and each interface the new identity enables
//! gets a new file with `UHID_CREATE2`. Retiring raises the device's `retiring` flag; the
//! writer looks at that flag before every item it takes from its queue, so the DESTROY
//! cannot be lost behind a full queue: once the flag is up the writer writes what is still
//! queued, waits (at most [`FEATURE_TIMEOUT`]) for the replies still owed to requests the
//! device accepted before, writes DESTROY if the kernel accepted the CREATE2
//! ([`DESTROY_AFTER_REPLY`] after the last reply), and ends. A new device's writer waits
//! until the old device's writer has ended (at most [`DROP_TIMEOUT`]; writes to
//! `/dev/uhid` do not block, so only a stuck file or an owed reply holds it up) before it
//! writes CREATE2, so the kernel does not hold both. A reader starts reading only once its
//! writer's CREATE2 was accepted (a UHID file carries no events before), so a device
//! retired before its CREATE2 was written ends both threads at once and its file is
//! closed.
//!
//! What the old device still writes, found with ykman on a real kernel
//! (`tools/linux-guest/tests/uhid.sh`): a Management write with REBOOT ends with a reply
//! (the CTAPHID response, or for OTP HID the SET_REPORT acknowledgement and the status
//! that the next GET_REPORT reads), and the reboot follows at once. A USB device completes
//! those transfers before it acts on them; here the outputs `deliver` queued before the
//! re-enumeration and the replies to requests whose input reached the runner first
//! ([`InFlight`], counted under the gate) are written before the DESTROY. Dropping the
//! transport writes the queued outputs too but no owed replies: no marker is answered any
//! more, and the DESTROY fails the kernel's pending requests (`uhid_dev_destroy`).
//!
//! What of the old instance reaches the rebooted device, exactly:
//!
//! - events the kernel still sends on an old file after the re-enumeration (outputs,
//!   requests) are dropped by its reader, and requests get no reply: the DESTROY fails
//!   them in the kernel (it clears `running` and wakes `report_wait`,
//!   `drivers/hid/uhid.c`);
//! - inputs an old reader handed to the runner before the re-enumeration are already in
//!   the runner's channel, ahead of the plug-in `BusEvent::PowerCycle`. The rebooted device
//!   handles them before that power cycle, which discards their volatile effects; a
//!   persistent one (an OTP slot write whose last feature report the host had sent, and
//!   whose SET_REPORT was acknowledged, before the reboot) still takes effect. Their
//!   outputs never reach the new devices: [`Transport::enumerate`] sends a
//!   `Command::Status` marker (the fence) behind them, and [`Transport::deliver`] drops
//!   report outputs until the runner has answered it. A reader checks `retiring` and sends
//!   an input under the device's gate, which `retire` takes to raise the flag, so no input
//!   of an old reader can follow the fence.
//!
//! # Pacing
//!
//! The runner's channel is unbounded, so each reader paces itself as the wire transport's
//! reader does (`docs/PROGRAM.md` "Program core as built", lk-wire backpressure): after
//! every [`INPUT_WINDOW`] inputs it sends a `Command::Status` marker, and before it sends
//! the next marker it waits for the answer to the previous one. At most two windows of a
//! device's inputs wait in the channel; meanwhile the reader does not read, and what a
//! host sends beyond that waits in the kernel's queue of `UHID_BUFSIZE` (32) events, where
//! `uhid_queue` drops it once full (`drivers/hid/uhid.c`). Every wait for a marker gives up
//! once the device is retiring (a feature read whose reply is owed only once the transport
//! is dropped), so dropping the transport never waits for a runner that is busy dropping
//! it.

use std::fmt;
use std::io::{self, Read, Write};
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender, TryRecvError};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use lk_device::{BusEvent, Output, UsbIdentity};
use lk_run::{Command, HostInput, Status, Transport};

use crate::event::{BUS_USB, Create2, EIO, Event, NAME_SIZE, ReportType, UHID_EVENT_SIZE, UNIQ_SIZE};
use crate::io::UhidIo;
use crate::report;

/// How long a GET_REPORT(feature) waits for the runner to hand back the device's
/// `Output::OtpFeature` before it is answered with [`EIO`] (`docs/PROGRAM.md`
/// "lk-gadget": bounded, 1 s). The kernel waits 5 s for the reply
/// (`__uhid_report_queue_and_wait` in `drivers/hid/uhid.c`), so the error arrives in time.
pub const FEATURE_TIMEOUT: Duration = Duration::from_secs(1);

/// Events queued for one device's writer. A full queue drops the event (counted in
/// [`UhidStats::dropped`]); writes to `/dev/uhid` never block (`Documentation/hid/uhid.rst`:
/// "writes are always handled immediately"), so only a stuck file fills it.
pub const WRITE_QUEUE_EVENTS: usize = 1024;

/// How long dropping the transport waits, in total, for the device threads to end, and how
/// long a new device's writer waits for its predecessor's writer. A reader ends when it
/// reads the `UHID_STOP` that follows `UHID_DESTROY`; a thread still running after this is
/// left behind and reported.
pub const DROP_TIMEOUT: Duration = Duration::from_secs(1);

/// How long an unplugged device's DESTROY waits after the last GET_REPORT or SET_REPORT
/// reply it wrote. The kernel wakes the caller waiting for the reply, but the caller, once
/// it runs, fails the request with `EIO` if the device no longer runs
/// (`__uhid_report_queue_and_wait` in `drivers/hid/uhid.c` checks `running` after the
/// wait), and a DESTROY written right behind the reply clears `running` first. Seen on a
/// real kernel: ykman's status read after a Management write over OTP HID failed that way
/// although its reply had been written. A USB device's reboot likewise comes some time
/// after the control transfer it answered. Generous for a loaded host; it delays only a
/// re-enumeration that follows a reply.
pub const DESTROY_AFTER_REPLY: Duration = Duration::from_millis(100);

/// Inputs per window of one device's reader (see the module docs, Pacing): at most twice
/// this many of a device's inputs wait in the runner's channel. Every input is one
/// fixed-size report (64 bytes FIDO, 8 bytes OTP), so a window needs no byte bound.
pub const INPUT_WINDOW: usize = 64;

/// `uhid_create2_req.phys` of every device (`docs/PROGRAM.md` "lk-uhid").
pub const PHYS: &str = "localkey";

/// OTP feature reports handed back by `deliver` and not yet taken by the reader.
const FEATURE_QUEUE: usize = 16;

/// How often a bounded join checks whether a thread has ended.
const JOIN_POLL: Duration = Duration::from_millis(5);

/// How often a reader waiting for a marker checks whether its device is retiring.
const RETIRE_POLL: Duration = Duration::from_millis(20);

/// Why reports of a device that is being destroyed are refused.
const RETIRING: &str = "the device is being destroyed";

/// A HID interface presented through UHID. CCID has no UHID counterpart and is not
/// presented (`docs/PROGRAM.md` "lk-uhid").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HidInterface {
    /// The OTP boot keyboard with its feature report (`lk_device::OTP_REPORT_DESCRIPTOR`).
    Otp,
    /// The FIDO CTAPHID interface (`lk_device::FIDO_REPORT_DESCRIPTOR`).
    Fido,
}

impl HidInterface {
    /// Both, in the order the devices are created.
    pub const ALL: [HidInterface; 2] = [HidInterface::Otp, HidInterface::Fido];

    /// `otp` or `fido`.
    pub fn name(self) -> &'static str {
        match self {
            HidInterface::Otp => "otp",
            HidInterface::Fido => "fido",
        }
    }

    fn enabled(self, identity: &UsbIdentity) -> bool {
        match self {
            HidInterface::Otp => identity.interfaces.otp,
            HidInterface::Fido => identity.interfaces.fido,
        }
    }

    fn report_descriptor(self, identity: &UsbIdentity) -> &[u8] {
        match self {
            HidInterface::Otp => &identity.otp_report_descriptor,
            HidInterface::Fido => &identity.fido_report_descriptor,
        }
    }
}

impl fmt::Display for HidInterface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Receives [`UhidNotice`]s, for the daemon's log. It runs on the transport's threads and
/// the runner thread, so it must be quick and must not call into the transport.
pub type Observer = Arc<dyn Fn(&UhidNotice) + Send + Sync>;

/// What happened on the UHID devices (`docs/PROGRAM.md` "localkeyd" logging). `Received`
/// and `Sent` are per event (the `-vv` level); the rest are device lifecycle and problems.
/// Never carries report bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UhidNotice {
    /// The runner enumerated the device with this identity.
    Enumerated { product_id: u16, otp: bool, fido: bool },
    /// The kernel accepted `UHID_CREATE2`: the device is plugged in.
    Created { interface: HidInterface, product_id: u32 },
    /// `UHID_DESTROY` was written.
    Destroyed { interface: HidInterface },
    /// `UHID_START` arrived with these `dev_flags` (0 for the engine's descriptors, which
    /// have no Report IDs).
    Started { interface: HidInterface, dev_flags: u64 },
    /// `UHID_STOP` arrived.
    Stopped { interface: HidInterface },
    /// `UHID_OPEN`: a process opened the HID device.
    Opened { interface: HidInterface },
    /// `UHID_CLOSE`: no process has it open any more.
    Closed { interface: HidInterface },
    /// An event from the kernel, with the size of its report data.
    Received { interface: HidInterface, event: &'static str, size: usize },
    /// An event written to the kernel, with the size of its report data.
    Sent { interface: HidInterface, event: &'static str, size: usize },
    /// A report or request from the host was refused (dropped, or answered with an error).
    Refused { interface: HidInterface, event: &'static str, size: usize, reason: &'static str },
    /// The kernel refused an input report with `-EINVAL`, which for a whole `UHID_INPUT2`
    /// means it does not run the device (`uhid_dev_input2`): adding it failed after
    /// `UHID_CREATE2` was accepted (`uhid_device_add_worker`, `drivers/hid/uhid.c`). Sent
    /// once; the device stays absent until the next enumeration.
    NotRunning { interface: HidInterface },
    /// The device's file ended on the kernel side; the next enumeration opens a new one.
    Ended { interface: HidInterface },
    /// Something could not be done (open, write, a thread).
    Failed(String),
}

impl fmt::Display for UhidNotice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UhidNotice::Enumerated { product_id, otp, fido } => {
                let list: Vec<&str> =
                    [(*otp, "otp"), (*fido, "fido")].into_iter().filter_map(|(on, name)| on.then_some(name)).collect();
                write!(f, "uhid: enumerated as product 0x{product_id:04x} ({})", list.join(","))
            }
            UhidNotice::Created { interface, product_id } => {
                write!(f, "uhid: {interface} device created (product 0x{product_id:04x})")
            }
            UhidNotice::Destroyed { interface } => write!(f, "uhid: {interface} device destroyed"),
            UhidNotice::Started { interface, dev_flags } => {
                write!(f, "uhid: {interface} device started (dev_flags {dev_flags:#x})")
            }
            UhidNotice::Stopped { interface } => write!(f, "uhid: {interface} device stopped"),
            UhidNotice::Opened { interface } => write!(f, "uhid: {interface} device opened by a process"),
            UhidNotice::Closed { interface } => write!(f, "uhid: {interface} device closed by every process"),
            UhidNotice::Received { interface, event, size } => write!(f, "uhid: {interface} <- {event}, {size} bytes"),
            UhidNotice::Sent { interface, event, size } => write!(f, "uhid: {interface} -> {event}, {size} bytes"),
            UhidNotice::Refused { interface, event, size, reason } => {
                write!(f, "uhid: {interface} {event} of {size} bytes refused: {reason}")
            }
            UhidNotice::NotRunning { interface } => write!(
                f,
                "uhid: the kernel does not run the {interface} device (it refused an input report); \
                 it stays absent until the next enumeration"
            ),
            UhidNotice::Ended { interface } => write!(f, "uhid: {interface} device file ended"),
            UhidNotice::Failed(reason) => write!(f, "uhid: {reason}"),
        }
    }
}

/// Counters of what the transport could not pass on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UhidStats {
    /// Device outputs UHID cannot present: CCID bulk-in and interrupt messages.
    pub ignored: u64,
    /// Host reports and requests refused: wrong size or report number, unsupported
    /// requests, reports of a device being destroyed, feature reads the device did not
    /// answer in time.
    pub refused: u64,
    /// Device outputs lost: no device for the interface, its file ended, its write queue
    /// was full, the kernel did not accept its CREATE2 or does not run it, or they answer
    /// inputs of an earlier enumeration (the fence, see the module docs).
    pub dropped: u64,
}

/// State shared by the runner thread and the device threads.
struct Shared {
    runner: Sender<Command>,
    observer: Option<Observer>,
    ignored: AtomicU64,
    refused: AtomicU64,
    dropped: AtomicU64,
}

impl Shared {
    fn notify(&self, notice: UhidNotice) {
        if let Some(observer) = &self.observer {
            observer(&notice);
        }
    }

    fn refuse(&self, interface: HidInterface, event: &'static str, size: usize, reason: &'static str) {
        self.refused.fetch_add(1, Ordering::Relaxed);
        self.notify(UhidNotice::Refused { interface, event, size, reason });
    }

    fn drop_output(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    fn input(&self, input: HostInput) {
        // A runner that is gone has nothing left to feed.
        let _ = self.runner.send(Command::Input(input));
    }

    /// Send a `Command::Status` marker; its answer arrives once the runner has handled
    /// every command sent before it. `None` when the runner is gone.
    fn marker(&self) -> Option<Receiver<Status>> {
        let (reply, answer) = mpsc::channel();
        self.runner.send(Command::Status(reply)).is_ok().then_some(answer)
    }
}

/// What one device's threads know about it.
#[derive(Debug, Default)]
struct DeviceState {
    /// The last CREATE2 was written and accepted, and no DESTROY since: the kernel holds a
    /// device that retiring must destroy.
    created: AtomicBool,
    /// Created, and the kernel has not refused an input report since (see
    /// [`UhidNotice::NotRunning`]): the device is presented as far as this side can tell.
    running: AtomicBool,
    /// Between `UHID_START` and `UHID_STOP`.
    started: AtomicBool,
    /// Between `UHID_OPEN` and `UHID_CLOSE`.
    opened: AtomicBool,
    /// The device is being unplugged: the writer writes what is still queued and the
    /// replies still owed, then DESTROY; the reader forwards nothing and ends at
    /// `UHID_STOP`.
    retiring: AtomicBool,
    /// Retired by a re-enumeration, not by dropping the transport: the runner still
    /// answers markers, so a feature read in flight waits for its answer and replies.
    /// Set before `retiring`, cleared when the transport is dropped.
    reenumerated: AtomicBool,
    /// Requests whose input reached the runner and whose reply is not queued yet
    /// ([`InFlight`]). A retiring writer waits for them (at most [`FEATURE_TIMEOUT`])
    /// before it writes DESTROY.
    in_flight: AtomicUsize,
    /// Held while the reader checks `retiring` and sends an input, and while `retire`
    /// raises the flag (see the module docs, Unplugging).
    gate: Mutex<()>,
}

impl DeviceState {
    fn gate(&self) -> MutexGuard<'_, ()> {
        self.gate.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn retiring(&self) -> bool {
        self.retiring.load(Ordering::SeqCst)
    }

    /// Neither created nor running any more.
    fn gone(&self) {
        self.created.store(false, Ordering::SeqCst);
        self.running.store(false, Ordering::SeqCst);
    }

    /// Whether a reply may still be queued: always before the device retires; after that
    /// only a reply `owed` to a request accepted before (an [`InFlight`]), and only when a
    /// re-enumeration retired the device. When the transport is dropped, the DESTROY fails
    /// the kernel's pending requests instead (`uhid_dev_destroy`).
    fn may_reply(&self, owed: bool) -> bool {
        !self.retiring() || (owed && self.reenumerated.load(Ordering::SeqCst))
    }
}

/// A request whose input the reader handed to the runner and whose reply it has not queued
/// yet (`DeviceState::in_flight`). Taken under the gate, so a request either counts before
/// the device retires or is refused; dropped once the reply is queued (or given up), which
/// lets a retiring writer go on to DESTROY. A USB device completes a control transfer it
/// accepted before it can act on its data, a reboot included, so its reply must not be
/// lost to a re-enumeration that the request itself caused.
struct InFlight(Arc<DeviceState>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

/// An item of a writer's queue.
enum Op {
    Event(Event),
    /// Wake the writer to stop: once the queue is written and DESTROY too when the device
    /// is retiring, at once when its reader has ended.
    Close,
}

/// One UHID device: its writer queue and its threads.
struct HidDevice {
    interface: HidInterface,
    queue: SyncSender<Op>,
    state: Arc<DeviceState>,
    /// Hands `Output::OtpFeature` to the OTP reader (OTP only).
    feature: Option<SyncSender<[u8; report::OTP_FEATURE_SIZE]>>,
    reader: Option<JoinHandle<()>>,
    writer: Option<JoinHandle<()>>,
    /// Disconnects when the writer thread ends; the device that replaces this one waits for
    /// it before it writes CREATE2.
    writer_done: Option<Receiver<()>>,
}

impl fmt::Debug for HidDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let flag = |flag: &AtomicBool| flag.load(Ordering::SeqCst);
        let alive = |handle: &Option<JoinHandle<()>>| handle.as_ref().is_some_and(|handle| !handle.is_finished());
        f.debug_struct("HidDevice")
            .field("interface", &self.interface)
            .field("reader_alive", &alive(&self.reader))
            .field("writer_alive", &alive(&self.writer))
            .field("created", &flag(&self.state.created))
            .field("running", &flag(&self.state.running))
            .field("started", &flag(&self.state.started))
            .field("opened", &flag(&self.state.opened))
            .field("retiring", &flag(&self.state.retiring))
            .finish()
    }
}

impl HidDevice {
    /// Open a UHID file for `interface` and start its threads. Nothing is written yet; the
    /// writer starts once `after` (the writer of the device this one replaces) has ended,
    /// or [`DROP_TIMEOUT`] has passed.
    fn open(
        interface: HidInterface,
        io: &mut dyn UhidIo,
        shared: &Arc<Shared>,
        after: Option<Receiver<()>>,
    ) -> io::Result<HidDevice> {
        let (input, output) = io.open()?;
        let (queue, ops) = mpsc::sync_channel(WRITE_QUEUE_EVENTS);
        let state = Arc::new(DeviceState::default());
        let (feature, answers) = match interface {
            HidInterface::Otp => {
                let (sender, receiver) = mpsc::sync_channel(FEATURE_QUEUE);
                (Some(sender), Some(receiver))
            }
            HidInterface::Fido => (None, None),
        };
        let (done, writer_done) = mpsc::channel::<()>();
        let (go, created) = mpsc::channel::<()>();
        let writer = {
            let (state, shared) = (Arc::clone(&state), Arc::clone(shared));
            thread::Builder::new().name(format!("lk-uhid-{interface}-w")).spawn(move || {
                let _done = done;
                if let Some(after) = after
                    && after.recv_timeout(DROP_TIMEOUT) == Err(RecvTimeoutError::Timeout)
                {
                    shared.notify(UhidNotice::Failed(format!("{interface}: the previous device's writer did not end")));
                }
                let writer = Writer {
                    interface,
                    output,
                    state: &state,
                    shared: &shared,
                    go: Some(go),
                    buffer: [0; UHID_EVENT_SIZE],
                    replied: None,
                };
                writer.run(&ops);
            })?
        };
        let reader = Reader {
            interface,
            input,
            created,
            queue: queue.clone(),
            state: Arc::clone(&state),
            shared: Arc::clone(shared),
            answers,
            window: Window::default(),
        };
        let reader = match thread::Builder::new().name(format!("lk-uhid-{interface}-r")).spawn(move || reader.run()) {
            Ok(handle) => handle,
            Err(error) => {
                // The writer ends on `Close` and drops its half; the reader's half went with
                // the closure.
                let _ = queue.try_send(Op::Close);
                return Err(error);
            }
        };
        Ok(HidDevice {
            interface,
            queue,
            state,
            feature,
            reader: Some(reader),
            writer: Some(writer),
            writer_done: Some(writer_done),
        })
    }

    /// Both threads have ended (or were joined).
    fn finished(&self) -> bool {
        [&self.reader, &self.writer].iter().all(|handle| handle.as_ref().is_none_or(JoinHandle::is_finished))
    }

    /// Queue an event for the writer without waiting. False when the queue is full or the
    /// writer is gone.
    fn send(&self, event: Event) -> bool {
        self.queue.try_send(Op::Event(event)).is_ok()
    }

    /// Unplug the device: raise `retiring` (under the gate, so the reader sends no input
    /// after this returns), then wake the writer, which writes what is still queued and
    /// the replies still owed, then `UHID_DESTROY`, and ends; the reader drops what still
    /// arrives and ends at the `UHID_STOP` that follows, or when the file ends.
    /// `reenumerated` is false when the transport is dropped: then no marker will be
    /// answered any more, and a feature read in flight gives up at once (also on a device
    /// an earlier re-enumeration retired). Idempotent.
    ///
    /// The wake is needed only when the queue is empty and the writer waits in `recv`.
    /// When the queue is full the wake is lost, and that is fine: the writer is busy, and
    /// it looks at the flag before the next item it takes, which is already there.
    fn retire(&mut self, reenumerated: bool) {
        self.feature = None;
        if !reenumerated {
            self.state.reenumerated.store(false, Ordering::SeqCst);
        }
        {
            let _gate = self.state.gate();
            if self.state.retiring() {
                return;
            }
            self.state.reenumerated.store(reenumerated, Ordering::SeqCst);
            self.state.retiring.store(true, Ordering::SeqCst);
        }
        let _ = self.queue.try_send(Op::Close);
    }

    /// Join the writer, then the reader, waiting until `deadline` at most; a thread still
    /// running then is left behind (it holds nothing but its half of the file and clones of
    /// the runner's sender) and reported.
    fn join(&mut self, deadline: Instant, shared: &Shared) {
        let interface = self.interface;
        for (role, slot) in [("writer", &mut self.writer), ("reader", &mut self.reader)] {
            let Some(handle) = slot.take() else {
                continue;
            };
            while !handle.is_finished() && Instant::now() < deadline {
                thread::sleep(JOIN_POLL);
            }
            if !handle.is_finished() {
                shared.notify(UhidNotice::Failed(format!("{interface}: the {role} thread did not end in time")));
            } else if handle.join().is_err() {
                shared.notify(UhidNotice::Failed(format!("{interface}: the {role} thread panicked")));
            }
        }
    }
}

/// The writer thread of one device.
struct Writer<'a> {
    interface: HidInterface,
    output: Box<dyn Write + Send>,
    state: &'a DeviceState,
    shared: &'a Shared,
    /// Tells the reader that the kernel accepted the CREATE2, so there is something to
    /// read. Dropped unsent when the writer ends before that (see [`Reader::run`]).
    go: Option<Sender<()>>,
    buffer: [u8; UHID_EVENT_SIZE],
    /// When the last GET_REPORT or SET_REPORT reply was written ([`DESTROY_AFTER_REPLY`]).
    replied: Option<Instant>,
}

impl Writer<'_> {
    /// Write queued events in order until `Op::Close`, the end of the queue, a file whose
    /// other side is gone, or the device is retiring; a retiring device is unplugged
    /// ([`Writer::unplug`]).
    fn run(mut self, ops: &Receiver<Op>) {
        let mut first = None;
        while let Ok(op) = ops.recv() {
            // Before every item, so a full queue cannot keep the unplug out (`retire`).
            if self.state.retiring() {
                first = Some(op);
                break;
            }
            let Op::Event(event) = op else {
                break;
            };
            if self.write(event).is_break() {
                self.state.gone();
                return;
            }
        }
        if self.state.retiring() {
            self.unplug(first, ops);
        }
        self.state.gone();
    }

    /// Unplug a retiring device: write what is still queued (`first`, then the rest), in
    /// order, waiting at most [`FEATURE_TIMEOUT`] for the replies still owed
    /// (`DeviceState::in_flight`), then `UHID_DESTROY` if the kernel holds the device.
    ///
    /// What is queued was queued before the device retired (`deliver` reaches only the
    /// current devices, and the reader queues only replies owed to requests it accepted
    /// before): outputs the device produced before it rebooted, such as the response to the
    /// command that rebooted it, and replies to requests it accepted, such as the
    /// SET_REPORT that completed that command. The queue is bounded and writes to
    /// `/dev/uhid` do not block, so the DESTROY still follows promptly: at once, or
    /// [`DESTROY_AFTER_REPLY`] after the last reply. A CREATE2 still queued is not
    /// written: a device retired before it was created stays uncreated, and one that was
    /// never created (or refused) gets no DESTROY either (`uhid_dev_destroy` would refuse
    /// it with `-EINVAL`).
    fn unplug(&mut self, first: Option<Op>, ops: &Receiver<Op>) {
        let deadline = Instant::now() + FEATURE_TIMEOUT;
        let mut next = first;
        loop {
            let op = match next.take() {
                Some(op) => op,
                None => match ops.try_recv() {
                    Ok(op) => op,
                    Err(TryRecvError::Disconnected) => break,
                    Err(TryRecvError::Empty) => {
                        // A reply is queued before its request stops counting, so once
                        // none counts, one more look finds every owed reply.
                        if self.state.in_flight.load(Ordering::SeqCst) == 0 || Instant::now() >= deadline {
                            next = ops.try_recv().ok();
                            if next.is_none() {
                                break;
                            }
                            continue;
                        }
                        match ops.recv_timeout(JOIN_POLL) {
                            Ok(op) => op,
                            Err(RecvTimeoutError::Timeout) => continue,
                            Err(RecvTimeoutError::Disconnected) => break,
                        }
                    }
                },
            };
            match op {
                Op::Close | Op::Event(Event::Create2(_)) => {}
                Op::Event(event) => {
                    if self.write(event).is_break() {
                        return;
                    }
                }
            }
        }
        if self.state.created.load(Ordering::SeqCst) {
            if let Some(replied) = self.replied {
                thread::sleep(DESTROY_AFTER_REPLY.saturating_sub(replied.elapsed()));
            }
            let _ = self.write(Event::Destroy);
        }
    }

    /// Write one event. `Break` when the other side of the file is gone.
    ///
    /// A write the kernel refuses concerns that event only and is reported; the file stays
    /// usable (`uhid_char_write` returns the error of the one event). `-EINVAL` for a whole
    /// `UHID_INPUT2` means the kernel does not run the device (see
    /// [`UhidNotice::NotRunning`]): that is reported once, and the device's input reports
    /// are dropped from then on.
    fn write(&mut self, event: Event) -> ControlFlow<()> {
        let (interface, state, shared) = (self.interface, self.state, self.shared);
        let input = matches!(event, Event::Input2 { .. });
        if input && !state.running.load(Ordering::SeqCst) {
            // `uhid_dev_input2` refuses input for a device the kernel does not run.
            shared.drop_output();
            return ControlFlow::Continue(());
        }
        if let Err(error) = event.encode_into(&mut self.buffer) {
            shared.notify(UhidNotice::Failed(format!("{interface}: {} cannot be encoded: {error}", event.name())));
            return ControlFlow::Continue(());
        }
        match self.output.write_all(&self.buffer).and_then(|()| self.output.flush()) {
            Ok(()) => {
                match &event {
                    Event::Create2(create) => {
                        state.created.store(true, Ordering::SeqCst);
                        state.running.store(true, Ordering::SeqCst);
                        if let Some(go) = self.go.take() {
                            let _ = go.send(());
                        }
                        shared.notify(UhidNotice::Created { interface, product_id: create.product });
                    }
                    Event::Destroy => {
                        state.gone();
                        shared.notify(UhidNotice::Destroyed { interface });
                    }
                    Event::GetReportReply { .. } | Event::SetReportReply { .. } => self.replied = Some(Instant::now()),
                    _ => {}
                }
                shared.notify(UhidNotice::Sent { interface, event: event.name(), size: event.data_len() });
            }
            Err(error) if input && error.kind() == io::ErrorKind::InvalidInput => {
                state.running.store(false, Ordering::SeqCst);
                shared.drop_output();
                shared.notify(UhidNotice::NotRunning { interface });
            }
            Err(error) => {
                if input {
                    shared.drop_output();
                }
                if matches!(event, Event::Create2(_)) {
                    state.gone();
                }
                shared.notify(UhidNotice::Failed(format!("{interface}: writing {} failed: {error}", event.name())));
                if peer_gone(&error) {
                    return ControlFlow::Break(());
                }
            }
        }
        ControlFlow::Continue(())
    }
}

/// Whether a write error means the other side of the file is gone (a socket pair whose
/// peer closed); `/dev/uhid` itself reports per-event errors only.
fn peer_gone(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected
            | io::ErrorKind::WriteZero
            | io::ErrorKind::UnexpectedEof
    )
}

/// A reader's inputs since its last marker, and the marker still to be answered (see the
/// module docs, Pacing).
#[derive(Debug, Default)]
struct Window {
    inputs: usize,
    marker: Option<Receiver<Status>>,
}

/// How a wait for a marker's answer ended.
enum Wait {
    Answered,
    /// The device is retiring; nothing it would forward matters any more.
    Retiring,
    /// The runner dropped the marker unanswered: it is gone.
    Gone,
    TimedOut,
}

/// The reader thread of one device.
struct Reader {
    interface: HidInterface,
    input: Box<dyn Read + Send>,
    /// Answered when the writer's CREATE2 was accepted; disconnected when the writer ended
    /// without one.
    created: Receiver<()>,
    /// The device's writer queue, for replies.
    queue: SyncSender<Op>,
    state: Arc<DeviceState>,
    shared: Arc<Shared>,
    /// Feature reports handed back by `deliver` (OTP only).
    answers: Option<Receiver<[u8; report::OTP_FEATURE_SIZE]>>,
    window: Window,
}

impl Reader {
    /// Read one whole event per read (`uhid_char_read` copies at most one event) until the
    /// file ends, or the device is retiring and its `UHID_STOP` arrives. Pace after each
    /// event (see the module docs).
    ///
    /// Reading starts once the kernel has accepted the CREATE2: before that a UHID file
    /// carries no events (`uhid_char_read` reads only what the device queued). A writer
    /// that ends without a CREATE2 (the device was retired before it was written, or the
    /// file failed) ends the reader at once, and with both halves dropped the file is
    /// closed. A reader blocked in `read()` could not be woken: no event would ever come.
    fn run(mut self) {
        let interface = self.interface;
        if self.created.recv().is_err() {
            return;
        }
        let mut buffer = [0; UHID_EVENT_SIZE];
        loop {
            if let Err(error) = self.input.read_exact(&mut buffer) {
                if !self.state.retiring() {
                    if error.kind() != io::ErrorKind::UnexpectedEof {
                        self.shared.notify(UhidNotice::Failed(format!("{interface}: reading failed: {error}")));
                    }
                    self.shared.notify(UhidNotice::Ended { interface });
                }
                break;
            }
            match Event::decode(&buffer) {
                Ok(event) => {
                    if self.handle(event).is_break() {
                        break;
                    }
                }
                Err(error) => {
                    self.shared
                        .notify(UhidNotice::Failed(format!("{interface}: event from the kernel ignored: {error}")));
                }
            }
            self.pace();
        }
        self.state.started.store(false, Ordering::SeqCst);
        self.state.opened.store(false, Ordering::SeqCst);
        // The writer ends too. A retiring device's writer ends on its own (`retire`); a
        // writer that is already gone has dropped the queue.
        if !self.state.retiring() {
            let _ = self.queue.send(Op::Close);
        }
    }

    fn handle(&mut self, event: Event) -> ControlFlow<()> {
        let interface = self.interface;
        self.shared.notify(UhidNotice::Received { interface, event: event.name(), size: event.data_len() });
        match event {
            Event::Start { dev_flags } => {
                self.state.started.store(true, Ordering::SeqCst);
                self.shared.notify(UhidNotice::Started { interface, dev_flags });
            }
            Event::Stop => {
                self.state.started.store(false, Ordering::SeqCst);
                self.shared.notify(UhidNotice::Stopped { interface });
                if self.state.retiring() {
                    return ControlFlow::Break(());
                }
            }
            Event::Open => {
                self.state.opened.store(true, Ordering::SeqCst);
                self.shared.notify(UhidNotice::Opened { interface });
            }
            Event::Close => {
                self.state.opened.store(false, Ordering::SeqCst);
                self.shared.notify(UhidNotice::Closed { interface });
            }
            Event::Output { data, rtype } => self.output(&data, rtype),
            Event::GetReport { id, rnum, rtype } => self.get_report(id, rnum, rtype),
            Event::SetReport { id, rnum, rtype, data } => self.set_report(id, rnum, rtype, &data),
            other => {
                let name = other.name();
                self.shared.notify(UhidNotice::Failed(format!("{interface}: unexpected {name} from the kernel")));
            }
        }
        ControlFlow::Continue(())
    }

    /// Send `input` to the runner, unless the device is retiring: reports of a device that
    /// is being destroyed do not reach the runner (the device has rebooted or the transport
    /// is going away). The check and the send happen under the gate (see the module docs,
    /// Unplugging). Counts into the window.
    fn forward(&mut self, input: HostInput) -> Result<(), &'static str> {
        self.forward_request(input).map(drop)
    }

    /// [`Reader::forward`] for a request that needs a reply: the request counts as in
    /// flight from before the input is sent (under the gate) until the returned
    /// [`InFlight`] is dropped, after its reply was queued.
    fn forward_request(&mut self, input: HostInput) -> Result<InFlight, &'static str> {
        let in_flight = {
            let _gate = self.state.gate();
            if self.state.retiring() {
                return Err(RETIRING);
            }
            self.state.in_flight.fetch_add(1, Ordering::SeqCst);
            self.shared.input(input);
            InFlight(Arc::clone(&self.state))
        };
        self.window.inputs += 1;
        Ok(in_flight)
    }

    /// When the window is full, wait for the runner to answer the previous window's marker,
    /// then send this window's (see the module docs, Pacing).
    fn pace(&mut self) {
        if self.window.inputs < INPUT_WINDOW {
            return;
        }
        if let Some(answer) = self.window.marker.take() {
            match self.wait(&answer, None, false) {
                Wait::Answered => {}
                // A retiring device forwards nothing more; a gone runner takes nothing.
                Wait::Retiring | Wait::Gone | Wait::TimedOut => {
                    self.window = Window::default();
                    return;
                }
            }
        }
        if let Some(marker) = self.shared.marker() {
            self.window = Window { inputs: 0, marker: Some(marker) };
        }
    }

    /// Wait for a marker's answer until `deadline` (or without one), in steps of
    /// [`RETIRE_POLL`], giving up once the device is retiring, unless the wait is for the
    /// answer to a request that is `owed` a reply and a re-enumeration retired the device
    /// ([`DeviceState::may_reply`]): the runner still answers then, and the reply is still
    /// written before the DESTROY.
    fn wait(&self, answer: &Receiver<Status>, deadline: Option<Instant>, owed: bool) -> Wait {
        loop {
            if !self.state.may_reply(owed) {
                return Wait::Retiring;
            }
            let step = match deadline {
                Some(deadline) => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Wait::TimedOut;
                    }
                    left.min(RETIRE_POLL)
                }
                None => RETIRE_POLL,
            };
            match answer.recv_timeout(step) {
                Ok(_) => return Wait::Answered,
                Err(RecvTimeoutError::Disconnected) => return Wait::Gone,
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
    }

    /// `UHID_OUTPUT`: the interrupt OUT path, where hidraw `write()` lands
    /// (`uhid_hid_output_report`).
    fn output(&mut self, data: &[u8], rtype: ReportType) {
        let refused = if self.state.retiring() {
            Some(RETIRING)
        } else {
            match self.interface {
                // The boot keyboard's LED output report (1 byte from the kernel's input
                // layer, 2 from a hidraw write): nothing in the engine takes it.
                HidInterface::Otp => None,
                HidInterface::Fido if rtype != ReportType::Output => Some("not an output report"),
                HidInterface::Fido => {
                    report::fido_output(data).and_then(|report| self.forward(HostInput::FidoReport(report))).err()
                }
            }
        };
        if let Some(reason) = refused {
            self.shared.refuse(self.interface, "OUTPUT", data.len(), reason);
        }
    }

    /// `UHID_GET_REPORT`: only the OTP feature report, report number 0, is supported.
    /// Everything else gets [`EIO`] at once, so the caller does not wait for the kernel's
    /// timeout.
    fn get_report(&mut self, id: u32, rnum: u8, rtype: ReportType) {
        let (in_flight, answer) = if self.state.retiring() {
            (None, Err(RETIRING))
        } else {
            match (self.interface, rtype) {
                (HidInterface::Otp, ReportType::Feature) if rnum == report::UNNUMBERED => {
                    let (in_flight, answer) = self.feature();
                    (in_flight, answer.map(|report| report::otp_feature_reply(&report).to_vec()))
                }
                (HidInterface::Otp, ReportType::Feature) => (None, Err("report number is not 0")),
                _ => (None, Err("unsupported GET_REPORT")),
            }
        };
        let reply = match answer {
            Ok(data) => Event::GetReportReply { id, err: 0, data },
            Err(reason) => {
                self.shared.refuse(self.interface, "GET_REPORT", 0, reason);
                Event::GetReportReply { id, err: EIO, data: Vec::new() }
            }
        };
        self.reply(reply, in_flight.is_some());
    }

    /// `UHID_SET_REPORT`: the OTP feature report goes to the runner, the keyboard's LED
    /// report is acknowledged and ignored, a FIDO output report goes to the runner
    /// (`docs/PROGRAM.md` "lk-gadget" control requests). The reply follows at once: the
    /// runner handles inputs in order, so a GET_REPORT after it sees its effect.
    fn set_report(&mut self, id: u32, rnum: u8, rtype: ReportType, data: &[u8]) {
        let result = if self.state.retiring() {
            Err(RETIRING)
        } else {
            match (self.interface, rtype) {
                (HidInterface::Otp, ReportType::Feature) => report::otp_feature_set(rnum, data)
                    .and_then(|report| self.forward_request(HostInput::OtpSetFeature(report)))
                    .map(Some),
                (HidInterface::Otp, ReportType::Output) => Ok(None),
                (HidInterface::Fido, ReportType::Output) => report::fido_set_output(rnum, data)
                    .and_then(|report| self.forward_request(HostInput::FidoReport(report)))
                    .map(Some),
                _ => Err("unsupported SET_REPORT"),
            }
        };
        let (in_flight, err) = match result {
            Ok(in_flight) => (in_flight, 0),
            Err(reason) => {
                self.shared.refuse(self.interface, "SET_REPORT", data.len(), reason);
                (None, EIO)
            }
        };
        self.reply(Event::SetReportReply { id, err }, in_flight.is_some());
    }

    /// Queue a reply; it waits for room, since a lost reply leaves the caller waiting for
    /// the kernel's timeout. A writer that is gone takes nothing. After the device retired,
    /// only a reply `owed` to a request accepted before is queued, and only after a
    /// re-enumeration ([`DeviceState::may_reply`]); the writer writes it before the
    /// DESTROY. Otherwise the DESTROY fails the kernel's request (`uhid_dev_destroy`).
    /// The caller drops the request's [`InFlight`] after this.
    fn reply(&self, event: Event, owed: bool) {
        if self.state.may_reply(owed) {
            let _ = self.queue.send(Op::Event(event));
        }
    }

    /// Ask the runner for the OTP feature report and wait (at most [`FEATURE_TIMEOUT`],
    /// giving up once the device is retiring) for the `Output::OtpFeature` that `deliver`
    /// hands back.
    ///
    /// Answers left from an earlier request that timed out are drained first. After
    /// `OtpGetFeature` a `Command::Status` marker follows: the runner handles commands in
    /// order and delivers an input's outputs before it takes the next command, so once the
    /// marker is answered, this request's answer has been handed over; it is the last one
    /// in the channel (a late answer to an earlier request can only come before it). The
    /// answered marker also means every input of this reader has been handled, so the
    /// window starts afresh.
    ///
    /// The request is in flight from before `OtpGetFeature` is sent (the returned
    /// [`InFlight`], `None` when it was refused at once). When the answer comes with a
    /// re-enumeration (the device reboots right after the host read the status of a
    /// Management write), the device is already retiring when the marker is answered; the
    /// wait goes on regardless and the reply is still written before the DESTROY.
    fn feature(&mut self) -> (Option<InFlight>, Result<[u8; report::OTP_FEATURE_SIZE], &'static str>) {
        const GONE: &str = "the runner is gone";
        let Some(answers) = self.answers.as_ref() else {
            return (None, Err("unsupported GET_REPORT"));
        };
        while answers.try_recv().is_ok() {}
        let in_flight = match self.forward_request(HostInput::OtpGetFeature) {
            Ok(in_flight) => in_flight,
            Err(reason) => return (None, Err(reason)),
        };
        let Some(marker) = self.shared.marker() else {
            return (Some(in_flight), Err(GONE));
        };
        let answer = match self.wait(&marker, Some(Instant::now() + FEATURE_TIMEOUT), true) {
            Wait::Answered => {
                self.window = Window::default();
                self.answers
                    .as_ref()
                    .and_then(|answers| answers.try_iter().last())
                    .ok_or("the device gave no feature report")
            }
            Wait::Retiring => Err(RETIRING),
            Wait::Gone => Err(GONE),
            Wait::TimedOut => Err("the device gave no feature report in time"),
        };
        (Some(in_flight), answer)
    }
}

/// The UHID transport: the FIDO and OTP HID interfaces as Linux UHID devices
/// (`docs/PROGRAM.md` "lk-uhid").
///
/// - [`Transport::enumerate`] retires the devices of the previous enumeration (DESTROY,
///   then their files are closed), sends the fence (see the module docs), and creates one
///   device per enabled HID interface, each on a new file, with `UHID_CREATE2` from the
///   identity. Then the runner gets `Input::Bus(BusEvent::PowerCycle)` once (creating the
///   devices is a plug-in), if any device was presented.
/// - [`Transport::deliver`] queues `UHID_INPUT2` (64 bytes on the FIDO device, 8 on the
///   OTP device) and hands `Output::OtpFeature` to the pending GET_REPORT; until the fence
///   is answered, these outputs are dropped. CCID outputs are ignored
///   ([`UhidStats::ignored`]), as is `PresenceIndicator`.
/// - [`Transport::attached`] is whether the kernel accepted a device's `UHID_CREATE2` and,
///   as far as this side can tell, runs it (no DESTROY since, no input refused with
///   `-EINVAL`).
/// - Dropping the transport destroys the devices, closes their files and joins their
///   threads (at most [`DROP_TIMEOUT`]).
pub struct UhidTransport {
    io: Box<dyn UhidIo>,
    shared: Arc<Shared>,
    otp: Option<HidDevice>,
    fido: Option<HidDevice>,
    /// Devices of earlier enumerations whose threads may still be ending.
    retired: Vec<HidDevice>,
    /// The answer to the fence of the last enumeration that retired a device, until it
    /// arrives.
    fence: Option<Receiver<Status>>,
}

impl fmt::Debug for UhidTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UhidTransport")
            .field("io", &self.io)
            .field("otp", &self.otp)
            .field("fido", &self.fido)
            .field("retired", &self.retired.len())
            .field("fenced", &self.fence.is_some())
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl UhidTransport {
    /// A transport that opens its devices through `io` (`DevUhid` for `/dev/uhid`) and
    /// feeds the runner through `runner` (`lk_run::Runner::sender`). Nothing is opened
    /// before the first enumeration. The runner must answer `Command::Status` (pacing, the
    /// fence and feature reads depend on it; `lk_run::Runner` does).
    pub fn new(io: Box<dyn UhidIo>, runner: Sender<Command>) -> UhidTransport {
        UhidTransport::with_observer(io, runner, None)
    }

    /// [`UhidTransport::new`] with an observer for device events.
    pub fn with_observer(io: Box<dyn UhidIo>, runner: Sender<Command>, observer: Option<Observer>) -> UhidTransport {
        let shared = Shared {
            runner,
            observer,
            ignored: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        };
        UhidTransport { io, shared: Arc::new(shared), otp: None, fido: None, retired: Vec::new(), fence: None }
    }

    /// The counters so far.
    pub fn stats(&self) -> UhidStats {
        UhidStats {
            ignored: self.shared.ignored.load(Ordering::Relaxed),
            refused: self.shared.refused.load(Ordering::Relaxed),
            dropped: self.shared.dropped.load(Ordering::Relaxed),
        }
    }

    fn slot(&mut self, interface: HidInterface) -> &mut Option<HidDevice> {
        match interface {
            HidInterface::Otp => &mut self.otp,
            HidInterface::Fido => &mut self.fido,
        }
    }

    fn device(&self, interface: HidInterface) -> Option<&HidDevice> {
        match interface {
            HidInterface::Otp => self.otp.as_ref(),
            HidInterface::Fido => self.fido.as_ref(),
        }
    }

    /// Whether the fence is still unanswered, so outputs now answer inputs of retired
    /// devices. A fence the runner dropped unanswered (it is gone) no longer holds.
    fn fenced(&mut self) -> bool {
        let Some(fence) = &self.fence else {
            return false;
        };
        match fence.try_recv() {
            Err(TryRecvError::Empty) => true,
            Ok(_) | Err(TryRecvError::Disconnected) => {
                self.fence = None;
                false
            }
        }
    }

    /// Queue an input report for the device of `interface`.
    fn input_report(&self, interface: HidInterface, report: &[u8]) {
        let queued = self.device(interface).is_some_and(|device| device.send(Event::Input2 { data: report.to_vec() }));
        if !queued {
            self.shared.drop_output();
        }
    }

    /// Join the retired devices whose threads have ended.
    fn reap(&mut self) {
        let shared = &self.shared;
        self.retired.retain_mut(|device| {
            if !device.finished() {
                return true;
            }
            device.join(Instant::now(), shared);
            false
        });
    }
}

impl Transport for UhidTransport {
    fn enumerate(&mut self, identity: &UsbIdentity) {
        self.reap();
        self.shared.notify(UhidNotice::Enumerated {
            product_id: identity.product_id,
            otp: identity.interfaces.otp,
            fido: identity.interfaces.fido,
        });
        // Unplug: every device of the previous enumeration goes, whether or not its
        // interface stays. Each new device's writer waits for its predecessor's writer.
        let mut previous: [Option<Receiver<()>>; 2] = [None, None];
        let mut retired = false;
        for (after, interface) in previous.iter_mut().zip(HidInterface::ALL) {
            if let Some(mut device) = self.slot(interface).take() {
                device.retire(true);
                *after = device.writer_done.take();
                self.retired.push(device);
                retired = true;
            }
        }
        if retired {
            // The fence follows every input of the retired devices (`retire` closed their
            // gates) and comes before any input of the new ones. A later fence replaces an
            // unanswered one: it comes later in the channel, so its answer implies the
            // earlier one's. After the `Reenumerate` that may have led here, the engine
            // emits nothing but `PresenceIndicator` in the same batch (`Device::handle`,
            // `crates/lk-device/src/lib.rs`), so the fence drops nothing of the rebooted
            // device's own.
            self.fence = self.shared.marker();
        }
        let mut presented = false;
        for (after, interface) in previous.into_iter().zip(HidInterface::ALL) {
            if !interface.enabled(identity) {
                continue;
            }
            match HidDevice::open(interface, self.io.as_mut(), &self.shared, after) {
                Ok(device) => {
                    presented |= self.slot(interface).insert(device).send(Event::Create2(create2(identity, interface)));
                }
                Err(error) => {
                    self.shared.notify(UhidNotice::Failed(format!("{interface}: cannot open a UHID device: {error}")));
                }
            }
        }
        if presented {
            // Creating the devices is a plug-in (`docs/PROGRAM.md` "lk-uhid", Bus events). The
            // CREATE2 events are queued ahead of any INPUT2 the power cycle causes.
            self.shared.input(HostInput::Bus(BusEvent::PowerCycle));
        }
    }

    fn deliver(&mut self, output: Output) {
        let report = matches!(output, Output::FidoReport(_) | Output::OtpKeyboard(_) | Output::OtpFeature(_));
        if report && self.fenced() {
            self.shared.drop_output();
            return;
        }
        match output {
            Output::FidoReport(report) => self.input_report(HidInterface::Fido, &report),
            Output::OtpKeyboard(report) => self.input_report(HidInterface::Otp, &report),
            Output::OtpFeature(report) => {
                let queued = self
                    .otp
                    .as_ref()
                    .and_then(|device| device.feature.as_ref())
                    .is_some_and(|answers| answers.try_send(report).is_ok());
                if !queued {
                    self.shared.drop_output();
                }
            }
            Output::Ccid(_) | Output::CcidInterrupt(_) => {
                self.shared.ignored.fetch_add(1, Ordering::Relaxed);
            }
            // UHID has no presence indicator; `Reenumerate` never arrives here (the runner
            // calls `enumerate`).
            Output::PresenceIndicator(_) | Output::Reenumerate(_) => {}
        }
    }

    fn attached(&self) -> Option<bool> {
        let running =
            [&self.otp, &self.fido].into_iter().flatten().any(|device| device.state.running.load(Ordering::SeqCst));
        Some(running)
    }
}

impl Drop for UhidTransport {
    fn drop(&mut self) {
        let mut devices: Vec<HidDevice> =
            self.otp.take().into_iter().chain(self.fido.take()).chain(self.retired.drain(..)).collect();
        for device in &mut devices {
            device.retire(false);
        }
        let deadline = Instant::now() + DROP_TIMEOUT;
        for device in &mut devices {
            device.join(deadline, &self.shared);
        }
    }
}

/// `UHID_CREATE2` for `interface` (`docs/PROGRAM.md` "lk-uhid"): `name` the product string,
/// `phys` [`PHYS`], `uniq` the serial string or empty, `bus` [`BUS_USB`], the identity's
/// vendor, product and release (`version`, which usbhid fills with `bcdDevice` too),
/// `country` 0 (the HID descriptor's `bCountryCode`, `lk_device::UsbIdentity::
/// configuration_descriptor`), and the interface's report descriptor.
fn create2(identity: &UsbIdentity, interface: HidInterface) -> Create2 {
    Create2 {
        name: c_string(&identity.product, NAME_SIZE - 1),
        phys: PHYS.to_owned(),
        uniq: c_string(identity.serial.as_deref().unwrap_or_default(), UNIQ_SIZE - 1),
        bus: BUS_USB,
        vendor: u32::from(identity.vendor_id),
        product: u32::from(identity.product_id),
        version: u32::from(identity.device_release),
        country: 0,
        report_descriptor: interface.report_descriptor(identity).to_vec(),
    }
}

/// `text` as the kernel would keep it in a field of `max` bytes plus NUL: up to the first
/// NUL, truncated at a character boundary (`strscpy` in `uhid_dev_create2` truncates too;
/// a name that is too long must not keep the device from being presented).
fn c_string(text: &str, max: usize) -> String {
    let text = text.split('\0').next().unwrap_or_default();
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_strings_end_at_nul_and_are_cut_at_a_character_boundary() {
        assert_eq!(c_string("YubiKey", 127), "YubiKey");
        assert_eq!(c_string("ab\0cd", 127), "ab");
        assert_eq!(c_string(&"x".repeat(200), 127).len(), 127);
        // "é" is two bytes; a cut through it moves back to the boundary.
        let text = format!("{}é", "x".repeat(126));
        assert_eq!(c_string(&text, 127), "x".repeat(126));
        assert_eq!(c_string("", 63), "");
    }

    #[test]
    fn notices_read_as_log_lines() {
        let enumerated = UhidNotice::Enumerated { product_id: 0x0407, otp: true, fido: true };
        assert_eq!(enumerated.to_string(), "uhid: enumerated as product 0x0407 (otp,fido)");
        let refused = UhidNotice::Refused {
            interface: HidInterface::Fido,
            event: "OUTPUT",
            size: 65,
            reason: "wrong report size",
        };
        assert_eq!(refused.to_string(), "uhid: fido OUTPUT of 65 bytes refused: wrong report size");
        let sent = UhidNotice::Sent { interface: HidInterface::Otp, event: "INPUT2", size: 8 };
        assert_eq!(sent.to_string(), "uhid: otp -> INPUT2, 8 bytes");
        let not_running = UhidNotice::NotRunning { interface: HidInterface::Fido };
        assert!(not_running.to_string().starts_with("uhid: the kernel does not run the fido device"), "{not_running}");
    }

    #[test]
    fn write_errors_of_a_gone_peer_end_the_writer_and_others_do_not() {
        assert!(peer_gone(&io::Error::from(io::ErrorKind::BrokenPipe)));
        assert!(peer_gone(&io::Error::from(io::ErrorKind::WriteZero)));
        assert!(!peer_gone(&io::Error::from(io::ErrorKind::InvalidInput)));
        assert!(!peer_gone(&io::Error::from(io::ErrorKind::Unsupported)));
        assert!(!peer_gone(&io::Error::other("EALREADY")));
    }
}
