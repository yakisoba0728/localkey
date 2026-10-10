//! Shared test harness: a fake [`UhidIo`] that hands out `UnixStream::pair()` halves, a
//! fake kernel per opened file that reads and writes whole `struct uhid_event`s, and a fake
//! runner thread that owns the transport, as `lk_run::Runner` does.
//!
//! The fake kernel answers `UHID_CREATE2` with `UHID_START` and `UHID_DESTROY` with
//! `UHID_STOP` (each switchable), as `drivers/hid/uhid.c` does once a HID driver has
//! started the device. Everything else it reads goes to the test.
//!
//! The fake runner forwards every input to the test. It answers `OtpGetFeature` by calling
//! `deliver(Output::OtpFeature)` on the transport and answers `Command::Status` markers,
//! according to its [`Answer`].
//!
//! [`PairIo`] is the bare alternative: it hands the kernel end of every file to the test
//! as a raw stream, so the test decides when (and whether) the kernel reads.

#![allow(dead_code)]

use std::fmt;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use lk_core::UsbInterfaces;
use lk_device::{FIDO_REPORT_DESCRIPTOR, OTP_REPORT_DESCRIPTOR, Output, UsbIdentity};
use lk_run::{Command, HostInput, Status, Transport};
use lk_uhid::event::{Create2, DecodeError, Event, UHID_EVENT_SIZE, UHID_INPUT2};
use lk_uhid::{HidInterface, Observer, UhidHalves, UhidIo, UhidNotice, UhidStats, UhidTransport};

/// How long a test waits for something that must happen. Generous, for loaded machines.
pub const WAIT: Duration = Duration::from_secs(10);
/// How long a test watches for something that must not happen.
pub const QUIET: Duration = Duration::from_millis(300);

/// Every interface.
pub const ALL: UsbInterfaces = UsbInterfaces { otp: true, fido: true, ccid: true };
/// FIDO and CCID, as the reference key ships.
pub const FIDO_CCID: UsbInterfaces = UsbInterfaces { otp: false, fido: true, ccid: true };
/// CCID only: nothing UHID can present.
pub const CCID: UsbInterfaces = UsbInterfaces { otp: false, fido: false, ccid: true };

/// A YubiKey-like identity with `product_id` and `interfaces`.
pub fn identity(product_id: u16, interfaces: UsbInterfaces) -> UsbIdentity {
    UsbIdentity {
        vendor_id: 0x1050,
        product_id,
        device_release: 0x0574,
        manufacturer: "Yubico".to_owned(),
        product: "YubiKey OTP+FIDO+CCID".to_owned(),
        serial: Some("12345678".to_owned()),
        interfaces,
        fido_report_descriptor: FIDO_REPORT_DESCRIPTOR.to_vec(),
        otp_report_descriptor: OTP_REPORT_DESCRIPTOR.to_vec(),
        ccid_class_descriptor: vec![0x36; 54],
    }
}

/// How the fake kernel answers device lifecycle events.
#[derive(Debug, Clone, Copy)]
pub struct KernelMode {
    /// Send `UHID_START` after every `UHID_CREATE2`.
    pub auto_start: bool,
    /// Send `UHID_STOP` after every `UHID_DESTROY`.
    pub auto_stop: bool,
}

impl Default for KernelMode {
    fn default() -> Self {
        KernelMode { auto_start: true, auto_stop: true }
    }
}

/// The kernel end of one opened UHID file.
pub struct Kernel {
    events: Receiver<(Vec<u8>, Result<Event, DecodeError>)>,
    /// The stream for writing, shared with the reading thread (for its START and STOP);
    /// `None` once the test closed the kernel side.
    writer: Arc<Mutex<Option<UnixStream>>>,
    closed: Arc<AtomicBool>,
}

impl fmt::Debug for Kernel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Kernel").finish_non_exhaustive()
    }
}

/// How often the fake kernel's reading thread checks whether the test closed its side.
const KERNEL_POLL: Duration = Duration::from_millis(20);

impl Kernel {
    fn spawn(stream: UnixStream, mode: KernelMode) -> io::Result<Kernel> {
        let mut reader = stream.try_clone()?;
        reader.set_read_timeout(Some(KERNEL_POLL))?;
        let writer = Arc::new(Mutex::new(Some(stream)));
        let replies = Arc::clone(&writer);
        let closed = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&closed);
        let (sender, events) = mpsc::channel();
        thread::spawn(move || {
            let mut buffer = vec![0; UHID_EVENT_SIZE];
            let mut filled = 0;
            // Whole events, kept across read timeouts; ends at EOF, on an error, or once
            // the test closed the kernel side (then its file descriptor goes too).
            while !stop.load(Ordering::SeqCst) {
                match reader.read(&mut buffer[filled..]) {
                    Ok(0) => break,
                    Ok(read) => filled += read,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
                        ) =>
                    {
                        continue;
                    }
                    Err(_) => break,
                }
                if filled < UHID_EVENT_SIZE {
                    continue;
                }
                filled = 0;
                let event = Event::decode(&buffer);
                match &event {
                    Ok(Event::Create2(_)) if mode.auto_start => write_event(&replies, &Event::Start { dev_flags: 0 }),
                    Ok(Event::Destroy) if mode.auto_stop => write_event(&replies, &Event::Stop),
                    _ => {}
                }
                if sender.send((buffer.clone(), event)).is_err() {
                    break;
                }
            }
        });
        Ok(Kernel { events, writer, closed })
    }

    /// The next event the transport wrote, with its raw bytes.
    pub fn next_raw(&self) -> (Vec<u8>, Event) {
        match self.events.recv_timeout(WAIT) {
            Ok((raw, Ok(event))) => (raw, event),
            Ok((_, Err(error))) => panic!("the transport wrote an undecodable event: {error}"),
            Err(RecvTimeoutError::Timeout) => panic!("the kernel received nothing within {WAIT:?}"),
            Err(RecvTimeoutError::Disconnected) => panic!("the transport closed the file"),
        }
    }

    /// The next event the transport wrote.
    pub fn next(&self) -> Event {
        self.next_raw().1
    }

    /// An event written within [`QUIET`], if any.
    pub fn quiet(&self) -> Option<Event> {
        match self.events.recv_timeout(QUIET) {
            Ok((_, event)) => Some(event.expect("the transport writes decodable events")),
            Err(_) => None,
        }
    }

    /// Whether the transport closes the file within [`WAIT`] (events before that are
    /// skipped).
    pub fn closes(&self) -> bool {
        let deadline = Instant::now() + WAIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.events.recv_timeout(left) {
                Ok(_) => {}
                Err(RecvTimeoutError::Disconnected) => return true,
                Err(RecvTimeoutError::Timeout) => return false,
            }
        }
    }

    /// Write one whole event to the transport.
    pub fn send(&self, event: &Event) {
        write_event(&self.writer, event);
    }

    /// An output report on the interrupt channel.
    pub fn output(&self, data: Vec<u8>) {
        self.send(&Event::Output { data, rtype: lk_uhid::event::ReportType::Output });
    }

    /// Close the kernel side of the file: shut the socket down and close every kernel-side
    /// descriptor (the reading thread lets go of its own within [`KERNEL_POLL`]).
    ///
    /// Shutting down alone is not enough on macOS: a peer `read()` that starts while the
    /// shutdown is under way was seen to miss the end of the stream and block, while the
    /// last close always wakes it.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let stream = self.writer.lock().unwrap_or_else(PoisonError::into_inner).take();
        if let Some(stream) = stream {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

fn write_event(writer: &Mutex<Option<UnixStream>>, event: &Event) {
    let bytes = event.encode().expect("test events encode");
    let mut stream = writer.lock().unwrap_or_else(PoisonError::into_inner);
    // A transport that closed its side takes nothing more; a closed kernel side sends
    // nothing more.
    if let Some(stream) = stream.as_mut() {
        let _ = stream.write_all(&bytes);
    }
}

/// The test [`UhidIo`]: every open is a new socket pair whose other end becomes a
/// [`Kernel`] for the test.
#[derive(Debug)]
struct FakeIo {
    kernels: Sender<Kernel>,
    mode: KernelMode,
    fail: Arc<AtomicBool>,
    refuse_input: Arc<AtomicBool>,
}

impl UhidIo for FakeIo {
    fn open(&mut self) -> io::Result<UhidHalves> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "fake: permission denied"));
        }
        let (ours, theirs) = UnixStream::pair()?;
        let reader = ours.try_clone()?;
        let _ = self.kernels.send(Kernel::spawn(theirs, self.mode)?);
        let writer = KernelWriter { stream: ours, refuse_input: Arc::clone(&self.refuse_input) };
        Ok((Box::new(reader), Box::new(writer)))
    }
}

/// The transport's half for writing. While `refuse_input` is set it refuses every
/// `UHID_INPUT2` with `-EINVAL` (`ErrorKind::InvalidInput`), as `uhid_char_write` does for a
/// device the kernel does not run (`uhid_dev_input2` in `drivers/hid/uhid.c`), and writes
/// nothing. The transport writes one whole event per `write` call.
#[derive(Debug)]
struct KernelWriter {
    stream: UnixStream,
    refuse_input: Arc<AtomicBool>,
}

impl Write for KernelWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.refuse_input.load(Ordering::SeqCst) && buf.get(..4) == Some(&UHID_INPUT2.to_ne_bytes()[..]) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "fake: the device is not running"));
        }
        self.stream.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/// A [`UhidIo`] that hands the kernel end of every opened file to the test as a raw
/// stream.
#[derive(Debug)]
pub struct PairIo {
    pub kernels: Sender<UnixStream>,
}

impl UhidIo for PairIo {
    fn open(&mut self) -> io::Result<UhidHalves> {
        let (ours, theirs) = UnixStream::pair()?;
        let reader = ours.try_clone()?;
        let _ = self.kernels.send(theirs);
        Ok((Box::new(reader), Box::new(ours)))
    }
}

/// One whole `struct uhid_event` from a raw kernel end.
pub fn read_event(stream: &mut UnixStream) -> io::Result<Event> {
    let mut buffer = vec![0; UHID_EVENT_SIZE];
    stream.read_exact(&mut buffer)?;
    Event::decode(&buffer).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
}

/// How the fake runner answers a GET_REPORT(feature).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// The device answers with this report; `Status` markers are answered.
    Feature([u8; 8]),
    /// A late answer to an earlier request is handed back first, then the device's answer
    /// (both after the reader sent `OtpGetFeature`); `Status` markers are answered.
    StaleThen([u8; 8], [u8; 8]),
    /// The device gives no feature report; `Status` markers are answered.
    Nothing,
    /// The runner is stuck: no feature report, `Status` markers never answered.
    Silent,
}

/// What the fake runner thread does.
enum Op {
    Command(Command),
    Enumerate(UsbIdentity),
    /// Enumerate, then deliver the outputs before taking any other command.
    EnumerateThenDeliver(UsbIdentity, Vec<Output>),
    Deliver(Output),
    SetAnswer(Answer),
    Stats(Sender<UhidStats>),
    Attached(Sender<Option<bool>>),
    Debug(Sender<String>),
    Drop(Sender<Duration>),
    Exit,
}

/// One device as the fake kernel first saw it.
#[derive(Debug)]
pub struct Device {
    pub kernel: Kernel,
    pub create: Create2,
    pub raw: Vec<u8>,
}

impl Device {
    fn from(kernel: Kernel) -> Device {
        match kernel.next_raw() {
            (raw, Event::Create2(create)) => Device { kernel, create, raw },
            (_, other) => panic!("the first event of a device is {other:?}, not CREATE2"),
        }
    }

    pub fn interface(&self) -> HidInterface {
        if self.create.report_descriptor == FIDO_REPORT_DESCRIPTOR { HidInterface::Fido } else { HidInterface::Otp }
    }
}

/// The transport inside a fake runner, with a fake kernel per opened file.
pub struct Harness {
    ops: Sender<Op>,
    inputs: Receiver<HostInput>,
    kernels: Receiver<Kernel>,
    notices: Receiver<UhidNotice>,
    fail: Arc<AtomicBool>,
    refuse_input: Arc<AtomicBool>,
    runner: Option<JoinHandle<()>>,
}

impl fmt::Debug for Harness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Harness").finish_non_exhaustive()
    }
}

impl Harness {
    pub fn new() -> Harness {
        Harness::with_mode(KernelMode::default())
    }

    pub fn with_mode(mode: KernelMode) -> Harness {
        let (kernel_sender, kernels) = mpsc::channel();
        let fail = Arc::new(AtomicBool::new(false));
        let refuse_input = Arc::new(AtomicBool::new(false));
        let io =
            FakeIo { kernels: kernel_sender, mode, fail: Arc::clone(&fail), refuse_input: Arc::clone(&refuse_input) };
        let (notice_sender, notices) = mpsc::channel();
        let observer: Observer = Arc::new(move |notice: &UhidNotice| {
            let _ = notice_sender.send(notice.clone());
        });
        let (command_sender, commands) = mpsc::channel::<Command>();
        let transport = UhidTransport::with_observer(Box::new(io), command_sender, Some(observer));
        let (ops, op_receiver) = mpsc::channel();
        let forward = ops.clone();
        thread::spawn(move || {
            for command in commands {
                if forward.send(Op::Command(command)).is_err() {
                    break;
                }
            }
        });
        let (input_sender, inputs) = mpsc::channel();
        let runner = thread::spawn(move || run(transport, &op_receiver, &input_sender));
        Harness { ops, inputs, kernels, notices, fail, refuse_input, runner: Some(runner) }
    }

    fn op(&self, op: Op) {
        self.ops.send(op).expect("the fake runner is running");
    }

    fn ask<T>(&self, op: impl FnOnce(Sender<T>) -> Op) -> T {
        let (reply, answer) = mpsc::channel();
        self.op(op(reply));
        answer.recv_timeout(WAIT).expect("the fake runner answers")
    }

    pub fn enumerate(&self, identity: &UsbIdentity) {
        self.op(Op::Enumerate(identity.clone()));
    }

    /// Enumerate and deliver `outputs` right after, before the runner takes any command:
    /// what `lk_run` does with outputs of inputs that were queued ahead of the fence.
    pub fn enumerate_then_deliver(&self, identity: &UsbIdentity, outputs: Vec<Output>) {
        self.op(Op::EnumerateThenDeliver(identity.clone(), outputs));
    }

    pub fn deliver(&self, output: Output) {
        self.op(Op::Deliver(output));
    }

    pub fn set_answer(&self, answer: Answer) {
        self.op(Op::SetAnswer(answer));
    }

    pub fn stats(&self) -> UhidStats {
        self.ask(Op::Stats)
    }

    pub fn attached(&self) -> Option<bool> {
        self.ask(Op::Attached)
    }

    /// Wait until `attached()` is `want`.
    pub fn attached_becomes(&self, want: bool) -> bool {
        let deadline = Instant::now() + WAIT;
        while Instant::now() < deadline {
            if self.attached() == Some(want) {
                return true;
            }
            thread::sleep(Duration::from_millis(5));
        }
        false
    }

    pub fn debug(&self) -> String {
        self.ask(Op::Debug)
    }

    /// Drop the transport on the runner thread; how long the drop took.
    pub fn drop_transport(&self) -> Duration {
        let (reply, answer) = mpsc::channel();
        self.op(Op::Drop(reply));
        answer.recv_timeout(WAIT + WAIT).expect("the transport drops")
    }

    pub fn fail_opens(&self, fail: bool) {
        self.fail.store(fail, Ordering::SeqCst);
    }

    /// Let every file refuse `UHID_INPUT2` with `-EINVAL`, as for a device the kernel does
    /// not run.
    pub fn refuse_input(&self, refuse: bool) {
        self.refuse_input.store(refuse, Ordering::SeqCst);
    }

    /// Wait until the stats satisfy `want`; the last stats seen.
    pub fn stats_become(&self, want: impl Fn(&UhidStats) -> bool) -> UhidStats {
        let deadline = Instant::now() + WAIT;
        loop {
            let stats = self.stats();
            if want(&stats) || Instant::now() >= deadline {
                return stats;
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// The next input the runner received.
    pub fn input(&self) -> HostInput {
        match self.inputs.recv_timeout(WAIT) {
            Ok(input) => input,
            Err(error) => panic!("the runner received no input within {WAIT:?}: {error}"),
        }
    }

    /// No input arrives within [`QUIET`].
    pub fn no_input(&self) {
        if let Ok(input) = self.inputs.recv_timeout(QUIET) {
            panic!("unexpected input {input:?}");
        }
    }

    /// The next opened file's kernel.
    pub fn kernel(&self) -> Kernel {
        self.kernels.recv_timeout(WAIT).expect("a UHID file is opened")
    }

    /// The next opened device.
    pub fn device(&self) -> Device {
        Device::from(self.kernel())
    }

    /// No file is opened within [`QUIET`].
    pub fn no_kernel(&self) {
        assert!(self.kernels.recv_timeout(QUIET).is_err(), "unexpected UHID file opened");
    }

    /// The two devices of an enumeration with OTP and FIDO: (OTP, FIDO).
    pub fn devices(&self) -> (Device, Device) {
        let first = self.device();
        let second = self.device();
        match (first.interface(), second.interface()) {
            (HidInterface::Otp, HidInterface::Fido) => (first, second),
            (HidInterface::Fido, HidInterface::Otp) => (second, first),
            other => panic!("expected an OTP and a FIDO device, got {other:?}"),
        }
    }

    /// Enumerate with every interface and return the started devices (OTP, FIDO), after
    /// the plug-in `PowerCycle`.
    pub fn plugged() -> (Harness, Device, Device) {
        let harness = Harness::new();
        harness.enumerate(&identity(0x0407, ALL));
        let (otp, fido) = harness.devices();
        assert_eq!(harness.input(), HostInput::Bus(lk_device::BusEvent::PowerCycle));
        (harness, otp, fido)
    }

    /// The first notice that matches, within [`WAIT`].
    pub fn notice(&self, matches: impl Fn(&UhidNotice) -> bool) -> UhidNotice {
        let deadline = Instant::now() + WAIT;
        let mut seen = Vec::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.notices.recv_timeout(left) {
                Ok(notice) if matches(&notice) => return notice,
                Ok(notice) => seen.push(notice.to_string()),
                Err(error) => panic!("no matching notice within {WAIT:?}: {error}; seen: {seen:#?}"),
            }
        }
    }

    /// Every notice so far.
    pub fn notices(&self) -> Vec<UhidNotice> {
        self.notices.try_iter().collect()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.ops.send(Op::Exit);
        if let Some(runner) = self.runner.take() {
            let _ = runner.join();
        }
    }
}

/// A status for the runner's answers to `Command::Status` markers.
fn status() -> Status {
    Status {
        serial: 0,
        product: String::new(),
        interfaces: UsbInterfaces { otp: false, fido: false, ccid: false },
        presence_pending: false,
        serving: true,
        attached: None,
        suspended: false,
        queued: 0,
        dropped: 0,
        unreadable: Vec::new(),
        uptime_ms: 0,
    }
}

/// The fake runner thread: owns the transport like `lk_run::Runner`.
fn run(transport: UhidTransport, ops: &Receiver<Op>, inputs: &Sender<HostInput>) {
    let mut transport = Some(transport);
    let mut answer = Answer::Feature([0; 8]);
    // Markers of a `Silent` runner, kept so their waiters time out instead of failing.
    let mut unanswered = Vec::new();
    for op in ops {
        match op {
            Op::Command(Command::Input(input)) => {
                if input == HostInput::OtpGetFeature
                    && let Some(transport) = transport.as_mut()
                {
                    match answer {
                        Answer::Feature(report) => transport.deliver(Output::OtpFeature(report)),
                        Answer::StaleThen(stale, report) => {
                            transport.deliver(Output::OtpFeature(stale));
                            transport.deliver(Output::OtpFeature(report));
                        }
                        Answer::Nothing | Answer::Silent => {}
                    }
                }
                let _ = inputs.send(input);
            }
            Op::Command(Command::Status(reply)) => match answer {
                Answer::Silent => unanswered.push(reply),
                _ => {
                    let _ = reply.send(status());
                }
            },
            Op::Command(_) => {}
            Op::Enumerate(identity) => {
                if let Some(transport) = transport.as_mut() {
                    transport.enumerate(&identity);
                }
            }
            Op::EnumerateThenDeliver(identity, outputs) => {
                if let Some(transport) = transport.as_mut() {
                    transport.enumerate(&identity);
                    for output in outputs {
                        transport.deliver(output);
                    }
                }
            }
            Op::Deliver(output) => {
                if let Some(transport) = transport.as_mut() {
                    transport.deliver(output);
                }
            }
            Op::SetAnswer(new) => answer = new,
            Op::Stats(reply) => {
                let _ = reply.send(transport.as_ref().map(UhidTransport::stats).unwrap_or_default());
            }
            Op::Attached(reply) => {
                let _ = reply.send(transport.as_ref().and_then(|transport| transport.attached()));
            }
            Op::Debug(reply) => {
                let _ = reply.send(format!("{transport:?}"));
            }
            Op::Drop(reply) => {
                let start = Instant::now();
                drop(transport.take());
                let _ = reply.send(start.elapsed());
            }
            Op::Exit => break,
        }
    }
}
