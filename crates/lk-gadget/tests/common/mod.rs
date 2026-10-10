//! Test harness: a fake kernel behind `GadgetIo` and a fake runner that owns the
//! transport, as `lk_run::Runner` does.
//!
//! The fake kernel hands the transport socket-pair halves and keeps the other halves:
//!
//! - data endpoints are plain `UnixStream` halves; the test writes OUT packets and reads
//!   IN data on its half;
//! - `ep0` is message oriented (whole events, zero-length status stages, stalls reported
//!   as errors), which a byte stream cannot carry, so the transport's half is wrapped in
//!   [`ProxyEp0`]: every `read`/`write` call goes over the socket as a frame (operation,
//!   length, bytes) and a kernel thread answers it the way f_fs does
//!   (`ffs_ep0_read`/`ffs_ep0_write` in `drivers/usb/gadget/function/f_fs.c`): blobs in
//!   the first two writes, then events, data stages and stalls (`EL2HLT`);
//! - `bind` writes the `UDC` file and hands the test a [`KernelSession`]; `unbind` writes
//!   `"\n"`, queues `UNBIND` on `ep0` and shuts the endpoint sockets down, as unbinding
//!   ends transfers in flight; [`FakeKernel::unbind_externally`] does the same for an
//!   unbind the transport did not ask for;
//! - every file handed to the transport counts itself open until the transport drops it
//!   ([`FakeKernel::open_files`]), as f_fs counts `ffs->opened`;
//! - a SETUP can be queued with a number of data-stage calls to fail with `EINTR`
//!   ([`Ep0Driver::setup_interrupted`]), which leaves the request pending, as f_fs does
//!   (`__ffs_ep0_queue_wait`).

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

use lk_core::UsbInterfaces;
use lk_device::{Output, UsbIdentity};
use lk_gadget::ffs::{CtrlRequest, EVENT_SIZE, Event};
use lk_gadget::{Ep0File, GadgetConfig, GadgetEvent, GadgetIo, GadgetTransport, Observer};
use lk_run::{Command, HostInput, Status, Transport};

/// How long a test waits for something that must happen. Generous, for loaded machines.
pub const WAIT: Duration = Duration::from_secs(10);
/// How long a test watches for something that must not happen.
pub const QUIET: Duration = Duration::from_millis(300);

/// Linux errno values the fake kernel answers with (`include/uapi/asm-generic/errno-base.h`,
/// `errno.h`). On macOS they map to other errors; the transport only tells success from
/// failure.
const ESRCH: u32 = 3;
/// `EINTR` is 4 on Linux and on macOS, so the transport sees `ErrorKind::Interrupted`.
const EINTR: u32 = 4;
const EINVAL: u32 = 22;
const EL2HLT: u32 = 51;

/// A fresh directory under the system temporary directory with a short name, removed on
/// drop.
#[derive(Debug)]
pub struct TestDir(PathBuf);

impl TestDir {
    pub fn new() -> TestDir {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("lkg{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("the test directory can be created");
        TestDir(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// `configuration_descriptor_hex` of
/// `reference/yubikey-5c-nano-5.7.4/usb-reference-observation.json` (FIDO+CCID).
pub const REFERENCE_CONFIGURATION: &str = "09027d00020100800f090400000203000000092110010001222200070504034000020705840340000209040100030b00000036210001000702000000a00f0000a00f00000000b0040000b0040000f60b00000000000000000000fe000400000c0000ffff00000001070502024000000705820240000007058303080020";

pub fn hex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap_or_default()).collect()
}

pub const FIDO_CCID: UsbInterfaces = UsbInterfaces { otp: false, fido: true, ccid: true };
pub const ALL: UsbInterfaces = UsbInterfaces { otp: true, fido: true, ccid: true };

/// An identity as the engine builds it, with the reference CCID class descriptor.
pub fn identity(interfaces: UsbInterfaces) -> UsbIdentity {
    let reference = hex(REFERENCE_CONFIGURATION);
    let ccid = reference.windows(2).position(|w| w == [0x36, 0x21]).expect("the CCID descriptor is there");
    UsbIdentity {
        vendor_id: 0x1050,
        product_id: if interfaces == ALL { 0x0407 } else { 0x0406 },
        device_release: 0x0574,
        manufacturer: "Yubico".into(),
        product: if interfaces == ALL { "YubiKey OTP+FIDO+CCID".into() } else { "YubiKey FIDO+CCID".into() },
        serial: Some("12345678".into()),
        interfaces,
        fido_report_descriptor: lk_device::FIDO_REPORT_DESCRIPTOR.to_vec(),
        otp_report_descriptor: lk_device::OTP_REPORT_DESCRIPTOR.to_vec(),
        ccid_class_descriptor: reference[ccid..ccid + 54].to_vec(),
    }
}

/// The transport's side of `ep0`: each call is a frame `op:u8 len:u32le [bytes]` and the
/// answer `status:u8 value:u32le [bytes]` (status 0: `value` bytes follow for a read, or
/// were taken by a write; status 1: `value` is an errno).
#[derive(Debug)]
pub struct ProxyEp0 {
    stream: UnixStream,
}

impl ProxyEp0 {
    fn answer(&mut self) -> io::Result<u32> {
        let mut head = [0u8; 5];
        self.stream.read_exact(&mut head)?;
        let value = u32::from_le_bytes([head[1], head[2], head[3], head[4]]);
        if head[0] == 0 { Ok(value) } else { Err(io::Error::from_raw_os_error(value as i32)) }
    }
}

impl Read for ProxyEp0 {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut frame = vec![b'R'];
        frame.extend_from_slice(&(buf.len() as u32).to_le_bytes());
        self.stream.write_all(&frame)?;
        let count = self.answer()? as usize;
        self.stream.read_exact(&mut buf[..count])?;
        Ok(count)
    }
}

impl Write for ProxyEp0 {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut frame = vec![b'W'];
        frame.extend_from_slice(&(buf.len() as u32).to_le_bytes());
        frame.extend_from_slice(buf);
        self.stream.write_all(&frame)?;
        Ok(self.answer()? as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// What the transport did with a SETUP, as the kernel saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// An IN data stage (cut to `wLength`).
    Reply(Vec<u8>),
    /// A stall (a read of an IN request or a write of an OUT request).
    Stall,
    /// An OUT data stage: this many bytes were handed over (0: status stage only).
    Read(usize),
    /// The transport closed `ep0`.
    Closed,
}

/// An event queued for one `ep0`: the OUT data of a SETUP, and how many of its data-stage
/// calls fail with `EINTR` before one is served.
#[derive(Debug)]
struct Queued {
    event: Event,
    data: Vec<u8>,
    interrupts: u32,
}

impl Queued {
    fn event(event: Event) -> Queued {
        Queued { event, data: Vec::new(), interrupts: 0 }
    }
}

/// Events queued for one `ep0`.
type EventQueue = Sender<Queued>;

/// A transport-side file that counts itself open until the transport drops it.
#[derive(Debug)]
struct Counted<T> {
    inner: T,
    open: Arc<AtomicUsize>,
}

impl<T> Counted<T> {
    fn new(inner: T, open: &Arc<AtomicUsize>) -> Counted<T> {
        open.fetch_add(1, Ordering::SeqCst);
        Counted { inner, open: Arc::clone(open) }
    }
}

impl<T> Drop for Counted<T> {
    fn drop(&mut self) {
        self.open.fetch_sub(1, Ordering::SeqCst);
    }
}

impl<T: Read> Read for Counted<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<T: Write> Write for Counted<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[derive(Debug, Default)]
struct Blobs {
    descriptors: Vec<u8>,
    strings: Vec<u8>,
}

/// The kernel side of one `ep0` open: f_fs's state machine over the proxy frames.
fn ep0_kernel(mut stream: UnixStream, events: Receiver<Queued>, outcomes: Sender<Outcome>, blobs: Arc<Mutex<Blobs>>) {
    enum State {
        Descriptors,
        Strings,
        Active,
    }
    let ok = |stream: &mut UnixStream, value: usize, data: &[u8]| {
        let mut answer = vec![0u8];
        answer.extend_from_slice(&(value as u32).to_le_bytes());
        answer.extend_from_slice(data);
        stream.write_all(&answer)
    };
    let fail = |stream: &mut UnixStream, errno: u32| {
        let mut answer = vec![1u8];
        answer.extend_from_slice(&errno.to_le_bytes());
        stream.write_all(&answer)
    };
    let mut state = State::Descriptors;
    let mut pending: Option<(CtrlRequest, Vec<u8>, u32)> = None;
    loop {
        let mut head = [0u8; 5];
        if stream.read_exact(&mut head).is_err() {
            let _ = outcomes.send(Outcome::Closed);
            return;
        }
        let length = u32::from_le_bytes([head[1], head[2], head[3], head[4]]) as usize;
        let sent = match head[0] {
            b'W' => {
                let mut bytes = vec![0u8; length];
                if stream.read_exact(&mut bytes).is_err() {
                    let _ = outcomes.send(Outcome::Closed);
                    return;
                }
                match state {
                    State::Descriptors => {
                        lock(&blobs).descriptors = bytes;
                        state = State::Strings;
                        ok(&mut stream, length, &[])
                    }
                    State::Strings => {
                        lock(&blobs).strings = bytes;
                        state = State::Active;
                        ok(&mut stream, length, &[])
                    }
                    State::Active => match pending.take() {
                        Some((request, data, interrupts)) if interrupts > 0 => {
                            // Interrupted: the request stays pending.
                            pending = Some((request, data, interrupts - 1));
                            fail(&mut stream, EINTR)
                        }
                        Some((request, _, _)) if request.is_in() => {
                            let count = length.min(usize::from(request.length));
                            let _ = outcomes.send(Outcome::Reply(bytes[..count].to_vec()));
                            ok(&mut stream, count, &[])
                        }
                        Some(_) => {
                            let _ = outcomes.send(Outcome::Stall);
                            fail(&mut stream, EL2HLT)
                        }
                        None => fail(&mut stream, ESRCH),
                    },
                }
            }
            _ => match (&state, pending.take()) {
                (State::Active, Some((request, data, interrupts))) if interrupts > 0 => {
                    pending = Some((request, data, interrupts - 1));
                    fail(&mut stream, EINTR)
                }
                (State::Active, Some((request, _, _))) if request.is_in() => {
                    let _ = outcomes.send(Outcome::Stall);
                    fail(&mut stream, EL2HLT)
                }
                (State::Active, Some((request, data, _))) => {
                    let count = length.min(usize::from(request.length)).min(data.len());
                    let _ = outcomes.send(Outcome::Read(count));
                    ok(&mut stream, count, &data[..count])
                }
                (State::Active, None) if length >= EVENT_SIZE => match events.recv() {
                    Ok(Queued { event, data, interrupts }) => {
                        if let Event::Setup(request) = event {
                            pending = Some((request, data, interrupts));
                        }
                        ok(&mut stream, EVENT_SIZE, &event.to_bytes())
                    }
                    Err(_) => fail(&mut stream, EINVAL),
                },
                _ => fail(&mut stream, EINVAL),
            },
        };
        if sent.is_err() {
            let _ = outcomes.send(Outcome::Closed);
            return;
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The test's handle on `ep0` of one session.
#[derive(Debug)]
pub struct Ep0Driver {
    events: EventQueue,
    outcomes: Receiver<Outcome>,
}

impl Ep0Driver {
    /// Queue an event for the transport.
    pub fn event(&self, event: Event) {
        let _ = self.events.send(Queued::event(event));
    }

    /// Send a SETUP (with the OUT data the host would send) and wait for its outcome.
    pub fn setup(&self, request: CtrlRequest, out_data: &[u8]) -> Outcome {
        self.setup_interrupted(request, out_data, 0)
    }

    /// Send a SETUP whose first `interrupts` data-stage calls fail with `EINTR` (the
    /// request stays pending), and wait for its outcome.
    pub fn setup_interrupted(&self, request: CtrlRequest, out_data: &[u8], interrupts: u32) -> Outcome {
        let _ = self.events.send(Queued { event: Event::Setup(request), data: out_data.to_vec(), interrupts });
        self.outcome()
    }

    /// The next outcome.
    pub fn outcome(&self) -> Outcome {
        match self.outcomes.recv_timeout(WAIT) {
            Ok(outcome) => outcome,
            Err(RecvTimeoutError::Timeout) => panic!("ep0 saw nothing within {WAIT:?}"),
            Err(RecvTimeoutError::Disconnected) => Outcome::Closed,
        }
    }
}

/// One binding of the gadget, as the fake kernel saw it.
#[derive(Debug)]
pub struct KernelSession {
    pub ep0: Ep0Driver,
    /// The kernel halves of the endpoint files, by file index.
    pub endpoints: BTreeMap<usize, UnixStream>,
    pub descriptors: Vec<u8>,
    pub strings: Vec<u8>,
}

impl KernelSession {
    pub fn endpoint(&mut self, index: usize) -> &mut UnixStream {
        let stream = self.endpoints.get_mut(&index).unwrap_or_else(|| panic!("no ep{index}"));
        let _ = stream.set_read_timeout(Some(WAIT));
        stream
    }

    /// Read exactly `length` bytes the transport wrote to IN endpoint `index`.
    pub fn read_in(&mut self, index: usize, length: usize) -> Vec<u8> {
        let mut data = vec![0u8; length];
        self.endpoint(index).read_exact(&mut data).unwrap_or_else(|e| panic!("ep{index}: {e}"));
        data
    }

    /// Write one OUT packet to endpoint `index`.
    pub fn write_out(&mut self, index: usize, packet: &[u8]) {
        self.endpoint(index).write_all(packet).unwrap_or_else(|e| panic!("ep{index}: {e}"));
    }
}

/// A session being built between `open_ep0` and `bind`.
#[derive(Debug)]
struct Building {
    events: EventQueue,
    outcomes: Receiver<Outcome>,
    blobs: Arc<Mutex<Blobs>>,
    endpoints: BTreeMap<usize, UnixStream>,
}

#[derive(Debug)]
struct KernelState {
    /// Files handed to the transport and not dropped yet.
    open: Arc<AtomicUsize>,
    log: Vec<String>,
    building: Option<Building>,
    /// The bound session: its event queue and clones of the endpoint halves.
    bound: Option<(EventQueue, Vec<UnixStream>)>,
    sessions: Sender<KernelSession>,
    fail_bind: bool,
    fail_unmount: bool,
    /// Where FunctionFS instances are mounted: (instance, mount point).
    mounts: Vec<(String, PathBuf)>,
}

/// The fake kernel: `GadgetIo` for the transport, sessions and a log for the test.
#[derive(Debug, Clone)]
pub struct FakeKernel {
    state: Arc<Mutex<KernelState>>,
    sessions: Arc<Mutex<Receiver<KernelSession>>>,
}

impl FakeKernel {
    pub fn new() -> FakeKernel {
        let (sessions_tx, sessions) = mpsc::channel();
        let state = KernelState {
            open: Arc::new(AtomicUsize::new(0)),
            log: Vec::new(),
            building: None,
            bound: None,
            sessions: sessions_tx,
            fail_bind: false,
            fail_unmount: false,
            mounts: Vec::new(),
        };
        FakeKernel { state: Arc::new(Mutex::new(state)), sessions: Arc::new(Mutex::new(sessions)) }
    }

    pub fn io(&self) -> Box<dyn GadgetIo> {
        Box::new(FakeIo { state: Arc::clone(&self.state) })
    }

    /// The session handed over at the last bind.
    pub fn session(&self) -> KernelSession {
        lock(&self.sessions).recv_timeout(WAIT).expect("the transport bound the gadget")
    }

    /// Whether another session was bound.
    pub fn has_session(&self) -> bool {
        lock(&self.sessions).try_recv().is_ok()
    }

    /// What the transport asked of the kernel so far.
    pub fn log(&self) -> Vec<String> {
        lock(&self.state).log.clone()
    }

    pub fn fail_bind(&self, fail: bool) {
        lock(&self.state).fail_bind = fail;
    }

    /// FunctionFS instance `instance` is mounted at `mount_point` (left by an earlier
    /// process, for example).
    pub fn mounted(&self, instance: &str, mount_point: &Path) {
        lock(&self.state).mounts.push((instance.to_owned(), mount_point.to_owned()));
    }

    /// The mount points of every mounted instance.
    pub fn mount_points(&self) -> Vec<PathBuf> {
        lock(&self.state).mounts.iter().map(|(_, mount_point)| mount_point.clone()).collect()
    }

    /// How many FunctionFS files the transport holds open.
    pub fn open_files(&self) -> usize {
        lock(&self.state).open.load(Ordering::SeqCst)
    }

    /// Wait until the transport holds `count` files open; false if it does not within
    /// [`WAIT`].
    pub fn wait_open_files(&self, count: usize) -> bool {
        let start = std::time::Instant::now();
        while self.open_files() != count {
            if start.elapsed() > WAIT {
                return false;
            }
            thread::sleep(Duration::from_millis(5));
        }
        true
    }

    /// Unbind the gadget the way an administrator or a vanishing UDC does: f_fs reports
    /// `UNBIND` and disables the endpoints (`ffs_func_unbind`), and nothing writes `UDC`
    /// for the transport.
    pub fn unbind_externally(&self) {
        let mut state = lock(&self.state);
        state.log.push("external unbind".into());
        if let Some((events, endpoints)) = state.bound.take() {
            let _ = events.send(Queued::event(Event::Unbind));
            for endpoint in endpoints {
                let _ = endpoint.shutdown(Shutdown::Both);
            }
        }
    }

    pub fn fail_unmount(&self, fail: bool) {
        lock(&self.state).fail_unmount = fail;
    }
}

#[derive(Debug)]
struct FakeIo {
    state: Arc<Mutex<KernelState>>,
}

impl FakeIo {
    fn pair(&self, index: usize, direction: &str) -> io::Result<UnixStream> {
        let (transport, kernel) = UnixStream::pair()?;
        let mut state = lock(&self.state);
        state.log.push(format!("open ep{index} {direction}"));
        let building = state.building.as_mut().ok_or_else(|| io::Error::other("ep0 is not open"))?;
        building.endpoints.insert(index, kernel);
        Ok(transport)
    }

    fn counted<T>(&self, inner: T) -> Counted<T> {
        Counted::new(inner, &lock(&self.state).open)
    }
}

impl GadgetIo for FakeIo {
    /// Like `ffs_acquire_dev`: an instance that is mounted already is `EBUSY`.
    fn mount(&mut self, instance: &str, mount_point: &Path) -> io::Result<()> {
        let mut state = lock(&self.state);
        state.log.push(format!("mount {instance} {}", mount_point.display()));
        if state.mounts.iter().any(|(mounted, _)| mounted == instance) {
            return Err(io::Error::from_raw_os_error(16));
        }
        state.mounts.push((instance.to_owned(), mount_point.to_owned()));
        Ok(())
    }

    fn unmount(&mut self, mount_point: &Path) -> io::Result<()> {
        let mut state = lock(&self.state);
        state.log.push(format!("umount {}", mount_point.display()));
        if state.fail_unmount {
            return Err(io::Error::other("target is busy"));
        }
        state.mounts.retain(|(_, mounted)| mounted != mount_point);
        Ok(())
    }

    fn functionfs_mounts(&mut self, instance: &str) -> io::Result<Vec<PathBuf>> {
        let mut state = lock(&self.state);
        state.log.push(format!("mounts of {instance}"));
        Ok(state.mounts.iter().filter(|(mounted, _)| mounted == instance).map(|(_, path)| path.clone()).collect())
    }

    fn open_ep0(&mut self, _mount_point: &Path) -> io::Result<Box<dyn Ep0File>> {
        let (transport, kernel) = UnixStream::pair()?;
        let (events, queue) = mpsc::channel();
        let (report, outcomes) = mpsc::channel();
        let blobs = Arc::new(Mutex::new(Blobs::default()));
        let kept = Arc::clone(&blobs);
        thread::spawn(move || ep0_kernel(kernel, queue, report, kept));
        let mut state = lock(&self.state);
        state.log.push("open ep0".into());
        state.building = Some(Building { events, outcomes, blobs, endpoints: BTreeMap::new() });
        drop(state);
        Ok(Box::new(self.counted(ProxyEp0 { stream: transport })))
    }

    fn open_out(&mut self, _mount_point: &Path, index: usize) -> io::Result<Box<dyn Read + Send>> {
        let stream = self.pair(index, "out")?;
        Ok(Box::new(self.counted(stream)))
    }

    fn open_in(&mut self, _mount_point: &Path, index: usize) -> io::Result<Box<dyn Write + Send>> {
        let stream = self.pair(index, "in")?;
        Ok(Box::new(self.counted(stream)))
    }

    fn bind(&mut self, udc_file: &Path, udc: &str) -> io::Result<()> {
        let mut state = lock(&self.state);
        state.log.push(format!("bind {udc}"));
        if state.fail_bind {
            return Err(io::Error::other("no such device"));
        }
        fs::write(udc_file, format!("{udc}\n"))?;
        let building = state.building.take().ok_or_else(|| io::Error::other("ep0 is not open"))?;
        let clones = building.endpoints.values().filter_map(|s| s.try_clone().ok()).collect();
        state.bound = Some((building.events.clone(), clones));
        let blobs = lock(&building.blobs);
        let session = KernelSession {
            ep0: Ep0Driver { events: building.events.clone(), outcomes: building.outcomes },
            endpoints: building.endpoints,
            descriptors: blobs.descriptors.clone(),
            strings: blobs.strings.clone(),
        };
        drop(blobs);
        let _ = state.sessions.send(session);
        Ok(())
    }

    fn unbind(&mut self, udc_file: &Path) -> io::Result<()> {
        let mut state = lock(&self.state);
        state.log.push("unbind".into());
        fs::write(udc_file, "\n")?;
        if let Some((events, endpoints)) = state.bound.take() {
            let _ = events.send(Queued::event(Event::Unbind));
            for endpoint in endpoints {
                let _ = endpoint.shutdown(Shutdown::Both);
            }
        }
        Ok(())
    }
}

/// What the fake runner thread is asked to do.
enum Message {
    Command(Command),
    Enumerate(UsbIdentity, Sender<()>),
    Deliver(Output, Sender<()>),
    Attached(Sender<Option<bool>>),
    Drop(Sender<()>),
}

/// A transport attached to a fake runner thread over a fake kernel, in a temporary
/// ConfigFS root.
pub struct Harness {
    pub dir: TestDir,
    pub kernel: FakeKernel,
    pub config: GadgetConfig,
    runner: Sender<Message>,
    inputs: Receiver<HostInput>,
    events: Arc<Mutex<Vec<GadgetEvent>>>,
    /// What the fake runner's device answers to `OtpGetFeature` (none: no output).
    pub otp_answer: Arc<Mutex<Option<[u8; 8]>>>,
}

impl Harness {
    pub fn new() -> Harness {
        Harness::prepared(|_, _| {})
    }

    /// A harness whose ConfigFS root and fake kernel `prepare` changes before the
    /// transport is made (to plant what an earlier process left, for example).
    pub fn prepared(prepare: impl FnOnce(&GadgetConfig, &FakeKernel)) -> Harness {
        let dir = TestDir::new();
        let root = dir.path().join("cfg");
        fs::create_dir(&root).expect("the configfs root can be created");
        let config = GadgetConfig {
            configfs_root: root,
            gadget_name: "lk".into(),
            function_name: "lkf".into(),
            mount_point: dir.path().join("ffs"),
            udc: "dummy_udc.0".into(),
        };
        let kernel = FakeKernel::new();
        prepare(&config, &kernel);
        let events = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&events);
        let observer: Observer = Arc::new(move |event: &GadgetEvent| lock(&seen).push(event.clone()));
        let (commands_tx, commands) = mpsc::channel::<Command>();
        let transport = GadgetTransport::with_io(config.clone(), commands_tx, kernel.io(), Some(observer))
            .expect("the configuration is valid");
        let (runner, messages) = mpsc::channel::<Message>();
        let forward = runner.clone();
        thread::spawn(move || {
            for command in commands {
                if forward.send(Message::Command(command)).is_err() {
                    return;
                }
            }
        });
        let (inputs_tx, inputs) = mpsc::channel();
        let otp_answer = Arc::new(Mutex::new(None));
        let answer = Arc::clone(&otp_answer);
        thread::spawn(move || run_fake_runner(transport, &messages, &inputs_tx, &answer));
        Harness { dir, kernel, config, runner, inputs, events, otp_answer }
    }

    pub fn enumerate(&self, identity: &UsbIdentity) {
        self.ask(|done| Message::Enumerate(identity.clone(), done));
    }

    pub fn deliver(&self, output: Output) {
        self.ask(|done| Message::Deliver(output, done));
    }

    pub fn attached(&self) -> Option<bool> {
        let (reply, answer) = mpsc::channel();
        self.runner.send(Message::Attached(reply)).expect("the fake runner runs");
        answer.recv_timeout(WAIT).expect("the fake runner answers")
    }

    /// Drop the transport on the runner thread.
    pub fn drop_transport(&self) {
        self.ask(Message::Drop);
    }

    fn ask(&self, message: impl FnOnce(Sender<()>) -> Message) {
        let (done, wait) = mpsc::channel();
        self.runner.send(message(done)).expect("the fake runner runs");
        wait.recv_timeout(WAIT).expect("the fake runner finishes the request");
    }

    /// The next input the runner received.
    pub fn input(&self) -> HostInput {
        match self.inputs.recv_timeout(WAIT) {
            Ok(input) => input,
            Err(RecvTimeoutError::Timeout) => panic!("the runner received nothing within {WAIT:?}"),
            Err(RecvTimeoutError::Disconnected) => panic!("the fake runner stopped"),
        }
    }

    /// No input reaches the runner for [`QUIET`].
    pub fn assert_quiet(&self) {
        if let Ok(input) = self.inputs.recv_timeout(QUIET) {
            panic!("the runner unexpectedly received {input:?}");
        }
    }

    pub fn events(&self) -> Vec<GadgetEvent> {
        lock(&self.events).clone()
    }

    pub fn gadget(&self) -> PathBuf {
        self.config.configfs_root.join("lk")
    }

    pub fn read(&self, relative: &str) -> String {
        let path = self.gadget().join(relative);
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }
}

fn run_fake_runner(
    transport: GadgetTransport,
    messages: &Receiver<Message>,
    inputs: &Sender<HostInput>,
    answer: &Mutex<Option<[u8; 8]>>,
) {
    let mut transport = Some(transport);
    for message in messages {
        match message {
            Message::Command(Command::Input(input)) => {
                if input == HostInput::OtpGetFeature
                    && let Some(report) = *lock(answer)
                    && let Some(transport) = transport.as_mut()
                {
                    transport.deliver(Output::OtpFeature(report));
                }
                let _ = inputs.send(input);
            }
            Message::Command(Command::Status(reply)) => {
                let _ = reply.send(status());
            }
            Message::Command(_) => {}
            Message::Enumerate(identity, done) => {
                if let Some(transport) = transport.as_mut() {
                    transport.enumerate(&identity);
                }
                let _ = done.send(());
            }
            Message::Deliver(output, done) => {
                if let Some(transport) = transport.as_mut() {
                    transport.deliver(output);
                }
                let _ = done.send(());
            }
            Message::Attached(reply) => {
                let _ = reply.send(transport.as_ref().and_then(|t| t.attached()));
            }
            Message::Drop(done) => {
                drop(transport.take());
                let _ = done.send(());
            }
        }
    }
}

fn status() -> Status {
    Status {
        serial: 12_345_678,
        product: "YubiKey 5C Nano".into(),
        interfaces: ALL,
        presence_pending: false,
        serving: true,
        attached: Some(true),
        suspended: false,
        queued: 0,
        dropped: 0,
        unreadable: Vec::new(),
        uptime_ms: 0,
    }
}

/// A `PC_to_RDR_XfrBlock` with `data_length` bytes of `abData`.
pub fn ccid_message(data_length: usize, seq: u8) -> Vec<u8> {
    let length = (data_length as u32).to_le_bytes();
    let mut out = vec![0x6F, length[0], length[1], length[2], length[3], 0, seq, 0, 0, 0];
    out.extend((0..data_length).map(|i| (i % 251) as u8));
    out
}

pub fn request(request_type: u8, request: u8, value: u16, index: u16, length: u16) -> CtrlRequest {
    CtrlRequest { request_type, request, value, index, length }
}
