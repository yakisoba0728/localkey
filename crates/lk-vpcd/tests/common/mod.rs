//! Shared test harness: a fake vpcd that listens on `127.0.0.1` with an ephemeral port and
//! plays vpcd's side of the protocol, and a fake runner thread that owns the transport, as
//! `lk_run::Runner` does, with a small scripted CCID card behind it.
//!
//! The fake vpcd frames messages by hand (2-byte big-endian length, then the payload;
//! vsmartcard api.html), independently of `lk_vpcd::protocol`. The fake card answers CCID
//! messages written from USB CCID Rev 1.1 §6.1–§6.2, independently of `lk_vpcd::ccid` and
//! of the engine's `lk-ccid`: IccPowerOn with a DataBlock carrying the ATR, IccPowerOff with
//! a SlotStatus, XfrBlock (with `wLevelParameter` chaining in both directions) with a
//! DataBlock carrying the response, optionally after time extensions, the control `ABORT`
//! (§5.3.1) with a failed DataBlock (`CMD_ABORTED`) for a held command, and
//! `PC_to_RDR_Abort` (§6.1.13) with a SlotStatus. It answers `Command::Status` markers
//! unless told not to.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use lk_core::UsbInterfaces;
use lk_device::{FIDO_REPORT_DESCRIPTOR, OTP_REPORT_DESCRIPTOR, Output, UsbIdentity};
use lk_run::{Command, HostInput, Status, Transport};
use lk_vpcd::{
    Connector, Observer, PeerCheck, PeerRefusal, PeerVerdict, RemoteRefused, TcpConnector, VpcdConfig, VpcdNotice,
    VpcdStats, VpcdTransport,
};

/// How long a test waits for something that must happen. Generous, for loaded machines.
pub const WAIT: Duration = Duration::from_secs(10);
/// How long a test watches for something that must not happen.
pub const QUIET: Duration = Duration::from_millis(300);

/// An ATR for the fake card (the reference key's, ISO/IEC 7816-3 §8.2 layout).
pub const ATR: [u8; 23] = [
    0x3B, 0xFD, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x15, 0x80, 0x73, 0xC0, 0x21, 0xC0, 0x57, 0x59, 0x75, 0x62, 0x69,
    0x4B, 0x65, 0x79, 0x40,
];

/// CCID message types (§6.1, §6.2).
pub const ICC_POWER_ON: u8 = 0x62;
pub const ICC_POWER_OFF: u8 = 0x63;
pub const XFR_BLOCK: u8 = 0x6F;
pub const ABORT: u8 = 0x72;
pub const DATA_BLOCK: u8 = 0x80;
pub const SLOT_STATUS: u8 = 0x81;

/// A YubiKey-like identity whose CCID class descriptor has `dwMaxCCIDMessageLength`
/// `max_message` (offset 44, §5.1).
pub fn identity(ccid: bool, max_message: u32) -> UsbIdentity {
    let mut descriptor = vec![0; 54];
    descriptor[0] = 0x36;
    descriptor[1] = 0x21;
    descriptor[44..48].copy_from_slice(&max_message.to_le_bytes());
    UsbIdentity {
        vendor_id: 0x1050,
        product_id: if ccid { 0x0407 } else { 0x0403 },
        device_release: 0x0574,
        manufacturer: "Yubico".to_owned(),
        product: "YubiKey OTP+FIDO+CCID".to_owned(),
        serial: None,
        interfaces: UsbInterfaces { otp: true, fido: true, ccid },
        fido_report_descriptor: FIDO_REPORT_DESCRIPTOR.to_vec(),
        otp_report_descriptor: OTP_REPORT_DESCRIPTOR.to_vec(),
        ccid_class_descriptor: descriptor,
    }
}

/// The reference key's identity: CCID with 3072-byte messages.
pub fn with_ccid() -> UsbIdentity {
    identity(true, 3072)
}

pub fn without_ccid() -> UsbIdentity {
    identity(false, 3072)
}

/// A bulk-in message written from §6.2: type, `dwLength`, slot 0, `seq`, `bStatus`,
/// `bError`, byte 9, data.
pub fn bulk_in(kind: u8, seq: u8, status: u8, error: u8, specific: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&[0, seq, status, error, specific]);
    out.extend_from_slice(data);
    out
}

pub fn data_block(seq: u8, chain: u8, data: &[u8]) -> Vec<u8> {
    bulk_in(DATA_BLOCK, seq, 0x00, 0x00, chain, data)
}

/// A time-extension DataBlock (`bStatus` `80`, `bError` the multiplier 1, §6.2.6).
pub fn time_extension(seq: u8) -> Vec<u8> {
    bulk_in(DATA_BLOCK, seq, 0x80, 0x01, 0x00, &[])
}

/// The fields of a bulk-out message the transport sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkOut {
    pub kind: u8,
    pub seq: u8,
    pub specific: [u8; 3],
    pub data: Vec<u8>,
}

impl BulkOut {
    pub fn parse(message: &[u8]) -> BulkOut {
        assert!(message.len() >= 10, "a bulk-out message has a header: {message:02X?}");
        let length = u32::from_le_bytes([message[1], message[2], message[3], message[4]]) as usize;
        assert_eq!(length, message.len() - 10, "dwLength matches: {:02X?}", &message[..10]);
        assert_eq!(message[5], 0, "slot 0");
        let specific = [message[7], message[8], message[9]];
        BulkOut { kind: message[0], seq: message[6], specific, data: message[10..].to_vec() }
    }

    /// `wLevelParameter` of an XfrBlock.
    pub fn level(&self) -> u16 {
        u16::from_le_bytes([self.specific[1], self.specific[2]])
    }
}

/// The vpcd side of the protocol: a listener on `127.0.0.1`.
pub struct FakeVpcd {
    listener: TcpListener,
    addr: SocketAddr,
}

impl fmt::Debug for FakeVpcd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeVpcd").field("addr", &self.addr).finish()
    }
}

impl FakeVpcd {
    /// Listen on an ephemeral port of `127.0.0.1`.
    pub fn bind() -> FakeVpcd {
        FakeVpcd::listen(TcpListener::bind("127.0.0.1:0").expect("an ephemeral loopback port"))
    }

    /// Listen on `addr` again (vpcd restarted), retrying while the port is still taken.
    pub fn rebind(addr: SocketAddr) -> FakeVpcd {
        let deadline = Instant::now() + WAIT;
        loop {
            match TcpListener::bind(addr) {
                Ok(listener) => return FakeVpcd::listen(listener),
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                Err(error) => panic!("cannot listen on {addr} again: {error}"),
            }
        }
    }

    fn listen(listener: TcpListener) -> FakeVpcd {
        listener.set_nonblocking(true).expect("the listener can be non-blocking");
        let addr = listener.local_addr().expect("bound");
        FakeVpcd { listener, addr }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The next connection within `within`, if any.
    pub fn accept_within(&self, within: Duration) -> Option<Conn> {
        let deadline = Instant::now() + within;
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => return Some(Conn::new(stream)),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return None;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        }
    }

    /// The next connection; the test fails without one within [`WAIT`].
    pub fn accept(&self) -> Conn {
        self.accept_within(WAIT).expect("the transport connects within the wait")
    }

    /// No connection arrives within `within`.
    pub fn no_connection(&self, within: Duration) {
        assert!(self.accept_within(within).is_none(), "unexpected connection");
    }
}

/// One accepted connection: vpcd talking to the card.
pub struct Conn {
    stream: TcpStream,
}

impl fmt::Debug for Conn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Conn").finish_non_exhaustive()
    }
}

impl Conn {
    fn new(stream: TcpStream) -> Conn {
        // An accepted socket inherits O_NONBLOCK from the listener on BSDs.
        stream.set_nonblocking(false).expect("blocking");
        stream.set_read_timeout(Some(WAIT)).expect("a read timeout");
        Conn { stream }
    }

    /// Send one framed message.
    pub fn send(&mut self, payload: &[u8]) {
        let mut frame = (payload.len() as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(payload);
        self.stream.write_all(&frame).expect("the card's socket takes the message");
    }

    /// One framed message from the card.
    pub fn recv(&mut self) -> Vec<u8> {
        let mut length = [0; 2];
        self.stream.read_exact(&mut length).expect("the card answers within the wait");
        let mut payload = vec![0; usize::from(u16::from_be_bytes(length))];
        self.stream.read_exact(&mut payload).expect("the whole answer arrives");
        payload
    }

    /// A control command (`VPCD_CTRL_*`), which gets no answer.
    pub fn control(&mut self, byte: u8) {
        self.send(&[byte]);
    }

    pub fn power_off(&mut self) {
        self.control(0x00);
    }

    pub fn power_on(&mut self) {
        self.control(0x01);
    }

    pub fn reset(&mut self) {
        self.control(0x02);
    }

    /// `VPCD_CTRL_ATR` and its answer.
    pub fn atr(&mut self) -> Vec<u8> {
        self.control(0x04);
        self.recv()
    }

    /// An APDU and its response.
    pub fn transmit(&mut self, apdu: &[u8]) -> Vec<u8> {
        assert_ne!(apdu.len(), 1, "a one-byte payload would be a control command");
        self.send(apdu);
        self.recv()
    }

    /// Nothing arrives from the card within `within` (the connection stays open).
    pub fn quiet(&mut self, within: Duration) -> bool {
        self.stream.set_read_timeout(Some(within)).expect("a read timeout");
        let mut byte = [0; 1];
        let quiet = match self.stream.peek(&mut byte) {
            Ok(0) => panic!("the card closed the connection"),
            Ok(_) => false,
            Err(error) => matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut),
        };
        self.stream.set_read_timeout(Some(WAIT)).expect("a read timeout");
        quiet
    }

    /// Whether the card closes the connection within [`WAIT`] without sending anything
    /// first; data before the close fails the test.
    pub fn ends_silently(&mut self) -> bool {
        // One read: it blocks for at most the read timeout, WAIT.
        let mut buffer = [0; 256];
        match self.stream.read(&mut buffer) {
            Ok(0) => true,
            Ok(read) => panic!("the card sent {read} bytes before it closed the connection"),
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => true,
            Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => false,
            Err(error) => panic!("reading from the card failed: {error}"),
        }
    }

    /// Whether the card closes the connection within [`WAIT`] (anything it sends first is
    /// skipped).
    pub fn ends(&mut self) -> bool {
        let deadline = Instant::now() + WAIT;
        let mut buffer = [0; 256];
        while Instant::now() < deadline {
            match self.stream.read(&mut buffer) {
                Ok(0) => return true,
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => return true,
                Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                    return false;
                }
                Err(error) => panic!("reading from the card failed: {error}"),
            }
        }
        false
    }

    /// The card's address (the transport's end of the connection).
    pub fn peer_addr(&self) -> SocketAddr {
        self.stream.peer_addr().expect("a connected socket")
    }

    /// Close vpcd's side (vpcd ejected the card or stopped).
    pub fn close(self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

/// How the fake card answers IccPowerOn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerOn {
    /// A DataBlock with the ATR.
    Atr,
    /// A failed DataBlock: no card (`bStatus` `42`, `bError` `FE` ICC_MUTE).
    Fail,
    /// No reply at all.
    Silent,
}

/// How the fake card answers a complete command APDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Xfr {
    /// The response, after `time_extensions` time extensions; with `stale_first`, a
    /// DataBlock with another `bSeq` comes first.
    Answer { time_extensions: usize, stale_first: bool },
    /// A failed DataBlock (`bStatus` `41`: ICC inactive, `bError` `FE`).
    Fail,
    /// No reply (the device dropped the command).
    Silent,
    /// One time extension now; the response when the test calls [`Harness::release`].
    Hold,
}

/// The fake card's script.
#[derive(Debug, Clone)]
pub struct Card {
    pub atr: Vec<u8>,
    pub power_on: PowerOn,
    pub xfr: Xfr,
    /// The response to a command APDU.
    pub respond: fn(&[u8]) -> Vec<u8>,
    /// The most response data in one DataBlock; longer responses are chained.
    pub response_part: usize,
    /// Whether `Command::Status` markers are answered.
    pub answer_markers: bool,
}

/// The command APDU echoed, then `9000`.
pub fn echo(apdu: &[u8]) -> Vec<u8> {
    let mut response = apdu.to_vec();
    response.extend_from_slice(&[0x90, 0x00]);
    response
}

impl Default for Card {
    fn default() -> Self {
        Card {
            atr: ATR.to_vec(),
            power_on: PowerOn::Atr,
            xfr: Xfr::Answer { time_extensions: 0, stale_first: false },
            respond: echo,
            response_part: 3062,
            answer_markers: true,
        }
    }
}

/// The fake card's CCID state.
#[derive(Default)]
struct CardState {
    /// Command parts received so far (`0001`, `0003`).
    chain: Option<Vec<u8>>,
    /// The unsent rest of a chained response.
    rest: Vec<u8>,
    /// A response held for [`Harness::release`]: `bSeq` and bytes.
    held: Option<(u8, Vec<u8>)>,
}

/// What the fake runner thread does.
enum Op {
    Command(Command),
    Enumerate(UsbIdentity),
    Deliver(Output),
    SetCard(Card),
    Release,
    /// Re-enumerate with this identity right after the next complete response is
    /// delivered, before taking another command (what `lk_run` does with an
    /// `Output::Reenumerate` among a command's outputs).
    RebootAfterResponse(UsbIdentity),
    Stats(Sender<VpcdStats>),
    Attached(Sender<Option<bool>>),
    Debug(Sender<String>),
    Drop(Sender<Duration>),
    Exit,
}

/// A [`Connector`] that reports every attempt to the test and connects with a
/// [`TcpConnector`]. With `reported`, it names that address instead of the one it
/// connects to (a remote address for the transport, a loopback connection in fact).
#[derive(Debug)]
pub struct Counting {
    inner: TcpConnector,
    attempts: Sender<Instant>,
    reported: Option<SocketAddr>,
}

impl Counting {
    /// A connector to `addr` that names `reported` (if any) instead, and the receiver of
    /// its attempt times.
    pub fn new(addr: SocketAddr, reported: Option<SocketAddr>) -> (Counting, Receiver<Instant>) {
        let (attempts, receiver) = mpsc::channel();
        (Counting { inner: TcpConnector::new(addr), attempts, reported }, receiver)
    }
}

impl Connector for Counting {
    fn connect(&mut self) -> io::Result<TcpStream> {
        let _ = self.attempts.send(Instant::now());
        self.inner.connect()
    }

    fn addr(&self) -> SocketAddr {
        self.reported.unwrap_or_else(|| self.inner.addr())
    }
}

/// A scripted [`PeerCheck`]: it records every connection's addresses and answers the
/// connections in turn from its script (`true` allows the peer as uid [`Scripted::UID`],
/// `false` refuses it as owned by [`Scripted::OTHER`]), then `Unchecked` once the script
/// is used up.
#[derive(Debug, Default)]
pub struct Scripted {
    script: Mutex<VecDeque<bool>>,
    seen: Mutex<Vec<(SocketAddr, SocketAddr)>>,
}

impl Scripted {
    /// The uid an allowed peer is reported with.
    pub const UID: u32 = 4242;
    /// The uid a refused peer is reported with.
    pub const OTHER: u32 = 1001;

    pub fn new(script: &[bool]) -> Arc<Scripted> {
        Arc::new(Scripted { script: Mutex::new(script.iter().copied().collect()), seen: Mutex::default() })
    }

    /// The (local, peer) addresses of every connection checked so far.
    pub fn seen(&self) -> Vec<(SocketAddr, SocketAddr)> {
        self.seen.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }
}

impl PeerCheck for Scripted {
    fn check(&self, local: SocketAddr, peer: SocketAddr) -> PeerVerdict {
        self.seen.lock().unwrap_or_else(PoisonError::into_inner).push((local, peer));
        match self.script.lock().unwrap_or_else(PoisonError::into_inner).pop_front() {
            Some(true) => PeerVerdict::Allowed { uid: Scripted::UID },
            Some(false) => PeerVerdict::Refused(PeerRefusal::NotAllowed {
                uid: Scripted::OTHER,
                allowed: vec![Scripted::UID],
            }),
            None => PeerVerdict::Unchecked { reason: "the script is used up".to_owned() },
        }
    }
}

/// The transport inside a fake runner, connecting to a fake vpcd.
pub struct Harness {
    ops: Sender<Op>,
    inputs: Receiver<HostInput>,
    notices: Receiver<VpcdNotice>,
    attempts: Receiver<Instant>,
    seen: Arc<Mutex<Vec<String>>>,
    runner: Option<JoinHandle<()>>,
}

impl fmt::Debug for Harness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Harness").finish_non_exhaustive()
    }
}

impl Harness {
    /// A transport that connects to `addr`, in a fake runner, not enumerated yet, with the
    /// default configuration (on Linux the real peer check, which allows the fake vpcd: it
    /// runs as this process's user).
    pub fn new(addr: SocketAddr) -> Harness {
        Harness::with_connector(addr, None, VpcdConfig::default()).expect("a loopback address")
    }

    /// A transport that connects to `addr` but is told its address is `reported`, a remote
    /// address it is allowed to use.
    pub fn disguised(addr: SocketAddr, reported: SocketAddr) -> Harness {
        let config = VpcdConfig { allow_remote: true, ..VpcdConfig::default() };
        Harness::with_connector(addr, Some(reported), config).expect("a remote address allowed")
    }

    /// A transport that connects to `addr` and asks `check` about every connection.
    pub fn with_peer_check(addr: SocketAddr, check: Arc<dyn PeerCheck>) -> Harness {
        let config = VpcdConfig { peer_check: check, ..VpcdConfig::default() };
        Harness::with_connector(addr, None, config).expect("a loopback address")
    }

    /// A transport that connects to `addr`, is told its address is `reported`, and is made
    /// with `config` (its observer replaced by the harness's own).
    pub fn with_connector(
        addr: SocketAddr,
        reported: Option<SocketAddr>,
        config: VpcdConfig,
    ) -> Result<Harness, RemoteRefused> {
        let (connector, attempts) = Counting::new(addr, reported);
        let (notice_sender, notices) = mpsc::channel();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        let observer: Observer = Arc::new(move |notice: &VpcdNotice| {
            log.lock().unwrap_or_else(PoisonError::into_inner).push(format!("{notice:?}"));
            let _ = notice_sender.send(notice.clone());
        });
        let (command_sender, commands) = mpsc::channel::<Command>();
        let config = VpcdConfig { observer: Some(observer), ..config };
        let transport = VpcdTransport::with_config(Box::new(connector), command_sender, config)?;
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
        Ok(Harness { ops, inputs, notices, attempts, seen, runner: Some(runner) })
    }

    /// A harness enumerated with CCID, with the accepted connection's peer check complete.
    pub fn connected(vpcd: &FakeVpcd) -> (Harness, Conn) {
        let harness = Harness::new(vpcd.addr());
        harness.enumerate(&with_ccid());
        let conn = vpcd.accept();
        // TCP accept precedes the peer check and registration on the connection thread.
        let deadline = Instant::now() + WAIT;
        while harness.stats().connections == 0 {
            assert!(Instant::now() < deadline, "the accepted connection was not registered");
            thread::sleep(Duration::from_millis(5));
        }
        (harness, conn)
    }

    fn op(&self, op: Op) {
        self.ops.send(op).expect("the fake runner is running");
    }

    fn ask<T>(&self, op: impl FnOnce(Sender<T>) -> Op) -> T {
        let (reply, answer) = mpsc::channel();
        self.op(op(reply));
        answer.recv_timeout(WAIT + WAIT).expect("the fake runner answers")
    }

    pub fn enumerate(&self, identity: &UsbIdentity) {
        self.op(Op::Enumerate(identity.clone()));
    }

    pub fn deliver(&self, output: Output) {
        self.op(Op::Deliver(output));
    }

    pub fn set_card(&self, card: Card) {
        self.op(Op::SetCard(card));
    }

    /// Deliver the held response (see [`Xfr::Hold`]).
    pub fn release(&self) {
        self.op(Op::Release);
    }

    pub fn reboot_after_response(&self, identity: &UsbIdentity) {
        self.op(Op::RebootAfterResponse(identity.clone()));
    }

    pub fn stats(&self) -> VpcdStats {
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
        self.ask(Op::Drop)
    }

    /// The next CCID message the transport sent to the runner.
    pub fn input(&self) -> BulkOut {
        match self.host_input(WAIT) {
            HostInput::Ccid(ref message) => BulkOut::parse(message),
            other => panic!("the transport sent {other:?}, not a CCID message"),
        }
    }

    /// The next input of any kind the transport sent to the runner, within `within`.
    pub fn host_input(&self, within: Duration) -> HostInput {
        match self.inputs.recv_timeout(within) {
            Ok(input) => input,
            Err(error) => panic!("the runner received no input within {within:?}: {error}"),
        }
    }

    /// No input arrives within [`QUIET`].
    pub fn no_input(&self) {
        if let Ok(input) = self.inputs.recv_timeout(QUIET) {
            panic!("unexpected input {input:?}");
        }
    }

    /// The times of the connection attempts so far, waiting until there are `count`.
    pub fn attempts(&self, count: usize) -> Vec<Instant> {
        let mut times = Vec::new();
        let deadline = Instant::now() + WAIT;
        while times.len() < count {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.attempts.recv_timeout(left) {
                Ok(time) => times.push(time),
                Err(error) => panic!("only {} of {count} attempts within {WAIT:?}: {error}", times.len()),
            }
        }
        times
    }

    /// Every attempt reported so far, without waiting.
    pub fn attempts_so_far(&self) -> usize {
        self.attempts.try_iter().count()
    }

    /// The first notice that matches, within [`WAIT`].
    pub fn notice(&self, matches: impl Fn(&VpcdNotice) -> bool) -> VpcdNotice {
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

    /// Every notice so far, as `Debug` text (including those already taken by
    /// [`Harness::notice`]).
    pub fn notice_log(&self) -> Vec<String> {
        self.seen.lock().unwrap_or_else(PoisonError::into_inner).clone()
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
        interfaces: UsbInterfaces { otp: false, fido: false, ccid: true },
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

/// The fake runner thread: owns the transport like `lk_run::Runner` and plays the card.
fn run(transport: VpcdTransport, ops: &Receiver<Op>, inputs: &Sender<HostInput>) {
    let mut transport = Some(transport);
    let mut card = Card::default();
    let mut state = CardState::default();
    let mut reboot: Option<UsbIdentity> = None;
    // Markers left unanswered, kept so their waiters do not see a gone runner.
    let mut unanswered = Vec::new();
    for op in ops {
        match op {
            Op::Command(Command::Input(input)) => {
                match (&input, transport.as_mut()) {
                    (HostInput::Ccid(message), Some(transport)) => {
                        let responded = answer(&card, &mut state, message, transport);
                        if responded && let Some(identity) = reboot.take() {
                            transport.enumerate(&identity);
                        }
                    }
                    // §5.3.1: a held command fails with CMD_ABORTED (`bError` FF).
                    (HostInput::CcidControlAbort { .. }, Some(transport)) => {
                        if let Some((seq, _)) = state.held.take() {
                            transport.deliver(Output::Ccid(bulk_in(DATA_BLOCK, seq, 0x40, 0xFF, 0x00, &[])));
                        }
                    }
                    _ => {}
                }
                let _ = inputs.send(input);
            }
            Op::Command(Command::Status(reply)) => {
                if card.answer_markers {
                    let _ = reply.send(status());
                } else {
                    unanswered.push(reply);
                }
            }
            Op::Command(_) => {}
            Op::Enumerate(identity) => {
                if let Some(transport) = transport.as_mut() {
                    transport.enumerate(&identity);
                }
            }
            Op::Deliver(output) => {
                if let Some(transport) = transport.as_mut() {
                    transport.deliver(output);
                }
            }
            Op::SetCard(new) => card = new,
            Op::Release => {
                if let (Some((seq, response)), Some(transport)) = (state.held.take(), transport.as_mut()) {
                    transport.deliver(Output::Ccid(data_block(seq, 0x00, &response)));
                }
            }
            Op::RebootAfterResponse(identity) => reboot = Some(identity),
            Op::Stats(reply) => {
                let _ = reply.send(transport.as_ref().map(VpcdTransport::stats).unwrap_or_default());
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

/// The fake card's answer to one bulk-out message. True when a complete response APDU
/// was delivered.
fn answer(card: &Card, state: &mut CardState, message: &[u8], transport: &mut VpcdTransport) -> bool {
    let out = BulkOut::parse(message);
    let seq = out.seq;
    let mut deliver = |bytes: Vec<u8>| transport.deliver(Output::Ccid(bytes));
    match out.kind {
        ICC_POWER_ON => match card.power_on {
            PowerOn::Atr => deliver(data_block(seq, 0x00, &card.atr)),
            PowerOn::Fail => deliver(bulk_in(DATA_BLOCK, seq, 0x42, 0xFE, 0x00, &[])),
            PowerOn::Silent => {}
        },
        ICC_POWER_OFF => deliver(bulk_in(SLOT_STATUS, seq, 0x01, 0x00, 0x00, &[])),
        ABORT => deliver(bulk_in(SLOT_STATUS, seq, 0x00, 0x00, 0x00, &[])),
        XFR_BLOCK => {
            let apdu = match out.level() {
                0x0000 => out.data,
                0x0001 => {
                    state.chain = Some(out.data);
                    deliver(data_block(seq, 0x10, &[]));
                    return false;
                }
                0x0003 => {
                    state.chain.get_or_insert_default().extend_from_slice(&out.data);
                    deliver(data_block(seq, 0x10, &[]));
                    return false;
                }
                0x0002 => {
                    let mut apdu = state.chain.take().unwrap_or_default();
                    apdu.extend_from_slice(&out.data);
                    apdu
                }
                0x0010 => {
                    let take = state.rest.len().min(card.response_part);
                    let part: Vec<u8> = state.rest.drain(..take).collect();
                    let chain = if state.rest.is_empty() { 0x02 } else { 0x03 };
                    deliver(data_block(seq, chain, &part));
                    return state.rest.is_empty();
                }
                other => panic!("unexpected wLevelParameter {other:#06x}"),
            };
            let response = (card.respond)(&apdu);
            match card.xfr {
                Xfr::Answer { time_extensions, stale_first } => {
                    for _ in 0..time_extensions {
                        deliver(time_extension(seq));
                    }
                    if stale_first {
                        deliver(data_block(seq.wrapping_add(100), 0x00, &[0x6A, 0x82]));
                    }
                    if response.len() > card.response_part {
                        state.rest = response[card.response_part..].to_vec();
                        deliver(data_block(seq, 0x01, &response[..card.response_part]));
                        return false;
                    }
                    deliver(data_block(seq, 0x00, &response));
                    return true;
                }
                Xfr::Fail => deliver(bulk_in(DATA_BLOCK, seq, 0x41, 0xFE, 0x00, &[])),
                Xfr::Silent => {}
                Xfr::Hold => {
                    deliver(time_extension(seq));
                    state.held = Some((seq, response));
                }
            }
        }
        other => panic!("the transport sent an unexpected message type {other:#04x}"),
    }
    false
}
