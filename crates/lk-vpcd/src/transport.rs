//! The vpcd bus transport (`docs/PROGRAM.md` "lk-vpcd").
//!
//! Threads:
//!
//! - the runner thread calls [`Transport::enumerate`] and [`Transport::deliver`]; both only
//!   update shared state and queue, so they never wait for the network;
//! - one connection thread, started at the first enumeration with CCID, connects to vpcd
//!   (every [`RETRY_INTERVAL`] while it is not listening), then serves the connection:
//!   it reads one vpcd message at a time, turns it into CCID bulk-out messages for the
//!   runner (`Command::Input(HostInput::Ccid(..))`), waits for each matching
//!   `Output::Ccid` that [`Transport::deliver`] hands over through a queue, and writes
//!   the answer, if vpcd expects one.
//!
//! # One command in flight
//!
//! vpcd is synchronous: it sends a message and, for `GET ATR` and APDUs, blocks until the
//! answer (`vicc_transmit`, `vpcd.c`). The connection thread is too: it sends one bulk-out
//! message, then a `Command::Status` marker, and waits for the bulk-in message with the
//! same `bSeq`, skipping time extensions. So at most one CCID message and one marker of
//! this transport wait in the runner's channel: pacing needs nothing more.
//!
//! The marker tells when the runner has handled the message: the runner delivers a
//! message's outputs before it takes the next command (`docs/PROGRAM.md` "lk-run").
//! IccPowerOn and IccPowerOff are answered at once, so once the marker is answered
//! without their reply, the device dropped the message. An XfrBlock may wait for a touch,
//! with a time extension every `lk_device::WTX_INTERVAL_MS`; once the marker is answered,
//! [`REPLY_SILENCE`] without a time extension or the reply means the device dropped the
//! command (a power cycle from the control socket ends a card command without a reply).
//! Until the marker is answered there is no limit: the runner may be busy with the
//! command itself (an RSA key generation) or with inputs queued before it.
//!
//! # A connection lost while a command waits
//!
//! While a message waits for its reply the thread does not read the socket, so it checks
//! every [`PEER_CHECK`] (from the first check on, [`PEER_CHECK`] after the message was
//! sent, so a quick reply costs nothing) whether vpcd closed or reset the connection: a
//! non-blocking `peek` that consumes nothing. vpcd sends nothing while it waits for an
//! answer: `vicc_transmit` holds the slot's `io_lock` from `sendToVICC` to `recvFromVICC`
//! (`vpcd.c`), and pcscd takes the reader's `mMutex` around every driver call
//! (`IFDTransmit`, `IFDStatusICC`, `IFDPowerICC`, pcsc-lite `ifdwrapper.c`). So a readable
//! socket then means end of stream or an error; data, which vpcd never sends then, is left
//! for the next read.
//!
//! A lost connection ends the wait at once instead of when the device gives up (a touch
//! wait lasts up to 15 s: `TOUCH_TIMEOUT_MS` of OATH, PIV, OpenPGP and YubiHSM Auth), and
//! the command is aborted in the device the way a CCID host aborts one (USB
//! CCID Rev 1.1 §5.3.1, §6.1.13): `HostInput::CcidControlAbort` and then
//! `PC_to_RDR_Abort`, both with a new `bSeq`. Without the abort the slot would stay busy:
//! the device answers everything but an abort with `CMD_SLOT_BUSY` while a command waits,
//! so the next connection's IccPowerOn would fail, and a tap would complete a command
//! whose client is gone. The device's answers to the abort (the aborted command's failed
//! DataBlock, the SlotStatus) are counted as stale. The `bSeq` counter runs on across
//! connections, as a host's counter runs on for its reader, so a late reply to a message
//! of an earlier connection is never taken for the reply to a new one.
//!
//! # Plugging
//!
//! A connection is a card in vpcd's reader. Every enumeration is an unplug and, if the
//! identity has CCID, a new plug-in: the current connection is closed (vpcd sees the card
//! removed) and a new one is made after [`REPLUG_PAUSE`] (the card inserted again),
//! because the device rebooted and its card session is gone. Without CCID no connection is
//! made until an enumeration enables CCID again, and not before [`REPLUG_PAUSE`] either.
//! The pause is what makes pcscd see the removal (see [`REPLUG_PAUSE`]).
//!
//! The answer to the command that caused the re-enumeration (a Management write with
//! REBOOT over CCID) reaches vpcd before the connection closes: it is delivered before the
//! runner calls `enumerate`, and the connection thread takes what is already queued before
//! it lets a re-enumeration end the connection. `enumerate` wakes a thread blocked in `read()` by shutting down the read
//! half only, so that answer can still be written.
//!
//! Dropping the transport shuts the connection down in both directions and waits at most
//! [`DROP_TIMEOUT`] for the thread; a thread still inside a connection attempt (at most
//! `CONNECT_TIMEOUT`) is left behind and ends by itself.
//!
//! # Who is connected
//!
//! The link has no authentication, so two rules keep the card from whoever happens to
//! listen on vpcd's address (see [`crate::peer`] for the threat):
//!
//! - **The address.** The transport cannot be made for an address that is not a loopback
//!   address unless [`VpcdConfig::allow_remote`] is set ([`crate::check_addr`]); with it, the
//!   address is reported once ([`VpcdNotice::NotLoopback`]).
//! - **The peer.** After each successful connect, before anything is read or written, the
//!   connection's own addresses go to [`VpcdConfig::peer_check`] (on Linux by default the
//!   owner of the peer's socket from `/proc/net/tcp`, which must be root, the local user
//!   `pcscd` or this process's user). A refused peer gets the connection shut down and closed unused: it receives no
//!   byte, the attempt counts in [`VpcdStats::refused`] (not in `connections`), and the next
//!   attempt follows on the normal schedule ([`RETRY_INTERVAL`] after the start of this
//!   one), because vpcd may come up later. A refusal is reported
//!   ([`VpcdNotice::PeerRefused`]) once per series of refusals, which ends with an accepted
//!   peer or a failed connection attempt; an allowed peer is reported with its uid
//!   ([`VpcdNotice::PeerAllowed`]), an unchecked one once for the transport's life
//!   ([`VpcdNotice::PeerUnchecked`]).

use std::fmt;
use std::io::{self, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender, TryRecvError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use lk_device::{Output, UsbIdentity};
use lk_run::{Command, HostInput, Transport};

use crate::ccid::{self, ApduExchange, Next, Reply, Sequence};
use crate::connect::{Connector, RemoteRefused, check_addr, is_loopback};
use crate::peer::{PeerCheck, PeerRefusal, PeerVerdict, default_peer_check};
use crate::protocol::{self, Control, MAX_PAYLOAD, Message};

/// How often a connection is attempted while vpcd does not accept one, and the shortest
/// time between two attempts after a connection was lost (`docs/PROGRAM.md` "lk-vpcd":
/// "retries every second"). A re-enumeration reconnects after [`REPLUG_PAUSE`] instead.
pub const RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// How long the card stays out of the reader when an enumeration closed its connection
/// (a re-plug, or CCID disabled and enabled again) before the transport connects again.
///
/// vpcd drops a connection only when a send or receive on it fails, and accepts a waiting
/// connection in its presence check as soon as it has none (`vicc_transmit`,
/// `vicc_eject`, `vicc_present`, `vpcd.c`). When a presence check finds the closed
/// connection, it reports the card absent and pcscd sees the removal. But when a client's
/// command finds it first, the next presence check already accepts a new connection that
/// waits, reports the card present, and pcscd never sees the card leave: it keeps the
/// reader at "no card" for good. Observed in the guest with vsmartcard-vpcd 3.3 and
/// pcsc-lite 2.4.1 after `ykman config usb` (a REBOOT): ykman disconnects with
/// `SCARD_UNPOWER_CARD`, so vpcd's power off meets the closed connection, and an
/// immediate reconnect left the card invisible. pcscd checks presence every
/// `PCSCLITE_STATUS_POLL_RATE` (400 ms, pcsc-lite `pcscd.h.in`; about 450 ms with vpcd's
/// round trip in the guest), and the connection is dropped within one check of the close,
/// so a pause longer than two checks lets one report the card absent.
pub const REPLUG_PAUSE: Duration = Duration::from_millis(1_500);

/// How long an XfrBlock that the runner has handled may go without its reply or a time
/// extension before it counts as dropped and vpcd gets [`ERROR_RESPONSE`]. Ten times the
/// device's time-extension cadence (`lk_device::WTX_INTERVAL_MS`, 500 ms): generous for a
/// loaded host.
pub const REPLY_SILENCE: Duration = Duration::from_secs(5);

/// How long dropping the transport waits for the connection thread.
pub const DROP_TIMEOUT: Duration = Duration::from_secs(1);

/// How long a write to vpcd may block before the connection counts as lost. vpcd reads
/// every answer it asked for at once; only a stuck peer fills the socket buffer.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// The answer to an APDU the device could not answer: a slot error, a card the reader
/// reports absent or unpowered, a dropped command (`docs/PROGRAM.md` "lk-vpcd"). `6F00`
/// is ISO/IEC 7816-4's "no precise diagnosis". vpcd needs some answer: an empty one makes
/// it eject the card (`vicc_transmit` calls `vicc_eject` when it receives nothing,
/// `vpcd.c`).
pub const ERROR_RESPONSE: [u8; 2] = [0x6F, 0x00];

/// CCID bulk-in messages queued for the connection thread. The device sends them only in
/// answer to this transport's own messages (one in flight) and as time extensions while
/// one waits, so the queue stays short; when it is full, a message is dropped and
/// counted in [`VpcdStats::stale`].
pub const OUTPUT_QUEUE: usize = 64;

/// How often the connection thread, while it waits for a reply, checks the marker and
/// whether the transport was re-enumerated or dropped.
const POLL: Duration = Duration::from_millis(20);

/// How often the connection thread, while a message waits for its reply, checks whether
/// vpcd closed or reset the connection (see the module docs, "A connection lost while a
/// command waits"). Three system calls per check; a reply within this time needs none.
/// (Not the check of who the peer is: that is [`VpcdConfig::peer_check`].)
pub const PEER_CHECK: Duration = Duration::from_millis(200);

/// How often a bounded join checks whether the thread has ended.
const JOIN_POLL: Duration = Duration::from_millis(5);

/// Receives [`VpcdNotice`]s, for the daemon's log. It runs on the connection thread and
/// the runner thread, so it must be quick and must not call into the transport.
pub type Observer = Arc<dyn Fn(&VpcdNotice) + Send + Sync>;

/// How a [`VpcdTransport`] is made ([`VpcdTransport::with_config`]); the module docs, "Who
/// is connected", say what the rules are for.
#[derive(Clone)]
pub struct VpcdConfig {
    /// Receives the transport's notices.
    pub observer: Option<Observer>,
    /// Whether vpcd's address may be other than a loopback address ([`crate::check_addr`]).
    /// Default false.
    pub allow_remote: bool,
    /// Asked about every new connection before it is used. Default
    /// [`crate::default_peer_check`]: the owner of the peer's socket on Linux, no check
    /// elsewhere.
    pub peer_check: Arc<dyn PeerCheck>,
}

impl Default for VpcdConfig {
    fn default() -> Self {
        VpcdConfig { observer: None, allow_remote: false, peer_check: default_peer_check() }
    }
}

impl fmt::Debug for VpcdConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VpcdConfig")
            .field("observer", &self.observer.is_some())
            .field("allow_remote", &self.allow_remote)
            .field("peer_check", &self.peer_check)
            .finish()
    }
}

/// What happened on the vpcd connection (`docs/PROGRAM.md` "localkeyd" logging).
/// `Received` and `Sent` are per message (the `-vv` level); the rest are connection
/// lifecycle and problems. Never carries APDU or ATR bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpcdNotice {
    /// The runner enumerated the device; with CCID the transport connects.
    Enumerated { ccid: bool },
    /// The address is not a loopback address (allowed explicitly): the APDUs travel
    /// unencrypted over a network. Sent once, when the transport is made.
    NotLoopback { addr: SocketAddr },
    /// The peer of a new connection is owned by `uid`, an allowed uid; the connection is
    /// used.
    PeerAllowed { addr: SocketAddr, uid: u32 },
    /// The peer of a new connection was not checked, for `reason`; the connection is used.
    /// Sent once for the transport's life.
    PeerUnchecked { addr: SocketAddr, reason: String },
    /// The peer of a new connection was refused: the connection was closed before anything
    /// was sent or read, and the transport retries every second. Sent for the first refusal
    /// of a series (see the module docs).
    PeerRefused { addr: SocketAddr, refusal: PeerRefusal },
    /// A connection to vpcd was made: the card is in the reader.
    Connected { addr: SocketAddr },
    /// A connection attempt failed. Sent for the first failure after a connection (or the
    /// start), not for every retry.
    Unreachable { addr: SocketAddr, reason: String },
    /// The connection ended: the card left the reader.
    Disconnected { reason: String },
    /// A message from vpcd, by kind, with its payload size.
    Received { message: &'static str, size: usize },
    /// An answer written to vpcd, with its payload size.
    Sent { message: &'static str, size: usize },
    /// A message from vpcd that no card answers (an unknown control byte, an empty
    /// payload) was ignored.
    Ignored { message: &'static str, size: usize },
    /// An APDU was answered with [`ERROR_RESPONSE`], and why.
    ErrorResponse { reason: String },
    /// Something else failed: a power-on or power-off the device did not complete, a
    /// thread.
    Failed(String),
}

impl fmt::Display for VpcdNotice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VpcdNotice::Enumerated { ccid: true } => f.write_str("vpcd: enumerated with CCID; connecting"),
            VpcdNotice::Enumerated { ccid: false } => f.write_str("vpcd: enumerated without CCID; no card"),
            VpcdNotice::NotLoopback { addr } => write!(
                f,
                "vpcd: warning: {addr} is not a loopback address; APDUs (PINs and keys among them) \
                 travel to it unencrypted, and whatever listens there is not checked"
            ),
            VpcdNotice::PeerAllowed { addr, uid } => {
                write!(f, "vpcd: the peer on {addr} is owned by uid {uid}, an allowed uid")
            }
            VpcdNotice::PeerUnchecked { addr, reason } => write!(f, "vpcd: the peer on {addr} is not checked: {reason}"),
            VpcdNotice::PeerRefused { addr, refusal } => {
                write!(f, "vpcd: the peer on {addr} {refusal}; refusing the connection, retrying every second")
            }
            VpcdNotice::Connected { addr } => write!(f, "vpcd: connected to {addr}; card inserted"),
            VpcdNotice::Unreachable { addr, reason } => {
                write!(f, "vpcd: cannot connect to {addr}: {reason}; retrying every second")
            }
            VpcdNotice::Disconnected { reason } => write!(f, "vpcd: disconnected ({reason}); card removed"),
            VpcdNotice::Received { message, size } => write!(f, "vpcd: <- {message}, {size} bytes"),
            VpcdNotice::Sent { message, size } => write!(f, "vpcd: -> {message}, {size} bytes"),
            VpcdNotice::Ignored { message, size } => write!(f, "vpcd: {message} of {size} bytes ignored"),
            VpcdNotice::ErrorResponse { reason } => write!(f, "vpcd: APDU answered with 6F00: {reason}"),
            VpcdNotice::Failed(reason) => write!(f, "vpcd: {reason}"),
        }
    }
}

/// Counters of the transport.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VpcdStats {
    /// Connections made to vpcd.
    pub connections: u64,
    /// Device outputs vpcd cannot carry: FIDO and OTP reports and CCID interrupt
    /// messages (vpcd has no slot-change message).
    pub ignored: u64,
    /// CCID bulk-in messages that answer nothing in flight (another `bSeq`, a malformed
    /// message, a reply after its command was given up), or lost to a full queue.
    pub stale: u64,
    /// Time-extension requests skipped while a command waited.
    pub time_extensions: u64,
    /// APDUs answered with [`ERROR_RESPONSE`].
    pub errors: u64,
    /// Connections closed unused because the peer check refused the peer.
    pub refused: u64,
}

/// An item of the queue from the runner thread to the connection thread.
enum Msg {
    /// A CCID bulk-in message (`Output::Ccid`).
    Ccid(lk_crypto::SecretBytes),
    /// Look at the shared state: it changed.
    Wake,
}

/// What the runner thread and the connection thread share under the lock.
struct State {
    /// The last enumeration has CCID.
    ccid: bool,
    /// The transport is being dropped.
    stopping: bool,
    /// The message limit of the last enumeration ([`ccid::max_data_len`]).
    max_data: usize,
    /// A clone of the current connection, so `enumerate` and `drop` can wake the thread.
    stream: Option<TcpStream>,
}

/// State shared by the runner thread and the connection thread.
struct Shared {
    runner: Sender<Command>,
    observer: Option<Observer>,
    addr: SocketAddr,
    peer_check: Arc<dyn PeerCheck>,
    /// Raised by every enumeration and by drop, always under the lock; a connection of an
    /// earlier generation ends.
    generation: AtomicU64,
    connected: AtomicBool,
    control: Mutex<State>,
    changed: Condvar,
    connections: AtomicU64,
    ignored: AtomicU64,
    stale: AtomicU64,
    time_extensions: AtomicU64,
    errors: AtomicU64,
    refused: AtomicU64,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.control.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn notify(&self, notice: VpcdNotice) {
        if let Some(observer) = &self.observer {
            observer(&notice);
        }
    }

    fn count(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Wait until a connection attempt is wanted (CCID enabled) and due (`at`); the
    /// generation and message limit to attempt it with. `None` once the transport is
    /// dropped.
    fn wait_for_attempt(&self, at: Instant) -> Option<(u64, usize)> {
        let mut control = self.lock();
        loop {
            if control.stopping {
                return None;
            }
            if control.ccid {
                let now = Instant::now();
                if now >= at {
                    return Some((self.generation(), control.max_data));
                }
                control = self.changed.wait_timeout(control, at - now).unwrap_or_else(PoisonError::into_inner).0;
            } else {
                control = self.changed.wait(control).unwrap_or_else(PoisonError::into_inner);
            }
        }
    }

    /// Make `stream` the current connection, unless the generation moved on while it
    /// was being made (then it is closed unused).
    fn register(&self, stream: &TcpStream, generation: u64) -> io::Result<bool> {
        let clone = stream.try_clone()?;
        let mut control = self.lock();
        if control.stopping || !control.ccid || self.generation() != generation {
            return Ok(false);
        }
        control.stream = Some(clone);
        self.connected.store(true, Ordering::SeqCst);
        Ok(true)
    }

    /// Ask the peer check about a new connection, with the connection's own addresses (not
    /// the configured one: a host name resolved once, a test connector's disguise).
    fn check_peer(&self, stream: &TcpStream) -> PeerVerdict {
        match (stream.local_addr(), stream.peer_addr()) {
            (Ok(local), Ok(peer)) => self.peer_check.check(local, peer),
            (Err(error), _) | (_, Err(error)) => {
                PeerVerdict::Refused(PeerRefusal::Failed(format!("the connection's addresses are unknown: {error}")))
            }
        }
    }

    fn unregister(&self) {
        let mut control = self.lock();
        control.stream = None;
        self.connected.store(false, Ordering::SeqCst);
    }

    /// Why a connection of `generation` must end, if it must.
    fn ended(&self, generation: u64) -> Option<End> {
        if self.generation() == generation {
            return None;
        }
        let control = self.lock();
        Some(if control.stopping {
            End::Stopped
        } else if control.ccid {
            End::Replugged
        } else {
            End::Disabled
        })
    }
}

/// Why a connection ended.
#[derive(Debug)]
enum End {
    /// vpcd closed the connection.
    Closed,
    ReadFailed(io::Error),
    /// vpcd closed the connection (`None`) or it failed while a message waited for the
    /// device's reply; the command was aborted in the device.
    LostWaiting(Option<io::Error>),
    WriteFailed(io::Error),
    /// A re-enumeration with CCID: unplugged, to be plugged in again after
    /// [`REPLUG_PAUSE`].
    Replugged,
    /// A re-enumeration without CCID.
    Disabled,
    /// The transport is being dropped.
    Stopped,
    /// The runner's channel is gone.
    RunnerGone,
    /// `GET ATR` could not be answered: the device did not power the card on.
    NoAtr,
}

impl fmt::Display for End {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            End::Closed => f.write_str("vpcd closed the connection"),
            End::ReadFailed(error) => write!(f, "reading from vpcd failed: {error}"),
            End::LostWaiting(None) => {
                f.write_str("vpcd closed the connection while a command waited; the command was aborted")
            }
            End::LostWaiting(Some(error)) => write!(
                f,
                "the connection to vpcd failed while a command waited ({error}); the command was aborted"
            ),
            End::WriteFailed(error) => write!(f, "writing to vpcd failed: {error}"),
            End::Replugged => f.write_str("the device re-enumerated"),
            End::Disabled => f.write_str("CCID is disabled"),
            End::Stopped => f.write_str("the transport is stopping"),
            End::RunnerGone => f.write_str("the runner has stopped"),
            End::NoAtr => f.write_str("the device gave no ATR"),
        }
    }
}

/// The connection thread: connect while CCID is enabled, check the peer, serve each
/// connection, retry.
fn run(shared: &Shared, mut connector: Box<dyn Connector>, outputs: &Receiver<Msg>) {
    let mut next_attempt = Instant::now();
    // In a series of failed attempts, of refused peers (each reported once per series).
    let mut failing = false;
    let mut refusing = false;
    let mut told_unchecked = false;
    // Runs on across connections (see the module docs).
    let mut seq = Sequence::default();
    while let Some((generation, max_data)) = shared.wait_for_attempt(next_attempt) {
        next_attempt = Instant::now() + RETRY_INTERVAL;
        let stream = match connector.connect() {
            Ok(stream) => stream,
            Err(error) => {
                refusing = false;
                if !failing {
                    shared.notify(VpcdNotice::Unreachable { addr: shared.addr, reason: error.to_string() });
                    failing = true;
                }
                continue;
            }
        };
        failing = false;
        // Before a byte is read or written (see the module docs, "Who is connected").
        match shared.check_peer(&stream) {
            PeerVerdict::Allowed { uid } => {
                refusing = false;
                shared.notify(VpcdNotice::PeerAllowed { addr: shared.addr, uid });
            }
            PeerVerdict::Unchecked { reason } => {
                refusing = false;
                if !told_unchecked {
                    told_unchecked = true;
                    shared.notify(VpcdNotice::PeerUnchecked { addr: shared.addr, reason });
                }
            }
            PeerVerdict::Refused(refusal) => {
                let _ = stream.shutdown(Shutdown::Both);
                drop(stream);
                Shared::count(&shared.refused);
                if !refusing {
                    refusing = true;
                    shared.notify(VpcdNotice::PeerRefused { addr: shared.addr, refusal });
                }
                continue;
            }
        }
        match shared.register(&stream, generation) {
            Ok(true) => {}
            Ok(false) => {
                // Re-enumerated (or dropped) during the attempt: try again with the new
                // state, at once.
                next_attempt = Instant::now();
                continue;
            }
            Err(error) => {
                shared.notify(VpcdNotice::Failed(format!("cannot use the connection to {}: {error}", shared.addr)));
                continue;
            }
        }
        Shared::count(&shared.connections);
        shared.notify(VpcdNotice::Connected { addr: shared.addr });
        let end = Session::new(shared, outputs, stream, generation, max_data, &mut seq).run();
        // A connection that failed because the transport re-enumerated or stopped ended
        // for that reason (a re-plug reconnects after the pause).
        let end = shared.ended(generation).unwrap_or(end);
        shared.unregister();
        shared.notify(VpcdNotice::Disconnected { reason: end.to_string() });
        match end {
            End::Replugged | End::Disabled => next_attempt = Instant::now() + REPLUG_PAUSE,
            End::Stopped | End::RunnerGone => return,
            End::Closed | End::ReadFailed(_) | End::LostWaiting(_) | End::WriteFailed(_) | End::NoAtr => {}
        }
    }
}

/// One connection to vpcd: one card insertion. The card session state the transport
/// keeps (ATR, power) starts afresh with each; the `bSeq` counter runs on.
struct Session<'a> {
    shared: &'a Shared,
    outputs: &'a Receiver<Msg>,
    stream: TcpStream,
    generation: u64,
    max_data: usize,
    seq: &'a mut Sequence,
    /// The ATR of the last successful power-on on this connection.
    atr: Option<Vec<u8>>,
    /// Whether the slot is powered as far as this side knows: after a successful
    /// power-on, until a power-off or a failed reply.
    powered: bool,
}

impl<'a> Session<'a> {
    fn new(
        shared: &'a Shared,
        outputs: &'a Receiver<Msg>,
        stream: TcpStream,
        generation: u64,
        max_data: usize,
        seq: &'a mut Sequence,
    ) -> Session<'a> {
        Session { shared, outputs, stream, generation, max_data, seq, atr: None, powered: false }
    }

    /// Serve vpcd's messages, one at a time, until the connection ends.
    fn run(&mut self) -> End {
        if let Err(error) = self.stream.set_write_timeout(Some(WRITE_TIMEOUT)) {
            return End::WriteFailed(error);
        }
        loop {
            if let Some(end) = self.ended() {
                return end;
            }
            let mut reader = &self.stream;
            let payload = match protocol::read_message(&mut reader) {
                Ok(Some(payload)) => lk_crypto::SecretBytes::new(payload),
                Ok(None) => return self.ended().unwrap_or(End::Closed),
                Err(error) => return self.ended().unwrap_or(End::ReadFailed(error)),
            };
            // A message read after a re-enumeration belongs to the card that was removed.
            if let Some(end) = self.ended() {
                return end;
            }
            let message = Message::parse(&payload);
            self.shared.notify(VpcdNotice::Received { message: message.name(), size: payload.len() });
            let handled = match message {
                Message::Control(control) => self.control(control),
                Message::Apdu(apdu) => self.apdu(apdu),
                Message::UnknownControl(_) | Message::Empty => {
                    self.shared.notify(VpcdNotice::Ignored { message: message.name(), size: payload.len() });
                    Ok(())
                }
            };
            if let Err(end) = handled {
                return end;
            }
        }
    }

    fn ended(&self) -> Option<End> {
        self.shared.ended(self.generation)
    }

    /// A control command: power off, power on, reset (power off, then on) and `GET ATR`,
    /// which is answered with the ATR of the last power-on on this connection, powering
    /// the card on first if there is none. Only `GET ATR` is answered.
    fn control(&mut self, control: Control) -> Result<(), End> {
        match control {
            Control::PowerOff => self.power_off(),
            Control::PowerOn => self.power_on_reporting(),
            Control::Reset => {
                self.power_off()?;
                self.power_on_reporting()
            }
            Control::GetAtr => {
                if self.atr.is_none() {
                    self.power_on_reporting()?;
                }
                // vpcd ejects the card on an empty answer; without an ATR there is no
                // card to present.
                let atr = self.atr.clone().ok_or(End::NoAtr)?;
                self.send(&atr, "ATR")
            }
        }
    }

    /// `PC_to_RDR_IccPowerOn`: keep the ATR from the DataBlock. `Ok(Err(reason))` when the
    /// device did not power the card on.
    fn power_on(&mut self) -> Result<Result<(), String>, End> {
        let seq = self.seq.take();
        let result = match self.transact(ccid::icc_power_on(seq), seq, None)? {
            Some(reply) => ccid::power_on_atr(&reply).map_err(|fault| fault.to_string()),
            None => Err("the device did not answer IccPowerOn".to_owned()),
        };
        Ok(match result {
            Ok(atr) => {
                self.atr = Some(atr);
                self.powered = true;
                Ok(())
            }
            Err(reason) => {
                self.powered = false;
                Err(reason)
            }
        })
    }

    fn power_on_reporting(&mut self) -> Result<(), End> {
        if let Err(reason) = self.power_on()? {
            self.shared.notify(VpcdNotice::Failed(format!("power-on failed: {reason}")));
        }
        Ok(())
    }

    /// `PC_to_RDR_IccPowerOff`. The slot counts as unpowered afterwards in any case.
    fn power_off(&mut self) -> Result<(), End> {
        let seq = self.seq.take();
        let reply = self.transact(ccid::icc_power_off(seq), seq, None)?;
        self.powered = false;
        let result = match reply {
            Some(reply) => ccid::power_off_done(&reply).map_err(|fault| fault.to_string()),
            None => Err("the device did not answer IccPowerOff".to_owned()),
        };
        if let Err(reason) = result {
            self.shared.notify(VpcdNotice::Failed(format!("power-off failed: {reason}")));
        }
        Ok(())
    }

    /// A command APDU: answered with the response APDU, or with [`ERROR_RESPONSE`] when
    /// the device could not answer it; then the slot is powered on again before the next
    /// APDU.
    fn apdu(&mut self, apdu: &[u8]) -> Result<(), End> {
        let response = match self.exchange(apdu)? {
            Ok(response) => response,
            Err(reason) => {
                self.powered = false;
                Shared::count(&self.shared.errors);
                self.shared.notify(VpcdNotice::ErrorResponse { reason });
                lk_crypto::SecretBytes::from_slice(&ERROR_RESPONSE)
            }
        };
        self.send(&response, "response")
    }

    /// Exchange one APDU with the device: power the slot on first unless it is known to
    /// be powered, then XfrBlocks until the response is complete.
    fn exchange(&mut self, apdu: &[u8]) -> Result<Result<lk_crypto::SecretBytes, String>, End> {
        if !self.powered
            && let Err(reason) = self.power_on()?
        {
            return Ok(Err(format!("the card could not be powered on: {reason}")));
        }
        let mut exchange = ApduExchange::new(apdu, self.max_data);
        loop {
            let seq = self.seq.take();
            let block = exchange.message(seq);
            let Some(reply) = self.transact(block, seq, Some(REPLY_SILENCE))? else {
                return Ok(Err("the device did not answer the command".to_owned()));
            };
            match exchange.accept(&reply) {
                Next::Send => {}
                Next::Done(mut response) if response.0.len() <= MAX_PAYLOAD => {
                    return Ok(Ok(lk_crypto::SecretBytes::new(std::mem::take(&mut response.0))));
                }
                Next::Done(response) => {
                    return Ok(Err(format!("a response of {} bytes does not fit a vpcd message", response.0.len())));
                }
                Next::Failed(fault) => return Ok(Err(fault.to_string())),
            }
        }
    }

    /// Send one bulk-out message with `bSeq` `seq` to the runner and wait for its reply:
    /// the first bulk-in message with the same `bSeq` that is not a time extension.
    ///
    /// `Ok(None)` when the device dropped the message: no reply by the time the runner
    /// answered the marker sent behind it (`patience` `None`), or no reply and no time
    /// extension for `patience` after that. A re-enumeration or drop ends the wait, but a
    /// reply that was delivered before it is still taken. A connection vpcd closed or
    /// reset ends it too ([`End::LostWaiting`]), and the command is aborted in the device
    /// (see the module docs).
    fn transact(&mut self, message: Vec<u8>, seq: u8, patience: Option<Duration>) -> Result<Option<Reply>, End> {
        // Whatever is queued now answers an earlier message.
        while let Ok(item) = self.outputs.try_recv() {
            if let Msg::Ccid(_) = item {
                Shared::count(&self.shared.stale);
            }
        }
        let runner = &self.shared.runner;
        runner.send(Command::Input(HostInput::Ccid(message))).map_err(|_| End::RunnerGone)?;
        let (answer, marker) = mpsc::channel();
        runner.send(Command::Status(answer)).map_err(|_| End::RunnerGone)?;
        let mut handled = false;
        let mut heard = Instant::now();
        let mut peer_checked = Instant::now();
        loop {
            match self.outputs.recv_timeout(POLL) {
                Ok(Msg::Ccid(bytes)) => {
                    if let Some(reply) = self.classify(&bytes, seq, &mut heard) {
                        return Ok(Some(reply));
                    }
                }
                Ok(Msg::Wake) | Err(RecvTimeoutError::Timeout) => {}
                // The transport is gone.
                Err(RecvTimeoutError::Disconnected) => return Err(End::Stopped),
            }
            if !handled {
                match marker.try_recv() {
                    Ok(_) => {
                        // Every output the message produced at once is queued by now.
                        handled = true;
                        heard = Instant::now();
                        if let Some(reply) = self.drain(seq, &mut heard) {
                            return Ok(Some(reply));
                        }
                        if patience.is_none() {
                            return Ok(None);
                        }
                    }
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => return Err(End::RunnerGone),
                }
            }
            if let Some(end) = self.ended() {
                return self.drain(seq, &mut heard).map(Some).ok_or(end);
            }
            if handled && patience.is_some_and(|patience| heard.elapsed() >= patience) {
                return Ok(None);
            }
            if peer_checked.elapsed() >= PEER_CHECK {
                peer_checked = Instant::now();
                if let Some(error) = self.peer_lost() {
                    // A re-enumeration shuts the read half down, which reads as the end of
                    // the stream: it keeps its own meaning.
                    if let Some(end) = self.ended() {
                        return self.drain(seq, &mut heard).map(Some).ok_or(end);
                    }
                    self.abort()?;
                    return Err(End::LostWaiting(error));
                }
            }
        }
    }

    /// Whether vpcd closed (`Some(None)`) or reset (`Some(Some(error))`) the connection,
    /// seen without blocking and without consuming anything (see the module docs). Data
    /// waiting on the socket counts as a live connection and stays there.
    fn peer_lost(&self) -> Option<Option<io::Error>> {
        if self.stream.set_nonblocking(true).is_err() {
            // Cannot look without blocking; the next read or write will tell.
            return None;
        }
        let mut byte = [0; 1];
        let peeked = self.stream.peek(&mut byte);
        if let Err(error) = self.stream.set_nonblocking(false) {
            // The connection cannot be used for blocking reads any more.
            return Some(Some(error));
        }
        match peeked {
            Ok(0) => Some(None),
            Ok(_) => None,
            Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => None,
            Err(error) => Some(Some(error)),
        }
    }

    /// Abort whatever the device holds for this transport (USB CCID Rev 1.1 §5.3.1,
    /// §6.1.13): the `ABORT` control request, then `PC_to_RDR_Abort`, with one new `bSeq`.
    /// The answers are not awaited; they arrive as stale messages. The runner handles both
    /// before anything sent later, the next connection's IccPowerOn included.
    fn abort(&mut self) -> Result<(), End> {
        let seq = self.seq.take();
        let send = |input: HostInput| self.shared.runner.send(Command::Input(input)).map_err(|_| End::RunnerGone);
        send(HostInput::CcidControlAbort { slot: ccid::SLOT, seq })?;
        send(HostInput::Ccid(ccid::abort(seq)))
    }

    /// Take every queued bulk-in message; the reply to `seq`, if one is among them.
    fn drain(&mut self, seq: u8, heard: &mut Instant) -> Option<Reply> {
        while let Ok(item) = self.outputs.try_recv() {
            if let Msg::Ccid(bytes) = item
                && let Some(reply) = self.classify(&bytes, seq, heard)
            {
                return Some(reply);
            }
        }
        None
    }

    /// One bulk-in message while `seq` is in flight: its reply, or `None` for a time
    /// extension (which renews `heard`) and for anything else (stale).
    fn classify(&self, bytes: &[u8], seq: u8, heard: &mut Instant) -> Option<Reply> {
        match Reply::parse(bytes) {
            Ok(reply) if reply.seq == seq && reply.is_time_extension() => {
                Shared::count(&self.shared.time_extensions);
                *heard = Instant::now();
                None
            }
            Ok(reply) if reply.seq == seq => Some(reply),
            Ok(_) | Err(_) => {
                Shared::count(&self.shared.stale);
                None
            }
        }
    }

    /// Write one answer to vpcd, as one framed message in one write.
    fn send(&mut self, payload: &[u8], what: &'static str) -> Result<(), End> {
        let frame = lk_crypto::SecretBytes::new(protocol::encode(payload)
            .map_err(|error| End::WriteFailed(io::Error::new(io::ErrorKind::InvalidData, error)))?);
        let mut writer = &self.stream;
        if let Err(error) = writer.write_all(&frame) {
            return Err(self.ended().unwrap_or(End::WriteFailed(error)));
        }
        self.shared.notify(VpcdNotice::Sent { message: what, size: payload.len() });
        Ok(())
    }
}

/// The vpcd transport: the CCID interface as a virtual card in vsmartcard's vpcd reader
/// (`docs/PROGRAM.md` "lk-vpcd").
///
/// - [`Transport::enumerate`] with CCID connects, at once the first time; a current
///   connection is closed first and the new one made after [`REPLUG_PAUSE`]. Without CCID
///   it disconnects and stays disconnected until an enumeration enables CCID again. The
///   connection thread starts at the first enumeration with CCID.
/// - [`Transport::deliver`] hands `Output::Ccid` to the connection thread and ignores
///   every other output ([`VpcdStats::ignored`]); `Output::CcidInterrupt` too, as vpcd has
///   no slot-change message.
/// - [`Transport::attached`] is whether a connection to vpcd is open.
/// - No bus events are sent: the device is powered from the moment it opens.
/// - Dropping the transport closes the connection and waits at most [`DROP_TIMEOUT`] for
///   the thread.
pub struct VpcdTransport {
    shared: Arc<Shared>,
    /// Until the connection thread starts.
    connector: Option<Box<dyn Connector>>,
    outputs: SyncSender<Msg>,
    /// Until the connection thread starts.
    receiver: Option<Receiver<Msg>>,
    thread: Option<JoinHandle<()>>,
}

impl fmt::Debug for VpcdTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let control = self.shared.lock();
        f.debug_struct("VpcdTransport")
            .field("addr", &self.shared.addr)
            .field("peer_check", &self.shared.peer_check)
            .field("ccid", &control.ccid)
            .field("connected", &self.shared.connected.load(Ordering::SeqCst))
            .field("generation", &self.shared.generation())
            .field("thread", &self.thread.as_ref().map(|thread| !thread.is_finished()))
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl VpcdTransport {
    /// A transport that connects through `connector` (`TcpConnector` for vpcd's address)
    /// and feeds the runner through `runner` (`lk_run::Runner::sender`), with the default
    /// [`VpcdConfig`]: a loopback address only, the default peer check, no observer.
    /// Nothing is opened before the first enumeration with CCID. The runner must answer
    /// `Command::Status` (`lk_run::Runner` does): the connection thread learns from it when
    /// a message was handled.
    ///
    /// Fails when `connector.addr()` is not a loopback address ([`crate::check_addr`]).
    pub fn new(connector: Box<dyn Connector>, runner: Sender<Command>) -> Result<VpcdTransport, RemoteRefused> {
        VpcdTransport::with_config(connector, runner, VpcdConfig::default())
    }

    /// [`VpcdTransport::new`] with an observer for connection events.
    pub fn with_observer(
        connector: Box<dyn Connector>,
        runner: Sender<Command>,
        observer: Option<Observer>,
    ) -> Result<VpcdTransport, RemoteRefused> {
        VpcdTransport::with_config(connector, runner, VpcdConfig { observer, ..VpcdConfig::default() })
    }

    /// A transport made with `config`. Fails when `connector.addr()` is not a loopback
    /// address and `config.allow_remote` is false ([`crate::check_addr`]); a non-loopback
    /// address that is allowed is reported to the observer at once
    /// ([`VpcdNotice::NotLoopback`]).
    pub fn with_config(
        connector: Box<dyn Connector>,
        runner: Sender<Command>,
        config: VpcdConfig,
    ) -> Result<VpcdTransport, RemoteRefused> {
        let addr = connector.addr();
        check_addr(addr, config.allow_remote)?;
        let VpcdConfig { observer, allow_remote: _, peer_check } = config;
        let shared = Shared {
            runner,
            observer,
            addr,
            peer_check,
            generation: AtomicU64::new(0),
            connected: AtomicBool::new(false),
            control: Mutex::new(State {
                ccid: false,
                stopping: false,
                max_data: ccid::max_data_len(&[]),
                stream: None,
            }),
            changed: Condvar::new(),
            connections: AtomicU64::new(0),
            ignored: AtomicU64::new(0),
            stale: AtomicU64::new(0),
            time_extensions: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            refused: AtomicU64::new(0),
        };
        if !is_loopback(&addr) {
            shared.notify(VpcdNotice::NotLoopback { addr });
        }
        let (outputs, receiver) = mpsc::sync_channel(OUTPUT_QUEUE);
        Ok(VpcdTransport {
            shared: Arc::new(shared),
            connector: Some(connector),
            outputs,
            receiver: Some(receiver),
            thread: None,
        })
    }

    /// vpcd's address.
    pub fn addr(&self) -> SocketAddr {
        self.shared.addr
    }

    /// The counters so far.
    pub fn stats(&self) -> VpcdStats {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        VpcdStats {
            connections: load(&self.shared.connections),
            ignored: load(&self.shared.ignored),
            stale: load(&self.shared.stale),
            time_extensions: load(&self.shared.time_extensions),
            errors: load(&self.shared.errors),
            refused: load(&self.shared.refused),
        }
    }

    /// Start the connection thread, once.
    fn start(&mut self) {
        if self.thread.is_some() {
            return;
        }
        let (Some(connector), Some(outputs)) = (self.connector.take(), self.receiver.take()) else {
            return;
        };
        let shared = Arc::clone(&self.shared);
        let spawned =
            thread::Builder::new().name("lk-vpcd".into()).spawn(move || run(&shared, connector, &outputs));
        match spawned {
            Ok(handle) => self.thread = Some(handle),
            Err(error) => {
                self.shared.notify(VpcdNotice::Failed(format!("cannot start the connection thread: {error}")));
            }
        }
    }
}

impl Transport for VpcdTransport {
    fn enumerate(&mut self, identity: &UsbIdentity) {
        let ccid = identity.interfaces.ccid;
        self.shared.notify(VpcdNotice::Enumerated { ccid });
        {
            let mut control = self.shared.lock();
            control.ccid = ccid;
            control.max_data = ccid::max_data_len(&identity.ccid_class_descriptor);
            self.shared.generation.fetch_add(1, Ordering::SeqCst);
            // Wake a thread blocked in `read()`; the write half stays open for an answer
            // that is already queued (see the module docs, Plugging).
            if let Some(stream) = &control.stream {
                let _ = stream.shutdown(Shutdown::Read);
            }
        }
        self.shared.changed.notify_all();
        let _ = self.outputs.try_send(Msg::Wake);
        if ccid {
            self.start();
        }
    }

    fn deliver(&mut self, mut output: Output) {
        match &mut output {
            Output::Ccid(message) => {
                if self.outputs.try_send(Msg::Ccid(lk_crypto::SecretBytes::new(std::mem::take(message)))).is_err() {
                    Shared::count(&self.shared.stale);
                }
            }
            Output::FidoReport(_) | Output::OtpFeature(_) | Output::OtpKeyboard(_) | Output::CcidInterrupt(_) => {
                Shared::count(&self.shared.ignored);
            }
            // vpcd has no presence indicator; `Reenumerate` never arrives here (the runner
            // calls `enumerate`).
            Output::PresenceIndicator(_) | Output::Reenumerate(_) => {}
        }
    }

    fn attached(&self) -> Option<bool> {
        Some(self.shared.connected.load(Ordering::SeqCst))
    }
}

impl Drop for VpcdTransport {
    fn drop(&mut self) {
        {
            let mut control = self.shared.lock();
            control.stopping = true;
            self.shared.generation.fetch_add(1, Ordering::SeqCst);
            if let Some(stream) = control.stream.take() {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
        self.shared.changed.notify_all();
        let _ = self.outputs.try_send(Msg::Wake);
        let Some(thread) = self.thread.take() else {
            return;
        };
        let deadline = Instant::now() + DROP_TIMEOUT;
        while !thread.is_finished() && Instant::now() < deadline {
            thread::sleep(JOIN_POLL);
        }
        if !thread.is_finished() {
            self.shared.notify(VpcdNotice::Failed("the connection thread did not end in time".to_owned()));
        } else if thread.join().is_err() {
            self.shared.notify(VpcdNotice::Failed("the connection thread panicked".to_owned()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notices_read_as_log_lines() {
        let addr: SocketAddr = "192.0.2.1:35963".parse().expect("valid");
        assert_eq!(VpcdNotice::Enumerated { ccid: true }.to_string(), "vpcd: enumerated with CCID; connecting");
        assert!(VpcdNotice::NotLoopback { addr }.to_string().contains("192.0.2.1:35963 is not a loopback address"));
        assert_eq!(
            VpcdNotice::Received { message: "APDU", size: 12 }.to_string(),
            "vpcd: <- APDU, 12 bytes"
        );
        assert_eq!(VpcdNotice::Sent { message: "ATR", size: 23 }.to_string(), "vpcd: -> ATR, 23 bytes");
        assert_eq!(
            VpcdNotice::Disconnected { reason: End::Replugged.to_string() }.to_string(),
            "vpcd: disconnected (the device re-enumerated); card removed"
        );
        assert!(VpcdNotice::Unreachable { addr, reason: "refused".into() }.to_string().contains("retrying"));
        let local: SocketAddr = "127.0.0.1:35963".parse().expect("valid");
        assert_eq!(
            VpcdNotice::PeerRefused {
                addr: local,
                refusal: PeerRefusal::NotAllowed { uid: 1001, allowed: vec![0, 1000] }
            }
            .to_string(),
            "vpcd: the peer on 127.0.0.1:35963 is owned by uid 1001, not an allowed uid (0, 1000); refusing the \
             connection, retrying every second"
        );
        assert_eq!(
            VpcdNotice::PeerAllowed { addr: local, uid: 0 }.to_string(),
            "vpcd: the peer on 127.0.0.1:35963 is owned by uid 0, an allowed uid"
        );
        assert_eq!(
            VpcdNotice::PeerUnchecked { addr: local, reason: "no /proc".into() }.to_string(),
            "vpcd: the peer on 127.0.0.1:35963 is not checked: no /proc"
        );
    }

    #[test]
    fn the_error_response_is_6f00() {
        assert_eq!(ERROR_RESPONSE, [0x6F, 0x00]);
    }
}
