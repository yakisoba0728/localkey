//! The bus transport over a Unix socket (`docs/PROGRAM.md` "lk-wire", "Connection
//! semantics").
//!
//! Threads:
//!
//! - the runner thread calls [`Transport::enumerate`] and [`Transport::deliver`]; both only
//!   encode and queue, so they never wait for the peer;
//! - the accept thread admits clients. It starts at the first enumeration, so a client never
//!   sees a frame before IDENTITY (an earlier connection waits in the listen backlog);
//! - per client, a writer thread writes the queued frames in order and a reader thread
//!   decodes frames and sends `Command::Input` to the runner, at the runner's pace (see
//!   below).
//!
//! The one slot for the current client is behind a mutex. Every thread that acts on a
//! client checks that the client is still the one it was started for (`id`), so a late
//! reader or writer of an old connection never touches its successor.
//!
//! A client closed after a malformed frame leaves the slot at once (the next host may plug
//! in), but its writer still writes what is queued, ending with the ERROR. Such a flush is
//! bounded by [`FLUSH_TIMEOUT`]: the writer checks its deadline after every write, and its
//! writes time out every [`WRITE_POLL`], so a client that stopped reading cannot keep the
//! thread and the socket. Dropping the transport shuts flushing clients down at once.
//!
//! The runner's channel is unbounded, so the reader paces itself: a USB device NAKs while
//! it is busy, and the wire's equivalent is a reader that stops reading. After every
//! window of inputs ([`INPUT_WINDOW_FRAMES`] frames or [`INPUT_WINDOW_BYTES`] of payload)
//! the reader sends `Command::Status` as a marker, and before it sends the next marker it
//! waits for the answer to the previous one. The runner handles commands in order, so an
//! answer means every input sent before its marker has been handled: at most two windows
//! of a client's inputs wait in the channel, whatever the client sends, and the rest waits
//! in the socket, where it holds up the client's writes. The reader waits with the slot
//! unlocked (the runner takes the slot to answer `Status`, for `Transport::attached`).

use std::fmt;
use std::io::{self, Write};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use lk_core::UsbInterfaces;
use lk_device::{BusEvent, Output, UsbIdentity};
use lk_run::{Command, HostInput, Status, Transport};

use crate::WireError;
use crate::codec::{Frame, FrameError, HEADER_LEN, Identity, Origin};
use crate::control::interface_list;
use crate::inbox::Inbox;
use crate::socket::{self, Acceptor, SocketFile};

/// Frames queued for one client. A client that falls this far behind is too slow and is
/// dropped (`Transport`: a transport buffers on its own threads and never blocks the
/// runner).
pub const WRITE_QUEUE_FRAMES: usize = 4096;

/// Frames per window of a client's inputs: the reader asks the runner to confirm that it
/// has handled the previous window before it sends more than one more (see the module
/// docs). At most twice this many inputs of a client wait in the runner's channel.
pub const INPUT_WINDOW_FRAMES: usize = 64;

/// Payload bytes per window of a client's inputs: a window also ends once its frames carry
/// this much, so large CCID messages are paced by size (two windows hold at most twice
/// this plus two maximal frames).
pub const INPUT_WINDOW_BYTES: usize = 256 * 1024;

/// How long writing ERROR `busy` to a refused client may take.
const REFUSE_TIMEOUT: Duration = Duration::from_secs(1);

/// How long the writer of a client closed after a malformed frame may take, in total, to
/// write what is queued and the ERROR. Then the socket is shut down, read or not.
const FLUSH_TIMEOUT: Duration = Duration::from_secs(1);

/// The write timeout of a writer thread: how often a writer blocked on a client that does
/// not read wakes up to check its flush deadline. A connected client is never dropped for
/// reading slowly; only a full queue drops it.
const WRITE_POLL: Duration = Duration::from_millis(100);

/// Receives [`WireEvent`]s, for the daemon's log. It runs on the transport's threads with
/// the client slot locked, so it must be quick and must not call into the transport.
pub type Observer = Arc<dyn Fn(&WireEvent) + Send + Sync>;

/// What happened on the wire socket (`docs/PROGRAM.md` "localkeyd" logging: connections
/// and enumeration at `-v`, frame types and sizes at `-vv`). Never carries payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireEvent {
    /// A client connected: a plug-in.
    Connected,
    /// A second client got ERROR `busy` and was closed.
    Refused,
    /// The client disconnected or was dropped.
    Disconnected,
    /// The client sent a malformed frame; it got ERROR with this reason and was closed.
    Malformed(String),
    /// The device was presented with this product ID and interface set.
    Enumerated { product_id: u16, interfaces: UsbInterfaces },
    /// A frame from the client went to the runner.
    Received { frame_type: u8, size: usize },
    /// A frame was queued for the client.
    Sent { frame_type: u8, size: usize },
    /// The transport could not do its work (for example start its accept thread).
    Failed(String),
}

impl fmt::Display for WireEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireEvent::Connected => f.write_str("wire: client connected"),
            WireEvent::Refused => f.write_str("wire: second client refused (busy)"),
            WireEvent::Disconnected => f.write_str("wire: client disconnected"),
            WireEvent::Malformed(reason) => write!(f, "wire: malformed frame from client: {reason}"),
            WireEvent::Enumerated { product_id, interfaces } => {
                write!(f, "wire: enumerated as product 0x{product_id:04x} ({})", interface_list(*interfaces))
            }
            WireEvent::Received { frame_type, size } => write!(f, "wire: <- 0x{frame_type:02x}, {size} bytes"),
            WireEvent::Sent { frame_type, size } => write!(f, "wire: -> 0x{frame_type:02x}, {size} bytes"),
            WireEvent::Failed(reason) => write!(f, "wire: {reason}"),
        }
    }
}

/// The wire transport: the device's bus is a Unix socket and its one client is the USB
/// host.
///
/// - [`WireTransport::bind`] places and binds the socket; the runner calls
///   [`Transport::enumerate`] when the transport is attached, which starts accepting.
/// - On accept, the client gets IDENTITY and the runner gets
///   `Input::Bus(BusEvent::PowerCycle)` (plugging in powers the key). A second client gets
///   ERROR `busy` and is closed; the first is unaffected.
/// - Outputs while no client is connected are dropped. A disconnect leaves the device
///   running; reconnecting is a new plug-in.
/// - A malformed frame gets ERROR with the reason and the connection is closed (at the
///   latest [`FLUSH_TIMEOUT`] later, whether the client reads or not); it never reaches the
///   runner.
/// - Dropping the transport closes the client, stops the threads and removes the socket
///   (only while the path still holds it: see the crate docs).
pub struct WireTransport {
    file: SocketFile,
    shared: Arc<Shared>,
    /// The bound socket until the first enumeration starts the accept thread.
    listener: Option<UnixListener>,
    acceptor: Option<Acceptor>,
}

impl fmt::Debug for WireTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireTransport")
            .field("path", &self.file.path())
            .field("accepting", &self.acceptor.is_some())
            .field("attached", &self.shared.slot().client.is_some())
            .finish_non_exhaustive()
    }
}

impl WireTransport {
    /// Bind the wire socket at `path` (placement rules in the crate docs). Inputs go to the
    /// runner through `runner` (`lk_run::Runner::sender`).
    pub fn bind(path: &Path, runner: Sender<Command>) -> Result<WireTransport, WireError> {
        Self::bind_with_observer(path, runner, None)
    }

    /// [`WireTransport::bind`] with an observer for connections, enumerations and frames.
    pub fn bind_with_observer(
        path: &Path,
        runner: Sender<Command>,
        observer: Option<Observer>,
    ) -> Result<WireTransport, WireError> {
        let (listener, file) = socket::bind_private(path)?;
        let shared = Shared { runner, observer, slot: Mutex::new(Slot::default()) };
        Ok(WireTransport { file, shared: Arc::new(shared), listener: Some(listener), acceptor: None })
    }

    /// The socket path.
    pub fn path(&self) -> &Path {
        self.file.path()
    }

    fn start_accepting(&mut self) {
        let Some(listener) = self.listener.take() else {
            return;
        };
        let shared = Arc::clone(&self.shared);
        let closing = Arc::new(AtomicBool::new(false));
        let admit = move |stream| shared.admit(stream);
        match Acceptor::spawn(self.file.clone(), listener, "lk-wire-accept", closing, admit) {
            Ok(acceptor) => self.acceptor = Some(acceptor),
            Err(error) => self.shared.notify(&WireEvent::Failed(error.to_string())),
        }
    }
}

impl Transport for WireTransport {
    /// Store the identity, send IDENTITY to a connected client, and start accepting at the
    /// first call. No `PowerCycle` here: a re-enumeration is the device's own reboot.
    fn enumerate(&mut self, identity: &UsbIdentity) {
        let identity = Identity::from_usb(identity);
        let event = WireEvent::Enumerated { product_id: identity.product_id, interfaces: identity.interfaces };
        match Frame::Identity(identity).encode() {
            Ok(bytes) => {
                let mut slot = self.shared.slot();
                slot.identity = bytes.clone();
                self.shared.notify(&event);
                self.shared.queue(&mut slot, bytes);
            }
            Err(error) => {
                // Without an IDENTITY there is nothing to present; clients wait in the backlog.
                self.shared.notify(&WireEvent::Failed(format!("identity cannot be encoded: {error}")));
                return;
            }
        }
        self.start_accepting();
    }

    /// Queue the output's frame for the client; dropped when no client is connected.
    fn deliver(&mut self, output: Output) {
        // `Reenumerate` has no frame (the runner enumerates instead), and the engine's
        // outputs always fit a frame.
        let Some(bytes) = Frame::from_output(output).and_then(|frame| frame.encode().ok()) else {
            return;
        };
        let mut slot = self.shared.slot();
        self.shared.queue(&mut slot, bytes);
    }

    fn attached(&self) -> Option<bool> {
        Some(self.shared.slot().client.is_some())
    }
}

impl Drop for WireTransport {
    fn drop(&mut self) {
        match self.acceptor.take() {
            Some(mut acceptor) => acceptor.stop(),
            None => {
                self.listener = None;
                self.file.remove();
            }
        }
        let mut slot = self.shared.slot();
        self.shared.close(&mut slot, Close::Now);
        for flushing in slot.flushing.drain(..) {
            let _ = flushing.stream.shutdown(Shutdown::Both);
        }
    }
}

/// State shared by the runner thread and the transport's threads.
struct Shared {
    runner: Sender<Command>,
    observer: Option<Observer>,
    slot: Mutex<Slot>,
}

#[derive(Default)]
struct Slot {
    /// The encoded IDENTITY frame of the last enumeration.
    identity: Vec<u8>,
    client: Option<Connection>,
    /// Clients closed after a malformed frame whose writers still flush the ERROR.
    flushing: Vec<Flushing>,
    next_id: u64,
}

impl Slot {
    fn is_current(&self, id: u64) -> bool {
        self.client.as_ref().is_some_and(|client| client.id == id)
    }
}

/// The connected client.
struct Connection {
    id: u64,
    /// Frames for the writer thread, in order.
    frames: SyncSender<Vec<u8>>,
    /// A handle to shut the socket down from any thread.
    stream: UnixStream,
}

/// A client out of the slot whose writer still writes what is queued.
struct Flushing {
    id: u64,
    /// When the writer must give up.
    deadline: Instant,
    /// A handle to shut the socket down when the transport is dropped.
    stream: UnixStream,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Close {
    /// Shut the socket down at once; queued frames are lost.
    Now,
    /// Let the writer write what is queued (an ERROR) within [`FLUSH_TIMEOUT`], then shut
    /// down.
    AfterFlush,
}

impl Shared {
    fn slot(&self) -> MutexGuard<'_, Slot> {
        // A panic elsewhere cannot leave the slot inconsistent: every update is one
        // assignment.
        self.slot.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn notify(&self, event: &WireEvent) {
        if let Some(observer) = &self.observer {
            observer(event);
        }
    }

    /// A new connection, on the accept thread.
    fn admit(self: &Arc<Self>, stream: UnixStream) {
        let mut slot = self.slot();
        if slot.client.is_some() {
            drop(slot);
            self.notify(&WireEvent::Refused);
            refuse(stream, "busy");
            return;
        }
        let id = slot.next_id;
        slot.next_id += 1;
        let (frames, queue) = mpsc::sync_channel(WRITE_QUEUE_FRAMES);
        if let Err(error) = self.spawn_threads(id, &stream, queue) {
            let _ = stream.shutdown(Shutdown::Both);
            self.notify(&WireEvent::Failed(format!("cannot serve a client: {error}")));
            return;
        }
        slot.client = Some(Connection { id, frames, stream });
        self.notify(&WireEvent::Connected);
        // IDENTITY is the first frame of every connection.
        let identity = slot.identity.clone();
        self.queue(&mut slot, identity);
        // Plugging in powers the key. Sent with the slot locked, so it reaches the runner
        // before any input of this client.
        if self.runner.send(Command::Input(HostInput::Bus(BusEvent::PowerCycle))).is_err() {
            self.close(&mut slot, Close::Now);
        }
    }

    fn spawn_threads(self: &Arc<Self>, id: u64, stream: &UnixStream, queue: Receiver<Vec<u8>>) -> io::Result<()> {
        let writer = stream.try_clone()?;
        // macOS refuses to set a timeout once the client has closed the connection; writes
        // then fail at once and cannot block.
        let _ = writer.set_write_timeout(Some(WRITE_POLL));
        let reader = stream.try_clone()?;
        let shared = Arc::clone(self);
        thread::Builder::new().name("lk-wire-write".into()).spawn(move || shared.write_loop(id, writer, queue))?;
        let shared = Arc::clone(self);
        thread::Builder::new().name("lk-wire-read".into()).spawn(move || shared.read_loop(id, reader))?;
        Ok(())
    }

    /// Queue a frame for the current client. A client whose queue is full or whose writer
    /// is gone is dropped (`docs/PROGRAM.md`: a write error drops that client).
    fn queue(&self, slot: &mut Slot, bytes: Vec<u8>) {
        let Some(client) = &slot.client else {
            return;
        };
        let frame_type = bytes.get(4).copied().unwrap_or_default();
        let size = bytes.len().saturating_sub(HEADER_LEN);
        match client.frames.try_send(bytes) {
            Ok(()) => self.notify(&WireEvent::Sent { frame_type, size }),
            Err(_) => self.close(slot, Close::Now),
        }
    }

    /// Remove the current client from the slot.
    fn close(&self, slot: &mut Slot, how: Close) {
        let Some(client) = slot.client.take() else {
            return;
        };
        match how {
            Close::Now => {
                let _ = client.stream.shutdown(Shutdown::Both);
            }
            Close::AfterFlush => {
                let deadline = Instant::now() + FLUSH_TIMEOUT;
                slot.flushing.push(Flushing { id: client.id, deadline, stream: client.stream });
            }
        }
        // Dropping `frames` ends the writer once it has written what is queued.
        self.notify(&WireEvent::Disconnected);
    }

    /// Drop client `id` if it is still the current one.
    fn drop_client(&self, id: u64) {
        let mut slot = self.slot();
        if slot.is_current(id) {
            self.close(&mut slot, Close::Now);
        }
    }

    /// The writer thread of client `id`: writes queued frames in order until the client
    /// leaves the slot and the queue is written, the socket fails, or a flush runs out of
    /// time; then it shuts the socket down.
    fn write_loop(&self, id: u64, mut stream: UnixStream, queue: Receiver<Vec<u8>>) {
        for bytes in queue {
            if !self.write_frame(id, &mut stream, &bytes) {
                break;
            }
        }
        let mut slot = self.slot();
        if slot.is_current(id) {
            // The socket failed under the current client: a write error drops it.
            self.close(&mut slot, Close::Now);
        }
        slot.flushing.retain(|flushing| flushing.id != id);
        drop(slot);
        let _ = stream.shutdown(Shutdown::Both);
    }

    /// Write one frame of client `id`. False when the socket failed or the client's flush
    /// ran out of time. Each write returns within [`WRITE_POLL`] when the client does not
    /// read, possibly having written part of the frame.
    fn write_frame(&self, id: u64, stream: &mut UnixStream, bytes: &[u8]) -> bool {
        let mut written = 0;
        while written < bytes.len() {
            match stream.write(&bytes[written..]) {
                Ok(0) => return false,
                Ok(count) => written += count,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return false,
            }
            if self.must_stop_writing(id) {
                return false;
            }
        }
        true
    }

    /// Whether the writer of client `id` must stop: the client left the slot and its flush
    /// is past its deadline, or it was shut down without a flush.
    fn must_stop_writing(&self, id: u64) -> bool {
        let slot = self.slot();
        if slot.is_current(id) {
            return false;
        }
        match slot.flushing.iter().find(|flushing| flushing.id == id) {
            Some(flushing) => Instant::now() >= flushing.deadline,
            None => true,
        }
    }

    /// The reader thread of client `id`: forwards host frames to the runner, at its pace,
    /// until the client disconnects or sends a malformed frame.
    fn read_loop(&self, id: u64, mut stream: UnixStream) {
        let mut inbox = Inbox::default();
        let mut window = Window::default();
        loop {
            match inbox.next(Origin::Host) {
                Ok(Some((frame, size))) => {
                    if !self.forward(id, frame, size) {
                        return;
                    }
                    if !self.pace(&mut window, size) {
                        break;
                    }
                    continue;
                }
                Ok(None) => {}
                Err(error) => {
                    self.refuse_frame(id, &error);
                    return;
                }
            }
            match inbox.fill(&mut stream) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        self.drop_client(id);
    }

    /// Send a host frame of client `id` to the runner. False when the client is no longer
    /// current or the runner is gone.
    fn forward(&self, id: u64, frame: Frame, size: usize) -> bool {
        let mut slot = self.slot();
        if !slot.is_current(id) {
            return false;
        }
        let frame_type = frame.frame_type();
        let Some(input) = frame.into_input() else {
            // `Origin::Host` decodes host frames only.
            drop(slot);
            self.refuse_frame(id, &FrameError::UnknownType(frame_type));
            return false;
        };
        self.notify(&WireEvent::Received { frame_type, size });
        if self.runner.send(Command::Input(input)).is_err() {
            self.close(&mut slot, Close::Now);
            return false;
        }
        true
    }

    /// Count a forwarded input into the window. When the window is full, wait for the
    /// runner to answer the previous window's marker, then send this window's (see the
    /// module docs). Called without the slot locked. False when the runner is gone.
    fn pace(&self, window: &mut Window, size: usize) -> bool {
        window.frames += 1;
        window.bytes = window.bytes.saturating_add(size);
        if window.frames < INPUT_WINDOW_FRAMES && window.bytes < INPUT_WINDOW_BYTES {
            return true;
        }
        // A runner that stops drops the marker unanswered, which ends the wait.
        if let Some(answer) = window.marker.take()
            && answer.recv().is_err()
        {
            return false;
        }
        let (reply, answer) = mpsc::channel();
        if self.runner.send(Command::Status(reply)).is_err() {
            return false;
        }
        *window = Window { frames: 0, bytes: 0, marker: Some(answer) };
        true
    }

    /// Answer a malformed frame of client `id` with ERROR and close the connection.
    fn refuse_frame(&self, id: u64, error: &FrameError) {
        let mut slot = self.slot();
        if !slot.is_current(id) {
            return;
        }
        let reason = error.to_string();
        self.notify(&WireEvent::Malformed(reason.clone()));
        if let Ok(bytes) = Frame::Error(reason).encode() {
            self.queue(&mut slot, bytes);
        }
        self.close(&mut slot, Close::AfterFlush);
    }
}

/// A reader's inputs since its last marker, and the marker still to be answered.
#[derive(Debug, Default)]
struct Window {
    frames: usize,
    bytes: usize,
    /// The answer to the last `Command::Status` marker, until the reader has waited for it.
    marker: Option<Receiver<Status>>,
}

/// Send ERROR with `reason` to a connection that is not admitted, and close it.
fn refuse(mut stream: UnixStream, reason: &str) {
    let _ = stream.set_write_timeout(Some(REFUSE_TIMEOUT));
    if let Ok(bytes) = Frame::Error(reason.to_owned()).encode() {
        let _ = stream.write_all(&bytes);
    }
    let _ = stream.shutdown(Shutdown::Both);
}
