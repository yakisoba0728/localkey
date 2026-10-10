//! Private Unix-socket transport and control socket (`docs/PROGRAM.md` "lk-wire").
//!
//! - [`Frame`], [`Identity`], [`decode`]: the frame format, the IDENTITY payload and the
//!   mapping between frames and the engine's inputs and outputs. Pure; the rest of the
//!   crate is built on them.
//! - [`WireTransport`]: the bus transport. One client at a time is the USB host the key is
//!   plugged into; it implements [`lk_run::Transport`] and feeds the runner through its
//!   `Sender<Command>`.
//! - [`Client`]: the other end, for tests and bridges.
//! - [`ControlServer`]: the user side (touch, power cycle, status, presence), one line-based
//!   command per connection.
//!
//! Both sockets follow the same placement rules (`docs/PROGRAM.md` "Socket placement"): the
//! parent directory must exist and grant no group or other permission, an existing socket
//! at the path is replaced, anything else there is an error and is left alone, the socket
//! file is mode 0600, and it is removed when its server is dropped.
//!
//! # As built
//!
//! Choices where `docs/PROGRAM.md` leaves room:
//!
//! - Sockets: a server remembers the device and inode of the socket file it bound. It
//!   removes the file at its path, and wakes its accept thread by connecting to it, only
//!   while the path still holds that file. When another server has taken the path over
//!   (the placement rules replace a socket, so two servers given the same path do this),
//!   dropping the first leaves the second's socket and clients alone, and the first's
//!   accept thread stays parked in `accept` for the rest of the process (with what it
//!   holds, such as a clone of the runner's `Sender`).
//! - Frames:
//!   - Each side accepts only the other side's types; a device type sent by the host is an
//!     unknown type.
//!   - The length and the type's payload size are checked as soon as the header is
//!     there, before the payload is buffered.
//!   - CCID_BULK_IN, CCID_INTERRUPT and ERROR take any size up to the cap.
//!   - TOUCH, BUS and PRESENCE values outside the table are malformed.
//!   - IDENTITY is parsed strictly: an 18-byte device descriptor, only the three interface
//!     bits, UTF-8 strings, no trailing bytes.
//! - The wire transport:
//!   - It accepts from the first `enumerate` on; a client that connects earlier waits in
//!     the listen backlog. So IDENTITY is always the first frame, and the plug-in
//!     `PowerCycle` never reaches the runner before the transport is attached.
//!   - Frames before a malformed frame are delivered; the rest of the stream is not read.
//!   - A writer thread per client writes from a queue of [`WRITE_QUEUE_FRAMES`]. A full
//!     queue (a client that stopped reading) or a write error drops the client, so
//!     `deliver` never blocks the runner.
//!   - A client closed after a malformed frame leaves the slot at once, so the next client
//!     can connect. Its writer then has one second in total to write what is still queued
//!     and the ERROR; after that the socket is shut down whether the client reads or not.
//!     Dropping the transport shuts such clients down at once.
//!   - A disconnect counts once the reader thread has seen it. A client that reconnects
//!     before that is refused with `busy` and retries.
//!   - The reader paces itself to the runner, whose channel is unbounded: after every
//!     window of inputs ([`INPUT_WINDOW_FRAMES`] frames or [`INPUT_WINDOW_BYTES`] of
//!     payload) it sends `Command::Status` as a marker, and it waits for the answer to the
//!     previous marker before it sends the next. At most two windows of a client's inputs
//!     are on their way to the runner; the rest waits in the socket and holds up the
//!     client's writes, as a busy USB device holds up the host with NAKs. A flooding
//!     client cannot grow the daemon, and once it disconnects the runner has at most two
//!     windows of its inputs left to handle. The runner must answer `Command::Status`
//!     (`lk_run::Runner` does, and drops an unanswered marker when it stops).
//!   - The transport cannot tell when the runner has handled a new client's `PowerCycle`.
//!     An output the runner produces just before it (for example a keepalive for the
//!     previous host's request) can reach the new client after IDENTITY.
//!   - It holds a clone of the runner's `Sender`. Once attached, the runner stops on
//!     `Command::Shutdown`, not when the other senders are dropped.
//!   - [`WireEvent`]s through an [`Observer`] report connections, enumerations, and frame
//!     types and sizes for the daemon's log (`docs/PROGRAM.md` "localkeyd").
//! - [`Client::connect`] waits for IDENTITY (at most [`CONNECT_TIMEOUT`]); ERROR instead is
//!   [`WireError::Refused`]. A timeout too long for `Instant` (such as `Duration::MAX`)
//!   given to [`Client::connect_timeout`] or [`Client::recv`] means no deadline.
//! - The control socket ([`status_lines`] documents the `status` format):
//!   - A request line is at most 256 bytes and may also end when the client closes its
//!     side (or only its writing side). It must arrive within 10 seconds in total.
//!   - Each connection is served on its own thread, with no cap: only the owner can
//!     connect (a 0600 socket in a 0700 directory), a request that does not arrive in time
//!     is answered `error no request`, and a connection whose thread cannot start is
//!     closed.
//!   - Error reasons: `empty request`, `unknown command: <words>`, `request too long`,
//!     `request is not UTF-8`, `no request`, `runner stopped`, `runner did not answer`.
//!   - `watch` writes a line only when the state differs from the last line written: the
//!     runner may repeat an unchanged state to its watchers (`lk_run`'s "As built" notes).
//!   - `watch` checks once a second whether its client is gone; closing the server ends
//!     open `watch` streams within that second. A client that shut down only its writing
//!     side is not gone: the stream goes on until the client closes the connection, which a
//!     zero-length write then reports (on a system where it cannot, the stream ends when
//!     the next presence line cannot be written).

#![cfg(unix)]

mod client;
mod codec;
mod control;
mod inbox;
mod socket;
mod transport;

use std::fmt;
use std::io;
use std::path::PathBuf;

pub use client::{CONNECT_TIMEOUT, Client};
pub use codec::{Frame, FrameError, HEADER_LEN, Identity, MAX_LENGTH, MAX_PAYLOAD, Origin, decode, frame_type};
pub use control::{ControlServer, status_lines};
pub use transport::{INPUT_WINDOW_BYTES, INPUT_WINDOW_FRAMES, Observer, WRITE_QUEUE_FRAMES, WireEvent, WireTransport};

/// Why a socket could not be set up or a connection failed. Messages name paths and
/// frame types, never payload bytes.
#[derive(Debug)]
pub enum WireError {
    /// A filesystem operation on this path, or binding or connecting to it, failed.
    Io { path: PathBuf, source: io::Error },
    /// The socket's parent directory grants group or other permissions.
    Permissions { path: PathBuf, mode: u32 },
    /// Something other than a socket exists at the socket path; it was left alone.
    NotASocket { path: PathBuf },
    /// Reading from or writing to the connection failed.
    Socket(io::Error),
    /// The peer sent bytes that are not a frame (or a frame cannot be encoded).
    Frame(FrameError),
    /// The server sent ERROR with this reason (for example `busy`) and closed.
    Refused(String),
    /// The peer closed the connection.
    Closed,
    /// No IDENTITY arrived in time after connecting.
    Timeout,
    /// The server's first frame was not IDENTITY.
    Protocol(String),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Io { path, source } => write!(f, "{}: {source}", path.display()),
            WireError::Permissions { path, mode } => {
                write!(f, "{}: mode {mode:03o} grants group or other access; use 0700", path.display())
            }
            WireError::NotASocket { path } => write!(f, "{}: exists and is not a socket", path.display()),
            WireError::Socket(source) => write!(f, "connection: {source}"),
            WireError::Frame(error) => write!(f, "malformed frame: {error}"),
            WireError::Refused(reason) => write!(f, "server refused the connection: {reason}"),
            WireError::Closed => f.write_str("connection closed"),
            WireError::Timeout => f.write_str("no IDENTITY from the server in time"),
            WireError::Protocol(reason) => write!(f, "protocol: {reason}"),
        }
    }
}

impl std::error::Error for WireError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            WireError::Io { source, .. } | WireError::Socket(source) => Some(source),
            WireError::Frame(error) => Some(error),
            _ => None,
        }
    }
}

impl From<FrameError> for WireError {
    fn from(error: FrameError) -> Self {
        WireError::Frame(error)
    }
}
