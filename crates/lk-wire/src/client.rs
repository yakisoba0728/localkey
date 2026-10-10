//! The client end of the wire socket, for tests and bridges (`docs/PROGRAM.md` "lk-wire",
//! "Client library").

use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use lk_run::HostInput;

use crate::WireError;
use crate::codec::{Frame, Identity, Origin};
use crate::inbox::Inbox;

/// How long [`Client::connect`] waits for the server's IDENTITY.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// A connection to a wire socket: the USB host side of the device.
///
/// The server sends IDENTITY first on every connection, so [`Client::connect`] waits for it
/// and [`Client::identity`] is always available; it follows every later IDENTITY that
/// [`Client::recv`] returns (a re-enumeration).
#[derive(Debug)]
pub struct Client {
    stream: UnixStream,
    inbox: Inbox,
    identity: Identity,
}

impl Client {
    /// Connect and wait up to [`CONNECT_TIMEOUT`] for IDENTITY. A refused connection (ERROR
    /// `busy`) is [`WireError::Refused`].
    pub fn connect(path: &Path) -> Result<Client, WireError> {
        Self::connect_timeout(path, CONNECT_TIMEOUT)
    }

    /// [`Client::connect`] with another wait for IDENTITY. A wait too long to represent
    /// (such as `Duration::MAX`) has no deadline.
    pub fn connect_timeout(path: &Path, timeout: Duration) -> Result<Client, WireError> {
        let mut stream = UnixStream::connect(path).map_err(|source| WireError::Io { path: path.to_owned(), source })?;
        let mut inbox = Inbox::default();
        match read_frame(&mut stream, &mut inbox, timeout)? {
            Some(Frame::Identity(identity)) => Ok(Client { stream, inbox, identity }),
            Some(Frame::Error(reason)) => Err(WireError::Refused(reason)),
            Some(frame) => Err(WireError::Protocol(format!(
                "expected IDENTITY first, got frame type 0x{:02x}",
                frame.frame_type()
            ))),
            None => Err(WireError::Timeout),
        }
    }

    /// The identity of the last enumeration seen.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Send one host input. An input the frame format cannot carry (a CCID message under 10
    /// bytes or over the cap) is [`WireError::Frame`] and nothing is sent.
    pub fn send(&mut self, input: &HostInput) -> Result<(), WireError> {
        let bytes = Frame::from_input(input).encode()?;
        self.stream
            .write_all(&bytes)
            .map_err(|error| if closed(&error) { WireError::Closed } else { WireError::Socket(error) })
    }

    /// The next frame from the server, waiting at most `timeout`; `Ok(None)` when none
    /// arrived in time. A wait too long to represent (such as `Duration::MAX`) waits until
    /// a frame arrives or the connection closes. ERROR is returned as [`Frame::Error`]; the
    /// server closes after it, and the next call is [`WireError::Closed`].
    pub fn recv(&mut self, timeout: Duration) -> Result<Option<Frame>, WireError> {
        let frame = read_frame(&mut self.stream, &mut self.inbox, timeout)?;
        if let Some(Frame::Identity(identity)) = &frame {
            self.identity = identity.clone();
        }
        Ok(frame)
    }
}

/// The next device frame from `stream`, waiting at most `timeout` (without a deadline when
/// `Instant` cannot represent it).
fn read_frame(stream: &mut UnixStream, inbox: &mut Inbox, timeout: Duration) -> Result<Option<Frame>, WireError> {
    let deadline = Instant::now().checked_add(timeout);
    loop {
        if let Some((frame, _)) = inbox.next(Origin::Device)? {
            return Ok(Some(frame));
        }
        // A zero read timeout is an error in std, so an expired deadline returns first.
        let left = deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
        if left.is_some_and(|left| left.is_zero()) {
            return Ok(None);
        }
        // macOS refuses to set a timeout once the server has closed the connection; reads
        // then return what it sent and the end of stream without waiting.
        let _ = stream.set_read_timeout(left);
        match inbox.fill(stream) {
            Ok(0) => return Err(WireError::Closed),
            Err(error) if closed(&error) => return Err(WireError::Closed),
            Ok(_) => {}
            // A read that times out reports `WouldBlock` on Unix; the loop then checks the
            // deadline, so a timer that fires a little early does not cut the wait short.
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(WireError::Socket(error)),
        }
    }
}

/// Whether an I/O error means the server closed the connection.
fn closed(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset)
}
