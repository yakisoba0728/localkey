//! The control socket (`docs/PROGRAM.md` "lk-wire", "Control socket"): the user side of the
//! key. One command per connection:
//! `tap pending` checks expiry and presses only a currently waiting request on the runner.
//!
//! - request: one line;
//! - reply: zero or more lines, then `ok` or `error <reason>`, then close;
//! - `watch` instead streams `presence waiting` / `presence idle` lines until the client
//!   disconnects, with no `ok`;
//! - `shutdown` replies `ok` and hands the open connection to the server's owner as a
//!   [`ShutdownRequest`] (`docs/PROGRAM.md` "Clean shutdown from the control socket"); the
//!   connection stays open until the owner has shut down, then carries one last line,
//!   `stopped` ([`ShutdownRequest::stopped`]) or `error <reason>`
//!   ([`ShutdownRequest::failed`]), and closes, so the client can wait for the shutdown to
//!   finish and learn how it ended.

use std::fmt;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

use lk_core::{Record, UsbInterfaces};
use lk_device::{BusEvent, TouchEdge};
use lk_run::{Command, HostInput, Status, TAP_LONG_MS, TAP_SHORT_MS};

use crate::WireError;
use crate::socket::{self, Acceptor};

/// The longest request line, newline excluded.
const MAX_REQUEST: usize = 256;
/// How long a client may take, in total, to send its request line.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// How long writing a reply may block on a client that does not read.
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);
/// How long `status` waits for the runner's answer.
const STATUS_TIMEOUT: Duration = Duration::from_secs(5);
/// How often a `watch` without presence changes checks whether its client is gone.
const WATCH_POLL: Duration = Duration::from_secs(1);
/// The read timeout of that check: it only looks for an end of stream already there.
const PROBE_TIMEOUT: Duration = Duration::from_millis(1);

const RUNNER_STOPPED: &str = "error runner stopped\n";
/// The reply to `shutdown` on a server bound without a [`ShutdownHook`].
const NO_SHUTDOWN: &str = "error shutdown not available\n";

/// What a [`ControlServer`] bound with [`ControlServer::bind_with_shutdown`] calls when a
/// client sends `shutdown`. It runs on that connection's thread after `ok` was written, so
/// it must not wait for the shutdown it starts (the owner usually sends the request to
/// the thread that shuts down, and the server is closed during the shutdown).
pub type ShutdownHook = Arc<dyn Fn(ShutdownRequest) + Send + Sync>;

/// A `shutdown` request that has been answered `ok` (`docs/PROGRAM.md` "Clean shutdown
/// from the control socket").
///
/// It holds the client's connection open: the client reads `ok`, then waits for the end of
/// the stream. An owner that keeps it until its shutdown is done lets the client
/// (`localkeyd ctl ... shutdown`, a supervisor's stop command) return only once the daemon
/// has stopped. The owner then says how the shutdown ended, in one last line before the
/// close: [`ShutdownRequest::stopped`] (`stopped`, a clean stop) or
/// [`ShutdownRequest::failed`] (`error <reason>`). `ok` alone only says that the request
/// was accepted, and a daemon can still fail after it (a startup that fails before the
/// daemon could act on the request, a panic in the device found while shutting down).
/// Dropping it (or [`ShutdownRequest::finish`]) closes the connection without that line,
/// and so does the process's exit: the client cannot tell a clean stop then.
pub struct ShutdownRequest {
    stream: UnixStream,
}

/// The last line of a clean shutdown ([`ShutdownRequest::stopped`]).
const STOPPED: &str = "stopped\n";

impl ShutdownRequest {
    /// Write `stopped` and close the connection: the owner has shut down cleanly.
    pub fn stopped(self) {
        self.last_line(STOPPED);
    }

    /// Write `error <reason>` and close the connection: the owner failed after accepting
    /// the request. Control characters in `reason` become spaces, so it stays one line.
    pub fn failed(self, reason: &str) {
        let reason: String = reason.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
        self.last_line(&format!("error {reason}\n"));
    }

    /// Close the connection without a last line: the client sees the end of the reply
    /// after `ok` and cannot tell how the shutdown ended. The same as dropping it.
    pub fn finish(self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }

    /// Write `line` (bounded by the connection's write timeout; a client that is gone
    /// makes it fail, which changes nothing), then close.
    fn last_line(self, line: &str) {
        let _ = (&self.stream).write_all(line.as_bytes());
        self.finish();
    }
}

impl fmt::Debug for ShutdownRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShutdownRequest").finish_non_exhaustive()
    }
}

/// The control socket server. Each connection is served on its own thread; dropping the
/// server (or [`ControlServer::close`]) stops accepting, ends running `watch` streams within
/// a second and removes the socket.
#[derive(Debug)]
pub struct ControlServer {
    path: PathBuf,
    acceptor: Acceptor,
}

impl ControlServer {
    /// Bind the control socket at `path` (the same placement rules as the wire socket).
    /// Commands go to the runner through `runner`. Nobody is told about a `shutdown`
    /// request, so it is answered `error shutdown not available`.
    pub fn bind(path: &Path, runner: Sender<Command>) -> Result<ControlServer, WireError> {
        ControlServer::start(path, runner, None)
    }

    /// [`ControlServer::bind`], and a `shutdown` request is answered `ok` and then handed
    /// to `shutdown` as a [`ShutdownRequest`] (`docs/PROGRAM.md` "Clean shutdown from the
    /// control socket").
    pub fn bind_with_shutdown(
        path: &Path,
        runner: Sender<Command>,
        shutdown: ShutdownHook,
    ) -> Result<ControlServer, WireError> {
        ControlServer::start(path, runner, Some(shutdown))
    }

    fn start(path: &Path, runner: Sender<Command>, shutdown: Option<ShutdownHook>) -> Result<ControlServer, WireError> {
        let (listener, file) = socket::bind_private(path)?;
        let closing = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&closing);
        let acceptor = Acceptor::spawn(file, listener, "lk-control-accept", closing, move |stream| {
            let runner = runner.clone();
            let shutdown = shutdown.clone();
            let closing = Arc::clone(&flag);
            // A connection whose thread cannot start is closed by dropping it.
            let _ = thread::Builder::new()
                .name("lk-control".into())
                .spawn(move || serve(stream, &runner, shutdown.as_ref(), &closing));
        })?;
        Ok(ControlServer { path: path.to_owned(), acceptor })
    }

    /// The socket path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Stop the server and remove the socket (the same as dropping it).
    pub fn close(mut self) {
        self.acceptor.stop();
    }
}

/// A control request line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Request {
    /// `tap` ([`TAP_SHORT_MS`]) or `tap long` ([`TAP_LONG_MS`]).
    Tap { long: bool },
    /// `tap pending`: a short tap only while a presence request still waits.
    TapPending,
    /// `down`: press the sensor.
    Down,
    /// `up`: release it.
    Up,
    /// `power-cycle`: unplug and plug in again.
    PowerCycle,
    /// `status`
    Status,
    /// `watch`
    Watch,
    /// `shutdown`: stop the daemon ([`ShutdownRequest`]).
    Shutdown,
}

impl Request {
    /// Parse one request line; surrounding whitespace and a trailing `\r` are ignored.
    fn parse(line: &str) -> Result<Request, String> {
        let words: Vec<&str> = line.split_whitespace().collect();
        let request = match words.as_slice() {
            ["tap"] => Request::Tap { long: false },
            ["tap", "long"] => Request::Tap { long: true },
            ["tap", "pending"] => Request::TapPending,
            ["down"] => Request::Down,
            ["up"] => Request::Up,
            ["power-cycle"] => Request::PowerCycle,
            ["status"] => Request::Status,
            ["watch"] => Request::Watch,
            ["shutdown"] => Request::Shutdown,
            [] => return Err("empty request".into()),
            _ => return Err(format!("unknown command: {}", words.join(" "))),
        };
        Ok(request)
    }
}

/// Serve one control connection.
fn serve(stream: UnixStream, runner: &Sender<Command>, shutdown: Option<&ShutdownHook>, closing: &AtomicBool) {
    let _ = stream.set_write_timeout(Some(REPLY_TIMEOUT));
    let reply = match read_request(&stream, REQUEST_TIMEOUT).and_then(|line| Request::parse(&line)) {
        Ok(Request::Watch) => return watch(&stream, runner, closing),
        Ok(Request::Shutdown) => return request_shutdown(stream, shutdown),
        Ok(Request::Status) => status(runner),
        Ok(Request::Tap { long }) => {
            send(runner, Command::Tap { hold_ms: if long { TAP_LONG_MS } else { TAP_SHORT_MS } })
        }
        Ok(Request::TapPending) => {
            let (reply, answer) = mpsc::channel();
            if runner.send(Command::TapPending(reply)).is_err() {
                RUNNER_STOPPED.into()
            } else {
                match answer.recv_timeout(STATUS_TIMEOUT) {
                    Ok(true) => "ok\n".into(),
                    Ok(false) => "error no pending presence or sensor unavailable\n".into(),
                    Err(_) => "error runner did not answer\n".into(),
                }
            }
        }
        Ok(Request::Down) => send(runner, Command::Input(HostInput::Touch(TouchEdge::Down))),
        Ok(Request::Up) => send(runner, Command::Input(HostInput::Touch(TouchEdge::Up))),
        Ok(Request::PowerCycle) => send(runner, Command::Input(HostInput::Bus(BusEvent::PowerCycle))),
        Err(reason) => format!("error {reason}\n"),
    };
    let _ = (&stream).write_all(reply.as_bytes());
    discard_pending(&stream);
}

/// `shutdown`: reply `ok`, then hand the connection to the owner, so the reply is out
/// before anything is shut down (`docs/PROGRAM.md`: "replies `ok`, then the daemon ...").
/// The request counts once its line has arrived: the hook is called even when the client
/// is gone before it could read `ok`. Without a hook the request is refused.
fn request_shutdown(stream: UnixStream, shutdown: Option<&ShutdownHook>) {
    let reply = if shutdown.is_some() { "ok\n" } else { NO_SHUTDOWN };
    let _ = (&stream).write_all(reply.as_bytes());
    discard_pending(&stream);
    if let Some(hook) = shutdown {
        // `discard_pending` left the socket non-blocking; the last line is written blocking,
        // within the write timeout `serve` set.
        let _ = stream.set_nonblocking(false);
        hook(ShutdownRequest { stream });
    }
}

/// Most bytes [`discard_pending`] reads.
const DISCARD_LIMIT: usize = 64 * 1024;

/// Read and drop the input that is already waiting, at most [`DISCARD_LIMIT`] bytes,
/// without waiting for more. Linux resets a Unix stream socket that is closed with unread
/// input (`unix_release_sock` in `net/unix/af_unix.c` sets `ECONNRESET` on the peer), so a
/// client that sent more than its request line (a line over [`MAX_REQUEST`], bytes after
/// the newline) would read its reply and then an error instead of the end of stream.
fn discard_pending(stream: &UnixStream) {
    if stream.set_nonblocking(true).is_err() {
        return;
    }
    let mut sink = [0; 1024];
    let mut discarded = 0;
    while discarded < DISCARD_LIMIT {
        match (&*stream).read(&mut sink) {
            Ok(0) => break,
            Ok(read) => discarded += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
}

/// The request line, without its newline, if it arrives within `limit` in total (each read
/// waits only for what is left of it, so a client that trickles bytes cannot hold the
/// connection longer). A client may also end the line by closing its side. Bytes after the
/// newline are ignored.
fn read_request(stream: &UnixStream, limit: Duration) -> Result<String, String> {
    const NO_REQUEST: &str = "no request";
    let deadline = Instant::now() + limit;
    let mut line = Vec::new();
    let mut chunk = [0; MAX_REQUEST + 1];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(NO_REQUEST.into());
        }
        // macOS refuses to set a timeout once the client has closed the connection; reads
        // then return what it sent and the end of stream without waiting.
        let _ = stream.set_read_timeout(Some(left));
        // Never more than one byte past the longest line, so the line stays bounded.
        let wanted = MAX_REQUEST + 1 - line.len();
        let read = match (&*stream).read(&mut chunk[..wanted]) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(NO_REQUEST.into()),
        };
        line.extend_from_slice(&chunk[..read]);
        if let Some(end) = line.iter().position(|&byte| byte == b'\n') {
            line.truncate(end);
            break;
        }
        if line.len() > MAX_REQUEST {
            return Err("request too long".into());
        }
    }
    String::from_utf8(line).map_err(|_| "request is not UTF-8".into())
}

fn send(runner: &Sender<Command>, command: Command) -> String {
    match runner.send(command) {
        Ok(()) => "ok\n".into(),
        Err(_) => RUNNER_STOPPED.into(),
    }
}

fn status(runner: &Sender<Command>) -> String {
    let (reply, answer) = mpsc::channel();
    if runner.send(Command::Status(reply)).is_err() {
        return RUNNER_STOPPED.into();
    }
    match answer.recv_timeout(STATUS_TIMEOUT) {
        Ok(status) => format!("{}ok\n", status_lines(&status)),
        Err(RecvTimeoutError::Timeout) => "error runner did not answer\n".into(),
        Err(RecvTimeoutError::Disconnected) => RUNNER_STOPPED.into(),
    }
}

/// Stream presence changes until the client disconnects, the runner stops or the server
/// closes. The runner sends the current state at once, then every change; it may also
/// repeat the unchanged state (`lk_run` probes its watchers that way), and a repeat is not
/// a change, so it writes no line (`docs/PROGRAM.md`: lines "as the state changes").
fn watch(stream: &UnixStream, runner: &Sender<Command>, closing: &AtomicBool) {
    let (watcher, changes) = mpsc::channel();
    if runner.send(Command::Watch(watcher)).is_err() {
        let _ = (&*stream).write_all(RUNNER_STOPPED.as_bytes());
        return;
    }
    let _ = stream.set_read_timeout(Some(PROBE_TIMEOUT));
    let mut probe = Probe::Read;
    let mut last = None;
    while !closing.load(Ordering::SeqCst) {
        match changes.recv_timeout(WATCH_POLL) {
            Ok(waiting) if last == Some(waiting) => {}
            Ok(waiting) => {
                last = Some(waiting);
                let line = if waiting { "presence waiting\n" } else { "presence idle\n" };
                if (&*stream).write_all(line.as_bytes()).is_err() {
                    return;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if client_gone(stream, &mut probe) {
                    return;
                }
            }
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

/// How a `watch` tells whether its client is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Probe {
    /// Read: an end of stream means the client closed its end, or only its writing side.
    Read,
    /// After an end of stream: a zero-length write. It fails once the client has closed the
    /// connection (`EPIPE` on macOS and Linux) and succeeds while a client that only shut
    /// down its writing side still reads.
    Write,
}

/// Whether the client disconnected. Anything it sends after `watch` is ignored. A client
/// that shut down its writing side after the request (as it may for every request) is still
/// connected and keeps the stream. Where a zero-length write cannot tell, the stream ends
/// at the next presence line instead, when writing it fails.
fn client_gone(stream: &UnixStream, probe: &mut Probe) -> bool {
    if *probe == Probe::Read {
        let mut scratch = [0; 64];
        match (&*stream).read(&mut scratch) {
            Ok(0) => *probe = Probe::Write,
            Ok(_) => return false,
            Err(error) => return !transient(&error),
        }
    }
    // An empty write sends nothing; only its error tells.
    (&*stream).write(&[]).err().is_some_and(|error| !transient(&error))
}

fn transient(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted)
}

/// The `status` reply lines, each ending in `\n` (`docs/PROGRAM.md` "Control socket"):
/// `serial`, `product`, `interfaces`, `presence`, `attached`, `suspended`, `queued`,
/// `dropped`, `unreadable`, `uptime_ms`, in that order.
///
/// - `interfaces` and `unreadable` are comma lists, empty when there is nothing to list;
///   records use the names of their files (`docs/PROGRAM.md` "lk-host").
/// - `presence` is `waiting` or `idle`.
/// - `attached` is present only when the transport knows whether a host is connected
///   (`Status::attached` is `Some`, as with the wire transport).
/// - Booleans are `true` or `false`.
pub fn status_lines(status: &Status) -> String {
    let unreadable: Vec<&str> = status.unreadable.iter().map(|record| record_name(*record)).collect();
    let mut lines = vec![
        format!("serial={}", status.serial),
        format!("product={}", status.product),
        format!("interfaces={}", interface_list(status.interfaces)),
        format!("presence={}", if status.presence_pending { "waiting" } else { "idle" }),
    ];
    if let Some(attached) = status.attached {
        lines.push(format!("attached={attached}"));
    }
    lines.extend([
        format!("suspended={}", status.suspended),
        format!("queued={}", status.queued),
        format!("dropped={}", status.dropped),
        format!("unreadable={}", unreadable.join(",")),
        format!("uptime_ms={}", status.uptime_ms),
    ]);
    lines.iter().map(|line| format!("{line}\n")).collect()
}

/// `otp,fido,ccid`, in that order, naming the enabled interfaces.
pub(crate) fn interface_list(interfaces: UsbInterfaces) -> String {
    let names = [(interfaces.otp, "otp"), (interfaces.fido, "fido"), (interfaces.ccid, "ccid")];
    names.iter().filter(|(enabled, _)| *enabled).map(|(_, name)| *name).collect::<Vec<_>>().join(",")
}

/// The record names of `docs/PROGRAM.md` "lk-host" (the record file names).
fn record_name(record: Record) -> &'static str {
    match record {
        Record::Device => "device",
        Record::Fido => "fido",
        Record::Oath => "oath",
        Record::Otp => "otp",
        Record::Piv => "piv",
        Record::OpenPgp => "openpgp",
        Record::HsmAuth => "hsmauth",
        Record::SecurityDomain => "sd",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A limit no test below gets near.
    const AMPLE: Duration = Duration::from_secs(10);

    fn status() -> Status {
        Status {
            serial: 12_345_678,
            product: "YubiKey 5C Nano".into(),
            interfaces: UsbInterfaces { otp: true, fido: true, ccid: true },
            presence_pending: false,
            serving: true,
            attached: Some(true),
            suspended: false,
            queued: 0,
            dropped: 0,
            unreadable: Vec::new(),
            uptime_ms: 1234,
        }
    }

    #[test]
    fn a_request_line_may_arrive_in_pieces() -> TestResult {
        let (server, mut client) = UnixStream::pair()?;
        client.write_all(b"ta")?;
        let rest = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            client.write_all(b"p long\nignored")
        });
        assert_eq!(read_request(&server, AMPLE), Ok("tap long".into()));
        rest.join().map_err(|_| "the writing thread panicked")??;
        Ok(())
    }

    #[test]
    fn a_request_line_is_at_most_256_bytes() -> TestResult {
        let longest = "x".repeat(MAX_REQUEST);
        let (server, mut client) = UnixStream::pair()?;
        client.write_all(format!("{longest}\n").as_bytes())?;
        assert_eq!(read_request(&server, AMPLE), Ok(longest.clone()));

        let (server, mut client) = UnixStream::pair()?;
        client.write_all(longest.as_bytes())?;
        drop(client);
        assert_eq!(read_request(&server, AMPLE), Ok(longest.clone()), "ended by the close");

        let (server, mut client) = UnixStream::pair()?;
        client.write_all(format!("{longest}x").as_bytes())?;
        assert_eq!(read_request(&server, AMPLE), Err("request too long".into()));
        Ok(())
    }

    /// The limit is for the whole line: a client that sends a byte now and then, each well
    /// within the limit, still runs out of time.
    #[test]
    fn a_request_line_must_arrive_within_the_limit_in_total() -> TestResult {
        let (server, mut client) = UnixStream::pair()?;
        let trickle = thread::spawn(move || {
            for _ in 0..30 {
                if client.write_all(b"s").is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
        });
        let limit = Duration::from_millis(500);
        let started = Instant::now();
        assert_eq!(read_request(&server, limit), Err("no request".into()));
        assert!(started.elapsed() >= limit);
        drop(server);
        trickle.join().map_err(|_| "the trickling thread panicked")?;
        Ok(())
    }

    #[test]
    fn every_documented_command_parses() {
        assert_eq!(Request::parse("tap"), Ok(Request::Tap { long: false }));
        assert_eq!(Request::parse("tap long"), Ok(Request::Tap { long: true }));
        assert_eq!(Request::parse("down"), Ok(Request::Down));
        assert_eq!(Request::parse("up"), Ok(Request::Up));
        assert_eq!(Request::parse("power-cycle"), Ok(Request::PowerCycle));
        assert_eq!(Request::parse("status"), Ok(Request::Status));
        assert_eq!(Request::parse("watch"), Ok(Request::Watch));
        assert_eq!(Request::parse("shutdown"), Ok(Request::Shutdown));
    }

    #[test]
    fn surrounding_whitespace_and_a_carriage_return_are_ignored() {
        assert_eq!(Request::parse("  tap   long \r"), Ok(Request::Tap { long: true }));
        assert_eq!(Request::parse("status\r"), Ok(Request::Status));
    }

    #[test]
    fn unknown_and_empty_requests_are_errors() {
        assert_eq!(Request::parse(""), Err("empty request".into()));
        assert_eq!(Request::parse("  \r"), Err("empty request".into()));
        assert_eq!(Request::parse("tap short"), Err("unknown command: tap short".into()));
        assert_eq!(Request::parse("TAP"), Err("unknown command: TAP".into()));
        assert_eq!(Request::parse("status now"), Err("unknown command: status now".into()));
        assert_eq!(Request::parse("powercycle"), Err("unknown command: powercycle".into()));
        assert_eq!(Request::parse("shutdown now"), Err("unknown command: shutdown now".into()));
        assert_eq!(Request::parse("SHUTDOWN"), Err("unknown command: SHUTDOWN".into()));
    }

    #[test]
    fn status_lists_the_documented_keys_in_order() {
        assert_eq!(
            status_lines(&status()),
            "serial=12345678\nproduct=YubiKey 5C Nano\ninterfaces=otp,fido,ccid\npresence=idle\nattached=true\n\
             suspended=false\nqueued=0\ndropped=0\nunreadable=\nuptime_ms=1234\n"
        );
    }

    #[test]
    fn status_reports_waiting_presence_suspension_and_counters() {
        let status = Status {
            presence_pending: true,
            attached: Some(false),
            suspended: true,
            queued: 3,
            dropped: 7,
            uptime_ms: 99,
            ..status()
        };
        let lines = status_lines(&status);
        for expected in ["presence=waiting\n", "attached=false\n", "suspended=true\n", "queued=3\n", "dropped=7\n"] {
            assert!(lines.contains(expected), "{expected:?} in {lines:?}");
        }
        assert!(lines.ends_with("uptime_ms=99\n"));
    }

    #[test]
    fn status_omits_attached_when_the_transport_cannot_tell() {
        let lines = status_lines(&Status { attached: None, serving: false, ..status() });
        assert!(!lines.contains("attached="));
        assert_eq!(lines.lines().count(), 9);
    }

    #[test]
    fn unreadable_records_use_their_file_names() {
        let all = vec![
            Record::Device,
            Record::Fido,
            Record::Oath,
            Record::Otp,
            Record::Piv,
            Record::OpenPgp,
            Record::HsmAuth,
            Record::SecurityDomain,
        ];
        let lines = status_lines(&Status { unreadable: all, ..status() });
        assert!(lines.contains("\nunreadable=device,fido,oath,otp,piv,openpgp,hsmauth,sd\n"));
        let lines = status_lines(&Status { unreadable: vec![Record::Piv], ..status() });
        assert!(lines.contains("\nunreadable=piv\n"));
    }

    #[test]
    fn interfaces_are_listed_in_otp_fido_ccid_order() {
        let set = |otp, fido, ccid| interface_list(UsbInterfaces { otp, fido, ccid });
        assert_eq!(set(true, true, true), "otp,fido,ccid");
        assert_eq!(set(false, true, true), "fido,ccid");
        assert_eq!(set(true, false, true), "otp,ccid");
        assert_eq!(set(false, false, true), "ccid");
        assert_eq!(set(false, false, false), "");
    }
}
