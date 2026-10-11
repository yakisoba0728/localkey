//! The control socket over real sockets with a fake runner (`docs/PROGRAM.md` "lk-wire",
//! "Control socket").

mod common;

use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use common::*;
use lk_device::{BusEvent, TouchEdge};
use lk_run::{Command, HostInput, TAP_LONG_MS, TAP_SHORT_MS};
use lk_wire::{ControlServer, ShutdownHook, ShutdownRequest, WireError};

fn serve(dir: &TestDir, runner: &FakeRunner) -> Result<ControlServer, WireError> {
    ControlServer::bind(&dir.join("c"), runner.sender())
}

/// A server whose shutdown hook sends every [`ShutdownRequest`] to the returned receiver.
fn serve_with_shutdown(
    dir: &TestDir,
    runner: &FakeRunner,
) -> Result<(ControlServer, Receiver<ShutdownRequest>), WireError> {
    let (requests, received) = mpsc::channel();
    let hook: ShutdownHook = Arc::new(move |request| {
        let _ = requests.send(request);
    });
    Ok((ControlServer::bind_with_shutdown(&dir.join("c"), runner.sender(), hook)?, received))
}

/// Read one line (up to and including `\n`) without buffering past it.
fn read_line(stream: &mut UnixStream) -> io::Result<String> {
    let mut line = Vec::new();
    let mut byte = [0; 1];
    while line.last() != Some(&b'\n') {
        if stream.read(&mut byte)? == 0 {
            break;
        }
        line.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&line).into_owned())
}

/// Whether the stream stays open and silent for [`QUIET`]: a read times out.
fn stays_open(stream: &mut UnixStream) -> io::Result<bool> {
    stream.set_read_timeout(Some(QUIET))?;
    let mut byte = [0; 1];
    let open = match stream.read(&mut byte) {
        Err(error) => matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut),
        Ok(_) => false,
    };
    stream.set_read_timeout(Some(WAIT))?;
    Ok(open)
}

#[test]
fn tap_sends_a_short_tap() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let server = serve(&dir, &runner)?;
    assert_eq!(control(server.path(), "tap\n")?, "ok\n");
    assert_eq!(runner.next(), Seen::Tap(TAP_SHORT_MS));
    assert_eq!(TAP_SHORT_MS, 500);
    Ok(())
}

#[test]
fn tap_long_sends_a_long_tap() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let server = serve(&dir, &runner)?;
    assert_eq!(control(server.path(), "tap long\n")?, "ok\n");
    assert_eq!(runner.next(), Seen::Tap(TAP_LONG_MS));
    assert_eq!(TAP_LONG_MS, 3_000);
    Ok(())
}

#[test]
fn down_and_up_press_and_release_the_sensor() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let server = serve(&dir, &runner)?;
    assert_eq!(control(server.path(), "down\n")?, "ok\n");
    assert_eq!(runner.next(), Seen::Input(HostInput::Touch(TouchEdge::Down)));
    assert_eq!(control(server.path(), "up\n")?, "ok\n");
    assert_eq!(runner.next(), Seen::Input(HostInput::Touch(TouchEdge::Up)));
    Ok(())
}

#[test]
fn power_cycle_unplugs_and_plugs_in_the_key() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let server = serve(&dir, &runner)?;
    assert_eq!(control(server.path(), "power-cycle\n")?, "ok\n");
    assert_eq!(runner.next(), Seen::Input(HostInput::Bus(BusEvent::PowerCycle)));
    Ok(())
}

#[test]
fn status_replies_key_value_lines_then_ok() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let server = serve(&dir, &runner)?;
    assert_eq!(
        control(server.path(), "status\n")?,
        "serial=12345678\n\
         product=YubiKey 5C Nano\n\
         interfaces=otp,fido,ccid\n\
         presence=idle\n\
         attached=true\n\
         suspended=false\n\
         queued=0\n\
         dropped=2\n\
         unreadable=oath\n\
         uptime_ms=4321\n\
         ok\n"
    );
    assert_eq!(runner.next(), Seen::Status);
    Ok(())
}

#[test]
fn watch_streams_presence_lines_without_ok() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::start(status(), vec![false, true, false]);
    let server = serve(&dir, &runner)?;
    let mut stream = raw_connect(server.path())?;
    stream.write_all(b"watch\n")?;
    let mut lines = BufReader::new(stream.try_clone()?).lines();
    let mut next_line = || lines.next().transpose().map(Option::unwrap_or_default);
    assert_eq!(next_line()?, "presence idle");
    assert_eq!(next_line()?, "presence waiting");
    assert_eq!(next_line()?, "presence idle");
    assert_eq!(runner.next(), Seen::Watch);
    assert_eq!(runner.presence(true), 1);
    assert_eq!(next_line()?, "presence waiting");
    assert_eq!(runner.presence(false), 1);
    assert_eq!(next_line()?, "presence idle");
    Ok(())
}

/// "as the state changes": the runner may repeat the unchanged state to a watcher (it
/// probes its watchers that way), and a repeat writes no line.
#[test]
fn watch_writes_no_line_for_a_repeated_state() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::start(status(), vec![false, false, true, true, false]);
    let server = serve(&dir, &runner)?;
    let mut stream = raw_connect(server.path())?;
    stream.write_all(b"watch\n")?;
    let mut lines = BufReader::new(stream.try_clone()?).lines();
    let mut next_line = || lines.next().transpose().map(Option::unwrap_or_default);
    assert_eq!(next_line()?, "presence idle");
    assert_eq!(next_line()?, "presence waiting");
    assert_eq!(next_line()?, "presence idle");
    assert_eq!(runner.next(), Seen::Watch);
    // Had the repeat been written, it would be the next line.
    assert_eq!(runner.presence(false), 1);
    assert_eq!(runner.presence(true), 1);
    assert_eq!(next_line()?, "presence waiting");
    Ok(())
}

#[test]
fn watch_ends_when_the_client_disconnects() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::start(status(), vec![false]);
    let server = serve(&dir, &runner)?;
    let mut stream = raw_connect(server.path())?;
    stream.write_all(b"watch\n")?;
    let mut line = String::new();
    BufReader::new(stream.try_clone()?).read_line(&mut line)?;
    assert_eq!(line, "presence idle\n");
    assert_eq!(runner.next(), Seen::Watch);
    drop(stream);
    // The server notices within its poll interval and drops the watcher.
    eventually("the watcher to be dropped", || runner.presence(true) == 0);
    Ok(())
}

/// "until the client disconnects": a client that shut down its writing side after the
/// request (as `nc -N` does, and as every other request may end) is still connected and
/// reading.
#[test]
fn watch_keeps_streaming_to_a_client_that_shut_down_its_writing_side() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::start(status(), vec![false]);
    let server = serve(&dir, &runner)?;
    let mut stream = raw_connect(server.path())?;
    stream.write_all(b"watch\n")?;
    stream.shutdown(Shutdown::Write)?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    assert_eq!(line, "presence idle\n");
    assert_eq!(runner.next(), Seen::Watch);
    // Three times the server's one-second check.
    thread::sleep(Duration::from_secs(3));
    assert_eq!(runner.presence(true), 1, "the watch of a half-closed client was dropped");
    line.clear();
    reader.read_line(&mut line)?;
    assert_eq!(line, "presence waiting\n");
    Ok(())
}

#[test]
fn a_half_closed_watch_ends_when_the_client_disconnects_without_a_presence_change() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::start(status(), vec![false]);
    let server = serve(&dir, &runner)?;
    let mut stream = raw_connect(server.path())?;
    stream.write_all(b"watch\n")?;
    stream.shutdown(Shutdown::Write)?;
    let mut line = String::new();
    BufReader::new(stream.try_clone()?).read_line(&mut line)?;
    assert_eq!(line, "presence idle\n");
    assert_eq!(runner.next(), Seen::Watch);
    // Past the server's first check, which sees the half-close.
    thread::sleep(Duration::from_millis(1_500));
    drop(stream);
    // The next checks find the connection closed; no presence line is needed to notice.
    thread::sleep(Duration::from_secs(3));
    assert_eq!(runner.presence(true), 0, "the watcher outlived its client");
    Ok(())
}

#[test]
fn closing_the_server_removes_the_socket_and_ends_watch_streams() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::start(status(), vec![true]);
    let server = serve(&dir, &runner)?;
    let path = server.path().to_owned();
    let mut stream = raw_connect(&path)?;
    stream.write_all(b"watch\n")?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    assert_eq!(line, "presence waiting\n");
    server.close();
    assert!(!path.exists());
    line.clear();
    assert_eq!(reader.read_line(&mut line)?, 0, "the stream ends without ok");
    Ok(())
}

#[test]
fn an_unknown_or_empty_command_gets_an_error() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let server = serve(&dir, &runner)?;
    assert_eq!(control(server.path(), "jump\n")?, "error unknown command: jump\n");
    assert_eq!(control(server.path(), "tap twice\n")?, "error unknown command: tap twice\n");
    assert_eq!(control(server.path(), "\n")?, "error empty request\n");
    assert_eq!(control(server.path(), &format!("{}\n", "x".repeat(300)))?, "error request too long\n");
    assert_eq!(control(server.path(), "st\u{e4}tus\n")?, "error unknown command: st\u{e4}tus\n");
    let mut invalid = raw_connect(server.path())?;
    invalid.write_all(b"\xFF\n")?;
    let mut reply = String::new();
    std::io::Read::read_to_string(&mut invalid, &mut reply)?;
    assert_eq!(reply, "error request is not UTF-8\n");
    runner.assert_quiet();
    Ok(())
}

/// Linux resets a Unix stream closed with unread input; the server reads what is waiting
/// first, so the client gets its reply and a clean end of stream.
#[test]
fn bytes_after_the_request_line_still_end_in_a_clean_close() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let server = serve(&dir, &runner)?;
    assert_eq!(control(server.path(), &format!("tap\n{}", "y".repeat(2000)))?, "ok\n");
    assert_eq!(runner.next(), Seen::Tap(TAP_SHORT_MS));
    assert_eq!(control(server.path(), &"z".repeat(5000))?, "error request too long\n");
    runner.assert_quiet();
    Ok(())
}

#[test]
fn a_request_may_end_at_the_close_of_the_clients_side() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let server = serve(&dir, &runner)?;
    let mut stream = raw_connect(server.path())?;
    stream.write_all(b"tap long\r")?;
    stream.shutdown(Shutdown::Write)?;
    let mut reply = String::new();
    std::io::Read::read_to_string(&mut stream, &mut reply)?;
    assert_eq!(reply, "ok\n");
    assert_eq!(runner.next(), Seen::Tap(TAP_LONG_MS));
    Ok(())
}

#[test]
fn a_stopped_runner_gives_an_error() -> TestResult {
    let dir = TestDir::new();
    let (sender, receiver) = mpsc::channel::<Command>();
    drop(receiver);
    let server = ControlServer::bind(&dir.join("c"), sender)?;
    for request in ["tap\n", "tap long\n", "down\n", "up\n", "power-cycle\n", "status\n", "watch\n"] {
        assert_eq!(control(server.path(), request)?, "error runner stopped\n", "{request:?}");
    }
    Ok(())
}

#[test]
fn the_control_socket_follows_the_placement_rules() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let server = serve(&dir, &runner)?;
    let meta = fs::symlink_metadata(server.path())?;
    assert!(meta.file_type().is_socket());
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    drop(server);
    assert!(!dir.join("c").exists());

    let file = dir.join("f");
    fs::write(&file, b"keep")?;
    assert!(matches!(ControlServer::bind(&file, runner.sender()), Err(WireError::NotASocket { .. })));
    assert_eq!(fs::read(&file)?, b"keep");

    dir.set_mode(0o750);
    assert!(matches!(serve(&dir, &runner), Err(WireError::Permissions { mode: 0o750, .. })));
    dir.set_mode(0o700);
    Ok(())
}

/// Two servers given the same path (a misconfiguration, such as the same path for the wire
/// and the control socket): dropping the first must not hang on an accept thread nobody
/// can reach, nor remove the second's socket.
#[test]
fn dropping_a_control_server_whose_path_was_taken_over_does_not_hang() -> TestResult {
    let dir = TestDir::new();
    let path = dir.join("c");
    let runner = FakeRunner::plain();
    let first = ControlServer::bind(&path, runner.sender())?;
    let second = ControlServer::bind(&path, runner.sender())?;
    assert!(drops_in_time(first), "dropping the first control server hung");
    assert!(fs::symlink_metadata(&path)?.file_type().is_socket(), "the second server's socket is kept");
    assert_eq!(control(second.path(), "down\n")?, "ok\n");
    assert_eq!(runner.next(), Seen::Input(HostInput::Touch(TouchEdge::Down)));
    Ok(())
}

#[test]
fn many_requests_in_a_row_are_each_served() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let server = serve(&dir, &runner)?;
    for _ in 0..20 {
        assert_eq!(control(server.path(), "down\n")?, "ok\n");
        assert_eq!(runner.next(), Seen::Input(HostInput::Touch(TouchEdge::Down)));
        assert!(control(server.path(), "status\n")?.ends_with("\nok\n"));
        assert_eq!(runner.next(), Seen::Status);
    }
    Ok(())
}

/// `docs/PROGRAM.md` "Clean shutdown from the control socket": `shutdown` replies `ok`, and
/// the owner gets the request; the connection stays open until the owner drops it, so the
/// client can wait for the shutdown to finish. Nothing reaches the runner.
#[test]
fn shutdown_replies_ok_and_hands_the_open_connection_to_the_hook() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let (server, requests) = serve_with_shutdown(&dir, &runner)?;
    let mut stream = raw_connect(server.path())?;
    stream.write_all(b"shutdown\n")?;
    assert_eq!(read_line(&mut stream)?, "ok\n");
    let request = requests.recv_timeout(WAIT)?;
    assert_eq!(format!("{request:?}"), "ShutdownRequest { .. }");
    assert!(stays_open(&mut stream)?, "the connection is held while the owner shuts down");
    request.finish();
    assert_closed(&mut stream);
    runner.assert_quiet();
    assert!(requests.try_recv().is_err(), "one request, one call");
    Ok(())
}

/// The owner ends a held request with how its shutdown went: `stopped` for a clean stop,
/// `error <reason>` when it failed after the `ok`, and then the connection closes. (Found
/// by review: with the close alone, a client could not tell a clean stop from a daemon
/// that failed after accepting the request.) A reason with line breaks stays one line.
#[test]
fn a_held_shutdown_ends_with_stopped_or_with_the_error_that_followed_the_ok() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let (server, requests) = serve_with_shutdown(&dir, &runner)?;
    let mut clean = raw_connect(server.path())?;
    clean.write_all(b"shutdown\n")?;
    assert_eq!(read_line(&mut clean)?, "ok\n");
    let stopped = requests.recv_timeout(WAIT)?;
    let mut failing = raw_connect(server.path())?;
    failing.write_all(b"shutdown\n")?;
    assert_eq!(read_line(&mut failing)?, "ok\n");
    let failed = requests.recv_timeout(WAIT)?;
    server.close();

    assert!(stays_open(&mut clean)?, "nothing more until the owner is done");
    stopped.stopped();
    assert_eq!(read_line(&mut clean)?, "stopped\n");
    assert_closed(&mut clean);
    failed.failed("the runner stopped:\nit panicked\r");
    assert_eq!(read_line(&mut failing)?, "error the runner stopped: it panicked \n");
    assert_closed(&mut failing);
    runner.assert_quiet();
    Ok(())
}

/// A client that has gone before the owner is done does not trouble the owner: writing
/// the last line fails quietly.
#[test]
fn the_last_line_to_a_client_that_has_gone_is_dropped_quietly() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let (server, requests) = serve_with_shutdown(&dir, &runner)?;
    let mut stream = raw_connect(server.path())?;
    stream.write_all(b"shutdown\n")?;
    assert_eq!(read_line(&mut stream)?, "ok\n");
    let request = requests.recv_timeout(WAIT)?;
    drop(stream);
    request.failed("gone");
    Ok(())
}

/// The reply is written before the hook runs: a hook that waits until the client has read
/// `ok` would otherwise wait for ever.
#[test]
fn the_shutdown_reply_is_out_before_the_hook_is_called() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let (read_ok, ok_was_read) = mpsc::channel::<()>();
    let ok_was_read = Mutex::new(ok_was_read);
    let (called, hook_called) = mpsc::channel();
    let hook: ShutdownHook = Arc::new(move |request| {
        // `Receiver` is not `Sync`, so the hook (shared by every connection) locks it.
        let waited = ok_was_read.lock().unwrap_or_else(PoisonError::into_inner).recv_timeout(WAIT).is_ok();
        let _ = called.send((waited, request));
    });
    let server = ControlServer::bind_with_shutdown(&dir.join("c"), runner.sender(), hook)?;
    let mut stream = raw_connect(server.path())?;
    stream.write_all(b"shutdown\n")?;
    assert_eq!(read_line(&mut stream)?, "ok\n");
    read_ok.send(())?;
    let (waited, request) = hook_called.recv_timeout(WAIT)?;
    assert!(waited, "the hook ran only after the client had its reply");
    drop(request);
    assert_closed(&mut stream);
    Ok(())
}

/// Closing the server (the daemon's first step of a clean shutdown) does not close a held
/// shutdown connection; only dropping the request does.
#[test]
fn a_held_shutdown_connection_outlives_the_server() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let (server, requests) = serve_with_shutdown(&dir, &runner)?;
    let path = server.path().to_owned();
    let mut stream = raw_connect(&path)?;
    stream.write_all(b"shutdown")?;
    stream.shutdown(Shutdown::Write)?;
    assert_eq!(read_line(&mut stream)?, "ok\n", "a request may end at the close of the client's side");
    let request = requests.recv_timeout(WAIT)?;
    server.close();
    assert!(!path.exists(), "the socket is removed");
    assert!(stays_open(&mut stream)?, "the held connection is still open");
    drop(request);
    assert_closed(&mut stream);
    Ok(())
}

/// Every `shutdown` request calls the hook, and the other commands still work beside it.
#[test]
fn every_shutdown_request_reaches_the_hook_and_other_commands_still_work() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let (server, requests) = serve_with_shutdown(&dir, &runner)?;
    let mut first = raw_connect(server.path())?;
    first.write_all(b"shutdown\n")?;
    assert_eq!(read_line(&mut first)?, "ok\n");
    let mut second = raw_connect(server.path())?;
    second.write_all(b"  shutdown \r\n")?;
    assert_eq!(read_line(&mut second)?, "ok\n");
    let held = [requests.recv_timeout(WAIT)?, requests.recv_timeout(WAIT)?];
    assert_eq!(control(server.path(), "down\n")?, "ok\n");
    assert_eq!(runner.next(), Seen::Input(HostInput::Touch(TouchEdge::Down)));
    drop(held);
    assert_closed(&mut first);
    assert_closed(&mut second);
    Ok(())
}

/// A server bound without a hook has nobody to tell: the request is refused, the
/// connection closes as for every other request, and the runner hears nothing.
#[test]
fn shutdown_without_a_hook_is_refused() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let server = serve(&dir, &runner)?;
    assert_eq!(control(server.path(), "shutdown\n")?, "error shutdown not available\n");
    runner.assert_quiet();
    Ok(())
}

/// `shutdown` does not need the runner: it is answered `ok` while the runner has stopped.
#[test]
fn shutdown_is_answered_while_the_runner_has_stopped() -> TestResult {
    let dir = TestDir::new();
    let (sender, receiver) = mpsc::channel::<Command>();
    drop(receiver);
    let (requests, received) = mpsc::channel();
    let hook: ShutdownHook = Arc::new(move |request| {
        let _ = requests.send(request);
    });
    let server = ControlServer::bind_with_shutdown(&dir.join("c"), sender, hook)?;
    let mut stream = raw_connect(server.path())?;
    stream.write_all(b"shutdown\n")?;
    assert_eq!(read_line(&mut stream)?, "ok\n");
    drop(received.recv_timeout(WAIT)?);
    assert_closed(&mut stream);
    Ok(())
}
