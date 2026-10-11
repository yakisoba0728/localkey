//! `localkeyd ctl --control PATH COMMAND`: one request on the control socket
//! (`docs/PROGRAM.md` "Control socket").
//!
//! The request line goes out, and every reply line is printed to stdout as it arrives (a
//! `watch` stream line by line). Exit codes: 0 when the reply ends in `ok` (`stopped` for
//! `shutdown`; or a `watch` stream simply ends, when the daemon stops), 1 when it ends in
//! `error <reason>`, when the socket cannot be reached, or when the daemon closes without
//! a reply.
//!
//! `shutdown` prints the daemon's `ok` at once and then waits for the end of the stream:
//! the daemon holds the connection until it has shut down and is about to exit
//! (`lk_wire::ShutdownRequest`), so `ctl ... shutdown` returns once the daemon is gone and a
//! supervisor's stop command does not race the clean shutdown. Before it lets the
//! connection go, the daemon writes how it ended: `stopped` (a clean stop, exit 0 here) or
//! `error <reason>` (it failed after accepting the request and exits non-zero; exit 1
//! here). A stream that ends after `ok` without either line (the daemon was killed or
//! aborted) is a failure too (exit 1). (Found by review: `ok` and the close alone looked
//! the same whether the daemon then stopped cleanly or failed, so `ctl` exited 0 either
//! way.) A daemon that has not finished within [`REPLY_TIMEOUT`] after its `ok` is
//! reported (exit 1).

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::time::Duration;

use crate::args::{CtlOptions, Request};
use crate::log;

/// How long a request other than `watch` waits for its reply, and `shutdown` for the end
/// of the stream between lines. The daemon answers at once or within its own 5-second
/// `status` limit; its clean shutdown takes a few seconds at most (transports that wait
/// about a second for their threads, at most 5 seconds for the last log lines). This only
/// keeps `ctl` from hanging on a daemon that has stopped working.
const REPLY_TIMEOUT: Duration = Duration::from_secs(30);

pub fn ctl(options: &CtlOptions) -> ExitCode {
    match request(options) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            log::line(format!("{}: {error}", options.control.display()));
            ExitCode::FAILURE
        }
    }
}

/// Send the request and print the reply; whether it succeeded.
fn request(options: &CtlOptions) -> io::Result<bool> {
    let watch = options.request == Request::Watch;
    let mut stream = UnixStream::connect(&options.control)?;
    if !watch {
        stream.set_read_timeout(Some(REPLY_TIMEOUT))?;
    }
    stream.write_all(format!("{}\n", options.request.line()).as_bytes())?;
    let mut stdout = io::stdout().lock();
    let mut last = None;
    for line in BufReader::new(&stream).lines() {
        let line = line.map_err(|error| match error.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                let seconds = REPLY_TIMEOUT.as_secs();
                let reason = if options.request == Request::Shutdown && last.as_deref() == Some("ok") {
                    format!("the daemon accepted the shutdown but did not stop within {seconds} seconds")
                } else {
                    format!("no reply within {seconds} seconds")
                };
                io::Error::new(io::ErrorKind::TimedOut, reason)
            }
            _ => error,
        })?;
        writeln!(stdout, "{line}")?;
        stdout.flush()?;
        last = Some(line);
    }
    let shutdown = options.request == Request::Shutdown;
    match last.as_deref() {
        Some(STOPPED) if shutdown => Ok(true),
        Some("ok") if shutdown => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the daemon accepted the shutdown but ended without reporting a clean stop",
        )),
        Some("ok") => Ok(true),
        Some(line) if line.starts_with("error") => Ok(false),
        _ if watch => Ok(true),
        _ => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the daemon closed the connection without a reply")),
    }
}

/// The daemon's last line after `shutdown` when it stopped cleanly
/// (`lk_wire::ShutdownRequest::stopped`).
const STOPPED: &str = "stopped";
