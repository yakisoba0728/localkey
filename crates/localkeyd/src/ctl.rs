//! `localkeyd ctl --control PATH COMMAND`: one request on the control socket
//! (`docs/PROGRAM.md` "Control socket").
//!
//! The request line goes out, and every reply line is printed to stdout as it arrives (a
//! `watch` stream line by line). Exit codes: 0 when the reply ends in `ok` (or a `watch`
//! stream simply ends, when the daemon stops), 1 when it ends in `error <reason>`, when the
//! socket cannot be reached, or when the daemon closes without a reply.

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::time::Duration;

use crate::args::{CtlOptions, Request};
use crate::log;

/// How long a request other than `watch` waits for its reply. The daemon answers at once
/// or within its own 5-second `status` limit; this only keeps `ctl` from hanging on a
/// daemon that has stopped working.
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
                io::Error::new(io::ErrorKind::TimedOut, format!("no reply within {} seconds", REPLY_TIMEOUT.as_secs()))
            }
            _ => error,
        })?;
        writeln!(stdout, "{line}")?;
        stdout.flush()?;
        last = Some(line);
    }
    match last.as_deref() {
        Some("ok") => Ok(true),
        Some(line) if line.starts_with("error") => Ok(false),
        _ if watch => Ok(true),
        _ => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the daemon closed the connection without a reply")),
    }
}
