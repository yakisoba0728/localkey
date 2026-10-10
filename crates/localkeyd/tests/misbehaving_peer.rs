//! A wire peer that misbehaves cannot hold the daemon up or grow it without bound
//! (`docs/PROGRAM.md` "lk-wire", "Connection semantics"; "localkeyd", logging).
//!
//! - Malformed frames are logged at the default level, and `lk_wire` calls the daemon's
//!   observer with its client slot locked. The daemon's log must therefore never block,
//!   even on a stderr pipe that nobody reads.
//! - The runner's channel is unbounded; `lk_wire`'s reader paces itself to the runner, so a
//!   client that floods frames waits in the socket instead of piling up in the daemon.

mod common;

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use common::*;

/// Kills and reaps the child on drop, so a failing test leaves no process behind.
struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Connect, take IDENTITY, send a frame whose length field is 0 (malformed), and read to
/// the end of the stream (the ERROR, then the close). False when the daemon did not get
/// that far within `limit`.
fn one_malformed_connection(dir: &TestDir, limit: Duration) -> bool {
    let Ok(mut stream) = UnixStream::connect(dir.wire()) else {
        return false;
    };
    if stream.set_read_timeout(Some(limit)).is_err() {
        return false;
    }
    let mut header = [0u8; 5];
    if stream.read_exact(&mut header).is_err() || header[4] != 0x80 {
        return false;
    }
    let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    let mut payload = vec![0u8; length.saturating_sub(1)];
    if stream.read_exact(&mut payload).is_err() || stream.write_all(&[0, 0, 0, 0, 0]).is_err() {
        return false;
    }
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).is_ok()
}

#[test]
fn malformed_frames_cannot_wedge_a_daemon_whose_stderr_is_not_read() -> TestResult {
    let dir = TestDir::new();
    keygen(&dir.key())?;
    let mut child = Command::new(BIN)
        .args([OsString::from("run"), "--state".into(), dir.state().into(), "--key-file".into(), dir.key().into()])
        .arg("--exit-on-stdin-eof")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let stderr = child.stderr.take().ok_or("stderr is piped")?;
    let mut guard = Guard(child);

    // Read stderr until the daemon serves, then stop reading but keep the pipe open (a
    // supervisor that only reads on exit, or a parent that never reads).
    let mut stderr = BufReader::new(stderr);
    let mut line = String::new();
    loop {
        line.clear();
        if stderr.read_line(&mut line)? == 0 {
            return Err("the daemon exited before serving".into());
        }
        if line.contains("localkeyd: serving") {
            break;
        }
    }

    // One default-level log line per connection, about 85 bytes: 2000 of them fill a
    // 64 KiB pipe and then the daemon's log queue, so lines are dropped too.
    let mut connections = 0;
    let mut wedged = false;
    while connections < 2_000 {
        if !one_malformed_connection(&dir, WAIT) {
            wedged = true;
            break;
        }
        connections += 1;
    }
    let status = ctl(&dir.control(), &["status"])?;

    // Closing stdin is the clean shutdown; the daemon gives its log a few seconds, then
    // exits whether the log was read or not.
    drop(guard.0.stdin.take());
    let deadline = Instant::now() + WAIT;
    let exited = loop {
        if let Some(code) = guard.0.try_wait()? {
            break Some(code);
        }
        if Instant::now() > deadline {
            break None;
        }
        thread::sleep(Duration::from_millis(50));
    };

    assert!(
        !wedged && status.status.success() && exited.is_some_and(|code| code.success()),
        "after {connections} malformed connections (wedged: {wedged}): `ctl status` exited {:?} with \
         {:?}; after closing stdin the daemon exited: {exited:?}",
        status.status.code(),
        text(&status.stdout),
    );
    Ok(())
}

/// The resident set size of process `pid` in KiB (`ps -o rss=`), 0 if it cannot be read.
fn rss_kib(pid: u32) -> u64 {
    Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()
        .and_then(|output| String::from_utf8_lossy(&output.stdout).trim().parse().ok())
        .unwrap_or(0)
}

#[test]
fn a_flooding_wire_client_cannot_grow_the_daemon_without_bound() -> TestResult {
    /// Growth of the daemon's resident set that paced inputs never come near: an unpaced
    /// reader passed it within two seconds of TOUCH frames on the review machine.
    const BOUND_KIB: u64 = 64 * 1024;
    /// How long the client floods.
    const FLOOD: Duration = Duration::from_secs(3);

    let dir = TestDir::new();
    keygen(&dir.key())?;
    let daemon = Daemon::with_key(&dir, &[])?;
    let pid = daemon.pid();
    let mut stream = UnixStream::connect(dir.wire())?;
    // Read everything the daemon sends, so the client is never dropped for not reading.
    let mut drain = stream.try_clone()?;
    let drained = thread::spawn(move || {
        let mut sink = [0u8; 65536];
        while matches!(drain.read(&mut sink), Ok(read) if read > 0) {}
    });
    let before = rss_kib(pid);

    // TOUCH down (`00 00 00 02 06 01`): the first presses the sensor and the runner
    // ignores every later one, so each costs it next to nothing.
    let frame = [0u8, 0, 0, 2, 0x06, 0x01];
    let block: Vec<u8> = frame.iter().copied().cycle().take(frame.len() * 10_000).collect();
    let started = Instant::now();
    let mut checked = Instant::now();
    let mut frames = 0u64;
    let mut growth = 0;
    while started.elapsed() < FLOOD {
        stream.write_all(&block)?;
        frames += 10_000;
        if checked.elapsed() >= Duration::from_millis(200) {
            checked = Instant::now();
            growth = rss_kib(pid).saturating_sub(before);
            if growth > BOUND_KIB {
                break;
            }
        }
    }
    stream.shutdown(Shutdown::Both)?;
    drop(stream);
    let _ = drained.join();

    // Once the client is gone, the runner has at most two windows of its inputs left, so
    // `status` answers well within the control socket's own 5-second limit.
    let output = ctl(&dir.control(), &["status"])?;
    assert!(
        growth <= BOUND_KIB,
        "{frames} TOUCH frames in {:?} grew the daemon by {growth} KiB (from {before} KiB)",
        started.elapsed(),
    );
    assert!(output.status.success(), "{}{}", text(&output.stdout), text(&output.stderr));
    Ok(())
}
