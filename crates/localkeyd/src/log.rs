//! Logging to stderr (`docs/PROGRAM.md` "localkeyd"): startup and errors by default, `-v`
//! adds connections, enumeration and presence, `-vv` adds frame types and sizes.
//!
//! Nothing logged carries payload bytes, record contents or key bytes: the daemon logs
//! paths, counts, frame types and sizes, and `lk_wire::WireEvent`s, whose texts never hold
//! payloads (`docs/PROGRAM.md` "Rules for program crates", Secrets).
//!
//! # As built
//!
//! - The daemon's [`Log`] never blocks the thread that logs. `lk_wire` calls its observer
//!   on the transport's threads with the client slot locked ("must be quick"), and a peer
//!   can make it log at every level (a malformed frame is an error, logged by default), so
//!   a stderr that nobody reads must not hold anything up. Lines go into a queue of
//!   [`QUEUE_LINES`] that one writer thread empties into stderr. When the queue is full a
//!   line is dropped and counted, and `<n> log line(s) dropped` takes its place: it is
//!   queued before the next line that fits, or by the final flush.
//! - Before the daemon exits it waits for the queue to be written, at most
//!   [`FLUSH_LIMIT`] ([`Log::flush`]), so its last lines (the reason it stops) reach a
//!   stderr that is read, and a stderr that is not read delays the exit by that much only.
//!   Lines the transport's threads log after that are lost.
//! - A failed write to stderr is ignored (a closed stderr must not stop the daemon).
//! - `keygen`, `ctl` and usage errors write their few lines synchronously with [`line`]:
//!   they run once and hold no lock.

use std::collections::VecDeque;
use std::fmt::Display;
use std::io::{self, Write};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

/// The verbosity of `-v`.
pub const VERBOSE: u8 = 1;
/// The verbosity of `-vv`.
pub const TRACE: u8 = 2;
/// Lines that wait for stderr before more are dropped.
pub const QUEUE_LINES: usize = 1024;
/// How long [`Log::flush`] waits, at most, for the queued lines to be written.
pub const FLUSH_LIMIT: Duration = Duration::from_secs(5);

/// The daemon's logger: a verbosity level and the queue of its writer thread. Clones share
/// the queue, so every thread that logs gets one.
#[derive(Debug, Clone)]
pub struct Log {
    verbosity: u8,
    queue: Arc<Queue>,
}

/// The lines between the threads that log and the writer thread.
#[derive(Debug, Default)]
struct Queue {
    pending: Mutex<Pending>,
    /// Signalled when a line is queued.
    queued: Condvar,
    /// Signalled when the writer has written every queued line.
    written: Condvar,
}

#[derive(Debug, Default)]
struct Pending {
    lines: VecDeque<String>,
    /// Lines dropped since the last one that fitted.
    dropped: u64,
    /// The writer is writing a line it took from `lines`.
    writing: bool,
}

impl Log {
    /// Start the writer thread.
    pub fn start(verbosity: u8) -> io::Result<Log> {
        let queue = Arc::new(Queue::default());
        let writer = Arc::clone(&queue);
        thread::Builder::new().name("log".into()).spawn(move || writer.write_lines())?;
        Ok(Log { verbosity, queue })
    }

    /// Startup and errors: always logged.
    pub fn info(&self, message: impl Display) {
        self.queue.push(message.to_string());
    }

    /// Connections, enumeration and presence (`-v`).
    pub fn verbose(&self, message: impl Display) {
        if self.verbosity >= VERBOSE {
            self.info(message);
        }
    }

    /// Frame types and sizes (`-vv`).
    pub fn trace(&self, message: impl Display) {
        if self.verbosity >= TRACE {
            self.info(message);
        }
    }

    /// Wait until every line logged so far is written, at most `limit`.
    pub fn flush(&self, limit: Duration) {
        let deadline = Instant::now() + limit;
        let mut pending = self.queue.lock();
        if pending.dropped > 0 {
            report_dropped(&mut pending);
            self.queue.queued.notify_one();
        }
        while !pending.lines.is_empty() || pending.writing {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            pending = self.queue.written.wait_timeout(pending, left).unwrap_or_else(PoisonError::into_inner).0;
        }
    }
}

impl Queue {
    fn lock(&self) -> MutexGuard<'_, Pending> {
        // Every update is a few assignments; a panic cannot leave the queue unusable.
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queue one line, or count it as dropped when the queue is full.
    fn push(&self, line: String) {
        let mut pending = self.lock();
        if pending.lines.len() >= QUEUE_LINES {
            pending.dropped = pending.dropped.saturating_add(1);
            return;
        }
        if pending.dropped > 0 {
            report_dropped(&mut pending);
        }
        pending.lines.push_back(line);
        self.queued.notify_one();
    }

    /// The writer thread: write the lines in order, for the rest of the process.
    fn write_lines(&self) {
        let mut pending = self.lock();
        loop {
            let Some(text) = pending.lines.pop_front() else {
                self.written.notify_all();
                pending = self.queued.wait(pending).unwrap_or_else(PoisonError::into_inner);
                continue;
            };
            pending.writing = true;
            drop(pending);
            line(text);
            pending = self.lock();
            pending.writing = false;
        }
    }
}

/// Queue the count of dropped lines where they were dropped (it may exceed the bound by
/// this one line).
fn report_dropped(pending: &mut Pending) {
    let dropped = std::mem::take(&mut pending.dropped);
    pending.lines.push_back(format!("{dropped} log line(s) dropped: stderr was not read fast enough"));
}

/// One `localkeyd: ` line on stderr, formatted first and written whole with one `write_all`.
pub fn line(message: impl Display) {
    let text = format!("localkeyd: {message}\n");
    let _ = io::stderr().lock().write_all(text.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A log without its writer thread: nothing leaves the queue unless the test takes it.
    fn unwritten() -> Log {
        Log { verbosity: TRACE, queue: Arc::new(Queue::default()) }
    }

    fn take(log: &Log) -> Option<String> {
        log.queue.lock().lines.pop_front()
    }

    #[test]
    fn levels_decide_what_is_queued() {
        let log = Log { verbosity: 0, ..unwritten() };
        log.info("startup");
        log.verbose("connected");
        log.trace("frame");
        assert_eq!(log.queue.lock().lines, ["startup"]);
        let log = Log { verbosity: VERBOSE, ..unwritten() };
        log.verbose("connected");
        log.trace("frame");
        assert_eq!(log.queue.lock().lines, ["connected"]);
    }

    #[test]
    fn a_full_queue_drops_lines_and_says_how_many_where_they_were_dropped() {
        let log = unwritten();
        for n in 0..QUEUE_LINES + 3 {
            log.info(n);
        }
        assert_eq!(log.queue.lock().lines.len(), QUEUE_LINES, "logging returned at once");
        assert_eq!(take(&log).as_deref(), Some("0"));
        log.info("after");
        let pending = log.queue.lock();
        let tail: Vec<&str> = pending.lines.iter().rev().take(3).rev().map(String::as_str).collect();
        let last_kept = (QUEUE_LINES - 1).to_string();
        assert_eq!(tail, [last_kept.as_str(), "3 log line(s) dropped: stderr was not read fast enough", "after"]);
        assert_eq!(pending.dropped, 0);
    }

    #[test]
    fn flush_reports_dropped_lines_and_gives_up_after_its_limit_when_nothing_writes() {
        let log = unwritten();
        for n in 0..=QUEUE_LINES {
            log.info(n);
        }
        let started = Instant::now();
        log.flush(Duration::from_millis(100));
        let waited = started.elapsed();
        assert!(waited >= Duration::from_millis(100), "flushed after {waited:?}");
        assert!(waited < Duration::from_secs(30), "flushed after {waited:?}");
        let last = log.queue.lock().lines.back().cloned();
        assert_eq!(last.as_deref(), Some("1 log line(s) dropped: stderr was not read fast enough"));
    }
}
