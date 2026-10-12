//! Shared test harness: private temporary directories, a fake runner that stands in for
//! `lk_run::Runner` on the other end of the `Sender<Command>`, and sample device values.
//!
//! The fake runner owns the `Receiver<Command>`. It forwards every input and tap to the
//! test over a channel, answers `Status` with a fixed value and `Watch` with a scripted
//! sequence of presence states, and keeps the watchers so a test can send more changes.

#![allow(dead_code)]

use std::fs::{self, DirBuilder, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use lk_core::{Millis, UsbInterfaces};
use lk_device::UsbIdentity;
use lk_run::{Command, HostInput, Status};

/// How long a test waits for something that must happen. Generous, for loaded machines.
pub const WAIT: Duration = Duration::from_secs(10);
/// How long a test watches for something that must not happen.
pub const QUIET: Duration = Duration::from_millis(300);

pub type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A fresh 0700 directory under the system temporary directory with a short name (a Unix
/// socket path must fit in 104 bytes on macOS), removed on drop.
#[derive(Debug)]
pub struct TestDir(PathBuf);

impl TestDir {
    pub fn new() -> TestDir {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("lkw{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        DirBuilder::new().mode(0o700).create(&path).expect("the test directory can be created");
        fs::set_permissions(&path, Permissions::from_mode(0o700)).expect("the test directory mode can be set");
        TestDir(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    pub fn set_mode(&self, mode: u32) {
        fs::set_permissions(&self.0, Permissions::from_mode(mode)).expect("the test directory mode can be set");
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.0, Permissions::from_mode(0o700));
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// What the fake runner was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seen {
    Input(HostInput),
    Tap(Millis),
    TapPending,
    Status,
    Watch,
}

/// A stand-in for the runner thread.
#[derive(Debug)]
pub struct FakeRunner {
    sender: Sender<Command>,
    seen: Receiver<Seen>,
    watchers: Arc<Mutex<Vec<Sender<bool>>>>,
}

impl FakeRunner {
    /// Answer `Status` with `status` and every `Watch` with `presence`, in order.
    pub fn start(status: Status, presence: Vec<bool>) -> FakeRunner {
        let (sender, commands) = mpsc::channel::<Command>();
        let (record, seen) = mpsc::channel();
        let watchers = Arc::new(Mutex::new(Vec::new()));
        let kept = Arc::clone(&watchers);
        thread::spawn(move || {
            for command in commands {
                let event = match command {
                    Command::Input(input) => Seen::Input(input),
                    Command::Tap { hold_ms } => Seen::Tap(hold_ms),
                    Command::TapPending(reply) => {
                        let _ = reply.send(status.presence_pending);
                        Seen::TapPending
                    }
                    Command::Status(reply) => {
                        let _ = reply.send(status.clone());
                        Seen::Status
                    }
                    Command::Watch(watcher) => {
                        for &waiting in &presence {
                            let _ = watcher.send(waiting);
                        }
                        kept.lock().expect("the watcher list is not poisoned").push(watcher);
                        Seen::Watch
                    }
                    _ => continue,
                };
                let _ = record.send(event);
            }
        });
        FakeRunner { sender, seen, watchers }
    }

    /// A runner with [`status`] and no scripted presence.
    pub fn plain() -> FakeRunner {
        FakeRunner::start(status(), Vec::new())
    }

    pub fn sender(&self) -> Sender<Command> {
        self.sender.clone()
    }

    /// The next thing the runner was asked to do.
    pub fn next(&self) -> Seen {
        match self.seen.recv_timeout(WAIT) {
            Ok(seen) => seen,
            Err(RecvTimeoutError::Timeout) => panic!("the runner received nothing within {WAIT:?}"),
            Err(RecvTimeoutError::Disconnected) => panic!("the fake runner stopped"),
        }
    }

    /// The next input; anything else fails the test.
    pub fn input(&self) -> HostInput {
        match self.next() {
            Seen::Input(input) => input,
            other => panic!("expected an input, the runner saw {other:?}"),
        }
    }

    /// Nothing reaches the runner for [`QUIET`].
    pub fn assert_quiet(&self) {
        if let Ok(seen) = self.seen.recv_timeout(QUIET) {
            panic!("the runner unexpectedly saw {seen:?}");
        }
    }

    /// Send a presence change to every registered watcher; how many still listen.
    pub fn presence(&self, waiting: bool) -> usize {
        let mut watchers = self.watchers.lock().expect("the watcher list is not poisoned");
        watchers.retain(|watcher| watcher.send(waiting).is_ok());
        watchers.len()
    }
}

/// The status the fake runner reports.
pub fn status() -> Status {
    Status {
        serial: 12_345_678,
        product: "YubiKey 5C Nano".into(),
        interfaces: UsbInterfaces { otp: true, fido: true, ccid: true },
        presence_pending: false,
        serving: true,
        attached: Some(true),
        suspended: false,
        queued: 0,
        dropped: 2,
        unreadable: vec![lk_core::Record::Oath],
        uptime_ms: 4_321,
    }
}

/// A device identity, built by hand from the public `UsbIdentity` fields (the CCID class
/// descriptor is a placeholder of its real length, 54 bytes).
pub fn usb_identity(serial: Option<&str>) -> UsbIdentity {
    UsbIdentity {
        vendor_id: 0x1050,
        product_id: 0x0407,
        device_release: 0x0574,
        manufacturer: "Yubico".into(),
        product: "YubiKey OTP+FIDO+CCID".into(),
        serial: serial.map(String::from),
        interfaces: UsbInterfaces { otp: true, fido: true, ccid: true },
        fido_report_descriptor: lk_device::FIDO_REPORT_DESCRIPTOR.to_vec(),
        otp_report_descriptor: lk_device::OTP_REPORT_DESCRIPTOR.to_vec(),
        ccid_class_descriptor: vec![0x36; 54],
    }
}

/// Connect without the client library, with a read timeout of [`WAIT`].
pub fn raw_connect(path: &Path) -> io::Result<UnixStream> {
    let stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(WAIT))?;
    Ok(stream)
}

/// Read one whole frame (length, type, payload) without the codec.
pub fn read_raw_frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let mut rest = vec![0; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut rest)?;
    let mut frame = length.to_vec();
    frame.extend_from_slice(&rest);
    Ok(frame)
}

/// The peer closed: a read gives end of stream (or a reset) within [`WAIT`].
pub fn assert_closed(stream: &mut UnixStream) {
    let mut byte = [0; 1];
    match stream.read(&mut byte) {
        Ok(0) => {}
        Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
        other => panic!("expected the connection to be closed, got {other:?}"),
    }
}

/// Wait until `condition` holds, failing the test after [`WAIT`].
pub fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !condition() {
        assert!(Instant::now() < deadline, "{what} did not happen within {WAIT:?}");
        thread::sleep(Duration::from_millis(10));
    }
}

/// Whether a one-byte write tells that the server has shut the connection down, without
/// reading (reading would unblock a server writer that waits for the client). A write that
/// succeeds only means the byte went into the server's receive buffer.
pub fn server_closed(stream: &mut UnixStream) -> bool {
    match stream.write_all(&[0]) {
        Ok(()) => false,
        Err(error) => matches!(
            error.kind(),
            io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset | io::ErrorKind::NotConnected
        ),
    }
}

/// Drop `value` on another thread; whether the drop finished within [`WAIT`]. A drop that
/// hangs leaves its thread behind instead of hanging the test.
pub fn drops_in_time<T: Send + 'static>(value: T) -> bool {
    let (done, finished) = mpsc::channel();
    thread::spawn(move || {
        drop(value);
        let _ = done.send(());
    });
    finished.recv_timeout(WAIT).is_ok()
}

/// One control request; the whole reply up to the server's close.
pub fn control(path: &Path, request: &str) -> io::Result<String> {
    let mut stream = raw_connect(path)?;
    stream.write_all(request.as_bytes())?;
    let mut reply = String::new();
    stream.read_to_string(&mut reply)?;
    Ok(reply)
}
