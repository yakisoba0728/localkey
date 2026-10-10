//! End-to-end harness: the real `localkeyd` binary as a child process in a fresh private
//! directory, and a USB host that speaks CTAPHID reports and CCID messages to it over the
//! wire socket with `lk_wire::Client`.
//!
//! Byte layouts are written from the specifications, as in `crates/lk-device/tests/common`:
//! CTAPHID packets from CTAP 2.1 §11.2.4, CCID messages from USB CCID Rev 1.1 §6.1/§6.2,
//! APDUs from ISO/IEC 7816-4 §5.1, OATH from Yubico's YKOATH protocol.
//!
//! Every daemon runs inside a [`Daemon`] guard, which kills it (SIGKILL) and reaps it when
//! dropped, and every directory inside a [`TestDir`], which removes it; a test that fails
//! half way leaves neither a process nor a directory behind.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fs::{self, DirBuilder, Permissions};
use std::io::{self, BufRead, BufReader};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use lk_run::HostInput;
use lk_wire::{Client, Frame};

/// The binary under test.
pub const BIN: &str = env!("CARGO_BIN_EXE_localkeyd");
/// How long a test waits for something that must happen. Generous: a debug build on a
/// loaded machine (other crates build at the same time) can be slow to open the device.
pub const WAIT: Duration = Duration::from_secs(60);

pub type TestResult = Result<(), Box<dyn Error>>;

/// CTAPHID (CTAP 2.1 §11.2.9).
pub const CTAPHID_MSG: u8 = 0x03;
pub const CTAPHID_INIT: u8 = 0x06;
pub const CTAPHID_CBOR: u8 = 0x10;
pub const CTAPHID_KEEPALIVE: u8 = 0x3B;
pub const BROADCAST: u32 = 0xFFFF_FFFF;
/// KEEPALIVE status: waiting for user presence (CTAP 2.1 §11.2.9.1.7).
pub const STATUS_UPNEEDED: u8 = 0x02;

/// The OATH application (`docs/CONTRACTS.md` "Application crates").
pub const AID_OATH: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];

/// A fresh 0700 directory under the system temporary directory with a short name (socket
/// paths inside it must fit in 104 bytes on macOS), removed on drop. The daemon's state
/// directory is [`TestDir::state`], created by the daemon itself.
#[derive(Debug)]
pub struct TestDir(PathBuf);

impl TestDir {
    pub fn new() -> TestDir {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("lkd{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        DirBuilder::new().mode(0o700).create(&path).expect("the test directory can be created");
        fs::set_permissions(&path, Permissions::from_mode(0o700)).expect("the test directory mode can be set");
        TestDir(path)
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// The daemon's state directory.
    pub fn state(&self) -> PathBuf {
        self.join("s")
    }

    /// The storage key file most tests use (written by [`keygen`]).
    pub fn key(&self) -> PathBuf {
        self.join("k")
    }

    /// The default socket paths of a daemon on [`TestDir::state`].
    pub fn wire(&self) -> PathBuf {
        self.state().join("wire.sock")
    }

    pub fn control(&self) -> PathBuf {
        self.state().join("control.sock")
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Run `localkeyd` with `args` to completion (keygen, ctl and usage errors end on their own).
pub fn localkeyd<I, S>(args: I) -> io::Result<Output>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    Command::new(BIN).args(args.into_iter().map(Into::into)).stdin(Stdio::null()).output()
}

/// `localkeyd keygen --key-file path`, which must succeed.
pub fn keygen(path: &Path) -> TestResult {
    let output = localkeyd([OsString::from("keygen"), "--key-file".into(), path.into()])?;
    if !output.status.success() {
        return Err(format!("keygen failed: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    Ok(())
}

/// `localkeyd ctl --control path words...`.
pub fn ctl(control: &Path, words: &[&str]) -> io::Result<Output> {
    let mut args = vec![OsString::from("ctl"), "--control".into(), control.into()];
    args.extend(words.iter().map(OsString::from));
    localkeyd(args)
}

/// The text of a finished process's stdout or stderr.
pub fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The serial in the state directory's `identity` file (`serial=<decimal>\n`).
pub fn persisted_serial(state: &Path) -> Result<String, Box<dyn Error>> {
    let identity = fs::read_to_string(state.join("identity"))?;
    let serial = identity.strip_prefix("serial=").and_then(|rest| rest.strip_suffix('\n'));
    Ok(serial.ok_or("the identity file has an unexpected form")?.to_owned())
}

/// Every `*.rec` file in the state directory with its bytes.
pub fn record_files(state: &Path) -> io::Result<BTreeMap<String, Vec<u8>>> {
    let mut records = BTreeMap::new();
    for entry in fs::read_dir(state)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".rec") {
            records.insert(name, fs::read(entry.path())?);
        }
    }
    Ok(records)
}

/// A running `localkeyd run`, killed and reaped on drop. Its stderr is collected on a
/// thread, so the daemon never blocks on a full pipe and the test can read the log.
#[derive(Debug)]
pub struct Daemon {
    child: Child,
    log: Arc<Mutex<String>>,
    reader: Option<JoinHandle<()>>,
}

impl Daemon {
    /// Start `localkeyd run --state <state> --exit-on-stdin-eof <args>` with stdin piped
    /// (closing it is the clean shutdown) and wait until it serves.
    pub fn start(dir: &TestDir, args: &[&str]) -> Result<Daemon, Box<dyn Error>> {
        let mut daemon = Daemon::spawn(dir, args)?;
        daemon.wait_serving()?;
        Ok(daemon)
    }

    /// [`Daemon::start`] with the key file [`TestDir::key`] and `extra` options.
    pub fn with_key(dir: &TestDir, extra: &[&str]) -> Result<Daemon, Box<dyn Error>> {
        let key = dir.key();
        let mut args = vec!["--key-file", key.to_str().ok_or("the key path is not UTF-8")?];
        args.extend_from_slice(extra);
        Daemon::start(dir, &args)
    }

    /// Start the daemon without waiting for it to serve.
    pub fn spawn(dir: &TestDir, args: &[&str]) -> io::Result<Daemon> {
        let mut child = Command::new(BIN)
            .arg("run")
            .arg("--state")
            .arg(dir.state())
            .arg("--exit-on-stdin-eof")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let log = Arc::new(Mutex::new(String::new()));
        let reader = child.stderr.take().map(|stderr| collect(stderr, Arc::clone(&log)));
        Ok(Daemon { child, log, reader })
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// What the daemon has written to stderr so far.
    pub fn log(&self) -> String {
        self.log.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// Wait until the log contains `expected`. The daemon writes its log from its own
    /// thread and this harness collects it on another, so a line can arrive after the
    /// frame or reply it goes with.
    pub fn wait_log(&self, expected: &str) -> Result<(), Box<dyn Error>> {
        let deadline = Instant::now() + WAIT;
        while !self.log().contains(expected) {
            if Instant::now() > deadline {
                return Err(format!("{expected:?} not in the log within {WAIT:?}:\n{}", self.log()).into());
            }
            thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }

    /// Wait until the daemon logs that it serves; an exit before that fails with its log.
    pub fn wait_serving(&mut self) -> Result<(), Box<dyn Error>> {
        let deadline = Instant::now() + WAIT;
        loop {
            if self.log().contains("localkeyd: serving") {
                return Ok(());
            }
            if let Some(status) = self.child.try_wait()? {
                return Err(format!("the daemon exited ({status}) before serving:\n{}", self.log()).into());
            }
            if Instant::now() > deadline {
                return Err(format!("the daemon did not serve within {WAIT:?}:\n{}", self.log()).into());
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// Wait for the daemon to exit on its own, then for its log to be complete.
    pub fn wait_exit(&mut self) -> Result<ExitStatus, Box<dyn Error>> {
        let deadline = Instant::now() + WAIT;
        let status = loop {
            if let Some(status) = self.child.try_wait()? {
                break status;
            }
            if Instant::now() > deadline {
                return Err(format!("the daemon did not exit within {WAIT:?}:\n{}", self.log()).into());
            }
            thread::sleep(Duration::from_millis(20));
        };
        if let Some(reader) = self.reader.take() {
            reader.join().map_err(|_| "the stderr reader panicked")?;
        }
        Ok(status)
    }

    /// Close the daemon's stdin (with `--exit-on-stdin-eof`, the clean shutdown) and wait
    /// for it to exit.
    pub fn stop(&mut self) -> Result<ExitStatus, Box<dyn Error>> {
        drop(self.child.stdin.take());
        self.wait_exit()
    }

    /// SIGKILL: a crash, with no chance to clean up.
    pub fn kill(&mut self) -> Result<(), Box<dyn Error>> {
        self.child.kill()?;
        self.wait_exit()?;
        Ok(())
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

/// Append every line of `stderr` to `log` until the pipe closes.
fn collect(stderr: ChildStderr, log: Arc<Mutex<String>>) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut stderr = BufReader::new(stderr);
        let mut line = Vec::new();
        while matches!(stderr.read_until(b'\n', &mut line), Ok(read) if read > 0) {
            log.lock().unwrap_or_else(PoisonError::into_inner).push_str(&String::from_utf8_lossy(&line));
            line.clear();
        }
    })
}

/// The USB host on the other end of the wire socket.
#[derive(Debug)]
pub struct Host {
    pub client: Client,
    /// `bSeq` of the next CCID message.
    seq: u8,
}

impl Host {
    /// Plug in: connect and take the IDENTITY.
    pub fn connect(dir: &TestDir) -> Result<Host, Box<dyn Error>> {
        Ok(Host { client: Client::connect_timeout(&dir.wire(), WAIT)?, seq: 0 })
    }

    /// The next frame from the daemon, of any type.
    pub fn frame(&mut self) -> Result<Frame, Box<dyn Error>> {
        Ok(self.client.recv(WAIT)?.ok_or_else(|| format!("no frame from the daemon within {WAIT:?}"))?)
    }

    // ----- CTAPHID (CTAP 2.1 §11.2.4) -----

    /// Send a message as 64-byte packets: an initialization packet `cid || 0x80 | cmd ||
    /// bcnt || 57 bytes`, then continuation packets `cid || seq || 59 bytes`.
    pub fn ctaphid_send(&mut self, cid: u32, cmd: u8, payload: &[u8]) -> TestResult {
        let length = u16::try_from(payload.len())?;
        let mut first = [0u8; 64];
        first[..4].copy_from_slice(&cid.to_be_bytes());
        first[4] = 0x80 | cmd;
        first[5..7].copy_from_slice(&length.to_be_bytes());
        let (head, rest) = payload.split_at(payload.len().min(57));
        first[7..7 + head.len()].copy_from_slice(head);
        self.client.send(&HostInput::FidoReport(first))?;
        for (seq, chunk) in rest.chunks(59).enumerate() {
            let mut packet = [0u8; 64];
            packet[..4].copy_from_slice(&cid.to_be_bytes());
            packet[4] = u8::try_from(seq)?;
            packet[5..5 + chunk.len()].copy_from_slice(chunk);
            self.client.send(&HostInput::FidoReport(packet))?;
        }
        Ok(())
    }

    /// The next whole CTAPHID message on `cid`, keepalives included. Frames of other
    /// interfaces and reports of other channels are skipped.
    pub fn ctaphid_message(&mut self, cid: u32) -> Result<(u8, Vec<u8>), Box<dyn Error>> {
        let mut partial: Option<(u8, usize, Vec<u8>)> = None;
        loop {
            let Frame::FidoIn(report) = self.frame()? else { continue };
            if report[..4] != cid.to_be_bytes() {
                continue;
            }
            let (cmd, length, mut data, chunk) = if report[4] & 0x80 != 0 {
                let length = usize::from(u16::from_be_bytes([report[5], report[6]]));
                (report[4] & 0x7F, length, Vec::new(), &report[7..])
            } else {
                let Some((cmd, length, data)) = partial.take() else { continue };
                (cmd, length, data, &report[5..])
            };
            let missing = length - data.len();
            data.extend_from_slice(&chunk[..missing.min(chunk.len())]);
            if data.len() == length {
                return Ok((cmd, data));
            }
            partial = Some((cmd, length, data));
        }
    }

    /// The response on `cid`, after any KEEPALIVE messages.
    pub fn ctaphid_response(&mut self, cid: u32) -> Result<(u8, Vec<u8>), Box<dyn Error>> {
        loop {
            let (cmd, payload) = self.ctaphid_message(cid)?;
            if cmd != CTAPHID_KEEPALIVE {
                return Ok((cmd, payload));
            }
        }
    }

    /// CTAPHID_INIT on the broadcast channel (§11.2.9.1.3); the allocated channel.
    pub fn ctaphid_init(&mut self) -> Result<u32, Box<dyn Error>> {
        let nonce = [0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE];
        self.ctaphid_send(BROADCAST, CTAPHID_INIT, &nonce)?;
        let (cmd, payload) = self.ctaphid_response(BROADCAST)?;
        if cmd != CTAPHID_INIT || payload.len() < 17 || payload[..8] != nonce {
            return Err(format!("unexpected INIT response: command {cmd:02x}, {payload:02x?}").into());
        }
        Ok(u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]))
    }

    /// A CTAP2 request (`CTAPHID_CBOR`, command byte then parameters) and its response.
    pub fn cbor(&mut self, cid: u32, request: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        self.ctaphid_send(cid, CTAPHID_CBOR, request)?;
        match self.ctaphid_response(cid)? {
            (CTAPHID_CBOR, payload) => Ok(payload),
            (cmd, payload) => Err(format!("expected a CBOR response, got command {cmd:02x}: {payload:02x?}").into()),
        }
    }

    // ----- CCID (USB CCID Rev 1.1 §6.1, §6.2) -----

    /// Send a `PC_to_RDR_*` message (10-byte header, slot 0) and return the reply with
    /// the same `bSeq`. Time-extension DataBlocks (`bStatus` bit 7, §6.2.6) and other
    /// frames are skipped.
    fn ccid(&mut self, kind: u8, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        let mut message = vec![kind];
        message.extend_from_slice(&u32::try_from(data.len())?.to_le_bytes());
        message.extend_from_slice(&[0, seq, 0, 0, 0]);
        message.extend_from_slice(data);
        self.client.send(&HostInput::Ccid(message))?;
        loop {
            let Frame::CcidBulkIn(reply) = self.frame()? else { continue };
            if reply.len() < 10 || reply[6] != seq {
                continue;
            }
            if reply[0] == 0x80 && reply[7] & 0x80 != 0 {
                continue;
            }
            return Ok(reply);
        }
    }

    /// The data of a successful `RDR_to_PC_DataBlock` reply.
    fn data_block(reply: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        if reply[0] != 0x80 || reply[7] & 0xC0 != 0 {
            return Err(format!("not a successful DataBlock: {reply:02x?}").into());
        }
        Ok(reply[10..].to_vec())
    }

    /// `PC_to_RDR_IccPowerOn` (§6.1.1); the ATR.
    pub fn power_on(&mut self) -> Result<Vec<u8>, Box<dyn Error>> {
        let reply = self.ccid(0x62, &[])?;
        Self::data_block(reply)
    }

    /// `PC_to_RDR_XfrBlock` (§6.1.4) carrying `apdu`; the response APDU (data || SW).
    pub fn apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let reply = self.ccid(0x6F, apdu)?;
        Self::data_block(reply)
    }

    /// SELECT by DF name (ISO/IEC 7816-4 §11.2.2), short form with Le.
    pub fn select(&mut self, aid: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut apdu = vec![0x00, 0xA4, 0x04, 0x00, u8::try_from(aid.len())?];
        apdu.extend_from_slice(aid);
        apdu.push(0x00);
        self.apdu(&apdu)
    }
}

/// The status word at the end of a response APDU.
pub fn sw(response: &[u8]) -> u16 {
    match response {
        [.., sw1, sw2] => u16::from_be_bytes([*sw1, *sw2]),
        _ => 0,
    }
}

/// YKOATH PUT (INS `01`) of a TOTP/SHA-1 credential (`21`) with 6 digits and a 20-byte
/// secret: `71 name, 73 len 21 06 secret`.
pub fn oath_put(name: &[u8]) -> Vec<u8> {
    let mut data = vec![0x71, name.len() as u8];
    data.extend_from_slice(name);
    data.extend_from_slice(&[0x73, 22, 0x21, 6]);
    data.extend_from_slice(&[0x11; 20]);
    let mut apdu = vec![0x00, 0x01, 0x00, 0x00, data.len() as u8];
    apdu.extend_from_slice(&data);
    apdu
}

/// YKOATH LIST (INS `A1`).
pub const OATH_LIST: [u8; 4] = [0x00, 0xA1, 0x00, 0x00];

/// The LIST response for exactly one TOTP/SHA-1 credential `name`: `72 len 21 name`, then
/// `90 00`.
pub fn oath_list_of_one(name: &[u8]) -> Vec<u8> {
    let mut expected = vec![0x72, name.len() as u8 + 1, 0x21];
    expected.extend_from_slice(name);
    expected.extend_from_slice(&[0x90, 0x00]);
    expected
}

/// The `key=value` lines of a `ctl status` reply, in order, without the final `ok`.
pub fn status_pairs(stdout: &str) -> Vec<(String, String)> {
    stdout
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

/// The value of `key` in a `ctl status` reply.
pub fn status_value(stdout: &str, key: &str) -> Option<String> {
    status_pairs(stdout).into_iter().find(|(name, _)| name == key).map(|(_, value)| value)
}
