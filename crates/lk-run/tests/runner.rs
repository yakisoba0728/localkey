//! The runner thread against a recording transport (`docs/PROGRAM.md` "lk-run").
//!
//! CTAPHID packets are written from CTAP 2.1 §11.2.4 (initialization packet: CID,
//! `0x80 | cmd`, big-endian length, data); every message here fits one packet. Timing
//! checks use generous margins: they assert what happens, never how quickly.

#![allow(clippy::unwrap_used)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, ThreadId};
use std::time::{Duration, Instant};

use lk_core::{DeviceProfile, Record, Store, StoreError, UsbInterfaces};
use lk_device::{BusEvent, Device, Output, TouchEdge, UsbIdentity};
use lk_run::{Command, HostInput, RunError, Runner, RunnerConfig, TAP_LONG_MS, TAP_SHORT_MS, Transport};
use lk_testkit::{MemoryStore, SeededEntropy};

const KEY: [u8; 32] = [0x5A; 32];
const SERIAL: u32 = 12_345_678;
/// How long a test waits for something that must happen.
const WAIT: Duration = Duration::from_secs(10);

/// CTAPHID (CTAP 2.1 §11.2.9).
const BROADCAST: u32 = 0xFFFF_FFFF;
const CTAPHID_INIT: u8 = 0x06;
const CTAPHID_CBOR: u8 = 0x10;
const CTAPHID_KEEPALIVE: u8 = 0x3B;
const KEEPALIVE_UPNEEDED: u8 = 0x02;
/// Yubico vendor command WRITE CONFIG (`lk-mgmt`, catalog "CTAPHID vendor 0x42 / 0x43").
const CTAPHID_WRITE_CONFIG: u8 = 0x43;
/// authenticatorSelection (CTAP 2.1 §6.9): waits for user presence, answers `00`.
const SELECTION: [u8; 1] = [0x0B];
/// WRITE CONFIG data `len || TLVs` (yubikit `DeviceConfig.get_bytes`): USB enabled
/// applications (tag `03`) OTP | U2F | FIDO2 = `0203`, then REBOOT (tag `0C`).
const OTP_FIDO_WITH_REBOOT: [u8; 7] = [0x06, 0x03, 0x02, 0x02, 0x03, 0x0C, 0x00];

/// One call the runner made on the transport.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Enumerate(UsbIdentity),
    Deliver(Output),
}

/// A transport that records every call in order, and copies it to a channel the test
/// can wait on.
#[derive(Debug)]
struct Recorder {
    log: Arc<Mutex<Vec<Event>>>,
    events: Sender<Event>,
}

impl Recorder {
    fn record(&mut self, event: Event) {
        self.log.lock().unwrap().push(event.clone());
        let _ = self.events.send(event);
    }
}

impl Transport for Recorder {
    fn enumerate(&mut self, identity: &UsbIdentity) {
        self.record(Event::Enumerate(identity.clone()));
    }

    fn deliver(&mut self, output: Output) {
        self.record(Event::Deliver(output));
    }

    fn attached(&self) -> Option<bool> {
        Some(true)
    }
}

/// A transport that spends `delay` on every delivery, like a slow peer, and counts them.
#[derive(Debug)]
struct Slow {
    delay: Duration,
    delivered: Arc<AtomicUsize>,
    enumerated: Sender<()>,
}

impl Transport for Slow {
    fn enumerate(&mut self, _identity: &UsbIdentity) {
        let _ = self.enumerated.send(());
    }

    fn deliver(&mut self, _output: Output) {
        thread::sleep(self.delay);
        self.delivered.fetch_add(1, Ordering::SeqCst);
    }
}

/// A store that panics on save once armed, to fail the device on the runner thread.
struct PanickingStore {
    inner: MemoryStore,
    armed: Arc<AtomicBool>,
}

impl Store for PanickingStore {
    fn load(&mut self, record: Record) -> Result<Option<Vec<u8>>, StoreError> {
        self.inner.load(record)
    }

    fn save(&mut self, record: Record, sealed: &[u8]) -> Result<(), StoreError> {
        assert!(!self.armed.load(Ordering::SeqCst), "injected store panic");
        self.inner.save(record, sealed)
    }
}

/// A store that records the thread it is dropped on (the device drops it).
struct DropProbe {
    inner: MemoryStore,
    dropped_on: ThreadRecord,
}

impl Store for DropProbe {
    fn load(&mut self, record: Record) -> Result<Option<Vec<u8>>, StoreError> {
        self.inner.load(record)
    }

    fn save(&mut self, record: Record, sealed: &[u8]) -> Result<(), StoreError> {
        self.inner.save(record, sealed)
    }
}

impl Drop for DropProbe {
    fn drop(&mut self) {
        *self.dropped_on.lock().unwrap() = Some(thread::current().id());
    }
}

fn open(store: Box<dyn Store>) -> Result<Device, String> {
    let profile = DeviceProfile::yubikey_5c_nano_5_7_4(SERIAL);
    Ok(Device::open(profile, store, Box::new(SeededEntropy::new(1)), KEY))
}

/// The initialization packet of a single-packet CTAPHID message.
fn packet(cid: u32, cmd: u8, payload: &[u8]) -> [u8; 64] {
    assert!(payload.len() <= 57, "single packet only");
    let mut report = [0u8; 64];
    report[..4].copy_from_slice(&cid.to_be_bytes());
    report[4] = 0x80 | cmd;
    report[5..7].copy_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    report[7..7 + payload.len()].copy_from_slice(payload);
    report
}

/// `(cid, cmd, payload)` of a delivered single-packet CTAPHID message.
fn message(event: &Event) -> (u32, u8, Vec<u8>) {
    let Event::Deliver(Output::FidoReport(report)) = event else {
        panic!("expected a FIDO report, got {event:02X?}");
    };
    assert_ne!(report[4] & 0x80, 0, "an initialization packet: {report:02X?}");
    let len = usize::from(u16::from_be_bytes([report[5], report[6]]));
    assert!(len <= 57, "single packet only: {report:02X?}");
    let cid = u32::from_be_bytes([report[0], report[1], report[2], report[3]]);
    (cid, report[4] & 0x7F, report[7..7 + len].to_vec())
}

fn is_keepalive(event: &Event) -> bool {
    matches!(event, Event::Deliver(Output::FidoReport(report)) if report[4] == 0x80 | CTAPHID_KEEPALIVE)
}

const NONCE_A: [u8; 8] = [0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8];
const NONCE_B: [u8; 8] = [0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8];
const NONCE_C: [u8; 8] = [0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8];
const NONCE_D: [u8; 8] = [0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8];

/// A runner with a [`Recorder`] ready to attach.
struct Bench {
    runner: Runner,
    sender: Sender<Command>,
    log: Arc<Mutex<Vec<Event>>>,
    events: Receiver<Event>,
    recorder: Option<Recorder>,
}

impl Bench {
    /// A runner on a fresh `MemoryStore`, not serving yet.
    fn spawn(config: RunnerConfig) -> Bench {
        let store = MemoryStore::new();
        Bench::with_runner(Runner::spawn(move || open(Box::new(store)), config).unwrap())
    }

    fn with_runner(runner: Runner) -> Bench {
        let (events_tx, events) = mpsc::channel();
        let log = Arc::new(Mutex::new(Vec::new()));
        let recorder = Recorder { log: Arc::clone(&log), events: events_tx };
        Bench { sender: runner.sender(), runner, log, events, recorder: Some(recorder) }
    }

    /// A serving runner whose first transport call, the enumeration, has been checked.
    fn serving(config: RunnerConfig) -> Bench {
        let mut bench = Bench::spawn(config);
        bench.serve();
        assert_eq!(bench.next(), Event::Enumerate(bench.runner.ready().identity.clone()));
        bench
    }

    fn serve(&mut self) {
        let recorder = self.recorder.take().unwrap();
        self.runner.serve(Box::new(recorder)).unwrap();
    }

    /// The next transport call.
    fn next(&self) -> Event {
        self.events.recv_timeout(WAIT).unwrap_or_else(|error| panic!("no transport call within {WAIT:?}: {error}"))
    }

    /// The next transport call that is not a KEEPALIVE.
    fn next_skipping_keepalives(&self) -> Event {
        let deadline = Instant::now() + WAIT;
        loop {
            let event = self
                .events
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|error| panic!("only keepalives within {WAIT:?}: {error}"));
            if !is_keepalive(&event) {
                return event;
            }
        }
    }

    /// Fail on anything but KEEPALIVEs for `period`.
    fn only_keepalives_for(&self, period: Duration) {
        let deadline = Instant::now() + period;
        while let Ok(event) = self.events.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            assert!(is_keepalive(&event), "expected only keepalives, got {event:02X?}");
        }
    }

    /// Whether no transport call is waiting to be read.
    fn quiet(&self) -> bool {
        self.events.try_recv().is_err()
    }

    fn input(&self, input: HostInput) {
        self.sender.send(Command::Input(input)).unwrap();
    }

    fn fido(&self, cid: u32, cmd: u8, payload: &[u8]) {
        self.input(HostInput::FidoReport(packet(cid, cmd, payload)));
    }

    fn tap(&self, hold_ms: u64) {
        self.sender.send(Command::Tap { hold_ms }).unwrap();
    }

    /// The status, which also proves every command sent before was handled.
    fn sync(&self) -> lk_run::Status {
        self.runner.status().unwrap()
    }

    /// Broadcast INIT with `nonce` and return the allocated channel.
    fn init(&self, nonce: [u8; 8]) -> u32 {
        self.fido(BROADCAST, CTAPHID_INIT, &nonce);
        self.expect_init_response(nonce)
    }

    fn expect_init_response(&self, nonce: [u8; 8]) -> u32 {
        let (cid, cmd, payload) = message(&self.next());
        assert_eq!((cid, cmd, payload.len()), (BROADCAST, CTAPHID_INIT, 17));
        assert_eq!(payload[..8], nonce, "the response echoes the nonce");
        u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]])
    }

    /// authenticatorSelection on `cid`: the indicator at once, then the first
    /// KEEPALIVE(UPNEEDED) one interval (95 ms) later. Measured on a YubiKey 5C Nano 5.7.4
    /// (docs/MEASUREMENT.md, probe selection-keepalive-cancel: no KEEPALIVE at once); the
    /// KEEPALIVE came first, at once, before the measurement.
    fn request_presence(&self, cid: u32) {
        self.fido(cid, CTAPHID_CBOR, &SELECTION);
        assert_eq!(self.next(), Event::Deliver(Output::PresenceIndicator(true)));
        assert_eq!(message(&self.next()), (cid, CTAPHID_KEEPALIVE, vec![KEEPALIVE_UPNEEDED]));
    }

    /// The answer to authenticatorSelection, then the indicator going out.
    fn expect_presence_granted(&self, cid: u32) {
        assert_eq!(message(&self.next_skipping_keepalives()), (cid, CTAPHID_CBOR, vec![0x00]));
        assert_eq!(self.next(), Event::Deliver(Output::PresenceIndicator(false)));
    }
}

/// `Ready` carries `Device::unreadable_records()`, the USB identity, the serial and the
/// profile's product name; `Status` reports the same before anything is attached.
#[test]
fn spawn_reports_unreadable_records_and_the_identity() {
    let store = MemoryStore::new();
    store.insert(Record::Oath, b"not a sealed record");
    let runner = Runner::spawn(move || open(Box::new(store)), RunnerConfig::default()).unwrap();
    let all = UsbInterfaces { otp: true, fido: true, ccid: true };
    let ready = runner.ready();
    assert_eq!(ready.unreadable, [Record::Oath]);
    assert_eq!((ready.serial, ready.product.as_str()), (SERIAL, "YubiKey"));
    assert_eq!(ready.identity.interfaces, all);
    assert_eq!((ready.identity.vendor_id, ready.identity.product_id), (0x1050, 0x0407));
    assert_eq!(ready.identity.product, "YubiKey OTP+FIDO+CCID");
    let status = runner.status().unwrap();
    assert_eq!(status.unreadable, [Record::Oath]);
    assert_eq!((status.serial, status.product.as_str(), status.interfaces), (SERIAL, "YubiKey", all));
    assert!(!status.serving && !status.suspended && !status.presence_pending);
    assert_eq!((status.attached, status.queued, status.dropped), (None, 0, 0));
    runner.shutdown().unwrap();
}

/// `docs/PROGRAM.md` "lk-run": `serve` calls `enumerate` first, then inputs flow; a
/// CTAPHID INIT broadcast (CTAP 2.1 §11.2.9.1.3) is answered through `deliver`.
#[test]
fn serve_enumerates_first_and_an_init_broadcast_is_answered_through_deliver() {
    let mut bench = Bench::spawn(RunnerConfig::default());
    bench.serve();
    bench.fido(BROADCAST, CTAPHID_INIT, &NONCE_A);
    let status = bench.sync();
    assert_eq!((status.serving, status.attached), (true, Some(true)));
    let log = bench.log.lock().unwrap().clone();
    assert_eq!(log.len(), 2, "{log:02X?}");
    assert_eq!(log[0], Event::Enumerate(bench.runner.ready().identity.clone()));
    let (cid, cmd, payload) = message(&log[1]);
    assert_eq!((cid, cmd, payload.len()), (BROADCAST, CTAPHID_INIT, 17));
    assert_eq!(payload[..8], NONCE_A);
    let allocated = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    assert!(allocated != 0 && allocated != BROADCAST, "{allocated:08X}");
    // The clock runs: uptime is the device's `now`.
    thread::sleep(Duration::from_millis(50));
    assert!(bench.sync().uptime_ms >= status.uptime_ms + 50);
}

/// `docs/PROGRAM.md` "lk-run": before `serve`, bus inputs and taps do not reach the
/// device; `Status` and `Watch` already work.
#[test]
fn inputs_before_serve_are_ignored() {
    let mut bench = Bench::spawn(RunnerConfig::default());
    let (watcher, watched) = mpsc::channel();
    bench.sender.send(Command::Watch(watcher)).unwrap();
    assert_eq!(watched.recv_timeout(WAIT), Ok(false));
    // A suspend that reached the device would make the resume below answer `50 03`, and
    // a press that reached it would keep the sensor held.
    bench.input(HostInput::Bus(BusEvent::Suspend));
    bench.input(HostInput::Touch(TouchEdge::Down));
    bench.tap(TAP_SHORT_MS);
    bench.fido(BROADCAST, CTAPHID_INIT, &NONCE_A);
    let status = bench.sync();
    assert!(!status.serving && !status.suspended);
    bench.serve();
    assert_eq!(bench.next(), Event::Enumerate(bench.runner.ready().identity.clone()));
    bench.input(HostInput::Bus(BusEvent::Resume));
    let cid = bench.init(NONCE_B);
    bench.request_presence(cid);
    bench.tap(TAP_SHORT_MS);
    bench.expect_presence_granted(cid);
}

/// The deadline loop: a request that waits for user presence gets a KEEPALIVE every
/// 95 ms (CTAP 2.1 §11.2.9.1.7; measured on a YubiKey 5C Nano 5.7.4, docs/MEASUREMENT.md,
/// probe selection-no-touch; 100 ms before the measurement) with no further input, and a
/// tap answers it.
#[test]
fn a_pending_presence_request_gets_keepalives_without_input_and_a_tap_answers_it() {
    let bench = Bench::serving(RunnerConfig::default());
    let cid = bench.init(NONCE_A);
    // The keepalive grid starts when the device takes the request, after this instant;
    // keepalives can be late on a loaded machine, never early.
    let asked = Instant::now();
    bench.request_presence(cid);
    for _ in 0..3 {
        assert_eq!(message(&bench.next()), (cid, CTAPHID_KEEPALIVE, vec![KEEPALIVE_UPNEEDED]));
    }
    // `request_presence` took the first keepalive (95 ms into the grid); the fourth is due
    // 380 ms into it (4 x 95 ms; it was the third after an immediate one, at 300 ms, before
    // the measurement), so with the same 50 ms slack as before at least 330 ms have passed.
    assert!(asked.elapsed() >= Duration::from_millis(330), "{:?}", asked.elapsed());
    assert!(bench.sync().presence_pending);
    bench.tap(TAP_SHORT_MS);
    bench.expect_presence_granted(cid);
    assert!(!bench.sync().presence_pending);
}

/// `Tap { hold_ms }` lets go of the sensor `hold_ms` later on its own: a later tap is
/// a new touch.
#[test]
fn a_tap_releases_the_sensor_after_its_hold_time() {
    let bench = Bench::serving(RunnerConfig::default());
    let cid = bench.init(NONCE_A);
    // Nothing is pending and no OTP slot is configured: the press is silent.
    bench.tap(TAP_SHORT_MS);
    thread::sleep(Duration::from_millis(TAP_SHORT_MS + 1_000));
    assert!(bench.quiet());
    bench.request_presence(cid);
    bench.tap(TAP_SHORT_MS);
    bench.expect_presence_granted(cid);
}

/// `docs/PROGRAM.md` "lk-run", Taps: a tap while the sensor is held is ignored. Had the
/// first tap been taken, its release would have let go of the raw press, and the second
/// tap would have answered the request.
#[test]
fn a_tap_is_ignored_while_the_sensor_is_held() {
    let bench = Bench::serving(RunnerConfig::default());
    let cid = bench.init(NONCE_A);
    bench.input(HostInput::Touch(TouchEdge::Down));
    bench.tap(100);
    thread::sleep(Duration::from_millis(400));
    // A request that starts during a hold waits for the next touch.
    bench.request_presence(cid);
    bench.tap(100);
    bench.only_keepalives_for(Duration::from_millis(600));
    assert!(bench.sync().presence_pending, "still held, so the tap was ignored");
    bench.input(HostInput::Touch(TouchEdge::Up));
    bench.tap(TAP_SHORT_MS);
    bench.expect_presence_granted(cid);
}

/// `docs/PROGRAM.md` "lk-run", Suspend: outputs produced while suspended are held, the
/// oldest dropped beyond the limit; on resume they go out first, in order, then the
/// resume's own `50 03` slot change.
#[test]
fn suspended_outputs_are_queued_up_to_the_limit_and_flushed_before_the_resume_outputs() {
    let bench = Bench::serving(RunnerConfig { suspend_queue_limit: 2, ..RunnerConfig::default() });
    bench.input(HostInput::Bus(BusEvent::Suspend));
    for nonce in [NONCE_A, NONCE_B, NONCE_C] {
        bench.fido(BROADCAST, CTAPHID_INIT, &nonce);
    }
    let status = bench.sync();
    assert!(status.suspended);
    assert_eq!((status.queued, status.dropped), (2, 1));
    assert!(bench.quiet(), "nothing reaches the host while suspended");
    bench.input(HostInput::Bus(BusEvent::Resume));
    bench.expect_init_response(NONCE_B);
    bench.expect_init_response(NONCE_C);
    assert_eq!(bench.next(), Event::Deliver(Output::CcidInterrupt(vec![0x50, 0x03])));
    let status = bench.sync();
    assert!(!status.suspended);
    assert_eq!((status.queued, status.dropped), (0, 1));
    bench.init(NONCE_D);
}

/// `docs/PROGRAM.md` "lk-run", Suspend: a reset or power cycle while suspended discards
/// the queue, counts it as dropped and ends the suspension.
#[test]
fn a_reset_or_power_cycle_while_suspended_discards_the_queue() {
    let bench = Bench::serving(RunnerConfig::default());
    let mut dropped = 0;
    for event in [BusEvent::Reset, BusEvent::PowerCycle] {
        bench.input(HostInput::Bus(BusEvent::Suspend));
        bench.fido(BROADCAST, CTAPHID_INIT, &NONCE_A);
        bench.fido(BROADCAST, CTAPHID_INIT, &NONCE_B);
        assert_eq!(bench.sync().queued, 2);
        bench.input(HostInput::Bus(event));
        dropped += 2;
        let status = bench.sync();
        assert!(!status.suspended, "{event:?}");
        assert_eq!((status.queued, status.dropped), (0, dropped), "{event:?}");
        assert!(bench.quiet(), "{event:?}: the queued answers never reach the host");
        bench.init(NONCE_C);
    }
}

/// A Management reboot while the bus is suspended is the device's own power cycle (it
/// also ends the device's suspend state): the queued answer to the write is lost with it
/// (counted as dropped), the suspension ends and the new enumeration is served at once.
/// A later `Bus(Resume)` has nothing to flush.
#[test]
fn a_management_reboot_while_suspended_discards_the_queue_and_ends_the_suspension() {
    let bench = Bench::serving(RunnerConfig::default());
    let cid = bench.init(NONCE_A);
    bench.input(HostInput::Bus(BusEvent::Suspend));
    bench.fido(cid, CTAPHID_WRITE_CONFIG, &OTP_FIDO_WITH_REBOOT);
    let Event::Enumerate(identity) = bench.next() else {
        panic!("expected the enumeration of the new identity");
    };
    assert_eq!(identity.interfaces, UsbInterfaces { otp: true, fido: true, ccid: false });
    let status = bench.sync();
    assert!(!status.suspended, "{status:?}");
    assert_eq!((status.queued, status.dropped), (0, 1), "the write's answer is lost with the reboot");
    bench.init(NONCE_B);
    bench.input(HostInput::Bus(BusEvent::Resume));
    bench.sync();
    assert!(bench.quiet(), "nothing was held for the resume");
}

/// `Bus(PowerCycle)` (a wire client's plug-in) makes the device forget a press the
/// previous host never released, whether a raw `Touch(Down)` or a tap still being held:
/// the runner lets go of the sensor too, so the next tap reaches the device.
#[test]
fn a_tap_after_a_power_cycle_reaches_the_device_although_the_sensor_was_held() {
    let presses = [Command::Input(HostInput::Touch(TouchEdge::Down)), Command::Tap { hold_ms: TAP_LONG_MS }];
    for press in presses {
        let shown = format!("{press:?}");
        let bench = Bench::serving(RunnerConfig::default());
        bench.sender.send(press).unwrap();
        bench.input(HostInput::Bus(BusEvent::PowerCycle));
        let cid = bench.init(NONCE_A);
        bench.request_presence(cid);
        bench.tap(TAP_SHORT_MS);
        assert_eq!(message(&bench.next_skipping_keepalives()), (cid, CTAPHID_CBOR, vec![0x00]), "after {shown}");
        assert_eq!(bench.next(), Event::Deliver(Output::PresenceIndicator(false)), "after {shown}");
    }
}

/// A Management reboot makes the device forget a held press as well (`Device::restart`):
/// after it, a tap answers a presence request.
#[test]
fn a_management_reboot_lets_go_of_a_held_sensor() {
    let bench = Bench::serving(RunnerConfig::default());
    let cid = bench.init(NONCE_A);
    bench.input(HostInput::Touch(TouchEdge::Down));
    bench.fido(cid, CTAPHID_WRITE_CONFIG, &OTP_FIDO_WITH_REBOOT);
    assert_eq!(message(&bench.next()), (cid, CTAPHID_WRITE_CONFIG, vec![]));
    assert!(matches!(bench.next(), Event::Enumerate(_)));
    let cid = bench.init(NONCE_B);
    bench.request_presence(cid);
    bench.tap(TAP_SHORT_MS);
    bench.expect_presence_granted(cid);
}

/// While suspended the presence indicator still goes out (it is not bus data), and the
/// keepalives the deadline loop produces are queued, then lost to a reset.
#[test]
fn the_presence_indicator_passes_a_suspended_bus() {
    let bench = Bench::serving(RunnerConfig::default());
    let (watcher, watched) = mpsc::channel();
    bench.sender.send(Command::Watch(watcher)).unwrap();
    assert_eq!(watched.recv_timeout(WAIT), Ok(false));
    let cid = bench.init(NONCE_A);
    bench.input(HostInput::Bus(BusEvent::Suspend));
    bench.fido(cid, CTAPHID_CBOR, &SELECTION);
    assert_eq!(bench.next(), Event::Deliver(Output::PresenceIndicator(true)));
    assert_eq!(watched.recv_timeout(WAIT), Ok(true));
    thread::sleep(Duration::from_millis(300));
    let queued = bench.sync().queued;
    assert!(queued >= 2, "the immediate keepalive and later ones: {queued}");
    // A bus reset drops the pending request and the queue.
    bench.input(HostInput::Bus(BusEvent::Reset));
    assert_eq!(bench.next(), Event::Deliver(Output::PresenceIndicator(false)));
    assert_eq!(watched.recv_timeout(WAIT), Ok(false));
    let status = bench.sync();
    assert!(!status.suspended && !status.presence_pending);
    assert!(status.queued == 0 && status.dropped >= 2, "{status:?}");
    assert!(bench.quiet());
}

/// `docs/PROGRAM.md` "lk-run", Re-enumeration: a Management write with REBOOT (CTAPHID
/// `0x43`) answers, then the runner enumerates the new identity; `Reenumerate` itself
/// never reaches `deliver`. Runs with the wall clock on.
#[test]
fn a_management_reboot_enumerates_the_new_identity_instead_of_delivering_it() {
    let bench = Bench::serving(RunnerConfig { wall_clock: true, ..RunnerConfig::default() });
    let cid = bench.init(NONCE_A);
    bench.fido(cid, CTAPHID_WRITE_CONFIG, &OTP_FIDO_WITH_REBOOT);
    assert_eq!(message(&bench.next()), (cid, CTAPHID_WRITE_CONFIG, vec![]));
    let Event::Enumerate(identity) = bench.next() else {
        panic!("expected a second enumeration");
    };
    let otp_fido = UsbInterfaces { otp: true, fido: true, ccid: false };
    assert_eq!(identity.interfaces, otp_fido);
    assert_eq!((identity.product_id, identity.product.as_str()), (0x0403, "YubiKey OTP+FIDO"));
    assert_eq!(bench.sync().interfaces, otp_fido);
    let log = bench.log.lock().unwrap().clone();
    assert!(!log.iter().any(|event| matches!(event, Event::Deliver(Output::Reenumerate(_)))));
    assert_eq!(log.iter().filter(|event| matches!(event, Event::Enumerate(_))).count(), 2);
}

/// `docs/PROGRAM.md` "lk-run", Presence watchers: the current state at once, then every
/// change.
#[test]
fn watchers_hear_the_current_state_and_every_change() {
    let bench = Bench::serving(RunnerConfig::default());
    let (watcher, watched) = mpsc::channel();
    bench.sender.send(Command::Watch(watcher)).unwrap();
    assert_eq!(watched.recv_timeout(WAIT), Ok(false));
    let cid = bench.init(NONCE_A);
    bench.request_presence(cid);
    assert_eq!(watched.recv_timeout(WAIT), Ok(true));
    let (late, late_watched) = mpsc::channel();
    bench.sender.send(Command::Watch(late)).unwrap();
    assert_eq!(late_watched.recv_timeout(WAIT), Ok(true), "a new watcher hears the current state");
    bench.tap(TAP_SHORT_MS);
    bench.expect_presence_granted(cid);
    assert_eq!(watched.recv_timeout(WAIT), Ok(false));
    assert_eq!(late_watched.recv_timeout(WAIT), Ok(false));
    bench.sync();
    assert!(watched.try_recv().is_err() && late_watched.try_recv().is_err(), "one message per change");
}

#[test]
fn a_factory_error_is_reported() {
    let error = Runner::spawn(|| Err("storage key rejected".to_owned()), RunnerConfig::default()).unwrap_err();
    assert_eq!(error, RunError::Factory("storage key rejected".into()));
}

#[test]
fn a_factory_panic_is_reported_instead_of_hanging() {
    let factory = || -> Result<Device, String> { panic!("factory exploded") };
    let error = Runner::spawn(factory, RunnerConfig::default()).unwrap_err();
    assert_eq!(error, RunError::Panicked("factory exploded".into()));
}

/// `docs/PROGRAM.md` "lk-run", Panics: a panic in the device ends the thread; `status`
/// then reports `Stopped` and `shutdown` the panic.
#[test]
fn a_device_panic_stops_the_runner() {
    let armed = Arc::new(AtomicBool::new(false));
    let store = PanickingStore { inner: MemoryStore::new(), armed: Arc::clone(&armed) };
    let runner = Runner::spawn(move || open(Box::new(store)), RunnerConfig::default()).unwrap();
    let mut bench = Bench::with_runner(runner);
    bench.serve();
    assert!(matches!(bench.next(), Event::Enumerate(_)));
    let cid = bench.init(NONCE_A);
    armed.store(true, Ordering::SeqCst);
    // The configuration write saves the device record.
    bench.fido(cid, CTAPHID_WRITE_CONFIG, &OTP_FIDO_WITH_REBOOT);
    assert_eq!(bench.runner.status(), Err(RunError::Stopped));
    let Bench { runner, .. } = bench;
    assert_eq!(runner.shutdown(), Err(RunError::Panicked("injected store panic".into())));
}

/// Where something happened, once it has.
type ThreadRecord = Arc<Mutex<Option<ThreadId>>>;

/// Opens a device whose store records the thread it is dropped on; returns the runner,
/// the factory's thread and the drop record.
fn probed() -> (Runner, ThreadRecord, ThreadRecord) {
    let opened_on = Arc::new(Mutex::new(None));
    let dropped_on = Arc::new(Mutex::new(None));
    let factory = {
        let opened_on = Arc::clone(&opened_on);
        let dropped_on = Arc::clone(&dropped_on);
        move || {
            *opened_on.lock().unwrap() = Some(thread::current().id());
            open(Box::new(DropProbe { inner: MemoryStore::new(), dropped_on }))
        }
    };
    let runner = Runner::spawn(factory, RunnerConfig::default()).unwrap();
    (runner, opened_on, dropped_on)
}

/// The device is `!Send`: it is built and dropped on the runner thread, and `shutdown`
/// returns only after it is gone.
#[test]
fn shutdown_drops_the_device_on_the_runner_thread() {
    let (runner, opened_on, dropped_on) = probed();
    assert!(dropped_on.lock().unwrap().is_none());
    runner.shutdown().unwrap();
    let dropped = dropped_on.lock().unwrap().unwrap();
    assert_eq!(Some(dropped), *opened_on.lock().unwrap());
    assert_ne!(dropped, thread::current().id());
}

/// `Runner::shutdown` ends the loop after the command in hand: a backlog of inputs
/// queued before it is dropped, not worked through (here it would take 5 s), even while
/// a transport still holds a `Sender`.
#[test]
fn shutdown_does_not_wait_for_queued_inputs() {
    let runner = Runner::spawn(|| open(Box::new(MemoryStore::new())), RunnerConfig::default()).unwrap();
    let delivered = Arc::new(AtomicUsize::new(0));
    let (enumerated, enumeration) = mpsc::channel();
    let transport = Slow { delay: Duration::from_millis(50), delivered: Arc::clone(&delivered), enumerated };
    runner.serve(Box::new(transport)).unwrap();
    enumeration.recv_timeout(WAIT).unwrap();
    let sender = runner.sender();
    for _ in 0..100 {
        sender.send(Command::Input(HostInput::FidoReport(packet(BROADCAST, CTAPHID_INIT, &NONCE_A)))).unwrap();
    }
    let stopping = Instant::now();
    runner.shutdown().unwrap();
    // Not a speed check: only that the 5 s backlog was not worked through.
    assert!(stopping.elapsed() < Duration::from_secs(3), "{:?}", stopping.elapsed());
    assert!(delivered.load(Ordering::SeqCst) < 100, "the backlog was worked through");
    assert!(sender.send(Command::Shutdown).is_err(), "the loop is gone");
}

/// Dropping the handle shuts the runner down and joins it.
#[test]
fn dropping_the_runner_joins_the_thread() {
    let (runner, opened_on, dropped_on) = probed();
    let sender = runner.sender();
    drop(runner);
    assert_eq!(*dropped_on.lock().unwrap(), *opened_on.lock().unwrap());
    assert!(dropped_on.lock().unwrap().is_some());
    assert!(sender.send(Command::Shutdown).is_err(), "the loop is gone");
}
