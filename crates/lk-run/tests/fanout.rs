//! `lk_run::Fanout` against recording transports, alone and attached to a runner
//! (`docs/PROGRAM.md` "Transport combinations": `enumerate` goes to every member in order,
//! `deliver` gives every member a clone, `attached` is `Some(true)` if any member says
//! so, `Some(false)` if all that know say false, else `None`).
//!
//! CTAPHID packets are written from CTAP 2.1 §11.2.4 (initialization packet: CID,
//! `0x80 | cmd`, big-endian length, data); the Management write from yubikit's
//! `DeviceConfig.get_bytes` (`len || TLVs`, USB enabled applications tag `03`, REBOOT tag
//! `0C`), sent as Yubico's CTAPHID vendor command `0x43` (catalog "CTAPHID vendor 0x42 /
//! 0x43").

use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use lk_core::{DeviceProfile, UsbInterfaces};
use lk_device::{Device, FIDO_REPORT_DESCRIPTOR, OTP_REPORT_DESCRIPTOR, Output, UsbIdentity};
use lk_run::{Command, Fanout, HostInput, Runner, RunnerConfig, Transport};
use lk_testkit::{MemoryStore, SeededEntropy};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// How long a test waits for something that must happen. Generous, for loaded machines.
const WAIT: Duration = Duration::from_secs(10);

/// One call a member received, with the member's name.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Enumerate(&'static str, UsbIdentity),
    Deliver(&'static str, Output),
}

/// A shared, ordered record of the calls of every member.
type Calls = Arc<Mutex<Vec<Call>>>;

fn calls_of(calls: &Calls) -> Vec<Call> {
    calls.lock().unwrap_or_else(PoisonError::into_inner).clone()
}

/// A member that records its calls into the shared list (so the order across members
/// shows), copies them to a channel a test can wait on, and reports a fixed `attached`.
#[derive(Debug)]
struct Recorder {
    name: &'static str,
    attached: Option<bool>,
    calls: Calls,
    events: Option<Sender<Call>>,
}

impl Recorder {
    fn new(name: &'static str, attached: Option<bool>, calls: &Calls) -> Recorder {
        Recorder { name, attached, calls: Arc::clone(calls), events: None }
    }

    fn boxed(name: &'static str, attached: Option<bool>, calls: &Calls) -> Box<dyn Transport> {
        Box::new(Recorder::new(name, attached, calls))
    }

    fn record(&mut self, call: Call) {
        self.calls.lock().unwrap_or_else(PoisonError::into_inner).push(call.clone());
        if let Some(events) = &self.events {
            let _ = events.send(call);
        }
    }
}

impl Transport for Recorder {
    fn enumerate(&mut self, identity: &UsbIdentity) {
        let call = Call::Enumerate(self.name, identity.clone());
        self.record(call);
    }

    fn deliver(&mut self, output: Output) {
        let call = Call::Deliver(self.name, output);
        self.record(call);
    }

    fn attached(&self) -> Option<bool> {
        self.attached
    }
}

/// A member that reports a fixed `attached` and otherwise does nothing.
#[derive(Debug)]
struct Knows(Option<bool>);

impl Transport for Knows {
    fn enumerate(&mut self, _identity: &UsbIdentity) {}

    fn deliver(&mut self, _output: Output) {}

    fn attached(&self) -> Option<bool> {
        self.0
    }
}

/// An identity built by hand from the public `UsbIdentity` fields (the CCID class
/// descriptor is a placeholder of its real length, 54 bytes).
fn identity(ccid: bool) -> UsbIdentity {
    UsbIdentity {
        vendor_id: 0x1050,
        product_id: if ccid { 0x0407 } else { 0x0403 },
        device_release: 0x0574,
        manufacturer: "Yubico".into(),
        product: if ccid { "YubiKey OTP+FIDO+CCID".into() } else { "YubiKey OTP+FIDO".into() },
        serial: None,
        interfaces: UsbInterfaces { otp: true, fido: true, ccid },
        fido_report_descriptor: FIDO_REPORT_DESCRIPTOR.to_vec(),
        otp_report_descriptor: OTP_REPORT_DESCRIPTOR.to_vec(),
        ccid_class_descriptor: vec![0x36; 54],
    }
}

#[test]
fn enumerate_goes_to_every_member_in_the_order_given() {
    let calls = Calls::default();
    let mut fanout = Fanout::new(vec![
        Recorder::boxed("uhid", None, &calls),
        Recorder::boxed("vpcd", None, &calls),
        Recorder::boxed("third", None, &calls),
    ]);
    fanout.enumerate(&identity(true));
    fanout.enumerate(&identity(false));
    let expected: Vec<Call> = [identity(true), identity(false)]
        .into_iter()
        .flat_map(|id| ["uhid", "vpcd", "third"].map(|name| Call::Enumerate(name, id.clone())))
        .collect();
    assert_eq!(calls_of(&calls), expected);
}

#[test]
fn deliver_gives_every_member_its_own_copy_of_each_output_in_order() {
    let calls = Calls::default();
    let mut fanout = Fanout::new(vec![Recorder::boxed("a", None, &calls), Recorder::boxed("b", None, &calls)]);
    let outputs = [
        Output::FidoReport([0x11; 64]),
        Output::Ccid(vec![0x80, 2, 0, 0, 0, 0, 7, 0, 0, 0, 0x90, 0x00]),
        Output::OtpKeyboard([0x22; 8]),
        Output::PresenceIndicator(true),
        Output::CcidInterrupt(vec![0x50, 0x03]),
        Output::OtpFeature([0x33; 8]),
    ];
    for output in &outputs {
        fanout.deliver(output.clone());
    }
    let expected: Vec<Call> = outputs
        .iter()
        .flat_map(|output| [Call::Deliver("a", output.clone()), Call::Deliver("b", output.clone())])
        .collect();
    assert_eq!(calls_of(&calls), expected, "each output to every member before the next output");
}

/// `attached`: `Some(true)` if any member says so, `Some(false)` if every member that
/// knows says false, `None` if none knows.
#[test]
fn attached_is_true_if_any_member_is_false_if_all_that_know_are_and_unknown_otherwise() {
    let cases: [(&[Option<bool>], Option<bool>); 12] = [
        (&[Some(true)], Some(true)),
        (&[Some(false)], Some(false)),
        (&[None], None),
        (&[None, None], None),
        (&[Some(false), Some(false)], Some(false)),
        (&[Some(true), Some(false)], Some(true)),
        (&[Some(false), Some(true)], Some(true)),
        (&[None, Some(true)], Some(true)),
        (&[Some(true), None], Some(true)),
        (&[None, Some(false)], Some(false)),
        (&[Some(false), None], Some(false)),
        (&[None, Some(false), None, Some(true)], Some(true)),
    ];
    for (members, expected) in cases {
        let fanout =
            Fanout::new(members.iter().map(|&attached| Box::new(Knows(attached)) as Box<dyn Transport>).collect());
        assert_eq!(fanout.attached(), expected, "{members:?}");
    }
}

#[test]
fn an_empty_fanout_does_nothing_and_knows_nothing() {
    let mut fanout = Fanout::default();
    assert!(fanout.is_empty());
    assert_eq!(fanout.len(), 0);
    fanout.enumerate(&identity(true));
    fanout.deliver(Output::FidoReport([0; 64]));
    assert_eq!(fanout.attached(), None);
}

#[test]
fn members_pushed_later_come_after_the_others() {
    let calls = Calls::default();
    let mut fanout = Fanout::from(vec![Recorder::boxed("first", None, &calls)]);
    fanout.push(Recorder::boxed("second", Some(false), &calls));
    assert_eq!((fanout.len(), fanout.is_empty()), (2, false));
    fanout.deliver(Output::PresenceIndicator(false));
    assert_eq!(
        calls_of(&calls),
        [Call::Deliver("first", Output::PresenceIndicator(false)), Call::Deliver("second", Output::PresenceIndicator(false))]
    );
    assert_eq!(fanout.attached(), Some(false));
    let shown = format!("{fanout:?}");
    assert!(shown.contains("first") && shown.contains("second"), "{shown}");
}

/// The initialization packet of a single-packet CTAPHID message.
fn packet(cid: u32, cmd: u8, payload: &[u8]) -> [u8; 64] {
    let mut report = [0u8; 64];
    report[..4].copy_from_slice(&cid.to_be_bytes());
    report[4] = 0x80 | cmd;
    report[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    report[7..7 + payload.len()].copy_from_slice(payload);
    report
}

/// CTAPHID (CTAP 2.1 §11.2.9).
const BROADCAST: u32 = 0xFFFF_FFFF;
const CTAPHID_INIT: u8 = 0x06;
/// Yubico's CTAPHID vendor command WRITE CONFIG.
const CTAPHID_WRITE_CONFIG: u8 = 0x43;
/// WRITE CONFIG data: USB enabled applications OTP | U2F | FIDO2 (`0203`, no CCID), then
/// REBOOT.
const OTP_FIDO_WITH_REBOOT: [u8; 7] = [0x06, 0x03, 0x02, 0x02, 0x03, 0x0C, 0x00];

fn next(events: &Receiver<Call>) -> Result<Call, Box<dyn std::error::Error>> {
    Ok(events.recv_timeout(WAIT).map_err(|error| format!("no member call within {WAIT:?}: {error}"))?)
}

/// The channel of the INIT response a member received.
fn allocated_channel(call: &Call) -> Option<u32> {
    match call {
        Call::Deliver(_, Output::FidoReport(report)) if report[4] == 0x80 | CTAPHID_INIT => {
            Some(u32::from_be_bytes([report[15], report[16], report[17], report[18]]))
        }
        _ => None,
    }
}

/// The fanout as the runner's one transport: the attach enumerates every member, every
/// output reaches both, a Management reboot re-enumerates both, and `Status::attached`
/// is the fanout's.
#[test]
fn a_runner_serving_a_fanout_reaches_every_member() -> TestResult {
    let store = MemoryStore::new();
    let profile = DeviceProfile::yubikey_compat(12_345_678);
    let runner = Runner::spawn(
        move || Ok(Device::open(profile, Box::new(store), Box::new(SeededEntropy::new(1)), [0x5A; 32])),
        RunnerConfig::default(),
    )?;
    let calls = Calls::default();
    let (events_tx, events) = mpsc::channel();
    let mut first = Recorder::new("uhid", None, &calls);
    first.events = Some(events_tx);
    let second = Recorder::new("vpcd", Some(false), &calls);
    runner.serve(Box::new(Fanout::new(vec![Box::new(first), Box::new(second)])))?;
    let initial = runner.ready().identity.clone();
    assert_eq!(next(&events)?, Call::Enumerate("uhid", initial.clone()));

    let sender: Sender<Command> = runner.sender();
    sender.send(Command::Input(HostInput::FidoReport(packet(BROADCAST, CTAPHID_INIT, &[0xA5; 8]))))?;
    let response = next(&events)?;
    let cid = allocated_channel(&response).ok_or_else(|| format!("not an INIT response: {response:02X?}"))?;
    let status = runner.status()?;
    assert_eq!(status.attached, Some(false), "one member does not know, the other says false");

    sender.send(Command::Input(HostInput::FidoReport(packet(cid, CTAPHID_WRITE_CONFIG, &OTP_FIDO_WITH_REBOOT))))?;
    let answer = next(&events)?;
    let Call::Enumerate(_, rebooted) = next(&events)? else {
        return Err(format!("expected the re-enumeration after {answer:02X?}").into());
    };
    assert_eq!(rebooted.interfaces, UsbInterfaces { otp: true, fido: true, ccid: false });
    runner.status()?;
    runner.shutdown()?;

    let Call::Deliver(_, init_response) = response else {
        return Err("the INIT response is a delivery".into());
    };
    let Call::Deliver(_, write_answer) = answer else {
        return Err("the WRITE CONFIG answer is a delivery".into());
    };
    assert_eq!(
        calls_of(&calls),
        [
            Call::Enumerate("uhid", initial.clone()),
            Call::Enumerate("vpcd", initial),
            Call::Deliver("uhid", init_response.clone()),
            Call::Deliver("vpcd", init_response),
            Call::Deliver("uhid", write_answer.clone()),
            Call::Deliver("vpcd", write_answer),
            Call::Enumerate("uhid", rebooted.clone()),
            Call::Enumerate("vpcd", rebooted),
        ],
        "both members see every call, in the runner's order"
    );
    Ok(())
}
