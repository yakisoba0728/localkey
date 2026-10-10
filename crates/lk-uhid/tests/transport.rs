//! The UHID transport against a fake kernel (`docs/PROGRAM.md` "lk-uhid"): every test plays
//! the kernel side of `/dev/uhid` over `UnixStream::pair()` halves, byte for byte.

#![cfg(unix)]

mod common;

use std::io::{self, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use lk_device::{BusEvent, FIDO_REPORT_DESCRIPTOR, OTP_REPORT_DESCRIPTOR, Output};
use lk_run::{Command, HostInput, Transport};
use lk_uhid::event::{EIO, Event, ReportType, UHID_EVENT_SIZE, UHID_INPUT2};
use lk_uhid::{
    DESTROY_AFTER_REPLY, DROP_TIMEOUT, FEATURE_TIMEOUT, HidInterface, INPUT_WINDOW, UhidHalves, UhidIo, UhidNotice,
    UhidStats, UhidTransport, WRITE_QUEUE_EVENTS,
};

use common::{ALL, Answer, CCID, FIDO_CCID, Harness, KernelMode, PairIo, WAIT, identity, read_event};

const POWER_CYCLE: HostInput = HostInput::Bus(BusEvent::PowerCycle);

fn report(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
}

fn fido_report(seed: u8) -> [u8; 64] {
    let mut out = [0; 64];
    out.copy_from_slice(&report(64, seed));
    out
}

fn feature(rnum: u8, data: Vec<u8>, id: u32) -> Event {
    Event::SetReport { id, rnum, rtype: ReportType::Feature, data }
}

fn ne16(value: u16) -> [u8; 2] {
    value.to_ne_bytes()
}

fn ne32(value: u32) -> [u8; 4] {
    value.to_ne_bytes()
}

#[test]
fn enumeration_creates_an_otp_and_a_fido_device_from_the_identity() {
    let harness = Harness::new();
    harness.enumerate(&identity(0x0407, ALL));
    let (otp, fido) = harness.devices();
    for (device, descriptor) in [(&otp, &OTP_REPORT_DESCRIPTOR[..]), (&fido, &FIDO_REPORT_DESCRIPTOR[..])] {
        let create = &device.create;
        assert_eq!(create.name, "YubiKey OTP+FIDO+CCID");
        assert_eq!(create.phys, "localkey");
        assert_eq!(create.uniq, "12345678");
        assert_eq!(
            (create.bus, create.vendor, create.product, create.version, create.country),
            (3, 0x1050, 0x0407, 0x0574, 0)
        );
        assert_eq!(create.report_descriptor, descriptor);

        // The raw `struct uhid_event` (`include/uapi/linux/uhid.h`): type, then the packed
        // `uhid_create2_req` at offset 4.
        let raw = &device.raw;
        assert_eq!(raw.len(), UHID_EVENT_SIZE);
        assert_eq!(&raw[..4], &ne32(11));
        assert_eq!(&raw[4..4 + 22], b"YubiKey OTP+FIDO+CCID\0");
        assert_eq!(&raw[4 + 128..4 + 137], b"localkey\0");
        assert_eq!(&raw[4 + 192..4 + 201], b"12345678\0");
        assert_eq!(&raw[4 + 256..4 + 258], &ne16(descriptor.len() as u16));
        assert_eq!(&raw[4 + 258..4 + 260], &ne16(3));
        assert_eq!(&raw[4 + 260..4 + 264], &ne32(0x1050));
        assert_eq!(&raw[4 + 264..4 + 268], &ne32(0x0407));
        assert_eq!(&raw[4 + 268..4 + 272], &ne32(0x0574));
        assert_eq!(&raw[4 + 272..4 + 276], &ne32(0));
        assert_eq!(&raw[4 + 276..4 + 276 + descriptor.len()], descriptor);
        assert!(raw[4 + 276 + descriptor.len()..].iter().all(|&byte| byte == 0));
    }
    assert_eq!(harness.input(), POWER_CYCLE, "creating the devices is a plug-in");
    harness.no_input();
}

#[test]
fn a_device_without_a_serial_gets_an_empty_uniq() {
    let harness = Harness::new();
    let mut identity = identity(0x0402, FIDO_CCID);
    identity.serial = None;
    harness.enumerate(&identity);
    let fido = harness.device();
    assert_eq!(fido.create.uniq, "");
    assert!(fido.raw[4 + 192..4 + 256].iter().all(|&byte| byte == 0));
}

#[test]
fn an_overlong_product_string_is_truncated_rather_than_refused() {
    let harness = Harness::new();
    let mut identity = identity(0x0402, FIDO_CCID);
    identity.product = "P".repeat(300);
    harness.enumerate(&identity);
    assert_eq!(harness.device().create.name, "P".repeat(127));
    assert_eq!(harness.input(), POWER_CYCLE);
}

#[test]
fn only_enabled_hid_interfaces_get_a_device() {
    let harness = Harness::new();
    harness.enumerate(&identity(0x0406, FIDO_CCID));
    let fido = harness.device();
    assert_eq!(fido.interface(), HidInterface::Fido);
    assert_eq!(fido.create.product, 0x0406);
    harness.no_kernel();
    assert_eq!(harness.input(), POWER_CYCLE);

    let harness = Harness::new();
    harness.enumerate(&identity(0x0404, CCID));
    harness.no_kernel();
    harness.no_input();
    assert_eq!(harness.attached(), Some(false), "CCID alone presents nothing through UHID");
}

#[test]
fn a_64_byte_output_report_reaches_the_runner_as_a_fido_report() {
    let (harness, _otp, fido) = Harness::plugged();
    fido.kernel.output(report(64, 1));
    assert_eq!(harness.input(), HostInput::FidoReport(fido_report(1)));
}

#[test]
fn a_65_byte_output_report_with_a_leading_zero_loses_its_report_number() {
    let (harness, _otp, fido) = Harness::plugged();
    let mut data = vec![0];
    data.extend(report(64, 9));
    fido.kernel.output(data);
    assert_eq!(harness.input(), HostInput::FidoReport(fido_report(9)));
}

#[test]
fn a_65_byte_output_report_with_a_non_zero_first_byte_is_dropped() {
    let (harness, _otp, fido) = Harness::plugged();
    let mut data = vec![0x86];
    data.extend(report(64, 9));
    fido.kernel.output(data);
    let notice = harness.notice(|notice| matches!(notice, UhidNotice::Refused { .. }));
    assert_eq!(
        notice,
        UhidNotice::Refused {
            interface: HidInterface::Fido,
            event: "OUTPUT",
            size: 65,
            reason: "the byte before the report is not report number 0"
        }
    );
    for len in [1, 63, 66, 128] {
        fido.kernel.output(vec![0; len]);
        harness.notice(|notice| matches!(notice, UhidNotice::Refused { size, .. } if *size == len));
    }
    fido.kernel.send(&Event::Output { data: report(64, 1), rtype: ReportType::Feature });
    harness.notice(|notice| matches!(notice, UhidNotice::Refused { reason: "not an output report", .. }));
    harness.no_input();
    assert_eq!(harness.stats(), UhidStats { ignored: 0, refused: 6, dropped: 0 });
}

#[test]
fn reports_are_served_without_waiting_for_uhid_start() {
    let harness = Harness::with_mode(KernelMode { auto_start: false, auto_stop: true });
    harness.enumerate(&identity(0x0407, ALL));
    let (otp, fido) = harness.devices();
    assert_eq!(harness.input(), POWER_CYCLE);
    fido.kernel.output(report(64, 1));
    assert_eq!(harness.input(), HostInput::FidoReport(fido_report(1)));
    otp.kernel.send(&feature(0, report(8, 1), 2));
    assert_eq!(harness.input(), HostInput::OtpSetFeature(report(8, 1).try_into().expect("8 bytes")));
    assert_eq!(otp.kernel.next(), Event::SetReportReply { id: 2, err: 0 });
}

#[test]
fn reports_left_on_the_old_file_do_not_reach_the_rebooted_device() {
    // No automatic STOP, so the old file stays open while the test writes to it.
    let harness = Harness::with_mode(KernelMode { auto_start: true, auto_stop: false });
    harness.enumerate(&identity(0x0402, FIDO_CCID));
    let old = harness.device();
    assert_eq!(harness.input(), POWER_CYCLE);

    harness.enumerate(&identity(0x0402, FIDO_CCID));
    assert_eq!(old.kernel.next(), Event::Destroy);
    let new = harness.device();
    assert_eq!(new.interface(), HidInterface::Fido);
    assert_eq!(harness.input(), POWER_CYCLE);

    // Events the kernel queued for the old device before its DESTROY.
    old.kernel.output(report(64, 3));
    harness.notice(|notice| {
        matches!(notice, UhidNotice::Refused { event: "OUTPUT", reason: "the device is being destroyed", .. })
    });
    old.kernel.send(&feature(0, report(8, 1), 7));
    harness.notice(|notice| matches!(notice, UhidNotice::Refused { event: "SET_REPORT", .. }));
    harness.no_input();
    old.kernel.send(&Event::Stop);
    assert!(old.kernel.closes(), "the old file is closed after its STOP");

    new.kernel.output(report(64, 4));
    assert_eq!(harness.input(), HostInput::FidoReport(fido_report(4)));
    new.kernel.close();
}

#[test]
fn feature_set_of_8_and_9_bytes_reaches_the_runner_and_is_acknowledged() {
    let (harness, otp, _fido) = Harness::plugged();
    otp.kernel.send(&feature(0, report(8, 0x10), 21));
    assert_eq!(harness.input(), HostInput::OtpSetFeature(report(8, 0x10).try_into().expect("8 bytes")));
    assert_eq!(otp.kernel.next(), Event::SetReportReply { id: 21, err: 0 });

    let mut data = vec![0];
    data.extend(report(8, 0x20));
    otp.kernel.send(&feature(0, data, 22));
    assert_eq!(harness.input(), HostInput::OtpSetFeature(report(8, 0x20).try_into().expect("8 bytes")));
    assert_eq!(otp.kernel.next(), Event::SetReportReply { id: 22, err: 0 });
}

#[test]
fn feature_set_with_a_wrong_size_prefix_or_report_number_is_refused() {
    let (harness, otp, _fido) = Harness::plugged();
    let mut prefixed = vec![5];
    prefixed.extend(report(8, 1));
    let cases = [
        feature(0, report(7, 1), 31),
        feature(0, prefixed, 32),
        feature(1, report(8, 1), 33),
        feature(0, Vec::new(), 34),
    ];
    for case in &cases {
        otp.kernel.send(case);
    }
    for id in 31..=34 {
        assert_eq!(otp.kernel.next(), Event::SetReportReply { id, err: EIO });
    }
    harness.no_input();
    assert_eq!(harness.stats().refused, 4);
}

#[test]
fn keyboard_led_reports_are_acknowledged_and_ignored() {
    let (harness, otp, _fido) = Harness::plugged();
    otp.kernel.output(vec![0x02]);
    otp.kernel.output(vec![0x00, 0x02]);
    otp.kernel.send(&Event::SetReport { id: 41, rnum: 0, rtype: ReportType::Output, data: vec![0x01] });
    assert_eq!(otp.kernel.next(), Event::SetReportReply { id: 41, err: 0 });
    harness.no_input();
    assert_eq!(harness.stats(), UhidStats::default());
}

#[test]
fn a_fido_set_report_of_an_output_report_is_a_fido_report() {
    let (harness, _otp, fido) = Harness::plugged();
    let mut data = vec![0];
    data.extend(report(64, 7));
    fido.kernel.send(&Event::SetReport { id: 51, rnum: 0, rtype: ReportType::Output, data });
    assert_eq!(harness.input(), HostInput::FidoReport(fido_report(7)));
    assert_eq!(fido.kernel.next(), Event::SetReportReply { id: 51, err: 0 });
}

#[test]
fn feature_get_round_trips_through_the_runner() {
    let (harness, otp, _fido) = Harness::plugged();
    harness.set_answer(Answer::Feature([1, 2, 3, 4, 5, 6, 7, 8]));
    otp.kernel.send(&Event::GetReport { id: 61, rnum: 0, rtype: ReportType::Feature });
    assert_eq!(harness.input(), HostInput::OtpGetFeature);
    let (raw, reply) = otp.kernel.next_raw();
    assert_eq!(reply, Event::GetReportReply { id: 61, err: 0, data: vec![0, 1, 2, 3, 4, 5, 6, 7, 8] });
    // `uhid_get_report_reply_req`: id, err, size, data.
    assert_eq!(&raw[..4], &ne32(10));
    assert_eq!(&raw[4..8], &ne32(61));
    assert_eq!(&raw[8..10], &ne16(0));
    assert_eq!(&raw[10..12], &ne16(9));
    assert_eq!(&raw[12..21], &[0, 1, 2, 3, 4, 5, 6, 7, 8]);

    harness.set_answer(Answer::Feature([9; 8]));
    otp.kernel.send(&Event::GetReport { id: 62, rnum: 0, rtype: ReportType::Feature });
    assert_eq!(harness.input(), HostInput::OtpGetFeature);
    assert_eq!(otp.kernel.next(), Event::GetReportReply { id: 62, err: 0, data: [&[0][..], &[9; 8]].concat() });
}

#[test]
fn feature_get_without_an_answer_in_time_gets_an_error_reply() {
    let (harness, otp, _fido) = Harness::plugged();
    harness.set_answer(Answer::Silent);
    let start = Instant::now();
    otp.kernel.send(&Event::GetReport { id: 71, rnum: 0, rtype: ReportType::Feature });
    assert_eq!(harness.input(), HostInput::OtpGetFeature);
    assert_eq!(otp.kernel.next(), Event::GetReportReply { id: 71, err: EIO, data: Vec::new() });
    let waited = start.elapsed();
    assert!(waited >= FEATURE_TIMEOUT - Duration::from_millis(100), "replied after {waited:?}");
    assert!(waited < Duration::from_secs(5), "the kernel's own timeout is 5 s; replied after {waited:?}");
}

#[test]
fn feature_get_that_the_device_does_not_answer_gets_an_error_reply_at_once() {
    let (harness, otp, _fido) = Harness::plugged();
    harness.set_answer(Answer::Nothing);
    let start = Instant::now();
    otp.kernel.send(&Event::GetReport { id: 72, rnum: 0, rtype: ReportType::Feature });
    assert_eq!(harness.input(), HostInput::OtpGetFeature);
    assert_eq!(otp.kernel.next(), Event::GetReportReply { id: 72, err: EIO, data: Vec::new() });
    let waited = start.elapsed();
    assert!(waited < FEATURE_TIMEOUT / 2, "the answered marker ends the wait; replied after {waited:?}");
}

#[test]
fn a_feature_report_handed_back_before_the_request_does_not_answer_it() {
    let (harness, otp, _fido) = Harness::plugged();
    harness.deliver(Output::OtpFeature([0xEE; 8]));
    // The round trip makes sure the stale report was handed over before the request.
    let _ = harness.stats();
    harness.set_answer(Answer::Feature([1; 8]));
    otp.kernel.send(&Event::GetReport { id: 81, rnum: 0, rtype: ReportType::Feature });
    assert_eq!(harness.input(), HostInput::OtpGetFeature);
    assert_eq!(otp.kernel.next(), Event::GetReportReply { id: 81, err: 0, data: [&[0][..], &[1; 8]].concat() });
}

#[test]
fn a_late_feature_report_that_arrives_while_the_request_waits_does_not_answer_it() {
    let (harness, otp, _fido) = Harness::plugged();
    // The runner hands back a late answer to an earlier request after the reader sent
    // `OtpGetFeature` (so after its drain), then this request's own answer.
    harness.set_answer(Answer::StaleThen([0xEE; 8], [1; 8]));
    otp.kernel.send(&Event::GetReport { id: 82, rnum: 0, rtype: ReportType::Feature });
    assert_eq!(harness.input(), HostInput::OtpGetFeature);
    assert_eq!(otp.kernel.next(), Event::GetReportReply { id: 82, err: 0, data: [&[0][..], &[1; 8]].concat() });
}

#[test]
fn dropping_the_transport_does_not_wait_out_a_pending_feature_read() {
    let (harness, otp, _fido) = Harness::plugged();
    // The runner cannot answer markers, as when it is busy dropping the transport
    // (`lk_run` drops it on the runner thread while the command channel is alive).
    harness.set_answer(Answer::Silent);
    otp.kernel.send(&Event::GetReport { id: 1, rnum: 0, rtype: ReportType::Feature });
    assert_eq!(harness.input(), HostInput::OtpGetFeature);
    let took = harness.drop_transport();
    assert!(took < DROP_TIMEOUT / 2, "dropping the transport waited for the pending feature read: took {took:?}");
    // The DESTROY already failed the kernel's request (`uhid_dev_destroy`); no reply follows.
    assert_eq!(otp.kernel.next(), Event::Destroy);
    assert!(otp.kernel.closes(), "the file is closed");
}

#[test]
fn unsupported_requests_get_an_error_reply_at_once() {
    let (harness, otp, fido) = Harness::plugged();
    let start = Instant::now();
    for (id, rtype) in [(91, ReportType::Feature), (92, ReportType::Input), (93, ReportType::Output)] {
        fido.kernel.send(&Event::GetReport { id, rnum: 0, rtype });
        assert_eq!(fido.kernel.next(), Event::GetReportReply { id, err: EIO, data: Vec::new() });
    }
    otp.kernel.send(&Event::GetReport { id: 94, rnum: 0, rtype: ReportType::Input });
    assert_eq!(otp.kernel.next(), Event::GetReportReply { id: 94, err: EIO, data: Vec::new() });
    otp.kernel.send(&Event::GetReport { id: 95, rnum: 1, rtype: ReportType::Feature });
    assert_eq!(otp.kernel.next(), Event::GetReportReply { id: 95, err: EIO, data: Vec::new() });
    otp.kernel.send(&Event::GetReport { id: 96, rnum: 0, rtype: ReportType::Other(7) });
    assert_eq!(otp.kernel.next(), Event::GetReportReply { id: 96, err: EIO, data: Vec::new() });
    fido.kernel.send(&feature(0, report(8, 1), 97));
    assert_eq!(fido.kernel.next(), Event::SetReportReply { id: 97, err: EIO });
    otp.kernel.send(&Event::SetReport { id: 98, rnum: 0, rtype: ReportType::Input, data: report(8, 1) });
    assert_eq!(otp.kernel.next(), Event::SetReportReply { id: 98, err: EIO });
    assert!(start.elapsed() < FEATURE_TIMEOUT, "no request waited for the runner");
    harness.no_input();
    assert_eq!(harness.stats().refused, 8);
}

#[test]
fn re_enumeration_destroys_and_recreates_only_the_enabled_devices() {
    let (harness, otp, fido) = Harness::plugged();

    harness.enumerate(&identity(0x0406, FIDO_CCID));
    assert_eq!(fido.kernel.next(), Event::Destroy);
    assert_eq!(otp.kernel.next(), Event::Destroy);
    assert!(fido.kernel.closes() && otp.kernel.closes(), "the old files are closed");
    let fido = harness.device();
    assert_eq!(fido.interface(), HidInterface::Fido);
    assert_eq!(fido.create.product, 0x0406);
    harness.no_kernel();
    assert_eq!(harness.input(), POWER_CYCLE);
    fido.kernel.output(report(64, 5));
    assert_eq!(harness.input(), HostInput::FidoReport(fido_report(5)), "the new device works");

    harness.enumerate(&identity(0x0407, ALL));
    assert_eq!(fido.kernel.next(), Event::Destroy);
    assert!(fido.kernel.closes());
    let (otp, fido) = harness.devices();
    assert_eq!((otp.create.product, fido.create.product), (0x0407, 0x0407));
    assert_eq!(harness.input(), POWER_CYCLE);
    harness.no_input();
    harness.deliver(Output::OtpKeyboard([0, 0, 4, 0, 0, 0, 0, 0]));
    assert_eq!(otp.kernel.next(), Event::Input2 { data: vec![0, 0, 4, 0, 0, 0, 0, 0] });
}

#[test]
fn deliver_writes_input2_events_of_64_and_8_bytes() {
    let (harness, otp, fido) = Harness::plugged();
    harness.deliver(Output::FidoReport(fido_report(0x40)));
    let (raw, event) = fido.kernel.next_raw();
    assert_eq!(event, Event::Input2 { data: report(64, 0x40) });
    // `uhid_input2_req`: size, then data.
    assert_eq!(raw.len(), UHID_EVENT_SIZE);
    assert_eq!(&raw[..4], &ne32(12));
    assert_eq!(&raw[4..6], &ne16(64));
    assert_eq!(&raw[6..70], report(64, 0x40).as_slice());
    assert!(raw[70..].iter().all(|&byte| byte == 0));

    let keys = [0x02, 0, 0x04, 0, 0, 0, 0, 0];
    harness.deliver(Output::OtpKeyboard(keys));
    let (raw, event) = otp.kernel.next_raw();
    assert_eq!(event, Event::Input2 { data: keys.to_vec() });
    assert_eq!(&raw[4..14], &[&ne16(8)[..], &keys].concat()[..]);

    harness.deliver(Output::Ccid(vec![0x80; 10]));
    harness.deliver(Output::CcidInterrupt(vec![0x50, 0x03]));
    harness.deliver(Output::PresenceIndicator(true));
    assert_eq!(fido.kernel.quiet(), None);
    assert_eq!(otp.kernel.quiet(), None);
    assert_eq!(harness.stats(), UhidStats { ignored: 2, refused: 0, dropped: 0 });
}

#[test]
fn outputs_for_an_interface_without_a_device_are_dropped() {
    let harness = Harness::new();
    harness.enumerate(&identity(0x0406, FIDO_CCID));
    let fido = harness.device();
    harness.deliver(Output::OtpKeyboard([0; 8]));
    harness.deliver(Output::OtpFeature([0; 8]));
    harness.deliver(Output::FidoReport([1; 64]));
    assert_eq!(fido.kernel.next(), Event::Input2 { data: vec![1; 64] });
    assert_eq!(harness.stats(), UhidStats { ignored: 0, refused: 0, dropped: 2 });
}

#[test]
fn lifecycle_events_are_reported() {
    let (harness, _otp, fido) = Harness::plugged();
    harness.notice(|notice| *notice == UhidNotice::Started { interface: HidInterface::Fido, dev_flags: 0 });
    fido.kernel.send(&Event::Open);
    harness.notice(|notice| *notice == UhidNotice::Opened { interface: HidInterface::Fido });
    fido.kernel.send(&Event::Close);
    harness.notice(|notice| *notice == UhidNotice::Closed { interface: HidInterface::Fido });
    fido.kernel.send(&Event::Start { dev_flags: 4 });
    harness.notice(|notice| *notice == UhidNotice::Started { interface: HidInterface::Fido, dev_flags: 4 });
    // A kernel-to-user event the other way round is reported and ignored.
    fido.kernel.send(&Event::Input2 { data: vec![1; 64] });
    harness.notice(|notice| matches!(notice, UhidNotice::Failed(reason) if reason.contains("unexpected INPUT2")));
    fido.kernel.output(report(64, 1));
    assert_eq!(harness.input(), HostInput::FidoReport(fido_report(1)), "the device keeps working");
}

#[test]
fn attached_reports_whether_a_device_was_created() {
    let harness = Harness::new();
    assert_eq!(harness.attached(), Some(false));
    harness.enumerate(&identity(0x0407, ALL));
    let (otp, fido) = harness.devices();
    assert!(harness.attached_becomes(true));
    otp.kernel.close();
    fido.kernel.close();
    assert!(harness.attached_becomes(false));
}

#[test]
fn a_kernel_side_that_closes_ends_the_reader_and_the_device_is_replaced() {
    let (harness, otp, fido) = Harness::plugged();
    fido.kernel.close();
    harness.notice(|notice| *notice == UhidNotice::Ended { interface: HidInterface::Fido });
    // The writer follows the reader; once it has ended, outputs for FIDO are dropped.
    let deadline = Instant::now() + common::WAIT;
    while !harness.debug().contains("interface: Fido, reader_alive: false, writer_alive: false") {
        assert!(Instant::now() < deadline, "the FIDO device threads end");
        std::thread::sleep(Duration::from_millis(5));
    }
    harness.deliver(Output::FidoReport([1; 64]));
    assert_eq!(harness.stats().dropped, 1);
    // OTP is unaffected.
    otp.kernel.send(&feature(0, report(8, 1), 5));
    assert_eq!(otp.kernel.next(), Event::SetReportReply { id: 5, err: 0 });
    assert_eq!(harness.input(), HostInput::OtpSetFeature(report(8, 1).try_into().expect("8 bytes")));

    harness.enumerate(&identity(0x0407, ALL));
    assert_eq!(otp.kernel.next(), Event::Destroy);
    let (_otp, fido) = harness.devices();
    assert_eq!(harness.input(), POWER_CYCLE);
    fido.kernel.output(report(64, 2));
    assert_eq!(harness.input(), HostInput::FidoReport(fido_report(2)), "a new file replaces the ended one");
    let panicked = harness.notices().into_iter().any(|notice| notice.to_string().contains("panicked"));
    assert!(!panicked);
}

#[test]
fn dropping_the_transport_destroys_every_device_and_joins_its_threads() {
    let (harness, otp, fido) = Harness::plugged();
    let took = harness.drop_transport();
    assert_eq!(otp.kernel.next(), Event::Destroy);
    assert_eq!(fido.kernel.next(), Event::Destroy);
    assert!(otp.kernel.closes() && fido.kernel.closes(), "both files are closed");
    assert!(took < DROP_TIMEOUT, "every thread ended at its UHID_STOP; took {took:?}");
    let failures: Vec<String> = harness
        .notices()
        .into_iter()
        .filter(|notice| matches!(notice, UhidNotice::Failed(_)))
        .map(|notice| notice.to_string())
        .collect();
    assert!(failures.is_empty(), "{failures:?}");
}

#[test]
fn dropping_waits_a_bounded_time_for_a_device_the_kernel_never_stops() {
    let harness = Harness::with_mode(KernelMode { auto_start: true, auto_stop: false });
    harness.enumerate(&identity(0x0406, FIDO_CCID));
    let fido = harness.device();
    assert_eq!(harness.input(), POWER_CYCLE);
    let took = harness.drop_transport();
    assert_eq!(fido.kernel.next(), Event::Destroy);
    assert!(took >= DROP_TIMEOUT - Duration::from_millis(100), "took {took:?}");
    assert!(took < DROP_TIMEOUT * 4, "took {took:?}");
    harness
        .notice(|notice| matches!(notice, UhidNotice::Failed(reason) if reason.contains("reader thread did not end")));
    // The reader left behind ends once the kernel side closes.
    fido.kernel.close();
    assert!(fido.kernel.closes());
}

#[test]
fn a_device_that_cannot_be_opened_is_reported_and_nothing_is_plugged_in() {
    let harness = Harness::new();
    harness.fail_opens(true);
    harness.enumerate(&identity(0x0407, ALL));
    harness.notice(|notice| matches!(notice, UhidNotice::Failed(reason) if reason.contains("otp: cannot open")));
    harness.notice(|notice| matches!(notice, UhidNotice::Failed(reason) if reason.contains("fido: cannot open")));
    harness.no_input();
    assert_eq!(harness.attached(), Some(false));

    harness.fail_opens(false);
    harness.enumerate(&identity(0x0407, ALL));
    let _ = harness.devices();
    assert_eq!(harness.input(), POWER_CYCLE);
}

#[test]
fn debug_output_and_notices_name_sizes_not_report_bytes() {
    let (harness, otp, fido) = Harness::plugged();
    harness.deliver(Output::FidoReport([0xAB; 64]));
    assert_eq!(fido.kernel.next(), Event::Input2 { data: vec![0xAB; 64] });
    otp.kernel.send(&feature(0, vec![0xAB; 8], 3));
    assert_eq!(otp.kernel.next(), Event::SetReportReply { id: 3, err: 0 });
    let _ = harness.input();
    let debug = harness.debug();
    assert!(debug.contains("UhidTransport") && debug.contains("Fido") && debug.contains("Otp"), "{debug}");
    let mut text = debug;
    for notice in harness.notices() {
        text.push_str(&format!("{notice:?} {notice}\n"));
    }
    assert!(text.contains("INPUT2, 64 bytes"), "{text}");
    assert!(!text.contains("171") && !text.to_lowercase().contains("abab"), "{text}");
}

/// `retire` used to queue `UHID_DESTROY` behind a full write queue and lose it: the kernel
/// kept the old device (and its hidraw node) next to its replacement, and the old threads
/// and file stayed forever (`uhid_dev_destroy` in `drivers/hid/uhid.c` is the only way,
/// besides closing the file, to unregister the device).
#[test]
fn re_enumeration_destroys_the_old_device_even_when_its_write_queue_is_full() {
    const DELIVERED: usize = WRITE_QUEUE_EVENTS + 100;
    let (kernels_tx, kernels) = mpsc::channel();
    let (runner, commands) = mpsc::channel::<Command>();
    let mut transport = UhidTransport::new(Box::new(PairIo { kernels: kernels_tx }), runner);
    transport.enumerate(&identity(0x0402, FIDO_CCID));
    let mut old = kernels.recv_timeout(WAIT).expect("the FIDO device's file is opened");
    old.set_read_timeout(Some(WAIT)).expect("a read timeout can be set");
    // The device must be created before it is retired (else it writes nothing at all).
    assert!(matches!(read_event(&mut old), Ok(Event::Create2(_))), "the first event is UHID_CREATE2");

    // The kernel end does not read for now: the writer blocks after a few events (the
    // socket buffer is small) and the queue fills; the overflow is dropped.
    for seed in 0..DELIVERED {
        transport.deliver(Output::FidoReport([seed as u8; 64]));
    }
    let dropped = transport.stats().dropped;

    transport.enumerate(&identity(0x0402, FIDO_CCID));
    let mut new = kernels.recv_timeout(WAIT).expect("the new FIDO device's file is opened");

    // Now the old kernel end reads everything the writer sends.
    let mut events = Vec::new();
    while let Ok(event) = read_event(&mut old) {
        let destroy = event == Event::Destroy;
        events.push(event);
        if destroy {
            break;
        }
    }
    // The old writer has ended and closed its half; the new one writes CREATE2.
    new.set_read_timeout(Some(WAIT)).expect("a read timeout can be set");
    let created = read_event(&mut new);
    let stats = transport.stats();

    // Clean up before asserting, so a failure leaves no thread blocked on these sockets.
    let _ = old.shutdown(Shutdown::Both);
    let _ = new.shutdown(Shutdown::Both);
    drop(transport);
    drop(commands);

    assert!(dropped > 0, "the write queue was full ({dropped} outputs dropped)");
    assert_eq!(events.last(), Some(&Event::Destroy), "the old device got UHID_DESTROY after {} events", events.len());
    let written = events.iter().filter(|event| matches!(event, Event::Input2 { .. })).count();
    assert_eq!(events.len(), written + 1, "only INPUT2 and the final DESTROY were written");
    // Every report was written (what was queued at the unplug too) or dropped at the full
    // queue.
    assert_eq!(stats.dropped, (DELIVERED - written) as u64, "{stats:?}");
    assert!(matches!(created, Ok(Event::Create2(_))), "the new device is created: {created:?}");
}

/// The runner's channel is unbounded; without pacing, a process that can write the
/// hidraw node fills the daemon's memory while the runner is busy. With it, the kernel's
/// own bound applies (`UHID_BUFSIZE` 32 in `drivers/hid/uhid.c`, where `uhid_queue` drops
/// events once full), as lk-wire's reader leaves the rest in its socket.
#[test]
fn the_reader_stops_taking_reports_while_the_runner_takes_none() {
    const FLOOD: usize = 2048;
    let (kernels_tx, kernels) = mpsc::channel();
    // The runner is busy: it takes no command during the test.
    let (runner, commands) = mpsc::channel::<Command>();
    let mut transport = UhidTransport::new(Box::new(PairIo { kernels: kernels_tx }), runner);
    transport.enumerate(&identity(0x0402, FIDO_CCID));
    let mut kernel = kernels.recv_timeout(WAIT).expect("the FIDO device's file is opened");
    assert!(matches!(read_event(&mut kernel), Ok(Event::Create2(_))), "the first event is UHID_CREATE2");

    // A hidraw client writes 65-byte reports in a loop; each becomes one UHID_OUTPUT.
    let written = Arc::new(AtomicUsize::new(0));
    let flood = {
        let mut stream = kernel.try_clone().expect("the kernel end can be cloned");
        let written = Arc::clone(&written);
        thread::spawn(move || {
            let mut data = vec![0u8];
            data.extend([0x11; 64]);
            let bytes = Event::Output { data, rtype: ReportType::Output }.encode().expect("the event encodes");
            for _ in 0..FLOOD {
                if stream.write_all(&bytes).is_err() {
                    break;
                }
                written.fetch_add(1, Ordering::SeqCst);
            }
        })
    };

    // Wait until the flood is done, or has made no progress for a second (backpressure).
    let deadline = Instant::now() + WAIT;
    let (mut last, mut since) = (0, Instant::now());
    while Instant::now() < deadline {
        let now = written.load(Ordering::SeqCst);
        if now == FLOOD {
            break;
        }
        if now != last {
            (last, since) = (now, Instant::now());
        } else if since.elapsed() > Duration::from_secs(1) {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    // Let the reader take what reached its socket.
    thread::sleep(Duration::from_millis(300));
    let mut queued = 0;
    let mut markers = Vec::new();
    for command in commands.try_iter() {
        match command {
            Command::Input(HostInput::FidoReport(_)) => queued += 1,
            // Kept unanswered (dropping one would tell the reader the runner is gone).
            Command::Status(marker) => markers.push(marker),
            _ => {}
        }
    }
    let written = written.load(Ordering::SeqCst);

    let _ = kernel.shutdown(Shutdown::Both);
    let start = Instant::now();
    drop(transport);
    let took = start.elapsed();
    let _ = flood.join();
    drop(markers);

    assert!(
        (INPUT_WINDOW..=2 * INPUT_WINDOW).contains(&queued),
        "{queued} FIDO reports of {written} written sit in the runner's channel while the runner takes nothing"
    );
    assert!(written < FLOOD, "the flood was held up in the kernel's queue ({written} written)");
    assert!(took < DROP_TIMEOUT / 2, "dropping does not wait for the unanswered marker: took {took:?}");
}

#[test]
fn a_flood_of_reports_reaches_a_runner_that_keeps_up_in_full() {
    const FLOOD: usize = 10 * INPUT_WINDOW + 7;
    let (harness, _otp, fido) = Harness::plugged();
    for seed in 0..FLOOD {
        fido.kernel.output(report(64, seed as u8));
    }
    for seed in 0..FLOOD {
        assert_eq!(harness.input(), HostInput::FidoReport(fido_report(seed as u8)), "report {seed}");
    }
    harness.no_input();
}

/// `uhid_dev_create2` accepts the device and adds it later (`uhid_device_add_worker`); when
/// that fails, the kernel sends nothing and only refuses input with `-EINVAL`
/// (`uhid_dev_input2`, `drivers/hid/uhid.c`).
#[test]
fn a_device_the_kernel_does_not_run_is_reported_once_and_is_not_attached() {
    let harness = Harness::new();
    harness.enumerate(&identity(0x0406, FIDO_CCID));
    let fido = harness.device();
    assert_eq!(harness.input(), POWER_CYCLE);
    assert!(harness.attached_becomes(true));

    harness.refuse_input(true);
    for seed in 0..3 {
        harness.deliver(Output::FidoReport(fido_report(seed)));
    }
    harness.notice(|notice| *notice == UhidNotice::NotRunning { interface: HidInterface::Fido });
    assert!(harness.attached_becomes(false), "a device the kernel does not run is not attached");
    assert_eq!(harness.stats_become(|stats| stats.dropped == 3).dropped, 3);
    assert_eq!(fido.kernel.quiet(), None);
    let notices = harness.notices();
    let not_running = notices.iter().filter(|notice| matches!(notice, UhidNotice::NotRunning { .. })).count();
    assert_eq!(not_running, 0, "reported once (the first notice was taken above): {notices:?}");
    assert!(!notices.iter().any(|notice| matches!(notice, UhidNotice::Failed(_))), "{notices:?}");

    // The kernel still holds the device it could not add; the next enumeration destroys
    // it and creates a new one.
    harness.refuse_input(false);
    harness.enumerate(&identity(0x0406, FIDO_CCID));
    assert_eq!(fido.kernel.next(), Event::Destroy);
    let fido = harness.device();
    assert_eq!(harness.input(), POWER_CYCLE);
    assert!(harness.attached_becomes(true));
    harness.deliver(Output::FidoReport(fido_report(9)));
    assert_eq!(fido.kernel.next(), Event::Input2 { data: report(64, 9) });
}

/// Inputs the old devices handed to the runner before a re-enumeration are still queued
/// ahead of the fence; what the runner delivers before it takes the fence answers them and
/// must not reach the new devices.
#[test]
fn outputs_of_inputs_from_before_a_re_enumeration_do_not_reach_the_new_devices() {
    let (harness, otp, fido) = Harness::plugged();
    harness.enumerate_then_deliver(
        &identity(0x0407, ALL),
        vec![
            Output::FidoReport(fido_report(7)),
            Output::OtpKeyboard([0, 0, 4, 0, 0, 0, 0, 0]),
            Output::OtpFeature([2; 8]),
            Output::Ccid(vec![0x80; 10]),
        ],
    );
    assert_eq!(otp.kernel.next(), Event::Destroy);
    assert_eq!(fido.kernel.next(), Event::Destroy);
    let (otp, fido) = harness.devices();
    assert_eq!(harness.input(), POWER_CYCLE);
    assert_eq!(fido.kernel.quiet(), None);
    assert_eq!(otp.kernel.quiet(), None);
    assert_eq!(harness.stats(), UhidStats { ignored: 1, refused: 0, dropped: 3 });

    // Once the runner has taken the fence, outputs reach the new devices.
    harness.deliver(Output::FidoReport(fido_report(8)));
    assert_eq!(fido.kernel.next(), Event::Input2 { data: report(64, 8) });
    harness.set_answer(Answer::Feature([3; 8]));
    otp.kernel.send(&Event::GetReport { id: 5, rnum: 0, rtype: ReportType::Feature });
    assert_eq!(harness.input(), HostInput::OtpGetFeature);
    assert_eq!(otp.kernel.next(), Event::GetReportReply { id: 5, err: 0, data: [&[0][..], &[3; 8]].concat() });
}

#[test]
fn the_first_enumeration_sets_no_fence() {
    let harness = Harness::new();
    // Without earlier devices there is nothing stale: outputs delivered at once reach the
    // new device.
    harness.enumerate_then_deliver(&identity(0x0406, FIDO_CCID), vec![Output::FidoReport(fido_report(1))]);
    let fido = harness.device();
    assert_eq!(fido.kernel.next(), Event::Input2 { data: report(64, 1) });
    assert!(harness.debug().contains("fenced: false"), "{}", harness.debug());
}

/// A [`UhidIo`] like [`PairIo`] whose writers hold every `UHID_INPUT2` until the test
/// releases one, and tell the test when they start holding it.
#[derive(Debug)]
struct HeldIo {
    kernels: mpsc::Sender<UnixStream>,
    holding: mpsc::Sender<()>,
    release: Arc<Mutex<mpsc::Receiver<()>>>,
}

impl UhidIo for HeldIo {
    fn open(&mut self) -> io::Result<UhidHalves> {
        let (ours, theirs) = UnixStream::pair()?;
        let reader = ours.try_clone()?;
        let _ = self.kernels.send(theirs);
        let writer = HeldWriter { stream: ours, holding: self.holding.clone(), release: Arc::clone(&self.release) };
        Ok((Box::new(reader), Box::new(writer)))
    }
}

struct HeldWriter {
    stream: UnixStream,
    holding: mpsc::Sender<()>,
    release: Arc<Mutex<mpsc::Receiver<()>>>,
}

impl Write for HeldWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.get(..4) == Some(&UHID_INPUT2.to_ne_bytes()[..]) {
            let _ = self.holding.send(());
            let _ = self.release.lock().unwrap_or_else(PoisonError::into_inner).recv();
        }
        self.stream.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/// A re-enumeration right after another retires a device whose writer still waits for its
/// predecessor: it writes nothing, and its file is closed at once (a reader blocked in
/// `read()` on a file without a device would wait forever).
#[test]
fn a_device_retired_before_its_create2_was_written_closes_its_file_at_once() {
    let (kernels_tx, kernels) = mpsc::channel();
    let (holding_tx, holding) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    let io = HeldIo { kernels: kernels_tx, holding: holding_tx, release: Arc::new(Mutex::new(release_rx)) };
    let (runner, commands) = mpsc::channel::<Command>();
    let mut transport = UhidTransport::new(Box::new(io), runner);
    transport.enumerate(&identity(0x0402, FIDO_CCID));
    let mut first = kernels.recv_timeout(WAIT).expect("the first device's file is opened");
    // The first writer writes CREATE2, then holds an INPUT2.
    transport.deliver(Output::FidoReport([1; 64]));
    holding.recv_timeout(WAIT).expect("the first writer holds the INPUT2");
    // The second device's writer waits for the first's; the third enumeration retires the
    // second device before it wrote anything.
    transport.enumerate(&identity(0x0402, FIDO_CCID));
    let mut second = kernels.recv_timeout(WAIT).expect("the second device's file is opened");
    transport.enumerate(&identity(0x0402, FIDO_CCID));
    let mut third = kernels.recv_timeout(WAIT).expect("the third device's file is opened");
    release.send(()).expect("the first writer takes the release");

    first.set_read_timeout(Some(WAIT)).expect("a read timeout can be set");
    let mut first_events = Vec::new();
    while let Ok(event) = read_event(&mut first) {
        let destroy = event == Event::Destroy;
        first_events.push(event);
        if destroy {
            break;
        }
    }
    // macOS refuses a timeout on a socket whose peer is already closed (`EINVAL`); the
    // read then ends at once anyway.
    let _ = second.set_read_timeout(Some(WAIT));
    let second_event = read_event(&mut second);
    third.set_read_timeout(Some(WAIT)).expect("a read timeout can be set");
    let third_event = read_event(&mut third);

    for stream in [&first, &second, &third] {
        let _ = stream.shutdown(Shutdown::Both);
    }
    drop(transport);
    drop(commands);

    assert!(
        matches!(first_events.as_slice(), [Event::Create2(_), Event::Input2 { .. }, Event::Destroy]),
        "the first device was created, sent its held report and was destroyed: {first_events:?}"
    );
    assert!(
        matches!(&second_event, Err(error) if error.kind() == io::ErrorKind::UnexpectedEof),
        "the second file is closed without a single event: {second_event:?}"
    );
    assert!(matches!(third_event, Ok(Event::Create2(_))), "the third device is created: {third_event:?}");
}

/// The events a raw kernel end reads up to and including `UHID_DESTROY` (or until the
/// stream ends or times out).
fn events_until_destroy(stream: &mut UnixStream) -> Vec<Event> {
    let mut events = Vec::new();
    while let Ok(event) = read_event(stream) {
        let destroy = event == Event::Destroy;
        events.push(event);
        if destroy {
            break;
        }
    }
    events
}

/// Found on a real kernel (`tools/linux-guest/tests/uhid.sh`, ykman 5.8.0 over hidraw):
/// the OTP SET_REPORT that completes a Management write with REBOOT makes the device
/// re-enumerate while the reader still has to reply. The reply was dropped (the device was
/// already retiring) or discarded with the rest of the writer's queue, the DESTROY failed
/// the kernel's request, and `HIDIOCSFEATURE` returned `EIO` for a write that had taken
/// effect. A request whose input reached the runner gets its reply before the DESTROY, as
/// a USB device completes a control transfer before it acts on its data. The writer is
/// held up here (the kernel end does not read, the queue is full), so the reply is still
/// waiting when the device is retired.
#[test]
fn a_set_report_whose_input_re_enumerates_is_acknowledged_before_the_destroy() {
    let otp_only = lk_core::UsbInterfaces { otp: true, fido: false, ccid: false };
    let (kernels_tx, kernels) = mpsc::channel();
    let (runner, commands) = mpsc::channel::<Command>();
    let mut transport = UhidTransport::new(Box::new(PairIo { kernels: kernels_tx }), runner);
    transport.enumerate(&identity(0x0401, otp_only));
    let mut old = kernels.recv_timeout(WAIT).expect("the OTP device's file is opened");
    old.set_read_timeout(Some(WAIT)).expect("a read timeout can be set");
    assert!(matches!(read_event(&mut old), Ok(Event::Create2(_))), "the first event is UHID_CREATE2");
    for _ in 0..WRITE_QUEUE_EVENTS + 100 {
        transport.deliver(Output::OtpKeyboard([0, 0, 4, 0, 0, 0, 0, 0]));
    }
    let set = feature(0, [&[0][..], &report(8, 1)].concat(), 77).encode().expect("the event encodes");
    old.try_clone().expect("the kernel end can be cloned").write_all(&set).expect("the kernel writes");
    let deadline = Instant::now() + WAIT;
    let mut taken = false;
    while !taken && Instant::now() < deadline {
        taken = matches!(
            commands.recv_timeout(WAIT),
            Ok(Command::Input(HostInput::OtpSetFeature(report))) if report[..] == self::report(8, 1)[..]
        );
    }
    // The runner handled the input, and the device rebooted in the same batch.
    transport.enumerate(&identity(0x0401, otp_only));
    let mut new = kernels.recv_timeout(WAIT).expect("the new OTP device's file is opened");
    let events = events_until_destroy(&mut old);
    new.set_read_timeout(Some(WAIT)).expect("a read timeout can be set");
    let created = read_event(&mut new);

    let _ = old.shutdown(Shutdown::Both);
    let _ = new.shutdown(Shutdown::Both);
    drop(transport);
    drop(commands);

    assert!(taken, "the runner received the SET_REPORT's input");
    let replies: Vec<&Event> = events.iter().filter(|event| !matches!(event, Event::Input2 { .. })).collect();
    assert_eq!(
        replies,
        vec![&Event::SetReportReply { id: 77, err: 0 }, &Event::Destroy],
        "the SET_REPORT is acknowledged before the DESTROY ({} events)",
        events.len()
    );
    assert!(matches!(created, Ok(Event::Create2(_))), "the new device is created: {created:?}");
}

/// Found on a real kernel with ykman: after a Management write over OTP HID the host reads
/// the status with GET_REPORT(feature), and the device reboots right after answering it
/// (`lk_device`: an OTP HID write with REBOOT re-enumerates after the status read). The
/// answer reaches the reader only after the device is retiring; the reply must still be
/// written, before the DESTROY, or `HIDIOCGFEATURE` fails with `EIO` and ykman reports a
/// failed write.
#[test]
fn a_feature_read_answered_right_before_a_re_enumeration_gets_its_reply_before_the_destroy() {
    let (harness, otp, fido) = Harness::plugged();
    harness.set_answer(Answer::Feature([5; 8]));
    harness.reboot_after(HostInput::OtpGetFeature, &identity(0x0402, FIDO_CCID));
    otp.kernel.send(&Event::GetReport { id: 91, rnum: 0, rtype: ReportType::Feature });
    assert_eq!(harness.input(), HostInput::OtpGetFeature);
    assert_eq!(otp.kernel.next(), Event::GetReportReply { id: 91, err: 0, data: [&[0][..], &[5; 8]].concat() });
    assert_eq!(otp.kernel.next(), Event::Destroy);
    assert_eq!(fido.kernel.next(), Event::Destroy);
    let new = harness.device();
    assert_eq!(new.interface(), HidInterface::Fido);
    assert_eq!(harness.input(), POWER_CYCLE);
    assert_eq!(harness.stats(), UhidStats::default());
}

/// Found on a real kernel with ykman: the CTAPHID response to a Management write with
/// REBOOT is delivered right before the re-enumeration. The writer discarded whatever was
/// still queued once the device was retiring, so whether the host got the response (and
/// ykman reported success) depended on thread timing. Outputs delivered before a
/// re-enumeration are written, in order, before the DESTROY. The writer is held up here
/// (the kernel end does not read yet), so the reports are still queued at the unplug.
#[test]
fn outputs_delivered_before_a_re_enumeration_reach_the_old_device_before_its_destroy() {
    const DELIVERED: usize = 200;
    let (kernels_tx, kernels) = mpsc::channel();
    let (runner, commands) = mpsc::channel::<Command>();
    let mut transport = UhidTransport::new(Box::new(PairIo { kernels: kernels_tx }), runner);
    transport.enumerate(&identity(0x0402, FIDO_CCID));
    let mut old = kernels.recv_timeout(WAIT).expect("the FIDO device's file is opened");
    old.set_read_timeout(Some(WAIT)).expect("a read timeout can be set");
    assert!(matches!(read_event(&mut old), Ok(Event::Create2(_))), "the first event is UHID_CREATE2");
    for seed in 0..DELIVERED {
        transport.deliver(Output::FidoReport([seed as u8; 64]));
    }
    transport.enumerate(&identity(0x0402, FIDO_CCID));
    let mut new = kernels.recv_timeout(WAIT).expect("the new FIDO device's file is opened");
    let events = events_until_destroy(&mut old);
    new.set_read_timeout(Some(WAIT)).expect("a read timeout can be set");
    let created = read_event(&mut new);
    let stats = transport.stats();

    let _ = old.shutdown(Shutdown::Both);
    let _ = new.shutdown(Shutdown::Both);
    drop(transport);
    drop(commands);

    let seeds: Vec<u8> = events
        .iter()
        .filter_map(|event| match event {
            Event::Input2 { data } => Some(data[0]),
            _ => None,
        })
        .collect();
    assert_eq!(seeds, (0..DELIVERED).map(|seed| seed as u8).collect::<Vec<u8>>(), "every report, in order");
    assert_eq!(events.last(), Some(&Event::Destroy));
    assert_eq!(events.len(), DELIVERED + 1, "only the reports and the DESTROY");
    assert_eq!(stats.dropped, 0, "{stats:?}");
    assert!(matches!(created, Ok(Event::Create2(_))), "the new device is created: {created:?}");
}

/// Found on a real kernel with ykman: with the reply to the status read written right
/// before the DESTROY, `HIDIOCGFEATURE` still failed with `EIO`. `uhid_hid_get_report`
/// (and `uhid_hid_set_report`) checks after waking whether the device still runs
/// (`__uhid_report_queue_and_wait` in `drivers/hid/uhid.c`), and a DESTROY written right
/// behind the reply clears that before the woken caller gets to look. The DESTROY waits
/// [`DESTROY_AFTER_REPLY`] after the last reply, as a USB device's reboot comes some time
/// after the control transfer it answered.
#[test]
fn the_destroy_after_a_reply_leaves_the_caller_time_to_take_it() {
    let (harness, otp, _fido) = Harness::plugged();
    harness.set_answer(Answer::Feature([6; 8]));
    harness.reboot_after(HostInput::OtpGetFeature, &identity(0x0402, FIDO_CCID));
    otp.kernel.send(&Event::GetReport { id: 92, rnum: 0, rtype: ReportType::Feature });
    assert_eq!(harness.input(), HostInput::OtpGetFeature);
    assert!(matches!(otp.kernel.next(), Event::GetReportReply { id: 92, err: 0, .. }));
    let replied = Instant::now();
    assert_eq!(otp.kernel.next(), Event::Destroy);
    let gap = replied.elapsed();
    // The fake kernel's thread hands the reply over a little after it was written.
    assert!(gap >= DESTROY_AFTER_REPLY - Duration::from_millis(20), "DESTROY {gap:?} after the reply");
    assert!(gap < DESTROY_AFTER_REPLY + Duration::from_secs(1), "DESTROY {gap:?} after the reply");
}
