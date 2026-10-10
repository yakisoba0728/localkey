//! End-to-end tests of the gadget transport against a fake kernel (socket pairs for the
//! FunctionFS files, a temporary directory for ConfigFS) and a fake runner.

mod common;

use std::fs;
use std::io::Read;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use common::{
    ALL, FIDO_CCID, FakeKernel, Harness, Outcome, REFERENCE_CONFIGURATION, TestDir, WAIT, ccid_message, hex, identity,
    request,
};
use lk_device::{BusEvent, Output};
use lk_gadget::ffs::Event;
use lk_gadget::{DRAIN_TIMEOUT, GadgetConfig, GadgetEvent, GadgetTransport, OTP_REPORT_TIMEOUT, Observer};
use lk_run::{Command, HostInput, Transport};

/// FIDO+CCID endpoint files: FIDO OUT, FIDO IN, CCID bulk OUT, bulk IN, interrupt IN.
const FIDO_OUT: usize = 1;
const FIDO_IN: usize = 2;
const CCID_OUT: usize = 3;
const CCID_IN: usize = 4;
const CCID_INT: usize = 5;

/// A harness enumerated as FIDO+CCID, plugged in (BIND, ENABLE → PowerCycle).
fn plugged_in() -> (Harness, common::KernelSession) {
    let harness = Harness::new();
    harness.enumerate(&identity(FIDO_CCID));
    let session = harness.kernel.session();
    session.ep0.event(Event::Bind);
    session.ep0.event(Event::Enable);
    assert_eq!(harness.input(), HostInput::Bus(BusEvent::PowerCycle));
    (harness, session)
}

#[test]
fn enumeration_writes_the_configfs_tree_and_the_ep0_blobs_then_binds() {
    let harness = Harness::new();
    harness.enumerate(&identity(FIDO_CCID));
    let session = harness.kernel.session();
    // Descriptors: V2 magic, length, FS only, 9 descriptors, then the reference bytes
    // after the 9-byte configuration header.
    let reference = hex(REFERENCE_CONFIGURATION);
    let mut expected = Vec::new();
    for field in [3u32, (16 + reference.len() - 9) as u32, 1, 9] {
        expected.extend_from_slice(&field.to_le_bytes());
    }
    expected.extend_from_slice(&reference[9..]);
    assert_eq!(session.descriptors, expected);
    assert_eq!(session.strings, [2, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(session.endpoints.keys().copied().collect::<Vec<_>>(), [1, 2, 3, 4, 5]);
    let mount_point = harness.config.mount_point.display().to_string();
    assert_eq!(
        harness.kernel.log(),
        [
            format!("mount lkf {mount_point}"),
            "open ep0".into(),
            "open ep1 out".into(),
            "open ep2 in".into(),
            "open ep3 out".into(),
            "open ep4 in".into(),
            "open ep5 in".into(),
            "bind dummy_udc.0".into(),
        ]
    );
    assert_eq!(harness.read("idVendor"), "0x1050\n");
    assert_eq!(harness.read("idProduct"), "0x0406\n");
    assert_eq!(harness.read("max_speed"), "full-speed\n");
    assert_eq!(harness.read("strings/0x409/serialnumber"), "12345678\n");
    assert_eq!(harness.read("configs/c.1/MaxPower"), "30\n");
    assert_eq!(harness.read("UDC"), "dummy_udc.0\n");
    let link = fs::read_link(harness.gadget().join("configs/c.1/ffs.lkf")).expect("the function is linked");
    assert_eq!(link, harness.gadget().join("functions/ffs.lkf"));
    let events = harness.events();
    assert!(events.contains(&GadgetEvent::Enumerated { product_id: 0x0406, interfaces: FIDO_CCID }), "{events:?}");
    assert!(events.contains(&GadgetEvent::Bound { udc: "dummy_udc.0".into() }), "{events:?}");
    assert_eq!(harness.attached(), Some(false), "not configured before ENABLE");
}

#[test]
fn the_first_enable_is_a_plug_in_and_further_enables_of_the_same_configuration_are_not_resets() {
    let (harness, session) = plugged_in();
    assert_eq!(harness.attached(), Some(true));
    session.ep0.event(Event::Enable);
    session.ep0.event(Event::Enable);
    harness.assert_quiet();
    session.ep0.event(Event::Disable);
    session.ep0.event(Event::Enable);
    assert_eq!(harness.input(), HostInput::Bus(BusEvent::Reset));
}

#[test]
fn a_report_descriptor_request_for_the_fido_interface_gets_the_fido_report_descriptor() {
    let (_harness, session) = plugged_in();
    let outcome = session.ep0.setup(request(0x81, 0x06, 0x2200, 0, 0xFF), &[]);
    assert_eq!(outcome, Outcome::Reply(lk_device::FIDO_REPORT_DESCRIPTOR.to_vec()));
    let outcome = session.ep0.setup(request(0x81, 0x06, 0x2100, 0, 9), &[]);
    assert_eq!(outcome, Outcome::Reply(hex("092110010001222200")));
}

#[test]
fn unknown_requests_are_stalled_by_a_read_for_in_and_a_write_for_out() {
    let (harness, session) = plugged_in();
    assert_eq!(session.ep0.setup(request(0xA1, 0x02, 0, 1, 4), &[]), Outcome::Stall, "GET_CLOCK_FREQUENCIES");
    assert_eq!(session.ep0.setup(request(0x21, 0x55, 0, 0, 3), &[1, 2, 3]), Outcome::Stall);
    assert_eq!(session.ep0.setup(request(0x81, 0x06, 0x2200, 7, 64), &[]), Outcome::Stall, "no interface 7");
    // The control pipe still works after stalls.
    let outcome = session.ep0.setup(request(0xA1, 0x03, 0, 0, 1), &[]);
    assert_eq!(outcome, Outcome::Reply(vec![1]));
    harness.assert_quiet();
}

#[test]
fn requests_without_data_are_acknowledged_with_the_status_stage() {
    let (harness, session) = plugged_in();
    assert_eq!(session.ep0.setup(request(0x21, 0x0A, 0x0400, 0, 0), &[]), Outcome::Read(0), "SET_IDLE");
    assert_eq!(session.ep0.setup(request(0xA1, 0x02, 0, 0, 1), &[]), Outcome::Reply(vec![4]));
    assert_eq!(session.ep0.setup(request(0x21, 0x01, 0x0900, 1, 0), &[]), Outcome::Read(0), "CCID ABORT");
    assert_eq!(harness.input(), HostInput::CcidControlAbort { slot: 0, seq: 9 });
}

#[test]
fn a_fido_set_report_on_the_control_pipe_reaches_the_runner_as_a_fido_report() {
    let (harness, session) = plugged_in();
    let report = [0x42u8; 64];
    assert_eq!(session.ep0.setup(request(0x21, 0x09, 0x0200, 0, 64), &report), Outcome::Read(64));
    assert_eq!(harness.input(), HostInput::FidoReport(report));
    // A data stage shorter than wLength is not a report.
    assert_eq!(session.ep0.setup(request(0x21, 0x09, 0x0200, 0, 64), &report[..10]), Outcome::Read(10));
    harness.assert_quiet();
}

#[test]
fn a_fido_out_packet_reaches_the_runner_as_a_fido_report() {
    let (harness, mut session) = plugged_in();
    let mut report = [0u8; 64];
    report[..7].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0x86, 0x00, 0x08]);
    session.write_out(FIDO_OUT, &report);
    assert_eq!(harness.input(), HostInput::FidoReport(report));
    session.write_out(FIDO_OUT, &[0x11; 64]);
    assert_eq!(harness.input(), HostInput::FidoReport([0x11; 64]));
}

#[test]
fn a_ccid_message_split_in_packets_reaches_the_runner_as_one_message() {
    let (harness, mut session) = plugged_in();
    let message = ccid_message(100, 1);
    session.write_out(CCID_OUT, &message[..64]);
    session.write_out(CCID_OUT, &message[64..]);
    assert_eq!(harness.input(), HostInput::Ccid(message));
    // A message that fills one packet exactly needs no zero-length packet.
    let exact = ccid_message(54, 2);
    session.write_out(CCID_OUT, &exact);
    assert_eq!(harness.input(), HostInput::Ccid(exact));
    let short = ccid_message(5, 3);
    session.write_out(CCID_OUT, &short);
    assert_eq!(harness.input(), HostInput::Ccid(short));
}

#[test]
fn delivered_outputs_appear_on_their_in_endpoints() {
    let (harness, mut session) = plugged_in();
    harness.deliver(Output::FidoReport([0x5A; 64]));
    assert_eq!(session.read_in(FIDO_IN, 64), vec![0x5A; 64]);
    let response = ccid_message(30, 4);
    harness.deliver(Output::Ccid(response.clone()));
    assert_eq!(session.read_in(CCID_IN, response.len()), response);
    let full = ccid_message(118, 5);
    harness.deliver(Output::Ccid(full.clone()));
    assert_eq!(session.read_in(CCID_IN, full.len()), full);
    harness.deliver(Output::CcidInterrupt(vec![0x50, 0x03]));
    assert_eq!(session.read_in(CCID_INT, 2), vec![0x50, 0x03]);
    // No OTP interface in this enumeration: keyboard reports have nowhere to go.
    harness.deliver(Output::OtpKeyboard([0, 0, 4, 0, 0, 0, 0, 0]));
    harness.deliver(Output::PresenceIndicator(true));
    harness.deliver(Output::FidoReport([0x5B; 64]));
    assert_eq!(session.read_in(FIDO_IN, 64), vec![0x5B; 64]);
}

#[test]
fn suspend_and_resume_become_bus_events() {
    let (harness, session) = plugged_in();
    session.ep0.event(Event::Suspend);
    assert_eq!(harness.input(), HostInput::Bus(BusEvent::Suspend));
    session.ep0.event(Event::Suspend);
    session.ep0.event(Event::Resume);
    assert_eq!(harness.input(), HostInput::Bus(BusEvent::Resume));
    assert!(harness.events().contains(&GadgetEvent::Bus(BusEvent::Suspend)));
}

#[test]
fn an_otp_get_report_is_answered_with_the_feature_report_the_runner_delivers() {
    let harness = Harness::new();
    *harness.otp_answer.lock().expect("not poisoned") = Some([1, 2, 3, 4, 5, 6, 7, 8]);
    harness.enumerate(&identity(ALL));
    let mut session = harness.kernel.session();
    session.ep0.event(Event::Enable);
    assert_eq!(harness.input(), HostInput::Bus(BusEvent::PowerCycle));
    let outcome = session.ep0.setup(request(0xA1, 0x01, 0x0300, 0, 8), &[]);
    assert_eq!(outcome, Outcome::Reply(vec![1, 2, 3, 4, 5, 6, 7, 8]));
    assert_eq!(harness.input(), HostInput::OtpGetFeature);
    // The answer is cut to wLength.
    let outcome = session.ep0.setup(request(0xA1, 0x01, 0x0300, 0, 3), &[]);
    assert_eq!(outcome, Outcome::Reply(vec![1, 2, 3]));
    assert_eq!(harness.input(), HostInput::OtpGetFeature);
    // SET_REPORT(feature) goes the other way.
    let outcome = session.ep0.setup(request(0x21, 0x09, 0x0300, 0, 8), &[9; 8]);
    assert_eq!(outcome, Outcome::Read(8));
    assert_eq!(harness.input(), HostInput::OtpSetFeature([9; 8]));
    // Keyboard reports go to the OTP interrupt IN endpoint, ep1 in this enumeration.
    harness.deliver(Output::OtpKeyboard([0, 0, 0x0B, 0, 0, 0, 0, 0]));
    assert_eq!(session.read_in(1, 8), vec![0, 0, 0x0B, 0, 0, 0, 0, 0]);
}

#[test]
fn an_otp_get_report_the_device_does_not_answer_is_stalled() {
    let harness = Harness::new();
    harness.enumerate(&identity(ALL));
    let session = harness.kernel.session();
    session.ep0.event(Event::Enable);
    assert_eq!(harness.input(), HostInput::Bus(BusEvent::PowerCycle));
    assert_eq!(session.ep0.setup(request(0xA1, 0x01, 0x0300, 0, 8), &[]), Outcome::Stall);
    assert_eq!(harness.input(), HostInput::OtpGetFeature);
}

#[test]
fn re_enumeration_unbinds_rewrites_the_product_id_and_reopens_with_the_new_interfaces() {
    let (harness, mut first) = plugged_in();
    harness.enumerate(&identity(ALL));
    let mut second = harness.kernel.session();
    // The old session ended: ep0 was closed after UNBIND and the endpoints were shut down.
    assert_eq!(first.ep0.outcome(), Outcome::Closed);
    let mut byte = [0u8; 1];
    assert_eq!(first.endpoint(FIDO_IN).read(&mut byte).expect("a shut down socket reads end of file"), 0);
    let log = harness.kernel.log();
    let mount_point = harness.config.mount_point.display().to_string();
    assert_eq!(
        log[8..],
        [
            "unbind".to_owned(),
            "open ep0".into(),
            "open ep1 in".into(),
            "open ep2 out".into(),
            "open ep3 in".into(),
            "open ep4 out".into(),
            "open ep5 in".into(),
            "open ep6 in".into(),
            "bind dummy_udc.0".into(),
        ]
    );
    assert_eq!(log.iter().filter(|line| line.starts_with("mount")).count(), 1, "mounted once: {log:?}");
    assert_eq!(log[0], format!("mount lkf {mount_point}"));
    assert_eq!(harness.read("idProduct"), "0x0407\n");
    assert_eq!(harness.read("strings/0x409/product"), "YubiKey OTP+FIDO+CCID\n");
    assert_eq!(harness.read("UDC"), "dummy_udc.0\n");
    let all = identity(ALL).configuration_descriptor();
    assert_eq!(second.descriptors[12..16], 12u32.to_le_bytes());
    assert_eq!(second.descriptors[16..], all[9..]);
    // The new binding is a new plug-in.
    second.ep0.event(Event::Enable);
    assert_eq!(harness.input(), HostInput::Bus(BusEvent::PowerCycle));
    // FIDO moved to interface 1 and ep2/ep3.
    let outcome = second.ep0.setup(request(0x81, 0x06, 0x2200, 1, 0xFF), &[]);
    assert_eq!(outcome, Outcome::Reply(lk_device::FIDO_REPORT_DESCRIPTOR.to_vec()));
    second.write_out(2, &[0x77; 64]);
    assert_eq!(harness.input(), HostInput::FidoReport([0x77; 64]));
    harness.deliver(Output::FidoReport([0x78; 64]));
    assert_eq!(second.read_in(3, 64), vec![0x78; 64]);
    assert!(harness.events().contains(&GadgetEvent::Unbound));
}

/// Found with ykman over the Linux guest's `dummy_hcd` (`tools/linux-guest/tests/gadget.sh`,
/// step 5): `ykman config usb --disable OTP` over OTP HID printed "Failed to configure USB
/// applications" although the device rebooted with the new configuration. `lk_device`
/// answers the status read that reports the write (GET_REPORT(feature)) and reboots right
/// after it; the runner then re-enumerates before it answers the request's marker, and
/// the transport unbound with the GET_REPORT still waiting for that marker, so the host's
/// request failed. Now the re-enumeration drains: the request takes the answer the runner
/// delivered, and the reply goes out before the unbind.
#[test]
fn an_otp_get_report_answered_right_before_a_re_enumeration_gets_its_reply_before_the_unbind() {
    let harness = Harness::new();
    *harness.otp_answer.lock().expect("not poisoned") = Some([0, 5, 7, 4, 0x2A, 0, 0, 0]);
    harness.enumerate(&identity(ALL));
    let first = harness.kernel.session();
    first.ep0.event(Event::Bind);
    first.ep0.event(Event::Enable);
    assert_eq!(harness.input(), HostInput::Bus(BusEvent::PowerCycle));
    *harness.reboot_after_get_feature.lock().expect("not poisoned") = Some(identity(FIDO_CCID));
    let start = Instant::now();
    let outcome = first.ep0.setup(request(0xA1, 0x01, 0x0300, 0, 8), &[]);
    assert_eq!(outcome, Outcome::Reply(vec![0, 5, 7, 4, 0x2A, 0, 0, 0]), "the reply, not a cancelled request");
    assert!(start.elapsed() < OTP_REPORT_TIMEOUT, "answered without waiting for the marker: {:?}", start.elapsed());
    assert_eq!(harness.input(), HostInput::OtpGetFeature);
    // The re-enumeration went on: the old session ended and the new one is FIDO+CCID.
    let mut second = harness.kernel.session();
    assert_eq!(first.ep0.outcome(), Outcome::Closed);
    assert_eq!(harness.read("idProduct"), "0x0406\n");
    second.ep0.event(Event::Enable);
    assert_eq!(harness.input(), HostInput::Bus(BusEvent::PowerCycle));
    harness.deliver(Output::FidoReport([0x31; 64]));
    assert_eq!(second.read_in(FIDO_IN, 64), vec![0x31; 64]);
}

/// The response to the command that rebooted the device (a CCID WRITE CONFIG response, a
/// CTAPHID response) is delivered right before `Output::Reenumerate`. The writer used to
/// see the stop flag and drop what was still queued, and the unbind ended a write in
/// progress, so whether the host got the response depended on thread timing (it did in
/// the guest's runs over CCID and FIDO HID, by luck). Here IN writes complete only when the
/// host takes them: one is in progress and one queued when the re-enumeration starts, and
/// both reach the host before the unbind.
#[test]
fn responses_queued_before_a_re_enumeration_reach_the_host_before_the_unbind() {
    let harness = Harness::new();
    harness.kernel.acknowledge_in(true);
    harness.enumerate(&identity(FIDO_CCID));
    let mut first = harness.kernel.session();
    first.ep0.event(Event::Bind);
    first.ep0.event(Event::Enable);
    assert_eq!(harness.input(), HostInput::Bus(BusEvent::PowerCycle));
    let in_progress = ccid_message(300, 8);
    let response = ccid_message(20, 9);
    harness.deliver(Output::Ccid(in_progress.clone()));
    harness.deliver(Output::FidoReport([0x42; 64]));
    harness.deliver(Output::Ccid(response.clone()));
    let done = harness.enumerate_in_background(&identity(ALL));
    thread::sleep(Duration::from_millis(100));
    assert_eq!(first.read_acknowledged(CCID_IN), Some(in_progress), "the write in progress completes");
    assert_eq!(first.read_acknowledged(CCID_IN), Some(response), "the queued response follows before the unbind");
    assert_eq!(first.read_acknowledged(FIDO_IN), Some(vec![0x42; 64]), "the queued CTAPHID report too");
    done.recv_timeout(WAIT).expect("the re-enumeration ends");
    assert_eq!(first.ep0.outcome(), Outcome::Closed);
    assert_eq!(first.read_acknowledged(CCID_IN), None, "the unbind ended the endpoint");
    let second = harness.kernel.session();
    second.ep0.event(Event::Enable);
    assert_eq!(harness.input(), HostInput::Bus(BusEvent::PowerCycle));
    let failed = harness.events().into_iter().any(|event| matches!(event, GadgetEvent::Failed(_)));
    assert!(!failed, "{:?}", harness.events());
}

/// A host that does not read holds a re-enumeration up for at most `DRAIN_TIMEOUT`; what
/// it did not take is dropped and reported.
#[test]
fn a_re_enumeration_waits_at_most_the_drain_timeout_for_a_host_that_does_not_read() {
    let (harness, _first) = plugged_in();
    harness.deliver(Output::Ccid(vec![0x80; 4 * 1024 * 1024]));
    let start = Instant::now();
    harness.enumerate(&identity(ALL));
    let took = start.elapsed();
    assert!(took >= DRAIN_TIMEOUT, "drained for {took:?}");
    assert!(took < DRAIN_TIMEOUT + Duration::from_secs(5), "drained for {took:?}");
    let second = harness.kernel.session();
    second.ep0.event(Event::Enable);
    assert_eq!(harness.input(), HostInput::Bus(BusEvent::PowerCycle));
    let reported = harness.events().into_iter().any(|event| {
        matches!(&event, GadgetEvent::Failed(reason) if reason.contains("did not read 1 queued response"))
    });
    assert!(reported, "{:?}", harness.events());
}

/// `dummy_hcd` reports SUSPEND before UNBIND whenever the gadget is unbound (seen in the
/// Linux guest at every re-enumeration: "gadget: bus Suspend", then "gadget: unbound").
/// That SUSPEND reached the runner after the re-enumeration and suspended the rebooted
/// device until the host configured it. A session the transport is ending passes no bus
/// event any more.
#[test]
fn bus_events_of_a_session_the_transport_is_ending_do_not_reach_the_runner() {
    let (harness, _first) = plugged_in();
    harness.kernel.suspend_on_unbind(true);
    harness.enumerate(&identity(ALL));
    let second = harness.kernel.session();
    second.ep0.event(Event::Bind);
    second.ep0.event(Event::Enable);
    assert_eq!(harness.input(), HostInput::Bus(BusEvent::PowerCycle), "no Suspend from the old session first");
    assert!(!harness.events().contains(&GadgetEvent::Bus(BusEvent::Suspend)), "{:?}", harness.events());
    // An unbind the transport did not cause still passes its SUSPEND: the session is live
    // until UNBIND.
    harness.kernel.unbind_externally();
    assert_eq!(harness.input(), HostInput::Bus(BusEvent::Suspend));
}

#[test]
fn dropping_the_transport_unbinds_unmounts_and_removes_what_it_created() {
    let (harness, session) = plugged_in();
    harness.drop_transport();
    assert_eq!(session.ep0.outcome(), Outcome::Closed);
    let log = harness.kernel.log();
    let mount_point = harness.config.mount_point.display().to_string();
    assert_eq!(log[log.len() - 2..], ["unbind".to_owned(), format!("umount {mount_point}")]);
    assert_eq!(harness.read("UDC"), "\n");
    assert!(fs::symlink_metadata(harness.gadget().join("configs/c.1/ffs.lkf")).is_err(), "the link is gone");
    assert!(!harness.gadget().join("functions/ffs.lkf").exists(), "the empty function directory is gone");
    // On a plain filesystem the other directories keep their attribute files; the
    // failures are reported, not fatal.
    let failures = harness.events().iter().filter(|e| matches!(e, GadgetEvent::Failed(_))).count();
    assert_eq!(failures, 3, "{:?}", harness.events());
}

#[test]
fn a_failed_unmount_leaves_the_configfs_tree_in_place() {
    let (harness, _session) = plugged_in();
    harness.kernel.fail_unmount(true);
    harness.drop_transport();
    assert!(harness.gadget().join("configs/c.1/ffs.lkf").exists(), "the link is still there");
    assert!(harness.gadget().join("functions/ffs.lkf").is_dir());
    let events = harness.events();
    let reported = events.iter().any(|e| matches!(e, GadgetEvent::Failed(r) if r.contains("left in place")));
    assert!(reported, "{events:?}");
}

#[test]
fn a_failed_bind_leaves_the_gadget_unbound_and_the_next_enumeration_binds() {
    let harness = Harness::new();
    harness.kernel.fail_bind(true);
    harness.enumerate(&identity(FIDO_CCID));
    assert!(!harness.kernel.has_session());
    let failed = harness.events().into_iter().any(|e| matches!(&e, GadgetEvent::Failed(r) if r.contains("bind")));
    assert!(failed, "{:?}", harness.events());
    harness.kernel.fail_bind(false);
    harness.enumerate(&identity(FIDO_CCID));
    let session = harness.kernel.session();
    session.ep0.event(Event::Enable);
    assert_eq!(harness.input(), HostInput::Bus(BusEvent::PowerCycle));
    let log = harness.kernel.log();
    assert_eq!(log.iter().filter(|line| line.starts_with("mount")).count(), 1, "{log:?}");
    assert_eq!(log.iter().filter(|line| *line == "open ep0").count(), 2, "{log:?}");
}

#[test]
fn an_unbind_by_someone_else_ends_the_control_pipe_and_a_later_enumeration_recovers() {
    let (harness, session) = plugged_in();
    session.ep0.event(Event::Disable);
    session.ep0.event(Event::Unbind);
    assert_eq!(session.ep0.outcome(), Outcome::Closed);
    assert_eq!(harness.attached(), Some(false));
    harness.enumerate(&identity(FIDO_CCID));
    let again = harness.kernel.session();
    again.ep0.event(Event::Enable);
    assert_eq!(harness.input(), HostInput::Bus(BusEvent::PowerCycle));
}

#[test]
fn an_unbind_by_someone_else_ends_the_session_and_closes_every_functionfs_file() {
    let (harness, _session) = plugged_in();
    assert_eq!(harness.kernel.open_files(), 6, "ep0 and five endpoint files");
    harness.kernel.unbind_externally();
    // With every file closed f_fs resets, so a bind from outside fails cleanly instead of
    // presenting a function nobody serves.
    assert!(harness.kernel.wait_open_files(0), "{} files still open", harness.kernel.open_files());
    assert_eq!(harness.attached(), Some(false));
    let ended = harness.events().into_iter().any(|e| matches!(&e, GadgetEvent::Failed(r) if r.contains("someone else")));
    assert!(ended, "{:?}", harness.events());
    // Outputs have nowhere to go, and the next enumeration presents the device again.
    harness.deliver(Output::FidoReport([0x33; 64]));
    harness.enumerate(&identity(FIDO_CCID));
    let mut again = harness.kernel.session();
    again.ep0.event(Event::Bind);
    again.ep0.event(Event::Enable);
    assert_eq!(harness.input(), HostInput::Bus(BusEvent::PowerCycle));
    harness.deliver(Output::FidoReport([0x34; 64]));
    assert_eq!(again.read_in(FIDO_IN, 64), vec![0x34; 64]);
}

/// The observer runs on the `ep0` thread inside the handling of the `ENABLE`, between
/// the bus event and the update of the configured state. Holding the thread there until
/// the re-enumeration has unbound the old session only widens a window that exists
/// anyway: the old session's thread may finish handling an `ENABLE` after the transport
/// started ending that session.
#[test]
fn attached_is_false_after_a_re_enumeration_until_the_new_session_is_configured() {
    let dir = TestDir::new();
    let root = dir.path().join("cfg");
    fs::create_dir(&root).expect("the configfs root can be created");
    let config = GadgetConfig {
        configfs_root: root,
        gadget_name: "lk".into(),
        function_name: "lkf".into(),
        mount_point: dir.path().join("ffs"),
        udc: "dummy_udc.0".into(),
    };
    let kernel = FakeKernel::new();
    type Gate = Option<(Sender<()>, Receiver<()>)>;
    let (entered_tx, entered) = mpsc::channel::<()>();
    let (release, release_rx) = mpsc::channel::<()>();
    let gate: Arc<Mutex<Gate>> = Arc::new(Mutex::new(Some((entered_tx, release_rx))));
    let observer: Observer = Arc::new(move |event: &GadgetEvent| {
        if matches!(event, GadgetEvent::Bus(BusEvent::PowerCycle)) {
            let taken = gate.lock().unwrap_or_else(PoisonError::into_inner).take();
            if let Some((entered, release)) = taken {
                let _ = entered.send(());
                let _ = release.recv_timeout(WAIT);
            }
        }
    });
    let (commands_tx, _commands) = mpsc::channel::<Command>();
    let mut transport = GadgetTransport::with_io(config, commands_tx, kernel.io(), Some(observer))
        .expect("the configuration is valid");
    transport.enumerate(&identity(FIDO_CCID));
    let first = kernel.session();
    first.ep0.event(Event::Bind);
    first.ep0.event(Event::Enable);
    entered.recv_timeout(WAIT).expect("the ep0 thread handles the ENABLE");
    let watcher = kernel.clone();
    thread::spawn(move || {
        let start = Instant::now();
        while !watcher.log().iter().any(|line| line == "unbind") && start.elapsed() < WAIT {
            thread::sleep(Duration::from_millis(5));
        }
        thread::sleep(Duration::from_millis(500));
        let _ = release.send(());
    });
    transport.enumerate(&identity(FIDO_CCID));
    let second = kernel.session();
    assert_eq!(transport.attached(), Some(false), "the new session has seen no ENABLE yet");
    second.ep0.event(Event::Bind);
    second.ep0.event(Event::Enable);
    let start = Instant::now();
    while transport.attached() != Some(true) && start.elapsed() < WAIT {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(transport.attached(), Some(true), "configured once the new session is enabled");
}

/// `dwMaxCCIDMessageLength` is the largest whole message, header included (USB CCID Rev
/// 1.1 §5.1: "between 261 + 10 (header) and 65544 + 10"); the reference class descriptor
/// advertises 3072.
#[test]
fn a_ccid_message_longer_than_the_advertised_maximum_message_length_is_not_passed_on() {
    let (harness, mut session) = plugged_in();
    let too_long = ccid_message(3072 - 10 + 1, 1);
    assert_eq!(too_long.len(), 3073);
    for packet in too_long.chunks(64) {
        session.write_out(CCID_OUT, packet);
        thread::sleep(Duration::from_millis(1));
    }
    // The pause keeps the socket pair from merging the next message with the last
    // packet, which a USB transfer never does.
    thread::sleep(Duration::from_millis(200));
    let largest = ccid_message(3072 - 10, 2);
    for packet in largest.chunks(64) {
        session.write_out(CCID_OUT, packet);
        thread::sleep(Duration::from_millis(1));
    }
    match harness.input() {
        HostInput::Ccid(message) if message == largest => {}
        HostInput::Ccid(message) => {
            panic!("a {}-byte message was passed on instead of the 3072-byte one", message.len())
        }
        other => panic!("unexpected input {other:?}"),
    }
    let dropped = harness.events().into_iter().any(|e| matches!(e, GadgetEvent::Dropped { .. }));
    assert!(dropped, "{:?}", harness.events());
}

#[test]
fn an_interrupted_data_stage_is_repeated_and_later_events_stay_aligned() {
    let (harness, session) = plugged_in();
    // f_fs keeps the SETUP pending after EINTR; a transport that went back to reading
    // events would read the host's data as events.
    let report = [0x5Au8; 64];
    let outcome = session.ep0.setup_interrupted(request(0x21, 0x09, 0x0200, 0, 64), &report, 2);
    assert_eq!(outcome, Outcome::Read(64));
    assert_eq!(harness.input(), HostInput::FidoReport(report));
    let ack = session.ep0.setup_interrupted(request(0x21, 0x01, 0x0300, 1, 0), &[], 1);
    assert_eq!(ack, Outcome::Read(0), "CCID ABORT acknowledged after an interruption");
    assert_eq!(harness.input(), HostInput::CcidControlAbort { slot: 0, seq: 3 });
    let reply = session.ep0.setup_interrupted(request(0xA1, 0x03, 0, 0, 1), &[], 1);
    assert_eq!(reply, Outcome::Reply(vec![1]), "GET_PROTOCOL answered after an interruption");
    session.ep0.event(Event::Suspend);
    assert_eq!(harness.input(), HostInput::Bus(BusEvent::Suspend));
}

#[test]
fn host_data_of_a_data_stage_left_pending_is_never_read_as_events() {
    let (harness, session) = plugged_in();
    // Every repeat is interrupted too, so the SETUP stays pending and the next event read
    // is its data stage: 48 bytes of the host's report, whose first chunk carries the
    // UNBIND type byte at offset 8 (with nonzero padding, which a real event never has).
    let mut report = [0x11u8; 64];
    report[8] = 1;
    let interrupts = u32::try_from(lk_gadget::io::INTERRUPTED_RETRIES + 1).expect("small");
    let outcome = session.ep0.setup_interrupted(request(0x21, 0x09, 0x0200, 0, 64), &report, interrupts);
    assert_eq!(outcome, Outcome::Read(48), "the event read was served as the data stage");
    harness.assert_quiet();
    session.ep0.event(Event::Suspend);
    assert_eq!(harness.input(), HostInput::Bus(BusEvent::Suspend), "the session goes on with aligned events");
    assert_eq!(harness.attached(), Some(true));
}

/// The position of the first log line equal to `line`.
fn position(log: &[String], line: &str) -> usize {
    log.iter().position(|entry| entry == line).unwrap_or_else(|| panic!("{line:?} is not in {log:?}"))
}

/// What a process killed right after it made the gadget directory leaves (the kernel
/// unbinds a gadget when its FunctionFS files close, `ffs_closed`; the mount stays). An
/// empty gadget directory is also the only leftover a plain file system lets the
/// ConfigFS removal order take apart: on ConfigFS, attribute files and default groups go
/// with their directory, on a plain file system they stay and the `rmdir` fails.
#[test]
fn a_leftover_of_a_killed_process_is_unmounted_and_removed_and_the_gadget_created_again() {
    let old_mount = std::env::temp_dir().join("lk-old-ffs");
    let harness = Harness::prepared(|config, kernel| {
        fs::create_dir(config.configfs_root.join("lk")).expect("the leftover can be planted");
        kernel.mounted("lkf", &old_mount);
    });
    harness.enumerate(&identity(FIDO_CCID));
    let session = harness.kernel.session();
    session.ep0.event(Event::Bind);
    session.ep0.event(Event::Enable);
    assert_eq!(harness.input(), HostInput::Bus(BusEvent::PowerCycle));
    let log = harness.kernel.log();
    let new_mount = harness.config.mount_point.display().to_string();
    let (query, umount, mount) = (
        position(&log, "mounts of lkf"),
        position(&log, &format!("umount {}", old_mount.display())),
        position(&log, &format!("mount lkf {new_mount}")),
    );
    assert!(query < umount && umount < mount, "{log:?}");
    let reclaimed = GadgetEvent::Reclaimed { gadget: harness.gadget(), unmounted: vec![old_mount.clone()] };
    assert!(harness.events().contains(&reclaimed), "{:?}", harness.events());
    assert_eq!(harness.read("idVendor"), "0x1050\n", "the gadget was created again");
    assert_eq!(harness.kernel.mount_points(), std::slice::from_ref(&harness.config.mount_point));
}

#[test]
fn a_leftover_whose_functionfs_is_still_in_use_is_left_in_place_and_nothing_is_bound() {
    let old_mount = std::env::temp_dir().join("lk-busy-ffs");
    let harness = Harness::prepared(|config, kernel| {
        fs::create_dir_all(config.configfs_root.join("lk/functions/ffs.lkf")).expect("the leftover can be planted");
        kernel.mounted("lkf", &old_mount);
        kernel.fail_unmount(true);
    });
    harness.enumerate(&identity(FIDO_CCID));
    assert!(!harness.kernel.has_session());
    let events = harness.events();
    let reported = events
        .iter()
        .any(|e| matches!(e, GadgetEvent::Failed(r) if r.contains("umount") && r.contains("Left in place")));
    assert!(reported, "{events:?}");
    assert!(harness.gadget().join("functions/ffs.lkf").is_dir(), "the function under the live mount stays");
    let log = harness.kernel.log();
    assert!(!log.iter().any(|line| line.starts_with("mount ") || line.starts_with("bind")), "{log:?}");
}

/// A whole leftover tree on a plain file system: the link and the empty function
/// directory go, `configs/c.1` keeps its attribute files (on ConfigFS they go with it),
/// so the reclaim stops there, is reported, and nothing is mounted or bound.
#[test]
fn a_leftover_that_cannot_be_removed_is_reported_and_nothing_is_mounted_or_bound() {
    let harness = Harness::prepared(|config, _| {
        let gadget = config.configfs_root.join("lk");
        for dir in ["functions/ffs.lkf", "configs/c.1", "strings/0x409"] {
            fs::create_dir_all(gadget.join(dir)).expect("the leftover can be planted");
        }
        std::os::unix::fs::symlink(gadget.join("functions/ffs.lkf"), gadget.join("configs/c.1/ffs.lkf"))
            .expect("the link can be planted");
        fs::write(gadget.join("configs/c.1/MaxPower"), "30\n").expect("an attribute");
        fs::write(gadget.join("UDC"), "\n").expect("an attribute");
    });
    harness.enumerate(&identity(FIDO_CCID));
    assert!(!harness.kernel.has_session());
    let events = harness.events();
    let reported = events
        .iter()
        .any(|e| matches!(e, GadgetEvent::Failed(r) if r.starts_with("leftover gadget") && r.contains("c.1")));
    assert!(reported, "{events:?}");
    assert!(!events.iter().any(|e| matches!(e, GadgetEvent::Reclaimed { .. })), "{events:?}");
    assert!(fs::symlink_metadata(harness.gadget().join("configs/c.1/ffs.lkf")).is_err(), "the link went first");
    let log = harness.kernel.log();
    assert!(!log.iter().any(|line| line.starts_with("mount ") || line.starts_with("bind")), "{log:?}");
}
