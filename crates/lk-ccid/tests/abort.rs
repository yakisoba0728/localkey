//! ABORT (USB CCID Rev 1.1 §5.3.1 control request, §6.1.13 `PC_to_RDR_Abort`) in
//! either delivery order, and the slot after a USB reset or resume
//! (reference/BEHAVIOR_CATALOG.md, transports: "control/bulk ABORT in either delivery
//! order"; Linux_native: after resume "each occupied slot becomes inactive, insertion
//! 5003 once, no unpowered APDU, new PowerOn/ATR required").

mod common;

use common::{ALL, ATR, ATR_PARAMS, MAX_DATA, cmd, failed, powered, reply, rsp, send_apdu, xfr};
use lk_ccid::CcidAction;

const OK_ACTIVE: u8 = 0x00;
const OK_INACTIVE: u8 = 0x01;
const FAILED_ACTIVE: u8 = 0x40;
const FAILED_INACTIVE: u8 = 0x41;
/// §6.2.6 CMD_ABORTED.
const CMD_ABORTED: u8 = 0xFF;

fn abort(seq: u8) -> Vec<u8> {
    cmd(0x72, 0, seq, [0; 3], &[])
}

fn slot_status_ok(seq: u8) -> Vec<u8> {
    rsp(0x81, seq, OK_ACTIVE, 0x00, 0x00, &[])
}

#[test]
fn bulk_abort_on_an_idle_slot_succeeds() {
    let mut ccid = powered();
    assert_eq!(reply(ccid.message(&abort(1))), slot_status_ok(1));
    send_apdu(&mut ccid, 2, &[0x00, 0xCA, 0x00, 0x00]);
}

#[test]
fn bulk_abort_on_an_inactive_slot_reports_it_inactive() {
    let mut ccid = lk_ccid::Ccid::new(ATR.to_vec());
    assert_eq!(
        reply(ccid.message(&abort(1))),
        rsp(0x81, 1, OK_INACTIVE, 0x00, 0x00, &[])
    );
}

#[test]
fn bulk_abort_cancels_an_outstanding_apdu() {
    let mut ccid = powered();
    send_apdu(&mut ccid, 3, &[0x00, 0x87, 0x07, 0x9E]);
    assert_eq!(reply(ccid.message(&abort(4))), slot_status_ok(4));
    assert_eq!(ccid.pending_seq(), None);
    // The late card answer is discarded.
    assert_eq!(ccid.apdu_response(3, &[0x90, 0x00]), Vec::<u8>::new());
    send_apdu(&mut ccid, 5, &[0x00, 0xCA, 0x00, 0x00]);
}

#[test]
fn bulk_abort_drops_command_and_response_chains() {
    let mut ccid = powered();
    reply(ccid.message(&xfr(1, 0x0001, &[0x00, 0xDB])));
    assert_eq!(reply(ccid.message(&abort(2))), slot_status_ok(2));
    assert_eq!(
        reply(ccid.message(&xfr(3, 0x0002, &[0x3F]))),
        rsp(0x80, 3, FAILED_ACTIVE, 0x08, 0, &[])
    );

    send_apdu(&mut ccid, 4, &[0x00, 0xCB, 0x3F, 0xFF]);
    ccid.apdu_response(4, &vec![0; MAX_DATA + 1]);
    assert_eq!(reply(ccid.message(&abort(5))), slot_status_ok(5));
    assert_eq!(
        reply(ccid.message(&xfr(6, 0x0010, &[]))),
        rsp(0x80, 6, FAILED_ACTIVE, 0x08, 0, &[])
    );
}

#[test]
fn control_then_bulk_abort() {
    let mut ccid = powered();
    send_apdu(&mut ccid, 0x10, &[0x00, 0x87, 0x07, 0x9E]);
    // The control request answers the outstanding XfrBlock with CMD_ABORTED.
    let aborted = ccid.control_abort(0, 0x11);
    assert_eq!(
        aborted,
        Some(rsp(0x80, 0x10, FAILED_ACTIVE, CMD_ABORTED, 0x00, &[]))
    );
    assert_eq!(ccid.pending_seq(), None);
    assert_eq!(ccid.apdu_response(0x10, &[0x90, 0x00]), Vec::<u8>::new());
    // Until the matching bulk Abort, other messages fail with CMD_ABORTED.
    let r = reply(ccid.message(&cmd(0x65, 0, 0x12, [0; 3], &[])));
    assert_eq!(r, rsp(0x81, 0x12, FAILED_ACTIVE, CMD_ABORTED, 0x00, &[]));
    let r = reply(ccid.message(&xfr(0x13, 0x0000, &[0x00, 0xCA, 0x00, 0x00])));
    assert_eq!(r, rsp(0x80, 0x13, FAILED_ACTIVE, CMD_ABORTED, 0x00, &[]));
    // A bulk Abort with another bSeq does not complete it.
    let r = reply(ccid.message(&abort(0x14)));
    assert_eq!(r, rsp(0x81, 0x14, FAILED_ACTIVE, CMD_ABORTED, 0x00, &[]));
    // The matching one does.
    assert_eq!(reply(ccid.message(&abort(0x11))), slot_status_ok(0x11));
    send_apdu(&mut ccid, 0x15, &[0x00, 0xCA, 0x00, 0x00]);
}

#[test]
fn control_abort_on_an_idle_slot() {
    let mut ccid = powered();
    assert_eq!(ccid.control_abort(0, 0x20), None);
    let r = reply(ccid.message(&cmd(0x65, 0, 0x21, [0; 3], &[])));
    assert_eq!(r, rsp(0x81, 0x21, FAILED_ACTIVE, CMD_ABORTED, 0x00, &[]));
    assert_eq!(reply(ccid.message(&abort(0x20))), slot_status_ok(0x20));
    let r = reply(ccid.message(&cmd(0x65, 0, 0x22, [0; 3], &[])));
    assert_eq!(r, slot_status_ok(0x22));
}

#[test]
fn bulk_then_control_abort() {
    let mut ccid = powered();
    send_apdu(&mut ccid, 0x30, &[0x00, 0x87, 0x07, 0x9E]);
    assert_eq!(reply(ccid.message(&abort(0x31))), slot_status_ok(0x31));
    // The late control request for the same bSeq changes nothing.
    assert_eq!(ccid.control_abort(0, 0x31), None);
    let r = reply(ccid.message(&cmd(0x65, 0, 0x32, [0; 3], &[])));
    assert_eq!(r, slot_status_ok(0x32));
    send_apdu(&mut ccid, 0x33, &[0x00, 0xCA, 0x00, 0x00]);
}

#[test]
fn control_abort_for_another_slot_is_ignored() {
    let mut ccid = powered();
    send_apdu(&mut ccid, 0x40, &[0x00, 0x87, 0x07, 0x9E]);
    assert_eq!(ccid.control_abort(1, 0x41), None);
    assert_eq!(ccid.pending_seq(), Some(0x40));
}

#[test]
fn bulk_abort_errors() {
    let mut ccid = powered();
    send_apdu(&mut ccid, 0x50, &[0x00, 0x87, 0x07, 0x9E]);
    // dwLength must be 0 (bError 01) and the slot must exist (bError 05); neither
    // malformed Abort cancels the APDU.
    let r = reply(ccid.message(&cmd(0x72, 0, 0x51, [0; 3], &[0x00])));
    assert_eq!(r, rsp(0x81, 0x51, FAILED_ACTIVE, 0x01, 0x00, &[]));
    let mut expected = rsp(0x81, 0x52, 0x42, 0x05, 0x00, &[]);
    expected[5] = 1;
    assert_eq!(
        reply(ccid.message(&cmd(0x72, 1, 0x52, [0; 3], &[]))),
        expected
    );
    assert_eq!(ccid.pending_seq(), Some(0x50));
}

#[test]
fn reset_deactivates_the_slot() {
    let mut ccid = powered();
    let block = [0x11, 0x10, 0x00, 0x15, 0x00, 0xFE, 0x00];
    reply(ccid.message(&cmd(0x61, 0, 1, [1, 0, 0], &block)));
    send_apdu(&mut ccid, 2, &[0x00, 0x87, 0x07, 0x9E]);
    ccid.reset();
    assert!(!ccid.is_active());
    assert_eq!(ccid.pending_seq(), None);
    assert_eq!(ccid.parameters_in_force().to_bytes(), ATR_PARAMS);
    assert_eq!(ccid.apdu_response(2, &[0x90, 0x00]), Vec::<u8>::new());
    // The device announces the ICC once on the interrupt pipe.
    assert_eq!(ccid.slot_change(true), [0x50, 0x03]);
    let r = reply(ccid.message(&cmd(0x65, 0, 3, [0; 3], &[])));
    assert_eq!(r, rsp(0x81, 3, OK_INACTIVE, 0x00, 0x00, &[]));
    // No unpowered APDU.
    let r = reply(ccid.message(&xfr(4, 0x0000, &[0x00, 0xCA, 0x00, 0x00])));
    assert_eq!(r, rsp(0x80, 4, FAILED_INACTIVE, 0xFE, 0x00, &[]));
    // A cold IccPowerOn with the ATR is required again.
    assert_eq!(
        ccid.message(&cmd(0x62, 0, 5, [0; 3], &[])),
        CcidAction::Reply(rsp(0x80, 5, OK_ACTIVE, 0, 0, &ATR))
    );
}

#[test]
fn reset_clears_a_pending_control_abort_and_chains() {
    let mut ccid = powered();
    reply(ccid.message(&xfr(1, 0x0001, &[0x00, 0xDB])));
    assert_eq!(ccid.control_abort(0, 2), None);
    ccid.reset();
    let r = reply(ccid.message(&cmd(0x65, 0, 3, [0; 3], &[])));
    assert_eq!(r, rsp(0x81, 3, OK_INACTIVE, 0x00, 0x00, &[]));
    reply(ccid.message(&cmd(0x62, 0, 4, [0; 3], &[])));
    assert_eq!(
        reply(ccid.message(&xfr(5, 0x0002, &[0x3F]))),
        rsp(0x80, 5, FAILED_ACTIVE, 0x08, 0, &[])
    );
}

#[test]
fn messages_between_control_and_bulk_abort_fail_in_their_reply_type() {
    // §5.3.1: after the control ABORT every bulk-out message except the matching
    // PC_to_RDR_Abort fails with CMD_ABORTED, in the reply type of its command, and
    // takes no effect (IccPowerOff does not power down, XfrBlock is not forwarded).
    let mut ccid = powered();
    assert_eq!(ccid.control_abort(0, 0x60), None);
    for (seq, (kind, specific, data, response)) in (0x61..).zip(ALL) {
        let r = reply(ccid.message(&cmd(kind, 0, seq, specific, data)));
        assert_eq!(
            r,
            failed(response, seq, FAILED_ACTIVE, CMD_ABORTED),
            "{kind:#04x}"
        );
    }
    assert!(ccid.is_active());
    assert_eq!(ccid.pending_seq(), None);
    assert_eq!(reply(ccid.message(&abort(0x60))), slot_status_ok(0x60));
    send_apdu(&mut ccid, 0x70, &[0x00, 0xCA, 0x00, 0x00]);
}

#[test]
fn late_control_abort_does_not_wedge_the_slot() {
    // Either delivery order (BEHAVIOR_CATALOG transports: "control/bulk ABORT in either
    // delivery order"): when the bulk Abort came first and was already answered, the
    // host may send more messages before the control request is delivered. That
    // late request must not make the slot fail every later message with CMD_ABORTED.
    let mut ccid = powered();
    send_apdu(&mut ccid, 0x30, &[0x00, 0x87, 0x07, 0x9E]);
    assert_eq!(reply(ccid.message(&abort(0x31))), slot_status_ok(0x31));
    assert_eq!(
        reply(ccid.message(&cmd(0x65, 0, 0x32, [0; 3], &[]))),
        slot_status_ok(0x32)
    );
    send_apdu(&mut ccid, 0x33, &[0x00, 0xCA, 0x00, 0x00]);
    assert_eq!(
        ccid.apdu_response(0x33, &[0x90, 0x00]),
        rsp(0x80, 0x33, OK_ACTIVE, 0, 0, &[0x90, 0x00])
    );
    // The control request for the Abort with bSeq 31 finally arrives.
    assert_eq!(ccid.control_abort(0, 0x31), None);
    assert_eq!(
        reply(ccid.message(&cmd(0x65, 0, 0x34, [0; 3], &[]))),
        slot_status_ok(0x34)
    );
    send_apdu(&mut ccid, 0x35, &[0x00, 0xCA, 0x00, 0x00]);
}

#[test]
fn a_newer_bulk_abort_replaces_an_unmatched_one() {
    // Two bulk Aborts without control requests: only the newer one is still waiting
    // for its control request, so a control request for the older bSeq starts a new
    // abort that the host must finish with a matching PC_to_RDR_Abort.
    let mut ccid = powered();
    assert_eq!(reply(ccid.message(&abort(0x01))), slot_status_ok(0x01));
    assert_eq!(reply(ccid.message(&abort(0x02))), slot_status_ok(0x02));
    assert_eq!(ccid.control_abort(0, 0x02), None);
    assert_eq!(
        reply(ccid.message(&cmd(0x65, 0, 0x03, [0; 3], &[]))),
        slot_status_ok(0x03)
    );
    assert_eq!(ccid.control_abort(0, 0x01), None);
    let r = reply(ccid.message(&cmd(0x65, 0, 0x04, [0; 3], &[])));
    assert_eq!(r, rsp(0x81, 0x04, FAILED_ACTIVE, CMD_ABORTED, 0x00, &[]));
    assert_eq!(reply(ccid.message(&abort(0x01))), slot_status_ok(0x01));
    assert_eq!(
        reply(ccid.message(&cmd(0x65, 0, 0x05, [0; 3], &[]))),
        slot_status_ok(0x05)
    );
}

#[test]
fn control_abort_drops_command_and_response_chains() {
    let mut ccid = powered();
    reply(ccid.message(&xfr(1, 0x0001, &[0x00, 0xDB])));
    assert_eq!(ccid.control_abort(0, 2), None);
    assert_eq!(reply(ccid.message(&abort(2))), slot_status_ok(2));
    assert_eq!(
        reply(ccid.message(&xfr(3, 0x0002, &[0x3F]))),
        rsp(0x80, 3, FAILED_ACTIVE, 0x08, 0, &[])
    );

    send_apdu(&mut ccid, 4, &[0x00, 0xCB, 0x3F, 0xFF]);
    ccid.apdu_response(4, &vec![0; MAX_DATA + 1]);
    assert_eq!(ccid.control_abort(0, 5), None);
    assert_eq!(reply(ccid.message(&abort(5))), slot_status_ok(5));
    assert_eq!(
        reply(ccid.message(&xfr(6, 0x0010, &[]))),
        rsp(0x80, 6, FAILED_ACTIVE, 0x08, 0, &[])
    );
}

#[test]
fn control_abort_of_a_chained_command_answers_its_last_part() {
    // The APDU assembled from 0001/0002 belongs to the XfrBlock that ended it, so the
    // CMD_ABORTED DataBlock carries that message's bSeq.
    let mut ccid = powered();
    reply(ccid.message(&xfr(0x10, 0x0001, &[0x00, 0xDB])));
    assert!(matches!(
        ccid.message(&xfr(0x11, 0x0002, &[0x3F, 0xFF])),
        CcidAction::Apdu { seq: 0x11, .. }
    ));
    assert_eq!(
        ccid.control_abort(0, 0x12),
        Some(rsp(0x80, 0x11, FAILED_ACTIVE, CMD_ABORTED, 0x00, &[]))
    );
    assert_eq!(reply(ccid.message(&abort(0x12))), slot_status_ok(0x12));
}

#[test]
fn abort_and_power_off_on_an_inactive_slot_report_it_inactive() {
    // After IccPowerOff a control/bulk abort pair still completes, and the
    // SlotStatus reports bmICCStatus 1 (catalog: slot status after power off).
    let mut ccid = powered();
    assert!(matches!(
        ccid.message(&cmd(0x63, 0, 1, [0; 3], &[])),
        CcidAction::PowerOff(_)
    ));
    assert_eq!(ccid.control_abort(0, 2), None);
    let r = reply(ccid.message(&cmd(0x65, 0, 3, [0; 3], &[])));
    assert_eq!(r, rsp(0x81, 3, FAILED_INACTIVE, CMD_ABORTED, 0x00, &[]));
    assert_eq!(
        reply(ccid.message(&abort(2))),
        rsp(0x81, 2, OK_INACTIVE, 0x00, 0x00, &[])
    );
    let r = reply(ccid.message(&xfr(4, 0x0000, &[0x00, 0xCA, 0x00, 0x00])));
    assert_eq!(r, rsp(0x80, 4, FAILED_INACTIVE, 0xFE, 0x00, &[]));
}
