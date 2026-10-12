//! `CTAPHID_CANCEL` (CTAP 2.1 §11.2.9.1.5): it cancels only the outstanding CBOR
//! request of its own channel, and it is never answered by the framer.

mod common;

use common::*;
use lk_ctaphid::Event;

fn cancel(cid: u32) -> Report {
    init_packet(cid, CANCEL, 0, &[])
}

#[test]
fn cancel_during_cbor_reports_cancel_and_keeps_the_request_outstanding() {
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let b = allocate(&mut dev, 0);
    start_cbor(&mut dev, 1, a, &[0x01, 0xA0]);
    assert_eq!(dev.report(2, &cancel(a)), vec![Event::Cancel { cid: a }]);
    // The application still has to answer (with CTAP2_ERR_KEEPALIVE_CANCEL 0x2D).
    assert_eq!(dev.outstanding(), Some((a, CBOR)));
    assert_eq!(
        dev.report(2, &init_packet(b, PING, 1, &[1])),
        error_events(b, ERR_CHANNEL_BUSY)
    );
    assert_eq!(
        reassemble(&dev.respond(a, CBOR, &[0x2D])),
        (a, CBOR, vec![0x2D])
    );
    assert_ping_echo(&mut dev, 3, b, 1);
}

#[test]
fn cancel_during_u2f_msg_is_ignored_while_init_still_aborts() {
    // `reference/BEHAVIOR_CATALOG.md` FIDO: "CTAPHID_CANCEL during a U2F MSG is ignored
    // while same-CID INIT still aborts".
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    let apdu = [0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x40];
    let events = dev.report(1, &init_packet(cid, MSG, apdu.len() as u16, &apdu));
    assert_eq!(
        events,
        vec![Event::Request {
            cid,
            cmd: MSG,
            payload: apdu.to_vec()
        }]
    );
    assert_eq!(dev.report(2, &cancel(cid)), vec![]);
    assert_eq!(dev.outstanding(), Some((cid, MSG)));
    let events = dev.report(3, &init_packet(cid, INIT, 8, &[1; 8]));
    assert_eq!(events.first(), Some(&Event::Abort { cid }));
    assert_eq!(dev.outstanding(), None);
}

#[test]
fn cancel_during_a_vendor_request_is_ignored() {
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    assert_eq!(
        dev.report(1, &init_packet(cid, 0x42, 0, &[])),
        vec![Event::Request {
            cid,
            cmd: 0x42,
            payload: vec![]
        }]
    );
    assert_eq!(dev.report(2, &cancel(cid)), vec![]);
    assert_eq!(dev.outstanding(), Some((cid, 0x42)));
}

#[test]
fn cancel_on_an_idle_or_foreign_channel_is_ignored_silently() {
    // CTAP 2.1 §11.2.9.1.5: "A CTAPHID_CANCEL received while no CTAPHID_CBOR request is
    // being processed, or on a non-active CID SHALL be ignored."
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let b = allocate(&mut dev, 0);
    for cid in [a, b, 0, BROADCAST, 0x7777_7777] {
        assert_eq!(dev.report(1, &cancel(cid)), vec![], "idle, CID {cid:#x}");
    }
    start_cbor(&mut dev, 2, a, &[0x01]);
    for cid in [b, 0, BROADCAST, 0x7777_7777] {
        assert_eq!(dev.report(3, &cancel(cid)), vec![], "busy, CID {cid:#x}");
    }
    assert_eq!(dev.outstanding(), Some((a, CBOR)));
}

#[test]
fn cancel_while_the_message_is_still_arriving_is_ignored() {
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    let payload = pattern(130, 2);
    let request = message(cid, CBOR, &payload);
    assert_eq!(feed(&mut dev, 1, &request[..2]), vec![]);
    assert_eq!(dev.report(1, &cancel(cid)), vec![]);
    assert_eq!(
        feed(&mut dev, 1, &request[2..]),
        vec![Event::Request {
            cid,
            cmd: CBOR,
            payload
        }]
    );
}

#[test]
fn cancel_with_nonzero_bcnt_still_cancels_and_never_starts_a_message() {
    // Model policy: CANCEL is honoured whatever its BCNT (the spec asks for 0) and
    // never opens a multi-packet transaction.
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    start_cbor(&mut dev, 1, cid, &[0x01]);
    assert_eq!(
        dev.report(2, &init_packet(cid, CANCEL, 100, &[0; 57])),
        vec![Event::Cancel { cid }]
    );
    assert_eq!(dev.next_deadline(), None);
    assert_eq!(dev.report(2, &cont_packet(cid, 0, &[0; 59])), vec![]);
}

#[test]
fn cancel_after_a_refused_empty_cbor_request_is_ignored() {
    // CTAP 2.1 §11.2.9.1.2 and §11.2.9.1.6: an empty CBOR request is ERR_INVALID_LEN and
    // starts nothing, so a CANCEL on its channel finds no outstanding request and is not
    // answered (§11.2.9.1.5); CANCEL from another channel is not answered either, and a
    // real CBOR request afterwards is cancelled as usual. Known difference: the YubiKey
    // reference key stays busy after the empty request and ignores CANCEL
    // (docs/MEASUREMENT.md, probe empty-cbor); that stall is a defect not copied
    // (§11.2.4, §11.2.5.2, "Revised by principle"). This test checked CANCEL during the
    // stall between the measurement and that revision, and CANCEL under a CTAPHID_LOCK
    // before the measurement (probe lock).
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let b = allocate(&mut dev, 0);
    assert_eq!(
        dev.report(1, &init_packet(a, CBOR, 0, &[])),
        error_events(a, ERR_INVALID_LEN)
    );
    assert_eq!(dev.report(2, &cancel(a)), vec![]);
    assert_eq!(dev.report(2, &cancel(b)), vec![]);
    assert_ping_echo(&mut dev, 3, b, 0);
    start_cbor(&mut dev, 5, a, &[0x01]);
    assert_eq!(dev.report(6, &cancel(a)), vec![Event::Cancel { cid: a }]);
}
