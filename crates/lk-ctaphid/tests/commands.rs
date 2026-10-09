//! Command dispatch: WINK, MSG, CBOR, vendor commands, unknown commands and
//! capability gating (CTAP 2.1 §11.2.9).

mod common;

use common::*;
use lk_ctaphid::{Ctaphid, Event};

#[test]
fn zero_length_wink_winks_and_answers_empty() {
    // CTAP 2.1 §11.2.9.2.1: request and response both have BCNT 0.
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    let events = dev.report(1, &init_packet(cid, WINK, 0, &[]));
    assert_eq!(
        events,
        vec![Event::Wink, Event::Send(init_packet(cid, WINK, 0, &[]))]
    );
}

#[test]
fn wink_with_payload_is_invalid_len_and_the_channel_recovers() {
    // `reference/BEHAVIOR_CATALOG.md` FIDO: "CTAPHID WINK rejects nonzero BCNT with
    // ERR_INVALID_LEN while zero-length WINK and subsequent PING succeed."
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    for bcnt in [1u16, 2, 57, 58, 7609] {
        assert_eq!(
            dev.report(1, &init_packet(cid, WINK, bcnt, &[0x55])),
            error_events(cid, ERR_INVALID_LEN),
            "BCNT {bcnt}"
        );
        assert_eq!(
            dev.next_deadline(),
            None,
            "no transaction started for BCNT {bcnt}"
        );
    }
    assert_eq!(
        dev.report(2, &cont_packet(cid, 0, &[0x55])),
        vec![],
        "orphan"
    );
    assert_eq!(
        dev.report(3, &init_packet(cid, WINK, 0, &[])),
        vec![Event::Wink, Event::Send(init_packet(cid, WINK, 0, &[]))]
    );
    assert_ping_echo(&mut dev, 4, cid, 8);
}

#[test]
fn msg_and_vendor_commands_reach_the_application() {
    // CTAP 2.1 §11.2.9.1.1 (MSG) and §11.2.9.3 (vendor commands 0x40..=0x7F).
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    for cmd in [MSG, 0x40, 0x42, 0x43, 0x7F] {
        let payload = pattern(70, cmd);
        let events = feed(&mut dev, 1, &message(cid, cmd, &payload));
        assert_eq!(
            events,
            vec![Event::Request { cid, cmd, payload }],
            "command {cmd:#x}"
        );
        assert_eq!(dev.outstanding(), Some((cid, cmd)));
        let reports = dev.respond(cid, cmd, &[0x90, 0x00]);
        assert_eq!(reassemble(&reports), (cid, cmd, vec![0x90, 0x00]));
    }
    // Vendor commands have no length rule in the specification (§11.2.9.3): a
    // zero-length vendor request is the application's to judge.
    let events = dev.report(2, &init_packet(cid, 0x41, 0, &[]));
    assert_eq!(
        events,
        vec![Event::Request {
            cid,
            cmd: 0x41,
            payload: vec![]
        }]
    );
    assert_eq!(dev.respond(cid, 0x41, &[]).len(), 1);
}

#[test]
fn empty_cbor_request_is_invalid_len() {
    // CTAP 2.1 §11.2.9.1.2: a CBOR request carries at least the command byte.
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    assert_eq!(
        dev.report(1, &init_packet(cid, CBOR, 0, &[])),
        error_events(cid, ERR_INVALID_LEN)
    );
    assert_eq!(dev.outstanding(), None);
    assert_eq!(dev.next_deadline(), None);
    assert_ping_echo(&mut dev, 2, cid, 1);
}

#[test]
fn empty_msg_request_is_invalid_len() {
    // CTAP 2.1 §11.2.9.1.1: a CTAPHID_MSG request has `BCNT 1..(n+1)`, the U2F command
    // byte then data, exactly like CTAPHID_CBOR. A one-byte MSG is still passed on.
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    assert_eq!(
        dev.report(1, &init_packet(cid, MSG, 0, &[])),
        error_events(cid, ERR_INVALID_LEN)
    );
    assert_eq!(dev.outstanding(), None);
    assert_ping_echo(&mut dev, 2, cid, 1);
    assert_eq!(
        dev.report(3, &init_packet(cid, MSG, 1, &[0x00])),
        vec![Event::Request {
            cid,
            cmd: MSG,
            payload: vec![0x00]
        }]
    );
}

#[test]
fn unknown_and_device_only_commands_are_invalid_cmd() {
    // CTAP 2.1 §11.2.9: KEEPALIVE and ERROR are device-to-host only; the other codes
    // below are unassigned. The command is checked before BCNT.
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    for cmd in [
        0x00, 0x02, 0x05, 0x07, 0x09, 0x0F, 0x12, 0x20, KEEPALIVE, ERROR,
    ] {
        for bcnt in [0u16, 1, 100, 7610] {
            assert_eq!(
                dev.report(1, &init_packet(cid, cmd, bcnt, &[1])),
                error_events(cid, ERR_INVALID_CMD),
                "command {cmd:#x} BCNT {bcnt}"
            );
        }
    }
    assert_eq!(dev.next_deadline(), None);
    assert_ping_echo(&mut dev, 2, cid, 100);
}

#[test]
fn commands_follow_the_advertised_capabilities() {
    // CTAP 2.1 §11.2.9.1.3: WINK 0x01 and CBOR 0x04 advertise those commands; NMSG
    // 0x08 says MSG is not implemented.
    let mut dev = Ctaphid::new(FIRMWARE, 0x08);
    let cid = allocate(&mut dev, 0);
    for (cmd, bcnt) in [(WINK, 0u16), (CBOR, 1), (MSG, 4)] {
        assert_eq!(
            dev.report(1, &init_packet(cid, cmd, bcnt, &[1, 2, 3, 4])),
            error_events(cid, ERR_INVALID_CMD),
            "command {cmd:#x}"
        );
    }
    assert_ping_echo(&mut dev, 2, cid, 4);

    let mut dev = Ctaphid::new(FIRMWARE, 0x01 | 0x04);
    let cid = allocate(&mut dev, 0);
    let events = dev.report(1, &init_packet(cid, MSG, 4, &[0, 1, 0, 0]));
    assert_eq!(
        events,
        vec![Event::Request {
            cid,
            cmd: MSG,
            payload: vec![0, 1, 0, 0]
        }]
    );
}
