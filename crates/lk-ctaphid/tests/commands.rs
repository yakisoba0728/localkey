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
fn empty_cbor_request_stalls_the_device_until_init_on_its_channel() {
    // Measured on a YubiKey 5C Nano 5.7.4 (docs/MEASUREMENT.md, probe empty-cbor, and
    // "The stuck-channel incident"): CTAPHID_CBOR with BCNT 0 is never answered (no
    // answer, no KEEPALIVE within 2 s); another channel's PING is ERR_CHANNEL_BUSY;
    // CANCEL on the channel is not answered and changes nothing (still busy 3 s after
    // the request); INIT on the channel is answered with the same CID and frees the
    // device. This test asserted ERR_INVALID_LEN before the measurement (CTAP 2.1
    // §11.2.9.1.2 asks for at least the command byte but names no error).
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let b = allocate(&mut dev, 0);
    assert_eq!(dev.report(1, &init_packet(a, CBOR, 0, &[])), vec![]);
    // Nothing reaches the application, and no timer will ever end the stall.
    assert_eq!(dev.outstanding(), None);
    assert_eq!(dev.next_deadline(), None);
    assert_eq!(dev.tick(2_000), vec![]);
    assert_eq!(dev.tick(u64::MAX / 2), vec![]);
    // Another channel is busy, and so is the stalled channel itself for anything but INIT.
    assert_eq!(
        dev.report(2_000, &init_packet(b, PING, 1, &[0x5A])),
        error_events(b, ERR_CHANNEL_BUSY)
    );
    assert_eq!(
        dev.report(2_000, &init_packet(BROADCAST, INIT, 8, &[1; 8])),
        error_events(BROADCAST, ERR_CHANNEL_BUSY)
    );
    assert_eq!(
        dev.report(2_000, &init_packet(a, PING, 1, &[0x5A])),
        error_events(a, ERR_CHANNEL_BUSY)
    );
    assert_eq!(
        dev.report(2_000, &init_packet(a, CBOR, 1, &[0x04])),
        error_events(a, ERR_CHANNEL_BUSY)
    );
    // CANCEL on the channel: never answered, no Cancel for the application, still busy.
    assert_eq!(dev.report(2_001, &init_packet(a, CANCEL, 0, &[])), vec![]);
    assert_eq!(
        dev.report(3_000, &init_packet(b, PING, 1, &[0x5A])),
        error_events(b, ERR_CHANNEL_BUSY)
    );
    // A malformed INIT is not a resynchronisation.
    assert_eq!(
        dev.report(3_000, &init_packet(a, INIT, 7, &[1; 7])),
        error_events(a, ERR_INVALID_LEN)
    );
    assert_eq!(
        dev.report(3_000, &init_packet(b, PING, 1, &[0x5A])),
        error_events(b, ERR_CHANNEL_BUSY)
    );
    // INIT on the stalled channel: an INIT answer with the same CID (no Abort, the
    // application never had the request), and the device is free again.
    let reports = sends(&dev.report(3_001, &init_packet(a, INIT, 8, &[7; 8])));
    let (cid, cmd, payload) = reassemble(&reports);
    assert_eq!((cid, cmd), (a, INIT));
    assert_eq!(&payload[..8], &[7; 8]);
    assert_eq!(&payload[8..12], &a.to_be_bytes(), "same CID");
    assert_ping_echo(&mut dev, 3_002, b, 1);
    assert_ping_echo(&mut dev, 3_002, a, 1);
}

#[test]
fn empty_cbor_stall_ignores_a_late_respond_and_ends_with_a_usb_reset() {
    // docs/MEASUREMENT.md, probe empty-cbor: only INIT on the channel was seen to end
    // the stall. A USB reset drops every transaction and channel (`Ctaphid::reset`), so
    // it ends the stall as well (model policy: not measured). A stray `respond` for the
    // channel frames nothing, because the application never had the request.
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    assert_eq!(dev.report(1, &init_packet(a, CBOR, 0, &[])), vec![]);
    assert_eq!(dev.respond(a, CBOR, &[0x00]), Vec::<Report>::new());
    assert_eq!(
        dev.report(2, &init_packet(a, PING, 0, &[])),
        error_events(a, ERR_CHANNEL_BUSY),
        "still stalled"
    );
    dev.reset();
    let fresh = allocate(&mut dev, 3);
    assert_ping_echo(&mut dev, 3, fresh, 1);
}

#[test]
fn every_request_above_1536_bytes_is_invalid_len() {
    // Measured on a YubiKey 5C Nano 5.7.4 (docs/MEASUREMENT.md, probe ping-max): PING
    // longer than 1536 bytes is ERR_INVALID_LEN at the initialization packet. GetInfo
    // `maxMsgSize` is 1536 on the same key, so CBOR, MSG and vendor requests get the same
    // limit (only PING was measured).
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    for cmd in [PING, CBOR, MSG, 0x40, 0x42, 0x7F] {
        for len in [1537usize, 2048, 7609] {
            let request = message(cid, cmd, &pattern(len, cmd));
            assert_eq!(
                dev.report(1, &request[0]),
                error_events(cid, ERR_INVALID_LEN),
                "command {cmd:#x} BCNT {len}"
            );
            assert_eq!(feed(&mut dev, 1, &request[1..]), vec![], "orphans");
            assert_eq!(dev.next_deadline(), None);
        }
        // 1536 bytes still go through.
        let payload = pattern(1536, cmd);
        let events = feed(&mut dev, 2, &message(cid, cmd, &payload));
        if cmd == PING {
            assert_eq!(reassemble(&sends(&events)), (cid, PING, payload));
        } else {
            assert_eq!(
                events,
                vec![Event::Request { cid, cmd, payload }],
                "command {cmd:#x}"
            );
            assert_eq!(dev.respond(cid, cmd, &[0x00]).len(), 1);
        }
    }
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
