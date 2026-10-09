//! `CTAPHID_INIT`: channel allocation, resynchronisation and channel validity
//! (CTAP 2.1 §11.2.4, §11.2.5.3, §11.2.9.1.3).

mod common;

use common::*;
use lk_ctaphid::{Ctaphid, Event};

const NONCE: [u8; 8] = [0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE];

/// The complete INIT response report for `nonce` and `channel`, sent on `on`
/// (CTAP 2.1 §11.2.9.1.3: nonce, CID, protocol 2, major, minor, build, capabilities).
fn init_response(on: u32, nonce: &[u8; 8], channel: u32) -> Report {
    let mut data = nonce.to_vec();
    data.extend_from_slice(&channel.to_be_bytes());
    data.extend_from_slice(&[2, 5, 7, 4, CAPS]);
    init_packet(on, INIT, 17, &data)
}

#[test]
fn broadcast_init_allocates_a_channel_with_exact_response_bytes() {
    let mut dev = device();
    let events = dev.report(0, &init_packet(BROADCAST, INIT, 8, &NONCE));
    let mut expected: Report = [0; 64]; // bytes 24.. stay zero padding
    expected[..24].copy_from_slice(&[
        0xFF, 0xFF, 0xFF, 0xFF, 0x86, 0x00, 0x11, // CID, INIT|0x80, BCNT 17
        0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, // nonce
        0x00, 0x00, 0x00, 0x01, // allocated CID (model policy: sequential from 1)
        0x02, 0x05, 0x07, 0x04, 0x05, // protocol 2, version 5.7.4, capabilities
    ]);
    assert_eq!(events, vec![Event::Send(expected)]);
    assert_ping_echo(&mut dev, 1, 1, 5);
}

#[test]
fn init_reports_the_capabilities_it_was_built_with() {
    // CTAP 2.1 §11.2.9.1.3 capability flags: WINK 0x01, CBOR 0x04, NMSG 0x08.
    let mut dev = Ctaphid::new(FIRMWARE, 0x0C);
    let reports = sends(&dev.report(0, &init_packet(BROADCAST, INIT, 8, &NONCE)));
    let (_, _, payload) = reassemble(&reports);
    assert_eq!(payload[16], 0x0C);
}

#[test]
fn each_broadcast_init_allocates_a_distinct_usable_channel() {
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let b = allocate(&mut dev, 0);
    let c = allocate(&mut dev, 0);
    assert!(a != b && b != c && a != c);
    for cid in [a, b, c] {
        assert!(cid != 0 && cid != BROADCAST);
        assert_ping_echo(&mut dev, 1, cid, 3);
    }
}

#[test]
fn init_nonce_ignores_padding_bytes_after_bcnt() {
    // BCNT is 8, so bytes 8.. of the packet data are padding (CTAP 2.1 §11.2.4).
    let mut dev = device();
    let mut data = NONCE.to_vec();
    data.extend_from_slice(&[0xEE; 49]);
    let events = dev.report(0, &init_packet(BROADCAST, INIT, 8, &data));
    assert_eq!(
        events,
        vec![Event::Send(init_response(BROADCAST, &NONCE, 1))]
    );
}

#[test]
fn init_with_wrong_length_is_invalid_len() {
    // CTAP 2.1 §11.2.9.1.3: the request carries exactly an 8-byte nonce.
    let mut dev = device();
    for bcnt in [0u16, 1, 7, 9, 17, 57] {
        let events = dev.report(0, &init_packet(BROADCAST, INIT, bcnt, &NONCE));
        assert_eq!(
            events,
            error_events(BROADCAST, ERR_INVALID_LEN),
            "BCNT {bcnt}"
        );
    }
    // A multi-packet BCNT is rejected at once; its continuation is then an orphan.
    assert_eq!(
        dev.report(0, &init_packet(BROADCAST, INIT, 58, &NONCE)),
        error_events(BROADCAST, ERR_INVALID_LEN)
    );
    assert_eq!(dev.report(0, &cont_packet(BROADCAST, 0, &[1])), vec![]);
    // Nothing was allocated by the rejected requests.
    assert_eq!(allocate(&mut dev, 1), 1);
}

#[test]
fn init_with_wrong_length_on_an_allocated_channel_keeps_it() {
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    assert_eq!(
        dev.report(0, &init_packet(cid, INIT, 4, &NONCE)),
        error_events(cid, ERR_INVALID_LEN)
    );
    assert_ping_echo(&mut dev, 1, cid, 1);
}

#[test]
fn init_on_an_allocated_channel_resynchronises_with_the_same_cid() {
    // CTAP 2.1 §11.2.9.1.3: the response goes out on the channel the INIT arrived on.
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    let events = dev.report(1, &init_packet(cid, INIT, 8, &NONCE));
    assert_eq!(events, vec![Event::Send(init_response(cid, &NONCE, cid))]);
    assert_ping_echo(&mut dev, 2, cid, 1);
}

#[test]
fn init_resync_drops_a_partial_message_on_the_same_channel() {
    // CTAP 2.1 §11.2.5.3: INIT on the active channel flushes buffered data.
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    let ping = message(cid, PING, &pattern(200, 1));
    assert_eq!(feed(&mut dev, 1, &ping[..2]), vec![]);
    let events = dev.report(2, &init_packet(cid, INIT, 8, &NONCE));
    assert_eq!(events, vec![Event::Send(init_response(cid, &NONCE, cid))]);
    // The rest of the old message is now a stream of orphan continuation packets.
    assert_eq!(feed(&mut dev, 3, &ping[2..]), vec![]);
    assert_eq!(dev.next_deadline(), None);
    assert_ping_echo(&mut dev, 4, cid, 60);
}

#[test]
fn init_resync_aborts_an_outstanding_request_and_discards_its_late_reply() {
    // CTAP 2.1 §11.2.5.3 and `reference/BEHAVIOR_CATALOG.md` FIDO: "Allocated CTAPHID
    // INIT now discards late replies from an aborted same-CID operation."
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    start_cbor(&mut dev, 1, cid, &[0x04]);
    let events = dev.report(2, &init_packet(cid, INIT, 8, &NONCE));
    assert_eq!(
        events,
        vec![
            Event::Abort { cid },
            Event::Send(init_response(cid, &NONCE, cid))
        ]
    );
    assert_eq!(dev.outstanding(), None);
    assert_eq!(dev.respond(cid, CBOR, &[0x00, 0xA0]), Vec::<Report>::new());
    // A new request on the same channel is served normally afterwards.
    start_cbor(&mut dev, 3, cid, &[0x04]);
    let reports = dev.respond(cid, CBOR, &[0x00]);
    assert_eq!(reassemble(&reports), (cid, CBOR, vec![0x00]));
}

#[test]
fn init_on_reserved_or_unknown_channels_is_invalid_channel() {
    // Channel 0 is reserved (CTAP 2.1 §11.2.4); unknown CIDs are rejected
    // (`reference/BEHAVIOR_CATALOG.md` FIDO: "an unknown-CID initial fragment returns
    // INVALID_CHANNEL immediately").
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    for bad in [0u32, cid + 1, 0x1234_5678, 0xFFFF_FFFE] {
        assert_eq!(
            dev.report(1, &init_packet(bad, INIT, 8, &NONCE)),
            error_events(bad, ERR_INVALID_CHANNEL),
            "CID {bad:#x}"
        );
    }
    // The rejected requests allocated nothing: the next channel follows the first.
    assert_eq!(allocate(&mut dev, 2), cid + 1);
}

#[test]
fn broadcast_channel_accepts_only_init() {
    // CTAP 2.1 §11.2.4: the broadcast CID is for CTAPHID_INIT.
    let mut dev = device();
    for (cmd, bcnt) in [
        (PING, 1u16),
        (MSG, 4),
        (CBOR, 1),
        (WINK, 0),
        (LOCK, 1),
        (0x40, 0),
    ] {
        assert_eq!(
            dev.report(0, &init_packet(BROADCAST, cmd, bcnt, &[0x01, 0, 0, 0])),
            error_events(BROADCAST, ERR_INVALID_CHANNEL),
            "command {cmd:#x}"
        );
    }
}

#[test]
fn init_with_wrong_length_keeps_the_channel_transaction() {
    // A malformed INIT is not a resynchronisation: the partial message or outstanding
    // request survives (model policy, length checked before CTAP 2.1 §11.2.5.3 applies).
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    let payload = pattern(100, 6);
    let ping = message(cid, PING, &payload);
    assert_eq!(dev.report(1, &ping[0]), vec![]);
    assert_eq!(
        dev.report(1, &init_packet(cid, INIT, 7, &NONCE)),
        error_events(cid, ERR_INVALID_LEN)
    );
    let reports = sends(&dev.report(1, &ping[1]));
    assert_eq!(reassemble(&reports), (cid, PING, payload));

    start_cbor(&mut dev, 2, cid, &[0x04]);
    assert_eq!(
        dev.report(3, &init_packet(cid, INIT, 9, &NONCE)),
        error_events(cid, ERR_INVALID_LEN)
    );
    assert_eq!(dev.outstanding(), Some((cid, CBOR)));
    assert_eq!(dev.respond(cid, CBOR, &[0x00]).len(), 1);
}
