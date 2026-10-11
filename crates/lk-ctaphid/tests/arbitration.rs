//! Channel arbitration: unknown channels, orphan continuation packets, one
//! transaction at a time, and busy answers (CTAP 2.1 §11.2.5.1, §11.2.5.4).

mod common;

use common::*;
use lk_ctaphid::Event;

#[test]
fn unknown_channel_initial_fragment_is_invalid_channel_while_a_valid_channel_pings() {
    // `reference/BEHAVIOR_CATALOG.md` FIDO: "an unknown-CID initial fragment returns
    // INVALID_CHANNEL immediately while a valid CID can PING."
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    for bad in [0u32, cid + 1, 0xDEAD_BEEF] {
        for (cmd, bcnt) in [
            (PING, 1u16),
            (PING, 200),
            (CBOR, 1),
            (MSG, 7),
            (WINK, 0),
            (LOCK, 1),
            (0x41, 0),
        ] {
            assert_eq!(
                dev.report(1, &init_packet(bad, cmd, bcnt, &[1])),
                error_events(bad, ERR_INVALID_CHANNEL),
                "CID {bad:#x} command {cmd:#x}"
            );
        }
    }
    // A rejected multi-packet start does not occupy the device.
    assert_eq!(dev.next_deadline(), None);
    assert_ping_echo(&mut dev, 2, cid, 10);
}

#[test]
fn orphan_continuation_packets_are_ignored_without_occupying_a_channel() {
    // CTAP 2.1 §11.2.5.4 and `reference/BEHAVIOR_CATALOG.md` FIDO: "An orphan CTAPHID
    // continuation frame is ignored without occupying a channel".
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let b = allocate(&mut dev, 0);
    for cid in [a, b, 0, BROADCAST, 0x0BAD_0BAD] {
        for seq in [0u8, 1, 0x7F] {
            assert_eq!(dev.report(1, &cont_packet(cid, seq, &[0xFF; 59])), vec![]);
        }
    }
    assert_eq!(dev.next_deadline(), None);
    assert_ping_echo(&mut dev, 2, a, 5);
    assert_ping_echo(&mut dev, 2, b, 5);
}

#[test]
fn outstanding_cbor_request_makes_every_other_channel_busy() {
    // `reference/BEHAVIOR_CATALOG.md` FIDO: "A concurrent CTAPHID CBOR operation
    // reserves the device for its CID: PING, WINK and INIT on another or broadcast CID
    // return CHANNEL_BUSY until the worker completes."
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let b = allocate(&mut dev, 0);
    start_cbor(&mut dev, 1, a, &[0x01, 0xA0]);
    let nonce = [9u8; 8];
    for (cid, cmd, bcnt, data) in [
        (b, PING, 1u16, &[1u8][..]),
        (b, PING, 200, &[1u8][..]),
        (b, WINK, 0, &[][..]),
        (b, CBOR, 1, &[4u8][..]),
        (b, MSG, 4, &[0u8, 1, 0, 0][..]),
        (b, LOCK, 1, &[5u8][..]),
        (b, INIT, 8, &nonce[..]),
        (BROADCAST, INIT, 8, &nonce[..]),
    ] {
        assert_eq!(
            dev.report(2, &init_packet(cid, cmd, bcnt, data)),
            error_events(cid, ERR_CHANNEL_BUSY),
            "CID {cid:#x} command {cmd:#x}"
        );
    }
    // CANCEL from another channel is ignored rather than answered (CTAP 2.1 §11.2.9.1.5).
    assert_eq!(dev.report(2, &init_packet(b, CANCEL, 0, &[])), vec![]);
    assert_eq!(dev.outstanding(), Some((a, CBOR)));
    // Completion frees the device for everyone.
    assert_eq!(
        reassemble(&dev.respond(a, CBOR, &[0x00])),
        (a, CBOR, vec![0x00])
    );
    assert_ping_echo(&mut dev, 3, b, 1);
    let c = allocate(&mut dev, 3);
    assert_ping_echo(&mut dev, 3, c, 1);
}

#[test]
fn partial_message_makes_other_channels_busy_and_ignores_their_continuations() {
    // CTAP 2.1 §11.2.5.1: the device is busy from the first packet of a request.
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let b = allocate(&mut dev, 0);
    let payload = pattern(200, 5);
    let request = message(a, PING, &payload);
    assert_eq!(request.len(), 4);
    assert_eq!(feed(&mut dev, 1, &request[..2]), vec![]);
    assert_eq!(
        dev.report(1, &init_packet(b, PING, 1, &[7])),
        error_events(b, ERR_CHANNEL_BUSY)
    );
    assert_eq!(
        dev.report(1, &init_packet(BROADCAST, INIT, 8, &[7; 8])),
        error_events(BROADCAST, ERR_CHANNEL_BUSY)
    );
    // Continuation packets on other channels, even with the expected SEQ, are orphans
    // and do not disturb channel A's message.
    assert_eq!(dev.report(1, &cont_packet(b, 1, &[0xEE; 59])), vec![]);
    assert_eq!(dev.report(1, &cont_packet(0, 1, &[0xEE; 59])), vec![]);
    let reports = sends(&feed(&mut dev, 1, &request[2..]));
    assert_eq!(reassemble(&reports), (a, PING, payload));
    assert_ping_echo(&mut dev, 2, b, 1);
}

#[test]
fn processing_channel_rejects_interleaved_ping_and_wink_but_keeps_working() {
    // `reference/BEHAVIOR_CATALOG.md` FIDO: "A processing CTAPHID CID rejects an
    // interleaved PING or WINK with CHANNEL_BUSY, while INIT resynchronization, CANCEL,
    // original completion and idle PING remain functional."
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    start_cbor(&mut dev, 1, cid, &[0x01]);
    for (cmd, bcnt) in [
        (PING, 1u16),
        (PING, 100),
        (WINK, 0),
        (CBOR, 1),
        (MSG, 4),
        (LOCK, 1),
        (0x42, 0),
    ] {
        assert_eq!(
            dev.report(2, &init_packet(cid, cmd, bcnt, &[1])),
            error_events(cid, ERR_CHANNEL_BUSY),
            "command {cmd:#x}"
        );
    }
    // CANCEL still reaches the application.
    assert_eq!(
        dev.report(3, &init_packet(cid, CANCEL, 0, &[])),
        vec![Event::Cancel { cid }]
    );
    // Original completion still works, then the channel is idle again.
    assert_eq!(
        reassemble(&dev.respond(cid, CBOR, &[0x2D])),
        (cid, CBOR, vec![0x2D])
    );
    assert_ping_echo(&mut dev, 4, cid, 1);
    // INIT resynchronisation also still works on a processing channel.
    start_cbor(&mut dev, 5, cid, &[0x01]);
    let events = dev.report(6, &init_packet(cid, INIT, 8, &[3; 8]));
    assert_eq!(events.first(), Some(&Event::Abort { cid }));
    assert_eq!(events.len(), 2);
    assert_ping_echo(&mut dev, 7, cid, 1);
}

#[test]
fn ping_on_one_channel_then_another_is_served_in_turn() {
    // Transactions are atomic but channels take turns once each completes
    // (CTAP 2.1 §11.2.5.1).
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let b = allocate(&mut dev, 0);
    for round in 0..3u64 {
        assert_ping_echo(&mut dev, round, a, 117);
        assert_ping_echo(&mut dev, round, b, 58);
    }
}

#[test]
fn delayed_host_reads_four_maximum_pings_come_back_complete_and_in_order() {
    // `reference/BEHAVIOR_CATALOG.md` appendix A: "echoes four 7609-byte PINGs after
    // delayed host reads". The longest PING is 1536 bytes on the measured key
    // (docs/MEASUREMENT.md, probe ping-max), so the four maximum PINGs are 1536 bytes
    // (27 reports each); they were 7609 bytes (129 reports) before the measurement. At
    // engine level the host reads nothing until all four requests are sent; each
    // request's reports must still be complete, in order, and not mixed with another
    // response. Bounding the report queue (256 reports in the legacy bridge) is the
    // program layer's job.
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let b = allocate(&mut dev, 0);
    let payloads: Vec<(u32, Vec<u8>)> = [(a, 1u8), (b, 2), (a, 3), (b, 4)]
        .into_iter()
        .map(|(cid, salt)| (cid, pattern(MAX_REQUEST, salt)))
        .collect();
    let mut unread = Vec::new();
    for (cid, payload) in &payloads {
        unread.extend(feed(&mut dev, 1, &message(*cid, PING, payload)));
    }
    let reports = sends(&unread);
    assert_eq!(reports.len(), 4 * 27);
    for (chunk, (cid, payload)) in reports.chunks(27).zip(&payloads) {
        assert_eq!(reassemble(chunk), (*cid, PING, payload.clone()));
    }
}
