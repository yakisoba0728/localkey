//! Message fragmentation, reassembly and sequencing at the 64-byte report level
//! (CTAP 2.1 §11.2.4, §11.2.5.4).
//!
//! Boundaries: 57 bytes fill the initialization packet, 58 and 116 need one
//! continuation packet, 117 needs two.
//!
//! Requests stop at 1536 bytes, measured on a YubiKey 5C Nano 5.7.4
//! (`docs/MEASUREMENT.md`, probe `ping-max`): 1532 = 57 + 25 * 59 ends on SEQ 24, 1533
//! is the first length that needs SEQ 25, 1536 is the longest PING echoed, and 1537 and
//! longer are `ERR_INVALID_LEN` at the initialization packet. Before the measurement the
//! engine echoed requests up to 7609 bytes (`reference/BEHAVIOR_CATALOG.md` FIDO:
//! "CTAPHID final legal sequence 127 completes a maximum 7609-byte PING; 7550/7551/7609-byte
//! boundaries verified", a legacy-emulator item not checked against the key).
//!
//! The device's own responses still use the whole sequence range: 7550 = 57 + 127 * 59
//! ends on SEQ 126, 7551 is the first length that needs SEQ 127, and 7609 = 57 + 128 * 59
//! is the framing maximum (CTAP 2.1 §11.2.4).

mod common;

use common::*;
use lk_ctaphid::Event;

/// Request lengths and their packet counts, up to the measured 1536-byte maximum.
const REQUEST_BOUNDARIES: [(usize, usize); 11] = [
    // (message length, packets)
    (0, 1),
    (1, 1),
    (57, 1),
    (58, 2),
    (59, 2),
    (116, 2),
    (117, 3),
    (175, 3),
    (1532, 26),
    (1533, 27),
    (1536, 27),
];

/// Response lengths and their packet counts, up to the 7609-byte framing maximum.
const RESPONSE_BOUNDARIES: [(usize, usize); 13] = [
    // (message length, packets)
    (0, 1),
    (1, 1),
    (57, 1),
    (58, 2),
    (59, 2),
    (116, 2),
    (117, 3),
    (175, 3),
    (1536, 27),
    (1537, 27),
    (7550, 128),
    (7551, 129),
    (7609, 129),
];

#[test]
fn ping_echoes_every_boundary_length() {
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    for (len, packets) in REQUEST_BOUNDARIES {
        let payload = pattern(len, len as u8);
        let request = message(cid, PING, &payload);
        assert_eq!(request.len(), packets, "request packets for {len}");
        // Every packet but the last is consumed silently.
        let (last, head) = request.split_last().expect("one packet");
        assert_eq!(feed(&mut dev, 1, head), vec![], "length {len}");
        let reports = sends(&dev.report(1, last));
        assert_eq!(reports.len(), packets, "response packets for {len}");
        assert_eq!(reassemble(&reports), (cid, PING, payload), "length {len}");
    }
}

#[test]
fn maximum_ping_is_1536_bytes_and_ends_on_sequence_25() {
    // docs/MEASUREMENT.md, probe ping-max: the longest PING echoed is 1536 bytes; the
    // echo is one initialization packet and continuation packets SEQ 0..=25.
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    let payload = pattern(MAX_REQUEST, 9);
    let request = message(cid, PING, &payload);
    assert_eq!(request.len(), 27);
    assert_eq!(request[26][4], 25);
    let reports = sends(&feed(&mut dev, 1, &request));
    assert_eq!(reports.len(), 27);
    assert_eq!(reports[26][4], 25, "last response SEQ");
    // 1536 - 1532 = 4 bytes in the last packet, then zero padding.
    assert_eq!(&reports[26][5..9], &payload[1532..]);
    assert!(reports[26][9..].iter().all(|&b| b == 0));
    assert_eq!(reassemble(&reports).2, payload);
}

#[test]
fn bcnt_above_1536_is_invalid_len_at_once_and_the_late_fragments_are_ignored() {
    // docs/MEASUREMENT.md, probes ping-max and ping-7609: every PING longer than 1536
    // bytes that was tried (1537, 1539, 1546, 1561, 1591, 1709, 1945, 3833, 7609) is
    // answered ERR_INVALID_LEN (03) right after the initialization packet, while the
    // host is still writing the continuation packets; those are ignored and the next
    // request works. BCNT 7610 and 0xFFFF (probes ping-7610, ping-bcnt-ffff) as well.
    // This test replaces `bcnt_above_7609_is_invalid_len_at_once` (the framing limit 7609
    // was the engine's maximum before the measurement).
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    for len in [
        1537usize, 1539, 1546, 1561, 1591, 1709, 1945, 3833, 7609, 7610, 8000, 0xFFFF,
    ] {
        let request = message(cid, PING, &pattern(len, 0xAB));
        assert_eq!(
            dev.report(1, &request[0]),
            error_events(cid, ERR_INVALID_LEN),
            "BCNT {len}"
        );
        // No transaction was started: the continuation packets are orphans, no timer runs.
        assert_eq!(feed(&mut dev, 2, &request[1..]), vec![], "BCNT {len}");
        assert_eq!(dev.next_deadline(), None);
        assert_eq!(dev.outstanding(), None);
        assert_ping_echo(&mut dev, 3, cid, 57);
    }
    assert_ping_echo(&mut dev, 4, cid, MAX_REQUEST);
}

#[test]
fn maximum_response_ends_on_sequence_127() {
    // CTAP 2.1 §11.2.4: 7609 = 57 + 128 * 59 is the longest message SEQ 0..=127 can carry.
    // Requests stop at 1536 bytes (docs/MEASUREMENT.md, probe ping-max), so this framing
    // limit applies to the device's responses; this test sent a 7609-byte PING before.
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    start_cbor(&mut dev, 1, cid, &[0x04]);
    let payload = pattern(MAX_FRAMED, 9);
    let reports = dev.respond(cid, CBOR, &payload);
    assert_eq!(reports.len(), 129);
    assert_eq!(reports[128][4], 0x7F, "last response SEQ");
    // The final packet carries 59 bytes exactly: no padding.
    assert_eq!(&reports[128][5..], &payload[MAX_FRAMED - 59..]);
    assert_eq!(reassemble(&reports), (cid, CBOR, payload));
}

#[test]
fn response_of_7550_bytes_ends_on_sequence_126_with_a_full_packet() {
    // Response side of the 7550-byte boundary (requests stop at 1536 bytes:
    // docs/MEASUREMENT.md, probe ping-max; this test sent a 7550-byte PING before).
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    start_cbor(&mut dev, 1, cid, &[0x04]);
    let payload = pattern(7550, 3);
    let reports = dev.respond(cid, CBOR, &payload);
    assert_eq!(reports.len(), 128);
    assert_eq!(reports[127][4], 126);
    assert_eq!(&reports[127][5..], &payload[7550 - 59..]);
}

#[test]
fn response_of_7551_bytes_needs_sequence_127_for_one_byte() {
    // Response side of the 7551-byte boundary (requests stop at 1536 bytes:
    // docs/MEASUREMENT.md, probe ping-max; this test sent a 7551-byte PING before).
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    start_cbor(&mut dev, 1, cid, &[0x04]);
    let payload = pattern(7551, 4);
    let reports = dev.respond(cid, CBOR, &payload);
    assert_eq!(reports.len(), 129);
    assert_eq!(reports[128][4], 0x7F);
    assert_eq!(reports[128][5], payload[7550]);
    assert!(reports[128][6..].iter().all(|&b| b == 0));
}

#[test]
fn bytes_after_bcnt_are_padding_and_ignored() {
    // A 60-byte message: 57 + 3 bytes; the other 56 bytes of SEQ 0 are padding.
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    let payload = pattern(60, 7);
    let mut tail = payload[57..].to_vec();
    tail.extend_from_slice(&[0xEE; 56]);
    let events = feed(
        &mut dev,
        1,
        &[
            init_packet(cid, PING, 60, &payload[..57]),
            cont_packet(cid, 0, &tail),
        ],
    );
    assert_eq!(reassemble(&sends(&events)), (cid, PING, payload));
    // The same holds for single-packet messages.
    let mut data = vec![1, 2, 3];
    data.extend_from_slice(&[0xEE; 54]);
    let events = dev.report(2, &init_packet(cid, PING, 3, &data));
    assert_eq!(reassemble(&sends(&events)), (cid, PING, vec![1, 2, 3]));
}

#[test]
fn first_continuation_must_be_sequence_zero() {
    // CTAP 2.1 §11.2.5.4: packets arrive in ascending order without gaps.
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    assert_eq!(
        dev.report(1, &init_packet(cid, PING, 100, &[1; 57])),
        vec![]
    );
    assert_eq!(
        dev.report(1, &cont_packet(cid, 1, &[1; 43])),
        error_events(cid, ERR_INVALID_SEQ)
    );
    // The transaction is over: the correct packet is now an orphan.
    assert_eq!(dev.report(1, &cont_packet(cid, 0, &[1; 43])), vec![]);
    assert_eq!(dev.next_deadline(), None);
    assert_ping_echo(&mut dev, 2, cid, 100);
}

#[test]
fn repeated_or_skipped_sequence_is_invalid_seq() {
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    let request = message(cid, PING, &pattern(300, 1));
    for bad_seq in [0u8, 2, 0x7F] {
        assert_eq!(feed(&mut dev, 1, &request[..2]), vec![], "SEQ {bad_seq}");
        assert_eq!(
            dev.report(1, &cont_packet(cid, bad_seq, &[0; 59])),
            error_events(cid, ERR_INVALID_SEQ),
            "SEQ {bad_seq} after SEQ 0"
        );
    }
    assert_ping_echo(&mut dev, 2, cid, 300);
}

#[test]
fn same_channel_initialization_packet_mid_message_is_invalid_seq() {
    // Model policy (spec silent): a new non-INIT command while the channel's message
    // is still arriving ends that message with ERR_INVALID_SEQ.
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    let request = message(cid, CBOR, &pattern(150, 1));
    assert_eq!(feed(&mut dev, 1, &request[..2]), vec![]);
    assert_eq!(
        dev.report(1, &init_packet(cid, PING, 1, &[9])),
        error_events(cid, ERR_INVALID_SEQ)
    );
    assert_eq!(
        dev.report(1, &request[2]),
        vec![],
        "remaining packet is an orphan"
    );
    assert_eq!(dev.outstanding(), None);
    assert_ping_echo(&mut dev, 2, cid, 1);
}

#[test]
fn cbor_request_reassembly_at_boundaries() {
    // Up to the measured 1536-byte maximum (docs/MEASUREMENT.md, probe ping-max; the
    // list ended with 7609 before the measurement).
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    for len in [1usize, 57, 58, 116, 117, 1532, 1533, MAX_REQUEST] {
        let payload = pattern(len, 0x10);
        let events = feed(&mut dev, 1, &message(cid, CBOR, &payload));
        assert_eq!(
            events,
            vec![Event::Request {
                cid,
                cmd: CBOR,
                payload
            }],
            "length {len}"
        );
        assert_eq!(dev.outstanding(), Some((cid, CBOR)));
        assert_eq!(
            reassemble(&dev.respond(cid, CBOR, &[0x00])),
            (cid, CBOR, vec![0x00])
        );
    }
}

#[test]
fn respond_fragments_responses_at_boundaries() {
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    for (len, packets) in RESPONSE_BOUNDARIES {
        start_cbor(&mut dev, 1, cid, &[0x04]);
        let payload = pattern(len, 0x77);
        let reports = dev.respond(cid, CBOR, &payload);
        assert_eq!(reports.len(), packets, "length {len}");
        assert_eq!(reassemble(&reports), (cid, CBOR, payload), "length {len}");
        assert_eq!(dev.outstanding(), None);
    }
}

#[test]
fn respond_sets_bit_7_whether_or_not_the_caller_did() {
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    start_cbor(&mut dev, 1, cid, &[0x04]);
    let plain = dev.respond(cid, CBOR, &[0x00]);
    start_cbor(&mut dev, 1, cid, &[0x04]);
    let flagged = dev.respond(cid, 0x80 | CBOR, &[0x00]);
    assert_eq!(plain, flagged);
    assert_eq!(plain[0][4], 0x90);
}

#[test]
fn respond_can_send_an_error_and_oversized_responses_become_err_other() {
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    start_cbor(&mut dev, 1, cid, &[0x04]);
    assert_eq!(
        dev.respond(cid, ERROR, &[ERR_INVALID_CMD]),
        vec![error_report(cid, ERR_INVALID_CMD)]
    );
    // Model policy: a response that cannot be framed is replaced by ERR_OTHER.
    start_cbor(&mut dev, 2, cid, &[0x04]);
    assert_eq!(
        dev.respond(cid, CBOR, &vec![0; 7610]),
        vec![error_report(cid, ERR_OTHER)]
    );
    assert_eq!(dev.outstanding(), None);
}

#[test]
fn respond_without_an_outstanding_request_sends_nothing() {
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let b = allocate(&mut dev, 0);
    assert_eq!(dev.respond(a, CBOR, &[0x00]), Vec::<Report>::new());
    start_cbor(&mut dev, 1, a, &[0x04]);
    // Wrong channel: discarded, and the real request stays outstanding.
    assert_eq!(dev.respond(b, CBOR, &[0x00]), Vec::<Report>::new());
    assert_eq!(dev.outstanding(), Some((a, CBOR)));
    assert_eq!(dev.respond(a, CBOR, &[0x00]).len(), 1);
    assert_eq!(
        dev.respond(a, CBOR, &[0x00]),
        Vec::<Report>::new(),
        "only once"
    );
}

#[test]
fn keepalive_report_layout() {
    // CTAP 2.1 §11.2.9.1.7: CMD 0xBB, BCNT 1, status 1 (PROCESSING) or 2 (UPNEEDED).
    let dev = device();
    let mut expected: Report = [0; 64];
    expected[..8].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0xBB, 0x00, 0x01, 0x02]);
    assert_eq!(
        dev.keepalive(0x0102_0304, lk_ctaphid::keepalive::UPNEEDED),
        expected
    );
    expected[7] = 0x01;
    assert_eq!(
        dev.keepalive(0x0102_0304, lk_ctaphid::keepalive::PROCESSING),
        expected
    );
}
