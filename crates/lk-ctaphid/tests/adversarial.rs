//! Adversarial interleavings found missing during independent review: other channels
//! poking at an active transaction, resynchronisation at the last packet, lock expiry
//! during a request, repeated CANCEL and reset with everything active at once
//! (CTAP 2.1 §11.2.5, §11.2.9).

mod common;

use common::*;
use lk_ctaphid::Event;

#[test]
fn init_from_another_allocated_channel_while_one_assembles_is_busy() {
    // CTAP 2.1 §11.2.5.1: "If an application tries to access the device from a
    // different channel while the device is busy with a transaction, that request will
    // immediately fail with a busy-error message sent to the requesting channel."
    // `reference/BEHAVIOR_CATALOG.md` FIDO: INIT "on another or broadcast CID return[s]
    // CHANNEL_BUSY". The busy channel's message is not disturbed.
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let b = allocate(&mut dev, 0);
    let payload = pattern(300, 0x31);
    let request = message(a, PING, &payload);
    assert_eq!(request.len(), 6);
    assert_eq!(feed(&mut dev, 1, &request[..3]), vec![]);
    for bcnt in [8u16, 7, 0] {
        assert_eq!(
            dev.report(2, &init_packet(b, INIT, bcnt, &[0x5A; 8])),
            error_events(b, ERR_CHANNEL_BUSY),
            "BCNT {bcnt}"
        );
    }
    let reports = sends(&feed(&mut dev, 3, &request[3..]));
    assert_eq!(reassemble(&reports), (a, PING, payload));
    // B is usable again, and still the same channel.
    assert_ping_echo(&mut dev, 4, b, 2);
}

#[test]
fn rejected_broadcast_init_allocates_no_channel() {
    // A busy or locked-out broadcast INIT must not consume a channel identifier
    // (CTAP 2.1 §11.2.5.1; model policy: identifiers are allocated in order).
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let broadcast_init = init_packet(BROADCAST, INIT, 8, &[0xC3; 8]);
    // While a message is arriving.
    assert_eq!(dev.report(1, &init_packet(a, PING, 100, &[0; 57])), vec![]);
    assert_eq!(
        dev.report(1, &broadcast_init),
        error_events(BROADCAST, ERR_CHANNEL_BUSY)
    );
    assert_eq!(dev.report(1, &cont_packet(a, 0, &[0; 43])).len(), 2);
    // While a request is with the application.
    start_cbor(&mut dev, 2, a, &[0x04]);
    assert_eq!(
        dev.report(2, &broadcast_init),
        error_events(BROADCAST, ERR_CHANNEL_BUSY)
    );
    assert_eq!(dev.respond(a, CBOR, &[0x00]).len(), 1);
    // While another channel holds the lock.
    assert_eq!(dev.report(3, &init_packet(a, LOCK, 1, &[2])).len(), 1);
    assert_eq!(
        dev.report(3, &broadcast_init),
        error_events(BROADCAST, ERR_CHANNEL_BUSY)
    );
    // Once free, the next identifier follows the first one directly.
    assert_eq!(allocate(&mut dev, 3 + 2000), a + 1);
}

#[test]
fn init_resync_just_before_the_final_sequence_drops_the_whole_message() {
    // CTAP 2.1 §11.2.5.3: INIT on the active channel aborts the transaction and flushes
    // buffered data. Here 7609 bytes have arrived except the last packet (SEQ 127,
    // `reference/BEHAVIOR_CATALOG.md` "final legal sequence 127").
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    let request = message(cid, PING, &pattern(7609, 0x17));
    assert_eq!(request.len(), 129);
    assert_eq!(feed(&mut dev, 1, &request[..128]), vec![]);
    let reports = sends(&dev.report(2, &init_packet(cid, INIT, 8, &[0x77; 8])));
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0][4], 0x80 | INIT);
    // The final packet is now an orphan and starts nothing.
    assert_eq!(dev.report(3, &request[128]), vec![]);
    assert_eq!(dev.next_deadline(), None);
    assert_ping_echo(&mut dev, 4, cid, 7609);
}

#[test]
fn foreign_continuation_with_the_expected_sequence_never_completes_a_message() {
    // CTAP 2.1 §11.2.5.4 assembles a message from its own channel's packets only:
    // a continuation from another, unknown or broadcast CID carrying exactly the
    // final bytes must not complete channel A's message.
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let b = allocate(&mut dev, 0);
    let payload = pattern(58, 0x44);
    let request = message(a, CBOR, &payload);
    assert_eq!(request.len(), 2);
    assert_eq!(dev.report(1, &request[0]), vec![]);
    for other in [b, 0, BROADCAST, a + 100] {
        assert_eq!(
            dev.report(1, &cont_packet(other, 0, &payload[57..])),
            vec![],
            "CID {other:#x}"
        );
    }
    assert_eq!(dev.outstanding(), None);
    assert_eq!(
        dev.report(1, &request[1]),
        vec![Event::Request {
            cid: a,
            cmd: CBOR,
            payload
        }]
    );
}

#[test]
fn any_new_command_on_the_assembling_channel_ends_the_message_except_cancel() {
    // Model policy (documented in framer.rs; CTAP 2.1 §11.2.5.3 and §11.2.5.4 are
    // silent): an initialization packet other than INIT or CANCEL on the channel whose
    // message is still arriving is ERR_INVALID_SEQ and drops the message. CANCEL is
    // never answered (§11.2.9.1.5) and leaves the message intact.
    for (cmd, bcnt) in [
        (PING, 1u16),
        (PING, 200),
        (CBOR, 1),
        (MSG, 1),
        (WINK, 0),
        (LOCK, 1),
        (0x40, 0),
        (0x02, 0), // unassigned command
    ] {
        let mut dev = device();
        let cid = allocate(&mut dev, 0);
        let request = message(cid, PING, &pattern(120, 1));
        assert_eq!(dev.report(1, &request[0]), vec![]);
        assert_eq!(dev.report(1, &init_packet(cid, CANCEL, 0, &[])), vec![]);
        assert_eq!(
            dev.report(1, &init_packet(cid, cmd, bcnt, &[1])),
            error_events(cid, ERR_INVALID_SEQ),
            "command {cmd:#x}"
        );
        assert_eq!(feed(&mut dev, 1, &request[1..]), vec![], "orphans");
        assert_eq!(dev.next_deadline(), None);
    }
}

#[test]
fn sequence_errors_at_the_far_end_of_a_maximum_message() {
    // CTAP 2.1 §11.2.5.4: packets arrive "in correct and ascending order and ... no
    // expected packets are missing". Skipping, repeating or wrapping a SEQ near 127 is
    // ERR_INVALID_SEQ.
    let request_payload = pattern(7609, 0x23);
    for (sent, bad_seq) in [(127usize, 0x7Eu8), (127, 0x00), (126, 0x7F), (1, 0x7F)] {
        let mut dev = device();
        let cid = allocate(&mut dev, 0);
        let request = message(cid, PING, &request_payload);
        // The initialization packet plus `sent` continuation packets (SEQ 0..sent).
        assert_eq!(feed(&mut dev, 1, &request[..=sent]), vec![]);
        assert_eq!(
            dev.report(1, &cont_packet(cid, bad_seq, &[0; 59])),
            error_events(cid, ERR_INVALID_SEQ),
            "SEQ {bad_seq:#x} after {sent} continuation packets"
        );
        assert_eq!(dev.next_deadline(), None);
    }
}

#[test]
fn lock_lapsing_during_the_holders_request_keeps_others_busy_until_the_answer() {
    // CTAP 2.1 §11.2.9.2.2 (lock time up to 10 s) and §11.2.5.1 (busy until the
    // response). Other channels see CHANNEL_BUSY while the lock holds, still after it
    // lapses via tick() while the holder's request is outstanding, and are served once
    // that request is answered.
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let b = allocate(&mut dev, 0);
    assert_eq!(dev.report(0, &init_packet(a, LOCK, 1, &[1])).len(), 1);
    start_cbor(&mut dev, 10, a, &[0x01]);
    assert_eq!(
        dev.report(999, &init_packet(b, PING, 0, &[])),
        error_events(b, ERR_CHANNEL_BUSY)
    );
    assert_eq!(dev.next_deadline(), Some(1000));
    assert_eq!(dev.tick(1000), vec![], "lock expiry sends nothing");
    assert_eq!(dev.next_deadline(), None);
    assert_eq!(
        dev.report(1001, &init_packet(b, PING, 0, &[])),
        error_events(b, ERR_CHANNEL_BUSY)
    );
    assert_eq!(dev.respond(a, CBOR, &[0x00]).len(), 1);
    assert_ping_echo(&mut dev, 1002, b, 0);
}

#[test]
fn tick_before_the_deadline_changes_nothing() {
    // `Ctaphid::tick` only acts on deadlines that are due (CTAP 2.1 §11.2.5.2 timeout,
    // §11.2.9.2.2 lock time).
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let b = allocate(&mut dev, 0);
    assert_eq!(dev.report(0, &init_packet(a, LOCK, 1, &[10])).len(), 1);
    assert_eq!(dev.report(0, &init_packet(a, PING, 58, &[0; 57])), vec![]);
    for now in [0, 1, TIMEOUT_MS - 1] {
        assert_eq!(dev.tick(now), vec![], "tick at {now}");
        assert_eq!(dev.next_deadline(), Some(TIMEOUT_MS));
    }
    assert_eq!(dev.tick(TIMEOUT_MS), error_events(a, ERR_MSG_TIMEOUT));
    for now in [TIMEOUT_MS, 9_999] {
        assert_eq!(dev.tick(now), vec![]);
        assert_eq!(dev.next_deadline(), Some(10_000));
    }
    assert_eq!(
        dev.report(9_999, &init_packet(b, PING, 0, &[])),
        error_events(b, ERR_CHANNEL_BUSY)
    );
    assert_eq!(dev.tick(10_000), vec![]);
    assert_eq!(dev.next_deadline(), None);
}

#[test]
fn repeated_cancel_reports_cancel_each_time_and_never_answers() {
    // CTAP 2.1 §11.2.9.1.5: "Whether a request was cancelled or not, the authenticator
    // MUST NOT reply to the CTAPHID_CANCEL message itself."
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    start_cbor(&mut dev, 1, cid, &[0x01, 0xA0]);
    for now in 2..5 {
        assert_eq!(
            dev.report(now, &init_packet(cid, CANCEL, 0, &[])),
            vec![Event::Cancel { cid }]
        );
    }
    assert_eq!(dev.outstanding(), Some((cid, CBOR)));
    // After the answer, CANCEL is ignored again.
    assert_eq!(dev.respond(cid, CBOR, &[0x2D]).len(), 1);
    assert_eq!(dev.report(6, &init_packet(cid, CANCEL, 0, &[])), vec![]);
}

#[test]
fn cancel_after_init_resync_is_ignored() {
    // CTAP 2.1 §11.2.5.3 and §11.2.9.1.5: once INIT has aborted the CBOR request, no
    // CBOR request is being processed, so CANCEL is ignored.
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    start_cbor(&mut dev, 1, cid, &[0x01]);
    let events = dev.report(2, &init_packet(cid, INIT, 8, &[1; 8]));
    assert_eq!(events.first(), Some(&Event::Abort { cid }));
    assert_eq!(dev.report(3, &init_packet(cid, CANCEL, 0, &[])), vec![]);
}

#[test]
fn reset_with_lock_assembly_and_old_channels_at_once() {
    // `reference/BEHAVIOR_CATALOG.md` appendix A: on USB bus reset "connection
    // generations discard old assembly, pending responses, and late worker replies".
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    assert_eq!(dev.report(0, &init_packet(a, LOCK, 1, &[10])).len(), 1);
    let request = message(a, PING, &pattern(200, 2));
    assert_eq!(dev.report(1, &request[0]), vec![]);
    dev.reset();
    assert_eq!(dev.next_deadline(), None);
    assert_eq!(dev.tick(20_000), vec![]);
    assert_eq!(feed(&mut dev, 2, &request[1..]), vec![]);
    // Broadcast INIT is no longer locked out, and the old channel is gone.
    let fresh = allocate(&mut dev, 3);
    assert_ne!(fresh, a);
    assert_eq!(
        dev.report(3, &init_packet(a, CANCEL, 0, &[])),
        vec![],
        "CANCEL is never answered, even on a stale channel"
    );
    assert_eq!(
        dev.report(3, &init_packet(a, PING, 0, &[])),
        error_events(a, ERR_INVALID_CHANNEL)
    );
    assert_ping_echo(&mut dev, 4, fresh, 200);
}

#[test]
fn responses_spanning_many_packets_interleave_with_nothing() {
    // CTAP 2.1 §11.2.4: a response is one initialization packet followed by
    // continuation packets SEQ 0, 1, ... on the same CID. `respond` returns the whole
    // message at once; the device is idle again afterwards.
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let b = allocate(&mut dev, 0);
    start_cbor(&mut dev, 1, a, &[0x01]);
    let payload = pattern(1200, 0x66);
    let reports = dev.respond(a, CBOR, &payload);
    assert_eq!(reports.len(), 1 + (1200usize - 57).div_ceil(59));
    assert!(reports.iter().all(|r| r[..4] == a.to_be_bytes()));
    assert_eq!(reassemble(&reports), (a, CBOR, payload));
    assert_ping_echo(&mut dev, 2, b, 1);
}
