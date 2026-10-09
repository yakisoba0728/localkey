//! Transaction timeout for incomplete messages (CTAP 2.1 §11.2.5.2).
//!
//! Model policy (`lk_ctaphid::TRANSACTION_TIMEOUT_MS`): the spec and the behaviour
//! catalog give no value, so a message is abandoned 3000 ms after its latest packet.

mod common;

use common::*;
use lk_ctaphid::{Event, TRANSACTION_TIMEOUT_MS};

#[test]
fn model_timeout_is_3000_ms() {
    assert_eq!(TRANSACTION_TIMEOUT_MS, TIMEOUT_MS);
}

#[test]
fn idle_and_processing_states_have_no_deadline() {
    let mut dev = device();
    assert_eq!(dev.next_deadline(), None);
    let cid = allocate(&mut dev, 0);
    assert_eq!(dev.next_deadline(), None);
    // A request with the application is not timed by the framer (the device sends
    // KEEPALIVE and applies its own touch timeout).
    start_cbor(&mut dev, 0, cid, &[0x01]);
    assert_eq!(dev.next_deadline(), None);
    assert_eq!(dev.tick(1_000_000), vec![]);
    assert_eq!(dev.outstanding(), Some((cid, CBOR)));
}

#[test]
fn incomplete_message_times_out_with_msg_timeout() {
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let b = allocate(&mut dev, 0);
    let request = message(a, CBOR, &pattern(120, 1));
    assert_eq!(dev.report(1000, &request[0]), vec![]);
    assert_eq!(dev.next_deadline(), Some(1000 + TIMEOUT_MS));
    assert_eq!(dev.tick(1000 + TIMEOUT_MS - 1), vec![]);
    assert_eq!(
        dev.tick(1000 + TIMEOUT_MS),
        error_events(a, ERR_MSG_TIMEOUT)
    );
    assert_eq!(dev.next_deadline(), None);
    assert_eq!(dev.tick(1000 + 2 * TIMEOUT_MS), vec![], "reported once");
    // The rest of the message is now orphaned, and the device is free.
    assert_eq!(feed(&mut dev, 4001, &request[1..]), vec![]);
    assert_eq!(dev.outstanding(), None);
    assert_ping_echo(&mut dev, 4001, b, 1);
    assert_ping_echo(&mut dev, 4001, a, 1);
}

#[test]
fn each_packet_restarts_the_timeout() {
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    let payload = pattern(57 + 3 * 59, 2);
    let request = message(cid, PING, &payload);
    assert_eq!(request.len(), 4);
    let mut now = 0;
    for packet in &request[..3] {
        assert_eq!(dev.report(now, packet), vec![]);
        assert_eq!(dev.next_deadline(), Some(now + TIMEOUT_MS));
        now += TIMEOUT_MS - 1;
        assert_eq!(dev.tick(now), vec![]);
    }
    let reports = sends(&dev.report(now, &request[3]));
    assert_eq!(reassemble(&reports), (cid, PING, payload));
}

#[test]
fn late_packet_sees_the_timeout_first_even_without_a_tick() {
    // The host program may not have ticked yet; report() applies due timeouts before
    // handling the packet, so the outcome does not depend on tick scheduling.
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let b = allocate(&mut dev, 0);
    let request = message(a, PING, &pattern(100, 3));
    assert_eq!(dev.report(0, &request[0]), vec![]);
    assert_eq!(
        dev.report(TIMEOUT_MS, &request[1]),
        error_events(a, ERR_MSG_TIMEOUT)
    );
    // A new message on channel A stalls too; the next packet, from channel B, first
    // sees A's timeout and is then served.
    assert_eq!(dev.report(TIMEOUT_MS, &request[0]), vec![]);
    let events = dev.report(2 * TIMEOUT_MS, &init_packet(b, PING, 1, &[7]));
    let mut expected = error_events(a, ERR_MSG_TIMEOUT);
    expected.push(Event::Send(init_packet(b, PING, 1, &[7])));
    assert_eq!(events, expected);
}

#[test]
fn other_channels_are_busy_until_the_timeout() {
    // CTAP 2.1 §11.2.5.2: a stalled sender cannot lock others out beyond the timeout.
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let b = allocate(&mut dev, 0);
    assert_eq!(dev.report(0, &init_packet(a, PING, 1000, &[0; 57])), vec![]);
    assert_eq!(
        dev.report(TIMEOUT_MS - 1, &init_packet(b, PING, 0, &[])),
        error_events(b, ERR_CHANNEL_BUSY)
    );
    assert_eq!(dev.tick(TIMEOUT_MS), error_events(a, ERR_MSG_TIMEOUT));
    assert_ping_echo(&mut dev, TIMEOUT_MS, b, 0);
}
