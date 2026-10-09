//! `CTAPHID_LOCK` (CTAP 2.1 §11.2.9.2.2): 0..=10 seconds, others answered
//! `ERR_LOCK_REQUIRED` while the lock holds.

mod common;

use common::*;
use lk_ctaphid::Event;

fn lock(cid: u32, seconds: u8) -> Report {
    init_packet(cid, LOCK, 1, &[seconds])
}

/// The LOCK response: CMD 0x84, BCNT 0 (CTAP 2.1 §11.2.9.2.2).
fn lock_ok(cid: u32) -> Vec<Event> {
    vec![Event::Send(init_packet(cid, LOCK, 0, &[]))]
}

#[test]
fn lock_keeps_other_channels_out_until_it_lapses() {
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let b = allocate(&mut dev, 0);
    assert_eq!(dev.report(1000, &lock(a, 5)), lock_ok(a));
    assert_eq!(dev.next_deadline(), Some(6000));
    for (cid, cmd, bcnt) in [
        (b, PING, 1u16),
        (b, CBOR, 1),
        (b, WINK, 0),
        (b, INIT, 8),
        (BROADCAST, INIT, 8),
    ] {
        assert_eq!(
            dev.report(5999, &init_packet(cid, cmd, bcnt, &[1; 8])),
            error_events(cid, ERR_LOCK_REQUIRED),
            "CID {cid:#x} command {cmd:#x}"
        );
    }
    // The holder keeps full use of the device.
    assert_ping_echo(&mut dev, 5999, a, 200);
    start_cbor(&mut dev, 5999, a, &[0x04]);
    dev.respond(a, CBOR, &[0x00]);
    // At the deadline the lock lapses, whether through tick() or the next report.
    assert_eq!(dev.tick(6000), vec![]);
    assert_eq!(dev.next_deadline(), None);
    assert_ping_echo(&mut dev, 6000, b, 1);
}

#[test]
fn lapsed_lock_is_released_by_the_next_report_without_a_tick() {
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let b = allocate(&mut dev, 0);
    assert_eq!(dev.report(0, &lock(a, 1)), lock_ok(a));
    assert_ping_echo(&mut dev, 1000, b, 1);
}

#[test]
fn ten_seconds_is_the_longest_lock() {
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let b = allocate(&mut dev, 0);
    assert_eq!(dev.report(0, &lock(a, 10)), lock_ok(a));
    assert_eq!(dev.next_deadline(), Some(10_000));
    assert_eq!(
        dev.report(9_999, &init_packet(b, PING, 0, &[])),
        error_events(b, ERR_LOCK_REQUIRED)
    );
    assert_ping_echo(&mut dev, 10_000, b, 0);
}

#[test]
fn lock_longer_than_ten_seconds_is_invalid_par() {
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let b = allocate(&mut dev, 0);
    for seconds in [11u8, 12, 0x7F, 0xFF] {
        assert_eq!(
            dev.report(0, &lock(a, seconds)),
            error_events(a, ERR_INVALID_PAR),
            "{seconds} s"
        );
    }
    assert_eq!(dev.next_deadline(), None);
    assert_ping_echo(&mut dev, 1, b, 1);
}

#[test]
fn lock_request_must_carry_exactly_one_byte() {
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    for bcnt in [0u16, 2, 57, 58] {
        assert_eq!(
            dev.report(0, &init_packet(a, LOCK, bcnt, &[5, 5])),
            error_events(a, ERR_INVALID_LEN),
            "BCNT {bcnt}"
        );
    }
    assert_eq!(dev.next_deadline(), None);
}

#[test]
fn lock_zero_releases_and_the_holder_can_renew() {
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let b = allocate(&mut dev, 0);
    assert_eq!(dev.report(0, &lock(a, 2)), lock_ok(a));
    assert_eq!(dev.report(1500, &lock(a, 3)), lock_ok(a));
    assert_eq!(dev.next_deadline(), Some(4500));
    assert_eq!(
        dev.report(4499, &init_packet(b, PING, 0, &[])),
        error_events(b, ERR_LOCK_REQUIRED)
    );
    assert_eq!(dev.report(4499, &lock(a, 0)), lock_ok(a));
    assert_eq!(dev.next_deadline(), None);
    assert_ping_echo(&mut dev, 4499, b, 1);
    // Releasing when no lock is held is harmless.
    assert_eq!(dev.report(4500, &lock(b, 0)), lock_ok(b));
}

#[test]
fn another_channel_cannot_take_or_release_the_lock() {
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let b = allocate(&mut dev, 0);
    assert_eq!(dev.report(0, &lock(a, 5)), lock_ok(a));
    for seconds in [0u8, 5] {
        assert_eq!(
            dev.report(1, &lock(b, seconds)),
            error_events(b, ERR_LOCK_REQUIRED)
        );
    }
    assert_eq!(dev.next_deadline(), Some(5000));
}

#[test]
fn unknown_channel_is_invalid_channel_even_under_a_lock() {
    // Channel validity is checked before the lock (model policy, see framer docs).
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    assert_eq!(dev.report(0, &lock(a, 5)), lock_ok(a));
    assert_eq!(
        dev.report(1, &init_packet(a + 1, PING, 0, &[])),
        error_events(a + 1, ERR_INVALID_CHANNEL)
    );
}

#[test]
fn lock_and_partial_message_deadlines_combine() {
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    assert_eq!(dev.report(0, &lock(a, 10)), lock_ok(a));
    assert_eq!(
        dev.report(100, &init_packet(a, PING, 100, &[0; 57])),
        vec![]
    );
    assert_eq!(dev.next_deadline(), Some(100 + TIMEOUT_MS));
    assert_eq!(dev.tick(100 + TIMEOUT_MS), error_events(a, ERR_MSG_TIMEOUT));
    assert_eq!(dev.next_deadline(), Some(10_000));
}

#[test]
fn holder_resynchronising_with_init_keeps_the_lock() {
    // Model policy (spec silent): INIT resynchronisation ends the holder's transaction
    // but not its lock.
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let b = allocate(&mut dev, 0);
    assert_eq!(dev.report(0, &lock(a, 5)), lock_ok(a));
    assert_eq!(dev.report(1, &init_packet(a, INIT, 8, &[1; 8])).len(), 1);
    assert_eq!(
        dev.report(2, &init_packet(b, PING, 0, &[])),
        error_events(b, ERR_LOCK_REQUIRED)
    );
    assert_eq!(dev.next_deadline(), Some(5000));
}
