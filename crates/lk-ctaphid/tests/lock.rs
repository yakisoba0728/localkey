//! `CTAPHID_LOCK` (CTAP 2.1 §11.2.9.2.2) is not implemented.
//!
//! Measured on a YubiKey 5C Nano 5.7.4 (`docs/MEASUREMENT.md`, probes `lock` and
//! `lock-expiry`): LOCK with 0, 1 or 2 seconds (BCNT 1) is answered `ERR_INVALID_CMD`
//! (`01`), and another channel's PING and a broadcast INIT sent right after it are
//! answered normally. Before the measurement the engine implemented the lock (0..=10 s,
//! other channels `ERR_CHANNEL_BUSY` until it lapsed); these tests replace those.

mod common;

use common::*;
use lk_ctaphid::Event;

fn lock(cid: u32, seconds: u8) -> Report {
    init_packet(cid, LOCK, 1, &[seconds])
}

#[test]
fn lock_is_invalid_cmd_for_every_duration() {
    // docs/MEASUREMENT.md, probes lock and lock-expiry: 0, 1 and 2 seconds were sent;
    // the other durations, including those CTAP 2.1 does not allow, get the same answer.
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    for seconds in [0u8, 1, 2, 5, 10, 11, 0x7F, 0xFF] {
        assert_eq!(
            dev.report(1, &lock(a, seconds)),
            error_events(a, ERR_INVALID_CMD),
            "{seconds} s"
        );
        assert_eq!(dev.next_deadline(), None, "{seconds} s sets no timer");
    }
    assert_ping_echo(&mut dev, 2, a, 1);
}

#[test]
fn lock_is_invalid_cmd_whatever_its_length() {
    // The command is unknown, so its BCNT is never looked at (framer check order: the
    // command before the length). Only BCNT 1 was measured.
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    for bcnt in [0u16, 1, 2, 57, 58, 1537, 0xFFFF] {
        assert_eq!(
            dev.report(1, &init_packet(a, LOCK, bcnt, &[5, 5])),
            error_events(a, ERR_INVALID_CMD),
            "BCNT {bcnt}"
        );
        assert_eq!(dev.next_deadline(), None);
    }
    // A multi-packet LOCK starts no message: its continuation packets are orphans.
    assert_eq!(dev.report(2, &cont_packet(a, 0, &[5; 59])), vec![]);
    assert_ping_echo(&mut dev, 3, a, 1);
}

#[test]
fn measured_probe_other_channels_are_served_right_after_a_lock() {
    // docs/MEASUREMENT.md, probe lock: LOCK 1 s on A is ERR_INVALID_CMD; B's PING,
    // a broadcast INIT and A's PING right after are answered normally; LOCK 1 and LOCK 0
    // again are ERR_INVALID_CMD and B's PING still works.
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let b = allocate(&mut dev, 0);
    assert_eq!(dev.report(0, &lock(a, 1)), error_events(a, ERR_INVALID_CMD));
    assert_eq!(
        dev.report(4, &init_packet(b, PING, 1, &[0x5A])),
        vec![Event::Send(init_packet(b, PING, 1, &[0x5A]))]
    );
    let c = allocate(&mut dev, 8);
    assert_eq!(c, b + 1, "the broadcast INIT allocated a channel");
    assert_ping_echo(&mut dev, 12, a, 1);
    assert_ping_echo(&mut dev, 1250, b, 1);
    assert_eq!(
        dev.report(1254, &lock(a, 1)),
        error_events(a, ERR_INVALID_CMD)
    );
    assert_eq!(
        dev.report(1258, &lock(a, 0)),
        error_events(a, ERR_INVALID_CMD)
    );
    assert_ping_echo(&mut dev, 1262, b, 1);
    assert_eq!(dev.next_deadline(), None);
}

#[test]
fn measured_probe_lock_expiry_a_polling_client_gets_through_at_the_first_poll() {
    // docs/MEASUREMENT.md, probe lock-expiry: after LOCK 1 s and LOCK 2 s (both
    // ERR_INVALID_CMD) B's first PING poll gets through (about 4 ms later), with no
    // ERR_CHANNEL_BUSY at all; before the measurement the engine kept B busy for
    // 1010 ms and 2015 ms.
    let mut dev = device();
    for seconds in [1u8, 2] {
        let a = allocate(&mut dev, 0);
        let b = allocate(&mut dev, 0);
        assert_eq!(
            dev.report(8, &lock(a, seconds)),
            error_events(a, ERR_INVALID_CMD)
        );
        let ping = init_packet(b, PING, 4, b"poll");
        assert_eq!(
            dev.report(12, &ping),
            vec![Event::Send(ping)],
            "{seconds} s"
        );
        assert_eq!(dev.next_deadline(), None);
    }
}

#[test]
fn lock_never_causes_lock_required() {
    // CTAP 2.1 §11.2.9.1.6 ERR_LOCK_REQUIRED ("Command requires channel lock"): with no
    // lock implemented no command requires one; a LOCK from another channel while a
    // request is outstanding is ERR_CHANNEL_BUSY like any other command (framer check
    // order, busy before command; which error the key gives a busy LOCK was not measured).
    let mut dev = device();
    let a = allocate(&mut dev, 0);
    let b = allocate(&mut dev, 0);
    start_cbor(&mut dev, 1, a, &[0x01]);
    assert_eq!(
        dev.report(2, &lock(b, 1)),
        error_events(b, ERR_CHANNEL_BUSY)
    );
    assert_eq!(
        dev.report(2, &lock(a, 1)),
        error_events(a, ERR_CHANNEL_BUSY)
    );
    assert_eq!(dev.respond(a, CBOR, &[0x00]).len(), 1);
    for cid in [a, b] {
        let events = dev.report(3, &lock(cid, 1));
        assert_ne!(events, error_events(cid, ERR_LOCK_REQUIRED));
        assert_eq!(events, error_events(cid, ERR_INVALID_CMD));
    }
}
