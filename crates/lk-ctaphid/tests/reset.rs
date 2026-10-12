//! USB bus reset (`Ctaphid::reset`).
//!
//! `reference/BEHAVIOR_CATALOG.md` appendix A: on USB bus reset "connection
//! generations discard old assembly, pending responses, and late worker replies".
//! Model policy: channels allocated before the reset become invalid.

mod common;

use common::*;

#[test]
fn reset_discards_a_partial_message() {
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    let request = message(cid, PING, &pattern(100, 1));
    assert_eq!(dev.report(0, &request[0]), vec![]);
    dev.reset();
    assert_eq!(dev.next_deadline(), None);
    assert_eq!(
        dev.tick(10 * TIMEOUT_MS),
        vec![],
        "no timeout for a discarded message"
    );
    assert_eq!(
        dev.report(1, &request[1]),
        vec![],
        "old continuation is an orphan"
    );
    let fresh = allocate(&mut dev, 2);
    assert_ping_echo(&mut dev, 2, fresh, 1);
}

#[test]
fn reset_discards_the_outstanding_request_and_its_late_reply() {
    let mut dev = device();
    let cid = allocate(&mut dev, 0);
    start_cbor(&mut dev, 1, cid, &[0x01]);
    dev.reset();
    assert_eq!(dev.outstanding(), None);
    assert_eq!(dev.respond(cid, CBOR, &[0x00]), Vec::<Report>::new());
    let fresh = allocate(&mut dev, 2);
    assert_ping_echo(&mut dev, 2, fresh, 1);
}

#[test]
fn channels_from_before_the_reset_are_invalid_and_never_reused() {
    let mut dev = device();
    let old: Vec<u32> = (0..3).map(|_| allocate(&mut dev, 0)).collect();
    dev.reset();
    for &cid in &old {
        assert_eq!(
            dev.report(1, &init_packet(cid, PING, 0, &[])),
            error_events(cid, ERR_INVALID_CHANNEL)
        );
        assert_eq!(
            dev.report(1, &init_packet(cid, INIT, 8, &[0; 8])),
            error_events(cid, ERR_INVALID_CHANNEL)
        );
    }
    let fresh = allocate(&mut dev, 2);
    assert!(!old.contains(&fresh));
    assert_ping_echo(&mut dev, 2, fresh, 1);
}
