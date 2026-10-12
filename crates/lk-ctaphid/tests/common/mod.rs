//! Host-side helpers for report-level tests.
//!
//! They are written from the CTAP 2.1 §11.2.4 packet layout and deliberately do not
//! use the crate's own framing code, so the tests do not check the framer against
//! itself:
//!
//! - initialization packet: `CID(4) CMD|0x80 BCNTH BCNTL DATA(57)`;
//! - continuation packet: `CID(4) SEQ(0..=0x7F) DATA(59)`.

#![allow(dead_code)]

use lk_core::Version;
use lk_ctaphid::{Ctaphid, Event};

pub type Report = [u8; 64];

pub const BROADCAST: u32 = 0xFFFF_FFFF;

/// Firmware values: `reference/physical-key/reference-observation.json`
/// `firmware_version` 329476 = 0x050704.
pub const FIRMWARE: Version = Version::new(5, 7, 4);

/// WINK (0x01) | CBOR (0x04), CTAP 2.1 §11.2.9.1.3. Test-chosen: the reference files
/// do not record the device's INIT capability byte.
pub const CAPS: u8 = 0x05;

// Command codes, CTAP 2.1 §11.2.9.
pub const PING: u8 = 0x01;
pub const MSG: u8 = 0x03;
pub const LOCK: u8 = 0x04;
pub const INIT: u8 = 0x06;
pub const WINK: u8 = 0x08;
pub const CBOR: u8 = 0x10;
pub const CANCEL: u8 = 0x11;
pub const KEEPALIVE: u8 = 0x3B;
pub const ERROR: u8 = 0x3F;

// Error codes, CTAP 2.1 §11.2.9.1.6.
pub const ERR_INVALID_CMD: u8 = 0x01;
pub const ERR_INVALID_PAR: u8 = 0x02;
pub const ERR_INVALID_LEN: u8 = 0x03;
pub const ERR_INVALID_SEQ: u8 = 0x04;
pub const ERR_MSG_TIMEOUT: u8 = 0x05;
pub const ERR_CHANNEL_BUSY: u8 = 0x06;
pub const ERR_LOCK_REQUIRED: u8 = 0x0A;
pub const ERR_INVALID_CHANNEL: u8 = 0x0B;
pub const ERR_OTHER: u8 = 0x7F;

/// The transaction timeout (`lk_ctaphid::TRANSACTION_TIMEOUT_MS`). Measured on a
/// reference key (`docs/MEASUREMENT.md`, probe `message-timeout`: 469.8 ms);
/// it was the model policy 3000 ms before the measurement.
pub const TIMEOUT_MS: u64 = 470;

/// The longest request message (`lk_ctaphid::MAX_MESSAGE_LEN`). Measured on a YubiKey
/// reference key (`docs/MEASUREMENT.md`, probe `ping-max`: the longest PING echoed is
/// 1536 bytes, 1537 is `ERR_INVALID_LEN`); it was the framing limit 7609 before.
pub const MAX_REQUEST: usize = 1536;

/// The framing limit for device responses, `57 + 128 * 59` (CTAP 2.1 §11.2.4).
pub const MAX_FRAMED: usize = 7609;

pub fn device() -> Ctaphid {
    Ctaphid::new(FIRMWARE, CAPS)
}

/// An initialization packet with an arbitrary BCNT and up to 57 data bytes.
pub fn init_packet(cid: u32, cmd: u8, bcnt: u16, data: &[u8]) -> Report {
    assert!(data.len() <= 57, "init packet data too long");
    let mut report = [0u8; 64];
    report[0..4].copy_from_slice(&cid.to_be_bytes());
    report[4] = 0x80 | cmd;
    report[5..7].copy_from_slice(&bcnt.to_be_bytes());
    report[7..7 + data.len()].copy_from_slice(data);
    report
}

/// A continuation packet with up to 59 data bytes.
pub fn cont_packet(cid: u32, seq: u8, data: &[u8]) -> Report {
    assert!(seq <= 0x7F, "continuation SEQ has bit 7 clear");
    assert!(data.len() <= 59, "cont packet data too long");
    let mut report = [0u8; 64];
    report[0..4].copy_from_slice(&cid.to_be_bytes());
    report[4] = seq;
    report[5..5 + data.len()].copy_from_slice(data);
    report
}

/// The host's fragmentation of a whole message (BCNT may exceed what the packets can
/// carry; only the first 57 + 128 * 59 bytes are sent).
pub fn message(cid: u32, cmd: u8, payload: &[u8]) -> Vec<Report> {
    let bcnt = u16::try_from(payload.len()).expect("payload fits in BCNT");
    let first = payload.len().min(57);
    let mut reports = vec![init_packet(cid, cmd, bcnt, &payload[..first])];
    for (seq, chunk) in payload[first..].chunks(59).enumerate().take(128) {
        reports.push(cont_packet(cid, seq as u8, chunk));
    }
    reports
}

/// A deterministic test payload.
pub fn pattern(len: usize, salt: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(salt))
        .collect()
}

/// Feeds reports one by one at `now` and collects every event.
pub fn feed(dev: &mut Ctaphid, now: u64, reports: &[Report]) -> Vec<Event> {
    reports
        .iter()
        .flat_map(|report| dev.report(now, report))
        .collect()
}

/// The reports carried by `Send` events; any other event fails the test.
pub fn sends(events: &[Event]) -> Vec<Report> {
    events
        .iter()
        .map(|event| match event {
            Event::Send(report) => *report,
            other => panic!("expected only Send events, got {other:?}"),
        })
        .collect()
}

/// The device's `CTAPHID_ERROR` report (CTAP 2.1 §11.2.9.1.6): BCNT 1, code, zero padding.
pub fn error_report(cid: u32, code: u8) -> Report {
    init_packet(cid, ERROR, 1, &[code])
}

/// The single `Send` event carrying an error, as a one-element event list.
pub fn error_events(cid: u32, code: u8) -> Vec<Event> {
    vec![Event::Send(error_report(cid, code))]
}

/// Reassembles one device message, checking the CID on every packet, consecutive
/// SEQ numbers from 0, the exact packet count and zero padding after the message.
pub fn reassemble(reports: &[Report]) -> (u32, u8, Vec<u8>) {
    let (init, conts) = reports.split_first().expect("at least one report");
    let cid = u32::from_be_bytes([init[0], init[1], init[2], init[3]]);
    assert!(
        init[4] & 0x80 != 0,
        "first report is an initialization packet"
    );
    let cmd = init[4] & 0x7F;
    let bcnt = usize::from(u16::from_be_bytes([init[5], init[6]]));
    let expected_packets = if bcnt <= 57 {
        1
    } else {
        1 + (bcnt - 57).div_ceil(59)
    };
    assert_eq!(
        reports.len(),
        expected_packets,
        "packet count for BCNT {bcnt}"
    );
    let mut data = init[7..].to_vec();
    for (seq, report) in conts.iter().enumerate() {
        assert_eq!(
            &report[0..4],
            &cid.to_be_bytes(),
            "CID of continuation {seq}"
        );
        assert_eq!(usize::from(report[4]), seq, "SEQ of continuation packet");
        data.extend_from_slice(&report[5..]);
    }
    assert!(
        data[bcnt..].iter().all(|&b| b == 0),
        "zero padding after a {bcnt}-byte message"
    );
    data.truncate(bcnt);
    (cid, cmd, data)
}

/// Allocates a channel with a broadcast INIT and returns its CID.
pub fn allocate(dev: &mut Ctaphid, now: u64) -> u32 {
    let nonce = [0xA5, 0x5A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    let reports = sends(&dev.report(now, &init_packet(BROADCAST, INIT, 8, &nonce)));
    assert_eq!(reports.len(), 1);
    let (cid, cmd, payload) = reassemble(&reports);
    assert_eq!((cid, cmd), (BROADCAST, INIT));
    assert_eq!(payload.len(), 17);
    assert_eq!(&payload[..8], &nonce);
    u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]])
}

/// Sends a PING and checks the echo; the channel must be idle and allowed.
pub fn assert_ping_echo(dev: &mut Ctaphid, now: u64, cid: u32, len: usize) {
    let payload = pattern(len, 0x42);
    let reports = sends(&feed(dev, now, &message(cid, PING, &payload)));
    assert_eq!(reassemble(&reports), (cid, PING, payload));
}

/// Sends a complete CBOR request and expects it to reach the application.
pub fn start_cbor(dev: &mut Ctaphid, now: u64, cid: u32, payload: &[u8]) {
    let events = feed(dev, now, &message(cid, CBOR, payload));
    assert_eq!(
        events,
        vec![Event::Request {
            cid,
            cmd: CBOR,
            payload: payload.to_vec()
        }]
    );
}
