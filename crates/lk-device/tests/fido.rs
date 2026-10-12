//! The FIDO HID interface end to end: CTAPHID reports in, CTAPHID reports out.

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use lk_codec::cbor;
use lk_device::{BusEvent, Input, KEEPALIVE_INTERVAL_MS, Output, U2F_LATCH_MS, U2F_REQUEST_WINDOW_MS};

/// CTAP 2.1 status codes (§8.2) used below.
const CTAP2_OK: u8 = 0x00;
const CTAP2_ERR_KEEPALIVE_CANCEL: u8 = 0x2D;
const CTAP2_ERR_USER_ACTION_TIMEOUT: u8 = 0x2F;
const CTAP2_ERR_NOT_ALLOWED: u8 = 0x30;
/// authenticatorSelection (CTAP 2.1 §6.9): always waits for user presence.
const SELECTION: [u8; 1] = [0x0B];
/// authenticatorReset (CTAP 2.1 §6.6).
const RESET: [u8; 1] = [0x07];

/// U2F REGISTER (FIDO U2F Raw Message Formats §4.1): challenge and application
/// parameters, short-form APDU with Le.
fn u2f_register() -> Vec<u8> {
    let mut data = vec![0x42; 32];
    data.extend_from_slice(&[0x24; 32]);
    apdu(0x00, 0x01, 0x00, 0x00, &data, Some(0))
}

/// CTAP 2.1 §11.2.9.1.3: the INIT response carries the nonce, the new channel, protocol
/// version 2, the firmware version of the profile and the capability flags. The device
/// advertises CBOR | WINK (0x05) with FIDO2 and U2F enabled.
#[test]
fn init_reports_profile_version_and_cbor_wink() {
    let mut rig = Rig::new();
    let out = rig.ctaphid_send(BROADCAST, CTAPHID_INIT, &[9, 8, 7, 6, 5, 4, 3, 2]);
    let (cmd, payload) = responses(&out).remove(0);
    assert_eq!(cmd, CTAPHID_INIT);
    assert_eq!(payload, vec![9, 8, 7, 6, 5, 4, 3, 2, 0, 0, 0, 1, 2, 5, 7, 4, 0x05]);
}

/// `reference/yubikey-5c-nano-5.7.4/reference-observation.json`: GetInfo through the
/// whole device carries the reference AAGUID, firmware version 329476 and
/// maxMsgSize 1536.
#[test]
fn get_info_through_the_device_matches_reference_fields() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    let response = rig.cbor(cid, &[0x04]);
    assert_eq!(response[0], CTAP2_OK);
    let info = cbor::decode(&response[1..]).unwrap();
    assert_eq!(info.map_get_int(3).and_then(|v| v.as_bytes()).unwrap(), hex("ff4dac45ede84ec2acedcf66103f4335"));
    assert_eq!(info.map_get_int(0x0E).and_then(|v| v.as_u64()), Some(329_476));
    assert_eq!(info.map_get_int(5).and_then(|v| v.as_u64()), Some(1536));
}

/// CTAP 2.1 §11.2.9.1.7: KEEPALIVE with STATUS_UPNEEDED every 95 ms while the command
/// waits, the first one interval after the request, none at once (measured on a YubiKey
/// 5C Nano 5.7.4: docs/MEASUREMENT.md, probes selection-keepalive-cancel and
/// selection-no-touch; before the measurement the first one went out at once and the
/// interval was 100 ms); a touch answers it; the presence indicator follows the wait.
#[test]
fn waiting_command_sends_keepalives_and_resolves_on_touch() {
    assert_eq!(KEEPALIVE_INTERVAL_MS, 95);
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    let out = rig.ctaphid_send(cid, CTAPHID_CBOR, &SELECTION);
    assert_eq!(keepalives(&out), Vec::<u8>::new(), "no KEEPALIVE at once");
    assert!(responses(&out).is_empty());
    assert_eq!(indicators(&out), vec![true]);
    assert_eq!(rig.dev.next_deadline(), Some(rig.now + KEEPALIVE_INTERVAL_MS));
    assert_eq!(keepalives(&rig.advance(KEEPALIVE_INTERVAL_MS - 1)), Vec::<u8>::new());
    assert_eq!(keepalives(&rig.advance(1)), vec![2], "the first KEEPALIVE");
    for _ in 0..3 {
        let out = rig.advance(KEEPALIVE_INTERVAL_MS);
        assert_eq!(keepalives(&out), vec![2]);
    }
    let out = rig.tap();
    assert_eq!(responses(&out), vec![(CTAPHID_CBOR, vec![CTAP2_OK])]);
    assert_eq!(indicators(&out), vec![false]);
    assert!(keyboard(&out).is_empty(), "a touch that satisfied a request never types");
    assert_eq!(keepalives(&rig.advance(500)), Vec::<u8>::new());
    assert_eq!(rig.dev.next_deadline(), None);
}

/// Periodic timers stay on the grid from the start: a late Tick sends one KEEPALIVE,
/// not a burst, and the next one is due at the next grid point (`presence.rs` module
/// documentation). With the measured 95 ms interval (docs/MEASUREMENT.md, probe
/// selection-no-touch) the first grid point after 1000 ms is 11 x 95 = 1045 ms; with the
/// former 100 ms it happened to be `now + 100`.
#[test]
fn late_tick_sends_one_keepalive() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    let start = rig.now;
    rig.ctaphid_send(cid, CTAPHID_CBOR, &SELECTION);
    let out = rig.advance(1_000);
    assert_eq!(keepalives(&out), vec![2]);
    assert_eq!(rig.dev.next_deadline(), Some(start + 11 * KEEPALIVE_INTERVAL_MS));
}

/// lk-fido `TOUCH_TIMEOUT_MS`; `presence_resolved(false)` for selection is
/// CTAP2_ERR_USER_ACTION_TIMEOUT (CTAP 2.1 §6.9). The timeout is 30 s (CTAP 2.1 §5,
/// "User action timeout": "Thirty seconds is a reasonable value"), which is not a multiple
/// of the 95 ms KEEPALIVE interval: the host sees 315 KEEPALIVEs, the last at 29 925 ms,
/// and then the answer alone at 30 000 ms, with no KEEPALIVE in that Tick. Known
/// difference: the YubiKey 5C Nano 5.7.4 answers after 300 KEEPALIVEs, 28 451.8 ms after
/// the request (docs/MEASUREMENT.md, probe selection-no-touch), its 30 s design value on a
/// clock that runs about 5.4 % fast; the drift is not copied ("Revised by principle").
/// This test expected 28 500 ms and 300 KEEPALIVEs between the measurement and that
/// revision.
#[test]
fn presence_timeout_answers_the_command() {
    assert_eq!(lk_fido::TOUCH_TIMEOUT_MS, 30_000);
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    let start = rig.now;
    rig.ctaphid_send(cid, CTAPHID_CBOR, &SELECTION);
    let mut sent = Vec::new();
    let last = loop {
        rig.now = rig.dev.next_deadline().expect("the command is waiting");
        let out = rig.input(Input::Tick);
        if !responses(&out).is_empty() {
            break out;
        }
        assert_eq!(keepalives(&out), vec![2], "at {}", rig.now);
        sent.push(rig.now);
    };
    assert_eq!(rig.now, start + lk_fido::TOUCH_TIMEOUT_MS);
    assert_eq!(sent.len(), 315, "KEEPALIVEs before the answer");
    assert_eq!(sent.last(), Some(&(start + 315 * KEEPALIVE_INTERVAL_MS)));
    assert_eq!(keepalives(&last), Vec::<u8>::new(), "the answer comes alone");
    assert_eq!(responses(&last), vec![(CTAPHID_CBOR, vec![CTAP2_ERR_USER_ACTION_TIMEOUT])]);
    assert_eq!(indicators(&last), vec![false]);
}

/// A touch after the timeout passed, without a Tick in between, does not satisfy the
/// request: deadlines are processed before the input (`lib.rs` "Time").
#[test]
fn touch_after_an_unticked_timeout_does_not_count() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    rig.ctaphid_send(cid, CTAPHID_CBOR, &SELECTION);
    rig.now = 31_000;
    let out = rig.touch_down();
    assert_eq!(responses(&out), vec![(CTAPHID_CBOR, vec![CTAP2_ERR_USER_ACTION_TIMEOUT])]);
}

/// CTAP 2.1 §11.2.9.1.5: CTAPHID_CANCEL ends the waiting command with
/// CTAP2_ERR_KEEPALIVE_CANCEL.
#[test]
fn cancel_ends_the_waiting_command() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    rig.ctaphid_send(cid, CTAPHID_CBOR, &SELECTION);
    let out = rig.ctaphid_send(cid, CTAPHID_CANCEL, &[]);
    assert_eq!(responses(&out), vec![(CTAPHID_CBOR, vec![CTAP2_ERR_KEEPALIVE_CANCEL])]);
    assert_eq!(indicators(&out), vec![false]);
    // The channel is free again.
    assert_eq!(rig.ctaphid(cid, CTAPHID_PING, b"hi"), (CTAPHID_PING, b"hi".to_vec()));
}

/// Catalog FIDO: "Allocated CTAPHID INIT now discards late replies from an aborted
/// same-CID operation"; docs/CONTRACTS.md: lk-device drops the pending operation on
/// `Event::Abort` and never sends its late reply.
#[test]
fn init_resynchronisation_drops_the_late_reply() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    rig.ctaphid_send(cid, CTAPHID_CBOR, &SELECTION);
    let out = rig.ctaphid_send(cid, CTAPHID_INIT, &[1; 8]);
    let messages = responses(&out);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].0, CTAPHID_INIT);
    assert_eq!(indicators(&out), vec![false]);
    let out = rig.tap();
    assert!(out.iter().all(|o| !matches!(o, Output::FidoReport(_))), "late reply: {out:02X?}");
    assert_eq!(rig.cbor(cid, &[0x04])[0], CTAP2_OK);
}

/// Catalog FIDO: "A concurrent CTAPHID CBOR operation reserves the device for its CID:
/// PING, WINK and INIT on another or broadcast CID return CHANNEL_BUSY".
#[test]
fn other_channels_are_busy_while_a_command_waits() {
    let mut rig = Rig::new();
    let first = rig.ctaphid_init();
    let second = rig.ctaphid_init();
    rig.ctaphid_send(first, CTAPHID_CBOR, &SELECTION);
    assert_eq!(rig.ctaphid(second, CTAPHID_PING, b"x"), (CTAPHID_ERROR, vec![0x06]));
    assert_eq!(rig.ctaphid(first, CTAPHID_PING, b"x"), (CTAPHID_ERROR, vec![0x06]));
}

/// docs/CONTRACTS.md U2F presence: `Requested` opens a window (the indicator lights);
/// a touch during it latches; the next U2F request that needs presence succeeds and
/// consumes the latch.
#[test]
fn u2f_touch_latch_lets_the_next_request_succeed() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    let out = rig.ctaphid_send(cid, CTAPHID_MSG, &u2f_register());
    assert_eq!(responses(&out), vec![(CTAPHID_MSG, vec![0x69, 0x85])]);
    assert_eq!(indicators(&out), vec![true]);
    let out = rig.tap();
    assert_eq!(indicators(&out), vec![false]);
    assert!(keyboard(&out).is_empty());
    let (cmd, response) = rig.ctaphid(cid, CTAPHID_MSG, &u2f_register());
    assert_eq!(cmd, CTAPHID_MSG);
    assert_eq!(sw(&response), 0x9000);
    assert_eq!(response[0], 0x05, "U2F registration reserved byte (§4.3)");
    // The latch was consumed.
    let (_, response) = rig.ctaphid(cid, CTAPHID_MSG, &u2f_register());
    assert_eq!(response, vec![0x69, 0x85]);
}

/// The latched touch expires after `U2F_LATCH_MS`.
#[test]
fn u2f_latch_expires() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    rig.ctaphid(cid, CTAPHID_MSG, &u2f_register());
    rig.tap();
    rig.advance(U2F_LATCH_MS);
    let (_, response) = rig.ctaphid(cid, CTAPHID_MSG, &u2f_register());
    assert_eq!(response, vec![0x69, 0x85]);
}

/// The U2F request window closes `U2F_REQUEST_WINDOW_MS` after the last `6985`; a later
/// touch is not latched.
#[test]
fn u2f_window_closes_when_the_client_stops_asking() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    rig.ctaphid(cid, CTAPHID_MSG, &u2f_register());
    rig.advance(1_000);
    // A repeated request keeps the window open.
    rig.ctaphid(cid, CTAPHID_MSG, &u2f_register());
    assert!(indicators(&rig.advance(U2F_REQUEST_WINDOW_MS - 1)).is_empty());
    assert_eq!(indicators(&rig.advance(1)), vec![false]);
    rig.tap();
    let (_, response) = rig.ctaphid(cid, CTAPHID_MSG, &u2f_register());
    assert_eq!(response, vec![0x69, 0x85]);
}

/// Catalog FIDO: "CTAPHID_CANCEL during a U2F MSG is ignored" (U2F never waits, and the
/// framer only cancels CBOR requests).
#[test]
fn cancel_after_u2f_does_nothing() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    rig.ctaphid(cid, CTAPHID_MSG, &u2f_register());
    let out = rig.ctaphid_send(cid, CTAPHID_CANCEL, &[]);
    assert!(out.iter().all(|o| !matches!(o, Output::FidoReport(_))));
}

/// Catalog Management "CTAPHID vendor 0x42 / 0x43 commands": READ CONFIG answers
/// `len || TLVs`; other vendor commands answer ERR_INVALID_CMD and leave the channel
/// usable (docs/CONTRACTS.md "Phase 0": an unanswered vendor request keeps the channel
/// busy).
#[test]
fn vendor_commands() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    let (cmd, config) = rig.ctaphid(cid, 0x42, &[]);
    assert_eq!(cmd, 0x42);
    assert_eq!(usize::from(config[0]), config.len() - 1);
    let serial = lk_codec::tlv::parse_all(&config[1..]).unwrap();
    let serial = lk_codec::tlv::find(&serial, 0x02).unwrap();
    assert_eq!(serial.value, SERIAL.to_be_bytes());
    assert_eq!(rig.ctaphid(cid, 0x50, &[1, 2]), (CTAPHID_ERROR, vec![0x01]));
    // YubiKey 4 SET MODE is not implemented (docs/catalog/mgmt.md).
    assert_eq!(rig.ctaphid(cid, 0x40, &[0x06, 0, 0, 0]), (CTAPHID_ERROR, vec![0x01]));
    assert_eq!(rig.ctaphid(cid, CTAPHID_PING, b"ok"), (CTAPHID_PING, b"ok".to_vec()));
}

/// CTAP 2.1 §11.2.9.2.1 WINK: answered, with a presence-indicator pulse (`fido.rs`).
#[test]
fn wink_pulses_the_indicator() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    let out = rig.ctaphid_send(cid, CTAPHID_WINK, &[]);
    assert_eq!(responses(&out), vec![(CTAPHID_WINK, vec![])]);
    assert_eq!(indicators(&out), vec![true, false]);
    assert!(!rig.dev.presence_pending());
}

/// CTAP 2.1 §6.6: authenticatorReset only within 10 s of power-up. `Device::open` is
/// power-up; `BusEvent::PowerCycle` is a new one (`Authenticator::power_cycle`).
#[test]
fn reset_window_counts_from_power_up() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    // A waiting command is answered by nothing at first (no KEEPALIVE at once, measured:
    // docs/MEASUREMENT.md, probe selection-keepalive-cancel; this test looked for that
    // immediate KEEPALIVE before the measurement) and lights the presence indicator.
    let out = rig.ctaphid_send(cid, CTAPHID_CBOR, &RESET);
    assert!(responses(&out).is_empty(), "reset within the window waits for a touch");
    assert_eq!(indicators(&out), vec![true]);
    rig.ctaphid_send(cid, CTAPHID_CANCEL, &[]);
    rig.advance(11_000);
    assert_eq!(rig.cbor(cid, &RESET), vec![CTAP2_ERR_NOT_ALLOWED]);
    rig.bus(BusEvent::PowerCycle);
    let cid = rig.ctaphid_init();
    let out = rig.ctaphid_send(cid, CTAPHID_CBOR, &RESET);
    assert!(responses(&out).is_empty());
    assert_eq!(indicators(&out), vec![true]);
}

/// docs/CONTRACTS.md "Phase 0", lk-ctaphid: on a USB reset lk-device drops the pending
/// operation itself; earlier channels are invalid afterwards (catalog appendix B
/// `fido_usb_bus_reset_old_report_isolation`).
#[test]
fn usb_reset_drops_the_waiting_command_and_channels() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    rig.ctaphid_send(cid, CTAPHID_CBOR, &SELECTION);
    let out = rig.bus(BusEvent::Reset);
    assert_eq!(indicators(&out), vec![false]);
    let out = rig.tap();
    assert!(out.iter().all(|o| !matches!(o, Output::FidoReport(_))));
    assert_eq!(rig.ctaphid(cid, CTAPHID_PING, b"x"), (CTAPHID_ERROR, vec![0x0B]));
    let cid = rig.ctaphid_init();
    assert_eq!(rig.cbor(cid, &[0x04])[0], CTAP2_OK);
}

/// Catalog appendix A `Linux_native` runtime PM: "same ... exact bytes while
/// suspended": suspend and resume keep the CTAPHID channel and the waiting command.
#[test]
fn suspend_and_resume_keep_fido_state() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    rig.ctaphid_send(cid, CTAPHID_CBOR, &SELECTION);
    rig.bus(BusEvent::Suspend);
    rig.bus(BusEvent::Resume);
    let out = rig.tap();
    assert_eq!(responses(&out), vec![(CTAPHID_CBOR, vec![CTAP2_OK])]);
    assert_eq!(rig.ctaphid(cid, CTAPHID_PING, b"x"), (CTAPHID_PING, b"x".to_vec()));
}

/// CTAP 2.1 §11.2.5.2: an incomplete message times out with ERR_MSG_TIMEOUT; the
/// device reports the framer's deadline and a Tick at it delivers the error. Measured on
/// a YubiKey 5C Nano 5.7.4 (docs/MEASUREMENT.md, probe message-timeout: this very request,
/// a PING initialization packet with BCNT 100, is answered after 469.8 ms); the engine
/// uses 470 ms (3000 ms model policy before the measurement).
#[test]
fn ctaphid_message_timeout_is_a_device_deadline() {
    assert_eq!(lk_ctaphid::TRANSACTION_TIMEOUT_MS, 470);
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    let packets = Rig::ctaphid_packets(cid, CTAPHID_PING, &[0x55; 100]);
    rig.input(Input::FidoReport(&packets[0]));
    let deadline = rig.dev.next_deadline().unwrap();
    assert_eq!(deadline, rig.now + lk_ctaphid::TRANSACTION_TIMEOUT_MS);
    assert!(responses(&rig.advance(deadline - rig.now - 1)).is_empty());
    let out = rig.advance(1);
    assert_eq!(responses(&out), vec![(CTAPHID_ERROR, vec![0x05])]);
}

/// CTAP 2.1 §11.2.9.1.2 ("BCNT 1..(n + 1)", the CTAP command byte first) and §11.2.9.1.6
/// (ERR_INVALID_LEN, "The length field (BCNT) is invalid for the request"): CTAPHID_CBOR
/// with BCNT 0 is ERR_INVALID_LEN at once and holds nothing; no presence request starts,
/// and another channel's PING works right away. Known difference: the YubiKey 5C Nano
/// 5.7.4 never answers it and stays busy (other channels ERR_CHANNEL_BUSY, CANCEL ignored)
/// until INIT on the channel (docs/MEASUREMENT.md, probe empty-cbor, "The stuck-channel
/// incident"). That stall is a defect not copied ("Revised by principle"): "A request
/// always triggers a response" (§11.2.4) and a stalling application must not lock the
/// device out (§11.2.5, §11.2.5.2). This test asserted the stall between the measurement
/// and that revision.
#[test]
fn empty_cbor_request_is_invalid_len_and_holds_nothing() {
    let mut rig = Rig::new();
    let a = rig.ctaphid_init();
    let b = rig.ctaphid_init();
    let out = rig.ctaphid_send(a, CTAPHID_CBOR, &[]);
    assert_eq!(responses(&out), vec![(CTAPHID_ERROR, vec![0x03])]);
    assert_eq!(keepalives(&out), Vec::<u8>::new());
    assert_eq!(rig.dev.next_deadline(), None, "nothing waits");
    assert!(!rig.dev.presence_pending());
    assert_eq!(rig.ctaphid(b, CTAPHID_PING, b"x"), (CTAPHID_PING, b"x".to_vec()));
    assert!(rig.ctaphid_send(a, CTAPHID_CANCEL, &[]).is_empty(), "CANCEL is not answered");
    assert_eq!(rig.ctaphid(a, CTAPHID_PING, b"y"), (CTAPHID_PING, b"y".to_vec()));
    // A touch is an ordinary button press: no FIDO request waits.
    let out = rig.tap();
    assert!(out.iter().all(|o| !matches!(o, Output::FidoReport(_))));
}

/// Measured on a YubiKey 5C Nano 5.7.4 (docs/MEASUREMENT.md, probe ping-max): the longest
/// PING echoed is 1536 bytes; a longer one is ERR_INVALID_LEN at once, its remaining
/// packets are ignored and the next request works. Before the measurement the device
/// echoed up to 7609 bytes.
#[test]
fn ping_longer_than_1536_bytes_is_invalid_len_and_the_rest_is_ignored() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    let payload: Vec<u8> = (0..1536u32).map(|i| (i * 7) as u8).collect();
    assert_eq!(rig.ctaphid(cid, CTAPHID_PING, &payload), (CTAPHID_PING, payload.clone()));
    for len in [1537usize, 1709, 3833, 7609] {
        let packets = Rig::ctaphid_packets(cid, CTAPHID_PING, &vec![0x33; len]);
        let out = rig.input(Input::FidoReport(&packets[0]));
        assert_eq!(responses(&out), vec![(CTAPHID_ERROR, vec![0x03])], "{len} bytes");
        for packet in &packets[1..] {
            assert!(rig.input(Input::FidoReport(packet)).is_empty(), "late fragment of {len} bytes");
        }
        assert_eq!(rig.dev.next_deadline(), None);
        assert_eq!(rig.ctaphid(cid, CTAPHID_PING, &payload[..57]), (CTAPHID_PING, payload[..57].to_vec()));
    }
}
