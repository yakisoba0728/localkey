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

/// CTAP 2.1 §11.2.9.1.7: KEEPALIVE with STATUS_UPNEEDED at once and every 100 ms while
/// the command waits; a touch answers it; the presence indicator follows the wait.
#[test]
fn waiting_command_sends_keepalives_and_resolves_on_touch() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    let out = rig.ctaphid_send(cid, CTAPHID_CBOR, &SELECTION);
    assert_eq!(keepalives(&out), vec![2]);
    assert!(responses(&out).is_empty());
    assert_eq!(indicators(&out), vec![true]);
    assert_eq!(rig.dev.next_deadline(), Some(rig.now + KEEPALIVE_INTERVAL_MS));
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

/// Periodic timers restart from the time they are processed: a late Tick sends one
/// KEEPALIVE, not a burst (`presence.rs` module documentation).
#[test]
fn late_tick_sends_one_keepalive() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    rig.ctaphid_send(cid, CTAPHID_CBOR, &SELECTION);
    let out = rig.advance(1_000);
    assert_eq!(keepalives(&out), vec![2]);
    assert_eq!(rig.dev.next_deadline(), Some(rig.now + KEEPALIVE_INTERVAL_MS));
}

/// lk-fido `TOUCH_TIMEOUT_MS` (30 s); `presence_resolved(false)` for selection is
/// CTAP2_ERR_USER_ACTION_TIMEOUT (CTAP 2.1 §6.9).
#[test]
fn presence_timeout_answers_the_command() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    rig.ctaphid_send(cid, CTAPHID_CBOR, &SELECTION);
    let mut last = Vec::new();
    while rig.now < 30_000 {
        last = rig.advance(KEEPALIVE_INTERVAL_MS);
        if !responses(&last).is_empty() {
            break;
        }
    }
    assert_eq!(rig.now, 30_000);
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
    let out = rig.ctaphid_send(cid, CTAPHID_CBOR, &RESET);
    assert_eq!(keepalives(&out), vec![2], "reset within the window waits for a touch");
    rig.ctaphid_send(cid, CTAPHID_CANCEL, &[]);
    rig.advance(11_000);
    assert_eq!(rig.cbor(cid, &RESET), vec![CTAP2_ERR_NOT_ALLOWED]);
    rig.bus(BusEvent::PowerCycle);
    let cid = rig.ctaphid_init();
    let out = rig.ctaphid_send(cid, CTAPHID_CBOR, &RESET);
    assert_eq!(keepalives(&out), vec![2]);
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
/// device reports the framer's deadline and a Tick at it delivers the error.
#[test]
fn ctaphid_message_timeout_is_a_device_deadline() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    let packets = Rig::ctaphid_packets(cid, CTAPHID_PING, &[0x55; 100]);
    rig.input(Input::FidoReport(&packets[0]));
    let deadline = rig.dev.next_deadline().unwrap();
    assert_eq!(deadline, rig.now + lk_ctaphid::TRANSACTION_TIMEOUT_MS);
    let out = rig.advance(deadline - rig.now);
    assert_eq!(responses(&out), vec![(CTAPHID_ERROR, vec![0x05])]);
}
