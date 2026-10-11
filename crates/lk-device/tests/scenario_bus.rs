//! End-to-end bus scenarios: a USB reset while a FIDO request waits, and a power cycle
//! clearing PIN tokens and the soft PIN block (`docs/DESIGN.md` §5 power/reset meaning).

#![allow(clippy::unwrap_used)]

mod common;

use common::ctap::{self, PinAuth, PinProtocol2, perm, status};
use common::*;
use lk_device::{BusEvent, Output};
use lk_testkit::SeededEntropy;

const RP: &str = "bus.example";

fn agree(rig: &mut Rig, cid: u32, entropy: &mut SeededEntropy) -> PinProtocol2 {
    PinProtocol2::from_key_agreement(&rig.cbor(cid, &PinProtocol2::key_agreement_request()), entropy)
}

fn token_response(rig: &mut Rig, cid: u32, pin: &str, entropy: &mut SeededEntropy) -> (PinProtocol2, Vec<u8>) {
    let pp = agree(rig, cid, entropy);
    let response = rig.cbor(cid, &pp.token_request(pin, perm::MC, Some(RP)));
    (pp, response)
}

fn retries(rig: &mut Rig, cid: u32) -> u64 {
    ctap::get(&ctap::ok_value(&rig.cbor(cid, &ctap::pin_retries_request())), 3).as_u64().unwrap()
}

fn remaining(rig: &mut Rig, cid: u32) -> u64 {
    let info = ctap::ok_value(&rig.cbor(cid, &ctap::request(ctap::cmd::GET_INFO, None)));
    ctap::get(&info, 0x14).as_u64().unwrap()
}

/// `docs/CONTRACTS.md` "Phase 0", lk-ctaphid (`reset()` emits no events; lk-device drops
/// the pending operation itself) and `docs/DESIGN.md` §5 ("`Reset` only resets the USB
/// level"): a bus reset during a pending MakeCredential ends it silently (indicator off,
/// no more keepalives, no reply on the next touch, nothing created); the old channel is
/// gone (ERR_INVALID_CHANNEL, CTAP 2.1 §11.2.4), and the PIN token survives because the
/// authenticator did not lose power.
#[test]
fn usb_reset_during_a_pending_make_credential() {
    let mut rig = Rig::new();
    let mut entropy = SeededEntropy::new(21);
    let cid = rig.ctaphid_init();
    let pp = agree(&mut rig, cid, &mut entropy);
    assert_eq!(rig.cbor(cid, &pp.set_pin("2580")), vec![status::OK]);
    let (pp, response) = token_response(&mut rig, cid, "2580", &mut entropy);
    let token = pp.token(&response);

    let request = ctap::make_credential(&[3; 32], RP, b"user", true, &PinAuth::Token(token.clone()));
    let out = rig.ctaphid_send(cid, CTAPHID_CBOR, &request);
    // Waiting, with no KEEPALIVE at once (docs/MEASUREMENT.md, probe
    // selection-keepalive-cancel; an immediate one was expected before the measurement).
    assert_eq!((keepalives(&out), indicators(&out)), (vec![], vec![true]));
    rig.run_until(rig.now + 450);
    let out = rig.bus(BusEvent::Reset);
    assert_eq!(out, vec![Output::PresenceIndicator(false)]);
    assert!(rig.run_until(rig.now + 1_000).is_empty(), "no keepalives after the reset");
    assert!(rig.tap().iter().all(|o| !matches!(o, Output::FidoReport(_))), "no late reply");
    assert_eq!(rig.ctaphid(cid, CTAPHID_PING, b"old"), (CTAPHID_ERROR, vec![0x0B]));

    let cid = rig.ctaphid_init();
    assert_eq!(remaining(&mut rig, cid), 100, "nothing was created");
    let (response, _) = rig.cbor_touch(cid, &request, 100);
    assert_eq!(response[0], status::OK, "the token survives a USB reset");
    assert_eq!(remaining(&mut rig, cid), 99);
}

/// CTAP 2.1 §6.5.5.7.2 ("If the authenticator sees 3 consecutive mismatches, it returns
/// CTAP2_ERR_PIN_AUTH_BLOCKED, indicating that power cycling is needed") and
/// `docs/DESIGN.md` §5 ("`PowerCycle` drops all volatile state: PIN tokens ..."): three
/// wrong PINs soft-block the PIN (even the right one is refused), a power cycle lifts
/// the block with the retry counter still spent (5 of 8), the token issued before the
/// power cycle is rejected, and a right PIN restores the counter.
#[test]
fn power_cycle_clears_pin_tokens_and_soft_blocks() {
    let mut rig = Rig::new();
    let mut entropy = SeededEntropy::new(22);
    let cid = rig.ctaphid_init();
    let pp = agree(&mut rig, cid, &mut entropy);
    assert_eq!(rig.cbor(cid, &pp.set_pin("2580")), vec![status::OK]);
    let (pp, response) = token_response(&mut rig, cid, "2580", &mut entropy);
    let token = pp.token(&response);
    let request = ctap::make_credential(&[4; 32], RP, b"user", true, &PinAuth::Token(token.clone()));
    let (response, _) = rig.cbor_touch(cid, &request, 100);
    assert_eq!(response[0], status::OK, "the token works before the power cycle");

    for expected in [status::PIN_INVALID, status::PIN_INVALID, status::PIN_AUTH_BLOCKED] {
        let (_, response) = token_response(&mut rig, cid, "0000", &mut entropy);
        assert_eq!(response, vec![expected]);
    }
    let (_, response) = token_response(&mut rig, cid, "2580", &mut entropy);
    assert_eq!(response, vec![status::PIN_AUTH_BLOCKED], "soft block until a power cycle");
    assert_eq!(retries(&mut rig, cid), 5);

    rig.now += 10_000;
    rig.bus(BusEvent::PowerCycle);
    let cid = rig.ctaphid_init();
    let request = ctap::make_credential(&[5; 32], RP, b"user2", true, &PinAuth::Token(token));
    assert_eq!(rig.cbor(cid, &request), vec![status::PIN_AUTH_INVALID], "old token rejected");
    assert_eq!(retries(&mut rig, cid), 5, "the counter is persistent");
    let (pp, response) = token_response(&mut rig, cid, "2580", &mut entropy);
    let fresh = pp.token(&response);
    assert_eq!(retries(&mut rig, cid), 8);
    let request = ctap::make_credential(&[5; 32], RP, b"user2", true, &PinAuth::Token(fresh));
    let (response, _) = rig.cbor_touch(cid, &request, 100);
    assert_eq!(response[0], status::OK);
}

/// `docs/DESIGN.md` §5 ("`PowerCycle` drops all volatile state") with three presence
/// requests pending at once — a FIDO MakeCredential, an OATH CALCULATE of a touch
/// credential over CCID, and an OTP HID challenge-response with `CHAL_BTN_TRIG`: the
/// power cycle ends all of them without replies (indicator off, no deadlines left, a
/// touch afterwards answers nothing and types nothing), and every interface works
/// afterwards (new CTAPHID channel, new IccPowerOn, an idle OTP status).
#[test]
fn power_cycle_ends_every_pending_request() {
    use common::iso::oath;
    use common::otp::{SlotConfig, slot};
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    rig.otp_program(slot::CONFIG2, &SlotConfig::hmac_challenge_response(&[0x31; 20], true), [0; 6]);
    rig.power_on();
    rig.select(AID_OATH);
    assert_eq!(rig.apdu(&oath::put(b"t", oath::TOTP_SHA1, 6, &[0x32; 20], true)), vec![0x90, 0x00]);

    let out = rig.ctaphid_send(cid, CTAPHID_CBOR, &ctap::make_credential(&[1; 32], RP, b"u", true, &PinAuth::None));
    assert_eq!(indicators(&out), vec![true]);
    let (seq, out) = rig.xfr(&oath::calculate(b"t", &[0; 8], true));
    assert!(data_block(&out, seq).is_none());
    rig.otp_send_frame(slot::CHAL_HMAC2, &[0x33; 64]);
    assert_eq!(rig.otp_feature()[7] & 0xE0, 0x20, "the OTP request waits too");
    rig.run_until(rig.now + 600);

    let out = rig.bus(BusEvent::PowerCycle);
    assert_eq!(out, vec![Output::PresenceIndicator(false)]);
    assert_eq!(rig.dev.next_deadline(), None, "nothing left to time");
    let out = rig.tap();
    assert!(out.is_empty(), "no late replies and no typing: {out:02X?}");

    let status = rig.otp_feature();
    assert_eq!((status[7], &status[1..4]), (0x00, &[5u8, 7, 4][..]), "idle OTP status");
    let cid = rig.ctaphid_init();
    assert_eq!(remaining(&mut rig, cid), 100);
    rig.power_on();
    rig.select(AID_OATH);
    let (seq, out) = rig.xfr(&oath::calculate(b"t", &[0; 8], true));
    assert!(data_block(&out, seq).is_none(), "the credential still needs a touch");
    let out = rig.tap();
    assert_eq!(sw(&data_block(&out, seq).unwrap()), 0x9000);
}
