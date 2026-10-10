//! Touch windows, fast trigger, explicit touch events, and Yubico OTP power-session
//! counter rules.
//!
//! Sources: Yubico documentation "Slots" (short touch 0.3–1.5 s for slot 1, long touch
//! 2.5–5 s for slot 2), `ykdef.h` `EXTFLAG_FAST_TRIG` ("use fast trig if only cfg1
//! set"), YubiKey manual "Yubico OTP" (non-volatile usage counter incremented on the
//! first OTP after power-up and when the 8-bit session counter wraps; volatile session
//! counter; 8 Hz timestamp), and `reference/BEHAVIOR_CATALOG.md` "OTP" (two-slot touch
//! windows, single-slot FAST_TRIG over a 300..5000 ms hold, touch_down/touch_up
//! model, counter exclusivity, session survives SELECT/reconnect, saturation and
//! rollover, session rollback on storage failure).

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use lk_core::{CardApplet, Host, Record, ResetKind};
use lk_otp::{Otp, OtpApplet, Press, Slot, Ticket, cmd, decode_reports, modhex_decode};

const KEY: [u8; 16] = [0x5A; 16];
const UID: [u8; 6] = [9, 8, 7, 6, 5, 4];
const RFC4226_SECRET: &[u8; 20] = b"12345678901234567890";

fn otp_config() -> Vec<u8> {
    yubico_otp_config(&[], &UID, &KEY, &[0; 6])
}

fn ticket_of(text: &str) -> Ticket {
    let encrypted = modhex_decode(&text[..32]).unwrap();
    let plain = lk_crypto::aes_ecb_decrypt_block(&KEY, &encrypted).unwrap();
    Ticket::from_bytes(&plain).expect("valid CRC")
}

fn two_slot_device() -> Device {
    let mut d = Device::new();
    d.write(cmd::CONFIG1, &write_payload(&otp_config(), None))
        .unwrap();
    d.write(
        cmd::CONFIG2,
        &write_payload(&hotp_config(RFC4226_SECRET, false, 0, &[], 0), None),
    )
    .unwrap();
    d
}

fn touch(d: &mut Device, held_ms: u64) -> (String, String) {
    let down = decode_reports(&d.otp.touch_down(&mut d.host));
    d.host.advance(held_ms);
    let up = decode_reports(&d.otp.touch_up(&mut d.host));
    (down, up)
}

#[test]
fn two_slot_touch_windows_select_on_release() {
    let mut d = two_slot_device();
    // Below 0.3 s, between the windows and above 5 s: nothing.
    for held in [100, 299, 1501, 2000, 2499, 5001, 8000] {
        assert_eq!(
            touch(&mut d, held),
            (String::new(), String::new()),
            "held {held} ms"
        );
    }
    // Short window: slot 1 on release.
    let (down, up) = touch(&mut d, 300);
    assert_eq!(down, "");
    assert_eq!(up.len(), 33);
    let (_, up) = touch(&mut d, 1500);
    assert_eq!(up.len(), 33);
    // Long window: slot 2 (HOTP) on release.
    assert_eq!(touch(&mut d, 2500).1, "755224\n");
    assert_eq!(touch(&mut d, 5000).1, "287082\n");
}

#[test]
fn single_slot1_fast_trigger_at_contact() {
    let mut d = Device::new();
    // A configuration without EXTFLAG_FAST_TRIG still fast-triggers when alone.
    let config = config_bytes(&[], &UID, &KEY, &[0; 6], 0x04, ENTER, 0);
    d.write(cmd::CONFIG1, &write_payload(&config, None))
        .unwrap();
    let down = d.otp.touch_down(&mut d.host);
    assert_eq!(decode_reports(&down).len(), 33, "output at contact");
    assert!(d.otp.is_touch_active());
    d.host.advance(3_000);
    assert!(
        d.otp.touch_up(&mut d.host).is_empty(),
        "no second output on release"
    );
    // The legacy completed-press API: both presses map to slot 1.
    assert_eq!(d.button(Press::Short).len(), 33);
    assert_eq!(d.button(Press::Long).len(), 33);
    // Exactly three tickets: session counters 0, 1, 2 with one usage counter.
    assert_eq!(d.otp.counter(Slot::One), Some(1));
    assert_eq!(ticket_of(&d.button(Press::Short)).session_counter, 3);
}

#[test]
fn slot2_alone_needs_a_long_touch() {
    let mut d = Device::new();
    d.write(
        cmd::CONFIG2,
        &write_payload(&hotp_config(RFC4226_SECRET, false, 0, &[], 0), None),
    )
    .unwrap();
    assert_eq!(d.otp.touch_down(&mut d.host), Vec::<[u8; 8]>::new());
    d.host.advance(800);
    assert!(d.otp.touch_up(&mut d.host).is_empty());
    assert_eq!(d.button(Press::Short), "");
    assert_eq!(d.button(Press::Long), "755224\n");
}

#[test]
fn legacy_button_is_rejected_during_an_active_touch() {
    let mut d = two_slot_device();
    d.otp.touch_down(&mut d.host);
    assert_eq!(d.button(Press::Short), "");
    assert_eq!(d.button(Press::Long), "");
    // A second touch_down while touching is ignored (no duplicate).
    assert!(d.otp.touch_down(&mut d.host).is_empty());
    d.host.advance(600);
    let up = decode_reports(&d.otp.touch_up(&mut d.host));
    assert_eq!(up.len(), 33);
    // Only one ticket consumed: session counter 0, usage counter 1.
    let t = ticket_of(&up);
    assert_eq!((t.use_counter, t.session_counter), (1, 0));
    assert!(
        d.otp.touch_up(&mut d.host).is_empty(),
        "release without touch"
    );
}

#[test]
fn session_survives_select_card_power_off_and_usb_reset() {
    let mut host = lk_testkit::TestHost::new();
    let mut applet = OtpApplet::new(None, &mut host);
    let config = write_payload(&otp_config(), None);
    let mut apdu = vec![0x00, 0x01, cmd::CONFIG1, 0x00, config.len() as u8];
    apdu.extend_from_slice(&config);
    applet.process(&apdu, &mut host);
    let t1 = ticket_of(&decode_reports(
        &applet.otp_mut().button(Press::Short, &mut host),
    ));
    applet.deselect();
    applet.select(
        &[
            0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01,
        ],
        &mut host,
    );
    applet.reset(ResetKind::CardPowerOff);
    applet.reset(ResetKind::UsbReset);
    let t2 = ticket_of(&decode_reports(
        &applet.otp_mut().button(Press::Short, &mut host),
    ));
    assert_eq!((t1.use_counter, t1.session_counter), (1, 0));
    assert_eq!((t2.use_counter, t2.session_counter), (1, 1));
    // Power cycle: a new session with the next usage counter.
    applet.reset(ResetKind::PowerCycle);
    let t3 = ticket_of(&decode_reports(
        &applet.otp_mut().button(Press::Short, &mut host),
    ));
    assert_eq!((t3.use_counter, t3.session_counter), (2, 0));
    // A restart from storage is a power cycle too.
    let mut otp = Otp::new(host.persisted(Record::Otp).as_deref(), &mut host);
    let t4 = ticket_of(&decode_reports(&otp.button(Press::Short, &mut host)));
    assert_eq!((t4.use_counter, t4.session_counter), (3, 0));
}

#[test]
fn session_counter_rollover_increments_usage_counter() {
    let mut d = Device::new();
    d.write(cmd::CONFIG1, &write_payload(&otp_config(), None))
        .unwrap();
    for expected in 0..=255u8 {
        assert_eq!(ticket_of(&d.button(Press::Short)).session_counter, expected);
    }
    let t = ticket_of(&d.button(Press::Short));
    assert_eq!((t.use_counter, t.session_counter), (2, 0));
    assert_eq!(d.otp.counter(Slot::One), Some(2));
}

#[test]
fn usage_counter_saturates() {
    // A record in the documented format (state.rs): slot 1 configuration and a usage
    // counter of 0x7FFE.
    let mut host = lk_testkit::TestHost::new();
    let mut record = vec![0x01];
    record.extend(lk_codec::tlv::encode(0x03, &otp_config()));
    record.extend(lk_codec::tlv::encode(0x05, &0x7FFEu32.to_be_bytes()));
    let mut otp = Otp::new(Some(&record), &mut host);
    assert!(otp.is_configured(Slot::One));
    let t = ticket_of(&decode_reports(&otp.button(Press::Short, &mut host)));
    assert_eq!(t.use_counter, 0x7FFF);
    otp.reset(ResetKind::PowerCycle);
    let t = ticket_of(&decode_reports(&otp.button(Press::Short, &mut host)));
    assert_eq!((t.use_counter, t.session_counter), (0x7FFF, 0));
    assert_eq!(otp.counter(Slot::One), Some(0x7FFF));
}

#[test]
fn storage_failure_rolls_the_session_back() {
    let mut d = Device::new();
    d.write(cmd::CONFIG1, &write_payload(&otp_config(), None))
        .unwrap();
    d.host.fail_next_saves(1);
    assert_eq!(d.button(Press::Short), "");
    assert_eq!(d.otp.counter(Slot::One), Some(0));
    let t = ticket_of(&d.button(Press::Short));
    assert_eq!((t.use_counter, t.session_counter), (1, 0));
    // A rejected configuration write keeps the running session.
    d.host.fail_next_saves(1);
    assert!(
        d.write(cmd::CONFIG1, &write_payload(&otp_config(), None))
            .is_err()
    );
    let t = ticket_of(&d.button(Press::Short));
    assert_eq!((t.use_counter, t.session_counter), (1, 1));
    // A committed rewrite starts a new configuration and session.
    d.write(cmd::CONFIG1, &write_payload(&otp_config(), None))
        .unwrap();
    let t = ticket_of(&d.button(Press::Short));
    assert_eq!((t.use_counter, t.session_counter), (1, 0));
}

#[test]
fn challenge_response_touch_does_not_go_to_keyboard() {
    // A CR slot needing touch: the HID request waits; the keyboard path stays silent.
    let mut d = Device::new();
    d.write(
        cmd::CONFIG2,
        &write_payload(&hmac_config(&[3; 20], true, true), None),
    )
    .unwrap();
    assert_eq!(
        d.send_frame(cmd::CHAL_HMAC2, &pad_challenge(b"abc")),
        lk_core::Outcome::NeedTouch { timeout_ms: 15_000 }
    );
    assert_eq!(d.button(Press::Long), "");
    d.hid.touch_resolved(true, &mut d.otp, &mut d.host);
    let mut data = Vec::new();
    for _ in 0..4 {
        data.extend_from_slice(&d.get()[..7]);
    }
    assert_eq!(data[..20], hmac_sha1(&[3; 20], b"abc"));
    // The management timeout is used when a bridge is present.
    d.reset_state();
    d.mgmt = Some(FakeMgmt {
        timeout_s: 30,
        ..FakeMgmt::default()
    });
    assert_eq!(
        d.send_frame(cmd::CHAL_HMAC2, &pad_challenge(b"abc")),
        lk_core::Outcome::NeedTouch { timeout_ms: 30_000 }
    );
}

#[test]
fn pending_challenge_is_bound_to_its_configuration() {
    let mut d = Device::new();
    d.write(
        cmd::CONFIG1,
        &write_payload(&hmac_config(&[3; 20], true, true), None),
    )
    .unwrap();
    d.send_frame(cmd::CHAL_HMAC1, &pad_challenge(b"abc"));
    // The slot is rewritten (e.g. over CCID) while the HID request waits.
    let mut applet = OtpApplet::from_otp(d.otp.clone());
    let config = write_payload(&hmac_config(&[4; 20], true, true), None);
    let mut apdu = vec![0x00, 0x01, cmd::CONFIG1, 0x00, config.len() as u8];
    apdu.extend_from_slice(&config);
    applet.process(&apdu, &mut d.host);
    d.otp = applet.into_otp();
    d.hid.touch_resolved(true, &mut d.otp, &mut d.host);
    assert_eq!(d.get()[7], 0, "no response computed with the new key");
}

/// Slot 1 Yubico OTP (keyboard), slot 2 HMAC-SHA1 challenge-response with
/// CHAL_BTN_TRIG.
fn keyboard_and_touch_cr_device() -> Device {
    let mut d = Device::new();
    d.write(cmd::CONFIG1, &write_payload(&otp_config(), None))
        .unwrap();
    d.write(
        cmd::CONFIG2,
        &write_payload(&hmac_config(&[3; 20], true, true), None),
    )
    .unwrap();
    d
}

/// Every way the slots can be triggered types nothing and records no contact.
fn assert_touch_belongs_to_the_challenge(d: &mut Device) {
    let attempts = d.host.persist_attempts();
    assert!(d.otp.is_challenge_waiting(d.host.now()));
    assert_eq!(d.button(Press::Short), "");
    assert_eq!(d.button(Press::Long), "");
    assert!(d.otp.touch_down(&mut d.host).is_empty());
    assert!(!d.otp.is_touch_active(), "no contact recorded");
    d.host.advance(500);
    assert!(d.otp.touch_up(&mut d.host).is_empty());
    assert_eq!(d.host.persist_attempts(), attempts, "no counter consumed");
    assert_eq!(d.otp.counter(Slot::One), Some(0));
}

#[test]
fn button_during_pending_hid_challenge_types_nothing() {
    // YubiKey manual "Challenge-response": with CHAL_BTN_TRIG the key waits for the
    // button and the press completes the response; it does not also type slot 1.
    let mut d = keyboard_and_touch_cr_device();
    assert_eq!(
        d.send_frame(cmd::CHAL_HMAC2, &pad_challenge(b"abc")),
        lk_core::Outcome::NeedTouch { timeout_ms: 15_000 }
    );
    assert_touch_belongs_to_the_challenge(&mut d);
    // lk-device gives the touch to the request.
    d.hid.touch_resolved(true, &mut d.otp, &mut d.host);
    assert!(!d.otp.is_challenge_waiting(d.host.now()));
    let response = d.read_frame(d.otp.programming_sequence()).unwrap();
    assert_eq!(response[..20], hmac_sha1(&[3; 20], b"abc"));
    // Afterwards the button types slot 1 again, starting its session normally.
    let t = ticket_of(&d.button(Press::Short));
    assert_eq!((t.use_counter, t.session_counter), (1, 0));
}

#[test]
fn touch_that_began_before_the_challenge_types_nothing_on_release() {
    let mut d = keyboard_and_touch_cr_device();
    assert!(d.otp.touch_down(&mut d.host).is_empty());
    d.send_frame(cmd::CHAL_HMAC2, &pad_challenge(b"abc"));
    d.host.advance(600);
    assert!(d.otp.touch_up(&mut d.host).is_empty());
    assert_eq!(d.otp.counter(Slot::One), Some(0));
}

#[test]
fn ended_waits_free_the_button() {
    let mut d = keyboard_and_touch_cr_device();
    // yubikit's abort (reset write) ends the wait.
    d.send_frame(cmd::CHAL_HMAC2, &pad_challenge(b"abc"));
    d.reset_state();
    assert!(!d.otp.is_challenge_waiting(d.host.now()));
    assert_eq!(d.button(Press::Short).len(), 33);
    // A timeout resolution ends it.
    d.send_frame(cmd::CHAL_HMAC2, &pad_challenge(b"abc"));
    assert_eq!(d.button(Press::Short), "");
    d.hid.touch_resolved(false, &mut d.otp, &mut d.host);
    assert_eq!(d.button(Press::Short).len(), 33);
    // A USB reset ends it (lk-device resets both the framer and the shared slots).
    d.send_frame(cmd::CHAL_HMAC2, &pad_challenge(b"abc"));
    d.hid.reset(ResetKind::UsbReset);
    d.otp.reset(ResetKind::UsbReset);
    assert_eq!(d.button(Press::Short).len(), 33);
    // An unresolved wait stops owning the touch once its deadline has passed.
    d.send_frame(cmd::CHAL_HMAC2, &pad_challenge(b"abc"));
    d.host.advance(14_999);
    assert_eq!(d.button(Press::Short), "");
    d.host.advance(1);
    assert_eq!(d.button(Press::Short).len(), 33);
}

#[test]
fn button_during_pending_ccid_challenge_types_nothing() {
    let mut host = lk_testkit::TestHost::new();
    let mut applet = OtpApplet::new(None, &mut host);
    for (p1, config) in [
        (cmd::CONFIG1, otp_config()),
        (cmd::CONFIG2, hmac_config(&[3; 20], true, true)),
    ] {
        let payload = write_payload(&config, None);
        let mut apdu = vec![0x00, 0x01, p1, 0x00, payload.len() as u8];
        apdu.extend_from_slice(&payload);
        applet.process(&apdu, &mut host);
    }
    let challenge = [&[0x00, 0x01, cmd::CHAL_HMAC2, 0x00, 0x03][..], b"abc"].concat();
    let pending = |applet: &mut OtpApplet, host: &mut lk_testkit::TestHost| {
        assert_eq!(
            applet.process(&challenge, host),
            lk_core::Outcome::NeedTouch { timeout_ms: 15_000 }
        );
        assert!(applet.otp_mut().button(Press::Short, host).is_empty());
        assert!(applet.otp_mut().touch_down(host).is_empty());
        assert!(!applet.otp().is_touch_active());
    };
    pending(&mut applet, &mut host);
    let r = applet.touch_resolved(true, &mut host);
    // The short APDU is zero-padded and LT64 strips the padding again.
    assert_eq!(r[..20], hmac_sha1(&[3; 20], b"abc")[..]);
    assert_eq!(applet.otp_mut().button(Press::Short, &mut host).len(), 66);
    // Deselect, card power-off and a new command each end the CCID wait.
    pending(&mut applet, &mut host);
    applet.deselect();
    assert_eq!(applet.otp_mut().button(Press::Short, &mut host).len(), 66);
    pending(&mut applet, &mut host);
    applet.reset(ResetKind::CardPowerOff);
    assert_eq!(applet.otp_mut().button(Press::Short, &mut host).len(), 66);
    pending(&mut applet, &mut host);
    applet.process(&[0x00, 0x01, cmd::DEVICE_SERIAL, 0x00], &mut host);
    assert_eq!(applet.otp_mut().button(Press::Short, &mut host).len(), 66);
}
