//! Touch arbitration across interfaces and the OTP HID interface with its button.

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use lk_device::Input;
use lk_otp::{SlotConfig, cfg, decode_reports, ext, tkt};

const OTP_KEY: [u8; 16] = [0x5A; 16];
const RFC4226_SECRET: &[u8; 20] = b"12345678901234567890";
const HMAC_KEY: [u8; 20] = [0x0B; 20];

/// Slot command numbers (Yubico `ykdef.h` `SLOT_*`).
const CONFIG1: u8 = 0x01;
const CONFIG2: u8 = 0x03;
const CHAL_HMAC2: u8 = 0x38;

/// The slot write payload `config(52) || access code(6) || 0(6)` (ykpers
/// `yk_write_command`).
fn payload(config: SlotConfig) -> [u8; 64] {
    let mut payload = [0u8; 64];
    payload[..52].copy_from_slice(&config.to_bytes());
    payload
}

fn config(uid: [u8; 6], key: [u8; 16], ext_flags: u8, tkt_flags: u8, cfg_flags: u8) -> SlotConfig {
    SlotConfig {
        fixed: [0; 16],
        uid,
        key,
        acc_code: [0; 6],
        fixed_size: 0,
        ext_flags,
        tkt_flags,
        cfg_flags,
        rfu: [0; 2],
    }
}

/// A Yubico OTP slot typing 32 modhex characters and Enter.
fn yubico_otp() -> SlotConfig {
    config([9, 8, 7, 6, 5, 4], OTP_KEY, ext::SERIAL_API_VISIBLE, tkt::APPEND_CR, 0)
}

/// An OATH-HOTP slot with the RFC 4226 Appendix D secret (key in `key || uid[..4]`).
fn hotp() -> SlotConfig {
    let key: [u8; 16] = RFC4226_SECRET[..16].try_into().unwrap();
    let mut uid = [0u8; 6];
    uid[..4].copy_from_slice(&RFC4226_SECRET[16..]);
    config(uid, key, 0, tkt::OATH_HOTP | tkt::APPEND_CR, 0)
}

/// HMAC-SHA1 challenge-response, LT64, waiting for the button (`CHAL_BTN_TRIG`).
fn hmac_with_button() -> SlotConfig {
    let key: [u8; 16] = HMAC_KEY[..16].try_into().unwrap();
    let mut uid = [0u8; 6];
    uid[..4].copy_from_slice(&HMAC_KEY[16..]);
    config(uid, key, 0, tkt::CHAL_RESP, cfg::CHAL_HMAC | cfg::HMAC_LT64 | cfg::CHAL_BTN_TRIG)
}

/// Hold the sensor for `held` ms and return the text typed at contact and at release.
fn press(rig: &mut Rig, held: u64) -> (String, String) {
    let down = decode_reports(&keyboard(&rig.touch_down()));
    rig.advance(held);
    let up = decode_reports(&keyboard(&rig.touch_up()));
    (down, up)
}

/// Catalog OTP "documented short/long hold release windows" (Yubico "Slots": short
/// touch 0.3–1.5 s → slot 1, long touch 2.5–5 s → slot 2) through the device's touch
/// input, with no presence request pending.
#[test]
fn button_windows_select_the_slot_on_release() {
    let mut rig = Rig::new();
    rig.otp_write(CONFIG1, &payload(yubico_otp()));
    rig.otp_write(CONFIG2, &payload(hotp()));
    let (down, up) = press(&mut rig, 500);
    assert_eq!(down, "");
    assert_eq!(up.len(), 33, "Yubico OTP and Enter: {up:?}");
    // RFC 4226 Appendix D, counts 0 and 1.
    assert_eq!(press(&mut rig, 3_000), (String::new(), "755224\n".to_string()));
    assert_eq!(press(&mut rig, 2_000), (String::new(), String::new()), "between the windows");
    assert_eq!(press(&mut rig, 6_000), (String::new(), String::new()), "beyond the long window");
    assert_eq!(press(&mut rig, 2_500).1, "287082\n");
}

/// Catalog OTP: "private touch_down/touch_up events return single-slot 1 FAST_TRIG
/// reports at modeled contact".
#[test]
fn single_slot_types_at_contact() {
    let mut rig = Rig::new();
    rig.otp_write(CONFIG1, &payload(yubico_otp()));
    let (down, up) = press(&mut rig, 1_000);
    assert_eq!(down.len(), 33);
    assert_eq!(up, "");
}

/// OTP challenge-response with `CHAL_BTN_TRIG` (YubiKey manual "Challenge-response"):
/// the HID request is a presence request; the touch completes it and types nothing;
/// while waiting the status report carries `RESP_TIMEOUT_WAIT_FLAG` (`ykdef.h`).
#[test]
fn hid_challenge_response_waits_for_touch() {
    let mut rig = Rig::new();
    rig.otp_write(CONFIG2, &payload(hmac_with_button()));
    let mut challenge = [0u8; 64];
    challenge[..3].copy_from_slice(b"abc");
    let out = rig.otp_write(CHAL_HMAC2, &challenge);
    assert_eq!(indicators(&out), vec![true]);
    let waiting = rig.otp_read();
    assert_eq!(waiting[7] & 0xE0, 0x20, "timeout-wait flag: {waiting:02X?}");
    assert_eq!(waiting[7] & 0x1F, 15, "seconds left (15 s default)");
    let out = rig.tap();
    assert_eq!(indicators(&out), vec![false]);
    assert!(keyboard(&out).is_empty());
    let mut response = Vec::new();
    for seq in 0..4u8 {
        let report = rig.otp_read();
        assert_eq!(report[7], 0x40 | seq);
        response.extend_from_slice(&report[..7]);
    }
    assert_eq!(&response[..20], &lk_crypto::hmac_sha1(&HMAC_KEY, b"abc"));
}

/// The challenge-response wait ends after the challenge-response timeout (Management
/// default 15 s) without a response.
#[test]
fn hid_challenge_response_times_out() {
    let mut rig = Rig::new();
    rig.otp_write(CONFIG2, &payload(hmac_with_button()));
    rig.otp_write(CHAL_HMAC2, &[0x01; 64]);
    assert_eq!(rig.dev.next_deadline(), Some(rig.now + 15_000));
    let out = rig.advance(15_000);
    assert_eq!(indicators(&out), vec![false]);
    let status = rig.otp_read();
    assert_eq!(status[7] & 0x60, 0, "neither waiting nor holding a response: {status:02X?}");
    assert!(keyboard(&rig.tap()).is_empty());
}

/// A reset write (`ykdef.h` `DUMMY_REPORT_WRITE`) aborts the wait; the device drops its
/// presence request (`OtpHid::is_waiting_for_touch`).
#[test]
fn reset_write_ends_the_hid_wait() {
    let mut rig = Rig::new();
    rig.otp_write(CONFIG2, &payload(hmac_with_button()));
    rig.otp_write(CHAL_HMAC2, &[0x01; 64]);
    let out = rig.input(Input::OtpSetFeature(&[0, 0, 0, 0, 0, 0, 0, 0x8F]));
    assert_eq!(indicators(&out), vec![false]);
}

/// docs/DESIGN.md §5: one touch satisfies only the earliest waiting request; the next
/// touch goes to the next one.
#[test]
fn earliest_request_wins_across_interfaces() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    rig.power_on();
    rig.select(AID_OATH);
    rig.apdu(&oath_put(b"t", true));
    let out = rig.ctaphid_send(cid, CTAPHID_CBOR, &[0x0B]);
    assert_eq!(indicators(&out), vec![true]);
    rig.now += 10;
    let (seq, out) = rig.xfr(&oath_calculate(b"t"));
    assert!(indicators(&out).is_empty(), "already lit");
    let out = rig.tap();
    assert_eq!(responses(&out), vec![(CTAPHID_CBOR, vec![0x00])]);
    assert!(data_block(&out, seq).is_none(), "the card command still waits");
    assert!(indicators(&out).is_empty(), "still lit");
    let out = rig.tap();
    assert_eq!(sw(&data_block(&out, seq).unwrap()), 0x9000);
    assert_eq!(indicators(&out), vec![false]);
}

/// The same with the card command first.
#[test]
fn earliest_request_wins_card_first() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    rig.power_on();
    rig.select(AID_OATH);
    rig.apdu(&oath_put(b"t", true));
    let (seq, _) = rig.xfr(&oath_calculate(b"t"));
    rig.now += 10;
    rig.ctaphid_send(cid, CTAPHID_CBOR, &[0x0B]);
    let out = rig.tap();
    assert_eq!(sw(&data_block(&out, seq).unwrap()), 0x9000);
    assert!(responses(&out).is_empty());
    let out = rig.tap();
    assert_eq!(responses(&out), vec![(CTAPHID_CBOR, vec![0x00])]);
}

/// A touch belongs to what it started as (`presence.rs`): a press that began with
/// nothing pending is an OTP press; a request that starts during the hold waits for
/// the next touch.
#[test]
fn hold_that_began_before_a_request_does_not_satisfy_it() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    rig.touch_down();
    rig.ctaphid_send(cid, CTAPHID_CBOR, &[0x0B]);
    rig.now += 500;
    let out = rig.touch_up();
    assert!(responses(&out).is_empty());
    let out = rig.tap();
    assert_eq!(responses(&out), vec![(CTAPHID_CBOR, vec![0x00])]);
}

/// With nothing pending and no slot configured, a press produces nothing.
#[test]
fn idle_press_without_slots_is_silent() {
    let mut rig = Rig::new();
    assert!(rig.tap().is_empty());
    // A second Down without Up is ignored, as is an Up without Down.
    assert!(rig.touch_down().is_empty());
    assert!(rig.touch_down().is_empty());
    assert!(rig.touch_up().is_empty());
    assert!(rig.touch_up().is_empty());
}

/// OTP HID status report (`ykdef.h` `STATUS`): version, programming sequence,
/// touchLevel; the sequence advances with each slot write.
#[test]
fn otp_status_report() {
    let mut rig = Rig::new();
    assert_eq!(rig.otp_read(), [0, 5, 7, 4, 0, 0, 0, 0]);
    rig.otp_write(CONFIG1, &payload(yubico_otp()));
    let status = rig.otp_read();
    assert_eq!(&status[..5], &[0, 5, 7, 4, 1]);
    assert_eq!(status[5] & 0x05, 0x05, "CONFIG1_VALID | CONFIG1_TOUCH");
}

/// Catalog Management "CCID and OTP HID device information": OTP slot `0x13` reads the
/// DeviceInfo page through the bridge (`len || TLVs`, CRC appended by lk-otp).
#[test]
fn otp_hid_reads_device_info_through_the_bridge() {
    let mut rig = Rig::new();
    rig.otp_write(0x13, &[0u8; 64]);
    let first = rig.otp_read();
    assert_eq!(first[7], 0x40, "response pending, chunk 0");
    let len = usize::from(first[0]);
    let chunks = (len + 1 + 2).div_ceil(7);
    let mut data = first[..7].to_vec();
    for _ in 1..chunks {
        data.extend_from_slice(&rig.otp_read()[..7]);
    }
    data.truncate(len + 3);
    assert!(lk_otp::crc_ok(&data), "OTP response CRC (yubikit check_crc)");
    let tlvs = lk_codec::tlv::parse_all(&data[1..=len]).unwrap();
    assert_eq!(lk_codec::tlv::find(&tlvs, 0x02).unwrap().value, SERIAL.to_be_bytes());
}

/// A bus reset discards a waiting OTP challenge-response (catalog appendix A: "USB
/// reset discards queued touch reports").
#[test]
fn usb_reset_ends_the_hid_wait() {
    let mut rig = Rig::new();
    rig.otp_write(CONFIG2, &payload(hmac_with_button()));
    rig.otp_write(CHAL_HMAC2, &[0x01; 64]);
    let out = rig.bus(lk_device::BusEvent::Reset);
    assert_eq!(indicators(&out), vec![false]);
    assert!(keyboard(&rig.tap()).is_empty());
}

/// Catalog appendix A `Linux_native`: "real CCID terminal wait concurrent FIDO
/// GetInfo/PING, cancellation without HOTP mutation and fresh approval": FIDO keeps
/// working while a card command waits for a touch; the touch then goes to the card.
#[test]
fn fido_works_while_a_card_command_waits() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    rig.power_on();
    rig.select(AID_OATH);
    rig.apdu(&oath_put(b"t", true));
    let (seq, _) = rig.xfr(&oath_calculate(b"t"));
    assert_eq!(rig.cbor(cid, &[0x04])[0], 0x00);
    assert_eq!(rig.ctaphid(cid, CTAPHID_PING, b"p"), (CTAPHID_PING, b"p".to_vec()));
    let out = rig.tap();
    assert_eq!(sw(&data_block(&out, seq).unwrap()), 0x9000);
}

/// Catalog appendix A `Linux_native`: "native OTP feature ioctls ... with shared CCID
/// state": one `Otp` serves the HID interface and the CCID OTP application (lk-otp
/// `OtpApplet::otp_mut`), so a slot written over HID shows in the CCID status.
#[test]
fn otp_state_is_shared_between_hid_and_ccid() {
    let mut rig = Rig::new();
    rig.otp_write(CONFIG1, &payload(yubico_otp()));
    rig.power_on();
    let status = rig.select(AID_OTP);
    assert_eq!(sw(&status), 0x9000);
    assert_eq!(&status[..4], &[5, 7, 4, 1], "version and programming sequence");
    assert_eq!(status[4] & 0x01, 0x01, "CONFIG1_VALID");
}
