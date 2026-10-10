//! End-to-end OTP scenarios: a host written from Yubico's `ykdef.h` and the yubikit OTP
//! host protocol programs the slots through 8-byte feature reports (frame CRC, write
//! readiness, skipped zero chunks, programming sequence), presses the sensor, decodes the
//! keyboard reports, and decrypts and checks every Yubico OTP.

#![allow(clippy::unwrap_used)]

mod common;

use common::otp::{self, SlotConfig, Ticket, decrypt_otp, keyboard_text, modhex_encode, slot};
use common::*;
use lk_device::{BusEvent, Input};

const PUBLIC_1: [u8; 6] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
const PRIVATE_1: [u8; 6] = [0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6];
const KEY_1: [u8; 16] = *b"slot-one-aes-key";
const PUBLIC_2: [u8; 6] = [0x11, 0x12, 0x13, 0x14, 0x15, 0x16];
const PRIVATE_2: [u8; 6] = [0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6];
const KEY_2: [u8; 16] = *b"slot-two-aes-key";
const HMAC_SECRET: [u8; 20] = *b"hmac-sha1-secret-20b";
const NO_ACCESS: [u8; 6] = [0; 6];

/// Hold the sensor for `held` ms (the program's timer loop running meanwhile) and return
/// everything typed.
fn press(rig: &mut Rig, held: u64) -> String {
    press_at(rig, held).0
}

/// [`press`], also returning when the first keyboard report came (at contact or at
/// release).
fn press_at(rig: &mut Rig, held: u64) -> (String, u64) {
    let mut first = None;
    let mut reports = keyboard(&rig.touch_down());
    if !reports.is_empty() {
        first = Some(rig.now);
    }
    for (at, output) in rig.run_until(rig.now + held) {
        if let lk_device::Output::OtpKeyboard(report) = output {
            first.get_or_insert(at);
            reports.push(report);
        }
    }
    let up = keyboard(&rig.touch_up());
    if !up.is_empty() {
        first.get_or_insert(rig.now);
    }
    reports.extend(up);
    (keyboard_text(&reports), first.unwrap_or(rig.now))
}

/// A typed Yubico OTP: the modhex public ID, 32 modhex characters, then ENTER
/// (`TKTFLAG_APPEND_CR`); returns the decrypted ticket.
fn typed_ticket(text: &str, public: &[u8], key: &[u8; 16]) -> Ticket {
    let line = text.strip_suffix('\n').unwrap_or_else(|| panic!("no ENTER after {text:?}"));
    assert!(line.starts_with(&modhex_encode(public)), "public ID prefix in {line:?}");
    assert_eq!(line.len(), 2 * public.len() + 32);
    let (id, ticket) = decrypt_otp(line, key);
    assert_eq!(id, public);
    ticket
}

/// The status report (`ykdef.h` `STATUS`): `[0, major, minor, patch, pgmSeq, touchLevel
/// lo, hi, 0]`.
fn status(rig: &mut Rig) -> (u8, u16) {
    let report = rig.otp_feature();
    assert_eq!(&report[..4], &[0, 5, 7, 4], "firmware version");
    assert_eq!(report[7], 0, "no response pending");
    (report[4], u16::from_le_bytes([report[5], report[6]]))
}

/// Yubico `ykdef.h` / YubiKey manual: slot 1 programmed as Yubico OTP and slot 2 as HMAC
/// challenge-response through HID frames (the programming sequence advancing, the touch
/// level bits `CONFIG1_VALID | CONFIG1_TOUCH` and `CONFIG2_VALID`); a short press types a
/// Yubico OTP that decrypts under the slot key with the private ID, a valid CRC, the
/// usage counter and a session counter starting at 0 and counting per press, and an
/// advancing 8 Hz timestamp; a long press goes to slot 2, which only answers challenges,
/// so it types nothing and leaves slot 1's session alone; after a power cycle the usage
/// counter grows and the session counter restarts (YubiKey manual "Yubico OTP": the
/// session counter is volatile, the usage counter non-volatile).
#[test]
fn short_press_types_a_valid_yubico_otp_and_long_press_uses_slot_two() {
    let mut rig = Rig::new();
    assert_eq!(status(&mut rig), (0, 0));
    rig.otp_program(slot::CONFIG1, &SlotConfig::yubico_otp(&PUBLIC_1, PRIVATE_1, KEY_1), NO_ACCESS);
    assert_eq!(status(&mut rig), (1, 0x01 | 0x04));
    rig.otp_program(slot::CONFIG2, &SlotConfig::hmac_challenge_response(&HMAC_SECRET, false), NO_ACCESS);
    assert_eq!(status(&mut rig), (2, 0x01 | 0x02 | 0x04));

    rig.now = 10_000;
    let (text, first_at) = press_at(&mut rig, 600);
    let first = typed_ticket(&text, &PUBLIC_1, &KEY_1);
    assert_eq!(first.uid, PRIVATE_1);
    assert_eq!(first.session_counter, 0);
    assert!(first.use_counter >= 1);

    rig.now = 12_000;
    let (text, second_at) = press_at(&mut rig, 400);
    let second = typed_ticket(&text, &PUBLIC_1, &KEY_1);
    assert_eq!((second.uid, second.use_counter, second.session_counter), (PRIVATE_1, first.use_counter, 1));
    let ticks = i64::from((second.timestamp.wrapping_sub(first.timestamp)) & 0x00FF_FFFF);
    let expected = i64::try_from((second_at - first_at) * 8 / 1000).unwrap();
    assert!((ticks - expected).abs() <= 1, "8 Hz timestamp: {ticks} ticks for {} ms", second_at - first_at);

    rig.now = 14_000;
    assert_eq!(press(&mut rig, 3_000), "", "a long press is slot 2, a challenge-response slot");
    rig.now = 20_000;
    let third = typed_ticket(&press(&mut rig, 500), &PUBLIC_1, &KEY_1);
    assert_eq!((third.use_counter, third.session_counter), (first.use_counter, 2));

    rig.bus(BusEvent::PowerCycle);
    rig.now = 30_000;
    let after = typed_ticket(&press(&mut rig, 500), &PUBLIC_1, &KEY_1);
    assert_eq!((after.use_counter, after.session_counter), (first.use_counter + 1, 0));
    assert_ne!(after.random, third.random, "the random field changes");
}

/// YubiKey manual "Slots": a short touch (0.3–1.5 s) uses slot 1 and a long touch
/// (2.5–5 s) slot 2; with two Yubico OTP slots each press types its own slot's OTP,
/// each decrypting only under its own key, with independent session counters.
#[test]
fn long_press_types_slot_two() {
    let mut rig = Rig::new();
    rig.otp_program(slot::CONFIG1, &SlotConfig::yubico_otp(&PUBLIC_1, PRIVATE_1, KEY_1), NO_ACCESS);
    rig.otp_program(slot::CONFIG2, &SlotConfig::yubico_otp(&PUBLIC_2, PRIVATE_2, KEY_2), NO_ACCESS);
    let long = typed_ticket(&press(&mut rig, 3_000), &PUBLIC_2, &KEY_2);
    assert_eq!((long.uid, long.session_counter), (PRIVATE_2, 0));
    rig.now += 1_000;
    let short = typed_ticket(&press(&mut rig, 700), &PUBLIC_1, &KEY_1);
    assert_eq!((short.uid, short.session_counter), (PRIVATE_1, 0));
    rig.now += 1_000;
    let long = typed_ticket(&press(&mut rig, 2_600), &PUBLIC_2, &KEY_2);
    assert_eq!(long.session_counter, 1);
}

/// HMAC-SHA1 challenge-response over HID (yubikit `calculate_hmac_sha1`: the challenge
/// padded to 64 bytes with a byte different from its last, `HMAC_LT64`; the response is
/// 20 bytes plus CRC read with `RESP_PENDING_FLAG` chunks). Without `CHAL_BTN_TRIG` the
/// response is ready at once and nothing asks for a touch; with it the device waits,
/// reports `RESP_TIMEOUT_WAIT_FLAG` with the seconds left (Management default 15 s), and
/// the touch completes the request without typing.
#[test]
fn hid_challenge_response_without_and_with_touch() {
    let mut rig = Rig::new();
    rig.otp_program(slot::CONFIG1, &SlotConfig::yubico_otp(&PUBLIC_1, PRIVATE_1, KEY_1), NO_ACCESS);
    rig.otp_program(slot::CONFIG2, &SlotConfig::hmac_challenge_response(&HMAC_SECRET, false), NO_ACCESS);
    let challenge: Vec<u8> = (1..=32u8).collect();
    let mut payload = [0u8; 64];
    payload[..32].copy_from_slice(&challenge);
    let expected = lk_crypto::hmac_sha1(&HMAC_SECRET, &challenge);

    let out = rig.otp_send_frame(slot::CHAL_HMAC2, &payload);
    assert!(indicators(&out).is_empty(), "no touch needed");
    assert_eq!(rig.otp_response(20), expected.to_vec());

    rig.otp_program(slot::CONFIG2, &SlotConfig::hmac_challenge_response(&HMAC_SECRET, true), NO_ACCESS);
    let start = rig.now;
    let out = rig.otp_send_frame(slot::CHAL_HMAC2, &payload);
    assert_eq!(indicators(&out), vec![true]);
    let waiting = rig.otp_feature();
    assert_eq!((waiting[7] & 0xE0, waiting[7] & 0x1F), (otp::RESP_TIMEOUT_WAIT_FLAG, 15));
    rig.run_until(start + 4_000);
    let waiting = rig.otp_feature();
    assert_eq!((waiting[7] & 0xE0, waiting[7] & 0x1F), (otp::RESP_TIMEOUT_WAIT_FLAG, 11));
    let out = rig.tap();
    assert_eq!(indicators(&out), vec![false]);
    assert!(keyboard(&out).is_empty(), "the touch belongs to the challenge");
    assert_eq!(rig.otp_response(20), expected.to_vec());
}

/// `ykdef.h` status report and yubikit `_check_status`: the programming sequence advances
/// with each accepted slot write; a frame with a bad CRC is dropped (`lk-otp` HID
/// documentation; ykpers sends `crc16(payload)`), a slot configuration with a bad
/// internal CRC is refused, and neither changes the sequence or the touch level.
#[test]
fn status_report_programming_sequence() {
    let mut rig = Rig::new();
    assert_eq!(status(&mut rig), (0, 0));
    let config = SlotConfig::yubico_otp(&PUBLIC_1, PRIVATE_1, KEY_1);

    let mut frame = [0u8; 70];
    frame[..64].copy_from_slice(&config.payload(NO_ACCESS));
    frame[64] = slot::CONFIG1;
    let bad = otp::crc16(&frame[..64]) ^ 0x0001;
    frame[65..67].copy_from_slice(&bad.to_le_bytes());
    for (seq, chunk) in frame.chunks(7).enumerate() {
        let mut report = [0u8; 8];
        report[..7].copy_from_slice(chunk);
        report[7] = 0x80 | seq as u8;
        rig.input(Input::OtpSetFeature(&report));
    }
    assert_eq!(status(&mut rig), (0, 0), "bad frame CRC");

    let mut payload = config.payload(NO_ACCESS);
    payload[51] ^= 0xFF;
    rig.otp_send_frame(slot::CONFIG1, &payload);
    assert_eq!(status(&mut rig), (0, 0), "bad configuration CRC");

    rig.otp_program(slot::CONFIG1, &config, NO_ACCESS);
    assert_eq!(status(&mut rig), (1, 0x05));
    rig.otp_program(slot::CONFIG2, &SlotConfig::yubico_otp(&PUBLIC_2, PRIVATE_2, KEY_2), NO_ACCESS);
    assert_eq!(status(&mut rig), (2, 0x0F));
    rig.otp_program(slot::SWAP, &SlotConfig::default(), NO_ACCESS);
    assert_eq!(status(&mut rig).0, 3);
    let swapped = typed_ticket(&press(&mut rig, 600), &PUBLIC_2, &KEY_2);
    assert_eq!(swapped.uid, PRIVATE_2, "slot 1 now holds the former slot 2");
}
