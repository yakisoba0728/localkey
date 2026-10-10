//! OTP modes through configured slots, checked independently of the implementation.
//!
//! Vector sources:
//! - RFC 4226 Appendix D (HOTP, secret "12345678901234567890", 6-digit values and the
//!   full 31-bit truncated values from which the 8-digit codes follow).
//! - RFC 2202 §3 (HMAC-SHA1 test cases 1, 2, 3 and 5; the cases with keys longer than
//!   20 bytes cannot be loaded into a 20-byte slot key).
//! - YubiKey manual "Yubico OTP" ticket layout, decrypted with AES-128 (FIPS 197) from
//!   lk-crypto and checked with the published CRC residue 0xF0B8.
//! - OATH Token Identifier Specification (token ID "ubhe" + 8 digits) with the
//!   `CFGFLAG_OATH_FIXED_MODHEX2` encoding from `ykdef.h`.
//! - HID Usage Tables §10 for scan codes; USB HID 1.11 Appendix B for report layout.

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use lk_otp::{
    Press, RELEASE, Slot, Ticket, cmd, crc16, decode_reports, modhex_decode, press_report,
};

const KEY: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];
const PUBLIC_ID: [u8; 6] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
const PRIVATE_ID: [u8; 6] = [0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6];
const RFC4226_SECRET: &[u8; 20] = b"12345678901234567890";

fn decrypt_ticket(modhex: &str, key: &[u8; 16]) -> Ticket {
    let encrypted = modhex_decode(modhex).unwrap();
    let plain = lk_crypto::aes_ecb_decrypt_block(key, &encrypted).unwrap();
    assert_eq!(crc16(&plain), 0xF0B8, "ticket CRC residue");
    Ticket::from_bytes(&plain).unwrap()
}

fn configure(d: &mut Device, slot: u8, config: &[u8]) {
    d.write(slot, &write_payload(config, None)).unwrap();
}

#[test]
fn yubico_otp_output_decrypts_and_validates() {
    let mut d = Device::new();
    configure(
        &mut d,
        cmd::CONFIG1,
        &yubico_otp_config(&PUBLIC_ID, &PRIVATE_ID, &KEY, &[0; 6]),
    );
    let first = d.button(Press::Short);
    // 12 modhex public ID + 32 modhex ticket + ENTER.
    assert_eq!(first.len(), 45);
    assert_eq!(&first[..12], "cbcdcecfcgch");
    assert!(first.ends_with('\n'));
    let t1 = decrypt_ticket(&first[12..44], &KEY);
    assert_eq!(t1.uid, PRIVATE_ID);
    assert_eq!(t1.use_counter, 1);
    assert_eq!(t1.session_counter, 0);
    d.host.advance(1_000);
    let t2 = decrypt_ticket(&d.button(Press::Short)[12..44], &KEY);
    assert_eq!(t2.use_counter, 1);
    assert_eq!(t2.session_counter, 1);
    // 8 Hz timestamp: one second later is eight ticks later.
    assert_eq!(t2.timestamp, (t1.timestamp + 8) & 0xFF_FFFF);
    // The usage counter was persisted before the first ticket was typed.
    assert_eq!(d.otp.counter(Slot::One), Some(1));
}

#[test]
fn hotp_rfc4226_vectors_through_a_slot() {
    let expected = [
        "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871",
        "520489",
    ];
    let mut d = Device::new();
    configure(
        &mut d,
        cmd::CONFIG1,
        &hotp_config(RFC4226_SECRET, false, 0, &[], 0),
    );
    for code in expected {
        assert_eq!(d.button(Press::Short), format!("{code}\n"));
    }
    assert_eq!(d.otp.counter(Slot::One), Some(10));
}

#[test]
fn hotp_eight_digits_and_initial_moving_factor() {
    // RFC 4226 Appendix D truncated values 1284755224 .. 645520489, last 8 digits.
    let truncated: [u32; 10] = [
        1284755224, 1094287082, 137359152, 1726969429, 1640338314, 868254676, 1918287922, 82162583,
        673399871, 645520489,
    ];
    let mut d = Device::new();
    configure(
        &mut d,
        cmd::CONFIG2,
        &hotp_config(RFC4226_SECRET, true, 0, &[], 0),
    );
    for value in truncated {
        assert_eq!(
            d.button(Press::Long),
            format!("{:08}\n", value % 100_000_000)
        );
    }
    // IMF 32: the first code is counter 32 (computed independently with RFC 4226 §5.3).
    let mut d = Device::new();
    configure(
        &mut d,
        cmd::CONFIG1,
        &hotp_config(RFC4226_SECRET, false, 32, &[], 0),
    );
    let mac = hmac_sha1(RFC4226_SECRET, &32u64.to_be_bytes());
    let off = (mac[19] & 0x0f) as usize;
    let bin = u32::from_be_bytes(mac[off..off + 4].try_into().unwrap()) & 0x7fff_ffff;
    assert_eq!(d.button(Press::Short), format!("{:06}\n", bin % 1_000_000));
}

#[test]
fn hotp_token_identifier_prefixes_the_code() {
    // "ubhe" (two modhex bytes) + BCD 00012345 with OATH_FIXED_MODHEX2.
    let mut token_id = modhex_decode("ubhe").unwrap();
    token_id.extend_from_slice(&[0x00, 0x01, 0x23, 0x45]);
    let mut d = Device::new();
    configure(
        &mut d,
        cmd::CONFIG1,
        &hotp_config(RFC4226_SECRET, false, 0, &token_id, 0x40),
    );
    assert_eq!(d.button(Press::Short), "ubhe00012345755224\n");
    // All-modhex token ID (OATH_FIXED_MODHEX).
    let mut d = Device::new();
    configure(
        &mut d,
        cmd::CONFIG1,
        &hotp_config(RFC4226_SECRET, false, 0, &token_id, 0x50),
    );
    assert_eq!(d.button(Press::Short), "ubhecccbdefg755224\n");
}

#[test]
fn hmac_sha1_rfc2202_vectors_over_hid() {
    let cases: [(&[u8], &[u8], &str); 4] = [
        (
            &[0x0b; 20],
            b"Hi There",
            "b617318655057264e28bc0b6fb378c8ef146be00",
        ),
        (
            b"Jefe",
            b"what do ya want for nothing?",
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
        ),
        (
            &[0xaa; 20],
            &[0xdd; 50],
            "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
        ),
        (
            &[0x0c; 20],
            b"Test With Truncation",
            "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04",
        ),
    ];
    for (key, data, mac) in cases {
        let mut d = Device::new();
        configure(&mut d, cmd::CONFIG2, &hmac_config(key, false, true));
        let response = d
            .read_checked(cmd::CHAL_HMAC2, &pad_challenge(data), 20)
            .unwrap();
        assert_eq!(response, hex(mac));
    }
}

#[test]
fn hmac_full_64_byte_challenge_without_lt64() {
    let mut d = Device::new();
    configure(
        &mut d,
        cmd::CONFIG1,
        &hmac_config(&[0x0b; 20], false, false),
    );
    let challenge: Vec<u8> = (0..64u8).map(|i| i.wrapping_mul(7)).collect();
    let response = d.read_checked(cmd::CHAL_HMAC1, &challenge, 20).unwrap();
    assert_eq!(response, hmac_sha1(&[0x0b; 20], &challenge));
    // Without LT64, trailing zeros are part of the message.
    let response = d
        .read_checked(cmd::CHAL_HMAC1, &pad_challenge(b"Hi There"), 20)
        .unwrap();
    assert_eq!(
        response,
        hmac_sha1(&[0x0b; 20], &pad_challenge(b"Hi There"))
    );
}

#[test]
fn lt64_empty_challenge_is_a_single_zero_byte() {
    let mut d = Device::new();
    configure(&mut d, cmd::CONFIG1, &hmac_config(&[0x0b; 20], false, true));
    let response = d
        .read_checked(cmd::CHAL_HMAC1, &pad_challenge(b""), 20)
        .unwrap();
    assert_eq!(response, hmac_sha1(&[0x0b; 20], &[0x00]));
    // A challenge ending in 00 is padded with 01 and keeps its zero.
    let response = d
        .read_checked(cmd::CHAL_HMAC1, &pad_challenge(b"a\0"), 20)
        .unwrap();
    assert_eq!(response, hmac_sha1(&[0x0b; 20], b"a\0"));
}

#[test]
fn yubico_challenge_response_xors_the_private_id() {
    let mut d = Device::new();
    let config = config_bytes(&[], &PRIVATE_ID, &KEY, &[0; 6], 0, 0x40, 0x20);
    configure(&mut d, cmd::CONFIG1, &config);
    let challenge = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
    let response = d.read_checked(cmd::CHAL_OTP1, &challenge, 16).unwrap();
    let plain = lk_crypto::aes_ecb_decrypt_block(&KEY, &response).unwrap();
    assert_eq!(crc16(&plain), 0xF0B8);
    let ticket = Ticket::from_bytes(&plain).unwrap();
    let expected: Vec<u8> = challenge
        .iter()
        .zip(PRIVATE_ID)
        .map(|(c, u)| c ^ u)
        .collect();
    assert_eq!(ticket.uid[..], expected[..]);
    assert_eq!(ticket.use_counter, 1);
    // Wrong mode: HMAC on a Yubico CR slot is rejected.
    assert_eq!(
        d.send_and_receive(cmd::CHAL_HMAC1, &pad_challenge(b"x")),
        Err("no data")
    );
    // Challenge-response slots do not type anything.
    assert_eq!(d.button(Press::Short), "");
}

#[test]
fn static_password_types_scan_codes_with_shift() {
    // "Ab1!" as scan codes: A = 0x04|SHIFT, b = 0x05, 1 = 0x1E, ! = 0x1E|SHIFT.
    let codes = [0x84, 0x05, 0x1E, 0x9E];
    let mut d = Device::new();
    let config = config_bytes(&codes, &[0; 6], &[0; 16], &[0; 6], 0x10, ENTER, 0x02);
    configure(&mut d, cmd::CONFIG1, &config);
    let reports = d.otp.button(Press::Short, &mut d.host);
    assert_eq!(
        reports,
        vec![
            [0x02, 0, 0x04, 0, 0, 0, 0, 0],
            RELEASE,
            [0x00, 0, 0x05, 0, 0, 0, 0, 0],
            RELEASE,
            [0x00, 0, 0x1E, 0, 0, 0, 0, 0],
            RELEASE,
            [0x02, 0, 0x1E, 0, 0, 0, 0, 0],
            RELEASE,
            [0x00, 0, 0x28, 0, 0, 0, 0, 0],
            RELEASE,
        ]
    );
    // 38 scan codes span fixed, uid and key.
    let long: Vec<u8> = (0..38).map(|i| 0x04 + (i % 26) as u8).collect();
    let config = config_bytes(
        &long[..16],
        long[16..22].try_into().unwrap(),
        long[22..].try_into().unwrap(),
        &[0; 6],
        0,
        0,
        0x02,
    );
    let mut d = Device::new();
    configure(&mut d, cmd::CONFIG1, &config);
    assert_eq!(d.otp.button(Press::Short, &mut d.host).len(), 76);
}

#[test]
fn static_ticket_is_constant_and_short_ticket_is_half() {
    let mut d = Device::new();
    let config = config_bytes(&PUBLIC_ID, &PRIVATE_ID, &KEY, &[0; 6], 0x10, ENTER, 0x20);
    configure(&mut d, cmd::CONFIG1, &config);
    let first = d.button(Press::Short);
    assert_eq!(first.len(), 45);
    assert_eq!(d.button(Press::Short), first);
    let ticket = decrypt_ticket(&first[12..44], &KEY);
    assert_eq!(ticket.uid, PRIVATE_ID);
    assert_eq!(
        (ticket.use_counter, ticket.session_counter, ticket.timestamp),
        (0, 0, 0)
    );
    // SHORT_TICKET: half of the ticket.
    let short = config_bytes(&PUBLIC_ID, &PRIVATE_ID, &KEY, &[0; 6], 0x10, ENTER, 0x22);
    configure(&mut d, cmd::CONFIG1, &short);
    let out = d.button(Press::Short);
    assert_eq!(out.len(), 12 + 16 + 1);
    assert_eq!(out[12..28], first[12..28]);
}

#[test]
fn static_ticket_strong_password_special_is_not_a_reference_string() {
    // yubikit StaticTicketSlotConfiguration.strong_password(special=True) sets
    // CFGFLAG_SEND_REF only together with CFGFLAG_STRONG_PW2: in static-ticket mode the
    // pair is the "special character" option, not "send reference string (0..F)".
    // Without STRONG_PW2 the reference string is still typed before the fixed part.
    const STATIC_TICKET: u8 = 0x20;
    const SEND_REF: u8 = 0x01;
    const STRONG_PW2: u8 = 0x40;
    let mut d = Device::new();
    let plain = config_bytes(&PUBLIC_ID, &PRIVATE_ID, &KEY, &[0; 6], 0x10, ENTER, STATIC_TICKET);
    configure(&mut d, cmd::CONFIG1, &plain);
    let untransformed = d.button(Press::Short);
    let special = config_bytes(
        &PUBLIC_ID,
        &PRIVATE_ID,
        &KEY,
        &[0; 6],
        0x10,
        ENTER,
        STATIC_TICKET | STRONG_PW2 | SEND_REF,
    );
    configure(&mut d, cmd::CONFIG1, &special);
    let out = d.button(Press::Short);
    assert!(!out.starts_with("cbdefghijklnrtuv"), "{out}");
    // The strong-password transforms themselves (upper case, digits, the special
    // character) are deferred (docs/catalog/otp.md), so the ticket is typed
    // untransformed; this length check pins only the absence of the reference string
    // and must change when the transforms are modelled.
    assert_eq!(out.len(), untransformed.len());
    let reference = config_bytes(
        &PUBLIC_ID,
        &PRIVATE_ID,
        &KEY,
        &[0; 6],
        0x10,
        ENTER,
        STATIC_TICKET | SEND_REF,
    );
    configure(&mut d, cmd::CONFIG1, &reference);
    assert_eq!(
        d.button(Press::Short),
        format!("cbdefghijklnrtuv{untransformed}")
    );
}

#[test]
fn keyboard_layout_flags_tabs_delays_pacing_and_reference() {
    // TAB_FIRST | APPEND_TAB1 | APPEND_TAB2 | APPEND_DELAY1 | APPEND_CR, PACING_10MS,
    // SEND_REF.
    let mut d = Device::new();
    let config = config_bytes(
        &[0xff],
        &PRIVATE_ID,
        &KEY,
        &[0; 6],
        0x10,
        0x01 | 0x02 | 0x04 | 0x08 | 0x20,
        0x01 | 0x04,
    );
    configure(&mut d, cmd::CONFIG1, &config);
    let reports = d.otp.button(Press::Short, &mut d.host);
    let text = decode_reports(&reports);
    assert_eq!(&text[..1], "\t");
    assert_eq!(&text[1..17], "cbdefghijklnrtuv");
    assert_eq!(&text[17..19], "vv");
    assert_eq!(&text[19..20], "\t");
    assert_eq!(&text[52..], "\t\n");
    // Each key is press, release and one 10 ms pacing idle; DELAY1 adds 50 idles.
    let keys = text.chars().count();
    assert_eq!(reports.len(), keys * 3 + 50);
    assert_eq!(reports[0], press_report(0x2B));
}

#[test]
fn numeric_keypad_flag_types_hotp_digits_on_the_keypad() {
    let mut d = Device::new();
    let mut config = hotp_config(RFC4226_SECRET, false, 0, &[], 0);
    config[45] |= 0x08; // EXTFLAG_USE_NUMERIC_KEYPAD
    let crc = !crc16(&config[..50]);
    config[50..].copy_from_slice(&crc.to_le_bytes());
    configure(&mut d, cmd::CONFIG1, &config);
    let reports = d.otp.button(Press::Short, &mut d.host);
    // 7 = Keypad 7 (0x5F), 5 = Keypad 5 (0x5D).
    assert_eq!(reports[0], [0, 0, 0x5F, 0, 0, 0, 0, 0]);
    assert_eq!(reports[2], [0, 0, 0x5D, 0, 0, 0, 0, 0]);
    assert_eq!(decode_reports(&reports), "755224\n");
}

#[test]
fn enter_is_only_sent_with_append_cr() {
    let mut d = Device::new();
    let config = config_bytes(&[], &PRIVATE_ID, &KEY, &[0; 6], 0x10, 0x00, 0);
    configure(&mut d, cmd::CONFIG1, &config);
    let out = d.button(Press::Short);
    assert_eq!(out.len(), 32);
    assert!(!out.contains('\n'));
}

#[test]
fn modhex_keyboard_reports_follow_the_scan_map() {
    let mut d = Device::new();
    configure(
        &mut d,
        cmd::CONFIG1,
        &yubico_otp_config(
            &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
            &PRIVATE_ID,
            &KEY,
            &[0; 6],
        ),
    );
    let reports = d.otp.button(Press::Short, &mut d.host);
    // c b d e f g h i j k l n r t u v: usages 06 05 07 08 09 0A 0B 0C 0D 0E 0F 11 15 17 18 19.
    let usages: Vec<u8> = reports.iter().step_by(2).take(16).map(|r| r[2]).collect();
    assert_eq!(
        usages,
        [
            0x06, 0x05, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x11, 0x15, 0x17,
            0x18, 0x19
        ]
    );
    assert!(reports.iter().skip(1).step_by(2).all(|r| *r == RELEASE));
    // Remap the scan map (slot command 0x12): 'c' becomes usage 0x1D ('z').
    let mut map = lk_otp::DEFAULT_SCAN_MAP;
    map[0] = 0x1D;
    d.write(cmd::SCAN_MAP, &map).unwrap();
    let reports = d.otp.button(Press::Short, &mut d.host);
    assert_eq!(reports[0][2], 0x1D);
    d.restart();
    assert_eq!(d.otp.scan_map()[0], 0x1D);
}

#[test]
fn exhausted_hotp_counter_types_nothing() {
    // A record in the documented format (src/state.rs): HOTP slot 1 whose next moving
    // factor is u32::MAX; the following one cannot be persisted, so nothing is typed.
    let mut host = lk_testkit::TestHost::new();
    let mut record = vec![0x01];
    record.extend(lk_codec::tlv::encode(
        0x03,
        &hotp_config(RFC4226_SECRET, false, 0, &[], 0),
    ));
    record.extend(lk_codec::tlv::encode(0x05, &u32::MAX.to_be_bytes()));
    let mut otp = lk_otp::Otp::new(Some(&record), &mut host);
    assert!(otp.is_configured(Slot::One));
    assert!(otp.button(Press::Short, &mut host).is_empty());
    assert_eq!(otp.counter(Slot::One), Some(u32::MAX));
    assert_eq!(host.persist_attempts(), 0);
}

#[test]
fn lt64_boundaries_at_63_and_64_bytes() {
    // ykdef.h CFGFLAG_HMAC_LT64 "set when HMAC message is less than 64 bytes": the key
    // strips the trailing bytes equal to the last one. yubikit calculate_hmac_sha1
    // pads with a byte different from the challenge's last byte, so every challenge
    // shorter than 64 bytes survives; a full 64-byte challenge loses its trailing run
    // (the documented reason LT64 slots cannot take 64-byte challenges).
    let key = [0x0b; 20];
    let mut d = Device::new();
    configure(&mut d, cmd::CONFIG1, &hmac_config(&key, false, true));
    let mut hmac = |challenge: &[u8]| d.read_checked(cmd::CHAL_HMAC1, challenge, 20).unwrap();
    // 63 bytes ending in a nonzero byte: padded with one 00, hashed as 63 bytes.
    let c63: Vec<u8> = (1..=63u8).collect();
    assert_eq!(hmac(&pad_challenge(&c63)), hmac_sha1(&key, &c63));
    // 63 bytes ending in 00: padded with one 01, the zero survives.
    let mut c63z = c63.clone();
    c63z[62] = 0;
    assert_eq!(hmac(&pad_challenge(&c63z)), hmac_sha1(&key, &c63z));
    // 64 distinct-tailed bytes: the last byte is taken as padding.
    let c64: Vec<u8> = (1..=64u8).collect();
    assert_eq!(hmac(&c64), hmac_sha1(&key, &c64[..63]));
    // 64 bytes ending in a run of three equal bytes: the whole run goes.
    let mut run = c64.clone();
    run[61..].copy_from_slice(&[0x77; 3]);
    assert_eq!(hmac(&run), hmac_sha1(&key, &run[..61]));
    // 64 equal bytes: one byte always remains.
    assert_eq!(hmac(&[0x41; 64]), hmac_sha1(&key, &[0x41]));
    // Without LT64 all 64 bytes are hashed.
    let mut d = Device::new();
    configure(&mut d, cmd::CONFIG1, &hmac_config(&key, false, false));
    assert_eq!(
        d.read_checked(cmd::CHAL_HMAC1, &run, 20).unwrap(),
        hmac_sha1(&key, &run)
    );
}
