//! OTP HID feature-report protocol at the report level.
//!
//! Sources: Yubico `ykdef.h` (`YKFRAME`, `SLOT_WRITE_FLAG 0x80`, `RESP_PENDING_FLAG
//! 0x40`, `RESP_TIMEOUT_WAIT_FLAG 0x20`, `DUMMY_REPORT_WRITE 0x8F`, `STATUS` layout,
//! touchLevel bits), ykpers `yk_write_to_key` / `yk_read_response_from_key`, yubikit
//! `OtpProtocol` (`_send_frame`, `_should_send`, `_read_frame`, `_reset_state`).

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use lk_core::Outcome;
use lk_otp::{cmd, crc16};

const KEY: [u8; 16] = [0x11; 16];

#[test]
fn status_report_layout_is_version_sequence_touch_level() {
    let mut d = Device::new();
    // [reserved, major, minor, patch, pgmSeq, touchLevel lo, hi, flags]
    assert_eq!(d.get(), [0, 5, 7, 4, 0, 0, 0, 0]);
    d.write(
        cmd::CONFIG1,
        &write_payload(
            &yubico_otp_config(&[1, 2, 3, 4, 5, 6], &[7; 6], &KEY, &[0; 6]),
            None,
        ),
    )
    .unwrap();
    // pgmSeq 1, CONFIG1_VALID | CONFIG1_TOUCH.
    assert_eq!(d.get(), [0, 5, 7, 4, 1, 0x05, 0, 0]);
}

#[test]
fn frame_write_skips_zero_chunks_and_bumps_programming_sequence() {
    let mut d = Device::new();
    let payload = write_payload(&yubico_otp_config(&[], &[0; 6], &KEY, &[0; 6]), None);
    // Count the reports a yubikit host sends for this frame: chunks of zeros in the
    // middle are skipped.
    let frame = build_frame(cmd::CONFIG1, &payload);
    let sent = frame
        .chunks(7)
        .enumerate()
        .filter(|(seq, c)| *seq == 0 || *seq == 9 || c.iter().any(|&b| b != 0))
        .count();
    assert!(sent < 10, "the fixture must exercise skipping");
    let before = d.read_status()[3];
    assert_eq!(d.send_frame(cmd::CONFIG1, &payload), Outcome::Done(()));
    let status = d.read_frame(before).unwrap();
    assert_eq!(status[3], before + 1);
    assert!(d.otp.is_configured(lk_otp::Slot::One));
}

#[test]
fn every_chunk_written_explicitly_is_also_accepted() {
    // ykpers writes every non-zero chunk too; writing all ten works the same way.
    let mut d = Device::new();
    let frame = build_frame(
        cmd::CONFIG2,
        &write_payload(&yubico_otp_config(&[], &[0; 6], &KEY, &[0; 6]), None),
    );
    for (seq, chunk) in frame.chunks(7).enumerate() {
        let mut report = [0u8; 8];
        report[..7].copy_from_slice(chunk);
        report[7] = 0x80 | seq as u8;
        d.set(report);
    }
    assert!(d.otp.is_configured(lk_otp::Slot::Two));
    assert_eq!(d.read_status()[3], 1);
}

#[test]
fn response_chunks_carry_sequence_and_wrap_to_zero() {
    let mut d = Device::new();
    let secret = [0x0b; 20];
    d.write(
        cmd::CONFIG2,
        &write_payload(&hmac_config(&secret, false, true), None),
    )
    .unwrap();
    d.send_frame(cmd::CHAL_HMAC2, &pad_challenge(b"Hi There"));
    // 20-byte HMAC + 2-byte CRC = 22 bytes = 4 chunks; then the sequence wraps.
    let mut data = Vec::new();
    for seq in 0..4u8 {
        let r = d.get();
        assert_eq!(r[7], 0x40 | seq);
        data.extend_from_slice(&r[..7]);
    }
    assert_eq!(d.get()[7], 0x40, "sequence wraps to 0 after the last chunk");
    assert_eq!(crc16(&data[..22]), 0xF0B8);
    // RFC 2202 test case 1.
    assert_eq!(
        data[..20],
        hex("b617318655057264e28bc0b6fb378c8ef146be00")[..]
    );
    // The dummy write ends the read phase: back to status.
    d.reset_state();
    assert_eq!(d.get()[7], 0);
    // ykpers' dummy write value 0x8F does the same.
    d.send_frame(cmd::CHAL_HMAC2, &pad_challenge(b"Hi There"));
    assert_eq!(d.get()[7], 0x40);
    d.set([0, 0, 0, 0, 0, 0, 0, lk_otp::DUMMY_REPORT_WRITE]);
    assert_eq!(d.get()[7], 0);
}

#[test]
fn bad_frame_crc_is_ignored() {
    let mut d = Device::new();
    let mut frame = build_frame(
        cmd::CONFIG1,
        &write_payload(&yubico_otp_config(&[], &[0; 6], &KEY, &[0; 6]), None),
    );
    frame[65] ^= 0xFF;
    for (seq, chunk) in frame.chunks(7).enumerate() {
        let mut report = [0u8; 8];
        report[..7].copy_from_slice(chunk);
        report[7] = 0x80 | seq as u8;
        d.set(report);
    }
    assert!(!d.otp.is_configured(lk_otp::Slot::One));
    assert_eq!(d.read_status()[3], 0);
}

#[test]
fn orphan_chunks_and_aborted_frames_do_nothing() {
    let mut d = Device::new();
    let frame = build_frame(
        cmd::CONFIG1,
        &write_payload(&yubico_otp_config(&[], &[0; 6], &KEY, &[0; 6]), None),
    );
    let report = |seq: usize| {
        let mut r = [0u8; 8];
        r[..7].copy_from_slice(&frame[seq * 7..seq * 7 + 7]);
        r[7] = 0x80 | seq as u8;
        r
    };
    // Orphan: chunks 1..9 without chunk 0.
    for seq in 1..10 {
        d.set(report(seq));
    }
    assert!(!d.otp.is_configured(lk_otp::Slot::One));
    // Abort: chunks 0..5, a dummy write, then the rest.
    for seq in 0..6 {
        d.set(report(seq));
    }
    d.reset_state();
    for seq in 6..10 {
        d.set(report(seq));
    }
    assert!(!d.otp.is_configured(lk_otp::Slot::One));
    // Out-of-order: a repeated sequence number drops the partial frame.
    for seq in [0, 1, 2, 2, 3, 4, 5, 6, 7, 8, 9] {
        d.set(report(seq));
    }
    assert!(!d.otp.is_configured(lk_otp::Slot::One));
    // A clean frame afterwards works.
    for seq in 0..10 {
        d.set(report(seq));
    }
    assert!(d.otp.is_configured(lk_otp::Slot::One));
    // Reports without the write flag are ignored.
    d.set(
        [0xFF; 7]
            .iter()
            .copied()
            .chain([0x00])
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    );
    assert_eq!(d.read_status()[3], 1);
}

#[test]
fn new_frame_restarts_assembly() {
    let mut d = Device::new();
    let junk = build_frame(cmd::CONFIG2, &[0xAA; 64]);
    let good = build_frame(
        cmd::CONFIG1,
        &write_payload(&yubico_otp_config(&[], &[0; 6], &KEY, &[0; 6]), None),
    );
    for (seq, chunk) in junk.chunks(7).enumerate().take(4) {
        let mut r = [0u8; 8];
        r[..7].copy_from_slice(chunk);
        r[7] = 0x80 | seq as u8;
        d.set(r);
    }
    for (seq, chunk) in good.chunks(7).enumerate() {
        let mut r = [0u8; 8];
        r[..7].copy_from_slice(chunk);
        r[7] = 0x80 | seq as u8;
        d.set(r);
    }
    assert!(d.otp.is_configured(lk_otp::Slot::One));
    assert!(!d.otp.is_configured(lk_otp::Slot::Two));
}

#[test]
fn touch_wait_reports_seconds_left_and_abort_cancels_it() {
    let mut d = Device::new();
    d.write(
        cmd::CONFIG1,
        &write_payload(&hmac_config(&[0x0b; 20], true, true), None),
    )
    .unwrap();
    let outcome = d.send_frame(cmd::CHAL_HMAC1, &pad_challenge(b"Hi There"));
    assert_eq!(outcome, Outcome::NeedTouch { timeout_ms: 15_000 });
    assert!(d.hid.is_waiting_for_touch());
    assert_eq!(d.get()[7], 0x20 | 15);
    d.host.advance(4_500);
    assert_eq!(d.get()[7], 0x20 | 11);
    // yubikit's user abort is the reset write.
    d.reset_state();
    assert!(!d.hid.is_waiting_for_touch());
    assert_eq!(d.get()[7], 0);
    // A late touch resolution is harmless.
    d.hid.touch_resolved(true, &mut d.otp, &mut d.host);
    assert_eq!(d.get()[7], 0);
}

#[test]
fn touch_then_response_or_timeout() {
    let mut d = Device::new();
    d.write(
        cmd::CONFIG1,
        &write_payload(&hmac_config(&[0x0b; 20], true, true), None),
    )
    .unwrap();
    let before = d.read_status()[3];
    d.send_frame(cmd::CHAL_HMAC1, &pad_challenge(b"Hi There"));
    d.hid.touch_resolved(true, &mut d.otp, &mut d.host);
    let data = d.read_frame(before).unwrap();
    assert_eq!(
        data[..20],
        hex("b617318655057264e28bc0b6fb378c8ef146be00")[..]
    );
    // Timeout: no data; the host sees an unchanged status.
    d.send_frame(cmd::CHAL_HMAC1, &pad_challenge(b"Hi There"));
    d.hid.touch_resolved(false, &mut d.otp, &mut d.host);
    assert_eq!(d.read_frame(before), Err("no data"));
}

#[test]
fn rejected_write_leaves_programming_sequence() {
    let mut d = Device::new();
    // Deleting an empty slot is rejected; the host sees "no data" (not updated).
    assert_eq!(d.write(cmd::CONFIG1, &[0u8; 58]), Err("no data"));
    assert_eq!(d.read_status()[3], 0);
}

#[test]
fn deleting_the_last_slot_resets_sequence_to_zero() {
    let mut d = Device::new();
    d.write(
        cmd::CONFIG1,
        &write_payload(&yubico_otp_config(&[], &[0; 6], &KEY, &[0; 6]), None),
    )
    .unwrap();
    d.write(
        cmd::CONFIG2,
        &write_payload(&yubico_otp_config(&[], &[0; 6], &KEY, &[0; 6]), None),
    )
    .unwrap();
    assert_eq!(d.read_status()[3], 2);
    d.write(cmd::CONFIG1, &[0u8; 58]).unwrap();
    assert_eq!(d.read_status()[3], 3);
    // yubikit accepts the 0 that follows deleting the last slot.
    let status = d.write(cmd::CONFIG2, &[0u8; 58]).unwrap();
    assert_eq!(status[3], 0);
    assert_eq!(status[4] & 0x03, 0);
}

#[test]
fn usb_reset_drops_partial_frame_and_response() {
    let mut d = Device::new();
    d.write(
        cmd::CONFIG1,
        &write_payload(&hmac_config(&[0x0b; 20], false, true), None),
    )
    .unwrap();
    d.send_frame(cmd::CHAL_HMAC1, &pad_challenge(b"x"));
    assert!(d.hid.has_response());
    d.hid.reset(lk_core::ResetKind::UsbReset);
    assert!(!d.hid.has_response());
    assert_eq!(d.get()[7], 0);
}

/// The ten reports of a frame, each `chunk || 0x80 | seq` (ykpers `yk_write_to_key`).
fn frame_reports(slot: u8, data: &[u8]) -> Vec<[u8; 8]> {
    build_frame(slot, data)
        .chunks(7)
        .enumerate()
        .map(|(seq, chunk)| {
            let mut r = [0u8; 8];
            r[..7].copy_from_slice(chunk);
            r[7] = 0x80 | seq as u8;
            r
        })
        .collect()
}

#[test]
fn out_of_order_duplicate_and_missing_chunks_never_execute() {
    let mut d = Device::new();
    // A Yubico OTP configuration with nonzero bytes in every chunk of the payload, so
    // that no chunk may legitimately be skipped.
    let config = yubico_otp_config(&[0x5A; 16], &[0x11; 6], &KEY, &[0x22; 6]);
    let payload = write_payload(&config, Some(&[0x33; 6]));
    let reports = frame_reports(cmd::CONFIG1, &payload);
    assert!(reports.iter().all(|r| r[..7].iter().any(|&b| b != 0)));
    let attempts = d.host.persist_attempts();
    let order = |seqs: &[usize]| seqs.iter().map(|&s| reports[s]).collect::<Vec<_>>();
    let cases: [(&str, Vec<[u8; 8]>); 5] = [
        ("swapped 1 and 2", order(&[0, 2, 1, 3, 4, 5, 6, 7, 8, 9])),
        (
            "repeated chunk 8",
            order(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 8, 9]),
        ),
        ("descending tail", order(&[0, 1, 2, 3, 4, 5, 6, 9, 8, 7])),
        // A missing nonzero chunk is taken as a skipped zero chunk: the frame CRC
        // (ykdef.h YKFRAME crc over the 64-byte payload) no longer matches.
        (
            "missing nonzero chunk 3",
            order(&[0, 1, 2, 4, 5, 6, 7, 8, 9]),
        ),
        // Chunk 9 carries the slot byte and the CRC; without it nothing completes.
        ("missing last chunk", order(&[0, 1, 2, 3, 4, 5, 6, 7, 8])),
    ];
    for (name, sequence) in cases {
        for report in sequence {
            assert_eq!(d.set(report), Outcome::Done(()), "{name}");
        }
        assert!(!d.otp.is_configured(lk_otp::Slot::One), "{name}");
        assert_eq!(d.read_status()[3], 0, "{name}");
        assert_eq!(d.host.persist_attempts(), attempts, "{name}");
    }
    // The partial frame left by the last case is discarded by the next chunk 0, and a
    // clean frame then executes once.
    for report in &reports {
        d.set(*report);
    }
    assert!(d.otp.is_configured(lk_otp::Slot::One));
    assert_eq!(d.read_status()[3], 1);
    assert_eq!(d.host.persist_attempts(), attempts + 1);
    // Replaying only the tail (no chunk 0) runs nothing a second time.
    for report in &reports[1..] {
        d.set(*report);
    }
    assert_eq!(d.read_status()[3], 1);
    assert_eq!(d.host.persist_attempts(), attempts + 1);
}

#[test]
fn frame_crc_is_the_plain_crc_of_the_payload() {
    // ykpers yk_write_to_key stores yubikey_crc16(payload) itself (not its complement,
    // which only the 52-byte configuration and responses carry). A frame carrying the
    // complemented CRC is corrupt and is dropped.
    let mut d = Device::new();
    let payload = write_payload(&yubico_otp_config(&[], &[0; 6], &KEY, &[0; 6]), None);
    let mut frame = build_frame(cmd::CONFIG1, &payload);
    let crc = !crc16(&frame[..64]);
    frame[65..67].copy_from_slice(&crc.to_le_bytes());
    for (seq, chunk) in frame.chunks(7).enumerate() {
        let mut r = [0u8; 8];
        r[..7].copy_from_slice(chunk);
        r[7] = 0x80 | seq as u8;
        d.set(r);
    }
    assert!(!d.otp.is_configured(lk_otp::Slot::One));
    // The filler bytes after the CRC are not checked.
    let mut frame = build_frame(cmd::CONFIG1, &payload);
    frame[67..70].copy_from_slice(&[0xDE, 0xAD, 0x99]);
    for (seq, chunk) in frame.chunks(7).enumerate() {
        let mut r = [0u8; 8];
        r[..7].copy_from_slice(chunk);
        r[7] = 0x80 | seq as u8;
        d.set(r);
    }
    assert!(d.otp.is_configured(lk_otp::Slot::One));
}

#[test]
fn reports_without_the_write_flag_do_not_disturb_frames_or_responses() {
    let mut d = Device::new();
    let noise = [0x40, 0x20, 0x1F, 0x09, 0x7F, 0x00, 0x60];
    // Noise between every chunk of a configuration frame.
    let reports = frame_reports(
        cmd::CONFIG1,
        &write_payload(&hmac_config(&[0x0b; 20], false, true), None),
    );
    for (i, report) in reports.iter().enumerate() {
        d.set(*report);
        let mut junk = [0xA5u8; 8];
        junk[7] = noise[i % noise.len()];
        assert_eq!(d.set(junk), Outcome::Done(()));
    }
    assert!(d.otp.is_configured(lk_otp::Slot::One));
    // Noise between the response reads does not end the read phase.
    d.send_frame(cmd::CHAL_HMAC1, &pad_challenge(b"Hi There"));
    let mut data = Vec::new();
    for seq in 0..4u8 {
        d.set([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F]);
        let r = d.get();
        assert_eq!(r[7], 0x40 | seq);
        data.extend_from_slice(&r[..7]);
    }
    assert_eq!(
        data[..20],
        hex("b617318655057264e28bc0b6fb378c8ef146be00")[..]
    );
}

#[test]
fn status_report_bytes_follow_each_change() {
    // ykdef.h STATUS: [reserved, major, minor, patch, pgmSeq, touchLevel LE, flags];
    // touchLevel bits CONFIG1_VALID 01, CONFIG2_VALID 02, CONFIG1_TOUCH 04,
    // CONFIG2_TOUCH 08, CONFIG_LED_INV 10.
    let mut d = Device::new();
    assert_eq!(d.get(), [0, 5, 7, 4, 0, 0x00, 0, 0]);
    let hotp = hotp_config(b"12345678901234567890", false, 0, &[], 0);
    d.write(cmd::CONFIG1, &write_payload(&hotp, None)).unwrap();
    assert_eq!(d.get(), [0, 5, 7, 4, 1, 0x05, 0, 0]);
    d.write(
        cmd::CONFIG2,
        &write_payload(&hmac_config(&[1; 20], true, true), None),
    )
    .unwrap();
    assert_eq!(d.get(), [0, 5, 7, 4, 2, 0x07, 0, 0]);
    // UPDATE slot 1 to dormant (it has ALLOW_UPDATE): valid but no touch bit.
    let dormant = config_bytes(&[], &[0; 6], &[0; 16], &[0; 6], 0x20 | 0x40, ENTER, 0);
    d.write(cmd::UPDATE1, &write_payload(&dormant, None))
        .unwrap();
    assert_eq!(d.get(), [0, 5, 7, 4, 3, 0x03, 0, 0]);
    // Wake it with LED_INV: touch bit back, LED_INV mirrored.
    let led = config_bytes(&[], &[0; 6], &[0; 16], &[0; 6], 0x20 | 0x80, ENTER, 0);
    d.write(cmd::UPDATE1, &write_payload(&led, None)).unwrap();
    assert_eq!(d.get(), [0, 5, 7, 4, 4, 0x17, 0, 0]);
    // Swap moves VALID/TOUCH with the configurations; LED_INV stays.
    d.write(cmd::SWAP, &[0u8; 6]).unwrap();
    assert_eq!(d.get(), [0, 5, 7, 4, 5, 0x1B, 0, 0]);
    // Delete slot 2 (the HOTP slot with LED_INV): only the CR slot 1 remains.
    d.write(cmd::CONFIG2, &[0u8; 58]).unwrap();
    assert_eq!(d.get(), [0, 5, 7, 4, 6, 0x01, 0, 0]);
    // Deleting the last slot reports sequence 0 and no bits.
    d.write(cmd::CONFIG1, &[0u8; 58]).unwrap();
    assert_eq!(d.get(), [0, 5, 7, 4, 0, 0x00, 0, 0]);
    // The firmware version comes from the device profile.
    let mut host = lk_testkit::TestHost::with_profile(lk_core::DeviceProfile {
        firmware: lk_core::Version::new(5, 4, 3),
        ..lk_core::DeviceProfile::own(1)
    });
    let otp = lk_otp::Otp::new(None, &mut host);
    assert_eq!(
        lk_otp::OtpHid::new().get_feature(&otp),
        [0, 5, 4, 3, 0, 0, 0, 0]
    );
}
