//! The OTP application over CCID.
//!
//! Sources: yubikit `_YubiOtpSmartCardBackend` (SELECT returns the status; INS 0x01
//! with P1 = slot command; writes answer the status, reads the bare data), ISO/IEC
//! 7816-4 §5.1 (APDU cases) and §5.6 (status words), RFC 2202 §3 test case 1,
//! `reference/BEHAVIOR_CATALOG.md` "OTP" (6985 for empty-slot delete, LT64 direct
//! short APDU).

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use lk_core::{CardApplet, Outcome};
use lk_otp::{OTP_AID, OtpApplet, cmd};
use lk_testkit::TestHost;

fn apdu(p1: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x00, 0x01, p1, 0x00];
    if !data.is_empty() {
        out.push(data.len() as u8);
        out.extend_from_slice(data);
    }
    out
}

fn done(outcome: Outcome<Vec<u8>>) -> Vec<u8> {
    match outcome {
        Outcome::Done(r) => r,
        Outcome::NeedTouch { .. } => panic!("unexpected touch"),
    }
}

fn setup() -> (OtpApplet, TestHost) {
    let mut host = TestHost::new();
    let applet = OtpApplet::new(None, &mut host);
    (applet, host)
}

#[test]
fn select_returns_status() {
    let (mut applet, mut host) = setup();
    assert_eq!(applet.aid(), &OTP_AID);
    let r = applet.select(
        &[
            0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01,
        ],
        &mut host,
    );
    assert_eq!(r, vec![5, 7, 4, 0, 0, 0, 0x90, 0x00]);
}

#[test]
fn writes_return_status_and_reads_return_bare_data() {
    let (mut applet, mut host) = setup();
    let r = done(applet.process(
        &apdu(
            cmd::CONFIG1,
            &write_payload(&hmac_config(&[0x0b; 20], false, true), None),
        ),
        &mut host,
    ));
    // version, pgmSeq 1, touchLevel CONFIG1_VALID (challenge-response: no touch bit).
    assert_eq!(r, vec![5, 7, 4, 1, 0x01, 0x00, 0x90, 0x00]);
    let r = done(applet.process(
        &apdu(cmd::CHAL_HMAC1, &pad_challenge(b"Hi There")),
        &mut host,
    ));
    assert_eq!(r[..20], hex("b617318655057264e28bc0b6fb378c8ef146be00")[..]);
    assert_eq!(r[20..], [0x90, 0x00]);
    let r = done(applet.process(&apdu(cmd::DEVICE_SERIAL, &[]), &mut host));
    assert_eq!(
        r,
        [&12_345_678u32.to_be_bytes()[..], &[0x90, 0x00]].concat()
    );
}

#[test]
fn short_challenge_apdus_are_zero_padded() {
    let (mut applet, mut host) = setup();
    done(applet.process(
        &apdu(
            cmd::CONFIG1,
            &write_payload(&hmac_config(&[0x0b; 20], false, true), None),
        ),
        &mut host,
    ));
    // "Hi There" without padding hashes the same as the padded SDK form.
    let r = done(applet.process(&apdu(cmd::CHAL_HMAC1, b"Hi There"), &mut host));
    assert_eq!(r[..20], hex("b617318655057264e28bc0b6fb378c8ef146be00")[..]);
    // An empty challenge APDU is the single byte 00 under LT64.
    let r = done(applet.process(&apdu(cmd::CHAL_HMAC1, &[]), &mut host));
    assert_eq!(r[..20], hmac_sha1(&[0x0b; 20], &[0]));
    // More than 64 bytes is a wrong length.
    let r = done(applet.process(&apdu(cmd::CHAL_HMAC1, &[1; 65]), &mut host));
    assert_eq!(r, [0x67, 0x00]);
}

#[test]
fn rejection_status_words() {
    let (mut applet, mut host) = setup();
    // Empty-slot delete: 6985.
    assert_eq!(
        done(applet.process(&apdu(cmd::CONFIG1, &[0; 58]), &mut host)),
        [0x69, 0x85]
    );
    // Bad configuration CRC: 6A80.
    let mut bad = yubico_otp_config(&[], &[1; 6], &[2; 16], &[0; 6]);
    bad[51] ^= 1;
    assert_eq!(
        done(applet.process(&apdu(cmd::CONFIG1, &write_payload(&bad, None)), &mut host)),
        [0x6A, 0x80]
    );
    // Wrong access code: 6982.
    let config = yubico_otp_config(&[], &[1; 6], &[2; 16], &[7; 6]);
    done(applet.process(
        &apdu(cmd::CONFIG1, &write_payload(&config, None)),
        &mut host,
    ));
    assert_eq!(
        done(applet.process(
            &apdu(cmd::CONFIG1, &write_payload(&config, None)),
            &mut host
        )),
        [0x69, 0x82]
    );
    // Swap with one slot: 6985. Challenge on a keyboard slot: 6985.
    assert_eq!(
        done(applet.process(&apdu(cmd::SWAP, &[]), &mut host)),
        [0x69, 0x85]
    );
    assert_eq!(
        done(applet.process(&apdu(cmd::CHAL_HMAC1, &[1]), &mut host)),
        [0x69, 0x85]
    );
    // Unknown slot command 6A86, NDEF 6A81, device info without bridge 6A81.
    assert_eq!(
        done(applet.process(&apdu(0x77, &[]), &mut host)),
        [0x6A, 0x86]
    );
    assert_eq!(
        done(applet.process(&apdu(cmd::NDEF1, &[1]), &mut host)),
        [0x6A, 0x81]
    );
    assert_eq!(
        done(applet.process(&apdu(cmd::YK4_CAPABILITIES, &[0]), &mut host)),
        [0x6A, 0x81]
    );
    // Header errors.
    assert_eq!(
        done(applet.process(&[0x00, 0x02, 0x01, 0x00], &mut host)),
        [0x6D, 0x00]
    );
    assert_eq!(
        done(applet.process(&[0x80, 0x01, 0x01, 0x00], &mut host)),
        [0x6E, 0x00]
    );
    assert_eq!(
        done(applet.process(&[0x10, 0x01, 0x01, 0x00, 0x01, 0x00], &mut host)),
        [0x68, 0x84]
    );
    assert_eq!(
        done(applet.process(&[0x00, 0x01, 0x01], &mut host)),
        [0x67, 0x00]
    );
    // Storage failure: 6581 and nothing changes.
    host.fail_next_saves(1);
    let other = yubico_otp_config(&[], &[1; 6], &[3; 16], &[0; 6]);
    assert_eq!(
        done(applet.process(&apdu(cmd::CONFIG2, &write_payload(&other, None)), &mut host)),
        [0x65, 0x81]
    );
    assert!(!applet.otp().is_configured(lk_otp::Slot::Two));
}

#[test]
fn touch_challenge_over_ccid() {
    let (mut applet, mut host) = setup();
    done(applet.process(
        &apdu(
            cmd::CONFIG2,
            &write_payload(&hmac_config(&[0x0b; 20], true, true), None),
        ),
        &mut host,
    ));
    let outcome = applet.process(
        &apdu(cmd::CHAL_HMAC2, &pad_challenge(b"Hi There")),
        &mut host,
    );
    assert_eq!(outcome, Outcome::NeedTouch { timeout_ms: 15_000 });
    let r = applet.touch_resolved(true, &mut host);
    assert_eq!(r[..20], hex("b617318655057264e28bc0b6fb378c8ef146be00")[..]);
    assert_eq!(r[20..], [0x90, 0x00]);
    // Timeout or cancel: 6985.
    applet.process(
        &apdu(cmd::CHAL_HMAC2, &pad_challenge(b"Hi There")),
        &mut host,
    );
    assert_eq!(applet.touch_resolved(false, &mut host), [0x69, 0x85]);
    // Deselect drops the pending request.
    applet.process(
        &apdu(cmd::CHAL_HMAC2, &pad_challenge(b"Hi There")),
        &mut host,
    );
    applet.deselect();
    assert_eq!(applet.touch_resolved(true, &mut host), [0x69, 0x85]);
}

#[test]
fn bridge_commands_over_ccid() {
    let (mut applet, mut host) = setup();
    let mut mgmt = FakeMgmt {
        serial: Some(77),
        info: vec![0x02, 0x04, 0, 0, 0, 77],
        ..FakeMgmt::default()
    };
    let r = applet.process_with(&apdu(cmd::DEVICE_SERIAL, &[]), Some(&mut mgmt), &mut host);
    assert_eq!(done(r), [0, 0, 0, 77, 0x90, 0x00]);
    let r = applet.process_with(
        &apdu(cmd::YK4_CAPABILITIES, &[0]),
        Some(&mut mgmt),
        &mut host,
    );
    assert_eq!(done(r), [6, 0x02, 0x04, 0, 0, 0, 77, 0x90, 0x00]);
    let r = applet.process_with(
        &apdu(cmd::YK4_SET_DEVICE_INFO, &[0x03, 0x03, 0x01, 0x3F]),
        Some(&mut mgmt),
        &mut host,
    );
    assert_eq!(done(r), [5, 7, 4, 1, 0, 0, 0x90, 0x00]);
    mgmt.reject = Some(0x6982);
    let r = applet.process_with(
        &apdu(cmd::YK4_SET_DEVICE_INFO, &[0x03, 0x03, 0x01, 0x3F]),
        Some(&mut mgmt),
        &mut host,
    );
    assert_eq!(done(r), [0x69, 0x82]);
}

#[test]
fn yubikit_programming_sequence_check_over_ccid() {
    // yubikit write_update: the status after each write must show prog_seq + 1, or 0
    // with no slot configured.
    let (mut applet, mut host) = setup();
    let mut prog = applet.otp().status()[3];
    for p1 in [cmd::CONFIG1, cmd::CONFIG2] {
        let r = done(applet.process(
            &apdu(
                p1,
                &write_payload(&yubico_otp_config(&[], &[1; 6], &[2; 16], &[0; 6]), None),
            ),
            &mut host,
        ));
        assert_eq!(r[3], prog + 1);
        prog = r[3];
    }
    let r = done(applet.process(&apdu(cmd::SWAP, &[]), &mut host));
    assert_eq!(r[3], prog + 1);
    done(applet.process(&apdu(cmd::CONFIG1, &[0; 58]), &mut host));
    let r = done(applet.process(&apdu(cmd::CONFIG2, &[0; 58]), &mut host));
    assert_eq!((r[3], r[4] & 0x03), (0, 0));
}

/// What a host does with one slot command.
enum Op {
    /// A configuration-type write, checked through the status / programming sequence.
    Write(u8, Vec<u8>),
    /// A read of `n` data bytes (HID adds and checks the CRC; CCID returns them bare).
    Read(u8, Vec<u8>, usize),
}

#[test]
fn ccid_and_hid_views_agree() {
    // yubikit drives the same slot commands through OtpProtocol (HID) and
    // _YubiOtpSmartCardBackend (CCID). Run one script through both on identical hosts
    // and require the same outcomes, the same status after every step and the same
    // persisted record at the end.
    const KEY: [u8; 16] = [0x2b; 16];
    const UID: [u8; 6] = [0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6];
    const CODE: [u8; 6] = [6, 5, 4, 3, 2, 1];
    let yubico_cr = config_bytes(&[], &UID, &KEY, &CODE, 0x04 | 0x20, 0x40, 0x20);
    let update = config_bytes(&[], &[0; 6], &[0; 16], &CODE, 0x04 | 0x20 | 0x80, 0, 0);
    let script = [
        Op::Write(cmd::CONFIG1, write_payload(&yubico_cr, None)),
        Op::Write(
            cmd::CONFIG2,
            write_payload(&hmac_config(&[0x0b; 20], false, true), None),
        ),
        Op::Read(cmd::DEVICE_SERIAL, vec![], 4),
        Op::Read(cmd::CHAL_HMAC2, pad_challenge(b"Hi There"), 20),
        Op::Read(cmd::CHAL_HMAC2, b"Hi There".to_vec(), 20),
        Op::Read(cmd::CHAL_OTP1, vec![1, 2, 3, 4, 5, 6], 16),
        Op::Read(cmd::CHAL_OTP1, vec![1, 2, 3, 4, 5, 6], 16),
        Op::Read(cmd::CHAL_OTP2, vec![1, 2, 3, 4, 5, 6], 16),
        Op::Write(cmd::CONFIG1, write_payload(&yubico_cr, Some(&[0; 6]))),
        Op::Write(cmd::UPDATE1, write_payload(&update, None)),
        Op::Write(cmd::UPDATE1, write_payload(&update, Some(&CODE))),
        Op::Write(cmd::SWAP, write_payload(&[0; 52], None)),
        Op::Write(cmd::SWAP, write_payload(&[0; 52], Some(&CODE))),
        Op::Read(cmd::CHAL_HMAC1, pad_challenge(b"Hi There"), 20),
        Op::Read(cmd::CHAL_OTP2, vec![9; 6], 16),
        Op::Read(cmd::CHAL_HMAC2, pad_challenge(b"x"), 20),
        Op::Write(cmd::SCAN_MAP, lk_otp::DEFAULT_SCAN_MAP.to_vec()),
        Op::Write(cmd::CONFIG2, write_payload(&[0; 52], Some(&CODE))),
        Op::Write(cmd::CONFIG2, write_payload(&[0; 52], Some(&CODE))),
        Op::Write(cmd::NDEF1, vec![1; 20]),
        Op::Write(0x7E, vec![]),
        Op::Write(cmd::CONFIG1, write_payload(&[0; 52], None)),
        Op::Read(cmd::DEVICE_SERIAL, vec![], 4),
    ];
    let mut d = Device::new();
    let (mut applet, mut host) = setup();
    for (step, op) in script.iter().enumerate() {
        match op {
            Op::Write(slot, payload) => {
                let hid = d.write(*slot, payload);
                let r = done(applet.process(&apdu(*slot, payload), &mut host));
                match hid {
                    Ok(status) => {
                        assert_eq!(r, [&status[..], &[0x90, 0x00]].concat(), "step {step}")
                    }
                    Err(e) => {
                        assert_eq!(e, "no data", "step {step}");
                        assert_eq!(r.len(), 2, "step {step}");
                        assert_ne!(r, [0x90, 0x00], "step {step}");
                    }
                }
            }
            Op::Read(slot, payload, n) => {
                let hid = d.read_checked(*slot, payload, *n);
                let r = done(applet.process(&apdu(*slot, payload), &mut host));
                match hid {
                    Ok(data) => assert_eq!(r, [&data[..], &[0x90, 0x00]].concat(), "step {step}"),
                    Err(e) => {
                        assert_eq!(e, "no data", "step {step}");
                        assert_eq!(r.len(), 2, "step {step}");
                    }
                }
            }
        }
        assert_eq!(d.otp.status(), applet.otp().status(), "step {step}");
    }
    assert_eq!(
        d.host.persisted(lk_core::Record::Otp),
        host.persisted(lk_core::Record::Otp)
    );
    assert_eq!(d.host.persist_count(), host.persist_count());
}

#[test]
fn yubico_challenge_storage_failure_reveals_nothing() {
    // The usage counter of a new session is persisted before the response that
    // reveals it (docs/CONTRACTS.md); if that fails, CCID answers 6581 and HID sends
    // no data, and the next attempt still starts at usage counter 1.
    const KEY: [u8; 16] = [0x2b; 16];
    let config = config_bytes(&[], &[1; 6], &KEY, &[0; 6], 0x04, 0x40, 0x20);
    let (mut applet, mut host) = setup();
    done(applet.process(
        &apdu(cmd::CONFIG1, &write_payload(&config, None)),
        &mut host,
    ));
    host.fail_next_saves(1);
    assert_eq!(
        done(applet.process(&apdu(cmd::CHAL_OTP1, &[0; 6]), &mut host)),
        [0x65, 0x81]
    );
    let r = done(applet.process(&apdu(cmd::CHAL_OTP1, &[0; 6]), &mut host));
    let plain = lk_crypto::aes_ecb_decrypt_block(&KEY, r[..16].try_into().unwrap()).unwrap();
    let ticket = lk_otp::Ticket::from_bytes(&plain).unwrap();
    assert_eq!((ticket.use_counter, ticket.session_counter), (1, 0));
    // HID.
    let mut d = Device::new();
    d.write(cmd::CONFIG1, &write_payload(&config, None))
        .unwrap();
    d.host.fail_next_saves(1);
    assert_eq!(d.read_checked(cmd::CHAL_OTP1, &[0; 6], 16), Err("no data"));
    let r = d.read_checked(cmd::CHAL_OTP1, &[0; 6], 16).unwrap();
    let plain = lk_crypto::aes_ecb_decrypt_block(&KEY, r[..16].try_into().unwrap()).unwrap();
    let ticket = lk_otp::Ticket::from_bytes(&plain).unwrap();
    assert_eq!((ticket.use_counter, ticket.session_counter), (1, 0));
}
