//! Deterministic pseudo-random malformed input (docs/DESIGN.md §12-4: fixed-seed
//! random testing instead of cargo-fuzz). Asserts only that nothing panics and that
//! the status stays well-formed.

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use lk_core::{CardApplet, Entropy, Host, Outcome};
use lk_otp::{Otp, OtpApplet, OtpHid, Press, cmd};
use lk_testkit::{SeededEntropy, TestHost};

fn byte(rng: &mut SeededEntropy) -> u8 {
    let mut b = [0u8; 1];
    rng.fill(&mut b);
    b[0]
}

#[test]
fn random_feature_reports_never_panic() {
    let mut rng = SeededEntropy::new(0x07D0);
    let mut d = Device::new();
    d.mgmt = Some(FakeMgmt {
        serial: Some(1),
        info: vec![1, 1, 1],
        ..FakeMgmt::default()
    });
    // Seed some state so that commands reach deep paths.
    d.write(
        cmd::CONFIG1,
        &write_payload(&hmac_config(&[1; 20], true, true), None),
    )
    .unwrap();
    d.write(
        cmd::CONFIG2,
        &write_payload(&yubico_otp_config(&[1], &[2; 6], &[3; 16], &[0; 6]), None),
    )
    .unwrap();
    let commands = [
        0x01, 0x03, 0x04, 0x05, 0x06, 0x08, 0x10, 0x11, 0x12, 0x13, 0x15, 0x20, 0x28, 0x30, 0x38,
        0xFF,
    ];
    for round in 0..4_000 {
        match byte(&mut rng) % 4 {
            // Raw report with random flags.
            0 => {
                let mut report = [0u8; 8];
                rng.fill(&mut report);
                if let Outcome::NeedTouch { .. } = d.set(report) {
                    d.hid
                        .touch_resolved(round % 2 == 0, &mut d.otp, &mut d.host);
                }
            }
            // A well-framed command with random payload (valid frame CRC).
            1 => {
                let mut payload = vec![0u8; (byte(&mut rng) % 65) as usize];
                rng.fill(&mut payload);
                let command = commands[(byte(&mut rng) as usize) % commands.len()];
                if let Outcome::NeedTouch { .. } = d.send_frame(command, &payload) {
                    d.hid
                        .touch_resolved(round % 3 == 0, &mut d.otp, &mut d.host);
                }
            }
            2 => {
                for _ in 0..(byte(&mut rng) % 6) {
                    let _ = d.get();
                }
            }
            _ => {
                let press = if byte(&mut rng) & 1 == 0 {
                    Press::Short
                } else {
                    Press::Long
                };
                let _ = d.otp.button(press, &mut d.host);
                d.host.advance(u64::from(byte(&mut rng)) * 37);
                let _ = d.otp.touch_down(&mut d.host);
                d.host.advance(u64::from(byte(&mut rng)) * 23);
                let _ = d.otp.touch_up(&mut d.host);
            }
        }
        if round % 500 == 0 {
            d.host.fail_next_saves(1);
        }
        let status = d.otp.status();
        assert_eq!(status[..3], [5, 7, 4]);
    }
}

#[test]
fn random_apdus_never_panic() {
    let mut rng = SeededEntropy::new(0x0A9D);
    let mut host = TestHost::new();
    let mut applet = OtpApplet::new(None, &mut host);
    for round in 0..6_000 {
        let len = (byte(&mut rng) % 80) as usize;
        let mut apdu = vec![0u8; len];
        rng.fill(&mut apdu);
        // Bias towards the real header so slot commands run.
        if round % 2 == 0 && apdu.len() >= 4 {
            apdu[0] = 0x00;
            apdu[1] = 0x01;
            if apdu.len() > 5 {
                apdu[4] = (apdu.len() - 5) as u8;
            }
        }
        let mut mgmt = FakeMgmt {
            serial: Some(9),
            info: vec![0; 70],
            ..FakeMgmt::default()
        };
        let mgmt_ref = if round % 3 == 0 {
            Some(&mut mgmt as &mut dyn lk_otp::MgmtBridge)
        } else {
            None
        };
        match applet.process_with(&apdu, mgmt_ref, &mut host) {
            Outcome::Done(r) => assert!(r.len() >= 2),
            Outcome::NeedTouch { .. } => {
                let r = applet.touch_resolved(round % 2 == 0, &mut host);
                assert!(r.len() >= 2);
            }
        }
        if round % 700 == 0 {
            applet.reset(lk_core::ResetKind::PowerCycle);
        }
    }
}

#[test]
fn random_stored_state_never_panics() {
    let mut rng = SeededEntropy::new(0x5707);
    let mut host = TestHost::new();
    let mut valid = TestHost::new();
    let mut otp = Otp::new(None, &mut valid);
    let mut hid = OtpHid::new();
    let config = write_payload(&yubico_otp_config(&[1], &[2; 6], &[3; 16], &[0; 6]), None);
    let frame = build_frame(cmd::CONFIG1, &config);
    for (seq, chunk) in frame.chunks(7).enumerate() {
        let mut r = [0u8; 8];
        r[..7].copy_from_slice(chunk);
        r[7] = 0x80 | seq as u8;
        hid.set_feature(&r, &mut otp, None, &mut valid);
    }
    let good = valid.persisted(lk_core::Record::Otp).unwrap();
    for round in 0..3_000 {
        let mut bytes = if round % 2 == 0 {
            let mut b = good.clone();
            let i = (byte(&mut rng) as usize) % b.len();
            b[i] ^= byte(&mut rng) | 1;
            b
        } else {
            let mut b = vec![0u8; (byte(&mut rng) % 200) as usize];
            rng.fill(&mut b);
            b
        };
        if round % 5 == 0 {
            bytes.truncate((byte(&mut rng) as usize) % (bytes.len() + 1));
        }
        let mut otp = Otp::new(Some(&bytes), &mut host);
        let _ = otp.button(Press::Short, &mut host);
        let _ = otp.status();
    }
}

#[test]
fn random_mixed_transports_and_resets_keep_invariants() {
    // HID reports, CCID APDUs, buttons, touches, resets of every kind, clock jumps and
    // storage failures in one fixed-seed stream over one shared Otp. Invariants: no
    // panic; while a challenge-response waits for a touch nothing is typed; a power
    // cycle ends every wait; the status keeps the profile version.
    let mut rng = SeededEntropy::new(0x0C1D);
    let mut host = TestHost::new();
    let mut applet = OtpApplet::new(None, &mut host);
    let mut hid = OtpHid::new();
    let configs = [
        hmac_config(&[1; 20], true, true),
        hmac_config(&[2; 20], false, false),
        yubico_otp_config(&[1], &[2; 6], &[3; 16], &[0; 6]),
        hotp_config(b"12345678901234567890", false, 0, &[], 0),
        config_bytes(&[], &[4; 6], &[5; 16], &[0; 6], 0x04, 0x40, 0x28),
    ];
    let commands = [
        0x01, 0x03, 0x04, 0x05, 0x06, 0x10, 0x12, 0x20, 0x28, 0x30, 0x38,
    ];
    let mut presses_while_waiting = 0;
    for round in 0..6_000 {
        match byte(&mut rng) % 8 {
            0 | 1 => {
                // A valid frame for a random command, mostly with a real configuration.
                let command = commands[(byte(&mut rng) as usize) % commands.len()];
                let mut payload = if byte(&mut rng).is_multiple_of(3) {
                    let mut p = vec![0u8; (byte(&mut rng) % 65) as usize];
                    rng.fill(&mut p);
                    p
                } else {
                    let config = &configs[(byte(&mut rng) as usize) % configs.len()];
                    write_payload(config, None)
                };
                payload.truncate(64);
                let frame = build_frame(command, &payload);
                for (seq, chunk) in frame.chunks(7).enumerate() {
                    let mut r = [0u8; 8];
                    r[..7].copy_from_slice(chunk);
                    r[7] = 0x80 | seq as u8;
                    let _ = hid.set_feature(&r, applet.otp_mut(), None, &mut host);
                }
            }
            2 => {
                let mut r = [0u8; 8];
                rng.fill(&mut r);
                let _ = hid.set_feature(&r, applet.otp_mut(), None, &mut host);
                let _ = hid.get_feature_at(applet.otp(), host.now());
            }
            3 => {
                let command = commands[(byte(&mut rng) as usize) % commands.len()];
                let config = &configs[(byte(&mut rng) as usize) % configs.len()];
                let data = write_payload(config, None);
                let mut apdu = vec![0x00, 0x01, command, 0x00, data.len() as u8];
                apdu.extend_from_slice(&data);
                if let Outcome::NeedTouch { .. } = applet.process(&apdu, &mut host)
                    && byte(&mut rng).is_multiple_of(2)
                {
                    let r = applet.touch_resolved(byte(&mut rng).is_multiple_of(2), &mut host);
                    assert!(r.len() >= 2);
                }
            }
            4 => {
                if hid.is_waiting_for_touch() {
                    hid.touch_resolved(
                        byte(&mut rng).is_multiple_of(2),
                        applet.otp_mut(),
                        &mut host,
                    );
                }
                let _ = hid.get_feature(applet.otp());
            }
            5 => {
                let now = host.now();
                let waiting = applet.otp().is_challenge_waiting(now);
                let press = if byte(&mut rng) & 1 == 0 {
                    Press::Short
                } else {
                    Press::Long
                };
                let typed = applet.otp_mut().button(press, &mut host);
                let down = applet.otp_mut().touch_down(&mut host);
                if waiting {
                    presses_while_waiting += 1;
                    assert!(typed.is_empty() && down.is_empty(), "round {round}");
                }
                host.advance(u64::from(byte(&mut rng)) * 20);
                let up = applet.otp_mut().touch_up(&mut host);
                if applet.otp().is_challenge_waiting(host.now()) {
                    assert!(up.is_empty(), "round {round}");
                }
            }
            6 => {
                let kind = match byte(&mut rng) % 3 {
                    0 => lk_core::ResetKind::CardPowerOff,
                    1 => lk_core::ResetKind::UsbReset,
                    _ => lk_core::ResetKind::PowerCycle,
                };
                applet.reset(kind);
                hid.reset(kind);
                if kind != lk_core::ResetKind::CardPowerOff {
                    assert!(!applet.otp().is_challenge_waiting(host.now()));
                    assert!(!hid.is_waiting_for_touch());
                }
            }
            _ => {
                host.advance(u64::from(byte(&mut rng)) * 150);
                if byte(&mut rng).is_multiple_of(4) {
                    applet.deselect();
                }
            }
        }
        if round % 400 == 0 {
            host.fail_next_saves(1);
        }
        assert_eq!(applet.otp().status()[..3], [5, 7, 4]);
    }
    assert!(presses_while_waiting > 20, "the stream must exercise waits");
}
