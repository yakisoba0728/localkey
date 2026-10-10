//! Access codes, swap, update, delete, dormant, slot-2 protection, serial/device-info
//! bridging, status bits and persistence.
//!
//! Sources: Yubico `ykdef.h` (slot commands, `EXTFLAG_ALLOW_UPDATE`/`DORMANT`,
//! `TKTFLAG_PROTECT_CFG2`, `*_UPDATE_MASK`, touchLevel bits), YubiKey manual "Access
//! code", "Update", "Swap"; yubikit `yubiotp.py` payloads; `reference/BEHAVIOR_CATALOG.md`
//! "OTP" (swap requires two configured slots, UPDATE with Allow Update or Dormant,
//! empty-slot delete rejection, merged serial visibility, touch status bits).

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use lk_core::{Host, Record};
use lk_otp::{Press, Slot, cmd, crc16, status_bits};

const KEY_A: [u8; 16] = [0xA0; 16];
const KEY_B: [u8; 16] = [0xB0; 16];
const CODE: [u8; 6] = [1, 2, 3, 4, 5, 6];
const RFC4226_SECRET: &[u8; 20] = b"12345678901234567890";

fn otp_a(acc: &[u8; 6]) -> Vec<u8> {
    yubico_otp_config(&[0xAA], &[1; 6], &KEY_A, acc)
}

fn otp_b(acc: &[u8; 6]) -> Vec<u8> {
    yubico_otp_config(&[0xBB], &[2; 6], &KEY_B, acc)
}

fn with_flags(mut config: Vec<u8>, ext: u8, tkt: u8, cfg: u8) -> Vec<u8> {
    config[45] = ext;
    config[46] = tkt;
    config[47] = cfg;
    let crc = !crc16(&config[..50]);
    config[50..].copy_from_slice(&crc.to_le_bytes());
    config
}

/// yubikit `UpdateConfiguration`: zero fixed/uid/key, new flags, new access code.
fn update_config(ext: u8, tkt: u8, cfg: u8, new_acc: &[u8; 6]) -> Vec<u8> {
    config_bytes(&[], &[0; 6], &[0; 16], new_acc, ext, tkt, cfg)
}

#[test]
fn access_code_protects_reprogramming_and_delete() {
    let mut d = Device::new();
    d.write(cmd::CONFIG1, &write_payload(&otp_a(&CODE), None))
        .unwrap();
    // No code / wrong code: not updated.
    assert_eq!(
        d.write(cmd::CONFIG1, &write_payload(&otp_b(&[0; 6]), None)),
        Err("no data")
    );
    assert_eq!(
        d.write(
            cmd::CONFIG1,
            &write_payload(&otp_b(&[0; 6]), Some(&[1, 2, 3, 4, 5, 7]))
        ),
        Err("no data")
    );
    assert_eq!(d.write(cmd::CONFIG1, &[0u8; 58]), Err("no data"));
    assert_eq!(d.otp.config(Slot::One).unwrap().key, KEY_A);
    // Correct code: reprogrammed, and the new configuration has no code.
    d.write(cmd::CONFIG1, &write_payload(&otp_b(&[0; 6]), Some(&CODE)))
        .unwrap();
    assert_eq!(d.otp.config(Slot::One).unwrap().key, KEY_B);
    // Protected delete with the code.
    d.write(cmd::CONFIG2, &write_payload(&otp_a(&CODE), None))
        .unwrap();
    assert_eq!(d.write(cmd::CONFIG2, &[0u8; 58]), Err("no data"));
    d.write(cmd::CONFIG2, &write_payload(&[0u8; 52], Some(&CODE)))
        .unwrap();
    assert!(!d.otp.is_configured(Slot::Two));
}

#[test]
fn empty_slot_delete_is_rejected_and_normal_delete_works() {
    let mut d = Device::new();
    d.write(cmd::CONFIG1, &write_payload(&otp_a(&[0; 6]), None))
        .unwrap();
    let seq = d.read_status()[3];
    assert_eq!(d.write(cmd::CONFIG2, &[0u8; 58]), Err("no data"));
    assert_eq!(d.read_status()[3], seq);
    assert!(d.otp.is_configured(Slot::One));
    d.write(cmd::CONFIG1, &[0u8; 58]).unwrap();
    assert!(!d.otp.is_configured(Slot::One));
}

#[test]
fn swap_requires_two_configured_slots() {
    let mut d = Device::new();
    assert_eq!(d.write(cmd::SWAP, &[0u8; 58]), Err("no data"));
    d.write(cmd::CONFIG1, &write_payload(&otp_a(&[0; 6]), None))
        .unwrap();
    let seq = d.read_status()[3];
    assert_eq!(d.write(cmd::SWAP, &[0u8; 58]), Err("no data"));
    assert_eq!(d.read_status()[3], seq);
    assert_eq!(d.otp.config(Slot::One).unwrap().key, KEY_A);
    assert!(!d.otp.is_configured(Slot::Two));
    d.write(
        cmd::CONFIG2,
        &write_payload(&hotp_config(RFC4226_SECRET, false, 0, &[], 0), None),
    )
    .unwrap();
    // Use the HOTP counter, then swap: the counter follows its configuration.
    assert_eq!(d.button(Press::Long), "755224\n");
    d.write(cmd::SWAP, &[0u8; 58]).unwrap();
    assert_eq!(d.otp.config(Slot::Two).unwrap().key, KEY_A);
    assert_eq!(d.otp.counter(Slot::One), Some(1));
    assert_eq!(d.button(Press::Short), "287082\n");
}

#[test]
fn swap_honours_access_codes() {
    let mut d = Device::new();
    d.write(cmd::CONFIG1, &write_payload(&otp_a(&CODE), None))
        .unwrap();
    d.write(cmd::CONFIG2, &write_payload(&otp_b(&[0; 6]), None))
        .unwrap();
    assert_eq!(d.write(cmd::SWAP, &[0u8; 58]), Err("no data"));
    d.write(cmd::SWAP, &write_payload(&[0u8; 52], Some(&CODE)))
        .unwrap();
    assert_eq!(d.otp.config(Slot::Two).unwrap().key, KEY_A);
}

#[test]
fn update_changes_flags_and_code_but_not_keys() {
    let mut d = Device::new();
    d.write(cmd::CONFIG1, &write_payload(&otp_a(&CODE), None))
        .unwrap();
    // New flags: TAB_FIRST, no ENTER; new access code; the zero key is ignored.
    let update = update_config(0x24, 0x01, 0, &[9; 6]);
    assert_eq!(
        d.write(cmd::UPDATE1, &write_payload(&update, None)),
        Err("no data")
    );
    d.write(cmd::UPDATE1, &write_payload(&update, Some(&CODE)))
        .unwrap();
    let config = d.otp.config(Slot::One).unwrap();
    assert_eq!(config.key, KEY_A);
    assert_eq!(config.tkt_flags, 0x01);
    assert_eq!(config.acc_code, [9; 6]);
    let out = d.button(Press::Short);
    assert!(out.starts_with('\t') && !out.ends_with('\n'));
    // Updating an empty slot is rejected.
    assert_eq!(
        d.write(cmd::UPDATE2, &write_payload(&update, None)),
        Err("no data")
    );
}

#[test]
fn update_requires_allow_update_or_dormant() {
    let mut d = Device::new();
    // Configured without ALLOW_UPDATE.
    let fixed = with_flags(otp_a(&[0; 6]), 0x04, 0x20, 0);
    d.write(cmd::CONFIG1, &write_payload(&fixed, None)).unwrap();
    assert_eq!(
        d.write(
            cmd::UPDATE1,
            &write_payload(&update_config(0x24, 0x20, 0, &[0; 6]), None)
        ),
        Err("no data")
    );
    // Dormant without ALLOW_UPDATE: no output, no touch bit, but it can be woken.
    let dormant = with_flags(otp_a(&[0; 6]), 0x40, 0x20, 0);
    d.write(cmd::CONFIG1, &write_payload(&dormant, None))
        .unwrap();
    assert_eq!(d.button(Press::Short), "");
    assert_eq!(d.otp.touch_level() & 0x0F, status_bits::CONFIG1_VALID);
    d.write(
        cmd::UPDATE1,
        &write_payload(&update_config(0x00, 0x20, 0, &[0; 6]), None),
    )
    .unwrap();
    assert_eq!(d.button(Press::Short).len(), 2 + 32 + 1);
    // Activated without ALLOW_UPDATE: it cannot be made dormant again.
    assert_eq!(
        d.write(
            cmd::UPDATE1,
            &write_payload(&update_config(0x40, 0x20, 0, &[0; 6]), None)
        ),
        Err("no data")
    );
    // With ALLOW_UPDATE, DORMANT toggles both ways.
    d.write(cmd::CONFIG2, &write_payload(&otp_b(&[0; 6]), None))
        .unwrap();
    d.write(
        cmd::UPDATE2,
        &write_payload(&update_config(0x60, 0x20, 0, &[0; 6]), None),
    )
    .unwrap();
    assert!(!d.otp.is_touch_triggered(Slot::Two));
    d.write(
        cmd::UPDATE2,
        &write_payload(&update_config(0x20, 0x20, 0, &[0; 6]), None),
    )
    .unwrap();
    assert!(d.otp.is_touch_triggered(Slot::Two));
}

#[test]
fn slot2_protection_precedence() {
    let mut d = Device::new();
    // Slot 1 with PROTECT_CFG2 blocks writes to an empty or unprotected slot 2.
    let protector = with_flags(otp_a(&[0; 6]), 0x24, 0x20 | 0x80, 0);
    d.write(cmd::CONFIG1, &write_payload(&protector, None))
        .unwrap();
    assert_eq!(
        d.write(cmd::CONFIG2, &write_payload(&otp_b(&[0; 6]), None)),
        Err("no data")
    );
    // Remove the protection, configure slot 2 opted in, then protect again.
    d.write(cmd::CONFIG1, &write_payload(&otp_a(&[0; 6]), None))
        .unwrap();
    let opted_in = with_flags(otp_b(&[0; 6]), 0x24, 0x20 | 0x80, 0);
    d.write(cmd::CONFIG2, &write_payload(&opted_in, None))
        .unwrap();
    d.write(cmd::CONFIG1, &write_payload(&protector, None))
        .unwrap();
    // Slot 2 carries the bit itself, so it may be rewritten (and swapped).
    d.write(cmd::CONFIG2, &write_payload(&opted_in, None))
        .unwrap();
    d.write(cmd::SWAP, &[0u8; 58]).unwrap();
    // Now slot 1 is the opted-in config and slot 2 the protector (also with the bit).
    d.write(cmd::CONFIG2, &write_payload(&otp_b(&[0; 6]), None))
        .unwrap();
    // Slot 2 without the bit can no longer be replaced or deleted.
    assert_eq!(d.write(cmd::CONFIG2, &[0u8; 58]), Err("no data"));
}

#[test]
fn touch_status_bits_distinguish_keyboard_from_challenge_response() {
    let mut d = Device::new();
    d.write(cmd::CONFIG1, &write_payload(&otp_a(&[0; 6]), None))
        .unwrap();
    d.write(
        cmd::CONFIG2,
        &write_payload(&hmac_config(&[1; 20], false, true), None),
    )
    .unwrap();
    let level = d.read_status()[4];
    assert_eq!(level & 0x0F, 0x01 | 0x02 | 0x04);
    // Swap moves the touch bit with the configuration.
    d.write(cmd::SWAP, &[0u8; 58]).unwrap();
    assert_eq!(d.read_status()[4] & 0x0F, 0x01 | 0x02 | 0x08);
    // Restart keeps it; delete clears it.
    d.restart();
    assert_eq!(d.read_status()[4] & 0x0F, 0x01 | 0x02 | 0x08);
    d.write(cmd::CONFIG2, &[0u8; 58]).unwrap();
    assert_eq!(d.read_status()[4] & 0x0F, 0x01);
    // LED_INV is reported when a configuration sets it.
    d.write(
        cmd::CONFIG2,
        &write_payload(&with_flags(otp_b(&[0; 6]), 0x80, 0x20, 0), None),
    )
    .unwrap();
    assert_eq!(d.read_status()[4] & 0x10, 0x10);
}

#[test]
fn serial_through_bridge_profile_and_visibility() {
    let mut d = Device::new();
    // Without a bridge the profile serial is used (factory: nothing configured).
    let serial = d.read_checked(cmd::DEVICE_SERIAL, &[], 4).unwrap();
    assert_eq!(serial, d.host.profile().serial.to_be_bytes());
    d.mgmt = Some(FakeMgmt {
        serial: Some(0x0102_0304),
        ..FakeMgmt::default()
    });
    assert_eq!(
        d.read_checked(cmd::DEVICE_SERIAL, &[], 4).unwrap(),
        [1, 2, 3, 4]
    );
    // A configured slot without SERIAL_API_VISIBLE hides it...
    d.write(
        cmd::CONFIG1,
        &write_payload(&with_flags(otp_a(&[0; 6]), 0x20, 0x20, 0), None),
    )
    .unwrap();
    assert_eq!(d.read_checked(cmd::DEVICE_SERIAL, &[], 4), Err("no data"));
    // ...until either slot makes it visible (merged visibility).
    d.write(cmd::CONFIG2, &write_payload(&otp_b(&[0; 6]), None))
        .unwrap();
    assert_eq!(
        d.read_checked(cmd::DEVICE_SERIAL, &[], 4).unwrap(),
        [1, 2, 3, 4]
    );
    // Management hiding the serial wins.
    d.mgmt.as_mut().unwrap().serial = None;
    assert_eq!(d.read_checked(cmd::DEVICE_SERIAL, &[], 4), Err("no data"));
}

#[test]
fn device_info_read_and_write_through_bridge() {
    let mut d = Device::new();
    let info = vec![0x01, 0x02, 0x02, 0x3F, 0x02, 0x04, 0x01, 0x02, 0x03, 0x04];
    d.mgmt = Some(FakeMgmt {
        info: info.clone(),
        ..FakeMgmt::default()
    });
    // yubikit read_config: response[0] is the length, CRC over length || TLVs.
    let response = d.send_and_receive(cmd::YK4_CAPABILITIES, &[0]).unwrap();
    let len = response[0] as usize;
    assert_eq!(len, info.len());
    assert_eq!(crc16(&response[..len + 3]), 0xF0B8);
    assert_eq!(response[1..len + 1], info[..]);
    // Unknown page: no data.
    assert_eq!(
        d.send_and_receive(cmd::YK4_CAPABILITIES, &[5]),
        Err("no data")
    );
    // Write: forwarded as length || TLVs; the programming sequence advances even with
    // no slot configured, as yubikit write_config expects.
    let config = [0x03, 0x03, 0x01, 0x3F];
    let status = d.write(cmd::YK4_SET_DEVICE_INFO, &config).unwrap();
    assert_eq!(status[3], 1);
    assert_eq!(d.mgmt.as_ref().unwrap().written, vec![config.to_vec()]);
    // Legacy mode write (0x11): forwarded. The sequence is 1 now (no slot configured),
    // so yubikit set_mode does not treat the key as empty and needs it to advance.
    assert_eq!(set_mode(&mut d, &[0x06, 15, 0, 0]), Ok(()));
    assert_eq!(d.mgmt.as_ref().unwrap().legacy, vec![vec![0x06, 15, 0, 0]]);
    assert_eq!(d.read_status()[3], 2);
    // Rejection by Management: not updated.
    d.mgmt.as_mut().unwrap().reject = Some(0x6985);
    assert_eq!(d.write(cmd::YK4_SET_DEVICE_INFO, &config), Err("no data"));
    // Without a bridge these commands are unavailable.
    d.mgmt = None;
    assert_eq!(
        d.send_and_receive(cmd::YK4_CAPABILITIES, &[0]),
        Err("no data")
    );
}

/// yubikit `_ManagementOtpBackend.set_mode`: `empty = read_status()[3] == 0`; a
/// rejected write ("no data") is accepted only when the key was empty.
fn set_mode(d: &mut Device, data: &[u8]) -> Result<(), &'static str> {
    let empty = d.read_status()[3] == 0;
    match d.send_and_receive(cmd::DEVICE_CONFIG, data) {
        Ok(_) => Ok(()),
        Err("no data") if empty => Ok(()),
        Err(e) => Err(e),
    }
}

#[test]
fn legacy_mode_write_follows_the_yubikit_programming_sequence_rule() {
    let mut d = Device::new();
    d.mgmt = Some(FakeMgmt::default());
    // Factory key (sequence 0): the sequence stays 0 and set_mode accepts that.
    assert_eq!(set_mode(&mut d, &[0x06, 15, 0, 0]), Ok(()));
    assert_eq!(d.read_status()[3], 0);
    // A scan-map write on an empty key moves the sequence off 0 without configuring a
    // slot; set_mode must then see an advance (was rejected before the fix).
    d.write(cmd::SCAN_MAP, &lk_otp::DEFAULT_SCAN_MAP).unwrap();
    assert_eq!(d.read_status()[3], 1);
    assert_eq!(set_mode(&mut d, &[0x06, 15, 0, 0]), Ok(()));
    assert_eq!(d.read_status()[3], 2);
    // With a configured slot it advances too.
    d.write(cmd::CONFIG1, &write_payload(&otp_a(&[0; 6]), None))
        .unwrap();
    assert_eq!(set_mode(&mut d, &[0x05, 15, 0, 0]), Ok(()));
    assert_eq!(d.read_status()[3], 4);
    // Management rejecting it: not updated, and set_mode reports the failure.
    d.mgmt.as_mut().unwrap().reject = Some(0x6A80);
    assert_eq!(set_mode(&mut d, &[0xFF, 15, 0, 0]), Err("no data"));
    assert_eq!(d.read_status()[3], 4);
    // The legacy write is not persisted on its own: the record still holds the
    // sequence of the last OTP record write (3, the slot write).
    d.restart();
    assert_eq!(d.otp.programming_sequence(), 3);
}

#[test]
fn ndef_is_not_available_on_a_usb_only_key() {
    let mut d = Device::new();
    assert_eq!(d.write(cmd::NDEF1, &[0x55; 32]), Err("no data"));
    assert_eq!(d.write(cmd::NDEF2, &[0x55; 32]), Err("no data"));
    assert_eq!(d.write(0x7F, &[0x55; 32]), Err("no data"));
}

#[test]
fn state_persists_across_restart() {
    let mut d = Device::new();
    d.write(
        cmd::CONFIG1,
        &write_payload(&hotp_config(RFC4226_SECRET, false, 0, &[], 0), None),
    )
    .unwrap();
    d.write(cmd::CONFIG2, &write_payload(&otp_b(&CODE), None))
        .unwrap();
    assert_eq!(d.button(Press::Short), "755224\n");
    d.restart();
    assert_eq!(d.otp.programming_sequence(), 2);
    assert_eq!(d.otp.config(Slot::Two).unwrap().acc_code, CODE);
    // The HOTP counter was persisted before the code was typed.
    assert_eq!(d.button(Press::Short), "287082\n");
    // Unreadable state is factory state.
    d.host.set_persisted(Record::Otp, &[0x01, 0x03, 0x05, 0xFF]);
    d.restart();
    assert!(!d.otp.is_configured(Slot::One));
    assert_eq!(d.otp.programming_sequence(), 0);
}

#[test]
fn storage_failure_keeps_previous_state() {
    let mut d = Device::new();
    d.write(cmd::CONFIG1, &write_payload(&otp_a(&[0; 6]), None))
        .unwrap();
    d.host.fail_next_saves(1);
    assert_eq!(
        d.write(cmd::CONFIG1, &write_payload(&otp_b(&[0; 6]), None)),
        Err("no data")
    );
    assert_eq!(d.otp.config(Slot::One).unwrap().key, KEY_A);
    assert_eq!(d.otp.programming_sequence(), 1);
    // HOTP: a failed counter persist types nothing and keeps the counter.
    d.write(
        cmd::CONFIG2,
        &write_payload(&hotp_config(RFC4226_SECRET, false, 0, &[], 0), None),
    )
    .unwrap();
    d.host.fail_next_saves(1);
    assert_eq!(d.button(Press::Long), "");
    assert_eq!(d.otp.counter(Slot::Two), Some(0));
    assert_eq!(d.button(Press::Long), "755224\n");
    // Delete, swap and update failures change nothing either.
    d.host.fail_all(true);
    assert_eq!(d.write(cmd::CONFIG1, &[0u8; 58]), Err("no data"));
    assert_eq!(d.write(cmd::SWAP, &[0u8; 58]), Err("no data"));
    assert_eq!(
        d.write(
            cmd::UPDATE1,
            &write_payload(&update_config(0x24, 0, 0, &[0; 6]), None)
        ),
        Err("no data")
    );
    d.host.fail_all(false);
    d.restart();
    assert_eq!(d.otp.config(Slot::One).unwrap().key, KEY_A);
    assert_eq!(d.otp.counter(Slot::Two), Some(1));
}

#[test]
fn access_code_mismatch_changes_nothing() {
    // YubiKey manual "Access code": a protected slot accepts CONFIG (including
    // delete), UPDATE and SWAP only with its current code (ykpers yk_write_command puts
    // it at bytes 52..58). A mismatch must not touch configurations, counters, the
    // running Yubico OTP session, the programming sequence or storage.
    const CODE2: [u8; 6] = [9, 9, 9, 9, 9, 9];
    let mut d = Device::new();
    d.write(cmd::CONFIG1, &write_payload(&otp_a(&CODE), None))
        .unwrap();
    let hotp = with_flags(
        hotp_config(RFC4226_SECRET, false, 0, &[], 0),
        0x24 | 0x10,
        0x40 | 0x20,
        0,
    );
    let mut hotp_protected = hotp.clone();
    hotp_protected[38..44].copy_from_slice(&CODE2);
    let crc = !crc16(&hotp_protected[..50]);
    hotp_protected[50..].copy_from_slice(&crc.to_le_bytes());
    d.write(cmd::CONFIG2, &write_payload(&hotp_protected, None))
        .unwrap();
    // Start the slot 1 session.
    let first = d.button(Press::Short);
    assert_eq!(first.len(), 2 + 32 + 1);
    let snapshot = |d: &Device| {
        (
            d.otp.config(Slot::One).cloned(),
            d.otp.config(Slot::Two).cloned(),
            d.otp.counter(Slot::One),
            d.otp.counter(Slot::Two),
            d.otp.status(),
            d.host.persist_attempts(),
            d.host.persisted(Record::Otp),
        )
    };
    let before = snapshot(&d);
    let wrong = [1, 2, 3, 4, 5, 0];
    let attempts: [(&str, u8, Vec<u8>); 9] = [
        (
            "config1 no code",
            cmd::CONFIG1,
            write_payload(&otp_b(&[0; 6]), None),
        ),
        (
            "config1 wrong code",
            cmd::CONFIG1,
            write_payload(&otp_b(&[0; 6]), Some(&wrong)),
        ),
        (
            "config1 other slot's code",
            cmd::CONFIG1,
            write_payload(&otp_b(&[0; 6]), Some(&CODE2)),
        ),
        (
            "delete1 wrong code",
            cmd::CONFIG1,
            write_payload(&[0; 52], Some(&wrong)),
        ),
        (
            "delete2 slot 1's code",
            cmd::CONFIG2,
            write_payload(&[0; 52], Some(&CODE)),
        ),
        (
            "update1 wrong code",
            cmd::UPDATE1,
            write_payload(&update_config(0x24, 0x20, 0, &[0; 6]), Some(&wrong)),
        ),
        (
            "update2 no code",
            cmd::UPDATE2,
            write_payload(&update_config(0x24, 0x20, 0, &[0; 6]), None),
        ),
        // SWAP needs both slots' codes; one supplied code can only match one of them.
        (
            "swap slot 1's code",
            cmd::SWAP,
            write_payload(&[0; 52], Some(&CODE)),
        ),
        (
            "swap slot 2's code",
            cmd::SWAP,
            write_payload(&[0; 52], Some(&CODE2)),
        ),
    ];
    for (name, slot, payload) in attempts {
        assert_eq!(d.write(slot, &payload), Err("no data"), "{name}");
        assert_eq!(snapshot(&d), before, "{name}");
    }
    // The running session continues: same usage counter, next session counter.
    let next = d.button(Press::Short);
    let key = KEY_A;
    let decrypt = |text: &str| {
        let enc = lk_otp::modhex_decode(&text[2..34]).unwrap();
        let plain = lk_crypto::aes_ecb_decrypt_block(&key, &enc).unwrap();
        lk_otp::Ticket::from_bytes(&plain).unwrap()
    };
    let (t1, t2) = (decrypt(&first), decrypt(&next));
    assert_eq!((t1.use_counter, t1.session_counter), (1, 0));
    assert_eq!((t2.use_counter, t2.session_counter), (1, 1));
    // Each slot accepts its own code; a slot without a code ignores the supplied one.
    d.write(cmd::CONFIG2, &write_payload(&hotp, Some(&CODE2)))
        .unwrap();
    d.write(cmd::CONFIG2, &write_payload(&hotp, Some(&wrong)))
        .unwrap();
    d.write(
        cmd::UPDATE1,
        &write_payload(&update_config(0x24, 0x20, 0, &CODE), Some(&CODE)),
    )
    .unwrap();
}

#[test]
fn update_cannot_change_mode_protection_or_secrets() {
    // ykdef.h "Flags valid for update": TKTFLAG_UPDATE_MASK (TAB/DELAY/CR bits),
    // CFGFLAG_UPDATE_MASK (pacing), EXTFLAG_UPDATE_MASK (all ext bits). Mode bits
    // (TKTFLAG_OATH_HOTP/CHAL_RESP, CFGFLAG_STATIC_TICKET/SHORT_TICKET/CHAL_*),
    // TKTFLAG_PROTECT_CFG2 and the fixed/uid/key fields of an UPDATE payload are not
    // applied.
    let mut d = Device::new();
    d.write(
        cmd::CONFIG1,
        &write_payload(&hotp_config(RFC4226_SECRET, false, 0, &[], 0), None),
    )
    .unwrap();
    let mut sneaky = config_bytes(
        &[0xEE; 16],
        &[0xEE; 6],
        &[0xEE; 16],
        &[0; 6],
        0x24,
        0x80 | 0x40 | 0x20 | 0x01,
        0x22 | 0x08 | 0x04,
    );
    // Valid CRC over the odd flags.
    let crc = !crc16(&sneaky[..50]);
    sneaky[50..].copy_from_slice(&crc.to_le_bytes());
    let status = d
        .write(cmd::UPDATE1, &write_payload(&sneaky, None))
        .unwrap();
    assert_eq!(status[3], 2);
    let config = d.otp.config(Slot::One).unwrap();
    assert_eq!(config.mode(), lk_otp::Mode::Hotp);
    assert_eq!(
        config.tkt_flags,
        0x40 | 0x20 | 0x01,
        "mode bit kept, PROTECT_CFG2 not set"
    );
    assert_eq!(config.cfg_flags, 0x08 | 0x04, "only the pacing bits");
    assert_eq!(config.key, RFC4226_SECRET[..16]);
    assert_eq!(config.fixed_size, 0);
    // TAB_FIRST and pacing now apply; the HOTP sequence continues from counter 0.
    let reports = d.otp.button(Press::Short, &mut d.host);
    assert_eq!(lk_otp::decode_reports(&reports), "\t755224\n");
    // Slot 2 is not protected by the ignored PROTECT_CFG2 bit.
    d.write(cmd::CONFIG2, &write_payload(&otp_b(&[0; 6]), None))
        .unwrap();
}

#[test]
fn oversized_fixed_size_is_rejected_on_both_transports() {
    // ykdef.h config_st: fixedSize counts bytes of the 16-byte fixed field.
    let mut config = otp_a(&[0; 6]);
    config[44] = 17;
    let crc = !crc16(&config[..50]);
    config[50..].copy_from_slice(&crc.to_le_bytes());
    let mut d = Device::new();
    assert_eq!(
        d.write(cmd::CONFIG1, &write_payload(&config, None)),
        Err("no data")
    );
    assert!(!d.otp.is_configured(Slot::One));
    let mut host = lk_testkit::TestHost::new();
    let mut applet = lk_otp::OtpApplet::new(None, &mut host);
    let payload = write_payload(&config, None);
    let mut apdu = vec![0x00, 0x01, cmd::CONFIG1, 0x00, payload.len() as u8];
    apdu.extend_from_slice(&payload);
    assert_eq!(
        lk_core::CardApplet::process(&mut applet, &apdu, &mut host),
        lk_core::Outcome::Done(vec![0x6A, 0x80])
    );
}
