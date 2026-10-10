//! Yubico PIV extensions: SET PIN RETRIES (FA), RESET (FB), GET VERSION (FD), GET
//! SERIAL (F8) and GET METADATA (F7) (Yubico PIV command reference; YubiKey 5 technical
//! manual), plus restart behaviour of the persisted record.

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use lk_core::{CardApplet, DeviceProfile, Record};
use lk_testkit::TestHost;

#[test]
fn get_version_reports_profile_firmware() {
    let mut card = Card::new();
    assert_eq!(card.send("00FD0000"), (hex("050704"), 0x9000));
    let mut card = Card::with_host(TestHost::with_profile(DeviceProfile::yubikey_5c_nano_5_7_4(1)));
    assert_eq!(card.send("00FD000000"), (hex("050704"), 0x9000));
}

#[test]
fn get_serial_reports_profile_serial_big_endian() {
    // TestHost default serial 12345678 = 0x00BC614E.
    let mut card = Card::new();
    assert_eq!(card.send("00F80000"), (hex("00BC614E"), 0x9000));
    let mut card = Card::with_host(TestHost::with_profile(DeviceProfile::yubikey_5c_nano_5_7_4(31_415_926)));
    assert_eq!(card.send("00F8000000"), (hex("01DF5E76"), 0x9000));
}

#[test]
fn metadata_for_factory_references() {
    let mut card = Card::new();
    // PIN/PUK: algorithm FF, default value, retries limit/remaining.
    assert_eq!(card.metadata(0x80), (hex("0101FF 050101 06020303"), 0x9000));
    assert_eq!(card.metadata(0x81), (hex("0101FF 050101 06020303"), 0x9000));
    // Management key: AES-192 (0A), PIN policy 00 / touch never (01), default.
    assert_eq!(card.metadata(0x9B), (hex("01010A 02020001 050101"), 0x9000));
    // Every user key slot is empty; F9 holds the own attestation key, ECC P-256 (11),
    // PIN never / touch never, generated on the device, public point under 86.
    for slot in [0x9A, 0x9C, 0x9D, 0x9E, 0x82, 0x95] {
        assert_eq!(card.metadata(slot).1, 0x6A88, "{slot:02X}");
    }
    let (f9, sw) = card.metadata(0xF9);
    assert_eq!(sw, 0x9000);
    assert_eq!(f9[..14], hex("010111 02020101 030101 0443 8641")[..]);
    assert_eq!(f9[14], 0x04, "uncompressed point");
    assert_eq!(f9.len(), 14 + 65);
    assert_eq!(card.metadata(0x00).1, 0x6A86);
    assert_eq!(card.metadata(0x96).1, 0x6A86);
    assert_eq!(card.cmd(0xF7, 0x01, 0x80, &[], None).1, 0x6A86);
}

#[test]
fn metadata_tracks_retries() {
    let mut card = Card::new();
    card.verify_pin(&pad(b"000000"));
    assert_eq!(card.metadata(0x80).0, hex("0101FF 050101 06020302"));
}

#[test]
fn set_pin_retries_requires_management_key_and_pin() {
    let mut card = Card::new();
    let base = card.host.persist_count();
    assert_eq!(card.send("00FA0505").1, 0x6982);
    card.auth_default();
    assert_eq!(card.send("00FA0505").1, 0x6982, "PIN not verified");
    card.piv.deselect();
    card.verify_default_pin();
    assert_eq!(card.send("00FA0505").1, 0x6982, "management key not authenticated");
    assert_eq!(card.host.persist_count(), base + 2, "only the VERIFY commits");
}

#[test]
fn set_pin_retries_sets_limits_and_resets_pin_and_puk() {
    // Yubico: SET PIN RETRIES also resets the PIN and PUK to their defaults.
    let mut card = Card::new();
    let mut change = hex(DEFAULT_PIN);
    change.extend_from_slice(&pad(b"246810"));
    assert_eq!(card.cmd(0x24, 0x00, 0x80, &change, None).1, 0x9000);
    let mut change = hex(DEFAULT_PUK);
    change.extend_from_slice(&pad(b"24681012"));
    assert_eq!(card.cmd(0x24, 0x00, 0x81, &change, None).1, 0x9000);
    card.auth_default();
    assert_eq!(card.verify_pin(&pad(b"246810")), 0x9000);
    assert_eq!(card.send("00FA050A").1, 0x9000);
    assert_eq!(card.pin_status(), 0x63C5, "PIN no longer verified");
    assert_eq!(card.metadata(0x80).0, hex("0101FF 050101 06020505"));
    assert_eq!(card.metadata(0x81).0, hex("0101FF 050101 06020A0A"));
    card.verify_default_pin();
    card.restart();
    assert_eq!(card.metadata(0x81).0, hex("0101FF 050101 06020A0A"));
}

#[test]
fn retry_limits_span_1_to_255_with_saturated_status() {
    // Profile: retry_limits [1, 255], status_retries_saturate_at 15, metadata_retries_bits 8.
    let mut card = Card::new();
    card.auth_default();
    card.verify_default_pin();
    assert_eq!(card.send("00FAFFFF").1, 0x9000);
    assert_eq!(card.pin_status(), 0x63CF);
    assert_eq!(card.verify_pin(&pad(b"000000")), 0x63CF, "254 left, saturated");
    assert_eq!(card.metadata(0x80).0, hex("0101FF 050101 0602FFFE"));
    card.restart();
    assert_eq!(card.metadata(0x80).0, hex("0101FF 050101 0602FFFE"), "eight bits across restart");
    assert_eq!(card.metadata(0x81).0, hex("0101FF 050101 0602FFFF"));
    // A limit of one blocks on the first wrong PIN.
    card.auth_default();
    card.verify_default_pin();
    assert_eq!(card.send("00FA0101").1, 0x9000);
    assert_eq!(card.pin_status(), 0x63C1);
    assert_eq!(card.verify_pin(&pad(b"000000")), 0x63C0);
    assert_eq!(card.pin_status(), 0x6983);
}

#[test]
fn set_pin_retries_guards() {
    // Catalog: malformed SET PIN RETRIES Le is rejected before changing PIN/PUK state.
    let mut card = Card::new();
    card.auth_default();
    card.verify_default_pin();
    let count = card.host.persist_count();
    assert_eq!(card.send("00FA0005").1, 0x6A86);
    assert_eq!(card.send("00FA0500").1, 0x6A86);
    assert_eq!(card.send("00FA050501").1, 0x6700, "explicit Le");
    assert_eq!(card.send("00FA05050000").1, 0x6700, "malformed length");
    assert_eq!(card.send("00FA0505000001").1, 0x6700, "extended Le");
    assert_eq!(card.send("00FA05050101").1, 0x6700, "command data");
    assert_eq!(card.host.persist_count(), count);
    assert_eq!(card.metadata(0x80).0, hex("0101FF 050101 06020303"));
}

#[test]
fn case_1_commands_accept_the_t0_p3_form() {
    // ISO/IEC 7816-3 §12.2.2: a case 1 command over T=0 is CLA INS P1 P2 00; this is how
    // yubico-piv-tool sends SET PIN RETRIES and RESET.
    let mut card = Card::new();
    card.auth_default();
    card.verify_default_pin();
    assert_eq!(card.send("00FA040400").1, 0x9000);
    assert_eq!(card.metadata(0x80).0, hex("0101FF 050101 06020404"));
    block_pin_and_puk(&mut card);
    assert_eq!(card.send("00FB000000").1, 0x9000);
    assert_eq!(card.metadata(0x80).0, hex("0101FF 050101 06020303"));
}

#[test]
fn case_1_commands_accept_the_extended_zero_length_form() {
    // python yubikit encodes data-less extended APDUs as CLA INS P1 P2 00 00 00 (an
    // extended Lc of zero, which ISO/IEC 7816-4 §5.1 does not allow and which parses as
    // case 2E with Le 0000).
    let mut card = Card::new();
    assert_eq!(card.send("00FD0000000000"), (hex("050704"), 0x9000));
    assert_eq!(card.send("00F80000000000"), (hex("00BC614E"), 0x9000));
    card.auth_default();
    card.verify_default_pin();
    assert_eq!(card.send("00FA0606000000").1, 0x9000);
    assert_eq!(card.metadata(0x81).0, hex("0101FF 050101 06020606"));
    block_pin_and_puk(&mut card);
    assert_eq!(card.send("00FB0000000000").1, 0x9000);
    assert_eq!(card.metadata(0x81).0, hex("0101FF 050101 06020303"));
}

/// Exhaust the PIN and PUK retry counters, whatever their limits.
fn block_pin_and_puk(card: &mut Card) {
    while card.verify_pin(&pad(b"000000")) != 0x6983 {}
    let mut data = pad(b"00000000");
    data.extend_from_slice(&pad(b"000000"));
    while card.cmd(0x2C, 0x00, 0x80, &data, None).1 != 0x6983 {}
    assert_eq!(card.pin_status(), 0x6983);
    assert_eq!(card.metadata(0x81).0.last(), Some(&0), "no PUK retries left");
}

#[test]
fn reset_requires_blocked_pin_and_puk() {
    let mut card = Card::new();
    assert_eq!(card.send("00FB0000").1, 0x6985);
    for _ in 0..3 {
        card.verify_pin(&pad(b"000000"));
    }
    assert_eq!(card.send("00FB0000").1, 0x6985, "PUK still usable");
    let mut card = Card::new();
    let mut data = pad(b"00000000");
    data.extend_from_slice(&pad(b"000000"));
    for _ in 0..3 {
        card.cmd(0x2C, 0x00, 0x80, &data, None);
    }
    assert_eq!(card.send("00FB0000").1, 0x6985, "PIN still usable");
}

#[test]
fn malformed_reset_is_rejected_before_erasing() {
    // Catalog: malformed RESET P1/P2, command data or explicit Le are rejected before
    // erasing keys or retries.
    let mut card = Card::new();
    card.auth_default();
    assert_eq!(card.put_object(0x5FC102, &[0x30, 0x01]), 0x9000);
    block_pin_and_puk(&mut card);
    let persisted = card.host.persisted(Record::Piv);
    for (apdu, sw) in [
        ("00FB0100", 0x6A86),
        ("00FB0001", 0x6A86),
        ("00FBFFFF", 0x6A86),
        ("00FB000001AA", 0x6700),
        ("00FB000001", 0x6700),
        ("00FB0000000100", 0x6700),
        ("00FB00000000", 0x6700),
    ] {
        assert_eq!(card.send(apdu).1, sw, "{apdu}");
    }
    assert_eq!(card.host.persisted(Record::Piv), persisted, "nothing erased");
    assert_eq!(card.pin_status(), 0x6983);
    card.restart();
    assert_eq!(card.pin_status(), 0x6983);
}

#[test]
fn reset_restores_factory_state_but_keeps_attestation_certificate() {
    // Catalog: F9 key/certificate retained through PIV reset; profile
    // piv_reset_preserves_current_f9_key_and_certificate.
    let mut card = Card::new();
    card.auth_default();
    let key = hex("000102030405060708090a0b0c0d0e0f");
    assert_eq!(card.set_mgmt_key(0x08, &key, true), 0x9000);
    assert_eq!(card.put_object(0x5FC102, &[0x30, 0x01]), 0x9000);
    assert_eq!(card.put_object(0x5FFF01, &[0x70, 0x01, 0x00]), 0x9000);
    assert_eq!(card.put_object(0x5FC109, &[0x88, 0x00]), 0x9000);
    card.verify_default_pin();
    assert_eq!(card.send("00FA0707").1, 0x9000);
    block_pin_and_puk(&mut card);
    assert_eq!(card.send("00FB0000").1, 0x9000);
    // Factory credentials, limits and management key.
    assert_eq!(card.metadata(0x80).0, hex("0101FF 050101 06020303"));
    assert_eq!(card.metadata(0x81).0, hex("0101FF 050101 06020303"));
    assert_eq!(card.metadata(0x9B).0, hex("01010A 02020001 050101"));
    card.verify_default_pin();
    card.auth_default();
    assert_eq!(card.get_object(0x5FC102).1, 0x6A82);
    assert_eq!(card.get_object(0x5FC109).1, 0x6A82);
    assert_eq!(card.object_value(0x5FFF01), Some(vec![0x70, 0x01, 0x00]));
    card.restart();
    assert_eq!(card.object_value(0x5FFF01), Some(vec![0x70, 0x01, 0x00]));
    assert_eq!(card.get_object(0x5FC102).1, 0x6A82);
}

#[test]
fn reset_clears_session_authorizations() {
    let mut card = Card::new();
    card.auth_default();
    block_pin_and_puk(&mut card);
    assert_eq!(card.send("00FB0000").1, 0x9000);
    assert_eq!(card.put_object(0x5FC102, &[0x30, 0x00]), 0x6982);
    assert_eq!(card.pin_status(), 0x63C3);
}

#[test]
fn reset_storage_failure_keeps_blocked_state() {
    let mut card = Card::new();
    card.auth_default();
    assert_eq!(card.put_object(0x5FC102, &[0x30, 0x01]), 0x9000);
    block_pin_and_puk(&mut card);
    card.host.fail_next_saves(1);
    assert_eq!(card.send("00FB0000").1, 0x6581);
    assert_eq!(card.pin_status(), 0x6983);
    card.auth_default();
    assert_eq!(card.object_value(0x5FC102), Some(vec![0x30, 0x01]));
}

#[test]
fn unreadable_record_starts_from_factory_state() {
    // docs/CONTRACTS.md: unreadable state means factory state.
    for stored in [vec![], vec![0x02], vec![0x01, 0x01], vec![0x01, 0x01, 0x08, 0x31], vec![0xFF; 40]] {
        let mut host = TestHost::new();
        host.set_persisted(Record::Piv, &stored);
        let mut card = Card::with_host(host);
        assert_eq!(card.metadata(0x80).0, hex("0101FF 050101 06020303"), "{stored:02X?}");
        card.auth_default();
    }
}

#[test]
fn factory_state_is_persisted_once_with_its_attestation_material() {
    // The own F9 key and certificate are created before first use and persisted at once
    // (profile piv_allocation_model.attestation_initialization), so they are the same
    // after a restart; nothing else is written until a change.
    let mut card = Card::new();
    assert_eq!(card.host.persist_attempts(), 1);
    let stored = card.host.persisted(Record::Piv).unwrap();
    assert_eq!(stored[0], 0x01, "format version byte");
    let certificate = card.object_value(0x5FFF01).unwrap();
    let f9 = card.metadata(0xF9).0;
    assert_eq!(card.send("00FD0000").1, 0x9000);
    card.auth_default();
    assert_eq!(card.host.persist_attempts(), 1);
    card.restart();
    assert_eq!(card.host.persist_attempts(), 1, "a restored record is not rewritten");
    assert_eq!(card.object_value(0x5FFF01), Some(certificate));
    assert_eq!(card.metadata(0xF9).0, f9);
    card.auth_default();
    assert_eq!(card.put_object(0x5FC102, &[0x30, 0x00]), 0x9000);
    assert_eq!(card.host.persist_attempts(), 2);
}
