//! TERMINATE DF (spec §7.2.16) and ACTIVATE FILE (spec §7.2.17).

use lk_core::Record;

use crate::common::{Card, hex};

/// TERMINATE DF needs PW3 verified (or PW3 blocked).
#[test]
fn terminate_requires_pw3() {
    let mut card = Card::new();
    assert_eq!(card.send(&hex("00E60000")).1, 0x6982);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    assert_eq!(card.send(&hex("00E60000")).1, 0x6982);
    card.admin();
    assert_eq!(card.send(&hex("00E60000")).1, 0x9000);
}

/// The YubiKit / GnuPG factory reset: block PW3 with wrong presentations, then TERMINATE
/// DF without verification and ACTIVATE FILE.
#[test]
fn blocked_pw3_terminate_and_activate_resets() {
    let mut card = Card::new();
    card.admin();
    assert_eq!(card.put(0x005B, b"Doe<<John"), 0x9000);
    assert_eq!(card.put(0x00D3, b"resetcode"), 0x9000);
    assert_eq!(card.put(0x00C1, &hex("16 2b06010401da470f01")), 0x9000);
    assert_eq!(card.apdu(0x00, 0x24, 0x00, 0x83, b"12345678otheradmin", None).1, 0x9000);
    card.select();
    for _ in 0..3 {
        card.verify(0x83, b"00000000");
    }
    for _ in 0..3 {
        card.verify(0x82, b"000000");
    }
    assert_eq!(card.send(&hex("00E60000")).1, 0x9000);
    assert_eq!(card.send(&hex("00440000")).1, 0x9000);
    assert_eq!(card.select(), 0x9000);
    assert_eq!(card.retries(), [3, 0, 3]);
    assert_eq!(card.get_ok(0x005B), b"");
    assert_eq!(card.get_ok(0x00C1), hex("010800001100"));
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    card.admin();
}

/// ISO 7816-4 §5.1.3 6285: while terminated, SELECT and every command except ACTIVATE
/// FILE answer 6285, also after a restart.
#[test]
fn terminated_state_answers_6285() {
    let mut card = Card::new();
    card.admin();
    assert_eq!(card.send(&hex("00E60000")).1, 0x9000);
    assert_eq!(card.get(0x006E), (vec![], 0x6285));
    assert_eq!(card.verify(0x83, b"12345678"), 0x6285);
    assert_eq!(card.send(&hex("0084000008")).1, 0x6285);
    assert_eq!(card.select(), 0x6285);
    card.reload();
    assert_eq!(card.select(), 0x6285);
    assert_eq!(card.send(&hex("00F1000000")).1, 0x6285);
    // ACTIVATE header rules still apply.
    assert_eq!(card.send(&hex("00440100")).1, 0x6A86);
    assert_eq!(card.send(&hex("0044000001")).1, 0x6700);
    assert_eq!(card.send(&hex("00440000")).1, 0x9000);
    assert_eq!(card.select(), 0x9000);
    card.reload();
    assert_eq!(card.select(), 0x9000);
    card.admin();
}

/// Catalog: "Operational ACTIVATE FILE succeeds without semantic state change or lazy
/// attestation creation; terminated ACTIVATE still resets".
#[test]
fn operational_activate_is_noop() {
    let mut card = Card::new();
    card.admin();
    assert_eq!(card.put(0x005B, b"Doe<<John"), 0x9000);
    let issuer_certificate = card.get_ok(0x00FC);
    let issuer_public = card.public_key(crate::common::crt::ATT);
    let persisted = card.host.persisted(Record::OpenPgp);
    let count = card.host.persist_count();
    assert_eq!(card.send(&hex("00440000")).1, 0x9000);
    assert_eq!(card.host.persist_count(), count);
    assert_eq!(card.host.persisted(Record::OpenPgp), persisted);
    assert_eq!(card.get_ok(0x005B), b"Doe<<John");
    // The PW3 verification also survives.
    assert_eq!(card.verify(0x83, b""), 0x9000);
    // No attestation material is created or replaced.
    assert_eq!(card.get_ok(0x00FC), issuer_certificate);
    assert_eq!(card.public_key(crate::common::crt::ATT), issuer_public);
}

/// Catalog OpenPGP_attestation: "app reset retains current independent ATT key/certificate,
/// attributes and modeled metadata".
#[test]
fn activate_retains_attestation_slot() {
    let mut card = Card::new();
    card.admin();
    assert_eq!(card.put(0x00FC, b"att-cert"), 0x9000);
    assert_eq!(card.put(0x00DA, &hex("13 2a8648ce3d030107")), 0x9000);
    assert_eq!(card.put(0x00DB, &[0xAB; 20]), 0x9000);
    assert_eq!(card.put(0x00DC, &[0xCD; 20]), 0x9000);
    assert_eq!(card.put(0x00DD, &[1, 2, 3, 4]), 0x9000);
    assert_eq!(card.put(0x00D9, &[0x02, 0x20]), 0x9000);
    assert_eq!(card.put(0x00D6, &[0x02, 0x20]), 0x9000);
    assert_eq!(card.put(0x00C7, &[0x11; 20]), 0x9000);
    assert_eq!(card.send(&hex("00E60000")).1, 0x9000);
    assert_eq!(card.send(&hex("00440000")).1, 0x9000);
    card.select();
    assert_eq!(card.get_ok(0x00FC), b"att-cert");
    assert_eq!(card.get_ok(0x00DA), hex("13 2a8648ce3d030107"));
    assert_eq!(card.get_ok(0x00D9), vec![0x02, 0x20]);
    assert_eq!(card.get_ok(0x00D6), vec![0x00, 0x20]);
    let c5 = card.get_ok(0x00C5);
    assert_eq!(&c5[..20], &[0; 20]);
    assert_eq!(&c5[60..], &[0xAB; 20]);
    assert_eq!(&card.get_ok(0x00C6)[60..], &[0xCD; 20]);
    assert_eq!(&card.get_ok(0x00CD)[12..], &[1, 2, 3, 4]);
}

/// Catalog: lifecycle explicit-Le guards; spec §7.2.16-§7.2.17 headers.
#[test]
fn lifecycle_header_rules() {
    let mut card = Card::new();
    card.admin();
    assert_eq!(card.send(&hex("00E6000001")).1, 0x6700);
    assert_eq!(card.send(&hex("00E60100")).1, 0x6A86);
    assert_eq!(card.send(&hex("00E6000001AA")).1, 0x6700);
    assert_eq!(card.send(&hex("0044000001")).1, 0x6700);
    assert_eq!(card.send(&hex("00440001")).1, 0x6A86);
    assert_eq!(card.verify(0x83, b""), 0x9000);
    assert_eq!(card.send(&hex("00E6000000")).1, 0x9000);
}

/// TERMINATE and ACTIVATE persist before success; a failed save changes nothing.
#[test]
fn lifecycle_storage_failure() {
    let mut card = Card::new();
    card.admin();
    card.host.fail_next_saves(1);
    assert_eq!(card.send(&hex("00E60000")).1, 0x6581);
    assert_eq!(card.get(0x5F52).1, 0x9000);
    assert_eq!(card.send(&hex("00E60000")).1, 0x9000);
    card.host.fail_next_saves(1);
    assert_eq!(card.send(&hex("00440000")).1, 0x6581);
    assert_eq!(card.select(), 0x6285);
    assert_eq!(card.send(&hex("00440000")).1, 0x9000);
    assert_eq!(card.select(), 0x9000);
}

/// Catalog OpenPGP_attestation: a deliberately deleted attestation certificate is not
/// resurrected by the application reset.
#[test]
fn deleted_attestation_certificate_not_restored() {
    let mut card = Card::new();
    card.admin();
    assert_eq!(card.put(0x00FC, b"att-cert"), 0x9000);
    assert_eq!(card.put(0x00FC, b""), 0x9000);
    assert_eq!(card.send(&hex("00E60000")).1, 0x9000);
    assert_eq!(card.send(&hex("00440000")).1, 0x9000);
    card.reload();
    assert_eq!(card.get_ok(0x00FC), b"");
}

/// Catalog OpenPGP_attestation: "PIV issuer and OATH private key/durable HOTP state survive
/// OpenPGP reset". The applet only ever writes `Record::OpenPgp`.
#[test]
fn reset_leaves_other_records() {
    let mut card = Card::new();
    card.host.set_persisted(Record::Piv, b"piv-state");
    card.host.set_persisted(Record::Oath, b"oath-state");
    card.admin();
    assert_eq!(card.send(&hex("00E60000")).1, 0x9000);
    assert_eq!(card.send(&hex("00440000")).1, 0x9000);
    assert_eq!(card.host.persisted(Record::Piv), Some(b"piv-state".to_vec()));
    assert_eq!(card.host.persisted(Record::Oath), Some(b"oath-state".to_vec()));
}
