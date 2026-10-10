//! GET DATA / PUT DATA access rules and limits, SELECT DATA / GET NEXT DATA.

use lk_codec::tlv;

use crate::common::{Card, hex};

/// Cardholder data 65 (spec §4.4.3.2-§4.4.3.5) after PUT DATA of 5B, 5F2D, 5F35.
#[test]
fn put_get_cardholder_data() {
    let mut card = Card::new();
    card.admin();
    assert_eq!(card.put(0x005B, b"Doe<<John"), 0x9000);
    assert_eq!(card.put(0x5F2D, b"ende"), 0x9000);
    assert_eq!(card.put(0x5F35, b"1"), 0x9000);
    let data = card.get_ok(0x0065);
    let (outer, _) = tlv::parse_one(&data).unwrap();
    assert_eq!(outer.tag, 0x65);
    let inner = outer.children().unwrap();
    assert_eq!(inner.iter().map(|t| t.tag).collect::<Vec<_>>(), vec![0x5B, 0x5F2D, 0x5F35]);
    assert_eq!(inner[0].value, b"Doe<<John");
    assert_eq!(inner[1].value, b"ende");
    assert_eq!(inner[2].value, b"1");
    assert_eq!(card.get_ok(0x005B), b"Doe<<John");
    assert_eq!(card.get_ok(0x5F2D), b"ende");
    assert_eq!(card.get_ok(0x5F35), b"1");
}

/// Catalog: "name 39, language eight bytes in pairs, ASCII sex" checks.
#[test]
fn name_language_sex_checks() {
    let mut card = Card::new();
    card.admin();
    assert_eq!(card.put(0x005B, &[b'a'; 39]), 0x9000);
    assert_eq!(card.put(0x005B, &[b'a'; 40]), 0x6700);
    assert_eq!(card.put(0x5F2D, b"enfrdeit"), 0x9000);
    assert_eq!(card.put(0x5F2D, b"enfrdeitx"), 0x6700);
    assert_eq!(card.put(0x5F2D, b"enf"), 0x6700);
    assert_eq!(card.put(0x5F2D, b""), 0x9000);
    for ok in [b"0", b"1", b"2", b"9"] {
        assert_eq!(card.put(0x5F35, ok), 0x9000);
    }
    assert_eq!(card.put(0x5F35, b"3"), 0x6A80);
    assert_eq!(card.put(0x5F35, &[0x01]), 0x6A80);
    assert_eq!(card.put(0x5F35, b"12"), 0x6700);
    assert_eq!(card.put(0x5F35, b""), 0x6700);
    assert_eq!(card.get_ok(0x005B), vec![b'a'; 39]);
    assert_eq!(card.get_ok(0x5F35), b"9");
}

/// Catalog: 255-byte special-object ceiling (C0 bytes 7-8) for URL, login and private DOs.
#[test]
fn special_do_limit() {
    let mut card = Card::new();
    card.admin();
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    for tag in [0x5F50, 0x005E, 0x0101, 0x0102, 0x0103, 0x0104] {
        assert_eq!(card.put(tag, &[0x41; 255]), 0x9000, "{tag:04X}");
        assert_eq!(card.put(tag, &[0x41; 256]), 0x6700, "{tag:04X}");
        assert_eq!(card.get_ok(tag), vec![0x41; 255]);
    }
    assert_eq!(card.put(0x5F50, b""), 0x9000);
    assert_eq!(card.get_ok(0x5F50), b"");
}

/// Catalog: "private-use write access requires PW1 reference 82 or PW3; protected reads
/// remain PIN scoped" (spec §4.4.1: 0101/0103 write PW1-82, 0102/0104 write PW3;
/// 0103 read PW1-82, 0104 read PW3).
#[test]
fn private_do_access_rules() {
    let mut card = Card::new();
    // Nothing verified.
    for tag in [0x0101, 0x0102, 0x0103, 0x0104] {
        assert_eq!(card.put(tag, b"x"), 0x6982, "{tag:04X}");
    }
    assert_eq!(card.get(0x0101), (vec![], 0x9000));
    assert_eq!(card.get(0x0102), (vec![], 0x9000));
    assert_eq!(card.get(0x0103), (vec![], 0x6982));
    assert_eq!(card.get(0x0104), (vec![], 0x6982));

    // PW3 alone writes 0102/0104 but not 0101/0103.
    card.admin();
    assert_eq!(card.put(0x0101, b"one"), 0x6982);
    assert_eq!(card.put(0x0103, b"three"), 0x6982);
    assert_eq!(card.put(0x0102, b"two"), 0x9000);
    assert_eq!(card.put(0x0104, b"four"), 0x9000);
    assert_eq!(card.get(0x0104), (b"four".to_vec(), 0x9000));
    assert_eq!(card.get(0x0103), (vec![], 0x6982));

    // PW1 in mode 81 is not enough; mode 82 is.
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert_eq!(card.put(0x0101, b"one"), 0x6982);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    assert_eq!(card.put(0x0101, b"one"), 0x9000);
    assert_eq!(card.put(0x0103, b"three"), 0x9000);
    assert_eq!(card.get(0x0103), (b"three".to_vec(), 0x9000));

    // After reselection the public ones stay readable, the protected ones do not.
    card.select();
    assert_eq!(card.get(0x0101), (b"one".to_vec(), 0x9000));
    assert_eq!(card.get(0x0102), (b"two".to_vec(), 0x9000));
    assert_eq!(card.get(0x0103), (vec![], 0x6982));
    assert_eq!(card.get(0x0104), (vec![], 0x6982));
    assert_eq!(card.put(0x0102, b"x"), 0x6982);
}

/// PUT DATA of the cardholder objects needs PW3 (spec §4.4.1).
#[test]
fn put_requires_pw3() {
    let mut card = Card::new();
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    for tag in [0x005B, 0x005E, 0x5F2D, 0x5F35, 0x5F50, 0x7F21, 0x00C1, 0x00C7, 0x00CA, 0x00CE, 0x00D6, 0x00F9, 0x00FC] {
        assert_eq!(card.put(tag, b"x"), 0x6982, "{tag:04X}");
    }
}

/// Catalog: "fingerprint 20 and generation-time four-byte checks"; spec §4.4.3.9 C5/C6/CD
/// and the DB/DC/DD attestation objects.
#[test]
fn fingerprint_and_generation_time_checks() {
    let mut card = Card::new();
    card.admin();
    let tags = [(0x00C7, 0x00CA, 0x00CE), (0x00C8, 0x00CB, 0x00CF), (0x00C9, 0x00CC, 0x00D0), (0x00DB, 0x00DC, 0x00DD)];
    for (i, (fp, ca, time)) in tags.into_iter().enumerate() {
        let n = i as u8 + 1;
        assert_eq!(card.put(fp, &[n; 19]), 0x6700);
        assert_eq!(card.put(fp, &[n; 21]), 0x6700);
        assert_eq!(card.put(fp, &[n; 20]), 0x9000);
        assert_eq!(card.put(ca, &[n + 0x10; 20]), 0x9000);
        assert_eq!(card.put(ca, &[n; 4]), 0x6700);
        assert_eq!(card.put(time, &[n; 3]), 0x6700);
        assert_eq!(card.put(time, &[n, 0, 0, n]), 0x9000);
    }
    let c5 = card.get_ok(0x00C5);
    assert_eq!(c5.len(), 80);
    assert_eq!(&c5[..20], &[1; 20]);
    assert_eq!(&c5[60..], &[4; 20]);
    let c6 = card.get_ok(0x00C6);
    assert_eq!(&c6[20..40], &[0x12; 20]);
    let cd = card.get_ok(0x00CD);
    assert_eq!(cd, vec![1, 0, 0, 1, 2, 0, 0, 2, 3, 0, 0, 3, 4, 0, 0, 4]);
    // The same values inside 6E/73.
    let app = card.get_ok(0x006E);
    let (outer, _) = tlv::parse_one(&app).unwrap();
    let top = outer.children().unwrap();
    let disc = tlv::find(&top, 0x73).unwrap().children().unwrap();
    assert_eq!(tlv::find(&disc, 0xC5).unwrap().value, c5.as_slice());
    assert_eq!(tlv::find(&disc, 0xC6).unwrap().value, c6.as_slice());
    assert_eq!(tlv::find(&disc, 0xCD).unwrap().value, cd.as_slice());
}

/// Catalog: "read-only and undeclared PUT rejection".
#[test]
fn read_only_and_undeclared_put_rejected() {
    let mut card = Card::new();
    card.admin();
    for tag in [
        0x004F, 0x5F52, 0x7F66, 0x7F74, 0x0065, 0x006E, 0x0073, 0x007A, 0x0093, 0x00C0, 0x00C5, 0x00C6,
        0x00CD, 0x00DE, 0x00FA, 0x0105, 0x00D1, 0x00D2, 0x00D5, 0x1234,
    ] {
        assert_eq!(card.put(tag, &[0; 4]), 0x6B00, "{tag:04X}");
    }
    // Undeclared GET DATA tags and the resetting code.
    for tag in [0x00D3, 0x0093, 0x0073, 0x00D1, 0x0105, 0x1234] {
        assert_eq!(card.get(tag), (vec![], 0x6B00), "{tag:04X}");
    }
}

/// Algorithm attributes C1/C2/C3/DA accept exactly the slot's FA entries (spec §4.4.3.10,
/// §4.4.3.13); the 6E record follows.
#[test]
fn algorithm_attributes_put() {
    let mut card = Card::new();
    card.admin();
    let ed25519 = hex("16 2b06010401da470f01");
    let x25519 = hex("12 2b060104019755010501");
    let p256_ecdsa = hex("13 2a8648ce3d030107");
    let rsa4096 = hex("01 1000 0011 00");
    assert_eq!(card.put(0x00C1, &ed25519), 0x9000);
    assert_eq!(card.put(0x00C2, &x25519), 0x9000);
    assert_eq!(card.put(0x00C3, &p256_ecdsa), 0x9000);
    assert_eq!(card.put(0x00DA, &rsa4096), 0x9000);
    assert_eq!(card.put(0x00C1, &x25519), 0x6A80);
    assert_eq!(card.put(0x00DA, &ed25519), 0x6A80);
    assert_eq!(card.put(0x00C2, &ed25519), 0x6A80);
    assert_eq!(card.put(0x00C1, &hex("01 0400 0011 00")), 0x6A80);
    assert_eq!(card.put(0x00C1, b""), 0x6A80);
    let mut with_pubkey_flag = p256_ecdsa.clone();
    with_pubkey_flag.push(0xFF);
    assert_eq!(card.put(0x00C3, &with_pubkey_flag), 0x9000);
    assert_eq!(card.get_ok(0x00C1), ed25519);
    let app = card.get_ok(0x006E);
    let (outer, _) = tlv::parse_one(&app).unwrap();
    let top = outer.children().unwrap();
    let disc = tlv::find(&top, 0x73).unwrap().children().unwrap();
    assert_eq!(tlv::find(&disc, 0xC1).unwrap().value, ed25519.as_slice());
    assert_eq!(tlv::find(&disc, 0xC2).unwrap().value, x25519.as_slice());
    assert_eq!(tlv::find(&disc, 0xC3).unwrap().value, with_pubkey_flag.as_slice());
    assert_eq!(tlv::find(&disc, 0xDA).unwrap().value, rsa4096.as_slice());
    card.reload();
    assert_eq!(card.get_ok(0x00C2), x25519);
}

/// UIF D6-D9 (Yubico touch policy): values 00-04 with the button byte 20; a fixed policy
/// cannot be changed.
#[test]
fn uif_put_rules() {
    let mut card = Card::new();
    card.admin();
    assert_eq!(card.put(0x00D6, &[0x01, 0x20]), 0x9000);
    assert_eq!(card.get_ok(0x00D6), vec![0x01, 0x20]);
    assert_eq!(card.put(0x00D6, &[0x05, 0x20]), 0x6A80);
    assert_eq!(card.put(0x00D6, &[0x01, 0x00]), 0x6A80);
    assert_eq!(card.put(0x00D6, &[0x01]), 0x6700);
    assert_eq!(card.put(0x00D7, &[0x02, 0x20]), 0x9000);
    assert_eq!(card.put(0x00D7, &[0x00, 0x20]), 0x6982);
    assert_eq!(card.put(0x00D7, &[0x02, 0x20]), 0x9000);
    assert_eq!(card.put(0x00D8, &[0x04, 0x20]), 0x9000);
    assert_eq!(card.put(0x00D8, &[0x03, 0x20]), 0x6982);
    assert_eq!(card.put(0x00D9, &[0x03, 0x20]), 0x9000);
    assert_eq!(card.get_ok(0x00D9), vec![0x03, 0x20]);
}

/// Catalog: four certificate occurrences. spec §7.2.5 SELECT DATA picks the occurrence of
/// 7F21 (0 AUT, 1 DEC, 2 SIG; 3 is the attestation certificate, also FC); GET NEXT DATA
/// (spec §7.2.7) walks them.
#[test]
fn certificate_occurrences() {
    let mut card = Card::new();
    card.admin();
    // Occurrence 0 is selected by default.
    assert_eq!(card.put(0x7F21, b"cert-aut"), 0x9000);
    for (occurrence, value) in [(1u8, &b"cert-dec"[..]), (2, b"cert-sig"), (3, b"cert-att")] {
        assert_eq!(card.select_occurrence(occurrence), 0x9000);
        assert_eq!(card.put(0x7F21, value), 0x9000);
    }
    assert_eq!(card.get_ok(0x00FC), b"cert-att");
    assert_eq!(card.select_occurrence(0), 0x9000);
    assert_eq!(card.get_ok(0x7F21), b"cert-aut");
    assert_eq!(card.send(&hex("00CC7F2100")), (b"cert-dec".to_vec(), 0x9000));
    assert_eq!(card.send(&hex("00CC7F2100")), (b"cert-sig".to_vec(), 0x9000));
    assert_eq!(card.send(&hex("00CC7F2100")), (b"cert-att".to_vec(), 0x9000));
    assert_eq!(card.get_ok(0x7F21), b"cert-att");
    // FC writes the same certificate.
    assert_eq!(card.put(0x00FC, b"att-2"), 0x9000);
    assert_eq!(card.get_ok(0x7F21), b"att-2");
    // SELECT resets the selection to occurrence 0.
    card.select();
    assert_eq!(card.get_ok(0x7F21), b"cert-aut");
    card.reload();
    assert_eq!(card.select_occurrence(2), 0x9000);
    assert_eq!(card.get_ok(0x7F21), b"cert-sig");
}

/// spec §7.2.5 syntax; catalog: "SELECT DATA rejects explicit Le=1 with 6700 before
/// changing the selected certificate occurrence; absent or zero Le remain valid".
#[test]
fn select_data_syntax() {
    let mut card = Card::new();
    card.admin();
    assert_eq!(card.put(0x7F21, b"cert-aut"), 0x9000);
    let list = hex("6004 5C02 7F21");
    assert_eq!(card.apdu(0x00, 0xA5, 0x01, 0x04, &list, Some(1)).1, 0x6700);
    assert_eq!(card.get_ok(0x7F21), b"cert-aut");
    assert_eq!(card.apdu(0x00, 0xA5, 0x01, 0x05, &list, None).1, 0x6A86);
    assert_eq!(card.apdu(0x00, 0xA5, 0x04, 0x04, &list, None).1, 0x6A86);
    assert_eq!(card.apdu(0x00, 0xA5, 0x01, 0x04, &hex("6004 5C02 7F22"), None).1, 0x6A88);
    assert_eq!(card.apdu(0x00, 0xA5, 0x01, 0x04, &hex("6003 5C02 7F"), None).1, 0x6A80);
    assert_eq!(card.apdu(0x00, 0xA5, 0x01, 0x04, &hex("06 6004 5C02 7F21"), None).1, 0x6A80);
    assert_eq!(card.apdu(0x00, 0xA5, 0x01, 0x04, &hex("6104 5C02 7F21"), None).1, 0x6A80);
    assert_eq!(card.apdu(0x00, 0xA5, 0x01, 0x04, b"", None).1, 0x6A80);
    assert_eq!(card.get_ok(0x7F21), b"cert-aut");
    // Absent and zero Le select.
    assert_eq!(card.apdu(0x00, 0xA5, 0x01, 0x04, &list, Some(0)).1, 0x9000);
    assert_eq!(card.get_ok(0x7F21), b"");
    assert_eq!(card.apdu(0x00, 0xA5, 0x00, 0x04, &list, None).1, 0x9000);
    assert_eq!(card.get_ok(0x7F21), b"cert-aut");
}

/// Catalog: "GET NEXT DATA with unexpected command data returns 6700 before advancing".
#[test]
fn get_next_data_with_data_rejected() {
    let mut card = Card::new();
    card.admin();
    assert_eq!(card.put(0x7F21, b"cert-aut"), 0x9000);
    assert_eq!(card.send(&hex("00CC7F21 01 00")).1, 0x6700);
    assert_eq!(card.get_ok(0x7F21), b"cert-aut");
    assert_eq!(card.send(&hex("00CC5F5000")).1, 0x6B00);
    assert_eq!(card.get_ok(0x7F21), b"cert-aut");
}

/// Catalog: "Exhausted GET NEXT DATA returns 6A88 without clearing the current certificate
/// occurrence, preventing subsequent PUT DATA from writing an unreachable object".
#[test]
fn exhausted_get_next_data_keeps_selection() {
    let mut card = Card::new();
    card.admin();
    assert_eq!(card.select_occurrence(3), 0x9000);
    assert_eq!(card.send(&hex("00CC7F2100")), (vec![], 0x6A88));
    assert_eq!(card.send(&hex("00CC7F2100")), (vec![], 0x6A88));
    assert_eq!(card.put(0x7F21, b"still-att"), 0x9000);
    assert_eq!(card.get_ok(0x00FC), b"still-att");
}

/// Catalog: "observed ... 2048-byte certificate" ceiling (C0 bytes 5-6), written with
/// command chaining (ISO 7816-4 §5.1.1.1) and with one extended APDU.
#[test]
fn certificate_size_limit() {
    let mut card = Card::new();
    card.admin();
    let cert: Vec<u8> = (0..2048u32).map(|i| i as u8).collect();
    // Chained short APDUs.
    for (i, part) in cert.chunks(255).enumerate() {
        let last = (i + 1) * 255 >= cert.len();
        let cla = if last { 0x00 } else { 0x10 };
        assert_eq!(card.apdu(cla, 0xDA, 0x7F, 0x21, part, None).1, 0x9000);
    }
    assert_eq!(card.get_ok(0x7F21), cert);
    // Extended APDU.
    assert_eq!(card.put(0x00FC, &cert), 0x9000);
    let (data, sw) = card.apdu_ext(0x00, 0xCA, 0x00, 0xFC, b"", Some(0));
    assert_eq!(sw, 0x9000);
    assert_eq!(data, cert);
    let mut too_big = cert.clone();
    too_big.push(0);
    assert_eq!(card.put(0x7F21, &too_big), 0x6700);
    assert_eq!(card.put(0x00FC, &too_big), 0x6700);
    // Empty clears.
    assert_eq!(card.put(0x7F21, b""), 0x9000);
    assert_eq!(card.get_ok(0x7F21), b"");
}

/// docs/CONTRACTS.md: PUT DATA persists before reporting success; on failure nothing
/// changes and the answer is 6581.
#[test]
fn put_data_storage_failure_keeps_previous_value() {
    let mut card = Card::new();
    card.admin();
    assert_eq!(card.put(0x5F50, b"https://example.org/key"), 0x9000);
    card.host.fail_next_saves(1);
    assert_eq!(card.put(0x5F50, b"https://other"), 0x6581);
    assert_eq!(card.get_ok(0x5F50), b"https://example.org/key");
    card.reload();
    assert_eq!(card.get_ok(0x5F50), b"https://example.org/key");
}

/// Catalog: PUT DATA explicit-Le mutation guard.
#[test]
fn put_data_le_guard() {
    let mut card = Card::new();
    card.admin();
    assert_eq!(card.apdu(0x00, 0xDA, 0x5F, 0x50, b"url", Some(1)).1, 0x6700);
    assert_eq!(card.get_ok(0x5F50), b"");
    assert_eq!(card.apdu(0x00, 0xDA, 0x5F, 0x50, b"url", Some(0)).1, 0x9000);
    assert_eq!(card.get_ok(0x5F50), b"url");
}

/// Everything written survives a restart (docs/DESIGN.md §7).
#[test]
fn persistence_roundtrip() {
    let mut card = Card::new();
    card.admin();
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    card.put(0x005B, b"Doe<<Jane");
    card.put(0x5F2D, b"de");
    card.put(0x5F35, b"2");
    card.put(0x005E, b"jane");
    card.put(0x5F50, b"https://k");
    card.put(0x0101, b"p1");
    card.put(0x0102, b"p2");
    card.put(0x0103, b"p3");
    card.put(0x0104, b"p4");
    card.put(0x00C8, &[8; 20]);
    card.put(0x00CB, &[9; 20]);
    card.put(0x00CF, &[1, 2, 3, 4]);
    card.put(0x00D8, &[0x01, 0x20]);
    card.put(0x00C4, &[0x00]);
    card.put(0x00D3, b"resetcode");
    let before: Vec<_> = [0x0065, 0x006E, 0x005E, 0x5F50, 0x0101, 0x0102, 0x00C4, 0x00D8, 0x00F9]
        .into_iter()
        .map(|tag| card.get_ok(tag))
        .collect();
    card.reload();
    let after: Vec<_> = [0x0065, 0x006E, 0x005E, 0x5F50, 0x0101, 0x0102, 0x00C4, 0x00D8, 0x00F9]
        .into_iter()
        .map(|tag| card.get_ok(tag))
        .collect();
    assert_eq!(before, after);
    card.admin();
    assert_eq!(card.get_ok(0x0104), b"p4");
    assert_eq!(card.apdu(0x00, 0x2C, 0x00, 0x81, b"resetcodenewpin1", None).1, 0x9000);
}

/// docs/CONTRACTS.md: unreadable state means factory state.
#[test]
fn unreadable_state_is_factory() {
    use lk_core::CardApplet;
    for stored in [&b""[..], &[0x01], &[0x02, 0x81, 0x01, 0x00], &[0x01, 0x81, 0x05, 0x31]] {
        let mut host = lk_testkit::TestHost::new();
        let mut app = lk_openpgp::OpenPgp::new(Some(stored), &mut host);
        assert_eq!(app.select(&crate::common::SELECT, &mut host), vec![0x90, 0x00]);
        let mut card = crate::common::Card { app, host };
        assert_eq!(card.verify(0x83, b"12345678"), 0x9000);
        assert_eq!(card.get_ok(0x00F9), vec![0x81, 0x01, 0x00]);
    }
}
