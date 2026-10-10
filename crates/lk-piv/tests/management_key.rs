//! Card management key authentication by GENERAL AUTHENTICATE (SP 800-73-4 Part 2
//! §3.2.4 and Appendix A; SP 800-78-4 Table 6-1) and Yubico SET MANAGEMENT KEY.

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use lk_codec::tlv;
use lk_core::{CardApplet, Outcome, Record};

/// Known-answer vectors for the block operation behind the handshake, as
/// (algorithm, key, plaintext, ciphertext):
/// - AES: FIPS 197 Appendix C.1 (AES-128), C.2 (AES-192), C.3 (AES-256);
/// - 3DES: NIST SP 800-67 Rev. 1 Appendix B, first block ("The qufc").
type Vector = (u8, Vec<u8>, Vec<u8>, Vec<u8>);

fn vectors() -> Vec<Vector> {
    let aes_pt = hex("00112233445566778899aabbccddeeff");
    vec![
        (ALG_AES128, hex("000102030405060708090a0b0c0d0e0f"), aes_pt.clone(), hex("69c4e0d86a7b0430d8cdb78070b4c55a")),
        (
            ALG_AES192,
            hex("000102030405060708090a0b0c0d0e0f1011121314151617"),
            aes_pt.clone(),
            hex("dda97ca4864cdfe06eaf70a0ec0d7191"),
        ),
        (
            ALG_AES256,
            hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            aes_pt,
            hex("8ea2b7ca516745bfeafc49904b496089"),
        ),
        (ALG_TDES, hex("0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123"), b"The qufc".to_vec(), hex("A826FD8CE53B855F")),
    ]
}

fn authenticated(card: &mut Card) -> bool {
    // PUT DATA needs the management key (SP 800-73-4 Part 2 §3.3.1); deleting an absent
    // object changes nothing.
    match card.send("00DB3FFF075C035FFF0F5300").1 {
        0x9000 => true,
        0x6982 => false,
        other => panic!("unexpected {other:04X}"),
    }
}

#[test]
fn default_management_key_is_aes192() {
    let mut card = Card::new();
    assert!(!authenticated(&mut card));
    card.auth_default();
    assert!(authenticated(&mut card));
    // The same bytes as a 3DES key are refused: P1 must name the stored algorithm.
    let mut card = Card::new();
    assert_eq!(card.try_mutual_auth(ALG_TDES, &hex(DEFAULT_MGMT_KEY)), 0x6A86);
}

#[test]
fn mutual_authentication_known_answers_for_every_algorithm() {
    for (alg, key, plain, cipher) in vectors() {
        let mut card = Card::new();
        card.auth_default();
        assert_eq!(card.set_mgmt_key(alg, &key, false), 0x9000, "alg {alg:02X}");
        // Step 1: the card's random witness W is scripted, so it sends E(K, W).
        card.host.push_entropy(&plain);
        let (resp, sw) = card.cmd(0x87, alg, 0x9B, &hex("7C028000"), None);
        assert_eq!(sw, 0x9000);
        assert_eq!(dyn_auth_item(&resp, 0x80), cipher, "witness alg {alg:02X}");
        // Step 2: return W and challenge the card with the same plaintext.
        let mut inner = tlv::encode(0x80, &plain);
        tlv::encode_into(&mut inner, 0x81, &plain);
        let (resp, sw) = card.cmd(0x87, alg, 0x9B, &tlv::encode(0x7C, &inner), None);
        assert_eq!(sw, 0x9000);
        assert_eq!(dyn_auth_item(&resp, 0x82), cipher, "response alg {alg:02X}");
        assert!(authenticated(&mut card));
    }
}

#[test]
fn external_authentication_known_answers_for_every_algorithm() {
    for (alg, key, plain, cipher) in vectors() {
        let mut card = Card::new();
        card.auth_default();
        assert_eq!(card.set_mgmt_key(alg, &key, false), 0x9000);
        card.piv.deselect();
        card.piv.select(&hex(SELECT), &mut card.host);
        assert!(!authenticated(&mut card));
        // Step 1: the card sends a random challenge C (scripted here).
        card.host.push_entropy(&plain);
        let (resp, sw) = card.cmd(0x87, alg, 0x9B, &hex("7C028100"), None);
        assert_eq!(sw, 0x9000);
        assert_eq!(dyn_auth_item(&resp, 0x81), plain);
        // Step 2: answer E(K, C).
        let (resp, sw) = card.cmd(0x87, alg, 0x9B, &tlv::encode(0x7C, &tlv::encode(0x82, &cipher)), None);
        assert_eq!((resp.len(), sw), (0, 0x9000), "alg {alg:02X}");
        assert!(authenticated(&mut card));
    }
}

#[test]
fn wrong_witness_or_response_is_refused() {
    let mut card = Card::new();
    let key = hex(DEFAULT_MGMT_KEY);
    // Mutual with a wrong witness.
    let (resp, _) = card.cmd(0x87, ALG_AES192, 0x9B, &hex("7C028000"), None);
    let mut witness = decrypt(ALG_AES192, &key, &dyn_auth_item(&resp, 0x80));
    witness[0] ^= 1;
    let mut inner = tlv::encode(0x80, &witness);
    tlv::encode_into(&mut inner, 0x81, &[0x55; 16]);
    assert_eq!(card.cmd(0x87, ALG_AES192, 0x9B, &tlv::encode(0x7C, &inner), None).1, 0x6982);
    assert!(!authenticated(&mut card));
    // External with a wrong response.
    let (resp, _) = card.cmd(0x87, ALG_AES192, 0x9B, &hex("7C028100"), None);
    let mut answer = encrypt(ALG_AES192, &key, &dyn_auth_item(&resp, 0x81));
    answer[15] ^= 0x80;
    assert_eq!(card.cmd(0x87, ALG_AES192, 0x9B, &tlv::encode(0x7C, &tlv::encode(0x82, &answer)), None).1, 0x6982);
    assert!(!authenticated(&mut card));
    // A failed attempt also drops an earlier authentication.
    card.auth_default();
    let (_, _) = card.cmd(0x87, ALG_AES192, 0x9B, &hex("7C028100"), None);
    assert_eq!(card.cmd(0x87, ALG_AES192, 0x9B, &tlv::encode(0x7C, &tlv::encode(0x82, &[0; 16])), None).1, 0x6982);
    assert!(!authenticated(&mut card));
    // Management key failures have no retry counter: the right key still works.
    card.auth_default();
}

#[test]
fn second_step_needs_its_first_step_immediately_before() {
    let mut card = Card::new();
    let key = hex(DEFAULT_MGMT_KEY);
    let mut inner = tlv::encode(0x80, &[0; 16]);
    tlv::encode_into(&mut inner, 0x81, &[0; 16]);
    let step2 = tlv::encode(0x7C, &inner);
    assert_eq!(card.cmd(0x87, ALG_AES192, 0x9B, &step2, None).1, 0x6A80, "no step 1");
    // Any command in between consumes the challenge.
    let (resp, _) = card.cmd(0x87, ALG_AES192, 0x9B, &hex("7C028000"), None);
    let witness = decrypt(ALG_AES192, &key, &dyn_auth_item(&resp, 0x80));
    assert_eq!(card.send("00FD0000").1, 0x9000);
    let mut inner = tlv::encode(0x80, &witness);
    tlv::encode_into(&mut inner, 0x81, &[0; 16]);
    assert_eq!(card.cmd(0x87, ALG_AES192, 0x9B, &tlv::encode(0x7C, &inner), None).1, 0x6A80);
    // A mutual step 1 does not open an external step 2.
    let (_, _) = card.cmd(0x87, ALG_AES192, 0x9B, &hex("7C028000"), None);
    assert_eq!(card.cmd(0x87, ALG_AES192, 0x9B, &tlv::encode(0x7C, &tlv::encode(0x82, &[0; 16])), None).1, 0x6A80);
    assert!(!authenticated(&mut card));
}

#[test]
fn malformed_authentication_requests() {
    let mut card = Card::new();
    for (p1, data, sw) in [
        (ALG_AES192, "7C028001", 0x6A80),               // truncated element
        (ALG_AES192, "7D028000", 0x6A80),               // not a 7C template
        (ALG_AES192, "7C028300", 0x6A80),               // unknown element
        (ALG_AES192, "7C0280007C00", 0x6A80),           // trailing data
        (ALG_AES192, "7C0A8008000000000000000081 00", 0x6A80), // 8-byte witness for AES
        (ALG_AES192, "7C048000 8100", 0x6A80),          // both empty
        (ALG_AES192, "", 0x6A80),                       // no data
        (0x07, "7C028000", 0x6A86),                     // not a management key algorithm
        (ALG_AES128, "7C028000", 0x6A86),               // not the stored algorithm
        (ALG_AES256, "7C028000", 0x6A86),
    ] {
        let data = hex(data);
        assert_eq!(card.cmd(0x87, p1, 0x9B, &data, None).1, sw, "{p1:02X} {data:02X?}");
    }
    // An empty key slot is 6A88 (slot keys are tested in tests/keys.rs); other
    // references are not keys.
    assert_eq!(card.cmd(0x87, 0x11, 0x9A, &hex("7C028100"), None).1, 0x6A88);
    assert_eq!(card.cmd(0x87, 0x11, 0x42, &hex("7C028100"), None).1, 0x6A86);
}

#[test]
fn authentication_accepts_explicit_le() {
    // SP 800-73-4 Part 2 §3.2.4: Le is "absent or length of expected response".
    let mut card = Card::new();
    let key = hex(DEFAULT_MGMT_KEY);
    let (resp, sw) = card.cmd(0x87, ALG_AES192, 0x9B, &hex("7C028000"), Some(0));
    assert_eq!(sw, 0x9000);
    let witness = decrypt(ALG_AES192, &key, &dyn_auth_item(&resp, 0x80));
    let mut inner = tlv::encode(0x80, &witness);
    tlv::encode_into(&mut inner, 0x81, &[0x42; 16]);
    let (resp, sw) = card.cmd(0x87, ALG_AES192, 0x9B, &tlv::encode(0x7C, &inner), Some(0));
    assert_eq!(sw, 0x9000);
    assert_eq!(dyn_auth_item(&resp, 0x82), encrypt(ALG_AES192, &key, &[0x42; 16]));
    assert!(authenticated(&mut card));
}

#[test]
fn touch_required_management_key() {
    // Yubico SET MANAGEMENT KEY P2 FE: completing the authentication needs a touch.
    let mut card = Card::new();
    card.auth_default();
    let key = hex("000102030405060708090a0b0c0d0e0f");
    assert_eq!(card.set_mgmt_key(ALG_AES128, &key, true), 0x9000);
    assert_eq!(card.metadata(0x9B).0, hex("010108 02020002 050100"));
    card.new_session();
    assert!(!authenticated(&mut card));

    let step2 = |card: &mut Card| {
        let (resp, sw) = card.cmd(0x87, ALG_AES128, 0x9B, &hex("7C028000"), None);
        assert_eq!(sw, 0x9000, "step 1 needs no touch");
        let witness = decrypt(ALG_AES128, &key, &dyn_auth_item(&resp, 0x80));
        let mut inner = tlv::encode(0x80, &witness);
        tlv::encode_into(&mut inner, 0x81, &[0x99; 16]);
        apdu(0x00, 0x87, ALG_AES128, 0x9B, &tlv::encode(0x7C, &inner), None)
    };

    // Touched: authenticated and the response arrives.
    let bytes = step2(&mut card);
    assert_eq!(card.outcome(&bytes), Outcome::NeedTouch { timeout_ms: 15_000 });
    let resp = card.piv.touch_resolved(true, &mut card.host);
    let (data, sw) = lk_codec::apdu::split_response(&resp).unwrap();
    assert_eq!(sw, 0x9000);
    assert_eq!(dyn_auth_item(data, 0x82), encrypt(ALG_AES128, &key, &[0x99; 16]));
    assert!(authenticated(&mut card));

    // Timed out: refused and not authenticated.
    let bytes = step2(&mut card);
    assert_eq!(card.outcome(&bytes), Outcome::NeedTouch { timeout_ms: 15_000 });
    assert_eq!(card.piv.touch_resolved(false, &mut card.host), hex("6982"));
    assert!(!authenticated(&mut card));

    // A new command abandons the pending touch.
    let bytes = step2(&mut card);
    assert_eq!(card.outcome(&bytes), Outcome::NeedTouch { timeout_ms: 15_000 });
    assert_eq!(card.send("00FD0000").1, 0x9000);
    assert_eq!(card.piv.touch_resolved(true, &mut card.host), hex("6985"));
    assert!(!authenticated(&mut card));

    // A wrong witness is refused before any touch.
    let (_, _) = card.cmd(0x87, ALG_AES128, 0x9B, &hex("7C028000"), None);
    let mut inner = tlv::encode(0x80, &[0; 16]);
    tlv::encode_into(&mut inner, 0x81, &[0; 16]);
    assert_eq!(card.cmd(0x87, ALG_AES128, 0x9B, &tlv::encode(0x7C, &inner), None).1, 0x6982);
}

#[test]
fn set_management_key_guards_leave_key_unchanged() {
    // Catalog: SET MANAGEMENT KEY P1/P2/Le are rejected before changing the key.
    let mut card = Card::new();
    let before = card.host.persisted(Record::Piv);
    let mut data = vec![ALG_AES128];
    tlv::encode_into(&mut data, 0x9B, &[0x11; 16]);
    assert_eq!(card.cmd(0xFF, 0xFF, 0xFF, &data, None).1, 0x6982, "needs authentication");
    card.auth_default();
    assert_eq!(card.cmd(0xFF, 0xFE, 0xFF, &data, None).1, 0x6A86, "P1");
    assert_eq!(card.cmd(0xFF, 0xFF, 0xFD, &data, None).1, 0x6A86, "P2");
    assert_eq!(card.cmd(0xFF, 0xFF, 0xFF, &data, Some(1)).1, 0x6700, "non-zero Le");
    for bad in [
        "07 9B10 11111111111111111111111111111111",         // unknown algorithm
        "08 9B18 111111111111111111111111111111111111111111111111", // length for AES-192
        "0C 9B18 111111111111111111111111111111111111111111111111", // short for AES-256
        "08 9A10 11111111111111111111111111111111",         // wrong reference
        "08 9B10 11111111111111111111111111111111 00",      // trailing byte
        "08 9B11 11111111111111111111111111111111",         // truncated
        "08",                                               // no key
        "",                                                 // no data
    ] {
        let bad = hex(bad);
        assert_eq!(card.cmd(0xFF, 0xFF, 0xFF, &bad, None).1, 0x6A80, "{bad:02X?}");
    }
    assert_eq!(card.host.persisted(Record::Piv), before);
    card.new_session();
    card.auth_default();
}

#[test]
fn set_management_key_persists_and_storage_failure_keeps_old_key() {
    let mut card = Card::new();
    card.auth_default();
    let key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    card.host.fail_next_saves(1);
    assert_eq!(card.set_mgmt_key(ALG_AES256, &key, false), 0x6581);
    card.new_session();
    card.auth_default();
    assert_eq!(card.set_mgmt_key(ALG_AES256, &key, false), 0x9000);
    card.restart();
    assert_eq!(card.try_mutual_auth(ALG_AES192, &hex(DEFAULT_MGMT_KEY)), 0x6A86);
    card.mutual_auth(ALG_AES256, &key);
    assert_eq!(card.metadata(0x9B).0, hex("01010C 02020001 050100"));
    // Back to 3DES with the default bytes: reported as default again.
    assert_eq!(card.set_mgmt_key(ALG_TDES, &hex(DEFAULT_MGMT_KEY), false), 0x9000);
    assert_eq!(card.metadata(0x9B).0, hex("010103 02020001 050101"));
    card.mutual_auth(ALG_TDES, &hex(DEFAULT_MGMT_KEY));
}

#[test]
fn management_authentication_does_not_survive_session_end() {
    let mut card = Card::new();
    card.auth_default();
    card.piv.deselect();
    assert!(!authenticated(&mut card));
    card.auth_default();
    card.piv.reset(lk_core::ResetKind::CardPowerOff);
    assert!(!authenticated(&mut card));
}
