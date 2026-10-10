//! Independent-review scenarios: access matrix of the PW1 modes (spec 3.4.1 §7.2.2,
//! §4.4.1), input validation of PSO:DECIPHER for ECDH (spec §7.2.11; RFC 7748 §6.1,
//! SEC 1 §3.2.2), the complete factory reset of TERMINATE DF / ACTIVATE FILE (spec
//! §7.2.16-§7.2.17), interruption of pending work by the life-cycle commands, and the
//! KDF-DO length rules for the resetting code (spec §4.3.2, §4.3.4).

use lk_core::{CardApplet, Outcome};
use lk_crypto::{Curve, EcPrivateKey, X25519Key};
use lk_testkit::SeededEntropy;

use crate::common::{Card, Public, attr, cipher_do, crt, hex, parse_public};

/// A card with Ed25519 SIG, X25519 DEC and Ed25519 AUT keys and PW3 verified.
fn card_with_keys() -> Card {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C1, attr::ED25519);
    card.set_attributes(0x00C2, attr::X25519);
    card.set_attributes(0x00C3, attr::ED25519);
    for crt in [crt::SIG, crt::DEC, crt::AUT] {
        card.generate(crt);
    }
    card
}

/// The status words of the PW1-protected operations, in a fixed order: PSO:CDS,
/// PSO:DECIPHER, INTERNAL AUTHENTICATE, GET DATA 0103, PUT DATA 0101, PUT DATA 0103,
/// GET ATTESTATION (SIG).
fn pw1_operations(card: &mut Card) -> [u16; 7] {
    let peer = X25519Key::generate(&mut SeededEntropy::new(5));
    [
        card.sign(b"m").1,
        card.decipher(&cipher_do(&peer.public())).1,
        card.authenticate(b"c").1,
        card.get(0x0103).1,
        card.put(0x0101, b"one"),
        card.put(0x0103, b"three"),
        card.attest(0x01).1,
    ]
}

/// spec §7.2.2 / §4.4.1: PW1 verified with 81 opens PSO:CDS only; with 82 it opens
/// PSO:DECIPHER, INTERNAL AUTHENTICATE and the 0101/0103 private DOs; PW3 opens none of
/// them. GET ATTESTATION (Yubico) accepts either PW1 mode (operations.rs model policy).
#[test]
fn pw1_mode_access_matrix() {
    const DENIED: u16 = 0x6982;
    const OK: u16 = 0x9000;
    let mut card = card_with_keys();
    // PW3 alone.
    assert_eq!(pw1_operations(&mut card), [DENIED; 7]);
    // PW1 mode 81 alone.
    card.select();
    assert_eq!(card.verify(0x81, b"123456"), OK);
    assert_eq!(pw1_operations(&mut card), [OK, DENIED, DENIED, DENIED, DENIED, DENIED, OK]);
    // PW1 mode 82 alone.
    card.select();
    assert_eq!(card.verify(0x82, b"123456"), OK);
    assert_eq!(pw1_operations(&mut card), [DENIED, OK, OK, OK, OK, OK, OK]);
    // Logging 82 out (VERIFY P1 FF, spec 3.4 §7.2.2) leaves 81 untouched.
    assert_eq!(card.verify(0x81, b"123456"), OK);
    assert_eq!(card.apdu(0x00, 0x20, 0xFF, 0x82, b"", None).1, OK);
    assert_eq!(pw1_operations(&mut card), [OK, DENIED, DENIED, DENIED, DENIED, DENIED, OK]);
}

/// A wrong resetting code or a wrong PW3 costs only its own counter and access; the PW1
/// verifications stay (spec §7.2.2 applies the both-modes rule to PW1 only).
#[test]
fn wrong_rc_or_pw3_keeps_pw1_access() {
    let mut card = card_with_keys();
    assert_eq!(card.put(0x00D3, b"resetcode"), 0x9000);
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    assert_eq!(card.apdu(0x00, 0x2C, 0x00, 0x81, b"resetcodXnewpin1", None).1, 0x63C2);
    assert_eq!(card.verify(0x83, b"00000000"), 0x63C2);
    assert_eq!(card.verify(0x81, b""), 0x9000);
    assert_eq!(card.verify(0x82, b""), 0x9000);
    assert_eq!(card.verify(0x83, b""), 0x63C2);
    assert_eq!(card.retries(), [3, 2, 2]);
}

/// RFC 7748 §6.1: an X25519 peer key of a small-order point gives the all-zero secret,
/// which the card refuses (6A80) instead of returning it; the cipher DO point must be
/// exactly 32 bytes. The key still works afterwards.
#[test]
fn x25519_decipher_rejects_low_order_and_bad_lengths() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C2, attr::X25519);
    let Public::Point(card_public) = parse_public(&card.generate(crt::DEC)) else { panic!() };
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    let mut one = [0u8; 32];
    one[0] = 1;
    let peer = X25519Key::generate(&mut SeededEntropy::new(17)).public();
    let mut prefixed = vec![0x40];
    prefixed.extend_from_slice(&peer);
    for (what, point) in [
        ("zero point", vec![0u8; 32]),
        ("u = 1 (order 4)", one.to_vec()),
        ("31 bytes", peer[..31].to_vec()),
        ("0x40 prefix (33 bytes)", prefixed),
    ] {
        assert_eq!(card.decipher(&cipher_do(&point)).1, 0x6A80, "{what}");
    }
    let peer_key = X25519Key::generate(&mut SeededEntropy::new(18));
    let (shared, sw) = card.decipher(&cipher_do(&peer_key.public()));
    assert_eq!(sw, 0x9000);
    assert_eq!(shared, peer_key.dh(&card_public).unwrap().to_vec());
}

/// SEC 1 §3.2.2: the ECDH peer point must be a point of the DEC key's own curve; a valid
/// P-256 point sent to a P-384 key, and the P-384 point at infinity encoding, are 6A80.
#[test]
fn ecdh_point_must_match_the_curve() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C2, attr::P384_ECDH);
    let Public::Point(card_point) = parse_public(&card.generate(crt::DEC)) else { panic!() };
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    let p256 = EcPrivateKey::generate(Curve::P256, &mut SeededEntropy::new(23)).public_uncompressed();
    assert_eq!(card.decipher(&cipher_do(&p256)).1, 0x6A80);
    let mut zero = vec![0x04];
    zero.extend_from_slice(&[0; 96]);
    assert_eq!(card.decipher(&cipher_do(&zero)).1, 0x6A80);
    assert_eq!(card.decipher(&cipher_do(&[0x00])).1, 0x6A80);
    let peer = EcPrivateKey::generate(Curve::P384, &mut SeededEntropy::new(24));
    let (shared, sw) = card.decipher(&cipher_do(&peer.public_uncompressed()));
    assert_eq!(sw, 0x9000);
    assert_eq!(shared, peer.ecdh(&card_point).unwrap().to_vec());
}

/// spec §7.2.16-§7.2.17 with the catalog's attestation rule: TERMINATE DF then ACTIVATE
/// FILE restores every factory value of the SIG/DEC/AUT side (keys, attributes, UIF,
/// certificates, fingerprints, PINs, retry maxima, resetting code, KDF-DO, C4 policy,
/// cardholder and private DOs, signature counter) and keeps the attestation slot.
#[test]
fn activate_restores_every_factory_value() {
    let mut factory = Card::new();
    let factory_objects: Vec<Vec<u8>> =
        [0x006E, 0x0065, 0x007A, 0x00C4, 0x00F9, 0x5F50, 0x005E, 0x0101, 0x0102].map(|t| factory.get_ok(t)).to_vec();

    let mut card = card_with_keys();
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert_eq!(card.sign(b"count me").1, 0x9000);
    for (tag, value) in [
        (0x005B, &b"Doe<<John"[..]),
        (0x5F2D, b"deen"),
        (0x5F35, b"1"),
        (0x5F50, b"https://example.org/key"),
        (0x005E, b"jdoe"),
        (0x0102, b"two"),
        (0x0104, b"four"),
        (0x00C7, &[0x11; 20]),
        (0x00CA, &[0x22; 20]),
        (0x00CE, &[1, 2, 3, 4]),
        (0x00D6, &[0x02, 0x20]),
        (0x00D7, &[0x04, 0x20]),
        (0x7F21, b"aut-cert"),
        (0x00C4, &[0x00]),
        (0x00D3, b"resetcode"),
    ] {
        assert_eq!(card.put(tag, value), 0x9000, "PUT {tag:04X}");
    }
    assert_eq!(card.apdu(0x00, 0xF2, 0x00, 0x00, &[5, 6, 7], None).1, 0x9000);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    assert_eq!(card.put(0x0101, b"one"), 0x9000);
    let att_public = card.public_key(crt::ATT);
    let att_certificate = card.get_ok(0x00FC);
    let mut kdf = hex("810103 820108 830400010000");
    kdf.extend_from_slice(&lk_codec::tlv::encode(0x84, &[7; 8]));
    kdf.extend_from_slice(&lk_codec::tlv::encode(0x87, &[0x11; 32]));
    kdf.extend_from_slice(&lk_codec::tlv::encode(0x88, &[0x33; 32]));
    assert_eq!(card.put(0x00F9, &kdf), 0x9000);
    // Block PW3 (KDF active: any value is wrong), then reset without verification.
    for _ in 0..7 {
        card.verify(0x83, b"wrong");
    }
    assert_eq!(card.verify(0x83, &[0x33; 32]), 0x6983);
    assert_eq!(card.send(&hex("00E60000")).1, 0x9000);
    assert_eq!(card.send(&hex("00440000")).1, 0x9000);
    card.reload();

    let objects: Vec<Vec<u8>> =
        [0x006E, 0x0065, 0x007A, 0x00C4, 0x00F9, 0x5F50, 0x005E, 0x0101, 0x0102].map(|t| card.get_ok(t)).to_vec();
    assert_eq!(objects, factory_objects);
    assert_eq!(card.key_status(), [0x00, 0x00, 0x00, 0x01]);
    assert_eq!(card.public_key(crt::ATT), att_public);
    assert_eq!(card.get_ok(0x00FC), att_certificate);
    for occurrence in 0..3 {
        assert_eq!(card.certificate(occurrence), b"");
    }
    assert_eq!(card.retries(), [3, 0, 3]);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    assert_eq!(card.get_ok(0x0103), b"");
    card.admin();
    assert_eq!(card.get_ok(0x0104), b"");
    assert_eq!(card.apdu(0x00, 0x2C, 0x00, 0x81, b"resetcodenewpin1", None).1, 0x6983);
    // The UIF of SIG and DEC is changeable again (the fixed policies are gone).
    assert_eq!(card.put(0x00D6, &[0x01, 0x20]), 0x9000);
    assert_eq!(card.put(0x00D7, &[0x00, 0x20]), 0x9000);
}

/// TERMINATE DF ends the session: a pending response, an open command chain and a touch
/// wait are all dropped; after ACTIVATE FILE nothing of them comes back.
#[test]
fn terminate_drops_pending_work() {
    let mut card = Card::yubikey();
    card.admin();
    // A pending long response.
    assert_eq!(card.send(&hex("00CA006E00")).1, 0x613B);
    assert_eq!(card.send(&hex("00E60000")).1, 0x9000);
    assert_eq!(card.send(&hex("00C0000000")).1, 0x6285);
    assert_eq!(card.send(&hex("00440000")).1, 0x9000);
    assert_eq!(card.send(&hex("00C0000000")).1, 0x6985);
    // An open chain.
    card.admin();
    assert_eq!(card.apdu(0x10, 0xDA, 0x5F, 0x50, b"https://", None).1, 0x9000);
    assert_eq!(card.send(&hex("00E60000")).1, 0x6883);
    assert_eq!(card.send(&hex("00E60000")).1, 0x9000);
    assert_eq!(card.send(&hex("00440000")).1, 0x9000);
    card.admin();
    assert_eq!(card.apdu(0x00, 0xDA, 0x5F, 0x50, b"example.org", None).1, 0x9000);
    assert_eq!(card.get_ok(0x5F50), b"example.org");
    // A touch wait.
    card.set_attributes(0x00C1, attr::ED25519);
    card.generate(crt::SIG);
    assert_eq!(card.put(0x00D6, &[0x01, 0x20]), 0x9000);
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert!(matches!(card.process(&Card::ext_bytes(0x2A, 0x9E, 0x9A, b"m")), Outcome::NeedTouch { .. }));
    assert_eq!(card.send(&hex("00E60000")).1, 0x9000);
    assert_eq!(card.app.touch_resolved(true, &mut card.host), vec![0x69, 0x85]);
    assert_eq!(card.send(&hex("00440000")).1, 0x9000);
    assert_eq!(card.signature_counter(), 0);
}

/// A cached touch (UIF 03/04) from before the application reset does not stand in for
/// one after it (lib.rs ACTIVATE FILE, model policy).
#[test]
fn application_reset_forgets_cached_touches() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C3, attr::ED25519);
    card.generate(crt::AUT);
    assert_eq!(card.put(0x00D8, &[0x03, 0x20]), 0x9000);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    let auth = Card::ext_bytes(0x88, 0x00, 0x00, b"challenge");
    assert_eq!(card.send_touch(&auth, true).1, 0x9000);
    assert_eq!(card.send(&auth).1, 0x9000);
    assert_eq!(card.send(&hex("00E60000")).1, 0x9000);
    assert_eq!(card.send(&hex("00440000")).1, 0x9000);
    card.admin();
    card.set_attributes(0x00C3, attr::ED25519);
    card.generate(crt::AUT);
    assert_eq!(card.put(0x00D8, &[0x03, 0x20]), 0x9000);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    assert_eq!(card.send_touch(&auth, true).1, 0x9000);
}

/// spec §4.3.2 / §4.3.4: while a KDF-DO is active the resetting code is stored as the
/// host-derived hash, so D3 must have exactly the hash length; a plain code is 6A80 and
/// leaves no code behind.
#[test]
fn kdf_resetting_code_must_be_hash_length() {
    let mut card = Card::new();
    card.admin();
    let mut kdf = hex("810103 82010A 830400010000");
    kdf.extend_from_slice(&lk_codec::tlv::encode(0x84, &[7; 8]));
    kdf.extend_from_slice(&lk_codec::tlv::encode(0x87, &[0x11; 64]));
    kdf.extend_from_slice(&lk_codec::tlv::encode(0x88, &[0x33; 64]));
    assert_eq!(card.put(0x00F9, &kdf), 0x9000);
    assert_eq!(card.verify(0x83, &[0x33; 64]), 0x9000);
    assert_eq!(card.put(0x00D3, b"resetcode"), 0x6A80);
    assert_eq!(card.put(0x00D3, &[0x55; 32]), 0x6A80);
    assert_eq!(card.retries(), [3, 0, 3]);
    assert_eq!(card.put(0x00D3, &[0x55; 64]), 0x9000);
    assert_eq!(card.retries(), [3, 3, 3]);
    // The new PW1 must be a hash too.
    let mut data = vec![0x55; 64];
    data.extend_from_slice(b"newpin");
    assert_eq!(card.apdu(0x00, 0x2C, 0x00, 0x81, &data, None).1, 0x6A80);
    let mut data = vec![0x55; 64];
    data.extend_from_slice(&[0x66; 64]);
    assert_eq!(card.apdu(0x00, 0x2C, 0x00, 0x81, &data, None).1, 0x9000);
    assert_eq!(card.verify(0x82, &[0x66; 64]), 0x9000);
}

/// Catalog "PSO SIGN Le mutation guard" over command chaining: a short explicit Le on the
/// last part is rejected before the counter moves, and the chain is gone afterwards.
#[test]
fn chained_signature_le_guard_keeps_counter() {
    let mut card = card_with_keys();
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert_eq!(card.apdu(0x10, 0x2A, 0x9E, 0x9A, b"first half ", None).1, 0x9000);
    assert_eq!(card.apdu(0x00, 0x2A, 0x9E, 0x9A, b"second half", Some(0x10)).1, 0x6700);
    assert_eq!(card.signature_counter(), 0);
    let (signature, sw) = card.apdu(0x00, 0x2A, 0x9E, 0x9A, b"second half", Some(0x40));
    assert_eq!((signature.len(), sw), (64, 0x9000));
    assert_eq!(card.signature_counter(), 1);
}
