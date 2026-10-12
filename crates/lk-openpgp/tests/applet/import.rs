//! Key import with PUT DATA odd INS DB, P1 P2 = 3FFF and the extended header list 4D
//! (spec §7.2.8, §4.4.3.12): RSA in the standard (e, p, q) and CRT (e, p, q, 1/q mod p,
//! d mod (p-1), d mod (q-1)) formats with and without the modulus, and ECC private keys
//! with and without the public key. Test keys are generated test-side with lk-crypto; the
//! CRT values are computed test-side (RFC 8017 §3.2).

use lk_crypto::{Curve, EcPrivateKey, Ed25519Key, RsaPrivateKey, X25519Key, ecdsa_verify_prehash, ed25519_verify};
use lk_testkit::SeededEntropy;

use crate::common::{
    Card, Public, attr, cipher_do, crt, digest_info_sha256, hex, import_data, parse_public, rsa_crt, rsa_encrypt,
    rsa_primes, rsa_verify,
};

const E: &[u8] = &[0x01, 0x00, 0x01];

struct TestRsa {
    p: Vec<u8>,
    q: Vec<u8>,
    n: Vec<u8>,
    qinv: Vec<u8>,
    dp: Vec<u8>,
    dq: Vec<u8>,
}

fn test_rsa(bits: usize) -> TestRsa {
    let (p, q) = rsa_primes(bits);
    let key = RsaPrivateKey::from_primes(&p, &q, E).unwrap();
    let (qinv, dp, dq) = rsa_crt(&p, &q);
    TestRsa { n: key.modulus(), p, q, qinv, dp, dq }
}

fn card_rsa_public(card: &mut Card, crt: &[u8]) -> (Vec<u8>, Vec<u8>) {
    match parse_public(&card.public_key(crt).0) {
        Public::Rsa { n, e } => (n, e),
        other => panic!("{other:?}"),
    }
}

fn card_point(card: &mut Card, crt: &[u8]) -> Vec<u8> {
    match parse_public(&card.public_key(crt).0) {
        Public::Point(p) => p,
        other => panic!("{other:?}"),
    }
}

/// The four RSA layouts of spec §4.4.3.12 all import the same key; DE reports 02.
#[test]
fn rsa_import_standard_and_crt_formats() {
    let key = test_rsa(2048);
    let layouts: [Vec<(u8, &[u8])>; 4] = [
        vec![(0x91, E), (0x92, &key.p), (0x93, &key.q)],
        vec![(0x91, E), (0x92, &key.p), (0x93, &key.q), (0x97, &key.n)],
        vec![(0x91, E), (0x92, &key.p), (0x93, &key.q), (0x94, &key.qinv), (0x95, &key.dp), (0x96, &key.dq)],
        vec![
            (0x91, E),
            (0x92, &key.p),
            (0x93, &key.q),
            (0x94, &key.qinv),
            (0x95, &key.dp),
            (0x96, &key.dq),
            (0x97, &key.n),
        ],
    ];
    for components in layouts {
        let mut card = Card::new();
        card.admin();
        assert_eq!(card.import(&import_data(crt::SIG, &components)), 0x9000);
        assert_eq!(card.key_status()[0], 0x02);
        let (n, e) = card_rsa_public(&mut card, crt::SIG);
        assert_eq!(n, key.n);
        assert_eq!(e, E);
        assert_eq!(card.verify(0x81, b"123456"), 0x9000);
        let digest_info = digest_info_sha256(b"imported");
        let (signature, sw) = card.sign(&digest_info);
        assert_eq!(sw, 0x9000);
        assert!(rsa_verify(&n, &e, &digest_info, &signature));
    }
}

/// A 4096-bit CRT import is longer than one short APDU: it arrives through command
/// chaining (ISO 7816-4 §5.1.1.1) and decrypts afterwards. A zero-padded exponent is fine.
#[test]
fn rsa4096_import_with_chaining() {
    let key = test_rsa(4096);
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C2, attr::RSA4096);
    let data = import_data(
        crt::DEC,
        &[(0x91, &[0x00, 0x01, 0x00, 0x01]), (0x92, &key.p), (0x93, &key.q), (0x94, &key.qinv), (0x95, &key.dp), (0x96, &key.dq)],
    );
    let chunks: Vec<&[u8]> = data.chunks(255).collect();
    for (i, chunk) in chunks.iter().enumerate() {
        let cla = if i + 1 < chunks.len() { 0x10 } else { 0x00 };
        assert_eq!(card.apdu(cla, 0xDB, 0x3F, 0xFF, chunk, None).1, 0x9000);
    }
    let (n, e) = card_rsa_public(&mut card, crt::DEC);
    assert_eq!(n, key.n);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    let mut cipher = vec![0x00];
    cipher.extend_from_slice(&rsa_encrypt(&n, &e, b"4096", 3));
    assert_eq!(card.decipher(&cipher), (b"4096".to_vec(), 0x9000));
}

/// Catalog OpenPGP_algorithms: "standard RSA e/p/q widths, exponent/modulus consistency
/// and duplicate/order/unknown-field rejection". Every rejection is `6A80` and keeps the
/// previous key.
#[test]
fn rsa_import_rejections() {
    let key = test_rsa(2048);
    let mut card = Card::new();
    card.admin();
    let good = import_data(crt::SIG, &[(0x91, E), (0x92, &key.p), (0x93, &key.q)]);
    assert_eq!(card.import(&good), 0x9000);
    let mut wrong_n = key.n.clone();
    wrong_n[200] ^= 1;
    let short_p = &key.p[1..];
    let mut long_p = vec![0x00];
    long_p.extend_from_slice(&key.p);
    type Components<'a> = Vec<(u8, &'a [u8])>;
    let cases: Vec<(&str, Components)> = vec![
        ("duplicate", vec![(0x91, E), (0x92, &key.p), (0x92, &key.p), (0x93, &key.q)]),
        ("order", vec![(0x92, &key.p), (0x91, E), (0x93, &key.q)]),
        ("unknown", vec![(0x91, E), (0x92, &key.p), (0x93, &key.q), (0x98, &[1])]),
        ("partial crt", vec![(0x91, E), (0x92, &key.p), (0x93, &key.q), (0x94, &key.qinv)]),
        ("missing q", vec![(0x91, E), (0x92, &key.p)]),
        ("short p", vec![(0x91, E), (0x92, short_p), (0x93, &key.q)]),
        ("long p", vec![(0x91, E), (0x92, &long_p), (0x93, &key.q)]),
        ("modulus", vec![(0x91, E), (0x92, &key.p), (0x93, &key.q), (0x97, &wrong_n)]),
        ("even e", vec![(0x91, &[0x01, 0x00, 0x02]), (0x92, &key.p), (0x93, &key.q)]),
        ("e above 17 bits", vec![(0x91, &[0x02, 0x00, 0x01]), (0x92, &key.p), (0x93, &key.q)]),
        ("e = 1", vec![(0x91, &[0x01]), (0x92, &key.p), (0x93, &key.q)]),
        ("e too long", vec![(0x91, &[0, 0, 0, 1, 0, 1]), (0x92, &key.p), (0x93, &key.q)]),
        ("p = q", vec![(0x91, E), (0x92, &key.p), (0x93, &key.p)]),
        ("ecc template", vec![(0x92, &[0x11; 32])]),
        ("crt too long", vec![(0x91, E), (0x92, &key.p), (0x93, &key.q), (0x94, &long_p), (0x95, &key.dp), (0x96, &key.dq)]),
    ];
    for (what, components) in cases {
        assert_eq!(card.import(&import_data(crt::SIG, &components)), 0x6A80, "{what}");
    }
    // 7F48 lengths that do not add up to the 5F48 length (the good import minus one byte
    // of q, with the outer lengths adjusted).
    let mut short = import_data(crt::SIG, &[(0x91, E), (0x92, &key.p), (0x93, &key.q)]);
    let len = short.len();
    short.truncate(len - 1);
    // 4D 82 hi lo ... 5F48 82 01 83 -> 82 01 82
    let outer = u16::from_be_bytes([short[2], short[3]]) - 1;
    short[2..4].copy_from_slice(&outer.to_be_bytes());
    let values_len_at = short.len() - (3 + 128 + 128 - 1) - 2;
    assert_eq!(&short[values_len_at - 3..values_len_at], &[0x5F, 0x48, 0x82]);
    let values = u16::from_be_bytes([short[values_len_at], short[values_len_at + 1]]) - 1;
    short[values_len_at..values_len_at + 2].copy_from_slice(&values.to_be_bytes());
    assert_eq!(card.import(&short), 0x6A80);
    // Structure: wrong outer tag, extra element, missing 5F48, mismatched CRT reference.
    assert_eq!(card.import(&hex("4E 0B B600 7F48 02 9201 5F48 01 01")), 0x6A80);
    assert_eq!(card.import(&hex("4D 0D B600 7F48 02 9201 5F48 01 01 0400")), 0x6A80);
    assert_eq!(card.import(&hex("4D 07 B600 7F48 02 9201")), 0x6A80);
    let mismatched_ref = import_data(&hex("B6 03 840102"), &[(0x91, E), (0x92, &key.p), (0x93, &key.q)]);
    assert_eq!(card.import(&mismatched_ref), 0x6A80);
    // An RSA template for a slot with ECC attributes.
    card.set_attributes(0x00C3, attr::ED25519);
    assert_eq!(card.import(&import_data(crt::AUT, &[(0x91, E), (0x92, &key.p), (0x93, &key.q)])), 0x6A80);
    // The SIG key is still the imported one.
    assert_eq!(card_rsa_public(&mut card, crt::SIG).0, key.n);
}

/// Import needs PW3, P1 P2 3FFF and no explicit Le (catalog: PUT DATA Le guard).
#[test]
fn import_access_and_header_rules() {
    let mut card = Card::new();
    let data = import_data(crt::SIG, &[(0x92, &[0x11; 32])]);
    assert_eq!(card.import(&data), 0x6982);
    card.admin();
    card.set_attributes(0x00C1, attr::ED25519);
    assert_eq!(card.apdu_ext(0x00, 0xDB, 0x3F, 0xFE, &data, None).1, 0x6B00);
    assert_eq!(card.apdu_ext(0x00, 0xDB, 0x3F, 0xFF, &data, Some(1)).1, 0x6700);
    assert_eq!(card.key_status()[0], 0x00);
    assert_eq!(card.apdu_ext(0x00, 0xDB, 0x3F, 0xFF, &data, Some(0)).1, 0x9000);
    assert_eq!(card.key_status()[0], 0x02);
}

/// ECDSA P-256 without and ECDH P-384 with the public key `99` (spec §4.4.3.12).
#[test]
fn ec_import_with_and_without_public_key() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C1, attr::P256_ECDSA);
    card.set_attributes(0x00C2, attr::P384_ECDH);
    let sig = EcPrivateKey::generate(Curve::P256, &mut SeededEntropy::new(21));
    let dec = EcPrivateKey::generate(Curve::P384, &mut SeededEntropy::new(22));
    assert_eq!(card.import(&import_data(crt::SIG, &[(0x92, sig.scalar())])), 0x9000);
    let dec_public = dec.public_uncompressed();
    assert_eq!(card.import(&import_data(crt::DEC, &[(0x92, dec.scalar()), (0x99, &dec_public)])), 0x9000);
    assert_eq!(card_point(&mut card, crt::SIG), sig.public_uncompressed());
    assert_eq!(card_point(&mut card, crt::DEC), dec_public);
    assert_eq!(card.key_status(), [0x02, 0x02, 0x00, 0x01]);
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    let digest = lk_crypto::sha256(b"ec import");
    let (signature, sw) = card.sign(&digest);
    assert_eq!(sw, 0x9000);
    assert!(ecdsa_verify_prehash(Curve::P256, &sig.public_uncompressed(), &digest, &signature));
    let peer = EcPrivateKey::generate(Curve::P384, &mut SeededEntropy::new(23));
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    let (shared, sw) = card.decipher(&cipher_do(&peer.public_uncompressed()));
    assert_eq!(sw, 0x9000);
    assert_eq!(shared, peer.ecdh(&dec_public).unwrap().to_vec());
}

/// Ed25519 (seed as is) and X25519 (RFC 9580 §5.5.5.6.1.1: the secret arrives reversed,
/// big-endian, as GnuPG and YubiKit send it).
#[test]
fn edwards_import() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C3, attr::ED25519);
    card.set_attributes(0x00C2, attr::X25519);
    let aut = Ed25519Key::from_seed(&[0x42; 32]).unwrap();
    let dec = X25519Key::generate(&mut SeededEntropy::new(31));
    let reversed: Vec<u8> = dec.secret().iter().rev().copied().collect();
    assert_eq!(card.import(&import_data(crt::AUT, &[(0x92, aut.seed()), (0x99, &aut.public())])), 0x9000);
    assert_eq!(card.import(&import_data(crt::DEC, &[(0x92, &reversed)])), 0x9000);
    assert_eq!(card_point(&mut card, crt::AUT), aut.public());
    assert_eq!(card_point(&mut card, crt::DEC), dec.public());
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    let (signature, sw) = card.authenticate(b"edwards");
    assert_eq!(sw, 0x9000);
    assert!(ed25519_verify(&aut.public(), b"edwards", &signature));
    let peer = X25519Key::generate(&mut SeededEntropy::new(32));
    let (shared, sw) = card.decipher(&cipher_do(&peer.public()));
    assert_eq!(sw, 0x9000);
    assert_eq!(shared, peer.dh(&dec.public()).unwrap().to_vec());
    // The public key 99 must match.
    let wrong = Ed25519Key::from_seed(&[0x43; 32]).unwrap().public();
    assert_eq!(card.import(&import_data(crt::AUT, &[(0x92, aut.seed()), (0x99, &wrong)])), 0x6A80);
}

/// Catalog OpenPGP_algorithms: "standard EC/Ed25519/X25519 import widths": the private key
/// has exactly the field length; the template is `92` then optionally `99`.
#[test]
fn ec_import_rejections() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C1, attr::P256_ECDSA);
    card.set_attributes(0x00C2, attr::X25519);
    let key = EcPrivateKey::generate(Curve::P256, &mut SeededEntropy::new(41));
    let public = key.public_uncompressed();
    let mut padded = vec![0x00];
    padded.extend_from_slice(key.scalar());
    let other = EcPrivateKey::generate(Curve::P256, &mut SeededEntropy::new(42)).public_uncompressed();
    let order: [u8; 32] = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551").try_into().unwrap();
    for (what, components) in [
        ("short", vec![(0x92, &key.scalar()[1..])]),
        ("padded", vec![(0x92, &padded[..])]),
        ("zero", vec![(0x92, &[0u8; 32][..])]),
        ("order", vec![(0x92, &order[..])]),
        ("public mismatch", vec![(0x92, key.scalar()), (0x99, &other[..])]),
        ("order of tags", vec![(0x99, &public[..]), (0x92, key.scalar())]),
        ("rsa tags", vec![(0x91, E), (0x92, key.scalar())]),
    ] {
        assert_eq!(card.import(&import_data(crt::SIG, &components)), 0x6A80, "{what}");
    }
    assert_eq!(card.import(&import_data(crt::DEC, &[(0x92, &[1; 31])])), 0x6A80);
    assert_eq!(card.key_status(), [0, 0, 0, 1]);
}

/// Import resets the signature counter for SIG only (spec §4.4.3.14) and goes to the
/// attestation slot with the Yubico CRT `B6 03 84 01 81`.
#[test]
fn import_counter_and_attestation_slot() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C1, attr::ED25519);
    card.set_attributes(0x00C2, attr::X25519);
    card.set_attributes(0x00DA, attr::P256_ECDSA);
    assert_eq!(card.import(&import_data(crt::SIG, &[(0x92, &[1; 32])])), 0x9000);
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    card.sign(b"a");
    card.sign(b"b");
    assert_eq!(card.signature_counter(), 2);
    assert_eq!(card.import(&import_data(crt::DEC, &[(0x92, &[2; 32])])), 0x9000);
    let att = EcPrivateKey::generate(Curve::P256, &mut SeededEntropy::new(51));
    assert_eq!(card.import(&import_data(crt::ATT, &[(0x92, att.scalar())])), 0x9000);
    assert_eq!(card.signature_counter(), 2);
    assert_eq!(card.key_status(), [0x02, 0x02, 0x00, 0x02]);
    assert_eq!(card_point(&mut card, crt::ATT), att.public_uncompressed());
    assert_eq!(card.import(&import_data(crt::SIG, &[(0x92, &[3; 32])])), 0x9000);
    assert_eq!(card.signature_counter(), 0);
}

/// A failed save keeps the previous key (docs/CONTRACTS.md "Persisted state").
#[test]
fn import_storage_failure_keeps_previous_key() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C1, attr::ED25519);
    assert_eq!(card.import(&import_data(crt::SIG, &[(0x92, &[1; 32])])), 0x9000);
    let before = card.public_key(crt::SIG);
    card.host.fail_next_saves(1);
    assert_eq!(card.import(&import_data(crt::SIG, &[(0x92, &[2; 32])])), 0x6581);
    assert_eq!(card.public_key(crt::SIG), before);
    card.reload();
    assert_eq!(card.public_key(crt::SIG), before);
}
