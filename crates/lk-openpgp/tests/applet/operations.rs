//! PSO:COMPUTE DIGITAL SIGNATURE (spec §7.2.10), PSO:DECIPHER (§7.2.11), INTERNAL
//! AUTHENTICATE (§7.2.13), MANAGE SECURITY ENVIRONMENT (§7.2.18), the digital signature
//! counter (§4.4.3.14) and the PW1 validity byte of C4 (§4.4.3.6).

use lk_core::Record;
use lk_crypto::{Curve, EcPrivateKey, RsaPrivateKey, ed25519_verify};
use lk_testkit::SeededEntropy;

use crate::common::{
    Card, Public, attr, cipher_do, crt, digest_info_sha256, hex, import_data, parse_public, rsa_encrypt, rsa_primes,
    rsa_verify,
};

const E: &[u8] = &[0x01, 0x00, 0x01];

/// A card with an Ed25519 SIG key, PW1 verified for signing.
fn ed25519_signer() -> (Card, Vec<u8>) {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C1, attr::ED25519);
    let Public::Point(public) = parse_public(&card.generate(crt::SIG)) else { panic!() };
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    (card, public)
}

/// A card whose DEC key is the cached RSA 2048 test key; returns (n, e).
fn rsa_decrypter(card: &mut Card) -> (Vec<u8>, Vec<u8>) {
    let (p, q) = rsa_primes(2048);
    card.admin();
    assert_eq!(card.import(&import_data(crt::DEC, &[(0x91, E), (0x92, &p), (0x93, &q)])), 0x9000);
    let key = RsaPrivateKey::from_primes(&p, &q, E).unwrap();
    (key.modulus(), key.public_exponent())
}

/// spec §7.2.10: PSO:CDS needs PW1 verified with 81; 82 alone is not enough.
#[test]
fn cds_requires_pw1_mode_81() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C1, attr::ED25519);
    card.generate(crt::SIG);
    card.select();
    assert_eq!(card.sign(b"x").1, 0x6982);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    assert_eq!(card.sign(b"x").1, 0x6982);
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert_eq!(card.sign(b"x").1, 0x9000);
}

/// spec §4.4.3.6: with C4 byte 1 = 00, a PW1 verification allows one signature; with 01,
/// several.
#[test]
fn pw1_valid_for_one_signature_when_c4_is_00() {
    let (mut card, _) = ed25519_signer();
    assert_eq!(card.sign(b"1").1, 0x9000);
    assert_eq!(card.sign(b"2").1, 0x9000);
    card.admin();
    assert_eq!(card.put(0x00C4, &[0x00]), 0x9000);
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert_eq!(card.sign(b"3").1, 0x9000);
    assert_eq!(card.sign(b"4").1, 0x6982);
    assert_eq!(card.verify(0x81, b""), 0x63C3);
    // A rejected request does not use the verification up.
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert_eq!(card.sign(b"").1, 0x6700);
    assert_eq!(card.sign(b"5").1, 0x9000);
    assert_eq!(card.sign(b"6").1, 0x6982);
}

/// docs/CONTRACTS.md: the counter is persisted before the signature that reveals it; a
/// failed save answers 6581 without a signature and leaves the counter and the PW1
/// verification as they were.
#[test]
fn signature_counter_persisted_before_signature() {
    let (mut card, public) = ed25519_signer();
    let count = card.host.persist_count();
    let (signature, sw) = card.sign(b"first");
    assert_eq!(sw, 0x9000);
    assert!(ed25519_verify(&public, b"first", &signature));
    assert_eq!(card.host.persist_count(), count + 1);
    assert_eq!(card.signature_counter(), 1);
    card.host.fail_next_saves(1);
    assert_eq!(card.sign(b"second"), (vec![], 0x6581));
    assert_eq!(card.signature_counter(), 1);
    assert_eq!(card.sign(b"third").1, 0x9000);
    assert_eq!(card.signature_counter(), 2);
    card.reload();
    assert_eq!(card.signature_counter(), 2);
    assert_eq!(card.get_ok(0x007A), hex("7A 05 93 03 000002"));
    let persisted = card.host.persisted(Record::OpenPgp).unwrap();
    assert!(!persisted.is_empty());
}

/// Header and input rules of PSO:CDS: P1 P2 9E 9A only, a key must exist (6A88), RSA input
/// at most k - 11 bytes and ECDSA at most 64 (6700), and the Le guard (catalog "PSO SIGN
/// Le mutation guard") rejects a short explicit Le before the counter moves.
#[test]
fn cds_header_and_input_rules() {
    let mut card = Card::new();
    card.admin();
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert_eq!(card.sign(&[1; 32]).1, 0x6A88);
    assert_eq!(card.ext(0x2A, 0x9E, 0x9B, &[1; 32]).1, 0x6A86);
    assert_eq!(card.ext(0x2A, 0x9A, 0x9E, &[1; 32]).1, 0x6A86);
    let (p, q) = rsa_primes(2048);
    assert_eq!(card.import(&import_data(crt::SIG, &[(0x91, E), (0x92, &p), (0x93, &q)])), 0x9000);
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert_eq!(card.sign(&[1; 246]).1, 0x6700);
    assert_eq!(card.sign(&[]).1, 0x6700);
    assert_eq!(card.sign(&[1; 245]).1, 0x9000);
    assert_eq!(card.signature_counter(), 1);
    let input = digest_info_sha256(b"m");
    let mut short = hex("00 2A 9E9A");
    short.push(input.len() as u8);
    short.extend_from_slice(&input);
    short.push(0x80);
    assert_eq!(card.send(&short), (vec![], 0x6700));
    assert_eq!(card.signature_counter(), 1);
    // Absent Le (YubiKit) and Le 00 are served in full.
    short.pop();
    let (signature, sw) = card.send(&short);
    assert_eq!((signature.len(), sw), (256, 0x9000));
    short.push(0x00);
    assert_eq!(card.send(&short).0.len(), 256);
    assert_eq!(card.signature_counter(), 3);
    // ECDSA input limits: at most 64 bytes; a shorter digest is used as an integer
    // (FIPS 186-5 §6.4.1) and a longer one truncated.
    card.set_attributes(0x00C1, attr::P256_ECDSA);
    let Public::Point(point) = parse_public(&card.generate(crt::SIG)) else { panic!() };
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert_eq!(card.sign(&[1; 65]).1, 0x6700);
    for len in [8, 32, 64] {
        let (signature, sw) = card.sign(&vec![1; len]);
        assert_eq!(sw, 0x9000);
        assert!(lk_crypto::ecdsa_verify_prehash(Curve::P256, &point, &vec![1; len], &signature), "{len}");
    }
}

/// PSO:DECIPHER: PW1 82, padding indicator 00 and a cryptogram of the modulus length; a bad
/// PKCS #1 v1.5 block is 6A80 (RFC 8017 §7.2.2); AES (indicator 02) is not offered (C0).
#[test]
fn rsa_decipher_rules() {
    let mut card = Card::new();
    let (n, e) = rsa_decrypter(&mut card);
    card.select();
    let mut good = vec![0x00];
    good.extend_from_slice(&rsa_encrypt(&n, &e, b"secret", 7));
    assert_eq!(card.decipher(&good).1, 0x6982);
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert_eq!(card.decipher(&good).1, 0x6982);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    assert_eq!(card.decipher(&good), (b"secret".to_vec(), 0x9000));
    let mut aes = good.clone();
    aes[0] = 0x02;
    assert_eq!(card.decipher(&aes).1, 0x6A81);
    let mut bad_indicator = good.clone();
    bad_indicator[0] = 0x01;
    assert_eq!(card.decipher(&bad_indicator).1, 0x6A80);
    assert_eq!(card.decipher(&good[..good.len() - 1]).1, 0x6700);
    assert_eq!(card.decipher(&[]).1, 0x6700);
    // A block that is not 00 02 PS 00 M.
    let mut block = vec![0x00, 0x01];
    block.resize(256, 0xFF);
    let mut not_type_2 = vec![0x00];
    not_type_2.extend_from_slice(&lk_crypto::rsa_public_op(&n, &e, &block).unwrap());
    assert_eq!(card.decipher(&not_type_2).1, 0x6A80);
    // A cryptogram not below the modulus.
    let mut too_big = vec![0x00];
    too_big.extend_from_slice(&[0xFF; 256]);
    assert_eq!(card.decipher(&too_big).1, 0x6A80);
    // Catalog: "invalid request ciphertext unchanged; retained ... keys verified after
    // rejection/restart".
    card.reload();
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    assert_eq!(card.decipher(&good), (b"secret".to_vec(), 0x9000));
}

/// ECDH: the cipher DO must be exactly `A6 { 7F49 { 86 point } }` with a valid point.
#[test]
fn ecdh_decipher_rules() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C2, attr::P256_ECDH);
    let Public::Point(card_point) = parse_public(&card.generate(crt::DEC)) else { panic!() };
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    let peer = EcPrivateKey::generate(Curve::P256, &mut SeededEntropy::new(61));
    let peer_point = peer.public_uncompressed();
    let mut off_curve = peer_point.clone();
    off_curve[64] ^= 1;
    let mut compressed = vec![0x02];
    compressed.extend_from_slice(&peer_point[1..33]);
    for (what, data) in [
        ("bare point", peer_point.clone()),
        ("wrong outer", lk_codec::tlv::encode(0xA7, &cipher_do(&peer_point)[2..])),
        ("off curve", cipher_do(&off_curve)),
        ("compressed", cipher_do(&compressed)),
        ("short", cipher_do(&peer_point[..64])),
        ("trailing", [cipher_do(&peer_point), vec![0x00]].concat()),
    ] {
        assert_eq!(card.decipher(&data).1, 0x6A80, "{what}");
    }
    let (shared, sw) = card.decipher(&cipher_do(&peer_point));
    assert_eq!(sw, 0x9000);
    assert_eq!(shared, peer.ecdh(&card_point).unwrap().to_vec());
}

/// INTERNAL AUTHENTICATE: P1 = P2 = 00 (catalog: "zero P1/P2 guard on INTERNAL
/// AUTHENTICATE") checked first, then PW1 82, a key, and the Le guard.
#[test]
fn internal_authenticate_rules() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C3, attr::ED25519);
    assert_eq!(card.authenticate(b"c").1, 0x6982);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    assert_eq!(card.authenticate(b"c").1, 0x6A88);
    let Public::Point(public) = parse_public(&card.generate(crt::AUT)) else { panic!() };
    assert_eq!(card.ext(0x88, 0x01, 0x00, b"c").1, 0x6A86);
    assert_eq!(card.ext(0x88, 0x00, 0x01, b"c").1, 0x6A86);
    assert_eq!(card.authenticate(b"").1, 0x6700);
    assert_eq!(card.apdu(0x00, 0x88, 0x00, 0x00, b"c", Some(0x20)).1, 0x6700);
    let (signature, sw) = card.apdu(0x00, 0x88, 0x00, 0x00, b"c", Some(0x40));
    assert_eq!(sw, 0x9000);
    assert!(ed25519_verify(&public, b"c", &signature));
    assert_eq!(card.signature_counter(), 0);
}

/// spec §7.2.18: MSE B8 03 makes PSO:DECIPHER use the AUT key, MSE A4 02 makes INTERNAL
/// AUTHENTICATE use the DEC key; SELECT restores the defaults. An algorithm that cannot do
/// the operation is 6985.
#[test]
fn mse_selects_keys_for_decipher_and_authenticate() {
    let mut card = Card::new();
    let (n, e) = rsa_decrypter(&mut card);
    card.set_attributes(0x00C3, attr::ED25519);
    let Public::Point(aut_public) = parse_public(&card.generate(crt::AUT)) else { panic!() };
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    // INTERNAL AUTHENTICATE with the DEC RSA key.
    assert_eq!(card.apdu(0x00, 0x22, 0x41, 0xA4, &hex("830102"), None).1, 0x9000);
    let challenge = digest_info_sha256(b"mse");
    let (signature, sw) = card.authenticate(&challenge);
    assert_eq!(sw, 0x9000);
    assert!(rsa_verify(&n, &e, &challenge, &signature));
    // PSO:DECIPHER with the AUT Ed25519 key cannot work.
    assert_eq!(card.apdu(0x00, 0x22, 0x41, 0xB8, &hex("830103"), None).1, 0x9000);
    let mut cipher = vec![0x00];
    cipher.extend_from_slice(&rsa_encrypt(&n, &e, b"m", 8));
    assert_eq!(card.decipher(&cipher).1, 0x6985);
    // SELECT restores DEC for decipher and AUT for authentication.
    card.select();
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    assert_eq!(card.decipher(&cipher), (b"m".to_vec(), 0x9000));
    let (signature, sw) = card.authenticate(b"aut");
    assert_eq!(sw, 0x9000);
    assert!(ed25519_verify(&aut_public, b"aut", &signature));
}

/// An X25519 DEC key chosen for INTERNAL AUTHENTICATE cannot sign: 6985.
#[test]
fn x25519_key_cannot_authenticate() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C2, attr::X25519);
    card.generate(crt::DEC);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    assert_eq!(card.apdu(0x00, 0x22, 0x41, 0xA4, &hex("830102"), None).1, 0x9000);
    assert_eq!(card.authenticate(b"x").1, 0x6985);
}

/// Catalog "KDF-DO PIN flows": with a KDF-DO the derived PIN hashes unlock key generation,
/// signing and deciphering like plain PINs (spec §4.3.2). F9 is written first: Yubico
/// locks it once a key exists ("YubiKey 5.2.3 Enhancements to OpenPGP 3.4", the order
/// `kdf-setup` before key generation that document gives).
#[test]
fn operations_with_kdf_pins() {
    let mut card = Card::new();
    card.admin();
    let pw1 = [0x11u8; 32];
    let pw3 = [0x33u8; 32];
    let mut kdf = hex("810103 820108 830400010000");
    kdf.extend_from_slice(&lk_codec::tlv::encode(0x84, &[1; 8]));
    kdf.extend_from_slice(&lk_codec::tlv::encode(0x87, &pw1));
    kdf.extend_from_slice(&lk_codec::tlv::encode(0x88, &pw3));
    assert_eq!(card.put(0x00F9, &kdf), 0x9000);
    assert_eq!(card.verify(0x83, b"12345678"), 0x63C2);
    assert_eq!(card.verify(0x83, &pw3), 0x9000);
    card.set_attributes(0x00C1, attr::ED25519);
    card.set_attributes(0x00C2, attr::X25519);
    let Public::Point(sig_public) = parse_public(&card.generate(crt::SIG)) else { panic!() };
    let Public::Point(dec_public) = parse_public(&card.generate(crt::DEC)) else { panic!() };
    assert_eq!(card.verify(0x81, b"123456"), 0x63C2);
    assert_eq!(card.verify(0x81, &pw1), 0x9000);
    assert_eq!(card.verify(0x82, &pw1), 0x9000);
    let (signature, sw) = card.sign(b"kdf");
    assert_eq!(sw, 0x9000);
    assert!(ed25519_verify(&sig_public, b"kdf", &signature));
    let peer = lk_crypto::X25519Key::generate(&mut SeededEntropy::new(71));
    let (shared, sw) = card.decipher(&cipher_do(&peer.public()));
    assert_eq!(sw, 0x9000);
    assert_eq!(shared, peer.dh(&dec_public).unwrap().to_vec());
    // The derived PW3 still administers the keys; with keys present F9 is locked.
    assert_eq!(card.verify(0x83, &pw3), 0x9000);
    assert_eq!(card.ext(0x47, 0x81, 0x00, crt::SIG).1, 0x9000);
    assert_eq!(card.put(0x00F9, &[0x81, 0x01, 0x00]), 0x6985);
    assert_eq!(card.retries(), [3, 0, 3]);
}
