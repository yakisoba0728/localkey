//! GENERATE ASYMMETRIC KEY PAIR (spec §7.2.14) for every advertised algorithm that
//! lk-crypto implements, each result checked independently with lk-crypto primitives:
//! RSA signatures with `rsa_public_op` and a test-side EMSA-PKCS1-v1_5 block (RFC 8017
//! §8.2.2), RSA decryption against test-side RSAES-PKCS1-v1_5 (RFC 8017 §7.2.1), ECDSA with
//! `ecdsa_verify_prehash` (FIPS 186-5 §6.4.2), Ed25519 with `ed25519_verify` (RFC 8032
//! §5.1.7), ECDH and X25519 by computing the shared secret on the test side (SEC 1 §3.3.1,
//! RFC 7748 §6.1).

use lk_crypto::{Curve, EcPrivateKey, HashAlg, X25519Key, ecdsa_verify_prehash, ed25519_verify};
use lk_testkit::SeededEntropy;

use crate::common::{
    Card, Public, attr, cipher_do, crt, digest_info_sha256, hex, parse_public, rsa_encrypt, rsa_verify,
};

fn rsa_public(template: &[u8]) -> (Vec<u8>, Vec<u8>) {
    match parse_public(template) {
        Public::Rsa { n, e } => (n, e),
        other => panic!("not RSA: {other:?}"),
    }
}

fn point(template: &[u8]) -> Vec<u8> {
    match parse_public(template) {
        Public::Point(p) => p,
        other => panic!("not ECC: {other:?}"),
    }
}

/// Factory SIG attributes are RSA 2048: generate, sign a DigestInfo, verify.
#[test]
fn generate_rsa2048_sig_and_sign() {
    let mut card = Card::new();
    card.admin();
    let template = card.generate(crt::SIG);
    let (n, e) = rsa_public(&template);
    assert_eq!(n.len(), 256);
    assert!(n[0] & 0x80 != 0);
    assert_eq!(e, vec![0x01, 0x00, 0x01]);
    assert_eq!(card.key_status(), [0x01, 0x00, 0x00, 0x01]);
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    let digest_info = digest_info_sha256(b"message");
    let (signature, sw) = card.sign(&digest_info);
    assert_eq!(sw, 0x9000);
    assert_eq!(signature.len(), 256);
    assert!(rsa_verify(&n, &e, &digest_info, &signature));
    assert_eq!(card.signature_counter(), 1);
}

/// RSA 3072 in DEC: PSO:DECIPHER of a test-side PKCS #1 v1.5 cryptogram.
#[test]
fn generate_rsa3072_dec_and_decipher() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C2, attr::RSA3072);
    let (n, e) = rsa_public(&card.generate(crt::DEC));
    assert_eq!(n.len(), 384);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    let cryptogram = rsa_encrypt(&n, &e, b"session key bytes", 1);
    let mut data = vec![0x00];
    data.extend_from_slice(&cryptogram);
    assert_eq!(card.decipher(&data), (b"session key bytes".to_vec(), 0x9000));
}

/// RSA 4096 in AUT over short APDUs: the 526-byte 7F49 and the 512-byte signature come back
/// in 61xx chunks (ISO 7816-4 §5.1.3); INTERNAL AUTHENTICATE verifies.
#[test]
fn generate_rsa4096_aut_and_authenticate() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C3, attr::RSA4096);
    let (template, sw) = card.full(&hex("00 47 8000 02 A400 00"));
    assert_eq!(sw, 0x9000);
    // 7F49 82 0209 { 81 82 0200 <512>, 82 03 010001 }
    assert_eq!(template.len(), 526);
    let (n, e) = rsa_public(&template);
    assert_eq!(n.len(), 512);
    assert_eq!(card.public_key(crt::AUT), (template.clone(), 0x9000));
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    let challenge = digest_info_sha256(b"challenge");
    let mut apdu = hex("00 88 0000");
    apdu.push(challenge.len() as u8);
    apdu.extend_from_slice(&challenge);
    apdu.push(0x00);
    let (signature, sw) = card.full(&apdu);
    assert_eq!(sw, 0x9000);
    assert!(rsa_verify(&n, &e, &challenge, &signature));
    // INTERNAL AUTHENTICATE leaves the signature counter alone (spec §4.4.3.14).
    assert_eq!(card.signature_counter(), 0);
}

/// ECDSA on P-256 (SIG) and P-384 (AUT): raw `r || s` of field length (spec §7.2.10).
#[test]
fn generate_ecdsa_sign_and_authenticate() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C1, attr::P256_ECDSA);
    card.set_attributes(0x00C3, attr::P384_ECDSA);
    let sig_point = point(&card.generate(crt::SIG));
    let aut_point = point(&card.generate(crt::AUT));
    assert_eq!((sig_point.len(), aut_point.len()), (65, 97));
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    let digest = lk_crypto::sha256(b"signed data");
    let (signature, sw) = card.sign(&digest);
    assert_eq!(sw, 0x9000);
    assert_eq!(signature.len(), 64);
    assert!(ecdsa_verify_prehash(Curve::P256, &sig_point, &digest, &signature));
    let digest = lk_crypto::sha384(b"authenticated data");
    let (signature, sw) = card.authenticate(&digest);
    assert_eq!(sw, 0x9000);
    assert_eq!(signature.len(), 96);
    assert!(ecdsa_verify_prehash(Curve::P384, &aut_point, &digest, &signature));
}

/// docs/CONTRACTS.md "Phase 0 as implemented": device-visible ECDSA uses a hedged nonce, so
/// signing the same digest twice gives two different valid signatures.
#[test]
fn ecdsa_signatures_are_hedged() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C1, attr::P256_ECDSA);
    let public = point(&card.generate(crt::SIG));
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    let digest = lk_crypto::sha256(b"same");
    let (first, _) = card.sign(&digest);
    let (second, _) = card.sign(&digest);
    assert_ne!(first, second);
    assert!(ecdsa_verify_prehash(Curve::P256, &public, &digest, &first));
    assert!(ecdsa_verify_prehash(Curve::P256, &public, &digest, &second));
}

/// ECDH on P-256 and P-384 in DEC: the card returns the X coordinate of the shared point,
/// which the test computes from its own ephemeral key (SEC 1 §3.3.1).
#[test]
fn generate_ecdh_and_decipher() {
    for (attributes, curve) in [(attr::P256_ECDH, Curve::P256), (attr::P384_ECDH, Curve::P384)] {
        let mut card = Card::new();
        card.admin();
        card.set_attributes(0x00C2, attributes);
        let card_point = point(&card.generate(crt::DEC));
        assert_eq!(card_point.len(), curve.point_len());
        let ephemeral = EcPrivateKey::generate(curve, &mut SeededEntropy::new(5));
        let expected = ephemeral.ecdh(&card_point).unwrap();
        assert_eq!(card.verify(0x82, b"123456"), 0x9000);
        let (shared, sw) = card.decipher(&cipher_do(&ephemeral.public_uncompressed()));
        assert_eq!(sw, 0x9000);
        assert_eq!(shared, expected.to_vec());
    }
}

/// Ed25519 in SIG and AUT: the data is the message itself (spec §7.2.10 EdDSA).
#[test]
fn generate_ed25519_sign_and_authenticate() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C1, attr::ED25519);
    card.set_attributes(0x00C3, attr::ED25519);
    let sig_public = point(&card.generate(crt::SIG));
    let aut_public = point(&card.generate(crt::AUT));
    assert_eq!(sig_public.len(), 32);
    assert_ne!(sig_public, aut_public);
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    let (signature, sw) = card.sign(b"an OpenPGP hash");
    assert_eq!(sw, 0x9000);
    assert!(ed25519_verify(&sig_public, b"an OpenPGP hash", &signature));
    let (signature, sw) = card.authenticate(b"ssh challenge");
    assert_eq!(sw, 0x9000);
    assert!(ed25519_verify(&aut_public, b"ssh challenge", &signature));
}

/// X25519 in DEC: native 32-byte keys in 7F49 and the cipher DO (RFC 7748 §6.1).
#[test]
fn generate_x25519_and_decipher() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C2, attr::X25519);
    let card_public = point(&card.generate(crt::DEC));
    assert_eq!(card_public.len(), 32);
    let ephemeral = X25519Key::generate(&mut SeededEntropy::new(9));
    let expected = ephemeral.dh(&card_public).unwrap();
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    let (shared, sw) = card.decipher(&cipher_do(&ephemeral.public()));
    assert_eq!(sw, 0x9000);
    assert_eq!(shared, expected.to_vec());
}

/// The attestation slot generates its advertised algorithms too (catalog: all advertised
/// variants generated); DE reports 01 for it.
#[test]
fn generate_attestation_slot_keys() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00DA, attr::P384_ECDSA);
    let template = card.generate(crt::ATT);
    assert_eq!(point(&template).len(), 97);
    assert_eq!(card.public_key(crt::ATT), (template, 0x9000));
    assert_eq!(card.key_status()[3], 0x01);
    card.set_attributes(0x00DA, attr::P256_ECDSA);
    assert_eq!(card.key_status()[3], 0x00);
    assert_eq!(point(&card.generate(crt::ATT)).len(), 65);
}

/// P1 81 reads the public key without any verification; an empty slot is `6A88`.
#[test]
fn read_public_key_without_pin() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C1, attr::ED25519);
    let template = card.generate(crt::SIG);
    card.select();
    assert_eq!(card.public_key(crt::SIG), (template.clone(), 0x9000));
    assert_eq!(card.public_key(&hex("B6 03 840101")), (template, 0x9000));
    assert_eq!(card.public_key(crt::DEC), (vec![], 0x6A88));
    assert_eq!(card.public_key(crt::AUT), (vec![], 0x6A88));
}

/// Header rules: P2 must be 00 and P1 80/81 (catalog: "nonzero generation P2 rejection");
/// PW3 is needed to generate; the CRT must be well formed with a matching key reference
/// (catalog: "short and extended CRT matching ... mismatched reference rejection").
#[test]
fn generate_header_and_crt_rules() {
    let mut card = Card::new();
    card.set_attributes_unchecked();
    assert_eq!(card.ext(0x47, 0x80, 0x00, crt::SIG).1, 0x6982);
    card.admin();
    assert_eq!(card.ext(0x47, 0x80, 0x01, crt::SIG).1, 0x6A86);
    assert_eq!(card.ext(0x47, 0x81, 0x01, crt::SIG).1, 0x6A86);
    assert_eq!(card.ext(0x47, 0x82, 0x00, crt::SIG).1, 0x6A86);
    for bad in ["B6 03 840102", "B8 03 840101", "A4 03 840181", "B7 00", "B6 00 00", "", "B6 01 00"] {
        assert_eq!(card.ext(0x47, 0x80, 0x00, &hex(bad)).1, 0x6A80, "{bad}");
    }
    assert_eq!(card.key_status(), [0, 0, 0, 1]);
    // Extended CRTs with the matching reference are accepted.
    for (crt, index) in [("B6 03 840101", 0), ("B8 03 840102", 1), ("A4 03 840103", 2)] {
        assert_eq!(card.ext(0x47, 0x80, 0x00, &hex(crt)).1, 0x9000);
        assert_eq!(card.key_status()[index], 0x01);
    }
}

/// Catalog: "GENERATE ... Le mutation guards": an explicit Le smaller than the public key
/// DO is `6700` before the key is replaced; Le 00 is served in chunks.
#[test]
fn generate_le_guard_keeps_previous_key() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C1, attr::P256_ECDSA);
    let before = card.generate(crt::SIG);
    let persists = card.host.persist_count();
    assert_eq!(card.send(&hex("00 47 8000 02 B600 10")).1, 0x6700);
    assert_eq!(card.apdu_ext(0x00, 0x47, 0x80, 0x00, crt::SIG, Some(60)).1, 0x6700);
    assert_eq!(card.host.persist_count(), persists);
    assert_eq!(card.public_key(crt::SIG), (before.clone(), 0x9000));
    // Le 00 and an absent Le are fine (YubiKit sends no Le).
    let (fresh, sw) = card.send(&hex("00 47 8000 02 B600 00"));
    assert_eq!(sw, 0x9000);
    assert_ne!(fresh, before);
    let (again, sw) = card.send(&hex("00 47 8000 02 B600"));
    assert_eq!(sw, 0x9000);
    assert_eq!(again.len(), fresh.len());
}

/// lk-crypto implements P-521, secp256k1 and brainpoolP256r1/P384r1, so generation and
/// import succeed for them in any slot; brainpoolP512r1 alone still answers `6A81` (spec
/// §7.2.14 / §4.4.3.12 "function not supported").
#[test]
fn only_brainpool_p512r1_answers_6a81() {
    let mut card = Card::new();
    card.admin();
    for (tag, attributes, crt, curve) in [
        (0x00C1, attr::P521_ECDSA, crt::SIG, Some(Curve::P521)),
        (0x00C1, attr::SECP256K1_ECDSA, crt::SIG, Some(Curve::Secp256k1)),
        (0x00C2, attr::BP256_ECDH, crt::DEC, Some(Curve::BrainpoolP256r1)),
        (0x00C3, attr::BP384_ECDSA, crt::AUT, Some(Curve::BrainpoolP384r1)),
        (0x00DA, attr::BP512_ECDSA, crt::ATT, None),
    ] {
        card.set_attributes(tag, attributes);
        match curve {
            Some(curve) => {
                let generated = point(&card.generate(crt));
                assert!(lk_crypto::ec_public_is_valid(curve, &generated), "{attributes}");
                let key = EcPrivateKey::generate(curve, &mut SeededEntropy::new(u64::from(tag)));
                let import = crate::common::import_data(crt, &[(0x92, key.scalar())]);
                assert_eq!(card.import(&import), 0x9000, "{attributes}");
                assert_eq!(point(&card.public_key(crt).0), key.public_uncompressed(), "{attributes}");
            }
            None => {
                assert_eq!(card.ext(0x47, 0x80, 0x00, crt).1, 0x6A81, "{attributes}");
                let import = crate::common::import_data(crt, &[(0x92, &[0x11; 64])]);
                assert_eq!(card.import(&import), 0x6A81, "{attributes}");
            }
        }
    }
    // Imported keys have status 02 (spec §4.4.3.8); changing DA's attributes removed the
    // factory issuer and no brainpoolP512r1 key replaced it.
    assert_eq!(card.key_status(), [0x02, 0x02, 0x02, 0x00]);
}

/// Catalog OpenPGP_algorithms: "SIG generation/import resets digital-signature counter;
/// other slots leave it unchanged" (spec §4.4.3.14).
#[test]
fn sig_generation_resets_counter_only_for_sig() {
    let mut card = Card::new();
    card.admin();
    for tag in [0x00C1, 0x00C3] {
        card.set_attributes(tag, attr::ED25519);
    }
    card.set_attributes(0x00C2, attr::X25519);
    card.generate(crt::SIG);
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    card.sign(b"one");
    card.sign(b"two");
    assert_eq!(card.signature_counter(), 2);
    card.generate(crt::DEC);
    card.generate(crt::AUT);
    assert_eq!(card.signature_counter(), 2);
    card.generate(crt::SIG);
    assert_eq!(card.signature_counter(), 0);
}

/// Keys are persisted: after a restart the same public keys answer and sign (catalog:
/// "retained independent ... private keys verified after rejection/restart").
#[test]
fn keys_survive_restart() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C1, attr::P384_ECDSA);
    card.set_attributes(0x00C2, attr::X25519);
    let sig = point(&card.generate(crt::SIG));
    let dec = point(&card.generate(crt::DEC));
    card.reload();
    assert_eq!(point(&card.public_key(crt::SIG).0), sig);
    assert_eq!(point(&card.public_key(crt::DEC).0), dec);
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    let digest = lk_crypto::digest(HashAlg::Sha384, b"after restart");
    let (signature, sw) = card.sign(&digest);
    assert_eq!(sw, 0x9000);
    assert!(ecdsa_verify_prehash(Curve::P384, &sig, &digest, &signature));
}

/// Generation persists before it reports success; a failed save keeps the previous key.
#[test]
fn generation_storage_failure_keeps_previous_key() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C1, attr::ED25519);
    let before = card.generate(crt::SIG);
    card.host.fail_next_saves(1);
    assert_eq!(card.ext(0x47, 0x80, 0x00, crt::SIG), (vec![], 0x6581));
    assert_eq!(card.public_key(crt::SIG), (before.clone(), 0x9000));
    card.reload();
    assert_eq!(card.public_key(crt::SIG), (before, 0x9000));
}

/// spec §4.4.3.10: changing a slot's algorithm attributes deletes its key; rewriting the
/// same attributes does not.
#[test]
fn attribute_change_deletes_key() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C1, attr::ED25519);
    let template = card.generate(crt::SIG);
    card.set_attributes(0x00C1, attr::ED25519);
    assert_eq!(card.public_key(crt::SIG), (template, 0x9000));
    card.set_attributes(0x00C1, attr::P256_ECDSA);
    assert_eq!(card.key_status()[0], 0x00);
    assert_eq!(card.public_key(crt::SIG).1, 0x6A88);
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert_eq!(card.sign(&[0x55; 32]).1, 0x6A88);
    card.reload();
    assert_eq!(card.public_key(crt::SIG).1, 0x6A88);
}

impl Card {
    /// Nothing to set up: generation with factory attributes (RSA 2048 everywhere) would be
    /// slow, so header tests switch SIG/DEC/AUT to Ed25519/X25519 first.
    fn set_attributes_unchecked(&mut self) {
        self.admin();
        self.set_attributes(0x00C1, attr::ED25519);
        self.set_attributes(0x00C2, attr::X25519);
        self.set_attributes(0x00C3, attr::ED25519);
        self.select();
    }
}
