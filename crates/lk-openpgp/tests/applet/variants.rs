//! Every slot/algorithm variant of the algorithm information FA (spec §4.4.3.13; the 43
//! entries of `reference/physical-key/openpgp-reference-observation.json`),
//! driven by the bytes the applet returns for GET DATA FA:
//! - the 39 variants lk-crypto implements are imported (spec §4.4.3.12) and, except RSA
//!   3072/4096 (same code path, generated once each in `generation.rs` because they take
//!   seconds in debug builds), generated (spec §7.2.14); each key then performs its slot's
//!   operation and the result is verified test-side with lk-crypto: SIG PSO:CDS, DEC
//!   PSO:DECIPHER, AUT INTERNAL AUTHENTICATE, ATT signing an attestation certificate;
//! - the 4 brainpoolP512r1 variants answer `6A81` (no lk-crypto arithmetic for it).

use lk_codec::tlv;
use lk_crypto::{Curve, EcPrivateKey, Ed25519Key, RsaPrivateKey, X25519Key, ecdsa_verify_prehash, ed25519_verify};
use lk_testkit::SeededEntropy;

use crate::common::{
    Card, Public, attr, cipher_do, crt, digest_info_sha256, import_data, parse_public, rsa_encrypt, rsa_primes, rsa_verify,
};

#[derive(Debug, Clone, Copy, PartialEq)]
enum Kind {
    Rsa(usize),
    Ec(Curve),
    Ed25519,
    X25519,
    Unsupported,
}

fn kind(attributes: &[u8]) -> Kind {
    match attributes[0] {
        0x01 => Kind::Rsa(usize::from(u16::from_be_bytes([attributes[1], attributes[2]]))),
        _ => match &attributes[1..] {
            [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] => Kind::Ec(Curve::P256),
            [0x2b, 0x81, 0x04, 0x00, 0x22] => Kind::Ec(Curve::P384),
            [0x2b, 0x81, 0x04, 0x00, 0x23] => Kind::Ec(Curve::P521),
            [0x2b, 0x81, 0x04, 0x00, 0x0a] => Kind::Ec(Curve::Secp256k1),
            [0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07] => Kind::Ec(Curve::BrainpoolP256r1),
            [0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b] => Kind::Ec(Curve::BrainpoolP384r1),
            [0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01] => Kind::Ed25519,
            [0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01] => Kind::X25519,
            _ => Kind::Unsupported,
        },
    }
}

/// Import components for a test-side key of `kind` and its expected public key DO value.
fn test_key(kind: Kind, seed: u64) -> (Vec<(u8, Vec<u8>)>, Public) {
    match kind {
        Kind::Rsa(bits) => {
            let (p, q) = rsa_primes(bits);
            let key = RsaPrivateKey::from_primes(&p, &q, &[1, 0, 1]).unwrap();
            (
                vec![(0x91, vec![1, 0, 1]), (0x92, p), (0x93, q)],
                Public::Rsa { n: key.modulus(), e: key.public_exponent() },
            )
        }
        Kind::Ec(curve) => {
            let key = EcPrivateKey::generate(curve, &mut SeededEntropy::new(seed));
            (vec![(0x92, key.scalar().to_vec())], Public::Point(key.public_uncompressed()))
        }
        Kind::Ed25519 => {
            let key = Ed25519Key::generate(&mut SeededEntropy::new(seed));
            (vec![(0x92, key.seed().to_vec())], Public::Point(key.public().to_vec()))
        }
        Kind::X25519 => {
            let key = X25519Key::generate(&mut SeededEntropy::new(seed));
            let reversed = key.secret().iter().rev().copied().collect();
            (vec![(0x92, reversed)], Public::Point(key.public().to_vec()))
        }
        Kind::Unsupported => unreachable!(),
    }
}

/// Run the slot's operation with the card key whose public key is `public` and verify the
/// result independently.
fn exercise(card: &mut Card, tag: u16, kind: Kind, public: &Public, seed: u64) {
    match (tag, public) {
        (0x00C1 | 0x00C3, _) => {
            let pin_mode = if tag == 0x00C1 { 0x81 } else { 0x82 };
            assert_eq!(card.verify(pin_mode, b"123456"), 0x9000);
            // ECDSA input is the digest conventionally paired with the curve: SHA-256 for
            // the 256-bit curves, SHA-384 for the 384-bit ones, SHA-512 for P-521.
            let input = match kind {
                Kind::Rsa(_) => digest_info_sha256(b"variant"),
                Kind::Ec(curve) => lk_crypto::digest(curve.nonce_hash(), b"variant"),
                _ => b"variant".to_vec(),
            };
            let (signature, sw) = if tag == 0x00C1 { card.sign(&input) } else { card.authenticate(&input) };
            assert_eq!(sw, 0x9000, "{tag:04X} {kind:?}");
            if let Kind::Ec(curve) = kind {
                assert_eq!(signature.len(), 2 * curve.field_len(), "{tag:04X} {kind:?}");
            }
            let valid = match (kind, public) {
                (Kind::Rsa(_), Public::Rsa { n, e }) => rsa_verify(n, e, &input, &signature),
                (Kind::Ec(curve), Public::Point(point)) => ecdsa_verify_prehash(curve, point, &input, &signature),
                (Kind::Ed25519, Public::Point(point)) => ed25519_verify(point, &input, &signature),
                _ => false,
            };
            assert!(valid, "{tag:04X} {kind:?}");
        }
        (0x00C2, Public::Rsa { n, e }) => {
            assert_eq!(card.verify(0x82, b"123456"), 0x9000);
            let mut data = vec![0x00];
            data.extend_from_slice(&rsa_encrypt(n, e, b"variant", seed));
            assert_eq!(card.decipher(&data), (b"variant".to_vec(), 0x9000), "{kind:?}");
        }
        (0x00C2, Public::Point(point)) => {
            assert_eq!(card.verify(0x82, b"123456"), 0x9000);
            let (peer_public, expected) = match kind {
                Kind::Ec(curve) => {
                    let peer = EcPrivateKey::generate(curve, &mut SeededEntropy::new(seed));
                    (peer.public_uncompressed(), peer.ecdh(point).unwrap().to_vec())
                }
                Kind::X25519 => {
                    let peer = X25519Key::generate(&mut SeededEntropy::new(seed));
                    (peer.public().to_vec(), peer.dh(point).unwrap().to_vec())
                }
                _ => unreachable!(),
            };
            assert_eq!(card.decipher(&cipher_do(&peer_public)), (expected, 0x9000), "{kind:?}");
        }
        (0x00DA, _) => {
            // The attestation key signs a certificate for the generated SIG key.
            assert_eq!(card.verify(0x81, b"123456"), 0x9000);
            assert_eq!(card.attest(0x01).1, 0x9000, "{kind:?}");
            let certificate = card.certificate(2);
            let body = lk_codec::der::expect_only(&certificate, lk_codec::der::tag::SEQUENCE).unwrap();
            let (tbs, rest) = lk_codec::der::split_der(body).unwrap();
            let (_, rest) = lk_codec::der::split_der(rest).unwrap();
            let bits = lk_codec::der::expect_only(rest, lk_codec::der::tag::BIT_STRING).unwrap();
            let (_, signature) = lk_codec::der::decode_bit_string(bits).unwrap();
            let valid = match (kind, public) {
                (Kind::Rsa(_), Public::Rsa { n, e }) => rsa_verify(n, e, &digest_info_sha256(tbs), signature),
                (Kind::Ec(curve), Public::Point(point)) => {
                    ecdsa_verify_prehash(curve, point, &lk_crypto::sha256(tbs), signature)
                }
                _ => false,
            };
            assert!(valid, "attestation by {kind:?}");
        }
        _ => unreachable!(),
    }
}

/// Catalog OpenPGP_algorithms: "all 43 variants generated and imported" (39 here; the 4
/// brainpoolP512r1 variants are deferred and answer 6A81) and "independent RSA/ECDSA/
/// Ed25519 signatures, PKCS1 decryption, ECDH/X25519 secret comparison and ten attestation
/// issuers" (nine issuer variants here: RSA 2048/3072/4096, P-256, P-384, P-521,
/// secp256k1, brainpoolP256r1 and brainpoolP384r1).
#[test]
fn every_advertised_variant() {
    let mut card = Card::new();
    let fa = card.get_ok(0x00FA);
    let (outer, _) = tlv::parse_one(&fa).unwrap();
    let entries = outer.children().unwrap();
    assert_eq!(entries.len(), 43);
    let (mut supported, mut unsupported) = (0, 0);
    for (index, entry) in entries.iter().enumerate() {
        let tag = entry.tag as u16;
        let attributes = entry.value.to_vec();
        let kind = kind(&attributes);
        let slot_crt = match tag {
            0x00C1 => crt::SIG,
            0x00C2 => crt::DEC,
            0x00C3 => crt::AUT,
            _ => crt::ATT,
        };
        card.admin();
        if tag == 0x00DA {
            // Attestation needs a generated SIG key to attest.
            card.set_attributes(0x00C1, attr::ED25519);
            card.generate(crt::SIG);
        }
        assert_eq!(card.put(tag, &attributes), 0x9000);
        let seed = 1000 + index as u64;
        if kind == Kind::Unsupported {
            unsupported += 1;
            assert_eq!(card.ext(0x47, 0x80, 0x00, slot_crt).1, 0x6A81, "{tag:04X} {attributes:02X?}");
            assert_eq!(card.import(&import_data(slot_crt, &[(0x92, &[0x11; 32])])), 0x6A81);
            continue;
        }
        supported += 1;
        let (components, public) = test_key(kind, seed);
        let components: Vec<(u8, &[u8])> = components.iter().map(|(t, v)| (*t, v.as_slice())).collect();
        assert_eq!(card.import(&import_data(slot_crt, &components)), 0x9000, "{tag:04X} {kind:?}");
        assert_eq!(parse_public(&card.public_key(slot_crt).0), public, "{tag:04X} {kind:?}");
        exercise(&mut card, tag, kind, &public, seed);
        if matches!(kind, Kind::Rsa(bits) if bits > 2048) {
            continue;
        }
        card.admin();
        let generated = parse_public(&card.generate(slot_crt));
        assert_ne!(generated, public);
        exercise(&mut card, tag, kind, &generated, seed + 500);
    }
    assert_eq!((supported, unsupported), (39, 4));
}
