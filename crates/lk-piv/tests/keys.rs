//! Asymmetric slot keys: GENERATE ASYMMETRIC KEY PAIR (SP 800-73-4 Part 2 §3.3.2),
//! IMPORT ASYMMETRIC KEY (Yubico PIV extensions) and GENERAL AUTHENTICATE with slot keys
//! (SP 800-73-4 Part 2 §3.2.4, Appendix A.3-A.5). Every result is checked with
//! `lk_crypto` on the test side.
//!
//! Vector sources: RFC 8032 §7.1 TEST 1 (Ed25519), RFC 7748 §6.1 (X25519), RFC 6979
//! Appendix A.2.5 and A.2.6 (P-256 and P-384 private keys and public points).

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::OnceLock;

use common::*;
use lk_codec::tlv;
use lk_core::{Outcome, Record};
use lk_crypto::{Curve, EcPrivateKey, Ed25519Key, HashAlg, RsaPrivateKey, X25519Key, digest, ed25519_verify, rsa_public_op};
use lk_testkit::SeededEntropy;

/// One test-side RSA-2048 key, generated once (generation is slow in debug builds).
fn rsa2048() -> &'static RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| RsaPrivateKey::generate(2048, &mut SeededEntropy::new(0x2048)).unwrap())
}

fn rsa1024() -> &'static RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| RsaPrivateKey::generate(1024, &mut SeededEntropy::new(0x1024)).unwrap())
}

fn authed() -> Card {
    let mut card = Card::new();
    card.auth_default();
    card
}

/// Sign a SHA-256 digest with an ECC slot (PIN policy never) and verify it.
fn check_ecdsa(card: &mut Card, slot: u8, alg: u8, public: &Public) {
    let digest = digest(HashAlg::Sha256, b"lk-piv ecdsa");
    let (sig1, sw) = card.ga(slot, alg, 0x81, &digest);
    assert_eq!(sw, 0x9000);
    assert!(ecdsa_ok(alg, public.point(), &digest, &sig1), "signature verifies");
    // Hedged nonces: the same digest signed twice gives different signatures
    // (docs/CONTRACTS.md "Phase 0 as implemented").
    let (sig2, _) = card.ga(slot, alg, 0x81, &digest);
    assert_ne!(sig1, sig2);
    assert!(ecdsa_ok(alg, public.point(), &digest, &sig2));
}

#[test]
fn generate_and_use_p256_and_p384() {
    let mut card = authed();
    for (slot, alg, point_len) in [(0x9A, P256, 65), (0x9D, P384, 97)] {
        let public = card.generate(slot, alg, Some(PIN_NEVER), None);
        assert_eq!(public.point().len(), point_len);
        assert_eq!(public.point()[0], 0x04, "uncompressed point (SEC 1 §2.3.3)");
        check_ecdsa(&mut card, slot, alg, &public);
        // ECDH (SP 800-56A §5.7.1.2): the X coordinate, checked against the test side.
        let curve = if alg == P256 { Curve::P256 } else { Curve::P384 };
        let peer = EcPrivateKey::generate(curve, &mut SeededEntropy::new(u64::from(alg)));
        let (shared, sw) = card.ga(slot, alg, 0x85, &peer.public_uncompressed());
        assert_eq!(sw, 0x9000);
        assert_eq!(shared, peer.ecdh(public.point()).unwrap().to_vec());
        // Metadata reports the same key, generated on the device (origin 01).
        let info = card.slot_info(slot).unwrap();
        assert_eq!((info.alg, info.pin, info.touch, info.origin), (alg, PIN_NEVER, TOUCH_NEVER, 0x01));
        assert_eq!(info.public, public);
    }
}

#[test]
fn ecdsa_digest_lengths() {
    // Yubico: the digest must be 256 bits or shorter for P-256 and 384 bits or shorter for
    // P-384; a shorter digest is the same integer left-padded (FIPS 186-5 §6.4.1).
    let mut card = authed();
    let public = card.generate(0x9E, P384, None, None);
    for len in [1usize, 20, 32, 48] {
        let digest = vec![0x5A; len];
        let (sig, sw) = card.ga(0x9E, P384, 0x81, &digest);
        assert_eq!(sw, 0x9000, "{len}");
        assert!(ecdsa_ok(P384, public.point(), &digest, &sig), "{len}");
    }
    assert_eq!(card.ga(0x9E, P384, 0x81, &[0x5A; 49]).1, 0x6A80, "longer than the key");
    assert_eq!(card.ga(0x9E, P384, 0x81, &[]).1, 0x6A80, "empty digest");
    let public = card.generate(0x9E, P256, None, None);
    let (sig, _) = card.ga(0x9E, P256, 0x81, &[0x11; 20]);
    assert!(ecdsa_ok(P256, public.point(), &[0x11; 20], &sig), "SHA-1 sized digest");
    assert_eq!(card.ga(0x9E, P256, 0x81, &[0x5A; 33]).1, 0x6A80);
}

#[test]
fn generate_and_use_ed25519() {
    let mut card = authed();
    let public = card.generate(0x9C, ED25519, Some(PIN_NEVER), None);
    assert_eq!(public.point().len(), 32);
    for message in [&b""[..], b"abc", &[0x42; 1000]] {
        let (sig, sw) = card.ga(0x9C, ED25519, 0x81, message);
        assert_eq!(sw, 0x9000);
        assert_eq!(sig.len(), 64);
        assert!(ed25519_verify(public.point(), message, &sig), "RFC 8032 §5.1.7");
    }
    assert_eq!(card.ga(0x9C, ED25519, 0x85, &[9; 32]).1, 0x6A80, "Ed25519 cannot agree keys");
}

#[test]
fn generate_and_use_x25519() {
    let mut card = authed();
    let public = card.generate(0x82, X25519, Some(PIN_NEVER), None);
    let peer = X25519Key::generate(&mut SeededEntropy::new(7));
    let (shared, sw) = card.ga(0x82, X25519, 0x85, &peer.public());
    assert_eq!(sw, 0x9000);
    assert_eq!(shared, peer.dh(public.point()).unwrap().to_vec(), "RFC 7748 §6.1 agreement");
    assert_eq!(card.ga(0x82, X25519, 0x81, &[1; 32]).1, 0x6A80, "X25519 cannot sign");
    assert_eq!(card.ga(0x82, X25519, 0x85, &[1; 31]).1, 0x6A80, "wrong length");
    // The all-zero shared secret of a small-order point (RFC 7748 §6.1) is refused.
    assert_eq!(card.ga(0x82, X25519, 0x85, &[0; 32]).1, 0x6A80);
}

/// RSA signature (raw private operation on a host-padded block) and decryption round
/// trip, both checked with the public operation (RFC 8017 §5.1, §5.2).
fn check_rsa(card: &mut Card, slot: u8, alg: u8, public: &Public) {
    let Public::Rsa { n, e } = public else { panic!("RSA expected") };
    assert_eq!(e, &[0x01, 0x00, 0x01]);
    let m = representative(n, 0x33);
    let (s, sw) = card.ga(slot, alg, 0x81, &m);
    assert_eq!(sw, 0x9000);
    assert_eq!(s.len(), n.len());
    assert_eq!(rsa_public_op(n, e, &s).unwrap(), m, "RSAVP1(s) = m");
    let c = rsa_public_op(n, e, &representative(n, 0x77)).unwrap();
    let (back, sw) = card.ga(slot, alg, 0x81, &c);
    assert_eq!(sw, 0x9000);
    assert_eq!(back, representative(n, 0x77), "RSADP(RSAEP(m)) = m");
    // Input must have the modulus length and be below the modulus.
    assert_eq!(card.ga(slot, alg, 0x81, &m[1..]).1, 0x6A80);
    assert_eq!(card.ga(slot, alg, 0x81, n).1, 0x6A80, "input = n");
    assert_eq!(card.ga(slot, alg, 0x81, &vec![0xFF; n.len()]).1, 0x6A80, "input > n");
    assert_eq!(card.ga(slot, alg, 0x85, &m).1, 0x6A80, "RSA cannot agree keys");
}

#[test]
fn generate_and_use_rsa_1024_and_2048() {
    let mut card = authed();
    for (alg, len) in [(RSA1024, 128), (RSA2048, 256)] {
        let public = card.generate(0x9D, alg, Some(PIN_NEVER), None);
        assert_eq!(public.modulus().len(), len);
        check_rsa(&mut card, 0x9D, alg, &public);
    }
}

#[test]
fn generate_and_use_rsa_3072() {
    let mut card = authed();
    let public = card.generate(0x83, RSA3072, Some(PIN_NEVER), None);
    assert_eq!(public.modulus().len(), 384);
    check_rsa(&mut card, 0x83, RSA3072, &public);
}

#[test]
fn generate_and_use_rsa_4096_with_response_chaining() {
    // The 7F49 template (526 bytes) and the 512-byte results exceed one short response
    // (ISO/IEC 7816-4 §5.1, Ne = 256) and come back with 61xx and GET RESPONSE.
    let mut card = authed();
    let first = card.cmd(0x47, 0x00, 0x84, &generate_template(RSA4096, Some(PIN_NEVER), None), None);
    assert_eq!(first.0.len(), 256);
    assert_eq!(first.1 & 0xFF00, 0x6100, "61xx for the rest");
    let (template, sw) = card.collect(first);
    assert_eq!(sw, 0x9000);
    let public = parse_public_template(&template);
    assert_eq!(public.modulus().len(), 512);
    check_rsa(&mut card, 0x84, RSA4096, &public);
}

#[test]
fn generate_requires_management_key_and_checks_p1_first() {
    let mut card = Card::new();
    assert_eq!(card.try_generate(0x9A, P256, None, None).1, 0x6982);
    card.auth_default();
    let public = card.generate(0x9A, P256, None, None);
    let before = card.host.persisted(Record::Piv);
    // Catalog: GENERATE KEY PAIR rejects nonzero P1 before replacing an occupied key.
    for p1 in [0x01, 0x80, 0xFF] {
        assert_eq!(card.cmd(0x47, p1, 0x9A, &generate_template(P256, None, None), None).1, 0x6A86);
    }
    assert_eq!(card.slot_info(0x9A).unwrap().public, public, "key unchanged");
    assert_eq!(card.host.persisted(Record::Piv), before);
    // Not a key slot.
    for p2 in [0x9B, 0x80, 0x81, 0x96, 0x00, 0xFA] {
        assert_eq!(card.cmd(0x47, 0x00, p2, &generate_template(P256, None, None), None).1, 0x6A86, "{p2:02X}");
    }
    // Le is accepted: GENERATE returns data and OpenSC sends it as case 4.
    let (data, sw) = card.cmd(0x47, 0x00, 0x9A, &generate_template(P256, None, None), Some(0));
    assert_eq!(sw, 0x9000);
    assert_ne!(parse_public_template(&data), public, "a new key replaced the old one");
}

#[test]
fn generate_template_validation() {
    let mut card = authed();
    for bad in [
        "",                       // no template
        "AC03 800111 00",         // trailing byte
        "AB03 800111",            // wrong template tag
        "AC00",                   // no algorithm
        "AC03 800199",            // unknown algorithm
        "AC03 80010A",            // management key algorithm
        "AC04 80021111",          // algorithm not one byte
        "AC06 800111 800114",     // algorithm twice
        "AC06 800111 AA0104",     // PIN policy match once (biometric only)
        "AC06 800111 AA0105",     // match always
        "AC06 800111 AA0106",     // unknown PIN policy
        "AC06 800111 AB0104",     // unknown touch policy
        "AC09 800111 AA0101 AA0102", // PIN policy twice
        "AC06 800111 AC0100",     // unknown element
        "AC05 800111 AA00",       // empty policy
    ] {
        let data = hex(bad);
        assert_eq!(card.cmd(0x47, 0x00, 0x9A, &data, None).1, 0x6A80, "{bad}");
    }
    assert_eq!(card.slot_info(0x9A), None, "nothing generated");
    // Elements in any order.
    assert_eq!(card.cmd(0x47, 0x00, 0x9A, &hex("AC09 AB0103 AA0103 800111"), None).1, 0x9000);
    let info = card.slot_info(0x9A).unwrap();
    assert_eq!((info.pin, info.touch), (PIN_ALWAYS, TOUCH_CACHED));
}

#[test]
fn default_policies_are_resolved_per_slot() {
    // Yubico "Certificate slots": 9C PIN always, 9E never, every other slot once; the
    // default touch policy is never. Metadata reports the resolved policy.
    let mut card = authed();
    for (slot, pin) in [(0x9A, PIN_ONCE), (0x9C, PIN_ALWAYS), (0x9D, PIN_ONCE), (0x9E, PIN_NEVER), (0x82, PIN_ONCE), (0x95, PIN_ONCE)] {
        card.generate(slot, P256, Some(PIN_DEFAULT), Some(TOUCH_DEFAULT));
        let info = card.slot_info(slot).unwrap();
        assert_eq!((info.pin, info.touch), (pin, TOUCH_NEVER), "{slot:02X}");
    }
    card.generate(0x9A, P256, Some(PIN_NEVER), Some(TOUCH_ALWAYS));
    let info = card.slot_info(0x9A).unwrap();
    assert_eq!((info.pin, info.touch), (PIN_NEVER, TOUCH_ALWAYS));
}

#[test]
fn attestation_slot_takes_only_issuer_algorithms() {
    // Profile attestation_key_algorithms: ECCP256, ECCP384, RSA2048, RSA3072, RSA4096.
    let mut card = authed();
    let own = card.slot_info(0xF9).unwrap();
    for alg in [ED25519, X25519, RSA1024] {
        assert_eq!(card.try_generate(0xF9, alg, None, None).1, 0x6A80, "{alg:02X}");
    }
    let seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    assert_eq!(card.import(0xF9, ED25519, &tlv::encode(0x07, &seed)), 0x6A80);
    assert_eq!(card.slot_info(0xF9).unwrap(), own, "F9 unchanged");
    let public = card.generate(0xF9, P384, None, None);
    let info = card.slot_info(0xF9).unwrap();
    assert_eq!((info.alg, info.public), (P384, public));
}

#[test]
fn generated_keys_persist_and_storage_failure_keeps_the_old_key() {
    let mut card = authed();
    let public = card.generate(0x9A, P256, Some(PIN_NEVER), None);
    card.host.fail_next_saves(1);
    assert_eq!(card.try_generate(0x9A, P256, Some(PIN_NEVER), None).1, 0x6581);
    assert_eq!(card.slot_info(0x9A).unwrap().public, public, "previous key kept in memory");
    card.restart();
    assert_eq!(card.slot_info(0x9A).unwrap().public, public, "and in storage");
    check_ecdsa(&mut card, 0x9A, P256, &public);
    // An import that cannot be stored leaves the slot as it was.
    card.auth_default();
    card.host.fail_next_saves(1);
    let scalar = hex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
    assert_eq!(card.import(0x9A, P256, &tlv::encode(0x06, &scalar)), 0x6581);
    assert_eq!(card.slot_info(0x9A).unwrap().public, public);
}

#[test]
fn import_ed25519_rfc8032_test_1() {
    // RFC 8032 §7.1 TEST 1: Ed25519 is deterministic, so the signature is exact.
    let mut card = authed();
    let seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let mut data = tlv::encode(0x07, &seed);
    tlv::encode_into(&mut data, 0xAA, &[PIN_NEVER]);
    assert_eq!(card.import(0x9C, ED25519, &data), 0x9000);
    let info = card.slot_info(0x9C).unwrap();
    assert_eq!((info.alg, info.pin, info.origin), (ED25519, PIN_NEVER, 0x02));
    assert_eq!(
        info.public,
        Public::Point(hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))
    );
    let (sig, sw) = card.ga(0x9C, ED25519, 0x81, b"");
    assert_eq!(sw, 0x9000);
    assert_eq!(
        sig,
        hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    );
}

#[test]
fn import_x25519_rfc7748_section_6_1() {
    // RFC 7748 §6.1: Alice's private key in the card, Bob's public key from the host.
    let mut card = authed();
    let alice = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let mut data = tlv::encode(0x08, &alice);
    tlv::encode_into(&mut data, 0xAA, &[PIN_NEVER]);
    assert_eq!(card.import(0x9D, X25519, &data), 0x9000);
    assert_eq!(
        card.slot_info(0x9D).unwrap().public,
        Public::Point(hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
    );
    let bob = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let (shared, sw) = card.ga(0x9D, X25519, 0x85, &bob);
    assert_eq!(sw, 0x9000);
    assert_eq!(shared, hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));
}

#[test]
fn import_ec_rfc6979_keys() {
    // RFC 6979 A.2.5 (P-256) and A.2.6 (P-384): private key x and public point (Ux, Uy).
    let mut card = authed();
    let cases = [
        (
            P256,
            "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
            "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6\
             7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
        ),
        (
            P384,
            "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5",
            "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13\
             8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720",
        ),
    ];
    for (alg, x, u) in cases {
        let mut data = tlv::encode(0x06, &hex(x));
        tlv::encode_into(&mut data, 0xAA, &[PIN_NEVER]);
        tlv::encode_into(&mut data, 0xAB, &[TOUCH_NEVER]);
        assert_eq!(card.import(0x9E, alg, &data), 0x9000);
        let mut point = vec![0x04];
        point.extend(hex(u));
        let info = card.slot_info(0x9E).unwrap();
        assert_eq!((info.alg, info.origin, info.public.clone()), (alg, 0x02, Public::Point(point)));
        check_ecdsa(&mut card, 0x9E, alg, &info.public);
    }
    // A P-256 scalar of the wrong length, zero, or the group order is refused (SEC 1
    // §3.2.1: 1 <= d < n).
    for bad in [
        "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F67",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
    ] {
        assert_eq!(card.import(0x9A, P256, &tlv::encode(0x06, &hex(bad))), 0x6A80, "{bad}");
    }
}

#[test]
fn import_rsa_from_crt_components() {
    // Yubico IMPORT: 01 P, 02 Q, 03 dP, 04 dQ, 05 qInv; exponent 65537.
    let mut card = authed();
    for (alg, key) in [(RSA1024, rsa1024()), (RSA2048, rsa2048())] {
        let primes = key.primes();
        let mut data = rsa_import_elements(&primes.0, &primes.1, key.size());
        tlv::encode_into(&mut data, 0xAA, &[PIN_NEVER]);
        assert_eq!(card.import(0x9A, alg, &data), 0x9000, "{alg:02X}");
        let info = card.slot_info(0x9A).unwrap();
        assert_eq!(info.origin, 0x02);
        assert_eq!(info.public, Public::Rsa { n: key.modulus(), e: vec![1, 0, 1] });
        check_rsa(&mut card, 0x9A, alg, &info.public);
    }
}

#[test]
fn import_rsa_rejects_inconsistent_or_wrong_size_keys() {
    let mut card = authed();
    let key = rsa1024();
    let primes = key.primes();
    let good = rsa_import_elements(&primes.0, &primes.1, key.size());
    let items = tlv::parse_all(&good).unwrap();
    let rebuild = |replace: u32, value: &[u8]| {
        let mut out = Vec::new();
        for item in &items {
            tlv::encode_into(&mut out, item.tag, if item.tag == replace { value } else { item.value });
        }
        out
    };
    let mut wrong = items[2].value.to_vec();
    *wrong.last_mut().unwrap() ^= 2;
    assert_eq!(card.import(0x9A, RSA1024, &rebuild(3, &wrong)), 0x6A80, "dP");
    let mut wrong = items[3].value.to_vec();
    *wrong.last_mut().unwrap() ^= 2;
    assert_eq!(card.import(0x9A, RSA1024, &rebuild(4, &wrong)), 0x6A80, "dQ");
    let mut wrong = items[4].value.to_vec();
    *wrong.last_mut().unwrap() ^= 2;
    assert_eq!(card.import(0x9A, RSA1024, &rebuild(5, &wrong)), 0x6A80, "qInv");
    // A 1024-bit key is not an RSA-2048 key.
    assert_eq!(card.import(0x9A, RSA2048, &good), 0x6A80, "modulus size");
    // Missing, duplicated or foreign elements.
    let missing: Vec<u8> = items[..4].iter().flat_map(|i| i.raw.to_vec()).collect();
    assert_eq!(card.import(0x9A, RSA1024, &missing), 0x6A80);
    let mut twice = good.clone();
    twice.extend_from_slice(items[0].raw);
    assert_eq!(card.import(0x9A, RSA1024, &twice), 0x6A80);
    let mut foreign = good.clone();
    tlv::encode_into(&mut foreign, 0x06, &[1; 32]);
    assert_eq!(card.import(0x9A, RSA1024, &foreign), 0x6A80);
    assert_eq!(card.slot_info(0x9A), None, "nothing imported");
}

#[test]
fn import_header_and_element_validation() {
    let mut card = Card::new();
    let seed = tlv::encode(0x07, &[7; 32]);
    assert_eq!(card.import(0x9A, ED25519, &seed), 0x6982, "needs the management key");
    card.auth_default();
    let before = card.host.persisted(Record::Piv);
    assert_eq!(card.cmd(0xFE, ED25519, 0x9A, &seed, Some(1)).1, 0x6700, "non-zero Le");
    assert_eq!(card.cmd(0xFE, 0x0A, 0x9A, &seed, None).1, 0x6A86, "unknown algorithm");
    assert_eq!(card.cmd(0xFE, ED25519, 0x9B, &seed, None).1, 0x6A86, "not a key slot");
    for bad in ["0720" , "071F0707070707070707070707070707070707070707070707070707070707070707", "0820 0707070707070707070707070707070707070707070707070707070707070707", "", "AA0101"] {
        assert_eq!(card.import(0x9A, ED25519, &hex(bad)), 0x6A80, "{bad}");
    }
    let mut policy_twice = seed.clone();
    policy_twice.extend(hex("AB0101 AB0102"));
    assert_eq!(card.import(0x9A, ED25519, &policy_twice), 0x6A80);
    let mut bio = seed.clone();
    bio.extend(hex("AA0104"));
    assert_eq!(card.import(0x9A, ED25519, &bio), 0x6A80, "biometric PIN policy");
    assert_eq!(card.host.persisted(Record::Piv), before, "nothing changed");
    assert_eq!(card.import(0x9A, ED25519, &seed), 0x9000);
    // An imported key cannot be told apart from a generated one when signing.
    let public = card.slot_info(0x9A).unwrap().public;
    card.verify_default_pin();
    let (sig, _) = card.ga(0x9A, ED25519, 0x81, b"msg");
    assert!(ed25519_verify(public.point(), b"msg", &sig));
    assert_eq!(public.point(), Ed25519Key::from_seed(&[7; 32]).unwrap().public());
}

#[test]
fn general_authenticate_request_validation() {
    let mut card = authed();
    card.generate(0x9A, P256, Some(PIN_NEVER), None);
    let digest = [0x22u8; 32];
    assert_eq!(card.ga(0x9C, P256, 0x81, &digest).1, 0x6A88, "empty slot");
    assert_eq!(card.ga(0x9A, P384, 0x81, &digest).1, 0x6A86, "P1 is not the key's algorithm");
    assert_eq!(card.ga(0x9A, ED25519, 0x81, &digest).1, 0x6A86);
    assert_eq!(card.ga(0xF9, P256, 0x81, &digest).1, 0x6A86, "the attestation key only attests");
    assert_eq!(card.ga(0x96, P256, 0x81, &digest).1, 0x6A86, "not a key slot");
    for bad in [
        "7C24 8200 8120 2222222222222222222222222222222222222222222222222222222222222222 00",  // trailing byte
        "7D24 8200 8120 2222222222222222222222222222222222222222222222222222222222222222",     // wrong template tag
        "7C22 8120 2222222222222222222222222222222222222222222222222222222222222222",          // no response request
        "7C25 820100 8120 2222222222222222222222222222222222222222222222222222222222222222",   // non-empty response request
        "7C26 8200 8200 8120 2222222222222222222222222222222222222222222222222222222222222222", // three elements
        "7C24 8200 8020 2222222222222222222222222222222222222222222222222222222222222222",     // witness instead of challenge
        "7C02 8200",
        "7C00",
        "",
        "7C05 8200 8130",
    ] {
        assert_eq!(card.cmd(0x87, P256, 0x9A, &hex(bad), None).1, 0x6A80, "{bad}");
    }
    // Elements in either order are accepted.
    let (resp, sw) = card.cmd(0x87, P256, 0x9A, &hex("7C24 8120 2222222222222222222222222222222222222222222222222222222222222222 8200"), None);
    assert_eq!(sw, 0x9000);
    assert!(!dyn_auth_item(&resp, 0x82).is_empty());
    // An invalid peer point (not on the curve / compressed) is refused.
    let mut off_curve = card.slot_info(0x9A).unwrap().public.point().to_vec();
    *off_curve.last_mut().unwrap() ^= 1;
    assert_eq!(card.ga(0x9A, P256, 0x85, &off_curve).1, 0x6A80);
    assert_eq!(card.ga(0x9A, P256, 0x85, &off_curve[..33]).1, 0x6A80);
}

#[test]
fn general_authenticate_accepts_le() {
    // SP 800-73-4 Part 2 §3.2.4: Le is "absent or length of expected response"; OpenSC
    // and the macOS PIV token send case 4. Model choice recorded in docs/catalog/piv.md.
    let mut card = authed();
    let public = card.generate(0x9A, P256, Some(PIN_NEVER), None);
    let mut inner = tlv::encode(0x82, &[]);
    tlv::encode_into(&mut inner, 0x81, &[0x33; 32]);
    for le in [0u32, 0x48, 0xFF] {
        let first = card.cmd(0x87, P256, 0x9A, &tlv::encode(0x7C, &inner), Some(le));
        // At most Ne bytes come back (ISO/IEC 7816-4 §5.1); a DER signature with its
        // 7C/82 headers can exceed 0x48 bytes, and the rest follows GET RESPONSE.
        let ne = if le == 0 { 256 } else { le as usize };
        assert!(first.0.len() <= ne, "Le {le:02X}");
        if first.1 != 0x9000 {
            assert_eq!((first.0.len(), first.1 >> 8), (ne, 0x61), "Le {le:02X}");
        }
        let (resp, sw) = card.collect(first);
        assert_eq!(sw, 0x9000);
        assert!(ecdsa_ok(P256, public.point(), &[0x33; 32], &dyn_auth_item(&resp, 0x82)));
    }
}

#[test]
fn chained_rsa_2048_request_and_chained_response() {
    // A 2048-bit operation needs command chaining (ISO/IEC 7816-4 §5.1.1.1) for its
    // 264-byte template and response chaining for its 264-byte answer.
    let mut card = authed();
    let public = card.generate(0x9A, RSA2048, Some(PIN_NEVER), None);
    let m = representative(public.modulus(), 0x44);
    let outcome = card.ga_outcome(0x9A, RSA2048, 0x81, &m);
    let Outcome::Done(resp) = outcome else { panic!("no touch") };
    let (data, sw) = lk_codec::apdu::split_response(&resp).unwrap();
    assert_eq!((data.len(), sw), (256, 0x6108), "first 256 bytes, 8 more");
    let (rest, sw) = card.send("00C0000000");
    assert_eq!((rest.len(), sw), (8, 0x9000));
    let mut all = data.to_vec();
    all.extend(rest);
    let s = dyn_auth_item(&all, 0x82);
    assert_eq!(rsa_public_op(public.modulus(), &[1, 0, 1], &s).unwrap(), m);
}
