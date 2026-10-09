//! Ed25519, RFC 8032 §7.1 TEST 1-3.

use lk_crypto::{CryptoError, Ed25519Key, ed25519_verify};

use crate::common::{ScriptedEntropy, hex};

struct Case {
    name: &'static str,
    secret: &'static str,
    public: &'static str,
    message: &'static str,
    signature: &'static str,
}

const CASES: [Case; 3] = [
    Case {
        name: "TEST 1",
        secret: "9d61b19deffd5a60ba844af492ec2cc4 4449c5697b326919703bac031cae7f60",
        public: "d75a980182b10ab7d54bfed3c964073a 0ee172f3daa62325af021a68f707511a",
        message: "",
        signature: "e5564300c360ac729086e2cc806e828a 84877f1eb8e5d974d873e06522490155
                    5fb8821590a33bacc61e39701cf9b46b d25bf5f0595bbe24655141438e7a100b",
    },
    Case {
        name: "TEST 2",
        secret: "4ccd089b28ff96da9db6c346ec114e0f 5b8a319f35aba624da8cf6ed4fb8a6fb",
        public: "3d4017c3e843895a92b70aa74d1b7ebc 9c982ccf2ec4968cc0cd55f12af4660c",
        message: "72",
        signature: "92a009a9f0d4cab8720e820b5f642540 a2b27b5416503f8fb3762223ebdb69da
                    085ac1e43e15996e458f3613d0f11d8c 387b2eaeb4302aeeb00d291612bb0c00",
    },
    Case {
        name: "TEST 3",
        secret: "c5aa8df43f9f837bedb7442f31dcb7b1 66d38535076f094b85ce3a2e0b4458f7",
        public: "fc51cd8e6218a1a38da47ed00230f058 0816ed13ba3303ac5deb911548908025",
        message: "af82",
        signature: "6291d657deec24024827e69c3abe01a3 0ce548a284743a445e3680d7db5ac3ac
                    18ff9b538d16f290ae67f760984dc659 4a7c15e9716ed28dc027beceea1ec40a",
    },
];

#[test]
fn rfc8032_public_keys_and_signatures() {
    for case in &CASES {
        let key = Ed25519Key::from_seed(&hex(case.secret)).unwrap();
        assert_eq!(key.seed().to_vec(), hex(case.secret), "{}", case.name);
        assert_eq!(key.public().to_vec(), hex(case.public), "{} public key", case.name);
        assert_eq!(key.sign(&hex(case.message)).to_vec(), hex(case.signature), "{} signature", case.name);
    }
}

#[test]
fn rfc8032_signatures_verify() {
    for case in &CASES {
        assert!(ed25519_verify(&hex(case.public), &hex(case.message), &hex(case.signature)), "{}", case.name);
    }
}

#[test]
fn verify_rejects_modified_inputs() {
    let case = &CASES[2];
    let public = hex(case.public);
    let message = hex(case.message);
    let signature = hex(case.signature);

    // Another message.
    assert!(!ed25519_verify(&public, b"\xaf\x83", &signature));
    assert!(!ed25519_verify(&public, &message[..1], &signature));
    // One flipped bit in R, then in S.
    for index in [0, 31, 32, 63] {
        let mut bad = signature.clone();
        bad[index] ^= 0x01;
        assert!(!ed25519_verify(&public, &message, &bad), "signature byte {index}");
    }
    // Another key's public key.
    assert!(!ed25519_verify(&hex(CASES[0].public), &message, &signature));
    // Wrong lengths.
    assert!(!ed25519_verify(&public[..31], &message, &signature));
    assert!(!ed25519_verify(&public, &message, &signature[..63]));
    assert!(!ed25519_verify(&public, &message, &[signature.as_slice(), &[0]].concat()));
}

/// Little-endian 256-bit addition (no overflow for the values used here).
fn add_le(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut carry = 0u16;
    a.iter()
        .zip(b)
        .map(|(&x, &y)| {
            let sum = u16::from(x) + u16::from(y) + carry;
            carry = sum >> 8;
            sum as u8
        })
        .collect()
}

#[test]
fn verify_rejects_non_canonical_s() {
    // RFC 8032 §5.1.7 step 1: reject S >= L. S + L verifies under the raw group equation,
    // so this checks the canonical-S rule rather than the arithmetic.
    // L = 2^252 + 27742317777372353535851937790883648493, little-endian.
    let order = hex("edd3f55c1a631258d69cf7a2def9de14 00000000000000000000000000000010");
    let case = &CASES[0];
    let signature = hex(case.signature);
    let malleated = [&signature[..32], add_le(&signature[32..], &order).as_slice()].concat();
    assert!(!ed25519_verify(&hex(case.public), &hex(case.message), &malleated));
}

#[test]
fn generate_uses_entropy_as_the_seed() {
    let mut entropy = ScriptedEntropy::new(vec![hex(CASES[1].secret)]);
    let key = Ed25519Key::generate(&mut entropy);
    assert_eq!(key.public().to_vec(), hex(CASES[1].public));
    assert_eq!(entropy.remaining(), 0);
}

#[test]
fn from_seed_rejects_wrong_lengths() {
    for len in [0, 31, 33, 64] {
        assert_eq!(Ed25519Key::from_seed(&vec![0; len]).unwrap_err(), CryptoError::InvalidKey, "{len}");
    }
}

#[test]
fn verify_rejects_small_order_keys_and_commitments() {
    // RFC 8032 §5.1.7 accepts when [S]B = R + [k]A. For a small-order ("weak") A that
    // holds for forgeries: with A the identity (y = 1, RFC 8032 §5.1.2 encoding 01 00 .. 00),
    // (R, S) = (B, 1) verifies for every message. B is the base point (x, 4/5) of
    // RFC 8032 §5.1, encoded 58 66 .. 66.
    let identity = "0100000000000000000000000000000000000000000000000000000000000000";
    let base = "5866666666666666666666666666666666666666666666666666666666666666";
    let forged = hex(&format!("{base}{identity}"));
    for message in [&b""[..], b"\x72", b"any message at all"] {
        assert!(!ed25519_verify(&hex(identity), message, &forged), "{message:?}");
    }
    // R = A = identity with S = 0 satisfies the same equation.
    let zero = "00".repeat(32);
    assert!(!ed25519_verify(&hex(identity), b"msg", &hex(&format!("{identity}{zero}"))));
    // The identity with the x sign bit set: RFC 8032 §5.1.3 step 4 says decoding fails.
    // Whether the key fails to decode or is refused as small-order, the answer is false.
    let mut signed_identity = hex(identity);
    signed_identity[31] |= 0x80;
    assert!(!ed25519_verify(&signed_identity, b"msg", &forged));
}

#[test]
fn verify_rejects_public_keys_that_do_not_decode() {
    // RFC 8032 §5.1.3 step 3: for y = 2, x^2 = (y^2 - 1) / (d y^2 + 1) has no square root
    // mod p, so decoding fails (checked against the §5.1 curve constants).
    let not_on_curve = hex("0200000000000000000000000000000000000000000000000000000000000000");
    let case = &CASES[0];
    assert!(!ed25519_verify(&not_on_curve, &hex(case.message), &hex(case.signature)));
}

#[test]
fn debug_does_not_leak_the_seed() {
    let key = Ed25519Key::from_seed(&hex(CASES[0].secret)).unwrap();
    assert_eq!(format!("{key:?}"), "Ed25519Key { .. }");
}
