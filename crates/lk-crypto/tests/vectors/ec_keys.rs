//! Private scalars on every curve: range checks and generation retries.
//!
//! The group orders: P-256 / P-384 from SEC 2 v2 §2.4.2 / §2.5.1 (also `q` in RFC 6979
//! A.2.5 and A.2.6); P-521 from RFC 6979 A.2.7 (`q`, SEC 2 v2 §2.6.1); secp256k1 from SEC 2
//! v2 §2.4.1; brainpoolP256r1 / brainpoolP384r1 from RFC 5639 §3.4 / §3.6 (`q`).
//! FIPS 186-5 §A.2 requires 1 <= d <= n - 1.

use lk_crypto::{Curve, CryptoError, EcPrivateKey};

use crate::common::{ScriptedEntropy, hex};

const P256_N: &str = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";
const P384_N: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973";
// 521 bits, written with the leading zero bits of its 66-byte encoding.
const P521_N: &str = "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
                      FA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409";
const SECP256K1_N: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const BP256_N: &str = "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7";
const BP384_N: &str = "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7
                       CF3AB6AF6B7FC3103B883202E9046565";

/// `n + delta` for a small signed `delta`, on big-endian bytes.
fn offset(n: &str, delta: i16) -> Vec<u8> {
    let mut bytes = hex(n);
    let mut carry = delta;
    for byte in bytes.iter_mut().rev() {
        let sum = i16::from(*byte) + carry;
        *byte = sum.rem_euclid(256) as u8;
        carry = sum.div_euclid(256);
        if carry == 0 {
            break;
        }
    }
    bytes
}

fn curves() -> [(Curve, &'static str); 6] {
    [
        (Curve::P256, P256_N),
        (Curve::P384, P384_N),
        (Curve::P521, P521_N),
        (Curve::Secp256k1, SECP256K1_N),
        (Curve::BrainpoolP256r1, BP256_N),
        (Curve::BrainpoolP384r1, BP384_N),
    ]
}

#[test]
fn lengths() {
    // SEC 1 v2 §2.3.5: ceil(log2 p / 8) octets per coordinate.
    for (curve, field, point) in [
        (Curve::P256, 32, 65),
        (Curve::P384, 48, 97),
        (Curve::P521, 66, 133),
        (Curve::Secp256k1, 32, 65),
        (Curve::BrainpoolP256r1, 32, 65),
        (Curve::BrainpoolP384r1, 48, 97),
    ] {
        assert_eq!(curve.field_len(), field, "{curve:?}");
        assert_eq!(curve.point_len(), point, "{curve:?}");
    }
    assert_eq!(Curve::ALL.len(), curves().len());
    for (curve, n) in curves() {
        assert!(Curve::ALL.contains(&curve));
        assert_eq!(hex(n).len(), curve.field_len(), "{curve:?}");
    }
}

#[test]
fn from_scalar_accepts_the_valid_range_edges() {
    for (curve, n) in curves() {
        let mut one = vec![0; curve.field_len()];
        *one.last_mut().unwrap() = 1;
        for scalar in [one, offset(n, -1)] {
            let key = EcPrivateKey::from_scalar(curve, &scalar).unwrap();
            assert_eq!(key.scalar(), scalar.as_slice());
            assert_eq!(key.curve(), curve);
            assert_eq!(key.public_uncompressed().len(), curve.point_len());
        }
    }
}

#[test]
fn from_scalar_rejects_zero_order_and_above() {
    for (curve, n) in curves() {
        let len = curve.field_len();
        for (scalar, what) in [
            (vec![0; len], "zero"),
            (hex(n), "n"),
            (offset(n, 1), "n + 1"),
            (vec![0xff; len], "all ones"),
        ] {
            assert_eq!(EcPrivateKey::from_scalar(curve, &scalar).unwrap_err(), CryptoError::InvalidKey, "{curve:?} {what}");
        }
    }
}

#[test]
fn from_scalar_rejects_wrong_lengths() {
    // A valid value with a missing or extra leading byte is still the wrong encoding.
    for (curve, _) in curves() {
        let len = curve.field_len();
        for bad in [0, 1, len - 1, len + 1, 2 * len] {
            let mut scalar = vec![0; bad];
            if let Some(last) = scalar.last_mut() {
                *last = 1;
            }
            assert_eq!(EcPrivateKey::from_scalar(curve, &scalar).unwrap_err(), CryptoError::InvalidKey, "{curve:?} {bad}");
        }
    }
    // A P-256 scalar is not a P-384 scalar and vice versa.
    assert!(EcPrivateKey::from_scalar(Curve::P384, &offset(P256_N, -1)).is_err());
    assert!(EcPrivateKey::from_scalar(Curve::P256, &offset(P384_N, -1)).is_err());
    // A P-521 scalar is 66 bytes even when its value fits in 65 (OpenPGP's "66-byte
    // zero-padded" import form).
    assert!(EcPrivateKey::from_scalar(Curve::P521, &offset(P521_N, -1)[1..]).is_err());
}

#[test]
fn orders_differ_between_same_length_curves() {
    // n - 1 of one 32-byte curve is out of range for another whose order is smaller.
    assert!(EcPrivateKey::from_scalar(Curve::BrainpoolP256r1, &offset(P256_N, -1)).is_err());
    assert!(EcPrivateKey::from_scalar(Curve::P256, &offset(SECP256K1_N, -1)).is_err());
    assert!(EcPrivateKey::from_scalar(Curve::Secp256k1, &offset(P256_N, -1)).is_ok());
    assert!(EcPrivateKey::from_scalar(Curve::BrainpoolP384r1, &offset(P384_N, -1)).is_err());
}

#[test]
fn p521_generation_draws_521_bits() {
    // FIPS 186-5 Appendix A.2.2: rejection sampling over bitlen(n) = 521 bits. The seven
    // excess bits of the first byte are cleared before the range check, so a 0xFE first
    // byte becomes 0x00 and the draw is used rather than rejected.
    let mut draw = vec![0xFE];
    draw.extend([0x5A; 65]);
    let mut entropy = ScriptedEntropy::new(vec![draw.clone()]);
    let key = EcPrivateKey::generate(Curve::P521, &mut entropy);
    let mut expected = draw;
    expected[0] = 0x00;
    assert_eq!(key.scalar(), expected.as_slice());
    assert_eq!(entropy.calls, 1);
    // 0x03.. keeps only bit 0: 0x01 5A.. is below n and accepted.
    let mut draw = vec![0x03];
    draw.extend([0x5A; 65]);
    let key = EcPrivateKey::generate(Curve::P521, &mut ScriptedEntropy::new(vec![draw]));
    assert_eq!(key.scalar()[0], 0x01);
    assert_eq!(key.scalar()[1..], [0x5A; 65]);
}

#[test]
fn generated_keys_are_valid_on_every_curve() {
    let mut entropy = crate::common::CounterEntropy::new(b"generate");
    for curve in Curve::ALL {
        for _ in 0..4 {
            let key = EcPrivateKey::generate(curve, &mut entropy);
            assert_eq!(key.scalar().len(), curve.field_len(), "{curve:?}");
            assert!(EcPrivateKey::from_scalar(curve, key.scalar()).is_ok(), "{curve:?}");
            assert!(lk_crypto::ec_public_is_valid(curve, &key.public_uncompressed()), "{curve:?}");
        }
    }
}

#[test]
fn generate_retries_until_the_scalar_is_valid() {
    // All-0xFF exceeds n and zero is excluded, so both draws must be discarded.
    for (curve, n) in curves() {
        let len = curve.field_len();
        let valid = offset(n, -2);
        let mut entropy = ScriptedEntropy::new(vec![vec![0xff; len], vec![0; len], hex(n), valid.clone()]);
        let key = EcPrivateKey::generate(curve, &mut entropy);
        assert_eq!(key.scalar(), valid.as_slice(), "{curve:?}");
        assert_eq!(entropy.calls, 4, "{curve:?}");
        assert_eq!(entropy.remaining(), 0, "{curve:?}");
    }
}

#[test]
fn generate_takes_the_first_valid_draw() {
    // RFC 6979 A.2.5 private key: valid on the first draw, nothing else consumed.
    let x = hex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
    let mut entropy = ScriptedEntropy::new(vec![x.clone()]);
    let key = EcPrivateKey::generate(Curve::P256, &mut entropy);
    assert_eq!(key.scalar(), x.as_slice());
    assert_eq!(entropy.calls, 1);
}

#[test]
fn debug_does_not_leak_the_scalar() {
    let key = EcPrivateKey::from_scalar(Curve::P256, &offset(P256_N, -1)).unwrap();
    let text = format!("{key:?}");
    assert!(text.contains("P256"));
    assert!(!text.contains("scalar"), "{text}");
    assert!(!text.contains("255"), "{text}");
}
