//! P-256 / P-384 private scalars: range checks and generation retries.
//!
//! The group orders are from SEC 2 v2 §2.4.2 / §2.5.1 (also printed as `q` in RFC 6979
//! A.2.5 and A.2.6). FIPS 186-5 §A.2 requires 1 <= d <= n - 1.

use lk_crypto::{Curve, CryptoError, EcPrivateKey};

use crate::common::{ScriptedEntropy, hex};

const P256_N: &str = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";
const P384_N: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973";

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

fn curves() -> [(Curve, &'static str); 2] {
    [(Curve::P256, P256_N), (Curve::P384, P384_N)]
}

#[test]
fn lengths() {
    assert_eq!(Curve::P256.field_len(), 32);
    assert_eq!(Curve::P384.field_len(), 48);
    assert_eq!(Curve::P256.point_len(), 65);
    assert_eq!(Curve::P384.point_len(), 97);
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
