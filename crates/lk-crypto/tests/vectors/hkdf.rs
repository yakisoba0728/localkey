//! HKDF-SHA-256, RFC 5869 Appendix A.1-A.3.

use lk_crypto::{CryptoError, hkdf_sha256};

use crate::common::hex;

#[test]
fn rfc5869_case1_basic() {
    // RFC 5869 A.1.
    let okm = hkdf_sha256(
        Some(&hex("000102030405060708090a0b0c")),
        &hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
        &hex("f0f1f2f3f4f5f6f7f8f9"),
        42,
    )
    .unwrap();
    assert_eq!(
        okm,
        hex("3cb25f25faacd57a90434f64d0362f2a 2d2d0a90cf1a5a4c5db02d56ecc4c5bf 34007208d5b887185865")
    );
}

#[test]
fn rfc5869_case2_long_inputs() {
    // RFC 5869 A.2: 80-byte IKM, salt and info; 82-byte output (three HMAC blocks).
    let ikm: Vec<u8> = (0x00..=0x4f).collect();
    let salt: Vec<u8> = (0x60..=0xaf).collect();
    let info: Vec<u8> = (0xb0..=0xff).collect();
    let okm = hkdf_sha256(Some(&salt), &ikm, &info, 82).unwrap();
    assert_eq!(
        okm,
        hex("b11e398dc80327a1c8e7f78c596a4934 4f012eda2d4efad8a050cc4c19afa97c
             59045a99cac7827271cb41c65e590e09 da3275600c2f09b8367793a9aca3db71
             cc30c58179ec3e87c14c01d5c1f3434f 1d87")
    );
}

#[test]
fn rfc5869_case3_empty_salt_and_info() {
    // RFC 5869 A.3. A zero-length salt and an absent salt are the same thing: §2.2 says
    // an absent salt is HashLen zero bytes, and HMAC zero-pads a short key anyway.
    let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let expected = hex("8da4e775a563c18f715f802a063c5a31 b8a11f5c5ee1879ec3454e5f3c738d2d 9d201395faa4b61a96c8");
    assert_eq!(hkdf_sha256(Some(&[]), &ikm, &[], 42).unwrap(), expected);
    assert_eq!(hkdf_sha256(None, &ikm, &[], 42).unwrap(), expected);
}

#[test]
fn output_length_limits() {
    // RFC 5869 §2.3: L <= 255 * HashLen.
    let ikm = [0x0b; 22];
    assert_eq!(hkdf_sha256(None, &ikm, b"", 255 * 32).unwrap().len(), 255 * 32);
    assert_eq!(hkdf_sha256(None, &ikm, b"", 255 * 32 + 1), Err(CryptoError::InvalidInput));
    assert_eq!(hkdf_sha256(None, &ikm, b"", 0).unwrap(), Vec::<u8>::new());
}

#[test]
fn shorter_output_is_a_prefix() {
    // RFC 5869 §2.3: T(1) || T(2) ... truncated to L octets.
    let ikm = [0x0b; 22];
    let long = hkdf_sha256(None, &ikm, b"info", 64).unwrap();
    let short = hkdf_sha256(None, &ikm, b"info", 20).unwrap();
    assert_eq!(short, long[..20]);
}

#[test]
fn oversized_lengths_fail_before_allocating() {
    // RFC 5869 §2.3 bounds L by 255 * HashLen. Lengths far beyond it must be refused
    // up front; allocating the buffer first overflowed (usize::MAX) or aborted the process.
    let ikm = [0x0b; 22];
    for len in [255 * 32 + 1, 1 << 40, usize::MAX] {
        assert_eq!(hkdf_sha256(None, &ikm, b"", len), Err(CryptoError::InvalidInput), "L = {len}");
    }
}
