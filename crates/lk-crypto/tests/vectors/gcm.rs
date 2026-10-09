//! AES-256-GCM. Vectors from McGrew and Viega, "The Galois/Counter Mode of Operation
//! (GCM)", revised submission to NIST (2005), Appendix B, test cases 13-16 (the AES-256
//! cases with a 96-bit IV).

use lk_crypto::{CryptoError, aes_gcm_open, aes_gcm_seal};

use crate::common::hex;

const KEY_15: &str = "feffe9928665731c6d6a8f9467308308 feffe9928665731c6d6a8f9467308308";
const IV_15: &str = "cafebabefacedbaddecaf888";
const PLAINTEXT_15: &str = "d9313225f88406e5a55909c5aff5269a 86a7a9531534f7da2e4c303d8a318a72
                            1c3c0c95956809532fcf0e2449a6b525 b16aedf5aa0de657ba637b391aafd255";
const CIPHERTEXT_15: &str = "522dc1f099567d07f47f37a32a84427d 643a8cdcbfe5c0c97598a2bd2555d1aa
                             8cb08e48590dbb3da7b08b1056828838 c5f61e6393ba7a0abcc9f662898015ad";

fn check(key: &[u8], iv: &[u8], aad: &[u8], plaintext: &[u8], sealed: &[u8], name: &str) {
    assert_eq!(aes_gcm_seal(key, iv, aad, plaintext).unwrap(), sealed, "{name} seal");
    assert_eq!(aes_gcm_open(key, iv, aad, sealed).unwrap(), plaintext, "{name} open");
}

#[test]
fn test_case_13_empty() {
    // Test case 13: K = 0^256, IV = 0^96, P and A empty; output is the tag alone.
    check(&[0; 32], &[0; 12], &[], &[], &hex("530f8afbc74536b9a963b4f1c4cb738b"), "case 13");
}

#[test]
fn test_case_14_one_zero_block() {
    // Test case 14: K = 0^256, IV = 0^96, P = 0^128, A empty.
    check(
        &[0; 32],
        &[0; 12],
        &[],
        &[0; 16],
        &hex("cea7403d4d606b6e074ec5d3baf39d18 d0d1c8a799996bf0265b98b5d48ab919"),
        "case 14",
    );
}

#[test]
fn test_case_15_four_blocks() {
    // Test case 15: 64-byte plaintext, no AAD.
    let sealed = [hex(CIPHERTEXT_15), hex("b094dac5d93471bdec1a502270e3cc6c")].concat();
    check(&hex(KEY_15), &hex(IV_15), &[], &hex(PLAINTEXT_15), &sealed, "case 15");
}

struct Case16 {
    key: Vec<u8>,
    iv: Vec<u8>,
    aad: Vec<u8>,
    plaintext: Vec<u8>,
    sealed: Vec<u8>,
}

fn case_16() -> Case16 {
    // Test case 16: the first 60 bytes of case 15's plaintext with 20 bytes of AAD.
    Case16 {
        key: hex(KEY_15),
        iv: hex(IV_15),
        aad: hex("feedfacedeadbeeffeedfacedeadbeef abaddad2"),
        plaintext: hex(PLAINTEXT_15)[..60].to_vec(),
        sealed: [hex(CIPHERTEXT_15)[..60].to_vec(), hex("76fc6ece0f4e1768cddf8853bb2d551b")].concat(),
    }
}

#[test]
fn test_case_16_with_aad() {
    let Case16 { key, iv, aad, plaintext, sealed } = case_16();
    check(&key, &iv, &aad, &plaintext, &sealed, "case 16");
}

#[test]
fn tampering_is_detected() {
    let Case16 { key, iv, aad, sealed, .. } = case_16();
    // Flip one bit in the ciphertext, then in the tag.
    for index in [0, 59, 60, sealed.len() - 1] {
        let mut tampered = sealed.clone();
        tampered[index] ^= 0x01;
        assert_eq!(aes_gcm_open(&key, &iv, &aad, &tampered), Err(CryptoError::VerificationFailed), "byte {index}");
    }
    // Modified or missing AAD.
    let mut bad_aad = aad.clone();
    bad_aad[19] ^= 0x80;
    assert_eq!(aes_gcm_open(&key, &iv, &bad_aad, &sealed), Err(CryptoError::VerificationFailed));
    assert_eq!(aes_gcm_open(&key, &iv, &[], &sealed), Err(CryptoError::VerificationFailed));
    // Another nonce or key.
    let mut bad_iv = iv.clone();
    bad_iv[0] ^= 0x01;
    assert_eq!(aes_gcm_open(&key, &bad_iv, &aad, &sealed), Err(CryptoError::VerificationFailed));
    let mut bad_key = key.clone();
    bad_key[31] ^= 0x01;
    assert_eq!(aes_gcm_open(&bad_key, &iv, &aad, &sealed), Err(CryptoError::VerificationFailed));
    // Truncated: dropping a tag byte, or less than a whole tag.
    assert_eq!(aes_gcm_open(&key, &iv, &aad, &sealed[..sealed.len() - 1]), Err(CryptoError::VerificationFailed));
    assert_eq!(aes_gcm_open(&key, &iv, &aad, &sealed[..15]), Err(CryptoError::VerificationFailed));
    assert_eq!(aes_gcm_open(&key, &iv, &aad, &[]), Err(CryptoError::VerificationFailed));
}

#[test]
fn rejects_bad_key_and_nonce_lengths() {
    // The API is AES-256 with a 96-bit nonce only (docs/CONTRACTS.md, lk-crypto and lk-device sealing).
    for len in [0, 16, 24, 31, 33] {
        assert_eq!(aes_gcm_seal(&vec![0; len], &[0; 12], b"", b"x"), Err(CryptoError::InvalidKey), "key {len}");
        assert_eq!(aes_gcm_open(&vec![0; len], &[0; 12], b"", &[0; 17]), Err(CryptoError::InvalidKey), "key {len}");
    }
    for len in [0, 8, 11, 13, 16] {
        assert_eq!(aes_gcm_seal(&[0; 32], &vec![0; len], b"", b"x"), Err(CryptoError::InvalidInput), "nonce {len}");
        assert_eq!(aes_gcm_open(&[0; 32], &vec![0; len], b"", &[0; 17]), Err(CryptoError::InvalidInput), "nonce {len}");
    }
}
