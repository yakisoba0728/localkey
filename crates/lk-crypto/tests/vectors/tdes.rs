//! TDEA (three-key 3DES, EDE) single-block ECB.

use lk_crypto::{CryptoError, tdes_ecb_decrypt_block, tdes_ecb_encrypt_block};

use crate::common::hex;

#[test]
fn sp800_67_appendix_b_example() {
    // NIST SP 800-67 Rev. 1, Appendix B (TDEA ECB example): Key1 = 0123456789ABCDEF,
    // Key2 = 23456789ABCDEF01, Key3 = 456789ABCDEF0123, plaintext "The qufck brown fox jump".
    let key = hex("0123456789ABCDEF 23456789ABCDEF01 456789ABCDEF0123");
    let plaintext = b"The qufck brown fox jump";
    let ciphertext = hex("A826FD8CE53B855F CCE21C8112256FE6 68D5C05DD9B6B900");
    for (block, (p, c)) in plaintext.chunks(8).zip(ciphertext.chunks(8)).enumerate() {
        assert_eq!(tdes_ecb_encrypt_block(&key, p).unwrap().to_vec(), c, "encrypt block {block}");
        assert_eq!(tdes_ecb_decrypt_block(&key, c).unwrap().to_vec(), p, "decrypt block {block}");
    }
}

#[test]
fn sp800_20_variable_plaintext_kat() {
    // NIST SP 800-20 Table A.1 (variable plaintext KAT), first entry: with
    // K1 = K2 = K3 = 0101010101010101, plaintext 8000000000000000.
    let key = hex("0101010101010101 0101010101010101 0101010101010101");
    let plaintext = hex("8000000000000000");
    let ciphertext = hex("95F8A5E5DD31D900");
    assert_eq!(tdes_ecb_encrypt_block(&key, &plaintext).unwrap().to_vec(), ciphertext);
    assert_eq!(tdes_ecb_decrypt_block(&key, &ciphertext).unwrap().to_vec(), plaintext);
}

#[test]
fn rejects_bad_lengths() {
    for len in [0, 8, 16, 23, 25, 32] {
        assert_eq!(tdes_ecb_encrypt_block(&vec![0; len], &[0; 8]), Err(CryptoError::InvalidKey), "key {len}");
        assert_eq!(tdes_ecb_decrypt_block(&vec![0; len], &[0; 8]), Err(CryptoError::InvalidKey), "key {len}");
    }
    for len in [0, 7, 9, 16] {
        assert_eq!(tdes_ecb_encrypt_block(&[0; 24], &vec![0; len]), Err(CryptoError::InvalidInput), "block {len}");
        assert_eq!(tdes_ecb_decrypt_block(&[0; 24], &vec![0; len]), Err(CryptoError::InvalidInput), "block {len}");
    }
}
