//! AES block cipher (FIPS 197 Appendix C) and CBC mode (NIST SP 800-38A Appendix F.2).

use lk_crypto::{CryptoError, aes_cbc_decrypt, aes_cbc_encrypt, aes_ecb_decrypt_block, aes_ecb_encrypt_block};

use crate::common::hex;

#[test]
fn fips197_appendix_c() {
    // FIPS 197 Appendix C.1 (AES-128), C.2 (AES-192), C.3 (AES-256): key 00 01 02 ..,
    // plaintext 00 11 22 .. ff.
    let plaintext = hex("00112233445566778899aabbccddeeff");
    let cases = [
        (16, "69c4e0d86a7b0430d8cdb78070b4c55a", "C.1"),
        (24, "dda97ca4864cdfe06eaf70a0ec0d7191", "C.2"),
        (32, "8ea2b7ca516745bfeafc49904b496089", "C.3"),
    ];
    for (key_len, ciphertext, section) in cases {
        let key: Vec<u8> = (0..key_len as u8).collect();
        let encrypted = aes_ecb_encrypt_block(&key, &plaintext).unwrap();
        assert_eq!(encrypted.to_vec(), hex(ciphertext), "FIPS 197 {section} encrypt");
        let decrypted = aes_ecb_decrypt_block(&key, &encrypted).unwrap();
        assert_eq!(decrypted.to_vec(), plaintext, "FIPS 197 {section} decrypt");
    }
}

#[test]
fn ecb_block_rejects_bad_lengths() {
    let block = [0u8; 16];
    for len in [0, 8, 15, 17, 20, 33] {
        assert_eq!(aes_ecb_encrypt_block(&vec![0; len], &block), Err(CryptoError::InvalidKey), "key {len}");
        assert_eq!(aes_ecb_decrypt_block(&vec![0; len], &block), Err(CryptoError::InvalidKey), "key {len}");
    }
    let key = [0u8; 16];
    for len in [0, 8, 15, 17, 32] {
        assert_eq!(aes_ecb_encrypt_block(&key, &vec![0; len]), Err(CryptoError::InvalidInput), "block {len}");
        assert_eq!(aes_ecb_decrypt_block(&key, &vec![0; len]), Err(CryptoError::InvalidInput), "block {len}");
    }
}

// NIST SP 800-38A Appendix F: the shared IV and four-block plaintext.
const IV: &str = "000102030405060708090a0b0c0d0e0f";
const PLAINTEXT: &str = "6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51
                         30c81c46a35ce411e5fbc1191a0a52ef f69f2445df4f9b17ad2b417be66c3710";

struct CbcCase {
    encrypt_section: &'static str,
    decrypt_section: &'static str,
    key: &'static str,
    ciphertext: &'static str,
}

const CBC_CASES: [CbcCase; 3] = [
    CbcCase {
        encrypt_section: "F.2.1 CBC-AES128.Encrypt",
        decrypt_section: "F.2.2 CBC-AES128.Decrypt",
        key: "2b7e151628aed2a6abf7158809cf4f3c",
        ciphertext: "7649abac8119b246cee98e9b12e9197d 5086cb9b507219ee95db113a917678b2
                     73bed6b8e3c1743b7116e69e22229516 3ff1caa1681fac09120eca307586e1a7",
    },
    CbcCase {
        encrypt_section: "F.2.3 CBC-AES192.Encrypt",
        decrypt_section: "F.2.4 CBC-AES192.Decrypt",
        key: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        ciphertext: "4f021db243bc633d7178183a9fa071e8 b4d9ada9ad7dedf4e5e738763f69145a
                     571b242012fb7ae07fa9baac3df102e0 08b0e27988598881d920a9e64f5615cd",
    },
    CbcCase {
        encrypt_section: "F.2.5 CBC-AES256.Encrypt",
        decrypt_section: "F.2.6 CBC-AES256.Decrypt",
        key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        ciphertext: "f58c4c04d6e5f1ba779eabfb5f7bfbd6 9cfc4e967edb808d679f777bc6702c7d
                     39f23369a9d9bacfa530e26304231461 b2eb05e2c39be9fcda6c19078c6a9d1b",
    },
];

#[test]
fn cbc_sp800_38a_encrypt() {
    for case in &CBC_CASES {
        let out = aes_cbc_encrypt(&hex(case.key), &hex(IV), &hex(PLAINTEXT)).unwrap();
        assert_eq!(out, hex(case.ciphertext), "SP 800-38A {}", case.encrypt_section);
    }
}

#[test]
fn cbc_sp800_38a_decrypt() {
    for case in &CBC_CASES {
        let out = aes_cbc_decrypt(&hex(case.key), &hex(IV), &hex(case.ciphertext)).unwrap();
        assert_eq!(out, hex(PLAINTEXT), "SP 800-38A {}", case.decrypt_section);
    }
}

#[test]
fn cbc_first_block_matches_ecb_of_plaintext_xor_iv() {
    // SP 800-38A §6.2: C1 = CIPH_K(P1 xor IV).
    let key = hex(CBC_CASES[0].key);
    let p1: Vec<u8> = hex(PLAINTEXT)[..16].iter().zip(hex(IV)).map(|(p, v)| p ^ v).collect();
    let c1 = aes_ecb_encrypt_block(&key, &p1).unwrap();
    assert_eq!(c1.to_vec(), hex(CBC_CASES[0].ciphertext)[..16]);
}

#[test]
fn cbc_rejects_partial_blocks_bad_iv_and_bad_keys() {
    let key = [0u8; 16];
    let iv = [0u8; 16];
    for len in [1, 15, 17, 31] {
        assert_eq!(aes_cbc_encrypt(&key, &iv, &vec![0; len]), Err(CryptoError::InvalidInput), "data {len}");
        assert_eq!(aes_cbc_decrypt(&key, &iv, &vec![0; len]), Err(CryptoError::InvalidInput), "data {len}");
    }
    for len in [0, 8, 15, 17] {
        assert_eq!(aes_cbc_encrypt(&key, &vec![0; len], &[0; 16]), Err(CryptoError::InvalidInput), "iv {len}");
        assert_eq!(aes_cbc_decrypt(&key, &vec![0; len], &[0; 16]), Err(CryptoError::InvalidInput), "iv {len}");
    }
    for len in [0, 8, 20, 33] {
        assert_eq!(aes_cbc_encrypt(&vec![0; len], &iv, &[0; 16]), Err(CryptoError::InvalidKey), "key {len}");
        assert_eq!(aes_cbc_decrypt(&vec![0; len], &iv, &[0; 16]), Err(CryptoError::InvalidKey), "key {len}");
    }
}

#[test]
fn cbc_empty_input_is_empty_output() {
    let key = [0u8; 32];
    let iv = [0u8; 16];
    assert_eq!(aes_cbc_encrypt(&key, &iv, &[]).unwrap(), Vec::<u8>::new());
    assert_eq!(aes_cbc_decrypt(&key, &iv, &[]).unwrap(), Vec::<u8>::new());
}
