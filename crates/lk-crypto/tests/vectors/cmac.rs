//! AES-CMAC: RFC 4493 §4 (AES-128) and NIST SP 800-38B Appendix D.2/D.3 (AES-192/256).
//!
//! All three key sizes MAC prefixes of the same 64-byte message (the SP 800-38A sample
//! plaintext) with lengths 0, 16, 40 and 64 bytes.

use lk_crypto::{CryptoError, aes_cmac};

use crate::common::hex;

const MESSAGE: &str = "6bc1bee2 2e409f96 e93d7e11 7393172a ae2d8a57 1e03ac9c 9eb76fac 45af8e51
                       30c81c46 a35ce411 e5fbc119 1a0a52ef f69f2445 df4f9b17 ad2b417b e66c3710";
const LENGTHS: [usize; 4] = [0, 16, 40, 64];

fn check(key: &str, tags: [&str; 4], source: &str) {
    let key = hex(key);
    let message = hex(MESSAGE);
    for (len, tag) in LENGTHS.into_iter().zip(tags) {
        assert_eq!(aes_cmac(&key, &message[..len]).unwrap().to_vec(), hex(tag), "{source}, Mlen {len}");
    }
}

#[test]
fn aes128_cmac_rfc4493() {
    // RFC 4493 §4, Examples 1-4 (identical to SP 800-38B D.1).
    check(
        "2b7e1516 28aed2a6 abf71588 09cf4f3c",
        [
            "bb1d6929 e9593728 7fa37d12 9b756746",
            "070a16b4 6b4d4144 f79bdd9d d04a287c",
            "dfa66747 de9ae630 30ca3261 1497c827",
            "51f0bebf 7e3b9d92 fc497417 79363cfe",
        ],
        "RFC 4493 §4",
    );
}

#[test]
fn aes192_cmac_sp800_38b() {
    // NIST SP 800-38B Appendix D.2, Examples 5-8.
    check(
        "8e73b0f7 da0e6452 c810f32b 809079e5 62f8ead2 522c6b7b",
        [
            "d17ddf46 adaacde5 31cac483 de7a9367",
            "9e99a7bf 31e71090 0662f65e 617c5184",
            "8a1de5be 2eb31aad 089a82e6 ee908b0e",
            "a1d5df0e ed790f79 4d775896 59f39a11",
        ],
        "SP 800-38B D.2",
    );
}

#[test]
fn aes256_cmac_sp800_38b() {
    // NIST SP 800-38B Appendix D.3, Examples 9-12.
    check(
        "603deb10 15ca71be 2b73aef0 857d7781 1f352c07 3b6108d7 2d9810a3 0914dff4",
        [
            "028962f6 1b7bf89e fc6b551f 4667d983",
            "28a7023f 452e8f82 bd4bf28d 8c37c35c",
            "aaf3d8f1 de5640c2 32f5b169 b9c911e6",
            "e1992190 549f6ed5 696a2c05 6c315410",
        ],
        "SP 800-38B D.3",
    );
}

#[test]
fn cmac_rejects_other_key_lengths() {
    for len in [0, 8, 15, 17, 31, 33] {
        assert_eq!(aes_cmac(&vec![0; len], b"data"), Err(CryptoError::InvalidKey), "key length {len}");
    }
}
