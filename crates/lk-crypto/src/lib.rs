//! The only crate allowed to depend on third-party code (RustCrypto, dalek).
//!
//! It exposes the engine's own small API:
//! - hashes, HMAC, HKDF;
//! - AES (ECB block, CBC, GCM) and AES-CMAC; 3DES;
//! - ECDSA/ECDH on P-256, P-384, P-521, secp256k1, brainpoolP256r1 and brainpoolP384r1
//!   (not brainpoolP512r1: no RustCrypto crate); Ed25519; X25519; RSA;
//! - an incremental [`Hasher`] and the zeroizing [`SecretBytes`] for other crates' secrets.
//!
//! Protocol crates never name a third-party type, so replacing a primitive is a change
//! to this crate alone. See `docs/DESIGN.md` §8.
//!
//! Randomness always comes from the host through [`lk_core::Entropy`]. Signing is
//! deterministic where the algorithm allows it (RFC 6979 ECDSA, Ed25519).

#![forbid(unsafe_code)]

mod cipher;
mod ec;
mod edwards;
mod hash;
mod mac;
mod rng;
mod rsa;
mod secret;

pub use cipher::{
    aes_cbc_decrypt, aes_cbc_encrypt, aes_ecb_decrypt_block, aes_ecb_encrypt_block, aes_gcm_open,
    aes_gcm_seal, tdes_ecb_decrypt_block, tdes_ecb_encrypt_block,
};
pub use ec::{Curve, EcPrivateKey, EcdsaSignature, ec_public_is_valid, ecdsa_verify_prehash};
pub use edwards::{Ed25519Key, X25519Key, ed25519_verify};
pub use hash::{HashAlg, Hasher, digest, sha1, sha256, sha384, sha512};
pub use mac::{aes_cmac, ct_eq, hkdf_sha256, hmac, hmac_sha1, hmac_sha256};
pub use rsa::{RsaPrivateKey, rsa_public_op};
pub use secret::SecretBytes;

use core::fmt;

/// A cryptographic operation failed or received invalid input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// A key had the wrong length or was not a valid value for its algorithm.
    InvalidKey,
    /// Input data had a length or value the operation cannot accept.
    InvalidInput,
    /// An authenticated decryption tag or signature did not verify.
    VerificationFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::InvalidKey => "invalid key",
            Self::InvalidInput => "invalid input",
            Self::VerificationFailed => "verification failed",
        };
        f.write_str(text)
    }
}

impl std::error::Error for CryptoError {}

pub type Result<T> = core::result::Result<T, CryptoError>;
