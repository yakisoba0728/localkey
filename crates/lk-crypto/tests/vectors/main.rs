//! Published known-answer vectors for every `lk-crypto` primitive.
//!
//! Each module checks one family against the document that defines it; every vector
//! names its source (RFC section, NIST publication and table, or specification test
//! case). The suite is one integration-test binary so the crate is linked only once.

// Test code: a failed unwrap is a failed test, which is exactly what we want here.
#![allow(clippy::unwrap_used)]

mod common;

mod aes;
mod cmac;
mod ec_keys;
mod ecdh;
mod ecdsa;
mod ed25519;
mod gcm;
mod hash;
mod hkdf;
mod hmac;
mod rsa;
mod tdes;
mod x25519;
