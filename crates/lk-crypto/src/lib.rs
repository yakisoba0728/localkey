//! The only crate allowed to depend on third-party code (RustCrypto, dalek).
//!
//! It exposes the engine's own small API: hashes, HMAC, HKDF, AES modes, AES-CMAC,
//! ECDSA/ECDH on P-256 and P-384, Ed25519, X25519 and, from the PIV phase, RSA.
//! Protocol crates never name a third-party type. Replacing a primitive is therefore
//! a change to this crate alone. See `docs/DESIGN.md` §8.

#![forbid(unsafe_code)]
