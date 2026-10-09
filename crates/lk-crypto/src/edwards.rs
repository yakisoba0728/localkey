use ed25519_dalek::Signer;
use lk_core::Entropy;
use zeroize::Zeroizing;

use crate::{CryptoError, Result};

/// An Ed25519 signing key held as its 32-byte seed (RFC 8032).
pub struct Ed25519Key {
    seed: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for Ed25519Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ed25519Key").finish_non_exhaustive()
    }
}

impl Ed25519Key {
    pub fn generate(entropy: &mut dyn Entropy) -> Self {
        let mut seed = Zeroizing::new([0; 32]);
        entropy.fill(seed.as_mut());
        Self { seed }
    }

    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let seed: [u8; 32] = seed.try_into().map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self { seed: Zeroizing::new(seed) })
    }

    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    pub fn public(&self) -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&self.seed).verifying_key().to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        ed25519_dalek::SigningKey::from_bytes(&self.seed).sign(message).to_bytes()
    }
}

/// Verify an Ed25519 signature (RFC 8032 §5.1.7).
///
/// Beyond the RFC 8032 equation and its `S < L` rule, this rejects a public key `A` or
/// commitment `R` of small order. With such a "weak" key a single signature verifies for
/// every message: for `A` the identity, `(R, S) = (B, 1)` satisfies `[S]B = R + [k]A` for
/// any `k`. Honest keys and signatures (`A = [s]B`, `R = [r]B`) are never of small order.
pub fn ed25519_verify(public: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(public) = <[u8; 32]>::try_from(public) else { return false };
    let Ok(signature) = <[u8; 64]>::try_from(signature) else { return false };
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&public) else { return false };
    key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(&signature)).is_ok()
}

/// An X25519 private key (RFC 7748).
pub struct X25519Key {
    secret: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for X25519Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("X25519Key").finish_non_exhaustive()
    }
}

impl X25519Key {
    pub fn generate(entropy: &mut dyn Entropy) -> Self {
        let mut secret = Zeroizing::new([0; 32]);
        entropy.fill(secret.as_mut());
        Self { secret }
    }

    pub fn from_bytes(secret: &[u8]) -> Result<Self> {
        let secret: [u8; 32] = secret.try_into().map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self { secret: Zeroizing::new(secret) })
    }

    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    pub fn public(&self) -> [u8; 32] {
        let secret = x25519_dalek::StaticSecret::from(*self.secret);
        x25519_dalek::PublicKey::from(&secret).to_bytes()
    }

    /// Shared secret with `peer`; rejects the all-zero result of a low-order point.
    pub fn dh(&self, peer: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let peer: [u8; 32] = peer.try_into().map_err(|_| CryptoError::InvalidInput)?;
        let secret = x25519_dalek::StaticSecret::from(*self.secret);
        let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer));
        if !shared.was_contributory() {
            return Err(CryptoError::InvalidInput);
        }
        Ok(Zeroizing::new(shared.to_bytes()))
    }
}
