use lk_core::Entropy;
use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use p256::elliptic_curve::sec1::ToSec1Point;
use zeroize::Zeroizing;

use crate::rng::EntropyRng;
use crate::{CryptoError, HashAlg, Result, digest};

/// NIST curves used by FIDO, PIV, OpenPGP and the secure channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Curve {
    P256,
    P384,
}

impl Curve {
    /// Scalar and coordinate length in bytes.
    pub const fn field_len(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
        }
    }

    /// Length of an uncompressed SEC1 point (`04 || X || Y`).
    pub const fn point_len(self) -> usize {
        1 + 2 * self.field_len()
    }
}

/// An ECDSA signature as fixed-length big-endian `r` and `s`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaSignature {
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

impl EcdsaSignature {
    /// `r || s` as stored (OpenPGP, COSE raw form). Signatures from
    /// [`EcPrivateKey::sign_prehash`] hold both values at the field length, which is what
    /// the raw form requires; a hand-built signature with shorter values is not padded.
    pub fn to_raw(&self) -> Vec<u8> {
        [self.r.as_slice(), self.s.as_slice()].concat()
    }

    /// ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }` (FIDO, PIV, X.509).
    pub fn to_der(&self) -> Vec<u8> {
        fn integer(value: &[u8]) -> Vec<u8> {
            let trimmed = match value.iter().position(|&b| b != 0) {
                Some(start) => &value[start..],
                None => &[0][..],
            };
            let mut body = Vec::with_capacity(trimmed.len() + 1);
            if trimmed[0] & 0x80 != 0 {
                body.push(0);
            }
            body.extend_from_slice(trimmed);
            let mut out = vec![0x02];
            push_der_len(&mut out, body.len());
            out.extend(body);
            out
        }
        let body = [integer(&self.r), integer(&self.s)].concat();
        let mut out = vec![0x30];
        push_der_len(&mut out, body.len());
        out.extend(body);
        out
    }
}

/// DER length octets (X.690 §8.1.3): short form below 128, otherwise the minimal long form.
fn push_der_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let bytes = len.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
    out.push(0x80 | (bytes.len() - start) as u8);
    out.extend_from_slice(&bytes[start..]);
}

/// An ECDSA/ECDH private key on P-256 or P-384.
pub struct EcPrivateKey {
    curve: Curve,
    scalar: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for EcPrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EcPrivateKey").field("curve", &self.curve).finish_non_exhaustive()
    }
}

impl EcPrivateKey {
    /// Draw a uniformly random valid scalar, retrying on the (negligible) invalid values.
    pub fn generate(curve: Curve, entropy: &mut dyn Entropy) -> Self {
        loop {
            let mut bytes = Zeroizing::new(vec![0; curve.field_len()]);
            entropy.fill(&mut bytes);
            if let Ok(key) = Self::from_scalar(curve, &bytes) {
                return key;
            }
        }
    }

    /// Import a big-endian scalar of exactly the field length (`0 < d < n`).
    pub fn from_scalar(curve: Curve, scalar: &[u8]) -> Result<Self> {
        if scalar.len() != curve.field_len() {
            return Err(CryptoError::InvalidKey);
        }
        let valid = match curve {
            Curve::P256 => p256::SecretKey::from_slice(scalar).is_ok(),
            Curve::P384 => p384::SecretKey::from_slice(scalar).is_ok(),
        };
        if !valid {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self { curve, scalar: Zeroizing::new(scalar.to_vec()) })
    }

    pub fn curve(&self) -> Curve {
        self.curve
    }

    pub fn scalar(&self) -> &[u8] {
        &self.scalar
    }

    /// Uncompressed SEC1 public point `04 || X || Y`.
    pub fn public_uncompressed(&self) -> Vec<u8> {
        match self.curve {
            Curve::P256 => p256_secret(&self.scalar).public_key().to_sec1_point(false).as_bytes().to_vec(),
            Curve::P384 => p384_secret(&self.scalar).public_key().to_sec1_point(false).as_bytes().to_vec(),
        }
    }

    /// Sign a message digest (already hashed by the caller), truncating per FIPS 186-5
    /// §6.4.1. The nonce is derived per RFC 6979 §3.2 with the curve's own hash (SHA-256
    /// for P-256, SHA-384 for P-384) as the HMAC_DRBG hash. For a digest of that same hash
    /// the signature is exactly RFC 6979's; for any other digest it is deterministic and
    /// valid but differs from the values RFC 6979 Appendix A publishes for that pairing.
    ///
    /// An empty digest is rejected: no approved hash has an empty output, and the
    /// RFC 6979 nonce derivation (`bits2int`) is undefined for it.
    pub fn sign_prehash(&self, prehash: &[u8]) -> Result<EcdsaSignature> {
        if prehash.is_empty() {
            return Err(CryptoError::InvalidInput);
        }
        let (r, s) = match self.curve {
            Curve::P256 => {
                let key = p256::ecdsa::SigningKey::from(p256_secret(&self.scalar));
                let sig: p256::ecdsa::Signature = key.sign_prehash(prehash).map_err(|_| CryptoError::InvalidInput)?;
                let (r, s) = sig.split_bytes();
                (r.to_vec(), s.to_vec())
            }
            Curve::P384 => {
                let key = p384::ecdsa::SigningKey::from(p384_secret(&self.scalar));
                let sig: p384::ecdsa::Signature = key.sign_prehash(prehash).map_err(|_| CryptoError::InvalidInput)?;
                let (r, s) = sig.split_bytes();
                (r.to_vec(), s.to_vec())
            }
        };
        Ok(EcdsaSignature { r, s })
    }

    /// Hash `message` with `alg` and sign the digest (see [`Self::sign_prehash`]).
    pub fn sign_message(&self, alg: HashAlg, message: &[u8]) -> Result<EcdsaSignature> {
        self.sign_prehash(&digest(alg, message))
    }

    /// Sign a digest with a hedged nonce: RFC 6979 §3.6 with fresh host entropy as the
    /// additional data `k'`. Signing the same digest twice gives different signatures, as
    /// on a device that draws a random nonce, while a weak entropy source still cannot
    /// leak the key. Device-visible signatures use this; [`Self::sign_prehash`] stays for
    /// known-answer tests.
    pub fn sign_prehash_hedged(&self, prehash: &[u8], entropy: &mut dyn Entropy) -> Result<EcdsaSignature> {
        use p256::ecdsa::signature::hazmat::RandomizedPrehashSigner;
        if prehash.is_empty() {
            return Err(CryptoError::InvalidInput);
        }
        let mut rng = EntropyRng(entropy);
        let (r, s) = match self.curve {
            Curve::P256 => {
                let key = p256::ecdsa::SigningKey::from(p256_secret(&self.scalar));
                let sig: p256::ecdsa::Signature =
                    key.sign_prehash_with_rng(&mut rng, prehash).map_err(|_| CryptoError::InvalidInput)?;
                let (r, s) = sig.split_bytes();
                (r.to_vec(), s.to_vec())
            }
            Curve::P384 => {
                let key = p384::ecdsa::SigningKey::from(p384_secret(&self.scalar));
                let sig: p384::ecdsa::Signature =
                    key.sign_prehash_with_rng(&mut rng, prehash).map_err(|_| CryptoError::InvalidInput)?;
                let (r, s) = sig.split_bytes();
                (r.to_vec(), s.to_vec())
            }
        };
        Ok(EcdsaSignature { r, s })
    }

    /// Hash `message` with `alg` and sign it with a hedged nonce ([`Self::sign_prehash_hedged`]).
    pub fn sign_message_hedged(&self, alg: HashAlg, message: &[u8], entropy: &mut dyn Entropy) -> Result<EcdsaSignature> {
        self.sign_prehash_hedged(&digest(alg, message), entropy)
    }

    /// ECDH: the X coordinate of `scalar * peer` (`peer` is an uncompressed SEC1 point).
    pub fn ecdh(&self, peer_uncompressed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if peer_uncompressed.len() != self.curve.point_len() || peer_uncompressed[0] != 0x04 {
            return Err(CryptoError::InvalidInput);
        }
        let shared = match self.curve {
            Curve::P256 => {
                let peer = p256::PublicKey::from_sec1_bytes(peer_uncompressed).map_err(|_| CryptoError::InvalidInput)?;
                let secret = p256_secret(&self.scalar);
                p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine())
                    .raw_secret_bytes()
                    .to_vec()
            }
            Curve::P384 => {
                let peer = p384::PublicKey::from_sec1_bytes(peer_uncompressed).map_err(|_| CryptoError::InvalidInput)?;
                let secret = p384_secret(&self.scalar);
                p384::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine())
                    .raw_secret_bytes()
                    .to_vec()
            }
        };
        Ok(Zeroizing::new(shared))
    }
}

// The scalar was validated in `from_scalar`, so re-parsing cannot fail.
fn p256_secret(scalar: &[u8]) -> p256::SecretKey {
    p256::SecretKey::from_slice(scalar).unwrap_or_else(|_| unreachable!())
}

fn p384_secret(scalar: &[u8]) -> p384::SecretKey {
    p384::SecretKey::from_slice(scalar).unwrap_or_else(|_| unreachable!())
}

/// True if `point` is an uncompressed SEC1 point on `curve` (not the identity).
pub fn ec_public_is_valid(curve: Curve, point: &[u8]) -> bool {
    if point.len() != curve.point_len() || point.first() != Some(&0x04) {
        return false;
    }
    match curve {
        Curve::P256 => p256::PublicKey::from_sec1_bytes(point).is_ok(),
        Curve::P384 => p384::PublicKey::from_sec1_bytes(point).is_ok(),
    }
}

/// Verify an ECDSA signature over a digest (FIPS 186-5 §6.4.2).
///
/// - `point` is an uncompressed SEC1 point on `curve`, as for [`ec_public_is_valid`] and
///   [`EcPrivateKey::ecdh`]; compressed, hybrid and identity encodings are rejected.
/// - `prehash` is the message digest, truncated to the order's bit length if longer and
///   used as an integer if shorter (FIPS 186-5 §6.4.2 step 3 / §6.4.1).
/// - `signature` is DER `SEQUENCE { r, s }` or raw `r || s`. A byte string can parse as
///   both, so the signature is accepted if either reading verifies.
pub fn ecdsa_verify_prehash(curve: Curve, point: &[u8], prehash: &[u8], signature: &[u8]) -> bool {
    // The encoding rule of `ec_public_is_valid`; `from_sec1_bytes` checks the curve equation.
    if point.len() != curve.point_len() || point.first() != Some(&0x04) {
        return false;
    }
    match curve {
        Curve::P256 => {
            use p256::ecdsa::{Signature, VerifyingKey};
            let Ok(key) = VerifyingKey::from_sec1_bytes(point) else { return false };
            let verifies = |sig: Signature| key.verify_prehash(prehash, &sig).is_ok();
            Signature::from_der(signature).is_ok_and(verifies) || Signature::from_slice(signature).is_ok_and(verifies)
        }
        Curve::P384 => {
            use p384::ecdsa::{Signature, VerifyingKey};
            let Ok(key) = VerifyingKey::from_sec1_bytes(point) else { return false };
            let verifies = |sig: Signature| key.verify_prehash(prehash, &sig).is_ok();
            Signature::from_der(signature).is_ok_and(verifies) || Signature::from_slice(signature).is_ok_and(verifies)
        }
    }
}
