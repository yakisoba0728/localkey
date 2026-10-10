//! ECDSA and ECDH on the short Weierstrass curves the applications use.
//!
//! Curves and their sources:
//! - P-256, P-384, P-521: FIPS 186-5 / SP 800-186 §3.2.1 (also SEC 2 v2 `secp256r1`,
//!   `secp384r1`, `secp521r1`); RustCrypto `p256`, `p384`, `p521`.
//! - secp256k1: SEC 2 v2 §2.4.1; RustCrypto `k256`.
//! - brainpoolP256r1, brainpoolP384r1: RFC 5639 §3.4 / §3.6; RustCrypto `bp256`, `bp384`.
//!
//! brainpoolP512r1 (RFC 5639 §3.7) is **not** supported: RustCrypto publishes no `bp512`
//! crate at the 0.14 generation, and this crate does not implement curve arithmetic
//! itself (docs/DESIGN.md §8). OpenPGP keeps answering `6A81` for it.
//!
//! All curves share one code path: [`with_curve!`] binds the RustCrypto curve type for a
//! [`Curve`] and the generic `elliptic-curve` / `ecdsa` types do the work, so every curve
//! has exactly the same input rules (fixed-length scalars, uncompressed SEC1 points only,
//! DER or raw signatures).

use lk_core::Entropy;
use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier, RandomizedPrehashSigner};
use p256::elliptic_curve::sec1::ToSec1Point;
use zeroize::Zeroizing;

use crate::rng::EntropyRng;
use crate::secret::SecretBytes;
use crate::{CryptoError, HashAlg, Result, digest};

/// Elliptic curves used by FIDO, PIV, OpenPGP and the secure channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Curve {
    /// NIST P-256 (`secp256r1`).
    P256,
    /// NIST P-384 (`secp384r1`).
    P384,
    /// NIST P-521 (`secp521r1`). Scalars and coordinates are 66 bytes, the top 7 bits zero.
    P521,
    /// SEC 2 `secp256k1`.
    Secp256k1,
    /// RFC 5639 `brainpoolP256r1`.
    BrainpoolP256r1,
    /// RFC 5639 `brainpoolP384r1`.
    BrainpoolP384r1,
}

impl Curve {
    /// Every supported curve.
    pub const ALL: [Curve; 6] =
        [Curve::P256, Curve::P384, Curve::P521, Curve::Secp256k1, Curve::BrainpoolP256r1, Curve::BrainpoolP384r1];

    /// Scalar and coordinate length in bytes (SEC 1 v2 §2.3.5: `ceil(log2(p) / 8)`).
    pub const fn field_len(self) -> usize {
        match self {
            Self::P256 | Self::Secp256k1 | Self::BrainpoolP256r1 => 32,
            Self::P384 | Self::BrainpoolP384r1 => 48,
            Self::P521 => 66,
        }
    }

    /// Length of an uncompressed SEC1 point (`04 || X || Y`).
    pub const fn point_len(self) -> usize {
        1 + 2 * self.field_len()
    }

    /// The hash RFC 6979 uses for this curve's HMAC_DRBG in [`EcPrivateKey::sign_prehash`]:
    /// the hash conventionally paired with the curve (SHA-512 for P-521).
    pub const fn nonce_hash(self) -> HashAlg {
        match self {
            Self::P256 | Self::Secp256k1 | Self::BrainpoolP256r1 => HashAlg::Sha256,
            Self::P384 | Self::BrainpoolP384r1 => HashAlg::Sha384,
            Self::P521 => HashAlg::Sha512,
        }
    }

    /// Mask for the first byte of a big-endian scalar so that it has at most as many bits
    /// as the group order: every order is a whole number of bytes except P-521's (521 bits,
    /// FIPS 186-5 Appendix A.2.2 draws exactly `bitlen(n)` bits).
    const fn first_byte_mask(self) -> u8 {
        match self {
            Self::P521 => 0x01,
            _ => 0xFF,
        }
    }
}

/// Run `$body` with `$c` bound to the RustCrypto curve type of `$curve`.
///
/// Each arm is monomorphised separately, so the body may use any generic
/// `elliptic_curve` / `ecdsa` API without spelling out trait bounds.
macro_rules! with_curve {
    ($curve:expr, |$c:ident| $body:expr) => {
        match $curve {
            Curve::P256 => {
                type $c = p256::NistP256;
                $body
            }
            Curve::P384 => {
                type $c = p384::NistP384;
                $body
            }
            Curve::P521 => {
                type $c = p521::NistP521;
                $body
            }
            Curve::Secp256k1 => {
                type $c = k256::Secp256k1;
                $body
            }
            Curve::BrainpoolP256r1 => {
                type $c = bp256::BrainpoolP256r1;
                $body
            }
            Curve::BrainpoolP384r1 => {
                type $c = bp384::BrainpoolP384r1;
                $body
            }
        }
    };
}

type SecretKey<C> = elliptic_curve::SecretKey<C>;
type PublicKey<C> = elliptic_curve::PublicKey<C>;
type SigningKey<C> = ecdsa::SigningKey<C>;
type VerifyingKey<C> = ecdsa::VerifyingKey<C>;
type Signature<C> = ecdsa::Signature<C>;

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

/// An ECDSA/ECDH private key on one of the [`Curve`]s.
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
    /// Draw a uniformly random valid scalar by rejection sampling (FIPS 186-5 Appendix
    /// A.2.2): take `field_len` bytes of entropy, clear the bits above the order's bit
    /// length (only P-521 has any), and retry while the value is 0 or not below `n`.
    pub fn generate(curve: Curve, entropy: &mut dyn Entropy) -> Self {
        loop {
            let mut bytes = Zeroizing::new(vec![0; curve.field_len()]);
            entropy.fill(&mut bytes);
            if let Some(first) = bytes.first_mut() {
                *first &= curve.first_byte_mask();
            }
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
        let valid = with_curve!(curve, |C| SecretKey::<C>::from_slice(scalar).is_ok());
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
        with_curve!(self.curve, |C| secret::<C>(&self.scalar).public_key().to_sec1_point(false).as_bytes().to_vec())
    }

    /// Sign a message digest (already hashed by the caller), truncating per FIPS 186-5
    /// §6.4.1 to the order's bit length (521 bits for P-521, see `p521_needs_truncation`).
    /// The nonce is derived per RFC 6979 §3.2 with [`Curve::nonce_hash`] as the HMAC_DRBG
    /// hash (SHA-256 for P-256, secp256k1 and brainpoolP256r1, SHA-384 for P-384 and
    /// brainpoolP384r1, SHA-512 for P-521). For a digest of that same hash the signature is
    /// exactly RFC 6979's; for any other digest it is deterministic and valid but differs
    /// from the values RFC 6979 Appendix A publishes for that pairing.
    ///
    /// secp256k1 signatures are low-S: `k256` replaces `s` by `n - s` when `s > n/2`
    /// (the BIP 62 rule). Both values are valid SEC 1 signatures and
    /// [`ecdsa_verify_prehash`] accepts either; this is model policy, not a device rule.
    ///
    /// An empty digest is rejected: no approved hash has an empty output, and the
    /// RFC 6979 nonce derivation (`bits2int`) is undefined for it.
    pub fn sign_prehash(&self, prehash: &[u8]) -> Result<EcdsaSignature> {
        if prehash.is_empty() {
            return Err(CryptoError::InvalidInput);
        }
        if p521_needs_truncation(self.curve, prehash) {
            return Ok(p521_sign_long(&self.scalar, prehash, &[]));
        }
        with_curve!(self.curve, |C| {
            let key = SigningKey::<C>::from(secret::<C>(&self.scalar));
            let sig: Signature<C> = key.sign_prehash(prehash).map_err(|_| CryptoError::InvalidInput)?;
            Ok(split::<C>(&sig))
        })
    }

    /// Hash `message` with `alg` and sign the digest (see [`Self::sign_prehash`]).
    pub fn sign_message(&self, alg: HashAlg, message: &[u8]) -> Result<EcdsaSignature> {
        self.sign_prehash(&digest(alg, message))
    }

    /// Sign a digest with a hedged nonce: RFC 6979 §3.6 with fresh host entropy as the
    /// additional data `k'`. Signing the same digest twice gives different signatures, as
    /// on a device that draws a random nonce, while a weak entropy source still cannot
    /// leak the key. Device-visible signatures use this; [`Self::sign_prehash`] stays for
    /// known-answer tests. secp256k1 signatures are low-S as for [`Self::sign_prehash`].
    pub fn sign_prehash_hedged(&self, prehash: &[u8], entropy: &mut dyn Entropy) -> Result<EcdsaSignature> {
        if prehash.is_empty() {
            return Err(CryptoError::InvalidInput);
        }
        if p521_needs_truncation(self.curve, prehash) {
            // The `k'` of RFC 6979 §3.6, drawn as `ecdsa`'s randomized signer draws it.
            let mut extra = Zeroizing::new(vec![0; self.curve.field_len()]);
            entropy.fill(&mut extra);
            return Ok(p521_sign_long(&self.scalar, prehash, &extra));
        }
        let mut rng = EntropyRng(entropy);
        with_curve!(self.curve, |C| {
            let key = SigningKey::<C>::from(secret::<C>(&self.scalar));
            let sig: Signature<C> =
                key.sign_prehash_with_rng(&mut rng, prehash).map_err(|_| CryptoError::InvalidInput)?;
            Ok(split::<C>(&sig))
        })
    }

    /// Hash `message` with `alg` and sign it with a hedged nonce ([`Self::sign_prehash_hedged`]).
    pub fn sign_message_hedged(&self, alg: HashAlg, message: &[u8], entropy: &mut dyn Entropy) -> Result<EcdsaSignature> {
        self.sign_prehash_hedged(&digest(alg, message), entropy)
    }

    /// ECDH (SEC 1 v2 §3.3.1): the X coordinate of `scalar * peer`, `field_len` bytes with
    /// leading zeros kept. `peer` is an uncompressed SEC1 point on this key's curve.
    pub fn ecdh(&self, peer_uncompressed: &[u8]) -> Result<SecretBytes> {
        if peer_uncompressed.len() != self.curve.point_len() || peer_uncompressed[0] != 0x04 {
            return Err(CryptoError::InvalidInput);
        }
        let shared = with_curve!(self.curve, |C| {
            let peer = PublicKey::<C>::from_sec1_bytes(peer_uncompressed).map_err(|_| CryptoError::InvalidInput)?;
            let secret = secret::<C>(&self.scalar);
            elliptic_curve::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine())
                .raw_secret_bytes()
                .to_vec()
        });
        Ok(SecretBytes::new(shared))
    }
}

/// P-521 digests of 66 bytes or more need FIPS 186-5 §6.4.1 truncation to their leftmost
/// 521 bits, which `ecdsa` 0.17 does not do: its `bytes2scalar` keeps the *low* 521 bits
/// of the first 66 bytes, while the `rfc6979` nonce uses the *high* 521 bits. Left alone,
/// two digests differing only in the low 7 bits of their 66th byte would get the same
/// deterministic nonce with different `z`, which reveals the key. Every other curve has
/// an order of a whole number of bytes, where both rules agree.
fn p521_needs_truncation(curve: Curve, prehash: &[u8]) -> bool {
    curve == Curve::P521 && prehash.len() >= Curve::P521.field_len()
}

/// The leftmost 521 bits of `prehash` (at least 66 bytes) as a 66-byte big-endian
/// integer: the first 528 bits shifted right by 7 (FIPS 186-5 §6.4.1 step 4, RFC 6979
/// §2.3.2 `bits2int`).
fn p521_leftmost_bits(prehash: &[u8]) -> [u8; 66] {
    let mut out = [0u8; 66];
    let mut previous = 0u8;
    for (slot, &byte) in out.iter_mut().zip(prehash) {
        *slot = (previous << 1) | (byte >> 7);
        previous = byte;
    }
    out
}

/// ECDSA on P-521 for a digest of 66 bytes or more: the nonce is RFC 6979 §3.2 (with
/// `extra` as the §3.6 `k'`) over the full digest, whose `bits2octets` already keeps the
/// leftmost 521 bits, and `z` is that same truncated value.
fn p521_sign_long(scalar: &[u8], prehash: &[u8], extra: &[u8]) -> EcdsaSignature {
    use elliptic_curve::ff::PrimeField;
    type C = p521::NistP521;
    let secret = secret::<C>(scalar);
    let d = secret.to_nonzero_scalar();
    let z = p521_leftmost_bits(prehash);
    let order = <C as elliptic_curve::Curve>::ORDER;
    let x = Zeroizing::new(d.to_repr());
    let mut nonces = rfc6979::KGenerator::<sha2::Sha512, _>::new(&x, prehash, extra, order.as_ref());
    loop {
        let mut k_bytes = Zeroizing::new(p521::FieldBytes::default());
        nonces.fill_next_k(&mut k_bytes);
        let Some(k) = elliptic_curve::NonZeroScalar::<C>::from_repr(*k_bytes).into_option() else { continue };
        // Fails only when r or s is zero; RFC 6979 §3.4 then takes the next candidate.
        if let Ok((sig, _)) = ecdsa::hazmat::sign_prehashed::<C>(&d, &k, &z) {
            return split::<C>(&sig);
        }
    }
}

// The scalar was validated in `from_scalar`, so re-parsing cannot fail.
fn secret<C: elliptic_curve::Curve>(scalar: &[u8]) -> SecretKey<C> {
    SecretKey::<C>::from_slice(scalar).unwrap_or_else(|_| unreachable!())
}

fn split<C>(sig: &Signature<C>) -> EcdsaSignature
where
    C: ecdsa::EcdsaCurve,
    ecdsa::SignatureSize<C>: elliptic_curve::array::ArraySize,
{
    let (r, s) = sig.split_bytes();
    EcdsaSignature { r: r.to_vec(), s: s.to_vec() }
}

/// True if `point` is an uncompressed SEC1 point on `curve` (not the identity).
pub fn ec_public_is_valid(curve: Curve, point: &[u8]) -> bool {
    if point.len() != curve.point_len() || point.first() != Some(&0x04) {
        return false;
    }
    with_curve!(curve, |C| PublicKey::<C>::from_sec1_bytes(point).is_ok())
}

/// Verify an ECDSA signature over a digest (FIPS 186-5 §6.4.2, SEC 1 v2 §4.1.4).
///
/// - `point` is an uncompressed SEC1 point on `curve`, as for [`ec_public_is_valid`] and
///   [`EcPrivateKey::ecdh`]; compressed, hybrid and identity encodings are rejected.
/// - `prehash` is the message digest, truncated to the order's bit length if longer and
///   used as an integer if shorter (FIPS 186-5 §6.4.2 step 3 / §6.4.1).
/// - `signature` is DER `SEQUENCE { r, s }` or raw `r || s`. A byte string can parse as
///   both, so the signature is accepted if either reading verifies.
/// - Either `s` or `n - s` is accepted on every curve, as SEC 1 defines ECDSA. `k256`
///   rejects high `s` (the Bitcoin rule), so `s` is normalised first; this is sound for
///   every curve because `(r, s)` and `(r, n - s)` verify identically (negating `s`
///   negates the recomputed point, which keeps its X coordinate).
pub fn ecdsa_verify_prehash(curve: Curve, point: &[u8], prehash: &[u8], signature: &[u8]) -> bool {
    // The encoding rule of `ec_public_is_valid`; `from_sec1_bytes` checks the curve equation.
    if point.len() != curve.point_len() || point.first() != Some(&0x04) {
        return false;
    }
    // See `p521_needs_truncation`: hand `ecdsa` the already truncated 521-bit value.
    let truncated;
    let prehash = if p521_needs_truncation(curve, prehash) {
        truncated = p521_leftmost_bits(prehash);
        &truncated[..]
    } else {
        prehash
    };
    with_curve!(curve, |C| {
        let Ok(key) = VerifyingKey::<C>::from_sec1_bytes(point) else { return false };
        let verifies = |sig: Signature<C>| key.verify_prehash(prehash, &sig.normalize_s()).is_ok();
        Signature::<C>::from_der(signature).is_ok_and(verifies) || Signature::<C>::from_slice(signature).is_ok_and(verifies)
    })
}
