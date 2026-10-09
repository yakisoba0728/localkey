use lk_core::Entropy;
use rsa::BoxedUint;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use zeroize::{Zeroize, Zeroizing};

use crate::rng::EntropyRng;
use crate::{CryptoError, Result};

/// An RSA private key with two primes.
pub struct RsaPrivateKey {
    inner: rsa::RsaPrivateKey,
}

impl core::fmt::Debug for RsaPrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RsaPrivateKey").field("bits", &(self.size() * 8)).finish_non_exhaustive()
    }
}

fn uint(bytes: &[u8]) -> BoxedUint {
    BoxedUint::from_be_slice_vartime(bytes)
}

/// `bytes` without its leading zero bytes; zero becomes the empty slice.
fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

/// True for an odd integer of at least 3, given big-endian without leading zeros.
fn is_odd_and_at_least_3(trimmed: &[u8]) -> bool {
    match trimmed {
        [] => false,
        [only] => *only >= 3 && only & 1 == 1,
        [.., last] => last & 1 == 1,
    }
}

/// Minimal big-endian bytes of a secret value. The full-width intermediate copy is wiped.
fn secret_bytes(value: &BoxedUint) -> Vec<u8> {
    let full = Zeroizing::new(value.to_be_bytes());
    trim_leading_zeros(&full).to_vec()
}

/// Big-endian bytes of `value`, left-padded to `len`. The intermediate copy is wiped,
/// since for RSADP the value is a decrypted secret.
fn to_fixed(value: &BoxedUint, len: usize) -> Result<Vec<u8>> {
    let full = Zeroizing::new(value.to_be_bytes());
    let bytes = trim_leading_zeros(&full);
    if bytes.len() > len {
        return Err(CryptoError::InvalidInput);
    }
    let mut out = vec![0; len - bytes.len()];
    out.extend_from_slice(bytes);
    Ok(out)
}

impl RsaPrivateKey {
    /// Generate a key of `bits` with public exponent 65537.
    pub fn generate(bits: usize, entropy: &mut dyn Entropy) -> Result<Self> {
        let mut rng = EntropyRng(entropy);
        let inner = rsa::RsaPrivateKey::new(&mut rng, bits).map_err(|_| CryptoError::InvalidInput)?;
        Ok(Self { inner })
    }

    /// Rebuild a key from its primes and public exponent (PIV and OpenPGP imports).
    ///
    /// All three are unsigned big-endian integers; leading zero bytes are ignored, so `p`
    /// and `q` may arrive with different encoded lengths. `p` and `q` must be distinct
    /// odd integers of at least 3 and `e` an odd integer of at least 3 (RFC 8017 §3.1,
    /// §3.2); anything else is [`CryptoError::InvalidKey`].
    ///
    /// The key must also pass a pairwise consistency test (NIST SP 800-56B Rev. 2
    /// §6.4.1.1): a fixed representative must come back unchanged from RSAEP followed by
    /// RSADP. That rejects most composite "primes", whose derived private exponent is
    /// wrong. Primality itself is not tested.
    pub fn from_primes(p: &[u8], q: &[u8], e: &[u8]) -> Result<Self> {
        let (p, q, e) = (trim_leading_zeros(p), trim_leading_zeros(q), trim_leading_zeros(e));
        let valid = is_odd_and_at_least_3(p) && is_odd_and_at_least_3(q) && is_odd_and_at_least_3(e);
        if !valid || crate::ct_eq(p, q) {
            return Err(CryptoError::InvalidKey);
        }
        // The rsa crate's constant-time arithmetic requires both primes at one precision
        // (it panics otherwise), so they are widened to the longer one's length.
        let bits = u32::try_from(8 * p.len().max(q.len())).map_err(|_| CryptoError::InvalidKey)?;
        let p = BoxedUint::from_be_slice(p, bits).map_err(|_| CryptoError::InvalidKey)?;
        let q = BoxedUint::from_be_slice(q, bits).map_err(|_| CryptoError::InvalidKey)?;
        let inner = rsa::RsaPrivateKey::from_p_q(p, q, uint(e)).map_err(|_| CryptoError::InvalidKey)?;
        let key = Self { inner };
        if !key.is_pairwise_consistent() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(key)
    }

    /// NIST SP 800-56B Rev. 2 §6.4.1.1 pairwise consistency: `(m^e mod n)^d mod n = m`.
    ///
    /// `m = 2` lies in the allowed range `1 < m < n - 1` because `n >= 3 * 5`. No blinding
    /// is applied; the representative is public.
    fn is_pairwise_consistent(&self) -> bool {
        let Ok(message) = BoxedUint::from_be_slice(&[2], self.inner.n().bits_precision()) else { return false };
        let Ok(ciphertext) = rsa::hazmat::rsa_encrypt(&self.inner, &message) else { return false };
        rsa::hazmat::rsa_decrypt(None::<&mut EntropyRng<'_>>, &self.inner, &ciphertext).is_ok_and(|back| back == message)
    }

    /// Modulus length in bytes.
    pub fn size(&self) -> usize {
        self.inner.size()
    }

    pub fn modulus(&self) -> Vec<u8> {
        self.inner.n().to_be_bytes_trimmed_vartime().to_vec()
    }

    pub fn public_exponent(&self) -> Vec<u8> {
        self.inner.e().to_be_bytes_trimmed_vartime().to_vec()
    }

    /// The primes `p` and `q`, each as big-endian bytes, for persistence.
    pub fn primes(&self) -> Zeroizing<(Vec<u8>, Vec<u8>)> {
        let primes = self.inner.primes();
        Zeroizing::new((secret_bytes(&primes[0]), secret_bytes(&primes[1])))
    }

    /// The raw private operation `input^d mod n` with blinding (RSADP / RSASP1, RFC 8017
    /// §5.1.2 and §5.2.1). `input` must have the modulus length and be numerically less
    /// than the modulus. Padding is the caller's job.
    pub fn raw_private(&self, input: &[u8], entropy: &mut dyn Entropy) -> Result<Vec<u8>> {
        let size = self.size();
        if input.len() != size {
            return Err(CryptoError::InvalidInput);
        }
        let precision = self.inner.n().bits_precision();
        let value = BoxedUint::from_be_slice(input, precision).map_err(|_| CryptoError::InvalidInput)?;
        if value >= *self.inner.n().as_ref() {
            return Err(CryptoError::InvalidInput);
        }
        let mut rng = EntropyRng(entropy);
        let mut result = rsa::hazmat::rsa_decrypt_and_check(&self.inner, Some(&mut rng), &value)
            .map_err(|_| CryptoError::InvalidInput)?;
        let out = to_fixed(&result, size);
        result.zeroize();
        out
    }
}

/// The raw public operation `input^e mod n` (RSAEP / RSAVP1, RFC 8017 §5.1.1 and §5.2.2),
/// used to check signatures in tests and chains.
///
/// `input` must have the modulus length and be numerically less than the modulus
/// (step 1 of both primitives), so `s` and `s + n` are not both accepted.
pub fn rsa_public_op(modulus: &[u8], exponent: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    let public = rsa::RsaPublicKey::new(uint(modulus), uint(exponent)).map_err(|_| CryptoError::InvalidKey)?;
    let size = public.size();
    if input.len() != size {
        return Err(CryptoError::InvalidInput);
    }
    let value = BoxedUint::from_be_slice(input, public.n().bits_precision()).map_err(|_| CryptoError::InvalidInput)?;
    if value >= *public.n().as_ref() {
        return Err(CryptoError::InvalidInput);
    }
    let result = rsa::hazmat::rsa_encrypt(&public, &value).map_err(|_| CryptoError::InvalidInput)?;
    to_fixed(&result, size)
}
