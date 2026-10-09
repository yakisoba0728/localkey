use lk_core::Entropy;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::BoxedUint;
use zeroize::Zeroizing;

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

/// Big-endian bytes of `value`, left-padded to `len`.
fn to_fixed(value: &BoxedUint, len: usize) -> Result<Vec<u8>> {
    let bytes = value.to_be_bytes_trimmed_vartime();
    if bytes.len() > len {
        return Err(CryptoError::InvalidInput);
    }
    let mut out = vec![0; len - bytes.len()];
    out.extend_from_slice(&bytes);
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
    pub fn from_primes(p: &[u8], q: &[u8], e: &[u8]) -> Result<Self> {
        let inner = rsa::RsaPrivateKey::from_p_q(uint(p), uint(q), uint(e)).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self { inner })
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
        Zeroizing::new((
            primes[0].to_be_bytes_trimmed_vartime().to_vec(),
            primes[1].to_be_bytes_trimmed_vartime().to_vec(),
        ))
    }

    /// The raw private operation `input^d mod n` with blinding. `input` must have the modulus
    /// length and be numerically less than the modulus. Padding is the caller's job.
    pub fn raw_private(&self, input: &[u8], entropy: &mut dyn Entropy) -> Result<Vec<u8>> {
        let size = self.size();
        if input.len() != size {
            return Err(CryptoError::InvalidInput);
        }
        let precision = self.inner.n().bits_precision();
        let value = BoxedUint::from_be_slice(input, precision).map_err(|_| CryptoError::InvalidInput)?;
        if &value >= self.inner.n().as_ref() {
            return Err(CryptoError::InvalidInput);
        }
        let mut rng = EntropyRng(entropy);
        let result = rsa::hazmat::rsa_decrypt_and_check(&self.inner, Some(&mut rng), &value)
            .map_err(|_| CryptoError::InvalidInput)?;
        to_fixed(&result, size)
    }
}

/// The raw public operation `input^e mod n`, used to check signatures in tests and chains.
pub fn rsa_public_op(modulus: &[u8], exponent: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    let public = rsa::RsaPublicKey::new(uint(modulus), uint(exponent)).map_err(|_| CryptoError::InvalidKey)?;
    let size = public.size();
    if input.len() != size {
        return Err(CryptoError::InvalidInput);
    }
    let value = BoxedUint::from_be_slice(input, public.n().bits_precision()).map_err(|_| CryptoError::InvalidInput)?;
    let result = rsa::hazmat::rsa_encrypt(&public, &value).map_err(|_| CryptoError::InvalidInput)?;
    to_fixed(&result, size)
}
