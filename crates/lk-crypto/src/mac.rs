use aes::{Aes128, Aes192, Aes256};
use cmac::Cmac;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;

use crate::{CryptoError, HashAlg, Result};

fn mac_bytes<M: Mac + KeyInit>(key: &[u8], data: &[u8]) -> Vec<u8> {
    // HMAC accepts keys of any length, so construction cannot fail.
    let mut mac = <M as KeyInit>::new_from_slice(key).unwrap_or_else(|_| unreachable!());
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

pub fn hmac(alg: HashAlg, key: &[u8], data: &[u8]) -> Vec<u8> {
    match alg {
        HashAlg::Sha1 => mac_bytes::<Hmac<Sha1>>(key, data),
        HashAlg::Sha256 => mac_bytes::<Hmac<Sha256>>(key, data),
        HashAlg::Sha384 => mac_bytes::<Hmac<Sha384>>(key, data),
        HashAlg::Sha512 => mac_bytes::<Hmac<Sha512>>(key, data),
    }
}

pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut out = [0; 20];
    out.copy_from_slice(&hmac(HashAlg::Sha1, key, data));
    out
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut out = [0; 32];
    out.copy_from_slice(&hmac(HashAlg::Sha256, key, data));
    out
}

/// AES-CMAC (RFC 4493 / NIST SP 800-38B) with a 128-, 192- or 256-bit key.
pub fn aes_cmac(key: &[u8], data: &[u8]) -> Result<[u8; 16]> {
    let tag = match key.len() {
        16 => cmac_tag::<Cmac<Aes128>>(key, data)?,
        24 => cmac_tag::<Cmac<Aes192>>(key, data)?,
        32 => cmac_tag::<Cmac<Aes256>>(key, data)?,
        _ => return Err(CryptoError::InvalidKey),
    };
    let mut out = [0; 16];
    out.copy_from_slice(&tag);
    Ok(out)
}

fn cmac_tag<M: Mac + KeyInit>(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut mac = <M as KeyInit>::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// HKDF-SHA-256 (RFC 5869). `salt: None` means a string of zero bytes.
pub fn hkdf_sha256(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
    let hk = hkdf::Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = vec![0; len];
    hk.expand(info, &mut okm).map_err(|_| CryptoError::InvalidInput)?;
    Ok(okm)
}

/// Constant-time equality; different lengths compare unequal.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}
