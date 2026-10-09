use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, BlockModeDecrypt, BlockModeEncrypt, KeyInit, KeyIvInit};
use aes::{Aes128, Aes192, Aes256};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use des::TdesEde3;

use crate::{CryptoError, Result};

fn block_op<C: KeyInit + BlockCipherEncrypt + BlockCipherDecrypt>(
    key: &[u8],
    block: &[u8],
    encrypt: bool,
) -> Result<Vec<u8>> {
    let cipher = C::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
    let mut buf = aes::cipher::Block::<C>::try_from(block).map_err(|_| CryptoError::InvalidInput)?;
    if encrypt {
        cipher.encrypt_block(&mut buf);
    } else {
        cipher.decrypt_block(&mut buf);
    }
    Ok(buf.to_vec())
}

fn aes_block(key: &[u8], block: &[u8], encrypt: bool) -> Result<[u8; 16]> {
    let out = match key.len() {
        16 => block_op::<Aes128>(key, block, encrypt)?,
        24 => block_op::<Aes192>(key, block, encrypt)?,
        32 => block_op::<Aes256>(key, block, encrypt)?,
        _ => return Err(CryptoError::InvalidKey),
    };
    let mut result = [0; 16];
    result.copy_from_slice(&out);
    Ok(result)
}

/// One AES block (16 bytes) encrypted with a 128/192/256-bit key.
pub fn aes_ecb_encrypt_block(key: &[u8], block: &[u8]) -> Result<[u8; 16]> {
    aes_block(key, block, true)
}

pub fn aes_ecb_decrypt_block(key: &[u8], block: &[u8]) -> Result<[u8; 16]> {
    aes_block(key, block, false)
}

fn cbc_encrypt<C>(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>>
where
    C: KeyInit + BlockCipherEncrypt,
{
    let mode = cbc::Encryptor::<C>::new_from_slices(key, iv).map_err(|_| CryptoError::InvalidKey)?;
    let mut buf = data.to_vec();
    let len = mode.encrypt_padded::<NoPadding>(&mut buf, data.len()).map_err(|_| CryptoError::InvalidInput)?.len();
    buf.truncate(len);
    Ok(buf)
}

fn cbc_decrypt<C>(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>>
where
    C: KeyInit + BlockCipherDecrypt,
{
    let mode = cbc::Decryptor::<C>::new_from_slices(key, iv).map_err(|_| CryptoError::InvalidKey)?;
    let mut buf = data.to_vec();
    let len = mode.decrypt_padded::<NoPadding>(&mut buf).map_err(|_| CryptoError::InvalidInput)?.len();
    buf.truncate(len);
    Ok(buf)
}

/// AES-CBC without padding; `data` must be a whole number of blocks.
pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if !data.len().is_multiple_of(16) || iv.len() != 16 {
        return Err(CryptoError::InvalidInput);
    }
    match key.len() {
        16 => cbc_encrypt::<Aes128>(key, iv, data),
        24 => cbc_encrypt::<Aes192>(key, iv, data),
        32 => cbc_encrypt::<Aes256>(key, iv, data),
        _ => Err(CryptoError::InvalidKey),
    }
}

pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if !data.len().is_multiple_of(16) || iv.len() != 16 {
        return Err(CryptoError::InvalidInput);
    }
    match key.len() {
        16 => cbc_decrypt::<Aes128>(key, iv, data),
        24 => cbc_decrypt::<Aes192>(key, iv, data),
        32 => cbc_decrypt::<Aes256>(key, iv, data),
        _ => Err(CryptoError::InvalidKey),
    }
}

/// AES-256-GCM with a 96-bit nonce; returns ciphertext followed by the 16-byte tag.
pub fn aes_gcm_seal(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if nonce.len() != 12 {
        return Err(CryptoError::InvalidInput);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
    let nonce = Nonce::try_from(nonce).map_err(|_| CryptoError::InvalidInput)?;
    cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::InvalidInput)
}

pub fn aes_gcm_open(key: &[u8], nonce: &[u8], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    if nonce.len() != 12 {
        return Err(CryptoError::InvalidInput);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
    let nonce = Nonce::try_from(nonce).map_err(|_| CryptoError::InvalidInput)?;
    cipher
        .decrypt(&nonce, Payload { msg: sealed, aad })
        .map_err(|_| CryptoError::VerificationFailed)
}

/// One 3DES (TDEA, three-key EDE) block with a 24-byte key.
pub fn tdes_ecb_encrypt_block(key: &[u8], block: &[u8]) -> Result<[u8; 8]> {
    let out = block_op::<TdesEde3>(key, block, true)?;
    let mut result = [0; 8];
    result.copy_from_slice(&out);
    Ok(result)
}

pub fn tdes_ecb_decrypt_block(key: &[u8], block: &[u8]) -> Result<[u8; 8]> {
    let out = block_op::<TdesEde3>(key, block, false)?;
    let mut result = [0; 8];
    result.copy_from_slice(&out);
    Ok(result)
}
