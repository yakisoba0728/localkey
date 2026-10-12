//! SCP03 cryptographic building blocks.
//!
//! Source: GlobalPlatform Card Specification v2.3.1, Amendment D "Secure Channel
//! Protocol '03'" v1.1.2 (cited below as "Amd D"):
//!
//! - §4.1.5 data derivation: NIST SP 800-108 KDF in counter mode with AES-CMAC as the
//!   PRF. The fixed input is an 11-byte zero label, a one-byte derivation constant, a
//!   zero separation indicator, the output length `L` in bits (2 bytes), the one-byte
//!   counter `i` and then the context. Table 4-1 lists the derivation constants.
//! - §6.2.1 session keys S-ENC, S-MAC, S-RMAC; §6.2.2 card and host cryptograms.
//! - §6.2.6 command encryption: the ICV is the encryption counter (16 bytes, big
//!   endian) encrypted with S-ENC. §6.2.7 response encryption: the same block with its
//!   first byte replaced by `0x80`. Padding is ISO/IEC 9797-1 method 2 (§4.1.4).
//!
//! Every function works on byte slices only; the protocol state lives in
//! [`crate::SecureChannel`] and [`crate::SecurityDomain`].

use lk_codec::apdu::sw;

/// An AES-128 key. The YubiKey 5.7 Security Domain only holds AES-128 SCP03 keys (its
/// key information template reports type `88` with length `10`;
/// `reference/physical-key/security-domain-reference-observation.json`).
pub(crate) type Key = [u8; 16];

/// Amd D Table 4-1: derivation constant for the card cryptogram.
pub(crate) const DC_CARD_CRYPTOGRAM: u8 = 0x00;
/// Amd D Table 4-1: derivation constant for the host cryptogram.
pub(crate) const DC_HOST_CRYPTOGRAM: u8 = 0x01;
/// Amd D Table 4-1: derivation constant for a pseudo-random card challenge. The YubiKey
/// advertises `i = 60` (random challenge, Amd D §5.1), so this constant is never used to
/// make a challenge; it is kept to document the table.
#[cfg(test)]
pub(crate) const DC_CARD_CHALLENGE: u8 = 0x02;
/// Amd D Table 4-1: derivation constant for S-ENC.
pub(crate) const DC_S_ENC: u8 = 0x04;
/// Amd D Table 4-1: derivation constant for S-MAC.
pub(crate) const DC_S_MAC: u8 = 0x06;
/// Amd D Table 4-1: derivation constant for S-RMAC.
pub(crate) const DC_S_RMAC: u8 = 0x07;

/// Status word for a primitive that failed on inputs whose sizes are fixed by
/// construction. It cannot happen with 16-byte keys and whole blocks; it is mapped to
/// `6F00` rather than unwrapped so that no input can cause a panic.
pub(crate) const CRYPTO_FAILURE: u16 = sw::UNKNOWN;

/// AES-CMAC (NIST SP 800-38B) with an AES-128 key.
pub(crate) fn cmac(key: &Key, data: &[u8]) -> Result<[u8; 16], u16> {
    lk_crypto::aes_cmac(key, data).map_err(|_| CRYPTO_FAILURE)
}

/// Amd D §4.1.5: derive `out_len` bytes from `key` with `constant` and `context`.
pub(crate) fn kdf(key: &Key, constant: u8, context: &[u8], out_len: usize) -> Result<Vec<u8>, u16> {
    let bits = out_len
        .checked_mul(8)
        .and_then(|b| u16::try_from(b).ok())
        .ok_or(CRYPTO_FAILURE)?;
    let mut out = Vec::with_capacity(out_len + 16);
    let mut counter: u8 = 1;
    while out.len() < out_len {
        let mut input = Vec::with_capacity(16 + context.len());
        input.extend_from_slice(&[0u8; 11]);
        input.push(constant);
        input.push(0x00);
        input.extend_from_slice(&bits.to_be_bytes());
        input.push(counter);
        input.extend_from_slice(context);
        out.extend_from_slice(&cmac(key, &input)?);
        counter = counter.checked_add(1).ok_or(CRYPTO_FAILURE)?;
    }
    out.truncate(out_len);
    Ok(out)
}

/// A 16-byte KDF output as a key.
fn kdf_key(key: &Key, constant: u8, context: &[u8]) -> Result<Key, u16> {
    to_key(&kdf(key, constant, context, 16)?).ok_or(CRYPTO_FAILURE)
}

/// The three SCP03 session keys (Amd D §6.2.1).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SessionKeys {
    pub(crate) enc: Key,
    pub(crate) mac: Key,
    pub(crate) rmac: Key,
}

impl core::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionKeys").finish_non_exhaustive()
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        wipe(&mut self.enc);
        wipe(&mut self.mac);
        wipe(&mut self.rmac);
    }
}

/// Amd D §6.2.1: S-ENC from K-ENC, S-MAC and S-RMAC from K-MAC, over
/// `context = host challenge || card challenge`.
pub(crate) fn derive_session_keys(k_enc: &Key, k_mac: &Key, context: &[u8]) -> Result<SessionKeys, u16> {
    Ok(SessionKeys {
        enc: kdf_key(k_enc, DC_S_ENC, context)?,
        mac: kdf_key(k_mac, DC_S_MAC, context)?,
        rmac: kdf_key(k_mac, DC_S_RMAC, context)?,
    })
}

/// Amd D §6.2.2: an 8-byte authentication cryptogram (`L = 0x0040`) from S-MAC.
pub(crate) fn cryptogram(s_mac: &Key, constant: u8, context: &[u8]) -> Result<[u8; 8], u16> {
    let bytes = kdf(s_mac, constant, context, 8)?;
    let mut out = [0u8; 8];
    out.copy_from_slice(bytes.get(..8).ok_or(CRYPTO_FAILURE)?);
    Ok(out)
}

/// Key check value of an AES key: the first three bytes of the key's encryption of
/// sixteen `01` bytes (GP Card Specification v2.3.1 §11.8.2.3 with the AES rule of
/// Amd D; it is what PUT KEY carries and returns).
pub(crate) fn key_check_value(key: &Key) -> Result<[u8; 3], u16> {
    let block = lk_crypto::aes_ecb_encrypt_block(key, &[0x01; 16]).map_err(|_| CRYPTO_FAILURE)?;
    Ok([block[0], block[1], block[2]])
}

/// ISO/IEC 9797-1 padding method 2 to a multiple of 16 bytes (Amd D §4.1.4): `80` then
/// zero bytes. A full extra block is added when the input is already aligned.
pub(crate) fn pad(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 16);
    out.extend_from_slice(data);
    out.push(0x80);
    while !out.len().is_multiple_of(16) {
        out.push(0x00);
    }
    out
}

/// Remove ISO/IEC 9797-1 method 2 padding; `None` if the padding is malformed.
pub(crate) fn unpad(data: &[u8]) -> Option<&[u8]> {
    let end = data.iter().rposition(|&b| b != 0)?;
    if data.get(end) != Some(&0x80) || data.len() - end > 16 {
        return None;
    }
    data.get(..end)
}

/// Amd D §6.2.6: ICV for command encryption, `AES(S-ENC, counter as 16 bytes)`.
pub(crate) fn command_icv(s_enc: &Key, counter: u128) -> Result<[u8; 16], u16> {
    lk_crypto::aes_ecb_encrypt_block(s_enc, &counter.to_be_bytes()).map_err(|_| CRYPTO_FAILURE)
}

/// Amd D §6.2.7: ICV for response encryption, `AES(S-ENC, 80 || counter[1..16])`,
/// where `counter` is the value used for the command being answered.
pub(crate) fn response_icv(s_enc: &Key, counter: u128) -> Result<[u8; 16], u16> {
    let mut block = counter.to_be_bytes();
    block[0] = 0x80;
    lk_crypto::aes_ecb_encrypt_block(s_enc, &block).map_err(|_| CRYPTO_FAILURE)
}

/// A slice of exactly 16 bytes as a key.
pub(crate) fn to_key(bytes: &[u8]) -> Option<Key> {
    bytes.try_into().ok()
}

/// Overwrite key material. Without `unsafe` volatile writes this is best effort; the
/// `black_box` keeps the compiler from proving the store dead.
pub(crate) fn wipe(bytes: &mut [u8]) {
    bytes.fill(0);
    std::hint::black_box(bytes);
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Default SCP03 key, Yubico's published "test keys" `40..4F`
    /// (docs.yubico.com yk5-apps-scp, "Default key set").
    const K: Key = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    ];

    fn context() -> Vec<u8> {
        (0xA0..0xA8).chain(0xB0..0xB8).collect()
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// Expected values computed with OpenSSL's AES-CMAC (Python `cryptography` 46)
    /// from the Amd D §4.1.5 layout, host challenge A0..A7, card challenge B0..B7.
    #[test]
    fn kdf_matches_independent_known_answers() {
        let ctx = context();
        let keys = derive_session_keys(&K, &K, &ctx).unwrap();
        assert_eq!(keys.enc.to_vec(), hex("2F053F034AAB44F6E947C1B2BFCF60AE"));
        assert_eq!(keys.mac.to_vec(), hex("7B249CE4831805885B7C3603BCE1A724"));
        assert_eq!(keys.rmac.to_vec(), hex("5B84BA66E3CF515D85A73CD06A56C5BB"));
        assert_eq!(cryptogram(&keys.mac, DC_CARD_CRYPTOGRAM, &ctx).unwrap().to_vec(), hex("2ACB7522D7BDC0EF"));
        assert_eq!(cryptogram(&keys.mac, DC_HOST_CRYPTOGRAM, &ctx).unwrap().to_vec(), hex("918D0D0D6FFF72CD"));
    }

    /// The KDF input is exactly the Amd D §4.1.5 layout: recomputing one block by hand
    /// with a direct CMAC call gives the same output.
    #[test]
    fn kdf_input_layout_is_label_constant_separator_length_counter_context() {
        let ctx = context();
        let mut input = vec![0u8; 11];
        input.extend_from_slice(&[DC_CARD_CHALLENGE, 0x00, 0x00, 0x40, 0x01]);
        input.extend_from_slice(&ctx);
        let direct = lk_crypto::aes_cmac(&K, &input).unwrap();
        assert_eq!(kdf(&K, DC_CARD_CHALLENGE, &ctx, 8).unwrap(), direct[..8].to_vec());
    }

    /// Longer outputs concatenate counter blocks 1, 2, ... (NIST SP 800-108 §4.1).
    #[test]
    fn kdf_counter_blocks_for_long_outputs() {
        let ctx = context();
        let out = kdf(&K, DC_S_ENC, &ctx, 32).unwrap();
        let block = |i: u8| {
            let mut input = vec![0u8; 11];
            input.extend_from_slice(&[DC_S_ENC, 0x00, 0x01, 0x00, i]);
            input.extend_from_slice(&ctx);
            lk_crypto::aes_cmac(&K, &input).unwrap()
        };
        assert_eq!(out[..16], block(1));
        assert_eq!(out[16..], block(2));
    }

    #[test]
    fn padding_round_trip_and_rejects_malformed() {
        assert_eq!(pad(&[]), [vec![0x80], vec![0; 15]].concat());
        assert_eq!(pad(&[1; 16]).len(), 32);
        for n in 0..40 {
            let data = vec![0x5A; n];
            assert_eq!(unpad(&pad(&data)), Some(&data[..]));
        }
        assert_eq!(unpad(&[0; 16]), None);
        assert_eq!(unpad(&[1, 2, 3]), None);
        assert_eq!(unpad(&[]), None);
        let mut long = vec![0x80];
        long.extend_from_slice(&[0; 31]);
        assert_eq!(unpad(&long), None);
    }

    /// Key check value of the default key, computed with OpenSSL AES-ECB over sixteen
    /// `01` bytes.
    #[test]
    fn key_check_value_of_default_key() {
        assert_eq!(key_check_value(&K).unwrap().to_vec(), hex("504A77"));
    }

    #[test]
    fn response_icv_sets_first_byte() {
        let a = response_icv(&K, 1).unwrap();
        let mut block = [0u8; 16];
        block[0] = 0x80;
        block[15] = 0x01;
        assert_eq!(a, lk_crypto::aes_ecb_encrypt_block(&K, &block).unwrap());
        assert_ne!(command_icv(&K, 1).unwrap(), a);
    }
}
