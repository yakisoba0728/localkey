//! Session-key derivations the application performs for the host.
//!
//! - **Symmetric** (YubiHSM 2 symmetric authentication, an SCP03 derivative): the
//!   context is `host challenge (8) || card challenge (8)`. Session keys come from the
//!   SCP03 data derivation scheme, GPC v2.3.1 Amendment D §4.1.5: NIST SP 800-108 KDF in
//!   counter mode (SP 800-108 §5.1) with AES-CMAC (NIST SP 800-38B) as PRF and the
//!   fixed input `label (11 x 00 || constant) || 00 || L (2 bytes) || i (1 byte) ||
//!   context`. Constants (Amendment D Table 4-1): card cryptogram `00`, S-ENC `04`,
//!   S-MAC `06`, S-RMAC `07`. S-ENC is derived from K-ENC, S-MAC and S-RMAC from K-MAC;
//!   the card cryptogram is the first 64 bits derived from S-MAC (Amendment D §6.2.2.2).
//! - **Asymmetric** (YubiHSM 2 asymmetric authentication, SCP11-like): the context is
//!   `EPK.OCE (65) || EPK.SD (65)` (yubikit `calculate_session_keys_asymmetric`
//!   docstring). As in yubihsm-shell `yh_create_session_asym`: `ShSee = ECDH(eSK.OCE,
//!   EPK.SD)`, `ShSss = ECDH(SK.OCE, PK.SD)`, key data = X9.63-KDF-SHA-256(`ShSee ||
//!   ShSss`, shared info `3C 88 10`, 64 bytes) (SEC 1 v2.0 §3.6.1; the shared info is the
//!   GPC Amendment F key usage `3C`, key type `88` (AES) and key length `10`), split into
//!   receipt key, S-ENC, S-MAC, S-RMAC. The receipt is AES-CMAC(receipt key, `EPK.SD ||
//!   EPK.OCE`), card key first.

use lk_crypto::{CryptoError, EcPrivateKey, aes_cmac, sha256};

/// Amendment D Table 4-1: derivation constant for the card cryptogram.
const CARD_CRYPTOGRAM: u8 = 0x00;
/// Amendment D Table 4-1: derivation constant for S-ENC.
const S_ENC: u8 = 0x04;
/// Amendment D Table 4-1: derivation constant for S-MAC.
const S_MAC: u8 = 0x06;
/// Amendment D Table 4-1: derivation constant for S-RMAC.
const S_RMAC: u8 = 0x07;

/// Shared info of the asymmetric X9.63 KDF (yubihsm-shell `yh_create_session_asym`).
const ASYM_SHARED_INFO: [u8; 3] = [0x3C, 0x88, 0x10];

/// S-ENC || S-MAC || S-RMAC as returned by CALCULATE (yubikit `SessionKeys.parse`).
pub(crate) type SessionKeys = [u8; 48];

/// SCP03 KDF (Amendment D §4.1.5): `out_bits` bits (a multiple of 8, at most 255
/// blocks) derived from `key` for `constant` and `context`.
pub(crate) fn scp03_kdf(key: &[u8], constant: u8, context: &[u8], out_bits: u16) -> Result<Vec<u8>, CryptoError> {
    let out_len = usize::from(out_bits / 8);
    let mut out = Vec::with_capacity(out_len + 16);
    let mut counter: u8 = 1;
    while out.len() < out_len {
        let mut input = Vec::with_capacity(16 + context.len());
        input.extend_from_slice(&[0u8; 11]);
        input.push(constant);
        input.push(0x00);
        input.extend_from_slice(&out_bits.to_be_bytes());
        input.push(counter);
        input.extend_from_slice(context);
        out.extend_from_slice(&aes_cmac(key, &input)?);
        counter = counter.checked_add(1).ok_or(CryptoError::InvalidInput)?;
    }
    out.truncate(out_len);
    Ok(out)
}

/// The symmetric session keys for `context` (host challenge || card challenge).
pub(crate) fn symmetric_session_keys(enc: &[u8], mac: &[u8], context: &[u8]) -> Result<SessionKeys, CryptoError> {
    let mut keys = [0u8; 48];
    let parts = [(enc, S_ENC), (mac, S_MAC), (mac, S_RMAC)];
    let (chunks, _) = keys.as_chunks_mut::<16>();
    for (chunk, (key, constant)) in chunks.iter_mut().zip(parts) {
        chunk.copy_from_slice(&scp03_kdf(key, constant, context, 128)?);
    }
    Ok(keys)
}

/// The card cryptogram (Amendment D §6.2.2.2): 64 bits derived from S-MAC.
pub(crate) fn card_cryptogram(s_mac: &[u8], context: &[u8]) -> Result<Vec<u8>, CryptoError> {
    scp03_kdf(s_mac, CARD_CRYPTOGRAM, context, 64)
}

/// ANSI X9.63 KDF with SHA-256 (SEC 1 v2.0 §3.6.1): `K_i = SHA-256(Z || i (4 bytes BE)
/// || SharedInfo)` for `i = 1, 2, ...`, truncated to `len`.
pub(crate) fn x963_kdf_sha256(z: &[u8], shared_info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    let mut counter: u32 = 1;
    while out.len() < len {
        let mut input = Vec::with_capacity(z.len() + 4 + shared_info.len());
        input.extend_from_slice(z);
        input.extend_from_slice(&counter.to_be_bytes());
        input.extend_from_slice(shared_info);
        out.extend_from_slice(&sha256(&input));
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    out
}

/// Asymmetric derivation result.
pub(crate) struct AsymmetricKeys {
    pub(crate) receipt: [u8; 16],
    pub(crate) session: SessionKeys,
}

/// Derive the asymmetric session keys and the receipt the YubiHSM must have sent.
///
/// `credential` is SK.OCE, `ephemeral` eSK.OCE, `card_static` PK.SD and `epk_oce` /
/// `epk_sd` the two halves of the context.
pub(crate) fn asymmetric_session_keys(
    credential: &EcPrivateKey,
    ephemeral: &EcPrivateKey,
    card_static: &[u8],
    epk_oce: &[u8],
    epk_sd: &[u8],
) -> Result<AsymmetricKeys, CryptoError> {
    let shsee = ephemeral.ecdh(epk_sd)?;
    let shsss = credential.ecdh(card_static)?;
    let mut z = Vec::with_capacity(shsee.len() + shsss.len());
    z.extend_from_slice(&shsee);
    z.extend_from_slice(&shsss);
    let mut key_data = x963_kdf_sha256(&z, &ASYM_SHARED_INFO, 64);
    crate::state::wipe(&mut z);
    let mut receipt_key = [0u8; 16];
    let mut session = [0u8; 48];
    let (head, tail) = key_data.split_at_checked(16).ok_or(CryptoError::InvalidInput)?;
    receipt_key.copy_from_slice(head);
    session.copy_from_slice(tail);
    crate::state::wipe(&mut key_data);
    let mut mac_input = Vec::with_capacity(epk_sd.len() + epk_oce.len());
    mac_input.extend_from_slice(epk_sd);
    mac_input.extend_from_slice(epk_oce);
    let receipt = aes_cmac(&receipt_key, &mac_input);
    crate::state::wipe(&mut receipt_key);
    Ok(AsymmetricKeys { receipt: receipt?, session })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .filter_map(|i| s.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
            .collect()
    }

    /// Yubico's published hardware test (yubikey-manager
    /// `tests/device/test_hsmauth.py::TestSessionKeys::test_calculate_session_keys_symmetric`):
    /// K-ENC || K-MAC = PBKDF2-HMAC-SHA256("pwd", "Yubico", 10000, 32) (yubikit
    /// `_password_to_key`; computed with Python `hashlib`), context and expected keys as
    /// published there.
    #[test]
    fn scp03_kdf_reproduces_yubico_published_vector() {
        let enc = hex("53b8fbfb11c05a9d15b5060dd7a35cd3");
        let mac = hex("cac17ab6fb0de15b2369592c7a960dc4");
        let context = hex("67fcf1feb5f1d883ed763dbf493090bb");
        let keys = symmetric_session_keys(&enc, &mac, &context).expect("valid keys");
        assert_eq!(keys.get(..16), Some(&hex("b06f1ac987912ebedc1bf0e02a6b5d85")[..]));
        assert_eq!(keys.get(16..32), Some(&hex("ead6c3a596ea8675bf31d349abb52c74")[..]));
        assert_eq!(keys.get(32..), Some(&hex("c2c61e96ab2c58e9837ad0e7d06ee90c")[..]));
    }

    #[test]
    fn scp03_kdf_truncates_and_extends() {
        let key = [7u8; 16];
        let short = scp03_kdf(&key, 0, b"ctx", 64).expect("kdf");
        assert_eq!(short.len(), 8);
        let long = scp03_kdf(&key, 0, b"ctx", 256).expect("kdf");
        assert_eq!(long.len(), 32);
        // Different L values change every block (L is part of the fixed input).
        assert_ne!(short.get(..8), long.get(..8));
        assert!(scp03_kdf(&[0u8; 5], 0, b"", 128).is_err());
    }

    /// NIST CAVP ANSI X9.63 KDF test vectors (SP 800-135, `ansx963_2001.rsp`, SHA-256),
    /// the case reproduced in pyca/cryptography `tests/hazmat/primitives/
    /// test_x963kdf.py::test_basic`; re-checked with pyca/cryptography 46
    /// `X963KDF(SHA256(), 128, sharedinfo).derive(z)`.
    #[test]
    fn x963_kdf_matches_nist_cavp_vector() {
        let z = hex("22518b10e70f2a3f243810ae3254139efbee04aa57c7af7d");
        let shared_info = hex("75eef81aa3041e33b80971203d2c0c52");
        let expected = hex(concat!(
            "c498af77161cc59f2962b9a713e2b215152d139766ce34a776df11866a69bf2e",
            "52a13d9c7c6fc878c50c5ea0bc7b00e0da2447cfd874f6cf92f30d0097111485",
            "500c90c3af8b487872d04685d14c8d1dc8d7fa08beb0ce0ababc11f0bd496269",
            "142d43525a78e5bc79a17f59676a5706dc54d54d4d1f0bd7e386128ec26afc21",
        ));
        assert_eq!(x963_kdf_sha256(&z, &shared_info, 128), expected);
    }

    /// Independent known-answer vector for the asymmetric derivation, computed with
    /// pyca/cryptography 46 (independent ECDH, `X963KDF`, AES `CMAC`) from the layout of
    /// yubihsm-shell `lib/yubihsm.c` `yh_create_session_asym`:
    ///
    /// ```text
    /// d(name) = SHA-256(name)   # SK.OCE, eSK.OCE, SK.SD, eSK.SD
    /// shsee = eSK.OCE.exchange(ECDH(), EPK.SD); shsss = SK.OCE.exchange(ECDH(), PK.SD)
    /// data = X963KDF(SHA256(), 64, bytes.fromhex("3c8810")).derive(shsee + shsss)
    /// receipt = CMAC(AES(data[:16])) over EPK.SD || EPK.OCE
    /// S-ENC, S-MAC, S-RMAC = data[16:32], data[32:48], data[48:64]
    /// ```
    ///
    /// The scalars are SHA-256 of "lk-hsmauth KAV SK.OCE", "... eSK.OCE", "... SK.SD"
    /// and "... eSK.SD".
    mod asym_kav {
        pub const SK_OCE: &str = "b727c96e2d291d449b310ba5da6e509c42fb45d7ce2ed323fecbc386aedc2431";
        pub const ESK_OCE: &str = "e5c82d43a4444908ce4d22384b39944fa91799bece7def44389525f34e4fd5cd";
        pub const SK_SD: &str = "35e118d2076ceff415f83872424ecd0594a645e7255f5c063b816ae0b1f7bb6d";
        pub const PK_SD: &str = "049609dd832e2e6fe0ca203e95278898feb2846b46872f7c0accd53fec0504f948\
                                        381e61b4f60a6afad0f5fa299bdc805bcd979ddb467890f2c358e1a8cb309f41";
        pub const EPK_OCE: &str = "04b108a3d4d5331cac150dddddaf3d42b8934c008ae297ad58c8ad23990b9c385c\
                                          bca77e4fa5947f106b3b89d3118de209d29912b9a332cc4a9270156b9bf4d8a3";
        pub const EPK_SD: &str = "04bf423d4c16e64926f1bf591d5a578e8e808526cdea1989c7a9c1cf498b9e6d33\
                                         e096402d77628a63e84d8c9ac9c62fa42af42572b5dc44b52c1740a1fb68fc54";
        pub const RECEIPT: &str = "d1bdf8ab803cb5c3f66f6b180dc85101";
        pub const S_ENC: &str = "d5ff16a9e77875fd47459cd7ba294c04";
        pub const S_MAC: &str = "2edaa61c1b8449a1afef5f5aac6a6141";
        pub const S_RMAC: &str = "07d922d52f0631baca3a2f454fd7765b";
    }

    #[test]
    fn asymmetric_session_keys_match_independent_vector() {
        use asym_kav::*;
        use lk_crypto::Curve;
        let credential = EcPrivateKey::from_scalar(Curve::P256, &hex(SK_OCE)).expect("SK.OCE");
        let ephemeral = EcPrivateKey::from_scalar(Curve::P256, &hex(ESK_OCE)).expect("eSK.OCE");
        assert_eq!(ephemeral.public_uncompressed(), hex(EPK_OCE));
        let card_static = EcPrivateKey::from_scalar(Curve::P256, &hex(SK_SD)).expect("SK.SD");
        assert_eq!(card_static.public_uncompressed(), hex(PK_SD));
        let keys = asymmetric_session_keys(&credential, &ephemeral, &hex(PK_SD), &hex(EPK_OCE), &hex(EPK_SD))
            .expect("valid points");
        assert_eq!(keys.receipt.to_vec(), hex(RECEIPT));
        assert_eq!(keys.session.to_vec(), hex(&[S_ENC, S_MAC, S_RMAC].concat()));
    }

    #[test]
    fn x963_kdf_lengths() {
        let out = x963_kdf_sha256(b"z", b"", 64);
        assert_eq!(out.len(), 64);
        let mut first = b"z".to_vec();
        first.extend_from_slice(&1u32.to_be_bytes());
        assert_eq!(out.get(..32), Some(&sha256(&first)[..]));
        assert_eq!(x963_kdf_sha256(b"z", b"", 10).len(), 10);
    }
}
