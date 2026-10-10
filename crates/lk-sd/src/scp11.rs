//! SCP11 key agreement building blocks (GlobalPlatform Card Specification v2.3.1
//! Amendment F, "Secure Channel Protocol '11'", cited as "Amd F").
//!
//! - §7.6.2.3 (MUTUAL AUTHENTICATE) / §7.7 (INTERNAL AUTHENTICATE) command data: a
//!   control reference template `A6 { 90 02 11 <i>, 95 01 <key usage>, 80 01 <key type>,
//!   81 01 <key length> }` followed by the OCE ephemeral public key `5F49`.
//! - §3.1.2 / §6.5.2.3 key derivation: the shared secrets ShSee || ShSes go through the
//!   ANSI X9.63 KDF with SHA-256 (BSI TR-03111 §4.3.3) with SharedInfo = key usage ||
//!   key type || key length. The output is, in order, the receipt key, S-ENC, S-MAC,
//!   S-RMAC and S-DEK, each as long as the key length.
//! - Receipt: AES-CMAC with the receipt key over the command data followed by the
//!   card's `5F49` object. It is the first MAC chaining value of the session.
//!
//! Profile (as Yubico's SDK sends it, yubikit `scp.py`): `i` = `01` for SCP11a, `00`
//! for SCP11b, `03` for SCP11c; key usage `3C` (C-MAC, C-DECRYPTION, R-MAC,
//! R-ENCRYPTION), key type `88` (AES), key length `10` (16 bytes). Other values are
//! refused: the YubiKey implements full protection with AES-128 only (Yubico
//! yk5-apps-scp: "Turning anything off is not an option").

use lk_codec::tlv;
use lk_crypto::Curve;

use crate::scp03::{Key, SessionKeys, to_key, wipe};

/// SCP identifier of SCP11 (Amd F §5.1).
pub(crate) const SCP11_ID: u8 = 0x11;
/// Key usage qualifier `3C`: C-MAC, C-DECRYPTION, R-MAC, R-ENCRYPTION.
pub(crate) const KEY_USAGE: u8 = 0x3C;
/// Key type `88`: AES (GP Card Specification v2.3.1 Table 11-16).
pub(crate) const KEY_TYPE_AES: u8 = 0x88;
/// Session key length in bytes (AES-128).
pub(crate) const KEY_LEN: u8 = 0x10;

/// Tag of an EC public key in the key agreement (Amd F, `5F49`).
pub(crate) const TAG_EPK: u32 = 0x5F49;
/// Tag of the receipt (Amd F, `86`).
pub(crate) const TAG_RECEIPT: u32 = 0x86;

mod tag {
    pub(super) const CRT: u32 = 0xA6;
    pub(super) const SCP_ID: u32 = 0x90;
    pub(super) const KEY_USAGE: u32 = 0x95;
    pub(super) const KEY_TYPE: u32 = 0x80;
    pub(super) const KEY_LEN: u32 = 0x81;
}

/// The three SCP11 variants (Amd F §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Variant {
    A,
    B,
    C,
}

impl Variant {
    /// The `i` parameter after `11` in tag `90` (yubikit `scp.py`).
    pub(crate) fn parameter(self) -> u8 {
        match self {
            Variant::A => 0x01,
            Variant::B => 0x00,
            Variant::C => 0x03,
        }
    }

    pub(crate) fn kid(self) -> u8 {
        match self {
            Variant::A => crate::state::KID_SCP11A,
            Variant::B => crate::state::KID_SCP11B,
            Variant::C => crate::state::KID_SCP11C,
        }
    }

    pub(crate) fn protocol(self) -> crate::channel::Protocol {
        match self {
            Variant::A => crate::channel::Protocol::Scp11a,
            Variant::B => crate::channel::Protocol::Scp11b,
            Variant::C => crate::channel::Protocol::Scp11c,
        }
    }
}

/// Parse the MUTUAL/INTERNAL AUTHENTICATE command data and return the OCE ephemeral
/// public key. Every object must appear exactly once, in the order above, with the
/// profile values; anything else is `None` (answered `6A80`).
pub(crate) fn parse_request(data: &[u8], variant: Variant) -> Option<Vec<u8>> {
    let (crt, rest) = tlv::parse_one(data).ok()?;
    let (epk, rest) = tlv::parse_one(rest).ok()?;
    if crt.tag != tag::CRT || epk.tag != TAG_EPK || !rest.is_empty() {
        return None;
    }
    let children = tlv::parse_all(crt.value).ok()?;
    let expected: [(u32, &[u8]); 4] = [
        (tag::SCP_ID, &[SCP11_ID, variant.parameter()]),
        (tag::KEY_USAGE, &[KEY_USAGE]),
        (tag::KEY_TYPE, &[KEY_TYPE_AES]),
        (tag::KEY_LEN, &[KEY_LEN]),
    ];
    if children.len() != expected.len() {
        return None;
    }
    for (child, (t, value)) in children.iter().zip(expected) {
        if child.tag != t || child.value != value {
            return None;
        }
    }
    lk_crypto::ec_public_is_valid(Curve::P256, epk.value).then(|| epk.value.to_vec())
}

/// ANSI X9.63 KDF with SHA-256 (BSI TR-03111 §4.3.3): `K_i = SHA-256(Z || i || SharedInfo)`
/// with a 32-bit big-endian counter from 1, concatenated and truncated to `len`.
pub(crate) fn x963_kdf_sha256(z: &[u8], shared_info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    let mut counter: u32 = 1;
    while out.len() < len {
        let mut input = Vec::with_capacity(z.len() + 4 + shared_info.len());
        input.extend_from_slice(z);
        input.extend_from_slice(&counter.to_be_bytes());
        input.extend_from_slice(shared_info);
        out.extend_from_slice(&lk_crypto::sha256(&input));
        wipe(&mut input);
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    out
}

/// What the key agreement produces.
pub(crate) struct Agreement {
    pub(crate) receipt: [u8; 16],
    pub(crate) keys: SessionKeys,
    pub(crate) dek: Key,
}

impl Drop for Agreement {
    fn drop(&mut self) {
        wipe(&mut self.dek);
    }
}

/// Amd F §3.1.2: derive the receipt key and the session keys from `sh_see || sh_ses`
/// and compute the receipt over `request || sd_epk_object`.
pub(crate) fn agree(sh_see: &[u8], sh_ses: &[u8], request: &[u8], sd_epk_object: &[u8]) -> Option<Agreement> {
    let mut z = Vec::with_capacity(sh_see.len() + sh_ses.len());
    z.extend_from_slice(sh_see);
    z.extend_from_slice(sh_ses);
    let n = usize::from(KEY_LEN);
    let mut material = x963_kdf_sha256(&z, &[KEY_USAGE, KEY_TYPE_AES, KEY_LEN], 5 * n);
    wipe(&mut z);
    let key = |i: usize| material.get(i * n..(i + 1) * n).and_then(to_key);
    let parts = (key(0), key(1), key(2), key(3), key(4));
    wipe(&mut material);
    let (Some(mut receipt_key), Some(enc), Some(mac), Some(rmac), Some(dek)) = parts else {
        return None;
    };
    let mut input = Vec::with_capacity(request.len() + sd_epk_object.len());
    input.extend_from_slice(request);
    input.extend_from_slice(sd_epk_object);
    let receipt = lk_crypto::aes_cmac(&receipt_key, &input).ok();
    wipe(&mut receipt_key);
    Some(Agreement { receipt: receipt?, keys: SessionKeys { enc, mac, rmac }, dek })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// X9.63 KDF known answer computed with Python `cryptography` 46 (OpenSSL)
    /// `X963KDF(SHA256(), 80, sharedinfo=3C8810)` over Z = 00 01 .. 3F.
    #[test]
    fn x963_kdf_matches_independent_known_answer() {
        let z: Vec<u8> = (0u8..64).collect();
        let out = x963_kdf_sha256(&z, &[0x3C, 0x88, 0x10], 80);
        assert_eq!(out, hex(X963_KAT));
    }

    pub(super) const X963_KAT: &str = "78E6AFBA798E338B0B6104DFC18E5B9EFAABDF39C991DE6879D9C7A0C21FF02240998CE38B6D3DD3FD3FA9C7D956B67323D069AF6457586600431B7EC83D38C7183F299DDC90B91643D6D2E137EEFCFF";

    /// The counter blocks are SHA-256(Z || i || SharedInfo) with a 4-byte counter.
    #[test]
    fn x963_kdf_layout() {
        let z = [7u8; 32];
        let out = x963_kdf_sha256(&z, b"info", 40);
        let block = |i: u32| lk_crypto::sha256(&[&z[..], &i.to_be_bytes(), b"info"].concat());
        assert_eq!(out[..32], block(1));
        assert_eq!(out[32..], block(2)[..8]);
    }

    #[test]
    fn request_parsing_is_exact() {
        let point = lk_crypto::EcPrivateKey::from_scalar(Curve::P256, &[1; 32]).unwrap().public_uncompressed();
        let build = |params: u8, usage: u8, extra: &[u8]| {
            let mut crt = Vec::new();
            tlv::encode_into(&mut crt, 0x90, &[0x11, params]);
            tlv::encode_into(&mut crt, 0x95, &[usage]);
            tlv::encode_into(&mut crt, 0x80, &[0x88]);
            tlv::encode_into(&mut crt, 0x81, &[0x10]);
            crt.extend_from_slice(extra);
            let mut data = tlv::encode(0xA6, &crt);
            tlv::encode_into(&mut data, 0x5F49, &point);
            data
        };
        assert_eq!(parse_request(&build(0x00, 0x3C, &[]), Variant::B), Some(point.clone()));
        assert_eq!(parse_request(&build(0x01, 0x3C, &[]), Variant::A), Some(point.clone()));
        assert_eq!(parse_request(&build(0x03, 0x3C, &[]), Variant::C), Some(point.clone()));
        assert_eq!(parse_request(&build(0x01, 0x3C, &[]), Variant::B), None);
        assert_eq!(parse_request(&build(0x00, 0x34, &[]), Variant::B), None);
        assert_eq!(parse_request(&build(0x00, 0x3C, &[0x84, 0x01, 0x00]), Variant::B), None);
        assert_eq!(parse_request(&[0; 8], Variant::B), None);
        let mut trailing = build(0x00, 0x3C, &[]);
        trailing.push(0);
        assert_eq!(parse_request(&trailing, Variant::B), None);
    }
}
