//! Public Security Domain data objects: the SELECT response, card recognition data
//! and the key information template.
//!
//! The SELECT response and the card recognition data are the bytes a YubiKey 5C Nano
//! 5.7.4 returned (`reference/yubikey-5c-nano-5.7.4/security-domain-reference-observation.json`,
//! `select_public_template` and `card_recognition_data`). Both are GlobalPlatform
//! data rather than device identity, so every profile uses them.

use crate::state::{KID_SCP03_DEK, KID_SCP03_ENC, KID_SCP03_MAC, State};

/// Response to SELECT (GP Card Specification v2.3.1 §11.9.3.1, File Control
/// Information): `6F { 84 AID, A5 { 73 { 06 OID 1.2.840.114283.1 } } }`, 25 bytes as
/// observed.
pub(crate) const SELECT_FCI: [u8; 25] = [
    0x6F, 0x17, 0x84, 0x08, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00, //
    0xA5, 0x0B, 0x73, 0x09, 0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, //
    0x01,
];

/// GET DATA `0066`: card recognition data (GP Card Specification v2.3.1 Annex H.2).
/// As observed, the device returns the `73` template itself, without a `66` wrapper:
/// GP 2.3.1 (`60`), card identification scheme (`63`), SCP03 with `i = 60` (`64`) and
/// SCP11 with option `9B06` (`64`). 63 bytes.
pub(crate) const CARD_RECOGNITION: [u8; 63] = [
    0x73, 0x3D, 0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x01, 0x60, //
    0x0C, 0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x02, 0x02, 0x03, //
    0x01, 0x63, 0x09, 0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x03, //
    0x64, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x04, 0x03, //
    0x60, 0x64, 0x0C, 0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x04, //
    0x11, 0x9B, 0x06,
];

/// The SCP03 `i` parameter the INITIALIZE UPDATE response reports (Amd D §5.1): R-MAC
/// and R-ENCRYPTION supported, random card challenge. It matches the `60` option of the
/// recognition data above.
pub(crate) const SCP03_I: u8 = 0x60;

/// SCP identifier of SCP03 (Amd D §5.1).
pub(crate) const SCP03_ID: u8 = 0x03;

/// Key type `88`: AES (GP Card Specification v2.3.1 Table 11-16).
pub(crate) const KEY_TYPE_AES: u8 = 0x88;
/// Key type `B0`: ECC public key (GP Amendment F).
pub(crate) const KEY_TYPE_EC_PUBLIC: u8 = 0xB0;
/// Key type `B1`: ECC private key (GP Amendment F).
pub(crate) const KEY_TYPE_EC_PRIVATE: u8 = 0xB1;
/// `F0`: ECC key parameter reference (GP Amendment F); value `00` is P-256.
pub(crate) const KEY_TYPE_EC_PARAMETERS: u8 = 0xF0;

/// GET DATA `00E0`: key information (GP Card Specification v2.3.1 §11.3.3.1).
///
/// As observed, the device returns the `C0` key information data objects without an
/// `E0` wrapper (26 bytes for three `C0 04` entries and one `C0 06`). Each AES key is
/// `C0 04 KID KVN 88 10`; an SCP11 private key is `C0 06 KID KVN B1 20 F0 00` and an OCE
/// CA public key `C0 06 KID KVN B0 41 F0 00` (component type, length pairs as yubikit's
/// `get_key_information` reads them). Order: SCP03 sets by KVN, each as KID 1, 2, 3;
/// then the EC keys by (KID, KVN).
pub(crate) fn key_information(state: &State) -> Vec<u8> {
    let mut out = Vec::new();
    for set in &state.scp03 {
        for kid in [KID_SCP03_ENC, KID_SCP03_MAC, KID_SCP03_DEK] {
            out.extend_from_slice(&[0xC0, 0x04, kid, set.kvn, KEY_TYPE_AES, 0x10]);
        }
    }
    let mut ec: Vec<(u8, u8, u8, u8)> = state
        .ec_private
        .iter()
        .map(|k| (k.kid, k.kvn, KEY_TYPE_EC_PRIVATE, 0x20))
        .chain(state.ec_public.iter().map(|k| (k.kid, k.kvn, KEY_TYPE_EC_PUBLIC, 0x41)))
        .collect();
    ec.sort_unstable_by_key(|e| (e.0, e.1));
    for (kid, kvn, key_type, len) in ec {
        out.extend_from_slice(&[0xC0, 0x06, kid, kvn, key_type, len, KEY_TYPE_EC_PARAMETERS, 0x00]);
    }
    out
}
