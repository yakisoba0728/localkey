//! Data objects of the OpenPGP application: constants, the public objects that must
//! byte-match the firmware 5.7.4 observation, and the builders of the constructed
//! objects 65, 6E and 7A.
//!
//! References:
//! - OpenPGP Smart Card Application Functional Specification 3.4.1 ("spec") §4.2.1
//!   (AID), §4.4.1 (data object table), §4.4.3 (individual objects), §6 (historical bytes).
//! - `reference/yubikey-5c-nano-5.7.4/openpgp-reference-observation.json` ("observation"):
//!   the bytes of 5F52, 7F66, 7F74, C0, FA and the 6E / 7A layouts.

use lk_core::DeviceProfile;

use crate::state::{SLOTS, State};

/// RID `D2 76 00 01 24` plus application `01` (spec §4.2.1). Hosts select with this
/// prefix; the full 16-byte AID adds version, manufacturer and serial.
pub const AID_PREFIX: [u8; 6] = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];

/// Specification version 3.4 as announced in the AID (spec §4.2.1).
const SPEC_VERSION: [u8; 2] = [0x03, 0x04];

/// Manufacturer ID of Yubico in the OpenPGP card manufacturer registry (spec §4.2.1,
/// registry maintained with the specification).
const MANUFACTURER_YUBICO: [u8; 2] = [0x00, 0x06];

/// Manufacturer ID reserved for test cards (spec §4.2.1: `FF FF` is a test card). Used for
/// this engine's own identity profile, which must not claim a registered manufacturer.
const MANUFACTURER_TEST: [u8; 2] = [0xFF, 0xFF];

/// Historical bytes 5F52 (spec §6; observation `public_objects.5f52`): category 00,
/// card capabilities 73 00 00 E0 (command chaining, extended Lc/Le, extended length
/// information), status indicator 05 (operational) 90 00.
pub(crate) const HISTORICAL_BYTES: [u8; 8] = [0x00, 0x73, 0x00, 0x00, 0xE0, 0x05, 0x90, 0x00];

/// Extended length information 7F66 (spec §4.4.3.11; observation `public_objects.7f66`):
/// maximum command and response length 3070 bytes each.
pub(crate) const EXTENDED_LENGTH_INFO: [u8; 8] = [0x02, 0x02, 0x0B, 0xFE, 0x02, 0x02, 0x0B, 0xFE];

/// General feature management 7F74 (spec §4.4.3.12; observation `public_objects.7f74`):
/// `81 01 20` = a button is present.
pub(crate) const GENERAL_FEATURE_MANAGEMENT: [u8; 3] = [0x81, 0x01, 0x20];

/// Extended capabilities C0 (spec §4.4.3.7; observation `public_objects.c0`): flags 7D
/// (GET CHALLENGE, key import, PW status changeable, private use DOs, algorithm attributes
/// changeable, KDF), no secure messaging, challenge 3070, certificate 2048, special DOs
/// 255, no PIN block 2 format, MSE not announced.
pub(crate) const EXTENDED_CAPABILITIES: [u8; 10] =
    [0x7D, 0x00, 0x0B, 0xFE, 0x08, 0x00, 0x00, 0xFF, 0x00, 0x00];

/// Factory algorithm attributes of every key slot: RSA 2048, 17-bit exponent, standard
/// import format (spec §4.4.3.10; observation `algorithm_attributes`).
pub(crate) const DEFAULT_ALGORITHM_ATTRIBUTES: [u8; 6] = [0x01, 0x08, 0x00, 0x00, 0x11, 0x00];

/// Factory user interaction flag: off, with the button as the only feature (Yubico
/// OpenPGP UIF extension; the second byte repeats 7F74's `20`). The observation keeps
/// only the length (2); the value is model policy.
pub(crate) const DEFAULT_UIF: [u8; 2] = [0x00, 0x20];

/// Largest GET CHALLENGE (C0 bytes 3-4; observation `challenge_max_length`).
pub(crate) const MAX_CHALLENGE: usize = 3070;
/// Largest command data field of one APDU (7F66).
pub(crate) const MAX_COMMAND_DATA: usize = 3070;
/// Largest response data field of one APDU (7F66).
pub(crate) const MAX_RESPONSE: usize = 3070;
/// Largest certificate (C0 bytes 5-6; observation `certificate_max_length`).
pub(crate) const MAX_CERTIFICATE: usize = 2048;
/// Largest special DO: private use, login data, URL, KDF-DO (C0 bytes 7-8; spec §4.4.3.7).
pub(crate) const MAX_SPECIAL_DO: usize = 255;
/// Largest cardholder name (spec §4.4.3.3: 39 bytes).
pub(crate) const MAX_NAME: usize = 39;
/// Largest language preference: up to four ISO 639 two-letter codes (spec §4.4.3.4).
pub(crate) const MAX_LANGUAGE: usize = 8;
/// Bytes accumulated over a command chain (ISO 7816-4 §5.1.1.1). Larger than one APDU so
/// that a certificate or an RSA 4096 key import can be chained in short APDUs.
pub(crate) const MAX_CHAIN_DATA: usize = 4096;

/// Algorithm information FA (spec §4.4.3.13): the exact 421 bytes of the observation
/// (`algorithm_information`), 43 slot/algorithm variants in device order.
pub(crate) const ALGORITHM_INFORMATION: [u8; 421] = [
    0xfa, 0x82, 0x01, 0xa1, 0xc1, 0x06, 0x01, 0x08, 0x00, 0x00, 0x11, 0x00, 0xc1, 0x06, 0x01, 0x0c,
    0x00, 0x00, 0x11, 0x00, 0xc1, 0x06, 0x01, 0x10, 0x00, 0x00, 0x11, 0x00, 0xc1, 0x09, 0x13, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xc1, 0x06, 0x13, 0x2b, 0x81, 0x04, 0x00, 0x22, 0xc1,
    0x06, 0x13, 0x2b, 0x81, 0x04, 0x00, 0x23, 0xc1, 0x06, 0x13, 0x2b, 0x81, 0x04, 0x00, 0x0a, 0xc1,
    0x0a, 0x13, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07, 0xc1, 0x0a, 0x13, 0x2b, 0x24,
    0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b, 0xc1, 0x0a, 0x13, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08,
    0x01, 0x01, 0x0d, 0xc1, 0x0a, 0x16, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01, 0xc2,
    0x06, 0x01, 0x08, 0x00, 0x00, 0x11, 0x00, 0xc2, 0x06, 0x01, 0x0c, 0x00, 0x00, 0x11, 0x00, 0xc2,
    0x06, 0x01, 0x10, 0x00, 0x00, 0x11, 0x00, 0xc2, 0x09, 0x12, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
    0x01, 0x07, 0xc2, 0x06, 0x12, 0x2b, 0x81, 0x04, 0x00, 0x22, 0xc2, 0x06, 0x12, 0x2b, 0x81, 0x04,
    0x00, 0x23, 0xc2, 0x06, 0x12, 0x2b, 0x81, 0x04, 0x00, 0x0a, 0xc2, 0x0a, 0x12, 0x2b, 0x24, 0x03,
    0x03, 0x02, 0x08, 0x01, 0x01, 0x07, 0xc2, 0x0a, 0x12, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01,
    0x01, 0x0b, 0xc2, 0x0a, 0x12, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d, 0xc2, 0x0b,
    0x12, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01, 0xc3, 0x06, 0x01, 0x08, 0x00,
    0x00, 0x11, 0x00, 0xc3, 0x06, 0x01, 0x0c, 0x00, 0x00, 0x11, 0x00, 0xc3, 0x06, 0x01, 0x10, 0x00,
    0x00, 0x11, 0x00, 0xc3, 0x09, 0x13, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xc3, 0x06,
    0x13, 0x2b, 0x81, 0x04, 0x00, 0x22, 0xc3, 0x06, 0x13, 0x2b, 0x81, 0x04, 0x00, 0x23, 0xc3, 0x06,
    0x13, 0x2b, 0x81, 0x04, 0x00, 0x0a, 0xc3, 0x0a, 0x13, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01,
    0x01, 0x07, 0xc3, 0x0a, 0x13, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b, 0xc3, 0x0a,
    0x13, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d, 0xc3, 0x0a, 0x16, 0x2b, 0x06, 0x01,
    0x04, 0x01, 0xda, 0x47, 0x0f, 0x01, 0xda, 0x06, 0x01, 0x08, 0x00, 0x00, 0x11, 0x00, 0xda, 0x06,
    0x01, 0x0c, 0x00, 0x00, 0x11, 0x00, 0xda, 0x06, 0x01, 0x10, 0x00, 0x00, 0x11, 0x00, 0xda, 0x09,
    0x13, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xda, 0x06, 0x13, 0x2b, 0x81, 0x04, 0x00,
    0x22, 0xda, 0x06, 0x13, 0x2b, 0x81, 0x04, 0x00, 0x23, 0xda, 0x06, 0x13, 0x2b, 0x81, 0x04, 0x00,
    0x0a, 0xda, 0x0a, 0x13, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07, 0xda, 0x0a, 0x13,
    0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b, 0xda, 0x0a, 0x13, 0x2b, 0x24, 0x03, 0x03,
    0x02, 0x08, 0x01, 0x01, 0x0d,
];

/// Data object tags (spec §4.4.1). Two-byte tags are written as `P1 P2` of GET DATA.
pub(crate) mod tag {
    pub const PRIVATE_1: u16 = 0x0101;
    pub const PRIVATE_2: u16 = 0x0102;
    pub const PRIVATE_3: u16 = 0x0103;
    pub const PRIVATE_4: u16 = 0x0104;
    pub const AID: u16 = 0x004F;
    pub const NAME: u16 = 0x005B;
    pub const LOGIN: u16 = 0x005E;
    pub const LANGUAGE: u16 = 0x5F2D;
    pub const SEX: u16 = 0x5F35;
    pub const URL: u16 = 0x5F50;
    pub const HISTORICAL: u16 = 0x5F52;
    pub const CARDHOLDER: u16 = 0x0065;
    pub const APPLICATION: u16 = 0x006E;
    pub const DISCRETIONARY: u16 = 0x0073;
    pub const SECURITY_SUPPORT: u16 = 0x007A;
    pub const SIGNATURE_COUNTER: u16 = 0x0093;
    pub const CERTIFICATE: u16 = 0x7F21;
    pub const EXTENDED_LENGTH: u16 = 0x7F66;
    pub const FEATURES: u16 = 0x7F74;
    pub const EXTENDED_CAPABILITIES: u16 = 0x00C0;
    pub const PW_STATUS: u16 = 0x00C4;
    pub const FINGERPRINTS: u16 = 0x00C5;
    pub const CA_FINGERPRINTS: u16 = 0x00C6;
    pub const GENERATION_TIMES: u16 = 0x00CD;
    pub const RESETTING_CODE: u16 = 0x00D3;
    pub const KEY_INFORMATION: u16 = 0x00DE;
    pub const KDF: u16 = 0x00F9;
    pub const ALGORITHM_INFORMATION: u16 = 0x00FA;
    /// Yubico extension: certificate of the attestation key.
    pub const ATTESTATION_CERTIFICATE: u16 = 0x00FC;
}

/// The four key slots in the order of C5/C6/CD/DE (spec §4.4.3.9-§4.4.3.10 plus the
/// Yubico attestation slot, which follows the three standard keys).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Slot {
    Sig = 0,
    Dec = 1,
    Aut = 2,
    Att = 3,
}

impl Slot {
    pub(crate) const ALL: [Slot; SLOTS] = [Slot::Sig, Slot::Dec, Slot::Aut, Slot::Att];

    pub(crate) const fn index(self) -> usize {
        self as usize
    }

    /// Algorithm attributes tag (C1, C2, C3; Yubico DA).
    pub(crate) const fn attributes_tag(self) -> u16 {
        match self {
            Slot::Sig => 0xC1,
            Slot::Dec => 0xC2,
            Slot::Aut => 0xC3,
            Slot::Att => 0xDA,
        }
    }

    /// Key reference used in DE and CRTs (spec §4.4.3.8; Yubico 81 for attestation).
    pub(crate) const fn key_ref(self) -> u8 {
        match self {
            Slot::Sig => 0x01,
            Slot::Dec => 0x02,
            Slot::Aut => 0x03,
            Slot::Att => 0x81,
        }
    }

    /// The occurrence of 7F21 that holds this slot's certificate (spec §7.2.5: occurrence 0
    /// is AUT, 1 DEC, 2 SIG; the catalog's fourth occurrence 3 is the attestation
    /// certificate, also reachable as FC).
    pub(crate) const fn certificate_occurrence(self) -> u8 {
        match self {
            Slot::Aut => 0,
            Slot::Dec => 1,
            Slot::Sig => 2,
            Slot::Att => 3,
        }
    }

    pub(crate) fn from_occurrence(occurrence: u8) -> Option<Slot> {
        Slot::ALL
            .into_iter()
            .find(|slot| slot.certificate_occurrence() == occurrence)
    }

    pub(crate) fn from_attributes_tag(tag: u16) -> Option<Slot> {
        Slot::ALL.into_iter().find(|slot| slot.attributes_tag() == tag)
    }

    /// Fingerprint tag (C7, C8, C9; Yubico DB).
    pub(crate) fn from_fingerprint_tag(tag: u16) -> Option<Slot> {
        match tag {
            0xC7 => Some(Slot::Sig),
            0xC8 => Some(Slot::Dec),
            0xC9 => Some(Slot::Aut),
            0xDB => Some(Slot::Att),
            _ => None,
        }
    }

    /// CA fingerprint tag (CA, CB, CC; Yubico DC).
    pub(crate) fn from_ca_fingerprint_tag(tag: u16) -> Option<Slot> {
        match tag {
            0xCA => Some(Slot::Sig),
            0xCB => Some(Slot::Dec),
            0xCC => Some(Slot::Aut),
            0xDC => Some(Slot::Att),
            _ => None,
        }
    }

    /// Generation time tag (CE, CF, D0; Yubico DD).
    pub(crate) fn from_generation_time_tag(tag: u16) -> Option<Slot> {
        match tag {
            0xCE => Some(Slot::Sig),
            0xCF => Some(Slot::Dec),
            0xD0 => Some(Slot::Aut),
            0xDD => Some(Slot::Att),
            _ => None,
        }
    }

    /// User interaction flag tag (Yubico D6, D7, D8, D9).
    pub(crate) fn from_uif_tag(tag: u16) -> Option<Slot> {
        match tag {
            0xD6 => Some(Slot::Sig),
            0xD7 => Some(Slot::Dec),
            0xD8 => Some(Slot::Aut),
            0xD9 => Some(Slot::Att),
            _ => None,
        }
    }

    const fn uif_tag(self) -> u32 {
        match self {
            Slot::Sig => 0xD6,
            Slot::Dec => 0xD7,
            Slot::Aut => 0xD8,
            Slot::Att => 0xD9,
        }
    }
}

/// The full 16-byte AID (spec §4.2.1): prefix, version 3.4, manufacturer, serial, RFU.
///
/// The serial is BCD-encoded when it has at most eight decimal digits, so that hosts that
/// print the AID serial in hex show the same number as the device serial (as the
/// YubiKey does); larger serials fall back to big-endian binary. The manufacturer is Yubico
/// (`00 06`) for a profile whose manufacturer is "Yubico", otherwise the test-card ID.
pub(crate) fn full_aid(profile: &DeviceProfile) -> [u8; 16] {
    let mut aid = [0u8; 16];
    let manufacturer = if profile.manufacturer == "Yubico" {
        MANUFACTURER_YUBICO
    } else {
        MANUFACTURER_TEST
    };
    let serial = serial_bytes(profile.serial);
    let parts: [&[u8]; 4] = [&AID_PREFIX, &SPEC_VERSION, &manufacturer, &serial];
    let mut at = 0;
    for part in parts {
        for &b in part {
            if let Some(slot) = aid.get_mut(at) {
                *slot = b;
            }
            at += 1;
        }
    }
    aid
}

fn serial_bytes(serial: u32) -> [u8; 4] {
    if serial >= 100_000_000 {
        return serial.to_be_bytes();
    }
    let mut out = [0u8; 4];
    let mut rest = serial;
    for byte in out.iter_mut().rev() {
        let low = (rest % 10) as u8;
        rest /= 10;
        let high = (rest % 10) as u8;
        rest /= 10;
        *byte = (high << 4) | low;
    }
    out
}

/// PW status bytes C4 (spec §4.4.3.6): PW1 validity, maximum lengths of PW1, RC and PW3,
/// and the three retry counters. The observation keeps only C4's length (7); the values
/// (factory `01 7F 7F 7F 03 00 03`) are model policy consistent with public YubiKey
/// documentation (127-byte PINs, 3 tries, no resetting code), not captured bytes.
pub(crate) fn pw_status(state: &State) -> [u8; 7] {
    let [pw1, rc, pw3] = state.retries;
    [u8::from(state.pw1_multi), 0x7F, 0x7F, 0x7F, pw1, rc, pw3]
}

/// Cardholder related data 65 (spec §4.4.3.2): name 5B, language 5F2D, sex 5F35.
pub(crate) fn cardholder_data(state: &State) -> Vec<u8> {
    let mut inner = Vec::new();
    lk_codec::tlv::encode_into(&mut inner, u32::from(tag::NAME), &state.name);
    lk_codec::tlv::encode_into(&mut inner, u32::from(tag::LANGUAGE), &state.language);
    lk_codec::tlv::encode_into(&mut inner, u32::from(tag::SEX), &[state.sex]);
    lk_codec::tlv::encode(u32::from(tag::CARDHOLDER), &inner)
}

/// Security support template 7A (spec §4.4.3.14; observation `security_support_template_layout`):
/// the digital signature counter 93 as three bytes.
pub(crate) fn security_support(state: &State) -> Vec<u8> {
    let counter = state.signature_counter.min(0x00FF_FFFF).to_be_bytes();
    let inner = lk_codec::tlv::encode(u32::from(tag::SIGNATURE_COUNTER), counter.get(1..).unwrap_or(&[]));
    lk_codec::tlv::encode(u32::from(tag::SECURITY_SUPPORT), &inner)
}

/// All four fingerprints C5, CA fingerprints C6 or generation times CD, concatenated in
/// slot order SIG, DEC, AUT, ATT (spec §4.4.3.9 with the Yubico fourth slot; observation
/// lengths 80, 80, 16).
pub(crate) fn fingerprints(state: &State) -> Vec<u8> {
    state.slots.iter().flat_map(|s| s.fingerprint).collect()
}

pub(crate) fn ca_fingerprints(state: &State) -> Vec<u8> {
    state.slots.iter().flat_map(|s| s.ca_fingerprint).collect()
}

pub(crate) fn generation_times(state: &State) -> Vec<u8> {
    state.slots.iter().flat_map(|s| s.generation_time).collect()
}

/// Key information DE (spec §4.4.3.8): key reference and status (00 absent, 01
/// generated, 02 imported) for each slot. The factory value is `01 00 02 00 03 00 81 01`:
/// only the attestation key exists, generated on first start (attest.rs; model policy,
/// the observation keeps only DE's length).
pub(crate) fn key_information(state: &State) -> Vec<u8> {
    Slot::ALL
        .into_iter()
        .zip(state.slots.iter())
        .flat_map(|(slot, data)| [slot.key_ref(), data.key_status])
        .collect()
}

/// Application related data 6E (spec §4.4.3.1) in the device order of the observation
/// (`application_related_layout`): 4F, 5F52, 7F74, then 73 holding C0, C1, C2, C3, DA,
/// C4, C5, C6, CD, DE, 7F66, D6, D7, D8, D9.
pub(crate) fn application_data(state: &State, profile: &DeviceProfile) -> Vec<u8> {
    use lk_codec::tlv::encode_into;
    let mut discretionary = Vec::new();
    encode_into(&mut discretionary, u32::from(tag::EXTENDED_CAPABILITIES), &EXTENDED_CAPABILITIES);
    for slot in Slot::ALL {
        if let Some(data) = state.slots.get(slot.index()) {
            encode_into(&mut discretionary, u32::from(slot.attributes_tag()), &data.attributes);
        }
    }
    encode_into(&mut discretionary, u32::from(tag::PW_STATUS), &pw_status(state));
    encode_into(&mut discretionary, u32::from(tag::FINGERPRINTS), &fingerprints(state));
    encode_into(&mut discretionary, u32::from(tag::CA_FINGERPRINTS), &ca_fingerprints(state));
    encode_into(&mut discretionary, u32::from(tag::GENERATION_TIMES), &generation_times(state));
    encode_into(&mut discretionary, u32::from(tag::KEY_INFORMATION), &key_information(state));
    encode_into(&mut discretionary, u32::from(tag::EXTENDED_LENGTH), &EXTENDED_LENGTH_INFO);
    for slot in Slot::ALL {
        if let Some(data) = state.slots.get(slot.index()) {
            encode_into(&mut discretionary, slot.uif_tag(), &data.uif);
        }
    }

    let mut inner = Vec::new();
    encode_into(&mut inner, u32::from(tag::AID), &full_aid(profile));
    encode_into(&mut inner, u32::from(tag::HISTORICAL), &HISTORICAL_BYTES);
    encode_into(&mut inner, u32::from(tag::FEATURES), &GENERAL_FEATURE_MANAGEMENT);
    encode_into(&mut inner, u32::from(tag::DISCRETIONARY), &discretionary);
    lk_codec::tlv::encode(u32::from(tag::APPLICATION), &inner)
}

/// Whether `value` is an algorithm attribute the slot accepts: one of the slot's entries
/// in FA (spec §4.4.3.13), or an ECDH/ECDSA/EdDSA entry followed by the import-format
/// byte `FF` ("public key included", spec §4.4.3.10).
pub(crate) fn attributes_supported(slot: Slot, value: &[u8]) -> bool {
    let Ok((fa, _)) = lk_codec::tlv::parse_one(&ALGORITHM_INFORMATION) else {
        return false;
    };
    let Ok(entries) = fa.children() else {
        return false;
    };
    entries
        .iter()
        .filter(|entry| entry.tag == u32::from(slot.attributes_tag()))
        .any(|entry| {
            if entry.value == value {
                return true;
            }
            let is_ec = matches!(entry.value.first(), Some(0x12 | 0x13 | 0x16));
            is_ec
                && value.len() == entry.value.len() + 1
                && value.starts_with(entry.value)
                && value.last() == Some(&0xFF)
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn bcd_serial_and_binary_fallback() {
        // spec §4.2.1: serial bytes 11-14 of the AID.
        assert_eq!(serial_bytes(12_345_678), [0x12, 0x34, 0x56, 0x78]);
        assert_eq!(serial_bytes(7), [0x00, 0x00, 0x00, 0x07]);
        assert_eq!(serial_bytes(99_999_999), [0x99, 0x99, 0x99, 0x99]);
        assert_eq!(serial_bytes(100_000_000), 100_000_000u32.to_be_bytes());
    }

    #[test]
    fn full_aid_layout() {
        // spec §4.2.1 table: RID, application, version, manufacturer, serial, RFU.
        let aid = full_aid(&DeviceProfile::yubikey_5c_nano_5_7_4(12_345_678));
        assert_eq!(
            aid,
            [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0x00, 0x06, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00]
        );
        let own = full_aid(&DeviceProfile::own(1));
        assert_eq!(own[8..10], [0xFF, 0xFF]);
    }

    #[test]
    fn fa_inventory_counts() {
        // observation `algorithm_information`; legacy profile advertised_variants 11/11/11/10.
        let (fa, rest) = lk_codec::tlv::parse_one(&ALGORITHM_INFORMATION).unwrap();
        assert!(rest.is_empty());
        let entries = fa.children().unwrap();
        assert_eq!(entries.len(), 43);
        for (slot, count) in [(Slot::Sig, 11), (Slot::Dec, 11), (Slot::Aut, 11), (Slot::Att, 10)] {
            let n = entries.iter().filter(|e| e.tag == u32::from(slot.attributes_tag())).count();
            assert_eq!(n, count);
        }
    }

    #[test]
    fn attribute_support_rules() {
        // spec §4.4.3.10 formats; FA entries from the observation.
        assert!(attributes_supported(Slot::Sig, &DEFAULT_ALGORITHM_ATTRIBUTES));
        let ed25519 = [0x16, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01];
        assert!(attributes_supported(Slot::Sig, &ed25519));
        assert!(attributes_supported(Slot::Aut, &ed25519));
        assert!(!attributes_supported(Slot::Dec, &ed25519));
        assert!(!attributes_supported(Slot::Att, &ed25519));
        let mut with_ff = ed25519.to_vec();
        with_ff.push(0xFF);
        assert!(attributes_supported(Slot::Sig, &with_ff));
        let mut rsa_ff = DEFAULT_ALGORITHM_ATTRIBUTES.to_vec();
        rsa_ff.push(0xFF);
        assert!(!attributes_supported(Slot::Sig, &rsa_ff));
        assert!(!attributes_supported(Slot::Sig, &[]));
        // RSA 2048 with CRT import format (02) is not advertised in FA.
        assert!(!attributes_supported(Slot::Sig, &[0x01, 0x08, 0x00, 0x00, 0x11, 0x02]));
    }
}
