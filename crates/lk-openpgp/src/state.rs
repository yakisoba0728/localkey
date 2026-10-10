//! Persistent state of the OpenPGP application and its storage format.
//!
//! Format (docs/CONTRACTS.md "Persisted state", docs/DESIGN.md §7): version byte `0x01`,
//! then BER-TLV fields (ISO 7816-4 §5.2.2 via `lk_codec::tlv`). Unknown fields are kept
//! and written back unchanged, so a later format can add tags without this version
//! dropping them. A buffer that does not parse, or lacks a password field, is unreadable
//! and the application starts from its factory state.
//!
//! Password references are stored as the card compares them (spec 3.4.1 §4.3): the PIN
//! bytes themselves, or, while a KDF-DO is active, only the derived hash the host sends
//! ("hash-only PIN state when KDF enabled" in the behaviour catalog).

use lk_codec::tlv;

use crate::kdf::{self, Kdf};
use crate::keys::KeyMaterial;
use crate::objects::{DEFAULT_ALGORITHM_ATTRIBUTES, DEFAULT_UIF, Slot};

/// Storage format version.
const FORMAT_VERSION: u8 = 0x01;

/// Number of key slots (SIG, DEC, AUT and the Yubico ATT slot).
pub(crate) const SLOTS: usize = 4;

/// Indexes into the retry counter arrays (order of C4 bytes 5-7, spec §4.4.3.6).
pub(crate) const PW1: usize = 0;
pub(crate) const RC: usize = 1;
pub(crate) const PW3: usize = 2;

/// Factory PINs (spec §4.3: PW1 `123456`, PW3 `12345678`).
pub(crate) const DEFAULT_PW1: &[u8] = b"123456";
pub(crate) const DEFAULT_PW3: &[u8] = b"12345678";
/// Factory retry counter (spec §4.3: three tries).
pub(crate) const DEFAULT_RETRIES: u8 = 3;
/// Factory sex 5F35: ISO 5218 `9`, "not applicable" (the value GnuPG writes for
/// "unspecified"). Not observed on the device; model policy.
pub(crate) const DEFAULT_SEX: u8 = 0x39;

// Top-level field tags (context-specific, primitive unless noted).
const T_TERMINATED: u32 = 0x80;
const T_PW1: u32 = 0x81;
const T_PW3: u32 = 0x82;
const T_RC: u32 = 0x83;
const T_RETRIES: u32 = 0x84;
const T_MAX_RETRIES: u32 = 0x85;
const T_PW1_MULTI: u32 = 0x86;
const T_KDF: u32 = 0x87;
const T_NAME: u32 = 0x88;
const T_LANGUAGE: u32 = 0x89;
const T_SEX: u32 = 0x8A;
const T_LOGIN: u32 = 0x8B;
const T_URL: u32 = 0x8C;
const T_PRIVATE: [u32; 4] = [0x8D, 0x8E, 0x8F, 0x90];
const T_SIGNATURE_COUNTER: u32 = 0x91;
/// Constructed slot records, SIG..ATT.
const T_SLOT: [u32; SLOTS] = [0xA0, 0xA1, 0xA2, 0xA3];

// Slot field tags.
const S_ATTRIBUTES: u32 = 0x80;
const S_FINGERPRINT: u32 = 0x81;
const S_CA_FINGERPRINT: u32 = 0x82;
const S_GENERATION_TIME: u32 = 0x83;
const S_UIF: u32 = 0x84;
const S_KEY_STATUS: u32 = 0x85;
const S_CERTIFICATE: u32 = 0x86;
/// Constructed: the slot's private key material (keys.rs storage encoding).
const S_KEY: u32 = 0xA7;

/// Per-slot data: attributes, fingerprints, generation time, UIF, key status, the private
/// key and the slot's certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SlotData {
    pub attributes: Vec<u8>,
    pub fingerprint: [u8; 20],
    pub ca_fingerprint: [u8; 20],
    pub generation_time: [u8; 4],
    pub uif: [u8; 2],
    /// DE status: 00 no key, 01 generated, 02 imported (spec §4.4.3.8).
    pub key_status: u8,
    /// The private key, if one was generated or imported (spec §7.2.14, §4.4.3.12).
    pub key: Option<KeyMaterial>,
    pub certificate: Vec<u8>,
    /// Unknown slot fields, written back unchanged.
    pub extra: Vec<u8>,
}

impl SlotData {
    fn factory() -> Self {
        Self {
            attributes: DEFAULT_ALGORITHM_ATTRIBUTES.to_vec(),
            fingerprint: [0; 20],
            ca_fingerprint: [0; 20],
            generation_time: [0; 4],
            uif: DEFAULT_UIF,
            key_status: 0,
            key: None,
            certificate: Vec::new(),
            extra: Vec::new(),
        }
    }

    /// Install a new key with its DE status (01 generated, 02 imported; spec §4.4.3.8).
    pub(crate) fn set_key(&mut self, key: KeyMaterial, status: u8) {
        self.key = Some(key);
        self.key_status = status;
    }

    /// Remove the key (spec §4.4.3.10: a key does not survive a change of its algorithm).
    pub(crate) fn clear_key(&mut self) {
        self.key = None;
        self.key_status = 0;
    }
}

/// Everything the application keeps across power cycles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct State {
    /// Life cycle: TERMINATE DF was executed and ACTIVATE FILE has not followed yet
    /// (spec §7.2.16-§7.2.17).
    pub terminated: bool,
    /// PW1 reference data (PIN bytes, or KDF hash).
    pub pw1: Vec<u8>,
    /// PW3 reference data.
    pub pw3: Vec<u8>,
    /// Resetting code reference data; `None` when not set (spec §4.3.4).
    pub rc: Option<Vec<u8>>,
    /// Remaining tries for PW1, RC, PW3 (C4 bytes 5-7).
    pub retries: [u8; 3],
    /// Tries restored after a successful verification (Yubico SET RETRIES).
    pub max_retries: [u8; 3],
    /// C4 byte 1: `true` = PW1 stays valid for several PSO:CDS (`01`), `false` = one (`00`).
    pub pw1_multi: bool,
    /// KDF-DO F9 contents as written by the host (spec §4.3.2).
    pub kdf: Vec<u8>,
    pub name: Vec<u8>,
    pub language: Vec<u8>,
    pub sex: u8,
    pub login: Vec<u8>,
    pub url: Vec<u8>,
    /// Private use DOs 0101-0104 (spec §4.4.1).
    pub private: [Vec<u8>; 4],
    /// Digital signature counter (spec §4.4.3.14).
    pub signature_counter: u32,
    pub slots: [SlotData; SLOTS],
    /// Unknown top-level fields, written back unchanged.
    pub extra: Vec<u8>,
}

impl State {
    /// Factory state (spec §4.3 defaults; observation defaults for attributes and UIF).
    pub(crate) fn factory() -> Self {
        Self {
            terminated: false,
            pw1: DEFAULT_PW1.to_vec(),
            pw3: DEFAULT_PW3.to_vec(),
            rc: None,
            retries: [DEFAULT_RETRIES, 0, DEFAULT_RETRIES],
            max_retries: [DEFAULT_RETRIES; 3],
            pw1_multi: true,
            kdf: kdf::KDF_NONE.to_vec(),
            name: Vec::new(),
            language: Vec::new(),
            sex: DEFAULT_SEX,
            login: Vec::new(),
            url: Vec::new(),
            private: Default::default(),
            signature_counter: 0,
            slots: [SlotData::factory(), SlotData::factory(), SlotData::factory(), SlotData::factory()],
            extra: Vec::new(),
        }
    }

    /// The state after ACTIVATE FILE of a terminated application: factory values, except
    /// that the attestation slot (its key, certificate, attributes, fingerprints,
    /// generation time and UIF) is retained, as the catalog's OpenPGP_attestation section
    /// requires ("app reset retains current independent ATT key/certificate").
    pub(crate) fn after_reset(&self) -> Self {
        let mut next = Self::factory();
        *next.slot_mut(Slot::Att) = self.slot(Slot::Att).clone();
        next
    }

    /// The parsed KDF-DO. The stored bytes were validated when written or loaded.
    pub(crate) fn kdf(&self) -> Kdf {
        Kdf::parse(&self.kdf).unwrap_or(Kdf::None)
    }

    pub(crate) fn slot(&self, slot: Slot) -> &SlotData {
        let [sig, dec, aut, att] = &self.slots;
        match slot {
            Slot::Sig => sig,
            Slot::Dec => dec,
            Slot::Aut => aut,
            Slot::Att => att,
        }
    }

    pub(crate) fn slot_mut(&mut self, slot: Slot) -> &mut SlotData {
        let [sig, dec, aut, att] = &mut self.slots;
        match slot {
            Slot::Sig => sig,
            Slot::Dec => dec,
            Slot::Aut => aut,
            Slot::Att => att,
        }
    }

    /// Serialize: version byte then BER-TLV fields.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![FORMAT_VERSION];
        tlv::encode_into(&mut out, T_TERMINATED, &[u8::from(self.terminated)]);
        tlv::encode_into(&mut out, T_PW1, &self.pw1);
        tlv::encode_into(&mut out, T_PW3, &self.pw3);
        if let Some(rc) = &self.rc {
            tlv::encode_into(&mut out, T_RC, rc);
        }
        tlv::encode_into(&mut out, T_RETRIES, &self.retries);
        tlv::encode_into(&mut out, T_MAX_RETRIES, &self.max_retries);
        tlv::encode_into(&mut out, T_PW1_MULTI, &[u8::from(self.pw1_multi)]);
        tlv::encode_into(&mut out, T_KDF, &self.kdf);
        tlv::encode_into(&mut out, T_NAME, &self.name);
        tlv::encode_into(&mut out, T_LANGUAGE, &self.language);
        tlv::encode_into(&mut out, T_SEX, &[self.sex]);
        tlv::encode_into(&mut out, T_LOGIN, &self.login);
        tlv::encode_into(&mut out, T_URL, &self.url);
        for (tag, value) in T_PRIVATE.iter().zip(self.private.iter()) {
            tlv::encode_into(&mut out, *tag, value);
        }
        tlv::encode_into(&mut out, T_SIGNATURE_COUNTER, &self.signature_counter.to_be_bytes());
        for (tag, slot) in T_SLOT.iter().zip(self.slots.iter()) {
            let mut inner = Vec::new();
            tlv::encode_into(&mut inner, S_ATTRIBUTES, &slot.attributes);
            tlv::encode_into(&mut inner, S_FINGERPRINT, &slot.fingerprint);
            tlv::encode_into(&mut inner, S_CA_FINGERPRINT, &slot.ca_fingerprint);
            tlv::encode_into(&mut inner, S_GENERATION_TIME, &slot.generation_time);
            tlv::encode_into(&mut inner, S_UIF, &slot.uif);
            tlv::encode_into(&mut inner, S_KEY_STATUS, &[slot.key_status]);
            if let Some(key) = &slot.key {
                tlv::encode_into(&mut inner, S_KEY, &key.to_storage());
            }
            tlv::encode_into(&mut inner, S_CERTIFICATE, &slot.certificate);
            inner.extend_from_slice(&slot.extra);
            tlv::encode_into(&mut out, *tag, &inner);
        }
        out.extend_from_slice(&self.extra);
        out
    }

    /// Parse stored bytes; `None` means unreadable (start from factory state).
    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (&version, body) = bytes.split_first()?;
        if version != FORMAT_VERSION {
            return None;
        }
        let fields = tlv::parse_all(body).ok()?;
        let mut state = Self::factory();
        let mut have_pw1 = false;
        let mut have_pw3 = false;
        let mut have_retries = false;
        state.rc = None;
        for field in fields {
            let v = field.value;
            match field.tag {
                T_TERMINATED => state.terminated = flag(v)?,
                T_PW1 => {
                    state.pw1 = password(v)?;
                    have_pw1 = true;
                }
                T_PW3 => {
                    state.pw3 = password(v)?;
                    have_pw3 = true;
                }
                T_RC => state.rc = Some(password(v)?),
                T_RETRIES => {
                    state.retries = v.try_into().ok()?;
                    have_retries = true;
                }
                T_MAX_RETRIES => {
                    let max: [u8; 3] = v.try_into().ok()?;
                    if max.contains(&0) {
                        return None;
                    }
                    state.max_retries = max;
                }
                T_PW1_MULTI => state.pw1_multi = flag(v)?,
                T_KDF => {
                    Kdf::parse(v).ok()?;
                    state.kdf = v.to_vec();
                }
                T_NAME => state.name = v.to_vec(),
                T_LANGUAGE => state.language = v.to_vec(),
                T_SEX => state.sex = single(v)?,
                T_LOGIN => state.login = v.to_vec(),
                T_URL => state.url = v.to_vec(),
                T_SIGNATURE_COUNTER => state.signature_counter = u32::from_be_bytes(v.try_into().ok()?),
                tag => {
                    if let Some(i) = T_PRIVATE.iter().position(|&t| t == tag) {
                        *state.private.get_mut(i)? = v.to_vec();
                    } else if let Some(i) = T_SLOT.iter().position(|&t| t == tag) {
                        *state.slots.get_mut(i)? = parse_slot(v)?;
                    } else {
                        state.extra.extend_from_slice(field.raw);
                    }
                }
            }
        }
        (have_pw1 && have_pw3 && have_retries).then_some(state)
    }
}

fn flag(v: &[u8]) -> Option<bool> {
    match v {
        [0] => Some(false),
        [1] => Some(true),
        _ => None,
    }
}

fn single(v: &[u8]) -> Option<u8> {
    match v {
        [b] => Some(*b),
        _ => None,
    }
}

/// A stored password reference must be non-empty and within the 127-byte maximum of C4.
fn password(v: &[u8]) -> Option<Vec<u8>> {
    (!v.is_empty() && v.len() <= 127).then(|| v.to_vec())
}

fn parse_slot(bytes: &[u8]) -> Option<SlotData> {
    let mut slot = SlotData::factory();
    for field in tlv::parse_all(bytes).ok()? {
        let v = field.value;
        match field.tag {
            S_ATTRIBUTES => slot.attributes = v.to_vec(),
            S_FINGERPRINT => slot.fingerprint = v.try_into().ok()?,
            S_CA_FINGERPRINT => slot.ca_fingerprint = v.try_into().ok()?,
            S_GENERATION_TIME => slot.generation_time = v.try_into().ok()?,
            S_UIF => slot.uif = v.try_into().ok()?,
            S_KEY_STATUS => slot.key_status = single(v)?,
            S_KEY => slot.key = Some(KeyMaterial::from_storage(v)?),
            S_CERTIFICATE => slot.certificate = v.to_vec(),
            _ => slot.extra.extend_from_slice(field.raw),
        }
    }
    if slot.key.is_none() {
        // DE reports a key only when one is present.
        slot.key_status = 0;
    }
    Some(slot)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn factory_roundtrip() {
        // docs/CONTRACTS.md "Persisted state": version 0x01 then BER-TLV.
        let state = State::factory();
        let bytes = state.to_bytes();
        assert_eq!(bytes[0], 0x01);
        assert_eq!(State::from_bytes(&bytes), Some(state));
    }

    #[test]
    fn modified_roundtrip_and_unknown_fields_kept() {
        let mut state = State::factory();
        state.rc = Some(b"resetcode".to_vec());
        state.retries = [1, 2, 0];
        state.name = b"Doe<<John".to_vec();
        state.private[2] = vec![9; 255];
        state.slots[3].certificate = vec![0x30; 2048];
        state.slots[1].fingerprint = [7; 20];
        let mut bytes = state.to_bytes();
        // An unknown field from a later format version (docs/DESIGN.md §7: unknown tags kept).
        bytes.extend_from_slice(&[0x9F, 0x40, 0x02, 0xAB, 0xCD]);
        let loaded = State::from_bytes(&bytes).unwrap();
        assert_eq!(loaded.extra, vec![0x9F, 0x40, 0x02, 0xAB, 0xCD]);
        assert_eq!(loaded.to_bytes(), bytes);
        let mut expected = state;
        expected.extra = loaded.extra.clone();
        assert_eq!(loaded, expected);
    }

    #[test]
    fn unreadable_states() {
        assert_eq!(State::from_bytes(&[]), None);
        assert_eq!(State::from_bytes(&[0x02]), None);
        // Version only: no password fields.
        assert_eq!(State::from_bytes(&[0x01]), None);
        // Truncated TLV.
        let mut bytes = State::factory().to_bytes();
        bytes.truncate(bytes.len() - 1);
        assert_eq!(State::from_bytes(&bytes), None);
        // Empty PW1 reference.
        let mut bad = vec![0x01];
        tlv::encode_into(&mut bad, T_PW1, &[]);
        tlv::encode_into(&mut bad, T_PW3, b"12345678");
        tlv::encode_into(&mut bad, T_RETRIES, &[3, 0, 3]);
        assert_eq!(State::from_bytes(&bad), None);
    }

    /// Fixed-seed pseudo-random input (docs/DESIGN.md §12-4): random buffers and damaged
    /// copies of a full state never panic the parser, and whatever parses round-trips.
    #[test]
    fn random_bytes_never_panic_the_parser() {
        let mut rng = lk_testkit::SeededEntropy::new(0x5041_5253);
        let mut below = |n: usize| usize::from(u16::from_be_bytes(rng.bytes(2).try_into().unwrap())) % n;
        let mut full = State::factory();
        full.slots[0].key = Some(KeyMaterial::Ec { curve: lk_crypto::Curve::P256, scalar: vec![5; 32] });
        full.slots[0].key_status = 1;
        full.slots[3].key = Some(KeyMaterial::Rsa { p: vec![7; 128], q: vec![9; 128], e: vec![1, 0, 1] });
        full.slots[3].certificate = vec![0x30; 300];
        full.rc = Some(b"resetcode".to_vec());
        let base = full.to_bytes();
        let mut entropy = lk_testkit::SeededEntropy::new(0x4D55_5441);
        let mut parsed = 0;
        for i in 0..5000 {
            let bytes = if i % 3 == 0 {
                let mut bytes = entropy.bytes(below(300));
                if let Some(first) = bytes.first_mut() {
                    *first = FORMAT_VERSION;
                }
                bytes
            } else {
                let mut bytes = base.clone();
                match below(3) {
                    0 => {
                        for _ in 0..1 + below(4) {
                            let at = below(bytes.len());
                            bytes[at] = entropy.bytes(1)[0];
                        }
                    }
                    1 => bytes.truncate(below(bytes.len())),
                    _ => {
                        let at = below(bytes.len());
                        bytes.insert(at, entropy.bytes(1)[0]);
                    }
                }
                bytes
            };
            if let Some(state) = State::from_bytes(&bytes) {
                parsed += 1;
                assert_eq!(State::from_bytes(&state.to_bytes()), Some(state));
            }
        }
        assert!(parsed > 100, "too few readable mutations: {parsed}");
    }

    #[test]
    fn key_material_roundtrip_and_status() {
        let mut state = State::factory();
        state.slots[1].set_key(KeyMaterial::X25519 { secret: vec![3; 32] }, 2);
        let loaded = State::from_bytes(&state.to_bytes()).unwrap();
        assert_eq!(loaded, state);
        // DE reports a key only when one is stored.
        let mut orphan = State::factory();
        orphan.slots[2].key_status = 1;
        assert_eq!(State::from_bytes(&orphan.to_bytes()).unwrap().slots[2].key_status, 0);
        // Malformed key material makes the state unreadable.
        let mut bad = State::factory().to_bytes();
        let mut slot = Vec::new();
        tlv::encode_into(&mut slot, S_KEY, &[0x80, 0x01, 0x07]);
        tlv::encode_into(&mut bad, T_SLOT[0], &slot);
        assert_eq!(State::from_bytes(&bad), None);
    }

    #[test]
    fn reset_keeps_attestation_slot_only() {
        let mut state = State::factory();
        state.name = b"x".to_vec();
        state.slots[0].fingerprint = [1; 20];
        state.slots[3].certificate = vec![1, 2, 3];
        state.slots[3].uif = [0x02, 0x20];
        state.slots[3].set_key(KeyMaterial::Ed25519 { seed: vec![1; 32] }, 1);
        state.slots[0].set_key(KeyMaterial::Ed25519 { seed: vec![2; 32] }, 1);
        state.terminated = true;
        let next = state.after_reset();
        assert!(!next.terminated);
        assert!(next.name.is_empty());
        assert_eq!(next.slots[0], SlotData::factory());
        assert_eq!(next.slots[3], state.slots[3]);
    }
}
