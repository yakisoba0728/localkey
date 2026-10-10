//! Persisted PIV state and its storage format.
//!
//! Format (`docs/CONTRACTS.md` "Rules for every crate", `docs/DESIGN.md` §7): version
//! byte `0x01`, then BER-TLV fields (ISO/IEC 7816-4 §5.2.2, via `lk_codec::tlv`):
//!
//! | Tag | Field |
//! | --- | --- |
//! | `01` | PIN reference data, 8 bytes padded with `FF` (SP 800-73-4 Part 2 §2.4.3) |
//! | `02` / `03` | PIN retry limit / retries remaining (1 byte each) |
//! | `04` | PUK reference data, 8 bytes |
//! | `05` / `06` | PUK retry limit / retries remaining |
//! | `07` | management key algorithm (SP 800-78-4 Table 6-1: `03`, `08`, `0A`, `0C`) |
//! | `08` | management key bytes |
//! | `09` | management key touch flag (`00` never, `01` always) |
//! | `0A` | attestation initialized (`01`); absent in records written before stage 2 |
//! | `70` | one data object: `01` tag bytes, `02` value (the contents of tag `53`) |
//! | `71` | one key slot: `01` slot id, `02` key record (`keys::SlotKey::encode`) |
//!
//! Unknown top-level fields are kept verbatim and written back after the known ones, so
//! a record written by a newer version survives a round trip through this one (§7:
//! "모르는 태그는 보존한다"). A record that is not version `0x01`, does not parse, or holds
//! inconsistent values is unreadable, and the applet starts from its factory state.
//!
//! Secrets (PIN and PUK reference data, the management key, slot private keys) are held
//! in `lk_crypto::SecretBytes`, which wipes them when dropped (`docs/DESIGN.md` §8: "비밀
//! 버퍼는 zeroize로 처리한다"). Every commit works on a copy of the state, so the copy it
//! replaces is wiped too. [`PivState::encode`] sizes its buffer up front so that building
//! the record never reallocates and leaves no unwiped partial copies behind; the caller
//! wraps the result in `SecretBytes`.

use std::collections::BTreeMap;
use std::fmt;

use lk_codec::tlv;
use lk_crypto::SecretBytes;

use crate::keys::SlotKey;
use crate::objects::{self, ObjectStore};

/// Storage format version (`docs/CONTRACTS.md`).
pub(crate) const FORMAT_VERSION: u8 = 0x01;

/// Factory PIN `123456`, padded to 8 bytes with `FF` (SP 800-73-4 Part 2 §2.4.3; Yubico
/// PIV documentation, "Default values").
pub(crate) const DEFAULT_PIN: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF];

/// Factory PUK `12345678` (Yubico PIV documentation, "Default values").
pub(crate) const DEFAULT_PUK: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];

/// Factory management key `010203040506070801020304050607080102030405060708`. From
/// firmware 5.7 it is an AES-192 key (Yubico PIV documentation, "Default values";
/// earlier firmware used the same bytes as a 3DES key).
pub(crate) const DEFAULT_MGMT_KEY: [u8; 24] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];

/// Factory PIN and PUK retry limit (Yubico PIV documentation, "Default values").
pub(crate) const DEFAULT_RETRIES: u8 = 3;

/// Slot holding the vendor attestation key (Yubico PIV attestation documentation).
pub(crate) const SLOT_ATTESTATION: u8 = 0xF9;

/// Upper bound on the header bytes of one BER-TLV element: a tag of up to 3 bytes and a
/// length of up to 4 (`lk_codec::tlv`).
pub(crate) const TLV_OVERHEAD: usize = 7;

const T_PIN: u32 = 0x01;
const T_PIN_MAX: u32 = 0x02;
const T_PIN_LEFT: u32 = 0x03;
const T_PUK: u32 = 0x04;
const T_PUK_MAX: u32 = 0x05;
const T_PUK_LEFT: u32 = 0x06;
const T_MGMT_ALG: u32 = 0x07;
const T_MGMT_KEY: u32 = 0x08;
const T_MGMT_TOUCH: u32 = 0x09;
const T_ATTESTATION_INIT: u32 = 0x0A;
const T_OBJECT: u32 = 0x70;
const T_SLOT: u32 = 0x71;
const T_ENTRY_ID: u32 = 0x01;
const T_ENTRY_VALUE: u32 = 0x02;

/// Management key algorithms (SP 800-78-4 Table 6-1 for 3DES and AES; the algorithm
/// identifier is P1 of GENERAL AUTHENTICATE, SP 800-73-4 Part 2 §3.2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MgmtAlg {
    /// `03`: three-key 3DES (TDEA), 24-byte key, 8-byte blocks.
    Tdes,
    /// `08`: AES-128.
    Aes128,
    /// `0A`: AES-192.
    Aes192,
    /// `0C`: AES-256.
    Aes256,
}

impl MgmtAlg {
    /// The algorithm for an identifier byte, if it is a symmetric management key one.
    pub(crate) fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x03 => Some(Self::Tdes),
            0x08 => Some(Self::Aes128),
            0x0A => Some(Self::Aes192),
            0x0C => Some(Self::Aes256),
            _ => None,
        }
    }

    /// The identifier byte (SP 800-78-4 Table 6-1).
    pub(crate) fn byte(self) -> u8 {
        match self {
            Self::Tdes => 0x03,
            Self::Aes128 => 0x08,
            Self::Aes192 => 0x0A,
            Self::Aes256 => 0x0C,
        }
    }

    /// Key length in bytes.
    pub(crate) fn key_len(self) -> usize {
        match self {
            Self::Tdes | Self::Aes192 => 24,
            Self::Aes128 => 16,
            Self::Aes256 => 32,
        }
    }

    /// Cipher block length, which is also the witness/challenge length of the
    /// authentication protocol (SP 800-73-4 Part 2 Appendix A).
    pub(crate) fn block_len(self) -> usize {
        match self {
            Self::Tdes => 8,
            _ => 16,
        }
    }
}

/// A PIN or PUK: its padded reference data and retry counters.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Credential {
    /// Reference data, 8 bytes padded with `FF` (SP 800-73-4 Part 2 §2.4.3).
    pub(crate) value: SecretBytes,
    /// Retry limit, 1..=255 (Yubico SET PIN RETRIES; profile `retry_limits`).
    pub(crate) max: u8,
    /// Retries remaining, 0..=max; 0 means blocked.
    pub(crate) remaining: u8,
}

impl Credential {
    pub(crate) fn new(value: [u8; 8], max: u8) -> Self {
        Self { value: SecretBytes::from_slice(&value), max, remaining: max }
    }

    /// Whether the retry counter is exhausted.
    pub(crate) fn blocked(&self) -> bool {
        self.remaining == 0
    }
}

/// The card management key (SP 800-73-4 Part 1 §3.5, key reference `9B`).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct MgmtKey {
    pub(crate) alg: MgmtAlg,
    pub(crate) key: SecretBytes,
    /// Touch required to complete authentication (Yubico SET MANAGEMENT KEY, P2 `FE`).
    pub(crate) touch: bool,
}

/// Everything the PIV applet persists in `Record::Piv`.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PivState {
    pub(crate) pin: Credential,
    pub(crate) puk: Credential,
    pub(crate) mgmt: MgmtKey,
    pub(crate) objects: ObjectStore,
    /// Key slots by slot id (`9A`, `9C`, `9D`, `9E`, `82..=95`, `F9`).
    pub(crate) slots: BTreeMap<u8, SlotKey>,
    /// Whether the own attestation key and certificate were created
    /// (`attest::initialize`); once set, they are never created again.
    pub(crate) attestation_initialized: bool,
    /// Unknown top-level TLV fields, kept verbatim.
    pub(crate) unknown: Vec<Vec<u8>>,
}

impl fmt::Debug for PivState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Reference data and keys are secrets; only counters and sizes are shown.
        f.debug_struct("PivState")
            .field("pin_retries", &(self.pin.remaining, self.pin.max))
            .field("puk_retries", &(self.puk.remaining, self.puk.max))
            .field("mgmt_alg", &self.mgmt.alg)
            .field("mgmt_touch", &self.mgmt.touch)
            .field("objects", &self.objects.len())
            .field("object_bytes", &self.objects.total())
            .field("slots", &self.slots)
            .field("attestation_initialized", &self.attestation_initialized)
            .field("unknown_fields", &self.unknown.len())
            .finish()
    }
}

impl PivState {
    /// Factory state: default PIN, PUK and AES-192 management key, three retries each,
    /// no data objects and no keys. `Piv::new` then adds the own attestation key and
    /// certificate (`attest::initialize`).
    pub(crate) fn factory() -> Self {
        Self {
            pin: Credential::new(DEFAULT_PIN, DEFAULT_RETRIES),
            puk: Credential::new(DEFAULT_PUK, DEFAULT_RETRIES),
            mgmt: MgmtKey { alg: MgmtAlg::Aes192, key: SecretBytes::from_slice(&DEFAULT_MGMT_KEY), touch: false },
            objects: ObjectStore::default(),
            slots: BTreeMap::new(),
            attestation_initialized: false,
            unknown: Vec::new(),
        }
    }

    /// The state after Yubico PIV RESET (`FB`): factory credentials and management key,
    /// no data objects or keys, except the attestation key and certificate, which
    /// survive the reset (catalog: "F9 key/certificate retained through PIV reset";
    /// profile `piv_reset_preserves_current_f9_key_and_certificate`). The initialization
    /// marker survives too, so a deleted `F9` key or certificate stays deleted (catalog
    /// "deleted certificate is not regenerated").
    pub(crate) fn after_reset(&self) -> Self {
        let mut next = Self::factory();
        next.attestation_initialized = self.attestation_initialized;
        if let Some(cert) = self.objects.get(objects::TAG_ATTESTATION) {
            next.objects.put(objects::TAG_ATTESTATION, cert.to_vec());
        }
        if let Some(key) = self.slots.get(&SLOT_ATTESTATION) {
            next.slots.insert(SLOT_ATTESTATION, key.clone());
        }
        next
    }

    /// Serialize to the storage format. The result holds every secret of the applet; the
    /// caller wraps it in `SecretBytes` (module documentation).
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len_bound());
        out.push(FORMAT_VERSION);
        tlv::encode_into(&mut out, T_PIN, &self.pin.value);
        tlv::encode_into(&mut out, T_PIN_MAX, &[self.pin.max]);
        tlv::encode_into(&mut out, T_PIN_LEFT, &[self.pin.remaining]);
        tlv::encode_into(&mut out, T_PUK, &self.puk.value);
        tlv::encode_into(&mut out, T_PUK_MAX, &[self.puk.max]);
        tlv::encode_into(&mut out, T_PUK_LEFT, &[self.puk.remaining]);
        tlv::encode_into(&mut out, T_MGMT_ALG, &[self.mgmt.alg.byte()]);
        tlv::encode_into(&mut out, T_MGMT_KEY, &self.mgmt.key);
        tlv::encode_into(&mut out, T_MGMT_TOUCH, &[u8::from(self.mgmt.touch)]);
        if self.attestation_initialized {
            tlv::encode_into(&mut out, T_ATTESTATION_INIT, &[0x01]);
        }
        for (tag, value) in self.objects.iter() {
            let mut entry = tlv::encode(T_ENTRY_ID, &tlv::encode_tag(tag));
            tlv::encode_into(&mut entry, T_ENTRY_VALUE, value);
            tlv::encode_into(&mut out, T_OBJECT, &entry);
        }
        for (slot, key) in &self.slots {
            let record = SecretBytes::new(key.encode());
            let mut entry = Vec::with_capacity(record.len() + 2 * TLV_OVERHEAD + 1);
            tlv::encode_into(&mut entry, T_ENTRY_ID, &[*slot]);
            tlv::encode_into(&mut entry, T_ENTRY_VALUE, &record);
            let entry = SecretBytes::new(entry);
            tlv::encode_into(&mut out, T_SLOT, &entry);
        }
        for raw in &self.unknown {
            out.extend_from_slice(raw);
        }
        out
    }

    /// An upper bound on the length of [`encode`](Self::encode)'s result, so its buffer
    /// never reallocates: every element is counted with [`TLV_OVERHEAD`].
    fn encoded_len_bound(&self) -> usize {
        let fixed = 1 + 10 * TLV_OVERHEAD + 2 * 8 + 6 + 1 + self.mgmt.key.len() + 2;
        let objects: usize = self.objects.iter().map(|(_, value)| 3 * TLV_OVERHEAD + 3 + value.len()).sum();
        let slots: usize = self.slots.values().map(|key| 3 * TLV_OVERHEAD + 1 + key.encoded_len_bound()).sum();
        let unknown: usize = self.unknown.iter().map(Vec::len).sum();
        fixed + objects + slots + unknown
    }

    /// Parse the storage format; `None` if the bytes are unreadable.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let (&version, body) = bytes.split_first()?;
        if version != FORMAT_VERSION {
            return None;
        }
        let mut pin = None;
        let mut pin_max = None;
        let mut pin_left = None;
        let mut puk = None;
        let mut puk_max = None;
        let mut puk_left = None;
        let mut alg = None;
        let mut key = None;
        let mut touch = None;
        let mut attestation_initialized = false;
        let mut objects = ObjectStore::default();
        let mut slots = BTreeMap::new();
        let mut unknown = Vec::new();
        for field in tlv::parse_all(body).ok()? {
            match field.tag {
                T_PIN => pin = Some(reference(field.value)?),
                T_PIN_MAX => pin_max = Some(single(field.value)?),
                T_PIN_LEFT => pin_left = Some(single(field.value)?),
                T_PUK => puk = Some(reference(field.value)?),
                T_PUK_MAX => puk_max = Some(single(field.value)?),
                T_PUK_LEFT => puk_left = Some(single(field.value)?),
                T_MGMT_ALG => alg = Some(MgmtAlg::from_byte(single(field.value)?)?),
                T_MGMT_KEY => key = Some(SecretBytes::from_slice(field.value)),
                T_MGMT_TOUCH => {
                    touch = Some(match single(field.value)? {
                        0 => false,
                        1 => true,
                        _ => return None,
                    })
                }
                T_ATTESTATION_INIT => {
                    attestation_initialized = match single(field.value)? {
                        0 => false,
                        1 => true,
                        _ => return None,
                    }
                }
                T_OBJECT => {
                    let (id, value) = entry(field.value)?;
                    let tag = objects::stored_tag(id)?;
                    if value.is_empty() || value.len() > objects::MAX_APDU_DATA {
                        return None;
                    }
                    objects.put(tag, value.to_vec());
                }
                T_SLOT => {
                    let (id, record) = entry(field.value)?;
                    let slot = single(id)?;
                    if !is_key_slot(slot) {
                        return None;
                    }
                    slots.insert(slot, SlotKey::decode(record)?);
                }
                _ => unknown.push(field.raw.to_vec()),
            }
        }
        let pin = credential(pin?, pin_max?, pin_left?)?;
        let puk = credential(puk?, puk_max?, puk_left?)?;
        let alg = alg?;
        let key = key?;
        if key.len() != alg.key_len() {
            return None;
        }
        Some(Self {
            pin,
            puk,
            mgmt: MgmtKey { alg, key, touch: touch? },
            objects,
            slots,
            attestation_initialized,
            unknown,
        })
    }
}

/// Whether `slot` names a PIV key slot: `9A`, `9C`, `9D`, `9E` (SP 800-73-4 Part 1
/// §3.1), the retired key management slots `82..=95` (§3.1.3) or the Yubico attestation
/// slot `F9`.
pub(crate) fn is_key_slot(slot: u8) -> bool {
    matches!(slot, 0x9A | 0x9C | 0x9D | 0x9E | 0x82..=0x95 | SLOT_ATTESTATION)
}

fn single(value: &[u8]) -> Option<u8> {
    match value {
        [b] => Some(*b),
        _ => None,
    }
}

/// Split a `70`/`71` entry into its `01` id and `02` value.
fn entry(value: &[u8]) -> Option<(&[u8], &[u8])> {
    match tlv::parse_all(value).ok()?.as_slice() {
        [id, val] if id.tag == T_ENTRY_ID && val.tag == T_ENTRY_VALUE => Some((id.value, val.value)),
        _ => None,
    }
}

/// Stored PIN or PUK reference data: exactly 8 bytes.
fn reference(value: &[u8]) -> Option<SecretBytes> {
    (value.len() == 8).then(|| SecretBytes::from_slice(value))
}

fn credential(value: SecretBytes, max: u8, remaining: u8) -> Option<Credential> {
    (max >= 1 && remaining <= max).then_some(Credential { value, max, remaining })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::keys::{KeyAlg, PinPolicy, Private, TouchPolicy};

    /// A structurally valid slot key record (only lengths are checked on load).
    fn p256_key(fill: u8) -> SlotKey {
        let mut public = vec![0x04];
        public.extend_from_slice(&[fill; 64]);
        SlotKey {
            alg: KeyAlg::P256,
            pin: PinPolicy::Once,
            touch: TouchPolicy::Cached,
            origin: crate::keys::Origin::Imported,
            private: Private::Bytes(vec![fill; 32].into()),
            public,
        }
    }

    #[test]
    fn factory_round_trips() {
        let state = PivState::factory();
        let bytes = state.encode();
        assert_eq!(bytes[0], FORMAT_VERSION);
        assert_eq!(PivState::decode(&bytes), Some(state));
    }

    #[test]
    fn populated_state_round_trips_and_keeps_unknown_fields() {
        let mut state = PivState::factory();
        state.pin.remaining = 1;
        state.puk.max = 255;
        state.mgmt = MgmtKey { alg: MgmtAlg::Aes256, key: vec![7; 32].into(), touch: true };
        state.objects.put(0x5FC102, vec![0xAA; 300]);
        state.objects.put(0x5FFF01, vec![0xBB; 3000]);
        state.slots.insert(0x9A, p256_key(1));
        state.attestation_initialized = true;
        let mut bytes = state.encode();
        // A field from a hypothetical newer version (tag 0x5F20 is unused here).
        bytes.extend_from_slice(&[0x5F, 0x20, 0x02, 0xCA, 0xFE]);
        let decoded = PivState::decode(&bytes).unwrap();
        assert_eq!(decoded.unknown, vec![vec![0x5F, 0x20, 0x02, 0xCA, 0xFE]]);
        assert_eq!(decoded.encode(), bytes);
        let mut expected = state;
        expected.unknown = decoded.unknown.clone();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn encoding_fits_its_preallocated_buffer() {
        // `encode` must never reallocate: a reallocation would leave an unwiped copy of
        // the secrets behind (module documentation).
        let mut state = PivState::factory();
        assert!(state.encode().len() <= state.encoded_len_bound());
        state.mgmt = MgmtKey { alg: MgmtAlg::Aes256, key: vec![7; 32].into(), touch: true };
        state.objects.put(0x5FC102, vec![0xAA; 300]);
        state.objects.put(0x5FFF01, vec![0xBB; 3000]);
        state.objects.put(0x5FC10D, vec![0xCC; 70_000]);
        state.attestation_initialized = true;
        for slot in [0x9A, 0x9C, 0x9D, 0x9E, 0x82, 0x95, SLOT_ATTESTATION] {
            state.slots.insert(slot, p256_key(slot));
        }
        let mut rsa = p256_key(9);
        rsa.alg = KeyAlg::Rsa4096;
        rsa.private = Private::Rsa { p: vec![0xD1; 256].into(), q: vec![0xD2; 256].into() };
        rsa.public = vec![0xD3; 512];
        assert!(rsa.encode().len() <= rsa.encoded_len_bound());
        state.slots.insert(0x83, rsa);
        state.unknown.push(vec![0x5F, 0x20, 0x02, 0xCA, 0xFE]);
        let bytes = state.encode();
        assert!(bytes.len() <= state.encoded_len_bound(), "{} > {}", bytes.len(), state.encoded_len_bound());
        for key in state.slots.values() {
            assert!(key.encode().len() <= key.encoded_len_bound());
        }
    }

    #[test]
    fn rejects_unreadable_records() {
        let good = PivState::factory().encode();
        assert!(PivState::decode(&[]).is_none());
        assert!(PivState::decode(&[0x02]).is_none(), "wrong version");
        let mut truncated = good.clone();
        truncated.pop();
        assert!(PivState::decode(&truncated).is_none());
        // Missing PIN field: drop the leading 01 08 .. TLV.
        let mut missing = vec![FORMAT_VERSION];
        missing.extend_from_slice(&good[11..]);
        assert!(PivState::decode(&missing).is_none());
        // Remaining retries above the limit.
        let mut state = PivState::factory();
        state.pin.remaining = 4;
        assert!(PivState::decode(&state.encode()).is_none());
        // Zero retry limit.
        let mut state = PivState::factory();
        state.puk.max = 0;
        state.puk.remaining = 0;
        assert!(PivState::decode(&state.encode()).is_none());
        // Key length that does not match the algorithm.
        let mut state = PivState::factory();
        state.mgmt.key = vec![0; 16].into();
        assert!(PivState::decode(&state.encode()).is_none());
        // A slot key record with a wrong length.
        let mut state = PivState::factory();
        let mut key = p256_key(2);
        key.public.pop();
        state.slots.insert(0x9C, key);
        assert!(PivState::decode(&state.encode()).is_none());
        // A slot entry for a reference that is not a key slot.
        let mut state = PivState::factory();
        state.slots.insert(0x9B, p256_key(3));
        assert!(PivState::decode(&state.encode()).is_none());
    }

    #[test]
    fn stage_one_records_read_back_uninitialized() {
        // Records written before the attestation marker existed are readable and report
        // the attestation material as not yet initialized.
        let state = PivState::factory();
        let decoded = PivState::decode(&state.encode()).unwrap();
        assert!(!decoded.attestation_initialized);
    }

    #[test]
    fn reset_keeps_only_attestation_material() {
        let mut state = PivState::factory();
        state.pin.remaining = 0;
        state.puk.remaining = 0;
        state.objects.put(0x5FC105, vec![1; 10]);
        state.objects.put(objects::TAG_ATTESTATION, vec![2; 10]);
        state.slots.insert(0x9A, p256_key(3));
        state.slots.insert(SLOT_ATTESTATION, p256_key(4));
        state.attestation_initialized = true;
        state.unknown.push(vec![0x5F, 0x20, 0x00]);
        let next = state.after_reset();
        assert!(next.pin == PivState::factory().pin);
        assert_eq!(next.objects.get(0x5FC105), None);
        assert_eq!(next.objects.get(objects::TAG_ATTESTATION), Some(&[2u8; 10][..]));
        assert_eq!(next.slots.get(&0x9A), None);
        assert!(next.slots.get(&SLOT_ATTESTATION) == Some(&p256_key(4)));
        assert!(next.attestation_initialized, "the F9 initialization never runs again");
        assert!(next.unknown.is_empty());
    }
}
