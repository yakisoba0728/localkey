//! Persistent FIDO state (`Record::Fido`) and its serialization.
//!
//! Format (`docs/CONTRACTS.md`, persisted state; `docs/DESIGN.md` §7): version byte `0x01`
//! followed by BER-TLV objects (ISO/IEC 7816-4 §5.2, `lk_codec::tlv`):
//!
//! | Tag | Content |
//! | --- | --- |
//! | `81` | credential wrapping secret (32) |
//! | `82` | attestation private scalar (32) |
//! | `83` | attestation certificate (DER) |
//! | `84` | attestation root certificate (DER) |
//! | `85` | AAGUID the certificate was issued for (16) |
//! | `86` | common name the certificate was issued for (UTF-8) |
//! | `87` | global signature counter (4, big-endian) |
//! | `88` | PIN hash, `LEFT(SHA-256(pin), 16)` (CTAP 2.1 §6.5 setPIN); absent when no PIN is set |
//! | `89` | PIN retries remaining (1) |
//! | `8A` | minimum PIN length in code points (1) |
//! | `8B` | forcePINChange (1) |
//! | `8C` | alwaysUv (1) |
//! | `8D` | PIN length in Unicode code points (1), present with `88` (CTAP 2.1 §6.11.4: a new minimum above it forces a PIN change) |
//! | `8E` | serialized large-blob array (CTAP 2.1 §6.10); absent means the initial empty array |
//! | `A1` | minPinLengthRPIDs: one `80` (UTF-8 RP ID) per entry |
//! | `A2` | one discoverable credential (repeated, oldest first), see [`Resident`] |
//!
//! Top-level objects with other tags are kept and written back unchanged, so a newer
//! format's additions survive a round trip through this version (`docs/DESIGN.md` §7).
//! Anything that cannot be parsed, or a known field with an invalid value, makes the whole
//! record unreadable: the authenticator then starts from its factory state
//! (`lk_core::CardApplet` constructor convention).

use lk_codec::tlv;
use lk_crypto::sha256;

use crate::attestation::Attestation;

const FORMAT_VERSION: u8 = 0x01;

const TAG_SECRET: u32 = 0x81;
const TAG_ATT_SCALAR: u32 = 0x82;
const TAG_ATT_CERT: u32 = 0x83;
const TAG_ATT_ROOT: u32 = 0x84;
const TAG_ATT_AAGUID: u32 = 0x85;
const TAG_ATT_CN: u32 = 0x86;
const TAG_COUNTER: u32 = 0x87;
const TAG_PIN_HASH: u32 = 0x88;
const TAG_PIN_RETRIES: u32 = 0x89;
const TAG_MIN_PIN_LENGTH: u32 = 0x8A;
const TAG_FORCE_PIN_CHANGE: u32 = 0x8B;
const TAG_ALWAYS_UV: u32 = 0x8C;
const TAG_PIN_CODE_POINTS: u32 = 0x8D;
const TAG_LARGE_BLOB: u32 = 0x8E;
const TAG_MIN_PIN_RP_IDS: u32 = 0xA1;
const TAG_RESIDENT: u32 = 0xA2;

// Inside TAG_MIN_PIN_RP_IDS.
const TAG_RP_ID_ENTRY: u32 = 0x80;

// Inside TAG_RESIDENT.
const R_ID: u32 = 0x80;
const R_RP_ID: u32 = 0x81;
const R_USER_ID: u32 = 0x82;
const R_USER_NAME: u32 = 0x83;
const R_DISPLAY_NAME: u32 = 0x84;
const R_CRED_BLOB: u32 = 0x85;
const R_LARGE_BLOB_KEY: u32 = 0x86;
const R_CRED_PROTECT: u32 = 0x87;

/// Factory PIN retry counter (CTAP 2.1 §6.5: the pinRetries counter starts at its maximum, 8).
pub(crate) const DEFAULT_PIN_RETRIES: u8 = 8;
/// Factory minimum PIN length (CTAP 2.1 §6.4 `minPINLength`, default 4; GetInfo key 13 of
/// `reference/yubikey-5c-nano-5.7.4/reference-observation.json`).
pub(crate) const DEFAULT_MIN_PIN_LENGTH: u8 = 4;

/// The initial serialized large-blob array: the CBOR empty array `80` followed by
/// `LEFT(SHA-256(80), 16)` (CTAP 2.1 §6.10.2, "initial serialized large-blob array").
pub(crate) const INITIAL_LARGE_BLOB: [u8; 17] = [
    0x80, 0x76, 0xbe, 0x8b, 0x52, 0x8d, 0x00, 0x75, 0xf7, 0xaa, 0xe9, 0x8d, 0x6f, 0xa5, 0x7a, 0x6d,
    0x3c,
];

/// PIN and configuration state (CTAP 2.1 §6.5 authenticatorClientPIN, §6.11
/// authenticatorConfig).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PinState {
    /// `LEFT(SHA-256(PIN), 16)`, the "CurrentStoredPIN" of §6.5.5.5.
    pub hash: Option<[u8; 16]>,
    /// Length of the current PIN in Unicode code points (0 without a PIN).
    pub code_points: u8,
    /// pinRetries (§6.5.2.2), persisted before any response that reveals it.
    pub retries: u8,
    pub min_length: u8,
    pub force_change: bool,
    pub always_uv: bool,
    pub min_pin_rp_ids: Vec<String>,
}

impl Default for PinState {
    fn default() -> Self {
        Self {
            hash: None,
            code_points: 0,
            retries: DEFAULT_PIN_RETRIES,
            min_length: DEFAULT_MIN_PIN_LENGTH,
            force_change: false,
            always_uv: false,
            min_pin_rp_ids: Vec::new(),
        }
    }
}

/// A discoverable credential (CTAP 2.1 §6.1.2 step 17). Its private key lives inside the
/// wrapped `id` (see `credential`); the row holds what the ID cannot: the RP and user
/// identities and the per-credential extension data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Resident {
    pub id: Vec<u8>,
    pub rp_id: String,
    /// SHA-256 of `rp_id`, derived on load.
    pub rp_id_hash: [u8; 32],
    pub user_id: Vec<u8>,
    pub user_name: Option<String>,
    pub display_name: Option<String>,
    /// credBlob (CTAP 2.1 §12.2).
    pub cred_blob: Option<Vec<u8>>,
    /// largeBlobKey (CTAP 2.1 §12.3).
    pub large_blob_key: Option<[u8; 32]>,
    /// credProtect level (CTAP 2.1 §12.1), duplicated from the ID for filtering.
    pub cred_protect: u8,
}

/// Everything the FIDO application persists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct State {
    /// Credential wrapping secret; generated on first use, rotated by reset.
    pub secret: Option<[u8; 32]>,
    /// Attestation key and certificate; generated on first use.
    pub attestation: Option<Attestation>,
    /// Global signature counter shared by every credential and U2F.
    pub counter: u32,
    pub pin: PinState,
    /// Discoverable credentials, oldest first.
    pub residents: Vec<Resident>,
    /// The serialized large-blob array (CTAP 2.1 §6.10).
    pub large_blob: Vec<u8>,
    /// Unknown top-level TLV objects, written back unchanged.
    pub unknown: Vec<Vec<u8>>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            secret: None,
            attestation: None,
            counter: 0,
            pin: PinState::default(),
            residents: Vec::new(),
            large_blob: INITIAL_LARGE_BLOB.to_vec(),
            unknown: Vec::new(),
        }
    }
}

impl State {
    pub(crate) fn pin_is_set(&self) -> bool {
        self.pin.hash.is_some()
    }

    /// Serialize as `0x01 || TLV*` (see the module documentation).
    pub(crate) fn serialize(&self) -> Vec<u8> {
        let mut out = vec![FORMAT_VERSION];
        if let Some(secret) = &self.secret {
            tlv::encode_into(&mut out, TAG_SECRET, secret);
        }
        if let Some(att) = &self.attestation {
            tlv::encode_into(&mut out, TAG_ATT_SCALAR, &att.scalar);
            tlv::encode_into(&mut out, TAG_ATT_CERT, &att.cert);
            tlv::encode_into(&mut out, TAG_ATT_ROOT, &att.root_cert);
            tlv::encode_into(&mut out, TAG_ATT_AAGUID, &att.aaguid);
            tlv::encode_into(&mut out, TAG_ATT_CN, att.common_name.as_bytes());
        }
        tlv::encode_into(&mut out, TAG_COUNTER, &self.counter.to_be_bytes());
        if let Some(hash) = &self.pin.hash {
            tlv::encode_into(&mut out, TAG_PIN_HASH, hash);
            tlv::encode_into(&mut out, TAG_PIN_CODE_POINTS, &[self.pin.code_points]);
        }
        tlv::encode_into(&mut out, TAG_PIN_RETRIES, &[self.pin.retries]);
        tlv::encode_into(&mut out, TAG_MIN_PIN_LENGTH, &[self.pin.min_length]);
        tlv::encode_into(
            &mut out,
            TAG_FORCE_PIN_CHANGE,
            &[u8::from(self.pin.force_change)],
        );
        tlv::encode_into(&mut out, TAG_ALWAYS_UV, &[u8::from(self.pin.always_uv)]);
        if !self.pin.min_pin_rp_ids.is_empty() {
            let mut list = Vec::new();
            for rp in &self.pin.min_pin_rp_ids {
                tlv::encode_into(&mut list, TAG_RP_ID_ENTRY, rp.as_bytes());
            }
            tlv::encode_into(&mut out, TAG_MIN_PIN_RP_IDS, &list);
        }
        if self.large_blob != INITIAL_LARGE_BLOB {
            tlv::encode_into(&mut out, TAG_LARGE_BLOB, &self.large_blob);
        }
        for r in &self.residents {
            let mut row = Vec::new();
            tlv::encode_into(&mut row, R_ID, &r.id);
            tlv::encode_into(&mut row, R_RP_ID, r.rp_id.as_bytes());
            tlv::encode_into(&mut row, R_USER_ID, &r.user_id);
            if let Some(name) = &r.user_name {
                tlv::encode_into(&mut row, R_USER_NAME, name.as_bytes());
            }
            if let Some(name) = &r.display_name {
                tlv::encode_into(&mut row, R_DISPLAY_NAME, name.as_bytes());
            }
            if let Some(blob) = &r.cred_blob {
                tlv::encode_into(&mut row, R_CRED_BLOB, blob);
            }
            if let Some(key) = &r.large_blob_key {
                tlv::encode_into(&mut row, R_LARGE_BLOB_KEY, key);
            }
            tlv::encode_into(&mut row, R_CRED_PROTECT, &[r.cred_protect]);
            tlv::encode_into(&mut out, TAG_RESIDENT, &row);
        }
        for raw in &self.unknown {
            out.extend_from_slice(raw);
        }
        out
    }

    /// Parse a serialized state; `None` if it is unreadable in any way.
    pub(crate) fn deserialize(bytes: &[u8]) -> Option<State> {
        let (&version, body) = bytes.split_first()?;
        if version != FORMAT_VERSION {
            return None;
        }
        let mut state = State::default();
        let mut att = AttestationParts::default();
        for item in tlv::parse_all(body).ok()? {
            let v = item.value;
            match item.tag {
                TAG_SECRET => state.secret = Some(v.try_into().ok()?),
                TAG_ATT_SCALAR => att.scalar = Some(v.try_into().ok()?),
                TAG_ATT_CERT => att.cert = Some(v.to_vec()),
                TAG_ATT_ROOT => att.root = Some(v.to_vec()),
                TAG_ATT_AAGUID => att.aaguid = Some(v.try_into().ok()?),
                TAG_ATT_CN => att.common_name = Some(utf8(v)?),
                TAG_COUNTER => state.counter = u32::from_be_bytes(v.try_into().ok()?),
                TAG_PIN_HASH => state.pin.hash = Some(v.try_into().ok()?),
                TAG_PIN_RETRIES => state.pin.retries = single(v)?,
                TAG_MIN_PIN_LENGTH => state.pin.min_length = single(v)?,
                TAG_FORCE_PIN_CHANGE => state.pin.force_change = flag(v)?,
                TAG_ALWAYS_UV => state.pin.always_uv = flag(v)?,
                TAG_PIN_CODE_POINTS => state.pin.code_points = single(v)?,
                TAG_LARGE_BLOB => {
                    // At least the 16-byte integrity trailer plus one CBOR byte (§6.10.2).
                    if v.len() < INITIAL_LARGE_BLOB.len() {
                        return None;
                    }
                    state.large_blob = v.to_vec();
                }
                TAG_MIN_PIN_RP_IDS => {
                    for entry in tlv::parse_all(v).ok()? {
                        if entry.tag == TAG_RP_ID_ENTRY {
                            state.pin.min_pin_rp_ids.push(utf8(entry.value)?);
                        }
                    }
                }
                TAG_RESIDENT => state.residents.push(resident(v)?),
                _ => state.unknown.push(item.raw.to_vec()),
            }
        }
        state.attestation = att.finish()?;
        Some(state)
    }
}

#[derive(Default)]
struct AttestationParts {
    scalar: Option<[u8; 32]>,
    cert: Option<Vec<u8>>,
    root: Option<Vec<u8>>,
    aaguid: Option<[u8; 16]>,
    common_name: Option<String>,
}

impl AttestationParts {
    /// `Some(None)` when no attestation is stored, `Some(Some(_))` when every part is
    /// present and valid, `None` (unreadable) for a partial or invalid set.
    fn finish(self) -> Option<Option<Attestation>> {
        match (
            self.scalar,
            self.cert,
            self.root,
            self.aaguid,
            self.common_name,
        ) {
            (None, None, None, None, None) => Some(None),
            (Some(scalar), Some(cert), Some(root_cert), Some(aaguid), Some(common_name)) => {
                let att = Attestation {
                    scalar,
                    cert,
                    root_cert,
                    aaguid,
                    common_name,
                };
                att.is_valid().then_some(Some(att))
            }
            _ => None,
        }
    }
}

fn resident(bytes: &[u8]) -> Option<Resident> {
    let mut id = None;
    let mut rp_id = None;
    let mut user_id = None;
    let mut row = Resident {
        id: Vec::new(),
        rp_id: String::new(),
        rp_id_hash: [0; 32],
        user_id: Vec::new(),
        user_name: None,
        display_name: None,
        cred_blob: None,
        large_blob_key: None,
        cred_protect: 1,
    };
    for item in tlv::parse_all(bytes).ok()? {
        let v = item.value;
        match item.tag {
            R_ID => id = Some(v.to_vec()),
            R_RP_ID => rp_id = Some(utf8(v)?),
            R_USER_ID => user_id = Some(v.to_vec()),
            R_USER_NAME => row.user_name = Some(utf8(v)?),
            R_DISPLAY_NAME => row.display_name = Some(utf8(v)?),
            R_CRED_BLOB => row.cred_blob = Some(v.to_vec()),
            R_LARGE_BLOB_KEY => row.large_blob_key = Some(v.try_into().ok()?),
            R_CRED_PROTECT => {
                row.cred_protect = single(v)?;
                if !(1..=3).contains(&row.cred_protect) {
                    return None;
                }
            }
            _ => {}
        }
    }
    row.id = id?;
    row.rp_id = rp_id?;
    row.user_id = user_id?;
    row.rp_id_hash = sha256(row.rp_id.as_bytes());
    Some(row)
}

fn utf8(bytes: &[u8]) -> Option<String> {
    String::from_utf8(bytes.to_vec()).ok()
}

fn single(bytes: &[u8]) -> Option<u8> {
    match bytes {
        [b] => Some(*b),
        _ => None,
    }
}

fn flag(bytes: &[u8]) -> Option<bool> {
    match bytes {
        [0] => Some(false),
        [1] => Some(true),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample() -> State {
        State {
            secret: Some([1; 32]),
            attestation: None,
            counter: 0x0102_0304,
            pin: PinState {
                hash: Some([9; 16]),
                code_points: 6,
                retries: 5,
                min_length: 6,
                force_change: true,
                always_uv: false,
                min_pin_rp_ids: vec!["example.com".into()],
            },
            residents: vec![Resident {
                id: vec![2; 128],
                rp_id: "example.com".into(),
                rp_id_hash: sha256(b"example.com"),
                user_id: vec![3; 16],
                user_name: Some("alice".into()),
                display_name: None,
                cred_blob: Some(vec![4; 32]),
                large_blob_key: Some([5; 32]),
                cred_protect: 2,
            }],
            large_blob: vec![0xA5; 40],
            unknown: vec![vec![0x9F, 0x20, 0x01, 0xAA]],
        }
    }

    #[test]
    fn round_trip_keeps_every_field_and_unknown_tags() {
        let state = sample();
        let bytes = state.serialize();
        assert_eq!(bytes.first(), Some(&FORMAT_VERSION));
        assert_eq!(State::deserialize(&bytes), Some(state));
    }

    #[test]
    fn unreadable_inputs_are_rejected() {
        assert_eq!(State::deserialize(&[]), None);
        assert_eq!(State::deserialize(&[0x02]), None);
        assert_eq!(State::deserialize(&[0x01, 0x81, 0x02, 0x00, 0x00]), None); // short secret
        assert_eq!(State::deserialize(&[0x01, 0x87, 0x05]), None); // truncated
        assert_eq!(State::deserialize(&[0x01, 0x82, 0x01, 0x00]), None); // partial attestation
        let mut bytes = sample().serialize();
        bytes.truncate(bytes.len() - 3);
        assert_eq!(State::deserialize(&bytes), None);
    }

    #[test]
    fn empty_body_is_factory_state() {
        assert_eq!(State::deserialize(&[0x01]), Some(State::default()));
    }

    #[test]
    fn initial_large_blob_array_is_the_cbor_empty_array_with_its_hash() {
        // CTAP 2.1 §6.10.2: 0x80 || LEFT(SHA-256(0x80), 16).
        assert_eq!(INITIAL_LARGE_BLOB[0], 0x80);
        assert_eq!(&INITIAL_LARGE_BLOB[1..], &sha256(&[0x80])[..16]);
        // The factory array is not written; another array is; a short one is unreadable.
        let factory = State::default().serialize();
        assert!(
            tlv::parse_all(&factory[1..])
                .unwrap()
                .iter()
                .all(|t| t.tag != TAG_LARGE_BLOB)
        );
        let custom = State {
            large_blob: vec![0xA0; 17],
            ..State::default()
        };
        let bytes = custom.serialize();
        assert_eq!(
            State::deserialize(&bytes).unwrap().large_blob,
            vec![0xA0; 17]
        );
        assert_eq!(State::deserialize(&[0x01, 0x8E, 0x01, 0x80]), None);
    }
}
