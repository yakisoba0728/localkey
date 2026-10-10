//! Persistent OATH state and its serialization.
//!
//! Format (`docs/CONTRACTS.md`, "Persisted state"; `docs/DESIGN.md` §7): the version
//! byte `0x01`, then BER-TLV data objects (ISO/IEC 7816-4 §5.2.2, via `lk_codec::tlv`):
//!
//! | Tag | Content |
//! | --- | --- |
//! | `80` | device salt / id, 8 bytes |
//! | `81` | access key: algorithm code (1 byte) then the HMAC key; absent when none is set |
//! | `A2` | one credential (constructed, repeated in list order) |
//!
//! Inside a credential:
//!
//! | Tag | Content |
//! | --- | --- |
//! | `80` | name (1..=64 bytes) |
//! | `81` | type/algorithm byte as in YKOATH §PUT |
//! | `82` | digits |
//! | `83` | HMAC key |
//! | `84` | property bits |
//! | `85` | HOTP next counter, 8 bytes big-endian |
//! | `86` | last challenge of an "only increasing" credential (may be empty) |
//!
//! Unknown tags are skipped. Anything else that does not decode to a valid state makes
//! the whole record unreadable, which means factory state.

use std::fmt;

use lk_codec::tlv;
use lk_core::Host;

use crate::credential::{Alg, Credential, Kind, PROP_ALL};
use crate::{MAX_CHALLENGE_LEN, MAX_CREDENTIALS, MAX_NAME_LEN};

/// Format version byte of the persisted record.
const VERSION: u8 = 0x01;

mod field {
    pub(super) const SALT: u32 = 0x80;
    pub(super) const ACCESS_KEY: u32 = 0x81;
    pub(super) const CREDENTIAL: u32 = 0xA2;

    pub(super) const NAME: u32 = 0x80;
    pub(super) const TYPE_ALG: u32 = 0x81;
    pub(super) const DIGITS: u32 = 0x82;
    pub(super) const KEY: u32 = 0x83;
    pub(super) const PROPS: u32 = 0x84;
    pub(super) const COUNTER: u32 = 0x85;
    pub(super) const LAST_CHALLENGE: u32 = 0x86;
}

/// Largest stored HMAC key: a key above the block size is stored hashed
/// (RFC 2104 §2), so no stored key exceeds 128 bytes.
const MAX_STORED_KEY: usize = 128;

/// The access key protecting the application (YKOATH §SET CODE).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AccessKey {
    pub(crate) alg: Alg,
    pub(crate) key: Vec<u8>,
}

impl fmt::Debug for AccessKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessKey")
            .field("alg", &self.alg)
            .field("key", &"<redacted>")
            .finish()
    }
}

/// Everything the OATH application keeps across power cycles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct State {
    /// Device id and PBKDF2 salt reported by SELECT tag `71` (YKOATH §SELECT).
    pub(crate) salt: [u8; 8],
    pub(crate) access_key: Option<AccessKey>,
    /// Credentials in creation order; LIST and CALCULATE ALL report them in this order.
    pub(crate) creds: Vec<Credential>,
}

impl State {
    /// Factory state: no credentials, no access key and a fresh random salt
    /// (YKOATH §RESET: a reset also changes the device id).
    pub(crate) fn factory(host: &mut dyn Host) -> Self {
        let mut salt = [0u8; 8];
        host.fill(&mut salt);
        Self {
            salt,
            access_key: None,
            creds: Vec::new(),
        }
    }

    /// Index of the credential named exactly `name` (names are compared byte for byte).
    pub(crate) fn find(&self, name: &[u8]) -> Option<usize> {
        self.creds.iter().position(|c| c.name == name)
    }

    /// Serialize as described in the module documentation.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = vec![VERSION];
        tlv::encode_into(&mut out, field::SALT, &self.salt);
        if let Some(key) = &self.access_key {
            let mut value = vec![key.alg.code()];
            value.extend_from_slice(&key.key);
            tlv::encode_into(&mut out, field::ACCESS_KEY, &value);
        }
        for cred in &self.creds {
            let mut value = Vec::new();
            tlv::encode_into(&mut value, field::NAME, &cred.name);
            tlv::encode_into(&mut value, field::TYPE_ALG, &[cred.type_alg()]);
            tlv::encode_into(&mut value, field::DIGITS, &[cred.digits]);
            tlv::encode_into(&mut value, field::KEY, &cred.key);
            tlv::encode_into(&mut value, field::PROPS, &[cred.props]);
            tlv::encode_into(&mut value, field::COUNTER, &cred.counter.to_be_bytes());
            if !cred.last_challenge.is_empty() {
                tlv::encode_into(&mut value, field::LAST_CHALLENGE, &cred.last_challenge);
            }
            tlv::encode_into(&mut out, field::CREDENTIAL, &value);
        }
        out
    }

    /// Restore a state written by [`State::encode`]; `None` if it is unreadable.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let (&version, body) = bytes.split_first()?;
        if version != VERSION {
            return None;
        }
        let mut salt = None;
        let mut access_key = None;
        let mut creds: Vec<Credential> = Vec::new();
        for item in tlv::parse_all(body).ok()? {
            match item.tag {
                field::SALT => salt = Some(<[u8; 8]>::try_from(item.value).ok()?),
                field::ACCESS_KEY => access_key = Some(decode_access_key(item.value)?),
                field::CREDENTIAL => {
                    let cred = decode_credential(item.value)?;
                    if creds.len() >= MAX_CREDENTIALS || creds.iter().any(|c| c.name == cred.name) {
                        return None;
                    }
                    creds.push(cred);
                }
                _ => {}
            }
        }
        Some(Self {
            salt: salt?,
            access_key,
            creds,
        })
    }
}

fn decode_access_key(value: &[u8]) -> Option<AccessKey> {
    let (&code, key) = value.split_first()?;
    let alg = Alg::from_code(code)?;
    if key.is_empty() || key.len() > MAX_STORED_KEY {
        return None;
    }
    Some(AccessKey { alg, key: key.to_vec() })
}

fn decode_credential(value: &[u8]) -> Option<Credential> {
    let mut name = None;
    let mut type_alg = None;
    let mut digits = None;
    let mut key = None;
    let mut props = 0u8;
    let mut counter = 0u64;
    let mut last_challenge = Vec::new();
    for item in tlv::parse_all(value).ok()? {
        match item.tag {
            field::NAME => name = Some(item.value.to_vec()),
            field::TYPE_ALG => type_alg = Some(single_byte(item.value)?),
            field::DIGITS => digits = Some(single_byte(item.value)?),
            field::KEY => key = Some(item.value.to_vec()),
            field::PROPS => props = single_byte(item.value)?,
            field::COUNTER => counter = u64::from_be_bytes(<[u8; 8]>::try_from(item.value).ok()?),
            field::LAST_CHALLENGE => last_challenge = item.value.to_vec(),
            _ => {}
        }
    }
    let name = name?;
    let type_alg = type_alg?;
    let digits = digits?;
    let key = key?;
    let kind = Kind::from_code(type_alg & 0xF0)?;
    let alg = Alg::from_code(type_alg & 0x0F)?;
    let valid = (1..=MAX_NAME_LEN).contains(&name.len())
        && crate::DIGITS_RANGE.contains(&digits)
        && !key.is_empty()
        && key.len() <= MAX_STORED_KEY
        && props & !PROP_ALL == 0
        && last_challenge.len() <= MAX_CHALLENGE_LEN;
    valid.then_some(Credential {
        name,
        kind,
        alg,
        digits,
        key,
        props,
        counter,
        last_challenge,
    })
}

fn single_byte(value: &[u8]) -> Option<u8> {
    match value {
        [b] => Some(*b),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::{PROP_ONLY_INCREASING, PROP_REQUIRE_TOUCH};
    use lk_testkit::TestHost;

    fn sample() -> State {
        State {
            salt: [1, 2, 3, 4, 5, 6, 7, 8],
            access_key: Some(AccessKey {
                alg: Alg::Sha256,
                key: vec![0x42; 16],
            }),
            creds: vec![
                Credential {
                    name: vec![0x00, 0xff, b'a'],
                    kind: Kind::Hotp,
                    alg: Alg::Sha1,
                    digits: 6,
                    key: vec![7; 20],
                    props: PROP_REQUIRE_TOUCH,
                    counter: u64::MAX - 1,
                    last_challenge: Vec::new(),
                },
                Credential {
                    name: b"totp".to_vec(),
                    kind: Kind::Totp,
                    alg: Alg::Sha512,
                    digits: 8,
                    key: vec![9; 128],
                    props: PROP_ONLY_INCREASING,
                    counter: 0,
                    last_challenge: vec![0, 0, 0, 0, 0, 0, 0, 9],
                },
            ],
        }
    }

    #[test]
    fn round_trip() {
        let state = sample();
        let bytes = state.encode();
        assert_eq!(bytes.first(), Some(&0x01));
        assert_eq!(State::decode(&bytes), Some(state));
    }

    #[test]
    fn unknown_fields_are_skipped() {
        let state = sample();
        let mut bytes = state.encode();
        // A one-byte and a two-byte unknown tag at the top level.
        tlv::encode_into(&mut bytes, 0x8F, &[1, 2, 3]);
        tlv::encode_into(&mut bytes, 0x9F20, &[4]);
        // An unknown field inside an extra credential.
        let mut cred = Vec::new();
        tlv::encode_into(&mut cred, 0x80, b"x");
        tlv::encode_into(&mut cred, 0x81, &[0x21]);
        tlv::encode_into(&mut cred, 0x82, &[6]);
        tlv::encode_into(&mut cred, 0x83, &[1; 14]);
        tlv::encode_into(&mut cred, 0x8E, &[0xEE]);
        tlv::encode_into(&mut bytes, 0xA2, &cred);
        let decoded = State::decode(&bytes).expect("decodes");
        assert_eq!(decoded.salt, state.salt);
        assert_eq!(decoded.access_key, state.access_key);
        assert_eq!(&decoded.creds[..2], &state.creds[..]);
        assert_eq!(decoded.creds[2].name, b"x");
        assert_eq!(decoded.creds[2].props, 0);
    }

    #[test]
    fn unreadable_records_are_rejected() {
        let bytes = sample().encode();
        assert_eq!(State::decode(&[]), None);
        assert_eq!(State::decode(&[0x02]), None);
        // Missing salt.
        assert_eq!(State::decode(&[0x01]), None);
        // Every truncation either decodes to a valid prefix state or is refused; none panics.
        for len in 0..bytes.len() {
            let _ = State::decode(&bytes[..len]);
        }
        // Wrong version.
        let mut wrong = bytes.clone();
        wrong[0] = 0x02;
        assert_eq!(State::decode(&wrong), None);
    }

    #[test]
    fn factory_state_uses_host_entropy() {
        let mut host = TestHost::new();
        host.push_entropy(&[9, 8, 7, 6, 5, 4, 3, 2]);
        let state = State::factory(&mut host);
        assert_eq!(state.salt, [9, 8, 7, 6, 5, 4, 3, 2]);
        assert!(state.creds.is_empty());
        assert!(state.access_key.is_none());
    }
}
