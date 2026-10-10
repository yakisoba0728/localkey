//! Persistent state and its record format.
//!
//! Record layout (`docs/CONTRACTS.md` "Persisted state"): version byte `0x01`, then
//! BER-TLV objects (ISO/IEC 7816-4 §5.2.2, `lk_codec::tlv`):
//!
//! | Tag | Content |
//! | --- | --- |
//! | `80` | management key (16 bytes) |
//! | `81` | management key tries left (1 byte, 0–8) |
//! | `A1` | one credential (constructed, repeated) |
//!
//! Inside `A1`: `80` label, `81` algorithm, `82` touch (`00`/`01`), `83` password tries
//! left (1–8), `84` credential password (16), `85` K-ENC (16), `86` K-MAC (16), `87`
//! P-256 private scalar (32). Unknown tags are skipped at both levels. Anything else
//! that does not validate makes the whole record unreadable, which means factory state.

use lk_codec::tlv;
use lk_crypto::{Curve, EcPrivateKey};

use crate::{
    CREDENTIAL_PASSWORD_LEN, DEFAULT_MANAGEMENT_KEY, MANAGEMENT_KEY_LEN, MAX_CREDENTIALS, MAX_LABEL_LEN, MIN_LABEL_LEN,
    RETRIES, alg,
};

/// Record format version.
const FORMAT_VERSION: u8 = 0x01;

mod field {
    pub const MANAGEMENT_KEY: u32 = 0x80;
    pub const MANAGEMENT_RETRIES: u32 = 0x81;
    pub const CREDENTIAL: u32 = 0xA1;
    pub const LABEL: u32 = 0x80;
    pub const ALGORITHM: u32 = 0x81;
    pub const TOUCH: u32 = 0x82;
    pub const RETRIES: u32 = 0x83;
    pub const PASSWORD: u32 = 0x84;
    pub const KEY_ENC: u32 = 0x85;
    pub const KEY_MAC: u32 = 0x86;
    pub const EC_SCALAR: u32 = 0x87;
}

/// Overwrite a buffer holding secret material before it is released (best effort: the
/// engine has no `unsafe` volatile writes, so `black_box` keeps the stores observable).
pub(crate) fn wipe(buf: &mut [u8]) {
    buf.fill(0);
    core::hint::black_box(buf);
}

/// A credential's key material.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Key {
    /// YubiHSM 2 symmetric authentication key pair.
    Symmetric { enc: [u8; 16], mac: [u8; 16] },
    /// SK.OCE for asymmetric authentication; always a valid P-256 scalar.
    EcP256 { scalar: [u8; 32] },
}

impl Key {
    pub(crate) fn algorithm(&self) -> u8 {
        match self {
            Self::Symmetric { .. } => alg::AES128_YUBICO_AUTHENTICATION,
            Self::EcP256 { .. } => alg::EC_P256_YUBICO_AUTHENTICATION,
        }
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        match self {
            Self::Symmetric { enc, mac } => {
                wipe(enc);
                wipe(mac);
            }
            Self::EcP256 { scalar } => wipe(scalar),
        }
    }
}

/// One stored credential.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Credential {
    pub(crate) label: Vec<u8>,
    pub(crate) key: Key,
    pub(crate) touch: bool,
    pub(crate) password: [u8; CREDENTIAL_PASSWORD_LEN],
    /// Password tries left, 1..=8 (a credential reaching 0 is deleted).
    pub(crate) retries: u8,
}

impl Credential {
    /// The private key of an asymmetric credential.
    pub(crate) fn ec_key(&self) -> Option<EcPrivateKey> {
        match &self.key {
            Key::EcP256 { scalar } => EcPrivateKey::from_scalar(Curve::P256, scalar).ok(),
            Key::Symmetric { .. } => None,
        }
    }
}

impl Drop for Credential {
    fn drop(&mut self) {
        wipe(&mut self.password);
    }
}

/// Everything YubiHSM Auth keeps across power cycles.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct State {
    pub(crate) management_key: [u8; MANAGEMENT_KEY_LEN],
    pub(crate) management_retries: u8,
    pub(crate) credentials: Vec<Credential>,
}

impl Drop for State {
    fn drop(&mut self) {
        wipe(&mut self.management_key);
    }
}

/// Label syntax (yubikit `_parse_label`): 1–64 bytes of UTF-8.
pub(crate) fn label_is_valid(label: &[u8]) -> bool {
    (MIN_LABEL_LEN..=MAX_LABEL_LEN).contains(&label.len()) && core::str::from_utf8(label).is_ok()
}

impl State {
    /// Factory state: default management key, full tries, no credentials.
    pub(crate) fn factory() -> Self {
        Self { management_key: DEFAULT_MANAGEMENT_KEY, management_retries: RETRIES, credentials: Vec::new() }
    }

    /// Index of the credential named `label`.
    pub(crate) fn find(&self, label: &[u8]) -> Option<usize> {
        self.credentials.iter().position(|c| c.label == label)
    }

    /// The record bytes.
    pub(crate) fn serialize(&self) -> Vec<u8> {
        let mut out = vec![FORMAT_VERSION];
        tlv::encode_into(&mut out, field::MANAGEMENT_KEY, &self.management_key);
        tlv::encode_into(&mut out, field::MANAGEMENT_RETRIES, &[self.management_retries]);
        for cred in &self.credentials {
            let mut body = Vec::new();
            tlv::encode_into(&mut body, field::LABEL, &cred.label);
            tlv::encode_into(&mut body, field::ALGORITHM, &[cred.key.algorithm()]);
            tlv::encode_into(&mut body, field::TOUCH, &[u8::from(cred.touch)]);
            tlv::encode_into(&mut body, field::RETRIES, &[cred.retries]);
            tlv::encode_into(&mut body, field::PASSWORD, &cred.password);
            match &cred.key {
                Key::Symmetric { enc, mac } => {
                    tlv::encode_into(&mut body, field::KEY_ENC, enc);
                    tlv::encode_into(&mut body, field::KEY_MAC, mac);
                }
                Key::EcP256 { scalar } => tlv::encode_into(&mut body, field::EC_SCALAR, scalar),
            }
            tlv::encode_into(&mut out, field::CREDENTIAL, &body);
            wipe(&mut body);
        }
        out
    }

    /// Parse record bytes; `None` if they are unreadable.
    pub(crate) fn deserialize(bytes: &[u8]) -> Option<Self> {
        let (&version, body) = bytes.split_first()?;
        if version != FORMAT_VERSION {
            return None;
        }
        let items = tlv::parse_all(body).ok()?;
        let management_key = fixed::<MANAGEMENT_KEY_LEN>(single(&items, field::MANAGEMENT_KEY)?)?;
        let management_retries = byte(single(&items, field::MANAGEMENT_RETRIES)?)?;
        if management_retries > RETRIES {
            return None;
        }
        let mut credentials: Vec<Credential> = Vec::new();
        for item in items.iter().filter(|i| i.tag == field::CREDENTIAL) {
            let cred = parse_credential(item.value)?;
            if credentials.len() >= MAX_CREDENTIALS || credentials.iter().any(|c| c.label == cred.label) {
                return None;
            }
            credentials.push(cred);
        }
        Some(Self { management_key, management_retries, credentials })
    }
}

fn parse_credential(value: &[u8]) -> Option<Credential> {
    let items = tlv::parse_all(value).ok()?;
    let label = single(&items, field::LABEL)?.to_vec();
    if !label_is_valid(&label) {
        return None;
    }
    let algorithm = byte(single(&items, field::ALGORITHM)?)?;
    let touch = match byte(single(&items, field::TOUCH)?)? {
        0 => false,
        1 => true,
        _ => return None,
    };
    let retries = byte(single(&items, field::RETRIES)?)?;
    if !(1..=RETRIES).contains(&retries) {
        return None;
    }
    let password = fixed::<CREDENTIAL_PASSWORD_LEN>(single(&items, field::PASSWORD)?)?;
    let key = match algorithm {
        alg::AES128_YUBICO_AUTHENTICATION => Key::Symmetric {
            enc: fixed::<16>(single(&items, field::KEY_ENC)?)?,
            mac: fixed::<16>(single(&items, field::KEY_MAC)?)?,
        },
        alg::EC_P256_YUBICO_AUTHENTICATION => {
            let scalar = fixed::<32>(single(&items, field::EC_SCALAR)?)?;
            EcPrivateKey::from_scalar(Curve::P256, &scalar).ok()?;
            Key::EcP256 { scalar }
        }
        _ => return None,
    };
    Some(Credential { label, key, touch, password, retries })
}

/// The value of the only object with `tag`; `None` if it is missing or repeated.
fn single<'a>(items: &[tlv::Tlv<'a>], tag: u32) -> Option<&'a [u8]> {
    let mut matching = items.iter().filter(|i| i.tag == tag);
    let first = matching.next()?;
    matching.next().is_none().then_some(first.value)
}

fn fixed<const N: usize>(value: &[u8]) -> Option<[u8; N]> {
    value.try_into().ok()
}

fn byte(value: &[u8]) -> Option<u8> {
    match value {
        [b] => Some(*b),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> State {
        let mut state = State::factory();
        state.management_key = [0x11; 16];
        state.management_retries = 5;
        state.credentials.push(Credential {
            label: b"sym".to_vec(),
            key: Key::Symmetric { enc: [1; 16], mac: [2; 16] },
            touch: true,
            password: [3; 16],
            retries: 7,
        });
        let mut scalar = [0u8; 32];
        scalar[31] = 1;
        state.credentials.push(Credential {
            label: "\u{e9}c".as_bytes().to_vec(),
            key: Key::EcP256 { scalar },
            touch: false,
            password: [4; 16],
            retries: 8,
        });
        state
    }

    #[test]
    fn round_trip() {
        let state = sample();
        let bytes = state.serialize();
        assert_eq!(bytes.first(), Some(&FORMAT_VERSION));
        assert!(State::deserialize(&bytes) == Some(state));
    }

    #[test]
    fn unknown_fields_are_skipped() {
        let state = sample();
        let mut bytes = state.serialize();
        tlv::encode_into(&mut bytes, 0x9F20, b"future");
        assert!(State::deserialize(&bytes) == Some(state));
    }

    #[test]
    fn invalid_records_are_rejected() {
        let good = sample().serialize();
        assert!(State::deserialize(&[]).is_none());
        assert!(State::deserialize(&[0x02]).is_none());
        let mut wrong_version = good.clone();
        if let Some(v) = wrong_version.first_mut() {
            *v = 0x02;
        }
        assert!(State::deserialize(&wrong_version).is_none());
        assert!(State::deserialize(good.get(..good.len() - 1).unwrap_or(&[])).is_none());
        // Zero scalar is not a valid P-256 key.
        let mut state = sample();
        if let Some(Credential { key: Key::EcP256 { scalar }, .. }) = state.credentials.get_mut(1) {
            *scalar = [0; 32];
        }
        assert!(State::deserialize(&state.serialize()).is_none());
        // Duplicate labels.
        let mut state = sample();
        if let Some(c) = state.credentials.get_mut(1) {
            c.label = b"sym".to_vec();
        }
        assert!(State::deserialize(&state.serialize()).is_none());
        // Credential with zero tries left cannot exist.
        let mut state = sample();
        if let Some(c) = state.credentials.get_mut(0) {
            c.retries = 0;
        }
        assert!(State::deserialize(&state.serialize()).is_none());
    }

    #[test]
    fn labels() {
        assert!(label_is_valid(b"a"));
        assert!(label_is_valid(&[b'x'; 64]));
        assert!(!label_is_valid(&[b'x'; 65]));
        assert!(!label_is_valid(b""));
        assert!(!label_is_valid(&[0xff, 0xfe]));
    }
}
