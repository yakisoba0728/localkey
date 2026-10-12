//! Typed access to CTAP2 request parameters with the CTAP 2.1 error mapping.
//!
//! - A request parameter set is a CBOR map with unsigned integer keys (CTAP 2.1 §8).
//!   Bytes that are not well-formed CBOR, that carry a tag ("Tags ... MUST NOT be
//!   present", §8) or duplicate map keys are `CTAP2_ERR_INVALID_CBOR`.
//! - Keys this implementation does not understand are ignored ("If map keys are present
//!   that an implementation does not understand, they MUST be ignored", §8). Their values
//!   may be any CBOR type, including floats (`reference/BEHAVIOR_CATALOG.md` FIDO: "canonical
//!   half/float/double CBOR values in unknown request fields are skipped").
//! - A missing required member is `CTAP2_ERR_MISSING_PARAMETER`; a known member of the
//!   wrong CBOR type is `CTAP2_ERR_CBOR_UNEXPECTED_TYPE` (§6.1.2 step 3, §6.2.2).

use lk_codec::cbor::{self, Value};

use crate::status;

/// A CTAP status byte as the error of a fallible step.
pub(crate) type CtapResult<T> = Result<T, u8>;

/// `"public-key"`, the only credential type (WebAuthn L2 §5.10.2, CTAP 2.1 §6.1).
pub(crate) const PUBLIC_KEY: &str = "public-key";

/// Whether `value` holds a CBOR tag anywhere (forbidden by CTAP 2.1 §8).
fn contains_tag(value: &Value) -> bool {
    match value {
        Value::Tag(..) => true,
        Value::Array(items) => items.iter().any(contains_tag),
        Value::Map(entries) => entries
            .iter()
            .any(|(k, v)| contains_tag(k) || contains_tag(v)),
        _ => false,
    }
}

/// The parameter map of a CTAP2 command.
#[derive(Debug)]
pub(crate) struct Params {
    entries: Vec<(Value, Value)>,
    /// The encoded bytes of each value as received, by unsigned key: pinUvAuthParam MACs
    /// cover `subCommandParams` as the platform sent it (CTAP 2.1 §6.8, §6.11), which a
    /// canonical re-encoding would not reproduce when the platform ordered keys otherwise.
    raw: Vec<(u64, Vec<u8>)>,
}

/// The encoded value of every entry of the CBOR map `bytes`, which has already decoded
/// successfully as a map with `count` entries (RFC 8949 §3: a map header, then key and
/// value items in turn). Entries whose key is not an unsigned integer are skipped.
fn raw_values(bytes: &[u8], count: usize) -> Option<Vec<(u64, Vec<u8>)>> {
    let (&initial, rest) = bytes.split_first()?;
    // RFC 8949 §3.1: additional information 0..=23 is the count itself; 24..=27 add 1, 2,
    // 4 or 8 argument bytes.
    let header = 1 + match initial & 0x1F {
        0..=23 => 0,
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return None,
    };
    rest.get(..header - 1)?;
    let mut pos = header;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let (key, used) = cbor::decode_prefix(bytes.get(pos..)?).ok()?;
        pos += used;
        let (_, used) = cbor::decode_prefix(bytes.get(pos..)?).ok()?;
        if let Some(key) = key.as_u64() {
            out.push((key, bytes.get(pos..pos + used)?.to_vec()));
        }
        pos += used;
    }
    Some(out)
}

impl Params {
    /// Decode the CBOR parameters that follow the command byte (CTAP 2.1 §8).
    ///
    /// - No bytes, malformed CBOR, trailing bytes, duplicate keys or tags:
    ///   `CTAP2_ERR_INVALID_CBOR`.
    /// - A well-formed item that is not a map: `CTAP2_ERR_CBOR_UNEXPECTED_TYPE`.
    pub(crate) fn decode(bytes: &[u8]) -> CtapResult<Self> {
        let value = cbor::decode(bytes).map_err(|_| status::INVALID_CBOR)?;
        if contains_tag(&value) {
            return Err(status::INVALID_CBOR);
        }
        match value {
            Value::Map(entries) => {
                let raw = raw_values(bytes, entries.len()).ok_or(status::INVALID_CBOR)?;
                Ok(Self { entries, raw })
            }
            _ => Err(status::CBOR_UNEXPECTED_TYPE),
        }
    }

    /// The encoded bytes of the value under the unsigned integer key `key`, as received.
    pub(crate) fn raw(&self, key: u64) -> Option<&[u8]> {
        self.raw
            .iter()
            .find_map(|(k, v)| (*k == key).then_some(v.as_slice()))
    }

    /// The value under the unsigned integer key `key`; other keys are ignored (§8).
    pub(crate) fn get(&self, key: u64) -> Option<&Value> {
        self.entries
            .iter()
            .find_map(|(k, v)| (k.as_u64() == Some(key)).then_some(v))
    }
}

/// The value under the unsigned integer key `key` of a CBOR map's entries (nested
/// parameter maps such as `subCommandParams`, CTAP 2.1 §6.8, §6.11).
pub(crate) fn uint_key(entries: &[(Value, Value)], key: u64) -> Option<&Value> {
    entries
        .iter()
        .find_map(|(k, v)| (k.as_u64() == Some(key)).then_some(v))
}

/// The value under the text key `key` of a CBOR map's entries.
pub(crate) fn text_key<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find_map(|(k, v)| (k.as_text() == Some(key)).then_some(v))
}

/// `CTAP2_ERR_MISSING_PARAMETER` if a required member is absent.
pub(crate) fn required<T>(value: Option<T>) -> CtapResult<T> {
    value.ok_or(status::MISSING_PARAMETER)
}

pub(crate) fn bytes(value: &Value) -> CtapResult<&[u8]> {
    value.as_bytes().ok_or(status::CBOR_UNEXPECTED_TYPE)
}

pub(crate) fn text(value: &Value) -> CtapResult<&str> {
    value.as_text().ok_or(status::CBOR_UNEXPECTED_TYPE)
}

pub(crate) fn map(value: &Value) -> CtapResult<&[(Value, Value)]> {
    value.as_map().ok_or(status::CBOR_UNEXPECTED_TYPE)
}

pub(crate) fn array(value: &Value) -> CtapResult<&[Value]> {
    value.as_array().ok_or(status::CBOR_UNEXPECTED_TYPE)
}

pub(crate) fn boolean(value: &Value) -> CtapResult<bool> {
    value.as_bool().ok_or(status::CBOR_UNEXPECTED_TYPE)
}

/// An unsigned integer (CBOR major type 0).
pub(crate) fn unsigned(value: &Value) -> CtapResult<u64> {
    value.as_u64().ok_or(status::CBOR_UNEXPECTED_TYPE)
}

/// A signed integer (major type 0 or 1). A negative value below `i64::MIN` is still an
/// integer, so it is mapped to `i64::MIN` (never a supported algorithm) rather than
/// reported as a type error.
pub(crate) fn integer(value: &Value) -> CtapResult<i64> {
    match value {
        Value::Unsigned(n) => Ok(i64::try_from(*n).unwrap_or(i64::MAX)),
        // -1 - n for n <= i64::MAX; anything smaller saturates.
        Value::Negative(n) => Ok(i64::try_from(*n).map(|n| -1 - n).unwrap_or(i64::MIN)),
        _ => Err(status::CBOR_UNEXPECTED_TYPE),
    }
}

/// An optional text member: absent is `None`, any other type is an error.
pub(crate) fn optional_text(entries: &[(Value, Value)], key: &str) -> CtapResult<Option<String>> {
    text_key(entries, key)
        .map(|v| text(v).map(str::to_owned))
        .transpose()
}

/// The most entries accepted in `allowList` / `excludeList`: GetInfo
/// `maxCredentialCountInList` (CTAP 2.1 §6.4; 8 in
/// `reference/physical-key/reference-observation.json`).
pub(crate) const MAX_CREDENTIAL_COUNT_IN_LIST: usize = 8;

/// Parse a list of `PublicKeyCredentialDescriptor`s (CTAP 2.1 §6.1 excludeList, §6.2
/// allowList; WebAuthn L2 §5.10.3) and return the ids of the `"public-key"` entries in
/// order.
///
/// - Each entry is a map with `type` (text) and `id` (bytes): absent members are
///   `CTAP2_ERR_MISSING_PARAMETER`, other types `CTAP2_ERR_CBOR_UNEXPECTED_TYPE`.
///   `transports` is optional and ignored, but must be an array when present.
/// - Entries of another credential type are skipped (unknown types are ignored).
/// - More than [`MAX_CREDENTIAL_COUNT_IN_LIST`] entries is `CTAP2_ERR_LIMIT_EXCEEDED`
///   (model policy: the list exceeds the advertised `maxCredentialCountInList`).
pub(crate) fn descriptor_ids(value: &Value) -> CtapResult<Vec<Vec<u8>>> {
    let items = array(value)?;
    let mut ids = Vec::with_capacity(items.len().min(MAX_CREDENTIAL_COUNT_IN_LIST));
    for item in items {
        let entries = map(item)?;
        let kind = text(required(text_key(entries, "type"))?)?;
        let id = bytes(required(text_key(entries, "id"))?)?;
        if let Some(transports) = text_key(entries, "transports") {
            array(transports)?;
        }
        if kind == PUBLIC_KEY {
            ids.push(id.to_vec());
        }
    }
    if items.len() > MAX_CREDENTIAL_COUNT_IN_LIST {
        return Err(status::LIMIT_EXCEEDED);
    }
    Ok(ids)
}

/// The `options` parameter (CTAP 2.1 §6.1.2 step 5, §6.2.2 step 4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Options {
    pub rk: Option<bool>,
    pub up: Option<bool>,
    pub uv: Option<bool>,
}

/// Parse `options`: `rk`, `up` and `uv` must be booleans (`CTAP2_ERR_CBOR_UNEXPECTED_TYPE`
/// otherwise); option keys that are not understood are ignored whatever their value
/// ("Treat any option keys that are not understood as absent", §6.1.2 step 5;
/// `reference/BEHAVIOR_CATALOG.md` FIDO: "Unknown CTAP option values are skipped while
/// recognized rk/up/uv remain boolean-typed").
pub(crate) fn options(value: Option<&Value>) -> CtapResult<Options> {
    let mut out = Options::default();
    let Some(value) = value else { return Ok(out) };
    for (key, v) in map(value)? {
        match key.as_text() {
            Some("rk") => out.rk = Some(boolean(v)?),
            Some("up") => out.up = Some(boolean(v)?),
            Some("uv") => out.uv = Some(boolean(v)?),
            _ => {}
        }
    }
    Ok(out)
}

/// pinUvAuthProtocol values this authenticator supports (CTAP 2.1 §6.5.6, §6.5.7; GetInfo
/// `pinUvAuthProtocols [2, 1]`).
pub(crate) fn pin_protocol_supported(protocol: u64) -> bool {
    matches!(protocol, 1 | 2)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use lk_codec::cbor::MapBuilder;

    #[test]
    fn tags_anywhere_are_invalid_cbor() {
        // CTAP 2.1 §8: tags MUST NOT be present. 0xA1 01 C1 00 = {1: tag(1, 0)}.
        assert_eq!(
            Params::decode(&[0xA1, 0x01, 0xC1, 0x00]).err(),
            Some(status::INVALID_CBOR)
        );
    }

    #[test]
    fn non_map_is_unexpected_type_and_empty_is_invalid() {
        assert_eq!(
            Params::decode(&[0x01]).err(),
            Some(status::CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(Params::decode(&[]).err(), Some(status::INVALID_CBOR));
    }

    #[test]
    fn unknown_option_values_are_ignored_but_known_options_are_typed() {
        // reference/BEHAVIOR_CATALOG.md FIDO: unknown option values are skipped.
        let opts = MapBuilder::new()
            .insert("rk", true)
            .insert("zz", 5)
            .insert("plat", "x")
            .build();
        assert_eq!(
            options(Some(&opts)),
            Ok(Options {
                rk: Some(true),
                up: None,
                uv: None
            })
        );
        let bad = MapBuilder::new().insert("up", 1).build();
        assert_eq!(options(Some(&bad)), Err(status::CBOR_UNEXPECTED_TYPE));
    }

    #[test]
    fn descriptor_lists_validate_members_and_skip_other_types() {
        let good = Value::Array(vec![
            MapBuilder::new()
                .insert("type", "public-key")
                .insert("id", vec![1u8, 2])
                .build(),
            MapBuilder::new()
                .insert("type", "other")
                .insert("id", vec![3u8])
                .build(),
        ]);
        assert_eq!(descriptor_ids(&good), Ok(vec![vec![1, 2]]));
        let missing = Value::Array(vec![MapBuilder::new().insert("type", "public-key").build()]);
        assert_eq!(descriptor_ids(&missing), Err(status::MISSING_PARAMETER));
        let wrong = Value::Array(vec![
            MapBuilder::new()
                .insert("type", "public-key")
                .insert("id", "x")
                .build(),
        ]);
        assert_eq!(descriptor_ids(&wrong), Err(status::CBOR_UNEXPECTED_TYPE));
        let entry = MapBuilder::new()
            .insert("type", "public-key")
            .insert("id", vec![1u8])
            .build();
        let nine = Value::Array(vec![entry; 9]);
        assert_eq!(descriptor_ids(&nine), Err(status::LIMIT_EXCEEDED));
    }

    #[test]
    fn raw_values_are_the_bytes_as_received() {
        // RFC 8949 §3: {2: {2: 1, 1: h'aa'}, 1: 6} with the inner keys out of canonical
        // order; the raw value keeps that order, a re-encoding would not.
        let bytes = [0xA2, 0x02, 0xA2, 0x02, 0x01, 0x01, 0x41, 0xAA, 0x01, 0x06];
        let p = Params::decode(&bytes).unwrap();
        assert_eq!(p.raw(2), Some(&bytes[2..8]));
        assert_eq!(p.raw(1), Some(&[0x06][..]));
        assert_eq!(p.raw(3), None);
        assert_ne!(cbor::encode(p.get(2).unwrap()), bytes[2..8].to_vec());
        // A map with a one-byte count header (24 entries) is walked correctly.
        let mut big = MapBuilder::new();
        for k in 0..24u64 {
            big.set(k, vec![k as u8; 3]);
        }
        let encoded = big.encode();
        assert_eq!(encoded[0], 0xB8);
        let p = Params::decode(&encoded).unwrap();
        assert_eq!(p.raw(23), Some(&[0x43, 23, 23, 23][..]));
    }

    #[test]
    fn integers_never_fail_on_range() {
        assert_eq!(integer(&Value::Negative(u64::MAX)), Ok(i64::MIN));
        assert_eq!(integer(&Value::Unsigned(u64::MAX)), Ok(i64::MAX));
        assert_eq!(integer(&Value::int_key(-7)), Ok(-7));
        assert_eq!(
            integer(&Value::Bool(true)),
            Err(status::CBOR_UNEXPECTED_TYPE)
        );
    }
}
