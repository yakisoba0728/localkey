//! CBOR with CTAP2 canonical encoding (CTAP 2.1 §8, RFC 8949).
//!
//! [`encode`] always produces the CTAP2 canonical CBOR encoding form (CTAP 2.1 §8):
//! integers, lengths and tag numbers in their shortest form, definite lengths only, and map
//! keys sorted by the CTAP2 rules (see [`canonical_key_order`]). Floating-point values are
//! written exactly as stored, because CTAP 2.1 §8 says "the representations of any
//! floating-point values are not changed".
//!
//! [`decode`] and [`decode_prefix`] are strict where malformed or non-minimal input could be
//! ambiguous, and lenient where the device is lenient:
//!
//! - rejected: indefinite lengths and break codes, reserved additional information 28–30,
//!   non-minimal integers, lengths and tag numbers, more than [`MAX_DEPTH`] nested arrays,
//!   maps or tags, duplicate map keys, invalid UTF-8 in text strings, simple values other
//!   than `false`, `true`, `null` and `undefined`, and (for [`decode`]) trailing bytes;
//! - accepted: half, single and double floats (kept as raw bits with their size, so that
//!   unknown float fields can be skipped; `BEHAVIOR_CATALOG.md` FIDO), tags (CTAP forbids
//!   them, but rejecting them is the caller's decision), and map keys in non-canonical
//!   order (the order received is kept in [`Value::Map`]).
//!
//! The decoder never allocates more than the remaining input could hold: a declared length
//! or element count larger than the rest of the input is reported as
//! [`CborError::Truncated`] before any allocation, and arrays and maps reserve room for at
//! most a few elements up front, growing only as elements are actually decoded.

use std::cmp::Ordering;
use std::fmt;

/// Maximum number of nested arrays, maps and tags that [`decode`] accepts.
///
/// The top-level item is at nesting level 1 if it is an array, map or tag. Scalars do not
/// add a level. CTAP 2.1 §8 lets messages use at most four levels of maps and arrays; the
/// extra room here covers tags and leaves a margin while bounding recursion.
pub const MAX_DEPTH: usize = 8;

/// The most elements an array or map reserves room for before its elements are decoded.
///
/// A declared count is already checked against the remaining input, but each of up to
/// [`MAX_DEPTH`] nested containers could otherwise reserve room for nearly the whole input.
/// Larger containers grow as their elements arrive, so memory stays proportional to the
/// bytes actually decoded.
const MAX_PREALLOC: usize = 64;

// Major types (RFC 8949 §3.1).
const MAJOR_UNSIGNED: u8 = 0;
const MAJOR_NEGATIVE: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_TAG: u8 = 6;
const MAJOR_SIMPLE: u8 = 7;

// Additional information values for major type 7 (RFC 8949 §3.3).
const SIMPLE_FALSE: u8 = 20;
const SIMPLE_TRUE: u8 = 21;
const SIMPLE_NULL: u8 = 22;
const SIMPLE_UNDEFINED: u8 = 23;
const SIMPLE_ONE_BYTE: u8 = 24;
const FLOAT_HALF: u8 = 25;
const FLOAT_SINGLE: u8 = 26;
const FLOAT_DOUBLE: u8 = 27;
const AI_INDEFINITE: u8 = 31;

/// A CBOR data item (RFC 8949 §2, §3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Value {
    /// Major type 0: an unsigned integer.
    Unsigned(u64),
    /// Major type 1: the negative integer `-1 - n`.
    Negative(u64),
    /// Major type 2: a byte string.
    Bytes(Vec<u8>),
    /// Major type 3: a UTF-8 text string.
    Text(String),
    /// Major type 4: an array.
    Array(Vec<Value>),
    /// Major type 5: a map, entries in the order given. [`encode`] sorts them canonically.
    Map(Vec<(Value, Value)>),
    /// Major type 7, simple values 20 and 21.
    Bool(bool),
    /// Major type 7, simple value 22.
    Null,
    /// Major type 7, simple value 23.
    Undefined,
    /// Major type 7, additional information 25, 26 or 27: the raw IEEE 754 bits
    /// (zero-extended) and the size in bytes (2, 4 or 8).
    ///
    /// The size is part of the value (CTAP 2.1 §8 note). [`encode`] writes the low
    /// `8 * size` bits; a size other than 2 or 4 is written as an 8-byte double.
    Float(u64, u8),
    /// Major type 6: a tag number and the tagged item.
    Tag(u64, Box<Value>),
}

/// Why [`decode`] or [`decode_prefix`] rejected its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CborError {
    /// The input ends before the item is complete, or a declared length or element count is
    /// larger than the remaining input could hold.
    Truncated,
    /// Bytes remain after the single top-level item ([`decode`] only).
    TrailingBytes,
    /// Additional information 28, 29 or 30, which RFC 8949 §3 reserves.
    ReservedAdditionalInfo,
    /// Additional information 31: an indefinite length or a break code. CTAP 2.1 §8 allows
    /// definite lengths only; for major types 0, 1 and 6 it is malformed (RFC 8949 §3).
    IndefiniteLength,
    /// An integer, length or tag number not in its shortest form (CTAP 2.1 §8).
    NonMinimal,
    /// More than [`MAX_DEPTH`] nested arrays, maps or tags.
    DepthExceeded,
    /// A map contains the same key twice (CTAP 2.1 §8).
    DuplicateKey,
    /// A text string is not valid UTF-8 (RFC 8949 §3.1, major type 3).
    InvalidUtf8,
    /// A simple value other than `false`, `true`, `null` or `undefined`.
    UnsupportedSimple,
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Truncated => "CBOR input is truncated",
            Self::TrailingBytes => "trailing bytes after CBOR item",
            Self::ReservedAdditionalInfo => "reserved CBOR additional information",
            Self::IndefiniteLength => "indefinite-length CBOR item or break code",
            Self::NonMinimal => "non-minimal CBOR integer or length",
            Self::DepthExceeded => "CBOR nesting too deep",
            Self::DuplicateKey => "duplicate CBOR map key",
            Self::InvalidUtf8 => "CBOR text string is not valid UTF-8",
            Self::UnsupportedSimple => "unsupported CBOR simple value",
        };
        f.write_str(text)
    }
}

impl std::error::Error for CborError {}

// ---------------------------------------------------------------------------
// Value helpers
// ---------------------------------------------------------------------------

impl Value {
    /// The integer `n` as a CBOR value: [`Value::Unsigned`] when `n >= 0`, otherwise
    /// [`Value::Negative`] holding `-1 - n`.
    #[must_use]
    pub fn int_key(n: i64) -> Value {
        match u64::try_from(n) {
            Ok(unsigned) => Value::Unsigned(unsigned),
            // For negative n, -1 - n is the bitwise complement and lies in 0..=i64::MAX.
            Err(_) => Value::Negative(!n as u64),
        }
    }

    /// The value stored under `key` if `self` is a map, comparing keys structurally.
    #[must_use]
    pub fn map_get(&self, key: &Value) -> Option<&Value> {
        self.as_map()?
            .iter()
            .find_map(|(k, v)| (k == key).then_some(v))
    }

    /// The value stored under the integer key `key` if `self` is a map.
    #[must_use]
    pub fn map_get_int(&self, key: i64) -> Option<&Value> {
        self.map_get(&Value::int_key(key))
    }

    /// The value stored under the text key `key` if `self` is a map.
    #[must_use]
    pub fn map_get_text(&self, key: &str) -> Option<&Value> {
        self.as_map()?
            .iter()
            .find_map(|(k, v)| (k.as_text() == Some(key)).then_some(v))
    }

    /// The integer if `self` is [`Value::Unsigned`].
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Unsigned(n) => Some(*n),
            _ => None,
        }
    }

    /// The integer if `self` is an unsigned or negative integer that fits in `i64`.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Unsigned(n) => i64::try_from(*n).ok(),
            // -1 - n fits in i64 exactly when n <= i64::MAX.
            Value::Negative(n) => i64::try_from(*n).ok().map(|n| -1 - n),
            _ => None,
        }
    }

    /// The contents if `self` is [`Value::Bytes`].
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// The contents if `self` is [`Value::Text`].
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }

    /// The elements if `self` is [`Value::Array`].
    #[must_use]
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    /// The entries if `self` is [`Value::Map`], in their stored order.
    #[must_use]
    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }

    /// The boolean if `self` is [`Value::Bool`]. Integers are not coerced.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

macro_rules! from_unsigned {
    ($($t:ty),*) => {$(
        impl From<$t> for Value {
            fn from(n: $t) -> Self {
                Value::Unsigned(u64::from(n))
            }
        }
    )*};
}
from_unsigned!(u8, u16, u32, u64);

impl From<usize> for Value {
    fn from(n: usize) -> Self {
        Value::Unsigned(usize_to_u64(n))
    }
}

impl From<i32> for Value {
    fn from(n: i32) -> Self {
        Value::int_key(i64::from(n))
    }
}

impl From<i64> for Value {
    fn from(n: i64) -> Self {
        Value::int_key(n)
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::Text(s.to_owned())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::Text(s)
    }
}

impl From<&[u8]> for Value {
    fn from(b: &[u8]) -> Self {
        Value::Bytes(b.to_vec())
    }
}

impl<const N: usize> From<&[u8; N]> for Value {
    fn from(b: &[u8; N]) -> Self {
        Value::Bytes(b.to_vec())
    }
}

impl<const N: usize> From<[u8; N]> for Value {
    fn from(b: [u8; N]) -> Self {
        Value::Bytes(b.to_vec())
    }
}

impl From<Vec<u8>> for Value {
    fn from(b: Vec<u8>) -> Self {
        Value::Bytes(b)
    }
}

impl From<Vec<Value>> for Value {
    fn from(items: Vec<Value>) -> Self {
        Value::Array(items)
    }
}

impl From<MapBuilder> for Value {
    fn from(builder: MapBuilder) -> Self {
        builder.build()
    }
}

/// Widens a length to `u64`. `usize` is at most 64 bits on every supported target.
fn usize_to_u64(n: usize) -> u64 {
    n as u64
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

/// Encodes `value` in the CTAP2 canonical CBOR encoding form (CTAP 2.1 §8).
///
/// Map entries are sorted with [`canonical_key_order`] at every level. `encode` cannot fail,
/// so a [`Value::Map`] holding two keys with the same encoding is written with both entries
/// (in their relative order), which [`decode`] rejects as [`CborError::DuplicateKey`]; build
/// maps with [`MapBuilder`] to rule that out.
#[must_use]
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

/// Appends the canonical encoding of `value` to `out` (see [`encode`]).
pub fn encode_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Unsigned(n) => write_head(out, MAJOR_UNSIGNED, *n),
        Value::Negative(n) => write_head(out, MAJOR_NEGATIVE, *n),
        Value::Bytes(b) => {
            write_head(out, MAJOR_BYTES, usize_to_u64(b.len()));
            out.extend_from_slice(b);
        }
        Value::Text(t) => {
            write_head(out, MAJOR_TEXT, usize_to_u64(t.len()));
            out.extend_from_slice(t.as_bytes());
        }
        Value::Array(items) => {
            write_head(out, MAJOR_ARRAY, usize_to_u64(items.len()));
            for item in items {
                encode_into(item, out);
            }
        }
        Value::Map(entries) => encode_map(entries, out),
        Value::Bool(false) => out.push(MAJOR_SIMPLE << 5 | SIMPLE_FALSE),
        Value::Bool(true) => out.push(MAJOR_SIMPLE << 5 | SIMPLE_TRUE),
        Value::Null => out.push(MAJOR_SIMPLE << 5 | SIMPLE_NULL),
        Value::Undefined => out.push(MAJOR_SIMPLE << 5 | SIMPLE_UNDEFINED),
        Value::Float(bits, size) => {
            let (ai, width) = match size {
                2 => (FLOAT_HALF, 2),
                4 => (FLOAT_SINGLE, 4),
                _ => (FLOAT_DOUBLE, 8),
            };
            out.push(MAJOR_SIMPLE << 5 | ai);
            out.extend_from_slice(&bits.to_be_bytes()[8 - width..]);
        }
        Value::Tag(tag, item) => {
            write_head(out, MAJOR_TAG, *tag);
            encode_into(item, out);
        }
    }
}

/// Appends a map with its entries in CTAP2 canonical key order (stable for equal keys).
fn encode_map(entries: &[(Value, Value)], out: &mut Vec<u8>) {
    let encoded: Vec<(Vec<u8>, &Value)> = entries.iter().map(|(k, v)| (encode(k), v)).collect();
    write_sorted_map(encoded, out);
}

/// Appends a map head and the `(encoded key, value)` entries in CTAP2 canonical key order
/// (stable for equal keys).
fn write_sorted_map<K: AsRef<[u8]>>(mut entries: Vec<(K, &Value)>, out: &mut Vec<u8>) {
    write_head(out, MAJOR_MAP, usize_to_u64(entries.len()));
    entries.sort_by(|a, b| canonical_key_order(a.0.as_ref(), b.0.as_ref()));
    for (key, item) in entries {
        out.extend_from_slice(key.as_ref());
        encode_into(item, out);
    }
}

/// Writes an initial byte and argument in the shortest form (CTAP 2.1 §8, RFC 8949 §3).
fn write_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let mt = major << 5;
    if arg < 24 {
        out.push(mt | arg as u8);
    } else if let Ok(b) = u8::try_from(arg) {
        out.extend_from_slice(&[mt | 24, b]);
    } else if let Ok(h) = u16::try_from(arg) {
        out.push(mt | 25);
        out.extend_from_slice(&h.to_be_bytes());
    } else if let Ok(w) = u32::try_from(arg) {
        out.push(mt | 26);
        out.extend_from_slice(&w.to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

/// Compares two encoded map keys in CTAP2 canonical order (CTAP 2.1 §8):
///
/// 1. if the major types differ, the lower major type sorts earlier;
/// 2. otherwise, if the lengths differ, the shorter encoding sorts earlier;
/// 3. otherwise, the bytewise lower encoding sorts earlier.
///
/// For major types 0–3 and 7 this equals bytewise order of the encodings; for arrays, maps
/// and tags it differs from RFC 8949 §4.2.1 (CTAP 2.1 §8 note).
#[must_use]
pub fn canonical_key_order(a: &[u8], b: &[u8]) -> Ordering {
    let major = |encoded: &[u8]| encoded.first().map(|initial| initial >> 5);
    major(a)
        .cmp(&major(b))
        .then_with(|| a.len().cmp(&b.len()))
        .then_with(|| a.cmp(b))
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

/// Decodes exactly one CBOR item; bytes after it are [`CborError::TrailingBytes`].
///
/// See the module documentation for what is accepted and rejected.
pub fn decode(input: &[u8]) -> Result<Value, CborError> {
    let (value, used) = decode_prefix(input)?;
    if used == input.len() {
        Ok(value)
    } else {
        Err(CborError::TrailingBytes)
    }
}

/// Decodes one CBOR item from the start of `input` and returns it with the number of bytes
/// it occupied. Bytes after the item are left alone.
pub fn decode_prefix(input: &[u8]) -> Result<(Value, usize), CborError> {
    let mut reader = Reader { input, pos: 0 };
    let value = reader.item(0)?;
    Ok((value, reader.pos))
}

/// A cursor over the input. Invariant: `pos <= input.len()`.
struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        let end = self.pos.checked_add(n).ok_or(CborError::Truncated)?;
        let bytes = self.input.get(self.pos..end).ok_or(CborError::Truncated)?;
        self.pos = end;
        Ok(bytes)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], CborError> {
        self.take(N)?.try_into().map_err(|_| CborError::Truncated)
    }

    /// Decodes one item. `depth` is the number of arrays, maps and tags around it.
    fn item(&mut self, depth: usize) -> Result<Value, CborError> {
        let [initial] = self.take_array::<1>()?;
        let major = initial >> 5;
        let ai = initial & 0x1f;
        if major == MAJOR_SIMPLE {
            return self.simple(ai);
        }
        let arg = self.argument(ai)?;
        match major {
            MAJOR_UNSIGNED => Ok(Value::Unsigned(arg)),
            MAJOR_NEGATIVE => Ok(Value::Negative(arg)),
            MAJOR_BYTES => {
                let len = self.count(arg, 1)?;
                Ok(Value::Bytes(self.take(len)?.to_vec()))
            }
            MAJOR_TEXT => {
                let len = self.count(arg, 1)?;
                let text =
                    std::str::from_utf8(self.take(len)?).map_err(|_| CborError::InvalidUtf8)?;
                Ok(Value::Text(text.to_owned()))
            }
            MAJOR_ARRAY => {
                let inner = nested(depth)?;
                let count = self.count(arg, 1)?;
                let mut items = Vec::with_capacity(count.min(MAX_PREALLOC));
                for _ in 0..count {
                    items.push(self.item(inner)?);
                }
                Ok(Value::Array(items))
            }
            MAJOR_MAP => self.map(arg, depth),
            _ => {
                // MAJOR_TAG; major type 7 returned above.
                let inner = nested(depth)?;
                Ok(Value::Tag(arg, Box::new(self.item(inner)?)))
            }
        }
    }

    /// Decodes the entries of a map of `count` pairs and rejects duplicate keys.
    fn map(&mut self, count: u64, depth: usize) -> Result<Value, CborError> {
        let inner = nested(depth)?;
        // Every pair needs at least two bytes.
        let count = self.count(count, 2)?;
        let mut entries = Vec::with_capacity(count.min(MAX_PREALLOC));
        let mut raw_keys: Vec<&'a [u8]> = Vec::with_capacity(count.min(MAX_PREALLOC));
        for _ in 0..count {
            let start = self.pos;
            let key = self.item(inner)?;
            raw_keys.push(self.input.get(start..self.pos).unwrap_or_default());
            let value = self.item(inner)?;
            entries.push((key, value));
        }
        // Every accepted item has exactly one accepted encoding (heads are minimal, floats
        // keep their size, maps keep their order), so equal raw keys mean equal values.
        raw_keys.sort_unstable();
        if raw_keys.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CborError::DuplicateKey);
        }
        Ok(Value::Map(entries))
    }

    /// Reads the argument for additional information `ai` of major types 0–6 and requires
    /// the shortest form (CTAP 2.1 §8).
    fn argument(&mut self, ai: u8) -> Result<u64, CborError> {
        let (value, minimum) = match ai {
            0..=23 => return Ok(u64::from(ai)),
            24 => (u64::from(u8::from_be_bytes(self.take_array()?)), 24),
            25 => (u64::from(u16::from_be_bytes(self.take_array()?)), 0x100),
            26 => (u64::from(u32::from_be_bytes(self.take_array()?)), 0x1_0000),
            27 => (u64::from_be_bytes(self.take_array()?), 0x1_0000_0000),
            AI_INDEFINITE => return Err(CborError::IndefiniteLength),
            _ => return Err(CborError::ReservedAdditionalInfo),
        };
        if value < minimum {
            Err(CborError::NonMinimal)
        } else {
            Ok(value)
        }
    }

    /// Converts a declared length or element count to `usize`, rejecting it unless the
    /// remaining input could hold that many elements of at least `min_size` bytes each.
    fn count(&self, declared: u64, min_size: u64) -> Result<usize, CborError> {
        let fits = usize_to_u64(self.remaining()) / min_size;
        if declared > fits {
            return Err(CborError::Truncated);
        }
        usize::try_from(declared).map_err(|_| CborError::Truncated)
    }

    /// Decodes a major type 7 item (RFC 8949 §3.3).
    fn simple(&mut self, ai: u8) -> Result<Value, CborError> {
        match ai {
            SIMPLE_FALSE => Ok(Value::Bool(false)),
            SIMPLE_TRUE => Ok(Value::Bool(true)),
            SIMPLE_NULL => Ok(Value::Null),
            SIMPLE_UNDEFINED => Ok(Value::Undefined),
            FLOAT_HALF => {
                let bits = u16::from_be_bytes(self.take_array()?);
                Ok(Value::Float(u64::from(bits), 2))
            }
            FLOAT_SINGLE => {
                let bits = u32::from_be_bytes(self.take_array()?);
                Ok(Value::Float(u64::from(bits), 4))
            }
            FLOAT_DOUBLE => Ok(Value::Float(u64::from_be_bytes(self.take_array()?), 8)),
            // simple(0..=19) is unassigned. SIMPLE_ONE_BYTE introduces simple(32..=255),
            // which is unassigned or reserved, or a malformed simple(0..=31).
            0..=19 | SIMPLE_ONE_BYTE => Err(CborError::UnsupportedSimple),
            AI_INDEFINITE => Err(CborError::IndefiniteLength),
            // 28..=30; `ai` has five bits.
            _ => Err(CborError::ReservedAdditionalInfo),
        }
    }
}

/// The nesting depth for the contents of an array, map or tag at `depth`.
fn nested(depth: usize) -> Result<usize, CborError> {
    if depth < MAX_DEPTH {
        Ok(depth + 1)
    } else {
        Err(CborError::DepthExceeded)
    }
}

// ---------------------------------------------------------------------------
// MapBuilder
// ---------------------------------------------------------------------------

/// Builds a map whose entries come out in CTAP2 canonical order (CTAP 2.1 §8).
///
/// Inserting a key that is already present replaces it and its value, so the result never
/// holds duplicate keys ("All encoders MUST serialize CBOR ... without duplicate map keys",
/// CTAP 2.1 §8). Keys are compared by their encoding, not structurally, so two different
/// [`Value`]s that encode to the same bytes (for example a [`Value::Float`] with bits above
/// its size, or map-valued keys with the same entries in another order) count as one key.
///
/// ```
/// use lk_codec::cbor::{MapBuilder, encode};
/// let map = MapBuilder::new().insert(3, -7).insert(1, 2).build();
/// assert_eq!(encode(&map), [0xa2, 0x01, 0x02, 0x03, 0x26]);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MapBuilder {
    /// `(encoded key, key, value)` in insertion order.
    entries: Vec<(Vec<u8>, Value, Value)>,
}

impl MapBuilder {
    /// An empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `key` with `value`, replacing any entry whose key has the same encoding.
    #[must_use]
    pub fn insert(mut self, key: impl Into<Value>, value: impl Into<Value>) -> Self {
        self.set(key, value);
        self
    }

    /// Adds `key` with `value` if `value` is `Some`; leaves the builder unchanged otherwise.
    #[must_use]
    pub fn insert_opt<V: Into<Value>>(self, key: impl Into<Value>, value: Option<V>) -> Self {
        match value {
            Some(value) => self.insert(key, value),
            None => self,
        }
    }

    /// Adds `key` with `value` in place, replacing any entry whose key has the same encoding.
    pub fn set(&mut self, key: impl Into<Value>, value: impl Into<Value>) {
        let key = key.into();
        let value = value.into();
        let encoded = encode(&key);
        match self.entries.iter_mut().find(|(e, _, _)| *e == encoded) {
            Some(entry) => {
                entry.1 = key;
                entry.2 = value;
            }
            None => self.entries.push((encoded, key, value)),
        }
    }

    /// The number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the builder has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The map, with entries sorted in CTAP2 canonical key order.
    #[must_use]
    pub fn build(mut self) -> Value {
        // Encoded keys are unique, so this order is total.
        self.entries.sort_by(|a, b| canonical_key_order(&a.0, &b.0));
        Value::Map(
            self.entries
                .into_iter()
                .map(|(_, key, value)| (key, value))
                .collect(),
        )
    }

    /// The canonical encoding of the map.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let entries = self.entries.iter().map(|(k, _, v)| (k.as_slice(), v));
        write_sorted_map(entries.collect(), &mut out);
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Parses a hex string, ignoring spaces.
    fn h(s: &str) -> Vec<u8> {
        let digits: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        assert!(digits.len().is_multiple_of(2), "odd hex length: {s}");
        digits
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn uint(n: u64) -> Value {
        Value::Unsigned(n)
    }

    fn text(s: &str) -> Value {
        Value::Text(s.to_owned())
    }

    fn bytes(b: &[u8]) -> Value {
        Value::Bytes(b.to_vec())
    }

    fn array(items: Vec<Value>) -> Value {
        Value::Array(items)
    }

    fn map(entries: Vec<(Value, Value)>) -> Value {
        Value::Map(entries)
    }

    fn tag(n: u64, item: Value) -> Value {
        Value::Tag(n, Box::new(item))
    }

    fn float(bits: u64, size: u8) -> Value {
        Value::Float(bits, size)
    }

    /// `n` nested one-element arrays around `0` (`81 81 ... 00`).
    fn nested_arrays(n: usize) -> Vec<u8> {
        let mut out = vec![0x81; n];
        out.push(0x00);
        out
    }

    /// Every definite-length row of RFC 8949 Appendix A (Table 6) that this decoder
    /// accepts, with the expected value. `simple(16)` and `simple(255)` are tested as
    /// rejections instead.
    fn appendix_a_definite() -> Vec<(&'static str, Value)> {
        vec![
            ("00", uint(0)),
            ("01", uint(1)),
            ("0a", uint(10)),
            ("17", uint(23)),
            ("1818", uint(24)),
            ("1819", uint(25)),
            ("1864", uint(100)),
            ("1903e8", uint(1000)),
            ("1a000f4240", uint(1_000_000)),
            ("1b000000e8d4a51000", uint(1_000_000_000_000)),
            ("1bffffffffffffffff", uint(u64::MAX)),
            (
                "c249010000000000000000",
                tag(2, bytes(&h("010000000000000000"))),
            ),
            ("3bffffffffffffffff", Value::Negative(u64::MAX)),
            (
                "c349010000000000000000",
                tag(3, bytes(&h("010000000000000000"))),
            ),
            ("20", Value::int_key(-1)),
            ("29", Value::int_key(-10)),
            ("3863", Value::int_key(-100)),
            ("3903e7", Value::int_key(-1000)),
            ("f90000", float(0x0000, 2)),
            ("f98000", float(0x8000, 2)),
            ("f93c00", float(0x3c00, 2)),
            ("fb3ff199999999999a", float(0x3ff1_9999_9999_999a, 8)),
            ("f93e00", float(0x3e00, 2)),
            ("f97bff", float(0x7bff, 2)),
            ("fa47c35000", float(0x47c3_5000, 4)),
            ("fa7f7fffff", float(0x7f7f_ffff, 4)),
            ("fb7e37e43c8800759c", float(0x7e37_e43c_8800_759c, 8)),
            ("f90001", float(0x0001, 2)),
            ("f90400", float(0x0400, 2)),
            ("f9c400", float(0xc400, 2)),
            ("fbc010666666666666", float(0xc010_6666_6666_6666, 8)),
            ("f97c00", float(0x7c00, 2)),
            ("f97e00", float(0x7e00, 2)),
            ("f9fc00", float(0xfc00, 2)),
            ("fa7f800000", float(0x7f80_0000, 4)),
            ("fa7fc00000", float(0x7fc0_0000, 4)),
            ("faff800000", float(0xff80_0000, 4)),
            ("fb7ff0000000000000", float(0x7ff0_0000_0000_0000, 8)),
            ("fb7ff8000000000000", float(0x7ff8_0000_0000_0000, 8)),
            ("fbfff0000000000000", float(0xfff0_0000_0000_0000, 8)),
            ("f4", Value::Bool(false)),
            ("f5", Value::Bool(true)),
            ("f6", Value::Null),
            ("f7", Value::Undefined),
            (
                "c074323031332d30332d32315432303a30343a30305a",
                tag(0, text("2013-03-21T20:04:00Z")),
            ),
            ("c11a514b67b0", tag(1, uint(1_363_896_240))),
            (
                "c1fb41d452d9ec200000",
                tag(1, float(0x41d4_52d9_ec20_0000, 8)),
            ),
            ("d74401020304", tag(23, bytes(&[1, 2, 3, 4]))),
            ("d818456449455446", tag(24, bytes(&h("6449455446")))),
            (
                "d82076687474703a2f2f7777772e6578616d706c652e636f6d",
                tag(32, text("http://www.example.com")),
            ),
            ("40", bytes(&[])),
            ("4401020304", bytes(&[1, 2, 3, 4])),
            ("60", text("")),
            ("6161", text("a")),
            ("6449455446", text("IETF")),
            ("62225c", text("\"\\")),
            ("62c3bc", text("\u{fc}")),
            ("63e6b0b4", text("\u{6c34}")),
            ("64f0908591", text("\u{10151}")),
            ("80", array(vec![])),
            ("83010203", array(vec![uint(1), uint(2), uint(3)])),
            (
                "8301820203820405",
                array(vec![
                    uint(1),
                    array(vec![uint(2), uint(3)]),
                    array(vec![uint(4), uint(5)]),
                ]),
            ),
            (
                "98190102030405060708090a0b0c0d0e0f101112131415161718181819",
                array((1..=25).map(uint).collect()),
            ),
            ("a0", map(vec![])),
            (
                "a201020304",
                map(vec![(uint(1), uint(2)), (uint(3), uint(4))]),
            ),
            (
                "a26161016162820203",
                map(vec![
                    (text("a"), uint(1)),
                    (text("b"), array(vec![uint(2), uint(3)])),
                ]),
            ),
            (
                "826161a161626163",
                array(vec![text("a"), map(vec![(text("b"), text("c"))])]),
            ),
            (
                "a56161614161626142616361436164614461656145",
                map(vec![
                    (text("a"), text("A")),
                    (text("b"), text("B")),
                    (text("c"), text("C")),
                    (text("d"), text("D")),
                    (text("e"), text("E")),
                ]),
            ),
        ]
    }

    // --- RFC 8949 Appendix A -------------------------------------------------------------

    #[test]
    fn rfc8949_appendix_a_definite_examples_round_trip() {
        for (hex, expected) in appendix_a_definite() {
            let encoded = h(hex);
            assert_eq!(decode(&encoded), Ok(expected.clone()), "decode {hex}");
            assert_eq!(encode(&expected), encoded, "encode {hex}");
            assert_eq!(
                decode_prefix(&encoded),
                Ok((expected, encoded.len())),
                "prefix {hex}"
            );
        }
    }

    /// Half-precision decoding from RFC 8949 Appendix D, used only to check that the float
    /// rows above were transcribed with the right bits.
    fn half_to_f64(half: u16) -> f64 {
        let exp = (half >> 10) & 0x1f;
        let mant = f64::from(half & 0x3ff);
        let magnitude = match exp {
            0 => mant * 2f64.powi(-24),
            31 if mant == 0.0 => f64::INFINITY,
            31 => f64::NAN,
            _ => (mant + 1024.0) * 2f64.powi(i32::from(exp) - 25),
        };
        if half & 0x8000 == 0 {
            magnitude
        } else {
            -magnitude
        }
    }

    #[test]
    fn rfc8949_appendix_a_float_bits_match_diagnostic_values() {
        // (encoded, diagnostic value) from RFC 8949 Appendix A, Table 6.
        let rows: [(&str, f64); 26] = [
            ("f90000", 0.0),
            ("f98000", -0.0),
            ("f93c00", 1.0),
            ("fb3ff199999999999a", 1.1),
            ("f93e00", 1.5),
            ("f97bff", 65504.0),
            ("fa47c35000", 100_000.0),
            ("fa7f7fffff", 3.402_823_466_385_288_6e38),
            ("fb7e37e43c8800759c", 1.0e300),
            ("f90001", 5.960_464_477_539_063e-8),
            ("f90400", 0.000_061_035_156_25),
            ("f9c400", -4.0),
            ("fbc010666666666666", -4.1),
            ("f97c00", f64::INFINITY),
            ("f97e00", f64::NAN),
            ("f9fc00", f64::NEG_INFINITY),
            ("fa7f800000", f64::INFINITY),
            ("fa7fc00000", f64::NAN),
            ("faff800000", f64::NEG_INFINITY),
            ("fb7ff0000000000000", f64::INFINITY),
            ("fb7ff8000000000000", f64::NAN),
            ("fbfff0000000000000", f64::NEG_INFINITY),
            ("c1fb41d452d9ec200000", 1_363_896_240.5),
            ("f93c00", 1.0),
            ("fa47c35000", 100_000.0),
            ("fb3ff199999999999a", 1.1),
        ];
        for (hex, expected) in rows {
            let value = match decode(&h(hex)).unwrap() {
                Value::Tag(_, inner) => *inner,
                other => other,
            };
            let Value::Float(bits, size) = value else {
                panic!("{hex} is not a float");
            };
            let actual = match size {
                2 => half_to_f64(u16::try_from(bits).unwrap()),
                4 => f64::from(f32::from_bits(u32::try_from(bits).unwrap())),
                _ => f64::from_bits(bits),
            };
            if expected.is_nan() {
                assert!(actual.is_nan(), "{hex}");
            } else {
                assert_eq!(actual, expected, "{hex}");
                assert_eq!(
                    actual.is_sign_negative(),
                    expected.is_sign_negative(),
                    "{hex}"
                );
            }
        }
    }

    #[test]
    fn rfc8949_appendix_a_indefinite_examples_are_rejected() {
        // The indefinite-length rows of RFC 8949 Appendix A, Table 6; CTAP 2.1 §8 requires
        // definite lengths.
        let rows = [
            "5f42010243030405ff",
            "7f657374726561646d696e67ff",
            "9fff",
            "9f018202039f0405ffff",
            "9f01820203820405ff",
            "83018202039f0405ff",
            "83019f0203ff820405",
            "9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff",
            "bf61610161629f0203ffff",
            "826161bf61626163ff",
            "bf6346756ef563416d7421ff",
        ];
        for hex in rows {
            assert_eq!(decode(&h(hex)), Err(CborError::IndefiniteLength), "{hex}");
            assert_eq!(
                decode_prefix(&h(hex)),
                Err(CborError::IndefiniteLength),
                "{hex}"
            );
        }
    }

    #[test]
    fn rfc8949_appendix_a_other_simple_values_are_rejected() {
        // simple(16) and simple(255) from RFC 8949 Appendix A; f8 18 is simple(24) in the
        // two-byte form, which RFC 8949 §3.3 makes malformed.
        for hex in ["f0", "f8ff", "f818", "e0", "f3", "f800"] {
            assert_eq!(decode(&h(hex)), Err(CborError::UnsupportedSimple), "{hex}");
        }
    }

    // --- RFC 8949 §3 well-formedness ------------------------------------------------------

    #[test]
    fn reserved_additional_information_is_rejected() {
        // RFC 8949 §3: additional information 28, 29 and 30 are reserved for every major type.
        for major in 0u8..8 {
            for ai in 28u8..=30 {
                let mut input = vec![major << 5 | ai];
                input.extend_from_slice(&[0; 8]);
                assert_eq!(
                    decode_prefix(&input),
                    Err(CborError::ReservedAdditionalInfo),
                    "major {major} ai {ai}"
                );
            }
        }
    }

    #[test]
    fn additional_information_31_is_rejected_for_every_major_type() {
        // RFC 8949 §3.2: indefinite lengths for majors 2–5, break for 7, malformed for 0/1/6.
        for major in 0u8..8 {
            let input = [major << 5 | 31, 0x00, 0xff];
            assert_eq!(
                decode(&input),
                Err(CborError::IndefiniteLength),
                "major {major}"
            );
        }
        assert_eq!(decode(&h("81ff")), Err(CborError::IndefiniteLength));
        assert_eq!(decode(&h("a101ff")), Err(CborError::IndefiniteLength));
    }

    #[test]
    fn invalid_utf8_text_is_rejected() {
        // RFC 8949 §3.1 (major type 3 is UTF-8, RFC 3629): a bad continuation byte, an
        // overlong encoding, a UTF-16 surrogate, and a truncated sequence.
        for hex in ["62c328", "62c080", "63eda080", "61e6", "61ff"] {
            assert_eq!(decode(&h(hex)), Err(CborError::InvalidUtf8), "{hex}");
        }
        // The same bytes are fine as a byte string.
        assert_eq!(decode(&h("42c328")), Ok(bytes(&[0xc3, 0x28])));
    }

    // --- CTAP 2.1 §8 shortest form -------------------------------------------------------

    #[test]
    fn ctap21_integer_boundaries_use_the_shortest_form() {
        // CTAP 2.1 §8: 0..=23 / -1..=-24 in the initial byte, then uint8_t, uint16_t,
        // uint32_t and uint64_t arguments.
        let rows: [(i128, &str); 18] = [
            (0, "00"),
            (23, "17"),
            (24, "1818"),
            (255, "18ff"),
            (256, "190100"),
            (65_535, "19ffff"),
            (65_536, "1a00010000"),
            (4_294_967_295, "1affffffff"),
            (4_294_967_296, "1b0000000100000000"),
            (-1, "20"),
            (-24, "37"),
            (-25, "3818"),
            (-256, "38ff"),
            (-257, "390100"),
            (-65_536, "39ffff"),
            (-65_537, "3a00010000"),
            (-4_294_967_296, "3affffffff"),
            (-4_294_967_297, "3b0000000100000000"),
        ];
        for (n, hex) in rows {
            let n = i64::try_from(n).unwrap();
            let value = Value::int_key(n);
            assert_eq!(encode(&value), h(hex), "encode {n}");
            assert_eq!(decode(&h(hex)), Ok(value), "decode {n}");
            assert_eq!(decode(&h(hex)).unwrap().as_i64(), Some(n));
        }
    }

    #[test]
    fn ctap21_lengths_use_the_shortest_form() {
        // CTAP 2.1 §8: lengths of major types 2–5 follow the integer rule, so each width
        // boundary (23/24, 255/256, 65535/65536) changes the head.
        for (len, head) in [
            (0usize, "00"),
            (1, "01"),
            (23, "17"),
            (24, "1818"),
            (255, "18ff"),
            (256, "190100"),
            (65_535, "19ffff"),
            (65_536, "1a00010000"),
        ] {
            let head = h(head);
            let with_major = |major: u8| {
                let mut out = head.clone();
                out[0] |= major << 5;
                out
            };

            let b = bytes(&vec![0xab; len]);
            let encoded = encode(&b);
            assert_eq!(
                encoded[..head.len()],
                with_major(MAJOR_BYTES)[..],
                "bytes {len}"
            );
            assert_eq!(decode(&encoded), Ok(b));

            let t = text(&"x".repeat(len));
            let encoded = encode(&t);
            assert_eq!(
                encoded[..head.len()],
                with_major(MAJOR_TEXT)[..],
                "text {len}"
            );
            assert_eq!(decode(&encoded), Ok(t));

            let a = array(vec![Value::Null; len]);
            let encoded = encode(&a);
            assert_eq!(
                encoded[..head.len()],
                with_major(MAJOR_ARRAY)[..],
                "array {len}"
            );
            assert_eq!(encoded.len(), head.len() + len, "array {len}");
            assert_eq!(decode(&encoded), Ok(a));

            // Keys 0..len are already in canonical order (shorter, then bytewise).
            let m = map((0..len).map(|i| (Value::from(i), Value::Null)).collect());
            let encoded = encode(&m);
            assert_eq!(
                encoded[..head.len()],
                with_major(MAJOR_MAP)[..],
                "map {len}"
            );
            assert_eq!(decode(&encoded), Ok(m));

            // One element or byte fewer than declared is truncated, never allocated.
            if len > 0 {
                for major in [MAJOR_BYTES, MAJOR_TEXT, MAJOR_ARRAY] {
                    let mut short = with_major(major);
                    short.extend(std::iter::repeat_n(0x00, len - 1));
                    assert_eq!(decode(&short), Err(CborError::Truncated), "{major} {len}");
                }
            }
        }
    }

    #[test]
    fn non_minimal_integers_lengths_and_tags_are_rejected() {
        // CTAP 2.1 §8: integers, lengths (major types 2–5) and, by RFC 8949 §4.2.1, tag
        // numbers must use the shortest argument.
        let rows = [
            "1800",
            "1817",
            "1900ff",
            "1a0000ffff",
            "1b00000000ffffffff",
            "3817",
            "3900ff",
            "3a0000ffff",
            "3b00000000ffffffff",
            "5801ff",
            "590003616263",
            "780161",
            "980100",
            "b8010000",
            "d81700",
            "d9001700",
            "82001805",
            "a1180100",
            "c1d81700",
        ];
        for hex in rows {
            assert_eq!(decode(&h(hex)), Err(CborError::NonMinimal), "{hex}");
        }
        // The smallest value for each argument width is accepted.
        for (hex, n) in [
            ("1818", 24),
            ("190100", 0x100),
            ("1a00010000", 0x1_0000),
            ("1b0000000100000000", 0x1_0000_0000),
        ] {
            assert_eq!(decode(&h(hex)), Ok(uint(n)), "{hex}");
        }
    }

    #[test]
    fn float_representation_is_not_changed() {
        // CTAP 2.1 §8: "The representations of any floating-point values are not changed",
        // and the size is part of the value, so 1.0 as a double stays a double.
        let double_one = h("fb3ff0000000000000");
        assert_eq!(decode(&double_one), Ok(float(0x3ff0_0000_0000_0000, 8)));
        assert_eq!(encode(&decode(&double_one).unwrap()), double_one);
        let single_one = h("fa3f800000");
        assert_eq!(encode(&decode(&single_one).unwrap()), single_one);
        // A size outside 2/4/8 can only come from code; it is written as a double.
        assert_eq!(encode(&float(0x3ff0_0000_0000_0000, 3)), double_one);
        // Only the low 8 * size bits are written.
        assert_eq!(encode(&float(0xffff_3c00, 2)), h("f93c00"));
    }

    // --- CTAP 2.1 §8 map key order -------------------------------------------------------

    /// The keys of an encoded map, in the order they were written.
    fn encoded_keys(value: &Value) -> Vec<Value> {
        let Value::Map(entries) = decode(&encode(value)).unwrap() else {
            panic!("not a map");
        };
        entries.into_iter().map(|(k, _)| k).collect()
    }

    #[test]
    fn ctap21_keys_of_lower_major_type_sort_first() {
        // CTAP 2.1 §8 rule 1: different major types sort by major type, even when the
        // lower major type has the longer encoding (24 = 18 18 before -1 = 20).
        let value = map(vec![
            (text("a"), uint(0)),
            (Value::int_key(-1), uint(0)),
            (uint(24), uint(0)),
            (uint(1), uint(0)),
            (bytes(&[]), uint(0)),
        ]);
        assert_eq!(encode(&value), h("a5 0100 181800 2000 4000 616100"));
    }

    #[test]
    fn ctap21_shorter_keys_sort_first_then_bytewise() {
        // CTAP 2.1 §8 rules 2 and 3 within one major type.
        let texts = map(vec![
            (text("ab"), uint(0)),
            (text("aa"), uint(0)),
            (text("b"), uint(0)),
            (text("a"), uint(0)),
        ]);
        assert_eq!(
            encoded_keys(&texts),
            [text("a"), text("b"), text("aa"), text("ab")]
        );
        let ints = map(vec![
            (uint(1000), uint(0)),
            (uint(24), uint(0)),
            (uint(100), uint(0)),
            (uint(10), uint(0)),
        ]);
        assert_eq!(encode(&ints), h("a4 0a00 181800 186400 1903e800"));
        let negatives = map(vec![
            (Value::int_key(-1000), uint(0)),
            (Value::int_key(-25), uint(0)),
            (Value::int_key(-1), uint(0)),
        ]);
        assert_eq!(encode(&negatives), h("a3 2000 381800 3903e700"));
    }

    #[test]
    fn ctap21_order_equals_bytewise_order_for_major_types_0_to_3_and_7() {
        // CTAP 2.1 §8 note: for integers, strings and simple values the rules equal a
        // lexicographic comparison of the encodings.
        let keys = [
            uint(10),
            uint(100),
            uint(1000),
            uint(u64::MAX),
            Value::int_key(-1),
            Value::int_key(-1000),
            bytes(&[]),
            bytes(&[0]),
            bytes(&[1, 2]),
            text(""),
            text("z"),
            text("aa"),
            text("b"),
            Value::Bool(false),
            Value::Bool(true),
            Value::Null,
            Value::Undefined,
            float(0x3c00, 2),
            float(0x3f80_0000, 4),
            float(0x3ff0_0000_0000_0000, 8),
        ];
        let mut canonical: Vec<Vec<u8>> = keys.iter().map(encode).collect();
        let mut bytewise = canonical.clone();
        canonical.sort_by(|a, b| canonical_key_order(a, b));
        bytewise.sort();
        assert_eq!(canonical, bytewise);
    }

    #[test]
    fn ctap21_order_for_array_keys_is_length_first() {
        // CTAP 2.1 §8 note: for arrays, maps and tags the CTAP2 rules differ from bytewise
        // order. [-1] (81 20) is shorter than [100] (81 18 64), so it sorts first, although
        // RFC 8949 §4.2.1 bytewise order would put [100] first.
        let value = map(vec![
            (array(vec![uint(100)]), uint(0)),
            (array(vec![Value::int_key(-1)]), uint(0)),
        ]);
        assert_eq!(encode(&value), h("a2 812000 81186400"));
    }

    #[test]
    fn nested_maps_are_sorted_too() {
        let value = array(vec![map(vec![
            (uint(2), map(vec![(uint(9), uint(0)), (uint(8), uint(0))])),
            (uint(1), uint(0)),
        ])]);
        assert_eq!(encode(&value), h("81 a2 0100 02 a2 0800 0900"));
        let tagged = tag(24, map(vec![(uint(1), uint(0)), (uint(0), uint(0))]));
        assert_eq!(encode(&tagged), h("d818 a2 0000 0100"));
    }

    #[test]
    fn cose_key_order_from_webauthn_example() {
        // The EC2 COSE_Key example in WebAuthn Level 2 §6.5.1.1, "encoded in the CTAP2
        // canonical CBOR encoding form" (kty, alg, crv, x, y), built from shuffled inserts.
        let x = h("65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d");
        let y = h("1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c");
        let expected = h("a5 0102 0326 2001 \
             215820 65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d \
             225820 1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c");
        let built = MapBuilder::new()
            .insert(-3, y)
            .insert(-2, x)
            .insert(-1, 1)
            .insert(3, -7)
            .insert(1, 2)
            .encode();
        assert_eq!(built, expected);
        let decoded = decode(&expected).unwrap();
        assert_eq!(decoded.map_get_int(3).and_then(Value::as_i64), Some(-7));
        assert_eq!(encode(&decoded), expected);
    }

    #[test]
    fn getinfo_option_names_from_device_are_in_canonical_order() {
        // The authenticatorGetInfo options keys, in the order the device reported them:
        // reference/physical-key/reference-observation.json
        // (reference.get_info_fields.options).
        let device_order = [
            "rk",
            "up",
            "plat",
            "alwaysUv",
            "credMgmt",
            "authnrCfg",
            "clientPin",
            "largeBlobs",
            "pinUvAuthToken",
            "setMinPINLength",
            "makeCredUvNotRqd",
            "credentialMgmtPreview",
        ];
        let mut builder = MapBuilder::new();
        for name in device_order.iter().rev() {
            builder.set(*name, true);
        }
        let keys = encoded_keys(&builder.build());
        let names: Vec<&str> = keys.iter().map(|k| k.as_text().unwrap()).collect();
        assert_eq!(names, device_order);
    }

    #[test]
    fn decoder_keeps_non_canonical_key_order() {
        // Not in the decoder's reject list: a map in non-canonical order is accepted with its
        // entries in the order received, and re-encoding sorts them (CTAP 2.1 §8).
        let input = h("a2 0200 0100");
        let value = decode(&input).unwrap();
        assert_eq!(value, map(vec![(uint(2), uint(0)), (uint(1), uint(0))]));
        assert_eq!(encode(&value), h("a2 0100 0200"));
    }

    // --- Duplicate keys, depth, truncation and huge lengths -------------------------------

    #[test]
    fn duplicate_map_keys_are_rejected() {
        // CTAP 2.1 §8: decoders should reject messages with duplicate map keys.
        let rows = [
            "a2 0100 0101",
            "a2 616100 616101",
            "a3 0100 0200 0100",
            "a2 4100 00 4100 01",
            "81 a2 2000 2001",
            "a1 01 a2 0000 0001",
            "a2 f93c00 00 f93c00 01",
        ];
        for hex in rows {
            assert_eq!(decode(&h(hex)), Err(CborError::DuplicateKey), "{hex}");
        }
        // Equal-looking keys of different types, or floats of different sizes (the size
        // is part of the value, CTAP 2.1 §8 note), are distinct.
        let distinct = [
            "a2 0100 2000",
            "a2 4161 00 6161 00",
            "a2 f93c00 00 fa3f800000 00",
            "a2 f4 00 f5 00",
        ];
        for hex in distinct {
            assert!(decode(&h(hex)).is_ok(), "{hex}");
        }
    }

    #[test]
    fn nesting_up_to_max_depth_is_accepted() {
        assert_eq!(MAX_DEPTH, 8);
        // Arrays.
        assert!(decode(&nested_arrays(MAX_DEPTH)).is_ok());
        assert_eq!(
            decode(&nested_arrays(MAX_DEPTH + 1)),
            Err(CborError::DepthExceeded)
        );
        // Maps: a1 00 a1 00 ... 00.
        let nested_maps = |n: usize| {
            let mut out = [0xa1, 0x00].repeat(n);
            out.push(0x00);
            out
        };
        assert!(decode(&nested_maps(MAX_DEPTH)).is_ok());
        assert_eq!(
            decode(&nested_maps(MAX_DEPTH + 1)),
            Err(CborError::DepthExceeded)
        );
        // Tags count as a level, so tag chains cannot recurse without bound.
        let nested_tags = |n: usize| {
            let mut out = vec![0xc6; n];
            out.push(0x00);
            out
        };
        assert!(decode(&nested_tags(MAX_DEPTH)).is_ok());
        assert_eq!(
            decode(&nested_tags(MAX_DEPTH + 1)),
            Err(CborError::DepthExceeded)
        );
        // Mixed: map -> array -> tag -> map -> array -> tag -> array -> map holding a scalar.
        let mixed = h("a1 00 81 c6 a1 00 81 c6 81 a1 00 00");
        assert!(decode(&mixed).is_ok());
        let too_deep = h("a1 00 81 c6 a1 00 81 c6 81 a1 00 80");
        assert_eq!(decode(&too_deep), Err(CborError::DepthExceeded));
        // An empty container at the last level is fine; a ninth level is not.
        let mut eight_empty = vec![0x81; MAX_DEPTH - 1];
        eight_empty.push(0x80);
        assert!(decode(&eight_empty).is_ok());
    }

    #[test]
    fn very_deep_input_fails_without_recursing() {
        let input = vec![0x81; 100_000];
        assert_eq!(decode(&input), Err(CborError::DepthExceeded));
        let tags = vec![0xc6; 100_000];
        assert_eq!(decode(&tags), Err(CborError::DepthExceeded));
    }

    /// Samples for truncation tests: RFC 8949 Appendix A rows plus a COSE key.
    fn truncation_samples() -> Vec<Vec<u8>> {
        let cose = MapBuilder::new()
            .insert(1, 2)
            .insert(3, -7)
            .insert(-1, 1)
            .insert(-2, [0x11u8; 32])
            .insert(-3, [0x22u8; 32])
            .encode();
        vec![
            h("a26161016162820203"),
            h("1b000000e8d4a51000"),
            h("c074323031332d30332d32315432303a30343a30305a"),
            h("fb3ff199999999999a"),
            h("98190102030405060708090a0b0c0d0e0f101112131415161718181819"),
            h("64f0908591"),
            h("826161a161626163"),
            cose,
        ]
    }

    #[test]
    fn every_truncation_of_a_valid_item_is_rejected() {
        for sample in truncation_samples() {
            for cut in 0..sample.len() {
                let prefix = &sample[..cut];
                assert_eq!(
                    decode(prefix),
                    Err(CborError::Truncated),
                    "{sample:02x?} cut {cut}"
                );
                assert_eq!(decode_prefix(prefix), Err(CborError::Truncated));
            }
            assert!(decode(&sample).is_ok());
        }
    }

    #[test]
    fn trailing_bytes_are_rejected_by_decode_only() {
        for sample in truncation_samples() {
            let value = decode(&sample).unwrap();
            let mut longer = sample.clone();
            longer.extend_from_slice(&[0x00, 0xff]);
            assert_eq!(decode(&longer), Err(CborError::TrailingBytes));
            assert_eq!(decode_prefix(&longer), Ok((value, sample.len())));
        }
    }

    #[test]
    fn declared_lengths_beyond_the_input_are_rejected() {
        // Lengths and counts up to 2^64 - 1 (RFC 8949 §3, additional information 27) must
        // fail on the length check, not by attempting the allocation.
        let rows = [
            "5bffffffffffffffff",
            "7bffffffffffffffff",
            "9bffffffffffffffff",
            "bbffffffffffffffff",
            "5affffffff00",
            "9a7fffffff00",
            "ba7fffffff0000",
            "5b0000000100000000",
            "4501020304",
            "64616263",
            "830000",
            // Three pairs need at least six bytes; four remain.
            "a300000000",
            "81 9bffffffffffffffff",
            "a1 00 bbffffffffffffffff",
        ];
        for hex in rows {
            assert_eq!(decode(&h(hex)), Err(CborError::Truncated), "{hex}");
        }
    }

    // --- Codec-level checks for BEHAVIOR_CATALOG.md (FIDO) --------------------------------

    #[test]
    fn catalog_unknown_float_fields_decode_and_are_skippable() {
        // BEHAVIOR_CATALOG.md FIDO: "CTAP2.1 canonical half/float/double CBOR values in
        // unknown request fields are skipped rather than rejected". A request-like map with
        // known keys 1 and 2 and unknown keys holding each float size decodes, and the known
        // fields are still found.
        let input = h("a5 01 4100 02 6178 10 f93e00 11 fa47c35000 12 fb3ff199999999999a");
        let request = decode(&input).unwrap();
        assert_eq!(request.map_get_int(1), Some(&bytes(&[0])));
        assert_eq!(request.map_get_int(2).and_then(Value::as_text), Some("x"));
        assert_eq!(request.map_get_int(0x10), Some(&float(0x3e00, 2)));
        assert_eq!(request.map_get_int(0x11), Some(&float(0x47c3_5000, 4)));
        assert_eq!(
            request.map_get_int(0x12),
            Some(&float(0x3ff1_9999_9999_999a, 8))
        );
        assert_eq!(request.map_get_int(3), None);
        assert_eq!(encode(&request), input);
    }

    #[test]
    fn catalog_option_values_are_not_coerced() {
        // BEHAVIOR_CATALOG.md FIDO: "Unknown CTAP option values are skipped while recognized
        // rk/up/uv remain boolean-typed" and enterpriseAttestation "wrong boolean type
        // returns 11". The helpers must not coerce between booleans and integers.
        let options = decode(&h("a3 627570 00 62726b f5 627a7a f93e00")).unwrap();
        assert_eq!(
            options.map_get_text("rk").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(options.map_get_text("up").and_then(Value::as_bool), None);
        assert_eq!(options.map_get_text("up").and_then(Value::as_u64), Some(0));
        assert_eq!(options.map_get_text("zz"), Some(&float(0x3e00, 2)));
        assert_eq!(Value::Bool(true).as_u64(), None);
        assert_eq!(Value::Bool(true).as_i64(), None);
        assert_eq!(uint(1).as_bool(), None);
    }

    #[test]
    fn catalog_present_empty_array_differs_from_absent_key() {
        // BEHAVIOR_CATALOG.md FIDO: an explicitly present empty allowList (getAssertion key
        // 3) and an empty minPinLengthRPIDs behave differently from absent ones, so the codec
        // must keep the distinction.
        let present = decode(&h("a2 01 6161 03 80")).unwrap();
        assert_eq!(
            present.map_get_int(3).and_then(Value::as_array),
            Some(&[][..])
        );
        let absent = decode(&h("a1 01 6161")).unwrap();
        assert_eq!(absent.map_get_int(3), None);
    }

    // --- Helpers and MapBuilder -----------------------------------------------------------

    #[test]
    fn integer_helpers_cover_the_full_range() {
        // RFC 8949 §3.1: major type 1 holds -1 - n.
        assert_eq!(Value::int_key(0), uint(0));
        assert_eq!(Value::int_key(-1), Value::Negative(0));
        assert_eq!(Value::int_key(i64::MAX), uint(i64::MAX as u64));
        assert_eq!(Value::int_key(i64::MIN), Value::Negative(i64::MAX as u64));
        assert_eq!(Value::Negative(i64::MAX as u64).as_i64(), Some(i64::MIN));
        assert_eq!(Value::Negative(i64::MAX as u64 + 1).as_i64(), None);
        assert_eq!(Value::Negative(u64::MAX).as_i64(), None);
        assert_eq!(uint(i64::MAX as u64).as_i64(), Some(i64::MAX));
        assert_eq!(uint(u64::MAX).as_i64(), None);
        assert_eq!(uint(u64::MAX).as_u64(), Some(u64::MAX));
        assert_eq!(Value::Negative(0).as_u64(), None);
        assert_eq!(Value::from(-7i32), Value::Negative(6));
        assert_eq!(Value::from(7u8), uint(7));
        assert_eq!(Value::from(7usize), uint(7));
    }

    #[test]
    fn accessor_helpers_match_only_their_type() {
        let value = map(vec![
            (uint(1), bytes(&[1, 2])),
            (text("t"), text("x")),
            (Value::int_key(-1), array(vec![Value::Null])),
            (uint(2), map(vec![])),
            (uint(3), Value::Bool(false)),
        ]);
        assert_eq!(
            value.map_get(&uint(1)).and_then(Value::as_bytes),
            Some(&[1u8, 2][..])
        );
        assert_eq!(value.map_get_text("t").and_then(Value::as_text), Some("x"));
        assert_eq!(
            value.map_get_int(-1).and_then(Value::as_array),
            Some(&[Value::Null][..])
        );
        assert_eq!(value.map_get_int(2).and_then(Value::as_map), Some(&[][..]));
        assert_eq!(value.map_get_int(3).and_then(Value::as_bool), Some(false));
        assert_eq!(value.map_get(&text("missing")), None);
        assert_eq!(uint(1).map_get(&uint(1)), None);
        assert_eq!(text("x").as_bytes(), None);
        assert_eq!(bytes(b"x").as_text(), None);
        assert_eq!(Value::Null.as_array(), None);
        assert_eq!(array(vec![]).as_map(), None);
    }

    #[test]
    fn map_builder_replaces_duplicates_and_skips_none() {
        let built = MapBuilder::new()
            .insert(2, "b")
            .insert(1, "a")
            .insert(2, "c")
            .insert_opt(3, None::<u64>)
            .insert_opt(4, Some(true))
            .insert("nested", MapBuilder::new().insert(1, b"x"))
            .build();
        assert_eq!(
            built,
            map(vec![
                (uint(1), text("a")),
                (uint(2), text("c")),
                (uint(4), Value::Bool(true)),
                (text("nested"), map(vec![(uint(1), bytes(b"x"))])),
            ])
        );
        assert_eq!(decode(&encode(&built)), Ok(built));
    }

    #[test]
    fn map_builder_encode_matches_build() {
        let mut builder = MapBuilder::new();
        assert!(builder.is_empty());
        builder.set(10, vec![Value::from(1u8), Value::from("two")]);
        builder.set(-5, String::from("s"));
        builder.set(&[1u8, 2][..], 0u64);
        assert_eq!(builder.len(), 3);
        let encoded = builder.encode();
        assert_eq!(encoded, encode(&builder.clone().build()));
        assert_eq!(encoded, h("a3 0a 82 01 6374776f 24 6173 420102 00"));
    }

    #[test]
    fn error_display_is_descriptive() {
        assert_eq!(
            CborError::DuplicateKey.to_string(),
            "duplicate CBOR map key"
        );
        let err: Box<dyn std::error::Error> = Box::new(CborError::Truncated);
        assert_eq!(err.to_string(), "CBOR input is truncated");
    }

    // --- Robustness ----------------------------------------------------------------------

    /// xorshift64 (Marsaglia 2003): a deterministic byte source for the fuzz test.
    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    #[test]
    fn random_inputs_never_panic_and_accepted_inputs_re_encode_stably() {
        let mut rng = XorShift(0x5eed_cb0e_2026_1010);
        // Bias towards small heads so that structured items appear often.
        let alphabet = h(
            "00 17 18 19 20 38 40 41 58 60 61 62 78 80 81 82 98 a0 a1 a2 b8 c1 d8 \
                          f4 f5 f6 f7 f9 fa fb ff 1c 7f 9f",
        );
        let mut accepted = 0;
        for _ in 0..20_000 {
            let len = (rng.next() % 24) as usize;
            let input: Vec<u8> = (0..len)
                .map(|_| {
                    let r = rng.next();
                    if r.is_multiple_of(3) {
                        (r >> 8) as u8
                    } else {
                        alphabet[(r >> 8) as usize % alphabet.len()]
                    }
                })
                .collect();
            if let Ok((value, used)) = decode_prefix(&input) {
                assert!(used <= input.len());
                assert_eq!(decode(&input[..used]), Ok(value.clone()));
                let encoded = encode(&value);
                let again = decode(&encoded).unwrap();
                assert_eq!(encode(&again), encoded);
                accepted += 1;
            }
        }
        assert!(accepted > 1000, "only {accepted} inputs decoded");
    }

    // --- Review hardening: boundaries ----------------------------------------------------

    #[test]
    fn integer_extremes_round_trip() {
        // RFC 8949 §3.1: major types 0 and 1 carry a full 64-bit argument, so integers span
        // -2^64 ..= 2^64 - 1; major type 1 holds -1 - n. Shortest form per CTAP 2.1 §8.
        let rows: [(Value, &str, Option<i64>); 9] = [
            (uint(u64::MAX), "1bffffffffffffffff", None),
            (uint(1 << 63), "1b8000000000000000", None),
            (uint(i64::MAX as u64), "1b7fffffffffffffff", Some(i64::MAX)),
            // -2^63 = i64::MIN.
            (
                Value::int_key(i64::MIN),
                "3b7fffffffffffffff",
                Some(i64::MIN),
            ),
            // -2^63 - 1, the first negative integer outside i64.
            (Value::Negative(1 << 63), "3b8000000000000000", None),
            // -2^64, the most negative CBOR integer (RFC 8949 Appendix A).
            (Value::Negative(u64::MAX), "3bffffffffffffffff", None),
            (Value::int_key(-24), "37", Some(-24)),
            (Value::int_key(-25), "3818", Some(-25)),
            (Value::int_key(-65_537), "3a00010000", Some(-65_537)),
        ];
        for (value, hex, as_i64) in rows {
            assert_eq!(encode(&value), h(hex), "encode {hex}");
            assert_eq!(decode(&h(hex)), Ok(value.clone()), "decode {hex}");
            assert_eq!(value.as_i64(), as_i64, "as_i64 {hex}");
        }
        assert_eq!(Value::Negative(u64::MAX).as_u64(), None);
        // Non-minimal forms of the extremes' neighbours are rejected (CTAP 2.1 §8).
        assert_eq!(decode(&h("3b00000000ffffffff")), Err(CborError::NonMinimal));
        assert_eq!(decode(&h("3a0000ffff")), Err(CborError::NonMinimal));
    }

    #[test]
    fn ctap21_mixed_integer_and_text_keys_sort_by_major_type_first() {
        // CTAP 2.1 §8 rule 1 puts every integer key before every byte or text key even
        // when the integer's encoding is longer: 1000 (19 03 e8) sorts before "a" (61 61)
        // and 24 (18 18) before -1 (20) and "" (60). A pure "shorter encoding first" rule
        // (RFC 7049 §3.9) would put "" and -1 first. Within a major type, rules 2 and 3
        // (shorter, then bytewise) apply.
        let entries = vec![
            (text("a"), uint(0)),
            (text(""), uint(0)),
            (Value::Bool(true), uint(0)),
            (Value::int_key(-25), uint(0)),
            (uint(1000), uint(0)),
            (bytes(&[]), uint(0)),
            (Value::int_key(-1), uint(0)),
            (uint(24), uint(0)),
            (text("b"), uint(0)),
            (uint(1), uint(0)),
        ];
        let expected = h("aa 0100 181800 1903e800 2000 381800 4000 6000 616100 616200 f500");
        assert_eq!(encode(&map(entries.clone())), expected);
        let mut builder = MapBuilder::new();
        for (key, value) in entries.into_iter().rev() {
            builder.set(key, value);
        }
        assert_eq!(builder.encode(), expected);
        assert_eq!(encode(&builder.build()), expected);

        assert_eq!(
            canonical_key_order(&h("1903e8"), &h("6161")),
            Ordering::Less
        );
        assert_eq!(canonical_key_order(&h("1818"), &h("20")), Ordering::Less);
        assert_eq!(canonical_key_order(&h("20"), &h("1818")), Ordering::Greater);
        assert_eq!(
            canonical_key_order(&h("6162"), &h("626161")),
            Ordering::Less
        );
        assert_eq!(canonical_key_order(&h("6161"), &h("6161")), Ordering::Equal);
    }

    #[test]
    fn ctap21_order_equals_bytewise_order_for_random_scalar_keys() {
        // CTAP 2.1 §8 note: for major types 0–3 and 7 the three rules equal a lexicographic
        // comparison of the encodings. Checked on random keys around every width boundary.
        let mut rng = XorShift(0x0c7a_9218_0000_0001);
        let mut keys: Vec<Vec<u8>> = (0..2000)
            .map(|_| encode(&random_scalar(&mut rng)))
            .collect();
        let mut bytewise = keys.clone();
        bytewise.sort();
        keys.sort_by(|a, b| canonical_key_order(a, b));
        assert_eq!(keys, bytewise);
    }

    #[test]
    fn nested_empty_containers_round_trip() {
        // RFC 8949 §3.1 and Appendix A ("[]" = 80, "{}" = a0): empty containers as array
        // elements, map keys and values, and tag content.
        let rows = [
            ("8180", array(vec![array(vec![])])),
            ("81a0", array(vec![map(vec![])])),
            ("828080", array(vec![array(vec![]), array(vec![])])),
            ("a100a0", map(vec![(uint(0), map(vec![]))])),
            ("a10080", map(vec![(uint(0), array(vec![]))])),
            ("a180a0", map(vec![(array(vec![]), map(vec![]))])),
            ("a1a080", map(vec![(map(vec![]), array(vec![]))])),
            // [] (major 4) sorts before {} (major 5), CTAP 2.1 §8 rule 1.
            (
                "a2 8000 a000",
                map(vec![(array(vec![]), uint(0)), (map(vec![]), uint(0))]),
            ),
            ("c180", tag(1, array(vec![]))),
            ("824060", array(vec![bytes(&[]), text("")])),
            (
                "81818180",
                array(vec![array(vec![array(vec![array(vec![])])])]),
            ),
        ];
        for (hex, expected) in rows {
            assert_eq!(decode(&h(hex)), Ok(expected.clone()), "decode {hex}");
            assert_eq!(encode(&expected), h(hex), "encode {hex}");
        }
        // Two empty arrays (or maps) as keys are the same key.
        assert_eq!(decode(&h("a2 8000 8001")), Err(CborError::DuplicateKey));
        assert_eq!(decode(&h("a2 a000 a001")), Err(CborError::DuplicateKey));
        // An empty container still counts as a nesting level.
        let mut nine = vec![0x81; MAX_DEPTH];
        nine.push(0xa0);
        assert_eq!(decode(&nine), Err(CborError::DepthExceeded));
    }

    #[test]
    fn decode_prefix_walks_a_stream_of_items() {
        // RFC 8742 §2 (CBOR sequences): decode_prefix returns the exact length of the first
        // item, so consecutive items can be read one after another.
        let items = [
            uint(0),
            uint(24),
            Value::int_key(-257),
            uint(u64::MAX),
            bytes(&[1, 2, 3]),
            text("IETF"),
            array(vec![uint(1), array(vec![])]),
            MapBuilder::new().insert(2, "b").insert(1, "a").build(),
            float(0x3c00, 2),
            float(0x47c3_5000, 4),
            float(0x3ff1_9999_9999_999a, 8),
            Value::Null,
            tag(1, uint(0)),
        ];
        let mut stream = Vec::new();
        let mut ends = Vec::new();
        for item in &items {
            encode_into(item, &mut stream);
            ends.push(stream.len());
        }
        let mut offset = 0;
        for (item, end) in items.iter().zip(&ends) {
            let (value, used) = decode_prefix(&stream[offset..]).unwrap();
            assert_eq!(&value, item);
            offset += used;
            assert_eq!(offset, *end);
        }
        assert_eq!(decode_prefix(&stream[offset..]), Err(CborError::Truncated));
        assert_eq!(decode(&stream), Err(CborError::TrailingBytes));
        // Bytes after the first item are not inspected, even when they are malformed.
        for junk in [0xff, 0x1c, 0x5b, 0x9f, 0xf8] {
            assert_eq!(
                decode_prefix(&[0x82, 0x01, 0x80, junk]),
                Ok((array(vec![uint(1), array(vec![])]), 3))
            );
            assert_eq!(
                decode(&[0x82, 0x01, 0x80, junk]),
                Err(CborError::TrailingBytes)
            );
        }
    }

    #[test]
    fn every_half_float_and_nan_payloads_are_preserved() {
        // CTAP 2.1 §8: "The representations of any floating-point values are not changed",
        // and the 16/32/64-bit size is part of the value. So every half-precision pattern
        // (RFC 8949 §3.3, additional information 25) round-trips, NaN payloads and
        // signalling NaNs are kept (unlike RFC 8949 §4.2.2), and nothing is shortened.
        for bits in 0..=u16::MAX {
            let mut input = vec![0xf9];
            input.extend_from_slice(&bits.to_be_bytes());
            assert_eq!(decode(&input), Ok(float(u64::from(bits), 2)), "{bits:04x}");
            assert_eq!(encode(&float(u64::from(bits), 2)), input, "{bits:04x}");
        }
        for hex in [
            "fa7fc00001",
            "fa7f800001",
            "faffffffff",
            "fa00000001",
            "fa00000000",
            "fa3fc00000",
            "fb7ff8000000000001",
            "fb7ff0000000000001",
            "fbffffffffffffffff",
            "fb0000000000000001",
            "fb8000000000000000",
            "fb3ff8000000000000",
        ] {
            let input = h(hex);
            let value = decode(&input).unwrap();
            assert_eq!(encode(&value), input, "{hex}");
        }
        // A float is neither an integer nor equal to the same number at another size.
        assert_ne!(decode(&h("f93c00")), decode(&h("01")));
        assert_ne!(decode(&h("f93e00")), decode(&h("fa3fc00000")));
        for hex in ["f9", "f93c", "fa", "fa3fc000", "fb", "fb3ff80000000000"] {
            assert_eq!(decode(&h(hex)), Err(CborError::Truncated), "{hex}");
        }
    }

    #[test]
    fn map_builder_merges_keys_with_the_same_encoding() {
        // CTAP 2.1 §8: "All encoders MUST serialize CBOR ... without duplicate map keys".
        // Different Values can share an encoding: a Float with bits above its size (only
        // the low 16 bits are written), and map keys whose entries differ only in order
        // (encode sorts them). The builder must still emit each key once.
        let builder = MapBuilder::new()
            .insert(float(0x1_3c00, 2), 1)
            .insert(float(0x3c00, 2), 2)
            .insert(map(vec![(uint(1), uint(0)), (uint(2), uint(0))]), 3)
            .insert(map(vec![(uint(2), uint(0)), (uint(1), uint(0))]), 4);
        assert_eq!(builder.len(), 2);
        // The map key (major 5) sorts before the float key (major 7); last insert wins.
        let expected = h("a2 a2 0100 0200 04 f93c00 02");
        assert_eq!(builder.encode(), expected);
        let built = builder.build();
        assert_eq!(encode(&built), expected);
        assert!(decode(&expected).is_ok());
        // encode() cannot fail, so a hand-built Value::Map with such keys is written as is
        // and the decoder rejects the result.
        let clash = map(vec![
            (float(0x1_3c00, 2), uint(1)),
            (float(0x3c00, 2), uint(2)),
        ]);
        assert_eq!(decode(&encode(&clash)), Err(CborError::DuplicateKey));
    }

    #[test]
    fn every_short_input_is_handled_and_accepted_items_are_canonical() {
        // No input may panic. An item of at most three bytes cannot be a map with two
        // entries, so every accepted one must be exactly the canonical encoding of its value
        // (CTAP 2.1 §8). The accepted counts follow from RFC 8949 §3:
        // - one byte: 24 + 24 small integers, h'' and "", [] and {}, false/true/null/undefined;
        // - two bytes: 18 xx / 38 xx with xx >= 24 (2 x 232), 41 xx (256), 61 xx with ASCII xx
        //   (128), 81 + a one-byte item (56), c0..d7 + a one-byte item (24 x 56).
        let mut complete = [0usize; 4];
        let mut check = |input: &[u8]| {
            check_decoder_invariants(input);
            if let Ok(value) = decode(input) {
                assert_eq!(encode(&value), input, "{input:02x?}");
                complete[input.len()] += 1;
            }
        };
        for a in 0..=u8::MAX {
            check(&[a]);
            for b in 0..=u8::MAX {
                check(&[a, b]);
                for c in [
                    0x00, 0x17, 0x18, 0x20, 0x41, 0x61, 0x80, 0xa0, 0xc1, 0xf6, 0xf9, 0xff,
                ] {
                    check(&[a, b, c]);
                }
            }
        }
        assert_eq!(complete[1], 56);
        assert_eq!(complete[2], 2 * 232 + 256 + 128 + 56 + 24 * 56);
    }

    // --- Review hardening: structured fuzzing ----------------------------------------------

    /// A random integer argument, biased towards the head-width boundaries of CTAP 2.1 §8.
    fn random_arg(rng: &mut XorShift) -> u64 {
        const EDGES: [u64; 10] = [
            0,
            23,
            24,
            255,
            256,
            65_535,
            65_536,
            0xffff_ffff,
            0x1_0000_0000,
            u64::MAX,
        ];
        let r = rng.next();
        match r % 4 {
            0 => EDGES[(r >> 8) as usize % EDGES.len()],
            1 => (r >> 8) % 24,
            2 => (r >> 8) >> ((r >> 2) % 64),
            _ => rng.next(),
        }
    }

    /// A short random length (strings and containers stay small to keep the test fast).
    fn random_len(rng: &mut XorShift, max: u64) -> usize {
        let r = rng.next();
        let len = if r.is_multiple_of(5) {
            [0, 1, 23, 24][(r >> 8) as usize % 4]
        } else {
            (r >> 8) % max
        };
        usize::try_from(len.min(max)).unwrap()
    }

    /// A random non-container value.
    fn random_scalar(rng: &mut XorShift) -> Value {
        const CHARS: [char; 7] = ['a', 'z', '\0', '\u{7f}', '\u{fc}', '\u{6c34}', '\u{10151}'];
        let r = rng.next();
        match r % 10 {
            0 | 1 => uint(random_arg(rng)),
            2 | 3 => Value::Negative(random_arg(rng)),
            4 => {
                let len = random_len(rng, 30);
                bytes(&(0..len).map(|_| rng.next() as u8).collect::<Vec<_>>())
            }
            5 => {
                let len = random_len(rng, 30);
                let s: String = (0..len)
                    .map(|_| CHARS[(rng.next() >> 8) as usize % CHARS.len()])
                    .collect();
                Value::Text(s)
            }
            6 => [
                Value::Bool(false),
                Value::Bool(true),
                Value::Null,
                Value::Undefined,
            ][(r >> 8) as usize % 4]
                .clone(),
            7 => float(rng.next() & 0xffff, 2),
            8 => float(rng.next() & 0xffff_ffff, 4),
            _ => float(rng.next(), 8),
        }
    }

    /// A random value of at most `levels` nested containers. Maps come from [`MapBuilder`],
    /// so they are in canonical order without duplicate keys, and every value is exactly
    /// what the decoder returns for its encoding (as long as it is not too deep).
    fn random_value(rng: &mut XorShift, levels: usize) -> Value {
        let r = rng.next();
        if levels == 0 || r.is_multiple_of(3) {
            return random_scalar(rng);
        }
        match (r >> 8) % 3 {
            0 => {
                let len = random_len(rng, 5);
                array((0..len).map(|_| random_value(rng, levels - 1)).collect())
            }
            1 => {
                let len = random_len(rng, 5);
                let mut builder = MapBuilder::new();
                for _ in 0..len {
                    // Mostly scalar keys, as in CTAP; sometimes container keys.
                    let key = if rng.next().is_multiple_of(4) {
                        random_value(rng, levels - 1)
                    } else {
                        random_scalar(rng)
                    };
                    builder.set(key, random_value(rng, levels - 1));
                }
                builder.build()
            }
            _ => tag(random_arg(rng), random_value(rng, levels - 1)),
        }
    }

    /// Nesting depth as the decoder counts it: arrays, maps and tags add one level.
    fn depth(value: &Value) -> usize {
        match value {
            Value::Array(items) => 1 + items.iter().map(depth).max().unwrap_or(0),
            Value::Map(entries) => {
                1 + entries
                    .iter()
                    .map(|(k, v)| depth(k).max(depth(v)))
                    .max()
                    .unwrap_or(0)
            }
            Value::Tag(_, inner) => 1 + depth(inner),
            _ => 0,
        }
    }

    /// Whether some map, at any level, holds two keys with the same encoding.
    fn has_duplicate_keys(value: &Value) -> bool {
        match value {
            Value::Array(items) => items.iter().any(has_duplicate_keys),
            Value::Map(entries) => {
                let mut keys: Vec<Vec<u8>> = entries.iter().map(|(k, _)| encode(k)).collect();
                keys.sort();
                keys.windows(2).any(|w| w[0] == w[1])
                    || entries
                        .iter()
                        .any(|(k, v)| has_duplicate_keys(k) || has_duplicate_keys(v))
            }
            Value::Tag(_, inner) => has_duplicate_keys(inner),
            _ => false,
        }
    }

    /// `value` with every map sorted by an independent statement of the CTAP 2.1 §8 rules:
    /// major type, then encoded length, then bytes.
    fn sorted_maps(value: &Value) -> Value {
        match value {
            Value::Array(items) => array(items.iter().map(sorted_maps).collect()),
            Value::Map(entries) => {
                let mut sorted: Vec<(Value, Value)> = entries
                    .iter()
                    .map(|(k, v)| (sorted_maps(k), sorted_maps(v)))
                    .collect();
                sorted.sort_by_key(|(k, _)| {
                    let e = encode(k);
                    (e[0] >> 5, e.len(), e)
                });
                map(sorted)
            }
            Value::Tag(n, inner) => tag(*n, sorted_maps(inner)),
            other => other.clone(),
        }
    }

    /// Properties every input must satisfy, accepted or not.
    fn check_decoder_invariants(input: &[u8]) {
        match decode_prefix(input) {
            Err(err) => assert_eq!(decode(input), Err(err), "{input:02x?}"),
            Ok((value, used)) => {
                assert!((1..=input.len()).contains(&used), "{input:02x?}");
                let item = &input[..used];
                if used == input.len() {
                    assert_eq!(decode(input), Ok(value.clone()));
                } else {
                    assert_eq!(decode(input), Err(CborError::TrailingBytes));
                }
                assert_eq!(decode(item), Ok(value.clone()));
                assert!(depth(&value) <= MAX_DEPTH, "{item:02x?}");
                assert!(!has_duplicate_keys(&value), "{item:02x?}");
                // Heads are minimal, lengths definite and floats unchanged, so re-encoding
                // can only reorder map entries: same length, and identical bytes exactly
                // when every map was already in canonical order (CTAP 2.1 §8).
                let encoded = encode(&value);
                assert_eq!(encoded.len(), used, "{item:02x?}");
                let canonical = sorted_maps(&value);
                assert_eq!(decode(&encoded), Ok(canonical.clone()), "{item:02x?}");
                assert_eq!(encode(&canonical), encoded);
                assert_eq!(encoded == item, canonical == value, "{item:02x?}");
            }
        }
    }

    /// One random byte-level mutation of `input`.
    fn mutate(rng: &mut XorShift, input: &[u8]) -> Vec<u8> {
        const INTERESTING: [u8; 12] = [
            0x00, 0x17, 0x18, 0x1b, 0x1c, 0x1f, 0x5b, 0x7b, 0x9b, 0xbb, 0xf8, 0xff,
        ];
        let mut out = input.to_vec();
        let at = |rng: &mut XorShift, len: usize| (rng.next() as usize) % len.max(1);
        match rng.next() % 7 {
            0 if !out.is_empty() => {
                let i = at(rng, out.len());
                out[i] ^= 1 << (rng.next() % 8);
            }
            1 if !out.is_empty() => {
                let i = at(rng, out.len());
                out[i] = INTERESTING[(rng.next() as usize) % INTERESTING.len()];
            }
            2 => {
                let i = at(rng, out.len() + 1);
                out.insert(i.min(out.len()), rng.next() as u8);
            }
            3 if !out.is_empty() => {
                let i = at(rng, out.len());
                out.remove(i);
            }
            4 => out.truncate(at(rng, out.len() + 1)),
            5 if !out.is_empty() => {
                let start = at(rng, out.len());
                let end = (start + at(rng, 8) + 1).min(out.len());
                let copy = out[start..end].to_vec();
                let i = at(rng, out.len() + 1).min(out.len());
                out.splice(i..i, copy);
            }
            _ => {
                let i = at(rng, out.len());
                out.splice(i.min(out.len())..i.min(out.len()), [rng.next() as u8; 2]);
            }
        }
        out
    }

    #[test]
    fn generated_values_round_trip_and_their_mutations_never_panic() {
        // Canonical inputs (CTAP 2.1 §8) are generated from random values, including values
        // one level deeper than MAX_DEPTH. Each must decode back to the same value and
        // re-encode to the same bytes; then byte-level mutations of it must satisfy
        // check_decoder_invariants (no panic, strict acceptance, stable re-encoding).
        let mut rng = XorShift(0x1d5e_ed00_cb0e_f022);
        let (mut too_deep, mut accepted_mutants, mut maps) = (0, 0, 0);
        for _ in 0..3000 {
            let value = random_value(&mut rng, MAX_DEPTH + 1);
            let encoded = encode(&value);
            if depth(&value) > MAX_DEPTH {
                assert_eq!(decode(&encoded), Err(CborError::DepthExceeded));
                too_deep += 1;
            } else {
                assert_eq!(decode(&encoded), Ok(value.clone()), "{encoded:02x?}");
                assert_eq!(encode(&decode(&encoded).unwrap()), encoded);
                if matches!(value, Value::Map(ref m) if m.len() > 1) {
                    maps += 1;
                }
            }
            check_decoder_invariants(&encoded);
            for _ in 0..20 {
                let mutant = mutate(&mut rng, &encoded);
                check_decoder_invariants(&mutant);
                accepted_mutants += usize::from(decode(&mutant).is_ok());
            }
        }
        assert!(too_deep > 10, "only {too_deep} values beyond MAX_DEPTH");
        assert!(maps > 100, "only {maps} multi-entry maps");
        assert!(
            accepted_mutants > 1000,
            "only {accepted_mutants} mutants accepted"
        );
    }

    #[test]
    fn swapped_map_entries_decode_and_re_encode_canonically() {
        // A canonical map with two entries swapped is still accepted (non-canonical order
        // is not on the reject list) and re-encodes to the canonical bytes (CTAP 2.1 §8).
        let mut rng = XorShift(0x5a5a_0000_1111_2222);
        let mut swapped = 0;
        for _ in 0..500 {
            let Value::Map(entries) = random_value(&mut rng, 3) else {
                continue;
            };
            if entries.len() < 2 || depth(&Value::Map(entries.clone())) > MAX_DEPTH {
                continue;
            }
            let canonical = encode(&Value::Map(entries.clone()));
            let mut reordered = entries.clone();
            reordered.swap(0, entries.len() - 1);
            let mut input = Vec::new();
            write_head(&mut input, MAJOR_MAP, usize_to_u64(reordered.len()));
            for (k, v) in &reordered {
                encode_into(k, &mut input);
                encode_into(v, &mut input);
            }
            assert_ne!(input, canonical);
            assert_eq!(decode(&input), Ok(Value::Map(reordered)));
            assert_eq!(encode(&decode(&input).unwrap()), canonical);
            check_decoder_invariants(&input);
            swapped += 1;
        }
        assert!(swapped > 20, "only {swapped} maps swapped");
    }
}
