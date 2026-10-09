//! DER encoder and minimal reader (ITU-T X.690).
//!
//! The encoder side is a set of free functions that each return one complete
//! tag-length-value element. Constructed values ([`sequence`], [`set`], [`set_of`],
//! [`explicit`]) take already-encoded elements, so certificates and other structures are
//! built bottom-up:
//!
//! ```
//! use lk_codec::der;
//! let alg = der::sequence([der::oid(&[1, 3, 101, 112])]);
//! assert_eq!(alg, [0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70]);
//! ```
//!
//! Only the low-tag-number form (tag numbers 0–30, X.690 §8.1.2.2) is supported, which
//! covers every type used by X.509 (RFC 5280), PKCS and FIDO. Tags are therefore single
//! identifier octets ([`u8`]), including the class and constructed bits.
//!
//! The reader ([`parse_der`] and helpers) enforces the DER length rules of X.690 §10.1:
//! definite form only, minimal number of length octets.

use core::fmt;

/// Identifier octets for the universal types used here (X.680 §8.6 Table 1, X.690 §8.1.2).
pub mod tag {
    /// BOOLEAN (universal 1).
    pub const BOOLEAN: u8 = 0x01;
    /// INTEGER (universal 2).
    pub const INTEGER: u8 = 0x02;
    /// BIT STRING (universal 3, primitive in DER per X.690 §10.2).
    pub const BIT_STRING: u8 = 0x03;
    /// OCTET STRING (universal 4, primitive in DER per X.690 §10.2).
    pub const OCTET_STRING: u8 = 0x04;
    /// NULL (universal 5).
    pub const NULL: u8 = 0x05;
    /// OBJECT IDENTIFIER (universal 6).
    pub const OID: u8 = 0x06;
    /// UTF8String (universal 12).
    pub const UTF8_STRING: u8 = 0x0C;
    /// PrintableString (universal 19).
    pub const PRINTABLE_STRING: u8 = 0x13;
    /// IA5String (universal 22).
    pub const IA5_STRING: u8 = 0x16;
    /// UTCTime (universal 23).
    pub const UTC_TIME: u8 = 0x17;
    /// GeneralizedTime (universal 24).
    pub const GENERALIZED_TIME: u8 = 0x18;
    /// SEQUENCE and SEQUENCE OF (universal 16, constructed).
    pub const SEQUENCE: u8 = 0x30;
    /// SET and SET OF (universal 17, constructed).
    pub const SET: u8 = 0x31;
}

/// Largest tag number that fits the low-tag-number form (X.690 §8.1.2.2). The context-tag
/// builders use the high-tag-number form (X.690 §8.1.2.4) above it.
pub const MAX_LOW_TAG_NUMBER: u8 = 30;

const CLASS_CONTEXT: u8 = 0x80;
const CONSTRUCTED: u8 = 0x20;
const TAG_NUMBER_MASK: u8 = 0x1F;

/// Errors from the DER reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerError {
    /// The input ended inside the identifier, length or value octets.
    Truncated,
    /// The indefinite length form `80` was used; DER forbids it (X.690 §10.1).
    IndefiniteLength,
    /// The length was not encoded in the minimum number of octets (X.690 §10.1).
    NonMinimalLength,
    /// The length needs more than four length octets.
    LengthOverflow,
    /// The identifier uses the high-tag-number form (X.690 §8.1.2.4), which is unsupported.
    HighTagNumber,
    /// The identifier is universal tag number 0, reserved for the end-of-contents octets of
    /// the indefinite form (X.680 §8.6 Table 1, X.690 §8.1.5), which DER never uses.
    ReservedTag,
    /// An element had a different tag than the caller required.
    UnexpectedTag {
        /// The tag the caller asked for.
        expected: u8,
        /// The tag found in the input.
        found: u8,
    },
    /// Data remained after the element(s) the caller expected.
    TrailingData,
    /// An OBJECT IDENTIFIER was empty, non-minimal, truncated or out of range (X.690 §8.19).
    InvalidOid,
    /// An INTEGER was empty, non-minimal (X.690 §8.3.2) or negative where unsigned was required.
    InvalidInteger,
    /// A BIT STRING had a bad unused-bits octet or nonzero padding bits (X.690 §8.6.2, §11.2.1).
    InvalidBitString,
}

impl fmt::Display for DerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("DER element truncated"),
            Self::IndefiniteLength => f.write_str("indefinite length is not allowed in DER"),
            Self::NonMinimalLength => f.write_str("DER length is not minimally encoded"),
            Self::LengthOverflow => f.write_str("DER length uses more than four octets"),
            Self::HighTagNumber => f.write_str("high-tag-number form is not supported"),
            Self::ReservedTag => {
                f.write_str("universal tag 0 (end-of-contents) is not allowed in DER")
            }
            Self::UnexpectedTag { expected, found } => {
                write!(f, "expected DER tag {expected:#04x}, found {found:#04x}")
            }
            Self::TrailingData => f.write_str("trailing data after DER element"),
            Self::InvalidOid => f.write_str("invalid OBJECT IDENTIFIER encoding"),
            Self::InvalidInteger => f.write_str("invalid INTEGER encoding"),
            Self::InvalidBitString => f.write_str("invalid BIT STRING encoding"),
        }
    }
}

impl std::error::Error for DerError {}

// ---------------------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------------------

/// Length octets in the minimal definite form (X.690 §8.1.3.4, §8.1.3.5, §10.1).
///
/// Lengths up to 127 use the short form; longer ones use `0x80 | n` followed by `n`
/// big-endian octets with no leading zero.
pub fn encode_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        // Short form: the length is the single octet itself.
        return vec![len as u8];
    }
    let bytes = len.to_be_bytes();
    let skip = bytes.iter().take_while(|&&b| b == 0).count();
    let significant = &bytes[skip..];
    let mut out = Vec::with_capacity(1 + significant.len());
    out.push(0x80 | significant.len() as u8);
    out.extend_from_slice(significant);
    out
}

/// One element: identifier octet, minimal length, then `value` as the contents octets.
pub fn element(tag: u8, value: &[u8]) -> Vec<u8> {
    element_with_identifier(&[tag], value)
}

/// One element with identifier octets of any length (X.690 §8.1.2).
fn element_with_identifier(identifier: &[u8], value: &[u8]) -> Vec<u8> {
    let len = encode_len(value.len());
    let mut out = Vec::with_capacity(identifier.len() + len.len() + value.len());
    out.extend_from_slice(identifier);
    out.extend_from_slice(&len);
    out.extend_from_slice(value);
    out
}

fn concat<I, T>(items: I) -> Vec<u8>
where
    I: IntoIterator<Item = T>,
    T: AsRef<[u8]>,
{
    let mut out = Vec::new();
    for item in items {
        out.extend_from_slice(item.as_ref());
    }
    out
}

/// SEQUENCE (or SEQUENCE OF) of already-encoded elements, kept in the given order
/// (X.690 §8.9, §8.10).
pub fn sequence<I, T>(items: I) -> Vec<u8>
where
    I: IntoIterator<Item = T>,
    T: AsRef<[u8]>,
{
    element(tag::SEQUENCE, &concat(items))
}

/// SET of already-encoded elements with distinct tags, ordered by tag as DER requires
/// (X.690 §10.3, canonical tag order of X.680 §8.6: class first, then tag number).
pub fn set<I, T>(items: I) -> Vec<u8>
where
    I: IntoIterator<Item = T>,
    T: AsRef<[u8]>,
{
    let mut items: Vec<T> = items.into_iter().collect();
    items.sort_by_key(|item| tag_order(item.as_ref()));
    element(tag::SET, &concat(items))
}

/// The `(class, tag number)` sort key of an encoded element for [`set`] (X.680 §8.6),
/// reading the high-tag-number form of X.690 §8.1.2.4 as well, so that `[31]` sorts before
/// `[128]`.
fn tag_order(element: &[u8]) -> (u8, u128) {
    let Some((&first, subsequent)) = element.split_first() else {
        return (0, 0);
    };
    let class = first >> 6;
    if first & TAG_NUMBER_MASK != TAG_NUMBER_MASK {
        return (class, u128::from(first & TAG_NUMBER_MASK));
    }
    let mut number: u128 = 0;
    // At most 18 base-128 octets (126 bits) are read, so the shift cannot overflow.
    for &octet in subsequent.iter().take(18) {
        number = (number << 7) | u128::from(octet & 0x7F);
        if octet & 0x80 == 0 {
            break;
        }
    }
    (class, number)
}

/// SET OF already-encoded elements, sorted by their encodings as DER requires (X.690 §11.6).
///
/// X.690 compares encodings as octet strings with the shorter one padded with trailing zero
/// octets. Plain lexicographic order gives the same result here, because two complete
/// elements that compare equal under that padding are interchangeable.
pub fn set_of<I, T>(items: I) -> Vec<u8>
where
    I: IntoIterator<Item = T>,
    T: AsRef<[u8]>,
{
    let mut items: Vec<T> = items.into_iter().collect();
    items.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
    element(tag::SET, &concat(items))
}

/// INTEGER from an unsigned big-endian magnitude (X.690 §8.3).
///
/// Leading zero octets are stripped, a `00` octet is prepended when the high bit of the
/// first remaining octet is set (so the value stays non-negative), and zero (including an
/// empty slice) encodes as `02 01 00`.
pub fn integer(unsigned_be: &[u8]) -> Vec<u8> {
    let skip = unsigned_be.iter().take_while(|&&b| b == 0).count();
    let magnitude = &unsigned_be[skip..];
    let mut content = Vec::with_capacity(magnitude.len() + 1);
    match magnitude.first() {
        None => content.push(0),
        Some(&first) => {
            if first & 0x80 != 0 {
                content.push(0);
            }
            content.extend_from_slice(magnitude);
        }
    }
    element(tag::INTEGER, &content)
}

/// INTEGER from a `u64` (X.690 §8.3), e.g. the certificate version or a path length.
pub fn integer_u64(value: u64) -> Vec<u8> {
    integer(&value.to_be_bytes())
}

/// BOOLEAN; DER encodes TRUE as `FF` (X.690 §8.2, §11.1).
pub fn boolean(value: bool) -> Vec<u8> {
    element(tag::BOOLEAN, &[if value { 0xFF } else { 0x00 }])
}

/// NULL, `05 00` (X.690 §8.8).
pub fn null() -> Vec<u8> {
    element(tag::NULL, &[])
}

/// BIT STRING of whole octets, with an unused-bits octet of 0 (X.690 §8.6).
///
/// This is the form used for keys and signatures (RFC 5280 §4.1.1.3, §4.1.2.7).
pub fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(bytes.len() + 1);
    content.push(0);
    content.extend_from_slice(bytes);
    element(tag::BIT_STRING, &content)
}

/// BIT STRING for a named bit list such as `KeyUsage` (X.690 §8.6, §11.2.2).
///
/// Bit `n` of `bits` is ASN.1 named bit `n`, where bit 0 is the most significant bit of the
/// first contents octet. DER removes trailing zero bits, so the unused-bits octet counts the
/// padding after the highest set bit; an empty set encodes as `03 01 00`.
pub fn named_bit_string(bits: u64) -> Vec<u8> {
    if bits == 0 {
        return element(tag::BIT_STRING, &[0]);
    }
    let highest = 63 - bits.leading_zeros() as usize;
    let octets = highest / 8 + 1;
    let mut content = vec![0u8; octets + 1];
    content[0] = (7 - highest % 8) as u8;
    for n in 0..=highest {
        if bits & (1 << n) != 0 {
            content[1 + n / 8] |= 0x80 >> (n % 8);
        }
    }
    element(tag::BIT_STRING, &content)
}

/// OCTET STRING (X.690 §8.7).
pub fn octet_string(bytes: &[u8]) -> Vec<u8> {
    element(tag::OCTET_STRING, bytes)
}

/// Appends `value` in base 128, most significant group first, with bit 8 set on every
/// octet except the last (X.690 §8.19.2).
fn push_base128(out: &mut Vec<u8>, value: u128) {
    let mut groups = Vec::with_capacity(19);
    let mut rest = value;
    loop {
        groups.push((rest & 0x7F) as u8);
        rest >>= 7;
        if rest == 0 {
            break;
        }
    }
    let last = groups.len() - 1;
    for (i, group) in groups.iter().rev().enumerate() {
        out.push(if i < last { group | 0x80 } else { *group });
    }
}

/// The contents octets of an OBJECT IDENTIFIER (X.690 §8.19), without tag and length.
///
/// Useful for comparing against the value returned by [`parse_der`]. See [`oid`] for the
/// rules on `arcs`.
pub fn oid_value(arcs: &[u64]) -> Vec<u8> {
    let mut out = Vec::new();
    let (first, rest): (u128, &[u64]) = match arcs {
        [] => return out,
        [x] => (u128::from(*x) * 40, &[]),
        [x, y, rest @ ..] => (u128::from(*x) * 40 + u128::from(*y), rest),
    };
    // X.690 §8.19.4: the first two arcs X.Y share one subidentifier, 40 * X + Y.
    push_base128(&mut out, first);
    for &arc in rest {
        push_base128(&mut out, u128::from(arc));
    }
    out
}

/// OBJECT IDENTIFIER from its arcs, e.g. `oid(&[1, 2, 840, 10045, 2, 1])` (X.690 §8.19).
///
/// The arcs must form a valid OID: at least two arcs, the first 0, 1 or 2, and the second
/// below 40 unless the first is 2. Valid input is the caller's job, as with the other
/// builders; invalid input still encodes without panicking, by the `40 * X + Y` formula, but
/// it is meaningless. Use [`oid_dotted`] for checked input.
pub fn oid(arcs: &[u64]) -> Vec<u8> {
    element(tag::OID, &oid_value(arcs))
}

/// Whether `arcs` is a valid OID: at least two arcs, first arc 0–2, second arc below 40
/// when the first is 0 or 1 (X.660 §A.2, X.690 §8.19.4).
pub fn oid_is_valid(arcs: &[u64]) -> bool {
    match arcs {
        [0 | 1, second, ..] => *second < 40,
        [2, _, ..] => true,
        _ => false,
    }
}

/// OBJECT IDENTIFIER from dotted decimal text such as `"1.3.101.112"`, checked with
/// [`oid_is_valid`].
///
/// Each arc is a decimal number without leading zeros (the `numericoid` form of RFC 4512
/// §1.4), so that the text and the encoding correspond one to one.
pub fn oid_dotted(dotted: &str) -> Result<Vec<u8>, DerError> {
    let mut arcs = Vec::new();
    for part in dotted.split('.') {
        let canonical = match part.as_bytes() {
            [] => false,
            [b'0', _, ..] => false,
            digits => digits.iter().all(u8::is_ascii_digit),
        };
        if !canonical {
            return Err(DerError::InvalidOid);
        }
        arcs.push(part.parse::<u64>().map_err(|_| DerError::InvalidOid)?);
    }
    if !oid_is_valid(&arcs) {
        return Err(DerError::InvalidOid);
    }
    Ok(oid(&arcs))
}

/// UTF8String (X.680 §41, X.690 §8.23).
pub fn utf8_string(text: &str) -> Vec<u8> {
    element(tag::UTF8_STRING, text.as_bytes())
}

/// Whether `text` uses only the PrintableString characters of X.680 §41.4 Table 10:
/// `A–Z a–z 0–9`, space and `' ( ) + , - . / : = ?`.
pub fn is_printable_string(text: &str) -> bool {
    text.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(&b))
}

/// PrintableString (X.680 §41.4). The caller keeps `text` within [`is_printable_string`].
pub fn printable_string(text: &str) -> Vec<u8> {
    element(tag::PRINTABLE_STRING, text.as_bytes())
}

/// IA5String (X.680 §41.4), used for e-mail addresses and URIs in RFC 5280.
pub fn ia5_string(text: &str) -> Vec<u8> {
    element(tag::IA5_STRING, text.as_bytes())
}

/// GeneralizedTime from its string form as given, e.g. `"20500101000000Z"`
/// (X.680 §46, X.690 §11.7; RFC 5280 §4.1.2.5.2 requires `YYYYMMDDHHMMSSZ`).
pub fn generalized_time(text: &str) -> Vec<u8> {
    element(tag::GENERALIZED_TIME, text.as_bytes())
}

/// UTCTime from its string form as given, e.g. `"160801121924Z"`
/// (X.680 §47, X.690 §11.8; RFC 5280 §4.1.2.5.1 requires `YYMMDDHHMMSSZ`).
pub fn utc_time(text: &str) -> Vec<u8> {
    element(tag::UTC_TIME, text.as_bytes())
}

/// The first identifier octet of context-specific tag `[number]` (X.690 §8.1.2).
///
/// For `number` up to [`MAX_LOW_TAG_NUMBER`] this is the whole identifier (§8.1.2.2). For
/// larger numbers it is the leading octet of the high-tag-number form, with tag-number bits
/// `11111` (§8.1.2.4.1). [`parse_der`] rejects that form, so the value never equals a parsed
/// tag and cannot be mistaken for a different `[n]`.
pub fn context_tag(number: u8, constructed: bool) -> u8 {
    let constructed = if constructed { CONSTRUCTED } else { 0 };
    CLASS_CONTEXT | constructed | number.min(TAG_NUMBER_MASK)
}

/// All identifier octets of context-specific tag `[number]`: one octet up to tag number 30,
/// otherwise the leading octet followed by the number in base 128 (X.690 §8.1.2.4.2).
fn context_identifier(number: u8, constructed: bool) -> Vec<u8> {
    let mut identifier = vec![context_tag(number, constructed)];
    if number > MAX_LOW_TAG_NUMBER {
        push_base128(&mut identifier, u128::from(number));
    }
    identifier
}

/// Explicitly tagged `[number] EXPLICIT`: a constructed context-specific element wrapping
/// the complete encoding `inner` (X.690 §8.14.2, e.g. the certificate version `[0]`).
pub fn explicit(number: u8, inner: &[u8]) -> Vec<u8> {
    element_with_identifier(&context_identifier(number, true), inner)
}

/// Implicitly tagged `[number] IMPLICIT` of a primitive type: `content` is the contents
/// octets of the underlying type (X.690 §8.14.3, e.g. `keyIdentifier [0]` in RFC 5280
/// §4.2.1.1 is `80 len id`).
pub fn implicit(number: u8, content: &[u8]) -> Vec<u8> {
    element_with_identifier(&context_identifier(number, false), content)
}

/// Implicitly tagged `[number] IMPLICIT` of a constructed type (SEQUENCE, SET): `content`
/// is the concatenated inner elements (X.690 §8.14.3).
pub fn implicit_constructed(number: u8, content: &[u8]) -> Vec<u8> {
    element_with_identifier(&context_identifier(number, true), content)
}

// ---------------------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------------------

/// Decodes the length octets at the start of `input`, returning the length and the number of
/// length octets (X.690 §8.1.3, with the DER minimality rule of §10.1).
fn decode_len(input: &[u8]) -> Result<(usize, usize), DerError> {
    let (&first, rest) = input.split_first().ok_or(DerError::Truncated)?;
    if first < 0x80 {
        return Ok((usize::from(first), 1));
    }
    let count = usize::from(first & 0x7F);
    if count == 0 {
        return Err(DerError::IndefiniteLength);
    }
    if count > 4 {
        return Err(DerError::LengthOverflow);
    }
    let octets = rest.get(..count).ok_or(DerError::Truncated)?;
    if octets[0] == 0 {
        return Err(DerError::NonMinimalLength);
    }
    let len = octets
        .iter()
        .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
    if len < 0x80 {
        return Err(DerError::NonMinimalLength);
    }
    Ok((len, 1 + count))
}

/// Parses one element at the start of `input`: `(tag, value, rest)`.
///
/// `tag` is the identifier octet (class, constructed bit and tag number), `value` the
/// contents octets and `rest` whatever follows the element. Lengths must be definite and
/// minimal (X.690 §10.1); the high-tag-number form and the reserved universal tag 0
/// (end-of-contents) are rejected.
pub fn parse_der(input: &[u8]) -> Result<(u8, &[u8], &[u8]), DerError> {
    let (&tag, after_tag) = input.split_first().ok_or(DerError::Truncated)?;
    if tag & TAG_NUMBER_MASK == TAG_NUMBER_MASK {
        return Err(DerError::HighTagNumber);
    }
    if tag & !CONSTRUCTED == 0 {
        return Err(DerError::ReservedTag);
    }
    let (len, len_octets) = decode_len(after_tag)?;
    let body = &after_tag[len_octets..];
    if body.len() < len {
        return Err(DerError::Truncated);
    }
    let (value, rest) = body.split_at(len);
    Ok((tag, value, rest))
}

/// Splits off the complete first element (identifier, length and contents) of `input`:
/// `(element, rest)`. Signature checks need the raw bytes, e.g. a certificate's
/// `tbsCertificate` (RFC 5280 §4.1.1.3).
pub fn split_der(input: &[u8]) -> Result<(&[u8], &[u8]), DerError> {
    let (_, _, rest) = parse_der(input)?;
    Ok(input.split_at(input.len() - rest.len()))
}

/// Parses one element that must carry `tag`: `(value, rest)`.
pub fn expect(input: &[u8], tag: u8) -> Result<(&[u8], &[u8]), DerError> {
    let (found, value, rest) = parse_der(input)?;
    if found != tag {
        return Err(DerError::UnexpectedTag {
            expected: tag,
            found,
        });
    }
    Ok((value, rest))
}

/// Parses exactly one element carrying `tag` that fills all of `input`, returning its value.
pub fn expect_only(input: &[u8], tag: u8) -> Result<&[u8], DerError> {
    let (value, rest) = expect(input, tag)?;
    if !rest.is_empty() {
        return Err(DerError::TrailingData);
    }
    Ok(value)
}

/// Parses consecutive elements until `input` is used up, e.g. the contents of a SEQUENCE:
/// a list of `(tag, value)`.
pub fn parse_all(input: &[u8]) -> Result<Vec<(u8, &[u8])>, DerError> {
    let mut out = Vec::new();
    let mut rest = input;
    while !rest.is_empty() {
        let (tag, value, next) = parse_der(rest)?;
        out.push((tag, value));
        rest = next;
    }
    Ok(out)
}

/// Decodes the contents octets of an OBJECT IDENTIFIER into its arcs (X.690 §8.19).
///
/// Rejects an empty value, subidentifiers with a leading `80` octet (non-minimal), a
/// truncated final subidentifier and arcs that do not fit in a `u64`.
pub fn decode_oid(value: &[u8]) -> Result<Vec<u64>, DerError> {
    if value.is_empty() {
        return Err(DerError::InvalidOid);
    }
    let mut subidentifiers = Vec::new();
    let mut current: u128 = 0;
    let mut start = true;
    for &octet in value {
        if start && octet == 0x80 {
            return Err(DerError::InvalidOid);
        }
        if current > u128::from(u64::MAX) {
            return Err(DerError::InvalidOid);
        }
        current = (current << 7) | u128::from(octet & 0x7F);
        start = octet & 0x80 == 0;
        if start {
            subidentifiers.push(current);
            current = 0;
        }
    }
    if !start {
        return Err(DerError::InvalidOid);
    }
    let mut arcs = Vec::with_capacity(subidentifiers.len() + 1);
    let mut iter = subidentifiers.into_iter();
    let first = iter.next().ok_or(DerError::InvalidOid)?;
    // X.690 §8.19.4: first subidentifier = 40 * X + Y, X in 0..=2, Y < 40 unless X = 2.
    let (x, y) = match first {
        0..40 => (0, first),
        40..80 => (1, first - 40),
        _ => (2, first - 80),
    };
    arcs.push(x);
    arcs.push(u64::try_from(y).map_err(|_| DerError::InvalidOid)?);
    for sub in iter {
        arcs.push(u64::try_from(sub).map_err(|_| DerError::InvalidOid)?);
    }
    Ok(arcs)
}

/// Decodes the contents octets of a non-negative INTEGER into its unsigned big-endian
/// magnitude, without the `00` sign octet (zero decodes to `[0]`).
///
/// Rejects an empty value, non-minimal encodings (X.690 §8.3.2) and negative numbers.
pub fn decode_unsigned(value: &[u8]) -> Result<&[u8], DerError> {
    match value {
        [] => Err(DerError::InvalidInteger),
        [first, ..] if first & 0x80 != 0 => Err(DerError::InvalidInteger),
        [0x00, second, ..] if second & 0x80 == 0 => Err(DerError::InvalidInteger),
        [0x00, rest @ ..] if !rest.is_empty() => Ok(rest),
        _ => Ok(value),
    }
}

/// Decodes the contents octets of a BIT STRING: `(unused_bits, octets)` (X.690 §8.6.2).
///
/// Rejects an unused-bits count above 7, a nonzero count with no octets, and nonzero
/// padding bits (DER, X.690 §11.2.1).
pub fn decode_bit_string(value: &[u8]) -> Result<(u8, &[u8]), DerError> {
    let (&unused, octets) = value.split_first().ok_or(DerError::InvalidBitString)?;
    if unused > 7 {
        return Err(DerError::InvalidBitString);
    }
    match octets.last() {
        None if unused != 0 => Err(DerError::InvalidBitString),
        Some(&last) if last & ((1u8 << unused) - 1) != 0 => Err(DerError::InvalidBitString),
        _ => Ok((unused, octets)),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        digits
            .chunks(2)
            .map(|pair| {
                let pair = core::str::from_utf8(pair).expect("ascii hex");
                u8::from_str_radix(pair, 16).expect("hex digit")
            })
            .collect()
    }

    // X.690 §8.1.3.4 (short form up to 127) and §8.1.3.5 (long form), minimal per §10.1.
    #[test]
    fn length_boundaries() {
        assert_eq!(encode_len(0), [0x00]);
        assert_eq!(encode_len(127), [0x7F]);
        assert_eq!(encode_len(128), [0x81, 0x80]);
        assert_eq!(encode_len(255), [0x81, 0xFF]);
        assert_eq!(encode_len(256), [0x82, 0x01, 0x00]);
        assert_eq!(encode_len(65535), [0x82, 0xFF, 0xFF]);
        assert_eq!(encode_len(65536), [0x83, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn element_headers_at_length_boundaries() {
        for (len, header) in [
            (127usize, &[0x04, 0x7F][..]),
            (128, &[0x04, 0x81, 0x80]),
            (255, &[0x04, 0x81, 0xFF]),
            (256, &[0x04, 0x82, 0x01, 0x00]),
            (65535, &[0x04, 0x82, 0xFF, 0xFF]),
        ] {
            let value = vec![0xA5; len];
            let encoded = octet_string(&value);
            assert_eq!(&encoded[..header.len()], header, "length {len}");
            assert_eq!(encoded.len(), header.len() + len);
            let (tag, parsed, rest) = parse_der(&encoded).expect("parse");
            assert_eq!(tag, tag::OCTET_STRING);
            assert_eq!(parsed, value.as_slice());
            assert!(rest.is_empty());
        }
    }

    // X.690 §8.3.2: two's complement in the minimum number of octets, so a positive value
    // whose top bit is set gets a leading 00.
    #[test]
    fn integers() {
        assert_eq!(integer(&[]), [0x02, 0x01, 0x00]);
        assert_eq!(integer(&[0]), [0x02, 0x01, 0x00]);
        assert_eq!(integer(&[0, 0, 0]), [0x02, 0x01, 0x00]);
        assert_eq!(integer(&[127]), [0x02, 0x01, 0x7F]);
        assert_eq!(integer(&[128]), [0x02, 0x02, 0x00, 0x80]);
        assert_eq!(integer(&[255]), [0x02, 0x02, 0x00, 0xFF]);
        assert_eq!(integer(&[1, 0]), [0x02, 0x02, 0x01, 0x00]);
        assert_eq!(integer(&[0, 0, 1, 0]), [0x02, 0x02, 0x01, 0x00]);
        assert_eq!(integer_u64(0), [0x02, 0x01, 0x00]);
        assert_eq!(integer_u64(2), [0x02, 0x01, 0x02]);
        assert_eq!(integer_u64(256), [0x02, 0x02, 0x01, 0x00]);
        assert_eq!(
            integer_u64(u64::MAX),
            hex("02 09 00 FF FF FF FF FF FF FF FF")
        );
    }

    #[test]
    fn decode_unsigned_round_trips_and_rejects_bad_forms() {
        for value in [&[0u8][..], &[127], &[128], &[255], &[1, 0], &[0x80, 0, 0]] {
            let encoded = integer(value);
            let content = expect_only(&encoded, tag::INTEGER).expect("integer");
            assert_eq!(decode_unsigned(content).expect("unsigned"), value);
        }
        assert_eq!(decode_unsigned(&[]), Err(DerError::InvalidInteger));
        assert_eq!(
            decode_unsigned(&[0x00, 0x7F]),
            Err(DerError::InvalidInteger)
        );
        assert_eq!(decode_unsigned(&[0xFF]), Err(DerError::InvalidInteger));
    }

    // X.690 §8.2.2 and §11.1: DER TRUE is FF. §8.8: NULL has no contents.
    #[test]
    fn boolean_and_null() {
        assert_eq!(boolean(true), [0x01, 0x01, 0xFF]);
        assert_eq!(boolean(false), [0x01, 0x01, 0x00]);
        assert_eq!(null(), [0x05, 0x00]);
    }

    // X.690 §8.6.2 and §11.2.2. The keyAgreement vector `03 02 03 08` is the keyUsage
    // extension value of the RFC 8410 §10.2 example certificate.
    #[test]
    fn bit_strings() {
        assert_eq!(bit_string(&[]), [0x03, 0x01, 0x00]);
        assert_eq!(bit_string(&[0x04, 0xAB]), [0x03, 0x03, 0x00, 0x04, 0xAB]);
        assert_eq!(named_bit_string(0), [0x03, 0x01, 0x00]);
        // digitalSignature (bit 0) only: one octet 80, seven unused bits.
        assert_eq!(named_bit_string(1 << 0), [0x03, 0x02, 0x07, 0x80]);
        // keyAgreement (bit 4).
        assert_eq!(named_bit_string(1 << 4), [0x03, 0x02, 0x03, 0x08]);
        // keyCertSign (5) | cRLSign (6).
        assert_eq!(
            named_bit_string((1 << 5) | (1 << 6)),
            [0x03, 0x02, 0x01, 0x06]
        );
        // digitalSignature (0) | decipherOnly (8) spans two octets, 7 unused bits.
        assert_eq!(
            named_bit_string((1 << 0) | (1 << 8)),
            [0x03, 0x03, 0x07, 0x80, 0x80]
        );
        // Bit 7 fills the first octet exactly.
        assert_eq!(named_bit_string(1 << 7), [0x03, 0x02, 0x00, 0x01]);
    }

    #[test]
    fn decode_bit_string_checks_padding() {
        assert_eq!(decode_bit_string(&[0x03, 0x08]), Ok((3, &[0x08][..])));
        assert_eq!(decode_bit_string(&[0x00]), Ok((0, &[][..])));
        assert_eq!(decode_bit_string(&[]), Err(DerError::InvalidBitString));
        assert_eq!(
            decode_bit_string(&[0x08, 0x00]),
            Err(DerError::InvalidBitString)
        );
        assert_eq!(decode_bit_string(&[0x01]), Err(DerError::InvalidBitString));
        assert_eq!(
            decode_bit_string(&[0x03, 0x09]),
            Err(DerError::InvalidBitString)
        );
    }

    // Object identifier vectors, each with its source.
    #[test]
    fn object_identifiers() {
        let cases: &[(&[u64], &str)] = &[
            // X.690 §8.19.5 example: {joint-iso-itu-t 100 3}, 2*40+100 = 180 -> 81 34.
            (&[2, 100, 3], "06 03 81 34 03"),
            // RFC 5480 §2.1.1 id-ecPublicKey.
            (&[1, 2, 840, 10045, 2, 1], "06 07 2A 86 48 CE 3D 02 01"),
            // RFC 5480 §2.1.1.1 secp256r1.
            (
                &[1, 2, 840, 10045, 3, 1, 7],
                "06 08 2A 86 48 CE 3D 03 01 07",
            ),
            // RFC 5480 §2.1.1.1 secp384r1 (contains a zero arc).
            (&[1, 3, 132, 0, 34], "06 05 2B 81 04 00 22"),
            // RFC 8410 §3: "30 05 06 03 2B 65 6E" (X25519) and "30 05 06 03 2B 65 70" (Ed25519).
            (&[1, 3, 101, 110], "06 03 2B 65 6E"),
            (&[1, 3, 101, 112], "06 03 2B 65 70"),
            // RFC 5758 §3.2 ecdsa-with-SHA256 / SHA384.
            (
                &[1, 2, 840, 10045, 4, 3, 2],
                "06 08 2A 86 48 CE 3D 04 03 02",
            ),
            (
                &[1, 2, 840, 10045, 4, 3, 3],
                "06 08 2A 86 48 CE 3D 04 03 03",
            ),
            // RFC 8017 Appendix C rsaEncryption and RFC 4055 §5 sha256WithRSAEncryption.
            (
                &[1, 2, 840, 113549, 1, 1, 1],
                "06 09 2A 86 48 86 F7 0D 01 01 01",
            ),
            (
                &[1, 2, 840, 113549, 1, 1, 11],
                "06 09 2A 86 48 86 F7 0D 01 01 0B",
            ),
            // RFC 5754 §2 id-sha256 (first arc 2).
            (
                &[2, 16, 840, 1, 101, 3, 4, 2, 1],
                "06 09 60 86 48 01 65 03 04 02 01",
            ),
            // WebAuthn §8.2.1 id-fido-gen-ce-aaguid 1.3.6.1.4.1.45724.1.1.4.
            (
                &[1, 3, 6, 1, 4, 1, 45724, 1, 1, 4],
                "06 0B 2B 06 01 04 01 82 E5 1C 01 01 04",
            ),
            // RFC 5280 §4.1.2.4 id-at-commonName.
            (&[2, 5, 4, 3], "06 03 55 04 03"),
        ];
        for &(arcs, expected) in cases {
            let encoded = oid(arcs);
            assert_eq!(encoded, hex(expected), "{arcs:?}");
            let value = expect_only(&encoded, tag::OID).expect("oid element");
            assert_eq!(decode_oid(value).expect("decode"), arcs);
            let dotted: Vec<String> = arcs.iter().map(u64::to_string).collect();
            assert_eq!(oid_dotted(&dotted.join(".")).expect("dotted"), encoded);
        }
    }

    #[test]
    fn oid_edge_cases() {
        // Largest arcs round-trip through the u128 first subidentifier.
        let arcs = [2, u64::MAX - 80, u64::MAX];
        assert_eq!(decode_oid(&oid_value(&arcs)).expect("decode"), arcs);
        // Degenerate input must not panic.
        assert_eq!(oid(&[]), [0x06, 0x00]);
        assert_eq!(oid(&[1]), [0x06, 0x01, 0x28]);
        // Checked text form.
        for bad in [
            "",
            "1",
            "3.1",
            "1.40",
            "1..2",
            "1.2.",
            "+1.2",
            "1.a",
            "1.2.99999999999999999999",
            // RFC 4512 §1.4 numericoid: no leading zeros, so text and encoding match 1:1.
            "1.02",
            "01.2",
            "1.2.840.010045",
            "1.2.00",
        ] {
            assert_eq!(oid_dotted(bad), Err(DerError::InvalidOid), "{bad:?}");
        }
        assert!(oid_dotted("2.999").is_ok());
        assert_eq!(oid_dotted("0.0"), Ok(vec![0x06, 0x01, 0x00]));
        assert_eq!(oid_dotted("1.2.0.10"), Ok(oid(&[1, 2, 0, 10])));
        // Decoder rejects empty, non-minimal (leading 80) and truncated subidentifiers.
        assert_eq!(decode_oid(&[]), Err(DerError::InvalidOid));
        assert_eq!(decode_oid(&[0x2B, 0x80, 0x01]), Err(DerError::InvalidOid));
        assert_eq!(decode_oid(&[0x2B, 0x86]), Err(DerError::InvalidOid));
        let too_big = [
            0x2B, 0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00,
        ];
        assert_eq!(decode_oid(&too_big), Err(DerError::InvalidOid));
    }

    // X.680 §41.4 PrintableString, §41 UTF8String; RFC 5280 §4.1.2.5 time formats.
    #[test]
    fn strings_and_times() {
        assert_eq!(
            utf8_string("IETF Test Demo"),
            hex("0C 0E 49 45 54 46 20 54 65 73 74 20 44 65 6D 6F")
        );
        assert_eq!(printable_string("US"), [0x13, 0x02, b'U', b'S']);
        assert_eq!(ia5_string("a@b"), [0x16, 0x03, b'a', b'@', b'b']);
        assert!(is_printable_string("Yubico AB (SE) 1+2=3?"));
        assert!(!is_printable_string("a@b"));
        assert!(!is_printable_string("é"));
        // RFC 8410 §10.2 validity fields.
        assert_eq!(
            utc_time("160801121924Z"),
            hex("17 0D 31 36 30 38 30 31 31 32 31 39 32 34 5A")
        );
        assert_eq!(
            generalized_time("20500101000000Z"),
            hex("18 0F 32 30 35 30 30 31 30 31 30 30 30 30 30 30 5A")
        );
    }

    // X.690 §8.14: [0] EXPLICIT wraps the whole inner TLV (certificate version, RFC 5280
    // §4.1), [0] IMPLICIT replaces the tag (AuthorityKeyIdentifier keyIdentifier).
    #[test]
    fn context_tags() {
        assert_eq!(explicit(0, &integer_u64(2)), [0xA0, 0x03, 0x02, 0x01, 0x02]);
        assert_eq!(implicit(0, &[0x11, 0x22]), [0x80, 0x02, 0x11, 0x22]);
        assert_eq!(implicit_constructed(1, &null()), [0xA1, 0x02, 0x05, 0x00]);
        assert_eq!(context_tag(3, true), 0xA3);
        assert_eq!(context_tag(30, false), 0x9E);
    }

    // X.690 §11.6: SET OF components ascend by encoding; §10.3: SET by tag.
    #[test]
    fn set_ordering() {
        let a = integer_u64(1);
        let b = integer_u64(256);
        let c = octet_string(&[0]);
        assert_eq!(
            set_of([&b, &c, &a]),
            [&[0x31, 0x0A][..], &a, &b, &c].concat()
        );
        // Sorting by full encoding: 02 01 05 < 02 02 01 00.
        assert_eq!(
            set_of([integer_u64(256), integer_u64(5)]),
            hex("31 07 02 01 05 02 02 01 00")
        );
        // SET by tag: context [0] after universal, [1] constructed after [0] primitive.
        let ctx1 = implicit_constructed(1, &[]);
        let ctx0 = implicit(0, &[]);
        assert_eq!(
            set([&ctx1, &ctx0, &a]),
            [&[0x31, 0x07][..], &a, &ctx0, &ctx1].concat()
        );
        assert_eq!(sequence(Vec::<Vec<u8>>::new()), [0x30, 0x00]);
    }

    #[test]
    fn reader_enforces_der_lengths() {
        assert_eq!(parse_der(&[]), Err(DerError::Truncated));
        assert_eq!(parse_der(&[0x04]), Err(DerError::Truncated));
        assert_eq!(parse_der(&[0x04, 0x02, 0x00]), Err(DerError::Truncated));
        assert_eq!(
            parse_der(&[0x30, 0x80, 0x00, 0x00]),
            Err(DerError::IndefiniteLength)
        );
        assert_eq!(
            parse_der(&[0x04, 0x81, 0x7F]),
            Err(DerError::NonMinimalLength)
        );
        assert_eq!(
            parse_der(&[0x04, 0x82, 0x00, 0xFF]),
            Err(DerError::NonMinimalLength)
        );
        assert_eq!(
            parse_der(&[0x04, 0x85, 1, 0, 0, 0, 0]),
            Err(DerError::LengthOverflow)
        );
        assert_eq!(parse_der(&[0x04, 0x82, 0x01]), Err(DerError::Truncated));
        assert_eq!(parse_der(&[0x1F, 0x22, 0x00]), Err(DerError::HighTagNumber));
        assert_eq!(parse_der(&[0xBF, 0x20, 0x00]), Err(DerError::HighTagNumber));

        let (tag, value, rest) = parse_der(&[0x02, 0x01, 0x05, 0xAA]).expect("parse");
        assert_eq!((tag, value, rest), (0x02, &[0x05][..], &[0xAA][..]));
        assert_eq!(
            split_der(&[0x02, 0x01, 0x05, 0xAA]),
            Ok((&[0x02, 0x01, 0x05][..], &[0xAA][..]))
        );
        assert_eq!(
            expect(&[0x02, 0x01, 0x05], tag::SEQUENCE),
            Err(DerError::UnexpectedTag {
                expected: 0x30,
                found: 0x02
            })
        );
        assert_eq!(
            expect_only(&[0x05, 0x00, 0x00], tag::NULL),
            Err(DerError::TrailingData)
        );
    }

    #[test]
    fn nested_structure_round_trip() {
        let encoded = sequence([
            explicit(0, &integer_u64(2)),
            oid(&[1, 3, 101, 112]),
            bit_string(&[1, 2]),
        ]);
        let content = expect_only(&encoded, tag::SEQUENCE).expect("sequence");
        let items = parse_all(content).expect("items");
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].0, context_tag(0, true));
        assert_eq!(expect_only(items[0].1, tag::INTEGER), Ok(&[0x02][..]));
        assert_eq!(items[1], (tag::OID, &[0x2B, 0x65, 0x70][..]));
        assert_eq!(decode_bit_string(items[2].1), Ok((0, &[1, 2][..])));
        assert_eq!(parse_all(&[0x05, 0x00, 0x04]), Err(DerError::Truncated));
    }

    #[test]
    fn errors_display() {
        let message = DerError::UnexpectedTag {
            expected: 0x30,
            found: 0x02,
        }
        .to_string();
        assert_eq!(message, "expected DER tag 0x30, found 0x02");
    }
    // X.690 §8.19.2: each subidentifier is base 128, high bit set on all but the last octet,
    // and minimal. Boundaries of 1, 2, 3 and 4 octets (2^7, 2^14, 2^21), plus the combined
    // first subidentifier 40 * X + Y of §8.19.4 crossing 127.
    #[test]
    fn oid_subidentifier_boundaries() {
        let cases: &[(&[u64], &str)] = &[
            (&[1, 2, 127], "2A 7F"),
            (&[1, 2, 128], "2A 81 00"),
            (&[1, 2, 16383], "2A FF 7F"),
            (&[1, 2, 16384], "2A 81 80 00"),
            (&[1, 2, 2097151], "2A FF FF 7F"),
            (&[1, 2, 2097152], "2A 81 80 80 00"),
            (&[1, 39], "4F"),
            (&[2, 0], "50"),
            (&[2, 47], "7F"),
            (&[2, 48], "81 00"),
            // 80 + 16304 = 16384 needs three octets.
            (&[2, 16304], "81 80 00"),
            // u64::MAX = 2^64 - 1 takes ten octets, the first holding the top bit.
            (&[1, 2, u64::MAX], "2A 81 FF FF FF FF FF FF FF FF 7F"),
        ];
        for &(arcs, expected) in cases {
            let value = hex(expected);
            assert_eq!(oid_value(arcs), value, "{arcs:?}");
            assert_eq!(decode_oid(&value).expect("decode"), arcs, "{arcs:?}");
        }
        // 2^64 itself does not fit an arc.
        assert_eq!(
            decode_oid(&hex("2A 82 80 80 80 80 80 80 80 80 00")),
            Err(DerError::InvalidOid)
        );
        // X.690 §8.19.2: a leading 80 octet is non-minimal in every subidentifier position.
        assert_eq!(decode_oid(&hex("80 2A")), Err(DerError::InvalidOid));
        assert_eq!(decode_oid(&hex("2A 80 7F")), Err(DerError::InvalidOid));
    }

    // X.690 §8.1.2.4: tag numbers above 30 use the high-tag-number form, leading octet with
    // tag bits 11111 followed by the number in minimal base 128.
    #[test]
    fn high_context_tag_numbers() {
        assert_eq!(explicit(30, &null()), [0xBE, 0x02, 0x05, 0x00]);
        assert_eq!(explicit(31, &null()), [0xBF, 0x1F, 0x02, 0x05, 0x00]);
        assert_eq!(implicit(127, &[0xAA]), [0x9F, 0x7F, 0x01, 0xAA]);
        assert_eq!(implicit(128, &[]), [0x9F, 0x81, 0x00, 0x00]);
        assert_eq!(implicit_constructed(255, &[]), [0xBF, 0x81, 0x7F, 0x00]);
        // context_tag gives the leading octet only, which the reader never returns, so it
        // cannot alias [30].
        assert_eq!(context_tag(31, true), 0xBF);
        assert_eq!(context_tag(200, false), 0x9F);
        assert_ne!(context_tag(31, true), context_tag(30, true));
        assert_eq!(
            parse_der(&explicit(31, &null())),
            Err(DerError::HighTagNumber)
        );
        // X.690 §10.3 / X.680 §8.6: SET orders by tag number, also in the high form, so
        // [30] < [31] < [128] < [255] whatever the input order.
        let t30 = implicit(30, &[]);
        let t31 = implicit(31, &[]);
        let t128 = implicit(128, &[]);
        let t255 = implicit_constructed(255, &[]);
        assert_eq!(
            set([&t255, &t128, &t31, &t30]),
            [&[0x31, 0x0D][..], &t30, &t31, &t128, &t255].concat()
        );
    }

    // X.690 §10.1 (definite, minimal lengths), §8.1.3.5 c) (FF is reserved), §8.1.5 and
    // X.680 §8.6 Table 1 (universal 0 is end-of-contents only).
    #[test]
    fn reader_rejects_more_non_der_forms() {
        for (input, error) in [
            (&[0x00, 0x00][..], DerError::ReservedTag),
            (&[0x20, 0x00], DerError::ReservedTag),
            (
                &[0x24, 0x80, 0x04, 0x00, 0x00, 0x00],
                DerError::IndefiniteLength,
            ),
            (&[0x04, 0x83, 0x00, 0xFF, 0xFF], DerError::NonMinimalLength),
            (
                &[0x04, 0x84, 0x00, 0x01, 0x00, 0x00],
                DerError::NonMinimalLength,
            ),
            (&[0x04, 0x82, 0x00, 0x80], DerError::NonMinimalLength),
            (&[0x04, 0x81, 0x00], DerError::NonMinimalLength),
            (&[0x04, 0xFF], DerError::LengthOverflow),
            (&[0x04, 0x81], DerError::Truncated),
            (&[0x04, 0x83, 0x01, 0x00], DerError::Truncated),
            (&[0x04, 0x81, 0x80], DerError::Truncated),
            (&[0x30, 0x03, 0x02, 0x01], DerError::Truncated),
        ] {
            assert_eq!(parse_der(input), Err(error), "{input:02X?}");
            assert_eq!(parse_all(input), Err(error), "{input:02X?}");
            assert_eq!(split_der(input), Err(error), "{input:02X?}");
        }
        // A 128-byte value with the minimal `81 80` length is accepted.
        let mut long = vec![0x04, 0x81, 0x80];
        long.extend_from_slice(&[0; 128]);
        assert_eq!(
            expect_only(&long, tag::OCTET_STRING).map(<[u8]>::len),
            Ok(128)
        );
        // Element lengths are relative to the element: a nested truncation is caught when
        // the contents are parsed.
        assert_eq!(
            expect_only(&[0x30, 0x02, 0x04, 0x05], tag::SEQUENCE).and_then(parse_all),
            Err(DerError::Truncated)
        );
    }

    // X.690 §8.3.2: no leading 00 unless the next octet's top bit is set, no leading FF.
    // RFC 5280 §4.1.2.2: a 20-octet serial with the top bit set needs 21 contents octets.
    #[test]
    fn integer_sign_handling() {
        assert_eq!(integer(&[0x00, 0x80]), [0x02, 0x02, 0x00, 0x80]);
        assert_eq!(integer(&[0x00, 0x7F]), [0x02, 0x01, 0x7F]);
        assert_eq!(integer(&[0, 0, 0xFF, 0x01]), [0x02, 0x03, 0x00, 0xFF, 0x01]);
        assert_eq!(
            integer(&[0x80, 0, 0, 0, 0, 0, 0, 0]),
            hex("02 09 00 80 00 00 00 00 00 00 00")
        );
        let serial = [0xFF; 20];
        let encoded = integer(&serial);
        assert_eq!(encoded[..3], [0x02, 0x15, 0x00]);
        assert_eq!(decode_unsigned(&encoded[2..]), Ok(&serial[..]));
        for negative_or_bad in [
            &[0x80][..],
            &[0xFF, 0x7F],
            &[0xFF, 0x80],
            &[0x00, 0x00],
            &[0x00, 0x00, 0x80],
        ] {
            assert_eq!(
                decode_unsigned(negative_or_bad),
                Err(DerError::InvalidInteger),
                "{negative_or_bad:02X?}"
            );
        }
        assert_eq!(decode_unsigned(&[0x00]), Ok(&[0x00][..]));
        assert_eq!(decode_unsigned(&[0x00, 0x80]), Ok(&[0x80][..]));
    }

    // X.690 §11.2.2: a named bit list drops trailing zero bits, so the last used bit is
    // set and §11.2.1 padding is zero. Checked for every 16-bit value (KeyUsage needs 9).
    #[test]
    fn named_bit_strings_are_minimal_for_every_u16() {
        for bits in 0..=u64::from(u16::MAX) {
            let encoded = named_bit_string(bits);
            let value = expect_only(&encoded, tag::BIT_STRING).expect("bit string");
            let (unused, octets) = decode_bit_string(value).expect("valid padding");
            let mut decoded = 0u64;
            for (n, octet) in octets.iter().enumerate() {
                for bit in 0..8 {
                    if octet & (0x80 >> bit) != 0 {
                        decoded |= 1 << (n * 8 + bit);
                    }
                }
            }
            assert_eq!(decoded, bits);
            match octets.last() {
                None => assert_eq!((bits, unused), (0, 0)),
                Some(last) => assert_ne!(last & (1 << unused), 0, "trailing zero bit {bits:#x}"),
            }
        }
        // Bit 63 is the last bit of the eighth octet.
        assert_eq!(
            named_bit_string(1 << 63),
            hex("03 09 00 00 00 00 00 00 00 00 01")
        );
    }

    // X.690 §11.6: SET OF orders by the encodings padded with trailing zeros, not by length
    // first; so a longer INTEGER precedes a shorter PrintableString.
    #[test]
    fn set_of_orders_by_padded_encoding() {
        let long_integer = integer_u64(256); // 02 02 01 00
        let short_string = printable_string("A"); // 13 01 41
        assert_eq!(
            set_of([&short_string, &long_integer]),
            hex("31 07 02 02 01 00 13 01 41")
        );
        // Same tag: 04 01 FF before 04 02 00 00 because 01 < 02 at the length octet.
        assert_eq!(
            set_of([octet_string(&[0, 0]), octet_string(&[0xFF])]),
            hex("31 07 04 01 FF 04 02 00 00")
        );
        // Duplicates are kept (SET OF allows them) and the input order does not matter.
        let a = set_of([integer_u64(7), integer_u64(3), integer_u64(7)]);
        let b = set_of([integer_u64(7), integer_u64(7), integer_u64(3)]);
        assert_eq!(a, b);
        assert_eq!(a, hex("31 09 02 01 03 02 01 07 02 01 07"));
    }

    /// xorshift64 (Marsaglia 2003): deterministic bytes for the no-panic tests.
    pub(crate) struct XorShift(pub(crate) u64);

    impl XorShift {
        pub(crate) fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }

    /// Checks the decoders on one contents field: whatever they accept must re-encode to
    /// exactly the same bytes, because DER has one encoding per value.
    fn check_contents(value: &[u8]) {
        if let Ok(arcs) = decode_oid(value) {
            assert_eq!(oid_value(&arcs), value, "OID {value:02X?}");
        }
        if let Ok(magnitude) = decode_unsigned(value) {
            assert_eq!(integer(magnitude), element(tag::INTEGER, value));
        }
        if let Ok((unused, octets)) = decode_bit_string(value) {
            assert!(unused <= 7);
            match octets.last() {
                None => assert_eq!(unused, 0),
                Some(last) => assert_eq!(last & ((1 << unused) - 1), 0),
            }
            if unused == 0 {
                assert_eq!(bit_string(octets), element(tag::BIT_STRING, value));
            }
        }
    }

    /// Walks every element the reader accepts in `input`, descending into constructed ones,
    /// and asserts that each re-encodes to its exact input bytes (minimal lengths, X.690
    /// §10.1). Returns the number of accepted elements. Never panics on malformed input.
    pub(crate) fn walk_canonical(input: &[u8], depth: usize) -> usize {
        let mut accepted = 0;
        let mut rest = input;
        while let Ok((tag, value, next)) = parse_der(rest) {
            let raw = &rest[..rest.len() - next.len()];
            assert_eq!(element(tag, value), raw, "re-encoding of {raw:02X?}");
            assert_eq!(split_der(rest), Ok((raw, next)));
            assert_eq!(expect(rest, tag), Ok((value, next)));
            check_contents(value);
            if tag & CONSTRUCTED != 0 && depth < 16 {
                accepted += walk_canonical(value, depth + 1);
            }
            accepted += 1;
            rest = next;
        }
        if rest.is_empty() {
            assert!(parse_all(input).is_ok());
        } else {
            assert!(parse_all(input).is_err());
        }
        accepted
    }

    // Fixed-seed robustness test: random and structure-biased inputs must never panic, and
    // everything the reader accepts must be canonical DER.
    #[test]
    fn random_inputs_never_panic_and_accepted_inputs_are_canonical() {
        let mut rng = XorShift(0x0de2_5eed_2026_1010);
        let alphabet = hex(
            "00 01 02 03 04 05 06 0C 13 16 17 18 1F 20 24 30 31 7F 80 81 82 83 84 85 \
             A0 A1 A3 BF FF 2A 86 48",
        );
        let mut accepted = 0;
        for _ in 0..30_000 {
            let len = (rng.next() % 40) as usize;
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
            accepted += walk_canonical(&input, 0);
            check_contents(&input);
            let _ = expect_only(&input, tag::SEQUENCE);
        }
        assert!(accepted > 5_000, "only {accepted} elements accepted");

        // Dotted OID text: accepted text must be canonical, so decoding gives it back.
        let digits = b"0123456789..";
        for _ in 0..20_000 {
            let len = (rng.next() % 14) as usize;
            let text: String = (0..len)
                .map(|_| char::from(digits[(rng.next() >> 8) as usize % digits.len()]))
                .collect();
            if let Ok(encoded) = oid_dotted(&text) {
                let value = expect_only(&encoded, tag::OID).expect("oid element");
                let arcs = decode_oid(value).expect("decodes");
                let again: Vec<String> = arcs.iter().map(u64::to_string).collect();
                assert_eq!(again.join("."), text);
            }
        }
    }
}
