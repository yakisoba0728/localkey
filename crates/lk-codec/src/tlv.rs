//! BER-TLV (ISO/IEC 7816-4 §5.2.2, with the BER rules of ITU-T X.690 §8.1).
//!
//! A data object is `tag || length || value`:
//!
//! - **Tag** (§5.2.2.1): one to three bytes. If bits b5..b1 of the first byte are all
//!   set (`0x1F`), the tag continues; every subsequent byte except the last has bit b8
//!   (`0x80`) set. The tag is kept as a `u32` holding the bytes exactly as written, so
//!   the class and constructed bits stay in place (`0x7F49`, `0x5FC109`, `0x9F7F`).
//!   Tag numbers are not otherwise validated, so the parser accepts every tag that
//!   fits in three bytes. In particular, §5.2.2.1 calls the second-byte values
//!   `00..=1E` and `80` invalid (tag numbers that a shorter tag could hold, as in
//!   EMV's `9F02`). They are still accepted, because the tag is only ever compared and
//!   re-emitted byte for byte, and rejecting it would only turn odd but harmless host
//!   data into a parse error.
//! - **Length** (§5.2.2.2): the short form `0x00..=0x7F`, or the long forms `0x81 XX`,
//!   `0x82 XX XX` and `0x83 XX XX XX`. The indefinite form `0x80` and the forms
//!   `0x84..=0xFF` are rejected. A long form that a shorter form could have expressed
//!   (for example `81 05`) is accepted when parsing: the §5.2.2.2 table gives `81` the
//!   range `00..=FF` and `82` the range `0000..=FFFF`, and BER allows it too (ITU-T
//!   X.690 §8.1.3.5). [`encode`] always writes the shortest form.
//!
//! Padding bytes (`00` or `FF`) that §5.2.2 allows before, between or after data
//! objects are not skipped. A `00` byte is parsed as the one-byte tag `0x00`. An
//! `FF` byte starts a multi-byte tag (its low five bits are all set). Callers that
//! read padded data, such as an erased file, must strip the padding first.
//!
//! Section numbers follow ISO/IEC 7816-4:2005.

use std::fmt;

/// Longest tag field this module accepts, in bytes (ISO/IEC 7816-4 §5.2.2.1).
const MAX_TAG_BYTES: usize = 3;

/// Largest number of length bytes after a `0x8N` long-form marker (§5.2.2.2).
const MAX_LENGTH_BYTES: usize = 3;

/// One BER-TLV data object borrowed from an input buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// The tag bytes as written, big-endian (`5F 52` is `0x5F52`).
    pub tag: u32,
    /// The value field.
    pub value: &'a [u8],
    /// The whole data object: tag, length and value.
    pub raw: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// Whether the tag marks a constructed data object: bit b6 (`0x20`) of the first
    /// tag byte (ISO/IEC 7816-4 §5.2.2.1).
    pub fn is_constructed(&self) -> bool {
        first_tag_byte(self.tag) & 0x20 != 0
    }

    /// Parse the value field as a sequence of data objects, as for a constructed
    /// object's contents.
    pub fn children(&self) -> Result<Vec<Tlv<'a>>, TlvError> {
        parse_all(self.value)
    }
}

/// Why a BER-TLV buffer could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlvError {
    /// The input ended inside a tag, a length field or a value.
    Truncated,
    /// The tag field is longer than three bytes.
    TagTooLong,
    /// The length byte was `0x80`, the indefinite form.
    IndefiniteLength,
    /// The length byte was `0x84` or higher: more than three length bytes.
    UnsupportedLength,
}

impl fmt::Display for TlvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Truncated => "truncated BER-TLV data object",
            Self::TagTooLong => "BER-TLV tag longer than three bytes",
            Self::IndefiniteLength => "indefinite BER-TLV length",
            Self::UnsupportedLength => "BER-TLV length field longer than three bytes",
        };
        f.write_str(text)
    }
}

impl std::error::Error for TlvError {}

/// Parse the first data object of `input` and return it with the bytes that follow.
///
/// Empty input is [`TlvError::Truncated`].
pub fn parse_one(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), TlvError> {
    let (tag, tag_len) = parse_tag(input)?;
    let after_tag = input.get(tag_len..).ok_or(TlvError::Truncated)?;
    let (value_len, len_len) = parse_length(after_tag)?;
    let header_len = tag_len + len_len;
    let total = header_len
        .checked_add(value_len)
        .ok_or(TlvError::Truncated)?;
    let raw = input.get(..total).ok_or(TlvError::Truncated)?;
    let value = raw.get(header_len..).ok_or(TlvError::Truncated)?;
    let rest = input.get(total..).ok_or(TlvError::Truncated)?;
    Ok((Tlv { tag, value, raw }, rest))
}

/// Parse a concatenation of data objects that must fill `input` exactly.
///
/// Empty input yields an empty list.
pub fn parse_all(input: &[u8]) -> Result<Vec<Tlv<'_>>, TlvError> {
    let mut items = Vec::new();
    let mut rest = input;
    while !rest.is_empty() {
        let (item, next) = parse_one(rest)?;
        items.push(item);
        rest = next;
    }
    Ok(items)
}

/// The first data object in `items` with `tag`.
pub fn find<'t, 'a>(items: &'t [Tlv<'a>], tag: u32) -> Option<&'t Tlv<'a>> {
    items.iter().find(|item| item.tag == tag)
}

/// Encode one data object: the tag bytes as written, the shortest length form, then
/// `value`.
///
/// The tag is written as the big-endian bytes of `tag` without leading zero bytes
/// (`0x7F49` becomes `7F 49`; `0x00` becomes a single `00`). The tag is not checked:
/// `tag` must be a well-formed 1–3 byte tag as written (§5.2.2.1), otherwise
/// [`parse_one`] will not read the output back (for example, `0x1F` alone announces a
/// second tag byte).
pub fn encode(tag: u32, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAX_TAG_BYTES + 1 + MAX_LENGTH_BYTES + value.len());
    encode_into(&mut out, tag, value);
    out
}

/// Append one encoded data object to `out` (see [`encode`]).
pub fn encode_into(out: &mut Vec<u8>, tag: u32, value: &[u8]) {
    out.extend_from_slice(&encode_tag(tag));
    out.extend_from_slice(&encode_len(value.len()));
    out.extend_from_slice(value);
}

/// The tag bytes for `tag`: its big-endian bytes without leading zero bytes, at least
/// one byte.
pub fn encode_tag(tag: u32) -> Vec<u8> {
    let bytes = tag.to_be_bytes();
    let skip = bytes.iter().take_while(|&&b| b == 0).count().min(3);
    bytes.get(skip..).unwrap_or(&[0]).to_vec()
}

/// The shortest length field for `len` (ISO/IEC 7816-4 §5.2.2.2).
///
/// Lengths up to `0xFF_FFFF` use the short form or `81`/`82`/`83`, which [`parse_one`]
/// reads back. Larger lengths, which no smart-card object reaches, are written in the
/// BER long form `8N` with as many bytes as needed (X.690 §8.1.3.5); [`parse_one`]
/// rejects those.
pub fn encode_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        // Short form: one byte, b8 clear.
        return vec![len as u8];
    }
    let bytes = len.to_be_bytes();
    let skip = bytes.iter().take_while(|&&b| b == 0).count();
    let significant = bytes.get(skip..).unwrap_or(&[]);
    let mut out = Vec::with_capacity(1 + significant.len());
    out.push(0x80 | significant.len() as u8);
    out.extend_from_slice(significant);
    out
}

/// Decode the tag field at the start of `input`; returns the tag and its byte count.
fn parse_tag(input: &[u8]) -> Result<(u32, usize), TlvError> {
    let first = *input.first().ok_or(TlvError::Truncated)?;
    let mut tag = u32::from(first);
    let mut len = 1;
    if first & 0x1F != 0x1F {
        return Ok((tag, len));
    }
    loop {
        if len == MAX_TAG_BYTES {
            return Err(TlvError::TagTooLong);
        }
        let byte = *input.get(len).ok_or(TlvError::Truncated)?;
        tag = (tag << 8) | u32::from(byte);
        len += 1;
        if byte & 0x80 == 0 {
            return Ok((tag, len));
        }
    }
}

/// Decode the length field at the start of `input`; returns the value length and the
/// length field's byte count.
fn parse_length(input: &[u8]) -> Result<(usize, usize), TlvError> {
    let first = *input.first().ok_or(TlvError::Truncated)?;
    if first < 0x80 {
        return Ok((usize::from(first), 1));
    }
    let count = usize::from(first & 0x7F);
    if count == 0 {
        return Err(TlvError::IndefiniteLength);
    }
    if count > MAX_LENGTH_BYTES {
        return Err(TlvError::UnsupportedLength);
    }
    let bytes = input.get(1..=count).ok_or(TlvError::Truncated)?;
    let len = bytes
        .iter()
        .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
    Ok((len, 1 + count))
}

/// The first byte of a tag held as a `u32` (see [`encode_tag`]).
fn first_tag_byte(tag: u32) -> u8 {
    tag.to_be_bytes().into_iter().find(|&b| b != 0).unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Decode a hex string (test helper).
    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // --- Tags (ISO/IEC 7816-4 §5.2.2.1) ---

    #[test]
    fn single_byte_tag() {
        // Synthetic object per §5.2.2: tag 0x5C (PIV tag list), short length 3.
        let input = hex("5C 03 5FC109");
        let (tlv, rest) = parse_one(&input).unwrap();
        assert_eq!(tlv.tag, 0x5C);
        assert_eq!(tlv.value, hex("5FC109"));
        assert_eq!(tlv.raw, &input[..]);
        assert!(rest.is_empty());
        assert!(!tlv.is_constructed());
    }

    #[test]
    fn two_byte_tag_keeps_constructed_bit() {
        // reference/yubikey-5c-nano-5.7.4/openpgp-reference-observation.json,
        // public_objects["7f74"] = "810120": DO 7F74 (constructed, 0x7F has b6 set)
        // wrapping the simple DO 81 01 20.
        let input = hex("7F74 03 810120");
        let (tlv, rest) = parse_one(&input).unwrap();
        assert_eq!(tlv.tag, 0x7F74);
        assert!(tlv.is_constructed());
        assert_eq!(tlv.value, hex("810120"));
        assert!(rest.is_empty());
        let inner = tlv.children().unwrap();
        assert_eq!(inner.len(), 1);
        assert_eq!(inner[0].tag, 0x81);
        assert_eq!(inner[0].value, [0x20]);
    }

    #[test]
    fn two_byte_primitive_tag() {
        // reference/.../openpgp-reference-observation.json, public_objects["5f52"]
        // (historical bytes, primitive DO 5F52, 8 value bytes).
        let input = hex("5F52 08 00730000e0059000");
        let (tlv, _) = parse_one(&input).unwrap();
        assert_eq!(tlv.tag, 0x5F52);
        assert!(!tlv.is_constructed());
        assert_eq!(tlv.value, hex("00730000e0059000"));

        // reference/.../security-domain-reference-observation.json, command
        // "00ca9f7f00": GET DATA for CPLC tag 9F7F (0x9F has b5..b1 = 0x1F).
        let input = hex("9F7F 00");
        let (tlv, _) = parse_one(&input).unwrap();
        assert_eq!(tlv.tag, 0x9F7F);
        assert!(tlv.value.is_empty());
    }

    #[test]
    fn three_byte_tag() {
        // NIST SP 800-73-4 Part 1 §3: PIV data object tags 5FC1xx (5FC109 is Printed
        // Information). §5.2.2.1: 0xC1 has b8 set, so the tag continues.
        let input = hex("5FC109 02 AABB");
        let (tlv, rest) = parse_one(&input).unwrap();
        assert_eq!(tlv.tag, 0x5F_C109);
        assert_eq!(tlv.value, [0xAA, 0xBB]);
        assert!(rest.is_empty());
        assert_eq!(encode(0x5F_C109, &[0xAA, 0xBB]), input);
    }

    #[test]
    fn four_byte_tag_is_rejected() {
        // §5.2.2.1 continuation: 5F 81 81 01 would need four tag bytes; this module
        // supports at most three (docs/CONTRACTS.md).
        assert_eq!(parse_one(&hex("5F818101 00")), Err(TlvError::TagTooLong));
    }

    #[test]
    fn truncated_tag() {
        // §5.2.2.1: 0x5F announces a subsequent tag byte that is missing.
        assert_eq!(parse_one(&hex("5F")), Err(TlvError::Truncated));
        // 0xC1 has b8 set, so a third byte is required.
        assert_eq!(parse_one(&hex("5FC1")), Err(TlvError::Truncated));
        assert_eq!(parse_one(&[]), Err(TlvError::Truncated));
    }

    #[test]
    fn constructed_bit_on_one_and_three_byte_tags() {
        // §5.2.2.1: b6 of the first byte marks a constructed object.
        let input = hex("7C 00");
        let (t, _) = parse_one(&input).unwrap();
        assert!(t.is_constructed());
        let input = hex("53 00");
        let (t, _) = parse_one(&input).unwrap();
        assert!(!t.is_constructed());
        let input = hex("7FC101 00");
        let (t, _) = parse_one(&input).unwrap();
        assert_eq!(t.tag, 0x7F_C101);
        assert!(t.is_constructed());
    }

    // --- Lengths (ISO/IEC 7816-4 §5.2.2.2) ---

    #[test]
    fn short_form_boundaries() {
        // §5.2.2.2: 0x00..=0x7F encode the length in one byte.
        let input = hex("80 00");
        let (t, _) = parse_one(&input).unwrap();
        assert!(t.value.is_empty());
        let mut input = hex("80 7F");
        input.extend(vec![0x11; 0x7F]);
        let (t, rest) = parse_one(&input).unwrap();
        assert_eq!(t.value.len(), 0x7F);
        assert!(rest.is_empty());
    }

    #[test]
    fn long_forms() {
        // §5.2.2.2: 81 XX (128..=255), 82 XX XX (..=65535), 83 XX XX XX (..=16M).
        for (len_field, len) in [
            (hex("8180"), 0x80usize),
            (hex("81FF"), 0xFF),
            (hex("820100"), 0x100),
            (hex("82FFFF"), 0xFFFF),
            (hex("83010000"), 0x1_0000),
        ] {
            let mut input = vec![0x53];
            input.extend_from_slice(&len_field);
            input.extend(vec![0xA5; len]);
            input.push(0x99); // trailing byte after the object
            let (t, rest) = parse_one(&input).unwrap();
            assert_eq!(t.value.len(), len, "length field {len_field:02X?}");
            assert_eq!(rest, [0x99]);
            assert_eq!(t.raw.len(), 1 + len_field.len() + len);
        }
    }

    #[test]
    fn non_minimal_long_form_is_accepted() {
        // X.690 §8.1.3.5 (BER): the long form may be used for short lengths.
        let input = hex("53 8105 0102030405");
        let (t, _) = parse_one(&input).unwrap();
        assert_eq!(t.value, [1, 2, 3, 4, 5]);
        let input = hex("53 820002 0102");
        let (t, _) = parse_one(&input).unwrap();
        assert_eq!(t.value, [1, 2]);
    }

    #[test]
    fn indefinite_and_oversized_length_forms_are_rejected() {
        // §5.2.2.2 allows only short form and 81/82/83 here; 80 is X.690 indefinite.
        assert_eq!(parse_one(&hex("53 80")), Err(TlvError::IndefiniteLength));
        assert_eq!(
            parse_one(&hex("53 84 00000001 00")),
            Err(TlvError::UnsupportedLength)
        );
        assert_eq!(parse_one(&hex("53 FF")), Err(TlvError::UnsupportedLength));
    }

    #[test]
    fn truncated_length_and_value() {
        // §5.2.2: tag, then length, then exactly `length` value bytes.
        assert_eq!(parse_one(&hex("53")), Err(TlvError::Truncated));
        assert_eq!(parse_one(&hex("53 81")), Err(TlvError::Truncated));
        assert_eq!(parse_one(&hex("53 8201")), Err(TlvError::Truncated));
        assert_eq!(parse_one(&hex("53 830100")), Err(TlvError::Truncated));
        assert_eq!(parse_one(&hex("53 03 0102")), Err(TlvError::Truncated));
        assert_eq!(parse_one(&hex("53 8180 00")), Err(TlvError::Truncated));
    }

    // --- Sequences and real device data ---

    #[test]
    fn parse_all_concatenated() {
        // reference/.../openpgp-reference-observation.json, public_objects["7f66"] =
        // "02020bfe02020bfe": OpenPGP Card 3.4 DO 7F66 (extended length
        // information), two INTEGER DOs each holding 0x0BFE.
        let input = hex("02020bfe02020bfe");
        let items = parse_all(&input).unwrap();
        assert_eq!(items.len(), 2);
        for item in &items {
            assert_eq!(item.tag, 0x02);
            assert_eq!(item.value, [0x0B, 0xFE]);
        }
        assert_eq!(items[1].raw, hex("02020bfe"));
        assert!(parse_all(&[]).unwrap().is_empty());
    }

    #[test]
    fn parse_all_rejects_trailing_garbage() {
        // §5.2.2: a trailing partial object is truncated input.
        assert_eq!(parse_all(&hex("0101AA 02")), Err(TlvError::Truncated));
        assert_eq!(parse_all(&hex("0101AA 0203AA")), Err(TlvError::Truncated));
    }

    #[test]
    fn security_domain_select_template() {
        // reference/yubikey-5c-nano-5.7.4/security-domain-reference-observation.json,
        // select_public_template and select_layout: 6F(23) { 84(8), A5(11) { 73(9) {
        // 06(7) } } }.
        let input = hex("6f178408a000000151000000a50b730906072a864886fc6b01");
        let (fci, rest) = parse_one(&input).unwrap();
        assert!(rest.is_empty());
        assert_eq!(fci.tag, 0x6F);
        assert_eq!(fci.value.len(), 23);
        let fields = fci.children().unwrap();
        assert_eq!(fields.len(), 2);
        assert_eq!(find(&fields, 0x84).unwrap().value, hex("a000000151000000"));
        let prop = find(&fields, 0xA5).unwrap();
        assert_eq!(prop.value.len(), 11);
        let inner = prop.children().unwrap();
        let oid_tmpl = find(&inner, 0x73).unwrap();
        let oid = oid_tmpl.children().unwrap();
        assert_eq!(oid[0].tag, 0x06);
        assert_eq!(oid[0].value, hex("2a864886fc6b01"));
        assert!(find(&fields, 0x99).is_none());
    }

    #[test]
    fn card_recognition_data() {
        // reference/.../security-domain-reference-observation.json,
        // card_recognition_data (63 bytes): template 73 with five children
        // (GlobalPlatform Card Specification 2.3.1, Appendix H).
        let input = hex(
            "733d06072a864886fc6b01600c060a2a864886fc6b02020301630906072a864886fc6b03\
             640b06092a864886fc6b040360640c060a2a864886fc6b04119b06",
        );
        let (crd, rest) = parse_one(&input).unwrap();
        assert!(rest.is_empty());
        let tags: Vec<u32> = crd.children().unwrap().iter().map(|t| t.tag).collect();
        assert_eq!(tags, [0x06, 0x60, 0x63, 0x64, 0x64]);
        // find returns the first of the two 0x64 entries.
        let kids = crd.children().unwrap();
        assert_eq!(find(&kids, 0x64).unwrap().value.len(), 0x0B);
    }

    #[test]
    fn openpgp_algorithm_information() {
        // reference/.../openpgp-reference-observation.json, algorithm_information
        // (421 bytes; the GET DATA 00FA response length in `commands`): DO FA with
        // the 82 01A1 long length form, holding C1/C2/C3/DA algorithm attributes.
        let input = hex(concat!(
            "fa8201a1c106010800001100c106010c00001100c106011000001100c109132a8648ce3d03",
            "0107c106132b81040022c106132b81040023c106132b8104000ac10a132b2403030208010107",
            "c10a132b240303020801010bc10a132b240303020801010dc10a162b06010401da470f01c2",
            "06010800001100c206010c00001100c206011000001100c209122a8648ce3d030107c20612",
            "2b81040022c206122b81040023c206122b8104000ac20a122b2403030208010107c20a122b",
            "240303020801010bc20a122b240303020801010dc20b122b060104019755010501c3060108",
            "00001100c306010c00001100c306011000001100c309132a8648ce3d030107c306132b8104",
            "0022c306132b81040023c306132b8104000ac30a132b2403030208010107c30a132b240303",
            "020801010bc30a132b240303020801010dc30a162b06010401da470f01da06010800001100",
            "da06010c00001100da06011000001100da09132a8648ce3d030107da06132b81040022da06",
            "132b81040023da06132b8104000ada0a132b2403030208010107da0a132b24030302080101",
            "0bda0a132b240303020801010d",
        ));
        assert_eq!(input.len(), 421);
        let (fa, rest) = parse_one(&input).unwrap();
        assert!(rest.is_empty());
        assert_eq!(fa.tag, 0xFA);
        assert_eq!(fa.value.len(), 0x01A1);
        let entries = fa.children().unwrap();
        assert_eq!(entries.len(), 43);
        let count = |tag| entries.iter().filter(|e| e.tag == tag).count();
        assert_eq!(count(0xC1), 11);
        assert_eq!(count(0xC2), 11);
        assert_eq!(count(0xC3), 11);
        assert_eq!(count(0xDA), 10);
        // RSA-2048 algorithm attributes 01 0800 0011 00 (OpenPGP Card 3.4, DO C1).
        assert_eq!(entries[0].value, hex("010800001100"));
        // Re-encoding reproduces the device bytes (minimal length form 82).
        let mut body = Vec::new();
        for e in &entries {
            encode_into(&mut body, e.tag, e.value);
        }
        assert_eq!(encode(0xFA, &body), input);
    }

    // --- Encoding ---

    #[test]
    fn encode_len_minimal_forms() {
        // §5.2.2.2 boundaries.
        assert_eq!(encode_len(0), [0x00]);
        assert_eq!(encode_len(0x7F), [0x7F]);
        assert_eq!(encode_len(0x80), [0x81, 0x80]);
        assert_eq!(encode_len(0xFF), [0x81, 0xFF]);
        assert_eq!(encode_len(0x100), [0x82, 0x01, 0x00]);
        assert_eq!(encode_len(0xFFFF), [0x82, 0xFF, 0xFF]);
        assert_eq!(encode_len(0x1_0000), [0x83, 0x01, 0x00, 0x00]);
        assert_eq!(encode_len(0xFF_FFFF), [0x83, 0xFF, 0xFF, 0xFF]);
        // Beyond the supported forms: X.690 §8.1.3.5 long form with four bytes.
        assert_eq!(encode_len(0x100_0000), [0x84, 0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn encode_tags_as_written() {
        // §5.2.2.1: the u32 holds the tag bytes as written.
        assert_eq!(encode_tag(0x00), [0x00]);
        assert_eq!(encode_tag(0x01), [0x01]);
        assert_eq!(encode_tag(0x7F49), [0x7F, 0x49]);
        assert_eq!(encode_tag(0x5F_C109), [0x5F, 0xC1, 0x09]);
        assert_eq!(encode(0x7F49, &[]), [0x7F, 0x49, 0x00]);
        assert_eq!(encode(0x01, &[0xAB]), [0x01, 0x01, 0xAB]);
    }

    #[test]
    fn encode_parse_round_trip_at_length_boundaries() {
        // §5.2.2.2 boundaries 127/128, 255/256, 65535/65536 with 1-, 2- and 3-byte tags.
        for tag in [0x53u32, 0x7F49, 0x5F_C105] {
            for len in [0usize, 1, 0x7F, 0x80, 0xFF, 0x100, 0xFFFF, 0x1_0000] {
                let value: Vec<u8> = (0..len).map(|i| i as u8).collect();
                let bytes = encode(tag, &value);
                let (t, rest) = parse_one(&bytes).unwrap();
                assert_eq!(t.tag, tag);
                assert_eq!(t.value, &value[..]);
                assert_eq!(t.raw, &bytes[..]);
                assert!(rest.is_empty());
            }
        }
    }

    #[test]
    fn errors_display() {
        // Display text for diagnostics (no external vector).
        assert_eq!(
            TlvError::Truncated.to_string(),
            "truncated BER-TLV data object"
        );
        assert!(!TlvError::UnsupportedLength.to_string().is_empty());
    }

    // --- Review: tag number boundaries (ISO/IEC 7816-4 §5.2.2.1, X.690 §8.1.2) ---

    #[test]
    fn tag_number_boundaries() {
        // §5.2.2.1 / X.690 §8.1.2.2: tag numbers 0..=30 fit in the first byte; low five
        // bits 0x1F announce subsequent bytes. Two-byte tags hold numbers 31..=127
        // (second byte 1F..7F, b8 clear); three-byte tags hold 128..=16383 (second
        // byte with b8 set, third byte with b8 clear).
        let cases: &[(&str, u32, usize)] = &[
            ("1E 00", 0x1E, 1),          // universal, number 30: still one byte
            ("9E 00", 0x9E, 1),          // context-specific, number 30
            ("DE 00", 0xDE, 1),          // private, number 30
            ("1F1F 00", 0x1F1F, 2),      // universal, number 31: first two-byte tag
            ("5F1F 00", 0x5F1F, 2),      // application, number 31
            ("5F7F 00", 0x5F7F, 2),      // number 127: last two-byte tag
            ("9F7F 00", 0x9F7F, 2),      // GP CPLC (security-domain observation)
            ("BF20 00", 0xBF20, 2),      // GP constructed context tag (catalog BF20)
            ("5F8100 00", 0x5F_8100, 3), // number 128: first three-byte tag
            ("5FFF7F 00", 0x5F_FF7F, 3), // number 16383: last three-byte tag
            ("5FFF01 00", 0x5F_FF01, 3), // Yubico PIV vendor object range 5FFFxx
            ("7FFF7F 00", 0x7F_FF7F, 3), // constructed three-byte tag
        ];
        for &(input, tag, tag_len) in cases {
            let bytes = hex(input);
            let (t, rest) = parse_one(&bytes).unwrap();
            assert_eq!(t.tag, tag, "{input}");
            assert_eq!(t.raw.len(), tag_len + 1, "{input}");
            assert!(rest.is_empty(), "{input}");
            assert_eq!(encode(tag, &[]), bytes, "{input}");
        }
        // Continuation on the third byte would need a fourth tag byte (§5.2.2.1 allows
        // at most three), whether or not the fourth byte is present.
        assert_eq!(parse_one(&hex("5F8181")), Err(TlvError::TagTooLong));
        assert_eq!(parse_one(&hex("5FFFFF7F 00")), Err(TlvError::TagTooLong));
    }

    #[test]
    fn non_minimal_tag_numbers_are_accepted() {
        // §5.2.2.1 calls second bytes 00..1E and 80 invalid; this module accepts them
        // and keeps the bytes as written (module docs). 9F02 is EMV Book 3 Annex A
        // "Amount, Authorised"; 5F 80 01 encodes tag number 1 with a leading zero group.
        let emv = hex("9F02 01 AA");
        let (t, _) = parse_one(&emv).unwrap();
        assert_eq!(t.tag, 0x9F02);
        assert_eq!(t.value, [0xAA]);
        let low = hex("5F00 00");
        assert_eq!(parse_one(&low).unwrap().0.tag, 0x5F00);
        let padded = hex("5F8001 00");
        assert_eq!(parse_one(&padded).unwrap().0.tag, 0x5F_8001);
        assert_eq!(encode(0x5F_8001, &[]), hex("5F8001 00"));
    }

    #[test]
    fn padding_bytes_are_not_skipped() {
        // §5.2.2 allows 00/FF padding between objects; this module parses them as
        // tags instead (module docs), so callers see the padding explicitly.
        let input = hex("5301AA 0000");
        let items = parse_all(&input).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[1].tag, 0x00);
        assert!(items[1].value.is_empty());
        // A lone FF announces a second tag byte that is missing.
        assert_eq!(parse_all(&hex("5301AA FF")), Err(TlvError::Truncated));
    }

    #[test]
    fn non_minimal_length_forms_cover_their_whole_range() {
        // ISO/IEC 7816-4:2005 §5.2.2.2 table: 81 covers 00..FF, 82 covers 0000..FFFF,
        // 83 covers 000000..FFFFFF, so zero and short lengths in long form are valid.
        for (input, len) in [
            ("53 8100", 0usize),
            ("53 817F", 0x7F),
            ("53 820000", 0),
            ("53 82007F", 0x7F),
            ("53 830000FF", 0xFF),
            ("53 83000005", 5),
        ] {
            let mut bytes = hex(input);
            bytes.extend(vec![0x5A; len]);
            let (t, rest) = parse_one(&bytes).unwrap();
            assert_eq!(t.value.len(), len, "{input}");
            assert!(rest.is_empty(), "{input}");
            // Re-encoding chooses the minimal form, so it is shorter than the input.
            let minimal = encode(t.tag, t.value);
            assert!(minimal.len() < bytes.len(), "{input}");
            assert_eq!(parse_one(&minimal).unwrap().0.value, t.value, "{input}");
        }
    }

    // --- Review: fixed-seed pseudo-random robustness ---

    /// SplitMix64 (Steele, Lea and Flood, "Fast Splittable Pseudorandom Number
    /// Generators", OOPSLA 2014): a tiny fixed-seed generator for reproducible inputs.
    struct SplitMix64(u64);

    impl SplitMix64 {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next_u64() % n as u64) as usize
        }

        fn byte(&mut self) -> u8 {
            self.next_u64() as u8
        }

        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.byte()).collect()
        }
    }

    /// A random tag field of 1–4 bytes (§5.2.2.1); 4 bytes is invalid here.
    fn random_tag(rng: &mut SplitMix64) -> Vec<u8> {
        let first_low = |rng: &mut SplitMix64| {
            let b = rng.byte();
            if b & 0x1F == 0x1F { b & !0x01 } else { b }
        };
        let first_high = |rng: &mut SplitMix64| rng.byte() | 0x1F;
        match rng.below(8) {
            0..=3 => vec![first_low(rng)],
            4 | 5 => vec![first_high(rng), rng.byte() & 0x7F],
            6 => vec![first_high(rng), rng.byte() | 0x80, rng.byte() & 0x7F],
            _ => vec![first_high(rng), 0x81, 0x81, 0x01],
        }
    }

    /// A random length field for `len` (§5.2.2.2): minimal, non-minimal or invalid.
    fn random_length(rng: &mut SplitMix64, len: usize) -> Vec<u8> {
        let be4 = (len as u32).to_be_bytes();
        match rng.below(12) {
            0..=4 => encode_len(len),
            5 if len <= 0xFF => vec![0x81, len as u8],
            6 if len <= 0xFFFF => vec![0x82, (len >> 8) as u8, len as u8],
            7 => vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8],
            8 => vec![0x80],
            // A well-formed X.690 four-byte length, outside this module's forms.
            9 => [&[0x84][..], &be4].concat(),
            10 => [&[0x85 + rng.below(0x7B) as u8][..], &be4].concat(),
            _ => encode_len(len),
        }
    }

    /// Check what every successful [`parse_one`] must satisfy for `input`.
    fn check_parse_one(input: &[u8]) -> Result<usize, TlvError> {
        let (t, rest) = parse_one(input)?;
        assert_eq!(t.raw.len() + rest.len(), input.len());
        assert_eq!(t.raw, &input[..t.raw.len()]);
        assert!(t.raw.ends_with(t.value));
        // The object re-parses from its raw bytes alone.
        assert_eq!(parse_one(t.raw), Ok((t, &[][..])));
        // Re-encoding keeps tag and value (raw may differ: minimal length form).
        let again = encode(t.tag, t.value);
        let (u, rest2) = parse_one(&again).unwrap();
        assert_eq!((u.tag, u.value), (t.tag, t.value));
        assert!(rest2.is_empty());
        assert!(again.len() <= t.raw.len());
        // Value parsing must not panic either.
        let _ = t.children();
        Ok(t.raw.len())
    }

    /// Check [`parse_all`] against repeated [`parse_one`] calls.
    fn check_parse_all(input: &[u8]) {
        let mut expected = Ok(Vec::new());
        let mut rest = input;
        while !rest.is_empty() {
            match check_parse_one(rest) {
                Ok(n) => {
                    if let Ok(v) = expected.as_mut() {
                        v.push(&rest[..n]);
                    }
                    rest = &rest[n..];
                }
                Err(e) => {
                    expected = Err(e);
                    break;
                }
            }
        }
        match (parse_all(input), expected) {
            (Ok(items), Ok(raws)) => {
                let got: Vec<&[u8]> = items.iter().map(|t| t.raw).collect();
                assert_eq!(got, raws);
                assert_eq!(got.concat(), input);
            }
            (Err(a), Err(b)) => assert_eq!(a, b),
            (a, b) => panic!("parse_all {a:?} disagrees with parse_one {b:?}"),
        }
    }

    #[test]
    fn seeded_random_inputs_never_panic_and_round_trip() {
        // Fixed seed so failures reproduce; no external vector (robustness test).
        let mut rng = SplitMix64(0x7816_0004_5222_0001);
        for i in 0..6000 {
            let input = if i % 3 == 0 {
                // Unstructured bytes.
                let n = rng.below(24);
                rng.bytes(n)
            } else {
                // One to four structured objects, sometimes damaged.
                let mut out = Vec::new();
                let mut expected = Vec::new();
                let mut all_valid = true;
                for _ in 0..1 + rng.below(4) {
                    let len = match rng.below(50) {
                        0 => 0x1_0000 + rng.below(0x200),
                        1..=4 => 0x80 + rng.below(0x200),
                        _ => rng.below(0x80),
                    };
                    let tag = random_tag(&mut rng);
                    let length = random_length(&mut rng, len);
                    let value = rng.bytes(len);
                    // §5.2.2.2: short form, or 81/82/83; 80 and 84.. are invalid.
                    let length_ok = length[0] < 0x80 || (0x81..=0x83).contains(&length[0]);
                    all_valid &= tag.len() <= MAX_TAG_BYTES && length_ok;
                    let tag_u32 = tag.iter().fold(0u32, |a, &b| (a << 8) | u32::from(b));
                    expected.push((tag_u32, value.clone()));
                    out.extend_from_slice(&tag);
                    out.extend_from_slice(&length);
                    out.extend_from_slice(&value);
                }
                let damaged = match rng.below(6) {
                    0 => {
                        let cut = rng.below(out.len());
                        out.truncate(cut);
                        true
                    }
                    1 => {
                        out.push(rng.byte());
                        true
                    }
                    _ => false,
                };
                if all_valid && !damaged {
                    // Well-formed input parses to exactly what was built.
                    let got: Vec<(u32, Vec<u8>)> = parse_all(&out)
                        .unwrap()
                        .iter()
                        .map(|t| (t.tag, t.value.to_vec()))
                        .collect();
                    assert_eq!(got, expected);
                } else if !all_valid && !damaged {
                    // An invalid tag or length form somewhere must be reported.
                    assert!(parse_all(&out).is_err());
                }
                out
            };
            check_parse_all(&input);
        }
    }
}
