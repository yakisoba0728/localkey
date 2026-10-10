//! Parsing of YKOATH command data fields.
//!
//! YKOATH request data is a sequence of one-byte tags with BER-TLV lengths
//! (ISO/IEC 7816-4 §5.2.2), with one exception: the PUT property field is the tag
//! `78` followed directly by the property byte, without a length (YKOATH §PUT,
//! "Property tag" / "Property"). Every malformed field is answered with `6A80`
//! (YKOATH: "Response 0x6a80 means the data is malformed").

use lk_codec::apdu::sw;
use lk_codec::tlv;

use crate::tag;

/// One field of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Field<'a> {
    pub(crate) tag: u8,
    pub(crate) value: &'a [u8],
}

/// Split `data` into fields. The property tag takes exactly one value byte.
pub(crate) fn parse_fields(data: &[u8]) -> Result<Vec<Field<'_>>, u16> {
    let mut fields = Vec::new();
    let mut rest = data;
    while let Some(&first) = rest.first() {
        if first == tag::PROPERTY {
            let value = rest.get(1..2).ok_or(sw::INCORRECT_DATA)?;
            fields.push(Field { tag: first, value });
            rest = rest.get(2..).unwrap_or(&[]);
            continue;
        }
        let (item, next) = tlv::parse_one(rest).map_err(|_| sw::INCORRECT_DATA)?;
        // YKOATH uses one-byte tags only; a multi-byte tag is unknown and malformed.
        let tag = u8::try_from(item.tag).map_err(|_| sw::INCORRECT_DATA)?;
        fields.push(Field { tag, value: item.value });
        rest = next;
    }
    Ok(fields)
}

/// Parse `data` and return the value of each tag in `allowed`, in that order.
///
/// A tag outside `allowed` or a repeated tag is malformed (`6A80`): each YKOATH field
/// appears at most once (model policy for the catalog's "singleton property and
/// required/allowed TLV syntax"). Whether a field is required is the caller's check.
pub(crate) fn pick<'a, const N: usize>(data: &'a [u8], allowed: [u8; N]) -> Result<[Option<&'a [u8]>; N], u16> {
    let mut out: [Option<&'a [u8]>; N] = [None; N];
    for field in parse_fields(data)? {
        let index = allowed
            .iter()
            .position(|&t| t == field.tag)
            .ok_or(sw::INCORRECT_DATA)?;
        let slot = out.get_mut(index).ok_or(sw::INCORRECT_DATA)?;
        if slot.is_some() {
            return Err(sw::INCORRECT_DATA);
        }
        *slot = Some(field.value);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn property_has_no_length_byte() {
        // 71 01 'a' | 78 02 | 7A 04 00000005  (YKOATH §PUT layout)
        let data = [0x71, 0x01, b'a', 0x78, 0x02, 0x7A, 0x04, 0, 0, 0, 5];
        let fields = parse_fields(&data).expect("parses");
        assert_eq!(
            fields,
            vec![
                Field { tag: 0x71, value: b"a" },
                Field { tag: 0x78, value: &[0x02] },
                Field { tag: 0x7A, value: &[0, 0, 0, 5] },
            ]
        );
    }

    #[test]
    fn malformed_fields_are_6a80() {
        assert_eq!(parse_fields(&[0x78]), Err(sw::INCORRECT_DATA));
        assert_eq!(parse_fields(&[0x71, 0x05, 1]), Err(sw::INCORRECT_DATA));
        assert_eq!(parse_fields(&[0x7F, 0x81, 0x01, 0x00]), Err(sw::INCORRECT_DATA));
        assert_eq!(parse_fields(&[0x71, 0x80]), Err(sw::INCORRECT_DATA));
    }

    #[test]
    fn pick_rejects_unknown_and_duplicate_tags() {
        let [name, key] = pick(&[0x71, 0x01, b'n'], [0x71, 0x73]).expect("valid");
        assert_eq!(name, Some(&b"n"[..]));
        assert_eq!(key, None);
        assert_eq!(pick(&[0x71, 0x00, 0x71, 0x00], [0x71]), Err(sw::INCORRECT_DATA));
        assert_eq!(pick(&[0x74, 0x00], [0x71]), Err(sw::INCORRECT_DATA));
        assert_eq!(pick(&[0x78, 0x01, 0x78, 0x02], [0x78]), Err(sw::INCORRECT_DATA));
    }
}
