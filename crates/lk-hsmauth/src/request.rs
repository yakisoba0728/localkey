//! Command data parsing: a flat list of BER-TLV objects (ISO/IEC 7816-4 §5.2.2) with the
//! tags of yubikit `hsmauth.py`.
//!
//! Model decision: objects may come in any order, but every tag must be one the command
//! defines and may appear only once (PUT MANAGEMENT KEY, whose two `7B` objects are
//! positional, parses its data itself). Anything else is `6A80`, which ykhsmauth
//! `translate_error` reports as invalid parameters. Syntax is checked before any
//! retry counter is touched, so malformed input never consumes a try.

use lk_codec::apdu::sw;
use lk_codec::tlv;

use crate::state::label_is_valid;
use crate::tag;

/// The objects of one command's data field, by tag.
pub(crate) struct Fields<'a> {
    items: Vec<(u32, &'a [u8])>,
}

impl<'a> Fields<'a> {
    /// Parse `data`, accepting only `allowed` tags, each at most once.
    pub(crate) fn parse(data: &'a [u8], allowed: &[u32]) -> Result<Self, u16> {
        let parsed = tlv::parse_all(data).map_err(|_| sw::INCORRECT_DATA)?;
        let mut items: Vec<(u32, &'a [u8])> = Vec::with_capacity(parsed.len());
        for item in parsed {
            if !allowed.contains(&item.tag) || items.iter().any(|(t, _)| *t == item.tag) {
                return Err(sw::INCORRECT_DATA);
            }
            items.push((item.tag, item.value));
        }
        Ok(Self { items })
    }

    /// The value of `tag` if present.
    pub(crate) fn get(&self, tag: u32) -> Option<&'a [u8]> {
        self.items.iter().find(|(t, _)| *t == tag).map(|(_, v)| *v)
    }

    /// The value of a required object.
    pub(crate) fn required(&self, tag: u32) -> Result<&'a [u8], u16> {
        self.get(tag).ok_or(sw::INCORRECT_DATA)
    }

    /// A required object of exactly `N` bytes.
    pub(crate) fn fixed<const N: usize>(&self, tag: u32) -> Result<[u8; N], u16> {
        fixed(self.required(tag)?)
    }

    /// An optional object that, when present, has exactly `N` bytes.
    pub(crate) fn optional_fixed<const N: usize>(&self, tag: u32) -> Result<Option<[u8; N]>, u16> {
        self.get(tag).map(fixed).transpose()
    }

    /// The required label (`71`), checked for yubikit `_parse_label` syntax: 1–64 bytes
    /// of valid UTF-8.
    pub(crate) fn label(&self) -> Result<&'a [u8], u16> {
        let label = self.required(tag::LABEL)?;
        if label_is_valid(label) { Ok(label) } else { Err(sw::INCORRECT_DATA) }
    }
}

/// `value` as an array of exactly `N` bytes, else `6A80`.
pub(crate) fn fixed<const N: usize>(value: &[u8]) -> Result<[u8; N], u16> {
    value.try_into().map_err(|_| sw::INCORRECT_DATA)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_and_duplicate_tags() {
        let mut data = tlv::encode(tag::LABEL, b"a");
        assert!(Fields::parse(&data, &[tag::LABEL]).is_ok());
        assert_eq!(Fields::parse(&data, &[tag::CONTEXT]).err(), Some(sw::INCORRECT_DATA));
        data.extend(tlv::encode(tag::LABEL, b"b"));
        assert_eq!(Fields::parse(&data, &[tag::LABEL]).err(), Some(sw::INCORRECT_DATA));
        assert_eq!(Fields::parse(&[0x71, 0x05, 0x00], &[tag::LABEL]).err(), Some(sw::INCORRECT_DATA));
    }

    #[test]
    fn fixed_lengths() {
        let data = tlv::encode(tag::CREDENTIAL_PASSWORD, &[1; 16]);
        let fields = Fields::parse(&data, &[tag::CREDENTIAL_PASSWORD, tag::TOUCH]).expect("parse");
        assert_eq!(fields.fixed::<16>(tag::CREDENTIAL_PASSWORD), Ok([1; 16]));
        assert_eq!(fields.fixed::<15>(tag::CREDENTIAL_PASSWORD), Err(sw::INCORRECT_DATA));
        assert_eq!(fields.optional_fixed::<1>(tag::TOUCH), Ok(None));
        assert_eq!(fields.label(), Err(sw::INCORRECT_DATA));
    }
}
