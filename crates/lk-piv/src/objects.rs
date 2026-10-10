//! PIV data objects: which tags exist, who may read them, and the storage budget.
//!
//! Containers and their read access rules are SP 800-73-4 Part 1 §3.1 and Table 3.
//! Yubico's PIV documentation ("GET DATA" / "PUT DATA") adds the vendor objects
//! `5FFF00..` (administrative data, attestation certificate `5FFF01`, ...) and states
//! that the YubiKey stores data under any tag of the form `5F xx xx`. Model policy: a
//! container tag is any well-formed three-byte BER tag (ISO/IEC 7816-4 §5.2.2.1) whose
//! first byte is `5F`, i.e. second byte with bit b8 set and third byte with b8 clear.
//!
//! Capacity model (`reference/legacy-v0.64-profiles.json`, `piv_allocation_model`):
//!
//! - assembled command data, chained or extended, is limited to
//!   [`MAX_APDU_DATA`] = 3072 bytes;
//! - the values of all stored objects (the contents of tag `53`, without the `53`
//!   header) share a budget of [`MAX_TOTAL_OBJECT_BYTES`] = 51200 bytes. The Discovery
//!   object is a constant and is not charged. The attestation certificate (`5FFF01`) is
//!   an ordinary stored object and is charged like any other, including the own F9
//!   certificate created at initialization (`attest::initialize`);
//! - a certificate (tag `70` inside a certificate container) may hold at most
//!   [`MAX_CERT_VALUE`] = 3052 bytes (`published_certificate_value_limit`).

use std::collections::BTreeMap;

use lk_codec::tlv;

/// Largest assembled command data field (`plaintext_apdu_data_limit`).
pub(crate) const MAX_APDU_DATA: usize = 3072;

/// Budget for the values of all stored objects (`stored_object_values_limit`).
pub(crate) const MAX_TOTAL_OBJECT_BYTES: usize = 51_200;

/// Largest certificate (tag `70` value) in a certificate container
/// (`published_certificate_value_limit`; catalog "published 3052-byte tag70 certificate
/// limit").
pub(crate) const MAX_CERT_VALUE: usize = 3052;

/// Tag list tag of GET DATA / PUT DATA (SP 800-73-4 Part 2 §3.1.2, §3.3.2).
pub(crate) const TAG_TAG_LIST: u32 = 0x5C;
/// Data field tag wrapping a container's value (SP 800-73-4 Part 2 §3.1.2).
pub(crate) const TAG_DATA: u32 = 0x53;
/// X.509 certificate inside a certificate container (SP 800-73-4 Part 1 Appendix A).
const TAG_CERTIFICATE: u32 = 0x70;

/// Yubico attestation certificate (slot `F9`).
pub(crate) const TAG_ATTESTATION: u32 = 0x5FFF01;

/// The fixed Discovery Object (`piv_initial_profile.discovery_response`): PIV AID,
/// PIN usage policy `40 00` (PIV Card Application PIN only; SP 800-73-4 Part 1 §3.3.2).
pub(crate) const DISCOVERY: [u8; 20] = [
    0x7E, 0x12, 0x4F, 0x0B, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x5F,
    0x2F, 0x02, 0x40, 0x00,
];

/// What a GET DATA / PUT DATA tag list names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObjectId {
    /// `7E`, the Discovery Object (SP 800-73-4 Part 1 §3.3.2): a read-only constant.
    Discovery,
    /// `7F61`, the Biometric Information Templates Group Template (SP 800-73-4 Part 1
    /// §3.3.3): not supported; read-only and never present (profile
    /// `biometric_group_template: "unsupported; no data"`).
    Bitgt,
    /// A `5F xx xx` container.
    Container(u32),
}

impl ObjectId {
    /// Decode the value of a `5C` tag list. SP 800-73-4 Part 2 §3.1.2 allows exactly one
    /// tag: `7E`, `7F61` or a three-byte container tag.
    pub(crate) fn from_tag_list(value: &[u8]) -> Option<Self> {
        match *value {
            [0x7E] => Some(Self::Discovery),
            [0x7F, 0x61] => Some(Self::Bitgt),
            [0x5F, b, c] if b & 0x80 != 0 && c & 0x80 == 0 => {
                Some(Self::Container(u32::from_be_bytes([0, 0x5F, b, c])))
            }
            _ => None,
        }
    }
}

/// The container tag for stored tag bytes, if they name a container.
pub(crate) fn stored_tag(bytes: &[u8]) -> Option<u32> {
    match ObjectId::from_tag_list(bytes)? {
        ObjectId::Container(tag) => Some(tag),
        _ => None,
    }
}

/// Whether reading `tag` requires the PIV PIN: SP 800-73-4 Part 1 Table 3 gives the
/// read access rule "PIN" (or "PIN or OCC") for Cardholder Fingerprints `5FC103`,
/// Cardholder Facial Image `5FC108`, Printed Information `5FC109`, Cardholder Iris
/// Images `5FC121` and Pairing Code Reference Data `5FC123`; every other container is
/// "Always".
pub(crate) fn read_requires_pin(tag: u32) -> bool {
    matches!(tag, 0x5FC103 | 0x5FC108 | 0x5FC109 | 0x5FC121 | 0x5FC123)
}

/// Whether `tag` is a certificate container: the four key certificates (SP 800-73-4
/// Part 1 §3.1: `5FC105` PIV Authentication, `5FC10A` Digital Signature, `5FC10B` Key
/// Management, `5FC101` Card Authentication), the retired key management certificates
/// `5FC10D..=5FC120` (§3.3.1), the Secure Messaging Certificate Signer `5FC122`
/// (§3.3.4) and the Yubico attestation certificate `5FFF01`.
pub(crate) fn is_certificate_container(tag: u32) -> bool {
    matches!(tag, 0x5FC101 | 0x5FC105 | 0x5FC10A | 0x5FC10B | 0x5FC10D..=0x5FC120 | 0x5FC122)
        || tag == TAG_ATTESTATION
}

/// Whether a certificate container value holds a certificate (tag `70`) longer than
/// [`MAX_CERT_VALUE`]. Only well-formed leading TLVs are inspected; the device stores
/// container contents opaquely otherwise.
pub(crate) fn certificate_too_large(tag: u32, value: &[u8]) -> bool {
    if !is_certificate_container(tag) {
        return false;
    }
    let mut rest = value;
    while let Ok((item, next)) = tlv::parse_one(rest) {
        if item.tag == TAG_CERTIFICATE && item.value.len() > MAX_CERT_VALUE {
            return true;
        }
        rest = next;
    }
    false
}

/// Stored container values, keyed by tag.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ObjectStore {
    map: BTreeMap<u32, Vec<u8>>,
}

impl ObjectStore {
    /// The stored value of `tag`.
    pub(crate) fn get(&self, tag: u32) -> Option<&[u8]> {
        self.map.get(&tag).map(Vec::as_slice)
    }

    /// Store `value` under `tag`; an empty value deletes the object (SP 800-73-4
    /// Part 2 §3.3.2: PUT DATA with a zero-length `53` erases the container).
    pub(crate) fn put(&mut self, tag: u32, value: Vec<u8>) {
        if value.is_empty() {
            self.map.remove(&tag);
        } else {
            self.map.insert(tag, value);
        }
    }

    /// Number of stored objects.
    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    /// Bytes charged to the budget: the sum of all stored values.
    pub(crate) fn total(&self) -> usize {
        self.map.values().map(Vec::len).sum()
    }

    /// Whether replacing `tag`'s value by `new_len` bytes stays within the budget. The
    /// old value is released first, so a replacement is judged on the resulting total. A
    /// change that does not grow the object (including a deletion) always fits, so a
    /// store that is over budget can still be shrunk.
    pub(crate) fn fits(&self, tag: u32, new_len: usize) -> bool {
        let old = self.get(tag).map_or(0, <[u8]>::len);
        new_len <= old || self.total().saturating_sub(old).saturating_add(new_len) <= MAX_TOTAL_OBJECT_BYTES
    }

    /// All objects in tag order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (u32, &[u8])> {
        self.map.iter().map(|(tag, value)| (*tag, value.as_slice()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_list_forms() {
        // SP 800-73-4 Part 1 Table 3 tags and the Yubico vendor range.
        assert_eq!(ObjectId::from_tag_list(&[0x7E]), Some(ObjectId::Discovery));
        assert_eq!(ObjectId::from_tag_list(&[0x7F, 0x61]), Some(ObjectId::Bitgt));
        assert_eq!(ObjectId::from_tag_list(&[0x5F, 0xC1, 0x02]), Some(ObjectId::Container(0x5FC102)));
        assert_eq!(ObjectId::from_tag_list(&[0x5F, 0xFF, 0x15]), Some(ObjectId::Container(0x5FFF15)));
        for bad in [&[][..], &[0x7F], &[0x5F, 0xC1], &[0x5F, 0x01, 0x02], &[0x5F, 0xC1, 0x85], &[0x5E, 0xC1, 0x02],
            &[0x5F, 0xC1, 0x02, 0x00], &[0x53]]
        {
            assert_eq!(ObjectId::from_tag_list(bad), None, "{bad:02X?}");
        }
    }

    #[test]
    fn budget_counts_replacement_once() {
        let mut store = ObjectStore::default();
        store.put(0x5FC102, vec![0; 1000]);
        assert_eq!(store.total(), 1000);
        assert!(store.fits(0x5FC102, MAX_TOTAL_OBJECT_BYTES));
        assert!(!store.fits(0x5FC103, MAX_TOTAL_OBJECT_BYTES - 999));
        assert!(store.fits(0x5FC103, MAX_TOTAL_OBJECT_BYTES - 1000));
        store.put(0x5FC102, Vec::new());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn over_budget_store_can_still_shrink() {
        // A store loaded over the budget (e.g. a record from another version) refuses
        // growth but never a shrink or a deletion.
        let mut store = ObjectStore::default();
        store.put(0x5FC102, vec![0; MAX_TOTAL_OBJECT_BYTES]);
        store.put(0x5FC105, vec![0; 100]);
        assert!(store.fits(0x5FC105, 0), "deletion");
        assert!(store.fits(0x5FC105, 50), "shrink");
        assert!(store.fits(0x5FC105, 100), "same size");
        assert!(!store.fits(0x5FC105, 101), "growth");
        assert!(!store.fits(0x5FC106, 1), "new object");
    }

    #[test]
    fn certificate_limit_only_for_certificate_containers() {
        let mut big = tlv::encode(0x70, &vec![0x30; MAX_CERT_VALUE + 1]);
        big.extend_from_slice(&[0x71, 0x01, 0x00, 0xFE, 0x00]);
        let ok = tlv::encode(0x70, &vec![0x30; MAX_CERT_VALUE]);
        assert!(certificate_too_large(0x5FC105, &big));
        assert!(certificate_too_large(0x5FC10D, &big));
        assert!(certificate_too_large(TAG_ATTESTATION, &big));
        assert!(!certificate_too_large(0x5FC105, &ok));
        assert!(!certificate_too_large(0x5FC102, &big), "CHUID is not a certificate container");
        assert!(!certificate_too_large(0x5FC105, &[0x70, 0x82]), "truncated TLV is opaque");
    }
}
