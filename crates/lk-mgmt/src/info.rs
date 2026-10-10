//! The DeviceInfo TLV list and its paging (yubikit-python `yubikit/management.py`,
//! `TAG`, `DeviceInfo.parse_tlvs` and `ManagementSession.read_device_info`).
//!
//! READ CONFIG answers `len || TLVs`, where `len` is one byte. When the TLV list does
//! not fit one page the host asks for page 1, 2, … (P1 on CCID, the payload byte on
//! CTAPHID and OTP HID) as long as the page carries `MORE_DATA` (`10 01 01`).

use lk_codec::tlv;

/// DeviceInfo / DeviceConfig tags (yubikit-python `yubikit/management.py`, `TAG`).
pub mod tag {
    /// Capabilities supported over USB, 2 bytes big-endian.
    pub const USB_SUPPORTED: u32 = 0x01;
    /// Serial number, 4 bytes big-endian.
    pub const SERIAL: u32 = 0x02;
    /// Capabilities enabled over USB, 2 bytes big-endian (read and write).
    pub const USB_ENABLED: u32 = 0x03;
    /// Form factor, 1 byte (`lk_core::profile::form_factor`; bit 7 FIPS, bit 6 SKY).
    pub const FORM_FACTOR: u32 = 0x04;
    /// Firmware version, 3 bytes `major minor patch`.
    pub const VERSION: u32 = 0x05;
    /// Auto-eject timeout in seconds, 2 bytes big-endian (read and write).
    pub const AUTO_EJECT_TIMEOUT: u32 = 0x06;
    /// Challenge-response touch timeout in seconds, 1 byte (read and write).
    pub const CHALRESP_TIMEOUT: u32 = 0x07;
    /// Device flags, 1 byte (read and write; see [`crate::device_flags`]).
    pub const DEVICE_FLAGS: u32 = 0x08;
    /// Application versions (not reported by this firmware).
    pub const APP_VERSIONS: u32 = 0x09;
    /// Read: configuration locked (`01`) or not (`00`). Write: the new 16-byte lock code.
    pub const CONFIG_LOCK: u32 = 0x0A;
    /// Write only: the current 16-byte lock code.
    pub const UNLOCK: u32 = 0x0B;
    /// Write only: reboot (re-enumerate) after the command.
    pub const REBOOT: u32 = 0x0C;
    /// Capabilities supported over NFC (NFC devices only; never sent here).
    pub const NFC_SUPPORTED: u32 = 0x0D;
    /// Capabilities enabled over NFC (NFC devices only; rejected on write here).
    pub const NFC_ENABLED: u32 = 0x0E;
    /// Lightning accessory detection (Lightning devices only).
    pub const IAP_DETECTION: u32 = 0x0F;
    /// `01`: more DeviceInfo follows on the next page.
    pub const MORE_DATA: u32 = 0x10;
    /// Free-form data (not reported).
    pub const FREE_FORM: u32 = 0x11;
    /// HID initialisation delay (not reported).
    pub const HID_INIT_DELAY: u32 = 0x12;
    /// Part number (not reported; see `docs/catalog/mgmt.md`).
    pub const PART_NUMBER: u32 = 0x13;
    /// FIPS-capable applications, bit field (reported as zero: not a FIPS device).
    pub const FIPS_CAPABLE: u32 = 0x14;
    /// FIPS-approved applications, bit field (reported as zero).
    pub const FIPS_APPROVED: u32 = 0x15;
    /// PIN complexity policy enforced, 1 byte (reported as `00`).
    pub const PIN_COMPLEXITY: u32 = 0x16;
    /// NFC restricted (NFC devices only).
    pub const NFC_RESTRICTED: u32 = 0x17;
    /// Applications whose reset is blocked, bit field (reported as zero).
    pub const RESET_BLOCKED: u32 = 0x18;
    /// Version qualifier (pre-release firmware only; not reported).
    pub const VERSION_QUALIFIER: u32 = 0x19;
}

/// Most TLV bytes in one READ CONFIG page: the page is prefixed by a one-byte length
/// (yubikit-python `read_device_info` checks `len(encoded) - 1 == encoded[0]`).
///
/// Model policy: the firmware's own page size is not documented; the engine fills a
/// page up to what the length byte can express. The DeviceInfo of this device (about
/// 50 bytes) always fits page 0.
pub const PAGE_LIMIT: usize = 0xFF;

/// The `MORE_DATA` object closing every page but the last.
const MORE_DATA_TLV: [u8; 3] = [tag::MORE_DATA as u8, 0x01, 0x01];

/// Everything DeviceInfo reports, already resolved against the profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InfoFields {
    pub usb_supported: u16,
    pub serial: u32,
    pub usb_enabled: u16,
    pub form_factor: u8,
    pub version: [u8; 3],
    pub auto_eject_timeout: u16,
    pub chalresp_timeout: u8,
    pub device_flags: u8,
    pub locked: bool,
}

/// The DeviceInfo data objects in the order the host receives them.
///
/// A USB-only device reports no NFC tags (`0D`, `0E`, `17`) and no Lightning tag
/// (`0F`). Of the tags added for the 5.7 firmware generation, `14`, `15`, `16` and
/// `18` are reported with zero values: yubikit decodes them to the same defaults as
/// their absence (not FIPS, no PIN complexity, no reset block). Model policy: whether
/// a non-FIPS 5.7.4 key sends them is unmeasured (`docs/catalog/mgmt.md`).
pub(crate) fn encode_items(f: &InfoFields) -> Vec<Vec<u8>> {
    vec![
        tlv::encode(tag::USB_SUPPORTED, &f.usb_supported.to_be_bytes()),
        tlv::encode(tag::SERIAL, &f.serial.to_be_bytes()),
        tlv::encode(tag::USB_ENABLED, &f.usb_enabled.to_be_bytes()),
        tlv::encode(tag::FORM_FACTOR, &[f.form_factor]),
        tlv::encode(tag::VERSION, &f.version),
        tlv::encode(tag::AUTO_EJECT_TIMEOUT, &f.auto_eject_timeout.to_be_bytes()),
        tlv::encode(tag::CHALRESP_TIMEOUT, &[f.chalresp_timeout]),
        tlv::encode(tag::DEVICE_FLAGS, &[f.device_flags]),
        tlv::encode(tag::CONFIG_LOCK, &[u8::from(f.locked)]),
        tlv::encode(tag::FIPS_CAPABLE, &[0x00, 0x00]),
        tlv::encode(tag::FIPS_APPROVED, &[0x00, 0x00]),
        tlv::encode(tag::PIN_COMPLEXITY, &[0x00]),
        tlv::encode(tag::RESET_BLOCKED, &[0x00, 0x00]),
    ]
}

/// The TLV bytes of page `page` when `items` are split into pages of at most `limit`
/// bytes, or `None` past the last page.
///
/// Whole data objects are packed greedily; every page but the last ends with
/// `MORE_DATA` (`10 01 01`), which counts towards `limit`. An empty list is one empty
/// page. A single object larger than a page still goes alone on its page (the
/// caller rejects a page that the length byte cannot express).
pub(crate) fn paginate(items: &[Vec<u8>], page: usize, limit: usize) -> Option<Vec<u8>> {
    let mut rest = items;
    let mut index = 0usize;
    loop {
        let total: usize = rest.iter().map(Vec::len).sum();
        if total <= limit {
            return (index == page).then(|| rest.concat());
        }
        let budget = limit.saturating_sub(MORE_DATA_TLV.len());
        let mut used = 0usize;
        let mut taken = 0usize;
        for item in rest {
            if taken > 0 && used.saturating_add(item.len()) > budget {
                break;
            }
            used = used.saturating_add(item.len());
            taken += 1;
        }
        if index == page {
            let mut out = rest.get(..taken).unwrap_or(&[]).concat();
            out.extend_from_slice(&MORE_DATA_TLV);
            return Some(out);
        }
        rest = rest.get(taken..).unwrap_or(&[]);
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(t: u8, len: usize) -> Vec<u8> {
        tlv::encode(u32::from(t), &vec![t; len])
    }

    // Source: yubikit-python `read_device_info`: pages are requested while the page
    // carries MORE_DATA (tag 0x10, value 01) and the TLVs of all pages are merged.
    #[test]
    fn paginate_single_page_has_no_more_data() {
        let items = vec![obj(1, 2), obj(2, 4)];
        assert_eq!(paginate(&items, 0, PAGE_LIMIT), Some(items.concat()));
        assert_eq!(paginate(&items, 1, PAGE_LIMIT), None);
    }

    #[test]
    fn paginate_empty_list_is_one_empty_page() {
        assert_eq!(paginate(&[], 0, PAGE_LIMIT), Some(Vec::new()));
        assert_eq!(paginate(&[], 1, PAGE_LIMIT), None);
    }

    #[test]
    fn paginate_splits_whole_objects_and_marks_more_data() {
        // Five 10-byte objects (2-byte header + 8), limit 25: a non-final page holds
        // 22 bytes of objects (two objects) plus the 3-byte marker.
        let items: Vec<Vec<u8>> = (1..=5).map(|t| obj(t, 8)).collect();
        let p0 = paginate(&items, 0, 25).expect("page 0");
        let p1 = paginate(&items, 1, 25).expect("page 1");
        let p2 = paginate(&items, 2, 25).expect("page 2");
        assert_eq!(paginate(&items, 3, 25), None);
        let mut want0 = [items[0].clone(), items[1].clone()].concat();
        want0.extend_from_slice(&[0x10, 0x01, 0x01]);
        let mut want1 = [items[2].clone(), items[3].clone()].concat();
        want1.extend_from_slice(&[0x10, 0x01, 0x01]);
        assert_eq!(p0, want0);
        assert_eq!(p1, want1);
        // The last page may use the whole limit and has no marker.
        assert_eq!(p2, items[4].clone());
        for p in [&p0, &p1, &p2] {
            assert!(p.len() <= 25);
        }
        // Merging the pages without their markers gives back the list.
        let merged: Vec<u8> = [p0, p1, p2]
            .iter()
            .flat_map(|p| {
                tlv::parse_all(p)
                    .expect("page parses")
                    .into_iter()
                    .filter(|t| t.tag != tag::MORE_DATA)
                    .flat_map(|t| t.raw.to_vec())
                    .collect::<Vec<u8>>()
            })
            .collect();
        assert_eq!(merged, items.concat());
    }

    #[test]
    fn paginate_last_page_fills_limit_exactly() {
        // 3 objects of 10 bytes, limit 30: everything fits, no marker.
        let items: Vec<Vec<u8>> = (1..=3).map(|t| obj(t, 8)).collect();
        assert_eq!(paginate(&items, 0, 30), Some(items.concat()));
        // Limit 29: page 0 takes two objects (20 <= 26) and the marker.
        let p0 = paginate(&items, 0, 29).expect("page 0");
        assert_eq!(p0.len(), 23);
        assert_eq!(paginate(&items, 1, 29), Some(items[2].clone()));
    }

    #[test]
    fn paginate_oversized_object_goes_alone() {
        let items = vec![obj(1, 40), obj(2, 1)];
        let p0 = paginate(&items, 0, 10).expect("page 0");
        assert_eq!(p0.len(), 42 + 3);
        assert_eq!(paginate(&items, 1, 10), Some(items[1].clone()));
        assert_eq!(paginate(&items, 2, 10), None);
    }

    #[test]
    fn paginate_tiny_limit_terminates() {
        let items: Vec<Vec<u8>> = (1..=4).map(|t| obj(t, 1)).collect();
        for limit in 0..4 {
            let mut pages = 0;
            while paginate(&items, pages, limit).is_some() {
                pages += 1;
                assert!(pages <= items.len() + 1);
            }
            assert!(pages >= 1);
        }
    }
}
