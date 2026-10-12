//! The DeviceInfo TLV list and its paging (yubikit-python `yubikit/management.py`,
//! `TAG`, `DeviceInfo.parse_tlvs` and `ManagementSession.read_device_info`).
//!
//! READ CONFIG answers `len || TLVs`, where `len` is one byte. When the TLV list does
//! not fit one page the host asks for page 1, 2, … (P1 on CCID, the payload byte on
//! CTAPHID and OTP HID) as long as the page carries `MORE_DATA` (`10 01 01`).
//!
//! The pages are laid out as the reference key sends them (`docs/MEASUREMENT.md`,
//! probe `mgmt-read-config`): two fixed pages, the first ending with `MORE_DATA`.

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
    /// Lightning accessory detection; the reference key reports `00`
    /// (`docs/MEASUREMENT.md`, probe `mgmt-read-config`).
    pub const IAP_DETECTION: u32 = 0x0F;
    /// `01`: more DeviceInfo follows on the next page.
    pub const MORE_DATA: u32 = 0x10;
    /// Free-form data; reported as four zero bytes (measured, probe `mgmt-read-config`).
    pub const FREE_FORM: u32 = 0x11;
    /// HID initialisation delay; reported as `00` (measured, probe `mgmt-read-config`).
    pub const HID_INIT_DELAY: u32 = 0x12;
    /// Part number, ASCII (`lk_core::DeviceProfile::part_number`).
    pub const PART_NUMBER: u32 = 0x13;
    /// FIPS-capable applications, bit field (reported as zero: not a FIPS device).
    pub const FIPS_CAPABLE: u32 = 0x14;
    /// FIPS-approved applications, bit field (reported as zero).
    pub const FIPS_APPROVED: u32 = 0x15;
    /// PIN complexity policy enforced, 1 byte (reported as `00`).
    pub const PIN_COMPLEXITY: u32 = 0x16;
    /// NFC restricted; a USB-only reference key reports `00` (measured, probe
    /// `mgmt-read-config`).
    pub const NFC_RESTRICTED: u32 = 0x17;
    /// Applications whose reset is blocked, bit field (reported as zero).
    pub const RESET_BLOCKED: u32 = 0x18;
    /// Version qualifier (pre-release firmware only; not reported).
    pub const VERSION_QUALIFIER: u32 = 0x19;
    /// Fingerprint sensor firmware version (YubiKey Bio), 3 bytes; the reference key
    /// reports `000000` (measured, probe `mgmt-read-config`), which yubikit reads as
    /// absent.
    pub const FPS_VERSION: u32 = 0x20;
    /// Secure element (STM) firmware version (YubiKey Bio), 3 bytes; reported as
    /// `000000` (measured, probe `mgmt-read-config`).
    pub const STM_VERSION: u32 = 0x21;
}

/// Most TLV bytes one READ CONFIG page can carry: the page is prefixed by a one-byte
/// length (yubikit-python `read_device_info` checks `len(encoded) - 1 == encoded[0]`).
///
/// The pages themselves follow the fixed layout measured on the reference key
/// (`docs/MEASUREMENT.md`, probe `mgmt-read-config`; 51 and 41 TLV bytes with the
/// profiles' part numbers), which stays well within this bound.
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
    pub part_number: Vec<u8>,
}

/// The DeviceInfo pages as bare TLVs, in the order and split the reference key
/// sends them (`docs/MEASUREMENT.md`, probe `mgmt-read-config`):
///
/// - page 0: `01 03 02 04 05 06 07 08 0A 0F 20 21`, then `MORE_DATA` (`10 01 01`);
/// - page 1: `11 12 13 14 15 16 17 18`, no `MORE_DATA`.
///
/// The values the key reported for tags the engine has no state for are sent as
/// measured: `0F 01 00`, `20 03 000000`, `21 03 000000`, `11 04 00000000`, `12 01 00`,
/// `14 02 0000`, `15 02 0000`, `16 01 00`, `17 01 00`, `18 02 0000`. yubikit decodes
/// each of them like an absent tag (not FIPS, no PIN complexity, no reset block, no
/// Bio sensor versions). The part number (`13`) is the profile's. No NFC tag (`0D`,
/// `0E`) and no version qualifier (`19`) is sent.
pub(crate) fn pages(f: &InfoFields) -> [Vec<u8>; 2] {
    let mut page0 = [
        tlv::encode(tag::USB_SUPPORTED, &f.usb_supported.to_be_bytes()),
        tlv::encode(tag::USB_ENABLED, &f.usb_enabled.to_be_bytes()),
        tlv::encode(tag::SERIAL, &f.serial.to_be_bytes()),
        tlv::encode(tag::FORM_FACTOR, &[f.form_factor]),
        tlv::encode(tag::VERSION, &f.version),
        tlv::encode(tag::AUTO_EJECT_TIMEOUT, &f.auto_eject_timeout.to_be_bytes()),
        tlv::encode(tag::CHALRESP_TIMEOUT, &[f.chalresp_timeout]),
        tlv::encode(tag::DEVICE_FLAGS, &[f.device_flags]),
        tlv::encode(tag::CONFIG_LOCK, &[u8::from(f.locked)]),
        tlv::encode(tag::IAP_DETECTION, &[0x00]),
        tlv::encode(tag::FPS_VERSION, &[0x00; 3]),
        tlv::encode(tag::STM_VERSION, &[0x00; 3]),
    ]
    .concat();
    page0.extend_from_slice(&MORE_DATA_TLV);
    let page1 = [
        tlv::encode(tag::FREE_FORM, &[0x00; 4]),
        tlv::encode(tag::HID_INIT_DELAY, &[0x00]),
        tlv::encode(tag::PART_NUMBER, &f.part_number),
        tlv::encode(tag::FIPS_CAPABLE, &[0x00, 0x00]),
        tlv::encode(tag::FIPS_APPROVED, &[0x00, 0x00]),
        tlv::encode(tag::PIN_COMPLEXITY, &[0x00]),
        tlv::encode(tag::NFC_RESTRICTED, &[0x00]),
        tlv::encode(tag::RESET_BLOCKED, &[0x00, 0x00]),
    ]
    .concat();
    [page0, page1]
}

/// Every DeviceInfo object of every page, without `MORE_DATA`: the merged list yubikit
/// builds from the pages.
pub(crate) fn merged(f: &InfoFields) -> Vec<u8> {
    let [mut page0, page1] = pages(f);
    page0.truncate(page0.len().saturating_sub(MORE_DATA_TLV.len()));
    page0.extend_from_slice(&page1);
    page0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields() -> InfoFields {
        InfoFields {
            usb_supported: 0x031E,
            serial: 0x0102_0304,
            usb_enabled: 0x031E,
            form_factor: 0x04,
            version: [5, 7, 4],
            auto_eject_timeout: 0,
            chalresp_timeout: 0x0F,
            device_flags: 0,
            locked: false,
            part_number: b"ABCDEFGHIJKL".to_vec(),
        }
    }

    // docs/MEASUREMENT.md, probe `mgmt-read-config`: with the key's values (supported
    // and enabled 031E, chalresp 0F; serial and part number replaced here) page 0 is
    // the 51 TLV bytes below and page 1 the 41 bytes below, byte for byte.
    #[test]
    fn pages_match_the_measured_layout() {
        let [p0, p1] = pages(&fields());
        let want0: [u8; 51] = [
            0x01, 0x02, 0x03, 0x1E, 0x03, 0x02, 0x03, 0x1E, 0x02, 0x04, 0x01, 0x02, 0x03,
            0x04, //
            0x04, 0x01, 0x04, 0x05, 0x03, 0x05, 0x07, 0x04, 0x06, 0x02, 0x00, 0x00, //
            0x07, 0x01, 0x0F, 0x08, 0x01, 0x00, 0x0A, 0x01, 0x00, 0x0F, 0x01, 0x00, //
            0x20, 0x03, 0x00, 0x00, 0x00, 0x21, 0x03, 0x00, 0x00, 0x00, 0x10, 0x01, 0x01,
        ];
        let mut want1 = vec![
            0x11, 0x04, 0x00, 0x00, 0x00, 0x00, 0x12, 0x01, 0x00, 0x13, 0x0C,
        ];
        want1.extend_from_slice(b"ABCDEFGHIJKL");
        want1.extend_from_slice(&[
            0x14, 0x02, 0x00, 0x00, 0x15, 0x02, 0x00, 0x00, 0x16, 0x01, 0x00, 0x17, 0x01,
            0x00, //
            0x18, 0x02, 0x00, 0x00,
        ]);
        assert_eq!(p0, want0.to_vec());
        assert_eq!(p1, want1);
        assert_eq!(p1.len(), 41);
        assert!(p0.len() <= PAGE_LIMIT && p1.len() <= PAGE_LIMIT);
    }

    // yubikit-python `read_device_info` merges the pages after popping MORE_DATA.
    #[test]
    fn merged_is_both_pages_without_more_data() {
        let f = fields();
        let [p0, p1] = pages(&f);
        let all = merged(&f);
        assert_eq!(all.len(), p0.len() - 3 + p1.len());
        let items = tlv::parse_all(&all).expect("parses");
        assert!(items.iter().all(|t| t.tag != tag::MORE_DATA));
        let tags: Vec<u32> = items.iter().map(|t| t.tag).collect();
        assert_eq!(
            tags,
            [
                0x01, 0x03, 0x02, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0A, 0x0F, 0x20, 0x21, 0x11, 0x12,
                0x13, 0x14, 0x15, 0x16, 0x17, 0x18
            ]
        );
    }

    #[test]
    fn empty_part_number_is_an_empty_value() {
        let f = InfoFields {
            part_number: Vec::new(),
            ..fields()
        };
        let [_, p1] = pages(&f);
        assert_eq!(p1.len(), 29);
        assert_eq!(p1.get(9..11), Some(&[0x13, 0x00][..]));
    }
}
