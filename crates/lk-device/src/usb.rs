//! What the program needs to present the device on a USB bus: identity strings, the
//! product ID for the enabled interfaces, and the class descriptors.

use lk_core::UsbInterfaces;

/// Everything the program needs to enumerate the device ([`crate::Device::usb_identity`]).
///
/// The descriptors are given for all three interfaces; the program exposes those named
/// in [`UsbIdentity::interfaces`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbIdentity {
    /// `idVendor` (`DeviceProfile::usb_vendor_id`).
    pub vendor_id: u16,
    /// `idProduct` for the enabled interfaces (`ProductIds::for_interfaces`; the YubiKey
    /// profile uses `0x0401..=0x0407`, catalog appendix A "USB class matching IDs for
    /// seven interface combinations").
    pub product_id: u16,
    /// `bcdDevice` (`DeviceProfile::usb_device_release`).
    pub device_release: u16,
    /// `iManufacturer` string.
    pub manufacturer: String,
    /// `iProduct` string, e.g. `"YubiKey FIDO+CCID"` (`DeviceProfile::product_string`;
    /// the reference observation names the FIDO+CCID device exactly so).
    pub product: String,
    /// `iSerialNumber` string, or `None` when the device reports no serial number over
    /// USB. Model policy from the OTP extended flag `EXTFLAG_SERIAL_USB_VISIBLE`
    /// (Yubico `ykdef.h`: "Serial number visible in the USB iSerial field"): the
    /// decimal serial is reported only while a configured OTP slot sets that flag.
    pub serial: Option<String>,
    /// The interfaces the device exposes now.
    pub interfaces: UsbInterfaces,
    /// The FIDO HID report descriptor ([`FIDO_REPORT_DESCRIPTOR`]).
    pub fido_report_descriptor: Vec<u8>,
    /// The OTP HID report descriptor ([`OTP_REPORT_DESCRIPTOR`]).
    pub otp_report_descriptor: Vec<u8>,
    /// The CCID class descriptor (`lk_ccid::descriptor::YUBIKEY_5C_NANO`, 54 bytes).
    pub ccid_class_descriptor: Vec<u8>,
}

/// `bcdUSB` 2.00 (`device_fields.bcdUSB` 512 in
/// `reference/yubikey-5c-nano-5.7.4/usb-reference-observation.json`).
const BCD_USB: u16 = 0x0200;
/// `bMaxPacketSize0` (`device_fields.bMaxPacketSize0` 64).
const MAX_PACKET_SIZE_0: u8 = 64;
/// `bmAttributes` of the configuration: bus powered, no remote wakeup (byte 7 of the
/// reference `configuration_descriptor_hex`, `80`; USB 2.0 §9.6.3).
const CONFIG_ATTRIBUTES: u8 = 0x80;
/// `bMaxPower` in 2 mA units (byte 8 of the reference configuration, `0F` = 30 mA).
const CONFIG_MAX_POWER: u8 = 0x0F;
/// Interface classes (USB-IF class codes): HID `03`, smart card (CCID) `0B`.
const CLASS_HID: u8 = 0x03;
const CLASS_CCID: u8 = 0x0B;
/// HID boot interface subclass and keyboard protocol (USB HID 1.11 §4.2, §4.3).
const SUBCLASS_BOOT: u8 = 0x01;
const PROTOCOL_KEYBOARD: u8 = 0x01;
/// Endpoint transfer types (USB 2.0 §9.6.6 `bmAttributes`).
const BULK: u8 = 0x02;
const INTERRUPT: u8 = 0x03;

/// One endpoint descriptor (USB 2.0 §9.6.6): address, transfer type, `wMaxPacketSize`,
/// `bInterval`.
#[derive(Debug, Clone, Copy)]
struct Endpoint(u8, u8, u16, u8);

/// The FIDO HID endpoints of the reference configuration: interrupt OUT `04` and IN
/// `84`, 64 bytes, `bInterval` 2.
const FIDO_ENDPOINTS: [Endpoint; 2] = [Endpoint(0x04, INTERRUPT, 64, 2), Endpoint(0x84, INTERRUPT, 64, 2)];
/// The CCID endpoints of the reference configuration: bulk OUT `02` and IN `82`, 64
/// bytes; interrupt IN `83`, 8 bytes, `bInterval` 32 (USB CCID Rev 1.1 §3.2: bulk-out,
/// bulk-in and the optional interrupt-in pipe).
const CCID_ENDPOINTS: [Endpoint; 3] = [
    Endpoint(0x02, BULK, 64, 0),
    Endpoint(0x82, BULK, 64, 0),
    Endpoint(0x83, INTERRUPT, 8, 32),
];
/// The OTP keyboard endpoint: interrupt IN `81`, 8 bytes (the boot report size, HID 1.11
/// Appendix B.1), `bInterval` 10. Model policy: no OTP interface was measured; endpoint
/// 1 is the number the reference configuration leaves free, and 10 ms is the report
/// period `lk_otp` paces keyboard output with (`lk_otp::REPORT_PERIOD_MS`).
const OTP_ENDPOINTS: [Endpoint; 1] = [Endpoint(0x81, INTERRUPT, 8, 10)];

impl UsbIdentity {
    /// The standard device descriptor (USB 2.0 §9.6.1, 18 bytes).
    ///
    /// `bcdUSB`, the zero class triple (each interface names its class),
    /// `bMaxPacketSize0`, the IDs, `bcdDevice` and one configuration match the
    /// reference `device_fields`. The string indices are model policy (not measured):
    /// manufacturer 1, product 2, serial number 3, or 0 while
    /// [`UsbIdentity::serial`] is `None` (§9.6.1: "zero if no string descriptor").
    pub fn device_descriptor(&self) -> [u8; 18] {
        let [usb_lo, usb_hi] = BCD_USB.to_le_bytes();
        let [vid_lo, vid_hi] = self.vendor_id.to_le_bytes();
        let [pid_lo, pid_hi] = self.product_id.to_le_bytes();
        let [rel_lo, rel_hi] = self.device_release.to_le_bytes();
        let serial_index = if self.serial.is_some() { 3 } else { 0 };
        [
            18, 0x01, usb_lo, usb_hi, 0x00, 0x00, 0x00, MAX_PACKET_SIZE_0, vid_lo, vid_hi, pid_lo, pid_hi, rel_lo,
            rel_hi, 1, 2, serial_index, 1,
        ]
    }

    /// The configuration descriptor with every interface, class and endpoint descriptor
    /// for [`UsbIdentity::interfaces`] (USB 2.0 §9.6.3–§9.6.6, USB HID 1.11 §6.2.1,
    /// USB CCID Rev 1.1 §5.1), as returned by GET_DESCRIPTOR(CONFIGURATION).
    ///
    /// For FIDO+CCID this is byte for byte the measured `configuration_descriptor_hex`
    /// of `reference/yubikey-5c-nano-5.7.4/usb-reference-observation.json`: the FIDO HID
    /// interface (HID descriptor naming the 34-byte report descriptor, endpoints
    /// `04`/`84`), then the CCID interface (the 54-byte class descriptor, endpoints
    /// `02`/`82`/`83`). Interfaces are numbered from 0 in the order OTP, FIDO, CCID, and
    /// each function keeps its endpoint numbers in every combination. The OTP keyboard
    /// interface (boot keyboard, HID 1.11 §4.2–§4.3; [`OTP_REPORT_DESCRIPTOR`]; endpoint
    /// `81`) is model policy: no configuration with OTP was measured.
    pub fn configuration_descriptor(&self) -> Vec<u8> {
        let mut body = Vec::new();
        let mut count = 0u8;
        if self.interfaces.otp {
            interface(&mut body, count, CLASS_HID, SUBCLASS_BOOT, PROTOCOL_KEYBOARD, &OTP_ENDPOINTS, |out| {
                hid_descriptor(out, self.otp_report_descriptor.len());
            });
            count += 1;
        }
        if self.interfaces.fido {
            interface(&mut body, count, CLASS_HID, 0, 0, &FIDO_ENDPOINTS, |out| {
                hid_descriptor(out, self.fido_report_descriptor.len());
            });
            count += 1;
        }
        if self.interfaces.ccid {
            interface(&mut body, count, CLASS_CCID, 0, 0, &CCID_ENDPOINTS, |out| {
                out.extend_from_slice(&self.ccid_class_descriptor);
            });
            count += 1;
        }
        let total = u16::try_from(9 + body.len()).unwrap_or(u16::MAX);
        let [total_lo, total_hi] = total.to_le_bytes();
        let mut out = vec![9, 0x02, total_lo, total_hi, count, 1, 0, CONFIG_ATTRIBUTES, CONFIG_MAX_POWER];
        out.extend_from_slice(&body);
        out
    }
}

/// An interface descriptor (USB 2.0 §9.6.5, no string), its class-specific descriptor
/// and its endpoint descriptors.
fn interface(
    out: &mut Vec<u8>,
    number: u8,
    class: u8,
    subclass: u8,
    protocol: u8,
    endpoints: &[Endpoint],
    class_descriptor: impl FnOnce(&mut Vec<u8>),
) {
    let count = u8::try_from(endpoints.len()).unwrap_or(u8::MAX);
    out.extend_from_slice(&[9, 0x04, number, 0, count, class, subclass, protocol, 0]);
    class_descriptor(out);
    for &Endpoint(address, kind, size, interval) in endpoints {
        let [size_lo, size_hi] = size.to_le_bytes();
        out.extend_from_slice(&[7, 0x05, address, kind, size_lo, size_hi, interval]);
    }
}

/// The HID descriptor (USB HID 1.11 §6.2.1): `bcdHID` `0110` (HID 1.10, as the
/// reference configuration has it), no country code, one report descriptor of
/// `report_len` bytes (`09 21 10 01 00 01 22 22 00` in the reference configuration).
fn hid_descriptor(out: &mut Vec<u8>, report_len: usize) {
    let [len_lo, len_hi] = u16::try_from(report_len).unwrap_or(u16::MAX).to_le_bytes();
    out.extend_from_slice(&[9, 0x21, 0x10, 0x01, 0x00, 0x01, 0x22, len_lo, len_hi]);
}

/// The FIDO HID report descriptor, byte-exact from
/// `reference/yubikey-5c-nano-5.7.4/usb-reference-observation.json`
/// (`hid_report_descriptor_hex`
/// `06d0f10901a1010920150026ff007508954081020921150026ff00750895409102c0`): usage page
/// `F1D0` (FIDO Alliance), usage 1 (CTAPHID), a 64-byte input report (usage `20`) and a
/// 64-byte output report (usage `21`), as CTAP 2.1 §11.2.8.1 prescribes. Its length
/// (34) is the `wDescriptorLength` in the reference configuration descriptor.
pub const FIDO_REPORT_DESCRIPTOR: [u8; 34] = [
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance, 0xF1D0)
    0x09, 0x01, // Usage (CTAPHID)
    0xA1, 0x01, // Collection (Application)
    0x09, 0x20, //   Usage (Input Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x81, 0x02, //   Input (Data, Variable, Absolute)
    0x09, 0x21, //   Usage (Output Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x91, 0x02, //   Output (Data, Variable, Absolute)
    0xC0, // End Collection
];

/// The OTP HID report descriptor.
///
/// Model policy: the reference observation was taken in the FIDO+CCID configuration,
/// so no OTP interface bytes were measured. The descriptor is the boot keyboard of
/// USB HID 1.11 Appendix E.6 (modifier byte, reserved byte, five LED outputs, six key
/// codes; Appendix B.1 boot protocol) followed by the 8-byte feature report the OTP
/// protocol uses (`lk_otp::FEATURE_RPT_SIZE`; Yubico `ykdef.h` `FEATURE_RPT_SIZE 8`),
/// declared in the vendor-defined usage page `FF00` because no public source fixes its
/// usage.
pub const OTP_REPORT_DESCRIPTOR: [u8; 77] = [
    0x05, 0x01, // Usage Page (Generic Desktop)
    0x09, 0x06, // Usage (Keyboard)
    0xA1, 0x01, // Collection (Application)
    0x05, 0x07, //   Usage Page (Keyboard/Keypad)
    0x19, 0xE0, //   Usage Minimum (Left Control)
    0x29, 0xE7, //   Usage Maximum (Right GUI)
    0x15, 0x00, //   Logical Minimum (0)
    0x25, 0x01, //   Logical Maximum (1)
    0x75, 0x01, //   Report Size (1)
    0x95, 0x08, //   Report Count (8)
    0x81, 0x02, //   Input (Data, Variable, Absolute): modifier byte
    0x95, 0x01, //   Report Count (1)
    0x75, 0x08, //   Report Size (8)
    0x81, 0x01, //   Input (Constant): reserved byte
    0x95, 0x05, //   Report Count (5)
    0x75, 0x01, //   Report Size (1)
    0x05, 0x08, //   Usage Page (LEDs)
    0x19, 0x01, //   Usage Minimum (Num Lock)
    0x29, 0x05, //   Usage Maximum (Kana)
    0x91, 0x02, //   Output (Data, Variable, Absolute): LED report
    0x95, 0x01, //   Report Count (1)
    0x75, 0x03, //   Report Size (3)
    0x91, 0x01, //   Output (Constant): LED padding
    0x95, 0x06, //   Report Count (6)
    0x75, 0x08, //   Report Size (8)
    0x15, 0x00, //   Logical Minimum (0)
    0x25, 0x65, //   Logical Maximum (101)
    0x05, 0x07, //   Usage Page (Keyboard/Keypad)
    0x19, 0x00, //   Usage Minimum (0)
    0x29, 0x65, //   Usage Maximum (101)
    0x81, 0x00, //   Input (Data, Array): key codes
    0x06, 0x00, 0xFF, //   Usage Page (Vendor Defined 0xFF00)
    0x09, 0x01, //   Usage (1)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x08, //   Report Count (8)
    0xB1, 0x02, //   Feature (Data, Variable, Absolute): OTP feature report
    0xC0, // End Collection
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a hex string (test vectors only).
    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap_or_default())
            .collect()
    }

    /// The FIDO report descriptor equals `hid_report_descriptor_hex` of
    /// `reference/yubikey-5c-nano-5.7.4/usb-reference-observation.json`.
    #[test]
    fn fido_descriptor_matches_the_reference() {
        let reference = hex("06d0f10901a1010920150026ff007508954081020921150026ff00750895409102c0");
        assert_eq!(FIDO_REPORT_DESCRIPTOR.to_vec(), reference);
    }

    /// Walks a HID report descriptor's short items (USB HID 1.11 §6.2.2.2) and checks
    /// collections balance; returns the total feature report bits of the OTP layout.
    fn walk(descriptor: &[u8]) -> (usize, usize, usize) {
        let (mut i, mut depth, mut report_size, mut report_count) = (0usize, 0i32, 0usize, 0usize);
        let (mut input_bits, mut output_bits, mut feature_bits) = (0, 0, 0);
        while i < descriptor.len() {
            let prefix = descriptor[i];
            let size = match prefix & 0x03 {
                3 => 4,
                n => usize::from(n),
            };
            let data = &descriptor[i + 1..i + 1 + size];
            let value = data.iter().rev().fold(0usize, |acc, &b| acc << 8 | usize::from(b));
            match prefix & 0xFC {
                0xA0 => depth += 1,
                0xC0 => depth -= 1,
                0x74 => report_size = value,
                0x94 => report_count = value,
                0x80 => input_bits += report_size * report_count,
                0x90 => output_bits += report_size * report_count,
                0xB0 => feature_bits += report_size * report_count,
                _ => {}
            }
            assert!(depth >= 0, "unbalanced collection");
            i += 1 + size;
        }
        assert_eq!(depth, 0, "unclosed collection");
        (input_bits, output_bits, feature_bits)
    }

    /// The OTP descriptor is a HID 1.11 Appendix B.1 boot keyboard (8-byte input report,
    /// 1-byte LED output report) plus the 8-byte OTP feature report (`ykdef.h`
    /// `FEATURE_RPT_SIZE`).
    #[test]
    fn otp_descriptor_is_boot_keyboard_with_feature_report() {
        assert_eq!(walk(&OTP_REPORT_DESCRIPTOR), (64, 8, 64));
        assert_eq!(&OTP_REPORT_DESCRIPTOR[..4], &[0x05, 0x01, 0x09, 0x06]);
        assert_eq!(walk(&FIDO_REPORT_DESCRIPTOR), (512, 512, 0));
    }
}
