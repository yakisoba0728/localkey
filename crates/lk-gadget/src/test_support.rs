//! Shared values for the unit tests: identities built from the engine's public types and
//! the reference observation of a YubiKey 5C Nano.

use lk_core::UsbInterfaces;
use lk_device::UsbIdentity;

/// `configuration_descriptor_hex` of
/// `reference/yubikey-5c-nano-5.7.4/usb-reference-observation.json` (FIDO+CCID).
pub const REFERENCE_CONFIGURATION: &str = "09027d00020100800f090400000203000000092110010001222200070504034000020705840340000209040100030b00000036210001000702000000a00f0000a00f00000000b0040000b0040000f60b00000000000000000000fe000400000c0000ffff00000001070502024000000705820240000007058303080020";

/// Decode a hex string (test vectors only).
pub fn hex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap_or_default()).collect()
}

/// The 54-byte CCID class descriptor of the reference configuration (the `0x21`
/// descriptor after the interface of class `0x0B`; `lk_ccid::descriptor::YUBIKEY_5C_NANO`
/// is decoded from it).
pub fn ccid_class_descriptor() -> Vec<u8> {
    let reference = hex(REFERENCE_CONFIGURATION);
    let start = reference.windows(2).position(|w| w == [0x36, 0x21]).unwrap_or(0);
    reference[start..start + 54].to_vec()
}

pub const FIDO_CCID: UsbInterfaces = UsbInterfaces { otp: false, fido: true, ccid: true };
pub const ALL: UsbInterfaces = UsbInterfaces { otp: true, fido: true, ccid: true };

/// An identity for `interfaces`, as the engine builds it.
pub fn identity(interfaces: UsbInterfaces, serial: Option<&str>) -> UsbIdentity {
    UsbIdentity {
        vendor_id: 0x1050,
        product_id: if interfaces == ALL { 0x0407 } else { 0x0406 },
        device_release: 0x0574,
        manufacturer: "Yubico".into(),
        product: "YubiKey FIDO+CCID".into(),
        serial: serial.map(String::from),
        interfaces,
        fido_report_descriptor: lk_device::FIDO_REPORT_DESCRIPTOR.to_vec(),
        otp_report_descriptor: lk_device::OTP_REPORT_DESCRIPTOR.to_vec(),
        ccid_class_descriptor: ccid_class_descriptor(),
    }
}

/// A fresh directory under the system temporary directory with a short name, removed on
/// drop.
#[derive(Debug)]
pub struct TestDir(std::path::PathBuf);

impl TestDir {
    pub fn new() -> TestDir {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("lkgu{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).expect("the test directory can be created");
        TestDir(path)
    }

    pub fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
