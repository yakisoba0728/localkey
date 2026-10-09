//! Device identity: everything the host can observe that names the device rather than
//! following from a protocol. Chosen by the program; see `docs/DESIGN.md` §9 and §12-2.

/// A firmware version `major.minor.patch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

impl Version {
    pub const fn new(major: u8, minor: u8, patch: u8) -> Self {
        Self { major, minor, patch }
    }

    /// The three bytes `major, minor, patch`, as most protocols report them.
    pub const fn bytes(self) -> [u8; 3] {
        [self.major, self.minor, self.patch]
    }

    /// The CTAP GetInfo `firmwareVersion` integer (`0x050704` for 5.7.4).
    pub const fn as_u32(self) -> u32 {
        (self.major as u32) << 16 | (self.minor as u32) << 8 | self.patch as u32
    }
}

/// Application capability bits as used by the Management application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Capabilities(pub u16);

impl Capabilities {
    pub const OTP: u16 = 0x0001;
    pub const U2F: u16 = 0x0002;
    pub const OPENPGP: u16 = 0x0008;
    pub const PIV: u16 = 0x0010;
    pub const OATH: u16 = 0x0020;
    pub const HSMAUTH: u16 = 0x0100;
    pub const FIDO2: u16 = 0x0200;
    /// Every application this engine implements.
    pub const ALL: Self = Self(
        Self::OTP | Self::U2F | Self::OPENPGP | Self::PIV | Self::OATH | Self::HSMAUTH | Self::FIDO2,
    );

    pub const fn contains(self, bits: u16) -> bool {
        self.0 & bits == bits
    }

    /// The USB interfaces needed to expose these applications.
    pub const fn interfaces(self) -> UsbInterfaces {
        UsbInterfaces {
            otp: self.0 & Self::OTP != 0,
            fido: self.0 & (Self::U2F | Self::FIDO2) != 0,
            ccid: self.0 & (Self::OPENPGP | Self::PIV | Self::OATH | Self::HSMAUTH) != 0,
        }
    }
}

/// Which USB interfaces the device exposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UsbInterfaces {
    pub otp: bool,
    pub fido: bool,
    pub ccid: bool,
}

/// USB product IDs for every combination of interfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductIds {
    pub otp: u16,
    pub fido: u16,
    pub otp_fido: u16,
    pub ccid: u16,
    pub otp_ccid: u16,
    pub fido_ccid: u16,
    pub otp_fido_ccid: u16,
}

impl ProductIds {
    /// The product ID for an interface set; `None` if no interface is enabled.
    pub const fn for_interfaces(&self, interfaces: UsbInterfaces) -> Option<u16> {
        match (interfaces.otp, interfaces.fido, interfaces.ccid) {
            (true, false, false) => Some(self.otp),
            (false, true, false) => Some(self.fido),
            (true, true, false) => Some(self.otp_fido),
            (false, false, true) => Some(self.ccid),
            (true, false, true) => Some(self.otp_ccid),
            (false, true, true) => Some(self.fido_ccid),
            (true, true, true) => Some(self.otp_fido_ccid),
            (false, false, false) => None,
        }
    }
}

/// Form-factor codes reported by the Management application.
pub mod form_factor {
    pub const USB_A_KEYCHAIN: u8 = 0x01;
    pub const USB_A_NANO: u8 = 0x02;
    pub const USB_C_KEYCHAIN: u8 = 0x03;
    pub const USB_C_NANO: u8 = 0x04;
}

/// Everything that identifies a device instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceProfile {
    pub firmware: Version,
    pub serial: u32,
    pub form_factor: u8,
    pub usb_vendor_id: u16,
    pub usb_product_ids: ProductIds,
    /// USB `bcdDevice`.
    pub usb_device_release: u16,
    pub manufacturer: String,
    /// Product string prefix; the interface list is appended (`"YubiKey OTP+FIDO+CCID"`).
    pub product: String,
    /// CTAP authenticator AAGUID.
    pub aaguid: [u8; 16],
    pub supported_usb: Capabilities,
    pub default_enabled_usb: Capabilities,
    /// Common name used in this device's own attestation certificates.
    pub attestation_common_name: String,
    /// Validity of generated certificates as X.509 GeneralizedTime (`YYYYMMDDHHMMSSZ`).
    pub cert_not_before: String,
    pub cert_not_after: String,
}

impl DeviceProfile {
    /// The default: this project's own identity (pid.codes test VID/PID, own AAGUID).
    pub fn own(serial: u32) -> Self {
        Self {
            firmware: Version::new(5, 7, 4),
            serial,
            form_factor: form_factor::USB_C_NANO,
            usb_vendor_id: 0x1209,
            usb_product_ids: ProductIds {
                otp: 0x0001,
                fido: 0x0001,
                otp_fido: 0x0001,
                ccid: 0x0001,
                otp_ccid: 0x0001,
                fido_ccid: 0x0001,
                otp_fido_ccid: 0x0001,
            },
            usb_device_release: 0x0574,
            manufacturer: "localkey".into(),
            product: "localkey".into(),
            aaguid: [
                0x6c, 0x6b, 0x65, 0x79, 0x2d, 0x4c, 0x4b, 0x01, 0x8f, 0x3a, 0x54, 0x6e, 0x67, 0x69, 0x6e, 0x65,
            ],
            supported_usb: Capabilities::ALL,
            default_enabled_usb: Capabilities::ALL,
            attestation_common_name: "localkey software authenticator".into(),
            cert_not_before: "20260101000000Z".into(),
            cert_not_after: "99991231235959Z".into(),
        }
    }

    /// Public identity values of a YubiKey 5C Nano 5.7.4 (`reference/yubikey-5c-nano-5.7.4/`).
    /// Attestation signatures remain this engine's own; no manufacturer key is reproduced.
    pub fn yubikey_5c_nano_5_7_4(serial: u32) -> Self {
        Self {
            usb_vendor_id: 0x1050,
            usb_product_ids: ProductIds {
                otp: 0x0401,
                fido: 0x0402,
                otp_fido: 0x0403,
                ccid: 0x0404,
                otp_ccid: 0x0405,
                fido_ccid: 0x0406,
                otp_fido_ccid: 0x0407,
            },
            manufacturer: "Yubico".into(),
            product: "YubiKey".into(),
            aaguid: [
                0xff, 0x4d, 0xac, 0x45, 0xed, 0xe8, 0x4e, 0xc2, 0xac, 0xed, 0xcf, 0x66, 0x10, 0x3f, 0x43, 0x35,
            ],
            ..Self::own(serial)
        }
    }

    /// USB product string for the enabled interfaces, e.g. `"YubiKey OTP+FIDO+CCID"`.
    pub fn product_string(&self, interfaces: UsbInterfaces) -> String {
        let parts: Vec<&str> = [(interfaces.otp, "OTP"), (interfaces.fido, "FIDO"), (interfaces.ccid, "CCID")]
            .into_iter()
            .filter_map(|(on, name)| on.then_some(name))
            .collect();
        format!("{} {}", self.product, parts.join("+"))
    }
}
