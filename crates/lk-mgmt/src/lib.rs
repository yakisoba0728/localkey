//! Management application: device information (form factor, serial, firmware version,
//! supported/enabled capabilities per transport), configuration lock, auto-eject and
//! touch timeouts, and reboot/re-enumeration requests. Reachable over CCID, the OTP
//! HID interface and CTAPHID vendor commands.
//!
//! # Sources
//!
//! There is no ISO or FIDO specification for this application. The behaviour follows
//! Yubico's public description of the Management application as used by its SDKs:
//!
//! - *yubikit-python* `yubikit/management.py` (and the equivalent yubikit-android
//!   `management` module): the AID, `INS_READ_CONFIG 0x1D`, `INS_WRITE_CONFIG 0x1C`,
//!   the DeviceInfo/DeviceConfig TLV tags, `DeviceConfig.get_bytes` (the
//!   length-prefixed write format), `read_device_info` (the paged read with the
//!   `MORE_DATA` tag `0x10`), the CTAP backend (`CTAP_READ_CONFIG 0x42`,
//!   `CTAP_WRITE_CONFIG 0x43`) and the OTP backend (`SLOT_YK4_CAPABILITIES 0x13`,
//!   `SLOT_YK4_SET_DEVICE_INFO 0x15`, response checked with `check_crc`).
//! - The *YubiKey 5 Series Technical Manual* (Yubico developer documentation),
//!   sections on USB interface/application enablement, the configuration lock code
//!   (16 bytes, all-zero means no lock), the auto-eject and challenge-response timeouts
//!   and the device flags.
//! - `reference/BEHAVIOR_CATALOG.md` section "Management" for the decisions taken by
//!   this project (mapping in `docs/catalog/mgmt.md`).
//!
//! # Structure
//!
//! - [`Management`] owns the persisted configuration and is transport-independent:
//!   [`Management::device_info`], [`Management::device_info_page`],
//!   [`Management::read_config`], [`Management::write_config`],
//!   [`Management::enabled_usb`], [`Management::legacy_set_mode`] and the byte-level
//!   entry points for the OTP HID slots ([`Management::otp_read_config`],
//!   [`Management::otp_write_config`], [`Management::serial`]) and the CTAPHID vendor
//!   commands ([`Management::ctaphid_vendor`]). The mapping onto
//!   `lk_otp::MgmtBridge` is in the `transport` module documentation.
//! - [`MgmtApplet`] is the CCID view ([`lk_core::CardApplet`]) wrapping one
//!   [`Management`]; `lk-device` reaches the shared state through
//!   [`MgmtApplet::management`] / [`MgmtApplet::management_mut`]. It follows the
//!   binding APDU conventions of `docs/CONTRACTS.md` ("Applications B"): `6882` for
//!   secure-messaging CLA bits, `6E00` for other classes (`6881` for a logical
//!   channel), and at most Ne response bytes per APDU with `61xx` and GET RESPONSE
//!   (`C0`) for the rest. Where the reference key was measured to differ
//!   (`docs/MEASUREMENT.md`), the measurement wins: CLA `80` is served like `00`, and
//!   GET RESPONSE with nothing pending is `6D00`.
//!
//! State is persisted in [`lk_core::Record::Device`] (format in [`Management::new`]).
//! The device identity (serial, firmware version, form factor, supported capabilities)
//! always comes from [`lk_core::Host::profile`] and is never stored.
//!
//! The configuration lock code is wiped when the state holding it is dropped, and the
//! records this crate persists are passed from a `lk_crypto::SecretBytes`
//! (`docs/DESIGN.md` §8); WRITE CONFIG data received over CCID is wiped by
//! `lk_codec::apdu`'s types. [`Management::to_record`] hands out a plain copy.

#![forbid(unsafe_code)]

mod applet;
mod config;
mod info;
mod transport;

pub use applet::{AID, MgmtApplet, ins};
pub use config::{
    ConfigEffect, DEFAULT_CHALRESP_TIMEOUT_SECS, LOCK_CODE_LEN, Management, device_flags,
};
pub use info::{PAGE_LIMIT, tag};
pub use transport::{VendorReply, append_otp_crc, ctaphid, otp_crc16, otp_slot};
