//! Byte-level entry points for the non-CCID transports of the Management application.
//!
//! - CTAPHID vendor commands (CTAP 2.1 §11.2.9.3 reserves `0x40..=0x7F` for vendors;
//!   yubikit-python `yubikit/management.py`, `_ManagementCtapBackend`):
//!   `0x42` READ CONFIG (payload empty or one page byte) and `0x43` WRITE CONFIG
//!   (payload `len || TLVs`).
//! - OTP HID slots (yubikit-python `yubikit/management.py`, `_ManagementOtpBackend`,
//!   and `yubikit/core/otp.py`): `0x13` read DeviceInfo (first data byte is the page;
//!   the response is checked with `check_crc`), `0x15` write configuration (`len ||
//!   TLVs` zero-padded to the 64-byte slot data), `0x10` serial.
//!
//! The OTP HID framing itself (feature reports, sequence numbers, the programming
//! sequence counter, the response length byte and CRC) belongs to `lk-otp`. Its
//! `MgmtBridge` maps onto this crate as follows (`lk-device` implements it):
//!
//! | `lk_otp::MgmtBridge` | `lk-mgmt` |
//! | --- | --- |
//! | `serial` | `Some(`[`Management::serial`]`)` |
//! | `device_info(page)` (bare TLVs) | [`Management::device_info_page`] |
//! | `write_device_info(len \|\| TLVs)` | [`Management::write_config`] (keep the [`ConfigEffect`]) |
//! | `write_device_config` (SET MODE) | [`Management::legacy_set_mode`] |
//! | `challenge_response_timeout_s` | [`Management::challenge_response_timeout_secs`] |
//!
//! [`Management::otp_read_config`] and [`Management::otp_read_config_frame`] return
//! the length-prefixed (and CRC-framed) page for a framing layer that does not add
//! them itself; passing either through the bridge would frame the page twice.

use lk_codec::apdu::sw;
use lk_core::Host;

use crate::config::{ConfigEffect, Management};

/// CTAPHID command and error codes used by the Management vendor commands.
pub mod ctaphid {
    /// YubiKey 4 "set mode" vendor command (yubikit `CTAP_YUBIKEY_DEVICE_CONFIG`);
    /// not implemented, see `docs/catalog/mgmt.md`.
    pub const DEVICE_CONFIG: u8 = 0x40;
    /// READ CONFIG (yubikit `CTAP_READ_CONFIG`).
    pub const READ_CONFIG: u8 = 0x42;
    /// WRITE CONFIG (yubikit `CTAP_WRITE_CONFIG`).
    pub const WRITE_CONFIG: u8 = 0x43;
    /// `CTAPHID_ERROR` (CTAP 2.1 §11.2.9.1.6).
    pub const ERROR: u8 = 0x3F;
    /// `ERR_INVALID_PAR` (CTAP 2.1 §11.2.9.1.6).
    pub const ERR_INVALID_PAR: u8 = 0x02;
    /// `ERR_INVALID_LEN` (CTAP 2.1 §11.2.9.1.6).
    pub const ERR_INVALID_LEN: u8 = 0x03;
    /// `ERR_OTHER` (CTAP 2.1 §11.2.9.1.6).
    pub const ERR_OTHER: u8 = 0x7F;

    /// The `CTAPHID_ERROR` code standing for a Management status word.
    ///
    /// Model policy (the firmware's CTAPHID error codes for these failures are not
    /// documented): `6700` → `ERR_INVALID_LEN`; `6A80`/`6A86` → `ERR_INVALID_PAR`;
    /// `6982` (lock code), `6581` (storage) and anything else → `ERR_OTHER`.
    pub const fn error_code(status: u16) -> u8 {
        match status {
            lk_codec::apdu::sw::WRONG_LENGTH => ERR_INVALID_LEN,
            lk_codec::apdu::sw::INCORRECT_DATA | lk_codec::apdu::sw::INCORRECT_P1P2 => {
                ERR_INVALID_PAR
            }
            _ => ERR_OTHER,
        }
    }
}

/// OTP HID slot numbers (yubikit-python `yubikit/core/otp.py` and `management.py`).
pub mod otp_slot {
    /// Read the serial number (`CMD_DEVICE_SERIAL`).
    pub const DEVICE_SERIAL: u8 = 0x10;
    /// YubiKey 4 "set mode" (`SLOT_DEVICE_CONFIG`); not implemented.
    pub const DEVICE_CONFIG: u8 = 0x11;
    /// Read DeviceInfo (`SLOT_YK4_CAPABILITIES`).
    pub const YK4_CAPABILITIES: u8 = 0x13;
    /// Write configuration (`SLOT_YK4_SET_DEVICE_INFO`).
    pub const YK4_SET_DEVICE_INFO: u8 = 0x15;
}

/// The answer to a Management CTAPHID vendor command: send `payload` with command
/// `cmd` on the requesting channel, then act on `effect`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorReply {
    /// The request's command (7-bit form) on success, [`ctaphid::ERROR`] on failure.
    pub cmd: u8,
    /// The response payload, or the one-byte CTAPHID error code.
    pub payload: Vec<u8>,
    /// What the device must do after sending the reply.
    pub effect: ConfigEffect,
}

impl VendorReply {
    fn error(status: u16) -> Self {
        Self {
            cmd: ctaphid::ERROR,
            payload: vec![ctaphid::error_code(status)],
            effect: ConfigEffect::None,
        }
    }
}

/// CRC-16 of the YubiKey OTP HID protocol: ISO/IEC 13239 (HDLC frame check
/// sequence), reflected polynomial `0x8408`, initial value `0xFFFF`, no final XOR.
///
/// A frame carrying its complemented CRC little-endian ([`append_otp_crc`]) has the
/// residue `0xF0B8` (yubikit-python `yubikit/core/otp.py`, `check_crc`).
pub fn otp_crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            let lsb = crc & 1;
            crc >>= 1;
            if lsb != 0 {
                crc ^= 0x8408;
            }
        }
    }
    crc
}

/// `data || !crc16(data)` little-endian, the form of an OTP HID response frame.
pub fn append_otp_crc(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 2);
    out.extend_from_slice(data);
    out.extend_from_slice(&(!otp_crc16(data)).to_le_bytes());
    out
}

impl Management {
    /// CTAPHID `0x42` READ CONFIG: `len || TLVs` for the page named by the payload
    /// (empty payload: page 0, as older yubikit sends; one byte: that page). A longer
    /// payload is `6700`.
    pub fn ctaphid_read_config(&self, payload: &[u8], host: &dyn Host) -> Result<Vec<u8>, u16> {
        let page = match payload {
            [] => 0,
            [page] => *page,
            _ => return Err(sw::WRONG_LENGTH),
        };
        self.read_config(page, host)
    }

    /// CTAPHID `0x43` WRITE CONFIG: the payload is `len || TLVs` exactly, as for
    /// [`Management::write_config`]. On success the reply payload is empty.
    pub fn ctaphid_write_config(
        &mut self,
        payload: &[u8],
        host: &mut dyn Host,
    ) -> Result<ConfigEffect, u16> {
        self.write_config(payload, host)
    }

    /// Handle a CTAPHID vendor request if it is a Management command (`cmd` in 7-bit
    /// or initialization-packet form); `None` for any other command, which the device
    /// answers itself (for example with `ERR_INVALID_CMD`).
    ///
    /// Failures become `CTAPHID_ERROR` with [`ctaphid::error_code`].
    pub fn ctaphid_vendor(
        &mut self,
        cmd: u8,
        payload: &[u8],
        host: &mut dyn Host,
    ) -> Option<VendorReply> {
        let cmd = cmd & 0x7F;
        let reply = match cmd {
            ctaphid::READ_CONFIG => match self.ctaphid_read_config(payload, host) {
                Ok(data) => VendorReply {
                    cmd,
                    payload: data,
                    effect: ConfigEffect::None,
                },
                Err(status) => VendorReply::error(status),
            },
            ctaphid::WRITE_CONFIG => match self.ctaphid_write_config(payload, host) {
                Ok(effect) => VendorReply {
                    cmd,
                    payload: Vec::new(),
                    effect,
                },
                Err(status) => VendorReply::error(status),
            },
            _ => return None,
        };
        Some(reply)
    }

    /// OTP HID slot `0x13`: `len || TLVs` for the page in the first byte of the
    /// (zero-padded) slot data; empty data reads page 0. No CRC; see
    /// [`Management::otp_read_config_frame`]. Not for `lk_otp::MgmtBridge`, which
    /// takes the bare TLVs of [`Management::device_info_page`].
    ///
    /// The OTP HID response carries at most 32 chunks of 7 bytes (the five sequence
    /// bits, `SEQUENCE_MASK 0x1F`, that yubikit-python `yubikit/core/otp.py`
    /// `_read_frame` follows; `lk-otp` refuses longer responses), so `len || TLVs ||
    /// CRC` must stay within 224 bytes; this device's pages (52 and 42 bytes with the
    /// length byte) do (tested).
    pub fn otp_read_config(&self, slot_data: &[u8], host: &dyn Host) -> Result<Vec<u8>, u16> {
        let page = slot_data.first().copied().unwrap_or(0);
        self.read_config(page, host)
    }

    /// [`Management::otp_read_config`] followed by the OTP response CRC
    /// ([`append_otp_crc`]): the bytes yubikit reads back and checks with `check_crc`.
    /// Use it only if the OTP framing layer does not append the CRC itself (`lk-otp`
    /// does; see the module documentation).
    pub fn otp_read_config_frame(&self, slot_data: &[u8], host: &dyn Host) -> Result<Vec<u8>, u16> {
        self.otp_read_config(slot_data, host)
            .map(|data| append_otp_crc(&data))
    }

    /// OTP HID slot `0x15`: WRITE CONFIG from the 64-byte zero-padded slot data
    /// ([`Management::write_config_padded`]). The OTP layer advances its programming
    /// sequence only on `Ok`.
    pub fn otp_write_config(
        &mut self,
        slot_data: &[u8],
        host: &mut dyn Host,
    ) -> Result<ConfigEffect, u16> {
        self.write_config_padded(slot_data, host)
    }

    /// OTP HID slot `0x10`: the serial number, 4 bytes big-endian (yubikit-python
    /// `YubiOtpSession.get_serial`).
    pub fn serial_bytes(&self, host: &dyn Host) -> [u8; 4] {
        self.serial(host).to_be_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Source: CRC RevEng catalogue, CRC-16/IBM-SDLC (alias X-25, the ISO/IEC 13239
    // FCS): check value 0x906E over "123456789" (after the final complement), residue
    // 0xF0B8.
    #[test]
    fn crc_matches_iso13239_check_value_and_residue() {
        assert_eq!(!otp_crc16(b"123456789"), 0x906E);
        let framed = append_otp_crc(b"123456789");
        assert_eq!(&framed[9..], &[0x6E, 0x90]);
        assert_eq!(otp_crc16(&framed), 0xF0B8);
    }

    #[test]
    fn error_codes_follow_the_model_mapping() {
        assert_eq!(
            ctaphid::error_code(sw::WRONG_LENGTH),
            ctaphid::ERR_INVALID_LEN
        );
        assert_eq!(
            ctaphid::error_code(sw::INCORRECT_DATA),
            ctaphid::ERR_INVALID_PAR
        );
        assert_eq!(
            ctaphid::error_code(sw::INCORRECT_P1P2),
            ctaphid::ERR_INVALID_PAR
        );
        assert_eq!(ctaphid::error_code(sw::SECURITY_STATUS), ctaphid::ERR_OTHER);
        assert_eq!(ctaphid::error_code(sw::MEMORY_FAILURE), ctaphid::ERR_OTHER);
    }
}
