//! The 52-byte slot configuration and its flag bits.
//!
//! Layout and flag values follow Yubico's public `ykdef.h` (yubikey-personalization)
//! `struct config_st` and the YubiKey manual's "Configuration structure" chapter:
//!
//! | Offset | Size | Field |
//! | --- | --- | --- |
//! | 0 | 16 | `fixed` (public ID / token ID / static scan codes) |
//! | 16 | 6 | `uid` (private ID; HMAC/HOTP key bytes 16..20; HOTP IMF) |
//! | 22 | 16 | `key` (AES key; HMAC/HOTP key bytes 0..16) |
//! | 38 | 6 | `accCode` (access code protecting this slot) |
//! | 44 | 1 | `fixedSize` |
//! | 45 | 1 | `extFlags` |
//! | 46 | 1 | `tktFlags` |
//! | 47 | 1 | `cfgFlags` |
//! | 48 | 2 | `rfu` |
//! | 50 | 2 | `crc`: complemented CRC-16, little-endian, over bytes 0..50 |

use core::fmt;

use crate::crc::{crc_ok, crc16};

/// Size of the public `fixed` field.
pub const FIXED_SIZE: usize = 16;
/// Size of the private `uid` field.
pub const UID_SIZE: usize = 6;
/// Size of the AES `key` field.
pub const KEY_SIZE: usize = 16;
/// Size of an access code.
pub const ACC_CODE_SIZE: usize = 6;
/// Size of the whole configuration structure.
pub const CONFIG_SIZE: usize = 52;
/// Size of a slot command payload (the data part of an HID frame).
pub const SLOT_DATA_SIZE: usize = 64;
/// Up to 38 static-password scan codes live in `fixed || uid || key`.
pub const SCAN_CODES_SIZE: usize = FIXED_SIZE + UID_SIZE + KEY_SIZE;

/// `extFlags` bits (`ykdef.h` "Extended flags").
pub mod ext {
    /// Serial number visible at startup (button press).
    pub const SERIAL_BTN_VISIBLE: u8 = 0x01;
    /// Serial number visible in the USB iSerial field.
    pub const SERIAL_USB_VISIBLE: u8 = 0x02;
    /// Serial number visible through the API (slot command `0x10`).
    pub const SERIAL_API_VISIBLE: u8 = 0x04;
    /// Use the numeric keypad for digits.
    pub const USE_NUMERIC_KEYPAD: u8 = 0x08;
    /// Fast trigger when only slot 1 is configured.
    pub const FAST_TRIG: u8 = 0x10;
    /// Allow later UPDATE of flags and access code.
    pub const ALLOW_UPDATE: u8 = 0x20;
    /// Dormant configuration: present but inactive until woken by UPDATE.
    pub const DORMANT: u8 = 0x40;
    /// LED idle state is off rather than on.
    pub const LED_INV: u8 = 0x80;
    /// Bits an UPDATE may change (`EXTFLAG_UPDATE_MASK`).
    pub const UPDATE_MASK: u8 = 0xFF;
}

/// `tktFlags` bits (`ykdef.h` "Ticket flags").
pub mod tkt {
    /// Send TAB before the first part.
    pub const TAB_FIRST: u8 = 0x01;
    /// Send TAB after the first part.
    pub const APPEND_TAB1: u8 = 0x02;
    /// Send TAB after the second part.
    pub const APPEND_TAB2: u8 = 0x04;
    /// Add a 0.5 s delay after the first part.
    pub const APPEND_DELAY1: u8 = 0x08;
    /// Add a 0.5 s delay after the second part.
    pub const APPEND_DELAY2: u8 = 0x10;
    /// Append CR (ENTER) as the final character.
    pub const APPEND_CR: u8 = 0x20;
    /// OATH-HOTP mode (shares its bit with [`CHAL_RESP`]).
    pub const OATH_HOTP: u8 = 0x40;
    /// Challenge-response mode (together with a `cfgFlags` challenge type).
    pub const CHAL_RESP: u8 = 0x40;
    /// Block writes to slot 2 unless slot 2 is configured with this bit too.
    pub const PROTECT_CFG2: u8 = 0x80;
    /// Bits an UPDATE may change (`TKTFLAG_UPDATE_MASK`).
    pub const UPDATE_MASK: u8 =
        TAB_FIRST | APPEND_TAB1 | APPEND_TAB2 | APPEND_DELAY1 | APPEND_DELAY2 | APPEND_CR;
}

/// `cfgFlags` bits (`ykdef.h` "Configuration flags"); meanings depend on the mode.
pub mod cfg {
    /// Send the reference string `0..F` (in modhex) before the data.
    pub const SEND_REF: u8 = 0x01;
    /// Static password (scan codes) without [`STATIC_TICKET`]; half-length ticket with it.
    pub const SHORT_TICKET: u8 = 0x02;
    /// Add 10 ms pacing between keys.
    pub const PACING_10MS: u8 = 0x04;
    /// Add 20 ms pacing between keys.
    pub const PACING_20MS: u8 = 0x08;
    /// Strong password policy #1 (mixed case).
    pub const STRONG_PW1: u8 = 0x10;
    /// Static ticket generation.
    pub const STATIC_TICKET: u8 = 0x20;
    /// Strong password policy #2 (digits).
    pub const STRONG_PW2: u8 = 0x40;
    /// Allow manual update of a static ticket.
    pub const MAN_UPDATE: u8 = 0x80;
    /// OATH-HOTP: eight digits instead of six.
    pub const OATH_HOTP8: u8 = 0x02;
    /// OATH-HOTP: first byte of the token ID in modhex.
    pub const OATH_FIXED_MODHEX1: u8 = 0x10;
    /// OATH-HOTP: first two bytes of the token ID in modhex.
    pub const OATH_FIXED_MODHEX2: u8 = 0x40;
    /// OATH-HOTP: whole token ID in modhex.
    pub const OATH_FIXED_MODHEX: u8 = 0x50;
    /// Challenge-response: Yubico OTP.
    pub const CHAL_YUBICO: u8 = 0x20;
    /// Challenge-response: HMAC-SHA1.
    pub const CHAL_HMAC: u8 = 0x22;
    /// HMAC challenge is shorter than 64 bytes (trailing padding is stripped).
    pub const HMAC_LT64: u8 = 0x04;
    /// Challenge-response requires a button press.
    pub const CHAL_BTN_TRIG: u8 = 0x08;
    /// Mask selecting the challenge type.
    pub const CHAL_MASK: u8 = 0x22;
    /// Bits an UPDATE may change (`CFGFLAG_UPDATE_MASK`).
    pub const UPDATE_MASK: u8 = PACING_10MS | PACING_20MS;
}

/// What a configured slot does, derived from its flags (YubiKey manual, "Modes").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Yubico OTP: public ID plus a fresh AES-encrypted ticket.
    YubicoOtp,
    /// Static ticket: Yubico OTP layout with frozen counters.
    StaticTicket,
    /// Static password: up to 38 scan codes typed verbatim.
    StaticPassword,
    /// OATH-HOTP (RFC 4226) with optional token identifier.
    Hotp,
    /// HMAC-SHA1 challenge-response.
    HmacChallenge,
    /// Yubico OTP challenge-response.
    YubicoChallenge,
}

/// One slot configuration (`struct config_st`).
#[derive(Clone, PartialEq, Eq)]
pub struct SlotConfig {
    pub fixed: [u8; FIXED_SIZE],
    pub uid: [u8; UID_SIZE],
    pub key: [u8; KEY_SIZE],
    pub acc_code: [u8; ACC_CODE_SIZE],
    pub fixed_size: u8,
    pub ext_flags: u8,
    pub tkt_flags: u8,
    pub cfg_flags: u8,
    pub rfu: [u8; 2],
}

impl fmt::Debug for SlotConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlotConfig")
            .field("mode", &self.mode())
            .field("fixed_size", &self.fixed_size)
            .field("ext_flags", &self.ext_flags)
            .field("tkt_flags", &self.tkt_flags)
            .field("cfg_flags", &self.cfg_flags)
            .field("has_access_code", &self.has_access_code())
            .finish_non_exhaustive()
    }
}

impl SlotConfig {
    /// Decode a 52-byte structure whose CRC is correct; `None` otherwise or if
    /// `fixedSize` exceeds the field.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let raw: &[u8; CONFIG_SIZE] = bytes.try_into().ok()?;
        if !crc_ok(raw) {
            return None;
        }
        let config = Self::from_raw(raw);
        if usize::from(config.fixed_size) > FIXED_SIZE {
            return None;
        }
        Some(config)
    }

    fn from_raw(raw: &[u8; CONFIG_SIZE]) -> Self {
        let mut config = Self {
            fixed: [0; FIXED_SIZE],
            uid: [0; UID_SIZE],
            key: [0; KEY_SIZE],
            acc_code: [0; ACC_CODE_SIZE],
            fixed_size: raw[44],
            ext_flags: raw[45],
            tkt_flags: raw[46],
            cfg_flags: raw[47],
            rfu: [raw[48], raw[49]],
        };
        config.fixed.copy_from_slice(&raw[0..16]);
        config.uid.copy_from_slice(&raw[16..22]);
        config.key.copy_from_slice(&raw[22..38]);
        config.acc_code.copy_from_slice(&raw[38..44]);
        config
    }

    /// Encode with a freshly computed CRC.
    pub fn to_bytes(&self) -> [u8; CONFIG_SIZE] {
        let mut raw = [0u8; CONFIG_SIZE];
        raw[0..16].copy_from_slice(&self.fixed);
        raw[16..22].copy_from_slice(&self.uid);
        raw[22..38].copy_from_slice(&self.key);
        raw[38..44].copy_from_slice(&self.acc_code);
        raw[44] = self.fixed_size;
        raw[45] = self.ext_flags;
        raw[46] = self.tkt_flags;
        raw[47] = self.cfg_flags;
        raw[48] = self.rfu[0];
        raw[49] = self.rfu[1];
        let crc = !crc16(&raw[..50]);
        raw[50..52].copy_from_slice(&crc.to_le_bytes());
        raw
    }

    /// The slot's mode (YubiKey manual "Modes"; `ykdef.h` flag combinations).
    pub fn mode(&self) -> Mode {
        if self.tkt_flags & tkt::CHAL_RESP != 0 {
            match self.cfg_flags & cfg::CHAL_MASK {
                cfg::CHAL_HMAC => Mode::HmacChallenge,
                cfg::CHAL_YUBICO => Mode::YubicoChallenge,
                // OATH_HOTP shares the CHAL_RESP bit; 0x02 alone is OATH_HOTP8.
                _ => Mode::Hotp,
            }
        } else if self.cfg_flags & cfg::STATIC_TICKET != 0 {
            Mode::StaticTicket
        } else if self.cfg_flags & cfg::SHORT_TICKET != 0 {
            Mode::StaticPassword
        } else {
            Mode::YubicoOtp
        }
    }

    /// Whether this is a challenge-response configuration.
    pub fn is_challenge_response(&self) -> bool {
        matches!(self.mode(), Mode::HmacChallenge | Mode::YubicoChallenge)
    }

    /// Whether the configuration is dormant (`EXTFLAG_DORMANT`).
    pub fn is_dormant(&self) -> bool {
        self.ext_flags & ext::DORMANT != 0
    }

    /// Whether touching the button makes this slot type something: configured, not
    /// dormant and not challenge-response (`CONFIGx_TOUCH` status bit).
    pub fn is_touch_triggered(&self) -> bool {
        !self.is_dormant() && !self.is_challenge_response()
    }

    /// Whether an access code protects the slot (any nonzero byte).
    pub fn has_access_code(&self) -> bool {
        self.acc_code.iter().any(|&b| b != 0)
    }

    /// The used part of `fixed`.
    pub fn fixed_part(&self) -> &[u8] {
        let len = usize::from(self.fixed_size).min(FIXED_SIZE);
        self.fixed.get(..len).unwrap_or(&[])
    }

    /// The 20-byte HMAC/HOTP secret: `key || uid[0..4]` (`KEY_SIZE_OATH`).
    pub fn secret20(&self) -> [u8; 20] {
        let mut secret = [0u8; 20];
        secret[..16].copy_from_slice(&self.key);
        secret[16..].copy_from_slice(&self.uid[..4]);
        secret
    }

    /// OATH-HOTP initial moving factor: big-endian `uid[4..6]` times 16
    /// (ykpers `ykp_set_oath_imf`).
    pub fn hotp_imf(&self) -> u32 {
        u32::from(u16::from_be_bytes([self.uid[4], self.uid[5]])) * 16
    }

    /// The 38 static-password scan codes `fixed || uid || key`.
    pub fn scan_codes(&self) -> [u8; SCAN_CODES_SIZE] {
        let mut codes = [0u8; SCAN_CODES_SIZE];
        codes[..16].copy_from_slice(&self.fixed);
        codes[16..22].copy_from_slice(&self.uid);
        codes[22..].copy_from_slice(&self.key);
        codes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SlotConfig {
        SlotConfig {
            fixed: [1; 16],
            uid: [2; 6],
            key: [3; 16],
            acc_code: [0; 6],
            fixed_size: 6,
            ext_flags: ext::SERIAL_API_VISIBLE | ext::ALLOW_UPDATE,
            tkt_flags: tkt::APPEND_CR,
            cfg_flags: 0,
            rfu: [0; 2],
        }
    }

    #[test]
    fn round_trip_and_crc_residue() {
        let bytes = sample().to_bytes();
        assert!(crc_ok(&bytes));
        assert_eq!(SlotConfig::parse(&bytes), Some(sample()));
        let mut bad = bytes;
        bad[3] ^= 0x40;
        assert_eq!(SlotConfig::parse(&bad), None);
        assert_eq!(SlotConfig::parse(&bytes[..51]), None);
    }

    #[test]
    fn oversized_fixed_size_is_rejected() {
        let mut config = sample();
        config.fixed_size = 17;
        assert_eq!(SlotConfig::parse(&config.to_bytes()), None);
    }

    #[test]
    fn modes_follow_flag_combinations() {
        let mut c = sample();
        assert_eq!(c.mode(), Mode::YubicoOtp);
        c.cfg_flags = cfg::STATIC_TICKET;
        assert_eq!(c.mode(), Mode::StaticTicket);
        c.cfg_flags = cfg::SHORT_TICKET;
        assert_eq!(c.mode(), Mode::StaticPassword);
        c.tkt_flags = tkt::OATH_HOTP;
        c.cfg_flags = cfg::OATH_HOTP8;
        assert_eq!(c.mode(), Mode::Hotp);
        c.cfg_flags = cfg::CHAL_HMAC | cfg::HMAC_LT64;
        assert_eq!(c.mode(), Mode::HmacChallenge);
        c.cfg_flags = cfg::CHAL_YUBICO;
        assert_eq!(c.mode(), Mode::YubicoChallenge);
        assert!(!c.is_touch_triggered());
    }

    #[test]
    fn imf_is_uid_tail_times_sixteen() {
        let mut c = sample();
        c.uid = [0, 0, 0, 0, 0x01, 0x02];
        assert_eq!(c.hotp_imf(), 0x0102 * 16);
    }
}
