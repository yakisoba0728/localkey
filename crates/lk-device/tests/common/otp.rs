//! The host side of the YubiKey OTP application, written from Yubico's public
//! `ykdef.h` (yubikey-personalization) and the yubikit host protocol description
//! (`yubikit/core/otp.py`): the 52-byte slot configuration, the 70-byte HID frame with
//! its CRC, the feature-report write and read loops, modhex, keyboard decoding (USB HID
//! Usage Tables §10) and Yubico OTP ticket decryption (YubiKey manual "Yubico OTP",
//! libyubikey `yubikey_token_st`). Nothing comes from `lk-otp`.

#![allow(dead_code, clippy::unwrap_used)]

use lk_device::{Input, Output};

use super::Rig;

/// Slot commands (`ykdef.h` `SLOT_*`).
pub mod slot {
    pub const CONFIG1: u8 = 0x01;
    pub const CONFIG2: u8 = 0x03;
    pub const UPDATE1: u8 = 0x04;
    pub const SWAP: u8 = 0x06;
    pub const DEVICE_SERIAL: u8 = 0x10;
    pub const YK4_CAPABILITIES: u8 = 0x13;
    pub const YK4_SET_DEVICE_INFO: u8 = 0x15;
    pub const CHAL_HMAC1: u8 = 0x30;
    pub const CHAL_HMAC2: u8 = 0x38;
}

/// `TKTFLAG_*`.
pub mod tkt {
    pub const APPEND_CR: u8 = 0x20;
    pub const OATH_HOTP: u8 = 0x40;
    pub const CHAL_RESP: u8 = 0x40;
}

/// `CFGFLAG_*`.
pub mod cfg {
    pub const STATIC_TICKET: u8 = 0x20;
    pub const CHAL_HMAC: u8 = 0x22;
    pub const HMAC_LT64: u8 = 0x04;
    pub const CHAL_BTN_TRIG: u8 = 0x08;
}

/// `EXTFLAG_*`.
pub mod ext {
    pub const SERIAL_API_VISIBLE: u8 = 0x04;
}

/// Feature report status byte (`ykdef.h`).
pub const SLOT_WRITE_FLAG: u8 = 0x80;
pub const RESP_PENDING_FLAG: u8 = 0x40;
pub const RESP_TIMEOUT_WAIT_FLAG: u8 = 0x20;
pub const SEQUENCE_MASK: u8 = 0x1F;

/// ISO/IEC 13239 CRC-16 as Yubico computes it (`yubikey_crc16`): reflected polynomial
/// `0x8408`, initial value `0xFFFF`, no final XOR.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0xFFFFu16;
    for &byte in data {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0x8408 } else { crc >> 1 };
        }
    }
    crc
}

/// Data followed by its complemented CRC (little-endian) leaves this residue
/// (`yubikey_crc_ok_p`, `CRC_OK_RESIDUAL`).
pub const CRC_OK_RESIDUE: u16 = 0xF0B8;

/// The modhex alphabet (YubiKey manual "Modhex").
pub const MODHEX: &[u8; 16] = b"cbdefghijklnrtuv";

pub fn modhex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|b| [MODHEX[usize::from(b >> 4)], MODHEX[usize::from(b & 0x0F)]])
        .map(char::from)
        .collect()
}

pub fn modhex_decode(text: &str) -> Vec<u8> {
    let nibble = |c: u8| MODHEX.iter().position(|&m| m == c).unwrap_or_else(|| panic!("not modhex: {c:?}")) as u8;
    text.as_bytes().chunks(2).map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1])).collect()
}

/// The 52-byte `YK_CONFIG` (`ykdef.h`).
#[derive(Debug, Clone, Default)]
pub struct SlotConfig {
    pub fixed: [u8; 16],
    pub fixed_size: u8,
    pub uid: [u8; 6],
    pub key: [u8; 16],
    pub acc_code: [u8; 6],
    pub ext_flags: u8,
    pub tkt_flags: u8,
    pub cfg_flags: u8,
}

impl SlotConfig {
    /// `fixed(16) uid(6) key(16) accCode(6) fixedSize extFlags tktFlags cfgFlags rfu(2)
    /// crc(2)`; `crc = ~yubikey_crc16(bytes 0..50)`, little-endian.
    pub fn to_bytes(&self) -> [u8; 52] {
        let mut out = [0u8; 52];
        out[..16].copy_from_slice(&self.fixed);
        out[16..22].copy_from_slice(&self.uid);
        out[22..38].copy_from_slice(&self.key);
        out[38..44].copy_from_slice(&self.acc_code);
        out[44] = self.fixed_size;
        out[45] = self.ext_flags;
        out[46] = self.tkt_flags;
        out[47] = self.cfg_flags;
        let crc = !crc16(&out[..50]);
        out[50..52].copy_from_slice(&crc.to_le_bytes());
        out
    }

    /// The slot write payload: `config || current access code(6)`, zero-padded to 64
    /// (yubikit `_write_config`).
    pub fn payload(&self, current_access: [u8; 6]) -> [u8; 64] {
        let mut payload = [0u8; 64];
        payload[..52].copy_from_slice(&self.to_bytes());
        payload[52..58].copy_from_slice(&current_access);
        payload
    }

    /// Yubico OTP (YubiKey manual "Yubico OTP"): public ID in `fixed`, private ID, AES key.
    pub fn yubico_otp(public_id: &[u8], private_id: [u8; 6], key: [u8; 16]) -> Self {
        let mut fixed = [0u8; 16];
        fixed[..public_id.len()].copy_from_slice(public_id);
        Self {
            fixed,
            fixed_size: public_id.len() as u8,
            uid: private_id,
            key,
            tkt_flags: tkt::APPEND_CR,
            ..Self::default()
        }
    }

    /// HMAC-SHA1 challenge-response (YubiKey manual "Challenge-response"): the 20-byte
    /// secret is `key(16) || uid[..4]`; `HMAC_LT64` for variable-length challenges.
    pub fn hmac_challenge_response(secret: &[u8; 20], button: bool) -> Self {
        let mut uid = [0u8; 6];
        uid[..4].copy_from_slice(&secret[16..]);
        let mut cfg_flags = cfg::CHAL_HMAC | cfg::HMAC_LT64;
        if button {
            cfg_flags |= cfg::CHAL_BTN_TRIG;
        }
        Self {
            uid,
            key: secret[..16].try_into().unwrap(),
            tkt_flags: tkt::CHAL_RESP,
            cfg_flags,
            ..Self::default()
        }
    }
}

/// The 16-byte Yubico OTP ticket (libyubikey `yubikey_token_st`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ticket {
    pub uid: [u8; 6],
    pub use_counter: u16,
    pub timestamp: u32,
    pub session_counter: u8,
    pub random: u16,
}

/// Split a typed Yubico OTP into public ID and ticket: modhex-decode the last 32
/// characters, decrypt with AES-128 (FIPS 197, one ECB block), and check the ticket CRC
/// (`yubikey_crc_ok_p`).
pub fn decrypt_otp(otp: &str, key: &[u8; 16]) -> (Vec<u8>, Ticket) {
    assert!(otp.len() >= 32, "OTP too short: {otp:?}");
    let (public, token) = otp.split_at(otp.len() - 32);
    let block = modhex_decode(token);
    let plain = lk_crypto::aes_ecb_decrypt_block(key, &block).unwrap();
    assert_eq!(crc16(&plain), CRC_OK_RESIDUE, "ticket CRC");
    let ticket = Ticket {
        uid: plain[..6].try_into().unwrap(),
        use_counter: u16::from_le_bytes([plain[6], plain[7]]),
        timestamp: u32::from_le_bytes([plain[8], plain[9], plain[10], 0]),
        session_counter: plain[11],
        random: u16::from_le_bytes([plain[12], plain[13]]),
    };
    (modhex_decode(public), ticket)
}

/// Decode boot-keyboard reports (USB HID 1.11 Appendix B.1; HID Usage Tables §10:
/// a..z = 04..1D, 1..9 = 1E..26, 0 = 27, ENTER = 28, TAB = 2B; left shift is modifier bit
/// `02`) into text. All-zero reports are key releases.
pub fn keyboard_text(reports: &[[u8; 8]]) -> String {
    let mut text = String::new();
    for report in reports {
        let shift = report[0] & 0x22 != 0;
        for &usage in &report[2..] {
            let c = match usage {
                0 => continue,
                0x04..=0x1D => char::from(b'a' + (usage - 0x04)),
                0x1E..=0x26 => char::from(b'1' + (usage - 0x1E)),
                0x27 => '0',
                0x28 => '\n',
                0x2B => '\t',
                other => panic!("unexpected usage {other:#04x}"),
            };
            text.push(if shift { c.to_ascii_uppercase() } else { c });
        }
    }
    text
}

impl Rig {
    /// Read the feature report (HID GET_REPORT).
    pub fn otp_feature(&mut self) -> [u8; 8] {
        let out = self.input(Input::OtpGetFeature);
        match out.as_slice() {
            [Output::OtpFeature(report)] => *report,
            other => panic!("expected one feature report, got {other:02X?}"),
        }
    }

    /// Send one slot command the way yubikit's `OtpProtocol._send_frame` does: the frame
    /// `payload(64) || slot || crc16(payload) LE || 00 00 00` in ten 7-byte chunks, each
    /// written as `chunk || 80 | seq` after a status read shows `SLOT_WRITE_FLAG` clear;
    /// all-zero chunks other than the first and the last are skipped. Returns every
    /// output of the writes.
    pub fn otp_send_frame(&mut self, slot: u8, payload: &[u8; 64]) -> Vec<Output> {
        let mut frame = [0u8; 70];
        frame[..64].copy_from_slice(payload);
        frame[64] = slot;
        frame[65..67].copy_from_slice(&crc16(payload).to_le_bytes());
        let mut out = Vec::new();
        for (seq, chunk) in frame.chunks(7).enumerate() {
            if seq != 0 && seq != 9 && chunk.iter().all(|&b| b == 0) {
                continue;
            }
            let status = self.otp_feature();
            assert_eq!(status[7] & SLOT_WRITE_FLAG, 0, "device busy before chunk {seq}: {status:02X?}");
            let mut report = [0u8; 8];
            report[..7].copy_from_slice(chunk);
            report[7] = SLOT_WRITE_FLAG | seq as u8;
            out.extend(self.input(Input::OtpSetFeature(&report)));
        }
        out
    }

    /// Read a response the way yubikit's `_read_frame` does: collect chunks while
    /// `RESP_PENDING_FLAG` is set and the sequence matches; a pending report with
    /// sequence 0 after data ends the transfer, and the host then resets the read state
    /// with a dummy write (`_reset_state`: seven zero bytes and `FF`). Returns the raw
    /// concatenated chunks.
    pub fn otp_read_frame(&mut self) -> Vec<u8> {
        let mut data = Vec::new();
        let mut seq = 0u8;
        for _ in 0..32 {
            let report = self.otp_feature();
            let status = report[7];
            assert_ne!(status & RESP_PENDING_FLAG, 0, "no response pending: {report:02X?}");
            if status & SEQUENCE_MASK == seq {
                data.extend_from_slice(&report[..7]);
                seq += 1;
            } else if status & SEQUENCE_MASK == 0 {
                self.input(Input::OtpSetFeature(&[0, 0, 0, 0, 0, 0, 0, 0xFF]));
                return data;
            } else {
                panic!("sequence {} instead of {seq}", status & SEQUENCE_MASK);
            }
        }
        panic!("response never completed");
    }

    /// A slot command with a response of `len` data bytes followed by a CRC (yubikit
    /// `check_crc` over `len + 2` bytes); returns the data.
    pub fn otp_response(&mut self, len: usize) -> Vec<u8> {
        let raw = self.otp_read_frame();
        assert!(raw.len() >= len + 2, "short response {raw:02X?}");
        assert_eq!(crc16(&raw[..len + 2]), CRC_OK_RESIDUE, "response CRC");
        raw[..len].to_vec()
    }

    /// Write a slot configuration and check the programming sequence the status
    /// reports afterwards (yubikit `_write_config` → `_check_status`: the sequence must
    /// advance by one, or restart at 1 after 0).
    pub fn otp_program(&mut self, command: u8, config: &SlotConfig, current_access: [u8; 6]) {
        let before = self.otp_feature()[4];
        self.otp_send_frame(command, &config.payload(current_access));
        let status = self.otp_feature();
        let expected = if before == 0 { 1 } else { before.wrapping_add(1) };
        assert_eq!(status[4], expected, "programming sequence after slot command {command:#04x}: {status:02X?}");
    }
}
