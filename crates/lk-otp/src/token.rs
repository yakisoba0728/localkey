//! The 16-byte Yubico OTP ticket (YubiKey manual, "Yubico OTP"; public libyubikey
//! `yubikey_token_st`).
//!
//! | Offset | Size | Field |
//! | --- | --- | --- |
//! | 0 | 6 | private ID (`uid`) |
//! | 6 | 2 | usage counter, little-endian (15 bits; bit 15 is the caps-lock flag) |
//! | 8 | 3 | timestamp, 8 Hz, little-endian 24 bits |
//! | 11 | 1 | session counter |
//! | 12 | 2 | pseudo-random value, little-endian |
//! | 14 | 2 | complemented CRC-16 of bytes 0..14, little-endian |
//!
//! The ticket is encrypted with AES-128 (FIPS 197) in a single ECB block and typed in
//! modhex after the public ID.

use crate::crc::crc16;

/// Largest usage-counter value; the counter saturates here.
pub const MAX_USE_COUNTER: u16 = 0x7FFF;

/// A plaintext Yubico OTP ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ticket {
    pub uid: [u8; 6],
    pub use_counter: u16,
    /// 24-bit timestamp.
    pub timestamp: u32,
    pub session_counter: u8,
    pub random: u16,
}

impl Ticket {
    /// Encode with the CRC.
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..6].copy_from_slice(&self.uid);
        out[6..8].copy_from_slice(&self.use_counter.to_le_bytes());
        let ts = self.timestamp.to_le_bytes();
        out[8..11].copy_from_slice(&ts[..3]);
        out[11] = self.session_counter;
        out[12..14].copy_from_slice(&self.random.to_le_bytes());
        let crc = !crc16(&out[..14]);
        out[14..16].copy_from_slice(&crc.to_le_bytes());
        out
    }

    /// Decode a plaintext ticket; `None` if its CRC does not check out.
    pub fn from_bytes(bytes: &[u8; 16]) -> Option<Self> {
        if !crate::crc::crc_ok(bytes) {
            return None;
        }
        let mut uid = [0u8; 6];
        uid.copy_from_slice(&bytes[..6]);
        Some(Self {
            uid,
            use_counter: u16::from_le_bytes([bytes[6], bytes[7]]),
            timestamp: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], 0]),
            session_counter: bytes[11],
            random: u16::from_le_bytes([bytes[12], bytes[13]]),
        })
    }

    /// AES-128 encrypt the ticket under `key`.
    pub fn encrypt(&self, key: &[u8; 16]) -> [u8; 16] {
        // A 16-byte key and block cannot be rejected; fall back to zeros defensively.
        lk_crypto::aes_ecb_encrypt_block(key, &self.to_bytes()).unwrap_or([0; 16])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_round_trips_through_aes() {
        let ticket = Ticket {
            uid: [1, 2, 3, 4, 5, 6],
            use_counter: 0x0102,
            timestamp: 0x00ab_cdef,
            session_counter: 7,
            random: 0xbeef,
        };
        let key = [0x42u8; 16];
        let enc = ticket.encrypt(&key);
        let dec = lk_crypto::aes_ecb_decrypt_block(&key, &enc).expect("aes");
        assert_eq!(Ticket::from_bytes(&dec), Some(ticket));
        let bytes = ticket.to_bytes();
        assert_eq!(bytes[6..11], [0x02, 0x01, 0xef, 0xcd, 0xab]);
        assert!(crate::crc::crc_ok(&bytes));
    }
}
