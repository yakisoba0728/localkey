//! CRC-16 and modhex, the two encodings every OTP structure uses.
//!
//! - CRC: Yubico's `yubikey_crc16` (published in the public libyubikey/ykpers sources and
//!   the YubiKey manual's "Yubico OTP" chapter) is CRC-16/ISO-HDLC without the final
//!   XOR: reflected polynomial `0x8408`, initial value `0xFFFF`. A buffer that ends
//!   with the little-endian one's complement of its own CRC leaves the residue
//!   [`CRC_OK_RESIDUE`] (`0xF0B8`, ISO/IEC 13239 §4.2.5.2 / ITU-T X.25 good-FCS value).
//! - Modhex: the YubiKey manual's "modified hexadecimal" alphabet `cbdefghijklnrtuv`,
//!   chosen because these keys sit at the same place on most keyboard layouts.

/// CRC residue of a correctly protected buffer (ISO/IEC 13239, "good FCS").
pub const CRC_OK_RESIDUE: u16 = 0xF0B8;

/// The modhex alphabet: character `n` encodes the nibble value `n`.
pub const MODHEX: &[u8; 16] = b"cbdefghijklnrtuv";

/// Yubico CRC-16 (init `0xFFFF`, reflected polynomial `0x8408`, no final XOR).
///
/// `crc16(b"123456789") == 0x6F91`, the CRC-16/IBM-SDLC check value `0x906E` before
/// its final XOR.
pub fn crc16(data: &[u8]) -> u16 {
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

/// Whether `data` (payload followed by its complemented little-endian CRC) checks out.
pub fn crc_ok(data: &[u8]) -> bool {
    crc16(data) == CRC_OK_RESIDUE
}

/// Append the complemented little-endian CRC of `data`, so that [`crc_ok`] holds.
pub fn append_crc(data: &mut Vec<u8>) {
    let crc = !crc16(data);
    data.extend_from_slice(&crc.to_le_bytes());
}

/// Encode bytes as modhex, high nibble first.
pub fn modhex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for &byte in data {
        out.push(char::from(modhex_char(byte >> 4)));
        out.push(char::from(modhex_char(byte & 0x0F)));
    }
    out
}

/// Decode modhex text (case-insensitive); `None` for odd length or a foreign character.
pub fn modhex_decode(text: &str) -> Option<Vec<u8>> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|&[hi, lo]| Some(modhex_value(hi)? << 4 | modhex_value(lo)?))
        .collect()
}

/// The modhex character for a nibble (only the low four bits are used).
pub(crate) fn modhex_char(nibble: u8) -> u8 {
    MODHEX
        .get(usize::from(nibble & 0x0F))
        .copied()
        .unwrap_or(b'c')
}

fn modhex_value(c: u8) -> Option<u8> {
    let lower = c.to_ascii_lowercase();
    MODHEX
        .iter()
        .position(|&m| m == lower)
        .and_then(|p| u8::try_from(p).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    // CRC catalogue (Greg Cook, "Catalogue of parametrised CRC algorithms"),
    // CRC-16/IBM-SDLC: check 0x906E, residue 0xF0B8. Without the final XOR the
    // check value is !0x906E = 0x6F91.
    #[test]
    fn crc_matches_the_published_check_value() {
        assert_eq!(crc16(b"123456789"), 0x6F91);
        assert_eq!(!crc16(b"123456789"), 0x906E);
    }

    #[test]
    fn appended_crc_leaves_the_residue() {
        let mut data = b"123456789".to_vec();
        append_crc(&mut data);
        assert_eq!(data[9..], [0x6E, 0x90]);
        assert!(crc_ok(&data));
        data[0] ^= 1;
        assert!(!crc_ok(&data));
    }

    // YubiKey manual, "Modhex": 0x0..0xF map to c b d e f g h i j k l n r t u v.
    #[test]
    fn modhex_alphabet_round_trips() {
        let bytes = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        assert_eq!(modhex_encode(&bytes), "cbdefghijklnrtuv");
        assert_eq!(
            modhex_decode("cbdefghijklnrtuv").as_deref(),
            Some(&bytes[..])
        );
        assert_eq!(modhex_decode("CBDE").as_deref(), Some(&[0x01, 0x23][..]));
        assert_eq!(modhex_decode("cba"), None);
        assert_eq!(modhex_decode("ca"), None);
    }
}
