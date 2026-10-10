//! The host side of the card applications, written from their specifications: ISO/IEC
//! 7816-4 command APDUs (§5.1 short and extended forms, §7.6.1 GET RESPONSE), YKOATH
//! (Yubico OATH protocol description), PIV (NIST SP 800-73-4 Part 2 and the Yubico PIV
//! extensions), OpenPGP card 3.4.1 and YubiHSM Auth (yubikit `hsmauth.py` wire format).

#![allow(dead_code, clippy::unwrap_used)]

use lk_crypto::{aes_ecb_decrypt_block, aes_ecb_encrypt_block};

use super::{Rig, sw};

/// A command APDU in the short form when it fits (Nc ≤ 255, Ne ≤ 256), else extended
/// (ISO/IEC 7816-4 §5.1). `le` is Ne; `Some(256)` encodes as `00` (short).
pub fn command(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: Option<usize>) -> Vec<u8> {
    if data.len() > 255 || le.is_some_and(|n| n > 256) {
        return extended(cla, ins, p1, p2, data, le);
    }
    let mut out = vec![cla, ins, p1, p2];
    if !data.is_empty() {
        out.push(data.len() as u8);
        out.extend_from_slice(data);
    }
    if let Some(n) = le {
        out.push((n % 256) as u8);
    }
    out
}

/// The extended form (§5.1): `00 Lc(2)` before the data, `Le(2)` (or `00 Le(2)` without
/// data); Ne 65 536 encodes as `00 00`.
pub fn extended(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: Option<usize>) -> Vec<u8> {
    let mut out = vec![cla, ins, p1, p2];
    if !data.is_empty() {
        out.push(0x00);
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
    }
    if let Some(n) = le {
        if data.is_empty() {
            out.push(0x00);
        }
        out.extend_from_slice(&((n % 65_536) as u16).to_be_bytes());
    }
    out
}

/// A BER-TLV with a one-byte or two-byte tag and a minimal length (ISO/IEC 7816-4 §5.2).
pub fn tlv(tag: u16, value: &[u8]) -> Vec<u8> {
    let mut out = if tag > 0xFF { tag.to_be_bytes().to_vec() } else { vec![tag as u8] };
    match value.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n <= 0xFF => out.extend_from_slice(&[0x81, n as u8]),
        n => {
            out.push(0x82);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
    }
    out.extend_from_slice(value);
    out
}

/// Split `data || SW1 SW2`.
pub fn split(response: &[u8]) -> (&[u8], u16) {
    let (data, status) = response.split_at(response.len() - 2);
    (data, u16::from_be_bytes([status[0], status[1]]))
}

/// Find a top-level BER-TLV object by tag in `data` (tags of one or two bytes).
pub fn find_tlv(data: &[u8], tag: u16) -> Option<Vec<u8>> {
    let mut rest = data;
    while !rest.is_empty() {
        let (t, after_tag) = if rest[0] & 0x1F == 0x1F {
            (u16::from_be_bytes([rest[0], rest[1]]), &rest[2..])
        } else {
            (u16::from(rest[0]), &rest[1..])
        };
        let (len, after_len) = match after_tag[0] {
            n if n < 0x80 => (usize::from(n), &after_tag[1..]),
            0x81 => (usize::from(after_tag[1]), &after_tag[2..]),
            0x82 => (usize::from(u16::from_be_bytes([after_tag[1], after_tag[2]])), &after_tag[3..]),
            other => panic!("length byte {other:#04x}"),
        };
        if t == tag {
            return Some(after_len[..len].to_vec());
        }
        rest = &after_len[len..];
    }
    None
}

impl Rig {
    /// Send a command and follow `61xx` with GET RESPONSE (`00 C0 00 00 xx`, ISO/IEC
    /// 7816-4 §7.6.1), as a host stack does; returns the reassembled response and the
    /// number of GET RESPONSE commands used.
    pub fn transmit(&mut self, apdu: &[u8]) -> (Vec<u8>, usize) {
        let mut response = self.apdu(apdu);
        let mut data = Vec::new();
        let mut fetches = 0;
        while response.len() >= 2 && response[response.len() - 2] == 0x61 {
            data.extend_from_slice(&response[..response.len() - 2]);
            let le = response[response.len() - 1];
            response = self.apdu(&[0x00, 0xC0, 0x00, 0x00, le]);
            fetches += 1;
            assert!(fetches < 400, "endless GET RESPONSE");
        }
        data.extend_from_slice(&response);
        (data, fetches)
    }

    /// [`Rig::transmit`] without the fetch count.
    pub fn send(&mut self, apdu: &[u8]) -> Vec<u8> {
        self.transmit(apdu).0
    }
}

// ----- PIV (SP 800-73-4 Part 2; Yubico PIV extensions) -----

pub mod piv {
    /// The default management key of firmware 5.7: AES-192
    /// `010203040506070801020304050607080102030405060708` (Yubico PIV documentation).
    pub const DEFAULT_MGMT_KEY: [u8; 24] = [
        1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
    ];
    /// Algorithm identifiers (SP 800-78-4 Table 6-2; Yubico AES-192 `0A`).
    pub const ALG_AES192: u8 = 0x0A;
    pub const ALG_ECCP256: u8 = 0x11;
    /// Key references.
    pub const SLOT_AUTH: u8 = 0x9A;
    pub const SLOT_SIGN: u8 = 0x9C;
    pub const MGMT: u8 = 0x9B;
    pub const PIN: u8 = 0x80;
    /// Yubico touch policy (GENERATE tag `AB`) values: `01` never, `02` always, `03`
    /// cached.
    pub const TOUCH_ALWAYS: u8 = 0x02;

    /// A PIN padded with `FF` to 8 bytes (Part 2 §3.2.1).
    pub fn pin_block(pin: &str) -> Vec<u8> {
        let mut block = vec![0xFF; 8];
        block[..pin.len()].copy_from_slice(pin.as_bytes());
        block
    }
}

impl Rig {
    /// PIV VERIFY (Part 2 §3.2.1).
    pub fn piv_verify(&mut self, pin: &str) -> u16 {
        sw(&self.apdu(&command(0x00, 0x20, 0x00, piv::PIN, &piv::pin_block(pin), None)))
    }

    /// Mutual authentication with the AES-192 management key (Part 2 §3.2.4, Appendix
    /// A.2): request a witness, decrypt it, return it with a challenge, and check the
    /// card's encryption of the challenge.
    pub fn piv_authenticate(&mut self, key: &[u8; 24]) {
        let request = command(0x00, 0x87, piv::ALG_AES192, piv::MGMT, &tlv(0x7C, &tlv(0x80, &[])), None);
        let response = self.apdu(&request);
        let (data, status) = split(&response);
        assert_eq!(status, 0x9000, "witness request");
        let witness = find_tlv(&find_tlv(data, 0x7C).unwrap(), 0x80).unwrap();
        assert_eq!(witness.len(), 16, "AES block witness");
        let clear = aes_ecb_decrypt_block(key, &witness).unwrap();
        let challenge = [0x5C; 16];
        let inner = [tlv(0x80, &clear), tlv(0x81, &challenge)].concat();
        let response = self.apdu(&command(0x00, 0x87, piv::ALG_AES192, piv::MGMT, &tlv(0x7C, &inner), None));
        let (data, status) = split(&response);
        assert_eq!(status, 0x9000, "mutual authentication");
        let answer = find_tlv(&find_tlv(data, 0x7C).unwrap(), 0x82).unwrap();
        assert_eq!(answer, aes_ecb_encrypt_block(key, &challenge).unwrap(), "card proves the key");
    }

    /// GENERATE ASYMMETRIC KEY PAIR (Part 2 §3.3.2) for ECC P-256, optionally with a
    /// Yubico touch policy (tag `AB`; `AA` is the PIN policy); returns the public point
    /// from `7F49 { 86 point }`.
    pub fn piv_generate_p256(&mut self, slot: u8, touch: Option<u8>) -> Vec<u8> {
        let mut template = tlv(0x80, &[piv::ALG_ECCP256]);
        if let Some(policy) = touch {
            template.extend_from_slice(&tlv(0xAB, &[policy]));
        }
        let response = self.send(&command(0x00, 0x47, 0x00, slot, &tlv(0xAC, &template), Some(256)));
        let (data, status) = split(&response);
        assert_eq!(status, 0x9000, "GENERATE");
        let point = find_tlv(&find_tlv(data, 0x7F49).unwrap(), 0x86).unwrap();
        assert_eq!((point.len(), point[0]), (65, 0x04));
        point
    }

    /// GENERAL AUTHENTICATE signature request (Part 2 §3.2.4, Appendix A.4):
    /// `7C { 82 00, 81 digest }`.
    pub fn piv_sign_request(slot: u8, digest: &[u8]) -> Vec<u8> {
        let inner = [tlv(0x82, &[]), tlv(0x81, digest)].concat();
        command(0x00, 0x87, piv::ALG_ECCP256, slot, &tlv(0x7C, &inner), Some(256))
    }

    /// The DER signature from a GENERAL AUTHENTICATE response `7C { 82 sig }`.
    pub fn piv_signature(response: &[u8]) -> Vec<u8> {
        let (data, status) = split(response);
        assert_eq!(status, 0x9000, "GENERAL AUTHENTICATE {response:02X?}");
        find_tlv(&find_tlv(data, 0x7C).unwrap(), 0x82).unwrap()
    }
}

// ----- OpenPGP card 3.4.1 -----

pub mod pgp {
    /// Default PW1 and PW3 (spec §4.3).
    pub const PW1: &[u8] = b"123456";
    pub const PW3: &[u8] = b"12345678";
    /// Algorithm attributes for ECDSA P-256 (spec §4.4.3.10: algorithm ID `13`, then
    /// the curve OID 1.2.840.10045.3.1.7).
    pub const ECDSA_P256: [u8; 9] = [0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
}

impl Rig {
    /// VERIFY (spec §7.2.2) with P2 `81` (PW1 for signing), `82` (PW1) or `83` (PW3).
    pub fn pgp_verify(&mut self, p2: u8, pin: &[u8]) -> u16 {
        sw(&self.apdu(&command(0x00, 0x20, 0x00, p2, pin, None)))
    }

    /// PUT DATA (spec §7.2.8) of a simple data object.
    pub fn pgp_put(&mut self, tag: u16, value: &[u8]) -> u16 {
        let [p1, p2] = tag.to_be_bytes();
        sw(&self.apdu(&command(0x00, 0xDA, p1, p2, value, None)))
    }

    /// GENERATE ASYMMETRIC KEY PAIR (spec §7.2.14) for the signature key (CRT `B6`);
    /// returns the EC point from `7F49 { 86 point }`.
    pub fn pgp_generate_signature_key(&mut self) -> Vec<u8> {
        let response = self.send(&command(0x00, 0x47, 0x80, 0x00, &[0xB6, 0x00], Some(256)));
        let (data, status) = split(&response);
        assert_eq!(status, 0x9000, "GENERATE {response:02X?}");
        let point = find_tlv(&find_tlv(data, 0x7F49).unwrap(), 0x86).unwrap();
        assert_eq!((point.len(), point[0]), (65, 0x04));
        point
    }

    /// PSO: COMPUTE DIGITAL SIGNATURE (spec §7.2.10).
    pub fn pgp_sign_request(digest: &[u8]) -> Vec<u8> {
        command(0x00, 0x2A, 0x9E, 0x9A, digest, Some(256))
    }

    /// The digital signature counter: DO `93` inside the security support template
    /// `7A` (spec §4.4.1).
    pub fn pgp_signature_counter(&mut self) -> u32 {
        let response = self.send(&command(0x00, 0xCA, 0x00, 0x7A, &[], Some(256)));
        let (data, status) = split(&response);
        assert_eq!(status, 0x9000);
        let counter = find_tlv(&find_tlv(data, 0x7A).unwrap(), 0x93).unwrap();
        counter.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b))
    }
}

// ----- YKOATH -----

pub mod oath {
    /// Type and algorithm byte: TOTP `20` | SHA-1 `01`, SHA-256 `02`, SHA-512 `03`.
    pub const TOTP_SHA1: u8 = 0x21;
    pub const TOTP_SHA256: u8 = 0x22;
    pub const TOTP_SHA512: u8 = 0x23;
    /// Property `REQUIRE_TOUCH`.
    pub const REQUIRE_TOUCH: u8 = 0x02;

    /// PUT (`01`): `71 name, 73 { type|alg, digits, secret } [, 78 property]`.
    pub fn put(name: &[u8], kind: u8, digits: u8, secret: &[u8], touch: bool) -> Vec<u8> {
        let mut data = super::tlv(0x71, name);
        let mut key = vec![kind, digits];
        key.extend_from_slice(secret);
        data.extend_from_slice(&super::tlv(0x73, &key));
        if touch {
            data.extend_from_slice(&[0x78, REQUIRE_TOUCH]);
        }
        super::command(0x00, 0x01, 0x00, 0x00, &data, None)
    }

    /// CALCULATE (`A2`): `71 name, 74 challenge`; P2 `01` truncated, `00` full.
    pub fn calculate(name: &[u8], challenge: &[u8], truncated: bool) -> Vec<u8> {
        let data = [super::tlv(0x71, name), super::tlv(0x74, challenge)].concat();
        super::command(0x00, 0xA2, 0x00, u8::from(truncated), &data, Some(256))
    }

    /// The code of a truncated response `76 { digits, 4 bytes }` (RFC 4226 §5.3:
    /// `value & 0x7FFFFFFF mod 10^digits`).
    pub fn code(response: &[u8]) -> String {
        let (data, status) = super::split(response);
        assert_eq!(status, 0x9000, "CALCULATE {response:02X?}");
        let value = super::find_tlv(data, 0x76).unwrap();
        let digits = u32::from(value[0]);
        let n = u32::from_be_bytes(value[1..5].try_into().unwrap()) & 0x7FFF_FFFF;
        format!("{:0width$}", n % 10u32.pow(digits), width = digits as usize)
    }
}

// ----- YubiHSM Auth (yubikit hsmauth.py) -----

pub mod hsmauth {
    /// Algorithm `AES128_YUBICO_AUTHENTICATION` (38).
    pub const AES128: u8 = 38;
    /// The default management key: 16 zero bytes.
    pub const DEFAULT_MGMT_KEY: [u8; 16] = [0; 16];

    /// PUT CREDENTIAL (`01`): `7B mgmt key, 71 label, 74 algorithm, 75 K-ENC, 76 K-MAC,
    /// 73 credential password, 7A touch`.
    pub fn put(label: &[u8], enc: &[u8; 16], mac: &[u8; 16], password: &[u8; 16], touch: bool) -> Vec<u8> {
        let data = [
            super::tlv(0x7B, &DEFAULT_MGMT_KEY),
            super::tlv(0x71, label),
            super::tlv(0x74, &[AES128]),
            super::tlv(0x75, enc),
            super::tlv(0x76, mac),
            super::tlv(0x73, password),
            super::tlv(0x7A, &[u8::from(touch)]),
        ]
        .concat();
        super::command(0x00, 0x01, 0x00, 0x00, &data, None)
    }

    /// CALCULATE (`03`): `71 label, 77 context(16), 73 credential password`.
    pub fn calculate(label: &[u8], context: &[u8; 16], password: &[u8; 16]) -> Vec<u8> {
        let data = [super::tlv(0x71, label), super::tlv(0x77, context), super::tlv(0x73, password)].concat();
        super::command(0x00, 0x03, 0x00, 0x00, &data, Some(256))
    }

    /// LIST CREDENTIALS (`05`).
    pub const LIST: [u8; 4] = [0x00, 0x05, 0x00, 0x00];
}
