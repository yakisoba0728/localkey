//! Test helpers: a card wrapper around `Oath` with a `TestHost`, APDU builders and a
//! client-side PBKDF2 (RFC 8018 §5.2) for the access-key flow clients implement.

#![allow(dead_code, clippy::unwrap_used)]

use lk_codec::tlv;
use lk_core::{CardApplet, Outcome, Record, ResetKind};
use lk_oath::Oath;
use lk_testkit::TestHost;

pub const SELECT: [u8; 12] = [0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];
pub const SEND_REMAINING: [u8; 4] = [0x00, 0xA5, 0x00, 0x00];
pub const OK: u16 = 0x9000;

pub const HOTP: u8 = 0x10;
pub const TOTP: u8 = 0x20;
pub const SHA1: u8 = 0x01;
pub const SHA256: u8 = 0x02;
pub const SHA512: u8 = 0x03;

/// The RFC 4226 Appendix D / RFC 6238 Appendix B SHA-1 secret.
pub const RFC_SECRET: &[u8] = b"12345678901234567890";

pub struct Card {
    pub oath: Oath,
    pub host: TestHost,
    /// `persist_attempts` right after the first construction: `Oath::new(None, ..)`
    /// stores the factory state (the device id must survive restarts), so commands are
    /// counted from here.
    pub opened: usize,
}

impl Default for Card {
    fn default() -> Self {
        Self::new()
    }
}

impl Card {
    pub fn new() -> Self {
        Self::with_host(TestHost::new())
    }

    pub fn with_host(mut host: TestHost) -> Self {
        let oath = Oath::new(host.persisted(Record::Oath).as_deref(), &mut host);
        let opened = host.persist_attempts();
        Self { oath, host, opened }
    }

    /// Save attempts made since the card was first constructed.
    pub fn writes(&self) -> usize {
        self.host.persist_attempts() - self.opened
    }

    /// Rebuild the applet from what it last persisted (a power cycle).
    pub fn restart(&mut self) {
        self.oath.reset(ResetKind::PowerCycle);
        self.oath = Oath::new(self.host.persisted(Record::Oath).as_deref(), &mut self.host);
    }

    pub fn select(&mut self) -> Vec<u8> {
        self.oath.select(&SELECT, &mut self.host)
    }

    /// SELECT and return the parsed response objects.
    pub fn select_fields(&mut self) -> Vec<(u8, Vec<u8>)> {
        let resp = self.select();
        let (data, sw) = split(&resp);
        assert_eq!(sw, OK);
        parse_tlvs(data)
    }

    pub fn salt(&mut self) -> Vec<u8> {
        field(&self.select_fields(), 0x71).unwrap()
    }

    pub fn outcome(&mut self, apdu: &[u8]) -> Outcome<Vec<u8>> {
        self.oath.process(apdu, &mut self.host)
    }

    /// Send a command that must finish without a touch.
    pub fn send(&mut self, apdu: &[u8]) -> Vec<u8> {
        match self.outcome(apdu) {
            Outcome::Done(resp) => resp,
            Outcome::NeedTouch { .. } => panic!("unexpected touch request"),
        }
    }

    pub fn sw(&mut self, apdu: &[u8]) -> u16 {
        let resp = self.send(apdu);
        split(&resp).1
    }

    /// Send a command and fetch every `61xx` continuation with SEND REMAINING.
    pub fn send_all(&mut self, apdu: &[u8]) -> (Vec<u8>, u16) {
        let first = self.send(apdu);
        self.drain(first)
    }

    /// Collect a response and its continuations.
    pub fn drain(&mut self, first: Vec<u8>) -> (Vec<u8>, u16) {
        let mut resp = first;
        let mut data = Vec::new();
        loop {
            let (chunk, sw) = split(&resp);
            data.extend_from_slice(chunk);
            if sw >> 8 == 0x61 {
                resp = self.send(&SEND_REMAINING);
            } else {
                return (data, sw);
            }
        }
    }

    pub fn touch(&mut self, touched: bool) -> Vec<u8> {
        self.oath.touch_resolved(touched, &mut self.host)
    }

    pub fn put(&mut self, data: &[u8]) -> u16 {
        self.sw(&apdu(0x00, 0x01, 0x00, 0x00, data))
    }

    /// LIST as `(type/algorithm, name)` pairs.
    pub fn list(&mut self) -> Vec<(u8, Vec<u8>)> {
        let (data, sw) = self.send_all(&[0x00, 0xA1, 0x00, 0x00]);
        assert_eq!(sw, OK);
        parse_tlvs(&data)
            .into_iter()
            .map(|(tag, value)| {
                assert_eq!(tag, 0x72);
                (value[0], value[1..].to_vec())
            })
            .collect()
    }

    pub fn names(&mut self) -> Vec<Vec<u8>> {
        self.list().into_iter().map(|(_, name)| name).collect()
    }

    /// CALCULATE with P2 = 01; returns the `76` value (digits then four bytes).
    pub fn calc_truncated(&mut self, name: &[u8], challenge: &[u8]) -> Result<Vec<u8>, u16> {
        let resp = self.send(&calculate_apdu(name, challenge, true));
        expect_object(&resp, 0x76)
    }

    /// CALCULATE with P2 = 00; returns the `75` value (digits then the HMAC).
    pub fn calc_full(&mut self, name: &[u8], challenge: &[u8]) -> Result<Vec<u8>, u16> {
        let resp = self.send(&calculate_apdu(name, challenge, false));
        expect_object(&resp, 0x75)
    }

    /// The decimal code of a truncated CALCULATE.
    pub fn code(&mut self, name: &[u8], challenge: &[u8]) -> u32 {
        code_of(&self.calc_truncated(name, challenge).unwrap())
    }
}

/// The single object `tag` of a successful response, or the status word.
pub fn expect_object(resp: &[u8], tag: u8) -> Result<Vec<u8>, u16> {
    let (data, sw) = split(resp);
    if sw != OK {
        assert!(data.is_empty());
        return Err(sw);
    }
    let fields = parse_tlvs(data);
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].0, tag);
    Ok(fields[0].1.clone())
}

/// `digits || 4 bytes` -> the displayed code (RFC 4226 §5.3 step 3).
pub fn code_of(value: &[u8]) -> u32 {
    let digits = u32::from(value[0]);
    let snum = u32::from_be_bytes([value[1], value[2], value[3], value[4]]);
    snum % 10u32.pow(digits)
}

pub fn split(resp: &[u8]) -> (&[u8], u16) {
    assert!(resp.len() >= 2, "response shorter than a status word");
    let (data, sw) = resp.split_at(resp.len() - 2);
    (data, u16::from_be_bytes([sw[0], sw[1]]))
}

/// A short (or, above 255 bytes, extended) command APDU without Le.
pub fn apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![cla, ins, p1, p2];
    if !data.is_empty() {
        if data.len() <= 255 {
            out.push(data.len() as u8);
        } else {
            out.push(0);
            out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(data);
    }
    out
}

pub fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    tlv::encode(u32::from(tag), value)
}

pub fn parse_tlvs(data: &[u8]) -> Vec<(u8, Vec<u8>)> {
    tlv::parse_all(data)
        .unwrap()
        .into_iter()
        .map(|t| (u8::try_from(t.tag).unwrap(), t.value.to_vec()))
        .collect()
}

pub fn field(fields: &[(u8, Vec<u8>)], tag: u8) -> Option<Vec<u8>> {
    fields.iter().find(|(t, _)| *t == tag).map(|(_, v)| v.clone())
}

/// PUT data as clients build it (YKOATH §PUT): `71` name, `73` type|alg, digits, key,
/// then the raw `78` property byte and the `7A` IMF.
pub fn put_data(name: &[u8], type_alg: u8, digits: u8, secret: &[u8], props: Option<u8>, imf: Option<u32>) -> Vec<u8> {
    let mut key = vec![type_alg, digits];
    key.extend_from_slice(secret);
    let mut data = tlv(0x71, name);
    data.extend(tlv(0x73, &key));
    if let Some(p) = props {
        data.extend([0x78, p]);
    }
    if let Some(counter) = imf {
        data.extend(tlv(0x7A, &counter.to_be_bytes()));
    }
    data
}

/// Client-side secret preparation (as YKOATH clients do): shorten keys longer than the
/// block size (RFC 2104 §2) and pad with zeros to 14 bytes.
pub fn client_secret(secret: &[u8], alg: u8) -> Vec<u8> {
    let (hash, block) = match alg {
        SHA1 => (lk_crypto::HashAlg::Sha1, 64),
        SHA256 => (lk_crypto::HashAlg::Sha256, 64),
        _ => (lk_crypto::HashAlg::Sha512, 128),
    };
    let mut key = if secret.len() > block {
        lk_crypto::digest(hash, secret)
    } else {
        secret.to_vec()
    };
    if key.len() < 14 {
        key.resize(14, 0);
    }
    key
}

pub fn calculate_apdu(name: &[u8], challenge: &[u8], truncated: bool) -> Vec<u8> {
    let mut data = tlv(0x71, name);
    data.extend(tlv(0x74, challenge));
    apdu(0x00, 0xA2, 0x00, u8::from(truncated), &data)
}

pub fn calculate_all_apdu(challenge: &[u8], truncated: bool) -> Vec<u8> {
    apdu(0x00, 0xA4, 0x00, u8::from(truncated), &tlv(0x74, challenge))
}

pub fn delete_apdu(name: &[u8]) -> Vec<u8> {
    apdu(0x00, 0x02, 0x00, 0x00, &tlv(0x71, name))
}

pub fn rename_apdu(old: &[u8], new: &[u8]) -> Vec<u8> {
    let mut data = tlv(0x71, old);
    data.extend(tlv(0x71, new));
    apdu(0x00, 0x05, 0x00, 0x00, &data)
}

/// SET CODE data with a correct HMAC-SHA1 proof (YKOATH §SET CODE).
pub fn set_code_apdu(key: &[u8], challenge: &[u8; 8]) -> Vec<u8> {
    let mut k = vec![TOTP | SHA1];
    k.extend_from_slice(key);
    let mut data = tlv(0x73, &k);
    data.extend(tlv(0x74, challenge));
    data.extend(tlv(0x75, &lk_crypto::hmac_sha1(key, challenge)));
    apdu(0x00, 0x03, 0x00, 0x00, &data)
}

pub fn validate_apdu(response: &[u8], challenge: &[u8]) -> Vec<u8> {
    let mut data = tlv(0x75, response);
    data.extend(tlv(0x74, challenge));
    apdu(0x00, 0xA3, 0x00, 0x00, &data)
}

/// PBKDF2 (RFC 8018 §5.2) with HMAC-SHA1, as YKOATH clients derive the access key from
/// a password: 1000 iterations, the SELECT name as salt, 16 bytes (YKOATH §SET CODE).
pub fn pbkdf2_hmac_sha1(password: &[u8], salt: &[u8], iterations: u32, len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut block = 1u32;
    while out.len() < len {
        let mut s = salt.to_vec();
        s.extend_from_slice(&block.to_be_bytes());
        let mut u = lk_crypto::hmac_sha1(password, &s);
        let mut t = u;
        for _ in 1..iterations {
            u = lk_crypto::hmac_sha1(password, &u);
            for (a, b) in t.iter_mut().zip(u.iter()) {
                *a ^= b;
            }
        }
        out.extend_from_slice(&t);
        block += 1;
    }
    out.truncate(len);
    out
}

pub fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
