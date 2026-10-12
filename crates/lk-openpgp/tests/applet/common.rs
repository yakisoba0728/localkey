//! Test harness: an `OpenPgp` applet driven through `CardApplet` with `lk_testkit::TestHost`.
#![allow(dead_code, clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::OnceLock;

use lk_codec::apdu::Command;
use lk_codec::tlv;
use lk_core::{CardApplet, DeviceProfile, Outcome, Record};
use lk_openpgp::OpenPgp;
use lk_testkit::{SeededEntropy, TestHost};

/// The public observation of a real reference key.
pub const OBSERVATION: &str =
    include_str!("../../../../reference/physical-key/openpgp-reference-observation.json");

pub const SELECT: [u8; 11] = [0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];

pub fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The first `"key": "<hex>"` string of the observation file.
pub fn observed_hex(key: &str) -> Vec<u8> {
    let needle = format!("\"{key}\": \"");
    let start = OBSERVATION.find(&needle).unwrap() + needle.len();
    let end = OBSERVATION[start..].find('"').unwrap() + start;
    hex(&OBSERVATION[start..end])
}

/// The `"tag": length` pairs of an object of the observation file, in file order.
pub fn observed_lengths(section: &str) -> Vec<(u32, usize)> {
    let start = OBSERVATION.find(&format!("\"{section}\"")).unwrap();
    let open = OBSERVATION[start..].find('{').unwrap() + start + 1;
    let close = OBSERVATION[open..].find('}').unwrap() + open;
    OBSERVATION[open..close]
        .split(',')
        .map(|entry| {
            let (k, v) = entry.split_once(':').unwrap();
            let k = k.trim().trim_matches('"');
            (u32::from_str_radix(k, 16).unwrap(), v.trim().parse().unwrap())
        })
        .collect()
}

pub fn split(resp: Vec<u8>) -> (Vec<u8>, u16) {
    let n = resp.len();
    assert!(n >= 2, "response without status word");
    let sw = u16::from_be_bytes([resp[n - 2], resp[n - 1]]);
    (resp[..n - 2].to_vec(), sw)
}

/// Algorithm attributes of the FA entries (spec §4.4.3.10; observation
/// `algorithm_information`).
pub mod attr {
    pub const RSA2048: &str = "01 0800 0011 00";
    pub const RSA3072: &str = "01 0C00 0011 00";
    pub const RSA4096: &str = "01 1000 0011 00";
    pub const P256_ECDSA: &str = "13 2a8648ce3d030107";
    pub const P384_ECDSA: &str = "13 2b81040022";
    pub const P256_ECDH: &str = "12 2a8648ce3d030107";
    pub const P384_ECDH: &str = "12 2b81040022";
    pub const ED25519: &str = "16 2b06010401da470f01";
    pub const X25519: &str = "12 2b060104019755010501";
    pub const P521_ECDSA: &str = "13 2b81040023";
    pub const P521_ECDH: &str = "12 2b81040023";
    pub const SECP256K1_ECDSA: &str = "13 2b8104000a";
    pub const SECP256K1_ECDH: &str = "12 2b8104000a";
    pub const BP256_ECDSA: &str = "13 2b2403030208010107";
    pub const BP256_ECDH: &str = "12 2b2403030208010107";
    pub const BP384_ECDSA: &str = "13 2b240303020801010b";
    pub const BP384_ECDH: &str = "12 2b240303020801010b";
    pub const BP512_ECDSA: &str = "13 2b240303020801010d";
    pub const BP512_ECDH: &str = "12 2b240303020801010d";
}

/// Control reference templates (spec §7.2.14; Yubico attestation `B6 03 84 01 81`).
pub mod crt {
    pub const SIG: &[u8] = &[0xB6, 0x00];
    pub const DEC: &[u8] = &[0xB8, 0x00];
    pub const AUT: &[u8] = &[0xA4, 0x00];
    pub const ATT: &[u8] = &[0xB6, 0x03, 0x84, 0x01, 0x81];
}

/// The factory state of a fresh applet for `profile`, generated once per test binary: a
/// fresh applet generates an RSA 2048 attestation issuer, which takes a while in debug
/// builds, so most tests start from this snapshot.
pub fn factory_snapshot(yubikey: bool) -> Vec<u8> {
    static OWN: OnceLock<Vec<u8>> = OnceLock::new();
    static YUBIKEY: OnceLock<Vec<u8>> = OnceLock::new();
    let (cell, profile) = if yubikey {
        (&YUBIKEY, DeviceProfile::yubikey_compat(12_345_678))
    } else {
        (&OWN, DeviceProfile::own(12_345_678))
    };
    cell.get_or_init(|| {
        let mut host = TestHost::with_profile(profile);
        let _ = OpenPgp::new(None, &mut host);
        host.persisted(Record::OpenPgp).unwrap()
    })
    .clone()
}

/// RSA primes of a test-side key of `bits`, generated once per binary from a fixed seed.
pub fn rsa_primes(bits: usize) -> (Vec<u8>, Vec<u8>) {
    static KEYS: [OnceLock<(Vec<u8>, Vec<u8>)>; 3] = [OnceLock::new(), OnceLock::new(), OnceLock::new()];
    let index = match bits {
        2048 => 0,
        3072 => 1,
        _ => 2,
    };
    KEYS[index]
        .get_or_init(|| {
            let key = lk_crypto::RsaPrivateKey::generate(bits, &mut SeededEntropy::new(bits as u64 + 77)).unwrap();
            (*key.primes()).clone()
        })
        .clone()
}

/// A public key as returned in 7F49 (spec §7.2.14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Public {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    Point(Vec<u8>),
}

pub fn parse_public(template: &[u8]) -> Public {
    let (outer, rest) = tlv::parse_one(template).unwrap();
    assert!(rest.is_empty());
    assert_eq!(outer.tag, 0x7F49);
    let inner = outer.children().unwrap();
    if let Some(point) = tlv::find(&inner, 0x86) {
        assert_eq!(inner.len(), 1);
        return Public::Point(point.value.to_vec());
    }
    assert_eq!(inner.len(), 2);
    Public::Rsa {
        n: tlv::find(&inner, 0x81).unwrap().value.to_vec(),
        e: tlv::find(&inner, 0x82).unwrap().value.to_vec(),
    }
}

/// SHA-256 DigestInfo (RFC 8017 §9.2 note 1) of `message`.
pub fn digest_info_sha256(message: &[u8]) -> Vec<u8> {
    let mut out = hex("3031300d060960864801650304020105000420");
    out.extend_from_slice(&lk_crypto::sha256(message));
    out
}

/// Verify an RSASSA-PKCS1-v1_5 signature over a DigestInfo independently: RSAVP1 then a
/// comparison with the EMSA-PKCS1-v1_5 block built here (RFC 8017 §8.2.2, §9.2).
pub fn rsa_verify(n: &[u8], e: &[u8], digest_info: &[u8], signature: &[u8]) -> bool {
    let Ok(em) = lk_crypto::rsa_public_op(n, e, signature) else { return false };
    let mut expected = vec![0x00, 0x01];
    expected.resize(n.len() - digest_info.len() - 1, 0xFF);
    expected.push(0x00);
    expected.extend_from_slice(digest_info);
    em == expected
}

/// RSAES-PKCS1-v1_5 encryption written test-side (RFC 8017 §7.2.1).
pub fn rsa_encrypt(n: &[u8], e: &[u8], message: &[u8], seed: u64) -> Vec<u8> {
    let mut entropy = SeededEntropy::new(seed);
    let ps_len = n.len() - message.len() - 3;
    let ps: Vec<u8> = entropy.bytes(ps_len * 2).into_iter().filter(|b| *b != 0).take(ps_len).collect();
    assert_eq!(ps.len(), ps_len);
    let mut em = vec![0x00, 0x02];
    em.extend_from_slice(&ps);
    em.push(0x00);
    em.extend_from_slice(message);
    lk_crypto::rsa_public_op(n, e, &em).unwrap()
}

/// The extended header list of a key import (spec §4.4.3.12).
pub fn import_data(crt: &[u8], components: &[(u8, &[u8])]) -> Vec<u8> {
    let mut list = Vec::new();
    let mut values = Vec::new();
    for (tag, value) in components {
        list.push(*tag);
        list.extend_from_slice(&tlv::encode_len(value.len()));
        values.extend_from_slice(value);
    }
    let mut inner = crt.to_vec();
    inner.extend_from_slice(&tlv::encode(0x7F48, &list));
    inner.extend_from_slice(&tlv::encode(0x5F48, &values));
    tlv::encode(0x4D, &inner)
}

/// The ECDH cipher DO `A6 { 7F49 { 86 point } }` (spec §7.2.11).
pub fn cipher_do(point: &[u8]) -> Vec<u8> {
    tlv::encode(0xA6, &tlv::encode(0x7F49, &tlv::encode(0x86, point)))
}

pub struct Card {
    pub app: OpenPgp,
    pub host: TestHost,
}

impl Card {
    /// An applet on `host`, restored from what the host persisted or, if nothing, from the
    /// cached factory snapshot.
    pub fn with_host(mut host: TestHost) -> Self {
        if host.persisted(Record::OpenPgp).is_none() {
            let yubikey = host_is_yubikey(&host);
            host.set_persisted(Record::OpenPgp, &factory_snapshot(yubikey));
        }
        let stored = host.persisted(Record::OpenPgp);
        let app = OpenPgp::new(stored.as_deref(), &mut host);
        let mut card = Card { app, host };
        card.select();
        card
    }

    /// A truly fresh applet (`new(None, ..)`): provisions its own attestation issuer.
    pub fn fresh(mut host: TestHost) -> Self {
        let app = OpenPgp::new(None, &mut host);
        let mut card = Card { app, host };
        card.select();
        card
    }

    /// Own profile (serial 12345678).
    pub fn new() -> Self {
        Self::with_host(TestHost::new())
    }

    /// reference key compatibility profile.
    pub fn yubikey() -> Self {
        Self::with_host(TestHost::with_profile(DeviceProfile::yubikey_compat(12_345_678)))
    }

    pub fn select(&mut self) -> u16 {
        split(self.app.select(&SELECT, &mut self.host)).1
    }

    /// Rebuild the applet from what it persisted, as after a power cycle.
    pub fn reload(&mut self) {
        let stored = self.host.persisted(Record::OpenPgp);
        self.app = OpenPgp::new(stored.as_deref(), &mut self.host);
        self.select();
    }

    pub fn raw(&mut self, apdu: &[u8]) -> Vec<u8> {
        match self.app.process(apdu, &mut self.host) {
            Outcome::Done(resp) => resp,
            other => panic!("unexpected {other:?}"),
        }
    }

    pub fn process(&mut self, apdu: &[u8]) -> Outcome<Vec<u8>> {
        self.app.process(apdu, &mut self.host)
    }

    /// Send a command that must wait for a touch, then resolve it.
    pub fn send_touch(&mut self, apdu: &[u8], touched: bool) -> (Vec<u8>, u16) {
        match self.process(apdu) {
            Outcome::NeedTouch { timeout_ms } => assert_eq!(timeout_ms, 15_000),
            Outcome::Done(resp) => panic!("expected a touch request, got {resp:02X?}"),
        }
        split(self.app.touch_resolved(touched, &mut self.host))
    }

    /// Extended-length command with Le 0000 (whole response at once, up to 3070 bytes).
    pub fn ext(&mut self, ins: u8, p1: u8, p2: u8, data: &[u8]) -> (Vec<u8>, u16) {
        self.apdu_ext(0x00, ins, p1, p2, data, Some(0))
    }

    pub fn ext_bytes(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
        let mut cmd = Command::new(0x00, ins, p1, p2).with_data(data.to_vec());
        cmd.le = Some(0);
        cmd.extended = true;
        cmd.to_bytes()
    }

    pub fn set_attributes(&mut self, tag: u16, attributes: &str) {
        assert_eq!(self.put(tag, &hex(attributes)), 0x9000, "attributes {tag:04X}");
    }

    /// GENERATE ASYMMETRIC KEY PAIR P1 80 (needs PW3 verified), returning 7F49.
    pub fn generate(&mut self, crt: &[u8]) -> Vec<u8> {
        let (data, sw) = self.ext(0x47, 0x80, 0x00, crt);
        assert_eq!(sw, 0x9000, "generate {crt:02X?}");
        data
    }

    /// GENERATE P1 81: read the public key.
    pub fn public_key(&mut self, crt: &[u8]) -> (Vec<u8>, u16) {
        self.ext(0x47, 0x81, 0x00, crt)
    }

    pub fn sign(&mut self, input: &[u8]) -> (Vec<u8>, u16) {
        self.ext(0x2A, 0x9E, 0x9A, input)
    }

    pub fn decipher(&mut self, input: &[u8]) -> (Vec<u8>, u16) {
        self.ext(0x2A, 0x80, 0x86, input)
    }

    pub fn authenticate(&mut self, input: &[u8]) -> (Vec<u8>, u16) {
        self.ext(0x88, 0x00, 0x00, input)
    }

    pub fn import(&mut self, data: &[u8]) -> u16 {
        self.apdu_ext(0x00, 0xDB, 0x3F, 0xFF, data, None).1
    }

    /// GET ATTESTATION `80 FB <key ref> 00` (Yubico).
    pub fn attest(&mut self, key_ref: u8) -> (Vec<u8>, u16) {
        self.send(&[0x80, 0xFB, key_ref, 0x00])
    }

    /// The certificate of 7F21 occurrence `occurrence` (spec §7.2.5).
    pub fn certificate(&mut self, occurrence: u8) -> Vec<u8> {
        assert_eq!(self.select_occurrence(occurrence), 0x9000);
        let (data, sw) = self.apdu_ext(0x00, 0xCA, 0x7F, 0x21, b"", Some(0));
        assert_eq!(sw, 0x9000);
        data
    }

    /// The digital signature counter from 7A (spec §4.4.3.14).
    pub fn signature_counter(&mut self) -> u32 {
        let data = self.get_ok(0x007A);
        u32::from_be_bytes([0, data[4], data[5], data[6]])
    }

    /// DE key status for the four slots.
    pub fn key_status(&mut self) -> [u8; 4] {
        let de = self.get_ok(0x00DE);
        [de[1], de[3], de[5], de[7]]
    }

    pub fn send(&mut self, apdu: &[u8]) -> (Vec<u8>, u16) {
        split(self.raw(apdu))
    }

    pub fn apdu(&mut self, cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: Option<u32>) -> (Vec<u8>, u16) {
        let mut cmd = Command::new(cla, ins, p1, p2).with_data(data.to_vec());
        cmd.le = le;
        self.send(&cmd.to_bytes())
    }

    /// Extended-length form (ISO 7816-4 §5.1) even for short fields; `Some(0)` is Le 0000.
    pub fn apdu_ext(&mut self, cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: Option<u32>) -> (Vec<u8>, u16) {
        let mut cmd = Command::new(cla, ins, p1, p2).with_data(data.to_vec());
        cmd.le = le;
        cmd.extended = true;
        self.send(&cmd.to_bytes())
    }

    /// Send and collect `61xx` continuations with GET RESPONSE.
    pub fn full(&mut self, apdu: &[u8]) -> (Vec<u8>, u16) {
        let (mut data, mut sw) = self.send(apdu);
        while sw & 0xFF00 == 0x6100 {
            let (more, next) = self.send(&[0x00, 0xC0, 0x00, 0x00, (sw & 0xFF) as u8]);
            data.extend_from_slice(&more);
            sw = next;
        }
        (data, sw)
    }

    pub fn get(&mut self, tag: u16) -> (Vec<u8>, u16) {
        self.full(&[0x00, 0xCA, (tag >> 8) as u8, tag as u8, 0x00])
    }

    pub fn get_ok(&mut self, tag: u16) -> Vec<u8> {
        let (data, sw) = self.get(tag);
        assert_eq!(sw, 0x9000, "GET DATA {tag:04X}");
        data
    }

    /// PUT DATA; extended form when the value exceeds 255 bytes.
    pub fn put(&mut self, tag: u16, data: &[u8]) -> u16 {
        self.apdu(0x00, 0xDA, (tag >> 8) as u8, tag as u8, data, None).1
    }

    pub fn verify(&mut self, p2: u8, pin: &[u8]) -> u16 {
        self.apdu(0x00, 0x20, 0x00, p2, pin, None).1
    }

    pub fn admin(&mut self) {
        assert_eq!(self.verify(0x83, b"12345678"), 0x9000);
    }

    pub fn pw_status(&mut self) -> Vec<u8> {
        self.get_ok(0xC4)
    }

    pub fn retries(&mut self) -> [u8; 3] {
        let c4 = self.pw_status();
        [c4[4], c4[5], c4[6]]
    }

    pub fn select_occurrence(&mut self, occurrence: u8) -> u16 {
        // spec §7.2.5: SELECT DATA with tag list 60 { 5C 7F21 }.
        self.apdu(0x00, 0xA5, occurrence, 0x04, &hex("6004 5C02 7F21"), None).1
    }
}

/// Which cached factory snapshot fits the host: the compatibility profile announces
/// Yubico's OpenPGP manufacturer ID `0006` (the snapshot only differs in the issuer's
/// names, so any other profile can start from the own snapshot).
fn host_is_yubikey(host: &TestHost) -> bool {
    use lk_core::Host;
    host.profile().openpgp_manufacturer == 0x0006
}

/// RSA CRT components `(1/q mod p, d mod (p-1), d mod (q-1))` for `e = 65537`, computed
/// test-side (RFC 8017 §3.2, second representation) with the small big-integer helpers
/// below, so that the CRT import format can be exercised with genuine values.
pub fn rsa_crt(p: &[u8], q: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let width = p.len();
    let (pb, qb) = (big::from_be(p), big::from_be(q));
    let q_mod_p = if big::cmp(&qb, &pb) == std::cmp::Ordering::Less { qb.clone() } else { big::sub(&qb, &pb) };
    let qinv = big::inverse_odd(&q_mod_p, &pb);
    let one = big::from_be(&[1]);
    let dp = big::inverse_small(65537, &big::sub(&pb, &one));
    let dq = big::inverse_small(65537, &big::sub(&qb, &one));
    (big::to_be(&qinv, width), big::to_be(&dp, width), big::to_be(&dq, width))
}

/// Minimal unsigned big integers as little-endian `u32` limbs (test-side only).
pub mod big {
    use std::cmp::Ordering;

    pub fn from_be(bytes: &[u8]) -> Vec<u32> {
        let mut limbs: Vec<u32> = bytes
            .rchunks(4)
            .map(|chunk| chunk.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b)))
            .collect();
        trim(&mut limbs);
        limbs
    }

    pub fn to_be(limbs: &[u32], len: usize) -> Vec<u8> {
        let mut out: Vec<u8> = limbs.iter().rev().flat_map(|l| l.to_be_bytes()).collect();
        while out.len() > len {
            assert_eq!(out.remove(0), 0);
        }
        while out.len() < len {
            out.insert(0, 0);
        }
        out
    }

    fn trim(limbs: &mut Vec<u32>) {
        while limbs.last() == Some(&0) {
            limbs.pop();
        }
    }

    pub fn cmp(a: &[u32], b: &[u32]) -> Ordering {
        a.len().cmp(&b.len()).then_with(|| a.iter().rev().cmp(b.iter().rev()))
    }

    pub fn add(a: &[u32], b: &[u32]) -> Vec<u32> {
        let mut out = Vec::with_capacity(a.len().max(b.len()) + 1);
        let mut carry = 0u64;
        for i in 0..a.len().max(b.len()) {
            let sum = u64::from(*a.get(i).unwrap_or(&0)) + u64::from(*b.get(i).unwrap_or(&0)) + carry;
            out.push(sum as u32);
            carry = sum >> 32;
        }
        out.push(carry as u32);
        trim(&mut out);
        out
    }

    /// `a - b` for `a >= b`.
    pub fn sub(a: &[u32], b: &[u32]) -> Vec<u32> {
        let mut out = Vec::with_capacity(a.len());
        let mut borrow = 0i64;
        for (i, limb) in a.iter().enumerate() {
            let mut diff = i64::from(*limb) - i64::from(*b.get(i).unwrap_or(&0)) - borrow;
            borrow = 0;
            if diff < 0 {
                diff += 1 << 32;
                borrow = 1;
            }
            out.push(diff as u32);
        }
        assert_eq!(borrow, 0);
        trim(&mut out);
        out
    }

    fn shr1(a: &[u32]) -> Vec<u32> {
        let mut out = vec![0u32; a.len()];
        for i in 0..a.len() {
            let high = a.get(i + 1).map_or(0, |n| n << 31);
            out[i] = (a[i] >> 1) | high;
        }
        trim(&mut out);
        out
    }

    fn is_even(a: &[u32]) -> bool {
        a.first().is_none_or(|l| l & 1 == 0)
    }

    fn is_one(a: &[u32]) -> bool {
        a == [1]
    }

    fn sub_mod(a: &[u32], b: &[u32], m: &[u32]) -> Vec<u32> {
        if cmp(a, b) == Ordering::Less { sub(&add(a, m), b) } else { sub(a, b) }
    }

    /// `a^-1 mod m` for odd `m` and `0 < a < m` coprime to it: binary extended Euclidean
    /// algorithm (Handbook of Applied Cryptography, algorithm 14.61, odd-modulus form).
    pub fn inverse_odd(a: &[u32], m: &[u32]) -> Vec<u32> {
        let (mut u, mut v) = (a.to_vec(), m.to_vec());
        let (mut x1, mut x2) = (vec![1u32], Vec::new());
        while !is_one(&u) && !is_one(&v) {
            while is_even(&u) {
                u = shr1(&u);
                x1 = if is_even(&x1) { shr1(&x1) } else { shr1(&add(&x1, m)) };
            }
            while is_even(&v) {
                v = shr1(&v);
                x2 = if is_even(&x2) { shr1(&x2) } else { shr1(&add(&x2, m)) };
            }
            if cmp(&u, &v) == Ordering::Less {
                v = sub(&v, &u);
                x2 = sub_mod(&x2, &x1, m);
            } else {
                u = sub(&u, &v);
                x1 = sub_mod(&x1, &x2, m);
            }
        }
        if is_one(&u) { x1 } else { x2 }
    }

    /// `e^-1 mod m` for a small `e`: the `(1 + k·m) / e` divisible by `e`.
    pub fn inverse_small(e: u32, m: &[u32]) -> Vec<u32> {
        for k in 1..e {
            let mut t = Vec::new();
            let mut carry = 1u64;
            for limb in m {
                let value = u64::from(*limb) * u64::from(k) + carry;
                t.push(value as u32);
                carry = value >> 32;
            }
            t.push(carry as u32);
            let mut remainder = 0u64;
            let mut quotient = vec![0u32; t.len()];
            for i in (0..t.len()).rev() {
                let value = (remainder << 32) | u64::from(t[i]);
                quotient[i] = (value / u64::from(e)) as u32;
                remainder = value % u64::from(e);
            }
            if remainder == 0 {
                trim(&mut quotient);
                return quotient;
            }
        }
        panic!("e not invertible")
    }

    #[test]
    fn small_vectors() {
        // 3^-1 mod 11 = 4; 7^-1 mod 40 = 23 (textbook RSA, p = 5, q = 11, e = 7: d = 23).
        assert_eq!(inverse_odd(&[3], &[11]), vec![4]);
        assert_eq!(inverse_small(7, &[40]), vec![23]);
        assert_eq!(to_be(&from_be(&[0, 1, 2, 3, 4, 5]), 6), vec![0, 1, 2, 3, 4, 5]);
    }
}
