//! Shared test helpers: a card wrapper over `lk_testkit::TestHost`, APDU builders in the
//! shape yubikit `hsmauth.py` sends, and test-side reference implementations written
//! from the specifications (not from this crate's sources):
//!
//! - SP 800-108 counter-mode KDF with AES-CMAC and the GPC Amendment D §4.1.5 fixed
//!   input layout ([`sp800_108_cmac`]);
//! - the ANSI X9.63 KDF with SHA-256, SEC 1 v2.0 §3.6.1 ([`x963_kdf_sha256`]);
//! - PBKDF2-HMAC-SHA256, RFC 8018 §5.2 ([`pbkdf2_hmac_sha256`]);
//! - the YubiHSM 2 side of the asymmetric session ([`HsmSide`]), as in yubihsm-shell
//!   `yh_create_session_asym` with the roles mirrored.

#![allow(dead_code)]

use lk_codec::apdu::{Command, split_response, sw};
use lk_codec::tlv;
use lk_core::{CardApplet, Outcome, Record};
use lk_crypto::{Curve, EcPrivateKey, aes_cmac, hmac_sha256, sha256};
use lk_hsmauth::{AID, HsmAuth, alg, ins, tag};
use lk_testkit::TestHost;

/// Factory management key (yubikit `DEFAULT_MANAGEMENT_KEY`).
pub const DEFAULT_KEY: [u8; 16] = [0; 16];

/// A credential password as yubikit `_parse_credential_password` builds it from a
/// string: UTF-8, zero-padded to 16 bytes.
pub fn pw(text: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (o, b) in out.iter_mut().zip(text.as_bytes()) {
        *o = *b;
    }
    out
}

pub fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2).expect("even length"), 16).expect("hex digit"))
        .collect()
}

pub fn tlv(tag: u32, value: &[u8]) -> Vec<u8> {
    tlv::encode(tag, value)
}

/// `CLA=00` APDU; the extended form is used automatically for more than 255 bytes.
pub fn apdu(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    Command::new(0, ins, p1, p2).with_data(data.to_vec()).to_bytes()
}

pub fn split(resp: &[u8]) -> (Vec<u8>, u16) {
    let (data, sw) = split_response(resp).expect("response has a status word");
    (data.to_vec(), sw)
}

/// SELECT by AID (ISO/IEC 7816-4 §11.2.2).
pub fn select_apdu() -> Vec<u8> {
    Command::new(0, 0xA4, 0x04, 0x00).with_data(AID.to_vec()).to_bytes()
}

/// One LIST entry (yubikit `list_credentials`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub algorithm: u8,
    pub touch: bool,
    pub label: Vec<u8>,
    pub retries: u8,
}

/// Credential definition for PUT.
pub struct Put<'a> {
    pub management_key: [u8; 16],
    pub label: &'a [u8],
    pub algorithm: u8,
    pub enc: Option<[u8; 16]>,
    pub mac: Option<[u8; 16]>,
    pub private: Option<Vec<u8>>,
    pub password: [u8; 16],
    pub touch: Option<Vec<u8>>,
}

impl<'a> Put<'a> {
    pub fn symmetric(label: &'a str, enc: [u8; 16], mac: [u8; 16], password: [u8; 16]) -> Self {
        Self {
            management_key: DEFAULT_KEY,
            label: label.as_bytes(),
            algorithm: alg::AES128_YUBICO_AUTHENTICATION,
            enc: Some(enc),
            mac: Some(mac),
            private: None,
            password,
            touch: Some(vec![0]),
        }
    }

    /// An asymmetric credential: import `Some(scalar)`, or generate on the device with
    /// `None`, sent as yubikit `generate_credential_asymmetric` sends it — an empty `7D`
    /// ("Empty byte will generate key"). Set `private = None` afterwards to omit `7D`.
    pub fn asymmetric(label: &'a str, private: Option<Vec<u8>>, password: [u8; 16]) -> Self {
        Self {
            management_key: DEFAULT_KEY,
            label: label.as_bytes(),
            algorithm: alg::EC_P256_YUBICO_AUTHENTICATION,
            enc: None,
            mac: None,
            private: Some(private.unwrap_or_default()),
            password,
            touch: Some(vec![0]),
        }
    }

    pub fn touch(mut self, touch: bool) -> Self {
        self.touch = Some(vec![u8::from(touch)]);
        self
    }

    /// The data field in yubikit `_put_credential` order.
    pub fn data(&self) -> Vec<u8> {
        let mut d = tlv(tag::MANAGEMENT_KEY, &self.management_key);
        d.extend(tlv(tag::LABEL, self.label));
        d.extend(tlv(tag::ALGORITHM, &[self.algorithm]));
        if let Some(enc) = self.enc {
            d.extend(tlv(tag::KEY_ENC, &enc));
        }
        if let Some(mac) = self.mac {
            d.extend(tlv(tag::KEY_MAC, &mac));
        }
        if let Some(private) = &self.private {
            d.extend(tlv(tag::PRIVATE_KEY, private));
        }
        d.extend(tlv(tag::CREDENTIAL_PASSWORD, &self.password));
        if let Some(touch) = &self.touch {
            d.extend(tlv(tag::TOUCH, touch));
        }
        d
    }
}

/// The application with a host, selected.
pub struct Card {
    pub app: HsmAuth,
    pub host: TestHost,
}

impl Card {
    pub fn new() -> Self {
        Self::with_host(TestHost::new())
    }

    /// Build the application from whatever `host` has persisted, then SELECT it.
    pub fn with_host(mut host: TestHost) -> Self {
        let stored = host.persisted(Record::HsmAuth);
        let mut app = HsmAuth::new(stored.as_deref(), &mut host);
        let resp = app.select(&select_apdu(), &mut host);
        assert_eq!(split(&resp).1, sw::OK);
        Self { app, host }
    }

    /// Power cycle: a new application instance from the persisted record.
    pub fn restart(self) -> Self {
        Self::with_host(self.host)
    }

    pub fn raw(&mut self, apdu: &[u8]) -> Outcome<Vec<u8>> {
        self.app.process(apdu, &mut self.host)
    }

    /// Send one APDU that must not wait for touch.
    pub fn send_raw(&mut self, apdu: &[u8]) -> (Vec<u8>, u16) {
        match self.raw(apdu) {
            Outcome::Done(resp) => split(&resp),
            Outcome::NeedTouch { .. } => panic!("unexpected touch request"),
        }
    }

    /// Send a command and collect `61xx` continuations with GET RESPONSE.
    pub fn send(&mut self, ins: u8, p1: u8, p2: u8, data: &[u8]) -> (Vec<u8>, u16) {
        let (mut out, mut status) = self.send_raw(&apdu(ins, p1, p2, data));
        while status & 0xFF00 == 0x6100 {
            let (more, next) = self.send_raw(&[0x00, ins::GET_RESPONSE, 0x00, 0x00, 0x00]);
            out.extend(more);
            status = next;
        }
        (out, status)
    }

    pub fn cmd(&mut self, ins: u8, data: &[u8]) -> (Vec<u8>, u16) {
        self.send(ins, 0, 0, data)
    }

    pub fn put(&mut self, put: &Put<'_>) -> u16 {
        let (data, status) = self.cmd(ins::PUT, &put.data());
        assert!(data.is_empty());
        status
    }

    pub fn put_symmetric(&mut self, label: &str, enc: [u8; 16], mac: [u8; 16], password: [u8; 16]) -> u16 {
        self.put(&Put::symmetric(label, enc, mac, password))
    }

    pub fn list(&mut self) -> Vec<Entry> {
        let (data, status) = self.cmd(ins::LIST, &[]);
        assert_eq!(status, sw::OK);
        tlv::parse_all(&data)
            .expect("LIST is BER-TLV")
            .iter()
            .map(|item| {
                assert_eq!(item.tag, tag::LABEL_LIST);
                let v = item.value;
                assert!(v.len() >= 3);
                Entry {
                    algorithm: v[0],
                    touch: v[1] != 0,
                    label: v[2..v.len() - 1].to_vec(),
                    retries: v[v.len() - 1],
                }
            })
            .collect()
    }

    pub fn delete(&mut self, management_key: &[u8], label: &str) -> u16 {
        let mut d = tlv(tag::MANAGEMENT_KEY, management_key);
        d.extend(tlv(tag::LABEL, label.as_bytes()));
        self.cmd(ins::DELETE, &d).1
    }

    pub fn get_challenge(&mut self, label: &str, password: Option<[u8; 16]>) -> (Vec<u8>, u16) {
        let mut d = tlv(tag::LABEL, label.as_bytes());
        if let Some(p) = password {
            d.extend(tlv(tag::CREDENTIAL_PASSWORD, &p));
        }
        self.cmd(ins::GET_CHALLENGE, &d)
    }

    pub fn get_public_key(&mut self, label: &str) -> (Vec<u8>, u16) {
        self.cmd(ins::GET_PUBLIC_KEY, &tlv(tag::LABEL, label.as_bytes()))
    }

    pub fn management_retries(&mut self) -> u8 {
        let (data, status) = self.cmd(ins::GET_MANAGEMENT_KEY_RETRIES, &[]);
        assert_eq!(status, sw::OK);
        assert_eq!(data.len(), 1);
        data[0]
    }

    pub fn put_management_key(&mut self, current: &[u8], new: &[u8]) -> u16 {
        let mut d = tlv(tag::MANAGEMENT_KEY, current);
        d.extend(tlv(tag::MANAGEMENT_KEY, new));
        self.cmd(ins::PUT_MANAGEMENT_KEY, &d).1
    }

    pub fn retries_of(&mut self, label: &str) -> Option<u8> {
        self.list().into_iter().find(|e| e.label == label.as_bytes()).map(|e| e.retries)
    }

    pub fn labels(&mut self) -> Vec<Vec<u8>> {
        self.list().into_iter().map(|e| e.label).collect()
    }
}

impl Default for Card {
    fn default() -> Self {
        Self::new()
    }
}

/// CALCULATE data in yubikit `_calculate_session_keys` order.
pub fn calculate_data(
    label: &str,
    context: &[u8],
    public_key: Option<&[u8]>,
    card_crypto: Option<&[u8]>,
    password: &[u8],
) -> Vec<u8> {
    let mut d = tlv(tag::LABEL, label.as_bytes());
    d.extend(tlv(tag::CONTEXT, context));
    if let Some(pk) = public_key {
        d.extend(tlv(tag::PUBLIC_KEY, pk));
    }
    if let Some(cc) = card_crypto {
        d.extend(tlv(tag::RESPONSE, cc));
    }
    d.extend(tlv(tag::CREDENTIAL_PASSWORD, password));
    d
}

/// NIST SP 800-108 KDF in counter mode (SP 800-108 §5.1) with AES-CMAC (RFC 4493) as PRF
/// and the fixed input data of GPC v2.3.1 Amendment D §4.1.5: an 11-byte zero label
/// prefix, the one-byte derivation constant (Table 4-1), a `00` separation indicator,
/// `[L]_2` (two bytes, bits), the counter `[i]_2` as one byte, then the context.
pub fn sp800_108_cmac(key: &[u8], constant: u8, context: &[u8], l_bits: u16) -> Vec<u8> {
    let blocks = usize::from(l_bits).div_ceil(128);
    let mut k = Vec::new();
    for i in 1..=blocks {
        let label: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, constant];
        let fixed: Vec<u8> = label
            .iter()
            .copied()
            .chain([0x00])
            .chain(l_bits.to_be_bytes())
            .chain([u8::try_from(i).expect("few blocks")])
            .chain(context.iter().copied())
            .collect();
        k.extend(aes_cmac(key, &fixed).expect("AES-128 key"));
    }
    k.truncate(usize::from(l_bits) / 8);
    k
}

/// Amendment D Table 4-1 derivation constants.
pub mod constant {
    pub const CARD_CRYPTOGRAM: u8 = 0x00;
    pub const HOST_CRYPTOGRAM: u8 = 0x01;
    pub const S_ENC: u8 = 0x04;
    pub const S_MAC: u8 = 0x06;
    pub const S_RMAC: u8 = 0x07;
}

/// ANSI X9.63 KDF (SEC 1 v2.0 §3.6.1) with SHA-256.
pub fn x963_kdf_sha256(z: &[u8], shared_info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut counter: u32 = 0;
    while out.len() < len {
        counter += 1;
        let block = sha256(&[z, &counter.to_be_bytes(), shared_info].concat());
        out.extend_from_slice(&block);
    }
    out.truncate(len);
    out
}

/// PBKDF2 (RFC 8018 §5.2) with HMAC-SHA256 as PRF.
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut block_index: u32 = 0;
    while out.len() < len {
        block_index += 1;
        let mut u = hmac_sha256(password, &[salt, &block_index.to_be_bytes()].concat());
        let mut t = u;
        for _ in 1..iterations {
            u = hmac_sha256(password, &u);
            for (a, b) in t.iter_mut().zip(u.iter()) {
                *a ^= b;
            }
        }
        out.extend_from_slice(&t);
    }
    out.truncate(len);
    out
}

/// A deterministic P-256 key for tests (SHA-256 of a name as the scalar).
pub fn test_key(name: &str) -> EcPrivateKey {
    EcPrivateKey::from_scalar(Curve::P256, &sha256(name.as_bytes())).expect("valid scalar")
}

/// The YubiHSM 2 ("SD") side of an asymmetric session: its static key SK.SD and
/// ephemeral key eSK.SD. Mirrors yubihsm-shell `yh_create_session_asym`: `ShSee =
/// ECDH(eSK.SD, EPK.OCE)`, `ShSss = ECDH(SK.SD, PK.OCE)`, X9.63-KDF-SHA-256 over `ShSee ||
/// ShSss` with shared info `3C 88 10`, 64 bytes = receipt key || S-ENC || S-MAC ||
/// S-RMAC, receipt = AES-CMAC(receipt key, `EPK.SD || EPK.OCE`).
pub struct HsmSide {
    pub static_key: EcPrivateKey,
    pub ephemeral: EcPrivateKey,
}

pub struct HsmSession {
    /// EPK.OCE || EPK.SD.
    pub context: Vec<u8>,
    pub receipt: Vec<u8>,
    /// S-ENC || S-MAC || S-RMAC.
    pub session_keys: Vec<u8>,
}

impl HsmSide {
    pub fn new(name: &str) -> Self {
        Self { static_key: test_key(&format!("{name}/SK.SD")), ephemeral: test_key(&format!("{name}/eSK.SD")) }
    }

    pub fn public(&self) -> Vec<u8> {
        self.static_key.public_uncompressed()
    }

    pub fn respond(&self, epk_oce: &[u8], pk_oce: &[u8]) -> HsmSession {
        let epk_sd = self.ephemeral.public_uncompressed();
        let shsee = self.ephemeral.ecdh(epk_oce).expect("EPK.OCE on curve");
        let shsss = self.static_key.ecdh(pk_oce).expect("PK.OCE on curve");
        let z = [shsee.as_slice(), shsss.as_slice()].concat();
        let key_data = x963_kdf_sha256(&z, &[0x3C, 0x88, 0x10], 64);
        let receipt = aes_cmac(&key_data[..16], &[epk_sd.as_slice(), epk_oce].concat()).expect("AES-128 key");
        HsmSession {
            context: [epk_oce, epk_sd.as_slice()].concat(),
            receipt: receipt.to_vec(),
            session_keys: key_data[16..].to_vec(),
        }
    }
}

/// A small deterministic PRNG (SplitMix64) for the fuzz tests.
pub struct SplitMix64(pub u64);

impl SplitMix64 {
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % (n.max(1) as u64)) as usize
    }

    pub fn byte(&mut self) -> u8 {
        self.next_u64() as u8
    }

    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
    }

    pub fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in) == 0
    }
}
