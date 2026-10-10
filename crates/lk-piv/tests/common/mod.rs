//! Shared helpers for the lk-piv integration tests: a selected card on a
//! `lk_testkit::TestHost`, APDU builders and the management key handshake.

#![allow(dead_code, clippy::unwrap_used)]

use lk_codec::apdu::{Command, split_response};
use lk_codec::tlv;
use lk_core::{CardApplet, DeviceProfile, Entropy, Host, Millis, Outcome, Record, StoreError};
use lk_crypto::{aes_ecb_decrypt_block, aes_ecb_encrypt_block, tdes_ecb_decrypt_block, tdes_ecb_encrypt_block};
use lk_piv::Piv;
use lk_testkit::TestHost;

/// Decode a hex string, ignoring whitespace.
pub fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// SELECT by the right-truncated PIV AID (SP 800-73-4 Part 2 §3.1.1).
pub const SELECT: &str = "00A4040005A000000308";

/// Default PIN `123456` padded with FF (SP 800-73-4 Part 2 §2.4.3; Yubico defaults).
pub const DEFAULT_PIN: &str = "313233343536FFFF";
/// Default PUK `12345678` (Yubico defaults).
pub const DEFAULT_PUK: &str = "3132333435363738";
/// Default management key of firmware 5.7, AES-192 (Yubico PIV documentation).
pub const DEFAULT_MGMT_KEY: &str = "010203040506070801020304050607080102030405060708";

/// Algorithm identifiers (SP 800-78-4 Table 6-1).
pub const ALG_TDES: u8 = 0x03;
pub const ALG_AES128: u8 = 0x08;
pub const ALG_AES192: u8 = 0x0A;
pub const ALG_AES256: u8 = 0x0C;

/// Pad a PIN or PUK to 8 bytes with FF.
pub fn pad(value: &[u8]) -> Vec<u8> {
    let mut out = value.to_vec();
    out.resize(8, 0xFF);
    out
}

/// A short-or-extended APDU with the given fields.
pub fn apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: Option<u32>) -> Vec<u8> {
    let mut cmd = Command::new(cla, ins, p1, p2).with_data(data.to_vec());
    cmd.le = le;
    cmd.to_bytes()
}

pub fn block_len(alg: u8) -> usize {
    if alg == ALG_TDES { 8 } else { 16 }
}

pub fn encrypt(alg: u8, key: &[u8], block: &[u8]) -> Vec<u8> {
    if alg == ALG_TDES {
        tdes_ecb_encrypt_block(key, block).unwrap().to_vec()
    } else {
        aes_ecb_encrypt_block(key, block).unwrap().to_vec()
    }
}

pub fn decrypt(alg: u8, key: &[u8], block: &[u8]) -> Vec<u8> {
    if alg == ALG_TDES {
        tdes_ecb_decrypt_block(key, block).unwrap().to_vec()
    } else {
        aes_ecb_decrypt_block(key, block).unwrap().to_vec()
    }
}

/// The single child `inner` of a `7C` template.
pub fn dyn_auth_item(data: &[u8], inner: u32) -> Vec<u8> {
    let (outer, rest) = tlv::parse_one(data).unwrap();
    assert_eq!(outer.tag, 0x7C);
    assert!(rest.is_empty());
    let items = outer.children().unwrap();
    assert_eq!(items.len(), 1, "one element in {data:02X?}");
    assert_eq!(items[0].tag, inner);
    items[0].value.to_vec()
}

/// A selected PIV applet on a test host.
pub struct Card {
    pub piv: Piv,
    pub host: TestHost,
}

impl Card {
    /// Factory card with the default `TestHost` profile, selected.
    pub fn new() -> Self {
        Self::with_host(TestHost::new())
    }

    pub fn with_host(mut host: TestHost) -> Self {
        let mut piv = Piv::new(host.persisted(Record::Piv).as_deref(), &mut host);
        let resp = piv.select(&hex(SELECT), &mut host);
        assert_eq!(split_response(&resp).unwrap().1, 0x9000);
        Self { piv, host }
    }

    /// Rebuild the applet from what it last persisted (a device restart) and select it.
    pub fn restart(&mut self) {
        let stored = self.host.persisted(Record::Piv);
        self.piv = Piv::new(stored.as_deref(), &mut self.host);
        let resp = self.piv.select(&hex(SELECT), &mut self.host);
        assert_eq!(split_response(&resp).unwrap().1, 0x9000);
    }

    /// End the card session and select PIV again: another application was selected in
    /// between, which clears every PIV security status (SP 800-73-4 Part 2 §3.1.1). A
    /// SELECT of PIV while it is selected keeps the security status.
    pub fn new_session(&mut self) {
        self.piv.deselect();
        let resp = self.piv.select(&hex(SELECT), &mut self.host);
        assert_eq!(split_response(&resp).unwrap().1, 0x9000);
    }

    /// Send raw APDU bytes and return the outcome.
    pub fn outcome(&mut self, bytes: &[u8]) -> Outcome<Vec<u8>> {
        self.piv.process(bytes, &mut self.host)
    }

    /// Send raw APDU bytes; the command must not wait for touch.
    pub fn raw(&mut self, bytes: &[u8]) -> (Vec<u8>, u16) {
        match self.outcome(bytes) {
            Outcome::Done(resp) => {
                let (data, sw) = split_response(&resp).unwrap();
                (data.to_vec(), sw)
            }
            Outcome::NeedTouch { .. } => panic!("unexpected touch request for {bytes:02X?}"),
        }
    }

    /// Send a hex APDU.
    pub fn send(&mut self, hex_apdu: &str) -> (Vec<u8>, u16) {
        self.raw(&hex(hex_apdu))
    }

    /// Send a command built from fields (short or extended as needed).
    pub fn cmd(&mut self, ins: u8, p1: u8, p2: u8, data: &[u8], le: Option<u32>) -> (Vec<u8>, u16) {
        self.raw(&apdu(0x00, ins, p1, p2, data, le))
    }

    /// Send `data` with command chaining in 255-byte parts (ISO/IEC 7816-4 §5.1.1.1);
    /// every intermediate part must answer 9000.
    pub fn chained(&mut self, ins: u8, p1: u8, p2: u8, data: &[u8]) -> (Vec<u8>, u16) {
        let parts: Vec<&[u8]> = data.chunks(255).collect();
        let Some((last, init)) = parts.split_last() else {
            return self.raw(&apdu(0x00, ins, p1, p2, &[], None));
        };
        for part in init {
            let (resp, sw) = self.raw(&apdu(0x10, ins, p1, p2, part, None));
            assert_eq!((resp.len(), sw), (0, 0x9000), "intermediate chain part");
        }
        self.raw(&apdu(0x00, ins, p1, p2, last, None))
    }

    /// Follow `61xx` with GET RESPONSE until the final status word.
    pub fn collect(&mut self, first: (Vec<u8>, u16)) -> (Vec<u8>, u16) {
        let (mut data, mut sw) = first;
        while sw >> 8 == 0x61 {
            let (more, next) = self.send("00C0000000");
            data.extend_from_slice(&more);
            sw = next;
        }
        (data, sw)
    }

    /// PIN status as reported by VERIFY without data.
    pub fn pin_status(&mut self) -> u16 {
        self.send("0020008000").1
    }

    pub fn verify_pin(&mut self, padded: &[u8]) -> u16 {
        self.cmd(0x20, 0x00, 0x80, padded, None).1
    }

    pub fn verify_default_pin(&mut self) {
        assert_eq!(self.verify_pin(&hex(DEFAULT_PIN)), 0x9000);
    }

    /// Mutual authentication (SP 800-73-4 Part 2 Appendix A.2) with `key`; returns the
    /// final status word.
    pub fn try_mutual_auth(&mut self, alg: u8, key: &[u8]) -> u16 {
        let (resp, sw) = self.cmd(0x87, alg, 0x9B, &hex("7C028000"), None);
        if sw != 0x9000 {
            return sw;
        }
        let encrypted = dyn_auth_item(&resp, 0x80);
        assert_eq!(encrypted.len(), block_len(alg));
        let witness = decrypt(alg, key, &encrypted);
        let challenge: Vec<u8> = (0..block_len(alg) as u8).map(|i| i.wrapping_mul(17).wrapping_add(3)).collect();
        let mut inner = tlv::encode(0x80, &witness);
        tlv::encode_into(&mut inner, 0x81, &challenge);
        let (resp, sw) = self.cmd(0x87, alg, 0x9B, &tlv::encode(0x7C, &inner), None);
        if sw == 0x9000 {
            assert_eq!(dyn_auth_item(&resp, 0x82), encrypt(alg, key, &challenge), "card response");
        }
        sw
    }

    pub fn mutual_auth(&mut self, alg: u8, key: &[u8]) {
        assert_eq!(self.try_mutual_auth(alg, key), 0x9000);
    }

    pub fn auth_default(&mut self) {
        self.mutual_auth(ALG_AES192, &hex(DEFAULT_MGMT_KEY));
    }

    /// SET MANAGEMENT KEY (Yubico extension), `touch` selects P2 FE.
    pub fn set_mgmt_key(&mut self, alg: u8, key: &[u8], touch: bool) -> u16 {
        let mut data = vec![alg];
        tlv::encode_into(&mut data, 0x9B, key);
        self.cmd(0xFF, 0xFF, if touch { 0xFE } else { 0xFF }, &data, None).1
    }

    /// PUT DATA payload `5C 03 tag 53 L value`.
    pub fn put_payload(tag: u32, value: &[u8]) -> Vec<u8> {
        let mut data = tlv::encode(0x5C, &tag.to_be_bytes()[1..]);
        tlv::encode_into(&mut data, 0x53, value);
        data
    }

    /// PUT DATA with chaining when needed.
    pub fn put_object(&mut self, tag: u32, value: &[u8]) -> u16 {
        let data = Self::put_payload(tag, value);
        self.chained(0xDB, 0x3F, 0xFF, &data).1
    }

    /// GET DATA for a three-byte tag, following response chaining; returns the
    /// assembled data and the final status word.
    pub fn get_object(&mut self, tag: u32) -> (Vec<u8>, u16) {
        let data = tlv::encode(0x5C, &tag.to_be_bytes()[1..]);
        let first = self.cmd(0xCB, 0x3F, 0xFF, &data, Some(0));
        self.collect(first)
    }

    /// The stored value of `tag` (contents of tag 53), if readable.
    pub fn object_value(&mut self, tag: u32) -> Option<Vec<u8>> {
        let (data, sw) = self.get_object(tag);
        if sw != 0x9000 {
            return None;
        }
        let (obj, rest) = tlv::parse_one(&data).unwrap();
        assert_eq!(obj.tag, 0x53);
        assert!(rest.is_empty());
        Some(obj.value.to_vec())
    }

    /// GET METADATA (Yubico extension) for `p2`, following response chaining (RSA
    /// public keys make it longer than one short response).
    pub fn metadata(&mut self, p2: u8) -> (Vec<u8>, u16) {
        let first = self.cmd(0xF7, 0x00, p2, &[], None);
        self.collect(first)
    }
}

/// A host that fails exactly the `fail_at`-th persist call (1-based) and delegates
/// everything else to a `TestHost`.
pub struct FailAt {
    pub inner: TestHost,
    pub fail_at: usize,
    pub calls: usize,
}

impl Entropy for FailAt {
    fn fill(&mut self, out: &mut [u8]) {
        self.inner.fill(out);
    }
}

impl Host for FailAt {
    fn now(&self) -> Millis {
        self.inner.now()
    }

    fn profile(&self) -> &DeviceProfile {
        self.inner.profile()
    }

    fn persist(&mut self, record: Record, plaintext: &[u8]) -> Result<(), StoreError> {
        self.calls += 1;
        if self.calls == self.fail_at {
            return Err(StoreError("injected".into()));
        }
        self.inner.persist(record, plaintext)
    }
}

// ---------------------------------------------------------------------------------------
// Asymmetric keys.

/// Algorithm identifiers (SP 800-78-4 Table 6-2; Yubico 5.7 extensions).
pub const RSA1024: u8 = 0x06;
pub const RSA2048: u8 = 0x07;
pub const RSA3072: u8 = 0x05;
pub const RSA4096: u8 = 0x16;
pub const P256: u8 = 0x11;
pub const P384: u8 = 0x14;
pub const ED25519: u8 = 0xE0;
pub const X25519: u8 = 0xE1;

/// PIN policy (`AA`) and touch policy (`AB`) values (Yubico PIV extensions).
pub const PIN_DEFAULT: u8 = 0x00;
pub const PIN_NEVER: u8 = 0x01;
pub const PIN_ONCE: u8 = 0x02;
pub const PIN_ALWAYS: u8 = 0x03;
pub const TOUCH_DEFAULT: u8 = 0x00;
pub const TOUCH_NEVER: u8 = 0x01;
pub const TOUCH_ALWAYS: u8 = 0x02;
pub const TOUCH_CACHED: u8 = 0x03;

/// A public key as the card reports it (SP 800-73-4 Part 2 Table 10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Public {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    /// ECC point, Ed25519 or X25519 key (tag 86).
    Point(Vec<u8>),
}

impl Public {
    pub fn point(&self) -> &[u8] {
        match self {
            Public::Point(p) => p,
            Public::Rsa { .. } => panic!("not a point"),
        }
    }

    pub fn modulus(&self) -> &[u8] {
        match self {
            Public::Rsa { n, .. } => n,
            Public::Point(_) => panic!("not RSA"),
        }
    }
}

/// Parse public key elements (`81`/`82` or `86`) without the `7F49` wrapper.
pub fn parse_public_elements(data: &[u8]) -> Public {
    let items = tlv::parse_all(data).unwrap();
    match items.as_slice() {
        [n, e] if n.tag == 0x81 && e.tag == 0x82 => Public::Rsa { n: n.value.to_vec(), e: e.value.to_vec() },
        [p] if p.tag == 0x86 => Public::Point(p.value.to_vec()),
        _ => panic!("unexpected public key elements {data:02X?}"),
    }
}

/// Parse a `7F49` public key template.
pub fn parse_public_template(data: &[u8]) -> Public {
    let (outer, rest) = tlv::parse_one(data).unwrap();
    assert_eq!(outer.tag, 0x7F49);
    assert!(rest.is_empty());
    parse_public_elements(outer.value)
}

/// GENERATE `AC { 80 alg [AA pin] [AB touch] }` data.
pub fn generate_template(alg: u8, pin: Option<u8>, touch: Option<u8>) -> Vec<u8> {
    let mut inner = tlv::encode(0x80, &[alg]);
    if let Some(pin) = pin {
        tlv::encode_into(&mut inner, 0xAA, &[pin]);
    }
    if let Some(touch) = touch {
        tlv::encode_into(&mut inner, 0xAB, &[touch]);
    }
    tlv::encode(0xAC, &inner)
}

/// The metadata `02` policy bytes, `03` origin and `04` public key of a slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotInfo {
    pub alg: u8,
    pub pin: u8,
    pub touch: u8,
    pub origin: u8,
    pub public: Public,
}

impl Card {
    /// GENERATE ASYMMETRIC KEY PAIR, following response chaining.
    pub fn try_generate(&mut self, slot: u8, alg: u8, pin: Option<u8>, touch: Option<u8>) -> (Vec<u8>, u16) {
        let first = self.cmd(0x47, 0x00, slot, &generate_template(alg, pin, touch), None);
        self.collect(first)
    }

    /// GENERATE that must succeed; returns the public key.
    pub fn generate(&mut self, slot: u8, alg: u8, pin: Option<u8>, touch: Option<u8>) -> Public {
        let (data, sw) = self.try_generate(slot, alg, pin, touch);
        assert_eq!(sw, 0x9000, "generate {alg:02X} in {slot:02X}");
        parse_public_template(&data)
    }

    /// IMPORT ASYMMETRIC KEY with chaining.
    pub fn import(&mut self, slot: u8, alg: u8, elements: &[u8]) -> u16 {
        self.chained(0xFE, alg, slot, elements).1
    }

    /// GENERAL AUTHENTICATE `7C { 82 00, tag data }` with chaining; the outcome of the
    /// final part.
    pub fn ga_outcome(&mut self, slot: u8, alg: u8, tag: u32, data: &[u8]) -> Outcome<Vec<u8>> {
        let mut inner = tlv::encode(0x82, &[]);
        tlv::encode_into(&mut inner, tag, data);
        let payload = tlv::encode(0x7C, &inner);
        let parts: Vec<&[u8]> = payload.chunks(255).collect();
        let (last, init) = parts.split_last().unwrap();
        for part in init {
            let (resp, sw) = self.raw(&apdu(0x10, 0x87, alg, slot, part, None));
            assert_eq!((resp.len(), sw), (0, 0x9000), "intermediate chain part");
        }
        self.outcome(&apdu(0x00, 0x87, alg, slot, last, None))
    }

    /// GENERAL AUTHENTICATE that must not wait for touch; returns the `82` result (after
    /// response chaining) and the status word.
    pub fn ga(&mut self, slot: u8, alg: u8, tag: u32, data: &[u8]) -> (Vec<u8>, u16) {
        match self.ga_outcome(slot, alg, tag, data) {
            Outcome::Done(resp) => {
                let (data, sw) = split_response(&resp).unwrap();
                self.finish_ga((data.to_vec(), sw))
            }
            Outcome::NeedTouch { .. } => panic!("unexpected touch request"),
        }
    }

    /// Resolve a pending touch and return the `82` result.
    pub fn touch(&mut self, touched: bool) -> (Vec<u8>, u16) {
        let resp = self.piv.touch_resolved(touched, &mut self.host);
        let (data, sw) = split_response(&resp).unwrap();
        self.finish_ga((data.to_vec(), sw))
    }

    fn finish_ga(&mut self, first: (Vec<u8>, u16)) -> (Vec<u8>, u16) {
        let (data, sw) = self.collect(first);
        if sw != 0x9000 {
            return (data, sw);
        }
        (dyn_auth_item(&data, 0x82), sw)
    }

    /// Slot metadata (Yubico GET METADATA) parsed.
    pub fn slot_info(&mut self, slot: u8) -> Option<SlotInfo> {
        let (data, sw) = self.metadata(slot);
        if sw != 0x9000 {
            assert_eq!(sw, 0x6A88);
            return None;
        }
        let items = tlv::parse_all(&data).unwrap();
        let get = |tag| tlv::find(&items, tag).unwrap().value;
        Some(SlotInfo {
            alg: get(0x01)[0],
            pin: get(0x02)[0],
            touch: get(0x02)[1],
            origin: get(0x03)[0],
            public: parse_public_elements(get(0x04)),
        })
    }

    /// ATTEST (Yubico extension), following response chaining.
    pub fn attest(&mut self, slot: u8) -> (Vec<u8>, u16) {
        let first = self.cmd(0xF9, slot, 0x00, &[], Some(0));
        self.collect(first)
    }
}

/// ECDSA verification over a digest left-padded to the field length (FIPS 186-5 §6.4.2).
pub fn ecdsa_ok(alg: u8, point: &[u8], digest: &[u8], der: &[u8]) -> bool {
    let curve = if alg == P256 { lk_crypto::Curve::P256 } else { lk_crypto::Curve::P384 };
    let mut padded = vec![0u8; curve.field_len().saturating_sub(digest.len())];
    padded.extend_from_slice(digest);
    lk_crypto::ecdsa_verify_prehash(curve, point, &padded, der)
}

/// A modulus-length message representative below `n` (RFC 8017 §5.2.1 step 1).
pub fn representative(n: &[u8], fill: u8) -> Vec<u8> {
    let mut m = vec![fill; n.len()];
    m[0] = 0x00;
    m[1] = 0x01;
    m
}

// ---- Test-side RSA CRT derivation (RFC 8017 §3.2), for building IMPORT data. ----------
// Little-endian u32 limbs; only what the derivation needs.

fn limbs(be: &[u8]) -> Vec<u32> {
    let mut out: Vec<u32> =
        be.rchunks(4).map(|c| c.iter().fold(0u32, |a, &b| (a << 8) | u32::from(b))).collect();
    while out.last() == Some(&0) {
        out.pop();
    }
    out
}

fn to_be(v: &[u32], len: usize) -> Vec<u8> {
    let mut out: Vec<u8> = v.iter().rev().flat_map(|l| l.to_be_bytes()).collect();
    let start = out.len().saturating_sub(len);
    assert!(out[..start].iter().all(|&b| b == 0), "value longer than {len}");
    out = out[start..].to_vec();
    let mut padded = vec![0u8; len - out.len()];
    padded.extend(out);
    padded
}

fn trim(v: &mut Vec<u32>) {
    while v.last() == Some(&0) {
        v.pop();
    }
}

fn ge(a: &[u32], b: &[u32]) -> bool {
    a.len().cmp(&b.len()).then_with(|| a.iter().rev().cmp(b.iter().rev())) != std::cmp::Ordering::Less
}

fn sub(a: &[u32], b: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(a.len());
    let mut borrow = 0i64;
    for (i, &x) in a.iter().enumerate() {
        let mut d = i64::from(x) - i64::from(*b.get(i).unwrap_or(&0)) - borrow;
        borrow = 0;
        if d < 0 {
            d += 1 << 32;
            borrow = 1;
        }
        out.push(d as u32);
    }
    assert_eq!(borrow, 0);
    trim(&mut out);
    out
}

fn add(a: &[u32], b: &[u32]) -> Vec<u32> {
    let mut out = Vec::new();
    let mut carry = 0u64;
    for i in 0..a.len().max(b.len()) {
        let s = u64::from(*a.get(i).unwrap_or(&0)) + u64::from(*b.get(i).unwrap_or(&0)) + carry;
        out.push(s as u32);
        carry = s >> 32;
    }
    if carry != 0 {
        out.push(carry as u32);
    }
    out
}

fn half(a: &[u32]) -> Vec<u32> {
    let mut out = a.to_vec();
    let mut carry = 0u32;
    for limb in out.iter_mut().rev() {
        let next = *limb & 1;
        *limb = (*limb >> 1) | (carry << 31);
        carry = next;
    }
    trim(&mut out);
    out
}

fn even(a: &[u32]) -> bool {
    a.first().is_none_or(|l| l & 1 == 0)
}

/// `a^-1 mod m` for odd `m` by the binary extended Euclidean algorithm.
fn mod_inverse(a: &[u32], m: &[u32]) -> Vec<u32> {
    let (mut u, mut v) = (a.to_vec(), m.to_vec());
    let (mut x1, mut x2) = (vec![1u32], Vec::new());
    let one = vec![1u32];
    while u != one && v != one {
        while even(&u) {
            u = half(&u);
            x1 = if even(&x1) { half(&x1) } else { half(&add(&x1, m)) };
        }
        while even(&v) {
            v = half(&v);
            x2 = if even(&x2) { half(&x2) } else { half(&add(&x2, m)) };
        }
        if ge(&u, &v) {
            u = sub(&u, &v);
            x1 = if ge(&x1, &x2) { sub(&x1, &x2) } else { sub(&add(&x1, m), &x2) };
        } else {
            v = sub(&v, &u);
            x2 = if ge(&x2, &x1) { sub(&x2, &x1) } else { sub(&add(&x2, m), &x1) };
        }
    }
    if u == one { x1 } else { x2 }
}

/// `e^-1 mod (p - 1)` for the small exponent `e`: `(k (p-1) + 1) / e` with the `k < e`
/// that makes it exact.
fn small_exponent_inverse(p: &[u32], e: u32) -> Vec<u32> {
    let p1 = sub(p, &[1]);
    let r = p1.iter().rev().fold(0u64, |acc, &l| ((acc << 32) | u64::from(l)) % u64::from(e));
    let k = (1..u64::from(e)).find(|k| (k * r + 1) % u64::from(e) == 0).unwrap();
    // t = k (p-1) + 1, then t / e.
    let mut t = Vec::new();
    let mut carry = 0u64;
    for &l in &p1 {
        let x = u64::from(l) * k + carry;
        t.push(x as u32);
        carry = x >> 32;
    }
    if carry != 0 {
        t.push(carry as u32);
    }
    t = add(&t, &[1]);
    let mut rem = 0u64;
    let mut q = vec![0u32; t.len()];
    for i in (0..t.len()).rev() {
        let cur = (rem << 32) | u64::from(t[i]);
        q[i] = (cur / u64::from(e)) as u32;
        rem = cur % u64::from(e);
    }
    assert_eq!(rem, 0);
    trim(&mut q);
    q
}

/// IMPORT data for an RSA key with exponent 65537: `01 p 02 q 03 dP 04 dQ 05 qInv`, each
/// padded to half the modulus length (as yubikit does).
pub fn rsa_import_elements(p: &[u8], q: &[u8], modulus_len: usize) -> Vec<u8> {
    let half_len = modulus_len / 2;
    let (pl, ql) = (limbs(p), limbs(q));
    let dp = small_exponent_inverse(&pl, 65537);
    let dq = small_exponent_inverse(&ql, 65537);
    let qinv = mod_inverse(&ql, &pl);
    let mut out = Vec::new();
    for (tag, value) in [(1u32, &pl), (2, &ql), (3, &dp), (4, &dq), (5, &qinv)] {
        tlv::encode_into(&mut out, tag, &to_be(value, half_len));
    }
    out
}
