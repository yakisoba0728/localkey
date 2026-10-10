//! Scenario tests, mostly through the public API with `lk_testkit::TestHost`.
//!
//! Test vector sources are cited per test. Signatures are always checked with
//! lk-crypto's verifiers (FIPS 186-5 §6.4.2 ECDSA, RFC 8032 §5.1.7 Ed25519), never by
//! recomputing them.

#![allow(clippy::unwrap_used)]

mod client_pin;
mod config;
mod cred_mgmt;
mod fuzz;
mod get_assertion;
mod get_info;
mod hmac_secret;
mod json;
mod large_blobs;
mod make_credential;
mod persistence;
mod platform;
mod u2f;

use lk_codec::cbor::{self, MapBuilder, Value};
use lk_codec::der;
use lk_core::{DeviceProfile, Host, Outcome, Record};
use lk_crypto::{Curve, ecdsa_verify_prehash, ed25519_verify, sha256, sha384};
use lk_testkit::TestHost;

use crate::state::State;
use crate::{Authenticator, TOUCH_TIMEOUT_MS};

/// An arbitrary clientDataHash (WebAuthn L2 §5.8.1 hash of the client data).
pub(super) const CDH: [u8; 32] = [0x5A; 32];
pub(super) const RP: &str = "example.com";

pub(super) fn device() -> (Authenticator, TestHost) {
    let mut host = TestHost::new();
    let auth = Authenticator::new(None, &mut host);
    (auth, host)
}

pub(super) fn yubikey_device() -> (Authenticator, TestHost) {
    let mut host = TestHost::with_profile(DeviceProfile::yubikey_5c_nano_5_7_4(31_415_926));
    let auth = Authenticator::new(None, &mut host);
    (auth, host)
}

/// A new authenticator built from what `host` last persisted (a restart).
pub(super) fn restart(host: &mut TestHost) -> Authenticator {
    let stored = host.persisted(Record::Fido);
    Authenticator::new(stored.as_deref(), host)
}

/// The persisted state, decoded.
pub(super) fn persisted_state(host: &TestHost) -> State {
    State::deserialize(&host.persisted(Record::Fido).expect("persisted")).expect("readable")
}

/// Replace the persisted state and restart from it.
pub(super) fn with_state(host: &mut TestHost, edit: impl FnOnce(&mut State)) -> Authenticator {
    let mut state = host
        .persisted(Record::Fido)
        .and_then(|b| State::deserialize(&b))
        .unwrap_or_default();
    edit(&mut state);
    host.set_persisted(Record::Fido, &state.serialize());
    restart(host)
}

/// Send a CBOR request and grant the touch if one is requested.
pub(super) fn send(auth: &mut Authenticator, host: &mut TestHost, request: &[u8]) -> Vec<u8> {
    match auth.cbor(request, host) {
        Outcome::Done(response) => response,
        Outcome::NeedTouch { timeout_ms } => {
            assert_eq!(timeout_ms, TOUCH_TIMEOUT_MS);
            assert!(auth.is_pending());
            let response = auth.presence_resolved(true, host);
            assert!(!auth.is_pending());
            response
        }
    }
}

/// Send a request that must finish without a touch.
pub(super) fn send_untouched(
    auth: &mut Authenticator,
    host: &mut TestHost,
    request: &[u8],
) -> Vec<u8> {
    match auth.cbor(request, host) {
        Outcome::Done(response) => response,
        Outcome::NeedTouch { .. } => panic!("unexpected touch request"),
    }
}

/// Send a request that must wait for a touch, then resolve it with `granted`.
pub(super) fn send_resolved(
    auth: &mut Authenticator,
    host: &mut TestHost,
    request: &[u8],
    granted: bool,
) -> Vec<u8> {
    match auth.cbor(request, host) {
        Outcome::NeedTouch { .. } => auth.presence_resolved(granted, host),
        Outcome::Done(response) => panic!("expected a touch request, got {response:02x?}"),
    }
}

pub(super) fn status_of(response: &[u8]) -> u8 {
    *response.first().expect("status byte")
}

/// The CBOR body of a successful response.
pub(super) fn body(response: &[u8]) -> Value {
    assert_eq!(
        status_of(response),
        0,
        "status {:#04x}",
        status_of(response)
    );
    cbor::decode(&response[1..]).expect("CBOR body")
}

pub(super) fn encode_request(command: u8, params: &Value) -> Vec<u8> {
    let mut out = vec![command];
    cbor::encode_into(params, &mut out);
    out
}

/// A copy of map `params` with integer key `key` replaced (or removed for `None`).
pub(super) fn set_param(params: &Value, key: i64, value: Option<Value>) -> Value {
    let mut entries: Vec<(Value, Value)> = params
        .as_map()
        .unwrap()
        .iter()
        .filter(|(k, _)| *k != Value::int_key(key))
        .cloned()
        .collect();
    if let Some(value) = value {
        entries.push((Value::int_key(key), value));
    }
    Value::Map(entries)
}

pub(super) fn descriptor(id: &[u8]) -> Value {
    MapBuilder::new()
        .insert("type", "public-key")
        .insert("id", id.to_vec())
        .build()
}

/// An authenticatorMakeCredential request (CTAP 2.1 §6.1.1).
#[derive(Clone, Debug)]
pub(super) struct Mc {
    pub rp_id: String,
    pub user_id: Vec<u8>,
    pub user_name: Option<String>,
    pub algs: Vec<i64>,
    pub options: Vec<(&'static str, Value)>,
    pub exclude: Option<Vec<Vec<u8>>>,
    pub extensions: Vec<(&'static str, Value)>,
    pub pin_param: Option<Vec<u8>>,
    pub pin_protocol: Option<u64>,
}

impl Mc {
    pub fn new() -> Self {
        Self {
            rp_id: RP.into(),
            user_id: vec![0x01; 16],
            user_name: Some("alice".into()),
            algs: vec![-7],
            options: Vec::new(),
            exclude: None,
            extensions: Vec::new(),
            pin_param: None,
            pin_protocol: None,
        }
    }

    pub fn alg(mut self, alg: i64) -> Self {
        self.algs = vec![alg];
        self
    }

    pub fn rk(self) -> Self {
        self.option("rk", true)
    }

    pub fn option(mut self, name: &'static str, value: impl Into<Value>) -> Self {
        self.options.push((name, value.into()));
        self
    }

    pub fn ext(mut self, name: &'static str, value: impl Into<Value>) -> Self {
        self.extensions.push((name, value.into()));
        self
    }

    pub fn user(mut self, id: &[u8]) -> Self {
        self.user_id = id.to_vec();
        self
    }

    pub fn rp(mut self, rp_id: &str) -> Self {
        self.rp_id = rp_id.into();
        self
    }

    pub fn exclude(mut self, ids: Vec<Vec<u8>>) -> Self {
        self.exclude = Some(ids);
        self
    }

    /// pinUvAuthParam = authenticate(pinUvAuthToken, clientDataHash) (CTAP 2.1 §6.1.2
    /// step 11).
    pub fn with_token(mut self, token: &platform::Token) -> Self {
        self.pin_param = Some(token.sign(&CDH));
        self.pin_protocol = Some(u64::from(token.protocol));
        self
    }

    pub fn params(&self) -> Value {
        let mut user = MapBuilder::new().insert("id", self.user_id.clone());
        if let Some(name) = &self.user_name {
            user.set("name", name.as_str());
            user.set("displayName", format!("{name} display"));
        }
        let algs = self
            .algs
            .iter()
            .map(|a| {
                MapBuilder::new()
                    .insert("alg", *a)
                    .insert("type", "public-key")
                    .build()
            })
            .collect::<Vec<_>>();
        let mut m = MapBuilder::new()
            .insert(1, CDH.to_vec())
            .insert(
                2,
                MapBuilder::new()
                    .insert("id", self.rp_id.as_str())
                    .insert("name", "Example")
                    .build(),
            )
            .insert(3, user.build())
            .insert(4, Value::Array(algs));
        if let Some(ids) = &self.exclude {
            m.set(
                5,
                Value::Array(ids.iter().map(|id| descriptor(id)).collect()),
            );
        }
        if !self.extensions.is_empty() {
            let mut ext = MapBuilder::new();
            for (k, v) in &self.extensions {
                ext.set(*k, v.clone());
            }
            m.set(6, ext.build());
        }
        if !self.options.is_empty() {
            let mut opts = MapBuilder::new();
            for (k, v) in &self.options {
                opts.set(*k, v.clone());
            }
            m.set(7, opts.build());
        }
        if let Some(p) = &self.pin_param {
            m.set(8, p.clone());
        }
        if let Some(p) = self.pin_protocol {
            m.set(9, p);
        }
        m.build()
    }

    pub fn encode(&self) -> Vec<u8> {
        encode_request(0x01, &self.params())
    }
}

/// An authenticatorGetAssertion request (CTAP 2.1 §6.2.1).
#[derive(Clone, Debug)]
pub(super) struct Ga {
    pub rp_id: String,
    pub allow: Option<Vec<Vec<u8>>>,
    pub options: Vec<(&'static str, Value)>,
    pub extensions: Vec<(&'static str, Value)>,
    pub pin_param: Option<Vec<u8>>,
    pub pin_protocol: Option<u64>,
}

impl Ga {
    pub fn new() -> Self {
        Self {
            rp_id: RP.into(),
            allow: None,
            options: Vec::new(),
            extensions: Vec::new(),
            pin_param: None,
            pin_protocol: None,
        }
    }

    /// pinUvAuthParam = authenticate(pinUvAuthToken, clientDataHash) (CTAP 2.1 §6.2.2
    /// step 6).
    pub fn with_token(mut self, token: &platform::Token) -> Self {
        self.pin_param = Some(token.sign(&CDH));
        self.pin_protocol = Some(u64::from(token.protocol));
        self
    }

    pub fn allow(mut self, ids: Vec<Vec<u8>>) -> Self {
        self.allow = Some(ids);
        self
    }

    pub fn rp(mut self, rp_id: &str) -> Self {
        self.rp_id = rp_id.into();
        self
    }

    pub fn option(mut self, name: &'static str, value: impl Into<Value>) -> Self {
        self.options.push((name, value.into()));
        self
    }

    pub fn ext(mut self, name: &'static str, value: impl Into<Value>) -> Self {
        self.extensions.push((name, value.into()));
        self
    }

    pub fn params(&self) -> Value {
        let mut m = MapBuilder::new()
            .insert(1, self.rp_id.as_str())
            .insert(2, CDH.to_vec());
        if let Some(ids) = &self.allow {
            m.set(
                3,
                Value::Array(ids.iter().map(|id| descriptor(id)).collect()),
            );
        }
        if !self.extensions.is_empty() {
            let mut ext = MapBuilder::new();
            for (k, v) in &self.extensions {
                ext.set(*k, v.clone());
            }
            m.set(4, ext.build());
        }
        if !self.options.is_empty() {
            let mut opts = MapBuilder::new();
            for (k, v) in &self.options {
                opts.set(*k, v.clone());
            }
            m.set(5, opts.build());
        }
        if let Some(p) = &self.pin_param {
            m.set(6, p.clone());
        }
        if let Some(p) = self.pin_protocol {
            m.set(7, p);
        }
        m.build()
    }

    pub fn encode(&self) -> Vec<u8> {
        encode_request(0x02, &self.params())
    }
}

/// authenticatorData fields (WebAuthn L2 §6.1, §6.5.1).
#[derive(Debug, Clone)]
pub(super) struct AuthData {
    pub raw: Vec<u8>,
    pub rp_id_hash: Vec<u8>,
    pub flags: u8,
    pub counter: u32,
    pub aaguid: Option<Vec<u8>>,
    pub cred_id: Option<Vec<u8>>,
    pub public_key: Option<Value>,
    pub extensions: Option<Value>,
}

pub(super) fn parse_auth_data(raw: &[u8]) -> AuthData {
    let flags = raw[32];
    let counter = u32::from_be_bytes(raw[33..37].try_into().unwrap());
    let mut rest = &raw[37..];
    let (mut aaguid, mut cred_id, mut public_key) = (None, None, None);
    if flags & 0x40 != 0 {
        aaguid = Some(rest[..16].to_vec());
        let len = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
        cred_id = Some(rest[18..18 + len].to_vec());
        let (key, used) = cbor::decode_prefix(&rest[18 + len..]).unwrap();
        public_key = Some(key);
        rest = &rest[18 + len + used..];
    }
    let extensions = if flags & 0x80 != 0 {
        Some(cbor::decode(rest).unwrap())
    } else {
        assert!(rest.is_empty(), "trailing authData bytes");
        None
    };
    AuthData {
        raw: raw.to_vec(),
        rp_id_hash: raw[..32].to_vec(),
        flags,
        counter,
        aaguid,
        cred_id,
        public_key,
        extensions,
    }
}

/// A parsed makeCredential response (CTAP 2.1 §6.1.2 response map).
#[derive(Debug, Clone)]
pub(super) struct Registration {
    pub fmt: String,
    pub auth_data: AuthData,
    pub att_stmt: Value,
    pub large_blob_key: Option<Vec<u8>>,
}

impl Registration {
    pub fn id(&self) -> Vec<u8> {
        self.auth_data.cred_id.clone().unwrap()
    }

    pub fn public_key(&self) -> Value {
        self.auth_data.public_key.clone().unwrap()
    }

    pub fn cert(&self) -> Vec<u8> {
        let x5c = self
            .att_stmt
            .map_get_text("x5c")
            .and_then(Value::as_array)
            .unwrap();
        x5c[0].as_bytes().unwrap().to_vec()
    }
}

pub(super) fn parse_registration(response: &[u8]) -> Registration {
    let map = body(response);
    let auth_data = parse_auth_data(map.map_get_int(2).and_then(Value::as_bytes).unwrap());
    Registration {
        fmt: map
            .map_get_int(1)
            .and_then(Value::as_text)
            .unwrap()
            .to_owned(),
        auth_data,
        att_stmt: map.map_get_int(3).unwrap().clone(),
        large_blob_key: map
            .map_get_int(5)
            .and_then(Value::as_bytes)
            .map(<[u8]>::to_vec),
    }
}

/// A parsed getAssertion response (CTAP 2.1 §6.2.2 response map).
#[derive(Debug, Clone)]
pub(super) struct Assertion {
    pub cred_id: Vec<u8>,
    pub auth_data: AuthData,
    pub signature: Vec<u8>,
    pub user: Option<Value>,
    pub count: Option<u64>,
    pub large_blob_key: Option<Vec<u8>>,
}

pub(super) fn parse_assertion(response: &[u8]) -> Assertion {
    let map = body(response);
    let descriptor = map.map_get_int(1).unwrap();
    assert_eq!(
        descriptor.map_get_text("type").and_then(Value::as_text),
        Some("public-key")
    );
    Assertion {
        cred_id: descriptor
            .map_get_text("id")
            .and_then(Value::as_bytes)
            .unwrap()
            .to_vec(),
        auth_data: parse_auth_data(map.map_get_int(2).and_then(Value::as_bytes).unwrap()),
        signature: map
            .map_get_int(3)
            .and_then(Value::as_bytes)
            .unwrap()
            .to_vec(),
        user: map.map_get_int(4).cloned(),
        count: map.map_get_int(5).and_then(Value::as_u64),
        large_blob_key: map
            .map_get_int(7)
            .and_then(Value::as_bytes)
            .map(<[u8]>::to_vec),
    }
}

impl Assertion {
    /// WebAuthn L2 §6.3.3 step 11: the signature covers authenticatorData || clientDataHash.
    pub fn verifies_with(&self, cose: &Value) -> bool {
        verify_cose(
            cose,
            &[self.auth_data.raw.as_slice(), &CDH].concat(),
            &self.signature,
        )
    }
}

/// Verify `sig` over `message` with a COSE public key (RFC 9053 §2.1 ECDSA, §2.2 EdDSA).
pub(super) fn verify_cose(cose: &Value, message: &[u8], sig: &[u8]) -> bool {
    let alg = cose.map_get_int(3).and_then(Value::as_i64).unwrap();
    let x = cose.map_get_int(-2).and_then(Value::as_bytes).unwrap();
    match alg {
        -8 => ed25519_verify(x, message, sig),
        -7 | -35 => {
            let y = cose.map_get_int(-3).and_then(Value::as_bytes).unwrap();
            let point = [&[0x04u8][..], x, y].concat();
            if alg == -7 {
                ecdsa_verify_prehash(Curve::P256, &point, &sha256(message), sig)
            } else {
                ecdsa_verify_prehash(Curve::P384, &point, &sha384(message), sig)
            }
        }
        other => panic!("unexpected COSE alg {other}"),
    }
}

/// A COSE ES256 key for an uncompressed P-256 point (RFC 9053 §7.1.1).
pub(super) fn cose_es256(point: &[u8]) -> Value {
    MapBuilder::new()
        .insert(1, 2)
        .insert(3, -7)
        .insert(-1, 1)
        .insert(-2, point[1..33].to_vec())
        .insert(-3, point[33..65].to_vec())
        .build()
}

/// Make a credential and return the parsed registration.
pub(super) fn register(auth: &mut Authenticator, host: &mut TestHost, mc: &Mc) -> Registration {
    parse_registration(&send(auth, host, &mc.encode()))
}

/// Get an assertion (touching if asked) and return it parsed.
pub(super) fn assert(auth: &mut Authenticator, host: &mut TestHost, ga: &Ga) -> Assertion {
    parse_assertion(&send(auth, host, &ga.encode()))
}

pub(super) fn get_info(auth: &mut Authenticator, host: &mut TestHost) -> Value {
    body(&send_untouched(auth, host, &[0x04]))
}

// ---------------------------------------------------------------------------
// X.509 helpers (RFC 5280 §4.1)
// ---------------------------------------------------------------------------

/// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }:
/// `(raw tbsCertificate, signature octets)`.
pub(super) fn cert_signed_parts(cert: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let content = der::expect_only(cert, der::tag::SEQUENCE).unwrap();
    let (tbs, rest) = der::split_der(content).unwrap();
    let (_alg, rest) = der::split_der(rest).unwrap();
    let bits = der::expect_only(rest, der::tag::BIT_STRING).unwrap();
    let (unused, sig) = der::decode_bit_string(bits).unwrap();
    assert_eq!(unused, 0);
    (tbs.to_vec(), sig.to_vec())
}

/// The TBSCertificate fields as `(tag, value)`.
fn tbs_fields(cert: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let (tbs, _) = cert_signed_parts(cert);
    let content = der::expect_only(&tbs, der::tag::SEQUENCE).unwrap();
    der::parse_all(content)
        .unwrap()
        .into_iter()
        .map(|(t, v)| (t, v.to_vec()))
        .collect()
}

/// The subject public key bits (an uncompressed EC point here).
pub(super) fn cert_public_key(cert: &[u8]) -> Vec<u8> {
    let fields = tbs_fields(cert);
    let spki = &fields[6];
    assert_eq!(spki.0, der::tag::SEQUENCE);
    let parts = der::parse_all(&spki.1).unwrap();
    let (unused, key) = der::decode_bit_string(parts[1].1).unwrap();
    assert_eq!(unused, 0);
    key.to_vec()
}

/// The certificate version field value (`[0] EXPLICIT INTEGER`).
pub(super) fn cert_version(cert: &[u8]) -> Vec<u8> {
    let fields = tbs_fields(cert);
    assert_eq!(fields[0].0, 0xA0);
    der::expect_only(&fields[0].1, der::tag::INTEGER)
        .unwrap()
        .to_vec()
}

/// Name attributes `(oid, string value)` of the issuer (`index` 3) or subject (5).
pub(super) fn cert_name(cert: &[u8], index: usize) -> Vec<(Vec<u64>, String)> {
    let fields = tbs_fields(cert);
    der::parse_all(&fields[index].1)
        .unwrap()
        .into_iter()
        .map(|(tag, set)| {
            assert_eq!(tag, der::tag::SET);
            let atv = der::expect_only(set, der::tag::SEQUENCE).unwrap();
            let parts = der::parse_all(atv).unwrap();
            (
                der::decode_oid(parts[0].1).unwrap(),
                String::from_utf8(parts[1].1.to_vec()).unwrap(),
            )
        })
        .collect()
}

/// The extension `oid`: `(critical, extnValue contents)`.
pub(super) fn cert_extension(cert: &[u8], oid: &[u64]) -> Option<(bool, Vec<u8>)> {
    let fields = tbs_fields(cert);
    let ext = fields.iter().find(|(tag, _)| *tag == 0xA3)?;
    let list = der::expect_only(&ext.1, der::tag::SEQUENCE).unwrap();
    for (_, extension) in der::parse_all(list).unwrap() {
        let parts = der::parse_all(extension).unwrap();
        if der::decode_oid(parts[0].1).unwrap() == oid {
            let critical = parts.len() == 3 && parts[1].1 == [0xFF];
            let value = parts.last().unwrap().1.to_vec();
            return Some((critical, value));
        }
    }
    None
}

/// Whether `cert` is signed (ECDSA P-256 / SHA-256) by the key `issuer_point`.
pub(super) fn cert_signed_by(cert: &[u8], issuer_point: &[u8]) -> bool {
    let (tbs, sig) = cert_signed_parts(cert);
    ecdsa_verify_prehash(Curve::P256, issuer_point, &sha256(&tbs), &sig)
}
