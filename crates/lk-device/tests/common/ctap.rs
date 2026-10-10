//! The host (platform) side of CTAP 2.1 and U2F, written from the specifications:
//! request maps (CTAP 2.1 §6), PIN/UV auth protocol 2 (§6.5.7), authenticator data
//! (WebAuthn L2 §6.1, §6.5.1), COSE keys (RFC 9052 §7, RFC 9053 §7.1.1) and U2F raw
//! messages (FIDO U2F Raw Message Formats v1.2 §3-§5). CBOR goes through
//! `lk_codec::cbor`, cryptography through `lk_crypto`; nothing comes from `lk-fido`.

#![allow(dead_code, clippy::unwrap_used)]

use lk_codec::cbor::{self, MapBuilder, Value};
use lk_core::Entropy;
use lk_crypto::{Curve, EcPrivateKey, aes_cbc_decrypt, aes_cbc_encrypt, ecdsa_verify_prehash, hkdf_sha256, hmac_sha256, sha256};

use super::der;

/// Authenticator API command bytes (CTAP 2.1 §6).
pub mod cmd {
    pub const MAKE_CREDENTIAL: u8 = 0x01;
    pub const GET_ASSERTION: u8 = 0x02;
    pub const GET_INFO: u8 = 0x04;
    pub const CLIENT_PIN: u8 = 0x06;
    pub const RESET: u8 = 0x07;
    pub const GET_NEXT_ASSERTION: u8 = 0x08;
    pub const CREDENTIAL_MANAGEMENT: u8 = 0x0A;
    pub const SELECTION: u8 = 0x0B;
}

/// Status codes (CTAP 2.1 §8.2).
pub mod status {
    pub const OK: u8 = 0x00;
    pub const CHANNEL_BUSY: u8 = 0x06;
    pub const CREDENTIAL_EXCLUDED: u8 = 0x19;
    pub const OPERATION_DENIED: u8 = 0x27;
    pub const KEEPALIVE_CANCEL: u8 = 0x2D;
    pub const NO_CREDENTIALS: u8 = 0x2E;
    pub const USER_ACTION_TIMEOUT: u8 = 0x2F;
    pub const NOT_ALLOWED: u8 = 0x30;
    pub const PIN_INVALID: u8 = 0x31;
    pub const PIN_BLOCKED: u8 = 0x32;
    pub const PIN_AUTH_INVALID: u8 = 0x33;
    pub const PIN_AUTH_BLOCKED: u8 = 0x34;
    pub const PIN_NOT_SET: u8 = 0x35;
    pub const PUAT_REQUIRED: u8 = 0x36;
    pub const PIN_POLICY_VIOLATION: u8 = 0x37;
    pub const OTHER: u8 = 0x7F;
}

/// pinUvAuthToken permissions (CTAP 2.1 §6.5.5.7).
pub mod perm {
    pub const MC: u8 = 0x01;
    pub const GA: u8 = 0x02;
    pub const CM: u8 = 0x04;
}

/// authenticatorData flags (WebAuthn L2 §6.1).
pub mod flag {
    pub const UP: u8 = 0x01;
    pub const UV: u8 = 0x04;
    pub const AT: u8 = 0x40;
    pub const ED: u8 = 0x80;
}

/// A CTAP2 message: the command byte followed by the canonical CBOR parameters (§8).
pub fn request(command: u8, params: Option<Value>) -> Vec<u8> {
    let mut out = vec![command];
    if let Some(params) = params {
        out.extend_from_slice(&cbor::encode(&params));
    }
    out
}

/// Split a CTAP2 response into status and decoded CBOR (absent for a bare status).
pub fn response(bytes: &[u8]) -> (u8, Option<Value>) {
    let (&status, body) = bytes.split_first().expect("empty CTAP2 response");
    let value = (!body.is_empty()).then(|| cbor::decode(body).expect("response CBOR"));
    (status, value)
}

/// The decoded CBOR of a successful response.
pub fn ok_value(bytes: &[u8]) -> Value {
    match response(bytes) {
        (status::OK, Some(value)) => value,
        (status, _) => panic!("CTAP2 status {status:#04x}, expected success with data"),
    }
}

/// Integer-keyed map member.
pub fn get(value: &Value, key: i64) -> &Value {
    value.map_get_int(key).unwrap_or_else(|| panic!("missing key {key} in {value:?}"))
}

/// `PublicKeyCredentialDescriptor` (WebAuthn L2 §5.8.3).
pub fn descriptor(id: &[u8]) -> Value {
    MapBuilder::new().insert("id", id.to_vec()).insert("type", "public-key").build()
}

/// How a request proves user verification.
#[derive(Debug, Clone)]
pub enum PinAuth {
    None,
    /// pinUvAuthParam computed with this token and protocol 2.
    Token(Vec<u8>),
    /// A zero-length pinUvAuthParam (the §6.1.2 step 1 probe).
    Probe,
}

impl PinAuth {
    fn apply(&self, map: MapBuilder, client_data_hash: &[u8]) -> MapBuilder {
        match self {
            PinAuth::None => map,
            PinAuth::Token(token) => map.insert(8, authenticate(token, client_data_hash)).insert(9, 2u8),
            PinAuth::Probe => map.insert(8, Vec::<u8>::new()).insert(9, 2u8),
        }
    }
}

/// authenticatorMakeCredential (§6.1) with ES256 and the given options.
pub fn make_credential(client_data_hash: &[u8; 32], rp_id: &str, user_id: &[u8], rk: bool, auth: &PinAuth) -> Vec<u8> {
    make_credential_with(client_data_hash, rp_id, user_id, rk, auth, &[])
}

/// authenticatorMakeCredential with an excludeList.
pub fn make_credential_with(
    client_data_hash: &[u8; 32],
    rp_id: &str,
    user_id: &[u8],
    rk: bool,
    auth: &PinAuth,
    exclude: &[Vec<u8>],
) -> Vec<u8> {
    let rp = MapBuilder::new().insert("id", rp_id).insert("name", "Example RP").build();
    let user = MapBuilder::new()
        .insert("id", user_id.to_vec())
        .insert("name", "user@example.com")
        .insert("displayName", "Example User")
        .build();
    let params = Value::Array(vec![MapBuilder::new().insert("alg", -7i64).insert("type", "public-key").build()]);
    let mut map = MapBuilder::new()
        .insert(1, client_data_hash.to_vec())
        .insert(2, rp)
        .insert(3, user)
        .insert(4, params);
    if !exclude.is_empty() {
        map = map.insert(5, Value::Array(exclude.iter().map(|id| descriptor(id)).collect()));
    }
    if rk {
        map = map.insert(7, MapBuilder::new().insert("rk", true).build());
    }
    let map = auth.apply(map, client_data_hash);
    request(cmd::MAKE_CREDENTIAL, Some(map.build()))
}

/// authenticatorGetAssertion (§6.2).
pub fn get_assertion(client_data_hash: &[u8; 32], rp_id: &str, allow: &[Vec<u8>], auth: &PinAuth) -> Vec<u8> {
    let mut map = MapBuilder::new().insert(1, rp_id).insert(2, client_data_hash.to_vec());
    if !allow.is_empty() {
        map = map.insert(3, Value::Array(allow.iter().map(|id| descriptor(id)).collect()));
    }
    let map = auth.apply(map, client_data_hash);
    request(cmd::GET_ASSERTION, Some(map.build()))
}

/// A COSE_Key EC2 P-256 public key (RFC 9053 §7.1.1) as an uncompressed SEC1 point.
pub fn cose_p256_point(key: &Value) -> Vec<u8> {
    assert_eq!(get(key, 1).as_i64(), Some(2), "kty EC2");
    assert_eq!(get(key, -1).as_i64(), Some(1), "crv P-256");
    let x = get(key, -2).as_bytes().unwrap();
    let y = get(key, -3).as_bytes().unwrap();
    assert_eq!((x.len(), y.len()), (32, 32));
    [&[0x04][..], x, y].concat()
}

/// Attested credential data (WebAuthn L2 §6.5.1).
#[derive(Debug, Clone)]
pub struct AttestedCredential {
    pub aaguid: [u8; 16],
    pub id: Vec<u8>,
    pub cose: Value,
    /// The ES256 public key as `04 || x || y`.
    pub public_key: Vec<u8>,
}

/// Authenticator data (WebAuthn L2 §6.1).
#[derive(Debug, Clone)]
pub struct AuthData {
    pub rp_id_hash: [u8; 32],
    pub flags: u8,
    pub sign_count: u32,
    pub credential: Option<AttestedCredential>,
    pub extensions: Option<Value>,
}

pub fn parse_auth_data(bytes: &[u8]) -> AuthData {
    assert!(bytes.len() >= 37, "authenticator data too short");
    let rp_id_hash: [u8; 32] = bytes[..32].try_into().unwrap();
    let flags = bytes[32];
    let sign_count = u32::from_be_bytes(bytes[33..37].try_into().unwrap());
    let mut rest = &bytes[37..];
    let credential = (flags & flag::AT != 0).then(|| {
        let aaguid: [u8; 16] = rest[..16].try_into().unwrap();
        let len = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
        let id = rest[18..18 + len].to_vec();
        let (cose, used) = cbor::decode_prefix(&rest[18 + len..]).expect("credential public key");
        rest = &rest[18 + len + used..];
        assert_eq!(get(&cose, 3).as_i64(), Some(-7), "alg ES256");
        let public_key = cose_p256_point(&cose);
        AttestedCredential {
            aaguid,
            id,
            cose,
            public_key,
        }
    });
    let extensions = (flags & flag::ED != 0).then(|| {
        let (value, used) = cbor::decode_prefix(rest).expect("extensions");
        rest = &rest[used..];
        value
    });
    assert!(rest.is_empty(), "trailing authenticator data");
    AuthData {
        rp_id_hash,
        flags,
        sign_count,
        credential,
        extensions,
    }
}

/// An ES256 signature over `authData || clientDataHash` (WebAuthn L2 §6.3.3 step 11,
/// §8.2 packed attestation; ECDSA with SHA-256, DER-encoded signature).
pub fn verify_es256(public_key: &[u8], auth_data: &[u8], client_data_hash: &[u8], signature: &[u8]) -> bool {
    assert_eq!(signature.first(), Some(&0x30), "DER ECDSA-Sig-Value");
    let digest = sha256(&[auth_data, client_data_hash].concat());
    ecdsa_verify_prehash(Curve::P256, public_key, &digest, signature)
}

/// pinUvAuthProtocol 2 `authenticate(key, message)` (§6.5.7): HMAC-SHA-256 with the first
/// 32 bytes of the key; the whole 32-byte result.
pub fn authenticate(key: &[u8], message: &[u8]) -> Vec<u8> {
    hmac_sha256(&key[..32], message).to_vec()
}

/// The platform half of PIN/UV auth protocol 2 (§6.5.7) after one key agreement.
pub struct PinProtocol2 {
    platform: EcPrivateKey,
    hmac_key: Vec<u8>,
    aes_key: Vec<u8>,
}

impl PinProtocol2 {
    /// getKeyAgreement (§6.5.5.4): `{1: 2, 2: 2}`.
    pub fn key_agreement_request() -> Vec<u8> {
        request(cmd::CLIENT_PIN, Some(MapBuilder::new().insert(1, 2u8).insert(2, 2u8).build()))
    }

    /// `encapsulate` (§6.5.6 "ecdh", §6.5.7 "kdf"): a fresh platform key, the ECDH x
    /// coordinate Z, and `HKDF-SHA-256(salt = 32 zero bytes, Z, "CTAP2 HMAC key" /
    /// "CTAP2 AES key", 32)`.
    pub fn from_key_agreement(response: &[u8], entropy: &mut dyn Entropy) -> Self {
        let value = ok_value(response);
        let peer = get(&value, 1);
        assert_eq!(get(peer, 3).as_i64(), Some(-25), "alg ECDH-ES+HKDF-256");
        let point = cose_p256_point(peer);
        let platform = EcPrivateKey::generate(Curve::P256, entropy);
        let z = platform.ecdh(&point).unwrap();
        let salt = [0u8; 32];
        let hmac_key = hkdf_sha256(Some(&salt), &z, b"CTAP2 HMAC key", 32).unwrap();
        let aes_key = hkdf_sha256(Some(&salt), &z, b"CTAP2 AES key", 32).unwrap();
        Self {
            platform,
            hmac_key,
            aes_key,
        }
    }

    /// The platform key agreement key as a COSE_Key (§6.5.6 `getPublicKey`).
    pub fn platform_cose(&self) -> Value {
        let point = self.platform.public_uncompressed();
        MapBuilder::new()
            .insert(1, 2u8)
            .insert(3, -25i64)
            .insert(-1, 1u8)
            .insert(-2, point[1..33].to_vec())
            .insert(-3, point[33..65].to_vec())
            .build()
    }

    /// `encrypt` (§6.5.7): a random IV, then AES-256-CBC without padding.
    pub fn encrypt(&self, iv: [u8; 16], plaintext: &[u8]) -> Vec<u8> {
        let mut out = iv.to_vec();
        out.extend_from_slice(&aes_cbc_encrypt(&self.aes_key, &iv, plaintext).unwrap());
        out
    }

    /// `decrypt` (§6.5.7).
    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        let (iv, body) = ciphertext.split_at(16);
        aes_cbc_decrypt(&self.aes_key, iv, body).unwrap()
    }

    pub fn authenticate(&self, message: &[u8]) -> Vec<u8> {
        authenticate(&self.hmac_key, message)
    }

    /// `newPinEnc`: the PIN padded with zeros to 64 bytes (§6.5.5.5).
    fn new_pin_enc(&self, pin: &str) -> Vec<u8> {
        let mut padded = [0u8; 64];
        padded[..pin.len()].copy_from_slice(pin.as_bytes());
        self.encrypt([0x1A; 16], &padded)
    }

    /// `pinHashEnc`: `LEFT(SHA-256(pin), 16)` encrypted (§6.5.5.6).
    fn pin_hash_enc(&self, pin: &str) -> Vec<u8> {
        self.encrypt([0x2B; 16], &sha256(pin.as_bytes())[..16])
    }

    /// setPIN (§6.5.5.5): `{1: 2, 2: 3, 3: keyAgreement, 4: authenticate(newPinEnc),
    /// 5: newPinEnc}`.
    pub fn set_pin(&self, pin: &str) -> Vec<u8> {
        let enc = self.new_pin_enc(pin);
        let map = MapBuilder::new()
            .insert(1, 2u8)
            .insert(2, 3u8)
            .insert(3, self.platform_cose())
            .insert(4, self.authenticate(&enc))
            .insert(5, enc);
        request(cmd::CLIENT_PIN, Some(map.build()))
    }

    /// changePIN (§6.5.5.6): authenticate(newPinEnc || pinHashEnc).
    pub fn change_pin(&self, current: &str, new: &str) -> Vec<u8> {
        let enc = self.new_pin_enc(new);
        let hash = self.pin_hash_enc(current);
        let map = MapBuilder::new()
            .insert(1, 2u8)
            .insert(2, 4u8)
            .insert(3, self.platform_cose())
            .insert(4, self.authenticate(&[enc.as_slice(), hash.as_slice()].concat()))
            .insert(5, enc)
            .insert(6, hash);
        request(cmd::CLIENT_PIN, Some(map.build()))
    }

    /// getPinUvAuthTokenUsingPinWithPermissions (§6.5.5.7.2): `{1: 2, 2: 9, 3: key
    /// agreement, 6: pinHashEnc, 9: permissions, 10: rpId}`.
    pub fn token_request(&self, pin: &str, permissions: u8, rp_id: Option<&str>) -> Vec<u8> {
        let mut map = MapBuilder::new()
            .insert(1, 2u8)
            .insert(2, 9u8)
            .insert(3, self.platform_cose())
            .insert(6, self.pin_hash_enc(pin))
            .insert(9, permissions);
        if let Some(rp_id) = rp_id {
            map = map.insert(10, rp_id);
        }
        request(cmd::CLIENT_PIN, Some(map.build()))
    }

    /// The pinUvAuthToken from a token response (`{2: encrypted token}`).
    pub fn token(&self, response: &[u8]) -> Vec<u8> {
        let value = ok_value(response);
        let token = self.decrypt(get(&value, 2).as_bytes().unwrap());
        assert_eq!(token.len(), 32, "protocol 2 tokens are 32 bytes");
        token
    }
}

/// getPINRetries (§6.5.5.2): `{1: 2, 2: 1}` → `{3: retries}`.
pub fn pin_retries_request() -> Vec<u8> {
    request(cmd::CLIENT_PIN, Some(MapBuilder::new().insert(1, 2u8).insert(2, 1u8).build()))
}

/// authenticatorCredentialManagement (§6.8) with `pinUvAuthParam = authenticate(token,
/// subCommand || subCommandParams)` when a token is given.
pub fn cred_mgmt(sub: u8, params: Option<Value>, token: Option<&[u8]>) -> Vec<u8> {
    let mut map = MapBuilder::new().insert(1, sub);
    let encoded = params.as_ref().map(cbor::encode).unwrap_or_default();
    if let Some(params) = params {
        map = map.insert(2, params);
    }
    if let Some(token) = token {
        let mut message = vec![sub];
        message.extend_from_slice(&encoded);
        map = map.insert(3, 2u8).insert(4, authenticate(token, &message));
    }
    request(cmd::CREDENTIAL_MANAGEMENT, Some(map.build()))
}

// ----- U2F raw messages (FIDO U2F Raw Message Formats v1.2) -----

/// U2F REGISTER (§4.1) in extended length encoding (§3.1.1): `00 01 00 00 00 00 40
/// challenge(32) application(32) 00 00`.
pub fn u2f_register(challenge: &[u8; 32], application: &[u8; 32]) -> Vec<u8> {
    let mut apdu = vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x40];
    apdu.extend_from_slice(challenge);
    apdu.extend_from_slice(application);
    apdu.extend_from_slice(&[0x00, 0x00]);
    apdu
}

/// U2F AUTHENTICATE (§5.1): control byte `03` enforce-user-presence-and-sign, `07`
/// check-only, `08` dont-enforce-user-presence-and-sign.
pub fn u2f_authenticate(control: u8, challenge: &[u8; 32], application: &[u8; 32], key_handle: &[u8]) -> Vec<u8> {
    let mut data = challenge.to_vec();
    data.extend_from_slice(application);
    data.push(key_handle.len() as u8);
    data.extend_from_slice(key_handle);
    let mut apdu = vec![0x00, 0x02, control, 0x00, 0x00];
    apdu.extend_from_slice(&(data.len() as u16).to_be_bytes());
    apdu.extend_from_slice(&data);
    apdu.extend_from_slice(&[0x00, 0x00]);
    apdu
}

/// A U2F registration response (§4.3).
#[derive(Debug, Clone)]
pub struct U2fRegistration {
    pub public_key: Vec<u8>,
    pub key_handle: Vec<u8>,
    pub certificate: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Parse `05 || user public key (65) || L || key handle || attestation certificate ||
/// signature || 90 00`.
pub fn parse_u2f_registration(response: &[u8]) -> U2fRegistration {
    let (body, sw) = response.split_at(response.len() - 2);
    assert_eq!(sw, [0x90, 0x00], "U2F REGISTER status");
    assert_eq!(body[0], 0x05, "reserved byte");
    let public_key = body[1..66].to_vec();
    let len = usize::from(body[66]);
    let key_handle = body[67..67 + len].to_vec();
    let rest = &body[67 + len..];
    let cert_len = der::element_len(rest);
    U2fRegistration {
        public_key,
        key_handle,
        certificate: rest[..cert_len].to_vec(),
        signature: rest[cert_len..].to_vec(),
    }
}

impl U2fRegistration {
    /// §4.3: the attestation signature over `00 || application || challenge || key handle
    /// || user public key`, by the key in the attestation certificate.
    pub fn verify(&self, challenge: &[u8; 32], application: &[u8; 32]) -> bool {
        let mut signed = vec![0x00];
        signed.extend_from_slice(application);
        signed.extend_from_slice(challenge);
        signed.extend_from_slice(&self.key_handle);
        signed.extend_from_slice(&self.public_key);
        let attestation_key = der::certificate_ec_public_key(&self.certificate);
        ecdsa_verify_prehash(Curve::P256, &attestation_key, &sha256(&signed), &self.signature)
    }
}

/// Check a U2F authentication response (§5.4): `user presence || counter(4) ||
/// signature` over `application || user presence || counter || challenge`. Returns the
/// presence byte and the counter.
pub fn verify_u2f_authentication(
    response: &[u8],
    public_key: &[u8],
    challenge: &[u8; 32],
    application: &[u8; 32],
) -> (u8, u32) {
    let (body, sw) = response.split_at(response.len() - 2);
    assert_eq!(sw, [0x90, 0x00], "U2F AUTHENTICATE status");
    let presence = body[0];
    let counter = u32::from_be_bytes(body[1..5].try_into().unwrap());
    let signature = &body[5..];
    let mut signed = application.to_vec();
    signed.push(presence);
    signed.extend_from_slice(&counter.to_be_bytes());
    signed.extend_from_slice(challenge);
    assert!(ecdsa_verify_prehash(Curve::P256, public_key, &sha256(&signed), signature), "U2F signature");
    (presence, counter)
}
