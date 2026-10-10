//! An independent test-side platform for PIN/UV auth protocols 1 and 2.
//!
//! Written again from CTAP 2.1 §6.5.6 (protocol 1) and §6.5.7 (protocol 2) using only
//! lk-crypto primitives, so the authenticator's own `pin_protocol` module is checked
//! against a second implementation rather than against itself:
//! - `encapsulate()`: a fresh platform P-256 key, ECDH with the authenticator's
//!   keyAgreement, `kdf(Z)`;
//! - protocol 1: `kdf = SHA-256(Z)`, AES-256-CBC with a zero IV,
//!   `authenticate = LEFT(HMAC-SHA-256, 16)`;
//! - protocol 2: `kdf = HKDF-SHA-256(32 zero bytes, Z, "CTAP2 HMAC key") ||
//!   HKDF-SHA-256(32 zero bytes, Z, "CTAP2 AES key")`, random IV prepended, full
//!   HMAC-SHA-256 with the first 32 bytes (or the whole 32-byte token).

use lk_codec::cbor::{MapBuilder, Value};
use lk_crypto::{
    Curve, EcPrivateKey, aes_cbc_decrypt, aes_cbc_encrypt, hkdf_sha256, hmac_sha256, sha256,
};
use lk_testkit::{SeededEntropy, TestHost};

use super::{body, encode_request, send_untouched, status_of};
use crate::Authenticator;

/// authenticatorClientPIN subcommands (CTAP 2.1 §6.5.5).
pub(super) mod sub {
    pub const GET_PIN_RETRIES: u64 = 0x01;
    pub const GET_KEY_AGREEMENT: u64 = 0x02;
    pub const SET_PIN: u64 = 0x03;
    pub const CHANGE_PIN: u64 = 0x04;
    pub const GET_PIN_TOKEN: u64 = 0x05;
    pub const GET_TOKEN_WITH_PERMISSIONS: u64 = 0x09;
}

/// Permissions (CTAP 2.1 §6.5.5.7).
pub(super) mod perm {
    pub const MC: u8 = 0x01;
    pub const GA: u8 = 0x02;
    pub const CM: u8 = 0x04;
    pub const BE: u8 = 0x08;
    pub const LBW: u8 = 0x10;
    pub const ACFG: u8 = 0x20;
}

/// The test PIN used where any valid PIN will do.
pub(super) const PIN: &str = "1234";

/// A platform with a shared secret for one protocol.
pub(super) struct Platform {
    pub protocol: u8,
    key: EcPrivateKey,
    pub shared: Vec<u8>,
    rng: SeededEntropy,
}

impl Platform {
    /// getKeyAgreement (§6.5.5.3) and `encapsulate()` against the authenticator's key.
    pub fn connect(auth: &mut Authenticator, host: &mut TestHost, protocol: u8) -> Self {
        let response = send_untouched(
            auth,
            host,
            &client_pin(Some(protocol), sub::GET_KEY_AGREEMENT).request(),
        );
        let peer = body(&response).map_get_int(1).cloned().unwrap();
        Self::with_peer(protocol, &peer)
    }

    /// `encapsulate(peer)` for an authenticator COSE key `{1: 2, 3: -25, -1: 1, -2, -3}`.
    pub fn with_peer(protocol: u8, peer: &Value) -> Self {
        assert_eq!(
            peer.map_get_int(1).and_then(Value::as_i64),
            Some(2),
            "kty EC2"
        );
        assert_eq!(
            peer.map_get_int(3).and_then(Value::as_i64),
            Some(-25),
            "alg"
        );
        assert_eq!(
            peer.map_get_int(-1).and_then(Value::as_i64),
            Some(1),
            "crv P-256"
        );
        let x = peer.map_get_int(-2).and_then(Value::as_bytes).unwrap();
        let y = peer.map_get_int(-3).and_then(Value::as_bytes).unwrap();
        let point = [&[0x04u8][..], x, y].concat();
        let mut rng = SeededEntropy::new(0x5150_0000 + u64::from(protocol));
        let key = EcPrivateKey::generate(Curve::P256, &mut rng);
        let z = key.ecdh(&point).unwrap();
        let shared = match protocol {
            1 => sha256(&z).to_vec(),
            _ => {
                let salt = [0u8; 32];
                let mut s = hkdf_sha256(Some(&salt), &z, b"CTAP2 HMAC key", 32).unwrap();
                s.extend(hkdf_sha256(Some(&salt), &z, b"CTAP2 AES key", 32).unwrap());
                s
            }
        };
        Self {
            protocol,
            key,
            shared,
            rng,
        }
    }

    /// The platform keyAgreement COSE key (§6.5.6 `getPublicKey()`).
    pub fn cose_key(&self) -> Value {
        let point = self.key.public_uncompressed();
        MapBuilder::new()
            .insert(1, 2)
            .insert(3, -25)
            .insert(-1, 1)
            .insert(-2, point[1..33].to_vec())
            .insert(-3, point[33..65].to_vec())
            .build()
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        match self.protocol {
            1 => aes_cbc_encrypt(&self.shared, &[0; 16], plaintext).unwrap(),
            _ => {
                let iv = self.rng.bytes(16);
                let mut out = iv.clone();
                out.extend(aes_cbc_encrypt(&self.shared[32..], &iv, plaintext).unwrap());
                out
            }
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        match self.protocol {
            1 => aes_cbc_decrypt(&self.shared, &[0; 16], ciphertext).unwrap(),
            _ => aes_cbc_decrypt(&self.shared[32..], &ciphertext[..16], &ciphertext[16..]).unwrap(),
        }
    }

    /// `authenticate(key, message)` for this protocol.
    pub fn mac(&self, key: &[u8], message: &[u8]) -> Vec<u8> {
        match self.protocol {
            1 => hmac_sha256(key, message)[..16].to_vec(),
            _ => hmac_sha256(&key[..32], message).to_vec(),
        }
    }

    /// `authenticate(shared secret, message)`.
    pub fn mac_shared(&self, message: &[u8]) -> Vec<u8> {
        self.mac(&self.shared, message)
    }

    /// `encrypt(shared secret, LEFT(SHA-256(pin), 16))` (§6.5.5.6).
    pub fn pin_hash_enc(&mut self, pin: &str) -> Vec<u8> {
        let hash = sha256(pin.as_bytes());
        self.encrypt(&hash[..16])
    }

    /// `encrypt(shared secret, paddedNewPin)` with the PIN zero-padded to 64 bytes.
    pub fn new_pin_enc(&mut self, pin: &[u8]) -> Vec<u8> {
        let mut padded = pin.to_vec();
        padded.resize(64, 0);
        self.encrypt(&padded)
    }

    /// A setPIN request (§6.5.5.5).
    pub fn set_pin_request(&mut self, pin: &[u8]) -> Vec<u8> {
        let new_pin_enc = self.new_pin_enc(pin);
        let auth = self.mac_shared(&new_pin_enc);
        client_pin(Some(self.protocol), sub::SET_PIN)
            .with(3, self.cose_key())
            .with(5, new_pin_enc)
            .with(4, auth)
            .request()
    }

    /// A changePIN request (§6.5.5.6).
    pub fn change_pin_request(&mut self, old: &str, new: &[u8]) -> Vec<u8> {
        let pin_hash_enc = self.pin_hash_enc(old);
        let new_pin_enc = self.new_pin_enc(new);
        let auth = self.mac_shared(&[new_pin_enc.as_slice(), &pin_hash_enc].concat());
        client_pin(Some(self.protocol), sub::CHANGE_PIN)
            .with(3, self.cose_key())
            .with(6, pin_hash_enc)
            .with(5, new_pin_enc)
            .with(4, auth)
            .request()
    }

    /// A getPinToken request (§6.5.5.4).
    pub fn pin_token_request(&mut self, pin: &str) -> Vec<u8> {
        let enc = self.pin_hash_enc(pin);
        client_pin(Some(self.protocol), sub::GET_PIN_TOKEN)
            .with(3, self.cose_key())
            .with(6, enc)
            .request()
    }

    /// A getPinUvAuthTokenUsingPinWithPermissions request (§6.5.5.7).
    pub fn token_request(&mut self, pin: &str, permissions: u8, rp_id: Option<&str>) -> Vec<u8> {
        let enc = self.pin_hash_enc(pin);
        let mut req = client_pin(Some(self.protocol), sub::GET_TOKEN_WITH_PERMISSIONS)
            .with(3, self.cose_key())
            .with(6, enc)
            .with(9, permissions);
        if let Some(rp) = rp_id {
            req = req.with(0x0A, rp);
        }
        req.request()
    }

    /// The token in a successful token response.
    pub fn token_from(&self, response: &[u8]) -> Token {
        let enc = body(response)
            .map_get_int(2)
            .and_then(Value::as_bytes)
            .unwrap()
            .to_vec();
        Token {
            protocol: self.protocol,
            value: self.decrypt(&enc),
        }
    }
}

/// A decrypted pinUvAuthToken.
#[derive(Clone, Debug)]
pub(crate) struct Token {
    pub protocol: u8,
    pub value: Vec<u8>,
}

impl Token {
    /// `authenticate(pinUvAuthToken, message)`.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self.protocol {
            1 => hmac_sha256(&self.value, message)[..16].to_vec(),
            _ => hmac_sha256(&self.value, message).to_vec(),
        }
    }
}

/// An authenticatorClientPIN parameter map under construction.
pub(super) struct ClientPin(MapBuilder);

/// `{1?: pinUvAuthProtocol, 2: subCommand}`.
pub(super) fn client_pin(protocol: Option<u8>, subcommand: u64) -> ClientPin {
    let mut m = MapBuilder::new().insert(2, subcommand);
    if let Some(p) = protocol {
        m.set(1, p);
    }
    ClientPin(m)
}

impl ClientPin {
    pub fn with(mut self, key: i64, value: impl Into<Value>) -> Self {
        self.0.set(key, value);
        self
    }

    pub fn request(self) -> Vec<u8> {
        encode_request(0x06, &self.0.build())
    }
}

/// Set `pin` with `protocol`; the response status must be OK.
pub(super) fn set_pin(auth: &mut Authenticator, host: &mut TestHost, protocol: u8, pin: &str) {
    let mut platform = Platform::connect(auth, host, protocol);
    let r = send_untouched(auth, host, &platform.set_pin_request(pin.as_bytes()));
    assert_eq!(r, vec![0x00], "setPIN");
}

/// Get a pinUvAuthToken with `permissions` (and `rp_id`) with `protocol`.
pub(super) fn token(
    auth: &mut Authenticator,
    host: &mut TestHost,
    protocol: u8,
    permissions: u8,
    rp_id: Option<&str>,
) -> Token {
    let mut platform = Platform::connect(auth, host, protocol);
    let r = send_untouched(auth, host, &platform.token_request(PIN, permissions, rp_id));
    assert_eq!(status_of(&r), 0x00, "token request {r:02x?}");
    platform.token_from(&r)
}

/// `{3: pinRetries, 4: powerCycleState}` from getPINRetries.
pub(super) fn retries(auth: &mut Authenticator, host: &mut TestHost) -> (u64, bool) {
    let r = body(&send_untouched(
        auth,
        host,
        &client_pin(Some(2), sub::GET_PIN_RETRIES).request(),
    ));
    (
        r.map_get_int(3).and_then(Value::as_u64).unwrap(),
        r.map_get_int(4).and_then(Value::as_bool).unwrap(),
    )
}
