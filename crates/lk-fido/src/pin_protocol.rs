//! PIN/UV auth protocols one and two (CTAP 2.1 §6.5.6 and §6.5.7) and the authenticator's
//! key-agreement key (§6.5.4 "getKeyAgreement", §6.5.6 `initialize()` / `getPublicKey()` /
//! `decapsulate()`).
//!
//! | Operation | Protocol 1 (§6.5.6) | Protocol 2 (§6.5.7) |
//! | --- | --- | --- |
//! | `kdf(Z)` | `SHA-256(Z)` (32 bytes) | `HKDF-SHA-256(salt = 32 zero bytes, Z, "CTAP2 HMAC key", 32) \|\| HKDF-SHA-256(salt, Z, "CTAP2 AES key", 32)` (64 bytes) |
//! | `encrypt` | AES-256-CBC, all-zero IV | random 16-byte IV, AES-256-CBC with the last 32 key bytes, `IV \|\| ct` |
//! | `decrypt` | ciphertext must be whole blocks | at least 16 bytes; IV, then whole blocks |
//! | `authenticate` | `LEFT(HMAC-SHA-256(key, m), 16)` | `HMAC-SHA-256(key[..32], m)` |
//!
//! `Z` is the X coordinate of the ECDH product on P-256 (§6.5.6 `ecdh()`).

use lk_codec::cbor::{MapBuilder, Value};
use lk_core::Entropy;
use lk_crypto::{
    Curve, EcPrivateKey, aes_cbc_decrypt, aes_cbc_encrypt, ct_eq, ec_public_is_valid, hkdf_sha256,
    hmac_sha256, sha256,
};

use crate::request::CtapResult;
use crate::status;

/// AES block / protocol 2 IV length.
const BLOCK: usize = 16;
/// HKDF salt of protocol 2: "a 32-byte array of zeros" (§6.5.7 `kdf()`).
const HKDF_SALT: [u8; 32] = [0; 32];
const HMAC_KEY_INFO: &[u8] = b"CTAP2 HMAC key";
const AES_KEY_INFO: &[u8] = b"CTAP2 AES key";
/// COSE algorithm of the key-agreement key: ECDH-ES + HKDF-256 (§6.5.6 `getPublicKey()`).
const COSE_ALG_ECDH_ES_HKDF_256: i64 = -25;

/// A supported pinUvAuthProtocol (GetInfo `pinUvAuthProtocols [2, 1]`, §6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinProtocol {
    One,
    Two,
}

impl PinProtocol {
    /// The protocol for a pinUvAuthProtocol parameter value, if supported.
    pub(crate) fn from_u64(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::One),
            2 => Some(Self::Two),
            _ => None,
        }
    }

    /// `kdf(Z)`: the shared secret (§6.5.6 / §6.5.7).
    pub(crate) fn kdf(self, z: &[u8]) -> CtapResult<Vec<u8>> {
        match self {
            Self::One => Ok(sha256(z).to_vec()),
            Self::Two => {
                let mut secret = hkdf_sha256(Some(&HKDF_SALT), z, HMAC_KEY_INFO, 32)
                    .map_err(|_| status::OTHER)?;
                secret.extend_from_slice(
                    &hkdf_sha256(Some(&HKDF_SALT), z, AES_KEY_INFO, 32)
                        .map_err(|_| status::OTHER)?,
                );
                Ok(secret)
            }
        }
    }

    /// The AES key inside a shared secret: all of it for protocol 1, the last 32 bytes for
    /// protocol 2 ("Discard the first 32 bytes of key", §6.5.7 `encrypt()`).
    fn aes_key(self, key: &[u8]) -> Option<&[u8]> {
        match self {
            Self::One => Some(key),
            Self::Two => key.get(32..),
        }
    }

    /// `encrypt(key, demPlaintext)`; `plaintext` is a whole number of blocks.
    pub(crate) fn encrypt(
        self,
        key: &[u8],
        plaintext: &[u8],
        entropy: &mut dyn Entropy,
    ) -> CtapResult<Vec<u8>> {
        let aes_key = self.aes_key(key).ok_or(status::OTHER)?;
        match self {
            Self::One => {
                aes_cbc_encrypt(aes_key, &[0; BLOCK], plaintext).map_err(|_| status::OTHER)
            }
            Self::Two => {
                let mut iv = [0u8; BLOCK];
                entropy.fill(&mut iv);
                let ct = aes_cbc_encrypt(aes_key, &iv, plaintext).map_err(|_| status::OTHER)?;
                let mut out = iv.to_vec();
                out.extend_from_slice(&ct);
                Ok(out)
            }
        }
    }

    /// `decrypt(key, demCiphertext)`; `None` for the protocol's error cases (not whole
    /// blocks; for protocol 2 also shorter than one IV).
    pub(crate) fn decrypt(self, key: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        let aes_key = self.aes_key(key)?;
        match self {
            Self::One => aes_cbc_decrypt(aes_key, &[0; BLOCK], ciphertext).ok(),
            Self::Two => {
                let iv = ciphertext.get(..BLOCK)?;
                let ct = ciphertext.get(BLOCK..)?;
                aes_cbc_decrypt(aes_key, iv, ct).ok()
            }
        }
    }

    /// `authenticate(key, message)`. For protocol 2 a key longer than 32 bytes (a shared
    /// secret) is cut to its HMAC half; a 32-byte pinUvAuthToken is used whole (§6.5.7).
    pub(crate) fn authenticate(self, key: &[u8], message: &[u8]) -> Vec<u8> {
        match self {
            Self::One => hmac_sha256(key, message)[..16].to_vec(),
            Self::Two => hmac_sha256(key.get(..32).unwrap_or(key), message).to_vec(),
        }
    }

    /// `verify(key, message, signature)`, compared in constant time (`lk_crypto::ct_eq`).
    pub(crate) fn verify(self, key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        ct_eq(&self.authenticate(key, message), signature)
    }
}

/// The authenticator's P-256 key-agreement key for one protocol (§6.5.6 `initialize()`).
pub(crate) struct KeyAgreement {
    key: EcPrivateKey,
}

impl core::fmt::Debug for KeyAgreement {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyAgreement").finish_non_exhaustive()
    }
}

impl KeyAgreement {
    /// "Generate a fresh, random P-256 private key" (§6.5.6 `initialize()`).
    pub(crate) fn generate(entropy: &mut dyn Entropy) -> Self {
        Self {
            key: EcPrivateKey::generate(Curve::P256, entropy),
        }
    }

    /// `getPublicKey()`: COSE_Key `{1: 2, 3: -25, -1: 1, -2: x, -3: y}` (§6.5.6; RFC 9053
    /// §7.1.1).
    pub(crate) fn cose_public(&self) -> Value {
        let point = self.key.public_uncompressed();
        MapBuilder::new()
            .insert(1, 2)
            .insert(3, COSE_ALG_ECDH_ES_HKDF_256)
            .insert(-1, 1)
            .insert(-2, point.get(1..33).unwrap_or_default().to_vec())
            .insert(-3, point.get(33..65).unwrap_or_default().to_vec())
            .build()
    }

    /// `decapsulate(peerCoseKey)`: parse the platform's COSE_Key, check the point is on
    /// P-256, compute ECDH and `kdf(Z)` (§6.5.6). The key must have `kty` 2 (EC2), `crv` 1
    /// (P-256) and 32-byte `x` and `y`; `alg` is not checked. Any failure is
    /// `CTAP1_ERR_INVALID_PARAMETER` ("If an error results, ... return
    /// CTAP1_ERR_INVALID_PARAMETER", §6.5.5.5 and the other subcommands).
    pub(crate) fn decapsulate(
        &self,
        protocol: PinProtocol,
        peer: &[(Value, Value)],
    ) -> CtapResult<Vec<u8>> {
        let get = |key: i64| {
            peer.iter()
                .find_map(|(k, v)| (*k == Value::int_key(key)).then_some(v))
        };
        let kty = get(1).and_then(Value::as_i64);
        let crv = get(-1).and_then(Value::as_i64);
        let x = get(-2).and_then(Value::as_bytes);
        let y = get(-3).and_then(Value::as_bytes);
        let (Some(2), Some(1), Some(x), Some(y)) = (kty, crv, x, y) else {
            return Err(status::INVALID_PARAMETER);
        };
        if x.len() != 32 || y.len() != 32 {
            return Err(status::INVALID_PARAMETER);
        }
        let mut point = Vec::with_capacity(65);
        point.push(0x04);
        point.extend_from_slice(x);
        point.extend_from_slice(y);
        if !ec_public_is_valid(Curve::P256, &point) {
            return Err(status::INVALID_PARAMETER);
        }
        let z = self
            .key
            .ecdh(&point)
            .map_err(|_| status::INVALID_PARAMETER)?;
        protocol.kdf(&z)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use lk_testkit::SeededEntropy;

    #[test]
    fn protocol_two_kdf_matches_rfc_5869_with_zero_salt() {
        // §6.5.7 kdf(): HKDF-SHA-256 with a 32-byte zero salt equals RFC 5869 §2.2 with the
        // salt "not provided" (a HashLen string of zeros), so both lk-crypto spellings agree.
        let z = [0x11u8; 32];
        let secret = PinProtocol::Two.kdf(&z).unwrap();
        assert_eq!(secret.len(), 64);
        assert_eq!(
            &secret[..32],
            &hkdf_sha256(None, &z, b"CTAP2 HMAC key", 32).unwrap()[..]
        );
        assert_eq!(
            &secret[32..],
            &hkdf_sha256(None, &z, b"CTAP2 AES key", 32).unwrap()[..]
        );
        assert_eq!(PinProtocol::One.kdf(&z).unwrap(), sha256(&z).to_vec());
    }

    #[test]
    fn decrypt_error_cases_and_round_trip() {
        // §6.5.6 decrypt(): not a multiple of the block size is an error; §6.5.7: shorter
        // than 16 bytes is an error.
        let mut rng = SeededEntropy::new(9);
        let k1 = [1u8; 32];
        let k2 = [2u8; 64];
        assert!(PinProtocol::One.decrypt(&k1, &[0; 15]).is_none());
        assert!(PinProtocol::Two.decrypt(&k2, &[0; 15]).is_none());
        assert!(PinProtocol::Two.decrypt(&k2, &[0; 33]).is_none());
        assert_eq!(PinProtocol::Two.decrypt(&k2, &[0; 16]), Some(vec![]));
        for (p, k) in [(PinProtocol::One, &k1[..]), (PinProtocol::Two, &k2[..])] {
            let ct = p.encrypt(k, &[7; 32], &mut rng).unwrap();
            assert_eq!(p.decrypt(k, &ct), Some(vec![7; 32]));
        }
        assert_eq!(PinProtocol::One.authenticate(&k1, b"m").len(), 16);
        assert_eq!(PinProtocol::Two.authenticate(&k2, b"m").len(), 32);
        assert_eq!(
            PinProtocol::Two.authenticate(&k2, b"m"),
            hmac_sha256(&k2[..32], b"m").to_vec()
        );
        assert!(!PinProtocol::Two.verify(&k2, b"m", &[0; 32]));
    }

    #[test]
    fn decapsulate_rejects_malformed_and_off_curve_keys() {
        let mut rng = SeededEntropy::new(10);
        let ka = KeyAgreement::generate(&mut rng);
        let good = ka.cose_public();
        let entries = good.as_map().unwrap();
        assert!(ka.decapsulate(PinProtocol::Two, entries).is_ok());
        let edit = |key: i64, value: Value| {
            let mut e: Vec<(Value, Value)> = entries.to_vec();
            for (k, v) in &mut e {
                if *k == Value::int_key(key) {
                    *v = value.clone();
                }
            }
            e
        };
        for bad in [
            edit(1, Value::from(1u8)),
            edit(-1, Value::from(2u8)),
            edit(-2, Value::Bytes(vec![0; 31])),
            edit(-3, Value::Bytes(vec![0; 32])),
            edit(-2, Value::from("x")),
        ] {
            assert_eq!(
                ka.decapsulate(PinProtocol::One, &bad),
                Err(status::INVALID_PARAMETER)
            );
        }
        assert_eq!(
            ka.decapsulate(PinProtocol::One, &[]),
            Err(status::INVALID_PARAMETER)
        );
    }
}
