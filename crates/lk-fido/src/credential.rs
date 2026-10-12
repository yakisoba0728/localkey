//! Credential key pairs, their COSE public keys, signatures, and the wrapped credential ID.
//!
//! # Credential ID format (model policy)
//!
//! Every credential ID this authenticator issues, discoverable or not, and every U2F key
//! handle, is the credential's private key sealed with AES-256-GCM and bound to the
//! RP ID hash (`reference/legacy-v0.64-profiles.json` `nonresident_model`: "independent
//! AES-256-GCM opaque ID; RP hash authenticated", 128 bytes):
//!
//! ```text
//! id      = 0x01 || nonce (12) || AES-256-GCM(wrapKey, nonce, aad, payload) (99 + 16)  = 128 bytes
//! aad     = 0x01 || rpIdHash (32)
//! wrapKey = HKDF-SHA-256(salt = none, ikm = device wrapping secret, info = WRAP_INFO, 32)
//! payload = alg (1) || credProtect (1) || flags (1) || key material (48, zero padded)
//!           || credRandom (32) || reserved (16, zero)
//! flags   = 0x01 discoverable | 0x02 created with "hmac-secret": true
//! ```
//!
//! - The length is constant (GetInfo `maxCredentialIdLength` 128, CTAP 2.1 §6.4), so the
//!   ID reveals neither the algorithm nor whether the credential is discoverable.
//! - `rpIdHash` in the AAD makes an ID unusable for any other RP (CTAP 2.1 §6.2.2 step 7:
//!   credentials "bound to the specified rpId"); for U2F the application parameter plays
//!   that role (U2F raw message formats v1.2 §5.3 "bad key handle"), so U2F key handles
//!   and CTAP non-discoverable credential IDs are interchangeable.
//! - `credRandom` is generated with every credential. The two hmac-secret values of
//!   CTAP 2.1 §12.5, CredRandomWithUV and CredRandomWithoutUV, are derived from it
//!   ([`CredSecret::hmac_secret_key`]); they are used only for credentials created with
//!   the extension (flag `0x02`), as only those have CredRandom values associated (§12.5
//!   "authenticatorMakeCredential additional behaviors").
//! - Non-discoverable registration therefore stores nothing on the device
//!   (`reference/BEHAVIOR_CATALOG.md` FIDO: "initialized store remains constant across
//!   ... nonresident registrations").
//! - The wrapping key, the plaintext payload (it holds the private key), credRandom and
//!   the derived hmac-secret keys are held in [`SecretBytes`] and wiped when dropped.

use lk_codec::cbor::{MapBuilder, Value};
use lk_core::Entropy;
use lk_crypto::{
    Curve, EcPrivateKey, Ed25519Key, HashAlg, SecretBytes, aes_gcm_open, aes_gcm_seal, hkdf_sha256,
    hmac_sha256,
};

use crate::pin_protocol::secret_from;
use crate::request::CtapResult;
use crate::status;

/// Total credential ID length.
pub(crate) const ID_LEN: usize = 128;
const ID_VERSION: u8 = 0x01;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const PAYLOAD_LEN: usize = ID_LEN - 1 - NONCE_LEN - TAG_LEN;
const KEY_MATERIAL_LEN: usize = 48;
const OFFSET_KEY: usize = 3;
const OFFSET_RANDOM: usize = OFFSET_KEY + KEY_MATERIAL_LEN;
const RANDOM_LEN: usize = 32;
const FLAG_DISCOVERABLE: u8 = 0x01;
const FLAG_HMAC_SECRET: u8 = 0x02;
const WRAP_INFO: &[u8] = b"localkey fido credential wrapping v1";
/// Derivation labels for the two hmac-secret CredRandom values (model policy).
const CRED_RANDOM_WITH_UV: &[u8] = b"localkey hmac-secret CredRandomWithUV";
const CRED_RANDOM_WITHOUT_UV: &[u8] = b"localkey hmac-secret CredRandomWithoutUV";

/// The signature algorithms this authenticator supports, in GetInfo `algorithms` order
/// (CTAP 2.1 §6.4; `reference/physical-key/reference-observation.json`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Alg {
    /// ES256: ECDSA on P-256 with SHA-256, COSE -7 (RFC 9053 §2.1).
    Es256,
    /// EdDSA with Ed25519, COSE -8 (RFC 9053 §2.2).
    EdDsa,
    /// ES384: ECDSA on P-384 with SHA-384, COSE -35 (RFC 9053 §2.1).
    Es384,
}

impl Alg {
    pub(crate) const ALL: [Alg; 3] = [Alg::Es256, Alg::EdDsa, Alg::Es384];

    /// COSE algorithm identifier (IANA COSE Algorithms registry).
    pub(crate) const fn cose(self) -> i64 {
        match self {
            Alg::Es256 => -7,
            Alg::EdDsa => -8,
            Alg::Es384 => -35,
        }
    }

    pub(crate) fn from_cose(alg: i64) -> Option<Alg> {
        Alg::ALL.into_iter().find(|a| a.cose() == alg)
    }

    const fn code(self) -> u8 {
        match self {
            Alg::Es256 => 1,
            Alg::EdDsa => 2,
            Alg::Es384 => 3,
        }
    }

    fn from_code(code: u8) -> Option<Alg> {
        Alg::ALL.into_iter().find(|a| a.code() == code)
    }
}

enum Key {
    Ec(EcPrivateKey),
    Ed(Ed25519Key),
}

/// A credential's secret material, as carried inside its ID.
pub(crate) struct CredSecret {
    alg: Alg,
    key: Key,
    /// credProtect level 1..=3 (CTAP 2.1 §12.1).
    pub cred_protect: u8,
    /// Whether the credential is discoverable (stored on the device).
    pub discoverable: bool,
    /// Whether the credential was created with `"hmac-secret": true` (CTAP 2.1 §12.5).
    pub hmac_secret: bool,
    /// Seed for the hmac-secret CredRandom values (CTAP 2.1 §12.5), 32 bytes.
    cred_random: SecretBytes,
}

impl core::fmt::Debug for CredSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CredSecret")
            .field("alg", &self.alg)
            .field("cred_protect", &self.cred_protect)
            .field("discoverable", &self.discoverable)
            .field("hmac_secret", &self.hmac_secret)
            .finish_non_exhaustive()
    }
}

impl CredSecret {
    /// A new key pair for `alg` (CTAP 2.1 §6.1.2 step 16) with a fresh credRandom.
    pub(crate) fn generate(
        alg: Alg,
        cred_protect: u8,
        discoverable: bool,
        entropy: &mut dyn Entropy,
    ) -> Self {
        let key = match alg {
            Alg::Es256 => Key::Ec(EcPrivateKey::generate(Curve::P256, entropy)),
            Alg::Es384 => Key::Ec(EcPrivateKey::generate(Curve::P384, entropy)),
            Alg::EdDsa => Key::Ed(Ed25519Key::generate(entropy)),
        };
        let mut cred_random = SecretBytes::zeroed(RANDOM_LEN);
        entropy.fill(&mut cred_random);
        Self {
            alg,
            key,
            cred_protect,
            discoverable,
            hmac_secret: false,
            cred_random,
        }
    }

    pub(crate) fn alg(&self) -> Alg {
        self.alg
    }

    /// CredRandomWithUV or CredRandomWithoutUV (CTAP 2.1 §12.5): two independent 32-byte
    /// values derived from the credential's credRandom with HMAC-SHA-256 under distinct
    /// labels, so the output with UV never equals the output without it.
    pub(crate) fn hmac_secret_key(&self, uv: bool) -> SecretBytes {
        let label = if uv {
            CRED_RANDOM_WITH_UV
        } else {
            CRED_RANDOM_WITHOUT_UV
        };
        secret_from(hmac_sha256(&self.cred_random, label))
    }

    /// The credential public key as a COSE_Key (RFC 9052 §7, RFC 9053 §7; CTAP 2.1 §6.1
    /// "credentialPublicKey"; WebAuthn L2 §6.5.1.1 examples):
    /// - ES256 `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`;
    /// - ES384 `{1: 2, 3: -35, -1: 2, -2: x, -3: y}`;
    /// - EdDSA `{1: 1, 3: -8, -1: 6, -2: x}`.
    pub(crate) fn cose_public_key(&self) -> Value {
        match &self.key {
            Key::Ec(key) => {
                let point = key.public_uncompressed();
                let len = key.curve().field_len();
                let x = point.get(1..1 + len).unwrap_or_default().to_vec();
                let y = point.get(1 + len..).unwrap_or_default().to_vec();
                let crv = if key.curve() == Curve::P256 { 1 } else { 2 };
                MapBuilder::new()
                    .insert(1, 2)
                    .insert(3, self.alg.cose())
                    .insert(-1, crv)
                    .insert(-2, x)
                    .insert(-3, y)
                    .build()
            }
            Key::Ed(key) => MapBuilder::new()
                .insert(1, 1)
                .insert(3, self.alg.cose())
                .insert(-1, 6)
                .insert(-2, key.public().to_vec())
                .build(),
        }
    }

    /// The uncompressed P-256 public point for U2F (U2F raw message formats v1.2 §4.3);
    /// `None` for other algorithms, which U2F cannot express.
    pub(crate) fn u2f_public_key(&self) -> Option<Vec<u8>> {
        match &self.key {
            Key::Ec(key) if self.alg == Alg::Es256 => Some(key.public_uncompressed()),
            _ => None,
        }
    }

    /// Sign `message` (WebAuthn L2 §6.3.3: `authenticatorData || clientDataHash`).
    ///
    /// ECDSA uses the hedged RFC 6979 §3.6 nonce with host entropy (`docs/CONTRACTS.md`,
    /// "Phase 0 as implemented") and is DER encoded (WebAuthn L2 §6.5.5); Ed25519 is the raw
    /// 64-byte RFC 8032 signature.
    pub(crate) fn sign(&self, message: &[u8], entropy: &mut dyn Entropy) -> CtapResult<Vec<u8>> {
        match &self.key {
            Key::Ec(key) => {
                let hash = if self.alg == Alg::Es384 {
                    HashAlg::Sha384
                } else {
                    HashAlg::Sha256
                };
                key.sign_message_hedged(hash, message, entropy)
                    .map(|sig| sig.to_der())
                    .map_err(|_| status::OTHER)
            }
            Key::Ed(key) => Ok(key.sign(message).to_vec()),
        }
    }

    /// Seal into a credential ID bound to `rp_id_hash` (see the module documentation).
    pub(crate) fn wrap(
        &self,
        secret: &[u8],
        rp_id_hash: &[u8; 32],
        entropy: &mut dyn Entropy,
    ) -> CtapResult<Vec<u8>> {
        let mut payload = SecretBytes::zeroed(PAYLOAD_LEN);
        payload[0] = self.alg.code();
        payload[1] = self.cred_protect;
        payload[2] = (if self.discoverable {
            FLAG_DISCOVERABLE
        } else {
            0
        }) | (if self.hmac_secret {
            FLAG_HMAC_SECRET
        } else {
            0
        });
        let material: &[u8] = match &self.key {
            Key::Ec(key) => key.scalar(),
            Key::Ed(key) => key.seed(),
        };
        let key_slot = payload
            .get_mut(OFFSET_KEY..OFFSET_KEY + material.len())
            .ok_or(status::OTHER)?;
        key_slot.copy_from_slice(material);
        payload[OFFSET_RANDOM..OFFSET_RANDOM + RANDOM_LEN].copy_from_slice(&self.cred_random);
        let mut nonce = [0u8; NONCE_LEN];
        entropy.fill(&mut nonce);
        let sealed = aes_gcm_seal(&wrap_key(secret)?, &nonce, &aad(rp_id_hash), &payload)
            .map_err(|_| status::OTHER)?;
        let mut id = Vec::with_capacity(ID_LEN);
        id.push(ID_VERSION);
        id.extend_from_slice(&nonce);
        id.extend_from_slice(&sealed);
        Ok(id)
    }

    /// Open a credential ID issued by this authenticator for `rp_id_hash`; `None` for any
    /// other ID (wrong length, other RP, other device secret, tampered).
    pub(crate) fn unwrap(id: &[u8], secret: &[u8], rp_id_hash: &[u8; 32]) -> Option<CredSecret> {
        if id.len() != ID_LEN || id.first() != Some(&ID_VERSION) {
            return None;
        }
        let nonce = id.get(1..1 + NONCE_LEN)?;
        let sealed = id.get(1 + NONCE_LEN..)?;
        let payload = SecretBytes::new(
            aes_gcm_open(&wrap_key(secret).ok()?, nonce, &aad(rp_id_hash), sealed).ok()?,
        );
        let alg = Alg::from_code(*payload.first()?)?;
        let cred_protect = *payload.get(1)?;
        if !(1..=3).contains(&cred_protect) {
            return None;
        }
        let flags = *payload.get(2)?;
        let discoverable = flags & FLAG_DISCOVERABLE != 0;
        let hmac_secret = flags & FLAG_HMAC_SECRET != 0;
        let material = payload.get(OFFSET_KEY..OFFSET_KEY + KEY_MATERIAL_LEN)?;
        let key = match alg {
            Alg::Es256 => {
                Key::Ec(EcPrivateKey::from_scalar(Curve::P256, material.get(..32)?).ok()?)
            }
            Alg::Es384 => Key::Ec(EcPrivateKey::from_scalar(Curve::P384, material).ok()?),
            Alg::EdDsa => Key::Ed(Ed25519Key::from_seed(material.get(..32)?).ok()?),
        };
        let cred_random =
            SecretBytes::from_slice(payload.get(OFFSET_RANDOM..OFFSET_RANDOM + RANDOM_LEN)?);
        Some(CredSecret {
            alg,
            key,
            cred_protect,
            discoverable,
            hmac_secret,
            cred_random,
        })
    }
}

fn wrap_key(secret: &[u8]) -> CtapResult<SecretBytes> {
    hkdf_sha256(None, secret, WRAP_INFO, 32)
        .map(SecretBytes::new)
        .map_err(|_| status::OTHER)
}

fn aad(rp_id_hash: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(33);
    aad.push(ID_VERSION);
    aad.extend_from_slice(rp_id_hash);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use lk_crypto::{ecdsa_verify_prehash, ed25519_verify, sha256, sha384};
    use lk_testkit::SeededEntropy;

    #[test]
    fn ids_are_128_bytes_and_bound_to_rp_and_secret() {
        let mut rng = SeededEntropy::new(1);
        let secret = [7u8; 32];
        let rp = sha256(b"example.com");
        for alg in Alg::ALL {
            let cred = CredSecret::generate(alg, 2, true, &mut rng);
            let id = cred.wrap(&secret, &rp, &mut rng).expect("wrap");
            assert_eq!(id.len(), ID_LEN);
            let back = CredSecret::unwrap(&id, &secret, &rp).expect("unwrap");
            assert_eq!(back.alg(), alg);
            assert_eq!(back.cred_protect, 2);
            assert!(back.discoverable);
            assert!(!back.hmac_secret);
            assert_eq!(back.hmac_secret_key(true), cred.hmac_secret_key(true));
            assert_ne!(back.hmac_secret_key(true), back.hmac_secret_key(false));
            assert_eq!(back.cose_public_key(), cred.cose_public_key());
            assert!(CredSecret::unwrap(&id, &secret, &sha256(b"other.example")).is_none());
            assert!(CredSecret::unwrap(&id, &[8u8; 32], &rp).is_none());
            let mut tampered = id.clone();
            tampered[60] ^= 1;
            assert!(CredSecret::unwrap(&tampered, &secret, &rp).is_none());
            assert!(CredSecret::unwrap(&id[..127], &secret, &rp).is_none());
        }
    }

    #[test]
    fn hmac_secret_flag_round_trips() {
        let mut rng = SeededEntropy::new(3);
        let secret = [7u8; 32];
        let rp = sha256(b"example.com");
        let mut cred = CredSecret::generate(Alg::Es256, 1, false, &mut rng);
        cred.hmac_secret = true;
        let id = cred.wrap(&secret, &rp, &mut rng).expect("wrap");
        let back = CredSecret::unwrap(&id, &secret, &rp).expect("unwrap");
        assert!(back.hmac_secret && !back.discoverable);
    }

    #[test]
    fn signatures_verify_for_every_algorithm() {
        // Verification with lk-crypto's independent verifiers (FIPS 186-5 §6.4.2, RFC 8032 §5.1.7).
        let mut rng = SeededEntropy::new(2);
        let msg = b"authData || clientDataHash";
        for alg in Alg::ALL {
            let cred = CredSecret::generate(alg, 1, false, &mut rng);
            let sig = cred.sign(msg, &mut rng).expect("sign");
            let cose = cred.cose_public_key();
            let x = cose
                .map_get_int(-2)
                .and_then(Value::as_bytes)
                .expect("x")
                .to_vec();
            match alg {
                Alg::EdDsa => assert!(ed25519_verify(&x, msg, &sig)),
                Alg::Es256 | Alg::Es384 => {
                    let y = cose.map_get_int(-3).and_then(Value::as_bytes).expect("y");
                    let point = [&[4u8][..], &x, y].concat();
                    let (curve, digest) = if alg == Alg::Es256 {
                        (Curve::P256, sha256(msg).to_vec())
                    } else {
                        (Curve::P384, sha384(msg).to_vec())
                    };
                    assert!(ecdsa_verify_prehash(curve, &point, &digest, &sig));
                }
            }
        }
    }
}
