//! Key slot algorithms, stored key material and the cryptographic operations on keys.
//!
//! References:
//! - OpenPGP Smart Card Application Functional Specification 3.4.1 ("spec") §4.4.3.10
//!   (algorithm attributes), §4.4.3.12 (private key template / extended header list for
//!   key import), §7.2.10 (PSO:COMPUTE DIGITAL SIGNATURE), §7.2.11 (PSO:DECIPHER),
//!   §7.2.13 (INTERNAL AUTHENTICATE), §7.2.14 (GENERATE ASYMMETRIC KEY PAIR and the public
//!   key DO 7F49).
//! - RFC 8017 §9.2 (EMSA-PKCS1-v1_5 encoding for signatures) and §7.2.2 (RSAES-PKCS1-v1_5
//!   decryption).
//! - FIPS 186-5 / SEC 1 (ECDSA and ECDH on the prime curves: NIST P-256/P-384/P-521, SEC 2
//!   secp256k1, RFC 5639 brainpoolP256r1/P384r1), RFC 8032 (Ed25519), RFC 7748 (X25519).
//! - RFC 9580 §5.5.5.6.1.1: the legacy Curve25519 ECDH secret is an MPI whose octets are the
//!   native little-endian X25519 scalar reversed. Hosts (GnuPG, YubiKit) import it in that
//!   big-endian form, so import reverses it; the public key DO and cipher DOs use the
//!   native 32-byte encoding.
//!
//! Only primitives of `lk_crypto` are used. It implements every prime curve of the
//! algorithm information FA except brainpoolP512r1 (no RustCrypto crate exists for it, see
//! lk-crypto's `ec` module); for that curve generation and import answer `6A81` (function
//! not supported) while its attributes stay selectable (FA parity). Key widths follow
//! spec §4.4.3.12 and the catalog ("standard EC ... import widths; 66-byte zero-padded
//! P521"): an ECC private key is exactly the field length (32, 48 or 66 bytes) and the
//! public key the uncompressed point.

use core::fmt;

use lk_codec::apdu::sw;
use lk_codec::tlv;
use lk_codec::x509::PublicKey;
use lk_core::Entropy;
use lk_crypto::{Curve, EcPrivateKey, Ed25519Key, RsaPrivateKey, X25519Key};

use crate::objects::Slot;

/// DER prefix of a SHA-256 `DigestInfo` (RFC 8017 §9.2, note 1).
pub(crate) const DIGEST_INFO_SHA256: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Minimum PKCS #1 v1.5 padding overhead: `00 01|02`, eight padding octets, `00`
/// (RFC 8017 §9.2 step 3, §7.2.1 step 1).
const PKCS1_OVERHEAD: usize = 11;

/// Largest ECDSA digest accepted (SHA-512). Longer input cannot be a hash the host computed
/// for a supported curve; FIPS 186-5 §6.4.1 uses shorter ones as integers (every digest up
/// to 64 bytes fits P-521's 521-bit order without truncation).
const MAX_ECDSA_DIGEST: usize = 64;

/// The named curves of the algorithm information FA (OIDs as DER content octets, X.690
/// §8.19), in device order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NamedCurve {
    P256,
    P384,
    P521,
    Secp256k1,
    BrainpoolP256r1,
    BrainpoolP384r1,
    BrainpoolP512r1,
}

impl NamedCurve {
    const TABLE: [(NamedCurve, &'static [u8]); 7] = [
        // 1.2.840.10045.3.1.7 (RFC 5480 §2.1.1.1)
        (NamedCurve::P256, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
        // 1.3.132.0.34
        (NamedCurve::P384, &[0x2b, 0x81, 0x04, 0x00, 0x22]),
        // 1.3.132.0.35
        (NamedCurve::P521, &[0x2b, 0x81, 0x04, 0x00, 0x23]),
        // 1.3.132.0.10 (SEC 2 §2.4.1)
        (NamedCurve::Secp256k1, &[0x2b, 0x81, 0x04, 0x00, 0x0a]),
        // 1.3.36.3.3.2.8.1.1.7 / .11 / .13 (RFC 5639 §4.1)
        (NamedCurve::BrainpoolP256r1, &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07]),
        (NamedCurve::BrainpoolP384r1, &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b]),
        (NamedCurve::BrainpoolP512r1, &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d]),
    ];

    fn from_oid(oid: &[u8]) -> Option<Self> {
        Self::TABLE.iter().find(|(_, o)| *o == oid).map(|(c, _)| *c)
    }

    /// The lk-crypto curve, if lk-crypto implements it (all but brainpoolP512r1).
    pub(crate) fn engine_curve(self) -> Option<Curve> {
        match self {
            NamedCurve::P256 => Some(Curve::P256),
            NamedCurve::P384 => Some(Curve::P384),
            NamedCurve::P521 => Some(Curve::P521),
            NamedCurve::Secp256k1 => Some(Curve::Secp256k1),
            NamedCurve::BrainpoolP256r1 => Some(Curve::BrainpoolP256r1),
            NamedCurve::BrainpoolP384r1 => Some(Curve::BrainpoolP384r1),
            NamedCurve::BrainpoolP512r1 => None,
        }
    }
}

/// Ed25519 OID 1.3.6.1.4.1.11591.15.1 (spec §4.4.3.10 table "EdDSA").
const OID_ED25519: [u8; 9] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01];
/// Curve25519 for ECDH, OID 1.3.6.1.4.1.3029.1.5.1 (spec §4.4.3.10 table "ECDH").
const OID_X25519: [u8; 10] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];

/// The algorithm a slot's attributes name (spec §4.4.3.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Algorithm {
    /// Algorithm ID 01: modulus and public exponent lengths in bits.
    Rsa { bits: u16, e_bits: u16 },
    /// Algorithm ID 13.
    Ecdsa(NamedCurve),
    /// Algorithm ID 12 on a prime curve.
    Ecdh(NamedCurve),
    /// Algorithm ID 16 with the Ed25519 OID.
    Ed25519,
    /// Algorithm ID 12 with the Curve25519 OID.
    X25519,
}

impl Algorithm {
    /// Decode algorithm attributes. ECC attributes may end with the import-format byte
    /// `FF`; it cannot be confused with the OID, whose last octet always has bit 8 clear
    /// (X.690 §8.19.2).
    pub(crate) fn from_attributes(attributes: &[u8]) -> Option<Self> {
        let (&id, rest) = attributes.split_first()?;
        match id {
            0x01 => {
                let [b0, b1, e0, e1, _format]: [u8; 5] = rest.try_into().ok()?;
                Some(Algorithm::Rsa {
                    bits: u16::from_be_bytes([b0, b1]),
                    e_bits: u16::from_be_bytes([e0, e1]),
                })
            }
            0x12 | 0x13 | 0x16 => {
                let oid = rest.strip_suffix(&[0xFF]).unwrap_or(rest);
                match (id, oid) {
                    (0x16, o) if o == OID_ED25519 => Some(Algorithm::Ed25519),
                    (0x12, o) if o == OID_X25519 => Some(Algorithm::X25519),
                    (0x12, o) => NamedCurve::from_oid(o).map(Algorithm::Ecdh),
                    (0x13, o) => NamedCurve::from_oid(o).map(Algorithm::Ecdsa),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// Whether the engine can hold a key of this algorithm (lk-crypto implements it).
    pub(crate) fn supported(self) -> bool {
        match self {
            Algorithm::Rsa { bits, .. } => matches!(bits, 2048 | 3072 | 4096),
            Algorithm::Ecdsa(curve) | Algorithm::Ecdh(curve) => curve.engine_curve().is_some(),
            Algorithm::Ed25519 | Algorithm::X25519 => true,
        }
    }

    /// Signature algorithms: PSO:CDS and INTERNAL AUTHENTICATE (spec §7.2.10, §7.2.13).
    pub(crate) fn can_sign(self) -> bool {
        matches!(self, Algorithm::Rsa { .. } | Algorithm::Ecdsa(_) | Algorithm::Ed25519)
    }

    /// Decryption / key agreement algorithms: PSO:DECIPHER (spec §7.2.11).
    pub(crate) fn can_decipher(self) -> bool {
        matches!(self, Algorithm::Rsa { .. } | Algorithm::Ecdh(_) | Algorithm::X25519)
    }

    /// Length of a signature (spec §7.2.10: RSA modulus length; ECDSA `r || s`, each the
    /// field length; EdDSA `R || S`, 64 bytes).
    pub(crate) fn signature_len(self) -> Option<usize> {
        match self {
            Algorithm::Rsa { bits, .. } => Some(usize::from(bits) / 8),
            Algorithm::Ecdsa(curve) => curve.engine_curve().map(|c| 2 * c.field_len()),
            Algorithm::Ed25519 => Some(64),
            Algorithm::Ecdh(_) | Algorithm::X25519 => None,
        }
    }
}

/// Private key material as stored, in plain bytes so that [`crate::state::State`] stays
/// `Clone + Eq`; lk-crypto key objects are rebuilt for each operation.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum KeyMaterial {
    /// Primes and public exponent, big-endian without leading zeros.
    Rsa { p: Vec<u8>, q: Vec<u8>, e: Vec<u8> },
    /// Scalar of exactly the field length.
    Ec { curve: Curve, scalar: Vec<u8> },
    /// RFC 8032 32-byte seed.
    Ed25519 { seed: Vec<u8> },
    /// RFC 7748 32-byte scalar in native (little-endian) order.
    X25519 { secret: Vec<u8> },
}

impl fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            KeyMaterial::Rsa { .. } => "Rsa",
            KeyMaterial::Ec { .. } => "Ec",
            KeyMaterial::Ed25519 { .. } => "Ed25519",
            KeyMaterial::X25519 { .. } => "X25519",
        };
        write!(f, "KeyMaterial::{kind}(<redacted>)")
    }
}

impl Drop for KeyMaterial {
    /// Best-effort wipe of secret bytes (lk-crypto's own keys use `zeroize`; this crate may
    /// not depend on it, docs/DESIGN.md §8).
    fn drop(&mut self) {
        let wipe = |part: &mut Vec<u8>| part.iter_mut().for_each(|b| *b = 0);
        match self {
            KeyMaterial::Rsa { p, q, .. } => {
                wipe(p);
                wipe(q);
            }
            KeyMaterial::Ec { scalar, .. } => wipe(scalar),
            KeyMaterial::Ed25519 { seed } => wipe(seed),
            KeyMaterial::X25519 { secret } => wipe(secret),
        }
    }
}

// Storage encoding of key material (inside the slot record, see state.rs):
// `80 01 kind` then `81` (p / scalar / seed / secret), `82` (q), `83` (e).
const KIND_RSA: u8 = 0x01;
const KIND_P256: u8 = 0x02;
const KIND_P384: u8 = 0x03;
const KIND_ED25519: u8 = 0x04;
const KIND_X25519: u8 = 0x05;
const KIND_P521: u8 = 0x06;
const KIND_SECP256K1: u8 = 0x07;
const KIND_BRAINPOOL_P256R1: u8 = 0x08;
const KIND_BRAINPOOL_P384R1: u8 = 0x09;
/// Storage kind of each EC curve.
const EC_KINDS: [(u8, Curve); 6] = [
    (KIND_P256, Curve::P256),
    (KIND_P384, Curve::P384),
    (KIND_P521, Curve::P521),
    (KIND_SECP256K1, Curve::Secp256k1),
    (KIND_BRAINPOOL_P256R1, Curve::BrainpoolP256r1),
    (KIND_BRAINPOOL_P384R1, Curve::BrainpoolP384r1),
];
/// Largest stored RSA component (a 4096-bit key's primes are 256 bytes).
const MAX_RSA_PART: usize = 512;

impl KeyMaterial {
    pub(crate) fn to_storage(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            KeyMaterial::Rsa { p, q, e } => {
                tlv::encode_into(&mut out, 0x80, &[KIND_RSA]);
                tlv::encode_into(&mut out, 0x81, p);
                tlv::encode_into(&mut out, 0x82, q);
                tlv::encode_into(&mut out, 0x83, e);
            }
            KeyMaterial::Ec { curve, scalar } => {
                let kind = match curve {
                    Curve::P256 => KIND_P256,
                    Curve::P384 => KIND_P384,
                    Curve::P521 => KIND_P521,
                    Curve::Secp256k1 => KIND_SECP256K1,
                    Curve::BrainpoolP256r1 => KIND_BRAINPOOL_P256R1,
                    Curve::BrainpoolP384r1 => KIND_BRAINPOOL_P384R1,
                };
                tlv::encode_into(&mut out, 0x80, &[kind]);
                tlv::encode_into(&mut out, 0x81, scalar);
            }
            KeyMaterial::Ed25519 { seed } => {
                tlv::encode_into(&mut out, 0x80, &[KIND_ED25519]);
                tlv::encode_into(&mut out, 0x81, seed);
            }
            KeyMaterial::X25519 { secret } => {
                tlv::encode_into(&mut out, 0x80, &[KIND_X25519]);
                tlv::encode_into(&mut out, 0x81, secret);
            }
        }
        out
    }

    /// Parse stored key material; structural problems make the whole state unreadable.
    /// Arithmetic validity (scalar range, prime consistency) is checked when the key is
    /// used ([`KeyMaterial::load`]).
    pub(crate) fn from_storage(bytes: &[u8]) -> Option<Self> {
        let fields = tlv::parse_all(bytes).ok()?;
        let get = |tag: u32| tlv::find(&fields, tag).map(|f| f.value);
        let sized = |tag: u32, len: usize| get(tag).filter(|v| v.len() == len).map(<[u8]>::to_vec);
        let rsa_part =
            |tag: u32| get(tag).filter(|v| !v.is_empty() && v.len() <= MAX_RSA_PART).map(<[u8]>::to_vec);
        match get(0x80)? {
            [KIND_RSA] => Some(KeyMaterial::Rsa { p: rsa_part(0x81)?, q: rsa_part(0x82)?, e: rsa_part(0x83)? }),
            [KIND_ED25519] => Some(KeyMaterial::Ed25519 { seed: sized(0x81, 32)? }),
            [KIND_X25519] => Some(KeyMaterial::X25519 { secret: sized(0x81, 32)? }),
            [kind] => {
                let (_, curve) = EC_KINDS.iter().find(|(k, _)| k == kind)?;
                Some(KeyMaterial::Ec { curve: *curve, scalar: sized(0x81, curve.field_len())? })
            }
            _ => None,
        }
    }

    /// Whether this material is a key of `alg` (the slot attributes).
    pub(crate) fn matches(&self, alg: Algorithm) -> bool {
        match (self, alg) {
            (KeyMaterial::Rsa { .. }, Algorithm::Rsa { .. }) => true,
            (KeyMaterial::Ec { curve, .. }, Algorithm::Ecdsa(named) | Algorithm::Ecdh(named)) => {
                named.engine_curve() == Some(*curve)
            }
            (KeyMaterial::Ed25519 { .. }, Algorithm::Ed25519) => true,
            (KeyMaterial::X25519 { .. }, Algorithm::X25519) => true,
            _ => false,
        }
    }

    /// Rebuild the lk-crypto key; `None` if the stored bytes are not a valid key.
    pub(crate) fn load(&self) -> Option<CryptoKey> {
        match self {
            KeyMaterial::Rsa { p, q, e } => RsaPrivateKey::from_primes(p, q, e).ok().map(CryptoKey::Rsa),
            KeyMaterial::Ec { curve, scalar } => EcPrivateKey::from_scalar(*curve, scalar).ok().map(CryptoKey::Ec),
            KeyMaterial::Ed25519 { seed } => Ed25519Key::from_seed(seed).ok().map(CryptoKey::Ed25519),
            KeyMaterial::X25519 { secret } => X25519Key::from_bytes(secret).ok().map(CryptoKey::X25519),
        }
    }
}

/// A key ready for use.
#[derive(Debug)]
pub(crate) enum CryptoKey {
    Rsa(RsaPrivateKey),
    Ec(EcPrivateKey),
    Ed25519(Ed25519Key),
    X25519(X25519Key),
}

impl CryptoKey {
    /// The public key DO 7F49 (spec §7.2.14): RSA `81` modulus and `82` exponent; ECC `86`
    /// with the uncompressed point (`04 || X || Y`) or the native 32-byte 25519 key.
    pub(crate) fn public_template(&self) -> Vec<u8> {
        let mut inner = Vec::new();
        match self {
            CryptoKey::Rsa(key) => {
                tlv::encode_into(&mut inner, 0x81, &key.modulus());
                tlv::encode_into(&mut inner, 0x82, &key.public_exponent());
            }
            CryptoKey::Ec(key) => tlv::encode_into(&mut inner, 0x86, &key.public_uncompressed()),
            CryptoKey::Ed25519(key) => tlv::encode_into(&mut inner, 0x86, &key.public()),
            CryptoKey::X25519(key) => tlv::encode_into(&mut inner, 0x86, &key.public()),
        }
        tlv::encode(0x7F49, &inner)
    }

    /// The SubjectPublicKeyInfo form for certificates.
    pub(crate) fn x509_public_key(&self) -> PublicKey {
        match self {
            CryptoKey::Rsa(key) => PublicKey::Rsa { modulus: key.modulus(), exponent: key.public_exponent() },
            CryptoKey::Ec(key) => {
                let point = key.public_uncompressed();
                match key.curve() {
                    Curve::P256 => PublicKey::EcP256(point),
                    Curve::P384 => PublicKey::EcP384(point),
                    Curve::P521 => PublicKey::EcP521(point),
                    Curve::Secp256k1 => PublicKey::EcSecp256k1(point),
                    Curve::BrainpoolP256r1 => PublicKey::EcBrainpoolP256r1(point),
                    Curve::BrainpoolP384r1 => PublicKey::EcBrainpoolP384r1(point),
                }
            }
            CryptoKey::Ed25519(key) => PublicKey::Ed25519(key.public().to_vec()),
            CryptoKey::X25519(key) => PublicKey::X25519(key.public().to_vec()),
        }
    }

    /// Signature or authentication response over `input` (spec §7.2.10, §7.2.13):
    /// - RSA: `input` (normally a DigestInfo) is EMSA-PKCS1-v1_5 encoded and signed;
    /// - ECDSA: `input` is the digest; the result is `r || s` (hedged nonce, CONTRACTS.md
    ///   "Phase 0 as implemented");
    /// - EdDSA: `input` is the message itself.
    pub(crate) fn sign(&self, input: &[u8], entropy: &mut dyn Entropy) -> Result<Vec<u8>, u16> {
        match self {
            CryptoKey::Rsa(key) => {
                let em = pkcs1_signature_block(input, key.size())?;
                key.raw_private(&em, entropy).map_err(|_| sw::UNKNOWN)
            }
            CryptoKey::Ec(key) => key
                .sign_prehash_hedged(input, entropy)
                .map(|sig| sig.to_raw())
                .map_err(|_| sw::INCORRECT_DATA),
            CryptoKey::Ed25519(key) => Ok(key.sign(input).to_vec()),
            CryptoKey::X25519(_) => Err(sw::CONDITIONS),
        }
    }

    /// PSO:DECIPHER (spec §7.2.11) on validated input: the RSA cryptogram (without the
    /// padding indicator) or the peer's public key from the cipher DO.
    pub(crate) fn decipher(&self, input: &[u8], entropy: &mut dyn Entropy) -> Result<Vec<u8>, u16> {
        match self {
            CryptoKey::Rsa(key) => {
                let em = key.raw_private(input, entropy).map_err(|_| sw::INCORRECT_DATA)?;
                pkcs1_decryption_payload(&em).ok_or(sw::INCORRECT_DATA)
            }
            CryptoKey::Ec(key) => key.ecdh(input).map(|z| z.to_vec()).map_err(|_| sw::INCORRECT_DATA),
            CryptoKey::X25519(key) => key.dh(input).map(|z| z.to_vec()).map_err(|_| sw::INCORRECT_DATA),
            CryptoKey::Ed25519(_) => Err(sw::CONDITIONS),
        }
    }
}

/// EMSA-PKCS1-v1_5 block `00 01 FF.. 00 || t` of `k` bytes (RFC 8017 §9.2 steps 3-5).
/// `t` longer than `k - 11` is `6700`.
pub(crate) fn pkcs1_signature_block(t: &[u8], k: usize) -> Result<Vec<u8>, u16> {
    if t.is_empty() || t.len() + PKCS1_OVERHEAD > k {
        return Err(sw::WRONG_LENGTH);
    }
    let mut em = Vec::with_capacity(k);
    em.extend_from_slice(&[0x00, 0x01]);
    em.resize(k - t.len() - 1, 0xFF);
    em.push(0x00);
    em.extend_from_slice(t);
    Ok(em)
}

/// The message of an RSAES-PKCS1-v1_5 block `00 02 PS 00 M` with at least eight non-zero
/// padding octets (RFC 8017 §7.2.2 step 3). The scan visits every octet whatever the
/// outcome; `None` on any padding error.
pub(crate) fn pkcs1_decryption_payload(em: &[u8]) -> Option<Vec<u8>> {
    let mut separator = 0usize;
    for (i, &b) in em.iter().enumerate().skip(2) {
        let first_zero = separator == 0 && b == 0;
        separator = if first_zero { i } else { separator };
    }
    let header_ok = em.first() == Some(&0x00) && em.get(1) == Some(&0x02);
    if !header_ok || separator < 2 + 8 {
        return None;
    }
    em.get(separator + 1..).map(<[u8]>::to_vec)
}

/// Check signature input before anything is computed: non-empty, and for RSA at most
/// `k - 11` bytes, for ECDSA at most 64 bytes (`6700` otherwise).
pub(crate) fn check_signature_input(alg: Algorithm, input: &[u8]) -> Result<(), u16> {
    let max = match alg {
        Algorithm::Rsa { bits, .. } => (usize::from(bits) / 8).saturating_sub(PKCS1_OVERHEAD),
        Algorithm::Ecdsa(_) => MAX_ECDSA_DIGEST,
        _ => usize::MAX,
    };
    if input.is_empty() || input.len() > max {
        return Err(sw::WRONG_LENGTH);
    }
    Ok(())
}

/// Validate PSO:DECIPHER data for `alg` and return the operation input (spec §7.2.11):
/// - RSA: padding indicator `00` then the cryptogram of exactly the modulus length
///   (indicator `02`, AES, is not offered: C0 bit "PSO:DEC/ENC with AES" is 0 → `6A81`);
/// - ECDH: the cipher DO `A6 { 7F49 { 86 <public key> } }`, with an uncompressed point of
///   the curve's length or a 32-byte X25519 key.
pub(crate) fn decipher_input(alg: Algorithm, data: &[u8]) -> Result<Vec<u8>, u16> {
    match alg {
        Algorithm::Rsa { bits, .. } => match data.split_first() {
            Some((0x00, cryptogram)) => {
                if cryptogram.len() != usize::from(bits) / 8 {
                    return Err(sw::WRONG_LENGTH);
                }
                Ok(cryptogram.to_vec())
            }
            Some((0x02, _)) => Err(sw::FUNC_NOT_SUPPORTED),
            Some(_) => Err(sw::INCORRECT_DATA),
            None => Err(sw::WRONG_LENGTH),
        },
        Algorithm::Ecdh(curve) => {
            let point = cipher_do_point(data).ok_or(sw::INCORRECT_DATA)?;
            let curve = curve.engine_curve().ok_or(sw::FUNC_NOT_SUPPORTED)?;
            if point.len() != curve.point_len() || point.first() != Some(&0x04) {
                return Err(sw::INCORRECT_DATA);
            }
            Ok(point.to_vec())
        }
        Algorithm::X25519 => {
            let point = cipher_do_point(data).ok_or(sw::INCORRECT_DATA)?;
            if point.len() != 32 {
                return Err(sw::INCORRECT_DATA);
            }
            Ok(point.to_vec())
        }
        Algorithm::Ecdsa(_) | Algorithm::Ed25519 => Err(sw::CONDITIONS),
    }
}

/// The `86` value of `A6 { 7F49 { 86 .. } }`, each level exactly one object.
fn cipher_do_point(data: &[u8]) -> Option<&[u8]> {
    let only = |bytes, tag| -> Option<&[u8]> {
        let (obj, rest) = tlv::parse_one(bytes).ok()?;
        (obj.tag == tag && rest.is_empty()).then_some(obj.value)
    };
    let template = only(data, 0xA6)?;
    let public = only(template, 0x7F49)?;
    only(public, 0x86)
}

/// Generate a key for `alg` (spec §7.2.14). brainpoolP512r1 (no lk-crypto support) is `6A81`.
pub(crate) fn generate(alg: Algorithm, entropy: &mut dyn Entropy) -> Result<KeyMaterial, u16> {
    match alg {
        Algorithm::Rsa { bits, .. } => {
            let key = RsaPrivateKey::generate(usize::from(bits), entropy).map_err(|_| sw::FUNC_NOT_SUPPORTED)?;
            Ok(rsa_material(&key))
        }
        Algorithm::Ecdsa(curve) | Algorithm::Ecdh(curve) => {
            let curve = curve.engine_curve().ok_or(sw::FUNC_NOT_SUPPORTED)?;
            let key = EcPrivateKey::generate(curve, entropy);
            Ok(KeyMaterial::Ec { curve, scalar: key.scalar().to_vec() })
        }
        Algorithm::Ed25519 => Ok(KeyMaterial::Ed25519 { seed: Ed25519Key::generate(entropy).seed().to_vec() }),
        Algorithm::X25519 => Ok(KeyMaterial::X25519 { secret: X25519Key::generate(entropy).secret().to_vec() }),
    }
}

pub(crate) fn rsa_material(key: &RsaPrivateKey) -> KeyMaterial {
    let primes = key.primes();
    KeyMaterial::Rsa { p: primes.0.clone(), q: primes.1.clone(), e: key.public_exponent() }
}

/// The Control Reference Template naming a key (spec §7.2.14 and §4.4.3.12): `B6`, `B8` or
/// `A4`, empty or with the matching key reference `84 01 01/02/03`; the Yubico attestation
/// key is `B6 03 84 01 81`. Anything else, including a reference that does not match the
/// template tag, is `6A80` (catalog: "short and extended CRT matching ... mismatched
/// reference rejection").
pub(crate) fn parse_crt(data: &[u8]) -> Result<Slot, u16> {
    let (crt, rest) = tlv::parse_one(data).map_err(|_| sw::INCORRECT_DATA)?;
    if !rest.is_empty() {
        return Err(sw::INCORRECT_DATA);
    }
    crt_slot(crt.tag, crt.value).ok_or(sw::INCORRECT_DATA)
}

fn crt_slot(tag: u32, value: &[u8]) -> Option<Slot> {
    match (tag, value) {
        (0xB6, []) | (0xB6, [0x84, 0x01, 0x01]) => Some(Slot::Sig),
        (0xB8, []) | (0xB8, [0x84, 0x01, 0x02]) => Some(Slot::Dec),
        (0xA4, []) | (0xA4, [0x84, 0x01, 0x03]) => Some(Slot::Aut),
        (0xB6, [0x84, 0x01, 0x81]) => Some(Slot::Att),
        _ => None,
    }
}

/// One component of an imported key: its 7F48 tag and its bytes from 5F48.
pub(crate) type Component<'a> = (u8, &'a [u8]);

/// Parse the extended header list of a key import (spec §4.4.3.12): exactly
/// `4D { CRT, 7F48 <tag/length list>, 5F48 <concatenated values> }`, where the 7F48
/// lengths add up to the length of 5F48. Returns the slot and the components in order.
pub(crate) fn parse_import(data: &[u8]) -> Result<(Slot, Vec<Component<'_>>), u16> {
    let (outer, rest) = tlv::parse_one(data).map_err(|_| sw::INCORRECT_DATA)?;
    if outer.tag != 0x4D || !rest.is_empty() {
        return Err(sw::INCORRECT_DATA);
    }
    let parts = tlv::parse_all(outer.value).map_err(|_| sw::INCORRECT_DATA)?;
    let [crt, template, values] = parts.as_slice() else {
        return Err(sw::INCORRECT_DATA);
    };
    if template.tag != 0x7F48 || values.tag != 0x5F48 {
        return Err(sw::INCORRECT_DATA);
    }
    let slot = crt_slot(crt.tag, crt.value).ok_or(sw::INCORRECT_DATA)?;
    let list = template_list(template.value).ok_or(sw::INCORRECT_DATA)?;
    let total = list.iter().try_fold(0usize, |acc, (_, len)| acc.checked_add(*len));
    if total != Some(values.value.len()) {
        return Err(sw::INCORRECT_DATA);
    }
    let mut components = Vec::with_capacity(list.len());
    let mut rest = values.value;
    for (tag, len) in list {
        let (value, tail) = rest.split_at_checked(len).ok_or(sw::INCORRECT_DATA)?;
        components.push((tag, value));
        rest = tail;
    }
    Ok((slot, components))
}

/// The 7F48 list: one-byte tags, each with a BER length (short form, `81 xx` or
/// `82 xx xx`) and no value.
fn template_list(mut bytes: &[u8]) -> Option<Vec<(u8, usize)>> {
    let mut out = Vec::new();
    while let Some((&tag, rest)) = bytes.split_first() {
        let (len, rest) = match rest {
            [n @ 0x00..=0x7F, rest @ ..] => (usize::from(*n), rest),
            [0x81, n, rest @ ..] => (usize::from(*n), rest),
            [0x82, hi, lo, rest @ ..] => (usize::from(u16::from_be_bytes([*hi, *lo])), rest),
            _ => return None,
        };
        out.push((tag, len));
        bytes = rest;
    }
    Some(out)
}

/// Build key material for `alg` from imported components (spec §4.4.3.12):
/// - RSA: `91` e, `92` p, `93` q, optionally `94` 1/q mod p, `95` d mod (p-1), `96` d mod
///   (q-1) (all three: CRT format) and `97` n, in exactly this order with no duplicates
///   or other tags. p and q have the standard width `bits/16`; e is an odd value of at
///   least 3 within the attributes' exponent length; a given modulus must equal p·q, which
///   must have exactly `bits` bits. The CRT values are accepted at their width up to
///   `bits/16` and not used: the key is rebuilt from p, q and e (model policy; lk-crypto
///   has no big-integer arithmetic to cross-check them).
/// - ECDSA/ECDH/EdDSA: `92` private key at the standard width (field length, or 32 for
///   Ed25519/X25519; X25519 in the reversed big-endian form, RFC 9580 §5.5.5.6.1.1),
///   optionally followed by `99` public key, which must match the private key.
///
/// Malformed input is `6A80`; algorithms lk-crypto lacks (brainpoolP512r1) are `6A81`.
pub(crate) fn import_material(alg: Algorithm, components: &[Component<'_>]) -> Result<KeyMaterial, u16> {
    if !alg.supported() {
        return Err(sw::FUNC_NOT_SUPPORTED);
    }
    let tags: Vec<u8> = components.iter().map(|(tag, _)| *tag).collect();
    let value = |tag: u8| components.iter().find(|(t, _)| *t == tag).map(|(_, v)| *v);
    match alg {
        Algorithm::Rsa { bits, e_bits } => {
            const ORDERS: [&[u8]; 4] = [
                &[0x91, 0x92, 0x93],
                &[0x91, 0x92, 0x93, 0x97],
                &[0x91, 0x92, 0x93, 0x94, 0x95, 0x96],
                &[0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97],
            ];
            if !ORDERS.contains(&tags.as_slice()) {
                return Err(sw::INCORRECT_DATA);
            }
            let half = usize::from(bits) / 16;
            let (e, p, q) = match (value(0x91), value(0x92), value(0x93)) {
                (Some(e), Some(p), Some(q)) => (e, p, q),
                _ => return Err(sw::INCORRECT_DATA),
            };
            if p.len() != half || q.len() != half || e.is_empty() || e.len() > 4 {
                return Err(sw::INCORRECT_DATA);
            }
            for tag in [0x94, 0x95, 0x96] {
                if value(tag).is_some_and(|v| v.is_empty() || v.len() > half) {
                    return Err(sw::INCORRECT_DATA);
                }
            }
            let e = trim_zeros(e);
            let e_value = e.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
            let e_fits = u64::from(e_bits) >= 64 || e_value < (1u64 << e_bits);
            if e_value < 3 || e_value % 2 == 0 || !e_fits {
                return Err(sw::INCORRECT_DATA);
            }
            let key = RsaPrivateKey::from_primes(p, q, e).map_err(|_| sw::INCORRECT_DATA)?;
            let modulus = key.modulus();
            let full_width = modulus.len() == usize::from(bits) / 8 && modulus.first().is_some_and(|b| b & 0x80 != 0);
            if !full_width || value(0x97).is_some_and(|n| n != modulus.as_slice()) {
                return Err(sw::INCORRECT_DATA);
            }
            Ok(rsa_material(&key))
        }
        Algorithm::Ecdsa(curve) | Algorithm::Ecdh(curve) => {
            let curve = curve.engine_curve().ok_or(sw::FUNC_NOT_SUPPORTED)?;
            let (private, public) = ec_components(&tags, value)?;
            let key = EcPrivateKey::from_scalar(curve, private).map_err(|_| sw::INCORRECT_DATA)?;
            if public.is_some_and(|p| p != key.public_uncompressed().as_slice()) {
                return Err(sw::INCORRECT_DATA);
            }
            Ok(KeyMaterial::Ec { curve, scalar: private.to_vec() })
        }
        Algorithm::Ed25519 => {
            let (private, public) = ec_components(&tags, value)?;
            let key = Ed25519Key::from_seed(private).map_err(|_| sw::INCORRECT_DATA)?;
            if public.is_some_and(|p| p != key.public().as_slice()) {
                return Err(sw::INCORRECT_DATA);
            }
            Ok(KeyMaterial::Ed25519 { seed: private.to_vec() })
        }
        Algorithm::X25519 => {
            let (private, public) = ec_components(&tags, value)?;
            let native: Vec<u8> = private.iter().rev().copied().collect();
            let key = X25519Key::from_bytes(&native).map_err(|_| sw::INCORRECT_DATA)?;
            if public.is_some_and(|p| p != key.public().as_slice()) {
                return Err(sw::INCORRECT_DATA);
            }
            Ok(KeyMaterial::X25519 { secret: native })
        }
    }
}

/// The `92` private key and optional `99` public key of an ECC import, in that order.
fn ec_components<'a>(
    tags: &[u8],
    value: impl Fn(u8) -> Option<&'a [u8]>,
) -> Result<(&'a [u8], Option<&'a [u8]>), u16> {
    if tags != [0x92] && tags != [0x92, 0x99] {
        return Err(sw::INCORRECT_DATA);
    }
    let private = value(0x92).ok_or(sw::INCORRECT_DATA)?;
    Ok((private, value(0x99)))
}

fn trim_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    bytes.get(start..).unwrap_or(&[])
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn attributes_decode_every_fa_entry() {
        // Every entry of the observed FA (reference/yubikey) decodes.
        let (fa, _) = tlv::parse_one(&crate::objects::ALGORITHM_INFORMATION).unwrap();
        let entries = fa.children().unwrap();
        let mut supported = 0;
        for entry in &entries {
            let alg = Algorithm::from_attributes(entry.value).unwrap();
            if alg.supported() {
                supported += 1;
            }
        }
        // Per slot: RSA x3 and the six prime curves lk-crypto implements, plus Ed25519 (SIG,
        // AUT) or X25519 (DEC); the attestation slot has no 25519 entry. Only the four
        // brainpoolP512r1 entries are unsupported.
        assert_eq!(supported, 10 + 10 + 10 + 9);
        assert_eq!(entries.len() - supported, 4);
        assert_eq!(
            Algorithm::from_attributes(&[0x01, 0x08, 0x00, 0x00, 0x11, 0x00]),
            Some(Algorithm::Rsa { bits: 2048, e_bits: 17 })
        );
        let mut ed = vec![0x16];
        ed.extend_from_slice(&OID_ED25519);
        assert_eq!(Algorithm::from_attributes(&ed), Some(Algorithm::Ed25519));
        ed.push(0xFF);
        assert_eq!(Algorithm::from_attributes(&ed), Some(Algorithm::Ed25519));
        assert_eq!(Algorithm::from_attributes(&[0x13]), None);
        assert_eq!(Algorithm::from_attributes(&[]), None);
    }

    #[test]
    fn pkcs1_blocks() {
        // RFC 8017 §9.2: 00 01 FF..FF 00 T, at least eight FF.
        let em = pkcs1_signature_block(&[0xAA; 5], 16).unwrap();
        assert_eq!(em, [0, 1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]);
        assert_eq!(pkcs1_signature_block(&[0xAA; 6], 16), Err(sw::WRONG_LENGTH));
        assert_eq!(pkcs1_signature_block(&[], 16), Err(sw::WRONG_LENGTH));
        // RFC 8017 §7.2.2 step 3.
        let mut block = vec![0x00, 0x02];
        block.extend_from_slice(&[0x55; 8]);
        block.push(0x00);
        block.extend_from_slice(b"msg");
        assert_eq!(pkcs1_decryption_payload(&block), Some(b"msg".to_vec()));
        let mut short_ps = vec![0x00, 0x02];
        short_ps.extend_from_slice(&[0x55; 7]);
        short_ps.push(0x00);
        short_ps.extend_from_slice(b"msg");
        assert_eq!(pkcs1_decryption_payload(&short_ps), None);
        let mut bad_header = block.clone();
        bad_header[1] = 0x01;
        assert_eq!(pkcs1_decryption_payload(&bad_header), None);
        assert_eq!(pkcs1_decryption_payload(&[0x00, 0x02, 0x55, 0x55]), None);
        assert_eq!(pkcs1_decryption_payload(&[]), None);
        // Empty message is allowed.
        let mut empty = vec![0x00, 0x02];
        empty.extend_from_slice(&[1; 8]);
        empty.push(0);
        assert_eq!(pkcs1_decryption_payload(&empty), Some(vec![]));
    }

    #[test]
    fn crt_forms() {
        // spec §7.2.14 / §4.4.3.12; YubiKit's attestation CRT B6 03 84 01 81.
        assert_eq!(parse_crt(&[0xB6, 0x00]), Ok(Slot::Sig));
        assert_eq!(parse_crt(&[0xB8, 0x00]), Ok(Slot::Dec));
        assert_eq!(parse_crt(&[0xA4, 0x00]), Ok(Slot::Aut));
        assert_eq!(parse_crt(&[0xB6, 0x03, 0x84, 0x01, 0x01]), Ok(Slot::Sig));
        assert_eq!(parse_crt(&[0xB8, 0x03, 0x84, 0x01, 0x02]), Ok(Slot::Dec));
        assert_eq!(parse_crt(&[0xA4, 0x03, 0x84, 0x01, 0x03]), Ok(Slot::Aut));
        assert_eq!(parse_crt(&[0xB6, 0x03, 0x84, 0x01, 0x81]), Ok(Slot::Att));
        for bad in [
            &[0xB6, 0x03, 0x84, 0x01, 0x02][..],
            &[0xB8, 0x03, 0x84, 0x01, 0x81],
            &[0xA4, 0x03, 0x84, 0x01, 0x01],
            &[0xB7, 0x00],
            &[0xB6, 0x00, 0x00],
            &[0xB6, 0x01, 0x00],
            &[],
        ] {
            assert_eq!(parse_crt(bad), Err(sw::INCORRECT_DATA), "{bad:02X?}");
        }
    }

    #[test]
    fn import_list_parsing() {
        // spec §4.4.3.12 example layout: 4D { B6 00, 7F48 {92 03, 99 02}, 5F48 {..} }.
        let data = [
            0x4D, 0x11, 0xB6, 0x00, 0x7F, 0x48, 0x04, 0x92, 0x03, 0x99, 0x02, 0x5F, 0x48, 0x05, 1, 2, 3, 4, 5,
        ];
        let (slot, parts) = parse_import(&data).unwrap();
        assert_eq!(slot, Slot::Sig);
        assert_eq!(parts, vec![(0x92, &[1, 2, 3][..]), (0x99, &[4, 5][..])]);
        // Length mismatch between 7F48 and 5F48.
        let mut bad = data;
        bad[10] = 0x03;
        assert_eq!(parse_import(&bad), Err(sw::INCORRECT_DATA));
        // Long-form lengths in 7F48.
        assert_eq!(template_list(&[0x92, 0x81, 0x80, 0x93, 0x82, 0x01, 0x00]), Some(vec![(0x92, 128), (0x93, 256)]));
        assert_eq!(template_list(&[0x92, 0x83, 0, 0, 1]), None);
        assert_eq!(template_list(&[0x92]), None);
    }

    #[test]
    fn storage_roundtrip() {
        for material in [
            KeyMaterial::Rsa { p: vec![7; 128], q: vec![9; 128], e: vec![1, 0, 1] },
            KeyMaterial::Ec { curve: Curve::P256, scalar: vec![1; 32] },
            KeyMaterial::Ec { curve: Curve::P384, scalar: vec![2; 48] },
            KeyMaterial::Ec { curve: Curve::P521, scalar: vec![1; 66] },
            KeyMaterial::Ec { curve: Curve::Secp256k1, scalar: vec![5; 32] },
            KeyMaterial::Ec { curve: Curve::BrainpoolP256r1, scalar: vec![6; 32] },
            KeyMaterial::Ec { curve: Curve::BrainpoolP384r1, scalar: vec![7; 48] },
            KeyMaterial::Ed25519 { seed: vec![3; 32] },
            KeyMaterial::X25519 { secret: vec![4; 32] },
        ] {
            assert_eq!(KeyMaterial::from_storage(&material.to_storage()), Some(material.clone()));
            assert!(format!("{material:?}").ends_with("(<redacted>)"));
        }
        assert_eq!(KeyMaterial::from_storage(&[0x80, 0x01, 0x02, 0x81, 0x01, 0x00]), None);
        assert_eq!(KeyMaterial::from_storage(&[0x80, 0x01, 0x09]), None);
        assert_eq!(KeyMaterial::from_storage(&[0x80, 0x01, 0x0A, 0x81, 0x01, 0x00]), None);
        // Each curve's scalar must have that curve's field length.
        for (kind, len) in [(0x06, 66), (0x07, 32), (0x08, 32), (0x09, 48)] {
            let mut bytes = vec![0x80, 0x01, kind, 0x81, len as u8 - 1];
            bytes.extend(vec![1; len - 1]);
            assert_eq!(KeyMaterial::from_storage(&bytes), None, "{kind:02X}");
            let mut bytes = vec![0x80, 0x01, kind, 0x81, len as u8];
            bytes.extend(vec![1; len]);
            assert!(KeyMaterial::from_storage(&bytes).is_some(), "{kind:02X}");
        }
        assert_eq!(KeyMaterial::from_storage(&[]), None);
    }
}
