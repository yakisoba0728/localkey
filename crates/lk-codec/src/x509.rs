//! X.509 certificate assembly (RFC 5280) on top of [`crate::der`].
//!
//! [`TbsCertificate::to_der`] produces the DER `TBSCertificate` (RFC 5280 §4.1). The caller
//! signs those bytes with `lk-crypto` and passes the signature to [`assemble`], which wraps
//! everything into the final `Certificate`:
//!
//! ```text
//! Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue BIT STRING }
//! ```
//!
//! Every certificate is version 3. The supported keys and algorithms are those the device
//! uses for FIDO, PIV, OpenPGP and Security Domain certificates: EC keys on P-256, P-384,
//! P-521 (RFC 5480), secp256k1 (SEC 2 v2 §A.2) and brainpoolP256r1/P384r1 (RFC 5639 §4.1),
//! Ed25519/X25519 (RFC 8410) and RSA (RFC 8017, RFC 4055).

use core::fmt;

use crate::der;

/// Object identifiers used by the certificate builder, as arcs for [`der::oid`].
pub mod oid {
    /// `id-ecPublicKey` (RFC 5480 §2.1.1).
    pub const EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];
    /// `secp256r1` / P-256 (RFC 5480 §2.1.1.1).
    pub const SECP256R1: &[u64] = &[1, 2, 840, 10045, 3, 1, 7];
    /// `secp384r1` / P-384 (RFC 5480 §2.1.1.1).
    pub const SECP384R1: &[u64] = &[1, 3, 132, 0, 34];
    /// `secp521r1` / P-521 (RFC 5480 §2.1.1.1).
    pub const SECP521R1: &[u64] = &[1, 3, 132, 0, 35];
    /// `secp256k1` (SEC 2 v2 §A.2.1).
    pub const SECP256K1: &[u64] = &[1, 3, 132, 0, 10];
    /// `brainpoolP256r1` (RFC 5639 §4.1).
    pub const BRAINPOOL_P256R1: &[u64] = &[1, 3, 36, 3, 3, 2, 8, 1, 1, 7];
    /// `brainpoolP384r1` (RFC 5639 §4.1).
    pub const BRAINPOOL_P384R1: &[u64] = &[1, 3, 36, 3, 3, 2, 8, 1, 1, 11];
    /// `id-X25519` (RFC 8410 §3).
    pub const X25519: &[u64] = &[1, 3, 101, 110];
    /// `id-Ed25519` (RFC 8410 §3), both key and signature algorithm.
    pub const ED25519: &[u64] = &[1, 3, 101, 112];
    /// `rsaEncryption` (RFC 8017 Appendix C, RFC 3279 §2.3.1).
    pub const RSA_ENCRYPTION: &[u64] = &[1, 2, 840, 113549, 1, 1, 1];
    /// `ecdsa-with-SHA256` (RFC 5758 §3.2).
    pub const ECDSA_WITH_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];
    /// `ecdsa-with-SHA384` (RFC 5758 §3.2).
    pub const ECDSA_WITH_SHA384: &[u64] = &[1, 2, 840, 10045, 4, 3, 3];
    /// `ecdsa-with-SHA512` (RFC 5758 §3.2).
    pub const ECDSA_WITH_SHA512: &[u64] = &[1, 2, 840, 10045, 4, 3, 4];
    /// `sha256WithRSAEncryption` (RFC 4055 §5).
    pub const SHA256_WITH_RSA_ENCRYPTION: &[u64] = &[1, 2, 840, 113549, 1, 1, 11];
    /// `id-at-commonName` (RFC 5280 §4.1.2.4, Appendix A.1).
    pub const COMMON_NAME: &[u64] = &[2, 5, 4, 3];
    /// `id-at-countryName` (RFC 5280 Appendix A.1).
    pub const COUNTRY_NAME: &[u64] = &[2, 5, 4, 6];
    /// `id-at-organizationName` (RFC 5280 Appendix A.1).
    pub const ORGANIZATION_NAME: &[u64] = &[2, 5, 4, 10];
    /// `id-at-organizationalUnitName` (RFC 5280 Appendix A.1).
    pub const ORGANIZATIONAL_UNIT_NAME: &[u64] = &[2, 5, 4, 11];
    /// `id-ce-subjectKeyIdentifier` (RFC 5280 §4.2.1.2).
    pub const SUBJECT_KEY_IDENTIFIER: &[u64] = &[2, 5, 29, 14];
    /// `id-ce-keyUsage` (RFC 5280 §4.2.1.3).
    pub const KEY_USAGE: &[u64] = &[2, 5, 29, 15];
    /// `id-ce-basicConstraints` (RFC 5280 §4.2.1.9).
    pub const BASIC_CONSTRAINTS: &[u64] = &[2, 5, 29, 19];
    /// `id-ce-authorityKeyIdentifier` (RFC 5280 §4.2.1.1).
    pub const AUTHORITY_KEY_IDENTIFIER: &[u64] = &[2, 5, 29, 35];
    /// `id-fido-gen-ce-aaguid` (WebAuthn §8.2.1).
    pub const FIDO_GEN_CE_AAGUID: &[u64] = &[1, 3, 6, 1, 4, 1, 45724, 1, 1, 4];
}

/// `KeyUsage` named bits for [`Extension::key_usage`] (RFC 5280 §4.2.1.3). Combine with `|`.
pub mod key_usage {
    /// `digitalSignature (0)`.
    pub const DIGITAL_SIGNATURE: u16 = 1 << 0;
    /// `nonRepudiation (1)`, also called `contentCommitment`.
    pub const NON_REPUDIATION: u16 = 1 << 1;
    /// `keyEncipherment (2)`.
    pub const KEY_ENCIPHERMENT: u16 = 1 << 2;
    /// `dataEncipherment (3)`.
    pub const DATA_ENCIPHERMENT: u16 = 1 << 3;
    /// `keyAgreement (4)`.
    pub const KEY_AGREEMENT: u16 = 1 << 4;
    /// `keyCertSign (5)`.
    pub const KEY_CERT_SIGN: u16 = 1 << 5;
    /// `cRLSign (6)`.
    pub const CRL_SIGN: u16 = 1 << 6;
    /// `encipherOnly (7)`.
    pub const ENCIPHER_ONLY: u16 = 1 << 7;
    /// `decipherOnly (8)`.
    pub const DECIPHER_ONLY: u16 = 1 << 8;
}

/// Errors from the certificate builder's checked constructors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X509Error {
    /// A time string was not `YYYYMMDDHHMMSSZ` with in-range fields (RFC 5280 §4.1.2.5.2).
    InvalidTime,
}

impl fmt::Display for X509Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTime => f.write_str("time is not a valid YYYYMMDDHHMMSSZ GeneralizedTime"),
        }
    }
}

impl std::error::Error for X509Error {}

/// A certificate signature algorithm (RFC 5280 §4.1.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    /// `ecdsa-with-SHA256`, parameters absent (RFC 5758 §3.2). The signature value is the
    /// DER `Ecdsa-Sig-Value` (`EcdsaSignature::to_der` in `lk-crypto`).
    EcdsaWithSha256,
    /// `ecdsa-with-SHA384`, parameters absent (RFC 5758 §3.2).
    EcdsaWithSha384,
    /// `ecdsa-with-SHA512`, parameters absent (RFC 5758 §3.2).
    EcdsaWithSha512,
    /// `id-Ed25519`, parameters absent (RFC 8410 §3, §6). The signature is the raw 64 bytes.
    Ed25519,
    /// `sha256WithRSAEncryption` with NULL parameters (RFC 4055 §5): PKCS #1 v1.5 signature.
    Sha256WithRsaEncryption,
}

impl SignatureAlgorithm {
    const ALL: [Self; 5] = [
        Self::EcdsaWithSha256,
        Self::EcdsaWithSha384,
        Self::EcdsaWithSha512,
        Self::Ed25519,
        Self::Sha256WithRsaEncryption,
    ];

    /// The algorithm's object identifier.
    pub fn oid(self) -> &'static [u64] {
        match self {
            Self::EcdsaWithSha256 => oid::ECDSA_WITH_SHA256,
            Self::EcdsaWithSha384 => oid::ECDSA_WITH_SHA384,
            Self::EcdsaWithSha512 => oid::ECDSA_WITH_SHA512,
            Self::Ed25519 => oid::ED25519,
            Self::Sha256WithRsaEncryption => oid::SHA256_WITH_RSA_ENCRYPTION,
        }
    }

    /// The DER `AlgorithmIdentifier` (RFC 5280 §4.1.1.2), used both inside the
    /// `TBSCertificate` and as the outer `signatureAlgorithm`.
    pub fn algorithm_identifier(self) -> Vec<u8> {
        match self {
            Self::Sha256WithRsaEncryption => der::sequence([der::oid(self.oid()), der::null()]),
            _ => der::sequence([der::oid(self.oid())]),
        }
    }

    /// Recognises a complete DER `AlgorithmIdentifier` element.
    ///
    /// ECDSA and Ed25519 require absent parameters (RFC 5758 §3.2, RFC 8410 §3);
    /// `sha256WithRSAEncryption` accepts NULL or absent parameters (RFC 4055 §5).
    pub fn from_algorithm_identifier(element: &[u8]) -> Option<Self> {
        let content = der::expect_only(element, der::tag::SEQUENCE).ok()?;
        let (oid_value, params) = der::expect(content, der::tag::OID).ok()?;
        let arcs = der::decode_oid(oid_value).ok()?;
        let algorithm = Self::ALL
            .into_iter()
            .find(|alg| alg.oid() == arcs.as_slice())?;
        let params_ok = match algorithm {
            Self::Sha256WithRsaEncryption => params.is_empty() || params == der::null().as_slice(),
            _ => params.is_empty(),
        };
        params_ok.then_some(algorithm)
    }
}

/// A subject public key (RFC 5280 §4.1.2.7).
///
/// The key bytes are taken as given; their validity is the caller's job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// P-256 uncompressed SEC1 point `04 || X || Y` (65 bytes, RFC 5480 §2.2).
    EcP256(Vec<u8>),
    /// P-384 uncompressed SEC1 point `04 || X || Y` (97 bytes, RFC 5480 §2.2).
    EcP384(Vec<u8>),
    /// P-521 uncompressed SEC1 point `04 || X || Y` (133 bytes, RFC 5480 §2.2).
    EcP521(Vec<u8>),
    /// secp256k1 uncompressed SEC1 point (65 bytes; RFC 5480 §2.2 encoding, SEC 2 OID).
    EcSecp256k1(Vec<u8>),
    /// brainpoolP256r1 uncompressed SEC1 point (65 bytes; RFC 5639 §4.1 OID).
    EcBrainpoolP256r1(Vec<u8>),
    /// brainpoolP384r1 uncompressed SEC1 point (97 bytes; RFC 5639 §4.1 OID).
    EcBrainpoolP384r1(Vec<u8>),
    /// Ed25519 public key, 32 bytes (RFC 8410 §4).
    Ed25519(Vec<u8>),
    /// X25519 public key, 32 bytes (RFC 8410 §4).
    X25519(Vec<u8>),
    /// RSA modulus and public exponent as unsigned big-endian bytes (RFC 8017 §A.1.1).
    Rsa {
        /// The modulus `n`.
        modulus: Vec<u8>,
        /// The public exponent `e`.
        exponent: Vec<u8>,
    },
}

impl PublicKey {
    /// The DER `AlgorithmIdentifier` of the key:
    /// `id-ecPublicKey` with the named curve (RFC 5480 §2.1.1), `id-Ed25519`/`id-X25519`
    /// without parameters (RFC 8410 §3), or `rsaEncryption` with NULL (RFC 3279 §2.3.1).
    pub fn algorithm_identifier(&self) -> Vec<u8> {
        match self {
            Self::EcP256(_) => ec_public_key(oid::SECP256R1),
            Self::EcP384(_) => ec_public_key(oid::SECP384R1),
            Self::EcP521(_) => ec_public_key(oid::SECP521R1),
            Self::EcSecp256k1(_) => ec_public_key(oid::SECP256K1),
            Self::EcBrainpoolP256r1(_) => ec_public_key(oid::BRAINPOOL_P256R1),
            Self::EcBrainpoolP384r1(_) => ec_public_key(oid::BRAINPOOL_P384R1),
            Self::Ed25519(_) => der::sequence([der::oid(oid::ED25519)]),
            Self::X25519(_) => der::sequence([der::oid(oid::X25519)]),
            Self::Rsa { .. } => der::sequence([der::oid(oid::RSA_ENCRYPTION), der::null()]),
        }
    }

    /// The bits of `subjectPublicKey` (the BIT STRING contents after the unused-bits
    /// octet): the EC point, the raw Edwards key, or the DER `RSAPublicKey`.
    ///
    /// RFC 5280 §4.2.1.2 method (1) derives a key identifier as SHA-1 of these bytes.
    pub fn subject_public_key(&self) -> Vec<u8> {
        match self {
            Self::EcP256(key)
            | Self::EcP384(key)
            | Self::EcP521(key)
            | Self::EcSecp256k1(key)
            | Self::EcBrainpoolP256r1(key)
            | Self::EcBrainpoolP384r1(key)
            | Self::Ed25519(key)
            | Self::X25519(key) => key.clone(),
            Self::Rsa { modulus, exponent } => {
                der::sequence([der::integer(modulus), der::integer(exponent)])
            }
        }
    }

    /// The `namedCurve` OID of an `id-ecPublicKey` key (RFC 5480 §2.1.1), `None` for the
    /// other key types.
    pub fn named_curve(&self) -> Option<&'static [u64]> {
        match self {
            Self::EcP256(_) => Some(oid::SECP256R1),
            Self::EcP384(_) => Some(oid::SECP384R1),
            Self::EcP521(_) => Some(oid::SECP521R1),
            Self::EcSecp256k1(_) => Some(oid::SECP256K1),
            Self::EcBrainpoolP256r1(_) => Some(oid::BRAINPOOL_P256R1),
            Self::EcBrainpoolP384r1(_) => Some(oid::BRAINPOOL_P384R1),
            Self::Ed25519(_) | Self::X25519(_) | Self::Rsa { .. } => None,
        }
    }

    /// The DER `SubjectPublicKeyInfo` (RFC 5280 §4.1.2.7).
    pub fn to_der(&self) -> Vec<u8> {
        der::sequence([
            self.algorithm_identifier(),
            der::bit_string(&self.subject_public_key()),
        ])
    }
}

/// `id-ecPublicKey` with `namedCurve` parameters (RFC 5480 §2.1.1).
fn ec_public_key(curve: &[u64]) -> Vec<u8> {
    der::sequence([der::oid(oid::EC_PUBLIC_KEY), der::oid(curve)])
}

/// A distinguished name built as an `RDNSequence` (RFC 5280 §4.1.2.4).
///
/// Each attribute becomes its own single-valued relative distinguished name, in the order
/// added. Typical order is country, organization, organizational unit, common name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Name {
    attributes: Vec<(Vec<u64>, Vec<u8>)>,
}

impl Name {
    /// An empty name, which encodes as `30 00`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends `commonName` as a UTF8String (RFC 5280 §4.1.2.4 recommends UTF8String).
    pub fn common_name(self, value: &str) -> Self {
        self.attribute(oid::COMMON_NAME, der::utf8_string(value))
    }

    /// Appends `organizationName` as a UTF8String.
    pub fn organization(self, value: &str) -> Self {
        self.attribute(oid::ORGANIZATION_NAME, der::utf8_string(value))
    }

    /// Appends `organizationalUnitName` as a UTF8String.
    pub fn organizational_unit(self, value: &str) -> Self {
        self.attribute(oid::ORGANIZATIONAL_UNIT_NAME, der::utf8_string(value))
    }

    /// Appends `countryName`, a two-letter ISO 3166 code, as a PrintableString
    /// (RFC 5280 Appendix A.1, `X520countryName`).
    pub fn country(self, code: &str) -> Self {
        self.attribute(oid::COUNTRY_NAME, der::printable_string(code))
    }

    /// Appends any attribute: `value` is its complete DER element.
    pub fn attribute(mut self, oid: &[u64], value: Vec<u8>) -> Self {
        self.attributes.push((oid.to_vec(), value));
        self
    }

    /// Whether the name has no attributes.
    pub fn is_empty(&self) -> bool {
        self.attributes.is_empty()
    }

    /// The DER `Name`: `SEQUENCE OF SET OF AttributeTypeAndValue`.
    pub fn to_der(&self) -> Vec<u8> {
        der::sequence(self.attributes.iter().map(|(oid, value)| {
            der::set_of([der::sequence([der::oid(oid).as_slice(), value.as_slice()])])
        }))
    }
}

/// The `notAfter` value for "no well-defined expiration date" (RFC 5280 §4.1.2.5).
pub const NO_WELL_DEFINED_EXPIRATION: &str = "99991231235959Z";

/// A certificate validity time (RFC 5280 §4.1.2.5).
///
/// The variants hold the string to encode as given. [`Time::from_generalized`] checks a
/// GeneralizedTime string and picks the encoding RFC 5280 requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Time {
    /// UTCTime, `YYMMDDHHMMSSZ` (RFC 5280 §4.1.2.5.1).
    Utc(String),
    /// GeneralizedTime, `YYYYMMDDHHMMSSZ` (RFC 5280 §4.1.2.5.2).
    Generalized(String),
}

impl Time {
    /// Checks a `YYYYMMDDHHMMSSZ` GeneralizedTime string and encodes it as RFC 5280
    /// §4.1.2.5 requires: UTCTime for years 1950 through 2049, GeneralizedTime otherwise.
    pub fn from_generalized(text: &str) -> Result<Self, X509Error> {
        let bytes = text.as_bytes();
        let (digits, zulu) = bytes.split_at_checked(14).ok_or(X509Error::InvalidTime)?;
        if zulu != b"Z" || !digits.iter().all(u8::is_ascii_digit) {
            return Err(X509Error::InvalidTime);
        }
        let field = |range: core::ops::Range<usize>| {
            digits[range]
                .iter()
                .fold(0u32, |acc, &d| acc * 10 + u32::from(d - b'0'))
        };
        let (year, month, day) = (field(0..4), field(4..6), field(6..8));
        let (hour, minute, second) = (field(8..10), field(10..12), field(12..14));
        let in_range = (1..=12).contains(&month)
            && (1..=days_in_month(year, month)).contains(&day)
            && hour <= 23
            && minute <= 59
            && second <= 59;
        if !in_range {
            return Err(X509Error::InvalidTime);
        }
        if (1950..=2049).contains(&year) {
            Ok(Self::Utc(text[2..].to_owned()))
        } else {
            Ok(Self::Generalized(text.to_owned()))
        }
    }

    /// The DER UTCTime or GeneralizedTime element.
    pub fn to_der(&self) -> Vec<u8> {
        match self {
            Self::Utc(text) => der::utc_time(text),
            Self::Generalized(text) => der::generalized_time(text),
        }
    }
}

/// Days in `month` (1–12) of `year` in the proleptic Gregorian calendar that
/// GeneralizedTime uses (X.680 §46.2, ISO 8601): February has 29 days in years divisible by
/// 4, except centuries not divisible by 400.
fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// The certificate validity period (RFC 5280 §4.1.2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validity {
    /// Start of the validity period.
    pub not_before: Time,
    /// End of the validity period.
    pub not_after: Time,
}

impl Validity {
    /// Both times encoded as GeneralizedTime exactly as given (`YYYYMMDDHHMMSSZ`), unchecked.
    ///
    /// RFC 5280 §4.1.2.5 requires UTCTime for dates through 2049, so a certificate built this
    /// way with such a date does not conform to the profile. Prefer [`Validity::rfc5280`].
    pub fn generalized(not_before: &str, not_after: &str) -> Self {
        Self {
            not_before: Time::Generalized(not_before.to_owned()),
            not_after: Time::Generalized(not_after.to_owned()),
        }
    }

    /// Both times given as GeneralizedTime strings, checked and encoded per RFC 5280
    /// §4.1.2.5 (see [`Time::from_generalized`]).
    pub fn rfc5280(not_before: &str, not_after: &str) -> Result<Self, X509Error> {
        Ok(Self {
            not_before: Time::from_generalized(not_before)?,
            not_after: Time::from_generalized(not_after)?,
        })
    }

    /// The DER `Validity` SEQUENCE.
    pub fn to_der(&self) -> Vec<u8> {
        der::sequence([self.not_before.to_der(), self.not_after.to_der()])
    }
}

/// A certificate extension (RFC 5280 §4.1.2.9, §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// `extnID`.
    pub oid: Vec<u64>,
    /// `critical`; omitted from the encoding when false (DEFAULT FALSE, X.690 §11.5).
    pub critical: bool,
    /// The DER value wrapped by the `extnValue` OCTET STRING.
    pub value: Vec<u8>,
}

impl Extension {
    /// Any extension: `value` is the DER encoding carried inside `extnValue`.
    pub fn new(oid: &[u64], critical: bool, value: &[u8]) -> Self {
        Self {
            oid: oid.to_vec(),
            critical,
            value: value.to_vec(),
        }
    }

    /// The same extension with a different criticality.
    pub fn with_critical(mut self, critical: bool) -> Self {
        self.critical = critical;
        self
    }

    /// `basicConstraints` (RFC 5280 §4.2.1.9), marked critical.
    ///
    /// `cA` is omitted when false (DEFAULT FALSE), so an end-entity value is `30 00`, as
    /// WebAuthn §8.2.1 requires for attestation certificates. RFC 5280 §4.2.1.9 allows
    /// `path_len` only together with `ca`; that combination is the caller's job.
    pub fn basic_constraints(ca: bool, path_len: Option<u32>) -> Self {
        let mut items = Vec::new();
        if ca {
            items.push(der::boolean(true));
        }
        if let Some(path_len) = path_len {
            items.push(der::integer_u64(u64::from(path_len)));
        }
        Self::new(oid::BASIC_CONSTRAINTS, true, &der::sequence(items))
    }

    /// `keyUsage` (RFC 5280 §4.2.1.3), marked critical. `bits` combines [`key_usage`]
    /// constants.
    pub fn key_usage(bits: u16) -> Self {
        Self::new(
            oid::KEY_USAGE,
            true,
            &der::named_bit_string(u64::from(bits)),
        )
    }

    /// `subjectKeyIdentifier` from a raw key identifier (RFC 5280 §4.2.1.2), non-critical
    /// as the RFC requires.
    pub fn subject_key_identifier(key_id: &[u8]) -> Self {
        Self::new(
            oid::SUBJECT_KEY_IDENTIFIER,
            false,
            &der::octet_string(key_id),
        )
    }

    /// `authorityKeyIdentifier` with only `keyIdentifier [0]` (RFC 5280 §4.2.1.1),
    /// non-critical as the RFC requires.
    pub fn authority_key_identifier(key_id: &[u8]) -> Self {
        Self::new(
            oid::AUTHORITY_KEY_IDENTIFIER,
            false,
            &der::sequence([der::implicit(0, key_id)]),
        )
    }

    /// The FIDO AAGUID extension `id-fido-gen-ce-aaguid` (WebAuthn §8.2.1): an OCTET STRING
    /// holding the 16-byte AAGUID, inside `extnValue`. Non-critical, as WebAuthn requires.
    pub fn fido_aaguid(aaguid: &[u8; 16]) -> Self {
        Self::new(oid::FIDO_GEN_CE_AAGUID, false, &der::octet_string(aaguid))
    }

    /// The DER `Extension` SEQUENCE.
    pub fn to_der(&self) -> Vec<u8> {
        let mut items = vec![der::oid(&self.oid)];
        if self.critical {
            items.push(der::boolean(true));
        }
        items.push(der::octet_string(&self.value));
        der::sequence(items)
    }
}

/// The to-be-signed part of a version 3 certificate (RFC 5280 §4.1).
///
/// Build it as a struct literal and call [`TbsCertificate::to_der`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TbsCertificate {
    /// Serial number as an unsigned big-endian magnitude. [`der::integer`] strips leading
    /// zeros and adds the sign octet. RFC 5280 §4.1.2.2 requires a positive value of at most
    /// 20 octets (an empty or all-zero serial encodes as `INTEGER 0`); that is the caller's
    /// job.
    pub serial: Vec<u8>,
    /// The signature algorithm; must match the one later passed to [`assemble`]
    /// (RFC 5280 §4.1.2.3).
    pub signature: SignatureAlgorithm,
    /// The issuer name.
    pub issuer: Name,
    /// The validity period.
    pub validity: Validity,
    /// The subject name.
    pub subject: Name,
    /// The subject public key.
    pub public_key: PublicKey,
    /// Extensions in encoding order; the `[3]` field is omitted when empty, because
    /// `Extensions` is `SEQUENCE SIZE (1..MAX)` (RFC 5280 §4.1).
    pub extensions: Vec<Extension>,
}

impl TbsCertificate {
    /// Certificate version v3, encoded as `INTEGER 2` (RFC 5280 §4.1.2.1).
    const VERSION_V3: u64 = 2;

    /// The DER `TBSCertificate`: the bytes to sign.
    pub fn to_der(&self) -> Vec<u8> {
        let mut items = vec![
            der::explicit(0, &der::integer_u64(Self::VERSION_V3)),
            der::integer(&self.serial),
            self.signature.algorithm_identifier(),
            self.issuer.to_der(),
            self.validity.to_der(),
            self.subject.to_der(),
            self.public_key.to_der(),
        ];
        if !self.extensions.is_empty() {
            let extensions = der::sequence(self.extensions.iter().map(Extension::to_der));
            items.push(der::explicit(3, &extensions));
        }
        der::sequence(items)
    }
}

/// The final DER `Certificate` (RFC 5280 §4.1.1) from the encoded `TBSCertificate`, its
/// signature algorithm and the signature value produced by the caller.
pub fn assemble(
    tbs_der: &[u8],
    signature_algorithm: SignatureAlgorithm,
    signature: &[u8],
) -> Vec<u8> {
    let algorithm = signature_algorithm.algorithm_identifier();
    let signature = der::bit_string(signature);
    der::sequence([tbs_der, algorithm.as_slice(), signature.as_slice()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::der::tag;
    use lk_core::Entropy;
    use lk_crypto::{Curve, EcPrivateKey, Ed25519Key, RsaPrivateKey};

    fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        digits
            .chunks(2)
            .map(|pair| {
                let pair = core::str::from_utf8(pair).expect("ascii hex");
                u8::from_str_radix(pair, 16).expect("hex digit")
            })
            .collect()
    }

    /// Deterministic test entropy: SHA-256(label || counter) blocks.
    struct TestEntropy {
        label: Vec<u8>,
        counter: u64,
    }

    impl TestEntropy {
        fn new(label: &str) -> Self {
            Self {
                label: label.as_bytes().to_vec(),
                counter: 0,
            }
        }
    }

    impl Entropy for TestEntropy {
        fn fill(&mut self, out: &mut [u8]) {
            for chunk in out.chunks_mut(32) {
                let mut input = self.label.clone();
                input.extend_from_slice(&self.counter.to_be_bytes());
                self.counter += 1;
                let block = lk_crypto::sha256(&input);
                chunk.copy_from_slice(&block[..chunk.len()]);
            }
        }
    }

    // ---- parsing helpers, built only on der::parse_der and friends ---------------------

    /// The three parts of a parsed `Certificate`, all taken from the encoded bytes.
    struct ParsedCertificate<'a> {
        tbs_raw: &'a [u8],
        tbs_fields: Vec<(u8, &'a [u8])>,
        signature_algorithm: &'a [u8],
        signature: &'a [u8],
    }

    fn parse_certificate(cert: &[u8]) -> ParsedCertificate<'_> {
        let content = der::expect_only(cert, tag::SEQUENCE).expect("Certificate SEQUENCE");
        let (tbs_raw, rest) = der::split_der(content).expect("tbsCertificate");
        let (signature_algorithm, rest) = der::split_der(rest).expect("signatureAlgorithm");
        let bits = der::expect_only(rest, tag::BIT_STRING).expect("signatureValue");
        let (unused, signature) = der::decode_bit_string(bits).expect("bit string");
        assert_eq!(unused, 0);
        let tbs_content =
            der::expect_only(tbs_raw, tag::SEQUENCE).expect("TBSCertificate SEQUENCE");
        let tbs_fields = der::parse_all(tbs_content).expect("TBSCertificate fields");
        ParsedCertificate {
            tbs_raw,
            tbs_fields,
            signature_algorithm,
            signature,
        }
    }

    /// `(attribute OID, value tag, value)` for each RDN of a `Name`.
    fn parse_name(value: &[u8]) -> Vec<(Vec<u64>, u8, String)> {
        der::parse_all(value)
            .expect("RDNSequence")
            .into_iter()
            .map(|(set_tag, rdn)| {
                assert_eq!(set_tag, tag::SET);
                let atv = der::expect_only(rdn, tag::SEQUENCE).expect("AttributeTypeAndValue");
                let (oid_value, rest) = der::expect(atv, tag::OID).expect("attribute type");
                let (value_tag, text, rest) = der::parse_der(rest).expect("attribute value");
                assert!(rest.is_empty());
                let text = String::from_utf8(text.to_vec()).expect("utf-8");
                (der::decode_oid(oid_value).expect("oid"), value_tag, text)
            })
            .collect()
    }

    /// `(algorithm element, subjectPublicKey bits)` of a `SubjectPublicKeyInfo` value.
    fn parse_spki(value: &[u8]) -> (&[u8], &[u8]) {
        let (algorithm, rest) = der::split_der(value).expect("algorithm");
        let bits = der::expect_only(rest, tag::BIT_STRING).expect("subjectPublicKey");
        let (unused, key) = der::decode_bit_string(bits).expect("bit string");
        assert_eq!(unused, 0);
        (algorithm, key)
    }

    /// `(extnID, critical, extnValue contents)` for each extension in an `[3]` field value.
    fn parse_extensions(value: &[u8]) -> Vec<(Vec<u64>, bool, Vec<u8>)> {
        let list = der::expect_only(value, tag::SEQUENCE).expect("Extensions");
        der::parse_all(list)
            .expect("Extension list")
            .into_iter()
            .map(|(ext_tag, ext)| {
                assert_eq!(ext_tag, tag::SEQUENCE);
                let (oid_value, rest) = der::expect(ext, tag::OID).expect("extnID");
                let (critical, rest) = match der::expect(rest, tag::BOOLEAN) {
                    Ok((flag, rest)) => (flag == [0xFF], rest),
                    Err(_) => (false, rest),
                };
                let inner = der::expect_only(rest, tag::OCTET_STRING).expect("extnValue");
                (
                    der::decode_oid(oid_value).expect("oid"),
                    critical,
                    inner.to_vec(),
                )
            })
            .collect()
    }

    // ---- algorithm identifiers and keys ------------------------------------------------

    #[test]
    fn signature_algorithm_identifiers() {
        // RFC 5758 §3.2: ECDSA parameters absent.
        assert_eq!(
            SignatureAlgorithm::EcdsaWithSha256.algorithm_identifier(),
            hex("30 0A 06 08 2A 86 48 CE 3D 04 03 02")
        );
        assert_eq!(
            SignatureAlgorithm::EcdsaWithSha384.algorithm_identifier(),
            hex("30 0A 06 08 2A 86 48 CE 3D 04 03 03")
        );
        // RFC 5758 §3.2: ecdsa-with-SHA512 is 1.2.840.10045.4.3.4.
        assert_eq!(
            SignatureAlgorithm::EcdsaWithSha512.algorithm_identifier(),
            hex("30 0A 06 08 2A 86 48 CE 3D 04 03 04")
        );
        let sha512_null = der::sequence([der::oid(oid::ECDSA_WITH_SHA512), der::null()]);
        assert_eq!(SignatureAlgorithm::from_algorithm_identifier(&sha512_null), None);
        // RFC 8410 §3: "30 05 06 03 2B 65 70".
        assert_eq!(
            SignatureAlgorithm::Ed25519.algorithm_identifier(),
            hex("30 05 06 03 2B 65 70")
        );
        // RFC 4055 §5: sha256WithRSAEncryption with NULL parameters.
        assert_eq!(
            SignatureAlgorithm::Sha256WithRsaEncryption.algorithm_identifier(),
            hex("30 0D 06 09 2A 86 48 86 F7 0D 01 01 0B 05 00")
        );
        for alg in SignatureAlgorithm::ALL {
            assert_eq!(
                SignatureAlgorithm::from_algorithm_identifier(&alg.algorithm_identifier()),
                Some(alg)
            );
        }
        // RFC 4055 §5: absent RSA parameters must also be accepted.
        let rsa_absent = der::sequence([der::oid(oid::SHA256_WITH_RSA_ENCRYPTION)]);
        assert_eq!(
            SignatureAlgorithm::from_algorithm_identifier(&rsa_absent),
            Some(SignatureAlgorithm::Sha256WithRsaEncryption)
        );
        // RFC 5758 §3.2: ECDSA parameters MUST be absent.
        let ecdsa_null = der::sequence([der::oid(oid::ECDSA_WITH_SHA256), der::null()]);
        assert_eq!(
            SignatureAlgorithm::from_algorithm_identifier(&ecdsa_null),
            None
        );
        let unknown = der::sequence([der::oid(oid::RSA_ENCRYPTION), der::null()]);
        assert_eq!(
            SignatureAlgorithm::from_algorithm_identifier(&unknown),
            None
        );
    }

    #[test]
    fn subject_public_key_info_encodings() {
        // RFC 5480 §2: P-256 SPKI header for a 65-byte uncompressed point.
        let p256 = PublicKey::EcP256([&[0x04][..], &[0x11; 64]].concat()).to_der();
        assert_eq!(
            p256[..27],
            hex("30 59 30 13 06 07 2A 86 48 CE 3D 02 01 06 08 2A 86 48 CE 3D 03 01 07 03 42 00 04")
        );
        assert_eq!(p256.len(), 91);
        // RFC 5480 §2: P-384 header for a 97-byte point.
        let p384 = PublicKey::EcP384([&[0x04][..], &[0x22; 96]].concat()).to_der();
        assert_eq!(
            p384[..24],
            hex("30 76 30 10 06 07 2A 86 48 CE 3D 02 01 06 05 2B 81 04 00 22 03 62 00 04")
        );
        assert_eq!(p384.len(), 120);
        // RFC 8410 §10.1 example Ed25519 public key.
        let ed = hex("19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1");
        assert_eq!(
            PublicKey::Ed25519(ed).to_der(),
            hex(
                "302a300506032b657003210019bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1"
            )
        );
        // RFC 8410 §10.2 example certificate's X25519 SubjectPublicKeyInfo.
        let x = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        assert_eq!(
            PublicKey::X25519(x).to_der(),
            hex(
                "302a300506032b656e0321008520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
            )
        );
        // RFC 3279 §2.3.1 / RFC 8017 §A.1.1: rsaEncryption with NULL, RSAPublicKey {n, e};
        // n gets a sign octet because its top bit is set.
        let rsa = PublicKey::Rsa {
            modulus: vec![0xC1, 0x02],
            exponent: vec![0x01, 0x00, 0x01],
        };
        assert_eq!(
            rsa.to_der(),
            hex(
                "30 1E 30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00 03 0D 00 30 0A 02 03 00 C1 02 02 03 01 00 01"
            )
        );
        assert_eq!(
            rsa.subject_public_key(),
            hex("30 0A 02 03 00 C1 02 02 03 01 00 01")
        );
    }

    /// A `PublicKey` EC variant used as a constructor.
    type EcKeyVariant = fn(Vec<u8>) -> PublicKey;

    #[test]
    fn subject_public_key_info_for_the_other_named_curves() {
        // Project Wycheproof testvectors_v1, tcId 1 ("normal case") `public` of
        // ecdh_secp521r1_test.json, ecdh_secp256k1_test.json, ecdh_brainpoolP256r1_test.json
        // and ecdh_brainpoolP384r1_test.json: complete SubjectPublicKeyInfo values with
        // the RFC 5480 / SEC 2 / RFC 5639 named-curve OIDs.
        let cases: [(EcKeyVariant, &[u64], &str); 4] = [
            (
                PublicKey::EcP521,
                &[1, 3, 132, 0, 35],
                "30819b301006072a8648ce3d020106052b8104002303818600040064da3e94733db536a74a0d8a5cb226
                 5a31c54a1da6529a198377fbd38575d9d79769ca2bdf2d4c972642926d444891a652e7f492337251adf1
                 613cf3077999b5ce00e04ad19cf9fd4722b0c824c069f70c3c0e7ebc5288940dfa92422152ae4a4f7918
                 3ced375afb54db1409ddf338b85bb6dbfc5950163346bb63a90a70c5aba098f7",
            ),
            (
                PublicKey::EcSecp256k1,
                &[1, 3, 132, 0, 10],
                "3056301006072a8648ce3d020106052b8104000a03420004d8096af8a11e0b80037e1ee68246b5dcbb0a
                 eb1cf1244fd767db80f3fa27da2b396812ea1686e7472e9692eaf3e958e50e9500d3b4c77243db1f2acd
                 67ba9cc4",
            ),
            (
                PublicKey::EcBrainpoolP256r1,
                &[1, 3, 36, 3, 3, 2, 8, 1, 1, 7],
                "305a301406072a8648ce3d020106092b2403030208010107034200044cee5e1072b30d64f70bf01958e2
                 2c044a2127ddd744ce3060c15990ff0fe1148c6ee56559829a5a84dd5c8646ee0c43d0b7c50181f234ec
                 09eba43bc86b169e",
            ),
            (
                PublicKey::EcBrainpoolP384r1,
                &[1, 3, 36, 3, 3, 2, 8, 1, 1, 11],
                "307a301406072a8648ce3d020106092b240303020801010b0362000470ffb350173256eb437b14036584
                 2397ebaf3611b6389596c1f17c5ff5ce5201f24f6985b8fe0890dcae54b2603dfb4087242aaf7b2d95b3
                 199bfa03e8fce54ef680b57109847274db3b3a65512b7f832248e70b1030e95db6429589775c3346",
            ),
        ];
        for (variant, curve, spki) in cases {
            let spki = hex(spki);
            let content = der::expect_only(&spki, tag::SEQUENCE).expect("SubjectPublicKeyInfo");
            let (algorithm, bits) = parse_spki(content);
            let key = variant(bits.to_vec());
            assert_eq!(key.to_der(), spki, "{curve:?}");
            assert_eq!(key.algorithm_identifier(), algorithm, "{curve:?}");
            assert_eq!(key.named_curve(), Some(curve));
            assert_eq!(key.subject_public_key(), bits);
        }
        assert_eq!(oid::SECP521R1, &[1, 3, 132, 0, 35]);
        assert_eq!(oid::SECP256K1, &[1, 3, 132, 0, 10]);
        assert_eq!(oid::BRAINPOOL_P256R1, &[1, 3, 36, 3, 3, 2, 8, 1, 1, 7]);
        assert_eq!(oid::BRAINPOOL_P384R1, &[1, 3, 36, 3, 3, 2, 8, 1, 1, 11]);
        // The two NIST curves keep their OIDs; non-EC keys have no named curve.
        assert_eq!(PublicKey::EcP256(vec![]).named_curve(), Some(oid::SECP256R1));
        assert_eq!(PublicKey::EcP384(vec![]).named_curve(), Some(oid::SECP384R1));
        assert_eq!(PublicKey::Ed25519(vec![]).named_curve(), None);
        assert_eq!(PublicKey::X25519(vec![]).named_curve(), None);
        assert_eq!(PublicKey::Rsa { modulus: vec![1], exponent: vec![3] }.named_curve(), None);
    }

    // ---- names, validity, extensions ---------------------------------------------------

    #[test]
    fn names() {
        // RFC 8410 §10.2: issuer and subject "CN=IETF Test Demo".
        assert_eq!(
            Name::new().common_name("IETF Test Demo").to_der(),
            hex("3019311730150603 5504030c0e4945544620546573742044656d6f")
        );
        assert_eq!(Name::new().to_der(), [0x30, 0x00]);
        assert!(Name::new().is_empty());
        let name = Name::new()
            .country("SE")
            .organization("O")
            .organizational_unit("Authenticator Attestation");
        let parsed = parse_name(der::expect_only(&name.to_der(), tag::SEQUENCE).expect("name"));
        assert_eq!(
            parsed,
            vec![
                (
                    oid::COUNTRY_NAME.to_vec(),
                    tag::PRINTABLE_STRING,
                    "SE".to_owned()
                ),
                (
                    oid::ORGANIZATION_NAME.to_vec(),
                    tag::UTF8_STRING,
                    "O".to_owned()
                ),
                (
                    oid::ORGANIZATIONAL_UNIT_NAME.to_vec(),
                    tag::UTF8_STRING,
                    "Authenticator Attestation".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn validity_times() {
        // RFC 8410 §10.2 validity, both inside 1950..=2049 so UTCTime (RFC 5280 §4.1.2.5).
        let validity = Validity::rfc5280("20160801121924Z", "20401231235959Z").expect("validity");
        assert_eq!(
            validity.to_der(),
            hex("301e170d3136303830313132313932345a170d3430313233313233353935395a")
        );
        // RFC 5280 §4.1.2.5: 2050 and later, and the no-expiration value, use GeneralizedTime.
        assert_eq!(
            Time::from_generalized("20500101000000Z"),
            Ok(Time::Generalized("20500101000000Z".into()))
        );
        assert_eq!(
            Time::from_generalized(NO_WELL_DEFINED_EXPIRATION),
            Ok(Time::Generalized(NO_WELL_DEFINED_EXPIRATION.into()))
        );
        assert_eq!(
            Time::from_generalized("19500101000000Z"),
            Ok(Time::Utc("500101000000Z".into()))
        );
        assert_eq!(
            Time::from_generalized("19491231235959Z"),
            Ok(Time::Generalized("19491231235959Z".into()))
        );
        for bad in [
            "",
            "2016080112192Z",
            "20160801121924",
            "20161301000000Z",
            "20160800000000Z",
            "20160801240000Z",
            "20160801126000Z",
            "20160801121960Z",
            "2016080112192AZ",
            "20160801121924+0000",
            "20160801121924.5Z",
        ] {
            assert_eq!(
                Time::from_generalized(bad),
                Err(X509Error::InvalidTime),
                "{bad:?}"
            );
        }
        // The contract form keeps GeneralizedTime as given.
        assert_eq!(
            Validity::generalized("20240101000000Z", NO_WELL_DEFINED_EXPIRATION).to_der(),
            der::sequence([
                der::generalized_time("20240101000000Z"),
                der::generalized_time(NO_WELL_DEFINED_EXPIRATION)
            ])
        );
    }

    #[test]
    fn extension_encodings() {
        // RFC 5280 §4.2.1.9 with DER DEFAULT omission (X.690 §11.5): end entity is `30 00`.
        assert_eq!(
            Extension::basic_constraints(false, None).to_der(),
            hex("30 0C 06 03 55 1D 13 01 01 FF 04 02 30 00")
        );
        assert_eq!(
            Extension::basic_constraints(true, Some(0)).to_der(),
            hex("30 12 06 03 55 1D 13 01 01 FF 04 08 30 06 01 01 FF 02 01 00")
        );
        assert_eq!(
            Extension::basic_constraints(true, None).value,
            hex("30 03 01 01 FF")
        );
        // RFC 5280 §4.2.1.3: digitalSignature only.
        assert_eq!(
            Extension::key_usage(key_usage::DIGITAL_SIGNATURE).to_der(),
            hex("30 0E 06 03 55 1D 0F 01 01 FF 04 04 03 02 07 80")
        );
        assert_eq!(
            Extension::key_usage(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN).value,
            hex("03 02 01 06")
        );
        assert_eq!(
            Extension::key_usage(key_usage::DECIPHER_ONLY).value,
            hex("03 03 07 00 80")
        );
        // RFC 5280 §4.2.1.2 / §4.2.1.1: non-critical, keyIdentifier [0] IMPLICIT.
        let id = [0xAB; 20];
        assert_eq!(
            Extension::subject_key_identifier(&id).to_der(),
            [hex("30 1D 06 03 55 1D 0E 04 16 04 14"), id.to_vec()].concat()
        );
        assert_eq!(
            Extension::authority_key_identifier(&id).to_der(),
            [hex("30 1F 06 03 55 1D 23 04 18 30 16 80 14"), id.to_vec()].concat()
        );
        // WebAuthn §8.2.1: AAGUID extension, OCTET STRING in extnValue, non-critical.
        // AAGUID ff4dac45... is the device's (reference/physical-key/reference-observation.json).
        let aaguid: [u8; 16] = hex("ff4dac45ede84ec2acedcf66103f4335")
            .try_into()
            .expect("16 bytes");
        assert_eq!(
            Extension::fido_aaguid(&aaguid).to_der(),
            [
                hex("30 21 06 0B 2B 06 01 04 01 82 E5 1C 01 01 04 04 12 04 10"),
                aaguid.to_vec()
            ]
            .concat()
        );
        // Raw extension and criticality override.
        let raw = Extension::new(&[1, 2, 3], false, &der::null()).with_critical(true);
        assert_eq!(raw.to_der(), hex("30 0B 06 02 2A 03 01 01 FF 04 02 05 00"));
    }

    #[test]
    fn oid_constants_match_spec_encodings() {
        let cases: [(&[u64], &str); 9] = [
            (oid::EC_PUBLIC_KEY, "2A 86 48 CE 3D 02 01"), // RFC 5480 §2.1.1
            (oid::SECP256R1, "2A 86 48 CE 3D 03 01 07"),  // RFC 5480 §2.1.1.1
            (oid::SECP384R1, "2B 81 04 00 22"),           // RFC 5480 §2.1.1.1
            (oid::X25519, "2B 65 6E"),                    // RFC 8410 §3
            (oid::ED25519, "2B 65 70"),                   // RFC 8410 §3
            (oid::RSA_ENCRYPTION, "2A 86 48 86 F7 0D 01 01 01"), // RFC 8017 Appendix C
            (
                oid::SHA256_WITH_RSA_ENCRYPTION,
                "2A 86 48 86 F7 0D 01 01 0B",
            ), // RFC 4055 §5
            (oid::AUTHORITY_KEY_IDENTIFIER, "55 1D 23"),  // RFC 5280 §4.2.1.1
            (oid::FIDO_GEN_CE_AAGUID, "2B 06 01 04 01 82 E5 1C 01 01 04"), // WebAuthn §8.2.1
        ];
        for (arcs, expected) in cases {
            assert_eq!(der::oid_value(arcs), hex(expected), "{arcs:?}");
        }
    }

    // ---- RFC 8410 §10.2 example certificate -------------------------------------------

    /// RFC 8410 §10.2 example X25519 certificate, signed with the Ed25519 key of §10.3.
    const RFC8410_CERT: &str = "3082012c3081dfa00302010202085601474a2a8dc330300506032b6570301931
        17301506035504030c0e4945544620546573742044656d6f301e170d31363038
        30313132313932345a170d3430313233313233353935395a3019311730150603
        5504030c0e4945544620546573742044656d6f302a300506032b656e03210085
        20f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6aa3
        453043300f0603551d130101ff04053003010100300e0603551d0f0101000404
        0302030830200603551d0e010100041604149b1f5eeded043385e4f7bc623c59
        75b90bc8bb3b300506032b6570034100af2301feddc9e6ffc1cca73d74d648a4
        398082cddb69b14e4d06ecf81a25ce50d4c2c3eb746c4edd8346856ec86f3dce
        1a1865c57ac27b50a0c35007f5e7d907";

    #[test]
    fn rfc8410_example_certificate() {
        let cert = hex(RFC8410_CERT);
        let parsed = parse_certificate(&cert);
        assert_eq!(parsed.tbs_raw.len(), 226);
        assert_eq!(
            SignatureAlgorithm::from_algorithm_identifier(parsed.signature_algorithm),
            Some(SignatureAlgorithm::Ed25519)
        );

        // The signer is the RFC 8410 §10.3 private key, whose public key is the §10.1 key.
        let signer = Ed25519Key::from_seed(&hex(
            "D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842",
        ))
        .expect("seed");
        let public = hex("19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1");
        assert_eq!(signer.public().as_slice(), public.as_slice());
        assert!(lk_crypto::ed25519_verify(
            &public,
            parsed.tbs_raw,
            parsed.signature
        ));
        // Ed25519 is deterministic (RFC 8032 §5.1.6), so re-signing reproduces the signature.
        assert_eq!(signer.sign(parsed.tbs_raw).as_slice(), parsed.signature);

        // Every TBSCertificate field before the extensions is reproduced byte for byte.
        let rebuilt = TbsCertificate {
            serial: hex("5601474a2a8dc330"),
            signature: SignatureAlgorithm::Ed25519,
            issuer: Name::new().common_name("IETF Test Demo"),
            validity: Validity::rfc5280("20160801121924Z", "20401231235959Z").expect("validity"),
            subject: Name::new().common_name("IETF Test Demo"),
            public_key: PublicKey::X25519(hex(
                "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
            )),
            extensions: Vec::new(),
        };
        let tbs_content = der::expect_only(parsed.tbs_raw, tag::SEQUENCE).expect("tbs");
        let (extensions_tag, _) = parsed.tbs_fields[7];
        assert_eq!(extensions_tag, der::context_tag(3, true));
        let before_extensions = &tbs_content[..152];
        assert_eq!(
            rebuilt.to_der(),
            der::element(tag::SEQUENCE, before_extensions)
        );

        // keyUsage and subjectKeyIdentifier values match ours. The example's basicConstraints
        // spells out the DEFAULT `cA FALSE` (`30 03 01 01 00`) and its non-critical
        // extensions carry an explicit `BOOLEAN FALSE`; DER omits both (X.690 §11.5).
        let extensions = parse_extensions(parsed.tbs_fields[7].1);
        let ski = hex("9b1f5eeded043385e4f7bc623c5975b90bc8bb3b");
        assert_eq!(
            extensions,
            vec![
                (oid::BASIC_CONSTRAINTS.to_vec(), true, hex("30 03 01 01 00")),
                (
                    oid::KEY_USAGE.to_vec(),
                    false,
                    Extension::key_usage(key_usage::KEY_AGREEMENT).value
                ),
                (
                    oid::SUBJECT_KEY_IDENTIFIER.to_vec(),
                    false,
                    Extension::subject_key_identifier(&ski).value
                ),
            ]
        );
        assert_eq!(
            Extension::basic_constraints(false, None).value,
            hex("30 00")
        );
    }

    // ---- self-signed certificates built here and verified with lk-crypto ---------------

    /// Asserts the generic structure of a certificate produced by `tbs` and returns its
    /// parsed form for algorithm-specific checks.
    fn check_structure<'a>(cert: &'a [u8], tbs: &TbsCertificate) -> ParsedCertificate<'a> {
        let parsed = parse_certificate(cert);
        assert_eq!(parsed.tbs_raw, tbs.to_der().as_slice());
        let fields = &parsed.tbs_fields;
        let field_tags: Vec<u8> = fields.iter().map(|(t, _)| *t).collect();
        assert_eq!(
            field_tags,
            [
                0xA0,
                tag::INTEGER,
                tag::SEQUENCE,
                tag::SEQUENCE,
                tag::SEQUENCE,
                tag::SEQUENCE,
                tag::SEQUENCE,
                0xA3
            ]
        );
        // version v3 = INTEGER 2 (RFC 5280 §4.1.2.1)
        assert_eq!(der::expect_only(fields[0].1, tag::INTEGER), Ok(&[2u8][..]));
        assert_eq!(
            der::element(fields[1].0, fields[1].1),
            der::integer(&tbs.serial)
        );
        // inner signature == outer signatureAlgorithm (RFC 5280 §4.1.2.3)
        let inner_algorithm = der::element(fields[2].0, fields[2].1);
        assert_eq!(inner_algorithm.as_slice(), parsed.signature_algorithm);
        assert_eq!(
            SignatureAlgorithm::from_algorithm_identifier(parsed.signature_algorithm),
            Some(tbs.signature)
        );
        // validity
        let times = der::parse_all(fields[4].1).expect("validity");
        assert_eq!(times.len(), 2);
        parsed
    }

    fn fido_names() -> (Name, Name) {
        // WebAuthn §8.2.1: subject C, O, OU = "Authenticator Attestation", CN.
        let subject = Name::new()
            .country("SE")
            .organization("localkey test")
            .organizational_unit("Authenticator Attestation")
            .common_name("localkey test attestation");
        let issuer = Name::new().common_name("localkey test attestation root");
        (issuer, subject)
    }

    /// A P-256 FIDO attestation certificate shaped by WebAuthn §8.2.1, self-signed with
    /// `lk-crypto`: `(certificate, tbs, aaguid, key identifier)`.
    fn p256_attestation() -> (Vec<u8>, TbsCertificate, [u8; 16], Vec<u8>) {
        let mut entropy = TestEntropy::new("x509 p256 attestation");
        let key = EcPrivateKey::generate(Curve::P256, &mut entropy);
        let public_key = PublicKey::EcP256(key.public_uncompressed());
        let key_id = lk_crypto::sha1(&public_key.subject_public_key()).to_vec();
        // AAGUID from reference/physical-key/reference-observation.json.
        let aaguid: [u8; 16] = hex("ff4dac45ede84ec2acedcf66103f4335")
            .try_into()
            .expect("16 bytes");
        let (issuer, subject) = fido_names();
        let tbs = TbsCertificate {
            serial: hex("8F3A1C2B"),
            signature: SignatureAlgorithm::EcdsaWithSha256,
            issuer,
            validity: Validity::rfc5280("20240101000000Z", NO_WELL_DEFINED_EXPIRATION)
                .expect("validity"),
            subject,
            public_key,
            extensions: vec![
                Extension::basic_constraints(false, None),
                Extension::key_usage(key_usage::DIGITAL_SIGNATURE),
                Extension::subject_key_identifier(&key_id),
                Extension::authority_key_identifier(&key_id),
                Extension::fido_aaguid(&aaguid),
            ],
        };
        let tbs_der = tbs.to_der();
        let signature = key
            .sign_prehash(&lk_crypto::sha256(&tbs_der))
            .expect("sign");
        let cert = assemble(
            &tbs_der,
            SignatureAlgorithm::EcdsaWithSha256,
            &signature.to_der(),
        );
        (cert, tbs, aaguid, key_id)
    }

    #[test]
    fn p256_fido_attestation_certificate() {
        let (cert, tbs, aaguid, key_id) = p256_attestation();
        let parsed = check_structure(&cert, &tbs);
        let fields = &parsed.tbs_fields;
        // Serial 8F... has its top bit set, so DER adds a sign octet (X.690 §8.3.2).
        assert_eq!(fields[1].1, hex("00 8F 3A 1C 2B").as_slice());
        assert_eq!(
            parse_name(fields[3].1),
            vec![(
                oid::COMMON_NAME.to_vec(),
                tag::UTF8_STRING,
                "localkey test attestation root".to_owned()
            )]
        );
        let subject_rdns = parse_name(fields[5].1);
        let subject_oids: Vec<Vec<u64>> = subject_rdns.iter().map(|(o, _, _)| o.clone()).collect();
        assert_eq!(
            subject_oids,
            [
                oid::COUNTRY_NAME,
                oid::ORGANIZATION_NAME,
                oid::ORGANIZATIONAL_UNIT_NAME,
                oid::COMMON_NAME
            ]
        );
        assert_eq!(subject_rdns[2].2, "Authenticator Attestation");
        // RFC 5280 §4.1.2.5: 2024 as UTCTime, 9999 as GeneralizedTime.
        let times = der::parse_all(fields[4].1).expect("validity");
        assert_eq!(
            times,
            [
                (tag::UTC_TIME, &b"240101000000Z"[..]),
                (tag::GENERALIZED_TIME, &b"99991231235959Z"[..])
            ]
        );

        let (algorithm, point) = parse_spki(fields[6].1);
        assert_eq!(
            algorithm,
            hex("30 13 06 07 2A 86 48 CE 3D 02 01 06 08 2A 86 48 CE 3D 03 01 07").as_slice()
        );
        assert_eq!(point.len(), 65);
        let digest = lk_crypto::sha256(parsed.tbs_raw);
        assert!(lk_crypto::ecdsa_verify_prehash(
            Curve::P256,
            point,
            &digest,
            parsed.signature
        ));
        let mut tampered = parsed.tbs_raw.to_vec();
        tampered[20] ^= 1;
        assert!(!lk_crypto::ecdsa_verify_prehash(
            Curve::P256,
            point,
            &lk_crypto::sha256(&tampered),
            parsed.signature
        ));

        let extensions = parse_extensions(fields[7].1);
        assert_eq!(
            extensions,
            vec![
                (oid::BASIC_CONSTRAINTS.to_vec(), true, hex("30 00")),
                (oid::KEY_USAGE.to_vec(), true, hex("03 02 07 80")),
                (
                    oid::SUBJECT_KEY_IDENTIFIER.to_vec(),
                    false,
                    der::octet_string(&key_id)
                ),
                (
                    oid::AUTHORITY_KEY_IDENTIFIER.to_vec(),
                    false,
                    der::sequence([der::implicit(0, &key_id)])
                ),
                (
                    oid::FIDO_GEN_CE_AAGUID.to_vec(),
                    false,
                    der::octet_string(&aaguid)
                ),
            ]
        );
        // The AAGUID extension value is OCTET STRING(16) (WebAuthn §8.2.1).
        let aaguid_value = &extensions[4].2;
        assert_eq!(
            der::expect_only(aaguid_value, tag::OCTET_STRING),
            Ok(&aaguid[..])
        );
    }

    #[test]
    fn p384_certificate() {
        let mut entropy = TestEntropy::new("x509 p384");
        let key = EcPrivateKey::generate(Curve::P384, &mut entropy);
        let name = Name::new().common_name("localkey p384");
        let tbs = TbsCertificate {
            serial: vec![0x01],
            signature: SignatureAlgorithm::EcdsaWithSha384,
            issuer: name.clone(),
            validity: Validity::generalized("20240101000000Z", "20500101000000Z"),
            subject: name,
            public_key: PublicKey::EcP384(key.public_uncompressed()),
            extensions: vec![
                Extension::basic_constraints(true, Some(0)),
                Extension::key_usage(key_usage::KEY_CERT_SIGN),
            ],
        };
        let tbs_der = tbs.to_der();
        let signature = key
            .sign_prehash(&lk_crypto::sha384(&tbs_der))
            .expect("sign");
        let cert = assemble(
            &tbs_der,
            SignatureAlgorithm::EcdsaWithSha384,
            &signature.to_der(),
        );

        let parsed = check_structure(&cert, &tbs);
        let (algorithm, point) = parse_spki(parsed.tbs_fields[6].1);
        assert_eq!(
            algorithm,
            PublicKey::EcP384(Vec::new())
                .algorithm_identifier()
                .as_slice()
        );
        let digest = lk_crypto::sha384(parsed.tbs_raw);
        assert!(lk_crypto::ecdsa_verify_prehash(
            Curve::P384,
            point,
            &digest,
            parsed.signature
        ));
        // Validity::generalized keeps GeneralizedTime as given, even for 2024.
        let times = der::parse_all(parsed.tbs_fields[4].1).expect("validity");
        assert_eq!(times[0], (tag::GENERALIZED_TIME, &b"20240101000000Z"[..]));
    }

    #[test]
    fn certificates_on_the_other_named_curves() {
        // P-521 with ecdsa-with-SHA512 (RFC 5758 §3.2), and SHA-256 signatures by
        // secp256k1 and brainpool keys: the SPKI names the curve, the signature verifies.
        let mut entropy = TestEntropy::new("x509 other curves");
        let cases: [(Curve, EcKeyVariant, SignatureAlgorithm); 4] = [
            (Curve::P521, PublicKey::EcP521, SignatureAlgorithm::EcdsaWithSha512),
            (Curve::Secp256k1, PublicKey::EcSecp256k1, SignatureAlgorithm::EcdsaWithSha256),
            (Curve::BrainpoolP256r1, PublicKey::EcBrainpoolP256r1, SignatureAlgorithm::EcdsaWithSha256),
            (Curve::BrainpoolP384r1, PublicKey::EcBrainpoolP384r1, SignatureAlgorithm::EcdsaWithSha384),
        ];
        for (curve, variant, algorithm) in cases {
            let key = EcPrivateKey::generate(curve, &mut entropy);
            let name = Name::new().common_name("localkey other curve");
            let tbs = TbsCertificate {
                serial: vec![0x02],
                signature: algorithm,
                issuer: name.clone(),
                validity: Validity::generalized("20240101000000Z", "20500101000000Z"),
                subject: name,
                public_key: variant(key.public_uncompressed()),
                extensions: vec![Extension::key_usage(key_usage::DIGITAL_SIGNATURE)],
            };
            let tbs_der = tbs.to_der();
            let hash = match algorithm {
                SignatureAlgorithm::EcdsaWithSha512 => lk_crypto::HashAlg::Sha512,
                SignatureAlgorithm::EcdsaWithSha384 => lk_crypto::HashAlg::Sha384,
                _ => lk_crypto::HashAlg::Sha256,
            };
            let signature = key.sign_message(hash, &tbs_der).expect("sign");
            let cert = assemble(&tbs_der, algorithm, &signature.to_der());
            let parsed = check_structure(&cert, &tbs);
            assert_eq!(
                SignatureAlgorithm::from_algorithm_identifier(parsed.signature_algorithm),
                Some(algorithm)
            );
            let (spki_algorithm, point) = parse_spki(parsed.tbs_fields[6].1);
            assert_eq!(spki_algorithm, variant(Vec::new()).algorithm_identifier().as_slice());
            assert_eq!(point, key.public_uncompressed().as_slice());
            let digest = lk_crypto::digest(hash, parsed.tbs_raw);
            assert!(lk_crypto::ecdsa_verify_prehash(curve, point, &digest, parsed.signature), "{curve:?}");
        }
    }

    #[test]
    fn ed25519_self_signed_certificate() {
        let mut entropy = TestEntropy::new("x509 ed25519");
        let key = Ed25519Key::generate(&mut entropy);
        let (issuer, subject) = fido_names();
        let tbs = TbsCertificate {
            serial: hex("00 00 7F 01"),
            signature: SignatureAlgorithm::Ed25519,
            issuer,
            validity: Validity::rfc5280("20240101000000Z", "20491231235959Z").expect("validity"),
            subject,
            public_key: PublicKey::Ed25519(key.public().to_vec()),
            extensions: vec![Extension::basic_constraints(false, None)],
        };
        let tbs_der = tbs.to_der();
        let cert = assemble(&tbs_der, SignatureAlgorithm::Ed25519, &key.sign(&tbs_der));

        let parsed = check_structure(&cert, &tbs);
        // Leading zeros of the serial are stripped (X.690 §8.3.2).
        assert_eq!(parsed.tbs_fields[1].1, hex("7F 01").as_slice());
        let (algorithm, public) = parse_spki(parsed.tbs_fields[6].1);
        assert_eq!(algorithm, hex("30 05 06 03 2B 65 70").as_slice());
        assert_eq!(parsed.signature.len(), 64);
        assert!(lk_crypto::ed25519_verify(
            public,
            parsed.tbs_raw,
            parsed.signature
        ));
    }

    /// EMSA-PKCS1-v1_5 encoding of a SHA-256 digest (RFC 8017 §9.2).
    fn emsa_pkcs1_v15_sha256(digest: &[u8], k: usize) -> Vec<u8> {
        let algorithm = der::sequence([der::oid(&[2, 16, 840, 1, 101, 3, 4, 2, 1]), der::null()]);
        let digest_info = der::sequence([algorithm, der::octet_string(digest)]);
        let mut em = vec![0x00, 0x01];
        em.resize(k - digest_info.len() - 1, 0xFF);
        em.push(0x00);
        em.extend_from_slice(&digest_info);
        em
    }

    #[test]
    fn rsa_2048_self_signed_certificate() {
        // RFC 8017 §9.2 note 1: the SHA-256 DigestInfo prefix.
        let em = emsa_pkcs1_v15_sha256(&[0; 32], 256);
        assert_eq!(
            em[256 - 51..256 - 32],
            hex("30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20")
        );
        assert_eq!(em[..4], [0x00, 0x01, 0xFF, 0xFF]);

        let mut entropy = TestEntropy::new("x509 rsa 2048");
        let key = RsaPrivateKey::generate(2048, &mut entropy).expect("rsa key");
        let name = Name::new()
            .country("SE")
            .organization("localkey test")
            .common_name("localkey rsa");
        let tbs = TbsCertificate {
            serial: hex("01 23 45 67 89 AB CD EF"),
            signature: SignatureAlgorithm::Sha256WithRsaEncryption,
            issuer: name.clone(),
            validity: Validity::rfc5280("20240101000000Z", "20340101000000Z").expect("validity"),
            subject: name,
            public_key: PublicKey::Rsa {
                modulus: key.modulus(),
                exponent: key.public_exponent(),
            },
            extensions: vec![Extension::key_usage(
                key_usage::DIGITAL_SIGNATURE | key_usage::KEY_ENCIPHERMENT,
            )],
        };
        let tbs_der = tbs.to_der();
        // A 2048-bit key makes the TBSCertificate longer than 255 bytes: `30 82 ...`.
        assert_eq!(tbs_der[..2], [0x30, 0x82]);
        let em = emsa_pkcs1_v15_sha256(&lk_crypto::sha256(&tbs_der), key.size());
        let signature = key.raw_private(&em, &mut entropy).expect("sign");
        let cert = assemble(
            &tbs_der,
            SignatureAlgorithm::Sha256WithRsaEncryption,
            &signature,
        );

        let parsed = check_structure(&cert, &tbs);
        let (algorithm, key_bits) = parse_spki(parsed.tbs_fields[6].1);
        assert_eq!(
            algorithm,
            hex("30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00").as_slice()
        );
        let rsa_public = der::expect_only(key_bits, tag::SEQUENCE).expect("RSAPublicKey");
        let (n, rest) = der::expect(rsa_public, tag::INTEGER).expect("modulus");
        let e = der::expect_only(rest, tag::INTEGER).expect("exponent");
        let n = der::decode_unsigned(n).expect("n");
        let e = der::decode_unsigned(e).expect("e");
        assert_eq!(n.len(), 256);
        assert_eq!(e, [0x01, 0x00, 0x01]);
        let recovered = lk_crypto::rsa_public_op(n, e, parsed.signature).expect("public op");
        assert_eq!(
            recovered,
            emsa_pkcs1_v15_sha256(&lk_crypto::sha256(parsed.tbs_raw), n.len())
        );
    }
    // WebAuthn §8.2.1 "Packed Attestation Statement Certificate Requirements", one assertion
    // per MUST, read back from the encoded certificate.
    #[test]
    fn webauthn_packed_attestation_requirements() {
        let (cert, _, aaguid, _) = p256_attestation();
        let parsed = parse_certificate(&cert);
        let fields = &parsed.tbs_fields;

        // "Version MUST be set to 3 (which is indicated by an ASN.1 INTEGER with value 2)."
        assert_eq!(fields[0].0, der::context_tag(0, true));
        assert_eq!(der::expect_only(fields[0].1, tag::INTEGER), Ok(&[2u8][..]));

        // Subject: C (PrintableString ISO 3166 code), O (UTF8String), OU = the literal
        // "Authenticator Attestation" (UTF8String), CN (UTF8String); one attribute per RDN.
        let subject = parse_name(fields[5].1);
        assert_eq!(subject.len(), 4);
        assert_eq!(
            (subject[0].0.as_slice(), subject[0].1),
            (oid::COUNTRY_NAME, tag::PRINTABLE_STRING)
        );
        assert_eq!(subject[0].2.len(), 2);
        assert!(der::is_printable_string(&subject[0].2));
        assert_eq!(
            (subject[1].0.as_slice(), subject[1].1),
            (oid::ORGANIZATION_NAME, tag::UTF8_STRING)
        );
        assert_eq!(
            (subject[2].0.as_slice(), subject[2].1, subject[2].2.as_str()),
            (
                oid::ORGANIZATIONAL_UNIT_NAME,
                tag::UTF8_STRING,
                "Authenticator Attestation"
            )
        );
        assert_eq!(
            (subject[3].0.as_slice(), subject[3].1),
            (oid::COMMON_NAME, tag::UTF8_STRING)
        );
        for rdn in der::parse_all(fields[5].1).expect("RDNSequence") {
            assert_eq!(der::parse_all(rdn.1).expect("RDN").len(), 1);
        }

        let extensions = parse_extensions(fields[7].1);
        let find = |wanted: &[u64]| {
            let matches: Vec<_> = extensions.iter().filter(|e| e.0 == wanted).collect();
            assert_eq!(matches.len(), 1, "exactly one {wanted:?} (RFC 5280 §4.2)");
            matches[0].clone()
        };
        // "The Basic Constraints extension MUST have the CA component set to false": cA is
        // absent, so it takes its DEFAULT FALSE (RFC 5280 §4.2.1.9, X.690 §11.5).
        let (_, _, basic) = find(oid::BASIC_CONSTRAINTS);
        assert_eq!(der::expect_only(&basic, tag::SEQUENCE), Ok(&[][..]));
        // id-fido-gen-ce-aaguid: "containing the AAGUID as a 16-byte OCTET STRING. The
        // extension MUST NOT be marked as critical."
        let (_, critical, value) = find(oid::FIDO_GEN_CE_AAGUID);
        assert!(!critical);
        assert_eq!(value, [&[0x04, 0x10][..], &aaguid].concat());
        // The DER `Extension` carries no `critical` BOOLEAN at all (DEFAULT FALSE).
        let raw_extensions = der::expect_only(fields[7].1, tag::SEQUENCE).expect("Extensions");
        let aaguid_extension = der::parse_all(raw_extensions)
            .expect("Extension list")
            .into_iter()
            .find(|(_, ext)| ext.starts_with(&der::oid(oid::FIDO_GEN_CE_AAGUID)))
            .expect("AAGUID extension");
        assert_eq!(der::parse_all(aaguid_extension.1).expect("fields").len(), 2);

        // ecdsa-with-SHA256 with absent parameters, inside and outside (RFC 5758 §3.2).
        let algorithm = hex("30 0A 06 08 2A 86 48 CE 3D 04 03 02");
        assert_eq!(parsed.signature_algorithm, algorithm.as_slice());
        assert_eq!(der::element(fields[2].0, fields[2].1), algorithm);
    }

    // RFC 5280 §4.1.2.5.2 with the X.680 §46 / ISO 8601 calendar: day must exist in month.
    #[test]
    fn validity_rejects_impossible_dates() {
        for bad in [
            "20230229000000Z", // 2023 is not a leap year
            "21000229000000Z", // century not divisible by 400
            "20230230000000Z",
            "20230431000000Z",
            "20230631000000Z",
            "20230931000000Z",
            "20231131000000Z",
            "20230132000000Z",
            "20230001000000Z",
            "20230100000000Z",
        ] {
            assert_eq!(
                Time::from_generalized(bad),
                Err(X509Error::InvalidTime),
                "{bad}"
            );
        }
        for good in [
            "20240229000000Z", // leap year
            "20000229000000Z", // divisible by 400
            "20230131235959Z",
            "20230430000000Z",
            "20231231235959Z",
        ] {
            assert!(Time::from_generalized(good).is_ok(), "{good}");
        }
        assert_eq!(
            Validity::rfc5280("20230229000000Z", NO_WELL_DEFINED_EXPIRATION),
            Err(X509Error::InvalidTime)
        );
    }

    // RFC 5758 §3.2 and RFC 8410 §3: parameters MUST be absent; RFC 4055 §5: NULL or
    // absent for sha256WithRSAEncryption, nothing else.
    #[test]
    fn algorithm_identifier_rejects_wrong_parameters() {
        let rejected = [
            der::sequence([der::oid(oid::ED25519), der::null()]),
            der::sequence([der::oid(oid::ECDSA_WITH_SHA384), der::octet_string(&[])]),
            der::sequence([
                der::oid(oid::SHA256_WITH_RSA_ENCRYPTION),
                der::octet_string(&[]),
            ]),
            der::sequence([
                der::oid(oid::SHA256_WITH_RSA_ENCRYPTION),
                der::null(),
                der::null(),
            ]),
            // NULL with contents is not NULL (X.690 §8.8.2).
            der::sequence([
                der::oid(oid::SHA256_WITH_RSA_ENCRYPTION),
                der::element(der::tag::NULL, &[0]),
            ]),
            // Trailing bytes after the AlgorithmIdentifier element.
            [
                SignatureAlgorithm::Ed25519.algorithm_identifier(),
                vec![0x00],
            ]
            .concat(),
            // Not a SEQUENCE, or the OID is not first.
            der::set([der::oid(oid::ED25519)]),
            der::sequence([der::null(), der::oid(oid::ED25519)]),
            der::sequence(Vec::<Vec<u8>>::new()),
            // A key algorithm is not a signature algorithm.
            PublicKey::EcP256(Vec::new()).algorithm_identifier(),
            PublicKey::X25519(Vec::new()).algorithm_identifier(),
            // Prefix of a known OID.
            der::sequence([der::oid(&[1, 2, 840, 10045, 4, 3])]),
            Vec::new(),
        ];
        for element in &rejected {
            assert_eq!(
                SignatureAlgorithm::from_algorithm_identifier(element),
                None,
                "{element:02X?}"
            );
        }
    }

    /// Walks a certificate with the fallible readers, as a verifier would, without assuming
    /// anything about its validity.
    fn try_walk_certificate(cert: &[u8]) -> Result<(), der::DerError> {
        let content = der::expect_only(cert, tag::SEQUENCE)?;
        let (tbs_raw, rest) = der::split_der(content)?;
        let (algorithm, rest) = der::split_der(rest)?;
        let _ = SignatureAlgorithm::from_algorithm_identifier(algorithm);
        der::decode_bit_string(der::expect_only(rest, tag::BIT_STRING)?)?;
        for (field_tag, field) in der::parse_all(der::expect_only(tbs_raw, tag::SEQUENCE)?)? {
            let _ = SignatureAlgorithm::from_algorithm_identifier(&der::element(field_tag, field));
            if field_tag == tag::SEQUENCE
                && let Ok((algorithm, key)) = der::split_der(field)
            {
                let _ = SignatureAlgorithm::from_algorithm_identifier(algorithm);
                let _ = der::expect_only(key, tag::BIT_STRING).and_then(der::decode_bit_string);
            }
        }
        Ok(())
    }

    // Fixed-seed robustness test over mutated certificates (byte changes, insertions,
    // deletions, truncations): the readers never panic and whatever they accept is canonical.
    #[test]
    fn mutated_certificates_never_panic_and_parse_canonically() {
        use crate::der::tests::{XorShift, walk_canonical};

        let (p256, ..) = p256_attestation();
        let bases = [hex(RFC8410_CERT), p256];
        for base in &bases {
            assert!(walk_canonical(base, 0) > 20);
            assert_eq!(try_walk_certificate(base), Ok(()));
        }
        let mut rng = XorShift(0xce47_5eed_2026_1010);
        let mut fully_parsed = 0;
        for i in 0..6_000 {
            let mut cert = bases[i % bases.len()].clone();
            for _ in 0..=rng.next() % 3 {
                let at = (rng.next() as usize) % (cert.len() + 1);
                let byte = (rng.next() >> 8) as u8;
                match rng.next() % 4 {
                    0 if at < cert.len() => cert[at] = byte,
                    1 => cert.insert(at, byte),
                    2 if at < cert.len() => {
                        cert.remove(at);
                    }
                    _ => cert.truncate(at),
                }
            }
            walk_canonical(&cert, 0);
            if try_walk_certificate(&cert).is_ok() {
                fully_parsed += 1;
            }
        }
        assert!(fully_parsed > 100, "only {fully_parsed} mutants parsed");

        // Time strings, including non-ASCII text, never panic; accepted ones round-trip.
        let alphabet: Vec<char> = "0123456789Z+.-é ".chars().collect();
        for _ in 0..20_000 {
            let len = (rng.next() % 17) as usize;
            let text: String = (0..len)
                .map(|_| alphabet[(rng.next() >> 8) as usize % alphabet.len()])
                .collect();
            match Time::from_generalized(&text) {
                Ok(Time::Utc(utc)) => assert_eq!(utc, text[2..]),
                Ok(Time::Generalized(generalized)) => assert_eq!(generalized, text),
                Err(X509Error::InvalidTime) => {}
            }
        }
    }
}
