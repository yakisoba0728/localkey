//! This device's own attestation identity: a P-256 attestation key and its certificate,
//! used for "packed" attestation (WebAuthn L2 §8.2) and U2F registration (U2F raw message
//! formats v1.2 §4.3).
//!
//! # Choice: an own batch root plus a leaf
//!
//! On first use the authenticator generates two P-256 keys:
//!
//! - a self-signed **root** (`CN = "<O> FIDO attestation root"`, `cA` true, keyCertSign);
//!   its private key signs the leaf once and is then discarded, like an offline batch CA.
//!   Its certificate is kept so that tools can install it as the attestation trust anchor
//!   (WebAuthn L2 §6.5.2 "trust path"); it is not sent in `x5c`, because trust anchors are
//!   omitted from the chain;
//! - the **attestation leaf**, whose key signs attestation statements. It meets WebAuthn L2
//!   §8.2.1: version 3; subject `C`, `O`, `OU = "Authenticator Attestation"`, `CN` =
//!   `DeviceProfile::attestation_common_name`; basic constraints `cA` false (critical);
//!   the `id-fido-gen-ce-aaguid` extension (non-critical) carrying the profile AAGUID.
//!
//! A two-level chain is how hardware batches are attested, and a root with `cA` true is
//! a valid RFC 5280 trust anchor, whereas a self-signed leaf with `cA` false is not.
//!
//! Subject values come from the profile (`docs/CONTRACTS.md`, lk-core additions):
//! `O = DeviceProfile::attestation_organization` and
//! `C = DeviceProfile::attestation_country`. Both built-in profiles use `"localkey"` and
//! `"ZZ"` (the ISO 3166-1 user-assigned code commonly used for "unknown"): the
//! compatibility profile reuses only public identity values and manufacturer attestation
//! is never reproduced (`docs/DESIGN.md` §9, §12-2). Model policy for unusable profile
//! values, so that a profile can never produce an invalid certificate: an empty
//! organization becomes `"localkey"` and one longer than `ub-organization-name` (64
//! characters, RFC 5280 Appendix A.1) is cut to 64 characters; a country that is not two
//! ASCII capital letters (`X520countryName`, PrintableString of size 2 holding an
//! ISO 3166 alpha-2 code, RFC 5280 Appendix A.1) becomes `"ZZ"`. The leaf's
//! `CN = DeviceProfile::attestation_common_name` follows the same rule as the organization
//! (`X520CommonName` is `SIZE (1..ub-common-name)`, 64 characters, RFC 5280 Appendix A.1):
//! empty becomes `"localkey software authenticator"`, longer is cut to 64 characters.
//!
//! The key and certificate survive `authenticatorReset`, as a hardware attestation key
//! does. They are re-issued when the profile's AAGUID, common name, organization or
//! country changes, because WebAuthn L2 §8.2.1 requires the certificate AAGUID to match
//! `authenticatorData` and the subject to name the authenticator.

use lk_codec::x509::{
    self, Extension, NO_WELL_DEFINED_EXPIRATION, Name, PublicKey, SignatureAlgorithm,
    TbsCertificate, Validity, key_usage,
};
use lk_core::{DeviceProfile, Entropy};
use lk_crypto::{Curve, EcPrivateKey, HashAlg, SecretBytes, sha1};

use crate::request::CtapResult;
use crate::status;

/// Organization used when the profile's is empty, and the one certificates issued before
/// the subject came from the profile carry (`state` loads records without it as this).
pub(crate) const DEFAULT_ORGANIZATION: &str = "localkey";
/// Country used when the profile's is not an ISO 3166 alpha-2 code, and the one older
/// certificates carry.
pub(crate) const DEFAULT_COUNTRY: &str = "ZZ";
/// `ub-organization-name` (RFC 5280 Appendix A.1), in characters.
const MAX_ORGANIZATION_CHARS: usize = 64;
/// `ub-common-name` (RFC 5280 Appendix A.1), in characters.
const MAX_COMMON_NAME_CHARS: usize = 64;
/// Leaf common name used when the profile's is empty (the `DeviceProfile::own` value).
const DEFAULT_COMMON_NAME: &str = "localkey software authenticator";
const ATTESTATION_OU: &str = "Authenticator Attestation";
const ROOT_CN_SUFFIX: &str = " FIDO attestation root";
const FALLBACK_NOT_BEFORE: &str = "20260101000000Z";

/// The organization for `profile` (see the module documentation).
fn organization(profile: &DeviceProfile) -> String {
    let org = profile.attestation_organization.as_str();
    if org.is_empty() {
        DEFAULT_ORGANIZATION.to_owned()
    } else {
        org.chars().take(MAX_ORGANIZATION_CHARS).collect()
    }
}

/// The country code for `profile` (see the module documentation).
fn country(profile: &DeviceProfile) -> String {
    let code = profile.attestation_country.as_str();
    if code.len() == 2 && code.bytes().all(|b| b.is_ascii_uppercase()) {
        code.to_owned()
    } else {
        DEFAULT_COUNTRY.to_owned()
    }
}

/// The leaf's common name for `profile` (see the module documentation).
fn common_name(profile: &DeviceProfile) -> String {
    let cn = profile.attestation_common_name.as_str();
    if cn.is_empty() {
        DEFAULT_COMMON_NAME.to_owned()
    } else {
        cn.chars().take(MAX_COMMON_NAME_CHARS).collect()
    }
}

/// The root's common name, cut to `ub-common-name` (64 characters, RFC 5280 Appendix A.1).
fn root_common_name(organization: &str) -> String {
    format!("{organization}{ROOT_CN_SUFFIX}")
        .chars()
        .take(MAX_COMMON_NAME_CHARS)
        .collect()
}

/// The attestation key, its certificate and the issuing root's certificate.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Attestation {
    /// The P-256 attestation private scalar (32 bytes), wiped when dropped.
    pub scalar: SecretBytes,
    pub cert: Vec<u8>,
    pub root_cert: Vec<u8>,
    /// The AAGUID and subject values the certificate was issued for.
    pub aaguid: [u8; 16],
    pub common_name: String,
    pub organization: String,
    pub country: String,
}

impl core::fmt::Debug for Attestation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Attestation")
            .field("cert_len", &self.cert.len())
            .field("common_name", &self.common_name)
            .field("organization", &self.organization)
            .field("country", &self.country)
            .finish_non_exhaustive()
    }
}

impl Attestation {
    /// Generate a root and an attestation leaf for `profile` (see the module documentation).
    pub(crate) fn generate(profile: &DeviceProfile, entropy: &mut dyn Entropy) -> CtapResult<Self> {
        // RFC 5280 §4.1.2.5; a profile with unusable times falls back to fixed defaults.
        let validity = Validity::rfc5280(&profile.cert_not_before, &profile.cert_not_after)
            .or_else(|_| Validity::rfc5280(FALLBACK_NOT_BEFORE, NO_WELL_DEFINED_EXPIRATION))
            .map_err(|_| status::OTHER)?;

        let organization = organization(profile);
        let country = country(profile);
        let common_name = common_name(profile);
        let root_key = EcPrivateKey::generate(Curve::P256, entropy);
        let root_public = root_key.public_uncompressed();
        // RFC 5280 §4.2.1.2 method (1): SHA-1 of the subjectPublicKey bits.
        let root_key_id = sha1(&root_public);
        let root_name = Name::new()
            .country(&country)
            .organization(&organization)
            .common_name(&root_common_name(&organization));
        let root_tbs = TbsCertificate {
            serial: serial(entropy),
            signature: SignatureAlgorithm::EcdsaWithSha256,
            issuer: root_name.clone(),
            validity: validity.clone(),
            subject: root_name.clone(),
            public_key: PublicKey::EcP256(root_public),
            extensions: vec![
                Extension::basic_constraints(true, Some(0)),
                Extension::key_usage(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN),
                Extension::subject_key_identifier(&root_key_id),
            ],
        }
        .to_der();
        let root_sig = root_key
            .sign_message_hedged(HashAlg::Sha256, &root_tbs, entropy)
            .map_err(|_| status::OTHER)?;
        let root_cert = x509::assemble(
            &root_tbs,
            SignatureAlgorithm::EcdsaWithSha256,
            &root_sig.to_der(),
        );

        let key = EcPrivateKey::generate(Curve::P256, entropy);
        let public = key.public_uncompressed();
        let subject = Name::new()
            .country(&country)
            .organization(&organization)
            .organizational_unit(ATTESTATION_OU)
            .common_name(&common_name);
        let tbs = TbsCertificate {
            serial: serial(entropy),
            signature: SignatureAlgorithm::EcdsaWithSha256,
            issuer: root_name,
            validity,
            subject,
            public_key: PublicKey::EcP256(public.clone()),
            extensions: vec![
                Extension::basic_constraints(false, None),
                Extension::key_usage(key_usage::DIGITAL_SIGNATURE),
                Extension::subject_key_identifier(&sha1(&public)),
                Extension::authority_key_identifier(&root_key_id),
                Extension::fido_aaguid(&profile.aaguid),
            ],
        }
        .to_der();
        let sig = root_key
            .sign_message_hedged(HashAlg::Sha256, &tbs, entropy)
            .map_err(|_| status::OTHER)?;
        let cert = x509::assemble(&tbs, SignatureAlgorithm::EcdsaWithSha256, &sig.to_der());

        Ok(Self {
            scalar: SecretBytes::from_slice(key.scalar()),
            cert,
            root_cert,
            aaguid: profile.aaguid,
            common_name,
            organization,
            country,
        })
    }

    /// Whether the certificate still names `profile`'s AAGUID, common name, organization
    /// and country (the last three after the fallbacks of the module documentation).
    pub(crate) fn matches(&self, profile: &DeviceProfile) -> bool {
        self.aaguid == profile.aaguid
            && self.common_name == common_name(profile)
            && self.organization == organization(profile)
            && self.country == country(profile)
    }

    /// Whether the stored scalar is a valid P-256 key (checked when state is loaded).
    pub(crate) fn is_valid(&self) -> bool {
        EcPrivateKey::from_scalar(Curve::P256, &self.scalar).is_ok() && !self.cert.is_empty()
    }

    /// ECDSA P-256/SHA-256 signature, DER encoded, with a hedged nonce (WebAuthn L2 §8.2
    /// "sig"; U2F raw message formats v1.2 §4.3 "signature").
    pub(crate) fn sign(&self, message: &[u8], entropy: &mut dyn Entropy) -> CtapResult<Vec<u8>> {
        let key =
            EcPrivateKey::from_scalar(Curve::P256, &self.scalar).map_err(|_| status::OTHER)?;
        key.sign_message_hedged(HashAlg::Sha256, message, entropy)
            .map(|s| s.to_der())
            .map_err(|_| status::OTHER)
    }
}

/// A random positive certificate serial of 16 octets (RFC 5280 §4.1.2.2: positive, at
/// most 20 octets, unique per issuer).
fn serial(entropy: &mut dyn Entropy) -> Vec<u8> {
    let mut serial = vec![0u8; 16];
    entropy.fill(&mut serial);
    if let Some(first) = serial.first_mut() {
        *first = (*first & 0x7F) | 0x40;
    }
    serial
}
