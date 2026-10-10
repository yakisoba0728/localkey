//! This device's own attestation identity: a P-256 attestation key and its certificate,
//! used for "packed" attestation (WebAuthn L2 §8.2) and U2F registration (U2F raw message
//! formats v1.2 §4.3).
//!
//! # Choice: an own batch root plus a leaf
//!
//! On first use the authenticator generates two P-256 keys:
//!
//! - a self-signed **root** ("localkey FIDO attestation root", `cA` true, keyCertSign);
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
//! Subject values: `O = "localkey"` and `C = "ZZ"` (the ISO 3166-1 user-assigned code
//! commonly used for "unknown") for every profile. The compatibility profile reuses only
//! public identity values; manufacturer attestation is never reproduced
//! (`docs/DESIGN.md` §9, §12-2).
//!
//! The key and certificate survive `authenticatorReset`, as a hardware attestation key
//! does. They are re-issued when the profile's AAGUID or common name changes, because
//! WebAuthn L2 §8.2.1 requires the certificate AAGUID to match `authenticatorData`.

use lk_codec::x509::{
    self, Extension, NO_WELL_DEFINED_EXPIRATION, Name, PublicKey, SignatureAlgorithm,
    TbsCertificate, Validity, key_usage,
};
use lk_core::{DeviceProfile, Entropy};
use lk_crypto::{Curve, EcPrivateKey, HashAlg, sha1};

use crate::request::CtapResult;
use crate::status;

const ORGANIZATION: &str = "localkey";
const COUNTRY: &str = "ZZ";
const ATTESTATION_OU: &str = "Authenticator Attestation";
const ROOT_CN: &str = "localkey FIDO attestation root";
const FALLBACK_NOT_BEFORE: &str = "20260101000000Z";

/// The attestation key, its certificate and the issuing root's certificate.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Attestation {
    pub scalar: [u8; 32],
    pub cert: Vec<u8>,
    pub root_cert: Vec<u8>,
    /// The AAGUID and common name the certificate was issued for.
    pub aaguid: [u8; 16],
    pub common_name: String,
}

impl core::fmt::Debug for Attestation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Attestation")
            .field("cert_len", &self.cert.len())
            .field("common_name", &self.common_name)
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

        let root_key = EcPrivateKey::generate(Curve::P256, entropy);
        let root_public = root_key.public_uncompressed();
        // RFC 5280 §4.2.1.2 method (1): SHA-1 of the subjectPublicKey bits.
        let root_key_id = sha1(&root_public);
        let root_name = Name::new()
            .country(COUNTRY)
            .organization(ORGANIZATION)
            .common_name(ROOT_CN);
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
            .country(COUNTRY)
            .organization(ORGANIZATION)
            .organizational_unit(ATTESTATION_OU)
            .common_name(&profile.attestation_common_name);
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

        let scalar = key.scalar().try_into().map_err(|_| status::OTHER)?;
        Ok(Self {
            scalar,
            cert,
            root_cert,
            aaguid: profile.aaguid,
            common_name: profile.attestation_common_name.clone(),
        })
    }

    /// Whether the certificate still names `profile`'s AAGUID and common name.
    pub(crate) fn matches(&self, profile: &DeviceProfile) -> bool {
        self.aaguid == profile.aaguid && self.common_name == profile.attestation_common_name
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
