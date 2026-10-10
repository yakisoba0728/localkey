//! Yubico OpenPGP attestation (Yubico developer documentation "OpenPGP attestation",
//! firmware 5.2 and later): the attestation key in the fourth slot (key reference 81,
//! attributes DA, certificate FC) signs an X.509 certificate for a key generated in SIG,
//! DEC or AUT. The command is `80 FB <key ref> 00`; the certificate is written to that
//! key's certificate DO (7F21 occurrence) and read back with SELECT DATA / GET DATA, which
//! is how YubiKit's `attest_key` uses it.
//!
//! Identity: the certificates are this engine's own. The factory issuer is a fresh RSA
//! 2048 key generated on first start with a self-signed certificate (catalog
//! OpenPGP_attestation: "fresh independent own RSA2048 attestation issuer; never
//! manufacturer trust"; docs/DESIGN.md §9). Its certificate carries the firmware version
//! extension 1.3.6.1.4.1.41482.5.3 as a DER OCTET STRING of three bytes, the structure the
//! observation records for the real template (`attestation_template_public_schema`).
//!
//! The generated certificate (catalog "copied template validity/subject, random 16-byte
//! positive serial input and SHA256 RSA/EC signatures"):
//! - issuer and validity copied from the stored attestation certificate FC; if FC does not
//!   parse (deleted or opaque), the profile's issuer name and validity are used and FC is
//!   left as it is (catalog: malformed issuers are not repaired);
//! - serial: 16 bytes of host entropy as a positive INTEGER;
//! - subject `CN=<product> OPGP Attestation <SIG|DEC|AUT>`;
//! - signature sha256WithRSAEncryption (PKCS #1 v1.5) or ecdsa-with-SHA256;
//! - non-critical extensions under 1.3.6.1.4.1.41482.5 (Yubico documentation; the
//!   encodings are a public-document model, catalog "generated leaf extensions ... are
//!   public-document models"):
//!
//! | OID | Content | Encoding |
//! | --- | --- | --- |
//! | .1 | cardholder name 5B, ISO 8859-1 converted to UTF-8 | UTF8String |
//! | .2 | key source: 01 generated (imported keys are not attested) | INTEGER |
//! | .3 | firmware version | OCTET STRING (3) |
//! | .4 | key fingerprint (C7/C8/C9) | OCTET STRING (20) |
//! | .5 | key generation time (CE/CF/D0) | OCTET STRING (4) |
//! | .6 | digital signature counter, SIG only | INTEGER |
//! | .7 | device serial number | INTEGER |
//! | .8 | UIF policy byte of the key (D6/D7/D8) | OCTET STRING (1) |
//! | .9 | form factor, FIPS (80) and CSPN (40) flags zero | OCTET STRING (1) |

use lk_codec::apdu::sw;
use lk_codec::der;
use lk_codec::x509::{self, Extension, Name, SignatureAlgorithm, Validity, key_usage};
use lk_core::{DeviceProfile, Entropy, Host};
use lk_crypto::{HashAlg, RsaPrivateKey};

use crate::keys::{self, CryptoKey, DIGEST_INFO_SHA256};
use crate::objects::{MAX_CERTIFICATE, Slot};
use crate::state::State;

/// Yubico OpenPGP attestation extension arc 1.3.6.1.4.1.41482.5.
const ARC: [u64; 8] = [1, 3, 6, 1, 4, 1, 41482, 5];

/// DE status of the factory attestation key: generated on the card (spec §4.4.3.8, 01).
pub(crate) const FACTORY_ISSUER_STATUS: u8 = 0x01;

/// The factory attestation key size: RSA 2048, as the observed factory DA
/// (`01 0800 0011 00`) announces.
const FACTORY_ISSUER_BITS: usize = 2048;

/// Serial number input length (catalog: "random 16-byte positive serial input").
const SERIAL_LEN: usize = 16;

/// Bits of the form factor byte that claim FIPS (80) or CSPN (40) certification; this
/// engine claims neither (catalog: "uncertified flags are zero").
const CERTIFICATION_FLAGS: u8 = 0xC0;

fn extension_oid(n: u64) -> Vec<u64> {
    let mut oid = ARC.to_vec();
    oid.push(n);
    oid
}

/// Install a fresh attestation issuer (RSA 2048 key and self-signed certificate) in the
/// attestation slot. Called only when the application starts without readable state; an
/// application reset keeps whatever the slot holds.
pub(crate) fn provision_factory_issuer(state: &mut State, host: &mut dyn Host) {
    let profile = host.profile().clone();
    let Ok(rsa) = RsaPrivateKey::generate(FACTORY_ISSUER_BITS, host) else {
        return;
    };
    let material = keys::rsa_material(&rsa);
    let key = CryptoKey::Rsa(rsa);
    let Ok(certificate) = issuer_certificate(&key, &profile, host) else {
        return;
    };
    let slot = state.slot_mut(Slot::Att);
    slot.set_key(material, FACTORY_ISSUER_STATUS);
    slot.certificate = certificate;
}

/// The issuer name of this engine's own attestation certificates.
fn issuer_name(profile: &DeviceProfile) -> Name {
    Name::new().common_name(&format!("{} OpenPGP Attestation", profile.attestation_common_name))
}

/// Validity from the profile (RFC 5280 §4.1.2.5 encoding); a profile string that is not a
/// valid GeneralizedTime is used verbatim.
fn profile_validity(profile: &DeviceProfile) -> Vec<u8> {
    Validity::rfc5280(&profile.cert_not_before, &profile.cert_not_after)
        .unwrap_or_else(|_| Validity::generalized(&profile.cert_not_before, &profile.cert_not_after))
        .to_der()
}

fn firmware_extension(profile: &DeviceProfile) -> Extension {
    Extension::new(&extension_oid(3), false, &der::octet_string(&profile.firmware.bytes()))
}

/// The self-signed certificate of the factory issuer.
fn issuer_certificate(key: &CryptoKey, profile: &DeviceProfile, host: &mut dyn Host) -> Result<Vec<u8>, u16> {
    let name = issuer_name(profile).to_der();
    let extensions = [
        Extension::basic_constraints(true, None),
        Extension::key_usage(key_usage::KEY_CERT_SIGN),
        firmware_extension(profile),
    ];
    let algorithm = signature_algorithm(key)?;
    let tbs = tbs_certificate(
        &random_serial(host),
        algorithm,
        &name,
        &profile_validity(profile),
        &name,
        &key.x509_public_key().to_der(),
        &extensions,
    );
    let signature = sign_tbs(key, &tbs, host)?;
    Ok(x509::assemble(&tbs, algorithm, &signature))
}

/// The attestation certificate for the key in `slot` (SIG, DEC or AUT), signed by the
/// attestation key. Errors: no attested key `6A88`; an imported key `6985` (catalog:
/// "imported-key provenance rejection"); no usable attestation key `6985`; a certificate
/// above the 2048-byte certificate limit `6A84`.
pub(crate) fn attestation_certificate(state: &State, slot: Slot, host: &mut dyn Host) -> Result<Vec<u8>, u16> {
    let data = state.slot(slot);
    let material = data.key.as_ref().ok_or(sw::REF_NOT_FOUND)?;
    if data.key_status != 0x01 {
        return Err(sw::CONDITIONS);
    }
    let subject_key = material.load().ok_or(sw::UNKNOWN)?;
    let issuer = state.slot(Slot::Att);
    let issuer_key = issuer.key.as_ref().and_then(|m| m.load()).ok_or(sw::CONDITIONS)?;
    let algorithm = signature_algorithm(&issuer_key)?;

    let profile = host.profile().clone();
    let (issuer_name_der, validity) = match copied_issuer_fields(&issuer.certificate) {
        Some((subject, validity)) => (subject, validity),
        None => (issuer_name(&profile).to_der(), profile_validity(&profile)),
    };
    let subject = Name::new()
        .common_name(&format!("{} OPGP Attestation {}", profile.product, slot_label(slot)))
        .to_der();
    let tbs = tbs_certificate(
        &random_serial(host),
        algorithm,
        &issuer_name_der,
        &validity,
        &subject,
        &subject_key.x509_public_key().to_der(),
        &extensions(state, slot, &profile),
    );
    let signature = sign_tbs(&issuer_key, &tbs, host)?;
    let certificate = x509::assemble(&tbs, algorithm, &signature);
    if certificate.len() > MAX_CERTIFICATE {
        return Err(sw::NO_SPACE);
    }
    Ok(certificate)
}

fn slot_label(slot: Slot) -> &'static str {
    match slot {
        Slot::Sig => "SIG",
        Slot::Dec => "DEC",
        Slot::Aut => "AUT",
        Slot::Att => "ATT",
    }
}

/// The Yubico metadata extensions (module table).
fn extensions(state: &State, slot: Slot, profile: &DeviceProfile) -> Vec<Extension> {
    let data = state.slot(slot);
    // ISO 8859-1 maps each byte to the Unicode code point of the same value.
    let name: String = state.name.iter().map(|&b| char::from(b)).collect();
    let mut out = vec![
        Extension::new(&extension_oid(1), false, &der::utf8_string(&name)),
        Extension::new(&extension_oid(2), false, &der::integer_u64(1)),
        firmware_extension(profile),
        Extension::new(&extension_oid(4), false, &der::octet_string(&data.fingerprint)),
        Extension::new(&extension_oid(5), false, &der::octet_string(&data.generation_time)),
    ];
    if slot == Slot::Sig {
        out.push(Extension::new(&extension_oid(6), false, &der::integer_u64(u64::from(state.signature_counter))));
    }
    let policy = data.uif.first().copied().unwrap_or(0);
    out.push(Extension::new(&extension_oid(7), false, &der::integer_u64(u64::from(profile.serial))));
    out.push(Extension::new(&extension_oid(8), false, &der::octet_string(&[policy])));
    out.push(Extension::new(
        &extension_oid(9),
        false,
        &der::octet_string(&[profile.form_factor & !CERTIFICATION_FLAGS]),
    ));
    out
}

/// RFC 5280 §4.1 `TBSCertificate` (version 3) from already-encoded parts.
fn tbs_certificate(
    serial: &[u8],
    algorithm: SignatureAlgorithm,
    issuer: &[u8],
    validity: &[u8],
    subject: &[u8],
    public_key: &[u8],
    extensions: &[Extension],
) -> Vec<u8> {
    let extensions = der::sequence(extensions.iter().map(Extension::to_der));
    der::sequence([
        der::explicit(0, &der::integer_u64(2)),
        der::integer(serial),
        algorithm.algorithm_identifier(),
        issuer.to_vec(),
        validity.to_vec(),
        subject.to_vec(),
        public_key.to_vec(),
        der::explicit(3, &extensions),
    ])
}

/// 16 bytes of host entropy; never all zero, so the INTEGER is positive (RFC 5280
/// §4.1.2.2).
fn random_serial(entropy: &mut dyn Entropy) -> Vec<u8> {
    let mut serial = vec![0u8; SERIAL_LEN];
    entropy.fill(&mut serial);
    if serial.iter().all(|&b| b == 0)
        && let Some(last) = serial.last_mut()
    {
        *last = 1;
    }
    serial
}

/// The certificate signature algorithm for an issuer key (catalog: SHA-256 with RSA PKCS #1
/// v1.5 or ECDSA).
fn signature_algorithm(key: &CryptoKey) -> Result<SignatureAlgorithm, u16> {
    match key {
        CryptoKey::Rsa(_) => Ok(SignatureAlgorithm::Sha256WithRsaEncryption),
        CryptoKey::Ec(_) => Ok(SignatureAlgorithm::EcdsaWithSha256),
        CryptoKey::Ed25519(_) => Ok(SignatureAlgorithm::Ed25519),
        CryptoKey::X25519(_) => Err(sw::CONDITIONS),
    }
}

/// Sign the encoded TBSCertificate: RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017 §8.2.1),
/// ECDSA with SHA-256 as a DER `Ecdsa-Sig-Value` (RFC 5758 §3.2, hedged nonce) or Ed25519.
fn sign_tbs(key: &CryptoKey, tbs: &[u8], host: &mut dyn Host) -> Result<Vec<u8>, u16> {
    match key {
        CryptoKey::Rsa(_) => {
            let mut digest_info = DIGEST_INFO_SHA256.to_vec();
            digest_info.extend_from_slice(&lk_crypto::sha256(tbs));
            key.sign(&digest_info, host)
        }
        CryptoKey::Ec(ec) => ec
            .sign_message_hedged(HashAlg::Sha256, tbs, host)
            .map(|sig| sig.to_der())
            .map_err(|_| sw::UNKNOWN),
        CryptoKey::Ed25519(ed) => Ok(ed.sign(tbs).to_vec()),
        CryptoKey::X25519(_) => Err(sw::CONDITIONS),
    }
}

/// The subject Name and Validity elements of a DER certificate (RFC 5280 §4.1), or `None`
/// if it does not parse.
fn copied_issuer_fields(certificate: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let body = der::expect_only(certificate, der::tag::SEQUENCE).ok()?;
    let (tbs, _) = der::expect(body, der::tag::SEQUENCE).ok()?;
    // Optional `version [0] EXPLICIT` (constructed context tag 0, X.690 §8.14).
    const VERSION_TAG: u8 = 0xA0;
    let mut rest = tbs;
    if rest.first() == Some(&VERSION_TAG) {
        rest = der::split_der(rest).ok()?.1;
    }
    let (_, rest) = der::expect(rest, der::tag::INTEGER).ok()?;
    let (_, rest) = der::expect(rest, der::tag::SEQUENCE).ok()?;
    let (_, rest) = der::expect(rest, der::tag::SEQUENCE).ok()?;
    let (validity, rest) = sequence_element(rest)?;
    let (subject, _) = sequence_element(rest)?;
    Some((subject.to_vec(), validity.to_vec()))
}

/// The next element, which must be a SEQUENCE, with its tag and length.
fn sequence_element(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let (element, rest) = der::split_der(input).ok()?;
    (element.first() == Some(&der::tag::SEQUENCE)).then_some((element, rest))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn copied_fields_from_built_certificate() {
        // RFC 5280 §4.1 layout produced by tbs_certificate.
        let name = Name::new().common_name("issuer").to_der();
        let validity = Validity::rfc5280("20260101000000Z", "20300101000000Z").unwrap().to_der();
        let tbs = tbs_certificate(&[1; 16], SignatureAlgorithm::Ed25519, &name, &validity, &name, &[0x30, 0x00], &[]);
        let cert = x509::assemble(&tbs, SignatureAlgorithm::Ed25519, &[0; 64]);
        assert_eq!(copied_issuer_fields(&cert), Some((name, validity)));
        assert_eq!(copied_issuer_fields(b"att-cert"), None);
        assert_eq!(copied_issuer_fields(&[]), None);
        assert_eq!(copied_issuer_fields(&cert[..cert.len() - 1]), None);
    }

    #[test]
    fn serial_is_positive() {
        let mut zero = lk_testkit::ScriptedEntropy::new(1, [vec![0u8; 16]]);
        let serial = random_serial(&mut zero);
        assert_eq!(serial.len(), 16);
        assert_ne!(der::integer(&serial), der::integer(&[]));
    }
}
