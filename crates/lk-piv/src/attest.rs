//! PIV attestation: the own attestation key and certificate in slot `F9`, and the ATTEST
//! certificates it signs.
//!
//! Sources: Yubico "PIV attestation" (developers.yubico.com/PIV/Introduction/
//! PIV_attestation.html) and the Yubico PIV extensions (ATTEST `F9`), with the model
//! profile `piv_initial_profile` / `piv_allocation_model` of
//! `reference/legacy-v0.64-profiles.json`:
//!
//! - The attestation certificate of a slot: version 3, a random 16-byte serial, issuer =
//!   the subject of the attesting (`F9`) certificate, validity copied from it, subject
//!   `"<product> PIV Attestation <slot>"`, the slot's public key, and the extensions
//!   `1.3.6.1.4.1.41482.3.3` firmware version (3 bytes), `.3.7` serial number (DER
//!   INTEGER), `.3.8` PIN policy and touch policy (2 bytes) and `.3.9` form factor (1
//!   byte). RSA issuers sign with SHA-256 and PKCS #1 v1.5, EC issuers with ECDSA-SHA256.
//! - Only keys generated on the device are attested.
//! - The device ships with an attestation key and certificate in `F9`; they survive a PIV
//!   reset and can be replaced by importing or generating a key in `F9` and storing a new
//!   certificate in `5FFF01`.
//!
//! Model policies: this engine never reproduces a manufacturer key or certification
//! claim (`docs/DESIGN.md` §9). The own issuer is an ECC P-256 key created once, before
//! first use, with a self-signed certificate named after the profile's
//! `attestation_common_name` and valid for the profile's certificate period (the
//! certificate value is charged to the object budget). After that the initialization
//! never runs again: a deleted `F9` key or certificate is not regenerated. When `5FFF01`
//! is missing or does not parse, ATTEST still answers, with the issuer name and validity
//! the own certificate would carry; a stored certificate that does not match the `F9` key
//! is used as is and verification fails on the host side.

use lk_codec::apdu::sw;
use lk_codec::der;
use lk_codec::tlv;
use lk_codec::x509::{self, Extension, Name, SignatureAlgorithm, TbsCertificate, Validity, key_usage};
use lk_core::{DeviceProfile, Entropy, Host};
use lk_crypto::{HashAlg, sha256};

use crate::keys::{KeyAlg, Origin, PinPolicy, SlotKey, TouchPolicy};
use crate::objects::{MAX_APDU_DATA, TAG_ATTESTATION};
use crate::state::{PivState, SLOT_ATTESTATION};

/// Yubico PIV attestation extensions (arc `1.3.6.1.4.1.41482.3`).
pub(crate) const OID_FIRMWARE: &[u64] = &[1, 3, 6, 1, 4, 1, 41482, 3, 3];
pub(crate) const OID_SERIAL: &[u64] = &[1, 3, 6, 1, 4, 1, 41482, 3, 7];
pub(crate) const OID_POLICY: &[u64] = &[1, 3, 6, 1, 4, 1, 41482, 3, 8];
pub(crate) const OID_FORM_FACTOR: &[u64] = &[1, 3, 6, 1, 4, 1, 41482, 3, 9];

/// Certificate container elements (SP 800-73-4 Part 1 Appendix A): `70` certificate,
/// `71` CertInfo (`00`: not compressed), `FE` error detection code (empty).
const TAG_CERTIFICATE: u32 = 0x70;
const TAG_CERT_INFO: u32 = 0x71;
const TAG_EDC: u32 = 0xFE;

/// Serial number length ("a random 16 byte integer"; profile `attestation_serial_bits`).
const SERIAL_LEN: usize = 16;

/// DigestInfo prefix of SHA-256 for EMSA-PKCS1-v1_5 (RFC 8017 §9.2, note 1).
const SHA256_DIGEST_INFO: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
];

/// A random positive serial of exactly 16 octets (RFC 5280 §4.1.2.2): the top bit is
/// cleared so the INTEGER needs no sign octet and the next bit set so it keeps 16 octets.
fn random_serial(entropy: &mut dyn Entropy) -> Vec<u8> {
    let mut serial = vec![0u8; SERIAL_LEN];
    entropy.fill(&mut serial);
    if let Some(first) = serial.first_mut() {
        *first = (*first & 0x7F) | 0x40;
    }
    serial
}

/// The own issuer's name.
fn own_name(profile: &DeviceProfile) -> Name {
    Name::new().common_name(&format!("{} PIV Attestation", profile.attestation_common_name))
}

/// The own issuer's validity: the profile's certificate period (RFC 5280 §4.1.2.5).
fn own_validity(profile: &DeviceProfile) -> Validity {
    Validity::rfc5280(&profile.cert_not_before, &profile.cert_not_after)
        .unwrap_or_else(|_| Validity::generalized(&profile.cert_not_before, &profile.cert_not_after))
}

/// The certificate signature algorithm of an issuer key, if it can sign certificates.
pub(crate) fn signature_algorithm(issuer: &SlotKey) -> Option<SignatureAlgorithm> {
    match issuer.alg {
        KeyAlg::P256 | KeyAlg::P384 => Some(SignatureAlgorithm::EcdsaWithSha256),
        alg if alg.rsa_bits().is_some() => Some(SignatureAlgorithm::Sha256WithRsaEncryption),
        _ => None,
    }
}

/// EMSA-PKCS1-v1_5 encoding of a SHA-256 digest to `len` bytes (RFC 8017 §9.2).
fn emsa_pkcs1_v15_sha256(digest: &[u8; 32], len: usize) -> Result<Vec<u8>, u16> {
    let t_len = SHA256_DIGEST_INFO.len() + digest.len();
    if len < t_len + 11 {
        return Err(sw::UNKNOWN);
    }
    let mut em = vec![0x00, 0x01];
    em.resize(len - t_len - 1, 0xFF);
    em.push(0x00);
    em.extend_from_slice(&SHA256_DIGEST_INFO);
    em.extend_from_slice(digest);
    Ok(em)
}

/// Sign `tbs` with the issuer key: ECDSA-SHA256 with a hedged nonce (FIPS 186-5 §6.4.1;
/// DER `Ecdsa-Sig-Value`, RFC 5758 §3.2) or RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017
/// §8.2.1).
fn sign(issuer: &SlotKey, tbs: &[u8], entropy: &mut dyn Entropy) -> Result<Vec<u8>, u16> {
    match issuer.alg {
        KeyAlg::P256 | KeyAlg::P384 => {
            let signature =
                issuer.ec_key()?.sign_message_hedged(HashAlg::Sha256, tbs, entropy).map_err(|_| sw::UNKNOWN)?;
            Ok(signature.to_der())
        }
        alg if alg.rsa_bits().is_some() => {
            let key = issuer.rsa_key()?;
            let em = emsa_pkcs1_v15_sha256(&sha256(tbs), key.size())?;
            key.raw_private(&em, entropy).map_err(|_| sw::UNKNOWN)
        }
        _ => Err(sw::INCORRECT_DATA),
    }
}

/// The value of a certificate container holding `cert` (SP 800-73-4 Part 1 Appendix A).
pub(crate) fn certificate_object(cert: &[u8]) -> Vec<u8> {
    let mut out = tlv::encode(TAG_CERTIFICATE, cert);
    tlv::encode_into(&mut out, TAG_CERT_INFO, &[0x00]);
    tlv::encode_into(&mut out, TAG_EDC, &[]);
    out
}

/// A self-signed CA certificate for the own issuer key (RFC 5280 §4.2.1.9 basic
/// constraints `cA`, §4.2.1.3 key usage `keyCertSign`).
fn self_signed_certificate(key: &SlotKey, profile: &DeviceProfile, entropy: &mut dyn Entropy) -> Result<Vec<u8>, u16> {
    let alg = signature_algorithm(key).ok_or(sw::INCORRECT_DATA)?;
    let name = own_name(profile);
    let tbs = TbsCertificate {
        serial: random_serial(entropy),
        signature: alg,
        issuer: name.clone(),
        validity: own_validity(profile),
        subject: name,
        public_key: key.x509_public(),
        extensions: vec![Extension::basic_constraints(true, None), Extension::key_usage(key_usage::KEY_CERT_SIGN)],
    }
    .to_der();
    let signature = sign(key, &tbs, entropy)?;
    Ok(x509::assemble(&tbs, alg, &signature))
}

/// Create the own attestation key and certificate unless that was done before (profile
/// `attestation_initialization`: "initialized before first use; certificate value charged
/// to budget"). An existing `F9` key or `5FFF01` certificate (from a record written before
/// this field existed) is kept. A certificate that would exceed the object budget, or be
/// longer than any PUT DATA could write (3072 bytes), is not stored. Returns whether `state` changed.
pub(crate) fn initialize(state: &mut PivState, host: &mut dyn Host) -> bool {
    if state.attestation_initialized {
        return false;
    }
    if !state.slots.contains_key(&SLOT_ATTESTATION)
        && let Ok(key) = SlotKey::generate(KeyAlg::P256, PinPolicy::Never, TouchPolicy::Never, host)
    {
        state.slots.insert(SLOT_ATTESTATION, key);
    }
    if state.objects.get(TAG_ATTESTATION).is_none()
        && let Some(issuer) = state.slots.get(&SLOT_ATTESTATION)
    {
        let profile = host.profile().clone();
        if let Ok(cert) = self_signed_certificate(issuer, &profile, host) {
            let value = certificate_object(&cert);
            // An object longer than a PUT DATA could write would make the record
            // unreadable on load (`state::PivState::decode`).
            if value.len() <= MAX_APDU_DATA && state.objects.fits(TAG_ATTESTATION, value.len()) {
                state.objects.put(TAG_ATTESTATION, value);
            }
        }
    }
    state.attestation_initialized = true;
    true
}

/// The subject Name and Validity of the certificate in an attestation certificate
/// container, as raw DER elements (RFC 5280 §4.1: `TBSCertificate` fields 1-6).
fn issuer_fields(container: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut rest = container;
    let cert = loop {
        let (item, next) = tlv::parse_one(rest).ok()?;
        if item.tag == TAG_CERTIFICATE {
            break item.value;
        }
        rest = next;
    };
    let certificate = der::expect_only(cert, der::tag::SEQUENCE).ok()?;
    let (mut fields, _) = der::expect(certificate, der::tag::SEQUENCE).ok()?;
    let (first, after) = der::split_der(fields).ok()?;
    if first.first() == Some(&der::context_tag(0, true)) {
        fields = after;
    }
    let (_serial, fields) = der::expect(fields, der::tag::INTEGER).ok()?;
    let (_signature, fields) = der::expect(fields, der::tag::SEQUENCE).ok()?;
    let (_issuer, fields) = der::expect(fields, der::tag::SEQUENCE).ok()?;
    let (validity, fields) = der::split_der(fields).ok()?;
    let (subject, _) = der::split_der(fields).ok()?;
    let times = der::parse_all(der::expect_only(validity, der::tag::SEQUENCE).ok()?).ok()?;
    let times_ok = times.len() == 2
        && times.iter().all(|(tag, _)| *tag == der::tag::UTC_TIME || *tag == der::tag::GENERALIZED_TIME);
    der::expect_only(subject, der::tag::SEQUENCE).ok()?;
    times_ok.then(|| (subject.to_vec(), validity.to_vec()))
}

/// The attestation certificate for the key in `slot` (Yubico ATTEST).
///
/// - Empty slot, or no key in `F9`: `6A88`.
/// - Imported key: `6A80` (Yubico: only keys generated on the device are attested; the
///   status word is model policy, physical status unmeasured).
pub(crate) fn attestation_certificate(
    state: &PivState,
    slot: u8,
    profile: &DeviceProfile,
    entropy: &mut dyn Entropy,
) -> Result<Vec<u8>, u16> {
    let key = state.slots.get(&slot).ok_or(sw::REF_NOT_FOUND)?;
    if key.origin != Origin::Generated {
        return Err(sw::INCORRECT_DATA);
    }
    let issuer = state.slots.get(&SLOT_ATTESTATION).ok_or(sw::REF_NOT_FOUND)?;
    let alg = signature_algorithm(issuer).ok_or(sw::REF_NOT_FOUND)?;
    let (issuer_name, validity) = state
        .objects
        .get(TAG_ATTESTATION)
        .and_then(issuer_fields)
        .unwrap_or_else(|| (own_name(profile).to_der(), own_validity(profile).to_der()));
    let subject = Name::new().common_name(&format!("{} PIV Attestation {slot:02x}", profile.product));
    let extensions = [
        Extension::new(OID_FIRMWARE, false, &profile.firmware.bytes()),
        Extension::new(OID_SERIAL, false, &der::integer(&profile.serial.to_be_bytes())),
        Extension::new(OID_POLICY, false, &[key.pin.byte(), key.touch.byte()]),
        Extension::new(OID_FORM_FACTOR, false, &[profile.form_factor]),
    ];
    let tbs = der::sequence([
        der::explicit(0, &der::integer_u64(2)),
        der::integer(&random_serial(entropy)),
        alg.algorithm_identifier(),
        issuer_name,
        validity,
        subject.to_der(),
        key.x509_public().to_der(),
        der::explicit(3, &der::sequence(extensions.iter().map(Extension::to_der))),
    ]);
    let signature = sign(issuer, &tbs, entropy)?;
    Ok(x509::assemble(&tbs, alg, &signature))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs1_v15_layout() {
        // RFC 8017 §9.2 step 5: EM = 00 01 PS 00 T, PS at least 8 bytes of FF.
        let em = emsa_pkcs1_v15_sha256(&[0xAB; 32], 256).unwrap_or_default();
        assert_eq!(em.len(), 256);
        assert_eq!(em.get(..2), Some(&[0x00, 0x01][..]));
        let t_start = 256 - 51;
        assert!(em.get(2..t_start - 1).is_some_and(|ps| ps.iter().all(|&b| b == 0xFF)));
        assert_eq!(em.get(t_start - 1), Some(&0x00));
        assert_eq!(em.get(t_start..t_start + 19), Some(&SHA256_DIGEST_INFO[..]));
        assert_eq!(emsa_pkcs1_v15_sha256(&[0; 32], 61), Err(sw::UNKNOWN));
    }

    #[test]
    fn serial_is_sixteen_positive_octets() {
        struct Ones;
        impl Entropy for Ones {
            fn fill(&mut self, out: &mut [u8]) {
                out.fill(0xFF);
            }
        }
        let serial = random_serial(&mut Ones);
        assert_eq!(serial.len(), 16);
        assert_eq!(serial.first(), Some(&0x7F));
        // INTEGER with no sign octet: 02 10 ...
        assert_eq!(der::integer(&serial).get(..2), Some(&[0x02, 0x10][..]));
    }
}
