//! X.509 certificates for SCP11: reading the OCE certificates that PERFORM SECURITY
//! OPERATION uploads, checking one link of a chain, and building the Security Domain's
//! own self-signed SCP11b certificate.
//!
//! Sources:
//! - RFC 5280 §4.1 (certificate structure), §4.1.1.2 (outer and inner algorithm
//!   identifiers must match), §4.1.2.2 (serial at most 20 octets), §4.1.2.5 (UTCTime and
//!   GeneralizedTime), §4.2 (extensions: a critical extension that is not recognised
//!   rejects the certificate; an extension appears at most once), §4.2.1.1/§4.2.1.2
//!   (key identifiers), §4.2.1.3 (keyUsage), §4.2.1.4 (certificatePolicies), §4.2.1.9
//!   (basicConstraints), §6.1.4 (l)-(n) (path length processing).
//! - RFC 5480 §2.1.1 (id-ecPublicKey with the secp256r1 named curve), RFC 5758 §3.2
//!   (ecdsa-with-SHA256, parameters absent), X.690 (DER, through `lk_codec::der`).
//! - GP Card Specification v2.3.1 Amendment F (SCP11) §7.5: the OCE certificate chain
//!   is checked certificate by certificate against the CA-KLOC public key; the last
//!   certificate carries the OCE key-agreement key.
//! - `reference/BEHAVIOR_CATALOG.md` SecurityDomain_profile, SecurityDomain_incremental_pso
//!   and SecurityDomain_allowlist for the checks applied at each prefix.
//!
//! Model limits (recorded in `docs/catalog/sd.md`):
//! - Only P-256 keys and ecdsa-with-SHA256 signatures are accepted: the Security Domain
//!   holds P-256 keys only (key parameter reference `00`).
//! - There is no wall clock in the engine (`docs/DESIGN.md` §4). Validity periods are
//!   checked for form and order (notBefore <= notAfter), and notAfter against the
//!   earliest the current time can be (the profile's certificate start date,
//!   [`earliest_now`]); a notBefore in the future cannot be detected.
//! - A critical certificatePolicies extension is processed as RFC 5280 §6.1 does with
//!   the initial policy set anyPolicy: any policy identifier is accepted, policy
//!   qualifiers are not supported and reject the certificate. GP role policy
//!   identifiers are not mapped to chain positions.

use lk_codec::der::{self, tag};
use lk_codec::x509::{self, Extension, Name, PublicKey, SignatureAlgorithm, TbsCertificate, Validity, key_usage};
use lk_core::Host;
use lk_crypto::{Curve, EcPrivateKey, HashAlg};

/// Object identifiers (RFC 5280 §4.2.1, RFC 5480 §2.1.1).
mod oid {
    pub(super) const SUBJECT_KEY_IDENTIFIER: &[u64] = &[2, 5, 29, 14];
    pub(super) const KEY_USAGE: &[u64] = &[2, 5, 29, 15];
    pub(super) const BASIC_CONSTRAINTS: &[u64] = &[2, 5, 29, 19];
    pub(super) const CERTIFICATE_POLICIES: &[u64] = &[2, 5, 29, 32];
    pub(super) const AUTHORITY_KEY_IDENTIFIER: &[u64] = &[2, 5, 29, 35];
    pub(super) const EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];
    pub(super) const SECP256R1: &[u64] = &[1, 2, 840, 10045, 3, 1, 7];
}

/// The certificate is not well-formed DER/X.509 (answered `6A80`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Malformed;

/// A parsed certificate. Only what the chain checks need is kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Certificate {
    /// The raw `TBSCertificate` element (the signed bytes).
    tbs: Vec<u8>,
    /// The signature as raw `r || s`, 32 bytes each.
    signature: [u8; 64],
    /// The signature algorithm is ecdsa-with-SHA256.
    ecdsa_sha256: bool,
    /// Certificate version (0 = v1, 2 = v3).
    version: u8,
    /// Serial number magnitude without leading zero bytes (`[0]` for zero).
    pub(crate) serial: Vec<u8>,
    issuer: Vec<u8>,
    subject: Vec<u8>,
    not_before: u64,
    not_after: u64,
    /// The subject key if it is a valid P-256 point.
    pub(crate) public_key: Option<Vec<u8>>,
    ca: bool,
    path_len: Option<u32>,
    key_usage: Option<u16>,
    ski: Option<Vec<u8>>,
    aki: Option<Vec<u8>>,
    /// A critical certificatePolicies extension carries policy qualifiers.
    unsupported_qualifiers: bool,
    /// A critical extension this reader does not recognise.
    unknown_critical: bool,
}

/// The state carried from one certificate to the next while a chain is checked: the
/// key that must have signed the next certificate, its subject key identifier (for the
/// AKI binding) and the remaining number of intermediate CAs allowed (`None` =
/// unlimited; RFC 5280 §6.1.4 `max_path_length`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Link {
    pub(crate) point: Vec<u8>,
    pub(crate) ski: Option<Vec<u8>>,
    pub(crate) budget: Option<u32>,
}

impl Certificate {
    /// Parse one DER certificate filling all of `input`.
    pub(crate) fn parse(input: &[u8]) -> Result<Self, Malformed> {
        let content = der::expect_only(input, tag::SEQUENCE).map_err(|_| Malformed)?;
        let (tbs, rest) = der::split_der(content).map_err(|_| Malformed)?;
        let (outer_alg, rest) = der::split_der(rest).map_err(|_| Malformed)?;
        let sig_bits = der::expect_only(rest, tag::BIT_STRING).map_err(|_| Malformed)?;
        let (unused, sig_der) = der::decode_bit_string(sig_bits).map_err(|_| Malformed)?;
        if unused != 0 {
            return Err(Malformed);
        }
        let signature = parse_ecdsa_signature(sig_der)?;
        let body = der::expect_only(tbs, tag::SEQUENCE).map_err(|_| Malformed)?;
        let elements = der::parse_all(body).map_err(|_| Malformed)?;
        let mut items = elements.iter().peekable();

        let mut version = 0u8;
        if let Some((0xA0, value)) = items.peek() {
            let v = der::expect_only(value, tag::INTEGER).map_err(|_| Malformed)?;
            version = match der::decode_unsigned(v).map_err(|_| Malformed)? {
                [v @ 0..=2] => *v,
                _ => return Err(Malformed),
            };
            items.next();
        }
        let serial = match items.next() {
            Some((tag::INTEGER, value)) => normalize_serial(der::decode_unsigned(value).map_err(|_| Malformed)?)?,
            _ => return Err(Malformed),
        };
        // RFC 5280 §4.1.2.3: the inner algorithm identifier equals the outer one.
        let inner_alg = match items.next() {
            Some((tag::SEQUENCE, value)) => der::sequence([*value]),
            _ => return Err(Malformed),
        };
        if inner_alg != outer_alg {
            return Err(Malformed);
        }
        let ecdsa_sha256 = SignatureAlgorithm::from_algorithm_identifier(outer_alg) == Some(SignatureAlgorithm::EcdsaWithSha256);
        let issuer = match items.next() {
            Some((tag::SEQUENCE, value)) => value.to_vec(),
            _ => return Err(Malformed),
        };
        let (not_before, not_after) = match items.next() {
            Some((tag::SEQUENCE, value)) => parse_validity(value)?,
            _ => return Err(Malformed),
        };
        let subject = match items.next() {
            Some((tag::SEQUENCE, value)) => value.to_vec(),
            _ => return Err(Malformed),
        };
        let public_key = match items.next() {
            Some((tag::SEQUENCE, value)) => parse_spki(value)?,
            _ => return Err(Malformed),
        };
        let mut cert = Certificate {
            tbs: tbs.to_vec(),
            signature,
            ecdsa_sha256,
            version,
            serial,
            issuer,
            subject,
            not_before,
            not_after,
            public_key,
            ca: false,
            path_len: None,
            key_usage: None,
            ski: None,
            aki: None,
            unsupported_qualifiers: false,
            unknown_critical: false,
        };
        // issuerUniqueID [1] and subjectUniqueID [2] (v2/v3) are skipped.
        while let Some((t, _)) = items.peek() {
            if matches!(*t, 0x81 | 0xA1 | 0x82 | 0xA2) && version >= 1 {
                items.next();
            } else {
                break;
            }
        }
        if let Some((0xA3, value)) = items.peek() {
            if version != 2 {
                return Err(Malformed);
            }
            let list = der::expect_only(value, tag::SEQUENCE).map_err(|_| Malformed)?;
            cert.read_extensions(list)?;
            items.next();
        }
        if items.next().is_some() {
            return Err(Malformed);
        }
        Ok(cert)
    }

    /// RFC 5280 §4.1.2.9 and §4.2: `Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension`;
    /// each `extnID` at most once (a repeated one is malformed, catalog
    /// SecurityDomain_incremental_pso: "duplicate certificate extensions treated as
    /// malformed").
    fn read_extensions(&mut self, list: &[u8]) -> Result<(), Malformed> {
        let entries = der::parse_all(list).map_err(|_| Malformed)?;
        if entries.is_empty() {
            return Err(Malformed);
        }
        let mut seen: Vec<Vec<u64>> = Vec::new();
        for (t, entry) in entries {
            if t != tag::SEQUENCE {
                return Err(Malformed);
            }
            let (oid_value, rest) = der::expect(entry, tag::OID).map_err(|_| Malformed)?;
            let id = der::decode_oid(oid_value).map_err(|_| Malformed)?;
            let (critical, rest) = match der::parse_der(rest).map_err(|_| Malformed)? {
                (tag::BOOLEAN, [0xFF], rest) => (true, rest),
                (tag::BOOLEAN, [0x00], rest) => (false, rest),
                (tag::BOOLEAN, _, _) => return Err(Malformed),
                _ => (false, rest),
            };
            let value = der::expect_only(rest, tag::OCTET_STRING).map_err(|_| Malformed)?;
            if seen.contains(&id) {
                return Err(Malformed);
            }
            match id.as_slice() {
                oid::BASIC_CONSTRAINTS => {
                    let (ca, path_len) = parse_basic_constraints(value)?;
                    self.ca = ca;
                    self.path_len = path_len;
                }
                oid::KEY_USAGE => self.key_usage = Some(parse_key_usage(value)?),
                oid::SUBJECT_KEY_IDENTIFIER => {
                    self.ski = Some(der::expect_only(value, tag::OCTET_STRING).map_err(|_| Malformed)?.to_vec());
                }
                oid::AUTHORITY_KEY_IDENTIFIER => self.aki = parse_aki(value)?,
                oid::CERTIFICATE_POLICIES => {
                    let qualifiers = parse_policies(value)?;
                    self.unsupported_qualifiers |= critical && qualifiers;
                }
                _ => self.unknown_critical |= critical,
            }
            seen.push(id);
        }
        Ok(())
    }

    /// The checks that do not depend on the issuer: algorithm, key type, version,
    /// validity, critical extensions and the role the position in the chain asks for.
    /// A certificate that will sign the next one (`issuing`) must be a CA
    /// (basicConstraints cA, keyCertSign when keyUsage is present, RFC 5280 §4.2.1.9 and
    /// §4.2.1.3); the last one is the OCE key-agreement certificate (not a CA,
    /// keyAgreement when keyUsage is present; GP Amendment F §7.5).
    ///
    /// Validity (RFC 5280 §4.1.2.5, §6.1.3 (a)(2)): notBefore <= notAfter, and notAfter
    /// is not before `earliest_now`, the earliest the current time can be (see
    /// [`earliest_now`]). A certificate that expired before that date is expired under
    /// any clock; without a wall clock nothing more can be checked.
    pub(crate) fn role_allows(&self, issuing: bool, earliest_now: u64) -> bool {
        let usage = |bit: u16| self.key_usage.is_none_or(|u| u & bit != 0);
        let role = if issuing { self.ca && usage(key_usage::KEY_CERT_SIGN) } else { !self.ca && usage(key_usage::KEY_AGREEMENT) };
        self.ecdsa_sha256
            && self.version == 2
            && self.public_key.is_some()
            && self.not_before <= self.not_after
            && self.not_after >= earliest_now
            && !self.unknown_critical
            && !self.unsupported_qualifiers
            && role
    }

    /// Check this certificate as the next link after `issuer` and return the link for
    /// the certificate after it, or `None` if it does not verify.
    ///
    /// - The signature verifies with the issuer's key (ECDSA P-256, SHA-256 of the TBS).
    /// - When both the authorityKeyIdentifier of this certificate and the issuer's
    ///   subject key identifier are known, they are equal (RFC 5280 §4.2.1.1).
    /// - When `allowlist` is not empty, the serial number is in it (Yubico SD commands:
    ///   every presented certificate is checked; serials compare as integers).
    /// - For an issuing certificate, RFC 5280 §6.1.4 (l)/(m): a certificate that is not
    ///   self-issued needs a remaining path length above zero and uses one; its own
    ///   pathLenConstraint can only lower the budget.
    pub(crate) fn link(&self, issuer: &Link, issuing: bool, allowlist: &[Vec<u8>]) -> Option<Link> {
        let digest = lk_crypto::sha256(&self.tbs);
        if !lk_crypto::ecdsa_verify_prehash(Curve::P256, &issuer.point, &digest, &self.signature) {
            return None;
        }
        if let (Some(aki), Some(ski)) = (&self.aki, &issuer.ski)
            && !lk_crypto::ct_eq(aki, ski)
        {
            return None;
        }
        if !allowlist.is_empty() && !allowlist.iter().any(|s| s == &self.serial) {
            return None;
        }
        let mut budget = issuer.budget;
        if issuing {
            if self.issuer != self.subject {
                match budget {
                    Some(0) => return None,
                    Some(n) => budget = Some(n - 1),
                    None => {}
                }
            }
            if let Some(limit) = self.path_len {
                budget = Some(budget.map_or(limit, |b| b.min(limit)));
            }
        }
        Some(Link { point: self.public_key.clone()?, ski: self.ski.clone(), budget })
    }
}

/// The earliest the current time can be, as `YYYYMMDDHHMMSS`: the start of validity of
/// the certificates this device issues (`DeviceProfile::cert_not_before`, a
/// GeneralizedTime). The engine has no wall clock (`docs/DESIGN.md` §4), but it cannot
/// run before the identity it claims became valid, so a certificate whose notAfter is
/// earlier has expired whatever the real date is. An unreadable profile date gives `0`
/// (no bound).
pub(crate) fn earliest_now(profile_not_before: &str) -> u64 {
    parse_time(tag::GENERALIZED_TIME, profile_not_before.as_bytes()).unwrap_or(0)
}

/// A serial number as an unsigned magnitude without leading zero bytes; at most 20
/// octets (RFC 5280 §4.1.2.2).
pub(crate) fn normalize_serial(magnitude: &[u8]) -> Result<Vec<u8>, Malformed> {
    let start = magnitude.iter().position(|&b| b != 0).unwrap_or(magnitude.len().saturating_sub(1));
    let trimmed = magnitude.get(start..).ok_or(Malformed)?;
    if trimmed.is_empty() || trimmed.len() > crate::state::MAX_SERIAL_LEN {
        return Err(Malformed);
    }
    Ok(trimmed.to_vec())
}

/// `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` (RFC 5480 §2.2 / RFC 3279
/// §2.2.3) as raw `r || s` with each value left-padded to 32 bytes.
fn parse_ecdsa_signature(input: &[u8]) -> Result<[u8; 64], Malformed> {
    let content = der::expect_only(input, tag::SEQUENCE).map_err(|_| Malformed)?;
    let (r, rest) = der::expect(content, tag::INTEGER).map_err(|_| Malformed)?;
    let s = der::expect_only(rest, tag::INTEGER).map_err(|_| Malformed)?;
    let mut raw = [0u8; 64];
    for (value, slot) in [(r, 0usize), (s, 32usize)] {
        let magnitude = der::decode_unsigned(value).map_err(|_| Malformed)?;
        if magnitude.len() > 32 {
            return Err(Malformed);
        }
        let offset = slot + 32 - magnitude.len();
        raw.get_mut(offset..slot + 32).ok_or(Malformed)?.copy_from_slice(magnitude);
    }
    Ok(raw)
}

/// `Validity ::= SEQUENCE { notBefore Time, notAfter Time }` (RFC 5280 §4.1.2.5).
fn parse_validity(value: &[u8]) -> Result<(u64, u64), Malformed> {
    let (first_tag, first, rest) = der::parse_der(value).map_err(|_| Malformed)?;
    let (second_tag, second, rest) = der::parse_der(rest).map_err(|_| Malformed)?;
    if !rest.is_empty() {
        return Err(Malformed);
    }
    Ok((parse_time(first_tag, first)?, parse_time(second_tag, second)?))
}

/// UTCTime `YYMMDDHHMMSSZ` (years 1950-2049, RFC 5280 §4.1.2.5.1) or GeneralizedTime
/// `YYYYMMDDHHMMSSZ` (§4.1.2.5.2) as the number `YYYYMMDDHHMMSS`, which orders like the
/// time it names.
fn parse_time(t: u8, value: &[u8]) -> Result<u64, Malformed> {
    let (digits, year_digits) = match (t, value.split_last()) {
        (tag::UTC_TIME, Some((b'Z', digits))) if digits.len() == 12 => (digits, 2),
        (tag::GENERALIZED_TIME, Some((b'Z', digits))) if digits.len() == 14 => (digits, 4),
        _ => return Err(Malformed),
    };
    if !digits.iter().all(u8::is_ascii_digit) {
        return Err(Malformed);
    }
    let number = |range: core::ops::Range<usize>| -> u64 {
        digits.get(range).unwrap_or(&[]).iter().fold(0u64, |acc, d| acc * 10 + u64::from(d - b'0'))
    };
    let mut year = number(0..year_digits);
    if year_digits == 2 {
        year += if year >= 50 { 1900 } else { 2000 };
    }
    let rest = |i: usize| number(year_digits + 2 * i..year_digits + 2 * i + 2);
    let (month, day, hour, minute, second) = (rest(0), rest(1), rest(2), rest(3), rest(4));
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 59 {
        return Err(Malformed);
    }
    Ok(((((year * 100 + month) * 100 + day) * 100 + hour) * 100 + minute) * 100 + second)
}

/// `SubjectPublicKeyInfo` (RFC 5280 §4.1.2.7): the point if the key is id-ecPublicKey
/// on secp256r1 (RFC 5480 §2.1.1) and on the curve; `None` for any other well-formed
/// key (a key-type failure, not malformed input).
fn parse_spki(value: &[u8]) -> Result<Option<Vec<u8>>, Malformed> {
    let (alg, rest) = der::expect(value, tag::SEQUENCE).map_err(|_| Malformed)?;
    let bits = der::expect_only(rest, tag::BIT_STRING).map_err(|_| Malformed)?;
    let (unused, key) = der::decode_bit_string(bits).map_err(|_| Malformed)?;
    let (alg_oid, params) = der::expect(alg, tag::OID).map_err(|_| Malformed)?;
    let algorithm = der::decode_oid(alg_oid).map_err(|_| Malformed)?;
    let curve = match der::expect_only(params, tag::OID) {
        Ok(curve) => der::decode_oid(curve).ok(),
        Err(_) => None,
    };
    let ok = algorithm == oid::EC_PUBLIC_KEY
        && curve.as_deref() == Some(oid::SECP256R1)
        && unused == 0
        && lk_crypto::ec_public_is_valid(Curve::P256, key);
    Ok(ok.then(|| key.to_vec()))
}

/// `BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint
/// INTEGER (0..MAX) OPTIONAL }` (RFC 5280 §4.2.1.9).
fn parse_basic_constraints(value: &[u8]) -> Result<(bool, Option<u32>), Malformed> {
    let content = der::expect_only(value, tag::SEQUENCE).map_err(|_| Malformed)?;
    let mut ca = false;
    let mut path_len = None;
    let mut rest = content;
    if let Ok((tag::BOOLEAN, v, next)) = der::parse_der(rest) {
        ca = match v {
            [0xFF] => true,
            [0x00] => false,
            _ => return Err(Malformed),
        };
        rest = next;
    }
    if !rest.is_empty() {
        let v = der::expect_only(rest, tag::INTEGER).map_err(|_| Malformed)?;
        let magnitude = der::decode_unsigned(v).map_err(|_| Malformed)?;
        if magnitude.len() > 4 {
            return Err(Malformed);
        }
        path_len = Some(magnitude.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b)));
    }
    Ok((ca, path_len))
}

/// `KeyUsage ::= BIT STRING` (RFC 5280 §4.2.1.3) as bit `i` = named bit `i`, the
/// layout of `lk_codec::x509::key_usage`.
fn parse_key_usage(value: &[u8]) -> Result<u16, Malformed> {
    let bits = der::expect_only(value, tag::BIT_STRING).map_err(|_| Malformed)?;
    let (_, octets) = der::decode_bit_string(bits).map_err(|_| Malformed)?;
    let mut usage = 0u16;
    for (i, octet) in octets.iter().take(2).enumerate() {
        for bit in 0..8 {
            if octet & (0x80 >> bit) != 0 {
                usage |= 1 << (i * 8 + bit);
            }
        }
    }
    Ok(usage)
}

/// `AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] OPTIONAL,
/// authorityCertIssuer [1] OPTIONAL, authorityCertSerialNumber [2] OPTIONAL }`
/// (RFC 5280 §4.2.1.1): the key identifier, if present.
fn parse_aki(value: &[u8]) -> Result<Option<Vec<u8>>, Malformed> {
    let content = der::expect_only(value, tag::SEQUENCE).map_err(|_| Malformed)?;
    let mut key_id = None;
    for (t, v) in der::parse_all(content).map_err(|_| Malformed)? {
        match t {
            0x80 => key_id = Some(v.to_vec()),
            0xA1 | 0x82 => {}
            _ => return Err(Malformed),
        }
    }
    Ok(key_id)
}

/// `certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation`,
/// `PolicyInformation ::= SEQUENCE { policyIdentifier OID, policyQualifiers SEQUENCE
/// SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL }` (RFC 5280 §4.2.1.4). Returns whether
/// any qualifier is present.
fn parse_policies(value: &[u8]) -> Result<bool, Malformed> {
    let content = der::expect_only(value, tag::SEQUENCE).map_err(|_| Malformed)?;
    let policies = der::parse_all(content).map_err(|_| Malformed)?;
    if policies.is_empty() {
        return Err(Malformed);
    }
    let mut qualifiers = false;
    for (t, policy) in policies {
        if t != tag::SEQUENCE {
            return Err(Malformed);
        }
        let (policy_oid, rest) = der::expect(policy, tag::OID).map_err(|_| Malformed)?;
        der::decode_oid(policy_oid).map_err(|_| Malformed)?;
        if !rest.is_empty() {
            der::expect_only(rest, tag::SEQUENCE).map_err(|_| Malformed)?;
            qualifiers = true;
        }
    }
    Ok(qualifiers)
}

/// The Security Domain's own certificate for an SCP11b key: self-signed with that key,
/// ecdsa-with-SHA256 with a hedged nonce (docs/CONTRACTS.md "Phase 0 as implemented"),
/// a random positive 16-byte serial, the profile's certificate validity
/// (`docs/DESIGN.md` §4), critical basicConstraints (not a CA), critical keyUsage
/// keyAgreement (the ECKA role of CERT.SD.ECKA, GP Amendment F) and a subject key
/// identifier (SHA-1 of the point, RFC 5280 §4.2.1.2 method 1). It claims no
/// manufacturer identity (catalog SecurityDomain_profile: "fresh independent software
/// SCP11b certificate").
pub(crate) fn own_certificate(key: &EcPrivateKey, host: &mut dyn Host) -> Vec<u8> {
    let point = key.public_uncompressed();
    let mut serial = [0u8; 16];
    host.fill(&mut serial);
    serial[0] = (serial[0] & 0x7F) | 0x40;
    let profile = host.profile();
    let validity = Validity::rfc5280(&profile.cert_not_before, &profile.cert_not_after)
        .unwrap_or_else(|_| Validity::generalized("20260101000000Z", x509::NO_WELL_DEFINED_EXPIRATION));
    let name = Name::new().common_name("Security Domain SCP11b");
    let tbs = TbsCertificate {
        serial: serial.to_vec(),
        signature: SignatureAlgorithm::EcdsaWithSha256,
        issuer: name.clone(),
        validity,
        subject: name,
        public_key: PublicKey::EcP256(point.clone()),
        extensions: vec![
            Extension::basic_constraints(false, None),
            Extension::key_usage(key_usage::KEY_AGREEMENT),
            Extension::subject_key_identifier(&lk_crypto::sha1(&point)),
        ],
    }
    .to_der();
    let signature = key
        .sign_message_hedged(HashAlg::Sha256, &tbs, host)
        .map(|s| s.to_der())
        .unwrap_or_default();
    x509::assemble(&tbs, SignatureAlgorithm::EcdsaWithSha256, &signature)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use lk_testkit::TestHost;

    #[test]
    fn own_certificate_is_self_signed_and_parses() {
        let mut host = TestHost::new();
        let key = EcPrivateKey::generate(Curve::P256, &mut host);
        let der_cert = own_certificate(&key, &mut host);
        let cert = Certificate::parse(&der_cert).unwrap();
        assert_eq!(cert.public_key.as_deref(), Some(key.public_uncompressed().as_slice()));
        assert_eq!(cert.key_usage, Some(key_usage::KEY_AGREEMENT));
        assert!(!cert.ca);
        assert!(cert.role_allows(false, earliest_now(&host.profile().cert_not_before)));
        let anchor = Link { point: key.public_uncompressed(), ski: None, budget: None };
        assert!(cert.link(&anchor, false, &[]).is_some());
        // Hedged signatures: a second certificate for the same key differs.
        assert_ne!(own_certificate(&key, &mut host), der_cert);
    }

    #[test]
    fn times_parse_and_order() {
        assert_eq!(parse_time(tag::UTC_TIME, b"491231235959Z").unwrap(), 20491231235959);
        assert_eq!(parse_time(tag::UTC_TIME, b"500101000000Z").unwrap(), 19500101000000);
        assert_eq!(parse_time(tag::GENERALIZED_TIME, b"99991231235959Z").unwrap(), 99991231235959);
        assert!(parse_time(tag::UTC_TIME, b"491331235959Z").is_err());
        assert!(parse_time(tag::UTC_TIME, b"4912312359Z").is_err());
        assert!(parse_time(tag::GENERALIZED_TIME, b"2049123123595Z").is_err());
        assert!(parse_time(tag::OCTET_STRING, b"491231235959Z").is_err());
    }

    /// The earliest current time comes from the profile's GeneralizedTime (`docs/DESIGN.md`
    /// §4); a notAfter before it fails the validity check, on or after it passes, and an
    /// unreadable profile date sets no bound (RFC 5280 §6.1.3 (a)(2)).
    #[test]
    fn expiry_is_checked_against_the_earliest_current_time() {
        assert_eq!(earliest_now("20260101000000Z"), 20260101000000);
        assert_eq!(earliest_now("2026"), 0);
        let mut host = TestHost::new();
        let key = EcPrivateKey::generate(Curve::P256, &mut host);
        let mut cert = Certificate::parse(&own_certificate(&key, &mut host)).unwrap();
        let floor = earliest_now("20260101000000Z");
        cert.not_before = 20200101000000;
        cert.not_after = 20251231235959;
        assert!(!cert.role_allows(false, floor), "expired before the earliest current time");
        cert.not_after = 20260101000000;
        assert!(cert.role_allows(false, floor));
        cert.not_after = 20251231235959;
        assert!(cert.role_allows(false, 0), "no bound");
    }

    #[test]
    fn serials_compare_as_integers() {
        assert_eq!(normalize_serial(&[0, 0, 0x80]).unwrap(), vec![0x80]);
        assert_eq!(normalize_serial(&[0]).unwrap(), vec![0]);
        assert_eq!(normalize_serial(&[0, 0]).unwrap(), vec![0]);
        assert!(normalize_serial(&[]).is_err());
        assert!(normalize_serial(&[1; 21]).is_err());
        assert_eq!(normalize_serial(&[[0u8].as_slice(), &[1; 20]].concat()).unwrap(), vec![1; 20]);
    }

    #[test]
    fn key_usage_bits_follow_named_bit_order() {
        let encoded = der::named_bit_string(u64::from(key_usage::KEY_CERT_SIGN | key_usage::DIGITAL_SIGNATURE));
        assert_eq!(parse_key_usage(&encoded).unwrap(), key_usage::KEY_CERT_SIGN | key_usage::DIGITAL_SIGNATURE);
        let encoded = der::named_bit_string(u64::from(key_usage::DECIPHER_ONLY));
        assert_eq!(parse_key_usage(&encoded).unwrap(), key_usage::DECIPHER_ONLY);
    }
}
