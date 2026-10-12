//! PIV attestation (Yubico "PIV attestation"; Yubico PIV extensions ATTEST `F9`) and the
//! own attestation issuer in slot `F9` (catalog bullets on the preinitialized own F9
//! issuer, copied validity, public-profile extensions, 16-byte random serials, reset and
//! restart retention, non-regeneration and opaque issuer storage).
//!
//! Certificates are parsed with `lk_codec::der` (X.690) along RFC 5280 §4.1 and their
//! signatures checked with `lk_crypto`: ECDSA with SHA-256 (FIPS 186-5 §6.4.2) or
//! RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017 §8.2.2, DigestInfo prefix from §9.2 note 1).

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use lk_codec::der::{self, tag};
use lk_codec::tlv;
use lk_codec::x509::{Name, PublicKey, SignatureAlgorithm, Validity};
use lk_core::{DeviceProfile, Record};
use lk_crypto::{Curve, ecdsa_verify_prehash, rsa_public_op, sha256};
use lk_testkit::TestHost;

const OID_FIRMWARE: &[u64] = &[1, 3, 6, 1, 4, 1, 41482, 3, 3];
const OID_SERIAL: &[u64] = &[1, 3, 6, 1, 4, 1, 41482, 3, 7];
const OID_POLICY: &[u64] = &[1, 3, 6, 1, 4, 1, 41482, 3, 8];
const OID_FORM_FACTOR: &[u64] = &[1, 3, 6, 1, 4, 1, 41482, 3, 9];
const OID_BASIC_CONSTRAINTS: &[u64] = &[2, 5, 29, 19];

/// The parts of an X.509 certificate the tests look at (RFC 5280 §4.1).
#[derive(Debug)]
struct Cert {
    tbs: Vec<u8>,
    sig_alg: Vec<u8>,
    signature: Vec<u8>,
    inner_sig_alg: Vec<u8>,
    serial: Vec<u8>,
    issuer: Vec<u8>,
    validity: Vec<u8>,
    subject: Vec<u8>,
    spki: Vec<u8>,
    extensions: Vec<(Vec<u64>, bool, Vec<u8>)>,
}

fn parse_cert(bytes: &[u8]) -> Cert {
    let content = der::expect_only(bytes, tag::SEQUENCE).unwrap();
    let (tbs, rest) = der::split_der(content).unwrap();
    let (sig_alg, rest) = der::split_der(rest).unwrap();
    let (unused, signature) = der::decode_bit_string(der::expect_only(rest, tag::BIT_STRING).unwrap()).unwrap();
    assert_eq!(unused, 0);
    let fields = der::expect_only(tbs, tag::SEQUENCE).unwrap();
    let (version, fields) = der::expect(fields, der::context_tag(0, true)).unwrap();
    assert_eq!(version, der::integer_u64(2), "v3");
    let (serial, fields) = der::expect(fields, tag::INTEGER).unwrap();
    let (inner_sig_alg, fields) = der::split_der(fields).unwrap();
    let (issuer, fields) = der::split_der(fields).unwrap();
    let (validity, fields) = der::split_der(fields).unwrap();
    let (subject, fields) = der::split_der(fields).unwrap();
    let (spki, fields) = der::split_der(fields).unwrap();
    let mut extensions = Vec::new();
    if !fields.is_empty() {
        let explicit = der::expect_only(fields, der::context_tag(3, true)).unwrap();
        let list = der::expect_only(explicit, tag::SEQUENCE).unwrap();
        for (t, ext) in der::parse_all(list).unwrap() {
            assert_eq!(t, tag::SEQUENCE);
            let (oid, rest) = der::expect(ext, tag::OID).unwrap();
            let (critical, rest) = match der::expect(rest, tag::BOOLEAN) {
                Ok((value, rest)) => (value == [0xFF], rest),
                Err(_) => (false, rest),
            };
            let value = der::expect_only(rest, tag::OCTET_STRING).unwrap();
            extensions.push((der::decode_oid(oid).unwrap(), critical, value.to_vec()));
        }
    }
    Cert {
        tbs: tbs.to_vec(),
        sig_alg: sig_alg.to_vec(),
        signature: signature.to_vec(),
        inner_sig_alg: inner_sig_alg.to_vec(),
        serial: serial.to_vec(),
        issuer: issuer.to_vec(),
        validity: validity.to_vec(),
        subject: subject.to_vec(),
        spki: spki.to_vec(),
        extensions,
    }
}

impl Cert {
    fn extension(&self, oid: &[u64]) -> Option<&(Vec<u64>, bool, Vec<u8>)> {
        self.extensions.iter().find(|(o, _, _)| o == oid)
    }
}

/// Whether `cert` carries a valid signature by `issuer` (an F9 public key).
fn signed_by(cert: &Cert, issuer: &Public) -> bool {
    let digest = sha256(&cert.tbs);
    match issuer {
        Public::Point(point) => {
            assert_eq!(cert.sig_alg, SignatureAlgorithm::EcdsaWithSha256.algorithm_identifier());
            let curve = if point.len() == 65 { Curve::P256 } else { Curve::P384 };
            ecdsa_verify_prehash(curve, point, &digest, &cert.signature)
        }
        Public::Rsa { n, e } => {
            assert_eq!(cert.sig_alg, SignatureAlgorithm::Sha256WithRsaEncryption.algorithm_identifier());
            let Ok(em) = rsa_public_op(n, e, &cert.signature) else { return false };
            let mut expected = vec![0x00, 0x01];
            expected.resize(n.len() - 51 - 1, 0xFF);
            expected.push(0x00);
            expected.extend(hex("3031300d060960864801650304020105000420"));
            expected.extend_from_slice(&digest);
            em == expected
        }
    }
}

fn x509_public(alg: u8, public: &Public) -> Vec<u8> {
    match (alg, public) {
        (P256, Public::Point(p)) => PublicKey::EcP256(p.clone()),
        (P384, Public::Point(p)) => PublicKey::EcP384(p.clone()),
        (ED25519, Public::Point(p)) => PublicKey::Ed25519(p.clone()),
        (X25519, Public::Point(p)) => PublicKey::X25519(p.clone()),
        (_, Public::Rsa { n, e }) => PublicKey::Rsa { modulus: n.clone(), exponent: e.clone() },
        _ => panic!("unexpected key"),
    }
    .to_der()
}

/// The certificate inside the F9 certificate container 5FFF01.
fn f9_certificate(card: &mut Card) -> Vec<u8> {
    let value = card.object_value(0x5FFF01).unwrap();
    let items = tlv::parse_all(&value).unwrap();
    tlv::find(&items, 0x70).unwrap().value.to_vec()
}

fn cn(text: &str) -> Vec<u8> {
    Name::new().common_name(text).to_der()
}

fn attest_ok(card: &mut Card, slot: u8) -> Cert {
    let (data, sw) = card.attest(slot);
    assert_eq!(sw, 0x9000, "attest {slot:02X}");
    parse_cert(&data)
}

#[test]
fn own_issuer_is_preinitialized_and_self_signed() {
    let mut card = Card::new();
    // Container layout: 70 certificate, 71 CertInfo 00, FE (SP 800-73-4 Part 1 App. A).
    let value = card.object_value(0x5FFF01).unwrap();
    let items = tlv::parse_all(&value).unwrap();
    assert_eq!(items.iter().map(|i| i.tag).collect::<Vec<_>>(), vec![0x70, 0x71, 0xFE]);
    assert_eq!(items[1].value, [0x00]);
    assert!(items[2].value.is_empty());
    let cert = parse_cert(items[0].value);
    let f9 = card.slot_info(0xF9).unwrap();
    assert_eq!((f9.alg, f9.pin, f9.touch, f9.origin), (P256, PIN_NEVER, TOUCH_NEVER, 0x01));
    assert!(signed_by(&cert, &f9.public), "self-signed by the F9 key");
    assert_eq!(cert.spki, x509_public(P256, &f9.public));
    assert_eq!(cert.issuer, cert.subject);
    assert_eq!(cert.subject, cn("localkey software authenticator PIV Attestation"));
    let profile = DeviceProfile::own(12_345_678);
    assert_eq!(cert.validity, Validity::rfc5280(&profile.cert_not_before, &profile.cert_not_after).unwrap().to_der());
    let (_, critical, value) = cert.extension(OID_BASIC_CONSTRAINTS).unwrap();
    assert!(critical);
    assert_eq!(value, &der::sequence([der::boolean(true)]), "cA TRUE");
    // No manufacturer certification claim: none of the Yubico attestation extensions.
    assert!(cert.extensions.iter().all(|(oid, _, _)| !oid.starts_with(&[1, 3, 6, 1, 4, 1, 41482])));
    assert_eq!(cert.serial.len(), 16);
}

#[test]
fn attestation_certificate_contents() {
    let mut card = Card::new();
    card.auth_default();
    let public = card.generate(0x9A, P256, Some(PIN_DEFAULT), Some(TOUCH_CACHED));
    let f9 = card.slot_info(0xF9).unwrap().public;
    let issuer = parse_cert(&f9_certificate(&mut card));
    let cert = attest_ok(&mut card, 0x9A);
    assert!(signed_by(&cert, &f9), "signed by the F9 key");
    assert_eq!(cert.inner_sig_alg, cert.sig_alg);
    // Issuer = subject of the attesting certificate; validity copied from it.
    assert_eq!(cert.issuer, issuer.subject);
    assert_eq!(cert.validity, issuer.validity);
    assert_eq!(cert.subject, cn("localkey PIV Attestation 9a"));
    assert_eq!(cert.spki, x509_public(P256, &public));
    // A random positive 16-byte serial (Yubico: "a random 16 byte integer").
    assert_eq!(cert.serial.len(), 16);
    assert_eq!(cert.serial[0] & 0x80, 0);
    // Public-profile extensions with this device's values, none critical. The form factor
    // is the own profile's byte, whatever it is (`form_factor_extension_follows_the_profile`).
    let expected: [(&[u64], Vec<u8>); 4] = [
        (OID_FIRMWARE, hex("050704")),
        (OID_SERIAL, der::integer(&12_345_678u32.to_be_bytes())),
        (OID_POLICY, vec![PIN_ONCE, TOUCH_CACHED]),
        (OID_FORM_FACTOR, vec![DeviceProfile::own(12_345_678).form_factor]),
    ];
    assert_eq!(cert.extensions.len(), 4);
    for (oid, value) in expected {
        assert_eq!(cert.extension(oid), Some(&(oid.to_vec(), false, value)), "{oid:?}");
    }
    // Each attestation is signed independently with a new serial.
    let again = attest_ok(&mut card, 0x9A);
    assert_ne!(again.serial, cert.serial);
    assert!(signed_by(&again, &f9));
}

#[test]
fn every_generated_algorithm_can_be_attested() {
    let mut card = Card::new();
    card.auth_default();
    let f9 = card.slot_info(0xF9).unwrap().public;
    for (slot, alg) in [(0x9C, P384), (0x9D, ED25519), (0x9E, X25519), (0x82, RSA1024), (0x95, P256)] {
        let public = card.generate(slot, alg, None, None);
        let cert = attest_ok(&mut card, slot);
        assert!(signed_by(&cert, &f9), "{alg:02X}");
        assert_eq!(cert.spki, x509_public(alg, &public), "{alg:02X}");
        assert_eq!(cert.subject, cn(&format!("localkey PIV Attestation {slot:02x}")));
        let policy = card.slot_info(slot).unwrap();
        assert_eq!(cert.extension(OID_POLICY).unwrap().2, vec![policy.pin, policy.touch]);
    }
}

#[test]
fn compatibility_profile_uses_the_public_subject_format() {
    let mut card = Card::with_host(TestHost::with_profile(DeviceProfile::yubikey_5c_nano_5_7_4(31_415_926)));
    card.auth_default();
    card.generate(0x9C, P256, None, None);
    let cert = attest_ok(&mut card, 0x9C);
    assert_eq!(cert.subject, cn("YubiKey PIV Attestation 9c"));
    assert_eq!(cert.extension(OID_SERIAL).unwrap().2, der::integer(&31_415_926u32.to_be_bytes()));
    // The compatibility profile claims the reference's shape: USB-C Nano (04).
    assert_eq!(cert.extension(OID_FORM_FACTOR).unwrap().2, vec![0x04]);
    // The issuer stays this engine's own (no manufacturer identity, DESIGN.md §9).
    assert_eq!(cert.issuer, cn("localkey software authenticator PIV Attestation"));
}

/// Extension 1.3.6.1.4.1.41482.3.9 carries the profile's form factor byte as it is,
/// including `00` (yubikit `FORM_FACTOR.UNKNOWN`), the truthful value for a software key
/// without a physical shape (own identity: no Yubico product shape is claimed).
#[test]
fn form_factor_extension_follows_the_profile() {
    for form_factor in [0x00, 0x04] {
        let profile = DeviceProfile { form_factor, ..DeviceProfile::own(12_345_678) };
        let mut card = Card::with_host(TestHost::with_profile(profile));
        card.auth_default();
        card.generate(0x9A, P256, None, None);
        let cert = attest_ok(&mut card, 0x9A);
        let expected = (OID_FORM_FACTOR.to_vec(), false, vec![form_factor]);
        assert_eq!(cert.extension(OID_FORM_FACTOR), Some(&expected), "{form_factor:02X}");
    }
}

#[test]
fn attest_errors_change_nothing() {
    let mut card = Card::new();
    card.auth_default();
    card.generate(0x9A, P256, None, None);
    card.import(0x9C, P256, &tlv::encode(0x06, &hex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")));
    let before = card.host.persisted(Record::Piv);
    let count = card.host.persist_count();
    assert_eq!(card.attest(0x9D).1, 0x6A88, "empty slot");
    assert_eq!(card.attest(0x9C).1, 0x6A80, "imported keys are not attested");
    assert_eq!(card.attest(0xF9).1, 0x6A86, "the attestation key itself");
    assert_eq!(card.attest(0x9B).1, 0x6A86, "not a key slot");
    assert_eq!(card.attest(0x80).1, 0x6A86);
    assert_eq!(card.cmd(0xF9, 0x9A, 0x01, &[], None).1, 0x6A86, "P2");
    assert_eq!(card.cmd(0xF9, 0x9A, 0x00, &[0x00], None).1, 0x6700, "data");
    // No authentication is needed and Le may be absent.
    card.new_session();
    let first = card.cmd(0xF9, 0x9A, 0x00, &[], None);
    let (data, sw) = card.collect(first);
    assert_eq!(sw, 0x9000);
    parse_cert(&data);
    assert_eq!(card.host.persist_count(), count, "ATTEST persists nothing");
    assert_eq!(card.host.persisted(Record::Piv), before);
}

#[test]
fn replaced_rsa_issuer_with_its_own_certificate() {
    // Yubico: the attestation key and certificate "can be overwritten by loading a new key
    // and certificate to slot f9"; catalog "independent issuer signatures, copied
    // validity".
    let mut card = Card::new();
    card.auth_default();
    let issuer = card.generate(0xF9, RSA2048, None, None);
    // A host-made certificate for it: only its subject and validity matter to ATTEST.
    let subject = cn("Custom PIV Attestation CA");
    let validity = Validity::rfc5280("20300101000000Z", "20400101000000Z").unwrap().to_der();
    let tbs = der::sequence([
        der::explicit(0, &der::integer_u64(2)),
        der::integer(&[0x01]),
        SignatureAlgorithm::Sha256WithRsaEncryption.algorithm_identifier(),
        subject.clone(),
        validity.clone(),
        subject.clone(),
        x509_public(RSA2048, &issuer),
    ]);
    let custom = lk_codec::x509::assemble(&tbs, SignatureAlgorithm::Sha256WithRsaEncryption, &[0; 256]);
    let mut container = tlv::encode(0x70, &custom);
    container.extend(hex("710100FE00"));
    assert_eq!(card.put_object(0x5FFF01, &container), 0x9000);
    let public = card.generate(0x9A, P384, None, None);
    let cert = attest_ok(&mut card, 0x9A);
    assert!(signed_by(&cert, &issuer), "RSASSA-PKCS1-v1_5 with SHA-256 by the new F9 key");
    assert_eq!(cert.issuer, subject);
    assert_eq!(cert.validity, validity);
    assert_eq!(cert.spki, x509_public(P384, &public));
}

#[test]
fn imported_ec_issuer_signs_attestations() {
    // Catalog: "imported RSA/EC issuers". RFC 6979 A.2.5 P-256 key.
    let mut card = Card::new();
    card.auth_default();
    let scalar = hex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
    assert_eq!(card.import(0xF9, P256, &tlv::encode(0x06, &scalar)), 0x9000);
    let issuer = card.slot_info(0xF9).unwrap();
    assert_eq!(issuer.origin, 0x02);
    card.generate(0x9E, ED25519, None, None);
    let cert = attest_ok(&mut card, 0x9E);
    assert!(signed_by(&cert, &issuer.public));
    // The stored certificate still belongs to the previous key: ATTEST copies its names
    // anyway, and verifying with that certificate's key fails on the host side.
    let old = parse_cert(&f9_certificate(&mut card));
    assert_eq!(cert.issuer, old.subject);
    assert!(!signed_by(&cert, &Public::Point(spki_point(&old.spki))), "independent failed verification");
}

/// The subject public key bits of an EC SubjectPublicKeyInfo (RFC 5480 §2).
fn spki_point(spki: &[u8]) -> Vec<u8> {
    let content = der::expect_only(spki, tag::SEQUENCE).unwrap();
    let (_alg, rest) = der::expect(content, tag::SEQUENCE).unwrap();
    let (_, bits) = der::decode_bit_string(der::expect_only(rest, tag::BIT_STRING).unwrap()).unwrap();
    bits.to_vec()
}

#[test]
fn malformed_issuer_certificate_is_stored_opaquely() {
    // Catalog: "opaque mismatched/malformed issuer storage, independent failed
    // verification and immutable failure state". The container is stored as given;
    // ATTEST then names the own issuer and validity and still signs with the F9 key.
    let mut card = Card::new();
    card.auth_default();
    let profile = DeviceProfile::own(12_345_678);
    card.generate(0x9A, P256, None, None);
    let f9 = card.slot_info(0xF9).unwrap().public;
    for garbage in [hex("7003010203"), hex("71010053020000"), hex("7006300402010102")] {
        assert_eq!(card.put_object(0x5FFF01, &garbage), 0x9000);
        assert_eq!(card.object_value(0x5FFF01), Some(garbage.clone()), "stored opaquely");
        let before = card.host.persisted(Record::Piv);
        let cert = attest_ok(&mut card, 0x9A);
        assert!(signed_by(&cert, &f9));
        assert_eq!(cert.issuer, cn("localkey software authenticator PIV Attestation"));
        assert_eq!(cert.validity, Validity::rfc5280(&profile.cert_not_before, &profile.cert_not_after).unwrap().to_der());
        assert_eq!(card.host.persisted(Record::Piv), before, "ATTEST changes nothing");
        assert_eq!(card.object_value(0x5FFF01), Some(garbage), "not repaired");
    }
}

#[test]
fn f9_key_and_certificate_survive_reset_and_restart() {
    // Yubico: "The attestation key and certificate will not be cleared out by a reset";
    // profile piv_reset_preserves_current_f9_key_and_certificate.
    let mut card = Card::new();
    let f9 = card.slot_info(0xF9).unwrap();
    let certificate = card.object_value(0x5FFF01).unwrap();
    card.auth_default();
    card.generate(0x9A, P256, None, None);
    for _ in 0..3 {
        card.verify_pin(&pad(b"000000"));
    }
    let mut change = pad(b"00000000");
    change.extend(pad(b"11111111"));
    for _ in 0..3 {
        card.cmd(0x24, 0x00, 0x81, &change, None);
    }
    assert_eq!(card.send("00FB0000").1, 0x9000);
    assert_eq!(card.slot_info(0x9A), None, "user keys erased");
    assert_eq!(card.slot_info(0xF9).unwrap(), f9);
    assert_eq!(card.object_value(0x5FFF01), Some(certificate.clone()));
    card.restart();
    assert_eq!(card.slot_info(0xF9).unwrap(), f9);
    assert_eq!(card.object_value(0x5FFF01), Some(certificate));
    card.auth_default();
    card.generate(0x9A, P256, None, None);
    assert!(signed_by(&attest_ok(&mut card, 0x9A), &f9.public));
}

#[test]
fn deleted_f9_key_and_certificate_are_not_regenerated() {
    // Catalog: "YubiKey 5.7 PIV F9 DELETE KEY is accepted ... issuer loss and persistence
    // over restart/PIV reset" and "deleted certificate is not regenerated".
    let mut card = Card::new();
    card.auth_default();
    card.generate(0x9A, P256, None, None);
    assert_eq!(card.send("00F6FFF9").1, 0x9000);
    assert_eq!(card.slot_info(0xF9), None);
    assert_eq!(card.attest(0x9A).1, 0x6A88, "no issuer key");
    assert_eq!(card.put_object(0x5FFF01, &[]), 0x9000);
    card.restart();
    assert_eq!(card.slot_info(0xF9), None, "not regenerated on restart");
    assert_eq!(card.get_object(0x5FFF01).1, 0x6A82);
    for _ in 0..3 {
        card.verify_pin(&pad(b"000000"));
    }
    let mut change = pad(b"00000000");
    change.extend(pad(b"11111111"));
    for _ in 0..3 {
        card.cmd(0x24, 0x00, 0x81, &change, None);
    }
    assert_eq!(card.send("00FB0000").1, 0x9000);
    card.restart();
    assert_eq!(card.slot_info(0xF9), None, "not regenerated by RESET");
    assert_eq!(card.get_object(0x5FFF01).1, 0x6A82);
    // A new issuer can be generated; without a certificate ATTEST names the own issuer.
    card.auth_default();
    let issuer = card.generate(0xF9, P256, None, None);
    card.generate(0x9A, P256, None, None);
    let cert = attest_ok(&mut card, 0x9A);
    assert!(signed_by(&cert, &issuer));
    assert_eq!(cert.issuer, cn("localkey software authenticator PIV Attestation"));
}

/// A stage 1 record (format version 01 without the attestation marker): factory PIN,
/// PUK, retries and AES-192 management key (`state` module table).
fn stage_one_record(extra: &[u8]) -> Vec<u8> {
    let mut out = vec![0x01];
    out.extend(hex("0108313233343536FFFF 020103 030103"));
    out.extend(hex("04083132333435363738 050103 060103 07010A"));
    out.extend(hex("0818010203040506070801020304050607080102030405060708 090100"));
    out.extend_from_slice(extra);
    out
}

#[test]
fn records_without_attestation_material_are_initialized_once() {
    let mut host = TestHost::new();
    host.set_persisted(Record::Piv, &stage_one_record(&[]));
    let mut card = Card::with_host(host);
    assert_eq!(card.host.persist_count(), 1, "initialized and persisted at once");
    assert_eq!(card.metadata(0x80).0, hex("0101FF 050101 06020303"), "credentials kept");
    let f9 = card.slot_info(0xF9).unwrap();
    assert!(signed_by(&parse_cert(&f9_certificate(&mut card)), &f9.public));
    card.restart();
    assert_eq!(card.host.persist_count(), 1);
    assert_eq!(card.slot_info(0xF9).unwrap(), f9);

    // An existing 5FFF01 object is kept as is; only the key is created.
    let mut object = tlv::encode(0x01, &hex("5FFF01"));
    tlv::encode_into(&mut object, 0x02, &hex("7003AABBCC"));
    let mut host = TestHost::new();
    host.set_persisted(Record::Piv, &stage_one_record(&tlv::encode(0x70, &object)));
    let mut card = Card::with_host(host);
    assert_eq!(card.object_value(0x5FFF01), Some(hex("7003AABBCC")));
    assert!(card.slot_info(0xF9).is_some());
}
