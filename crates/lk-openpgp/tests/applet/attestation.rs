//! Yubico OpenPGP attestation (Yubico developer documentation "OpenPGP attestation"):
//! the factory issuer, GET ATTESTATION `80 FB`, the generated X.509 certificate (RFC 5280
//! §4.1) and its 1.3.6.1.4.1.41482.5 extensions, and the reset rules of the catalog's
//! OpenPGP_attestation section. Certificates are parsed test-side with `lk_codec::der`
//! readers and their signatures verified with lk-crypto (RFC 8017 §8.2.2, FIPS 186-5
//! §6.4.2).

use lk_codec::der;
use lk_core::{DeviceProfile, Record};
use lk_crypto::{Curve, EcPrivateKey, ecdsa_verify_prehash};
use lk_testkit::{SeededEntropy, TestHost};

use crate::common::{Card, Public, attr, crt, digest_info_sha256, hex, import_data, parse_public, rsa_verify};

const SHA256_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 11];
const ECDSA_WITH_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];
const ARC: [u64; 8] = [1, 3, 6, 1, 4, 1, 41482, 5];

#[derive(Debug)]
struct Cert {
    tbs: Vec<u8>,
    serial: Vec<u8>,
    issuer: Vec<u8>,
    validity: Vec<u8>,
    subject: Vec<u8>,
    spki: Vec<u8>,
    extensions: Vec<(Vec<u64>, bool, Vec<u8>)>,
    algorithm: Vec<u64>,
    signature: Vec<u8>,
}

impl Cert {
    fn parse(bytes: &[u8]) -> Cert {
        let body = der::expect_only(bytes, der::tag::SEQUENCE).unwrap();
        let (tbs_element, rest) = der::split_der(body).unwrap();
        let (algorithm, rest) = der::expect(rest, der::tag::SEQUENCE).unwrap();
        let signature = der::expect_only(rest, der::tag::BIT_STRING).unwrap();
        let (unused, signature) = der::decode_bit_string(signature).unwrap();
        assert_eq!(unused, 0);
        let algorithm = der::decode_oid(der::expect(algorithm, der::tag::OID).unwrap().0).unwrap();

        let tbs = der::expect_only(tbs_element, der::tag::SEQUENCE).unwrap();
        let (version, rest) = der::split_der(tbs).unwrap();
        assert_eq!(version, hex("A003 020102"), "version v3");
        let (serial, rest) = der::expect(rest, der::tag::INTEGER).unwrap();
        let (inner_algorithm, rest) = der::split_der(rest).unwrap();
        let (issuer, rest) = der::split_der(rest).unwrap();
        let (validity, rest) = der::split_der(rest).unwrap();
        let (subject, rest) = der::split_der(rest).unwrap();
        let (spki, rest) = der::split_der(rest).unwrap();
        let (tag, extensions_wrapper, rest) = der::parse_der(rest).unwrap();
        assert_eq!(tag, 0xA3);
        assert!(rest.is_empty());
        let outer_alg = der::expect_only(inner_algorithm, der::tag::SEQUENCE).unwrap();
        assert_eq!(der::decode_oid(der::expect(outer_alg, der::tag::OID).unwrap().0).unwrap(), algorithm);
        let mut extensions = Vec::new();
        for (_, extension) in der::parse_all(der::expect_only(extensions_wrapper, der::tag::SEQUENCE).unwrap()).unwrap() {
            let (oid, rest) = der::expect(extension, der::tag::OID).unwrap();
            let (critical, rest) = match der::expect(rest, der::tag::BOOLEAN) {
                Ok((value, rest)) => (value == [0xFF], rest),
                Err(_) => (false, rest),
            };
            let value = der::expect_only(rest, der::tag::OCTET_STRING).unwrap();
            extensions.push((der::decode_oid(oid).unwrap(), critical, value.to_vec()));
        }
        Cert {
            tbs: tbs_element.to_vec(),
            serial: serial.to_vec(),
            issuer: issuer.to_vec(),
            validity: validity.to_vec(),
            subject: subject.to_vec(),
            spki: spki.to_vec(),
            extensions,
            algorithm,
            signature: signature.to_vec(),
        }
    }

    fn extension(&self, n: u64) -> Option<&[u8]> {
        let mut oid = ARC.to_vec();
        oid.push(n);
        self.extensions.iter().find(|(o, _, _)| *o == oid).map(|(_, critical, value)| {
            assert!(!critical);
            value.as_slice()
        })
    }

    /// The UTF-8 common name of a Name with one CN attribute.
    fn common_name(name: &[u8]) -> String {
        let rdns = der::expect_only(name, der::tag::SEQUENCE).unwrap();
        let set = der::expect_only(rdns, der::tag::SET).unwrap();
        let attribute = der::expect_only(set, der::tag::SEQUENCE).unwrap();
        let (oid, value) = der::expect(attribute, der::tag::OID).unwrap();
        assert_eq!(der::decode_oid(oid).unwrap(), vec![2, 5, 4, 3]);
        String::from_utf8(der::expect_only(value, der::tag::UTF8_STRING).unwrap().to_vec()).unwrap()
    }

    /// Verify the signature with an RSA issuer key.
    fn verify_rsa(&self, n: &[u8], e: &[u8]) -> bool {
        self.algorithm == SHA256_WITH_RSA && rsa_verify(n, e, &digest_info_sha256(&self.tbs), &self.signature)
    }
}

fn issuer_rsa(card: &mut Card) -> (Vec<u8>, Vec<u8>) {
    match parse_public(&card.public_key(crt::ATT).0) {
        Public::Rsa { n, e } => (n, e),
        other => panic!("{other:?}"),
    }
}

/// SubjectPublicKeyInfo of an RSA key (RFC 3279 §2.3.1).
fn rsa_spki(n: &[u8], e: &[u8]) -> Vec<u8> {
    lk_codec::x509::PublicKey::Rsa { modulus: n.to_vec(), exponent: e.to_vec() }.to_der()
}

/// Catalog: "fresh independent own RSA2048 attestation issuer; never manufacturer trust".
/// A fresh applet generates the issuer, saves it at once, and keeps it across restarts.
#[test]
fn fresh_applet_provisions_rsa2048_issuer() {
    let mut card = Card::fresh(TestHost::new().seeded(4242));
    assert!(card.host.persisted(Record::OpenPgp).is_some());
    assert_eq!(card.key_status(), [0, 0, 0, 0x01]);
    assert_eq!(card.get_ok(0x00DA), hex(attr::RSA2048));
    let (n, e) = issuer_rsa(&mut card);
    assert_eq!(n.len(), 256);
    let certificate = card.get_ok(0x00FC);
    assert_eq!(card.certificate(3), certificate);
    let cert = Cert::parse(&certificate);
    assert_eq!(cert.issuer, cert.subject);
    assert_eq!(Cert::common_name(&cert.subject), "localkey software authenticator OpenPGP Attestation");
    assert_eq!(cert.spki, rsa_spki(&n, &e));
    assert!(cert.verify_rsa(&n, &e));
    assert!(cert.serial.len() <= 17 && cert.serial[0] & 0x80 == 0);
    // Observation `attestation_template_public_schema`: 1.3.6.1.4.1.41482.5.3 as a DER
    // OCTET STRING of three bytes (here the profile firmware 5.7.4).
    assert_eq!(cert.extension(3), Some(&hex("04 03 050704")[..]));
    card.reload();
    assert_eq!(card.get_ok(0x00FC), certificate);
    assert_eq!(issuer_rsa(&mut card), (n.clone(), e));
    // Another device gets its own issuer.
    let mut other = Card::fresh(TestHost::new().seeded(4343));
    assert_ne!(issuer_rsa(&mut other).0, n);
}

/// The issuer is provisioned even if the first save fails; the next successful save of
/// any command carries it.
#[test]
fn issuer_survives_failed_first_save() {
    let mut host = TestHost::new().seeded(77);
    host.fail_all(true);
    let mut card = Card::fresh(host);
    assert!(card.host.persisted(Record::OpenPgp).is_none());
    let certificate = card.get_ok(0x00FC);
    assert!(!certificate.is_empty());
    card.host.fail_all(false);
    card.admin();
    assert_eq!(card.put(0x005B, b"x"), 0x9000);
    card.reload();
    assert_eq!(card.get_ok(0x00FC), certificate);
}

/// GET ATTESTATION for a generated SIG key: the certificate replaces 7F21 occurrence 2,
/// is signed by the RSA issuer, copies the issuer certificate's subject and validity and
/// carries the Yubico metadata (attest.rs table).
#[test]
fn attest_generated_sig_key() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C1, attr::ED25519);
    let Public::Point(public) = parse_public(&card.generate(crt::SIG)) else { panic!() };
    // Cardholder name in ISO 8859-1 (spec §4.4.3.3): "Doe<<Jörg".
    assert_eq!(card.put(0x005B, b"Doe<<J\xF6rg"), 0x9000);
    assert_eq!(card.put(0x00C7, &[0x11; 20]), 0x9000);
    assert_eq!(card.put(0x00CE, &[0x5A, 0x00, 0x00, 0x01]), 0x9000);
    assert_eq!(card.put(0x00D6, &[0x02, 0x20]), 0x9000);
    card.put_sig_certificate(b"old");
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    for message in [b"a", b"b"] {
        assert_eq!(card.send_touch(&Card::ext_bytes(0x2A, 0x9E, 0x9A, message), true).1, 0x9000);
    }
    let (n, e) = issuer_rsa(&mut card);
    let issuer = Cert::parse(&card.get_ok(0x00FC));
    assert_eq!(card.attest(0x01), (vec![], 0x9000));
    let certificate = card.certificate(2);
    assert!(certificate.len() <= 2048);
    let cert = Cert::parse(&certificate);
    assert!(cert.verify_rsa(&n, &e));
    assert_eq!(cert.issuer, issuer.subject);
    assert_eq!(cert.validity, issuer.validity);
    assert_eq!(Cert::common_name(&cert.subject), "localkey OPGP Attestation SIG");
    assert_eq!(cert.spki, lk_codec::x509::PublicKey::Ed25519(public).to_der());
    // Positive serial from 16 random bytes.
    assert!(!cert.serial.is_empty() && cert.serial.len() <= 17 && cert.serial[0] & 0x80 == 0);
    assert_eq!(cert.extension(1), Some(&der::utf8_string("Doe<<Jörg")[..]));
    assert_eq!(cert.extension(2), Some(&hex("020101")[..]));
    assert_eq!(cert.extension(3), Some(&hex("0403050704")[..]));
    assert_eq!(cert.extension(4), Some(&der::octet_string(&[0x11; 20])[..]));
    assert_eq!(cert.extension(5), Some(&hex("04 04 5A000001")[..]));
    assert_eq!(cert.extension(6), Some(&hex("020102")[..]));
    assert_eq!(cert.extension(7), Some(&der::integer_u64(12_345_678)[..]));
    assert_eq!(cert.extension(8), Some(&hex("0401 02")[..]));
    assert_eq!(cert.extension(9), Some(&hex("0401 04")[..]));
    // Attestation does not move the signature counter.
    assert_eq!(card.signature_counter(), 2);
    // Two attestations differ (fresh serial).
    assert_eq!(card.attest(0x01).1, 0x9000);
    assert_ne!(card.certificate(2), certificate);
}

/// DEC and AUT certificates go to occurrences 1 and 0 and carry no counter extension.
#[test]
fn attest_dec_and_aut_keys() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C2, attr::X25519);
    card.set_attributes(0x00C3, attr::P256_ECDSA);
    let Public::Point(dec) = parse_public(&card.generate(crt::DEC)) else { panic!() };
    let Public::Point(aut) = parse_public(&card.generate(crt::AUT)) else { panic!() };
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    assert_eq!(card.attest(0x02).1, 0x9000);
    assert_eq!(card.attest(0x03).1, 0x9000);
    let (n, e) = issuer_rsa(&mut card);
    for (occurrence, public, label) in [
        (1, lk_codec::x509::PublicKey::X25519(dec), "DEC"),
        (0, lk_codec::x509::PublicKey::EcP256(aut), "AUT"),
    ] {
        let cert = Cert::parse(&card.certificate(occurrence));
        assert!(cert.verify_rsa(&n, &e));
        assert_eq!(cert.spki, public.to_der());
        assert_eq!(Cert::common_name(&cert.subject), format!("localkey OPGP Attestation {label}"));
        assert_eq!(cert.extension(6), None);
        assert_eq!(cert.extension(8), Some(&hex("0401 00")[..]));
    }
}

/// An imported EC issuer signs with ecdsa-with-SHA256 (catalog: "default/replacement
/// RSA/EC issuer ... independently signs new generated keys").
#[test]
fn replacement_ec_issuer_signs() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00DA, attr::P256_ECDSA);
    let issuer = EcPrivateKey::generate(Curve::P256, &mut SeededEntropy::new(81));
    assert_eq!(card.import(&import_data(crt::ATT, &[(0x92, issuer.scalar())])), 0x9000);
    card.set_attributes(0x00C1, attr::P384_ECDSA);
    card.generate(crt::SIG);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    assert_eq!(card.attest(0x01).1, 0x9000);
    let cert = Cert::parse(&card.certificate(2));
    assert_eq!(cert.algorithm, ECDSA_WITH_SHA256);
    let digest = lk_crypto::sha256(&cert.tbs);
    assert!(ecdsa_verify_prehash(Curve::P256, &issuer.public_uncompressed(), &digest, &cert.signature));
    // The issuer certificate FC was left as it was (now mismatched, catalog: not repaired).
    let fc = Cert::parse(&card.get_ok(0x00FC));
    assert_eq!(cert.issuer, fc.subject);
}

/// Catalog: "own software attestation and imported-key provenance rejection".
#[test]
fn imported_key_is_not_attested() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C1, attr::ED25519);
    assert_eq!(card.import(&import_data(crt::SIG, &[(0x92, &[7; 32])])), 0x9000);
    card.put_sig_certificate(b"kept");
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert_eq!(card.attest(0x01), (vec![], 0x6985));
    assert_eq!(card.certificate(2), b"kept");
}

/// Header rules (catalog: "proprietary CLA/header validation"; "GET ATTESTATION with
/// explicit Le=1 is rejected before replacing a SIG certificate").
#[test]
fn attest_header_rules() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C1, attr::ED25519);
    card.generate(crt::SIG);
    card.put_sig_certificate(b"sig-cert");
    card.select();
    assert_eq!(card.attest(0x01).1, 0x6982);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    assert_eq!(card.send(&hex("00FB0100")).1, 0x6E00);
    assert_eq!(card.send(&hex("90FB0100")).1, 0x6E00);
    assert_eq!(card.send(&hex("80FB010001")).1, 0x6700);
    assert_eq!(card.send(&hex("80FB01000155")).1, 0x6700);
    assert_eq!(card.send(&hex("80FB0101")).1, 0x6A86);
    for p1 in [0x00, 0x04, 0x81] {
        assert_eq!(card.attest(p1).1, 0x6A86, "{p1:02X}");
    }
    assert_eq!(card.attest(0x02).1, 0x6A88);
    assert_eq!(card.certificate(2), b"sig-cert");
    assert_eq!(card.send(&hex("80FB010000")).1, 0x9000);
    assert_ne!(card.certificate(2), b"sig-cert");
}

/// The certificate is saved before success; a failed save keeps the old one.
#[test]
fn attest_storage_failure_keeps_certificate() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C1, attr::ED25519);
    card.generate(crt::SIG);
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    card.host.fail_next_saves(1);
    assert_eq!(card.attest(0x01), (vec![], 0x6581));
    assert_eq!(card.certificate(2), b"");
    card.reload();
    assert_eq!(card.certificate(2), b"");
}

/// Catalog: "deliberately deleted key/certificate ... are not resurrected". Changing DA
/// deletes the issuer key; attestation then fails, also after an application reset and a
/// restart.
#[test]
fn deleted_issuer_key_not_resurrected() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C1, attr::ED25519);
    card.set_attributes(0x00DA, attr::P256_ECDSA);
    assert_eq!(card.key_status()[3], 0x00);
    card.generate(crt::SIG);
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert_eq!(card.attest(0x01).1, 0x6985);
    assert_eq!(card.send(&hex("00E60000")).1, 0x9000);
    assert_eq!(card.send(&hex("00440000")).1, 0x9000);
    card.reload();
    assert_eq!(card.key_status(), [0, 0, 0, 0]);
    assert_eq!(card.public_key(crt::ATT).1, 0x6A88);
    assert_eq!(card.get_ok(0x00DA), hex(attr::P256_ECDSA));
}

/// Catalog: "app reset retains current independent ATT key/certificate, attributes and
/// modeled metadata"; the retained issuer signs keys generated after the reset.
#[test]
fn reset_retains_issuer_and_signs_new_keys() {
    let mut card = Card::new();
    card.admin();
    assert_eq!(card.put(0x00D9, &[0x00, 0x20]), 0x9000);
    let (n, e) = issuer_rsa(&mut card);
    let issuer_certificate = card.get_ok(0x00FC);
    card.set_attributes(0x00C1, attr::ED25519);
    card.generate(crt::SIG);
    assert_eq!(card.send(&hex("00E60000")).1, 0x9000);
    assert_eq!(card.send(&hex("00440000")).1, 0x9000);
    card.reload();
    assert_eq!(card.key_status(), [0, 0, 0, 0x01]);
    assert_eq!(card.get_ok(0x00FC), issuer_certificate);
    assert_eq!(issuer_rsa(&mut card), (n.clone(), e.clone()));
    card.admin();
    card.set_attributes(0x00C1, attr::P256_ECDSA);
    card.generate(crt::SIG);
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert_eq!(card.attest(0x01).1, 0x9000);
    assert!(Cert::parse(&card.certificate(2)).verify_rsa(&n, &e));
}

/// An opaque issuer certificate is neither repaired nor needed: the profile's issuer name
/// and validity stand in, and FC stays as written.
#[test]
fn opaque_issuer_certificate_not_repaired() {
    let mut card = Card::new();
    card.admin();
    assert_eq!(card.put(0x00FC, b"att-cert"), 0x9000);
    card.set_attributes(0x00C1, attr::ED25519);
    card.generate(crt::SIG);
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert_eq!(card.attest(0x01).1, 0x9000);
    let cert = Cert::parse(&card.certificate(2));
    assert_eq!(Cert::common_name(&cert.issuer), "localkey software authenticator OpenPGP Attestation");
    let (n, e) = issuer_rsa(&mut card);
    assert!(cert.verify_rsa(&n, &e));
    assert_eq!(card.get_ok(0x00FC), b"att-cert");
}

/// Catalog: "bounded generated certificate with immutable failure state": a certificate
/// above the 2048-byte limit (C0) is refused and nothing changes.
#[test]
fn oversized_attestation_rejected() {
    let mut card = Card::new();
    card.admin();
    // An issuer certificate whose subject alone is about 1.9 KB (RFC 5280 layout up to the
    // subject; the rest is never read).
    let subject = der::sequence([der::octet_string(&[0x41; 1880])]);
    let validity = lk_codec::x509::Validity::rfc5280("20260101000000Z", "20300101000000Z").unwrap().to_der();
    let tbs = der::sequence([
        hex("A003020102"),
        der::integer(&[1]),
        der::sequence([der::oid(SHA256_WITH_RSA)]),
        der::sequence::<[&[u8]; 0], &[u8]>([]),
        validity,
        subject,
    ]);
    let fc = der::sequence([tbs]);
    assert!(fc.len() <= 2048);
    assert_eq!(card.put(0x00FC, &fc), 0x9000);
    card.set_attributes(0x00C1, attr::ED25519);
    card.generate(crt::SIG);
    card.put_sig_certificate(b"before");
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert_eq!(card.attest(0x01), (vec![], 0x6A84));
    assert_eq!(card.certificate(2), b"before");
}

/// Compatibility profile: product "YubiKey" in the subject, but the issuer stays this
/// engine's own identity (docs/DESIGN.md §9: no manufacturer attestation).
#[test]
fn yubikey_profile_names() {
    let mut card = Card::with_host(TestHost::with_profile(DeviceProfile::yubikey_5c_nano_5_7_4(12_345_678)));
    card.admin();
    card.set_attributes(0x00C3, attr::ED25519);
    card.generate(crt::AUT);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    assert_eq!(card.attest(0x03).1, 0x9000);
    let cert = Cert::parse(&card.certificate(0));
    assert_eq!(Cert::common_name(&cert.subject), "YubiKey OPGP Attestation AUT");
    assert!(!Cert::common_name(&cert.issuer).contains("Yubico"));
    assert_eq!(cert.extension(7), Some(&der::integer_u64(12_345_678)[..]));
    assert_eq!(cert.extension(9), Some(&hex("0401 04")[..]));
}

impl Card {
    /// Write the SIG certificate: 7F21 occurrence 2 (spec §7.2.5).
    fn put_sig_certificate(&mut self, value: &[u8]) {
        assert_eq!(self.select_occurrence(2), 0x9000);
        assert_eq!(self.put(0x7F21, value), 0x9000);
    }
}
