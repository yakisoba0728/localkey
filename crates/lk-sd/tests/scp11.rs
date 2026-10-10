//! SCP11a/b/c (GP Card Specification v2.3.1 Amendment F) driven by the independent OCE
//! in `common/scp11.rs`: handshakes and receipts, protected exchanges, EC key
//! management, OCE certificate chains, allowlists, the OCE cache, SCP11c rules,
//! handoff, reset and persistence.
//!
//! Known-answer values marked "Python/OpenSSL" were computed outside this crate with the
//! Python `cryptography` package 46 (OpenSSL ECDH on P-256, `X963KDF(SHA256)`, AES-CMAC,
//! AES-CBC) from fixed scalars, following Amd F §3.1.2 and the yubikit request layout;
//! the script builds every byte string by hand.

#![allow(clippy::unwrap_used, clippy::too_many_arguments, clippy::type_complexity)]

mod common;

use common::scp11::*;
use common::*;
use lk_codec::x509::{Extension, PublicKey, SignatureAlgorithm, key_usage};
use lk_core::{CardApplet, Record};
use lk_crypto::{Curve, EcPrivateKey};
use lk_sd::{Protocol, SecureChannel, SecurityDomain};
use lk_testkit::TestHost;

const FACTORY_KEY_INFO: &str = "C00401FF8810 C00402FF8810 C00403FF8810 C0061301B120F000";

fn fresh() -> (SecurityDomain, TestHost) {
    let mut host = TestHost::new();
    let sd = SecurityDomain::new(None, &mut host);
    (sd, host)
}

fn restart(host: &mut TestHost) -> SecurityDomain {
    let stored = host.persisted(Record::SecurityDomain);
    SecurityDomain::new(stored.as_deref(), host)
}

/// An SCP03 session with the default keys (Yubico yk5-apps-scp).
fn admin(sd: &mut SecurityDomain, host: &mut TestHost) -> (HostSession, SecureChannel) {
    open(sd, host, &StaticKeys::DEFAULT, 0xFF, 0x33)
}

/// A protected command expected to succeed; long data goes in the extended form.
fn ok(sd: &mut SecurityDomain, ch: &mut SecureChannel, host: &mut TestHost, s: &mut HostSession, cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let (resp, sw) = if data.len() > 200 { send_ext(sd, ch, host, s, cla, ins, p1, p2, data) } else { send(sd, ch, host, s, cla, ins, p1, p2, data) };
    assert_eq!(sw, 0x9000, "{cla:02X} {ins:02X} {p1:02X} {p2:02X}");
    resp
}

fn sw_of(sd: &mut SecurityDomain, ch: &mut SecureChannel, host: &mut TestHost, s: &mut HostSession, cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> u16 {
    if data.len() > 200 { send_ext(sd, ch, host, s, cla, ins, p1, p2, data).1 } else { send(sd, ch, host, s, cla, ins, p1, p2, data).1 }
}

fn store(sd: &mut SecurityDomain, ch: &mut SecureChannel, host: &mut TestHost, s: &mut HostSession, data: &[u8]) -> u16 {
    sw_of(sd, ch, host, s, 0x00, 0xE2, 0x90, 0x00, data)
}

/// Present a chain in plaintext (PSO per certificate); the status of each command.
fn present(sd: &mut SecurityDomain, host: &mut TestHost, kid: u8, kvn: u8, chain: &[Vec<u8>]) -> Vec<u16> {
    pso_apdus(kid, kvn, chain).iter().map(|apdu| status(&sd.handshake(apdu, host).0)).collect()
}

fn all_ok(statuses: &[u16]) -> bool {
    statuses.iter().all(|&s| s == 0x9000)
}

/// Plaintext GET DATA, following `61xx` with GET RESPONSE (ISO/IEC 7816-4 §7.6.1).
fn get(sd: &mut SecurityDomain, host: &mut TestHost, p1: u8, p2: u8, data: &[u8]) -> (Vec<u8>, u16) {
    let mut resp = plain(sd, host, &encode_apdu(0x00, 0xCA, p1, p2, data, Some(0), false));
    let mut out = Vec::new();
    loop {
        let sw = status(&resp);
        out.extend_from_slice(&resp[..resp.len() - 2]);
        if sw >> 8 != 0x61 {
            return (out, sw);
        }
        resp = plain(sd, host, &hex("00C0000000"));
    }
}

fn key_info(sd: &mut SecurityDomain, host: &mut TestHost) -> Vec<u8> {
    let (data, sw) = get(sd, host, 0x00, 0xE0, &[]);
    assert_eq!(sw, 0x9000);
    data
}

/// Run an SCP11 handshake (plaintext transport) and check it with the independent OCE.
fn authenticate(sd: &mut SecurityDomain, host: &mut TestHost, variant: Variant, kvn: u8, esk_start: u8, pk_sd: &[u8], sk_oce: Option<&EcPrivateKey>) -> (Established, SecureChannel) {
    let req = request(variant, kvn, key_from(esk_start));
    let (resp, ch) = sd.handshake(&req.apdu, host);
    let est = req.finish(&resp, pk_sd, sk_oce).unwrap_or_else(|e| panic!("{variant:?}: {e}"));
    (est, ch.expect("channel"))
}

/// Provision with the default SCP03 keys: an OCE CA key at (10, 03) from `pki`, an
/// SCP11a key at (11, 01) and an SCP11c key at (15, 01) (scalar `61..80`, the
/// known-answer key). Returns the SD public key.
fn provision(sd: &mut SecurityDomain, host: &mut TestHost, pki: &Pki) -> Vec<u8> {
    let (mut s, mut ch) = admin(sd, host);
    assert_eq!(ok(sd, &mut ch, host, &mut s, 0x80, 0xD8, 0x00, 0x10, &ca_key_data(0x03, &pki.ca.public_uncompressed())), vec![0x03]);
    let sd_key = key_from(0x61);
    let dek = s.dek;
    assert_eq!(ok(sd, &mut ch, host, &mut s, 0x80, 0xD8, 0x00, 0x11, &private_key_data(&dek, 0x01, sd_key.scalar())), vec![0x01]);
    assert_eq!(ok(sd, &mut ch, host, &mut s, 0x80, 0xD8, 0x00, 0x15, &private_key_data(&dek, 0x01, sd_key.scalar())), vec![0x01]);
    sd_key.public_uncompressed()
}

// ---------------------------------------------------------------------------------
// Known answers
// ---------------------------------------------------------------------------------

/// SCP11b with fixed scalars: SD key `01..20`, card ephemeral `21..40` (scripted host
/// entropy), OCE ephemeral `41..60`. Request, response, session keys, and the first
/// protected GET DATA `0066` (yubikit style: encrypted empty field, Le `00`) and its
/// R-ENC/R-MAC response match Python/OpenSSL byte for byte; the receipt is the first
/// MAC chaining value.
#[test]
fn scp11b_matches_independent_known_answers() {
    let (mut sd, mut host) = fresh();
    let (mut s, mut ch) = admin(&mut sd, &mut host);
    let d = key_from(0x01);
    let dek = s.dek;
    assert_eq!(ok(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x01, 0x13, &private_key_data(&dek, 0x01, d.scalar())), vec![0x01]);
    assert_eq!(d.public_uncompressed(), hex("04515C3D6EB9E396B904D3FECA7F54FDCD0CC1E997BF375DCA515AD0A6C3B4035F4536BE3A50F318FBF9A5475902A221502BEF0D57E08C53B2CC0A56F17D9F9354"));

    host.push_entropy(key_from(0x21).scalar());
    let req = request(Variant::B, 0x01, key_from(0x41));
    assert_eq!(req.data, hex("A60D9002110095013C8001888101105F494104261EFBD3550CF068EF013ED7366BA32F5D6FE557B4B2ABCE8ADE58CBA168A55E1788A0B29A56A6ABEC4084C0C96BD3DCBCA6B507F35DBEA9E985708479D8BDC9"));
    let (resp, channel) = sd.handshake(&req.apdu, &mut host);
    assert_eq!(resp, hex("5F4941041F140146BFB1B251F84F4DDBE0D4CDCFD77AFD984A9520E35794021F8312BB9EEC995A08B1FA7704DF3DCC0B50A9665263FB7711F95F9F8A449C5096E47C892B861007A8D0AEB5CCCBE71E22913A6FCED7F79000"));
    let mut est = req.finish(&resp, &d.public_uncompressed(), None).unwrap();
    assert_eq!(est.session.s_enc.to_vec(), hex("96E54A0B15160DFD731E248037128414"));
    assert_eq!(est.session.s_mac.to_vec(), hex("8B0B2C2A457BDDC8B6C11DAD4F305F78"));
    assert_eq!(est.session.s_rmac.to_vec(), hex("E8E990A24ACA722563514D46CDE96BE8"));
    assert_eq!(est.session.dek.to_vec(), hex("F5AAA9289C422F83228228F345095F6C"));

    let mut channel = channel.unwrap();
    assert_eq!(channel.protocol(), Protocol::Scp11b);
    assert_eq!(channel.key_version(), 0x01);
    assert_eq!(channel.security_level(), 0x33);
    let command = est.session.wrap(0x80, 0xCA, 0x00, 0x66, &[], Some(0), false);
    assert_eq!(command, hex("84CA00661876A05DBF13517041E3F03E90AC2F40EF85B4570107A74FEB00"));
    let wrapped = device_transmit(&mut sd, &mut channel, &mut host, &command);
    assert_eq!(wrapped, hex("20B1B97C9771DCE25C8D6C6E546BA4F0064C27D4413058AC2333FC961F4250C2B25735D8180EC28F90FD203D1400AEC14400B53E955E1D423560CA98C2CE59F710AB4EED32D5CEFC9000"));
    let (data, sw) = est.session.unwrap(&wrapped).unwrap();
    assert_eq!(sw, 0x9000);
    assert_eq!(data.len(), 63);
}

/// SCP11a and SCP11c with fixed scalars: SD key `61..80`, OCE static (leaf certificate)
/// key `81..A0`, OCE ephemeral `41..60`, card ephemeral `21..40` (SCP11a). Responses
/// and S-DEK match Python/OpenSSL. SCP11c answers with PK.SD and uses SK.SD for both
/// ECDH terms (catalog SecurityDomain_scp11c).
#[test]
fn scp11a_and_scp11c_match_independent_known_answers() {
    let (mut sd, mut host) = fresh();
    let pki = pki(0);
    let pk_sd = provision(&mut sd, &mut host, &pki);
    assert_eq!(pk_sd, hex("04BD5714B9C20400411F1E51DBFF63647F05D1D70B55FC200C6CAD10C2F4614DC1E5048562F731F54573C04224D973A916A59F526A8268076FC1CFA92A5F143F19"));
    assert_eq!(pki.leaf.public_uncompressed(), hex("04ECB6A2F86C7825EE71D022C29B9F8AA35971520EC3F9739855635765EAD1BD14ADAD028BFBA628ED75B72E3CBEB1EF192E60F52B3E2021497DF3AFB3006550DF"));
    assert!(all_ok(&present(&mut sd, &mut host, 0x10, 0x03, &pki.full_chain())));

    host.push_entropy(key_from(0x21).scalar());
    let req = request(Variant::A, 0x01, key_from(0x41));
    let (resp, ch) = sd.handshake(&req.apdu, &mut host);
    assert_eq!(resp, hex("5F4941041F140146BFB1B251F84F4DDBE0D4CDCFD77AFD984A9520E35794021F8312BB9EEC995A08B1FA7704DF3DCC0B50A9665263FB7711F95F9F8A449C5096E47C892B86100ABFCBDA6222741F5CD215DCC88B46BC9000"));
    let est = req.finish(&resp, &pk_sd, Some(&pki.leaf)).unwrap();
    assert_eq!(est.session.dek.to_vec(), hex("685CB041650AD47C855C4A76A590E227"));
    assert_eq!(ch.unwrap().protocol(), Protocol::Scp11a);

    let req = request(Variant::C, 0x01, key_from(0x41));
    let (resp, ch) = sd.handshake(&req.apdu, &mut host);
    assert_eq!(resp, hex("5F494104BD5714B9C20400411F1E51DBFF63647F05D1D70B55FC200C6CAD10C2F4614DC1E5048562F731F54573C04224D973A916A59F526A8268076FC1CFA92A5F143F19861093004DC57E3423A785425E4359AF6EE49000"));
    let est = req.finish(&resp, &pk_sd, Some(&pki.leaf)).unwrap();
    assert_eq!(est.session.dek.to_vec(), hex("F1E8695C2E241FA1357A1F81326D1976"));
    assert_eq!(est.card_point, pk_sd, "SCP11c returns the static SD point");
    assert_eq!(ch.unwrap().protocol(), Protocol::Scp11c);
    // Same request, same response (no card randomness).
    let (again, _) = sd.handshake(&req.apdu, &mut host);
    assert_eq!(again, resp);
}

// ---------------------------------------------------------------------------------
// SCP11b and the factory identity
// ---------------------------------------------------------------------------------

/// The factory SCP11b key has its own self-signed certificate in the store (catalog
/// SecurityDomain_profile: critical role and ECKA usage, self signature verified
/// independently). GET DATA `BF21` works without a session and chains a long answer
/// with `61xx`; SCP11b then authenticates with the certificate's key, protected
/// exchanges work, a second identical request gets a fresh card key, and the session
/// cannot manage keys (`6982`, catalog SCP11: "SCP11b cannot provision").
#[test]
fn scp11b_with_the_factory_certificate() {
    let (mut sd, mut host) = fresh();
    let (bundle, sw) = get(&mut sd, &mut host, 0xBF, 0x21, &hex("A60483021301"));
    assert_eq!(sw, 0x9000);
    let certs = der_split_all(&bundle);
    assert_eq!(certs.len(), 1);
    let (pk_sd, self_signed) = cert_key_and_check(&certs[0], None);
    assert!(self_signed, "self signature verifies");
    let (critical, usage) = cert_extension(&certs[0], &[2, 5, 29, 15]).unwrap();
    assert!(critical);
    assert_eq!(usage, lk_codec::der::named_bit_string(u64::from(key_usage::KEY_AGREEMENT)));
    assert!(cert_extension(&certs[0], &[2, 5, 29, 19]).unwrap().0, "critical basicConstraints");
    // Long plaintext answers are chained (ISO/IEC 7816-4 §5.1.3) when Le is short.
    let first = plain(&mut sd, &mut host, &hex("00CABF2106A604830213010A"));
    assert_eq!(status(&first) >> 8, 0x61);

    let cplc = get(&mut sd, &mut host, 0x9F, 0x7F, &[]).0;
    let (mut est, mut ch) = authenticate(&mut sd, &mut host, Variant::B, 0x00, 0x41, &pk_sd, None);
    let (data, sw) = send(&mut sd, &mut ch, &mut host, &mut est.session, 0x80, 0xCA, 0x00, 0x66, &[]);
    assert_eq!((data.len(), sw), (63, 0x9000));
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut est.session, 0x80, 0xCA, 0x9F, 0x7F, &[]), (cplc, 0x9000), "CPLC stable through SCP11b reads");
    for (ins, p1, p2, data) in [
        (0xD8, 0x00, 0x81, StaticKeys::DEFAULT.enc.to_vec()),
        (0xE4, 0x00, 0x00, hex("D00113")),
        (0xF1, 0x00, 0x13, hex("02F00100")),
    ] {
        assert_eq!(send(&mut sd, &mut ch, &mut host, &mut est.session, 0x80, ins, p1, p2, &data).1, 0x6982);
    }
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut est.session, &ca_issuer_data(0x13, 0x01, &[1; 20])), 0x6982);
    assert!(ch.is_open());
    // A second identical request re-randomizes the card contribution.
    let req = request(Variant::B, 0x01, key_from(0x41));
    let a = sd.handshake(&req.apdu, &mut host).0;
    let b = sd.handshake(&req.apdu, &mut host).0;
    assert_ne!(a, b);
    req.finish(&b, &pk_sd, None).unwrap();
}

// ---------------------------------------------------------------------------------
// SCP11a with certificate chains
// ---------------------------------------------------------------------------------

/// SCP11a with a root/intermediate/leaf chain, an omitted root, and a leaf signed
/// directly by the CA (catalog SecurityDomain_incremental_pso: optional root,
/// intermediate and direct leaf). Each chain authorises MUTUAL AUTHENTICATE; the session
/// manages keys with the session DEK (catalog SCP11: "private-key import with session
/// DEK").
#[test]
fn scp11a_with_full_omitted_root_and_direct_chains() {
    let (mut sd, mut host) = fresh();
    let pki = pki(0);
    let pk_sd = provision(&mut sd, &mut host, &pki);
    for chain in [pki.full_chain(), vec![pki.inter_cert.clone(), pki.leaf_cert.clone()], vec![pki.direct_leaf_cert.clone()]] {
        assert!(!sd.has_verified_oce());
        assert!(all_ok(&present(&mut sd, &mut host, 0x10, 0x03, &chain)));
        assert!(sd.has_verified_oce());
        let (mut est, mut ch) = authenticate(&mut sd, &mut host, Variant::A, 0x01, 0x41, &pk_sd, Some(&pki.leaf));
        assert_eq!(send(&mut sd, &mut ch, &mut host, &mut est.session, 0x80, 0xCA, 0x00, 0x66, &[]).1, 0x9000);
        sd.end_session();
    }
    // Management under SCP11a: import an SCP11b key with the session DEK, then use it.
    assert!(all_ok(&present(&mut sd, &mut host, 0x10, 0x03, &pki.full_chain())));
    let (mut est, mut ch) = authenticate(&mut sd, &mut host, Variant::A, 0x01, 0x41, &pk_sd, Some(&pki.leaf));
    let imported = key_from(0x33);
    let dek = est.session.dek;
    assert_eq!(ok(&mut sd, &mut ch, &mut host, &mut est.session, 0x80, 0xD8, 0x00, 0x13, &private_key_data(&dek, 0x02, imported.scalar())), vec![0x02]);
    assert_eq!(sd.remaining_tries(0x13, 0x02), Some(64));
    // An SCP03 key set wrapped with the SCP11a S-DEK; it then authenticates.
    let set = StaticKeys::from_seed(5);
    let data = est.session.put_key_data(0x05, &set);
    assert_eq!(ok(&mut sd, &mut ch, &mut host, &mut est.session, 0x80, 0xD8, 0x00, 0x81, &data), put_key_response(0x05, &set));
    let generated = ok(&mut sd, &mut ch, &mut host, &mut est.session, 0x80, 0xF1, 0x00, 0x13, &hex("03F00100"));
    assert_eq!(&generated[..2], &[0xB0, 0x41]);
    assert_eq!(ok(&mut sd, &mut ch, &mut host, &mut est.session, 0x80, 0xE4, 0x00, 0x00, &hex("D00113D20103")), Vec::<u8>::new());
    drop(ch);
    authenticate(&mut sd, &mut host, Variant::B, 0x02, 0x45, &imported.public_uncompressed(), None);
    open(&mut sd, &mut host, &set, 0x05, 0x33);
}

/// SCP11a/c without a verified OCE (none presented, an incomplete chain, after SELECT):
/// `6985`, and each such request uses a try (catalog SecurityDomain_oce_cache).
#[test]
fn mutual_authenticate_needs_a_verified_oce() {
    let (mut sd, mut host) = fresh();
    let pki = pki(0);
    provision(&mut sd, &mut host, &pki);
    let req = request(Variant::A, 0x01, key_from(0x41));
    assert_eq!(sd.handshake(&req.apdu, &mut host).0, hex("6985"));
    assert_eq!(sd.remaining_tries(0x11, 0x01), Some(63));
    // Incomplete chain: the last PSO still announced more certificates.
    let apdus = pso_apdus(0x10, 0x03, &pki.full_chain());
    for apdu in &apdus[..2] {
        assert_eq!(sd.handshake(apdu, &mut host).0, hex("9000"));
    }
    assert_eq!(sd.handshake(&req.apdu, &mut host).0, hex("6985"));
    let req_c = request(Variant::C, 0x01, key_from(0x41));
    assert_eq!(sd.handshake(&req_c.apdu, &mut host).0, hex("6985"));
    assert_eq!(sd.remaining_tries(0x15, 0x01), Some(63));
    // After a complete chain, SELECT drops the cache.
    assert!(all_ok(&present(&mut sd, &mut host, 0x10, 0x03, &pki.full_chain())));
    sd.select(&hex("00A4040008A00000015100000000"), &mut host);
    assert!(!sd.has_verified_oce());
    assert_eq!(sd.handshake(&req.apdu, &mut host).0, hex("6985"));
    assert_eq!(sd.remaining_tries(0x11, 0x01), Some(61));
}

/// Certificate checks per prefix (catalog SecurityDomain_profile and
/// SecurityDomain_incremental_pso): each refusal answers `6982`, drops the chain and the
/// cached OCE and changes no persistent state; malformed certificates answer `6A80` and
/// use one try of the initial CA, even when a continuation names another CA.
#[test]
fn certificate_chain_checks() {
    let pki = pki(0);
    let other = key_from(0x55);
    let inter_point = PublicKey::EcP256(pki.inter.public_uncompressed());
    let leaf_point = PublicKey::EcP256(pki.leaf.public_uncompressed());
    let inter = |spec: CertSpec| spec.build(inter_point.clone(), &pki.ca);
    let leaf = |spec: CertSpec| spec.build(leaf_point.clone(), &pki.inter);
    let base_inter = || CertSpec { ski: Some(pki.inter_ski.clone()), ..CertSpec::ca(&pki.inter_serial, "OCE Root", "OCE Intermediate", Some(0)) };
    let base_leaf = || CertSpec::leaf(&pki.leaf_serial, "OCE Intermediate", "OCE");
    let qualifier = lk_codec::der::sequence([lk_codec::der::sequence([
        lk_codec::der::oid(&[1, 2, 3, 4]),
        lk_codec::der::sequence([lk_codec::der::sequence([lk_codec::der::oid(&[1, 3, 6, 1, 5, 5, 7, 2, 1]), lk_codec::der::ia5_string("http://x")])]),
    ])]);
    let plain_policy = lk_codec::der::sequence([lk_codec::der::sequence([lk_codec::der::oid(&[1, 2, 840, 114283, 100, 0, 1, 2, 1])])]);
    let p384 = EcPrivateKey::generate(Curve::P384, &mut TestHost::new());

    // (description, chain, expected statuses)
    let cases: Vec<(&str, Vec<Vec<u8>>, Vec<u16>)> = vec![
        ("leaf signed by another key", vec![pki.inter_cert.clone(), base_leaf().build(leaf_point.clone(), &other)], vec![0x9000, 0x6982]),
        ("intermediate not a CA", vec![inter(CertSpec { basic: Some((false, None)), ..base_inter() }), pki.leaf_cert.clone()], vec![0x6982, 0x6982]),
        ("intermediate without basicConstraints", vec![inter(CertSpec { basic: None, ..base_inter() }), pki.leaf_cert.clone()], vec![0x6982, 0x6982]),
        ("intermediate without keyCertSign", vec![inter(CertSpec { usage: Some(key_usage::DIGITAL_SIGNATURE), ..base_inter() }), pki.leaf_cert.clone()], vec![0x6982, 0x6982]),
        ("leaf is a CA", vec![pki.inter_cert.clone(), leaf(CertSpec { basic: Some((true, None)), ..base_leaf() })], vec![0x9000, 0x6982]),
        ("leaf without keyAgreement", vec![pki.inter_cert.clone(), leaf(CertSpec { usage: Some(key_usage::DIGITAL_SIGNATURE), ..base_leaf() })], vec![0x9000, 0x6982]),
        ("leaf without keyUsage is accepted", vec![pki.inter_cert.clone(), leaf(CertSpec { usage: None, ..base_leaf() })], vec![0x9000, 0x9000]),
        ("path length exhausted by the root", vec![
            CertSpec { ski: Some(pki.root_ski.clone()), ..CertSpec::ca(&pki.root_serial, "OCE Root", "OCE Root", Some(0)) }.build_for(&pki.ca, &pki.ca),
            pki.inter_cert.clone(),
            pki.leaf_cert.clone(),
        ], vec![0x9000, 0x6982, 0x6982]),
        ("validity inverted", vec![pki.inter_cert.clone(), leaf(CertSpec { not_before: "20300101000000Z".into(), not_after: "20290101000000Z".into(), ..base_leaf() })], vec![0x9000, 0x6982]),
        // RFC 5280 §6.1.3 (a)(2) against the earliest possible current time (TestHost
        // lends no wall clock): the profile's certificate start date 2026-01-01
        // (lk_core::DeviceProfile::own). With a clock: `pso_validity_follows_a_lent_wall_clock`.
        ("leaf expired before the profile date", vec![pki.inter_cert.clone(), leaf(CertSpec { not_before: "20200101000000Z".into(), not_after: "20251231235959Z".into(), ..base_leaf() })], vec![0x9000, 0x6982]),
        ("intermediate expired before the profile date", vec![inter(CertSpec { not_before: "20150101000000Z".into(), not_after: "20240101000000Z".into(), ..base_inter() }), pki.leaf_cert.clone()], vec![0x6982, 0x6982]),
        ("old leaf still valid after the profile date", vec![pki.inter_cert.clone(), leaf(CertSpec { not_before: "20100101000000Z".into(), not_after: "20260101000000Z".into(), ..base_leaf() })], vec![0x9000, 0x9000]),
        ("unknown critical extension", vec![pki.inter_cert.clone(), leaf(CertSpec { extra: vec![Extension::new(&[1, 2, 3, 4, 5], true, &[0x05, 0x00])], ..base_leaf() })], vec![0x9000, 0x6982]),
        ("unknown non-critical extension is ignored", vec![pki.inter_cert.clone(), leaf(CertSpec { extra: vec![Extension::new(&[1, 2, 3, 4, 5], false, &[0x05, 0x00])], ..base_leaf() })], vec![0x9000, 0x9000]),
        ("critical policies with a qualifier", vec![pki.inter_cert.clone(), leaf(CertSpec { extra: vec![Extension::new(&[2, 5, 29, 32], true, &qualifier)], ..base_leaf() })], vec![0x9000, 0x6982]),
        ("critical policies without qualifiers", vec![pki.inter_cert.clone(), leaf(CertSpec { extra: vec![Extension::new(&[2, 5, 29, 32], true, &plain_policy)], ..base_leaf() })], vec![0x9000, 0x9000]),
        ("P-384 leaf key", vec![pki.inter_cert.clone(), base_leaf().build(PublicKey::EcP384(p384.public_uncompressed()), &pki.inter)], vec![0x9000, 0x6982]),
        ("ecdsa-with-SHA384", vec![pki.inter_cert.clone(), leaf(CertSpec { algorithm: SignatureAlgorithm::EcdsaWithSha384, ..base_leaf() })], vec![0x9000, 0x6982]),
        ("AKI does not match the issuer SKI", vec![pki.inter_cert.clone(), leaf(CertSpec { aki: Some(vec![9, 9, 9]), ..base_leaf() })], vec![0x9000, 0x6982]),
        ("matching AKI", vec![pki.inter_cert.clone(), leaf(CertSpec { aki: Some(pki.inter_ski.clone()), ..base_leaf() })], vec![0x9000, 0x9000]),
        ("eight certificates", (0..6).map(|_| pki.root_cert.clone()).chain([pki.inter_cert.clone(), pki.leaf_cert.clone()]).collect(), vec![0x9000; 8]),
        ("nine certificates", (0..7).map(|_| pki.root_cert.clone()).chain([pki.inter_cert.clone(), pki.leaf_cert.clone()]).collect(), vec![0x9000; 8].into_iter().chain([0x6982]).collect()),
    ];
    for (name, chain, expected) in cases {
        let (mut sd, mut host) = fresh();
        provision(&mut sd, &mut host, &pki);
        let before = host.persisted(Record::SecurityDomain);
        let got = present(&mut sd, &mut host, 0x10, 0x03, &chain);
        assert_eq!(got, expected, "{name}");
        let accepted = got.iter().all(|&s| s == 0x9000);
        assert_eq!(sd.has_verified_oce(), accepted, "{name}");
        if !accepted {
            assert_eq!(host.persisted(Record::SecurityDomain), before, "{name}: no state change");
            assert_eq!(sd.remaining_tries(0x10, 0x03), Some(64), "{name}: no CA try used");
        }
    }

    // Malformed: garbage, a truncated certificate and a duplicate extension use a try of
    // the CA named first, also when the continuation names another CA.
    let duplicate = leaf(CertSpec { extra: vec![Extension::key_usage(key_usage::KEY_AGREEMENT)], ..base_leaf() });
    let (mut sd, mut host) = fresh();
    provision(&mut sd, &mut host, &pki);
    let (mut s, mut ch) = admin(&mut sd, &mut host);
    ok(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x00, 0x20, &ca_key_data(0x01, &other.public_uncompressed()));
    let before = host.persisted(Record::SecurityDomain);
    assert_eq!(present(&mut sd, &mut host, 0x10, 0x03, &[vec![0x30, 0x03, 0x02, 0x01, 0x01]]), vec![0x6A80]);
    assert_eq!(present(&mut sd, &mut host, 0x10, 0x03, &[pki.leaf_cert[..pki.leaf_cert.len() - 1].to_vec()]), vec![0x6A80]);
    let mut apdus = pso_apdus(0x10, 0x03, &[pki.inter_cert.clone(), duplicate]);
    apdus[1][2] = 0x01;
    apdus[1][3] = 0x20;
    assert_eq!(status(&sd.handshake(&apdus[0], &mut host).0), 0x9000);
    assert_eq!(status(&sd.handshake(&apdus[1], &mut host).0), 0x6A80);
    assert_eq!(sd.remaining_tries(0x10, 0x03), Some(61));
    assert_eq!(sd.remaining_tries(0x20, 0x01), Some(64));
    assert_ne!(host.persisted(Record::SecurityDomain), before);
    assert!(!sd.has_verified_oce());
    // Later P1/P2 are ignored: a valid continuation naming another CA still verifies
    // under the first one.
    let mut apdus = pso_apdus(0x10, 0x03, &pki.full_chain());
    for apdu in apdus.iter_mut().skip(1) {
        apdu[2] = 0x01;
        apdu[3] = (apdu[3] & 0x80) | 0x20;
    }
    assert!(apdus.iter().all(|a| status(&sd.handshake(a, &mut host).0) == 0x9000));
    assert!(sd.has_verified_oce());
    // A complete verification restores the CA's tries.
    assert_eq!(sd.remaining_tries(0x10, 0x03), Some(64));
}

/// `Host::unix_time` (docs/CONTRACTS.md "Applications B": "for certificate validity").
/// With a reading, every presented certificate must be valid at that instant (RFC 5280
/// §6.1.3 (a)(2); §4.1.2.5: both bounds inclusive), so a notBefore in the future is
/// refused with `6982` like an expired notAfter, and the profile's certificate start
/// date no longer matters. Without one, the floor rule is unchanged (notAfter not before
/// the profile date 2026-01-01; a future notBefore passes). Refusals change no
/// persistent state and use no CA try. The `pki` chain is valid 2025-01-01 to
/// 2045-01-01. Instants: Python 3 `datetime(..., tzinfo=timezone.utc).timestamp()`.
#[test]
fn pso_validity_follows_a_lent_wall_clock() {
    const Y2024_12_31_235959: u64 = 1_735_689_599;
    const Y2025_06_01: u64 = 1_748_736_000;
    const Y2027_01_15_080000: u64 = 1_800_000_000;
    const Y2029_12_31_235959: u64 = 1_893_455_999;
    const Y2030_01_01: u64 = 1_893_456_000;
    const Y2045_01_01: u64 = 2_366_841_600;
    const Y2045_01_01_000001: u64 = 2_366_841_601;
    let pki = pki(0);
    let leaf_point = PublicKey::EcP256(pki.leaf.public_uncompressed());
    let leaf = |not_before: &str, not_after: &str| {
        CertSpec { not_before: not_before.into(), not_after: not_after.into(), ..CertSpec::leaf(&pki.leaf_serial, "OCE Intermediate", "OCE") }
            .build(leaf_point.clone(), &pki.inter)
    };
    let with_inter = |leaf: Vec<u8>| vec![pki.inter_cert.clone(), leaf];
    let from_2030 = with_inter(leaf("20300101000000Z", "20400101000000Z"));
    let until_2026 = with_inter(leaf("20100101000000Z", "20260101000000Z"));
    let until_2027 = with_inter(leaf("20250101000000Z", "20270101000000Z"));
    let ended_2025 = with_inter(leaf("20200101000000Z", "20251231235959Z"));
    let ok2 = vec![0x9000, 0x9000];
    let leaf_refused = vec![0x9000, 0x6982];
    // A refused first certificate drops the chain, so the next one starts a new chain:
    // the intermediate is refused for the same date, the leaf because the CA key did
    // not sign it.
    let all_refused = vec![0x6982, 0x6982, 0x6982];

    let cases: Vec<(Option<u64>, &str, Vec<Vec<u8>>, Vec<u16>)> = vec![
        (None, "no clock: full chain", pki.full_chain(), vec![0x9000; 3]),
        (None, "no clock: a future notBefore cannot be detected", from_2030.clone(), ok2.clone()),
        (None, "no clock: valid on the profile date", until_2026.clone(), ok2.clone()),
        (None, "no clock: expired before the profile date", ended_2025.clone(), leaf_refused.clone()),
        (Some(Y2027_01_15_080000), "full chain inside its period", pki.full_chain(), vec![0x9000; 3]),
        (Some(Y2027_01_15_080000), "leaf not yet valid", from_2030.clone(), leaf_refused.clone()),
        (Some(Y2027_01_15_080000), "leaf expired on 2026-01-01", until_2026, leaf_refused.clone()),
        (Some(Y2027_01_15_080000), "leaf expired on 2027-01-01", until_2027, leaf_refused.clone()),
        (Some(Y2029_12_31_235959), "one second before notBefore", from_2030.clone(), leaf_refused.clone()),
        (Some(Y2030_01_01), "notBefore is inclusive", from_2030, ok2.clone()),
        (Some(Y2025_06_01), "the reading, not the profile date, decides", ended_2025, ok2),
        (Some(Y2024_12_31_235959), "root and intermediate not yet valid", pki.full_chain(), all_refused.clone()),
        (Some(Y2045_01_01), "notAfter is inclusive", pki.full_chain(), vec![0x9000; 3]),
        (Some(Y2045_01_01_000001), "root and intermediate expired", pki.full_chain(), all_refused),
        (Some(u64::MAX), "a reading past 9999 saturates: everything expired", pki.full_chain(), vec![0x6982; 3]),
    ];
    for (unix_time, name, chain, expected) in cases {
        let mut host = ClockHost { unix_time, ..ClockHost::default() };
        let mut sd = SecurityDomain::new(None, &mut host);
        provision(&mut sd, &mut host.inner, &pki);
        let before = host.inner.persisted(Record::SecurityDomain);
        let got: Vec<u16> = pso_apdus(0x10, 0x03, &chain).iter().map(|apdu| status(&sd.handshake(apdu, &mut host).0)).collect();
        assert_eq!(got, expected, "{name}");
        let accepted = got.iter().all(|&s| s == 0x9000);
        assert_eq!(sd.has_verified_oce(), accepted, "{name}");
        if !accepted {
            assert_eq!(host.inner.persisted(Record::SecurityDomain), before, "{name}: no state change");
            assert_eq!(sd.remaining_tries(0x10, 0x03), Some(64), "{name}: no CA try used");
        }
    }

    // End to end: a chain accepted under the lent clock authorizes SCP11a, and the
    // independent OCE verifies the receipt.
    let mut host = ClockHost { unix_time: Some(Y2027_01_15_080000), ..ClockHost::default() };
    let mut sd = SecurityDomain::new(None, &mut host);
    let pk_sd = provision(&mut sd, &mut host.inner, &pki);
    let statuses: Vec<u16> = pso_apdus(0x10, 0x03, &pki.full_chain()).iter().map(|apdu| status(&sd.handshake(apdu, &mut host).0)).collect();
    assert!(all_ok(&statuses));
    let req = request(Variant::A, 0x01, key_from(0x41));
    let (resp, ch) = sd.handshake(&req.apdu, &mut host);
    req.finish(&resp, &pk_sd, Some(&pki.leaf)).unwrap();
    assert!(ch.is_some_and(|c| c.protocol() == Protocol::Scp11a));
}

/// Allowlists (Yubico SD commands: every presented certificate is checked; catalog
/// SecurityDomain_allowlist): serials compare as integers (sign byte ignored), omitted
/// roots need not be listed, lists of different CAs are never combined, a wildcard keeps
/// every CA that verifies, an empty list removes the restriction.
#[test]
fn allowlist_rules() {
    let pki = pki(0);
    let (mut sd, mut host) = fresh();
    provision(&mut sd, &mut host, &pki);
    let (mut s, mut ch) = admin(&mut sd, &mut host);
    let all: Vec<&[u8]> = vec![&pki.root_serial, &pki.inter_serial, &pki.leaf_serial];
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &allowlist_data(0x10, 0x03, &all, None)), 0x9000);
    assert!(all_ok(&present(&mut sd, &mut host, 0x10, 0x03, &pki.full_chain())));
    // Without the intermediate's serial the chain stops at the intermediate.
    let no_inter: Vec<&[u8]> = vec![&pki.root_serial, &pki.leaf_serial];
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &allowlist_data(0x10, 0x03, &no_inter, None)), 0x9000);
    assert_eq!(present(&mut sd, &mut host, 0x10, 0x03, &pki.full_chain())[..2], [0x9000, 0x6982]);
    // An omitted root needs no entry; presenting it then fails at the root.
    let tail: Vec<&[u8]> = vec![&pki.inter_serial, &pki.leaf_serial];
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &allowlist_data(0x10, 0x03, &tail, None)), 0x9000);
    assert!(all_ok(&present(&mut sd, &mut host, 0x10, 0x03, &[pki.inter_cert.clone(), pki.leaf_cert.clone()])));
    assert_eq!(present(&mut sd, &mut host, 0x10, 0x03, &pki.full_chain())[0], 0x6982);
    // Serials without the sign byte match too (integers).
    let raw = tlv(&[0xA6], &tlv(&[0x83], &[0x10, 0x03]));
    let list = [tlv(&[0x93], &pki.inter_serial), tlv(&[0x93], &[&[0u8, 0][..], &pki.leaf_serial].concat())].concat();
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &[raw, tlv(&[0x70], &list)].concat()), 0x9000);
    assert!(all_ok(&present(&mut sd, &mut host, 0x10, 0x03, &[pki.inter_cert.clone(), pki.leaf_cert.clone()])));
    // Two CAs with the same key: each list covers part of the chain; no union.
    ok(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x00, 0x20, &ca_key_data(0x01, &pki.ca.public_uncompressed()));
    let part_a: Vec<&[u8]> = vec![&pki.root_serial, &pki.inter_serial];
    let part_b: Vec<&[u8]> = vec![&pki.root_serial, &pki.leaf_serial];
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &allowlist_data(0x10, 0x03, &part_a, None)), 0x9000);
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &allowlist_data(0x20, 0x01, &part_b, None)), 0x9000);
    let wildcard = present(&mut sd, &mut host, 0x00, 0x00, &pki.full_chain());
    assert_ne!(wildcard.last(), Some(&0x9000), "lists of different CAs are not combined: {wildcard:04X?}");
    // The wildcard moves on to a CA whose list allows the chain; the explicit CA stays bound.
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &allowlist_data(0x20, 0x01, &all, None)), 0x9000);
    assert!(all_ok(&present(&mut sd, &mut host, 0x00, 0x00, &pki.full_chain())));
    assert!(!all_ok(&present(&mut sd, &mut host, 0x10, 0x03, &pki.full_chain())));
    // A direct leaf needs only its own serial; a listed serial bypasses no check.
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &allowlist_data(0x10, 0x03, &[&pki.direct_serial], None)), 0x9000);
    assert!(all_ok(&present(&mut sd, &mut host, 0x10, 0x03, std::slice::from_ref(&pki.direct_leaf_cert))));
    let forged = CertSpec::leaf(&pki.direct_serial, "OCE Root", "OCE direct").build_for(&pki.leaf, &key_from(0x55));
    assert_eq!(present(&mut sd, &mut host, 0x10, 0x03, &[forged]), vec![0x6982]);
    let wrong_role = CertSpec { usage: Some(key_usage::DIGITAL_SIGNATURE), ..CertSpec::leaf(&pki.direct_serial, "OCE Root", "OCE direct") }.build_for(&pki.leaf, &pki.ca);
    assert_eq!(present(&mut sd, &mut host, 0x10, 0x03, &[wrong_role]), vec![0x6982]);
    assert!(ch.is_open(), "refused prefixes leave the SCP03 channel alone");
    // An empty list removes the restriction.
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &allowlist_data(0x10, 0x03, &[], None)), 0x9000);
    assert!(all_ok(&present(&mut sd, &mut host, 0x10, 0x03, &pki.full_chain())));
    // Refusals: missing CA, private key, too many serials, malformed entries.
    let many: Vec<Vec<u8>> = (0..65u8).map(|i| vec![1, i]).collect();
    let many: Vec<&[u8]> = many.iter().map(Vec::as_slice).collect();
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &allowlist_data(0x10, 0x09, &all, None)), 0x6A88);
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &allowlist_data(0x11, 0x01, &all, None)), 0x6A88);
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &allowlist_data(0x10, 0x03, &many, None)), 0x6A84);
    let bad = [tlv(&[0xA6], &tlv(&[0x83], &[0x10, 0x03])), tlv(&[0x70], &tlv(&[0x94], &[1]))].concat();
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &bad), 0x6A80);
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &allowlist_data(0x10, 0x03, &all, Some(1))), 0x6A80, "counter outside SCP11c");
}

/// OCE cache invalidation (catalog SecurityDomain_oce_cache, SecurityDomain_shared_state):
/// every successful allowlist update (identical, clear, other CA) drops it, a refused one
/// does not; SELECT, restart, a new partial chain and a plaintext command in an open
/// channel drop it; a second complete chain replaces it; CA-key replacement keeps it and
/// the allowlist but drops the SKI; deleting the CA drops its list and the cache; the
/// current SCP03 session survives.
#[test]
fn oce_cache_invalidation() {
    let pki = pki(0);
    let (mut sd, mut host) = fresh();
    provision(&mut sd, &mut host, &pki);
    let (mut s, mut ch) = admin(&mut sd, &mut host);
    ok(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x00, 0x20, &ca_key_data(0x01, &key_from(0x55).public_uncompressed()));
    let all: Vec<&[u8]> = vec![&pki.root_serial, &pki.inter_serial, &pki.leaf_serial];
    let verify = |sd: &mut SecurityDomain, host: &mut TestHost| assert!(all_ok(&present(sd, host, 0x10, 0x03, &pki.full_chain())));

    for update in [allowlist_data(0x10, 0x03, &all, None), allowlist_data(0x10, 0x03, &all, None), allowlist_data(0x10, 0x03, &[], None), allowlist_data(0x20, 0x01, &all, None)] {
        verify(&mut sd, &mut host);
        assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &update), 0x9000);
        assert!(!sd.has_verified_oce());
    }
    verify(&mut sd, &mut host);
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &allowlist_data(0x10, 0x09, &all, None)), 0x6A88);
    assert!(sd.has_verified_oce(), "a refused update keeps the cache");
    assert!(ch.is_open(), "the SCP03 session survives");
    // An allowlist update also drops a partial chain: the continuation then starts anew.
    let apdus = pso_apdus(0x10, 0x03, &pki.full_chain());
    assert_eq!(status(&sd.handshake(&apdus[0], &mut host).0), 0x9000);
    assert_eq!(status(&sd.handshake(&apdus[1], &mut host).0), 0x9000);
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &allowlist_data(0x10, 0x03, &[], None)), 0x9000);
    assert_eq!(status(&sd.handshake(&apdus[2], &mut host).0), 0x6982, "the leaf alone does not chain to the CA");
    verify(&mut sd, &mut host);
    // A new partial chain cannot reuse the previous OCE; a complete one replaces it.
    sd.handshake(&pso_apdus(0x10, 0x03, &pki.full_chain())[0], &mut host);
    assert!(!sd.has_verified_oce());
    verify(&mut sd, &mut host);
    verify(&mut sd, &mut host);
    assert!(sd.has_verified_oce());
    // CA replacement keeps the list (moved to the new version) and the cache, drops the SKI.
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &ca_issuer_data(0x10, 0x03, &pki.root_ski)), 0x9000);
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &allowlist_data(0x10, 0x03, &[&pki.inter_serial], None)), 0x9000);
    assert_eq!(present(&mut sd, &mut host, 0x10, 0x03, &pki.full_chain())[0], 0x6982, "root not listed");
    assert!(!all_ok(&present(&mut sd, &mut host, 0x00, 0x00, &[pki.inter_cert.clone(), pki.leaf_cert.clone()])), "leaf not listed");
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &allowlist_data(0x10, 0x03, &[], None)), 0x9000);
    verify(&mut sd, &mut host);
    assert_eq!(get(&mut sd, &mut host, 0xFF, 0x33, &[]).1, 0x9000);
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &allowlist_data(0x10, 0x03, &[&pki.leaf_serial, &pki.inter_serial], None)), 0x9000);
    assert!(all_ok(&present(&mut sd, &mut host, 0x10, 0x03, &[pki.inter_cert.clone(), pki.leaf_cert.clone()])));
    assert_eq!(ok(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x03, 0x10, &ca_key_data(0x04, &pki.ca.public_uncompressed())), vec![0x04]);
    assert!(sd.has_verified_oce(), "CA replacement keeps the cache");
    assert_eq!(get(&mut sd, &mut host, 0xFF, 0x33, &[]).1, 0x6A88, "old SKI discarded");
    assert_eq!(present(&mut sd, &mut host, 0x10, 0x04, &pki.full_chain())[0], 0x6982, "allowlist moved to the new version");
    assert!(all_ok(&present(&mut sd, &mut host, 0x10, 0x04, &[pki.inter_cert.clone(), pki.leaf_cert.clone()])));
    // Deleting the CA drops its list and the cache anchored there.
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xE4, 0x00, 0x00, &hex("D00110D20104")).1, 0x9000);
    assert!(!sd.has_verified_oce());
    ok(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x00, 0x10, &ca_key_data(0x04, &pki.ca.public_uncompressed()));
    assert!(all_ok(&present(&mut sd, &mut host, 0x10, 0x04, &pki.full_chain())), "the list went with the deleted key");
    // A plaintext command in an open channel revokes the cache.
    let wrong = encode_apdu(0x80, 0xCA, 0x00, 0x66, &[], Some(0), false);
    assert_eq!(device_transmit(&mut sd, &mut ch, &mut host, &wrong), hex("6982"));
    assert!(!sd.has_verified_oce());
    // Restart drops it.
    assert!(all_ok(&present(&mut sd, &mut host, 0x10, 0x04, &pki.full_chain())));
    assert!(sd.has_verified_oce());
    let sd = restart(&mut host);
    assert!(!sd.has_verified_oce());
}

// ---------------------------------------------------------------------------------
// SCP11c
// ---------------------------------------------------------------------------------

/// SCP11c restrictions and replay protection (catalog SecurityDomain_scp11c): PUT KEY,
/// DELETE, GENERATE, SET STATUS and other STORE DATA answer `6985`; an allowlist needs a
/// counter `92` (two bytes, 1..32767) above the last accepted one for that CA, and list
/// and counter commit together. A recorded session replayed byte for byte (PSO, MUTUAL
/// AUTHENTICATE, STORE DATA) passes the secure channel, since SCP11c has no card
/// randomness, and is refused by the durable counter, also after a restart.
#[test]
fn scp11c_restrictions_and_replay() {
    let pki = pki(0);
    let (mut sd, mut host) = fresh();
    let pk_sd = provision(&mut sd, &mut host, &pki);
    let all: Vec<&[u8]> = vec![&pki.root_serial, &pki.inter_serial, &pki.leaf_serial];
    {
        let (mut est, mut ch) = c_session(&mut sd, &mut host, &pki, &pk_sd);
        let s = &mut est.session;
        let dek = s.dek;
        for (ins, p1, p2, data) in [
            (0xD8, 0x00, 0x13, private_key_data(&dek, 0x05, key_from(0x33).scalar())),
            (0xD8, 0x00, 0x10, ca_key_data(0x05, &pki.ca.public_uncompressed())),
            (0xD8, 0x00, 0x81, s.put_key_data(0x05, &StaticKeys::from_seed(5))),
            (0xE4, 0x00, 0x00, hex("D00115D20101")),
            (0xE4, 0x00, 0x00, hex("D00113")),
            (0xE4, 0x00, 0x01, hex("D201FF")),
            (0xF1, 0x00, 0x13, hex("05F00100")),
            (0xF0, 0x80, 0x07, vec![]),
        ] {
            assert_eq!(send(&mut sd, &mut ch, &mut host, s, 0x80, ins, p1, p2, &data).1, 0x6985, "INS {ins:02X}");
        }
        assert_eq!(store(&mut sd, &mut ch, &mut host, s, &ca_issuer_data(0x10, 0x03, &[1; 20])), 0x6985);
        assert_eq!(store(&mut sd, &mut ch, &mut host, s, &cert_store_data(0x10, 0x03, std::slice::from_ref(&pki.root_cert))), 0x6985);
        // Malformed or ambiguous envelopes use no counter value.
        let mut doubled = allowlist_data(0x10, 0x03, &all, Some(1));
        doubled.extend(tlv(&[0x92], &[0x00, 0x02]));
        for bad in [allowlist_data(0x10, 0x03, &all, None), allowlist_data(0x10, 0x03, &all, Some(0)), allowlist_data(0x10, 0x03, &all, Some(0x8000)), doubled] {
            assert_eq!(store(&mut sd, &mut ch, &mut host, s, &bad), 0x6A80);
        }
        assert!(ch.is_open());
        assert_eq!(key_info(&mut sd, &mut host).len(), 3 * 6 + 4 * 8, "nothing changed");
    }

    // Record a clean session: PSO chain, MUTUAL AUTHENTICATE, STORE DATA with counter 5.
    sd.end_session();
    let mut script: Vec<Vec<u8>> = pso_apdus(0x10, 0x03, &pki.full_chain());
    for apdu in &script {
        assert_eq!(sd.handshake(apdu, &mut host).0, hex("9000"));
    }
    let req = request(Variant::C, 0x01, key_from(0x41));
    script.push(req.apdu.clone());
    let (c_response, ch) = sd.handshake(&req.apdu, &mut host);
    let mut est = req.finish(&c_response, &pk_sd, Some(&pki.leaf)).unwrap();
    let mut ch = ch.unwrap();
    let store_cmd = est.session.wrap(0x00, 0xE2, 0x90, 0x00, &allowlist_data(0x10, 0x03, &all, Some(5)), Some(0), false);
    script.push(store_cmd.clone());
    assert!(sd.has_verified_oce());
    let resp = device_transmit(&mut sd, &mut ch, &mut host, &store_cmd);
    assert_eq!(est.session.unwrap(&resp).unwrap().1, 0x9000);
    assert!(!sd.has_verified_oce(), "an SCP11c counter commit revokes the cached OCE");
    let s = &mut est.session;
    assert_eq!(store(&mut sd, &mut ch, &mut host, s, &allowlist_data(0x10, 0x03, &all, Some(5))), 0x6982, "same counter");
    assert_eq!(store(&mut sd, &mut ch, &mut host, s, &allowlist_data(0x10, 0x03, &all, Some(4))), 0x6982, "lower counter");
    assert_eq!(store(&mut sd, &mut ch, &mut host, s, &allowlist_data(0x10, 0x03, &[], Some(6))), 0x9000, "clear with a higher counter");
    drop(ch);

    // Replay, in the same power cycle and after a restart.
    for restarted in [false, true] {
        if restarted {
            sd = restart(&mut host);
        } else {
            sd.end_session();
        }
        for apdu in &script[..3] {
            assert_eq!(sd.handshake(apdu, &mut host).0, hex("9000"));
        }
        let (again, ch) = sd.handshake(&script[3], &mut host);
        assert_eq!(again, c_response, "same request, same SCP11c response");
        let mut ch = ch.unwrap();
        let replay = device_transmit(&mut sd, &mut ch, &mut host, &script[4]);
        assert_eq!(replay, hex("6982"), "replayed allowlist refused by the counter");
        assert!(ch.is_open(), "the C-MAC verified: the refusal came from the counter");
    }
    // The counter never resets: not by a non-SCP11c write, not by CA replacement.
    let (mut s3, mut ch3) = admin(&mut sd, &mut host);
    assert_eq!(store(&mut sd, &mut ch3, &mut host, &mut s3, &allowlist_data(0x10, 0x03, &[], None)), 0x9000);
    assert_eq!(ok(&mut sd, &mut ch3, &mut host, &mut s3, 0x80, 0xD8, 0x03, 0x10, &ca_key_data(0x03, &pki.ca.public_uncompressed())), vec![0x03]);
    drop(ch3);
    let (mut est, mut ch) = c_session(&mut sd, &mut host, &pki, &pk_sd);
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut est.session, &allowlist_data(0x10, 0x03, &all, Some(6))), 0x6982);
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut est.session, &allowlist_data(0x10, 0x03, &all, Some(0x7FFF))), 0x9000);
    let (mut est, mut ch) = c_session(&mut sd, &mut host, &pki, &pk_sd);
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut est.session, &allowlist_data(0x10, 0x03, &all, Some(0x7FFF))), 0x6982, "exhausted counter");
}

fn c_session(sd: &mut SecurityDomain, host: &mut TestHost, pki: &Pki, pk_sd: &[u8]) -> (Established, SecureChannel) {
    assert!(all_ok(&present(sd, host, 0x10, 0x03, &pki.full_chain())));
    authenticate(sd, host, Variant::C, 0x01, 0x47, pk_sd, Some(&pki.leaf))
}

/// One SCP11c session at a time (catalog SecurityDomain_handoff: "latest committed
/// successful c context supersedes older c contexts"); SCP03, SCP11a and SCP11b channels
/// survive; a refused SCP11c request supersedes nothing.
#[test]
fn latest_scp11c_session_supersedes_older_ones() {
    let pki = pki(0);
    let (mut sd, mut host) = fresh();
    let pk_sd = provision(&mut sd, &mut host, &pki);
    let (mut s03, mut ch03) = admin(&mut sd, &mut host);
    let (_, mut ch_c1) = c_session(&mut sd, &mut host, &pki, &pk_sd);
    assert!(ch_c1.is_open());
    let (_, ch_a) = authenticate(&mut sd, &mut host, Variant::A, 0x01, 0x42, &pk_sd, Some(&pki.leaf));
    let pk_b = cert_key_and_check(&der_split_all(&get(&mut sd, &mut host, 0xBF, 0x21, &hex("A60483021301")).0)[0], None).0;
    let (_, ch_b) = authenticate(&mut sd, &mut host, Variant::B, 0x01, 0x43, &pk_b, None);
    // A malformed SCP11c request does not supersede the current one.
    assert_eq!(sd.handshake(&encode_apdu(0x80, 0x82, 0x01, 0x15, &[0; 8], None, false), &mut host).0, hex("6A80"));
    assert!(ch_c1.is_open());
    let (_, ch_c2) = authenticate(&mut sd, &mut host, Variant::C, 0x01, 0x44, &pk_sd, Some(&pki.leaf));
    assert!(!ch_c1.is_open(), "the older SCP11c session ends");
    assert!(ch_c2.is_open() && ch_a.is_open() && ch_b.is_open() && ch03.is_open());
    assert_eq!(device_transmit(&mut sd, &mut ch_c1, &mut host, &hex("84CA006600")), hex("6982"));
    assert!(ch_c2.is_open(), "refusing the obsolete wrapper does not close the current owner");
    assert_eq!(send(&mut sd, &mut ch03, &mut host, &mut s03, 0x80, 0xCA, 0x00, 0x66, &[]).1, 0x9000);
}

// ---------------------------------------------------------------------------------
// Handoff
// ---------------------------------------------------------------------------------

/// Every outer session (SCP03, SCP11a, SCP11b, SCP11c) can carry a new SCP11a, b or c
/// handshake (12 combinations, catalog SecurityDomain_handoff): the PSO and the
/// authenticate command are protected by the outer channel, its response is verified
/// under the outer session, and the new context then protects the next exchange.
#[test]
fn protected_handoff_in_every_combination() {
    let pki = pki(0);
    for outer in ["03", "a", "b", "c"] {
        for target in [Variant::A, Variant::B, Variant::C] {
            let (mut sd, mut host) = fresh();
            let pk_sd = provision(&mut sd, &mut host, &pki);
            let pk_b = cert_key_and_check(&der_split_all(&get(&mut sd, &mut host, 0xBF, 0x21, &hex("A60483021301")).0)[0], None).0;
            let (mut s, mut ch) = match outer {
                "03" => admin(&mut sd, &mut host),
                "a" | "c" => {
                    assert!(all_ok(&present(&mut sd, &mut host, 0x10, 0x03, &pki.full_chain())));
                    let v = if outer == "a" { Variant::A } else { Variant::C };
                    let (est, ch) = authenticate(&mut sd, &mut host, v, 0x01, 0x48, &pk_sd, Some(&pki.leaf));
                    (est.session, ch)
                }
                _ => {
                    let (est, ch) = authenticate(&mut sd, &mut host, Variant::B, 0x01, 0x48, &pk_b, None);
                    (est.session, ch)
                }
            };
            if target != Variant::B {
                for apdu in pso_apdus(0x10, 0x03, &pki.full_chain()) {
                    let cmd = lk_codec::apdu::Command::parse(&apdu).unwrap();
                    let wrapped = s.wrap(0x80, 0x2A, cmd.p1, cmd.p2, &cmd.data, None, cmd.data.len() > 200);
                    let (resp, new) = device_handshake(&mut sd, Some(&mut ch), &mut host, &wrapped);
                    assert!(new.is_none());
                    assert_eq!(s.unwrap(&resp).unwrap().1, 0x9000, "{outer} -> {target:?} PSO");
                }
            }
            let req = request(target, 0x01, key_from(0x49));
            let wrapped = s.wrap(0x80, if target == Variant::B { 0x88 } else { 0x82 }, 0x01, target.kid(), &req.data, None, false);
            let (resp, new) = device_handshake(&mut sd, Some(&mut ch), &mut host, &wrapped);
            let (plain_resp, sw) = s.unwrap(&resp).unwrap();
            assert_eq!(sw, 0x9000, "{outer} -> {target:?}");
            let pk = if target == Variant::B { &pk_b } else { &pk_sd };
            let est = req.finish(&[plain_resp, vec![0x90, 0x00]].concat(), pk, (target != Variant::B).then_some(&pki.leaf)).unwrap();
            let mut new = new.expect("new context");
            let mut session = est.session;
            assert_eq!(send(&mut sd, &mut new, &mut host, &mut session, 0x80, 0xCA, 0x00, 0x66, &[]).1, 0x9000, "{outer} -> {target:?} new context");
        }
    }
}

// ---------------------------------------------------------------------------------
// EC key management
// ---------------------------------------------------------------------------------

/// GENERATE EC KEY and PUT KEY for EC keys (yubikit layouts): versions 1..127 (0, 128,
/// 255 refused, catalog SecurityDomain_versions), replacement and collision rules,
/// sixteen EC keys at most, key information, certificate stores and CA identifiers
/// (GET DATA `BF21`, `FF33`, `FF34`), deletion with the attached data.
#[test]
fn ec_key_management() {
    let pki = pki(0);
    let (mut sd, mut host) = fresh();
    let (mut s, mut ch) = admin(&mut sd, &mut host);
    let dek = s.dek;
    let point = pki.ca.public_uncompressed();
    for kvn in [0x00, 0x80, 0xFF] {
        assert_eq!(sw_of(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xF1, 0x00, 0x11, &[kvn, 0xF0, 0x01, 0x00]), 0x6A80);
        assert_eq!(sw_of(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x00, 0x10, &ca_key_data(kvn, &point)), 0x6A80);
    }
    let generated = ok(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xF1, 0x00, 0x11, &hex("7FF00100"));
    assert_eq!(generated.len(), 67);
    for (p1, p2, data, expected) in [
        (0x00, 0x12, hex("01F00100"), 0x6A86),
        (0x00, 0x11, hex("01F00101"), 0x6A80),
        (0x00, 0x11, hex("7FF00100"), 0x6A80),
        (0x05, 0x11, hex("01F00100"), 0x6A88),
    ] {
        assert_eq!(sw_of(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xF1, p1, p2, &data), expected);
    }
    // Wrong key objects for the KID, invalid point/scalar, wrong curve.
    for (p2, data) in [
        (0x10, private_key_data(&dek, 0x01, key_from(0x22).scalar())),
        (0x13, ca_key_data(0x02, &point)),
        (0x10, ca_key_data(0x01, &[4; 65])),
        (0x13, private_key_data(&dek, 0x02, &[0; 32])),
        (0x10, [vec![0x01], tlv(&[0xB0], &point), vec![0xF0, 0x01, 0x01]].concat()),
        (0x10, [vec![0x01], tlv(&[0xB0], &point)].concat()),
    ] {
        assert_eq!(sw_of(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x00, p2, &data), 0x6A80);
    }
    assert_eq!(sw_of(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x00, 0x16, &ca_key_data(0x01, &point)), 0x6A86);
    // Fill up to sixteen EC keys (one SCP11b + one SCP11a are there).
    for kvn in 1..=14u8 {
        assert_eq!(ok(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x00, 0x20 + (kvn % 16), &ca_key_data(kvn, &point)), vec![kvn]);
    }
    assert_eq!(sw_of(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x00, 0x10, &ca_key_data(0x01, &point)), 0x6A84);
    // Replacement does not need room.
    assert_eq!(ok(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x01, 0x21, &ca_key_data(0x01, &point)), vec![0x01]);
    let info = key_info(&mut sd, &mut host);
    assert_eq!(info.len(), 3 * 6 + 16 * 8);
    assert!(info.windows(8).any(|w| w == hex("C006117FB120F000")));
    assert!(info.windows(8).any(|w| w == hex("C0062101B041F000")));
    // Delete the CA keys again.
    for kvn in 1..=14u8 {
        assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xE4, 0x00, 0x00, &[0xD0, 0x01, 0x20 + (kvn % 16), 0xD2, 0x01, kvn]).1, 0x9000);
    }

    // Certificate stores and CA identifiers.
    ok(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x00, 0x10, &ca_key_data(0x03, &point));
    let chain = pki.full_chain();
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &cert_store_data(0x10, 0x03, &chain)), 0x9000);
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &cert_store_data(0x10, 0x09, &chain)), 0x6A88);
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &cert_store_data(0x10, 0x03, &vec![pki.leaf_cert.clone(); 9])), 0x6A84);
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &[tlv(&[0xA6], &tlv(&[0x83], &[0x10, 0x03])), tlv(&[0xBF, 0x21], &[0x04, 0x00])].concat()), 0x6A80);
    let (bundle, sw) = get(&mut sd, &mut host, 0xBF, 0x21, &hex("A60483021003"));
    assert_eq!((der_split_all(&bundle), sw), (chain.clone(), 0x9000));
    let (bundle, _) = send_ext(&mut sd, &mut ch, &mut host, &mut s, 0x00, 0xCA, 0xBF, 0x21, &hex("A60483021003"));
    assert_eq!(der_split_all(&bundle), chain, "a protected answer is returned whole");
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &ca_issuer_data(0x10, 0x03, &pki.root_ski)), 0x9000);
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &ca_issuer_data(0x13, 0x01, &[0x5A; 20])), 0x9000);
    assert_eq!(get(&mut sd, &mut host, 0xFF, 0x33, &[]), ([tlv(&[0x42], &pki.root_ski), hex("83021003")].concat(), 0x9000));
    assert_eq!(get(&mut sd, &mut host, 0xFF, 0x34, &[]), ([tlv(&[0x42], &[0x5A; 20]), hex("83021301")].concat(), 0x9000));
    let wrong_kind = tlv(&[0xA6], &[tlv(&[0x80], &[0x01]), tlv(&[0x42], &[1]), tlv(&[0x83], &[0x10, 0x03])].concat());
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &wrong_kind), 0x6A80);
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &ca_issuer_data(0x10, 0x07, &[1])), 0x6A88);
    assert_eq!(sw_of(&mut sd, &mut ch, &mut host, &mut s, 0x00, 0xE2, 0x00, 0x00, &ca_issuer_data(0x10, 0x03, &[1])), 0x6A86);
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &hex("5F2001AA")), 0x6A80);
    // An empty store removes the bundle; deleting a key removes its data.
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &cert_store_data(0x10, 0x03, &[])), 0x9000);
    assert_eq!(get(&mut sd, &mut host, 0xBF, 0x21, &hex("A60483021003")).1, 0x6A88);
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xE4, 0x00, 0x00, &hex("D00110")).1, 0x9000);
    assert_eq!(get(&mut sd, &mut host, 0xFF, 0x33, &[]).1, 0x6A88);
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xE4, 0x00, 0x00, &hex("D00110")).1, 0x6A88);
    // Without a session nothing is managed.
    assert_eq!(plain(&mut sd, &mut host, &encode_apdu(0x00, 0xE2, 0x90, 0x00, &ca_issuer_data(0x13, 0x01, &[1]), None, false)), hex("6982"));
    assert_eq!(plain(&mut sd, &mut host, &encode_apdu(0x80, 0xF1, 0x00, 0x13, &hex("02F00100"), None, false)), hex("6982"));
    assert_eq!(plain(&mut sd, &mut host, &hex("80F0800700")), hex("6D00"));
}

// ---------------------------------------------------------------------------------
// Tries, reset, persistence
// ---------------------------------------------------------------------------------

/// yubikit's `SecurityDomainSession.reset()` over every kind of key: three SCP03 sets,
/// SCP11a/b/c keys and OCE CA keys at `10`, `20` and `2F` (INITIALIZE UPDATE with KVN 0,
/// MUTUAL/INTERNAL AUTHENTICATE and PSO with eight zero bytes, 65 tries each, stop on
/// `6983`/`6982`, continue on `6A80`). The domain ends factory fresh (catalog
/// SecurityDomain_profile: "SDK reset covers all three custom SCP03 sets and sixteen EC
/// rows").
#[test]
fn blocking_reset_over_every_key_kind() {
    let pki = pki(0);
    let (mut sd, mut host) = fresh();
    provision(&mut sd, &mut host, &pki);
    let (mut s, mut ch) = admin(&mut sd, &mut host);
    for kvn in [0x01, 0x7F, 0xFE] {
        let data = s.put_key_data(kvn, &StaticKeys::from_seed(kvn));
        ok(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x00, 0x81, &data);
    }
    drop(ch);
    let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::from_seed(0xFE), 0xFE, 0x33);
    for (kid, kvn) in [(0x20, 0x01), (0x2F, 0x7F), (0x10, 0x01), (0x10, 0x7F), (0x21, 0x02), (0x22, 0x03), (0x23, 0x04), (0x24, 0x05)] {
        ok(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x00, kid, &ca_key_data(kvn, &pki.ca.public_uncompressed()));
    }
    for (kid, kvn) in [(0x11, 0x7F), (0x13, 0x02), (0x13, 0x7F), (0x15, 0x7F)] {
        ok(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xF1, 0x00, kid, &[kvn, 0xF0, 0x01, 0x00]);
    }
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &allowlist_data(0x10, 0x03, &[&pki.leaf_serial], None)), 0x9000);
    let info = key_info(&mut sd, &mut host);
    let mut refs = Vec::new();
    let mut rest = &info[..];
    while !rest.is_empty() {
        refs.push((rest[2], rest[3]));
        rest = &rest[2 + rest[1] as usize..];
    }
    assert_eq!(refs.len(), 9 + 16, "three SCP03 sets and sixteen EC keys");
    for (kid, kvn) in refs {
        let (ins, p1, p2) = match kid {
            0x01 => (0x50, 0x00, 0x00),
            0x02 | 0x03 => continue,
            0x11 | 0x15 => (0x82, kvn, kid),
            0x13 => (0x88, kvn, kid),
            _ => (0x2A, kvn, kid),
        };
        let mut stopped = false;
        for _ in 0..65 {
            let sw = status(&sd.handshake(&encode_apdu(0x80, ins, p1, p2, &[0; 8], None, false), &mut host).0);
            match sw {
                0x6983 | 0x6982 => {
                    stopped = true;
                    break;
                }
                0x6A80 | 0x9000 => {}
                other => panic!("key {kid:02X}/{kvn:02X}: unexpected {other:04X} (yubikit would raise)"),
            }
        }
        assert!(stopped, "key {kid:02X}/{kvn:02X} not blocked");
    }
    assert!(!ch.is_open());
    assert_eq!(key_info(&mut sd, &mut host), hex(FACTORY_KEY_INFO));
    assert_eq!(get(&mut sd, &mut host, 0xBF, 0x21, &hex("A60483021301")).1, 0x9000, "fresh own certificate");
    admin(&mut sd, &mut host);
}

/// Persistence failures (docs/CONTRACTS.md "Persisted state") for every new commit: the
/// command answers `6581` and nothing changes. A failed SCP11c allowlist commit also ends
/// the SCP11c session (catalog SecurityDomain_scp11c); a retry with the same counter in a
/// new session succeeds.
#[test]
fn persistence_failures_in_scp11_commands() {
    let pki = pki(0);
    let (mut sd, mut host) = fresh();
    let pk_sd = provision(&mut sd, &mut host, &pki);
    let (mut s, mut ch) = admin(&mut sd, &mut host);
    assert!(all_ok(&present(&mut sd, &mut host, 0x10, 0x03, &pki.full_chain())));
    let before = host.persisted(Record::SecurityDomain);
    let point = pki.ca.public_uncompressed();
    for (cla, ins, p1, p2, data) in [
        (0x80, 0xD8, 0x00, 0x20, ca_key_data(0x01, &point)),
        (0x80, 0xF1, 0x00, 0x13, hex("05F00100")),
        (0x00, 0xE2, 0x90, 0x00, allowlist_data(0x10, 0x03, &[&pki.leaf_serial], None)),
        (0x00, 0xE2, 0x90, 0x00, ca_issuer_data(0x10, 0x03, &[1; 20])),
        (0x00, 0xE2, 0x90, 0x00, cert_store_data(0x10, 0x03, std::slice::from_ref(&pki.leaf_cert))),
        (0x80, 0xE4, 0x00, 0x00, hex("D00110")),
    ] {
        host.fail_next_saves(1);
        assert_eq!(sw_of(&mut sd, &mut ch, &mut host, &mut s, cla, ins, p1, p2, &data), 0x6581, "INS {ins:02X}");
        assert_eq!(host.persisted(Record::SecurityDomain), before);
        assert!(sd.has_verified_oce(), "a failed commit keeps the cached OCE");
    }
    assert!(ch.is_open());
    drop(ch);
    // A failed SCP11 attempt cannot record its try: 6581.
    host.fail_next_saves(1);
    assert_eq!(sd.handshake(&encode_apdu(0x80, 0x88, 0x01, 0x13, &[0; 8], None, false), &mut host).0, hex("6581"));
    assert_eq!(sd.remaining_tries(0x13, 0x01), Some(64));
    // A malformed certificate cannot record the CA try: 6581.
    host.fail_next_saves(1);
    assert_eq!(present(&mut sd, &mut host, 0x10, 0x03, &[vec![0; 8]]), vec![0x6581]);
    assert_eq!(sd.remaining_tries(0x10, 0x03), Some(64));
    // A successful SCP11 handshake that cannot restore tries gives no session.
    assert_eq!(sd.handshake(&encode_apdu(0x80, 0x88, 0x01, 0x13, &[0; 8], None, false), &mut host).0, hex("6A80"));
    let pk_b = cert_key_and_check(&der_split_all(&get(&mut sd, &mut host, 0xBF, 0x21, &hex("A60483021301")).0)[0], None).0;
    let req = request(Variant::B, 0x01, key_from(0x41));
    host.fail_next_saves(1);
    let (resp, ch) = sd.handshake(&req.apdu, &mut host);
    assert_eq!((resp, ch.is_none()), (hex("6581"), true));
    assert_eq!(sd.remaining_tries(0x13, 0x01), Some(63));
    authenticate(&mut sd, &mut host, Variant::B, 0x01, 0x41, &pk_b, None);
    assert_eq!(sd.remaining_tries(0x13, 0x01), Some(64));
    // SCP11c allowlist: the failed commit ends the session; the same counter works later.
    let all: Vec<&[u8]> = vec![&pki.leaf_serial, &pki.inter_serial, &pki.root_serial];
    let (mut est, mut ch) = c_session(&mut sd, &mut host, &pki, &pk_sd);
    host.fail_next_saves(1);
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut est.session, &allowlist_data(0x10, 0x03, &all, Some(9))), 0x6581);
    assert!(!ch.is_open(), "the failed SCP11c commit ends the session");
    let (mut est, mut ch) = c_session(&mut sd, &mut host, &pki, &pk_sd);
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut est.session, &allowlist_data(0x10, 0x03, &all, Some(9))), 0x9000);
}

/// Restart keeps every SCP11 key, try count, CA key, CA identifier, certificate store,
/// allowlist and SCP11c counter (catalog SecurityDomain_versions boundary 127, and
/// SecurityDomain_allowlist "restart retains policy/key/SKI/cert/CPLC").
#[test]
fn restart_keeps_scp11_material() {
    let pki = pki(0);
    let (mut sd, mut host) = fresh();
    let pk_sd = provision(&mut sd, &mut host, &pki);
    let (mut s, mut ch) = admin(&mut sd, &mut host);
    ok(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x00, 0x2F, &ca_key_data(0x7F, &pki.ca.public_uncompressed()));
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &ca_issuer_data(0x10, 0x03, &pki.root_ski)), 0x9000);
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &cert_store_data(0x11, 0x01, std::slice::from_ref(&pki.leaf_cert))), 0x9000);
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut s, &allowlist_data(0x10, 0x03, &[&pki.inter_serial, &pki.leaf_serial], None)), 0x9000);
    drop(ch);
    let (mut est, mut ch) = authenticate_after_chain(&mut sd, &mut host, &pki, &pk_sd);
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut est.session, &allowlist_data(0x10, 0x03, &[&pki.inter_serial, &pki.leaf_serial], Some(3))), 0x9000);
    sd.handshake(&encode_apdu(0x80, 0x82, 0x01, 0x11, &[0; 8], None, false), &mut host);
    let info = key_info(&mut sd, &mut host);
    let cplc = get(&mut sd, &mut host, 0x9F, 0x7F, &[]);
    let own = get(&mut sd, &mut host, 0xBF, 0x21, &hex("A60483021301"));

    let mut sd = restart(&mut host);
    assert_eq!(key_info(&mut sd, &mut host), info);
    assert_eq!(get(&mut sd, &mut host, 0xBF, 0x21, &hex("A60483021301")), own, "own SCP11b certificate kept");
    assert_eq!(get(&mut sd, &mut host, 0x9F, 0x7F, &[]), cplc);
    assert_eq!(sd.remaining_tries(0x11, 0x01), Some(63));
    assert_eq!(get(&mut sd, &mut host, 0xFF, 0x33, &[]).1, 0x9000);
    assert_eq!(der_split_all(&get(&mut sd, &mut host, 0xBF, 0x21, &hex("A60483021101")).0), vec![pki.leaf_cert.clone()]);
    assert_eq!(present(&mut sd, &mut host, 0x10, 0x03, &pki.full_chain())[0], 0x6982, "allowlist kept");
    let (mut est, mut ch) = authenticate_after_chain(&mut sd, &mut host, &pki, &pk_sd);
    assert_eq!(store(&mut sd, &mut ch, &mut host, &mut est.session, &allowlist_data(0x10, 0x03, &[], Some(3))), 0x6982, "counter kept");
}

fn authenticate_after_chain(sd: &mut SecurityDomain, host: &mut TestHost, pki: &Pki, pk_sd: &[u8]) -> (Established, SecureChannel) {
    assert!(all_ok(&present(sd, host, 0x10, 0x03, &[pki.inter_cert.clone(), pki.leaf_cert.clone()])));
    authenticate(sd, host, Variant::C, 0x01, 0x4A, pk_sd, Some(&pki.leaf))
}

/// A record written before SCP11 support (no revision object, no certificate store)
/// keeps its keys, tries and CPLC and gains a self-signed certificate for the existing
/// SCP11b key (catalog SecurityDomain_shared_state: "missing generation metadata is
/// added on legacy load without recreating keys/certificates/retries/CPLC").
#[test]
fn records_before_scp11_support_gain_a_certificate() {
    let (mut sd, mut host) = fresh();
    sd.handshake(&encode_apdu(0x80, 0x88, 0x01, 0x13, &[0; 8], None, false), &mut host);
    let (bundle, _) = get(&mut sd, &mut host, 0xBF, 0x21, &hex("A60483021301"));
    let pk_b = cert_key_and_check(&bundle, None).0;
    let cplc = get(&mut sd, &mut host, 0x9F, 0x7F, &[]);
    let record = host.persisted(Record::SecurityDomain).unwrap();
    // Drop the revision object (82) and the certificate stores (A4).
    let mut old = vec![record[0]];
    let mut rest = &record[1..];
    while !rest.is_empty() {
        let (tag, _, element, next) = der_next(rest);
        if tag != 0x82 && tag != 0xA4 {
            old.extend_from_slice(element);
        }
        rest = next;
    }
    host.set_persisted(Record::SecurityDomain, &old);
    let mut sd = restart(&mut host);
    assert_eq!(key_info(&mut sd, &mut host), hex(FACTORY_KEY_INFO));
    assert_eq!(get(&mut sd, &mut host, 0x9F, 0x7F, &[]), cplc);
    assert_eq!(sd.remaining_tries(0x13, 0x01), Some(63));
    let (bundle, sw) = get(&mut sd, &mut host, 0xBF, 0x21, &hex("A60483021301"));
    assert_eq!(sw, 0x9000);
    let (key, self_signed) = cert_key_and_check(&bundle, None);
    assert_eq!(key, pk_b);
    assert!(self_signed);
    assert_ne!(host.persisted(Record::SecurityDomain).unwrap(), old, "the migrated record is written back");
}

/// SCP11 tries (catalog SecurityDomain_profile and SecurityDomain_versions): the last
/// try can succeed and restores the count; a key without tries is deleted when next
/// selected (`6983`, Yubico: "that key set is deleted"); the KVN wildcard then moves on
/// to the next version; KVN 127 works.
#[test]
fn scp11_tries_last_attempt_exhaustion_and_wildcard() {
    let (mut sd, mut host) = fresh();
    let (mut s, mut ch) = admin(&mut sd, &mut host);
    let generated = ok(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xF1, 0x00, 0x13, &hex("7FF00100"));
    let pk_7f = generated[2..].to_vec();
    drop(ch);
    let malformed = encode_apdu(0x80, 0x88, 0x7F, 0x13, &[0; 8], None, false);
    for _ in 0..63 {
        assert_eq!(sd.handshake(&malformed, &mut host).0, hex("6A80"));
    }
    assert_eq!(sd.remaining_tries(0x13, 0x7F), Some(1));
    authenticate(&mut sd, &mut host, Variant::B, 0x7F, 0x41, &pk_7f, None);
    assert_eq!(sd.remaining_tries(0x13, 0x7F), Some(64), "the last try succeeded and restored the count");
    for _ in 0..64 {
        assert_eq!(sd.handshake(&malformed, &mut host).0, hex("6A80"));
    }
    let sd_restarted = &mut restart(&mut host);
    assert_eq!(sd_restarted.remaining_tries(0x13, 0x7F), Some(0), "failures are durable");
    let mut sd = restart(&mut host);
    // The wildcard selects the exhausted 7F, deletes it, then uses 01.
    let req = request(Variant::B, 0x00, key_from(0x41));
    assert_eq!(sd.handshake(&req.apdu, &mut host).0, hex("6983"));
    assert_eq!(sd.remaining_tries(0x13, 0x7F), None);
    assert_eq!(key_info(&mut sd, &mut host), hex(FACTORY_KEY_INFO));
    let pk_b = cert_key_and_check(&der_split_all(&get(&mut sd, &mut host, 0xBF, 0x21, &hex("A60483021301")).0)[0], None).0;
    authenticate(&mut sd, &mut host, Variant::B, 0x00, 0x41, &pk_b, None);
}

/// Handoff details (catalog SecurityDomain_handoff): a request under the old wrapper is
/// refused once the new context replaced it (the old MAC chain does not verify) and the
/// stored state is unchanged; a malformed nested SCP11 request answers bare `6A80`,
/// uses a try and keeps the outer transport.
#[test]
fn handoff_old_wrapper_and_nested_failures() {
    let (mut sd, mut host) = fresh();
    let pk_b = cert_key_and_check(&der_split_all(&get(&mut sd, &mut host, 0xBF, 0x21, &hex("A60483021301")).0)[0], None).0;
    let (mut s, mut ch) = admin(&mut sd, &mut host);
    // A malformed nested request keeps the outer session.
    let wrapped = s.wrap(0x80, 0x88, 0x01, 0x13, &[0; 8], None, false);
    let (resp, new) = device_handshake(&mut sd, Some(&mut ch), &mut host, &wrapped);
    assert_eq!((resp, new.is_none()), (hex("6A80"), true));
    assert!(ch.is_open());
    assert_eq!(sd.remaining_tries(0x13, 0x01), Some(63));
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xCA, 0x00, 0x66, &[]).1, 0x9000);
    // A refused protected PSO (no such CA) answers bare and keeps the transport.
    let wrapped = s.wrap(0x80, 0x2A, 0x03, 0x10, &[0x30, 0x00], None, false);
    let (resp, _) = device_handshake(&mut sd, Some(&mut ch), &mut host, &wrapped);
    assert_eq!(resp, hex("6A88"));
    assert!(ch.is_open());
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xCA, 0x00, 0x66, &[]).1, 0x9000);
    // A valid nested SCP11b handshake replaces the channel.
    let req = request(Variant::B, 0x01, key_from(0x41));
    let wrapped = s.wrap(0x80, 0x88, 0x01, 0x13, &req.data, None, false);
    let (resp, new) = device_handshake(&mut sd, Some(&mut ch), &mut host, &wrapped);
    let (body, sw) = s.unwrap(&resp).unwrap();
    assert_eq!(sw, 0x9000);
    req.finish(&[body, vec![0x90, 0x00]].concat(), &pk_b, None).unwrap();
    let mut new = new.unwrap();
    let before = host.persisted(Record::SecurityDomain);
    let old_wrapper = s.wrap(0x80, 0xCA, 0x00, 0x66, &[], Some(0), false);
    assert_eq!(device_transmit(&mut sd, &mut new, &mut host, &old_wrapper), hex("6982"));
    assert_eq!(host.persisted(Record::SecurityDomain), before);
    assert!(!new.is_open(), "the bad MAC ended the session");
}

/// Reset across sessions (catalog SecurityDomain_shared_state): the explicit reset
/// (DELETE of the last management key with P2 `01`) closes every channel, SCP03 and
/// SCP11c alike, and drops the cached OCE; reprovisioning the same keys does not revive
/// them. A reset that cannot be persisted changes nothing and keeps channels and cache.
/// A failed SCP11c commit keeps the current SCP11c session.
#[test]
fn reset_and_failed_commits_across_sessions() {
    let pki = pki(0);
    let (mut sd, mut host) = fresh();
    let pk_sd = provision(&mut sd, &mut host, &pki);
    let (mut s, mut ch) = admin(&mut sd, &mut host);
    let (_, ch_c) = c_session(&mut sd, &mut host, &pki, &pk_sd);
    // A failed SCP11c handshake commit (restoring tries) keeps the current c session.
    assert_eq!(sd.handshake(&encode_apdu(0x80, 0x82, 0x01, 0x15, &[0; 8], None, false), &mut host).0, hex("6A80"));
    host.fail_next_saves(1);
    let req = request(Variant::C, 0x01, key_from(0x4B));
    let (resp, none) = sd.handshake(&req.apdu, &mut host);
    assert_eq!((resp, none.is_none()), (hex("6581"), true));
    assert!(ch_c.is_open());
    // Leave the SCP03 set as the last management key; deleting keys ends no session.
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xE4, 0x00, 0x00, &hex("D00111")).1, 0x9000);
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xE4, 0x00, 0x00, &hex("D00115")).1, 0x9000);
    assert!(ch_c.is_open());
    // A reset that cannot be persisted changes nothing and keeps sessions and cache.
    let before = host.persisted(Record::SecurityDomain);
    host.fail_next_saves(1);
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xE4, 0x00, 0x01, &hex("D201FF")).1, 0x6581);
    assert_eq!(host.persisted(Record::SecurityDomain), before);
    assert!(ch.is_open() && ch_c.is_open());
    assert!(sd.has_verified_oce());
    // The last management key: the domain resets.
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xE4, 0x00, 0x01, &hex("D201FF")).1, 0x9000);
    assert!(!ch.is_open());
    assert!(!ch_c.is_open());
    assert!(!sd.has_verified_oce());
    assert_eq!(key_info(&mut sd, &mut host), hex(FACTORY_KEY_INFO));
    provision(&mut sd, &mut host, &pki);
    assert!(!ch.is_open() && !ch_c.is_open());
}

/// Plaintext in an established SCP11a/b/c session (Yubico yk5-apps-scp; catalog
/// SecurityDomain_plaintext): PSO, MUTUAL AUTHENTICATE, INTERNAL AUTHENTICATE, GET DATA
/// and chained CLA `90` are refused before dispatch (`6982`), as is YKOATH CALCULATE ALL
/// `00 A4 00 01` (only `xx A4 04 xx` is SELECT, docs/CONTRACTS.md "Applications A as
/// implemented"); a plaintext SELECT with bad parameters is passed through as the
/// session boundary (the device validates it afterwards) and an unparsable one answers
/// `6700`. Either way the session ends, no try is used, the state is unchanged and the
/// cached OCE is revoked, while a peer SCP03 channel stays open.
#[test]
fn plaintext_ends_scp11_sessions_before_dispatch() {
    let pki = pki(0);
    let (mut sd, mut host) = fresh();
    let pk_sd = provision(&mut sd, &mut host, &pki);
    let pk_b = cert_key_and_check(&der_split_all(&get(&mut sd, &mut host, 0xBF, 0x21, &hex("A60483021301")).0)[0], None).0;
    let plaintexts = [
        pso_apdus(0x10, 0x03, std::slice::from_ref(&pki.leaf_cert)).remove(0),
        request(Variant::A, 0x01, key_from(0x41)).apdu,
        request(Variant::B, 0x01, key_from(0x41)).apdu,
        hex("00CA006600"),
        hex("90CA006600"),
        hex("00A4000100"),
        hex("00A404FF"),
        hex("00A4"),
    ];
    for variant in [Variant::A, Variant::B, Variant::C] {
        for apdu in &plaintexts {
            let (mut s03, mut peer) = admin(&mut sd, &mut host);
            assert!(all_ok(&present(&mut sd, &mut host, 0x10, 0x03, &pki.full_chain())));
            let (_, mut ch) = match variant {
                Variant::B => authenticate(&mut sd, &mut host, variant, 0x01, 0x41, &pk_b, None),
                _ => authenticate(&mut sd, &mut host, variant, 0x01, 0x41, &pk_sd, Some(&pki.leaf)),
            };
            let before = host.persisted(Record::SecurityDomain);
            assert!(sd.has_verified_oce());
            let resp = channel_entry(&mut ch, apdu);
            match apdu.as_slice() {
                [_, _] => assert_eq!(resp, Err(0x6700), "an unparsable command"),
                [_, 0xA4, 0x04, _] => assert_eq!(resp, Ok(apdu.clone()), "a plaintext SELECT passes through to its own validation"),
                _ => assert_eq!(resp, Err(0x6982), "{variant:?} {apdu:02X?}"),
            }
            assert!(!ch.is_open());
            assert!(!sd.has_verified_oce(), "plaintext revokes the cached OCE");
            assert_eq!(host.persisted(Record::SecurityDomain), before);
            for (kid, kvn) in [(0x11, 0x01), (0x13, 0x01), (0x15, 0x01), (0x10, 0x03)] {
                assert_eq!(sd.remaining_tries(kid, kvn), Some(64));
            }
            assert!(peer.is_open(), "the peer channel stays open");
            assert_eq!(send(&mut sd, &mut peer, &mut host, &mut s03, 0x80, 0xCA, 0x00, 0x66, &[]).1, 0x9000);
        }
    }
}

/// The device's first step for a command while a channel is open.
fn channel_entry(ch: &mut SecureChannel, apdu: &[u8]) -> Result<Vec<u8>, u16> {
    ch.unwrap_command(apdu)
}

/// An SCP11a session manages allowlists and survives the cache invalidation its own
/// update causes (catalog SecurityDomain_oce_cache: "current SCP03/SCP11a secure
/// messaging and management survive allowlist cache invalidation"); the CPLC is stable
/// through SCP11 reads.
#[test]
fn scp11a_session_survives_allowlist_updates() {
    let pki = pki(0);
    let (mut sd, mut host) = fresh();
    let pk_sd = provision(&mut sd, &mut host, &pki);
    let cplc = get(&mut sd, &mut host, 0x9F, 0x7F, &[]).0;
    assert!(all_ok(&present(&mut sd, &mut host, 0x10, 0x03, &pki.full_chain())));
    let (mut est, mut ch) = authenticate(&mut sd, &mut host, Variant::A, 0x01, 0x41, &pk_sd, Some(&pki.leaf));
    let s = &mut est.session;
    assert_eq!(store(&mut sd, &mut ch, &mut host, s, &allowlist_data(0x10, 0x03, &[&pki.leaf_serial], None)), 0x9000);
    assert!(!sd.has_verified_oce());
    assert!(ch.is_open());
    assert_eq!(ok(&mut sd, &mut ch, &mut host, s, 0x80, 0xCA, 0x9F, 0x7F, &[]), cplc);
    assert_eq!(ok(&mut sd, &mut ch, &mut host, s, 0x80, 0xF1, 0x00, 0x13, &hex("02F00100")).len(), 67);
}

/// Card ephemeral keys are never reused (GP Amendment F §3.1.2: SCP11a/b generate a fresh
/// eSK.SD/ePK.SD pair for every key agreement; catalog SecurityDomain_scp11c: "a/b same
/// request re-randomizes card contribution"). The same SCP11a request sent twice, and
/// again after a failed attempt, gets a different ePK.SD each time, never PK.SD itself,
/// and every receipt verifies with the independent OCE, giving different session keys.
/// SCP11c, by design, answers the same request with the same static point.
#[test]
fn scp11a_card_ephemeral_is_fresh_for_every_handshake() {
    let pki = pki(0);
    let (mut sd, mut host) = fresh();
    let pk_sd = provision(&mut sd, &mut host, &pki);
    assert!(all_ok(&present(&mut sd, &mut host, 0x10, 0x03, &pki.full_chain())));
    let req = request(Variant::A, 0x01, key_from(0x41));
    let mut points = Vec::new();
    let mut macs = Vec::new();
    for round in 0..3 {
        if round == 2 {
            // A failed attempt in between does not pin the next ephemeral key.
            assert_eq!(sd.handshake(&encode_apdu(0x80, 0x82, 0x01, 0x11, &[0; 8], None, false), &mut host).0, hex("6A80"));
        }
        let (resp, ch) = sd.handshake(&req.apdu, &mut host);
        assert!(ch.is_some());
        let est = req.finish(&resp, &pk_sd, Some(&pki.leaf)).unwrap();
        assert_ne!(est.card_point, pk_sd, "SCP11a never answers with the static key");
        points.push(est.card_point);
        macs.push(est.session.s_mac);
    }
    assert!(points[0] != points[1] && points[1] != points[2] && points[0] != points[2], "fresh ePK.SD every time");
    assert!(macs[0] != macs[1] && macs[1] != macs[2], "fresh session keys every time");
}

/// Replacing an OCE CA key drops a certificate chain that was being presented under the
/// old key (catalog SecurityDomain_shared_state: "fresh PSO enforces the replacement
/// CA"); a complete, already verified OCE stays cached ("CA public-key replacement
/// retains previously validated OCE"). The continuation then starts a new chain and the
/// leaf alone does not chain to the CA.
#[test]
fn ca_replacement_drops_a_partial_chain() {
    let pki = pki(0);
    let (mut sd, mut host) = fresh();
    provision(&mut sd, &mut host, &pki);
    let (mut s, mut ch) = admin(&mut sd, &mut host);
    let apdus = pso_apdus(0x10, 0x03, &pki.full_chain());
    assert_eq!(status(&sd.handshake(&apdus[0], &mut host).0), 0x9000);
    assert_eq!(status(&sd.handshake(&apdus[1], &mut host).0), 0x9000);
    let other = key_from(0x5A);
    assert_eq!(ok(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x03, 0x10, &ca_key_data(0x04, &other.public_uncompressed())), vec![0x04]);
    assert_eq!(status(&sd.handshake(&apdus[2], &mut host).0), 0x6A88, "the leaf starts a new chain under the vanished CA 10/03");
    assert!(!sd.has_verified_oce());
    // A verified OCE survives a replacement.
    assert_eq!(ok(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x04, 0x10, &ca_key_data(0x03, &pki.ca.public_uncompressed())), vec![0x03]);
    assert!(all_ok(&present(&mut sd, &mut host, 0x10, 0x03, &pki.full_chain())));
    assert_eq!(ok(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x03, 0x10, &ca_key_data(0x05, &other.public_uncompressed())), vec![0x05]);
    assert!(sd.has_verified_oce());
}

// ---------------------------------------------------------------------------------
// yubikit wire shapes on USB (extended) and NFC (short) sessions
// ---------------------------------------------------------------------------------

/// The APDUs yubikit sends for one command (yubikit `core/smartcard`:
/// `SmartCardProtocol.send_apdu` passes Le 0, which both formatters leave out):
/// - extended session (USB, `configure(Version(5, 3, 0))`): one extended APDU without
///   Le; a command without data is the bare header (case 1);
/// - short session (NFC, `force_short`): `CommandChainingProcessor` splits the data into
///   255-byte parts, CLA b5 on all but the last, no Le; a command without data ends in
///   `00` ("explicit Lc").
fn yubikit_apdus(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], extended: bool) -> Vec<Vec<u8>> {
    if extended {
        return vec![encode_apdu(cla, ins, p1, p2, data, None, true)];
    }
    if data.is_empty() {
        return vec![encode_apdu(cla, ins, p1, p2, &[], Some(0), false)];
    }
    let parts: Vec<&[u8]> = data.chunks(255).collect();
    let last = parts.len() - 1;
    parts
        .iter()
        .enumerate()
        .map(|(i, part)| encode_apdu(if i < last { cla | 0x10 } else { cla }, ins, p1, p2, part, None, false))
        .collect()
}

/// A plaintext command as yubikit sends it, with `lk-device`'s routing (handshakes to
/// `handshake`, others to `process`), followed through `61xx` with yubikit's GET
/// RESPONSE (`ResponseChainingProcessor`: `00 C0 00 00`, Le 0, in the session's form).
fn yubikit_plain(sd: &mut SecurityDomain, host: &mut TestHost, cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], extended: bool) -> (Vec<u8>, u16, Option<SecureChannel>) {
    let apdus = yubikit_apdus(cla, ins, p1, p2, data, extended);
    let mut channel = None;
    let mut resp = Vec::new();
    for (i, apdu) in apdus.iter().enumerate() {
        if lk_sd::is_handshake(apdu) {
            (resp, channel) = sd.handshake(apdu, host);
        } else {
            resp = plain(sd, host, apdu);
        }
        if i + 1 < apdus.len() {
            assert_eq!(resp, hex("9000"), "intermediate chained part");
        }
    }
    let mut out = Vec::new();
    loop {
        let sw = status(&resp);
        out.extend_from_slice(&resp[..resp.len() - 2]);
        if sw >> 8 != 0x61 {
            return (out, sw, channel);
        }
        let get_response = yubikit_apdus(0x00, 0xC0, 0x00, 0x00, &[], extended).remove(0);
        resp = plain(sd, host, &get_response);
    }
}

/// A protected command as yubikit's `ScpProcessor.send_apdu` sends it: the data is
/// always encrypted (an empty field becomes one padding block), the C-MAC covers the
/// extended Lc when the protected data exceeds 255 bytes or the session is extended and
/// the short Lc otherwise, and on a short session a long protected command is then split
/// by command chaining. `lk-device` reassembles such a chain and re-encodes it with
/// `Command::to_bytes` before `unwrap_command` (lk-sd `channel.rs` layering note 1).
fn yubikit_send(sd: &mut SecurityDomain, ch: &mut SecureChannel, host: &mut TestHost, s: &mut HostSession, cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], extended: bool) -> (Vec<u8>, u16) {
    let protected_len = (data.len() / 16 + 1) * 16 + 8;
    let mac_extended = extended || protected_len > 255;
    let protected = s.wrap(cla, ins, p1, p2, data, None, mac_extended);
    let apdu = if extended || !mac_extended {
        protected
    } else {
        let full = lk_codec::apdu::Command::parse(&protected).unwrap();
        let mut chain = lk_codec::apdu::CommandChain::new(65_535);
        let mut assembled = None;
        for part in yubikit_apdus(full.cla, ins, p1, p2, &full.data, false) {
            assembled = chain.push(lk_codec::apdu::Command::parse(&part).unwrap()).unwrap();
        }
        assembled.unwrap().to_bytes()
    };
    s.unwrap(&device_transmit(sd, ch, host, &apdu)).unwrap()
}

/// Every Security Domain request shape yubikit produces (`securitydomain.py`, `scp.py`,
/// `core/smartcard`) on a USB session (extended APDUs, never an Le) and on a short NFC
/// session (command chaining, data-less commands ending in `00`): SELECT (sent before
/// `configure`, so short), public GET DATA including chained answers, SCP11b with the
/// factory certificate, SCP03 with an EXTERNAL AUTHENTICATE MACed over the session's Lc
/// form, key and data provisioning (a certificate bundle longer than a short APDU), CA
/// identifiers longer than 256 bytes (`61xx` and GET RESPONSE), and SCP11a with the
/// chain presented one certificate per PSO.
#[test]
fn yubikit_request_shapes_on_extended_and_short_sessions() {
    for extended in [true, false] {
        let session = if extended { "USB/extended" } else { "NFC/short" };
        let (mut sd, mut host) = fresh();
        let pki = pki(0);

        let select = encode_apdu(0x00, 0xA4, 0x04, 0x00, lk_sd::AID, None, false);
        assert_eq!(sd.select(&select, &mut host), [&hex("6f178408a000000151000000a50b730906072a864886fc6b01")[..], &[0x90, 0x00]].concat());
        assert_eq!(yubikit_plain(&mut sd, &mut host, 0x00, 0xCA, 0x00, 0xE0, &[], extended).0, hex(FACTORY_KEY_INFO), "{session}");
        assert_eq!(yubikit_plain(&mut sd, &mut host, 0x00, 0xCA, 0x00, 0x66, &[], extended).0.len(), 63, "{session}");
        assert_eq!(yubikit_plain(&mut sd, &mut host, 0x00, 0xCA, 0xFF, 0x33, &[], extended).1, 0x6A88, "{session}: no CA identifiers yet");

        // SCP11b with the key of the factory certificate (ykman reads BF21 first).
        let (bundle, sw, _) = yubikit_plain(&mut sd, &mut host, 0x00, 0xCA, 0xBF, 0x21, &hex("A60483021301"), extended);
        assert_eq!(sw, 0x9000, "{session}");
        let (pk_sd_b, _) = cert_key_and_check(&der_split_all(&bundle)[0], None);
        let req = request(Variant::B, 0x01, key_from(0x41));
        let (resp, sw, ch) = yubikit_plain(&mut sd, &mut host, 0x80, 0x88, 0x01, 0x13, &req.data, extended);
        let mut est = req.finish(&[resp, sw.to_be_bytes().to_vec()].concat(), &pk_sd_b, None).unwrap();
        let mut ch = ch.unwrap();
        assert_eq!(yubikit_send(&mut sd, &mut ch, &mut host, &mut est.session, 0x00, 0xCA, 0x00, 0x66, &[], extended).0.len(), 63, "{session}");

        // SCP03 in a new `SecurityDomainSession` (SELECT ends the SCP11b session):
        // INITIALIZE UPDATE without Le, EXTERNAL AUTHENTICATE MACed over the Lc form of
        // the session and sent without Le.
        sd.select(&select, &mut host);
        assert!(!ch.is_open());
        let challenge = [0x5Au8; 8];
        let (resp, sw, _) = yubikit_plain(&mut sd, &mut host, 0x80, 0x50, 0x00, 0x00, &challenge, extended);
        let pending = read_init_response(&StaticKeys::DEFAULT, &challenge, &[resp, sw.to_be_bytes().to_vec()].concat());
        assert!(pending.card_cryptogram_ok, "{session}");
        let (ea, mut s) = pending.external_authenticate_form(0x33, &pending.host_cryptogram(), extended, extended);
        let ea_data = lk_codec::apdu::Command::parse(&ea).unwrap().data;
        let (_, sw, ch) = yubikit_plain(&mut sd, &mut host, 0x84, 0x82, 0x33, 0x00, &ea_data, extended);
        assert_eq!(sw, 0x9000, "{session}");
        let mut ch = ch.unwrap();

        // Provisioning as yubikit `put_key`, `store_ca_issuer`, `store_certificate_bundle`.
        let mut send = |sd: &mut SecurityDomain, host: &mut TestHost, cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]| {
            yubikit_send(sd, &mut ch, host, &mut s, cla, ins, p1, p2, data, extended)
        };
        assert_eq!(send(&mut sd, &mut host, 0x80, 0xD8, 0x00, 0x10, &ca_key_data(0x03, &pki.ca.public_uncompressed())), (vec![0x03], 0x9000));
        let dek = pending.dek;
        let sd_key = key_from(0x61);
        assert_eq!(send(&mut sd, &mut host, 0x80, 0xD8, 0x00, 0x11, &private_key_data(&dek, 0x01, sd_key.scalar())), (vec![0x01], 0x9000));
        let bundle = pki.full_chain();
        assert!(bundle.iter().all(|c| c.len() > 255), "each certificate needs the long form (chained PSO on NFC)");
        assert_eq!(send(&mut sd, &mut host, 0x00, 0xE2, 0x90, 0x00, &cert_store_data(0x11, 0x01, &bundle)).1, 0x9000, "{session}");
        // The anchor's identifier is the root's SKI: the card binds it to the first AKI.
        assert_eq!(send(&mut sd, &mut host, 0x00, 0xE2, 0x90, 0x00, &ca_issuer_data(0x10, 0x03, &pki.root_ski)).1, 0x9000);
        for kid in 0x20..0x2Au8 {
            let point = key_from(kid).public_uncompressed();
            assert_eq!(send(&mut sd, &mut host, 0x80, 0xD8, 0x00, kid, &ca_key_data(0x01, &point)), (vec![0x01], 0x9000));
            assert_eq!(send(&mut sd, &mut host, 0x00, 0xE2, 0x90, 0x00, &ca_issuer_data(kid, 0x01, &[kid; 20])).1, 0x9000);
        }
        // One identifier of 10 bytes and ten of 26: 270 bytes, more than one short answer.
        let (ids, sw) = send(&mut sd, &mut host, 0x00, 0xCA, 0xFF, 0x33, &[]);
        assert_eq!((ids.len(), sw), (270, 0x9000), "{session}");
        assert!(ch.is_open());

        let (plain_ids, sw, _) = yubikit_plain(&mut sd, &mut host, 0x00, 0xCA, 0xFF, 0x33, &[], extended);
        assert_eq!((plain_ids, sw), (ids, 0x9000), "{session}: GET RESPONSE completes the answer");
        let (stored, sw, _) = yubikit_plain(&mut sd, &mut host, 0x00, 0xCA, 0xBF, 0x21, &hex("A60483021101"), extended);
        assert_eq!((stored, sw), (bundle.concat(), 0x9000), "{session}");

        // SCP11a in a new session: one PSO per certificate (P2 b8 while more follow),
        // then MUTUAL AUTHENTICATE without Le.
        sd.select(&select, &mut host);
        let last = bundle.len() - 1;
        for (i, cert) in bundle.iter().enumerate() {
            let p2 = 0x10 | if i < last { 0x80 } else { 0x00 };
            assert_eq!(yubikit_plain(&mut sd, &mut host, 0x80, 0x2A, 0x03, p2, cert, extended).1, 0x9000, "{session}: PSO {i}");
        }
        let req = request(Variant::A, 0x01, key_from(0x42));
        let (resp, sw, ch) = yubikit_plain(&mut sd, &mut host, 0x80, 0x82, 0x01, 0x11, &req.data, extended);
        let mut est = req.finish(&[resp, sw.to_be_bytes().to_vec()].concat(), &sd_key.public_uncompressed(), Some(&pki.leaf)).unwrap();
        let mut ch = ch.unwrap();
        assert_eq!(ch.protocol(), Protocol::Scp11a);
        let (info, sw) = yubikit_send(&mut sd, &mut ch, &mut host, &mut est.session, 0x00, 0xCA, 0x00, 0xE0, &[], extended);
        assert_eq!((info.len(), sw), (18 + 13 * 8, 0x9000), "{session}: SCP03 set, CA 10/03, 11/01, 13/01, CAs 20-29");
    }
}
