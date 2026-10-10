//! The prime curves beyond P-256/P-384 that the algorithm information FA advertises:
//! P-521, secp256k1, brainpoolP256r1 and brainpoolP384r1 are usable in every slot;
//! brainpoolP512r1 stays unsupported (lk-crypto has no arithmetic for it, `6A81`).
//!
//! Published vectors driven through the card:
//! - RFC 6979 A.2.7 (P-521 key pair) for import and signing;
//! - RFC 5903 §8.3 (P-521), RFC 7027 Appendix A.1 / A.2 (brainpoolP256r1 / P384r1) and
//!   Project Wycheproof `ecdh_secp256k1_test.json` tcId 1 (secp256k1) for PSO:DECIPHER.
//!
//! Signatures and certificates are verified test-side with lk-crypto and lk-codec.

use lk_codec::der;
use lk_codec::x509::{PublicKey, SignatureAlgorithm};
use lk_crypto::{Curve, EcPrivateKey, HashAlg, digest, ecdsa_verify_prehash};
use lk_testkit::SeededEntropy;

use crate::common::{Card, Public, attr, cipher_do, crt, hex, import_data, parse_public};

fn card_point(template: &[u8]) -> Vec<u8> {
    match parse_public(template) {
        Public::Point(point) => point,
        other => panic!("not ECC: {other:?}"),
    }
}

/// RFC 6979 A.2.7: private key `x` (521 bits, printed with 131 hex digits) and `U = xG`.
const RFC6979_P521_X: &str = "00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C
                              AA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538";
const RFC6979_P521_UX: &str = "01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD3
                               71123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4";
const RFC6979_P521_UY: &str = "00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A2
                               8A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5";

fn rfc6979_p521_public() -> Vec<u8> {
    [vec![0x04], hex(RFC6979_P521_UX), hex(RFC6979_P521_UY)].concat()
}

/// A published ECDH case: the card holds `private`, the host sends `peer`, the shared
/// secret is `shared`.
struct EcdhCase {
    source: &'static str,
    attributes: &'static str,
    private: &'static str,
    public: &'static str,
    peer: &'static str,
    shared: &'static str,
}

const ECDH_CASES: [EcdhCase; 4] = [
    EcdhCase {
        source: "RFC 5903 §8.3 (i, g^i, g^r, g^ir x)",
        attributes: attr::P521_ECDH,
        private: "0037ADE9319A89F4DABDB3EF411AACCCA5123C61ACAB57B5393DCE47608172A0
                  95AA85A30FE1C2952C6771D937BA9777F5957B2639BAB072462F68C27A57382D4A52",
        public: "04
                 0015417E84DBF28C0AD3C278713349DC7DF153C897A1891BD98BAB4357C9ECBE
                 E1E3BF42E00B8E380AEAE57C2D107564941885942AF5A7F4601723C4195D176CED3E
                 017CAE20B6641D2EEB695786D8C946146239D099E18E1D5A514C739D7CB4A10A
                 D8A788015AC405D7799DC75E7B7D5B6CF2261A6A7F1507438BF01BEB6CA3926F9582",
        peer: "04
               00D0B3975AC4B799F5BEA16D5E13E9AF971D5E9B984C9F39728B5E5739735A21
               9B97C356436ADC6E95BB0352F6BE64A6C2912D4EF2D0433CED2B6171640012D9460F
               015C68226383956E3BD066E797B623C27CE0EAC2F551A10C2C724D9852077B87
               220B6536C5C408A1D2AEBB8E86D678AE49CB57091F4732296579AB44FCD17F0FC56A",
        shared: "01144C7D79AE6956BC8EDB8E7C787C4521CB086FA64407F97894E5E6B2D79B04
                 D1427E73CA4BAA240A34786859810C06B3C715A3A8CC3151F2BEE417996D19F3DDEA",
    },
    EcdhCase {
        source: "RFC 7027 A.1 (dA, qA, qB, x_Z)",
        attributes: attr::BP256_ECDH,
        private: "81DB1EE100150FF2EA338D708271BE38300CB54241D79950F77B063039804F1D",
        public: "04
                 44106E913F92BC02A1705D9953A8414DB95E1AAA49E81D9E85F929A8E3100BE5
                 8AB4846F11CACCB73CE49CBDD120F5A900A69FD32C272223F789EF10EB089BDC",
        peer: "04
               8D2D688C6CF93E1160AD04CC4429117DC2C41825E1E9FCA0ADDD34E6F1B39F7B
               990C57520812BE512641E47034832106BC7D3E8DD0E4C7F1136D7006547CEC6A",
        shared: "89AFC39D41D3B327814B80940B042590F96556EC91E6AE7939BCE31F3A18BF2B",
    },
    EcdhCase {
        source: "RFC 7027 A.2 (dA, qA, qB, x_Z)",
        attributes: attr::BP384_ECDH,
        private: "1E20F5E048A5886F1F157C74E91BDE2B98C8B52D58E5003D57053FC4B0BD65D6
                  F15EB5D1EE1610DF870795143627D042",
        public: "04
                 68B665DD91C195800650CDD363C625F4E742E8134667B767B1B476793588F885
                 AB698C852D4A6E77A252D6380FCAF068
                 55BC91A39C9EC01DEE36017B7D673A931236D2F1F5C83942D049E3FA20607493
                 E0D038FF2FD30C2AB67D15C85F7FAA59",
        peer: "04
               4D44326F269A597A5B58BBA565DA5556ED7FD9A8A9EB76C25F46DB69D19DC8CE
               6AD18E404B15738B2086DF37E71D1EB4
               62D692136DE56CBE93BF5FA3188EF58BC8A3A0EC6C1E151A21038A42E9185329
               B5B275903D192F8D4E1F32FE9CC78C48",
        shared: "0BD9D3A7EA0B3D519D09D8E48D0785FB744A6B355E6304BC51C229FBBCE239BB
                 ADF6403715C35D4FB2A5444F575D4F42",
    },
    EcdhCase {
        // Wycheproof gives the private key and the peer's SubjectPublicKeyInfo, not the
        // private key's public point, so `public` is empty and not imported.
        source: "Wycheproof ecdh_secp256k1_test.json tcId 1",
        attributes: attr::SECP256K1_ECDH,
        private: "f4b7ff7cccc98813a69fae3df222bfe3f4e28f764bf91b4a10d8096ce446b254",
        public: "",
        peer: "04
               d8096af8a11e0b80037e1ee68246b5dcbb0aeb1cf1244fd767db80f3fa27da2b
               396812ea1686e7472e9692eaf3e958e50e9500d3b4c77243db1f2acd67ba9cc4",
        shared: "544dfae22af6af939042b1d85b71a1e49e9a5614123c4d6ad0c8af65baf87d65",
    },
];

/// Import `case.private` into DEC (with its public key when published) and return the card.
fn card_with_ecdh_key(case: &EcdhCase) -> Card {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C2, case.attributes);
    let private = hex(case.private);
    let public = hex(case.public);
    let mut components: Vec<(u8, &[u8])> = vec![(0x92, &private)];
    if !public.is_empty() {
        components.push((0x99, &public));
    }
    assert_eq!(card.import(&import_data(crt::DEC, &components)), 0x9000, "{}", case.source);
    card
}

/// Catalog OpenPGP: "sign/decrypt/ECDH" on the curves added with lk-crypto's P-521,
/// secp256k1 and brainpool support; the shared secrets are the published ones.
#[test]
fn published_ecdh_vectors_through_the_card() {
    for case in &ECDH_CASES {
        let mut card = card_with_ecdh_key(case);
        if !case.public.is_empty() {
            assert_eq!(card_point(&card.public_key(crt::DEC).0), hex(case.public), "{}", case.source);
        }
        assert_eq!(card.verify(0x82, b"123456"), 0x9000);
        assert_eq!(card.decipher(&cipher_do(&hex(case.peer))), (hex(case.shared), 0x9000), "{}", case.source);
    }
}

/// Catalog OpenPGP_algorithms: "standard EC/Ed25519/X25519 import widths; 66-byte
/// zero-padded P521". The RFC 6979 A.2.7 private key has 521 bits whose first byte is 00
/// at the 66-byte width: the padded form imports, the 65-byte form does not.
#[test]
fn p521_import_is_66_byte_zero_padded() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C1, attr::P521_ECDSA);
    let x = hex(RFC6979_P521_X);
    assert_eq!((x.len(), x[0]), (66, 0x00));
    let public = rfc6979_p521_public();
    for (what, components) in [
        ("65 bytes (leading zero dropped)", vec![(0x92, &x[1..])]),
        ("67 bytes", vec![(0x92, &[&[0u8][..], &x].concat()[..])]),
        ("above 521 bits", vec![(0x92, &[0x11; 66][..])]),
        ("zero", vec![(0x92, &[0; 66][..])]),
        ("public key of another key", vec![(0x92, &x[..]), (0x99, &[&[0x04][..], &[0x11; 132]].concat()[..])]),
        ("P-384 width public key", vec![(0x92, &x[..]), (0x99, &public[..97])]),
    ] {
        assert_eq!(card.import(&import_data(crt::SIG, &components)), 0x6A80, "{what}");
    }
    assert_eq!(card.key_status()[0], 0x00);
    assert_eq!(card.import(&import_data(crt::SIG, &[(0x92, &x), (0x99, &public)])), 0x9000);
    let (template, sw) = card.public_key(crt::SIG);
    assert_eq!(sw, 0x9000);
    assert_eq!(card_point(&template), public);
    // PSO:CDS with a SHA-512 digest: r || s, 66 bytes each (spec §7.2.10).
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    let sha512 = digest(HashAlg::Sha512, b"sample");
    let (signature, sw) = card.sign(&sha512);
    assert_eq!(sw, 0x9000);
    assert_eq!(signature.len(), 132);
    assert!(ecdsa_verify_prehash(Curve::P521, &public, &sha512, &signature));
    // The digest limit is SHA-512's 64 bytes whatever the curve.
    assert_eq!(card.sign(&[0x55; 65]).1, 0x6700);
}

/// Catalog OpenPGP_algorithms: "invalid request ciphertext unchanged; retained independent
/// RSA/P521 private keys verified after rejection/restart".
#[test]
fn p521_keys_retained_after_rejected_requests_and_restart() {
    let case = &ECDH_CASES[0];
    let mut card = card_with_ecdh_key(case);
    card.set_attributes(0x00C1, attr::P521_ECDSA);
    let x = hex(RFC6979_P521_X);
    let public = rfc6979_p521_public();
    assert_eq!(card.import(&import_data(crt::SIG, &[(0x92, &x)])), 0x9000);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    let peer = hex(case.peer);
    let mut off_curve = peer.clone();
    off_curve[132] ^= 0x01;
    let p384_point = EcPrivateKey::generate(Curve::P384, &mut SeededEntropy::new(5)).public_uncompressed();
    let p521_order: Vec<u8> = [vec![0x04], vec![0xFF; 132]].concat();
    for (what, bad) in [
        ("off curve", off_curve),
        ("P-384 point", p384_point),
        ("truncated", peer[..132].to_vec()),
        ("coordinates >= p", p521_order),
        ("compressed", [&[0x02 | (peer[132] & 1)][..], &peer[1..67]].concat()),
    ] {
        assert_eq!(card.decipher(&cipher_do(&bad)).1, 0x6A80, "{what}");
    }
    assert_eq!(card.decipher(&cipher_do(&peer)), (hex(case.shared), 0x9000));
    card.reload();
    assert_eq!(card_point(&card.public_key(crt::DEC).0), hex(case.public));
    assert_eq!(card_point(&card.public_key(crt::SIG).0), public);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    assert_eq!(card.decipher(&cipher_do(&peer)), (hex(case.shared), 0x9000));
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    let sha512 = digest(HashAlg::Sha512, b"after restart");
    let (signature, sw) = card.sign(&sha512);
    assert_eq!(sw, 0x9000);
    assert!(ecdsa_verify_prehash(Curve::P521, &public, &sha512, &signature));
}

/// Each newly usable curve generated in a different slot: SIG P-521, AUT secp256k1, DEC
/// brainpoolP384r1 and an ATT brainpoolP256r1 issuer that attests the SIG key.
#[test]
fn generate_on_the_new_curves() {
    let mut card = Card::new();
    card.admin();
    card.set_attributes(0x00C1, attr::P521_ECDSA);
    card.set_attributes(0x00C2, attr::BP384_ECDH);
    card.set_attributes(0x00C3, attr::SECP256K1_ECDSA);
    card.set_attributes(0x00DA, attr::BP256_ECDSA);
    let sig = card_point(&card.generate(crt::SIG));
    let dec = card_point(&card.generate(crt::DEC));
    let aut = card_point(&card.generate(crt::AUT));
    let att = card_point(&card.generate(crt::ATT));
    assert_eq!((sig.len(), dec.len(), aut.len(), att.len()), (133, 97, 65, 65));
    assert!(lk_crypto::ec_public_is_valid(Curve::P521, &sig));
    assert!(lk_crypto::ec_public_is_valid(Curve::BrainpoolP384r1, &dec));
    assert!(lk_crypto::ec_public_is_valid(Curve::Secp256k1, &aut));
    assert!(lk_crypto::ec_public_is_valid(Curve::BrainpoolP256r1, &att));
    assert_eq!(card.key_status(), [0x01, 0x01, 0x01, 0x01]);

    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    let sha512 = digest(HashAlg::Sha512, b"sig");
    let (signature, sw) = card.sign(&sha512);
    assert_eq!((signature.len(), sw), (132, 0x9000));
    assert!(ecdsa_verify_prehash(Curve::P521, &sig, &sha512, &signature));
    let sha256 = digest(HashAlg::Sha256, b"aut");
    let (signature, sw) = card.authenticate(&sha256);
    assert_eq!((signature.len(), sw), (64, 0x9000));
    assert!(ecdsa_verify_prehash(Curve::Secp256k1, &aut, &sha256, &signature));
    let peer = EcPrivateKey::generate(Curve::BrainpoolP384r1, &mut SeededEntropy::new(9));
    let expected = peer.ecdh(&dec).unwrap().to_vec();
    assert_eq!(card.decipher(&cipher_do(&peer.public_uncompressed())), (expected, 0x9000));

    // GET ATTESTATION: ecdsa-with-SHA256 by the brainpool issuer (catalog "SHA256 RSA/EC
    // signatures"), subject key named as secp521r1.
    assert_eq!(card.attest(0x01).1, 0x9000);
    let certificate = card.certificate(2);
    let (tbs, algorithm, signature) = certificate_parts(&certificate);
    assert_eq!(algorithm, SignatureAlgorithm::EcdsaWithSha256.algorithm_identifier());
    assert!(ecdsa_verify_prehash(Curve::BrainpoolP256r1, &att, &lk_crypto::sha256(&tbs), &signature));
    assert_eq!(subject_public_key_info(&tbs), PublicKey::EcP521(sig).to_der());
}

/// Attestation certificates name each new curve in the attested key's SubjectPublicKeyInfo
/// (RFC 5480 §2.1.1 named curves; secp256k1 SEC 2; brainpool RFC 5639 §4.1), and issuers on
/// P-521 and secp256k1 sign them too.
#[test]
fn attestation_names_the_new_curves() {
    for (sig_attributes, issuer_attributes, issuer_curve, wrap) in [
        (attr::SECP256K1_ECDSA, attr::P521_ECDSA, Curve::P521, PublicKey::EcSecp256k1 as fn(Vec<u8>) -> PublicKey),
        (attr::BP256_ECDSA, attr::SECP256K1_ECDSA, Curve::Secp256k1, PublicKey::EcBrainpoolP256r1),
        (attr::BP384_ECDSA, attr::BP384_ECDSA, Curve::BrainpoolP384r1, PublicKey::EcBrainpoolP384r1),
    ] {
        let mut card = Card::new();
        card.admin();
        card.set_attributes(0x00C1, sig_attributes);
        card.set_attributes(0x00DA, issuer_attributes);
        let sig = card_point(&card.generate(crt::SIG));
        let issuer = card_point(&card.generate(crt::ATT));
        assert_eq!(card.verify(0x81, b"123456"), 0x9000);
        assert_eq!(card.attest(0x01).1, 0x9000, "{sig_attributes}");
        let certificate = card.certificate(2);
        let (tbs, algorithm, signature) = certificate_parts(&certificate);
        assert_eq!(algorithm, SignatureAlgorithm::EcdsaWithSha256.algorithm_identifier());
        assert!(ecdsa_verify_prehash(issuer_curve, &issuer, &lk_crypto::sha256(&tbs), &signature), "{issuer_attributes}");
        assert_eq!(subject_public_key_info(&tbs), wrap(sig).to_der(), "{sig_attributes}");
    }
}

/// brainpoolP512r1 is advertised and selectable in every slot, but no key of it can exist.
#[test]
fn brainpool_p512r1_stays_unsupported_in_every_slot() {
    let mut card = Card::new();
    card.admin();
    for (tag, attributes, crt) in [
        (0x00C1, attr::BP512_ECDSA, crt::SIG),
        (0x00C2, attr::BP512_ECDH, crt::DEC),
        (0x00C3, attr::BP512_ECDSA, crt::AUT),
        (0x00DA, attr::BP512_ECDSA, crt::ATT),
    ] {
        card.set_attributes(tag, attributes);
        assert_eq!(card.ext(0x47, 0x80, 0x00, crt).1, 0x6A81, "{tag:04X}");
        assert_eq!(card.import(&import_data(crt, &[(0x92, &[0x11; 64])])), 0x6A81, "{tag:04X}");
    }
    assert_eq!(card.key_status(), [0, 0, 0, 0]);
}

/// `(TBSCertificate element, outer signatureAlgorithm element, signature bytes)`.
fn certificate_parts(certificate: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let body = der::expect_only(certificate, der::tag::SEQUENCE).unwrap();
    let (tbs, rest) = der::split_der(body).unwrap();
    let (algorithm, rest) = der::split_der(rest).unwrap();
    let bits = der::expect_only(rest, der::tag::BIT_STRING).unwrap();
    let (unused, signature) = der::decode_bit_string(bits).unwrap();
    assert_eq!(unused, 0);
    (tbs.to_vec(), algorithm.to_vec(), signature.to_vec())
}

/// The subjectPublicKeyInfo element of a TBSCertificate (RFC 5280 §4.1: version, serial,
/// signature, issuer, validity, subject, subjectPublicKeyInfo).
fn subject_public_key_info(tbs: &[u8]) -> Vec<u8> {
    let mut rest = der::expect_only(tbs, der::tag::SEQUENCE).unwrap();
    for _ in 0..6 {
        rest = der::split_der(rest).unwrap().1;
    }
    der::split_der(rest).unwrap().0.to_vec()
}
