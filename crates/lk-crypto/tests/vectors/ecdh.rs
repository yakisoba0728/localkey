//! ECDH known answers and point validation on every curve:
//! - P-256, P-384, P-521: RFC 5903 §8.1, §8.2, §8.3;
//! - brainpoolP256r1, brainpoolP384r1: RFC 7027 Appendix A.1 / A.2 and RFC 6932
//!   Appendix A.2 / A.3 (two independent key pairs per curve);
//! - secp256k1: Project Wycheproof `testvectors_v1/ecdh_secp256k1_test.json` (C2SP/wycheproof),
//!   tcId 1 ("normal case") and tcId 3 (shared x = 1, so the 32-byte output is mostly
//!   leading zeros).

use lk_crypto::{Curve, CryptoError, EcPrivateKey, ec_public_is_valid};

use crate::common::hex;

struct Case {
    section: &'static str,
    curve: Curve,
    i: &'static str,
    gix: &'static str,
    giy: &'static str,
    r: &'static str,
    grx: &'static str,
    gry: &'static str,
    girx: &'static str,
}

const CASES: &[Case] = &[
    Case {
        section: "RFC 5903 §8.1",
        curve: Curve::P256,
        i: "C88F01F5 10D9AC3F 70A292DA A2316DE5 44E9AAB8 AFE84049 C62A9C57 862D1433",
        gix: "DAD0B653 94221CF9 B051E1FE CA5787D0 98DFE637 FC90B9EF 945D0C37 72581180",
        giy: "5271A046 1CDB8252 D61F1C45 6FA3E59A B1F45B33 ACCF5F58 389E0577 B8990BB3",
        r: "C6EF9C5D 78AE012A 011164AC B397CE20 88685D8F 06BF9BE0 B283AB46 476BEE53",
        grx: "D12DFB52 89C8D4F8 1208B702 70398C34 2296970A 0BCCB74C 736FC755 4494BF63",
        gry: "56FBF3CA 366CC23E 8157854C 13C58D6A AC23F046 ADA30F83 53E74F33 039872AB",
        girx: "D6840F6B 42F6EDAF D13116E0 E1256520 2FEF8E9E CE7DCE03 812464D0 4B9442DE",
    },
    Case {
        section: "RFC 5903 §8.2",
        curve: Curve::P384,
        i: "099F3C70 34D4A2C6 99884D73 A375A67F 7624EF7C 6B3C0F16 0647B674 14DCE655
            E35B5380 41E649EE 3FAEF896 783AB194",
        gix: "667842D7 D180AC2C DE6F74F3 7551F557 55C7645C 20EF73E3 1634FE72 B4C55EE6
              DE3AC808 ACB4BDB4 C88732AE E95F41AA",
        giy: "9482ED1F C0EEB9CA FC498462 5CCFC23F 65032149 E0E144AD A0241815 35A0F38E
              EB9FCFF3 C2C947DA E69B4C63 4573A81C",
        r: "41CB0779 B4BDB85D 47846725 FBEC3C94 30FAB46C C8DC5060 855CC9BD A0AA2942
            E0308312 916B8ED2 960E4BD5 5A7448FC",
        grx: "E558DBEF 53EECDE3 D3FCCFC1 AEA08A89 A987475D 12FD950D 83CFA417 32BC509D
              0D1AC43A 0336DEF9 6FDA41D0 774A3571",
        gry: "DCFBEC7A ACF31964 72169E83 8430367F 66EEBE3C 6E70C416 DD5F0C68 759DD1FF
              F83FA401 42209DFF 5EAAD96D B9E6386C",
        girx: "11187331 C279962D 93D60424 3FD592CB 9D0A926F 422E4718 7521287E 7156C5C4
               D6031355 69B9E9D0 9CF5D4A2 70F59746",
    },
    Case {
        section: "RFC 5903 §8.3",
        curve: Curve::P521,
        i: "0037ADE9 319A89F4 DABDB3EF 411AACCC A5123C61 ACAB57B5 393DCE47 608172A0
            95AA85A3 0FE1C295 2C6771D9 37BA9777 F5957B26 39BAB072 462F68C2 7A57382D
            4A52",
        gix: "0015417E 84DBF28C 0AD3C278 713349DC 7DF153C8 97A1891B D98BAB43 57C9ECBE
              E1E3BF42 E00B8E38 0AEAE57C 2D107564 94188594 2AF5A7F4 601723C4 195D176C
              ED3E",
        giy: "017CAE20 B6641D2E EB695786 D8C94614 6239D099 E18E1D5A 514C739D 7CB4A10A
              D8A78801 5AC405D7 799DC75E 7B7D5B6C F2261A6A 7F150743 8BF01BEB 6CA3926F
              9582",
        r: "0145BA99 A847AF43 793FDD0E 872E7CDF A16BE30F DC780F97 BCCC3F07 8380201E
            9C677D60 0B343757 A3BDBF2A 3163E4C2 F869CCA7 458AA4A4 EFFC311F 5CB15168
            5EB9",
        grx: "00D0B397 5AC4B799 F5BEA16D 5E13E9AF 971D5E9B 984C9F39 728B5E57 39735A21
              9B97C356 436ADC6E 95BB0352 F6BE64A6 C2912D4E F2D0433C ED2B6171 640012D9
              460F",
        gry: "015C6822 6383956E 3BD066E7 97B623C2 7CE0EAC2 F551A10C 2C724D98 52077B87
              220B6536 C5C408A1 D2AEBB8E 86D678AE 49CB5709 1F473229 6579AB44 FCD17F0F
              C56A",
        girx: "01144C7D 79AE6956 BC8EDB8E 7C787C45 21CB086F A64407F9 7894E5E6 B2D79B04
               D1427E73 CA4BAA24 0A347868 59810C06 B3C715A3 A8CC3151 F2BEE417 996D19F3
               DDEA",
    },
    // RFC 7027 names the values dA, x_qA, y_qA, dB, x_qB, y_qB, x_Z.
    Case {
        section: "RFC 7027 A.1",
        curve: Curve::BrainpoolP256r1,
        i: "81DB1EE100150FF2EA338D708271BE38300CB54241D79950F77B063039804F1D",
        gix: "44106E913F92BC02A1705D9953A8414DB95E1AAA49E81D9E85F929A8E3100BE5",
        giy: "8AB4846F11CACCB73CE49CBDD120F5A900A69FD32C272223F789EF10EB089BDC",
        r: "55E40BC41E37E3E2AD25C3C6654511FFA8474A91A0032087593852D3E7D76BD3",
        grx: "8D2D688C6CF93E1160AD04CC4429117DC2C41825E1E9FCA0ADDD34E6F1B39F7B",
        gry: "990C57520812BE512641E47034832106BC7D3E8DD0E4C7F1136D7006547CEC6A",
        girx: "89AFC39D41D3B327814B80940B042590F96556EC91E6AE7939BCE31F3A18BF2B",
    },
    Case {
        section: "RFC 6932 A.2",
        curve: Curve::BrainpoolP256r1,
        i: "041EB8B1 E2BC681B CE8E3996 3B2E9FC4 15B05283 313DD1A8 BCC055F1 1AE49699",
        gix: "78028496 B5ECAAB3 C8B6C12E 45DB1E02 C9E4D26B 4113BC4F 015F60C5 CCC0D206",
        giy: "A2AE1762 A3831C1D 20F03F8D 1E3C0C39 AFE6F09B 4D44BBE8 0CD10098 7B05F92B",
        r: "06F5240E ACDB9837 BC96D482 74C8AA83 4B6C87BA 9CC3EEDD 81F99A16 B8D804D3",
        grx: "8E07E219 BA588916 C5B06AA3 0A2F464C 2F2ACFC1 610A3BE2 FB240B63 5341F0DB",
        gry: "148EA1D7 D1E7E54B 9555B6C9 AC90629C 18B63BEE 5D7AA694 9EBBF47B 24FDE40D",
        girx: "05E94091 5549E9F6 A4A75693 716E3746 6ABA79B4 BF291987 7A16DD2C C2E23708",
    },
    Case {
        section: "RFC 7027 A.2",
        curve: Curve::BrainpoolP384r1,
        i: "1E20F5E048A5886F1F157C74E91BDE2B98C8B52D58E5003D57053FC4B0BD6
            5D6F15EB5D1EE1610DF870795143627D042",
        gix: "68B665DD91C195800650CDD363C625F4E742E8134667B767B1B47679358
              8F885AB698C852D4A6E77A252D6380FCAF068",
        giy: "55BC91A39C9EC01DEE36017B7D673A931236D2F1F5C83942D049E3FA206
              07493E0D038FF2FD30C2AB67D15C85F7FAA59",
        r: "032640BC6003C59260F7250C3DB58CE647F98E1260ACCE4ACDA3DD869F74E
            01F8BA5E0324309DB6A9831497ABAC96670",
        grx: "4D44326F269A597A5B58BBA565DA5556ED7FD9A8A9EB76C25F46DB69D19
              DC8CE6AD18E404B15738B2086DF37E71D1EB4",
        gry: "62D692136DE56CBE93BF5FA3188EF58BC8A3A0EC6C1E151A21038A42E91
              85329B5B275903D192F8D4E1F32FE9CC78C48",
        girx: "0BD9D3A7EA0B3D519D09D8E48D0785FB744A6B355E6304BC51C229FBBCE2
               39BBADF6403715C35D4FB2A5444F575D4F42",
    },
    Case {
        section: "RFC 6932 A.3",
        curve: Curve::BrainpoolP384r1,
        i: "014EC075 5B78594B A47FB0A5 6F617304 5B4331E7 4BA1A6F4
            7322E70D 79D828D9 7E095884 CA72B73F DABD5910 DF0FA76A",
        gix: "45CB26E4 384DAF6F B7768853 07B9A38B 7AD1B5C6 92E0C32F
              01253327 78F3B8D3 F50CA358 099B30DE B5EE69A9 5C058B4E",
        giy: "8173A1C5 4AFFA7E7 81D0E1E1 D12C0DC2 B74F4DF5 8E4A4E3A
              F7026C5D 32DC530A 2CD89C85 9BB4B4B7 68497F49 AB8CC859",
        r: "6B461CB7 9BD0EA51 9A87D682 8815D8CE 7CD9B3CA A0B5A826
            2CBCD550 A015C900 95B976F3 52995750 6E1224A8 61711D54",
        grx: "01BF92A9 2EE4BE8D ED1A9111 25C209B0 3F99E316 1CFCC986
              DC771138 3FC30AF9 CE28CA33 86D59E2C 8D72CE1E 7B4666E8",
        gry: "3289C4A3 A4FEE035 E39BDB88 5D509D22 4A142FF9 FBCC5CFE
              5CCBB302 68EE4748 7ED80448 58D31D84 8F7A95C6 35A347AC",
        girx: "04CC4FF3 DCCCB07A F24E0ACC 529955B3 6D7C8077 72B92FCB
               E48F3AFE 9A2F370A 1F98D3FA 73FD0C07 47C632E1 2F1423EC",
    },
];

fn point(x: &str, y: &str) -> Vec<u8> {
    [vec![0x04], hex(x), hex(y)].concat()
}

#[test]
fn published_public_keys() {
    for case in CASES {
        let initiator = EcPrivateKey::from_scalar(case.curve, &hex(case.i)).unwrap();
        let responder = EcPrivateKey::from_scalar(case.curve, &hex(case.r)).unwrap();
        assert_eq!(initiator.public_uncompressed(), point(case.gix, case.giy), "{} g^i", case.section);
        assert_eq!(responder.public_uncompressed(), point(case.grx, case.gry), "{} g^r", case.section);
    }
}

#[test]
fn published_shared_secrets() {
    for case in CASES {
        let initiator = EcPrivateKey::from_scalar(case.curve, &hex(case.i)).unwrap();
        let responder = EcPrivateKey::from_scalar(case.curve, &hex(case.r)).unwrap();
        let from_initiator = initiator.ecdh(&point(case.grx, case.gry)).unwrap();
        let from_responder = responder.ecdh(&point(case.gix, case.giy)).unwrap();
        assert_eq!(from_initiator.as_slice(), hex(case.girx).as_slice(), "{} initiator", case.section);
        assert_eq!(from_responder.as_slice(), hex(case.girx).as_slice(), "{} responder", case.section);
        assert_eq!(from_initiator.len(), case.curve.field_len(), "{}", case.section);
    }
}

#[test]
fn every_curve_has_a_published_vector() {
    for curve in Curve::ALL {
        let covered = CASES.iter().any(|case| case.curve == curve) || curve == Curve::Secp256k1;
        assert!(covered, "{curve:?}");
    }
}

/// Project Wycheproof `ecdh_secp256k1_test.json`: the peer key is an X.509
/// SubjectPublicKeyInfo (`id-ecPublicKey`, `secp256k1`) whose BIT STRING is the
/// uncompressed point; the private key is printed as a DER INTEGER body (leading 00).
const SECP256K1_SPKI_PREFIX: &str = "3056301006072a8648ce3d020106052b8104000a034200";

struct WycheproofCase {
    tc_id: u32,
    public: &'static str,
    private: &'static str,
    shared: &'static str,
}

const WYCHEPROOF_SECP256K1: [WycheproofCase; 2] = [
    WycheproofCase {
        tc_id: 1,
        public: "3056301006072a8648ce3d020106052b8104000a03420004d8096af8a11e0b80037e1ee68246b5dc
                 bb0aeb1cf1244fd767db80f3fa27da2b396812ea1686e7472e9692eaf3e958e50e9500d3b4c77243
                 db1f2acd67ba9cc4",
        private: "00f4b7ff7cccc98813a69fae3df222bfe3f4e28f764bf91b4a10d8096ce446b254",
        shared: "544dfae22af6af939042b1d85b71a1e49e9a5614123c4d6ad0c8af65baf87d65",
    },
    WycheproofCase {
        tc_id: 3,
        public: "3056301006072a8648ce3d020106052b8104000a03420004965ff42d654e058ee7317cced7caf093
                 fbb180d8d3a74b0dcd9d8cd47a39d5cb9c2aa4daac01a4be37c20467ede964662f12983e0b5272a4
                 7a5f2785685d8087",
        private: "00a2b6442a37f8a3764aeff4011a4c422b389a1e509669c43f279c8b7e32d80c3a",
        shared: "0000000000000000000000000000000000000000000000000000000000000001",
    },
];

#[test]
fn wycheproof_secp256k1_shared_secret() {
    for case in &WYCHEPROOF_SECP256K1 {
        let spki = hex(case.public);
        let prefix = hex(SECP256K1_SPKI_PREFIX);
        assert_eq!(spki[..prefix.len()], prefix, "tcId {}", case.tc_id);
        let peer = &spki[prefix.len()..];
        let private = hex(case.private);
        assert_eq!(private[0], 0x00);
        let key = EcPrivateKey::from_scalar(Curve::Secp256k1, &private[1..]).unwrap();
        assert!(ec_public_is_valid(Curve::Secp256k1, peer), "tcId {}", case.tc_id);
        let shared = key.ecdh(peer).unwrap();
        assert_eq!(shared.as_slice(), hex(case.shared).as_slice(), "tcId {}", case.tc_id);
        assert_eq!(shared.len(), 32, "tcId {}", case.tc_id);
    }
}

#[test]
fn ecdh_round_trips_on_every_curve() {
    let mut entropy = crate::common::CounterEntropy::new(b"ecdh round trip");
    for curve in Curve::ALL {
        for _ in 0..3 {
            let a = EcPrivateKey::generate(curve, &mut entropy);
            let b = EcPrivateKey::generate(curve, &mut entropy);
            let ab = a.ecdh(&b.public_uncompressed()).unwrap();
            let ba = b.ecdh(&a.public_uncompressed()).unwrap();
            assert_eq!(ab, ba, "{curve:?}");
            assert_eq!(ab.len(), curve.field_len(), "{curve:?}");
            assert!(format!("{ab:?}").contains("redacted"));
        }
    }
}

#[test]
fn published_points_are_valid() {
    for case in CASES {
        assert!(ec_public_is_valid(case.curve, &point(case.gix, case.giy)), "{}", case.section);
        assert!(ec_public_is_valid(case.curve, &point(case.grx, case.gry)), "{}", case.section);
    }
}

/// Invalid encodings of an otherwise valid point (SEC 1 v2 §2.3.4).
fn invalid_variants(case: &Case) -> Vec<(Vec<u8>, &'static str)> {
    let good = point(case.grx, case.gry);
    let mut off_curve = good.clone();
    *off_curve.last_mut().unwrap() ^= 0x01;
    let mut compressed = vec![0x02 | (good.last().unwrap() & 1)];
    compressed.extend_from_slice(&hex(case.grx));
    let mut hybrid = good.clone();
    hybrid[0] = 0x06 | (good.last().unwrap() & 1);
    let mut x_too_big = good.clone();
    x_too_big[1..1 + case.curve.field_len()].fill(0xff);
    vec![
        (off_curve, "y changed (not on the curve)"),
        (compressed, "compressed encoding"),
        (hybrid, "hybrid encoding"),
        (x_too_big, "coordinate >= p"),
        (vec![0x00], "identity encoding"),
        (vec![0x04; case.curve.point_len()], "garbage"),
        (good[..good.len() - 1].to_vec(), "truncated"),
        ([good.as_slice(), &[0]].concat(), "trailing byte"),
        (Vec::new(), "empty"),
    ]
}

#[test]
fn invalid_peer_points_are_rejected() {
    for case in CASES {
        let initiator = EcPrivateKey::from_scalar(case.curve, &hex(case.i)).unwrap();
        for (bad, what) in invalid_variants(case) {
            assert!(!ec_public_is_valid(case.curve, &bad), "{} {what}", case.section);
            assert_eq!(initiator.ecdh(&bad).unwrap_err(), CryptoError::InvalidInput, "{} {what}", case.section);
        }
    }
}

#[test]
fn points_from_the_other_curve_are_rejected() {
    let p256 = point(CASES[0].gix, CASES[0].giy);
    let p384 = point(CASES[1].gix, CASES[1].giy);
    assert!(!ec_public_is_valid(Curve::P384, &p256));
    assert!(!ec_public_is_valid(Curve::P256, &p384));
    let key = EcPrivateKey::from_scalar(Curve::P256, &hex(CASES[0].i)).unwrap();
    assert_eq!(key.ecdh(&p384).unwrap_err(), CryptoError::InvalidInput);
    // Same-length curves: a point of one is not on the other (P-256, secp256k1 and
    // brainpoolP256r1 all use 65-byte points; P-384 and brainpoolP384r1 97-byte ones).
    let mut published: Vec<(Curve, Vec<u8>)> =
        CASES.iter().map(|case| (case.curve, point(case.gix, case.giy))).collect();
    let k1 = &WYCHEPROOF_SECP256K1[0];
    published.push((Curve::Secp256k1, hex(k1.public)[hex(SECP256K1_SPKI_PREFIX).len()..].to_vec()));
    for (owner, point) in &published {
        for curve in Curve::ALL {
            assert_eq!(ec_public_is_valid(curve, point), curve == *owner, "{owner:?} point on {curve:?}");
        }
    }
}
