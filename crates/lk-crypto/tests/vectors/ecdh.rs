//! ECDH on P-256 and P-384, RFC 5903 §8.1 and §8.2, plus point validation.

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

const CASES: [Case; 2] = [
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
];

fn point(x: &str, y: &str) -> Vec<u8> {
    [vec![0x04], hex(x), hex(y)].concat()
}

#[test]
fn rfc5903_public_keys() {
    for case in &CASES {
        let initiator = EcPrivateKey::from_scalar(case.curve, &hex(case.i)).unwrap();
        let responder = EcPrivateKey::from_scalar(case.curve, &hex(case.r)).unwrap();
        assert_eq!(initiator.public_uncompressed(), point(case.gix, case.giy), "{} g^i", case.section);
        assert_eq!(responder.public_uncompressed(), point(case.grx, case.gry), "{} g^r", case.section);
    }
}

#[test]
fn rfc5903_shared_secret() {
    for case in &CASES {
        let initiator = EcPrivateKey::from_scalar(case.curve, &hex(case.i)).unwrap();
        let responder = EcPrivateKey::from_scalar(case.curve, &hex(case.r)).unwrap();
        let from_initiator = initiator.ecdh(&point(case.grx, case.gry)).unwrap();
        let from_responder = responder.ecdh(&point(case.gix, case.giy)).unwrap();
        assert_eq!(from_initiator.as_slice(), hex(case.girx).as_slice(), "{} initiator", case.section);
        assert_eq!(from_responder.as_slice(), hex(case.girx).as_slice(), "{} responder", case.section);
    }
}

#[test]
fn rfc5903_points_are_valid() {
    for case in &CASES {
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
    for case in &CASES {
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
}
