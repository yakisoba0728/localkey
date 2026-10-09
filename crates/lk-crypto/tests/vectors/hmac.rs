//! HMAC (RFC 2104) with SHA-1 (RFC 2202 §3) and SHA-2 (RFC 4231 §4), plus `ct_eq`.

use lk_crypto::{HashAlg, ct_eq, hmac, hmac_sha1, hmac_sha256};

use crate::common::hex;

#[test]
fn hmac_sha1_rfc2202() {
    // RFC 2202 §3, test cases 1, 2, 3 and 6 (case 6: 80-byte key, longer than the block).
    let cases: [(Vec<u8>, Vec<u8>, &str); 4] = [
        (vec![0x0b; 20], b"Hi There".to_vec(), "b617318655057264e28bc0b6fb378c8ef146be00"),
        (b"Jefe".to_vec(), b"what do ya want for nothing?".to_vec(), "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"),
        (vec![0xaa; 20], vec![0xdd; 50], "125d7342b9ac11cd91a39af48aa17b4f63f175d3"),
        (
            vec![0xaa; 80],
            b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
            "aa4ae5e15272d00e95705637ce8a3b55ed402112",
        ),
    ];
    for (i, (key, data, expected)) in cases.iter().enumerate() {
        assert_eq!(hmac_sha1(key, data).to_vec(), hex(expected), "case index {i}");
        assert_eq!(hmac(HashAlg::Sha1, key, data), hex(expected), "case index {i}");
    }
}

struct Rfc4231Case {
    name: &'static str,
    key: Vec<u8>,
    data: Vec<u8>,
    sha256: &'static str,
    sha384: &'static str,
    sha512: &'static str,
}

fn rfc4231_cases() -> Vec<Rfc4231Case> {
    vec![
        // RFC 4231 §4.2, Test Case 1.
        Rfc4231Case {
            name: "4.2 case 1",
            key: vec![0x0b; 20],
            data: b"Hi There".to_vec(),
            sha256: "b0344c61d8db38535ca8afceaf0bf12b 881dc200c9833da726e9376c2e32cff7",
            sha384: "afd03944d84895626b0825f4ab46907f 15f9dadbe4101ec682aa034c7cebc59c
                     faea9ea9076ede7f4af152e8b2fa9cb6",
            sha512: "87aa7cdea5ef619d4ff0b4241a1d6cb0 2379f4e2ce4ec2787ad0b30545e17cde
                     daa833b7d6b8a702038b274eaea3f4e4 be9d914eeb61f1702e696c203a126854",
        },
        // RFC 4231 §4.3, Test Case 2 (key shorter than the output).
        Rfc4231Case {
            name: "4.3 case 2",
            key: b"Jefe".to_vec(),
            data: b"what do ya want for nothing?".to_vec(),
            sha256: "5bdcc146bf60754e6a042426089575c7 5a003f089d2739839dec58b964ec3843",
            sha384: "af45d2e376484031617f78d2b58a6b1b 9c7ef464f5a01b47e42ec3736322445e
                     8e2240ca5e69e2c78b3239ecfab21649",
            sha512: "164b7a7bfcf819e2e395fbe73b56e0a3 87bd64222e831fd610270cd7ea250554
                     9758bf75c05a994a6d034f65f8f0e6fd caeab1a34d4a6b4b636e070a38bce737",
        },
        // RFC 4231 §4.4, Test Case 3.
        Rfc4231Case {
            name: "4.4 case 3",
            key: vec![0xaa; 20],
            data: vec![0xdd; 50],
            sha256: "773ea91e36800e46854db8ebd09181a7 2959098b3ef8c122d9635514ced565fe",
            sha384: "88062608d3e6ad8a0aa2ace014c8a86f 0aa635d947ac9febe83ef4e55966144b
                     2a5ab39dc13814b94e3ab6e101a34f27",
            sha512: "fa73b0089d56a284efb0f0756c890be9 b1b5dbdd8ee81a3655f83e33b2279d39
                     bf3e848279a722c806b485a47e67c807 b946a337bee8942674278859e13292fb",
        },
        // RFC 4231 §4.5, Test Case 4.
        Rfc4231Case {
            name: "4.5 case 4",
            key: hex("0102030405060708090a0b0c0d0e0f10 111213141516171819"),
            data: vec![0xcd; 50],
            sha256: "82558a389a443c0ea4cc819899f2083a 85f0faa3e578f8077a2e3ff46729665b",
            sha384: "3e8a69b7783c25851933ab6290af6ca7 7a9981480850009cc5577c6e1f573b4e
                     6801dd23c4a7d679ccf8a386c674cffb",
            sha512: "b0ba465637458c6990e5a8c5f61d4af7 e576d97ff94b872de76f8050361ee3db
                     a91ca5c11aa25eb4d679275cc5788063 a5f19741120c4f2de2adebeb10a298dd",
        },
        // RFC 4231 §4.7, Test Case 6 (131-byte key, longer than every block size).
        Rfc4231Case {
            name: "4.7 case 6",
            key: vec![0xaa; 131],
            data: b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
            sha256: "60e431591ee0b67f0d8a26aacbf5b77f 8e0bc6213728c5140546040f0ee37f54",
            sha384: "4ece084485813e9088d2c63a041bc5b4 4f9ef1012a2b588f3cd11f05033ac4c6
                     0c2ef6ab4030fe8296248df163f44952",
            sha512: "80b24263c7c1a3ebb71493c1dd7be8b4 9b46d1f41b4aeec1121b013783f8f352
                     6b56d037e05f2598bd0fd2215d6a1e52 95e64f73f63f0aec8b915a985d786598",
        },
        // RFC 4231 §4.8, Test Case 7 (131-byte key and 152-byte data).
        Rfc4231Case {
            name: "4.8 case 7",
            key: vec![0xaa; 131],
            data: b"This is a test using a larger than block-size key and a larger than \
block-size data. The key needs to be hashed before being used by the HMAC algorithm."
                .to_vec(),
            sha256: "9b09ffa71b942fcb27635fbcd5b0e944 bfdc63644f0713938a7f51535c3a35e2",
            sha384: "6617178e941f020d351e2f254e8fd32c 602420feb0b8fb9adccebb82461e99c5
                     a678cc31e799176d3860e6110c46523e",
            sha512: "e37b6a775dc87dbaa4dfa9f96e5e3ffd debd71f8867289865df5a32d20cdc944
                     b6022cac3c4982b10d5eeb55c3e4de15 134676fb6de0446065c97440fa8c6a58",
        },
    ]
}

#[test]
fn hmac_sha2_rfc4231() {
    for case in rfc4231_cases() {
        let name = case.name;
        assert_eq!(hmac(HashAlg::Sha256, &case.key, &case.data), hex(case.sha256), "SHA-256 {name}");
        assert_eq!(hmac_sha256(&case.key, &case.data).to_vec(), hex(case.sha256), "SHA-256 {name}");
        assert_eq!(hmac(HashAlg::Sha384, &case.key, &case.data), hex(case.sha384), "SHA-384 {name}");
        assert_eq!(hmac(HashAlg::Sha512, &case.key, &case.data), hex(case.sha512), "SHA-512 {name}");
    }
}

#[test]
fn rfc4231_case7_data_length() {
    // RFC 4231 §4.8 prints the data as 152 bytes over ten lines.
    let case = rfc4231_cases().pop().unwrap();
    assert_eq!(case.data.len(), 152);
}

#[test]
fn hmac_output_lengths() {
    for alg in [HashAlg::Sha1, HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512] {
        assert_eq!(hmac(alg, b"", b"").len(), alg.output_len(), "{alg:?}");
    }
}

#[test]
fn ct_eq_compares_content_and_length() {
    assert!(ct_eq(b"", b""));
    assert!(ct_eq(b"abc", b"abc"));
    assert!(!ct_eq(b"abc", b"abd"));
    assert!(!ct_eq(b"abc", b"ab"));
    assert!(!ct_eq(b"ab", b"abc"));
}
