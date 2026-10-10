//! Published test vectors through the YKOATH CALCULATE / CALCULATE ALL commands.
//!
//! - RFC 4226 Appendix D: HMAC-SHA-1 values, truncated values and HOTP codes for the
//!   secret "12345678901234567890", counters 0..=9.
//! - RFC 6238 Appendix B: the 18 TOTP values for SHA-1/SHA-256/SHA-512 with the seeds
//!   of Appendix A (20, 32 and 64 ASCII bytes), X = 30, T0 = 0, 8 digits.

#![allow(clippy::unwrap_used)]

mod common;

use common::*;

/// RFC 4226 Appendix D, columns "HMAC-SHA-1(secret, count)", "Truncated (Dec)" and
/// "HOTP".
const RFC4226_APPENDIX_D: [(&str, u32, u32); 10] = [
    ("cc93cf18508d94934c64b65d8ba7667fb7cde4b0", 1_284_755_224, 755_224),
    ("75a48a19d4cbe100644e8ac1397eea747a2d33ab", 1_094_287_082, 287_082),
    ("0bacb7fa082fef30782211938bc1c5e70416ff44", 137_359_152, 359_152),
    ("66c28227d03a2d5529262ff016a1e6ef76557ece", 1_726_969_429, 969_429),
    ("a904c900a64b35909874b33e61c5938a8e15ed1c", 1_640_338_314, 338_314),
    ("a37e783d7b7233c083d4f62926c7a25f238d0316", 868_254_676, 254_676),
    ("bc9cd28561042c83f219324d3c607256c03272ae", 1_918_287_922, 287_922),
    ("a4fb960c0bc06e1eabb804e5b397cdc4b45596fa", 82_162_583, 162_583),
    ("1b3c89f65e6c9e883012052823443f048b4332db", 673_399_871, 399_871),
    ("1637409809a679dc698207310c8c7fc07290d9e5", 645_520_489, 520_489),
];

/// RFC 6238 Appendix A seeds.
const SEED_SHA1: &[u8] = b"12345678901234567890";
const SEED_SHA256: &[u8] = b"12345678901234567890123456789012";
const SEED_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

/// RFC 6238 Appendix B: (time, T, SHA-1, SHA-256, SHA-512).
const RFC6238_APPENDIX_B: [(u64, u64, u32, u32, u32); 6] = [
    (59, 0x1, 94_287_082, 46_119_246, 90_693_936),
    (1_111_111_109, 0x23523EC, 7_081_804, 68_084_774, 25_091_201),
    (1_111_111_111, 0x23523ED, 14_050_471, 67_062_674, 99_943_326),
    (1_234_567_890, 0x273EF07, 89_005_924, 91_819_424, 93_441_116),
    (2_000_000_000, 0x3F940AA, 69_279_037, 90_698_825, 38_618_901),
    (20_000_000_000, 0x27BC86AA, 65_353_130, 77_737_706, 47_863_826),
];

/// RFC 4226 Appendix D through truncated CALCULATE: digits, truncated value and HOTP
/// code for counters 0..=9; the counter advances once per CALCULATE.
#[test]
fn rfc4226_appendix_d_truncated() {
    let mut card = Card::new();
    assert_eq!(card.put(&put_data(b"hotp", HOTP | SHA1, 6, RFC_SECRET, None, None)), OK);
    for (count, (_, truncated, hotp)) in RFC4226_APPENDIX_D.iter().enumerate() {
        // Clients send an empty challenge for HOTP (it is ignored).
        let value = card.calc_truncated(b"hotp", &[]).unwrap();
        assert_eq!(value[0], 6, "digits, count {count}");
        assert_eq!(u32::from_be_bytes([value[1], value[2], value[3], value[4]]), *truncated, "count {count}");
        assert_eq!(code_of(&value), *hotp, "count {count}");
    }
}

/// RFC 4226 Appendix D through full CALCULATE (P2 = 00): the response is digits then
/// the whole HMAC-SHA-1 value of the table.
#[test]
fn rfc4226_appendix_d_full_hmac() {
    let mut card = Card::new();
    assert_eq!(card.put(&put_data(b"hotp", HOTP | SHA1, 6, RFC_SECRET, None, None)), OK);
    for (count, (mac, _, _)) in RFC4226_APPENDIX_D.iter().enumerate() {
        // A non-empty challenge is ignored for HOTP as well.
        let value = card.calc_full(b"hotp", &[0xAA; 8]).unwrap();
        assert_eq!(value[0], 6);
        assert_eq!(value[1..], hex(mac)[..], "count {count}");
    }
}

/// RFC 4226 Appendix D with the challenge field left out entirely (HOTP ignores it).
#[test]
fn rfc4226_hotp_without_challenge_field() {
    let mut card = Card::new();
    assert_eq!(card.put(&put_data(b"hotp", HOTP | SHA1, 6, RFC_SECRET, None, None)), OK);
    let resp = card.send(&apdu(0x00, 0xA2, 0x00, 0x01, &tlv(0x71, b"hotp")));
    assert_eq!(code_of(&expect_object(&resp, 0x76).unwrap()), 755_224);
}

/// All 18 RFC 6238 Appendix B vectors through truncated CALCULATE. The challenge is
/// the 8-byte big-endian T = floor(time / 30) (RFC 6238 §4.2).
#[test]
fn rfc6238_appendix_b_all_18_vectors() {
    let mut card = Card::new();
    assert_eq!(card.put(&put_data(b"sha1", TOTP | SHA1, 8, SEED_SHA1, None, None)), OK);
    assert_eq!(card.put(&put_data(b"sha256", TOTP | SHA256, 8, SEED_SHA256, None, None)), OK);
    assert_eq!(card.put(&put_data(b"sha512", TOTP | SHA512, 8, SEED_SHA512, None, None)), OK);
    let mut checked = 0;
    for (time, t, sha1, sha256, sha512) in RFC6238_APPENDIX_B {
        assert_eq!(time / 30, t);
        let challenge = t.to_be_bytes();
        assert_eq!(card.code(b"sha1", &challenge), sha1, "SHA-1 at {time}");
        assert_eq!(card.code(b"sha256", &challenge), sha256, "SHA-256 at {time}");
        assert_eq!(card.code(b"sha512", &challenge), sha512, "SHA-512 at {time}");
        checked += 3;
    }
    assert_eq!(checked, 18);
}

/// RFC 6238 Appendix B through full CALCULATE: the response carries the whole HMAC,
/// checked against an independent HMAC (lk-crypto, RFC 2104) and against the RFC
/// value after the client applies RFC 4226 §5.3 truncation itself.
#[test]
fn rfc6238_full_response_is_independent_hmac() {
    let mut card = Card::new();
    let creds: [(&[u8], u8, &[u8], lk_crypto::HashAlg); 3] = [
        (b"sha1", SHA1, SEED_SHA1, lk_crypto::HashAlg::Sha1),
        (b"sha256", SHA256, SEED_SHA256, lk_crypto::HashAlg::Sha256),
        (b"sha512", SHA512, SEED_SHA512, lk_crypto::HashAlg::Sha512),
    ];
    for (name, alg, seed, _) in creds {
        assert_eq!(card.put(&put_data(name, TOTP | alg, 8, seed, None, None)), OK);
    }
    for (time, t, sha1, sha256, sha512) in RFC6238_APPENDIX_B {
        let challenge = t.to_be_bytes();
        for ((name, _, seed, hash), expected) in creds.iter().zip([sha1, sha256, sha512]) {
            let value = card.calc_full(name, &challenge).unwrap();
            assert_eq!(value[0], 8);
            let mac = &value[1..];
            assert_eq!(mac, &lk_crypto::hmac(*hash, seed, &challenge)[..], "{time}");
            let offset = usize::from(mac[mac.len() - 1] & 0x0F);
            let snum = u32::from_be_bytes([mac[offset] & 0x7F, mac[offset + 1], mac[offset + 2], mac[offset + 3]]);
            assert_eq!(snum % 100_000_000, expected, "{time}");
        }
    }
}

/// HOTP with SHA-256 and SHA-512 (no published vectors): the truncated CALCULATE
/// equals RFC 4226 §5.3 applied to an independent HMAC over the 8-byte counter.
#[test]
fn hotp_sha256_sha512_match_independent_hmac() {
    let mut card = Card::new();
    assert_eq!(card.put(&put_data(b"h256", HOTP | SHA256, 8, SEED_SHA256, None, None)), OK);
    assert_eq!(card.put(&put_data(b"h512", HOTP | SHA512, 7, SEED_SHA512, None, Some(1000))), OK);
    for step in 0..5u64 {
        let mac = lk_crypto::hmac(lk_crypto::HashAlg::Sha256, SEED_SHA256, &step.to_be_bytes());
        let value = card.calc_truncated(b"h256", &[]).unwrap();
        assert_eq!(value[1..], truncate(&mac)[..]);
        let mac = lk_crypto::hmac(lk_crypto::HashAlg::Sha512, SEED_SHA512, &(1000 + step).to_be_bytes());
        let value = card.calc_full(b"h512", &[]).unwrap();
        assert_eq!(value[0], 7);
        assert_eq!(value[1..], mac[..]);
    }
}

/// CALCULATE ALL with the three RFC 6238 seeds at T = 0x23523EC (time 1111111109):
/// truncated `76` and full `75` objects in list order.
#[test]
fn rfc6238_through_calculate_all() {
    let mut card = Card::new();
    assert_eq!(card.put(&put_data(b"sha1", TOTP | SHA1, 8, SEED_SHA1, None, None)), OK);
    assert_eq!(card.put(&put_data(b"sha256", TOTP | SHA256, 8, SEED_SHA256, None, None)), OK);
    assert_eq!(card.put(&put_data(b"sha512", TOTP | SHA512, 8, SEED_SHA512, None, None)), OK);
    let challenge = 0x23523ECu64.to_be_bytes();

    let (data, sw) = card.send_all(&calculate_all_apdu(&challenge, true));
    assert_eq!(sw, OK);
    let fields = parse_tlvs(&data);
    let expected: [(&[u8], u32); 3] = [(b"sha1", 7_081_804), (b"sha256", 68_084_774), (b"sha512", 25_091_201)];
    assert_eq!(fields.len(), 6);
    for (pair, (name, code)) in fields.chunks(2).zip(expected) {
        assert_eq!(pair[0], (0x71, name.to_vec()));
        assert_eq!(pair[1].0, 0x76);
        assert_eq!(code_of(&pair[1].1), code);
    }

    let (data, sw) = card.send_all(&calculate_all_apdu(&challenge, false));
    assert_eq!(sw, OK);
    let fields = parse_tlvs(&data);
    assert_eq!(fields[1].0, 0x75);
    assert_eq!(fields[1].1[1..], lk_crypto::hmac(lk_crypto::HashAlg::Sha1, SEED_SHA1, &challenge)[..]);
    assert_eq!(fields[5].1.len(), 1 + 64);
}

/// RFC 2104 §2: keys longer than the block size are hashed. A 100-byte SHA-1 key and a
/// 200-byte SHA-512 key give the same MAC as HMAC with the long key, and as the
/// client-shortened key.
#[test]
fn long_keys_are_shortened_per_rfc2104() {
    let mut card = Card::new();
    let long1: Vec<u8> = (0..100u8).collect();
    let long512: Vec<u8> = (0..200u8).collect();
    assert_eq!(card.put(&put_data(b"raw1", TOTP | SHA1, 6, &long1, None, None)), OK);
    assert_eq!(card.put(&put_data(b"pre1", TOTP | SHA1, 6, &client_secret(&long1, SHA1), None, None)), OK);
    assert_eq!(card.put(&put_data(b"raw512", TOTP | SHA512, 6, &long512, None, None)), OK);
    let challenge = 7u64.to_be_bytes();
    let raw = card.calc_full(b"raw1", &challenge).unwrap();
    let pre = card.calc_full(b"pre1", &challenge).unwrap();
    assert_eq!(raw, pre);
    assert_eq!(raw[1..], lk_crypto::hmac(lk_crypto::HashAlg::Sha1, &long1, &challenge)[..]);
    let raw = card.calc_full(b"raw512", &challenge).unwrap();
    assert_eq!(raw[1..], lk_crypto::hmac(lk_crypto::HashAlg::Sha512, &long512, &challenge)[..]);
}

/// RFC 4226 §5.3 dynamic truncation, written independently for the tests.
fn truncate(mac: &[u8]) -> [u8; 4] {
    let offset = usize::from(mac[mac.len() - 1] & 0x0F);
    [mac[offset] & 0x7F, mac[offset + 1], mac[offset + 2], mac[offset + 3]]
}
