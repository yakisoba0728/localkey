//! Deterministic ECDSA (RFC 6979 A.2.5 / A.2.6 / A.2.7), verification, and signature
//! encodings.
//!
//! RFC 6979 has no secp256k1 or brainpool vectors. For those curves the key pairs are
//! published ones (the brainpool dA of RFC 7027 Appendix A.1 / A.2, the secp256k1 private
//! key of Wycheproof `ecdh_secp256k1_test.json` tcId 1), so the public-key derivation is
//! still a known answer; signing is checked by round trips and, for secp256k1, by the
//! Wycheproof `ecdsa_secp256k1_sha256_p1363_test.json` signatures.

use lk_crypto::{CryptoError, Curve, EcPrivateKey, EcdsaSignature, HashAlg, digest, ecdsa_verify_prehash};

use crate::common::hex;

struct Key {
    curve: Curve,
    hash: HashAlg,
    x: &'static str,
    ux: &'static str,
    uy: &'static str,
}

// RFC 6979 A.2.5 key pair (P-256).
const P256: Key = Key {
    curve: Curve::P256,
    hash: HashAlg::Sha256,
    x: "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
    ux: "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
    uy: "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
};

// RFC 6979 A.2.6 key pair (P-384).
const P384: Key = Key {
    curve: Curve::P384,
    hash: HashAlg::Sha384,
    x: "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8
        96D5724E4C70A825F872C9EA60D2EDF5",
    ux: "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64
         DEF8F0EA9055866064A254515480BC13",
    uy: "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1
         288B231C3AE0D4FE7344FD2533264720",
};

// RFC 6979 A.2.7 key pair (P-521); values are printed with 521 bits and are left-padded
// here to the 66-byte field length.
const P521: Key = Key {
    curve: Curve::P521,
    hash: HashAlg::Sha512,
    x: "00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C
        AA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538",
    ux: "01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD3
         71123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4",
    uy: "00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A2
         8A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5",
};

// secp256k1: d = 1, whose public key is the generator G published in SEC 2 v2 §2.4.1.
const SECP256K1: Key = Key {
    curve: Curve::Secp256k1,
    hash: HashAlg::Sha256,
    x: "0000000000000000000000000000000000000000000000000000000000000001",
    ux: "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
    uy: "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
};

// RFC 7027 Appendix A.1 dA, x_qA, y_qA (brainpoolP256r1).
const BP256: Key = Key {
    curve: Curve::BrainpoolP256r1,
    hash: HashAlg::Sha256,
    x: "81DB1EE100150FF2EA338D708271BE38300CB54241D79950F77B063039804F1D",
    ux: "44106E913F92BC02A1705D9953A8414DB95E1AAA49E81D9E85F929A8E3100BE5",
    uy: "8AB4846F11CACCB73CE49CBDD120F5A900A69FD32C272223F789EF10EB089BDC",
};

// RFC 7027 Appendix A.2 dA, x_qA, y_qA (brainpoolP384r1).
const BP384: Key = Key {
    curve: Curve::BrainpoolP384r1,
    hash: HashAlg::Sha384,
    x: "1E20F5E048A5886F1F157C74E91BDE2B98C8B52D58E5003D57053FC4B0BD65D6
        F15EB5D1EE1610DF870795143627D042",
    ux: "68B665DD91C195800650CDD363C625F4E742E8134667B767B1B476793588F885
         AB698C852D4A6E77A252D6380FCAF068",
    uy: "55BC91A39C9EC01DEE36017B7D673A931236D2F1F5C83942D049E3FA20607493
         E0D038FF2FD30C2AB67D15C85F7FAA59",
};

/// One key per curve, in `Curve::ALL` order.
const KEYS: [&Key; 6] = [&P256, &P384, &P521, &SECP256K1, &BP256, &BP384];

struct Vector {
    name: &'static str,
    key: &'static Key,
    message: &'static [u8],
    r: &'static str,
    s: &'static str,
}

const VECTORS: [Vector; 6] = [
    Vector {
        name: "A.2.5 SHA-256 \"sample\"",
        key: &P256,
        message: b"sample",
        r: "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
        s: "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
    },
    Vector {
        name: "A.2.5 SHA-256 \"test\"",
        key: &P256,
        message: b"test",
        r: "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
        s: "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083",
    },
    Vector {
        name: "A.2.6 SHA-384 \"sample\"",
        key: &P384,
        message: b"sample",
        r: "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C
            81A648152E44ACF96E36DD1E80FABE46",
        s: "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94F
            A329C145786E679E7B82C71A38628AC8",
    },
    Vector {
        name: "A.2.6 SHA-384 \"test\"",
        key: &P384,
        message: b"test",
        r: "8203B63D3C853E8D77227FB377BCF7B7B772E97892A80F36AB775D509D7A5FEB
            0542A7F0812998DA8F1DD3CA3CF023DB",
        s: "DDD0760448D42D8A43AF45AF836FCE4DE8BE06B485E9B61B827C2F13173923E0
            6A739F040649A667BF3B828246BAA5A5",
    },
    Vector {
        name: "A.2.7 SHA-512 \"sample\"",
        key: &P521,
        message: b"sample",
        r: "00C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F1
            74E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E377FA",
        s: "00617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF2
            82623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A67A",
    },
    Vector {
        name: "A.2.7 SHA-512 \"test\"",
        key: &P521,
        message: b"test",
        r: "013E99020ABF5CEE7525D16B69B229652AB6BDF2AFFCAEF38773B4B7D08725F10
            CDB93482FDCC54EDCEE91ECA4166B2A7C6265EF0CE2BD7051B7CEF945BABD47EE6D",
        s: "01FBD0013C674AA79CB39849527916CE301C66EA7CE8B80682786AD60F98F7E78
            A19CA69EFF5C57400E3B3A0AD66CE0978214D13BAF4E9AC60752F7B155E2DE4DCE3",
    },
];

fn private(key: &Key) -> EcPrivateKey {
    EcPrivateKey::from_scalar(key.curve, &hex(key.x)).unwrap()
}

fn public(key: &Key) -> Vec<u8> {
    [vec![0x04], hex(key.ux), hex(key.uy)].concat()
}

fn expected(vector: &Vector) -> EcdsaSignature {
    EcdsaSignature { r: hex(vector.r), s: hex(vector.s) }
}

#[test]
fn published_public_keys() {
    // RFC 6979 A.2.5-A.2.7, SEC 2 v2 §2.4.1 (G for d = 1), RFC 7027 A.1 / A.2.
    for (key, curve) in KEYS.iter().zip(Curve::ALL) {
        assert_eq!(key.curve, curve);
        assert_eq!(key.hash, curve.nonce_hash(), "{curve:?}");
        assert_eq!(private(key).public_uncompressed(), public(key), "{curve:?}");
        assert!(lk_crypto::ec_public_is_valid(curve, &public(key)), "{curve:?}");
    }
}

#[test]
fn rfc6979_sign_message_is_exact() {
    for vector in &VECTORS {
        let signature = private(vector.key).sign_message(vector.key.hash, vector.message).unwrap();
        assert_eq!(signature, expected(vector), "{}", vector.name);
    }
}

#[test]
fn rfc6979_sign_prehash_is_exact() {
    for vector in &VECTORS {
        let prehash = digest(vector.key.hash, vector.message);
        assert_eq!(private(vector.key).sign_prehash(&prehash).unwrap(), expected(vector), "{}", vector.name);
    }
}

#[test]
fn verify_accepts_der_and_raw() {
    for vector in &VECTORS {
        let key = vector.key;
        let prehash = digest(key.hash, vector.message);
        let signature = expected(vector);
        assert!(ecdsa_verify_prehash(key.curve, &public(key), &prehash, &signature.to_der()), "{} DER", vector.name);
        assert!(ecdsa_verify_prehash(key.curve, &public(key), &prehash, &signature.to_raw()), "{} raw", vector.name);
    }
}

#[test]
fn verify_rejects_modified_signatures() {
    for vector in &VECTORS {
        let key = vector.key;
        let point = public(key);
        let prehash = digest(key.hash, vector.message);
        let raw = expected(vector).to_raw();
        let len = key.curve.field_len();
        // One flipped bit at each end of r and s, in the raw form (a flipped DER byte
        // would mostly test the parser).
        for index in [0, len - 1, len, 2 * len - 1] {
            let mut bad = raw.clone();
            bad[index] ^= 0x01;
            assert!(!ecdsa_verify_prehash(key.curve, &point, &prehash, &bad), "{} byte {index}", vector.name);
        }
        // r = 0 or s = 0 is never valid (FIPS 186-5 §6.4.2 step 2).
        let zero = vec![0; len];
        let (r, s) = raw.split_at(len);
        assert!(!ecdsa_verify_prehash(key.curve, &point, &prehash, &[r, &zero].concat()), "{} s = 0", vector.name);
        assert!(!ecdsa_verify_prehash(key.curve, &point, &prehash, &[&zero, s].concat()), "{} r = 0", vector.name);
        // The DER form with a modified integer.
        let mut der = expected(vector).to_der();
        let last = der.len() - 1;
        der[last] ^= 0x01;
        assert!(!ecdsa_verify_prehash(key.curve, &point, &prehash, &der), "{} DER", vector.name);
        // Wrong lengths of raw form.
        assert!(!ecdsa_verify_prehash(key.curve, &point, &prehash, &raw[1..]), "{} short raw", vector.name);
        assert!(!ecdsa_verify_prehash(key.curve, &point, &prehash, &[raw.as_slice(), &[0]].concat()), "{}", vector.name);
        assert!(!ecdsa_verify_prehash(key.curve, &point, &prehash, &[]), "{} empty", vector.name);
    }
}

#[test]
fn verify_rejects_other_message_key_or_curve() {
    let vector = &VECTORS[0];
    let signature = expected(vector).to_der();
    let prehash = digest(HashAlg::Sha256, b"sample");
    let other = digest(HashAlg::Sha256, b"samplf");
    assert!(!ecdsa_verify_prehash(Curve::P256, &public(&P256), &other, &signature));
    // Same message, the other vector's signature.
    assert!(!ecdsa_verify_prehash(Curve::P256, &public(&P256), &prehash, &expected(&VECTORS[1]).to_der()));
    // Another public key.
    let other_key = EcPrivateKey::from_scalar(Curve::P256, &[0x11; 32]).unwrap().public_uncompressed();
    assert!(!ecdsa_verify_prehash(Curve::P256, &other_key, &prehash, &signature));
    // The point does not belong to the named curve, or is malformed.
    assert!(!ecdsa_verify_prehash(Curve::P384, &public(&P256), &prehash, &signature));
    let mut off_curve = public(&P256);
    off_curve[64] ^= 0x01;
    assert!(!ecdsa_verify_prehash(Curve::P256, &off_curve, &prehash, &signature));
}

#[test]
fn other_hash_curve_pairings_sign_and_verify() {
    // FIPS 186-5 §6.4.1: the digest is truncated to the order length, or used as an
    // integer when shorter. RFC 6979 publishes these pairings too, but our nonce uses
    // the curve's own hash for HMAC_DRBG, so only validity is checked here.
    for key in KEYS {
        for alg in [HashAlg::Sha1, HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512] {
            let signature = private(key).sign_message(alg, b"sample").unwrap();
            assert_eq!(signature.r.len(), key.curve.field_len());
            assert_eq!(signature.s.len(), key.curve.field_len());
            let prehash = digest(alg, b"sample");
            assert!(ecdsa_verify_prehash(key.curve, &public(key), &prehash, &signature.to_der()), "{:?} {alg:?}", key.curve);
            // Deterministic: the same input signs the same way.
            assert_eq!(private(key).sign_message(alg, b"sample").unwrap(), signature, "{:?} {alg:?}", key.curve);
        }
    }
}

#[test]
fn sign_prehash_rejects_an_empty_digest() {
    // RFC 6979 §2.3.2 bits2int is undefined for an empty string (and panicked before).
    for key in KEYS {
        assert_eq!(private(key).sign_prehash(&[]).unwrap_err(), CryptoError::InvalidInput, "{:?}", key.curve);
    }
}

#[test]
fn verify_rejects_an_empty_digest() {
    for vector in &VECTORS {
        let key = vector.key;
        let signature = expected(vector);
        assert!(!ecdsa_verify_prehash(key.curve, &public(key), &[], &signature.to_der()), "{}", vector.name);
        assert!(!ecdsa_verify_prehash(key.curve, &public(key), &[], &signature.to_raw()), "{}", vector.name);
    }
}

#[test]
fn short_digests_are_integers_not_left_aligned_bit_strings() {
    // FIPS 186-5 §6.4.1 / RFC 6979 §2.3.2: a digest shorter than the order is used as
    // an integer, i.e. it equals the same value left-padded with zero bytes.
    let key = private(&P384);
    let short = digest(HashAlg::Sha1, b"sample");
    let padded = [vec![0; 48 - short.len()], short.clone()].concat();
    let signature = key.sign_prehash(&short).unwrap();
    assert_eq!(key.sign_prehash(&padded).unwrap(), signature);
    assert!(ecdsa_verify_prehash(Curve::P384, &public(&P384), &padded, &signature.to_raw()));
}

#[test]
fn to_der_pads_high_bit_integers() {
    // X.690 §8.3.2: a positive INTEGER whose first content bit is set gets a 0x00 prefix.
    // A.2.5 "sample": both r and s start with a byte >= 0x80.
    let vector = &VECTORS[0];
    let der = expected(vector).to_der();
    let expected_der = [
        hex("3046 022100"),
        hex(vector.r),
        hex("022100"),
        hex(vector.s),
    ]
    .concat();
    assert_eq!(der, expected_der);

    // A.2.5 "test": r is padded, s (0x01 9F ..) is not.
    let vector = &VECTORS[1];
    let der = expected(vector).to_der();
    let expected_der = [hex("3045 022100"), hex(vector.r), hex("0220"), hex(vector.s)].concat();
    assert_eq!(der, expected_der);
}

#[test]
fn to_der_trims_leading_zero_bytes() {
    // X.690 §8.3.2: INTEGER content is minimal. Fixed-width r and s with leading zero
    // bytes shrink; a zero byte is kept when the next byte has its top bit set.
    let mut r = vec![0x00, 0x00, 0x01];
    r.extend([0x22; 29]);
    let mut s = vec![0x00, 0x80];
    s.extend([0x33; 30]);
    let signature = EcdsaSignature { r: r.clone(), s: s.clone() };
    // r: 30 content bytes. s: 0x80.. needs its zero byte back, so 32 content bytes.
    let expected_der = [hex("3042 021e"), r[2..].to_vec(), hex("0220"), s.clone()].concat();
    assert_eq!(signature.to_der(), expected_der);
    assert_eq!(signature.to_raw(), [r, s].concat());
}

#[test]
fn to_der_handles_short_and_zero_integers() {
    // Already-short r and s (fewer bytes than the field) and an all-zero value.
    let signature = EcdsaSignature { r: vec![0x01], s: vec![0x7f, 0xff] };
    assert_eq!(signature.to_der(), hex("3007 020101 02027fff"));
    let signature = EcdsaSignature { r: vec![0x00; 32], s: vec![0x80] };
    assert_eq!(signature.to_der(), hex("3007 020100 02020080"));
}

#[test]
fn to_der_of_short_values_verifies() {
    // Signatures whose r or s has a leading zero byte must DER-encode with a shorter
    // INTEGER and still verify. RFC 6979 makes the search below deterministic.
    let key = private(&P256);
    let point = public(&P256);
    let mut found = 0;
    for counter in 0u32..2048 {
        let message = counter.to_be_bytes();
        let signature = key.sign_message(HashAlg::Sha256, &message).unwrap();
        if signature.r[0] != 0 && signature.s[0] != 0 {
            continue;
        }
        let der = signature.to_der();
        assert!(der.len() < 2 + 2 * (2 + 33), "counter {counter}");
        let prehash = digest(HashAlg::Sha256, &message);
        assert!(ecdsa_verify_prehash(Curve::P256, &point, &prehash, &der), "counter {counter} DER");
        assert!(ecdsa_verify_prehash(Curve::P256, &point, &prehash, &signature.to_raw()), "counter {counter} raw");
        found += 1;
        if found == 3 {
            return;
        }
    }
    panic!("no signature with a leading zero byte found");
}

/// RFC 6979 A.2.5 / A.2.6 signatures for digests whose length differs from the order's.
/// Only verification is checked with them: verification does not depend on the nonce,
/// whereas `sign_prehash` derives its nonce with the curve's own hash (see its docs).
const OTHER_HASH_VECTORS: [(&Key, HashAlg, &[u8], &str, &str); 8] = [
    (&P256, HashAlg::Sha1, b"sample",
     "61340C88C3AAEBEB4F6D667F672CA9759A6CCAA9FA8811313039EE4A35471D32",
     "6D7F147DAC089441BB2E2FE8F7A3FA264B9C475098FDCF6E00D7C996E1B8B7EB"),
    (&P256, HashAlg::Sha1, b"test",
     "0CBCC86FD6ABD1D99E703E1EC50069EE5C0B4BA4B9AC60E409E8EC5910D81A89",
     "01B9D7B73DFAA60D5651EC4591A0136F87653E0FD780C3B1BC872FFDEAE479B1"),
    (&P256, HashAlg::Sha512, b"sample",
     "8496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F00",
     "2362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE"),
    (&P256, HashAlg::Sha512, b"test",
     "461D93F31B6540894788FD206C07CFA0CC35F46FA3C91816FFF1040AD1581A04",
     "39AF9F15DE0DB8D97E72719C74820D304CE5226E32DEDAE67519E840D1194E55"),
    (&P384, HashAlg::Sha1, b"sample",
     "EC748D839243D6FBEF4FC5C4859A7DFFD7F3ABDDF72014540C16D73309834FA37B9BA002899F6FDA3A4A9386790D4EB2",
     "A3BCFA947BEEF4732BF247AC17F71676CB31A847B9FF0CBC9C9ED4C1A5B3FACF26F49CA031D4857570CCB5CA4424A443"),
    (&P384, HashAlg::Sha1, b"test",
     "4BC35D3A50EF4E30576F58CD96CE6BF638025EE624004A1F7789A8B8E43D0678ACD9D29876DAF46638645F7F404B11C7",
     "D5A6326C494ED3FF614703878961C0FDE7B2C278F9A65FD8C4B7186201A2991695BA1C84541327E966FA7B50F7382282"),
    (&P384, HashAlg::Sha512, b"sample",
     "ED0959D5880AB2D869AE7F6C2915C6D60F96507F9CB3E047C0046861DA4A799CFE30F35CC900056D7C99CD7882433709",
     "512C8CCEEE3890A84058CE1E22DBC2198F42323CE8ACA9135329F03C068E5112DC7CC3EF3446DEFCEB01A45C2667FDD5"),
    (&P384, HashAlg::Sha512, b"test",
     "A0D5D090C9980FAF3C2CE57B7AE951D31977DD11C775D314AF55F76C676447D06FB6495CD21B4B6E340FC236584FB277",
     "976984E59B4C77B0E8E4460DCA3D9F20E07B9BB1F63BEEFAF576F6B2E8B224634A2092CD3792E0159AD9CEE37659C736"),
];

#[test]
fn rfc6979_other_hash_signatures_verify() {
    // FIPS 186-5 §6.4.2 step 3 (via §6.4.1): a longer digest is cut to its leftmost
    // order-length bits; a shorter one is used as an integer.
    for (key, alg, message, r, s) in OTHER_HASH_VECTORS {
        let name = format!("{:?} {alg:?} {:?}", key.curve, String::from_utf8_lossy(message));
        let signature = EcdsaSignature { r: hex(r), s: hex(s) };
        let prehash = digest(alg, message);
        let point = public(key);
        let len = key.curve.field_len();
        assert!(ecdsa_verify_prehash(key.curve, &point, &prehash, &signature.to_der()), "{name} DER");
        assert!(ecdsa_verify_prehash(key.curve, &point, &prehash, &signature.to_raw()), "{name} raw");
        if prehash.len() > len {
            // Leftmost bits only: the truncated digest is equivalent, the rightmost is not.
            assert!(ecdsa_verify_prehash(key.curve, &point, &prehash[..len], &signature.to_raw()), "{name} left");
            let right = &prehash[prehash.len() - len..];
            assert!(!ecdsa_verify_prehash(key.curve, &point, right, &signature.to_raw()), "{name} right");
        } else {
            // An integer, not a left-aligned bit string: zero bytes go in front, not behind.
            let front = [vec![0; len - prehash.len()], prehash.clone()].concat();
            let behind = [prehash.clone(), vec![0; len - prehash.len()]].concat();
            assert!(ecdsa_verify_prehash(key.curve, &point, &front, &signature.to_raw()), "{name} front");
            assert!(!ecdsa_verify_prehash(key.curve, &point, &behind, &signature.to_raw()), "{name} behind");
        }
    }
}

#[test]
fn long_digests_are_truncated_before_signing() {
    // FIPS 186-5 §6.4.1 step 4 and RFC 6979 §2.3.2 (bits2int) both keep the leftmost
    // order-length bits, so z and the nonce match those of the truncated digest. For
    // P-521 the leftmost 521 bits of the 66-byte prefix are those of the whole input.
    for key in KEYS {
        let len = key.curve.field_len();
        let prehash = [digest(HashAlg::Sha512, b"sample"), digest(HashAlg::Sha512, b"test")].concat();
        let signature = private(key).sign_prehash(&prehash).unwrap();
        assert_eq!(private(key).sign_prehash(&prehash[..len]).unwrap(), signature, "{:?}", key.curve);
        assert!(ecdsa_verify_prehash(key.curve, &public(key), &prehash, &signature.to_der()), "{:?}", key.curve);
    }
}

#[test]
fn any_nonempty_digest_length_signs_and_verifies() {
    // Lengths around every field size, SHA-1's 20 bytes, and far beyond SHA-512's 64.
    for key in KEYS {
        for len in [1, 2, 16, 20, 31, 32, 33, 47, 48, 49, 64, 65, 66, 67, 128] {
            let prehash: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37).wrapping_add(0x5a)).collect();
            let signature = private(key).sign_prehash(&prehash).unwrap();
            assert!(ecdsa_verify_prehash(key.curve, &public(key), &prehash, &signature.to_der()), "{:?} {len}", key.curve);
        }
    }
}

#[test]
fn verify_requires_an_uncompressed_point() {
    // Same rule as `ec_public_is_valid` and `ecdh`: SEC 1 v2 §2.3.3 uncompressed form only.
    let vector = &VECTORS[0];
    let signature = expected(vector).to_der();
    let prehash = digest(HashAlg::Sha256, vector.message);
    let full = public(&P256);
    let y_is_odd = full[64] & 1;
    let compressed = [vec![0x02 | y_is_odd], full[1..33].to_vec()].concat();
    let mut hybrid = full.clone();
    hybrid[0] = 0x06 | y_is_odd;
    assert!(ecdsa_verify_prehash(Curve::P256, &full, &prehash, &signature));
    assert!(!ecdsa_verify_prehash(Curve::P256, &compressed, &prehash, &signature), "compressed");
    assert!(!ecdsa_verify_prehash(Curve::P256, &hybrid, &prehash, &signature), "hybrid");
    assert!(!ecdsa_verify_prehash(Curve::P256, &[0x00], &prehash, &signature), "identity");
}

#[test]
fn to_der_uses_long_form_lengths() {
    // X.690 §8.1.3.5: lengths of 128 or more use 0x80 | n followed by n length octets.
    let signature = EcdsaSignature { r: vec![0x01; 200], s: vec![0x01] };
    let der = signature.to_der();
    assert_eq!(der[..6], hex("3081ce 0281c8"));
    assert_eq!(der.len(), 3 + 206);

    // 70000 = 0x011170 needs three length octets; the sequence body is 70008 = 0x011178.
    let signature = EcdsaSignature { r: vec![0x01; 70000], s: vec![0x01] };
    let der = signature.to_der();
    assert_eq!(der[..10], hex("3083011178 0283011170"));
    assert_eq!(der.len(), 5 + 70008);
    assert_eq!(der[der.len() - 3..], hex("020101"));
}

/// Hedged signing (RFC 6979 §3.6 with host entropy as k') must verify and must differ
/// between two signatures of the same digest when the entropy differs.
#[test]
fn hedged_signatures_verify_and_vary() {
    struct Counter(u8);
    impl lk_core::Entropy for Counter {
        fn fill(&mut self, out: &mut [u8]) {
            for b in out {
                self.0 = self.0.wrapping_add(1);
                *b = self.0;
            }
        }
    }
    for curve in [lk_crypto::Curve::P256, lk_crypto::Curve::P384] {
        let mut entropy = Counter(7);
        let key = lk_crypto::EcPrivateKey::generate(curve, &mut entropy);
        let digest = lk_crypto::sha256(b"hedged");
        let a = key.sign_prehash_hedged(&digest, &mut entropy).expect("sign");
        let b = key.sign_prehash_hedged(&digest, &mut entropy).expect("sign");
        assert_ne!(a, b);
        let point = key.public_uncompressed();
        assert!(lk_crypto::ecdsa_verify_prehash(curve, &point, &digest, &a.to_der()));
        assert!(lk_crypto::ecdsa_verify_prehash(curve, &point, &digest, &b.to_raw()));
        assert!(key.sign_prehash_hedged(&[], &mut entropy).is_err());
    }
}

/// RFC 6979 A.2.7 signatures with the other hashes; as for `OTHER_HASH_VECTORS`, only
/// verification is checked because `sign_prehash` uses SHA-512 for P-521's nonce.
const P521_OTHER_HASH_VECTORS: [(HashAlg, &[u8], &str, &str); 6] = [
    (HashAlg::Sha1, b"sample",
     "00343B6EC45728975EA5CBA6659BBB6062A5FF89EEA58BE3C80B619F322C87910FE092F7D45BB0F8EEE01ED3F20BABEC079D202AE677B243AB40B5431D497C55D75D",
     "00E7B0E675A9B24413D448B8CC119D2BF7B2D2DF032741C096634D6D65D0DBE3D5694625FB9E8104D3B842C1B0E2D0B98BEA19341E8676AEF66AE4EBA3D5475D5D16"),
    (HashAlg::Sha256, b"sample",
     "01511BB4D675114FE266FC4372B87682BAECC01D3CC62CF2303C92B3526012659D16876E25C7C1E57648F23B73564D67F61C6F14D527D54972810421E7D87589E1A7",
     "004A171143A83163D6DF460AAF61522695F207A58B95C0644D87E52AA1A347916E4F7A72930B1BC06DBE22CE3F58264AFD23704CBB63B29B931F7DE6C9D949A7ECFC"),
    (HashAlg::Sha384, b"sample",
     "01EA842A0E17D2DE4F92C15315C63DDF72685C18195C2BB95E572B9C5136CA4B4B576AD712A52BE9730627D16054BA40CC0B8D3FF035B12AE75168397F5D50C67451",
     "01F21A3CEE066E1961025FB048BD5FE2B7924D0CD797BABE0A83B66F1E35EEAF5FDE143FA85DC394A7DEE766523393784484BDF3E00114A1C857CDE1AA203DB65D61"),
    (HashAlg::Sha1, b"test",
     "013BAD9F29ABE20DE37EBEB823C252CA0F63361284015A3BF430A46AAA80B87B0693F0694BD88AFE4E661FC33B094CD3B7963BED5A727ED8BD6A3A202ABE009D0367",
     "01E9BB81FF7944CA409AD138DBBEE228E1AFCC0C890FC78EC8604639CB0DBDC90F717A99EAD9D272855D00162EE9527567DD6A92CBD629805C0445282BBC916797FF"),
    (HashAlg::Sha256, b"test",
     "000E871C4A14F993C6C7369501900C4BC1E9C7B0B4BA44E04868B30B41D8071042EB28C4C250411D0CE08CD197E4188EA4876F279F90B3D8D74A3C76E6F1E4656AA8",
     "00CD52DBAA33B063C3A6CD8058A1FB0A46A4754B034FCC644766CA14DA8CA5CA9FDE00E88C1AD60CCBA759025299079D7A427EC3CC5B619BFBC828E7769BCD694E86"),
    (HashAlg::Sha384, b"test",
     "014BEE21A18B6D8B3C93FAB08D43E739707953244FDBE924FA926D76669E7AC8C89DF62ED8975C2D8397A65A49DCC09F6B0AC62272741924D479354D74FF6075578C",
     "0133330865C067A0EAF72362A65E2D7BC4E461E8C8995C3B6226A21BD1AA78F0ED94FE536A0DCA35534F0CD1510C41525D163FE9D74D134881E35141ED5E8E95B979"),
];

#[test]
fn rfc6979_p521_other_hash_signatures_verify_with_bit_level_truncation() {
    // FIPS 186-5 §6.4.2 step 3: the digest is cut to the leftmost 521 bits, not bytes.
    // Zero bytes in front keep the integer while the input stays within 65 bytes (520
    // bits); at 66 bytes (528 bits) the value is shifted right by 7 and no longer verifies.
    let point = public(&P521);
    for (alg, message, r, s) in P521_OTHER_HASH_VECTORS {
        let name = format!("{alg:?} {:?}", String::from_utf8_lossy(message));
        let signature = EcdsaSignature { r: hex(r), s: hex(s) };
        let prehash = digest(alg, message);
        assert!(ecdsa_verify_prehash(Curve::P521, &point, &prehash, &signature.to_der()), "{name} DER");
        assert!(ecdsa_verify_prehash(Curve::P521, &point, &prehash, &signature.to_raw()), "{name} raw");
        let to_65 = [vec![0; 65 - prehash.len()], prehash.clone()].concat();
        let to_66 = [vec![0; 66 - prehash.len()], prehash.clone()].concat();
        assert!(ecdsa_verify_prehash(Curve::P521, &point, &to_65, &signature.to_raw()), "{name} 65 bytes");
        assert!(!ecdsa_verify_prehash(Curve::P521, &point, &to_66, &signature.to_raw()), "{name} 66 bytes");
    }
    // The SHA-512 vector likewise, and a signature of the shifted value is a different one.
    let key = private(&P521);
    let sha512 = digest(HashAlg::Sha512, b"sample");
    let to_66 = [vec![0, 0], sha512.clone()].concat();
    assert_ne!(key.sign_prehash(&to_66).unwrap(), key.sign_prehash(&sha512).unwrap());
    assert_eq!(key.sign_prehash(&sha512).unwrap(), expected(&VECTORS[4]));
}

/// Project Wycheproof `testvectors_v1/ecdsa_secp256k1_sha256_p1363_test.json`, test
/// group 0 (raw `r || s`, SHA-256 of `msg`).
const WYCHEPROOF_K1_PUBLIC: &str = "04b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f
                                      f0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9";

const WYCHEPROOF_K1: [(u32, &str, &str, bool); 4] = [
    // "signature malleability": s > n/2, valid ECDSA (Wycheproof result "valid").
    (1, "313233343030",
     "813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f87",
     true),
    // "Edge case for Shamir multiplication": low s, valid.
    (60, "3235353835",
     "dd1b7d09a7bd8218961034a39a87fecf5314f00c4d25eb58a07ac85e85eab51635138c401ef8d3493d65c9002fe62b43aee568731b744548358996d9cc427e06",
     true),
    // "replaced r by n - r": invalid.
    (4, "313233343030",
     "7ec10863310565a908457fa0f1b87a79bc4fcf10b9e0e4320ac021c106b31ddc6ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba",
     false),
    // "r=0 and s=n - 1": invalid.
    (14, "313233343030",
     "0000000000000000000000000000000000000000000000000000000000000000fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
     false),
];

#[test]
fn wycheproof_secp256k1_signatures() {
    // SEC 1 v2 §4.1.4 has no low-S rule, so the high-S case 1 is accepted like case 60.
    let point = hex(WYCHEPROOF_K1_PUBLIC);
    assert!(lk_crypto::ec_public_is_valid(Curve::Secp256k1, &point));
    for (tc_id, msg, sig, valid) in WYCHEPROOF_K1 {
        let prehash = digest(HashAlg::Sha256, &hex(msg));
        let raw = hex(sig);
        assert_eq!(ecdsa_verify_prehash(Curve::Secp256k1, &point, &prehash, &raw), valid, "tcId {tc_id} raw");
        let (r, s) = raw.split_at(32);
        let der = EcdsaSignature { r: r.to_vec(), s: s.to_vec() }.to_der();
        assert_eq!(ecdsa_verify_prehash(Curve::Secp256k1, &point, &prehash, &der), valid, "tcId {tc_id} DER");
    }
}

#[test]
fn secp256k1_signatures_are_low_s() {
    // k256 normalises s to at most n/2 (model policy, see `EcPrivateKey::sign_prehash`).
    const HALF_N: &str = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0";
    let half = hex(HALF_N);
    let key = private(&SECP256K1);
    let mut entropy = crate::common::CounterEntropy::new(b"low s");
    for counter in 0u32..64 {
        let message = counter.to_be_bytes();
        let deterministic = key.sign_message(HashAlg::Sha256, &message).unwrap();
        let hedged = key.sign_message_hedged(HashAlg::Sha256, &message, &mut entropy).unwrap();
        for signature in [deterministic, hedged] {
            assert!(signature.s.as_slice() <= half.as_slice(), "counter {counter}");
            let prehash = digest(HashAlg::Sha256, &message);
            assert!(ecdsa_verify_prehash(Curve::Secp256k1, &public(&SECP256K1), &prehash, &signature.to_raw()));
        }
    }
}

#[test]
fn high_and_low_s_verify_on_every_curve() {
    // (r, s) and (r, n - s) are both valid SEC 1 signatures; verification accepts both
    // whichever form the signer produced.
    let orders = [
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
        "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7",
        "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565",
    ];
    for (key, order) in KEYS.iter().zip(orders) {
        let prehash = digest(key.hash, b"negate s");
        let signature = private(key).sign_prehash(&prehash).unwrap();
        let negated = EcdsaSignature { r: signature.r.clone(), s: sub(&hex(order), &signature.s) };
        for form in [&signature, &negated] {
            assert!(ecdsa_verify_prehash(key.curve, &public(key), &prehash, &form.to_raw()), "{:?}", key.curve);
            assert!(ecdsa_verify_prehash(key.curve, &public(key), &prehash, &form.to_der()), "{:?}", key.curve);
        }
    }
}

/// `a - b` for big-endian values of the same length, `a >= b`.
fn sub(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = vec![0; a.len()];
    let mut borrow = 0i16;
    for i in (0..a.len()).rev() {
        let diff = i16::from(a[i]) - i16::from(b[i]) - borrow;
        out[i] = diff.rem_euclid(256) as u8;
        borrow = i16::from(diff < 0);
    }
    out
}

#[test]
fn hedged_signatures_verify_and_vary_on_every_curve() {
    let mut entropy = crate::common::CounterEntropy::new(b"hedged");
    for curve in Curve::ALL {
        let key = EcPrivateKey::generate(curve, &mut entropy);
        let prehash = digest(curve.nonce_hash(), b"hedged");
        let a = key.sign_prehash_hedged(&prehash, &mut entropy).unwrap();
        let b = key.sign_prehash_hedged(&prehash, &mut entropy).unwrap();
        assert_ne!(a, b, "{curve:?}");
        assert_eq!(a.r.len(), curve.field_len());
        assert_eq!(a.s.len(), curve.field_len());
        let point = key.public_uncompressed();
        assert!(ecdsa_verify_prehash(curve, &point, &prehash, &a.to_der()), "{curve:?}");
        assert!(ecdsa_verify_prehash(curve, &point, &prehash, &b.to_raw()), "{curve:?}");
        // A signature from one curve's key does not verify under another curve's key.
        for other in Curve::ALL {
            if other != curve && other.field_len() == curve.field_len() {
                let other_key = EcPrivateKey::generate(other, &mut entropy);
                assert!(!ecdsa_verify_prehash(other, &other_key.public_uncompressed(), &prehash, &a.to_raw()));
            }
        }
    }
}

/// The leftmost 521 bits of `bytes` (at least 66 bytes) as a 66-byte big-endian integer,
/// computed test-side with plain shifts (FIPS 186-5 §6.4.1 step 4).
fn leftmost_521_bits(bytes: &[u8]) -> Vec<u8> {
    let head = &bytes[..66];
    (0..66).map(|i| (if i == 0 { 0 } else { head[i - 1] << 1 }) | (head[i] >> 7)).collect()
}

#[test]
fn p521_long_digests_truncate_to_521_bits() {
    // A 128-byte digest whose first bit is clear: its leftmost 521 bits fit in 65 bytes,
    // an input that needs no truncation. FIPS 186-5 §6.4.1 gives both the same z and
    // RFC 6979 §2.3.4 (bits2octets) the same nonce, so the signatures are identical.
    let key = private(&P521);
    let point = public(&P521);
    let long: Vec<u8> = [vec![0x3C], digest(HashAlg::Sha512, b"long"), digest(HashAlg::Sha512, b"digest")]
        .concat()[..128]
        .to_vec();
    let truncated = leftmost_521_bits(&long);
    assert_eq!(truncated[0], 0);
    let short = &truncated[1..];
    let signature = key.sign_prehash(&long).unwrap();
    assert_eq!(key.sign_prehash(short).unwrap(), signature);
    assert_eq!(key.sign_prehash(&long[..66]).unwrap(), signature);
    for input in [&long[..], short, &long[..66], &long[..100]] {
        assert!(ecdsa_verify_prehash(Curve::P521, &point, input, &signature.to_raw()), "{}", input.len());
        assert!(ecdsa_verify_prehash(Curve::P521, &point, input, &signature.to_der()), "{}", input.len());
    }
    // The low-bits reading of the first 66 bytes (what `ecdsa` 0.17 alone would use) is
    // a different integer and must not verify.
    let mut low_bits = long[..66].to_vec();
    low_bits[0] &= 0x01;
    assert!(!ecdsa_verify_prehash(Curve::P521, &point, &low_bits, &signature.to_raw()));
    // The hedged path draws the same 66 bytes of k' for both inputs and agrees as well.
    let script = || crate::common::ScriptedEntropy::new(vec![vec![0xA5; 66]]);
    let hedged_long = key.sign_prehash_hedged(&long, &mut script()).unwrap();
    let hedged_short = key.sign_prehash_hedged(short, &mut script()).unwrap();
    assert_eq!(hedged_long, hedged_short);
    assert_ne!(hedged_long, signature);
    assert!(ecdsa_verify_prehash(Curve::P521, &point, &long, &hedged_long.to_raw()));
}

#[test]
fn p521_digests_differing_beyond_bit_521_sign_identically() {
    // Bits after the 521st are discarded, so they cannot change the signature. (With
    // `z` from the low 521 bits but the nonce from the high 521 bits, these inputs would
    // share a nonce and differ in z, which reveals the private key.)
    let key = private(&P521);
    let point = public(&P521);
    for seed in [b"one".as_slice(), b"two", b"three"] {
        let base = [digest(HashAlg::Sha512, seed), digest(HashAlg::Sha256, seed)].concat()[..66].to_vec();
        let mut beyond = base.clone();
        beyond[65] ^= 0x7F;
        let mut inside = base.clone();
        inside[65] ^= 0x80;
        let signature = key.sign_prehash(&base).unwrap();
        assert_eq!(key.sign_prehash(&beyond).unwrap(), signature);
        let other = key.sign_prehash(&inside).unwrap();
        assert_ne!(other.r, signature.r);
        assert!(ecdsa_verify_prehash(Curve::P521, &point, &beyond, &signature.to_raw()));
        assert!(!ecdsa_verify_prehash(Curve::P521, &point, &inside, &signature.to_raw()));
        assert!(ecdsa_verify_prehash(Curve::P521, &point, &inside, &other.to_raw()));
    }
}
