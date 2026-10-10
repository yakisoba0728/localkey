//! SHA-1 and SHA-2 (FIPS 180-4).
//!
//! "abc" and the 448-bit message are the examples published by NIST CSRC ("Examples
//! with Intermediate Values", SHA1.pdf / SHA256.pdf) and in FIPS 180-2 Appendices A–C.
//! For SHA-384/512 NIST's two-block example is the 896-bit message (FIPS 180-2
//! Appendices C.2 / D.2); the 448-bit digests for those two are the widely republished
//! values (e.g. di-mgt.com.au SHA test vectors), cross-checked with an independent
//! implementation (Python hashlib).

use lk_crypto::{HashAlg, Hasher, digest, sha1, sha256, sha384, sha512};

use crate::common::hex;

const ABC: &[u8] = b"abc";
const MSG_448: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
const MSG_896: &[u8] = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

#[test]
fn messages_have_the_published_lengths() {
    assert_eq!(MSG_448.len() * 8, 448);
    assert_eq!(MSG_896.len() * 8, 896);
}

#[test]
fn sha1_fips_180_examples() {
    // FIPS 180-2 Appendix A.1 (one block) and A.2 (two blocks).
    assert_eq!(sha1(ABC).to_vec(), hex("a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d"));
    assert_eq!(sha1(MSG_448).to_vec(), hex("84983e44 1c3bd26e baae4aa1 f95129e5 e54670f1"));
}

#[test]
fn sha256_fips_180_examples() {
    // FIPS 180-2 Appendix B.1 and B.2.
    assert_eq!(
        sha256(ABC).to_vec(),
        hex("ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad")
    );
    assert_eq!(
        sha256(MSG_448).to_vec(),
        hex("248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1")
    );
}

#[test]
fn sha384_fips_180_examples() {
    // FIPS 180-2 Appendix D.1 ("abc") and D.2 (896-bit message).
    assert_eq!(
        sha384(ABC).to_vec(),
        hex("cb00753f45a35e8b b5a03d699ac65007 272c32ab0eded163 1a8b605a43ff5bed
             8086072ba1e7cc23 58baeca134c825a7")
    );
    assert_eq!(
        sha384(MSG_896).to_vec(),
        hex("09330c33f71147e8 3d192fc782cd1b47 53111b173b3b05d2 2fa08086e3b0f712
             fcc7c71a557e2db9 66c3e9fa91746039")
    );
    // 448-bit message: republished value, cross-checked (see module docs).
    assert_eq!(
        sha384(MSG_448).to_vec(),
        hex("3391fdddfc8dc739 3707a65b1b470939 7cf8b1d162af05ab fe8f450de5f36bc6
             b0455a8520bc4e6f 5fe95b1fe3c8452b")
    );
}

#[test]
fn sha512_fips_180_examples() {
    // FIPS 180-2 Appendix C.1 ("abc") and C.2 (896-bit message).
    assert_eq!(
        sha512(ABC).to_vec(),
        hex("ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a
             2192992a274fc1a8 36ba3c23a3feebbd 454d4423643ce80e 2a9ac94fa54ca49f")
    );
    assert_eq!(
        sha512(MSG_896).to_vec(),
        hex("8e959b75dae313da 8cf4f72814fc143f 8f7779c6eb9f7fa1 7299aeadb6889018
             501d289e4900f7e4 331b99dec4b5433a c7d329eeb6dd2654 5e96e55b874be909")
    );
    // 448-bit message: republished value, cross-checked (see module docs).
    assert_eq!(
        sha512(MSG_448).to_vec(),
        hex("204a8fc6dda82f0a 0ced7beb8e08a416 57c16ef468b228a8 279be331a703c335
             96fd15c13b1b07f9 aa1d3bea57789ca0 31ad85c7a71dd703 54ec631238ca3445")
    );
}

#[test]
fn digest_dispatches_to_the_named_algorithm() {
    for (alg, expected) in [
        (HashAlg::Sha1, sha1(ABC).to_vec()),
        (HashAlg::Sha256, sha256(ABC).to_vec()),
        (HashAlg::Sha384, sha384(ABC).to_vec()),
        (HashAlg::Sha512, sha512(ABC).to_vec()),
    ] {
        let out = digest(alg, ABC);
        assert_eq!(out, expected, "{alg:?}");
        assert_eq!(out.len(), alg.output_len(), "{alg:?}");
    }
}

#[test]
fn empty_message() {
    // NIST CAVP SHAVS byte-oriented ShortMsg files, `Len = 0` entries.
    assert_eq!(sha1(b"").to_vec(), hex("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
    assert_eq!(
        sha256(b"").to_vec(),
        hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
    assert_eq!(
        sha384(b"").to_vec(),
        hex("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da
             274edebfe76f65fbd51ad2f14898b95b")
    );
    assert_eq!(
        sha512(b"").to_vec(),
        hex("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
    );
}

const ALGS: [HashAlg; 4] = [HashAlg::Sha1, HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512];

#[test]
fn hasher_million_a_examples() {
    // FIPS 180-2 Appendices A.3, B.3, C.3 and D.3: one million repetitions of "a", fed in
    // 1000-byte pieces so the result depends on the incremental state.
    let piece = [b'a'; 1000];
    for (alg, expected) in [
        (HashAlg::Sha1, "34aa973c d4c4daa4 f61eeb2b dbad2731 6534016f"),
        (HashAlg::Sha256, "cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0"),
        (
            HashAlg::Sha384,
            "9d0e1809716474cb 086e834e310a4a1c ed149e9c00f24852 7972cec5704c2a5b
             07b8b3dc38ecc4eb ae97ddd87f3d8985",
        ),
        (
            HashAlg::Sha512,
            "e718483d0ce76964 4e2e42c7bc15b463 8e1f98b13b204428 5632a803afa973eb
             de0ff244877ea60a 4cb0432ce577c31b eb009c5c2c49aa2e 4eadb217ad8cc09b",
        ),
    ] {
        let mut hasher = Hasher::new(alg);
        for _ in 0..1000 {
            hasher.update(&piece);
        }
        assert_eq!(hasher.finalize(), hex(expected), "{alg:?}");
    }
}

#[test]
fn hasher_matches_the_one_shot_digest_for_any_split() {
    // Every split point of the published messages, including empty updates.
    for alg in ALGS {
        for message in [ABC, MSG_448, MSG_896, b"".as_slice()] {
            let expected = digest(alg, message);
            for cut in 0..=message.len() {
                let mut hasher = Hasher::new(alg);
                hasher.update(&message[..cut]);
                hasher.update(&[]);
                hasher.update(&message[cut..]);
                assert_eq!(hasher.finalize(), expected, "{alg:?} cut {cut}");
            }
            // Byte by byte.
            let mut hasher = Hasher::new(alg);
            for byte in message {
                hasher.update(std::slice::from_ref(byte));
            }
            let out = hasher.finalize();
            assert_eq!(out, expected, "{alg:?} bytewise");
            assert_eq!(out.len(), alg.output_len());
        }
    }
}

#[test]
fn hasher_without_input_is_the_empty_digest_and_clones_independently() {
    for alg in ALGS {
        let hasher = Hasher::new(alg);
        assert_eq!(hasher.alg(), alg);
        assert_eq!(hasher.clone().finalize(), digest(alg, b""), "{alg:?}");
        // A clone continues from the same state without affecting the original.
        let mut first = Hasher::new(alg);
        first.update(b"ab");
        let mut second = first.clone();
        second.update(b"c");
        first.update(b"x");
        assert_eq!(second.finalize(), digest(alg, ABC), "{alg:?}");
        assert_eq!(first.finalize(), digest(alg, b"abx"), "{alg:?}");
        assert_eq!(format!("{:?}", Hasher::new(alg)), format!("Hasher {{ alg: {alg:?}, .. }}"));
    }
}
