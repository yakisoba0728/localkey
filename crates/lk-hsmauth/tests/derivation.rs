//! Session-key derivation (CALCULATE, GET CHALLENGE) checked against test-side
//! implementations written from the specifications (see `common`).
//!
//! Vector sources:
//! - RFC 4493 §4 Example 1 (AES-CMAC) anchors the test-side PRF.
//! - RFC 7914 §11 (PBKDF2-HMAC-SHA256, P="passwd", S="salt", c=1) anchors the test-side
//!   PBKDF2.
//! - Yubico's published hardware test, yubikey-manager
//!   `tests/device/test_hsmauth.py::TestSessionKeys::test_calculate_session_keys_symmetric`
//!   (derivation password "pwd", credential password "a password", context and expected
//!   S-ENC/S-MAC/S-RMAC as published), with K-ENC/K-MAC from yubikit `_password_to_key`
//!   (PBKDF2-HMAC-SHA256, salt "Yubico", 10000 iterations, 32 bytes).
//!
//! No public known-answer vector exists for the asymmetric (dual ECDH) derivation; it is
//! checked by playing the YubiHSM 2 side independently (`common::HsmSide`).

mod common;

use common::*;
use lk_codec::apdu::sw;
use lk_crypto::{Curve, EcPrivateKey, aes_cmac, ec_public_is_valid};
use lk_hsmauth::{alg, ins, tag};
use lk_testkit::SeededEntropy;

#[test]
fn test_side_prf_matches_rfc4493_example() {
    // RFC 4493 §4, Example 1: K = 2b7e1516 28aed2a6 abf71588 09cf4f3c, M = <empty>.
    let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
    assert_eq!(aes_cmac(&key, &[]).expect("key").to_vec(), hex("bb1d6929e95937287fa37d129b756746"));
    // RFC 4493 §4, Example 2: M = 6bc1bee2 2e409f96 e93d7e11 7393172a.
    let m = hex("6bc1bee22e409f96e93d7e117393172a");
    assert_eq!(aes_cmac(&key, &m).expect("key").to_vec(), hex("070a16b46b4d4144f79bdd9dd04a287c"));
}

#[test]
fn test_side_pbkdf2_matches_rfc7914_vector() {
    // RFC 7914 §11: PBKDF2-HMAC-SHA256 (P="passwd", S="salt", c=1, dkLen=64).
    let expected = hex(
        "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc
         49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
    );
    assert_eq!(pbkdf2_hmac_sha256(b"passwd", b"salt", 1, 64), expected);
}

#[test]
fn symmetric_session_keys_match_yubico_published_vector() {
    // yubikit `_password_to_key("pwd")`; the hex is the same PBKDF2 computed with Python
    // `hashlib.pbkdf2_hmac("sha256", b"pwd", b"Yubico", 10000, 32)`.
    let derived = pbkdf2_hmac_sha256(b"pwd", b"Yubico", 10_000, 32);
    assert_eq!(derived, hex("53b8fbfb11c05a9d15b5060dd7a35cd3 cac17ab6fb0de15b2369592c7a960dc4"));
    let enc: [u8; 16] = derived[..16].try_into().expect("16");
    let mac: [u8; 16] = derived[16..].try_into().expect("16");

    let mut card = Card::new();
    let password = pw("a password");
    assert_eq!(card.put_symmetric("Test PUT", enc, mac, password), sw::OK);

    // test_hsmauth.py: context = b"g\xfc\xf1\xfe\xb5\xf1\xd8\x83\xedv=\xbfI0\x90\xbb".
    let context = hex("67fcf1feb5f1d883ed763dbf493090bb");
    let (keys, status) = card.cmd(ins::CALCULATE, &calculate_data("Test PUT", &context, None, None, &password));
    assert_eq!(status, sw::OK);
    assert_eq!(keys.len(), 48);
    // key_senc = b"\xb0o\x1a\xc9\x87\x91.\xbe\xdc\x1b\xf0\xe0*k]\x85"
    assert_eq!(keys[..16], hex("b06f1ac987912ebedc1bf0e02a6b5d85")[..]);
    // key_smac = b"\xea\xd6\xc3\xa5\x96\xea\x86u\xbf1\xd3I\xab\xb5,t"
    assert_eq!(keys[16..32], hex("ead6c3a596ea8675bf31d349abb52c74")[..]);
    // key_srmac = b"\xc2\xc6\x1e\x96\xab,X\xe9\x83z\xd0\xe7\xd0n\xe9\x0c"
    assert_eq!(keys[32..], hex("c2c61e96ab2c58e9837ad0e7d06ee90c")[..]);
}

#[test]
fn symmetric_session_keys_match_independent_sp800_108_kdf() {
    let mut rng = SeededEntropy::new(0x5C03);
    let mut card = Card::new();
    for round in 0..4 {
        let enc: [u8; 16] = rng.bytes(16).try_into().expect("16");
        let mac: [u8; 16] = rng.bytes(16).try_into().expect("16");
        let label = format!("cred-{round}");
        let password = pw(&format!("pw{round}"));
        assert_eq!(card.put_symmetric(&label, enc, mac, password), sw::OK);
        for _ in 0..3 {
            let context = rng.bytes(16);
            let (keys, status) = card.cmd(ins::CALCULATE, &calculate_data(&label, &context, None, None, &password));
            assert_eq!(status, sw::OK);
            assert_eq!(keys[..16], sp800_108_cmac(&enc, constant::S_ENC, &context, 128)[..]);
            assert_eq!(keys[16..32], sp800_108_cmac(&mac, constant::S_MAC, &context, 128)[..]);
            assert_eq!(keys[32..], sp800_108_cmac(&mac, constant::S_RMAC, &context, 128)[..]);
        }
    }
}

/// The YubiHSM 2 symmetric session (CREATE SESSION): host challenge from GET CHALLENGE,
/// card challenge and card cryptogram from the HSM (Amendment D §6.2.2.2, constant `00`,
/// 64 bits from S-MAC). The card verifies a supplied cryptogram.
#[test]
fn symmetric_card_cryptogram_is_verified_when_supplied() {
    let enc = [0x40; 16];
    let mac = [0x41; 16];
    let password = pw("hsm");
    let mut card = Card::new();
    assert_eq!(card.put_symmetric("sym", enc, mac, password), sw::OK);

    let (host_challenge, status) = card.get_challenge("sym", None);
    assert_eq!(status, sw::OK);
    assert_eq!(host_challenge.len(), 8);
    let card_challenge = hex("0102030405060708");
    let context = [host_challenge.as_slice(), &card_challenge].concat();
    let hsm_s_mac = sp800_108_cmac(&mac, constant::S_MAC, &context, 128);
    let cryptogram = sp800_108_cmac(&hsm_s_mac, constant::CARD_CRYPTOGRAM, &context, 64);

    let (keys, status) =
        card.cmd(ins::CALCULATE, &calculate_data("sym", &context, None, Some(&cryptogram), &password));
    assert_eq!(status, sw::OK);
    assert_eq!(keys[16..32], hsm_s_mac[..]);
    // The host cryptogram the host then sends (constant `01`) follows from the returned S-MAC.
    let host_cryptogram = sp800_108_cmac(&keys[16..32], constant::HOST_CRYPTOGRAM, &context, 64);
    assert_eq!(host_cryptogram, sp800_108_cmac(&hsm_s_mac, constant::HOST_CRYPTOGRAM, &context, 64));

    let mut wrong = cryptogram.clone();
    wrong[0] ^= 1;
    let (data, status) = card.cmd(ins::CALCULATE, &calculate_data("sym", &context, None, Some(&wrong), &password));
    assert_eq!((data.len(), status), (0, sw::DATA_INVALID));
    // A failed cryptogram is not a wrong password: no try is consumed.
    assert_eq!(card.retries_of("sym"), Some(8));
    // Wrong cryptogram length is a syntax error.
    let (_, status) = card.cmd(ins::CALCULATE, &calculate_data("sym", &context, None, Some(&[0; 16]), &password));
    assert_eq!(status, sw::INCORRECT_DATA);
}

#[test]
fn symmetric_calculate_rejects_wrong_context_or_public_key() {
    let password = pw("p");
    let mut card = Card::new();
    assert_eq!(card.put_symmetric("sym", [1; 16], [2; 16], password), sw::OK);
    for context in [vec![0u8; 15], vec![0u8; 17], vec![0u8; 130]] {
        let (_, status) = card.cmd(ins::CALCULATE, &calculate_data("sym", &context, None, None, &password));
        assert_eq!(status, sw::INCORRECT_DATA);
    }
    let pk = test_key("x").public_uncompressed();
    let (_, status) = card.cmd(ins::CALCULATE, &calculate_data("sym", &[0; 16], Some(&pk), None, &password));
    assert_eq!(status, sw::INCORRECT_DATA);
    // Missing password, short password.
    let mut d = tlv(tag::LABEL, b"sym");
    d.extend(tlv(tag::CONTEXT, &[0; 16]));
    assert_eq!(card.cmd(ins::CALCULATE, &d).1, sw::INCORRECT_DATA);
    d.extend(tlv(tag::CREDENTIAL_PASSWORD, &[0; 15]));
    assert_eq!(card.cmd(ins::CALCULATE, &d).1, sw::INCORRECT_DATA);
    // None of these consumed a try.
    assert_eq!(card.retries_of("sym"), Some(8));
    // Unknown label.
    let (_, status) = card.cmd(ins::CALCULATE, &calculate_data("nope", &[0; 16], None, None, &password));
    assert_eq!(status, sw::FILE_NOT_FOUND);
}

/// yubikit `test_get_challenge_symmetric`: 8 bytes, different each time; no touch even
/// for a touch-required credential (catalog `hsmauth_symmetric_challenge_touch`).
#[test]
fn symmetric_challenge_is_eight_random_bytes_without_touch() {
    let mut card = Card::new();
    assert_eq!(card.put(&Put::symmetric("t", [1; 16], [2; 16], pw("p")).touch(true)), sw::OK);
    // `send_raw` panics on a touch request.
    let (a, sa) = card.send_raw(&apdu(ins::GET_CHALLENGE, 0, 0, &tlv(tag::LABEL, b"t")));
    let (b, sb) = card.send_raw(&apdu(ins::GET_CHALLENGE, 0, 0, &tlv(tag::LABEL, b"t")));
    assert_eq!((sa, sb), (sw::OK, sw::OK));
    assert_eq!((a.len(), b.len()), (8, 8));
    assert_ne!(a, b);
}

fn asymmetric_card(label: &str, password: [u8; 16]) -> (Card, EcPrivateKey) {
    let mut card = Card::new();
    let credential = test_key(&format!("{label}/SK.OCE"));
    let status = card.put(&Put::asymmetric(label, Some(credential.scalar().to_vec()), password));
    assert_eq!(status, sw::OK);
    (card, credential)
}

/// Full asymmetric session: the HSM side derives independently from its own keys and
/// the card must return the same S-ENC/S-MAC/S-RMAC after verifying the receipt.
#[test]
fn asymmetric_dual_ecdh_session_keys_match_yubihsm_side() {
    let password = pw("123456");
    // A 64-byte label makes CALCULATE 302 bytes: an extended APDU (ISO/IEC 7816-4 §5.1).
    let label = format!("asym-{}", "x".repeat(59));
    let (mut card, credential) = asymmetric_card(&label, password);
    let (pk, status) = card.get_public_key(&label);
    assert_eq!(status, sw::OK);
    assert_eq!(pk, credential.public_uncompressed());

    for round in 0..3 {
        let hsm = HsmSide::new(&format!("hsm{round}"));
        let (epk_oce, status) = card.get_challenge(&label, Some(password));
        assert_eq!(status, sw::OK);
        assert!(ec_public_is_valid(Curve::P256, &epk_oce));
        let session = hsm.respond(&epk_oce, &pk);
        let data = calculate_data(&label, &session.context, Some(&hsm.public()), Some(&session.receipt), &password);
        assert!(data.len() > 255, "needs an extended APDU");
        let (keys, status) = card.cmd(ins::CALCULATE, &data);
        assert_eq!(status, sw::OK);
        assert_eq!(keys, session.session_keys);
    }
}

#[test]
fn asymmetric_generated_credential_derives_with_exported_public_key() {
    let password = pw("gen");
    let mut card = Card::new();
    assert_eq!(card.put(&Put::asymmetric("gen", None, password)), sw::OK);
    let entry = card.list().into_iter().next().expect("one credential");
    assert_eq!(entry.algorithm, alg::EC_P256_YUBICO_AUTHENTICATION);
    let (pk, status) = card.get_public_key("gen");
    assert_eq!(status, sw::OK);
    assert!(ec_public_is_valid(Curve::P256, &pk));

    let hsm = HsmSide::new("gen-hsm");
    let (epk_oce, _) = card.get_challenge("gen", None);
    let session = hsm.respond(&epk_oce, &pk);
    let data = calculate_data("gen", &session.context, Some(&hsm.public()), Some(&session.receipt), &password);
    let (keys, status) = card.cmd(ins::CALCULATE, &data);
    assert_eq!(status, sw::OK);
    assert_eq!(keys, session.session_keys);
}

#[test]
fn asymmetric_receipt_mismatch_is_rejected() {
    let password = pw("r");
    let (mut card, credential) = asymmetric_card("asym", password);
    let hsm = HsmSide::new("hsm");
    let (epk_oce, _) = card.get_challenge("asym", None);
    let session = hsm.respond(&epk_oce, &credential.public_uncompressed());
    let mut receipt = session.receipt.clone();
    receipt[15] ^= 0x80;
    let data = calculate_data("asym", &session.context, Some(&hsm.public()), Some(&receipt), &password);
    let (keys, status) = card.cmd(ins::CALCULATE, &data);
    assert_eq!((keys.len(), status), (0, sw::DATA_INVALID));

    // A receipt computed against a different HSM static key does not verify either.
    let (epk_oce, _) = card.get_challenge("asym", None);
    let session = hsm.respond(&epk_oce, &credential.public_uncompressed());
    let other = HsmSide::new("other");
    let data = calculate_data("asym", &session.context, Some(&other.public()), Some(&session.receipt), &password);
    assert_eq!(card.cmd(ins::CALCULATE, &data).1, sw::DATA_INVALID);
    // Receipt failures are not password failures.
    assert_eq!(card.retries_of("asym"), Some(8));
}

/// Catalog "single-use ephemeral challenges": the ephemeral key is consumed by the
/// first CALCULATE, successful or not.
#[test]
fn asymmetric_challenge_is_single_use() {
    let password = pw("s");
    let (mut card, credential) = asymmetric_card("asym", password);
    let hsm = HsmSide::new("hsm");
    let (epk_oce, _) = card.get_challenge("asym", None);
    let session = hsm.respond(&epk_oce, &credential.public_uncompressed());
    let data = calculate_data("asym", &session.context, Some(&hsm.public()), Some(&session.receipt), &password);
    assert_eq!(card.cmd(ins::CALCULATE, &data).1, sw::OK);
    assert_eq!(card.cmd(ins::CALCULATE, &data).1, sw::DATA_INVALID);

    // A failed attempt (wrong password) also consumes it.
    let (epk_oce, _) = card.get_challenge("asym", None);
    let session = hsm.respond(&epk_oce, &credential.public_uncompressed());
    let bad = calculate_data("asym", &session.context, Some(&hsm.public()), Some(&session.receipt), &pw("wrong"));
    assert_eq!(card.cmd(ins::CALCULATE, &bad).1, sw::retries(7));
    let good = calculate_data("asym", &session.context, Some(&hsm.public()), Some(&session.receipt), &password);
    assert_eq!(card.cmd(ins::CALCULATE, &good).1, sw::DATA_INVALID);

    // Two challenges in a row: only the latest is valid.
    let (first, _) = card.get_challenge("asym", None);
    let (second, _) = card.get_challenge("asym", None);
    assert_ne!(first, second);
    let stale = hsm.respond(&first, &credential.public_uncompressed());
    let data = calculate_data("asym", &stale.context, Some(&hsm.public()), Some(&stale.receipt), &password);
    assert_eq!(card.cmd(ins::CALCULATE, &data).1, sw::DATA_INVALID);
}

#[test]
fn asymmetric_calculate_without_challenge_is_rejected() {
    let password = pw("n");
    let (mut card, credential) = asymmetric_card("asym", password);
    let hsm = HsmSide::new("hsm");
    // EPK.OCE the card never issued.
    let fake = test_key("fake eSK.OCE").public_uncompressed();
    let session = hsm.respond(&fake, &credential.public_uncompressed());
    let data = calculate_data("asym", &session.context, Some(&hsm.public()), Some(&session.receipt), &password);
    assert_eq!(card.cmd(ins::CALCULATE, &data).1, sw::DATA_INVALID);
}

#[test]
fn asymmetric_context_must_carry_the_issued_challenge() {
    let password = pw("c");
    let (mut card, credential) = asymmetric_card("asym", password);
    let pk = credential.public_uncompressed();
    let hsm = HsmSide::new("hsm");
    // Issued challenge exists, but the context names another EPK.OCE.
    let (_issued, _) = card.get_challenge("asym", None);
    let fake = test_key("fake eSK.OCE").public_uncompressed();
    let session = hsm.respond(&fake, &pk);
    let data = calculate_data("asym", &session.context, Some(&hsm.public()), Some(&session.receipt), &password);
    assert_eq!(card.cmd(ins::CALCULATE, &data).1, sw::DATA_INVALID);

    // A challenge issued for another credential does not serve this one.
    assert_eq!(card.put(&Put::asymmetric("other", None, password)), sw::OK);
    let (epk_other, _) = card.get_challenge("other", None);
    let session = hsm.respond(&epk_other, &pk);
    let data = calculate_data("asym", &session.context, Some(&hsm.public()), Some(&session.receipt), &password);
    assert_eq!(card.cmd(ins::CALCULATE, &data).1, sw::DATA_INVALID);
}

#[test]
fn asymmetric_calculate_requires_public_key_receipt_and_valid_points() {
    let password = pw("v");
    let (mut card, credential) = asymmetric_card("asym", password);
    let hsm = HsmSide::new("hsm");
    let (epk_oce, _) = card.get_challenge("asym", None);
    let session = hsm.respond(&epk_oce, &credential.public_uncompressed());
    let pk_sd = hsm.public();
    let cases: Vec<Vec<u8>> = vec![
        calculate_data("asym", &session.context, None, Some(&session.receipt), &password),
        calculate_data("asym", &session.context, Some(&pk_sd), None, &password),
        calculate_data("asym", &session.context, Some(&pk_sd), Some(&session.receipt[..8]), &password),
        calculate_data("asym", &session.context[..129], Some(&pk_sd), Some(&session.receipt), &password),
        calculate_data("asym", &session.context[..16], Some(&pk_sd), Some(&session.receipt), &password),
        calculate_data("asym", &session.context, Some(&pk_sd[..64]), Some(&session.receipt), &password),
        calculate_data("asym", &session.context, Some(&[0x04; 65]), Some(&session.receipt), &password),
        {
            let mut ctx = session.context.clone();
            ctx[100] ^= 1; // EPK.SD no longer on the curve
            calculate_data("asym", &ctx, Some(&pk_sd), Some(&session.receipt), &password)
        },
    ];
    for data in cases {
        assert_eq!(card.cmd(ins::CALCULATE, &data).1, sw::INCORRECT_DATA);
    }
    // Syntax errors neither consume the challenge nor a try.
    assert_eq!(card.retries_of("asym"), Some(8));
    let good = calculate_data("asym", &session.context, Some(&pk_sd), Some(&session.receipt), &password);
    assert_eq!(card.cmd(ins::CALCULATE, &good), (session.session_keys.clone(), sw::OK));
}

/// ISO/IEC 7816-4 §5.1.1.1 command chaining: a host without extended APDUs sends the
/// ~300-byte asymmetric CALCULATE in short chained parts.
#[test]
fn asymmetric_calculate_accepts_command_chaining() {
    let password = pw("chain");
    let (mut card, credential) = asymmetric_card("asym", password);
    let hsm = HsmSide::new("hsm");
    let (epk_oce, _) = card.get_challenge("asym", None);
    let session = hsm.respond(&epk_oce, &credential.public_uncompressed());
    let data = calculate_data("asym", &session.context, Some(&hsm.public()), Some(&session.receipt), &password);
    let parts: Vec<&[u8]> = data.chunks(100).collect();
    assert_eq!(parts.len(), 3);
    let last = parts.len() - 1;
    let mut result = None;
    for (i, part) in parts.iter().enumerate() {
        let cla = if i == last { 0x00 } else { 0x10 };
        let mut a = vec![cla, ins::CALCULATE, 0, 0, u8::try_from(part.len()).expect("short")];
        a.extend_from_slice(part);
        let (out, status) = card.send_raw(&a);
        if i == last {
            result = Some((out, status));
        } else {
            assert_eq!((out.len(), status), (0, sw::OK));
        }
    }
    assert_eq!(result, Some((session.session_keys, sw::OK)));
}

/// yubikit `test_get_challenge_asymmetric`: 65-byte EPK.OCE, different each time.
#[test]
fn asymmetric_challenges_are_fresh_points() {
    let password = pw("f");
    let (mut card, _) = asymmetric_card("asym", password);
    let (a, sa) = card.get_challenge("asym", Some(password));
    let (b, sb) = card.get_challenge("asym", Some(password));
    assert_eq!((sa, sb), (sw::OK, sw::OK));
    assert_eq!((a.len(), b.len()), (65, 65));
    assert!(ec_public_is_valid(Curve::P256, &a) && ec_public_is_valid(Curve::P256, &b));
    assert_ne!(a, b);
}

/// End-to-end known-answer vector for the asymmetric CALCULATE, computed independently
/// with pyca/cryptography 46 (ECDH, `X963KDF(SHA256(), 64, 3C 88 10)`, AES `CMAC`) from
/// the layout of yubihsm-shell `lib/yubihsm.c` `yh_create_session_asym`; the generating
/// script is quoted in `src/kdf.rs` (`asymmetric_session_keys_match_independent_vector`).
/// Scalars are SHA-256 of "lk-hsmauth KAV SK.OCE" etc. The card's ephemeral key is fixed
/// by scripting the 32 entropy bytes `EcPrivateKey::generate` draws as its scalar.
#[test]
fn asymmetric_calculate_matches_independent_known_answer() {
    const SK_OCE: &str = "b727c96e2d291d449b310ba5da6e509c42fb45d7ce2ed323fecbc386aedc2431";
    const ESK_OCE: &str = "e5c82d43a4444908ce4d22384b39944fa91799bece7def44389525f34e4fd5cd";
    const PK_OCE: &str = "04c033f34c106319fba3b76ca7e4ee8b33ffd3b67b947fdbec050421fdbc68925e
                          f7959db53607276357b4d308d0169877b0cf838e7de892ae1635e29dfb909395";
    const EPK_OCE: &str = "04b108a3d4d5331cac150dddddaf3d42b8934c008ae297ad58c8ad23990b9c385c
                           bca77e4fa5947f106b3b89d3118de209d29912b9a332cc4a9270156b9bf4d8a3";
    const PK_SD: &str = "049609dd832e2e6fe0ca203e95278898feb2846b46872f7c0accd53fec0504f948
                         381e61b4f60a6afad0f5fa299bdc805bcd979ddb467890f2c358e1a8cb309f41";
    const EPK_SD: &str = "04bf423d4c16e64926f1bf591d5a578e8e808526cdea1989c7a9c1cf498b9e6d33
                          e096402d77628a63e84d8c9ac9c62fa42af42572b5dc44b52c1740a1fb68fc54";
    const RECEIPT: &str = "d1bdf8ab803cb5c3f66f6b180dc85101";
    const SESSION_KEYS: &str = "d5ff16a9e77875fd47459cd7ba294c04 2edaa61c1b8449a1afef5f5aac6a6141
                                07d922d52f0631baca3a2f454fd7765b";

    let password = pw("kav");
    let mut card = Card::new();
    assert_eq!(card.put(&Put::asymmetric("kav", Some(hex(SK_OCE)), password)), sw::OK);
    assert_eq!(card.get_public_key("kav"), (hex(PK_OCE), sw::OK));
    card.host.push_entropy(&hex(ESK_OCE));
    assert_eq!(card.get_challenge("kav", None), (hex(EPK_OCE), sw::OK));
    let context = [hex(EPK_OCE), hex(EPK_SD)].concat();
    let data = calculate_data("kav", &context, Some(&hex(PK_SD)), Some(&hex(RECEIPT)), &password);
    assert_eq!(card.cmd(ins::CALCULATE, &data), (hex(SESSION_KEYS), sw::OK));

    // A receipt MACed over the halves in context order (EPK.OCE || EPK.SD) instead of
    // yubihsm-shell's EPK.SD || EPK.OCE (same script, `c2.update(epk_oce + epk_sd)`),
    // and a receipt with one bit flipped, are both rejected.
    const RECEIPT_CONTEXT_ORDER: &str = "6176e2e2a3b219996a2af3a3229f3c61";
    let mut flipped = hex(RECEIPT);
    flipped[7] ^= 0x10;
    for receipt in [hex(RECEIPT_CONTEXT_ORDER), flipped] {
        card.host.push_entropy(&hex(ESK_OCE));
        assert_eq!(card.get_challenge("kav", None).0, hex(EPK_OCE));
        let data = calculate_data("kav", &context, Some(&hex(PK_SD)), Some(&receipt), &password);
        assert_eq!(card.cmd(ins::CALCULATE, &data).1, sw::DATA_INVALID);
    }
}
