//! Credential management: SELECT/GET VERSION, PUT (store, import, generate), DELETE,
//! LIST, GET PUBLIC KEY, the management key and its tries, input syntax, duplicates and
//! capacity.
//!
//! Sources: yubikit `hsmauth.py` (command layout, lengths, `INITIAL_RETRY_COUNTER`),
//! ykman `_cli/hsmauth.py` `handle_error` (status words), ykhsmauth `ykhsmauth.c`
//! (GET VERSION, LIST parsing), yubikey-manager `tests/device/test_hsmauth.py`
//! (expected behaviours: duplicate import fails, delete of a missing credential fails,
//! GET PUBLIC KEY of a symmetric credential fails, management key retries 8 → 7), and
//! `reference/BEHAVIOR_CATALOG.md` YubiHSMAuth.

mod common;

use common::*;
use lk_codec::apdu::sw;
use lk_core::{CardApplet, Record};
use lk_crypto::{Curve, ec_public_is_valid};
use lk_hsmauth::{AID, MAX_CREDENTIALS, alg, ins, tag};
use lk_testkit::TestHost;

#[test]
fn select_reports_firmware_version_tlv() {
    let mut host = TestHost::new();
    let mut app = lk_hsmauth::HsmAuth::new(None, &mut host);
    assert_eq!(app.aid(), AID);
    assert_eq!(AID, &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x07, 0x01]);
    // yubikit `_parse_select`: exactly `79 03 05 07 04`.
    assert_eq!(app.select(&select_apdu(), &mut host), hex("7903050704 9000"));
    host.profile_mut().firmware = lk_core::Version::new(5, 6, 1);
    assert_eq!(app.select(&select_apdu(), &mut host), hex("7903050601 9000"));
}

#[test]
fn get_version_returns_raw_firmware_bytes() {
    let mut card = Card::new();
    // ykhsmauth `ykhsmauth_get_version`: `recv_len == 3`, data[0..3].
    assert_eq!(card.cmd(ins::GET_VERSION, &[]), (vec![5, 7, 4], sw::OK));
    // Older formatters always send an Lc byte: `00 07 00 00 00`.
    assert_eq!(card.send_raw(&[0, ins::GET_VERSION, 0, 0, 0]), (vec![5, 7, 4], sw::OK));
}

#[test]
fn put_symmetric_credential_and_list() {
    let mut card = Card::new();
    assert!(card.list().is_empty());
    assert_eq!(card.put_symmetric("Test PUT", [1; 16], [2; 16], pw("123456")), sw::OK);
    assert_eq!(card.put(&Put::symmetric("touchy", [3; 16], [4; 16], pw("x")).touch(true)), sw::OK);
    assert_eq!(
        card.list(),
        vec![
            Entry { algorithm: alg::AES128_YUBICO_AUTHENTICATION, touch: false, label: b"Test PUT".to_vec(), retries: 8 },
            Entry { algorithm: alg::AES128_YUBICO_AUTHENTICATION, touch: true, label: b"touchy".to_vec(), retries: 8 },
        ]
    );
    // Raw LIST bytes: `72 len alg touch label ctr` (ykhsmauth `ykhsmauth_list_keys`).
    let (raw, _) = card.cmd(ins::LIST, &[]);
    assert_eq!(&raw[..13], &hex("720b 26 00 5465737420505554 08")[..]);
}

#[test]
fn generate_asymmetric_credential_and_get_public_key() {
    let mut card = Card::new();
    assert_eq!(card.put(&Put::asymmetric("gen", None, pw("p"))), sw::OK);
    let (pk, status) = card.get_public_key("gen");
    assert_eq!(status, sw::OK);
    assert_eq!(pk.len(), 65);
    assert!(ec_public_is_valid(Curve::P256, &pk));
    assert_eq!(card.get_public_key("gen").0, pk, "stable");
    // A second generated credential gets a different key.
    assert_eq!(card.put(&Put::asymmetric("gen2", None, pw("p"))), sw::OK);
    assert_ne!(card.get_public_key("gen2").0, pk);
    let entries = card.list();
    assert!(entries.iter().all(|e| e.algorithm == alg::EC_P256_YUBICO_AUTHENTICATION));
}

#[test]
fn import_asymmetric_credential_public_key_matches() {
    let mut card = Card::new();
    let key = test_key("imported");
    assert_eq!(card.put(&Put::asymmetric("imp", Some(key.scalar().to_vec()), pw("p"))), sw::OK);
    assert_eq!(card.get_public_key("imp"), (key.public_uncompressed(), sw::OK));
    // Invalid scalars (zero, the group order n, wrong length) are syntax errors.
    let order = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    for bad in [vec![0u8; 32], order, vec![1u8; 31], vec![1u8; 33]] {
        assert_eq!(card.put(&Put::asymmetric("bad", Some(bad), pw("p"))), sw::INCORRECT_DATA);
    }
    assert_eq!(card.labels(), vec![b"imp".to_vec()]);
}

/// ykman `export`: `6983` "The entry is not an asymmetric credential".
#[test]
fn get_public_key_of_symmetric_credential_is_rejected() {
    let mut card = Card::new();
    assert_eq!(card.put_symmetric("sym", [1; 16], [2; 16], pw("p")), sw::OK);
    assert_eq!(card.get_public_key("sym"), (vec![], sw::AUTH_BLOCKED));
    assert_eq!(card.get_public_key("missing"), (vec![], sw::FILE_NOT_FOUND));
    assert_eq!(card.cmd(ins::GET_PUBLIC_KEY, &[]).1, sw::INCORRECT_DATA);
}

#[test]
fn delete_credential_requires_management_key() {
    let mut card = Card::new();
    assert_eq!(card.put_symmetric("a", [1; 16], [2; 16], pw("p")), sw::OK);
    assert_eq!(card.put_symmetric("b", [1; 16], [2; 16], pw("p")), sw::OK);
    assert_eq!(card.delete(&[9; 16], "a"), sw::retries(7));
    assert_eq!(card.labels().len(), 2);
    assert_eq!(card.delete(&DEFAULT_KEY, "a"), sw::OK);
    assert_eq!(card.labels(), vec![b"b".to_vec()]);
    // A correct key restored the tries.
    assert_eq!(card.management_retries(), 8);
}

/// yubikit `test_delete_credential_not_found`-style check; ykman maps `6A82`.
#[test]
fn delete_unknown_label_is_file_not_found() {
    let mut card = Card::new();
    assert_eq!(card.delete(&DEFAULT_KEY, "nothing"), sw::FILE_NOT_FOUND);
    assert_eq!(card.delete(&DEFAULT_KEY, ""), sw::INCORRECT_DATA);
    assert_eq!(card.delete(&[0; 15], "nothing"), sw::INCORRECT_DATA);
    assert_eq!(card.management_retries(), 8);
}

/// Catalog `yubihsm_auth_add_input_syntax_and_duplicates`: duplicate labels are `6983`.
#[test]
fn duplicate_label_is_rejected_with_6983() {
    let mut card = Card::new();
    assert_eq!(card.put_symmetric("dup", [1; 16], [2; 16], pw("p")), sw::OK);
    let before = card.host.persist_count();
    assert_eq!(card.put_symmetric("dup", [5; 16], [6; 16], pw("q")), sw::AUTH_BLOCKED);
    assert_eq!(card.put(&Put::asymmetric("dup", None, pw("q"))), sw::AUTH_BLOCKED);
    assert_eq!(card.host.persist_count(), before, "nothing stored");
    assert_eq!(card.list().len(), 1);
    // The original credential is intact.
    let context = [0u8; 16];
    let (keys, status) = card.cmd(ins::CALCULATE, &calculate_data("dup", &context, None, None, &pw("p")));
    assert_eq!(status, sw::OK);
    assert_eq!(keys[..16], sp800_108_cmac(&[1; 16], constant::S_ENC, &context, 128)[..]);
}

/// Catalog `yubihsm_auth_add_input_syntax_and_duplicates`: malformed algorithm length is
/// `6A80` and stores nothing.
#[test]
fn malformed_algorithm_is_rejected_without_storage() {
    let mut card = Card::new();
    for algorithm in [vec![], vec![0x00, 0x26], vec![0x26, 0x00], vec![0x25], vec![0x28]] {
        let mut d = tlv(tag::MANAGEMENT_KEY, &DEFAULT_KEY);
        d.extend(tlv(tag::LABEL, b"x"));
        d.extend(tlv(tag::ALGORITHM, &algorithm));
        d.extend(tlv(tag::KEY_ENC, &[1; 16]));
        d.extend(tlv(tag::KEY_MAC, &[2; 16]));
        d.extend(tlv(tag::CREDENTIAL_PASSWORD, &pw("p")));
        assert_eq!(card.cmd(ins::PUT, &d).1, sw::INCORRECT_DATA, "{algorithm:02x?}");
    }
    assert!(card.list().is_empty());
    assert_eq!(card.host.persist_attempts(), 0);
    assert_eq!(card.management_retries(), 8);
}

/// Catalog `yubihsm_auth_add_input_syntax_and_duplicates`: invalid UTF-8 labels are `6A80`.
#[test]
fn invalid_utf8_label_is_rejected_without_storage() {
    let mut card = Card::new();
    for label in [&[0xFFu8, 0xFE][..], &[0xC3][..], &[b'a', 0x80][..]] {
        let mut put = Put::symmetric("", [1; 16], [2; 16], pw("p"));
        put.label = label;
        assert_eq!(card.put(&put), sw::INCORRECT_DATA);
    }
    assert!(card.list().is_empty());
    assert_eq!(card.host.persist_attempts(), 0);
    // Multi-byte UTF-8 is fine.
    assert_eq!(card.put_symmetric("caf\u{e9} \u{1F511}", [1; 16], [2; 16], pw("p")), sw::OK);
    assert_eq!(card.labels(), vec!["caf\u{e9} \u{1F511}".as_bytes().to_vec()]);
}

/// yubikit `MIN_LABEL_LEN = 1`, `MAX_LABEL_LEN = 64` (bytes).
#[test]
fn label_length_bounds() {
    let mut card = Card::new();
    let longest = "L".repeat(64);
    assert_eq!(card.put_symmetric(&longest, [1; 16], [2; 16], pw("p")), sw::OK);
    assert_eq!(card.put_symmetric(&"L".repeat(65), [1; 16], [2; 16], pw("p")), sw::INCORRECT_DATA);
    assert_eq!(card.put_symmetric("", [1; 16], [2; 16], pw("p")), sw::INCORRECT_DATA);
    assert_eq!(card.put_symmetric("1", [1; 16], [2; 16], pw("p")), sw::OK);
    assert_eq!(card.labels(), vec![longest.into_bytes(), b"1".to_vec()]);
}

/// Catalog `yubihsm_auth_touch_policy_syntax` (and the YubiHSM Auth bullet filed under
/// FIDO): tag `7A` only as one byte `00` or `01`; anything else is rejected without
/// storage.
#[test]
fn touch_policy_tag_accepts_only_one_byte_00_or_01() {
    let mut card = Card::new();
    for touch in [vec![], vec![0x02], vec![0xFF], vec![0x00, 0x00], vec![0x01, 0x00], vec![0x00, 0x01]] {
        let mut put = Put::symmetric("t", [1; 16], [2; 16], pw("p"));
        put.touch = Some(touch.clone());
        assert_eq!(card.put(&put), sw::INCORRECT_DATA, "{touch:02x?}");
    }
    assert!(card.list().is_empty());
    assert_eq!(card.host.persist_attempts(), 0);
    assert_eq!(card.put(&Put::symmetric("off", [1; 16], [2; 16], pw("p")).touch(false)), sw::OK);
    assert_eq!(card.put(&Put::symmetric("on", [1; 16], [2; 16], pw("p")).touch(true)), sw::OK);
    let touches: Vec<bool> = card.list().iter().map(|e| e.touch).collect();
    assert_eq!(touches, vec![false, true]);
}

/// Model decision: an absent `7A` means no touch (yubikit and ykhsmauth always send it).
#[test]
fn absent_touch_tag_means_no_touch() {
    let mut card = Card::new();
    let mut put = Put::symmetric("t", [1; 16], [2; 16], pw("p"));
    put.touch = None;
    assert_eq!(card.put(&put), sw::OK);
    assert!(!card.list()[0].touch);
}

#[test]
fn put_rejects_wrong_key_material_for_algorithm() {
    let mut card = Card::new();
    // Symmetric without K-MAC, with short K-ENC, with a private key.
    let mut p = Put::symmetric("x", [1; 16], [2; 16], pw("p"));
    p.mac = None;
    assert_eq!(card.put(&p), sw::INCORRECT_DATA);
    let mut p = Put::symmetric("x", [1; 16], [2; 16], pw("p"));
    p.private = Some(test_key("k").scalar().to_vec());
    assert_eq!(card.put(&p), sw::INCORRECT_DATA);
    let mut d = tlv(tag::MANAGEMENT_KEY, &DEFAULT_KEY);
    d.extend(tlv(tag::LABEL, b"x"));
    d.extend(tlv(tag::ALGORITHM, &[alg::AES128_YUBICO_AUTHENTICATION]));
    d.extend(tlv(tag::KEY_ENC, &[1; 15]));
    d.extend(tlv(tag::KEY_MAC, &[2; 16]));
    d.extend(tlv(tag::CREDENTIAL_PASSWORD, &pw("p")));
    assert_eq!(card.cmd(ins::PUT, &d).1, sw::INCORRECT_DATA);
    // Asymmetric with symmetric key fields.
    let mut p = Put::asymmetric("x", None, pw("p"));
    p.enc = Some([1; 16]);
    assert_eq!(card.put(&p), sw::INCORRECT_DATA);
    // Password must be exactly 16 bytes; management key exactly 16 bytes.
    let mut d = tlv(tag::MANAGEMENT_KEY, &DEFAULT_KEY);
    d.extend(tlv(tag::LABEL, b"x"));
    d.extend(tlv(tag::ALGORITHM, &[alg::AES128_YUBICO_AUTHENTICATION]));
    d.extend(tlv(tag::KEY_ENC, &[1; 16]));
    d.extend(tlv(tag::KEY_MAC, &[2; 16]));
    let mut short_pw = d.clone();
    short_pw.extend(tlv(tag::CREDENTIAL_PASSWORD, b"123456"));
    assert_eq!(card.cmd(ins::PUT, &short_pw).1, sw::INCORRECT_DATA);
    assert_eq!(card.cmd(ins::PUT, &d).1, sw::INCORRECT_DATA, "password missing");
    let mut p = Put::symmetric("x", [1; 16], [2; 16], pw("p")).data();
    p[1] = 0x0F; // management key TLV length 15: misparses
    assert_eq!(card.cmd(ins::PUT, &p).1, sw::INCORRECT_DATA);
    // Unknown, duplicated and malformed TLVs.
    let mut p = Put::symmetric("x", [1; 16], [2; 16], pw("p")).data();
    p.extend(tlv(tag::CONTEXT, &[0; 16]));
    assert_eq!(card.cmd(ins::PUT, &p).1, sw::INCORRECT_DATA);
    let mut p = Put::symmetric("x", [1; 16], [2; 16], pw("p")).data();
    p.extend(tlv(tag::LABEL, b"y"));
    assert_eq!(card.cmd(ins::PUT, &p).1, sw::INCORRECT_DATA);
    let mut p = Put::symmetric("x", [1; 16], [2; 16], pw("p")).data();
    p.push(0x71);
    assert_eq!(card.cmd(ins::PUT, &p).1, sw::INCORRECT_DATA);
    assert!(card.list().is_empty());
    assert_eq!(card.management_retries(), 8);
    assert_eq!(card.host.persist_attempts(), 0);
}

/// Yubico documents 32 YubiHSM Auth credential slots; the 33rd PUT is `6A84` (ykman
/// "No space left on the YubiKey for YubiHSM Auth credentials").
#[test]
fn capacity_is_32_credentials_then_no_space() {
    let mut card = Card::new();
    for i in 0..MAX_CREDENTIALS {
        let label = format!("{i:02}-{}", "x".repeat(61));
        assert_eq!(card.put_symmetric(&label, [i as u8; 16], [2; 16], pw("p")), sw::OK, "credential {i}");
    }
    assert_eq!(MAX_CREDENTIALS, 32);
    assert_eq!(card.put_symmetric("one more", [1; 16], [2; 16], pw("p")), sw::NO_SPACE);
    assert_eq!(card.put(&Put::asymmetric("one more", None, pw("p"))), sw::NO_SPACE);
    // Duplicates are reported before capacity.
    let first = format!("00-{}", "x".repeat(61));
    assert_eq!(card.put_symmetric(&first, [1; 16], [2; 16], pw("p")), sw::AUTH_BLOCKED);
    assert_eq!(card.list().len(), 32);
    // Freeing a slot makes room again.
    assert_eq!(card.delete(&DEFAULT_KEY, &first), sw::OK);
    assert_eq!(card.put_symmetric("one more", [1; 16], [2; 16], pw("p")), sw::OK);
    assert_eq!(card.list().len(), 32);
}

/// A full LIST (32 × 69 bytes) exceeds one short response: `61xx` and GET RESPONSE
/// (ISO/IEC 7816-4 §5.1.3, §7.6.1), or a single extended response.
#[test]
fn list_longer_than_256_bytes_uses_get_response() {
    let mut card = Card::new();
    for i in 0..MAX_CREDENTIALS {
        let label = format!("{i:02}{}", "y".repeat(62));
        assert_eq!(card.put_symmetric(&label, [1; 16], [2; 16], pw("p")), sw::OK);
    }
    let (first, status) = card.send_raw(&apdu(ins::LIST, 0, 0, &[]));
    assert_eq!(first.len(), 256);
    assert_eq!(status, 0x6100, "more than 255 bytes remain");
    let entries = card.list();
    assert_eq!(entries.len(), 32);
    assert!(entries.iter().all(|e| e.label.len() == 64 && e.retries == 8));
    // Extended Le: everything at once.
    let (all, status) = card.send_raw(&[0, ins::LIST, 0, 0, 0, 0, 0]);
    assert_eq!((all.len(), status), (32 * 69, sw::OK));
    // GET RESPONSE with nothing pending.
    assert_eq!(card.send_raw(&[0, ins::GET_RESPONSE, 0, 0, 0]).1, sw::CONDITIONS);
    // Another command drops pending response data.
    let (_, status) = card.send_raw(&apdu(ins::LIST, 0, 0, &[]));
    assert_eq!(status, 0x6100);
    assert_eq!(card.cmd(ins::GET_VERSION, &[]).1, sw::OK);
    assert_eq!(card.send_raw(&[0, ins::GET_RESPONSE, 0, 0, 0]).1, sw::CONDITIONS);
}

/// yubikit `put_management_key`; yubikey-manager `test_hsmauth.py` checks the retry
/// counter starts at 8 and drops to 7 after a wrong key.
#[test]
fn management_key_change_and_retries() {
    let mut card = Card::new();
    let new_key = hex("11111111111111111111111111111112");
    assert_eq!(card.management_retries(), 8);
    assert_eq!(card.put_management_key(&[1; 16], &new_key), sw::retries(7));
    assert_eq!(card.management_retries(), 7);
    assert_eq!(card.put_management_key(&DEFAULT_KEY, &new_key), sw::OK);
    assert_eq!(card.management_retries(), 8);
    // The old key no longer works; the new one does.
    assert_eq!(card.put_symmetric("a", [1; 16], [2; 16], pw("p")), sw::retries(7));
    let mut put = Put::symmetric("a", [1; 16], [2; 16], pw("p"));
    put.management_key = new_key.clone().try_into().expect("16");
    assert_eq!(card.put(&put), sw::OK);
    assert_eq!(card.management_retries(), 8);
    // Malformed: one key, wrong lengths, wrong tag, three keys.
    let syntax = [
        tlv(tag::MANAGEMENT_KEY, &new_key),
        [tlv(tag::MANAGEMENT_KEY, &new_key), tlv(tag::MANAGEMENT_KEY, &[0; 15])].concat(),
        [tlv(tag::MANAGEMENT_KEY, &new_key[..15]), tlv(tag::MANAGEMENT_KEY, &[0; 16])].concat(),
        [tlv(tag::MANAGEMENT_KEY, &new_key), tlv(tag::LABEL, &[0; 16])].concat(),
        [tlv(tag::MANAGEMENT_KEY, &new_key), tlv(tag::MANAGEMENT_KEY, &[0; 16]), tlv(tag::MANAGEMENT_KEY, &[0; 16])]
            .concat(),
        vec![0x7B, 0x10],
    ];
    for data in syntax {
        assert_eq!(card.cmd(ins::PUT_MANAGEMENT_KEY, &data).1, sw::INCORRECT_DATA);
    }
    assert_eq!(card.management_retries(), 8);
}

/// Eight wrong management keys block it (`63C0`, ykman "Management key is blocked"),
/// even for the right key, until RESET.
#[test]
fn management_key_blocks_after_eight_wrong_attempts_until_reset() {
    let mut card = Card::new();
    assert_eq!(card.put_symmetric("keep", [1; 16], [2; 16], pw("p")), sw::OK);
    for left in (0..8).rev() {
        assert_eq!(card.delete(&[0xEE; 16], "keep"), sw::retries(left));
    }
    assert_eq!(card.management_retries(), 0);
    assert_eq!(card.delete(&DEFAULT_KEY, "keep"), sw::retries(0));
    assert_eq!(card.put_symmetric("new", [1; 16], [2; 16], pw("p")), sw::retries(0));
    assert_eq!(card.put_management_key(&DEFAULT_KEY, &[3; 16]), sw::retries(0));
    assert_eq!(card.labels(), vec![b"keep".to_vec()]);
    // The block survives a restart.
    let mut card = card.restart();
    assert_eq!(card.management_retries(), 0);
    // Credentials remain usable; RESET recovers the management key.
    let (_, status) = card.cmd(ins::CALCULATE, &calculate_data("keep", &[0; 16], None, None, &pw("p")));
    assert_eq!(status, sw::OK);
    assert_eq!(card.send(ins::RESET, 0xDE, 0xAD, &[]).1, sw::OK);
    assert_eq!(card.management_retries(), 8);
    assert!(card.list().is_empty());
}

#[test]
fn syntax_errors_do_not_consume_management_key_retries() {
    let mut card = Card::new();
    let mut put = Put::symmetric("", [1; 16], [2; 16], pw("p"));
    put.management_key = [0xAA; 16]; // wrong key, but the label is malformed first
    assert_eq!(card.put(&put), sw::INCORRECT_DATA);
    assert_eq!(card.delete(&[0xAA; 16], ""), sw::INCORRECT_DATA);
    assert_eq!(card.management_retries(), 8);
    assert_eq!(card.host.persist_attempts(), 0);
}

/// yubikit `require_version(self.version, (5, 8, 0))` for CHANGE CREDENTIAL PASSWORD:
/// absent on 5.7.4.
#[test]
fn change_credential_password_is_not_supported_on_5_7_4() {
    let mut card = Card::new();
    assert_eq!(card.put_symmetric("a", [1; 16], [2; 16], pw("old")), sw::OK);
    let mut d = tlv(tag::LABEL, b"a");
    d.extend(tlv(tag::CREDENTIAL_PASSWORD, &pw("old")));
    d.extend(tlv(tag::CREDENTIAL_PASSWORD, &pw("new")));
    assert_eq!(card.cmd(lk_hsmauth::ins::CHANGE_CREDENTIAL_PASSWORD, &d).1, sw::INS_NOT_SUPPORTED);
}

#[test]
fn unknown_instruction_class_and_malformed_apdus() {
    let mut card = Card::new();
    for unknown in [0x00, 0x0C, 0x20, 0xA4, 0xCA, 0xFF] {
        assert_eq!(card.cmd(unknown, &[]).1, sw::INS_NOT_SUPPORTED, "INS {unknown:02x}");
    }
    for cla in [0x80, 0x84, 0x01, 0x40, 0xFF] {
        assert_eq!(card.send_raw(&[cla, ins::LIST, 0, 0]).1, sw::CLA_NOT_SUPPORTED, "CLA {cla:02x}");
    }
    // Secure-messaging indication bits are tolerated (the secure channel unwrapped it).
    assert_eq!(card.send_raw(&[0x04, ins::GET_VERSION, 0, 0]).1, sw::OK);
    assert_eq!(card.send_raw(&[0x00, ins::LIST]).1, sw::WRONG_LENGTH);
    assert_eq!(card.send_raw(&[0x00, ins::LIST, 0, 0, 2, 1]).1, sw::WRONG_LENGTH);
    // A changed header in the middle of a chain.
    assert_eq!(card.send_raw(&[0x10, ins::PUT, 0, 0, 1, 0x7B]).1, sw::OK);
    assert_eq!(card.send_raw(&[0x00, ins::DELETE, 0, 0, 1, 0x10]).1, sw::LAST_COMMAND_EXPECTED);
}

#[test]
fn credentials_persist_in_record_hsmauth() {
    let mut card = Card::new();
    assert_eq!(card.put_symmetric("sym", [1; 16], [2; 16], pw("p")), sw::OK);
    let stored = card.host.persisted(Record::HsmAuth).expect("persisted before 9000");
    assert_eq!(stored[0], 0x01, "format version");
    assert!(lk_codec::tlv::parse_all(&stored[1..]).is_ok(), "BER-TLV body");
}

/// yubikit `generate_credential_asymmetric` calls `_put_credential` with key `b""`
/// ("Empty byte will generate key"), which appends `Tlv(TAG_PRIVATE_KEY, b"")`: the
/// exact data field below, with `7D 00`. Before the review fix this answered `6A80`.
#[test]
fn generate_accepts_yubikit_empty_private_key_object() {
    let mut card = Card::new();
    let data = hex(concat!(
        "7b10 00000000000000000000000000000000", // TAG_MANAGEMENT_KEY, default key
        "7103 67656e",                           // TAG_LABEL "gen"
        "7401 27",                               // TAG_ALGORITHM 39
        "7d00",                                  // TAG_PRIVATE_KEY, empty: generate
        "7310 70617373776f72640000000000000000", // "password" padded to 16
        "7a01 01",                               // TAG_TOUCH 1
    ));
    let mut apdu = vec![0x00, ins::PUT, 0x00, 0x00, u8::try_from(data.len()).expect("short")];
    apdu.extend_from_slice(&data);
    assert_eq!(card.send_raw(&apdu), (vec![], sw::OK));
    assert_eq!(
        card.list(),
        vec![Entry { algorithm: alg::EC_P256_YUBICO_AUTHENTICATION, touch: true, label: b"gen".to_vec(), retries: 8 }]
    );
    let (pk, status) = card.get_public_key("gen");
    assert_eq!(status, sw::OK);
    assert!(ec_public_is_valid(Curve::P256, &pk));
    // A symmetric credential with an (even empty) `7D` is still malformed.
    let mut p = Put::symmetric("s", [1; 16], [2; 16], pw("p"));
    p.private = Some(vec![]);
    assert_eq!(card.put(&p), sw::INCORRECT_DATA);
    // Any non-empty `7D` other than 32 bytes is malformed.
    for len in [1usize, 16, 31, 33, 64] {
        assert_eq!(card.put(&Put::asymmetric("bad", Some(vec![1; len]), pw("p"))), sw::INCORRECT_DATA, "{len}");
    }
    assert_eq!(card.labels(), vec![b"gen".to_vec()]);
}

/// Model decision: an alg 39 PUT without any `7D` also generates (no SDK sends it).
#[test]
fn generate_without_private_key_object_is_accepted() {
    let mut card = Card::new();
    let mut p = Put::asymmetric("gen", None, pw("p"));
    p.private = None;
    assert!(!p.data().windows(1).any(|w| w == [0x7D]), "no 7D in the data field");
    assert_eq!(card.put(&p), sw::OK);
    assert_eq!(card.get_public_key("gen").1, sw::OK);
}

/// Label syntax (yubikit `_parse_label`; YESDK `Credential.Label`: "its UTF-8 byte count
/// is between 1 and 64 ... Non-printing characters are allowed ... null (UTF-8: 0x00)").
/// Bytes, not characters, are counted; invalid UTF-8 (RFC 3629 §3: overlong forms,
/// surrogates, truncated sequences) is `6A80`; labels compare as exact bytes.
#[test]
fn label_rules_count_utf8_bytes_and_compare_exactly() {
    let mut card = Card::new();
    let euro = "\u{20AC}"; // 3 bytes in UTF-8
    let at_limit = format!("{}a", euro.repeat(21)); // 63 + 1 = 64 bytes
    assert_eq!(at_limit.len(), 64);
    assert_eq!(card.put_symmetric(&at_limit, [1; 16], [2; 16], pw("p")), sw::OK);
    let over = euro.repeat(22); // 22 characters, 66 bytes
    assert_eq!(card.put_symmetric(&over, [1; 16], [2; 16], pw("p")), sw::INCORRECT_DATA);
    // NUL and other control characters are valid UTF-8 and allowed.
    assert_eq!(card.put_symmetric("\u{0}", [1; 16], [2; 16], pw("p")), sw::OK);
    assert_eq!(card.put_symmetric("a\u{0}", [1; 16], [2; 16], pw("p")), sw::OK);
    assert_eq!(card.put_symmetric("a", [1; 16], [2; 16], pw("p")), sw::OK, "'a' differs from 'a\\0'");
    assert_eq!(card.put_symmetric("A", [1; 16], [2; 16], pw("p")), sw::OK, "case-sensitive");
    assert_eq!(card.put_symmetric("a", [3; 16], [4; 16], pw("q")), sw::AUTH_BLOCKED);
    // Invalid UTF-8: overlong NUL, a UTF-16 surrogate, a lone continuation byte, a
    // 4-byte sequence above U+10FFFF, a truncated 3-byte sequence at the end.
    let invalid: [&[u8]; 5] = [&[0xC0, 0x80], &[0xED, 0xA0, 0x80], &[0x80], &[0xF4, 0x90, 0x80, 0x80], &[b'x', 0xE2, 0x82]];
    for label in invalid {
        let mut put = Put::symmetric("", [1; 16], [2; 16], pw("p"));
        put.label = label;
        assert_eq!(card.put(&put), sw::INCORRECT_DATA, "{label:02x?}");
    }
    assert_eq!(card.list().len(), 5);
}

/// The same label syntax applies wherever a command names a credential (yubikit
/// `_parse_label` is used by every method): `6A80` before any lookup, retry counter or
/// challenge is touched.
#[test]
fn label_rules_apply_to_every_command() {
    let mut card = Card::new();
    assert_eq!(card.put_symmetric("s", [1; 16], [2; 16], pw("p")), sw::OK);
    let bad_labels: [Vec<u8>; 3] = [vec![], vec![b'L'; 65], vec![0xFF]];
    for label in &bad_labels {
        let mut d = tlv(tag::MANAGEMENT_KEY, &[0xEE; 16]); // wrong key: must not be checked
        d.extend(tlv(tag::LABEL, label));
        assert_eq!(card.cmd(ins::DELETE, &d).1, sw::INCORRECT_DATA);
        let mut d = tlv(tag::LABEL, label);
        d.extend(tlv(tag::CONTEXT, &[0; 16]));
        d.extend(tlv(tag::CREDENTIAL_PASSWORD, &pw("wrong")));
        assert_eq!(card.cmd(ins::CALCULATE, &d).1, sw::INCORRECT_DATA);
        let mut d = tlv(tag::LABEL, label);
        d.extend(tlv(tag::CREDENTIAL_PASSWORD, &pw("wrong")));
        assert_eq!(card.cmd(ins::GET_CHALLENGE, &d).1, sw::INCORRECT_DATA);
        assert_eq!(card.cmd(ins::GET_PUBLIC_KEY, &tlv(tag::LABEL, label)).1, sw::INCORRECT_DATA);
    }
    assert_eq!(card.management_retries(), 8);
    assert_eq!(card.retries_of("s"), Some(8));
    assert_eq!(card.host.persist_count(), 1, "only the first PUT was stored");
}

/// Malformed BER-TLV in the data field (ISO/IEC 7816-4 §5.2.2; `lk_codec::tlv` errors:
/// truncated value, indefinite length `80`, unsupported length form `84`, tag longer
/// than three bytes, `00` padding between objects, a trailing lone tag) is `6A80` for
/// every command that takes data, and consumes no try and stores nothing.
#[test]
fn malformed_tlv_is_6a80_for_every_command() {
    let mut card = Card::new();
    assert_eq!(card.put_symmetric("s", [1; 16], [2; 16], pw("p")), sw::OK);
    let attempts = card.host.persist_attempts();
    let corruptions: [&[u8]; 6] = [
        &[0x71, 0x05, b's'],                         // truncated value
        &[0x71, 0x80, b's', 0x00, 0x00],             // indefinite length
        &[0x71, 0x84, 0x00, 0x00, 0x00, 0x01, b's'], // 4-byte length form
        &[0x7F, 0xFF, 0xFF, 0x7F, 0x01, 0x00],       // 4-byte tag
        &[0x00, 0x71, 0x01, b's'],                   // leading 00 padding
        &[0x71],                                     // lone tag
    ];
    let commands = [ins::PUT, ins::DELETE, ins::CALCULATE, ins::GET_CHALLENGE, ins::PUT_MANAGEMENT_KEY, ins::GET_PUBLIC_KEY];
    for ins in commands {
        for bad in corruptions {
            // A valid-looking prefix of the right objects, then the corruption.
            let mut d = match ins {
                ins::PUT | ins::DELETE | ins::PUT_MANAGEMENT_KEY => tlv(tag::MANAGEMENT_KEY, &[0xEE; 16]),
                _ => Vec::new(),
            };
            if ins == ins::CALCULATE || ins == ins::GET_CHALLENGE {
                d.extend(tlv(tag::CREDENTIAL_PASSWORD, &pw("wrong")));
            }
            d.extend_from_slice(bad);
            assert_eq!(card.cmd(ins, &d).1, sw::INCORRECT_DATA, "INS {ins:02x} data {d:02x?}");
        }
    }
    assert_eq!(card.management_retries(), 8);
    assert_eq!(card.retries_of("s"), Some(8));
    assert_eq!(card.host.persist_attempts(), attempts, "nothing was written");
}

/// YESDK `AddCredentialCommand` / `ChangeManagementKeyCommand`: "Supplying the correct
/// management key before the management key is blocked will reset the retry counter to
/// 8"; `lk_core::Host::persist`: retry counters are persisted before the response that
/// reveals them. Every management-key command (PUT, DELETE, PUT MANAGEMENT KEY) costs a
/// try on a wrong key, persisted; a correct key's reset to 8 is persisted before the
/// command's own effect, and a storage failure there leaves everything as it was.
#[test]
fn management_key_tries_are_persisted_for_every_command() {
    let mut card = Card::new();
    assert_eq!(card.put_symmetric("s", [1; 16], [2; 16], pw("p")), sw::OK);
    let wrong = [0xEE; 16];
    let mut put = Put::symmetric("t", [1; 16], [2; 16], pw("p"));
    put.management_key = wrong;
    assert_eq!(card.put(&put), sw::retries(7));
    assert_eq!(card.delete(&wrong, "s"), sw::retries(6));
    assert_eq!(card.put_management_key(&wrong, &[1; 16]), sw::retries(5));
    let mut card = card.restart();
    assert_eq!(card.management_retries(), 5, "each wrong try was persisted");
    // A wrong try whose persist fails is not counted and reveals no count.
    card.host.fail_next_saves(1);
    assert_eq!(card.delete(&wrong, "s"), sw::MEMORY_FAILURE);
    assert_eq!(card.management_retries(), 5);
    // The correct key: the reset to 8 cannot be stored, so nothing happens.
    card.host.fail_next_saves(1);
    assert_eq!(card.delete(&DEFAULT_KEY, "s"), sw::MEMORY_FAILURE);
    assert_eq!(card.management_retries(), 5);
    assert_eq!(card.labels(), vec![b"s".to_vec()]);
    // Correct key, storage working: the tries come back, persisted.
    assert_eq!(card.put_management_key(&DEFAULT_KEY, &[7; 16]), sw::OK);
    let mut card = card.restart();
    assert_eq!(card.management_retries(), 8);
    assert_eq!(card.delete(&[7; 16], "s"), sw::OK);
    assert!(card.list().is_empty());
}

/// YESDK `AddCredentialCommand`: "Once the management key is blocked, the application
/// must be reset before performing operations which require authentication with the
/// management key". A blocked key answers `63C0` (yubikit `InvalidPinError` with 0
/// attempts, ykman "... is blocked") without writing anything, before any lookup.
#[test]
fn blocked_management_key_writes_nothing() {
    let mut card = Card::new();
    for left in (0..8).rev() {
        assert_eq!(card.put_management_key(&[0xEE; 16], &[1; 16]), sw::retries(left));
    }
    let attempts = card.host.persist_attempts();
    assert_eq!(card.delete(&DEFAULT_KEY, "missing"), sw::retries(0), "before the 6A82 lookup");
    assert_eq!(card.put_symmetric("x", [1; 16], [2; 16], pw("p")), sw::retries(0));
    assert_eq!(card.put_management_key(&DEFAULT_KEY, &[1; 16]), sw::retries(0));
    assert_eq!(card.host.persist_attempts(), attempts);
    // Syntax is still checked first.
    assert_eq!(card.put_management_key(&DEFAULT_KEY, &[1; 15]), sw::INCORRECT_DATA);
}
