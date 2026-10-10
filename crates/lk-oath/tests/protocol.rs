//! YKOATH command behaviour: SELECT, PUT, DELETE, RENAME, LIST, CALCULATE, CALCULATE
//! ALL, SET CODE, VALIDATE, RESET and SEND REMAINING, plus capacity, touch,
//! persistence and the boundary decisions of the catalog's OATH section.
//!
//! Sources: Yubico YKOATH Protocol Specification (cited per instruction), RFC 4226,
//! RFC 6238, RFC 8018 §5.2 (PBKDF2), RFC 6070 (PBKDF2 vectors), ISO/IEC 7816-4, the
//! OATH section of `reference/BEHAVIOR_CATALOG.md` and `oath_profile` of
//! `reference/legacy-v0.64-profiles.json`.

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use lk_core::{CardApplet, DeviceProfile, Outcome, Record, ResetKind, Version};
use lk_oath::{MAX_CREDENTIALS, TOUCH_TIMEOUT_MS};
use lk_testkit::TestHost;

const LIST: [u8; 4] = [0x00, 0xA1, 0x00, 0x00];

fn hotp(name: &[u8]) -> Vec<u8> {
    put_data(name, HOTP | SHA1, 6, RFC_SECRET, None, None)
}

fn totp(name: &[u8]) -> Vec<u8> {
    put_data(name, TOTP | SHA1, 8, RFC_SECRET, None, None)
}

/// A card with an access key derived from `password` as clients do (PBKDF2-HMAC-SHA1,
/// 1000 iterations, SELECT salt, 16 bytes; YKOATH §SET CODE). Returns the key.
fn lock(card: &mut Card, password: &[u8]) -> Vec<u8> {
    let salt = card.salt();
    let key = pbkdf2_hmac_sha1(password, &salt, 1000, 16);
    assert_eq!(card.sw(&set_code_apdu(&key, &[0x11; 8])), OK);
    key
}

/// Run the client side of YKOATH §VALIDATE after a fresh SELECT.
fn unlock(card: &mut Card, key: &[u8]) -> u16 {
    let fields = card.select_fields();
    let challenge = field(&fields, 0x74).unwrap();
    let host_challenge = [0x5A; 8];
    let resp = card.send(&validate_apdu(&lk_crypto::hmac_sha1(key, &challenge), &host_challenge));
    let (data, sw) = split(&resp);
    if sw == OK {
        let answer = parse_tlvs(data);
        assert_eq!(answer, vec![(0x75, lk_crypto::hmac_sha1(key, &host_challenge).to_vec())]);
    }
    sw
}

// --- SELECT ---------------------------------------------------------------------------

/// YKOATH §SELECT: `79` version from the device profile and `71` the 8-byte salt; no
/// challenge or algorithm without an access key.
#[test]
fn select_reports_version_and_salt() {
    let mut host = TestHost::with_profile(DeviceProfile::yubikey_5c_nano_5_7_4(1));
    host.push_entropy(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let mut card = Card::with_host(host);
    assert_eq!(card.oath.aid(), &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01]);
    assert_eq!(
        card.select(),
        vec![0x79, 0x03, 0x05, 0x07, 0x04, 0x71, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 0x90, 0x00]
    );
    card.host.profile_mut().firmware = Version::new(5, 4, 3);
    let fields = card.select_fields();
    assert_eq!(field(&fields, 0x79), Some(vec![5, 4, 3]));
    assert_eq!(fields.len(), 2);
}

/// YKOATH §SELECT with an access key: `74` an 8-byte challenge that changes on every
/// SELECT, and `7B` the key algorithm.
#[test]
fn select_with_access_key_adds_challenge_and_algorithm() {
    let mut card = Card::new();
    lock(&mut card, b"password");
    let first = card.select_fields();
    let second = card.select_fields();
    assert_eq!(first.iter().map(|f| f.0).collect::<Vec<_>>(), vec![0x79, 0x71, 0x74, 0x7B]);
    assert_eq!(field(&first, 0x74).unwrap().len(), 8);
    assert_eq!(field(&first, 0x7B), Some(vec![0x01]));
    assert_ne!(field(&first, 0x74), field(&second, 0x74));
    assert_eq!(field(&first, 0x71), field(&second, 0x71));
}

// --- PUT ------------------------------------------------------------------------------

/// YKOATH §PUT / §LIST / §CALCULATE / §DELETE / §RENAME round trip.
#[test]
fn list_calculate_rename_delete_round_trip() {
    let mut card = Card::new();
    assert!(card.list().is_empty());
    assert_eq!(card.put(&hotp(b"a")), OK);
    assert_eq!(card.put(&put_data(b"b", TOTP | SHA256, 8, &[7; 32], None, None)), OK);
    assert_eq!(card.put(&put_data(b"c", TOTP | SHA512, 7, &[9; 64], None, None)), OK);
    assert_eq!(
        card.list(),
        vec![(0x11, b"a".to_vec()), (0x22, b"b".to_vec()), (0x23, b"c".to_vec())]
    );
    assert_eq!(card.code(b"a", &[]), 755_224);
    assert_eq!(card.sw(&rename_apdu(b"b", b"bee")), OK);
    assert_eq!(card.names(), vec![b"a".to_vec(), b"bee".to_vec(), b"c".to_vec()]);
    assert_eq!(card.calc_truncated(b"b", &[0; 8]), Err(0x6984));
    assert!(card.calc_truncated(b"bee", &[0; 8]).is_ok());
    assert_eq!(card.sw(&delete_apdu(b"a")), OK);
    assert_eq!(card.names(), vec![b"bee".to_vec(), b"c".to_vec()]);
    assert_eq!(card.calc_truncated(b"a", &[]), Err(0x6984));
}

/// Catalog "four-byte HOTP-only IMF, singleton property and required/allowed TLV
/// syntax": every malformed PUT is `6A80` (YKOATH §PUT) and writes nothing.
#[test]
fn put_rejects_malformed_data_before_writing() {
    let mut card = Card::new();
    let good_key = {
        let mut k = vec![TOTP | SHA1, 6];
        k.extend_from_slice(RFC_SECRET);
        k
    };
    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("missing key", tlv(0x71, b"n")),
        ("missing name", tlv(0x73, &good_key)),
        ("empty name", put_data(b"", TOTP | SHA1, 6, RFC_SECRET, None, None)),
        ("65-byte name", put_data(&[b'x'; 65], TOTP | SHA1, 6, RFC_SECRET, None, None)),
        ("type 0x30", put_data(b"n", 0x31, 6, RFC_SECRET, None, None)),
        ("type 0x00", put_data(b"n", 0x01, 6, RFC_SECRET, None, None)),
        ("algorithm 0", put_data(b"n", TOTP, 6, RFC_SECRET, None, None)),
        ("algorithm 4", put_data(b"n", TOTP | 4, 6, RFC_SECRET, None, None)),
        ("5 digits", put_data(b"n", TOTP | SHA1, 5, RFC_SECRET, None, None)),
        ("9 digits", put_data(b"n", TOTP | SHA1, 9, RFC_SECRET, None, None)),
        ("key without digits", [tlv(0x71, b"n"), tlv(0x73, &[0x21])].concat()),
        ("property bit 0x04", put_data(b"n", TOTP | SHA1, 6, RFC_SECRET, Some(0x04), None)),
        ("property 0x80", put_data(b"n", TOTP | SHA1, 6, RFC_SECRET, Some(0x80), None)),
        ("IMF on TOTP", put_data(b"n", TOTP | SHA1, 6, RFC_SECRET, None, Some(1))),
        ("unknown tag", [totp(b"n"), tlv(0x74, &[1])].concat()),
        ("duplicate name", [totp(b"n"), tlv(0x71, b"m")].concat()),
        ("duplicate key", [totp(b"n"), tlv(0x73, &good_key)].concat()),
        ("truncated TLV", {
            let mut d = totp(b"n");
            d.pop();
            d
        }),
        ("property without value", [totp(b"n"), vec![0x78]].concat()),
    ];
    let imf_base = hotp(b"n");
    cases.push(("IMF 3 bytes", [imf_base.clone(), tlv(0x7A, &[0, 0, 1])].concat()));
    cases.push(("IMF 5 bytes", [imf_base.clone(), tlv(0x7A, &[0, 0, 0, 0, 1])].concat()));
    cases.push(("IMF 8 bytes", [imf_base.clone(), tlv(0x7A, &[0; 8])].concat()));
    cases.push(("duplicate IMF", [imf_base.clone(), tlv(0x7A, &[0; 4]), tlv(0x7A, &[0; 4])].concat()));
    cases.push(("duplicate property", [imf_base, vec![0x78, 0x02, 0x78, 0x02]].concat()));
    for (what, data) in cases {
        assert_eq!(card.put(&data), 0x6A80, "{what}");
    }
    assert_eq!(card.writes(), 0);
    assert!(card.list().is_empty());
}

/// Catalog "PUT credential secret minimum 14 wire bytes; unpadded 13-byte APDU
/// rejected before persistent write and SDK padded one-byte source verified".
#[test]
fn put_secret_minimum_is_14_wire_bytes() {
    let mut card = Card::new();
    assert_eq!(card.put(&put_data(b"n", TOTP | SHA1, 6, &[0x42; 13], None, None)), 0x6A80);
    assert_eq!(card.writes(), 0);
    assert_eq!(card.put(&put_data(b"n", TOTP | SHA1, 6, &[0x42; 14], None, None)), OK);
    // A one-byte secret padded by the client with zeros to 14 bytes computes exactly
    // HMAC with the one-byte key (RFC 2104 §2 zero-pads keys to the block size).
    let padded = client_secret(&[0x42], SHA1);
    assert_eq!(padded.len(), 14);
    assert_eq!(card.put(&put_data(b"one", TOTP | SHA1, 6, &padded, None, None)), OK);
    let challenge = 1234u64.to_be_bytes();
    let value = card.calc_full(b"one", &challenge).unwrap();
    assert_eq!(value[1..], lk_crypto::hmac_sha1(&[0x42], &challenge)[..]);
}

/// YKOATH §PUT: a PUT with an existing name overwrites that credential in place
/// (new type, key and counter; same list position).
#[test]
fn put_overwrites_existing_name() {
    let mut card = Card::new();
    assert_eq!(card.put(&hotp(b"x")), OK);
    assert_eq!(card.put(&totp(b"y")), OK);
    assert_eq!(card.code(b"x", &[]), 755_224);
    assert_eq!(card.put(&put_data(b"x", TOTP | SHA256, 8, &[1; 20], None, None)), OK);
    assert_eq!(card.list(), vec![(0x22, b"x".to_vec()), (0x21, b"y".to_vec())]);
    // Back to HOTP: the counter starts again from 0.
    assert_eq!(card.put(&hotp(b"x")), OK);
    assert_eq!(card.code(b"x", &[]), 755_224);
}

/// Catalog "four-byte HOTP-only IMF" and "durable IMF": the IMF sets the first HOTP
/// counter (RFC 4226 Appendix D counter 5 = 254676) and survives a restart.
#[test]
fn imf_sets_initial_counter_and_is_durable() {
    let mut card = Card::new();
    assert_eq!(card.put(&put_data(b"h", HOTP | SHA1, 6, RFC_SECRET, None, Some(5))), OK);
    card.restart();
    assert_eq!(card.code(b"h", &[]), 254_676);
    card.restart();
    assert_eq!(card.code(b"h", &[]), 287_922);
    // The largest four-byte IMF.
    assert_eq!(card.put(&put_data(b"max", HOTP | SHA1, 6, RFC_SECRET, None, Some(u32::MAX))), OK);
    let mac = lk_crypto::hmac_sha1(RFC_SECRET, &u64::from(u32::MAX).to_be_bytes());
    assert_eq!(card.calc_full(b"max", &[]).unwrap()[1..], mac[..]);
}

/// Binary credential names (catalog "OATH binary credential name ... original
/// credential bytes and HMAC preserved"): names are arbitrary bytes compared exactly.
#[test]
fn binary_names_are_kept_byte_for_byte() {
    let mut card = Card::new();
    let binary = [0x00, 0xFF, 0xC3, 0x28, 0x0A, 0x80];
    let longest = [0xEE; 64];
    assert_eq!(card.put(&hotp(&binary)), OK);
    assert_eq!(card.put(&hotp(&longest)), OK);
    assert_eq!(card.names(), vec![binary.to_vec(), longest.to_vec()]);
    assert_eq!(card.code(&binary, &[]), 755_224);
    assert_eq!(card.calc_truncated(&binary[..5], &[]), Err(0x6984));
    assert_eq!(card.sw(&rename_apdu(&binary, &[0x01, 0x02])), OK);
    assert_eq!(card.code(&[0x01, 0x02], &[]), 287_082);
    let (data, _) = card.send_all(&calculate_all_apdu(&[0; 8], true));
    assert_eq!(parse_tlvs(&data)[0], (0x71, vec![0x01, 0x02]));
}

// --- capacity -------------------------------------------------------------------------

/// Catalog "published 64-credential capacity; overflow, overwrite/rename at full
/// capacity, release/restart": the 65th credential is `6A84` (YKOATH §PUT "no
/// space"), overwrite and rename still work when full, deleting frees a slot, and the
/// full set survives a restart.
#[test]
fn capacity_is_64_credentials() {
    let mut card = Card::new();
    assert_eq!(MAX_CREDENTIALS, 64);
    for i in 0..64u8 {
        assert_eq!(card.put(&totp(&[b'c', i])), OK, "credential {i}");
    }
    let attempts = card.host.persist_attempts();
    assert_eq!(card.put(&totp(b"overflow")), 0x6A84);
    assert_eq!(card.host.persist_attempts(), attempts);
    assert_eq!(card.put(&hotp(&[b'c', 10])), OK, "overwrite at full capacity");
    assert_eq!(card.sw(&rename_apdu(&[b'c', 11], b"renamed")), OK, "rename at full capacity");
    assert_eq!(card.list().len(), 64);
    card.restart();
    assert_eq!(card.list().len(), 64);
    assert_eq!(card.put(&totp(b"overflow")), 0x6A84);
    assert_eq!(card.sw(&delete_apdu(&[b'c', 0])), OK);
    assert_eq!(card.put(&totp(b"overflow")), OK);
    assert_eq!(card.put(&totp(b"again")), 0x6A84);
    card.restart();
    let names = card.names();
    assert_eq!(names.len(), 64);
    assert_eq!(names.last().unwrap(), b"overflow");
    assert!(names.contains(&b"renamed".to_vec()));
}

// --- RENAME / DELETE ------------------------------------------------------------------

/// YKOATH §RENAME boundaries (model policy for the unspecified ones).
#[test]
fn rename_rules() {
    let mut card = Card::new();
    assert_eq!(card.put(&hotp(b"a")), OK);
    assert_eq!(card.put(&totp(b"b")), OK);
    assert_eq!(card.code(b"a", &[]), 755_224);
    assert_eq!(card.sw(&rename_apdu(b"zz", b"c")), 0x6984);
    assert_eq!(card.sw(&rename_apdu(b"a", b"b")), 0x6A80);
    assert_eq!(card.sw(&rename_apdu(b"a", b"")), 0x6A80);
    assert_eq!(card.sw(&rename_apdu(b"a", &[b'x'; 65])), 0x6A80);
    assert_eq!(card.sw(&apdu(0, 0x05, 0, 0, &tlv(0x71, b"a"))), 0x6A80);
    assert_eq!(card.sw(&apdu(0, 0x05, 0, 0, &[tlv(0x71, b"a"), tlv(0x73, b"b")].concat())), 0x6A80);
    let attempts = card.host.persist_attempts();
    assert_eq!(card.sw(&rename_apdu(b"a", b"a")), OK);
    assert_eq!(card.host.persist_attempts(), attempts);
    assert_eq!(card.sw(&rename_apdu(b"a", b"c")), OK);
    // The HOTP counter moves with the credential.
    assert_eq!(card.code(b"c", &[]), 287_082);
    card.restart();
    assert_eq!(card.names(), vec![b"c".to_vec(), b"b".to_vec()]);
}

/// `oath_profile.missing_credential_status`: DELETE, CALCULATE and RENAME of a
/// missing credential answer `6984`.
#[test]
fn missing_credentials_are_6984() {
    let mut card = Card::new();
    assert_eq!(card.sw(&delete_apdu(b"none")), 0x6984);
    assert_eq!(card.calc_truncated(b"none", &[0; 8]), Err(0x6984));
    assert_eq!(card.sw(&rename_apdu(b"none", b"x")), 0x6984);
    assert_eq!(card.sw(&apdu(0, 0x02, 0, 0, &[])), 0x6A80);
    assert_eq!(card.sw(&apdu(0, 0x02, 0, 0, &tlv(0x74, b"x"))), 0x6A80);
}

// --- P1/P2, CLA, INS, body ------------------------------------------------------------

/// Catalog "command P1/P2/body validation": wrong P1/P2 is `6A86` for every command,
/// commands without data refuse it with `6700`, unknown INS is `6D00`, an
/// unsupported CLA is `6E00`.
#[test]
fn header_and_body_validation() {
    let mut card = Card::new();
    assert_eq!(card.put(&totp(b"t")), OK);
    let calc = [tlv(0x71, b"t"), tlv(0x74, &[0; 8])].concat();
    for (ins, data) in [
        (0x01u8, totp(b"u")),
        (0x02, tlv(0x71, b"t")),
        (0x03, tlv(0x73, &[])),
        (0x05, rename_apdu(b"t", b"v")[5..].to_vec()),
        (0xA1, vec![]),
        (0xA3, vec![]),
    ] {
        assert_eq!(card.sw(&apdu(0, ins, 0x01, 0x00, &data)), 0x6A86, "INS {ins:02X} P1");
        assert_eq!(card.sw(&apdu(0, ins, 0x00, 0x01, &data)), 0x6A86, "INS {ins:02X} P2");
    }
    for ins in [0xA2u8, 0xA4] {
        let data = if ins == 0xA2 { calc.clone() } else { tlv(0x74, &[0; 8]) };
        assert_eq!(card.sw(&apdu(0, ins, 0x01, 0x00, &data)), 0x6A86);
        assert_eq!(card.sw(&apdu(0, ins, 0x00, 0x02, &data)), 0x6A86);
        // SELECT's P1 04 reaching the applet as a command is not CALCULATE ALL.
        assert_eq!(card.sw(&apdu(0, ins, 0x04, 0x00, &data)), 0x6A86);
    }
    assert_eq!(card.sw(&[0x00, 0x04, 0x00, 0x00]), 0x6A86);
    assert_eq!(card.sw(&[0x00, 0x04, 0xDE, 0x00]), 0x6A86);
    assert_eq!(card.sw(&[0x00, 0x04, 0xAD, 0xDE]), 0x6A86);
    assert_eq!(card.sw(&[0x00, 0x04, 0xDE, 0xAD, 0x01, 0x00]), 0x6700);
    assert_eq!(card.sw(&[0x00, 0xA1, 0x00, 0x00, 0x01, 0x00]), 0x6700);
    assert_eq!(card.sw(&[0x00, 0x06, 0x00, 0x00]), 0x6D00);
    assert_eq!(card.sw(&[0x00, 0xC0, 0x00, 0x00]), 0x6D00);
    // CLA (ISO/IEC 7816-4 §5.1.1): other classes 6E00, secure-messaging bits 6882 (the
    // device's secure channel clears them after unwrapping), logical channels 6881.
    assert_eq!(card.sw(&[0x80, 0xA1, 0x00, 0x00]), 0x6E00);
    assert_eq!(card.sw(&[0x84, 0xA1, 0x00, 0x00]), 0x6E00);
    assert_eq!(card.sw(&[0x40, 0xA1, 0x00, 0x00]), 0x6E00);
    assert_eq!(card.sw(&[0x01, 0xA1, 0x00, 0x00]), 0x6881);
    assert_eq!(card.sw(&[0x04, 0xA1, 0x00, 0x00]), 0x6882);
    assert_eq!(card.sw(&[0x0C, 0xA1, 0x00, 0x00]), 0x6882);
    assert_eq!(card.sw(&apdu(0x0C, 0x01, 0, 0, &totp(b"sm"))), 0x6882);
    assert_eq!(card.sw(&apdu(0x1C, 0x01, 0, 0, &totp(b"sm"))), 0x6882);
    assert_eq!(card.writes(), 1);
    assert_eq!(card.sw(&[0x00, 0xA1, 0x00]), 0x6700);
    assert_eq!(card.sw(&[0x00, 0xA1, 0x00, 0x00, 0x05, 0x01]), 0x6700);
    // The credential survived all of it.
    assert_eq!(card.names(), vec![b"t".to_vec()]);
}

/// ISO/IEC 7816-4 §5.1.1.1 command chaining: a PUT split over CLA `10` parts is
/// assembled; a header change mid-chain is `6883`.
#[test]
fn command_chaining_assembles_put() {
    let mut card = Card::new();
    let data = totp(b"chained");
    let (first, second) = data.split_at(10);
    let (first_a, first_b) = first.split_at(4);
    assert_eq!(card.sw(&apdu(0x10, 0x01, 0, 0, first_a)), OK);
    assert_eq!(card.sw(&apdu(0x10, 0x01, 0, 0, first_b)), OK);
    assert_eq!(card.writes(), 0);
    assert_eq!(card.sw(&apdu(0x00, 0x01, 0, 0, second)), OK);
    assert_eq!(card.names(), vec![b"chained".to_vec()]);
    // A different command in the middle of a chain is refused and drops the chain.
    assert_eq!(card.sw(&apdu(0x10, 0x01, 0, 0, first)), OK);
    assert_eq!(card.sw(&apdu(0x00, 0x02, 0, 0, second)), 0x6883);
    assert_eq!(card.sw(&apdu(0x00, 0x01, 0, 0, second)), 0x6A80);
    assert_eq!(card.names(), vec![b"chained".to_vec()]);
}

// --- only increasing ------------------------------------------------------------------

/// YKOATH §PUT property `01` "only increasing" (catalog "only-increasing property" and
/// "durable ... only-increasing state"): a lower challenge is `6982`, an equal one is
/// allowed, and the last challenge survives a restart. CALCULATE ALL applies the same
/// rule.
#[test]
fn only_increasing_property_is_enforced_and_durable() {
    let mut card = Card::new();
    assert_eq!(card.put(&put_data(b"inc", TOTP | SHA1, 8, RFC_SECRET, Some(0x01), None)), OK);
    assert_eq!(card.code(b"inc", &10u64.to_be_bytes()), card_code_at(10));
    assert_eq!(card.calc_truncated(b"inc", &9u64.to_be_bytes()), Err(0x6982));
    assert_eq!(card.code(b"inc", &10u64.to_be_bytes()), card_code_at(10));
    // Numeric comparison: a shorter encoding of a larger T is larger.
    assert_eq!(card.code(b"inc", &[0x0B]), {
        let mac = lk_crypto::hmac_sha1(RFC_SECRET, &[0x0B]);
        let o = usize::from(mac[19] & 0x0F);
        u32::from_be_bytes([mac[o] & 0x7F, mac[o + 1], mac[o + 2], mac[o + 3]]) % 100_000_000
    });
    card.restart();
    assert_eq!(card.calc_truncated(b"inc", &10u64.to_be_bytes()), Err(0x6982));
    assert_eq!(card.sw(&calculate_all_apdu(&10u64.to_be_bytes(), true)), 0x6982);
    assert_eq!(card.sw(&calculate_all_apdu(&12u64.to_be_bytes(), true)), OK);
    card.restart();
    assert_eq!(card.calc_truncated(b"inc", &11u64.to_be_bytes()), Err(0x6982));
    assert!(card.calc_truncated(b"inc", &12u64.to_be_bytes()).is_ok());
}

fn card_code_at(t: u64) -> u32 {
    let mac = lk_crypto::hmac_sha1(RFC_SECRET, &t.to_be_bytes());
    let o = usize::from(mac[19] & 0x0F);
    u32::from_be_bytes([mac[o] & 0x7F, mac[o + 1], mac[o + 2], mac[o + 3]]) % 100_000_000
}

// --- CALCULATE ALL --------------------------------------------------------------------

/// YKOATH §CALCULATE ALL (catalog "full/truncated CALCULATE ALL and HOTP/touch
/// placeholders without HOTP counter consumption").
#[test]
fn calculate_all_full_truncated_and_placeholders() {
    let mut card = Card::new();
    assert_eq!(card.put(&totp(b"totp")), OK);
    assert_eq!(card.put(&hotp(b"hotp")), OK);
    assert_eq!(card.put(&put_data(b"touch", TOTP | SHA256, 7, &[3; 32], Some(0x02), None)), OK);
    assert_eq!(card.put(&put_data(b"hotp-touch", HOTP | SHA1, 8, RFC_SECRET, Some(0x02), None)), OK);
    let challenge = 1u64.to_be_bytes();
    for truncated in [true, false] {
        let outcome = card.outcome(&calculate_all_apdu(&challenge, truncated));
        let Outcome::Done(first) = outcome else {
            panic!("CALCULATE ALL must not wait for a touch")
        };
        let (data, sw) = card.drain(first);
        assert_eq!(sw, OK);
        let fields = parse_tlvs(&data);
        let tags: Vec<u8> = fields.iter().map(|f| f.0).collect();
        let response = if truncated { 0x76 } else { 0x75 };
        assert_eq!(tags, vec![0x71, response, 0x71, 0x77, 0x71, 0x7C, 0x71, 0x77]);
        assert_eq!(fields[3].1, vec![6]);
        assert_eq!(fields[5].1, vec![7]);
        assert_eq!(fields[7].1, vec![8]);
        if truncated {
            assert_eq!(code_of(&fields[1].1), 94_287_082);
        } else {
            assert_eq!(fields[1].1[1..], lk_crypto::hmac_sha1(RFC_SECRET, &challenge)[..]);
        }
    }
    // No HOTP counter was consumed: the first CALCULATE still uses counter 0.
    assert_eq!(card.code(b"hotp", &[]), 755_224);
    // CALCULATE ALL requires the challenge.
    assert_eq!(card.sw(&apdu(0, 0xA4, 0, 1, &[])), 0x6A80);
    assert_eq!(card.sw(&apdu(0, 0xA4, 0, 1, &tlv(0x74, &[0; 65]))), 0x6A80);
}

// --- touch ----------------------------------------------------------------------------

/// YKOATH §PUT property `02` "require touch": CALCULATE answers NeedTouch and finishes
/// in `touch_resolved`; a refused touch is `6982` and consumes nothing.
#[test]
fn touch_credentials_wait_for_presence() {
    let mut card = Card::new();
    assert_eq!(card.put(&put_data(b"t", TOTP | SHA1, 8, RFC_SECRET, Some(0x02), None)), OK);
    assert_eq!(card.put(&put_data(b"h", HOTP | SHA1, 6, RFC_SECRET, Some(0x02), None)), OK);
    let challenge = 1u64.to_be_bytes();
    assert_eq!(
        card.outcome(&calculate_apdu(b"t", &challenge, true)),
        Outcome::NeedTouch {
            timeout_ms: TOUCH_TIMEOUT_MS
        }
    );
    let resp = card.touch(true);
    assert_eq!(code_of(&expect_object(&resp, 0x76).unwrap()), 94_287_082);
    // Nothing pending any more.
    assert_eq!(card.touch(true), vec![0x69, 0x85]);

    // HOTP with touch: the counter is consumed only when the touch arrives.
    assert!(matches!(card.outcome(&calculate_apdu(b"h", &[], true)), Outcome::NeedTouch { .. }));
    let attempts = card.host.persist_attempts();
    assert_eq!(card.touch(false), vec![0x69, 0x82]);
    assert_eq!(card.host.persist_attempts(), attempts);
    assert!(matches!(card.outcome(&calculate_apdu(b"h", &[], true)), Outcome::NeedTouch { .. }));
    let resp = card.touch(true);
    assert_eq!(code_of(&expect_object(&resp, 0x76).unwrap()), 755_224);
    card.restart();
    assert!(matches!(card.outcome(&calculate_apdu(b"h", &[], false)), Outcome::NeedTouch { .. }));
    let resp = card.touch(true);
    assert_eq!(expect_object(&resp, 0x75).unwrap()[1..], hex(RFC4226_COUNT1)[..]);

    // The pending calculation is dropped by deselect, resets and new commands.
    assert!(matches!(card.outcome(&calculate_apdu(b"t", &challenge, true)), Outcome::NeedTouch { .. }));
    card.oath.deselect();
    assert_eq!(card.touch(true), vec![0x69, 0x85]);
    assert!(matches!(card.outcome(&calculate_apdu(b"t", &challenge, true)), Outcome::NeedTouch { .. }));
    card.oath.reset(ResetKind::UsbReset);
    assert_eq!(card.touch(true), vec![0x69, 0x85]);
    assert!(matches!(card.outcome(&calculate_apdu(b"t", &challenge, true)), Outcome::NeedTouch { .. }));
    assert_eq!(card.list().len(), 2);
    assert_eq!(card.touch(true), vec![0x69, 0x85]);
    // Errors are reported before asking for a touch.
    assert_eq!(card.send(&calculate_apdu(b"zz", &challenge, true)), vec![0x69, 0x84]);
}

/// RFC 4226 Appendix D, count 1.
const RFC4226_COUNT1: &str = "75a48a19d4cbe100644e8ac1397eea747a2d33ab";

/// A touch CALCULATE whose result does not fit the command's Le continues with SEND
/// REMAINING like any other response.
#[test]
fn touch_response_honours_le() {
    let mut card = Card::new();
    assert_eq!(card.put(&put_data(b"t", TOTP | SHA512, 8, &[1; 64], Some(0x02), None)), OK);
    let mut cmd = calculate_apdu(b"t", &[0; 8], false);
    cmd.push(0x20);
    assert!(matches!(card.outcome(&cmd), Outcome::NeedTouch { .. }));
    let first = card.touch(true);
    assert_eq!(first.len(), 0x20 + 2);
    assert_eq!(first[0x20], 0x61);
    let (data, sw) = card.drain(first);
    assert_eq!(sw, OK);
    assert_eq!(data.len(), 2 + 1 + 64);
}

// --- access key -----------------------------------------------------------------------

/// RFC 6070 §2 PBKDF2-HMAC-SHA1 vectors for the test-side key derivation.
#[test]
fn pbkdf2_helper_matches_rfc6070() {
    assert_eq!(
        pbkdf2_hmac_sha1(b"password", b"salt", 1, 20),
        hex("0c60c80f961f0e71f3a9b524af6012062fe037a6")
    );
    assert_eq!(
        pbkdf2_hmac_sha1(b"password", b"salt", 2, 20),
        hex("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957")
    );
    assert_eq!(
        pbkdf2_hmac_sha1(b"password", b"salt", 4096, 20),
        hex("4b007901b765489abead49d926f721d065a429c1")
    );
    assert_eq!(
        pbkdf2_hmac_sha1(b"passwordPASSWORDpassword", b"saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25),
        hex("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038")
    );
}

/// Catalog "access key mutual challenge-response" and "mutual SDK access-code
/// validation and independent PBKDF2 derivation": the client derives the key with
/// PBKDF2 from the SELECT salt, sets it (YKOATH §SET CODE), and must VALIDATE after
/// each SELECT; the device's answer proves it knows the key too. The key survives a
/// restart and `73 00` removes it. A wrong password is `6A80`: YKOATH §VALIDATE lists
/// only "auth not enabled" `6984` and "wrong syntax" `6A80` as failures, the catalog
/// fixes no status for a wrong proof, and public YKOATH clients recognise a wrong
/// password by `6A80`.
#[test]
fn access_key_flow_with_pbkdf2() {
    let mut card = Card::new();
    assert_eq!(card.put(&totp(b"t")), OK);
    let key = lock(&mut card, b"correct horse");
    // The session that set the key stays authorized.
    assert_eq!(card.names(), vec![b"t".to_vec()]);

    card.select();
    assert_eq!(card.sw(&LIST), 0x6982);
    assert_eq!(unlock(&mut card, &key), OK);
    assert_eq!(card.names(), vec![b"t".to_vec()]);

    // A wrong password fails with 6A80 and drops the authorization; the same SELECT
    // challenge may then be answered correctly.
    let fields = card.select_fields();
    let challenge = field(&fields, 0x74).unwrap();
    let wrong = pbkdf2_hmac_sha1(b"wrong", &card.salt(), 1000, 16);
    // (`salt()` re-selected; fetch the new challenge.)
    let fields = card.select_fields();
    let challenge2 = field(&fields, 0x74).unwrap();
    assert_ne!(challenge, challenge2);
    assert_eq!(card.sw(&validate_apdu(&lk_crypto::hmac_sha1(&wrong, &challenge2), &[1; 8])), 0x6A80);
    assert_eq!(card.sw(&LIST), 0x6982);
    let resp = card.send(&validate_apdu(&lk_crypto::hmac_sha1(&key, &challenge2), &[2; 4]));
    assert_eq!(expect_object(&resp, 0x75).unwrap(), lk_crypto::hmac_sha1(&key, &[2; 4]).to_vec());
    assert_eq!(card.sw(&LIST), OK);
    // A later failed attempt revokes it again.
    assert_eq!(card.sw(&validate_apdu(&[0; 20], &[1; 8])), 0x6A80);
    assert_eq!(card.sw(&LIST), 0x6982);

    card.restart();
    assert_eq!(card.sw(&LIST), 0x6982);
    assert_eq!(unlock(&mut card, &wrong), 0x6A80);
    assert_eq!(unlock(&mut card, &key), OK);
    // Remove the access key.
    assert_eq!(card.sw(&apdu(0, 0x03, 0, 0, &tlv(0x73, &[]))), OK);
    let fields = card.select_fields();
    assert_eq!(fields.len(), 2);
    assert_eq!(card.names(), vec![b"t".to_vec()]);
    card.restart();
    assert_eq!(card.select_fields().len(), 2);
    assert_eq!(card.sw(&LIST), OK);
}

/// YKOATH §VALIDATE note: while an access key is set, LIST, PUT, DELETE, SET CODE,
/// RENAME, CALCULATE and CALCULATE ALL need a validated session (`6982`); RESET does
/// not.
#[test]
fn access_key_guards_every_credential_command() {
    let mut card = Card::new();
    assert_eq!(card.put(&totp(b"t")), OK);
    let key = lock(&mut card, b"pw");
    card.select();
    let attempts = card.host.persist_attempts();
    for cmd in [
        LIST.to_vec(),
        apdu(0, 0x01, 0, 0, &totp(b"u")),
        delete_apdu(b"t"),
        set_code_apdu(&[9; 16], &[0; 8]),
        apdu(0, 0x03, 0, 0, &tlv(0x73, &[])),
        rename_apdu(b"t", b"v"),
        calculate_apdu(b"t", &[0; 8], true),
        calculate_all_apdu(&[0; 8], true),
    ] {
        assert_eq!(card.sw(&cmd), 0x6982, "{cmd:02X?}");
    }
    assert_eq!(card.host.persist_attempts(), attempts);
    assert_eq!(unlock(&mut card, &key), OK);
    assert_eq!(card.names(), vec![b"t".to_vec()]);
}

/// Authorization is per selection (YKOATH §SELECT starts a session): a new SELECT,
/// deselect or any reset kind requires VALIDATE again.
#[test]
fn authorization_is_per_selection() {
    let mut card = Card::new();
    let key = lock(&mut card, b"pw");
    for end in 0..4 {
        assert_eq!(unlock(&mut card, &key), OK);
        assert_eq!(card.sw(&LIST), OK);
        match end {
            0 => {
                card.select();
            }
            1 => card.oath.deselect(),
            2 => card.oath.reset(ResetKind::CardPowerOff),
            _ => card.oath.reset(ResetKind::PowerCycle),
        }
        assert_eq!(card.sw(&LIST), 0x6982, "case {end}");
    }
    // Without a SELECT challenge VALIDATE cannot succeed.
    card.oath.deselect();
    assert_eq!(card.sw(&validate_apdu(&[0; 20], &[1; 8])), 0x6984);
}

/// `oath_profile.validate_without_access_code_status`: VALIDATE without an access key
/// is `6984`; malformed VALIDATE data is `6A80` ("variable VALIDATE challenge" of
/// 1..=64 bytes, SHA-1 proof of 20 bytes).
#[test]
fn validate_boundaries() {
    let mut card = Card::new();
    card.select();
    assert_eq!(card.sw(&validate_apdu(&[0; 20], &[1; 8])), 0x6984);
    assert_eq!(card.sw(&apdu(0, 0xA3, 0, 0, &[])), 0x6984);

    let key = lock(&mut card, b"pw");
    let challenge = field(&card.select_fields(), 0x74).unwrap();
    let proof = lk_crypto::hmac_sha1(&key, &challenge);
    let attempts = card.host.persist_attempts();
    assert_eq!(card.sw(&validate_apdu(&proof[..19], &[1; 8])), 0x6A80);
    assert_eq!(card.sw(&validate_apdu(&[proof.as_slice(), &[0]].concat(), &[1; 8])), 0x6A80);
    assert_eq!(card.sw(&validate_apdu(&proof, &[])), 0x6A80);
    assert_eq!(card.sw(&validate_apdu(&proof, &[1; 65])), 0x6A80);
    assert_eq!(card.sw(&apdu(0, 0xA3, 0, 0, &tlv(0x75, &proof))), 0x6A80);
    assert_eq!(card.sw(&apdu(0, 0xA3, 0, 0, &[tlv(0x75, &proof), tlv(0x74, &[1]), tlv(0x71, b"x")].concat())), 0x6A80);
    // Challenge order does not matter, and 1- and 64-byte host challenges work.
    let resp = card.send(&apdu(0, 0xA3, 0, 0, &[tlv(0x74, &[7]), tlv(0x75, &proof)].concat()));
    assert_eq!(expect_object(&resp, 0x75).unwrap(), lk_crypto::hmac_sha1(&key, &[7]).to_vec());
    let resp = card.send(&validate_apdu(&proof, &[8; 64]));
    assert_eq!(expect_object(&resp, 0x75).unwrap(), lk_crypto::hmac_sha1(&key, &[8; 64]).to_vec());
    assert_eq!(card.host.persist_attempts(), attempts);
}

/// Catalog "eight-byte SET CODE challenge ... SHA1 proof length; incorrect SET CODE
/// proof returns 6984": anything else is refused before writing.
#[test]
fn set_code_boundaries() {
    let mut card = Card::new();
    let key = [0x33; 16];
    let set = |key_field: &[u8], challenge: &[u8], response: &[u8]| {
        let mut data = tlv(0x73, key_field);
        data.extend(tlv(0x74, challenge));
        data.extend(tlv(0x75, response));
        apdu(0, 0x03, 0, 0, &data)
    };
    let key_field = [&[0x21][..], &key].concat();
    let proof = |c: &[u8]| lk_crypto::hmac_sha1(&key, c).to_vec();
    assert_eq!(card.sw(&set(&key_field, &[1; 7], &proof(&[1; 7]))), 0x6A80);
    assert_eq!(card.sw(&set(&key_field, &[1; 9], &proof(&[1; 9]))), 0x6A80);
    assert_eq!(card.sw(&set(&key_field, &[1; 8], &proof(&[1; 8])[..19])), 0x6A80);
    assert_eq!(card.sw(&set(&key_field, &[1; 8], &[0; 32])), 0x6A80);
    assert_eq!(card.sw(&set(&[0x24, 1, 2], &[1; 8], &[0; 20])), 0x6A80);
    assert_eq!(card.sw(&set(&[0x21], &[1; 8], &[0; 20])), 0x6A80);
    assert_eq!(card.sw(&apdu(0, 0x03, 0, 0, &tlv(0x73, &key_field))), 0x6A80);
    assert_eq!(card.sw(&apdu(0, 0x03, 0, 0, &[tlv(0x73, &[]), tlv(0x74, &[1; 8])].concat())), 0x6A80);
    assert_eq!(card.sw(&apdu(0, 0x03, 0, 0, &[])), 0x6A80);
    let mut wrong = proof(&[1; 8]);
    wrong[0] ^= 1;
    assert_eq!(card.sw(&set(&key_field, &[1; 8], &wrong)), 0x6984);
    assert_eq!(card.writes(), 0);
    assert_eq!(card.select_fields().len(), 2);
    assert_eq!(card.sw(&set(&key_field, &[1; 8], &proof(&[1; 8]))), OK);
    assert_eq!(card.select_fields().len(), 4);
}

/// SET CODE with an HMAC-SHA256 access key: SELECT reports `7B 02` and VALIDATE uses
/// 32-byte responses (YKOATH §SET CODE / §VALIDATE, algorithm from the key byte).
#[test]
fn sha256_access_key() {
    let mut card = Card::new();
    let key = [0x44; 16];
    let challenge = [5; 8];
    let mut data = tlv(0x73, &[&[0x22][..], &key].concat());
    data.extend(tlv(0x74, &challenge));
    data.extend(tlv(0x75, &lk_crypto::hmac_sha256(&key, &challenge)));
    assert_eq!(card.sw(&apdu(0, 0x03, 0, 0, &data)), OK);
    let fields = card.select_fields();
    assert_eq!(field(&fields, 0x7B), Some(vec![0x02]));
    let device_challenge = field(&fields, 0x74).unwrap();
    assert_eq!(card.sw(&validate_apdu(&lk_crypto::hmac_sha1(&key, &device_challenge), &[1; 8])), 0x6A80);
    let resp = card.send(&validate_apdu(&lk_crypto::hmac_sha256(&key, &device_challenge), &[1; 8]));
    assert_eq!(expect_object(&resp, 0x75).unwrap(), lk_crypto::hmac_sha256(&key, &[1; 8]).to_vec());
    assert_eq!(card.sw(&LIST), OK);
}

/// Changing the access key while authorized re-binds the session to the new key
/// (catalog "authorization is bound to ... access key and rotation revision"); the old
/// key then fails VALIDATE as a wrong response (`6A80`, YKOATH §VALIDATE).
#[test]
fn changing_the_access_key() {
    let mut card = Card::new();
    let old = lock(&mut card, b"old");
    assert_eq!(unlock(&mut card, &old), OK);
    let new = pbkdf2_hmac_sha1(b"new", &card.salt(), 1000, 16);
    assert_eq!(unlock(&mut card, &old), OK);
    assert_eq!(card.sw(&set_code_apdu(&new, &[3; 8])), OK);
    assert_eq!(card.sw(&LIST), OK);
    assert_eq!(unlock(&mut card, &old), 0x6A80);
    assert_eq!(unlock(&mut card, &new), OK);
}

// --- RESET ----------------------------------------------------------------------------

/// YKOATH §RESET and catalog "reset" / "locked app reset rotates OATH salt": RESET
/// needs no authentication, removes credentials and the access key, changes the salt
/// and writes only the OATH record.
#[test]
fn reset_while_locked_rotates_salt() {
    let mut card = Card::new();
    assert_eq!(card.put(&totp(b"t")), OK);
    lock(&mut card, b"pw");
    card.host.set_persisted(Record::Piv, b"piv state");
    let old_salt = card.salt();
    assert_eq!(card.sw(&LIST), 0x6982);
    assert_eq!(card.sw(&[0x00, 0x04, 0xDE, 0xAD]), OK);
    let fields = card.select_fields();
    assert_eq!(fields.len(), 2);
    assert_ne!(field(&fields, 0x71).unwrap(), old_salt);
    assert!(card.list().is_empty());
    assert_eq!(card.host.persisted(Record::Piv), Some(b"piv state".to_vec()));
    card.restart();
    assert_eq!(card.salt(), field(&fields, 0x71).unwrap());
    assert!(card.list().is_empty());
}

// --- SEND REMAINING -------------------------------------------------------------------

fn fill_long_names(card: &mut Card, count: u8) {
    for i in 0..count {
        let name: Vec<u8> = std::iter::repeat_n(b'n', 60).chain([i]).collect();
        assert_eq!(card.put(&totp(&name)), OK);
    }
}

/// YKOATH §SEND REMAINING: a long LIST ends with `61xx` and continues with `00 A5`.
#[test]
fn send_remaining_serves_long_list() {
    let mut card = Card::new();
    fill_long_names(&mut card, 20);
    let first = card.send(&LIST);
    assert_eq!(first.len(), 256 + 2);
    assert_eq!(first[256], 0x61);
    let (data, sw) = card.drain(first);
    assert_eq!(sw, OK);
    assert_eq!(data.len(), 20 * 64);
    assert_eq!(card.list().len(), 20);
    // CALCULATE ALL of 64 long names continues the same way.
    fill_long_names(&mut card, 64);
    let (data, sw) = card.send_all(&calculate_all_apdu(&[0; 8], false));
    assert_eq!(sw, OK);
    assert_eq!(parse_tlvs(&data).len(), 128);
}

/// Catalog "SEND REMAINING rejects nonzero CLA before consuming a pending response":
/// a bad CLA (or P1/P2, or data) leaves the continuation intact.
#[test]
fn send_remaining_rejects_bad_cla_without_consuming() {
    let mut card = Card::new();
    fill_long_names(&mut card, 8);
    let first = card.send(&LIST);
    assert_eq!(first[first.len() - 2], 0x61);
    let mut data = first[..first.len() - 2].to_vec();
    assert_eq!(card.send(&[0x80, 0xA5, 0x00, 0x00]), vec![0x6E, 0x00]);
    assert_eq!(card.send(&[0x84, 0xA5, 0x00, 0x00]), vec![0x6E, 0x00]);
    assert_eq!(card.send(&[0x10, 0xA5, 0x00, 0x00]), vec![0x6E, 0x00]);
    assert_eq!(card.send(&[0x01, 0xA5, 0x00, 0x00]), vec![0x68, 0x81]);
    // Secure-messaging bits are nonzero CLA too: continuations arrive with CLA 00 (the
    // device's secure channel clears the bits of commands it unwraps).
    assert_eq!(card.send(&[0x04, 0xA5, 0x00, 0x00]), vec![0x68, 0x82]);
    assert_eq!(card.send(&[0x08, 0xA5, 0x00, 0x00]), vec![0x68, 0x82]);
    assert_eq!(card.send(&[0x0C, 0xA5, 0x00, 0x00]), vec![0x68, 0x82]);
    assert_eq!(card.send(&[0x1C, 0xA5, 0x00, 0x00]), vec![0x68, 0x82]);
    assert_eq!(card.send(&[0x00, 0xA5, 0x01, 0x00]), vec![0x6A, 0x86]);
    assert_eq!(card.send(&[0x00, 0xA5, 0x00, 0x00, 0x01, 0x00]), vec![0x67, 0x00]);
    let next = card.send(&SEND_REMAINING);
    let (rest, sw) = card.drain(next);
    assert_eq!(sw, OK);
    data.extend(rest);
    assert_eq!(parse_tlvs(&data).len(), 8);
    // Nothing pending: 6985.
    assert_eq!(card.send(&SEND_REMAINING), vec![0x69, 0x85]);
    // Any other command drops a pending continuation.
    let first = card.send(&LIST);
    assert_eq!(first[first.len() - 2], 0x61);
    assert_eq!(card.put(&totp(b"x")), OK);
    assert_eq!(card.send(&SEND_REMAINING), vec![0x69, 0x85]);
    // So does a new selection.
    let first = card.send(&LIST);
    assert_eq!(first[first.len() - 2], 0x61);
    card.select();
    assert_eq!(card.send(&SEND_REMAINING), vec![0x69, 0x85]);
}

/// ISO/IEC 7816-4 §5.1: the pieces follow the command's Le (`00` = 256).
#[test]
fn le_sets_the_piece_size() {
    let mut card = Card::new();
    fill_long_names(&mut card, 2);
    let first = card.send(&[0x00, 0xA1, 0x00, 0x00, 0x10]);
    assert_eq!(first.len(), 0x10 + 2);
    assert_eq!(&first[0x10..], &[0x61, 128 - 16]);
    let second = card.send(&[0x00, 0xA5, 0x00, 0x00, 0x20]);
    assert_eq!(second.len(), 0x20 + 2);
    assert_eq!(&second[0x20..], &[0x61, 128 - 48]);
    let third = card.send(&[0x00, 0xA5, 0x00, 0x00, 0x00]);
    assert_eq!(third.len(), 80 + 2);
    assert_eq!(&third[80..], &[0x90, 0x00]);
}

// --- persistence ----------------------------------------------------------------------

/// `docs/DESIGN.md` §7: the HOTP counter is persisted before the code is returned, so
/// a restart after every CALCULATE continues with the next RFC 4226 code.
#[test]
fn hotp_counter_is_persisted_before_the_code() {
    let mut card = Card::new();
    assert_eq!(card.put(&hotp(b"h")), OK);
    for expected in [755_224, 287_082, 359_152, 969_429] {
        let before = card.host.persist_count();
        assert_eq!(card.code(b"h", &[]), expected);
        assert_eq!(card.host.persist_count(), before + 1);
        card.restart();
    }
}

/// `docs/CONTRACTS.md` "Persisted state": on a storage failure every command answers
/// `6581` and keeps the previous state; an HOTP code is not revealed and its counter
/// not consumed.
#[test]
fn storage_failures_keep_the_previous_state() {
    let mut card = Card::new();
    assert_eq!(card.put(&hotp(b"h")), OK);
    assert_eq!(card.put(&put_data(b"inc", TOTP | SHA1, 8, RFC_SECRET, Some(0x01), None)), OK);

    card.host.fail_next_saves(1);
    assert_eq!(card.put(&totp(b"new")), 0x6581);
    assert_eq!(card.names(), vec![b"h".to_vec(), b"inc".to_vec()]);

    card.host.fail_next_saves(1);
    assert_eq!(card.send(&calculate_apdu(b"h", &[], true)), vec![0x65, 0x81]);
    assert_eq!(card.code(b"h", &[]), 755_224);

    card.host.fail_next_saves(1);
    assert_eq!(card.send(&calculate_apdu(b"inc", &5u64.to_be_bytes(), true)), vec![0x65, 0x81]);
    assert!(card.calc_truncated(b"inc", &4u64.to_be_bytes()).is_ok());

    card.host.fail_next_saves(1);
    assert_eq!(card.sw(&calculate_all_apdu(&9u64.to_be_bytes(), true)), 0x6581);
    assert!(card.calc_truncated(b"inc", &5u64.to_be_bytes()).is_ok());

    card.host.fail_next_saves(1);
    assert_eq!(card.sw(&delete_apdu(b"h")), 0x6581);
    card.host.fail_next_saves(1);
    assert_eq!(card.sw(&rename_apdu(b"h", b"g")), 0x6581);
    assert_eq!(card.names(), vec![b"h".to_vec(), b"inc".to_vec()]);

    let salt = card.salt();
    card.host.fail_next_saves(1);
    assert_eq!(card.sw(&set_code_apdu(&[1; 16], &[2; 8])), 0x6581);
    assert_eq!(card.select_fields().len(), 2);

    card.host.fail_next_saves(1);
    assert_eq!(card.sw(&[0x00, 0x04, 0xDE, 0xAD]), 0x6581);
    assert_eq!(card.salt(), salt);
    assert_eq!(card.names().len(), 2);

    // And what was committed is what a restart sees.
    card.restart();
    assert_eq!(card.salt(), salt);
    assert_eq!(card.code(b"h", &[]), 287_082);
}

/// `new(stored)` restores everything. Missing state is factory state, and `new` stores
/// it at once so that the device id (YKOATH §SELECT tag `71`, the PBKDF2 salt) is the
/// same after a restart even before the first mutating command: yubikit and
/// yubikit-android derive `device_id = base64(SHA-256(salt)[..16])` from it, and ykman
/// and Yubico Authenticator key remembered passwords by that id (`docs/CONTRACTS.md`
/// "Constructors may persist"; requirement of the final review). A stored record that
/// does not decode is factory state too, but opening never overwrites it
/// (`docs/DESIGN.md` §7: only a commit of an OATH command replaces the record).
#[test]
fn restart_and_unreadable_state() {
    let mut card = Card::new();
    // Construction stored the factory state: exactly one save, nothing else.
    assert_eq!(card.host.persist_attempts(), 1);
    assert_eq!(card.host.persist_count(), 1);
    assert!(card.host.persisted(Record::Oath).is_some());
    let salt = card.salt();
    // The device id survives restarts without any command that changes state, and a
    // restart from the stored record writes nothing.
    for _ in 0..3 {
        card.restart();
        assert_eq!(card.salt(), salt);
        assert!(card.list().is_empty());
    }
    assert_eq!(card.host.persist_attempts(), 1);
    assert_eq!(card.put(&totp(b"t")), OK);
    let key = lock(&mut card, b"pw");
    card.restart();
    assert_eq!(card.salt(), salt);
    assert_eq!(unlock(&mut card, &key), OK);
    assert_eq!(card.names(), vec![b"t".to_vec()]);

    for garbage in [&[][..], &[0x02, 0x80, 0x08], &[0x01, 0x80, 0x07, 1, 2, 3, 4, 5, 6, 7], &[0x01, 0xFF]] {
        let mut host = TestHost::new();
        host.set_persisted(Record::Oath, garbage);
        let mut card = Card::with_host(host);
        assert_eq!(card.select_fields().len(), 2);
        assert!(card.list().is_empty());
        assert_eq!(card.host.persist_attempts(), 0);
        assert_eq!(card.host.persisted(Record::Oath), Some(garbage.to_vec()));
    }
}

/// The factory save of `Oath::new` may be rejected by the store. The applet still
/// works from the factory state in memory, and the first commit stores that state,
/// salt included, so the device id the host already saw is the one a restart finds
/// (`docs/DESIGN.md` §7: every commit writes the whole state).
#[test]
fn rejected_factory_save_is_stored_by_the_first_commit() {
    let mut host = TestHost::new();
    host.fail_next_saves(1);
    let mut card = Card::with_host(host);
    assert_eq!(card.host.persist_attempts(), 1);
    assert_eq!(card.host.persisted(Record::Oath), None);
    let salt = card.salt();
    assert!(card.list().is_empty());
    assert_eq!(card.put(&totp(b"t")), OK);
    card.restart();
    assert_eq!(card.salt(), salt);
    assert_eq!(card.names(), vec![b"t".to_vec()]);
}

// --- review additions -----------------------------------------------------------------

/// RFC 4226 §5.3 step 3 and YKOATH §PUT "Digits": the digits byte (6, 7 or 8) comes
/// back first in every `76`/`75`/`77` object and selects the code length; the four
/// truncated bytes do not depend on it. Vectors: RFC 4226 Appendix D count 0
/// (truncated value 1284755224) and RFC 6238 Appendix B T = 1 SHA-1 (94287082),
/// reduced modulo 10^6 and 10^7.
#[test]
fn digits_6_7_8_select_the_code_length() {
    let mut card = Card::new();
    for digits in [6u8, 7, 8] {
        let name = [b'h', b'0' + digits];
        assert_eq!(card.put(&put_data(&name, HOTP | SHA1, digits, RFC_SECRET, None, None)), OK);
        let name = [b't', b'0' + digits];
        assert_eq!(card.put(&put_data(&name, TOTP | SHA1, digits, RFC_SECRET, None, None)), OK);
    }
    let expected_hotp = [(6u8, 755_224u32), (7, 4_755_224), (8, 84_755_224)];
    for (digits, code) in expected_hotp {
        let value = card.calc_truncated(&[b'h', b'0' + digits], &[]).unwrap();
        assert_eq!(value[0], digits);
        assert_eq!(value[1..], [0x4C, 0x93, 0xCF, 0x18]);
        assert_eq!(code_of(&value), code, "{digits} digits");
    }
    let t1 = 1u64.to_be_bytes();
    for (digits, code) in [(6u8, 287_082u32), (7, 4_287_082), (8, 94_287_082)] {
        assert_eq!(card.code(&[b't', b'0' + digits], &t1), code, "{digits} digits");
        let full = card.calc_full(&[b't', b'0' + digits], &t1).unwrap();
        assert_eq!(full[0], digits);
        assert_eq!(full.len(), 1 + 20);
    }
    // CALCULATE ALL carries the digits in every object, placeholders included.
    let (data, sw) = card.send_all(&calculate_all_apdu(&t1, true));
    assert_eq!(sw, OK);
    let fields = parse_tlvs(&data);
    let digits: Vec<(u8, u8)> = fields.iter().skip(1).step_by(2).map(|(tag, v)| (*tag, v[0])).collect();
    assert_eq!(digits, vec![(0x77, 6), (0x76, 6), (0x77, 7), (0x76, 7), (0x77, 8), (0x76, 8)]);
}

/// YKOATH §PUT "Name ... max 64 bytes" at the boundary, for PUT, RENAME, CALCULATE,
/// LIST and DELETE.
#[test]
fn name_length_boundaries() {
    let mut card = Card::new();
    let longest = [b'L'; 64];
    let other = [b'M'; 64];
    assert_eq!(card.put(&hotp(&longest)), OK);
    assert_eq!(card.put(&hotp(&[b'L'; 65])), 0x6A80);
    assert_eq!(card.list(), vec![(0x11, longest.to_vec())]);
    assert_eq!(card.code(&longest, &[]), 755_224);
    assert_eq!(card.sw(&rename_apdu(&longest, &[b'M'; 65])), 0x6A80);
    assert_eq!(card.sw(&rename_apdu(&longest, &other)), OK);
    assert_eq!(card.code(&other, &[]), 287_082);
    assert_eq!(card.sw(&delete_apdu(&other)), OK);
    assert!(card.list().is_empty());
}

/// YKOATH §CALCULATE ALL with every kind of credential at once: TOTP (`76`), HOTP
/// (`77`), touch (`7C`), HOTP with touch (`77`), "only increasing" with and without
/// touch. Placeholders consume nothing: no HOTP counter step, and an "only
/// increasing" touch credential whose last challenge is higher neither fails the
/// command nor has its last challenge moved. The only-increasing TOTP credential that
/// is computed has its challenge raised durably (catalog "durable IMF/only-increasing
/// state").
#[test]
fn calculate_all_mixed_types_touch_and_only_increasing() {
    let mut card = Card::new();
    assert_eq!(card.put(&put_data(b"a", TOTP | SHA256, 7, &[3; 32], None, None)), OK);
    assert_eq!(card.put(&put_data(b"b", HOTP | SHA512, 8, &[4; 64], Some(0x02), Some(7))), OK);
    assert_eq!(card.put(&put_data(b"c", TOTP | SHA1, 8, RFC_SECRET, Some(0x03), None)), OK);
    assert_eq!(card.put(&put_data(b"d", TOTP | SHA1, 6, RFC_SECRET, Some(0x01), None)), OK);
    assert_eq!(card.put(&hotp(b"e")), OK);

    // Raise "c" to T = 100 through a touched CALCULATE.
    assert!(matches!(
        card.outcome(&calculate_apdu(b"c", &100u64.to_be_bytes(), true)),
        Outcome::NeedTouch { .. }
    ));
    assert_eq!(card.touch(true)[..2], [0x76, 0x05]);

    let t = 50u64.to_be_bytes();
    let (data, sw) = card.send_all(&calculate_all_apdu(&t, true));
    assert_eq!(sw, OK);
    let fields = parse_tlvs(&data);
    let truncated = |hash, key: &[u8], digits: u8| {
        let mac = lk_crypto::hmac(hash, key, &t);
        let o = usize::from(mac[mac.len() - 1] & 0x0F);
        vec![digits, mac[o] & 0x7F, mac[o + 1], mac[o + 2], mac[o + 3]]
    };
    assert_eq!(
        fields,
        vec![
            (0x71, b"a".to_vec()),
            (0x76, truncated(lk_crypto::HashAlg::Sha256, &[3; 32], 7)),
            (0x71, b"b".to_vec()),
            (0x77, vec![8]),
            (0x71, b"c".to_vec()),
            (0x7C, vec![8]),
            (0x71, b"d".to_vec()),
            (0x76, truncated(lk_crypto::HashAlg::Sha1, RFC_SECRET, 6)),
            (0x71, b"e".to_vec()),
            (0x77, vec![6]),
        ]
    );

    // No HOTP counter moved: "e" starts at 0 and "b" at its IMF 7.
    assert_eq!(card.code(b"e", &[]), 755_224);
    assert!(matches!(card.outcome(&calculate_apdu(b"b", &[], false)), Outcome::NeedTouch { .. }));
    let full = expect_object(&card.touch(true), 0x75).unwrap();
    assert_eq!(full[1..], lk_crypto::hmac(lk_crypto::HashAlg::Sha512, &[4; 64], &7u64.to_be_bytes())[..]);
    // "c" still refuses anything below 100, without asking for a touch.
    assert_eq!(card.send(&calculate_apdu(b"c", &99u64.to_be_bytes(), true)), vec![0x69, 0x82]);
    // "d" was raised to 50, durably.
    card.restart();
    assert_eq!(card.calc_truncated(b"d", &49u64.to_be_bytes()), Err(0x6982));
    assert_eq!(card.sw(&calculate_all_apdu(&49u64.to_be_bytes(), true)), 0x6982);
    assert!(card.calc_truncated(b"d", &t).is_ok());
}

/// `docs/DESIGN.md` §7 / `lk_core::Host::persist` through the touch path: when the
/// store fails after the touch, the HOTP code is not revealed (`6581`) and the counter
/// is not consumed, in memory or on disk.
#[test]
fn touch_hotp_storage_failure_consumes_nothing() {
    let mut card = Card::new();
    assert_eq!(card.put(&put_data(b"h", HOTP | SHA1, 6, RFC_SECRET, Some(0x02), None)), OK);
    for _ in 0..2 {
        assert!(matches!(card.outcome(&calculate_apdu(b"h", &[], true)), Outcome::NeedTouch { .. }));
        let count = card.host.persist_count();
        card.host.fail_next_saves(1);
        assert_eq!(card.touch(true), vec![0x65, 0x81]);
        assert_eq!(card.host.persist_count(), count);
    }
    assert!(matches!(card.outcome(&calculate_apdu(b"h", &[], true)), Outcome::NeedTouch { .. }));
    assert_eq!(code_of(&expect_object(&card.touch(true), 0x76).unwrap()), 755_224);
    card.restart();
    assert!(matches!(card.outcome(&calculate_apdu(b"h", &[], true)), Outcome::NeedTouch { .. }));
    assert_eq!(code_of(&expect_object(&card.touch(true), 0x76).unwrap()), 287_082);
}

/// `docs/CONTRACTS.md` "Persisted state" for an overwriting PUT: a failed store keeps
/// the old credential whole (type, key and HOTP counter), in memory and on disk.
#[test]
fn put_overwrite_storage_failure_keeps_old_credential() {
    let mut card = Card::new();
    assert_eq!(card.put(&hotp(b"x")), OK);
    assert_eq!(card.code(b"x", &[]), 755_224);
    card.host.fail_next_saves(1);
    assert_eq!(card.put(&put_data(b"x", TOTP | SHA256, 8, &[9; 32], Some(0x02), None)), 0x6581);
    assert_eq!(card.list(), vec![(0x11, b"x".to_vec())]);
    assert_eq!(card.code(b"x", &[]), 287_082);
    card.restart();
    assert_eq!(card.code(b"x", &[]), 359_152);
}

/// A failed VALIDATE ends the pending LIST continuation and the authorization: the
/// next SEND REMAINING returns no data and LIST needs a new VALIDATE (single-session
/// form of the catalog "pending LIST continuation reject"; ISO/IEC 7816-4 §5.1.3: a
/// command other than the continuation ends a pending response).
#[test]
fn failed_validate_drops_pending_continuation() {
    let mut card = Card::new();
    fill_long_names(&mut card, 8);
    let key = lock(&mut card, b"pw");
    assert_eq!(unlock(&mut card, &key), OK);
    let first = card.send(&LIST);
    assert_eq!(first[first.len() - 2], 0x61);
    assert_eq!(card.sw(&validate_apdu(&[0; 20], &[1; 8])), 0x6A80);
    assert_eq!(card.send(&SEND_REMAINING), vec![0x69, 0x85]);
    assert_eq!(card.sw(&LIST), 0x6982);
    assert_eq!(card.send(&SEND_REMAINING), vec![0x69, 0x85]);
    // VALIDATE again and the list is complete.
    assert_eq!(unlock(&mut card, &key), OK);
    assert_eq!(card.list().len(), 8);
}

/// YKOATH §SELECT / §SEND REMAINING: a SELECT response cut by a small Le continues with
/// SEND REMAINING even while the access key is not validated (it carries only the
/// public version, salt, challenge and algorithm).
#[test]
fn select_response_continues_while_locked() {
    let mut card = Card::new();
    lock(&mut card, b"pw");
    let mut select = SELECT.to_vec();
    select.push(0x04);
    let first = card.oath.select(&select, &mut card.host);
    assert_eq!(first.len(), 4 + 2);
    assert_eq!(first[4], 0x61);
    let (data, sw) = card.drain(first);
    assert_eq!(sw, OK);
    let tags: Vec<u8> = parse_tlvs(&data).iter().map(|f| f.0).collect();
    assert_eq!(tags, vec![0x79, 0x71, 0x74, 0x7B]);
    assert_eq!(card.sw(&LIST), 0x6982);
}

/// ISO/IEC 7816-4 §5.1.1.1: SEND REMAINING in the middle of a command chain is a header
/// change (`6883`); the chain is dropped and nothing is written.
#[test]
fn send_remaining_in_the_middle_of_a_chain() {
    let mut card = Card::new();
    let data = totp(b"chained");
    let (first, second) = data.split_at(10);
    assert_eq!(card.sw(&apdu(0x10, 0x01, 0, 0, first)), OK);
    assert_eq!(card.send(&SEND_REMAINING), vec![0x68, 0x83]);
    assert_eq!(card.sw(&apdu(0x00, 0x01, 0, 0, second)), 0x6A80);
    assert_eq!(card.writes(), 0);
    assert!(card.list().is_empty());
}
