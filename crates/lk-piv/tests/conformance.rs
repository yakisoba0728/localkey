//! Independent review: SP 800-73-4 conformance points and hardening checks that the
//! stage 1/2 suites did not cover. Each test names the clause it checks.

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use lk_codec::tlv;
use lk_core::{CardApplet, Outcome, Record};
use lk_piv::Piv;
use lk_testkit::TestHost;

const DIGEST: [u8; 32] = [0x6B; 32];

/// Mutual authentication step 2 with an explicit `82 00`; returns the status word.
fn mutual_with_response_request(card: &mut Card, alg: u8, key: &[u8], extra: &[u8]) -> u16 {
    let (resp, sw) = card.cmd(0x87, alg, 0x9B, &hex("7C028000"), Some(0));
    assert_eq!(sw, 0x9000);
    let witness = decrypt(alg, key, &dyn_auth_item(&resp, 0x80));
    let challenge = vec![0x5Au8; block_len(alg)];
    let mut inner = tlv::encode(0x80, &witness);
    tlv::encode_into(&mut inner, 0x81, &challenge);
    inner.extend_from_slice(extra);
    let (resp, sw) = card.cmd(0x87, alg, 0x9B, &tlv::encode(0x7C, &inner), Some(0));
    if sw == 0x9000 {
        assert_eq!(dyn_auth_item(&resp, 0x82), encrypt(alg, key, &challenge));
    }
    sw
}

fn management_authenticated(card: &mut Card) -> bool {
    // PUT DATA needs the management key (SP 800-73-4 Part 2 §3.3.1); an empty 53 on an
    // absent object changes nothing visible.
    card.cmd(0xDB, 0x3F, 0xFF, &Card::put_payload(0x5FC10E, &[]), None).1 == 0x9000
}

#[test]
fn mutual_authentication_accepts_the_table_19_form() {
    // SP 800-73-4 Part 2 Appendix A.2, Table 19: step 2 is
    // `7C 16 80 08 <witness> 81 08 <challenge> 82 00` with Le 00; Table 7: an empty tag
    // requests that element. The Yubico form without `82 00` is covered elsewhere.
    let mut card = Card::new();
    let key = hex(DEFAULT_MGMT_KEY);
    assert_eq!(mutual_with_response_request(&mut card, ALG_AES192, &key, &hex("8200")), 0x9000);
    assert!(management_authenticated(&mut card));
    let tdes = hex("0102030405060708 1112131415161718 2122232425262728");
    let mut card = Card::new();
    card.auth_default();
    assert_eq!(card.set_mgmt_key(ALG_TDES, &tdes, false), 0x9000);
    card.new_session();
    assert!(!management_authenticated(&mut card));
    assert_eq!(mutual_with_response_request(&mut card, ALG_TDES, &tdes, &hex("8200")), 0x9000);
    assert!(management_authenticated(&mut card));
    // Other trailing elements are still malformed: a non-empty 82, a repeated 82, 85.
    for extra in ["820100", "82008200", "8500", "8000"] {
        let mut card = Card::new();
        let key = hex(DEFAULT_MGMT_KEY);
        assert_eq!(mutual_with_response_request(&mut card, ALG_AES192, &key, &hex(extra)), 0x6A80, "{extra}");
        assert!(!management_authenticated(&mut card), "{extra}");
    }
}

#[test]
fn short_responses_honour_ne() {
    // ISO/IEC 7816-4 §5.1: at most Ne bytes are returned; the rest follows with 61xx and
    // GET RESPONSE whose Le names the length (SP 800-73-4 Part 2 Appendix A.4.1,
    // command 3).
    let mut card = Card::new();
    let (full, sw) = card.get_object(0x5FFF01);
    assert_eq!(sw, 0x9000);
    assert!(full.len() > 300);
    let (first, sw) = card.cmd(0xCB, 0x3F, 0xFF, &hex("5C035FFF01"), Some(0x10));
    assert_eq!(first.len(), 0x10);
    let left = full.len() - 0x10;
    assert_eq!(sw, lk_codec::apdu::sw::more_data(left));
    let mut all = first;
    let (piece, sw) = card.send("00C0000020");
    assert_eq!(piece.len(), 0x20, "GET RESPONSE Le 20");
    assert_eq!(sw >> 8, 0x61);
    all.extend(piece);
    let next = card_get_response(&mut card);
    let (rest, sw) = card.collect(next);
    assert_eq!(sw, 0x9000);
    all.extend(rest);
    assert_eq!(all, full);
    // Le 00 is Ne = 256; no Le behaves the same.
    let (first, sw) = card.cmd(0xCB, 0x3F, 0xFF, &hex("5C035FFF01"), Some(0));
    assert_eq!((first.len(), sw >> 8), (256, 0x61));
    let (first, sw) = card.cmd(0xCB, 0x3F, 0xFF, &hex("5C035FFF01"), None);
    assert_eq!((first.len(), sw >> 8), (256, 0x61));
    // An extended command with a small Ne is served the same way.
    let mut cmd = lk_codec::apdu::Command::new(0x00, 0xCB, 0x3F, 0xFF).with_data(hex("5C035FFF01"));
    cmd.le = Some(0x40);
    cmd.extended = true;
    let (first, sw) = card.raw(&cmd.to_bytes());
    assert_eq!((first.len(), sw >> 8), (0x40, 0x61));
    // The size of the pieces travels with a touch-gated operation.
    let mut card = Card::new();
    card.auth_default();
    let public = card.generate(0x9D, RSA2048, Some(PIN_NEVER), Some(TOUCH_ALWAYS));
    let m = representative(public.modulus(), 0x31);
    let mut inner = tlv::encode(0x82, &[]);
    tlv::encode_into(&mut inner, 0x81, &m);
    let payload = tlv::encode(0x7C, &inner);
    let (head, tail) = payload.split_at(200);
    assert_eq!(card.raw(&apdu(0x10, 0x87, RSA2048, 0x9D, head, None)).1, 0x9000);
    let outcome = card.outcome(&apdu(0x00, 0x87, RSA2048, 0x9D, tail, Some(0x80)));
    assert!(matches!(outcome, Outcome::NeedTouch { .. }));
    let resp = card.piv.touch_resolved(true, &mut card.host);
    assert_eq!(resp.len(), 0x80 + 2, "Ne = 0x80 after the touch");
    let next = card_get_response(&mut card);
    let (rest, sw) = card.collect(next);
    assert_eq!(sw, 0x9000);
    let mut all = resp[..0x80].to_vec();
    all.extend(rest);
    let s = dyn_auth_item(&all, 0x82);
    assert_eq!(lk_crypto::rsa_public_op(public.modulus(), &[1, 0, 1], &s).unwrap(), m);
}

/// One GET RESPONSE with Le 00.
fn card_get_response(card: &mut Card) -> (Vec<u8>, u16) {
    card.send("00C0000000")
}

#[test]
fn change_pin_sets_the_security_status() {
    // SP 800-73-4 Part 2 §3.2.2: "If the card command succeeds, then the security status
    // of the key reference shall be set to TRUE"; on 63CX it "shall be set to FALSE".
    let mut card = Card::new();
    assert_eq!(card.pin_status(), 0x63C3);
    let new_pin = pad(b"246810");
    let mut data = hex(DEFAULT_PIN);
    data.extend_from_slice(&new_pin);
    assert_eq!(card.cmd(0x24, 0x00, 0x80, &data, None).1, 0x9000);
    assert_eq!(card.pin_status(), 0x9000, "verified by the change");
    // A wrong current PIN clears it again.
    let mut wrong = pad(b"999999");
    wrong.extend_from_slice(&pad(b"135791"));
    assert_eq!(card.cmd(0x24, 0x00, 0x80, &wrong, None).1, 0x63C2);
    assert_eq!(card.pin_status(), 0x63C2);
    // Only VERIFY arms a PIN-always key (crate model policy).
    card.auth_default();
    let always = card.generate(0x9C, P256, Some(PIN_ALWAYS), None);
    let mut data = new_pin.clone();
    data.extend_from_slice(&pad(b"112233"));
    assert_eq!(card.cmd(0x24, 0x00, 0x80, &data, None).1, 0x9000);
    assert_eq!(card.ga(0x9C, P256, 0x81, &DIGEST).1, 0x6982);
    assert_eq!(card.verify_pin(&pad(b"112233")), 0x9000);
    let (sig, sw) = card.ga(0x9C, P256, 0x81, &DIGEST);
    assert_eq!(sw, 0x9000);
    assert!(ecdsa_ok(P256, always.point(), &DIGEST, &sig));
    // Changing the PUK does not touch the PIN's status.
    card.send("0020FF80");
    let mut data = hex(DEFAULT_PUK);
    data.extend_from_slice(&pad(b"8765432"));
    assert_eq!(card.cmd(0x24, 0x00, 0x81, &data, None).1, 0x9000);
    assert_eq!(card.pin_status(), 0x63C3);
}

#[test]
fn reset_retry_counter_and_the_pin_security_status() {
    // SP 800-73-4 Part 2 §3.2.3: on 63CX "the security status of the PIN's key reference
    // shall be set to FALSE"; on success it "shall not be changed".
    let mut card = Card::new();
    card.verify_default_pin();
    let mut wrong = pad(b"00000000");
    wrong.extend_from_slice(&pad(b"135790"));
    assert_eq!(card.cmd(0x2C, 0x00, 0x80, &wrong, None).1, 0x63C2);
    assert_eq!(card.pin_status(), 0x63C3, "a wrong PUK clears the PIN status");
    // Success while verified: stays verified, with the new PIN in force.
    card.verify_default_pin();
    let mut right = hex(DEFAULT_PUK);
    right.extend_from_slice(&pad(b"135790"));
    assert_eq!(card.cmd(0x2C, 0x00, 0x80, &right, None).1, 0x9000);
    assert_eq!(card.pin_status(), 0x9000, "unchanged: still verified");
    assert_eq!(card.metadata(0x81).0, hex("0101FF 050101 06020303"), "PUK counter restored");
    // Success while not verified: stays unverified.
    card.send("0020FF80");
    let mut right = hex(DEFAULT_PUK);
    right.extend_from_slice(&pad(b"246802"));
    assert_eq!(card.cmd(0x2C, 0x00, 0x80, &right, None).1, 0x9000);
    assert_eq!(card.pin_status(), 0x63C3, "unchanged: still not verified");
    assert_eq!(card.verify_pin(&pad(b"246802")), 0x9000);
    // A storage failure (6581, nothing compared) leaves the PIN status alone.
    let base = card.host.persisted(Record::Piv);
    card.host.fail_next_saves(1);
    assert_eq!(card.cmd(0x2C, 0x00, 0x80, &wrong, None).1, 0x6581);
    assert_eq!(card.pin_status(), 0x9000);
    assert_eq!(card.host.persisted(Record::Piv), base);
}

#[test]
fn malformed_pin_data_is_refused_without_consuming_a_retry() {
    // SP 800-73-4 Part 2 §3.2.1.1: PIN data that does not satisfy §2.4.3 fails with
    // 6A80 (security status and retry counter unchanged) or 63CX; footnote 7 recommends
    // not comparing it. §3.2.2 likewise for the current PIN of CHANGE REFERENCE DATA.
    let mut card = Card::new();
    card.verify_default_pin();
    let base = card.host.persist_count();
    for bad in ["3132333435FFFFFF", "FFFFFFFFFFFFFFFF", "313233343536FF37", "31FF323334353637"] {
        assert_eq!(card.verify_pin(&hex(bad)), 0x6A80, "VERIFY {bad}");
        let mut data = hex(bad);
        data.extend_from_slice(&pad(b"654321"));
        assert_eq!(card.cmd(0x24, 0x00, 0x80, &data, None).1, 0x6A80, "CHANGE {bad}");
    }
    assert_eq!(card.host.persist_count(), base, "nothing consumed");
    assert_eq!(card.pin_status(), 0x9000, "security status unchanged");
    assert_eq!(card.metadata(0x80).0, hex("0101FF 050101 06020303"));
    // The PUK may be any 8-byte value (§2.4.3), so it is compared and counted.
    let mut data = hex("0000000000000000");
    data.extend_from_slice(&pad(b"87654321"));
    assert_eq!(card.cmd(0x24, 0x00, 0x81, &data, None).1, 0x63C2);
}

#[test]
fn generate_accepts_the_rsa_exponent_parameter() {
    // SP 800-73-4 Part 2 §3.3.2 Table 11: AC may carry the mechanism-specific parameter
    // `81`; for RSA it is the public exponent, and this model generates only 65537.
    let mut card = Card::new();
    card.auth_default();
    for exponent in ["010001", "00010001"] {
        let mut inner = tlv::encode(0x80, &[RSA1024]);
        tlv::encode_into(&mut inner, 0x81, &hex(exponent));
        let first = card.cmd(0x47, 0x00, 0x9A, &tlv::encode(0xAC, &inner), Some(0));
        let (data, sw) = card.collect(first);
        assert_eq!(sw, 0x9000, "{exponent}");
        let Public::Rsa { e, .. } = parse_public_template(&data) else { panic!("RSA") };
        assert_eq!(e, hex("010001"));
    }
    let before = card.host.persisted(Record::Piv);
    for (alg, parameter) in [(RSA1024, "03"), (RSA1024, "010003"), (RSA1024, ""), (P256, "010001"), (ED25519, "00")] {
        let mut inner = tlv::encode(0x80, &[alg]);
        tlv::encode_into(&mut inner, 0x81, &hex(parameter));
        assert_eq!(card.cmd(0x47, 0x00, 0x9A, &tlv::encode(0xAC, &inner), None).1, 0x6A80, "{alg:02X} {parameter}");
    }
    let mut inner = tlv::encode(0x80, &[RSA1024]);
    tlv::encode_into(&mut inner, 0x81, &hex("010001"));
    tlv::encode_into(&mut inner, 0x81, &hex("010001"));
    assert_eq!(card.cmd(0x47, 0x00, 0x9A, &tlv::encode(0xAC, &inner), None).1, 0x6A80, "repeated 81");
    assert_eq!(card.host.persisted(Record::Piv), before, "rejections change nothing");
}

#[test]
fn touch_cache_is_filled_only_by_a_successful_operation() {
    // Yubico: "Touch is cached for 15s after use". A touched operation that then fails
    // (an X25519 peer key giving the all-zero secret, RFC 7748 §6.1) does not count.
    let mut card = Card::new();
    card.auth_default();
    card.generate(0x9A, X25519, Some(PIN_NEVER), Some(TOUCH_ALWAYS));
    let cached = card.generate(0x9E, P256, Some(PIN_NEVER), Some(TOUCH_CACHED));
    assert!(matches!(card.ga_outcome(0x9A, X25519, 0x85, &[0; 32]), Outcome::NeedTouch { .. }));
    assert_eq!(card.touch(true).1, 0x6A80);
    assert!(matches!(card.ga_outcome(0x9E, P256, 0x81, &DIGEST), Outcome::NeedTouch { .. }), "not cached");
    let (sig, sw) = card.touch(true);
    assert_eq!(sw, 0x9000);
    assert!(ecdsa_ok(P256, cached.point(), &DIGEST, &sig));
    let (sig, sw) = card.ga(0x9E, P256, 0x81, &DIGEST);
    assert_eq!(sw, 0x9000, "cached now");
    assert!(ecdsa_ok(P256, cached.point(), &DIGEST, &sig));
}

#[test]
fn oversized_own_certificate_is_not_stored() {
    // attest::initialize: a 5FFF01 value longer than a PUT DATA could write (3072 bytes,
    // piv_allocation_model.plaintext_apdu_data_limit) would make the record unreadable on
    // load. It is left out, and the record stays readable: the F9 key is created once.
    let mut host = TestHost::new();
    host.profile_mut().attestation_common_name = "x".repeat(4000);
    let mut card = Card::with_host(host);
    assert_eq!(card.get_object(0x5FFF01).1, 0x6A82);
    let f9 = card.slot_info(0xF9).unwrap();
    let count = card.host.persist_count();
    card.restart();
    assert_eq!(card.slot_info(0xF9).unwrap(), f9, "same key after restart");
    assert_eq!(card.host.persist_count(), count, "nothing re-initialized");
}

#[test]
fn piv_new_tolerates_a_failed_initial_save() {
    // lk_core::Host::persist: a failed save keeps the in-memory state; Piv::new ignores
    // it and the next successful commit stores the whole state, F9 key included.
    let mut host = TestHost::new();
    host.fail_next_saves(1);
    let mut piv = Piv::new(None, &mut host);
    assert!(host.persisted(Record::Piv).is_none());
    piv.select(&hex(SELECT), &mut host);
    let mut card = Card { piv, host };
    let f9 = card.slot_info(0xF9).unwrap();
    card.verify_default_pin();
    card.restart();
    assert_eq!(card.slot_info(0xF9).unwrap(), f9);
}
