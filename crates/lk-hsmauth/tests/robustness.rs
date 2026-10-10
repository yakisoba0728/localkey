//! Credential password retries, touch, RESET, volatile state, persistence, storage
//! failure and malformed input.
//!
//! Sources: yubikit `hsmauth.py` (`INITIAL_RETRY_COUNTER = 8`, `63Cx` via
//! `_retries_from_sw`, RESET `00 06 DE AD`), ykman `handle_error` (`6982` "The device
//! was not touched"), `reference/BEHAVIOR_CATALOG.md` YubiHSMAuth (deletion on the eighth
//! wrong password, RESET APDU shape, challenge/touch separation), `docs/CONTRACTS.md`
//! (persist before success, `6581` on storage failure, unreadable state is factory).

mod common;

use common::*;
use lk_codec::apdu::sw;
use lk_core::{CardApplet, DeviceProfile, Entropy, Host, Millis, Outcome, Record, ResetKind, StoreError};
use lk_hsmauth::{MAX_CREDENTIALS, TOUCH_TIMEOUT_MS, ins, tag};
use lk_testkit::TestHost;

fn sym_calc(label: &str, password: [u8; 16]) -> Vec<u8> {
    apdu(ins::CALCULATE, 0, 0, &calculate_data(label, &[0x33; 16], None, None, &password))
}

#[test]
fn wrong_credential_password_decrements_and_correct_resets() {
    let mut card = Card::new();
    assert_eq!(card.put_symmetric("c", [1; 16], [2; 16], pw("right")), sw::OK);
    for left in [7u8, 6, 5] {
        assert_eq!(card.send_raw(&sym_calc("c", pw("wrong"))), (vec![], sw::retries(left)));
        assert_eq!(card.retries_of("c"), Some(left));
    }
    let (keys, status) = card.send_raw(&sym_calc("c", pw("right")));
    assert_eq!((keys.len(), status), (48, sw::OK));
    assert_eq!(card.retries_of("c"), Some(8));
    // A password differing only in padding is a different password.
    let mut almost = pw("right");
    almost[15] = 1;
    assert_eq!(card.send_raw(&sym_calc("c", almost)).1, sw::retries(7));
}

/// Catalog: "credential deleted on eighth wrong password with ephemeral state cleared,
/// label recoverable after restart" (the restart half is
/// `deleted_label_is_reusable_after_restart`).
#[test]
fn eighth_wrong_password_deletes_credential_and_clears_challenge() {
    let password = pw("right");
    let mut card = Card::new();
    let credential = test_key("victim/SK.OCE");
    let pk = credential.public_uncompressed();
    let put = Put::asymmetric("victim", Some(credential.scalar().to_vec()), password);
    assert_eq!(card.put(&put), sw::OK);
    let hsm = HsmSide::new("hsm");
    // Seven wrong CALCULATEs, each with a fresh challenge so the password is checked.
    for left in (1..8).rev() {
        let (epk, _) = card.get_challenge("victim", None);
        let s = hsm.respond(&epk, &pk);
        let data = calculate_data("victim", &s.context, Some(&hsm.public()), Some(&s.receipt), &pw("wrong"));
        assert_eq!(card.cmd(ins::CALCULATE, &data).1, sw::retries(left));
        assert_eq!(card.retries_of("victim"), Some(left));
    }
    // The eighth deletes the credential while an ephemeral key is outstanding.
    let (epk, status) = card.get_challenge("victim", None);
    assert_eq!(status, sw::OK);
    let last = hsm.respond(&epk, &pk);
    let wrong = calculate_data("victim", &last.context, Some(&hsm.public()), Some(&last.receipt), &pw("wrong"));
    assert_eq!(card.cmd(ins::CALCULATE, &wrong).1, sw::retries(0));
    assert!(card.list().is_empty());
    let right = calculate_data("victim", &last.context, Some(&hsm.public()), Some(&last.receipt), &password);
    assert_eq!(card.cmd(ins::CALCULATE, &right).1, sw::FILE_NOT_FOUND);
    assert_eq!(card.get_challenge("victim", None).1, sw::FILE_NOT_FOUND);
    // Re-creating the label does not revive the old ephemeral key.
    assert_eq!(card.put(&put), sw::OK);
    assert_eq!(card.cmd(ins::CALCULATE, &right).1, sw::DATA_INVALID);

    // The same through GET CHALLENGE with a password (5.7.1+), on a symmetric credential.
    assert_eq!(card.put_symmetric("sym", [1; 16], [2; 16], password), sw::OK);
    for left in (0..8).rev() {
        assert_eq!(card.get_challenge("sym", Some(pw("wrong"))), (vec![], sw::retries(left)));
    }
    assert_eq!(card.labels(), vec![b"victim".to_vec()]);
}

#[test]
fn deleted_label_is_reusable_after_restart() {
    let mut card = Card::new();
    assert_eq!(card.put_symmetric("gone", [1; 16], [2; 16], pw("right")), sw::OK);
    for left in (0..8).rev() {
        assert_eq!(card.send_raw(&sym_calc("gone", pw("wrong"))).1, sw::retries(left));
    }
    let mut card = card.restart();
    assert!(card.list().is_empty(), "deletion was persisted");
    assert_eq!(card.put_symmetric("gone", [5; 16], [6; 16], pw("new")), sw::OK);
    assert_eq!(card.retries_of("gone"), Some(8));
    let (keys, status) = card.send_raw(&sym_calc("gone", pw("new")));
    assert_eq!(status, sw::OK);
    assert_eq!(keys[..16], sp800_108_cmac(&[5; 16], constant::S_ENC, &[0x33; 16], 128)[..]);
}

/// `lk_core::Host::persist`: retry counters are persisted before the response that
/// reveals them, so a power cut cannot replay a try.
#[test]
fn wrong_password_counter_is_persisted_before_response() {
    let mut card = Card::new();
    assert_eq!(card.put_symmetric("c", [1; 16], [2; 16], pw("right")), sw::OK);
    assert_eq!(card.send_raw(&sym_calc("c", pw("wrong"))).1, sw::retries(7));
    let mut card = card.restart();
    assert_eq!(card.retries_of("c"), Some(7));
    // Storage failure: no try consumed, nothing revealed, `6581`.
    card.host.fail_next_saves(1);
    assert_eq!(card.send_raw(&sym_calc("c", pw("wrong"))), (vec![], sw::MEMORY_FAILURE));
    assert_eq!(card.retries_of("c"), Some(7));
    // The reset-to-8 after a correct password is persisted before the keys go out.
    card.host.fail_next_saves(1);
    assert_eq!(card.send_raw(&sym_calc("c", pw("right"))), (vec![], sw::MEMORY_FAILURE));
    assert_eq!(card.retries_of("c"), Some(7));
    assert_eq!(card.send_raw(&sym_calc("c", pw("right"))).1, sw::OK);
    let mut card = card.restart();
    assert_eq!(card.retries_of("c"), Some(8));
    // Wrong management key try is persisted too.
    assert_eq!(card.delete(&[1; 16], "c"), sw::retries(7));
    let mut card = card.restart();
    assert_eq!(card.management_retries(), 7);
    card.host.fail_next_saves(1);
    assert_eq!(card.delete(&[1; 16], "c"), sw::MEMORY_FAILURE);
    assert_eq!(card.management_retries(), 7);
}

/// yubikit `get_challenge(label, credential_password)` on 5.7.1+: a supplied password is
/// verified with the same retry rules.
#[test]
fn get_challenge_with_password_verifies_it() {
    let mut card = Card::new();
    assert_eq!(card.put_symmetric("c", [1; 16], [2; 16], pw("right")), sw::OK);
    assert_eq!(card.get_challenge("c", Some(pw("wrong"))), (vec![], sw::retries(7)));
    let (challenge, status) = card.get_challenge("c", Some(pw("right")));
    assert_eq!((challenge.len(), status), (8, sw::OK));
    assert_eq!(card.retries_of("c"), Some(8));
    let mut d = tlv(tag::LABEL, b"c");
    d.extend(tlv(tag::CREDENTIAL_PASSWORD, b"short"));
    assert_eq!(card.cmd(ins::GET_CHALLENGE, &d).1, sw::INCORRECT_DATA);
    assert_eq!(card.get_challenge("missing", None).1, sw::FILE_NOT_FOUND);
}

#[test]
fn touch_required_calculate_waits_for_touch() {
    let mut card = Card::new();
    let password = pw("t");
    assert_eq!(card.put(&Put::symmetric("t", [1; 16], [2; 16], password).touch(true)), sw::OK);
    let out = card.raw(&sym_calc("t", password));
    assert_eq!(out, Outcome::NeedTouch { timeout_ms: TOUCH_TIMEOUT_MS });
    let resp = card.app.touch_resolved(true, &mut card.host);
    let (keys, status) = split(&resp);
    assert_eq!(status, sw::OK);
    assert_eq!(keys[..16], sp800_108_cmac(&[1; 16], constant::S_ENC, &[0x33; 16], 128)[..]);
    assert_eq!(keys[16..32], sp800_108_cmac(&[2; 16], constant::S_MAC, &[0x33; 16], 128)[..]);
    // Nothing is pending any more.
    assert_eq!(split(&card.app.touch_resolved(true, &mut card.host)).1, sw::CONDITIONS);
}

/// ykman: `6982` "The device was not touched" (declined, timed out or cancelled).
#[test]
fn touch_declined_or_timed_out_returns_6982() {
    let mut card = Card::new();
    let password = pw("t");
    assert_eq!(card.put(&Put::symmetric("t", [1; 16], [2; 16], password).touch(true)), sw::OK);
    assert!(matches!(card.raw(&sym_calc("t", password)), Outcome::NeedTouch { .. }));
    assert_eq!(card.app.touch_resolved(false, &mut card.host), hex("6982"));
    // Wrong password and syntax errors answer at once, without a touch request.
    assert_eq!(card.send_raw(&sym_calc("t", pw("wrong"))).1, sw::retries(7));
    let bad = apdu(ins::CALCULATE, 0, 0, &calculate_data("t", &[0; 3], None, None, &password));
    assert_eq!(card.send_raw(&bad).1, sw::INCORRECT_DATA);
}

#[test]
fn asymmetric_touch_required_calculate_waits_for_touch() {
    let password = pw("t");
    let mut card = Card::new();
    let credential = test_key("touch/SK.OCE");
    let put = Put::asymmetric("t", Some(credential.scalar().to_vec()), password).touch(true);
    assert_eq!(card.put(&put), sw::OK);
    // GET CHALLENGE never waits (catalog `hsmauth_symmetric_challenge_touch`).
    let (epk_oce, status) = card.send_raw(&apdu(ins::GET_CHALLENGE, 0, 0, &tlv(tag::LABEL, b"t")));
    assert_eq!(status, sw::OK);
    let hsm = HsmSide::new("hsm");
    let s = hsm.respond(&epk_oce, &credential.public_uncompressed());
    let data = calculate_data("t", &s.context, Some(&hsm.public()), Some(&s.receipt), &password);
    assert!(matches!(card.raw(&apdu(ins::CALCULATE, 0, 0, &data)), Outcome::NeedTouch { .. }));
    let (keys, status) = split(&card.app.touch_resolved(true, &mut card.host));
    assert_eq!((keys, status), (s.session_keys, sw::OK));
}

/// Catalog `hsmauth_symmetric_challenge_touch`: GET CHALLENGE returns its 8 bytes
/// without touch while CALCULATE on the same credential still requires touch.
#[test]
fn get_challenge_never_requires_touch() {
    let password = pw("t");
    let mut card = Card::new();
    assert_eq!(card.put(&Put::symmetric("t", [1; 16], [2; 16], password).touch(true)), sw::OK);
    let (challenge, status) = card.send_raw(&apdu(ins::GET_CHALLENGE, 0, 0, &tlv(tag::LABEL, b"t")));
    assert_eq!((challenge.len(), status), (8, sw::OK));
    let context = [challenge.as_slice(), &[9; 8]].concat();
    let calc = apdu(ins::CALCULATE, 0, 0, &calculate_data("t", &context, None, None, &password));
    assert!(matches!(card.raw(&calc), Outcome::NeedTouch { .. }));
}

/// Model decision: a new command while a CALCULATE waits for touch abandons it.
#[test]
fn new_command_while_touch_pending_cancels_it() {
    let password = pw("t");
    let mut card = Card::new();
    assert_eq!(card.put(&Put::symmetric("t", [1; 16], [2; 16], password).touch(true)), sw::OK);
    assert!(matches!(card.raw(&sym_calc("t", password)), Outcome::NeedTouch { .. }));
    assert_eq!(card.cmd(ins::GET_VERSION, &[]).1, sw::OK);
    assert_eq!(split(&card.app.touch_resolved(true, &mut card.host)).1, sw::CONDITIONS);
}

#[test]
fn deselect_and_reset_clear_volatile_state() {
    let password = pw("v");
    let mut card = Card::new();
    let credential = test_key("v/SK.OCE");
    assert_eq!(card.put(&Put::asymmetric("a", Some(credential.scalar().to_vec()), password)), sw::OK);
    assert_eq!(card.put(&Put::symmetric("t", [1; 16], [2; 16], password).touch(true)), sw::OK);
    let hsm = HsmSide::new("hsm");
    let kinds = [None, Some(ResetKind::CardPowerOff), Some(ResetKind::UsbReset), Some(ResetKind::PowerCycle)];
    for kind in kinds {
        // Outstanding ephemeral key.
        let (epk, _) = card.get_challenge("a", None);
        // Pending touch.
        assert!(matches!(card.raw(&sym_calc("t", password)), Outcome::NeedTouch { .. }));
        // Half a chained command.
        assert_eq!(card.send_raw(&[0x10, ins::PUT, 0, 0, 1, 0x7B]).1, sw::OK);
        match kind {
            None => card.app.deselect(),
            Some(kind) => card.app.reset(kind),
        }
        assert_eq!(split(&card.app.touch_resolved(true, &mut card.host)).1, sw::CONDITIONS);
        // A late "not touched" after the reset still reads as not touched.
        assert_eq!(card.app.touch_resolved(false, &mut card.host), hex("6982"));
        let s = hsm.respond(&epk, &credential.public_uncompressed());
        let data = calculate_data("a", &s.context, Some(&hsm.public()), Some(&s.receipt), &password);
        assert_eq!(card.cmd(ins::CALCULATE, &data).1, sw::DATA_INVALID, "{kind:?}");
        // The chain was dropped: an unrelated command is processed normally.
        assert_eq!(card.cmd(ins::GET_VERSION, &[]).1, sw::OK);
        let resp = card.app.select(&select_apdu(), &mut card.host);
        assert_eq!(split(&resp).1, sw::OK);
    }
    // Persistent state is untouched by all of it.
    assert_eq!(card.list().len(), 2);
}

/// Catalog `hsmauth_reset_apdu_shape`: P1P2 must be DE AD; data or an explicit Le is
/// rejected before anything is cleared.
#[test]
fn reset_requires_dead_p1p2_and_rejects_data_or_le() {
    let mut card = Card::new();
    assert_eq!(card.put_symmetric("keep", [1; 16], [2; 16], pw("p")), sw::OK);
    let saves_after_put = card.host.persist_count();
    let rejected: [(&[u8], u16); 9] = [
        (&[0x00, 0x06, 0x00, 0x00], sw::INCORRECT_P1P2),
        (&[0x00, 0x06, 0xDE, 0xAE], sw::INCORRECT_P1P2),
        (&[0x00, 0x06, 0xDE, 0xAD, 0x01, 0x00], sw::WRONG_LENGTH),
        (&[0x00, 0x06, 0xDE, 0xAD, 0x02, 0xDE, 0xAD], sw::WRONG_LENGTH),
        (&[0x00, 0x06, 0xDE, 0xAD, 0x10], sw::WRONG_LENGTH),
        // Extended explicit Le (256, 1).
        (&[0x00, 0x06, 0xDE, 0xAD, 0x00, 0x01, 0x00], sw::WRONG_LENGTH),
        (&[0x00, 0x06, 0xDE, 0xAD, 0x00, 0x00, 0x01], sw::WRONG_LENGTH),
        // Extended data (one zero byte) with Le.
        (&[0x00, 0x06, 0xDE, 0xAD, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00], sw::WRONG_LENGTH),
        (&[0x00, 0x06, 0xDE, 0xAD, 0x00, 0x00, 0x01, 0x00], sw::WRONG_LENGTH),
    ];
    for (apdu, expected) in rejected {
        assert_eq!(card.send_raw(apdu).1, expected, "{apdu:02x?}");
    }
    assert_eq!(card.labels(), vec![b"keep".to_vec()]);
    assert_eq!(card.host.persist_count(), saves_after_put, "rejected RESETs store nothing");
}

/// Catalog `hsmauth_reset_apdu_shape`: the normal SDK forms reset — `00 06 DE AD`
/// (YESDK, current yubikit extended), the ambiguous short-zero form `00 06 DE AD 00`
/// (ykhsmauth `send_data` always writes Lc; current yubikit `ShortApduFormatter` adds an
/// "explicit Lc" `00`) and its extended counterpart `00 06 DE AD 00 00 00`, which
/// yubikit 5.0's `_encode_extended_apdu` (`">BBBBBH", cla, ins, p1, p2, 0, len(data)`)
/// produces for `ykman hsmauth reset` over USB (`docs/CONTRACTS.md` "APDU conventions":
/// the extended data-less form is accepted where an explicit Le is rejected). Before
/// the review fix the extended form answered `6700`.
#[test]
fn reset_accepts_sdk_and_ambiguous_short_zero_forms() {
    let forms: [&[u8]; 3] =
        [&[0x00, 0x06, 0xDE, 0xAD], &[0x00, 0x06, 0xDE, 0xAD, 0x00], &[0x00, 0x06, 0xDE, 0xAD, 0x00, 0x00, 0x00]];
    for form in forms {
        let mut card = Card::new();
        assert_eq!(card.put_symmetric("x", [1; 16], [2; 16], pw("p")), sw::OK);
        assert_eq!(card.send_raw(form), (vec![], sw::OK), "{form:02x?}");
        assert!(card.list().is_empty());
    }
}

#[test]
fn reset_clears_credentials_and_management_key() {
    let mut card = Card::new();
    let new_key = [7u8; 16];
    assert_eq!(card.put_management_key(&DEFAULT_KEY, &new_key), sw::OK);
    assert_eq!(card.delete(&[1; 16], "x"), sw::retries(7));
    let mut put = Put::asymmetric("a", None, pw("p"));
    put.management_key = new_key;
    assert_eq!(card.put(&put), sw::OK);
    let (_epk, _) = card.get_challenge("a", None);
    assert_eq!(card.send(ins::RESET, 0xDE, 0xAD, &[]).1, sw::OK);
    assert!(card.list().is_empty());
    assert_eq!(card.management_retries(), 8);
    // Factory management key again.
    assert_eq!(card.put_symmetric("b", [1; 16], [2; 16], pw("p")), sw::OK);
    let mut card = card.restart();
    assert_eq!(card.labels(), vec![b"b".to_vec()]);
}

#[test]
fn state_survives_restart() {
    let mut card = Card::new();
    let password = pw("persist");
    let credential = test_key("p/SK.OCE");
    assert_eq!(card.put_symmetric("sym", [1; 16], [2; 16], password), sw::OK);
    assert_eq!(card.put(&Put::asymmetric("asym", Some(credential.scalar().to_vec()), password).touch(true)), sw::OK);
    assert_eq!(card.put(&Put::asymmetric("gen", None, password)), sw::OK);
    let generated = card.get_public_key("gen").0;
    assert_eq!(card.put_management_key(&DEFAULT_KEY, &[5; 16]), sw::OK);
    assert_eq!(card.send_raw(&sym_calc("sym", pw("no"))).1, sw::retries(7));
    let before = card.list();

    let mut card = card.restart();
    assert_eq!(card.list(), before);
    assert_eq!(card.get_public_key("gen").0, generated);
    assert_eq!(card.get_public_key("asym").0, credential.public_uncompressed());
    assert_eq!(card.delete(&DEFAULT_KEY, "gen"), sw::retries(7));
    assert_eq!(card.delete(&[5; 16], "gen"), sw::OK);
    let (keys, status) = card.send_raw(&sym_calc("sym", password));
    assert_eq!(status, sw::OK);
    assert_eq!(keys[32..], sp800_108_cmac(&[2; 16], constant::S_RMAC, &[0x33; 16], 128)[..]);
}

/// `docs/CONTRACTS.md`: unreadable state means factory state.
#[test]
fn unreadable_state_is_factory() {
    for garbage in [vec![], vec![0x01], vec![0x02, 0x80, 0x00], vec![0x01, 0x80, 0x10, 0x00], vec![0xFF; 40]] {
        let mut host = TestHost::new();
        host.set_persisted(Record::HsmAuth, &garbage);
        let mut card = Card::with_host(host);
        assert!(card.list().is_empty());
        assert_eq!(card.management_retries(), 8);
        assert_eq!(card.put_symmetric("x", [1; 16], [2; 16], pw("p")), sw::OK, "factory key works");
    }
}

/// `docs/CONTRACTS.md`: on a failed persist the previous in-memory state stays and the
/// answer is `6581`.
#[test]
fn storage_failure_keeps_previous_state() {
    let mut card = Card::new();
    assert_eq!(card.put_symmetric("a", [1; 16], [2; 16], pw("p")), sw::OK);
    let snapshot = card.host.persisted(Record::HsmAuth);

    card.host.fail_next_saves(1);
    assert_eq!(card.put_symmetric("b", [1; 16], [2; 16], pw("p")), sw::MEMORY_FAILURE);
    card.host.fail_next_saves(1);
    assert_eq!(card.put(&Put::asymmetric("g", None, pw("p"))), sw::MEMORY_FAILURE);
    card.host.fail_next_saves(1);
    assert_eq!(card.delete(&DEFAULT_KEY, "a"), sw::MEMORY_FAILURE);
    card.host.fail_next_saves(1);
    assert_eq!(card.put_management_key(&DEFAULT_KEY, &[9; 16]), sw::MEMORY_FAILURE);
    card.host.fail_next_saves(1);
    assert_eq!(card.send(ins::RESET, 0xDE, 0xAD, &[]).1, sw::MEMORY_FAILURE);

    assert_eq!(card.labels(), vec![b"a".to_vec()]);
    assert_eq!(card.management_retries(), 8);
    assert_eq!(card.host.persisted(Record::HsmAuth), snapshot);
    // The old management key still works and the stored state still loads.
    assert_eq!(card.put_symmetric("b", [1; 16], [2; 16], pw("p")), sw::OK);
    let mut card = card.restart();
    assert_eq!(card.labels(), vec![b"a".to_vec(), b"b".to_vec()]);

    // A failed persist of the eighth wrong password keeps the credential.
    for left in (1..8).rev() {
        assert_eq!(card.send_raw(&sym_calc("a", pw("x"))).1, sw::retries(left));
    }
    card.host.fail_all(true);
    assert_eq!(card.send_raw(&sym_calc("a", pw("x"))).1, sw::MEMORY_FAILURE);
    card.host.fail_all(false);
    assert_eq!(card.retries_of("a"), Some(1));
}

/// Fixed-seed pseudo-random malformed APDUs (DESIGN §12-4: deterministic inputs instead
/// of cargo-fuzz). No input may panic and every response ends in a status word.
///
/// A quarter of the inputs are raw noise; the rest are valid command templates (PUT,
/// DELETE, CALCULATE with real challenges and receipts, GET CHALLENGE, RESET, ...) that
/// are randomly mutated (byte flips, truncation, appended bytes, wrong passwords, chained
/// or extended framing). Credentials are re-planted when they disappear, storage faults
/// and session resets are injected, so retry counters, deletion, touch and receipt
/// verification are all reached — checked by the coverage assertions at the end.
#[test]
fn fuzzed_apdus_never_panic() {
    use lk_codec::apdu::Command;

    fn plant(card: &mut Card, credential: &lk_crypto::EcPrivateKey) {
        // End whatever the fuzzer left open (a chain, pending response data).
        card.app.reset(ResetKind::CardPowerOff);
        if card.management_retries() == 0 || card.put_symmetric("probe", [0; 16], [0; 16], pw("p")) != sw::OK {
            assert_eq!(card.send_raw(&[0x00, ins::RESET, 0xDE, 0xAD]).1, sw::OK);
        } else {
            assert_eq!(card.delete(&DEFAULT_KEY, "probe"), sw::OK);
        }
        let labels = card.labels();
        if !labels.contains(&b"sym".to_vec()) {
            assert_eq!(card.put_symmetric("sym", [1; 16], [2; 16], pw("p")), sw::OK);
        }
        if !labels.contains(&b"symt".to_vec()) {
            assert_eq!(card.put(&Put::symmetric("symt", [3; 16], [4; 16], pw("p")).touch(true)), sw::OK);
        }
        if !labels.contains(&b"asym".to_vec()) {
            let put = Put::asymmetric("asym", Some(credential.scalar().to_vec()), pw("p")).touch(true);
            assert_eq!(card.put(&put), sw::OK);
        }
    }

    let mut rng = SplitMix64(0x4853_4D41_5554_4821);
    let mut card = Card::new();
    let credential = test_key("fuzz/SK.OCE");
    let pk_oce = credential.public_uncompressed();
    let hsm = HsmSide::new("fuzz-hsm");
    let mut session = hsm.respond(&test_key("stale").public_uncompressed(), &pk_oce);
    let mut touches = 0usize;
    let mut seen = std::collections::BTreeMap::<u16, usize>::new();
    plant(&mut card, &credential);

    for round in 0..10_000 {
        if round % 250 == 0 {
            card.host.fail_next_saves(0);
            plant(&mut card, &credential);
        }
        if rng.chance(60) {
            card.host.fail_next_saves(1);
        }
        let password = if rng.chance(3) { pw("wrong") } else { pw("p") };
        let label: &str = ["sym", "symt", "asym", "none", "probe"][rng.below(5)];
        let (ins, p1p2, mut data): (u8, [u8; 2], Vec<u8>) = match rng.below(12) {
            0 => (ins::PUT, [0, 0], Put::symmetric(label, [5; 16], [6; 16], password).data()),
            1 => (ins::PUT, [0, 0], Put::asymmetric(label, None, password).touch(rng.chance(2)).data()),
            2 => {
                let key = if rng.chance(4) { [9u8; 16] } else { DEFAULT_KEY };
                let mut d = tlv(tag::MANAGEMENT_KEY, &key);
                d.extend(tlv(tag::LABEL, label.as_bytes()));
                (ins::DELETE, [0, 0], d)
            }
            3 | 4 => {
                let context = rng.bytes(16);
                (ins::CALCULATE, [0, 0], calculate_data(label, &context, None, None, &password))
            }
            5 | 6 => {
                let receipt = if rng.chance(4) { rng.bytes(16) } else { session.receipt.clone() };
                let d = calculate_data(label, &session.context, Some(&hsm.public()), Some(&receipt), &password);
                (ins::CALCULATE, [0, 0], d)
            }
            7 => {
                let mut d = tlv(tag::LABEL, label.as_bytes());
                if rng.chance(2) {
                    d.extend(tlv(tag::CREDENTIAL_PASSWORD, &password));
                }
                (ins::GET_CHALLENGE, [0, 0], d)
            }
            8 => (ins::GET_PUBLIC_KEY, [0, 0], tlv(tag::LABEL, label.as_bytes())),
            9 => {
                let current = if rng.chance(4) { [9u8; 16] } else { DEFAULT_KEY };
                let d = [tlv(tag::MANAGEMENT_KEY, &current), tlv(tag::MANAGEMENT_KEY, &DEFAULT_KEY)].concat();
                (ins::PUT_MANAGEMENT_KEY, [0, 0], d)
            }
            10 => {
                let i = [ins::LIST, ins::GET_VERSION, ins::GET_MANAGEMENT_KEY_RETRIES, ins::GET_RESPONSE, ins::CHANGE_CREDENTIAL_PASSWORD][rng.below(5)];
                (i, [0, 0], Vec::new())
            }
            _ => (ins::RESET, if rng.chance(8) { [0xDE, 0xAD] } else { [0xDE, rng.byte()] }, Vec::new()),
        };
        // Mutations.
        let mut ins = ins;
        let mut p1p2 = p1p2;
        if rng.chance(2) {
            match rng.below(6) {
                0 if !data.is_empty() => {
                    let i = rng.below(data.len());
                    data[i] ^= 1 << rng.below(8);
                }
                1 if !data.is_empty() => {
                    let cut = rng.below(data.len());
                    data.truncate(cut);
                }
                2 => {
                    let extra = rng.below(8);
                    data.extend(rng.bytes(extra));
                }
                3 => ins = rng.byte(),
                4 => p1p2 = [rng.byte(), rng.byte()],
                _ => {
                    if !data.is_empty() {
                        let i = rng.below(data.len());
                        data[i] = rng.byte();
                    }
                }
            }
        }
        let apdu = if rng.chance(4) {
            let len = rng.below(300);
            rng.bytes(len)
        } else {
            let cla = [0x00u8, 0x00, 0x00, 0x10, 0x04, 0x80][rng.below(6)];
            let mut cmd = Command::new(cla, ins, p1p2[0], p1p2[1]).with_data(data);
            if rng.chance(4) {
                cmd = cmd.with_le(u32::from(rng.byte()));
            }
            if rng.chance(8) {
                cmd.extended = true;
            }
            cmd.to_bytes()
        };
        match card.app.process(&apdu, &mut card.host) {
            Outcome::Done(resp) => {
                let (out, status) = split(&resp);
                *seen.entry(status).or_default() += 1;
                if ins == ins::GET_CHALLENGE && out.len() == 65 {
                    session = hsm.respond(&out, &pk_oce);
                }
            }
            Outcome::NeedTouch { timeout_ms } => {
                assert_eq!(timeout_ms, TOUCH_TIMEOUT_MS);
                if rng.chance(5) {
                    // Abandoned by the next command instead of resolved.
                } else {
                    if rng.chance(6) {
                        // The deferred return to eight tries may fail to persist.
                        card.host.fail_next_saves(1);
                    }
                    let resp = card.app.touch_resolved(rng.chance(2), &mut card.host);
                    *seen.entry(split(&resp).1).or_default() += 1;
                }
                touches += 1;
            }
        }
        match rng.below(300) {
            0 => card.app.deselect(),
            1 => card.app.reset(ResetKind::CardPowerOff),
            2 => {
                let resp = card.app.select(&select_apdu(), &mut card.host);
                assert_eq!(split(&resp).1, sw::OK);
            }
            _ => {}
        }
    }
    eprintln!("fuzz status words: {seen:04x?}, touch requests: {touches}");
    for expected in [
        sw::OK,
        sw::INCORRECT_DATA,
        sw::FILE_NOT_FOUND,
        sw::WRONG_LENGTH,
        sw::CLA_NOT_SUPPORTED,
        sw::INS_NOT_SUPPORTED,
        sw::MEMORY_FAILURE,
        sw::AUTH_BLOCKED,
        sw::DATA_INVALID,
        sw::SECURITY_STATUS,
        sw::INCORRECT_P1P2,
    ] {
        assert!(seen.contains_key(&expected), "never saw {expected:04x}");
    }
    assert!(seen.keys().any(|s| s & 0xFFF0 == 0x63C0), "never reached a retry counter");
    assert!(touches > 0, "never reached a touch request");
    // Whatever the run persisted must still load.
    let mut card = card.restart();
    let _ = card.list();
}

/// A touch-required symmetric credential with `tries` password tries left.
fn touch_card_with_tries(tries: u8) -> Card {
    let mut card = Card::new();
    assert_eq!(card.put(&Put::symmetric("t", [1; 16], [2; 16], pw("right")).touch(true)), sw::OK);
    for left in (tries..8).rev() {
        assert_eq!(card.send_raw(&sym_calc("t", pw("wrong"))).1, sw::retries(left));
    }
    assert_eq!(card.retries_of("t"), Some(tries));
    card
}

/// YESDK `GetAes128SessionKeysResponse` / `GetEccP256SessionKeysResponse`: "If this proof
/// of user presence fails, the Status will be set to RetryWithTouch [6982], and the
/// credential password retry count is not changed." With five tries left and the right
/// password, a declined touch leaves five (in memory and in the record). The try is
/// spent before the comparison (security review: no guessing oracle on a failing store)
/// and put back when the touch is declined or abandoned.
#[test]
fn declined_touch_leaves_password_tries_unchanged() {
    let mut card = touch_card_with_tries(5);
    assert!(matches!(card.raw(&sym_calc("t", pw("right"))), Outcome::NeedTouch { .. }));
    // (Querying LIST here would abandon the pending CALCULATE, so check the record.)
    let mut peek = Card::with_host(card.host.clone());
    assert_eq!(peek.retries_of("t"), Some(4), "the try is spent while the touch is pending");
    assert_eq!(card.app.touch_resolved(false, &mut card.host), hex("6982"));
    assert_eq!(card.retries_of("t"), Some(5));
    // Abandoned by another command instead of declined: also unchanged.
    assert!(matches!(card.raw(&sym_calc("t", pw("right"))), Outcome::NeedTouch { .. }));
    card.app.reset(ResetKind::CardPowerOff);
    assert_eq!(card.app.touch_resolved(false, &mut card.host), hex("6982"));
    let mut card = card.restart();
    assert_eq!(card.retries_of("t"), Some(5));
}

/// YESDK `GetAes128SessionKeysCommand`: "Supplying the correct password before the
/// credential is deleted will reset the retry counter to 8" — committed when the touch
/// completes, before the keys go out.
#[test]
fn touch_completion_restores_tries_before_keys() {
    let mut card = touch_card_with_tries(5);
    assert!(matches!(card.raw(&sym_calc("t", pw("right"))), Outcome::NeedTouch { .. }));
    let (keys, status) = split(&card.app.touch_resolved(true, &mut card.host));
    assert_eq!(status, sw::OK);
    assert_eq!(keys[..16], sp800_108_cmac(&[1; 16], constant::S_ENC, &[0x33; 16], 128)[..]);
    let mut card = card.restart();
    assert_eq!(card.retries_of("t"), Some(8), "persisted before the keys");
    // With all tries left the count is spent and given back: still eight.
    assert!(matches!(card.raw(&sym_calc("t", pw("right"))), Outcome::NeedTouch { .. }));
    assert_eq!(split(&card.app.touch_resolved(true, &mut card.host)).1, sw::OK);
    assert_eq!(card.retries_of("t"), Some(8));
}

/// `docs/CONTRACTS.md`: on a failed persist keep the previous state and answer `6581`.
/// If the return to eight tries cannot be stored after the touch, no key is revealed.
#[test]
fn storage_failure_after_touch_reveals_no_keys() {
    let mut card = touch_card_with_tries(5);
    assert!(matches!(card.raw(&sym_calc("t", pw("right"))), Outcome::NeedTouch { .. }));
    card.host.fail_next_saves(1);
    assert_eq!(card.app.touch_resolved(true, &mut card.host), hex("6581"));
    // The try spent before the comparison stays spent when it cannot be given back.
    assert_eq!(card.retries_of("t"), Some(4));
    // Nothing remains pending; the next attempt works normally.
    assert_eq!(split(&card.app.touch_resolved(true, &mut card.host)).1, sw::CONDITIONS);
    assert!(matches!(card.raw(&sym_calc("t", pw("right"))), Outcome::NeedTouch { .. }));
    assert_eq!(split(&card.app.touch_resolved(true, &mut card.host)).1, sw::OK);
    assert_eq!(card.retries_of("t"), Some(8));
}

/// YESDK: a correct password resets the counter to 8 (see above) — also when the
/// command then fails on the receipt (`6984`, YESDK `ReferenceDataUnusable` "invalid
/// authentication data"), and that answer comes at once, without a touch request.
#[test]
fn correct_password_with_bad_receipt_restores_tries_without_touch() {
    let password = pw("right");
    let mut card = Card::new();
    let credential = test_key("r/SK.OCE");
    let pk = credential.public_uncompressed();
    let put = Put::asymmetric("a", Some(credential.scalar().to_vec()), password).touch(true);
    assert_eq!(card.put(&put), sw::OK);
    let hsm = HsmSide::new("hsm");
    for left in [7u8, 6, 5] {
        let (epk, _) = card.get_challenge("a", None);
        let s = hsm.respond(&epk, &pk);
        let data = calculate_data("a", &s.context, Some(&hsm.public()), Some(&s.receipt), &pw("wrong"));
        assert_eq!(card.send_raw(&apdu(ins::CALCULATE, 0, 0, &data)).1, sw::retries(left));
    }
    let (epk, _) = card.get_challenge("a", None);
    let s = hsm.respond(&epk, &pk);
    let mut receipt = s.receipt.clone();
    receipt[0] ^= 1;
    let data = calculate_data("a", &s.context, Some(&hsm.public()), Some(&receipt), &password);
    // `send_raw` panics on a touch request.
    assert_eq!(card.send_raw(&apdu(ins::CALCULATE, 0, 0, &data)), (vec![], sw::DATA_INVALID));
    let mut card = card.restart();
    assert_eq!(card.retries_of("a"), Some(8));
    // If that reset cannot be stored, the storage failure is what the host sees.
    for left in [7u8, 6] {
        let (epk, _) = card.get_challenge("a", None);
        let s = hsm.respond(&epk, &pk);
        let data = calculate_data("a", &s.context, Some(&hsm.public()), Some(&s.receipt), &pw("wrong"));
        assert_eq!(card.send_raw(&apdu(ins::CALCULATE, 0, 0, &data)).1, sw::retries(left));
    }
    let (epk, _) = card.get_challenge("a", None);
    let s = hsm.respond(&epk, &pk);
    let data = calculate_data("a", &s.context, Some(&hsm.public()), Some(&receipt), &password);
    card.host.fail_next_saves(1);
    assert_eq!(card.send_raw(&apdu(ins::CALCULATE, 0, 0, &data)).1, sw::MEMORY_FAILURE);
    assert_eq!(card.retries_of("a"), Some(6));
}

/// Catalog "single-use ephemeral challenges": a declined touch still consumed the
/// ephemeral key, so the same CALCULATE cannot be replayed to get the keys later.
#[test]
fn declined_touch_consumes_the_ephemeral_challenge() {
    let password = pw("t");
    let mut card = Card::new();
    let credential = test_key("d/SK.OCE");
    let put = Put::asymmetric("a", Some(credential.scalar().to_vec()), password).touch(true);
    assert_eq!(card.put(&put), sw::OK);
    let hsm = HsmSide::new("hsm");
    let (epk, _) = card.get_challenge("a", None);
    let s = hsm.respond(&epk, &credential.public_uncompressed());
    let calc = apdu(ins::CALCULATE, 0, 0, &calculate_data("a", &s.context, Some(&hsm.public()), Some(&s.receipt), &password));
    assert!(matches!(card.raw(&calc), Outcome::NeedTouch { .. }));
    assert_eq!(card.app.touch_resolved(false, &mut card.host), hex("6982"));
    assert_eq!(card.send_raw(&calc), (vec![], sw::DATA_INVALID), "replay after a declined touch");
}

/// Catalog "single-use ephemeral challenges": a used EPK.OCE never works again — not
/// after re-SELECT, not after a power cycle (a new instance from the record), and not
/// after a later GET CHALLENGE issued a different key.
#[test]
fn used_challenge_cannot_be_replayed() {
    let password = pw("u");
    let mut card = Card::new();
    let credential = test_key("u/SK.OCE");
    let pk = credential.public_uncompressed();
    assert_eq!(card.put(&Put::asymmetric("a", Some(credential.scalar().to_vec()), password)), sw::OK);
    let hsm = HsmSide::new("hsm");
    let (epk, _) = card.get_challenge("a", None);
    let s = hsm.respond(&epk, &pk);
    let data = calculate_data("a", &s.context, Some(&hsm.public()), Some(&s.receipt), &password);
    assert_eq!(card.cmd(ins::CALCULATE, &data), (s.session_keys.clone(), sw::OK));
    assert_eq!(card.cmd(ins::CALCULATE, &data).1, sw::DATA_INVALID);
    let resp = card.app.select(&select_apdu(), &mut card.host);
    assert_eq!(split(&resp).1, sw::OK);
    assert_eq!(card.cmd(ins::CALCULATE, &data).1, sw::DATA_INVALID);
    let (fresh, _) = card.get_challenge("a", None);
    assert_ne!(fresh, epk);
    assert_eq!(card.cmd(ins::CALCULATE, &data).1, sw::DATA_INVALID, "a newer challenge does not revive it");
    let mut card = card.restart();
    assert_eq!(card.cmd(ins::CALCULATE, &data).1, sw::DATA_INVALID);
    assert_eq!(card.retries_of("a"), Some(8), "stale challenges cost no password try");
}

/// Model decision (`HsmAuth::get_challenge`): only a well-formed GET CHALLENGE naming an
/// existing credential discards the outstanding ephemeral key; a syntax error or an
/// unknown label leaves it usable. A symmetric CALCULATE does not touch it either.
#[test]
fn outstanding_challenge_survives_unrelated_failures() {
    let password = pw("k");
    let mut card = Card::new();
    let credential = test_key("k/SK.OCE");
    let pk = credential.public_uncompressed();
    assert_eq!(card.put(&Put::asymmetric("a", Some(credential.scalar().to_vec()), password)), sw::OK);
    assert_eq!(card.put_symmetric("s", [1; 16], [2; 16], password), sw::OK);
    let hsm = HsmSide::new("hsm");
    let (epk, _) = card.get_challenge("a", None);
    assert_eq!(card.get_challenge("missing", None).1, sw::FILE_NOT_FOUND);
    assert_eq!(card.cmd(ins::GET_CHALLENGE, &tlv(tag::LABEL, &[])).1, sw::INCORRECT_DATA);
    assert_eq!(card.cmd(ins::CALCULATE, &calculate_data("s", &[0; 16], None, None, &password)).1, sw::OK);
    assert_eq!(card.cmd(ins::CALCULATE, &calculate_data("a", &[0; 16], None, None, &password)).1, sw::INCORRECT_DATA);
    let s = hsm.respond(&epk, &pk);
    let data = calculate_data("a", &s.context, Some(&hsm.public()), Some(&s.receipt), &password);
    assert_eq!(card.cmd(ins::CALCULATE, &data), (s.session_keys, sw::OK));
    // A GET CHALLENGE for an existing credential replaces it, even with a wrong password.
    let (epk, _) = card.get_challenge("a", None);
    assert_eq!(card.get_challenge("s", Some(pw("wrong"))).1, sw::retries(7));
    let s = hsm.respond(&epk, &pk);
    let data = calculate_data("a", &s.context, Some(&hsm.public()), Some(&s.receipt), &password);
    assert_eq!(card.cmd(ins::CALCULATE, &data).1, sw::DATA_INVALID);
}

/// YESDK overview: touch is required "when calculating session keys" only (catalog
/// `hsmauth_symmetric_challenge_touch`). With only touch-required credentials stored,
/// no other command ever asks for touch (`send_raw` panics on a touch request), and a
/// CALCULATE that fails before the touch answers at once.
#[test]
fn touch_is_requested_by_calculate_only() {
    let password = pw("t");
    let mut card = Card::new();
    let credential = test_key("o/SK.OCE");
    let pk = credential.public_uncompressed();
    assert_eq!(card.put(&Put::symmetric("s", [1; 16], [2; 16], password).touch(true)), sw::OK);
    assert_eq!(card.put(&Put::asymmetric("a", Some(credential.scalar().to_vec()), password).touch(true)), sw::OK);
    assert_eq!(card.put(&Put::asymmetric("g", None, password).touch(true)), sw::OK);
    let hsm = HsmSide::new("hsm");
    for label in ["s", "a", "g"] {
        assert_eq!(card.send_raw(&apdu(ins::GET_CHALLENGE, 0, 0, &tlv(tag::LABEL, label.as_bytes()))).1, sw::OK);
        let mut d = tlv(tag::LABEL, label.as_bytes());
        d.extend(tlv(tag::CREDENTIAL_PASSWORD, &password));
        assert_eq!(card.send_raw(&apdu(ins::GET_CHALLENGE, 0, 0, &d)).1, sw::OK);
    }
    assert_eq!(card.send_raw(&apdu(ins::GET_PUBLIC_KEY, 0, 0, &tlv(tag::LABEL, b"a"))).1, sw::OK);
    assert_eq!(card.send(ins::LIST, 0, 0, &[]).1, sw::OK);
    assert_eq!(card.send_raw(&apdu(ins::GET_VERSION, 0, 0, &[])).1, sw::OK);
    assert_eq!(card.send_raw(&apdu(ins::GET_MANAGEMENT_KEY_RETRIES, 0, 0, &[])).1, sw::OK);
    assert_eq!(card.put_management_key(&DEFAULT_KEY, &DEFAULT_KEY), sw::OK);
    // CALCULATE failures before the touch: wrong password, bad cryptogram, stale or
    // wrong receipt, syntax.
    assert_eq!(card.send_raw(&sym_calc("s", pw("wrong"))).1, sw::retries(7));
    let bad_crypto = calculate_data("s", &[0x33; 16], None, Some(&[0; 8]), &password);
    assert_eq!(card.send_raw(&apdu(ins::CALCULATE, 0, 0, &bad_crypto)).1, sw::DATA_INVALID);
    let (epk, _) = card.get_challenge("a", None);
    let s = hsm.respond(&epk, &pk);
    let mut receipt = s.receipt.clone();
    receipt[3] ^= 4;
    let data = calculate_data("a", &s.context, Some(&hsm.public()), Some(&receipt), &password);
    assert_eq!(card.send_raw(&apdu(ins::CALCULATE, 0, 0, &data)).1, sw::DATA_INVALID);
    let data = calculate_data("a", &s.context, Some(&hsm.public()), Some(&s.receipt), &password);
    assert_eq!(card.send_raw(&apdu(ins::CALCULATE, 0, 0, &data)).1, sw::DATA_INVALID, "challenge already used");
    assert_eq!(card.delete(&DEFAULT_KEY, "g"), sw::OK);
    assert_eq!(card.send_raw(&[0x00, ins::RESET, 0xDE, 0xAD]).1, sw::OK);
}

// ----- Zero tries on disk (second review) -----

/// A host that fails exactly one save, `skip` saves from now, and passes everything
/// else to `inner` (`TestHost::fail_next_saves` can only fail the very next saves).
struct FailOneSave<'a> {
    inner: &'a mut TestHost,
    skip: Option<usize>,
}

impl Entropy for FailOneSave<'_> {
    fn fill(&mut self, out: &mut [u8]) {
        self.inner.fill(out);
    }
}

impl Host for FailOneSave<'_> {
    fn now(&self) -> Millis {
        self.inner.now()
    }

    fn profile(&self) -> &DeviceProfile {
        self.inner.profile()
    }

    fn persist(&mut self, record: Record, plaintext: &[u8]) -> Result<(), StoreError> {
        match self.skip {
            Some(0) => {
                self.skip = None;
                Err(StoreError("injected failure".into()))
            }
            Some(n) => {
                self.skip = Some(n - 1);
                self.inner.persist(record, plaintext)
            }
            None => self.inner.persist(record, plaintext),
        }
    }
}

const OTHER_KEY: [u8; 16] = [0x5A; 16];

/// A card with a non-default management key, a bystander credential "other" and a
/// credential "t" (touch as given) with one password try left.
fn last_try_card(touch: bool) -> Card {
    let mut card = Card::new();
    assert_eq!(card.put_management_key(&DEFAULT_KEY, &OTHER_KEY), sw::OK);
    let mut other = Put::symmetric("other", [7; 16], [8; 16], pw("other"));
    other.management_key = OTHER_KEY;
    assert_eq!(card.put(&other), sw::OK);
    let mut t = Put::symmetric("t", [1; 16], [2; 16], pw("right")).touch(touch);
    t.management_key = OTHER_KEY;
    assert_eq!(card.put(&t), sw::OK);
    for left in (1..8).rev() {
        assert_eq!(card.send_raw(&sym_calc("t", pw("wrong"))).1, sw::retries(left));
    }
    assert_eq!(card.retries_of("t"), Some(1));
    card
}

/// What a power cycle right now would load: the bystander and the management key are
/// intact, and "t" is present with `t_tries` or gone (`None`).
fn assert_record_loads(host: &TestHost, t_tries: Option<u8>) {
    let mut peek = Card::with_host(host.clone());
    let mut expected = vec![(b"other".to_vec(), 8u8)];
    if let Some(tries) = t_tries {
        expected.push((b"t".to_vec(), tries));
    }
    let got: Vec<(Vec<u8>, u8)> = peek.list().into_iter().map(|e| (e.label, e.retries)).collect();
    assert_eq!(got, expected, "not factory state");
    assert_eq!(peek.management_retries(), 8);
    assert_eq!(peek.put_management_key(&OTHER_KEY, &OTHER_KEY), sw::OK, "management key kept");
}

/// Second review: spending the last try persists a credential with zero tries
/// (`docs/CONTRACTS.md` "Retry counters": spend and persist before comparing). The
/// loader used to reject such a record as a whole — factory state, every credential
/// gone and the management key back to sixteen zero bytes — so a power loss while a
/// touch-required CALCULATE waited on the last try wiped the application. Now the
/// record loads with only that credential deleted (it had no tries left), and the
/// running card completes normally.
#[test]
fn last_try_spent_before_touch_does_not_wipe_the_record() {
    let mut card = last_try_card(true);
    assert!(matches!(card.raw(&sym_calc("t", pw("right"))), Outcome::NeedTouch { .. }));
    // Power lost now: the record holds "t" at zero tries.
    assert_record_loads(&card.host, None);
    // Not lost: the touch completes and the tries come back.
    let (keys, status) = split(&card.app.touch_resolved(true, &mut card.host));
    assert_eq!((keys.len(), status), (48, sw::OK));
    assert_eq!(card.retries_of("t"), Some(8));
    assert_record_loads(&card.host, Some(8));
}

/// A touch on the last try that is declined or abandoned gives the try back before the
/// zero-tries cleanup runs (`HsmAuth::settle` restores first, then deletes what is still
/// at zero), so the credential stays with its one try — in memory and in the record.
#[test]
fn abandoned_or_declined_last_try_touch_keeps_the_credential() {
    // Declined.
    let mut card = last_try_card(true);
    assert!(matches!(card.raw(&sym_calc("t", pw("right"))), Outcome::NeedTouch { .. }));
    assert_eq!(card.app.touch_resolved(false, &mut card.host), hex("6982"));
    assert_eq!(card.retries_of("t"), Some(1));
    assert_record_loads(&card.host, Some(1));
    // Abandoned by another command.
    assert!(matches!(card.raw(&sym_calc("t", pw("right"))), Outcome::NeedTouch { .. }));
    assert_eq!(card.cmd(ins::GET_VERSION, &[]).1, sw::OK);
    assert_eq!(card.retries_of("t"), Some(1));
    assert_record_loads(&card.host, Some(1));
    // Abandoned by a deselect or a session reset, then any command.
    for end in [None, Some(ResetKind::CardPowerOff), Some(ResetKind::UsbReset)] {
        assert!(matches!(card.raw(&sym_calc("t", pw("right"))), Outcome::NeedTouch { .. }));
        match end {
            None => card.app.deselect(),
            Some(kind) => card.app.reset(kind),
        }
        let resp = card.app.select(&select_apdu(), &mut card.host);
        assert_eq!(split(&resp).1, sw::OK);
        assert_eq!(card.retries_of("t"), Some(1), "{end:?}");
        assert_record_loads(&card.host, Some(1));
    }
    // And the try still works.
    assert!(matches!(card.raw(&sym_calc("t", pw("right"))), Outcome::NeedTouch { .. }));
    assert_eq!(split(&card.app.touch_resolved(true, &mut card.host)).1, sw::OK);
    assert_eq!(card.retries_of("t"), Some(8));
}

/// Second review: a correct password on the last try whose return to eight tries cannot
/// be stored (`6581`, the try stays spent) leaves "t" at zero tries. The running card
/// deletes it at the next command and a restart loads it deleted; nothing else is lost.
#[test]
fn failed_restore_of_the_last_try_deletes_only_that_credential() {
    // After a touch.
    let mut card = last_try_card(true);
    assert!(matches!(card.raw(&sym_calc("t", pw("right"))), Outcome::NeedTouch { .. }));
    card.host.fail_next_saves(1);
    assert_eq!(card.app.touch_resolved(true, &mut card.host), hex("6581"));
    assert_record_loads(&card.host, None);
    assert_eq!(card.labels(), vec![b"other".to_vec()], "the running card finished the deletion");
    let mut card = card.restart();
    assert_eq!(card.labels(), vec![b"other".to_vec()]);
    assert_eq!(card.put_symmetric("t", [1; 16], [2; 16], pw("right")), sw::retries(7), "default key refused");

    // Without touch: the spend is stored, the restore is not.
    let mut card = last_try_card(false);
    let mut host = FailOneSave { inner: &mut card.host, skip: Some(1) };
    let resp = card.app.process(&sym_calc("t", pw("right")), &mut host);
    assert_eq!(resp, Outcome::Done(hex("6581")), "no keys without the stored restore");
    assert_record_loads(&card.host, None);
    assert_eq!(card.labels(), vec![b"other".to_vec()]);
}

/// Second review: the eighth wrong password whose deletion cannot be stored (the
/// spent try was) answers `6581`. The record loads with only that credential gone;
/// while the store keeps failing the running card reports it with zero tries and any
/// password attempt on it is refused without a comparison; once the store works the
/// next command finishes the deletion and forgets its ephemeral key.
#[test]
fn eighth_wrong_password_with_failed_deletion_keeps_the_rest() {
    let mut card = last_try_card(false);
    let mut host = FailOneSave { inner: &mut card.host, skip: Some(1) };
    let resp = card.app.process(&sym_calc("t", pw("wrong")), &mut host);
    assert_eq!(resp, Outcome::Done(hex("6581")));
    assert_record_loads(&card.host, None);
    card.host.fail_all(true);
    assert_eq!(card.retries_of("t"), Some(0), "the store keeps failing: deletion pending");
    assert_eq!(card.send_raw(&sym_calc("t", pw("right"))).1, sw::MEMORY_FAILURE);
    card.host.fail_all(false);
    assert_eq!(card.send_raw(&sym_calc("t", pw("right"))).1, sw::FILE_NOT_FOUND);
    assert_eq!(card.labels(), vec![b"other".to_vec()]);
    // The label is free again, with the kept management key.
    let mut t = Put::symmetric("t", [3; 16], [4; 16], pw("new"));
    t.management_key = OTHER_KEY;
    assert_eq!(card.put(&t), sw::OK);
    assert_eq!(card.retries_of("t"), Some(8));
}

/// The pending deletion of an asymmetric credential at zero tries also drops its
/// outstanding ephemeral key, so a re-created credential with the same label cannot
/// use it.
#[test]
fn finished_deletion_forgets_the_ephemeral_key() {
    let password = pw("right");
    let mut card = Card::new();
    let credential = test_key("z/SK.OCE");
    let pk = credential.public_uncompressed();
    let put = Put::asymmetric("a", Some(credential.scalar().to_vec()), password);
    assert_eq!(card.put(&put), sw::OK);
    let hsm = HsmSide::new("hsm");
    for left in (1..8).rev() {
        let (epk, _) = card.get_challenge("a", None);
        let s = hsm.respond(&epk, &pk);
        let data = calculate_data("a", &s.context, Some(&hsm.public()), Some(&s.receipt), &pw("wrong"));
        assert_eq!(card.cmd(ins::CALCULATE, &data).1, sw::retries(left));
    }
    // GET CHALLENGE with a wrong password on the last try: spend stored, deletion not.
    let mut d = tlv(tag::LABEL, b"a");
    d.extend(tlv(tag::CREDENTIAL_PASSWORD, &pw("wrong")));
    let mut host = FailOneSave { inner: &mut card.host, skip: Some(1) };
    assert_eq!(card.app.process(&apdu(ins::GET_CHALLENGE, 0, 0, &d), &mut host), Outcome::Done(hex("6581")));
    // A challenge issued while the deletion is pending (no password: nothing is checked).
    card.host.fail_all(true);
    let (epk, status) = card.get_challenge("a", None);
    assert_eq!((epk.len(), status), (65, sw::OK));
    card.host.fail_all(false);
    assert_eq!(card.labels(), Vec::<Vec<u8>>::new(), "deleted at the next command");
    assert_eq!(card.put(&put), sw::OK);
    let s = hsm.respond(&epk, &pk);
    let data = calculate_data("a", &s.context, Some(&hsm.public()), Some(&s.receipt), &password);
    assert_eq!(card.cmd(ins::CALCULATE, &data).1, sw::DATA_INVALID);
}

// ----- Ne (second review) -----

/// `docs/CONTRACTS.md` "APDU conventions": at most Ne bytes per response, the rest with
/// `61xx` and GET RESPONSE (ISO/IEC 7816-4 §5.1, §7.6.1). Before the review fix a short
/// Le was ignored. The continuation shapes of the real hosts keep working: yubikit's
/// `00 C0 00 00 00` and ykhsmauth's `00 C0 00 00 XX` with XX from the previous `61XX`.
#[test]
fn short_le_limits_each_response_piece() {
    let mut card = Card::new();
    for i in 0..MAX_CREDENTIALS {
        let label = format!("{i:02}{}", "n".repeat(62));
        assert_eq!(card.put_symmetric(&label, [1; 16], [2; 16], pw("p")), sw::OK);
    }
    let (full, status) = card.cmd(ins::LIST, &[]);
    assert_eq!((full.len(), status), (32 * 69, sw::OK));
    // Short Le 16.
    let (first, status) = card.send_raw(&[0x00, ins::LIST, 0x00, 0x00, 0x10]);
    assert_eq!((first.len(), status), (16, 0x6100));
    // ykhsmauth: `00 C0 00 00 XX`, XX = SW2 of the last `61XX` (`00` asks for 256).
    let mut got = first;
    let mut status = status;
    while status & 0xFF00 == 0x6100 {
        let le = (status & 0xFF) as u8;
        let (more, next) = card.send_raw(&[0x00, ins::GET_RESPONSE, 0x00, 0x00, le]);
        let expected = if le == 0 { 256 } else { usize::from(le) };
        assert_eq!(more.len(), expected.min(full.len() - got.len()));
        got.extend(more);
        status = next;
    }
    assert_eq!((got, status), (full.clone(), sw::OK));
    // Extended Le 300.
    let (piece, status) = card.send_raw(&[0x00, ins::LIST, 0x00, 0x00, 0x00, 0x01, 0x2C]);
    assert_eq!((piece.len(), status), (300, 0x6100));

    // CALCULATE: 48 bytes of keys with short Le 16, with and without touch.
    let context = [0x33u8; 16];
    let expected: Vec<u8> = [
        sp800_108_cmac(&[1; 16], constant::S_ENC, &context, 128),
        sp800_108_cmac(&[2; 16], constant::S_MAC, &context, 128),
        sp800_108_cmac(&[2; 16], constant::S_RMAC, &context, 128),
    ]
    .concat();
    let label = format!("00{}", "n".repeat(62));
    let calc = lk_codec::apdu::Command::new(0, ins::CALCULATE, 0, 0)
        .with_data(calculate_data(&label, &context, None, None, &pw("p")))
        .with_le(16)
        .to_bytes();
    let (head, status) = card.send_raw(&calc);
    assert_eq!((head.len(), status), (16, 0x6120));
    let (tail, status) = card.send_raw(&[0x00, ins::GET_RESPONSE, 0x00, 0x00, 0x20]);
    assert_eq!(([head, tail].concat(), status), (expected.clone(), sw::OK));

    let mut card = Card::new();
    assert_eq!(card.put(&Put::symmetric("t", [1; 16], [2; 16], pw("p")).touch(true)), sw::OK);
    let calc = lk_codec::apdu::Command::new(0, ins::CALCULATE, 0, 0)
        .with_data(calculate_data("t", &context, None, None, &pw("p")))
        .with_le(32)
        .to_bytes();
    assert!(matches!(card.raw(&calc), Outcome::NeedTouch { .. }));
    let (head, status) = split(&card.app.touch_resolved(true, &mut card.host));
    assert_eq!((head.len(), status), (32, 0x6110));
    let (tail, status) = card.send_raw(&[0x00, ins::GET_RESPONSE, 0x00, 0x00, 0x00]);
    assert_eq!(([head, tail].concat(), status), (expected, sw::OK));
    assert_eq!(card.retries_of("t"), Some(8));
}
