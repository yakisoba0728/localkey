//! VERIFY, CHANGE REFERENCE DATA and RESET RETRY COUNTER
//! (SP 800-73-4 Part 2 §2.4.3, §3.2.1, §3.2.2, §3.2.3).

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use lk_core::{CardApplet, Outcome, Record, ResetKind};
use lk_piv::Piv;
use lk_testkit::TestHost;

#[test]
fn default_pin_verifies_and_status_reports_verified() {
    let mut card = Card::new();
    // SP 800-73-4 Part 2 §3.2.1: VERIFY without data reports 63CX when not verified.
    // Every case 1 encoding: four bytes (short APDUs), the T=0 form with P3 = 00
    // (ISO/IEC 7816-3 §12.2.2; yubico-piv-tool) and the extended "Lc = 0000" form
    // (python yubikit with extended APDUs).
    assert_eq!(card.send("00200080").1, 0x63C3);
    assert_eq!(card.pin_status(), 0x63C3);
    assert_eq!(card.send("00200080000000").1, 0x63C3);
    assert_eq!(card.send("0020008001").1, 0x6700, "a real Le is explicit");
    assert_eq!(card.send("00200080000001").1, 0x6700, "a real extended Le is explicit");
    assert_eq!(card.send("0020008008313233343536FFFF").1, 0x9000);
    assert_eq!(card.pin_status(), 0x9000);
}

#[test]
fn wrong_pins_count_down_then_block() {
    let mut card = Card::new();
    let wrong = pad(b"654321");
    assert_eq!(card.verify_pin(&wrong), 0x63C2);
    assert_eq!(card.verify_pin(&wrong), 0x63C1);
    assert_eq!(card.verify_pin(&wrong), 0x63C0, "the blocking attempt reports 0 left");
    assert_eq!(card.verify_pin(&hex(DEFAULT_PIN)), 0x6983, "blocked even for the right PIN");
    assert_eq!(card.pin_status(), 0x6983);
    // Blocked attempts do not persist anything.
    let count = card.host.persist_count();
    assert_eq!(card.verify_pin(&wrong), 0x6983);
    assert_eq!(card.host.persist_count(), count);
}

#[test]
fn wrong_pin_clears_verified_status() {
    let mut card = Card::new();
    card.verify_default_pin();
    assert_eq!(card.verify_pin(&pad(b"000000")), 0x63C2);
    assert_eq!(card.pin_status(), 0x63C2);
    card.verify_default_pin();
    assert_eq!(card.pin_status(), 0x9000, "a correct PIN restores the counter");
    assert_eq!(card.metadata(0x80).0, hex("0101FF 050101 06020303"));
}

#[test]
fn retry_counter_is_persisted_before_the_response() {
    // lk_core::Host::persist: retry counters are persisted before the response that
    // reveals them. Each attempt is visible after a restart.
    let mut card = Card::new();
    let base = card.host.persist_count();
    assert_eq!(card.verify_pin(&pad(b"999999")), 0x63C2);
    assert_eq!(card.host.persist_count(), base + 1);
    card.restart();
    assert_eq!(card.pin_status(), 0x63C2);
    assert_eq!(card.verify_pin(&pad(b"999999")), 0x63C1);
    card.restart();
    assert_eq!(card.pin_status(), 0x63C1);
}

#[test]
fn storage_failure_before_comparison_reveals_nothing() {
    let mut card = Card::new();
    let before = card.host.persisted(Record::Piv);
    card.host.fail_next_saves(1);
    assert_eq!(card.verify_pin(&pad(b"999999")), 0x6581);
    assert_eq!(card.pin_status(), 0x63C3, "counter unchanged");
    card.host.fail_next_saves(1);
    assert_eq!(card.verify_pin(&hex(DEFAULT_PIN)), 0x6581, "same answer for the right PIN");
    assert_eq!(card.pin_status(), 0x63C3, "not verified");
    assert_eq!(card.host.persisted(Record::Piv), before);
}

#[test]
fn storage_failure_after_correct_pin_keeps_the_decrement() {
    // The decrement is durable before the comparison; if restoring the counter fails the
    // card answers 6581, is not verified, and memory matches storage.
    // Persist calls: 1 the initial F9 attestation material in `new`, 2 the decrement,
    // 3 the restore (which fails).
    let mut host = FailAt { inner: TestHost::new(), fail_at: 3, calls: 0 };
    let mut piv = Piv::new(None, &mut host);
    piv.select(&hex(SELECT), &mut host);
    let verify = apdu(0x00, 0x20, 0x00, 0x80, &hex(DEFAULT_PIN), None);
    assert_eq!(piv.process(&verify, &mut host), Outcome::Done(hex("6581")));
    assert_eq!(piv.process(&hex("0020008000"), &mut host), Outcome::Done(hex("63C2")));
    let stored = host.inner.persisted(Record::Piv);
    let mut restarted = Piv::new(stored.as_deref(), &mut host);
    restarted.select(&hex(SELECT), &mut host);
    assert_eq!(restarted.process(&hex("0020008000"), &mut host), Outcome::Done(hex("63C2")));
}

#[test]
fn verify_reset_security_status() {
    // SP 800-73-4 Part 2 §3.2.1: P1 FF resets the security status of the reference.
    let mut card = Card::new();
    card.verify_default_pin();
    assert_eq!(card.send("0020FF80").1, 0x9000);
    assert_eq!(card.pin_status(), 0x63C3);
    assert_eq!(card.send("0020FF8008313233343536FFFF").1, 0x6700, "P1 FF takes no data");
}

#[test]
fn verify_header_guards_consume_no_retry() {
    // Catalog: VERIFY/CHANGE/RESET RETRY P1/P2/Le guards before state changes.
    let mut card = Card::new();
    let base = card.host.persist_count();
    assert_eq!(card.send("0020018008313233343536FFFF").1, 0x6A86, "P1");
    // §3.2.1: "If any key reference value is specified that cannot be verified by the
    // PIV Card Application, then the PIV Card Application shall return ... '6A 88'".
    assert_eq!(card.send("0020000008313233343536FFFF").1, 0x6A88, "global PIN");
    // The PUK cannot be verified by VERIFY either (§3.2.1, 6A88). Known difference: the
    // YubiKey 5C Nano 5.7.4 answers 6A80 (docs/MEASUREMENT.md, probe piv-verify-status-81;
    // tests/measured.rs).
    assert_eq!(card.send("0020008108313233343536FFFF").1, 0x6A88, "PUK cannot be verified");
    assert_eq!(card.send("0020009E08313233343536FFFF").1, 0x6A88);
    assert_eq!(card.send("0020000108313233343536FFFF").1, 0x6A88);
    // A non-zero Le; Le 00 (yubico-piv-tool on T=1) is accepted (tests/interop.rs).
    assert_eq!(card.send("0020008008313233343536FFFF01").1, 0x6700, "explicit Le");
    assert_eq!(card.send("0020008006313233343536").1, 0x6A80, "not 8 bytes");
    assert_eq!(card.send("0020008009313233343536FFFFFF").1, 0x6A80, "not 8 bytes");
    assert_eq!(card.pin_status(), 0x63C3);
    assert_eq!(card.host.persist_count(), base);
}

#[test]
fn change_pin() {
    let mut card = Card::new();
    let new_pin = pad(b"8642097");
    let mut data = hex(DEFAULT_PIN);
    data.extend_from_slice(&new_pin);
    assert_eq!(card.cmd(0x24, 0x00, 0x80, &data, None).1, 0x9000);
    assert_eq!(card.verify_pin(&hex(DEFAULT_PIN)), 0x63C2);
    assert_eq!(card.verify_pin(&new_pin), 0x9000);
    assert_eq!(card.metadata(0x80).0, hex("0101FF 050100 06020303"), "no longer default");
    // Survives a restart.
    card.restart();
    assert_eq!(card.verify_pin(&new_pin), 0x9000);
}

#[test]
fn change_pin_with_wrong_current_value_consumes_a_retry() {
    let mut card = Card::new();
    let mut data = pad(b"111111");
    data.extend_from_slice(&pad(b"222222"));
    assert_eq!(card.cmd(0x24, 0x00, 0x80, &data, None).1, 0x63C2);
    assert_eq!(card.verify_pin(&pad(b"222222")), 0x63C1);
    card.verify_default_pin();
}

#[test]
fn new_reference_data_format_is_checked_first() {
    // SP 800-73-4 Part 2 §2.4.3: 6 to 8 bytes padded with FF. A malformed new value is
    // 6A80 without consuming a retry, even with a wrong current value.
    let mut card = Card::new();
    for new in ["31323334FFFFFFFF", "313233343536FF37", "FFFFFFFFFFFFFFFF", "3132333435FFFFFF"] {
        let mut data = hex(DEFAULT_PIN);
        data.extend_from_slice(&hex(new));
        assert_eq!(card.cmd(0x24, 0x00, 0x80, &data, None).1, 0x6A80, "{new}");
        let mut wrong = pad(b"000000");
        wrong.extend_from_slice(&hex(new));
        assert_eq!(card.cmd(0x24, 0x00, 0x80, &wrong, None).1, 0x6A80, "{new}");
    }
    assert_eq!(card.cmd(0x24, 0x00, 0x80, &hex(DEFAULT_PIN), None).1, 0x6A80, "8 bytes only");
    assert_eq!(card.pin_status(), 0x63C3);
    // Eight bytes without padding is a valid 8-character PIN.
    let mut data = hex(DEFAULT_PIN);
    data.extend_from_slice(b"abcdefgh");
    assert_eq!(card.cmd(0x24, 0x00, 0x80, &data, None).1, 0x9000);
    assert_eq!(card.verify_pin(b"abcdefgh"), 0x9000);
}

#[test]
fn change_reference_header_guards() {
    let mut card = Card::new();
    let base = card.host.persist_count();
    let mut data = hex(DEFAULT_PIN);
    data.extend_from_slice(&pad(b"777777"));
    assert_eq!(card.cmd(0x24, 0x01, 0x80, &data, None).1, 0x6A86);
    // §3.2.2: an unsupported key reference is '6A 88'.
    assert_eq!(card.cmd(0x24, 0x00, 0x00, &data, None).1, 0x6A88);
    assert_eq!(card.cmd(0x24, 0x00, 0x9B, &data, None).1, 0x6A88);
    assert_eq!(card.cmd(0x24, 0x00, 0x80, &data, Some(1)).1, 0x6700, "non-zero Le");
    assert_eq!(card.host.persist_count(), base);
    card.verify_default_pin();
}

#[test]
fn change_puk_and_use_it() {
    let mut card = Card::new();
    let new_puk = pad(b"87654321");
    let mut data = hex(DEFAULT_PUK);
    data.extend_from_slice(&new_puk);
    assert_eq!(card.cmd(0x24, 0x00, 0x81, &data, None).1, 0x9000);
    assert_eq!(card.metadata(0x81).0, hex("0101FF 050100 06020303"));
    // Wrong PUK now consumes a PUK retry.
    let mut data = hex(DEFAULT_PUK);
    data.extend_from_slice(&pad(b"999999"));
    assert_eq!(card.cmd(0x2C, 0x00, 0x80, &data, None).1, 0x63C2);
    let mut data = new_puk.clone();
    data.extend_from_slice(&pad(b"999999"));
    assert_eq!(card.cmd(0x2C, 0x00, 0x80, &data, None).1, 0x9000);
    assert_eq!(card.verify_pin(&pad(b"999999")), 0x9000);
    assert_eq!(card.metadata(0x81).0, hex("0101FF 050100 06020303"), "PUK counter restored");
}

#[test]
fn reset_retry_counter_unblocks_pin() {
    let mut card = Card::new();
    for _ in 0..3 {
        card.verify_pin(&pad(b"000000"));
    }
    assert_eq!(card.pin_status(), 0x6983);
    let new_pin = pad(b"135790");
    let mut data = hex(DEFAULT_PUK);
    data.extend_from_slice(&new_pin);
    assert_eq!(card.cmd(0x2C, 0x00, 0x80, &data, None).1, 0x9000);
    assert_eq!(card.pin_status(), 0x63C3, "unblocked, not verified");
    assert_eq!(card.verify_pin(&new_pin), 0x9000);
}

#[test]
fn wrong_puk_blocks_after_three_attempts() {
    let mut card = Card::new();
    let mut data = pad(b"00000000");
    data.extend_from_slice(&pad(b"135790"));
    assert_eq!(card.cmd(0x2C, 0x00, 0x80, &data, None).1, 0x63C2);
    assert_eq!(card.cmd(0x2C, 0x00, 0x80, &data, None).1, 0x63C1);
    assert_eq!(card.cmd(0x2C, 0x00, 0x80, &data, None).1, 0x63C0);
    let mut right = hex(DEFAULT_PUK);
    right.extend_from_slice(&pad(b"135790"));
    assert_eq!(card.cmd(0x2C, 0x00, 0x80, &right, None).1, 0x6983);
    // The PUK cannot be changed either.
    let mut change = hex(DEFAULT_PUK);
    change.extend_from_slice(&pad(b"11111111"));
    assert_eq!(card.cmd(0x24, 0x00, 0x81, &change, None).1, 0x6983);
    // The PIN is unaffected.
    card.verify_default_pin();
}

#[test]
fn reset_retry_counter_guards() {
    let mut card = Card::new();
    let base = card.host.persist_count();
    let mut data = hex(DEFAULT_PUK);
    data.extend_from_slice(&pad(b"135790"));
    assert_eq!(card.cmd(0x2C, 0x01, 0x80, &data, None).1, 0x6A86);
    // §3.2.3: "If a key reference is specified in P2 that is not supported by the card,
    // the PIV Card Application shall return the status word '6A 88'".
    assert_eq!(card.cmd(0x2C, 0x00, 0x81, &data, None).1, 0x6A88);
    assert_eq!(card.cmd(0x2C, 0x00, 0x00, &data, None).1, 0x6A88);
    assert_eq!(card.cmd(0x2C, 0x00, 0x80, &data, Some(1)).1, 0x6700, "non-zero Le");
    assert_eq!(card.cmd(0x2C, 0x00, 0x80, &data[..15], None).1, 0x6A80);
    assert_eq!(card.host.persist_count(), base);
    // The PUK is compared before the new PIN's format (python yubikit blocks the PUK with
    // FF*16, tests/interop.rs). A correct PUK with a malformed new PIN is 6A80 and
    // changes nothing: the PIN, both counters and the record stay as they were.
    let before = card.host.persisted(Record::Piv);
    let mut wrong = pad(b"00000000");
    wrong.extend_from_slice(&pad(b"135790"));
    assert_eq!(card.cmd(0x2C, 0x00, 0x80, &wrong, None).1, 0x63C2);
    let after_wrong = card.host.persisted(Record::Piv);
    for new in ["3132333435FFFFFF", "FFFFFFFFFFFFFFFF", "313233343536FF37"] {
        let mut short_pin = hex(DEFAULT_PUK);
        short_pin.extend_from_slice(&hex(new));
        assert_eq!(card.cmd(0x2C, 0x00, 0x80, &short_pin, None).1, 0x6A80, "{new}");
        assert_eq!(card.host.persisted(Record::Piv), after_wrong, "{new}: PUK counter put back");
    }
    assert_eq!(card.metadata(0x81).0, hex("0101FF 050101 06020302"), "still one retry spent");
    // A wrong PUK with a malformed new PIN spends a retry (63CX, not 6A80).
    let mut wrong_and_short = pad(b"00000000");
    wrong_and_short.extend_from_slice(&pad(b"12345"));
    assert_eq!(card.cmd(0x2C, 0x00, 0x80, &wrong_and_short, None).1, 0x63C1);
    assert_ne!(card.host.persisted(Record::Piv), before);
    card.verify_default_pin();
}

#[test]
fn reset_retry_counter_storage_failure_on_the_malformed_new_pin_path() {
    // Persist calls after construction: the decrement, then putting the counter back. If
    // that second save fails the card answers 6581 and keeps the durable decrement
    // (`docs/CONTRACTS.md` retry counters: storage failure is the answer whatever the
    // secret was).
    let mut card = Card::new();
    let mut short_pin = hex(DEFAULT_PUK);
    short_pin.extend_from_slice(&pad(b"12345"));
    let base = card.host.persist_count();
    card.host.fail_next_saves(1);
    assert_eq!(card.cmd(0x2C, 0x00, 0x80, &short_pin, None).1, 0x6581, "decrement fails");
    assert_eq!(card.host.persist_count(), base);
    assert_eq!(card.metadata(0x81).0, hex("0101FF 050101 06020303"));
    let inner = std::mem::replace(&mut card.host, TestHost::new());
    let mut host = FailAt { inner, fail_at: 2, calls: 0 };
    let resp = card.piv.process(&apdu(0x00, 0x2C, 0x00, 0x80, &short_pin, None), &mut host);
    assert_eq!(resp, Outcome::Done(hex("6581")), "putting the counter back fails");
    card.host = host.inner;
    assert_eq!(card.metadata(0x81).0, hex("0101FF 050101 06020302"), "memory matches storage");
    card.restart();
    assert_eq!(card.metadata(0x81).0, hex("0101FF 050101 06020302"));
}

#[test]
fn session_events_clear_pin_verification() {
    // SP 800-73-4 Part 2 §3.1.1: selecting another application sets every PIV security
    // status indicator to FALSE; a card reset ends the session.
    let mut card = Card::new();
    card.verify_default_pin();
    card.piv.deselect();
    assert_eq!(card.pin_status(), 0x63C3);
    for kind in [ResetKind::CardPowerOff, ResetKind::UsbReset, ResetKind::PowerCycle] {
        card.verify_default_pin();
        card.piv.reset(kind);
        assert_eq!(card.pin_status(), 0x63C3, "{kind:?}");
    }
    card.verify_default_pin();
    card.piv.deselect();
    card.piv.select(&hex(SELECT), &mut card.host);
    assert_eq!(card.pin_status(), 0x63C3, "selected again after another application");
}

#[test]
fn reselecting_piv_keeps_the_security_status() {
    // SP 800-73-4 Part 2 §3.1.1: a SELECT of the PIV AID (full or right-truncated) while
    // PIV is selected leaves "the setting of all security status indicators ...
    // unchanged"; an AID the card does not support leaves PIV selected and unchanged.
    let mut card = Card::new();
    card.verify_default_pin();
    card.auth_default();
    let resp = card.piv.select(&hex(SELECT), &mut card.host);
    assert_eq!(resp, [hex("61114F0600001000010079074F05A000000308"), hex("9000")].concat());
    assert_eq!(card.pin_status(), 0x9000, "trait SELECT keeps PIN status");
    for aid in ["A000000308", "A00000030800001000", "A0000003080000100001", "A000000308000010000100"] {
        let (data, sw) = card.send(&format!("00A40400{:02X}{aid}00", aid.len() / 2));
        assert_eq!((data, sw), (hex("61114F0600001000010079074F05A000000308"), 0x9000), "{aid}");
        assert_eq!(card.pin_status(), 0x9000, "{aid}");
    }
    for aid in ["A0000003", "A000000527471117", "A000000308000010000101", "A00000030800001000010000"] {
        assert_eq!(card.send(&format!("00A40400{:02X}{aid}00", aid.len() / 2)).1, 0x6A82, "{aid}");
        assert_eq!(card.pin_status(), 0x9000, "{aid}");
    }
    assert_eq!(card.send("00A4000005A00000030800").1, 0x6A86, "P1 must be 04");
    assert_eq!(card.pin_status(), 0x9000);
    // The management key authentication survives too: PUT DATA still works.
    assert_eq!(card.put_object(0x5FC102, &[0x01, 0x02]), 0x9000);
}
