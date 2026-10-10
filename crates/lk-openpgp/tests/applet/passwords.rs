//! VERIFY, CHANGE REFERENCE DATA, RESET RETRY COUNTER and SET RETRIES.

use lk_codec::apdu::Command;
use lk_core::{CardApplet, DeviceProfile, Entropy, Host, Millis, Outcome, Record, StoreError};
use lk_testkit::TestHost;

use crate::common::Card;

/// Default PINs `123456` / `12345678` (spec §4.3) for all three references.
#[test]
fn verify_default_pins() {
    let mut card = Card::new();
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    assert_eq!(card.verify(0x83, b"12345678"), 0x9000);
    assert_eq!(card.retries(), [3, 0, 3]);
}

/// spec §7.2.2: VERIFY without data reports the access status or the remaining tries.
#[test]
fn verify_empty_data_reports_status() {
    let mut card = Card::new();
    assert_eq!(card.verify(0x81, b""), 0x63C3);
    assert_eq!(card.verify(0x82, b""), 0x63C3);
    assert_eq!(card.verify(0x83, b""), 0x63C3);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    assert_eq!(card.verify(0x82, b""), 0x9000);
    // 81 and 82 are separate access conditions.
    assert_eq!(card.verify(0x81, b""), 0x63C3);
    assert_eq!(card.verify(0x83, b"00000000"), 0x63C2);
    assert_eq!(card.verify(0x83, b""), 0x63C2);
}

/// spec §7.2.2: wrong presentations count down to 63C0, then 6983 even for the right PIN.
#[test]
fn wrong_pin_decrements_and_blocks() {
    let mut card = Card::new();
    assert_eq!(card.verify(0x82, b"654321"), 0x63C2);
    assert_eq!(card.verify(0x81, b"654321"), 0x63C1);
    assert_eq!(card.verify(0x82, b"654321"), 0x63C0);
    assert_eq!(card.verify(0x82, b"123456"), 0x6983);
    assert_eq!(card.verify(0x81, b""), 0x6983);
    assert_eq!(card.retries(), [0, 0, 3]);
    // A too-short PIN is still a wrong presentation.
    assert_eq!(card.verify(0x83, b"1"), 0x63C2);
}

/// Catalog: "wrong PIN invalidates both PW1 authorization modes".
#[test]
fn wrong_pin_invalidates_both_pw1_modes() {
    let mut card = Card::new();
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    assert_eq!(card.verify(0x81, b"000000"), 0x63C2);
    assert_eq!(card.verify(0x81, b""), 0x63C2);
    assert_eq!(card.verify(0x82, b""), 0x63C2);
    // PW3 is unaffected by a wrong PW1.
    card.admin();
    assert_eq!(card.verify(0x82, b"000000"), 0x63C1);
    assert_eq!(card.verify(0x83, b""), 0x9000);
}

/// spec §7.2.2: a correct presentation restores the counter.
#[test]
fn correct_pin_restores_counter() {
    let mut card = Card::new();
    assert_eq!(card.verify(0x82, b"000000"), 0x63C2);
    assert_eq!(card.verify(0x83, b"00000000"), 0x63C2);
    assert_eq!(card.retries(), [2, 0, 2]);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    card.admin();
    assert_eq!(card.retries(), [3, 0, 3]);
}

/// docs/CONTRACTS.md: retry counters are persisted before the response that reveals them.
#[test]
fn wrong_pin_counter_persisted_before_response() {
    let mut card = Card::new();
    let before = card.host.persist_count();
    assert_eq!(card.verify(0x83, b"wrongpin"), 0x63C2);
    assert_eq!(card.host.persist_count(), before + 1);
    card.reload();
    assert_eq!(card.retries(), [3, 0, 2]);
}

/// docs/CONTRACTS.md: a storage failure answers 6581 and changes nothing. Every
/// presentation first spends its try and saves it (auth.rs, the anti-tearing order of
/// ISO/IEC 7816 cards); when that save fails no comparison is made. So with storage
/// failing a right and a wrong value give the same answer, and the persisted counter is
/// never left higher than the presentations made (no oracle whose tries a restart gives
/// back). Covers VERIFY, CHANGE REFERENCE DATA and RESET RETRY COUNTER.
#[test]
fn storage_failure_reveals_nothing_and_changes_nothing() {
    let mut card = Card::new();
    card.admin();
    assert_eq!(card.put(0x00D3, b"resetcode"), 0x9000);
    card.select();
    let before = card.host.persisted(Record::OpenPgp);
    card.host.fail_all(true);
    for (p2, pin) in [(0x81, &b"123456"[..]), (0x82, b"000000"), (0x82, b"123456"), (0x83, b"12345678"), (0x83, b"0")] {
        assert_eq!(card.verify(p2, pin), 0x6581, "VERIFY {p2:02X} {pin:?}");
    }
    for data in [&b"123456abcdef"[..], b"654321abcdef"] {
        assert_eq!(card.apdu(0x00, 0x24, 0x00, 0x81, data, None).1, 0x6581);
    }
    for data in [&b"resetcodenewpin1"[..], b"resetcodXnewpin1"] {
        assert_eq!(card.apdu(0x00, 0x2C, 0x00, 0x81, data, None).1, 0x6581);
    }
    // Nothing was verified, spent or changed, in memory or in storage.
    assert_eq!(card.retries(), [3, 3, 3]);
    for p2 in [0x81, 0x82, 0x83] {
        assert_eq!(card.verify(p2, b""), 0x63C3);
    }
    assert_eq!(card.host.persisted(Record::OpenPgp), before);
    card.host.fail_all(false);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    card.reload();
    assert_eq!(card.retries(), [3, 3, 3]);
}

/// Saves of a right presentation: the spent try, then the restored counter. When only
/// the restore fails the answer is 6581, the access is not granted and the try stays
/// spent (fail closed, persisted state and memory agree).
#[test]
fn right_pin_with_failed_counter_restore_stays_spent() {
    let mut card = Card::new();
    assert_eq!(card.verify(0x83, b"00000000"), 0x63C2);
    let attempts = card.host.persist_attempts();
    let verify = Command::new(0x00, 0x20, 0x00, 0x83).with_data(b"12345678".to_vec()).to_bytes();
    let resp = match card.app.process(&verify, &mut FailNth::new(&mut card.host, 2)) {
        Outcome::Done(resp) => resp,
        other => panic!("{other:?}"),
    };
    assert_eq!(resp, vec![0x65, 0x81]);
    assert_eq!(card.host.persist_attempts(), attempts + 2);
    assert_eq!(card.verify(0x83, b""), 0x63C1);
    card.reload();
    assert_eq!(card.retries(), [3, 0, 1]);
    // The next right presentation restores the counter (two saves).
    let attempts = card.host.persist_attempts();
    assert_eq!(card.verify(0x83, b"12345678"), 0x9000);
    assert_eq!(card.host.persist_attempts(), attempts + 2);
    assert_eq!(card.retries(), [3, 0, 3]);
    // A right PW1 change whose final save fails keeps the old PIN with the try spent.
    let change = Command::new(0x00, 0x24, 0x00, 0x81).with_data(b"123456abcdef".to_vec()).to_bytes();
    let resp = match card.app.process(&change, &mut FailNth::new(&mut card.host, 2)) {
        Outcome::Done(resp) => resp,
        other => panic!("{other:?}"),
    };
    assert_eq!(resp, vec![0x65, 0x81]);
    assert_eq!(card.retries(), [2, 0, 3]);
    assert_eq!(card.verify(0x82, b"abcdef"), 0x63C1);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
}

/// A host that fails exactly the `n`-th persist from now (1-based) and delegates
/// everything else to the `TestHost`.
struct FailNth<'a> {
    host: &'a mut TestHost,
    left: usize,
}

impl<'a> FailNth<'a> {
    fn new(host: &'a mut TestHost, n: usize) -> Self {
        Self { host, left: n }
    }
}

impl Entropy for FailNth<'_> {
    fn fill(&mut self, out: &mut [u8]) {
        self.host.fill(out);
    }
}

impl Host for FailNth<'_> {
    fn now(&self) -> Millis {
        self.host.now()
    }

    fn profile(&self) -> &DeviceProfile {
        self.host.profile()
    }

    fn persist(&mut self, record: Record, plaintext: &[u8]) -> Result<(), StoreError> {
        self.left = self.left.saturating_sub(1);
        if self.left == 0 {
            self.host.fail_next_saves(1);
            self.left = usize::MAX;
        }
        self.host.persist(record, plaintext)
    }
}

/// spec 3.4 §7.2.2: VERIFY with P1 = FF resets the access status of P2's password.
#[test]
fn verify_p1_ff_resets_status() {
    let mut card = Card::new();
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    card.admin();
    assert_eq!(card.apdu(0x00, 0x20, 0xFF, 0x82, b"", None).1, 0x9000);
    assert_eq!(card.verify(0x82, b""), 0x63C3);
    assert_eq!(card.verify(0x83, b""), 0x9000);
    assert_eq!(card.apdu(0x00, 0x20, 0xFF, 0x83, b"", None).1, 0x9000);
    assert_eq!(card.verify(0x83, b""), 0x63C3);
    // Lc must be absent.
    assert_eq!(card.apdu(0x00, 0x20, 0xFF, 0x83, b"x", None).1, 0x6700);
}

/// Catalog: VERIFY P1/P2, explicit Le and data validation happen before any retry change.
#[test]
fn verify_header_validation_before_retry() {
    let mut card = Card::new();
    assert_eq!(card.apdu(0x00, 0x20, 0x01, 0x82, b"000000", None).1, 0x6A86);
    assert_eq!(card.apdu(0x00, 0x20, 0x00, 0x84, b"000000", None).1, 0x6A86);
    assert_eq!(card.apdu(0x00, 0x20, 0x00, 0x80, b"000000", None).1, 0x6A86);
    assert_eq!(card.apdu(0x00, 0x20, 0x00, 0x82, b"000000", Some(1)).1, 0x6700);
    assert_eq!(card.apdu(0x00, 0x20, 0x00, 0x82, &[0x30; 128], None).1, 0x6700);
    assert_eq!(card.retries(), [3, 0, 3]);
    // Le = 00 is tolerated.
    assert_eq!(card.apdu(0x00, 0x20, 0x00, 0x82, b"123456", Some(0)).1, 0x9000);
}

/// spec §7.2.3: CHANGE REFERENCE DATA for PW1 and PW3.
#[test]
fn change_reference_data_pw1_and_pw3() {
    let mut card = Card::new();
    assert_eq!(card.apdu(0x00, 0x24, 0x00, 0x81, b"123456abcdef", None).1, 0x9000);
    assert_eq!(card.verify(0x82, b"123456"), 0x63C2);
    assert_eq!(card.verify(0x82, b"abcdef"), 0x9000);
    assert_eq!(card.verify(0x81, b"abcdef"), 0x9000);
    assert_eq!(card.apdu(0x00, 0x24, 0x00, 0x83, b"12345678new-admin-pin", None).1, 0x9000);
    assert_eq!(card.verify(0x83, b"new-admin-pin"), 0x9000);
    card.reload();
    assert_eq!(card.verify(0x82, b"abcdef"), 0x9000);
    assert_eq!(card.verify(0x83, b"new-admin-pin"), 0x9000);
}

/// Catalog: CHANGE REFERENCE DATA validates P1/P2/Le/new PIN before the retry counter.
#[test]
fn change_reference_data_validation_before_retry() {
    let mut card = Card::new();
    assert_eq!(card.apdu(0x00, 0x24, 0x01, 0x81, b"123456abcdef", None).1, 0x6A86);
    assert_eq!(card.apdu(0x00, 0x24, 0x00, 0x82, b"123456abcdef", None).1, 0x6A86);
    assert_eq!(card.apdu(0x00, 0x24, 0x00, 0x81, b"123456abcdef", Some(2)).1, 0x6700);
    assert_eq!(card.apdu(0x00, 0x24, 0x00, 0x81, b"", None).1, 0x6700);
    // New PW1 shorter than 6, new PW3 shorter than 8, new value longer than 127.
    assert_eq!(card.apdu(0x00, 0x24, 0x00, 0x81, b"000000abcde", None).1, 0x6A80);
    assert_eq!(card.apdu(0x00, 0x24, 0x00, 0x83, b"00000000abcdefg", None).1, 0x6A80);
    let mut long = b"000000".to_vec();
    long.extend_from_slice(&[b'a'; 128]);
    assert_eq!(card.apdu(0x00, 0x24, 0x00, 0x81, &long, None).1, 0x6A80);
    // Too short to hold the current PIN.
    assert_eq!(card.apdu(0x00, 0x24, 0x00, 0x81, b"1234", None).1, 0x6A80);
    assert_eq!(card.retries(), [3, 0, 3]);
}

/// spec §7.2.3: a wrong old PIN counts as a wrong presentation.
#[test]
fn change_reference_data_wrong_old_decrements() {
    let mut card = Card::new();
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    assert_eq!(card.apdu(0x00, 0x24, 0x00, 0x81, b"654321abcdef", None).1, 0x63C2);
    assert_eq!(card.verify(0x82, b""), 0x63C2);
    assert_eq!(card.apdu(0x00, 0x24, 0x00, 0x83, b"87654321abcdefgh", None).1, 0x63C2);
    assert_eq!(card.retries(), [2, 0, 2]);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
}

/// spec §7.2.4 P1 00 with the resetting code (spec §4.3.4).
#[test]
fn reset_retry_counter_with_resetting_code() {
    let mut card = Card::new();
    card.admin();
    assert_eq!(card.put(0x00D3, b"resetcode"), 0x9000);
    assert_eq!(card.retries(), [3, 3, 3]);
    for _ in 0..3 {
        card.verify(0x82, b"000000");
    }
    assert_eq!(card.verify(0x82, b"123456"), 0x6983);
    assert_eq!(card.apdu(0x00, 0x2C, 0x00, 0x81, b"resetcodenewpin1", None).1, 0x9000);
    assert_eq!(card.retries(), [3, 3, 3]);
    assert_eq!(card.verify(0x82, b"newpin1"), 0x9000);
}

/// spec §7.2.4 P1 02 after PW3 verification ("blocked PIN/admin reset").
#[test]
fn reset_retry_counter_with_pw3() {
    let mut card = Card::new();
    for _ in 0..3 {
        card.verify(0x82, b"000000");
    }
    assert_eq!(card.apdu(0x00, 0x2C, 0x02, 0x81, b"abcdef", None).1, 0x6982);
    card.admin();
    assert_eq!(card.apdu(0x00, 0x2C, 0x02, 0x81, b"abcde", None).1, 0x6A80);
    assert_eq!(card.apdu(0x00, 0x2C, 0x02, 0x81, b"abcdef", None).1, 0x9000);
    assert_eq!(card.retries(), [3, 0, 3]);
    assert_eq!(card.verify(0x81, b"abcdef"), 0x9000);
}

#[test]
fn reset_retry_counter_without_code_is_blocked() {
    let mut card = Card::new();
    assert_eq!(card.apdu(0x00, 0x2C, 0x00, 0x81, b"whateveranewpin", None).1, 0x6983);
}

/// A wrong resetting code decrements its own counter; header errors change nothing.
#[test]
fn reset_retry_counter_wrong_code_and_headers() {
    let mut card = Card::new();
    card.admin();
    assert_eq!(card.put(0x00D3, b"resetcode"), 0x9000);
    assert_eq!(card.apdu(0x00, 0x2C, 0x00, 0x81, b"resetcodXnewpin1", None).1, 0x63C2);
    assert_eq!(card.retries(), [3, 2, 3]);
    assert_eq!(card.apdu(0x00, 0x2C, 0x00, 0x82, b"resetcodenewpin1", None).1, 0x6A86);
    assert_eq!(card.apdu(0x00, 0x2C, 0x01, 0x81, b"resetcodenewpin1", None).1, 0x6A86);
    // Catalog: RESET RETRY COUNTER explicit-Le mutation guard.
    assert_eq!(card.apdu(0x00, 0x2C, 0x00, 0x81, b"resetcodenewpin1", Some(1)).1, 0x6700);
    // New PIN too short: rejected before the code is checked.
    assert_eq!(card.apdu(0x00, 0x2C, 0x00, 0x81, b"resetcodXnew", None).1, 0x6A80);
    assert_eq!(card.retries(), [3, 2, 3]);
    for _ in 0..2 {
        card.apdu(0x00, 0x2C, 0x00, 0x81, b"resetcodXnewpin1", None);
    }
    assert_eq!(card.apdu(0x00, 0x2C, 0x00, 0x81, b"resetcodenewpin1", None).1, 0x6983);
}

/// PW3 blocked: VERIFY 83 answers 6983 (recovery only by TERMINATE/ACTIVATE).
#[test]
fn pw3_blocks() {
    let mut card = Card::new();
    for expected in [0x63C2, 0x63C1, 0x63C0] {
        assert_eq!(card.verify(0x83, b"00000000"), expected);
    }
    assert_eq!(card.verify(0x83, b"12345678"), 0x6983);
    assert_eq!(card.apdu(0x00, 0x24, 0x00, 0x83, b"12345678abcdefgh", None).1, 0x6983);
}

/// Yubico SET RETRIES (F2): header rules before any change (catalog), PW3 required,
/// counters refilled to the new maxima.
#[test]
fn set_retries_rules() {
    let mut card = Card::new();
    assert_eq!(card.apdu(0x00, 0xF2, 0x01, 0x00, &[5, 5, 5], None).1, 0x6A86);
    assert_eq!(card.apdu(0x00, 0xF2, 0x00, 0x01, &[5, 5, 5], None).1, 0x6A86);
    assert_eq!(card.apdu(0x00, 0xF2, 0x00, 0x00, &[5, 5, 5], Some(1)).1, 0x6700);
    assert_eq!(card.apdu(0x00, 0xF2, 0x00, 0x00, &[5, 5, 5], None).1, 0x6982);
    card.admin();
    assert_eq!(card.apdu(0x00, 0xF2, 0x01, 0x00, &[5, 5, 5], None).1, 0x6A86);
    assert_eq!(card.apdu(0x00, 0xF2, 0x00, 0x00, &[5, 5, 5], Some(3)).1, 0x6700);
    assert_eq!(card.apdu(0x00, 0xF2, 0x00, 0x00, &[5, 5], None).1, 0x6700);
    assert_eq!(card.apdu(0x00, 0xF2, 0x00, 0x00, &[5, 0, 5], None).1, 0x6A80);
    assert_eq!(card.retries(), [3, 0, 3]);
    assert_eq!(card.apdu(0x00, 0xF2, 0x00, 0x00, &[5, 4, 7], None).1, 0x9000);
    // No resetting code set: its counter stays 0.
    assert_eq!(card.retries(), [5, 0, 7]);
    assert_eq!(card.put(0x00D3, b"resetcode"), 0x9000);
    assert_eq!(card.retries(), [5, 4, 7]);
    // PINs are unchanged and the new maximum applies after a wrong presentation.
    assert_eq!(card.verify(0x82, b"000000"), 0x63C4);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    assert_eq!(card.retries(), [5, 4, 7]);
    card.reload();
    assert_eq!(card.retries(), [5, 4, 7]);
}

/// SET RETRIES persists before it reports success; a storage failure changes nothing.
#[test]
fn set_retries_storage_failure() {
    let mut card = Card::new();
    card.admin();
    let before = card.host.persisted(Record::OpenPgp);
    card.host.fail_next_saves(1);
    assert_eq!(card.apdu(0x00, 0xF2, 0x00, 0x00, &[9, 9, 9], None).1, 0x6581);
    assert_eq!(card.retries(), [3, 0, 3]);
    assert_eq!(card.host.persisted(Record::OpenPgp), before);
}

/// Selecting the application again drops every verification (spec §4.3).
#[test]
fn select_drops_verification() {
    let mut card = Card::new();
    assert_eq!(card.verify(0x81, b"123456"), 0x9000);
    assert_eq!(card.verify(0x82, b"123456"), 0x9000);
    card.admin();
    assert_eq!(card.select(), 0x9000);
    assert_eq!(card.verify(0x81, b""), 0x63C3);
    assert_eq!(card.verify(0x82, b""), 0x63C3);
    assert_eq!(card.verify(0x83, b""), 0x63C3);
}

/// Every reset kind ends the card session (lk_core::ResetKind).
#[test]
fn reset_kinds_clear_volatile_state() {
    use lk_core::{CardApplet, ResetKind};
    for kind in [ResetKind::CardPowerOff, ResetKind::UsbReset, ResetKind::PowerCycle] {
        let mut card = Card::new();
        card.admin();
        card.app.reset(kind);
        assert_eq!(card.verify(0x83, b""), 0x63C3);
    }
    let mut card = Card::new();
    card.admin();
    card.app.deselect();
    assert_eq!(card.verify(0x83, b""), 0x63C3);
}

/// C4 byte 1 (PW1 validity) is writable with PW3 (spec §4.4.3.6).
#[test]
fn pw_status_byte_put() {
    let mut card = Card::new();
    assert_eq!(card.put(0x00C4, &[0x00]), 0x6982);
    card.admin();
    assert_eq!(card.put(0x00C4, &[0x00]), 0x9000);
    assert_eq!(card.pw_status()[0], 0x00);
    assert_eq!(card.put(0x00C4, &[0x02]), 0x6A80);
    assert_eq!(card.put(0x00C4, &[0x01, 0x7F]), 0x6700);
    assert_eq!(card.put(0x00C4, &[0x01]), 0x9000);
    assert_eq!(card.pw_status(), vec![0x01, 0x7F, 0x7F, 0x7F, 0x03, 0x00, 0x03]);
}

/// Resetting code D3 (spec §4.3.4): length policy, removal, never readable (catalog).
#[test]
fn resetting_code_rules() {
    let mut card = Card::new();
    assert_eq!(card.put(0x00D3, b"resetcode"), 0x6982);
    card.admin();
    assert_eq!(card.put(0x00D3, b"short"), 0x6A80);
    assert_eq!(card.put(0x00D3, &[b'r'; 128]), 0x6700);
    assert_eq!(card.put(0x00D3, b"resetcode"), 0x9000);
    assert_eq!(card.get(0x00D3), (vec![], 0x6B00));
    assert_eq!(card.retries(), [3, 3, 3]);
    assert_eq!(card.put(0x00D3, b""), 0x9000);
    assert_eq!(card.retries(), [3, 0, 3]);
    assert_eq!(card.apdu(0x00, 0x2C, 0x00, 0x81, b"resetcodenewpin1", None).1, 0x6983);
}
