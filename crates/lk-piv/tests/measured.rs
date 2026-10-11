//! Answers measured on a physical YubiKey 5C Nano 5.7.4 (docs/MEASUREMENT.md): each test
//! replays the APDUs of one probe of `tools/measure/probes.py` and expects the key's
//! answers. Assertions marked "derived" extend a measured rule to a case the read-only
//! probes could not send.

#![allow(clippy::unwrap_used)]

mod common;

use common::*;

/// The Discovery Object as the key returned it.
const DISCOVERY: &str = "7E124F0BA0000003080000100001005F2F024000";

/// Probe `piv-verify-status-81`: VERIFY with the PUK reference and no data is `6A80`
/// (SP 800-73-4 Part 2 §3.2.1 would give `6A88`).
#[test]
fn verify_of_the_puk_reference_answers_6a80() {
    let mut card = Card::new();
    let base = card.host.persist_count();
    assert_eq!(card.send("00200081"), (vec![], 0x6A80));
    // Derived: the PUK reference answers 6A80 whatever follows, and spends nothing.
    assert_eq!(card.send("0020008108313233343536FFFF").1, 0x6A80);
    assert_eq!(card.send("0020008108313233343536FFFF01").1, 0x6A80);
    assert_eq!(card.send("0020FF81").1, 0x6A80);
    // P1 is checked first; other references keep 6A88.
    assert_eq!(card.send("00200181").1, 0x6A86);
    for p2 in ["00", "01", "82", "9B"] {
        assert_eq!(card.send(&format!("002000{p2}")).1, 0x6A88, "{p2}");
    }
    assert_eq!(card.metadata(0x81).0, hex("0101FF 050101 06020303"), "PUK retries untouched");
    assert_eq!(card.pin_status(), 0x63C3);
    assert_eq!(card.host.persist_count(), base);
}

/// Probe `bad-p1p2-piv`: GET DATA with P1-P2 other than `3FFF` is `6A82`; GET VERSION and
/// GET SERIAL ignore P1-P2; GET METADATA with P1 `01` on an empty slot is `6A88`.
#[test]
fn bad_p1_p2_answers() {
    let mut card = Card::new();
    assert_eq!(card.send("00CB3FFE035C017E"), (vec![], 0x6A82));
    assert_eq!(card.send("00CB0000035C017E"), (vec![], 0x6A82));
    assert_eq!(card.send("00FD0100"), (hex("050704"), 0x9000));
    let (serial, sw) = card.send("00F80001");
    assert_eq!((serial.len(), sw), (4, 0x9000));
    assert_eq!(card.send("00F7019A"), (vec![], 0x6A88));
    assert_eq!(card.send("00F7009A"), (vec![], 0x6A88));
    // Derived: GET METADATA ignores P1 for every reference.
    assert_eq!(card.send("00F7FF80"), (hex("0101FF 050101 06020303"), 0x9000));
    let management = card.send("00F7009B");
    assert_eq!(card.send("00F7019B"), management);
    assert_eq!(card.send("00F70100").1, 0x6A86, "not a reference");
    // PUT DATA was not measured and keeps 6A86.
    card.auth_default();
    let payload = Card::put_payload(0x5FC102, &[0x01]);
    assert_eq!(card.cmd(0xDB, 0x3F, 0xFE, &payload, None).1, 0x6A86);
}

/// Probe `lc-le-piv-get-data`: Le forms are accepted, a tag list cut short is `6A82`, and a
/// short Le gets `61xx`.
#[test]
fn get_data_length_forms_and_a_cut_short_tag_list() {
    let mut card = Card::new();
    assert_eq!(card.send("00CB3FFF035C017E00"), (hex(DISCOVERY), 0x9000));
    assert_eq!(card.send("00CB3FFF0000035C017E0000"), (hex(DISCOVERY), 0x9000));
    assert_eq!(card.send("00CB3FFF0000035C017E"), (hex(DISCOVERY), 0x9000));
    // Lc 2: `5C 01` with its value missing; the trailing 7E is Le.
    assert_eq!(card.send("00CB3FFF025C017E"), (vec![], 0x6A82));
    let (first, sw) = card.send("00CB3FFF035C017E01");
    assert_eq!((first, sw), (hex("7E"), 0x6113));
    // Derived: any one-byte length running past the data field; a missing length byte
    // or a malformed list stays 6A80 (unmeasured).
    assert_eq!(card.send("00CB3FFF045C035FC1").1, 0x6A82);
    assert_eq!(card.send("00CB3FFF015C").1, 0x6A80);
    assert_eq!(card.send("00CB3FFF035C0101").1, 0x6A80);
}

/// Probe `get-response-idle-piv`: GET RESPONSE with nothing pending is `6A80`.
#[test]
fn get_response_with_nothing_pending_answers_6a80() {
    let mut card = Card::new();
    assert_eq!(card.send("00C0000000"), (vec![], 0x6A80));
    // Derived: also once a long response has been read to its end.
    let (first, sw) = card.send("00CB3FFF035C017E01");
    assert_eq!((first.len(), sw), (1, 0x6113));
    let (rest, sw) = card.send("00C0000000");
    assert_eq!((rest.len(), sw), (0x13, 0x9000));
    assert_eq!(card.send("00C0000000"), (vec![], 0x6A80));
    // P1-P2 other than 0000 keeps 6A86 (model policy).
    assert_eq!(card.send("00C0010000").1, 0x6A86);
}

/// Probe `cla-variants-piv`: CLA 80 is taken like 00; CLA 10 leaves a chain open, which
/// another instruction answers with 6883; a SELECT clears it.
#[test]
fn class_variants() {
    let mut card = Card::new();
    assert_eq!(card.send("80CB3FFF035C017E"), (hex(DISCOVERY), 0x9000));
    assert_eq!(card.send("10CB3FFF035C017E"), (vec![], 0x9000));
    assert_eq!(card.send("00FD0000"), (vec![], 0x6883));
    assert_eq!(card.send(SELECT).1, 0x9000);
    assert_eq!(card.send("00CB3FFF035C017E"), (hex(DISCOVERY), 0x9000));
    // Derived: CLA 80 for other instructions.
    assert_eq!(card.send("80FD0000"), (hex("050704"), 0x9000));
    assert_eq!(card.send("80200080").1, 0x63C3);
    // 90 (80 with the chaining bit) is unmeasured and stays 6E00.
    assert_eq!(card.send("90CB3FFF035C017E").1, 0x6E00);
}
