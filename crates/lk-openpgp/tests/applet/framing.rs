//! CLA/INS rules, command chaining, GET RESPONSE, extended length, GET CHALLENGE, MSE.

use crate::common::{Card, hex};

/// ISO 7816-4 §5.4.1: proprietary class and logical channels; unknown instructions. CLA 80
/// is taken like 00 (docs/MEASUREMENT.md, probe cla-variants-openpgp; tests/applet/measured.rs),
/// so the unsupported class here is A0.
#[test]
fn unsupported_cla_and_ins() {
    let mut card = Card::new();
    assert_eq!(card.send(&hex("A0CA006E00")).1, 0x6E00);
    assert_eq!(card.send(&hex("90CA006E00")).1, 0x6E00);
    assert_eq!(card.send(&hex("01CA006E00")).1, 0x6881);
    assert_eq!(card.send(&hex("0012000000")).1, 0x6D00);
    // The key instructions exist; the Yubico GET ATTESTATION takes CLA 80 only.
    assert_eq!(card.apdu(0x00, 0x47, 0x00, 0x00, b"", None).1, 0x6A86);
    assert_eq!(card.apdu(0x00, 0x2A, 0x00, 0x00, b"", None).1, 0x6A86);
    assert_eq!(card.apdu(0x00, 0x88, 0x01, 0x00, b"", None).1, 0x6A86);
    assert_eq!(card.apdu(0x00, 0xDB, 0x00, 0x00, b"", None).1, 0x6B00);
    assert_eq!(card.apdu(0x00, 0xFB, 0x01, 0x00, b"", None).1, 0x6E00);
    assert_eq!(card.apdu(0x80, 0xFB, 0x01, 0x00, b"", None).1, 0x6982);
}

/// ISO 7816-4 §5.1: a malformed APDU is `6700`.
#[test]
fn malformed_apdu_is_wrong_length() {
    let mut card = Card::new();
    assert_eq!(card.send(&[0x00, 0xCA]).1, 0x6700);
    assert_eq!(card.send(&hex("00DA5F5005 6162")).1, 0x6700);
}

/// docs/CONTRACTS.md "APDU conventions": applets answer `6882` to secure-messaging CLA
/// bits. lk-device clears them after unwrapping a secure channel, and forwards them
/// unchanged when no channel is open, so a command that still has them was never
/// verified; C0 announces no secure messaging (ISO 7816-4 §5.1.1). The check comes before
/// the logical-channel one (as in lk-piv), and like every CLA rejection it leaves a
/// pending response in place.
#[test]
fn secure_messaging_bits_answer_6882() {
    let mut card = Card::yubikey();
    for apdu in ["04CA5F5200", "08CA5F5200", "0CCA5F5200", "1CDA5F5000", "0DCA5F5200", "0C20008106313233343536"] {
        assert_eq!(card.send(&hex(apdu)), (vec![], 0x6882), "{apdu}");
    }
    assert_eq!(card.retries(), [3, 0, 3]);
    // GET ATTESTATION: proprietary 84 is the secure-messaging form of 80.
    assert_eq!(card.send(&hex("84FB010000")).1, 0x6882);
    assert_eq!(card.send(&hex("80FB010000")).1, 0x6982);
    // A pending response survives the rejected class.
    assert_eq!(card.send(&hex("00CA006E00")).1, 0x613B);
    assert_eq!(card.send(&hex("0CC0000000")).1, 0x6882);
    let (rest, sw) = card.send(&hex("00C0000000"));
    assert_eq!((rest.len(), sw), (59, 0x9000));
    assert_eq!(card.send(&hex("00CA5F5200")).1, 0x9000);
}

/// Catalog: "OpenPGP GET DATA rejects unsupported command-chain CLA 10 with 6E00, leaving
/// the next YubiKit GET DATA unaffected". The first half is contradicted by the
/// measurement: the reference key answers `10 CA 00 C4` with `9000` and no data,
/// leaving the chain open (docs/MEASUREMENT.md, probe cla-variants-openpgp; this test
/// expected 6E00 before). The next GET DATA of the same object completes the chain and is
/// answered as usual; one of another object breaks it (6883) and is not executed.
#[test]
fn get_data_accepts_chaining_cla_10() {
    let mut card = Card::new();
    assert_eq!(card.send(&hex("10CA006E00")), (vec![], 0x9000));
    assert_eq!(card.send(&hex("00CA5F5200")), (vec![], 0x6883));
    assert_eq!(card.get(0x5F52).1, 0x9000);
    assert_eq!(card.send(&hex("10CA5F5200")), (vec![], 0x9000));
    let (data, sw) = card.get(0x5F52);
    assert_eq!((data, sw), card.get(0x5F52), "the chained read gives the plain answer");
    // Other data-less commands reject chaining (model policy, unmeasured).
    for apdu in ["10CC7F2100", "1084000008", "10E60000", "10440000", "10F1000000", "10C0000000"] {
        assert_eq!(card.send(&hex(apdu)).1, 0x6E00, "{apdu}");
    }
}

/// ISO 7816-4 §7.6.1 GET RESPONSE: long responses are served in 61xx chunks.
#[test]
fn get_response_serves_long_data() {
    let mut card = Card::yubikey();
    let (first, sw) = card.send(&hex("00CA006E00"));
    assert_eq!(first.len(), 256);
    assert_eq!(sw, 0x613B);
    let (rest, sw) = card.send(&hex("00C0000000"));
    assert_eq!(sw, 0x9000);
    assert_eq!(first.len() + rest.len(), 315);
    // Le smaller than the data: chunks of Le.
    let (part, sw) = card.send(&hex("00CA5F5205"));
    assert_eq!((part.len(), sw), (5, 0x6103));
    let (tail, sw) = card.send(&hex("00C0000003"));
    assert_eq!((tail.len(), sw), (3, 0x9000));
    // Nothing pending: 6D00 (docs/MEASUREMENT.md, probes get-response-idle-openpgp and
    // chain-61xx; was 6985).
    assert_eq!(card.send(&hex("00C0000000")).1, 0x6D00);
}

/// Catalog: "GET RESPONSE rejects unsupported plaintext CLA before consuming a pending
/// response".
#[test]
fn get_response_rejects_bad_cla_without_consuming() {
    let mut card = Card::yubikey();
    let (first, sw) = card.send(&hex("00CA00FA00"));
    assert_eq!(sw, 0x61A5);
    // CLA 80 is a supported class since docs/MEASUREMENT.md (probe cla-variants-openpgp),
    // so A0 and 90 stand for the unsupported proprietary classes here.
    assert_eq!(card.send(&hex("A0C0000000")), (vec![], 0x6E00));
    assert_eq!(card.send(&hex("90C0000000")), (vec![], 0x6E00));
    assert_eq!(card.send(&hex("10C0000000")), (vec![], 0x6E00));
    assert_eq!(card.send(&hex("01C0000000")), (vec![], 0x6881));
    assert_eq!(card.send(&hex("00C0010000")), (vec![], 0x6A86));
    let (rest, sw) = card.send(&hex("00C0000000"));
    assert_eq!(sw, 0x9000);
    let mut all = first;
    all.extend_from_slice(&rest);
    assert_eq!(all, crate::common::observed_hex("algorithm_information"));
}

/// Any other command discards the pending response (ISO 7816-4 §7.6.1).
#[test]
fn other_command_discards_pending_response() {
    let mut card = Card::yubikey();
    assert_eq!(card.send(&hex("00CA006E00")).1, 0x613B);
    assert_eq!(card.get(0x5F52).1, 0x9000);
    // Nothing pending: 6D00 (docs/MEASUREMENT.md, probe get-response-idle-openpgp).
    assert_eq!(card.send(&hex("00C0000000")).1, 0x6D00);
}

/// Catalog: "OpenPGP GET RESPONSE during unfinished command chaining returns 6883". The
/// status is contradicted by the measurement: the reference key answers GET
/// RESPONSE during an open chain with 6D00 (docs/MEASUREMENT.md, probe
/// cla-variants-openpgp; this test expected 6883 before). The chain is dropped (model
/// policy) and a later chained PUT DATA works.
#[test]
fn get_response_during_chain_returns_6d00() {
    let mut card = Card::new();
    card.admin();
    assert_eq!(card.apdu(0x10, 0xDA, 0x5F, 0x50, b"https://", None).1, 0x9000);
    assert_eq!(card.send(&hex("00C0000000")).1, 0x6D00);
    // The final part alone is now an unchained command.
    assert_eq!(card.apdu(0x00, 0xDA, 0x5F, 0x50, b"example.org", None).1, 0x9000);
    assert_eq!(card.get_ok(0x5F50), b"example.org");
    assert_eq!(card.apdu(0x10, 0xDA, 0x5F, 0x50, b"https://", None).1, 0x9000);
    assert_eq!(card.apdu(0x00, 0xDA, 0x5F, 0x50, b"example.org", None).1, 0x9000);
    assert_eq!(card.get_ok(0x5F50), b"https://example.org");
}

/// ISO 7816-4 §5.1.1.1 / lk_codec CommandChain: a header change mid-chain is 6883.
#[test]
fn header_change_mid_chain_returns_6883() {
    let mut card = Card::new();
    card.admin();
    assert_eq!(card.apdu(0x10, 0xDA, 0x5F, 0x50, b"abc", None).1, 0x9000);
    assert_eq!(card.apdu(0x00, 0xDA, 0x00, 0x5E, b"def", None).1, 0x6883);
    assert_eq!(card.get_ok(0x5F50), b"");
    assert_eq!(card.get_ok(0x005E), b"");
    // An unknown INS or a rejected CLA does not disturb an open chain.
    assert_eq!(card.apdu(0x10, 0xDA, 0x5F, 0x50, b"abc", None).1, 0x9000);
    assert_eq!(card.send(&hex("0012000000")).1, 0x6D00);
    // (CLA 80 is a supported class since docs/MEASUREMENT.md; A0 is not.)
    assert_eq!(card.send(&hex("A0CA006E00")).1, 0x6E00);
    assert_eq!(card.apdu(0x00, 0xDA, 0x5F, 0x50, b"def", None).1, 0x9000);
    assert_eq!(card.get_ok(0x5F50), b"abcdef");
}

/// Chained VERIFY is assembled before the password is checked.
#[test]
fn chained_verify() {
    let mut card = Card::new();
    assert_eq!(card.apdu(0x10, 0x20, 0x00, 0x83, b"1234", None).1, 0x9000);
    assert_eq!(card.apdu(0x00, 0x20, 0x00, 0x83, b"5678", None).1, 0x9000);
    assert_eq!(card.verify(0x83, b""), 0x9000);
}

/// Extended length (historical bytes / 7F66): a whole response in one extended APDU, and
/// the 3070-byte command limit.
#[test]
fn extended_length() {
    let mut card = Card::yubikey();
    let (data, sw) = card.apdu_ext(0x00, 0xCA, 0x00, 0x6E, b"", Some(0));
    assert_eq!((data.len(), sw), (315, 0x9000));
    let (data, sw) = card.apdu_ext(0x00, 0xCA, 0x00, 0xFA, b"", Some(0));
    assert_eq!((data.len(), sw), (421, 0x9000));
    card.admin();
    assert_eq!(card.put(0x5F50, &[0x41; 3071]), 0x6700);
    assert_eq!(card.put(0x5F50, &[0x41; 300]), 0x6700);
}

/// spec §7.2.15 GET CHALLENGE, up to 3070 bytes (catalog: observed 3070-byte challenge).
#[test]
fn get_challenge() {
    let mut card = Card::new();
    let (a, sw) = card.send(&hex("0084000008"));
    assert_eq!((a.len(), sw), (8, 0x9000));
    let (b, _) = card.send(&hex("0084000008"));
    assert_ne!(a, b);
    let (short_max, sw) = card.send(&hex("0084000000"));
    assert_eq!((short_max.len(), sw), (256, 0x9000));
    let (big, sw) = card.apdu(0x00, 0x84, 0x00, 0x00, b"", Some(3070));
    assert_eq!((big.len(), sw), (3070, 0x9000));
    assert_eq!(card.apdu(0x00, 0x84, 0x00, 0x00, b"", Some(3071)).1, 0x6700);
    assert_eq!(card.apdu(0x00, 0x84, 0x00, 0x00, b"", Some(0)).1, 0x9000);
    assert_eq!(card.send(&hex("00840000")).1, 0x6700);
    assert_eq!(card.send(&hex("0084010008")).1, 0x6A86);
    assert_eq!(card.send(&hex("008400000101 08")).1, 0x6700);
}

/// The challenge comes from host entropy (deterministic under a fixed seed).
#[test]
fn get_challenge_uses_host_entropy() {
    let mut card = Card::new();
    card.host.push_entropy(&[1, 2, 3, 4]);
    assert_eq!(card.send(&hex("0084000004")), (vec![1, 2, 3, 4], 0x9000));
}

/// spec §7.2.18 MANAGE SECURITY ENVIRONMENT header and data rules.
#[test]
fn manage_security_environment_rules() {
    let mut card = Card::new();
    assert_eq!(card.apdu(0x00, 0x22, 0x41, 0xA4, &hex("830102"), None).1, 0x9000);
    assert_eq!(card.apdu(0x00, 0x22, 0x41, 0xB8, &hex("830103"), None).1, 0x9000);
    assert_eq!(card.apdu(0x00, 0x22, 0x41, 0xB8, &hex("830102"), None).1, 0x9000);
    assert_eq!(card.apdu(0x00, 0x22, 0x81, 0xB8, &hex("830102"), None).1, 0x6A86);
    assert_eq!(card.apdu(0x00, 0x22, 0x41, 0xB6, &hex("830102"), None).1, 0x6A86);
    assert_eq!(card.apdu(0x00, 0x22, 0x41, 0xA4, &hex("830101"), None).1, 0x6A80);
    assert_eq!(card.apdu(0x00, 0x22, 0x41, 0xA4, &hex("840102"), None).1, 0x6A80);
    assert_eq!(card.apdu(0x00, 0x22, 0x41, 0xA4, &hex("83020203"), None).1, 0x6A80);
    assert_eq!(card.apdu(0x00, 0x22, 0x41, 0xA4, &hex("830102"), Some(2)).1, 0x6700);
}

/// Without an operation waiting for a touch, a stray resume is refused.
#[test]
fn touch_resolved_without_pending_command() {
    use lk_core::CardApplet;
    let mut card = Card::new();
    assert_eq!(card.app.touch_resolved(true, &mut card.host), vec![0x69, 0x85]);
}
