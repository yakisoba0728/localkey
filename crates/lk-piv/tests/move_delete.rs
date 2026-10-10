//! MOVE KEY and DELETE KEY (`INS F6`, Yubico PIV extensions, firmware 5.7): P1 the
//! destination or `FF`, P2 the source. Yubico: "Move a key from any slot except F9
//! (attestation) to any other slot except F9", "Delete a key from any slot including F9";
//! the Yubico SDK documents that "the destination slot must be empty", and
//! yubico-piv-tool that a move "only moves the key, not the certificate".

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use lk_core::Record;

const DIGEST: [u8; 32] = [0x3C; 32];

fn authed() -> Card {
    let mut card = Card::new();
    card.auth_default();
    card
}

#[test]
fn move_key_keeps_policies_and_origin_and_leaves_certificates() {
    let mut card = authed();
    let public = card.generate(0x9A, P256, Some(PIN_NEVER), Some(TOUCH_NEVER));
    let info = card.slot_info(0x9A).unwrap();
    assert_eq!(card.put_object(0x5FC105, &hex("7003300100 710100 FE00")), 0x9000);
    assert_eq!(card.send("00F6829A").1, 0x9000);
    assert_eq!(card.slot_info(0x9A), None, "source is empty");
    assert_eq!(card.slot_info(0x82).unwrap(), info, "same key, policies and origin");
    assert_eq!(card.object_value(0x5FC105), Some(hex("7003300100 710100 FE00")), "certificate stays");
    assert_eq!(card.get_object(0x5FC10D).1, 0x6A82, "nothing copied to the retired container");
    let (sig, sw) = card.ga(0x82, P256, 0x81, &DIGEST);
    assert_eq!(sw, 0x9000);
    assert!(ecdsa_ok(P256, public.point(), &DIGEST, &sig));
    assert_eq!(card.ga(0x9A, P256, 0x81, &DIGEST).1, 0x6A88);
    // A moved generated key can still be attested.
    assert_eq!(card.attest(0x82).1, 0x9000);
    card.restart();
    assert_eq!(card.slot_info(0x82).unwrap(), info, "persisted");
    assert_eq!(card.slot_info(0x9A), None);
}

#[test]
fn move_key_rules() {
    let mut card = Card::new();
    assert_eq!(card.send("00F6829A").1, 0x6982, "needs the management key");
    card.auth_default();
    card.generate(0x9A, P256, None, None);
    card.generate(0x9C, ED25519, None, None);
    let before = card.host.persisted(Record::Piv);
    // Catalog: extra data or explicit Le is 6700 before any key changes.
    assert_eq!(card.send("00F6829A0100").1, 0x6700, "data");
    assert_eq!(card.send("00F6829A01").1, 0x6700, "explicit Le");
    assert_eq!(card.send("00F6829A0000").1, 0x6700, "malformed length field");
    assert_eq!(card.send("00F6F99A").1, 0x6A86, "F9 destination");
    assert_eq!(card.send("00F682F9").1, 0x6A86, "F9 source");
    assert_eq!(card.send("00F69A9A").1, 0x6A86, "same slot");
    assert_eq!(card.send("00F69B9A").1, 0x6A86, "management key reference");
    assert_eq!(card.send("00F6809A").1, 0x6A86, "PIN reference");
    assert_eq!(card.send("00F68296").1, 0x6A86, "source not a key slot");
    assert_eq!(card.send("00F6829D").1, 0x6A88, "empty source");
    assert_eq!(card.send("00F69C9A").1, 0x6985, "occupied destination");
    assert_eq!(card.host.persisted(Record::Piv), before, "nothing changed");
    assert_eq!(card.slot_info(0x9C).unwrap().alg, ED25519);
    assert_eq!(card.slot_info(0x9A).unwrap().alg, P256);
    // The T=0 case 1 form (P3 = 00, ISO/IEC 7816-3 §12.2.2) is not an explicit Le.
    assert_eq!(card.send("00F6959A00").1, 0x9000);
    assert_eq!(card.slot_info(0x95).unwrap().alg, P256);
}

#[test]
fn delete_key_including_f9() {
    let mut card = Card::new();
    assert_eq!(card.send("00F6FF9A").1, 0x6982);
    card.auth_default();
    card.generate(0x9A, P256, None, None);
    assert_eq!(card.send("00F6FF9A01").1, 0x6700);
    assert_eq!(card.send("00F6FF9A0100").1, 0x6700);
    assert_eq!(card.send("00F6FF96").1, 0x6A86);
    assert_eq!(card.send("00F6FF9A").1, 0x9000);
    assert_eq!(card.slot_info(0x9A), None);
    assert_eq!(card.send("00F6FF9A").1, 0x6A88, "already empty");
    // Firmware 5.7 accepts deleting the attestation key.
    assert_eq!(card.send("00F6FFF9").1, 0x9000);
    assert_eq!(card.slot_info(0xF9), None);
    card.restart();
    assert_eq!(card.slot_info(0xF9), None);
}

#[test]
fn storage_failure_keeps_keys_where_they_were() {
    let mut card = authed();
    let info = {
        card.generate(0x9A, P256, None, None);
        card.slot_info(0x9A).unwrap()
    };
    card.host.fail_next_saves(1);
    assert_eq!(card.send("00F6829A").1, 0x6581);
    assert_eq!(card.slot_info(0x9A).unwrap(), info);
    assert_eq!(card.slot_info(0x82), None);
    card.host.fail_next_saves(1);
    assert_eq!(card.send("00F6FF9A").1, 0x6581);
    assert_eq!(card.slot_info(0x9A).unwrap(), info);
    card.restart();
    assert_eq!(card.slot_info(0x9A).unwrap(), info);
}
