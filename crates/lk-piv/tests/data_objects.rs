//! SELECT, GET DATA, PUT DATA, capacity limits and chaining
//! (SP 800-73-4 Part 2 §3.1.1, §3.1.2, §3.3.2; ISO/IEC 7816-4 §5.1.1.1, §7.6.1).

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use lk_codec::tlv;
use lk_core::{CardApplet, Record};

/// `reference/legacy-v0.64-profiles.json`, `piv_initial_profile.select_response`.
const SELECT_RESPONSE: &str = "61114f0600001000010079074f05a000000308";
/// `reference/legacy-v0.64-profiles.json`, `piv_initial_profile.discovery_response`.
const DISCOVERY: &str = "7e124f0ba0000003080000100001005f2f024000";

const CHUID: u32 = 0x5FC102;
const PIV_AUTH_CERT: u32 = 0x5FC105;
const PRINTED: u32 = 0x5FC109;
const FACIAL: u32 = 0x5FC108;
const ATTESTATION_CERT: u32 = 0x5FFF01;

#[test]
fn select_returns_profile_application_property_template() {
    let mut card = Card::new();
    let resp = card.piv.select(&hex(SELECT), &mut card.host);
    assert_eq!(resp, hex(&format!("{SELECT_RESPONSE}9000")));
    assert_eq!(card.piv.aid(), hex("A000000308").as_slice());
    // A SELECT routed through process answers the same template.
    assert_eq!(card.send(SELECT), (hex(SELECT_RESPONSE), 0x9000));
}

#[test]
fn discovery_object_is_fixed_and_read_only() {
    let mut card = Card::new();
    assert_eq!(card.send("00CB3FFF035C017E00"), (hex(DISCOVERY), 0x9000));
    card.auth_default();
    let before = card.host.persist_count();
    assert_eq!(card.send("00DB3FFF0B5C017E7E065F2F024000FF").1, 0x6A80);
    assert_eq!(card.send("00DB3FFF055C017E5300").1, 0x6A80);
    assert_eq!(card.host.persist_count(), before, "no state change");
    assert_eq!(card.send("00CB3FFF035C017E00"), (hex(DISCOVERY), 0x9000));
}

#[test]
fn biometric_group_template_is_unsupported() {
    // Profile: biometric_group_template "unsupported; no data"; readonly_objects 7F61.
    let mut card = Card::new();
    assert_eq!(card.send("00CB3FFF045C027F6100").1, 0x6A82);
    card.auth_default();
    assert_eq!(card.send("00DB3FFF075C027F617F6100").1, 0x6A80);
    assert_eq!(card.send("00DB3FFF065C027F615300").1, 0x6A80);
    assert_eq!(card.send("00CB3FFF045C027F6100").1, 0x6A82);
}

#[test]
fn factory_card_has_no_chuid_ccc_or_certificates() {
    let mut card = Card::new();
    for tag in [CHUID, 0x5FC107, 0x5FC106, PIV_AUTH_CERT, 0x5FC10A, 0x5FC10B, 0x5FC101, 0x5FC10C, 0x5FC10D, 0x5FC120] {
        assert_eq!(card.get_object(tag).1, 0x6A82, "{tag:06X}");
    }
}

#[test]
fn get_data_header_and_tag_list_validation() {
    let mut card = Card::new();
    // P1-P2 must be 3FFF (SP 800-73-4 Part 2 §3.1.2).
    assert_eq!(card.send("00CB3FFE035C017E00").1, 0x6A86);
    assert_eq!(card.send("00CB0000035C017E00").1, 0x6A86);
    for data in [
        "",                   // no tag list
        "5C",                 // truncated
        "5C025FC1",           // two-byte 5F tag
        "5C035F0102",         // not a three-byte BER tag
        "5C045FC10200",       // too long
        "5C065FC1025FC105",   // more than one tag
        "53035FC102",         // wrong wrapper tag
        "5C035FC10200",       // trailing byte
        "5C0101",             // one-byte tag other than 7E
    ] {
        let data = hex(data);
        assert_eq!(card.cmd(0xCB, 0x3F, 0xFF, &data, Some(0)).1, 0x6A80, "{data:02X?}");
    }
    // Le absent is accepted (ykpiv sends GET DATA without Le).
    assert_eq!(card.send("00CB3FFF035C017E"), (hex(DISCOVERY), 0x9000));
}

#[test]
fn put_data_requires_management_key() {
    let mut card = Card::new();
    let base = card.host.persist_count();
    assert_eq!(card.put_object(CHUID, &[0x30, 0x19]), 0x6982);
    card.verify_default_pin();
    assert_eq!(card.put_object(CHUID, &[0x30, 0x19]), 0x6982, "the PIN does not authorize PUT DATA");
    assert_eq!(card.host.persist_count(), base + 2, "only the PIN check persisted");
}

#[test]
fn put_then_get_round_trip_and_delete() {
    let mut card = Card::new();
    card.auth_default();
    let chuid = hex("3019d4e739da739ced39ce739d836858210842108421c84210c3eb3410000000000000000000000000000000003508323033303031303135");
    assert_eq!(card.put_object(CHUID, &chuid), 0x9000);
    let (data, sw) = card.get_object(CHUID);
    assert_eq!(sw, 0x9000);
    assert_eq!(data, tlv::encode(0x53, &chuid));
    // An empty 53 deletes the object (SP 800-73-4 Part 2 §3.3.2).
    assert_eq!(card.send("00DB3FFF075C035FC1025300").1, 0x9000);
    assert_eq!(card.get_object(CHUID).1, 0x6A82);
    // Deleting an absent object succeeds too.
    assert_eq!(card.send("00DB3FFF075C035FC1025300").1, 0x9000);
}

#[test]
fn put_data_header_and_layout_validation() {
    let mut card = Card::new();
    let before = card.host.persisted(Record::Piv);
    card.auth_default();
    assert_eq!(card.send("00DB3FFE095C035FC1025302AABB").1, 0x6A86);
    // Explicit Le is rejected before any change (catalog: PUT DATA absent-Le guard).
    assert_eq!(card.send("00DB3FFF095C035FC1025302AABB00").1, 0x6700);
    for data in [
        "5C035FC102",             // no 53
        "5C035FC1025302AA",       // truncated 53
        "5C035FC1025402AABB",     // wrong data tag
        "5C035FC1025302AABB00",   // trailing byte
        "5C035FC10253",           // truncated length
        "5D035FC1025302AABB",     // wrong tag list tag
        "5C025FC15302AABB",       // malformed tag
    ] {
        let data = hex(data);
        assert_eq!(card.cmd(0xDB, 0x3F, 0xFF, &data, None).1, 0x6A80, "{data:02X?}");
    }
    assert_eq!(card.get_object(CHUID).1, 0x6A82, "nothing was stored");
    assert_eq!(card.host.persisted(Record::Piv), before, "nothing was persisted");
}

#[test]
fn vendor_and_arbitrary_5f_tags_are_storage() {
    // Yubico PIV documentation: vendor objects 5FFF00.. and any 5F xx xx tag.
    let mut card = Card::new();
    card.auth_default();
    for tag in [0x5FFF00, 0x5FFF10, 0x5FFF15, 0x5FC123, 0x5FA001] {
        assert_eq!(card.put_object(tag, &[1, 2, 3]), 0x9000, "{tag:06X}");
    }
    assert_eq!(card.object_value(0x5FFF10), Some(vec![1, 2, 3]));
    assert_eq!(card.object_value(0x5FA001), Some(vec![1, 2, 3]));
}

#[test]
fn pin_protected_objects_need_verified_pin() {
    // SP 800-73-4 Part 1 Table 3: fingerprints, facial image, printed information, iris
    // and pairing code are read with the PIN.
    let mut card = Card::new();
    card.auth_default();
    // reference/piv-printed-source-conflict.md: model policy accepts PUT DATA 5FC109.
    assert_eq!(card.put_object(PRINTED, &hex("8803AABBCC")), 0x9000);
    assert_eq!(card.put_object(CHUID, &[0x30, 0x00]), 0x9000);
    for tag in [PRINTED, FACIAL, 0x5FC103, 0x5FC121, 0x5FC123] {
        assert_eq!(card.get_object(tag).1, 0x6982, "{tag:06X} without PIN");
    }
    assert_eq!(card.object_value(CHUID), Some(vec![0x30, 0x00]), "always readable");
    card.verify_default_pin();
    assert_eq!(card.object_value(PRINTED), Some(hex("8803AABBCC")));
    assert_eq!(card.get_object(FACIAL).1, 0x6A82);
    // Resetting the PIN status (VERIFY P1 FF) protects them again.
    assert_eq!(card.send("0020FF80").1, 0x9000);
    assert_eq!(card.get_object(PRINTED).1, 0x6982);
}

#[test]
fn long_object_uses_command_and_response_chaining() {
    let mut card = Card::new();
    card.auth_default();
    let value: Vec<u8> = (0..3000u32).map(|i| (i * 7 + 1) as u8).collect();
    assert_eq!(card.put_object(CHUID, &value), 0x9000);
    // Short GET DATA: 256-byte pieces with 61xx, then GET RESPONSE (ISO/IEC 7816-4
    // §7.6.1). 3004 bytes = 11 pieces of 256 and one of 188.
    let data = tlv::encode(0x5C, &[0x5F, 0xC1, 0x02]);
    let (first, sw) = card.cmd(0xCB, 0x3F, 0xFF, &data, Some(0));
    assert_eq!((first.len(), sw), (256, 0x6100));
    let mut all = first;
    let mut statuses = Vec::new();
    loop {
        let (more, sw) = card.send("00C0000000");
        all.extend_from_slice(&more);
        statuses.push(sw);
        if sw == 0x9000 {
            break;
        }
    }
    assert_eq!(statuses.len(), 11);
    assert_eq!(statuses[9], 0x61BC, "188 bytes left before the last piece");
    assert_eq!(all, tlv::encode(0x53, &value));
    // Nothing more is pending.
    assert_eq!(card.send("00C0000000").1, 0x6985);
    // Extended GET DATA with Le 0000 returns everything at once.
    let (all_at_once, sw) = card.send("00CB3FFF0000055C035FC1020000");
    assert_eq!(sw, 0x9000);
    assert_eq!(all_at_once, tlv::encode(0x53, &value));
}

#[test]
fn another_command_discards_pending_response() {
    let mut card = Card::new();
    card.auth_default();
    assert_eq!(card.put_object(CHUID, &[0xAB; 600]), 0x9000);
    let (_, sw) = card.send("00CB3FFF055C035FC10200");
    assert_eq!(sw, 0x6100);
    assert_eq!(card.pin_status(), 0x63C3);
    assert_eq!(card.send("00C0000000").1, 0x6985);
    // GET RESPONSE with P1-P2 other than 0000.
    let (_, sw) = card.send("00CB3FFF055C035FC10200");
    assert_eq!(sw, 0x6100);
    assert_eq!(card.send("00C0010000").1, 0x6A86);
}

#[test]
fn assembled_command_data_limit_is_3072_bytes() {
    // piv_allocation_model.plaintext_apdu_data_limit = 3072. Payload = 5C 03 tag (5) +
    // 53 82 LL LL (4) + value.
    let mut card = Card::new();
    card.auth_default();
    let fits = Card::put_payload(CHUID, &vec![0x11; 3063]);
    assert_eq!(fits.len(), 3072);
    assert_eq!(card.chained(0xDB, 0x3F, 0xFF, &fits).1, 0x9000);
    let persisted = card.host.persisted(Record::Piv);
    let count = card.host.persist_count();
    let over = Card::put_payload(CHUID, &vec![0x22; 3064]);
    assert_eq!(over.len(), 3073);
    assert_eq!(card.chained(0xDB, 0x3F, 0xFF, &over).1, 0x6700, "chained");
    // A single extended APDU over the limit as well.
    assert_eq!(card.cmd(0xDB, 0x3F, 0xFF, &over, None).1, 0x6700, "extended");
    // And a single extended APDU at the limit is fine.
    assert_eq!(card.cmd(0xDB, 0x3F, 0xFF, &fits, None).1, 0x9000);
    assert_eq!(card.host.persist_count(), count + 1);
    assert_eq!(card.host.persisted(Record::Piv), persisted, "same bytes stored again");
    assert_eq!(card.object_value(CHUID), Some(vec![0x11; 3063]));
}

#[test]
fn chain_header_change_aborts_chain() {
    // ISO/IEC 7816-4 §5.1.1.1; lk_codec ChainError::HeaderChanged = 6883.
    let mut card = Card::new();
    card.auth_default();
    let payload = Card::put_payload(CHUID, &[0x33; 400]);
    let (resp, sw) = card.raw(&apdu(0x10, 0xDB, 0x3F, 0xFF, &payload[..255], None));
    assert_eq!((resp.len(), sw), (0, 0x9000));
    assert_eq!(card.send("00CB3FFF035C017E00").1, 0x6883);
    // The chain was dropped: the remainder alone is not a valid PUT DATA.
    assert_eq!(card.raw(&apdu(0x00, 0xDB, 0x3F, 0xFF, &payload[255..], None)).1, 0x6A80);
    assert_eq!(card.get_object(CHUID).1, 0x6A82);
}

/// A certificate container value as written by Yubico tools: `70 cert 71 01 00 FE 00`
/// (SP 800-73-4 Part 1 Appendix A).
fn cert_container(cert_len: usize) -> Vec<u8> {
    let mut value = tlv::encode(0x70, &vec![0x30; cert_len]);
    value.extend_from_slice(&hex("710100FE00"));
    value
}

#[test]
fn certificate_limit_is_3052_bytes() {
    // piv_allocation_model.published_certificate_value_limit = 3052; catalog: oversized
    // PIV PUTs answer 6700 and keep the previous object.
    let mut card = Card::new();
    card.auth_default();
    let ok = cert_container(3052);
    assert_eq!(Card::put_payload(PIV_AUTH_CERT, &ok).len(), 3070);
    assert_eq!(card.put_object(PIV_AUTH_CERT, &ok), 0x9000);
    let persisted = card.host.persisted(Record::Piv);
    let too_big = cert_container(3053);
    assert_eq!(Card::put_payload(PIV_AUTH_CERT, &too_big).len(), 3071, "fits the APDU buffer");
    assert_eq!(card.put_object(PIV_AUTH_CERT, &too_big), 0x6700);
    assert_eq!(card.put_object(ATTESTATION_CERT, &too_big), 0x6700);
    assert_eq!(card.put_object(0x5FC10D, &too_big), 0x6700);
    assert_eq!(card.host.persisted(Record::Piv), persisted);
    assert_eq!(card.object_value(PIV_AUTH_CERT), Some(ok));
    // Containers that are not certificate containers take the same bytes.
    assert_eq!(card.put_object(0x5FFF10, &too_big), 0x9000);
}

#[test]
fn storage_budget_is_51200_bytes_with_atomic_replacement() {
    // piv_allocation_model.stored_object_values_limit = 51200, charged with object
    // values; catalog "atomic out-of-space replacement/deletion and restart accounting".
    let mut card = Card::new();
    card.auth_default();
    let big = vec![0x00; 3063];
    let tags: Vec<u32> = (0x5FC10D..=0x5FC11C).collect(); // 16 retired containers
    for &tag in &tags {
        assert_eq!(card.put_object(tag, &big), 0x9000, "{tag:06X}");
    }
    // The own attestation certificate (5FFF01) is charged too (piv_allocation_model
    // "certificate value charged to budget").
    let attestation = card.object_value(0x5FFF01).unwrap().len();
    let used = 16 * 3063 + attestation;
    let left = 51_200 - used;
    assert_eq!(card.put_object(0x5FFF00, &vec![0x01; left]), 0x9000, "exactly full");
    let full_state = card.host.persisted(Record::Piv);
    assert_eq!(card.put_object(0x5FFF02, &[0x01]), 0x6A84);
    // Growing an object by one byte does not fit; replacing it with the same size does.
    assert_eq!(card.put_object(0x5FFF00, &vec![0x02; left + 1]), 0x6A84);
    assert_eq!(card.host.persisted(Record::Piv), full_state, "rejections change nothing");
    assert_eq!(card.object_value(0x5FFF00), Some(vec![0x01; left]));
    assert_eq!(card.put_object(tags[0], &vec![0x07; 3063]), 0x9000, "same-size replacement");
    // Accounting survives a restart.
    card.restart();
    card.auth_default();
    assert_eq!(card.put_object(0x5FFF02, &[0x01]), 0x6A84);
    // Deleting frees the space.
    assert_eq!(card.put_object(tags[1], &[]), 0x9000);
    assert_eq!(card.put_object(0x5FFF02, &vec![0x03; 3063]), 0x9000);
    assert_eq!(card.put_object(0x5FFF03, &[0x01]), 0x6A84);
    card.restart();
    card.auth_default();
    assert_eq!(card.put_object(0x5FFF03, &[0x01]), 0x6A84);
    assert_eq!(card.object_value(0x5FFF02), Some(vec![0x03; 3063]));
    assert_eq!(card.object_value(tags[0]), Some(vec![0x07; 3063]));
}

#[test]
fn put_data_storage_failure_keeps_previous_object() {
    // lk_core::Host::persist: on Err keep the previous state and answer 6581.
    let mut card = Card::new();
    card.auth_default();
    assert_eq!(card.put_object(CHUID, &[1, 1, 1]), 0x9000);
    let persisted = card.host.persisted(Record::Piv);
    card.host.fail_next_saves(1);
    assert_eq!(card.put_object(CHUID, &[2, 2, 2]), 0x6581);
    assert_eq!(card.object_value(CHUID), Some(vec![1, 1, 1]));
    assert_eq!(card.host.persisted(Record::Piv), persisted);
    card.host.fail_next_saves(1);
    assert_eq!(card.put_object(CHUID, &[]), 0x6581, "failed delete");
    assert_eq!(card.object_value(CHUID), Some(vec![1, 1, 1]));
}

#[test]
fn class_byte_validation() {
    // ISO/IEC 7816-4 §5.1.1.
    let mut card = Card::new();
    assert_eq!(card.send("0CCB3FFF035C017E00").1, 0x6882, "secure messaging");
    assert_eq!(card.send("01CB3FFF035C017E00").1, 0x6881, "logical channel");
    assert_eq!(card.send("80CB3FFF035C017E00").1, 0x6E00);
    assert_eq!(card.send("A0CB3FFF035C017E00").1, 0x6E00);
    assert_eq!(card.send("00CA3FFF035C017E00").1, 0x6D00, "unknown INS");
    assert_eq!(card.send("00CB").1, 0x6700, "malformed APDU");
}
