//! Cross-application reset scenario: each application's reset leaves the others alone.
//!
//! `reference/BEHAVIOR_CATALOG.md` has four bullets that only a whole device can check:
//! - PIV: "PIV reset preserves independent OATH key and durable HOTP counter";
//! - OpenPGP: "PIV issuer and OATH private key/durable HOTP state survive OpenPGP reset";
//! - Security Domain: "Domain reset retains independent PIV issuer and OATH secret/HOTP
//!   progression";
//! - OATH: "locked app reset rotates OATH salt while retaining PIV own F9 issuer".
//!
//! Each application crate shows that its reset writes only its own record; this test
//! drives the four resets through `Device` over CCID, as a host would, and checks after
//! each one (and after a restart) that the OATH HOTP credential continues with the next
//! RFC 4226 Appendix D value and that the PIV `F9` attestation certificate (`5FFF01`,
//! Yubico PIV attestation) is byte for byte the same.

#![allow(clippy::unwrap_used)]

mod common;

use common::iso::{command, find_tlv, oath, piv, split, tlv};
use common::*;
use lk_crypto::hmac_sha1;

/// RFC 4226 Appendix D: the secret `"12345678901234567890"` and the 6-digit HOTP values
/// for counts 0 to 9.
const RFC4226_SECRET: &[u8; 20] = b"12345678901234567890";
const RFC4226_CODES: [&str; 10] = [
    "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489",
];
/// YKOATH type and algorithm byte: HOTP `10` | SHA-1 `01`.
const HOTP_SHA1: u8 = 0x11;
const NAME: &[u8] = b"cross-app";

/// GET DATA (SP 800-73-4 Part 2 §3.1.2) of the Yubico attestation certificate object
/// `5FFF01`, which certifies the PIV `F9` attestation key.
const PIV_F9_CERTIFICATE: [u8; 11] = [0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xFF, 0x01, 0x00];
/// GET DATA CPLC (GP 2.3.1 §11.3, tag `9F7F`) and key information (Amendment D/F, `E0`).
const SD_CPLC: [u8; 5] = [0x80, 0xCA, 0x9F, 0x7F, 0x00];
const SD_KEY_INFO: [u8; 5] = [0x80, 0xCA, 0x00, 0xE0, 0x00];
/// The factory key information (`reference/yubikey-5c-nano-5.7.4/` Security Domain
/// observation): SCP03 `01`/`02`/`03` at KVN `FF` and SCP11b `13` at KVN `01`.
const SD_FACTORY_KEYS: &str = "C00401FF8810 C00402FF8810 C00403FF8810 C0061301B120F000";

/// The next HOTP code of the test credential (YKOATH CALCULATE, truncated, with the
/// empty challenge `74 00` that yubikit sends for HOTP).
fn hotp(rig: &mut Rig) -> String {
    rig.select(AID_OATH);
    oath::code(&rig.send(&oath::calculate(NAME, &[], true)))
}

/// The PIV `F9` attestation certificate object.
fn piv_f9_certificate(rig: &mut Rig) -> Vec<u8> {
    rig.select(AID_PIV_FULL);
    let response = rig.send(&PIV_F9_CERTIFICATE);
    let (data, status) = split(&response);
    assert_eq!(status, 0x9000, "GET DATA 5FFF01");
    assert_eq!(data[0], 0x53, "a PIV data object");
    data.to_vec()
}

fn get_data(rig: &mut Rig, apdu: &[u8]) -> Vec<u8> {
    let response = rig.send(apdu);
    let (data, status) = split(&response);
    assert_eq!(status, 0x9000, "{apdu:02X?}");
    data.to_vec()
}

/// PIV RESET (Yubico PIV extension `FB`): only allowed once PIN and PUK are both blocked.
fn piv_reset(rig: &mut Rig) {
    rig.select(AID_PIV_FULL);
    // Part 2 §3.2.1: a failed comparison answers `63CX` with the tries left, so the
    // third is `63C0`; once blocked the answer is `6983`.
    for expected in [0x63C2, 0x63C1, 0x63C0, 0x6983] {
        assert_eq!(rig.piv_verify("000000"), expected, "block the PIN");
    }
    // RESET RETRY COUNTER (Part 2 §3.2.3) with a wrong PUK.
    let data = [piv::pin_block("00000000"), piv::pin_block("654321")].concat();
    for expected in [0x63C2, 0x63C1, 0x63C0, 0x6983] {
        assert_eq!(sw(&rig.apdu(&command(0x00, 0x2C, 0x00, piv::PIN, &data, None))), expected, "block the PUK");
    }
    assert_eq!(sw(&rig.apdu(&[0x00, 0xFB, 0x00, 0x00])), 0x9000, "PIV RESET");
    assert_eq!(rig.piv_verify("123456"), 0x9000, "the factory PIN is back");
}

/// OpenPGP reset (card spec 3.4.1 §7.2.16-§7.2.17): TERMINATE DF after PW3, then
/// ACTIVATE FILE. A cardholder name written before must be gone afterwards.
fn openpgp_reset(rig: &mut Rig) {
    rig.select(AID_OPENPGP);
    assert_eq!(rig.pgp_verify(0x83, b"12345678"), 0x9000, "PW3");
    assert_eq!(rig.pgp_put(0x5B, b"Cross<<App"), 0x9000, "PUT DATA name");
    assert_eq!(get_data(rig, &[0x00, 0xCA, 0x00, 0x5B, 0x00]), b"Cross<<App");
    assert_eq!(sw(&rig.apdu(&[0x00, 0xE6, 0x00, 0x00])), 0x9000, "TERMINATE DF");
    assert_eq!(sw(&rig.apdu(&[0x00, 0x44, 0x00, 0x00])), 0x9000, "ACTIVATE FILE");
    rig.select(AID_OPENPGP);
    assert!(get_data(rig, &[0x00, 0xCA, 0x00, 0x5B, 0x00]).is_empty(), "name cleared by the reset");
}

/// The Security Domain's blocking reset as yubikit `SecurityDomainSession.reset` does
/// it: for every key in the key information, send the authentication command with
/// eight zero bytes until it answers `6983`/`6982`, continuing on `9000`/`6A80`
/// (`docs/catalog/sd.md` "Tries"). SCP03 uses INITIALIZE UPDATE (`50`), SCP11b
/// INTERNAL AUTHENTICATE (`88`); `02`/`03` are the other keys of the SCP03 set. The
/// domain then starts from a fresh factory state, with a new CPLC.
fn security_domain_reset(rig: &mut Rig) {
    rig.select(AID_SD);
    let old_cplc = get_data(rig, &SD_CPLC);
    let info = sd_key_entries(rig);
    let mut refs = Vec::new();
    let mut rest = &info[..];
    while !rest.is_empty() {
        assert_eq!(rest[0], 0xC0, "key information template");
        let len = 2 + usize::from(rest[1]);
        refs.push((rest[2], rest[3]));
        rest = &rest[len..];
    }
    assert!(!refs.is_empty());
    for (kid, kvn) in refs {
        let (ins, p1, p2) = match kid {
            0x01 => (0x50, 0x00, 0x00),
            0x02 | 0x03 => continue,
            0x13 => (0x88, kvn, kid),
            other => panic!("unexpected key {other:02X}"),
        };
        let mut blocked = false;
        for _ in 0..65 {
            match sw(&rig.apdu(&apdu(0x80, ins, p1, p2, &[0; 8], None))) {
                0x6983 | 0x6982 => {
                    blocked = true;
                    break;
                }
                0x9000 | 0x6A80 => continue,
                other => panic!("unexpected {other:04X} for key {kid:02X}/{kvn:02X}"),
            }
        }
        assert!(blocked || kid == 0x01, "key {kid:02X}/{kvn:02X} not blocked");
    }
    rig.select(AID_SD);
    assert_eq!(sd_key_entries(rig), hex(SD_FACTORY_KEYS), "factory keys again");
    assert_ne!(get_data(rig, &SD_CPLC), old_cplc, "a fresh identity rotates the CPLC");
}

/// The `C0` key information templates, without the `E0` wrapper.
fn sd_key_entries(rig: &mut Rig) -> Vec<u8> {
    let info = get_data(rig, &SD_KEY_INFO);
    find_tlv(&info, 0xE0).unwrap_or(info)
}

/// The SELECT response of OATH: `71` salt and, while an access key is set, `74`
/// challenge (YKOATH SELECT).
fn oath_select(rig: &mut Rig) -> (Vec<u8>, Option<Vec<u8>>) {
    let response = rig.select(AID_OATH);
    let (data, status) = split(&response);
    assert_eq!(status, 0x9000);
    (find_tlv(data, 0x71).unwrap(), find_tlv(data, 0x74))
}

/// Lock OATH with an access key (YKOATH SET CODE `03`: `73 { type|alg, key }`,
/// `74 challenge`, `75 HMAC-SHA1(key, challenge)`), then RESET (`04`, P1P2 `DE AD`)
/// without VALIDATE.
fn locked_oath_reset(rig: &mut Rig) -> (Vec<u8>, Vec<u8>) {
    let key = [0x11u8; 16];
    let challenge = [0x22u8; 8];
    let (salt_before, locked) = oath_select(rig);
    assert_eq!(locked, None, "no access key yet");
    let mut key_field = vec![0x21];
    key_field.extend_from_slice(&key);
    let data = [tlv(0x73, &key_field), tlv(0x74, &challenge), tlv(0x75, &hmac_sha1(&key, &challenge))].concat();
    assert_eq!(sw(&rig.apdu(&command(0x00, 0x03, 0x00, 0x00, &data, None))), 0x9000, "SET CODE");
    let (salt_locked, locked) = oath_select(rig);
    assert_eq!(salt_locked, salt_before);
    assert!(locked.is_some(), "locked: SELECT carries a challenge");
    assert_eq!(sw(&rig.send(&oath::calculate(NAME, &[], true))), 0x6982, "locked");
    assert_eq!(sw(&rig.apdu(&[0x00, 0x04, 0xDE, 0xAD])), 0x9000, "RESET without VALIDATE");
    let (salt_after, locked) = oath_select(rig);
    assert_eq!(locked, None, "the reset removed the access key");
    (salt_before, salt_after)
}

#[test]
fn each_application_reset_keeps_the_other_applications() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_OATH);
    assert_eq!(rig.apdu(&oath::put(NAME, HOTP_SHA1, 6, RFC4226_SECRET, false)), vec![0x90, 0x00]);
    let mut count = 0;
    let mut next = |rig: &mut Rig| {
        let code = hotp(rig);
        assert_eq!(code, RFC4226_CODES[count], "HOTP count {count}");
        count += 1;
    };
    next(&mut rig);
    let f9 = piv_f9_certificate(&mut rig);

    piv_reset(&mut rig);
    next(&mut rig);
    assert_eq!(piv_f9_certificate(&mut rig), f9, "PIV RESET keeps the F9 attestation certificate");

    openpgp_reset(&mut rig);
    next(&mut rig);
    assert_eq!(piv_f9_certificate(&mut rig), f9, "OpenPGP reset leaves PIV alone");

    security_domain_reset(&mut rig);
    next(&mut rig);
    assert_eq!(piv_f9_certificate(&mut rig), f9, "Security Domain reset leaves PIV alone");

    // Everything above was persisted: a restart sees the same counter and certificate.
    rig.restart();
    rig.power_on();
    next(&mut rig);
    assert_eq!(piv_f9_certificate(&mut rig), f9, "after restart");

    let (salt_before, salt_after) = locked_oath_reset(&mut rig);
    assert_ne!(salt_after, salt_before, "a locked OATH reset rotates the salt");
    assert_eq!(sw(&rig.send(&oath::calculate(NAME, &[], true))), 0x6984, "the credential is gone");
    assert_eq!(piv_f9_certificate(&mut rig), f9, "OATH reset keeps the PIV F9 issuer");

    rig.restart();
    rig.power_on();
    assert_eq!(piv_f9_certificate(&mut rig), f9, "after the OATH reset and a restart");
    assert_eq!(oath_select(&mut rig).0, salt_after, "the rotated salt was persisted");
}
