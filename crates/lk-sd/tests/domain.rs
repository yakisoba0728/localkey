//! Security Domain data objects, key management, authentication tries, reset and
//! persistence.

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use lk_core::{CardApplet, DeviceProfile, Record};
use lk_sd::{AID, SecurityDomain};
use lk_testkit::TestHost;

/// `reference/yubikey-5c-nano-5.7.4/security-domain-reference-observation.json`,
/// `select_public_template` (25 bytes).
const REF_SELECT: &str = "6f178408a000000151000000a50b730906072a864886fc6b01";
/// Same file, `card_recognition_data` (63 bytes, the response to `00CA006600`).
const REF_RECOGNITION: &str = "733d06072a864886fc6b01600c060a2a864886fc6b02020301630906072a864886fc6b03640b06092a864886fc6b040360640c060a2a864886fc6b04119b06";

fn fresh() -> (SecurityDomain, TestHost) {
    let mut host = TestHost::new();
    let sd = SecurityDomain::new(None, &mut host);
    (sd, host)
}

fn get_data(sd: &mut SecurityDomain, host: &mut TestHost, p1: u8, p2: u8) -> Vec<u8> {
    let resp = plain(sd, host, &[0x00, 0xCA, p1, p2, 0x00]);
    assert_eq!(status(&resp), 0x9000);
    resp[..resp.len() - 2].to_vec()
}

fn key_info(sd: &mut SecurityDomain, host: &mut TestHost) -> Vec<u8> {
    get_data(sd, host, 0x00, 0xE0)
}

fn cplc(sd: &mut SecurityDomain, host: &mut TestHost) -> Vec<u8> {
    get_data(sd, host, 0x9F, 0x7F)
}

fn restart(host: &mut TestHost) -> SecurityDomain {
    let stored = host.persisted(Record::SecurityDomain);
    SecurityDomain::new(stored.as_deref(), host)
}

/// The reference SELECT command `00a4040008a00000015100000000` returns the observed
/// 25-byte template in both profiles.
#[test]
fn select_response_matches_reference() {
    for profile in [DeviceProfile::own(1), DeviceProfile::yubikey_5c_nano_5_7_4(1)] {
        let mut host = TestHost::with_profile(profile);
        let mut sd = SecurityDomain::new(None, &mut host);
        assert_eq!(sd.aid(), AID);
        let resp = sd.select(&hex("00a4040008a00000015100000000"), &mut host);
        assert_eq!(resp, [hex(REF_SELECT), hex("9000")].concat());
        assert_eq!(resp.len() - 2, 25);
        assert_eq!(sd.select(&hex("00a4040c08a000000151000000"), &mut host), hex("9000"));
    }
}

/// GET DATA `0066` returns the observed 63 bytes.
#[test]
fn card_recognition_data_matches_reference() {
    let (mut sd, mut host) = fresh();
    assert_eq!(get_data(&mut sd, &mut host, 0x00, 0x66), hex(REF_RECOGNITION));
    assert_eq!(status(&plain(&mut sd, &mut host, &hex("80CA006600"))), 0x9000);
}

/// GET DATA `00E0` matches the observed schema (26 bytes; three `C0 04` entries with
/// type `88` length 16 and one `C0 06` entry with `B1` length 32 and `F0 00`). The key
/// references are Yubico's defaults (SCP03 KID 1-3 at KVN `FF`, SCP11b KID `13` KVN
/// `01`); the observation did not retain them.
#[test]
fn key_information_matches_reference_schema() {
    let (mut sd, mut host) = fresh();
    let info = key_info(&mut sd, &mut host);
    assert_eq!(info.len(), 26);
    assert_eq!(info, hex("C00401FF8810 C00402FF8810 C00403FF8810 C0061301B120F000"));
    // Schema check exactly as the observation records it.
    let entries: Vec<&[u8]> = vec![&info[0..6], &info[6..12], &info[12..18], &info[18..26]];
    for e in &entries[..3] {
        assert_eq!((e[0], e[1], e[4], e[5]), (0xC0, 4, 0x88, 16));
    }
    assert_eq!((entries[3][0], entries[3][1]), (0xC0, 6));
    assert_eq!(&entries[3][4..], &[0xB1, 32, 0xF0, 0]);
}

/// CPLC: 42 bytes (observation `cplc_schema.response_length`), software platform
/// marker `0000` (catalog SecurityDomain_metadata), random identifier, stable across
/// SELECT, SCP03 reads, ordinary deletion and restart.
#[test]
fn cplc_layout_and_stability() {
    let (mut sd, mut host) = fresh();
    let first = cplc(&mut sd, &mut host);
    assert_eq!(first.len(), 42);
    assert_eq!(&first[..2], &[0, 0]);
    assert!(first[12..18].iter().any(|&b| b != 0));
    sd.select(&hex("00a4040008a000000151000000"), &mut host);
    assert_eq!(cplc(&mut sd, &mut host), first);
    let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    let (data, sw) = send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xCA, 0x9F, 0x7F, &[]);
    assert_eq!((data, sw), (first.clone(), 0x9000));
    // Ordinary deletion of the SCP11b key keeps the CPLC.
    let (data, sw) = send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xE4, 0x00, 0x00, &hex("D001 13D20101"));
    assert_eq!((data, sw), (vec![], 0x9000));
    assert_eq!(cplc(&mut sd, &mut host), first);
    let mut sd = restart(&mut host);
    assert_eq!(cplc(&mut sd, &mut host), first);
    // Another device has another identifier.
    let mut other_host = TestHost::new().seeded(99);
    let mut other = SecurityDomain::new(None, &mut other_host);
    assert_ne!(cplc(&mut other, &mut other_host), first);
}

/// Unknown GET DATA tags: `6A88`. The certificate store needs a key reference
/// (`6A80` without one); CA identifiers answer `6A88` while none is stored.
#[test]
fn unknown_get_data_tag() {
    let (mut sd, mut host) = fresh();
    for p in [[0x00, 0x01], [0x00, 0x42], [0x9F, 0x7E], [0xFF, 0x33], [0xFF, 0x34]] {
        assert_eq!(plain(&mut sd, &mut host, &[0x00, 0xCA, p[0], p[1], 0x00]), hex("6A88"));
    }
    assert_eq!(plain(&mut sd, &mut host, &hex("00CABF2100")), hex("6A80"));
    assert_eq!(plain(&mut sd, &mut host, &hex("00CABF2106A6048302130200")), hex("6A88"));
    // An unknown instruction outside a secure channel is 6982 (docs/MEASUREMENT.md,
    // probe `undefined-ins-sd`; 6D00 before the measurement).
    assert_eq!(plain(&mut sd, &mut host, &hex("00EE000000")), hex("6982"));
    assert_eq!(plain(&mut sd, &mut host, &hex("A0CA006600")), hex("6E00"));
    assert_eq!(plain(&mut sd, &mut host, &hex("01CA006600")), hex("6881"));
}

/// Plaintext response chaining (ISO/IEC 7816-4 §5.1.3, §7.6.1): a short Le leaves the
/// rest for GET RESPONSE (`61xx`), which must immediately follow; any other command
/// discards it. lk-device sends handshakes straight to `SecurityDomain::handshake`, so
/// an INITIALIZE UPDATE or PSO in between must discard it too (regression: the queued
/// card recognition data used to be served after a handshake).
#[test]
fn get_response_is_discarded_by_an_intervening_command() {
    let reference = hex(REF_RECOGNITION);
    let (mut sd, mut host) = fresh();
    let first = plain(&mut sd, &mut host, &hex("00CA006610"));
    assert_eq!(first, [&reference[..16], &[0x61, 0x2F]].concat());
    let rest = plain(&mut sd, &mut host, &hex("00C0000000"));
    assert_eq!(rest, [&reference[16..], &[0x90, 0x00]].concat());
    // Nothing left: 6982 (docs/MEASUREMENT.md, probe `get-response-idle-sd`; 6985
    // before the measurement).
    assert_eq!(plain(&mut sd, &mut host, &hex("00C0000000")), hex("6982"), "nothing left");

    let interveners: [Vec<u8>; 3] = [
        init_update_apdu(0xFF, &[7; 8]),
        encode_apdu(0x80, 0x2A, 0x00, 0x10, &[0; 8], None, false),
        encode_apdu(0x00, 0xCA, 0x00, 0xE0, &[], Some(0), false),
    ];
    for (i, intervening) in interveners.iter().enumerate() {
        assert_eq!(status(&plain(&mut sd, &mut host, &hex("00CA006610"))), 0x612F);
        if i < 2 {
            sd.handshake(intervening, &mut host);
        } else {
            plain(&mut sd, &mut host, intervening);
        }
        assert_eq!(plain(&mut sd, &mut host, &hex("00C0000000")), hex("6982"), "{intervening:02X?}");
    }
}

/// docs/MEASUREMENT.md, probes `undefined-ins-sd`, `get-response-idle-sd` and
/// `cla-variants-sd`: with the Security Domain selected and no secure channel, the key
/// answers INS `5E`, `6E` and `93` with `6982`, GET RESPONSE with nothing pending with
/// `6982`, and GET RESPONSE right after `10 CA 00 66` (a chained part, `9000`) with
/// `6982` as well. Before the measurement the engine answered `6D00`, `6985` and `6883`.
#[test]
fn unserved_plaintext_commands_are_6982() {
    let (mut sd, mut host) = fresh();
    assert_eq!(sd.select(&hex("00a4040008a000000151000000"), &mut host), [hex(REF_SELECT), hex("9000")].concat());
    for ins in [0x5E, 0x6E, 0x93] {
        assert_eq!(plain(&mut sd, &mut host, &[0x00, ins, 0x00, 0x00]), hex("6982"), "INS {ins:02X}");
    }
    assert_eq!(plain(&mut sd, &mut host, &hex("00C0000000")), hex("6982"));
    assert_eq!(plain(&mut sd, &mut host, &hex("10CA0066")), hex("9000"));
    assert_eq!(plain(&mut sd, &mut host, &hex("00C0000000")), hex("6982"));
    // The chain was dropped: GET DATA works on its own again.
    assert_eq!(get_data(&mut sd, &mut host, 0x00, 0x66), hex(REF_RECOGNITION));
    // A handshake-class command for the selected domain is still served (INITIALIZE
    // UPDATE goes to the handshake, not to the fallback).
    assert_eq!(status(&plain(&mut sd, &mut host, &init_update_apdu(0xFF, &[7; 8]))), 0x9000);
}

/// docs/MEASUREMENT.md, probe `cla-variants-sd`: `80 CA 00 66` answers the card
/// recognition data inside its `66` template (GP 2.3.1 Annex H.2), 65 bytes `66 3F 73 3D
/// ...`; `00 CA 00 66` answers the bare 63-byte `73` template. Before the measurement
/// both classes got the bare template.
#[test]
fn proprietary_class_card_data_has_the_66_template() {
    let (mut sd, mut host) = fresh();
    let resp = plain(&mut sd, &mut host, &hex("80CA0066"));
    assert_eq!(resp, [hex("663F"), hex(REF_RECOGNITION), hex("9000")].concat());
    assert_eq!(resp.len(), 65 + 2);
    assert_eq!(plain(&mut sd, &mut host, &hex("00CA0066")), [hex(REF_RECOGNITION), hex("9000")].concat());
    // Ne applies to the wrapped form too.
    let first = plain(&mut sd, &mut host, &hex("80CA006610"));
    assert_eq!(status(&first), 0x6131);
    // Other objects are unmeasured with CLA 80 and keep their plain form.
    assert_eq!(plain(&mut sd, &mut host, &hex("80CA00E000")), plain(&mut sd, &mut host, &hex("00CA00E000")));
}

/// PUT KEY of a whole set: KCVs returned (GP 2.3.1 §11.8.2.3), the factory set is
/// replaced (Yubico: "When a new key set is installed, it replaces the default key
/// set"), the new keys authenticate.
#[test]
fn put_key_installs_a_set_and_replaces_the_default() {
    let (mut sd, mut host) = fresh();
    let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    let new = StaticKeys::from_seed(1);
    let data = s.put_key_data(0x01, &new);
    let (resp, sw) = send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x00, 0x81, &data);
    assert_eq!((resp, sw), (put_key_response(0x01, &new), 0x9000));
    assert_eq!(key_info(&mut sd, &mut host), hex("C004010188 10C004020188 10C004030188 10C0061301B120F000"));
    // The old session goes on with its own keys.
    let (_, sw) = send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xCA, 0x00, 0xE0, &[]);
    assert_eq!(sw, 0x9000);
    // FF is gone, 01 works, and both survive a restart.
    assert_eq!(status(&sd.handshake(&init_update_apdu(0xFF, &[0; 8]), &mut host).0), 0x6A88);
    let mut sd = restart(&mut host);
    open(&mut sd, &mut host, &new, 0x01, 0x33);
    open(&mut sd, &mut host, &new, 0x00, 0x33);
}

/// Some hosts prefix the encrypted key with its length (`88 11 10 <16>`); both forms
/// are accepted, and a missing KCV is computed by the card.
#[test]
fn put_key_accepts_length_prefixed_key_data_and_absent_kcv() {
    let (mut sd, mut host) = fresh();
    let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    let new = StaticKeys::from_seed(2);
    let mut data = vec![0x02];
    for k in [new.enc, new.mac, new.dek] {
        data.extend_from_slice(&[0x88, 0x11, 0x10]);
        data.extend_from_slice(&lk_crypto::aes_cbc_encrypt(&DEFAULT_KEY, &[0; 16], &k).unwrap());
        data.push(0);
    }
    let (resp, sw) = send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x00, 0x81, &data);
    assert_eq!((resp, sw), (put_key_response(0x02, &new), 0x9000));
    open(&mut sd, &mut host, &new, 0x02, 0x33);
}

/// PUT KEY refusals (GP 2.3.1 §11.8; Yubico: versions 1-254, three sets, whole sets).
/// None of them changes the state.
#[test]
fn put_key_refusals() {
    let (mut sd, mut host) = fresh();
    let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    let k = StaticKeys::from_seed(4);
    let mut cases: Vec<(u8, u8, Vec<u8>, u16)> = vec![
        (0x00, 0x81, s.put_key_data(0x00, &k), 0x6A80),
        (0x00, 0x81, s.put_key_data(0xFF, &k), 0x6A80),
        (0x00, 0x01, s.put_key_data(0x05, &k), 0x6A86),
        (0x00, 0x82, s.put_key_data(0x05, &k), 0x6A86),
        (0x00, 0x83, s.put_key_data(0x05, &k), 0x6A86),
        (0x00, 0x91, s.put_key_data(0x05, &k), 0x6A86),
        // An SCP11 KID with SCP03 key data: the EC key objects are missing.
        (0x00, 0x13, s.put_key_data(0x05, &k), 0x6A80),
        (0x07, 0x81, s.put_key_data(0x05, &k), 0x6A88),
        (0x00, 0x81, vec![], 0x6A80),
        (0x00, 0x81, s.put_key_data(0x05, &k)[..40].to_vec(), 0x6A80),
        (0x00, 0x81, [s.put_key_data(0x05, &k), vec![0x00]].concat(), 0x6A80),
    ];
    // Wrong KCV on the MAC key.
    let mut bad = s.put_key_data(0x05, &k);
    bad[1 + 22 + 19] ^= 0x01;
    cases.push((0x00, 0x81, bad, 0x6A80));
    // Wrong key type.
    let mut bad = s.put_key_data(0x05, &k);
    bad[1] = 0x80;
    cases.push((0x00, 0x81, bad, 0x6A80));
    // Wrong KCV length.
    let mut bad = s.put_key_data(0x05, &k);
    bad[1 + 18] = 0x02;
    cases.push((0x00, 0x81, bad, 0x6A80));
    let before = host.persisted(Record::SecurityDomain);
    for (p1, p2, data, expected) in cases {
        let (_, sw) = send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, p1, p2, &data);
        assert_eq!(sw, expected, "P1 {p1:02X} P2 {p2:02X} {data:02X?}");
    }
    assert_eq!(host.persisted(Record::SecurityDomain), before);
    assert_eq!(key_info(&mut sd, &mut host), hex("C00401FF8810 C00402FF8810 C00403FF8810 C0061301B120F000"));
}

/// Three sets at most (`6A84`); replacement, collision and deletion rules across low
/// and high versions (catalog SecurityDomain_versions).
#[test]
fn three_set_capacity_replacement_and_collision() {
    let (mut sd, mut host) = fresh();
    let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    for kvn in [0x01, 0x80, 0xFE] {
        let data = s.put_key_data(kvn, &StaticKeys::from_seed(kvn));
        let (_, sw) = send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x00, 0x81, &data);
        assert_eq!(sw, 0x9000);
    }
    let data = s.put_key_data(0x7F, &StaticKeys::from_seed(0x7F));
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x00, 0x81, &data).1, 0x6A84);
    // Collision with another set.
    let data = s.put_key_data(0x80, &StaticKeys::from_seed(0x11));
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x01, 0x81, &data).1, 0x6A80);
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x00, 0x81, &data).1, 0x6A80);
    // Replace 0x80 by 0x7F, and 0x01 in place.
    let data = s.put_key_data(0x7F, &StaticKeys::from_seed(0x7F));
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x80, 0x81, &data).1, 0x9000);
    let data = s.put_key_data(0x01, &StaticKeys::from_seed(0x21));
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x01, 0x81, &data).1, 0x9000);
    let info = key_info(&mut sd, &mut host);
    let kvns: Vec<u8> = info.chunks(6).take(9).map(|e| e[3]).collect();
    assert_eq!(kvns, vec![0x01, 0x01, 0x01, 0x7F, 0x7F, 0x7F, 0xFE, 0xFE, 0xFE]);
    let mut sd = restart(&mut host);
    open(&mut sd, &mut host, &StaticKeys::from_seed(0x21), 0x01, 0x33);
    open(&mut sd, &mut host, &StaticKeys::from_seed(0x7F), 0x7F, 0x33);
    open(&mut sd, &mut host, &StaticKeys::from_seed(0xFE), 0xFE, 0x33);
    // Wildcard picks the highest version.
    let (_, ch) = open(&mut sd, &mut host, &StaticKeys::from_seed(0xFE), 0x00, 0x33);
    assert_eq!(ch.key_version(), 0xFE);
}

/// Catalog SecurityDomain_versions: every custom version 1..=254 can be imported and
/// authenticates; the INITIALIZE UPDATE header carries `KVN 03 60` and the card
/// cryptogram is recomputed independently each time.
#[test]
fn every_custom_version_imports_and_authenticates() {
    let (mut sd, mut host) = fresh();
    let id = cplc(&mut sd, &mut host);
    let mut keys = StaticKeys::DEFAULT;
    let mut current = 0xFF;
    for kvn in 1..=254u8 {
        let (mut s, mut ch) = open(&mut sd, &mut host, &keys, current, 0x33);
        let new = StaticKeys::from_seed(kvn);
        let data = s.put_key_data(kvn, &new);
        let (resp, sw) = send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, current, 0x81, &data);
        assert_eq!((resp, sw), (put_key_response(kvn, &new), 0x9000), "version {kvn}");
        keys = new;
        current = kvn;
        if matches!(kvn, 127 | 128 | 254) {
            let info = key_info(&mut sd, &mut host);
            sd = restart(&mut host);
            assert_eq!(key_info(&mut sd, &mut host), info);
            assert_eq!(cplc(&mut sd, &mut host), id);
            assert_eq!(sd.remaining_tries(0x13, 0x01), Some(64));
        }
    }
    open(&mut sd, &mut host, &keys, 254, 0x33);
}

/// DELETE KEY by version; no match is `6A88`; malformed data `6A80`; parameters `6A86`.
#[test]
fn delete_key_rules() {
    let (mut sd, mut host) = fresh();
    let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    for kvn in [0x10, 0x20] {
        let data = s.put_key_data(kvn, &StaticKeys::from_seed(kvn));
        assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x00, 0x81, &data).1, 0x9000);
    }
    let cases: [(u8, u8, &str, u16); 9] = [
        (0x00, 0x00, "D20130", 0x6A88),
        (0x00, 0x00, "D00104", 0x6A88),
        (0x00, 0x00, "", 0x6A80),
        (0x00, 0x00, "D2021020", 0x6A80),
        (0x00, 0x00, "D201 10D20120", 0x6A80),
        (0x00, 0x00, "C10110", 0x6A80),
        (0x00, 0x00, "D201", 0x6A80),
        (0x01, 0x00, "D20110", 0x6A86),
        (0x00, 0x80, "D20110", 0x6A86),
    ];
    for (p1, p2, data, expected) in cases {
        let (_, sw) = send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xE4, p1, p2, &hex(data));
        assert_eq!(sw, expected, "{data}");
    }
    // Delete set 0x10 by KVN (and KID 1, as GP allows).
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xE4, 0x00, 0x00, &hex("D00101 D20110")).1, 0x9000);
    assert_eq!(status(&sd.handshake(&init_update_apdu(0x10, &[0; 8]), &mut host).0), 0x6A88);
    let info = key_info(&mut sd, &mut host);
    assert_eq!(info.len(), 18 + 8);
    // The session that used the factory keys is unaffected by deleting another set.
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xCA, 0x00, 0xE0, &[]).1, 0x9000);
}

/// Deleting the last management key needs P2 `01` (Yubico: "To delete the last key set
/// on purpose and force a reset, send the delete instruction with p2=1") and restores
/// a fresh default domain: factory keys, new SCP11b key, rotated CPLC.
#[test]
fn deleting_the_last_key_set_needs_p2_1_and_resets() {
    let (mut sd, mut host) = fresh();
    let old_cplc = cplc(&mut sd, &mut host);
    let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    let new = StaticKeys::from_seed(5);
    let data = s.put_key_data(0x05, &new);
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x00, 0x81, &data).1, 0x9000);
    let before = host.persisted(Record::SecurityDomain);
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xE4, 0x00, 0x00, &hex("D20105")).1, 0x6985);
    assert_eq!(host.persisted(Record::SecurityDomain), before);
    // Deleting the SCP11b key alone is an ordinary deletion.
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xE4, 0x00, 0x00, &hex("D00113")).1, 0x9000);
    assert_eq!(key_info(&mut sd, &mut host).len(), 18);
    // Now the last set, explicitly.
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xE4, 0x00, 0x01, &hex("D20105")).1, 0x9000);
    assert!(!ch.is_open());
    assert_eq!(key_info(&mut sd, &mut host), hex("C00401FF8810 C00402FF8810 C00403FF8810 C0061301B120F000"));
    assert_ne!(cplc(&mut sd, &mut host), old_cplc);
    open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    let mut sd = restart(&mut host);
    open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
}

/// Each INITIALIZE UPDATE uses a try, persisted before the response; a successful
/// EXTERNAL AUTHENTICATE restores all 64 (`reference/legacy-v0.64-profiles.json`
/// `software_authentication_tries`); the last try can succeed (catalog
/// SecurityDomain_profile).
#[test]
fn tries_are_used_by_init_update_and_restored_by_authentication() {
    let (mut sd, mut host) = fresh();
    for left in (1..64u8).rev() {
        let (resp, _) = sd.handshake(&init_update_apdu(0xFF, &[1; 8]), &mut host);
        assert_eq!(status(&resp), 0x9000);
        assert_eq!(sd.remaining_tries(1, 0xFF), Some(left));
        // Persisted before the response.
        assert_eq!(restart(&mut host.clone()).remaining_tries(1, 0xFF), Some(left));
    }
    // The 64th attempt takes the last try and still succeeds.
    open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    assert_eq!(sd.remaining_tries(1, 0xFF), Some(64));
}

/// Yubico: "When authentication with a key set fails repeatedly ... that key set is
/// deleted". The exhausted set is removed on its next selection (`6983`); the wildcard
/// then uses the next highest set; an explicit version never falls back (catalog
/// SecurityDomain_versions).
#[test]
fn exhausted_set_is_deleted_and_wildcard_moves_on() {
    let (mut sd, mut host) = fresh();
    let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    for kvn in [0x02, 0x09] {
        let data = s.put_key_data(kvn, &StaticKeys::from_seed(kvn));
        assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x00, 0x81, &data).1, 0x9000);
    }
    for _ in 0..64 {
        assert_eq!(status(&sd.handshake(&init_update_apdu(0x00, &[1; 8]), &mut host).0), 0x9000);
    }
    assert_eq!(sd.remaining_tries(1, 0x09), Some(0));
    assert_eq!(sd.remaining_tries(1, 0x02), Some(64));
    assert_eq!(status(&sd.handshake(&init_update_apdu(0x00, &[1; 8]), &mut host).0), 0x6983);
    assert_eq!(sd.remaining_tries(1, 0x09), None);
    assert_eq!(status(&sd.handshake(&init_update_apdu(0x09, &[1; 8]), &mut host).0), 0x6A88);
    let (_, ch) = open(&mut sd, &mut host, &StaticKeys::from_seed(0x02), 0x00, 0x33);
    assert_eq!(ch.key_version(), 0x02);

    // An explicitly addressed exhausted set: removed with 6983, no fallback.
    for _ in 0..64 {
        sd.handshake(&init_update_apdu(0x02, &[1; 8]), &mut host);
    }
    assert_eq!(status(&sd.handshake(&init_update_apdu(0x02, &[1; 8]), &mut host).0), 0x6983);
    assert_eq!(sd.remaining_tries(1, 0x02), None);
    assert_eq!(status(&sd.handshake(&init_update_apdu(0x02, &[1; 8]), &mut host).0), 0x6A88);
}

/// A failed EXTERNAL AUTHENTICATE on the last try deletes the set at once.
#[test]
fn failed_last_try_deletes_the_set() {
    let (mut sd, mut host) = fresh();
    let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    let data = s.put_key_data(0x03, &StaticKeys::from_seed(3));
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x00, 0x81, &data).1, 0x9000);
    for _ in 0..63 {
        sd.handshake(&init_update_apdu(0x03, &[1; 8]), &mut host);
    }
    let (resp, _) = sd.handshake(&init_update_apdu(0x03, &[1; 8]), &mut host);
    assert_eq!(sd.remaining_tries(1, 0x03), Some(0));
    let pending = read_init_response(&StaticKeys::from_seed(3), &[1; 8], &resp);
    let mut bad = pending.host_cryptogram();
    bad[7] ^= 0x40;
    let (apdu, _) = pending.external_authenticate_with(0x33, &bad);
    assert_eq!(sd.handshake(&apdu, &mut host).0, hex("6300"));
    assert_eq!(sd.remaining_tries(1, 0x03), None);
    // The SCP11b key remains, so no reset happened.
    assert_eq!(key_info(&mut sd, &mut host), hex("C0061301B120F000"));
}

/// yubikit's `SecurityDomainSession.reset()` blocks every key: INITIALIZE UPDATE with
/// KVN 0 for SCP03 and INTERNAL AUTHENTICATE for SCP11b, each repeated until `6983`
/// (continuing on `6A80`), then the domain is factory fresh: default keys, a new SCP11b
/// key and a new CPLC (catalog SecurityDomain: "blocking-based reset and fresh own
/// SCP11b identity").
#[test]
fn blocking_reset_like_yubikit() {
    for custom_sets in [0usize, 3] {
        let (mut sd, mut host) = fresh();
        let old_cplc = cplc(&mut sd, &mut host);
        let mut session = Some(open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33));
        if custom_sets > 0 {
            let (s, ch) = session.as_mut().unwrap();
            for kvn in [0x01, 0x7F, 0xFE].into_iter().take(custom_sets) {
                let data = s.put_key_data(kvn, &StaticKeys::from_seed(kvn));
                assert_eq!(send(&mut sd, ch, &mut host, s, 0x80, 0xD8, 0x00, 0x81, &data).1, 0x9000);
            }
        }
        let (_, ch) = session.unwrap();

        let info = key_info(&mut sd, &mut host);
        let mut refs = Vec::new();
        let mut rest = &info[..];
        while !rest.is_empty() {
            let len = 2 + rest[1] as usize;
            refs.push((rest[2], rest[3]));
            rest = &rest[len..];
        }
        for (kid, kvn) in refs {
            let (ins, p1, p2) = match kid {
                0x01 => (0x50, 0x00, 0x00),
                0x02 | 0x03 => continue,
                0x13 => (0x88, kvn, kid),
                _ => unreachable!(),
            };
            let mut blocked = false;
            for _ in 0..65 {
                let apdu = encode_apdu(0x80, ins, p1, p2, &[0; 8], None, false);
                let sw = status(&sd.handshake(&apdu, &mut host).0);
                match sw {
                    0x6983 | 0x6982 => {
                        blocked = true;
                        break;
                    }
                    0x6A80 | 0x9000 => continue,
                    other => panic!("unexpected {other:04X}"),
                }
            }
            assert!(blocked || kid == 0x01, "key {kid:02X}/{kvn:02X} not blocked");
        }
        assert!(!ch.is_open(), "the reset ends the old session");
        assert_eq!(key_info(&mut sd, &mut host), hex("C00401FF8810 C00402FF8810 C00403FF8810 C0061301B120F000"));
        assert_ne!(cplc(&mut sd, &mut host), old_cplc);
        assert_eq!(sd.remaining_tries(0x13, 0x01), Some(64));
        open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
        let mut sd = restart(&mut host);
        open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    }
}

/// SCP11 request errors (GP Amendment F §7.6/§7.7): unknown key `6A88` (no try used),
/// wrong INS/KID pairing `6A86`, a malformed request `6A80` using one try of the selected
/// key (KVN `00` selects the highest version); PSO without any CA key `6A88`, with a KID
/// that is not a CA key `6A86`.
#[test]
fn scp11_request_errors_and_try_accounting() {
    let (mut sd, mut host) = fresh();
    assert_eq!(sd.handshake(&hex("80880213080000000000000000"), &mut host).0, hex("6A88"));
    assert_eq!(sd.handshake(&hex("80880111080000000000000000"), &mut host).0, hex("6A86"));
    assert_eq!(sd.handshake(&hex("80820111080000000000000000"), &mut host).0, hex("6A88"));
    assert_eq!(sd.remaining_tries(0x13, 0x01), Some(64));
    assert_eq!(sd.handshake(&hex("80880113080000000000000000"), &mut host).0, hex("6A80"));
    assert_eq!(sd.remaining_tries(0x13, 0x01), Some(63));
    assert_eq!(sd.handshake(&hex("80880013080000000000000000"), &mut host).0, hex("6A80"));
    assert_eq!(sd.remaining_tries(0x13, 0x01), Some(62));
    assert_eq!(sd.handshake(&hex("802A01100100"), &mut host).0, hex("6A88"));
    assert_eq!(sd.handshake(&hex("802A01110100"), &mut host).0, hex("6A86"));
    assert_eq!(sd.handshake(&hex("80CA006600"), &mut host).0, hex("6D00"));
}

/// Persistence failures (docs/CONTRACTS.md "Persisted state"): the command answers
/// `6581` and nothing changes.
#[test]
fn persistence_failures_keep_the_previous_state() {
    let (mut sd, mut host) = fresh();
    // INITIALIZE UPDATE: the try cannot be recorded, so no cryptogram is revealed.
    host.fail_next_saves(1);
    assert_eq!(sd.handshake(&init_update_apdu(0xFF, &[1; 8]), &mut host).0, hex("6581"));
    assert_eq!(sd.remaining_tries(1, 0xFF), Some(64));
    let (resp, _) = sd.handshake(&encode_apdu(0x84, 0x82, 0x33, 0x00, &[0; 16], None, false), &mut host);
    assert_eq!(resp, hex("6985"), "no pending handshake");

    // EXTERNAL AUTHENTICATE: restoring the tries fails, so no session.
    let (resp, _) = sd.handshake(&init_update_apdu(0xFF, &[1; 8]), &mut host);
    let pending = read_init_response(&StaticKeys::DEFAULT, &[1; 8], &resp);
    let (apdu, _) = pending.external_authenticate(0x33);
    host.fail_next_saves(1);
    let (resp, ch) = sd.handshake(&apdu, &mut host);
    assert_eq!(resp, hex("6581"));
    assert!(ch.is_none());
    assert_eq!(sd.remaining_tries(1, 0xFF), Some(63));

    // PUT KEY and DELETE KEY.
    let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    let before = host.persisted(Record::SecurityDomain);
    let data = s.put_key_data(0x01, &StaticKeys::from_seed(1));
    host.fail_next_saves(1);
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x00, 0x81, &data).1, 0x6581);
    host.fail_next_saves(1);
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xE4, 0x00, 0x00, &hex("D00113")).1, 0x6581);
    host.fail_next_saves(1);
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xE4, 0x00, 0x01, &hex("D201FF")).1, 0x6581);
    assert!(ch.is_open(), "a failed reset keeps the session");
    assert_eq!(host.persisted(Record::SecurityDomain), before);
    assert_eq!(key_info(&mut sd, &mut host), hex("C00401FF8810 C00402FF8810 C00403FF8810 C0061301B120F000"));
    // The session still works and the same command now succeeds.
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x00, 0x81, &data).1, 0x9000);
}

/// A failed removal of an exhausted set answers `6581` and leaves it exhausted; the next
/// attempt removes it.
#[test]
fn failed_exhaustion_removal_is_retried() {
    let (mut sd, mut host) = fresh();
    for _ in 0..64 {
        sd.handshake(&init_update_apdu(0xFF, &[1; 8]), &mut host);
    }
    host.fail_next_saves(1);
    assert_eq!(sd.handshake(&init_update_apdu(0xFF, &[1; 8]), &mut host).0, hex("6581"));
    assert_eq!(sd.remaining_tries(1, 0xFF), Some(0));
    assert_eq!(sd.handshake(&init_update_apdu(0xFF, &[1; 8]), &mut host).0, hex("6983"));
    assert_eq!(sd.remaining_tries(1, 0xFF), None);
    assert_eq!(key_info(&mut sd, &mut host), hex("C0061301B120F000"));
}

/// Restart: keys, tries, CPLC and the SCP11b key come back; an unreadable record is
/// factory state; a record without CPLC keeps its keys and gains a CPLC; unknown
/// top-level objects are written back.
#[test]
fn restart_and_record_migration() {
    let (mut sd, mut host) = fresh();
    let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    let new = StaticKeys::from_seed(8);
    let data = s.put_key_data(0x08, &new);
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x00, 0x81, &data).1, 0x9000);
    sd.handshake(&init_update_apdu(0x08, &[1; 8]), &mut host);
    let info = key_info(&mut sd, &mut host);
    let id = cplc(&mut sd, &mut host);

    let mut sd2 = restart(&mut host);
    assert_eq!(key_info(&mut sd2, &mut host), info);
    assert_eq!(cplc(&mut sd2, &mut host), id);
    assert_eq!(sd2.remaining_tries(1, 0x08), Some(63));
    open(&mut sd2, &mut host, &new, 0x08, 0x33);

    // Unknown object kept across a mutation.
    let mut record = host.persisted(Record::SecurityDomain).unwrap();
    let extra = hex("BF2003010203");
    record.extend_from_slice(&extra);
    host.set_persisted(Record::SecurityDomain, &record);
    let mut sd3 = restart(&mut host);
    sd3.handshake(&init_update_apdu(0x08, &[1; 8]), &mut host);
    assert!(host.persisted(Record::SecurityDomain).unwrap().ends_with(&extra));

    // Unreadable records: factory state.
    for bad in [vec![], vec![0x02], vec![0x01, 0xA1, 0x05], hex("01FF")] {
        let mut h = TestHost::new();
        let mut sd = SecurityDomain::new(Some(&bad), &mut h);
        assert_eq!(key_info(&mut sd, &mut h), hex("C00401FF8810 C00402FF8810 C00403FF8810 C0061301B120F000"));
        assert!(h.persisted(Record::SecurityDomain).is_some());
    }

    // A record without CPLC (an older format revision) keeps its keys.
    let record = host.persisted(Record::SecurityDomain).unwrap();
    assert_eq!(&record[1..3], &[0x81, 42]);
    let without: Vec<u8> = [&record[..1], &record[3 + 42..]].concat();
    let mut h = TestHost::new().seeded(5);
    let mut sd4 = SecurityDomain::new(Some(&without), &mut h);
    assert_eq!(key_info(&mut sd4, &mut h), info);
    let new_id = cplc(&mut sd4, &mut h);
    assert_eq!(&new_id[..2], &[0, 0]);
    assert_ne!(new_id, id);
    assert_eq!(cplc(&mut restart(&mut h), &mut h), new_id);
}

/// SELECT and deselect drop a half-open handshake (Yubico: the session is bound to the
/// selected applet).
#[test]
fn select_drops_a_pending_handshake() {
    let (mut sd, mut host) = fresh();
    let (resp, _) = sd.handshake(&init_update_apdu(0xFF, &[1; 8]), &mut host);
    let pending = read_init_response(&StaticKeys::DEFAULT, &[1; 8], &resp);
    sd.select(&hex("00a4040008a000000151000000"), &mut host);
    let (apdu, _) = pending.external_authenticate(0x33);
    assert_eq!(sd.handshake(&apdu, &mut host).0, hex("6985"));
    assert_eq!(sd.touch_resolved(true, &mut host), hex("6985"));
}

/// The Security Domain persists only its own record: a reset leaves other applications'
/// records untouched (catalog SecurityDomain_profile: "Domain reset retains independent
/// PIV issuer and OATH secret/HOTP progression").
#[test]
fn reset_touches_only_the_security_domain_record() {
    let (mut sd, mut host) = fresh();
    host.set_persisted(Record::Piv, b"piv state");
    host.set_persisted(Record::Oath, b"oath state");
    let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xE4, 0x00, 0x01, &hex("D201FF")).1, 0x9000);
    assert_eq!(host.persisted(Record::Piv), Some(b"piv state".to_vec()));
    assert_eq!(host.persisted(Record::Oath), Some(b"oath state".to_vec()));
}

/// A channel does not outlive the Security Domain that created it (device restart).
#[test]
fn channel_ends_when_the_domain_is_dropped() {
    let (mut sd, mut host) = fresh();
    let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    drop(sd);
    assert!(!ch.is_open());
    let apdu = s.wrap(0x80, 0xCA, 0x00, 0xE0, &[], None, false);
    assert_eq!(ch.unwrap_command(&apdu), Err(0x6982));
}

/// Only SELECT by name (`00 A4 04 xx`, GP 2.3.1 §11.9.2.1) selects the Security Domain
/// (docs/CONTRACTS.md "Applications A as implemented": only `xx A4 04 xx` is SELECT).
/// Another INS `A4` reaching the selected domain answers `6A86` and ends nothing: a
/// half-open handshake and an open session survive it.
#[test]
fn only_select_by_name_selects_the_domain() {
    let (mut sd, mut host) = fresh();
    let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    let (resp, _) = sd.handshake(&init_update_apdu(0xFF, &[2; 8]), &mut host);
    let pending = read_init_response(&StaticKeys::DEFAULT, &[2; 8], &resp);
    for apdu in [hex("00A4000100"), hex("00A4000C02 3F00")] {
        assert_eq!(plain(&mut sd, &mut host, &apdu), hex("6A86"));
    }
    assert!(ch.is_open());
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xCA, 0x00, 0x66, &[]).1, 0x9000);
    let (apdu, _) = pending.external_authenticate(0x33);
    let (resp, new) = sd.handshake(&apdu, &mut host);
    assert_eq!((resp, new.is_some()), (hex("9000"), true), "the half-open handshake survived");
    // A SELECT by name through process() selects and ends the session.
    let resp = plain(&mut sd, &mut host, &hex("00A4040008A00000015100000000"));
    assert_eq!(resp, hex("6f178408a000000151000000a50b730906072a864886fc6b019000"));
    assert!(!ch.is_open());
}
