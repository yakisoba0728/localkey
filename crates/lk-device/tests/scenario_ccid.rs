//! End-to-end CCID scenarios: a host written from USB CCID Rev 1.1, ISO/IEC 7816-3/-4,
//! YKOATH, SP 800-73-4, OpenPGP card 3.4.1, YubiHSM Auth and GlobalPlatform SCP03 drives
//! the device with raw CCID messages and verifies what comes back.

#![allow(clippy::unwrap_used)]

mod common;

use common::iso::{self, command, find_tlv, hsmauth, oath, pgp, piv, split, tlv};
use common::*;
use lk_crypto::{Curve, HashAlg, ecdsa_verify_prehash, hmac, sha256};
use lk_device::{Input, Output, WTX_INTERVAL_MS};

const SD_REFERENCE: &str = include_str!("../../../reference/physical-key/security-domain-reference-observation.json");

/// Largest `abData` of one CCID message: `dwMaxCCIDMessageLength` 3072 minus the 10-byte
/// header (`reference/physical-key/usb-reference-observation.json` class
/// descriptor; USB CCID Rev 1.1 §5.1).
const MAX_DATA: usize = 3062;

/// Send an APDU of any length over XfrBlock (USB CCID Rev 1.1 §6.1.4): parts of at most
/// `MAX_DATA` bytes with `wLevelParameter` 0001 (begins), 0003 (continues), 0002 (ends);
/// a chained response (`bChainParameter` 01/03, §6.2.1) is fetched with empty XfrBlocks
/// carrying `wLevelParameter` 0010. Returns the response APDU and the number of
/// messages each way.
fn xfr_long(rig: &mut Rig, apdu: &[u8]) -> (Vec<u8>, usize, usize) {
    let parts: Vec<&[u8]> = apdu.chunks(MAX_DATA).collect();
    let mut seq = 0x40u8;
    let mut reply = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        let level: u16 = match (i, parts.len()) {
            (_, 1) => 0x0000,
            (0, _) => 0x0001,
            (i, n) if i + 1 == n => 0x0002,
            _ => 0x0003,
        };
        let [lo, hi] = level.to_le_bytes();
        let out = rig.input(Input::Ccid(&Rig::ccid_message(0x6F, seq, [0, lo, hi], part)));
        let replies = ccid_replies(&out);
        assert_eq!(replies.len(), 1, "one reply per message: {out:02X?}");
        reply = replies[0].clone();
        assert_eq!((reply[0], reply[6], reply[7]), (0x80, seq, 0x00), "DataBlock for seq {seq}");
        if i + 1 < parts.len() {
            assert_eq!((reply[9], reply.len()), (0x10, 10), "empty block, more command expected");
        }
        seq = seq.wrapping_add(1);
    }
    let mut response = reply[10..].to_vec();
    let mut chain = reply[9];
    let mut received = 1;
    while matches!(chain, 0x01 | 0x03) {
        let out = rig.input(Input::Ccid(&Rig::ccid_message(0x6F, seq, [0, 0x10, 0x00], &[])));
        let next = ccid_replies(&out).remove(0);
        assert_eq!((next[0], next[6]), (0x80, seq));
        response.extend_from_slice(&next[10..]);
        chain = next[9];
        received += 1;
        seq = seq.wrapping_add(1);
    }
    assert!(matches!(chain, 0x00 | 0x02), "chain ends: {chain:#04x}");
    (response, parts.len(), received)
}

/// ISO/IEC 7816-3 §8.2: parse an ATR and check its structure: TS `3B` (direct
/// convention), the interface bytes announced by each Y nibble, K historical bytes, and
/// TCK (present when a protocol other than T=0 is indicated) making the XOR of T0..TCK
/// zero. Returns the protocols and the historical bytes.
fn parse_atr(atr: &[u8]) -> (Vec<u8>, Vec<u8>) {
    assert_eq!(atr[0], 0x3B, "TS direct convention");
    let t0 = atr[1];
    let k = usize::from(t0 & 0x0F);
    let mut y = t0 >> 4;
    let mut i = 2;
    let mut protocols = Vec::new();
    loop {
        for bit in [0x1, 0x2, 0x4] {
            if y & bit != 0 {
                i += 1;
            }
        }
        if y & 0x8 == 0 {
            break;
        }
        let td = atr[i];
        protocols.push(td & 0x0F);
        y = td >> 4;
        i += 1;
    }
    let historical = atr[i..i + k].to_vec();
    let tck_present = protocols.iter().any(|&t| t != 0);
    assert_eq!(atr.len(), i + k + usize::from(tck_present), "ATR length");
    if tck_present {
        assert_eq!(atr[1..].iter().fold(0u8, |x, b| x ^ b), 0, "TCK");
    }
    (protocols, historical)
}

/// USB CCID Rev 1.1 §6.1.1 / §6.2.1: IccPowerOn answers `RDR_to_PC_DataBlock` with the
/// profile ATR, ICC present and active, no error; the ATR is well formed (ISO/IEC 7816-3
/// §8.2), offers T=1 and names "YubiKey" in its historical bytes.
#[test]
fn icc_power_on_returns_a_well_formed_atr() {
    let mut rig = Rig::new();
    let out = rig.input(Input::Ccid(&Rig::ccid_message(0x62, 3, [0, 0, 0], &[])));
    let reply = &ccid_replies(&out)[0];
    let len = u32::from_le_bytes(reply[1..5].try_into().unwrap()) as usize;
    assert_eq!((reply[0], reply[5], reply[6], reply[7], reply[8], reply[9]), (0x80, 0, 3, 0x00, 0x00, 0x00));
    let atr = &reply[10..];
    assert_eq!(atr.len(), len);
    assert_eq!(atr, rig.profile.atr.as_slice());
    let (protocols, historical) = parse_atr(atr);
    assert!(protocols.contains(&1), "T=1");
    assert!(historical.ends_with(b"YubiKey"), "{historical:02X?}");
}

/// ISO/IEC 7816-4 §5.3.1 selection by DF name across all seven applications, each
/// recognised by its SELECT answer and by a command only it understands:
/// - OATH: version tag `79` (YKOATH SELECT), LIST;
/// - PIV: application property template `61` (SP 800-73-4 Part 2 §3.1.1), Yubico GET
///   VERSION `FD`;
/// - OpenPGP: empty `9000` (`openpgp-reference-observation.json` SELECT), GET VERSION
///   `F1` (3 bytes in the same file);
/// - Management: the version text, READ CONFIG `1D` (`len || TLVs`);
/// - OTP: the status bytes (version first), the serial slot `10`;
/// - HSM Auth: version tag `79`, GET VERSION `07`;
/// - Security Domain: the `select_public_template` of
///   `security-domain-reference-observation.json` with the `9F65` that GP Card
///   Specification v2.3.1 Table 11-82 makes mandatory added inside `A5` (the reference
///   omits it: a known difference, specification over reference), and the GET DATA
///   `0066` card recognition data of the same file.
///
/// An unknown AID answers `6A82` and keeps the selection.
#[test]
fn select_routes_between_all_seven_applications() {
    let reference = json::parse(SD_REFERENCE);
    let reference_select = hex(reference.get("select_public_template").as_str());
    // GP 2.3.1 §11.9.3.1 Table 11-82: `9F65 01 FF` inside `A5`, both template lengths
    // grown by 4 (the reference's 25 bytes lack it; the engine sent those before).
    let mut sd_select = reference_select.clone();
    sd_select[1] += 4;
    sd_select[13] += 4;
    sd_select.extend_from_slice(&[0x9F, 0x65, 0x01, 0xFF]);
    assert_eq!(sd_select, hex("6F1B8408A000000151000000A50F730906072A864886FC6B019F6501FF"));
    let recognition = hex(reference.get("card_recognition_data").as_str());
    let mut rig = Rig::new();
    rig.power_on();
    let version = [5u8, 7, 4];
    for _round in 0..2 {
        let answer = rig.select(AID_OATH);
        assert_eq!((&answer[..5], sw(&answer)), (&[0x79, 0x03, 5, 7, 4][..], 0x9000));
        assert_eq!(rig.apdu(&[0x00, 0xA1, 0x00, 0x00]), vec![0x90, 0x00]);

        let answer = rig.select(AID_PIV);
        assert_eq!((answer[0], sw(&answer)), (0x61, 0x9000));
        assert_eq!(rig.apdu(&[0x00, 0xFD, 0x00, 0x00]), [&version[..], &[0x90, 0x00]].concat());

        assert_eq!(rig.select(AID_OPENPGP), vec![0x90, 0x00]);
        assert_eq!(rig.apdu(&[0x00, 0xF1, 0x00, 0x00, 0x00]), [&version[..], &[0x90, 0x00]].concat());

        // The Management SELECT text as measured (docs/MEASUREMENT.md, probe `select-mgmt`).
        assert_eq!(rig.select(AID_MGMT), rig.management_select_text());
        let config = rig.apdu(&[0x00, 0x1D, 0x00, 0x00, 0x00]);
        assert_eq!((usize::from(config[0]), sw(&config)), (config.len() - 3, 0x9000));

        let answer = rig.select(AID_OTP);
        assert_eq!((&answer[..3], sw(&answer)), (&version[..], 0x9000));
        assert_eq!(rig.apdu(&[0x00, 0x01, 0x10, 0x00]), [&SERIAL.to_be_bytes()[..], &[0x90, 0x00]].concat());

        let answer = rig.select(AID_HSMAUTH);
        assert_eq!(answer, vec![0x79, 0x03, 5, 7, 4, 0x90, 0x00]);
        assert_eq!(rig.apdu(&[0x00, 0x07, 0x00, 0x00, 0x00]), [&version[..], &[0x90, 0x00]].concat());

        // `80 CA 00 66` answers the recognition data inside its `66` template, 65 bytes
        // (docs/MEASUREMENT.md, probe `cla-variants-sd`; the engine answered the bare
        // 63 bytes before the measurement).
        let wrapped = [&[0x66, 0x3F][..], recognition.as_slice(), &[0x90, 0x00]].concat();
        let answer = rig.select(AID_SD);
        assert_eq!(answer, [sd_select.as_slice(), &[0x90, 0x00]].concat());
        assert_eq!(rig.apdu(&[0x80, 0xCA, 0x00, 0x66, 0x00]), wrapped);

        assert_eq!(rig.select(&[0xA0, 0x00, 0x00, 0x05, 0x27, 0x99]), vec![0x6A, 0x82]);
        assert_eq!(rig.apdu(&[0x80, 0xCA, 0x00, 0x66, 0x00]), wrapped);
    }
}

/// RFC 6238 Appendix B test vectors through YKOATH PUT and CALCULATE (8 digits, T0 = 0,
/// X = 30 s; the host sends the time step as the 8-byte challenge): SHA-1, SHA-256 and
/// SHA-512 with the RFC's seeds at T = 59 and T = 1111111109. A full CALCULATE (`75`)
/// returns the whole HMAC (RFC 4226 §5.3 before truncation).
#[test]
fn oath_totp_rfc6238_vectors() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_OATH);
    let seed20 = b"12345678901234567890".to_vec();
    let seed32 = b"12345678901234567890123456789012".to_vec();
    let seed64 = b"1234567890123456789012345678901234567890123456789012345678901234".to_vec();
    let credentials = [
        (&b"sha1"[..], oath::TOTP_SHA1, &seed20, HashAlg::Sha1, ["94287082", "07081804"]),
        (b"sha256", oath::TOTP_SHA256, &seed32, HashAlg::Sha256, ["46119246", "68084774"]),
        (b"sha512", oath::TOTP_SHA512, &seed64, HashAlg::Sha512, ["90693936", "25091201"]),
    ];
    for (name, kind, seed, _, _) in &credentials {
        assert_eq!(rig.apdu(&oath::put(name, *kind, 8, seed, false)), vec![0x90, 0x00]);
    }
    for (name, _, seed, alg, codes) in &credentials {
        for (time, expected) in [59u64, 1_111_111_109].into_iter().zip(codes) {
            let challenge = (time / 30).to_be_bytes();
            let response = rig.send(&oath::calculate(name, &challenge, true));
            assert_eq!(oath::code(&response), *expected, "{} at T={time}", String::from_utf8_lossy(name));
            let full = rig.send(&oath::calculate(name, &challenge, false));
            let (data, status) = split(&full);
            assert_eq!(status, 0x9000);
            let value = find_tlv(data, 0x75).unwrap();
            assert_eq!(value[0], 8, "digits");
            assert_eq!(&value[1..], hmac(*alg, seed, &challenge).as_slice());
        }
    }
}

/// SP 800-73-4 Part 2: management key mutual authentication (§3.2.4, AES-192 default key
/// of firmware 5.7), GENERATE ASYMMETRIC KEY PAIR in `9A` (§3.3.2), a signature refused
/// before VERIFY (`6982`), VERIFY (§3.2.1), and GENERAL AUTHENTICATE whose ECDSA P-256
/// signature verifies under the generated public key (FIPS 186-5).
#[test]
fn piv_verify_generate_and_sign_verified() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_PIV_FULL);
    assert_eq!(sw(&rig.apdu(&command(0x00, 0x47, 0x00, piv::SLOT_AUTH, &tlv(0xAC, &tlv(0x80, &[0x11])), Some(256)))), 0x6982, "GENERATE needs the management key");
    rig.piv_authenticate(&piv::DEFAULT_MGMT_KEY);
    let point = rig.piv_generate_p256(piv::SLOT_AUTH, None);
    let digest = sha256(b"to be signed by PIV");
    assert_eq!(sw(&rig.send(&Rig::piv_sign_request(piv::SLOT_AUTH, &digest))), 0x6982, "PIN not verified");
    assert_eq!(rig.piv_verify("000000"), 0x63C2, "wrong PIN, two tries left");
    assert_eq!(rig.piv_verify("123456"), 0x9000);
    let signature = Rig::piv_signature(&rig.send(&Rig::piv_sign_request(piv::SLOT_AUTH, &digest)));
    assert_eq!(signature[0], 0x30, "DER");
    assert!(ecdsa_verify_prehash(Curve::P256, &point, &digest, &signature));
    assert!(!ecdsa_verify_prehash(Curve::P256, &point, &sha256(b"other"), &signature));
}

/// OpenPGP card 3.4.1: VERIFY PW3 (§7.2.2), algorithm attributes `C1` for ECDSA P-256
/// (§4.4.3.10), GENERATE (§7.2.14), PSO:CDS refused without PW1 (`6982`), VERIFY PW1 `81`,
/// PSO:CDS (§7.2.10) whose raw `r || s` verifies, and the signature counter `93` counting
/// each signature (§4.4.1). The PW status byte (`C4` byte 1, §4.4.3.6) decides how long
/// PW1 `81` lasts: `01` (the YubiKey default, GnuPG "Signature PIN: not forced") for
/// several signatures; after PUT DATA `C4` = `00` for one only.
#[test]
fn openpgp_verify_and_sign_verified() {
    let mut rig = Rig::new();
    rig.power_on();
    assert_eq!(rig.select(AID_OPENPGP), vec![0x90, 0x00]);
    assert_eq!(rig.pgp_verify(0x83, pgp::PW3), 0x9000);
    assert_eq!(rig.pgp_put(0x00C1, &pgp::ECDSA_P256), 0x9000);
    let point = rig.pgp_generate_signature_key();
    assert_eq!(rig.pgp_signature_counter(), 0);
    let digest = sha256(b"to be signed by OpenPGP");
    assert_eq!(sw(&rig.send(&Rig::pgp_sign_request(&digest))), 0x6982);
    assert_eq!(rig.pgp_verify(0x81, pgp::PW1), 0x9000);
    let status = rig.send(&command(0x00, 0xCA, 0x00, 0xC4, &[], Some(256)));
    assert_eq!((status.len(), status[0], sw(&status)), (9, 0x01, 0x9000), "PW status bytes");
    for count in 1..=2 {
        let response = rig.send(&Rig::pgp_sign_request(&digest));
        let (signature, status) = split(&response);
        assert_eq!((status, signature.len()), (0x9000, 64), "raw r || s");
        assert!(ecdsa_verify_prehash(Curve::P256, &point, &digest, signature));
        assert!(!ecdsa_verify_prehash(Curve::P256, &point, &sha256(b"other"), signature));
        assert_eq!(rig.pgp_signature_counter(), count);
    }
    assert_eq!(rig.pgp_put(0x00C4, &[0x00]), 0x9000, "signature PIN forced");
    assert_eq!(rig.pgp_verify(0x81, pgp::PW1), 0x9000);
    assert_eq!(sw(&rig.send(&Rig::pgp_sign_request(&digest))), 0x9000);
    assert_eq!(sw(&rig.send(&Rig::pgp_sign_request(&digest))), 0x6982, "PW1 81 is spent");
    assert_eq!(rig.pgp_signature_counter(), 3);
}

/// The times of the time-extension messages (`bStatus` `80`, USB CCID Rev 1.1 §6.2.6)
/// for `seq` in timed outputs.
fn wtx_times(outputs: &[(u64, Output)], seq: u8) -> Vec<u64> {
    outputs
        .iter()
        .filter_map(|(at, o)| match o {
            Output::Ccid(m) if m[0] == 0x80 && m[6] == seq && m[7] & 0xC0 == 0x80 => Some(*at),
            _ => None,
        })
        .collect()
}

/// Send a command that waits for a touch: no answer at once, a time extension every
/// `WTX_INTERVAL_MS` for `wait` ms, then Touch(Down) answers it.
fn touch_command(rig: &mut Rig, apdu: &[u8], wait: u64) -> Vec<u8> {
    let start = rig.now;
    let (seq, out) = rig.xfr(apdu);
    assert!(data_block(&out, seq).is_none(), "answered without a touch: {out:02X?}");
    assert_eq!(indicators(&out), vec![true]);
    let timed = rig.run_until(start + wait);
    let expected: Vec<u64> = (1..=wait / WTX_INTERVAL_MS).map(|i| start + i * WTX_INTERVAL_MS).collect();
    assert_eq!(wtx_times(&timed, seq), expected, "time extensions");
    let out = rig.touch_down();
    let response = data_block(&out, seq).unwrap_or_else(|| panic!("no answer after the touch: {out:02X?}"));
    assert_eq!(indicators(&out), vec![false]);
    rig.touch_up();
    response
}

/// Yubico PIV touch policy ALWAYS (`AA 02` in GENERATE): GENERAL AUTHENTICATE waits for a
/// touch with time extensions; Touch(Down) answers with a signature that verifies.
#[test]
fn piv_touch_policy_waits_with_time_extensions() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_PIV);
    rig.piv_authenticate(&piv::DEFAULT_MGMT_KEY);
    let point = rig.piv_generate_p256(piv::SLOT_SIGN, Some(piv::TOUCH_ALWAYS));
    assert_eq!(rig.piv_verify("123456"), 0x9000);
    let digest = sha256(b"touch to sign");
    let response = touch_command(&mut rig, &Rig::piv_sign_request(piv::SLOT_SIGN, &digest), 1_600);
    let signature = Rig::piv_signature(&response);
    assert!(ecdsa_verify_prehash(Curve::P256, &point, &digest, &signature));
}

/// OpenPGP user interaction flag (Yubico UIF, DO `D6` = `01 20`): PSO:CDS waits for a
/// touch with time extensions, then signs.
#[test]
fn openpgp_uif_waits_with_time_extensions() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_OPENPGP);
    rig.pgp_verify(0x83, pgp::PW3);
    rig.pgp_put(0x00C1, &pgp::ECDSA_P256);
    let point = rig.pgp_generate_signature_key();
    assert_eq!(rig.pgp_put(0x00D6, &[0x01, 0x20]), 0x9000);
    rig.pgp_verify(0x81, pgp::PW1);
    let digest = sha256(b"uif");
    let response = touch_command(&mut rig, &Rig::pgp_sign_request(&digest), 2_100);
    let (signature, status) = split(&response);
    assert_eq!(status, 0x9000);
    assert!(ecdsa_verify_prehash(Curve::P256, &point, &digest, signature));
}

/// YubiHSM Auth CALCULATE for a credential with the touch flag (`7A 01`) waits for a
/// touch with time extensions; the session keys it returns are the SCP03 derivations of
/// the stored K-ENC/K-MAC over the host || card challenge context (GP 2.3.1 Amd D
/// §6.2.1: S-ENC constant `04`, S-MAC `06`, S-RMAC `07`).
#[test]
fn hsmauth_touch_credential_waits_with_time_extensions() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_HSMAUTH);
    let (enc, mac, password) = ([0x41u8; 16], [0x42u8; 16], *b"password\0\0\0\0\0\0\0\0");
    assert_eq!(rig.apdu(&hsmauth::put(b"touchy", &enc, &mac, &password, true)), vec![0x90, 0x00]);
    let context: [u8; 16] = *b"hostchalcardchal";
    let response = touch_command(&mut rig, &hsmauth::calculate(b"touchy", &context, &password), 1_000);
    let (keys, status) = split(&response);
    assert_eq!((status, keys.len()), (0x9000, 48));
    assert_eq!(&keys[..16], scp03_derive(&enc, 0x04, &context, 128).as_slice(), "S-ENC");
    assert_eq!(&keys[16..32], scp03_derive(&mac, 0x06, &context, 128).as_slice(), "S-MAC");
    assert_eq!(&keys[32..], scp03_derive(&mac, 0x07, &context, 128).as_slice(), "S-RMAC");
}

/// USB CCID Rev 1.1 §6.1.13 / `docs/CONTRACTS.md` "Phase 0", lk-ccid: a bulk
/// `PC_to_RDR_Abort` for the pending XfrBlock answers `RDR_to_PC_SlotStatus`, cancels the
/// waiting OpenPGP signature (no late reply, the signature counter unchanged), and the
/// slot works again.
#[test]
fn bulk_abort_of_a_pending_apdu() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_OPENPGP);
    rig.pgp_verify(0x83, pgp::PW3);
    rig.pgp_put(0x00C1, &pgp::ECDSA_P256);
    rig.pgp_generate_signature_key();
    rig.pgp_put(0x00D6, &[0x01, 0x20]);
    rig.pgp_verify(0x81, pgp::PW1);
    let (seq, out) = rig.xfr(&Rig::pgp_sign_request(&sha256(b"aborted")));
    assert!(data_block(&out, seq).is_none());
    rig.run_until(rig.now + 700);
    let out = rig.bulk_abort(seq);
    let replies = ccid_replies(&out);
    assert_eq!(replies.len(), 1);
    assert_eq!((replies[0][0], replies[0][6], replies[0][7] & 0xC0), (0x81, seq, 0x00), "SlotStatus, command OK");
    assert_eq!(indicators(&out), vec![false]);
    assert!(rig.run_until(rig.now + 2_000).is_empty(), "no more time extensions");
    assert!(ccid_replies(&rig.tap()).is_empty(), "no late reply");
    assert_eq!(rig.pgp_signature_counter(), 0, "nothing was signed");
}

/// USB CCID Rev 1.1 §6.1.2 IccPowerOff with `docs/DESIGN.md` §5: the card session ends —
/// no application selected afterwards (`6D00`), PIV PIN verification and OpenPGP PW1
/// verification dropped, and the SCP03 session gone (a wrapped command reaches the
/// applet with its secure-messaging bits, `6882`).
#[test]
fn icc_power_off_ends_sessions() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_OPENPGP);
    assert_eq!(rig.pgp_verify(0x82, pgp::PW1), 0x9000);
    rig.select(AID_PIV);
    assert_eq!(rig.piv_verify("123456"), 0x9000);
    let mut session = Scp03::open(&mut rig);
    let status_query = session.wrap(0x00, 0x20, 0x00, 0x80, &[], None);
    assert_eq!(session.unwrap(&rig.apdu(&status_query)), (vec![], 0x9000), "PIN verified, under SCP03");

    let out = rig.power_off();
    assert_eq!(ccid_replies(&out)[0][0], 0x81, "RDR_to_PC_SlotStatus");
    rig.power_on();
    assert_eq!(rig.apdu(&[0x00, 0x20, 0x00, 0x80]), vec![0x6D, 0x00], "no selection");
    rig.select(AID_PIV);
    assert_eq!(rig.apdu(&[0x00, 0x20, 0x00, 0x80]), vec![0x63, 0xC3], "PIN no longer verified");
    let wrapped = session.wrap(0x00, 0x20, 0x00, 0x80, &[], None);
    assert_eq!(rig.apdu(&wrapped), vec![0x68, 0x82], "no secure channel");
    rig.select(AID_OPENPGP);
    assert_eq!(rig.apdu(&[0x00, 0x20, 0x00, 0x82]), vec![0x63, 0xC3], "PW1 no longer verified");
}

/// ISO/IEC 7816-4 §5.1 extended APDUs and §7.6.1 response chaining, with USB CCID Rev 1.1
/// §6.1.4 / §6.2.1 message chaining underneath: a PIV certificate object at the 3052-byte
/// limit (`docs/catalog/piv.md` "published 3052-byte tag70 certificate") is written with
/// one extended PUT DATA that needs two CCID messages; a short GET DATA returns it in
/// 256-byte pieces with `61xx` and GET RESPONSE; an extended GET DATA returns it in one
/// APDU that needs two CCID messages.
#[test]
fn extended_apdus_and_response_chaining() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_PIV);
    rig.piv_authenticate(&piv::DEFAULT_MGMT_KEY);
    let certificate: Vec<u8> = (0..3052u32).map(|i| (i * 7 + 3) as u8).collect();
    let content = [tlv(0x70, &certificate), tlv(0x71, &[0x00]), tlv(0xFE, &[])].concat();
    let object = tlv(0x53, &content);
    let id = [0x5C, 0x03, 0x5F, 0xC1, 0x05];
    let put = iso::extended(0x00, 0xDB, 0x3F, 0xFF, &[&id[..], &object].concat(), None);
    assert!(put.len() > MAX_DATA);
    let (response, sent, received) = xfr_long(&mut rig, &put);
    assert_eq!((response, sent, received), (vec![0x90, 0x00], 2, 1));

    let (data, fetches) = rig.transmit(&command(0x00, 0xCB, 0x3F, 0xFF, &id, Some(256)));
    assert_eq!(sw(&data), 0x9000);
    assert_eq!(&data[..data.len() - 2], object.as_slice());
    assert_eq!(fetches, object.len().div_ceil(256) - 1, "256-byte pieces");

    let get = iso::extended(0x00, 0xCB, 0x3F, 0xFF, &id, Some(65_536));
    let (response, sent, received) = xfr_long(&mut rig, &get);
    assert_eq!((sent, received), (1, 2), "the response needs CCID response chaining");
    assert_eq!(response, [object.as_slice(), &[0x90, 0x00]].concat());
}

/// GlobalPlatform 2.3.1 Amd D SCP03 (`common::Scp03`, written from the specification)
/// opened while PIV is selected, then PIV driven entirely through wrapped commands:
/// VERIFY, management key mutual authentication, GENERATE and GENERAL AUTHENTICATE; the
/// responses carry valid R-MACs and decrypt, and the signature verifies.
#[test]
fn scp03_then_wrapped_piv_commands() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_PIV);
    let mut session = Scp03::open(&mut rig);
    let verify = session.wrap(0x00, 0x20, 0x00, 0x80, &piv::pin_block("123456"), None);
    assert_eq!(session.unwrap(&rig.apdu(&verify)), (vec![], 0x9000));

    let request = session.wrap(0x00, 0x87, piv::ALG_AES192, piv::MGMT, &tlv(0x7C, &tlv(0x80, &[])), None);
    let (data, status) = session.unwrap(&rig.apdu(&request));
    assert_eq!(status, 0x9000);
    let witness = find_tlv(&find_tlv(&data, 0x7C).unwrap(), 0x80).unwrap();
    let clear = lk_crypto::aes_ecb_decrypt_block(&piv::DEFAULT_MGMT_KEY, &witness).unwrap();
    let challenge = [0x3Cu8; 16];
    let inner = [tlv(0x80, &clear), tlv(0x81, &challenge)].concat();
    let request = session.wrap(0x00, 0x87, piv::ALG_AES192, piv::MGMT, &tlv(0x7C, &inner), None);
    let (data, status) = session.unwrap(&rig.apdu(&request));
    assert_eq!(status, 0x9000);
    let answer = find_tlv(&find_tlv(&data, 0x7C).unwrap(), 0x82).unwrap();
    assert_eq!(answer, lk_crypto::aes_ecb_encrypt_block(&piv::DEFAULT_MGMT_KEY, &challenge).unwrap());

    let generate = session.wrap(0x00, 0x47, 0x00, piv::SLOT_AUTH, &tlv(0xAC, &tlv(0x80, &[piv::ALG_ECCP256])), Some(0));
    let (data, status) = session.unwrap(&rig.apdu(&generate));
    assert_eq!(status, 0x9000);
    let point = find_tlv(&find_tlv(&data, 0x7F49).unwrap(), 0x86).unwrap();

    let digest = sha256(b"signed under SCP03");
    let inner = [tlv(0x82, &[]), tlv(0x81, &digest)].concat();
    let sign = session.wrap(0x00, 0x87, piv::ALG_ECCP256, piv::SLOT_AUTH, &tlv(0x7C, &inner), Some(0));
    let (data, status) = session.unwrap(&rig.apdu(&sign));
    assert_eq!(status, 0x9000);
    let signature = find_tlv(&find_tlv(&data, 0x7C).unwrap(), 0x82).unwrap();
    assert!(ecdsa_verify_prehash(Curve::P256, &point, &digest, &signature));
}

/// Yubico yk5-apps-scp ("When a new applet is selected, the session is terminated") and
/// catalog SecurityDomain_plaintext ("malformed plaintext SELECT clears OCE and PIV
/// PIN/admin"): after a plaintext SELECT the next wrapped command is not unwrapped — PIV
/// rejects its secure-messaging CLA (`6882`, `docs/CONTRACTS.md` "Applications B") — and
/// the PIN verified inside the channel is gone.
#[test]
fn wrapped_command_after_select_is_rejected() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_PIV);
    let mut session = Scp03::open(&mut rig);
    let verify = session.wrap(0x00, 0x20, 0x00, 0x80, &piv::pin_block("123456"), None);
    assert_eq!(session.unwrap(&rig.apdu(&verify)), (vec![], 0x9000));
    assert_eq!(sw(&rig.select(AID_PIV)), 0x9000);
    let status_query = session.wrap(0x00, 0x20, 0x00, 0x80, &[], None);
    assert_eq!(rig.apdu(&status_query), vec![0x68, 0x82]);
    assert_eq!(rig.apdu(&[0x00, 0x20, 0x00, 0x80]), vec![0x63, 0xC3]);
}

/// GP 2.3.1 Amd D §6.2.4 with ISO/IEC 7816-4 §5.1 extended APDUs (yubikit's
/// `ScpProcessor` wraps long commands in the extended form): a wrapped extended PUT DATA
/// of a 1 200-byte PIV object, then a wrapped GET DATA answered in one wrapped response
/// when Ne is 65 536, and in 256-byte `61xx` pieces fetched with plaintext GET RESPONSE
/// when Ne is 256 (lk-sd channel docs: the device wraps the complete response, then
/// splits it); one R-MAC covers the whole response either way.
#[test]
fn scp03_wrapped_extended_commands_and_long_responses() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_PIV);
    rig.piv_authenticate(&piv::DEFAULT_MGMT_KEY);
    let mut session = Scp03::open(&mut rig);
    let content: Vec<u8> = (0..1_200u32).map(|i| (i % 251) as u8).collect();
    let object = tlv(0x53, &tlv(0x70, &content));
    let id = [0x5C, 0x03, 0x5F, 0xC1, 0x0A];
    let put = session.wrap_extended(0x00, 0xDB, 0x3F, 0xFF, &[&id[..], &object].concat(), None);
    assert_eq!(session.unwrap(&rig.apdu(&put)), (vec![], 0x9000));

    let get = session.wrap_extended(0x00, 0xCB, 0x3F, 0xFF, &id, Some(65_536));
    let (data, status) = session.unwrap(&rig.apdu(&get));
    assert_eq!((status, data), (0x9000, object.clone()));

    let get = session.wrap(0x00, 0xCB, 0x3F, 0xFF, &id, Some(0));
    let (wrapped, fetches) = rig.transmit(&get);
    assert!(fetches >= 4, "the wrapped response came in 256-byte pieces");
    let (data, status) = session.unwrap(&wrapped);
    assert_eq!((status, data), (0x9000, object));
}

/// A wrapped command that waits for a touch (Yubico PIV touch policy ALWAYS) keeps the
/// secure channel: time extensions while waiting, then the response wrapped with the
/// channel (valid R-MAC, decrypting to a signature that verifies), and the channel
/// usable afterwards.
#[test]
fn scp03_wrapped_command_waiting_for_touch() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_PIV);
    rig.piv_authenticate(&piv::DEFAULT_MGMT_KEY);
    let point = rig.piv_generate_p256(piv::SLOT_SIGN, Some(piv::TOUCH_ALWAYS));
    let mut session = Scp03::open(&mut rig);
    let verify = session.wrap(0x00, 0x20, 0x00, 0x80, &piv::pin_block("123456"), None);
    assert_eq!(session.unwrap(&rig.apdu(&verify)), (vec![], 0x9000));
    let digest = sha256(b"wrapped and touched");
    let inner = [tlv(0x82, &[]), tlv(0x81, &digest)].concat();
    let sign = session.wrap(0x00, 0x87, piv::ALG_ECCP256, piv::SLOT_SIGN, &tlv(0x7C, &inner), Some(0));
    let response = touch_command(&mut rig, &sign, 1_000);
    let (data, status) = session.unwrap(&response);
    assert_eq!(status, 0x9000);
    let signature = find_tlv(&find_tlv(&data, 0x7C).unwrap(), 0x82).unwrap();
    assert!(ecdsa_verify_prehash(Curve::P256, &point, &digest, &signature));
    let query = session.wrap(0x00, 0x20, 0x00, 0x80, &[], None);
    let (_, status) = session.unwrap(&rig.apdu(&query));
    assert_eq!(status, 0x9000, "the channel still works");
}

/// The OTP application over CCID (yubikit `_YubiOtpSmartCardBackend`: `00 01 <slot> 00
/// <data>`) shares the slots programmed over HID; an HMAC-SHA1 challenge-response slot
/// with `CHAL_BTN_TRIG` makes the APDU wait for a touch with time extensions, and the
/// touch answers it with `HMAC-SHA1(secret, challenge)` (RFC 2104) instead of typing.
#[test]
fn ccid_otp_challenge_response_waits_for_touch() {
    use common::otp::{SlotConfig, slot};
    let mut rig = Rig::new();
    let secret = *b"ccid-otp-hmac-secret";
    rig.otp_program(slot::CONFIG2, &SlotConfig::hmac_challenge_response(&secret, true), [0; 6]);
    rig.power_on();
    let answer = rig.select(AID_OTP);
    assert_eq!(answer[4], 2, "programming sequence from the HID writes");
    let challenge = [0xC7u8; 32];
    let mut padded = challenge.to_vec();
    padded.resize(64, 0x00);
    let response = touch_command(&mut rig, &command(0x00, 0x01, slot::CHAL_HMAC2, 0x00, &padded, None), 1_500);
    assert_eq!(response, [&lk_crypto::hmac_sha1(&secret, &challenge)[..], &[0x90, 0x00]].concat());
}

/// Yubico PIV touch policy CACHED (`AB 03`: a touch is remembered for 15 seconds,
/// Yubico PIV documentation "touch policy"): the first signature waits for a touch, a
/// second one 5 s later does not, and one 16 s after the touch waits again — the device
/// hands every applet the input's time (`docs/DESIGN.md` §4).
#[test]
fn piv_cached_touch_policy_follows_device_time() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_PIV);
    rig.piv_authenticate(&piv::DEFAULT_MGMT_KEY);
    let point = rig.piv_generate_p256(piv::SLOT_AUTH, Some(0x03));
    assert_eq!(rig.piv_verify("123456"), 0x9000);
    let digest = sha256(b"cached");
    let response = touch_command(&mut rig, &Rig::piv_sign_request(piv::SLOT_AUTH, &digest), 500);
    assert!(ecdsa_verify_prehash(Curve::P256, &point, &digest, &Rig::piv_signature(&response)));
    let touched = rig.now;
    rig.now = touched + 5_000;
    let signature = Rig::piv_signature(&rig.send(&Rig::piv_sign_request(piv::SLOT_AUTH, &digest)));
    assert!(ecdsa_verify_prehash(Curve::P256, &point, &digest, &signature), "within the cache");
    rig.now = touched + 16_000;
    let response = touch_command(&mut rig, &Rig::piv_sign_request(piv::SLOT_AUTH, &digest), 500);
    assert!(ecdsa_verify_prehash(Curve::P256, &point, &digest, &Rig::piv_signature(&response)));
}
