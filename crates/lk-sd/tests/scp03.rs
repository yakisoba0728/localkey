//! SCP03 handshake and secure messaging, driven by the independent host in `common`.
//!
//! Known-answer values marked "Python/OpenSSL" were computed outside this crate with
//! the Python `cryptography` package (OpenSSL AES and AES-CMAC) following Amd D
//! §4.1.5/§6.2.1-6.2.7 with the default keys `40..4F`, host challenge `A0..A7` and card
//! challenge `B0..B7`; the script builds every byte string by hand.

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use lk_core::{CardApplet, Host, Record};
use lk_sd::{LevelPolicy, SecurityDomain, level};
use lk_testkit::TestHost;

const HOST_CHALLENGE: [u8; 8] = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];
const CARD_CHALLENGE: [u8; 8] = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7];

fn fresh() -> (SecurityDomain, TestHost) {
    let mut host = TestHost::new();
    let sd = SecurityDomain::new(None, &mut host);
    (sd, host)
}

/// The test host's own KDF agrees with the Python/OpenSSL values.
#[test]
fn test_host_kdf_matches_independent_known_answers() {
    let ctx = [HOST_CHALLENGE, CARD_CHALLENGE].concat();
    assert_eq!(derive(&DEFAULT_KEY, 0x04, &ctx, 128), hex("2F053F034AAB44F6E947C1B2BFCF60AE"));
    assert_eq!(derive(&DEFAULT_KEY, 0x06, &ctx, 128), hex("7B249CE4831805885B7C3603BCE1A724"));
    assert_eq!(derive(&DEFAULT_KEY, 0x07, &ctx, 128), hex("5B84BA66E3CF515D85A73CD06A56C5BB"));
    let s_mac: [u8; 16] = hex("7B249CE4831805885B7C3603BCE1A724").try_into().unwrap();
    assert_eq!(derive(&s_mac, 0x00, &ctx, 64), hex("2ACB7522D7BDC0EF"));
    assert_eq!(derive(&s_mac, 0x01, &ctx, 64), hex("918D0D0D6FFF72CD"));
    assert_eq!(kcv(&DEFAULT_KEY).to_vec(), hex("504A77"));
}

/// INITIALIZE UPDATE response bytes for a known card challenge (Python/OpenSSL).
#[test]
fn init_update_response_matches_independent_known_answer() {
    let (mut sd, mut host) = fresh();
    host.push_entropy(&CARD_CHALLENGE);
    let (resp, ch) = sd.handshake(&init_update_apdu(0xFF, &HOST_CHALLENGE), &mut host);
    assert!(ch.is_none());
    assert_eq!(resp, hex("00000000000000000000FF0360B0B1B2B3B4B5B6B72ACB7522D7BDC0EF9000"));
}

/// EXTERNAL AUTHENTICATE, a GET DATA with an encrypted empty field and a PUT KEY, byte
/// for byte (Python/OpenSSL).
///
/// The GET DATA has CLA `84`, a GlobalPlatform class (GP 2.3.1 §11.1.4.1 Table 11-11),
/// so its answer is the whole `66` object, 65 bytes (GP 2.3.1 §11.3.3.1, b8 = 1). The
/// wrapped response was recomputed independently with Python `cryptography` (response
/// ICV `AES(S-ENC, 80 || 0..0 || counter 1)`, AES-CBC, R-MAC = CMAC(S-RMAC, C-MAC ||
/// data || 9000), Amd D §6.2.6-§6.2.7) after the same script reproduced the earlier
/// vector for the bare 63-byte template, which this command got before.
#[test]
fn wrapped_exchange_matches_independent_known_answers() {
    let (mut sd, mut host) = fresh();
    host.push_entropy(&CARD_CHALLENGE);
    sd.handshake(&init_update_apdu(0x00, &HOST_CHALLENGE), &mut host);
    let (resp, ch) = sd.handshake(&hex("8482330010918D0D0D6FFF72CD6216B6FE1D4E3415"), &mut host);
    assert_eq!(resp, hex("9000"));
    let mut ch = ch.unwrap();
    assert_eq!(ch.security_level(), level::FULL);
    assert_eq!(ch.key_version(), 0xFF);

    let cmd1 = hex("84CA00661858EE7EF597E5AD109342BBFAF2AA35845F8539C7E544569800");
    assert_eq!(ch.unwrap_command(&cmd1).unwrap(), hex("80CA006600"));
    let resp = device_after_unwrap(&mut sd, &mut ch, &mut host, &hex("80CA006600"));
    assert_eq!(
        resp,
        hex("CC682FA78B3ECA5382D875B2E50AC8878502D0CF04454846E67E8FC4088741F250B71C907D9A91ADE06F9967D83D3CB8E366A2455D274D6CDCD202A4C508D33E6D3B00D64D8AF339C364BAFB15B0D45E1B67DE449B948C059000")
    );

    let cmd2 = hex(
        "84D80081587C389D0A73B10D68B437B25179ED699D178B8146CB8F647353F66DCB4FAEE8B7A501DC4B1937D62F853719A6C946E84D3F7815D09CC7D64527A0322AD9726279854846178C04DD490A2161BEBB0E230CCDBC4F44C9F64D49",
    );
    let plain = ch.unwrap_command(&cmd2).unwrap();
    let mut expected = hex("80D8008143");
    expected.extend(hex("018810790ACCDA858B997029FA9AE50C9CD0280301380888108CAA7F589AA0CEB6350A45E70A6E435B03840DE588101445AD3442BE8A465148C5667F6022C5035EAADA"));
    assert_eq!(plain, expected);
    let resp = device_after_unwrap(&mut sd, &mut ch, &mut host, &plain);
    assert_eq!(resp, hex("A09D9683A632CC0C5DE38B3DA3E9F07CE706BFB41C5BC2DF9000"));
}

fn device_after_unwrap(sd: &mut SecurityDomain, ch: &mut lk_sd::SecureChannel, host: &mut TestHost, plain: &[u8]) -> Vec<u8> {
    let resp = match sd.process_secure(plain, ch, host) {
        lk_core::Outcome::Done(r) => r,
        _ => unreachable!(),
    };
    ch.wrap_response(&resp)
}

/// Every Amd D §7.1.2 Table 7-3 level, end to end, under the Amd D policy: GET DATA
/// with and without data, PUT KEY (key data in clear or encrypted according to
/// C-DECRYPTION), an error status, and the R-MAC/R-ENCRYPTION shape of each response.
#[test]
fn full_handshake_at_every_security_level() {
    for &lvl in &level::AMENDMENT_D {
        for pad_empty in [true, false] {
            let (mut sd, mut host) = fresh();
            sd.set_level_policy(LevelPolicy::AmendmentD);
            let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, lvl);
            s.pad_empty = pad_empty;
            assert_eq!(ch.security_level(), lvl);

            // GET DATA 0066 through the channel: the raw wrapped response reveals the
            // level. CLA `84` is a GlobalPlatform class, so the answer is the whole `66`
            // object, 65 bytes (GP 2.3.1 §11.3.3.1).
            let apdu = s.wrap(0x80, 0xCA, 0x00, 0x66, &[], Some(0), false);
            let raw = device_transmit(&mut sd, &mut ch, &mut host, &apdu);
            let (data, sw) = s.unwrap(&raw).unwrap();
            assert_eq!(sw, 0x9000);
            assert_eq!(data, hex("663f733d06072a864886fc6b01600c060a2a864886fc6b02020301630906072a864886fc6b03640b06092a864886fc6b040360640c060a2a864886fc6b04119b06"));
            let expected_len = match (lvl & level::R_ENCRYPTION != 0, lvl & level::R_MAC != 0) {
                (true, true) => 80 + 8 + 2,
                (false, true) => 65 + 8 + 2,
                (false, false) => 65 + 2,
                (true, false) => unreachable!(),
            };
            assert_eq!(raw.len(), expected_len, "level {lvl:02X}");

            // PUT KEY: data field is encrypted under C-DECRYPTION.
            let new = StaticKeys::from_seed(lvl);
            let data = s.put_key_data(0x01, &new);
            let apdu = s.wrap(0x80, 0xD8, 0x00, 0x81, &data, None, false);
            if lvl & level::C_DECRYPTION == 0 {
                assert_eq!(&apdu[5..5 + data.len()], &data[..], "C-MAC only sends clear data");
            } else {
                assert_ne!(&apdu[5..5 + data.len()], &data[..]);
            }
            let raw = device_transmit(&mut sd, &mut ch, &mut host, &apdu);
            let (resp, sw) = s.unwrap(&raw).unwrap();
            assert_eq!(sw, 0x9000);
            assert_eq!(resp, put_key_response(0x01, &new));

            // An error status comes back bare and still leaves the session usable.
            let (resp, sw) = send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xCA, 0x00, 0x01, &[]);
            assert_eq!((resp.len(), sw), (0, 0x6A88));
            let (resp, sw) = send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xCA, 0x00, 0xE0, &[]);
            assert_eq!(sw, 0x9000);
            assert_eq!(resp, hex("E01A C004010188 10C004020188 10C004030188 10C00613 01B120F000"));

            // The new keys authenticate; the factory set is gone.
            let (_s2, _ch2) = open(&mut sd, &mut host, &new, 0x01, lvl);
            let (resp, _) = sd.handshake(&init_update_apdu(0xFF, &[0; 8]), &mut host);
            assert_eq!(status(&resp), 0x6A88);
        }
    }
}

/// Yubico yk5-apps-scp: "The YubiKey implements this with all of them turned on.
/// Turning anything off is not an option." Under the default policy only `33` passes.
#[test]
fn default_policy_accepts_only_the_full_security_level() {
    for lvl in [0x00, 0x01, 0x03, 0x10, 0x11, 0x13, 0x31, 0x23, 0xFF] {
        let (mut sd, mut host) = fresh();
        assert_eq!(sd.level_policy(), LevelPolicy::FullOnly);
        let (resp, _) = sd.handshake(&init_update_apdu(0, &[1; 8]), &mut host);
        let pending = read_init_response(&StaticKeys::DEFAULT, &[1; 8], &resp);
        let (apdu, _) = pending.external_authenticate(lvl);
        let (resp, ch) = sd.handshake(&apdu, &mut host);
        assert_eq!(status(&resp), 0x6A86, "level {lvl:02X}");
        assert!(ch.is_none());
    }
    let (mut sd, mut host) = fresh();
    let (_s, ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    assert!(ch.is_open());
    // Under the Amendment D policy, 00 and invalid combinations are still refused.
    sd.set_level_policy(LevelPolicy::AmendmentD);
    for lvl in [0x00, 0x10, 0x31, 0x23] {
        let (resp, _) = sd.handshake(&init_update_apdu(0, &[1; 8]), &mut host);
        let pending = read_init_response(&StaticKeys::DEFAULT, &[1; 8], &resp);
        let (apdu, _) = pending.external_authenticate(lvl);
        assert_eq!(status(&sd.handshake(&apdu, &mut host).0), 0x6A86);
    }
}

/// Wrong static keys: the host sees a wrong card cryptogram, and the card rejects the
/// host's MAC (Amd D §7.1.2: C-MAC verified first, `6982`).
#[test]
fn wrong_static_keys_are_rejected() {
    let (mut sd, mut host) = fresh();
    let wrong = StaticKeys::from_seed(9);
    let (resp, _) = sd.handshake(&init_update_apdu(0xFF, &[7; 8]), &mut host);
    let pending = read_init_response(&wrong, &[7; 8], &resp);
    assert!(!pending.card_cryptogram_ok);
    let (apdu, _) = pending.external_authenticate(0x33);
    let (resp, ch) = sd.handshake(&apdu, &mut host);
    assert_eq!(resp, hex("6982"));
    assert!(ch.is_none());
    // The pending handshake was consumed.
    let (resp, _) = sd.handshake(&apdu, &mut host);
    assert_eq!(resp, hex("6985"));
}

/// A valid C-MAC over a wrong host cryptogram: `6300` (Amd D §7.1.2, "Authentication of
/// host cryptogram failed").
#[test]
fn wrong_host_cryptogram_with_valid_mac_is_6300() {
    let (mut sd, mut host) = fresh();
    let (resp, _) = sd.handshake(&init_update_apdu(0xFF, &[7; 8]), &mut host);
    let pending = read_init_response(&StaticKeys::DEFAULT, &[7; 8], &resp);
    let mut bad = pending.host_cryptogram();
    bad[0] ^= 1;
    let (apdu, _) = pending.external_authenticate_with(0x33, &bad);
    let (resp, ch) = sd.handshake(&apdu, &mut host);
    assert_eq!(resp, hex("6300"));
    assert!(ch.is_none());
}

/// EXTERNAL AUTHENTICATE without INITIALIZE UPDATE: `6985`; wrong Lc: `6700`.
#[test]
fn external_authenticate_preconditions() {
    let (mut sd, mut host) = fresh();
    let apdu = encode_apdu(0x84, 0x82, 0x33, 0x00, &[0; 16], None, false);
    assert_eq!(sd.handshake(&apdu, &mut host).0, hex("6985"));
    sd.handshake(&init_update_apdu(0xFF, &[7; 8]), &mut host);
    let (resp, _) = sd.handshake(&encode_apdu(0x84, 0x82, 0x33, 0x00, &[0; 8], None, false), &mut host);
    assert_eq!(resp, hex("6700"));
    // P2 other than 00 / an SCP11a/c key reference.
    sd.handshake(&init_update_apdu(0xFF, &[7; 8]), &mut host);
    let (resp, _) = sd.handshake(&encode_apdu(0x84, 0x82, 0x33, 0x01, &[0; 16], None, false), &mut host);
    assert_eq!(resp, hex("6A86"));
}

/// A wrong C-MAC ends the session (`6982`, bare) and later commands are refused, even
/// correctly wrapped ones (Amd D §6.2.4).
#[test]
fn wrong_cmac_ends_the_session() {
    let (mut sd, mut host) = fresh();
    let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    let mut apdu = s.wrap(0x80, 0xCA, 0x00, 0xE0, &[], None, false);
    let last = apdu.len() - 1;
    apdu[last] ^= 0x01;
    assert_eq!(ch.unwrap_command(&apdu), Err(0x6982));
    assert!(!ch.is_open());
    let apdu = s.wrap(0x80, 0xCA, 0x00, 0xE0, &[], None, false);
    assert_eq!(ch.unwrap_command(&apdu), Err(0x6982));
    // A response after a refused command passes unchanged.
    assert_eq!(ch.wrap_response(&hex("9000")), hex("9000"));
}

/// Tampered ciphertext fails the C-MAC; a missing MAC is refused.
#[test]
fn tampered_or_truncated_commands_are_refused() {
    let (mut sd, mut host) = fresh();
    let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    let mut apdu = s.wrap(0x80, 0xCA, 0x00, 0xE0, &[1, 2, 3], None, false);
    apdu[6] ^= 0x80;
    assert_eq!(ch.unwrap_command(&apdu), Err(0x6982));

    let (_s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    assert_eq!(ch.unwrap_command(&hex("84CA00E00401020304")), Err(0x6982));
    let (_s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    assert_eq!(ch.unwrap_command(&hex("84CA00E0")), Err(0x6982));
    let (_s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    assert_eq!(ch.unwrap_command(&hex("84CA")), Err(0x6700));
    assert!(!ch.is_open());
}

/// A host whose MAC covered the short Lc form but sent the extended form fails: the
/// MAC covers Lc as sent (Amd D §6.2.4).
#[test]
fn extended_length_commands_mac_the_extended_lc() {
    let (mut sd, mut host) = fresh();
    let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    let long = vec![0x5A; 300];
    let apdu = s.wrap(0x80, 0xCA, 0x00, 0x66, &long, Some(0), true);
    let plain = ch.unwrap_command(&apdu).unwrap();
    assert_eq!(&plain[..7], &[0x80, 0xCA, 0x00, 0x66, 0x00, 0x01, 0x2C]);
    assert_eq!(&plain[7..307], &long[..]);
    assert_eq!(&plain[307..], &[0x00, 0x00]);
    let resp = device_after_unwrap(&mut sd, &mut ch, &mut host, &plain);
    let (data, sw) = s.unwrap(&resp).unwrap();
    // CLA `84`: the whole `66` object (GP 2.3.1 §11.3.3.1).
    assert_eq!((data.len(), sw), (65, 0x9000));

    // Short data in the extended form (as Yubico's SDK sends it).
    let apdu = s.wrap(0x80, 0xCA, 0x00, 0xE0, &[], Some(0), true);
    let resp = device_transmit(&mut sd, &mut ch, &mut host, &apdu);
    assert_eq!(s.unwrap(&resp).unwrap().1, 0x9000);

    // MAC computed over the short form, sent in the extended form.
    let mut wrong = s.clone();
    let short = wrong.wrap(0x80, 0xCA, 0x00, 0xE0, &[1, 2], None, false);
    let mut ext = short[..4].to_vec();
    ext.extend_from_slice(&[0x00, 0x00, short[4]]);
    ext.extend_from_slice(&short[5..]);
    assert_eq!(ch.unwrap_command(&ext), Err(0x6982));
}

/// A long response is protected as a whole, before any `61xx` splitting.
#[test]
fn long_responses_are_protected_whole() {
    let (mut sd, mut host) = fresh();
    let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    let apdu = s.wrap(0x00, 0xCB, 0x3F, 0xFF, &[], Some(0), true);
    ch.unwrap_command(&apdu).unwrap();
    let big: Vec<u8> = (0..2000u32).map(|i| i as u8).collect();
    let wrapped = ch.wrap_response(&[big.clone(), vec![0x90, 0x00]].concat());
    assert_eq!(wrapped.len(), 2000 + 16 + 8 + 2);
    assert_eq!(s.unwrap(&wrapped).unwrap(), (big, 0x9000));
    // A warning status with data is protected too.
    let apdu = s.wrap(0x00, 0xCB, 0x3F, 0xFF, &[], Some(0), false);
    ch.unwrap_command(&apdu).unwrap();
    let wrapped = ch.wrap_response(&hex("0102036283"));
    assert_eq!(s.unwrap(&wrapped).unwrap(), (vec![1, 2, 3], 0x6283));
}

/// Commands for other applets: CLA `00` becomes `04` on the wire and `00` after
/// unwrapping (ISO/IEC 7816-4 §5.1.1 secure messaging indication).
#[test]
fn interindustry_class_is_unwrapped_to_plain_class() {
    let (mut sd, mut host) = fresh();
    let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    let apdu = s.wrap(0x00, 0xCB, 0x3F, 0xFF, &[0x5C, 0x03, 0x5F, 0xC1, 0x05], Some(0), false);
    assert_eq!(apdu[0], 0x04);
    assert_eq!(ch.unwrap_command(&apdu).unwrap(), hex("00CB3FFF055C035FC10500"));
    let (data, sw) = s.unwrap(&ch.wrap_response(&hex("53009000"))).unwrap();
    assert_eq!((data, sw), (hex("5300"), 0x9000));
}

/// Yubico yk5-apps-scp: "Sending a command in plain text will not be accepted and
/// immediately ends the session". Catalog SecurityDomain_plaintext: INIT UPDATE, GET
/// DATA, chained CLA 90, unsupported CLA are rejected before dispatch and consume no
/// tries.
#[test]
fn plaintext_commands_end_the_session_before_dispatch() {
    let cases = [
        init_update_apdu(0xFF, &[1; 8]),
        hex("80CA00E000"),
        hex("00CA006600"),
        hex("90E2000001AA"),
        hex("00C0000000"),
        hex("A0CA006600"),
        hex("80880113080000000000000000"),
        hex("802A0110020000"),
    ];
    for apdu in cases {
        let (mut sd, mut host) = fresh();
        let (_s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
        let persisted = host.persist_count();
        assert_eq!(ch.unwrap_command(&apdu), Err(0x6982), "{apdu:02X?}");
        assert!(!ch.is_open());
        assert_eq!(sd.remaining_tries(1, 0xFF), Some(64));
        assert_eq!(host.persist_count(), persisted);
    }
}

/// A plaintext SELECT ends the session and is processed normally; its response is not
/// wrapped (Yubico: "When a new applet is selected, the session is terminated").
#[test]
fn plaintext_select_ends_the_session_and_passes_through() {
    let (mut sd, mut host) = fresh();
    let (_s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    let select = hex("00A4040008A000000151000000");
    assert_eq!(ch.unwrap_command(&select).unwrap(), select);
    assert!(!ch.is_open());
    let resp = sd.select(&select, &mut host);
    assert_eq!(ch.wrap_response(&resp), resp);
}

/// An encrypted SELECT is protected and then ends the session (catalog
/// SecurityDomain_metadata: "encrypted SELECT terminate[s] authorization for subsequent
/// commands").
#[test]
fn encrypted_select_protects_its_response_then_closes() {
    let (mut sd, mut host) = fresh();
    let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    let apdu = s.wrap(0x00, 0xA4, 0x04, 0x00, lk_sd::AID, Some(0), false);
    let resp = device_transmit(&mut sd, &mut ch, &mut host, &apdu);
    let (data, sw) = s.unwrap(&resp).unwrap();
    assert_eq!(sw, 0x9000);
    // GP 2.3.1 Table 11-82 FCI with `9F65` (the reference's 25 bytes lack it).
    assert_eq!(data, hex("6f1b8408a000000151000000a50f730906072a864886fc6b019f6501ff"));
    assert!(!ch.is_open());
    let apdu = s.wrap(0x80, 0xCA, 0x00, 0xE0, &[], None, false);
    assert_eq!(ch.unwrap_command(&apdu), Err(0x6982));
}

/// An encrypted SELECT whose class codes another logical channel (`05`, unwrapped to
/// `01`) is not a session boundary: lk-device answers it `6881` without selecting
/// anything (ISO/IEC 7816-4:1995 §5.5.2; lk-device `card.rs`), so the session goes on and
/// the next protected command works.
#[test]
fn encrypted_select_on_another_logical_channel_keeps_the_session() {
    let (mut sd, mut host) = fresh();
    let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    let apdu = s.wrap(0x01, 0xA4, 0x04, 0x00, lk_sd::AID, Some(0), false);
    assert_eq!(apdu[0], 0x05);
    let plain = ch.unwrap_command(&apdu).unwrap();
    assert_eq!(&plain[..4], &[0x01, 0xA4, 0x04, 0x00]);
    assert_eq!(ch.wrap_response(&hex("6881")), hex("6881"), "error statuses are bare");
    assert!(ch.is_open());
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xCA, 0x00, 0x66, &[]).1, 0x9000);
    // The same SELECT on the basic channel still ends the session after its response.
    let apdu = s.wrap(0x00, 0xA4, 0x04, 0x00, lk_sd::AID, Some(0), false);
    let (_, sw) = s.unwrap(&device_transmit(&mut sd, &mut ch, &mut host, &apdu)).unwrap();
    assert_eq!(sw, 0x9000);
    assert!(!ch.is_open());
}

/// Selecting another applet (the device calls `end_session`/`deselect`) or a reset ends
/// the session.
#[test]
fn session_ends_on_deselect_and_reset() {
    for action in 0..3 {
        let (mut sd, mut host) = fresh();
        let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
        match action {
            0 => sd.deselect(),
            1 => sd.reset(lk_core::ResetKind::CardPowerOff),
            _ => sd.end_session(),
        }
        assert!(!ch.is_open());
        let apdu = s.wrap(0x80, 0xCA, 0x00, 0xE0, &[], None, false);
        assert_eq!(ch.unwrap_command(&apdu), Err(0x6982));
    }
}

/// Catalog SCP03: "INITIALIZE UPDATE rejects a non-maximum explicit Le before resetting
/// a session or decrementing authentication retries; an absent or maximum Le ...
/// pass".
#[test]
fn init_update_le_guard() {
    let (mut sd, mut host) = fresh();
    let challenge = [3u8; 8];
    let (resp, _) = sd.handshake(&init_update_apdu(0xFF, &challenge), &mut host);
    let pending = read_init_response(&StaticKeys::DEFAULT, &challenge, &resp);
    assert_eq!(sd.remaining_tries(1, 0xFF), Some(63));
    for le in [0x1D, 0x01, 0xFF] {
        let apdu = encode_apdu(0x80, 0x50, 0xFF, 0x00, &challenge, Some(le), false);
        assert_eq!(sd.handshake(&apdu, &mut host).0, hex("6700"));
    }
    let apdu = encode_apdu(0x80, 0x50, 0xFF, 0x00, &challenge, Some(0x001D), true);
    assert_eq!(sd.handshake(&apdu, &mut host).0, hex("6700"));
    assert_eq!(sd.remaining_tries(1, 0xFF), Some(63));
    // The pending handshake survived.
    let (apdu, _) = pending.external_authenticate(0x33);
    let (resp, ch) = sd.handshake(&apdu, &mut host);
    assert_eq!(resp, hex("9000"));
    assert!(ch.is_some());
    assert_eq!(sd.remaining_tries(1, 0xFF), Some(64));
    // Le 00 (short) and 0000 (extended) are the maximum and pass.
    for (le, ext) in [(0u16, false), (0u16, true)] {
        let apdu = encode_apdu(0x80, 0x50, 0xFF, 0x00, &challenge, Some(le), ext);
        assert_eq!(status(&sd.handshake(&apdu, &mut host).0), 0x9000);
    }
}

/// INITIALIZE UPDATE parameter errors (Amd D §7.1.1). Handshake commands may be
/// chained (ISO/IEC 7816-4 §5.1.1.1, needed for certificates in PSO): a chained part is
/// buffered, and the assembled 16-byte challenge is then refused.
#[test]
fn init_update_parameter_errors() {
    let (mut sd, mut host) = fresh();
    assert_eq!(sd.handshake(&encode_apdu(0x80, 0x50, 0xFF, 0x01, &[0; 8], None, false), &mut host).0, hex("6A86"));
    assert_eq!(sd.handshake(&encode_apdu(0x80, 0x50, 0xFF, 0x00, &[0; 16], None, false), &mut host).0, hex("6A80"));
    assert_eq!(sd.handshake(&encode_apdu(0x80, 0x50, 0xFF, 0x00, &[], None, false), &mut host).0, hex("6A80"));
    assert_eq!(sd.handshake(&init_update_apdu(0x01, &[0; 8]), &mut host).0, hex("6A88"));
    assert_eq!(sd.handshake(&encode_apdu(0x81, 0x50, 0xFF, 0x00, &[0; 8], None, false), &mut host).0, hex("6881"));
    assert_eq!(sd.handshake(&encode_apdu(0x90, 0x50, 0xFF, 0x00, &[0; 8], None, false), &mut host).0, hex("9000"));
    assert_eq!(sd.handshake(&encode_apdu(0x80, 0x50, 0xFF, 0x00, &[0; 8], None, false), &mut host).0, hex("6A80"));
    assert_eq!(sd.handshake(&encode_apdu(0x90, 0x50, 0xFF, 0x00, &[0; 8], None, false), &mut host).0, hex("9000"));
    assert_eq!(sd.handshake(&encode_apdu(0x80, 0x50, 0xFE, 0x00, &[0; 8], None, false), &mut host).0, hex("6883"));
    assert_eq!(sd.handshake(&encode_apdu(0x00, 0x50, 0xFF, 0x00, &[0; 8], None, false), &mut host).0, hex("6E00"));
    assert_eq!(sd.handshake(&hex("8050"), &mut host).0, hex("6700"));
    assert_eq!(sd.remaining_tries(1, 0xFF), Some(64));
}

/// A handshake through an existing channel (catalog SecurityDomain_handoff: a
/// not-yet-authenticated SCP03 INITIALIZE UPDATE keeps the outer transport; the old
/// channel protects the handshake responses; the new context replaces it).
#[test]
fn nested_handshake_through_an_outer_channel() {
    let (mut sd, mut host) = fresh();
    let (mut outer, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    let challenge = [9u8; 8];
    let apdu = outer.wrap(0x80, 0x50, 0xFF, 0x00, &challenge, None, false);
    let resp = device_transmit(&mut sd, &mut ch, &mut host, &apdu);
    let (data, sw) = outer.unwrap(&resp).unwrap();
    assert_eq!(sw, 0x9000);
    let pending = read_init_response(&StaticKeys::DEFAULT, &challenge, &[data, vec![0x90, 0x00]].concat());
    assert!(pending.card_cryptogram_ok);
    assert!(ch.is_open(), "INITIALIZE UPDATE keeps the outer channel");

    let (ext, mut inner) = pending.external_authenticate(0x33);
    let apdu = outer.wrap(0x80, 0x82, 0x33, 0x00, &ext[5..], None, false);
    let plain = ch.unwrap_command(&apdu).unwrap();
    let (resp, new) = sd.handshake(&plain, &mut host);
    let wrapped = ch.wrap_response(&resp);
    assert_eq!(outer.unwrap(&wrapped).unwrap(), (vec![], 0x9000));
    let mut ch = new.unwrap();
    let (data, sw) = send(&mut sd, &mut ch, &mut host, &mut inner, 0x80, 0xCA, 0x00, 0x66, &[]);
    assert_eq!((data.len(), sw), (65, 0x9000), "the whole `66` object for CLA `84`");
}

/// Command chaining with one C-MAC per part: the parts are unwrapped one by one, keep
/// CLA bit b5, and the Security Domain reassembles them (ISO/IEC 7816-4 §5.1.1.1).
#[test]
fn chained_parts_each_with_their_own_mac() {
    let (mut sd, mut host) = fresh();
    let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    let new = StaticKeys::from_seed(3);
    let data = s.put_key_data(0x07, &new);
    let (a, b) = data.split_at(30);
    let part1 = s.wrap(0x90, 0xD8, 0x00, 0x81, a, None, false);
    assert_eq!(part1[0], 0x94);
    let resp = device_transmit(&mut sd, &mut ch, &mut host, &part1);
    assert_eq!(s.unwrap(&resp).unwrap(), (vec![], 0x9000));
    let part2 = s.wrap(0x80, 0xD8, 0x00, 0x81, b, None, false);
    let resp = device_transmit(&mut sd, &mut ch, &mut host, &part2);
    assert_eq!(s.unwrap(&resp).unwrap(), (put_key_response(0x07, &new), 0x9000));
}

/// A session after the domain reset closes after its last response (catalog
/// SecurityDomain_metadata: "old response remains SDK MAC-verified while reset ...
/// terminate[s] authorization for subsequent commands").
#[test]
fn explicit_reset_protects_the_last_response_then_closes() {
    let (mut sd, mut host) = fresh();
    let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    let (data, sw) = send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xE4, 0x00, 0x01, &hex("D201FF"));
    assert_eq!((data, sw), (vec![], 0x9000));
    assert!(!ch.is_open());
    let apdu = s.wrap(0x80, 0xCA, 0x00, 0xE0, &[], None, false);
    assert_eq!(ch.unwrap_command(&apdu), Err(0x6982));
}

/// PUT KEY and DELETE KEY need a session: `6982` without one, and a CLA 84 command
/// without a channel is not accepted as protected.
#[test]
fn management_commands_need_a_session() {
    let (mut sd, mut host) = fresh();
    let data = put_key_data(&DEFAULT_KEY, 1, &StaticKeys::from_seed(1));
    let apdu = encode_apdu(0x80, 0xD8, 0x00, 0x81, &data, None, false);
    assert_eq!(plain(&mut sd, &mut host, &apdu), hex("6982"));
    let apdu = encode_apdu(0x84, 0xD8, 0x00, 0x81, &data, None, false);
    assert_eq!(plain(&mut sd, &mut host, &apdu), hex("6982"));
    assert_eq!(plain(&mut sd, &mut host, &hex("80E4000003D201FF")), hex("6982"));
    // A closed channel does not authorize either.
    let (_s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    ch.close();
    let resp = match sd.process_secure(&hex("80E4000003D201FF"), &ch, &mut host) {
        lk_core::Outcome::Done(r) => r,
        _ => unreachable!(),
    };
    assert_eq!(resp, hex("6982"));
    assert_eq!(sd.remaining_tries(1, 0xFF), Some(64));
}

/// `close_after_response` lets the device end a session after protecting one more
/// response.
#[test]
fn close_after_response_is_honoured() {
    let (mut sd, mut host) = fresh();
    let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    let apdu = s.wrap(0x80, 0xCA, 0x00, 0x66, &[], None, false);
    let plain = ch.unwrap_command(&apdu).unwrap();
    ch.close_after_response();
    assert!(ch.is_open());
    let resp = device_after_unwrap(&mut sd, &mut ch, &mut host, &plain);
    assert_eq!(s.unwrap(&resp).unwrap().1, 0x9000);
    assert!(!ch.is_open());
    let _ = host.now();
}

/// yubikit on a session configured for extended APDUs (USB; `SecurityDomainSession`
/// calls `configure(Version(5, 3, 0))`) sends every command in the extended form, and
/// `ScpProcessor.send_apdu` MACs the header and the extended Lc (`00 00 10`) of
/// EXTERNAL AUTHENTICATE too. Amd D §6.2.4 / §7.1.2.1: the C-MAC covers the command
/// header and Lc as sent. The extended EXTERNAL AUTHENTICATE is accepted with an
/// extended-Lc MAC and refused (`6982`) with a short-Lc MAC, and the short form the
/// other way round. The session then runs on extended commands, also when it carries a
/// nested extended EXTERNAL AUTHENTICATE.
#[test]
fn extended_external_authenticate_macs_the_extended_lc() {
    let challenge = [0x2Au8; 8];
    for (extended, mac_extended, expected) in [(true, true, 0x9000), (true, false, 0x6982), (false, true, 0x6982), (false, false, 0x9000)] {
        let (mut sd, mut host) = fresh();
        let iu = encode_apdu(0x80, 0x50, 0x00, 0x00, &challenge, Some(0), true);
        let (resp, _) = sd.handshake(&iu, &mut host);
        let pending = read_init_response(&StaticKeys::DEFAULT, &challenge, &resp);
        assert!(pending.card_cryptogram_ok);
        let (apdu, mut s) = pending.external_authenticate_form(0x33, &pending.host_cryptogram(), extended, mac_extended);
        let (resp, ch) = sd.handshake(&apdu, &mut host);
        assert_eq!(status(&resp), expected, "extended {extended}, MAC over extended Lc {mac_extended}");
        assert_eq!(ch.is_some(), expected == 0x9000);
        let Some(mut ch) = ch else { continue };
        let (data, sw) = send_ext(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xCA, 0x00, 0x66, &[]);
        assert_eq!((data.len(), sw), (65, 0x9000), "the whole `66` object for CLA `84`");
        let new = StaticKeys::from_seed(0x31);
        let data = s.put_key_data(0x31, &new);
        assert_eq!(send_ext(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xD8, 0x00, 0x81, &data), (put_key_response(0x31, &new), 0x9000));

        // A nested handshake through the extended outer channel.
        let apdu = s.wrap(0x80, 0x50, 0x31, 0x00, &challenge, Some(0), true);
        let (data, sw) = s.unwrap(&device_transmit(&mut sd, &mut ch, &mut host, &apdu)).unwrap();
        assert_eq!(sw, 0x9000);
        let inner_pending = read_init_response(&new, &challenge, &[data, vec![0x90, 0x00]].concat());
        let (inner_ea, mut inner) = inner_pending.external_authenticate_form(0x33, &inner_pending.host_cryptogram(), true, true);
        let inner_data = lk_codec::apdu::Command::parse(&inner_ea).unwrap().data.clone();
        let apdu = s.wrap(0x80, 0x82, 0x33, 0x00, &inner_data, Some(0), true);
        let plain = ch.unwrap_command(&apdu).unwrap();
        let (resp, next) = sd.handshake(&plain, &mut host);
        assert_eq!(s.unwrap(&ch.wrap_response(&resp)).unwrap(), (vec![], 0x9000));
        let mut next = next.expect("nested extended EXTERNAL AUTHENTICATE");
        assert_eq!(next.key_version(), 0x31);
        assert_eq!(send_ext(&mut sd, &mut next, &mut host, &mut inner, 0x80, 0xCA, 0x00, 0x66, &[]).1, 0x9000);
    }
}

/// Replays (Amd D §6.2.2: the card challenge is random with `i = 60`, so the session
/// keys and both cryptograms change with every INITIALIZE UPDATE; §6.2.4: the C-MAC
/// chains every command to the previous one):
/// - a recorded EXTERNAL AUTHENTICATE replayed after a new INITIALIZE UPDATE with the
///   same host challenge fails its C-MAC (`6982`); the new INITIALIZE UPDATE used a try
///   and the failure does not restore it;
/// - a recorded EXTERNAL AUTHENTICATE replayed without a new INITIALIZE UPDATE finds no
///   pending handshake (`6985`);
/// - a wrapped command replayed in the same session fails the MAC chain and ends the
///   session; replayed in a new session it fails too.
///
/// No replay changes the stored state beyond the try counter.
#[test]
fn replayed_handshakes_and_commands_are_refused() {
    let (mut sd, mut host) = fresh();
    let challenge = [0x77u8; 8];
    let (iu_resp, _) = sd.handshake(&init_update_apdu(0xFF, &challenge), &mut host);
    let pending = read_init_response(&StaticKeys::DEFAULT, &challenge, &iu_resp);
    let (recorded_ea, mut s) = pending.external_authenticate(0x33);
    let (resp, ch) = sd.handshake(&recorded_ea, &mut host);
    assert_eq!(resp, hex("9000"));
    let mut ch = ch.unwrap();
    let recorded_cmd = s.wrap(0x80, 0xCA, 0x00, 0x66, &[], Some(0), false);
    let resp = device_transmit(&mut sd, &mut ch, &mut host, &recorded_cmd);
    assert_eq!(s.unwrap(&resp).unwrap().1, 0x9000);

    // The same command again in the same session: the MAC chain moved on.
    let before = host.persisted(Record::SecurityDomain);
    assert_eq!(device_transmit(&mut sd, &mut ch, &mut host, &recorded_cmd), hex("6982"));
    assert!(!ch.is_open());
    assert_eq!(host.persisted(Record::SecurityDomain), before);

    // The recorded EXTERNAL AUTHENTICATE without a fresh INITIALIZE UPDATE.
    let (resp, ch) = sd.handshake(&recorded_ea, &mut host);
    assert_eq!((resp, ch.is_none()), (hex("6985"), true));

    // A new INITIALIZE UPDATE with the old host challenge gets a new card challenge.
    let (resp2, _) = sd.handshake(&init_update_apdu(0xFF, &challenge), &mut host);
    assert_ne!(resp2, iu_resp, "a fresh card challenge and cryptogram");
    assert_eq!(sd.remaining_tries(1, 0xFF), Some(63));
    let before = host.persisted(Record::SecurityDomain);
    let (resp, ch) = sd.handshake(&recorded_ea, &mut host);
    assert_eq!((resp, ch.is_none()), (hex("6982"), true));
    assert_eq!(sd.remaining_tries(1, 0xFF), Some(63), "the failed replay restores nothing");
    assert_eq!(host.persisted(Record::SecurityDomain), before);

    // A recorded command in a new session.
    let (_s2, mut ch2) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    assert_eq!(device_transmit(&mut sd, &mut ch2, &mut host, &recorded_cmd), hex("6982"));
    assert!(!ch2.is_open());
}

/// A half-open handshake does not outlive its key set: an INITIALIZE UPDATE answered
/// under a set that is then replaced or deleted (here from an outer session) cannot be
/// completed, so no session is ever opened under keys that are no longer installed
/// (Amd D §7.1.2: EXTERNAL AUTHENTICATE completes the INITIALIZE UPDATE of the current
/// key set; GP 2.3.1 §11.8 / §11.2: PUT KEY and DELETE change the key set).
#[test]
fn key_changes_drop_a_half_open_handshake() {
    for change in ["replace", "delete"] {
        let (mut sd, mut host) = fresh();
        let (mut outer, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
        let first = StaticKeys::from_seed(1);
        let data = outer.put_key_data(0x01, &first);
        assert_eq!(send(&mut sd, &mut ch, &mut host, &mut outer, 0x80, 0xD8, 0x00, 0x81, &data).1, 0x9000);
        let data = outer.put_key_data(0x02, &StaticKeys::from_seed(2));
        assert_eq!(send(&mut sd, &mut ch, &mut host, &mut outer, 0x80, 0xD8, 0x00, 0x81, &data).1, 0x9000);
        // INITIALIZE UPDATE under set 01, in plaintext.
        let challenge = [0x44u8; 8];
        let (resp, _) = sd.handshake(&init_update_apdu(0x01, &challenge), &mut host);
        let pending = read_init_response(&first, &challenge, &resp);
        assert!(pending.card_cryptogram_ok);
        // The outer session changes set 01.
        let sw = match change {
            "replace" => {
                let data = outer.put_key_data(0x01, &StaticKeys::from_seed(9));
                send(&mut sd, &mut ch, &mut host, &mut outer, 0x80, 0xD8, 0x01, 0x81, &data).1
            }
            _ => send(&mut sd, &mut ch, &mut host, &mut outer, 0x80, 0xE4, 0x00, 0x00, &hex("D20101")).1,
        };
        assert_eq!(sw, 0x9000);
        let (apdu, _) = pending.external_authenticate(0x33);
        let (resp, new) = sd.handshake(&apdu, &mut host);
        assert_eq!((resp, new.is_none()), (hex("6985"), true), "{change}");
    }
}

/// yubikit on a short-APDU session (`force_short`, NFC): `ScpProcessor.send_apdu` MACs a
/// command whose protected data exceeds 255 bytes over the extended Lc form, then its
/// command-chaining processor splits the protected command into short parts with CLA
/// b5 (ISO/IEC 7816-4 §5.1.1.1). What `lk-device` must do (`channel.rs` layering note 1):
/// reassemble with `CommandChain`, encode with `Command::to_bytes` (extended form for
/// more than 255 bytes) and unwrap once. Unwrapping the parts one by one fails.
#[test]
fn reassembled_short_chain_of_a_long_protected_command_verifies() {
    let (mut sd, mut host) = fresh();
    let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    let long = vec![0xA5; 400];
    let protected = s.wrap(0x80, 0xCA, 0x00, 0x66, &long, None, true);
    let full = lk_codec::apdu::Command::parse(&protected).unwrap();
    let parts: Vec<Vec<u8>> = full
        .data
        .chunks(255)
        .enumerate()
        .map(|(i, chunk)| {
            let last = (i + 1) * 255 >= full.data.len();
            encode_apdu(if last { 0x84 } else { 0x94 }, 0xCA, 0x00, 0x66, chunk, None, false)
        })
        .collect();
    assert_eq!(parts.len(), 2);

    // Part by part: the first part carries no valid C-MAC of its own.
    let (_s2, mut ch2) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    assert_eq!(ch2.unwrap_command(&parts[0]), Err(0x6982));

    // Reassembled as lk-device does it.
    let mut chain = lk_codec::apdu::CommandChain::new(8192);
    assert!(chain.push(lk_codec::apdu::Command::parse(&parts[0]).unwrap()).unwrap().is_none());
    let assembled = chain.push(lk_codec::apdu::Command::parse(&parts[1]).unwrap()).unwrap().unwrap();
    let plain = ch.unwrap_command(&assembled.to_bytes()).unwrap();
    let cmd = lk_codec::apdu::Command::parse(&plain).unwrap();
    assert_eq!((cmd.cla, cmd.data.clone()), (0x80, long));
    let resp = device_after_unwrap(&mut sd, &mut ch, &mut host, &plain);
    assert_eq!(s.unwrap(&resp).unwrap().1, 0x9000);
}

/// Only `xx A4 04 xx` is SELECT (docs/CONTRACTS.md "Applications A as implemented":
/// `00 A4 00 0x` is OATH CALCULATE ALL, YKOATH, and goes to the selected applet). An
/// encrypted CALCULATE ALL is an ordinary protected command: the session stays open
/// after its response. A plaintext CALCULATE ALL in an open session is a plaintext
/// command like any other: refused before dispatch (`6982`), and the session ends
/// (Yubico yk5-apps-scp), whereas a plaintext SELECT is passed through as the session
/// boundary.
#[test]
fn only_select_by_name_is_a_session_boundary() {
    let (mut sd, mut host) = fresh();
    let (mut s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    let challenge = hex("7406000000000000003B");
    let apdu = s.wrap(0x00, 0xA4, 0x00, 0x01, &challenge, Some(0), false);
    let plain = ch.unwrap_command(&apdu).unwrap();
    assert_eq!(&plain[..4], &[0x00, 0xA4, 0x00, 0x01]);
    let (data, sw) = s.unwrap(&ch.wrap_response(&hex("7103AABBCC9000"))).unwrap();
    assert_eq!((data, sw), (hex("7103AABBCC"), 0x9000));
    assert!(ch.is_open(), "CALCULATE ALL does not end the session");
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut s, 0x80, 0xCA, 0x00, 0x66, &[]).1, 0x9000);

    let plaintext_calculate_all = encode_apdu(0x00, 0xA4, 0x00, 0x01, &challenge, None, false);
    assert_eq!(ch.unwrap_command(&plaintext_calculate_all), Err(0x6982));
    assert!(!ch.is_open());

    let (_s, mut ch) = open(&mut sd, &mut host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    let select = hex("00A4040007A0000005272101");
    assert_eq!(ch.unwrap_command(&select), Ok(select.clone()));
    assert!(!ch.is_open());
}
