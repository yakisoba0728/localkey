//! The request shapes the public OATH host software sends, byte for byte, and the
//! status words it interprets.
//!
//! Sources (public host code, read for their APDU encoding and status handling):
//!
//! - yubikit (Python, `yubikit/oath.py` and `yubikit/core/smartcard/__init__.py`, used
//!   by ykman and by the Yubico Authenticator desktop helper):
//!   - `SmartCardProtocol.configure` switches to the extended APDU format on USB.
//!     `ExtendedApduFormatter` adds no Le when Le is 0, so data-less commands are the
//!     4-byte case 1 and commands with data are case 3E (`00 Lc Lc`).
//!   - `ShortApduFormatter` (NFC or `force_short`) appends a `00` byte to a command
//!     without data or Le (case 2S, Ne 256).
//!   - `61xx` is followed with `send_apdu(0, INS_SEND_REMAINING, 0, 0, b"", 0)`.
//!   - `OathSession`: CALCULATE ALL `00 A4 00 01` with an 8-byte time step;
//!     `calculate_code` P2 `01` with `74 00` for HOTP; `calculate` P2 `00`;
//!     `put_credential` pads the secret to 14 bytes, writes the touch property as the
//!     raw pair `78 02` and the IMF only for a counter above 0; `set_key` sends
//!     `73 (21 || key) 74 challenge 75 HMAC-SHA1` and keeps the session (it re-selects
//!     and validates only on the NEO); `unset_key` sends `73 00`; `reset` sends
//!     `00 04 DE AD` and re-selects; `device_id = base64(SHA-256(salt)[..16])`;
//!     `calculate_all` infers HOTP only from tag `77`.
//! - yubikit-android `OathSession.java`: the same commands, except that
//!   `calculateCode` sends an 8-byte all-zero challenge for HOTP and `putCredential`
//!   writes the IMF as `7A 04` for HOTP only.
//! - ykman `ykman/_cli/oath.py`: `6A80` after VALIDATE is "Wrong password?", `6982`
//!   from a touch CALCULATE is "Touch account timed out!", `6A84` from PUT is "No space
//!   left". Remembered passwords are keyed by `device_id`.
//! - Yubico Authenticator `helper/helper/oath.py`: `6982` means "authentication
//!   required" (or a touch timeout after 5 s), `6A80` from VALIDATE means a wrong
//!   password, `6A80` from PUT or RENAME is reported as "Issuer/name too long".

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use lk_core::{CardApplet, Outcome};
use lk_oath::AID;

/// yubikit `ExtendedApduFormatter.format_apdu`: `00 Lc(2) data` when there is data,
/// then Le as two bytes (with a leading `00` if there was no data) only when Le is
/// nonzero.
fn ext(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: u16) -> Vec<u8> {
    let mut out = vec![cla, ins, p1, p2];
    if !data.is_empty() {
        out.push(0);
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
    }
    if le != 0 {
        if data.is_empty() {
            out.push(0);
        }
        out.extend_from_slice(&le.to_be_bytes());
    }
    out
}

/// yubikit `ShortApduFormatter.format_apdu`: `Lc data` when there is data, then Le,
/// or a single `00` when there is neither data nor Le.
fn short(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: u8) -> Vec<u8> {
    let mut out = vec![cla, ins, p1, p2];
    if !data.is_empty() {
        out.push(data.len() as u8);
        out.extend_from_slice(data);
    }
    if le != 0 || data.is_empty() {
        out.push(le);
    }
    out
}

/// yubikit/yubikit-android `device_id`: the first 16 bytes of SHA-256 over the salt
/// (before base64).
fn device_id(salt: &[u8]) -> Vec<u8> {
    lk_crypto::sha256(salt)[..16].to_vec()
}

/// yubikit `put_credential` data: `71` name, `73` type|alg, digits and the secret
/// zero-padded to 14 bytes, the raw touch pair `78 02`, `7A` IMF only for a counter
/// above 0.
fn yubikit_put(name: &[u8], type_alg: u8, digits: u8, secret: &[u8], touch: bool, counter: u32) -> Vec<u8> {
    let mut secret = secret.to_vec();
    if secret.len() < 14 {
        secret.resize(14, 0);
    }
    put_data(name, type_alg, digits, &secret, touch.then_some(0x02), (counter > 0).then_some(counter))
}

/// The SELECT a yubikit session sends over USB (`00 A4 04 00`, extended format).
fn yubikit_select(card: &mut Card) -> Vec<(u8, Vec<u8>)> {
    let resp = card.oath.select(&ext(0x00, 0xA4, 0x04, 0x00, AID, 0), &mut card.host);
    let (data, sw) = split(&resp);
    assert_eq!(sw, OK);
    parse_tlvs(data)
}

/// Send and follow `61xx` with yubikit's continuation, encoded by `continuation`.
fn exchange(card: &mut Card, apdu: &[u8], continuation: &[u8]) -> (Vec<u8>, u16) {
    let mut resp = card.send(apdu);
    let mut data = Vec::new();
    loop {
        let (chunk, sw) = split(&resp);
        assert!(chunk.len() <= 256, "a piece longer than Ne 256");
        data.extend_from_slice(chunk);
        if sw >> 8 != 0x61 {
            return (data, sw);
        }
        resp = card.send(continuation);
    }
}

/// RFC 4226 §5.3 truncation of an independent HMAC, reduced to `digits`.
fn expected_code(alg: lk_crypto::HashAlg, key: &[u8], message: &[u8], digits: u32) -> u32 {
    let mac = lk_crypto::hmac(alg, key, message);
    let o = usize::from(mac[mac.len() - 1] & 0x0F);
    u32::from_be_bytes([mac[o] & 0x7F, mac[o + 1], mac[o + 2], mac[o + 3]]) % 10u32.pow(digits)
}

/// A whole ykman / Yubico Authenticator session through yubikit over USB, in the
/// extended APDU format yubikit uses there.
#[test]
fn yubikit_usb_session_in_extended_format() {
    let mut card = Card::new();
    let send_remaining = ext(0x00, 0xA5, 0x00, 0x00, &[], 0);
    assert_eq!(send_remaining, [0x00, 0xA5, 0x00, 0x00]);

    // OathSession(): version, salt, no challenge (not locked).
    let fields = yubikit_select(&mut card);
    let salt = field(&fields, 0x71).unwrap();
    assert_eq!(salt.len(), 8);
    assert_eq!(field(&fields, 0x74), None);

    // ykman `oath accounts add`: a 10-byte TOTP secret, an HOTP account with counter 5,
    // a touch TOTP account with a 60 s period (cred id "60/...").
    let totp_secret = b"0123456789";
    for (name, type_alg, digits, secret, touch, counter) in [
        (&b"Example:alice@example.com"[..], TOTP | SHA1, 6u8, &totp_secret[..], false, 0u32),
        (b"hotp-account", HOTP | SHA1, 6, RFC_SECRET, false, 5),
        (b"60/Issuer:bob", TOTP | SHA256, 8, &[0x5A; 32], true, 0),
    ] {
        let put = ext(0x00, 0x01, 0x00, 0x00, &yubikit_put(name, type_alg, digits, secret, touch, counter), 0);
        assert_eq!(card.send(&put), vec![0x90, 0x00]);
    }

    // list_credentials: `00 A1 00 00`, one `72` (type|alg, id) per credential.
    let (data, sw) = exchange(&mut card, &ext(0x00, 0xA1, 0x00, 0x00, &[], 0), &send_remaining);
    assert_eq!(sw, OK);
    let listed: Vec<(u8, Vec<u8>)> = parse_tlvs(&data)
        .into_iter()
        .map(|(tag, v)| {
            assert_eq!(tag, 0x72);
            (v[0], v[1..].to_vec())
        })
        .collect();
    assert_eq!(
        listed,
        vec![
            (0x21, b"Example:alice@example.com".to_vec()),
            (0x11, b"hotp-account".to_vec()),
            (0x22, b"60/Issuer:bob".to_vec()),
        ]
    );

    // calculate_all at timestamp 1_111_111_109: challenge = timestamp // 30 as 8 bytes.
    let step = (1_111_111_109u64 / 30).to_be_bytes();
    let (data, sw) = exchange(&mut card, &ext(0x00, 0xA4, 0x00, 0x01, &tlv(0x74, &step), 0), &send_remaining);
    assert_eq!(sw, OK);
    let fields = parse_tlvs(&data);
    let tags: Vec<u8> = fields.iter().map(|f| f.0).collect();
    // yubikit: `oath_type = HOTP if resp_tag == TAG_HOTP else TOTP`, `touch = resp_tag ==
    // TAG_TOUCH`, and only `76` carries a code.
    assert_eq!(tags, vec![0x71, 0x76, 0x71, 0x77, 0x71, 0x7C]);
    let mut padded = totp_secret.to_vec();
    padded.resize(14, 0);
    assert_eq!(code_of(&fields[1].1), expected_code(lk_crypto::HashAlg::Sha1, totp_secret, &step, 6));
    assert_eq!(code_of(&fields[1].1), expected_code(lk_crypto::HashAlg::Sha1, &padded, &step, 6));
    assert_eq!(fields[3].1, vec![6]);
    assert_eq!(fields[5].1, vec![8]);

    // calculate_code for HOTP: P2 01, `71 id 74 00`. The IMF made the first counter 5
    // (RFC 4226 Appendix D: 254676).
    let calc_hotp = ext(0x00, 0xA2, 0x00, 0x01, &[tlv(0x71, b"hotp-account"), tlv(0x74, &[])].concat(), 0);
    assert_eq!(code_of(&expect_object(&card.send(&calc_hotp), 0x76).unwrap()), 254_676);

    // calculate_code for the touch account: the period-60 time step, then a touch.
    let step60 = (1_111_111_109u64 / 60).to_be_bytes();
    let calc_touch = ext(0x00, 0xA2, 0x00, 0x01, &[tlv(0x71, b"60/Issuer:bob"), tlv(0x74, &step60)].concat(), 0);
    assert!(matches!(card.outcome(&calc_touch), Outcome::NeedTouch { .. }));
    let value = expect_object(&card.touch(true), 0x76).unwrap();
    assert_eq!(code_of(&value), expected_code(lk_crypto::HashAlg::Sha256, &[0x5A; 32], &step60, 8));

    // calculate (raw HMAC): P2 00, `75 digits || HMAC`, yubikit returns `resp[1:]`.
    let calc_raw = ext(0x00, 0xA2, 0x00, 0x00, &[tlv(0x71, b"Example:alice@example.com"), tlv(0x74, b"raw")].concat(), 0);
    let value = expect_object(&card.send(&calc_raw), 0x75).unwrap();
    assert_eq!(value[1..], lk_crypto::hmac_sha1(totp_secret, b"raw")[..]);

    // rename_credential (firmware 5.3.1+) and delete_credential.
    let rename = ext(0x00, 0x05, 0x00, 0x00, &[tlv(0x71, b"hotp-account"), tlv(0x71, b"Issuer:hotp")].concat(), 0);
    assert_eq!(card.send(&rename), vec![0x90, 0x00]);
    let delete = ext(0x00, 0x02, 0x00, 0x00, &tlv(0x71, b"Issuer:hotp"), 0);
    assert_eq!(card.send(&delete), vec![0x90, 0x00]);
    assert_eq!(card.names(), vec![b"Example:alice@example.com".to_vec(), b"60/Issuer:bob".to_vec()]);

    // set_key: derive_key = PBKDF2-HMAC-SHA1(password, salt, 1000, 16). The session
    // keeps working without a new SELECT (yubikit re-selects only on the NEO).
    let key = pbkdf2_hmac_sha1(b"hunter2", &salt, 1000, 16);
    let challenge = [0xC3; 8];
    let set_key = [
        tlv(0x73, &[&[TOTP | SHA1][..], &key].concat()),
        tlv(0x74, &challenge),
        tlv(0x75, &lk_crypto::hmac_sha1(&key, &challenge)),
    ]
    .concat();
    assert_eq!(card.send(&ext(0x00, 0x03, 0x00, 0x00, &set_key, 0)), vec![0x90, 0x00]);
    assert_eq!(card.sw(&ext(0x00, 0xA1, 0x00, 0x00, &[], 0)), OK);

    // A new session is locked: SELECT carries `74` and `7B 01`; LIST is `6982`.
    let fields = yubikit_select(&mut card);
    assert_eq!(field(&fields, 0x71), Some(salt.clone()), "the device id is unchanged");
    assert_eq!(field(&fields, 0x7B), Some(vec![0x01]));
    let device_challenge = field(&fields, 0x74).unwrap();
    assert_eq!(card.sw(&ext(0x00, 0xA1, 0x00, 0x00, &[], 0)), 0x6982);

    // validate with a wrong password: 6A80 (ykman "Wrong password?").
    let wrong = pbkdf2_hmac_sha1(b"hunter3", &salt, 1000, 16);
    let host_challenge = [0x17; 8];
    let validate = |key: &[u8]| {
        let data = [tlv(0x75, &lk_crypto::hmac_sha1(key, &device_challenge)), tlv(0x74, &host_challenge)].concat();
        ext(0x00, 0xA3, 0x00, 0x00, &data, 0)
    };
    assert_eq!(card.send(&validate(&wrong)), vec![0x6A, 0x80]);
    // The right one: yubikit compares the `75` answer with HMAC(key, its challenge).
    let answer = expect_object(&card.send(&validate(&key)), 0x75).unwrap();
    assert_eq!(answer, lk_crypto::hmac_sha1(&key, &host_challenge).to_vec());
    assert_eq!(card.list().len(), 2);

    // unset_key: `73 00`; the next session has no challenge.
    assert_eq!(card.send(&ext(0x00, 0x03, 0x00, 0x00, &tlv(0x73, &[]), 0)), vec![0x90, 0x00]);
    assert_eq!(field(&yubikit_select(&mut card), 0x74), None);

    // reset: `00 04 DE AD`, then yubikit re-selects and recomputes device_id.
    let reset = ext(0x00, 0x04, 0xDE, 0xAD, &[], 0);
    assert_eq!(reset, [0x00, 0x04, 0xDE, 0xAD]);
    assert_eq!(card.send(&reset), vec![0x90, 0x00]);
    let new_salt = field(&yubikit_select(&mut card), 0x71).unwrap();
    assert_ne!(device_id(&new_salt), device_id(&salt));
    assert!(card.list().is_empty());
}

/// yubikit over USB sends no Le, so a long LIST or CALCULATE ALL comes back in pieces
/// of 256 bytes with `61xx`, fetched with the 4-byte SEND REMAINING `00 A5 00 00`.
/// 64 credentials with 64-byte names (the capacity and the longest name).
#[test]
fn yubikit_extended_long_responses_continue_with_send_remaining() {
    let mut card = Card::new();
    for i in 0..64u8 {
        let name: Vec<u8> = std::iter::repeat_n(b'x', 63).chain([i]).collect();
        let put = ext(0x00, 0x01, 0x00, 0x00, &yubikit_put(&name, TOTP | SHA1, 6, b"secret", false, 0), 0);
        assert_eq!(card.sw(&put), OK, "credential {i}");
    }
    let send_remaining = ext(0x00, 0xA5, 0x00, 0x00, &[], 0);
    let first = card.send(&ext(0x00, 0xA1, 0x00, 0x00, &[], 0));
    assert_eq!(first.len(), 256 + 2);
    assert_eq!(first[256], 0x61);
    let (data, sw) = exchange(&mut card, &ext(0x00, 0xA1, 0x00, 0x00, &[], 0), &send_remaining);
    assert_eq!(sw, OK);
    assert_eq!(parse_tlvs(&data).len(), 64);
    let step = 1u64.to_be_bytes();
    let (data, sw) = exchange(&mut card, &ext(0x00, 0xA4, 0x00, 0x01, &tlv(0x74, &step), 0), &send_remaining);
    assert_eq!(sw, OK);
    let fields = parse_tlvs(&data);
    assert_eq!(fields.len(), 128);
    assert!(fields.iter().skip(1).step_by(2).all(|(tag, v)| *tag == 0x76 && v.len() == 5));
}

/// yubikit in the short format (NFC, or `force_short`): commands without data carry a
/// `00` byte (case 2S, Ne 256), including SEND REMAINING and RESET. The LIST is the
/// catalog's "YubiKit 504-byte list continuation": eight 63-byte entries, served as
/// 256 bytes with `61 F8` and then the remaining 248.
#[test]
fn yubikit_short_format_dataless_commands() {
    let mut card = Card::new();
    for i in 0..8u8 {
        let name: Vec<u8> = std::iter::repeat_n(b's', 59).chain([i]).collect();
        let put = short(0x00, 0x01, 0x00, 0x00, &yubikit_put(&name, HOTP | SHA1, 6, RFC_SECRET, false, 0), 0);
        assert_eq!(card.sw(&put), OK);
    }
    let list = short(0x00, 0xA1, 0x00, 0x00, &[], 0);
    assert_eq!(list, [0x00, 0xA1, 0x00, 0x00, 0x00]);
    let send_remaining = short(0x00, 0xA5, 0x00, 0x00, &[], 0);
    assert_eq!(send_remaining, [0x00, 0xA5, 0x00, 0x00, 0x00]);
    let first = card.send(&list);
    assert_eq!(first.len(), 256 + 2);
    assert_eq!(&first[256..], &[0x61, 0xF8]);
    let second = card.send(&send_remaining);
    assert_eq!(second.len(), 248 + 2);
    assert_eq!(&second[248..], &[0x90, 0x00]);
    let (data, sw) = exchange(&mut card, &list, &send_remaining);
    assert_eq!(sw, OK);
    assert_eq!(data.len(), 504);
    assert_eq!(parse_tlvs(&data).len(), 8);
    let calc_all = short(0x00, 0xA4, 0x00, 0x01, &tlv(0x74, &[0; 8]), 0);
    let (data, sw) = exchange(&mut card, &calc_all, &send_remaining);
    assert_eq!(sw, OK);
    assert_eq!(parse_tlvs(&data).len(), 16);
    let reset = short(0x00, 0x04, 0xDE, 0xAD, &[], 0);
    assert_eq!(reset, [0x00, 0x04, 0xDE, 0xAD, 0x00]);
    assert_eq!(card.send(&reset), vec![0x90, 0x00]);
    assert!(card.list().is_empty());
}

/// `docs/CONTRACTS.md` "APDU conventions": the extended data-less form
/// `CLA INS P1 P2 00 00 00` (Ne 65536) is accepted where commands take no data. With
/// that Ne the whole LIST comes in one response.
#[test]
fn extended_dataless_form_is_accepted() {
    let mut card = Card::new();
    for i in 0..20u8 {
        let name: Vec<u8> = std::iter::repeat_n(b'e', 60).chain([i]).collect();
        assert_eq!(card.put(&put_data(&name, TOTP | SHA1, 6, RFC_SECRET, None, None)), OK);
    }
    let resp = card.send(&[0x00, 0xA1, 0x00, 0x00, 0x00, 0x00, 0x00]);
    let (data, sw) = split(&resp);
    assert_eq!(sw, OK);
    assert_eq!(parse_tlvs(data).len(), 20);
    // SEND REMAINING in the same form, after a LIST cut by a small Le.
    let first = card.send(&[0x00, 0xA1, 0x00, 0x00, 0x10]);
    assert_eq!(first[0x10], 0x61);
    let rest = card.send(&[0x00, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00]);
    let (tail, sw) = split(&rest);
    assert_eq!(sw, OK);
    assert_eq!(0x10 + tail.len(), 20 * 64);
    assert_eq!(card.send(&[0x00, 0x04, 0xDE, 0xAD, 0x00, 0x00, 0x00]), vec![0x90, 0x00]);
    assert!(card.list().is_empty());
}

/// yubikit-android: `calculateCode` sends an 8-byte all-zero challenge for HOTP (the
/// HOTP challenge is ignored, RFC 4226 §5.2 uses the counter), `putCredential` writes
/// the IMF as `7A 04` for HOTP, `setAccessKey` takes exactly 16 bytes, and
/// `deleteAccessKey` sends `73 00`.
#[test]
fn yubikit_android_shapes() {
    let mut card = Card::new();
    let salt = card.salt();
    assert_eq!(card.put(&yubikit_put(b"h", HOTP | SHA1, 6, RFC_SECRET, false, 3)), OK);
    let calc = |p2: u8| apdu(0x00, 0xA2, 0x00, p2, &[tlv(0x71, b"h"), tlv(0x74, &[0; 8])].concat());
    // RFC 4226 Appendix D, counters 3 and 4.
    assert_eq!(code_of(&expect_object(&card.send(&calc(1)), 0x76).unwrap()), 969_429);
    let full = expect_object(&card.send(&calc(0)), 0x75).unwrap();
    assert_eq!(full[1..], hex("a904c900a64b35909874b33e61c5938a8e15ed1c")[..]);

    let key = pbkdf2_hmac_sha1(b"android", &salt, 1000, 16);
    assert_eq!(key.len(), 16);
    assert_eq!(card.sw(&set_code_apdu(&key, &[0x42; 8])), OK);
    let fields = card.select_fields();
    let challenge = field(&fields, 0x74).unwrap();
    assert_eq!(card.sw(&validate_apdu(&lk_crypto::hmac_sha1(&key, &challenge), &[9; 8])), OK);
    assert_eq!(card.sw(&apdu(0x00, 0x03, 0x00, 0x00, &[0x73, 0x00])), OK);
    assert_eq!(card.select_fields().len(), 2);
}

/// The status words the hosts interpret (sources in the module documentation).
#[test]
fn status_words_the_hosts_interpret() {
    let mut card = Card::new();
    // Authenticator: 6A80 from PUT or RENAME is "Issuer/name too long".
    assert_eq!(card.put(&yubikit_put(&[b'n'; 65], TOTP | SHA1, 6, b"k", false, 0)), 0x6A80);
    assert_eq!(card.put(&yubikit_put(b"n", TOTP | SHA1, 6, b"k", true, 0)), OK);
    assert_eq!(card.sw(&rename_apdu(b"n", &[b'm'; 65])), 0x6A80);
    // ykman: 6982 from a touch CALCULATE is "Touch account timed out!".
    assert!(matches!(card.outcome(&calculate_apdu(b"n", &[0; 8], true)), Outcome::NeedTouch { .. }));
    assert_eq!(card.touch(false), vec![0x69, 0x82]);
    // ykman: 6A84 from PUT is "No space left on the YubiKey for OATH accounts".
    for i in 1..64u8 {
        assert_eq!(card.put(&yubikit_put(&[b'c', i], TOTP | SHA1, 6, b"k", false, 0)), OK);
    }
    assert_eq!(card.put(&yubikit_put(b"65th", TOTP | SHA1, 6, b"k", false, 0)), 0x6A84);
    // Authenticator: 6982 from any credential command means "authentication required";
    // ykman, Authenticator and yubikit-android: 6A80 from VALIDATE is a wrong password.
    let salt = card.salt();
    let key = pbkdf2_hmac_sha1(b"pw", &salt, 1000, 16);
    assert_eq!(card.sw(&set_code_apdu(&key, &[1; 8])), OK);
    let challenge = field(&card.select_fields(), 0x74).unwrap();
    assert_eq!(card.sw(&calculate_all_apdu(&[0; 8], true)), 0x6982);
    assert_eq!(card.sw(&validate_apdu(&lk_crypto::hmac_sha1(&[0; 16], &challenge), &[2; 8])), 0x6A80);
    assert_eq!(card.sw(&validate_apdu(&lk_crypto::hmac_sha1(&key, &challenge), &[2; 8])), OK);
}

/// ykman `oath access remember` and Yubico Authenticator store the derived key under
/// `device_id = SHA-256(salt)[..16]`, so the id must not change across restarts, also
/// when no command has changed anything yet; RESET gives a new id that is stable too.
#[test]
fn device_id_is_stable_across_restarts() {
    let mut card = Card::new();
    let id = device_id(&card.salt());
    for _ in 0..3 {
        card.restart();
        assert_eq!(device_id(&card.salt()), id);
    }
    assert_eq!(card.sw(&[0x00, 0x04, 0xDE, 0xAD]), OK);
    let new_id = device_id(&card.salt());
    assert_ne!(new_id, id);
    card.restart();
    assert_eq!(device_id(&card.salt()), new_id);
}
