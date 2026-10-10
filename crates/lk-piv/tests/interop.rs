//! Second independent review: request sequences exactly as the named host software
//! encodes them. Each test cites the host source it reproduces.
//!
//! - python yubikit (`yubikit/piv.py`, `yubikit/core/smartcard/__init__.py`, yubikey-manager
//!   main branch): `PivSession.reset()` first calls `get_bio_metadata()` (GET METADATA
//!   P2 `96`, where only `6A88` or `6D00` mean "no biometrics"), then blocks the PIN with
//!   `verify_pin("")` and the PUK with `_change_reference(INS_RESET_RETRY, PIN_P2, "",
//!   "")`; `_pin_bytes("")` is eight `FF` bytes, and `_retries_from_sw` must find `63CX`
//!   or `6983` in every answer, or the reset aborts with `ApduError`. `ykman piv info`
//!   calls `get_bio_metadata()` the same way. Over USB yubikit uses the extended APDU
//!   formatter, which sends a data-less command as the four header bytes.
//! - yubico-piv-tool (`lib/ykpiv.c`, `_ykpiv_transfer_data`, "Add Le for T=1"): on T=1
//!   every command that carries data gets a trailing `Le = 00`, each 255-byte chained part
//!   included, and a data-less command is sent as `CLA INS P1 P2 00`. The YubiKey CCID
//!   interface is T=1.
//! - OpenSC (`src/libopensc/card-piv.c`, shared by the PKCS#11 module and the
//!   minidriver): `piv_general_io` sends case 4 with Le `00` when it reads a response and
//!   case 3 otherwise, chains 255-byte parts with Le only on the last one, and follows
//!   `61xx` with `00 C0 00 00 SW2`; PIN status and logout are case 1 VERIFY commands;
//!   mutual authentication step 2 carries `82 00` (SP 800-73-4 Table 19), external
//!   authentication answers as case 3, and ECDH uses tag `85`.
//! - macOS CryptoTokenKit (`TKSmartCard` with `useExtendedLength`): one extended command
//!   with Le `0000` instead of a chain, and the whole answer at once.

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use lk_codec::tlv;
use lk_core::Record;

/// yubikit `_retries_from_sw` (SW `6983` is 0, `63CX` is X); `None` makes yubikit raise
/// `ApduError` out of `reset()`.
fn retries_from_sw(sw: u16) -> Option<u8> {
    if sw == 0x6983 {
        Some(0)
    } else if sw & 0xFFF0 == 0x63C0 {
        Some((sw & 0x0F) as u8)
    } else {
        None
    }
}

/// yubikit's `ExtendedApduFormatter` (USB) or `ShortApduFormatter` (NFC, `force_short`)
/// for a command without Le.
fn yubikit_apdu(extended: bool, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x00, ins, p1, p2];
    if extended {
        if !data.is_empty() {
            out.push(0x00);
            out.extend_from_slice(&(data.len() as u16).to_be_bytes());
            out.extend_from_slice(data);
        }
    } else if data.is_empty() {
        out.push(0x00);
    } else {
        out.push(data.len() as u8);
        out.extend_from_slice(data);
    }
    out
}

/// The retries remaining (second byte of tag `06`) in a PIN or PUK metadata answer.
fn remaining_from_metadata(data: &[u8]) -> u8 {
    let items = tlv::parse_all(data).unwrap();
    tlv::find(&items, 0x06).unwrap().value[1]
}

/// `PivSession.reset()` step by step, failing where yubikit would raise.
fn yubikit_reset(card: &mut Card, extended: bool) {
    // get_bio_metadata(): NotSupportedError only for 6A88 or 6D00.
    let (_, sw) = card.raw(&yubikit_apdu(extended, 0xF7, 0x00, 0x96, &[]));
    assert!(sw == 0x6A88 || sw == 0x6D00, "get_bio_metadata would raise ApduError on {sw:04X}");
    // get_pin_attempts() through get_pin_metadata().
    let (md, sw) = card.raw(&yubikit_apdu(extended, 0xF7, 0x00, 0x80, &[]));
    assert_eq!(sw, 0x9000);
    let mut counter = remaining_from_metadata(&md);
    let mut sent = 0;
    while counter > 0 {
        let (_, sw) = card.raw(&yubikit_apdu(extended, 0x20, 0x00, 0x80, &[0xFF; 8]));
        counter = retries_from_sw(sw).unwrap_or_else(|| panic!("verify_pin(\"\") would raise ApduError on {sw:04X}"));
        sent += 1;
        assert!(sent <= 255, "the PIN never blocks");
    }
    // get_puk_metadata().
    let (md, sw) = card.raw(&yubikit_apdu(extended, 0xF7, 0x00, 0x81, &[]));
    assert_eq!(sw, 0x9000);
    let mut counter = remaining_from_metadata(&md);
    let mut sent = 0;
    while counter > 0 {
        let (_, sw) = card.raw(&yubikit_apdu(extended, 0x2C, 0x00, 0x80, &[0xFF; 16]));
        counter = retries_from_sw(sw)
            .unwrap_or_else(|| panic!("_change_reference(INS_RESET_RETRY, ..) would raise ApduError on {sw:04X}"));
        sent += 1;
        assert!(sent <= 255, "the PUK never blocks");
    }
    assert_eq!(card.raw(&yubikit_apdu(extended, 0xFB, 0x00, 0x00, &[])).1, 0x9000, "INS_RESET");
    // Update management key type: get_management_key_metadata().
    let (md, sw) = card.raw(&yubikit_apdu(extended, 0xF7, 0x00, 0x9B, &[]));
    assert_eq!((md, sw), (hex("01010A 02020001 050101"), 0x9000));
}

#[test]
fn yubikit_reset_sequence_completes() {
    for extended in [true, false] {
        let mut card = Card::new();
        card.auth_default();
        card.generate(0x9A, P256, None, None);
        assert_eq!(card.put_object(0x5FC105, &[0x70, 0x01, 0x00]), 0x9000);
        let f9 = card.slot_info(0xF9).unwrap();
        // A PUK retry limit other than the default, so the loops follow the counters.
        card.verify_default_pin();
        assert_eq!(card.send("00FA0306").1, 0x9000);
        yubikit_reset(&mut card, extended);
        // Factory credentials, keys and objects erased, own attestation key kept.
        assert_eq!(card.metadata(0x80).0, hex("0101FF 050101 06020303"));
        assert_eq!(card.metadata(0x81).0, hex("0101FF 050101 06020303"));
        card.verify_default_pin();
        card.auth_default();
        assert_eq!(card.slot_info(0x9A), None);
        assert_eq!(card.get_object(0x5FC105).1, 0x6A82);
        assert_eq!(card.slot_info(0xF9), Some(f9));
    }
}

#[test]
fn bio_metadata_probe_reports_no_reference_data() {
    // `ykman piv info` (ykman/piv.py `get_piv_info`) calls get_bio_metadata() and lets
    // any status other than 6A88/6D00 escape. SP 800-73-4 Part 1 Table 4 defines `96`
    // and `97` as the on-card biometric comparison references, which this card does not
    // hold: 6A88 like an empty key slot, for every encoding of the request.
    let mut card = Card::new();
    for apdu in ["00F70096", "00F7009600", "00F70096000000", "00F70097"] {
        assert_eq!(card.send(apdu), (Vec::new(), 0x6A88), "{apdu}");
    }
    // A reference the specification does not define stays 6A86.
    assert_eq!(card.send("00F70001").1, 0x6A86);
}

/// libykpiv `_ykpiv_transfer_data` on T=1: 255-byte parts with CLA `10`, every part
/// that carries data followed by `Le = 00`.
fn ykpiv_t1(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<Vec<u8>> {
    if data.is_empty() {
        return vec![vec![0x00, ins, p1, p2, 0x00]];
    }
    let parts: Vec<&[u8]> = data.chunks(255).collect();
    let last = parts.len() - 1;
    parts
        .iter()
        .enumerate()
        .map(|(i, part)| {
            let cla = if i == last { 0x00 } else { 0x10 };
            let mut out = vec![cla, ins, p1, p2, part.len() as u8];
            out.extend_from_slice(part);
            out.push(0x00);
            out
        })
        .collect()
}

/// Send a libykpiv request and follow `61xx` the way libykpiv does
/// (`00 C0 00 00 SW2`).
fn ykpiv_send(card: &mut Card, ins: u8, p1: u8, p2: u8, data: &[u8]) -> (Vec<u8>, u16) {
    let apdus = ykpiv_t1(ins, p1, p2, data);
    let (last, init) = apdus.split_last().unwrap();
    for part in init {
        assert_eq!(card.raw(part), (Vec::new(), 0x9000), "intermediate part {part:02X?}");
    }
    let (mut out, mut sw) = card.raw(last);
    while sw >> 8 == 0x61 {
        let (more, next) = card.raw(&[0x00, 0xC0, 0x00, 0x00, (sw & 0xFF) as u8]);
        out.extend(more);
        sw = next;
    }
    (out, sw)
}

#[test]
fn yubico_piv_tool_t1_requests_are_accepted() {
    let mut card = Card::new();
    let key = hex(DEFAULT_MGMT_KEY);
    // verify-pin, then the status query and logout as libykpiv sends them.
    assert_eq!(ykpiv_send(&mut card, 0x20, 0x00, 0x80, &hex(DEFAULT_PIN)).1, 0x9000);
    assert_eq!(card.send("0020008000").1, 0x9000);
    assert_eq!(card.send("0020FF8000").1, 0x9000);
    assert_eq!(card.send("0020008000").1, 0x63C3);
    // ykpiv_authenticate2: mutual authentication, Le 00 on both steps.
    let (resp, sw) = ykpiv_send(&mut card, 0x87, ALG_AES192, 0x9B, &hex("7C028000"));
    assert_eq!(sw, 0x9000);
    let witness = decrypt(ALG_AES192, &key, &dyn_auth_item(&resp, 0x80));
    let challenge = [0x42u8; 16];
    let mut inner = tlv::encode(0x80, &witness);
    tlv::encode_into(&mut inner, 0x81, &challenge);
    let (resp, sw) = ykpiv_send(&mut card, 0x87, ALG_AES192, 0x9B, &tlv::encode(0x7C, &inner));
    assert_eq!(sw, 0x9000);
    assert_eq!(dyn_auth_item(&resp, 0x82), encrypt(ALG_AES192, &key, &challenge));
    // write-object: a chained PUT DATA, Le 00 on every part; read it back.
    let value: Vec<u8> = (0..600u32).map(|i| i as u8).collect();
    let payload = Card::put_payload(0x5FC105, &value);
    assert!(payload.len() > 510, "three parts");
    assert_eq!(ykpiv_send(&mut card, 0xDB, 0x3F, 0xFF, &payload).1, 0x9000);
    let (data, sw) = ykpiv_send(&mut card, 0xCB, 0x3F, 0xFF, &hex("5C035FC105"));
    assert_eq!(sw, 0x9000);
    assert_eq!(data, tlv::encode(0x53, &value));
    // import-key (P-256 with policies) and generate (P-256 in 9C).
    let scalar = hex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
    let mut import = tlv::encode(0x06, &scalar);
    import.extend(hex("AA0101 AB0101"));
    assert_eq!(ykpiv_send(&mut card, 0xFE, P256, 0x9A, &import).1, 0x9000);
    let (data, sw) = ykpiv_send(&mut card, 0x47, 0x00, 0x9C, &generate_template(P256, None, None));
    assert_eq!(sw, 0x9000);
    let public = parse_public_template(&data);
    // Sign with the PIN-always key: verify-pin immediately before, as yubico-piv-tool does.
    let digest = [0x5Au8; 32];
    assert_eq!(ykpiv_send(&mut card, 0x20, 0x00, 0x80, &hex(DEFAULT_PIN)).1, 0x9000);
    let mut inner = tlv::encode(0x82, &[]);
    tlv::encode_into(&mut inner, 0x81, &digest);
    let (resp, sw) = ykpiv_send(&mut card, 0x87, P256, 0x9C, &tlv::encode(0x7C, &inner));
    assert_eq!(sw, 0x9000);
    assert!(ecdsa_ok(P256, public.point(), &digest, &dyn_auth_item(&resp, 0x82)));
    // attest, metadata and move (data-less: CLA INS P1 P2 00).
    let (cert, sw) = ykpiv_send(&mut card, 0xF9, 0x9C, 0x00, &[]);
    assert_eq!((cert.first(), sw), (Some(&0x30), 0x9000));
    assert_eq!(ykpiv_send(&mut card, 0xF7, 0x00, 0x9A, &[]).1, 0x9000);
    assert_eq!(ykpiv_send(&mut card, 0xF6, 0x82, 0x9A, &[]).1, 0x9000);
    assert_eq!(card.slot_info(0x82).unwrap().origin, 0x02, "moved, still imported");
    // change-pin, change-puk, unblock-pin.
    let new_pin = pad(b"864213");
    let mut data = hex(DEFAULT_PIN);
    data.extend_from_slice(&new_pin);
    assert_eq!(ykpiv_send(&mut card, 0x24, 0x00, 0x80, &data).1, 0x9000);
    let new_puk = pad(b"97531864");
    let mut data = hex(DEFAULT_PUK);
    data.extend_from_slice(&new_puk);
    assert_eq!(ykpiv_send(&mut card, 0x24, 0x00, 0x81, &data).1, 0x9000);
    let unblocked = pad(b"112358");
    let mut data = new_puk.clone();
    data.extend_from_slice(&unblocked);
    assert_eq!(ykpiv_send(&mut card, 0x2C, 0x00, 0x80, &data).1, 0x9000);
    assert_eq!(card.verify_pin(&unblocked), 0x9000);
    // set-mgm-key (ykpiv_set_mgmkey3), then authenticate with the new key.
    let new_key = [0x24u8; 32];
    let mut data = vec![ALG_AES256];
    tlv::encode_into(&mut data, 0x9B, &new_key);
    assert_eq!(ykpiv_send(&mut card, 0xFF, 0xFF, 0xFF, &data).1, 0x9000);
    card.new_session();
    card.mutual_auth(ALG_AES256, &new_key);
    // set-retries and reset are data-less.
    card.verify_pin(&unblocked);
    assert_eq!(ykpiv_send(&mut card, 0xFA, 0x04, 0x04, &[]).1, 0x9000);
}

#[test]
fn a_non_zero_le_on_a_command_without_response_data_is_still_refused() {
    // Le 00 (Ne = the maximum, ISO/IEC 7816-4 §5.1) is what hosts append by habit; a
    // non-zero Le asks for response data these commands never return. The catalog's
    // "explicit Le" guards keep applying to it, before any state changes.
    let mut card = Card::new();
    card.auth_default();
    let before = card.host.persisted(Record::Piv);
    let count = card.host.persist_count();
    let mut change = hex(DEFAULT_PIN);
    change.extend_from_slice(&pad(b"999999"));
    let mut unblock = hex(DEFAULT_PUK);
    unblock.extend_from_slice(&pad(b"999999"));
    let mut mgmt = vec![ALG_AES128];
    tlv::encode_into(&mut mgmt, 0x9B, &[0x11; 16]);
    for (ins, p1, p2, data) in [
        (0x20, 0x00, 0x80, hex(DEFAULT_PIN)),
        (0x24, 0x00, 0x80, change.clone()),
        (0x2C, 0x00, 0x80, unblock.clone()),
        (0xDB, 0x3F, 0xFF, Card::put_payload(0x5FC102, &[1, 2, 3])),
        (0xFE, ED25519, 0x9A, tlv::encode(0x07, &[7; 32])),
        (0xFF, 0xFF, 0xFF, mgmt.clone()),
    ] {
        for le in [1, 8, 0xFF] {
            assert_eq!(card.cmd(ins, p1, p2, &data, Some(le)).1, 0x6700, "{ins:02X} Le {le:02X}");
        }
        // The extended form of a non-zero Le.
        let mut cmd = lk_codec::apdu::Command::new(0x00, ins, p1, p2).with_data(data.clone());
        cmd.le = Some(0x0100);
        cmd.extended = true;
        assert_eq!(card.raw(&cmd.to_bytes()).1, 0x6700, "{ins:02X} extended Le");
    }
    assert_eq!(card.host.persist_count(), count, "nothing spent or changed");
    assert_eq!(card.host.persisted(Record::Piv), before);
    assert_eq!(card.pin_status(), 0x63C3);
}

#[test]
fn le_zero_with_data_is_accepted_in_both_length_forms() {
    // Le 00 (short) and 0000 (extended) are Ne = maximum: accepted on every command that
    // returns no data, the same as no Le at all.
    let mut card = Card::new();
    for extended in [false, true] {
        let mut cmd = lk_codec::apdu::Command::new(0x00, 0x20, 0x00, 0x80).with_data(hex(DEFAULT_PIN));
        cmd.le = Some(0);
        cmd.extended = extended;
        assert_eq!(card.raw(&cmd.to_bytes()), (Vec::new(), 0x9000), "extended {extended}");
        card.send("0020FF80");
    }
    card.auth_default();
    let mut cmd = lk_codec::apdu::Command::new(0x00, 0xDB, 0x3F, 0xFF).with_data(Card::put_payload(0x5FC102, &[9]));
    cmd.le = Some(0);
    cmd.extended = true;
    assert_eq!(card.raw(&cmd.to_bytes()).1, 0x9000);
    assert_eq!(card.object_value(0x5FC102), Some(vec![9]));
}

/// OpenSC `card-piv.c` `piv_general_io`: case 4 short with Le `00` (Ne 256) when it reads
/// a response, case 3 otherwise; `SC_APDU_FLAGS_CHAINING` cuts the data into 255-byte
/// parts with CLA `10` and only the last part carries Le; `sc_get_response` follows
/// `61xx` with `00 C0 00 00 SW2`.
fn opensc_io(card: &mut Card, ins: u8, p1: u8, p2: u8, data: &[u8], reads: bool) -> (Vec<u8>, u16) {
    let parts: Vec<&[u8]> = if data.is_empty() { vec![&[][..]] } else { data.chunks(255).collect() };
    let (last, init) = parts.split_last().unwrap();
    for part in init {
        assert_eq!(card.raw(&apdu(0x10, ins, p1, p2, part, None)), (Vec::new(), 0x9000), "intermediate part");
    }
    let (mut out, mut sw) = card.raw(&apdu(0x00, ins, p1, p2, last, reads.then_some(0)));
    while sw >> 8 == 0x61 {
        let (more, next) = card.raw(&[0x00, 0xC0, 0x00, 0x00, (sw & 0xFF) as u8]);
        out.extend(more);
        sw = next;
    }
    (out, sw)
}

#[test]
fn opensc_request_shapes_are_accepted() {
    let mut card = Card::new();
    // piv_pin_cmd: SC_PIN_CMD_GET_INFO is VERIFY case 1, the PIN goes out padded with FF
    // as case 3, and piv_logout is iso7816_logout (VERIFY P1 FF, case 1).
    assert_eq!(card.send("00200080").1, 0x63C3);
    assert_eq!(opensc_io(&mut card, 0x20, 0x00, 0x80, &hex(DEFAULT_PIN), false), (Vec::new(), 0x9000));
    assert_eq!(card.send("00200080").1, 0x9000);
    assert_eq!(card.send("0020FF80").1, 0x9000);
    assert_eq!(card.send("00200080").1, 0x63C3);
    // piv_find_discovery reads 7E; CI_LEAKS_FILE_NOT_FOUND: an empty object is 6A82.
    let (discovery, sw) = opensc_io(&mut card, 0xCB, 0x3F, 0xFF, &hex("5C017E"), true);
    assert_eq!((discovery, sw), (hex("7E124F0BA0000003080000100001005F2F024000"), 0x9000));
    assert_eq!(opensc_io(&mut card, 0xCB, 0x3F, 0xFF, &hex("5C035FC102"), true).1, 0x6A82);
    // piv-tool -A A:9B:0A, piv_general_external_authenticate: the challenge request is
    // case 4, the encrypted challenge goes back as case 3 (SP 800-73-4 Appendix A.1).
    let key = hex(DEFAULT_MGMT_KEY);
    let (resp, sw) = opensc_io(&mut card, 0x87, ALG_AES192, 0x9B, &hex("7C028100"), true);
    assert_eq!(sw, 0x9000);
    let answer = encrypt(ALG_AES192, &key, &dyn_auth_item(&resp, 0x81));
    let answer = tlv::encode(0x7C, &tlv::encode(0x82, &answer));
    assert_eq!(opensc_io(&mut card, 0x87, ALG_AES192, 0x9B, &answer, false), (Vec::new(), 0x9000));
    // piv-tool -G 9A:07, piv_generate_key: AC { 80 07, 81 010001 } as case 4; the 265-byte
    // answer comes back in two pieces.
    let (data, sw) = opensc_io(&mut card, 0x47, 0x00, 0x9A, &hex("AC08 800107 8103010001"), true);
    assert_eq!(sw, 0x9000);
    let rsa = parse_public_template(&data);
    let (data, sw) = opensc_io(&mut card, 0x47, 0x00, 0x9D, &hex("AC03 800111"), true);
    assert_eq!(sw, 0x9000);
    let ec = parse_public_template(&data);
    // piv-tool -w: a chained PUT DATA (case 3) read back through GET RESPONSE.
    let mut container = tlv::encode(0x70, &vec![0x30; 600]);
    container.extend(hex("710100 FE00"));
    let payload = Card::put_payload(0x5FC105, &container);
    assert_eq!(opensc_io(&mut card, 0xDB, 0x3F, 0xFF, &payload, false), (Vec::new(), 0x9000));
    let (read, sw) = opensc_io(&mut card, 0xCB, 0x3F, 0xFF, &hex("5C035FC105"), true);
    assert_eq!((read, sw), (tlv::encode(0x53, &container), 0x9000));
    // piv_compute_signature (RSA): 7C { 82 00, 81 <256> } chained, case 4.
    assert_eq!(opensc_io(&mut card, 0x20, 0x00, 0x80, &hex(DEFAULT_PIN), false).1, 0x9000);
    let m = representative(rsa.modulus(), 0x5B);
    let mut inner = tlv::encode(0x82, &[]);
    tlv::encode_into(&mut inner, 0x81, &m);
    let (resp, sw) = opensc_io(&mut card, 0x87, RSA2048, 0x9A, &tlv::encode(0x7C, &inner), true);
    assert_eq!(sw, 0x9000);
    let s = dyn_auth_item(&resp, 0x82);
    assert_eq!(lk_crypto::rsa_public_op(rsa.modulus(), &[1, 0, 1], &s).unwrap(), m);
    // piv_compute_signature (ECDSA): the DER signature OpenSC converts to r || s.
    let digest = [0x3Cu8; 32];
    let mut inner = tlv::encode(0x82, &[]);
    tlv::encode_into(&mut inner, 0x81, &digest);
    let (resp, sw) = opensc_io(&mut card, 0x87, P256, 0x9D, &tlv::encode(0x7C, &inner), true);
    assert_eq!(sw, 0x9000);
    assert!(ecdsa_ok(P256, ec.point(), &digest, &dyn_auth_item(&resp, 0x82)));
    // piv_decipher for an EC key (C_DeriveKey ECDH1): 7C { 82 00, 85 <peer point> }.
    let peer = lk_crypto::EcPrivateKey::generate(lk_crypto::Curve::P256, &mut lk_testkit::SeededEntropy::new(0x5C));
    let mut inner = tlv::encode(0x82, &[]);
    tlv::encode_into(&mut inner, 0x85, &peer.public_uncompressed());
    let (resp, sw) = opensc_io(&mut card, 0x87, P256, 0x9D, &tlv::encode(0x7C, &inner), true);
    assert_eq!(sw, 0x9000);
    assert_eq!(dyn_auth_item(&resp, 0x82), peer.ecdh(ec.point()).unwrap().to_vec());
}

/// An extended APDU (ISO/IEC 7816-4 §5.1) with the given Le.
fn extended(ins: u8, p1: u8, p2: u8, data: &[u8], le: Option<u32>) -> Vec<u8> {
    let mut cmd = lk_codec::apdu::Command::new(0x00, ins, p1, p2).with_data(data.to_vec());
    cmd.le = le;
    cmd.extended = true;
    cmd.to_bytes()
}

/// python yubikit over USB: extended APDUs without Le (a data-less command is the bare
/// header), `61xx` followed with the bare header `00 C0 00 00`
/// (`ChainedResponseProcessor`).
fn yubikit_send(card: &mut Card, ins: u8, p1: u8, p2: u8, data: &[u8]) -> (Vec<u8>, u16) {
    let (mut out, mut sw) = card.raw(&yubikit_apdu(true, ins, p1, p2, data));
    while sw >> 8 == 0x61 {
        let (more, next) = card.raw(&[0x00, 0xC0, 0x00, 0x00]);
        out.extend(more);
        sw = next;
    }
    (out, sw)
}

#[test]
fn yubikit_and_cryptotokenkit_extended_requests_are_accepted() {
    let mut card = Card::new();
    let key = hex(DEFAULT_MGMT_KEY);
    // yubikit: VERIFY, mutual authentication and GENERATE as extended APDUs without Le.
    assert_eq!(yubikit_send(&mut card, 0x20, 0x00, 0x80, &hex(DEFAULT_PIN)), (Vec::new(), 0x9000));
    let (resp, sw) = yubikit_send(&mut card, 0x87, ALG_AES192, 0x9B, &hex("7C028000"));
    assert_eq!(sw, 0x9000);
    let witness = decrypt(ALG_AES192, &key, &dyn_auth_item(&resp, 0x80));
    let mut inner = tlv::encode(0x80, &witness);
    tlv::encode_into(&mut inner, 0x81, &[0x77; 16]);
    let (resp, sw) = yubikit_send(&mut card, 0x87, ALG_AES192, 0x9B, &tlv::encode(0x7C, &inner));
    assert_eq!(sw, 0x9000);
    assert_eq!(dyn_auth_item(&resp, 0x82), encrypt(ALG_AES192, &key, &[0x77; 16]));
    // An extended command without Le gets its whole answer at once (Ne = 65 536).
    let (data, sw) = card.raw(&extended(0x47, 0x00, 0x9A, &generate_template(RSA2048, None, None), None));
    assert_eq!(sw, 0x9000, "no 61xx");
    let rsa = parse_public_template(&data);
    // A 1000-byte object in one extended PUT DATA, read back in one extended GET DATA.
    let value = vec![0xA5; 1000];
    assert_eq!(yubikit_send(&mut card, 0xDB, 0x3F, 0xFF, &Card::put_payload(0x5FC10D, &value)), (Vec::new(), 0x9000));
    let (data, sw) = card.raw(&extended(0xCB, 0x3F, 0xFF, &hex("5C035FC10D"), None));
    assert_eq!((data, sw), (tlv::encode(0x53, &value), 0x9000));
    // Data-less commands are the bare header (case 1): metadata and attestation longer
    // than 256 bytes come in pieces fetched with the bare GET RESPONSE header.
    let (md, sw) = yubikit_send(&mut card, 0xF7, 0x00, 0x9A, &[]);
    assert_eq!(sw, 0x9000);
    assert!(md.len() > 256);
    let (cert, sw) = yubikit_send(&mut card, 0xF9, 0x9A, 0x00, &[]);
    assert_eq!((cert.first(), sw), (Some(&0x30), 0x9000));
    assert!(cert.len() > 256);
    // CryptoTokenKit (TKSmartCard with useExtendedLength): one extended command with Le
    // 0000 instead of chaining, and the whole answer at once.
    let m = representative(rsa.modulus(), 0x6D);
    let mut inner = tlv::encode(0x82, &[]);
    tlv::encode_into(&mut inner, 0x81, &m);
    let (resp, sw) = card.raw(&extended(0x87, RSA2048, 0x9A, &tlv::encode(0x7C, &inner), Some(0)));
    assert_eq!(sw, 0x9000, "no 61xx");
    let s = dyn_auth_item(&resp, 0x82);
    assert_eq!(lk_crypto::rsa_public_op(rsa.modulus(), &[1, 0, 1], &s).unwrap(), m);
    let (full, sw) = card.get_object(0x5FFF01);
    assert_eq!(sw, 0x9000);
    assert_eq!(card.raw(&extended(0xCB, 0x3F, 0xFF, &hex("5C035FFF01"), Some(0))), (full, 0x9000));
}
