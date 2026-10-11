//! End-to-end persistence scenarios (`docs/DESIGN.md` §7; `docs/CONTRACTS.md` "Persisted
//! state"): state created in every application through the device's transports survives
//! a restart on the same `MemoryStore` and storage key; a wrong key gives factory state;
//! a failing store leaves state unchanged and answers the storage-failure status.

#![allow(clippy::unwrap_used)]

mod common;

use common::ctap::{self, PinAuth, PinProtocol2, perm, status};
use common::iso::{self, command, find_tlv, hsmauth, oath, pgp, piv, split};
use common::otp::{self, SlotConfig, slot};
use common::*;
use lk_core::{DeviceProfile, Record};
use lk_crypto::{Curve, ecdsa_verify_prehash, sha256};
use lk_device::Device;
use lk_testkit::SeededEntropy;

const ALL_RECORDS: [Record; 8] = [
    Record::Device,
    Record::Fido,
    Record::Oath,
    Record::Otp,
    Record::Piv,
    Record::OpenPgp,
    Record::HsmAuth,
    Record::SecurityDomain,
];
const RP: &str = "persist.example";
const OTP_KEY: [u8; 16] = *b"persisted-otpkey";
const HSM_ENC: [u8; 16] = [0x61; 16];
const HSM_MAC: [u8; 16] = [0x62; 16];
const HSM_PASSWORD: [u8; 16] = *b"hsm-password-16b";
const NEW_SCP03: Scp03Keys = [[0x71; 16], [0x72; 16], [0x73; 16]];
const RFC6238_SHA1: &[u8] = b"12345678901234567890";

fn agree(rig: &mut Rig, cid: u32, entropy: &mut SeededEntropy) -> PinProtocol2 {
    PinProtocol2::from_key_agreement(&rig.cbor(cid, &PinProtocol2::key_agreement_request()), entropy)
}

fn token(rig: &mut Rig, cid: u32, pin: &str, entropy: &mut SeededEntropy) -> Result<Vec<u8>, u8> {
    let pp = agree(rig, cid, entropy);
    let response = rig.cbor(cid, &pp.token_request(pin, perm::MC | perm::GA, Some(RP)));
    if response[0] == status::OK { Ok(pp.token(&response)) } else { Err(response[0]) }
}

fn client_pin_set(rig: &mut Rig, cid: u32) -> bool {
    let info = ctap::ok_value(&rig.cbor(cid, &ctap::request(ctap::cmd::GET_INFO, None)));
    ctap::get(&info, 4).map_get_text("clientPin").and_then(lk_codec::cbor::Value::as_bool).unwrap()
}

fn press_otp(rig: &mut Rig) -> otp::Ticket {
    let mut reports = keyboard(&rig.touch_down());
    rig.now += 600;
    reports.extend(keyboard(&rig.touch_up()));
    let text = otp::keyboard_text(&reports);
    otp::decrypt_otp(text.trim_end(), &OTP_KEY).1
}

/// What the first session created and later checks need.
struct Created {
    credential: ctap::AttestedCredential,
    piv_point: Vec<u8>,
    pgp_point: Vec<u8>,
    otp_use_counter: u16,
    cplc: Vec<u8>,
}

/// Create state in every application through its own transport.
fn create_everything(rig: &mut Rig) -> Created {
    let mut entropy = SeededEntropy::new(11);
    // FIDO: a PIN and a discoverable credential (CTAP 2.1 §6.5.5.5, §6.1).
    let cid = rig.ctaphid_init();
    let pp = agree(rig, cid, &mut entropy);
    assert_eq!(rig.cbor(cid, &pp.set_pin("8642")), vec![status::OK]);
    let t = token(rig, cid, "8642", &mut entropy).unwrap();
    let request = ctap::make_credential(&[1; 32], RP, b"persisted user", true, &PinAuth::Token(t));
    let (response, _) = rig.cbor_touch(cid, &request, 100);
    let attestation = ctap::ok_value(&response);
    let credential = ctap::parse_auth_data(ctap::get(&attestation, 2).as_bytes().unwrap()).credential.unwrap();

    // OTP: slot 1 Yubico OTP over HID.
    rig.otp_program(slot::CONFIG1, &SlotConfig::yubico_otp(&[0xCA, 0xFE, 0, 0, 0, 1], [3; 6], OTP_KEY), [0; 6]);
    let otp_use_counter = press_otp(rig).use_counter;

    rig.power_on();
    // Management: challenge-response timeout 30 s (yubikit DeviceConfig tag 07).
    rig.select(AID_MGMT);
    assert_eq!(rig.apdu(&[0x00, 0x1C, 0x00, 0x00, 0x04, 0x03, 0x07, 0x01, 30]), vec![0x90, 0x00]);
    // OATH: the RFC 6238 SHA-1 credential.
    rig.select(AID_OATH);
    assert_eq!(rig.apdu(&oath::put(b"rfc6238", oath::TOTP_SHA1, 8, RFC6238_SHA1, false)), vec![0x90, 0x00]);
    // PIV: a generated key in 9A and a new PIN.
    rig.select(AID_PIV);
    rig.piv_authenticate(&piv::DEFAULT_MGMT_KEY);
    let piv_point = rig.piv_generate_p256(piv::SLOT_AUTH, None);
    let change = [piv::pin_block("123456"), piv::pin_block("654321")].concat();
    assert_eq!(rig.apdu(&command(0x00, 0x24, 0x00, piv::PIN, &change, None)), vec![0x90, 0x00]);
    // OpenPGP: an ECDSA signature key, the cardholder name, one signature.
    rig.select(AID_OPENPGP);
    rig.pgp_verify(0x83, pgp::PW3);
    rig.pgp_put(0x00C1, &pgp::ECDSA_P256);
    let pgp_point = rig.pgp_generate_signature_key();
    assert_eq!(rig.pgp_put(0x005B, b"Doe<<Jane"), 0x9000);
    rig.pgp_verify(0x81, pgp::PW1);
    assert_eq!(sw(&rig.send(&Rig::pgp_sign_request(&sha256(b"one")))), 0x9000);
    // HSM Auth: a symmetric credential.
    rig.select(AID_HSMAUTH);
    assert_eq!(rig.apdu(&hsmauth::put(b"persisted", &HSM_ENC, &HSM_MAC, &HSM_PASSWORD, false)), vec![0x90, 0x00]);
    // Security Domain: a new SCP03 key set replacing the factory set (GP 2.3.1 §11.8).
    rig.select(AID_SD);
    let cplc = rig.send(&[0x80, 0xCA, 0x9F, 0x7F, 0x00]);
    assert_eq!(sw(&cplc), 0x9000);
    let mut session = Scp03::open(rig);
    let (data, expected) = session.put_key_data(0x02, &NEW_SCP03);
    let put = session.wrap(0x80, 0xD8, 0x00, 0x81, &data, Some(0));
    assert_eq!(session.unwrap(&rig.apdu(&put)), (expected, 0x9000));
    Created {
        credential,
        piv_point,
        pgp_point,
        otp_use_counter,
        cplc,
    }
}

/// `docs/DESIGN.md` §7 "restart persistence": after a restart on the same store and key
/// every application has its state: the FIDO PIN and credential (an assertion verifies
/// under the public key made before), the OATH secret (RFC 6238 code), the OTP slot (an
/// OTP decrypting under its key with a higher usage counter, YubiKey manual "Yubico
/// OTP"), the Management challenge-response timeout (the OTP HID wait counts down from
/// 30 s), the PIV key and new PIN, the OpenPGP key, name and signature counter, the HSM
/// Auth credential (its session keys follow GP Amd D §6.2.1), and the Security Domain's
/// replaced key set and identity.
#[test]
fn every_application_survives_a_restart() {
    let mut rig = Rig::new();
    let created = create_everything(&mut rig);
    rig.now += 1_000;
    rig.restart();
    assert!(rig.dev.unreadable_records().is_empty());
    let mut entropy = SeededEntropy::new(12);

    let cid = rig.ctaphid_init();
    assert!(client_pin_set(&mut rig, cid));
    assert_eq!(token(&mut rig, cid, "0000", &mut entropy), Err(status::PIN_INVALID));
    let t = token(&mut rig, cid, "8642", &mut entropy).unwrap();
    let hash = sha256(b"after restart");
    let (response, _) = rig.cbor_touch(cid, &ctap::get_assertion(&hash, RP, &[], &PinAuth::Token(t)), 100);
    let assertion = ctap::ok_value(&response);
    let data = ctap::get(&assertion, 2).as_bytes().unwrap();
    assert!(ctap::verify_es256(&created.credential.public_key, data, &hash, ctap::get(&assertion, 3).as_bytes().unwrap()));
    let user = ctap::get(&assertion, 4);
    assert_eq!(user.map_get_text("id").and_then(lk_codec::cbor::Value::as_bytes), Some(&b"persisted user"[..]));

    rig.now += 1_000;
    let ticket = press_otp(&mut rig);
    assert_eq!((ticket.uid, ticket.session_counter), ([3; 6], 0));
    assert!(ticket.use_counter > created.otp_use_counter);
    rig.otp_program(slot::CONFIG2, &SlotConfig::hmac_challenge_response(&[0x44; 20], true), [0; 6]);
    rig.otp_send_frame(slot::CHAL_HMAC2, &[0x01; 64]);
    assert_eq!(rig.otp_feature()[7], otp::RESP_TIMEOUT_WAIT_FLAG | 30, "Management timeout kept");
    rig.input(lk_device::Input::OtpSetFeature(&[0, 0, 0, 0, 0, 0, 0, 0xFF]));

    rig.power_on();
    rig.select(AID_OATH);
    assert_eq!(oath::code(&rig.send(&oath::calculate(b"rfc6238", &1u64.to_be_bytes(), true))), "94287082");

    rig.select(AID_PIV);
    assert_eq!(rig.piv_verify("123456"), 0x63C2, "the old PIN is gone");
    assert_eq!(rig.piv_verify("654321"), 0x9000);
    let digest = sha256(b"piv after restart");
    let signature = Rig::piv_signature(&rig.send(&Rig::piv_sign_request(piv::SLOT_AUTH, &digest)));
    assert!(ecdsa_verify_prehash(Curve::P256, &created.piv_point, &digest, &signature));

    rig.select(AID_OPENPGP);
    let holder = rig.send(&command(0x00, 0xCA, 0x00, 0x65, &[], Some(256)));
    assert_eq!(find_tlv(&find_tlv(&holder, 0x65).unwrap(), 0x5B).unwrap(), b"Doe<<Jane".to_vec());
    assert_eq!(rig.pgp_signature_counter(), 1);
    rig.pgp_verify(0x81, pgp::PW1);
    let digest = sha256(b"pgp after restart");
    let response = rig.send(&Rig::pgp_sign_request(&digest));
    assert!(ecdsa_verify_prehash(Curve::P256, &created.pgp_point, &digest, split(&response).0));

    rig.select(AID_HSMAUTH);
    let list = rig.send(&hsmauth::LIST);
    assert_eq!(sw(&list), 0x9000);
    assert!(list.windows(9).any(|w| w == b"persisted"), "LIST names the credential: {list:02X?}");
    let context = *b"0123456789abcdef";
    let keys = rig.send(&hsmauth::calculate(b"persisted", &context, &HSM_PASSWORD));
    assert_eq!(&keys[..16], scp03_derive(&HSM_ENC, 0x04, &context, 128).as_slice());

    rig.select(AID_SD);
    assert_eq!(rig.send(&[0x80, 0xCA, 0x9F, 0x7F, 0x00]), created.cplc, "CPLC");
    assert_eq!(sw(&rig.apdu(&iso::command(0x80, 0x50, 0xFF, 0x00, &[0x01; 8], None))), 0x6A88, "factory keys gone");
    let mut session = Scp03::open_with(&mut rig, 0x02, &NEW_SCP03);
    let get = session.wrap(0x80, 0xCA, 0x00, 0xE0, &[], Some(0));
    let (info, status) = session.unwrap(&rig.apdu(&get));
    assert_eq!(status, 0x9000);
    assert_eq!(&info[..4], &[0xC0, 0x04, 0x01, 0x02], "key information names KVN 02");
}

/// `docs/CONTRACTS.md` "Persisted state": records that do not open under the storage key
/// mean factory state (`Device::unreadable_records` names them): no FIDO PIN, no OATH
/// credential, the default PIV PIN (Yubico GET METADATA `F7` for the PIN: default-value
/// flag `05 01`); and the device works. Opening and reading write nothing, so the records
/// stay in the store untouched and the right key afterwards opens the user's state
/// again (`docs/DESIGN.md` §7: a record is only replaced by a commit of that
/// application's own command). A store whose loads fail at open is treated the same.
#[test]
fn wrong_storage_key_gives_factory_state_without_destroying_records() {
    let mut rig = Rig::new();
    let created = create_everything(&mut rig);
    let stored: Vec<Option<Vec<u8>>> = ALL_RECORDS.iter().map(|&r| rig.store.get(r)).collect();
    let profile = DeviceProfile::yubikey_5c_nano_5_7_4(SERIAL);

    let saves = rig.store.save_count();
    rig.dev = Device::open_at(rig.now, profile.clone(), Box::new(rig.store.clone()), Box::new(SeededEntropy::new(77)), [0x11; 32]);
    assert_eq!(rig.dev.unreadable_records(), &ALL_RECORDS);
    assert_eq!(rig.store.save_count(), saves, "opening saved nothing");
    let cid = rig.ctaphid_init();
    assert!(!client_pin_set(&mut rig, cid));
    rig.power_on();
    rig.select(AID_OATH);
    assert_eq!(rig.apdu(&[0x00, 0xA1, 0x00, 0x00]), vec![0x90, 0x00], "no OATH credentials");
    rig.select(AID_PIV);
    let metadata = rig.send(&[0x00, 0xF7, 0x00, 0x80, 0x00]);
    assert_eq!(sw(&metadata), 0x9000);
    assert_eq!(find_tlv(&metadata[..metadata.len() - 2], 0x05), Some(vec![0x01]), "factory PIN");
    rig.select(AID_SD);
    assert_ne!(rig.send(&[0x80, 0xCA, 0x9F, 0x7F, 0x00]), created.cplc, "a factory identity");
    let after: Vec<Option<Vec<u8>>> = ALL_RECORDS.iter().map(|&r| rig.store.get(r)).collect();
    assert_eq!(after, stored, "opening with the wrong key wrote nothing");

    rig.restart();
    assert!(rig.dev.unreadable_records().is_empty());
    rig.power_on();
    rig.select(AID_PIV);
    assert_eq!(rig.piv_verify("654321"), 0x9000, "the user's PIN is back");
    rig.select(AID_SD);
    assert_eq!(rig.send(&[0x80, 0xCA, 0x9F, 0x7F, 0x00]), created.cplc);

    // The same for a store whose loads fail for a while (`MemoryStore::fail_loads`).
    rig.store.fail_loads(true);
    let saves = rig.store.save_count();
    rig.restart();
    assert_eq!(rig.dev.unreadable_records(), &ALL_RECORDS);
    assert_eq!(rig.store.save_count(), saves, "opening saved nothing");
    rig.store.fail_loads(false);
    rig.restart();
    assert!(rig.dev.unreadable_records().is_empty());
    rig.power_on();
    rig.select(AID_OPENPGP);
    let holder = rig.send(&command(0x00, 0xCA, 0x00, 0x65, &[], Some(256)));
    assert_eq!(find_tlv(&find_tlv(&holder, 0x65).unwrap(), 0x5B).unwrap(), b"Doe<<Jane".to_vec());
}

/// `docs/DESIGN.md` §7 commit rule with `MemoryStore::fail_all`: a MakeCredential whose
/// save fails after the touch answers CTAP1_ERR_OTHER (`docs/CONTRACTS.md` "Persisted
/// state") and creates nothing; a PIV CHANGE REFERENCE DATA whose save fails answers
/// `6581` and keeps the old PIN and its retry counter (`docs/CONTRACTS.md` "Retry
/// counters"). The stored records are unchanged, and both work once the store does.
#[test]
fn store_failure_leaves_state_unchanged() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    let fido_before = rig.store.get(Record::Fido);
    let request = ctap::make_credential(&[2; 32], RP, b"user", true, &PinAuth::None);
    let out = rig.ctaphid_send(cid, CTAPHID_CBOR, &request);
    // Waiting for the touch: no answer and no KEEPALIVE at once (docs/MEASUREMENT.md,
    // probe selection-keepalive-cancel; an immediate KEEPALIVE was expected before the
    // measurement).
    assert!(responses(&out).is_empty() && keepalives(&out).is_empty());
    assert_eq!(indicators(&out), vec![true]);
    rig.store.fail_all(true);
    let out = rig.tap();
    assert_eq!(responses(&out), vec![(CTAPHID_CBOR, vec![status::OTHER])]);
    assert_eq!(rig.store.get(Record::Fido), fido_before);
    let info = ctap::ok_value(&rig.cbor(cid, &ctap::request(ctap::cmd::GET_INFO, None)));
    assert_eq!(ctap::get(&info, 0x14).as_u64(), Some(100), "no credential stored");

    rig.store.fail_all(false);
    rig.power_on();
    rig.select(AID_PIV);
    let piv_before = rig.store.get(Record::Piv);
    rig.store.fail_all(true);
    let change = [piv::pin_block("123456"), piv::pin_block("777777")].concat();
    assert_eq!(rig.apdu(&command(0x00, 0x24, 0x00, piv::PIN, &change, None)), vec![0x65, 0x81]);
    rig.store.fail_all(false);
    assert_eq!(rig.store.get(Record::Piv), piv_before);
    assert_eq!(rig.apdu(&[0x00, 0x20, 0x00, 0x80]), vec![0x63, 0xC3], "retries unchanged");
    assert_eq!(rig.piv_verify("123456"), 0x9000, "old PIN still valid");

    let (response, _) = rig.cbor_touch(cid, &request, 100);
    assert_eq!(response[0], status::OK);
    assert_eq!(rig.apdu(&command(0x00, 0x24, 0x00, piv::PIN, &change, None)), vec![0x90, 0x00]);
    assert_eq!(rig.piv_verify("777777"), 0x9000);
}

/// YKOATH SELECT: tag `71` is the device's name, the salt hosts use as its device ID and
/// for the access-key PBKDF2 (yubikit `OathSession.device_id`); on a key it changes only
/// with an OATH reset. Through the device it survives power cycles, and once the OATH
/// record exists (here after the first PUT) program restarts too. (Before the first
/// mutating command a restart still picks a new one: lk-oath persists factory state
/// only with the first mutation, `docs/CONTRACTS.md` "Applications A": "a known gap for
/// the final review".)
#[test]
fn oath_device_id_survives_power_cycles_and_restarts() {
    let mut rig = Rig::new();
    rig.power_on();
    let name = |rig: &mut Rig| {
        let answer = rig.select(AID_OATH);
        find_tlv(&answer[..answer.len() - 2], 0x71).unwrap()
    };
    let first = name(&mut rig);
    rig.bus(lk_device::BusEvent::PowerCycle);
    rig.power_on();
    assert_eq!(name(&mut rig), first, "after a power cycle");
    assert_eq!(rig.apdu(&oath::put(b"x", oath::TOTP_SHA1, 6, &[1; 20], false)), vec![0x90, 0x00]);
    rig.restart();
    rig.power_on();
    assert_eq!(name(&mut rig), first, "after a restart");
}
