//! End-to-end determinism (`docs/DESIGN.md` §1, §4: the device is a deterministic state
//! machine; the same inputs at the same times with the same entropy give the same
//! outputs): one script over every interface, run twice with the same seed.

#![allow(clippy::unwrap_used)]

mod common;

use common::ctap::{self, PinAuth, PinProtocol2, perm};
use common::iso::{oath, pgp, piv};
use common::otp::{SlotConfig, slot};
use common::*;
use lk_core::{DeviceProfile, Millis, Record};
use lk_crypto::sha256;
use lk_device::{BusEvent, Output};
use lk_testkit::{MemoryStore, SeededEntropy};

const RECORDS: [Record; 8] = [
    Record::Device,
    Record::Fido,
    Record::Oath,
    Record::Otp,
    Record::Piv,
    Record::OpenPgp,
    Record::HsmAuth,
    Record::SecurityDomain,
];

/// The script: FIDO (PIN, MakeCredential and GetAssertion with touches, U2F with the
/// latch), PIV and OpenPGP key generation and signatures, OATH, an SCP03 session, OTP
/// programming, a press and a challenge-response, Management over CTAPHID, and a power
/// cycle, all at explicit times. Every output is logged with its time.
fn script(rig: &mut Rig) -> Vec<(Millis, Output)> {
    rig.log = Some(Vec::new());
    let mut entropy = SeededEntropy::new(31);
    let cid = rig.ctaphid_init();
    rig.cbor(cid, &ctap::request(ctap::cmd::GET_INFO, None));
    let pp = PinProtocol2::from_key_agreement(&rig.cbor(cid, &PinProtocol2::key_agreement_request()), &mut entropy);
    rig.cbor(cid, &pp.set_pin("97531"));
    let pp = PinProtocol2::from_key_agreement(&rig.cbor(cid, &PinProtocol2::key_agreement_request()), &mut entropy);
    let token = pp.token(&rig.cbor(cid, &pp.token_request("97531", perm::MC | perm::GA, Some("det.example"))));
    let (response, _) = rig.cbor_touch(cid, &ctap::make_credential(&[9; 32], "det.example", b"u", true, &PinAuth::Token(token.clone())), 333);
    let id = ctap::parse_auth_data(ctap::get(&ctap::ok_value(&response), 2).as_bytes().unwrap()).credential.unwrap().id;
    rig.cbor_touch(cid, &ctap::get_assertion(&[8; 32], "det.example", &[id], &PinAuth::Token(token)), 250);
    let application = sha256(b"https://det.example");
    rig.ctaphid(cid, CTAPHID_MSG, &ctap::u2f_register(&[7; 32], &application));
    rig.tap();
    rig.ctaphid(cid, CTAPHID_MSG, &ctap::u2f_register(&[7; 32], &application));
    rig.ctaphid(cid, 0x42, &[]);

    rig.now += 1_234;
    rig.power_on();
    rig.select(AID_PIV);
    rig.piv_authenticate(&piv::DEFAULT_MGMT_KEY);
    rig.piv_generate_p256(piv::SLOT_AUTH, None);
    rig.piv_verify("123456");
    rig.send(&Rig::piv_sign_request(piv::SLOT_AUTH, &sha256(b"piv")));
    rig.select(AID_OPENPGP);
    rig.pgp_verify(0x83, pgp::PW3);
    rig.pgp_put(0x00C1, &pgp::ECDSA_P256);
    rig.pgp_generate_signature_key();
    rig.pgp_verify(0x81, pgp::PW1);
    rig.send(&Rig::pgp_sign_request(&sha256(b"pgp")));
    rig.select(AID_OATH);
    rig.apdu(&oath::put(b"det", oath::TOTP_SHA1, 6, b"12345678901234567890", true));
    rig.xfr(&oath::calculate(b"det", &[0, 0, 0, 0, 0, 0, 0, 1], true));
    rig.run_until(rig.now + 1_100);
    rig.tap();
    let mut session = Scp03::open(rig);
    let list = session.wrap(0x00, 0xA1, 0x00, 0x00, &[], Some(0));
    rig.apdu(&list);

    rig.now += 777;
    rig.otp_program(slot::CONFIG1, &SlotConfig::yubico_otp(&[1, 1, 2, 3, 5, 8], [13; 6], [21; 16]), [0; 6]);
    rig.otp_program(slot::CONFIG2, &SlotConfig::hmac_challenge_response(&[34; 20], false), [0; 6]);
    rig.touch_down();
    rig.run_until(rig.now + 640);
    rig.touch_up();
    rig.otp_send_frame(slot::CHAL_HMAC2, &[0x55; 64]);
    rig.otp_response(20);

    rig.now += 5_000;
    rig.bus(BusEvent::PowerCycle);
    let cid = rig.ctaphid_init();
    rig.cbor(cid, &ctap::request(ctap::cmd::GET_INFO, None));
    rig.log.take().unwrap()
}

/// `docs/DESIGN.md` §1: two devices with the same profile, store contents and entropy
/// seed, given the same script, produce byte-identical outputs at identical times and
/// identical sealed records; a device with another seed differs (the comparison is not
/// vacuous: keys, nonces and attestation come from the seed).
#[test]
fn same_script_and_seed_give_byte_identical_outputs() {
    let profile = DeviceProfile::yubikey_5c_nano_5_7_4(SERIAL);
    let mut first = Rig::with_store(profile.clone(), MemoryStore::new(), 1);
    let mut second = Rig::with_store(profile.clone(), MemoryStore::new(), 1);
    let a = script(&mut first);
    let b = script(&mut second);
    assert!(a.len() > 200, "the script exercised the device ({} outputs)", a.len());
    assert_eq!(a.len(), b.len());
    for (i, (x, y)) in a.iter().zip(&b).enumerate() {
        assert_eq!(x, y, "output {i}");
    }
    for record in RECORDS {
        assert_eq!(first.store.get(record), second.store.get(record), "{record:?}");
    }

    let mut other = Rig::with_store(profile, MemoryStore::new(), 2);
    let c = script(&mut other);
    assert_ne!(a, c, "another seed gives other keys and signatures");
}
