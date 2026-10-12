//! Persistence atomicity sweep (device:verify). `docs/DESIGN.md` §7 commit rule: a
//! command's state is saved before success is answered, and a failed save leaves the
//! previous state in memory. Seen from the host, memory and store must therefore never
//! disagree: whatever the device shows after a failed save, it shows again after the
//! program restarts on the same store.
//!
//! A script commits once or more in every application through the device's own
//! transports (FIDO PIN, PIN token, a discoverable credential after a touch; an OTP slot
//! over HID and a button press; Management configuration; OATH; PIV PIN verification and
//! change; OpenPGP PIN, data, key generation, touch policy and a touch-gated signature;
//! YubiHSM Auth; a Security Domain key set over SCP03). A counting store makes exactly
//! one save fail, for every save the script performs, including the saves the
//! applications' constructors make while the device opens. Each run checks that the
//! command whose save failed did not report success, then reads every application's
//! host-visible persistent state, restarts the program on the same store, reads it again
//! and requires both readings to be equal.

#![allow(clippy::unwrap_used)]

mod common;

use std::cell::RefCell;
use std::rc::Rc;

use common::ctap::{self, PinAuth, PinProtocol2, perm, status};
use common::iso::{command, hsmauth, oath, pgp, piv, split};
use common::otp::{SlotConfig, slot};
use common::*;
use lk_core::{DeviceProfile, Record, Store, StoreError};
use lk_device::Device;
use lk_testkit::{MemoryStore, SeededEntropy};

const RP: &str = "sweep.example";
const NEW_SCP03: Scp03Keys = [[0x71; 16], [0x72; 16], [0x73; 16]];

/// Save attempts seen so far, and the attempt to fail.
#[derive(Debug, Default)]
struct Sweep {
    attempts: usize,
    fail_at: Option<usize>,
    failed: Option<Record>,
}

/// A store whose save attempt number `fail_at` fails (the `lk_core::Store` contract:
/// a failed save keeps the record's previous bytes); everything else goes to `inner`.
struct SweepStore {
    inner: MemoryStore,
    sweep: Rc<RefCell<Sweep>>,
}

impl Store for SweepStore {
    fn load(&mut self, record: Record) -> Result<Option<Vec<u8>>, StoreError> {
        self.inner.load(record)
    }

    fn save(&mut self, record: Record, sealed: &[u8]) -> Result<(), StoreError> {
        let fail = {
            let mut sweep = self.sweep.borrow_mut();
            let attempt = sweep.attempts;
            sweep.attempts += 1;
            let fail = sweep.fail_at == Some(attempt);
            if fail {
                sweep.failed = Some(record);
            }
            fail
        };
        if fail {
            return Err(StoreError("sweep: injected failure".into()));
        }
        self.inner.save(record, sealed)
    }
}

/// What the script carries between steps.
struct Ctx {
    cid: u32,
    entropy: SeededEntropy,
    token: Vec<u8>,
}

fn agree(rig: &mut Rig, ctx: &mut Ctx) -> PinProtocol2 {
    let cid = ctx.cid;
    PinProtocol2::from_key_agreement(&rig.cbor(cid, &PinProtocol2::key_agreement_request()), &mut ctx.entropy)
}

// Each step makes one change through the device and returns whether the device
// reported success.

/// CTAP 2.1 §6.5.5.5 setPIN.
fn fido_set_pin(rig: &mut Rig, ctx: &mut Ctx) -> bool {
    let pp = agree(rig, ctx);
    rig.cbor(ctx.cid, &pp.set_pin("8642")) == vec![status::OK]
}

/// CTAP 2.1 §6.5.5.7 getPinUvAuthTokenUsingPinWithPermissions (spends and restores a
/// PIN retry: two saves, `docs/CONTRACTS.md` "Retry counters").
fn fido_token(rig: &mut Rig, ctx: &mut Ctx) -> bool {
    let pp = agree(rig, ctx);
    let response = rig.cbor(ctx.cid, &pp.token_request("8642", perm::MC | perm::GA, Some(RP)));
    if response[0] != status::OK {
        return false;
    }
    ctx.token = pp.token(&response);
    true
}

/// CTAP 2.1 §6.1 authenticatorMakeCredential of a discoverable credential, committed
/// after the touch.
fn fido_make_credential(rig: &mut Rig, ctx: &mut Ctx) -> bool {
    let request = ctap::make_credential(&[1; 32], RP, b"sweep user", true, &PinAuth::Token(ctx.token.clone()));
    let out = rig.ctaphid_send(ctx.cid, CTAPHID_CBOR, &request);
    assert!(responses(&out).is_empty(), "MakeCredential waits for the touch");
    let out = rig.tap();
    let (command, response) = responses(&out).remove(0);
    assert_eq!(command, CTAPHID_CBOR);
    response[0] == status::OK
}

/// Yubico OTP in slot 1 over OTP HID; a rejected write leaves the programming sequence
/// unchanged (yubikit `_check_status`).
fn otp_program(rig: &mut Rig, _: &mut Ctx) -> bool {
    let before = rig.otp_feature()[4];
    rig.otp_send_frame(slot::CONFIG1, &SlotConfig::yubico_otp(&[0xCA, 0xFE], [2; 6], [0x5C; 16]).payload([0; 6]));
    rig.otp_feature()[4] != before
}

/// A button press: the Yubico OTP usage counter is saved before the OTP is typed
/// (YubiKey manual "Yubico OTP"; `lk_core::Host::persist` counters rule), so a failed
/// save types nothing.
fn otp_press(rig: &mut Rig, _: &mut Ctx) -> bool {
    let mut reports = keyboard(&rig.touch_down());
    rig.now += 600;
    reports.extend(keyboard(&rig.touch_up()));
    !reports.is_empty()
}

/// Management WRITE CONFIG: challenge-response timeout 30 s (yubikit tag `07`).
fn mgmt_write_config(rig: &mut Rig, _: &mut Ctx) -> bool {
    rig.power_on();
    rig.select(AID_MGMT);
    rig.apdu(&[0x00, 0x1C, 0x00, 0x00, 0x04, 0x03, 0x07, 0x01, 30]) == vec![0x90, 0x00]
}

/// YKOATH PUT.
fn oath_put_credential(rig: &mut Rig, _: &mut Ctx) -> bool {
    rig.select(AID_OATH);
    rig.apdu(&oath::put(b"sweep", oath::TOTP_SHA1, 6, &[0x33; 20], false)) == vec![0x90, 0x00]
}

/// PIV VERIFY (SP 800-73-4 Part 2 §3.2.1; two saves).
fn piv_verify(rig: &mut Rig, _: &mut Ctx) -> bool {
    rig.select(AID_PIV);
    rig.piv_verify("123456") == 0x9000
}

/// PIV CHANGE REFERENCE DATA (§3.2.2).
fn piv_change_pin(rig: &mut Rig, _: &mut Ctx) -> bool {
    let change = [piv::pin_block("123456"), piv::pin_block("654321")].concat();
    rig.apdu(&command(0x00, 0x24, 0x00, piv::PIN, &change, None)) == vec![0x90, 0x00]
}

/// OpenPGP VERIFY PW3 (spec §7.2.2).
fn pgp_verify_admin(rig: &mut Rig, _: &mut Ctx) -> bool {
    rig.select(AID_OPENPGP);
    rig.pgp_verify(0x83, pgp::PW3) == 0x9000
}

/// OpenPGP PUT DATA name (`5B`), algorithm attributes (`C1`), touch policy (`D6`,
/// Yubico UIF: on, button).
fn pgp_put_name(rig: &mut Rig, _: &mut Ctx) -> bool {
    rig.pgp_put(0x005B, b"Sweep<<Ann") == 0x9000
}

fn pgp_put_algorithm(rig: &mut Rig, _: &mut Ctx) -> bool {
    rig.pgp_put(0x00C1, &pgp::ECDSA_P256) == 0x9000
}

/// GENERATE ASYMMETRIC KEY PAIR for the signature key (spec §7.2.14).
fn pgp_generate(rig: &mut Rig, _: &mut Ctx) -> bool {
    let response = rig.send(&command(0x00, 0x47, 0x80, 0x00, &[0xB6, 0x00], Some(256)));
    split(&response).1 == 0x9000
}

fn pgp_put_uif(rig: &mut Rig, _: &mut Ctx) -> bool {
    rig.pgp_put(0x00D6, &[0x01, 0x20]) == 0x9000
}

/// OpenPGP VERIFY PW1 for signing (`81`).
fn pgp_verify_user(rig: &mut Rig, _: &mut Ctx) -> bool {
    rig.pgp_verify(0x81, pgp::PW1) == 0x9000
}

/// PSO: COMPUTE DIGITAL SIGNATURE with UIF: the signature counter (DO `93`) is saved
/// after the touch, before the signature is answered.
fn pgp_sign_with_touch(rig: &mut Rig, _: &mut Ctx) -> bool {
    let (seq, out) = rig.xfr(&Rig::pgp_sign_request(&[0x5A; 32]));
    assert!(data_block(&out, seq).is_none(), "the signature waits for the touch");
    let out = rig.tap();
    let response = data_block(&out, seq).unwrap();
    split(&response).1 == 0x9000
}

/// PIV VERIFY with the changed PIN.
fn piv_verify_new(rig: &mut Rig, _: &mut Ctx) -> bool {
    rig.select(AID_PIV);
    rig.piv_verify("654321") == 0x9000
}

/// YubiHSM Auth PUT CREDENTIAL.
fn hsm_put(rig: &mut Rig, _: &mut Ctx) -> bool {
    rig.select(AID_HSMAUTH);
    rig.apdu(&hsmauth::put(b"sweep", &[0x61; 16], &[0x62; 16], b"hsm-password-16b", false)) == vec![0x90, 0x00]
}

/// Security Domain PUT KEY of a new SCP03 key set over SCP03 (GP 2.3.1 §11.8). The
/// handshake saves too (lk-sd `handshake.rs`: INITIALIZE UPDATE spends one try of the
/// key set before answering, EXTERNAL AUTHENTICATE restores it), so it can fail.
fn sd_put_key(rig: &mut Rig, _: &mut Ctx) -> bool {
    rig.select(AID_SD);
    let Ok(mut session) = Scp03::try_open_with(rig, 0x00, &SCP03_DEFAULT_KEYS) else {
        return false;
    };
    let (data, expected) = session.put_key_data(0x02, &NEW_SCP03);
    let put = session.wrap(0x80, 0xD8, 0x00, 0x81, &data, Some(0));
    session.unwrap(&rig.apdu(&put)) == (expected, 0x9000)
}

type Step = (&'static str, fn(&mut Rig, &mut Ctx) -> bool);

const SCRIPT: [Step; 19] = [
    ("FIDO setPIN", fido_set_pin),
    ("FIDO PIN token", fido_token),
    ("FIDO MakeCredential after touch", fido_make_credential),
    ("OTP slot 1 over HID", otp_program),
    ("OTP button press", otp_press),
    ("Management WRITE CONFIG", mgmt_write_config),
    ("OATH PUT", oath_put_credential),
    ("PIV VERIFY", piv_verify),
    ("PIV CHANGE PIN", piv_change_pin),
    ("OpenPGP VERIFY PW3", pgp_verify_admin),
    ("OpenPGP PUT name", pgp_put_name),
    ("OpenPGP PUT algorithm", pgp_put_algorithm),
    ("OpenPGP GENERATE", pgp_generate),
    ("OpenPGP PUT UIF", pgp_put_uif),
    ("OpenPGP VERIFY PW1", pgp_verify_user),
    ("OpenPGP sign after touch", pgp_sign_with_touch),
    ("PIV VERIFY new PIN", piv_verify_new),
    ("YubiHSM Auth PUT", hsm_put),
    ("Security Domain PUT KEY", sd_put_key),
];

/// Every application's persistent state as a host reads it, through read-only
/// commands: FIDO GetInfo (`clientPin`, remaining discoverable credentials) and
/// getPINRetries; the OTP status report (version, programming sequence, touch level);
/// Management READ CONFIG; YKOATH LIST; PIV PIN/PUK metadata (Yubico `F7`) and the
/// attestation certificate (`5FFF01`); OpenPGP application related data (`6E`),
/// cardholder data (`65`), security support template (`7A`, signature counter) and the
/// attestation certificate (SELECT DATA occurrence 3, `7F21`); YubiHSM Auth LIST; the
/// Security Domain CPLC (`9F7F`) and key information (`E0`). Volatile state (PIN
/// tokens, verification status, sessions, the OATH salt that lk-oath persists only with
/// the first mutation, `docs/CONTRACTS.md` "Applications A") is left out.
#[derive(Debug, PartialEq, Eq)]
struct Reading {
    fido: (bool, u64, u64),
    otp: Vec<u8>,
    card: Vec<Vec<u8>>,
}

fn read_state(rig: &mut Rig) -> Reading {
    let cid = rig.ctaphid_init();
    let info = ctap::ok_value(&rig.cbor(cid, &ctap::request(ctap::cmd::GET_INFO, None)));
    let client_pin = ctap::get(&info, 4).map_get_text("clientPin").and_then(lk_codec::cbor::Value::as_bool).unwrap();
    let remaining = ctap::get(&info, 0x14).as_u64().unwrap();
    let retries = ctap::ok_value(&rig.cbor(cid, &ctap::pin_retries_request()));
    let retries = ctap::get(&retries, 3).as_u64().unwrap();
    let otp = rig.otp_feature()[1..7].to_vec();
    rig.power_on();
    let mut card = Vec::new();
    rig.select(AID_MGMT);
    card.push(rig.send(&[0x00, 0x1D, 0x00, 0x00, 0x00]));
    rig.select(AID_OATH);
    card.push(rig.send(&[0x00, 0xA1, 0x00, 0x00]));
    rig.select(AID_PIV);
    card.push(rig.send(&[0x00, 0xF7, 0x00, 0x80, 0x00]));
    card.push(rig.send(&[0x00, 0xF7, 0x00, 0x81, 0x00]));
    card.push(rig.send(&[0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xFF, 0x01, 0x00]));
    rig.select(AID_OPENPGP);
    for tag in [0x6E, 0x65, 0x7A] {
        card.push(rig.send(&[0x00, 0xCA, 0x00, tag, 0x00]));
    }
    card.push(rig.apdu(&[0x00, 0xA5, 0x03, 0x04, 0x06, 0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21]));
    card.push(rig.send(&[0x00, 0xCA, 0x7F, 0x21, 0x00]));
    rig.select(AID_HSMAUTH);
    card.push(rig.send(&hsmauth::LIST));
    rig.select(AID_SD);
    card.push(rig.send(&[0x80, 0xCA, 0x9F, 0x7F, 0x00]));
    card.push(rig.send(&[0x80, 0xCA, 0x00, 0xE0, 0x00]));
    rig.power_off();
    Reading {
        fido: (client_pin, remaining, retries),
        otp,
        card,
    }
}

/// Open a device whose store fails save attempt `fail_at`, run the script until that
/// save fails (or to its end), check the failing command reported no success, and
/// compare the state read before and after a restart. Returns the number of save
/// attempts and the step that failed.
fn run(fail_at: Option<usize>) -> (usize, Option<&'static str>) {
    let profile = DeviceProfile::yubikey_compat(SERIAL);
    let store = MemoryStore::new();
    let sweep = Rc::new(RefCell::new(Sweep {
        fail_at,
        ..Sweep::default()
    }));
    let dev = Device::open(
        profile.clone(),
        Box::new(SweepStore {
            inner: store.clone(),
            sweep: Rc::clone(&sweep),
        }),
        Box::new(SeededEntropy::new(1)),
        KEY,
    );
    let mut rig = Rig::from_parts(dev, store, profile, 1);
    let mut failed_step = sweep.borrow().failed.map(|_| "open");
    if failed_step.is_none() {
        let mut ctx = Ctx {
            cid: 0,
            entropy: SeededEntropy::new(7),
            token: Vec::new(),
        };
        ctx.cid = rig.ctaphid_init();
        for (name, step) in SCRIPT {
            rig.now += 1_000;
            let reported = step(&mut rig, &mut ctx);
            if sweep.borrow().failed.is_some() {
                assert!(!reported, "{name}: success reported although its save {fail_at:?} failed");
                failed_step = Some(name);
                break;
            }
            assert!(reported, "{name} failed without a store failure");
        }
    }
    rig.now += 1_000;
    let live = read_state(&mut rig);
    let attempts = sweep.borrow().attempts;
    rig.now += 1_000;
    rig.restart();
    assert!(rig.dev.unreadable_records().is_empty());
    let reopened = read_state(&mut rig);
    assert_eq!(
        live, reopened,
        "save attempt {fail_at:?} ({:?} during {failed_step:?}): memory and store disagree",
        sweep.borrow().failed
    );
    (attempts, failed_step)
}

/// `docs/DESIGN.md` §7 commit rule and `docs/CONTRACTS.md` "Persisted state" at every
/// failure point (module documentation).
#[test]
fn every_failed_save_leaves_memory_and_store_in_agreement() {
    let (total, failed) = run(None);
    assert_eq!(failed, None);
    assert!(total > 30, "the script saves {total} times");
    let mut steps = Vec::new();
    for k in 0..total {
        let (_, step) = run(Some(k));
        steps.push(step.unwrap_or_else(|| panic!("save attempt {k} never happened")));
    }
    assert!(steps.contains(&"open"), "constructor saves are swept");
    for (name, _) in SCRIPT {
        assert!(steps.contains(&name), "{name} was never hit by a failure");
    }
}

/// The constructor part of the sweep, for a store outage that lasts: a store that fails
/// every save while the device opens and for a while after. The Security Domain, PIV
/// and OpenPGP generate their identity in their constructors and keep it in memory
/// when its save fails (`docs/CONTRACTS.md` "Constructors may persist"; lk-sd "the next
/// successful mutation persists the whole state again"). The device saves that state
/// again before each later input (`Device::open`), so once the store works the identity
/// the host read (Security Domain CPLC, PIV attestation certificate `5FFF01`) is the one
/// a restart finds (`docs/DESIGN.md` §7).
#[test]
fn constructor_state_is_saved_once_the_store_recovers() {
    let store = MemoryStore::new();
    store.fail_all(true);
    let mut rig = Rig::with_store(DeviceProfile::yubikey_compat(SERIAL), store.clone(), 3);
    rig.power_on();
    rig.select(AID_SD);
    let cplc = rig.send(&[0x80, 0xCA, 0x9F, 0x7F, 0x00]);
    assert_eq!(split(&cplc).1, 0x9000);
    rig.select(AID_PIV);
    let attestation = rig.send(&[0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xFF, 0x01, 0x00]);
    assert_eq!(split(&attestation).1, 0x9000);
    for record in [Record::SecurityDomain, Record::Piv, Record::OpenPgp] {
        assert_eq!(store.get(record), None, "{record:?} not stored while the store fails");
    }
    rig.now += 1_000;
    store.fail_all(false);
    rig.input(lk_device::Input::Tick);
    for record in [Record::SecurityDomain, Record::Piv, Record::OpenPgp] {
        assert!(store.get(record).is_some(), "{record:?} stored at the first input after the outage");
    }
    let saves = store.save_count();
    rig.input(lk_device::Input::Tick);
    assert_eq!(store.save_count(), saves, "saved once, not again");
    rig.restart();
    rig.power_on();
    rig.select(AID_SD);
    assert_eq!(rig.send(&[0x80, 0xCA, 0x9F, 0x7F, 0x00]), cplc, "the CPLC the host read");
    rig.select(AID_PIV);
    assert_eq!(rig.send(&[0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xFF, 0x01, 0x00]), attestation);
}
