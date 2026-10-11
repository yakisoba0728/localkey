//! Persistence through the device: sealing, restart, and unreadable records
//! (docs/DESIGN.md §7; docs/CONTRACTS.md "Persisted state", "lk-device::storage").

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use lk_core::{DeviceProfile, Record};
use lk_device::{Device, storage};
use lk_testkit::{MemoryStore, SeededEntropy};

const ALL: [Record; 8] = [
    Record::Device,
    Record::Fido,
    Record::Oath,
    Record::Otp,
    Record::Piv,
    Record::OpenPgp,
    Record::HsmAuth,
    Record::SecurityDomain,
];

const OATH_LIST: [u8; 4] = [0x00, 0xA1, 0x00, 0x00];
/// GP 2.3.1 §11.3 GET DATA CPLC (`9F7F`).
const SD_CPLC: [u8; 5] = [0x80, 0xCA, 0x9F, 0x7F, 0x00];

/// docs/DESIGN.md §7: the store only sees sealed bytes; every record the device wrote
/// opens with the storage key under its own record id (format `01 || nonce || ct || tag`).
#[test]
fn records_are_sealed_with_the_storage_key() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_OATH);
    rig.apdu(&oath_put(b"sealed-name", false));
    let mut seen = 0;
    for record in ALL {
        let Some(bytes) = rig.store.get(record) else { continue };
        seen += 1;
        assert_eq!(bytes[0], storage::FORMAT_VERSION);
        let plaintext = storage::open(&KEY, record, &bytes).unwrap();
        assert_eq!(plaintext[0], 0x01, "application record version byte ({record:?})");
        assert!(!bytes.windows(11).any(|w| w == b"sealed-name"), "plaintext leaked ({record:?})");
    }
    assert!(seen >= 2, "OATH and the Security Domain identity at least");
    assert!(storage::open(&[0; 32], Record::Oath, &rig.store.get(Record::Oath).unwrap()).is_err());
}

/// docs/DESIGN.md §7 "restart persistence": state written before a restart is there
/// after it; the Security Domain identity (CPLC) is stable.
#[test]
fn state_survives_restart() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_OATH);
    rig.apdu(&oath_put(b"persist", false));
    rig.select(AID_SD);
    let cplc = rig.apdu(&SD_CPLC);
    assert_eq!(sw(&cplc), 0x9000);
    rig.restart();
    assert!(rig.dev.unreadable_records().is_empty());
    rig.power_on();
    rig.select(AID_OATH);
    let list = rig.apdu(&OATH_LIST);
    assert_eq!(&list[3..10], b"persist");
    rig.select(AID_SD);
    assert_eq!(rig.apdu(&SD_CPLC), cplc);
}

/// docs/CONTRACTS.md: "a record that fails to open is treated as factory state for that
/// application only, never a panic".
#[test]
fn one_corrupt_record_gives_factory_state_for_that_application_only() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_OATH);
    rig.apdu(&oath_put(b"lost", false));
    rig.select(AID_SD);
    let cplc = rig.apdu(&SD_CPLC);
    let mut bytes = rig.store.get(Record::Oath).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    rig.store.insert(Record::Oath, &bytes);
    rig.restart();
    assert_eq!(rig.dev.unreadable_records(), &[Record::Oath]);
    rig.power_on();
    rig.select(AID_OATH);
    assert_eq!(rig.apdu(&OATH_LIST), vec![0x90, 0x00], "OATH starts empty");
    rig.select(AID_SD);
    assert_eq!(rig.apdu(&SD_CPLC), cplc, "the Security Domain kept its record");
}

/// The AAD binds the record id (storage.rs): bytes sealed for one record never open as
/// another.
#[test]
fn record_moved_to_another_name_is_unreadable() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_OATH);
    rig.apdu(&oath_put(b"moved", false));
    let bytes = rig.store.get(Record::Oath).unwrap();
    rig.store.insert(Record::HsmAuth, &bytes);
    rig.restart();
    assert_eq!(rig.dev.unreadable_records(), &[Record::HsmAuth]);
    rig.power_on();
    rig.select(AID_OATH);
    assert_eq!(&rig.apdu(&OATH_LIST)[3..8], b"moved");
}

/// A wrong storage key opens nothing; every application starts from factory state and
/// the device still works.
#[test]
fn wrong_storage_key_gives_factory_state() {
    let store = MemoryStore::new();
    let profile = DeviceProfile::yubikey_5c_nano_5_7_4(SERIAL);
    drop(Device::open(profile.clone(), Box::new(store.clone()), Box::new(SeededEntropy::new(1)), KEY));
    let written: Vec<Record> = ALL.into_iter().filter(|&r| store.get(r).is_some()).collect();
    assert!(!written.is_empty());
    let dev = Device::open(profile, Box::new(store.clone()), Box::new(SeededEntropy::new(2)), [0x11; 32]);
    assert_eq!(dev.unreadable_records(), written.as_slice());
}

/// A failing store load is unreadable state for every record, never a panic.
#[test]
fn failing_loads_give_factory_state() {
    let store = MemoryStore::new();
    store.fail_loads(true);
    let mut rig = Rig::with_store(DeviceProfile::yubikey_5c_nano_5_7_4(SERIAL), store, 3);
    assert_eq!(rig.dev.unreadable_records(), &ALL);
    rig.power_on();
    // The Management SELECT text as measured (docs/MEASUREMENT.md, probe `select-mgmt`).
    assert_eq!(rig.select(AID_MGMT), b"Virtual mgr - FW version 5.7.4\x90\x00".to_vec());
}

/// A restart reads the identities created at first start and writes nothing back
/// (constructors persist only factory material, docs/CONTRACTS.md "Applications B").
#[test]
fn restart_does_not_rewrite_records() {
    let mut rig = Rig::new();
    let saves = rig.store.save_count();
    let before: Vec<Option<Vec<u8>>> = ALL.iter().map(|&r| rig.store.get(r)).collect();
    rig.restart();
    assert_eq!(rig.store.save_count(), saves);
    let after: Vec<Option<Vec<u8>>> = ALL.iter().map(|&r| rig.store.get(r)).collect();
    assert_eq!(before, after);
}

/// docs/DESIGN.md §7 "failure rollback": a failed save on one record leaves the others
/// and the previous state of that record (here: Management after an OATH failure).
#[test]
fn failed_save_rolls_back_only_that_command() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_OATH);
    rig.apdu(&oath_put(b"first", false));
    let stored = rig.store.get(Record::Oath);
    rig.store.fail_all(true);
    assert_eq!(rig.apdu(&oath_put(b"second", false)), vec![0x65, 0x81]);
    rig.store.fail_all(false);
    assert_eq!(rig.store.get(Record::Oath), stored);
    rig.restart();
    rig.power_on();
    rig.select(AID_OATH);
    let list = rig.apdu(&OATH_LIST);
    assert_eq!(&list[3..8], b"first");
    assert_eq!(list.len(), 2 + 3 + 5);
}

/// The records whose application creates its own identity at first start
/// (docs/CONTRACTS.md "Constructors may persist").
const IDENTITY_RECORDS: [Record; 3] = [Record::Piv, Record::OpenPgp, Record::SecurityDomain];

/// Second device review, regression: opening with a wrong storage key wrote the
/// constructor identities of applications whose record was absent (here PIV, OpenPGP and
/// the Security Domain, as for a store whose identity records were never taken or an
/// application newer than the store), sealed under the wrong key. Once the program
/// supplied the right key those records were unreadable, so the identities could never
/// again be saved at open and changed at every start. Now a key that no record confirms
/// (none opened, some unreadable) writes nothing at open, and the right key later
/// creates and keeps the identities (`apps::protected_at_open`).
#[test]
fn unconfirmed_key_writes_no_identity_for_absent_records() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_OATH);
    rig.apdu(&oath_put(b"kept", false));
    for record in IDENTITY_RECORDS {
        rig.store.remove(record);
    }
    let saves = rig.store.save_count();
    let profile = DeviceProfile::yubikey_5c_nano_5_7_4(SERIAL);
    let mut wrong = Device::open(profile, Box::new(rig.store.clone()), Box::new(SeededEntropy::new(40)), [0x11; 32]);
    assert_eq!(wrong.unreadable_records(), &[Record::Oath]);
    // Inputs retry deferred constructor saves; skipped ones are not deferred.
    wrong.handle(10, lk_device::Input::Tick);
    wrong.handle(20, lk_device::Input::Tick);
    assert_eq!(rig.store.save_count(), saves, "nothing sealed under an unconfirmed key");
    for record in IDENTITY_RECORDS {
        assert_eq!(rig.store.get(record), None, "{record:?} still absent");
    }
    drop(wrong);

    rig.restart();
    assert!(rig.dev.unreadable_records().is_empty());
    for record in IDENTITY_RECORDS {
        let sealed = rig.store.get(record).unwrap_or_else(|| panic!("{record:?} created under the right key"));
        assert!(storage::open(&KEY, record, &sealed).is_ok(), "{record:?} sealed under the right key");
    }
    rig.power_on();
    rig.select(AID_OATH);
    assert_eq!(&rig.apdu(&OATH_LIST)[3..7], b"kept");
    rig.select(AID_SD);
    let cplc = rig.apdu(&SD_CPLC);
    assert_eq!(sw(&cplc), 0x9000);
    rig.restart();
    rig.power_on();
    rig.select(AID_SD);
    assert_eq!(rig.apdu(&SD_CPLC), cplc, "the identity created then is kept");
}

/// The mirror case of `unconfirmed_key_writes_no_identity_for_absent_records`: one
/// record that opens proves the key right (AES-GCM authenticates it), so a damaged
/// record is protected but the absent identities are created and saved at open, and stay
/// the same at the next start.
#[test]
fn confirmed_key_saves_absent_identities_next_to_a_damaged_record() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_OATH);
    rig.apdu(&oath_put(b"damaged", false));
    let mut damaged = rig.store.get(Record::Oath).unwrap();
    let last = damaged.len() - 1;
    damaged[last] ^= 0x01;
    rig.store.insert(Record::Oath, &damaged);
    rig.store.remove(Record::Piv);
    rig.store.remove(Record::OpenPgp);
    assert!(rig.store.get(Record::SecurityDomain).is_some(), "a record that opens");
    rig.restart();
    assert_eq!(rig.dev.unreadable_records(), &[Record::Oath]);
    assert_eq!(rig.store.get(Record::Oath), Some(damaged), "the damaged record is not overwritten");
    let piv = rig.store.get(Record::Piv).expect("PIV identity saved at open");
    let openpgp = rig.store.get(Record::OpenPgp).expect("OpenPGP identity saved at open");
    rig.restart();
    assert_eq!(rig.store.get(Record::Piv), Some(piv), "PIV identity kept");
    assert_eq!(rig.store.get(Record::OpenPgp), Some(openpgp), "OpenPGP identity kept");
}
