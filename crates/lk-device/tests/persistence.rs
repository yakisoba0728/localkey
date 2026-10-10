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
    assert_eq!(rig.select(AID_MGMT), b"5.7.4\x90\x00".to_vec());
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
