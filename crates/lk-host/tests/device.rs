//! The program's storage under the real engine: `lk_device::Device` opened over a
//! [`FileStore`] with a storage key, then reopened with the same key and with a wrong one
//! (`docs/PROGRAM.md` "lk-host"; `docs/CONTRACTS.md` "Final integration (as built,
//! binding)": constructor saves never overwrite an unreadable record, and nothing at all
//! is written while the storage key is unconfirmed).

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use lk_core::{DeviceProfile, Record};
use lk_crypto::SecretBytes;
use lk_device::{Device, storage};
use lk_host::{FileStore, HostError, OsEntropy, generate_key, load_or_create_serial, record_name, to_array};

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

/// A fresh directory `<temp>/lkhd<pid>`, removed on drop.
struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("lkhd{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn open_device(dir: &Path, serial: u32, key: &SecretBytes) -> Device {
    let store = FileStore::open(dir).unwrap();
    Device::open(DeviceProfile::own(serial), Box::new(store), Box::new(OsEntropy::open().unwrap()), to_array(key))
}

/// Every file in `dir` with its bytes.
fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(dir)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (entry.file_name().to_string_lossy().into_owned(), fs::read(entry.path()).unwrap())
        })
        .collect()
}

/// The records that have a file in `dir`.
fn stored_records(dir: &Path) -> Vec<Record> {
    ALL.into_iter().filter(|&record| dir.join(format!("{}.rec", record_name(record))).exists()).collect()
}

#[test]
fn a_device_reopens_its_records_with_the_right_key_and_never_rewrites_them_with_a_wrong_one() {
    let dir = TestDir::new();
    let mut entropy = OsEntropy::open().unwrap();
    let key = generate_key(&mut entropy);

    // First run: the constructors persist the identities they create.
    let serial = {
        let store = FileStore::open(dir.path()).unwrap();
        let serial = load_or_create_serial(store.dir(), &mut entropy).unwrap();
        drop(store);
        let device = open_device(dir.path(), serial, &key);
        assert!(device.unreadable_records().is_empty());
        // The device owns the store, and with it the directory's lock.
        assert!(matches!(FileStore::open(dir.path()), Err(HostError::Locked { .. })));
        serial
    };
    let stored = stored_records(dir.path());
    for record in [Record::SecurityDomain, Record::Piv, Record::OpenPgp, Record::Oath] {
        assert!(stored.contains(&record), "{record:?} was not persisted at first open");
    }
    // The files hold exactly the sealed records, which open under the key.
    for &record in &stored {
        let sealed = fs::read(dir.path().join(format!("{}.rec", record_name(record)))).unwrap();
        assert_eq!(sealed.first(), Some(&storage::FORMAT_VERSION));
        assert!(storage::open(&to_array(&key), record, &sealed).is_ok(), "{record:?}");
    }

    // Same key: everything opens.
    let device = open_device(dir.path(), serial, &key);
    assert!(device.unreadable_records().is_empty());
    drop(device);

    // Wrong key: every stored record is unreadable, and no file changes or appears.
    let before = snapshot(dir.path());
    let wrong = generate_key(&mut entropy);
    assert_ne!(wrong, key);
    let device = open_device(dir.path(), serial, &wrong);
    let mut unreadable = device.unreadable_records().to_vec();
    unreadable.sort_by_key(|&record| storage::record_id(record));
    assert_eq!(unreadable, stored);
    drop(device);
    assert_eq!(snapshot(dir.path()), before);

    // The right key still opens everything afterwards.
    let device = open_device(dir.path(), serial, &key);
    assert!(device.unreadable_records().is_empty());
    assert_eq!(device.profile().serial, serial);
}
