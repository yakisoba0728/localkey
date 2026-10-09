//! An in-memory [`Store`] with fault injection, for device-level tests.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use lk_core::{Record, Store, StoreError};

use crate::faults::{FaultInjector, RecordMap};

#[derive(Debug, Default)]
struct Inner {
    records: RecordMap,
    saves: FaultInjector,
    fail_loads: bool,
}

/// An in-memory [`Store`] whose writes can be made to fail on demand.
///
/// Cloning a `MemoryStore` gives another handle to the **same** storage, so a test can
/// move one handle into the device and keep another to inject faults and inspect what
/// was written. (The handles share state through `Arc<Mutex<_>>`, which keeps the store
/// `Send` whatever the device requires; no thread is ever started.)
///
/// Fault rules for [`Store::save`]:
/// - [`fail_next_saves(n)`](Self::fail_next_saves): the next `n` save attempts fail;
/// - [`fail_all(true)`](Self::fail_all): every save fails until `fail_all(false)`;
/// - each attempt consumes one pending failure even while `fail_all` is set;
/// - a failed save leaves the record's previous bytes untouched, as the `Store`
///   contract's atomicity rule requires.
///
/// Loads fail only while [`fail_loads(true)`](Self::fail_loads) is set.
///
/// # Examples
///
/// ```
/// use lk_core::{Record, Store};
/// use lk_testkit::MemoryStore;
///
/// let inspector = MemoryStore::new();
/// let mut store = inspector.clone(); // e.g. handed to the device under test
///
/// store.save(Record::Oath, b"v1").unwrap();
/// inspector.fail_next_saves(1);
/// assert!(store.save(Record::Oath, b"v2").is_err());
///
/// // The failed write kept the old bytes.
/// assert_eq!(inspector.get(Record::Oath), Some(b"v1".to_vec()));
/// assert_eq!(store.load(Record::Oath).unwrap(), Some(b"v1".to_vec()));
/// assert_eq!(inspector.save_count(), 1);
/// assert_eq!(inspector.save_attempts(), 2);
/// ```
#[derive(Debug, Clone, Default)]
pub struct MemoryStore {
    inner: Arc<Mutex<Inner>>,
}

impl MemoryStore {
    /// An empty store with no faults armed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Make the next `count` save attempts fail (replacing any count still pending).
    pub fn fail_next_saves(&self, count: usize) {
        self.lock().saves.fail_next(count);
    }

    /// While `fail` is true, every save fails.
    pub fn fail_all(&self, fail: bool) {
        self.lock().saves.fail_all(fail);
    }

    /// While `fail` is true, every load fails.
    pub fn fail_loads(&self, fail: bool) {
        self.lock().fail_loads = fail;
    }

    /// Number of saves that succeeded.
    pub fn save_count(&self) -> usize {
        self.lock().saves.successes()
    }

    /// Number of save calls, failed ones included.
    pub fn save_attempts(&self) -> usize {
        self.lock().saves.attempts()
    }

    /// The bytes currently stored for `record`.
    pub fn get(&self, record: Record) -> Option<Vec<u8>> {
        self.lock().records.get(record).map(<[u8]>::to_vec)
    }

    /// Store `bytes` for `record` directly, bypassing fault injection and counters
    /// (to set up existing or corrupted state before a test).
    pub fn insert(&self, record: Record, bytes: &[u8]) {
        self.lock().records.insert(record, bytes);
    }

    /// Forget `record`, bypassing fault injection and counters.
    pub fn remove(&self, record: Record) {
        self.lock().records.remove(record);
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A panic while holding the lock can only come from a failing test; the data is
        // still consistent because every critical section is a single field update.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Store for MemoryStore {
    fn load(&mut self, record: Record) -> Result<Option<Vec<u8>>, StoreError> {
        let inner = self.lock();
        if inner.fail_loads {
            return Err(StoreError("injected read failure".into()));
        }
        Ok(inner.records.get(record).map(<[u8]>::to_vec))
    }

    fn save(&mut self, record: Record, sealed: &[u8]) -> Result<(), StoreError> {
        let mut inner = self.lock();
        inner.saves.attempt()?;
        inner.records.insert(record, sealed);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_of_missing_record_is_none() {
        let mut store = MemoryStore::new();
        assert_eq!(store.load(Record::Piv), Ok(None));
    }

    #[test]
    fn records_are_independent() {
        let mut store = MemoryStore::new();
        assert_eq!(store.save(Record::Fido, b"fido"), Ok(()));
        assert_eq!(store.save(Record::Piv, b"piv"), Ok(()));
        assert_eq!(store.load(Record::Fido), Ok(Some(b"fido".to_vec())));
        assert_eq!(store.load(Record::Piv), Ok(Some(b"piv".to_vec())));
        assert_eq!(store.load(Record::Otp), Ok(None));
    }

    #[test]
    fn save_overwrites_previous_bytes() {
        let mut store = MemoryStore::new();
        assert_eq!(store.save(Record::Otp, b"old"), Ok(()));
        assert_eq!(store.save(Record::Otp, b"new"), Ok(()));
        assert_eq!(store.get(Record::Otp), Some(b"new".to_vec()));
        assert_eq!(store.save_count(), 2);
    }

    #[test]
    fn fail_next_saves_fails_exactly_n_and_keeps_old_bytes() {
        let mut store = MemoryStore::new();
        store.insert(Record::Oath, b"before");
        store.fail_next_saves(2);
        assert!(store.save(Record::Oath, b"a").is_err());
        assert!(store.save(Record::Fido, b"b").is_err());
        assert_eq!(store.get(Record::Oath), Some(b"before".to_vec()));
        assert_eq!(store.get(Record::Fido), None);
        assert_eq!(store.save(Record::Oath, b"after"), Ok(()));
        assert_eq!(store.get(Record::Oath), Some(b"after".to_vec()));
        assert_eq!((store.save_count(), store.save_attempts()), (1, 3));
    }

    #[test]
    fn fail_all_fails_until_cleared() {
        let mut store = MemoryStore::new();
        store.fail_all(true);
        for _ in 0..3 {
            assert!(store.save(Record::Device, b"x").is_err());
        }
        assert_eq!(store.get(Record::Device), None);
        store.fail_all(false);
        assert_eq!(store.save(Record::Device, b"x"), Ok(()));
        assert_eq!(store.get(Record::Device), Some(b"x".to_vec()));
    }

    #[test]
    fn fail_loads_only_affects_loads() {
        let mut store = MemoryStore::new();
        assert_eq!(store.save(Record::HsmAuth, b"h"), Ok(()));
        store.fail_loads(true);
        assert!(store.load(Record::HsmAuth).is_err());
        assert_eq!(store.save(Record::HsmAuth, b"i"), Ok(()));
        store.fail_loads(false);
        assert_eq!(store.load(Record::HsmAuth), Ok(Some(b"i".to_vec())));
    }

    #[test]
    fn insert_and_remove_bypass_counters_and_faults() {
        let store = MemoryStore::new();
        store.fail_all(true);
        store.insert(Record::SecurityDomain, b"sd");
        assert_eq!(store.get(Record::SecurityDomain), Some(b"sd".to_vec()));
        store.remove(Record::SecurityDomain);
        assert_eq!(store.get(Record::SecurityDomain), None);
        assert_eq!(store.save_attempts(), 0);
    }

    #[test]
    fn clones_share_state() {
        let a = MemoryStore::new();
        let mut b = a.clone();
        a.fail_next_saves(1);
        assert!(b.save(Record::OpenPgp, b"p").is_err());
        assert_eq!(b.save(Record::OpenPgp, b"p"), Ok(()));
        assert_eq!(a.get(Record::OpenPgp), Some(b"p".to_vec()));
        assert_eq!(a.save_count(), 1);
    }

    #[test]
    fn usable_as_boxed_send_store() {
        fn takes(_: Box<dyn Store + Send>) {}
        takes(Box::new(MemoryStore::new()));
    }

    #[test]
    fn failed_save_leaves_every_record_untouched() {
        // lk_core::Store: a failed save keeps the old bytes, and records are independent.
        let mut store = MemoryStore::new();
        store.insert(Record::Fido, b"fido v1");
        store.insert(Record::Piv, b"piv v1");
        store.fail_next_saves(1);
        assert!(store.save(Record::Piv, b"piv v2").is_err());
        store.fail_all(true);
        assert!(store.save(Record::Oath, b"oath v1").is_err());
        assert_eq!(store.get(Record::Fido), Some(b"fido v1".to_vec()));
        assert_eq!(store.get(Record::Piv), Some(b"piv v1".to_vec()));
        assert_eq!(store.get(Record::Oath), None);
        assert_eq!((store.save_count(), store.save_attempts()), (0, 2));
    }

    #[test]
    fn empty_record_is_distinct_from_a_missing_one() {
        let mut store = MemoryStore::new();
        assert_eq!(store.save(Record::Fido, b""), Ok(()));
        assert_eq!(store.load(Record::Fido), Ok(Some(Vec::new())));
        assert_eq!(store.load(Record::Otp), Ok(None));
    }

    #[test]
    fn loads_change_nothing_and_are_not_counted() {
        let mut store = MemoryStore::new();
        assert_eq!(store.save(Record::Device, b"d"), Ok(()));
        store.fail_loads(true);
        for _ in 0..3 {
            assert!(store.load(Record::Device).is_err());
        }
        store.fail_loads(false);
        assert_eq!(store.load(Record::Device), Ok(Some(b"d".to_vec())));
        assert_eq!((store.save_count(), store.save_attempts()), (1, 1));
    }

    #[test]
    fn counters_are_exact_across_handles() {
        // Faults armed through one handle apply to saves through another, and both
        // handles report the same counts.
        let inspector = MemoryStore::new();
        let mut device = inspector.clone();
        inspector.fail_next_saves(5);
        inspector.fail_next_saves(2); // replaces the 5
        let outcomes: Vec<bool> = (0..4).map(|i| device.save(Record::Otp, &[i]).is_ok()).collect();
        assert_eq!(outcomes, [false, false, true, true]);
        inspector.fail_all(true);
        assert!(device.save(Record::Otp, b"lost").is_err());
        assert_eq!(inspector.get(Record::Otp), Some(vec![3]));
        assert_eq!((inspector.save_count(), inspector.save_attempts()), (2, 5));
        assert_eq!((device.save_count(), device.save_attempts()), (2, 5));
    }
}
