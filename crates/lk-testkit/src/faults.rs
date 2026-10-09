//! Pieces shared by [`MemoryStore`](crate::MemoryStore) and [`TestHost`](crate::TestHost):
//! a per-[`Record`] byte map and a write fault injector.

use lk_core::{Record, StoreError};

/// Number of [`Record`] variants; [`slot`] maps each one to a distinct index below it.
const RECORD_COUNT: usize = 8;

/// A fixed index for each record. The match is exhaustive, so a new `Record` variant
/// fails to compile here instead of silently sharing a slot.
fn slot(record: Record) -> usize {
    match record {
        Record::Device => 0,
        Record::Fido => 1,
        Record::Oath => 2,
        Record::Otp => 3,
        Record::Piv => 4,
        Record::OpenPgp => 5,
        Record::HsmAuth => 6,
        Record::SecurityDomain => 7,
    }
}

/// Bytes stored per record. An array rather than a `HashMap`, which would seed its
/// hasher from OS randomness.
#[derive(Debug, Clone, Default)]
pub(crate) struct RecordMap {
    slots: [Option<Vec<u8>>; RECORD_COUNT],
}

impl RecordMap {
    pub(crate) fn get(&self, record: Record) -> Option<&[u8]> {
        self.slots[slot(record)].as_deref()
    }

    pub(crate) fn insert(&mut self, record: Record, bytes: &[u8]) {
        self.slots[slot(record)] = Some(bytes.to_vec());
    }

    pub(crate) fn remove(&mut self, record: Record) {
        self.slots[slot(record)] = None;
    }
}

/// Decides whether the next write fails, and counts writes.
///
/// Rules, shared by every write path that uses it:
/// - each attempt consumes one pending failure from [`fail_next`](Self::fail_next), if any;
/// - an attempt fails if it consumed a pending failure or [`fail_all`](Self::fail_all) is set;
/// - a failed write changes no stored bytes.
#[derive(Debug, Clone, Default)]
pub(crate) struct FaultInjector {
    pending: usize,
    all: bool,
    attempts: usize,
    successes: usize,
}

impl FaultInjector {
    pub(crate) fn fail_next(&mut self, count: usize) {
        self.pending = count;
    }

    pub(crate) fn fail_all(&mut self, fail: bool) {
        self.all = fail;
    }

    /// Record one write attempt; `Err` means the caller must not apply the write.
    ///
    /// Counters saturate instead of overflowing, so a long fuzz loop cannot panic here.
    pub(crate) fn attempt(&mut self) -> Result<(), StoreError> {
        self.attempts = self.attempts.saturating_add(1);
        let consumed = self.pending > 0;
        self.pending = self.pending.saturating_sub(1);
        if consumed || self.all {
            return Err(StoreError("injected write failure".into()));
        }
        self.successes = self.successes.saturating_add(1);
        Ok(())
    }

    pub(crate) fn attempts(&self) -> usize {
        self.attempts
    }

    pub(crate) fn successes(&self) -> usize {
        self.successes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Record; RECORD_COUNT] = [
        Record::Device,
        Record::Fido,
        Record::Oath,
        Record::Otp,
        Record::Piv,
        Record::OpenPgp,
        Record::HsmAuth,
        Record::SecurityDomain,
    ];

    #[test]
    fn every_record_has_its_own_slot() {
        let mut map = RecordMap::default();
        for (i, record) in ALL.into_iter().enumerate() {
            map.insert(record, &[i as u8]);
        }
        for (i, record) in ALL.into_iter().enumerate() {
            assert_eq!(map.get(record), Some(&[i as u8][..]));
        }
        map.remove(Record::Oath);
        assert_eq!(map.get(Record::Oath), None);
        assert_eq!(map.get(Record::Otp), Some(&[3u8][..]));
    }

    #[test]
    fn pending_failures_are_consumed_in_order() {
        let mut faults = FaultInjector::default();
        faults.fail_next(2);
        assert!(faults.attempt().is_err());
        assert!(faults.attempt().is_err());
        assert!(faults.attempt().is_ok());
        assert_eq!((faults.attempts(), faults.successes()), (3, 1));
    }

    #[test]
    fn fail_all_holds_until_cleared_and_still_consumes_pending() {
        let mut faults = FaultInjector::default();
        faults.fail_next(1);
        faults.fail_all(true);
        assert!(faults.attempt().is_err());
        assert!(faults.attempt().is_err());
        faults.fail_all(false);
        // The pending failure was used up by the first attempt above.
        assert!(faults.attempt().is_ok());
        assert_eq!((faults.attempts(), faults.successes()), (3, 1));
    }

    #[test]
    fn fail_next_replaces_the_pending_count() {
        let mut faults = FaultInjector::default();
        faults.fail_next(5);
        faults.fail_next(1);
        assert!(faults.attempt().is_err());
        assert!(faults.attempt().is_ok(), "the earlier count of 5 was replaced, not added to");
        faults.fail_next(3);
        faults.fail_next(0);
        assert!(faults.attempt().is_ok(), "fail_next(0) disarms pending failures");
        assert_eq!((faults.attempts(), faults.successes()), (3, 2));
    }

    #[test]
    fn counters_are_exact_over_a_mixed_sequence() {
        // Each step: (arm pending, set fail_all, expected outcome of one attempt). The
        // expectations follow the documented rules, worked out by hand.
        let steps: [(Option<usize>, Option<bool>, bool); 9] = [
            (Some(2), Some(true), false), // pending 2 -> 1, fail_all
            (None, Some(false), false),   // pending 1 -> 0
            (None, None, true),
            (None, Some(true), false), // fail_all alone
            (None, None, false),
            (Some(1), Some(false), false), // pending 1 -> 0
            (None, None, true),
            (Some(0), None, true),
            (None, None, true),
        ];
        let mut faults = FaultInjector::default();
        let mut successes = 0;
        for (i, (pending, all, ok)) in steps.into_iter().enumerate() {
            if let Some(count) = pending {
                faults.fail_next(count);
            }
            if let Some(fail) = all {
                faults.fail_all(fail);
            }
            assert_eq!(faults.attempt().is_ok(), ok, "step {i}");
            successes += usize::from(ok);
            assert_eq!((faults.attempts(), faults.successes()), (i + 1, successes), "step {i}");
        }
    }

    #[test]
    fn counters_saturate() {
        let mut faults = FaultInjector { attempts: usize::MAX, successes: usize::MAX, ..FaultInjector::default() };
        assert!(faults.attempt().is_ok());
        assert_eq!((faults.attempts(), faults.successes()), (usize::MAX, usize::MAX));
    }
}
