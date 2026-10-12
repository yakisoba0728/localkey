//! An in-memory [`Host`] for application-level tests.

use lk_core::{DeviceProfile, Entropy, Host, Millis, Record, StoreError};

use crate::entropy::ScriptedEntropy;
use crate::faults::{FaultInjector, RecordMap};

/// A [`Host`] with settable time, a fixed profile, deterministic entropy and an
/// in-memory, fault-injectable record map.
///
/// - Time starts at 0 and changes only through [`set_now`](Self::set_now) and
///   [`advance`](Self::advance).
/// - The profile defaults to `DeviceProfile::own(12345678)`
///   ([`DEFAULT_SERIAL`](Self::DEFAULT_SERIAL)); [`with_profile`](Self::with_profile)
///   takes any other.
/// - Entropy is a [`ScriptedEntropy`] seeded with [`DEFAULT_SEED`](Self::DEFAULT_SEED)
///   (change it with [`seeded`](Self::seeded)); [`push_entropy`](Self::push_entropy)
///   scripts the next random bytes, for example a known private key.
/// - [`Host::persist`] stores the plaintext per [`Record`]. It follows the same fault
///   rules as [`MemoryStore`](crate::MemoryStore): [`fail_next_saves`](Self::fail_next_saves)
///   and [`fail_all`](Self::fail_all) make persists fail, and a failed persist keeps the
///   previous bytes.
///
/// # Examples
///
/// ```
/// use lk_core::{Entropy, Host, Record};
/// use lk_testkit::TestHost;
///
/// let mut host = TestHost::new();
/// assert_eq!(host.profile().serial, 12345678);
///
/// host.advance(1500);
/// assert_eq!(host.now(), 1500);
///
/// assert!(host.persist(Record::Oath, b"state v1").is_ok());
/// host.fail_next_saves(1);
/// assert!(host.persist(Record::Oath, b"state v2").is_err());
/// assert_eq!(host.persisted(Record::Oath), Some(b"state v1".to_vec()));
/// assert_eq!(host.persist_count(), 1);
///
/// // Script the next random bytes, e.g. a challenge the test wants to know.
/// host.push_entropy(&[0xde, 0xad]);
/// let mut challenge = [0u8; 2];
/// host.fill(&mut challenge);
/// assert_eq!(challenge, [0xde, 0xad]);
/// ```
///
/// An applet that reloads its state is built from what it last persisted:
///
/// ```
/// # use lk_core::{Host, Record};
/// # use lk_testkit::TestHost;
/// # struct Applet;
/// # impl Applet { fn new(_: Option<&[u8]>, _: &mut dyn Host) -> Self { Applet } }
/// let mut host = TestHost::new();
/// let _applet = Applet::new(host.persisted(Record::Piv).as_deref(), &mut host);
/// ```
#[derive(Debug, Clone)]
pub struct TestHost {
    now: Millis,
    profile: DeviceProfile,
    entropy: ScriptedEntropy,
    records: RecordMap,
    persists: FaultInjector,
}

impl TestHost {
    /// Serial number of the default profile.
    pub const DEFAULT_SERIAL: u32 = 12_345_678;
    /// Entropy seed of a new host.
    pub const DEFAULT_SEED: u64 = 0;

    /// A host with `DeviceProfile::own(DEFAULT_SERIAL)`.
    pub fn new() -> Self {
        Self::with_profile(DeviceProfile::own(Self::DEFAULT_SERIAL))
    }

    /// A host presenting `profile`, e.g. `DeviceProfile::yubikey_compat(serial)`.
    pub fn with_profile(profile: DeviceProfile) -> Self {
        Self {
            now: 0,
            profile,
            entropy: ScriptedEntropy::new(Self::DEFAULT_SEED, [] as [&[u8]; 0]),
            records: RecordMap::default(),
            persists: FaultInjector::default(),
        }
    }

    /// Replace the entropy with a fresh stream for `seed` (dropping any scripted bytes).
    pub fn seeded(mut self, seed: u64) -> Self {
        self.entropy = ScriptedEntropy::new(seed, [] as [&[u8]; 0]);
        self
    }

    /// Set the current time.
    pub fn set_now(&mut self, now: Millis) {
        self.now = now;
    }

    /// Move the current time forward by `ms`.
    pub fn advance(&mut self, ms: Millis) {
        self.now = self.now.saturating_add(ms);
    }

    /// Mutable access to the profile, to change one field for a test.
    pub fn profile_mut(&mut self) -> &mut DeviceProfile {
        &mut self.profile
    }

    /// Return `bytes` from the next entropy draws, before the seeded stream continues.
    pub fn push_entropy(&mut self, bytes: &[u8]) {
        self.entropy.push(bytes);
    }

    /// The entropy source, to inspect or extend its script.
    pub fn entropy_mut(&mut self) -> &mut ScriptedEntropy {
        &mut self.entropy
    }

    /// Make the next `count` persists fail (replacing any count still pending).
    pub fn fail_next_saves(&mut self, count: usize) {
        self.persists.fail_next(count);
    }

    /// While `fail` is true, every persist fails.
    pub fn fail_all(&mut self, fail: bool) {
        self.persists.fail_all(fail);
    }

    /// The plaintext last persisted for `record`.
    pub fn persisted(&self, record: Record) -> Option<Vec<u8>> {
        self.records.get(record).map(<[u8]>::to_vec)
    }

    /// Number of persists that succeeded.
    pub fn persist_count(&self) -> usize {
        self.persists.successes()
    }

    /// Number of persist calls, failed ones included.
    pub fn persist_attempts(&self) -> usize {
        self.persists.attempts()
    }

    /// Store `plaintext` for `record` directly, bypassing fault injection and counters.
    pub fn set_persisted(&mut self, record: Record, plaintext: &[u8]) {
        self.records.insert(record, plaintext);
    }

    /// Forget `record`, bypassing fault injection and counters.
    pub fn clear_persisted(&mut self, record: Record) {
        self.records.remove(record);
    }
}

impl Default for TestHost {
    fn default() -> Self {
        Self::new()
    }
}

impl Entropy for TestHost {
    fn fill(&mut self, out: &mut [u8]) {
        self.entropy.fill(out);
    }
}

impl Host for TestHost {
    fn now(&self) -> Millis {
        self.now
    }

    fn profile(&self) -> &DeviceProfile {
        &self.profile
    }

    fn persist(&mut self, record: Record, plaintext: &[u8]) -> Result<(), StoreError> {
        self.persists.attempt()?;
        self.records.insert(record, plaintext);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SeededEntropy;

    #[test]
    fn default_profile_is_own_with_default_serial() {
        let host = TestHost::default();
        assert_eq!(host.profile(), &DeviceProfile::own(12_345_678));
        assert_eq!(host.now(), 0);
    }

    #[test]
    fn with_profile_uses_the_given_profile() {
        let profile = DeviceProfile::yubikey_compat(31_415_926);
        let host = TestHost::with_profile(profile.clone());
        assert_eq!(host.profile(), &profile);
    }

    #[test]
    fn profile_mut_changes_the_profile() {
        let mut host = TestHost::new();
        host.profile_mut().serial = 1;
        assert_eq!(host.profile().serial, 1);
    }

    #[test]
    fn time_is_set_and_advanced() {
        let mut host = TestHost::new();
        host.set_now(10);
        host.advance(5);
        assert_eq!(host.now(), 15);
        host.advance(Millis::MAX);
        assert_eq!(host.now(), Millis::MAX);
    }

    #[test]
    fn entropy_is_the_default_seeded_stream() {
        let mut host = TestHost::new();
        let mut out = [0u8; 48];
        host.fill(&mut out);
        assert_eq!(out.to_vec(), SeededEntropy::new(TestHost::DEFAULT_SEED).bytes(48));
    }

    #[test]
    fn seeded_changes_the_stream_and_scripted_bytes_come_first() {
        let mut host = TestHost::new().seeded(77);
        host.push_entropy(&[1, 2]);
        assert_eq!(host.entropy_mut().scripted_remaining(), 2);
        let mut out = [0u8; 6];
        host.fill(&mut out);
        assert_eq!(out[..2], [1, 2]);
        assert_eq!(out[2..], SeededEntropy::new(77).bytes(4)[..]);
    }

    #[test]
    fn usable_as_dyn_host_and_dyn_entropy() {
        fn draw(entropy: &mut dyn Entropy) -> u8 {
            let mut byte = [0u8];
            entropy.fill(&mut byte);
            byte[0]
        }
        let mut host = TestHost::new();
        host.push_entropy(&[0x5a]);
        let dyn_host: &mut dyn Host = &mut host;
        assert_eq!(draw(dyn_host), 0x5a);
    }

    #[test]
    fn persist_stores_plaintext_per_record() {
        let mut host = TestHost::new();
        assert_eq!(host.persist(Record::Fido, b"f"), Ok(()));
        assert_eq!(host.persist(Record::Otp, b"o"), Ok(()));
        assert_eq!(host.persisted(Record::Fido), Some(b"f".to_vec()));
        assert_eq!(host.persisted(Record::Otp), Some(b"o".to_vec()));
        assert_eq!(host.persisted(Record::Piv), None);
        assert_eq!(host.persist_count(), 2);
    }

    #[test]
    fn failed_persist_keeps_previous_plaintext() {
        let mut host = TestHost::new();
        assert_eq!(host.persist(Record::Oath, b"one"), Ok(()));
        host.fail_next_saves(2);
        assert!(host.persist(Record::Oath, b"two").is_err());
        assert!(host.persist(Record::Oath, b"three").is_err());
        assert_eq!(host.persisted(Record::Oath), Some(b"one".to_vec()));
        assert_eq!(host.persist(Record::Oath, b"four"), Ok(()));
        assert_eq!(host.persisted(Record::Oath), Some(b"four".to_vec()));
        assert_eq!((host.persist_count(), host.persist_attempts()), (2, 4));
    }

    #[test]
    fn fail_all_fails_every_persist_until_cleared() {
        let mut host = TestHost::new();
        host.fail_all(true);
        assert!(host.persist(Record::Device, b"d").is_err());
        assert!(host.persist(Record::Device, b"d").is_err());
        assert_eq!(host.persisted(Record::Device), None);
        host.fail_all(false);
        assert_eq!(host.persist(Record::Device, b"d"), Ok(()));
    }

    #[test]
    fn set_and_clear_persisted_bypass_faults_and_counters() {
        let mut host = TestHost::new();
        host.fail_all(true);
        host.set_persisted(Record::HsmAuth, b"seed");
        assert_eq!(host.persisted(Record::HsmAuth), Some(b"seed".to_vec()));
        host.clear_persisted(Record::HsmAuth);
        assert_eq!(host.persisted(Record::HsmAuth), None);
        assert_eq!(host.persist_attempts(), 0);
    }

    #[test]
    fn failed_persist_leaves_every_record_untouched() {
        let mut host = TestHost::new();
        assert_eq!(host.persist(Record::Fido, b"fido v1"), Ok(()));
        assert_eq!(host.persist(Record::Piv, b"piv v1"), Ok(()));
        host.fail_next_saves(1);
        assert!(host.persist(Record::Piv, b"piv v2").is_err());
        host.fail_all(true);
        assert!(host.persist(Record::Oath, b"oath v1").is_err());
        assert!(host.persist(Record::Fido, b"fido v2").is_err());
        assert_eq!(host.persisted(Record::Fido), Some(b"fido v1".to_vec()));
        assert_eq!(host.persisted(Record::Piv), Some(b"piv v1".to_vec()));
        assert_eq!(host.persisted(Record::Oath), None);
        assert_eq!((host.persist_count(), host.persist_attempts()), (2, 5));
    }

    #[test]
    fn pending_failures_are_consumed_while_fail_all_is_set() {
        let mut host = TestHost::new();
        host.fail_next_saves(2);
        host.fail_all(true);
        assert!(host.persist(Record::Otp, b"a").is_err());
        host.fail_all(false);
        // One pending failure is left: the attempt under fail_all used up the other.
        assert!(host.persist(Record::Otp, b"b").is_err());
        assert_eq!(host.persist(Record::Otp, b"c"), Ok(()));
        assert_eq!(host.persisted(Record::Otp), Some(b"c".to_vec()));
        assert_eq!((host.persist_count(), host.persist_attempts()), (1, 3));
    }

    #[test]
    fn empty_plaintext_is_distinct_from_nothing_persisted() {
        let mut host = TestHost::new();
        assert_eq!(host.persist(Record::SecurityDomain, b""), Ok(()));
        assert_eq!(host.persisted(Record::SecurityDomain), Some(Vec::new()));
        assert_eq!(host.persisted(Record::OpenPgp), None);
    }

    #[test]
    fn persisting_draws_no_entropy() {
        // Persisting (and failing to persist) must not move the entropy stream, or an
        // application's later keys and nonces would depend on its storage traffic.
        let mut host = TestHost::new();
        assert_eq!(host.persist(Record::Fido, b"state"), Ok(()));
        host.fail_next_saves(1);
        assert!(host.persist(Record::Fido, b"state").is_err());
        let mut out = [0u8; 16];
        host.fill(&mut out);
        assert_eq!(out.to_vec(), SeededEntropy::new(TestHost::DEFAULT_SEED).bytes(16));
    }
}
