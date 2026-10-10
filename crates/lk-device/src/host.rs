//! The device's implementation of [`lk_core::Host`]: time, identity, randomness and
//! sealed persistence lent to an application while it handles one command.
//!
//! - `persist` seals the plaintext with [`crate::storage::seal`] under the program's
//!   storage key (AES-256-GCM, `docs/DESIGN.md` §7, `docs/CONTRACTS.md` "lk-device") and
//!   hands the sealed bytes to [`Store::save`]. The store never sees plaintext.
//! - The commit rule (`docs/DESIGN.md` §7: "save succeeds before the memory state is
//!   committed and success is answered") is the application's: a `StoreError` reaches it
//!   unchanged, and it keeps its previous state and answers its storage-failure status.
//! - Every seal draws its nonce from the same entropy stream the applications use, so a
//!   device with one advancing stream never reuses a nonce under its key
//!   (SP 800-38D §8.2.2, documented on [`crate::storage::seal`]).

use core::fmt;

use lk_core::{DeviceProfile, Entropy, Host, Millis, Record, Store, StoreError};

use crate::storage;

/// The records in the order the device loads them and constructs their applications.
/// The order is fixed so that construction draws entropy deterministically
/// (`docs/DESIGN.md` §1: same inputs, time and randomness give the same outputs).
pub(crate) const RECORDS: [Record; 8] = [
    Record::Device,
    Record::Fido,
    Record::Oath,
    Record::Otp,
    Record::Piv,
    Record::OpenPgp,
    Record::HsmAuth,
    Record::SecurityDomain,
];

/// What loading one record produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Loaded {
    /// The store holds nothing for the record: factory state.
    Absent,
    /// The record opened; this is the plaintext the application last persisted.
    Opened(Vec<u8>),
    /// The store failed, or the sealed bytes did not open (wrong key, wrong record,
    /// unknown format version, modified bytes). `docs/CONTRACTS.md` "Persisted state":
    /// unreadable state means factory state, for that application only.
    Unreadable,
}

/// Host services owned by the device. Kept apart from the applications so that a call
/// such as `apps.oath.process(apdu, &mut host)` borrows disjoint fields.
pub(crate) struct DeviceHost {
    pub(crate) profile: DeviceProfile,
    store: Box<dyn Store>,
    entropy: Box<dyn Entropy>,
    storage_key: [u8; 32],
    /// The time of the input being processed (`docs/DESIGN.md` §4: the engine never
    /// reads a clock; time arrives with every input).
    pub(crate) now: Millis,
    /// Wall-clock seconds supplied by the program ([`crate::Device::set_unix_time`]).
    pub(crate) unix_time: Option<u64>,
    /// Records whose saves are skipped (see [`DeviceHost::begin_construction`]).
    protected: Vec<Record>,
    /// The applications are being constructed ([`DeviceHost::begin_construction`]).
    constructing: bool,
    /// Plaintexts a constructor persisted while the store failed, waiting to be saved
    /// again ([`DeviceHost::retry_deferred`]).
    deferred: Vec<(Record, Vec<u8>)>,
}

impl DeviceHost {
    pub(crate) fn new(
        profile: DeviceProfile,
        store: Box<dyn Store>,
        entropy: Box<dyn Entropy>,
        storage_key: [u8; 32],
        now: Millis,
    ) -> Self {
        Self {
            profile,
            store,
            entropy,
            storage_key,
            now,
            unix_time: None,
            protected: Vec::new(),
            constructing: false,
            deferred: Vec::new(),
        }
    }

    /// Start constructing the applications at open; [`DeviceHost::end_construction`]
    /// ends it. Two rules apply meanwhile:
    ///
    /// - Saves of `unreadable` records are skipped: `persist` reports success without
    ///   touching the store. A record that exists but cannot be read (wrong storage key,
    ///   failing store, modified bytes) gives its application factory state, and a
    ///   constructor that persists its new identity (Security Domain, PIV, OpenPGP;
    ///   `docs/CONTRACTS.md` "Constructors may persist") must not overwrite the unreadable
    ///   record with it. Opening the device is then never destructive: the program can
    ///   fix its key or store and reopen without losing state (`docs/DESIGN.md` §7: a
    ///   record only changes through a commit of its application's own command). The
    ///   factory identity of such an application lives in memory until its first
    ///   mutating command saves the whole state.
    /// - A constructor save that the store rejects is kept and retried
    ///   ([`DeviceHost::retry_deferred`]). Those constructors ignore the failure ("the
    ///   next successful mutation persists the whole state again", lk-sd) and keep the
    ///   identity they generated in memory, so without a retry the host could read it
    ///   (a Security Domain CPLC or certificate, the PIV attestation certificate) and
    ///   find another one after the next open: memory and store would disagree in a way
    ///   the host sees (`docs/DESIGN.md` §7 commit rule).
    pub(crate) fn begin_construction(&mut self, unreadable: &[Record]) {
        self.protected = unreadable.to_vec();
        self.constructing = true;
    }

    /// End [`DeviceHost::begin_construction`].
    pub(crate) fn end_construction(&mut self) {
        self.protected.clear();
        self.constructing = false;
    }

    /// Save again every constructor state the store rejected at open, until it takes
    /// it. Called before each input is processed (`Device::handle`), so once the store
    /// works the generated identity is stored before the host can observe it. The
    /// plaintext is still the application's state: an application changes its persisted
    /// state only through a successful `persist`, which supersedes the deferred copy
    /// (`persist` drops it).
    pub(crate) fn retry_deferred(&mut self) {
        if self.deferred.is_empty() {
            return;
        }
        let pending = std::mem::take(&mut self.deferred);
        for (record, plaintext) in pending {
            let sealed = storage::seal(&self.storage_key, record, &plaintext, self.entropy.as_mut());
            if self.store.save(record, &sealed).is_err() {
                self.deferred.push((record, plaintext));
            }
        }
    }

    /// Records whose constructor state still waits for a successful save.
    pub(crate) fn deferred_records(&self) -> Vec<Record> {
        self.deferred.iter().map(|(record, _)| *record).collect()
    }

    /// Load `record` from the store and open it under the storage key. Never panics:
    /// every failure is [`Loaded::Unreadable`].
    pub(crate) fn load(&mut self, record: Record) -> Loaded {
        match self.store.load(record) {
            Ok(None) => Loaded::Absent,
            Ok(Some(sealed)) => match storage::open(&self.storage_key, record, &sealed) {
                Ok(plaintext) => Loaded::Opened(plaintext),
                Err(_) => Loaded::Unreadable,
            },
            Err(_) => Loaded::Unreadable,
        }
    }
}

impl Entropy for DeviceHost {
    fn fill(&mut self, out: &mut [u8]) {
        self.entropy.fill(out);
    }
}

impl Host for DeviceHost {
    fn now(&self) -> Millis {
        self.now
    }

    fn profile(&self) -> &DeviceProfile {
        &self.profile
    }

    fn unix_time(&self) -> Option<u64> {
        self.unix_time
    }

    /// Seal under the storage key, then save (`docs/DESIGN.md` §7 commit rule; the
    /// application only reports success after this returns `Ok`).
    ///
    /// A failed save during construction is kept for [`DeviceHost::retry_deferred`]; a
    /// successful save replaces any deferred state of the record.
    fn persist(&mut self, record: Record, plaintext: &[u8]) -> Result<(), StoreError> {
        if self.protected.contains(&record) {
            return Ok(());
        }
        let sealed = storage::seal(&self.storage_key, record, plaintext, self.entropy.as_mut());
        let result = self.store.save(record, &sealed);
        if result.is_ok() || self.constructing {
            self.deferred.retain(|(deferred, _)| *deferred != record);
        }
        if result.is_err() && self.constructing {
            self.deferred.push((record, plaintext.to_vec()));
        }
        result
    }
}

/// Never prints the storage key.
impl fmt::Debug for DeviceHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceHost")
            .field("serial", &self.profile.serial)
            .field("now", &self.now)
            .field("unix_time", &self.unix_time)
            .field("deferred", &self.deferred_records())
            .finish_non_exhaustive()
    }
}

/// Best-effort wipe of the storage key when the device goes away (`docs/DESIGN.md` §8:
/// secret buffers are cleared; `zeroize` is only available inside `lk-crypto`).
impl Drop for DeviceHost {
    fn drop(&mut self) {
        self.storage_key = [0; 32];
        std::hint::black_box(&mut self.storage_key);
        for (_, plaintext) in &mut self.deferred {
            plaintext.fill(0);
            std::hint::black_box(plaintext);
        }
    }
}
