//! Shared types and the engine's only contact points with its host program.
//!
//! The engine never reads the OS clock, opens a device, spawns a thread or touches the
//! filesystem. Time arrives as an argument, randomness through [`Entropy`] and
//! persistence through [`Store`]. Everything else is an input or output value of
//! `lk_device::Device`. See `docs/DESIGN.md` §4.

#![forbid(unsafe_code)]

use core::fmt;

/// Milliseconds on a monotonic clock owned by the host program.
pub type Millis = u64;

/// Cryptographically secure randomness supplied by the host.
///
/// The program passes OS randomness; tests pass a deterministic stream so that
/// every protocol exchange is reproducible.
pub trait Entropy {
    fn fill(&mut self, out: &mut [u8]);
}

/// Names of the independently persisted state records.
///
/// Each application owns one record so that a failed write in one never rolls back
/// another (the legacy model's commit/rollback rules, `reference/BEHAVIOR_CATALOG.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Record {
    Device,
    Fido,
    Oath,
    Otp,
    Piv,
    OpenPgp,
    HsmAuth,
    SecurityDomain,
}

/// Durable byte storage supplied by the host.
///
/// `save` must be atomic: after a crash the record holds either the old or the new
/// bytes, never a mix. Encryption at rest is the engine's job (§7); the store only
/// sees opaque, already-sealed bytes.
pub trait Store {
    fn load(&mut self, record: Record) -> Result<Option<Vec<u8>>, StoreError>;
    fn save(&mut self, record: Record, sealed: &[u8]) -> Result<(), StoreError>;
}

/// A host storage failure; the engine reports it to the client as the protocol's
/// generic failure status and keeps the previous in-memory state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(pub String);

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "store: {}", self.0)
    }
}

impl std::error::Error for StoreError {}
