//! Deterministic test support shared by every crate: a fixed-seed [`lk_core::Entropy`],
//! an in-memory [`lk_core::Store`] with fault injection, and a [`lk_core::Host`]
//! implementation for application tests. It depends only on `lk-core` and `lk-crypto`,
//! so any crate may use it as a dev-dependency. Device-level scenario helpers live in
//! `lk-device`'s own tests.
//!
//! - [`SeededEntropy`]: a reproducible byte stream from a `u64` seed.
//! - [`ScriptedEntropy`]: chosen bytes first (a known key or nonce), then a seeded stream.
//! - [`MemoryStore`]: sealed-record storage for `lk-device` tests, with save/load faults.
//! - [`TestHost`]: settable time, a profile, scripted entropy and plaintext persistence
//!   with the same fault rules, for application tests.
//!
//! # Example
//!
//! ```
//! use lk_core::{Host, Record};
//! use lk_testkit::TestHost;
//!
//! // What an application test typically checks: state is persisted before success,
//! // and a storage failure leaves the last good state in place.
//! let mut host = TestHost::new();
//! assert!(host.persist(Record::Fido, &[0x01]).is_ok());
//! host.fail_all(true);
//! assert!(host.persist(Record::Fido, &[0x01, 0xff]).is_err());
//! assert_eq!(host.persisted(Record::Fido), Some(vec![0x01]));
//! ```

#![forbid(unsafe_code)]

mod entropy;
mod faults;
mod host;
mod store;

pub use entropy::{ScriptedEntropy, SeededEntropy};
pub use host::TestHost;
pub use store::MemoryStore;
