//! Storage, randomness and the storage key for the program (`docs/PROGRAM.md` "lk-host").
//!
//! The engine meets the OS only through `lk_core::Store` and `lk_core::Entropy`
//! (`docs/DESIGN.md` §4). This crate provides both, and everything the daemon prepares
//! before it opens `lk_device::Device`:
//!
//! - [`FileStore`]: the private state directory, its process lock, and one sealed record
//!   file per `lk_core::Record`, replaced atomically on every save ([`state`]).
//! - [`load_or_create_serial`]: the device serial, drawn once and kept in `identity`.
//! - [`OsEntropy`]: `/dev/urandom`, which panics rather than hand out partial bytes.
//! - The storage key ([`key`]): generation, its 64-hex-digit text form, key files with
//!   mode 0600, and key commands that fetch it from a keychain or password manager.
//! - [`HostError`]: failures that name paths, never contents; [`Refusal`] says why a path
//!   was refused.
//!
//! Unix only (macOS and Linux): the crate is `cfg(unix)` (`docs/PROGRAM.md` "Rules for
//! program crates").
//!
//! # Example
//!
//! ```
//! use lk_core::{Record, Store};
//! use lk_host::{FileStore, OsEntropy, generate_key, load_or_create_serial, to_array};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let state = std::env::temp_dir().join(format!("lkh-doc-{}", std::process::id()));
//! let mut store = FileStore::open(&state)?;
//! let mut entropy = OsEntropy::open()?;
//! let serial = load_or_create_serial(store.dir(), &mut entropy)?;
//! assert!((10_000_000..=99_999_999).contains(&serial));
//!
//! // What `lk_device::Device::open` receives (the device seals before it saves).
//! let key = to_array(&generate_key(&mut entropy));
//! assert_eq!(key.len(), 32);
//! assert_eq!(store.load(Record::Fido)?, None);
//!
//! // While the store lives, the directory is locked.
//! assert!(matches!(FileStore::open(&state), Err(lk_host::HostError::Locked { .. })));
//! drop(store);
//! std::fs::remove_dir_all(&state)?;
//! # Ok(())
//! # }
//! ```

#![cfg(unix)]
#![forbid(unsafe_code)]

mod entropy;
mod error;
mod identity;
pub mod key;
pub mod state;

pub use entropy::OsEntropy;
pub use error::{HostError, Refusal};
pub use identity::{IDENTITY_FILE, SERIAL_MAX, SERIAL_MIN, load_or_create_serial};
pub use key::{KEY_LEN, generate_key, key_from_command, key_text, read_key_file, to_array, write_key_file};
pub use state::{FileStore, LOCK_FILE, record_name};

#[cfg(test)]
mod test_dir;
