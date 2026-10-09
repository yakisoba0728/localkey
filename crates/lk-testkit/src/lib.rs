//! Deterministic test support shared by every crate: a fixed-seed [`lk_core::Entropy`],
//! an in-memory [`lk_core::Store`] with fault injection, and a [`lk_core::Host`]
//! implementation for application tests. It depends only on `lk-core` and `lk-crypto`,
//! so any crate may use it as a dev-dependency. Device-level scenario helpers live in
//! `lk-device`'s own tests.

#![forbid(unsafe_code)]
