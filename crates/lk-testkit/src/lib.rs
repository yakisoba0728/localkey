//! Deterministic test harness: fixed-seed [`lk_core::Entropy`], an in-memory
//! [`lk_core::Store`] with fault injection, and helpers that drive an
//! `lk_device::Device` with CTAPHID reports, CCID messages and touch events as a real
//! host would. No OS device or network is involved.

#![forbid(unsafe_code)]
