//! Scenario tests of the OpenPGP applet through `lk_core::CardApplet`, using
//! `lk_testkit::TestHost`. Specification references are to the OpenPGP Smart Card
//! Application Functional Specification 3.4.1 ("spec"); behaviour catalog references are
//! to `reference/BEHAVIOR_CATALOG.md` (OpenPGP sections); observed bytes come from
//! `reference/yubikey-5c-nano-5.7.4/openpgp-reference-observation.json`.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

mod common;

mod attestation;
mod data_objects;
mod framing;
mod generation;
mod import;
mod kdf;
mod lifecycle;
mod operations;
mod passwords;
mod public_objects;
mod review;
mod robustness;
mod touch;
mod variants;
