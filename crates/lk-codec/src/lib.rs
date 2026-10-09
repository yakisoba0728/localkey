//! Byte-level codecs written from the specifications, with no third-party code.
//!
//! - [`cbor`]: CBOR with CTAP2 canonical encoding rules (CTAP 2.1 §8, RFC 8949 §4.2)
//! - [`tlv`]: BER-TLV as used by ISO 7816-4, PIV, OpenPGP and GlobalPlatform
//! - [`apdu`]: ISO 7816-4 command/response APDUs, chaining helpers and status words
//! - [`der`] and [`x509`]: DER encoding and certificate assembly (X.690, RFC 5280)
//!
//! See `docs/CONTRACTS.md` for the required API.

#![forbid(unsafe_code)]

pub mod apdu;
pub mod cbor;
pub mod der;
pub mod tlv;
pub mod x509;
