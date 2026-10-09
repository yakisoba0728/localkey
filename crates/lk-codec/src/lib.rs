//! Byte-level codecs written from the specifications, with no third-party code.
//!
//! - CBOR with CTAP2 canonical encoding rules (CTAP 2.1 §8, RFC 8949 §4.2)
//! - BER-TLV as used by ISO 7816-4, PIV, OpenPGP and GlobalPlatform
//! - ISO 7816-4 command/response APDUs: short and extended length, command chaining
//!   (CLA bit 0x10) and response chaining (`61xx` / GET RESPONSE)

#![forbid(unsafe_code)]
