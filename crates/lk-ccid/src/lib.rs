//! USB CCID class framing (CCID Rev 1.1): `PC_to_RDR_*` / `RDR_to_PC_*` messages,
//! slot power and ICC status, ATR, XfrBlock with extended-APDU level exchange,
//! time extension (WTX) and ABORT. It hands complete APDUs to the device's card
//! session and frames the responses.

#![forbid(unsafe_code)]
