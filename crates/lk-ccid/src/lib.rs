//! USB CCID class framing (USB CCID Rev 1.1): `PC_to_RDR_*` / `RDR_to_PC_*` messages,
//! slot power and ICC status, ATR, XfrBlock with extended-APDU level exchange,
//! time extension (WTX) and ABORT. It hands complete APDUs to the device's card
//! session and frames the responses.
//!
//! The reader model follows the CCID descriptor of the reference device
//! ([`descriptor::YUBIKEY_5C_NANO`]): one slot, T=1 only, short and extended APDU level
//! exchange (`dwFeatures` = `0x000400FE`), at most 3072 bytes per message (3062 bytes of
//! `abData`), one busy slot, no PIN pad, no mechanics, no clock stop.
//!
//! - [`Ccid::message`] takes one bulk-out message and returns a [`CcidAction`].
//! - [`Ccid::apdu_response`] frames the card's answer to an XfrBlock.
//! - [`Ccid::time_extension`] and [`Ccid::slot_change`] build the waiting-time extension
//!   and the interrupt-pipe insertion message.
//!
//! The crate never reads a clock: the device decides when to send time extensions.

#![forbid(unsafe_code)]

mod atr;
mod ccid;
mod chain;
pub mod descriptor;
pub mod message;
mod params;

pub use ccid::{Ccid, CcidAction};
pub use params::T1Parameters;
