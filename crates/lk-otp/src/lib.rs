//! OTP application: two configurable slots (Yubico OTP, OATH-HOTP, static password,
//! static ticket, HMAC-SHA1 and Yubico OTP challenge-response), access codes,
//! swap/delete/update, the 8-byte HID feature-report protocol with frame CRC, and
//! keyboard output. The same slot logic is reachable through the CCID OTP AID.
//!
//! Specifications (clean room, public sources only):
//! - Yubico `ykdef.h` from yubikey-personalization (protocol constants, configuration
//!   structure, frame layout, status bits) and the YubiKey manual / Yubico developer
//!   documentation for the OTP modes, access codes, update/dormant and touch windows.
//! - yubikit-python `yubikit/core/otp.py` and `yubikit/yubiotp.py` for the host side of
//!   the HID and CCID protocols (frame chunking, all-zero chunk skipping, response
//!   sequence wrap, status checks, payload layouts).
//! - RFC 4226 (HOTP), RFC 2104 (HMAC-SHA1), FIPS 197 (AES), ISO/IEC 13239 (CRC),
//!   USB HID 1.11 Appendix B (boot keyboard), HID Usage Tables §10.
//! - `reference/BEHAVIOR_CATALOG.md` "OTP" for boundary decisions; the mapping of each
//!   item is in `docs/catalog/otp.md`.
//!
//! Integration (`lk-device`):
//! - [`OtpApplet`] owns the [`Otp`] state and is the CCID applet;
//!   [`OtpApplet::otp_mut`] gives the same state to [`OtpHid`] and the button.
//! - [`OtpHid::set_feature`] / [`OtpHid::get_feature`] carry the feature reports;
//!   [`Outcome::NeedTouch`](lk_core::Outcome) is finished with
//!   [`OtpHid::touch_resolved`] (or [`CardApplet::touch_resolved`](lk_core::CardApplet)
//!   for CCID).
//! - [`Otp::touch_down`] / [`Otp::touch_up`] model the sensor; [`Otp::button`] is the
//!   completed-press API. Both return boot-keyboard reports to send in order.
//! - While a challenge-response waits for a touch ([`Otp::is_challenge_waiting`]) the
//!   touch belongs to that request: the slots type nothing, and `lk-device` resolves
//!   the request instead. On a USB reset or power cycle `lk-device` resets both
//!   [`OtpHid`] and the [`OtpApplet`] (which resets the shared [`Otp`]).
//! - [`MgmtBridge`] connects the serial and device-information slot commands to
//!   Management.
//!
//! Secrets are wiped (`docs/DESIGN.md` §8): a [`SlotConfig`] wipes its `fixed`, `uid`,
//! `key` and access code when dropped; the serialized record is held in
//! `lk_crypto::SecretBytes`; the HID receive buffer, slot payloads, a pending
//! challenge-response, the read-back response and every temporary copy of a key,
//! private ID, scan-code block or encrypted ticket are wiped after use with
//! `lk_crypto::wipe`. The keyboard report buffer is allocated for the longest emission,
//! so it never reallocates while holding a static password. `Debug` prints no secret:
//! [`SlotConfig`] omits its secret fields and [`Ticket`] its private ID. Two copies
//! stay outside this crate's reach: [`Ticket`] is `Copy` (its `uid` is wiped where this
//! crate holds one), and the finished keyboard reports of a static password leave
//! through `lk-device`'s outputs.

#![forbid(unsafe_code)]

mod applet;
mod config;
mod crc;
mod hid;
mod keyboard;
mod otp;
mod state;
mod token;

pub use applet::{INS_CONFIG, OTP_AID, OtpApplet};
pub use config::{
    ACC_CODE_SIZE, CONFIG_SIZE, FIXED_SIZE, KEY_SIZE, Mode, SCAN_CODES_SIZE, SLOT_DATA_SIZE,
    SlotConfig, UID_SIZE, cfg, ext, tkt,
};
pub use crc::{CRC_OK_RESIDUE, MODHEX, append_crc, crc_ok, crc16, modhex_decode, modhex_encode};
pub use hid::{
    DUMMY_REPORT_WRITE, FEATURE_RPT_DATA_SIZE, FEATURE_RPT_SIZE, FRAME_SIZE, OtpHid,
    RESP_PENDING_FLAG, RESP_TIMEOUT_WAIT_FLAG, SEQUENCE_MASK, SLOT_WRITE_FLAG,
};
pub use keyboard::{
    DEFAULT_SCAN_MAP, MAP_BANG, MAP_CR, MAP_DIGITS, MAP_TAB, MAP_UPPER, RELEASE, REPORT_PERIOD_MS,
    SCAN_MAP_SIZE, SHIFT, decode_reports, press_report,
};
pub use otp::{
    DEFAULT_CHALRESP_TIMEOUT_S, LONG_TOUCH_MS, MgmtBridge, Otp, Press, SHORT_TOUCH_MS, Slot,
    classify_hold, cmd, status_bits,
};
pub use token::{MAX_USE_COUNTER, Ticket};
