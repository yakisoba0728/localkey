//! The CCID view of the Management application (yubikit-python
//! `yubikit/management.py`, `_ManagementSmartCardBackend`; APDU structure
//! ISO/IEC 7816-4 §5.1).
//!
//! APDU conventions (`docs/CONTRACTS.md`, "Applications B and orchestrator changes",
//! APDU conventions, binding for every applet):
//!
//! | Status | Meaning |
//! | --- | --- |
//! | `6E00` | class outside the first interindustry range (`20`..`FF`), except `80` |
//! | `6882` | secure-messaging CLA bits (the device's secure channel clears them) |
//! | `6881` | logical channel number (ISO/IEC 7816-4 §5.6; as lk-piv and lk-oath) |
//! | `61xx` | more response data than Ne; fetch it with GET RESPONSE (`C0`) |
//! | `6D00` | unknown instruction; GET RESPONSE with nothing pending |
//!
//! Measured on a YubiKey 5C Nano 5.7.4 (`docs/MEASUREMENT.md`): CLA `80` is served like
//! `00` (probe `cla-variants-mgmt`), and GET RESPONSE with nothing pending is `6D00`,
//! also right after a chained command part left a chain open (probes
//! `get-response-idle-mgmt`, `cla-variants-mgmt`). These replace the `docs/CONTRACTS.md`
//! conventions `6E00` for CLA `80` and `6985` for an idle GET RESPONSE.
//!
//! A response is served in pieces of at most Ne bytes (Ne of the command; 256 for a
//! short command without Le, 65 536 for an extended one), the rest with `61xx` and
//! GET RESPONSE (ISO/IEC 7816-4 §5.1.3, §7.6.1). Any other command, SELECT, deselect
//! and reset discard unread response data. lk-device relies on GET RESPONSE: under a
//! secure channel it collects a `61xx` response with `00 C0 00 00 00`
//! (`AppId::continuation_ins`) before wrapping it.

use lk_codec::apdu::{self, Command, CommandChain, ResponseQueue, sw};
use lk_core::{CardApplet, Host, Outcome, ResetKind};

use crate::config::{ConfigEffect, Management};

/// Management application identifier (yubikit-python `yubikit/core/smartcard.py`,
/// `AID.MANAGEMENT`).
pub const AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];

/// Instruction bytes (yubikit-python `yubikit/management.py`).
pub mod ins {
    /// ISO/IEC 7816-4 §11.1.1 SELECT.
    pub const SELECT: u8 = 0xA4;
    /// WRITE CONFIG (`INS_WRITE_CONFIG`), data `len || TLVs`, P1 = P2 = 0.
    pub const WRITE_CONFIG: u8 = 0x1C;
    /// READ CONFIG (`INS_READ_CONFIG`), P1 = page; P2 is ignored (measured, probe
    /// `bad-p1p2-mgmt`).
    pub const READ_CONFIG: u8 = 0x1D;
    /// YubiKey 4 SET MODE (`INS_SET_MODE`, P1 `11`); not implemented (`6D00`, see
    /// [`crate::Management::legacy_set_mode`]).
    pub const SET_MODE: u8 = 0x16;
    /// DEVICE RESET (`INS_DEVICE_RESET`), only on YubiKey Bio; not on this device (`6D00`).
    pub const DEVICE_RESET: u8 = 0x1F;
    /// ISO/IEC 7816-4 §7.6.1 GET RESPONSE (yubikit `INS_SEND_REMAINING 0xC0`, sent by
    /// `ResponseChainingProcessor` after `61xx`), P1 = P2 = 0.
    pub const GET_RESPONSE: u8 = 0xC0;
}

/// Largest WRITE CONFIG data: the length byte plus at most 255 TLV bytes
/// (yubikit-python `DeviceConfig.get_bytes` refuses more). A host sending it in short
/// APDUs needs command chaining (ISO/IEC 7816-4 §5.1.1.1).
const CHAIN_LIMIT: usize = 256;

/// Response data per APDU for a short command without a smaller Le (ISO/IEC 7816-4
/// §5.1: Ne at most 256).
const SHORT_MAX_NE: usize = 256;

/// Response data per APDU for an extended command without a smaller Le.
const EXTENDED_MAX_NE: usize = 65_536;

/// Check the class byte (ISO/IEC 7816-4 §5.1.1): `00`, `10` for a chained command, or
/// the proprietary class `80`.
///
/// A YubiKey 5C Nano 5.7.4 serves `80 1D 00 00` exactly like `00 1D 00 00`
/// (`docs/MEASUREMENT.md`, probe `cla-variants-mgmt`). The other classes follow
/// `docs/CONTRACTS.md` (APDU conventions; unmeasured): secure-messaging bits are `6882`
/// and any other class of `80` or more (`84`, `90`, …) is `6E00`; the first
/// interindustry class with a logical channel number is `6881` and the other classes
/// (`20`..`7F`) are `6E00`, as in lk-piv and lk-oath.
fn check_cla(cla: u8) -> Result<(), u16> {
    let base = cla & !0x10;
    if base == 0 || cla == 0x80 {
        Ok(())
    } else if cla & 0xE0 != 0 {
        Err(sw::CLA_NOT_SUPPORTED)
    } else if base & 0x0C != 0 {
        Err(sw::SM_NOT_SUPPORTED)
    } else {
        Err(sw::LOGICAL_CHANNEL_NOT_SUPPORTED)
    }
}

/// The largest response piece for `cmd`: Ne (ISO/IEC 7816-4 §5.1), or the maximum of
/// the length form when the command has no Le field (yubikit's extended formatter
/// sends READ CONFIG as the four-byte case 1 `00 1D 00 00`).
fn response_max(cmd: &Command) -> usize {
    if cmd.extended {
        cmd.expected_len().unwrap_or(EXTENDED_MAX_NE)
    } else {
        cmd.expected_len()
            .map_or(SHORT_MAX_NE, |ne| ne.min(SHORT_MAX_NE))
    }
}

/// The Management application on CCID. It owns the device's one [`Management`].
#[derive(Clone)]
pub struct MgmtApplet {
    mgmt: Management,
    chain: CommandChain,
    /// Response data beyond Ne, served by GET RESPONSE.
    responses: ResponseQueue,
    effect: ConfigEffect,
}

/// Prints no chained command data: an unfinished WRITE CONFIG may hold a lock code.
impl std::fmt::Debug for MgmtApplet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MgmtApplet")
            .field("mgmt", &self.mgmt)
            .field("chain_active", &self.chain.is_active())
            .field("response_pending", &self.responses.remaining())
            .field("effect", &self.effect)
            .finish()
    }
}

impl MgmtApplet {
    /// Restore from the stored [`lk_core::Record::Device`] plaintext (see
    /// [`Management::new`]).
    pub fn new(stored: Option<&[u8]>, host: &mut dyn Host) -> Self {
        Self::from_management(Management::new(stored, host))
    }

    /// Wrap an existing [`Management`].
    pub fn from_management(mgmt: Management) -> Self {
        Self {
            mgmt,
            chain: CommandChain::new(CHAIN_LIMIT),
            responses: ResponseQueue::new(),
            effect: ConfigEffect::None,
        }
    }

    /// The shared Management state (also used for the OTP HID and CTAPHID paths).
    pub fn management(&self) -> &Management {
        &self.mgmt
    }

    /// Mutable access to the shared Management state.
    pub fn management_mut(&mut self) -> &mut Management {
        &mut self.mgmt
    }

    /// Unwrap the Management state.
    pub fn into_management(self) -> Management {
        self.mgmt
    }

    /// The effect owed to the host, cleared by this call. `lk-device` calls it after
    /// sending each response and reboots on [`ConfigEffect::Reboot`].
    ///
    /// A reboot is owed from the moment a WRITE CONFIG carrying the `REBOOT` tag
    /// (`0C`, yubikit-python `DeviceConfig.get_bytes(reboot=True)`) was answered with
    /// `9000` until it is taken or the device resets ([`CardApplet::reset`]). A later
    /// command does not cancel it, whether it succeeds without `REBOOT` or fails: the
    /// host was told the device will reboot.
    pub fn take_effect(&mut self) -> ConfigEffect {
        std::mem::replace(&mut self.effect, ConfigEffect::None)
    }

    /// The SELECT response data, answered with `9000`: the ASCII text
    /// `Virtual mgr - FW version major.minor.patch`, 30 bytes for 5.7.4, as a YubiKey 5C
    /// Nano 5.7.4 sends it (`docs/MEASUREMENT.md`, probe `select-mgmt`).
    ///
    /// yubikit-python `_ManagementSmartCardBackend` decodes the SELECT response as
    /// UTF-8 and reads the version with `Version.from_string`, which searches the text
    /// for `\b(\d+).(\d).(\d)\b` (`yubikit/core/__init__.py`,
    /// `_VERSION_STRING_PATTERN`).
    fn select_text(host: &dyn Host) -> Vec<u8> {
        let v = host.profile().firmware;
        format!(
            "Virtual mgr - FW version {}.{}.{}",
            v.major, v.minor, v.patch
        )
        .into_bytes()
    }

    /// Drop an unfinished command chain and unread response data.
    fn abort_command(&mut self) {
        self.chain.clear();
        self.responses.clear();
    }

    /// GET RESPONSE: the next piece of the pending response.
    ///
    /// With nothing pending the answer is `6D00`, as for an unknown instruction
    /// (`docs/MEASUREMENT.md`, probe `get-response-idle-mgmt`; model policy: whatever
    /// P1/P2). With data pending, P1/P2 other than `00 00` is `6A86` and keeps the data
    /// (model policy).
    fn get_response(&mut self, cmd: &Command) -> Vec<u8> {
        if !self.responses.is_pending() {
            return apdu::status(sw::INS_NOT_SUPPORTED);
        }
        if cmd.p1 != 0 || cmd.p2 != 0 {
            return apdu::status(sw::INCORRECT_P1P2);
        }
        self.responses
            .next(response_max(cmd))
            .unwrap_or_else(|| apdu::status(sw::INS_NOT_SUPPORTED))
    }

    /// Record the effect of a successful command; see [`MgmtApplet::take_effect`].
    fn owe(&mut self, effect: ConfigEffect) {
        if effect == ConfigEffect::Reboot {
            self.effect = ConfigEffect::Reboot;
        }
    }

    fn handle(&mut self, raw: &[u8], host: &mut dyn Host) -> Vec<u8> {
        let cmd = match Command::parse(raw) {
            Ok(cmd) => cmd,
            Err(e) => {
                self.abort_command();
                return apdu::status(e.sw());
            }
        };
        if let Err(status) = check_cla(cmd.cla) {
            self.abort_command();
            return apdu::status(status);
        }
        if cmd.ins == ins::GET_RESPONSE {
            // GET RESPONSE right after a chained part (`10 1D 00 00`) is answered like an
            // idle GET RESPONSE (`6D00`), not as a chain break (`docs/MEASUREMENT.md`,
            // probe `cla-variants-mgmt`); the open chain is dropped.
            self.chain.clear();
            return self.get_response(&cmd);
        }
        // Any other command discards unread response data (ISO/IEC 7816-4 §7.6.1).
        self.responses.clear();
        let cmd = match self.chain.push(cmd) {
            Ok(Some(cmd)) => cmd,
            Ok(None) => return apdu::status(sw::OK),
            Err(e) => return apdu::status(e.sw()),
        };
        let max = response_max(&cmd);
        match cmd.ins {
            // P1 alone selects the page: P2 is ignored, and a page past the last is a
            // bare `9000` without even a length byte (`docs/MEASUREMENT.md`, probe
            // `bad-p1p2-mgmt`: `00 1D 00 01` is page 0, `00 1D 02 00` and `00 1D FF 00`
            // are `9000` with no data).
            ins::READ_CONFIG => match self.mgmt.device_info_page(cmd.p1, host) {
                None => apdu::status(sw::OK),
                Some(_) => match self.mgmt.read_config(cmd.p1, host) {
                    Ok(data) => self.responses.start(data, sw::OK, max),
                    Err(status) => apdu::status(status),
                },
            },
            ins::WRITE_CONFIG => {
                if cmd.p1 != 0 || cmd.p2 != 0 {
                    return apdu::status(sw::INCORRECT_P1P2);
                }
                match self.mgmt.write_config(&cmd.data, host) {
                    Ok(effect) => {
                        self.owe(effect);
                        apdu::status(sw::OK)
                    }
                    Err(status) => apdu::status(status),
                }
            }
            ins::SET_MODE => match self.mgmt.legacy_set_mode(&cmd.data, host) {
                Ok(effect) => {
                    self.owe(effect);
                    apdu::status(sw::OK)
                }
                Err(status) => apdu::status(status),
            },
            ins::SELECT => {
                // A re-SELECT of this application by AID (ISO/IEC 7816-4 §11.1.1).
                if cmd.p1 == 0x04 && cmd.data == AID {
                    self.responses.start(Self::select_text(host), sw::OK, max)
                } else {
                    apdu::status(sw::FILE_NOT_FOUND)
                }
            }
            _ => apdu::status(sw::INS_NOT_SUPPORTED),
        }
    }
}

impl CardApplet for MgmtApplet {
    fn aid(&self) -> &'static [u8] {
        AID
    }

    /// The SELECT response (the version text, see `select_text`), at most Ne bytes of it
    /// (`61xx` for the rest). A SELECT discards an unfinished chain and unread
    /// response data.
    fn select(&mut self, apdu: &[u8], host: &mut dyn Host) -> Vec<u8> {
        self.abort_command();
        let max = Command::parse(apdu).map_or(SHORT_MAX_NE, |cmd| response_max(&cmd));
        self.responses.start(Self::select_text(host), sw::OK, max)
    }

    fn process(&mut self, apdu: &[u8], host: &mut dyn Host) -> Outcome<Vec<u8>> {
        Outcome::Done(self.handle(apdu, host))
    }

    /// Management never asks for a touch; a stray call answers `6985`.
    fn touch_resolved(&mut self, _touched: bool, _host: &mut dyn Host) -> Vec<u8> {
        apdu::status(sw::CONDITIONS)
    }

    fn deselect(&mut self) {
        self.abort_command();
    }

    fn reset(&mut self, _kind: ResetKind) {
        self.abort_command();
        self.effect = ConfigEffect::None;
    }
}
