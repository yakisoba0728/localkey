//! The CCID view of the Management application (yubikit-python
//! `yubikit/management.py`, `_ManagementSmartCardBackend`; APDU structure
//! ISO/IEC 7816-4 §5.1).

use lk_codec::apdu::{self, Command, CommandChain, sw};
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
    /// READ CONFIG (`INS_READ_CONFIG`), P1 = page, P2 = 0.
    pub const READ_CONFIG: u8 = 0x1D;
    /// YubiKey 4 SET MODE (`INS_SET_MODE`, P1 `11`); not implemented (`6D00`, see
    /// [`crate::Management::legacy_set_mode`]).
    pub const SET_MODE: u8 = 0x16;
    /// DEVICE RESET (`INS_DEVICE_RESET`), only on YubiKey Bio; not on this device (`6D00`).
    pub const DEVICE_RESET: u8 = 0x1F;
}

/// Largest WRITE CONFIG data: the length byte plus at most 255 TLV bytes
/// (yubikit-python `DeviceConfig.get_bytes` refuses more). A host sending it in short
/// APDUs needs command chaining (ISO/IEC 7816-4 §5.1.1.1).
const CHAIN_LIMIT: usize = 256;

/// The Management application on CCID. It owns the device's one [`Management`].
#[derive(Clone)]
pub struct MgmtApplet {
    mgmt: Management,
    chain: CommandChain,
    effect: ConfigEffect,
}

/// Prints no chained command data: an unfinished WRITE CONFIG may hold a lock code.
impl std::fmt::Debug for MgmtApplet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MgmtApplet")
            .field("mgmt", &self.mgmt)
            .field("chain_active", &self.chain.is_active())
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

    /// The SELECT response: the firmware version as ASCII `major.minor.patch`
    /// (yubikit-python `_ManagementSmartCardBackend` reads the version with
    /// `Version.from_string` from the SELECT response), then `9000`.
    ///
    /// Model policy: `Version.from_string` searches the text for
    /// `\b(\d+).(\d).(\d)\b`, so a bare `5.7.4` and a longer text ending in the version
    /// parse alike. The exact text of the 5.7.4 firmware is not in `reference/`; the
    /// engine sends the bare version (`docs/catalog/mgmt.md`).
    fn select_response(host: &dyn Host) -> Vec<u8> {
        let v = host.profile().firmware;
        let text = format!("{}.{}.{}", v.major, v.minor, v.patch);
        apdu::response(text.as_bytes(), sw::OK)
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
                self.chain.clear();
                return apdu::status(e.sw());
            }
        };
        // ISO/IEC 7816-4 §5.1.1: only the first interindustry class without secure
        // messaging or logical channels; bit b5 (0x10) is command chaining.
        if cmd.cla & !0x10 != 0x00 {
            self.chain.clear();
            return apdu::status(sw::CLA_NOT_SUPPORTED);
        }
        let cmd = match self.chain.push(cmd) {
            Ok(Some(cmd)) => cmd,
            Ok(None) => return apdu::status(sw::OK),
            Err(e) => return apdu::status(e.sw()),
        };
        match cmd.ins {
            ins::READ_CONFIG => {
                if cmd.p2 != 0 {
                    return apdu::status(sw::INCORRECT_P1P2);
                }
                match self.mgmt.read_config(cmd.p1, host) {
                    Ok(data) => apdu::response(&data, sw::OK),
                    Err(status) => apdu::status(status),
                }
            }
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
                    Self::select_response(host)
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

    fn select(&mut self, _apdu: &[u8], host: &mut dyn Host) -> Vec<u8> {
        self.chain.clear();
        Self::select_response(host)
    }

    fn process(&mut self, apdu: &[u8], host: &mut dyn Host) -> Outcome<Vec<u8>> {
        Outcome::Done(self.handle(apdu, host))
    }

    /// Management never asks for a touch; a stray call answers `6985`.
    fn touch_resolved(&mut self, _touched: bool, _host: &mut dyn Host) -> Vec<u8> {
        apdu::status(sw::CONDITIONS)
    }

    fn deselect(&mut self) {
        self.chain.clear();
    }

    fn reset(&mut self, _kind: ResetKind) {
        self.chain.clear();
        self.effect = ConfigEffect::None;
    }
}
