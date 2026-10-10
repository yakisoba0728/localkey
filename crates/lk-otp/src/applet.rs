//! The OTP application over CCID (AID `A0 00 00 05 27 20 01`).
//!
//! Yubico's smart-card OTP interface (yubikit `_YubiOtpSmartCardBackend`):
//! - SELECT answers the 6-byte status (version, programming sequence, touchLevel).
//! - INS `01` runs slot command P1 on the command data, zero-padded to 64 bytes; data
//!   longer than 64 bytes is `6700`. A short challenge is therefore the same as the
//!   zero-padded HID payload (catalog "LT64 direct short-APDU": an empty APDU with an
//!   LT64 HMAC slot hashes the single byte `00`).
//! - Writes answer the status with `9000`; reads answer the data without CRC.
//! - Rejections (model policy, ISO/IEC 7816-4 §5.6 status words): wrong access code
//!   `6982`; condition not met (empty slot, swap without two slots, not updatable,
//!   protected slot 2, wrong mode, touch not given) `6985`; bad configuration `6A80`;
//!   storage failure `6581`; unknown slot command `6A86`; NDEF on this USB-only model
//!   `6A81`; other INS `6D00`; other CLA `6E00`; chained CLA `6884`.

use lk_codec::apdu::{Command, response, status, sw};
use lk_core::{CardApplet, Host, Outcome, ResetKind};

use crate::config::SLOT_DATA_SIZE;
use crate::otp::{MgmtBridge, Otp, PendingChallenge, Reply, Transport};

/// The OTP application identifier.
pub const OTP_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01];

/// INS of the slot command APDU.
pub const INS_CONFIG: u8 = 0x01;

/// The CCID view of [`Otp`]. `lk-device` keeps one `OtpApplet` and reaches the shared
/// slots for HID and the button through [`otp_mut`](Self::otp_mut).
#[derive(Debug, Clone)]
pub struct OtpApplet {
    otp: Otp,
    pending: Option<PendingChallenge>,
}

impl OtpApplet {
    /// Restore from the plaintext last persisted under `Record::Otp`.
    pub fn new(stored: Option<&[u8]>, host: &mut dyn Host) -> Self {
        Self::from_otp(Otp::new(stored, host))
    }

    pub fn from_otp(otp: Otp) -> Self {
        Self { otp, pending: None }
    }

    pub fn otp(&self) -> &Otp {
        &self.otp
    }

    pub fn otp_mut(&mut self) -> &mut Otp {
        &mut self.otp
    }

    pub fn into_otp(self) -> Otp {
        self.otp
    }

    /// Forget a challenge-response waiting for a touch.
    fn drop_pending(&mut self) {
        if self.pending.take().is_some() {
            self.otp.end_touch_wait(Transport::Ccid);
        }
    }

    /// [`CardApplet::process`] with access to Management for the serial and
    /// device-information slot commands. Without a bridge the serial comes from the
    /// host profile and device information is not available.
    pub fn process_with(
        &mut self,
        apdu: &[u8],
        mgmt: Option<&mut dyn MgmtBridge>,
        host: &mut dyn Host,
    ) -> Outcome<Vec<u8>> {
        // A new command replaces any request still waiting for a touch.
        self.drop_pending();
        let command = match Command::parse(apdu) {
            Ok(command) => command,
            Err(e) => return Outcome::Done(status(e.sw())),
        };
        if command.is_chained() {
            return Outcome::Done(status(sw::CHAINING_NOT_SUPPORTED));
        }
        if command.cla != 0x00 {
            return Outcome::Done(status(sw::CLA_NOT_SUPPORTED));
        }
        if command.ins != INS_CONFIG {
            return Outcome::Done(status(sw::INS_NOT_SUPPORTED));
        }
        if command.data.len() > SLOT_DATA_SIZE {
            return Outcome::Done(status(sw::WRONG_LENGTH));
        }
        let mut payload = [0u8; SLOT_DATA_SIZE];
        if let Some(dst) = payload.get_mut(..command.data.len()) {
            dst.copy_from_slice(&command.data);
        }
        match self.otp.execute(command.p1, &payload, mgmt, host) {
            Ok(Reply::Status) => Outcome::Done(response(&self.otp.status(), sw::OK)),
            Ok(Reply::Data(data)) => Outcome::Done(response(&data, sw::OK)),
            Ok(Reply::NeedTouch(pending)) => {
                let timeout_ms = pending.timeout_ms;
                self.otp
                    .begin_touch_wait(Transport::Ccid, host.now().saturating_add(timeout_ms));
                self.pending = Some(pending);
                Outcome::NeedTouch { timeout_ms }
            }
            Err(code) => Outcome::Done(status(code)),
        }
    }
}

impl CardApplet for OtpApplet {
    fn aid(&self) -> &'static [u8] {
        &OTP_AID
    }

    fn select(&mut self, _apdu: &[u8], _host: &mut dyn Host) -> Vec<u8> {
        self.drop_pending();
        response(&self.otp.status(), sw::OK)
    }

    fn process(&mut self, apdu: &[u8], host: &mut dyn Host) -> Outcome<Vec<u8>> {
        self.process_with(apdu, None, host)
    }

    fn touch_resolved(&mut self, touched: bool, host: &mut dyn Host) -> Vec<u8> {
        let Some(pending) = self.pending.take() else {
            return status(sw::CONDITIONS);
        };
        self.otp.end_touch_wait(Transport::Ccid);
        if !touched {
            return status(sw::CONDITIONS);
        }
        match self.otp.complete_challenge(&pending, host) {
            Ok(data) => response(&data, sw::OK),
            Err(code) => status(code),
        }
    }

    fn deselect(&mut self) {
        self.drop_pending();
    }

    fn reset(&mut self, kind: ResetKind) {
        self.drop_pending();
        self.otp.reset(kind);
    }
}
