//! The OTP application over CCID (AID `A0 00 00 05 27 20 01`).
//!
//! Yubico's smart-card OTP interface (yubikit `_YubiOtpSmartCardBackend`):
//! - SELECT answers the 6-byte status (version, programming sequence, touchLevel).
//! - INS `01` runs slot command P1 on the command data, zero-padded to 64 bytes; data
//!   longer than 64 bytes is `6700`. A short challenge is therefore the same as the
//!   zero-padded HID payload (catalog "LT64 direct short-APDU": an empty APDU with an
//!   LT64 HMAC slot hashes the single byte `00`).
//! - Writes answer the status with `9000`; reads answer the data without CRC.
//! - Request shapes (ISO/IEC 7816-4 §5.1): every short and extended case is accepted,
//!   P2 is ignored. This covers the shapes yubikit's short and extended encoders can
//!   produce for `send_apdu(0, 0x01, slot, 0, data)`: case 3S/3E with the data, and for
//!   data-less commands case 1, case 2S (`Lc = 00` read as `Le = 00`) or case 2E
//!   (`00 00 00`, the form lk-piv documents for yubikit's extended encoder). The
//!   extended `Lc = 0000` followed by an Le, which ISO/IEC 7816-4 forbids, is `6700`
//!   as `lk_codec::apdu` parses it; the OTP backend sends no Le.
//! - Responses follow `docs/CONTRACTS.md` "APDU conventions": at most Ne bytes, the
//!   rest with `61xx` and GET RESPONSE (`00 C0 00 00 Le`, ISO/IEC 7816-4 §7.6.1). A
//!   command without an Le field is answered as if Ne were the maximum of its length
//!   form (256 short, 65 536 extended). Any other command, SELECT, deselect and every
//!   reset discard unread data; GET RESPONSE with nothing pending is `6985` and with
//!   P1-P2 other than `00 00` `6A86` (the statuses lk-mgmt, lk-piv and lk-hsmauth use).
//! - Rejections (model policy, ISO/IEC 7816-4 §5.6 status words): wrong access code
//!   `6982`; condition not met (empty slot, swap without two slots, not updatable,
//!   protected slot 2, wrong mode, touch not given) `6985`; bad configuration `6A80`;
//!   storage failure `6581`; unknown slot command `6A86`; NDEF on this USB-only model
//!   `6A81`; other INS `6D00`.
//! - Class byte (ISO/IEC 7816-4 §5.1.1; `docs/CONTRACTS.md` "APDU conventions"),
//!   checked in this order: a class outside the first interindustry range (`20`..`FF`)
//!   `6E00`; secure-messaging bits (`04`/`08`/`0C`; lk-device clears them after
//!   unwrapping, so a command that still has them was never verified) `6882`; the
//!   command-chaining bit `10` (no OTP command is longer than 64 bytes) `6884`; a
//!   logical channel number `6881`.

use lk_codec::apdu::{Command, ResponseQueue, response, status, sw};
use lk_core::{CardApplet, Host, Outcome, ResetKind};

use crate::config::SLOT_DATA_SIZE;
use crate::otp::{MgmtBridge, Otp, PendingChallenge, Reply, Transport};

/// The OTP application identifier.
pub const OTP_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01];

/// INS of the slot command APDU.
pub const INS_CONFIG: u8 = 0x01;

/// INS of GET RESPONSE (ISO/IEC 7816-4 §7.6.1; yubikit `INS_SEND_REMAINING`).
const INS_GET_RESPONSE: u8 = 0xC0;

/// Ne of a short command with `Le = 00`, and the most a short response carries.
const SHORT_MAX_NE: usize = 256;
/// Ne of an extended command with `Le = 0000`.
const EXTENDED_MAX_NE: usize = 65_536;

/// The CCID view of [`Otp`]. `lk-device` keeps one `OtpApplet` and reaches the shared
/// slots for HID and the button through [`otp_mut`](Self::otp_mut).
#[derive(Debug, Clone)]
pub struct OtpApplet {
    otp: Otp,
    /// A challenge-response waiting for a touch, with the Ne of its command.
    pending: Option<(PendingChallenge, usize)>,
    /// Response data not yet fetched with GET RESPONSE.
    responses: ResponseQueue,
}

impl OtpApplet {
    /// Restore from the plaintext last persisted under `Record::Otp`.
    pub fn new(stored: Option<&[u8]>, host: &mut dyn Host) -> Self {
        Self::from_otp(Otp::new(stored, host))
    }

    pub fn from_otp(otp: Otp) -> Self {
        Self {
            otp,
            pending: None,
            responses: ResponseQueue::new(),
        }
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

    /// End the command-scoped state: a waiting challenge-response and unread data.
    fn end_command(&mut self) {
        self.drop_pending();
        self.responses.clear();
    }

    /// GET RESPONSE: the next piece of the pending response.
    fn get_response(&mut self, command: &Command) -> Vec<u8> {
        if command.p1 != 0 || command.p2 != 0 {
            return status(sw::INCORRECT_P1P2);
        }
        self.responses
            .next(response_max(command))
            .unwrap_or_else(|| status(sw::CONDITIONS))
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
            Err(e) => {
                self.responses.clear();
                return Outcome::Done(status(e.sw()));
            }
        };
        if let Err(code) = check_cla(command.cla) {
            self.responses.clear();
            return Outcome::Done(status(code));
        }
        if command.ins == INS_GET_RESPONSE {
            return Outcome::Done(self.get_response(&command));
        }
        // Any other command discards unread response data (ISO/IEC 7816-4 §7.6.1).
        self.responses.clear();
        if command.ins != INS_CONFIG {
            return Outcome::Done(status(sw::INS_NOT_SUPPORTED));
        }
        if command.data.len() > SLOT_DATA_SIZE {
            return Outcome::Done(status(sw::WRONG_LENGTH));
        }
        let max = response_max(&command);
        let mut payload = [0u8; SLOT_DATA_SIZE];
        if let Some(dst) = payload.get_mut(..command.data.len()) {
            dst.copy_from_slice(&command.data);
        }
        match self.otp.execute(command.p1, &payload, mgmt, host) {
            Ok(Reply::Status) => {
                let data = self.otp.status().to_vec();
                Outcome::Done(self.responses.start(data, sw::OK, max))
            }
            Ok(Reply::Data(data)) => Outcome::Done(self.responses.start(data, sw::OK, max)),
            Ok(Reply::NeedTouch(pending)) => {
                let timeout_ms = pending.timeout_ms;
                self.otp
                    .begin_touch_wait(Transport::Ccid, host.now().saturating_add(timeout_ms));
                self.pending = Some((pending, max));
                Outcome::NeedTouch { timeout_ms }
            }
            Err(code) => Outcome::Done(status(code)),
        }
    }
}

/// The class byte check described in the module documentation.
fn check_cla(cla: u8) -> Result<(), u16> {
    if cla == 0x00 {
        Ok(())
    } else if cla & 0xE0 != 0 {
        Err(sw::CLA_NOT_SUPPORTED)
    } else if cla & 0x0C != 0 {
        Err(sw::SM_NOT_SUPPORTED)
    } else if cla & 0x10 != 0 {
        Err(sw::CHAINING_NOT_SUPPORTED)
    } else {
        Err(sw::LOGICAL_CHANNEL_NOT_SUPPORTED)
    }
}

/// The largest response piece for `command`: Ne (ISO/IEC 7816-4 §5.1), or the maximum
/// of the length form when the command has no Le field.
fn response_max(command: &Command) -> usize {
    if command.extended {
        command.expected_len().unwrap_or(EXTENDED_MAX_NE)
    } else {
        command
            .expected_len()
            .map_or(SHORT_MAX_NE, |ne| ne.min(SHORT_MAX_NE))
    }
}

impl CardApplet for OtpApplet {
    fn aid(&self) -> &'static [u8] {
        &OTP_AID
    }

    fn select(&mut self, _apdu: &[u8], _host: &mut dyn Host) -> Vec<u8> {
        self.end_command();
        response(&self.otp.status(), sw::OK)
    }

    fn process(&mut self, apdu: &[u8], host: &mut dyn Host) -> Outcome<Vec<u8>> {
        self.process_with(apdu, None, host)
    }

    fn touch_resolved(&mut self, touched: bool, host: &mut dyn Host) -> Vec<u8> {
        let Some((pending, max)) = self.pending.take() else {
            return status(sw::CONDITIONS);
        };
        self.otp.end_touch_wait(Transport::Ccid);
        if !touched {
            return status(sw::CONDITIONS);
        }
        match self.otp.complete_challenge(&pending, host) {
            Ok(data) => self.responses.start(data, sw::OK, max),
            Err(code) => status(code),
        }
    }

    fn deselect(&mut self) {
        self.end_command();
    }

    fn reset(&mut self, kind: ResetKind) {
        self.end_command();
        self.otp.reset(kind);
    }
}
