//! The OTP HID feature-report protocol (Yubico `ykdef.h` `YKFRAME`, ykpers
//! `yk_write_to_key` / `yk_read_response_from_key`, yubikit `OtpProtocol`).
//!
//! Writing (host → device), one 8-byte feature report at a time:
//! - a 70-byte frame `payload(64) || slot command(1) || CRC-16 of payload (2, LE) ||
//!   filler(3)` is cut into ten 7-byte chunks;
//! - each report is `chunk(7) || 0x80 | seq` (`SLOT_WRITE_FLAG`, seq 0..9);
//! - all-zero chunks other than the first (seq 0) and last (seq 9) may be skipped, so a
//!   missing sequence number between two received ones is a zero chunk;
//! - chunk 9 completes the frame; a frame with a wrong CRC is dropped;
//! - a report with the write flag and a sequence above 9 (ykpers `DUMMY_REPORT_WRITE`
//!   `0x8F`, yubikit `0xFF`) resets: it aborts a partial frame, a pending response and
//!   a touch wait;
//! - a chunk that does not continue the current frame (no seq 0 first, or a sequence
//!   that does not increase) is an orphan: the partial frame is dropped and nothing
//!   runs (catalog "OTP HID abort/orphan-frame boundaries").
//!
//! Reading (device → host):
//! - status report `[0, major, minor, patch, pgmSeq, touchLevel lo, hi, 0]`;
//! - response data (with complemented CRC appended, padded to 7-byte chunks) as
//!   `chunk(7) || 0x40 | seq` (`RESP_PENDING_FLAG`); after the last chunk the sequence
//!   wraps to 0, which tells the host the transfer is complete;
//! - while waiting for a touch, `0x20 | seconds left` (`RESP_TIMEOUT_WAIT_FLAG`).
//!
//! Processing is instantaneous here, so the device never reports `SLOT_WRITE_FLAG` as
//! busy between chunks.

use core::fmt;

use lk_core::{Host, Millis, Outcome, ResetKind};

use crate::config::SLOT_DATA_SIZE;
use crate::crc::{append_crc, crc16};
use crate::otp::{MgmtBridge, Otp, PendingChallenge, Reply, Transport};

/// Size of one feature report.
pub const FEATURE_RPT_SIZE: usize = 8;
/// Data bytes per feature report.
pub const FEATURE_RPT_DATA_SIZE: usize = 7;
/// Size of a write frame.
pub const FRAME_SIZE: usize = SLOT_DATA_SIZE + 6;
/// Host write flag in byte 7.
pub const SLOT_WRITE_FLAG: u8 = 0x80;
/// Response data pending flag in byte 7.
pub const RESP_PENDING_FLAG: u8 = 0x40;
/// Waiting for a touch; the low five bits are the seconds left.
pub const RESP_TIMEOUT_WAIT_FLAG: u8 = 0x20;
/// Sequence number bits of byte 7.
pub const SEQUENCE_MASK: u8 = 0x1F;
/// The ykpers dummy write that resets the read state.
pub const DUMMY_REPORT_WRITE: u8 = 0x8F;
/// Sequence number of the last write chunk.
const LAST_SEQ: u8 = 9;
/// A response can use at most 32 chunks (five sequence bits).
const MAX_RESPONSE_CHUNKS: usize = 32;

#[derive(Clone)]
struct Response {
    data: Vec<u8>,
    next: u8,
    chunks: u8,
}

#[derive(Debug, Clone)]
struct Wait {
    pending: PendingChallenge,
    deadline: Millis,
}

/// Framing state of the OTP HID interface.
#[derive(Clone)]
pub struct OtpHid {
    rx: [u8; FRAME_SIZE],
    rx_seq: Option<u8>,
    response: Option<Response>,
    wait: Option<Wait>,
    last_now: Millis,
}

impl fmt::Debug for OtpHid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtpHid")
            .field("rx_seq", &self.rx_seq)
            .field("response_pending", &self.response.is_some())
            .field("wait", &self.wait)
            .finish_non_exhaustive()
    }
}

impl Default for OtpHid {
    fn default() -> Self {
        Self::new()
    }
}

impl OtpHid {
    pub fn new() -> Self {
        Self {
            rx: [0; FRAME_SIZE],
            rx_seq: None,
            response: None,
            wait: None,
            last_now: 0,
        }
    }

    /// Handle one SET_REPORT of the feature report.
    ///
    /// Returns [`Outcome::NeedTouch`] when the completed frame is a challenge-response
    /// whose slot requires a touch; finish it with
    /// [`touch_resolved`](Self::touch_resolved).
    pub fn set_feature(
        &mut self,
        report: &[u8; FEATURE_RPT_SIZE],
        otp: &mut Otp,
        mgmt: Option<&mut dyn MgmtBridge>,
        host: &mut dyn Host,
    ) -> Outcome<()> {
        self.last_now = host.now();
        let flags = report[FEATURE_RPT_SIZE - 1];
        if flags & SLOT_WRITE_FLAG == 0 {
            return Outcome::Done(());
        }
        // Every write ends the read phase and any touch wait.
        self.response = None;
        if self.wait.take().is_some() {
            otp.end_touch_wait(Transport::Hid);
        }
        let seq = flags & !SLOT_WRITE_FLAG;
        if seq > LAST_SEQ {
            self.rx_seq = None;
            return Outcome::Done(());
        }
        match (seq, self.rx_seq) {
            (0, _) => self.rx = [0; FRAME_SIZE],
            (s, Some(previous)) if s > previous => {}
            _ => {
                self.rx_seq = None;
                return Outcome::Done(());
            }
        }
        let offset = usize::from(seq) * FEATURE_RPT_DATA_SIZE;
        if let (Some(dst), Some(src)) = (
            self.rx.get_mut(offset..offset + FEATURE_RPT_DATA_SIZE),
            report.get(..FEATURE_RPT_DATA_SIZE),
        ) {
            dst.copy_from_slice(src);
        }
        if seq == LAST_SEQ {
            self.rx_seq = None;
            return self.dispatch(otp, mgmt, host);
        }
        self.rx_seq = Some(seq);
        Outcome::Done(())
    }

    /// Handle one GET_REPORT of the feature report.
    pub fn get_feature(&mut self, otp: &Otp) -> [u8; FEATURE_RPT_SIZE] {
        if let Some(wait) = &self.wait {
            let left = wait.deadline.saturating_sub(self.last_now).div_ceil(1000);
            let seconds = u8::try_from(left.min(u64::from(SEQUENCE_MASK))).unwrap_or(SEQUENCE_MASK);
            let mut report = status_report(otp);
            report[FEATURE_RPT_SIZE - 1] = RESP_TIMEOUT_WAIT_FLAG | seconds;
            return report;
        }
        if let Some(response) = &mut self.response {
            let mut report = [0u8; FEATURE_RPT_SIZE];
            let start = usize::from(response.next) * FEATURE_RPT_DATA_SIZE;
            if let Some(chunk) = response.data.get(start..start + FEATURE_RPT_DATA_SIZE) {
                report[..FEATURE_RPT_DATA_SIZE].copy_from_slice(chunk);
            }
            report[FEATURE_RPT_SIZE - 1] = RESP_PENDING_FLAG | response.next;
            response.next = (response.next + 1) % response.chunks.max(1);
            return report;
        }
        status_report(otp)
    }

    /// [`get_feature`](Self::get_feature) at time `now`, so the touch-wait report
    /// counts the seconds down.
    pub fn get_feature_at(&mut self, otp: &Otp, now: Millis) -> [u8; FEATURE_RPT_SIZE] {
        self.last_now = self.last_now.max(now);
        self.get_feature(otp)
    }

    /// Finish the challenge-response that returned [`Outcome::NeedTouch`]. Without a
    /// touch (timeout or cancel) the wait ends and the host reads an unchanged status.
    pub fn touch_resolved(&mut self, touched: bool, otp: &mut Otp, host: &mut dyn Host) {
        self.last_now = host.now();
        let Some(wait) = self.wait.take() else {
            return;
        };
        otp.end_touch_wait(Transport::Hid);
        if touched && let Ok(data) = otp.complete_challenge(&wait.pending, host) {
            self.load_response(data);
        }
    }

    /// Whether a challenge-response waits for a touch. A reset write aborts the wait;
    /// `lk-device` checks this after each [`set_feature`](Self::set_feature) to drop
    /// its touch request.
    pub fn is_waiting_for_touch(&self) -> bool {
        self.wait.is_some()
    }

    /// Whether response data is waiting to be read.
    pub fn has_response(&self) -> bool {
        self.response.is_some()
    }

    /// USB reset and power cycle drop the partial frame, the response and the wait.
    /// (`lk-device` resets the shared [`Otp`] with the same kind, which ends its record
    /// of the HID touch wait.)
    pub fn reset(&mut self, kind: ResetKind) {
        if matches!(kind, ResetKind::UsbReset | ResetKind::PowerCycle) {
            *self = Self::new();
        }
    }

    fn dispatch(
        &mut self,
        otp: &mut Otp,
        mgmt: Option<&mut dyn MgmtBridge>,
        host: &mut dyn Host,
    ) -> Outcome<()> {
        let mut payload = [0u8; SLOT_DATA_SIZE];
        payload.copy_from_slice(&self.rx[..SLOT_DATA_SIZE]);
        let command = self.rx[SLOT_DATA_SIZE];
        let crc = u16::from_le_bytes([self.rx[SLOT_DATA_SIZE + 1], self.rx[SLOT_DATA_SIZE + 2]]);
        if crc16(&payload) != crc {
            return Outcome::Done(());
        }
        match otp.execute(command, &payload, mgmt, host) {
            Ok(Reply::Data(data)) => {
                self.load_response(data);
                Outcome::Done(())
            }
            Ok(Reply::NeedTouch(pending)) => {
                let timeout_ms = pending.timeout_ms;
                let deadline = self.last_now.saturating_add(timeout_ms);
                otp.begin_touch_wait(Transport::Hid, deadline);
                self.wait = Some(Wait { pending, deadline });
                Outcome::NeedTouch { timeout_ms }
            }
            Ok(Reply::Status) | Err(_) => Outcome::Done(()),
        }
    }

    fn load_response(&mut self, mut data: Vec<u8>) {
        append_crc(&mut data);
        let chunks = data.len().div_ceil(FEATURE_RPT_DATA_SIZE);
        let Ok(count) = u8::try_from(chunks) else {
            return;
        };
        if chunks == 0 || chunks > MAX_RESPONSE_CHUNKS {
            return;
        }
        data.resize(chunks * FEATURE_RPT_DATA_SIZE, 0);
        self.response = Some(Response {
            data,
            next: 0,
            chunks: count,
        });
    }
}

/// `[0, version(3), pgmSeq, touchLevel(2, LE), 0]`.
fn status_report(otp: &Otp) -> [u8; FEATURE_RPT_SIZE] {
    let mut report = [0u8; FEATURE_RPT_SIZE];
    report[1..7].copy_from_slice(&otp.status());
    report
}
