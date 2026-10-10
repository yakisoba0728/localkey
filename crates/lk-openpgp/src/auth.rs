//! Password commands: VERIFY (spec 3.4.1 §7.2.2), CHANGE REFERENCE DATA (§7.2.3),
//! RESET RETRY COUNTER (§7.2.4) and the Yubico SET RETRIES (INS F2).
//!
//! Rules shared by all of them:
//! - Header (P1/P2), explicit Le and data length are validated before any retry counter
//!   or password changes (catalog: "P1/data validation before PIN retry or state
//!   mutation", "explicit Le guards").
//! - A new password must respect the length policy (PW1 6-127 bytes, PW3 and resetting
//!   code 8-127 bytes, spec §4.3; exactly the hash length while a KDF-DO is active,
//!   §4.3.2); a violation answers `6A80` without touching any counter.
//! - Comparisons use `lk_crypto::ct_eq`.
//! - Every presentation first spends one try and persists the lowered counter; only then
//!   is the value compared (the anti-tearing order of ISO/IEC 7816 cards: a comparison is
//!   made only once its failure is on record). A wrong value answers `63Cx` with the
//!   already saved counter; a right one restores the counter to its maximum and persists
//!   that before `9000`. If a save fails, the answer is `6581` and nothing changes
//!   (docs/CONTRACTS.md "Persisted state"): when the try cannot be saved no comparison is
//!   made at all, so failing storage reveals nothing about the value and never yields
//!   tries that a restart would give back. A right value whose counter cannot be restored
//!   stays spent (fail closed) and is not verified.
//! - A wrong PW1 clears both PW1 modes (81 and 82; catalog: "wrong PIN invalidates both
//!   PW1 authorization modes").
//! - A blocked password (counter 0) answers `6983`.
//! - CHANGE REFERENCE DATA and RESET RETRY COUNTER split `old || new` at the length of
//!   the stored reference, which the card necessarily knows.

use lk_codec::apdu::{Command, sw};
use lk_core::Host;
use lk_crypto::ct_eq;

use crate::state::{PW1, PW3, RC, State};
use crate::{OpenPgp, Reply, le_absent_or_zero};

/// Largest password presented to VERIFY (C4 maximum length 127).
const MAX_PW_LEN: usize = 127;
const MIN_PW1_LEN: usize = 6;
const MIN_PW3_LEN: usize = 8;
const MIN_RC_LEN: usize = 8;

/// Which password a command addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Password {
    /// PW1 for PSO:CDS (P2 81).
    Pw1Cds,
    /// PW1 for the other PW1 operations (P2 82).
    Pw1Other,
    /// PW3 (P2 83).
    Pw3,
}

impl Password {
    fn counter(self) -> usize {
        match self {
            Password::Pw1Cds | Password::Pw1Other => PW1,
            Password::Pw3 => PW3,
        }
    }
}

/// The length policy for a new password value (spec §4.3, §4.3.2).
pub(crate) fn new_password_ok(state: &State, value: &[u8], min_len: usize) -> bool {
    match state.kdf().hash_len() {
        Some(len) => value.len() == len,
        None => (min_len..=MAX_PW_LEN).contains(&value.len()),
    }
}

/// Minimum length of a new resetting code.
pub(crate) const RC_MIN: usize = MIN_RC_LEN;

impl OpenPgp {
    fn verified(&self, pw: Password) -> bool {
        match pw {
            Password::Pw1Cds => self.session.pw1_cds,
            Password::Pw1Other => self.session.pw1_other,
            Password::Pw3 => self.session.pw3,
        }
    }

    fn set_verified(&mut self, pw: Password, value: bool) {
        match pw {
            Password::Pw1Cds => self.session.pw1_cds = value,
            Password::Pw1Other => self.session.pw1_other = value,
            Password::Pw3 => self.session.pw3 = value,
        }
    }

    /// Drop the access a wrong password presentation invalidates.
    fn invalidate(&mut self, counter: usize) {
        if counter == PW1 {
            self.session.pw1_cds = false;
            self.session.pw1_other = false;
        } else if counter == PW3 {
            self.session.pw3 = false;
        }
    }

    fn remaining(&self, counter: usize) -> u8 {
        self.state.retries.get(counter).copied().unwrap_or(0)
    }

    /// Spend one try of `counter` and persist it before the presented value is compared
    /// (module documentation). Returns the tries left. On a storage failure nothing
    /// changes and the answer is `6581`; the caller must then not compare at all, so that
    /// `6581` (try not recorded) is the answer for right and wrong values alike. Without
    /// this order a right PIN whose counter is already at its maximum needs no save and
    /// answers `9000` while a wrong one answers `6581`: with storage failing, that is an
    /// oracle whose tries a restart gives back.
    fn spend_try(&mut self, host: &mut dyn Host, counter: usize) -> Result<u8, u16> {
        let left = self.remaining(counter).saturating_sub(1);
        let mut next = self.state.clone();
        if let Some(slot) = next.retries.get_mut(counter) {
            *slot = left;
        }
        self.commit(host, next)?;
        Ok(left)
    }

    /// A wrong presentation whose try [`Self::spend_try`] already saved: drop the access
    /// it invalidates and answer `63Cx`.
    fn wrong_password(&mut self, counter: usize, left: u8) -> u16 {
        self.invalidate(counter);
        sw::retries(left)
    }

    /// Restore a counter to its maximum after a correct presentation. After
    /// [`Self::spend_try`] the counter is normally below its maximum, so this saves; the
    /// save is skipped only when the counter already equals the maximum.
    fn reset_counter(&mut self, host: &mut dyn Host, counter: usize) -> Result<(), u16> {
        let max = self.state.max_retries.get(counter).copied().unwrap_or(0);
        if self.remaining(counter) == max {
            return Ok(());
        }
        let mut next = self.state.clone();
        if let Some(slot) = next.retries.get_mut(counter) {
            *slot = max;
        }
        self.commit(host, next)
    }

    /// VERIFY (spec §7.2.2). P1 00 presents a password; P1 FF (spec 3.4) resets the
    /// access status of P2's password. Without data the command reports the status:
    /// `9000` when verified, otherwise `63Cx` or `6983`.
    pub(crate) fn verify(&mut self, cmd: &Command, host: &mut dyn Host) -> Reply {
        if !le_absent_or_zero(cmd) {
            return Err(sw::WRONG_LENGTH);
        }
        let pw = match cmd.p2 {
            0x81 => Password::Pw1Cds,
            0x82 => Password::Pw1Other,
            0x83 => Password::Pw3,
            _ => return Err(sw::INCORRECT_P1P2),
        };
        match cmd.p1 {
            0x00 => {}
            0xFF => {
                if !cmd.data.is_empty() {
                    return Err(sw::WRONG_LENGTH);
                }
                self.set_verified(pw, false);
                return Ok(Vec::new());
            }
            _ => return Err(sw::INCORRECT_P1P2),
        }
        let counter = pw.counter();
        if cmd.data.is_empty() {
            if self.verified(pw) {
                return Ok(Vec::new());
            }
            return Err(match self.remaining(counter) {
                0 => sw::AUTH_BLOCKED,
                n => sw::retries(n),
            });
        }
        if cmd.data.len() > MAX_PW_LEN {
            return Err(sw::WRONG_LENGTH);
        }
        if self.remaining(counter) == 0 {
            return Err(sw::AUTH_BLOCKED);
        }
        let left = self.spend_try(host, counter)?;
        let reference = if counter == PW1 { &self.state.pw1 } else { &self.state.pw3 };
        if !ct_eq(&cmd.data, reference) {
            return Err(self.wrong_password(counter, left));
        }
        self.reset_counter(host, counter)?;
        self.set_verified(pw, true);
        Ok(Vec::new())
    }

    /// CHANGE REFERENCE DATA (spec §7.2.3): P1 00, P2 81 (PW1) or 83 (PW3), data
    /// `old || new`. The access status is left as it was.
    pub(crate) fn change_reference_data(&mut self, cmd: &Command, host: &mut dyn Host) -> Reply {
        if !le_absent_or_zero(cmd) {
            return Err(sw::WRONG_LENGTH);
        }
        if cmd.p1 != 0 {
            return Err(sw::INCORRECT_P1P2);
        }
        let (counter, min_len) = match cmd.p2 {
            0x81 => (PW1, MIN_PW1_LEN),
            0x83 => (PW3, MIN_PW3_LEN),
            _ => return Err(sw::INCORRECT_P1P2),
        };
        if cmd.data.is_empty() || cmd.data.len() > 2 * MAX_PW_LEN {
            return Err(sw::WRONG_LENGTH);
        }
        if self.remaining(counter) == 0 {
            return Err(sw::AUTH_BLOCKED);
        }
        let reference_len = if counter == PW1 { self.state.pw1.len() } else { self.state.pw3.len() };
        let (old, new) = cmd
            .data
            .split_at_checked(reference_len)
            .ok_or(sw::INCORRECT_DATA)?;
        if !new_password_ok(&self.state, new, min_len) {
            return Err(sw::INCORRECT_DATA);
        }
        let left = self.spend_try(host, counter)?;
        let reference = if counter == PW1 { &self.state.pw1 } else { &self.state.pw3 };
        if !ct_eq(old, reference) {
            return Err(self.wrong_password(counter, left));
        }
        let mut next = self.state.clone();
        if counter == PW1 {
            next.pw1 = new.to_vec();
        } else {
            next.pw3 = new.to_vec();
        }
        if let (Some(slot), Some(max)) = (next.retries.get_mut(counter), self.state.max_retries.get(counter)) {
            *slot = *max;
        }
        self.commit(host, next)?;
        Ok(Vec::new())
    }

    /// RESET RETRY COUNTER (spec §7.2.4), P2 81: P1 00 with data `resetting code || new
    /// PW1`, or P1 02 with data `new PW1` after PW3 verification. Success sets PW1 and
    /// restores its counter (and the resetting code's, for P1 00).
    pub(crate) fn reset_retry_counter(&mut self, cmd: &Command, host: &mut dyn Host) -> Reply {
        if !le_absent_or_zero(cmd) {
            return Err(sw::WRONG_LENGTH);
        }
        if cmd.p2 != 0x81 {
            return Err(sw::INCORRECT_P1P2);
        }
        match cmd.p1 {
            0x00 => self.reset_with_code(cmd, host),
            0x02 => {
                if cmd.data.is_empty() || cmd.data.len() > MAX_PW_LEN {
                    return Err(sw::WRONG_LENGTH);
                }
                if !self.session.pw3 {
                    return Err(sw::SECURITY_STATUS);
                }
                if !new_password_ok(&self.state, &cmd.data, MIN_PW1_LEN) {
                    return Err(sw::INCORRECT_DATA);
                }
                let next = self.with_new_pw1(&cmd.data, false);
                self.commit(host, next)?;
                Ok(Vec::new())
            }
            _ => Err(sw::INCORRECT_P1P2),
        }
    }

    fn reset_with_code(&mut self, cmd: &Command, host: &mut dyn Host) -> Reply {
        if cmd.data.is_empty() || cmd.data.len() > 2 * MAX_PW_LEN {
            return Err(sw::WRONG_LENGTH);
        }
        let Some(code) = self.state.rc.clone() else {
            return Err(sw::AUTH_BLOCKED);
        };
        if self.remaining(RC) == 0 {
            return Err(sw::AUTH_BLOCKED);
        }
        let (old, new) = cmd
            .data
            .split_at_checked(code.len())
            .ok_or(sw::INCORRECT_DATA)?;
        if !new_password_ok(&self.state, new, MIN_PW1_LEN) {
            return Err(sw::INCORRECT_DATA);
        }
        let left = self.spend_try(host, RC)?;
        if !ct_eq(old, &code) {
            return Err(self.wrong_password(RC, left));
        }
        let next = self.with_new_pw1(new, true);
        self.commit(host, next)?;
        Ok(Vec::new())
    }

    fn with_new_pw1(&self, new: &[u8], restore_rc: bool) -> State {
        let mut next = self.state.clone();
        next.pw1 = new.to_vec();
        let [pw1_max, rc_max, _] = next.max_retries;
        if let Some(slot) = next.retries.get_mut(PW1) {
            *slot = pw1_max;
        }
        if restore_rc && let Some(slot) = next.retries.get_mut(RC) {
            *slot = rc_max;
        }
        next
    }

    /// Yubico SET RETRIES (INS F2, Yubico OpenPGP extension, firmware 4.3.1 and later):
    /// P1 = P2 = 00, data = tries for PW1, RC and PW3, PW3 verification required. The
    /// counters become the new maxima and are refilled; the resetting code's counter stays
    /// 0 while no code is set. The PINs themselves are unchanged. Header and Le are
    /// checked before anything else (catalog: SET RETRIES F2 header rules).
    pub(crate) fn set_retries(&mut self, cmd: &Command, host: &mut dyn Host) -> Reply {
        if cmd.p1 != 0 || cmd.p2 != 0 {
            return Err(sw::INCORRECT_P1P2);
        }
        if !le_absent_or_zero(cmd) {
            return Err(sw::WRONG_LENGTH);
        }
        if !self.session.pw3 {
            return Err(sw::SECURITY_STATUS);
        }
        let tries: [u8; 3] = cmd.data.as_slice().try_into().map_err(|_| sw::WRONG_LENGTH)?;
        if tries.contains(&0) {
            return Err(sw::INCORRECT_DATA);
        }
        let mut next = self.state.clone();
        next.max_retries = tries;
        let [pw1, rc, pw3] = tries;
        next.retries = [pw1, if next.rc.is_some() { rc } else { 0 }, pw3];
        self.commit(host, next)?;
        Ok(Vec::new())
    }
}
