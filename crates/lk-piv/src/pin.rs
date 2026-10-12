//! PIN and PUK: VERIFY, CHANGE REFERENCE DATA and RESET RETRY COUNTER
//! (SP 800-73-4 Part 2 §3.2.1, §3.2.2, §3.2.3), with the reference data format of
//! §2.4.3 and Yubico's retry limits.
//!
//! Reference data is always 8 bytes: the PIN or PUK followed by `FF` padding. A new
//! value must be 6 to 8 bytes long (SP 800-73-4 Part 2 §2.4.3 for the PIN; Yubico PIV
//! documentation for the PUK); any byte other than `FF` may appear in it (Yubico: the PIN
//! "supports any type of alphanumeric characters", relaxing the §2.4.3 digits-only rule).
//!
//! A presented current value (the PIN of VERIFY and CHANGE REFERENCE DATA, the PUK of
//! CHANGE REFERENCE DATA and RESET RETRY COUNTER) must be exactly 8 bytes (`6A80`, nothing
//! spent), and any 8 bytes are compared, with a retry spent first. SP 800-73-4 Part 2
//! §3.2.1.1 and §3.2.2 allow `6A80` or `63CX` for PIN data outside the §2.4.3 format;
//! this model answers `63CX` because python yubikit's `PivSession.reset()` (`ykman piv
//! reset`) blocks the PIN with `verify_pin("")`, eight `FF` bytes, and fails unless every
//! answer is `63CX` or `6983`. A stored PIN always has the §2.4.3 format, so such data
//! never matches.
//!
//! Order of the checks for `current || new`: CHANGE REFERENCE DATA checks the new value's
//! format before comparing (`6A80`, nothing spent). RESET RETRY COUNTER compares the PUK
//! first, because `reset()` blocks the PUK with `FF*8 || FF*8` and needs `63CX` for it; a
//! matching PUK with a malformed new PIN is `6A80` and leaves the PIN, the PUK retry
//! counter (restored to its value before the command) and the security status unchanged.
//!
//! Security status (SP 800-73-4 Part 2): a successful VERIFY or CHANGE REFERENCE DATA of
//! the PIN sets the PIN's security status (§3.2.1.1, §3.2.2); a failed comparison clears
//! it, including a wrong PUK in RESET RETRY COUNTER (§3.2.3), whose success leaves it
//! unchanged ("The security status of the PIN's key reference shall not be changed"). Only
//! VERIFY arms the PIN-always authorization (crate documentation).
//!
//! Retry counter ordering: before comparing, the counter is decremented and persisted;
//! on a match the counter is restored to its limit and persisted again (together with
//! any new reference data). A comparison therefore never happens unless its failure is
//! already durable, and a storage failure answers `6581` without revealing whether the
//! value was right (`docs/DESIGN.md` §7; `lk_core::Host::persist`).

use lk_codec::apdu::{Command, sw};
use lk_core::Host;
use lk_crypto::{SecretBytes, ct_eq};

use crate::state::{Credential, PivState};
use crate::{Piv, Reply, explicit_le};

/// Key reference of the PIV Card Application PIN (SP 800-73-4 Part 1 Table 4).
pub(crate) const KEY_PIN: u8 = 0x80;
/// Key reference of the PIN Unblocking Key (SP 800-73-4 Part 1 Table 4).
pub(crate) const KEY_PUK: u8 = 0x81;

/// Length of padded reference data (SP 800-73-4 Part 2 §2.4.3).
const REFERENCE_LEN: usize = 8;
/// Shortest PIN or PUK (SP 800-73-4 Part 2 §2.4.3).
const MIN_REFERENCE_LEN: usize = 6;
/// The padding byte (SP 800-73-4 Part 2 §2.4.3).
const PAD: u8 = 0xFF;

/// Which retry-counted reference: PIN (`80`) or PUK (`81`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CredRef {
    Pin,
    Puk,
}

impl PivState {
    pub(crate) fn cred(&self, which: CredRef) -> &Credential {
        match which {
            CredRef::Pin => &self.pin,
            CredRef::Puk => &self.puk,
        }
    }

    pub(crate) fn cred_mut(&mut self, which: CredRef) -> &mut Credential {
        match which {
            CredRef::Pin => &mut self.pin,
            CredRef::Puk => &mut self.puk,
        }
    }
}

/// Whether `block` is well-formed PIN or PUK reference data: 8 bytes, 6 to 8 leading
/// non-`FF` bytes, then only `FF` (SP 800-73-4 Part 2 §2.4.3).
pub(crate) fn valid_reference(block: &[u8]) -> bool {
    if block.len() != REFERENCE_LEN {
        return false;
    }
    let len = block.iter().position(|&b| b == PAD).unwrap_or(REFERENCE_LEN);
    len >= MIN_REFERENCE_LEN && block.get(len..).is_some_and(|pad| pad.iter().all(|&b| b == PAD))
}

/// Check P2 of a PIN command: any key reference outside `allowed` is `6A88` (SP 800-73-4
/// Part 2 §3.2.1: "If any key reference value is specified that cannot be verified ...
/// '6A 88'"; §3.2.2 and §3.2.3 likewise for references that are not supported). That
/// includes the global PIN `00` (Part 1 Table 4b), which this card does not hold: the
/// Discovery Object's PIN usage policy names only the PIV Card Application PIN.
fn check_reference_p2(p2: u8, allowed: &[u8]) -> Result<(), u16> {
    if allowed.contains(&p2) { Ok(()) } else { Err(sw::REF_NOT_FOUND) }
}

/// Whether `status` is a failed comparison (`63CX`).
fn is_retry_status(status: u16) -> bool {
    status & 0xFFF0 == 0x63C0
}

impl Piv {
    /// Compare `candidate` with the PIN or PUK.
    ///
    /// Blocked: `6983` without comparing. Otherwise the counter is decremented and
    /// persisted first. Mismatch: `63Cx` with the retries left (`63C0` on the attempt that
    /// blocks; SP 800-73-4 Part 2 §3.2.1) and, for the PIN, the verified status is reset.
    /// Match: the counter is restored to its limit and `on_match` is applied in the same
    /// commit. If `on_match` refuses the request instead (a matching PUK with a malformed
    /// new PIN), the counter is put back to its value before the command and that status
    /// is returned. Storage failure: `6581`.
    pub(crate) fn check_reference(
        &mut self,
        which: CredRef,
        candidate: &[u8],
        host: &mut dyn Host,
        on_match: impl FnOnce(&mut PivState) -> Result<(), u16>,
    ) -> Result<(), u16> {
        if self.state.cred(which).blocked() {
            return Err(sw::AUTH_BLOCKED);
        }
        let before = self.state.cred(which).remaining;
        self.modify(host, |s| {
            let cred = s.cred_mut(which);
            cred.remaining = cred.remaining.saturating_sub(1);
        })?;
        if !ct_eq(candidate, &self.state.cred(which).value) {
            if which == CredRef::Pin {
                self.session.pin_verified = false;
            }
            return Err(sw::retries(self.state.cred(which).remaining));
        }
        let mut next = self.state.clone();
        let cred = next.cred_mut(which);
        cred.remaining = cred.max;
        match on_match(&mut next) {
            Ok(()) => self.commit(host, next),
            Err(status) => {
                self.modify(host, |s| s.cred_mut(which).remaining = before)?;
                Err(status)
            }
        }
    }

    /// VERIFY (`INS 20`, SP 800-73-4 Part 2 §3.2.1).
    ///
    /// - P1 `00` with the 8-byte PIN: verify; P1 `00` without data: report the status
    ///   (`9000` if verified, else `63Cx`, or `6983` when blocked); P1 `FF` without data:
    ///   reset the PIN's security status.
    /// - P1 other than `00`/`FF` is `6A86`. Any P2 other than `80` is then `6A88`, the PUK
    ///   `81` included: §3.2.1 "If any key reference value is specified that cannot be
    ///   verified by the PIV Card Application, then the PIV Card Application shall return
    ///   the status word '6A 88'", and this card compares the PUK only inside CHANGE
    ///   REFERENCE DATA and RESET RETRY COUNTER. Known difference: the reference key
    ///   answers `00 20 00 81` with `6A80` (docs/MEASUREMENT.md, probe
    ///   `piv-verify-status-81`); the specification is followed instead, and no listed
    ///   host depends on that answer (libykpiv verifies P2 `80` only, yubikit reads the
    ///   PUK retries with GET METADATA). A non-zero Le is `6700` (§3.2.1 lists Le as
    ///   absent; catalog "VERIFY/CHANGE/RESET RETRY PIN-command P1/P2/Le guards before
    ///   state changes"); Le `00`, which yubico-piv-tool appends on T=1, and the five-byte
    ///   T=0 form of the status query are accepted (`crate::explicit_le`).
    /// - PIN data that is not 8 bytes is `6A80` and does not consume a retry (§3.2.1.1).
    ///   Any 8 bytes are compared (module documentation: python yubikit verifies eight
    ///   `FF` bytes to block the PIN and needs `63CX`).
    ///
    /// `armed` is the PIN-always authorization from before this command: the status query
    /// keeps it, a successful verification arms it, anything else clears it.
    pub(crate) fn verify(&mut self, cmd: &Command, armed: bool, host: &mut dyn Host) -> Reply {
        if cmd.p1 != 0x00 && cmd.p1 != 0xFF {
            return Err(sw::INCORRECT_P1P2);
        }
        check_reference_p2(cmd.p2, &[KEY_PIN])?;
        if explicit_le(cmd) {
            return Err(sw::WRONG_LENGTH);
        }
        if cmd.p1 == 0xFF {
            if !cmd.data.is_empty() {
                return Err(sw::WRONG_LENGTH);
            }
            self.session.pin_verified = false;
            return Ok(Vec::new());
        }
        if cmd.data.is_empty() {
            // A status query neither verifies nor changes anything.
            self.session.pin_always = armed;
            return if self.state.pin.blocked() {
                Err(sw::AUTH_BLOCKED)
            } else if self.session.pin_verified {
                Ok(Vec::new())
            } else {
                Err(sw::retries(self.state.pin.remaining))
            };
        }
        if cmd.data.len() != REFERENCE_LEN {
            return Err(sw::INCORRECT_DATA);
        }
        self.check_reference(CredRef::Pin, &cmd.data, host, |_| Ok(()))?;
        self.session.pin_verified = true;
        // Arms one operation with PIN policy "always" (`asym::slot_authenticate`).
        self.session.pin_always = true;
        Ok(Vec::new())
    }

    /// CHANGE REFERENCE DATA (`INS 24`, SP 800-73-4 Part 2 §3.2.2): P1 `00`, P2 `80`
    /// (PIN) or `81` (PUK), data = current value (8) || new value (8), Le absent or `00`.
    ///
    /// The length and the new value's format are checked before the current value is
    /// compared, so a malformed request is `6A80` and never consumes a retry (§3.2.2: "If
    /// status word '6A 80' is returned, the security status and retry counter ... shall
    /// remain unchanged"). The current value may be any 8 bytes and is compared (module
    /// documentation). A wrong current value consumes one retry and clears the PIN's
    /// security status; success sets it ("the security status of the key reference shall
    /// be set to TRUE"). Other key references are `6A88`.
    pub(crate) fn change_reference(&mut self, cmd: &Command, host: &mut dyn Host) -> Reply {
        if cmd.p1 != 0x00 {
            return Err(sw::INCORRECT_P1P2);
        }
        check_reference_p2(cmd.p2, &[KEY_PIN, KEY_PUK])?;
        if explicit_le(cmd) {
            return Err(sw::WRONG_LENGTH);
        }
        let which = if cmd.p2 == KEY_PIN { CredRef::Pin } else { CredRef::Puk };
        let (current, new) = split_pair(&cmd.data)?;
        let new = new_reference(new)?;
        self.check_reference(which, current, host, |s| {
            s.cred_mut(which).value = new;
            Ok(())
        })?;
        if which == CredRef::Pin {
            self.session.pin_verified = true;
        }
        Ok(Vec::new())
    }

    /// RESET RETRY COUNTER (`INS 2C`, SP 800-73-4 Part 2 §3.2.3): P1 `00`, P2 `80`
    /// (anything else `6A88`), data = PUK (8) || new PIN (8), Le absent or `00`. Data that
    /// is not 16 bytes is `6A80` and spends nothing. The PUK is compared before the new
    /// PIN's format is checked (python yubikit blocks the PUK with `FF*8 || FF*8` and
    /// needs `63CX`; module documentation). A correct PUK with a well-formed new PIN sets
    /// it, restores both retry counters and leaves the PIN's security status unchanged
    /// ("The security status of the PIN's key reference shall not be changed"); with a
    /// malformed new PIN it is `6A80` and nothing changes. A wrong PUK consumes a PUK retry
    /// and clears the PIN's security status (§3.2.3: on '63 CX' "the security status of
    /// the PIN's key reference shall be set to FALSE").
    pub(crate) fn reset_retry_counter(&mut self, cmd: &Command, host: &mut dyn Host) -> Reply {
        if cmd.p1 != 0x00 {
            return Err(sw::INCORRECT_P1P2);
        }
        check_reference_p2(cmd.p2, &[KEY_PIN])?;
        if explicit_le(cmd) {
            return Err(sw::WRONG_LENGTH);
        }
        let (puk, new_pin) = split_pair(&cmd.data)?;
        self.check_reference(CredRef::Puk, puk, host, |s| {
            s.pin.value = new_reference(new_pin)?;
            s.pin.remaining = s.pin.max;
            Ok(())
        })
        .inspect_err(|&status| {
            if is_retry_status(status) {
                self.session.pin_verified = false;
            }
        })?;
        Ok(Vec::new())
    }
}

/// Split `current || new` (8 + 8 bytes; `6A80` otherwise).
fn split_pair(data: &[u8]) -> Result<(&[u8], &[u8]), u16> {
    if data.len() != 2 * REFERENCE_LEN {
        return Err(sw::INCORRECT_DATA);
    }
    data.split_at_checked(REFERENCE_LEN).ok_or(sw::INCORRECT_DATA)
}

/// A new PIN or PUK in the §2.4.3 format (`6A80` otherwise).
fn new_reference(new: &[u8]) -> Result<SecretBytes, u16> {
    if !valid_reference(new) {
        return Err(sw::INCORRECT_DATA);
    }
    Ok(SecretBytes::from_slice(new))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_reference_format() {
        // SP 800-73-4 Part 2 §2.4.3: 6..=8 bytes, padded with FF to 8.
        assert!(valid_reference(b"123456\xFF\xFF"));
        assert!(valid_reference(b"1234567\xFF"));
        assert!(valid_reference(b"12345678"));
        assert!(valid_reference(b"abc!@#\xFF\xFF"), "any non-FF byte is allowed");
        assert!(!valid_reference(b"12345\xFF\xFF\xFF"), "too short");
        assert!(!valid_reference(b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"), "empty");
        assert!(!valid_reference(b"123456\xFF7"), "data after padding");
        assert!(!valid_reference(b"123456"), "not padded to 8");
        assert!(!valid_reference(b"123456789"), "longer than 8");
    }

    #[test]
    fn retry_status_detection() {
        assert!(is_retry_status(sw::retries(0)));
        assert!(is_retry_status(sw::retries(15)));
        assert!(!is_retry_status(sw::AUTH_BLOCKED));
        assert!(!is_retry_status(sw::MEMORY_FAILURE));
    }
}
