//! Key commands: GENERATE ASYMMETRIC KEY PAIR (spec 3.4.1 §7.2.14), key import with PUT
//! DATA odd INS DB (§7.2.8, §4.4.3.12), PERFORM SECURITY OPERATION: COMPUTE DIGITAL
//! SIGNATURE (§7.2.10) and DECIPHER (§7.2.11), INTERNAL AUTHENTICATE (§7.2.13), and the
//! Yubico GET ATTESTATION (`80 FB`), with the user interaction flags D6-D9.
//!
//! Rules (spec unless noted):
//! - GENERATE needs PW3 for P1 80 and nothing for P1 81 (read the public key); P2 must be
//!   00 (catalog: "nonzero generation P2 rejection"). Generation or import sets DE to 01 or
//!   02; for the SIG key it also resets the digital signature counter (§4.4.3.14; catalog:
//!   "SIG generation/import resets digital-signature counter; other slots leave it
//!   unchanged").
//! - PSO:CDS needs PW1 verified with 81; when C4 byte 1 is 00 that verification is used up
//!   by one signature (§4.4.3.6). The counter 93 is incremented and persisted before the
//!   signature is returned (docs/CONTRACTS.md "Persisted state"); a failed save answers
//!   `6581` and reveals no signature. It saturates at `FF FF FF` (model policy).
//! - PSO:DECIPHER and INTERNAL AUTHENTICATE need PW1 verified with 82. They use the DEC and
//!   AUT keys, or the other one of the two after MANAGE SECURITY ENVIRONMENT (§7.2.18).
//!   INTERNAL AUTHENTICATE needs P1 = P2 = 00 (catalog). A key whose algorithm cannot do
//!   the operation (an ECDH key asked to sign, a signature key asked to decipher) is
//!   `6985` (model policy).
//! - A slot without a key is `6A88`.
//! - Commands that change state and return data (GENERATE P1 80, PSO:CDS, INTERNAL
//!   AUTHENTICATE) reject an explicit non-zero Le smaller than the result with `6700`
//!   before anything changes, so no signature counter step or key is lost to a truncated
//!   response (catalog: "GENERATE, PSO SIGN and INTERNAL AUTHENTICATE Le mutation
//!   guards"). Le `00`, `0000` or absent are served in chunks with `61xx`.
//! - Touch (Yubico OpenPGP UIF, D6 SIG, D7 DEC, D8 AUT, D9 attestation): 01 on and 02 fixed
//!   need a touch for every operation; 03 cached and 04 cached-fixed accept a touch on that
//!   key made less than 15 s earlier (catalog "15-second cached/fixed touch"; the cache is
//!   per key and kept until power is removed, model policy). The touch is requested after
//!   every access and input check, so a request that would fail never waits; the command
//!   then finishes in `touch_resolved`: on a touch it runs, otherwise it answers `6982`
//!   (model policy shared with lk-piv) and changes nothing. A touch waits at most 15 s.
//! - GET ATTESTATION: CLA 80 only, P1 01/02/03, P2 00, no data, no explicit Le (catalog:
//!   "GET ATTESTATION with explicit Le=1 is rejected before replacing a SIG certificate").
//!   It needs PW1 verified in either mode (YubiKit's `attest_key` is used after
//!   `verify_pin`, which presents mode 81; GnuPG-style hosts hold 82). See attest.rs.

use lk_codec::apdu::{Command, sw};
use lk_core::{Host, Millis};

use crate::attest;
use crate::keys::{self, Algorithm, CryptoKey};
use crate::objects::Slot;
use crate::{OpenPgp, Reply, chunk_len, le_absent_or_zero};

/// How long a command waits for a touch (Yubico documents 15 seconds).
pub(crate) const TOUCH_TIMEOUT_MS: Millis = 15_000;
/// How long a touch stays valid for the cached UIF policies 03 and 04.
pub(crate) const TOUCH_CACHE_MS: Millis = 15_000;
/// Largest digital signature counter: three bytes in DO 93 (spec §4.4.3.14).
const MAX_SIGNATURE_COUNTER: u32 = 0x00FF_FFFF;

/// UIF policy bytes (Yubico OpenPGP touch policy).
const UIF_ON: u8 = 0x01;
const UIF_FIXED: u8 = 0x02;
const UIF_CACHED: u8 = 0x03;
const UIF_CACHED_FIXED: u8 = 0x04;

/// DE status values (spec §4.4.3.8).
const STATUS_GENERATED: u8 = 0x01;
const STATUS_IMPORTED: u8 = 0x02;

/// What a command handler produced: a reply, or an operation waiting for a touch.
#[derive(Debug)]
pub(crate) enum Step {
    Done(Reply),
    Touch(Pending),
}

impl From<Reply> for Step {
    fn from(reply: Reply) -> Self {
        Step::Done(reply)
    }
}

/// An operation that passed every check and waits for the user's touch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pending {
    pub op: Operation,
    /// Response chunk size of the original command.
    pub chunk: usize,
}

/// The work left after the checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Operation {
    Sign { input: Vec<u8> },
    Decipher { slot: Slot, input: Vec<u8> },
    Authenticate { slot: Slot, input: Vec<u8> },
    Attest { slot: Slot },
}

impl Operation {
    /// The key whose UIF governs the operation.
    pub(crate) fn touch_slot(&self) -> Slot {
        match self {
            Operation::Sign { .. } => Slot::Sig,
            Operation::Decipher { slot, .. } | Operation::Authenticate { slot, .. } => *slot,
            Operation::Attest { .. } => Slot::Att,
        }
    }
}

/// Key reference chosen by MSE → slot (02 DEC, 03 AUT).
fn slot_for_reference(reference: u8) -> Slot {
    if reference == 0x02 { Slot::Dec } else { Slot::Aut }
}

/// The mutation guard on Le described in the module documentation.
fn le_guard(cmd: &Command, result_len: usize) -> Result<(), u16> {
    match cmd.le {
        Some(n) if n != 0 && usize::try_from(n).unwrap_or(usize::MAX) < result_len => Err(sw::WRONG_LENGTH),
        _ => Ok(()),
    }
}

impl OpenPgp {
    /// The algorithm of the key in `slot`; `6A88` if the slot holds no usable key.
    fn key_algorithm(&self, slot: Slot) -> Result<Algorithm, u16> {
        let data = self.state.slot(slot);
        let alg = Algorithm::from_attributes(&data.attributes).ok_or(sw::REF_NOT_FOUND)?;
        match &data.key {
            Some(key) if key.matches(alg) => Ok(alg),
            _ => Err(sw::REF_NOT_FOUND),
        }
    }

    /// Rebuild the key of `slot` for use; stored bytes that are not a valid key are `6F00`.
    fn load_key(&self, slot: Slot) -> Result<CryptoKey, u16> {
        let data = self.state.slot(slot);
        data.key.as_ref().and_then(|key| key.load()).ok_or(sw::UNKNOWN)
    }

    /// Whether `slot`'s UIF requires a touch now (module documentation).
    fn needs_touch(&self, slot: Slot, now: Millis) -> bool {
        match self.state.slot(slot).uif.first().copied() {
            Some(UIF_ON | UIF_FIXED) => true,
            Some(UIF_CACHED | UIF_CACHED_FIXED) => {
                let last = self.touch_cache.get(slot.index()).copied().flatten();
                !last.is_some_and(|at| now.saturating_sub(at) < TOUCH_CACHE_MS)
            }
            _ => false,
        }
    }

    /// Run `op` now, or hand it to the touch arbitration.
    fn gate(&mut self, op: Operation, cmd: &Command, host: &mut dyn Host) -> Step {
        if self.needs_touch(op.touch_slot(), host.now()) {
            return Step::Touch(Pending { op, chunk: chunk_len(cmd) });
        }
        Step::Done(self.perform(op, host))
    }

    /// Record a touch for the cached policies.
    pub(crate) fn touched(&mut self, slot: Slot, now: Millis) {
        if let Some(entry) = self.touch_cache.get_mut(slot.index()) {
            *entry = Some(now);
        }
    }

    /// The cryptographic part of an operation, after all checks (and the touch).
    pub(crate) fn perform(&mut self, op: Operation, host: &mut dyn Host) -> Reply {
        match op {
            Operation::Sign { input } => {
                let signature = self.load_key(Slot::Sig)?.sign(&input, host)?;
                let mut next = self.state.clone();
                next.signature_counter = next.signature_counter.saturating_add(1).min(MAX_SIGNATURE_COUNTER);
                self.commit(host, next)?;
                if !self.state.pw1_multi {
                    self.session.pw1_cds = false;
                }
                Ok(signature)
            }
            Operation::Decipher { slot, input } => self.load_key(slot)?.decipher(&input, host),
            Operation::Authenticate { slot, input } => self.load_key(slot)?.sign(&input, host),
            Operation::Attest { slot } => {
                let certificate = attest::attestation_certificate(&self.state, slot, host)?;
                let mut next = self.state.clone();
                next.slot_mut(slot).certificate = certificate;
                self.commit(host, next)?;
                Ok(Vec::new())
            }
        }
    }

    /// GENERATE ASYMMETRIC KEY PAIR (spec §7.2.14). The response is the public key DO 7F49.
    pub(crate) fn generate_key_pair(&mut self, cmd: &Command, host: &mut dyn Host) -> Reply {
        if cmd.p2 != 0 {
            return Err(sw::INCORRECT_P1P2);
        }
        match cmd.p1 {
            0x81 => {
                let slot = keys::parse_crt(&cmd.data)?;
                self.key_algorithm(slot)?;
                Ok(self.load_key(slot)?.public_template())
            }
            0x80 => {
                if !self.session.pw3 {
                    return Err(sw::SECURITY_STATUS);
                }
                let slot = keys::parse_crt(&cmd.data)?;
                let alg = Algorithm::from_attributes(&self.state.slot(slot).attributes).ok_or(sw::CONDITIONS)?;
                let material = keys::generate(alg, host)?;
                let template = material.load().ok_or(sw::UNKNOWN)?.public_template();
                le_guard(cmd, template.len())?;
                let mut next = self.state.clone();
                next.slot_mut(slot).set_key(material, STATUS_GENERATED);
                if slot == Slot::Sig {
                    next.signature_counter = 0;
                }
                self.commit(host, next)?;
                Ok(template)
            }
            _ => Err(sw::INCORRECT_P1P2),
        }
    }

    /// Key import: PUT DATA odd INS DB with P1 P2 = 3FFF and the extended header list 4D
    /// (spec §7.2.8, §4.4.3.12). Needs PW3. Other P1 P2 are `6B00` like PUT DATA.
    pub(crate) fn import_key(&mut self, cmd: &Command, host: &mut dyn Host) -> Reply {
        if !le_absent_or_zero(cmd) {
            return Err(sw::WRONG_LENGTH);
        }
        if u16::from_be_bytes([cmd.p1, cmd.p2]) != 0x3FFF {
            return Err(sw::WRONG_P1P2);
        }
        if !self.session.pw3 {
            return Err(sw::SECURITY_STATUS);
        }
        let (slot, components) = keys::parse_import(&cmd.data)?;
        let alg = Algorithm::from_attributes(&self.state.slot(slot).attributes).ok_or(sw::CONDITIONS)?;
        let material = keys::import_material(alg, &components)?;
        let mut next = self.state.clone();
        next.slot_mut(slot).set_key(material, STATUS_IMPORTED);
        if slot == Slot::Sig {
            next.signature_counter = 0;
        }
        self.commit(host, next)?;
        Ok(Vec::new())
    }

    /// PERFORM SECURITY OPERATION (spec §7.2.10-§7.2.11): P1 P2 9E 9A or 80 86.
    pub(crate) fn perform_security_operation(&mut self, cmd: &Command, host: &mut dyn Host) -> Step {
        let prepared = match (cmd.p1, cmd.p2) {
            (0x9E, 0x9A) => self.prepare_signature(cmd),
            (0x80, 0x86) => self.prepare_decipher(cmd),
            _ => Err(sw::INCORRECT_P1P2),
        };
        match prepared {
            Ok(op) => self.gate(op, cmd, host),
            Err(status) => Step::Done(Err(status)),
        }
    }

    fn prepare_signature(&self, cmd: &Command) -> Result<Operation, u16> {
        if !self.session.pw1_cds {
            return Err(sw::SECURITY_STATUS);
        }
        let alg = self.key_algorithm(Slot::Sig)?;
        if !alg.can_sign() {
            return Err(sw::CONDITIONS);
        }
        keys::check_signature_input(alg, &cmd.data)?;
        le_guard(cmd, alg.signature_len().unwrap_or(0))?;
        Ok(Operation::Sign { input: cmd.data.clone() })
    }

    fn prepare_decipher(&self, cmd: &Command) -> Result<Operation, u16> {
        if !self.session.pw1_other {
            return Err(sw::SECURITY_STATUS);
        }
        if cmd.data.is_empty() {
            return Err(sw::WRONG_LENGTH);
        }
        let slot = slot_for_reference(self.session.mse_confidentiality);
        let alg = self.key_algorithm(slot)?;
        if !alg.can_decipher() {
            return Err(sw::CONDITIONS);
        }
        let input = keys::decipher_input(alg, &cmd.data)?;
        Ok(Operation::Decipher { slot, input })
    }

    /// INTERNAL AUTHENTICATE (spec §7.2.13): P1 = P2 = 00, the authentication input as
    /// data, the response the signature.
    pub(crate) fn internal_authenticate(&mut self, cmd: &Command, host: &mut dyn Host) -> Step {
        match self.prepare_authenticate(cmd) {
            Ok(op) => self.gate(op, cmd, host),
            Err(status) => Step::Done(Err(status)),
        }
    }

    fn prepare_authenticate(&self, cmd: &Command) -> Result<Operation, u16> {
        if cmd.p1 != 0 || cmd.p2 != 0 {
            return Err(sw::INCORRECT_P1P2);
        }
        if !self.session.pw1_other {
            return Err(sw::SECURITY_STATUS);
        }
        let slot = slot_for_reference(self.session.mse_authentication);
        let alg = self.key_algorithm(slot)?;
        if !alg.can_sign() {
            return Err(sw::CONDITIONS);
        }
        keys::check_signature_input(alg, &cmd.data)?;
        le_guard(cmd, alg.signature_len().unwrap_or(0))?;
        Ok(Operation::Authenticate { slot, input: cmd.data.clone() })
    }

    /// Yubico GET ATTESTATION `80 FB <key ref> 00` (module documentation, attest.rs).
    pub(crate) fn attest(&mut self, cmd: &Command, host: &mut dyn Host) -> Step {
        match self.prepare_attest(cmd) {
            Ok(op) => self.gate(op, cmd, host),
            Err(status) => Step::Done(Err(status)),
        }
    }

    fn prepare_attest(&self, cmd: &Command) -> Result<Operation, u16> {
        if !le_absent_or_zero(cmd) || !cmd.data.is_empty() {
            return Err(sw::WRONG_LENGTH);
        }
        if cmd.p2 != 0 {
            return Err(sw::INCORRECT_P1P2);
        }
        let slot = match cmd.p1 {
            0x01 => Slot::Sig,
            0x02 => Slot::Dec,
            0x03 => Slot::Aut,
            _ => return Err(sw::INCORRECT_P1P2),
        };
        if !self.session.pw1_cds && !self.session.pw1_other {
            return Err(sw::SECURITY_STATUS);
        }
        self.key_algorithm(slot)?;
        if self.state.slot(slot).key_status != STATUS_GENERATED {
            return Err(sw::CONDITIONS);
        }
        if self.key_algorithm(Slot::Att).is_err() {
            return Err(sw::CONDITIONS);
        }
        Ok(Operation::Attest { slot })
    }
}
