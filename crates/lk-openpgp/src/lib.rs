//! OpenPGP card application (OpenPGP Smart Card Application Functional Specification
//! 3.4.1, "spec") as a YubiKey 5C Nano 5.7.4 presents it: SIG/DEC/AUT keys plus the
//! Yubico attestation slot, PW1/PW3 with resetting code, KDF-DO, data objects, signature
//! counter, GET DATA / PUT DATA chaining, TERMINATE DF / ACTIVATE FILE.
//!
//! Commands: SELECT, GET DATA / PUT DATA for every data object, SELECT DATA / GET NEXT DATA
//! for the certificate DO 7F21, VERIFY, CHANGE REFERENCE DATA, RESET RETRY COUNTER, KDF-DO,
//! GET CHALLENGE, MANAGE SECURITY ENVIRONMENT, TERMINATE DF / ACTIVATE FILE, command
//! chaining, GET RESPONSE, GENERATE ASYMMETRIC KEY PAIR, key import (PUT DATA odd INS DB),
//! PSO:COMPUTE DIGITAL SIGNATURE, PSO:DECIPHER, INTERNAL AUTHENTICATE, and the Yubico GET
//! VERSION (F1), SET RETRIES (F2) and GET ATTESTATION (80 FB). Key algorithms are those of
//! the algorithm information FA that lk-crypto implements: RSA 2048/3072/4096, ECDSA and
//! ECDH on P-256, P-384, P-521, secp256k1, brainpoolP256r1 and brainpoolP384r1, Ed25519
//! and X25519 (operations.rs, keys.rs); brainpoolP512r1 is advertised but answers `6A81`
//! (no lk-crypto arithmetic). The user
//! interaction flags D6-D9 make operations wait for a touch (`Outcome::NeedTouch`).
//!
//! On first start (no readable stored state) the application provisions its own RSA 2048
//! attestation issuer with a self-signed certificate (attest.rs) and saves it.
//!
//! Public objects (5F52, 7F66, 7F74, C0, FA, the 6E and 7A layouts) byte-match
//! `reference/yubikey-5c-nano-5.7.4/openpgp-reference-observation.json`.
//!
//! Framing rules (ISO/IEC 7816-4 §5.1 and the behaviour catalog's OpenPGP section):
//! - CLA must be interindustry on the basic channel without secure messaging (`6E00` for
//!   other classes, `6882` for the secure-messaging bits, `6881` for a logical channel),
//!   except GET ATTESTATION, which takes the proprietary CLA 80 only (`84`, its
//!   secure-messaging form, is `6882`). `lk-device` unwraps a secure channel and clears
//!   those bits before the applet sees the command, so a command that still carries them
//!   was never verified; C0 announces no secure messaging either (docs/CONTRACTS.md
//!   "APDU conventions"; ISO 7816-4 §5.1.1, the order of lk-piv). A command rejected for
//!   its CLA or INS leaves a pending response and a pending command chain untouched.
//! - Command chaining (CLA bit `10`, ISO 7816-4 §5.1.1.1) is accepted only for commands
//!   that carry data; GET DATA and the other data-less commands answer `6E00` to it.
//! - GET RESPONSE (`C0`) serves the rest of a long response; any other command discards
//!   it. GET RESPONSE during an unfinished chain answers `6883` and drops the chain.
//! - Commands that return no data reject an explicit non-zero Le with `6700` before they
//!   change any state (catalog: VERIFY/CHANGE/RESET RETRY COUNTER/PUT DATA/SELECT DATA/
//!   SET RETRIES/GET ATTESTATION/lifecycle "explicit Le" guards). `Le = 00` stays
//!   acceptable. Commands that change state and return data reject an explicit Le smaller
//!   than their result (operations.rs).
//! - While the application is terminated every supported command except ACTIVATE FILE
//!   answers `6285` (ISO 7816-4 §5.1.3 "selected file in termination state"); CLA, INS
//!   and chaining-bit errors are reported first, as in the operational state.
//! - A command waiting for a touch is abandoned by any other command, SELECT, deselection
//!   or reset; `touch_resolved` then answers `6985`.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

mod attest;
mod auth;
mod data;
mod kdf;
mod keys;
mod objects;
mod operations;
mod state;

use lk_codec::apdu::{self, Command, CommandChain, ResponseQueue, sw};
use lk_core::{CardApplet, Host, Millis, Outcome, Record, ResetKind};

pub use objects::AID_PREFIX;

use objects::{MAX_CHAIN_DATA, MAX_CHALLENGE, MAX_COMMAND_DATA, MAX_RESPONSE};
use operations::{Pending, Step, TOUCH_TIMEOUT_MS};
use state::{PW3, SLOTS, State};

/// ISO 7816-4 §5.1.3: "selected file in termination state".
const SW_TERMINATED: u16 = 0x6285;

/// Instruction bytes (spec §7.1 table, plus Yubico F1/F2).
mod ins {
    pub const SELECT_DATA: u8 = 0xA5;
    pub const GET_DATA: u8 = 0xCA;
    pub const GET_NEXT_DATA: u8 = 0xCC;
    pub const VERIFY: u8 = 0x20;
    pub const CHANGE_REFERENCE_DATA: u8 = 0x24;
    pub const RESET_RETRY_COUNTER: u8 = 0x2C;
    pub const PUT_DATA: u8 = 0xDA;
    pub const GET_CHALLENGE: u8 = 0x84;
    pub const MANAGE_SECURITY_ENVIRONMENT: u8 = 0x22;
    pub const GET_RESPONSE: u8 = 0xC0;
    pub const TERMINATE_DF: u8 = 0xE6;
    pub const ACTIVATE_FILE: u8 = 0x44;
    /// Yubico: firmware version.
    pub const GET_VERSION: u8 = 0xF1;
    /// Yubico: set the PIN retry counters.
    pub const SET_RETRIES: u8 = 0xF2;
    pub const GENERATE_ASYMMETRIC_KEY_PAIR: u8 = 0x47;
    pub const PERFORM_SECURITY_OPERATION: u8 = 0x2A;
    pub const INTERNAL_AUTHENTICATE: u8 = 0x88;
    /// PUT DATA with odd INS: key import (spec §7.2.8).
    pub const PUT_DATA_ODD: u8 = 0xDB;
    /// Yubico: attest a key (CLA 80).
    pub const GET_ATTESTATION: u8 = 0xFB;
}

/// The proprietary class of the Yubico GET ATTESTATION command.
const CLA_PROPRIETARY: u8 = 0x80;
/// The same class with the secure-messaging bit b3 set (GP 2.3.1 §11.1.4).
const CLA_PROPRIETARY_SM: u8 = 0x84;

/// Volatile access state: dropped by SELECT, deselection and every reset (spec §4.3:
/// the verification status lasts until the application is reselected or the card reset).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Session {
    /// PW1 verified with P2 = 81 (PSO:CDS).
    pw1_cds: bool,
    /// PW1 verified with P2 = 82 (other PW1 operations).
    pw1_other: bool,
    /// PW3 verified.
    pw3: bool,
    /// Current occurrence of 7F21 chosen by SELECT DATA (spec §7.2.5; 0 after SELECT).
    cert_occurrence: u8,
    /// Key reference MSE chose for INTERNAL AUTHENTICATE (spec §7.2.18; default AUT 03).
    mse_authentication: u8,
    /// Key reference MSE chose for PSO:DECIPHER (default DEC 02).
    mse_confidentiality: u8,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            pw1_cds: false,
            pw1_other: false,
            pw3: false,
            cert_occurrence: 0,
            mse_authentication: 0x03,
            mse_confidentiality: 0x02,
        }
    }
}

/// Result of a command handler: response data with `9000`, or an error status word.
type Reply = Result<Vec<u8>, u16>;

/// The OpenPGP card application.
pub struct OpenPgp {
    state: State,
    session: Session,
    chain: CommandChain,
    responses: ResponseQueue,
    /// The operation waiting for a touch, if any.
    pending: Option<Pending>,
    /// Time of the last touch per key for the cached UIF policies; volatile, it ends with
    /// the OpenPGP session like the PIN verifications (operations.rs).
    touch_cache: [Option<Millis>; SLOTS],
}

impl OpenPgp {
    /// Restore from the plaintext last passed to `Host::persist(Record::OpenPgp, ..)`.
    ///
    /// Missing or unreadable state starts from the factory state (docs/CONTRACTS.md), which
    /// includes a freshly generated attestation issuer (attest.rs). That state is saved at
    /// once so the issuer stays the same across restarts; if the save fails the state stays
    /// in memory and the next successful save of any command carries it.
    pub fn new(stored: Option<&[u8]>, host: &mut dyn Host) -> Self {
        let state = match stored.and_then(State::from_bytes) {
            Some(state) => state,
            None => {
                let mut state = State::factory();
                attest::provision_factory_issuer(&mut state, host);
                // Best effort, see above.
                let _ = host.persist(Record::OpenPgp, &state.to_bytes());
                state
            }
        };
        Self {
            state,
            session: Session::default(),
            chain: CommandChain::new(MAX_CHAIN_DATA),
            responses: ResponseQueue::new(),
            pending: None,
            touch_cache: [None; SLOTS],
        }
    }

    /// End the OpenPGP session: verifications, SELECT DATA / MSE choices, chains, pending
    /// responses and touches, and the cached touches. Yubico documents that a cached touch
    /// lasts "up to 15 seconds or until the OpenPGP session ends" (YubiKey 5.2.3
    /// Enhancements to OpenPGP 3.4, "Touch Cache"), so it goes with every SELECT,
    /// deselection, reset kind, TERMINATE DF and ACTIVATE FILE.
    fn clear_volatile(&mut self) {
        self.session = Session::default();
        self.chain.clear();
        self.responses.clear();
        self.pending = None;
        self.touch_cache = [None; SLOTS];
    }

    /// Persist `next` and make it current; on a storage failure keep the current state and
    /// answer `6581` (docs/CONTRACTS.md "Persisted state").
    fn commit(&mut self, host: &mut dyn Host, next: State) -> Result<(), u16> {
        host.persist(Record::OpenPgp, &next.to_bytes())
            .map_err(|_| sw::MEMORY_FAILURE)?;
        self.state = next;
        Ok(())
    }

    fn handle(&mut self, apdu: &[u8], host: &mut dyn Host) -> Outcome<Vec<u8>> {
        let cmd = match Command::parse(apdu) {
            Ok(cmd) => cmd,
            Err(err) => return Outcome::Done(apdu::status(err.sw())),
        };
        if let Err(status) = check_class(&cmd) {
            return Outcome::Done(apdu::status(status));
        }
        if !known_ins(cmd.ins) {
            return Outcome::Done(apdu::status(sw::INS_NOT_SUPPORTED));
        }
        // Catalog: GET DATA (and every data-less command) rejects chaining CLA 10 with
        // 6E00 and leaves the next command unaffected.
        if cmd.is_chained() && !chainable(cmd.ins) {
            return Outcome::Done(apdu::status(sw::CLA_NOT_SUPPORTED));
        }
        if self.state.terminated && cmd.ins != ins::ACTIVATE_FILE {
            self.chain.clear();
            self.responses.clear();
            return Outcome::Done(apdu::status(SW_TERMINATED));
        }
        if cmd.ins == ins::GET_RESPONSE {
            return Outcome::Done(self.get_response(&cmd));
        }
        self.responses.clear();
        if cmd.data.len() > MAX_COMMAND_DATA {
            self.chain.clear();
            return Outcome::Done(apdu::status(sw::WRONG_LENGTH));
        }
        let full = match self.chain.push(cmd) {
            Err(err) => return Outcome::Done(apdu::status(err.sw())),
            Ok(None) => return Outcome::Done(apdu::status(sw::OK)),
            Ok(Some(full)) => full,
        };
        match self.execute(&full, host) {
            Step::Done(reply) => Outcome::Done(self.reply(reply, chunk_len(&full))),
            Step::Touch(pending) => {
                self.pending = Some(pending);
                Outcome::NeedTouch { timeout_ms: TOUCH_TIMEOUT_MS }
            }
        }
    }

    fn execute(&mut self, cmd: &Command, host: &mut dyn Host) -> Step {
        match cmd.ins {
            ins::GET_DATA => self.get_data(cmd, host).into(),
            ins::GET_NEXT_DATA => self.get_next_data(cmd).into(),
            ins::SELECT_DATA => self.select_data(cmd).into(),
            ins::PUT_DATA => self.put_data(cmd, host).into(),
            ins::PUT_DATA_ODD => self.import_key(cmd, host).into(),
            ins::VERIFY => self.verify(cmd, host).into(),
            ins::CHANGE_REFERENCE_DATA => self.change_reference_data(cmd, host).into(),
            ins::RESET_RETRY_COUNTER => self.reset_retry_counter(cmd, host).into(),
            ins::SET_RETRIES => self.set_retries(cmd, host).into(),
            ins::GET_CHALLENGE => get_challenge(cmd, host).into(),
            ins::MANAGE_SECURITY_ENVIRONMENT => self.manage_security_environment(cmd).into(),
            ins::TERMINATE_DF => self.terminate(cmd, host).into(),
            ins::ACTIVATE_FILE => self.activate(cmd, host).into(),
            ins::GET_VERSION => Step::Done(Ok(host.profile().firmware.bytes().to_vec())),
            ins::GENERATE_ASYMMETRIC_KEY_PAIR => self.generate_key_pair(cmd, host).into(),
            ins::PERFORM_SECURITY_OPERATION => self.perform_security_operation(cmd, host),
            ins::INTERNAL_AUTHENTICATE => self.internal_authenticate(cmd, host),
            ins::GET_ATTESTATION => self.attest(cmd, host),
            _ => Step::Done(Err(sw::INS_NOT_SUPPORTED)),
        }
    }

    /// The response APDU for a handler's result. Data is served in chunks of the
    /// command's Ne, with `61xx` while more remains (ISO 7816-4 §5.1.3, §7.6.1).
    fn reply(&mut self, reply: Reply, chunk: usize) -> Vec<u8> {
        match reply {
            Ok(data) if data.is_empty() => apdu::status(sw::OK),
            Ok(data) => self.responses.start(data, sw::OK, chunk),
            Err(status) => apdu::status(status),
        }
    }

    /// GET RESPONSE (ISO 7816-4 §7.6.1). The CLA was checked before this point, so an
    /// unsupported CLA never consumes the pending data (catalog).
    fn get_response(&mut self, cmd: &Command) -> Vec<u8> {
        if self.chain.is_active() {
            // Catalog: GET RESPONSE during unfinished command chaining returns 6883.
            self.chain.clear();
            return apdu::status(sw::LAST_COMMAND_EXPECTED);
        }
        if cmd.p1 != 0 || cmd.p2 != 0 {
            return apdu::status(sw::INCORRECT_P1P2);
        }
        if !cmd.data.is_empty() {
            return apdu::status(sw::WRONG_LENGTH);
        }
        self.responses
            .next(chunk_len(cmd))
            .unwrap_or_else(|| apdu::status(sw::CONDITIONS))
    }

    /// MANAGE SECURITY ENVIRONMENT (spec §7.2.18): P1 41, P2 A4 (authentication, used by
    /// INTERNAL AUTHENTICATE) or B8 (confidentiality, used by PSO:DECIPHER), data
    /// `83 01 <key ref>` with key reference 02 (DEC) or 03 (AUT). The choice is volatile.
    /// C0 keeps the observed "MSE not announced" byte; the command is still accepted.
    fn manage_security_environment(&mut self, cmd: &Command) -> Reply {
        if !le_absent_or_zero(cmd) {
            return Err(sw::WRONG_LENGTH);
        }
        if cmd.p1 != 0x41 || !matches!(cmd.p2, 0xA4 | 0xB8) {
            return Err(sw::INCORRECT_P1P2);
        }
        let key_ref = match cmd.data.as_slice() {
            [0x83, 0x01, key @ (0x02 | 0x03)] => *key,
            _ => return Err(sw::INCORRECT_DATA),
        };
        if cmd.p2 == 0xA4 {
            self.session.mse_authentication = key_ref;
        } else {
            self.session.mse_confidentiality = key_ref;
        }
        Ok(Vec::new())
    }

    /// TERMINATE DF (spec §7.2.16): allowed after PW3 verification, or without it once PW3
    /// is blocked. The application enters the termination state until ACTIVATE FILE.
    ///
    /// Whether the device also accepts it with only PW3 blocked (rather than PW1 and PW3
    /// both blocked) is unmeasured; this lenient reading accepts the YubiKit and GnuPG
    /// factory-reset flows, which block both before terminating.
    fn terminate(&mut self, cmd: &Command, host: &mut dyn Host) -> Reply {
        check_no_data_header(cmd)?;
        let pw3_blocked = self.state.retries.get(PW3).copied() == Some(0);
        if !self.session.pw3 && !pw3_blocked {
            return Err(sw::SECURITY_STATUS);
        }
        let mut next = self.state.clone();
        next.terminated = true;
        self.commit(host, next)?;
        self.clear_volatile();
        Ok(Vec::new())
    }

    /// ACTIVATE FILE (spec §7.2.17). In the termination state it resets the application to
    /// its factory state (keeping the attestation slot, catalog OpenPGP_attestation). In the
    /// operational state it succeeds without any change (catalog: operational ACTIVATE is a
    /// no-op and creates nothing lazily).
    ///
    /// The reset ends the session ([`Self::clear_volatile`]), so a touch given before the
    /// factory reset never stands in for one after it.
    fn activate(&mut self, cmd: &Command, host: &mut dyn Host) -> Reply {
        check_no_data_header(cmd)?;
        if !self.state.terminated {
            return Ok(Vec::new());
        }
        let next = self.state.after_reset();
        self.commit(host, next)?;
        self.clear_volatile();
        Ok(Vec::new())
    }
}

/// Only non-secret status: the state holds PIN references and key material.
impl core::fmt::Debug for OpenPgp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OpenPgp")
            .field("terminated", &self.state.terminated)
            .field("key_status", &objects::key_information(&self.state))
            .field("signature_counter", &self.state.signature_counter)
            .field("touch_pending", &self.pending.is_some())
            .finish_non_exhaustive()
    }
}

impl CardApplet for OpenPgp {
    fn aid(&self) -> &'static [u8] {
        &AID_PREFIX
    }

    /// SELECT (spec §7.2.1): no FCI is returned (observation: `00a4040006d2760001240100`
    /// answers `9000` with 0 bytes). A terminated application answers `6285`.
    fn select(&mut self, _apdu: &[u8], _host: &mut dyn Host) -> Vec<u8> {
        self.clear_volatile();
        if self.state.terminated {
            apdu::status(SW_TERMINATED)
        } else {
            apdu::status(sw::OK)
        }
    }

    fn process(&mut self, apdu: &[u8], host: &mut dyn Host) -> Outcome<Vec<u8>> {
        // A new command abandons one still waiting for a touch.
        self.pending = None;
        self.handle(apdu, host)
    }

    /// Finish the operation that waited for a touch (operations.rs): on a touch it runs and
    /// its result is served like any response; without one the answer is `6982` and
    /// nothing changes. Without a waiting operation the answer is `6985`.
    fn touch_resolved(&mut self, touched: bool, host: &mut dyn Host) -> Vec<u8> {
        let Some(pending) = self.pending.take() else {
            return apdu::status(sw::CONDITIONS);
        };
        if !touched {
            return apdu::status(sw::SECURITY_STATUS);
        }
        self.touched(pending.op.touch_slot(), host.now());
        let reply = self.perform(pending.op, host);
        self.reply(reply, pending.chunk)
    }

    fn deselect(&mut self) {
        self.clear_volatile();
    }

    fn reset(&mut self, _kind: ResetKind) {
        // Every reset kind ends the card session, so all volatile state goes, cached
        // touches included (clear_volatile).
        self.clear_volatile();
    }
}

/// GET CHALLENGE (spec §7.2.15): Le random bytes, at most 3070 (C0). Le absent or above
/// the maximum is `6700`.
fn get_challenge(cmd: &Command, host: &mut dyn Host) -> Reply {
    if cmd.p1 != 0 || cmd.p2 != 0 {
        return Err(sw::INCORRECT_P1P2);
    }
    if !cmd.data.is_empty() {
        return Err(sw::WRONG_LENGTH);
    }
    let len = cmd.expected_len().ok_or(sw::WRONG_LENGTH)?;
    if len > MAX_CHALLENGE {
        return Err(sw::WRONG_LENGTH);
    }
    let mut out = vec![0u8; len];
    host.fill(&mut out);
    Ok(out)
}

/// ISO 7816-4 §5.1.1 / §5.4.1: interindustry class on the basic logical channel without
/// secure messaging; the Yubico GET ATTESTATION uses the proprietary class 80 and only that
/// (catalog: "proprietary CLA/header validation"). Secure-messaging bits that reach the
/// applet are `6882` (module documentation; docs/CONTRACTS.md "APDU conventions").
fn check_class(cmd: &Command) -> Result<(), u16> {
    if cmd.ins == ins::GET_ATTESTATION {
        return match cmd.cla {
            CLA_PROPRIETARY => Ok(()),
            // GlobalPlatform proprietary class with secure messaging (GP 2.3.1 §11.1.4).
            CLA_PROPRIETARY_SM => Err(sw::SM_NOT_SUPPORTED),
            _ => Err(sw::CLA_NOT_SUPPORTED),
        };
    }
    if cmd.cla & 0xE0 != 0 {
        return Err(sw::CLA_NOT_SUPPORTED);
    }
    if cmd.cla & 0x0C != 0 {
        return Err(sw::SM_NOT_SUPPORTED);
    }
    if cmd.cla & 0x03 != 0 {
        return Err(sw::LOGICAL_CHANNEL_NOT_SUPPORTED);
    }
    Ok(())
}

fn known_ins(code: u8) -> bool {
    matches!(
        code,
        ins::SELECT_DATA
            | ins::GET_DATA
            | ins::GET_NEXT_DATA
            | ins::VERIFY
            | ins::CHANGE_REFERENCE_DATA
            | ins::RESET_RETRY_COUNTER
            | ins::PUT_DATA
            | ins::GET_CHALLENGE
            | ins::MANAGE_SECURITY_ENVIRONMENT
            | ins::GET_RESPONSE
            | ins::TERMINATE_DF
            | ins::ACTIVATE_FILE
            | ins::GET_VERSION
            | ins::SET_RETRIES
            | ins::GENERATE_ASYMMETRIC_KEY_PAIR
            | ins::PERFORM_SECURITY_OPERATION
            | ins::INTERNAL_AUTHENTICATE
            | ins::PUT_DATA_ODD
            | ins::GET_ATTESTATION
    )
}

/// Commands that carry a data field and may therefore be chained.
fn chainable(code: u8) -> bool {
    matches!(
        code,
        ins::SELECT_DATA
            | ins::VERIFY
            | ins::CHANGE_REFERENCE_DATA
            | ins::RESET_RETRY_COUNTER
            | ins::PUT_DATA
            | ins::MANAGE_SECURITY_ENVIRONMENT
            | ins::SET_RETRIES
            | ins::GENERATE_ASYMMETRIC_KEY_PAIR
            | ins::PERFORM_SECURITY_OPERATION
            | ins::INTERNAL_AUTHENTICATE
            | ins::PUT_DATA_ODD
    )
}

/// Response chunk size: Ne, capped at the 3070-byte maximum response of 7F66. Without Le
/// a short command gets 256 bytes and an extended one the maximum.
fn chunk_len(cmd: &Command) -> usize {
    match cmd.expected_len() {
        Some(ne) => ne.min(MAX_RESPONSE),
        None if cmd.extended => MAX_RESPONSE,
        None => 256,
    }
}

/// A command that returns no data accepts Le only when absent or `00`.
fn le_absent_or_zero(cmd: &Command) -> bool {
    matches!(cmd.le, None | Some(0))
}

/// Header rules of TERMINATE DF / ACTIVATE FILE: P1 = P2 = 00, no data, no explicit Le.
fn check_no_data_header(cmd: &Command) -> Result<(), u16> {
    if cmd.p1 != 0 || cmd.p2 != 0 {
        return Err(sw::INCORRECT_P1P2);
    }
    if !le_absent_or_zero(cmd) || !cmd.data.is_empty() {
        return Err(sw::WRONG_LENGTH);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use lk_testkit::TestHost;

    use super::*;
    use crate::keys::KeyMaterial;
    use crate::objects::Slot;

    const SELECT: [u8; 11] = [0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];
    const RSA2048: &[u8] = &[0x01, 0x08, 0x00, 0x00, 0x11, 0x00];
    const P256_ECDSA: &[u8] = &[0x13, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    const P384_ECDH: &[u8] = &[0x12, 0x2b, 0x81, 0x04, 0x00, 0x22];
    const ED25519: &[u8] = &[0x16, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01];
    const X25519: &[u8] = &[0x12, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];
    const P521_ECDSA: &[u8] = &[0x13, 0x2b, 0x81, 0x04, 0x00, 0x23];
    const BP384_ECDH: &[u8] = &[0x12, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b];

    fn applet_with(state: &State) -> (OpenPgp, TestHost) {
        let mut host = TestHost::new();
        let mut app = OpenPgp::new(Some(&state.to_bytes()), &mut host);
        assert_eq!(app.select(&SELECT, &mut host), vec![0x90, 0x00]);
        (app, host)
    }

    fn run(app: &mut OpenPgp, host: &mut TestHost, apdu: &[u8]) -> Vec<u8> {
        let resp = match app.process(apdu, host) {
            Outcome::Done(resp) => resp,
            Outcome::NeedTouch { .. } => app.touch_resolved(true, host),
        };
        assert!(resp.len() >= 2, "{apdu:02X?}");
        resp
    }

    fn status(resp: &[u8]) -> u16 {
        u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]])
    }

    /// Readable state whose key material is not a valid key, or not a key of the slot's
    /// algorithm, is answered with status words (6A88 / 6F00 / 6985 ...) and never panics.
    #[test]
    fn corrupt_key_material_never_panics() {
        let materials = [
            KeyMaterial::Rsa { p: vec![4; 128], q: vec![6; 128], e: vec![1, 0, 1] },
            KeyMaterial::Rsa { p: vec![0xFF; 3], q: vec![0xFD; 3], e: vec![3] },
            KeyMaterial::Rsa { p: vec![0xC5; 128], q: vec![0xC5; 128], e: vec![1, 0, 1] },
            KeyMaterial::Ec { curve: lk_crypto::Curve::P256, scalar: vec![0; 32] },
            KeyMaterial::Ec { curve: lk_crypto::Curve::P384, scalar: vec![0xFF; 48] },
            // A P-521 scalar with bits above 521 set, and others at or above n.
            KeyMaterial::Ec { curve: lk_crypto::Curve::P521, scalar: vec![0xFF; 66] },
            KeyMaterial::Ec { curve: lk_crypto::Curve::Secp256k1, scalar: vec![0xFF; 32] },
            KeyMaterial::Ec { curve: lk_crypto::Curve::BrainpoolP256r1, scalar: vec![0; 32] },
            KeyMaterial::Ec { curve: lk_crypto::Curve::BrainpoolP384r1, scalar: vec![0xFF; 48] },
            KeyMaterial::Ed25519 { seed: vec![1; 32] },
            KeyMaterial::X25519 { secret: vec![2; 32] },
        ];
        let mut cipher_do = vec![0xA6, 0x26, 0x7F, 0x49, 0x22, 0x86, 0x20];
        cipher_do.extend_from_slice(&[9; 32]);
        let mut rsa_cryptogram = vec![0x00];
        rsa_cryptogram.extend_from_slice(&[0x11; 256]);
        let commands: Vec<Vec<u8>> = vec![
            [&[0x00, 0x2A, 0x9E, 0x9A, 0x20][..], &[0x42; 32], &[0x00]].concat(),
            [&[0x00, 0x2A, 0x80, 0x86, 0x00, 0x01, 0x01][..], &rsa_cryptogram, &[0x00, 0x00]].concat(),
            [&[0x00, 0x2A, 0x80, 0x86, cipher_do.len() as u8][..], &cipher_do, &[0x00]].concat(),
            [&[0x00, 0x88, 0x00, 0x00, 0x20][..], &[0x42; 32], &[0x00]].concat(),
            vec![0x00, 0x47, 0x81, 0x00, 0x02, 0xB6, 0x00, 0x00],
            vec![0x00, 0x47, 0x81, 0x00, 0x02, 0xB8, 0x00, 0x00],
            vec![0x00, 0x47, 0x81, 0x00, 0x02, 0xA4, 0x00, 0x00],
            vec![0x00, 0x47, 0x81, 0x00, 0x05, 0xB6, 0x03, 0x84, 0x01, 0x81, 0x00],
            vec![0x80, 0xFB, 0x01, 0x00],
            vec![0x80, 0xFB, 0x02, 0x00],
            vec![0x80, 0xFB, 0x03, 0x00],
            vec![0x00, 0x22, 0x41, 0xA4, 0x03, 0x83, 0x01, 0x02],
            vec![0x00, 0x22, 0x41, 0xB8, 0x03, 0x83, 0x01, 0x03],
            [&[0x00, 0x88, 0x00, 0x00, 0x20][..], &[0x42; 32], &[0x00]].concat(),
            [&[0x00, 0x2A, 0x80, 0x86, cipher_do.len() as u8][..], &cipher_do, &[0x00]].concat(),
            vec![0x00, 0xCA, 0x00, 0x6E, 0x00],
        ];
        for material in &materials {
            for attributes in [RSA2048, P256_ECDSA, P384_ECDH, ED25519, X25519, P521_ECDSA, BP384_ECDH] {
                let mut state = State::factory();
                for slot in Slot::ALL {
                    let data = state.slot_mut(slot);
                    data.attributes = attributes.to_vec();
                    data.set_key(material.clone(), 0x01);
                }
                let (mut app, mut host) = applet_with(&state);
                for verify in [&b"\x00\x20\x00\x81\x06123456"[..], b"\x00\x20\x00\x82\x06123456"] {
                    assert_eq!(status(&run(&mut app, &mut host, verify)), 0x9000);
                }
                for command in &commands {
                    run(&mut app, &mut host, command);
                }
            }
        }
    }

    /// The digital signature counter has three bytes (spec §4.4.3.14); at FF FF FF it stays
    /// there (model policy) and signing still works.
    #[test]
    fn debug_output_has_no_secrets() {
        let mut state = State::factory();
        state.pw1 = b"pin-secret".to_vec();
        state.slot_mut(Slot::Sig).set_key(KeyMaterial::Ed25519 { seed: vec![0xAB; 32] }, 0x02);
        let (app, _) = applet_with(&state);
        let text = format!("{app:?}");
        assert!(!text.contains("pin-secret") && !text.contains("112, 105, 110"), "{text}");
        assert!(!text.contains("171"), "{text}");
        assert!(text.contains("signature_counter"));
    }

    #[test]
    fn signature_counter_saturates() {
        let mut state = State::factory();
        state.signature_counter = 0x00FF_FFFF;
        let sig = state.slot_mut(Slot::Sig);
        sig.attributes = ED25519.to_vec();
        sig.set_key(KeyMaterial::Ed25519 { seed: vec![7; 32] }, 0x02);
        let (mut app, mut host) = applet_with(&state);
        assert_eq!(status(&run(&mut app, &mut host, b"\x00\x20\x00\x81\x06123456")), 0x9000);
        let resp = run(&mut app, &mut host, &[0x00, 0x2A, 0x9E, 0x9A, 0x01, 0x55, 0x00]);
        assert_eq!((resp.len(), status(&resp)), (66, 0x9000));
        assert_eq!(app.state.signature_counter, 0x00FF_FFFF);
        let resp = run(&mut app, &mut host, &[0x00, 0xCA, 0x00, 0x7A, 0x00]);
        assert_eq!(resp, vec![0x7A, 0x05, 0x93, 0x03, 0xFF, 0xFF, 0xFF, 0x90, 0x00]);
    }
}
