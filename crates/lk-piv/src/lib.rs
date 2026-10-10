//! PIV application (NIST SP 800-73-4) with vendor extensions: management-key mutual
//! authentication, PIN/PUK and retries, key generation/import/move/delete, GENERAL
//! AUTHENTICATE (sign, decrypt, ECDH), data objects and capacity limits, PIN and touch
//! policies, metadata and attestation.
//!
//! # Commands
//!
//! - SELECT with the application property template of the profile (SP 800-73-4 Part 2
//!   §3.1.1).
//! - GET DATA / PUT DATA with the data object model and capacity limits of
//!   the `objects` module (Part 2 §3.1.2, §3.3.1).
//! - VERIFY, CHANGE REFERENCE DATA, RESET RETRY COUNTER (Part 2 §3.2.1-§3.2.3).
//! - Management key authentication by GENERAL AUTHENTICATE with 3DES and AES-128/192/256
//!   (Part 2 §3.2.4, Appendix A; SP 800-78-4 Table 6-1).
//! - Yubico extensions SET MANAGEMENT KEY, SET PIN RETRIES, RESET, GET VERSION, GET
//!   SERIAL and GET METADATA.
//! - Command chaining (ISO/IEC 7816-4 §5.1.1.1) up to 3072 assembled bytes and response
//!   chaining with GET RESPONSE (ISO/IEC 7816-4 §7.6.1).
//! - Asymmetric keys in slots `9A`, `9C`, `9D`, `9E`, `82`-`95` and `F9`: RSA-1024/2048/
//!   3072/4096, ECC P-256/P-384, Ed25519 and X25519 (`keys`), GENERATE ASYMMETRIC KEY
//!   PAIR (`47`, Part 2 §3.3.2), GENERAL AUTHENTICATE for sign, decrypt and key agreement
//!   (Part 2 §3.2.4) with PIN and touch policies, and the Yubico extensions IMPORT (`FE`),
//!   MOVE/DELETE KEY (`F6`), ATTEST (`F9`) and key slot metadata (`asym`, `attest`).
//!
//! The own attestation key and certificate in `F9` are created once, when the applet is
//! first constructed (`attest::initialize`), and persisted at once.
//!
//! # Volatile state
//!
//! PIN verification (and the PIN-always authorization), management key authentication,
//! an open authentication challenge, a pending touch, a partial command chain and unread
//! response data live only for the card session: deselection and every [`ResetKind`]
//! drop them. A SELECT of the PIV application while it is already selected keeps the
//! security status (SP 800-73-4 Part 2 §3.1.1: "the setting of all security status
//! indicators in the PIV Card Application shall be unchanged") and only drops the
//! per-command state (challenge, pending touch, chain, unread response data, PIN-always
//! authorization). A SELECT naming another AID that reaches this applet answers `6A82`
//! and changes nothing (§3.1.1: an invalid AID leaves the PIV application selected with
//! its security status unchanged). The cached-touch time survives selection changes and
//! is dropped by every reset.
//!
//! # Secrets
//!
//! PIN and PUK reference data, the management key, slot private keys, the mutual
//! authentication witness and the serialized record live in `lk_crypto::SecretBytes` and
//! are wiped when dropped (`docs/DESIGN.md` §8); they are compared with `lk_crypto::ct_eq`.
//! Command and response buffers owned by `lk_codec` (the chain buffer, the APDU data) are
//! outside this crate's reach.
//!
//! # PIN always
//!
//! The PIN-always authorization follows SP 800-73-4 Part 1 §3.2.1 ("the PIN ... must be
//! submitted and verified every time immediately before a digital signature key
//! operation"): a successful VERIFY arms it, and any later command clears it except a
//! VERIFY status query (no data), GET RESPONSE, an intermediate part of a command chain,
//! and a GENERAL AUTHENTICATE rejected before its PIN check. The host software is written
//! for this: OpenSC (`card-piv.c`, `context_specific`) keeps the card locked from the
//! context-specific VERIFY to the signature, libykpiv does not reselect the application
//! before a private key operation "to avoid problems with PIN_ALWAYS", and ykman verifies
//! the PIN again and retries when a signature answers `6982` (`_verify_pin_if_needed`).

#![forbid(unsafe_code)]

mod admin;
mod asym;
mod attest;
mod bignum;
mod data;
mod keys;
mod objects;
mod pin;
mod state;

use std::fmt;

use lk_codec::apdu::{self, Command, CommandChain, ResponseQueue, sw};
use lk_core::{CardApplet, Host, Millis, Outcome, Record, ResetKind};
use lk_crypto::SecretBytes;

use crate::admin::{Challenge, PendingTouch};
use crate::objects::MAX_APDU_DATA;
use crate::state::PivState;

/// The PIV application identifier, right-truncated (SP 800-73-4 Part 1 §2.2; the full
/// AID is `A0 00 00 03 08 00 00 10 00 01 00`).
pub const AID: &[u8] = &[0xA0, 0x00, 0x00, 0x03, 0x08];

/// The full PIV AID with its version (SP 800-73-4 Part 1 §2.2).
const FULL_AID: [u8; 11] = [0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00];

/// SELECT P1 "select by DF name" (ISO/IEC 7816-4 §7.1.1; SP 800-73-4 Part 2 §3.1.1).
const P1_SELECT_BY_NAME: u8 = 0x04;

/// The SELECT answer (`piv_initial_profile.select_response`): application property
/// template `61` with the PIX `4F 06 00 00 10 00 01 00` and the coexistent tag
/// allocation authority `79 { 4F A0 00 00 03 08 }` (SP 800-73-4 Part 2 §3.1.1, Table 3).
const SELECT_TEMPLATE: [u8; 19] = [
    0x61, 0x11, 0x4F, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x79, 0x07, 0x4F, 0x05, 0xA0, 0x00,
    0x00, 0x03, 0x08,
];

/// How long a command waits for a touch. Yubico documents a 15-second touch window
/// for PIV operations.
pub const TOUCH_TIMEOUT_MS: Millis = 15_000;

/// Largest response piece for a short command (ISO/IEC 7816-4 §5.1: Ne at most 256).
const SHORT_MAX_RESPONSE: usize = 256;
/// Largest response piece for an extended command without Le (§5.1: Ne = 65 536).
const EXTENDED_MAX_RESPONSE: usize = 65_536;

// Instruction bytes: SP 800-73-4 Part 2 §3 and the Yubico PIV extensions.
const INS_SELECT: u8 = 0xA4;
const INS_GET_DATA: u8 = 0xCB;
const INS_PUT_DATA: u8 = 0xDB;
const INS_VERIFY: u8 = 0x20;
const INS_CHANGE_REFERENCE: u8 = 0x24;
const INS_RESET_RETRY: u8 = 0x2C;
const INS_GENERAL_AUTHENTICATE: u8 = 0x87;
const INS_GET_RESPONSE: u8 = 0xC0;
const INS_GENERATE: u8 = 0x47;
const INS_IMPORT: u8 = 0xFE;
const INS_MOVE_KEY: u8 = 0xF6;
const INS_ATTEST: u8 = 0xF9;
const INS_GET_METADATA: u8 = 0xF7;
const INS_GET_SERIAL: u8 = 0xF8;
const INS_SET_PIN_RETRIES: u8 = 0xFA;
const INS_RESET: u8 = 0xFB;
const INS_GET_VERSION: u8 = 0xFD;
const INS_SET_MGMT_KEY: u8 = 0xFF;

/// The data of a successful (`9000`) answer, or the status word of any other answer.
pub(crate) type Reply = Result<Vec<u8>, u16>;

/// What a dispatched command produced.
pub(crate) enum Step {
    Reply(Reply),
    /// Waiting for a touch; the result comes from `touch_resolved`.
    Touch,
}

/// Card-session state (never persisted; `docs/DESIGN.md` §7).
struct Session {
    pin_verified: bool,
    /// A successful VERIFY immediately before (see the module documentation); consumed
    /// by an operation with PIN policy "always" (`asym`).
    pin_always: bool,
    mgmt_authenticated: bool,
    challenge: Option<Challenge>,
    touch: Option<PendingTouch>,
    chain: CommandChain,
    responses: ResponseQueue,
}

impl Session {
    fn new() -> Self {
        Self {
            pin_verified: false,
            pin_always: false,
            mgmt_authenticated: false,
            challenge: None,
            touch: None,
            chain: CommandChain::new(MAX_APDU_DATA),
            responses: ResponseQueue::new(),
        }
    }

    /// Drop the per-command transient state after a command that never reached dispatch.
    fn abort_command(&mut self) {
        self.challenge = None;
        self.pin_always = false;
        self.chain.clear();
        self.responses.clear();
    }

    /// A new SELECT of this application: drop the per-command state but keep the
    /// security status (SP 800-73-4 Part 2 §3.1.1).
    fn reselect(&mut self) {
        self.abort_command();
        self.touch = None;
    }
}

/// The PIV card application.
pub struct Piv {
    state: PivState,
    session: Session,
    /// When a slot operation was last completed with a touch (cached touch policy).
    touch_cache: Option<Millis>,
}

impl fmt::Debug for Piv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Piv")
            .field("state", &self.state)
            .field("pin_verified", &self.session.pin_verified)
            .field("mgmt_authenticated", &self.session.mgmt_authenticated)
            .field("challenge_open", &self.session.challenge.is_some())
            .field("touch_pending", &self.session.touch.is_some())
            .field("touch_cache", &self.touch_cache)
            .finish()
    }
}

impl Piv {
    /// Restore the applet from the plaintext it last persisted, or start from the
    /// factory state when there is none or it is unreadable (`docs/CONTRACTS.md`).
    ///
    /// A state whose attestation material was never initialized (a fresh device, an
    /// unreadable record, or a record from before that field existed) gets the own `F9`
    /// key and certificate now, and is persisted at once so they stay the same across
    /// restarts. If that save fails the state stays in memory and the next successful
    /// commit stores it (every commit writes the whole state).
    pub fn new(stored: Option<&[u8]>, host: &mut dyn Host) -> Self {
        let mut state = stored.and_then(PivState::decode).unwrap_or_else(PivState::factory);
        if attest::initialize(&mut state, host) {
            let _ = host.persist(Record::Piv, &SecretBytes::new(state.encode()));
        }
        Self { state, session: Session::new(), touch_cache: None }
    }

    /// Persist `next` and make it current; on failure keep the current state and answer
    /// `6581` (`lk_core::Host::persist`).
    pub(crate) fn commit(&mut self, host: &mut dyn Host, next: PivState) -> Result<(), u16> {
        // The plaintext record holds every secret; it is wiped once handed over.
        let record = SecretBytes::new(next.encode());
        host.persist(Record::Piv, &record).map_err(|_| sw::MEMORY_FAILURE)?;
        self.state = next;
        Ok(())
    }

    /// Apply `change` to a copy of the state and [`commit`](Self::commit) it.
    pub(crate) fn modify(&mut self, host: &mut dyn Host, change: impl FnOnce(&mut PivState)) -> Result<(), u16> {
        let mut next = self.state.clone();
        change(&mut next);
        self.commit(host, next)
    }

    /// Run one assembled command. `armed` is the PIN-always authorization as it stood
    /// before this command; only VERIFY and GENERAL AUTHENTICATE may keep or use it.
    fn dispatch(
        &mut self,
        cmd: &Command,
        pending: Option<Challenge>,
        armed: bool,
        host: &mut dyn Host,
        max: usize,
    ) -> Step {
        let reply = match cmd.ins {
            INS_SELECT => self.select_command(cmd),
            INS_GET_DATA => self.get_data(cmd),
            INS_PUT_DATA => self.put_data(cmd, host),
            INS_VERIFY => self.verify(cmd, armed, host),
            INS_CHANGE_REFERENCE => self.change_reference(cmd, host),
            INS_RESET_RETRY => self.reset_retry_counter(cmd, host),
            INS_GENERAL_AUTHENTICATE => return self.general_authenticate(cmd, pending, armed, host, max),
            INS_SET_MGMT_KEY => self.set_management_key(cmd, host),
            INS_SET_PIN_RETRIES => self.set_pin_retries(cmd, host),
            INS_RESET => self.reset_applet(cmd, host),
            INS_GET_VERSION => self.get_version(host),
            INS_GET_SERIAL => self.get_serial(host),
            INS_GET_METADATA => self.get_metadata(cmd),
            INS_GENERATE => self.generate_key(cmd, host),
            INS_IMPORT => self.import_key(cmd, host),
            INS_MOVE_KEY => self.move_or_delete_key(cmd, host),
            INS_ATTEST => self.attest(cmd, host),
            _ => Err(sw::INS_NOT_SUPPORTED),
        };
        Step::Reply(reply)
    }

    /// SELECT received while this applet is current (SP 800-73-4 Part 2 §3.1.1). P1 must
    /// be `04` (select by name, `6A86`). The data must be the PIV AID, full or
    /// right-truncated: a prefix of `A0 00 00 03 08 00 00 10 00 01 00` of at least the
    /// five RID bytes (ISO/IEC 7816-4 §8.2.1.2 partial DF name). Then the application
    /// stays selected with its security status unchanged and the answer is the
    /// application property template. Any other AID is `6A82` and changes nothing
    /// (§3.1.1: "an invalid AID not supported by the ICC").
    fn select_command(&mut self, cmd: &Command) -> Reply {
        if cmd.p1 != P1_SELECT_BY_NAME {
            return Err(sw::INCORRECT_P1P2);
        }
        if !is_piv_aid(&cmd.data) {
            return Err(sw::FILE_NOT_FOUND);
        }
        self.session.reselect();
        Ok(SELECT_TEMPLATE.to_vec())
    }

    /// GET RESPONSE (`INS C0`, ISO/IEC 7816-4 §7.6.1): the next piece of the pending
    /// response. P1-P2 must be `0000` (`6A86`); with nothing pending the answer is `6985`
    /// (model policy).
    fn get_response(&mut self, cmd: &Command) -> Vec<u8> {
        if cmd.p1 != 0 || cmd.p2 != 0 {
            return apdu::status(sw::INCORRECT_P1P2);
        }
        self.session
            .responses
            .next(response_max(cmd))
            .unwrap_or_else(|| apdu::status(sw::CONDITIONS))
    }
}

/// Whether `aid` selects the PIV application: the full AID or a right-truncated prefix
/// of it that keeps at least the five-byte RID (SP 800-73-4 Part 1 §2.2, Part 2 §3.1.1).
fn is_piv_aid(aid: &[u8]) -> bool {
    aid.len() >= AID.len() && FULL_AID.starts_with(aid)
}

/// Check the class byte (ISO/IEC 7816-4 §5.1.1): `00`, or `10` for a chained command.
/// Secure messaging (`6882`) and logical channels (`6881`) are not supported; other
/// classes are `6E00`.
fn check_cla(cla: u8) -> Result<(), u16> {
    let base = cla & !0x10;
    if base == 0 {
        Ok(())
    } else if cla & 0xE0 != 0 {
        Err(sw::CLA_NOT_SUPPORTED)
    } else if base & 0x0C != 0 {
        Err(sw::SM_NOT_SUPPORTED)
    } else {
        Err(sw::LOGICAL_CHANNEL_NOT_SUPPORTED)
    }
}

/// Whether `cmd` carries an Le field that a command without response data must not
/// have: a non-zero Le, which asks for a number of response bytes the command never
/// returns. An Le of `00` (short) or `0000` (extended) means "Ne = the maximum"
/// (ISO/IEC 7816-4 §5.1) and is accepted like an absent Le, with or without command
/// data. Hosts add it by habit:
///
/// - yubico-piv-tool (`lib/ykpiv.c`, `_ykpiv_transfer_data`, "Add Le for T=1") appends
///   `00` to every command that carries data when the protocol is T=1, which the
///   YubiKey CCID interface is, so VERIFY, CHANGE REFERENCE DATA, RESET RETRY COUNTER,
///   PUT DATA, IMPORT and SET MANAGEMENT KEY all arrive as case 4 with Le `00`; it sends
///   data-less commands as `CLA INS P1 P2 00`, the T=0 form of case 1 (ISO/IEC 7816-3
///   §12.2.2);
/// - older python yubikit extended encoders emit `CLA INS P1 P2 00 00 00`, an extended
///   "Lc = 0" that ISO/IEC 7816-4 §5.1 does not allow and that parses as case 2E with
///   Le `0000`.
///
/// The catalog's "explicit Le" guards (VERIFY/CHANGE/RESET RETRY, PUT DATA, IMPORT, SET
/// PIN RETRIES, SET MANAGEMENT KEY, RESET, MOVE/DELETE KEY) apply to a non-zero Le.
pub(crate) fn explicit_le(cmd: &Command) -> bool {
    matches!(cmd.le, Some(le) if le != 0)
}

/// The largest response piece for `cmd`: Ne (ISO/IEC 7816-4 §5.1: "Ne ... the maximum
/// number of bytes expected in the response data field"), the rest following with
/// `61xx` and GET RESPONSE (SP 800-73-4 Part 2 Appendix A.4.1, command 3). Without an
/// Le field the card answers as if Ne were the maximum of the length form (256 short,
/// 65 536 extended), which is what hosts that omit Le expect.
fn response_max(cmd: &Command) -> usize {
    if cmd.extended {
        cmd.expected_len().unwrap_or(EXTENDED_MAX_RESPONSE)
    } else {
        cmd.expected_len().map_or(SHORT_MAX_RESPONSE, |ne| ne.min(SHORT_MAX_RESPONSE))
    }
}

impl CardApplet for Piv {
    fn aid(&self) -> &'static [u8] {
        AID
    }

    /// SELECT (SP 800-73-4 Part 2 §3.1.1): answer the application property template.
    /// The device has matched the AID. After [`deselect`](CardApplet::deselect) or a
    /// [`reset`](CardApplet::reset) the session is already fresh; a SELECT while this
    /// applet is current keeps the security status ("the setting of all security status
    /// indicators in the PIV Card Application shall be unchanged") and drops only the
    /// per-command state.
    fn select(&mut self, apdu: &[u8], host: &mut dyn Host) -> Vec<u8> {
        let _ = (apdu, host);
        self.session.reselect();
        apdu::response(&SELECT_TEMPLATE, sw::OK)
    }

    fn process(&mut self, apdu: &[u8], host: &mut dyn Host) -> Outcome<Vec<u8>> {
        // A new command abandons one still waiting for a touch.
        self.session.touch = None;
        let cmd = match Command::parse(apdu) {
            Ok(cmd) => cmd,
            Err(err) => {
                self.session.abort_command();
                return Outcome::Done(apdu::status(err.sw()));
            }
        };
        if let Err(status) = check_cla(cmd.cla) {
            self.session.abort_command();
            return Outcome::Done(apdu::status(status));
        }
        if cmd.ins == INS_GET_RESPONSE && !self.session.chain.is_active() {
            return Outcome::Done(self.get_response(&cmd));
        }
        // Any other command discards unread response data (ISO/IEC 7816-4 §7.6.1).
        self.session.responses.clear();
        if !self.session.chain.is_active() && cmd.data.len() > MAX_APDU_DATA {
            // An extended APDU larger than the assembly buffer (profile
            // `plaintext_apdu_data_limit`).
            self.session.abort_command();
            return Outcome::Done(apdu::status(sw::WRONG_LENGTH));
        }
        // The PIN-always authorization does not survive another command (module
        // documentation); VERIFY and GENERAL AUTHENTICATE decide whether to keep it.
        let armed = std::mem::take(&mut self.session.pin_always);
        let cmd = match self.session.chain.push(cmd) {
            Ok(Some(cmd)) => cmd,
            Ok(None) => {
                // An intermediate part belongs to the command it starts.
                self.session.pin_always = armed;
                return Outcome::Done(apdu::status(sw::OK));
            }
            Err(err) => {
                self.session.challenge = None;
                return Outcome::Done(apdu::status(err.sw()));
            }
        };
        let max = response_max(&cmd);
        let pending = self.session.challenge.take();
        match self.dispatch(&cmd, pending, armed, host, max) {
            Step::Reply(Ok(data)) => Outcome::Done(self.session.responses.start(data, sw::OK, max)),
            Step::Reply(Err(status)) => Outcome::Done(apdu::status(status)),
            Step::Touch => Outcome::NeedTouch { timeout_ms: TOUCH_TIMEOUT_MS },
        }
    }

    /// Finish the command that waited for a touch: a management key authentication
    /// becomes authenticated and is answered, a slot operation runs and is answered
    /// (`asym`); without a touch (timeout or cancel) the answer is `6982` (model policy;
    /// the physical status is unmeasured). With nothing pending the answer is `6985`.
    fn touch_resolved(&mut self, touched: bool, host: &mut dyn Host) -> Vec<u8> {
        match self.session.touch.take() {
            Some(PendingTouch::MgmtAuth { response, max }) => {
                if touched {
                    self.session.mgmt_authenticated = true;
                    self.session.responses.start(response, sw::OK, max)
                } else {
                    self.session.mgmt_authenticated = false;
                    apdu::status(sw::SECURITY_STATUS)
                }
            }
            Some(PendingTouch::SlotOperation { slot, op, input, max }) => {
                self.finish_slot_operation(slot, op, &input, max, touched, host)
            }
            None => apdu::status(sw::CONDITIONS),
        }
    }

    fn deselect(&mut self) {
        self.session = Session::new();
    }

    fn reset(&mut self, kind: ResetKind) {
        // Every reset kind ends the card session (lk_core::ResetKind) and forgets the
        // cached touch.
        let _ = kind;
        self.session = Session::new();
        self.touch_cache = None;
    }
}
