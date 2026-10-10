//! GlobalPlatform Security Domain of a YubiKey 5 (firmware 5.7): key information and
//! card recognition data, SCP03 key sets, and the secure-messaging wrapper the device
//! applies to the card applications once a secure channel is open.
//!
//! Sources, in the order `docs/DESIGN.md` §2 ranks them:
//! 1. `reference/yubikey-5c-nano-5.7.4/security-domain-reference-observation.json`:
//!    the SELECT response, GET DATA `0066`, the `00E0` schema and the CPLC length.
//! 2. GlobalPlatform Card Specification v2.3.1 (SELECT §11.9, GET DATA §11.3, PUT KEY
//!    §11.8, DELETE §11.2, Annex H) and Amendment D v1.1.2, SCP03.
//! 3. Yubico, YubiKey 5 technical manual, "Secure Channel" (yk5-apps-scp): default keys,
//!    three key sets, versions 1-254, default replacement, full security level only,
//!    plaintext termination, deletion after repeated failures, reset by deleting the
//!    last key set (`p2=1`).
//! 4. `reference/BEHAVIOR_CATALOG.md` (SCP03, SecurityDomain*) for edge behaviour.
//!
//! 5. GP Card Specification v2.3.1 Amendment F (SCP11) and the wire format of Yubico's
//!    SDK (yubikit `scp.py`, `securitydomain.py`) for SCP11a/b/c, EC keys, certificates,
//!    CA identifiers, allowlists and the blocking reset.
//!
//! # Scope
//!
//! - SCP03 (Amd D) with the YubiKey's profile: S8, `i = 60`, AES-128.
//! - SCP11a, SCP11b and SCP11c (Amd F) with P-256 Security Domain keys: MUTUAL and
//!   INTERNAL AUTHENTICATE, the OCE certificate chain through PERFORM SECURITY
//!   OPERATION (`pso.rs`, `cert.rs`), X9.63 key derivation and receipts (`scp11.rs`).
//! - Key management: SCP03 sets, SCP11 private keys (import and generation), OCE CA
//!   public keys, certificate stores, CA identifiers, serial allowlists with SCP11c
//!   replay counters (`manage.rs`), all persisted (`state.rs`).
//!
//! Who may manage keys: an SCP03 or SCP11a session. An SCP11b session did not
//! authenticate the host and gets `6982`; an SCP11c session can be replayed, so key
//! changes answer `6985` and only allowlist updates with a fresh counter are accepted
//! (catalog SecurityDomain_scp11c).
//!
//! # Use by `lk-device`
//!
//! - INITIALIZE UPDATE, EXTERNAL AUTHENTICATE, INTERNAL AUTHENTICATE and PERFORM
//!   SECURITY OPERATION in the GlobalPlatform class ([`is_handshake`]) go to
//!   [`SecurityDomain::handshake`] whichever applet is selected ("The session is
//!   established only within the scope of the currently selected applet", Yubico).
//!   A returned [`SecureChannel`] replaces the current one after the handshake response
//!   has been wrapped with the current one (if any).
//! - While a channel is open, each command goes through
//!   [`SecureChannel::unwrap_command`] (an `Err` is answered bare), the plain command
//!   is dispatched, and the response goes through [`SecureChannel::wrap_response`].
//!   Commands for the selected Security Domain itself go to
//!   [`SecurityDomain::process_secure`], which is where PUT KEY and DELETE KEY are
//!   authorized; [`CardApplet::process`] never authorizes them.
//! - On every SELECT, card power-off and USB reset the device calls
//!   [`SecurityDomain::end_session`] (or `select`/`deselect`/`reset`, which do the same),
//!   which ends any session and drops a half-open handshake and the cached OCE.
//! - [`SecurityDomain::process_secure`] returns whole responses; the device splits a
//!   wrapped response into `61xx` pieces itself. Plaintext responses longer than Ne are
//!   chained by the Security Domain (GET RESPONSE `00 C0`).

#![forbid(unsafe_code)]

mod cert;
mod channel;
mod data;
mod handshake;
mod manage;
mod pso;
mod scp03;
mod scp11;
mod state;

use std::sync::Arc;

use lk_codec::apdu::{self, Command, CommandChain, ResponseQueue, sw};
use lk_core::{CardApplet, Host, Outcome, Record, ResetKind};

pub use channel::{Protocol, SecureChannel, level};

use channel::Shared;
use handshake::Pending;
use state::State;

/// The Security Domain AID (GP Card Specification v2.3.1 §H.1; as selected in the
/// reference observation).
pub const AID: &[u8] = &[0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];

/// Instruction bytes: GP Card Specification v2.3.1 chapter 11 (DELETE §11.2, GET DATA
/// §11.3, PUT KEY §11.8, SELECT §11.9), Amendment D §7.1 (INITIALIZE UPDATE, EXTERNAL
/// AUTHENTICATE) and Amendment F (INTERNAL/MUTUAL AUTHENTICATE, PERFORM SECURITY
/// OPERATION).
pub mod ins {
    pub const INITIALIZE_UPDATE: u8 = 0x50;
    /// EXTERNAL AUTHENTICATE (SCP03) and MUTUAL AUTHENTICATE (SCP11a/c).
    pub const EXTERNAL_AUTHENTICATE: u8 = 0x82;
    pub const INTERNAL_AUTHENTICATE: u8 = 0x88;
    pub const PERFORM_SECURITY_OPERATION: u8 = 0x2A;
    pub const GET_DATA: u8 = 0xCA;
    /// GET RESPONSE (ISO/IEC 7816-4 §7.6.1), for plaintext response chaining.
    pub const GET_RESPONSE: u8 = 0xC0;
    pub const PUT_KEY: u8 = 0xD8;
    /// STORE DATA (GP 2.3.1 §11.11).
    pub const STORE_DATA: u8 = 0xE2;
    pub const DELETE: u8 = 0xE4;
    /// SET STATUS (GP 2.3.1 §11.10); only refused here (see `dispatch`).
    pub const SET_STATUS: u8 = 0xF0;
    /// GENERATE EC KEY (Yubico proprietary; yubikit `generate_ec_key`).
    pub const GENERATE_KEY: u8 = 0xF1;
    pub const SELECT: u8 = 0xA4;
}

/// Largest command the Security Domain reassembles from ISO command chaining: room for
/// a certificate store of eight certificates.
const MAX_CHAINED_DATA: usize = 8192;

/// Whether `apdu` is a secure channel handshake command the device must send to the
/// Security Domain whichever applet is selected: INITIALIZE UPDATE `50`, EXTERNAL /
/// MUTUAL AUTHENTICATE `82`, INTERNAL AUTHENTICATE `88` or PERFORM SECURITY OPERATION
/// `2A`, in the GlobalPlatform proprietary class (`80`-`83`, with or without secure
/// messaging `04` and chaining `10`).
///
/// The class matters: OpenPGP uses `00 88` (INTERNAL AUTHENTICATE) and `00 2A` (PSO),
/// which must stay with the OpenPGP applet.
pub fn is_handshake(apdu: &[u8]) -> bool {
    match apdu {
        [cla, ins, _, _, ..] => {
            cla & !0x17 == 0x80
                && matches!(
                    *ins,
                    ins::INITIALIZE_UPDATE
                        | ins::EXTERNAL_AUTHENTICATE
                        | ins::INTERNAL_AUTHENTICATE
                        | ins::PERFORM_SECURITY_OPERATION
                )
        }
        _ => false,
    }
}

/// Which EXTERNAL AUTHENTICATE security levels the SCP03 handshake accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LevelPolicy {
    /// Only `33` (C-MAC, C-DECRYPTION, R-MAC, R-ENCRYPTION). Yubico yk5-apps-scp: "The
    /// YubiKey implements this with all of them turned on. Turning anything off is not
    /// an option." Other levels answer `6A86`.
    #[default]
    FullOnly,
    /// Every secure-messaging level of Amd D §7.1.2 Table 7-3: `01`, `03`, `11`, `13`,
    /// `33`. A conformance option for exercising the GP secure-messaging layer; no
    /// YubiKey behaves this way.
    AmendmentD,
}

/// The Security Domain application.
pub struct SecurityDomain {
    state: State,
    pending: Option<Pending>,
    /// Session counters shared with the channels this domain created.
    shared: Arc<Shared>,
    policy: LevelPolicy,
    chain: CommandChain,
    /// Whether the chain in progress arrived through a secure channel.
    chain_secure: bool,
    /// Command chaining of handshake commands (a certificate in PSO).
    hs_chain: CommandChain,
    /// Plaintext response data waiting for GET RESPONSE.
    responses: ResponseQueue,
    /// An OCE certificate chain being uploaded with PERFORM SECURITY OPERATION.
    oce_chain: Option<pso::Chain>,
    /// The last verified OCE (volatile).
    oce: Option<pso::Oce>,
}

impl core::fmt::Debug for SecurityDomain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecurityDomain")
            .field("state", &self.state)
            .field("pending", &self.pending)
            .field("policy", &self.policy)
            .field("oce_chain", &self.oce_chain.is_some())
            .field("oce", &self.oce.is_some())
            .finish_non_exhaustive()
    }
}

impl SecurityDomain {
    /// Restore from the plaintext last persisted, or start from the factory state.
    ///
    /// The factory state draws a new SCP11b key, its self-signed certificate and a CPLC
    /// identifier from `host` and is persisted at once (best effort) so that the
    /// identity stays stable across restarts. A readable record without a CPLC keeps its
    /// keys and gets a new CPLC; a record written before SCP11 support keeps its keys
    /// and gets a certificate for each SCP11b key that has none.
    pub fn new(stored: Option<&[u8]>, host: &mut dyn Host) -> Self {
        let (state, dirty) = match stored.and_then(State::parse) {
            Some(parsed) => {
                let mut state = parsed.state;
                if parsed.missing_cplc {
                    state.cplc = state::new_cplc(host);
                }
                if parsed.missing_revision {
                    state.add_own_certificates(host);
                }
                (state, parsed.missing_cplc || parsed.missing_revision)
            }
            None => (State::factory(host), true),
        };
        if dirty {
            // A failure here is not reported: the next successful mutation persists the
            // whole state again.
            let _ = host.persist(Record::SecurityDomain, &state.serialize());
        }
        Self {
            state,
            pending: None,
            shared: Arc::new(Shared::default()),
            policy: LevelPolicy::default(),
            chain: CommandChain::new(MAX_CHAINED_DATA),
            chain_secure: false,
            hs_chain: CommandChain::new(MAX_CHAINED_DATA),
            responses: ResponseQueue::new(),
            oce_chain: None,
            oce: None,
        }
    }

    /// See [`is_handshake`].
    pub fn is_handshake(apdu: &[u8]) -> bool {
        is_handshake(apdu)
    }

    /// The accepted SCP03 security levels.
    pub fn level_policy(&self) -> LevelPolicy {
        self.policy
    }

    /// Change the accepted SCP03 security levels (volatile).
    pub fn set_level_policy(&mut self, policy: LevelPolicy) {
        self.policy = policy;
    }

    /// Authentication tries left for a key: an SCP03 set for KID 1-3, an OCE CA key for
    /// KID `10`/`20`-`2F`, otherwise the SCP11 private key (`kid`, `kvn`). `None` if
    /// there is no such key. Diagnostic only; the GP interface does not expose it.
    pub fn remaining_tries(&self, kid: u8, kvn: u8) -> Option<u8> {
        let row = if (1..=3).contains(&kid) {
            handshake::KeyRow::Scp03 { kvn }
        } else if state::is_ca_kid(kid) {
            handshake::KeyRow::Ca { kid, kvn }
        } else {
            handshake::KeyRow::Ec { kid, kvn }
        };
        row.tries(&self.state)
    }

    /// Whether a verified OCE certificate chain is cached for SCP11a/c (diagnostic).
    pub fn has_verified_oce(&self) -> bool {
        self.current_oce().is_some()
    }

    /// End any secure channel session this Security Domain created and drop a half-open
    /// handshake, a partial OCE certificate chain and the cached OCE. Called on every
    /// SELECT (Yubico: "When a new applet is selected, the session is terminated"), card
    /// power-off and reset.
    pub fn end_session(&mut self) {
        self.pending = None;
        self.chain.clear();
        self.hs_chain.clear();
        self.responses.clear();
        self.clear_oce();
        Shared::bump(&self.shared.epoch);
    }

    /// Process a secure channel handshake command (see [`is_handshake`]).
    ///
    /// Returns the response and, after a successful EXTERNAL, MUTUAL or INTERNAL
    /// AUTHENTICATE, the new channel. Works whichever applet is selected. ISO command
    /// chaining (CLA b5) is reassembled, so a certificate for PERFORM SECURITY OPERATION
    /// may arrive in short pieces as well as in one extended APDU.
    pub fn handshake(&mut self, apdu: &[u8], host: &mut dyn Host) -> (Vec<u8>, Option<SecureChannel>) {
        let cmd = match Command::parse(apdu) {
            Ok(cmd) => cmd,
            Err(e) => {
                self.hs_chain.clear();
                return (apdu::status(e.sw()), None);
            }
        };
        if cmd.cla & 0x03 != 0 {
            self.hs_chain.clear();
            return (apdu::status(sw::LOGICAL_CHANNEL_NOT_SUPPORTED), None);
        }
        if cmd.cla & !0x14 != 0x80 {
            self.hs_chain.clear();
            return (apdu::status(sw::CLA_NOT_SUPPORTED), None);
        }
        let cmd = match self.hs_chain.push(cmd) {
            Ok(Some(cmd)) => cmd,
            Ok(None) => return (apdu::status(sw::OK), None),
            Err(e) => return (apdu::status(e.sw()), None),
        };
        match cmd.ins {
            ins::INITIALIZE_UPDATE => (self.initialize_update(&cmd, host), None),
            ins::EXTERNAL_AUTHENTICATE => self.external_authenticate(&cmd, host),
            ins::INTERNAL_AUTHENTICATE => self.internal_authenticate(&cmd, host),
            ins::PERFORM_SECURITY_OPERATION => (self.perform_security_operation(&cmd, host), None),
            _ => (apdu::status(sw::INS_NOT_SUPPORTED), None),
        }
    }

    /// Process a command for the selected Security Domain that `channel` unwrapped.
    ///
    /// This is the only path that authorizes PUT KEY, DELETE KEY, GENERATE EC KEY and
    /// STORE DATA (GP 2.3.1 §11.8.1, §11.2.1, §11.11.1: secure channel required). A
    /// closed or stale channel, or one another Security Domain created, answers `6982`.
    /// The response is returned whole, for the device to wrap and then split.
    pub fn process_secure(
        &mut self,
        apdu: &[u8],
        channel: &SecureChannel,
        host: &mut dyn Host,
    ) -> Outcome<Vec<u8>> {
        if !channel.is_open() || !channel.belongs_to(&self.shared) {
            return Outcome::Done(apdu::status(sw::SECURITY_STATUS));
        }
        self.responses.clear();
        Outcome::Done(self.dispatch(apdu, Some(channel), host))
    }

    /// A plaintext command: dispatch it and chain a response longer than Ne with `61xx`
    /// (ISO/IEC 7816-4 §5.1.3); GET RESPONSE fetches the rest (`6985` if nothing waits).
    fn process_plain(&mut self, apdu: &[u8], host: &mut dyn Host) -> Vec<u8> {
        let parsed = Command::parse(apdu).ok();
        if let Some(cmd) = &parsed
            && cmd.ins == ins::GET_RESPONSE
            && cmd.cla == 0x00
            && !self.chain.is_active()
        {
            let max = max_response(cmd);
            return self.responses.next(max).unwrap_or_else(|| apdu::status(sw::CONDITIONS));
        }
        self.responses.clear();
        let response = self.dispatch(apdu, None, host);
        let Some(cmd) = parsed else {
            return response;
        };
        let max = max_response(&cmd);
        match apdu::split_response(&response) {
            Some((data, status)) if data.len() > max => self.responses.start(data.to_vec(), status, max),
            _ => response,
        }
    }

    fn dispatch(&mut self, apdu: &[u8], channel: Option<&SecureChannel>, host: &mut dyn Host) -> Vec<u8> {
        let cmd = match Command::parse(apdu) {
            Ok(cmd) => cmd,
            Err(e) => {
                self.chain.clear();
                return apdu::status(e.sw());
            }
        };
        let secure = channel.is_some();
        if cmd.cla & 0x03 != 0 && cmd.cla & 0x40 == 0 {
            self.chain.clear();
            return apdu::status(sw::LOGICAL_CHANNEL_NOT_SUPPORTED);
        }
        // Without a channel there is nothing that could have verified secure messaging.
        if !secure && cmd.cla & 0x04 != 0 {
            self.chain.clear();
            return apdu::status(sw::SECURITY_STATUS);
        }
        if self.chain.is_active() && self.chain_secure != secure {
            self.chain.clear();
        }
        if cmd.is_chained() && !self.chain.is_active() {
            self.chain_secure = secure;
        }
        let cmd = match self.chain.push(cmd) {
            Ok(Some(cmd)) => cmd,
            Ok(None) => return apdu::status(sw::OK),
            Err(e) => return apdu::status(e.sw()),
        };
        let gp_class = cmd.cla == 0x80;
        let any_class = gp_class || cmd.cla == 0x00;
        let protocol = channel.map(SecureChannel::protocol);
        match cmd.ins {
            ins::GET_DATA if any_class => self.get_data(&cmd),
            // GP 2.3.1 §11.9.2.1: the Security Domain is selected by name (P1 `04`), the
            // only SELECT the device recognises (docs/CONTRACTS.md "Applications A as
            // implemented"); any other INS `A4` is not a SELECT and changes nothing.
            ins::SELECT if cmd.cla == 0x00 && cmd.p1 == 0x04 => self.select(apdu, host),
            ins::SELECT if cmd.cla == 0x00 => apdu::status(sw::INCORRECT_P1P2),
            ins::INITIALIZE_UPDATE
            | ins::EXTERNAL_AUTHENTICATE
            | ins::INTERNAL_AUTHENTICATE
            | ins::PERFORM_SECURITY_OPERATION
                if gp_class =>
            {
                // The device routes these to `handshake`; a channel created here is
                // not handed out.
                self.handshake(&cmd.to_bytes(), host).0
            }
            ins::PUT_KEY | ins::DELETE | ins::GENERATE_KEY if gp_class => match (protocol, channel) {
                (Some(Protocol::Scp11c), _) => apdu::status(sw::CONDITIONS),
                (Some(Protocol::Scp03 | Protocol::Scp11a), Some(channel)) => match cmd.ins {
                    ins::PUT_KEY => self.put_key(&cmd, channel, host),
                    ins::DELETE => self.delete_key(&cmd, host),
                    _ => self.generate_key(&cmd, host),
                },
                _ => apdu::status(sw::SECURITY_STATUS),
            },
            ins::STORE_DATA if any_class => match protocol {
                Some(Protocol::Scp03 | Protocol::Scp11a) => self.store_data(&cmd, false, host),
                Some(Protocol::Scp11c) => self.store_data(&cmd, true, host),
                _ => apdu::status(sw::SECURITY_STATUS),
            },
            // GP 2.3.1 §11.10 SET STATUS is not offered; an SCP11c session gets the same
            // refusal as other state changes (catalog SecurityDomain_scp11c).
            ins::SET_STATUS if gp_class => match protocol {
                Some(Protocol::Scp11c) => apdu::status(sw::CONDITIONS),
                _ => apdu::status(sw::INS_NOT_SUPPORTED),
            },
            ins::GET_DATA
            | ins::SELECT
            | ins::INITIALIZE_UPDATE
            | ins::EXTERNAL_AUTHENTICATE
            | ins::INTERNAL_AUTHENTICATE
            | ins::PERFORM_SECURITY_OPERATION
            | ins::PUT_KEY
            | ins::DELETE
            | ins::GENERATE_KEY
            | ins::STORE_DATA
            | ins::SET_STATUS => apdu::status(sw::CLA_NOT_SUPPORTED),
            _ => apdu::status(sw::INS_NOT_SUPPORTED),
        }
    }

    /// Persist `next` and make it current; on failure keep the current state and
    /// answer `6581` (docs/CONTRACTS.md "Persisted state").
    pub(crate) fn commit(&mut self, next: State, host: &mut dyn Host) -> Result<(), u16> {
        host.persist(Record::SecurityDomain, &next.serialize())
            .map_err(|_| sw::MEMORY_FAILURE)?;
        self.state = next;
        Ok(())
    }

    /// Reset the Security Domain to a fresh factory state (new SCP11b key, certificate
    /// and CPLC; no CA keys, certificates, allowlists or counters) and end every session.
    /// On a persistence failure nothing changes.
    pub(crate) fn factory_reset(&mut self, host: &mut dyn Host) -> Result<(), u16> {
        let fresh = State::factory(host);
        self.commit(fresh, host)?;
        self.end_session();
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn state(&self) -> &State {
        &self.state
    }

    #[cfg(test)]
    pub(crate) fn row_tries(&self, row: handshake::KeyRow) -> Option<u8> {
        row.tries(&self.state)
    }
}

/// The most response data one response may carry for `cmd`: Ne, or the form's maximum
/// when Le is absent.
fn max_response(cmd: &Command) -> usize {
    cmd.expected_len().unwrap_or(if cmd.extended { 65_536 } else { 256 })
}

/// Dropping the Security Domain (device restart, power cycle) ends the sessions it
/// created, so a stale channel cannot outlive it.
impl Drop for SecurityDomain {
    fn drop(&mut self) {
        Shared::bump(&self.shared.epoch);
    }
}

impl CardApplet for SecurityDomain {
    fn aid(&self) -> &'static [u8] {
        AID
    }

    /// SELECT (GP 2.3.1 §11.9): ends any session and returns the File Control
    /// Information observed on the reference device. P2 with "no response data"
    /// (`0C`) answers `9000` alone.
    fn select(&mut self, apdu: &[u8], _host: &mut dyn Host) -> Vec<u8> {
        self.end_session();
        match Command::parse(apdu) {
            Ok(cmd) if cmd.p2 & 0x0C == 0x0C => apdu::status(sw::OK),
            Ok(_) => apdu::response(&data::SELECT_FCI, sw::OK),
            Err(e) => apdu::status(e.sw()),
        }
    }

    /// A command without secure messaging: GET DATA (with GET RESPONSE for long
    /// answers), and handshakes if the device sent them here. Key management needs a
    /// session (`6982`).
    fn process(&mut self, apdu: &[u8], host: &mut dyn Host) -> Outcome<Vec<u8>> {
        Outcome::Done(self.process_plain(apdu, host))
    }

    /// The Security Domain never waits for touch.
    fn touch_resolved(&mut self, _touched: bool, _host: &mut dyn Host) -> Vec<u8> {
        apdu::status(sw::CONDITIONS)
    }

    fn deselect(&mut self) {
        self.end_session();
    }

    /// Every kind of reset ends the session and drops the half-open handshake; the
    /// Security Domain has no other volatile state.
    fn reset(&mut self, _kind: ResetKind) {
        self.end_session();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use lk_testkit::TestHost;

    #[test]
    fn handshake_classification() {
        assert!(is_handshake(&[0x80, 0x50, 0x00, 0x00, 0x08]));
        assert!(is_handshake(&[0x84, 0x82, 0x33, 0x00]));
        assert!(is_handshake(&[0x80, 0x88, 0x01, 0x13]));
        assert!(is_handshake(&[0x90, 0x2A, 0x01, 0x10]));
        assert!(is_handshake(&[0x94, 0x2A, 0x01, 0x10]));
        // OpenPGP INTERNAL AUTHENTICATE and PSO (OpenPGP Card 3.4 §7.2.13, §7.2.10).
        assert!(!is_handshake(&[0x00, 0x88, 0x00, 0x00]));
        assert!(!is_handshake(&[0x00, 0x2A, 0x9E, 0x9A]));
        assert!(!is_handshake(&[0x0C, 0x2A, 0x9E, 0x9A]));
        assert!(!is_handshake(&[0x80, 0xCA, 0x00, 0x66]));
        assert!(!is_handshake(&[0x80, 0x50, 0x00]));
        assert!(!is_handshake(&[0xA0, 0x50, 0x00, 0x00]));
        assert!(!is_handshake(&[]));
    }

    #[test]
    fn factory_state_is_persisted_on_creation() {
        let mut host = TestHost::new();
        let sd = SecurityDomain::new(None, &mut host);
        let stored = host.persisted(Record::SecurityDomain).unwrap();
        assert_eq!(State::parse(&stored).unwrap().state, *sd.state());
        assert_eq!(sd.row_tries(handshake::KeyRow::Scp03 { kvn: 0xFF }), Some(state::AUTH_TRIES));
        assert_eq!(sd.row_tries(handshake::KeyRow::Ec { kid: 0x13, kvn: 0x01 }), Some(state::AUTH_TRIES));
    }
}
