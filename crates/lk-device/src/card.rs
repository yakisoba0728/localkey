//! The CCID interface and the card session behind it.
//!
//! `lk_ccid::Ccid` frames the USB CCID messages (USB CCID Rev 1.1); every complete
//! command APDU it hands over is routed here:
//!
//! 1. **Device-held response data.** While part of a wrapped response is waiting, a
//!    plaintext GET RESPONSE (`00 C0 00 00`, ISO/IEC 7816-4 §7.6.1; or YKOATH SEND
//!    REMAINING `00 A5 00 00` with OATH selected) is served from it. Any other command
//!    discards it (§7.6.1).
//! 2. **Secure channel** (`lk-sd`). While a channel is open, ISO-chained
//!    secure-messaging commands are reassembled first (`docs/CONTRACTS.md` "Applications
//!    B": "Reassemble ISO-chained secure-messaging commands before
//!    `SecureChannel::unwrap_command`"; intermediate parts answer `9000`), then
//!    `SecureChannel::unwrap_command` verifies and decrypts; the applet receives the
//!    command with the CLA secure-messaging bits cleared (`docs/CONTRACTS.md`
//!    "Applications A"). A rejected command (plaintext, bad C-MAC) is answered with the
//!    bare status and ends the channel; a plaintext SELECT ends it and is processed
//!    normally (Yubico yk5-apps-scp: "Sending a command in plain text will not be
//!    accepted and immediately ends the session"). Either way the selected applet's
//!    selection-scoped authorization is dropped with `CardApplet::deselect` (catalog
//!    SecurityDomain_plaintext: "plaintext in an established channel rejects before
//!    dispatch and revokes all local authorization"; "PIV verified PIN/admin and OATH
//!    access authorization revoked"; "malformed plaintext SELECT clears OCE and PIV
//!    PIN/admin before validation").
//! 3. **Handshakes.** `lk_sd::is_handshake` commands go to `SecurityDomain::handshake`
//!    whichever applet is selected; under an open channel the response is wrapped with
//!    the current channel and a new channel then replaces it (lk-sd crate docs; catalog
//!    SecurityDomain_handoff).
//! 4. **SELECT** (`xx A4 04 xx` only; `00 A4 00 0x` is OATH CALCULATE ALL,
//!    `docs/CONTRACTS.md` "Applications A"). The applet whose AID is a prefix of the
//!    DF name is selected (the longest such AID; ISO/IEC 7816-4 §5.3.1 selection by DF
//!    name, with right-truncated PIV and OpenPGP AIDs). Re-selecting the selected
//!    applet calls `select()` without `deselect()` (SP 800-73-4 Part 2 §3.1.1 keeps the
//!    PIV security status); selecting another one deselects the previous one first.
//!    `9000`, `61xx`, `62xx` and `63xx` count as success (`docs/CONTRACTS.md`: OpenPGP
//!    answers `6285` while terminated and stays selected). An unknown AID, or an
//!    application whose Management capability is disabled, answers `6A82` and leaves
//!    the current selection unchanged (ISO/IEC 7816-4 §5.6: "file or application not
//!    found"). Every SELECT ends the secure channel session (Yubico: "When a new
//!    applet is selected, the session is terminated"; `SecurityDomain::end_session`);
//!    an encrypted SELECT first drops the selected applet's authorization, so nothing
//!    gained under the channel stays usable in plaintext. A channel that ends with a
//!    response does the same.
//! 5. **Other commands** go to the selected applet; the Security Domain receives
//!    unwrapped commands through `SecurityDomain::process_secure`, and the OTP applet
//!    its Management bridge through `OtpApplet::process_with`. With no application
//!    selected the answer is `6D00` (model policy: ISO/IEC 7816-4 §5.6 "instruction code
//!    not supported" in the absence of a current application; a malformed APDU is
//!    `6700`).
//!
//! Under a secure channel the device collects the applet's whole response first (the
//! applet's own `61xx` chaining is followed with its continuation command), wraps it
//! once, and splits the wrapped bytes into `61xx` pieces of at most Ne itself (lk-sd
//! channel docs: "`wrap_response` receives the complete response before any `61xx`
//! splitting; the device serves the wrapped bytes with GET RESPONSE itself").
//!
//! A command that returns `Outcome::NeedTouch` keeps the CCID slot busy: the device
//! sends a time extension every [`crate::WTX_INTERVAL_MS`] and resolves it on a touch,
//! the timeout, an abort (bulk `PC_to_RDR_Abort` or the control `ABORT`, detected by
//! `Ccid::pending_seq` changing, `docs/CONTRACTS.md` "Phase 0", lk-ccid) or the end of
//! the session. IccPowerOff and a warm IccPowerOn (`CcidAction::PowerOff`) end the card
//! session with `CardApplet::reset(CardPowerOff)` and drop the secure channel.

use lk_ccid::CcidAction;
use lk_codec::apdu::{self, Command, CommandChain, ResponseQueue, sw};
use lk_core::{CardApplet, Millis, Outcome, ResetKind};
use lk_sd::SecureChannel;

use crate::apps::{AppId, Bridge};
use crate::{Device, Output};

/// Largest command data reassembled from ISO chaining under a secure channel: the
/// most an extended APDU can express (ISO/IEC 7816-4 §5.1, Nc ≤ 65 535), which is
/// what `Command::to_bytes` writes for `unwrap_command`.
const SM_CHAIN_LIMIT: usize = 65_535;

/// Upper bound on internal continuation commands while collecting one response
/// (65 536 bytes in 256-byte pieces, with margin).
const MAX_CONTINUATIONS: usize = 512;

/// Ne when Le is absent: the form's maximum (ISO/IEC 7816-4 §5.1), as lk-sd uses.
const SHORT_MAX_NE: usize = 256;
const EXTENDED_MAX_NE: usize = 65_536;

/// Selection, secure channel and response state of the card interface.
pub(crate) struct CardSession {
    pub(crate) selected: Option<AppId>,
    pub(crate) channel: Option<SecureChannel>,
    sm_chain: CommandChain,
    /// Wrapped response data waiting for GET RESPONSE.
    wrapped: ResponseQueue,
}

impl CardSession {
    pub(crate) fn new() -> Self {
        Self {
            selected: None,
            channel: None,
            sm_chain: CommandChain::new(SM_CHAIN_LIMIT),
            wrapped: ResponseQueue::new(),
        }
    }

    /// End the session: no selection, no channel, no partial command or response.
    pub(crate) fn clear(&mut self) {
        self.selected = None;
        self.channel = None;
        self.sm_chain.clear();
        self.wrapped.clear();
    }
}

/// What one command APDU produced.
enum Step {
    Reply(Vec<u8>),
    Wait {
        app: AppId,
        timeout_ms: Millis,
        wrap: bool,
        max: usize,
    },
}

/// The secure channel's verdict on one received command.
enum Unwrapped {
    /// Answer this now (an intermediate chain part, or a rejection).
    Reply(Vec<u8>),
    /// A verified command; its response is wrapped.
    Protected(Vec<u8>),
    /// A plaintext SELECT that ended the channel; processed without wrapping.
    Ended(Vec<u8>),
}

impl Device {
    /// One CCID bulk-out message.
    pub(crate) fn ccid_message(&mut self, message: &[u8], out: &mut Vec<Output>) {
        let before = self.ccid.pending_seq();
        let action = self.ccid.message(message);
        if before.is_some() && self.ccid.pending_seq() != before {
            self.drop_card_wait();
        }
        match action {
            CcidAction::Reply(reply) => out.push(Output::Ccid(reply)),
            CcidAction::Apdu { seq, apdu } => self.card_apdu(seq, &apdu, out),
            CcidAction::PowerOff(reply) => {
                self.drop_card_wait();
                self.end_card_session(ResetKind::CardPowerOff);
                out.push(Output::Ccid(reply));
            }
        }
    }

    /// The CCID class-specific `ABORT` control request (USB CCID Rev 1.1 §5.3.1).
    pub(crate) fn ccid_control_abort(&mut self, slot: u8, seq: u8, out: &mut Vec<Output>) {
        let before = self.ccid.pending_seq();
        let reply = self.ccid.control_abort(slot, seq);
        if before.is_some() && self.ccid.pending_seq() != before {
            self.drop_card_wait();
        }
        out.extend(reply.map(Output::Ccid));
    }

    fn card_apdu(&mut self, seq: u8, apdu: &[u8], out: &mut Vec<Output>) {
        match self.card_command(apdu) {
            Step::Reply(response) => self.send_card_response(seq, response, out),
            Step::Wait {
                app,
                timeout_ms,
                wrap,
                max,
            } => self.wait_card(seq, app, timeout_ms, wrap, max),
        }
    }

    /// Frame the card's response to XfrBlock `seq`; nothing is sent if the XfrBlock
    /// is no longer outstanding (`Ccid::apdu_response` returns an empty message).
    pub(crate) fn send_card_response(&mut self, seq: u8, response: Vec<u8>, out: &mut Vec<Output>) {
        let message = self.ccid.apdu_response(seq, &response);
        if !message.is_empty() {
            out.push(Output::Ccid(message));
        }
    }

    /// Route one command APDU (module documentation, steps 1 to 5).
    fn card_command(&mut self, raw: &[u8]) -> Step {
        let max = response_limit(raw);
        if self.card.wrapped.is_pending() {
            if let Some(limit) = self.continuation_limit(raw) {
                let piece = self
                    .card
                    .wrapped
                    .next(limit)
                    .unwrap_or_else(|| apdu::status(sw::CONDITIONS));
                return Step::Reply(piece);
            }
            self.card.wrapped.clear();
        }
        let (command, wrap) = if self.card.channel.is_some() {
            match self.unwrap_secure(raw) {
                Unwrapped::Reply(response) => return Step::Reply(response),
                Unwrapped::Protected(plain) => (plain, true),
                Unwrapped::Ended(plain) => (plain, false),
            }
        } else {
            (raw.to_vec(), false)
        };
        if lk_sd::is_handshake(&command) {
            return Step::Reply(self.handshake(&command, wrap, max));
        }
        if is_select(&command) {
            return Step::Reply(self.select(&command, wrap, max));
        }
        let Some(app) = self.card.selected else {
            let response = no_selection(&command);
            return Step::Reply(self.finish(None, response, wrap, max));
        };
        match self.applet_process(app, &command, wrap) {
            Outcome::Done(response) => Step::Reply(self.finish(Some(app), response, wrap, max)),
            Outcome::NeedTouch { timeout_ms } => Step::Wait {
                app,
                timeout_ms,
                wrap,
                max,
            },
        }
    }

    /// Ne of a plaintext continuation command for the device-held wrapped response, or
    /// `None` if `raw` is not one.
    fn continuation_limit(&self, raw: &[u8]) -> Option<usize> {
        let cmd = Command::parse(raw).ok()?;
        let continuation = cmd.ins == 0xC0
            || (cmd.ins == lk_oath::ins::SEND_REMAINING && self.card.selected == Some(AppId::Oath));
        (cmd.cla == 0x00 && continuation && cmd.p1 == 0 && cmd.p2 == 0 && cmd.data.is_empty()).then(|| limit_of(&cmd))
    }

    /// Step 2: reassemble a chained secure-messaging command and unwrap it.
    fn unwrap_secure(&mut self, raw: &[u8]) -> Unwrapped {
        let protected = raw.first().is_some_and(|&cla| has_secure_messaging(cla));
        let assembled = if protected && (self.card.sm_chain.is_active() || is_chained(raw)) {
            match Command::parse(raw) {
                Ok(cmd) => match self.card.sm_chain.push(cmd) {
                    Ok(None) => return Unwrapped::Reply(apdu::status(sw::OK)),
                    Ok(Some(cmd)) => cmd.to_bytes(),
                    Err(e) => return Unwrapped::Reply(apdu::status(e.sw())),
                },
                // Malformed: the channel rejects it below.
                Err(_) => {
                    self.card.sm_chain.clear();
                    raw.to_vec()
                }
            }
        } else {
            // A plaintext command in the middle of a protected chain ends the chain;
            // the channel then rejects it.
            self.card.sm_chain.clear();
            raw.to_vec()
        };
        let Some(channel) = self.card.channel.as_mut() else {
            return Unwrapped::Ended(assembled);
        };
        match channel.unwrap_command(&assembled) {
            Ok(plain) if channel.is_open() => Unwrapped::Protected(plain),
            Ok(plain) => {
                self.card.channel = None;
                self.revoke_selected();
                Unwrapped::Ended(plain)
            }
            Err(status) => {
                self.card.channel = None;
                self.revoke_selected();
                Unwrapped::Reply(apdu::status(status))
            }
        }
    }

    /// The channel ended on a rejected or plaintext command: drop the selected applet's
    /// selection-scoped authorization (module documentation, step 2).
    fn revoke_selected(&mut self) {
        self.card.sm_chain.clear();
        if let Some(app) = self.card.selected {
            self.apps.card(app).deselect();
        }
    }

    /// Step 3: a secure channel handshake for the Security Domain.
    fn handshake(&mut self, command: &[u8], wrap: bool, max: usize) -> Vec<u8> {
        let (response, channel) = self.apps.sd.handshake(command, &mut self.host);
        let response = if wrap { self.wrap_and_split(response, max) } else { response };
        if let Some(channel) = channel {
            self.card.channel = Some(channel);
        }
        response
    }

    /// Step 4: SELECT by DF name.
    fn select(&mut self, command: &[u8], wrap: bool, max: usize) -> Vec<u8> {
        self.apps.sd.end_session();
        if wrap {
            // An encrypted SELECT ends the session, and the authorization gained under it
            // ends before the SELECT is validated, also when it re-selects the current
            // applet or names an unknown one (catalog SecurityDomain_versions: "encrypted
            // SELECT terminate[s] authorization for subsequent commands";
            // SecurityDomain_plaintext: "malformed plaintext SELECT clears OCE and PIV
            // PIN/admin before validation"). `unwrap_secure` already revoked for a
            // plaintext SELECT that ended the channel.
            self.revoke_selected();
        }
        let response = match Command::parse(command) {
            Err(e) => apdu::status(e.sw()),
            Ok(cmd) => match self.find_applet(&cmd.data) {
                None => apdu::status(sw::FILE_NOT_FOUND),
                Some(id) => {
                    if let Some(previous) = self.card.selected.filter(|&p| p != id) {
                        self.apps.card(previous).deselect();
                    }
                    let response = self.apps.card(id).select(command, &mut self.host);
                    self.card.selected = selection_succeeded(&response).then_some(id);
                    response
                }
            },
        };
        let selected = self.card.selected;
        let response = self.seal(selected, response, wrap, max);
        if self.card.channel.as_ref().is_some_and(|channel| !channel.is_open()) {
            self.card.channel = None;
        }
        response
    }

    /// The enabled applet whose AID is the longest prefix of `name`.
    fn find_applet(&self, name: &[u8]) -> Option<AppId> {
        AppId::ALL
            .into_iter()
            .filter(|&id| name.starts_with(id.aid()) && self.app_enabled(id))
            .max_by_key(|id| id.aid().len())
    }

    /// [`Device::find_applet`] for unit tests.
    #[cfg(test)]
    pub(crate) fn find_applet_for_test(&self, name: &[u8]) -> Option<AppId> {
        self.find_applet(name)
    }

    /// Whether the application is enabled by the capabilities of the last enumeration
    /// (`lk_mgmt::Management::enabled_usb`: settings apply when the device enumerates).
    fn app_enabled(&self, id: AppId) -> bool {
        id.capability().is_none_or(|bit| self.caps.contains(bit))
    }

    /// Step 5: give a command to applet `app`.
    fn applet_process(&mut self, app: AppId, command: &[u8], secure: bool) -> Outcome<Vec<u8>> {
        match app {
            AppId::Otp => {
                // docs/CONTRACTS.md "Applications A": CCID APDUs to the OTP AID use
                // `OtpApplet::process_with` with the Management bridge.
                let mut bridge = Bridge::new(self.apps.mgmt.management_mut());
                let outcome = self.apps.otp.process_with(command, Some(&mut bridge), &mut self.host);
                self.reboot_owed |= bridge.reboot_requested();
                outcome
            }
            AppId::SecurityDomain if secure => match &self.card.channel {
                Some(channel) => self.apps.sd.process_secure(command, channel, &mut self.host),
                None => self.apps.sd.process(command, &mut self.host),
            },
            id => self.apps.card(id).process(command, &mut self.host),
        }
    }

    /// The response to send for a command of `app`: unchanged without a secure
    /// channel; collected, wrapped and split under one. If the channel ended with this
    /// response, the selected applet's authorization ends with it (catalog
    /// SecurityDomain_versions: "reset ... terminate[s] authorization for subsequent
    /// commands"), so nothing gained under the channel is usable in plaintext.
    pub(crate) fn finish(&mut self, app: Option<AppId>, response: Vec<u8>, wrap: bool, max: usize) -> Vec<u8> {
        let response = self.seal(app, response, wrap, max);
        if wrap && self.card.channel.is_none() {
            self.revoke_selected();
        }
        response
    }

    /// [`Device::finish`] without the revocation, for SELECT: it revokes before it is
    /// processed, and the applet it selected keeps its fresh selection state.
    fn seal(&mut self, app: Option<AppId>, response: Vec<u8>, wrap: bool, max: usize) -> Vec<u8> {
        if !wrap {
            return response;
        }
        let full = match app {
            Some(app) => self.collect(app, response),
            None => response,
        };
        self.wrap_and_split(full, max)
    }

    /// Follow `61xx` with the applet's continuation command until the whole response
    /// is in hand.
    fn collect(&mut self, app: AppId, first: Vec<u8>) -> Vec<u8> {
        let mut data = Vec::new();
        let mut response = first;
        for _ in 0..MAX_CONTINUATIONS {
            let Some((part, status)) = apdu::split_response(&response) else {
                return response;
            };
            data.extend_from_slice(part);
            if status >> 8 != 0x61 {
                return apdu::response(&data, status);
            }
            let next = [0x00, app.continuation_ins(), 0x00, 0x00, 0x00];
            response = match self.applet_process(app, &next, true) {
                Outcome::Done(response) => response,
                // A continuation never waits for a touch.
                Outcome::NeedTouch { .. } => return apdu::status(sw::UNKNOWN),
            };
        }
        apdu::status(sw::UNKNOWN)
    }

    /// Wrap a complete response with the channel, drop a channel that ended, and keep
    /// what does not fit in Ne for GET RESPONSE.
    fn wrap_and_split(&mut self, response: Vec<u8>, max: usize) -> Vec<u8> {
        let Some(channel) = self.card.channel.as_mut() else {
            return response;
        };
        let wrapped = channel.wrap_response(&response);
        if !channel.is_open() {
            self.card.channel = None;
        }
        match apdu::split_response(&wrapped) {
            Some((data, status)) if data.len() > max => self.card.wrapped.start(data.to_vec(), status, max),
            _ => wrapped,
        }
    }
}

/// `xx A4 04 xx`: SELECT by DF name, the only SELECT the device recognises.
fn is_select(command: &[u8]) -> bool {
    matches!(command, [_, 0xA4, 0x04, _, ..])
}

/// Whether a SELECT response selected the applet (see the module documentation).
fn selection_succeeded(response: &[u8]) -> bool {
    apdu::split_response(response).is_some_and(|(_, status)| status == sw::OK || matches!(status >> 8, 0x61..=0x63))
}

/// The answer to a command while no application is selected (model policy, module
/// documentation step 5).
fn no_selection(command: &[u8]) -> Vec<u8> {
    match Command::parse(command) {
        Err(e) => apdu::status(e.sw()),
        Ok(_) => apdu::status(sw::INS_NOT_SUPPORTED),
    }
}

/// Ne of a command, or the form's maximum when Le is absent.
fn limit_of(cmd: &Command) -> usize {
    cmd.expected_len()
        .unwrap_or(if cmd.extended { EXTENDED_MAX_NE } else { SHORT_MAX_NE })
}

/// Ne of a raw command (256 for a malformed one).
fn response_limit(raw: &[u8]) -> usize {
    Command::parse(raw).map_or(SHORT_MAX_NE, |cmd| limit_of(&cmd))
}

/// Whether a CLA indicates secure messaging: bits b4-b3 for the first interindustry
/// class, b6 for the further interindustry class (ISO/IEC 7816-4 §5.1.1), b3 for
/// proprietary classes (GlobalPlatform `84`, GP Card Specification v2.3.1 §11.1.4).
fn has_secure_messaging(cla: u8) -> bool {
    match cla {
        0x00..=0x1F => cla & 0x0C != 0,
        0x40..=0x7F => cla & 0x20 != 0,
        0x80..=0xFE => cla & 0x04 != 0,
        _ => false,
    }
}

/// Whether CLA bit b5 (command chaining, ISO/IEC 7816-4 §5.1.1.1) is set.
fn is_chained(raw: &[u8]) -> bool {
    raw.first().is_some_and(|&cla| cla != 0xFF && cla & 0x10 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/CONTRACTS.md "Applications A as implemented": only `xx A4 04 xx` is SELECT.
    #[test]
    fn only_select_by_name_is_select() {
        assert!(is_select(&[0x00, 0xA4, 0x04, 0x00, 0x01, 0xA0]));
        assert!(is_select(&[0x84, 0xA4, 0x04, 0x0C]));
        assert!(!is_select(&[0x00, 0xA4, 0x00, 0x01]));
        assert!(!is_select(&[0x00, 0xA4, 0x04]));
    }

    /// docs/CONTRACTS.md "Applications B": `62xx` is a successful selection.
    #[test]
    fn selection_success_statuses() {
        for status in [0x9000u16, 0x6285, 0x6110, 0x63C1] {
            assert!(selection_succeeded(&status.to_be_bytes()), "{status:04X}");
        }
        for status in [0x6A82u16, 0x6700, 0x6D00] {
            assert!(!selection_succeeded(&status.to_be_bytes()), "{status:04X}");
        }
        assert!(!selection_succeeded(&[]));
    }

    /// The secure-messaging indication per class, the same table as lk-sd's
    /// `strip_secure_messaging` (ISO/IEC 7816-4 §5.1.1; GP 2.3.1 §11.1.4).
    #[test]
    fn secure_messaging_classes() {
        for cla in [0x04, 0x0C, 0x14, 0x84, 0x94, 0x60] {
            assert!(has_secure_messaging(cla), "{cla:02X}");
        }
        for cla in [0x00, 0x10, 0x80, 0x90, 0x40, 0x24, 0xFF] {
            assert!(!has_secure_messaging(cla), "{cla:02X}");
        }
        assert!(is_chained(&[0x14]));
        assert!(is_chained(&[0x94]));
        assert!(!is_chained(&[0x04]));
        assert!(!is_chained(&[0xFF]));
    }

    /// ISO/IEC 7816-4 §5.1: absent Le means the form's maximum; `00` is 256 (short) or
    /// 65 536 (extended).
    #[test]
    fn response_limits() {
        assert_eq!(response_limit(&[0x00, 0xCA, 0x00, 0x66]), 256);
        assert_eq!(response_limit(&[0x00, 0xCA, 0x00, 0x66, 0x00]), 256);
        assert_eq!(response_limit(&[0x00, 0xCA, 0x00, 0x66, 0x10]), 16);
        assert_eq!(response_limit(&[0x00, 0xCA, 0x00, 0x66, 0x00, 0x00, 0x00]), 65_536);
        assert_eq!(response_limit(&[0x00]), 256);
    }
}
