//! The secure-messaging wrapper returned by a successful handshake.
//!
//! Sources:
//! - GlobalPlatform Card Specification v2.3.1 Amendment D v1.1.2 ("Amd D") §6.2.4
//!   C-MAC, §6.2.5 R-MAC, §6.2.6 command decryption, §6.2.7 response encryption, and
//!   §7.1.2 Table 7-3 (security levels).
//! - GlobalPlatform Card Specification v2.3.1 Amendment F (SCP11): SCP11 sessions use
//!   the SCP03 secure messaging with the derived S-ENC, S-MAC and S-RMAC, the receipt as
//!   the first MAC chaining value and the counter starting at 1.
//! - Yubico, YubiKey 5 technical manual, "Secure Channel" (yk5-apps-scp): "Sending a
//!   command in plain text will not be accepted and immediately ends the session";
//!   "When a new applet is selected, the session is terminated".
//!
//! Layering expected from `lk-device` (see the crate documentation):
//! 1. `unwrap_command` receives one complete command. A device that reassembles ISO
//!    command chaining first passes the assembled command (one C-MAC over the whole
//!    command, as Yubico's SDK sends it in the extended form); a device that does not
//!    passes each part, and each part then carries its own C-MAC and keeps CLA bit b5.
//!    Yubico's SDK needs the first: on a short-APDU session `ScpProcessor.send_apdu`
//!    MACs a command whose data exceeds 255 bytes over the extended Lc form and then
//!    splits the protected command with ISO chaining, so only the reassembled command
//!    (CLA without b5, `Command::to_bytes`, which picks the extended form for more than
//!    255 data bytes) verifies.
//! 2. The plain command goes to the selected applet (or to
//!    [`crate::SecurityDomain::handshake`] / [`crate::SecurityDomain::process_secure`]).
//! 3. `wrap_response` receives the complete response before any `61xx` splitting; the
//!    device serves the wrapped bytes with GET RESPONSE itself.
//! 4. After `wrap_response`, a channel for which [`SecureChannel::is_open`] is false is
//!    dropped.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use lk_codec::apdu::{self, Command, sw};

use crate::scp03::{self, Key, SessionKeys};

/// Session bookkeeping shared between a Security Domain and the channels it created.
///
/// The engine has no threads; the atomics only let a channel the device owns observe
/// events in the Security Domain (and the reverse) without a borrow between them.
#[derive(Debug, Default)]
pub(crate) struct Shared {
    /// Incremented whenever every session must end (SELECT, reset, Security Domain
    /// reset, the domain being dropped).
    pub(crate) epoch: AtomicU64,
    /// Incremented when a new SCP11c session supersedes the previous one (catalog
    /// SecurityDomain_handoff: "latest committed successful c context supersedes older
    /// c contexts"), or when a failed SCP11c commit ends the current one.
    pub(crate) c_epoch: AtomicU64,
    /// Incremented when a channel ends because it rejected a command (plaintext or a
    /// bad C-MAC). The Security Domain drops its cached OCE when this changes (catalog
    /// SecurityDomain_plaintext: plaintext "revokes all local authorization").
    pub(crate) revocations: AtomicU64,
}

impl Shared {
    pub(crate) fn load(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::SeqCst)
    }

    pub(crate) fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::SeqCst);
    }
}

/// Security level bits: the P1 of EXTERNAL AUTHENTICATE (Amd D §7.1.2, Table 7-3).
pub mod level {
    /// C-MAC on every command.
    pub const C_MAC: u8 = 0x01;
    /// Command data encrypted with S-ENC.
    pub const C_DECRYPTION: u8 = 0x02;
    /// R-MAC on every protected response.
    pub const R_MAC: u8 = 0x10;
    /// Response data encrypted with S-ENC.
    pub const R_ENCRYPTION: u8 = 0x20;
    /// All four: the only level the YubiKey implements ("The YubiKey implements this
    /// with all of them turned on. Turning anything off is not an option", Yubico
    /// yk5-apps-scp).
    pub const FULL: u8 = 0x33;
    /// Every level Amd D Table 7-3 defines with secure messaging. `00` (no secure
    /// messaging) is excluded: Yubico's rule that a plaintext command ends the session
    /// makes such a session unusable.
    pub const AMENDMENT_D: [u8; 5] = [0x01, 0x03, 0x11, 0x13, 0x33];
}

/// Which handshake established a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// SCP03 (Amd D), established with INITIALIZE UPDATE / EXTERNAL AUTHENTICATE.
    Scp03,
    /// SCP11a (GP Amendment F): mutual authentication with an OCE certificate chain,
    /// established with PERFORM SECURITY OPERATION and MUTUAL AUTHENTICATE.
    Scp11a,
    /// SCP11b (GP Amendment F): card authentication only, established with INTERNAL
    /// AUTHENTICATE. The host is not authenticated, so the session cannot manage the
    /// Security Domain.
    Scp11b,
    /// SCP11c (GP Amendment F): like SCP11a, but the card contributes no fresh key, so
    /// a recorded session can be replayed; state changes are restricted.
    Scp11c,
}

impl Protocol {
    /// Whether the host was authenticated (SCP03, SCP11a, SCP11c).
    pub fn host_authenticated(self) -> bool {
        !matches!(self, Protocol::Scp11b)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Open,
    /// The command being answered ends the session (an encrypted SELECT, a Security
    /// Domain reset); its response is still protected.
    CloseAfterResponse,
    Closed,
}

/// An established secure channel session.
///
/// Created only by [`crate::SecurityDomain::handshake`]. The device keeps it while the
/// session lasts and passes every command through [`unwrap_command`](Self::unwrap_command)
/// and every response through [`wrap_response`](Self::wrap_response).
///
/// The channel stays tied to the Security Domain that created it: when that domain
/// resets (blocking or explicit last-key deletion) or ends its session (SELECT, card
/// power-off, USB reset), the channel protects the response being produced and then
/// reports itself closed.
pub struct SecureChannel {
    protocol: Protocol,
    kvn: u8,
    level: u8,
    keys: SessionKeys,
    /// The key-encryption key for PUT KEY: for SCP03 the static K-DEK of the key set
    /// that authenticated the session (Amd D §6.2.1 has no session DEK).
    dek: Key,
    /// MAC chaining value (Amd D §6.2.4).
    mcv: [u8; 16],
    /// Encryption counter (Amd D §6.2.6): 1 for the first command after EXTERNAL
    /// AUTHENTICATE, incremented once per command while C-DECRYPTION is on.
    counter: u128,
    state: State,
    /// A command was unwrapped and its response has not been wrapped yet.
    awaiting: bool,
    shared: Arc<Shared>,
    /// The value of [`Shared::epoch`] when the channel was created.
    born: u64,
    /// For SCP11c, the value of [`Shared::c_epoch`] when the channel was created.
    c_born: Option<u64>,
}

impl core::fmt::Debug for SecureChannel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecureChannel")
            .field("protocol", &self.protocol)
            .field("kvn", &self.kvn)
            .field("level", &self.level)
            .field("counter", &self.counter)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl Drop for SecureChannel {
    fn drop(&mut self) {
        scp03::wipe(&mut self.dek);
        scp03::wipe(&mut self.mcv);
    }
}

/// What a received command turned out to be.
enum Unwrapped {
    Protected(Vec<u8>),
    PlainSelect,
}

impl SecureChannel {
    /// A new SCP03 session after a verified EXTERNAL AUTHENTICATE whose full C-MAC is
    /// `mcv`.
    pub(crate) fn scp03(
        kvn: u8,
        level: u8,
        keys: SessionKeys,
        dek: Key,
        mcv: [u8; 16],
        shared: Arc<Shared>,
    ) -> Self {
        Self::new(Protocol::Scp03, kvn, level, keys, dek, mcv, shared)
    }

    /// A new SCP11 session (GP Amendment F §3.1.2, §6.5): the session keys and S-DEK
    /// derived from the key agreement, the receipt as the first MAC chaining value, the
    /// encryption counter at 1 and every protection on (key usage `3C`).
    pub(crate) fn scp11(
        protocol: Protocol,
        kvn: u8,
        keys: SessionKeys,
        dek: Key,
        receipt: [u8; 16],
        shared: Arc<Shared>,
    ) -> Self {
        Self::new(protocol, kvn, level::FULL, keys, dek, receipt, shared)
    }

    fn new(
        protocol: Protocol,
        kvn: u8,
        level: u8,
        keys: SessionKeys,
        dek: Key,
        mcv: [u8; 16],
        shared: Arc<Shared>,
    ) -> Self {
        let born = Shared::load(&shared.epoch);
        let c_born = (protocol == Protocol::Scp11c).then(|| Shared::load(&shared.c_epoch));
        Self {
            protocol,
            kvn,
            level,
            keys,
            dek,
            mcv,
            counter: 1,
            state: State::Open,
            awaiting: false,
            shared,
            born,
            c_born,
        }
    }

    /// The handshake that established this channel.
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// The key version number of the key that authenticated the session (the SCP03 key
    /// set, or the SCP11 Security Domain key).
    pub fn key_version(&self) -> u8 {
        self.kvn
    }

    /// The security level (bits of [`level`]).
    pub fn security_level(&self) -> u8 {
        self.level
    }

    /// Whether the session still accepts commands. The device drops a channel once
    /// this is false (checked after each `wrap_response`).
    pub fn is_open(&self) -> bool {
        self.state != State::Closed && self.is_current()
    }

    /// End the session now; later commands are rejected and responses pass unchanged.
    pub fn close(&mut self) {
        self.state = State::Closed;
        self.awaiting = false;
    }

    /// End the session after the response to the current command has been wrapped.
    pub fn close_after_response(&mut self) {
        if self.state == State::Open {
            self.state = State::CloseAfterResponse;
        }
    }

    /// The Security Domain that created this channel has not reset or ended its
    /// session since.
    pub(crate) fn is_current(&self) -> bool {
        Shared::load(&self.shared.epoch) == self.born
            && self.c_born.is_none_or(|born| Shared::load(&self.shared.c_epoch) == born)
    }

    /// Whether this channel was created by the Security Domain that owns `shared`.
    pub(crate) fn belongs_to(&self, shared: &Arc<Shared>) -> bool {
        Arc::ptr_eq(&self.shared, shared)
    }

    /// The key-encryption key for PUT KEY: the static K-DEK for SCP03, the derived
    /// S-DEK for SCP11 (catalog SCP11: "private-key import with session DEK").
    pub(crate) fn dek(&self) -> &Key {
        &self.dek
    }

    /// Verify and decrypt one command.
    ///
    /// - A command whose CLA indicates secure messaging is checked against its C-MAC
    ///   (Amd D §6.2.4) and, under C-DECRYPTION, decrypted (§6.2.6). The result is the
    ///   plain command with the secure-messaging indication removed from CLA, the MAC
    ///   stripped and the data decrypted. Le is kept as received.
    /// - A plaintext command ends the session (Yubico yk5-apps-scp). A plaintext SELECT
    ///   (`xx A4 04 xx`, see [`is_select`]) is returned unchanged for normal processing,
    ///   because selecting an applet is itself the end of the session; its response is
    ///   not wrapped. Every other plaintext command, including other INS `A4` commands
    ///   such as YKOATH CALCULATE ALL, is rejected with `6982` before it reaches an
    ///   applet.
    /// - A missing or wrong C-MAC, malformed ciphertext or padding, or an unparsable APDU
    ///   ends the session; the error status is returned without R-MAC (Amd D §6.2.5).
    /// - An encrypted SELECT (`A4 04`) is unwrapped normally and ends the session after
    ///   its response, if it is a SELECT of the basic channel. One whose class codes
    ///   another logical channel is refused by the device with `6881` without selecting
    ///   anything (ISO/IEC 7816-4:1995 §5.5; lk-device `card.rs`), so it is not a session
    ///   boundary and the session goes on.
    pub fn unwrap_command(&mut self, apdu: &[u8]) -> Result<Vec<u8>, u16> {
        self.awaiting = false;
        if self.state != State::Open || !self.is_current() {
            self.close();
            return Err(sw::SECURITY_STATUS);
        }
        match self.unwrap_inner(apdu) {
            Ok(Unwrapped::Protected(plain)) => {
                self.awaiting = true;
                Ok(plain)
            }
            Ok(Unwrapped::PlainSelect) => {
                self.close();
                Shared::bump(&self.shared.revocations);
                Ok(apdu.to_vec())
            }
            Err(status) => {
                self.close();
                Shared::bump(&self.shared.revocations);
                Err(status)
            }
        }
    }

    fn unwrap_inner(&mut self, apdu: &[u8]) -> Result<Unwrapped, u16> {
        let cmd = Command::parse(apdu).map_err(|e| e.sw())?;
        let Some(plain_cla) = strip_secure_messaging(cmd.cla) else {
            return if is_select(&cmd) {
                Ok(Unwrapped::PlainSelect)
            } else {
                Err(sw::SECURITY_STATUS)
            };
        };
        let split = cmd.data.len().checked_sub(8).ok_or(sw::SECURITY_STATUS)?;
        let (payload, mac) = cmd.data.split_at_checked(split).ok_or(sw::SECURITY_STATUS)?;

        // Amd D §6.2.4: C-MAC = first 8 bytes of CMAC(S-MAC, MCV || header || Lc || data);
        // Lc counts the MAC and is written in the form the command used.
        let mut input = Vec::with_capacity(16 + 7 + payload.len());
        input.extend_from_slice(&self.mcv);
        input.extend_from_slice(&[cmd.cla, cmd.ins, cmd.p1, cmd.p2]);
        let lc = cmd.data.len();
        if cmd.extended {
            let lc = u16::try_from(lc).map_err(|_| sw::WRONG_LENGTH)?;
            input.push(0x00);
            input.extend_from_slice(&lc.to_be_bytes());
        } else {
            input.push(u8::try_from(lc).map_err(|_| sw::WRONG_LENGTH)?);
        }
        input.extend_from_slice(payload);
        let full = scp03::cmac(&self.keys.mac, &input)?;
        if !lk_crypto::ct_eq(full.get(..8).unwrap_or(&[]), mac) {
            return Err(sw::SECURITY_STATUS);
        }
        self.mcv = full;

        let data = if self.level & level::C_DECRYPTION != 0 {
            let counter = self.counter;
            self.counter = counter.checked_add(1).ok_or(sw::SECURITY_STATUS)?;
            if payload.is_empty() {
                // Amd D §6.2.6: an empty data field is not encrypted; the counter still
                // advances.
                Vec::new()
            } else {
                if !payload.len().is_multiple_of(16) {
                    return Err(sw::SECURITY_STATUS);
                }
                let icv = scp03::command_icv(&self.keys.enc, counter)?;
                let padded = lk_crypto::aes_cbc_decrypt(&self.keys.enc, &icv, payload)
                    .map_err(|_| sw::SECURITY_STATUS)?;
                scp03::unpad(&padded).ok_or(sw::SECURITY_STATUS)?.to_vec()
            }
        } else {
            payload.to_vec()
        };

        if is_select(&cmd) && on_basic_channel(cmd.cla) {
            self.state = State::CloseAfterResponse;
        }
        let plain = Command {
            cla: plain_cla,
            data,
            ..cmd
        };
        Ok(Unwrapped::Protected(plain.to_bytes()))
    }

    /// Protect the response to the command last unwrapped.
    ///
    /// - Responses with `9000` or a `61xx`/`62xx`/`63xx` status get R-ENCRYPTION of
    ///   their data (when present, Amd D §6.2.7) and an R-MAC over the (encrypted)
    ///   data and status word (§6.2.5), as the security level asks. The R-MAC uses the
    ///   chaining value of the command's C-MAC and does not change it.
    /// - Error statuses (`64xx`-`6Fxx`) are returned bare: Amd D §6.2.5 says no R-MAC
    ///   is applied to a response carrying an error status word.
    /// - A response not preceded by a successful `unwrap_command` (for example the
    ///   answer to a plaintext SELECT that ended the session) is returned unchanged.
    pub fn wrap_response(&mut self, response: &[u8]) -> Vec<u8> {
        if !self.awaiting {
            return response.to_vec();
        }
        self.awaiting = false;
        let out = match self.wrap_inner(response) {
            Ok(out) => out,
            Err(status) => {
                self.state = State::Closed;
                apdu::status(status)
            }
        };
        if self.state == State::CloseAfterResponse || !self.is_current() {
            self.state = State::Closed;
        }
        out
    }

    fn wrap_inner(&self, response: &[u8]) -> Result<Vec<u8>, u16> {
        let Some((data, status)) = apdu::split_response(response) else {
            return Ok(response.to_vec());
        };
        if !is_protected_status(status) {
            return Ok(response.to_vec());
        }
        let mut body = if self.level & level::R_ENCRYPTION != 0 && !data.is_empty() {
            let icv = scp03::response_icv(&self.keys.enc, self.counter.saturating_sub(1))?;
            lk_crypto::aes_cbc_encrypt(&self.keys.enc, &icv, &scp03::pad(data))
                .map_err(|_| scp03::CRYPTO_FAILURE)?
        } else {
            data.to_vec()
        };
        if self.level & level::R_MAC != 0 {
            let mut input = Vec::with_capacity(16 + body.len() + 2);
            input.extend_from_slice(&self.mcv);
            input.extend_from_slice(&body);
            input.extend_from_slice(&status.to_be_bytes());
            let mac = scp03::cmac(&self.keys.rmac, &input)?;
            body.extend_from_slice(mac.get(..8).unwrap_or(&[]));
        }
        Ok(apdu::response(&body, status))
    }
}

/// Whether `cmd` is SELECT by DF name, `xx A4 04 xx` (ISO/IEC 7816-4 §11.2.2, GP 2.3.1
/// §11.9.2.1), the only SELECT the device recognises (docs/CONTRACTS.md "Applications A
/// as implemented": `00 A4 00 0x` is YKOATH CALCULATE ALL for the selected applet). Only
/// a SELECT ends the session as a boundary; any other INS `A4` is an ordinary command.
fn is_select(cmd: &Command) -> bool {
    cmd.ins == crate::ins::SELECT && cmd.p1 == 0x04
}

/// Whether a CLA codes the basic logical channel 0: bits b2-b1 clear in `00`-`3F` and
/// `80`-`BF` (ISO/IEC 7816-4:1995 §5.5.2; GP 2.3.1 §11.1.4.1 Table 11-11); the further
/// interindustry classes `40`-`7F` and `C0`-`FE` code channels 4-19 (GP 2.3.1 §11.1.4.2
/// Table 11-12), and `FF` is invalid. The secure-messaging bits do not change it.
fn on_basic_channel(cla: u8) -> bool {
    matches!(cla, 0x00..=0x3F | 0x80..=0xBF) && cla & 0x03 == 0
}

/// Whether a status word is protected by R-MAC/R-ENCRYPTION: `9000` and the warning
/// classes `62xx`/`63xx` (Amd D §6.2.5), plus `61xx`, which ISO/IEC 7816-4 §5.1.3 also
/// counts as normal processing.
pub(crate) fn is_protected_status(status: u16) -> bool {
    status == sw::OK || matches!(status >> 8, 0x61..=0x63)
}

/// The CLA without its secure-messaging indication, or `None` when the CLA indicates
/// no secure messaging.
///
/// - First interindustry class `00`-`1F`: bits b4-b3 (ISO/IEC 7816-4 §5.1.1).
/// - Further interindustry class `40`-`7F`: bit b6.
/// - Proprietary classes `80`-`FE`: bit b3, the GlobalPlatform convention (`80` plain,
///   `84` secure messaging; GP Card Specification v2.3.1 §11.1.4).
/// - `20`-`3F` (reserved) and `FF` (invalid) never carry secure messaging.
fn strip_secure_messaging(cla: u8) -> Option<u8> {
    match cla {
        0x00..=0x1F => (cla & 0x0C != 0).then_some(cla & !0x0C),
        0x40..=0x7F => (cla & 0x20 != 0).then_some(cla & !0x20),
        0x80..=0xFE => (cla & 0x04 != 0).then_some(cla & !0x04),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_messaging_indication_by_class() {
        assert_eq!(strip_secure_messaging(0x00), None);
        assert_eq!(strip_secure_messaging(0x04), Some(0x00));
        assert_eq!(strip_secure_messaging(0x0C), Some(0x00));
        assert_eq!(strip_secure_messaging(0x14), Some(0x10));
        assert_eq!(strip_secure_messaging(0x80), None);
        assert_eq!(strip_secure_messaging(0x84), Some(0x80));
        assert_eq!(strip_secure_messaging(0x94), Some(0x90));
        assert_eq!(strip_secure_messaging(0x60), Some(0x40));
        assert_eq!(strip_secure_messaging(0x24), None);
        assert_eq!(strip_secure_messaging(0xFF), None);
    }

    #[test]
    fn protected_status_words() {
        for s in [0x9000, 0x6100, 0x6180, 0x6283, 0x63C2] {
            assert!(is_protected_status(s), "{s:04X}");
        }
        for s in [0x6982, 0x6A88, 0x6700, 0x6D00, 0x6F00, 0x6581, 0x9001] {
            assert!(!is_protected_status(s), "{s:04X}");
        }
    }
}
