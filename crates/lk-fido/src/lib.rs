//! FIDO authenticator: CTAP 2.1 (FIDO Alliance Proposed Standard, 15 June 2021) and U2F
//! raw messages v1.2 (CTAP1).
//!
//! # Scope
//!
//! - Commands: `authenticatorMakeCredential` (§6.1), `authenticatorGetAssertion` (§6.2),
//!   `authenticatorGetNextAssertion` (§6.3), `authenticatorGetInfo` (§6.4),
//!   `authenticatorClientPIN` (§6.5) with PIN/UV auth protocols 1 and 2 (§6.5.6, §6.5.7),
//!   `authenticatorReset` (§6.6), `authenticatorCredentialManagement` (§6.8) and its
//!   FIDO_2_1_PRE prototype 0x41, `authenticatorSelection` (§6.9),
//!   `authenticatorLargeBlobs` (§6.10) and `authenticatorConfig` (§6.11).
//! - U2F REGISTER, AUTHENTICATE and VERSION.
//! - Algorithms ES256, EdDSA and ES384.
//! - Extensions credProtect (§12.1), credBlob (§12.2), largeBlobKey (§12.3), minPinLength
//!   (§12.4) and hmac-secret (§12.5).
//! - Packed self-issued attestation (WebAuthn L2 §8.2).
//!
//! Not supported, as GetInfo states: built-in user verification (no `uv` option, so no
//! getPinUvAuthTokenUsingUvWithPermissions or getUVRetries), bio enrollment, enterprise
//! attestation (no `ep`) and vendor prototype config commands.
//!
//! # Contract
//!
//! The API is the one `docs/CONTRACTS.md` fixes for `lk-fido::Authenticator`. The engine
//! never blocks: a command that needs user presence returns [`Outcome::NeedTouch`] and
//! finishes in [`Authenticator::presence_resolved`]. State is persisted through
//! [`Host::persist`] before any response that depends on it. PIN tokens, key-agreement
//! keys, the soft PIN block and enumeration state are volatile and end with
//! [`Authenticator::power_cycle`].

#![forbid(unsafe_code)]

mod attestation;
mod client_pin;
mod config;
mod cred_mgmt;
mod credential;
mod get_assertion;
mod get_info;
mod large_blobs;
mod make_credential;
mod pin_protocol;
mod request;
mod state;
pub mod status;
mod u2f;

#[cfg(test)]
mod tests;

use lk_codec::cbor::{self, Value};
use lk_core::{Host, Millis, Outcome, Record};
use lk_crypto::SecretBytes;

use crate::attestation::Attestation;
use crate::client_pin::PinSession;
use crate::credential::CredSecret;
use crate::request::{CtapResult, pin_protocol_supported};
use crate::state::State;

/// How long a command waits for a touch before the device resolves it as not granted.
/// CTAP 2.1 leaves the value to the authenticator; 30 s is the CTAPHID-era convention
/// (the catalog states no other value).
pub const TOUCH_TIMEOUT_MS: Millis = 30_000;

/// `authenticatorReset` is accepted only this long after power-up (CTAP 2.1 §6.6: "request
/// MUST have come to the authenticator within 10 seconds of powering up").
pub const RESET_WINDOW_MS: Millis = 10_000;

/// Length of the credential wrapping secret (the HKDF input of `credential`).
const WRAPPING_SECRET_LEN: usize = 32;

/// What a U2F request did with the device's latched touch (`docs/CONTRACTS.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum U2fPresence {
    /// The request did not need user presence; any latched touch stays latched.
    NotNeeded,
    /// The request used the latched touch.
    Consumed,
    /// The response was `6985` (test of user presence required); the device should latch
    /// the next touch for a later U2F request.
    Requested,
}

/// A command waiting for user presence.
enum Pending {
    /// Zero-length pinUvAuthParam probe (CTAP 2.1 §6.1.2 / §6.2.2 step 1).
    PinProbe,
    /// excludeList hit (CTAP 2.1 §6.1.2 step 12).
    Excluded,
    MakeCredential(Box<make_credential::Plan>),
    GetAssertion(Box<get_assertion::Plan>),
    Reset,
    Selection,
}

impl Pending {
    fn name(&self) -> &'static str {
        match self {
            Pending::PinProbe => "pin-probe",
            Pending::Excluded => "excluded",
            Pending::MakeCredential(_) => "makeCredential",
            Pending::GetAssertion(_) => "getAssertion",
            Pending::Reset => "reset",
            Pending::Selection => "selection",
        }
    }
}

/// The FIDO2/U2F authenticator application.
pub struct Authenticator {
    state: State,
    pending: Option<Pending>,
    /// authenticatorGetNextAssertion state (CTAP 2.1 §6.3).
    assertion: Option<get_assertion::NextAssertion>,
    /// Key-agreement keys, the pinUvAuthToken and the consecutive PIN mismatch count
    /// (CTAP 2.1 §6.5); volatile.
    pin: PinSession,
    /// credentialManagement enumeration state (CTAP 2.1 §6.8.3, §6.8.4).
    cred_mgmt: Option<cred_mgmt::Enumeration>,
    /// A largeBlobs write sequence in progress (CTAP 2.1 §6.10.2).
    large_blob_write: Option<large_blobs::PendingWrite>,
    /// Time of the last power-up, for the reset window.
    power_up: Millis,
}

impl core::fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Authenticator")
            .field("initialized", &self.state.secret.is_some())
            .field("counter", &self.state.counter)
            .field("discoverable_credentials", &self.state.residents.len())
            .field("pin_set", &self.state.pin_is_set())
            .field("pin_session", &self.pin)
            .field("pending", &self.pending.as_ref().map(Pending::name))
            .field("power_up", &self.power_up)
            .finish_non_exhaustive()
    }
}

impl Authenticator {
    /// Restore from the plaintext last passed to [`Host::persist`] for `Record::Fido`;
    /// absent or unreadable state is the factory state. Construction counts as power-up
    /// for the reset window.
    pub fn new(stored: Option<&[u8]>, host: &mut dyn Host) -> Self {
        let state = stored.and_then(State::deserialize).unwrap_or_default();
        Self {
            state,
            pending: None,
            assertion: None,
            pin: PinSession::default(),
            cred_mgmt: None,
            large_blob_write: None,
            power_up: host.now(),
        }
    }

    /// Handle one CTAP2 request: the command byte followed by its CBOR parameters
    /// (CTAP 2.1 §8). The response is the status byte followed by CBOR.
    ///
    /// - A request longer than `maxMsgSize` (1536) is `CTAP1_ERR_INVALID_LENGTH`, the value
    ///   CTAPHID uses for an over-long message (§11.2, CTAPHID_ERROR `ERR_INVALID_LEN` 0x03).
    /// - Unknown commands are `CTAP1_ERR_INVALID_COMMAND`.
    /// - Any command other than getNextAssertion discards the getNextAssertion state
    ///   (§6.3); any command other than credentialManagement discards its enumeration
    ///   state (§6.8.3, §6.8.4).
    /// - While a command waits for a touch the device does not deliver another one
    ///   (CTAPHID busy rules); if it does, the answer is `CTAP1_ERR_CHANNEL_BUSY` and the
    ///   waiting command is kept.
    pub fn cbor(&mut self, request: &[u8], host: &mut dyn Host) -> Outcome<Vec<u8>> {
        if self.pending.is_some() {
            return Outcome::Done(vec![status::CHANNEL_BUSY]);
        }
        let Some((&command, params)) = request.split_first() else {
            return Outcome::Done(vec![status::INVALID_LENGTH]);
        };
        if request.len() > get_info::MAX_MSG_SIZE {
            return Outcome::Done(vec![status::INVALID_LENGTH]);
        }
        if command != status::command::GET_NEXT_ASSERTION {
            self.assertion = None;
        }
        if command != status::command::CREDENTIAL_MANAGEMENT
            && command != status::command::CREDENTIAL_MANAGEMENT_PREVIEW
        {
            self.cred_mgmt = None;
        }
        match command {
            status::command::GET_INFO => {
                Outcome::Done(ok(get_info::get_info(&self.state, host.profile())))
            }
            status::command::MAKE_CREDENTIAL => self.make_credential(params, host),
            status::command::GET_ASSERTION => self.get_assertion(params, host),
            status::command::GET_NEXT_ASSERTION => Outcome::Done(self.get_next_assertion(host)),
            status::command::CLIENT_PIN => Outcome::Done(self.client_pin(params, host)),
            status::command::RESET => self.reset(host),
            status::command::CREDENTIAL_MANAGEMENT => {
                Outcome::Done(self.credential_management(params, false, host))
            }
            status::command::CREDENTIAL_MANAGEMENT_PREVIEW => {
                Outcome::Done(self.credential_management(params, true, host))
            }
            status::command::SELECTION => self.wait_for_touch(Pending::Selection),
            status::command::LARGE_BLOBS => Outcome::Done(self.large_blobs(params, host)),
            status::command::CONFIG => Outcome::Done(self.config(params, host)),
            _ => Outcome::Done(vec![status::INVALID_COMMAND]),
        }
    }

    /// Finish the command that returned [`Outcome::NeedTouch`]. `granted` is false when the
    /// touch timed out or the session was reset first.
    ///
    /// - makeCredential / getAssertion: `CTAP2_ERR_OPERATION_DENIED` ("If the user declines
    ///   permission, or the operation times out", CTAP 2.1 §6.1.2 step 14, §6.2.2 step 9).
    /// - excludeList hit: `CTAP2_ERR_CREDENTIAL_EXCLUDED` "regardless of whether user
    ///   presence is obtained or the authenticator times out" (§6.1.2 step 12.1.4).
    /// - zero-length pinUvAuthParam probe: `CTAP2_ERR_PIN_NOT_SET` / `CTAP2_ERR_PIN_INVALID`
    ///   after a touch, `CTAP2_ERR_OPERATION_DENIED` otherwise (§6.1.2 step 1).
    /// - reset and selection: `CTAP2_ERR_USER_ACTION_TIMEOUT` ("If a user action timeout
    ///   occurs", §6.6, §6.9).
    /// - Nothing pending: `CTAP2_ERR_NOT_ALLOWED`.
    pub fn presence_resolved(&mut self, granted: bool, host: &mut dyn Host) -> Vec<u8> {
        let Some(pending) = self.pending.take() else {
            return vec![status::NOT_ALLOWED];
        };
        match pending {
            Pending::PinProbe if granted => {
                vec![if self.state.pin_is_set() {
                    status::PIN_INVALID
                } else {
                    status::PIN_NOT_SET
                }]
            }
            Pending::PinProbe => vec![status::OPERATION_DENIED],
            Pending::Excluded => vec![status::CREDENTIAL_EXCLUDED],
            Pending::MakeCredential(plan) if granted => self.finish_make_credential(*plan, host),
            Pending::GetAssertion(plan) if granted => self.finish_get_assertion(*plan, true, host),
            Pending::MakeCredential(_) | Pending::GetAssertion(_) => vec![status::OPERATION_DENIED],
            Pending::Reset if granted => self.finish_reset(host),
            Pending::Selection if granted => vec![status::OK],
            Pending::Reset | Pending::Selection => vec![status::USER_ACTION_TIMEOUT],
        }
    }

    /// The host cancelled (CTAPHID_CANCEL, CTAP 2.1 §11.2): a waiting command ends
    /// with `CTAP2_ERR_KEEPALIVE_CANCEL`; with nothing pending there is no response.
    pub fn cancel(&mut self, _host: &mut dyn Host) -> Option<Vec<u8>> {
        self.pending.take().map(|_| vec![status::KEEPALIVE_CANCEL])
    }

    /// Handle one U2F request APDU (U2F raw message formats v1.2). `user_present` reports a
    /// latched touch; see [`U2fPresence`]. U2F requests never wait: without presence they
    /// answer `6985` at once, so a CTAPHID_CANCEL has nothing to cancel.
    pub fn u2f(
        &mut self,
        apdu: &[u8],
        user_present: bool,
        host: &mut dyn Host,
    ) -> (Vec<u8>, U2fPresence) {
        self.assertion = None;
        self.cred_mgmt = None;
        if self.pending.is_some() {
            return (
                lk_codec::apdu::status(lk_codec::apdu::sw::CONDITIONS),
                U2fPresence::NotNeeded,
            );
        }
        self.handle_u2f(apdu, user_present, host)
    }

    /// Power was removed and restored: drop the waiting command, the getNextAssertion
    /// and credentialManagement enumeration state, the pinUvAuthToken, the key-agreement
    /// keys, the soft PIN block (CTAP 2.1 §6.5.5.7.2 step 9 "power cycling is needed") and any
    /// largeBlobs write in progress, and restart the reset window.
    pub fn power_cycle(&mut self, host: &mut dyn Host) {
        self.pending = None;
        self.drop_volatile_state();
        self.power_up = host.now();
    }

    fn drop_volatile_state(&mut self) {
        self.assertion = None;
        self.pin = PinSession::default();
        self.cred_mgmt = None;
        self.large_blob_write = None;
    }

    /// Whether a command waits for user presence.
    pub fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    fn wait_for_touch(&mut self, pending: Pending) -> Outcome<Vec<u8>> {
        self.pending = Some(pending);
        Outcome::NeedTouch {
            timeout_ms: TOUCH_TIMEOUT_MS,
        }
    }

    /// `authenticatorReset` (CTAP 2.1 §6.6): `CTAP2_ERR_NOT_ALLOWED` more than
    /// [`RESET_WINDOW_MS`] after power-up, otherwise wait for a touch.
    fn reset(&mut self, host: &mut dyn Host) -> Outcome<Vec<u8>> {
        if host.now().saturating_sub(self.power_up) > RESET_WINDOW_MS {
            return Outcome::Done(vec![status::NOT_ALLOWED]);
        }
        self.wait_for_touch(Pending::Reset)
    }

    /// Wipe every credential, the counter, the PIN, the configuration and the large-blob
    /// array, and rotate the wrapping secret so that every credential ID issued before
    /// stops working (`reference/BEHAVIOR_CATALOG.md` FIDO: "reset rotates root"). The
    /// attestation identity is kept, as a hardware attestation key is. Tokens and
    /// key-agreement keys are discarded too.
    fn finish_reset(&mut self, host: &mut dyn Host) -> Vec<u8> {
        let mut secret = SecretBytes::zeroed(WRAPPING_SECRET_LEN);
        host.fill(&mut secret);
        let next = State {
            secret: Some(secret),
            attestation: self.state.attestation.clone(),
            ..State::default()
        };
        match self.commit(next, host) {
            Ok(()) => {
                self.drop_volatile_state();
                vec![status::OK]
            }
            Err(code) => vec![code],
        }
    }

    /// Persist `next` and make it current; on failure keep the current state and report
    /// `CTAP1_ERR_OTHER` (`docs/CONTRACTS.md`, persisted state). The serialized record holds
    /// the wrapping secret, the attestation scalar and the PIN hash, so it is wiped once
    /// the host has stored it.
    fn commit(&mut self, next: State, host: &mut dyn Host) -> CtapResult<()> {
        let record = SecretBytes::new(next.serialize());
        host.persist(Record::Fido, &record)
            .map_err(|_| status::OTHER)?;
        self.state = next;
        Ok(())
    }

    /// The credential behind `id` if this authenticator issued it for `rp_id_hash`. A
    /// discoverable credential must still be stored: once overwritten or deleted, its
    /// ID no longer works even though the key inside it still unwraps.
    fn resolve(&self, id: &[u8], rp_id_hash: &[u8; 32]) -> Option<CredSecret> {
        let secret = self.state.secret.as_ref()?;
        let cred = CredSecret::unwrap(id, secret, rp_id_hash)?;
        if cred.discoverable
            && !self
                .state
                .residents
                .iter()
                .any(|r| r.id == id && r.rp_id_hash == *rp_id_hash)
        {
            return None;
        }
        Some(cred)
    }

    /// pinUvAuthProtocol checks for a non-empty pinUvAuthParam (CTAP 2.1 §6.1.2 step 2,
    /// §6.2.2 step 2): absent is `CTAP2_ERR_MISSING_PARAMETER`, unsupported is
    /// `CTAP1_ERR_INVALID_PARAMETER`.
    fn check_pin_protocol(protocol: Option<u64>) -> CtapResult<()> {
        match protocol {
            None => Err(status::MISSING_PARAMETER),
            Some(p) if !pin_protocol_supported(p) => Err(status::INVALID_PARAMETER),
            Some(_) => Ok(()),
        }
    }
}

/// Make sure `next` has a wrapping secret and an attestation identity for the current
/// profile, generating what is missing; returns whether anything changed (and so must be
/// persisted with the command that needed it).
fn ensure_keys(next: &mut State, host: &mut dyn Host) -> CtapResult<bool> {
    let mut changed = false;
    if next.secret.is_none() {
        let mut secret = SecretBytes::zeroed(WRAPPING_SECRET_LEN);
        host.fill(&mut secret);
        next.secret = Some(secret);
        changed = true;
    }
    let profile = host.profile().clone();
    if !next
        .attestation
        .as_ref()
        .is_some_and(|a| a.matches(&profile))
    {
        next.attestation = Some(Attestation::generate(&profile, host)?);
        changed = true;
    }
    Ok(changed)
}

/// `CTAP2_OK` followed by the CBOR encoding of `value`.
fn ok(value: Value) -> Vec<u8> {
    let mut out = vec![status::OK];
    cbor::encode_into(&value, &mut out);
    out
}
