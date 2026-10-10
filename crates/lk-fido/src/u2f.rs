//! U2F raw messages (FIDO U2F Raw Message Formats v1.2, Proposed Standard 2017-04-11),
//! carried in CTAPHID_MSG (CTAP 2.1 §11.2, §10 "Interoperating with CTAP1/U2F").
//!
//! - Request framing: ISO 7816-4 APDUs in short or extended length (§3.1, `lk_codec::apdu`);
//!   a malformed APDU is `SW_WRONG_LENGTH` (6700).
//! - CLA other than 00 is `SW_CLA_NOT_SUPPORTED` (6E00); INS other than REGISTER (01),
//!   AUTHENTICATE (02) and VERSION (03) is `SW_INS_NOT_SUPPORTED` (6D00) (§3.3).
//! - REGISTER (§4) issues an ES256 key handle in the same format as a CTAP
//!   non-discoverable credential ID, with the application parameter as RP ID hash, so a
//!   U2F registration also works in authenticatorGetAssertion (CTAP 2.1 §10.3 "Using
//!   the CTAP2 authenticatorGetAssertion Command with CTAP1/U2F authenticators" in the
//!   other direction: the WebAuthn `appid` extension sends rpId = appId).
//! - AUTHENTICATE (§5) accepts any ES256 credential ID this device issued for the
//!   application parameter; other key handles are `SW_WRONG_DATA` (6A80).
//! - User presence uses the device's latched touch (`docs/CONTRACTS.md` U2F presence): a
//!   request that needs it without one answers `SW_CONDITIONS_NOT_SATISFIED` (6985) and
//!   asks the device to latch the next touch.
//! - A PIN does not affect U2F, which has no user verification.
//! - While alwaysUv is on, CTAP1/U2F is disabled (CTAP 2.1 §7.2.4: "The U2F_REGISTER and
//!   U2F_AUTHENTICATE commands MUST immediately fail and return SW_COMMAND_NOT_ALLOWED",
//!   6986; GetInfo then leaves "U2F_V2" out of `versions`). VERSION still answers (§7.2.4
//!   names only REGISTER and AUTHENTICATE).

use lk_codec::apdu::{self, Command, sw};
use lk_core::Host;

use crate::credential::{Alg, CredSecret};
use crate::{Authenticator, U2fPresence, ensure_keys};

const INS_REGISTER: u8 = 0x01;
const INS_AUTHENTICATE: u8 = 0x02;
const INS_VERSION: u8 = 0x03;

/// AUTHENTICATE control byte values (§5.1).
const P1_CHECK_ONLY: u8 = 0x07;
const P1_ENFORCE_USER_PRESENCE: u8 = 0x03;
const P1_DONT_ENFORCE_USER_PRESENCE: u8 = 0x08;

/// Registration response reserved byte (§4.3).
const REGISTER_RESERVED: u8 = 0x05;

fn status(code: u16, presence: U2fPresence) -> (Vec<u8>, U2fPresence) {
    (apdu::status(code), presence)
}

impl Authenticator {
    pub(crate) fn handle_u2f(
        &mut self,
        raw: &[u8],
        user_present: bool,
        host: &mut dyn Host,
    ) -> (Vec<u8>, U2fPresence) {
        let cmd = match Command::parse(raw) {
            Ok(cmd) => cmd,
            Err(err) => return status(err.sw(), U2fPresence::NotNeeded),
        };
        if cmd.cla != 0x00 {
            return status(sw::CLA_NOT_SUPPORTED, U2fPresence::NotNeeded);
        }
        if self.state.pin.always_uv && matches!(cmd.ins, INS_REGISTER | INS_AUTHENTICATE) {
            return status(sw::COMMAND_NOT_ALLOWED, U2fPresence::NotNeeded);
        }
        match cmd.ins {
            INS_REGISTER => self.u2f_register(&cmd.data, user_present, host),
            INS_AUTHENTICATE => self.u2f_authenticate(cmd.p1, &cmd.data, user_present, host),
            INS_VERSION => {
                // §6.1: no data; the response is "U2F_V2" without a terminator.
                if cmd.data.is_empty() {
                    (apdu::response(b"U2F_V2", sw::OK), U2fPresence::NotNeeded)
                } else {
                    status(sw::WRONG_LENGTH, U2fPresence::NotNeeded)
                }
            }
            _ => status(sw::INS_NOT_SUPPORTED, U2fPresence::NotNeeded),
        }
    }

    /// U2F_REGISTER (§4.1, §4.3). P1 is not checked: §3.1.1 has hosts send 00, while
    /// browsers send 03.
    fn u2f_register(
        &mut self,
        data: &[u8],
        user_present: bool,
        host: &mut dyn Host,
    ) -> (Vec<u8>, U2fPresence) {
        // §4.1: challenge parameter (32) || application parameter (32).
        let (Some(challenge), Some(application)) = (data.get(..32), data.get(32..64)) else {
            return status(sw::WRONG_LENGTH, U2fPresence::NotNeeded);
        };
        if data.len() != 64 {
            return status(sw::WRONG_LENGTH, U2fPresence::NotNeeded);
        }
        if !user_present {
            return status(sw::CONDITIONS, U2fPresence::Requested);
        }
        let Ok(application) = <[u8; 32]>::try_from(application) else {
            return status(sw::WRONG_LENGTH, U2fPresence::NotNeeded);
        };

        let mut next = self.state.clone();
        let Ok(keys_changed) = ensure_keys(&mut next, host) else {
            return status(sw::UNKNOWN, U2fPresence::NotNeeded);
        };
        let (Some(secret), Some(attestation)) = (next.secret, next.attestation.as_ref()) else {
            return status(sw::UNKNOWN, U2fPresence::NotNeeded);
        };
        let cred = CredSecret::generate(Alg::Es256, 1, false, host);
        let (Ok(key_handle), Some(public)) = (
            cred.wrap(&secret, &application, host),
            cred.u2f_public_key(),
        ) else {
            return status(sw::UNKNOWN, U2fPresence::NotNeeded);
        };
        let Ok(handle_len) = u8::try_from(key_handle.len()) else {
            return status(sw::UNKNOWN, U2fPresence::NotNeeded);
        };
        // §4.3: signature over 0x00 || application || challenge || key handle || public key.
        let mut signed = Vec::with_capacity(1 + 32 + 32 + key_handle.len() + public.len());
        signed.push(0x00);
        signed.extend_from_slice(&application);
        signed.extend_from_slice(challenge);
        signed.extend_from_slice(&key_handle);
        signed.extend_from_slice(&public);
        let Ok(signature) = attestation.sign(&signed, host) else {
            return status(sw::UNKNOWN, U2fPresence::NotNeeded);
        };
        let mut out = Vec::with_capacity(
            1 + public.len() + 1 + key_handle.len() + attestation.cert.len() + 72 + 2,
        );
        out.push(REGISTER_RESERVED);
        out.extend_from_slice(&public);
        out.push(handle_len);
        out.extend_from_slice(&key_handle);
        out.extend_from_slice(&attestation.cert);
        out.extend_from_slice(&signature);
        // The first registration creates the device secret and attestation identity,
        // which must be stored before the key handle is revealed.
        if keys_changed && self.commit(next, host).is_err() {
            return status(sw::MEMORY_FAILURE, U2fPresence::NotNeeded);
        }
        (apdu::response(&out, sw::OK), U2fPresence::Consumed)
    }

    /// U2F_AUTHENTICATE (§5.1, §5.4).
    fn u2f_authenticate(
        &mut self,
        p1: u8,
        data: &[u8],
        user_present: bool,
        host: &mut dyn Host,
    ) -> (Vec<u8>, U2fPresence) {
        // §5.1: challenge (32) || application (32) || L (1) || key handle (L).
        let (Some(challenge), Some(application), Some(&handle_len)) =
            (data.get(..32), data.get(32..64), data.get(64))
        else {
            return status(sw::WRONG_LENGTH, U2fPresence::NotNeeded);
        };
        let Some(key_handle) = data.get(65..) else {
            return status(sw::WRONG_LENGTH, U2fPresence::NotNeeded);
        };
        if key_handle.len() != usize::from(handle_len) {
            return status(sw::WRONG_LENGTH, U2fPresence::NotNeeded);
        }
        // §5.1 defines three control bytes; others are reserved (model policy: ISO 7816-4
        // "incorrect parameters P1-P2").
        if !matches!(
            p1,
            P1_CHECK_ONLY | P1_ENFORCE_USER_PRESENCE | P1_DONT_ENFORCE_USER_PRESENCE
        ) {
            return status(sw::INCORRECT_P1P2, U2fPresence::NotNeeded);
        }
        let Ok(application) = <[u8; 32]>::try_from(application) else {
            return status(sw::WRONG_LENGTH, U2fPresence::NotNeeded);
        };
        // §5.3 bad key handle: not issued by this device for this application, not a
        // P-256 key that U2F can use, or a credProtect userVerificationRequired credential,
        // which needs UV that U2F cannot perform (CTAP 2.1 §12.1, §6.2.2 step 7.4).
        let Some(cred) = self
            .resolve(key_handle, &application)
            .filter(|c| c.alg() == Alg::Es256 && c.cred_protect != 3)
        else {
            return status(sw::INCORRECT_DATA, U2fPresence::NotNeeded);
        };
        let (user_presence, presence) = match p1 {
            // §5.1: check-only answers "test-of-user-presence-required" for a valid handle.
            P1_CHECK_ONLY => return status(sw::CONDITIONS, U2fPresence::NotNeeded),
            P1_ENFORCE_USER_PRESENCE if !user_present => {
                return status(sw::CONDITIONS, U2fPresence::Requested);
            }
            P1_ENFORCE_USER_PRESENCE => (0x01u8, U2fPresence::Consumed),
            _ => (0x00u8, U2fPresence::NotNeeded),
        };
        // §5.4: the counter is incremented with each authentication; it is the counter
        // CTAP2 assertions use and is persisted before it is revealed.
        let mut next = self.state.clone();
        let Some(counter) = next.counter.checked_add(1) else {
            return status(sw::UNKNOWN, U2fPresence::NotNeeded);
        };
        next.counter = counter;
        // §5.4: signature over application || user presence || counter || challenge.
        let mut signed = Vec::with_capacity(32 + 1 + 4 + 32);
        signed.extend_from_slice(&application);
        signed.push(user_presence);
        signed.extend_from_slice(&counter.to_be_bytes());
        signed.extend_from_slice(challenge);
        let Ok(signature) = cred.sign(&signed, host) else {
            return status(sw::UNKNOWN, U2fPresence::NotNeeded);
        };
        if self.commit(next, host).is_err() {
            return status(sw::MEMORY_FAILURE, U2fPresence::NotNeeded);
        }
        let mut out = Vec::with_capacity(1 + 4 + signature.len());
        out.push(user_presence);
        out.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&signature);
        (apdu::response(&out, sw::OK), presence)
    }
}
