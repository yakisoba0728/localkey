//! `authenticatorClientPIN` (CTAP 2.1 §6.5) and the volatile pinUvAuthToken state
//! (§6.5.2.1).
//!
//! # PIN attempt ordering
//!
//! changePIN, getPinToken and getPinUvAuthTokenUsingPinWithPermissions check, in order
//! (§6.5.5.6, §6.5.5.7.1, §6.5.5.7.2, with the orderings `reference/BEHAVIOR_CATALOG.md` FIDO
//! decided):
//!
//! 1. mandatory parameters (`CTAP2_ERR_MISSING_PARAMETER`), then pinUvAuthProtocol
//!    (`CTAP1_ERR_INVALID_PARAMETER`) and, for the permissions command, the permissions
//!    value (zero: `CTAP1_ERR_INVALID_PARAMETER`; `be`, whose feature is absent:
//!    `CTAP2_ERR_UNAUTHORIZED_PERMISSION`; undefined bits are ignored, §6.5.5.7.2 step 14);
//! 2. no PIN set: `CTAP2_ERR_PIN_NOT_SET`;
//! 3. pinRetries 0: `CTAP2_ERR_PIN_BLOCKED`;
//! 4. three consecutive mismatches since power-up: `CTAP2_ERR_PIN_AUTH_BLOCKED`, consuming
//!    no retry ("further PIN attempts consume no durable retry until a power cycle");
//! 5. `decapsulate` (`CTAP1_ERR_INVALID_PARAMETER`); for changePIN the pinUvAuthParam over
//!    `newPinEnc || pinHashEnc` (`CTAP2_ERR_PIN_AUTH_INVALID`);
//! 6. pinRetries is decremented and **persisted before** `pinHashEnc` is decrypted, so a
//!    malformed proof also costs a retry ("Malformed encrypted PIN proofs now decrement
//!    durable retries before decryption and participate in the three-attempt soft block");
//! 7. a decryption error, a plaintext that is not 16 bytes, or a hash mismatch is a
//!    mismatch: the request protocol's key-agreement key is regenerated and the answer is
//!    `CTAP2_ERR_PIN_BLOCKED` at zero retries, `CTAP2_ERR_PIN_AUTH_BLOCKED` on the third
//!    consecutive mismatch, else `CTAP2_ERR_PIN_INVALID`;
//! 8. on a match pinRetries returns to 8, and only then does forcePINChange apply:
//!    `CTAP2_ERR_PIN_POLICY_VIOLATION` for the permissions command, `CTAP2_ERR_PIN_INVALID`
//!    for the superseded getPinToken ("Forced-PIN-change token commands now verify the
//!    supplied old PIN and update retries before policy status; legacy token returns
//!    PIN_INVALID for a correct PIN under forced change").
//!
//! # Key agreement and tokens
//!
//! Each protocol has its own key-agreement key, created on first use after power-up (which
//! is indistinguishable from creating it at power-up, §6.5.6 `initialize()`) and dropped on
//! power cycle, on authenticatorReset and, for the protocol of the request only, on every
//! PIN mismatch ("Calls regenerate for the selected pinUvAuthProtocol", §6.5.5.6 step 7,
//! §6.5.5.7.1, §6.5.5.7.2 step 9). Issuing a token does not regenerate it; §6.5.5 does not
//! ask for that.
//!
//! One pinUvAuthToken is in use at a time: issuing a new one replaces it
//! (`resetPinUvAuthToken()` for all protocols), changePIN, power cycle and reset discard it.
//! It is only valid under the protocol it was issued with.
//!
//! # The userPresent flag
//!
//! A token carries no userPresent state because here it is always false: both issuing
//! subcommands call `beginUsingPinUvAuthToken(userIsPresent: false)` (§6.5.5.7.1 getPinToken,
//! §6.5.5.7.2 getPinUvAuthTokenUsingPinWithPermissions), and only
//! getPinUvAuthTokenUsingUvWithPermissions (§6.5.5.7.3), which needs built-in user
//! verification this authenticator lacks, can pass true. `getUserPresentFlagValue()`
//! (§6.5.3.2) is therefore false for every token, so makeCredential and getAssertion with a
//! pinUvAuthParam request a touch whenever "up" is true (§6.1.2 step 14.1.1, §6.2.2 step
//! 9.1.1) and before answering `CTAP2_ERR_CREDENTIAL_EXCLUDED` (§6.1.2 step 12.1.4); a token
//! never stands in for a touch. `clearUserPresentFlag()` is consequently a no-op and only
//! the userVerified flag and the permissions are cleared after presence
//! (`Authenticator::consume_token_after_presence`).
//!
//! The token value, like the shared secrets and decrypted PIN material, is held in
//! [`SecretBytes`] and wiped when dropped.

use lk_codec::cbor::{MapBuilder, Value};
use lk_core::{Host, Millis};
use lk_crypto::{SecretBytes, ct_eq, sha256};

use crate::pin_protocol::{KeyAgreement, PinProtocol, secret_from};
use crate::request::{CtapResult, Params, bytes, map, required, text, unsigned};
use crate::state::{DEFAULT_PIN_RETRIES, State};
use crate::{Authenticator, ok, status};

/// clientPIN subcommands (§6.5.5).
pub(crate) mod subcommand {
    pub const GET_PIN_RETRIES: u64 = 0x01;
    pub const GET_KEY_AGREEMENT: u64 = 0x02;
    pub const SET_PIN: u64 = 0x03;
    pub const CHANGE_PIN: u64 = 0x04;
    pub const GET_PIN_TOKEN: u64 = 0x05;
    pub const GET_PIN_UV_AUTH_TOKEN_USING_UV_WITH_PERMISSIONS: u64 = 0x06;
    pub const GET_UV_RETRIES: u64 = 0x07;
    pub const GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS: u64 = 0x09;
}

/// pinUvAuthToken permissions (§6.5.5.7 table "Permissions").
pub(crate) mod permission {
    /// makeCredential.
    pub const MC: u8 = 0x01;
    /// getAssertion.
    pub const GA: u8 = 0x02;
    /// credentialManagement.
    pub const CM: u8 = 0x04;
    /// bioEnrollment: not supported (GetInfo has no `bioEnroll`).
    pub const BE: u8 = 0x08;
    /// largeBlobWrite.
    pub const LBW: u8 = 0x10;
    /// authenticatorConfiguration.
    pub const ACFG: u8 = 0x20;
    /// Every permission CTAP 2.1 defines; the other bits are RFU.
    pub const DEFINED: u8 = MC | GA | CM | BE | LBW | ACFG;
    /// What this authenticator grants (GetInfo `credMgmt`, `largeBlobs`, `authnrCfg`; no
    /// `bioEnroll`).
    pub const SUPPORTED: u8 = DEFINED & !BE;
}

/// "initial usage time limit": a token not used within this time of issuance stops being
/// usable (§6.5.2.1 `pinUvAuthTokenUsageTimerObserver()`; the 30-second default).
pub(crate) const INITIAL_USAGE_TIME_LIMIT_MS: Millis = 30_000;
/// "max usage time period": no token is usable longer than this after issuance
/// (§6.5.2.1; the 10-minute default).
pub(crate) const MAX_USAGE_TIME_PERIOD_MS: Millis = 600_000;
/// Consecutive mismatches after which a power cycle is needed (§6.5.5.6 step 7,
/// §6.5.5.7.1, §6.5.5.7.2 step 9: "If the authenticator sees 3 consecutive mismatches, it
/// returns CTAP2_ERR_PIN_AUTH_BLOCKED").
const MAX_CONSECUTIVE_MISMATCHES: u8 = 3;
/// `paddedNewPin` is exactly 64 bytes (§6.5.5.5 step 7).
const PADDED_PIN_LEN: usize = 64;
/// "the maximum PIN length is 63 bytes" (§6.5.1 PIN composition).
const MAX_PIN_BYTES: usize = 63;
/// pinUvAuthToken length (§6.5.2.1: 32 bytes for both protocols here).
const TOKEN_LEN: usize = 32;

/// The pinUvAuthToken and its state (§6.5.2.1).
pub(crate) struct PinToken {
    /// The token itself (§6.5.6 / §6.5.7 `resetPinUvAuthToken()`), wiped when dropped.
    value: SecretBytes,
    protocol: PinProtocol,
    /// Permissions bit field (§6.5.5.7).
    pub permissions: u8,
    /// The permissions RP ID, if bound.
    pub rp_id: Option<String>,
    issued: Millis,
    /// Whether the token was used since issuance (initial usage time limit).
    used: bool,
    /// The "user verified" flag: set at issuance, cleared by a makeCredential or
    /// getAssertion that collected user presence (§6.1.2 step 14, §6.2.2 step 9). There is
    /// no userPresent flag: it would always be false (module documentation).
    pub user_verified: bool,
    /// Issued by the superseded getPinToken (§6.5.5.7.1), whose token the FIDO_2_1_PRE
    /// credentialManagement command 0x41 accepts (cred_mgmt model policy). Like the
    /// permissions it stands in for, this is cleared when user presence consumes the
    /// token (§6.1.2 step 14.4, §6.2.2 step 9), so a consumed token gains nothing on 0x41.
    pub legacy: bool,
    /// Which issuance this is (see [`PinSession::token_still_valid`]).
    serial: u64,
}

impl PinToken {
    fn live(&self, now: Millis) -> bool {
        let age = now.saturating_sub(self.issued);
        age <= MAX_USAGE_TIME_PERIOD_MS && (self.used || age <= INITIAL_USAGE_TIME_LIMIT_MS)
    }
}

/// Volatile clientPIN state, dropped on power cycle (`docs/DESIGN.md` §7, volatile state).
#[derive(Default)]
pub(crate) struct PinSession {
    key_agreement_v1: Option<KeyAgreement>,
    key_agreement_v2: Option<KeyAgreement>,
    pub token: Option<PinToken>,
    consecutive_mismatches: u8,
    /// Tokens issued since power-up; numbers each issuance.
    issued: u64,
}

impl core::fmt::Debug for PinSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PinSession")
            .field("token_in_use", &self.token.is_some())
            .field("consecutive_mismatches", &self.consecutive_mismatches)
            .finish_non_exhaustive()
    }
}

impl PinSession {
    /// Whether a power cycle is needed before the next PIN attempt (getPINRetries
    /// `powerCycleState`, §6.5.5.2).
    pub(crate) fn soft_blocked(&self) -> bool {
        self.consecutive_mismatches >= MAX_CONSECUTIVE_MISMATCHES
    }

    fn slot(&mut self, protocol: PinProtocol) -> &mut Option<KeyAgreement> {
        match protocol {
            PinProtocol::One => &mut self.key_agreement_v1,
            PinProtocol::Two => &mut self.key_agreement_v2,
        }
    }

    /// `regenerate()` for `protocol` (§6.5.6): the next use creates a fresh key.
    fn regenerate(&mut self, protocol: PinProtocol) {
        *self.slot(protocol) = None;
    }

    /// The serial of the in-use pinUvAuthToken, recorded by a state initializing command
    /// that it authenticated.
    pub(crate) fn token_serial(&self) -> Option<u64> {
        self.token.as_ref().map(|t| t.serial)
    }

    /// Whether the token with `serial` is still the in-use token and within its usage
    /// limits. CTAP 2.1 §6: "An authenticator MUST discard the state for a stateful command
    /// if the pinUvAuthToken that authenticated the state initializing command expires";
    /// a token replaced by a new issuance, changePIN, reset or power cycle has expired too.
    pub(crate) fn token_still_valid(&self, serial: u64, now: Millis) -> bool {
        self.token
            .as_ref()
            .is_some_and(|t| t.serial == serial && t.live(now))
    }
}

/// The parameters of an authenticatorClientPIN request (§6.5.4 table), type-checked.
#[derive(Debug)]
struct Request {
    protocol: Option<u64>,
    sub: u64,
    key_agreement: Option<Vec<(Value, Value)>>,
    pin_uv_auth_param: Option<Vec<u8>>,
    new_pin_enc: Option<Vec<u8>>,
    pin_hash_enc: Option<Vec<u8>>,
    permissions: Option<u64>,
    rp_id: Option<String>,
}

impl Request {
    /// Known members of the wrong CBOR type are `CTAP2_ERR_CBOR_UNEXPECTED_TYPE`; a missing
    /// subCommand is `CTAP2_ERR_MISSING_PARAMETER`.
    fn parse(params: &[u8]) -> CtapResult<Self> {
        let p = Params::decode(params)?;
        let protocol = p.get(0x01).map(unsigned).transpose()?;
        let sub = p.get(0x02).map(unsigned).transpose()?;
        let key_agreement = p.get(0x03).map(map).transpose()?.map(<[_]>::to_vec);
        let pin_uv_auth_param = p.get(0x04).map(bytes).transpose()?.map(<[u8]>::to_vec);
        let new_pin_enc = p.get(0x05).map(bytes).transpose()?.map(<[u8]>::to_vec);
        let pin_hash_enc = p.get(0x06).map(bytes).transpose()?.map(<[u8]>::to_vec);
        let permissions = p.get(0x09).map(unsigned).transpose()?;
        let rp_id = p.get(0x0A).map(text).transpose()?.map(str::to_owned);
        Ok(Self {
            protocol,
            sub: required(sub)?,
            key_agreement,
            pin_uv_auth_param,
            new_pin_enc,
            pin_hash_enc,
            permissions,
            rp_id,
        })
    }
}

/// A supported pinUvAuthProtocol, or `CTAP1_ERR_INVALID_PARAMETER`.
pub(crate) fn supported_protocol(value: u64) -> CtapResult<PinProtocol> {
    PinProtocol::from_u64(value).ok_or(status::INVALID_PARAMETER)
}

/// `LEFT(SHA-256(pin), 16)`, the CurrentStoredPIN (§6.5.5.5 step 12).
fn pin_hash(pin: &[u8]) -> SecretBytes {
    let digest = secret_from(sha256(pin));
    SecretBytes::from_slice(digest.get(..16).unwrap_or_default())
}

impl Authenticator {
    pub(crate) fn client_pin(&mut self, params: &[u8], host: &mut dyn Host) -> Vec<u8> {
        match self.client_pin_inner(params, host) {
            Ok(response) => response,
            Err(code) => vec![code],
        }
    }

    fn client_pin_inner(&mut self, params: &[u8], host: &mut dyn Host) -> CtapResult<Vec<u8>> {
        let req = Request::parse(params)?;
        match req.sub {
            subcommand::GET_PIN_RETRIES => Ok(self.get_pin_retries()),
            subcommand::GET_KEY_AGREEMENT => {
                let protocol = supported_protocol(required(req.protocol)?)?;
                let key = self.key_agreement(protocol, host).cose_public();
                Ok(ok(MapBuilder::new().insert(0x01, key).build()))
            }
            subcommand::SET_PIN => self.set_pin(&req, host),
            subcommand::CHANGE_PIN => self.change_pin(&req, host),
            subcommand::GET_PIN_TOKEN => self.get_pin_token(&req, host),
            subcommand::GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS => {
                self.get_pin_uv_auth_token_using_pin(&req, host)
            }
            // No built-in user verification: GetInfo has no "uv" option, so the UV
            // subcommands are not implemented (getUVRetries counts "built-in UV attempts",
            // §6.5.5.3; getPinUvAuthTokenUsingUvWithPermissions, §6.5.5.7.3). §8.1: "If the
            // authenticator implements a command code having subcommands, but does not
            // implement an invoked subcommand, it MUST return
            // CTAP2_ERR_INVALID_SUBCOMMAND." Known difference: the YubiKey 5C Nano 5.7.4
            // answers getUVRetries CTAP2_ERR_PIN_AUTH_INVALID (0x33), the pinUvAuthParam
            // failure code of §8.2 (docs/MEASUREMENT.md, probe client-pin-uv-retries, and
            // "Revised by principle"); the specification is followed (the note after the
            // §8.1 rule allows for older authenticators that do not), and no host stack
            // depends on 0x33. The engine copied 0x33 between the measurement and that
            // revision.
            subcommand::GET_PIN_UV_AUTH_TOKEN_USING_UV_WITH_PERMISSIONS
            | subcommand::GET_UV_RETRIES => Err(status::INVALID_SUBCOMMAND),
            _ => Err(status::INVALID_SUBCOMMAND),
        }
    }

    /// getPINRetries (§6.5.5.2): `{3: pinRetries}`, plus `4: true` (powerCycleState)
    /// while the PIN is soft-blocked until a power cycle. pinUvAuthProtocol is not needed
    /// and its value is not checked.
    ///
    /// Measured on a YubiKey 5C Nano 5.7.4 (`docs/MEASUREMENT.md`, probe
    /// `client-pin-retries`): without a soft block the answer is `00 A1 03 08` (`{3: 8}`),
    /// no powerCycleState (§6.5.5.2 makes it optional); the engine sent `4: false` before
    /// the measurement. The soft-blocked answer was not measured; it keeps `4: true`.
    fn get_pin_retries(&self) -> Vec<u8> {
        let soft_blocked = self.pin.soft_blocked();
        ok(MapBuilder::new()
            .insert(0x03, self.state.pin.retries)
            .insert_opt(0x04, soft_blocked.then_some(true))
            .build())
    }

    /// The key-agreement key for `protocol`, created on first use since power-up.
    fn key_agreement(&mut self, protocol: PinProtocol, host: &mut dyn Host) -> &KeyAgreement {
        self.pin
            .slot(protocol)
            .get_or_insert_with(|| KeyAgreement::generate(host))
    }

    /// `decapsulate(keyAgreement)` with the current key for `protocol`.
    pub(crate) fn decapsulate(
        &mut self,
        protocol: PinProtocol,
        peer: &[(Value, Value)],
        host: &mut dyn Host,
    ) -> CtapResult<SecretBytes> {
        self.key_agreement(protocol, host)
            .decapsulate(protocol, peer)
    }

    /// Decrypt and check a new PIN (§6.5.5.5 steps 6-10): decryption error
    /// `CTAP2_ERR_PIN_AUTH_INVALID`, not 64 bytes `CTAP1_ERR_INVALID_PARAMETER`; after the
    /// trailing zero bytes are dropped, more than 63 bytes, invalid UTF-8 or fewer code
    /// points than minPINLength is `CTAP2_ERR_PIN_POLICY_VIOLATION`. Returns the PIN hash
    /// and its length in code points.
    fn new_pin(
        &self,
        protocol: PinProtocol,
        shared: &[u8],
        new_pin_enc: &[u8],
    ) -> CtapResult<(SecretBytes, u8)> {
        let padded = protocol
            .decrypt(shared, new_pin_enc)
            .ok_or(status::PIN_AUTH_INVALID)?;
        if padded.len() != PADDED_PIN_LEN {
            return Err(status::INVALID_PARAMETER);
        }
        let end = padded.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        let pin = padded.get(..end).ok_or(status::INVALID_PARAMETER)?;
        if pin.len() > MAX_PIN_BYTES {
            return Err(status::PIN_POLICY_VIOLATION);
        }
        let text = core::str::from_utf8(pin).map_err(|_| status::PIN_POLICY_VIOLATION)?;
        let code_points = text.chars().count();
        if code_points < usize::from(self.state.pin.min_length) {
            return Err(status::PIN_POLICY_VIOLATION);
        }
        let code_points = u8::try_from(code_points).map_err(|_| status::PIN_POLICY_VIOLATION)?;
        Ok((pin_hash(pin), code_points))
    }

    /// setPIN (§6.5.5.5).
    fn set_pin(&mut self, req: &Request, host: &mut dyn Host) -> CtapResult<Vec<u8>> {
        let (Some(protocol), Some(peer), Some(new_pin_enc), Some(param)) = (
            req.protocol,
            &req.key_agreement,
            &req.new_pin_enc,
            &req.pin_uv_auth_param,
        ) else {
            return Err(status::MISSING_PARAMETER);
        };
        let protocol = supported_protocol(protocol)?;
        // Step 3: "If a PIN has already been set, return CTAP2_ERR_PIN_AUTH_INVALID."
        if self.state.pin_is_set() {
            return Err(status::PIN_AUTH_INVALID);
        }
        let shared = self.decapsulate(protocol, peer, host)?;
        if !protocol.verify(&shared, new_pin_enc, param) {
            return Err(status::PIN_AUTH_INVALID);
        }
        let (hash, code_points) = self.new_pin(protocol, &shared, new_pin_enc)?;
        let mut next = self.state.clone();
        next.pin.hash = Some(hash);
        next.pin.code_points = code_points;
        next.pin.retries = DEFAULT_PIN_RETRIES;
        next.pin.force_change = false;
        self.commit(next, host)?;
        self.pin.consecutive_mismatches = 0;
        Ok(vec![status::OK])
    }

    /// The checks before a PIN attempt (module documentation, steps 2-4).
    fn pin_attempt_allowed(&self) -> CtapResult<()> {
        if !self.state.pin_is_set() {
            return Err(status::PIN_NOT_SET);
        }
        if self.state.pin.retries == 0 {
            return Err(status::PIN_BLOCKED);
        }
        if self.pin.soft_blocked() {
            return Err(status::PIN_AUTH_BLOCKED);
        }
        Ok(())
    }

    /// Steps 6-8 of the module documentation: persist the decremented retry counter,
    /// then compare `pinHashEnc`. On a match, returns the state with pinRetries back at
    /// its maximum, for the caller to persist with its own changes.
    fn check_pin(
        &mut self,
        protocol: PinProtocol,
        shared: &[u8],
        pin_hash_enc: &[u8],
        host: &mut dyn Host,
    ) -> CtapResult<State> {
        let mut decremented = self.state.clone();
        decremented.pin.retries = decremented.pin.retries.saturating_sub(1);
        self.commit(decremented, host)?;

        let matches = match (protocol.decrypt(shared, pin_hash_enc), &self.state.pin.hash) {
            (Some(plaintext), Some(stored)) => plaintext.len() == 16 && ct_eq(&plaintext, stored),
            _ => false,
        };
        if !matches {
            self.pin.regenerate(protocol);
            self.pin.consecutive_mismatches = self.pin.consecutive_mismatches.saturating_add(1);
            return Err(if self.state.pin.retries == 0 {
                status::PIN_BLOCKED
            } else if self.pin.soft_blocked() {
                status::PIN_AUTH_BLOCKED
            } else {
                status::PIN_INVALID
            });
        }
        self.pin.consecutive_mismatches = 0;
        let mut next = self.state.clone();
        next.pin.retries = DEFAULT_PIN_RETRIES;
        Ok(next)
    }

    /// Persist `next` if it differs from the current state.
    fn commit_if_changed(&mut self, next: State, host: &mut dyn Host) -> CtapResult<()> {
        if next == self.state {
            Ok(())
        } else {
            self.commit(next, host)
        }
    }

    /// changePIN (§6.5.5.6). A new PIN equal to the current one is refused while
    /// forcePINChange is set; success clears forcePINChange and discards the
    /// pinUvAuthToken.
    fn change_pin(&mut self, req: &Request, host: &mut dyn Host) -> CtapResult<Vec<u8>> {
        let (Some(protocol), Some(peer), Some(pin_hash_enc), Some(new_pin_enc), Some(param)) = (
            req.protocol,
            &req.key_agreement,
            &req.pin_hash_enc,
            &req.new_pin_enc,
            &req.pin_uv_auth_param,
        ) else {
            return Err(status::MISSING_PARAMETER);
        };
        let protocol = supported_protocol(protocol)?;
        self.pin_attempt_allowed()?;
        let shared = self.decapsulate(protocol, peer, host)?;
        let signed = [new_pin_enc.as_slice(), pin_hash_enc.as_slice()].concat();
        if !protocol.verify(&shared, &signed, param) {
            return Err(status::PIN_AUTH_INVALID);
        }
        let mut next = self.check_pin(protocol, &shared, pin_hash_enc, host)?;
        let (hash, code_points) = match self.new_pin(protocol, &shared, new_pin_enc) {
            Ok(pin) => pin,
            Err(code) => {
                self.commit_if_changed(next, host)?;
                return Err(code);
            }
        };
        if next.pin.force_change
            && next
                .pin
                .hash
                .as_ref()
                .is_some_and(|stored| ct_eq(stored, &hash))
        {
            self.commit_if_changed(next, host)?;
            return Err(status::PIN_POLICY_VIOLATION);
        }
        next.pin.hash = Some(hash);
        next.pin.code_points = code_points;
        next.pin.force_change = false;
        self.commit(next, host)?;
        self.pin.token = None;
        Ok(vec![status::OK])
    }

    /// getPinToken (§6.5.5.7.1, superseded). The token has the default permissions mc and
    /// ga; `permissions` or `rpId` in the request are `CTAP1_ERR_INVALID_PARAMETER`.
    fn get_pin_token(&mut self, req: &Request, host: &mut dyn Host) -> CtapResult<Vec<u8>> {
        let (Some(protocol), Some(peer), Some(pin_hash_enc)) =
            (req.protocol, &req.key_agreement, &req.pin_hash_enc)
        else {
            return Err(status::MISSING_PARAMETER);
        };
        if req.permissions.is_some() || req.rp_id.is_some() {
            return Err(status::INVALID_PARAMETER);
        }
        let protocol = supported_protocol(protocol)?;
        self.pin_attempt_allowed()?;
        let shared = self.decapsulate(protocol, peer, host)?;
        let next = self.check_pin(protocol, &shared, pin_hash_enc, host)?;
        self.commit_if_changed(next, host)?;
        if self.state.pin.force_change {
            return Err(status::PIN_INVALID);
        }
        self.issue_token(
            protocol,
            &shared,
            permission::MC | permission::GA,
            None,
            true,
            host,
        )
    }

    /// getPinUvAuthTokenUsingPinWithPermissions (§6.5.5.7.2). `rpId` is optional; without
    /// it the token binds to the first RP it is used with for mc/ga (§6.1.2 step 11.5).
    fn get_pin_uv_auth_token_using_pin(
        &mut self,
        req: &Request,
        host: &mut dyn Host,
    ) -> CtapResult<Vec<u8>> {
        let (Some(protocol), Some(peer), Some(pin_hash_enc), Some(permissions)) = (
            req.protocol,
            &req.key_agreement,
            &req.pin_hash_enc,
            req.permissions,
        ) else {
            return Err(status::MISSING_PARAMETER);
        };
        let protocol = supported_protocol(protocol)?;
        // Step 3: "If the permissions parameter value is 0, return
        // CTAP1_ERR_INVALID_PARAMETER."
        if permissions == 0 {
            return Err(status::INVALID_PARAMETER);
        }
        // Step 4: a defined permission whose feature is absent is
        // CTAP2_ERR_UNAUTHORIZED_PERMISSION; here only bioEnrollment (GetInfo has no
        // bioEnroll). Step 14 assigns the requested permissions "ignoring undefined ones",
        // so RFU bits are dropped rather than refused.
        let permissions = u8::try_from(permissions & u64::from(permission::DEFINED))
            .map_err(|_| status::OTHER)?;
        if permissions & !permission::SUPPORTED != 0 {
            return Err(status::UNAUTHORIZED_PERMISSION);
        }
        self.pin_attempt_allowed()?;
        let shared = self.decapsulate(protocol, peer, host)?;
        let next = self.check_pin(protocol, &shared, pin_hash_enc, host)?;
        self.commit_if_changed(next, host)?;
        if self.state.pin.force_change {
            return Err(status::PIN_POLICY_VIOLATION);
        }
        self.issue_token(
            protocol,
            &shared,
            permissions,
            req.rp_id.clone(),
            false,
            host,
        )
    }

    /// `resetPinUvAuthToken()` and `beginUsingPinUvAuthToken(userIsPresent: false)`, then
    /// `{2: encrypt(shared secret, pinUvAuthToken)}` (§6.5.5.7.2 steps 12-16).
    fn issue_token(
        &mut self,
        protocol: PinProtocol,
        shared: &[u8],
        permissions: u8,
        rp_id: Option<String>,
        legacy: bool,
        host: &mut dyn Host,
    ) -> CtapResult<Vec<u8>> {
        let mut value = SecretBytes::zeroed(TOKEN_LEN);
        host.fill(&mut value);
        let encrypted = protocol.encrypt(shared, &value, host)?;
        self.pin.issued = self.pin.issued.wrapping_add(1);
        self.pin.token = Some(PinToken {
            serial: self.pin.issued,
            value,
            protocol,
            permissions,
            rp_id,
            issued: host.now(),
            used: false,
            user_verified: true,
            legacy,
        });
        Ok(ok(MapBuilder::new().insert(0x02, encrypted).build()))
    }

    /// Verify `pinUvAuthParam` over `message` with the in-use pinUvAuthToken (`verify()`,
    /// §6.5.6 / §6.5.7) and return it. A token past its usage limits is discarded first
    /// (`stopUsingPinUvAuthToken()`, §6.5.2.1). No token in use (always the case without a
    /// PIN: "If the key parameter value is the current pinUvAuthToken and it is not in use,
    /// then return error", §6.5.6 `verify()` step 1), another protocol or a wrong signature
    /// is `CTAP2_ERR_PIN_AUTH_INVALID`, the status credentialManagement (§6.8.2 to §6.8.6),
    /// largeBlobs (§6.10.2 step 5.4.1) and authenticatorConfig (§6.11 step 4.4.1) give for a
    /// failed verification.
    pub(crate) fn verified_token(
        &mut self,
        protocol: PinProtocol,
        message: &[u8],
        param: &[u8],
        now: Millis,
    ) -> CtapResult<&mut PinToken> {
        if self.pin.token.as_ref().is_some_and(|t| !t.live(now)) {
            self.pin.token = None;
        }
        let token = self.pin.token.as_mut().ok_or(status::PIN_AUTH_INVALID)?;
        if token.protocol != protocol || !protocol.verify(&token.value, message, param) {
            return Err(status::PIN_AUTH_INVALID);
        }
        token.used = true;
        Ok(token)
    }

    /// pinUvAuthParam verification for makeCredential / getAssertion (§6.1.2 step 11,
    /// §6.2.2 step 6): signature over clientDataHash, the `mc` / `ga` permission, the
    /// permissions RP ID (bound now if unbound) and the user verified flag; each failure
    /// is `CTAP2_ERR_PIN_AUTH_INVALID`. Returns the UV flag value (true).
    ///
    /// Without a PIN the answer is `CTAP2_ERR_PIN_NOT_SET` (model policy: these steps run
    /// only on an authenticator "protected by some form of user verification" and give no
    /// status for a non-empty pinUvAuthParam without a PIN, nor does CTAP 2.0 §5.1 / §5.2;
    /// answering an error fails closed instead of silently dropping the requested UV, and
    /// PIN_NOT_SET is the status §6.1.2 step 1.3 gives the zero-length probe in the same
    /// state). Commands whose steps name a status for a failed verification use
    /// [`Authenticator::verified_token`] directly.
    pub(crate) fn verify_for_rp(
        &mut self,
        protocol: Option<u64>,
        param: &[u8],
        client_data_hash: &[u8],
        needed: u8,
        rp_id: &str,
        now: Millis,
    ) -> CtapResult<bool> {
        let protocol = supported_protocol(required(protocol)?)?;
        if !self.state.pin_is_set() {
            return Err(status::PIN_NOT_SET);
        }
        let token = self.verified_token(protocol, client_data_hash, param, now)?;
        if token.permissions & needed == 0
            || token.rp_id.as_deref().is_some_and(|bound| bound != rp_id)
            || !token.user_verified
        {
            return Err(status::PIN_AUTH_INVALID);
        }
        if token.rp_id.is_none() {
            token.rp_id = Some(rp_id.to_owned());
        }
        Ok(true)
    }

    /// `clearUserPresentFlag()`, `clearUserVerifiedFlag()` and
    /// `clearPinUvAuthTokenPermissionsExceptLbw()` after a makeCredential or getAssertion
    /// collected user presence (§6.1.2 step 14, §6.2.2 step 9; "no-ops if there is not an
    /// in-use pinUvAuthToken").
    pub(crate) fn consume_token_after_presence(&mut self) {
        if let Some(token) = self.pin.token.as_mut() {
            token.user_verified = false;
            token.permissions &= permission::LBW;
            token.legacy = false;
        }
    }
}
