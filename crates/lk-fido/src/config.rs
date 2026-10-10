//! `authenticatorConfig` (CTAP 2.1 §6.11).
//!
//! Supported subcommands follow GetInfo (§6.4):
//! - toggleAlwaysUv (§6.11.2): `alwaysUv` is present in GetInfo `options` (false), which
//!   means the feature is supported and currently off;
//! - setMinPINLength (§6.11.4): `setMinPINLength` is true.
//!
//! enableEnterpriseAttestation (§6.11.1) needs the `ep` option, which GetInfo does not list,
//! and vendorPrototype (§6.11.3) needs `vendorPrototypeConfigCommands`, also absent. They and
//! unknown subcommands are `CTAP1_ERR_INVALID_PARAMETER`, checked before authorization
//! (§6.11 step 2: "If the authenticator does not support the subcommand being invoked, per
//! subCommand's value, return CTAP1_ERR_INVALID_PARAMETER").
//!
//! When a PIN is set or alwaysUv is on, every subcommand needs a pinUvAuthToken with the
//! `acfg` permission (§6.11 step 4): pinUvAuthParam absent `CTAP2_ERR_PUAT_REQUIRED`,
//! pinUvAuthProtocol absent `CTAP2_ERR_MISSING_PARAMETER` or unsupported
//! `CTAP1_ERR_INVALID_PARAMETER`, and
//! `verify(pinUvAuthToken, 32×0xff || 0x0d || uint8(subCommand) || subCommandParams)` or a
//! missing `acfg` permission `CTAP2_ERR_PIN_AUTH_INVALID`. `subCommandParams` is MACed as
//! received. The one exception (§6.11 step 3): toggleAlwaysUv on an authenticator without
//! a PIN while alwaysUv is on needs no token, so alwaysUv can always be switched off again.

use lk_codec::cbor::Value;
use lk_core::Host;

use crate::client_pin::{permission, supported_protocol};
use crate::get_info::MAX_RPIDS_FOR_SET_MIN_PIN_LENGTH;
use crate::request::{
    CtapResult, Params, array, boolean, bytes, map, required, text, uint_key, unsigned,
};
use crate::{Authenticator, status};

/// authenticatorConfig subcommands (§6.11 table).
pub(crate) mod subcommand {
    pub const ENABLE_ENTERPRISE_ATTESTATION: u64 = 0x01;
    pub const TOGGLE_ALWAYS_UV: u64 = 0x02;
    pub const SET_MIN_PIN_LENGTH: u64 = 0x03;
    pub const VENDOR_PROTOTYPE: u64 = 0xFF;
}

/// The longest PIN is 63 bytes (§6.5.1), so no minimum above 63 code points can be met;
/// such a value is refused as a policy violation (model policy).
const MAX_MIN_PIN_LENGTH: u64 = 63;

/// setMinPINLength subCommandParams (§6.11.4), type-checked.
#[derive(Debug, Default)]
struct MinPinParams {
    new_min_pin_length: Option<u64>,
    rp_ids: Option<Vec<String>>,
    force_change_pin: Option<bool>,
}

impl MinPinParams {
    fn parse(value: Option<&Value>) -> CtapResult<Self> {
        let Some(value) = value else {
            return Ok(Self::default());
        };
        let entries = map(value)?;
        let new_min_pin_length = uint_key(entries, 0x01).map(unsigned).transpose()?;
        let rp_ids = uint_key(entries, 0x02)
            .map(|v| -> CtapResult<Vec<String>> {
                array(v)?
                    .iter()
                    .map(|item| text(item).map(str::to_owned))
                    .collect()
            })
            .transpose()?;
        let force_change_pin = uint_key(entries, 0x03).map(boolean).transpose()?;
        Ok(Self {
            new_min_pin_length,
            rp_ids,
            force_change_pin,
        })
    }
}

impl Authenticator {
    pub(crate) fn config(&mut self, params: &[u8], host: &mut dyn Host) -> Vec<u8> {
        match self.config_inner(params, host) {
            Ok(()) => vec![status::OK],
            Err(code) => vec![code],
        }
    }

    fn config_inner(&mut self, params: &[u8], host: &mut dyn Host) -> CtapResult<()> {
        let p = Params::decode(params)?;
        let sub = p.get(0x01).map(unsigned).transpose()?;
        p.get(0x02).map(map).transpose()?;
        let protocol = p.get(0x03).map(unsigned).transpose()?;
        let param = p.get(0x04).map(bytes).transpose()?;
        let sub = required(sub)?;
        let min_pin = if sub == subcommand::SET_MIN_PIN_LENGTH {
            MinPinParams::parse(p.get(0x02))?
        } else {
            MinPinParams::default()
        };
        // Step 2: enableEnterpriseAttestation and vendorPrototype are not supported
        // (GetInfo has no `ep` and no `vendorPrototypeConfigCommands`), nor is anything else.
        match sub {
            subcommand::TOGGLE_ALWAYS_UV | subcommand::SET_MIN_PIN_LENGTH => {}
            subcommand::ENABLE_ENTERPRISE_ATTESTATION | subcommand::VENDOR_PROTOTYPE => {
                return Err(status::INVALID_PARAMETER);
            }
            _ => return Err(status::INVALID_PARAMETER),
        }
        // Step 3: toggleAlwaysUv, no PIN and alwaysUv on: go straight to the subcommand.
        let unprotected_toggle = sub == subcommand::TOGGLE_ALWAYS_UV
            && !self.state.pin_is_set()
            && self.state.pin.always_uv;
        // Step 4.
        if !unprotected_toggle && (self.state.pin_is_set() || self.state.pin.always_uv) {
            let param = param.ok_or(status::PUAT_REQUIRED)?;
            let protocol = supported_protocol(required(protocol)?)?;
            let mut message = vec![0xFF; 32];
            message.push(0x0D);
            message.push(u8::try_from(sub).map_err(|_| status::INVALID_SUBCOMMAND)?);
            message.extend_from_slice(p.raw(0x02).unwrap_or_default());
            let token = self.verified_token(protocol, &message, param, host.now())?;
            if token.permissions & permission::ACFG == 0 {
                return Err(status::PIN_AUTH_INVALID);
            }
        }
        if sub == subcommand::TOGGLE_ALWAYS_UV {
            // §6.11.2: flip the alwaysUv option.
            let mut next = self.state.clone();
            next.pin.always_uv = !next.pin.always_uv;
            return self.commit(next, host);
        }
        self.set_min_pin_length(min_pin, host)
    }

    /// setMinPINLength (§6.11.4), checks in the step order of §6.11.4:
    /// - newMinPINLength absent means the current minimum; below the current minimum is
    ///   `CTAP2_ERR_PIN_POLICY_VIOLATION`, and so is a minimum above 63 that no PIN can meet
    ///   (model policy, §6.5.1: at most 63 bytes);
    /// - forceChangePin without a PIN is `CTAP2_ERR_PIN_NOT_SET` (step 4.1); forceChangePin,
    ///   or a new minimum above the current PIN's length, sets forcePINChange;
    /// - minPinLengthRPIDs replaces the stored list when it has entries; absent or empty,
    ///   the previous list is kept (step 7 "present and contains at least one string";
    ///   `reference/BEHAVIOR_CATALOG.md` FIDO: "empty minPinLengthRPIDs preserves previous
    ///   allowlist while updating supplied minPinLength"). More than
    ///   maxRPIDsForSetMinPINLength (1) entries cannot be stored: `CTAP2_ERR_KEY_STORE_FULL`
    ///   (step 7.3, "If the authenticator cannot store or add the minPinLengthRPIDs, it
    ///   returns CTAP2_ERR_KEY_STORE_FULL"). Nothing is changed by a failing request.
    fn set_min_pin_length(&mut self, params: MinPinParams, host: &mut dyn Host) -> CtapResult<()> {
        let current = u64::from(self.state.pin.min_length);
        let new_min = params.new_min_pin_length.unwrap_or(current);
        if new_min < current || new_min > MAX_MIN_PIN_LENGTH {
            return Err(status::PIN_POLICY_VIOLATION);
        }
        let new_min = u8::try_from(new_min).map_err(|_| status::PIN_POLICY_VIOLATION)?;
        let force = params.force_change_pin.unwrap_or(false);
        if force && !self.state.pin_is_set() {
            return Err(status::PIN_NOT_SET);
        }
        if params
            .rp_ids
            .as_ref()
            .is_some_and(|ids| ids.len() > MAX_RPIDS_FOR_SET_MIN_PIN_LENGTH)
        {
            return Err(status::KEY_STORE_FULL);
        }
        let mut next = self.state.clone();
        next.pin.min_length = new_min;
        if let Some(ids) = params.rp_ids.filter(|ids| !ids.is_empty()) {
            next.pin.min_pin_rp_ids = ids;
        }
        if force || (next.pin_is_set() && new_min > next.pin.code_points) {
            next.pin.force_change = true;
        }
        self.commit(next, host)
    }
}
