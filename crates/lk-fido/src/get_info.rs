//! `authenticatorGetInfo` (CTAP 2.1 §6.4).
//!
//! With `DeviceProfile::yubikey_compat` the response carries exactly the keys
//! {1..16, 20} and the values of `reference/physical-key/reference-observation.json`.
//! Two values follow this device's state rather than the observed key: `clientPin` is
//! false until a PIN is set (the observed key had one), and
//! `remainingDiscoverableCredentials` is 100 minus the stored discoverable credentials
//! (the observed key held one, so it reported 99).

use lk_codec::cbor::{MapBuilder, Value};
use lk_core::DeviceProfile;

use crate::credential::Alg;
use crate::request::{MAX_CREDENTIAL_COUNT_IN_LIST, PUBLIC_KEY};
use crate::state::State;

/// `maxMsgSize` (key 5): the largest CTAP message accepted, command byte included.
pub(crate) const MAX_MSG_SIZE: usize = 1536;
/// `maxCredentialIdLength` (key 8).
pub(crate) const MAX_CREDENTIAL_ID_LENGTH: usize = 128;
/// `maxSerializedLargeBlobArray` (key 11).
pub(crate) const MAX_SERIALIZED_LARGE_BLOB_ARRAY: usize = 4096;
/// `maxCredBlobLength` (key 15).
pub(crate) const MAX_CRED_BLOB_LENGTH: usize = 32;
/// `maxRPIDsForSetMinPINLength` (key 16).
pub(crate) const MAX_RPIDS_FOR_SET_MIN_PIN_LENGTH: usize = 1;
/// Discoverable credential capacity: `remainingDiscoverableCredentials` (key 20) of an
/// empty device (`reference/legacy-v0.64-profiles.json` `discoverable_capacity`).
pub(crate) const DISCOVERABLE_CAPACITY: usize = 100;

/// `versions` (key 1). While alwaysUv is on, "U2F_V2" is left out: "Authenticators MUST
/// disable CTAP1/U2F when the alwaysUv option ID is present and true ... unless the
/// CTAP1/U2F authenticator is protected by a built-in user verification method" (none
/// here), and then "The authenticator MUST NOT return "U2F_V2" in the versions array"
/// (CTAP 2.1 §7.2.4; §7.2.3 offers the same choice).
const VERSIONS: [&str; 4] = ["U2F_V2", "FIDO_2_0", "FIDO_2_1_PRE", "FIDO_2_1"];
/// `extensions` (key 2), in the observed order.
const EXTENSIONS: [&str; 5] = [
    "credProtect",
    "hmac-secret",
    "largeBlobKey",
    "credBlob",
    "minPinLength",
];

/// The GetInfo response map (CTAP 2.1 §6.4, keys 0x01..0x10 and 0x14).
pub(crate) fn get_info(state: &State, profile: &DeviceProfile) -> Value {
    let text_array = |items: &[&str]| Value::Array(items.iter().map(|s| Value::from(*s)).collect());
    // §6.4 "options". `makeCredUvNotRqd` reads false while `alwaysUv` is on: "If the
    // alwaysUv option ID is present and true the authenticator MUST set the value of
    // makeCredUvNotRqd to false" (§6.4 options table, alwaysUv; §6.1.2 step 6.1 "Let the
    // makeCredUvNotRqd option ID be treated as false").
    let options = MapBuilder::new()
        .insert("rk", true)
        .insert("up", true)
        .insert("plat", false)
        .insert("alwaysUv", state.pin.always_uv)
        .insert("credMgmt", true)
        .insert("authnrCfg", true)
        .insert("clientPin", state.pin_is_set())
        .insert("largeBlobs", true)
        .insert("pinUvAuthToken", true)
        .insert("setMinPINLength", true)
        .insert("makeCredUvNotRqd", !state.pin.always_uv)
        .insert("credentialMgmtPreview", true)
        .build();
    let algorithms = Value::Array(
        Alg::ALL
            .iter()
            .map(|alg| {
                MapBuilder::new()
                    .insert("alg", alg.cose())
                    .insert("type", PUBLIC_KEY)
                    .build()
            })
            .collect(),
    );
    let remaining = DISCOVERABLE_CAPACITY.saturating_sub(state.residents.len());
    let versions = if state.pin.always_uv {
        VERSIONS.get(1..).unwrap_or_default()
    } else {
        &VERSIONS[..]
    };
    MapBuilder::new()
        .insert(0x01, text_array(versions))
        .insert(0x02, text_array(&EXTENSIONS))
        .insert(0x03, profile.aaguid.to_vec())
        .insert(0x04, options)
        .insert(0x05, MAX_MSG_SIZE)
        .insert(0x06, Value::Array(vec![Value::from(2u8), Value::from(1u8)]))
        .insert(0x07, MAX_CREDENTIAL_COUNT_IN_LIST)
        .insert(0x08, MAX_CREDENTIAL_ID_LENGTH)
        .insert(0x09, text_array(&["usb"]))
        .insert(0x0A, algorithms)
        .insert(0x0B, MAX_SERIALIZED_LARGE_BLOB_ARRAY)
        .insert(0x0C, state.pin.force_change)
        .insert(0x0D, state.pin.min_length)
        .insert(0x0E, profile.firmware.as_u32())
        .insert(0x0F, MAX_CRED_BLOB_LENGTH)
        .insert(0x10, MAX_RPIDS_FOR_SET_MIN_PIN_LENGTH)
        .insert(0x14, remaining)
        .build()
}
