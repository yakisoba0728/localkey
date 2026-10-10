//! End-to-end FIDO scenarios: a platform written from CTAP 2.1 and the U2F raw message
//! specification drives the device through 64-byte CTAPHID reports, touches and timer
//! ticks at explicit times, and verifies every signature it receives.

#![allow(clippy::unwrap_used)]

mod common;

use common::ctap::{self, PinAuth, PinProtocol2, cmd, perm, status};
use common::json::{self, Json};
use common::*;
use lk_codec::cbor::{self, MapBuilder, Value};
use lk_crypto::sha256;
use lk_device::{BusEvent, Output};
use lk_testkit::SeededEntropy;

const RP: &str = "example.com";
const REFERENCE: &str = include_str!("../../../reference/yubikey-5c-nano-5.7.4/reference-observation.json");

fn cdh(label: &str) -> [u8; 32] {
    sha256(label.as_bytes())
}

/// The platform's own randomness for key agreement (any source works; fixed for
/// reproducibility).
fn platform_entropy() -> SeededEntropy {
    SeededEntropy::new(0x00C1_1E47)
}

fn get_info(rig: &mut Rig, cid: u32) -> Value {
    let bytes = rig.cbor(cid, &ctap::request(cmd::GET_INFO, None));
    assert_eq!(bytes[0], status::OK);
    let value = cbor::decode(&bytes[1..]).unwrap();
    // CTAP 2.1 §8: the authenticator's CBOR is canonical, so re-encoding is the identity.
    assert_eq!(cbor::encode(&value), bytes[1..].to_vec(), "canonical CBOR");
    value
}

/// A key agreement with the device (getKeyAgreement, CTAP 2.1 §6.5.5.4).
fn agree(rig: &mut Rig, cid: u32, entropy: &mut SeededEntropy) -> PinProtocol2 {
    let response = rig.cbor(cid, &PinProtocol2::key_agreement_request());
    PinProtocol2::from_key_agreement(&response, entropy)
}

fn set_pin(rig: &mut Rig, cid: u32, pin: &str, entropy: &mut SeededEntropy) {
    let pp = agree(rig, cid, entropy);
    assert_eq!(rig.cbor(cid, &pp.set_pin(pin)), vec![status::OK], "setPIN");
}

fn token(rig: &mut Rig, cid: u32, pin: &str, permissions: u8, rp_id: Option<&str>, entropy: &mut SeededEntropy) -> Vec<u8> {
    let pp = agree(rig, cid, entropy);
    let response = rig.cbor(cid, &pp.token_request(pin, permissions, rp_id));
    pp.token(&response)
}

fn pin_retries(rig: &mut Rig, cid: u32) -> u64 {
    let value = ctap::ok_value(&rig.cbor(cid, &ctap::pin_retries_request()));
    ctap::get(&value, 3).as_u64().unwrap()
}

/// The JSON value as CBOR: integers, text, booleans, arrays and objects (as canonical
/// maps with text keys).
fn json_to_cbor(json: &Json) -> Value {
    match json {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(*b),
        Json::Int(n) => Value::from(*n),
        Json::Str(s) => Value::from(s.as_str()),
        Json::Arr(items) => Value::Array(items.iter().map(json_to_cbor).collect()),
        Json::Obj(members) => {
            let mut map = MapBuilder::new();
            for (key, value) in members {
                map.set(key.as_str(), json_to_cbor(value));
            }
            map.build()
        }
    }
}

/// The GetInfo map the reference device returned, rebuilt from
/// `reference-observation.json` with the CTAP 2.1 §6.4 member keys.
fn reference_get_info() -> (Value, Vec<i64>) {
    let observation = json::parse(REFERENCE);
    let reference = observation.get("reference");
    let fields = reference.get("get_info_fields");
    let keys: [(i64, &str); 17] = [
        (0x01, "versions"),
        (0x02, "extensions"),
        (0x03, "aaguid"),
        (0x04, "options"),
        (0x05, "max_msg_size"),
        (0x06, "pin_uv_protocols"),
        (0x07, "max_creds_in_list"),
        (0x08, "max_cred_id_length"),
        (0x09, "transports"),
        (0x0A, "algorithms"),
        (0x0B, "max_large_blob"),
        (0x0C, "force_pin_change"),
        (0x0D, "min_pin_length"),
        (0x0E, "firmware_version"),
        (0x0F, "max_cred_blob_length"),
        (0x10, "max_rpids_for_min_pin"),
        (0x14, "remaining_disc_creds"),
    ];
    let mut map = MapBuilder::new();
    for (key, name) in keys {
        let value = match name {
            "aaguid" => Value::Bytes(hex(fields.get(name).as_str())),
            _ => json_to_cbor(fields.get(name)),
        };
        map.set(key, value);
    }
    assert_eq!(fields.as_object().len(), keys.len(), "every observed field is mapped");
    let present = reference.get("present_cbor_keys").as_array().iter().map(Json::as_i64).collect();
    (map.build(), present)
}

/// Replace one member of a CBOR map.
fn with_member(map: &Value, key: Value, value: Value) -> Value {
    let mut builder = MapBuilder::new();
    for (k, v) in map.as_map().unwrap() {
        builder.set(k.clone(), if *k == key { value.clone() } else { v.clone() });
    }
    builder.build()
}

/// `reference/yubikey-5c-nano-5.7.4/reference-observation.json` (CTAPHID_INIT then
/// authenticatorGetInfo on the physical key) under
/// `DeviceProfile::yubikey_5c_nano_5_7_4`: the device answers with exactly the observed
/// member keys, and once it is in the observed key's state (a PIN set, one discoverable
/// credential stored: `clientPin` true, `remainingDiscoverableCredentials` 99, the two
/// state-dependent values lk-fido documents) the canonical encodings are byte-identical.
/// A factory device differs in exactly those two members.
#[test]
fn get_info_equals_the_reference_observation() {
    let (reference, present) = reference_get_info();
    let mut rig = Rig::new();
    // CTAPHID_INIT (CTAP 2.1 §11.2.9.1.3): nonce, new channel, protocol version 2, the
    // profile's firmware 5.7.4 and CAPABILITY_WINK | CAPABILITY_CBOR.
    let nonce = [0xA5, 0x5A, 1, 2, 3, 4, 5, 6];
    let (command, payload) = responses(&rig.ctaphid_send(BROADCAST, CTAPHID_INIT, &nonce)).remove(0);
    assert_eq!((command, payload.len()), (CTAPHID_INIT, 17));
    assert_eq!(&payload[..8], &nonce);
    assert_ne!(&payload[8..12], &[0xFF; 4], "a real channel");
    assert_eq!(&payload[12..], &[2, 5, 7, 4, 0x05]);
    let cid = u32::from_be_bytes(payload[8..12].try_into().unwrap());

    let factory = get_info(&mut rig, cid);
    let keys: Vec<i64> = factory.as_map().unwrap().iter().map(|(k, _)| k.as_i64().unwrap()).collect();
    assert_eq!(keys, present, "present_cbor_keys");
    let options = ctap::get(&reference, 4);
    let factory_options = with_member(options, Value::from("clientPin"), Value::Bool(false));
    let expected = with_member(&with_member(&reference, Value::from(4), factory_options), Value::from(0x14), Value::from(100u8));
    assert_eq!(cbor::encode(&factory), cbor::encode(&expected), "factory GetInfo");

    let mut entropy = platform_entropy();
    set_pin(&mut rig, cid, "4321", &mut entropy);
    let token = token(&mut rig, cid, "4321", perm::MC, Some(RP), &mut entropy);
    let request = ctap::make_credential(&cdh("reference"), RP, b"user-1", true, &PinAuth::Token(token));
    let (response, _) = rig.cbor_touch(cid, &request, 200);
    assert_eq!(response[0], status::OK);

    let info = get_info(&mut rig, cid);
    assert_eq!(cbor::encode(&info), cbor::encode(&reference), "GetInfo in the observed state");
}

/// CTAP 2.1 §6.1 with §11.2.9.1.7: MakeCredential waits for user presence, sending
/// KEEPALIVE(STATUS_UPNEEDED) at once and every 100 ms until Touch(Down); the packed
/// attestation (WebAuthn L2 §8.2) verifies under the x5c certificate's key; then
/// GetAssertion (§6.2) waits the same way and its signature verifies under the new
/// credential's public key, with a growing signature counter (WebAuthn L2 §6.1.1).
#[test]
fn make_credential_and_get_assertion_with_touch_verify() {
    let mut rig = Rig::with_profile(lk_core::DeviceProfile::yubikey_5c_nano_5_7_4(SERIAL));
    let cid = rig.ctaphid_init();
    rig.now = 1_000;
    let mc_hash = cdh("make-credential");
    let request = ctap::make_credential(&mc_hash, RP, b"user-1", false, &PinAuth::None);
    let (response, keepalive_times) = rig.cbor_touch(cid, &request, 1_000);
    let expected: Vec<u64> = (0..=10).map(|i| 1_000 + 100 * i).collect();
    assert_eq!(keepalive_times, expected, "KEEPALIVE cadence");

    let attestation = ctap::ok_value(&response);
    assert_eq!(ctap::get(&attestation, 1).as_text(), Some("packed"));
    let auth_data_bytes = ctap::get(&attestation, 2).as_bytes().unwrap().to_vec();
    let auth_data = ctap::parse_auth_data(&auth_data_bytes);
    assert_eq!(auth_data.rp_id_hash, sha256(RP.as_bytes()));
    assert_eq!(auth_data.flags, ctap::flag::UP | ctap::flag::AT, "UP and AT, no UV without a PIN");
    let credential = auth_data.credential.clone().unwrap();
    assert_eq!(credential.aaguid, rig.profile.aaguid);
    let statement = ctap::get(&attestation, 3);
    assert_eq!(statement.map_get_text("alg").and_then(Value::as_i64), Some(-7));
    let signature = statement.map_get_text("sig").and_then(Value::as_bytes).unwrap();
    let x5c = statement.map_get_text("x5c").and_then(Value::as_array).unwrap();
    let attestation_key = der::certificate_ec_public_key(x5c[0].as_bytes().unwrap());
    assert!(ctap::verify_es256(&attestation_key, &auth_data_bytes, &mc_hash, signature), "attestation signature");

    let mut last_count = auth_data.sign_count;
    for round in 0..2 {
        let ga_hash = cdh(&format!("get-assertion-{round}"));
        let request = ctap::get_assertion(&ga_hash, RP, std::slice::from_ref(&credential.id), &PinAuth::None);
        let (response, _) = rig.cbor_touch(cid, &request, 250);
        let assertion = ctap::ok_value(&response);
        let used = ctap::get(&assertion, 1);
        assert_eq!(used.map_get_text("id").and_then(Value::as_bytes), Some(credential.id.as_slice()));
        let data = ctap::get(&assertion, 2).as_bytes().unwrap();
        let parsed = ctap::parse_auth_data(data);
        assert_eq!(parsed.flags, ctap::flag::UP);
        assert!(parsed.sign_count > last_count, "signature counter grows");
        last_count = parsed.sign_count;
        let signature = ctap::get(&assertion, 3).as_bytes().unwrap();
        assert!(ctap::verify_es256(&credential.public_key, data, &ga_hash, signature), "assertion signature");
        // A signature over other client data does not verify (the check is not vacuous).
        assert!(!ctap::verify_es256(&credential.public_key, data, &cdh("other"), signature));
    }
}

/// CTAP 2.1 §11.2.9.1.5: CTAPHID_CANCEL during a pending MakeCredential answers
/// CTAP2_ERR_KEEPALIVE_CANCEL; no credential is created (GetInfo
/// remainingDiscoverableCredentials stays 100) and a later touch sends nothing.
#[test]
fn cancel_during_pending_make_credential() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    let request = ctap::make_credential(&cdh("cancel"), RP, b"user-1", true, &PinAuth::None);
    let out = rig.ctaphid_send(cid, CTAPHID_CBOR, &request);
    assert_eq!(keepalives(&out), vec![2]);
    rig.run_until(rig.now + 350);
    let out = rig.ctaphid_send(cid, CTAPHID_CANCEL, &[]);
    assert_eq!(responses(&out), vec![(CTAPHID_CBOR, vec![status::KEEPALIVE_CANCEL])]);
    assert_eq!(indicators(&out), vec![false]);
    assert!(rig.run_until(rig.now + 500).is_empty(), "no keepalives after the cancel");
    assert!(rig.tap().iter().all(|o| !matches!(o, Output::FidoReport(_))));
    let info = get_info(&mut rig, cid);
    assert_eq!(ctap::get(&info, 0x14).as_u64(), Some(100));
}

/// CTAP 2.1 §11.2.9.1.3 / catalog FIDO "Allocated CTAPHID INIT now discards late replies
/// from an aborted same-CID operation": INIT on the busy channel resynchronises it,
/// aborts the pending MakeCredential without a reply, and nothing is created.
#[test]
fn init_resync_aborts_pending_make_credential() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    let request = ctap::make_credential(&cdh("resync"), RP, b"user-1", true, &PinAuth::None);
    rig.ctaphid_send(cid, CTAPHID_CBOR, &request);
    rig.run_until(rig.now + 220);
    let nonce = [7u8; 8];
    let out = rig.ctaphid_send(cid, CTAPHID_INIT, &nonce);
    let messages = responses(&out);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].0, CTAPHID_INIT);
    assert_eq!(&messages[0].1[..8], &nonce);
    assert_eq!(&messages[0].1[8..12], &cid.to_be_bytes(), "same channel");
    assert_eq!(indicators(&out), vec![false]);
    assert!(rig.run_until(rig.now + 300).is_empty(), "no keepalives for the aborted request");
    assert!(rig.tap().iter().all(|o| !matches!(o, Output::FidoReport(_))), "no late reply");
    let info = get_info(&mut rig, cid);
    assert_eq!(ctap::get(&info, 0x14).as_u64(), Some(100));
}

/// CTAP 2.1 §11.2.9.1.2 / catalog FIDO "A concurrent CTAPHID CBOR operation reserves the
/// device for its CID: PING, WINK and INIT on another or broadcast CID return
/// CHANNEL_BUSY": while a MakeCredential waits on one channel, a second channel's PING
/// and CBOR get ERR_CHANNEL_BUSY; after the touch both channels work.
#[test]
fn other_channel_is_busy_while_make_credential_waits() {
    let mut rig = Rig::new();
    let first = rig.ctaphid_init();
    let second = rig.ctaphid_init();
    let request = ctap::make_credential(&cdh("busy"), RP, b"user-1", false, &PinAuth::None);
    rig.ctaphid_send(first, CTAPHID_CBOR, &request);
    assert_eq!(rig.ctaphid(second, CTAPHID_PING, b"ping"), (CTAPHID_ERROR, vec![0x06]));
    assert_eq!(rig.ctaphid(second, CTAPHID_CBOR, &[cmd::GET_INFO]), (CTAPHID_ERROR, vec![0x06]));
    let out = rig.tap();
    let messages = responses(&out);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].0, CTAPHID_CBOR);
    assert_eq!(messages[0].1[0], status::OK);
    assert_eq!(rig.ctaphid(second, CTAPHID_PING, b"ping"), (CTAPHID_PING, b"ping".to_vec()));
    assert_eq!(get_info(&mut rig, first).as_map().unwrap().len(), 17);
}

/// lk-fido `TOUCH_TIMEOUT_MS` (30 s) with CTAP 2.1 §6.1.2 step 14 ("If the user declines
/// permission, or the operation times out, then end the operation by returning
/// CTAP2_ERR_OPERATION_DENIED"): without a touch the MakeCredential ends exactly when the
/// timeout passes, after a KEEPALIVE every 100 ms; a touch afterwards does nothing.
#[test]
fn make_credential_presence_timeout() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    let start = rig.now;
    let request = ctap::make_credential(&cdh("timeout"), RP, b"user-1", false, &PinAuth::None);
    rig.ctaphid_send(cid, CTAPHID_CBOR, &request);
    let timed = rig.run_until(start + 31_000);
    let mut keepalive_times = Vec::new();
    let mut answer = None;
    for (at, output) in &timed {
        for (command, payload) in parse_fido(std::slice::from_ref(output)) {
            if command == CTAPHID_KEEPALIVE {
                assert!(answer.is_none(), "keepalive after the answer");
                keepalive_times.push(*at);
            } else {
                answer = Some((*at, command, payload));
            }
        }
    }
    assert_eq!(answer, Some((start + 30_000, CTAPHID_CBOR, vec![status::OPERATION_DENIED])));
    // One every 100 ms after the immediate one; at 30 000 ms the keepalive timer fires
    // just before the timeout (`presence.rs`: equal times fire in `Timer` order).
    let expected: Vec<u64> = (1..=300).map(|i| start + 100 * i).collect();
    assert_eq!(keepalive_times, expected);
    assert!(rig.tap().iter().all(|o| !matches!(o, Output::FidoReport(_))));
}

/// CTAP 2.1 §6.5.5 with PIN/UV auth protocol 2 (§6.5.7): setPIN, a second setPIN refused,
/// getPinUvAuthTokenUsingPinWithPermissions with a wrong PIN (retries 8 → 7) and the right
/// one (back to 8), a too-short PIN refused, a discoverable MakeCredential without a token
/// refused (§6.1.2 step 6, PUAT_REQUIRED) and with one accepted (UV flag), changePIN,
/// and the old token and PIN rejected afterwards (§6.5.5.6: changing the PIN resets
/// every token).
#[test]
fn pin_set_change_and_token_flows() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    let mut entropy = platform_entropy();
    assert_eq!(pin_retries(&mut rig, cid), 8);

    let pp = agree(&mut rig, cid, &mut entropy);
    assert_eq!(rig.cbor(cid, &pp.set_pin("12")), vec![status::PIN_POLICY_VIOLATION], "minPINLength 4");
    set_pin(&mut rig, cid, "123456", &mut entropy);
    let pp = agree(&mut rig, cid, &mut entropy);
    assert_eq!(rig.cbor(cid, &pp.set_pin("999999")), vec![status::PIN_AUTH_INVALID], "already set");

    let pp = agree(&mut rig, cid, &mut entropy);
    assert_eq!(rig.cbor(cid, &pp.token_request("000000", perm::MC, Some(RP))), vec![status::PIN_INVALID]);
    assert_eq!(pin_retries(&mut rig, cid), 7);
    let old_token = token(&mut rig, cid, "123456", perm::MC, Some(RP), &mut entropy);
    assert_eq!(pin_retries(&mut rig, cid), 8);

    let request = ctap::make_credential(&cdh("rk"), RP, b"user-1", true, &PinAuth::None);
    assert_eq!(rig.cbor(cid, &request), vec![status::PUAT_REQUIRED]);
    let request = ctap::make_credential(&cdh("rk"), RP, b"user-1", true, &PinAuth::Token(old_token.clone()));
    let (response, _) = rig.cbor_touch(cid, &request, 100);
    let attestation = ctap::ok_value(&response);
    let auth_data = ctap::parse_auth_data(ctap::get(&attestation, 2).as_bytes().unwrap());
    assert_eq!(auth_data.flags, ctap::flag::UP | ctap::flag::UV | ctap::flag::AT);

    let pp = agree(&mut rig, cid, &mut entropy);
    assert_eq!(rig.cbor(cid, &pp.change_pin("123456", "654321")), vec![status::OK], "changePIN");
    let request = ctap::make_credential(&cdh("rk2"), RP, b"user-2", true, &PinAuth::Token(old_token));
    assert_eq!(rig.cbor(cid, &request), vec![status::PIN_AUTH_INVALID], "tokens die with the PIN change");
    let pp = agree(&mut rig, cid, &mut entropy);
    assert_eq!(rig.cbor(cid, &pp.token_request("123456", perm::MC, Some(RP))), vec![status::PIN_INVALID]);
    let new_token = token(&mut rig, cid, "654321", perm::MC, Some(RP), &mut entropy);
    let request = ctap::make_credential(&cdh("rk2"), RP, b"user-2", true, &PinAuth::Token(new_token));
    let (response, _) = rig.cbor_touch(cid, &request, 100);
    assert_eq!(response[0], status::OK);
    let info = get_info(&mut rig, cid);
    assert_eq!(ctap::get(&info, 4).map_get_text("clientPin").and_then(Value::as_bool), Some(true));
    assert_eq!(ctap::get(&info, 0x14).as_u64(), Some(98));
}

/// CTAP 2.1 §6.8 credential management with a `cm` token: metadata, RP enumeration,
/// credential enumeration per RP (with the stored public key), deletion, and the deleted
/// credential no longer usable for GetAssertion (§6.2.2: CTAP2_ERR_NO_CREDENTIALS).
#[test]
fn credential_management_enumerates_and_deletes() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    let mut entropy = platform_entropy();
    set_pin(&mut rig, cid, "2468", &mut entropy);
    let mut made = Vec::new();
    for (rp, user) in [("a.example", &b"alice"[..]), ("a.example", b"bob"), ("b.example", b"carol")] {
        let token = token(&mut rig, cid, "2468", perm::MC, Some(rp), &mut entropy);
        let request = ctap::make_credential(&cdh(rp), rp, user, true, &PinAuth::Token(token));
        let (response, _) = rig.cbor_touch(cid, &request, 100);
        let attestation = ctap::ok_value(&response);
        let auth_data = ctap::parse_auth_data(ctap::get(&attestation, 2).as_bytes().unwrap());
        made.push((rp, user.to_vec(), auth_data.credential.unwrap()));
    }

    let cm = token(&mut rig, cid, "2468", perm::CM, None, &mut entropy);
    let metadata = ctap::ok_value(&rig.cbor(cid, &ctap::cred_mgmt(0x01, None, Some(&cm))));
    assert_eq!(ctap::get(&metadata, 1).as_u64(), Some(3));
    assert_eq!(ctap::get(&metadata, 2).as_u64(), Some(97));

    let first = ctap::ok_value(&rig.cbor(cid, &ctap::cred_mgmt(0x02, None, Some(&cm))));
    assert_eq!(ctap::get(&first, 5).as_u64(), Some(2), "totalRPs");
    let next = ctap::ok_value(&rig.cbor(cid, &ctap::cred_mgmt(0x03, None, None)));
    let mut rp_ids: Vec<String> = [&first, &next]
        .iter()
        .map(|v| ctap::get(v, 3).map_get_text("id").and_then(Value::as_text).unwrap().to_string())
        .collect();
    for v in [&first, &next] {
        let id = ctap::get(v, 3).map_get_text("id").and_then(Value::as_text).unwrap();
        assert_eq!(ctap::get(v, 4).as_bytes(), Some(&sha256(id.as_bytes())[..]), "rpIDHash");
    }
    rp_ids.sort();
    assert_eq!(rp_ids, ["a.example", "b.example"]);

    let params = MapBuilder::new().insert(1, sha256(b"a.example").to_vec()).build();
    let begin = ctap::ok_value(&rig.cbor(cid, &ctap::cred_mgmt(0x04, Some(params), Some(&cm))));
    assert_eq!(ctap::get(&begin, 9).as_u64(), Some(2), "totalCredentials");
    let next = ctap::ok_value(&rig.cbor(cid, &ctap::cred_mgmt(0x05, None, None)));
    for entry in [&begin, &next] {
        let id = ctap::get(entry, 7).map_get_text("id").and_then(Value::as_bytes).unwrap();
        let (_, user, credential) = made.iter().find(|(_, _, c)| c.id == id).expect("a credential the platform made");
        assert_eq!(ctap::get(entry, 6).map_get_text("id").and_then(Value::as_bytes), Some(user.as_slice()));
        assert_eq!(ctap::cose_p256_point(ctap::get(entry, 8)), credential.public_key);
    }

    let carol = made[2].2.id.clone();
    let params = MapBuilder::new().insert(2, ctap::descriptor(&carol)).build();
    assert_eq!(rig.cbor(cid, &ctap::cred_mgmt(0x06, Some(params), Some(&cm))), vec![status::OK]);
    let metadata = ctap::ok_value(&rig.cbor(cid, &ctap::cred_mgmt(0x01, None, Some(&cm))));
    assert_eq!(ctap::get(&metadata, 1).as_u64(), Some(2));
    let request = ctap::get_assertion(&cdh("gone"), "b.example", &[carol], &PinAuth::None);
    let out = rig.ctaphid_send(cid, CTAPHID_CBOR, &request);
    let mut answer = responses(&out);
    if answer.is_empty() {
        answer = responses(&rig.tap());
    }
    assert_eq!(answer, vec![(CTAPHID_CBOR, vec![status::NO_CREDENTIALS])]);
}

/// U2F raw messages v1.2 over CTAPHID_MSG (CTAP 2.1 §11.2.9.1.1) with the device's
/// touch latch (`docs/CONTRACTS.md` U2F presence): REGISTER answers `6985` until a touch,
/// then registers (§4.3, attestation signature verified with the certificate key);
/// check-only AUTHENTICATE answers `6985` for its own key handle (§5.1) without asking
/// for a touch; enforce-presence AUTHENTICATE needs a fresh touch and its signature
/// verifies (§5.4, presence byte 1, counter growing); dont-enforce signs without a
/// touch (presence byte 0); a key handle for another application is `6A80`.
#[test]
fn u2f_register_and_authenticate_with_the_touch_latch() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    let challenge = sha256(b"u2f challenge");
    let application = sha256(b"https://u2f.example");

    let (command, response) = rig.ctaphid(cid, CTAPHID_MSG, &ctap::u2f_register(&challenge, &application));
    assert_eq!((command, response), (CTAPHID_MSG, vec![0x69, 0x85]));
    assert!(rig.dev.presence_pending(), "the device asks for a touch");
    let out = rig.tap();
    assert_eq!(indicators(&out), vec![false]);
    let (_, response) = rig.ctaphid(cid, CTAPHID_MSG, &ctap::u2f_register(&challenge, &application));
    let registration = ctap::parse_u2f_registration(&response);
    assert!(registration.verify(&challenge, &application), "registration signature");
    assert!(!registration.verify(&sha256(b"other"), &application));

    let kh = registration.key_handle.clone();
    let (_, response) = rig.ctaphid(cid, CTAPHID_MSG, &ctap::u2f_authenticate(0x07, &challenge, &application, &kh));
    assert_eq!(response, vec![0x69, 0x85], "check-only: a key handle of this device");
    assert!(!rig.dev.presence_pending(), "check-only asks for no touch");

    let auth = ctap::u2f_authenticate(0x03, &challenge, &application, &kh);
    let (_, response) = rig.ctaphid(cid, CTAPHID_MSG, &auth);
    assert_eq!(response, vec![0x69, 0x85], "no latched touch");
    rig.tap();
    let (_, response) = rig.ctaphid(cid, CTAPHID_MSG, &auth);
    let (presence, first) = ctap::verify_u2f_authentication(&response, &registration.public_key, &challenge, &application);
    assert_eq!(presence, 0x01);
    let (_, response) = rig.ctaphid(cid, CTAPHID_MSG, &auth);
    assert_eq!(response, vec![0x69, 0x85], "the latch was consumed");

    let silent = ctap::u2f_authenticate(0x08, &challenge, &application, &kh);
    let (_, response) = rig.ctaphid(cid, CTAPHID_MSG, &silent);
    let (presence, second) = ctap::verify_u2f_authentication(&response, &registration.public_key, &challenge, &application);
    assert_eq!(presence, 0x00);
    assert!(second > first, "counter grows");

    let other = sha256(b"https://other.example");
    let (_, response) = rig.ctaphid(cid, CTAPHID_MSG, &ctap::u2f_authenticate(0x03, &challenge, &other, &kh));
    assert_eq!(response, vec![0x6A, 0x80]);
}

/// CTAP 2.1 §6.6: authenticatorReset within 10 s of power-up waits for a touch and
/// erases the PIN and the credentials; after the window it is CTAP2_ERR_NOT_ALLOWED at
/// once; `BusEvent::PowerCycle` is a new power-up that opens a new window.
#[test]
fn reset_within_and_after_the_power_up_window() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    let mut entropy = platform_entropy();
    set_pin(&mut rig, cid, "1357", &mut entropy);
    let token = token(&mut rig, cid, "1357", perm::MC, Some(RP), &mut entropy);
    let request = ctap::make_credential(&cdh("before reset"), RP, b"user-1", true, &PinAuth::Token(token));
    rig.cbor_touch(cid, &request, 100);
    let info = get_info(&mut rig, cid);
    assert_eq!(ctap::get(&info, 0x14).as_u64(), Some(99));

    rig.now = 9_000;
    let (response, _) = rig.cbor_touch(cid, &ctap::request(cmd::RESET, None), 300);
    assert_eq!(response, vec![status::OK], "reset inside the window");
    let info = get_info(&mut rig, cid);
    assert_eq!(ctap::get(&info, 4).map_get_text("clientPin").and_then(Value::as_bool), Some(false));
    assert_eq!(ctap::get(&info, 0x14).as_u64(), Some(100));

    rig.now = 10_500;
    assert_eq!(rig.cbor(cid, &ctap::request(cmd::RESET, None)), vec![status::NOT_ALLOWED], "window closed");

    rig.now = 60_000;
    rig.bus(BusEvent::PowerCycle);
    let cid = rig.ctaphid_init();
    rig.now = 65_000;
    let (response, _) = rig.cbor_touch(cid, &ctap::request(cmd::RESET, None), 100);
    assert_eq!(response, vec![status::OK], "a power cycle opens a new window");
}

/// CTAP 2.1 §6.2.2 / §6.3: GetAssertion without an allowList finds every discoverable
/// credential of the RP (numberOfCredentials 2) after one touch; GetNextAssertion returns
/// the other one without a touch; each signature verifies under its own credential key
/// and each assertion names its user.
#[test]
fn get_next_assertion_returns_every_discoverable_credential() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    let mut made = Vec::new();
    for user in [&b"first"[..], b"second"] {
        let request = ctap::make_credential(&cdh("mc"), RP, user, true, &PinAuth::None);
        let (response, _) = rig.cbor_touch(cid, &request, 100);
        let attestation = ctap::ok_value(&response);
        let auth = ctap::parse_auth_data(ctap::get(&attestation, 2).as_bytes().unwrap());
        made.push((user.to_vec(), auth.credential.unwrap()));
        rig.now += 1_000;
    }
    let hash = cdh("discoverable");
    let (response, _) = rig.cbor_touch(cid, &ctap::get_assertion(&hash, RP, &[], &PinAuth::None), 100);
    let first = ctap::ok_value(&response);
    assert_eq!(ctap::get(&first, 5).as_u64(), Some(2), "numberOfCredentials");
    let next = rig.cbor(cid, &ctap::request(cmd::GET_NEXT_ASSERTION, None));
    let second = ctap::ok_value(&next);
    let mut users = Vec::new();
    for assertion in [&first, &second] {
        let id = ctap::get(assertion, 1).map_get_text("id").and_then(Value::as_bytes).unwrap();
        let (user, credential) = made.iter().find(|(_, c)| c.id == id).expect("one of ours");
        assert_eq!(ctap::get(assertion, 4).map_get_text("id").and_then(Value::as_bytes), Some(user.as_slice()));
        let data = ctap::get(assertion, 2).as_bytes().unwrap();
        assert!(ctap::verify_es256(&credential.public_key, data, &hash, ctap::get(assertion, 3).as_bytes().unwrap()));
        users.push(user.clone());
    }
    users.sort();
    assert_eq!(users, [b"first".to_vec(), b"second".to_vec()]);
    let (status_byte, _) = ctap::response(&rig.cbor(cid, &ctap::request(cmd::GET_NEXT_ASSERTION, None)));
    assert_eq!(status_byte, 0x30, "CTAP2_ERR_NOT_ALLOWED: no more assertions");
}

/// CTAP 2.1 §11.2.9.2.2 CTAPHID_LOCK ("As long as the lock is active, any other channel
/// trying to send a message will fail"): other channels get ERR_CHANNEL_BUSY (`0x06`,
/// §11.2.9.1.6 "The client SHOULD retry the request after a short delay"; lk-ctaphid
/// framer check order, step 3: ERR_LOCK_REQUIRED means "Command requires channel lock",
/// and Chromium and python-fido2 retry only CHANNEL_BUSY) until the lock expires — a
/// device deadline the program's timer loop reaches — or is released with a zero lock
/// time.
#[test]
fn ctaphid_lock_reserves_the_device_until_it_expires() {
    let mut rig = Rig::new();
    let first = rig.ctaphid_init();
    let second = rig.ctaphid_init();
    assert_eq!(rig.ctaphid(first, 0x04, &[2]), (0x04, vec![]));
    assert_eq!(rig.ctaphid(second, CTAPHID_PING, b"p"), (CTAPHID_ERROR, vec![0x06]));
    let probe = Rig::ctaphid_packets(BROADCAST, CTAPHID_INIT, &[9; 8]);
    let refused = parse_fido(&rig.input(lk_device::Input::FidoReport(&probe[0])));
    assert_eq!(refused, vec![(CTAPHID_ERROR, vec![0x06])], "a new client's broadcast INIT is busy too");
    assert_eq!(rig.ctaphid(first, CTAPHID_PING, b"p"), (CTAPHID_PING, b"p".to_vec()), "the owner works");
    let start = rig.now;
    assert_eq!(rig.dev.next_deadline(), Some(start + 2_000), "the lock expiry is a deadline");
    rig.run_until(start + 2_000);
    assert_eq!(rig.ctaphid(second, CTAPHID_PING, b"p"), (CTAPHID_PING, b"p".to_vec()));

    assert_eq!(rig.ctaphid(second, 0x04, &[10]), (0x04, vec![]));
    assert_eq!(rig.ctaphid(first, CTAPHID_PING, b"p"), (CTAPHID_ERROR, vec![0x06]));
    assert_eq!(rig.ctaphid(second, 0x04, &[0]), (0x04, vec![]), "release");
    assert_eq!(rig.ctaphid(first, CTAPHID_PING, b"p"), (CTAPHID_PING, b"p".to_vec()));
}

/// GetInfo `maxMsgSize` 1536 (`reference-observation.json`): a 1536-byte CTAP2 message
/// spread over 27 CTAPHID packets is processed (here a GetAssertion for an RP with no
/// credentials: CTAP2_ERR_NO_CREDENTIALS), a 1537-byte one is CTAP1_ERR_INVALID_LENGTH
/// (lk-fido `cbor`: an over-long request is the CTAPHID over-length status).
#[test]
fn max_message_size_boundary() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    let request = |len: usize| {
        let mut rp_len = len - 40;
        loop {
            let rp: String = "r".repeat(rp_len);
            let message = ctap::get_assertion(&[6; 32], &rp, &[], &PinAuth::None);
            match message.len().cmp(&len) {
                std::cmp::Ordering::Equal => return message,
                std::cmp::Ordering::Less => rp_len += 1,
                std::cmp::Ordering::Greater => rp_len -= 1,
            }
        }
    };
    let fits = request(1536);
    assert_eq!(Rig::ctaphid_packets(cid, CTAPHID_CBOR, &fits).len(), 27);
    let out = rig.ctaphid_send(cid, CTAPHID_CBOR, &fits);
    let mut answer = responses(&out);
    if answer.is_empty() {
        answer = responses(&rig.tap());
    }
    assert_eq!(answer, vec![(CTAPHID_CBOR, vec![status::NO_CREDENTIALS])]);
    let too_long = request(1537);
    assert_eq!(rig.ctaphid(cid, CTAPHID_CBOR, &too_long), (CTAPHID_CBOR, vec![0x03]));
}
