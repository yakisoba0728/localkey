//! authenticatorConfig (CTAP 2.1 §6.11) and the alwaysUv feature it controls.

use super::platform::{PIN, Platform, Token, perm, set_pin, token};
use super::*;
use crate::status;

const TOGGLE_ALWAYS_UV: u64 = 0x02;
const SET_MIN_PIN_LENGTH: u64 = 0x03;

/// An authenticatorConfig request; the pinUvAuthParam covers
/// `32×0xff || 0x0d || uint8(subCommand) || subCommandParams` (§6.11).
fn config_request(subcommand: u64, params: Option<&Value>, token: Option<&Token>) -> Vec<u8> {
    let mut m = MapBuilder::new().insert(1, subcommand);
    if let Some(p) = params {
        m.set(2, p.clone());
    }
    if let Some(t) = token {
        let mut message = vec![0xFF; 32];
        message.push(0x0D);
        message.push(subcommand as u8);
        if let Some(p) = params {
            message.extend(cbor::encode(p));
        }
        m.set(3, t.protocol);
        m.set(4, t.sign(&message));
    }
    encode_request(0x0D, &m.build())
}

fn config(
    auth: &mut Authenticator,
    host: &mut TestHost,
    subcommand: u64,
    params: Option<Value>,
    token: Option<&Token>,
) -> Vec<u8> {
    send_untouched(
        auth,
        host,
        &config_request(subcommand, params.as_ref(), token),
    )
}

fn min_pin(new: Option<u64>, rp_ids: Option<&[&str]>, force: Option<bool>) -> Value {
    let mut m = MapBuilder::new();
    if let Some(n) = new {
        m.set(1, n);
    }
    if let Some(ids) = rp_ids {
        m.set(
            2,
            Value::Array(ids.iter().map(|s| Value::from(*s)).collect()),
        );
    }
    if let Some(f) = force {
        m.set(3, f);
    }
    m.build()
}

fn min_pin_length_output(auth: &mut Authenticator, host: &mut TestHost, rp: &str) -> Option<u64> {
    let reg = register(auth, host, &Mc::new().rp(rp).ext("minPinLength", true));
    reg.auth_data
        .extensions
        .and_then(|e| e.map_get_text("minPinLength").and_then(Value::as_u64))
}

#[test]
fn set_min_pin_length_without_a_pin_needs_no_token() {
    // CTAP 2.1 §6.11.4 and §6.11 (no authorization without a PIN or alwaysUv); GetInfo
    // minPINLength (0x0D) follows; a lower or impossible minimum is PIN_POLICY_VIOLATION;
    // forceChangePin without a PIN is PIN_NOT_SET.
    let (mut auth, mut host) = device();
    assert_eq!(
        config(
            &mut auth,
            &mut host,
            SET_MIN_PIN_LENGTH,
            Some(min_pin(Some(6), None, None)),
            None
        ),
        vec![0]
    );
    assert_eq!(
        get_info(&mut auth, &mut host)
            .map_get_int(0x0D)
            .and_then(Value::as_u64),
        Some(6)
    );
    let mut platform = Platform::connect(&mut auth, &mut host, 2);
    let r = send_untouched(&mut auth, &mut host, &platform.set_pin_request(b"12345"));
    assert_eq!(r, vec![status::PIN_POLICY_VIOLATION]);
    let r = send_untouched(&mut auth, &mut host, &platform.set_pin_request(b"123456"));
    assert_eq!(r, vec![status::OK]);
    let (mut auth, mut host) = device();
    for (value, want) in [
        (Some(3), status::PIN_POLICY_VIOLATION),
        (Some(64), status::PIN_POLICY_VIOLATION),
        (Some(u64::MAX), status::PIN_POLICY_VIOLATION),
        (None, status::OK),
        (Some(63), status::OK),
        (Some(62), status::PIN_POLICY_VIOLATION),
    ] {
        let r = config(
            &mut auth,
            &mut host,
            SET_MIN_PIN_LENGTH,
            Some(min_pin(value, None, None)),
            None,
        );
        assert_eq!(r, vec![want], "{value:?}");
    }
    let r = config(
        &mut auth,
        &mut host,
        SET_MIN_PIN_LENGTH,
        Some(min_pin(None, None, Some(true))),
        None,
    );
    assert_eq!(r, vec![status::PIN_NOT_SET]);
    let r = config(&mut auth, &mut host, SET_MIN_PIN_LENGTH, None, None);
    assert_eq!(r, vec![status::OK], "no parameters keeps everything");
    assert_eq!(persisted_state(&host).pin.min_length, 63);
}

#[test]
fn an_empty_rp_id_list_preserves_the_previous_list() {
    // BEHAVIOR_CATALOG FIDO: "CTAP 2.1 empty minPinLengthRPIDs preserves previous
    // allowlist while updating supplied minPinLength"; one RP ID at most
    // (maxRPIDsForSetMinPINLength 1, reference-observation.json), a longer list cannot be
    // stored: KEY_STORE_FULL (§6.11.4 step 7.3) with nothing changed; §12.4 minPinLength
    // output.
    let (mut auth, mut host) = device();
    let r = config(
        &mut auth,
        &mut host,
        SET_MIN_PIN_LENGTH,
        Some(min_pin(Some(6), Some(&[RP]), None)),
        None,
    );
    assert_eq!(r, vec![0]);
    assert_eq!(min_pin_length_output(&mut auth, &mut host, RP), Some(6));
    let r = config(
        &mut auth,
        &mut host,
        SET_MIN_PIN_LENGTH,
        Some(min_pin(Some(7), Some(&[]), None)),
        None,
    );
    assert_eq!(r, vec![0]);
    assert_eq!(
        persisted_state(&host).pin.min_pin_rp_ids,
        vec![RP.to_owned()]
    );
    assert_eq!(min_pin_length_output(&mut auth, &mut host, RP), Some(7));
    let r = config(
        &mut auth,
        &mut host,
        SET_MIN_PIN_LENGTH,
        Some(min_pin(Some(8), None, None)),
        None,
    );
    assert_eq!(r, vec![0]);
    assert_eq!(min_pin_length_output(&mut auth, &mut host, RP), Some(8));
    let two = min_pin(Some(9), Some(&[RP, "other.example"]), None);
    let before = host.persisted(Record::Fido);
    assert_eq!(
        config(&mut auth, &mut host, SET_MIN_PIN_LENGTH, Some(two), None),
        vec![status::KEY_STORE_FULL]
    );
    assert_eq!(host.persisted(Record::Fido), before, "nothing changed");
    assert_eq!(min_pin_length_output(&mut auth, &mut host, RP), Some(8));
    let r = config(
        &mut auth,
        &mut host,
        SET_MIN_PIN_LENGTH,
        Some(min_pin(None, Some(&["other.example"]), None)),
        None,
    );
    assert_eq!(r, vec![0]);
    assert_eq!(min_pin_length_output(&mut auth, &mut host, RP), None);
    assert_eq!(
        min_pin_length_output(&mut auth, &mut host, "other.example"),
        Some(8)
    );
    let bad = MapBuilder::new()
        .insert(2, Value::Array(vec![Value::from(5u8)]))
        .build();
    assert_eq!(
        config(&mut auth, &mut host, SET_MIN_PIN_LENGTH, Some(bad), None),
        vec![status::CBOR_UNEXPECTED_TYPE]
    );
}

#[test]
fn a_pin_requires_a_token_with_the_acfg_permission() {
    // CTAP 2.1 §6.11: PUAT_REQUIRED, MISSING_PARAMETER (protocol), INVALID_PARAMETER,
    // PIN_AUTH_INVALID (MAC or no acfg).
    for protocol in [1u8, 2] {
        let (mut auth, mut host) = device();
        set_pin(&mut auth, &mut host, protocol, PIN);
        let params = min_pin(Some(5), None, None);
        let r = config(
            &mut auth,
            &mut host,
            SET_MIN_PIN_LENGTH,
            Some(params.clone()),
            None,
        );
        assert_eq!(r, vec![status::PUAT_REQUIRED]);
        let t = token(&mut auth, &mut host, protocol, perm::ACFG, None);
        let no_protocol = encode_request(
            0x0D,
            &MapBuilder::new()
                .insert(1, SET_MIN_PIN_LENGTH)
                .insert(2, params.clone())
                .insert(4, vec![0u8; 16])
                .build(),
        );
        assert_eq!(
            send_untouched(&mut auth, &mut host, &no_protocol),
            vec![status::MISSING_PARAMETER]
        );
        let bad_protocol = encode_request(
            0x0D,
            &MapBuilder::new()
                .insert(1, SET_MIN_PIN_LENGTH)
                .insert(3, 9)
                .insert(4, vec![0u8; 16])
                .build(),
        );
        assert_eq!(
            send_untouched(&mut auth, &mut host, &bad_protocol),
            vec![status::INVALID_PARAMETER]
        );
        // The MAC covers subCommandParams: a MAC for other params does not verify.
        let mut request = config_request(
            SET_MIN_PIN_LENGTH,
            Some(&min_pin(Some(9), None, None)),
            Some(&t),
        );
        let honest = config_request(SET_MIN_PIN_LENGTH, Some(&params), Some(&t));
        let mac_len = if protocol == 1 { 16 } else { 32 };
        let mac_at = request.len() - mac_len;
        let honest_mac = honest[honest.len() - mac_len..].to_vec();
        request[mac_at..].copy_from_slice(&honest_mac);
        assert_eq!(
            send_untouched(&mut auth, &mut host, &request),
            vec![status::PIN_AUTH_INVALID]
        );
        let no_acfg = token(
            &mut auth,
            &mut host,
            protocol,
            perm::MC | perm::GA | perm::CM | perm::LBW,
            None,
        );
        let r = config(
            &mut auth,
            &mut host,
            SET_MIN_PIN_LENGTH,
            Some(params.clone()),
            Some(&no_acfg),
        );
        assert_eq!(r, vec![status::PIN_AUTH_INVALID]);
        let t = token(&mut auth, &mut host, protocol, perm::ACFG, None);
        assert_eq!(
            config(
                &mut auth,
                &mut host,
                SET_MIN_PIN_LENGTH,
                Some(params.clone()),
                Some(&t)
            ),
            vec![0]
        );
        assert_eq!(persisted_state(&host).pin.min_length, 5);
        // acfg is not consumed: the same token toggles alwaysUv on and off.
        assert_eq!(
            config(&mut auth, &mut host, TOGGLE_ALWAYS_UV, None, Some(&t)),
            vec![0]
        );
        assert_eq!(
            config(&mut auth, &mut host, TOGGLE_ALWAYS_UV, None, Some(&t)),
            vec![0]
        );
    }
}

#[test]
fn a_new_minimum_above_the_pin_length_forces_a_pin_change() {
    // CTAP 2.1 §6.11.4: forceChangePin, or newMinPINLength above the current PIN length,
    // sets forcePINChange (GetInfo 0x0C); then token requests answer
    // PIN_POLICY_VIOLATION until changePIN (§6.5.5.7.2 step 11).
    let (mut auth, mut host) = device();
    set_pin(&mut auth, &mut host, 2, "ab€d");
    let t = token_with(&mut auth, &mut host, "ab€d", perm::ACFG);
    let r = config(
        &mut auth,
        &mut host,
        SET_MIN_PIN_LENGTH,
        Some(min_pin(Some(4), None, None)),
        Some(&t),
    );
    assert_eq!(r, vec![0]);
    assert_eq!(
        get_info(&mut auth, &mut host).map_get_int(0x0C),
        Some(&Value::Bool(false)),
        "4 code points"
    );
    let r = config(
        &mut auth,
        &mut host,
        SET_MIN_PIN_LENGTH,
        Some(min_pin(Some(5), None, None)),
        Some(&t),
    );
    assert_eq!(r, vec![0]);
    assert_eq!(
        get_info(&mut auth, &mut host).map_get_int(0x0C),
        Some(&Value::Bool(true))
    );
    let mut platform = Platform::connect(&mut auth, &mut host, 2);
    let r = send_untouched(
        &mut auth,
        &mut host,
        &platform.token_request("ab€d", perm::MC, None),
    );
    assert_eq!(r, vec![status::PIN_POLICY_VIOLATION]);
    let r = send_untouched(
        &mut auth,
        &mut host,
        &platform.change_pin_request("ab€d", b"abcd"),
    );
    assert_eq!(
        r,
        vec![status::PIN_POLICY_VIOLATION],
        "new PIN shorter than the minimum"
    );
    let r = send_untouched(
        &mut auth,
        &mut host,
        &platform.change_pin_request("ab€d", b"abcde"),
    );
    assert_eq!(r, vec![status::OK]);
    assert_eq!(
        get_info(&mut auth, &mut host).map_get_int(0x0C),
        Some(&Value::Bool(false))
    );
    // forceChangePin true sets the flag whatever the length.
    let t = token_with(&mut auth, &mut host, "abcde", perm::ACFG);
    let r = config(
        &mut auth,
        &mut host,
        SET_MIN_PIN_LENGTH,
        Some(min_pin(None, None, Some(true))),
        Some(&t),
    );
    assert_eq!(r, vec![0]);
    assert!(persisted_state(&host).pin.force_change);
}

fn token_with(auth: &mut Authenticator, host: &mut TestHost, pin: &str, permissions: u8) -> Token {
    let mut platform = Platform::connect(auth, host, 2);
    let r = send_untouched(auth, host, &platform.token_request(pin, permissions, None));
    platform.token_from(&r)
}

#[test]
fn always_uv_requires_user_verification_everywhere() {
    // CTAP 2.1 §6.11.2 toggleAlwaysUv; §6.4 alwaysUv / makeCredUvNotRqd; §6.1.2 step 6 and
    // §6.2.2 step 5 (PUAT_REQUIRED without a PIN, steps 6.2.1 / 5.1.1, and without a token,
    // steps 6.4 / 5.5; silent assertions unaffected); §6.11 step 4 (config itself then needs
    // a token, except toggleAlwaysUv without a PIN, step 3); CTAP1/U2F disabled (§7.2.4:
    // REGISTER / AUTHENTICATE "MUST immediately fail and return SW_COMMAND_NOT_ALLOWED"
    // and "MUST NOT return "U2F_V2" in the versions array").
    let (mut auth, mut host) = device();
    let reg = register(&mut auth, &mut host, &Mc::new());
    assert_eq!(
        config(&mut auth, &mut host, TOGGLE_ALWAYS_UV, None, None),
        vec![0]
    );
    let info = get_info(&mut auth, &mut host);
    let options = info.map_get_int(4).unwrap();
    assert_eq!(options.map_get_text("alwaysUv"), Some(&Value::Bool(true)));
    assert_eq!(
        options.map_get_text("makeCredUvNotRqd"),
        Some(&Value::Bool(false))
    );
    let versions = |info: &Value| -> Vec<String> {
        info.map_get_int(1)
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .map(|v| v.as_text().unwrap().to_owned())
            .collect()
    };
    assert_eq!(versions(&info), ["FIDO_2_0", "FIDO_2_1_PRE", "FIDO_2_1"]);
    assert_eq!(
        send_untouched(&mut auth, &mut host, &Mc::new().encode()),
        vec![status::PUAT_REQUIRED]
    );
    let ga = Ga::new().allow(vec![reg.id()]);
    assert_eq!(
        send_untouched(&mut auth, &mut host, &ga.encode()),
        vec![status::PUAT_REQUIRED]
    );
    let silent = assert(&mut auth, &mut host, &ga.clone().option("up", false));
    assert_eq!(silent.auth_data.flags, 0x00);
    // U2F REGISTER / AUTHENTICATE are refused, VERSION still answers.
    let register_apdu = [&[0x00u8, 0x01, 0x03, 0x00, 0x40][..], &[0x11; 64]].concat();
    let (r, presence) = auth.u2f(&register_apdu, true, &mut host);
    assert_eq!(r, vec![0x69, 0x86]);
    assert_eq!(presence, crate::U2fPresence::NotNeeded);
    let auth_apdu = [&[0x00u8, 0x02, 0x03, 0x00, 0x41][..], &[0x11; 64], &[0x00]].concat();
    assert_eq!(auth.u2f(&auth_apdu, true, &mut host).0, vec![0x69, 0x86]);
    assert_eq!(
        auth.u2f(&[0x00, 0x03, 0x00, 0x00], false, &mut host).0,
        b"U2F_V2\x90\x00".to_vec()
    );
    // Config now needs a token even without a PIN (toggleAlwaysUv excepted, see
    // always_uv_can_be_switched_off_without_a_pin).
    let r = config(
        &mut auth,
        &mut host,
        SET_MIN_PIN_LENGTH,
        Some(min_pin(Some(5), None, None)),
        None,
    );
    assert_eq!(r, vec![status::PUAT_REQUIRED]);
    // Large-blob writes too (CTAP 2.1 §6.10.2).
    let r = super::large_blobs::write_fragment(
        &mut auth,
        &mut host,
        &crate::state::INITIAL_LARGE_BLOB,
        0,
        Some(17),
        None,
    );
    assert_eq!(r, vec![status::PUAT_REQUIRED]);

    set_pin(&mut auth, &mut host, 2, PIN);
    assert_eq!(
        send_untouched(&mut auth, &mut host, &Mc::new().encode()),
        vec![status::PUAT_REQUIRED]
    );
    assert_eq!(
        send_untouched(&mut auth, &mut host, &ga.encode()),
        vec![status::PUAT_REQUIRED]
    );
    let t = token(&mut auth, &mut host, 2, perm::MC, None);
    let made = register(&mut auth, &mut host, &Mc::new().with_token(&t));
    assert_eq!(made.auth_data.flags & 0x05, 0x05);
    let t = token(&mut auth, &mut host, 2, perm::GA, None);
    assert_eq!(
        assert(&mut auth, &mut host, &ga.clone().with_token(&t))
            .auth_data
            .flags,
        0x05
    );
    // With a PIN the step 3 exception no longer applies.
    assert_eq!(
        config(&mut auth, &mut host, TOGGLE_ALWAYS_UV, None, None),
        vec![status::PUAT_REQUIRED]
    );
    let t = token(&mut auth, &mut host, 2, perm::ACFG, None);
    assert_eq!(
        config(&mut auth, &mut host, TOGGLE_ALWAYS_UV, None, Some(&t)),
        vec![0]
    );
    assert!(!persisted_state(&host).pin.always_uv);
    assert_eq!(
        versions(&get_info(&mut auth, &mut host)),
        ["U2F_V2", "FIDO_2_0", "FIDO_2_1_PRE", "FIDO_2_1"]
    );
    assert_eq!(
        status_of(&send(&mut auth, &mut host, &ga.encode())),
        status::OK
    );
    assert!(
        auth.u2f(&register_apdu, true, &mut host)
            .0
            .ends_with(&[0x90, 0x00])
    );
}

#[test]
fn always_uv_can_be_switched_off_without_a_pin() {
    // CTAP 2.1 §6.11 step 3: toggleAlwaysUv on an authenticator that is not protected by
    // user verification while alwaysUv is on skips authorization ("then go to Step 5"),
    // so a device without a PIN never stays locked in alwaysUv. §6.11.2 step 2: disabling
    // restores makeCredUvNotRqd.
    let (mut auth, mut host) = device();
    for expected in [true, false, true, false] {
        assert_eq!(
            config(&mut auth, &mut host, TOGGLE_ALWAYS_UV, None, None),
            vec![0]
        );
        assert_eq!(persisted_state(&host).pin.always_uv, expected);
        let options = get_info(&mut auth, &mut host)
            .map_get_int(4)
            .unwrap()
            .clone();
        assert_eq!(
            options.map_get_text("makeCredUvNotRqd"),
            Some(&Value::Bool(!expected))
        );
    }
    // The exception is only for toggleAlwaysUv: setMinPINLength still needs a token.
    assert_eq!(
        config(&mut auth, &mut host, TOGGLE_ALWAYS_UV, None, None),
        vec![0]
    );
    let r = config(
        &mut auth,
        &mut host,
        SET_MIN_PIN_LENGTH,
        Some(min_pin(Some(6), None, None)),
        None,
    );
    assert_eq!(r, vec![status::PUAT_REQUIRED]);
    // Storage failure keeps the previous value (docs/CONTRACTS.md persisted state).
    host.fail_next_saves(1);
    assert_eq!(
        config(&mut auth, &mut host, TOGGLE_ALWAYS_UV, None, None),
        vec![status::OTHER]
    );
    assert!(persisted_state(&host).pin.always_uv);
    assert_eq!(
        option_value(&mut auth, &mut host, "alwaysUv"),
        Some(Value::Bool(true))
    );
}

fn option_value(auth: &mut Authenticator, host: &mut TestHost, name: &str) -> Option<Value> {
    get_info(auth, host)
        .map_get_int(4)
        .and_then(|o| o.map_get_text(name))
        .cloned()
}

#[test]
fn unsupported_subcommands_and_parameter_errors() {
    // CTAP 2.1 §6.11.1 enableEnterpriseAttestation needs "ep" and §6.11.3 vendorPrototype
    // needs vendorPrototypeConfigCommands, both absent from GetInfo: §6.11 step 2 "If the
    // authenticator does not support the subcommand being invoked ... return
    // CTAP1_ERR_INVALID_PARAMETER", before authorization (step 4).
    let (mut auth, mut host) = device();
    set_pin(&mut auth, &mut host, 2, PIN);
    for subcommand in [0x01u64, 0x04, 0xFF, 0x100] {
        assert_eq!(
            config(&mut auth, &mut host, subcommand, None, None),
            vec![status::INVALID_PARAMETER]
        );
    }
    let r = send_untouched(
        &mut auth,
        &mut host,
        &encode_request(0x0D, &MapBuilder::new().insert(3, 2).build()),
    );
    assert_eq!(r, vec![status::MISSING_PARAMETER]);
    let r = send_untouched(
        &mut auth,
        &mut host,
        &encode_request(0x0D, &MapBuilder::new().insert(1, 3).insert(2, 1).build()),
    );
    assert_eq!(r, vec![status::CBOR_UNEXPECTED_TYPE]);
    let bad = MapBuilder::new().insert(3, 1).build();
    let r = config(&mut auth, &mut host, SET_MIN_PIN_LENGTH, Some(bad), None);
    assert_eq!(r, vec![status::CBOR_UNEXPECTED_TYPE]);
}

#[test]
fn reset_clears_the_configuration() {
    // CTAP 2.1 §6.6: reset returns minPINLength, the RP list, forcePINChange and alwaysUv to
    // their factory values.
    let (mut auth, mut host) = device();
    let r = config(
        &mut auth,
        &mut host,
        SET_MIN_PIN_LENGTH,
        Some(min_pin(Some(8), Some(&[RP]), None)),
        None,
    );
    assert_eq!(r, vec![0]);
    assert_eq!(
        config(&mut auth, &mut host, TOGGLE_ALWAYS_UV, None, None),
        vec![0]
    );
    assert_eq!(send(&mut auth, &mut host, &[0x07]), vec![status::OK]);
    let pin = persisted_state(&host).pin;
    assert_eq!(pin, crate::state::PinState::default());
}

#[test]
fn with_always_uv_and_no_pin_a_presented_token_is_pin_auth_invalid() {
    // Regression: verification answered CTAP2_ERR_PIN_NOT_SET when no PIN was set. CTAP 2.1
    // §6.11 step 4 applies when alwaysUv is on even without a PIN (except toggleAlwaysUv,
    // step 3): no pinUvAuthParam is CTAP2_ERR_PUAT_REQUIRED (step 4.1) and a failed
    // verify() is CTAP2_ERR_PIN_AUTH_INVALID (step 4.4.1); without a PIN no token is in use,
    // so verify() fails (§6.5.6).
    let (mut auth, mut host) = device();
    assert_eq!(
        config(&mut auth, &mut host, TOGGLE_ALWAYS_UV, None, None),
        vec![0]
    );
    let forged = Token {
        protocol: 1,
        value: vec![0x42; 32],
    };
    let params = min_pin(Some(6), None, None);
    assert_eq!(
        config(
            &mut auth,
            &mut host,
            SET_MIN_PIN_LENGTH,
            Some(params.clone()),
            None
        ),
        vec![status::PUAT_REQUIRED]
    );
    assert_eq!(
        config(
            &mut auth,
            &mut host,
            SET_MIN_PIN_LENGTH,
            Some(params),
            Some(&forged)
        ),
        vec![status::PIN_AUTH_INVALID]
    );
    assert_eq!(persisted_state(&host).pin.min_length, 4, "nothing changed");
}
