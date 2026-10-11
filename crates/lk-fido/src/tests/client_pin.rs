//! authenticatorClientPIN (CTAP 2.1 §6.5) with PIN/UV auth protocols 1 and 2, driven by
//! the independent platform in `platform.rs`, and pinUvAuthToken use in makeCredential /
//! getAssertion (§6.1.2 step 11, §6.2.2 step 6).

use super::platform::{PIN, Platform, Token, client_pin, perm, retries, set_pin, sub, token};
use super::*;
use crate::status;

const PROTOCOLS: [u8; 2] = [1, 2];

fn device_with_pin(protocol: u8) -> (Authenticator, TestHost) {
    let (mut auth, mut host) = device();
    set_pin(&mut auth, &mut host, protocol, PIN);
    (auth, host)
}

/// Send a token request with `pin` and return its status byte.
fn token_status(auth: &mut Authenticator, host: &mut TestHost, pin: &str) -> u8 {
    let mut platform = Platform::connect(auth, host, 2);
    status_of(&send_untouched(
        auth,
        host,
        &platform.token_request(pin, perm::MC, None),
    ))
}

#[test]
fn pin_flows_round_trip_with_an_independent_platform_for_both_protocols() {
    // CTAP 2.1 §6.5.5.5 setPIN, §6.5.5.7.1 getPinToken, §6.5.5.7.2 getPinUvAuthToken...;
    // the token then verifies in makeCredential / getAssertion and sets the UV flag
    // (WebAuthn L2 §6.1 flags bit 2).
    for protocol in PROTOCOLS {
        let (mut auth, mut host) = device();
        let mut platform = Platform::connect(&mut auth, &mut host, protocol);
        assert_eq!(
            send_untouched(&mut auth, &mut host, &platform.set_pin_request(b"123456")),
            vec![status::OK]
        );
        let state = persisted_state(&host);
        assert_eq!(state.pin.hash.unwrap()[..], sha256(b"123456")[..16]);
        assert_eq!(state.pin.retries, 8);
        assert_eq!(state.pin.code_points, 6);

        // Superseded getPinToken: permissions mc and ga.
        let r = send_untouched(&mut auth, &mut host, &platform.pin_token_request("123456"));
        let legacy = platform.token_from(&r);
        assert_eq!(legacy.value.len(), 32);
        let reg = register(&mut auth, &mut host, &Mc::new().rk().with_token(&legacy));
        assert_eq!(reg.auth_data.flags & 0x05, 0x05, "UP | UV");

        let r = send_untouched(
            &mut auth,
            &mut host,
            &platform.token_request("123456", perm::GA, Some(RP)),
        );
        let t = platform.token_from(&r);
        let a = assert(&mut auth, &mut host, &Ga::new().with_token(&t));
        assert_eq!(a.auth_data.flags, 0x05, "UP | UV");
        assert!(a.verifies_with(&reg.public_key()));
    }
}

#[test]
fn get_key_agreement_returns_a_cose_key_per_power_cycle() {
    // CTAP 2.1 §6.5.5.4 getKeyAgreement: COSE_Key {1: 2, 3: -25, -1: 1, -2, -3}
    // (§6.5.6 getPublicKey); the key is generated at power-up (§6.5.6 initialize()).
    let (mut auth, mut host) = device();
    let get = |auth: &mut Authenticator, host: &mut TestHost, p: u8| {
        body(&send_untouched(
            auth,
            host,
            &client_pin(Some(p), sub::GET_KEY_AGREEMENT).request(),
        ))
        .map_get_int(1)
        .cloned()
        .unwrap()
    };
    let k1 = get(&mut auth, &mut host, 1);
    let k2 = get(&mut auth, &mut host, 2);
    Platform::with_peer(1, &k1);
    assert_eq!(
        get(&mut auth, &mut host, 1),
        k1,
        "stable within a power cycle"
    );
    assert_ne!(k1, k2, "one key per protocol");
    auth.power_cycle(&mut host);
    assert_ne!(get(&mut auth, &mut host, 1), k1, "regenerated at power-up");
    assert_eq!(
        send_untouched(
            &mut auth,
            &mut host,
            &client_pin(None, sub::GET_KEY_AGREEMENT).request()
        ),
        vec![status::MISSING_PARAMETER]
    );
    assert_eq!(
        send_untouched(
            &mut auth,
            &mut host,
            &client_pin(Some(3), sub::GET_KEY_AGREEMENT).request()
        ),
        vec![status::INVALID_PARAMETER]
    );
    assert_eq!(host.persist_attempts(), 0, "key agreement is volatile");
}

#[test]
fn parameter_types_and_subcommands() {
    // CTAP 2.1 §6.5.4 parameter types → CTAP2_ERR_CBOR_UNEXPECTED_TYPE; missing
    // subCommand → MISSING_PARAMETER; getPinUvAuthTokenUsingUvWithPermissions (0x06) needs
    // built-in UV, absent from GetInfo; unknown subcommands. getUVRetries (0x07) is
    // CTAP2_ERR_PIN_AUTH_INVALID on the measured key (docs/MEASUREMENT.md, probe
    // client-pin-uv-retries); it was in the INVALID_SUBCOMMAND list before the measurement.
    let (mut auth, mut host) = device();
    let send = |auth: &mut Authenticator, host: &mut TestHost, m: Value| {
        send_untouched(auth, host, &encode_request(0x06, &m))
    };
    let m = MapBuilder::new().insert(1, 2).build();
    assert_eq!(
        send(&mut auth, &mut host, m),
        vec![status::MISSING_PARAMETER]
    );
    let m = MapBuilder::new().insert(1, 2).insert(2, "x").build();
    assert_eq!(
        send(&mut auth, &mut host, m),
        vec![status::CBOR_UNEXPECTED_TYPE]
    );
    let m = MapBuilder::new()
        .insert(1, 2)
        .insert(2, 3)
        .insert(3, 5)
        .build();
    assert_eq!(
        send(&mut auth, &mut host, m),
        vec![status::CBOR_UNEXPECTED_TYPE]
    );
    let m = MapBuilder::new()
        .insert(1, 2)
        .insert(2, 9)
        .insert(0x0A, 1)
        .build();
    assert_eq!(
        send(&mut auth, &mut host, m),
        vec![status::CBOR_UNEXPECTED_TYPE]
    );
    for subcommand in [0x06u64, 0x08, 0x0A, 0xFF] {
        assert_eq!(
            send_untouched(
                &mut auth,
                &mut host,
                &client_pin(Some(2), subcommand).request()
            ),
            vec![status::INVALID_SUBCOMMAND],
            "{subcommand:#x}"
        );
    }
    assert_eq!(
        send_untouched(
            &mut auth,
            &mut host,
            &client_pin(Some(2), sub::GET_UV_RETRIES).request()
        ),
        vec![status::PIN_AUTH_INVALID],
        "getUVRetries"
    );
    assert_eq!(
        send_untouched(&mut auth, &mut host, &[0x06]),
        vec![status::INVALID_CBOR]
    );
}

#[test]
fn get_pin_retries_reports_retries_and_power_cycle_state() {
    // CTAP 2.1 §6.5.5.2: {3: pinRetries, 4: powerCycleState (optional)};
    // pinUvAuthProtocol not needed. Without a soft block the measured key leaves
    // powerCycleState out (docs/MEASUREMENT.md, probe client-pin-retries); this test
    // expected `4: false` before the measurement. `4: true` while soft-blocked is in
    // `three_wrong_pins_soft_block_until_a_power_cycle`.
    let (mut auth, mut host) = device();
    assert_eq!(retries(&mut auth, &mut host), (8, None));
    let r = send_untouched(
        &mut auth,
        &mut host,
        &client_pin(None, sub::GET_PIN_RETRIES).request(),
    );
    assert_eq!(body(&r).map_get_int(3).and_then(Value::as_u64), Some(8));
    assert_eq!(body(&r).map_get_int(4), None);
}

#[test]
fn get_pin_retries_with_a_pin_set_is_byte_identical_to_the_measured_key() {
    // docs/MEASUREMENT.md, probe client-pin-retries: getPINRetries with protocol 2
    // (`06 A2 01 02 02 01`) on the key with a PIN set and 8 retries is answered
    // `00 A1 03 08`, 4 bytes ({3: 8}); the engine answered `00 A2 03 08 04 F4`
    // ({3: 8, 4: false}) before the measurement.
    let (mut auth, mut host) = device_with_pin(2);
    let request = client_pin(Some(2), sub::GET_PIN_RETRIES).request();
    assert_eq!(request, vec![0x06, 0xA2, 0x01, 0x02, 0x02, 0x01]);
    assert_eq!(
        send_untouched(&mut auth, &mut host, &request),
        vec![0x00, 0xA1, 0x03, 0x08]
    );
}

#[test]
fn set_pin_errors() {
    // CTAP 2.1 §6.5.5.5 steps 1-10 and §6.5.1 PIN composition (4..=63 bytes of UTF-8,
    // at least minPINLength code points).
    for protocol in PROTOCOLS {
        let (mut auth, mut host) = device();
        let mut platform = Platform::connect(&mut auth, &mut host, protocol);
        let new_pin_enc = platform.new_pin_enc(b"1234");
        let mac = platform.mac_shared(&new_pin_enc);
        let base = || {
            client_pin(Some(protocol), sub::SET_PIN)
                .with(3, platform.cose_key())
                .with(5, new_pin_enc.clone())
        };
        let r = send_untouched(&mut auth, &mut host, &base().request());
        assert_eq!(r, vec![status::MISSING_PARAMETER], "pinUvAuthParam");
        let mut wrong = mac.clone();
        wrong[0] ^= 1;
        let r = send_untouched(&mut auth, &mut host, &base().with(4, wrong).request());
        assert_eq!(r, vec![status::PIN_AUTH_INVALID]);
        let r = send_untouched(
            &mut auth,
            &mut host,
            &client_pin(Some(3), sub::SET_PIN)
                .with(3, platform.cose_key())
                .with(5, new_pin_enc.clone())
                .with(4, mac.clone())
                .request(),
        );
        assert_eq!(r, vec![status::INVALID_PARAMETER], "protocol 3");
        // An off-curve platform key fails decapsulate().
        let bad_key = MapBuilder::new()
            .insert(1, 2)
            .insert(3, -25)
            .insert(-1, 1)
            .insert(-2, vec![1u8; 32])
            .insert(-3, vec![1u8; 32])
            .build();
        let r = send_untouched(
            &mut auth,
            &mut host,
            &client_pin(Some(protocol), sub::SET_PIN)
                .with(3, bad_key)
                .with(5, new_pin_enc.clone())
                .with(4, mac.clone())
                .request(),
        );
        assert_eq!(r, vec![status::INVALID_PARAMETER], "decapsulate");
        // paddedNewPin of 48 bytes: CTAP1_ERR_INVALID_PARAMETER.
        let short = platform.encrypt(&[0x31; 48]);
        let r = send_untouched(
            &mut auth,
            &mut host,
            &client_pin(Some(protocol), sub::SET_PIN)
                .with(3, platform.cose_key())
                .with(5, short.clone())
                .with(4, platform.mac_shared(&short))
                .request(),
        );
        assert_eq!(r, vec![status::INVALID_PARAMETER], "not 64 bytes");
        for pin in [
            &b"123"[..],
            "ééé".as_bytes(),
            &[0x31; 64],
            &[0xFF, 0xFE, 0x31, 0x32],
        ] {
            let r = send_untouched(&mut auth, &mut host, &platform.set_pin_request(pin));
            assert_eq!(r, vec![status::PIN_POLICY_VIOLATION], "{pin:02x?}");
        }
        assert_eq!(host.persist_attempts(), 0);
        // Four code points in eight bytes, and 63 bytes, are acceptable.
        host.fail_next_saves(1);
        let r = send_untouched(
            &mut auth,
            &mut host,
            &platform.set_pin_request("éééé".as_bytes()),
        );
        assert_eq!(r, vec![status::OTHER], "storage failure");
        assert!(!persisted_state_or_default(&host).pin_is_set());
        let r = send_untouched(&mut auth, &mut host, &platform.set_pin_request(&[0x31; 63]));
        assert_eq!(r, vec![status::OK]);
        assert_eq!(persisted_state(&host).pin.code_points, 63);
        let r = send_untouched(&mut auth, &mut host, &platform.set_pin_request(b"5678"));
        assert_eq!(r, vec![status::PIN_AUTH_INVALID], "already set");
    }
}

fn persisted_state_or_default(host: &TestHost) -> crate::state::State {
    host.persisted(Record::Fido)
        .and_then(|b| crate::state::State::deserialize(&b))
        .unwrap_or_default()
}

#[test]
fn three_wrong_pins_soft_block_until_a_power_cycle() {
    // BEHAVIOR_CATALOG FIDO: "Three wrong PINs now return PIN_AUTH_BLOCKED with
    // powerCycleState true; further PIN attempts consume no durable retry until a power
    // cycle" (CTAP 2.1 §6.5.5.7.2 step 9).
    let (mut auth, mut host) = device_with_pin(2);
    assert_eq!(
        token_status(&mut auth, &mut host, "0000"),
        status::PIN_INVALID
    );
    assert_eq!(
        token_status(&mut auth, &mut host, "0000"),
        status::PIN_INVALID
    );
    assert_eq!(
        token_status(&mut auth, &mut host, "0000"),
        status::PIN_AUTH_BLOCKED
    );
    assert_eq!(persisted_state(&host).pin.retries, 5);
    assert_eq!(retries(&mut auth, &mut host), (5, Some(true)));
    let attempts = host.persist_attempts();
    // Even the correct PIN is refused, without consuming a retry.
    assert_eq!(
        token_status(&mut auth, &mut host, PIN),
        status::PIN_AUTH_BLOCKED
    );
    let mut platform = Platform::connect(&mut auth, &mut host, 1);
    let r = send_untouched(
        &mut auth,
        &mut host,
        &platform.change_pin_request(PIN, b"9999"),
    );
    assert_eq!(r, vec![status::PIN_AUTH_BLOCKED]);
    let r = send_untouched(&mut auth, &mut host, &platform.pin_token_request(PIN));
    assert_eq!(r, vec![status::PIN_AUTH_BLOCKED]);
    assert_eq!(host.persist_attempts(), attempts, "no retry consumed");
    assert_eq!(persisted_state(&host).pin.retries, 5);

    auth.power_cycle(&mut host);
    assert_eq!(retries(&mut auth, &mut host), (5, None));
    assert_eq!(token_status(&mut auth, &mut host, PIN), status::OK);
    assert_eq!(
        retries(&mut auth, &mut host),
        (8, None),
        "a match restores the retries"
    );
    assert_eq!(persisted_state(&host).pin.retries, 8);
}

#[test]
fn a_correct_pin_resets_the_consecutive_mismatch_count() {
    // CTAP 2.1 §6.5.5.7.2 step 9: the soft block counts *consecutive* mismatches.
    let (mut auth, mut host) = device_with_pin(2);
    for _ in 0..2 {
        assert_eq!(
            token_status(&mut auth, &mut host, "0000"),
            status::PIN_INVALID
        );
    }
    assert_eq!(token_status(&mut auth, &mut host, PIN), status::OK);
    for _ in 0..2 {
        assert_eq!(
            token_status(&mut auth, &mut host, "0000"),
            status::PIN_INVALID
        );
    }
    assert_eq!(retries(&mut auth, &mut host), (6, None));
}

#[test]
fn eight_failures_across_power_cycles_hard_block() {
    // BEHAVIOR_CATALOG FIDO: "eight failures across cycles hard-block"; CTAP 2.1 §6.5.5.7.2
    // steps 5 and 9 (pinRetries 0 → CTAP2_ERR_PIN_BLOCKED) take precedence over the soft
    // block.
    let (mut auth, mut host) = device_with_pin(1);
    let mut statuses = Vec::new();
    for round in 0..3 {
        for _ in 0..3 {
            statuses.push(token_status(&mut auth, &mut host, "0000"));
            if persisted_state(&host).pin.retries == 0 {
                break;
            }
        }
        if round < 2 {
            auth.power_cycle(&mut host);
        }
    }
    use status::{PIN_AUTH_BLOCKED as AB, PIN_BLOCKED as B, PIN_INVALID as I};
    assert_eq!(statuses, vec![I, I, AB, I, I, AB, I, B]);
    assert_eq!(retries(&mut auth, &mut host), (0, None));
    auth.power_cycle(&mut host);
    let attempts = host.persist_attempts();
    assert_eq!(token_status(&mut auth, &mut host, PIN), status::PIN_BLOCKED);
    let mut platform = Platform::connect(&mut auth, &mut host, 2);
    let r = send_untouched(
        &mut auth,
        &mut host,
        &platform.change_pin_request(PIN, b"9999"),
    );
    assert_eq!(r, vec![status::PIN_BLOCKED]);
    assert_eq!(host.persist_attempts(), attempts);
    // Only authenticatorReset recovers (CTAP 2.1 §6.6).
    auth.power_cycle(&mut host);
    assert_eq!(send(&mut auth, &mut host, &[0x07]), vec![status::OK]);
    assert_eq!(retries(&mut auth, &mut host), (8, None));
    set_pin(&mut auth, &mut host, 2, PIN);
    assert_eq!(token_status(&mut auth, &mut host, PIN), status::OK);
}

#[test]
fn the_retry_decrement_is_persisted_before_the_pin_is_checked() {
    // docs/DESIGN.md §7 (retry counters persisted before the response); CTAP 2.1 §6.5.5.7.2
    // step 8 decrements before step 9 compares. A storage failure answers CTAP1_ERR_OTHER
    // without checking the PIN or counting a mismatch.
    let (mut auth, mut host) = device_with_pin(2);
    host.fail_next_saves(1);
    assert_eq!(token_status(&mut auth, &mut host, "0000"), status::OTHER);
    assert_eq!(retries(&mut auth, &mut host), (8, None));
    let before = host.persist_count();
    assert_eq!(
        token_status(&mut auth, &mut host, "0000"),
        status::PIN_INVALID
    );
    assert_eq!(host.persist_count(), before + 1);
    assert_eq!(
        persisted_state(&host).pin.retries,
        7,
        "persisted before the answer"
    );
    // A restart keeps the decrement.
    let mut auth = restart(&mut host);
    assert_eq!(retries(&mut auth, &mut host), (7, None));
}

#[test]
fn malformed_pin_proofs_cost_a_retry_and_count_toward_the_soft_block() {
    // BEHAVIOR_CATALOG FIDO: "Malformed encrypted PIN proofs now decrement durable retries
    // before decryption and participate in the three-attempt soft block."
    for protocol in PROTOCOLS {
        let (mut auth, mut host) = device_with_pin(protocol);
        let malformed: [Vec<u8>; 3] = [vec![0u8; 15], vec![0u8; 17], vec![0u8; 64]];
        let mut statuses = Vec::new();
        for (i, enc) in malformed.iter().enumerate() {
            let platform = Platform::connect(&mut auth, &mut host, protocol);
            let r = send_untouched(
                &mut auth,
                &mut host,
                &client_pin(Some(protocol), sub::GET_TOKEN_WITH_PERMISSIONS)
                    .with(3, platform.cose_key())
                    .with(6, enc.clone())
                    .with(9, perm::GA)
                    .request(),
            );
            statuses.push(status_of(&r));
            assert_eq!(persisted_state(&host).pin.retries, 7 - i as u8);
        }
        assert_eq!(
            statuses,
            vec![
                status::PIN_INVALID,
                status::PIN_INVALID,
                status::PIN_AUTH_BLOCKED
            ]
        );
        assert_eq!(retries(&mut auth, &mut host), (5, Some(true)));
        auth.power_cycle(&mut host);
        assert_eq!(token_status(&mut auth, &mut host, PIN), status::OK);
        assert_eq!(retries(&mut auth, &mut host), (8, None));
    }
}

#[test]
fn a_mismatch_regenerates_the_key_agreement() {
    // CTAP 2.1 §6.5.5.7.2 step 9: on a mismatch the authenticator "Calls regenerate for the
    // selected pinUvAuthProtocol", so a platform must run getKeyAgreement again.
    let (mut auth, mut host) = device_with_pin(2);
    let mut platform = Platform::connect(&mut auth, &mut host, 2);
    let before = platform.cose_key();
    let r = send_untouched(
        &mut auth,
        &mut host,
        &platform.token_request("0000", perm::GA, None),
    );
    assert_eq!(r, vec![status::PIN_INVALID]);
    // The old shared secret no longer decrypts to the right hash.
    let r = send_untouched(
        &mut auth,
        &mut host,
        &platform.token_request(PIN, perm::GA, None),
    );
    assert_eq!(r, vec![status::PIN_INVALID]);
    let fresh = Platform::connect(&mut auth, &mut host, 2);
    assert_ne!(fresh.shared, platform.shared);
    assert_eq!(
        fresh.cose_key(),
        before,
        "same platform key, new authenticator key"
    );
    assert_eq!(token_status(&mut auth, &mut host, PIN), status::OK);
}

#[test]
fn a_mismatch_regenerates_only_the_key_agreement_of_its_protocol() {
    // Regression: a mismatch dropped the key-agreement keys of both protocols. CTAP 2.1
    // §6.5.5.7.2 step 9 (likewise §6.5.5.6 step 7 and §6.5.5.7.1) "Calls regenerate for the
    // selected pinUvAuthProtocol" only, so a platform holding a shared secret for the other
    // protocol (for example for hmac-secret) keeps it.
    let (mut auth, mut host) = device_with_pin(2);
    let mut v1 = Platform::connect(&mut auth, &mut host, 1);
    let mut v2 = Platform::connect(&mut auth, &mut host, 2);
    let r = send_untouched(
        &mut auth,
        &mut host,
        &v2.token_request("0000", perm::GA, None),
    );
    assert_eq!(r, vec![status::PIN_INVALID]);
    let r = send_untouched(&mut auth, &mut host, &v1.token_request(PIN, perm::GA, None));
    assert_eq!(status_of(&r), status::OK, "protocol 1 key kept");
    let r = send_untouched(&mut auth, &mut host, &v2.token_request(PIN, perm::GA, None));
    assert_eq!(r, vec![status::PIN_INVALID], "protocol 2 key regenerated");
    let fresh = Platform::connect(&mut auth, &mut host, 2);
    assert_ne!(fresh.shared, v2.shared);
}

#[test]
fn issuing_a_token_keeps_the_key_agreement() {
    // CTAP 2.1 §6.5.5.7.2 does not regenerate the key-agreement key on success.
    let (mut auth, mut host) = device_with_pin(1);
    let mut platform = Platform::connect(&mut auth, &mut host, 1);
    for _ in 0..2 {
        let r = send_untouched(
            &mut auth,
            &mut host,
            &platform.token_request(PIN, perm::GA, None),
        );
        assert_eq!(status_of(&r), status::OK);
    }
}

#[test]
fn forced_pin_change_verifies_the_pin_before_the_policy_status() {
    // BEHAVIOR_CATALOG FIDO: "Forced-PIN-change token commands now verify the supplied old
    // PIN and update retries before policy status; legacy token returns PIN_INVALID for a
    // correct PIN under forced change." CTAP 2.1 §6.5.5.7.2 step 11 (PIN_POLICY_VIOLATION),
    // §6.5.5.7.1 (PIN_INVALID), §6.5.5.6 steps 13 and 16 (same PIN refused, flag cleared).
    let (_, mut host) = device_with_pin(2);
    let mut auth = with_state(&mut host, |s| s.pin.force_change = true);
    assert_eq!(
        get_info(&mut auth, &mut host).map_get_int(0x0C),
        Some(&Value::Bool(true))
    );
    assert_eq!(
        token_status(&mut auth, &mut host, "0000"),
        status::PIN_INVALID
    );
    assert_eq!(
        persisted_state(&host).pin.retries,
        7,
        "wrong PIN still costs a retry"
    );
    assert_eq!(
        token_status(&mut auth, &mut host, PIN),
        status::PIN_POLICY_VIOLATION
    );
    assert_eq!(
        persisted_state(&host).pin.retries,
        8,
        "retries restored before the policy"
    );
    assert_eq!(
        token_status(&mut auth, &mut host, "0000"),
        status::PIN_INVALID
    );
    let mut platform = Platform::connect(&mut auth, &mut host, 2);
    let r = send_untouched(&mut auth, &mut host, &platform.pin_token_request(PIN));
    assert_eq!(
        r,
        vec![status::PIN_INVALID],
        "legacy getPinToken under forced change"
    );
    assert_eq!(persisted_state(&host).pin.retries, 8);
    let r = send_untouched(
        &mut auth,
        &mut host,
        &platform.change_pin_request(PIN, PIN.as_bytes()),
    );
    assert_eq!(r, vec![status::PIN_POLICY_VIOLATION], "same PIN");
    assert!(persisted_state(&host).pin.force_change);
    let r = send_untouched(
        &mut auth,
        &mut host,
        &platform.change_pin_request(PIN, b"24680"),
    );
    assert_eq!(r, vec![status::OK]);
    assert_eq!(
        get_info(&mut auth, &mut host).map_get_int(0x0C),
        Some(&Value::Bool(false))
    );
    let r = send_untouched(
        &mut auth,
        &mut host,
        &platform.token_request("24680", perm::MC, None),
    );
    assert_eq!(status_of(&r), status::OK);
}

#[test]
fn change_pin_flow_errors_and_token_invalidation() {
    // CTAP 2.1 §6.5.5.6.
    for protocol in PROTOCOLS {
        let (mut auth, mut host) = device();
        let mut platform = Platform::connect(&mut auth, &mut host, protocol);
        let r = send_untouched(
            &mut auth,
            &mut host,
            &platform.change_pin_request(PIN, b"5678"),
        );
        assert_eq!(r, vec![status::PIN_NOT_SET]);
        set_pin(&mut auth, &mut host, protocol, PIN);
        let t = token(&mut auth, &mut host, protocol, perm::GA | perm::MC, None);
        let mut platform = Platform::connect(&mut auth, &mut host, protocol);
        // A bad pinUvAuthParam is refused before any retry is consumed.
        let pin_hash_enc = platform.pin_hash_enc(PIN);
        let new_pin_enc = platform.new_pin_enc(b"5678");
        let wrong_mac = platform.mac_shared(&[pin_hash_enc.as_slice(), &new_pin_enc].concat());
        let bad = client_pin(Some(protocol), sub::CHANGE_PIN)
            .with(3, platform.cose_key())
            .with(6, pin_hash_enc)
            .with(5, new_pin_enc)
            .with(4, wrong_mac)
            .request();
        assert_eq!(
            send_untouched(&mut auth, &mut host, &bad),
            vec![status::PIN_AUTH_INVALID]
        );
        let missing = client_pin(Some(protocol), sub::CHANGE_PIN)
            .with(3, platform.cose_key())
            .with(6, platform.pin_hash_enc(PIN))
            .request();
        assert_eq!(
            send_untouched(&mut auth, &mut host, &missing),
            vec![status::MISSING_PARAMETER]
        );
        assert_eq!(persisted_state(&host).pin.retries, 8);
        // A correct old PIN with a too short new one: retries restored, PIN unchanged.
        let r = send_untouched(
            &mut auth,
            &mut host,
            &platform.change_pin_request(PIN, b"12"),
        );
        assert_eq!(r, vec![status::PIN_POLICY_VIOLATION]);
        assert_eq!(persisted_state(&host).pin.retries, 8);
        assert_eq!(
            persisted_state(&host).pin.hash.unwrap()[..],
            sha256(PIN.as_bytes())[..16]
        );
        // Wrong old PIN.
        let r = send_untouched(
            &mut auth,
            &mut host,
            &platform.change_pin_request("0000", b"5678"),
        );
        assert_eq!(r, vec![status::PIN_INVALID]);
        assert_eq!(persisted_state(&host).pin.retries, 7);
        let mut platform = Platform::connect(&mut auth, &mut host, protocol);
        let r = send_untouched(
            &mut auth,
            &mut host,
            &platform.change_pin_request(PIN, b"5678"),
        );
        assert_eq!(r, vec![status::OK]);
        assert_eq!(persisted_state(&host).pin.retries, 8);
        // The old token is gone; the old PIN no longer works; the new one does.
        let r = send(
            &mut auth,
            &mut host,
            &Ga::new().rp(RP).with_token(&t).encode(),
        );
        assert_eq!(r, vec![status::PIN_AUTH_INVALID]);
        assert_eq!(token_status(&mut auth, &mut host, PIN), status::PIN_INVALID);
        let mut platform = Platform::connect(&mut auth, &mut host, 2);
        let r = send_untouched(
            &mut auth,
            &mut host,
            &platform.token_request("5678", perm::GA, None),
        );
        assert_eq!(status_of(&r), status::OK);
    }
}

#[test]
fn permissions_are_checked_at_issuance() {
    // CTAP 2.1 §6.5.5.7.2 steps 3-4: zero → INVALID_PARAMETER; bioEnrollment (no bioEnroll
    // in GetInfo) → UNAUTHORIZED_PERMISSION; §6.5.5.7.1 steps 3-4: getPinToken with
    // permissions or rpId → INVALID_PARAMETER. None of these consume a retry.
    let (mut auth, mut host) = device_with_pin(2);
    let mut platform = Platform::connect(&mut auth, &mut host, 2);
    for (permissions, want) in [
        (0u8, status::INVALID_PARAMETER),
        (perm::BE, status::UNAUTHORIZED_PERMISSION),
        (perm::GA | perm::BE, status::UNAUTHORIZED_PERMISSION),
        (perm::BE | 0x40, status::UNAUTHORIZED_PERMISSION),
    ] {
        let r = send_untouched(
            &mut auth,
            &mut host,
            &platform.token_request(PIN, permissions, None),
        );
        assert_eq!(r, vec![want], "{permissions:#x}");
    }
    let enc = platform.pin_hash_enc(PIN);
    for extra in [(9i64, Value::from(1u8)), (0x0A, Value::from(RP))] {
        let r = send_untouched(
            &mut auth,
            &mut host,
            &client_pin(Some(2), sub::GET_PIN_TOKEN)
                .with(3, platform.cose_key())
                .with(6, enc.clone())
                .with(extra.0, extra.1)
                .request(),
        );
        assert_eq!(r, vec![status::INVALID_PARAMETER]);
    }
    let r = send_untouched(
        &mut auth,
        &mut host,
        &client_pin(Some(2), sub::GET_TOKEN_WITH_PERMISSIONS)
            .with(3, platform.cose_key())
            .with(6, enc)
            .request(),
    );
    assert_eq!(
        r,
        vec![status::MISSING_PARAMETER],
        "permissions are required"
    );
    assert_eq!(persisted_state(&host).pin.retries, 8);
    // Without a PIN: PIN_NOT_SET.
    let (mut auth, mut host) = device();
    assert_eq!(token_status(&mut auth, &mut host, PIN), status::PIN_NOT_SET);
}

#[test]
fn undefined_permission_bits_are_ignored() {
    // CTAP 2.1 §6.5.5.7.2: step 3 refuses only the value 0, step 4 only defined permissions
    // whose feature is absent, and step 14 assigns the requested permissions "ignoring
    // undefined ones". RFU bits 0x40, 0x80 and above 0xFF therefore neither fail the request
    // nor grant anything.
    let (mut auth, mut host) = device_with_pin(2);
    let reg = register(&mut auth, &mut host, &Mc::new());
    let ga = |t: &Token| Ga::new().allow(vec![reg.id()]).with_token(t);
    for permissions in [0x40u64, 0x80, 0x100, 0xC0 | u64::from(perm::GA), 0x1_0002] {
        let mut platform = Platform::connect(&mut auth, &mut host, 2);
        let enc = platform.pin_hash_enc(PIN);
        let r = send_untouched(
            &mut auth,
            &mut host,
            &client_pin(Some(2), sub::GET_TOKEN_WITH_PERMISSIONS)
                .with(3, platform.cose_key())
                .with(6, enc)
                .with(9, permissions)
                .request(),
        );
        assert_eq!(status_of(&r), status::OK, "{permissions:#x}");
        let t = platform.token_from(&r);
        let r = send(&mut auth, &mut host, &ga(&t).encode());
        if permissions & u64::from(perm::GA) != 0 {
            let a = parse_assertion(&r);
            assert_eq!(a.auth_data.flags, 0x05, "UP and UV with the ga permission");
        } else {
            assert_eq!(
                r,
                vec![status::PIN_AUTH_INVALID],
                "{permissions:#x} grants nothing"
            );
        }
    }
}

#[test]
fn tokens_need_the_permission_and_rp_they_were_issued_for() {
    // CTAP 2.1 §6.1.2 step 11 / §6.2.2 step 6: mc / ga permission and the permissions RP ID.
    let (mut auth, mut host) = device_with_pin(2);
    let reg = register(&mut auth, &mut host, &Mc::new());
    let ga_only = token(&mut auth, &mut host, 2, perm::GA, None);
    let r = send(
        &mut auth,
        &mut host,
        &Mc::new().with_token(&ga_only).encode(),
    );
    assert_eq!(r, vec![status::PIN_AUTH_INVALID], "no mc permission");
    let scoped = token(&mut auth, &mut host, 2, perm::MC | perm::GA, Some(RP));
    let r = send(
        &mut auth,
        &mut host,
        &Mc::new().rp("other.example").with_token(&scoped).encode(),
    );
    assert_eq!(r, vec![status::PIN_AUTH_INVALID], "other RP");
    let r = send(
        &mut auth,
        &mut host,
        &Ga::new()
            .allow(vec![reg.id()])
            .with_token(&scoped)
            .option("up", false)
            .encode(),
    );
    assert_eq!(status_of(&r), status::OK);
    // An unbound token binds to the first RP it is used with (§6.1.2 step 11.5).
    let unbound = token(&mut auth, &mut host, 2, perm::GA, None);
    let silent = |rp: &str| {
        Ga::new()
            .rp(rp)
            .allow(vec![reg.id()])
            .with_token(&unbound)
            .option("up", false)
            .encode()
    };
    assert_eq!(
        status_of(&send(&mut auth, &mut host, &silent(RP))),
        status::OK
    );
    assert_eq!(
        send(&mut auth, &mut host, &silent("other.example")),
        vec![status::PIN_AUTH_INVALID]
    );
    assert_eq!(
        status_of(&send(&mut auth, &mut host, &silent(RP))),
        status::OK
    );
}

#[test]
fn user_presence_consumes_the_token_except_large_blob_write() {
    // CTAP 2.1 §6.1.2 step 14 / §6.2.2 step 9: clearUserVerifiedFlag() and
    // clearPinUvAuthTokenPermissionsExceptLbw() after user presence; "up": false does not
    // consume the token.
    let (mut auth, mut host) = device_with_pin(1);
    let reg = register(&mut auth, &mut host, &Mc::new());
    let t = token(
        &mut auth,
        &mut host,
        1,
        perm::GA | perm::MC | perm::LBW,
        Some(RP),
    );
    let silent = Ga::new()
        .allow(vec![reg.id()])
        .with_token(&t)
        .option("up", false);
    for _ in 0..2 {
        let a = assert(&mut auth, &mut host, &silent);
        assert_eq!(a.auth_data.flags, 0x04, "UV without UP");
    }
    let a = assert(
        &mut auth,
        &mut host,
        &Ga::new().allow(vec![reg.id()]).with_token(&t),
    );
    assert_eq!(a.auth_data.flags, 0x05);
    let r = send(&mut auth, &mut host, &silent.encode());
    assert_eq!(r, vec![status::PIN_AUTH_INVALID], "ga consumed");
    let r = send(&mut auth, &mut host, &Mc::new().with_token(&t).encode());
    assert_eq!(r, vec![status::PIN_AUTH_INVALID], "mc cleared too");
    // lbw survives: the large-blob write is authorized (CTAP 2.1 §6.10.2).
    let r = super::large_blobs::write_fragment(
        &mut auth,
        &mut host,
        &crate::state::INITIAL_LARGE_BLOB,
        0,
        Some(17),
        Some(&t),
    );
    assert_eq!(r, vec![status::OK]);
    // A declined touch leaves the token usable.
    let t = token(&mut auth, &mut host, 1, perm::MC, None);
    let mc = Mc::new().with_token(&t).encode();
    assert_eq!(
        send_resolved(&mut auth, &mut host, &mc, false),
        vec![status::OPERATION_DENIED]
    );
    assert_eq!(status_of(&send(&mut auth, &mut host, &mc)), status::OK);
}

#[test]
fn tokens_are_bound_to_their_protocol_and_expire() {
    // CTAP 2.1 §6.5.2.1: initial usage time limit (30 s) and max usage time period
    // (10 min); a token is used with the protocol it was obtained with; power cycle and a
    // new issuance (resetPinUvAuthToken) discard it.
    let (mut auth, mut host) = device_with_pin(2);
    let reg = register(&mut auth, &mut host, &Mc::new());
    let silent = |t: &platform::Token| {
        Ga::new()
            .allow(vec![reg.id()])
            .with_token(t)
            .option("up", false)
            .encode()
    };
    let t2 = token(&mut auth, &mut host, 2, perm::GA, None);
    let as_v1 = platform::Token {
        protocol: 1,
        value: t2.value.clone(),
    };
    assert_eq!(
        send(&mut auth, &mut host, &silent(&as_v1)),
        vec![status::PIN_AUTH_INVALID]
    );
    // Unused for longer than the initial usage time limit.
    host.advance(30_001);
    assert_eq!(
        send(&mut auth, &mut host, &silent(&t2)),
        vec![status::PIN_AUTH_INVALID]
    );
    // Used in time, it lasts up to the max usage time period.
    let t = token(&mut auth, &mut host, 2, perm::GA, None);
    host.advance(29_000);
    assert_eq!(
        status_of(&send(&mut auth, &mut host, &silent(&t))),
        status::OK
    );
    host.advance(560_000);
    assert_eq!(
        status_of(&send(&mut auth, &mut host, &silent(&t))),
        status::OK
    );
    host.advance(12_000);
    assert_eq!(
        send(&mut auth, &mut host, &silent(&t)),
        vec![status::PIN_AUTH_INVALID]
    );
    // A new token replaces the old one.
    let a = token(&mut auth, &mut host, 2, perm::GA, None);
    let b = token(&mut auth, &mut host, 1, perm::GA, None);
    assert_eq!(
        send(&mut auth, &mut host, &silent(&a)),
        vec![status::PIN_AUTH_INVALID]
    );
    assert_eq!(
        status_of(&send(&mut auth, &mut host, &silent(&b))),
        status::OK
    );
    auth.power_cycle(&mut host);
    assert_eq!(
        send(&mut auth, &mut host, &silent(&b)),
        vec![status::PIN_AUTH_INVALID]
    );
}

#[test]
fn a_pin_requires_a_token_for_discoverable_credentials_and_reveals_user_details_with_uv() {
    // CTAP 2.1 §6.1.2 step 7 (makeCredUvNotRqd: rk needs a pinUvAuthToken when a PIN is
    // set) and §6.2.2 response "user" (name/displayName only with UV and several
    // accounts).
    let (mut auth, mut host) = device_with_pin(2);
    let r = send_untouched(&mut auth, &mut host, &Mc::new().rk().encode());
    assert_eq!(r, vec![status::PUAT_REQUIRED]);
    assert_eq!(
        register(&mut auth, &mut host, &Mc::new()).auth_data.flags & 0x04,
        0,
        "no UV"
    );
    for user in [&b"u1"[..], b"u2"] {
        let t = token(&mut auth, &mut host, 2, perm::MC, Some(RP));
        let mut mc = Mc::new().rk().user(user).with_token(&t);
        mc.user_name = Some(String::from_utf8(user.to_vec()).unwrap());
        let reg = register(&mut auth, &mut host, &mc);
        assert_eq!(reg.auth_data.flags & 0x04, 0x04, "UV");
    }
    let t = token(&mut auth, &mut host, 2, perm::GA, Some(RP));
    let a = assert(&mut auth, &mut host, &Ga::new().with_token(&t));
    assert_eq!(a.count, Some(2));
    let user = a.user.unwrap();
    assert_eq!(
        user.map_get_text("id").and_then(Value::as_bytes),
        Some(&b"u2"[..])
    );
    assert_eq!(
        user.map_get_text("name").and_then(Value::as_text),
        Some("u2")
    );
    assert_eq!(
        user.map_get_text("displayName").and_then(Value::as_text),
        Some("u2 display")
    );
    let next = parse_assertion(&send_untouched(&mut auth, &mut host, &[0x08]));
    assert_eq!(
        next.user
            .unwrap()
            .map_get_text("name")
            .and_then(Value::as_text),
        Some("u1")
    );
    assert_eq!(next.auth_data.flags, 0x05);
    // Without UV only the id is returned.
    let a = assert(&mut auth, &mut host, &Ga::new());
    assert_eq!(a.user.unwrap().as_map().unwrap().len(), 1);
}

#[test]
fn reset_clears_the_pin_and_the_token() {
    // CTAP 2.1 §6.6: reset removes the PIN; volatile token state goes with it.
    let (mut auth, mut host) = device_with_pin(2);
    let t = token(&mut auth, &mut host, 2, perm::MC, None);
    assert_eq!(send(&mut auth, &mut host, &[0x07]), vec![status::OK]);
    let state = persisted_state(&host);
    assert!(!state.pin_is_set());
    assert_eq!(state.pin.retries, 8);
    let r = send(&mut auth, &mut host, &Mc::new().with_token(&t).encode());
    assert_eq!(r, vec![status::PIN_NOT_SET]);
    set_pin(&mut auth, &mut host, 2, PIN);
    let r = send(&mut auth, &mut host, &Mc::new().with_token(&t).encode());
    assert_eq!(r, vec![status::PIN_AUTH_INVALID]);
}

/// A way to obtain a pinUvAuthToken.
type IssueToken<'a> = dyn Fn(&mut Authenticator, &mut TestHost) -> Token + 'a;

#[test]
fn a_pin_issued_token_never_stands_in_for_a_touch() {
    // CTAP 2.1 §6.5.5.7.1 and §6.5.5.7.2 call beginUsingPinUvAuthToken(userIsPresent:
    // false), so getUserPresentFlagValue() (§6.5.3.2) is false for every token here:
    // makeCredential (§6.1.2 step 14.1.1), getAssertion (§6.2.2 step 9.1.1) and an
    // excludeList hit (§6.1.2 step 12.1.4) must all wait for a touch even with a fresh
    // token, whichever subcommand issued it.
    for protocol in PROTOCOLS {
        let (mut auth, mut host) = device_with_pin(protocol);
        let reg = register(&mut auth, &mut host, &Mc::new());
        let legacy = |auth: &mut Authenticator, host: &mut TestHost| {
            let mut platform = Platform::connect(auth, host, protocol);
            let r = send_untouched(auth, host, &platform.pin_token_request(PIN));
            platform.token_from(&r)
        };
        let with_permissions = |auth: &mut Authenticator, host: &mut TestHost| {
            token(auth, host, protocol, perm::MC | perm::GA, Some(RP))
        };
        let issuers: [&IssueToken<'_>; 2] = [&legacy, &with_permissions];
        for issue in issuers {
            let t = issue(&mut auth, &mut host);
            let mc = Mc::new().with_token(&t).encode();
            assert!(
                matches!(auth.cbor(&mc, &mut host), Outcome::NeedTouch { .. }),
                "makeCredential"
            );
            assert_eq!(
                status_of(&auth.presence_resolved(true, &mut host)),
                status::OK
            );

            let t = issue(&mut auth, &mut host);
            let ga = Ga::new().allow(vec![reg.id()]).with_token(&t).encode();
            assert!(
                matches!(auth.cbor(&ga, &mut host), Outcome::NeedTouch { .. }),
                "getAssertion"
            );
            let a = parse_assertion(&auth.presence_resolved(true, &mut host));
            assert_eq!(
                a.auth_data.flags, 0x05,
                "UP from the touch, UV from the token"
            );

            let t = issue(&mut auth, &mut host);
            let excluded = Mc::new().exclude(vec![reg.id()]).with_token(&t).encode();
            assert!(
                matches!(auth.cbor(&excluded, &mut host), Outcome::NeedTouch { .. }),
                "excludeList hit"
            );
            assert_eq!(
                auth.presence_resolved(true, &mut host),
                vec![status::CREDENTIAL_EXCLUDED]
            );
        }
    }
}
