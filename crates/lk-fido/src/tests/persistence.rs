//! Persistence (docs/CONTRACTS.md "Persisted state", docs/DESIGN.md §7), reset (CTAP 2.1
//! §6.6), selection (§6.9) and the pending-command lifecycle.

use super::*;
use crate::{RESET_WINDOW_MS, status};

#[test]
fn state_round_trips_through_a_restart() {
    // DESIGN §7: credentials, counter and keys survive; non-resident IDs keep working
    // (BEHAVIOR_CATALOG FIDO: "independent SDK signature verification across restart").
    let (mut auth, mut host) = device();
    let resident = register(
        &mut auth,
        &mut host,
        &Mc::new().rk().alg(-35).ext("credBlob", vec![1, 2, 3]),
    );
    let plain = register(&mut auth, &mut host, &Mc::new().alg(-8));
    assert_eq!(
        assert(&mut auth, &mut host, &Ga::new().allow(vec![plain.id()]))
            .auth_data
            .counter,
        1
    );

    let mut auth = restart(&mut host);
    let info = get_info(&mut auth, &mut host);
    assert_eq!(info.map_get_int(0x14).and_then(Value::as_u64), Some(99));
    let a = assert(&mut auth, &mut host, &Ga::new().ext("credBlob", true));
    assert!(a.verifies_with(&resident.public_key()));
    assert_eq!(a.auth_data.counter, 2);
    assert_eq!(
        a.auth_data.extensions,
        Some(
            MapBuilder::new()
                .insert("credBlob", vec![1u8, 2, 3])
                .build()
        )
    );
    assert!(
        assert(&mut auth, &mut host, &Ga::new().allow(vec![plain.id()]))
            .verifies_with(&plain.public_key())
    );
    // The attestation identity is stable across restarts.
    assert_eq!(
        register(&mut auth, &mut host, &Mc::new()).cert(),
        plain.cert()
    );
}

#[test]
fn storage_failure_on_resident_registration_keeps_previous_state() {
    // docs/CONTRACTS.md: persist before success; on Err keep the previous in-memory state
    // and answer CTAP1_ERR_OTHER.
    let (mut auth, mut host) = device();
    register(&mut auth, &mut host, &Mc::new().rk().user(b"first"));
    let before = host.persisted(Record::Fido);
    host.fail_next_saves(1);
    assert_eq!(
        send(
            &mut auth,
            &mut host,
            &Mc::new().rk().user(b"second").encode()
        ),
        vec![status::OTHER]
    );
    assert_eq!(host.persisted(Record::Fido), before);
    let info = get_info(&mut auth, &mut host);
    assert_eq!(
        info.map_get_int(0x14).and_then(Value::as_u64),
        Some(99),
        "in-memory state unchanged"
    );
    let a = assert(&mut auth, &mut host, &Ga::new());
    assert_eq!(a.count, None, "the failed credential does not exist");
    register(&mut auth, &mut host, &Mc::new().rk().user(b"second"));
    assert_eq!(persisted_state(&host).residents.len(), 2);
}

#[test]
fn storage_failure_on_first_use_keeps_the_device_uninitialized() {
    // The first registration creates the wrapping secret and attestation identity; an ID
    // must never be revealed under a secret that was not stored.
    let (mut auth, mut host) = device();
    host.fail_next_saves(1);
    assert_eq!(
        send(&mut auth, &mut host, &Mc::new().encode()),
        vec![status::OTHER]
    );
    assert_eq!(host.persisted(Record::Fido), None);
    let reg = register(&mut auth, &mut host, &Mc::new());
    let mut auth = restart(&mut host);
    assert!(
        assert(&mut auth, &mut host, &Ga::new().allow(vec![reg.id()]))
            .verifies_with(&reg.public_key())
    );
}

#[test]
fn unreadable_state_is_factory_state() {
    // lk_core::CardApplet constructor convention: unreadable state = factory state.
    for stored in [
        vec![],
        vec![0x02, 0x00],
        vec![0x01, 0x81, 0x05, 0x00],
        vec![0xFF; 40],
    ] {
        let mut host = TestHost::new();
        let mut auth = Authenticator::new(Some(&stored), &mut host);
        let info = get_info(&mut auth, &mut host);
        assert_eq!(info.map_get_int(0x14).and_then(Value::as_u64), Some(100));
        assert_eq!(register(&mut auth, &mut host, &Mc::new()).fmt, "packed");
    }
}

#[test]
fn reset_wipes_everything_rotates_the_secret_and_keeps_attestation() {
    // CTAP 2.1 §6.6 (touch within 10 s of power-up); BEHAVIOR_CATALOG FIDO "reset rotates
    // root"; PIN and configuration return to factory values.
    let (mut auth, mut host) = device();
    let resident = register(&mut auth, &mut host, &Mc::new().rk());
    let plain = register(&mut auth, &mut host, &Mc::new());
    assert(&mut auth, &mut host, &Ga::new().allow(vec![plain.id()]));
    let mut auth = with_state(&mut host, |s| {
        s.pin.hash = Some(SecretBytes::from_slice(&[1; 16]));
        s.pin.min_length = 8;
        s.pin.min_pin_rp_ids = vec!["x".into()];
    });
    let secret_before = persisted_state(&host).secret;

    host.advance(RESET_WINDOW_MS);
    assert_eq!(
        send_resolved(&mut auth, &mut host, &[0x07], true),
        vec![status::OK]
    );
    let state = persisted_state(&host);
    assert_ne!(state.secret, secret_before);
    assert!(state.secret.is_some());
    assert_eq!(state.counter, 0);
    assert!(state.residents.is_empty());
    assert_eq!(state.pin, crate::state::PinState::default());

    let info = get_info(&mut auth, &mut host);
    assert_eq!(info.map_get_int(0x14).and_then(Value::as_u64), Some(100));
    assert_eq!(
        info.map_get_int(4).unwrap().map_get_text("clientPin"),
        Some(&Value::Bool(false))
    );
    for ga in [
        Ga::new().allow(vec![plain.id()]),
        Ga::new().allow(vec![resident.id()]),
        Ga::new(),
    ] {
        assert_eq!(
            send_untouched(&mut auth, &mut host, &ga.encode()),
            vec![status::NO_CREDENTIALS]
        );
    }
    assert_eq!(
        register(&mut auth, &mut host, &Mc::new()).cert(),
        plain.cert(),
        "attestation kept"
    );
}

#[test]
fn reset_outside_the_power_up_window_is_not_allowed() {
    // CTAP 2.1 §6.6: "If the request comes after 10 seconds of powering up, the
    // authenticator returns CTAP2_ERR_NOT_ALLOWED"; power_cycle restarts the window.
    let (mut auth, mut host) = device();
    host.set_now(RESET_WINDOW_MS + 1);
    assert_eq!(
        send_untouched(&mut auth, &mut host, &[0x07]),
        vec![status::NOT_ALLOWED]
    );
    auth.power_cycle(&mut host);
    host.advance(9_999);
    assert_eq!(
        send_resolved(&mut auth, &mut host, &[0x07], true),
        vec![status::OK]
    );
    // Construction counts as power-up.
    host.advance(60_000);
    let mut auth = restart(&mut host);
    assert_eq!(
        send_resolved(&mut auth, &mut host, &[0x07], true),
        vec![status::OK]
    );
}

#[test]
fn reset_timeout_and_storage_failure_keep_state() {
    // CTAP 2.1 §6.6: "If a user action timeout occurs, the authenticator returns
    // CTAP2_ERR_USER_ACTION_TIMEOUT"; storage failure → CTAP1_ERR_OTHER, state kept.
    let (mut auth, mut host) = device();
    let reg = register(&mut auth, &mut host, &Mc::new().rk());
    assert_eq!(
        send_resolved(&mut auth, &mut host, &[0x07], false),
        vec![status::USER_ACTION_TIMEOUT]
    );
    host.fail_next_saves(1);
    assert_eq!(
        send_resolved(&mut auth, &mut host, &[0x07], true),
        vec![status::OTHER]
    );
    assert!(assert(&mut auth, &mut host, &Ga::new()).verifies_with(&reg.public_key()));
    assert!(matches!(
        auth.cbor(&[0x07], &mut host),
        Outcome::NeedTouch { .. }
    ));
    assert_eq!(auth.cancel(&mut host), Some(vec![status::KEEPALIVE_CANCEL]));
    assert_eq!(persisted_state(&host).residents.len(), 1);
}

#[test]
fn selection_waits_for_a_touch() {
    // CTAP 2.1 §6.9: CTAP2_OK on touch, CTAP2_ERR_USER_ACTION_TIMEOUT on timeout.
    let (mut auth, mut host) = device();
    assert_eq!(
        send_resolved(&mut auth, &mut host, &[0x0B], true),
        vec![status::OK]
    );
    assert_eq!(
        send_resolved(&mut auth, &mut host, &[0x0B], false),
        vec![status::USER_ACTION_TIMEOUT]
    );
    assert_eq!(host.persist_attempts(), 0);
}

#[test]
fn touch_timeout_is_the_measured_28_5_seconds() {
    // docs/MEASUREMENT.md, probe selection-no-touch: selection without a touch is answered
    // CTAP2_ERR_USER_ACTION_TIMEOUT 28 451.8 ms after the request, after 300 KEEPALIVEs;
    // the engine waits 28 500 ms = 300 x 95 ms (lk-device KEEPALIVE_INTERVAL_MS). It was
    // the model policy 30 000 ms before the measurement.
    assert_eq!(crate::TOUCH_TIMEOUT_MS, 28_500);
    let (mut auth, mut host) = device();
    assert_eq!(
        auth.cbor(&[0x0B], &mut host),
        Outcome::NeedTouch { timeout_ms: 28_500 }
    );
    assert_eq!(
        auth.presence_resolved(false, &mut host),
        vec![status::USER_ACTION_TIMEOUT]
    );
}

#[test]
fn power_cycle_drops_a_waiting_command() {
    // docs/CONTRACTS.md power_cycle; lk_core::Outcome::NeedTouch ("the session is reset").
    let (mut auth, mut host) = device();
    assert!(matches!(
        auth.cbor(&Mc::new().encode(), &mut host),
        Outcome::NeedTouch { .. }
    ));
    auth.power_cycle(&mut host);
    assert!(!auth.is_pending());
    assert_eq!(
        auth.presence_resolved(true, &mut host),
        vec![status::NOT_ALLOWED]
    );
    assert_eq!(auth.cancel(&mut host), None);
    assert_eq!(host.persist_attempts(), 0);
}

#[test]
fn debug_output_hides_secrets() {
    let (mut auth, mut host) = device();
    register(&mut auth, &mut host, &Mc::new());
    super::platform::set_pin(&mut auth, &mut host, 2, super::platform::PIN);
    let token = super::platform::token(&mut auth, &mut host, 2, 0x01, None);
    let state = persisted_state(&host);
    let text = format!("{auth:?}");
    assert!(text.contains("Authenticator"));
    assert!(text.contains("token_in_use: true"));
    let secret = state.secret.unwrap();
    let pin_hash = state.pin.hash.unwrap();
    for hidden in [&secret[..4], &pin_hash[..4], &token.value[..4]] {
        assert!(!text.contains(&format!("{hidden:?}")), "{text}");
        let hex: String = hidden.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!text.contains(&hex), "{text}");
    }
}

#[test]
fn cancel_ends_every_kind_of_waiting_command_without_side_effects() {
    // CTAP 2.1 §11.2.9.1.5 CTAPHID_CANCEL: the waiting command ends with
    // CTAP2_ERR_KEEPALIVE_CANCEL (docs/CONTRACTS.md cancel). A cancelled command changes
    // nothing: no state is persisted, no counter advances, and a pinUvAuthToken is not
    // consumed (§6.1.2 step 14.4 / §6.2.2 step 9 run only after user presence). Afterwards
    // nothing is pending: a late presence_resolved is NOT_ALLOWED and a second cancel None.
    use super::platform::{PIN, perm, set_pin, token};
    let (mut auth, mut host) = device();
    let excluded = register(&mut auth, &mut host, &Mc::new());
    register(&mut auth, &mut host, &Mc::new().rk().user(b"r"));
    set_pin(&mut auth, &mut host, 2, PIN);
    let t = token(&mut auth, &mut host, 2, perm::MC | perm::GA, None);
    let waiting: Vec<(&str, Vec<u8>)> = vec![
        ("pin probe", {
            let mut mc = Mc::new();
            mc.pin_param = Some(Vec::new());
            mc.pin_protocol = Some(2);
            mc.encode()
        }),
        ("excluded", Mc::new().exclude(vec![excluded.id()]).encode()),
        (
            "makeCredential",
            Mc::new().rk().user(b"new").with_token(&t).encode(),
        ),
        ("getAssertion", Ga::new().with_token(&t).encode()),
        ("reset", vec![0x07]),
        ("selection", vec![0x0B]),
    ];
    let before = host.persisted(Record::Fido);
    let attempts = host.persist_attempts();
    for (name, request) in &waiting {
        assert!(
            matches!(auth.cbor(request, &mut host), Outcome::NeedTouch { .. }),
            "{name}"
        );
        assert!(auth.is_pending());
        // Other requests are refused while it waits and do not disturb it.
        assert_eq!(
            auth.cbor(&[0x04], &mut host),
            Outcome::Done(vec![status::CHANNEL_BUSY])
        );
        assert_eq!(
            auth.u2f(&[0x00, 0x03, 0x00, 0x00], true, &mut host),
            (vec![0x69, 0x85], crate::U2fPresence::NotNeeded)
        );
        assert!(auth.is_pending());
        assert_eq!(
            auth.cancel(&mut host),
            Some(vec![status::KEEPALIVE_CANCEL]),
            "{name}"
        );
        assert!(!auth.is_pending());
        assert_eq!(auth.cancel(&mut host), None);
        assert_eq!(
            auth.presence_resolved(true, &mut host),
            vec![status::NOT_ALLOWED]
        );
    }
    assert_eq!(host.persisted(Record::Fido), before);
    assert_eq!(host.persist_attempts(), attempts);
    // The token survived both cancelled uses.
    let made = register(
        &mut auth,
        &mut host,
        &Mc::new().rk().user(b"new").with_token(&t),
    );
    assert_eq!(made.auth_data.flags & 0x05, 0x05);
}
