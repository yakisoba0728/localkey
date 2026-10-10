//! authenticatorGetAssertion (CTAP 2.1 §6.2) and authenticatorGetNextAssertion (§6.3).

use super::*;
use crate::status;

#[test]
fn shared_counter_advances_and_is_persisted_before_each_response() {
    // docs/DESIGN.md §7 (counters persisted before the response); legacy-v0.64-profiles.json
    // counter_policy ("starts at 1; persisted increment before UP response").
    let (mut auth, mut host) = device();
    let a = register(&mut auth, &mut host, &Mc::new().alg(-7));
    let b = register(&mut auth, &mut host, &Mc::new().alg(-35));
    for (i, reg) in [&a, &b, &a].into_iter().enumerate() {
        let assertion = assert(&mut auth, &mut host, &Ga::new().allow(vec![reg.id()]));
        let expected = u32::try_from(i + 1).unwrap();
        assert_eq!(assertion.auth_data.counter, expected);
        assert_eq!(
            persisted_state(&host).counter,
            expected,
            "persisted before the response"
        );
        assert_eq!(assertion.auth_data.flags, 0x01, "UP only");
        assert!(assertion.verifies_with(&reg.public_key()));
    }
    // Registration reports the current value without advancing it.
    assert_eq!(
        register(&mut auth, &mut host, &Mc::new()).auth_data.counter,
        3
    );
}

#[test]
fn present_empty_allow_list_is_no_credentials_without_touch_or_counter() {
    // CTAP 2.1 §6.2.2 step 7 (7.1 needs a non-empty list) and 7.6 before the touch;
    // BEHAVIOR_CATALOG FIDO: "explicitly present empty allowList returns NoCredentials
    // without consuming a signature counter".
    let (mut auth, mut host) = device();
    register(&mut auth, &mut host, &Mc::new().rk());
    let before = host.persisted(Record::Fido);
    let r = send_untouched(&mut auth, &mut host, &Ga::new().allow(vec![]).encode());
    assert_eq!(r, vec![status::NO_CREDENTIALS]);
    assert_eq!(host.persisted(Record::Fido), before);
    // An absent list still finds the discoverable credential.
    assert_eq!(
        assert(&mut auth, &mut host, &Ga::new()).auth_data.counter,
        1
    );
}

#[test]
fn foreign_and_unknown_credentials_are_no_credentials() {
    // CTAP 2.1 §6.2.2 step 7.1: only credentials "bound to the specified rpId".
    let (mut auth, mut host) = device();
    let reg = register(&mut auth, &mut host, &Mc::new());
    for ga in [
        Ga::new().rp("other.example").allow(vec![reg.id()]),
        Ga::new().allow(vec![vec![0; 128], vec![1; 16]]),
        Ga::new().rp("empty.example"),
    ] {
        assert_eq!(
            send_untouched(&mut auth, &mut host, &ga.encode()),
            vec![status::NO_CREDENTIALS]
        );
    }
    // Fresh device without any secret.
    let (mut fresh, mut host2) = device();
    assert_eq!(
        send_untouched(
            &mut fresh,
            &mut host2,
            &Ga::new().allow(vec![reg.id()]).encode()
        ),
        vec![status::NO_CREDENTIALS]
    );
}

#[test]
fn allow_list_selects_the_first_applicable_credential() {
    // CTAP 2.1 §6.2.2 step 11: "select any credential from the applicable credentials
    // list"; no numberOfCredentials with an allowList.
    let (mut auth, mut host) = device();
    let a = register(&mut auth, &mut host, &Mc::new());
    let b = register(&mut auth, &mut host, &Mc::new().alg(-8));
    let assertion = assert(
        &mut auth,
        &mut host,
        &Ga::new().allow(vec![vec![3; 128], b.id(), a.id()]),
    );
    assert_eq!(assertion.cred_id, b.id());
    assert_eq!(assertion.count, None);
    assert_eq!(
        send_untouched(&mut auth, &mut host, &[0x08]),
        vec![status::NOT_ALLOWED]
    );
}

#[test]
fn discoverable_credentials_newest_first_with_get_next_assertion() {
    // CTAP 2.1 §6.2.2 step 12.2.1 (reverse creation order), numberOfCredentials, user id
    // only without UV; §6.3 getNextAssertion serves the rest, then NOT_ALLOWED.
    let (mut auth, mut host) = device();
    let regs: Vec<Registration> = [b"A", b"B", b"C"]
        .iter()
        .map(|u| register(&mut auth, &mut host, &Mc::new().rk().user(*u)))
        .collect();
    register(&mut auth, &mut host, &Mc::new().rk().rp("other.example"));
    let first = assert(&mut auth, &mut host, &Ga::new());
    assert_eq!(first.count, Some(3));
    assert_eq!(first.cred_id, regs[2].id());
    assert_eq!(
        first.user,
        Some(MapBuilder::new().insert("id", b"C".to_vec()).build())
    );
    assert!(first.verifies_with(&regs[2].public_key()));
    for (i, reg) in [&regs[1], &regs[0]].into_iter().enumerate() {
        let next = parse_assertion(&send_untouched(&mut auth, &mut host, &[0x08]));
        assert_eq!(next.cred_id, reg.id());
        assert_eq!(next.count, None, "not in getNextAssertion responses");
        assert_eq!(next.auth_data.flags, 0x01, "UP of the original assertion");
        assert_eq!(next.auth_data.counter, u32::try_from(i + 2).unwrap());
        assert!(next.verifies_with(&reg.public_key()));
        assert!(next.user.is_some());
    }
    assert_eq!(
        send_untouched(&mut auth, &mut host, &[0x08]),
        vec![status::NOT_ALLOWED]
    );
}

#[test]
fn get_next_assertion_state_expires_and_is_cleared_by_other_commands() {
    // CTAP 2.1 §6.3 steps 1-3: no state → NOT_ALLOWED; more than 30 s → NOT_ALLOWED.
    let (mut auth, mut host) = device();
    assert_eq!(
        send_untouched(&mut auth, &mut host, &[0x08]),
        vec![status::NOT_ALLOWED]
    );
    register(&mut auth, &mut host, &Mc::new().rk().user(b"A"));
    register(&mut auth, &mut host, &Mc::new().rk().user(b"B"));

    assert_eq!(assert(&mut auth, &mut host, &Ga::new()).count, Some(2));
    host.advance(30_000);
    assert_eq!(
        status_of(&send_untouched(&mut auth, &mut host, &[0x08])),
        0,
        "exactly 30 s is still allowed"
    );

    assert_eq!(assert(&mut auth, &mut host, &Ga::new()).count, Some(2));
    host.advance(30_001);
    assert_eq!(
        send_untouched(&mut auth, &mut host, &[0x08]),
        vec![status::NOT_ALLOWED]
    );

    assert_eq!(assert(&mut auth, &mut host, &Ga::new()).count, Some(2));
    get_info(&mut auth, &mut host);
    assert_eq!(
        send_untouched(&mut auth, &mut host, &[0x08]),
        vec![status::NOT_ALLOWED]
    );

    assert_eq!(assert(&mut auth, &mut host, &Ga::new()).count, Some(2));
    auth.power_cycle(&mut host);
    assert_eq!(
        send_untouched(&mut auth, &mut host, &[0x08]),
        vec![status::NOT_ALLOWED]
    );
}

#[test]
fn single_discoverable_credential_has_no_count() {
    // CTAP 2.1 §6.2.2 response: numberOfCredentials only when more than one is found.
    let (mut auth, mut host) = device();
    register(&mut auth, &mut host, &Mc::new().rk());
    let a = assert(&mut auth, &mut host, &Ga::new());
    assert_eq!(a.count, None);
    assert!(a.user.is_some());
}

#[test]
fn cred_protect_is_enforced() {
    // CTAP 2.1 §6.2.2 steps 7.4 / 7.5 and §12.1: level 2 needs an allowList (or UV),
    // level 3 always needs UV.
    let (mut auth, mut host) = device();
    let l1 = register(
        &mut auth,
        &mut host,
        &Mc::new().rk().user(b"1").rp("one.example"),
    );
    let l2 = register(
        &mut auth,
        &mut host,
        &Mc::new()
            .rk()
            .user(b"2")
            .rp("two.example")
            .ext("credProtect", 2),
    );
    let l3 = register(
        &mut auth,
        &mut host,
        &Mc::new()
            .rk()
            .user(b"3")
            .rp("three.example")
            .ext("credProtect", 3),
    );
    let nr3 = register(
        &mut auth,
        &mut host,
        &Mc::new().rp("three.example").ext("credProtect", 3),
    );
    assert!(
        assert(&mut auth, &mut host, &Ga::new().rp("one.example")).verifies_with(&l1.public_key())
    );
    assert_eq!(
        send_untouched(&mut auth, &mut host, &Ga::new().rp("two.example").encode()),
        vec![status::NO_CREDENTIALS]
    );
    let a = assert(
        &mut auth,
        &mut host,
        &Ga::new().rp("two.example").allow(vec![l2.id()]),
    );
    assert!(a.verifies_with(&l2.public_key()));
    for ga in [
        Ga::new().rp("three.example"),
        Ga::new().rp("three.example").allow(vec![l3.id()]),
        Ga::new().rp("three.example").allow(vec![nr3.id()]),
    ] {
        assert_eq!(
            send_untouched(&mut auth, &mut host, &ga.encode()),
            vec![status::NO_CREDENTIALS]
        );
    }
}

#[test]
fn up_false_is_silent_and_leaves_the_up_flag_clear() {
    // CTAP 2.1 §6.2.2 step 4.5 / step 9: "up": false skips the presence test; the
    // signature counter still advances.
    let (mut auth, mut host) = device();
    let reg = register(&mut auth, &mut host, &Mc::new().alg(-8));
    let r = send_untouched(
        &mut auth,
        &mut host,
        &Ga::new().allow(vec![reg.id()]).option("up", false).encode(),
    );
    let a = parse_assertion(&r);
    assert_eq!(a.auth_data.flags, 0x00);
    assert_eq!(a.auth_data.counter, 1);
    assert!(a.verifies_with(&reg.public_key()));
}

#[test]
fn option_errors() {
    // CTAP 2.1 §6.2.2 step 4: "uv": true without built-in UV → INVALID_OPTION; "rk"
    // present → UNSUPPORTED_OPTION; option types (BEHAVIOR_CATALOG unknown options).
    let (mut auth, mut host) = device();
    let reg = register(&mut auth, &mut host, &Mc::new());
    let ga = Ga::new().allow(vec![reg.id()]);
    assert_eq!(
        send_untouched(
            &mut auth,
            &mut host,
            &ga.clone().option("uv", true).encode()
        ),
        vec![status::INVALID_OPTION]
    );
    assert_eq!(
        send_untouched(
            &mut auth,
            &mut host,
            &ga.clone().option("rk", false).encode()
        ),
        vec![status::UNSUPPORTED_OPTION]
    );
    assert_eq!(
        send_untouched(&mut auth, &mut host, &ga.clone().option("up", 0).encode()),
        vec![status::CBOR_UNEXPECTED_TYPE]
    );
    let a = assert(
        &mut auth,
        &mut host,
        &ga.clone()
            .option("zz", Value::Float(0x7E00, 2))
            .option("plat", "x"),
    );
    assert!(a.verifies_with(&reg.public_key()));
}

#[test]
fn parameter_errors() {
    // CTAP 2.1 §6.2.1: rpId and clientDataHash required; member types.
    let (mut auth, mut host) = device();
    let base = Ga::new().params();
    let ga_status = |auth: &mut Authenticator, host: &mut TestHost, p: &Value| {
        status_of(&send(auth, host, &encode_request(2, p)))
    };
    assert_eq!(
        ga_status(&mut auth, &mut host, &set_param(&base, 1, None)),
        status::MISSING_PARAMETER
    );
    assert_eq!(
        ga_status(&mut auth, &mut host, &set_param(&base, 2, None)),
        status::MISSING_PARAMETER
    );
    for (key, value) in [
        (1, Value::Bytes(vec![1])),
        (2, Value::from("x")),
        (3, Value::from("x")),
        (4, Value::from("x")),
        (5, Value::Array(vec![])),
        (6, Value::from("x")),
        (7, Value::Bool(true)),
    ] {
        assert_eq!(
            ga_status(&mut auth, &mut host, &set_param(&base, key, Some(value))),
            status::CBOR_UNEXPECTED_TYPE,
            "key {key}"
        );
    }
    let nine = Value::Array(vec![descriptor(&[1; 16]); 9]);
    assert_eq!(
        ga_status(&mut auth, &mut host, &set_param(&base, 3, Some(nine))),
        status::LIMIT_EXCEEDED
    );
    assert_eq!(
        status_of(&send(&mut auth, &mut host, &[0x02])),
        status::INVALID_CBOR
    );
    let mut probe = set_param(&base, 6, Some(Value::Bytes(vec![])));
    assert_eq!(
        status_of(&send_resolved(
            &mut auth,
            &mut host,
            &encode_request(2, &probe),
            true
        )),
        status::PIN_NOT_SET
    );
    probe = set_param(&base, 6, Some(Value::Bytes(vec![1; 32])));
    assert_eq!(
        ga_status(&mut auth, &mut host, &probe),
        status::MISSING_PARAMETER
    );
    probe = set_param(&probe, 7, Some(Value::Unsigned(9)));
    assert_eq!(
        ga_status(&mut auth, &mut host, &probe),
        status::INVALID_PARAMETER
    );
}

fn hmac_secret_input() -> Value {
    let key = MapBuilder::new()
        .insert(1, 2)
        .insert(3, -25)
        .insert(-1, 1)
        .insert(-2, vec![0u8; 32])
        .insert(-3, vec![0u8; 32])
        .build();
    MapBuilder::new()
        .insert(1, key)
        .insert(2, vec![0u8; 32])
        .insert(3, vec![0u8; 16])
        .insert(4, 1)
        .build()
}

#[test]
fn hmac_secret_with_up_false_is_unsupported_option_without_counter() {
    // CTAP 2.1 §12.5 ("If "up" is set to false, authenticator returns
    // CTAP2_ERR_UNSUPPORTED_OPTION"); BEHAVIOR_CATALOG FIDO: "without advancing the
    // signature counter".
    let (mut auth, mut host) = device();
    let reg = register(&mut auth, &mut host, &Mc::new().ext("hmac-secret", true));
    let before = host.persisted(Record::Fido);
    let ga = Ga::new()
        .allow(vec![reg.id()])
        .ext("hmac-secret", hmac_secret_input())
        .option("up", false);
    assert_eq!(
        send_untouched(&mut auth, &mut host, &ga.encode()),
        vec![status::UNSUPPORTED_OPTION]
    );
    assert_eq!(host.persisted(Record::Fido), before);
    // Malformed input is rejected by type.
    let missing = MapBuilder::new()
        .insert(1, MapBuilder::new().build())
        .insert(3, vec![0u8; 16])
        .build();
    let r = send(
        &mut auth,
        &mut host,
        &Ga::new()
            .allow(vec![reg.id()])
            .ext("hmac-secret", missing)
            .encode(),
    );
    assert_eq!(r, vec![status::MISSING_PARAMETER]);
    let r = send(
        &mut auth,
        &mut host,
        &Ga::new()
            .allow(vec![reg.id()])
            .ext("hmac-secret", true)
            .encode(),
    );
    assert_eq!(r, vec![status::CBOR_UNEXPECTED_TYPE]);
    // With "up" the all-zero keyAgreement is decapsulated and is not a P-256 point
    // (§12.5 / §6.5.6 decapsulate → CTAP1_ERR_INVALID_PARAMETER), still without a touch;
    // valid inputs are covered in `tests::hmac_secret`.
    let r = send_untouched(
        &mut auth,
        &mut host,
        &Ga::new()
            .allow(vec![reg.id()])
            .ext("hmac-secret", hmac_secret_input())
            .encode(),
    );
    assert_eq!(r, vec![status::INVALID_PARAMETER]);
    assert_eq!(host.persisted(Record::Fido), before);
}

#[test]
fn cred_blob_and_large_blob_key_outputs() {
    // CTAP 2.1 §12.2 (stored blob, or an empty byte string) and §12.3 (key 0x07; value
    // false → INVALID_OPTION).
    let (mut auth, mut host) = device();
    let resident = register(
        &mut auth,
        &mut host,
        &Mc::new()
            .rk()
            .ext("credBlob", vec![0xCB; 5])
            .ext("largeBlobKey", true),
    );
    let plain = register(&mut auth, &mut host, &Mc::new());
    let a = assert(
        &mut auth,
        &mut host,
        &Ga::new().ext("credBlob", true).ext("largeBlobKey", true),
    );
    assert_eq!(a.auth_data.flags, 0x81, "UP | ED");
    assert_eq!(
        a.auth_data.extensions,
        Some(MapBuilder::new().insert("credBlob", vec![0xCB; 5]).build())
    );
    assert_eq!(a.large_blob_key, resident.large_blob_key);
    assert!(a.verifies_with(&resident.public_key()));
    let b = assert(
        &mut auth,
        &mut host,
        &Ga::new()
            .allow(vec![plain.id()])
            .ext("credBlob", true)
            .ext("largeBlobKey", true),
    );
    assert_eq!(
        b.auth_data.extensions,
        Some(
            MapBuilder::new()
                .insert("credBlob", Vec::<u8>::new())
                .build()
        )
    );
    assert_eq!(b.large_blob_key, None);
    let c = assert(&mut auth, &mut host, &Ga::new().ext("credBlob", false));
    assert_eq!(c.auth_data.extensions, None);
    let r = send_untouched(
        &mut auth,
        &mut host,
        &Ga::new().ext("largeBlobKey", false).encode(),
    );
    assert_eq!(r, vec![status::INVALID_OPTION]);
}

#[test]
fn user_details_need_uv_and_several_accounts() {
    // CTAP 2.1 §6.2.2 response "user": name/displayName "MUST NOT be returned if user
    // verification is not done"; without UV only the id is returned.
    let (mut auth, mut host) = device();
    register(&mut auth, &mut host, &Mc::new().rk().user(b"u1"));
    let a = assert(&mut auth, &mut host, &Ga::new());
    let user = a.user.unwrap();
    assert_eq!(user.as_map().unwrap().len(), 1);
    assert_eq!(
        user.map_get_text("id").and_then(Value::as_bytes),
        Some(&b"u1"[..])
    );
}

#[test]
fn touch_denied_and_cancel() {
    // CTAP 2.1 §6.2.2 step 9 → OPERATION_DENIED; cancel → KEEPALIVE_CANCEL; no counter.
    let (mut auth, mut host) = device();
    let reg = register(&mut auth, &mut host, &Mc::new());
    let ga = Ga::new().allow(vec![reg.id()]).encode();
    assert_eq!(
        send_resolved(&mut auth, &mut host, &ga, false),
        vec![status::OPERATION_DENIED]
    );
    assert!(matches!(
        auth.cbor(&ga, &mut host),
        Outcome::NeedTouch { .. }
    ));
    assert_eq!(
        auth.cbor(&[0x04], &mut host),
        Outcome::Done(vec![status::CHANNEL_BUSY])
    );
    assert_eq!(auth.cancel(&mut host), Some(vec![status::KEEPALIVE_CANCEL]));
    assert_eq!(persisted_state(&host).counter, 0);
}

#[test]
fn storage_failure_does_not_advance_the_counter() {
    // docs/CONTRACTS.md persisted state: on persist failure keep the previous state and
    // answer CTAP1_ERR_OTHER; the signature is never revealed.
    let (mut auth, mut host) = device();
    let reg = register(&mut auth, &mut host, &Mc::new());
    let before = host.persisted(Record::Fido);
    host.fail_next_saves(1);
    let ga = Ga::new().allow(vec![reg.id()]);
    assert_eq!(
        send(&mut auth, &mut host, &ga.encode()),
        vec![status::OTHER]
    );
    assert_eq!(host.persisted(Record::Fido), before);
    assert_eq!(assert(&mut auth, &mut host, &ga).auth_data.counter, 1);
}

#[test]
fn counter_never_rolls_over() {
    // legacy-v0.64-profiles.json counter_policy: "refuses overflow".
    let (mut auth, mut host) = device();
    let reg = register(&mut auth, &mut host, &Mc::new());
    let mut auth = with_state(&mut host, |s| s.counter = u32::MAX - 1);
    let ga = Ga::new().allow(vec![reg.id()]);
    assert_eq!(
        assert(&mut auth, &mut host, &ga).auth_data.counter,
        u32::MAX
    );
    assert_eq!(
        send(&mut auth, &mut host, &ga.encode()),
        vec![status::OTHER]
    );
    assert_eq!(persisted_state(&host).counter, u32::MAX);
}

#[test]
fn cred_protect_levels_are_served_with_user_verification() {
    // CTAP 2.1 §6.2.2 steps 7.4 / 7.5 remove level 3 (userVerificationRequired) and, without
    // an allowList, level 2 (userVerificationOptionalWithCredentialIDList) credentials only
    // "if the "uv" bit is false"; with a pinUvAuthToken (step 6.1, "uv" bit set) all of
    // them are applicable. §6.1.2 step 12.2: a level 3 credential in the excludeList counts
    // only when UV was collected (12.2.1 → CREDENTIAL_EXCLUDED, 12.2.2 → skipped).
    use super::platform::{PIN, perm, set_pin, token};
    let (mut auth, mut host) = device();
    let l2 = register(
        &mut auth,
        &mut host,
        &Mc::new()
            .rk()
            .user(b"2")
            .rp("two.example")
            .ext("credProtect", 2),
    );
    let l3 = register(
        &mut auth,
        &mut host,
        &Mc::new()
            .rk()
            .user(b"3")
            .rp("three.example")
            .ext("credProtect", 3),
    );
    let nr3 = register(
        &mut auth,
        &mut host,
        &Mc::new().rp("three.example").ext("credProtect", 3),
    );
    set_pin(&mut auth, &mut host, 2, PIN);

    let served = [
        (Ga::new().rp("two.example"), &l2),
        (Ga::new().rp("three.example").allow(vec![l3.id()]), &l3),
        (Ga::new().rp("three.example").allow(vec![nr3.id()]), &nr3),
    ];
    for (ga, reg) in served {
        let t = token(&mut auth, &mut host, 2, perm::GA, None);
        let a = assert(&mut auth, &mut host, &ga.with_token(&t));
        assert_eq!(a.cred_id, reg.id());
        assert_eq!(a.auth_data.flags, 0x05, "UP and UV");
        assert!(a.verifies_with(&reg.public_key()));
    }
    // Discoverable level 3 without an allowList, silently (up=false, flags UV only): the
    // token is not consumed by a silent assertion, so it serves twice.
    let t = token(&mut auth, &mut host, 1, perm::GA, None);
    for _ in 0..2 {
        let r = send_untouched(
            &mut auth,
            &mut host,
            &Ga::new()
                .rp("three.example")
                .option("up", false)
                .with_token(&t)
                .encode(),
        );
        let a = parse_assertion(&r);
        assert_eq!(a.cred_id, l3.id());
        assert_eq!(a.auth_data.flags, 0x04);
        assert!(a.verifies_with(&l3.public_key()));
    }
    // Without UV the same requests find nothing.
    for ga in [
        Ga::new().rp("two.example"),
        Ga::new().rp("three.example"),
        Ga::new().rp("three.example").allow(vec![l3.id(), nr3.id()]),
    ] {
        assert_eq!(
            send_untouched(&mut auth, &mut host, &ga.encode()),
            vec![status::NO_CREDENTIALS]
        );
    }

    // excludeList with a level 3 credential: excluded with UV (after a touch) ...
    let mc = Mc::new().rp("three.example").exclude(vec![nr3.id()]);
    for granted in [true, false] {
        let t = token(&mut auth, &mut host, 2, perm::MC, None);
        let mc = mc.clone().with_token(&t);
        assert_eq!(
            send_resolved(&mut auth, &mut host, &mc.encode(), granted),
            vec![status::CREDENTIAL_EXCLUDED]
        );
    }
    // ... and skipped without UV (non-discoverable registration needs no token,
    // makeCredUvNotRqd).
    let reg = register(&mut auth, &mut host, &mc);
    assert_eq!(reg.auth_data.flags & 0x04, 0, "no UV");
    assert_ne!(reg.id(), nr3.id());
}

#[test]
fn a_failed_persist_never_reveals_a_get_next_assertion_signature() {
    // docs/CONTRACTS.md persisted state and DESIGN §7: the counter is persisted before the
    // response that reveals it. On getNextAssertion (CTAP 2.1 §6.3) a storage failure is
    // CTAP1_ERR_OTHER, the counter stays, and the same credential is served next (steps 4
    // and 8: credentialCounter advances only with a response).
    let (mut auth, mut host) = device();
    let regs: Vec<Registration> = [b"A", b"B", b"C"]
        .iter()
        .map(|u| register(&mut auth, &mut host, &Mc::new().rk().user(*u)))
        .collect();
    let first = assert(&mut auth, &mut host, &Ga::new());
    assert_eq!((first.count, first.auth_data.counter), (Some(3), 1));
    let before = host.persisted(Record::Fido);
    host.fail_next_saves(1);
    assert_eq!(
        send_untouched(&mut auth, &mut host, &[0x08]),
        vec![status::OTHER]
    );
    assert_eq!(host.persisted(Record::Fido), before);
    let next = parse_assertion(&send_untouched(&mut auth, &mut host, &[0x08]));
    assert_eq!(next.cred_id, regs[1].id(), "the same credential again");
    assert_eq!(
        next.auth_data.counter, 2,
        "no counter value was skipped or reused"
    );
    assert!(next.verifies_with(&regs[1].public_key()));
    assert_eq!(persisted_state(&host).counter, 2);
    // A storage failure on the last one, then success, then the state is used up.
    host.fail_next_saves(1);
    assert_eq!(
        send_untouched(&mut auth, &mut host, &[0x08]),
        vec![status::OTHER]
    );
    let last = parse_assertion(&send_untouched(&mut auth, &mut host, &[0x08]));
    assert_eq!((last.cred_id, last.auth_data.counter), (regs[0].id(), 3));
    assert_eq!(
        send_untouched(&mut auth, &mut host, &[0x08]),
        vec![status::NOT_ALLOWED]
    );
    // The same holds for a silent first assertion and for a storage failure on it.
    host.fail_next_saves(1);
    assert_eq!(
        send_untouched(
            &mut auth,
            &mut host,
            &Ga::new().option("up", false).encode()
        ),
        vec![status::OTHER]
    );
    assert_eq!(persisted_state(&host).counter, 3);
    assert_eq!(
        send_untouched(&mut auth, &mut host, &[0x08]),
        vec![status::NOT_ALLOWED],
        "a failed first assertion leaves no getNextAssertion state"
    );
}

#[test]
fn get_next_assertion_state_ends_when_its_token_expires() {
    // CTAP 2.1 §6 stateful commands: "An authenticator MUST discard the state for a stateful
    // command if the pinUvAuthToken that authenticated the state initializing command
    // expires". Tokens expire 10 minutes after issuance (§6.5.2.1 max usage time period,
    // 600 s default), independently of the 30 s getNextAssertion timer (§6.3 step 3).
    use super::platform::{PIN, perm, set_pin, token};
    let (mut auth, mut host) = device();
    register(&mut auth, &mut host, &Mc::new().rk().user(b"A"));
    register(&mut auth, &mut host, &Mc::new().rk().user(b"B"));
    set_pin(&mut auth, &mut host, 2, PIN);
    let silent = Ga::new().option("up", false);
    for (ga_at, next_at, want) in [
        (590_000u64, 599_000u64, status::OK),
        (595_000, 600_000, status::OK),
        (595_000, 600_001, status::NOT_ALLOWED),
    ] {
        let t = token(&mut auth, &mut host, 2, perm::GA, None);
        let start = host.now();
        // Use the token at once (initial usage time limit, §6.5.2.1).
        assert_eq!(
            status_of(&send_untouched(
                &mut auth,
                &mut host,
                &silent.clone().with_token(&t).encode()
            )),
            status::OK
        );
        host.set_now(start + ga_at);
        let first = parse_assertion(&send_untouched(
            &mut auth,
            &mut host,
            &silent.clone().with_token(&t).encode(),
        ));
        assert_eq!((first.count, first.auth_data.flags), (Some(2), 0x04));
        host.set_now(start + next_at);
        assert_eq!(
            status_of(&send_untouched(&mut auth, &mut host, &[0x08])),
            want,
            "getAssertion at +{ga_at} ms, getNextAssertion at +{next_at} ms"
        );
    }
    // Without a token there is nothing to expire: only the 30 s timer applies.
    let first = assert(&mut auth, &mut host, &Ga::new());
    assert_eq!(first.count, Some(2));
    host.advance(30_000);
    assert_eq!(
        status_of(&send_untouched(&mut auth, &mut host, &[0x08])),
        status::OK
    );
}
