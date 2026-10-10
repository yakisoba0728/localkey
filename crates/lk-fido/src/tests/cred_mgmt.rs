//! authenticatorCredentialManagement (CTAP 2.1 §6.8) and the prototype command 0x41.

use super::platform::{PIN, Platform, Token, perm, set_pin, token};
use super::*;
use crate::status;

const OTHER_RP: &str = "other.example";

/// subCommand numbers (CTAP 2.1 §6.8 table).
mod sub {
    pub const METADATA: u64 = 0x01;
    pub const RPS_BEGIN: u64 = 0x02;
    pub const RPS_NEXT: u64 = 0x03;
    pub const CREDS_BEGIN: u64 = 0x04;
    pub const CREDS_NEXT: u64 = 0x05;
    pub const DELETE: u64 = 0x06;
    pub const UPDATE: u64 = 0x07;
}

/// A credentialManagement request; `params` is the encoded subCommandParams map, which
/// the pinUvAuthParam covers as `uint8(subCommand) || subCommandParams` (§6.8.2-§6.8.6).
fn cm_request(
    command: u8,
    subcommand: u64,
    params: Option<&[u8]>,
    token: Option<&Token>,
) -> Vec<u8> {
    // Assemble the map by hand so subCommandParams keeps its exact encoding.
    let mut entries: Vec<Vec<u8>> = Vec::new();
    entries.push(
        [
            cbor::encode(&Value::from(1u8)),
            cbor::encode(&Value::from(subcommand)),
        ]
        .concat(),
    );
    if let Some(p) = params {
        entries.push([&[0x02u8][..], p].concat());
    }
    if let Some(t) = token {
        let mut message = vec![subcommand as u8];
        message.extend_from_slice(params.unwrap_or_default());
        entries.push(
            [
                cbor::encode(&Value::from(3u8)),
                cbor::encode(&Value::from(t.protocol)),
            ]
            .concat(),
        );
        entries.push(
            [
                cbor::encode(&Value::from(4u8)),
                cbor::encode(&Value::Bytes(t.sign(&message))),
            ]
            .concat(),
        );
    }
    let mut out = vec![command, 0xA0 | entries.len() as u8];
    for e in entries {
        out.extend(e);
    }
    out
}

fn cm(
    auth: &mut Authenticator,
    host: &mut TestHost,
    subcommand: u64,
    params: Option<Value>,
    token: Option<&Token>,
) -> Vec<u8> {
    let encoded = params.map(|p| cbor::encode(&p));
    send_untouched(
        auth,
        host,
        &cm_request(0x0A, subcommand, encoded.as_deref(), token),
    )
}

fn rp_hash_params(rp: &str) -> Value {
    MapBuilder::new()
        .insert(1, sha256(rp.as_bytes()).to_vec())
        .build()
}

fn cred_params(id: &[u8]) -> Value {
    MapBuilder::new().insert(2, descriptor(id)).build()
}

/// Three discoverable credentials over two RPs, with a PIN; returns their registrations.
fn populated() -> (Authenticator, TestHost, Vec<Registration>) {
    let (mut auth, mut host) = device();
    let regs = vec![
        register(
            &mut auth,
            &mut host,
            &Mc::new()
                .rk()
                .user(b"alice")
                .ext("credProtect", 2)
                .ext("largeBlobKey", true),
        ),
        register(&mut auth, &mut host, &Mc::new().rk().user(b"bob").alg(-8)),
        register(
            &mut auth,
            &mut host,
            &Mc::new().rk().rp(OTHER_RP).user(b"carol").alg(-35),
        ),
    ];
    set_pin(&mut auth, &mut host, 2, PIN);
    (auth, host, regs)
}

#[test]
fn metadata_and_enumerations() {
    // CTAP 2.1 §6.8.2 getCredsMetadata, §6.8.3 enumerateRPs, §6.8.4 enumerateCredentials:
    // response keys 0x01-0x0B; totals only in the "begin" responses.
    let (mut auth, mut host, regs) = populated();
    let t = token(&mut auth, &mut host, 2, perm::CM, None);
    let meta = body(&cm(&mut auth, &mut host, sub::METADATA, None, Some(&t)));
    assert_eq!(meta.map_get_int(1).and_then(Value::as_u64), Some(3));
    assert_eq!(meta.map_get_int(2).and_then(Value::as_u64), Some(97));

    let first = body(&cm(&mut auth, &mut host, sub::RPS_BEGIN, None, Some(&t)));
    assert_eq!(first.map_get_int(5).and_then(Value::as_u64), Some(2));
    // §6.8.3: "the id field SHOULD be included and other fields MAY be included"; the
    // stored rp.name is returned.
    assert_eq!(
        first.map_get_int(3),
        Some(
            &MapBuilder::new()
                .insert("id", RP)
                .insert("name", "Example")
                .build()
        )
    );
    assert_eq!(
        first.map_get_int(4).and_then(Value::as_bytes),
        Some(&sha256(RP.as_bytes())[..])
    );
    let next = body(&cm(&mut auth, &mut host, sub::RPS_NEXT, None, None));
    assert_eq!(
        next.map_get_int(3)
            .unwrap()
            .map_get_text("id")
            .and_then(Value::as_text),
        Some(OTHER_RP)
    );
    assert_eq!(next.map_get_int(5), None, "totalRPs only at the beginning");
    assert_eq!(
        cm(&mut auth, &mut host, sub::RPS_NEXT, None, None),
        vec![status::NOT_ALLOWED]
    );

    let c1 = body(&cm(
        &mut auth,
        &mut host,
        sub::CREDS_BEGIN,
        Some(rp_hash_params(RP)),
        Some(&t),
    ));
    assert_eq!(c1.map_get_int(9).and_then(Value::as_u64), Some(2));
    assert_eq!(
        c1.map_get_int(6)
            .unwrap()
            .map_get_text("id")
            .and_then(Value::as_bytes),
        Some(&b"alice"[..])
    );
    assert_eq!(
        c1.map_get_int(6)
            .unwrap()
            .map_get_text("name")
            .and_then(Value::as_text),
        Some("alice")
    );
    assert_eq!(c1.map_get_int(7), Some(&descriptor(&regs[0].id())));
    assert_eq!(c1.map_get_int(8), Some(&regs[0].public_key()));
    assert_eq!(c1.map_get_int(0x0A).and_then(Value::as_u64), Some(2));
    assert_eq!(
        c1.map_get_int(0x0B).and_then(Value::as_bytes),
        regs[0].large_blob_key.as_deref()
    );
    let c2 = body(&cm(&mut auth, &mut host, sub::CREDS_NEXT, None, None));
    assert_eq!(c2.map_get_int(7), Some(&descriptor(&regs[1].id())));
    assert_eq!(c2.map_get_int(8), Some(&regs[1].public_key()));
    assert_eq!(c2.map_get_int(9), None);
    assert_eq!(c2.map_get_int(0x0A).and_then(Value::as_u64), Some(1));
    assert_eq!(c2.map_get_int(0x0B), None);
    assert_eq!(
        cm(&mut auth, &mut host, sub::CREDS_NEXT, None, None),
        vec![status::NOT_ALLOWED]
    );

    // The enumerated public key verifies an assertion (WebAuthn L2 §6.3.3).
    let c3 = body(&cm(
        &mut auth,
        &mut host,
        sub::CREDS_BEGIN,
        Some(rp_hash_params(OTHER_RP)),
        Some(&t),
    ));
    let a = assert(
        &mut auth,
        &mut host,
        &Ga::new().rp(OTHER_RP).allow(vec![regs[2].id()]),
    );
    assert!(a.verifies_with(c3.map_get_int(8).unwrap()));
}

#[test]
fn enumeration_state_is_discarded_by_other_commands() {
    // CTAP 2.1 §6.8.3 / §6.8.4: the "get next" subcommands continue only an enumeration
    // that nothing else interrupted.
    let (mut auth, mut host, _) = populated();
    let t = token(&mut auth, &mut host, 2, perm::CM, None);
    body(&cm(&mut auth, &mut host, sub::RPS_BEGIN, None, Some(&t)));
    get_info(&mut auth, &mut host);
    assert_eq!(
        cm(&mut auth, &mut host, sub::RPS_NEXT, None, None),
        vec![status::NOT_ALLOWED]
    );
    body(&cm(
        &mut auth,
        &mut host,
        sub::CREDS_BEGIN,
        Some(rp_hash_params(RP)),
        Some(&t),
    ));
    assert_eq!(
        cm(&mut auth, &mut host, sub::RPS_NEXT, None, None),
        vec![status::NOT_ALLOWED]
    );
    assert_eq!(
        cm(&mut auth, &mut host, sub::CREDS_NEXT, None, None),
        vec![status::NOT_ALLOWED]
    );
    body(&cm(
        &mut auth,
        &mut host,
        sub::CREDS_BEGIN,
        Some(rp_hash_params(RP)),
        Some(&t),
    ));
    auth.power_cycle(&mut host);
    assert_eq!(
        cm(&mut auth, &mut host, sub::CREDS_NEXT, None, None),
        vec![status::NOT_ALLOWED]
    );
}

#[test]
fn authorization_requires_a_token_with_the_cm_permission() {
    // CTAP 2.1 §6.8.2: pinUvAuthParam absent → PUAT_REQUIRED; protocol absent →
    // MISSING_PARAMETER, unsupported → INVALID_PARAMETER; wrong MAC or no cm permission →
    // PIN_AUTH_INVALID.
    let (mut auth, mut host, _) = populated();
    assert_eq!(
        cm(&mut auth, &mut host, sub::METADATA, None, None),
        vec![status::PUAT_REQUIRED]
    );
    let t = token(&mut auth, &mut host, 2, perm::CM, None);
    let without_protocol = encode_request(
        0x0A,
        &MapBuilder::new()
            .insert(1, sub::METADATA)
            .insert(4, t.sign(&[1]))
            .build(),
    );
    assert_eq!(
        send_untouched(&mut auth, &mut host, &without_protocol),
        vec![status::MISSING_PARAMETER]
    );
    let bad_protocol = encode_request(
        0x0A,
        &MapBuilder::new()
            .insert(1, sub::METADATA)
            .insert(3, 7)
            .insert(4, t.sign(&[1]))
            .build(),
    );
    assert_eq!(
        send_untouched(&mut auth, &mut host, &bad_protocol),
        vec![status::INVALID_PARAMETER]
    );
    let signed_for_other_sub = encode_request(
        0x0A,
        &MapBuilder::new()
            .insert(1, sub::METADATA)
            .insert(3, 2)
            .insert(4, t.sign(&[2]))
            .build(),
    );
    assert_eq!(
        send_untouched(&mut auth, &mut host, &signed_for_other_sub),
        vec![status::PIN_AUTH_INVALID]
    );
    let no_cm = token(
        &mut auth,
        &mut host,
        2,
        perm::MC | perm::GA | perm::LBW | perm::ACFG,
        None,
    );
    assert_eq!(
        cm(&mut auth, &mut host, sub::METADATA, None, Some(&no_cm)),
        vec![status::PIN_AUTH_INVALID]
    );
    // The cm permission is not consumed by credential management itself.
    let t = token(&mut auth, &mut host, 1, perm::CM, None);
    for _ in 0..2 {
        assert_eq!(
            status_of(&cm(&mut auth, &mut host, sub::METADATA, None, Some(&t))),
            status::OK
        );
    }
    // Missing subCommand, wrong types and unknown subcommands.
    let r = send_untouched(
        &mut auth,
        &mut host,
        &encode_request(0x0A, &MapBuilder::new().insert(3, 2).build()),
    );
    assert_eq!(r, vec![status::MISSING_PARAMETER]);
    let r = send_untouched(
        &mut auth,
        &mut host,
        &encode_request(0x0A, &MapBuilder::new().insert(1, 4).insert(2, 5).build()),
    );
    assert_eq!(r, vec![status::CBOR_UNEXPECTED_TYPE]);
    assert_eq!(
        cm(&mut auth, &mut host, 0x08, None, Some(&t)),
        vec![status::INVALID_SUBCOMMAND]
    );
}

#[test]
fn missing_parameters_are_reported_before_an_unsupported_protocol() {
    // CTAP 2.1 §6.8.4-§6.8.6 step order: pinUvAuthParam absent → PUAT_REQUIRED; then any
    // mandatory parameter absent (pinUvAuthProtocol, rpIDHash, credentialID, user) →
    // MISSING_PARAMETER; only then an unsupported pinUvAuthProtocol → INVALID_PARAMETER.
    let (mut auth, mut host, regs) = populated();
    let raw = |sub: u64, params: Option<Value>, protocol: Option<u64>, param: bool| {
        let mut m = MapBuilder::new().insert(1, sub);
        if let Some(p) = params {
            m.set(2, p);
        }
        if let Some(p) = protocol {
            m.set(3, p);
        }
        if param {
            m.set(4, vec![0u8; 32]);
        }
        encode_request(0x0A, &m.build())
    };
    let user_only = MapBuilder::new()
        .insert(3, MapBuilder::new().insert("id", b"alice".to_vec()).build())
        .build();
    let cred_no_user = cred_params(&regs[0].id());
    let cases = [
        // Begin enumeration without rpIDHash, protocol unsupported.
        (
            raw(sub::CREDS_BEGIN, None, Some(9), true),
            status::MISSING_PARAMETER,
        ),
        (
            raw(
                sub::CREDS_BEGIN,
                Some(MapBuilder::new().build()),
                Some(9),
                true,
            ),
            status::MISSING_PARAMETER,
        ),
        (
            raw(sub::DELETE, None, Some(9), true),
            status::MISSING_PARAMETER,
        ),
        (
            raw(sub::UPDATE, Some(user_only.clone()), Some(9), true),
            status::MISSING_PARAMETER,
        ),
        (
            raw(sub::UPDATE, Some(cred_no_user.clone()), Some(9), true),
            status::MISSING_PARAMETER,
        ),
        // pinUvAuthProtocol itself absent.
        (
            raw(sub::CREDS_BEGIN, Some(rp_hash_params(RP)), None, true),
            status::MISSING_PARAMETER,
        ),
        // PUAT_REQUIRED comes first of all.
        (raw(sub::DELETE, None, None, false), status::PUAT_REQUIRED),
        // With every mandatory parameter present the protocol is checked.
        (
            raw(sub::CREDS_BEGIN, Some(rp_hash_params(RP)), Some(9), true),
            status::INVALID_PARAMETER,
        ),
        (
            raw(sub::DELETE, Some(cred_params(&regs[0].id())), Some(0), true),
            status::INVALID_PARAMETER,
        ),
        // And then the MAC.
        (
            raw(sub::DELETE, Some(cred_params(&regs[0].id())), Some(2), true),
            status::PIN_AUTH_INVALID,
        ),
    ];
    for (request, want) in cases {
        assert_eq!(
            send_untouched(&mut auth, &mut host, &request),
            vec![want],
            "{request:02x?}"
        );
    }
    assert_eq!(persisted_state(&host).residents.len(), 3, "nothing deleted");
}

#[test]
fn the_prototype_command_accepts_a_legacy_token_but_0x0a_does_not() {
    // Model policy (cred_mgmt module documentation): FIDO_2_1_PRE platforms use 0x41 with
    // getPinToken (CTAP 2.1 §6.5.5.7.1, permissions mc and ga; §6.13: the prototype "does not
    // require permissions, thus it is compatible with a pinUvAuthToken generated by the
    // getPinToken command").
    let (mut auth, mut host, _) = populated();
    let mut platform = Platform::connect(&mut auth, &mut host, 1);
    let r = send_untouched(&mut auth, &mut host, &platform.pin_token_request(PIN));
    let legacy = platform.token_from(&r);
    let r = send_untouched(
        &mut auth,
        &mut host,
        &cm_request(0x0A, sub::METADATA, None, Some(&legacy)),
    );
    assert_eq!(r, vec![status::PIN_AUTH_INVALID]);
    let r = send_untouched(
        &mut auth,
        &mut host,
        &cm_request(0x41, sub::METADATA, None, Some(&legacy)),
    );
    assert_eq!(body(&r).map_get_int(1).and_then(Value::as_u64), Some(3));
    let r = send_untouched(
        &mut auth,
        &mut host,
        &cm_request(0x41, sub::RPS_BEGIN, None, Some(&legacy)),
    );
    assert_eq!(body(&r).map_get_int(5).and_then(Value::as_u64), Some(2));
    let r = send_untouched(
        &mut auth,
        &mut host,
        &cm_request(0x41, sub::RPS_NEXT, None, None),
    );
    assert_eq!(status_of(&r), status::OK, "enumeration continues on 0x41");
    // A permissions token works on 0x41 too.
    let t = token(&mut auth, &mut host, 2, perm::CM, None);
    let r = send_untouched(
        &mut auth,
        &mut host,
        &cm_request(0x41, sub::METADATA, None, Some(&t)),
    );
    assert_eq!(status_of(&r), status::OK);
    // A legacy token consumed by user presence (CTAP 2.1 §6.1.2 step 14.4 /
    // §6.2.2 step 9: permissions other than lbw cleared) no longer opens 0x41 either.
    let r = send_untouched(&mut auth, &mut host, &platform.pin_token_request(PIN));
    let legacy = platform.token_from(&r);
    assert_eq!(
        status_of(&send_untouched(
            &mut auth,
            &mut host,
            &cm_request(0x41, sub::METADATA, None, Some(&legacy)),
        )),
        status::OK
    );
    let reg = register(&mut auth, &mut host, &Mc::new());
    let r = send_untouched(
        &mut auth,
        &mut host,
        &cm_request(0x41, sub::METADATA, None, Some(&legacy)),
    );
    assert_eq!(
        r,
        vec![status::PIN_AUTH_INVALID],
        "consumed by makeCredential"
    );
    let r = send_untouched(&mut auth, &mut host, &platform.pin_token_request(PIN));
    let legacy = platform.token_from(&r);
    assert_eq!(
        status_of(&send(
            &mut auth,
            &mut host,
            &Ga::new().allow(vec![reg.id()]).encode()
        )),
        status::OK
    );
    let r = send_untouched(
        &mut auth,
        &mut host,
        &cm_request(0x41, sub::METADATA, None, Some(&legacy)),
    );
    assert_eq!(
        r,
        vec![status::PIN_AUTH_INVALID],
        "consumed by getAssertion"
    );
}

#[test]
fn rp_scoped_tokens_reach_only_their_rp() {
    // CTAP 2.1 §6.8.2-§6.8.6 with a permissions RP ID (§6.5.5.7 rpId).
    let (mut auth, mut host, regs) = populated();
    let t = token(&mut auth, &mut host, 2, perm::CM, Some(RP));
    assert_eq!(
        cm(&mut auth, &mut host, sub::METADATA, None, Some(&t)),
        vec![status::PIN_AUTH_INVALID]
    );
    assert_eq!(
        cm(&mut auth, &mut host, sub::RPS_BEGIN, None, Some(&t)),
        vec![status::PIN_AUTH_INVALID]
    );
    let r = cm(
        &mut auth,
        &mut host,
        sub::CREDS_BEGIN,
        Some(rp_hash_params(RP)),
        Some(&t),
    );
    assert_eq!(body(&r).map_get_int(9).and_then(Value::as_u64), Some(2));
    let r = cm(
        &mut auth,
        &mut host,
        sub::CREDS_BEGIN,
        Some(rp_hash_params(OTHER_RP)),
        Some(&t),
    );
    assert_eq!(r, vec![status::PIN_AUTH_INVALID]);
    let r = cm(
        &mut auth,
        &mut host,
        sub::DELETE,
        Some(cred_params(&regs[2].id())),
        Some(&t),
    );
    assert_eq!(r, vec![status::PIN_AUTH_INVALID]);
    let r = cm(
        &mut auth,
        &mut host,
        sub::DELETE,
        Some(cred_params(&regs[1].id())),
        Some(&t),
    );
    assert_eq!(r, vec![status::OK]);
    assert_eq!(persisted_state(&host).residents.len(), 2);
}

#[test]
fn missing_credentials_are_no_credentials() {
    // BEHAVIOR_CATALOG FIDO: "Credential management delete/update of a missing resident
    // credential returns CTAP2_ERR_NO_CREDENTIALS (0x2e)"; empty enumerations too.
    let (mut auth, mut host) = device();
    set_pin(&mut auth, &mut host, 2, PIN);
    let plain = register(&mut auth, &mut host, &Mc::new());
    let t = token(&mut auth, &mut host, 2, perm::CM, None);
    let meta = body(&cm(&mut auth, &mut host, sub::METADATA, None, Some(&t)));
    assert_eq!(meta.map_get_int(1).and_then(Value::as_u64), Some(0));
    assert_eq!(meta.map_get_int(2).and_then(Value::as_u64), Some(100));
    assert_eq!(
        cm(&mut auth, &mut host, sub::RPS_BEGIN, None, Some(&t)),
        vec![status::NO_CREDENTIALS]
    );
    let r = cm(
        &mut auth,
        &mut host,
        sub::CREDS_BEGIN,
        Some(rp_hash_params(RP)),
        Some(&t),
    );
    assert_eq!(r, vec![status::NO_CREDENTIALS]);
    // A non-discoverable credential is not stored, so it cannot be deleted.
    let r = cm(
        &mut auth,
        &mut host,
        sub::DELETE,
        Some(cred_params(&plain.id())),
        Some(&t),
    );
    assert_eq!(r, vec![status::NO_CREDENTIALS]);
    let update = MapBuilder::new()
        .insert(2, descriptor(&[7; 128]))
        .insert(3, MapBuilder::new().insert("id", vec![1u8]).build())
        .build();
    assert_eq!(
        cm(&mut auth, &mut host, sub::UPDATE, Some(update), Some(&t)),
        vec![status::NO_CREDENTIALS]
    );
    // Required members are checked after the token presence checks.
    assert_eq!(
        cm(&mut auth, &mut host, sub::DELETE, None, None),
        vec![status::PUAT_REQUIRED]
    );
    assert_eq!(
        cm(&mut auth, &mut host, sub::DELETE, None, Some(&t)),
        vec![status::MISSING_PARAMETER]
    );
    assert_eq!(
        cm(&mut auth, &mut host, sub::CREDS_BEGIN, None, Some(&t)),
        vec![status::MISSING_PARAMETER]
    );
    let no_user = cred_params(&plain.id());
    assert_eq!(
        cm(&mut auth, &mut host, sub::UPDATE, Some(no_user), Some(&t)),
        vec![status::MISSING_PARAMETER]
    );
    // Any makeCredential that collects user presence consumes the in-use token's
    // permissions other than lbw, with or without a pinUvAuthParam (CTAP 2.1 §6.1.2
    // step 14: "no-ops if there is not an in-use pinUvAuthToken").
    register(&mut auth, &mut host, &Mc::new());
    assert_eq!(
        cm(&mut auth, &mut host, sub::METADATA, None, Some(&t)),
        vec![status::PIN_AUTH_INVALID]
    );
}

#[test]
fn delete_and_update_user_information() {
    // CTAP 2.1 §6.8.5 deleteCredential and §6.8.6 updateUserInformation (user id must
    // match; absent or empty names are removed).
    let (mut auth, mut host, regs) = populated();
    let t = token(&mut auth, &mut host, 2, perm::CM, None);
    let update = |user_id: &[u8], name: Option<&str>| {
        let mut user = MapBuilder::new().insert("id", user_id.to_vec());
        if let Some(n) = name {
            user.set("name", n);
            user.set("displayName", "");
        }
        MapBuilder::new()
            .insert(2, descriptor(&regs[0].id()))
            .insert(3, user.build())
            .build()
    };
    let r = cm(
        &mut auth,
        &mut host,
        sub::UPDATE,
        Some(update(b"mallory", Some("x"))),
        Some(&t),
    );
    assert_eq!(r, vec![status::INVALID_PARAMETER], "user id mismatch");
    let r = cm(
        &mut auth,
        &mut host,
        sub::UPDATE,
        Some(update(b"alice", Some("Alice A."))),
        Some(&t),
    );
    assert_eq!(r, vec![status::OK]);
    let row = persisted_state(&host).residents[0].clone();
    assert_eq!(row.user_name.as_deref(), Some("Alice A."));
    assert_eq!(row.display_name, None);
    let r = cm(
        &mut auth,
        &mut host,
        sub::UPDATE,
        Some(update(b"alice", None)),
        Some(&t),
    );
    assert_eq!(r, vec![status::OK]);
    assert_eq!(persisted_state(&host).residents[0].user_name, None);

    let before = get_info(&mut auth, &mut host)
        .map_get_int(0x14)
        .and_then(Value::as_u64);
    host.fail_next_saves(1);
    let r = cm(
        &mut auth,
        &mut host,
        sub::DELETE,
        Some(cred_params(&regs[0].id())),
        Some(&t),
    );
    assert_eq!(r, vec![status::OTHER]);
    assert_eq!(persisted_state(&host).residents.len(), 3);
    let r = cm(
        &mut auth,
        &mut host,
        sub::DELETE,
        Some(cred_params(&regs[0].id())),
        Some(&t),
    );
    assert_eq!(r, vec![status::OK]);
    let after = get_info(&mut auth, &mut host)
        .map_get_int(0x14)
        .and_then(Value::as_u64);
    assert_eq!(after, before.map(|n| n + 1));
    // The deleted credential's ID no longer works (it was discoverable).
    let r = send(
        &mut auth,
        &mut host,
        &Ga::new().allow(vec![regs[0].id()]).encode(),
    );
    assert_eq!(r, vec![status::NO_CREDENTIALS]);
    let r = cm(
        &mut auth,
        &mut host,
        sub::DELETE,
        Some(cred_params(&regs[0].id())),
        Some(&t),
    );
    assert_eq!(r, vec![status::NO_CREDENTIALS]);
}

#[test]
fn the_mac_covers_sub_command_params_as_received() {
    // CTAP 2.1 §6.8.6: verify(pinUvAuthToken, updateUserInformation (0x07) ||
    // subCommandParams); keys sent in a non-canonical order are MACed as sent.
    let (mut auth, mut host, regs) = populated();
    let t = token(&mut auth, &mut host, 2, perm::CM, None);
    // {3: user, 2: credentialID}: user first, against canonical order.
    let user = cbor::encode(
        &MapBuilder::new()
            .insert("id", b"bob".to_vec())
            .insert("name", "B")
            .build(),
    );
    let cred = cbor::encode(&descriptor(&regs[1].id()));
    let params = [&[0xA2u8, 0x03][..], &user, &[0x02], &cred].concat();
    assert_ne!(
        params,
        cbor::encode(&cbor::decode(&params).unwrap()),
        "not canonical"
    );
    let r = send_untouched(
        &mut auth,
        &mut host,
        &cm_request(0x0A, sub::UPDATE, Some(&params), Some(&t)),
    );
    assert_eq!(r, vec![status::OK]);
    assert_eq!(
        persisted_state(&host).residents[1].user_name.as_deref(),
        Some("B")
    );
    // A MAC over the canonical re-encoding does not verify.
    let canonical = cbor::encode(&cbor::decode(&params).unwrap());
    let mut message = vec![sub::UPDATE as u8];
    message.extend_from_slice(&canonical);
    let forged = [
        &[0x0A, 0xA4, 0x01, 0x07, 0x02][..],
        &params,
        &[0x03, 0x02, 0x04, 0x58, 0x20],
        &t.sign(&message),
    ]
    .concat();
    assert_eq!(
        send_untouched(&mut auth, &mut host, &forged),
        vec![status::PIN_AUTH_INVALID]
    );
}

#[test]
fn a_deleted_discoverable_credential_id_is_dead_everywhere() {
    // CTAP 2.1 §6.8.5 deleteCredential removes the credential; its ID must then be refused
    // by getAssertion (§6.2.2 step 7.1 → NO_CREDENTIALS), by U2F AUTHENTICATE (U2F raw
    // message formats v1.2 §5.3 → 6A80) and by the excludeList (§6.1.2 step 12), even though
    // the key inside the wrapped ID would still unwrap (credential.rs: a discoverable ID
    // works only while its stored record exists). The same holds for an overwritten one
    // (§6.1.2 step 17.2).
    let (mut auth, mut host, regs) = populated();
    let alice = regs[0].id();
    let t = token(&mut auth, &mut host, 2, perm::CM, None);
    assert_eq!(
        cm(
            &mut auth,
            &mut host,
            sub::DELETE,
            Some(cred_params(&alice)),
            Some(&t)
        ),
        vec![status::OK]
    );
    assert_eq!(
        send_untouched(
            &mut auth,
            &mut host,
            &Ga::new().allow(vec![alice.clone()]).encode()
        ),
        vec![status::NO_CREDENTIALS]
    );
    let mut u2f = vec![0x00, 0x02, 0x03, 0x00, 0x00, 0x00, 0xC1];
    u2f.extend_from_slice(&[0xC4; 32]);
    u2f.extend_from_slice(&sha256(RP.as_bytes()));
    u2f.push(128);
    u2f.extend_from_slice(&alice);
    u2f.extend_from_slice(&[0x00, 0x00]);
    assert_eq!(auth.u2f(&u2f, true, &mut host).0, vec![0x6A, 0x80]);
    // Excluding the deleted ID excludes nothing (non-discoverable: no token needed).
    let made = register(
        &mut auth,
        &mut host,
        &Mc::new().exclude(vec![alice.clone()]),
    );
    assert_ne!(made.id(), alice);
    // That makeCredential collected user presence and so consumed the token's cm
    // permission (§6.1.2 step 14.4).
    assert_eq!(
        cm(
            &mut auth,
            &mut host,
            sub::DELETE,
            Some(cred_params(&alice)),
            Some(&t)
        ),
        vec![status::PIN_AUTH_INVALID]
    );
    // Deleting it again is NO_CREDENTIALS (catalog: missing resident credential).
    let t = token(&mut auth, &mut host, 2, perm::CM, None);
    assert_eq!(
        cm(
            &mut auth,
            &mut host,
            sub::DELETE,
            Some(cred_params(&alice)),
            Some(&t)
        ),
        vec![status::NO_CREDENTIALS]
    );
    // Overwrite bob (same RP and user id) with a token-authorized discoverable registration:
    // the old ID dies, the new one works.
    let bob = regs[1].id();
    let mc_token = token(&mut auth, &mut host, 2, perm::MC, None);
    let new_bob = register(
        &mut auth,
        &mut host,
        &Mc::new().rk().user(b"bob").with_token(&mc_token),
    );
    assert_eq!(
        send_untouched(&mut auth, &mut host, &Ga::new().allow(vec![bob]).encode()),
        vec![status::NO_CREDENTIALS]
    );
    assert!(
        assert(&mut auth, &mut host, &Ga::new().allow(vec![new_bob.id()]))
            .verifies_with(&new_bob.public_key())
    );
}

#[test]
fn enumeration_state_ends_when_its_token_expires() {
    // CTAP 2.1 §6 stateful commands: the state of enumerateRPsGetNextRP /
    // enumerateCredentialsGetNextCredential "MUST" be discarded once the pinUvAuthToken
    // that authenticated the begin subcommand expires (§6.5.2.1: 600 s after issuance).
    let (mut auth, mut host, _) = populated();
    for (begin, next, want) in [
        (sub::RPS_BEGIN, sub::RPS_NEXT, None),
        (sub::CREDS_BEGIN, sub::CREDS_NEXT, Some(rp_hash_params(RP))),
    ] {
        for (begin_at, next_at, expected) in [
            (10_000u64, 600_000u64, status::OK),
            (10_000, 600_001, status::NOT_ALLOWED),
        ] {
            let t = token(&mut auth, &mut host, 2, perm::CM, None);
            let start = host.now();
            // Use it within the initial usage time limit (§6.5.2.1).
            host.set_now(start + begin_at);
            let r = cm(&mut auth, &mut host, begin, want.clone(), Some(&t));
            assert_eq!(status_of(&r), status::OK);
            host.set_now(start + next_at);
            assert_eq!(
                status_of(&cm(&mut auth, &mut host, next, None, None)),
                expected,
                "subcommand {next} at +{next_at} ms"
            );
        }
    }
}

#[test]
fn enumerate_rps_returns_the_newest_stored_rp_name() {
    // CTAP 2.1 §6.8.3 rp: PublicKeyCredentialRpEntity, id SHOULD and other fields MAY be
    // included. The name comes from the RP's most recently created credential, is cut to
    // 64 bytes on a character boundary (WebAuthn L2 §5.4.1, §6.4.1), is left out when that
    // registration sent none, and survives a restart.
    let (mut auth, mut host) = device();
    let long = format!("{}é{}", "a".repeat(63), "b".repeat(10));
    register(
        &mut auth,
        &mut host,
        &Mc::new().rk().user(b"alice").rp_name(Some("Old name")),
    );
    register(
        &mut auth,
        &mut host,
        &Mc::new().rk().user(b"bob").rp_name(Some(&long)),
    );
    register(
        &mut auth,
        &mut host,
        &Mc::new().rk().rp(OTHER_RP).user(b"carol").rp_name(None),
    );
    // A non-discoverable credential stores nothing, so its name never shows.
    register(&mut auth, &mut host, &Mc::new().rp_name(Some("Ignored")));
    set_pin(&mut auth, &mut host, 2, PIN);
    let mut auth = restart(&mut host);
    let t = token(&mut auth, &mut host, 2, perm::CM, None);
    let first = body(&cm(&mut auth, &mut host, sub::RPS_BEGIN, None, Some(&t)));
    assert_eq!(
        first.map_get_int(3),
        Some(
            &MapBuilder::new()
                .insert("id", RP)
                .insert("name", "a".repeat(63))
                .build()
        ),
        "newest name, truncated before the two-byte character at byte 63"
    );
    let next = body(&cm(&mut auth, &mut host, sub::RPS_NEXT, None, None));
    assert_eq!(
        next.map_get_int(3),
        Some(&MapBuilder::new().insert("id", OTHER_RP).build()),
        "no rp.name sent, none returned"
    );
}

#[test]
fn without_a_pin_a_presented_token_is_pin_auth_invalid() {
    // Regression: verification answered CTAP2_ERR_PIN_NOT_SET when no PIN was set. CTAP 2.1
    // §6.8.2 to §6.8.6: "If pinUvAuthParam verification fails, authenticator returns
    // CTAP2_ERR_PIN_AUTH_INVALID"; without a PIN no pinUvAuthToken is in use, so verify()
    // fails ("If the key parameter value is the current pinUvAuthToken and it is not in use,
    // then return error", §6.5.6). The model policy PIN_NOT_SET is only for makeCredential /
    // getAssertion, whose step 11 / step 6 name no status in that state.
    let (mut auth, mut host) = device();
    register(&mut auth, &mut host, &Mc::new().rk());
    for protocol in [1u8, 2] {
        let forged = Token {
            protocol,
            value: vec![0x42; 32],
        };
        for command in [0x0A, 0x41] {
            let r = send_untouched(
                &mut auth,
                &mut host,
                &cm_request(command, sub::METADATA, None, Some(&forged)),
            );
            assert_eq!(r, vec![status::PIN_AUTH_INVALID], "command {command:#04x}");
        }
    }
    assert_eq!(
        cm(&mut auth, &mut host, sub::METADATA, None, None),
        vec![status::PUAT_REQUIRED]
    );
}
