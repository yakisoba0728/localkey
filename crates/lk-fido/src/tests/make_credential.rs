//! authenticatorMakeCredential (CTAP 2.1 §6.1) and packed attestation (WebAuthn L2 §8.2).

use lk_codec::x509::oid;

use super::*;
use crate::status;

const ALGS: [i64; 3] = [-7, -8, -35];

#[test]
fn round_trip_all_algorithms_with_packed_attestation() {
    // WebAuthn L2 §8.2.1 verification procedure: sig over authenticatorData ||
    // clientDataHash with the attestnCert key, alg -7; authData per §6.1 / §6.5.1.
    let (mut auth, mut host) = device();
    for (assertions_so_far, alg) in (0u32..).zip(ALGS) {
        let reg = register(&mut auth, &mut host, &Mc::new().alg(alg));
        assert_eq!(reg.fmt, "packed");
        let ad = &reg.auth_data;
        assert_eq!(ad.rp_id_hash, sha256(RP.as_bytes()));
        assert_eq!(ad.flags, 0x41, "UP | AT");
        assert_eq!(
            ad.counter, assertions_so_far,
            "registration reports the shared counter without advancing it"
        );
        assert_eq!(ad.aaguid.as_deref(), Some(&host.profile().aaguid[..]));
        assert_eq!(reg.id().len(), 128, "catalog: RP-bound 128-byte IDs");
        let cose = reg.public_key();
        assert_eq!(cose.map_get_int(3).and_then(Value::as_i64), Some(alg));
        assert_eq!(
            reg.att_stmt.map_get_text("alg").and_then(Value::as_i64),
            Some(-7)
        );
        let x5c = reg
            .att_stmt
            .map_get_text("x5c")
            .and_then(Value::as_array)
            .unwrap();
        assert_eq!(x5c.len(), 1, "trust anchor omitted from x5c");
        let sig = reg
            .att_stmt
            .map_get_text("sig")
            .and_then(Value::as_bytes)
            .unwrap();
        let point = cert_public_key(&reg.cert());
        let signed = [ad.raw.as_slice(), &CDH].concat();
        assert!(
            ecdsa_verify_prehash(Curve::P256, &point, &sha256(&signed), sig),
            "attestation signature"
        );

        // The credential signs assertions verifiable with its COSE key.
        let a = assert(&mut auth, &mut host, &Ga::new().allow(vec![reg.id()]));
        assert_eq!(a.cred_id, reg.id());
        assert!(a.verifies_with(&cose), "assertion signature alg {alg}");
        assert!(
            a.user.is_none(),
            "non-discoverable credentials carry no user"
        );
    }
}

#[test]
fn signatures_are_hedged_and_differ_between_identical_requests() {
    // docs/CONTRACTS.md "Phase 0 as implemented": device-visible ECDSA uses the hedged
    // RFC 6979 §3.6 nonce, so the same message signed twice gives different signatures.
    let (mut auth, mut host) = device();
    let reg = register(&mut auth, &mut host, &Mc::new());
    let ga = Ga::new().allow(vec![reg.id()]);
    // Two authenticators restored from the same state sign the same authData.
    let mut auth2 = restart(&mut host);
    let a = assert(&mut auth, &mut host, &ga);
    let b = assert(&mut auth2, &mut host, &ga);
    assert_eq!(a.auth_data.raw, b.auth_data.raw, "same signed bytes");
    assert_ne!(a.signature, b.signature);
}

#[test]
fn attestation_certificate_meets_webauthn_8_2_1_and_chains_to_own_root() {
    // WebAuthn L2 §8.2.1: v3; subject C, O, OU "Authenticator Attestation", CN; basic
    // constraints CA false; id-fido-gen-ce-aaguid matches authData; RFC 5280 §4.1 chain.
    let (mut auth, mut host) = device();
    let reg = register(&mut auth, &mut host, &Mc::new());
    let cert = reg.cert();
    assert_eq!(cert_version(&cert), vec![2], "version 3");
    let subject = cert_name(&cert, 5);
    let attr = |o: &[u64]| subject.iter().find(|(k, _)| k == o).map(|(_, v)| v.clone());
    assert_eq!(attr(oid::COUNTRY_NAME).map(|c| c.len()), Some(2));
    assert!(attr(oid::ORGANIZATION_NAME).is_some());
    assert_eq!(
        attr(oid::ORGANIZATIONAL_UNIT_NAME).as_deref(),
        Some("Authenticator Attestation")
    );
    assert_eq!(
        attr(oid::COMMON_NAME),
        Some(host.profile().attestation_common_name.clone())
    );
    assert_eq!(
        cert_extension(&cert, oid::BASIC_CONSTRAINTS),
        Some((true, vec![0x30, 0x00]))
    );
    let (critical, aaguid) = cert_extension(&cert, oid::FIDO_GEN_CE_AAGUID).unwrap();
    assert!(!critical);
    assert_eq!(aaguid, der::octet_string(&host.profile().aaguid));

    let root = persisted_state(&host).attestation.unwrap().root_cert;
    let root_point = cert_public_key(&root);
    assert!(cert_signed_by(&root, &root_point), "root is self-signed");
    assert!(
        cert_signed_by(&cert, &root_point),
        "leaf is issued by the root"
    );
    assert_eq!(
        cert_name(&cert, 3),
        cert_name(&root, 5),
        "issuer = root subject"
    );
    let (critical, bc) = cert_extension(&root, oid::BASIC_CONSTRAINTS).unwrap();
    assert!(critical);
    assert_eq!(&bc[..5], &[0x30, 0x06, 0x01, 0x01, 0xFF], "root cA true");
}

#[test]
fn attestation_is_reissued_when_the_profile_identity_changes() {
    // WebAuthn L2 §8.2.1: the certificate AAGUID must match authenticatorData.
    let (mut auth, mut host) = device();
    let first = register(&mut auth, &mut host, &Mc::new());
    host.profile_mut().aaguid = [0xAB; 16];
    let second = register(&mut auth, &mut host, &Mc::new());
    assert_ne!(first.cert(), second.cert());
    let (_, aaguid) = cert_extension(&second.cert(), oid::FIDO_GEN_CE_AAGUID).unwrap();
    assert_eq!(aaguid, der::octet_string(&[0xAB; 16]));
    assert_eq!(second.auth_data.aaguid.as_deref(), Some(&[0xAB; 16][..]));
    // The wrapping secret is unchanged, so the earlier credential still works.
    let a = assert(&mut auth, &mut host, &Ga::new().allow(vec![first.id()]));
    assert!(a.verifies_with(&first.public_key()));
}

fn mc_status(auth: &mut Authenticator, host: &mut TestHost, params: &Value) -> u8 {
    status_of(&send(auth, host, &encode_request(0x01, params)))
}

#[test]
fn missing_required_parameters_are_missing_parameter() {
    // CTAP 2.1 §6.1.1: clientDataHash, rp, user, pubKeyCredParams are required; rp.id,
    // user.id and the PublicKeyCredentialParameters members are required.
    let (mut auth, mut host) = device();
    let base = Mc::new().params();
    for key in 1..=4 {
        assert_eq!(
            mc_status(&mut auth, &mut host, &set_param(&base, key, None)),
            status::MISSING_PARAMETER,
            "key {key}"
        );
    }
    let rp = MapBuilder::new().insert("name", "x").build();
    assert_eq!(
        mc_status(&mut auth, &mut host, &set_param(&base, 2, Some(rp))),
        status::MISSING_PARAMETER
    );
    let user = MapBuilder::new().insert("name", "x").build();
    assert_eq!(
        mc_status(&mut auth, &mut host, &set_param(&base, 3, Some(user))),
        status::MISSING_PARAMETER
    );
    let no_alg = Value::Array(vec![MapBuilder::new().insert("type", "public-key").build()]);
    assert_eq!(
        mc_status(&mut auth, &mut host, &set_param(&base, 4, Some(no_alg))),
        status::MISSING_PARAMETER
    );
    let no_type = Value::Array(vec![MapBuilder::new().insert("alg", -7).build()]);
    assert_eq!(
        mc_status(&mut auth, &mut host, &set_param(&base, 4, Some(no_type))),
        status::MISSING_PARAMETER
    );
    let bad_exclude = Value::Array(vec![MapBuilder::new().insert("type", "public-key").build()]);
    assert_eq!(
        mc_status(
            &mut auth,
            &mut host,
            &set_param(&base, 5, Some(bad_exclude))
        ),
        status::MISSING_PARAMETER
    );
}

#[test]
fn wrong_types_are_cbor_unexpected_type() {
    // CTAP 2.1 §6.1.2 step 3 ("values of any known members have the wrong type") and §8.
    let (mut auth, mut host) = device();
    let base = Mc::new().params();
    let text = || Value::from("x");
    let cases: Vec<(i64, Value)> = vec![
        (1, text()),
        (2, Value::Array(vec![])),
        (2, MapBuilder::new().insert("id", vec![1u8]).build()),
        (
            2,
            MapBuilder::new().insert("id", RP).insert("name", 5).build(),
        ),
        (3, text()),
        (3, MapBuilder::new().insert("id", "text-id").build()),
        (
            3,
            MapBuilder::new()
                .insert("id", vec![1u8])
                .insert("name", 1)
                .build(),
        ),
        (
            3,
            MapBuilder::new()
                .insert("id", vec![1u8])
                .insert("displayName", vec![1u8])
                .build(),
        ),
        (4, MapBuilder::new().build()),
        (4, Value::Array(vec![text()])),
        (
            4,
            Value::Array(vec![
                MapBuilder::new()
                    .insert("alg", "ES256")
                    .insert("type", "public-key")
                    .build(),
            ]),
        ),
        (
            4,
            Value::Array(vec![
                MapBuilder::new()
                    .insert("alg", -7)
                    .insert("type", 1)
                    .build(),
            ]),
        ),
        (5, text()),
        (
            5,
            Value::Array(vec![
                MapBuilder::new()
                    .insert("type", "public-key")
                    .insert("id", "x")
                    .build(),
            ]),
        ),
        (6, text()),
        (6, MapBuilder::new().insert("credProtect", "high").build()),
        (6, MapBuilder::new().insert("credBlob", "blob").build()),
        (6, MapBuilder::new().insert("hmac-secret", 1).build()),
        (6, MapBuilder::new().insert("largeBlobKey", 1).build()),
        (6, MapBuilder::new().insert("minPinLength", "yes").build()),
        (7, text()),
        (7, MapBuilder::new().insert("rk", 1).build()),
        (7, MapBuilder::new().insert("up", "true").build()),
        (7, MapBuilder::new().insert("uv", Value::Null).build()),
        (8, text()),
        (9, text()),
        (10, Value::Bool(true)),
        (10, Value::int_key(-1)),
    ];
    for (key, value) in cases {
        let params = set_param(&base, key, Some(value.clone()));
        assert_eq!(
            mc_status(&mut auth, &mut host, &params),
            status::CBOR_UNEXPECTED_TYPE,
            "key {key} = {value:?}"
        );
    }
}

#[test]
fn malformed_cbor_is_invalid_cbor() {
    // CTAP 2.1 §8: well-formed canonical CBOR without tags or duplicate keys.
    let (mut auth, mut host) = device();
    let valid = Mc::new().encode();
    let cases: Vec<Vec<u8>> = vec![
        vec![0x01],                               // no parameters
        valid[..valid.len() - 1].to_vec(),        // truncated
        [valid.as_slice(), &[0x00]].concat(),     // trailing byte
        vec![0x01, 0xA2, 0x01, 0x40, 0x01, 0x40], // duplicate key
        vec![0x01, 0xA1, 0x01, 0xD8, 0x18, 0x40], // tag 24
        vec![0x01, 0xBF, 0xFF],                   // indefinite map
    ];
    for request in cases {
        assert_eq!(
            status_of(&send(&mut auth, &mut host, &request)),
            status::INVALID_CBOR,
            "{request:02x?}"
        );
    }
    assert_eq!(
        status_of(&send(&mut auth, &mut host, &[0x01, 0x80])),
        status::CBOR_UNEXPECTED_TYPE
    );
}

#[test]
fn unknown_parameters_and_float_values_are_ignored() {
    // CTAP 2.1 §8 (unknown keys MUST be ignored); BEHAVIOR_CATALOG FIDO: canonical
    // half/float/double values in unknown request fields are skipped.
    let (mut auth, mut host) = device();
    let base = Mc::new().params();
    let params = set_param(&base, 0x20, Some(Value::Float(0x3C00, 2)));
    let params = set_param(&params, 0x21, Some(Value::Float(0x3FF0_0000_0000_0000, 8)));
    let mut entries = params.as_map().unwrap().to_vec();
    entries.push((Value::from("text-key"), Value::Float(0x3F80_0000, 4)));
    let reg = parse_registration(&send(
        &mut auth,
        &mut host,
        &encode_request(0x01, &Value::Map(entries)),
    ));
    assert_eq!(reg.fmt, "packed");
}

#[test]
fn algorithm_selection_and_unsupported_algorithms() {
    // CTAP 2.1 §6.1.2 step 3: the first supported "public-key" algorithm, else
    // CTAP2_ERR_UNSUPPORTED_ALGORITHM; unknown credential types are skipped.
    let (mut auth, mut host) = device();
    let mut mc = Mc::new();
    mc.algs = vec![-257, -8, -7];
    assert_eq!(
        register(&mut auth, &mut host, &mc)
            .public_key()
            .map_get_int(3)
            .and_then(Value::as_i64),
        Some(-8)
    );
    mc.algs = vec![-35, -7];
    assert_eq!(
        register(&mut auth, &mut host, &mc)
            .public_key()
            .map_get_int(3)
            .and_then(Value::as_i64),
        Some(-35)
    );
    mc.algs = vec![-257, -37];
    assert_eq!(
        status_of(&send(&mut auth, &mut host, &mc.encode())),
        status::UNSUPPORTED_ALGORITHM
    );
    mc.algs = vec![];
    assert_eq!(
        status_of(&send(&mut auth, &mut host, &mc.encode())),
        status::UNSUPPORTED_ALGORITHM
    );
    let other_type = Value::Array(vec![
        MapBuilder::new()
            .insert("alg", -7)
            .insert("type", "secret-key")
            .build(),
    ]);
    let params = set_param(&Mc::new().params(), 4, Some(other_type));
    assert_eq!(
        mc_status(&mut auth, &mut host, &params),
        status::UNSUPPORTED_ALGORITHM
    );
}

#[test]
fn option_rules() {
    // CTAP 2.1 §6.1.2 step 5: "uv": true without built-in UV and "up": false are
    // CTAP2_ERR_INVALID_OPTION; unknown options are ignored whatever their value
    // (BEHAVIOR_CATALOG FIDO "Unknown CTAP option values are skipped").
    let (mut auth, mut host) = device();
    assert_eq!(
        status_of(&send_untouched(
            &mut auth,
            &mut host,
            &Mc::new().option("up", false).encode()
        )),
        status::INVALID_OPTION
    );
    assert_eq!(
        status_of(&send_untouched(
            &mut auth,
            &mut host,
            &Mc::new().option("uv", true).encode()
        )),
        status::INVALID_OPTION
    );
    let mc = Mc::new()
        .option("plat", Value::Array(vec![]))
        .option("ep", 7)
        .option("zz", Value::Float(0, 2));
    assert_eq!(register(&mut auth, &mut host, &mc).fmt, "packed");
    let reg = register(
        &mut auth,
        &mut host,
        &Mc::new()
            .option("up", true)
            .option("uv", false)
            .option("rk", false),
    );
    assert_eq!(persisted_state(&host).residents.len(), 0);
    assert_eq!(reg.auth_data.flags, 0x41);
}

#[test]
fn enterprise_attestation_is_not_supported() {
    // CTAP 2.1 §6.1.2 step 9 (not enterprise attestation capable → INVALID_PARAMETER);
    // BEHAVIOR_CATALOG FIDO: unsigned 0/1/2/3 → 02, wrong boolean type → 11, no mutation.
    let (mut auth, mut host) = device();
    register(&mut auth, &mut host, &Mc::new());
    let before = host.persisted(Record::Fido);
    let base = Mc::new().rk().params();
    for value in 0u64..=3 {
        let params = set_param(&base, 10, Some(Value::Unsigned(value)));
        assert_eq!(
            status_of(&send_untouched(
                &mut auth,
                &mut host,
                &encode_request(1, &params)
            )),
            status::INVALID_PARAMETER
        );
    }
    let params = set_param(&base, 10, Some(Value::Bool(true)));
    assert_eq!(
        status_of(&send_untouched(
            &mut auth,
            &mut host,
            &encode_request(1, &params)
        )),
        status::CBOR_UNEXPECTED_TYPE
    );
    assert_eq!(
        host.persisted(Record::Fido),
        before,
        "no credential mutation"
    );
}

#[test]
fn exclude_list_hit_returns_credential_excluded_with_or_without_touch() {
    // CTAP 2.1 §6.1.2 step 12.1.4: wait for user presence, then CREDENTIAL_EXCLUDED
    // "regardless of whether user presence is obtained or the authenticator times out".
    let (mut auth, mut host) = device();
    let reg = register(&mut auth, &mut host, &Mc::new());
    let mc = Mc::new().exclude(vec![vec![9; 16], reg.id()]);
    assert_eq!(
        status_of(&send_resolved(&mut auth, &mut host, &mc.encode(), true)),
        status::CREDENTIAL_EXCLUDED
    );
    assert_eq!(
        status_of(&send_resolved(&mut auth, &mut host, &mc.encode(), false)),
        status::CREDENTIAL_EXCLUDED
    );
    // Bound to its RP: another RP's exclude list does not match.
    let other = register(
        &mut auth,
        &mut host,
        &Mc::new().rp("other.example").exclude(vec![reg.id()]),
    );
    assert_eq!(other.fmt, "packed");
}

#[test]
fn exclude_list_skips_user_verification_required_credentials_without_uv() {
    // CTAP 2.1 §6.1.2 step 12.2: a userVerificationRequired credential is removed from
    // the exclude list when UV was not collected.
    let (mut auth, mut host) = device();
    let reg = register(&mut auth, &mut host, &Mc::new().ext("credProtect", 3));
    let again = register(&mut auth, &mut host, &Mc::new().exclude(vec![reg.id()]));
    assert_eq!(again.fmt, "packed");
}

#[test]
fn touch_denied_is_operation_denied_and_cancel_is_keepalive_cancel() {
    // CTAP 2.1 §6.1.2 step 14 ("declines permission, or the operation times out");
    // CTAPHID_CANCEL → CTAP2_ERR_KEEPALIVE_CANCEL (§11.2).
    let (mut auth, mut host) = device();
    assert_eq!(
        status_of(&send_resolved(
            &mut auth,
            &mut host,
            &Mc::new().encode(),
            false
        )),
        status::OPERATION_DENIED
    );
    assert!(matches!(
        auth.cbor(&Mc::new().encode(), &mut host),
        Outcome::NeedTouch { .. }
    ));
    assert_eq!(auth.cancel(&mut host), Some(vec![status::KEEPALIVE_CANCEL]));
    assert!(!auth.is_pending());
    assert_eq!(auth.cancel(&mut host), None);
    assert_eq!(host.persist_attempts(), 0);
}

#[test]
fn pin_uv_auth_param_probe_and_protocol_checks() {
    // CTAP 2.1 §6.1.2 step 1 (zero-length pinUvAuthParam: touch, then PIN_NOT_SET /
    // PIN_INVALID; decline → OPERATION_DENIED) and step 2 (protocol missing / unsupported).
    let (mut auth, mut host) = device();
    let mut mc = Mc::new();
    mc.pin_param = Some(vec![]);
    assert_eq!(
        status_of(&send_resolved(&mut auth, &mut host, &mc.encode(), true)),
        status::PIN_NOT_SET
    );
    assert_eq!(
        status_of(&send_resolved(&mut auth, &mut host, &mc.encode(), false)),
        status::OPERATION_DENIED
    );
    mc.pin_param = Some(vec![0; 16]);
    assert_eq!(
        status_of(&send_untouched(&mut auth, &mut host, &mc.encode())),
        status::MISSING_PARAMETER
    );
    mc.pin_protocol = Some(3);
    assert_eq!(
        status_of(&send_untouched(&mut auth, &mut host, &mc.encode())),
        status::INVALID_PARAMETER
    );
    mc.pin_protocol = Some(2);
    assert_eq!(
        status_of(&send_untouched(&mut auth, &mut host, &mc.encode())),
        status::PIN_NOT_SET
    );
    // With a PIN set, the probe reports PIN_INVALID and a
    // discoverable credential needs a pinUvAuthToken (step 7, makeCredUvNotRqd).
    register(&mut auth, &mut host, &Mc::new());
    let mut auth = with_state(&mut host, |s| s.pin.hash = Some([7; 16]));
    let mut probe = Mc::new();
    probe.pin_param = Some(vec![]);
    assert_eq!(
        status_of(&send_resolved(&mut auth, &mut host, &probe.encode(), true)),
        status::PIN_INVALID
    );
    assert_eq!(
        status_of(&send_untouched(
            &mut auth,
            &mut host,
            &Mc::new().rk().encode()
        )),
        status::PUAT_REQUIRED
    );
    assert_eq!(
        register(&mut auth, &mut host, &Mc::new()).fmt,
        "packed",
        "makeCredUvNotRqd"
    );
    mc.pin_protocol = Some(1);
    assert_eq!(
        status_of(&send_untouched(&mut auth, &mut host, &mc.encode())),
        status::PIN_AUTH_INVALID
    );
}

#[test]
fn discoverable_credential_extensions_and_large_blob_key() {
    // CTAP 2.1 §12.1 credProtect output, §12.2 credBlob stored → true, §12.3 largeBlobKey
    // at response key 0x05 (no authData output), §12.5 hmac-secret true, §12.4
    // minPinLength only for listed RPs.
    let (mut auth, mut host) = device();
    let mc = Mc::new()
        .rk()
        .ext("credProtect", 2)
        .ext("credBlob", vec![0xB1; 32])
        .ext("largeBlobKey", true)
        .ext("hmac-secret", true)
        .ext("minPinLength", true)
        .ext("unknownExt", Value::Float(0, 2));
    let reg = register(&mut auth, &mut host, &mc);
    assert_eq!(reg.auth_data.flags, 0xC1, "UP | AT | ED");
    let want = MapBuilder::new()
        .insert("credProtect", 2)
        .insert("credBlob", true)
        .insert("hmac-secret", true)
        .build();
    assert_eq!(reg.auth_data.extensions, Some(want));
    assert_eq!(reg.large_blob_key.as_ref().map(Vec::len), Some(32));
    let stored = persisted_state(&host);
    assert_eq!(stored.residents.len(), 1);
    assert_eq!(stored.residents[0].cred_blob, Some(vec![0xB1; 32]));
    assert_eq!(
        stored.residents[0].large_blob_key.map(|k| k.to_vec()),
        reg.large_blob_key
    );
    assert_eq!(stored.residents[0].cred_protect, 2);

    // minPinLength is reported once the RP is on the list (injected here; set through
    // authenticatorConfig in tests::config::an_empty_rp_id_list_preserves_the_previous_list).
    let mut auth = with_state(&mut host, |s| s.pin.min_pin_rp_ids = vec![RP.into()]);
    let reg = register(&mut auth, &mut host, &Mc::new().ext("minPinLength", true));
    let want = MapBuilder::new().insert("minPinLength", 4).build();
    assert_eq!(reg.auth_data.extensions, Some(want));
}

#[test]
fn cred_blob_is_stored_only_for_discoverable_credentials_within_32_bytes() {
    // CTAP 2.1 §12.2 ("credBlob": false when it cannot be stored);
    // reference/legacy-v0.64-profiles.json credBlob_policy (discoverable only).
    let (mut auth, mut host) = device();
    let reg = register(&mut auth, &mut host, &Mc::new().ext("credBlob", vec![1; 8]));
    assert_eq!(
        reg.auth_data.extensions,
        Some(MapBuilder::new().insert("credBlob", false).build())
    );
    let reg = register(
        &mut auth,
        &mut host,
        &Mc::new().rk().ext("credBlob", vec![1; 33]),
    );
    assert_eq!(
        reg.auth_data.extensions,
        Some(MapBuilder::new().insert("credBlob", false).build())
    );
    assert_eq!(persisted_state(&host).residents[0].cred_blob, None);
}

#[test]
fn large_blob_key_requires_true_and_rk() {
    // CTAP 2.1 §12.3: not true → INVALID_OPTION; rk not true → INVALID_OPTION.
    let (mut auth, mut host) = device();
    let r = send_untouched(
        &mut auth,
        &mut host,
        &Mc::new().ext("largeBlobKey", true).encode(),
    );
    assert_eq!(status_of(&r), status::INVALID_OPTION);
    let r = send_untouched(
        &mut auth,
        &mut host,
        &Mc::new().rk().ext("largeBlobKey", false).encode(),
    );
    assert_eq!(status_of(&r), status::INVALID_OPTION);
}

#[test]
fn unsupported_cred_protect_levels_are_ignored() {
    // CTAP 2.1 §12.1 defines levels 1-3 and forbids unsolicited output; other values are
    // treated as not understood (model policy).
    let (mut auth, mut host) = device();
    for level in [0u64, 4, 1000] {
        let reg = register(&mut auth, &mut host, &Mc::new().ext("credProtect", level));
        assert_eq!(reg.auth_data.extensions, None);
        assert_eq!(reg.auth_data.flags & 0x80, 0);
    }
}

#[test]
fn non_resident_registrations_leave_the_initialized_store_unchanged() {
    // BEHAVIOR_CATALOG FIDO: "initialized store remains constant across ... software
    // nonresident registrations"; legacy-v0.64-profiles.json nonresident_model.
    let (mut auth, mut host) = device();
    register(&mut auth, &mut host, &Mc::new());
    assert_eq!(host.persist_count(), 1, "first use initializes the store");
    let initialized = host.persisted(Record::Fido);
    let mut ids = Vec::new();
    for i in 0..25u8 {
        let alg = ALGS[usize::from(i) % 3];
        ids.push(register(&mut auth, &mut host, &Mc::new().alg(alg).user(&[i])).id());
    }
    assert_eq!(host.persist_count(), 1);
    assert_eq!(host.persisted(Record::Fido), initialized);
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 25, "every ID is distinct");
}

#[test]
fn same_user_overwrites_and_capacity_is_one_hundred() {
    // CTAP 2.1 §6.1.2 step 17: same rp.id and user id overwrite; no room → KEY_STORE_FULL.
    // BEHAVIOR_CATALOG FIDO: "full resident capacity permits further nonresident
    // registration"; capacity 100 (legacy-v0.64-profiles.json discoverable_capacity).
    let (mut auth, mut host) = device();
    let first = register(&mut auth, &mut host, &Mc::new().rk().alg(-8).user(&[0, 0]));
    let replaced = register(&mut auth, &mut host, &Mc::new().rk().alg(-8).user(&[0, 0]));
    assert_eq!(persisted_state(&host).residents.len(), 1);
    let r = send(
        &mut auth,
        &mut host,
        &Ga::new().allow(vec![first.id()]).encode(),
    );
    assert_eq!(
        status_of(&r),
        status::NO_CREDENTIALS,
        "overwritten credential is gone"
    );
    assert!(assert(&mut auth, &mut host, &Ga::new()).verifies_with(&replaced.public_key()));

    for i in 1..100u16 {
        register(
            &mut auth,
            &mut host,
            &Mc::new().rk().alg(-8).user(&i.to_be_bytes()),
        );
    }
    let info = get_info(&mut auth, &mut host);
    assert_eq!(info.map_get_int(0x14).and_then(Value::as_u64), Some(0));
    let r = send(
        &mut auth,
        &mut host,
        &Mc::new().rk().alg(-8).user(&[0xFF, 0xFF]).encode(),
    );
    assert_eq!(status_of(&r), status::KEY_STORE_FULL);
    assert_eq!(persisted_state(&host).residents.len(), 100);
    // A non-discoverable registration and an overwrite still work at capacity.
    assert_eq!(
        register(&mut auth, &mut host, &Mc::new().alg(-8)).fmt,
        "packed"
    );
    assert_eq!(
        register(&mut auth, &mut host, &Mc::new().rk().alg(-8).user(&[0, 7])).fmt,
        "packed"
    );
    assert_eq!(persisted_state(&host).residents.len(), 100);
}

#[test]
fn user_names_are_truncated_to_64_bytes_on_a_character_boundary() {
    // WebAuthn L2 §6.4.1 string truncation.
    let (mut auth, mut host) = device();
    let mut mc = Mc::new().rk();
    mc.user_name = Some(format!("a{}", "é".repeat(40))); // 81 bytes; byte 64 splits an "é"
    register(&mut auth, &mut host, &mc);
    let row = &persisted_state(&host).residents[0];
    assert_eq!(row.user_name, Some(format!("a{}", "é".repeat(31))));
    assert_eq!(row.display_name.as_ref().map(String::len), Some(63));
}

#[test]
fn request_size_and_unknown_commands() {
    // GetInfo maxMsgSize 1536 (reference-observation.json); CTAP 2.1 §8.1 command codes.
    let (mut auth, mut host) = device();
    let mut long = Mc::new();
    long.user_name = Some("x".repeat(1400));
    let request = long.encode();
    assert!(request.len() > 1536);
    assert_eq!(
        send_untouched(&mut auth, &mut host, &request),
        vec![status::INVALID_LENGTH]
    );
    assert_eq!(
        send_untouched(&mut auth, &mut host, &[]),
        vec![status::INVALID_LENGTH]
    );
    // Commands 0x06, 0x0A, 0x0C, 0x0D and 0x41 are implemented (tests::client_pin,
    // tests::cred_mgmt, tests::large_blobs, tests::config); these are not CTAP 2.1
    // commands.
    for command in [0x00u8, 0x03, 0x05, 0x09, 0x0E, 0x10, 0x40, 0x42, 0xBF, 0xFF] {
        assert_eq!(
            send_untouched(&mut auth, &mut host, &[command, 0xA0]),
            vec![status::INVALID_COMMAND],
            "{command:#04x}"
        );
    }
}

/// The catalog's full count; long-running, so it is kept out of the default run
/// (docs/DESIGN.md §11): `cargo test -p lk-fido -- --ignored`.
#[test]
#[ignore = "long repeat test (10001 registrations); run with --ignored"]
fn ten_thousand_and_one_non_resident_registrations_leave_the_store_unchanged() {
    // BEHAVIOR_CATALOG FIDO: "initialized store remains constant across 10001 software
    // nonresident registrations".
    let (mut auth, mut host) = device();
    let first = register(&mut auth, &mut host, &Mc::new().alg(-8));
    let initialized = host.persisted(Record::Fido);
    let mut last = first.clone();
    for i in 1..10_001u32 {
        last = register(
            &mut auth,
            &mut host,
            &Mc::new().alg(-8).user(&i.to_be_bytes()),
        );
    }
    assert_eq!(host.persist_count(), 1);
    assert_eq!(host.persisted(Record::Fido), initialized);
    for reg in [&first, &last] {
        let a = assert(&mut auth, &mut host, &Ga::new().allow(vec![reg.id()]));
        assert!(a.verifies_with(&reg.public_key()));
    }
}
