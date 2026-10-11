//! Request sequences that host software actually sends, replayed byte-shape for byte-shape.
//!
//! These cover the cross-command state that single-command tests do not: a touch probe that
//! must leave the PIN state alone, and an excludeList "pre-flight" with `"up": false` whose
//! pinUvAuthToken must still authorize the makeCredential that follows (CTAP 2.1 §6.1.1
//! step 1.1.1: "the platform may first invoke the authenticatorGetAssertion operation
//! multiple times to "pre-flight" the "exclude list"").

use super::platform::{PIN, perm, retries, set_pin, token};
use super::*;
use crate::status;

/// libfido2 `fido_dev_get_touch_begin` on a device with `clientPin` in GetInfo: a
/// makeCredential for rp ".dummy", user `{id: h'01', name: "dummy"}`, ES256, clientDataHash
/// SHA-256(""), a zero-length pinUvAuthParam and the device's pinUvAuthProtocol.
fn libfido2_touch_probe(protocol: u64) -> Vec<u8> {
    let params = MapBuilder::new()
        .insert(1, sha256(b"").to_vec())
        .insert(2, MapBuilder::new().insert("id", ".dummy").build())
        .insert(
            3,
            MapBuilder::new()
                .insert("id", vec![0x01u8])
                .insert("name", "dummy")
                .build(),
        )
        .insert(
            4,
            Value::Array(vec![
                MapBuilder::new()
                    .insert("alg", -7)
                    .insert("type", "public-key")
                    .build(),
            ]),
        )
        .insert(8, Vec::<u8>::new())
        .insert(9, protocol)
        .build();
    encode_request(0x01, &params)
}

#[test]
fn libfido2_touch_probe_reports_pin_state_after_a_touch_and_changes_nothing() {
    // CTAP 2.1 §6.1.2 step 1: evidence of user interaction, then CTAP2_ERR_PIN_NOT_SET or
    // CTAP2_ERR_PIN_INVALID; a declined or timed-out touch is CTAP2_ERR_OPERATION_DENIED.
    // libfido2 (fido_dev_get_touch_status) treats PIN_NOT_SET / PIN_INVALID as "touched".
    // The probe is not a PIN attempt: no retry is spent and nothing is persisted.
    let (mut auth, mut host) = device();
    let probe = libfido2_touch_probe(2);
    assert_eq!(
        send_resolved(&mut auth, &mut host, &probe, true),
        vec![status::PIN_NOT_SET]
    );
    assert_eq!(
        send_resolved(&mut auth, &mut host, &probe, false),
        vec![status::OPERATION_DENIED]
    );
    assert_eq!(host.persist_count(), 0, "a probe stores nothing");

    set_pin(&mut auth, &mut host, 2, PIN);
    let saves = host.persist_count();
    for protocol in [1, 2] {
        assert_eq!(
            send_resolved(&mut auth, &mut host, &libfido2_touch_probe(protocol), true),
            vec![status::PIN_INVALID]
        );
    }
    assert_eq!(retries(&mut auth, &mut host), (8, None), "no retry spent");
    assert_eq!(host.persist_count(), saves);
}

/// python-fido2 `_filter_creds`: getAssertion with a 32-byte zero clientDataHash, the
/// excludeList chunk as allowList, `{"up": false}` and pinUvAuthParam =
/// authenticate(pinUvAuthToken, 32 zero bytes) when a token is in use.
fn preflight(ids: &[Vec<u8>], token: Option<&platform::Token>) -> Vec<u8> {
    let zeros = [0u8; 32];
    let mut params = MapBuilder::new()
        .insert(1, RP)
        .insert(2, zeros.to_vec())
        .insert(
            3,
            Value::Array(ids.iter().map(|id| descriptor(id)).collect()),
        )
        .insert(5, MapBuilder::new().insert("up", false).build());
    if let Some(t) = token {
        params.set(6, t.sign(&zeros));
        params.set(7, u64::from(t.protocol));
    }
    encode_request(0x02, &params.build())
}

#[test]
fn python_fido2_exclude_list_preflight_keeps_the_token_for_make_credential() {
    // python-fido2 Fido2Client make_credential with an excludeList: one token with mc | ga
    // and permissions RP ID = rp.id (CTAP 2.1 §6.1.1 step 1.1.2.4: "with the mc (and likely
    // also with the ga) permission (see "pre-flight")"), the silent getAssertion above, then
    // makeCredential with the same token and the found credential as the only excludeList
    // entry. The silent assertion must not consume the token (§6.2.2 step 9 applies only
    // when "up" is true), and the excluded registration still waits for a touch before
    // CTAP2_ERR_CREDENTIAL_EXCLUDED (§6.1.2 step 12.1.4). Without a PIN (Chromium and
    // python-fido2 on an unprotected device) the same pre-flight runs without a token.
    for protocol in [None, Some(1u8), Some(2u8)] {
        let (mut auth, mut host) = device();
        if let Some(p) = protocol {
            set_pin(&mut auth, &mut host, p, PIN);
        }
        let issue = |auth: &mut Authenticator, host: &mut TestHost| {
            protocol.map(|p| token(auth, host, p, perm::MC | perm::GA, Some(RP)))
        };
        let mc_with = |t: &Option<platform::Token>, mc: Mc| match t {
            Some(t) => mc.with_token(t),
            None => mc,
        };
        let t = issue(&mut auth, &mut host);
        let reg = register(&mut auth, &mut host, &mc_with(&t, Mc::new()));
        let unknown = vec![0x77; 128];

        // A known credential: found silently, then the registration is excluded.
        let t = issue(&mut auth, &mut host);
        let found = parse_assertion(&send_untouched(
            &mut auth,
            &mut host,
            &preflight(&[unknown.clone(), reg.id()], t.as_ref()),
        ));
        assert_eq!(found.cred_id, reg.id());
        let uv = if protocol.is_some() { 0x04 } else { 0x00 };
        assert_eq!(found.auth_data.flags, uv, "neither UP nor a consumed token");
        let excluded = mc_with(&t, Mc::new().user(b"bob").exclude(vec![found.cred_id]));
        assert_eq!(
            send_resolved(&mut auth, &mut host, &excluded.encode(), true),
            vec![status::CREDENTIAL_EXCLUDED]
        );

        // Nothing known: NO_CREDENTIALS without a touch, and the token still registers.
        let t = issue(&mut auth, &mut host);
        assert_eq!(
            send_untouched(&mut auth, &mut host, &preflight(&[unknown], t.as_ref())),
            vec![status::NO_CREDENTIALS]
        );
        let fresh = register(&mut auth, &mut host, &mc_with(&t, Mc::new().user(b"bob")));
        assert_eq!(fresh.auth_data.flags, 0x41 | uv, "UP | AT (| UV)");
    }
}
