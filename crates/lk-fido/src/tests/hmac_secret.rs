//! The hmac-secret extension output in authenticatorGetAssertion (CTAP 2.1 §12.5), checked
//! with the independent platform: the platform encrypts the salts with its shared secret,
//! decrypts the output, and compares outputs across requests.

use super::platform::{PIN, Platform, perm, set_pin, token};
use super::*;
use crate::status;

const SALT1: [u8; 32] = [0x51; 32];
const SALT2: [u8; 32] = [0x52; 32];

/// The hmac-secret input `{1: keyAgreement, 2: saltEnc, 3: saltAuth, 4: protocol}`
/// (§12.5); protocol 1 inputs omit key 4 when `explicit` is false (it defaults to 1).
fn input(platform: &mut Platform, salts: &[u8], explicit: bool) -> Value {
    let salt_enc = platform.encrypt(salts);
    let salt_auth = platform.mac_shared(&salt_enc);
    let mut m = MapBuilder::new()
        .insert(1, platform.cose_key())
        .insert(2, salt_enc)
        .insert(3, salt_auth);
    if explicit {
        m.set(4, platform.protocol);
    }
    m.build()
}

/// The decrypted hmac-secret output of an assertion.
fn output(platform: &Platform, a: &Assertion) -> Vec<u8> {
    let enc = a
        .auth_data
        .extensions
        .as_ref()
        .and_then(|e| e.map_get_text("hmac-secret"))
        .and_then(Value::as_bytes)
        .expect("hmac-secret output")
        .to_vec();
    let expected_len = if platform.protocol == 1 { 0 } else { 16 };
    assert!(enc.len() == 32 + expected_len || enc.len() == 64 + expected_len);
    platform.decrypt(&enc)
}

/// getAssertion `ga` with an hmac-secret input for `salts`: the assertion and its
/// decrypted output. Protocol 1 inputs leave pinUvAuthProtocol out (it defaults to 1).
fn hmac_output(
    auth: &mut Authenticator,
    host: &mut TestHost,
    platform: &mut Platform,
    ga: Ga,
    salts: &[u8],
) -> (Assertion, Vec<u8>) {
    let explicit = platform.protocol == 2;
    let ga = ga.ext("hmac-secret", input(platform, salts, explicit));
    let a = assert(auth, host, &ga);
    let out = output(platform, &a);
    (a, out)
}

#[test]
fn output_decrypts_and_is_deterministic_for_both_protocols() {
    // CTAP 2.1 §12.5: output1 = HMAC-SHA-256(CredRandom, salt1), output2 with salt2,
    // encrypted with the shared secret; the same salt gives the same output for the same
    // credential, a different salt or credential a different one.
    for protocol in [1u8, 2] {
        let (mut auth, mut host) = device();
        let reg = register(&mut auth, &mut host, &Mc::new().ext("hmac-secret", true));
        let other = register(&mut auth, &mut host, &Mc::new().ext("hmac-secret", true));
        let mut platform = Platform::connect(&mut auth, &mut host, protocol);
        let ga = |id: Vec<u8>| Ga::new().allow(vec![id]);
        let (a, one) = hmac_output(&mut auth, &mut host, &mut platform, ga(reg.id()), &SALT1);
        assert!(a.verifies_with(&reg.public_key()));
        assert_eq!(a.auth_data.flags, 0x81, "UP | ED");
        assert_eq!(one.len(), 32);
        let (_, again) = hmac_output(&mut auth, &mut host, &mut platform, ga(reg.id()), &SALT1);
        assert_eq!(again, one, "deterministic");
        let both_salts = [SALT1, SALT2].concat();
        let (_, both) = hmac_output(
            &mut auth,
            &mut host,
            &mut platform,
            ga(reg.id()),
            &both_salts,
        );
        assert_eq!(both.len(), 64);
        assert_eq!(
            both[..32],
            one[..],
            "output1 is the same with salt2 present"
        );
        assert_ne!(both[32..], one[..]);
        let swapped_salts = [SALT2, SALT1].concat();
        let (_, swapped) = hmac_output(
            &mut auth,
            &mut host,
            &mut platform,
            ga(reg.id()),
            &swapped_salts,
        );
        assert_eq!(swapped[..32], both[32..]);
        let (_, other_out) =
            hmac_output(&mut auth, &mut host, &mut platform, ga(other.id()), &SALT1);
        assert_ne!(other_out, one, "per-credential CredRandom");
        // A new shared secret (power cycle) decrypts to the same output.
        auth.power_cycle(&mut host);
        let mut platform = Platform::connect(&mut auth, &mut host, protocol);
        let (_, after) = hmac_output(&mut auth, &mut host, &mut platform, ga(reg.id()), &SALT1);
        assert_eq!(after, one);
    }
}

#[test]
fn outputs_with_and_without_user_verification_differ() {
    // CTAP 2.1 §12.5: CredRandomWithUV is used when UV was performed, CredRandomWithoutUV
    // otherwise (BEHAVIOR_CATALOG FIDO: "derived dual hmac-secret ... across restart").
    let (mut auth, mut host) = device();
    set_pin(&mut auth, &mut host, 2, PIN);
    let reg = register(&mut auth, &mut host, &Mc::new().ext("hmac-secret", true));
    let ga = || Ga::new().allow(vec![reg.id()]);
    let mut platform = Platform::connect(&mut auth, &mut host, 2);
    let (a, without) = hmac_output(&mut auth, &mut host, &mut platform, ga(), &SALT1);
    assert_eq!(a.auth_data.flags, 0x81, "UP | ED");
    let t = token(&mut auth, &mut host, 2, perm::GA, None);
    let mut platform = Platform::connect(&mut auth, &mut host, 2);
    let (a, with) = hmac_output(
        &mut auth,
        &mut host,
        &mut platform,
        ga().with_token(&t),
        &SALT1,
    );
    assert_eq!(a.auth_data.flags, 0x85, "UP | UV | ED");
    assert_ne!(with, without);
    // Both survive a restart: they are derived from the wrapped credential.
    let mut auth = restart(&mut host);
    let mut platform = Platform::connect(&mut auth, &mut host, 2);
    let (_, again) = hmac_output(&mut auth, &mut host, &mut platform, ga(), &SALT1);
    assert_eq!(again, without);
    let t = token(&mut auth, &mut host, 2, perm::GA, None);
    let mut platform = Platform::connect(&mut auth, &mut host, 2);
    let (_, again) = hmac_output(
        &mut auth,
        &mut host,
        &mut platform,
        ga().with_token(&t),
        &SALT1,
    );
    assert_eq!(again, with);
}

#[test]
fn discoverable_credentials_get_their_own_outputs_through_get_next_assertion() {
    // CTAP 2.1 §6.3: each credential's assertion carries its own extension output.
    let (mut auth, mut host) = device();
    register(
        &mut auth,
        &mut host,
        &Mc::new().rk().user(b"1").ext("hmac-secret", true),
    );
    register(
        &mut auth,
        &mut host,
        &Mc::new().rk().user(b"2").ext("hmac-secret", true),
    );
    let mut platform = Platform::connect(&mut auth, &mut host, 1);
    let (first, out1) = hmac_output(&mut auth, &mut host, &mut platform, Ga::new(), &SALT1);
    assert_eq!(first.count, Some(2));
    let second = parse_assertion(&send_untouched(&mut auth, &mut host, &[0x08]));
    assert_ne!(out1, output(&platform, &second));
}

#[test]
fn a_valid_input_with_up_false_is_unsupported_option_without_counter() {
    // BEHAVIOR_CATALOG FIDO: "getAssertion with hmac-secret and up=false rejects with
    // UnsupportedOption (0x2B), without advancing the signature counter" (CTAP 2.1 §12.5),
    // also for an input that would otherwise verify.
    for protocol in [1u8, 2] {
        let (mut auth, mut host) = device();
        let reg = register(&mut auth, &mut host, &Mc::new().ext("hmac-secret", true));
        let mut platform = Platform::connect(&mut auth, &mut host, protocol);
        let ext = input(&mut platform, &SALT1, true);
        let ga = Ga::new()
            .allow(vec![reg.id()])
            .ext("hmac-secret", ext)
            .option("up", false);
        let before = host.persisted(Record::Fido);
        assert_eq!(
            send_untouched(&mut auth, &mut host, &ga.encode()),
            vec![status::UNSUPPORTED_OPTION]
        );
        assert_eq!(host.persisted(Record::Fido), before);
    }
}

#[test]
fn credentials_created_without_hmac_secret_give_no_output() {
    // CTAP 2.1 §12.5: CredRandom values exist only for credentials created with the
    // extension; U2F key handles have none either.
    let (mut auth, mut host) = device();
    let plain = register(&mut auth, &mut host, &Mc::new());
    let mut platform = Platform::connect(&mut auth, &mut host, 2);
    let a = assert(
        &mut auth,
        &mut host,
        &Ga::new()
            .allow(vec![plain.id()])
            .ext("hmac-secret", input(&mut platform, &SALT1, true)),
    );
    assert_eq!(a.auth_data.extensions, None);
    assert_eq!(a.auth_data.flags, 0x01);
}

#[test]
fn input_errors_are_reported_before_the_touch() {
    // CTAP 2.1 §12.5 GetAssertion processing: an unsupported protocol →
    // CTAP2_ERR_PIN_AUTH_INVALID (the status §12.5 gives when the protocol to use is not
    // supported); a bad keyAgreement → CTAP1_ERR_INVALID_PARAMETER (decapsulate, as in
    // §6.5.5); saltAuth that does not verify → CTAP2_ERR_PIN_AUTH_INVALID; "If the decryption
    // fails, or if the result is not 32 or 64 bytes long, return
    // CTAP1_ERR_INVALID_PARAMETER". No touch is requested and nothing is persisted.
    let (mut auth, mut host) = device();
    let reg = register(&mut auth, &mut host, &Mc::new().ext("hmac-secret", true));
    let mut platform = Platform::connect(&mut auth, &mut host, 2);
    let good = input(&mut platform, &SALT1, true);
    // A copy of the input with `key` replaced.
    let with = |base: &Value, key: i64, value: Value| {
        let mut e = base.as_map().unwrap().to_vec();
        e.retain(|(k, _)| *k != Value::int_key(key));
        e.push((Value::int_key(key), value));
        Value::Map(e)
    };
    let mut bad_auth = good
        .map_get_int(3)
        .and_then(Value::as_bytes)
        .unwrap()
        .to_vec();
    bad_auth[0] ^= 1;
    let off_curve = MapBuilder::new()
        .insert(1, 2)
        .insert(3, -25)
        .insert(-1, 1)
        .insert(-2, vec![3u8; 32])
        .insert(-3, vec![3u8; 32])
        .build();
    // Well-authenticated salts of the wrong length: 48 bytes, and none at all (IV only).
    let authenticated = |platform: &mut Platform, salt_enc: Vec<u8>| {
        let salt_auth = platform.mac_shared(&salt_enc);
        with(
            &with(&good, 2, Value::Bytes(salt_enc)),
            3,
            Value::Bytes(salt_auth),
        )
    };
    let salt16 = platform.encrypt(&[0u8; 16]);
    let salt48 = platform.encrypt(&[0u8; 48]);
    let salt80 = platform.encrypt(&[0u8; 80]);
    let iv_only = platform.encrypt(&[])[..16].to_vec();
    let mut unaligned = platform.encrypt(&SALT1);
    unaligned.pop();
    let short_x = with(&platform.cose_key(), -2, Value::Bytes(vec![0x11; 31]));
    let mut cases = vec![
        (with(&good, 4, Value::from(3u8)), status::PIN_AUTH_INVALID),
        (with(&good, 4, Value::from(0u8)), status::PIN_AUTH_INVALID),
        (with(&good, 1, off_curve), status::INVALID_PARAMETER),
        (with(&good, 1, short_x), status::INVALID_PARAMETER),
        (
            with(&good, 3, Value::Bytes(bad_auth)),
            status::PIN_AUTH_INVALID,
        ),
        // saltAuth of protocol 1's length does not verify under protocol 2.
        (
            with(&good, 3, Value::Bytes(vec![0; 16])),
            status::PIN_AUTH_INVALID,
        ),
        // Protocol 1 derives another shared secret, so the protocol-2 saltAuth fails.
        (with(&good, 4, Value::from(1u8)), status::PIN_AUTH_INVALID),
        (
            authenticated(&mut platform, salt16),
            status::INVALID_PARAMETER,
        ),
        (
            authenticated(&mut platform, salt48),
            status::INVALID_PARAMETER,
        ),
        (
            authenticated(&mut platform, salt80),
            status::INVALID_PARAMETER,
        ),
        (
            authenticated(&mut platform, iv_only),
            status::INVALID_PARAMETER,
        ),
        (
            authenticated(&mut platform, vec![0; 15]),
            status::INVALID_PARAMETER,
        ),
        (
            authenticated(&mut platform, unaligned),
            status::INVALID_PARAMETER,
        ),
        // Member types and presence (§12.5 input map; CTAP 2.1 §8 error mapping).
        (
            with(&good, 2, Value::from("salt")),
            status::CBOR_UNEXPECTED_TYPE,
        ),
        (
            with(&good, 4, Value::int_key(-1)),
            status::CBOR_UNEXPECTED_TYPE,
        ),
        (
            Value::Map(
                good.as_map()
                    .unwrap()
                    .iter()
                    .filter(|(k, _)| *k != Value::int_key(3))
                    .cloned()
                    .collect(),
            ),
            status::MISSING_PARAMETER,
        ),
    ];
    // Protocol 1 (no key 4): salts of the wrong length or not whole blocks.
    let mut p1 = Platform::connect(&mut auth, &mut host, 1);
    let p1_input = |p1: &mut Platform, salt_enc: Vec<u8>| {
        let salt_auth = p1.mac_shared(&salt_enc);
        MapBuilder::new()
            .insert(1, p1.cose_key())
            .insert(2, salt_enc)
            .insert(3, salt_auth)
            .build()
    };
    for salt_enc in [
        p1.encrypt(&[0u8; 16]),
        p1.encrypt(&[0u8; 48]),
        p1.encrypt(&[0u8; 96]),
        vec![0u8; 33],
        Vec::new(),
    ] {
        cases.push((p1_input(&mut p1, salt_enc), status::INVALID_PARAMETER));
    }
    let attempts = host.persist_attempts();
    for (ext, want) in cases {
        let request = Ga::new()
            .allow(vec![reg.id()])
            .ext("hmac-secret", ext.clone())
            .encode();
        assert_eq!(
            send_untouched(&mut auth, &mut host, &request),
            vec![want],
            "{ext:?}"
        );
    }
    assert_eq!(host.persist_attempts(), attempts, "nothing persisted");
    assert_eq!(persisted_state(&host).counter, 0);
    // A protocol 1 platform that sends key 4 = 1 explicitly is the same as omitting it.
    let explicit = input(&mut p1, &SALT1, true);
    let a = assert(
        &mut auth,
        &mut host,
        &Ga::new().allow(vec![reg.id()]).ext("hmac-secret", explicit),
    );
    assert_eq!(output(&p1, &a).len(), 32);
    // The good input still works afterwards.
    let a = assert(
        &mut auth,
        &mut host,
        &Ga::new().allow(vec![reg.id()]).ext("hmac-secret", good),
    );
    assert_eq!(output(&platform, &a).len(), 32);
}
