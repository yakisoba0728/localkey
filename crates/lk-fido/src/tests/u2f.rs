//! U2F raw messages (FIDO U2F Raw Message Formats v1.2) and their interplay with CTAP2.

use lk_codec::apdu::{Command, sw};

use super::*;
use crate::{U2fPresence, status};

const CHALLENGE: [u8; 32] = [0xC4; 32];

fn app() -> [u8; 32] {
    sha256(RP.as_bytes())
}

/// An extended-length APDU (U2F raw message formats v1.2 §3.1: "extended length encoding").
fn apdu(ins: u8, p1: u8, data: &[u8]) -> Vec<u8> {
    Command::new(0x00, ins, p1, 0x00)
        .with_data(data.to_vec())
        .with_le(0)
        .to_bytes()
}

fn split(response: &[u8]) -> (&[u8], u16) {
    lk_codec::apdu::split_response(response).unwrap()
}

struct U2fRegistration {
    public_key: Vec<u8>,
    key_handle: Vec<u8>,
    cert: Vec<u8>,
    signature: Vec<u8>,
}

/// §4.3 registration response: 05 || public key (65) || L || key handle || cert || sig.
fn parse_register(data: &[u8]) -> U2fRegistration {
    assert_eq!(data[0], 0x05, "reserved byte");
    let public_key = data[1..66].to_vec();
    let len = usize::from(data[66]);
    let key_handle = data[67..67 + len].to_vec();
    let (cert, signature) = der::split_der(&data[67 + len..]).unwrap();
    U2fRegistration {
        public_key,
        key_handle,
        cert: cert.to_vec(),
        signature: signature.to_vec(),
    }
}

fn u2f_register(
    auth: &mut Authenticator,
    host: &mut TestHost,
    application: &[u8; 32],
) -> U2fRegistration {
    let (response, presence) = auth.u2f(
        &apdu(0x01, 0x03, &[&CHALLENGE[..], application].concat()),
        true,
        host,
    );
    assert_eq!(presence, U2fPresence::Consumed);
    let (data, sw) = split(&response);
    assert_eq!(sw, sw::OK);
    parse_register(data)
}

fn authenticate_request(p1: u8, application: &[u8; 32], key_handle: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&CHALLENGE);
    data.extend_from_slice(application);
    data.push(u8::try_from(key_handle.len()).unwrap());
    data.extend_from_slice(key_handle);
    apdu(0x02, p1, &data)
}

#[test]
fn version_is_u2f_v2() {
    // U2F raw message formats v1.2 §6.1: "U2F_V2" without a terminator.
    let (mut auth, mut host) = device();
    let (response, presence) = auth.u2f(&[0x00, 0x03, 0x00, 0x00], false, &mut host);
    assert_eq!(response, [b"U2F_V2".as_slice(), &[0x90, 0x00]].concat());
    assert_eq!(presence, U2fPresence::NotNeeded);
    let (response, _) = auth.u2f(&apdu(0x03, 0, &[]), false, &mut host);
    assert_eq!(split(&response).1, sw::OK);
    let (response, _) = auth.u2f(&apdu(0x03, 0, &[1]), false, &mut host);
    assert_eq!(response, vec![0x67, 0x00]);
}

#[test]
fn register_and_authenticate_signatures_verify() {
    // §4.3: attestation signature over 00 || app || challenge || key handle || public key;
    // §5.4: signature over app || user presence || counter || challenge.
    let (mut auth, mut host) = device();
    let reg = u2f_register(&mut auth, &mut host, &app());
    assert_eq!(reg.key_handle.len(), 128);
    let signed = [
        &[0x00][..],
        &app(),
        &CHALLENGE,
        &reg.key_handle,
        &reg.public_key,
    ]
    .concat();
    let att_point = cert_public_key(&reg.cert);
    assert!(ecdsa_verify_prehash(
        Curve::P256,
        &att_point,
        &sha256(&signed),
        &reg.signature
    ));
    // The same attestation certificate as CTAP2 packed attestation.
    let ctap = register(&mut auth, &mut host, &Mc::new());
    assert_eq!(ctap.cert(), reg.cert);

    for expected_counter in 1u32..=2 {
        let (response, presence) = auth.u2f(
            &authenticate_request(0x03, &app(), &reg.key_handle),
            true,
            &mut host,
        );
        assert_eq!(presence, U2fPresence::Consumed);
        let (data, sw) = split(&response);
        assert_eq!(sw, sw::OK);
        assert_eq!(data[0], 0x01, "user presence verified");
        let counter = u32::from_be_bytes(data[1..5].try_into().unwrap());
        assert_eq!(counter, expected_counter);
        let signed = [&app()[..], &[0x01], &data[1..5], &CHALLENGE].concat();
        assert!(ecdsa_verify_prehash(
            Curve::P256,
            &reg.public_key,
            &sha256(&signed),
            &data[5..]
        ));
        assert_eq!(
            persisted_state(&host).counter,
            counter,
            "persisted before the response"
        );
    }
}

#[test]
fn presence_is_requested_when_no_touch_is_latched() {
    // docs/CONTRACTS.md U2fPresence::Requested; §3.3 SW_CONDITIONS_NOT_SATISFIED.
    let (mut auth, mut host) = device();
    let (response, presence) = auth.u2f(&apdu(0x01, 0x00, &[0u8; 64]), false, &mut host);
    assert_eq!(
        (response, presence),
        (vec![0x69, 0x85], U2fPresence::Requested)
    );
    assert_eq!(host.persist_attempts(), 0);
    let reg = u2f_register(&mut auth, &mut host, &app());
    let (response, presence) = auth.u2f(
        &authenticate_request(0x03, &app(), &reg.key_handle),
        false,
        &mut host,
    );
    assert_eq!(
        (response, presence),
        (vec![0x69, 0x85], U2fPresence::Requested)
    );
    assert_eq!(persisted_state(&host).counter, 0);
}

#[test]
fn check_only_and_dont_enforce() {
    // §5.1: check-only answers 6985 for a valid handle (a success condition) and 6A80 for
    // a bad one; dont-enforce signs without presence (bit 0 clear).
    let (mut auth, mut host) = device();
    let reg = u2f_register(&mut auth, &mut host, &app());
    let (response, presence) = auth.u2f(
        &authenticate_request(0x07, &app(), &reg.key_handle),
        true,
        &mut host,
    );
    assert_eq!(
        (response, presence),
        (vec![0x69, 0x85], U2fPresence::NotNeeded)
    );
    let other_app = sha256(b"other.example");
    let (response, presence) = auth.u2f(
        &authenticate_request(0x07, &other_app, &reg.key_handle),
        true,
        &mut host,
    );
    assert_eq!(
        (response, presence),
        (vec![0x6A, 0x80], U2fPresence::NotNeeded)
    );
    let (response, presence) = auth.u2f(
        &authenticate_request(0x08, &app(), &reg.key_handle),
        false,
        &mut host,
    );
    assert_eq!(presence, U2fPresence::NotNeeded);
    let (data, sw) = split(&response);
    assert_eq!(sw, sw::OK);
    assert_eq!(data[0], 0x00);
    let signed = [&app()[..], &[0x00], &data[1..5], &CHALLENGE].concat();
    assert!(ecdsa_verify_prehash(
        Curve::P256,
        &reg.public_key,
        &sha256(&signed),
        &data[5..]
    ));
}

#[test]
fn status_words_for_malformed_requests() {
    // §3.3 status words; ISO 7816-4 §5.1 APDU framing; reserved P1 (model policy 6A86).
    let (mut auth, mut host) = device();
    let reg = u2f_register(&mut auth, &mut host, &app());
    let cases: Vec<(Vec<u8>, u16)> = vec![
        (vec![0x80, 0x03, 0x00, 0x00], sw::CLA_NOT_SUPPORTED),
        (vec![0x00, 0x05, 0x00, 0x00], sw::INS_NOT_SUPPORTED),
        (vec![0x00, 0x01, 0x00], sw::WRONG_LENGTH),
        (vec![0x00, 0x01, 0x00, 0x00, 0x05, 0x01], sw::WRONG_LENGTH),
        (apdu(0x01, 0x03, &[0; 63]), sw::WRONG_LENGTH),
        (apdu(0x01, 0x03, &[0; 65]), sw::WRONG_LENGTH),
        (apdu(0x02, 0x03, &[0; 64]), sw::WRONG_LENGTH),
        (
            apdu(0x02, 0x03, &[[0u8; 64].as_slice(), &[5, 1, 2]].concat()),
            sw::WRONG_LENGTH,
        ),
        (
            authenticate_request(0x00, &app(), &reg.key_handle),
            sw::INCORRECT_P1P2,
        ),
        (
            authenticate_request(0x03, &app(), &[0x01; 64]),
            sw::INCORRECT_DATA,
        ),
        (
            authenticate_request(0x03, &app(), &reg.key_handle[..127]),
            sw::INCORRECT_DATA,
        ),
    ];
    for (request, expected) in cases {
        let (response, presence) = auth.u2f(&request, true, &mut host);
        assert_eq!(split(&response), (&[][..], expected), "{request:02x?}");
        assert_eq!(presence, U2fPresence::NotNeeded);
    }
}

#[test]
fn short_apdus_are_accepted() {
    // ISO 7816-4 §5.1 short form (case 4S), which some hosts send for U2F.
    let (mut auth, mut host) = device();
    let short = Command::new(0, 0x01, 0, 0)
        .with_data([&CHALLENGE[..], &app()].concat())
        .with_le(0);
    let mut bytes = short.to_bytes();
    assert_eq!(bytes[4], 64, "short Lc");
    let (response, _) = auth.u2f(&bytes, true, &mut host);
    assert_eq!(split(&response).1, sw::OK);
    bytes.pop();
    let (response, _) = auth.u2f(&bytes, true, &mut host);
    assert_eq!(split(&response).1, sw::OK, "case 3S without Le");
}

#[test]
fn u2f_key_handles_work_in_get_assertion() {
    // CTAP 2.1 §10 interoperation: a U2F key handle is a non-discoverable credential ID
    // bound to the application parameter, so getAssertion with rpIdHash = appId hash
    // (WebAuthn L2 §10.1 appid extension) uses it.
    let (mut auth, mut host) = device();
    let reg = u2f_register(&mut auth, &mut host, &app());
    let a = assert(
        &mut auth,
        &mut host,
        &Ga::new().allow(vec![reg.key_handle.clone()]),
    );
    assert_eq!(a.cred_id, reg.key_handle);
    assert!(a.verifies_with(&cose_es256(&reg.public_key)));
    assert_eq!(a.auth_data.counter, 1);
}

#[test]
fn ctap_es256_credentials_work_in_u2f_but_other_algorithms_do_not() {
    // §5.3 bad key handle: U2F signs with P-256 only.
    let (mut auth, mut host) = device();
    let es256 = register(&mut auth, &mut host, &Mc::new().alg(-7));
    let eddsa = register(&mut auth, &mut host, &Mc::new().alg(-8));
    let (response, presence) = auth.u2f(
        &authenticate_request(0x03, &app(), &es256.id()),
        true,
        &mut host,
    );
    assert_eq!(presence, U2fPresence::Consumed);
    let (data, sw) = split(&response);
    assert_eq!(sw, sw::OK);
    let point = [
        &[0x04u8][..],
        es256
            .public_key()
            .map_get_int(-2)
            .and_then(Value::as_bytes)
            .unwrap(),
        es256
            .public_key()
            .map_get_int(-3)
            .and_then(Value::as_bytes)
            .unwrap(),
    ]
    .concat();
    let signed = [&app()[..], &[0x01], &data[1..5], &CHALLENGE].concat();
    assert!(ecdsa_verify_prehash(
        Curve::P256,
        &point,
        &sha256(&signed),
        &data[5..]
    ));
    let (response, _) = auth.u2f(
        &authenticate_request(0x03, &app(), &eddsa.id()),
        true,
        &mut host,
    );
    assert_eq!(response, vec![0x6A, 0x80]);
}

#[test]
fn u2f_and_ctap_share_one_counter() {
    // legacy-v0.64-profiles.json nonresident_model: one persisted shared counter.
    let (mut auth, mut host) = device();
    let reg = u2f_register(&mut auth, &mut host, &app());
    assert_eq!(
        assert(
            &mut auth,
            &mut host,
            &Ga::new().allow(vec![reg.key_handle.clone()])
        )
        .auth_data
        .counter,
        1
    );
    let (response, _) = auth.u2f(
        &authenticate_request(0x03, &app(), &reg.key_handle),
        true,
        &mut host,
    );
    assert_eq!(&split(&response).0[1..5], &2u32.to_be_bytes());
    assert_eq!(
        assert(
            &mut auth,
            &mut host,
            &Ga::new().allow(vec![reg.key_handle.clone()])
        )
        .auth_data
        .counter,
        3
    );
}

#[test]
fn u2f_never_waits_so_cancel_finds_nothing() {
    // BEHAVIOR_CATALOG FIDO: "CTAPHID_CANCEL during a U2F MSG is ignored": U2F answers 6985
    // at once instead of waiting, so there is never a pending U2F operation to cancel.
    let (mut auth, mut host) = device();
    let (response, presence) = auth.u2f(&apdu(0x01, 0x03, &[0u8; 64]), false, &mut host);
    assert_eq!(
        (response, presence),
        (vec![0x69, 0x85], U2fPresence::Requested)
    );
    assert!(!auth.is_pending());
    assert_eq!(auth.cancel(&mut host), None);
}

#[test]
fn storage_failures() {
    // docs/CONTRACTS.md: storage failure → 6581 and the previous state.
    let (mut auth, mut host) = device();
    host.fail_next_saves(1);
    let (response, presence) = auth.u2f(
        &apdu(0x01, 0x03, &[[0u8; 32], app()].concat()),
        true,
        &mut host,
    );
    assert_eq!(
        (response, presence),
        (vec![0x65, 0x81], U2fPresence::NotNeeded)
    );
    assert_eq!(
        host.persisted(Record::Fido),
        None,
        "first-use keys were not kept"
    );
    let reg = u2f_register(&mut auth, &mut host, &app());
    let before = host.persisted(Record::Fido);
    host.fail_next_saves(1);
    let (response, _) = auth.u2f(
        &authenticate_request(0x03, &app(), &reg.key_handle),
        true,
        &mut host,
    );
    assert_eq!(response, vec![0x65, 0x81]);
    assert_eq!(host.persisted(Record::Fido), before);
    let (response, _) = auth.u2f(
        &authenticate_request(0x03, &app(), &reg.key_handle),
        true,
        &mut host,
    );
    assert_eq!(&split(&response).0[1..5], &1u32.to_be_bytes());
}

#[test]
fn u2f_while_a_ctap_command_waits_is_refused() {
    // CTAPHID allows one transaction at a time (CTAP 2.1 §11.2); defensive answer.
    let (mut auth, mut host) = device();
    assert!(matches!(
        auth.cbor(&[0x0B], &mut host),
        Outcome::NeedTouch { .. }
    ));
    let (response, presence) = auth.u2f(&[0x00, 0x03, 0x00, 0x00], true, &mut host);
    assert_eq!(
        (response, presence),
        (vec![0x69, 0x85], U2fPresence::NotNeeded)
    );
    assert_eq!(auth.presence_resolved(true, &mut host), vec![status::OK]);
}

#[test]
fn user_verification_required_credentials_are_not_usable_over_u2f() {
    // CTAP 2.1 §12.1 / §6.2.2 step 7.4: userVerificationRequired needs UV, which U2F
    // cannot perform; level 2 is usable because U2F always names the key handle.
    let (mut auth, mut host) = device();
    let level3 = register(&mut auth, &mut host, &Mc::new().ext("credProtect", 3));
    let level2 = register(&mut auth, &mut host, &Mc::new().ext("credProtect", 2));
    let (response, _) = auth.u2f(
        &authenticate_request(0x07, &app(), &level3.id()),
        true,
        &mut host,
    );
    assert_eq!(response, vec![0x6A, 0x80]);
    let (response, _) = auth.u2f(
        &authenticate_request(0x07, &app(), &level2.id()),
        true,
        &mut host,
    );
    assert_eq!(response, vec![0x69, 0x85]);
}

#[test]
fn every_tampered_credential_id_and_key_handle_is_refused() {
    // Credential IDs and U2F key handles are AES-256-GCM sealed and bound to the RP ID hash
    // (credential.rs; legacy-v0.64-profiles.json nonresident_model "RP hash authenticated").
    // Flipping any bit of any of the 128 bytes (version, nonce, ciphertext, tag) must make
    // the ID unknown: getAssertion answers NO_CREDENTIALS before any touch and without
    // persisting (CTAP 2.1 §6.2.2 step 7.6), U2F AUTHENTICATE answers 6A80 for every control
    // byte (U2F raw message formats v1.2 §5.3 "bad key handle"), and the excludeList does
    // not match it (CTAP 2.1 §6.1.2 step 12: only IDs "created by this authenticator").
    let (mut auth, mut host) = device();
    let ctap = register(&mut auth, &mut host, &Mc::new()).id();
    let u2f = u2f_register(&mut auth, &mut host, &app()).key_handle;
    let attempts = host.persist_attempts();
    for (name, id) in [("ctap", &ctap), ("u2f", &u2f)] {
        assert_eq!(id.len(), 128);
        for i in 0..id.len() {
            for bit in [i % 8, 7 - i % 8] {
                let mut tampered = id.clone();
                tampered[i] ^= 1 << bit;
                assert_eq!(
                    send_untouched(
                        &mut auth,
                        &mut host,
                        &Ga::new().allow(vec![tampered.clone()]).encode()
                    ),
                    vec![status::NO_CREDENTIALS],
                    "{name} byte {i} bit {bit}"
                );
                for p1 in [0x03u8, 0x07, 0x08] {
                    assert_eq!(
                        auth.u2f(
                            &authenticate_request(p1, &app(), &tampered),
                            true,
                            &mut host
                        ),
                        (vec![0x6A, 0x80], U2fPresence::NotNeeded),
                        "{name} byte {i} bit {bit} p1 {p1:#04x}"
                    );
                }
            }
        }
        // Shorter, longer and empty IDs.
        let mut longer = id.clone();
        longer.push(0);
        for other in [id[..127].to_vec(), longer, Vec::new()] {
            assert_eq!(
                send_untouched(
                    &mut auth,
                    &mut host,
                    &Ga::new().allow(vec![other.clone()]).encode()
                ),
                vec![status::NO_CREDENTIALS]
            );
            assert_eq!(
                auth.u2f(&authenticate_request(0x03, &app(), &other), true, &mut host)
                    .0,
                vec![0x6A, 0x80]
            );
        }
    }
    assert_eq!(
        host.persist_attempts(),
        attempts,
        "nothing was signed or stored"
    );
    // A tampered ID in the excludeList does not exclude.
    let mut tampered = ctap.clone();
    tampered[100] ^= 0x10;
    let made = register(&mut auth, &mut host, &Mc::new().exclude(vec![tampered]));
    assert_eq!(made.id().len(), 128);
    // The untampered IDs still work.
    assert_eq!(
        status_of(&send(
            &mut auth,
            &mut host,
            &Ga::new().allow(vec![ctap, u2f]).encode()
        )),
        status::OK
    );
}

/// What python-fido2's `Ctap1.send_apdu` puts on the wire:
/// `struct.pack(">BBBBBH", cla, ins, p1, p2, 0, len(data)) + data + b"\0\0"`, i.e. an
/// extended Lc (`00 Lc1 Lc2`, zero for no data) followed by an extended Le of `00 00`.
fn python_fido2_apdu(ins: u8, p1: u8, data: &[u8]) -> Vec<u8> {
    let len = u16::try_from(data.len()).unwrap().to_be_bytes();
    [
        &[0x00, ins, p1, 0x00, 0x00, len[0], len[1]][..],
        data,
        &[0x00, 0x00],
    ]
    .concat()
}

#[test]
fn legacy_version_encoding_is_accepted() {
    // U2F raw message formats v1.2 §9 "Implementation Considerations": earlier revisions
    // defined U2F_VERSION as 00 03 00 00 00 00 00 00 00 (an extended Lc of zero and an
    // extended Le), which is not ISO 7816-4. python-fido2 (`Ctap1.get_version`),
    // Firefox's authenticator-rs and Chromium's legacy version request send exactly this;
    // it used to be refused with 6700.
    let (mut auth, mut host) = device();
    let legacy = python_fido2_apdu(0x03, 0x00, &[]);
    assert_eq!(
        legacy,
        [0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    );
    let (response, presence) = auth.u2f(&legacy, false, &mut host);
    assert_eq!(response, [b"U2F_V2".as_slice(), &[0x90, 0x00]].concat());
    assert_eq!(presence, U2fPresence::NotNeeded);
    // The ISO 7816-4 forms Chromium sends (case 2E) and the short case 2S still work.
    for iso in [
        vec![0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00],
        vec![0x00, 0x03, 0x00, 0x00, 0x00],
    ] {
        let (response, _) = auth.u2f(&iso, false, &mut host);
        assert_eq!(response, [b"U2F_V2".as_slice(), &[0x90, 0x00]].concat());
    }
    // The legacy layout means "no data": REGISTER in it lacks its 64 bytes.
    let (response, _) = auth.u2f(&python_fido2_apdu(0x01, 0x03, &[]), true, &mut host);
    assert_eq!(response, vec![0x67, 0x00]);
    // A zero extended Lc followed by anything but a two-byte Le stays malformed.
    for bad in [
        vec![0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        vec![0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    ] {
        let (response, _) = auth.u2f(&bad, false, &mut host);
        assert_eq!(response, vec![0x67, 0x00], "{bad:02x?}");
    }
}

#[test]
fn python_fido2_register_and_authenticate_shapes_work() {
    // python-fido2 `Ctap1.register` / `Ctap1.authenticate` (extended Lc, data, Le 00 00);
    // U2F raw message formats v1.2 §4.1, §5.1.
    let (mut auth, mut host) = device();
    let (response, presence) = auth.u2f(
        &python_fido2_apdu(0x01, 0x00, &[&CHALLENGE[..], &app()].concat()),
        true,
        &mut host,
    );
    assert_eq!(presence, U2fPresence::Consumed);
    let (data, sw) = split(&response);
    assert_eq!(sw, sw::OK);
    let reg = parse_register(data);
    let mut request = Vec::new();
    request.extend_from_slice(&CHALLENGE);
    request.extend_from_slice(&app());
    request.push(u8::try_from(reg.key_handle.len()).unwrap());
    request.extend_from_slice(&reg.key_handle);
    let (response, presence) = auth.u2f(&python_fido2_apdu(0x02, 0x03, &request), true, &mut host);
    assert_eq!(presence, U2fPresence::Consumed);
    let (data, sw) = split(&response);
    assert_eq!(sw, sw::OK);
    assert_eq!(data[0], 0x01, "user presence");
    let signed = [&app()[..], &data[..5], &CHALLENGE].concat();
    assert!(ecdsa_verify_prehash(
        Curve::P256,
        &reg.public_key,
        &sha256(&signed),
        &data[5..]
    ));
    // Check-only (P1 07) with a known handle: 6985 without asking for a touch.
    let (response, presence) = auth.u2f(&python_fido2_apdu(0x02, 0x07, &request), false, &mut host);
    assert_eq!(response, vec![0x69, 0x85]);
    assert_eq!(presence, U2fPresence::NotNeeded);
}
