//! Fixed-seed pseudo-random malformed input (docs/DESIGN.md §12-4: deterministic random
//! tests instead of cargo-fuzz). Every request must get a response without a panic.

use lk_testkit::SeededEntropy;

use super::platform::{PIN, Platform, Token, client_pin, perm, set_pin, sub};
use super::*;

struct Rng(SeededEntropy);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(SeededEntropy::new(seed))
    }

    fn below(&mut self, n: usize) -> usize {
        let bytes = self.0.bytes(4);
        usize::try_from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])).unwrap()
            % n.max(1)
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        self.0.bytes(n)
    }

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }
}

/// A random CBOR value of bounded depth, biased toward the shapes CTAP uses.
fn random_value(rng: &mut Rng, depth: usize) -> Value {
    let kinds = if depth == 0 { 7 } else { 10 };
    match rng.below(kinds) {
        0 => Value::Unsigned(u64::try_from(rng.below(300)).unwrap()),
        1 => Value::int_key(-1 - i64::try_from(rng.below(300)).unwrap()),
        2 => {
            let len = [0, 1, 16, 32, 65, 128, 129][rng.below(7)];
            Value::Bytes(rng.bytes(len))
        }
        3 => Value::Text(
            [
                "id",
                "public-key",
                "rk",
                "up",
                "uv",
                "alg",
                "type",
                "credProtect",
                "credBlob",
                "largeBlobKey",
                "hmac-secret",
                "x",
            ][rng.below(12)]
            .into(),
        ),
        4 => Value::Bool(rng.chance(50)),
        5 => [Value::Null, Value::Undefined, Value::Float(0x3C00, 2)][rng.below(3)].clone(),
        6 => Value::Tag(1, Box::new(Value::Unsigned(0))),
        7 => Value::Array(
            (0..rng.below(4))
                .map(|_| random_value(rng, depth - 1))
                .collect(),
        ),
        _ => {
            let mut m = MapBuilder::new();
            for _ in 0..rng.below(6) {
                let key = if rng.chance(50) {
                    Value::Unsigned(u64::try_from(rng.below(12)).unwrap())
                } else {
                    random_value(rng, 0)
                };
                m.set(key, random_value(rng, depth - 1));
            }
            m.build()
        }
    }
}

/// Drive a request to completion: grant, deny or cancel any touch request.
fn drive(auth: &mut Authenticator, host: &mut TestHost, rng: &mut Rng, request: &[u8]) {
    match auth.cbor(request, host) {
        Outcome::Done(response) => assert!(!response.is_empty()),
        Outcome::NeedTouch { .. } => match rng.below(3) {
            0 => assert!(!auth.presence_resolved(true, host).is_empty()),
            1 => assert!(!auth.presence_resolved(false, host).is_empty()),
            _ => assert!(auth.cancel(host).is_some()),
        },
    }
    assert!(!auth.is_pending());
}

#[test]
fn random_cbor_requests_never_panic() {
    let mut rng = Rng::new(0x5EED_F1D0);
    let (mut auth, mut host) = device();
    let commands = [
        0x01u8, 0x02, 0x04, 0x07, 0x08, 0x0B, 0x06, 0x0A, 0x41, 0x0C, 0x0D, 0x00, 0xFF,
    ];
    for _ in 0..1500 {
        let command = commands[rng.below(commands.len())];
        let request = match rng.below(3) {
            0 => {
                let len = rng.below(64);
                [vec![command], rng.bytes(len)].concat()
            }
            _ => encode_request(command, &random_value(&mut rng, 3)),
        };
        drive(&mut auth, &mut host, &mut rng, &request);
        if rng.chance(2) {
            auth.power_cycle(&mut host);
        }
        if rng.chance(5) {
            host.advance(u64::try_from(rng.below(40_000)).unwrap());
        }
    }
}

#[test]
fn mutated_valid_requests_never_panic() {
    let mut rng = Rng::new(0xD00D_2026);
    let (mut auth, mut host) = device();
    // A user the seed requests never name, so no mutation overwrites this credential.
    let reg = register(
        &mut auth,
        &mut host,
        &Mc::new().rk().user(b"kept").ext("credBlob", vec![1; 4]),
    );
    let seeds = [
        Mc::new()
            .rk()
            .ext("credProtect", 2)
            .ext("largeBlobKey", true)
            .encode(),
        Mc::new().alg(-8).exclude(vec![reg.id()]).encode(),
        Ga::new()
            .allow(vec![reg.id()])
            .ext("credBlob", true)
            .encode(),
        Ga::new().option("up", false).encode(),
    ];
    for _ in 0..400 {
        let mut request = seeds[rng.below(seeds.len())].clone();
        match rng.below(3) {
            0 => {
                for _ in 0..=rng.below(4) {
                    let at = 1 + rng.below(request.len() - 1);
                    request[at] ^= 1 << rng.below(8);
                }
            }
            1 => request.truncate(1 + rng.below(request.len() - 1)),
            _ => {
                let at = 1 + rng.below(request.len() - 1);
                let byte = rng.bytes(1)[0];
                request.insert(at, byte);
            }
        }
        drive(&mut auth, &mut host, &mut rng, &request);
    }
    // The device still works afterwards.
    assert!(
        assert(&mut auth, &mut host, &Ga::new().allow(vec![reg.id()]))
            .verifies_with(&reg.public_key())
    );
}

/// Flip bits in, truncate, or insert a byte into `request` (never the command byte).
fn mutate(rng: &mut Rng, request: &mut Vec<u8>) {
    if request.len() < 2 {
        return;
    }
    match rng.below(3) {
        0 => {
            for _ in 0..=rng.below(4) {
                let at = 1 + rng.below(request.len() - 1);
                request[at] ^= 1 << rng.below(8);
            }
        }
        1 => request.truncate(1 + rng.below(request.len() - 1)),
        _ => {
            let at = 1 + rng.below(request.len() - 1);
            let byte = rng.bytes(1)[0];
            request.insert(at, byte);
        }
    }
}

/// Valid requests (clientPIN, credentialManagement, largeBlobs, config,
/// pinUvAuthParam-carrying makeCredential / getAssertion with hmac-secret) for the current
/// token and key agreement.
fn authorized_seeds(
    auth: &mut Authenticator,
    host: &mut TestHost,
    token: &Token,
    rp_id_hash: &[u8],
    cred_id: &[u8],
) -> Vec<Vec<u8>> {
    let mut platform = Platform::connect(auth, host, 2);
    let cm = |subcommand: u8, params: Option<Value>| {
        let mut m = MapBuilder::new().insert(1, subcommand);
        let mut message = vec![subcommand];
        if let Some(p) = params {
            message.extend(cbor::encode(&p));
            m.set(2, p);
        }
        m.set(3, 2);
        m.set(4, token.sign(&message));
        encode_request(0x0A, &m.build())
    };
    let config = |subcommand: u8, params: Option<Value>| {
        let mut m = MapBuilder::new().insert(1, subcommand);
        let mut message = vec![0xFF; 32];
        message.extend([0x0D, subcommand]);
        if let Some(p) = params {
            message.extend(cbor::encode(&p));
            m.set(2, p);
        }
        m.set(3, 2);
        m.set(4, token.sign(&message));
        encode_request(0x0D, &m.build())
    };
    let blob = {
        let mut a = vec![0x80];
        a.extend_from_slice(&sha256(&[0x80])[..16]);
        let mut message = vec![0xFF; 32];
        message.extend([0x0C, 0x00, 0, 0, 0, 0]);
        message.extend(sha256(&a));
        let m = MapBuilder::new()
            .insert(2, a.clone())
            .insert(3, 0)
            .insert(4, a.len())
            .insert(5, token.sign(&message))
            .insert(6, 2)
            .build();
        encode_request(0x0C, &m)
    };
    let salt_enc = platform.encrypt(&[7u8; 64]);
    let hmac = MapBuilder::new()
        .insert(1, platform.cose_key())
        .insert(2, salt_enc.clone())
        .insert(3, platform.mac_shared(&salt_enc))
        .insert(4, 2)
        .build();
    let user = MapBuilder::new()
        .insert("id", b"kept".to_vec())
        .insert("name", "k")
        .build();
    vec![
        client_pin(Some(2), sub::GET_PIN_RETRIES).request(),
        client_pin(Some(1), sub::GET_KEY_AGREEMENT).request(),
        platform.pin_token_request(PIN),
        platform.token_request(
            PIN,
            perm::MC | perm::GA | perm::CM | perm::LBW | perm::ACFG,
            Some(RP),
        ),
        platform.change_pin_request(PIN, PIN.as_bytes()),
        platform.set_pin_request(b"5678"),
        cm(0x01, None),
        cm(0x02, None),
        encode_request(0x0A, &MapBuilder::new().insert(1, 0x03).build()),
        cm(
            0x04,
            Some(MapBuilder::new().insert(1, rp_id_hash.to_vec()).build()),
        ),
        encode_request(0x41, &MapBuilder::new().insert(1, 0x05).build()),
        cm(
            0x07,
            Some(
                MapBuilder::new()
                    .insert(2, descriptor(cred_id))
                    .insert(3, user)
                    .build(),
            ),
        ),
        cm(
            0x06,
            Some(MapBuilder::new().insert(2, descriptor(&[1; 128])).build()),
        ),
        blob,
        encode_request(0x0C, &MapBuilder::new().insert(1, 64).insert(3, 0).build()),
        config(
            0x03,
            Some(
                MapBuilder::new()
                    .insert(1, 4)
                    .insert(2, vec![Value::from(RP)])
                    .build(),
            ),
        ),
        config(0x02, None),
        Mc::new()
            .rk()
            .ext("largeBlobKey", true)
            .ext("hmac-secret", true)
            .with_token(token)
            .encode(),
        Ga::new()
            .with_token(token)
            .ext("hmac-secret", hmac)
            .encode(),
    ]
}

#[test]
fn mutated_authorized_requests_never_panic() {
    // The bodies of clientPIN, credentialManagement, largeBlobs and config only run past
    // their parameter checks with a PIN set and a live token, so the seeds carry valid
    // MACs before mutation. The PIN state is restored periodically so that mutated PIN
    // attempts do not block the PIN for the rest of the run.
    let mut rng = Rng::new(0x57A6_E002);
    let (mut auth, mut host) = device();
    let kept = register(&mut auth, &mut host, &Mc::new().rk().user(b"kept"));
    set_pin(&mut auth, &mut host, 2, PIN);
    let rp_id_hash = sha256(RP.as_bytes());
    for round in 0..12 {
        let mut auth_now = with_state(&mut host, |s| {
            s.pin.hash = Some(SecretBytes::from_slice(&sha256(PIN.as_bytes())[..16]));
            s.pin.code_points = 4;
            s.pin.retries = 8;
            s.pin.force_change = false;
            s.pin.min_length = 4;
            s.pin.always_uv = false;
        });
        std::mem::swap(&mut auth, &mut auth_now);
        let all = perm::MC | perm::GA | perm::CM | perm::LBW | perm::ACFG;
        let token = super::platform::token(&mut auth, &mut host, 2, all, None);
        let seeds = authorized_seeds(&mut auth, &mut host, &token, &rp_id_hash, &kept.id());
        // Unmutated, the authorized seeds succeed: getCredsMetadata and the large-blob read.
        assert_eq!(
            status_of(&send_untouched(&mut auth, &mut host, &seeds[6])),
            0
        );
        assert_eq!(
            status_of(&send_untouched(&mut auth, &mut host, &seeds[14])),
            0
        );
        for i in 0..60 {
            let mut request = seeds[(round * 60 + i) % seeds.len()].clone();
            if rng.chance(85) {
                mutate(&mut rng, &mut request);
            }
            drive(&mut auth, &mut host, &mut rng, &request);
            if rng.chance(3) {
                auth.power_cycle(&mut host);
            }
            if rng.chance(3) {
                host.advance(u64::try_from(rng.below(40_000)).unwrap());
            }
        }
    }
    // The device still answers.
    assert_eq!(status_of(&send_untouched(&mut auth, &mut host, &[0x04])), 0);
}

#[test]
fn random_u2f_apdus_never_panic() {
    let mut rng = Rng::new(0x0002_F00D);
    let (mut auth, mut host) = device();
    for _ in 0..1500 {
        let mut apdu = vec![
            if rng.chance(80) {
                0x00
            } else {
                rng.bytes(1)[0]
            },
            [0x01u8, 0x02, 0x03, 0x04][rng.below(4)],
        ];
        apdu.extend(rng.bytes(2));
        match rng.below(4) {
            0 => {
                let len = rng.below(8);
                apdu.extend(rng.bytes(len));
            }
            1 => {
                let len = rng.below(200);
                apdu.push(u8::try_from(len.min(255)).unwrap());
                apdu.extend(rng.bytes(len));
            }
            2 => {
                let len = rng.below(300);
                apdu.extend([
                    0,
                    u8::try_from(len >> 8).unwrap(),
                    u8::try_from(len & 0xFF).unwrap(),
                ]);
                apdu.extend(rng.bytes(len));
                if rng.chance(50) {
                    apdu.extend([0, 0]);
                }
            }
            _ => {}
        }
        let (response, _) = auth.u2f(&apdu, rng.chance(50), &mut host);
        assert!(response.len() >= 2);
    }
}

#[test]
fn mutated_persisted_state_never_panics() {
    // lk_core::CardApplet constructor convention / docs/CONTRACTS.md: "Unreadable state
    // means factory state". `Authenticator::new` takes whatever the store returns, so
    // mutated records (bit flips, truncation, inserted bytes) must either load or fall
    // back to factory state, and every command must still answer without a panic,
    // including when a mutation produced odd but well-formed values.
    let mut rng = Rng::new(0x57A7_E5ED);
    let (mut auth, mut host) = device();
    let kept = register(
        &mut auth,
        &mut host,
        &Mc::new()
            .rk()
            .user(b"kept")
            .ext("credBlob", vec![7; 8])
            .ext("largeBlobKey", true)
            .ext("credProtect", 2),
    );
    register(
        &mut auth,
        &mut host,
        &Mc::new().rk().rp("other.example").alg(-8),
    );
    set_pin(&mut auth, &mut host, 2, PIN);
    let original = host.persisted(Record::Fido).unwrap();
    let requests = [
        vec![0x04],
        Ga::new().encode(),
        Ga::new()
            .allow(vec![kept.id()])
            .ext("credBlob", true)
            .encode(),
        Ga::new().option("up", false).encode(),
        Mc::new().encode(),
        vec![0x08],
        client_pin(Some(2), sub::GET_PIN_RETRIES).request(),
        client_pin(Some(1), sub::GET_KEY_AGREEMENT).request(),
        encode_request(0x0C, &MapBuilder::new().insert(1, 64).insert(3, 0).build()),
    ];
    for _ in 0..120 {
        let mut stored = original.clone();
        for _ in 0..=rng.below(3) {
            if stored.len() < 2 {
                break;
            }
            match rng.below(3) {
                0 => {
                    let at = rng.below(stored.len());
                    stored[at] ^= 1 << rng.below(8);
                }
                1 => stored.truncate(rng.below(stored.len())),
                _ => {
                    let at = rng.below(stored.len());
                    let byte = rng.bytes(1)[0];
                    stored.insert(at, byte);
                }
            }
        }
        let mut auth = Authenticator::new(Some(&stored), &mut host);
        for request in &requests {
            drive(&mut auth, &mut host, &mut rng, request);
        }
        let (response, _) = auth.u2f(&[0x00, 0x03, 0x00, 0x00], false, &mut host);
        assert!(response.ends_with(&[0x90, 0x00]));
        // A correct PIN attempt and a token-authorized request also run.
        let mut platform = Platform::connect(&mut auth, &mut host, 2);
        let r = send_untouched(
            &mut auth,
            &mut host,
            &platform.token_request(PIN, perm::GA | perm::CM, None),
        );
        assert!(!r.is_empty());
        host.set_persisted(Record::Fido, &original);
    }
    // Pure noise and empty input are factory state.
    for len in [0usize, 1, 2, 17, 300] {
        let noise = rng.bytes(len);
        let mut auth = Authenticator::new(Some(&noise), &mut host);
        assert_eq!(status_of(&send_untouched(&mut auth, &mut host, &[0x04])), 0);
    }
}
