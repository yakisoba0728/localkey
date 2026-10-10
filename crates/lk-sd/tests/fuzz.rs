//! Deterministic malformed-input test (docs/DESIGN.md §12-4: fixed-seed pseudo-random
//! inputs instead of cargo-fuzz). Every entry point must answer without panicking.

#![allow(clippy::unwrap_used)]

mod common;

use common::scp11::*;
use common::*;
use lk_core::{CardApplet, Entropy, Outcome, Record};
use lk_sd::{LevelPolicy, SecureChannel, SecurityDomain};
use lk_testkit::{SeededEntropy, TestHost};

/// Instruction bytes the Security Domain knows, so that random inputs reach deep code.
const INTERESTING_INS: [u8; 12] = [0x50, 0x82, 0x88, 0x2A, 0xCA, 0xD8, 0xE4, 0xA4, 0xC0, 0xE2, 0xF1, 0xF0];
const INTERESTING_CLA: [u8; 10] = [0x80, 0x84, 0x90, 0x94, 0x00, 0x04, 0x0C, 0x81, 0xFF, 0x10];

fn byte(rng: &mut SeededEntropy) -> u8 {
    let mut b = [0u8; 1];
    rng.fill(&mut b);
    b[0]
}

/// A random APDU: sometimes well-framed with a known CLA/INS, sometimes raw bytes.
fn random_apdu(rng: &mut SeededEntropy) -> Vec<u8> {
    let kind = byte(rng) % 4;
    let len = usize::from(byte(rng)) % 64;
    let mut body = rng.bytes(len);
    match kind {
        0 => body,
        1 | 2 => {
            let cla = INTERESTING_CLA[usize::from(byte(rng)) % INTERESTING_CLA.len()];
            let ins = INTERESTING_INS[usize::from(byte(rng)) % INTERESTING_INS.len()];
            let (p1, p2) = (byte(rng), byte(rng));
            let le = match byte(rng) % 3 {
                0 => None,
                1 => Some(0),
                _ => Some(u16::from(byte(rng))),
            };
            body.truncate(255);
            encode_apdu(cla, ins, p1, p2, &body, le, kind == 2)
        }
        _ => {
            // A TLV-shaped data field for PUT KEY / DELETE KEY.
            let mut data = vec![byte(rng) % 3, 0x88, byte(rng) % 20];
            data.extend(body);
            let ins = [0xD8, 0xE4][usize::from(byte(rng)) % 2];
            let p1 = byte(rng) % 2;
            encode_apdu(0x80, ins, p1, 0x81, &data, None, false)
        }
    }
}

/// Open a default-key session, or `None` if the random commands so far made that
/// impossible.
fn try_open(sd: &mut SecurityDomain, host: &mut TestHost) -> Option<(HostSession, lk_sd::SecureChannel)> {
    let challenge = [0x5Au8; 8];
    let (resp, _) = sd.handshake(&init_update_apdu(0x00, &challenge), host);
    if resp.len() != 31 || resp[10] != 0xFF {
        return None;
    }
    let pending = read_init_response(&StaticKeys::DEFAULT, &challenge, &resp);
    let (apdu, session) = pending.external_authenticate(0x33);
    let (resp, ch) = sd.handshake(&apdu, host);
    (resp == [0x90, 0x00]).then_some(())?;
    Some((session, ch?))
}

#[test]
fn random_apdus_never_panic() {
    let mut rng = SeededEntropy::new(0x5D_F0_22);
    let mut host = TestHost::new();
    let mut sd = SecurityDomain::new(None, &mut host);
    sd.set_level_policy(LevelPolicy::AmendmentD);
    let mut dispatched = 0;
    for round in 0..40 {
        let Some((mut session, mut ch)) = try_open(&mut sd, &mut host) else {
            // Random commands may have removed the default keys; only a panic fails.
            sd = SecurityDomain::new(None, &mut host);
            sd.set_level_policy(LevelPolicy::AmendmentD);
            continue;
        };
        for i in 0..150 {
            let apdu = random_apdu(&mut rng);
            let resp = match i % 5 {
                0 => sd.handshake(&apdu, &mut host).0,
                1 => match sd.process(&apdu, &mut host) {
                    Outcome::Done(r) => r,
                    Outcome::NeedTouch { .. } => panic!("no touch"),
                },
                2 => match sd.process_secure(&apdu, &ch, &mut host) {
                    Outcome::Done(r) => r,
                    Outcome::NeedTouch { .. } => panic!("no touch"),
                },
                3 => {
                    // Random bytes into the channel, then (on a fresh session if that
                    // one closed) a correctly MACed random command.
                    let _ = ch.unwrap_command(&apdu);
                    let w = ch.wrap_response(&apdu);
                    if !ch.is_open() {
                        match try_open(&mut sd, &mut host) {
                            Some(fresh) => (session, ch) = fresh,
                            None => continue,
                        }
                    }
                    let cla = INTERESTING_CLA[usize::from(byte(&mut rng)) % 4];
                    let n = usize::from(byte(&mut rng)) % 40;
                    let data = rng.bytes(n);
                    let (ins, p1, p2) = (byte(&mut rng), byte(&mut rng), byte(&mut rng));
                    let wrapped = session.wrap(cla, ins, p1, p2, &data, None, false);
                    let resp = device_transmit(&mut sd, &mut ch, &mut host, &wrapped);
                    if resp != [0x69, 0x82] {
                        dispatched += 1;
                    }
                    w
                }
                _ => sd.select(&apdu, &mut host),
            };
            assert!(resp.len() >= 2 || i % 5 == 3, "round {round} step {i}: {apdu:02X?} -> {resp:02X?}");
        }
        // The domain still answers sanely afterwards (it may have reset itself).
        let resp = plain(&mut sd, &mut host, &[0x00, 0xCA, 0x00, 0x66, 0x00]);
        assert_eq!(status(&resp), 0x9000);
        sd.deselect();
    }
    assert!(dispatched > 500, "MACed random commands reached dispatch {dispatched} times");
}

#[test]
fn random_stored_records_never_panic() {
    let mut rng = SeededEntropy::new(77);
    let mut host = TestHost::new();
    let good = {
        SecurityDomain::new(None, &mut host);
        host.persisted(lk_core::Record::SecurityDomain).unwrap()
    };
    for _ in 0..500 {
        let mut record = good.clone();
        for _ in 0..(byte(&mut rng) % 4) {
            let pos = usize::from(byte(&mut rng)) % record.len();
            record[pos] = byte(&mut rng);
        }
        let cut = usize::from(byte(&mut rng)) % (record.len() + 1);
        record.truncate(cut.max(record.len() / 2));
        let mut h = TestHost::new();
        let mut sd = SecurityDomain::new(Some(&record), &mut h);
        let resp = plain(&mut sd, &mut h, &[0x00, 0xCA, 0x00, 0xE0, 0x00]);
        assert_eq!(status(&resp), 0x9000);
    }
}

/// Flip, insert, delete or truncate a few bytes of `input`.
fn mutate(rng: &mut SeededEntropy, input: &[u8]) -> Vec<u8> {
    let mut out = input.to_vec();
    for _ in 0..=(byte(rng) % 4) {
        if out.is_empty() {
            out.push(byte(rng));
            continue;
        }
        let pos = (usize::from(byte(rng)) << 8 | usize::from(byte(rng))) % out.len();
        match byte(rng) % 4 {
            0 => out[pos] ^= 1 << (byte(rng) % 8),
            1 => out[pos] = byte(rng),
            2 => out.insert(pos, byte(rng)),
            _ => out.truncate(pos.max(1)),
        }
    }
    out
}

fn done(o: Outcome<Vec<u8>>) -> Vec<u8> {
    match o {
        Outcome::Done(r) => r,
        Outcome::NeedTouch { .. } => panic!("no touch"),
    }
}

/// Provision an OCE CA key, SCP11a/c keys, a CA identifier, an allowlist and a
/// certificate store; return the SD key and the PKI.
fn provisioned(host: &mut TestHost) -> (SecurityDomain, Vec<u8>, Pki) {
    let pki = pki(3);
    let mut sd = SecurityDomain::new(None, host);
    let (mut s, mut ch) = open(&mut sd, host, &StaticKeys::DEFAULT, 0xFF, 0x33);
    let sd_key = key_from(0x61);
    let dek = s.dek;
    let cmds: Vec<(u8, u8, u8, u8, Vec<u8>)> = vec![
        (0x80, 0xD8, 0x00, 0x10, ca_key_data(0x03, &pki.ca.public_uncompressed())),
        (0x80, 0xD8, 0x00, 0x11, private_key_data(&dek, 0x01, sd_key.scalar())),
        (0x80, 0xD8, 0x00, 0x15, private_key_data(&dek, 0x01, sd_key.scalar())),
        (0x00, 0xE2, 0x90, 0x00, ca_issuer_data(0x10, 0x03, &pki.root_ski)),
        (0x00, 0xE2, 0x90, 0x00, allowlist_data(0x10, 0x03, &[&pki.root_serial, &pki.inter_serial, &pki.leaf_serial], None)),
        (0x00, 0xE2, 0x90, 0x00, cert_store_data(0x11, 0x01, std::slice::from_ref(&pki.leaf_cert))),
    ];
    for (cla, ins, p1, p2, data) in cmds {
        let (_, sw) = if data.len() > 200 {
            send_ext(&mut sd, &mut ch, host, &mut s, cla, ins, p1, p2, &data)
        } else {
            send(&mut sd, &mut ch, host, &mut s, cla, ins, p1, p2, &data)
        };
        assert_eq!(sw, 0x9000);
    }
    (sd, sd_key.public_uncompressed(), pki)
}

/// Random SCP11 inputs: mutated certificates into PERFORM SECURITY OPERATION (with
/// random "more" bits and CA references), mutated MUTUAL/INTERNAL AUTHENTICATE requests,
/// and mutated STORE DATA / PUT KEY / GENERATE / GET DATA data through an SCP03 session
/// and an SCP11c session. Nothing panics, every answer has a status word, and valid
/// handshakes still work afterwards.
#[test]
fn random_scp11_inputs_never_panic() {
    let mut rng = SeededEntropy::new(0x11_5C_0D);
    let mut host = TestHost::new();
    let (mut sd, pk_sd, pki) = provisioned(&mut host);
    let certs = [pki.root_cert.clone(), pki.inter_cert.clone(), pki.leaf_cert.clone(), pki.direct_leaf_cert.clone()];
    let requests: Vec<Vec<u8>> = [Variant::A, Variant::B, Variant::C].iter().map(|&v| request_data(v, &key_from(0x41).public_uncompressed())).collect();
    let store_templates = [
        allowlist_data(0x10, 0x03, &[&pki.leaf_serial], Some(7)),
        allowlist_data(0x10, 0x03, &[&pki.leaf_serial, &[0x80, 1]], None),
        ca_issuer_data(0x13, 0x01, &[7; 20]),
        cert_store_data(0x10, 0x03, std::slice::from_ref(&pki.leaf_cert)),
    ];
    let key_templates = [ca_key_data(0x05, &pki.ca.public_uncompressed()), hex("05F00100"), private_key_data(&[0; 16], 0x05, key_from(0x22).scalar())];
    for round in 0..30 {
        for _ in 0..40 {
            let pick = usize::from(byte(&mut rng)) % certs.len();
            let cert = mutate(&mut rng, &certs[pick]);
            let p2 = [0x10, 0x90, 0x00, 0x80, 0x20, byte(&mut rng)][usize::from(byte(&mut rng)) % 6];
            let p1 = [0x03, 0x00, byte(&mut rng)][usize::from(byte(&mut rng)) % 3];
            let resp = sd.handshake(&encode_apdu(0x80, 0x2A, p1, p2, &cert, None, true), &mut host).0;
            assert!(resp.len() >= 2);
            let i = usize::from(byte(&mut rng)) % 3;
            let data = mutate(&mut rng, &requests[i]);
            let (ins, kid) = [(0x82, 0x11), (0x88, 0x13), (0x82, 0x15)][i];
            let resp = sd.handshake(&encode_apdu(0x80, ins, 0x01, kid, &data, None, false), &mut host).0;
            assert!(resp.len() >= 2, "round {round}: {data:02X?}");
        }
        // Management commands with mutated data through SCP03 and SCP11c sessions.
        let channels: Vec<(HostSession, SecureChannel)> = {
            let mut v = Vec::new();
            if let Some(admin) = try_open(&mut sd, &mut host) {
                v.push(admin);
            }
            let ok = pso_apdus(0x10, 0x03, &pki.full_chain()).iter().all(|a| sd.handshake(a, &mut host).0 == [0x90, 0x00]);
            if ok {
                let req = request(Variant::C, 0x01, key_from(0x41));
                let (resp, ch) = sd.handshake(&req.apdu, &mut host);
                if let (Ok(est), Some(ch)) = (req.finish(&resp, &pk_sd, Some(&pki.leaf)), ch) {
                    v.push((est.session, ch));
                }
            }
            v
        };
        for (mut session, mut ch) in channels {
            for _ in 0..20 {
                let pick = usize::from(byte(&mut rng));
                let (cla, ins, p1, p2, data) = match byte(&mut rng) % 4 {
                    0 => (0x00, 0xE2, 0x90, 0x00, mutate(&mut rng, &store_templates[pick % 4])),
                    1 => (0x80, 0xD8, byte(&mut rng) % 4, [0x10, 0x13, 0x20, 0x81][pick % 4], mutate(&mut rng, &key_templates[pick % 3])),
                    2 => (0x80, 0xF1, byte(&mut rng) % 3, [0x11, 0x13, 0x15][usize::from(byte(&mut rng)) % 3], mutate(&mut rng, &key_templates[1])),
                    _ => (0x00, 0xCA, 0xBF, 0x21, mutate(&mut rng, &hex("A60483021101"))),
                };
                if !ch.is_open() {
                    break;
                }
                let wrapped = session.wrap(cla, ins, p1, p2, &data, Some(0), data.len() > 200);
                let resp = device_transmit(&mut sd, &mut ch, &mut host, &wrapped);
                assert!(resp.len() >= 2);
                if ch.is_open() {
                    session.unwrap(&resp).unwrap();
                }
            }
        }
        // Valid handshakes still work (unless random commands reset the domain).
        let resp = plain(&mut sd, &mut host, &[0x00, 0xCA, 0x00, 0x66, 0x00]);
        assert_eq!(status(&resp), 0x9000);
        if round % 10 == 9 {
            (sd, _, _) = provisioned(&mut host);
        }
        sd.deselect();
    }
    // Plaintext management and GET RESPONSE without pending data.
    assert_eq!(status(&done(sd.process(&hex("00C0000000"), &mut host))), 0x6985);
}

/// Mutated records of a fully provisioned domain (CA keys, certificate stores, CA
/// identifiers, allowlists, SCP11c counters) load as themselves or as factory state.
#[test]
fn random_full_records_never_panic() {
    let mut rng = SeededEntropy::new(99);
    let mut host = TestHost::new();
    let (mut sd, pk_sd, pki) = provisioned(&mut host);
    assert!(pso_apdus(0x10, 0x03, &pki.full_chain()).iter().all(|a| sd.handshake(a, &mut host).0 == [0x90, 0x00]));
    let req = request(Variant::C, 0x01, key_from(0x41));
    let (resp, ch) = sd.handshake(&req.apdu, &mut host);
    let mut est = req.finish(&resp, &pk_sd, Some(&pki.leaf)).unwrap();
    let mut ch = ch.unwrap();
    let data = allowlist_data(0x10, 0x03, &[&pki.leaf_serial], Some(3));
    assert_eq!(send(&mut sd, &mut ch, &mut host, &mut est.session, 0x00, 0xE2, 0x90, 0x00, &data).1, 0x9000);
    let good = host.persisted(Record::SecurityDomain).unwrap();
    for _ in 0..400 {
        let record = mutate(&mut rng, &good);
        let mut h = TestHost::new();
        let mut sd = SecurityDomain::new(Some(&record), &mut h);
        let resp = plain(&mut sd, &mut h, &[0x00, 0xCA, 0x00, 0xE0, 0x00]);
        assert_eq!(status(&resp), 0x9000);
        let resp = plain(&mut sd, &mut h, &hex("00CABF2106A6048302110100"));
        assert!(resp.len() >= 2);
    }
}
