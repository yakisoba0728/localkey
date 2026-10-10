//! Fixed-seed pseudo-random malformed APDUs (docs/DESIGN.md §12-4: deterministic random
//! input tests instead of cargo-fuzz). The applet must answer every input with a status
//! word and never panic.

use lk_core::{CardApplet, Outcome, ResetKind};
use lk_testkit::SeededEntropy;

use crate::common::{Card, attr, cipher_do, crt, hex, import_data};

/// Instructions worth hitting often: every command plus a few unknown ones.
const INS: [u8; 20] = [
    0xA5, 0xCA, 0xCC, 0x20, 0x24, 0x2C, 0xDA, 0x84, 0x22, 0xC0, 0xE6, 0x44, 0xF1, 0xF2, 0xDB, 0x47,
    0x2A, 0x88, 0xA4, 0x00,
];
const CLA: [u8; 8] = [0x00, 0x00, 0x00, 0x10, 0x0C, 0x1C, 0x80, 0x01];
const TAGS: [u16; 24] = [
    0x0101, 0x0102, 0x0103, 0x0104, 0x004F, 0x005B, 0x005E, 0x5F2D, 0x5F35, 0x5F50, 0x5F52, 0x0065,
    0x006E, 0x007A, 0x7F21, 0x7F66, 0x7F74, 0x00C4, 0x00C1, 0x00D3, 0x00D6, 0x00F9, 0x00FA, 0x00FC,
];

struct Rng(SeededEntropy);

impl Rng {
    fn byte(&mut self) -> u8 {
        self.0.bytes(1)[0]
    }
    fn below(&mut self, n: usize) -> usize {
        let b = self.0.bytes(2);
        usize::from(u16::from_be_bytes([b[0], b[1]])) % n
    }
    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }
}

fn random_apdu(rng: &mut Rng) -> Vec<u8> {
    let mode = rng.below(10);
    if mode == 0 {
        // Pure garbage of random length.
        let len = rng.below(12);
        return rng.0.bytes(len);
    }
    let cla = rng.pick(&CLA);
    let ins = if rng.below(8) == 0 { rng.byte() } else { rng.pick(&INS) };
    let (p1, p2) = match rng.below(4) {
        0 => (rng.byte(), rng.byte()),
        1 => (0x00, rng.pick(&[0x81, 0x82, 0x83, 0x00, 0x04])),
        _ => {
            let tag = rng.pick(&TAGS);
            ((tag >> 8) as u8, tag as u8)
        }
    };
    let mut apdu = vec![cla, ins, p1, p2];
    let data_len = match rng.below(6) {
        0 => 0,
        1 => rng.below(8),
        2 => 6 + rng.below(4),
        3 => rng.below(64),
        4 => rng.below(300),
        _ => 32,
    };
    let mut data = rng.0.bytes(data_len);
    if rng.below(4) == 0 && !data.is_empty() {
        // Sometimes a well-formed TLV prefix.
        data[0] = rng.pick(&[0x60, 0x81, 0x83, 0x5C]);
    }
    if rng.below(3) == 0 {
        data = match rng.below(4) {
            0 => b"123456".to_vec(),
            1 => b"12345678".to_vec(),
            2 => b"1234561234567".to_vec(),
            _ => vec![0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21],
        };
    }
    let extended = data.len() > 255 || rng.below(5) == 0;
    if !data.is_empty() {
        if extended {
            apdu.push(0);
            apdu.extend_from_slice(&(data.len() as u16).to_be_bytes());
        } else {
            apdu.push(data.len() as u8);
        }
        apdu.extend_from_slice(&data);
    }
    match rng.below(4) {
        0 => {}
        1 if extended => apdu.extend_from_slice(&[rng.byte(), rng.byte()]),
        1 => apdu.push(rng.byte()),
        2 => apdu.push(0),
        _ => {
            // Deliberately inconsistent length fields.
            let cut = rng.below(apdu.len() + 1);
            apdu.truncate(cut.max(1));
            apdu.push(rng.byte());
        }
    }
    apdu
}

#[test]
fn malformed_apdus_never_panic() {
    for seed in 0..4u64 {
        let mut rng = Rng(SeededEntropy::new(0x6F70_6770 + seed));
        let mut card = Card::new();
        for i in 0..4000 {
            match rng.below(50) {
                0 => {
                    let resp = card.app.select(&crate::common::SELECT, &mut card.host);
                    assert!(resp.len() >= 2);
                }
                1 => card.app.reset(ResetKind::CardPowerOff),
                2 => card.host.fail_next_saves(1),
                3 => card.reload(),
                4 => {
                    // Keep the mutating paths reachable.
                    card.verify(0x83, b"12345678");
                    card.verify(0x82, b"123456");
                }
                5 => {
                    let resp = card.app.touch_resolved(rng.below(2) == 0, &mut card.host);
                    assert_eq!(resp.len(), 2);
                }
                _ => {}
            }
            let apdu = random_apdu(&mut rng);
            match card.app.process(&apdu, &mut card.host) {
                Outcome::Done(resp) => assert!(resp.len() >= 2, "seed {seed} step {i}: {apdu:02X?}"),
                Outcome::NeedTouch { .. } => {
                    let resp = card.app.touch_resolved(rng.below(2) == 0, &mut card.host);
                    assert!(resp.len() >= 2);
                }
            }
        }
    }
}

/// Random stored state never panics the constructor and yields a working applet. Random
/// bytes are almost never readable, and every unreadable state provisions a fresh RSA
/// issuer, so this runs a few iterations; `state::tests::random_bytes_never_panic_the_parser`
/// covers the parser with thousands, and `mutated_snapshots_never_panic` below covers
/// readable but damaged states.
#[test]
fn random_stored_state_never_panics() {
    let mut rng = Rng(SeededEntropy::new(0x5354_4154));
    for _ in 0..6 {
        let len = rng.below(200);
        let mut bytes = rng.0.bytes(len);
        if let Some(first) = bytes.first_mut() {
            *first = 0x01;
        }
        let mut host = lk_testkit::TestHost::new();
        let mut app = lk_openpgp::OpenPgp::new(Some(&bytes), &mut host);
        let resp = app.select(&crate::common::SELECT, &mut host);
        assert!(resp.len() >= 2);
        match app.process(&[0x00, 0xCA, 0x00, 0x6E, 0x00], &mut host) {
            Outcome::Done(resp) => assert!(resp.len() >= 2),
            Outcome::NeedTouch { .. } => panic!(),
        }
    }
}

/// Structured random key commands (docs/DESIGN.md §12-4): GENERATE, import, PSO, INTERNAL
/// AUTHENTICATE, GET ATTESTATION and MSE with CRTs, cipher DOs, import lists and PSO data
/// that are often almost right, mixed with touches, storage faults, reloads, resets and
/// clock steps. Keys are ECC so that stray generations stay cheap; RSA appears through
/// imports of random "primes" and the factory RSA attestation key.
#[test]
fn key_commands_never_panic() {
    const CRTS: [&[u8]; 8] = [
        crt::SIG,
        crt::DEC,
        crt::AUT,
        crt::ATT,
        &[0xB6, 0x03, 0x84, 0x01, 0x01],
        &[0xB8, 0x03, 0x84, 0x01, 0x03],
        &[0xA4, 0x01, 0x84],
        &[0xB6],
    ];
    const ATTRIBUTES: [&str; 7] = [
        attr::ED25519,
        attr::X25519,
        attr::P256_ECDSA,
        attr::P384_ECDH,
        attr::P384_ECDSA,
        attr::P256_ECDH,
        attr::SECP256K1_ECDSA,
    ];
    for seed in 0..3u64 {
        let mut rng = Rng(SeededEntropy::new(0x4B45_5953 + seed));
        let mut card = Card::new();
        card.admin();
        card.set_attributes(0x00C1, attr::ED25519);
        card.set_attributes(0x00C2, attr::X25519);
        card.set_attributes(0x00C3, attr::P256_ECDSA);
        for crt in [crt::SIG, crt::DEC, crt::AUT] {
            card.generate(crt);
        }
        assert_eq!(card.put(0x00D6, &[0x03, 0x20]), 0x9000);
        assert_eq!(card.put(0x00D7, &[0x01, 0x20]), 0x9000);
        for step in 0..1500 {
            match rng.below(40) {
                0 => {
                    card.select();
                }
                1 => card.app.reset(ResetKind::PowerCycle),
                2 => card.host.fail_next_saves(1),
                3 => card.reload(),
                4..=6 => {
                    card.verify(0x83, b"12345678");
                    card.verify(0x81, b"123456");
                    card.verify(0x82, b"123456");
                }
                7 => card.host.advance(rng.below(20_000) as u64),
                8 => {
                    let mse = [hex("0022 41A4 03 830102"), hex("0022 41B8 03 830103"), hex("0022 41A4 03 830103")];
                    card.send(&mse[rng.below(3)]);
                }
                9 => {
                    let tag = [0x00C1u16, 0x00C2, 0x00C3][rng.below(3)];
                    card.put(tag, &hex(ATTRIBUTES[rng.below(ATTRIBUTES.len())]));
                }
                10 => {
                    let tag = [0x00D6u16, 0x00D7, 0x00D8, 0x00D9][rng.below(4)];
                    card.put(tag, &[rng.below(5) as u8, 0x20]);
                }
                _ => {}
            }
            let apdu = random_key_apdu(&mut rng, &CRTS);
            match card.app.process(&apdu, &mut card.host) {
                Outcome::Done(resp) => assert!(resp.len() >= 2, "seed {seed} step {step}: {apdu:02X?}"),
                Outcome::NeedTouch { timeout_ms } => {
                    assert_eq!(timeout_ms, 15_000);
                    if rng.below(5) == 0 {
                        // The device may drop the waiting command instead.
                        card.app.deselect();
                    }
                    let resp = card.app.touch_resolved(rng.below(3) != 0, &mut card.host);
                    assert!(resp.len() >= 2);
                }
            }
        }
    }
}

fn mutate(rng: &mut Rng, mut data: Vec<u8>) -> Vec<u8> {
    match rng.below(6) {
        0 if !data.is_empty() => {
            let at = rng.below(data.len());
            data[at] ^= 1 << rng.below(8);
        }
        1 => data.truncate(rng.below(data.len() + 1)),
        2 => data.push(rng.byte()),
        _ => {}
    }
    data
}

fn random_key_apdu(rng: &mut Rng, crts: &[&[u8]]) -> Vec<u8> {
    let (cla, ins, p1, p2, data): (u8, u8, u8, u8, Vec<u8>) = match rng.below(7) {
        0 => {
            let p1 = [0x80, 0x81, 0x81, 0x82][rng.below(4)];
            let mut crt = crts[rng.below(crts.len())].to_vec();
            if p1 == 0x80 && crt == crt::ATT {
                // An RSA 2048 attestation key generation is slow in debug builds.
                crt = crt::SIG.to_vec();
            }
            (0x00, 0x47, p1, [0x00, 0x00, 0x01][rng.below(3)], mutate(rng, crt))
        }
        1 => {
            let crt = crts[rng.below(crts.len())];
            let private_len = [32, 48, 31, 128][rng.below(4)];
            let private = rng.0.bytes(private_len);
            let public = { let n = [32, 65, 97][rng.below(3)]; rng.0.bytes(n) };
            let components: Vec<(u8, &[u8])> = match rng.below(4) {
                0 => vec![(0x92, &private)],
                1 => vec![(0x92, &private), (0x99, &public)],
                2 => vec![(0x91, &[1, 0, 1]), (0x92, &private), (0x93, &private)],
                _ => vec![(0x99, &public), (0x92, &private)],
            };
            (0x00, 0xDB, 0x3F, [0xFF, 0xFF, 0xFE][rng.below(3)], mutate(rng, import_data(crt, &components)))
        }
        2 => {
            let len = [0, 1, 20, 32, 48, 64, 65, 100][rng.below(8)];
            (0x00, 0x2A, 0x9E, [0x9A, 0x9A, 0x9B][rng.below(3)], rng.0.bytes(len))
        }
        3 => {
            let point = match rng.below(4) {
                0 => rng.0.bytes(32),
                1 => {
                    let mut p = rng.0.bytes(65);
                    p[0] = 0x04;
                    p
                }
                2 => {
                    let mut p = vec![0x00];
                    p.extend_from_slice(&rng.0.bytes(256));
                    return [vec![0x00, 0x2A, 0x80, 0x86, 0x00, 0x01, 0x01], p, vec![0x00, 0x00]].concat();
                }
                _ => { let n = rng.below(70); rng.0.bytes(n) }
            };
            (0x00, 0x2A, 0x80, 0x86, mutate(rng, cipher_do(&point)))
        }
        4 => (0x00, 0x88, [0x00, 0x00, 0x01][rng.below(3)], 0x00, { let n = [0, 16, 32, 64, 65][rng.below(5)]; rng.0.bytes(n) }),
        5 => {
            let cla = [0x80, 0x80, 0x00][rng.below(3)];
            let data = if rng.below(4) == 0 { vec![rng.byte()] } else { vec![] };
            (cla, 0xFB, rng.below(5) as u8, [0x00, 0x00, 0x01][rng.below(3)], data)
        }
        _ => (0x10 * (rng.below(2) as u8), [0x2A, 0x88, 0xDB, 0x47][rng.below(4)], rng.byte(), rng.byte(), { let n = rng.below(40); rng.0.bytes(n) }),
    };
    let mut apdu = vec![cla, ins, p1, p2];
    let extended = data.len() > 255 || rng.below(3) == 0;
    if !data.is_empty() {
        if extended {
            apdu.push(0);
            apdu.extend_from_slice(&(data.len() as u16).to_be_bytes());
        } else {
            apdu.push(data.len() as u8);
        }
        apdu.extend_from_slice(&data);
    }
    match rng.below(4) {
        0 => {}
        1 if extended => apdu.extend_from_slice(&[0, 0]),
        1 => apdu.push(0),
        2 if extended => apdu.extend_from_slice(&[0, rng.byte()]),
        _ => apdu.push(rng.byte()),
    }
    apdu
}
