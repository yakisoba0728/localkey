//! Deterministic pseudo-random malformed input (`docs/DESIGN.md` §12-4: fixed-seed
//! random tests instead of a fuzzer). Every APDU must get an answer of at least a status
//! word, and no input or stored record may panic the applet.

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use lk_codec::apdu::{Command, split_response};
use lk_codec::tlv;
use lk_core::{CardApplet, Entropy, Outcome, Record, ResetKind};
use lk_piv::Piv;
use lk_testkit::{SeededEntropy, TestHost};

struct Rng(SeededEntropy);

impl Rng {
    fn byte(&mut self) -> u8 {
        let mut b = [0u8; 1];
        self.0.fill(&mut b);
        b[0]
    }

    fn below(&mut self, n: usize) -> usize {
        let mut b = [0u8; 4];
        self.0.fill(&mut b);
        u32::from_le_bytes(b) as usize % n.max(1)
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        self.0.bytes(n)
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }
}

/// Instructions the applet knows and a few neighbours.
const INS: &[u8] = &[
    0xA4, 0xCB, 0xDB, 0x20, 0x24, 0x2C, 0x87, 0xC0, 0xF7, 0xF8, 0xFA, 0xFB, 0xFD, 0xFF, 0x47, 0xFE, 0xF6, 0xF9, 0xCA,
];

/// Asymmetric algorithms for GENERATE-shaped data. RSA is left out: one RSA-4096
/// generation takes seconds in a debug build, and RSA paths have their own tests.
const FAST_ALGS: &[u8] = &[0x11, 0x14, 0xE0, 0xE1, 0x11, 0x00, 0x0A, 0x99];

fn random_data(rng: &mut Rng) -> Vec<u8> {
    match rng.below(11) {
        0 => {
            let n = rng.below(300);
            rng.bytes(n)
        }
        1 => {
            // GET/PUT DATA shaped: a tag list, then a 53 object of random size.
            let tag = rng.pick(&[&[0x7E][..], &[0x7F, 0x61], &[0x5F, 0xC1, 0x02], &[0x5F, 0xC1, 0x05], &[0x5F, 0xFF, 0x01]]);
            let mut data = tlv::encode(0x5C, tag);
            let n = rng.below(400);
            let value = rng.bytes(n);
            tlv::encode_into(&mut data, rng.pick(&[0x53, 0x53, 0x70, 0x7E]), &value);
            data
        }
        2 => {
            // A certificate container with a 70 TLV.
            let len = if rng.below(4) == 0 { rng.pick(&[3052, 3053]) } else { rng_len(rng, 64) };
            let mut inner = tlv::encode(0x70, &rng.bytes(len));
            inner.extend_from_slice(&[0x71, 0x01, 0x00, 0xFE, 0x00]);
            let mut data = tlv::encode(0x5C, &[0x5F, 0xC1, 0x0A]);
            tlv::encode_into(&mut data, 0x53, &inner);
            data
        }
        3 => {
            // Dynamic authentication template with random elements.
            let mut inner = Vec::new();
            for _ in 0..rng.below(3) {
                let tag = rng.pick(&[0x80, 0x81, 0x82, 0x85, 0x83]);
                let len = rng.pick(&[0usize, 8, 16, 7, 17]);
                tlv::encode_into(&mut inner, tag, &rng.bytes(len));
            }
            tlv::encode(0x7C, &inner)
        }
        4 => {
            let n = rng.pick(&[8usize, 16, 15, 17]);
            rng.bytes(n)
        }
        7 => {
            // GENERATE shaped: AC { 80 alg [AA pin] [AB touch] } with odd extras.
            let mut inner = tlv::encode(0x80, &[rng.pick(FAST_ALGS)]);
            for _ in 0..rng.below(3) {
                let tag = rng.pick(&[0xAA, 0xAB, 0x80, 0xAC]);
                let len = rng.pick(&[1usize, 1, 1, 0, 2]);
                tlv::encode_into(&mut inner, tag, &rng.bytes(len).iter().map(|b| b % 7).collect::<Vec<_>>());
            }
            tlv::encode(rng.pick(&[0xAC, 0xAC, 0xAC, 0x7C]), &inner)
        }
        8 => {
            // IMPORT shaped: one key element and optional policies.
            let tag = rng.pick(&[0x06u32, 0x07, 0x08, 0x01, 0x05]);
            let len = rng.pick(&[32usize, 48, 31, 33, 64]);
            let mut data = tlv::encode(tag, &rng.bytes(len));
            if rng.below(2) == 0 {
                tlv::encode_into(&mut data, 0xAA, &[rng.byte() % 6]);
            }
            if rng.below(2) == 0 {
                tlv::encode_into(&mut data, 0xAB, &[rng.byte() % 5]);
            }
            data
        }
        9 => {
            // Slot GENERAL AUTHENTICATE shaped: 7C { 82 00, 81|85 data }.
            let mut inner = tlv::encode(0x82, &[]);
            let len = rng.pick(&[0usize, 1, 20, 32, 33, 48, 49, 65, 97, 128]);
            let mut value = rng.bytes(len);
            if let Some(first) = value.first_mut().filter(|_| rng.below(2) == 0) {
                *first = 0x04;
            }
            tlv::encode_into(&mut inner, rng.pick(&[0x81, 0x85, 0x81, 0x80]), &value);
            tlv::encode(0x7C, &inner)
        }
        5 => {
            // SET MANAGEMENT KEY shaped.
            let alg = rng.pick(&[0x03u8, 0x08, 0x0A, 0x0C, 0x11]);
            let mut data = vec![alg];
            let len = rng.pick(&[16usize, 24, 32, 0]);
            tlv::encode_into(&mut data, rng.pick(&[0x9B, 0x9A]), &rng.bytes(len));
            data
        }
        6 => {
            // SELECT shaped: PIV AID prefixes (SP 800-73-4 Part 2 §3.1.1) and others.
            let full = hex("A000000308000010000100");
            match rng.below(3) {
                0 => full[..5 + rng.below(7)].to_vec(),
                1 => {
                    let mut aid = full[..rng.below(full.len() + 1)].to_vec();
                    aid.push(rng.byte());
                    aid
                }
                _ => rng.pick(&[&hex("A000000527471117")[..], &hex("A0000003")[..], &[][..]]).to_vec(),
            }
        }
        _ => Vec::new(),
    }
}

fn rng_len(rng: &mut Rng, max: usize) -> usize {
    rng.below(max + 1)
}

fn random_apdu(rng: &mut Rng) -> Vec<u8> {
    if rng.below(5) == 0 {
        // Raw garbage, including APDUs shorter than a header and broken length fields.
        let n = rng.below(12);
        return rng.bytes(n);
    }
    let cla = rng.pick(&[0x00, 0x00, 0x00, 0x10, 0x10, 0x0C, 0x01, 0x80]);
    let ins = if rng.below(6) == 0 { rng.byte() } else { rng.pick(INS) };
    let p1 = if rng.below(4) == 0 {
        rng.byte()
    } else {
        rng.pick(&[0x00, 0x3F, 0xFF, 0x03, 0x08, 0x0A, 0x0C, 0x04, 0x01, 0x11, 0x14, 0xE0, 0xE1, 0x9A, 0x9C, 0x82, 0xF9])
    };
    let p2 = if rng.below(4) == 0 {
        rng.byte()
    } else {
        rng.pick(&[0x00, 0xFF, 0xFE, 0x80, 0x81, 0x9B, 0x9A, 0xF9, 0x01, 0x9C, 0x9D, 0x9E, 0x82, 0x95])
    };
    // Never let random traffic start an RSA generation or import (seconds per key in a
    // debug build): GENERATE carries its algorithm in the data (FAST_ALGS), and IMPORT
    // with an RSA algorithm cannot carry consistent CRT components anyway.
    let mut cmd = Command::new(cla, ins, p1, p2).with_data(random_data(rng));
    cmd.le = match rng.below(4) {
        0 => Some(0),
        1 => Some(rng.below(300) as u32),
        _ => None,
    };
    cmd.extended = rng.below(5) == 0;
    let mut bytes = cmd.to_bytes();
    if rng.below(10) == 0 && !bytes.is_empty() {
        let i = rng.below(bytes.len());
        bytes[i] = rng.byte();
    }
    if rng.below(15) == 0 {
        let keep = rng.below(bytes.len() + 1);
        bytes.truncate(keep);
    }
    bytes
}

fn answer(outcome: Outcome<Vec<u8>>, piv: &mut Piv, host: &mut TestHost, touched: bool) -> Vec<u8> {
    match outcome {
        Outcome::Done(resp) => resp,
        Outcome::NeedTouch { timeout_ms } => {
            assert_eq!(timeout_ms, 15_000);
            piv.touch_resolved(touched, host)
        }
    }
}

/// Mutual authentication with the default key that tolerates any answer (the random
/// traffic may have changed the key or its touch flag). With `request_response` step 2
/// carries the `82 00` of SP 800-73-4 Part 2 Table 19.
fn try_default_auth(card: &mut Card, request_response: bool) {
    let key = hex(DEFAULT_MGMT_KEY);
    let step1 = apdu(0x00, 0x87, ALG_AES192, 0x9B, &hex("7C028000"), None);
    let Outcome::Done(resp) = card.piv.process(&step1, &mut card.host) else {
        return;
    };
    let Some((data, 0x9000)) = split_response(&resp) else {
        return;
    };
    let Ok((outer, _)) = tlv::parse_one(data) else {
        return;
    };
    let Ok(items) = outer.children() else {
        return;
    };
    let Some(item) = items.first().filter(|t| t.value.len() == 16) else {
        return;
    };
    let mut inner = tlv::encode(0x80, &decrypt(ALG_AES192, &key, item.value));
    tlv::encode_into(&mut inner, 0x81, &[0x5A; 16]);
    if request_response {
        tlv::encode_into(&mut inner, 0x82, &[]);
    }
    let step2 = apdu(0x00, 0x87, ALG_AES192, 0x9B, &tlv::encode(0x7C, &inner), None);
    if let Outcome::NeedTouch { .. } = card.piv.process(&step2, &mut card.host) {
        let _ = card.piv.touch_resolved(true, &mut card.host);
    }
}

#[test]
fn random_apdus_never_panic() {
    let mut rng = Rng(SeededEntropy::new(0x5049_5631));
    let mut card = Card::new();
    let mut successes = std::collections::BTreeMap::new();
    for round in 0..20_000u32 {
        if round % 400 == 0 {
            // Re-establish authorization so deeper paths run; failures are fine (the
            // random traffic may have changed or blocked the credentials).
            try_default_auth(&mut card, round % 800 == 0);
            let _ = card.verify_pin(&hex(DEFAULT_PIN));
        }
        match rng.below(60) {
            0 => card.piv.deselect(),
            1 => card.piv.reset(rng.pick(&[ResetKind::CardPowerOff, ResetKind::UsbReset, ResetKind::PowerCycle])),
            2 => {
                let resp = card.piv.select(&hex(SELECT), &mut card.host);
                assert!(resp.len() >= 2);
            }
            3 => {
                let touched = rng.below(2) == 0;
                assert!(card.piv.touch_resolved(touched, &mut card.host).len() >= 2);
            }
            4 => {
                card.host.fail_next_saves(1);
            }
            5 => card.restart(),
            6 => card.host.advance(rng.below(20_000) as u64),
            _ => {}
        }
        let bytes = random_apdu(&mut rng);
        let touched = rng.below(2) == 0;
        let outcome = card.piv.process(&bytes, &mut card.host);
        let resp = answer(outcome, &mut card.piv, &mut card.host, touched);
        assert!(resp.len() >= 2, "round {round}: {bytes:02X?}");
        let sw1 = resp[resp.len() - 2];
        if (sw1 == 0x90 || sw1 == 0x61) && bytes.len() > 4 {
            *successes.entry(bytes[1]).or_insert(0usize) += 1;
        }
    }
    // The random traffic reached the key commands, not only their error paths.
    for ins in [0x47u8, 0xFE, 0xF6, 0xF9, 0x87, 0xDB, 0xA4, 0x20, 0xCB] {
        assert!(successes.get(&ins).copied().unwrap_or(0) > 0, "no successful {ins:02X}: {successes:02X?}");
    }
    // Whatever was stored must reload to a working applet.
    card.restart();
    assert_eq!(card.send("00FD0000").1, 0x9000);
}

#[test]
fn random_stored_records_never_panic() {
    let mut rng = Rng(SeededEntropy::new(0x5049_5632));
    // A populated valid record to mutate: objects, the own F9 issuer and slot keys.
    let mut card = Card::new();
    card.auth_default();
    assert_eq!(card.put_object(0x5FC102, &[0x30; 40]), 0x9000);
    assert_eq!(card.put_object(0x5FC105, &[0x70, 0x02, 0x30, 0x00]), 0x9000);
    card.generate(0x9A, P256, Some(PIN_NEVER), None);
    card.generate(0x9C, ED25519, Some(PIN_NEVER), None);
    card.generate(0x9D, X25519, None, None);
    let valid = card.host.persisted(Record::Piv).unwrap();
    // Each unreadable record means a fresh F9 key and certificate (an ECDSA signature),
    // so the count stays moderate for debug builds.
    for _ in 0..1_200 {
        let stored = match rng.below(3) {
            0 => {
                let n = rng.below(200);
                let mut bytes = rng.bytes(n);
                if let Some(first) = bytes.first_mut() {
                    *first = 0x01;
                }
                bytes
            }
            1 => {
                let mut bytes = valid.clone();
                for _ in 0..1 + rng.below(4) {
                    let i = rng.below(bytes.len());
                    bytes[i] = rng.byte();
                }
                bytes
            }
            _ => {
                let mut bytes = valid.clone();
                let keep = rng.below(bytes.len() + 1);
                bytes.truncate(keep);
                bytes
            }
        };
        let mut host = TestHost::new();
        let mut piv = Piv::new(Some(&stored), &mut host);
        let resp = piv.select(&hex(SELECT), &mut host);
        assert!(resp.len() >= 2);
        let sign = format!("0087119A267C248200 8120{}", "11".repeat(32));
        for apdu in [
            "00F7000080",
            "00F7000081",
            "00F700009B",
            "00F700009A",
            "00F70000F9",
            "00CB3FFF055C035FC10200",
            "0020008000",
            "00F99A0000",
            sign.as_str(),
        ] {
            // A mutated record may carry any policy, so a touch request is possible.
            match piv.process(&hex(apdu), &mut host) {
                Outcome::Done(resp) => assert!(resp.len() >= 2),
                Outcome::NeedTouch { .. } => assert!(piv.touch_resolved(false, &mut host).len() >= 2),
            }
        }
    }
}

/// A well-formed command that changes persistent state when authorized (or spends a
/// retry), with random parameters, so the persistence checks see many commits.
fn random_mutation(rng: &mut Rng) -> Vec<u8> {
    let slot = rng.pick(&[0x9A, 0x9C, 0x9D, 0x9E, 0x82, 0x95, 0xF9]);
    let other = rng.pick(&[0x9A, 0x9C, 0x9D, 0x9E, 0x82, 0x95, 0xF9, 0xFF]);
    let pin = rng.pick(&[0x00, 0x01, 0x02, 0x03]);
    let touch = rng.pick(&[0x00, 0x01, 0x02, 0x03]);
    let (ins, p1, p2, data) = match rng.below(9) {
        0 => {
            let tag = rng.pick(&[0x5FC102u32, 0x5FC105, 0x5FFF01]);
            let n = rng.below(300);
            (0xDB, 0x3F, 0xFF, Card::put_payload(tag, &rng.bytes(n)))
        }
        1 => (0x47, 0x00, slot, generate_template(rng.pick(&[P256, P384, ED25519, X25519]), Some(pin), Some(touch))),
        2 => {
            let mut data = tlv::encode(0x07, &rng.bytes(32));
            data.extend([0xAA, 0x01, pin, 0xAB, 0x01, touch]);
            (0xFE, ED25519, slot, data)
        }
        3 => (0xF6, other, slot, Vec::new()),
        4 => {
            let pin = if rng.below(2) == 0 { hex(DEFAULT_PIN) } else { pad(b"999999") };
            (0x20, 0x00, 0x80, pin)
        }
        5 => {
            let mut data = if rng.below(2) == 0 { hex(DEFAULT_PIN) } else { pad(b"999999") };
            data.extend_from_slice(&hex(DEFAULT_PIN));
            (0x24, 0x00, 0x80, data)
        }
        6 => {
            let mut data = if rng.below(2) == 0 { hex(DEFAULT_PUK) } else { pad(b"99999999") };
            data.extend_from_slice(&hex(DEFAULT_PIN));
            (0x2C, 0x00, 0x80, data)
        }
        7 => (0xFA, 1 + rng.below(5) as u8, 1 + rng.below(5) as u8, Vec::new()),
        _ => {
            let mut data = vec![ALG_AES192];
            tlv::encode_into(&mut data, 0x9B, &hex(DEFAULT_MGMT_KEY));
            if rng.below(4) == 0 {
                (0xFB, 0x00, 0x00, Vec::new())
            } else {
                (0xFF, 0xFF, 0xFF, data)
            }
        }
    };
    apdu(0x00, ins, p1, p2, &data, None)
}

/// Everything persistent that the card shows without the PIN, read with extended APDUs
/// (Le `0000`, so each answer comes whole): PIN, PUK and management key metadata, every
/// key slot's metadata and the always-readable objects the random traffic writes.
fn observe(piv: &mut Piv, host: &mut TestHost) -> Vec<Vec<u8>> {
    let read = |piv: &mut Piv, host: &mut TestHost, ins: u8, p1: u8, p2: u8, data: &[u8]| {
        let mut cmd = Command::new(0x00, ins, p1, p2).with_data(data.to_vec());
        cmd.le = Some(0);
        cmd.extended = true;
        match piv.process(&cmd.to_bytes(), host) {
            Outcome::Done(resp) => resp,
            Outcome::NeedTouch { .. } => panic!("a read asked for a touch"),
        }
    };
    // A chain left open by the traffic ends with 6883 on the first command of another
    // header (docs/CONTRACTS.md "lk-codec::apdu"); this one is not observed.
    let _ = read(piv, host, 0xFD, 0x00, 0x00, &[]);
    let mut seen = Vec::new();
    let references = [0x80u8, 0x81, 0x9B, 0x9A, 0x9C, 0x9D, 0x9E, 0xF9].into_iter().chain(0x82..=0x95);
    for reference in references {
        seen.push(read(piv, host, 0xF7, 0x00, reference, &[]));
    }
    for tag in [[0x5F, 0xC1, 0x02], [0x5F, 0xC1, 0x05], [0x5F, 0xFF, 0x01]] {
        seen.push(read(piv, host, 0xCB, 0x3F, 0xFF, &tlv::encode(0x5C, &tag)));
    }
    seen
}

#[test]
fn memory_always_matches_storage() {
    // docs/DESIGN.md §7 commit rule and docs/CONTRACTS.md: a change is persisted before
    // it is answered, and a failed save leaves the previous state in memory. So at every
    // point the running applet and one rebuilt from the last persisted record must show
    // the same persistent state, through random traffic with injected save failures.
    let mut rng = Rng(SeededEntropy::new(0x5049_5633));
    let mut card = Card::new();
    let mut refused_saves = 0;
    for round in 0..6_000u32 {
        if round % 10 == 0 {
            // Keep the authorizations up so the mutating paths run (the traffic may have
            // changed or blocked the credentials; failures are fine).
            try_default_auth(&mut card, round % 20 == 0);
            let _ = card.verify_pin(&hex(DEFAULT_PIN));
        }
        let injected = rng.below(6) == 0;
        if injected {
            card.host.fail_next_saves(1 + rng.below(2));
        }
        let bytes = if rng.below(2) == 0 { random_mutation(&mut rng) } else { random_apdu(&mut rng) };
        let touched = rng.below(2) == 0;
        let outcome = card.piv.process(&bytes, &mut card.host);
        let resp = answer(outcome, &mut card.piv, &mut card.host, touched);
        assert!(resp.len() >= 2);
        if injected {
            refused_saves += usize::from(resp.ends_with(&[0x65, 0x81]));
            // An unused injected failure must not hit the reads below.
            card.host.fail_next_saves(0);
        }
        if injected || round % 20 == 0 {
            let live = observe(&mut card.piv, &mut card.host);
            let stored = card.host.persisted(Record::Piv);
            let mut fresh_host = TestHost::new();
            let mut reloaded = Piv::new(stored.as_deref(), &mut fresh_host);
            assert_eq!(fresh_host.persist_count(), 0, "round {round}: the stored record was complete");
            let from_storage = observe(&mut reloaded, &mut fresh_host);
            assert_eq!(live, from_storage, "round {round} after {bytes:02X?} -> {resp:02X?}");
        }
    }
    // The traffic changed the record many times and hit commits with failing saves.
    assert!(card.host.persist_count() > 1_000, "{} saves", card.host.persist_count());
    assert!(refused_saves > 100, "{refused_saves} refused saves");
}
