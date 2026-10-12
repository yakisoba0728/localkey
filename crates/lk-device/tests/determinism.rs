//! Determinism and robustness (docs/DESIGN.md §1, §11, §12-4: fixed-seed random input
//! tests instead of cargo-fuzz).

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use lk_core::{DeviceProfile, Entropy, Record};
use lk_device::{BusEvent, Input, Output, TouchEdge};
use lk_testkit::SeededEntropy;

/// A session over every interface: CTAPHID INIT/GetInfo/PING, a touch-waiting CBOR
/// command, CCID OATH and PIV commands, an SCP03 session, OTP HID writes and reads.
fn session(rig: &mut Rig) -> Vec<Output> {
    let mut out = Vec::new();
    let cid = rig.ctaphid_init();
    out.extend(rig.ctaphid_send(cid, CTAPHID_CBOR, &[0x04]));
    out.extend(rig.ctaphid_send(cid, CTAPHID_CBOR, &[0x0B]));
    out.extend(rig.advance(250));
    out.extend(rig.tap());
    rig.power_on();
    rig.select(AID_OATH);
    let (_, o) = rig.xfr(&oath_put(b"det", true));
    out.extend(o);
    let (_, o) = rig.xfr(&oath_calculate(b"det"));
    out.extend(o);
    out.extend(rig.advance(700));
    out.extend(rig.tap());
    let mut scp = Scp03::open(rig);
    let wrapped = scp.wrap(0x00, 0xA1, 0x00, 0x00, &[], Some(0));
    let (_, o) = rig.xfr(&wrapped);
    out.extend(o);
    out.extend(rig.otp_write(0x13, &[0; 64]));
    for _ in 0..3 {
        out.extend(rig.input(Input::OtpGetFeature));
    }
    out
}

/// docs/DESIGN.md §1: the same inputs, times and entropy give the same outputs and the
/// same stored bytes.
#[test]
fn same_seed_same_outputs_and_store() {
    let mut a = Rig::new();
    let mut b = Rig::new();
    let out_a = session(&mut a);
    let out_b = session(&mut b);
    assert!(!out_a.is_empty());
    assert_eq!(out_a, out_b);
    for record in [Record::Device, Record::Fido, Record::Oath, Record::Otp, Record::Piv, Record::OpenPgp, Record::HsmAuth, Record::SecurityDomain] {
        assert_eq!(a.store.get(record), b.store.get(record), "{record:?}");
    }
}

/// A different entropy seed changes the device's random choices (here the stored
/// Security Domain identity), so the comparison above is not vacuous.
#[test]
fn different_seed_differs() {
    let a = Rig::with_store(DeviceProfile::yubikey_compat(SERIAL), lk_testkit::MemoryStore::new(), 1);
    let b = Rig::with_store(DeviceProfile::yubikey_compat(SERIAL), lk_testkit::MemoryStore::new(), 2);
    assert_ne!(a.store.get(Record::SecurityDomain), b.store.get(Record::SecurityDomain));
}

fn below(rng: &mut SeededEntropy, bound: usize) -> usize {
    let mut b = [0u8; 4];
    rng.fill(&mut b);
    u32::from_be_bytes(b) as usize % bound
}

/// A random input of every kind, biased toward well-formed frames so the routing
/// behind the framers is reached.
fn random_input(rng: &mut SeededEntropy, rig: &mut Rig, cids: &[u32]) -> Vec<Output> {
    match below(rng, 12) {
        0 | 1 => {
            let mut report = [0u8; 64];
            rng.fill(&mut report);
            if below(rng, 2) == 0 {
                let cid = cids.get(below(rng, cids.len().max(1))).copied().unwrap_or(BROADCAST);
                report[..4].copy_from_slice(&cid.to_be_bytes());
                report[4] = [0x86, 0x90, 0x83, 0x81, 0x91, 0xC2, 0xC3, 0xC0, 0x88][below(rng, 9)];
                report[5] = 0;
                report[6] = below(rng, 70) as u8;
            }
            rig.input(Input::FidoReport(&report))
        }
        2..=4 => {
            let kind = [0x62, 0x63, 0x65, 0x6F, 0x6F, 0x6F, 0x72, 0x6C, 0x61][below(rng, 9)];
            let len = below(rng, 40);
            let mut data = rng.bytes(len);
            if kind == 0x6F && len >= 5 && below(rng, 2) == 0 {
                // A SELECT of a real AID or a command to it.
                let aids: [&[u8]; 8] = [AID_MGMT, AID_OTP, AID_OATH, AID_PIV, AID_OPENPGP, AID_HSMAUTH, AID_SD, &[0xA0, 0, 0]];
                let aid = aids[below(rng, aids.len())];
                data = vec![0x00, 0xA4, 0x04, 0x00, aid.len() as u8];
                data.extend_from_slice(aid);
            }
            let seq = below(rng, 4) as u8;
            let message = Rig::ccid_message(kind, seq, [0, 0, 0], &data);
            rig.input(Input::Ccid(&message))
        }
        5 => rig.input(Input::CcidControlAbort {
            slot: below(rng, 2) as u8,
            seq: below(rng, 4) as u8,
        }),
        6 => {
            let mut report = [0u8; 8];
            rng.fill(&mut report);
            if below(rng, 2) == 0 {
                report[7] = 0x80 | below(rng, 11) as u8;
            }
            rig.input(Input::OtpSetFeature(&report))
        }
        7 => rig.input(Input::OtpGetFeature),
        8 => {
            let edge = if below(rng, 2) == 0 { TouchEdge::Down } else { TouchEdge::Up };
            rig.input(Input::Touch(edge))
        }
        9 | 10 => rig.advance(below(rng, 4_000) as u64),
        _ => {
            let event = [BusEvent::Reset, BusEvent::Suspend, BusEvent::Resume, BusEvent::PowerCycle][below(rng, 4)];
            rig.bus(event)
        }
    }
}

/// Fixed-seed random inputs never panic, and after every call the device's invariants
/// hold: nothing due is left unprocessed (`next_deadline() > now`), and the presence
/// indicator alternates and matches `presence_pending`.
#[test]
fn random_inputs_keep_invariants() {
    let mut rng = SeededEntropy::new(0xD3_71CE);
    for round in 0..6 {
        let mut rig = Rig::new();
        let cids = vec![rig.ctaphid_init(), rig.ctaphid_init()];
        let mut lit = false;
        for step in 0..1_500 {
            let out = random_input(&mut rng, &mut rig, &cids);
            if let Some(deadline) = rig.dev.next_deadline() {
                assert!(deadline > rig.now, "round {round} step {step}: deadline {deadline} at {}", rig.now);
            }
            // Each report changes the state (a WINK pulse is `true` then `false` from an
            // unlit indicator).
            for state in indicators(&out) {
                assert_ne!(state, lit, "round {round} step {step}: repeated indicator state");
                lit = state;
            }
            assert_eq!(lit, rig.dev.presence_pending(), "round {round} step {step}");
            for o in &out {
                if let Output::Ccid(message) = o {
                    assert!(message.len() >= 10, "CCID bulk-in header");
                }
            }
        }
    }
}
