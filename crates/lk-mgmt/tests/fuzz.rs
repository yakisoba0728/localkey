//! Deterministic random-input tests (docs/DESIGN.md §12-4: fixed-seed pseudo-random
//! inputs from `lk_testkit` instead of cargo-fuzz).
//!
//! Every entry point (CCID APDUs, CTAPHID vendor payloads, OTP HID slot data, stored
//! records) gets random and half-structured malformed input. The tests assert that
//! nothing panics, every APDU response carries a status word, and the DeviceInfo
//! invariants hold afterwards (at least one application enabled, only supported ones).

use lk_codec::apdu::{Command, split_response, sw};
use lk_codec::tlv;
use lk_core::{CardApplet, Outcome, Record, ResetKind};
use lk_mgmt::{AID, Management, MgmtApplet, tag};
use lk_testkit::{SeededEntropy, TestHost};

struct Rng(SeededEntropy);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(SeededEntropy::new(seed))
    }

    fn byte(&mut self) -> u8 {
        self.0.bytes(1).first().copied().unwrap_or(0)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        let b = self.0.bytes(2);
        let v = usize::from(b.first().copied().unwrap_or(0)) << 8
            | usize::from(b.get(1).copied().unwrap_or(0));
        v % n
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        self.0.bytes(n)
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        let i = self.below(items.len());
        *items.get(i).expect("non-empty choice")
    }
}

/// The lock code the well-formed generator sets and presents.
const FUZZ_LOCK: [u8; 16] = [0xA5; 16];

/// A well-formed WRITE CONFIG TLV list (right widths, mostly valid values), so the
/// random sessions also reach the lock, persistence and reboot paths.
fn wellformed_tlvs(rng: &mut Rng) -> Vec<u8> {
    let mut out = Vec::new();
    if rng.below(4) == 0 {
        out.extend_from_slice(&tlv::encode(tag::REBOOT, &[]));
    }
    if rng.below(3) == 0 {
        let code = if rng.below(4) == 0 {
            [0u8; 16]
        } else {
            FUZZ_LOCK
        };
        out.extend_from_slice(&tlv::encode(tag::UNLOCK, &code));
    }
    if rng.below(2) == 0 {
        let bits = u16::from_be_bytes([rng.byte(), rng.byte()]) & 0x033B;
        out.extend_from_slice(&tlv::encode(tag::USB_ENABLED, &bits.to_be_bytes()));
    }
    if rng.below(3) == 0 {
        out.extend_from_slice(&tlv::encode(tag::AUTO_EJECT_TIMEOUT, &rng.bytes(2)));
    }
    if rng.below(3) == 0 {
        out.extend_from_slice(&tlv::encode(tag::CHALRESP_TIMEOUT, &rng.bytes(1)));
    }
    if rng.below(3) == 0 {
        out.extend_from_slice(&tlv::encode(tag::DEVICE_FLAGS, &[rng.byte() & 0xC0]));
    }
    if rng.below(5) == 0 {
        let code = if rng.below(3) == 0 {
            [0u8; 16]
        } else {
            FUZZ_LOCK
        };
        out.extend_from_slice(&tlv::encode(tag::CONFIG_LOCK, &code));
    }
    out
}

/// A TLV list built from Management tags with random (often wrong) lengths.
fn random_tlvs(rng: &mut Rng) -> Vec<u8> {
    if rng.below(2) == 0 {
        return wellformed_tlvs(rng);
    }
    let mut out = Vec::new();
    for _ in 0..rng.below(6) {
        let t = match rng.below(4) {
            0 => u32::from(rng.byte()),
            _ => rng.pick(&[
                tag::USB_ENABLED,
                tag::AUTO_EJECT_TIMEOUT,
                tag::CHALRESP_TIMEOUT,
                tag::DEVICE_FLAGS,
                tag::CONFIG_LOCK,
                tag::UNLOCK,
                tag::REBOOT,
                tag::NFC_ENABLED,
                tag::SERIAL,
            ]),
        };
        let len = match rng.below(4) {
            0 => 16,
            1 => rng.pick(&[0usize, 1, 2]),
            _ => rng.below(20),
        };
        let value = match rng.below(3) {
            0 => vec![0; len],
            _ => rng.bytes(len),
        };
        if (t & 0x1F) == 0x1F {
            // Keep the tag one byte so the list stays mostly parseable.
            out.extend_from_slice(&tlv::encode(t ^ 0x01, &value));
        } else {
            out.extend_from_slice(&tlv::encode(t, &value));
        }
        if rng.below(10) == 0 {
            // Truncate or corrupt.
            let cut = rng.below(out.len() + 1);
            out.truncate(cut);
        }
    }
    out
}

/// `len || tlvs`, usually with the right length byte.
fn random_config(rng: &mut Rng) -> Vec<u8> {
    let body = random_tlvs(rng);
    let len = match rng.below(8) {
        0 => rng.byte(),
        _ => u8::try_from(body.len()).unwrap_or(0xFF),
    };
    let mut out = vec![len];
    out.extend_from_slice(&body);
    out
}

fn random_apdu(rng: &mut Rng) -> Vec<u8> {
    match rng.below(3) {
        0 => {
            let n = rng.below(300);
            rng.bytes(n)
        }
        _ => {
            let cla = rng.pick(&[0x00u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x80, 0x0C, 0x01]);
            let ins = match rng.below(8) {
                0 => rng.byte(),
                _ => rng.pick(&[0x1Cu8, 0x1C, 0x1D, 0xA4, 0x16, 0x1F, 0xC0]),
            };
            let p1 = if rng.below(8) == 0 { rng.byte() } else { 0 };
            let p2 = if rng.below(8) == 0 { rng.byte() } else { 0 };
            let data = match ins {
                0xA4 if rng.below(2) == 0 => AID.to_vec(),
                _ => random_config(rng),
            };
            let mut cmd = Command::new(cla, ins, p1, p2).with_data(data);
            if rng.below(3) == 0 {
                cmd = cmd.with_le(u32::from(rng.byte()));
            }
            cmd.extended = rng.below(4) == 0;
            let mut bytes = cmd.to_bytes();
            if rng.below(10) == 0 {
                let cut = rng.below(bytes.len() + 1);
                bytes.truncate(cut);
            }
            bytes
        }
    }
}

fn check_invariants(m: &Management, host: &TestHost) {
    let info = m.device_info(host);
    let items = tlv::parse_all(&info).expect("device info always parses");
    let enabled = tlv::find(&items, tag::USB_ENABLED).expect("enabled reported");
    let supported = tlv::find(&items, tag::USB_SUPPORTED).expect("supported reported");
    let e = u16::from_be_bytes(enabled.value.try_into().expect("2 bytes"));
    let s = u16::from_be_bytes(supported.value.try_into().expect("2 bytes"));
    assert_ne!(e, 0);
    assert_eq!(e & !s, 0);
    // The three read forms agree: bare TLVs (lk-otp bridge), len || TLVs (CCID,
    // CTAPHID) and the two pages holding the whole DeviceInfo (docs/MEASUREMENT.md,
    // probe `mgmt-read-config`: page 0 ends with MORE_DATA, page 1 is the last).
    let page0 = m.device_info_page(0, host).expect("page 0");
    let page1 = m.device_info_page(1, host).expect("page 1");
    assert!(page0.ends_with(&[0x10, 0x01, 0x01]));
    let mut merged = page0[..page0.len() - 3].to_vec();
    merged.extend_from_slice(&page1);
    assert_eq!(merged, info);
    for (p, page) in [(0u8, &page0), (1, &page1)] {
        let encoded = m.read_config(p, host).expect("page");
        assert_eq!(
            encoded.split_first(),
            Some((&(page.len() as u8), &page[..]))
        );
    }
    assert_eq!(m.device_info_page(2, host), None);
}

/// How often the deep paths were reached, so the test proves it covers them.
#[derive(Debug, Default, PartialEq, Eq)]
struct Coverage {
    ccid_write_ok: usize,
    locked: usize,
    reboot: usize,
    storage_failure: usize,
}

/// Run `steps` random operations and return every response, for the determinism check.
fn session(seed: u64, steps: usize) -> (Vec<Vec<u8>>, Coverage) {
    let mut cov = Coverage::default();
    let mut rng = Rng::new(seed);
    let mut host = TestHost::new().seeded(seed);
    let mut applet = MgmtApplet::new(None, &mut host);
    let mut transcript = Vec::with_capacity(steps);
    for step in 0..steps {
        if step % 200 == 0 {
            // Start over now and then so a random lock code does not end coverage.
            applet = MgmtApplet::new(None, &mut host);
        }
        if rng.below(25) == 0 {
            host.fail_next_saves(1);
        }
        let resp = match rng.below(10) {
            0 => {
                let cmd = rng.pick(&[0x40u8, 0x42, 0x43, 0xC2, 0xC3, 0x10, 0x7F]);
                let payload = if rng.below(2) == 0 {
                    random_config(&mut rng)
                } else {
                    let n = rng.below(80);
                    rng.bytes(n)
                };
                match applet
                    .management_mut()
                    .ctaphid_vendor(cmd, &payload, &mut host)
                {
                    Some(reply) => {
                        assert!(!reply.payload.is_empty() || reply.cmd != 0x3F);
                        if reply.effect == lk_mgmt::ConfigEffect::Reboot {
                            cov.reboot += 1;
                        }
                        [vec![reply.cmd], reply.payload].concat()
                    }
                    None => vec![],
                }
            }
            1 => {
                let mut slot = random_config(&mut rng);
                slot.resize(64, 0);
                if rng.below(4) == 0 {
                    slot = rng.bytes(64);
                }
                match applet.management_mut().otp_write_config(&slot, &mut host) {
                    Ok(effect) => {
                        if effect == lk_mgmt::ConfigEffect::Reboot {
                            cov.reboot += 1;
                        }
                        vec![0x90, 0x00]
                    }
                    Err(s) => s.to_be_bytes().to_vec(),
                }
            }
            2 => {
                let n = rng.below(65);
                let slot = rng.bytes(n);
                match rng.below(3) {
                    0 => applet
                        .management()
                        .device_info_page(slot.first().copied().unwrap_or(0), &host)
                        .unwrap_or_default(),
                    1 => {
                        // Legacy SET MODE never changes anything.
                        let before = applet.management().to_record();
                        let r = applet.management_mut().legacy_set_mode(&slot, &mut host);
                        assert_eq!(r, Err(sw::INS_NOT_SUPPORTED));
                        assert_eq!(applet.management().to_record(), before);
                        sw::INS_NOT_SUPPORTED.to_be_bytes().to_vec()
                    }
                    _ => match applet.management().otp_read_config_frame(&slot, &host) {
                        Ok(frame) => frame,
                        Err(s) => s.to_be_bytes().to_vec(),
                    },
                }
            }
            3 => {
                match rng.below(3) {
                    0 => applet.deselect(),
                    1 => applet.reset(ResetKind::PowerCycle),
                    _ => {}
                }
                let apdu = random_apdu(&mut rng);
                applet.select(&apdu, &mut host)
            }
            _ => {
                let apdu = random_apdu(&mut rng);
                match applet.process(&apdu, &mut host) {
                    Outcome::Done(resp) => {
                        let (_, status) = split_response(&resp).expect("status word present");
                        assert_ne!(status, 0);
                        let ins = apdu.get(1).copied();
                        if status == sw::OK && ins == Some(0x1C) && apdu.first() == Some(&0x00) {
                            cov.ccid_write_ok += 1;
                        }
                        if status == sw::MEMORY_FAILURE {
                            cov.storage_failure += 1;
                        }
                        if applet.take_effect() == lk_mgmt::ConfigEffect::Reboot {
                            cov.reboot += 1;
                        }
                        resp
                    }
                    Outcome::NeedTouch { .. } => panic!("management never needs touch"),
                }
            }
        };
        check_invariants(applet.management(), &host);
        if applet.management().is_locked() {
            cov.locked += 1;
        }
        transcript.push(resp);
    }
    // The applet restores from whatever it last persisted.
    let restored = Management::new(host.persisted(Record::Device).as_deref(), &mut host);
    check_invariants(&restored, &host);
    (transcript, cov)
}

#[test]
fn random_inputs_never_panic() {
    for seed in [1u64, 2, 3] {
        let (transcript, cov) = session(seed, 3000);
        // Some random writes must have succeeded and some must have failed.
        assert!(transcript.iter().any(|r| r == &[0x90, 0x00]));
        assert!(
            transcript
                .iter()
                .any(|r| r.ends_with(&sw::INCORRECT_DATA.to_be_bytes()))
        );
        assert!(cov.ccid_write_ok > 0, "{cov:?}");
        assert!(cov.locked > 0, "{cov:?}");
        assert!(cov.reboot > 0, "{cov:?}");
        assert!(cov.storage_failure > 0, "{cov:?}");
        eprintln!("seed {seed}: {cov:?}");
    }
}

#[test]
fn random_sessions_are_deterministic() {
    assert_eq!(session(42, 500), session(42, 500));
}

#[test]
fn random_stored_records_never_panic() {
    let mut rng = Rng::new(7);
    let mut host = TestHost::new();
    for _ in 0..3000 {
        let stored = match rng.below(3) {
            0 => {
                let n = rng.below(64);
                rng.bytes(n)
            }
            _ => [vec![0x01], random_tlvs(&mut rng)].concat(),
        };
        let mut m = Management::new(Some(&stored), &mut host);
        check_invariants(&m, &host);
        // A restored device must still parse its own record back identically.
        let record = m.to_record();
        assert_eq!(
            Management::new(Some(&record), &mut host).to_record(),
            record
        );
        let _ = m.write_config(&random_config(&mut rng), &mut host);
        check_invariants(&m, &host);
    }
}
