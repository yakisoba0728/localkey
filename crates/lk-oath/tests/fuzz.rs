//! Fixed-seed pseudo-random malformed input tests (`docs/DESIGN.md` §12-4: deterministic
//! random inputs from `lk_testkit` instead of cargo-fuzz). They assert that no APDU
//! sequence, touch decision, reset or stored record makes the applet panic, and that
//! every answer is a well-formed ISO/IEC 7816-4 response (`data || SW1 SW2`).

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use lk_core::{CardApplet, Entropy, Outcome, Record, ResetKind};
use lk_oath::Oath;
use lk_testkit::{SeededEntropy, TestHost};

struct Rng(SeededEntropy);

impl Rng {
    fn byte(&mut self) -> u8 {
        let mut b = [0u8; 1];
        self.0.fill(&mut b);
        b[0]
    }

    fn below(&mut self, n: usize) -> usize {
        let mut b = [0u8; 2];
        self.0.fill(&mut b);
        usize::from(u16::from_be_bytes(b)) % n.max(1)
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        self.0.bytes(n)
    }
}

/// A plausible-looking but often broken YKOATH data field.
fn random_body(rng: &mut Rng) -> Vec<u8> {
    const TAGS: [u8; 14] = [0x71, 0x71, 0x73, 0x74, 0x74, 0x75, 0x78, 0x7A, 0x7B, 0x7C, 0x72, 0x7F, 0x00, 0xFF];
    let mut body = Vec::new();
    for _ in 0..rng.below(5) {
        let tag = rng.pick(&TAGS);
        body.push(tag);
        if tag == 0x78 {
            body.push(rng.pick(&[0x00, 0x01, 0x02, 0x03, 0x04, 0xFF]));
            continue;
        }
        let len = match rng.below(6) {
            0 => 0,
            1 => 8,
            2 => 20,
            3 => rng.below(70),
            4 => rng.below(140),
            _ => rng.below(4),
        };
        let mut value = rng.bytes(len);
        if tag == 0x73 && !value.is_empty() {
            value[0] = rng.pick(&[0x11, 0x12, 0x13, 0x21, 0x22, 0x23, 0x00, 0x31, 0x24]);
            if let Some(d) = value.get_mut(1) {
                *d = rng.pick(&[5, 6, 7, 8, 9, 0]);
            }
        }
        match rng.below(10) {
            // Wrong length byte.
            0 => body.push(len.wrapping_add(rng.below(3) + 1) as u8),
            // Long-form or invalid length forms.
            1 => body.extend_from_slice(&[0x81, len as u8]),
            2 => body.push(rng.pick(&[0x80, 0x84, 0xFF, 0x82])),
            _ => body.extend_from_slice(&lk_codec::tlv::encode_len(len)),
        }
        body.extend_from_slice(&value);
    }
    if rng.below(8) == 0 {
        body.truncate(rng.below(body.len() + 1));
    }
    body
}

/// A well-formed command, mutated now and then.
fn valid_apdu(rng: &mut Rng) -> Vec<u8> {
    const NAMES: [&[u8]; 6] = [b"hotp", b"totp", b"touch", &[0xFF, 0x00], b"new", b""];
    let name = rng.pick(&NAMES);
    let truncated = rng.below(2) == 0;
    let mut apdu = match rng.below(12) {
        0 | 1 => vec![0x00, 0xA1, 0x00, 0x00],
        2 | 3 => {
            let len = rng.below(10);
            calculate_all_apdu(&rng.bytes(len), truncated)
        }
        4 | 5 => {
            let challenge = (rng.below(40) as u64).to_be_bytes();
            calculate_apdu(name, &challenge, truncated)
        }
        6 => {
            let type_alg = rng.pick(&[0x11, 0x12, 0x13, 0x21, 0x22, 0x23]);
            let digits = rng.pick(&[6, 7, 8]);
            let len = 14 + rng.below(140);
            let secret = rng.bytes(len);
            let props = rng.pick(&[None, Some(0), Some(1), Some(2), Some(3)]);
            let imf = (type_alg & 0xF0 == 0x10 && rng.below(2) == 0).then(|| u32::MAX - rng.below(3) as u32);
            let mut name = name.to_vec();
            name.push(rng.byte() % 80);
            apdu(0x00, 0x01, 0x00, 0x00, &put_data(&name, type_alg, digits, &secret, props, imf))
        }
        7 => rename_apdu(name, rng.pick(&NAMES)),
        8 => delete_apdu(name),
        9 => SEND_REMAINING.to_vec(),
        10 => match rng.below(8) {
            0 => {
                let key = rng.bytes(16);
                let mut challenge = [0u8; 8];
                challenge.copy_from_slice(&rng.bytes(8));
                set_code_apdu(&key, &challenge)
            }
            1 => vec![0x00, 0x04, 0xDE, 0xAD],
            2 => apdu(0x00, 0x03, 0x00, 0x00, &tlv(0x73, &[])),
            _ => validate_apdu(&rng.bytes(20), &rng.bytes(8)),
        },
        _ => {
            let mut cmd = vec![0x00, 0xA1, 0x00, 0x00];
            cmd.push(rng.byte());
            cmd
        }
    };
    if rng.below(5) == 0 && !apdu.is_empty() {
        let i = rng.below(apdu.len());
        apdu[i] = rng.byte();
    }
    apdu
}

fn random_apdu(rng: &mut Rng) -> Vec<u8> {
    const INS: [u8; 15] = [0x01, 0x02, 0x03, 0x04, 0x05, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA5, 0xC0, 0xA4, 0x00, 0xFF];
    match rng.below(10) {
        // Mostly-valid commands.
        2..=5 => valid_apdu(rng),
        // Raw noise.
        0 => {
            let len = rng.below(300);
            rng.bytes(len)
        }
        // Header-only and Le-only forms.
        1 => {
            let mut apdu = vec![rng.pick(&[0x00, 0x10, 0x80]), rng.pick(&INS), rng.byte(), rng.byte()];
            match rng.below(3) {
                0 => {}
                1 => apdu.push(rng.byte()),
                _ => apdu.extend_from_slice(&[0x00, rng.byte(), rng.byte()]),
            }
            apdu
        }
        // Structured commands with random bodies, short or extended.
        _ => {
            let cla = rng.pick(&[0x00, 0x00, 0x00, 0x00, 0x10, 0x0C, 0x80, 0x01, 0x84]);
            let ins = rng.pick(&INS);
            let (p1, p2) = match rng.below(6) {
                0 => (rng.byte(), rng.byte()),
                1 => (0xDE, 0xAD),
                2 => (0x00, 0x01),
                _ => (0x00, 0x00),
            };
            let body = random_body(rng);
            let mut apdu = vec![cla, ins, p1, p2];
            let extended = body.len() > 255 || rng.below(6) == 0;
            if !body.is_empty() {
                if extended {
                    apdu.push(0);
                    apdu.extend_from_slice(&(body.len() as u16).to_be_bytes());
                } else {
                    apdu.push(body.len() as u8);
                }
                apdu.extend_from_slice(&body);
            }
            match rng.below(4) {
                0 if extended => apdu.extend_from_slice(&[rng.byte(), rng.byte()]),
                0 => apdu.push(rng.byte()),
                // Corrupt the length or the data.
                1 if apdu.len() > 4 => {
                    let i = 4 + rng.below(apdu.len() - 4);
                    apdu[i] = rng.byte();
                }
                _ => {}
            }
            apdu
        }
    }
}

fn assert_response(resp: &[u8]) {
    assert!(resp.len() >= 2, "response without a status word");
    let sw1 = resp[resp.len() - 2];
    assert!(sw1 == 0x90 || (0x61..=0x6F).contains(&sw1), "bad SW1 {sw1:02X}");
    if sw1 != 0x90 && sw1 != 0x61 {
        assert_eq!(resp.len(), 2, "error responses carry no data");
    }
}

/// The device-specific part of a SELECT response (YKOATH §SELECT): the salt `71`, and
/// the algorithm `7B` when an access key is set. The challenge `74` changes on every
/// SELECT, so only its presence counts.
fn select_view(resp: &[u8]) -> (Vec<u8>, Option<Vec<u8>>, bool) {
    let (data, sw) = split(resp);
    assert_eq!(sw, OK);
    let fields = parse_tlvs(data);
    (field(&fields, 0x71).unwrap(), field(&fields, 0x7B), field(&fields, 0x74).is_some())
}

fn seed_credentials(card: &mut Card) {
    card.put(&put_data(b"hotp", HOTP | SHA1, 6, RFC_SECRET, None, Some(3)));
    card.put(&put_data(b"totp", TOTP | SHA256, 8, &[1; 32], Some(0x01), None));
    card.put(&put_data(b"touch", TOTP | SHA512, 7, &[2; 64], Some(0x02), None));
    card.put(&put_data(&[0xFF, 0x00], HOTP | SHA512, 8, &[3; 20], Some(0x03), None));
}

/// 30 000 random commands interleaved with SELECT, deselect, resets, restarts, touch
/// decisions and storage failures. No panic, and every response is well formed.
#[test]
fn random_apdus_never_panic() {
    let mut rng = Rng(SeededEntropy::new(0x0A7B_5EED));
    let mut card = Card::with_host(TestHost::new().seeded(7));
    seed_credentials(&mut card);
    // How often each kind of answer came back, to show the inputs reach deep paths.
    let (mut data_answers, mut touches, mut statuses) = (0u32, 0u32, std::collections::BTreeSet::new());
    let mut checked_restores = 0u32;
    for round in 0..30_000u32 {
        match rng.below(40) {
            0 => assert_response(&card.select()),
            1 => card.oath.deselect(),
            2 => card.oath.reset(rng.pick(&[ResetKind::CardPowerOff, ResetKind::UsbReset, ResetKind::PowerCycle])),
            3 => card.restart(),
            4 => card.host.fail_next_saves(rng.below(3)),
            5 if round % 7 == 0 => seed_credentials(&mut card),
            6 => {
                // Something that looks like a real flow: a SELECT with an odd APDU.
                let len = rng.below(20);
                let apdu = rng.bytes(len);
                assert_response(&card.oath.select(&apdu, &mut card.host));
            }
            _ => {}
        }
        let apdu = random_apdu(&mut rng);
        let resp = match card.oath.process(&apdu, &mut card.host) {
            Outcome::Done(resp) => resp,
            Outcome::NeedTouch { timeout_ms } => {
                assert_eq!(timeout_ms, lk_oath::TOUCH_TIMEOUT_MS);
                touches += 1;
                let touched = rng.below(2) == 0;
                card.touch(touched)
            }
        };
        assert_response(&resp);
        statuses.insert(u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]));
        if resp.len() > 2 {
            data_answers += 1;
        }
        // A stray touch resolution must be harmless too.
        if rng.below(50) == 0 {
            assert_response(&card.touch(true));
        }
        // Whatever was persisted restores (`docs/CONTRACTS.md` "Persisted state"): a
        // fresh instance built from the record reports the live salt and the same
        // access-key status in SELECT. An unreadable record would come back as factory
        // state with a new random salt.
        if let Some(record) = card.host.persisted(Record::Oath).filter(|_| round % 250 == 0) {
            let live = select_view(&card.select());
            let mut other = TestHost::new().seeded(u64::from(round));
            let mut restored = Oath::new(Some(&record), &mut other);
            assert_eq!(select_view(&restored.select(&SELECT, &mut other)), live, "round {round}");
            checked_restores += 1;
        }
    }
    assert!(checked_restores > 50, "only {checked_restores} restore checks");
    assert!(data_answers > 100, "only {data_answers} answers with data");
    assert!(touches > 10, "only {touches} touch requests");
    for sw in [0x9000, 0x6A80, 0x6A86, 0x6984, 0x6982, 0x6E00, 0x6882, 0x6881, 0x6D00, 0x6700, 0x6581, 0x6883] {
        assert!(statuses.contains(&sw), "status {sw:04X} never seen");
    }
    // The applet still works afterwards.
    card.restart();
    assert_response(&card.select());
}

/// Random and mutated stored records: `Oath::new` never panics, and whatever it
/// restores answers SELECT, LIST and CALCULATE ALL.
#[test]
fn random_stored_state_never_panics() {
    let mut rng = Rng(SeededEntropy::new(0x5707_ED00));
    let mut card = Card::new();
    seed_credentials(&mut card);
    lock_with(&mut card, &[0x42; 16]);
    let good = card.host.persisted(Record::Oath).unwrap();
    for _ in 0..3_000 {
        let record = match rng.below(3) {
            0 => {
                let len = rng.below(200);
                let mut r = rng.bytes(len);
                if let Some(v) = r.first_mut() {
                    *v = 0x01;
                }
                r
            }
            1 => {
                let mut r = good.clone();
                for _ in 0..=rng.below(4) {
                    let i = rng.below(r.len());
                    r[i] = rng.byte();
                }
                r
            }
            _ => {
                let mut r = good.clone();
                r.truncate(rng.below(good.len() + 1));
                r
            }
        };
        let mut host = TestHost::new();
        let mut oath = Oath::new(Some(&record), &mut host);
        assert_response(&oath.select(&SELECT, &mut host));
        for apdu in [&[0x00, 0xA1, 0x00, 0x00][..], &calculate_all_apdu(&[0; 8], true), &calculate_apdu(b"hotp", &[], true)] {
            match oath.process(apdu, &mut host) {
                Outcome::Done(resp) => assert_response(&resp),
                Outcome::NeedTouch { .. } => assert_response(&oath.touch_resolved(true, &mut host)),
            }
        }
    }
}

fn lock_with(card: &mut Card, key: &[u8; 16]) {
    assert_eq!(card.sw(&set_code_apdu(key, &[9; 8])), OK);
}
