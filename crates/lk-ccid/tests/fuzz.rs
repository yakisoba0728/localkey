//! Fixed-seed fuzzing of the CCID slot. Random, mostly well-formed bulk-out messages
//! (USB CCID Rev 1.1 §6.1) are interleaved with card answers, control-pipe ABORT
//! requests (§5.3.1), time extensions (§6.2.6) and USB resets.
//!
//! Nothing may panic. Every bulk-in message must keep the framing of §6.2 and the
//! `bStatus` encoding of §6.2.6. Chained commands and responses (§6.1.4, §6.2.1) must
//! reassemble to exactly the bytes that were split, and the slot must always recover
//! after a reset.

mod common;

use common::{ATR, ATR_PARAMS, CLOCK_AND_RATE, MAX_DATA};
use lk_ccid::{Ccid, CcidAction};

/// SplitMix64 (Steele, Lea and Flood, "Fast Splittable Pseudorandom Number
/// Generators", OOPSLA 2014). A fixed seed replays the same run every time.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).expect("n fits u64")).expect("< n")
    }

    fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }
}

/// The bulk-out message types of §6.1.1–§6.1.14.
const TYPES: [u8; 14] = [
    0x62, 0x63, 0x65, 0x6F, 0x6C, 0x6D, 0x61, 0x6B, 0x6E, 0x6A, 0x69, 0x71, 0x72, 0x73,
];

/// The reply type §6.1 pairs with each command; anything else is answered with
/// RDR_to_PC_SlotStatus.
fn paired_reply(command: u8) -> u8 {
    match command {
        0x62 | 0x6F | 0x69 => 0x80,
        0x61 | 0x6C | 0x6D => 0x82,
        0x6B => 0x83,
        0x73 => 0x84,
        _ => 0x81,
    }
}

/// wLevelParameter values at extended APDU level (§6.1.4).
const LEVELS: [u16; 5] = [0x0000, 0x0001, 0x0002, 0x0003, 0x0010];

/// One random bulk-out message with bSeq `seq`; mostly well-formed for slot 0.
fn random_message(rng: &mut Rng, seq: u8) -> Vec<u8> {
    let msg_type = if rng.chance(4) {
        rng.byte()
    } else if rng.chance(45) {
        0x6F
    } else {
        rng.pick(&TYPES)
    };
    let slot = if rng.chance(96) { 0 } else { rng.byte() };
    let rfu = |rng: &mut Rng| if rng.chance(95) { 0 } else { rng.byte() };
    let (specific, data) = match msg_type {
        0x6F => {
            let level = if rng.chance(95) {
                rng.pick(&LEVELS)
            } else {
                u16::from_le_bytes([rng.byte(), rng.byte()])
            };
            let len = if level == 0x0010 && rng.chance(90) {
                0
            } else {
                match rng.below(10) {
                    0 => 0,
                    1 => MAX_DATA,
                    2 => MAX_DATA + 1,
                    3 => rng.below(MAX_DATA + 40),
                    4..=6 => 4 + rng.below(300),
                    _ => 1 + rng.below(12),
                }
            };
            let [lo, hi] = level.to_le_bytes();
            ([rfu(rng), lo, hi], rng.bytes(len))
        }
        0x62 => {
            let select = if rng.chance(90) {
                rng.pick(&[0, 1, 2, 3])
            } else {
                rng.byte()
            };
            ([select, 0, 0], Vec::new())
        }
        0x61 => {
            let protocol = if rng.chance(85) { 1 } else { rng.byte() };
            let mut block = ATR_PARAMS.to_vec();
            if rng.chance(50) {
                let i = rng.below(block.len());
                block[i] = rng.byte();
            }
            if rng.chance(10) {
                block.truncate(rng.below(9));
            }
            ([protocol, 0, 0], block)
        }
        0x73 => {
            let mut values = CLOCK_AND_RATE.to_vec();
            if rng.chance(30) {
                let i = rng.below(values.len());
                values[i] = rng.byte();
            }
            if rng.chance(10) {
                values.truncate(rng.below(10));
            }
            ([0; 3], values)
        }
        _ => {
            let len = if rng.chance(85) { 0 } else { rng.below(6) };
            ([rfu(rng), rfu(rng), rfu(rng)], rng.bytes(len))
        }
    };
    let mut length = u32::try_from(data.len()).expect("small");
    if rng.chance(3) {
        length = match rng.below(3) {
            0 => length.wrapping_add(1),
            1 => length.wrapping_sub(1),
            _ => u32::from_le_bytes([rng.byte(), rng.byte(), rng.byte(), rng.byte()]),
        };
    }
    let mut msg = vec![msg_type];
    msg.extend_from_slice(&length.to_le_bytes());
    msg.extend_from_slice(&[slot, seq]);
    msg.extend_from_slice(&specific);
    msg.extend_from_slice(&data);
    if rng.chance(2) {
        msg.truncate(rng.below(10));
    }
    msg
}

/// Check the framing and status rules every bulk-in message obeys (§6.2, §6.2.6).
fn check_bulk_in(bytes: &[u8], context: &str) {
    assert!(bytes.len() >= 10, "{context}: short reply {bytes:02x?}");
    assert!(
        bytes.len() <= 3072,
        "{context}: exceeds dwMaxCCIDMessageLength"
    );
    let length = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
    assert_eq!(
        usize::try_from(length).expect("u32"),
        bytes.len() - 10,
        "{context}: dwLength"
    );
    let (kind, status, error, byte9) = (bytes[0], bytes[7], bytes[8], bytes[9]);
    assert!((0x80..=0x84).contains(&kind), "{context}: type {kind:#04x}");
    assert_eq!(
        status & 0x3C,
        0,
        "{context}: bmRFU bits set in {status:#04x}"
    );
    assert_ne!(status & 0x03, 0x03, "{context}: bmICCStatus 3 is RFU");
    assert_ne!(status >> 6, 0x03, "{context}: bmCommandStatus 3 is RFU");
    if status >> 6 == 0 {
        assert_eq!(error, 0, "{context}: bError set on success");
    }
    let data = &bytes[10..];
    match kind {
        0x81 => assert!(data.is_empty(), "{context}: SlotStatus with data"),
        0x82 if bytes[5] == 0 => {
            assert_eq!(byte9, 0x01, "{context}: bProtocolNum");
            assert_eq!(data.len(), 7, "{context}: T=1 structure");
        }
        0x84 => assert_eq!(data.len(), 8, "{context}: §6.2.5 dwLength 8"),
        0x80 if status >> 6 != 0 => {
            assert!(data.is_empty(), "{context}: failed DataBlock with data");
        }
        _ => {}
    }
}

/// The two-step abort of §5.3.1 as the host sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AbortModel {
    Idle,
    /// A control ABORT with this bSeq was sent; only the matching bulk Abort passes.
    Awaiting(u8),
    /// A bulk Abort with this bSeq completed without a control ABORT; a control
    /// ABORT with the same bSeq is taken as its late partner and changes nothing.
    BulkFirst(u8),
}

/// A response APDU being fetched in parts: the whole response and how much of it
/// the host has received.
struct ResponseInFlight {
    response: Vec<u8>,
    received: usize,
}

/// How often the run reached each interesting state, so that a passing run is known
/// to have exercised it.
#[derive(Debug, Default)]
struct Coverage {
    chained_apdus: usize,
    single_apdus: usize,
    response_ends: usize,
    response_middles: usize,
    control_aborts_answered: usize,
    aborted_replies: usize,
    late_control_aborts: usize,
    busy_replies: usize,
    power_offs: usize,
    warm_resets: usize,
    inactive_xfr: usize,
    wrong_slot: usize,
    length_errors: usize,
    level_errors: usize,
}

/// The harness state: what the host has sent and received so far.
struct Harness {
    ccid: Ccid,
    rng: Rng,
    seq: u8,
    /// Command parts acknowledged with bChainParameter 10 since the last 0001.
    command: Option<Vec<u8>>,
    response: Option<ResponseInFlight>,
    /// A bulk Abort the host sends next, after a control ABORT.
    queued_abort: Option<u8>,
    abort: AbortModel,
    seen: Coverage,
}

impl Harness {
    fn new(seed: u64) -> Self {
        Self {
            ccid: Ccid::new(ATR.to_vec()),
            rng: Rng(seed),
            seq: 0,
            command: None,
            response: None,
            queued_abort: None,
            abort: AbortModel::Idle,
            seen: Coverage::default(),
        }
    }

    fn next_seq(&mut self) -> u8 {
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }

    fn step(&mut self, step: usize) {
        let context = format!("step {step}");
        match self.rng.below(100) {
            0..=59 => {
                let seq = self.next_seq();
                let msg = match self.queued_abort.take() {
                    Some(abort_seq) => vec![0x72, 0, 0, 0, 0, 0, abort_seq, 0, 0, 0],
                    None if !self.ccid.is_active() && self.rng.chance(30) => {
                        vec![0x62, 0, 0, 0, 0, 0, seq, 0, 0, 0]
                    }
                    None => random_message(&mut self.rng, seq),
                };
                self.message(&msg, &context);
            }
            60..=84 => self.answer(&context),
            85..=91 => self.control_abort(&context),
            92..=97 => {
                let seq = self.ccid.pending_seq().unwrap_or_else(|| self.rng.byte());
                let wtx = self.ccid.time_extension(seq);
                check_bulk_in(&wtx, &context);
                assert_eq!((wtx[0], wtx[6], wtx[7], wtx[8]), (0x80, seq, 0x80, 0x01));
            }
            98 => {
                let present = self.rng.chance(50);
                assert_eq!(
                    self.ccid.slot_change(present),
                    [0x50, 0x02 | u8::from(present)]
                );
            }
            _ => {
                self.ccid.reset();
                self.forget_chains();
                self.queued_abort = None;
                self.abort = AbortModel::Idle;
                assert!(!self.ccid.is_active(), "{context}: active after reset");
                assert_eq!(self.ccid.pending_seq(), None, "{context}");
            }
        }
    }

    fn forget_chains(&mut self) {
        self.command = None;
        self.response = None;
    }

    fn message(&mut self, msg: &[u8], context: &str) {
        let was_active = self.ccid.is_active();
        let was_pending = self.ccid.pending_seq();
        let action = self.ccid.message(msg);
        let context = format!("{context} msg {:02x?}", &msg[..msg.len().min(10)]);
        let level = msg
            .get(8..10)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .unwrap_or(0);
        let data = msg.get(10..).unwrap_or_default();
        match action {
            CcidAction::Reply(r) | CcidAction::PowerOff(r) if msg.len() < 10 => {
                check_bulk_in(&r, &context);
                assert_eq!(r[8], 0x01, "{context}: truncated message is a length error");
                assert_eq!(self.ccid.is_active(), was_active, "{context}");
                assert_eq!(self.ccid.pending_seq(), was_pending, "{context}");
            }
            CcidAction::Reply(r) => {
                self.check_reply(&r, msg, &context);
                self.count_reply(&r, msg);
                if r[5] == 0 && r[0] == 0x80 && r[7] == 0x00 && msg[0] == 0x6F {
                    self.track_xfr_reply(&r, level, data, &context);
                }
                if msg[0] == 0x72 && r[5] == 0 && r[7] >> 6 == 0 {
                    // A completed Abort leaves the slot idle and accepting messages.
                    self.abort = match self.abort {
                        AbortModel::Awaiting(seq) => {
                            assert_eq!(seq, msg[6], "{context}: unmatched Abort passed");
                            AbortModel::Idle
                        }
                        AbortModel::Idle | AbortModel::BulkFirst(_) => {
                            AbortModel::BulkFirst(msg[6])
                        }
                    };
                    self.forget_chains();
                    let seq = self.next_seq();
                    let status = self.ccid.message(&[0x65, 0, 0, 0, 0, 0, seq, 0, 0, 0]);
                    let CcidAction::Reply(status) = status else {
                        panic!("{context}: GetSlotStatus answered with {status:?}");
                    };
                    assert_eq!(status[7] >> 6, 0, "{context}: slot unusable after Abort");
                }
            }
            CcidAction::PowerOff(r) => {
                self.check_reply(&r, msg, &context);
                assert_eq!(r[7] >> 6, 0, "{context}: PowerOff for a failed command");
                match msg[0] {
                    0x63 => {
                        assert!(!self.ccid.is_active(), "{context}");
                        self.seen.power_offs += 1;
                    }
                    0x62 => {
                        assert!(was_active && self.ccid.is_active(), "{context}");
                        self.seen.warm_resets += 1;
                    }
                    other => panic!("{context}: PowerOff for {other:#04x}"),
                }
                assert_eq!(was_pending, None, "{context}: busy slot powered off");
                self.forget_chains();
            }
            CcidAction::Apdu { seq, apdu } => {
                assert_eq!((msg[0], msg[5]), (0x6F, 0), "{context}: Apdu source");
                assert_eq!(seq, msg[6], "{context}: Apdu bSeq");
                assert!(was_active, "{context}: APDU to an inactive ICC");
                assert_eq!(was_pending, None, "{context}: APDU while busy");
                assert!(!apdu.is_empty() && apdu.len() <= 65_544, "{context}");
                assert_eq!(self.ccid.pending_seq(), Some(seq), "{context}");
                match level {
                    0x0000 => {
                        assert_eq!(apdu, data, "{context}: single-part APDU");
                        self.seen.single_apdus += 1;
                    }
                    0x0002 => {
                        if let Some(mut parts) = self.command.take() {
                            parts.extend_from_slice(data);
                            assert_eq!(apdu, parts, "{context}: chained APDU");
                            self.seen.chained_apdus += 1;
                        }
                    }
                    other => panic!("{context}: APDU from wLevelParameter {other:#06x}"),
                }
                self.command = None;
            }
        }
    }

    fn count_reply(&mut self, r: &[u8], msg: &[u8]) {
        if r[7] >> 6 != 1 {
            return;
        }
        let seen = &mut self.seen;
        match (r[7] & 0x03, r[8]) {
            (2, 0x05) => seen.wrong_slot += 1,
            (_, 0xFF) => seen.aborted_replies += 1,
            (_, 0xE0) => seen.busy_replies += 1,
            (1, 0xFE) if msg[0] == 0x6F => seen.inactive_xfr += 1,
            (_, 0x01) => seen.length_errors += 1,
            (_, 0x08) if msg[0] == 0x6F => seen.level_errors += 1,
            _ => {}
        }
    }

    /// Rules for a reply to a message that has a complete header.
    fn check_reply(&self, r: &[u8], msg: &[u8], context: &str) {
        check_bulk_in(r, context);
        assert_eq!(r[0], paired_reply(msg[0]), "{context}: reply type");
        assert_eq!((r[5], r[6]), (msg[5], msg[6]), "{context}: bSlot/bSeq echo");
        assert_ne!(r[7] >> 6, 2, "{context}: time extension from message()");
        if msg[5] != 0 {
            assert_eq!((r[7], r[8]), (0x42, 0x05), "{context}: wrong slot");
            return;
        }
        let icc = if self.ccid.is_active() { 0 } else { 1 };
        assert_eq!(r[7] & 0x03, icc, "{context}: bmICCStatus");
        if r[7] >> 6 == 1 && !matches!(self.abort, AbortModel::Awaiting(_)) {
            assert_ne!(r[8], 0xFF, "{context}: CMD_ABORTED without a pending abort");
        }
        if let AbortModel::Awaiting(seq) = self.abort {
            // §5.3.1: between the control ABORT and its bulk Abort every message
            // fails with CMD_ABORTED; only a malformed length is reported first.
            let partner = msg[0] == 0x72 && msg[6] == seq;
            if !(partner && r[7] >> 6 == 0) {
                assert_eq!(r[7] >> 6, 1, "{context}: passed a pending abort");
                assert!(
                    r[8] == 0xFF || r[8] == 0x01,
                    "{context}: bError {:#04x} during a pending abort",
                    r[8]
                );
            }
        }
    }

    /// Follow the chaining state from a successful DataBlock answering an XfrBlock.
    fn track_xfr_reply(&mut self, r: &[u8], level: u16, data: &[u8], context: &str) {
        let part = &r[10..];
        match (level, r[9]) {
            (0x0001, 0x10) => self.command = Some(data.to_vec()),
            (0x0003, 0x10) => {
                if let Some(parts) = self.command.as_mut() {
                    parts.extend_from_slice(data);
                }
            }
            (0x0010, 0x02 | 0x03) => {
                let flight = self
                    .response
                    .as_mut()
                    .unwrap_or_else(|| panic!("{context}: response part without a response"));
                let end = flight.received + part.len();
                assert_eq!(
                    part,
                    &flight.response[flight.received..end],
                    "{context}: response part"
                );
                flight.received = end;
                if r[9] == 0x03 {
                    assert_eq!(part.len(), MAX_DATA, "{context}: middle part size");
                    self.seen.response_middles += 1;
                } else {
                    assert!(!part.is_empty(), "{context}: empty last part");
                    assert_eq!(end, flight.response.len(), "{context}: response complete");
                    self.response = None;
                    self.seen.response_ends += 1;
                }
            }
            other => panic!("{context}: unexpected successful XfrBlock reply {other:x?}"),
        }
    }

    /// The card answers the outstanding APDU, or a stale or wrong one.
    fn answer(&mut self, context: &str) {
        let pending = self.ccid.pending_seq();
        let seq = match pending {
            Some(seq) if self.rng.chance(85) => seq,
            _ => self.rng.byte(),
        };
        let len = match self.rng.below(12) {
            0 => MAX_DATA,
            1 => MAX_DATA + 1,
            2 => 2 * MAX_DATA,
            3 => 2 * MAX_DATA + 1,
            4 => 65_538,
            5 => self.rng.below(20_000),
            _ => 2 + self.rng.below(260),
        };
        let response = self.rng.bytes(len);
        let out = self.ccid.apdu_response(seq, &response);
        if pending != Some(seq) {
            assert!(
                out.is_empty(),
                "{context}: answer to a seq that is not pending"
            );
            assert_eq!(self.ccid.pending_seq(), pending, "{context}");
            return;
        }
        check_bulk_in(&out, context);
        assert_eq!(
            (out[0], out[5], out[6], out[7], out[8]),
            (0x80, 0, seq, 0, 0)
        );
        assert_eq!(self.ccid.pending_seq(), None, "{context}: still busy");
        if len <= MAX_DATA {
            assert_eq!((out[9], &out[10..]), (0x00, &response[..]), "{context}");
            self.response = None;
        } else {
            assert_eq!(
                (out[9], &out[10..]),
                (0x01, &response[..MAX_DATA]),
                "{context}"
            );
            self.response = Some(ResponseInFlight {
                response,
                received: MAX_DATA,
            });
        }
    }

    fn control_abort(&mut self, context: &str) {
        let slot = if self.rng.chance(90) {
            0
        } else {
            1 + self.rng.below(255)
        };
        let slot = u8::try_from(slot).expect("byte");
        let seq = match self.abort {
            // Reordered delivery: the control request of an answered bulk Abort.
            AbortModel::BulkFirst(seq) if self.rng.chance(40) => seq,
            _ => self.next_seq(),
        };
        let pending = self.ccid.pending_seq();
        let out = self.ccid.control_abort(slot, seq);
        if slot != 0 {
            assert_eq!(out, None, "{context}: abort of another slot");
            assert_eq!(self.ccid.pending_seq(), pending, "{context}");
            return;
        }
        if self.abort == AbortModel::BulkFirst(seq) {
            // The late partner of a bulk Abort that already completed.
            assert_eq!(out, None, "{context}: late control ABORT answered");
            assert_eq!(self.ccid.pending_seq(), pending, "{context}");
            self.abort = AbortModel::Idle;
            self.seen.late_control_aborts += 1;
            return;
        }
        match (out, pending) {
            (Some(r), Some(aborted)) => {
                check_bulk_in(&r, context);
                assert_eq!(r, [0x80, 0, 0, 0, 0, 0, aborted, 0x40, 0xFF, 0x00]);
                self.seen.control_aborts_answered += 1;
            }
            (None, None) => {}
            other => panic!("{context}: control ABORT gave {other:x?}"),
        }
        assert_eq!(
            self.ccid.pending_seq(),
            None,
            "{context}: abort left the slot busy"
        );
        self.abort = AbortModel::Awaiting(seq);
        self.forget_chains();
        if self.rng.chance(85) {
            self.queued_abort = Some(seq);
        }
    }

    /// After a reset the slot always comes back: IccPowerOn returns the ATR and an
    /// APDU reaches the card.
    fn recover(&mut self) {
        self.ccid.reset();
        let r = self.ccid.message(&[0x62, 0, 0, 0, 0, 0, 0x01, 0, 0, 0]);
        let mut expected = vec![0x80, 23, 0, 0, 0, 0, 0x01, 0, 0, 0];
        expected.extend_from_slice(&ATR);
        assert_eq!(r, CcidAction::Reply(expected));
        let apdu = [0x00, 0xA4, 0x04, 0x00];
        let mut msg = vec![0x6F, 4, 0, 0, 0, 0, 0x02, 0, 0, 0];
        msg.extend_from_slice(&apdu);
        assert_eq!(
            self.ccid.message(&msg),
            CcidAction::Apdu {
                seq: 0x02,
                apdu: apdu.to_vec()
            }
        );
    }
}

#[test]
fn random_traffic_never_panics_and_keeps_the_framing() {
    let mut total = Coverage::default();
    for seed in 0..24u64 {
        let mut harness = Harness::new(0x4C4B_4343_4944_0000 ^ seed);
        for step in 0..3000 {
            harness.step(step);
        }
        harness.recover();
        let c = &harness.seen;
        for (sum, n) in [
            (&mut total.chained_apdus, c.chained_apdus),
            (&mut total.single_apdus, c.single_apdus),
            (&mut total.response_ends, c.response_ends),
            (&mut total.response_middles, c.response_middles),
            (
                &mut total.control_aborts_answered,
                c.control_aborts_answered,
            ),
            (&mut total.aborted_replies, c.aborted_replies),
            (&mut total.late_control_aborts, c.late_control_aborts),
            (&mut total.busy_replies, c.busy_replies),
            (&mut total.power_offs, c.power_offs),
            (&mut total.warm_resets, c.warm_resets),
            (&mut total.inactive_xfr, c.inactive_xfr),
            (&mut total.wrong_slot, c.wrong_slot),
            (&mut total.length_errors, c.length_errors),
            (&mut total.level_errors, c.level_errors),
        ] {
            *sum += n;
        }
    }
    // Every state the invariants talk about was reached many times. The late
    // control ABORT needs a bSeq collision, so it is rarer.
    let c = &total;
    for (name, n, min) in [
        ("chained APDUs", c.chained_apdus, 20),
        ("single APDUs", c.single_apdus, 100),
        ("response ends", c.response_ends, 20),
        ("response middles", c.response_middles, 20),
        ("answered control ABORTs", c.control_aborts_answered, 20),
        ("CMD_ABORTED replies", c.aborted_replies, 20),
        ("late control ABORTs", c.late_control_aborts, 1),
        ("CMD_SLOT_BUSY replies", c.busy_replies, 100),
        ("IccPowerOff", c.power_offs, 100),
        ("warm IccPowerOn", c.warm_resets, 100),
        ("XfrBlock to an inactive ICC", c.inactive_xfr, 100),
        ("wrong slot", c.wrong_slot, 100),
        ("dwLength errors", c.length_errors, 100),
        ("wLevelParameter errors", c.level_errors, 100),
    ] {
        assert!(
            n >= min,
            "{name}: reached {n} times, expected at least {min}"
        );
    }
}

#[test]
fn arbitrary_bytes_never_panic() {
    // Unstructured input: any byte string, of any length up to beyond one message,
    // gets exactly one well-framed reply or a forwarded APDU.
    let mut rng = Rng(0x0BAD_C0DE);
    let mut ccid = Ccid::new(ATR.to_vec());
    for round in 0..20_000 {
        let len = match rng.below(4) {
            0 => rng.below(10),
            1 => 10 + rng.below(16),
            2 => rng.below(3100),
            _ => 10,
        };
        let mut msg = rng.bytes(len);
        if round % 3 == 0 && msg.len() >= 6 {
            msg[5] = 0;
        }
        match ccid.message(&msg) {
            CcidAction::Reply(r) | CcidAction::PowerOff(r) => {
                check_bulk_in(&r, &format!("round {round}"));
            }
            CcidAction::Apdu { seq, .. } => {
                assert_eq!(ccid.pending_seq(), Some(seq));
                let out = ccid.apdu_response(seq, &[0x90, 0x00]);
                check_bulk_in(&out, &format!("round {round}"));
            }
        }
        if round % 500 == 0 {
            ccid.message(&[0x62, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        }
    }
}
