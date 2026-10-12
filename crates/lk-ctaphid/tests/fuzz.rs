//! Fixed-seed pseudo-random fuzzing at the 64-byte report level.
//!
//! A deterministic generator drives the framer with a mix of plausible and hostile
//! traffic: random and allocated CIDs, every command code, boundary and random BCNT
//! values, continuation packets with right and wrong SEQ, complete messages with
//! foreign packets mixed in, time jumps, `tick`, `respond`, `keepalive` and `reset`.
//!
//! Every call is checked twice:
//!
//! 1. Structurally, without any model: every `Send` belongs to a complete message
//!    (an initialization packet then continuation packets SEQ 0, 1, ... on the same
//!    CID, BCNT at most 7609, and at most 1536 for what the framer itself sends; zero
//!    padding), nothing but ERR_INVALID_CHANNEL on the reserved CID 0, and
//!    device-generated commands carry the layouts of CTAP 2.1 §11.2.9 (ERROR with one
//!    known code, INIT with 17 bytes, WINK empty).
//! 2. Against a small host-side model of the rules this crate documents: CTAP 2.1
//!    §11.2.4 to §11.2.9, the `reference/BEHAVIOR_CATALOG.md` CTAPHID decisions, the
//!    behaviour measured on the reference key (`docs/MEASUREMENT.md`: requests of
//!    at most 1536 bytes, probe `ping-max`; LOCK is ERR_INVALID_CMD, probe `lock`;
//!    470 ms message timeout, probe `message-timeout`), and the check order and model
//!    policies stated in `src/framer.rs` (channel, busy, command, length; the timeout
//!    restarted per packet). An empty CBOR request is ERR_INVALID_LEN (§11.2.9.1.2); the
//!    reference device's stall on it (probe `empty-cbor`) is a defect not copied. The
//!    model predicts the exact events of every call, `outstanding()` and
//!    `next_deadline()`.
//!
//! The generator is SplitMix64 (Steele, Lea and Flood, "Fast Splittable Pseudorandom
//! Number Generators", OOPSLA 2014), so every run replays the same traffic; a failure
//! message names the seed and step.

mod common;

use std::collections::HashSet;

use common::*;
use lk_ctaphid::{Ctaphid, Event};

/// CTAP 2.1 §11.2.4: 57 data bytes in the initialization packet.
const INIT_DATA: usize = 57;
/// CTAP 2.1 §11.2.4: 59 data bytes in a continuation packet.
const CONT_DATA: usize = 59;
/// CTAP 2.1 §11.2.4: `64 - 7 + 128 * (64 - 5) = 7609`, the framing limit of responses.
const MAX_MESSAGE: usize = MAX_FRAMED;
/// CTAP 2.1 §11.2.9.1.6 error codes.
const ERROR_CODES: [u8; 9] = [
    ERR_INVALID_CMD,
    ERR_INVALID_PAR,
    ERR_INVALID_LEN,
    ERR_INVALID_SEQ,
    ERR_MSG_TIMEOUT,
    ERR_CHANNEL_BUSY,
    ERR_LOCK_REQUIRED,
    ERR_INVALID_CHANNEL,
    ERR_OTHER,
];
/// Lengths around the packet boundaries of CTAP 2.1 §11.2.4, the measured 1536-byte
/// request limit (docs/MEASUREMENT.md, probe ping-max) and the 7550/7551/7609 framing
/// boundaries, plus lengths no message can have.
const BOUNDARY_LENGTHS: [usize; 22] = [
    0, 1, 7, 8, 9, 17, 56, 57, 58, 59, 116, 117, 175, 1532, 1533, 1536, 1537, 7550, 7551, 7609,
    7610, 0xFFFF,
];
/// Command codes the generator favours: every CTAP 2.1 §11.2.9 command, a few vendor
/// codes, device-only codes and unassigned codes.
const COMMANDS: [u8; 19] = [
    PING, PING, PING, INIT, INIT, CBOR, CBOR, MSG, WINK, LOCK, CANCEL, 0x40, 0x42, 0x7F, KEEPALIVE,
    ERROR, 0x00, 0x05, 0x12,
];

/// SplitMix64 (Steele, Lea and Flood, OOPSLA 2014).
struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    fn percent(&mut self, p: usize) -> bool {
        self.below(100) < p
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }

    fn byte(&mut self) -> u8 {
        self.next_u64() as u8
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }
}

fn cid_of(report: &Report) -> u32 {
    u32::from_be_bytes([report[0], report[1], report[2], report[3]])
}

fn bcnt_of(report: &Report) -> usize {
    usize::from(u16::from_be_bytes([report[5], report[6]]))
}

fn packets_for(bcnt: usize) -> usize {
    if bcnt <= INIT_DATA {
        1
    } else {
        1 + (bcnt - INIT_DATA).div_ceil(CONT_DATA)
    }
}

/// Model-free check that every `Send` in `events` is part of a complete, well-formed
/// device message. With `framer_only`, the command must be one the framer itself
/// generates (CTAP 2.1 §11.2.9: PING, INIT, WINK echoes and ERROR), at most 1536 bytes.
fn assert_well_formed(events: &[Event], framer_only: bool, ctx: &str) {
    let mut i = 0;
    while i < events.len() {
        let Event::Send(first) = &events[i] else {
            i += 1;
            continue;
        };
        assert!(
            first[4] & 0x80 != 0,
            "{ctx}: message starts with an init packet"
        );
        // Channel 0 is reserved (CTAP 2.1 §11.2.3); the only report it may carry is
        // the ERR_INVALID_CHANNEL answer to a request sent on it.
        if cid_of(first) == 0 {
            assert_eq!(first, &error_report(0, ERR_INVALID_CHANNEL), "{ctx}: CID 0");
        }
        let bcnt = bcnt_of(first);
        assert!(bcnt <= MAX_MESSAGE, "{ctx}: BCNT {bcnt} above 7609");
        if framer_only {
            assert!(bcnt <= MAX_REQUEST, "{ctx}: framer message of {bcnt} bytes");
        }
        let wanted = packets_for(bcnt);
        let group: Vec<Report> = events[i..]
            .iter()
            .take(wanted)
            .map(|event| match event {
                Event::Send(report) => *report,
                other => panic!("{ctx}: {other:?} inside a {bcnt}-byte message"),
            })
            .collect();
        assert_eq!(group.len(), wanted, "{ctx}: truncated {bcnt}-byte message");
        let (_, cmd, payload) = reassemble(&group);
        match cmd {
            _ if !framer_only => {}
            ERROR => {
                assert_eq!(payload.len(), 1, "{ctx}: ERROR carries one byte");
                assert!(ERROR_CODES.contains(&payload[0]), "{ctx}: error code");
            }
            INIT => assert_eq!(payload.len(), 17, "{ctx}: INIT response length"),
            WINK => assert!(payload.is_empty(), "{ctx}: empty response"),
            PING => {}
            other => panic!("{ctx}: framer sent command {other:#x}"),
        }
        i += wanted;
    }
}

/// The host's copy of a multi-packet request the device accepted.
struct Partial {
    cid: u32,
    cmd: u8,
    bcnt: usize,
    data: Vec<u8>,
    next_seq: u8,
    deadline: u64,
}

/// What the model expects one initialization packet to produce.
#[derive(Debug)]
enum Expect {
    Error(u8),
    Started,
    Request(Vec<u8>),
    Ping(Vec<u8>),
    Init { fresh: bool, abort: bool },
    Wink,
}

#[derive(Default, Debug)]
struct Coverage {
    errors: [usize; 9],
    multi_packet_completions: usize,
    longest_completion: usize,
    requests: usize,
    aborts: usize,
    cancels: usize,
    allocations: usize,
    /// LOCK answered ERR_INVALID_CMD (docs/MEASUREMENT.md, probe lock).
    locks_refused: usize,
    /// Empty CBOR requests refused with ERR_INVALID_LEN (CTAP 2.1 §11.2.9.1.2; the
    /// reference device's stall is not copied, docs/MEASUREMENT.md probe empty-cbor).
    empty_cbor_refused: usize,
    /// Initialization packets refused for a BCNT between 1537 and 7609.
    over_limit: usize,
    responses: usize,
    resets: usize,
}

impl Coverage {
    fn error(&mut self, code: u8) {
        if let Some(index) = ERROR_CODES.iter().position(|&c| c == code) {
            self.errors[index] += 1;
        }
    }

    fn count(&self, code: u8) -> usize {
        ERROR_CODES
            .iter()
            .position(|&c| c == code)
            .map_or(0, |index| self.errors[index])
    }
}

struct Harness {
    dev: Ctaphid,
    caps: u8,
    rng: SplitMix64,
    seed: u64,
    step: usize,
    now: u64,
    /// Channels allocated since the last reset.
    channels: Vec<u32>,
    /// Every channel ever allocated, across resets.
    ever: HashSet<u32>,
    partial: Option<Partial>,
    outstanding: Option<(u32, u8)>,
    coverage: Coverage,
}

impl Harness {
    fn new(seed: u64, caps: u8) -> Self {
        Self {
            dev: Ctaphid::new(FIRMWARE, caps),
            caps,
            rng: SplitMix64(seed),
            seed,
            step: 0,
            now: 0,
            channels: Vec::new(),
            ever: HashSet::new(),
            partial: None,
            outstanding: None,
            coverage: Coverage::default(),
        }
    }

    fn ctx(&self) -> String {
        format!("seed {:#x} step {} t={}", self.seed, self.step, self.now)
    }

    fn model_deadline(&self) -> Option<u64> {
        self.partial.as_ref().map(|p| p.deadline)
    }

    fn check_model_state(&self) {
        let ctx = self.ctx();
        assert!(
            self.partial.is_none() || self.outstanding.is_none(),
            "{ctx}: model has two transactions"
        );
        assert_eq!(
            self.dev.outstanding(),
            self.outstanding,
            "{ctx}: outstanding"
        );
        assert_eq!(
            self.dev.next_deadline(),
            self.model_deadline(),
            "{ctx}: next_deadline"
        );
        if let Some(deadline) = self.dev.next_deadline() {
            assert!(
                deadline > self.now,
                "{ctx}: deadline {deadline} already due"
            );
        }
    }

    /// Applies due deadlines to the model and returns the events they must produce
    /// (CTAP 2.1 §11.2.5.2 timeout).
    fn model_tick(&mut self) -> Vec<Event> {
        match self.partial.take() {
            Some(partial) if self.now >= partial.deadline => {
                self.coverage.error(ERR_MSG_TIMEOUT);
                error_events(partial.cid, ERR_MSG_TIMEOUT)
            }
            other => {
                self.partial = other;
                Vec::new()
            }
        }
    }

    // ----- traffic generation -------------------------------------------------------

    fn pick_cid(&mut self) -> u32 {
        let roll = self.rng.below(100);
        let partial_cid = self.partial.as_ref().map(|p| p.cid);
        let outstanding_cid = self.outstanding.map(|(cid, _)| cid);
        match roll {
            0..=14 => BROADCAST,
            15..=19 => 0,
            20..=24 => self.rng.next_u64() as u32,
            25..=39 if partial_cid.is_some() => partial_cid.unwrap_or(BROADCAST),
            25..=44 if outstanding_cid.is_some() => outstanding_cid.unwrap_or(BROADCAST),
            _ if !self.channels.is_empty() => self.rng.pick(&self.channels),
            _ => BROADCAST,
        }
    }

    fn pick_length(&mut self) -> usize {
        if self.rng.percent(70) {
            self.rng.pick(&BOUNDARY_LENGTHS)
        } else {
            self.rng.below(MAX_MESSAGE + 200)
        }
    }

    fn random_init(&mut self) -> Report {
        let cid = self.pick_cid();
        let cmd = if self.rng.percent(90) {
            self.rng.pick(&COMMANDS)
        } else {
            self.rng.byte() & 0x7F
        };
        let usual = self.rng.percent(80);
        let bcnt = match cmd {
            INIT if usual => 8,
            LOCK if usual => 1,
            WINK | CANCEL if usual => 0,
            _ => self.pick_length(),
        };
        let mut data = self.rng.bytes(INIT_DATA);
        if cmd == LOCK {
            data[0] = self.rng.below(14) as u8;
        }
        init_packet(cid, cmd, (bcnt & 0xFFFF) as u16, &data)
    }

    fn random_cont(&mut self) -> Report {
        let (cid, seq) = match &self.partial {
            Some(partial) if self.rng.percent(75) => {
                let expected = partial.next_seq;
                let seq = if self.rng.percent(85) {
                    expected
                } else {
                    self.rng.pick(&[
                        expected.wrapping_add(1) & 0x7F,
                        expected.wrapping_sub(1) & 0x7F,
                        0,
                        0x7F,
                    ])
                };
                (partial.cid, seq)
            }
            _ => (self.pick_cid(), self.rng.byte() & 0x7F),
        };
        let data = self.rng.bytes(CONT_DATA);
        cont_packet(cid, seq, &data)
    }

    // ----- oracle ---------------------------------------------------------------------

    /// The documented outcome of an initialization packet other than CANCEL, applying
    /// the check order of `src/framer.rs`.
    fn expect_init(&self, cid: u32, cmd: u8, bcnt: usize, data: &[u8]) -> Expect {
        let valid = if cid == BROADCAST {
            cmd == INIT
        } else {
            self.channels.contains(&cid)
        };
        if !valid {
            return Expect::Error(ERR_INVALID_CHANNEL);
        }
        let active = match (&self.partial, self.outstanding) {
            (Some(partial), _) => Some((partial.cid, true)),
            (None, Some((owner, _))) => Some((owner, false)),
            (None, None) => None,
        };
        if let Some((owner, assembling)) = active {
            if owner != cid {
                return Expect::Error(ERR_CHANNEL_BUSY);
            }
            if cmd != INIT {
                return Expect::Error(if assembling {
                    ERR_INVALID_SEQ
                } else {
                    ERR_CHANNEL_BUSY
                });
            }
        }
        if cmd == INIT {
            return if bcnt == 8 {
                Expect::Init {
                    fresh: cid == BROADCAST,
                    abort: self.outstanding.is_some(),
                }
            } else {
                Expect::Error(ERR_INVALID_LEN)
            };
        }
        // LOCK is not among the accepted commands: ERR_INVALID_CMD (docs/MEASUREMENT.md,
        // probe lock). MSG and CBOR carry at least the command byte (CTAP 2.1
        // §11.2.9.1.1, §11.2.9.1.2), so an empty one is ERR_INVALID_LEN (§11.2.9.1.6); the
        // reference device's stall on an empty CBOR request (probe empty-cbor) is a defect
        // not copied.
        let length_ok = match cmd {
            PING => true,
            MSG if self.caps & 0x08 == 0 => bcnt >= 1,
            CBOR if self.caps & 0x04 != 0 => bcnt >= 1,
            WINK if self.caps & 0x01 != 0 => bcnt == 0,
            0x40..=0x7F => true,
            _ => return Expect::Error(ERR_INVALID_CMD),
        };
        // At most 1536 bytes for every request (docs/MEASUREMENT.md, probe ping-max).
        if !length_ok || bcnt > MAX_REQUEST {
            return Expect::Error(ERR_INVALID_LEN);
        }
        if bcnt > INIT_DATA {
            return Expect::Started;
        }
        let payload = data[..bcnt].to_vec();
        match cmd {
            PING => Expect::Ping(payload),
            WINK => Expect::Wink,
            _ => Expect::Request(payload),
        }
    }

    /// Feeds one host report and checks every resulting event against the model.
    fn send(&mut self, report: Report) {
        let ctx = self.ctx();
        let events = self.dev.report(self.now, &report);
        assert_well_formed(&events, true, &ctx);
        let leading = self.model_tick();
        assert!(
            events.starts_with(&leading),
            "{ctx}: due timeout first: expected {leading:?}, got {events:?}"
        );
        let rest = &events[leading.len()..];
        let cid = cid_of(&report);
        if report[4] & 0x80 == 0 {
            self.check_cont(cid, report[4], &report[5..], rest, &ctx);
        } else if report[4] & 0x7F == CANCEL {
            // CTAP 2.1 §11.2.9.1.5: never answered; acts only on an outstanding CBOR
            // request of the same channel.
            let expected = if self.outstanding == Some((cid, CBOR)) {
                self.coverage.cancels += 1;
                vec![Event::Cancel { cid }]
            } else {
                Vec::new()
            };
            assert_eq!(rest, expected, "{ctx}: CANCEL on {cid:#x}");
        } else {
            self.check_init(cid, &report, rest, &ctx);
        }
        self.check_model_state();
    }

    fn check_cont(&mut self, cid: u32, seq: u8, data: &[u8], events: &[Event], ctx: &str) {
        let Some(partial) = self.partial.as_mut().filter(|p| p.cid == cid) else {
            // CTAP 2.1 §11.2.5.4: spurious continuation packets are ignored.
            assert!(
                events.is_empty(),
                "{ctx}: orphan continuation on {cid:#x}: {events:?}"
            );
            return;
        };
        if seq != partial.next_seq {
            self.partial = None;
            self.coverage.error(ERR_INVALID_SEQ);
            assert_eq!(events, error_events(cid, ERR_INVALID_SEQ), "{ctx}: bad SEQ");
            return;
        }
        let wanted = (partial.bcnt - partial.data.len()).min(CONT_DATA);
        partial.data.extend_from_slice(&data[..wanted]);
        partial.next_seq += 1;
        partial.deadline = self.now + TIMEOUT_MS;
        if partial.data.len() < partial.bcnt {
            assert!(
                events.is_empty(),
                "{ctx}: message still arriving: {events:?}"
            );
            return;
        }
        let Some(done) = self.partial.take() else {
            return;
        };
        self.coverage.multi_packet_completions += 1;
        self.coverage.longest_completion = self.coverage.longest_completion.max(done.bcnt);
        if done.cmd == PING {
            assert_eq!(
                reassemble(&sends(events)),
                (cid, PING, done.data),
                "{ctx}: PING echo"
            );
        } else {
            self.coverage.requests += 1;
            self.outstanding = Some((cid, done.cmd));
            assert_eq!(
                events,
                [Event::Request {
                    cid,
                    cmd: done.cmd,
                    payload: done.data
                }],
                "{ctx}: reassembled request"
            );
        }
    }

    fn check_init(&mut self, cid: u32, report: &Report, events: &[Event], ctx: &str) {
        let cmd = report[4] & 0x7F;
        let bcnt = bcnt_of(report);
        let data = &report[7..];
        let expect = self.expect_init(cid, cmd, bcnt, data);
        match expect {
            Expect::Error(code) => {
                self.coverage.error(code);
                if code == ERR_INVALID_SEQ {
                    self.partial = None;
                }
                if code == ERR_INVALID_CMD && cmd == LOCK {
                    self.coverage.locks_refused += 1;
                }
                if code == ERR_INVALID_LEN && cmd == CBOR && bcnt == 0 {
                    self.coverage.empty_cbor_refused += 1;
                }
                if code == ERR_INVALID_LEN && (MAX_REQUEST + 1..=MAX_MESSAGE).contains(&bcnt) {
                    self.coverage.over_limit += 1;
                }
                assert_eq!(
                    events,
                    error_events(cid, code),
                    "{ctx}: command {cmd:#x} BCNT {bcnt} on {cid:#x}"
                );
            }
            Expect::Started => {
                assert!(
                    events.is_empty(),
                    "{ctx}: start of a {bcnt}-byte message: {events:?}"
                );
                self.partial = Some(Partial {
                    cid,
                    cmd,
                    bcnt,
                    data: data.to_vec(),
                    next_seq: 0,
                    deadline: self.now + TIMEOUT_MS,
                });
            }
            Expect::Request(payload) => {
                self.coverage.requests += 1;
                self.outstanding = Some((cid, cmd));
                assert_eq!(
                    events,
                    [Event::Request { cid, cmd, payload }],
                    "{ctx}: request"
                );
            }
            Expect::Ping(payload) => {
                assert_eq!(
                    reassemble(&sends(events)),
                    (cid, PING, payload),
                    "{ctx}: PING"
                );
            }
            Expect::Wink => {
                assert_eq!(
                    events,
                    [Event::Wink, Event::Send(init_packet(cid, WINK, 0, &[]))],
                    "{ctx}: WINK"
                );
            }
            Expect::Init { fresh, abort } => {
                self.check_init_response(cid, data, events, fresh, abort, ctx)
            }
        }
    }

    /// CTAP 2.1 §11.2.9.1.3 response: nonce, CID, protocol 2, version, capabilities.
    fn check_init_response(
        &mut self,
        cid: u32,
        data: &[u8],
        events: &[Event],
        fresh: bool,
        abort: bool,
        ctx: &str,
    ) {
        let events = if abort {
            assert_eq!(
                events.first(),
                Some(&Event::Abort { cid }),
                "{ctx}: Abort first"
            );
            self.coverage.aborts += 1;
            self.outstanding = None;
            &events[1..]
        } else {
            events
        };
        let reports = sends(events);
        assert_eq!(reports.len(), 1, "{ctx}: one INIT response");
        let (on, cmd, payload) = reassemble(&reports);
        assert_eq!((on, cmd), (cid, INIT), "{ctx}: INIT response header");
        assert_eq!(&payload[..8], &data[..8], "{ctx}: nonce");
        assert_eq!(
            &payload[12..],
            &[2, 5, 7, 4, self.caps],
            "{ctx}: version, caps"
        );
        let channel = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
        if fresh {
            assert!(channel != 0 && channel != BROADCAST, "{ctx}: reserved CID");
            assert!(self.ever.insert(channel), "{ctx}: CID {channel:#x} reused");
            self.channels.push(channel);
            self.coverage.allocations += 1;
        } else {
            assert_eq!(channel, cid, "{ctx}: resynchronised CID");
            if self.partial.as_ref().is_some_and(|p| p.cid == cid) {
                self.partial = None;
            }
        }
    }

    // ----- actions ---------------------------------------------------------------------

    fn advance(&mut self, max_ms: usize) {
        self.now += self.rng.below(max_ms + 1) as u64;
    }

    fn act_tick(&mut self) {
        match self.rng.below(4) {
            0 | 1 => {
                if let Some(deadline) = self.dev.next_deadline() {
                    self.now = self.now.max(deadline);
                }
            }
            2 => self.advance(50),
            _ => self.now += 1000 + self.rng.below(3500) as u64,
        }
        let ctx = self.ctx();
        let events = self.dev.tick(self.now);
        assert_well_formed(&events, true, &ctx);
        let expected = self.model_tick();
        assert_eq!(events, expected, "{ctx}: tick");
        self.check_model_state();
    }

    fn act_respond(&mut self) {
        let ctx = self.ctx();
        let mut len = self.pick_length().min(MAX_MESSAGE + 1);
        let reply_error = self.rng.percent(20);
        if reply_error {
            // `respond(cid, cmd::ERROR, &[code])` answers with a CTAPHID error.
            len = 1;
        }
        let payload = self.rng.bytes(len);
        match self.outstanding {
            Some((owner, cmd)) if self.rng.percent(85) => {
                let reply = if reply_error { ERROR } else { cmd };
                let flag = if self.rng.percent(50) { 0x80 } else { 0 };
                let reports = self.dev.respond(owner, reply | flag, &payload);
                let events: Vec<Event> = reports.iter().copied().map(Event::Send).collect();
                assert_well_formed(&events, false, &ctx);
                if len > MAX_MESSAGE {
                    assert_eq!(reports, vec![error_report(owner, ERR_OTHER)], "{ctx}");
                } else {
                    assert_eq!(reassemble(&reports), (owner, reply, payload), "{ctx}");
                }
                self.outstanding = None;
                self.coverage.responses += 1;
            }
            _ => {
                // Any channel without an outstanding request: nothing is sent.
                let cid = self.pick_cid();
                if self.outstanding.is_some_and(|(owner, _)| owner == cid) {
                    return;
                }
                assert_eq!(
                    self.dev.respond(cid, CBOR, &payload),
                    Vec::<Report>::new(),
                    "{ctx}"
                );
            }
        }
        self.check_model_state();
    }

    fn act_keepalive(&mut self) {
        let cid = self.pick_cid();
        let status = self.rng.pick(&[1u8, 2]);
        assert_eq!(
            self.dev.keepalive(cid, status),
            init_packet(cid, KEEPALIVE, 1, &[status]),
            "{}: KEEPALIVE layout (CTAP 2.1 §11.2.9.1.7)",
            self.ctx()
        );
    }

    /// CTAPHID_CANCEL, mostly aimed at the channel with the outstanding request
    /// (CTAP 2.1 §11.2.9.1.5), sometimes with a non-zero BCNT (model policy: honoured).
    fn act_cancel(&mut self) {
        let cid = match self.outstanding {
            Some((owner, _)) if self.rng.percent(70) => owner,
            _ => self.pick_cid(),
        };
        let bcnt = if self.rng.percent(80) {
            0
        } else {
            self.pick_length() as u16
        };
        self.advance(20);
        self.send(init_packet(cid, CANCEL, bcnt, &[]));
    }

    fn act_reset(&mut self) {
        self.dev.reset();
        self.channels.clear();
        self.partial = None;
        self.outstanding = None;
        self.coverage.resets += 1;
        self.check_model_state();
    }

    /// A complete host message on one channel, with foreign packets mixed in.
    /// Foreign packets never use the message's own CID, so long messages (up to the
    /// 1536-byte maximum) still complete while other channels are answered busy. One
    /// message in ten may be longer: refused at its first packet, the rest orphans.
    fn act_message(&mut self) {
        if let Some((owner, cmd)) = self.outstanding.filter(|_| self.rng.percent(90)) {
            assert_eq!(
                self.dev.respond(owner, cmd, &[0x00]).len(),
                1,
                "{}",
                self.ctx()
            );
            self.outstanding = None;
            self.coverage.responses += 1;
        }
        let cid = match self.channels.is_empty() {
            true => BROADCAST,
            false => self.rng.pick(&self.channels),
        };
        let cmd = self.rng.pick(&[PING, PING, PING, CBOR, MSG, 0x41, INIT]);
        let limit = if self.rng.percent(10) {
            MAX_MESSAGE
        } else {
            MAX_REQUEST
        };
        let len = match cmd {
            INIT => 8,
            _ => self.rng.pick(&BOUNDARY_LENGTHS).min(limit),
        };
        let payload = self.rng.bytes(len);
        for report in message(cid, cmd, &payload) {
            if self.rng.percent(10) {
                let noise = if self.rng.percent(50) {
                    self.random_init()
                } else {
                    self.random_cont()
                };
                if cid_of(&noise) != cid {
                    self.step += 1;
                    self.send(noise);
                }
            }
            self.step += 1;
            self.advance(5);
            self.send(report);
        }
    }

    fn run(&mut self, steps: usize) {
        while self.step < steps {
            self.step += 1;
            if self.rng.below(1000) < 3 {
                self.act_reset();
                continue;
            }
            match self.rng.below(100) {
                0..=39 => {
                    self.advance(20);
                    let report = self.random_init();
                    self.send(report);
                }
                40..=69 => {
                    self.advance(20);
                    let report = self.random_cont();
                    self.send(report);
                }
                70..=77 => self.act_message(),
                78..=87 => self.act_tick(),
                88..=94 => self.act_respond(),
                95..=97 => self.act_cancel(),
                _ => self.act_keepalive(),
            }
        }
    }
}

fn fuzz(seed: u64, caps: u8, steps: usize) -> Coverage {
    let mut harness = Harness::new(seed, caps);
    harness.run(steps);
    harness.coverage
}

/// The generator must reach every rule it is meant to check, or a passing run says
/// nothing.
fn assert_covered(coverage: &Coverage) {
    for code in [
        ERR_INVALID_CMD,
        ERR_INVALID_LEN,
        ERR_INVALID_SEQ,
        ERR_MSG_TIMEOUT,
        ERR_CHANNEL_BUSY,
        ERR_INVALID_CHANNEL,
    ] {
        assert!(
            coverage.count(code) > 0,
            "error {code:#x} never seen: {coverage:?}"
        );
    }
    assert!(coverage.multi_packet_completions > 20, "{coverage:?}");
    // Nothing longer than the measured 1536-byte maximum completes, and it is reached.
    assert_eq!(coverage.longest_completion, MAX_REQUEST, "{coverage:?}");
    assert!(coverage.over_limit > 0, "{coverage:?}");
    assert!(coverage.requests > 20, "{coverage:?}");
    assert!(coverage.aborts > 0, "{coverage:?}");
    assert!(coverage.cancels > 0, "{coverage:?}");
    assert!(coverage.allocations > 5, "{coverage:?}");
    assert!(coverage.locks_refused > 0, "{coverage:?}");
    assert!(coverage.empty_cbor_refused > 0, "{coverage:?}");
    assert_eq!(
        coverage.count(ERR_LOCK_REQUIRED),
        0,
        "no command requires a lock: {coverage:?}"
    );
    // ERR_INVALID_PAR came only from LOCK durations above 10 s, before LOCK was
    // refused as a whole (docs/MEASUREMENT.md, probe lock).
    assert_eq!(
        coverage.count(ERR_INVALID_PAR),
        0,
        "no parameter is checked: {coverage:?}"
    );
    assert!(coverage.responses > 20, "{coverage:?}");
    assert!(coverage.resets > 0, "{coverage:?}");
}

#[test]
fn fuzz_wink_cbor_msg_device() {
    // Capabilities WINK | CBOR (0x05), MSG implemented (CTAP 2.1 §11.2.9.1.3).
    for seed in [0x5EED_0001_u64, 0x00C0_FFEE] {
        assert_covered(&fuzz(seed, CAPS, 8000));
    }
}

#[test]
fn fuzz_cbor_only_device() {
    // Capabilities CBOR | NMSG (0x0C): WINK and MSG are not implemented, so they are
    // ERR_INVALID_CMD (CTAP 2.1 §11.2.9.1.3).
    let coverage = fuzz(0xF1D0_2026, 0x0C, 8000);
    assert!(coverage.count(ERR_INVALID_CMD) > 0, "{coverage:?}");
    assert!(coverage.requests > 0, "{coverage:?}");
}
