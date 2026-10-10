//! Fixed-seed pseudo-random input fuzz across every interface (`docs/DESIGN.md` §11,
//! §12-4: seeded random input tests instead of cargo-fuzz). Inputs are biased toward
//! well-formed frames (whole CTAPHID messages, CCID messages around real APDUs, OTP frames
//! with a valid CRC) so the routing behind the framers is reached. After every input
//! the outputs must be well formed and the device's invariants must hold; at the end the
//! device must still work.

#![allow(clippy::unwrap_used)]

mod common;

use common::otp::crc16;
use common::*;
use lk_core::Entropy;
use lk_device::{BusEvent, Input, Output, TouchEdge};
use lk_testkit::SeededEntropy;

struct Fuzz {
    rng: SeededEntropy,
    /// The host's CCID sequence counter (a real host numbers its messages).
    seq: u8,
    /// The CCID input of the last step: message type (`None` for the control ABORT),
    /// `bSeq`, and the `wLevelParameter` of an XfrBlock.
    ccid_input: Option<(Option<u8>, u8, u16)>,
    /// The last step was a bus event that ends the card session.
    session_reset: bool,
    /// Complete CBOR and MSG requests sent per (channel, command) and not yet answered.
    asked: std::collections::HashMap<(u32, u8), usize>,
    /// A one-line description of the last input, for failure messages.
    desc: String,
}

impl Fuzz {
    fn below(&mut self, bound: usize) -> usize {
        let mut b = [0u8; 4];
        self.rng.fill(&mut b);
        u32::from_be_bytes(b) as usize % bound.max(1)
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        self.rng.bytes(n)
    }

    /// Up to `max - 1` random bytes.
    fn noise(&mut self, max: usize) -> Vec<u8> {
        let n = self.below(max);
        self.rng.bytes(n)
    }

    fn byte(&mut self) -> u8 {
        self.rng.bytes(1)[0]
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }

    /// A command APDU: a SELECT of a real AID, a command with an INS some application
    /// knows, or noise; short or extended, sometimes chained or with SM CLA bits.
    fn apdu(&mut self) -> Vec<u8> {
        let aids: [&[u8]; 9] = [AID_MGMT, AID_OTP, AID_OATH, AID_PIV, AID_PIV_FULL, AID_OPENPGP, AID_HSMAUTH, AID_SD, &[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]];
        match self.below(10) {
            0..=2 => {
                let aid = self.pick(&aids);
                let mut apdu = vec![0x00, 0xA4, 0x04, 0x00, aid.len() as u8];
                apdu.extend_from_slice(aid);
                if self.below(2) == 0 {
                    apdu.push(0x00);
                }
                apdu
            }
            3 => {
                // Known-good credentials for deeper states.
                match self.below(4) {
                    0 => vec![0x00, 0x20, 0x00, 0x80, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF],
                    1 => [&[0x00, 0x20, 0x00, 0x83, 0x08][..], b"12345678"].concat(),
                    2 => [&[0x00, 0x20, 0x00, 0x81, 0x06][..], b"123456"].concat(),
                    _ => vec![0x80, 0x50, 0x00, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8],
                }
            }
            4 => self.noise(12),
            _ => {
                let cla = self.pick(&[0x00, 0x00, 0x00, 0x10, 0x80, 0x84, 0x04, 0x0C, 0x1C, 0xFF]);
                let ins = self.pick(&[
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x1D, 0xA1, 0xA2, 0xA4, 0xA5, 0xB2, 0xC0, 0xCA, 0xCB, 0xDA, 0xDB, 0x20,
                    0x24, 0x2C, 0x2A, 0x47, 0x87, 0xF1, 0xF7, 0xF8, 0xFD, 0x82, 0x88, 0xE2, 0xE4, 0xD8, 0x84, 0x22,
                ]);
                // Never generate keys (RSA key generation would only slow the run).
                let ins = if ins == 0x47 { 0xCA } else { ins };
                let any = self.byte();
                let p1 = self.pick(&[0x00, 0x00, 0x01, 0x3F, 0x80, 0x9E, any]);
                let any = self.byte();
                let p2 = self.pick(&[0x00, 0x00, 0x80, 0x9A, 0xFF, 0x66, 0xE0, any]);
                let len = self.pick(&[0usize, 0, 1, 8, 16, 40, 255, 256, 300]);
                let data = self.bytes(len);
                let mut apdu = vec![cla, ins, p1, p2];
                let extended = len > 255 || self.below(6) == 0;
                if !data.is_empty() {
                    if extended {
                        apdu.push(0);
                        apdu.extend_from_slice(&(len as u16).to_be_bytes());
                    } else {
                        apdu.push(len as u8);
                    }
                    apdu.extend_from_slice(&data);
                }
                match self.below(3) {
                    0 => {}
                    1 if extended => apdu.extend_from_slice(if data.is_empty() { &[0, 0, 0] } else { &[0, 0] }),
                    _ => apdu.push(self.pick(&[0x00, 0x10, 0xFF])),
                }
                apdu
            }
        }
    }

    /// A CTAP2 request: a command byte (often a real one) and a CBOR map with small
    /// integer keys and random values, or noise.
    fn cbor_request(&mut self) -> Vec<u8> {
        use lk_codec::cbor::{MapBuilder, Value};
        let command = self.pick(&[0x01, 0x02, 0x04, 0x06, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x41, 0x07, 0x55]);
        let mut out = vec![command];
        if self.below(4) == 0 {
            out.extend(self.noise(60));
            return out;
        }
        let mut map = MapBuilder::new();
        for _ in 0..self.below(6) {
            let key = self.below(12) as i64 + 1;
            let value = match self.below(6) {
                0 => Value::from(self.below(300) as i64 - 20),
                1 => Value::Bytes(self.noise(40)),
                2 => Value::from("example.com"),
                3 => Value::Bool(self.below(2) == 0),
                4 => MapBuilder::new().insert("id", "example.com").insert("rk", self.below(2) == 0).build(),
                _ => Value::Array(vec![MapBuilder::new().insert("alg", -7i64).insert("type", "public-key").build()]),
            };
            map.set(key, value);
        }
        out.extend(lk_codec::cbor::encode(&map.build()));
        out
    }

    /// One input; returns its outputs and the CCID slot it addressed, if any.
    fn step(&mut self, rig: &mut Rig, cids: &mut Vec<u32>) -> (Vec<Output>, Option<u8>) {
        self.ccid_input = None;
        self.session_reset = false;
        self.desc = String::from("other");
        match self.below(16) {
            0..=3 => {
                let cid = match self.below(8) {
                    0 => BROADCAST,
                    1 => u32::from_be_bytes(self.bytes(4).try_into().unwrap()),
                    _ => cids.get(self.below(cids.len())).copied().unwrap_or(BROADCAST),
                };
                let cmd = self.pick(&[0x06, 0x01, 0x03, 0x10, 0x10, 0x10, 0x11, 0x08, 0x04, 0x42, 0x40, 0x50, 0x7F, 0x3B]);
                let payload = match cmd {
                    0x06 => self.bytes(8),
                    0x10 => self.cbor_request(),
                    0x03 => self.apdu(),
                    0x04 => vec![self.below(12) as u8],
                    _ => self.noise(130),
                };
                let mut packets = Rig::ctaphid_packets(cid, cmd, &payload);
                let mut complete = true;
                if packets.len() > 1 && self.below(5) == 0 {
                    // An incomplete message: the transaction timeout ends it, unless a later
                    // continuation packet of the same channel (from another message whose
                    // initialization packet the framer ignores, such as a CANCEL with data)
                    // completes it — so it still counts as a possible request.
                    packets.pop();
                    complete = false;
                }
                let mut sequence_error = false;
                if packets.len() > 1 && self.below(8) == 0 {
                    packets[1][4] ^= 0x01; // a sequence error ends the transaction
                    complete = false;
                    sequence_error = true;
                }
                if cmd == 0x06 && cid != BROADCAST {
                    self.asked.retain(|(c, _), _| *c != cid); // resynchronisation aborts
                }
                if !sequence_error && matches!(cmd, 0x10 | 0x03) {
                    *self.asked.entry((cid, cmd)).or_default() += 1;
                }
                self.desc = format!("CTAPHID cid {cid:08X} cmd {cmd:02X} len {} complete {complete} head {:02X?}", payload.len(), &payload[..payload.len().min(6)]);
                let mut out = Vec::new();
                for packet in &packets {
                    out.extend(rig.input(Input::FidoReport(packet)));
                }
                for (command, payload) in parse_fido(&out) {
                    if command == CTAPHID_INIT && payload.len() >= 12 && cid == BROADCAST {
                        cids.push(u32::from_be_bytes(payload[8..12].try_into().unwrap()));
                    }
                }
                (out, None)
            }
            4 => {
                let mut report = [0u8; 64];
                self.rng.fill(&mut report);
                (rig.input(Input::FidoReport(&report)), None)
            }
            5..=8 => {
                let kind = match self.below(20) {
                    0..=11 => 0x6F,
                    12 | 13 => 0x62,
                    14 => 0x63,
                    _ => self.pick(&[0x65, 0x6C, 0x6D, 0x6A, 0x61, 0x69, 0x71, 0x72, 0x73, 0x50]),
                };
                let slot = if self.below(16) == 0 { 1 } else { 0 };
                self.seq = self.seq.wrapping_add(1);
                let seq = if self.below(10) == 0 { self.byte() } else { self.seq };
                let data = if kind == 0x6F {
                    self.apdu()
                } else {
                    let n = self.pick(&[0, 0, 0, 5, 7]);
                    self.bytes(n)
                };
                let level: u16 = if self.below(8) == 0 { self.pick(&[1, 2, 3, 0x10]) } else { 0 };
                let [lo, hi] = level.to_le_bytes();
                let specific = if kind == 0x62 { self.pick(&[0, 0, 0, 1, 2, 3]) } else { 0 };
                let mut message = Rig::ccid_message(kind, seq, [specific, lo, hi], &data);
                message[5] = slot;
                if self.below(30) == 0 {
                    message[1] ^= 0x01; // dwLength disagreeing with the message
                }
                self.ccid_input = Some((Some(kind), seq, level));
                (rig.input(Input::Ccid(&message)), Some(slot))
            }
            9 => {
                // The two-step abort (USB CCID Rev 1.1 §5.3.1): the control request for the
                // last message, usually followed by the matching bulk Abort.
                let slot = if self.below(8) == 0 { 1 } else { 0 };
                let seq = if self.below(6) == 0 { self.byte() } else { self.seq };
                self.ccid_input = Some((None, seq, 0));
                let mut out = rig.input(Input::CcidControlAbort { slot, seq });
                if self.below(4) != 0 {
                    out.extend(rig.input(Input::Ccid(&Rig::ccid_message(0x72, seq, [0, 0, 0], &[]))));
                }
                (out, Some(slot))
            }
            10 => {
                // A whole OTP frame with a valid CRC, the yubikit way (status read first).
                let command = self.pick(&[0x01, 0x03, 0x04, 0x05, 0x06, 0x10, 0x13, 0x20, 0x28, 0x30, 0x38, 0x12, 0x11, 0x99]);
                let mut payload = [0u8; 64];
                if matches!(command, 0x01 | 0x03) && self.below(2) == 0 {
                    // A valid Yubico OTP or HMAC challenge-response configuration
                    // (`ykdef.h` `YK_CONFIG` with its CRC), so presses can type.
                    let key: [u8; 16] = self.bytes(16).try_into().unwrap();
                    let config = if self.below(3) == 0 {
                        common::otp::SlotConfig::hmac_challenge_response(&[0x77; 20], self.below(2) == 0)
                    } else {
                        common::otp::SlotConfig::yubico_otp(&[1, 2, 3, 4, 5, 6], [7; 6], key)
                    };
                    payload = config.payload([0; 6]);
                } else {
                    let n = self.below(65);
                    payload[..n].copy_from_slice(&self.bytes(n));
                }
                let mut frame = [0u8; 70];
                frame[..64].copy_from_slice(&payload);
                frame[64] = command;
                frame[65..67].copy_from_slice(&crc16(&payload).to_le_bytes());
                let mut out = Vec::new();
                for (seq, chunk) in frame.chunks(7).enumerate() {
                    if seq != 0 && seq != 9 && chunk.iter().all(|&b| b == 0) {
                        continue;
                    }
                    let mut report = [0u8; 8];
                    report[..7].copy_from_slice(chunk);
                    report[7] = 0x80 | seq as u8;
                    out.extend(rig.input(Input::OtpSetFeature(&report)));
                }
                (out, None)
            }
            11 => {
                let mut report = [0u8; 8];
                self.rng.fill(&mut report);
                if self.below(2) == 0 {
                    report[7] = 0x80 | self.below(16) as u8;
                }
                (rig.input(Input::OtpSetFeature(&report)), None)
            }
            12 => (rig.input(Input::OtpGetFeature), None),
            13 => {
                let edge = if self.below(2) == 0 { TouchEdge::Down } else { TouchEdge::Up };
                self.desc = format!("touch {edge:?}");
                (rig.input(Input::Touch(edge)), None)
            }
            14 => {
                if self.below(2) == 0 {
                    let until = rig.now + self.below(3_000) as u64;
                    self.desc = format!("run until {until}");
                    (rig.run_until(until).into_iter().map(|(_, o)| o).collect(), None)
                } else {
                    (rig.advance(self.below(40_000) as u64), None)
                }
            }
            _ => {
                if self.below(4) != 0 {
                    return (rig.advance(self.below(200) as u64), None);
                }
                let event = self.pick(&[BusEvent::Reset, BusEvent::Suspend, BusEvent::Resume, BusEvent::PowerCycle]);
                if matches!(event, BusEvent::Reset | BusEvent::PowerCycle) {
                    cids.clear();
                }
                self.session_reset = !matches!(event, BusEvent::Suspend);
                if matches!(event, BusEvent::Reset | BusEvent::PowerCycle) {
                    self.asked.clear();
                }
                self.desc = format!("bus {event:?}");
                (rig.bus(event), None)
            }
        }
    }
}

/// The channel and command of every complete CTAPHID message in `out` (CTAP 2.1
/// §11.2.4 framing), KEEPALIVE included.
fn fido_messages(out: &[Output]) -> Vec<(u32, u8)> {
    let mut messages = Vec::new();
    let mut current: Option<(u32, u8, usize, usize)> = None;
    for o in out {
        let Output::FidoReport(r) = o else { continue };
        let cid = u32::from_be_bytes(r[..4].try_into().unwrap());
        if r[4] & 0x80 != 0 {
            let len = usize::from(u16::from_be_bytes([r[5], r[6]]));
            if len <= 57 {
                messages.push((cid, r[4] & 0x7F));
                current = None;
            } else {
                current = Some((cid, r[4] & 0x7F, len, 57));
            }
        } else if let Some((c, command, len, have)) = current {
            assert_eq!(c, cid, "continuation on another channel");
            let have = have + 59;
            if have >= len {
                messages.push((cid, command));
                current = None;
            } else {
                current = Some((c, command, len, have));
            }
        }
    }
    messages
}

/// USB CCID Rev 1.1 §6.2: a bulk-in message is a 10-byte header with `dwLength` equal
/// to the data that follows, a known `RDR_to_PC_*` type, the slot of the request (or 0
/// for the pending command's answers), reserved `bStatus` bits clear, `bmICCStatus` and
/// `bmCommandStatus` within 0..=2, no DataBlock data with a failed command, an empty
/// SlotStatus, and a T=0 or T=1 parameter structure.
fn assert_ccid_message(m: &[u8], slot: Option<u8>, context: &str) {
    assert!(m.len() >= 10, "{context}: short CCID message {m:02X?}");
    let len = u32::from_le_bytes(m[1..5].try_into().unwrap()) as usize;
    assert_eq!(len, m.len() - 10, "{context}: dwLength {m:02X?}");
    assert!(matches!(m[0], 0x80..=0x84), "{context}: message type {m:02X?}");
    assert!(m[5] == 0 || Some(m[5]) == slot, "{context}: bSlot {m:02X?}");
    let status = m[7];
    assert_eq!(status & 0x3C, 0, "{context}: reserved bStatus bits {m:02X?}");
    assert!(status & 0x03 <= 2 && status >> 6 <= 2, "{context}: bStatus {m:02X?}");
    if m[0] == 0x80 && status >> 6 == 1 {
        assert_eq!(len, 0, "{context}: DataBlock data with a failed command {m:02X?}");
    }
    if m[0] == 0x81 {
        assert_eq!(len, 0, "{context}: SlotStatus has no data");
    }
    if m[0] == 0x82 {
        // §6.2.3: the T=0 (5 bytes) or T=1 (7 bytes) structure; a failed SetParameters
        // reports the parameters in force (lk-ccid `failed_parameter_replies_report_the_parameters_in_force`).
        assert!(matches!((m[9], len), (0, 5) | (1, 7) | (_, 0)), "{context}: Parameters {m:02X?}");
    }
}

/// Fixed-seed random inputs across FIDO HID, CCID (bulk and control), OTP HID, touches,
/// time and bus events: no panic; every FIDO output is one 64-byte report (by type) on a
/// channel the host knows or the broadcast channel; every CCID output is a well-formed
/// bulk-in message; every interrupt is `NotifySlotChange`; deadlines are always in the
/// future; the presence indicator alternates and matches `presence_pending`; and after
/// the run the device still answers on every enabled interface.
#[test]
fn seeded_random_inputs_across_all_interfaces() {
    // The seed is fixed; `LK_FUZZ_SEED` overrides it for local exploration.
    let seed = std::env::var("LK_FUZZ_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(0x5EED_F022);
    let mut fuzz = Fuzz {
        rng: SeededEntropy::new(seed),
        seq: 0,
        ccid_input: None,
        session_reset: false,
        asked: std::collections::HashMap::new(),
        desc: String::new(),
    };
    // How far the inputs reached: card answers `9000`, CTAP2 successes, presence
    // requests, OTP response reads, keyboard reports.
    let mut reach = [0usize; 5];
    for round in 0..10 {
        let mut rig = Rig::new();
        let mut cids = vec![rig.ctaphid_init(), rig.ctaphid_init()];
        let mut lit = false;
        // The XfrBlock waiting for its answer (a touch), as the host sees it.
        let mut waiting: Option<u8> = None;
        let mut history: Vec<String> = Vec::new();
        for step in 0..2_000 {
            let context = format!("seed {seed} round {round} step {step}");
            let (out, slot) = fuzz.step(&mut rig, &mut cids);
            let fido: Vec<(u8, Vec<u8>)> = parse_fido(&out).into_iter().map(|(c, p)| (c, p[..p.len().min(4)].to_vec())).collect();
            history.push(format!("{step} @{}: {} -> {fido:02X?}", rig.now, fuzz.desc));
            if let Some(deadline) = rig.dev.next_deadline() {
                assert!(deadline > rig.now, "{context}: deadline {deadline} at {}", rig.now);
            }
            for output in &out {
                match output {
                    Output::FidoReport(report) => {
                        assert_eq!(report.len(), 64);
                        let cid = u32::from_be_bytes(report[..4].try_into().unwrap());
                        assert!(cid != 0, "{context}: CID 0 in {report:02X?}");
                        if report[4] & 0x80 != 0 {
                            let len = usize::from(u16::from_be_bytes([report[5], report[6]]));
                            assert!(len <= 7609, "{context}: message length {len}");
                        }
                    }
                    Output::Ccid(message) => {
                        assert_ccid_message(message, slot, &context);
                        if message[0] == 0x80 && message.len() >= 12 && message.ends_with(&[0x90, 0x00]) {
                            reach[0] += 1;
                        }
                    }
                    Output::CcidInterrupt(message) => {
                        assert!(matches!(message.as_slice(), [0x50, 0x02 | 0x03]), "{context}: {message:02X?}");
                    }
                    Output::PresenceIndicator(state) => {
                        assert_ne!(*state, lit, "{context}: repeated indicator state");
                        lit = *state;
                        reach[2] += usize::from(*state);
                    }
                    Output::Reenumerate(interfaces) => {
                        assert!(interfaces.otp || interfaces.fido || interfaces.ccid, "{context}: no interface left");
                        assert_eq!(*interfaces, rig.dev.interfaces());
                    }
                    Output::OtpFeature(report) => reach[3] += usize::from(report[7] & 0x40 != 0),
                    Output::OtpKeyboard(_) => reach[4] += 1,
                }
            }
            assert_eq!(lit, rig.dev.presence_pending(), "{context}");
            // USB CCID Rev 1.1 §6.2: every bulk-in message answers the bSeq of the message
            // it belongs to: the input's own, or the XfrBlock that waits (its time
            // extensions and its deferred answer); nothing answers an XfrBlock twice.
            let replies: Vec<&Vec<u8>> = out
                .iter()
                .filter_map(|o| match o {
                    Output::Ccid(m) => Some(m),
                    _ => None,
                })
                .collect();
            let is_final = |m: &Vec<u8>| !(m[0] == 0x80 && m[7] >> 6 == 2);
            match fuzz.ccid_input {
                Some((kind, seq, level)) => {
                    for m in &replies {
                        assert!(m[6] == seq || Some(m[6]) == waiting, "{context}: bSeq {:02X} for input {seq:02X} (waiting {waiting:02X?})", m[6]);
                        if Some(m[6]) == waiting && is_final(m) {
                            waiting = None;
                        }
                    }
                    let answered = replies.iter().any(|m| m[6] == seq);
                    if kind == Some(0x6F) && level == 0 && !answered && rig.dev.interfaces().ccid {
                        assert!(rig.dev.presence_pending(), "{context}: an XfrBlock without an answer waits for a touch");
                        waiting = Some(seq);
                    }
                }
                None => {
                    for m in &replies {
                        assert_eq!(Some(m[6]), waiting, "{context}: an unsolicited CCID message {m:02X?}");
                        if is_final(m) {
                            waiting = None;
                        }
                    }
                }
            }
            if fuzz.session_reset || !rig.dev.interfaces().ccid {
                waiting = None;
            }
            // CTAP 2.1 §11.2.4: a CBOR or MSG response answers one request of its channel
            // (counted as an upper bound: incomplete messages count too); a request
            // dropped by INIT resynchronisation, a bus reset or a re-enumeration is never
            // answered late.
            for (cid, command) in fido_messages(&out) {
                if matches!(command, 0x10 | 0x03) {
                    let count = fuzz.asked.get_mut(&(cid, command));
                    assert!(
                        count.as_ref().is_some_and(|n| **n > 0),
                        "{context}: unsolicited response {command:#04x} on {cid:08X}; last inputs:\n{}",
                        history[history.len().saturating_sub(16)..].join("\n")
                    );
                    if let Some(n) = count {
                        *n -= 1;
                    }
                }
            }
            if out.iter().any(|o| matches!(o, Output::Reenumerate(_))) {
                fuzz.asked.clear();
                cids.clear();
            }
            reach[1] += parse_fido(&out).iter().filter(|(c, p)| *c == CTAPHID_CBOR && p.first() == Some(&0x00)).count();
        }

        // The device still works on every enabled interface.
        rig.touch_up();
        rig.now += 60_000;
        rig.bus(BusEvent::PowerCycle);
        let interfaces = rig.dev.interfaces();
        if interfaces.fido {
            let cid = rig.ctaphid_init();
            assert_eq!(rig.ctaphid(cid, CTAPHID_PING, b"alive"), (CTAPHID_PING, b"alive".to_vec()), "round {round}");
        }
        if interfaces.ccid {
            assert_eq!(rig.power_on(), rig.profile.atr, "round {round}");
            assert_eq!(rig.select(AID_MGMT), b"5.7.4\x90\x00".to_vec(), "round {round}");
        }
        if interfaces.otp {
            rig.input(Input::OtpSetFeature(&[0, 0, 0, 0, 0, 0, 0, 0xFF]));
            assert_eq!(&rig.otp_feature()[1..4], &[5, 7, 4], "round {round}");
        }
    }
    println!("reach: {reach:?}");
    assert!(reach.iter().all(|&n| n > 0), "every kind of deep state was reached: {reach:?}");
}
