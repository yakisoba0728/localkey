//! Device-level test harness: a host that speaks CTAPHID reports, CCID messages, OTP
//! feature reports and touch events to one `lk_device::Device`, with a deterministic
//! store and entropy (`lk_testkit::MemoryStore`, `lk_testkit::SeededEntropy`).
//!
//! Frame layouts are written from the specifications, not from the crates under test:
//! CTAPHID packets from CTAP 2.1 §11.2.4, CCID messages from USB CCID Rev 1.1 §6.1/§6.2,
//! OTP feature reports from Yubico `ykdef.h` (`lk-otp` documents the same layout), and
//! the SCP03 host from GlobalPlatform Card Specification v2.3.1 Amendment D.

#![allow(dead_code, clippy::unwrap_used, clippy::too_many_arguments)]

pub mod ctap;
pub mod der;
pub mod iso;
pub mod json;
pub mod otp;

use lk_core::{DeviceProfile, Millis};
use lk_device::{BusEvent, Device, Input, Output, TouchEdge};
use lk_testkit::{MemoryStore, SeededEntropy};

pub const KEY: [u8; 32] = [0x5A; 32];
pub const SERIAL: u32 = 12_345_678;

/// CTAPHID constants (CTAP 2.1 §11.2.9).
pub const CTAPHID_MSG: u8 = 0x03;
pub const CTAPHID_INIT: u8 = 0x06;
pub const CTAPHID_PING: u8 = 0x01;
pub const CTAPHID_WINK: u8 = 0x08;
pub const CTAPHID_CBOR: u8 = 0x10;
pub const CTAPHID_CANCEL: u8 = 0x11;
pub const CTAPHID_KEEPALIVE: u8 = 0x3B;
pub const CTAPHID_ERROR: u8 = 0x3F;
pub const BROADCAST: u32 = 0xFFFF_FFFF;

/// AIDs (`docs/CONTRACTS.md` "Application crates").
pub const AID_MGMT: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];
pub const AID_OTP: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01];
pub const AID_OATH: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];
pub const AID_PIV: &[u8] = &[0xA0, 0x00, 0x00, 0x03, 0x08];
pub const AID_PIV_FULL: &[u8] = &[0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00];
pub const AID_OPENPGP: &[u8] = &[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];
pub const AID_HSMAUTH: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x07, 0x01];
pub const AID_SD: &[u8] = &[0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00];

/// The harness: a device, a handle on its store, and the program's clock.
pub struct Rig {
    pub dev: Device,
    pub store: MemoryStore,
    pub profile: DeviceProfile,
    pub now: Millis,
    ccid_seq: u8,
    seed: u64,
    /// When set, every output with the time it was produced (for determinism checks).
    pub log: Option<Vec<(Millis, Output)>>,
}

impl Default for Rig {
    fn default() -> Self {
        Self::new()
    }
}

impl Rig {
    /// A fresh device with the YubiKey 5C Nano 5.7.4 compatibility profile.
    pub fn new() -> Self {
        Self::with_profile(DeviceProfile::yubikey_5c_nano_5_7_4(SERIAL))
    }

    pub fn with_profile(profile: DeviceProfile) -> Self {
        Self::with_store(profile, MemoryStore::new(), 1)
    }

    pub fn with_store(profile: DeviceProfile, store: MemoryStore, seed: u64) -> Self {
        let dev = Device::open(profile.clone(), Box::new(store.clone()), Box::new(SeededEntropy::new(seed)), KEY);
        Rig {
            dev,
            store,
            profile,
            now: 0,
            ccid_seq: 0,
            seed,
            log: None,
        }
    }

    /// A rig around a device the test opened itself (for example on a store that wraps
    /// `store`), opened at time 0 with entropy seed `seed`; [`Rig::restart`] reopens on
    /// `store` directly.
    pub fn from_parts(dev: Device, store: MemoryStore, profile: DeviceProfile, seed: u64) -> Self {
        Rig {
            dev,
            store,
            profile,
            now: 0,
            ccid_seq: 0,
            seed,
            log: None,
        }
    }

    /// Reopen the device on the same store (a restart of the program), at the current
    /// time.
    pub fn restart(&mut self) {
        self.seed += 1;
        self.dev = Device::open_at(
            self.now,
            self.profile.clone(),
            Box::new(self.store.clone()),
            Box::new(SeededEntropy::new(self.seed)),
            KEY,
        );
        self.ccid_seq = 0;
    }

    pub fn input(&mut self, input: Input<'_>) -> Vec<Output> {
        let out = self.dev.handle(self.now, input);
        if let Some(log) = self.log.as_mut() {
            log.extend(out.iter().map(|o| (self.now, o.clone())));
        }
        out
    }

    /// Advance the clock by `ms` and deliver a Tick.
    pub fn advance(&mut self, ms: Millis) -> Vec<Output> {
        self.now += ms;
        self.input(Input::Tick)
    }

    /// Run the program's timer loop until `until` (`docs/DESIGN.md` §4: the host
    /// delivers `Tick` no later than `next_deadline()`): a Tick at every deadline up to
    /// `until`, then the clock moves to `until`. Returns each output with its time.
    pub fn run_until(&mut self, until: Millis) -> Vec<(Millis, Output)> {
        let mut out = Vec::new();
        while let Some(deadline) = self.dev.next_deadline() {
            if deadline > until {
                break;
            }
            assert!(deadline >= self.now, "deadline {deadline} in the past at {}", self.now);
            self.now = deadline;
            out.extend(self.input(Input::Tick).into_iter().map(|o| (deadline, o)));
        }
        self.now = self.now.max(until);
        out
    }

    /// Send a CTAP2 request that waits for user presence: check that nothing is sent at
    /// once, run the timer loop for `wait` ms (a KEEPALIVE(UPNEEDED) every
    /// `KEEPALIVE_INTERVAL_MS`, 95 ms, the first one interval after the request; CTAP 2.1
    /// §11.2.9.1.7), touch, and return the response and the times of the keepalives seen.
    /// Measured on a YubiKey 5C Nano 5.7.4 (docs/MEASUREMENT.md, probe
    /// selection-keepalive-cancel); before the measurement the helper expected an
    /// immediate KEEPALIVE and listed the request time first.
    pub fn cbor_touch(&mut self, cid: u32, request: &[u8], wait: Millis) -> (Vec<u8>, Vec<Millis>) {
        let start = self.now;
        let out = self.ctaphid_send(cid, CTAPHID_CBOR, request);
        assert!(responses(&out).is_empty(), "answered without a touch: {:02X?}", responses(&out));
        assert_eq!(keepalives(&out), Vec::<u8>::new(), "no KEEPALIVE at once");
        assert_eq!(self.dev.next_deadline(), Some(start + lk_device::KEEPALIVE_INTERVAL_MS), "first KEEPALIVE one interval later");
        let mut times = Vec::new();
        for (at, o) in self.run_until(start + wait) {
            let messages = parse_fido(std::slice::from_ref(&o));
            for (command, payload) in messages {
                assert_eq!((command, payload.as_slice()), (CTAPHID_KEEPALIVE, &[2u8][..]), "only keepalives while waiting");
                times.push(at);
            }
        }
        let mut out = self.touch_down();
        self.now += 80;
        out.extend(self.touch_up());
        let (command, payload) = responses(&out).into_iter().next().unwrap_or_else(|| panic!("no response after touch: {out:02X?}"));
        assert_eq!(command, CTAPHID_CBOR);
        (payload, times)
    }

    pub fn bus(&mut self, event: BusEvent) -> Vec<Output> {
        self.input(Input::Bus(event))
    }

    pub fn touch_down(&mut self) -> Vec<Output> {
        self.input(Input::Touch(TouchEdge::Down))
    }

    pub fn touch_up(&mut self) -> Vec<Output> {
        self.input(Input::Touch(TouchEdge::Up))
    }

    /// A short touch: down, 50 ms, up. Outputs of both edges.
    pub fn tap(&mut self) -> Vec<Output> {
        let mut out = self.touch_down();
        self.now += 50;
        out.extend(self.touch_up());
        out
    }

    // ----- CTAPHID (CTAP 2.1 §11.2.4) -----

    /// Split a message into 64-byte CTAPHID packets.
    pub fn ctaphid_packets(cid: u32, cmd: u8, payload: &[u8]) -> Vec<[u8; 64]> {
        let mut packets = Vec::new();
        let mut first = [0u8; 64];
        first[..4].copy_from_slice(&cid.to_be_bytes());
        first[4] = 0x80 | cmd;
        first[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        let n = payload.len().min(57);
        first[7..7 + n].copy_from_slice(&payload[..n]);
        packets.push(first);
        for (seq, chunk) in payload[n..].chunks(59).enumerate() {
            let mut cont = [0u8; 64];
            cont[..4].copy_from_slice(&cid.to_be_bytes());
            cont[4] = seq as u8;
            cont[5..5 + chunk.len()].copy_from_slice(chunk);
            packets.push(cont);
        }
        packets
    }

    /// Send a message; return every output.
    pub fn ctaphid_send(&mut self, cid: u32, cmd: u8, payload: &[u8]) -> Vec<Output> {
        let mut out = Vec::new();
        for packet in Self::ctaphid_packets(cid, cmd, payload) {
            out.extend(self.input(Input::FidoReport(&packet)));
        }
        out
    }

    /// Broadcast INIT; returns the allocated channel.
    pub fn ctaphid_init(&mut self) -> u32 {
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        let out = self.ctaphid_send(BROADCAST, CTAPHID_INIT, &nonce);
        let (cmd, payload) = parse_fido(&out).into_iter().next().unwrap();
        assert_eq!(cmd, CTAPHID_INIT);
        assert_eq!(&payload[..8], &nonce);
        u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]])
    }

    /// Send a request and return the response message (keepalives skipped).
    pub fn ctaphid(&mut self, cid: u32, cmd: u8, payload: &[u8]) -> (u8, Vec<u8>) {
        let out = self.ctaphid_send(cid, cmd, payload);
        responses(&out).into_iter().next().unwrap_or_else(|| panic!("no CTAPHID response in {out:02X?}"))
    }

    /// A CTAP2 request: command byte then CBOR parameters.
    pub fn cbor(&mut self, cid: u32, request: &[u8]) -> Vec<u8> {
        let (cmd, payload) = self.ctaphid(cid, CTAPHID_CBOR, request);
        assert_eq!(cmd, CTAPHID_CBOR, "{payload:02X?}");
        payload
    }

    // ----- CCID (USB CCID Rev 1.1 §6.1, §6.2) -----

    fn next_seq(&mut self) -> u8 {
        let seq = self.ccid_seq;
        self.ccid_seq = self.ccid_seq.wrapping_add(1);
        seq
    }

    /// `PC_to_RDR_*` message with a 10-byte header.
    pub fn ccid_message(kind: u8, seq: u8, specific: [u8; 3], data: &[u8]) -> Vec<u8> {
        let mut m = vec![kind];
        m.extend_from_slice(&(data.len() as u32).to_le_bytes());
        m.push(0); // bSlot
        m.push(seq);
        m.extend_from_slice(&specific);
        m.extend_from_slice(data);
        m
    }

    /// `PC_to_RDR_IccPowerOn` (§6.1.1); returns the ATR.
    pub fn power_on(&mut self) -> Vec<u8> {
        let seq = self.next_seq();
        let out = self.input(Input::Ccid(&Self::ccid_message(0x62, seq, [0, 0, 0], &[])));
        let reply = ccid_replies(&out).into_iter().next().unwrap();
        assert_eq!(reply[0], 0x80, "RDR_to_PC_DataBlock");
        assert_eq!(reply[7] & 0xC0, 0x00, "command OK: {reply:02X?}");
        reply[10..].to_vec()
    }

    /// `PC_to_RDR_IccPowerOff` (§6.1.2).
    pub fn power_off(&mut self) -> Vec<Output> {
        let seq = self.next_seq();
        self.input(Input::Ccid(&Self::ccid_message(0x63, seq, [0, 0, 0], &[])))
    }

    /// `PC_to_RDR_XfrBlock` (§6.1.4) carrying `apdu`; all outputs and the seq used.
    pub fn xfr(&mut self, apdu: &[u8]) -> (u8, Vec<Output>) {
        let seq = self.next_seq();
        let out = self.input(Input::Ccid(&Self::ccid_message(0x6F, seq, [0, 0, 0], apdu)));
        (seq, out)
    }

    /// Send an APDU and return the response APDU (data || SW), which must come at once.
    pub fn apdu(&mut self, apdu: &[u8]) -> Vec<u8> {
        let (seq, out) = self.xfr(apdu);
        data_block(&out, seq).unwrap_or_else(|| panic!("no DataBlock for {apdu:02X?}: {out:02X?}"))
    }

    /// `PC_to_RDR_Abort` (§6.1.13) for `seq`.
    pub fn bulk_abort(&mut self, seq: u8) -> Vec<Output> {
        self.input(Input::Ccid(&Self::ccid_message(0x72, seq, [0, 0, 0], &[])))
    }

    /// SELECT by DF name (ISO/IEC 7816-4 §11.2.2), short form with Le.
    pub fn select(&mut self, aid: &[u8]) -> Vec<u8> {
        let mut apdu = vec![0x00, 0xA4, 0x04, 0x00, aid.len() as u8];
        apdu.extend_from_slice(aid);
        apdu.push(0x00);
        self.apdu(&apdu)
    }

    // ----- OTP HID (Yubico ykdef.h; lk-otp hid.rs) -----

    /// Write a 70-byte frame `payload(64) || slot || crc16(payload) LE || 0 0 0` as ten
    /// feature reports `chunk(7) || 0x80 | seq`.
    pub fn otp_write(&mut self, slot: u8, payload: &[u8; 64]) -> Vec<Output> {
        let mut frame = [0u8; 70];
        frame[..64].copy_from_slice(payload);
        frame[64] = slot;
        frame[65..67].copy_from_slice(&otp::crc16(payload).to_le_bytes());
        let mut out = Vec::new();
        for seq in 0..10u8 {
            let mut report = [0u8; 8];
            report[..7].copy_from_slice(&frame[usize::from(seq) * 7..usize::from(seq) * 7 + 7]);
            report[7] = 0x80 | seq;
            out.extend(self.input(Input::OtpSetFeature(&report)));
        }
        out
    }

    pub fn otp_read(&mut self) -> [u8; 8] {
        let out = self.input(Input::OtpGetFeature);
        match out.as_slice() {
            [Output::OtpFeature(report)] => *report,
            other => panic!("expected one feature report, got {other:02X?}"),
        }
    }
}

/// Reassemble the CTAPHID messages in `out` (including keepalives and errors).
pub fn parse_fido(out: &[Output]) -> Vec<(u8, Vec<u8>)> {
    let mut messages = Vec::new();
    let mut current: Option<(u8, usize, Vec<u8>)> = None;
    for o in out {
        let Output::FidoReport(r) = o else { continue };
        if r[4] & 0x80 != 0 {
            let cmd = r[4] & 0x7F;
            let len = usize::from(u16::from_be_bytes([r[5], r[6]]));
            let mut data = r[7..7 + len.min(57)].to_vec();
            data.truncate(len);
            if data.len() == len {
                messages.push((cmd, data));
                current = None;
            } else {
                current = Some((cmd, len, data));
            }
        } else if let Some((cmd, len, mut data)) = current.take() {
            let need = len - data.len();
            data.extend_from_slice(&r[5..5 + need.min(59)]);
            if data.len() == len {
                messages.push((cmd, data));
            } else {
                current = Some((cmd, len, data));
            }
        }
    }
    messages
}

/// CTAPHID messages other than KEEPALIVE.
pub fn responses(out: &[Output]) -> Vec<(u8, Vec<u8>)> {
    parse_fido(out).into_iter().filter(|(cmd, _)| *cmd != CTAPHID_KEEPALIVE).collect()
}

/// KEEPALIVE status bytes in `out`.
pub fn keepalives(out: &[Output]) -> Vec<u8> {
    parse_fido(out).into_iter().filter(|(cmd, _)| *cmd == CTAPHID_KEEPALIVE).map(|(_, p)| p[0]).collect()
}

pub fn ccid_replies(out: &[Output]) -> Vec<Vec<u8>> {
    out.iter()
        .filter_map(|o| match o {
            Output::Ccid(m) => Some(m.clone()),
            _ => None,
        })
        .collect()
}

/// The data of the successful `RDR_to_PC_DataBlock` for `seq` (time extensions skipped).
pub fn data_block(out: &[Output], seq: u8) -> Option<Vec<u8>> {
    ccid_replies(out)
        .into_iter()
        .find(|m| m[0] == 0x80 && m[6] == seq && m[7] & 0x80 == 0)
        .map(|m| m[10..].to_vec())
}

/// Time-extension DataBlocks (`bStatus` bit 7, §6.2.6) in `out`.
pub fn time_extensions(out: &[Output]) -> usize {
    ccid_replies(out).iter().filter(|m| m[0] == 0x80 && m[7] & 0x80 != 0).count()
}

pub fn indicators(out: &[Output]) -> Vec<bool> {
    out.iter()
        .filter_map(|o| match o {
            Output::PresenceIndicator(b) => Some(*b),
            _ => None,
        })
        .collect()
}

pub fn keyboard(out: &[Output]) -> Vec<[u8; 8]> {
    out.iter()
        .filter_map(|o| match o {
            Output::OtpKeyboard(r) => Some(*r),
            _ => None,
        })
        .collect()
}

pub fn reenumerations(out: &[Output]) -> Vec<lk_core::UsbInterfaces> {
    out.iter()
        .filter_map(|o| match o {
            Output::Reenumerate(i) => Some(*i),
            _ => None,
        })
        .collect()
}

pub fn sw(resp: &[u8]) -> u16 {
    u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]])
}

pub fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// A short APDU (ISO/IEC 7816-4 §5.1) with optional Le.
pub fn apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: Option<u8>) -> Vec<u8> {
    let mut out = vec![cla, ins, p1, p2];
    if !data.is_empty() {
        out.push(data.len() as u8);
        out.extend_from_slice(data);
    }
    if let Some(le) = le {
        out.push(le);
    }
    out
}

// ----- OATH helpers (YKOATH) -----

/// YKOATH PUT of a TOTP/SHA-1 credential with a 20-byte secret; `touch` adds property
/// `78 02` (REQUIRE_TOUCH).
pub fn oath_put(name: &[u8], touch: bool) -> Vec<u8> {
    let mut data = vec![0x71, name.len() as u8];
    data.extend_from_slice(name);
    data.extend_from_slice(&[0x73, 22, 0x21, 6]);
    data.extend_from_slice(&[0x11; 20]);
    if touch {
        data.extend_from_slice(&[0x78, 0x02]);
    }
    apdu(0x00, 0x01, 0x00, 0x00, &data, None)
}

/// YKOATH CALCULATE (truncated) with an 8-byte challenge.
pub fn oath_calculate(name: &[u8]) -> Vec<u8> {
    let mut data = vec![0x71, name.len() as u8];
    data.extend_from_slice(name);
    data.extend_from_slice(&[0x74, 0x08, 0, 0, 0, 0, 0, 0, 0, 1]);
    apdu(0x00, 0xA2, 0x00, 0x01, &data, Some(0))
}

// ----- SCP03 host (GP Card Specification v2.3.1 Amendment D) -----

pub const SCP03_DEFAULT_KEY: [u8; 16] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
];

fn cmac(key: &[u8; 16], data: &[u8]) -> [u8; 16] {
    lk_crypto::aes_cmac(key, data).unwrap()
}

/// Amd D §4.1.5 KDF (NIST SP 800-108 counter mode with AES-CMAC).
fn derive(key: &[u8; 16], constant: u8, context: &[u8], bits: u16) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 1u8;
    while out.len() * 8 < usize::from(bits) {
        let mut data = vec![0u8; 11];
        data.push(constant);
        data.push(0x00);
        data.extend_from_slice(&bits.to_be_bytes());
        data.push(i);
        data.extend_from_slice(context);
        out.extend_from_slice(&cmac(key, &data));
        i += 1;
    }
    out.truncate(usize::from(bits) / 8);
    out
}

fn pad(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    out.push(0x80);
    while !out.len().is_multiple_of(16) {
        out.push(0);
    }
    out
}

fn unpad(data: &[u8]) -> Option<Vec<u8>> {
    let end = data.iter().rposition(|&b| b != 0)?;
    (data[end] == 0x80).then(|| data[..end].to_vec())
}

/// The SCP03 session-key derivation of Amd D §6.2.1 (public for the YubiHSM Auth
/// session keys, which use the same derivation).
pub fn scp03_derive(key: &[u8; 16], constant: u8, context: &[u8], bits: u16) -> Vec<u8> {
    derive(key, constant, context, bits)
}

/// A static SCP03 key set: K-ENC, K-MAC, K-DEK.
pub type Scp03Keys = [[u8; 16]; 3];

/// The factory key set (Yubico yk5-apps-scp: all three keys `40..4F`, version `FF`).
pub const SCP03_DEFAULT_KEYS: Scp03Keys = [SCP03_DEFAULT_KEY; 3];

/// An established SCP03 host session at security level `33`.
#[derive(Debug, Clone)]
pub struct Scp03 {
    s_enc: [u8; 16],
    s_mac: [u8; 16],
    s_rmac: [u8; 16],
    mcv: [u8; 16],
    counter: u128,
    /// The static DEK of the key set (Amd D §7.2: PUT KEY data is encrypted with it).
    pub dek: [u8; 16],
}

impl Scp03 {
    /// INITIALIZE UPDATE (`80 50 00 00 08 challenge`) then EXTERNAL AUTHENTICATE
    /// (`84 82 33 00 10 cryptogram C-MAC`) with the published default keys
    /// (Yubico yk5-apps-scp), over the device's CCID interface.
    pub fn open(rig: &mut Rig) -> Scp03 {
        Self::open_with(rig, 0x00, &SCP03_DEFAULT_KEYS)
    }

    /// The same with key version `kvn` (P1; `00` = the first available) and `keys`.
    pub fn open_with(rig: &mut Rig, kvn: u8, keys: &Scp03Keys) -> Scp03 {
        Self::try_open_with(rig, kvn, keys).unwrap_or_else(|status| panic!("SCP03 handshake answered {status:04X}"))
    }

    /// [`Scp03::open_with`], returning the status word of a handshake command that
    /// answered an error status instead of a session.
    pub fn try_open_with(rig: &mut Rig, kvn: u8, keys: &Scp03Keys) -> Result<Scp03, u16> {
        let challenge = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let resp = rig.apdu(&apdu(0x80, 0x50, kvn, 0x00, &challenge, None));
        if resp.len() == 2 {
            return Err(sw(&resp));
        }
        assert_eq!(resp.len(), 31, "INITIALIZE UPDATE {resp:02X?}");
        assert_eq!(sw(&resp), 0x9000);
        let mut context = challenge.to_vec();
        context.extend_from_slice(&resp[13..21]);
        let [k_enc, k_mac, dek] = *keys;
        let s_enc: [u8; 16] = derive(&k_enc, 0x04, &context, 128).try_into().unwrap();
        let s_mac: [u8; 16] = derive(&k_mac, 0x06, &context, 128).try_into().unwrap();
        let s_rmac: [u8; 16] = derive(&k_mac, 0x07, &context, 128).try_into().unwrap();
        assert_eq!(derive(&s_mac, 0x00, &context, 64), resp[21..29].to_vec(), "card cryptogram");
        let host_cryptogram = derive(&s_mac, 0x01, &context, 64);
        let mut input = vec![0u8; 16];
        input.extend_from_slice(&[0x84, 0x82, 0x33, 0x00, 0x10]);
        input.extend_from_slice(&host_cryptogram);
        let mcv = cmac(&s_mac, &input);
        let mut data = host_cryptogram.clone();
        data.extend_from_slice(&mcv[..8]);
        let resp = rig.apdu(&apdu(0x84, 0x82, 0x33, 0x00, &data, None));
        if resp != [0x90, 0x00] {
            return Err(sw(&resp));
        }
        Ok(Scp03 {
            s_enc,
            s_mac,
            s_rmac,
            mcv,
            counter: 1,
            dek,
        })
    }

    /// A session whose keys were agreed by an SCP11 handshake (GP Card Specification
    /// v2.3.1 Amendment F §3.1.2, §6.5.2.3): S-ENC, S-MAC, S-RMAC and S-DEK from the key
    /// derivation; secure messaging then works as in SCP03 (Amd D §6.2), with the
    /// receipt as the first MAC chaining value and the encryption counter at 1.
    pub fn from_scp11(s_enc: [u8; 16], s_mac: [u8; 16], s_rmac: [u8; 16], receipt: [u8; 16], s_dek: [u8; 16]) -> Scp03 {
        Scp03 {
            s_enc,
            s_mac,
            s_rmac,
            mcv: receipt,
            counter: 1,
            dek: s_dek,
        }
    }

    /// PUT KEY of a whole SCP03 key set (GP 2.3.1 §11.8, Amd D §7.2): `80 D8 <replace
    /// KVN> 81 <new KVN> { 88 11 10 <key encrypted with the DEK, AES-CBC zero ICV> 03
    /// <KCV> } x3`, where the KCV is the first three bytes of `AES(key, 01..01)`
    /// (Amd D §4.1.1). Returns the command data and the expected response `new KVN ||
    /// KCVs`.
    pub fn put_key_data(&self, new_kvn: u8, keys: &Scp03Keys) -> (Vec<u8>, Vec<u8>) {
        let mut data = vec![new_kvn];
        let mut expected = vec![new_kvn];
        for key in keys {
            let encrypted = lk_crypto::aes_cbc_encrypt(&self.dek, &[0u8; 16], key).unwrap();
            let kcv = lk_crypto::aes_ecb_encrypt_block(key, &[0x01; 16]).unwrap();
            data.extend_from_slice(&[0x88, 0x11, 0x10]);
            data.extend_from_slice(&encrypted);
            data.push(0x03);
            data.extend_from_slice(&kcv[..3]);
            expected.extend_from_slice(&kcv[..3]);
        }
        (data, expected)
    }

    /// Wrap a short command (Amd D §6.2.6 encryption, then §6.2.4 C-MAC).
    pub fn wrap(&mut self, cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: Option<u8>) -> Vec<u8> {
        let icv = lk_crypto::aes_ecb_encrypt_block(&self.s_enc, &self.counter.to_be_bytes()).unwrap();
        self.counter += 1;
        let mut body = lk_crypto::aes_cbc_encrypt(&self.s_enc, &icv, &pad(data)).unwrap();
        let cla = cla | 0x04;
        let mut input = self.mcv.to_vec();
        input.extend_from_slice(&[cla, ins, p1, p2, (body.len() + 8) as u8]);
        input.extend_from_slice(&body);
        self.mcv = cmac(&self.s_mac, &input);
        body.extend_from_slice(&self.mcv[..8]);
        apdu(cla, ins, p1, p2, &body, le)
    }

    /// Wrap a command in the extended form (ISO/IEC 7816-4 §5.1): the C-MAC input
    /// carries the three-byte Lc the command uses (Amd D §6.2.4); `le` is Ne (65 536
    /// encodes as `00 00`).
    pub fn wrap_extended(&mut self, cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: Option<usize>) -> Vec<u8> {
        let icv = lk_crypto::aes_ecb_encrypt_block(&self.s_enc, &self.counter.to_be_bytes()).unwrap();
        self.counter += 1;
        let mut body = if data.is_empty() {
            Vec::new()
        } else {
            lk_crypto::aes_cbc_encrypt(&self.s_enc, &icv, &pad(data)).unwrap()
        };
        let cla = cla | 0x04;
        let lc = (body.len() + 8) as u16;
        let mut input = self.mcv.to_vec();
        input.extend_from_slice(&[cla, ins, p1, p2, 0x00]);
        input.extend_from_slice(&lc.to_be_bytes());
        input.extend_from_slice(&body);
        self.mcv = cmac(&self.s_mac, &input);
        body.extend_from_slice(&self.mcv[..8]);
        let mut apdu = vec![cla, ins, p1, p2, 0x00];
        apdu.extend_from_slice(&lc.to_be_bytes());
        apdu.extend_from_slice(&body);
        if let Some(n) = le {
            apdu.extend_from_slice(&((n % 65_536) as u16).to_be_bytes());
        }
        apdu
    }

    /// Verify the R-MAC and decrypt (Amd D §6.2.5, §6.2.7). Error statuses come bare.
    pub fn unwrap(&self, resp: &[u8]) -> (Vec<u8>, u16) {
        let (data, status) = resp.split_at(resp.len() - 2);
        let status = u16::from_be_bytes([status[0], status[1]]);
        if !(status == 0x9000 || matches!(status >> 8, 0x61..=0x63)) {
            assert!(data.is_empty(), "error status with data");
            return (Vec::new(), status);
        }
        let (body, mac) = data.split_at(data.len() - 8);
        let mut input = self.mcv.to_vec();
        input.extend_from_slice(body);
        input.extend_from_slice(&status.to_be_bytes());
        assert_eq!(&cmac(&self.s_rmac, &input)[..8], mac, "R-MAC");
        if body.is_empty() {
            return (Vec::new(), status);
        }
        let mut block = (self.counter - 1).to_be_bytes();
        block[0] = 0x80;
        let icv = lk_crypto::aes_ecb_encrypt_block(&self.s_enc, &block).unwrap();
        let clear = lk_crypto::aes_cbc_decrypt(&self.s_enc, &icv, body).unwrap();
        (unpad(&clear).unwrap(), status)
    }
}
