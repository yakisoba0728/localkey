//! The two OTP slots and everything they do, independent of the transport.
//!
//! Sources:
//! - Yubico `ykdef.h` (yubikey-personalization, public): slot command numbers, the
//!   configuration structure, flag bits, status bits.
//! - YubiKey manual / Yubico developer documentation: "Yubico OTP", "OATH-HOTP",
//!   "Static password", "Challenge-response", "Access code", "Swap", "Update",
//!   "Dormant", "Slots and touch durations".
//! - yubikit-python `yubikit/yubiotp.py` (public): payload layouts written by the SDK
//!   (`config || current access code`, challenge padding, serial and device-info reads)
//!   and the programming-sequence rule a host relies on.
//! - RFC 4226 §5.3/§5.4 (HOTP), RFC 2104 (HMAC), FIPS 197 (AES).
//! - `reference/BEHAVIOR_CATALOG.md` "OTP" for the boundary decisions noted per item.

use core::fmt;

use lk_codec::apdu::sw;
use lk_core::{Host, Millis, Record, ResetKind};
use lk_crypto::{ct_eq, hmac_sha1};

use crate::config::{
    ACC_CODE_SIZE, CONFIG_SIZE, Mode, SCAN_CODES_SIZE, SLOT_DATA_SIZE, SlotConfig, cfg, ext, tkt,
};
use crate::keyboard::{SCAN_MAP_SIZE, Typist};
use crate::state::{Persistent, SlotState};
use crate::token::{MAX_USE_COUNTER, Ticket};

/// Slot command numbers (`ykdef.h` `SLOT_*`); over CCID they are P1 of INS `01`.
pub mod cmd {
    /// Write slot 1 configuration (all-zero configuration deletes).
    pub const CONFIG1: u8 = 0x01;
    /// Write slot 2 configuration.
    pub const CONFIG2: u8 = 0x03;
    /// Update slot 1 (flags and access code only).
    pub const UPDATE1: u8 = 0x04;
    /// Update slot 2.
    pub const UPDATE2: u8 = 0x05;
    /// Swap slot 1 and slot 2.
    pub const SWAP: u8 = 0x06;
    /// Write the NDEF record for slot 1 (NFC models only).
    pub const NDEF1: u8 = 0x08;
    /// Write the NDEF record for slot 2 (NFC models only).
    pub const NDEF2: u8 = 0x09;
    /// Read the device serial number.
    pub const DEVICE_SERIAL: u8 = 0x10;
    /// Write the legacy device configuration (mode, CR timeout, auto-eject).
    pub const DEVICE_CONFIG: u8 = 0x11;
    /// Write the keyboard scan map.
    pub const SCAN_MAP: u8 = 0x12;
    /// Read device information (management TLVs).
    pub const YK4_CAPABILITIES: u8 = 0x13;
    /// Write device information (management configuration).
    pub const YK4_SET_DEVICE_INFO: u8 = 0x15;
    /// Yubico OTP challenge-response, slot 1 (6-byte challenge).
    pub const CHAL_OTP1: u8 = 0x20;
    /// Yubico OTP challenge-response, slot 2.
    pub const CHAL_OTP2: u8 = 0x28;
    /// HMAC-SHA1 challenge-response, slot 1 (64-byte challenge).
    pub const CHAL_HMAC1: u8 = 0x30;
    /// HMAC-SHA1 challenge-response, slot 2.
    pub const CHAL_HMAC2: u8 = 0x38;
}

/// Bits of the status `touchLevel` field (`ykdef.h` "Bitmasks for touchLevel").
pub mod status_bits {
    /// Slot 1 holds a configuration.
    pub const CONFIG1_VALID: u16 = 0x01;
    /// Slot 2 holds a configuration.
    pub const CONFIG2_VALID: u16 = 0x02;
    /// Touching triggers slot 1 (keyboard output; not challenge-response, not dormant).
    pub const CONFIG1_TOUCH: u16 = 0x04;
    /// Touching triggers slot 2.
    pub const CONFIG2_TOUCH: u16 = 0x08;
    /// LED idle state inverted.
    pub const CONFIG_LED_INV: u16 = 0x10;
}

/// Short touch window for slot 1 and long touch window for slot 2, in milliseconds
/// (Yubico documentation "Slots": short touch 0.3–1.5 s, long touch 2.5–5 s).
pub const SHORT_TOUCH_MS: (Millis, Millis) = (300, 1500);
/// See [`SHORT_TOUCH_MS`].
pub const LONG_TOUCH_MS: (Millis, Millis) = (2500, 5000);
/// Default challenge-response touch timeout (Yubico: 15 s, the management
/// `chalresp_timeout` default).
pub const DEFAULT_CHALRESP_TIMEOUT_S: u8 = 15;
/// `TKTFLAG_APPEND_DELAYx` delay.
const APPEND_DELAY_MS: u64 = 500;

/// A completed button press of the legacy software button API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Press {
    /// Short touch: slot 1.
    Short,
    /// Long touch: slot 2 (slot 1 when it is the only configured slot).
    Long,
}

/// One of the two slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Slot {
    One,
    Two,
}

impl Slot {
    fn index(self) -> usize {
        match self {
            Self::One => 0,
            Self::Two => 1,
        }
    }
}

/// Classify a completed touch by its duration (see [`SHORT_TOUCH_MS`]).
pub fn classify_hold(held_ms: Millis) -> Option<Press> {
    if (SHORT_TOUCH_MS.0..=SHORT_TOUCH_MS.1).contains(&held_ms) {
        Some(Press::Short)
    } else if (LONG_TOUCH_MS.0..=LONG_TOUCH_MS.1).contains(&held_ms) {
        Some(Press::Long)
    } else {
        None
    }
}

/// What `lk-otp` needs from the Management application; `lk-device` implements it
/// with `lk-mgmt`. Slot commands `0x10`, `0x11`, `0x13` and `0x15` go through it.
pub trait MgmtBridge {
    /// The device serial number, or `None` if Management hides it.
    fn serial(&mut self, host: &mut dyn Host) -> Option<u32>;

    /// Device information page `page` as management TLVs, without the leading length
    /// byte (`lk-otp` adds it). `None` if the page does not exist.
    fn device_info(&mut self, page: u8, host: &mut dyn Host) -> Option<Vec<u8>>;

    /// Write device information: `data` is the length-prefixed TLV block, exactly the
    /// data of the management WRITE CONFIG command. `Err(sw)` rejects it.
    fn write_device_info(&mut self, data: &[u8], host: &mut dyn Host) -> Result<(), u16>;

    /// Write the legacy 4-byte device configuration (`ykdef.h` `YK_DEVICE_CONFIG`:
    /// mode, challenge-response timeout, auto-eject time little-endian).
    fn write_device_config(&mut self, data: &[u8], host: &mut dyn Host) -> Result<(), u16>;

    /// Challenge-response touch timeout in seconds (management `chalresp_timeout`).
    fn challenge_response_timeout_s(&self) -> u8 {
        DEFAULT_CHALRESP_TIMEOUT_S
    }
}

/// Per-slot volatile Yubico OTP session (YubiKey manual "Yubico OTP": the session
/// counter and timestamp live in RAM; the usage counter is non-volatile).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Session {
    session_counter: u8,
    timestamp_base: u32,
    started_at: Millis,
    /// The session counter wrapped: the next ticket needs a new usage counter.
    bump_pending: bool,
}

/// An explicit touch in progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Contact {
    down_at: Millis,
    /// Output already happened at contact (fast trigger).
    consumed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChallengeKind {
    Hmac,
    Yubico,
}

/// A challenge-response waiting for a touch, bound to the configuration it was asked
/// of.
#[derive(Clone)]
pub(crate) struct PendingChallenge {
    slot: usize,
    kind: ChallengeKind,
    challenge: [u8; SLOT_DATA_SIZE],
    config: [u8; CONFIG_SIZE],
    pub(crate) timeout_ms: Millis,
}

impl fmt::Debug for PendingChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingChallenge")
            .field("slot", &self.slot)
            .field("kind", &self.kind)
            .field("timeout_ms", &self.timeout_ms)
            .finish_non_exhaustive()
    }
}

/// The result of a slot command, before transport framing.
#[derive(Debug)]
pub(crate) enum Reply {
    /// A write succeeded; the transport answers with the status.
    Status,
    /// Response data (HID adds the CRC).
    Data(Vec<u8>),
    /// The command waits for a touch.
    NeedTouch(PendingChallenge),
}

/// The transport a challenge-response waits on (index into `Otp::waits`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transport {
    Hid,
    Ccid,
}

impl Transport {
    fn index(self) -> usize {
        match self {
            Self::Hid => 0,
            Self::Ccid => 1,
        }
    }
}

/// Both OTP slots, the shared scan map and the volatile Yubico OTP sessions.
#[derive(Debug, Clone)]
pub struct Otp {
    state: Persistent,
    version: [u8; 3],
    sessions: [Option<Session>; 2],
    contact: Option<Contact>,
    /// Deadlines of challenge-responses waiting for a touch, per transport. While one
    /// waits the touch belongs to it, so the slots type nothing (YubiKey manual
    /// "Challenge-response": with `CHAL_BTN_TRIG` the key waits for the button and
    /// the press completes the response).
    waits: [Option<Millis>; 2],
}

impl Otp {
    /// Restore from the plaintext last persisted under `Record::Otp`; unreadable or
    /// absent state is factory state (both slots empty).
    pub fn new(stored: Option<&[u8]>, host: &mut dyn Host) -> Self {
        let state = stored.and_then(Persistent::deserialize).unwrap_or_default();
        Self {
            state,
            version: host.profile().firmware.bytes(),
            sessions: [None, None],
            contact: None,
            waits: [None, None],
        }
    }

    /// The 6-byte status: firmware version (3), programming sequence, `touchLevel`
    /// little-endian (`ykdef.h` `STATUS`). SELECT over CCID returns it, as does the
    /// HID status report (bytes 1..7).
    pub fn status(&self) -> [u8; 6] {
        let [lo, hi] = self.touch_level().to_le_bytes();
        let [major, minor, patch] = self.version;
        [major, minor, patch, self.state.pgm_seq, lo, hi]
    }

    /// The `touchLevel` status bits (see [`status_bits`]).
    pub fn touch_level(&self) -> u16 {
        const VALID: [u16; 2] = [status_bits::CONFIG1_VALID, status_bits::CONFIG2_VALID];
        const TOUCH: [u16; 2] = [status_bits::CONFIG1_TOUCH, status_bits::CONFIG2_TOUCH];
        let mut bits = 0;
        for ((slot, valid), touch) in self.state.slots.iter().zip(VALID).zip(TOUCH) {
            if let Some(slot) = slot {
                bits |= valid;
                if slot.config.is_touch_triggered() {
                    bits |= touch;
                }
                if slot.config.ext_flags & ext::LED_INV != 0 {
                    bits |= status_bits::CONFIG_LED_INV;
                }
            }
        }
        bits
    }

    /// The programming sequence: incremented by every successful write, 0 when no
    /// slot is configured after a slot write.
    pub fn programming_sequence(&self) -> u8 {
        self.state.pgm_seq
    }

    /// Whether `slot` holds a configuration.
    pub fn is_configured(&self, slot: Slot) -> bool {
        self.slot(slot.index()).is_some()
    }

    /// Whether touching triggers `slot` (configured keyboard mode, not dormant).
    pub fn is_touch_triggered(&self, slot: Slot) -> bool {
        self.slot(slot.index())
            .is_some_and(|s| s.config.is_touch_triggered())
    }

    /// The configuration of `slot`.
    pub fn config(&self, slot: Slot) -> Option<&SlotConfig> {
        self.slot(slot.index()).map(|s| &s.config)
    }

    /// The persistent counter of `slot`: the next HOTP moving factor, or the last
    /// Yubico OTP usage counter.
    pub fn counter(&self, slot: Slot) -> Option<u32> {
        self.slot(slot.index()).map(|s| s.counter)
    }

    /// The keyboard scan map in use.
    pub fn scan_map(&self) -> &[u8; SCAN_MAP_SIZE] {
        &self.state.scan_map
    }

    /// Serial visibility through slot command `0x10`: visible when no slot is
    /// configured or when any configured slot sets `EXTFLAG_SERIAL_API_VISIBLE`
    /// (catalog "merged OTP serial API visibility").
    pub fn serial_api_visible(&self) -> bool {
        let mut configured = self.state.slots.iter().flatten().peekable();
        configured.peek().is_none()
            || configured.any(|s| s.config.ext_flags & ext::SERIAL_API_VISIBLE != 0)
    }

    /// The legacy software button: a completed press. Ignored while an explicit touch
    /// ([`touch_down`](Self::touch_down)) is active, so one physical touch never
    /// produces two outputs or consumes two counters (catalog "explicit touch events
    /// and counter exclusivity").
    ///
    /// When slot 1 is the only configured slot it answers both presses (fast trigger:
    /// `EXTFLAG_FAST_TRIG` "use fast trig if only cfg1 set", applied with or without
    /// the flag as the catalog records for a 300..5000 ms completed hold).
    ///
    /// While a challenge-response waits for a touch ([`is_challenge_waiting`]) the
    /// press belongs to it and nothing is typed; `lk-device` routes it to
    /// [`OtpHid::touch_resolved`](crate::OtpHid::touch_resolved) or
    /// [`CardApplet::touch_resolved`](lk_core::CardApplet::touch_resolved).
    ///
    /// [`is_challenge_waiting`]: Self::is_challenge_waiting
    pub fn button(&mut self, press: Press, host: &mut dyn Host) -> Vec<[u8; 8]> {
        if self.contact.is_some() || self.is_challenge_waiting(host.now()) {
            return Vec::new();
        }
        let slot = match press {
            Press::Short => 0,
            Press::Long if self.fast_trigger() => 0,
            Press::Long => 1,
        };
        self.emit(slot, host)
    }

    /// The touch sensor was pressed. With slot 1 as the only configured slot its
    /// output is produced immediately (fast trigger at contact); otherwise the slot is
    /// chosen on release by the touch duration. Ignored (no contact is recorded) while
    /// a challenge-response waits for the touch.
    pub fn touch_down(&mut self, host: &mut dyn Host) -> Vec<[u8; 8]> {
        if self.contact.is_some() || self.is_challenge_waiting(host.now()) {
            return Vec::new();
        }
        let fast = self.fast_trigger();
        self.contact = Some(Contact {
            down_at: host.now(),
            consumed: fast,
        });
        if fast { self.emit(0, host) } else { Vec::new() }
    }

    /// The touch sensor was released: a short touch (0.3–1.5 s) types slot 1, a long
    /// touch (2.5–5 s) types slot 2, anything else nothing. A touch that began before a
    /// challenge-response started waiting types nothing either.
    pub fn touch_up(&mut self, host: &mut dyn Host) -> Vec<[u8; 8]> {
        let Some(contact) = self.contact.take() else {
            return Vec::new();
        };
        if contact.consumed || self.is_challenge_waiting(host.now()) {
            return Vec::new();
        }
        match classify_hold(host.now().saturating_sub(contact.down_at)) {
            Some(Press::Short) => self.emit(0, host),
            Some(Press::Long) => self.emit(1, host),
            None => Vec::new(),
        }
    }

    /// Whether an explicit touch is in progress.
    pub fn is_touch_active(&self) -> bool {
        self.contact.is_some()
    }

    /// Whether a challenge-response (over HID or CCID) waits for a touch at `now`.
    /// `lk-device` gives the next touch to that request; the slots type nothing
    /// meanwhile.
    pub fn is_challenge_waiting(&self, now: Millis) -> bool {
        self.waits.iter().flatten().any(|&deadline| now < deadline)
    }

    /// Drop volatile state. Yubico OTP sessions survive SELECT, card power-off and USB
    /// reset and end only with a power cycle (catalog "volatile power session survives
    /// logical SELECT and reconnect"); a device reboot is a power cycle. A card
    /// power-off ends a CCID touch wait; a USB reset or power cycle ends both.
    pub fn reset(&mut self, kind: ResetKind) {
        match kind {
            ResetKind::CardPowerOff => self.end_touch_wait(Transport::Ccid),
            ResetKind::UsbReset => self.waits = [None, None],
            ResetKind::PowerCycle => {
                self.sessions = [None, None];
                self.contact = None;
                self.waits = [None, None];
            }
        }
    }

    /// A challenge-response on `transport` now waits for a touch until `deadline`.
    pub(crate) fn begin_touch_wait(&mut self, transport: Transport, deadline: Millis) {
        if let Some(wait) = self.waits.get_mut(transport.index()) {
            *wait = Some(deadline);
        }
    }

    /// The touch wait on `transport` ended (touched, timed out, cancelled or aborted).
    pub(crate) fn end_touch_wait(&mut self, transport: Transport) {
        if let Some(wait) = self.waits.get_mut(transport.index()) {
            *wait = None;
        }
    }

    fn slot(&self, index: usize) -> Option<&SlotState> {
        self.state.slots.get(index).and_then(Option::as_ref)
    }

    fn set_session(&mut self, index: usize, session: Option<Session>) {
        if let Some(entry) = self.sessions.get_mut(index) {
            *entry = session;
        }
    }

    fn fast_trigger(&self) -> bool {
        self.slot(0).is_some_and(|s| s.config.is_touch_triggered()) && self.slot(1).is_none()
    }

    /// Persist `next`, then adopt it (`docs/CONTRACTS.md` persistence rule).
    fn commit(&mut self, next: Persistent, host: &mut dyn Host) -> Result<(), u16> {
        host.persist(Record::Otp, &next.serialize())
            .map_err(|_| sw::MEMORY_FAILURE)?;
        self.state = next;
        Ok(())
    }

    /// Run one slot command on a 64-byte payload.
    ///
    /// `Err(sw)` is a rejection: CCID answers the status word, HID leaves the
    /// programming sequence unchanged so the host sees "not updated".
    pub(crate) fn execute(
        &mut self,
        command: u8,
        payload: &[u8; SLOT_DATA_SIZE],
        mgmt: Option<&mut dyn MgmtBridge>,
        host: &mut dyn Host,
    ) -> Result<Reply, u16> {
        match command {
            cmd::CONFIG1 => self.write_config(0, payload, host),
            cmd::CONFIG2 => self.write_config(1, payload, host),
            cmd::UPDATE1 => self.update_config(0, payload, host),
            cmd::UPDATE2 => self.update_config(1, payload, host),
            cmd::SWAP => self.swap(payload, host),
            // The 5C Nano has no NFC interface: there is no NDEF record to write.
            cmd::NDEF1 | cmd::NDEF2 => Err(sw::FUNC_NOT_SUPPORTED),
            cmd::DEVICE_SERIAL => self.read_serial(mgmt, host),
            cmd::DEVICE_CONFIG => self.write_device_config(payload, mgmt, host),
            cmd::SCAN_MAP => self.write_scan_map(payload, host),
            cmd::YK4_CAPABILITIES => self.read_device_info(payload, mgmt, host),
            cmd::YK4_SET_DEVICE_INFO => self.write_device_info(payload, mgmt, host),
            cmd::CHAL_OTP1 => self.challenge(0, ChallengeKind::Yubico, payload, mgmt, host),
            cmd::CHAL_OTP2 => self.challenge(1, ChallengeKind::Yubico, payload, mgmt, host),
            cmd::CHAL_HMAC1 => self.challenge(0, ChallengeKind::Hmac, payload, mgmt, host),
            cmd::CHAL_HMAC2 => self.challenge(1, ChallengeKind::Hmac, payload, mgmt, host),
            _ => Err(sw::INCORRECT_P1P2),
        }
    }

    /// Access code check: a slot with a nonzero access code accepts a write only with
    /// that code (YubiKey manual "Access code"; compared in constant time).
    fn check_access(&self, index: usize, supplied: &[u8]) -> Result<(), u16> {
        match self.slot(index) {
            Some(slot)
                if slot.config.has_access_code() && !ct_eq(&slot.config.acc_code, supplied) =>
            {
                Err(sw::SECURITY_STATUS)
            }
            _ => Ok(()),
        }
    }

    /// `TKTFLAG_PROTECT_CFG2` ("block update of config 2 unless config 2 is configured
    /// and has this bit set"): checked for every write that replaces slot 2.
    fn check_slot2_protection(&self) -> Result<(), u16> {
        let protects = |index| {
            self.slot(index)
                .is_some_and(|s| s.config.tkt_flags & tkt::PROTECT_CFG2 != 0)
        };
        if protects(0) && !protects(1) {
            Err(sw::CONDITIONS)
        } else {
            Ok(())
        }
    }

    /// CONFIG1/CONFIG2: `payload = config(52) || current access code(6)` (ykpers
    /// `yk_write_command`). An all-zero configuration deletes the slot; deleting an
    /// empty slot is rejected with `6985` (catalog "empty-slot delete").
    fn write_config(
        &mut self,
        index: usize,
        payload: &[u8; SLOT_DATA_SIZE],
        host: &mut dyn Host,
    ) -> Result<Reply, u16> {
        let (config_bytes, supplied) = split_config(payload);
        let replacement = if config_bytes.iter().all(|&b| b == 0) {
            if self.slot(index).is_none() {
                return Err(sw::CONDITIONS);
            }
            None
        } else {
            let config = SlotConfig::parse(config_bytes).ok_or(sw::INCORRECT_DATA)?;
            // RFC 4226 §5.2 moving factor starts at the configured IMF.
            let counter = if config.mode() == Mode::Hotp {
                config.hotp_imf()
            } else {
                0
            };
            Some(SlotState { config, counter })
        };
        self.check_access(index, supplied)?;
        if index == 1 {
            self.check_slot2_protection()?;
        }
        let mut next = self.state.clone();
        if let Some(slot) = next.slots.get_mut(index) {
            *slot = replacement;
        }
        next.pgm_seq = slot_write_sequence(&next, self.state.pgm_seq);
        self.commit(next, host)?;
        self.set_session(index, None);
        Ok(Reply::Status)
    }

    /// UPDATE1/UPDATE2 (YubiKey manual "Update"; `*_UPDATE_MASK` in `ykdef.h`): only
    /// the updatable ticket/config/extended flags and the access code change; keys,
    /// IDs and counters stay. The slot must be configured with `ALLOW_UPDATE` or
    /// `DORMANT`, and `DORMANT` may be toggled (catalog "UPDATE accepts a configured
    /// slot with Allow Update or Dormant"; an activated slot without `ALLOW_UPDATE`
    /// cannot be made dormant again).
    fn update_config(
        &mut self,
        index: usize,
        payload: &[u8; SLOT_DATA_SIZE],
        host: &mut dyn Host,
    ) -> Result<Reply, u16> {
        let (config_bytes, supplied) = split_config(payload);
        let update = SlotConfig::parse(config_bytes).ok_or(sw::INCORRECT_DATA)?;
        let current = self.slot(index).ok_or(sw::CONDITIONS)?;
        if current.config.ext_flags & (ext::ALLOW_UPDATE | ext::DORMANT) == 0 {
            return Err(sw::CONDITIONS);
        }
        self.check_access(index, supplied)?;
        if index == 1 {
            self.check_slot2_protection()?;
        }
        let mut updated = current.clone();
        let config = &mut updated.config;
        config.ext_flags = merge(config.ext_flags, update.ext_flags, ext::UPDATE_MASK);
        config.tkt_flags = merge(config.tkt_flags, update.tkt_flags, tkt::UPDATE_MASK);
        config.cfg_flags = merge(config.cfg_flags, update.cfg_flags, cfg::UPDATE_MASK);
        config.acc_code = update.acc_code;
        let mut next = self.state.clone();
        if let Some(slot) = next.slots.get_mut(index) {
            *slot = Some(updated);
        }
        next.pgm_seq = slot_write_sequence(&next, self.state.pgm_seq);
        self.commit(next, host)?;
        Ok(Reply::Status)
    }

    /// SWAP: exchanges both configurations with their counters and sessions. Both
    /// slots must be configured (catalog "swap requires two configured slots"); each
    /// access-code-protected slot needs its code at the ykpers position (bytes
    /// 52..58), and slot 2 protection applies because slot 2 is replaced.
    fn swap(&mut self, payload: &[u8; SLOT_DATA_SIZE], host: &mut dyn Host) -> Result<Reply, u16> {
        if self.slot(0).is_none() || self.slot(1).is_none() {
            return Err(sw::CONDITIONS);
        }
        let (_, supplied) = split_config(payload);
        self.check_access(0, supplied)?;
        self.check_access(1, supplied)?;
        self.check_slot2_protection()?;
        let mut next = self.state.clone();
        next.slots.swap(0, 1);
        next.pgm_seq = slot_write_sequence(&next, self.state.pgm_seq);
        self.commit(next, host)?;
        self.sessions.swap(0, 1);
        Ok(Reply::Status)
    }

    /// DEVICE_SERIAL: 4-byte big-endian serial (yubikit `get_serial`).
    fn read_serial(
        &mut self,
        mgmt: Option<&mut dyn MgmtBridge>,
        host: &mut dyn Host,
    ) -> Result<Reply, u16> {
        if !self.serial_api_visible() {
            return Err(sw::CONDITIONS);
        }
        let serial = match mgmt {
            Some(bridge) => bridge.serial(host).ok_or(sw::CONDITIONS)?,
            None => host.profile().serial,
        };
        Ok(Reply::Data(serial.to_be_bytes().to_vec()))
    }

    /// DEVICE_CONFIG (legacy mode write, 4 bytes). The programming sequence advances
    /// unless it is 0: yubikit `_ManagementOtpBackend.set_mode` reads the status first
    /// and accepts an unchanged sequence only when that sequence was 0 ("ProgSeq isn't
    /// updated by set mode when empty"); any other value must advance. (A sequence can
    /// be nonzero with no slot configured after a `0x12`/`0x15` write.) It belongs to
    /// Management's record, so the advance is not persisted on its own; the next slot
    /// write persists it.
    fn write_device_config(
        &mut self,
        payload: &[u8; SLOT_DATA_SIZE],
        mgmt: Option<&mut dyn MgmtBridge>,
        host: &mut dyn Host,
    ) -> Result<Reply, u16> {
        let bridge = mgmt.ok_or(sw::FUNC_NOT_SUPPORTED)?;
        bridge.write_device_config(payload.get(..4).unwrap_or(&[]), host)?;
        if self.state.pgm_seq != 0 {
            self.state.pgm_seq = advance(self.state.pgm_seq);
        }
        Ok(Reply::Status)
    }

    /// SCAN_MAP: the first 45 payload bytes replace the scan map (ykpers
    /// `yk_write_scan_map`).
    fn write_scan_map(
        &mut self,
        payload: &[u8; SLOT_DATA_SIZE],
        host: &mut dyn Host,
    ) -> Result<Reply, u16> {
        let map = payload
            .get(..SCAN_MAP_SIZE)
            .and_then(|m| <[u8; SCAN_MAP_SIZE]>::try_from(m).ok());
        let mut next = self.state.clone();
        next.scan_map = map.ok_or(sw::WRONG_LENGTH)?;
        next.pgm_seq = advance(next.pgm_seq);
        self.commit(next, host)?;
        Ok(Reply::Status)
    }

    /// YK4_CAPABILITIES: `length || TLVs` of device-info page `payload[0]` (yubikit
    /// `read_config`, which checks the CRC over `length || TLVs`).
    fn read_device_info(
        &mut self,
        payload: &[u8; SLOT_DATA_SIZE],
        mgmt: Option<&mut dyn MgmtBridge>,
        host: &mut dyn Host,
    ) -> Result<Reply, u16> {
        let bridge = mgmt.ok_or(sw::FUNC_NOT_SUPPORTED)?;
        let page = payload.first().copied().unwrap_or(0);
        let info = bridge.device_info(page, host).ok_or(sw::INCORRECT_DATA)?;
        let len = u8::try_from(info.len()).map_err(|_| sw::UNKNOWN)?;
        let mut out = Vec::with_capacity(info.len() + 1);
        out.push(len);
        out.extend_from_slice(&info);
        Ok(Reply::Data(out))
    }

    /// YK4_SET_DEVICE_INFO: forwards `length || TLVs` to Management. The programming
    /// sequence advances so the host's write check passes (yubikit `write_config`
    /// expects it); like DEVICE_CONFIG this advance is not persisted on its own.
    fn write_device_info(
        &mut self,
        payload: &[u8; SLOT_DATA_SIZE],
        mgmt: Option<&mut dyn MgmtBridge>,
        host: &mut dyn Host,
    ) -> Result<Reply, u16> {
        let bridge = mgmt.ok_or(sw::FUNC_NOT_SUPPORTED)?;
        let len = usize::from(payload.first().copied().unwrap_or(0));
        let data = payload.get(..len + 1).ok_or(sw::WRONG_LENGTH)?;
        bridge.write_device_info(data, host)?;
        self.state.pgm_seq = advance(self.state.pgm_seq);
        Ok(Reply::Status)
    }

    /// CHAL_OTP/CHAL_HMAC (YubiKey manual "Challenge-response"). With
    /// `CFGFLAG_CHAL_BTN_TRIG` the command waits for a touch.
    fn challenge(
        &mut self,
        index: usize,
        kind: ChallengeKind,
        payload: &[u8; SLOT_DATA_SIZE],
        mgmt: Option<&mut dyn MgmtBridge>,
        host: &mut dyn Host,
    ) -> Result<Reply, u16> {
        let slot = self.slot(index).ok_or(sw::CONDITIONS)?;
        let config = &slot.config;
        let matches = matches!(
            (kind, config.mode()),
            (ChallengeKind::Hmac, Mode::HmacChallenge)
                | (ChallengeKind::Yubico, Mode::YubicoChallenge)
        );
        if config.is_dormant() || !matches {
            return Err(sw::CONDITIONS);
        }
        let timeout_s = mgmt.map_or(DEFAULT_CHALRESP_TIMEOUT_S, |m| {
            m.challenge_response_timeout_s()
        });
        let timeout_s = if timeout_s == 0 {
            DEFAULT_CHALRESP_TIMEOUT_S
        } else {
            timeout_s
        };
        let pending = PendingChallenge {
            slot: index,
            kind,
            challenge: *payload,
            config: config.to_bytes(),
            timeout_ms: Millis::from(timeout_s) * 1000,
        };
        if config.cfg_flags & cfg::CHAL_BTN_TRIG != 0 {
            Ok(Reply::NeedTouch(pending))
        } else {
            self.complete_challenge(&pending, host).map(Reply::Data)
        }
    }

    /// Compute a challenge-response, re-checking that the slot still holds the
    /// configuration the challenge was addressed to.
    pub(crate) fn complete_challenge(
        &mut self,
        pending: &PendingChallenge,
        host: &mut dyn Host,
    ) -> Result<Vec<u8>, u16> {
        let slot = self.slot(pending.slot).ok_or(sw::CONDITIONS)?;
        if !ct_eq(&slot.config.to_bytes(), &pending.config) {
            return Err(sw::CONDITIONS);
        }
        let config = slot.config.clone();
        match pending.kind {
            ChallengeKind::Hmac => {
                let lt64 = config.cfg_flags & cfg::HMAC_LT64 != 0;
                Ok(hmac_sha1(&config.secret20(), hmac_message(&pending.challenge, lt64)).to_vec())
            }
            ChallengeKind::Yubico => {
                // The 6-byte challenge replaces the private ID, XORed with it
                // (catalog "nonzero private UID XOR in Yubico challenge-response").
                let mut uid = config.uid;
                for (u, c) in uid.iter_mut().zip(pending.challenge.iter()) {
                    *u ^= c;
                }
                let ticket = self.next_ticket(pending.slot, uid, host)?;
                Ok(ticket.encrypt(&config.key).to_vec())
            }
        }
    }

    /// The next Yubico OTP ticket for slot `index` (YubiKey manual "Yubico OTP"):
    ///
    /// - the first ticket of a power session, and the first after the 8-bit session
    ///   counter wraps, increments the non-volatile usage counter, which is persisted
    ///   before the ticket exists; the counter saturates at `0x7FFF`;
    /// - the session counter starts at 0 and increments per ticket;
    /// - the 24-bit timestamp starts random and runs at 8 Hz from the session start.
    ///
    /// A failed persist leaves counters and session unchanged.
    fn next_ticket(
        &mut self,
        index: usize,
        uid: [u8; 6],
        host: &mut dyn Host,
    ) -> Result<Ticket, u16> {
        let stored = self.slot(index).ok_or(sw::CONDITIONS)?.counter;
        let mut random = [0u8; 5];
        host.fill(&mut random);
        let now = host.now();
        let existing = self.sessions.get(index).copied().flatten();
        let mut session = existing.unwrap_or(Session {
            session_counter: 0,
            timestamp_base: u32::from_le_bytes([random[2], random[3], random[4], 0]),
            started_at: now,
            bump_pending: true,
        });
        let mut use_counter =
            u16::try_from(stored.min(u32::from(MAX_USE_COUNTER))).unwrap_or(MAX_USE_COUNTER);
        if session.bump_pending {
            let bumped = use_counter.saturating_add(1).min(MAX_USE_COUNTER);
            if u32::from(bumped) != stored {
                let mut next = self.state.clone();
                if let Some(Some(slot)) = next.slots.get_mut(index) {
                    slot.counter = u32::from(bumped);
                }
                self.commit(next, host)?;
            }
            use_counter = bumped;
            session.session_counter = 0;
            session.bump_pending = false;
        }
        let ticks = now.saturating_sub(session.started_at).saturating_mul(8) / 1000;
        let timestamp = (u64::from(session.timestamp_base).wrapping_add(ticks)) & 0x00FF_FFFF;
        let ticket = Ticket {
            uid,
            use_counter,
            timestamp: u32::try_from(timestamp).unwrap_or(0),
            session_counter: session.session_counter,
            random: u16::from_le_bytes([random[0], random[1]]),
        };
        session.session_counter = session.session_counter.wrapping_add(1);
        if session.session_counter == 0 {
            session.bump_pending = true;
        }
        self.set_session(index, Some(session));
        Ok(ticket)
    }

    /// Reserve the next HOTP moving factor: persisted as `c + 1` before `c` is used
    /// (RFC 4226 §7.2 counter resynchronisation relies on it never repeating).
    fn next_hotp_counter(&mut self, index: usize, host: &mut dyn Host) -> Result<u32, u16> {
        let counter = self.slot(index).ok_or(sw::CONDITIONS)?.counter;
        let following = counter.checked_add(1).ok_or(sw::CONDITIONS)?;
        let mut next = self.state.clone();
        if let Some(Some(slot)) = next.slots.get_mut(index) {
            slot.counter = following;
        }
        self.commit(next, host)?;
        Ok(counter)
    }

    /// Keyboard output of slot `index`, or nothing if it is not touch-triggered or a
    /// counter could not be persisted.
    ///
    /// Layout (`ykdef.h` ticket flags): `[TAB] [ref] part1 [TAB] [delay] part2 [TAB]
    /// [delay] [ENTER]`, where part 1 is the public ID / token ID / static password
    /// and part 2 the ticket / HOTP value.
    fn emit(&mut self, index: usize, host: &mut dyn Host) -> Vec<[u8; 8]> {
        let Some(slot) = self.slot(index) else {
            return Vec::new();
        };
        if !slot.config.is_touch_triggered() {
            return Vec::new();
        }
        let config = slot.config.clone();
        let body = match config.mode() {
            Mode::YubicoOtp => match self.next_ticket(index, config.uid, host) {
                Ok(ticket) => Body::Modhex(ticket.encrypt(&config.key).to_vec()),
                Err(_) => return Vec::new(),
            },
            Mode::StaticTicket => {
                // Static ticket: the same AES/CRC ticket with frozen (zero) counters;
                // SHORT_TICKET sends half of it.
                let ticket = Ticket {
                    uid: config.uid,
                    use_counter: 0,
                    timestamp: 0,
                    session_counter: 0,
                    random: 0,
                };
                let encrypted = ticket.encrypt(&config.key);
                let len = if config.cfg_flags & cfg::SHORT_TICKET != 0 {
                    8
                } else {
                    16
                };
                Body::Modhex(encrypted.get(..len).unwrap_or(&encrypted).to_vec())
            }
            Mode::StaticPassword => Body::None,
            Mode::Hotp => match self.next_hotp_counter(index, host) {
                Ok(counter) => {
                    let digits = if config.cfg_flags & cfg::OATH_HOTP8 != 0 {
                        8
                    } else {
                        6
                    };
                    Body::Digits(hotp(&config.secret20(), u64::from(counter), digits), digits)
                }
                Err(_) => return Vec::new(),
            },
            Mode::HmacChallenge | Mode::YubicoChallenge => return Vec::new(),
        };
        let scan_map = self.state.scan_map;
        let pacing = if config.cfg_flags & cfg::PACING_10MS != 0 {
            10
        } else {
            0
        } + if config.cfg_flags & cfg::PACING_20MS != 0 {
            20
        } else {
            0
        };
        let mut typist = Typist::new(
            &scan_map,
            pacing,
            config.ext_flags & ext::USE_NUMERIC_KEYPAD != 0,
        );
        let tkt = config.tkt_flags;
        if tkt & tkt::TAB_FIRST != 0 {
            typist.tab();
        }
        match config.mode() {
            Mode::YubicoOtp | Mode::StaticTicket => {
                if sends_reference(&config) {
                    for nibble in 0..16 {
                        typist.modhex_nibble(nibble);
                    }
                }
                typist.modhex(config.fixed_part());
            }
            Mode::StaticPassword => {
                let codes: [u8; SCAN_CODES_SIZE] = config.scan_codes();
                for &code in codes.iter().take_while(|&&c| c != 0) {
                    typist.scan(code);
                }
            }
            Mode::Hotp => {
                let modhex_bytes = match config.cfg_flags & cfg::OATH_FIXED_MODHEX {
                    cfg::OATH_FIXED_MODHEX => usize::MAX,
                    cfg::OATH_FIXED_MODHEX2 => 2,
                    cfg::OATH_FIXED_MODHEX1 => 1,
                    _ => 0,
                };
                for (i, &byte) in config.fixed_part().iter().enumerate() {
                    if i < modhex_bytes {
                        typist.modhex(&[byte]);
                    } else {
                        typist.numeric_byte(byte);
                    }
                }
            }
            Mode::HmacChallenge | Mode::YubicoChallenge => {}
        }
        if tkt & tkt::APPEND_TAB1 != 0 {
            typist.tab();
        }
        if tkt & tkt::APPEND_DELAY1 != 0 {
            typist.delay(APPEND_DELAY_MS);
        }
        match body {
            Body::Modhex(bytes) => typist.modhex(&bytes),
            Body::Digits(value, digits) => {
                let text = format!("{value:0width$}", width = digits as usize);
                for c in text.bytes() {
                    typist.digit(c.wrapping_sub(b'0'));
                }
            }
            Body::None => {}
        }
        if tkt & tkt::APPEND_TAB2 != 0 {
            typist.tab();
        }
        if tkt & tkt::APPEND_DELAY2 != 0 {
            typist.delay(APPEND_DELAY_MS);
        }
        if tkt & tkt::APPEND_CR != 0 {
            typist.enter();
        }
        typist.finish()
    }
}

/// The dynamic second part of a keyboard emission.
enum Body {
    Modhex(Vec<u8>),
    Digits(u32, u32),
    None,
}

/// Whether the keyboard output starts with the modhex reference string `0..F`
/// (`CFGFLAG_SEND_REF`, "send reference string (0..F) before data"). In static-ticket
/// mode `SEND_REF` together with `CFGFLAG_STRONG_PW2` is the "special character" option
/// of the strong password policy (yubikit `StaticTicketSlotConfiguration.strong_password`
/// sets `SEND_REF` only as `special`, and only with `STRONG_PW2`), not a reference
/// string, so nothing extra is typed then. (The strong-password transforms themselves
/// are not modelled; see `docs/catalog/otp.md`.)
fn sends_reference(config: &SlotConfig) -> bool {
    let strong_special = config.mode() == Mode::StaticTicket
        && config.cfg_flags & cfg::STRONG_PW2 != 0;
    config.cfg_flags & cfg::SEND_REF != 0 && !strong_special
}

/// Split a payload into the configuration and the current access code.
fn split_config(payload: &[u8; SLOT_DATA_SIZE]) -> (&[u8], &[u8]) {
    let (config, rest) = payload.split_at(CONFIG_SIZE);
    (config, rest.get(..ACC_CODE_SIZE).unwrap_or(&[]))
}

fn merge(old: u8, new: u8, mask: u8) -> u8 {
    (old & !mask) | (new & mask)
}

/// Programming-sequence increment (never wraps back to the "no configuration" 0).
fn advance(seq: u8) -> u8 {
    match seq.wrapping_add(1) {
        0 => 1,
        n => n,
    }
}

/// After a slot write: 0 when no slot remains configured, otherwise the next value
/// (`ykdef.h` "pgmSeq: 0 if no valid configuration"; yubikit accepts either).
fn slot_write_sequence(next: &Persistent, current: u8) -> u8 {
    if next.any_configured() {
        advance(current)
    } else {
        0
    }
}

/// The HMAC message of a 64-byte challenge. With `HMAC_LT64` the trailing bytes equal
/// to the last byte are padding and are removed (yubikit pads with a byte different
/// from the challenge's last); at least one byte always remains, so an empty
/// challenge (64 zero bytes) is the single byte `00` (catalog "LT64 empty HMAC
/// challenge maps to a single zero byte").
fn hmac_message(challenge: &[u8; SLOT_DATA_SIZE], lt64: bool) -> &[u8] {
    if !lt64 {
        return challenge;
    }
    let pad = challenge[SLOT_DATA_SIZE - 1];
    let len = challenge
        .iter()
        .rposition(|&b| b != pad)
        .map_or(1, |p| p + 1);
    challenge.get(..len).unwrap_or(challenge)
}

/// RFC 4226 §5.3 HOTP value with `digits` digits.
fn hotp(secret: &[u8], counter: u64, digits: u32) -> u32 {
    let mac = hmac_sha1(secret, &counter.to_be_bytes());
    let offset = usize::from(mac[19] & 0x0F);
    let word = mac
        .get(offset..offset + 4)
        .and_then(|w| <[u8; 4]>::try_from(w).ok())
        .map_or(0, u32::from_be_bytes);
    (word & 0x7FFF_FFFF) % 10u32.pow(digits.min(9))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4226 Appendix D: secret "12345678901234567890", counters 0..9.
    #[test]
    fn hotp_matches_rfc4226_appendix_d() {
        let expected = [
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];
        for (counter, value) in expected.into_iter().enumerate() {
            assert_eq!(hotp(b"12345678901234567890", counter as u64, 6), value);
        }
    }

    #[test]
    fn lt64_strips_padding_but_keeps_one_byte() {
        let mut challenge = [0u8; 64];
        assert_eq!(hmac_message(&challenge, true), &[0u8][..]);
        challenge[..2].copy_from_slice(b"ab");
        assert_eq!(hmac_message(&challenge, true), b"ab");
        assert_eq!(hmac_message(&challenge, false).len(), 64);
        let mut ones = [1u8; 64];
        ones[0] = 0;
        assert_eq!(hmac_message(&ones, true), &[0u8][..]);
    }

    #[test]
    fn hold_windows() {
        assert_eq!(classify_hold(299), None);
        assert_eq!(classify_hold(300), Some(Press::Short));
        assert_eq!(classify_hold(1500), Some(Press::Short));
        assert_eq!(classify_hold(2000), None);
        assert_eq!(classify_hold(2500), Some(Press::Long));
        assert_eq!(classify_hold(5000), Some(Press::Long));
        assert_eq!(classify_hold(5001), None);
    }

    #[test]
    fn sequence_never_wraps_to_zero() {
        assert_eq!(advance(0), 1);
        assert_eq!(advance(254), 255);
        assert_eq!(advance(255), 1);
    }
}
