//! The single-slot CCID state machine (USB CCID Rev 1.1 §5.3.1, §6.1–§6.3).

use crate::chain::{CommandChain, ResponseChain};
use crate::descriptor::YUBIKEY_COMPAT;
use crate::message::msg_type::{
    PC_TO_RDR_ABORT, PC_TO_RDR_GET_PARAMETERS, PC_TO_RDR_GET_SLOT_STATUS, PC_TO_RDR_ICC_CLOCK,
    PC_TO_RDR_ICC_POWER_OFF, PC_TO_RDR_ICC_POWER_ON, PC_TO_RDR_MECHANICAL,
    PC_TO_RDR_RESET_PARAMETERS, PC_TO_RDR_SET_DATA_RATE_AND_CLOCK_FREQUENCY,
    PC_TO_RDR_SET_PARAMETERS, PC_TO_RDR_T0_APDU, PC_TO_RDR_XFR_BLOCK, RDR_TO_PC_DATA_BLOCK,
    RDR_TO_PC_DATA_RATE_AND_CLOCK_FREQUENCY, RDR_TO_PC_NOTIFY_SLOT_CHANGE, RDR_TO_PC_PARAMETERS,
    RDR_TO_PC_SLOT_STATUS,
};
use crate::message::{HEADER_LEN, Header, Reply, chain, error, level, response_type, status};
use crate::params::{PROTOCOL_T1, T1Parameters};

/// The only slot (`bMaxSlotIndex` = 0).
const SLOT: u8 = 0;
/// `bError` of a time-extension reply: the BWT multiplier (§6.2.6).
const WTX_MULTIPLIER: u8 = 1;
/// `bClockStatus` 0: the clock is running (§6.2.2). The CCID cannot stop the ICC
/// clock (`dwFeatures` lacks [`crate::descriptor::feature::CLOCK_STOP`]).
const CLOCK_RUNNING: u8 = 0x00;

/// What the device must do with one bulk-out message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CcidAction {
    /// Send this bulk-in message.
    Reply(Vec<u8>),
    /// Hand this complete command APDU to the card session, then send
    /// [`Ccid::apdu_response`] for the same `seq`. Until then the slot is busy.
    Apdu { seq: u8, apdu: Vec<u8> },
    /// The card session ended: reset the card applets
    /// (`lk_core::ResetKind::CardPowerOff`), then send this bulk-in message.
    ///
    /// Returned for `PC_to_RDR_IccPowerOff`, and for `PC_to_RDR_IccPowerOn` while the
    /// ICC is already active (a warm reset with a new ATR).
    PowerOff(Vec<u8>),
}

/// Power and activity of the slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    /// ICC present, not powered: XfrBlock is refused until IccPowerOn.
    Inactive,
    /// ICC powered and idle.
    Active,
    /// ICC powered; the APDU of XfrBlock `seq` is with the card session.
    Busy { seq: u8 },
}

/// Progress of the two-step abort (§5.3.1: control `ABORT` and bulk `PC_to_RDR_Abort`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Abort {
    Idle,
    /// The control request came first; every bulk message except the matching
    /// `PC_to_RDR_Abort` fails with `CMD_ABORTED`.
    AwaitingBulk {
        seq: u8,
    },
    /// The bulk message came first and already aborted; a matching control request
    /// is then a no-op. Kept until that request arrives, a newer bulk Abort replaces
    /// it, or [`Ccid::reset`]: the host may already have sent further messages when a
    /// late control request arrives, and it must not wedge the slot in
    /// [`Abort::AwaitingBulk`].
    BulkFirst {
        seq: u8,
    },
}

/// One CCID slot with an APDU-level ICC behind it.
///
/// The CCID answers every bulk-out message with one bulk-in message, except XfrBlock
/// carrying a complete APDU, which the device answers later with
/// [`Ccid::apdu_response`] (or [`Ccid::time_extension`] while it waits).
#[derive(Debug)]
pub struct Ccid {
    atr: Vec<u8>,
    defaults: T1Parameters,
    params: T1Parameters,
    slot: Slot,
    command: CommandChain,
    response: ResponseChain,
    abort: Abort,
}

impl Ccid {
    /// A slot whose ICC answers IccPowerOn with `atr`. The ICC starts inactive.
    pub fn new(atr: Vec<u8>) -> Self {
        let defaults = T1Parameters::from_atr(&atr);
        Self {
            atr,
            defaults,
            params: defaults,
            slot: Slot::Inactive,
            command: CommandChain::default(),
            response: ResponseChain::default(),
            abort: Abort::Idle,
        }
    }

    /// Process one complete bulk-out message, header included.
    ///
    /// Checks, in order: a header is present; `bSlot` is 0 (`bError` 5); `dwLength`
    /// matches the message and the command (`bError` 1); an abort started by
    /// [`Ccid::control_abort`] is not pending (`CMD_ABORTED`); the slot is not busy
    /// (`CMD_SLOT_BUSY`, except for `PC_to_RDR_Abort`). Failed replies use the
    /// response type paired with the command. A failed `RDR_to_PC_Parameters` for
    /// slot 0 still carries the T=1 structure in force (§6.2.3), and a failed
    /// `RDR_to_PC_DataRateAndClockFrequency` the clock and rate (§6.2.5 fixes
    /// `dwLength` at 8); other failed replies carry no data.
    pub fn message(&mut self, msg: &[u8]) -> CcidAction {
        let Some(h) = Header::parse(msg) else {
            return CcidAction::Reply(self.truncated(msg));
        };
        if h.slot != SLOT {
            let kind = response_type(h.msg_type);
            let reply = self.failed(kind, h.slot, h.seq, status::ICC_ABSENT, error::INDEX_SLOT);
            return CcidAction::Reply(reply);
        }
        if !h.length_matches(msg) || msg.len() > self.max_message_len() || !fixed_length_ok(&h) {
            return self.fail(&h, error::INDEX_DW_LENGTH);
        }
        if let Abort::AwaitingBulk { seq } = self.abort
            && !(h.msg_type == PC_TO_RDR_ABORT && h.seq == seq)
        {
            return self.fail(&h, error::CMD_ABORTED);
        }
        if matches!(self.slot, Slot::Busy { .. }) && h.msg_type != PC_TO_RDR_ABORT {
            return self.fail(&h, error::CMD_SLOT_BUSY);
        }
        let data = msg.get(HEADER_LEN..).unwrap_or_default();
        match h.msg_type {
            PC_TO_RDR_ICC_POWER_ON => self.power_on(&h),
            PC_TO_RDR_ICC_POWER_OFF => self.power_off(&h),
            PC_TO_RDR_GET_SLOT_STATUS => CcidAction::Reply(self.slot_status(&h)),
            PC_TO_RDR_XFR_BLOCK => self.xfr_block(&h, data),
            PC_TO_RDR_GET_PARAMETERS => CcidAction::Reply(self.parameters(&h, None)),
            PC_TO_RDR_RESET_PARAMETERS => {
                self.params = self.defaults;
                CcidAction::Reply(self.parameters(&h, None))
            }
            PC_TO_RDR_SET_PARAMETERS => self.set_parameters(&h, data),
            PC_TO_RDR_ABORT => self.bulk_abort(&h),
            PC_TO_RDR_SET_DATA_RATE_AND_CLOCK_FREQUENCY => self.set_data_rate(&h, data),
            // Not supported, like unknown types: Escape (no vendor commands), IccClock
            // (dwFeatures lacks clock stop 0x100), T0APDU (dwProtocols = T=1 only),
            // Secure (bPINSupport = 0) and Mechanical (dwMechanical = 0).
            _ => self.fail(&h, error::CMD_NOT_SUPPORTED),
        }
    }

    /// The `RDR_to_PC_DataBlock` carrying the card's `response` to XfrBlock `seq`.
    ///
    /// A response longer than one message is split with `bChainParameter` `01`; the
    /// host fetches the rest with `wLevelParameter` `0010`. Returns an empty vector,
    /// meaning "send nothing", if no APDU with this `seq` is outstanding (it was
    /// aborted, or the slot was powered off or reset meanwhile).
    pub fn apdu_response(&mut self, seq: u8, response: &[u8]) -> Vec<u8> {
        if self.slot != (Slot::Busy { seq }) {
            return Vec::new();
        }
        self.slot = Slot::Active;
        let (chain, part) = self
            .response
            .start(response, YUBIKEY_COMPAT.max_data_len());
        Reply::ok(RDR_TO_PC_DATA_BLOCK, SLOT, seq, status::ICC_ACTIVE)
            .with_byte9(chain)
            .encode(&part)
    }

    /// A time-extension `RDR_to_PC_DataBlock` for XfrBlock `seq`: `bStatus` `80`,
    /// `bError` = BWT multiplier 1 (§6.2.6).
    pub fn time_extension(&self, seq: u8) -> Vec<u8> {
        Reply {
            kind: RDR_TO_PC_DATA_BLOCK,
            slot: SLOT,
            seq,
            status: status::TIME_EXTENSION | status::ICC_ACTIVE,
            error: WTX_MULTIPLIER,
            byte9: 0,
        }
        .encode(&[])
    }

    /// `RDR_to_PC_NotifySlotChange` for slot 0 (§6.3.1): bit 0 is the ICC presence,
    /// bit 1 says it changed.
    pub fn slot_change(&self, present: bool) -> Vec<u8> {
        vec![RDR_TO_PC_NOTIFY_SLOT_CHANGE, 0x02 | u8::from(present)]
    }

    /// USB reset, re-enumeration or resume: the ICC becomes inactive and needs a new
    /// IccPowerOn; outstanding APDUs, chains and aborts are forgotten.
    pub fn reset(&mut self) {
        self.slot = Slot::Inactive;
        self.params = self.defaults;
        self.command.clear();
        self.response.clear();
        self.abort = Abort::Idle;
    }

    /// The class-specific control request `ABORT` (§5.3.1), `wValue` = `bSeq << 8 | bSlot`.
    ///
    /// Stops the slot's activity. If an APDU was outstanding, returns its failed
    /// `RDR_to_PC_DataBlock` (`CMD_ABORTED`) to send now. Until the bulk
    /// `PC_to_RDR_Abort` with the same `bSeq` arrives, other bulk messages fail with
    /// `CMD_ABORTED`. If that bulk message already arrived (it was the latest bulk
    /// Abort, whatever came after it), this is a no-op: a request delivered late must
    /// not stop newer activity or block later messages (`docs/CONTRACTS.md` "Phase 0 as
    /// implemented", lk-ccid).
    pub fn control_abort(&mut self, slot: u8, seq: u8) -> Option<Vec<u8>> {
        if slot != SLOT {
            return None;
        }
        if self.abort == (Abort::BulkFirst { seq }) {
            self.abort = Abort::Idle;
            return None;
        }
        self.abort = Abort::AwaitingBulk { seq };
        let aborted = self.stop_activity()?;
        let reply = Reply::failed(
            RDR_TO_PC_DATA_BLOCK,
            SLOT,
            aborted,
            status::ICC_ACTIVE,
            error::CMD_ABORTED,
        );
        Some(reply.encode(&[]))
    }

    /// The `bSeq` of the XfrBlock whose APDU is with the card session, if any.
    pub fn pending_seq(&self) -> Option<u8> {
        match self.slot {
            Slot::Busy { seq } => Some(seq),
            Slot::Inactive | Slot::Active => None,
        }
    }

    /// Whether the ICC is powered.
    pub fn is_active(&self) -> bool {
        self.slot != Slot::Inactive
    }

    /// The T=1 parameters in force.
    pub fn parameters_in_force(&self) -> T1Parameters {
        self.params
    }

    /// The ATR returned by IccPowerOn.
    pub fn atr(&self) -> &[u8] {
        &self.atr
    }

    fn max_message_len(&self) -> usize {
        HEADER_LEN + YUBIKEY_COMPAT.max_data_len()
    }

    fn icc_status(&self) -> u8 {
        match self.slot {
            Slot::Inactive => status::ICC_INACTIVE,
            Slot::Active | Slot::Busy { .. } => status::ICC_ACTIVE,
        }
    }

    fn fail(&self, h: &Header, error: u8) -> CcidAction {
        let kind = response_type(h.msg_type);
        CcidAction::Reply(self.failed(kind, h.slot, h.seq, self.icc_status(), error))
    }

    /// A failed reply of type `kind` (`bmCommandStatus` 1, §6.2.6).
    ///
    /// The body keeps the layout the reply type fixes:
    /// - `RDR_to_PC_DataRateAndClockFrequency` always carries the clock frequency and
    ///   data rate in force (§6.2.5: `dwLength` is `00000008h`);
    /// - `RDR_to_PC_Parameters` for slot 0 carries the T=1 structure in force
    ///   (§6.2.3: `bProtocolNum` 1, `dwLength` 7), so a failed reply never claims a
    ///   T=0 structure without its bytes. A slot that does not exist has no protocol,
    ///   so that reply is empty;
    /// - every other failed reply has no `abData`.
    fn failed(&self, kind: u8, slot: u8, seq: u8, icc: u8, error: u8) -> Vec<u8> {
        let reply = Reply::failed(kind, slot, seq, icc, error);
        match kind {
            RDR_TO_PC_PARAMETERS if slot == SLOT => reply
                .with_byte9(PROTOCOL_T1)
                .encode(&self.params.to_bytes()),
            RDR_TO_PC_DATA_RATE_AND_CLOCK_FREQUENCY => reply.encode(&clock_and_rate()),
            _ => reply.encode(&[]),
        }
    }

    /// Reply to a message shorter than its header: whatever header bytes exist are
    /// echoed and `bError` names `dwLength`.
    fn truncated(&self, msg: &[u8]) -> Vec<u8> {
        let byte = |i: usize| msg.get(i).copied().unwrap_or(0);
        let slot = byte(5);
        let icc = if slot == SLOT {
            self.icc_status()
        } else {
            status::ICC_ABSENT
        };
        self.failed(
            response_type(byte(0)),
            slot,
            byte(6),
            icc,
            error::INDEX_DW_LENGTH,
        )
    }

    /// Drop chains; if an APDU was outstanding, forget it and return its `bSeq`.
    fn stop_activity(&mut self) -> Option<u8> {
        self.command.clear();
        self.response.clear();
        let aborted = self.pending_seq();
        if aborted.is_some() {
            self.slot = Slot::Active;
        }
        aborted
    }

    fn ok(&self, kind: u8, h: &Header) -> Reply {
        Reply::ok(kind, h.slot, h.seq, self.icc_status())
    }

    fn slot_status(&self, h: &Header) -> Vec<u8> {
        self.ok(RDR_TO_PC_SLOT_STATUS, h)
            .with_byte9(CLOCK_RUNNING)
            .encode(&[])
    }

    /// §6.1.1: `bPowerSelect` 0 (automatic) or 1–3 (5 V, 3 V, 1.8 V, all advertised
    /// in `bVoltageSupport` = 7).
    fn power_on(&mut self, h: &Header) -> CcidAction {
        if h.specific[0] > 3 {
            return self.fail(h, error::INDEX_POWER_SELECT);
        }
        let warm = self.slot != Slot::Inactive;
        self.slot = Slot::Active;
        self.params = self.defaults;
        self.command.clear();
        self.response.clear();
        let reply = self.ok(RDR_TO_PC_DATA_BLOCK, h).encode(&self.atr);
        if warm {
            CcidAction::PowerOff(reply)
        } else {
            CcidAction::Reply(reply)
        }
    }

    /// §6.1.2: always succeeds, even if the ICC is already inactive.
    fn power_off(&mut self, h: &Header) -> CcidAction {
        self.slot = Slot::Inactive;
        self.params = self.defaults;
        self.command.clear();
        self.response.clear();
        CcidAction::PowerOff(self.slot_status(h))
    }

    /// §6.1.4 with the extended APDU level `wLevelParameter` values.
    fn xfr_block(&mut self, h: &Header, data: &[u8]) -> CcidAction {
        if self.slot == Slot::Inactive {
            // Model policy: an unpowered ICC does not answer, as for a mute card.
            return self.fail(h, error::ICC_MUTE);
        }
        let level_parameter = u16::from_le_bytes([h.specific[1], h.specific[2]]);
        let chain_open = self.command.is_open();
        match level_parameter {
            level::BEGIN_AND_END if !chain_open => {
                self.response.clear();
                self.dispatch(h, data.to_vec())
            }
            level::BEGIN if !chain_open => {
                self.response.clear();
                self.command.begin(data);
                self.command_continuation(h)
            }
            level::CONTINUE if chain_open => match self.command.append(data) {
                Ok(()) => self.command_continuation(h),
                Err(_) => self.fail(h, error::INDEX_DW_LENGTH),
            },
            level::END if chain_open => match self.command.finish(data) {
                Ok(apdu) => self.dispatch(h, apdu),
                Err(_) => self.fail(h, error::INDEX_DW_LENGTH),
            },
            level::RESPONSE_CONTINUATION
                if !chain_open && data.is_empty() && self.response.is_pending() =>
            {
                let max = YUBIKEY_COMPAT.max_data_len();
                let (chain, part) = self.response.next(max).unwrap_or_default();
                CcidAction::Reply(
                    self.ok(RDR_TO_PC_DATA_BLOCK, h)
                        .with_byte9(chain)
                        .encode(&part),
                )
            }
            _ => {
                // Out-of-order or unknown wLevelParameter: drop all chaining state.
                self.command.clear();
                self.response.clear();
                self.fail(h, error::INDEX_LEVEL_PARAMETER)
            }
        }
    }

    /// Hand a complete APDU to the card session; an empty one is refused.
    fn dispatch(&mut self, h: &Header, apdu: Vec<u8>) -> CcidAction {
        if apdu.is_empty() {
            return self.fail(h, error::INDEX_DW_LENGTH);
        }
        self.slot = Slot::Busy { seq: h.seq };
        CcidAction::Apdu { seq: h.seq, apdu }
    }

    /// Empty DataBlock with `bChainParameter` `10`: send the next command part.
    fn command_continuation(&self, h: &Header) -> CcidAction {
        let reply = self
            .ok(RDR_TO_PC_DATA_BLOCK, h)
            .with_byte9(chain::COMMAND_CONTINUATION);
        CcidAction::Reply(reply.encode(&[]))
    }

    /// `RDR_to_PC_Parameters` with the T=1 parameters in force; `error` marks a rejection.
    fn parameters(&self, h: &Header, error: Option<u8>) -> Vec<u8> {
        match error {
            None => self
                .ok(RDR_TO_PC_PARAMETERS, h)
                .with_byte9(PROTOCOL_T1)
                .encode(&self.params.to_bytes()),
            Some(e) => self.failed(RDR_TO_PC_PARAMETERS, h.slot, h.seq, self.icc_status(), e),
        }
    }

    /// §6.1.7: only T=1 (`bProtocolNum` 1, `dwLength` 7), validated atomically.
    fn set_parameters(&mut self, h: &Header, data: &[u8]) -> CcidAction {
        if h.specific[0] != PROTOCOL_T1 {
            return CcidAction::Reply(self.parameters(h, Some(error::INDEX_PROTOCOL_NUM)));
        }
        let Ok(block) = <&[u8; T1Parameters::LEN]>::try_from(data) else {
            return self.fail(h, error::INDEX_DW_LENGTH);
        };
        match self.defaults.validate(block) {
            Ok(params) => {
                self.params = params;
                CcidAction::Reply(self.parameters(h, None))
            }
            Err(offset) => CcidAction::Reply(self.parameters(h, Some(offset))),
        }
    }

    /// §6.1.13 without a preceding control request, or completing one.
    fn bulk_abort(&mut self, h: &Header) -> CcidAction {
        if self.abort == (Abort::AwaitingBulk { seq: h.seq }) {
            self.abort = Abort::Idle;
        } else {
            self.stop_activity();
            self.abort = Abort::BulkFirst { seq: h.seq };
        }
        CcidAction::Reply(self.slot_status(h))
    }

    /// §6.1.14: `bNumClockSupported` and `bNumDataRatesSupported` are 0 and the
    /// default equals the maximum, so only 4000 kHz and 307 200 bps exist.
    fn set_data_rate(&self, h: &Header, data: &[u8]) -> CcidAction {
        let word = |i: usize| {
            data.get(i..i + 4)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map_or(0, u32::from_le_bytes)
        };
        let (clock, rate) = (word(0), word(4));
        let error = if clock != YUBIKEY_COMPAT.default_clock_khz {
            Some(error::INDEX_CLOCK_FREQUENCY)
        } else if rate != YUBIKEY_COMPAT.data_rate_bps {
            Some(error::INDEX_DATA_RATE)
        } else {
            None
        };
        let kind = RDR_TO_PC_DATA_RATE_AND_CLOCK_FREQUENCY;
        CcidAction::Reply(match error {
            None => self.ok(kind, h).encode(&clock_and_rate()),
            Some(e) => self.failed(kind, h.slot, h.seq, self.icc_status(), e),
        })
    }
}

/// `dwClockFrequency` and `dwDataRate` of `RDR_to_PC_DataRateAndClockFrequency`
/// (§6.2.5): the only clock and rate the descriptor offers.
fn clock_and_rate() -> [u8; 8] {
    let [c0, c1, c2, c3] = YUBIKEY_COMPAT.default_clock_khz.to_le_bytes();
    let [r0, r1, r2, r3] = YUBIKEY_COMPAT.data_rate_bps.to_le_bytes();
    [c0, c1, c2, c3, r0, r1, r2, r3]
}

/// `dwLength` of the commands whose size the specification fixes (§6.1).
fn fixed_length_ok(h: &Header) -> bool {
    let expected = match h.msg_type {
        PC_TO_RDR_ICC_POWER_ON
        | PC_TO_RDR_ICC_POWER_OFF
        | PC_TO_RDR_GET_SLOT_STATUS
        | PC_TO_RDR_GET_PARAMETERS
        | PC_TO_RDR_RESET_PARAMETERS
        | PC_TO_RDR_ICC_CLOCK
        | PC_TO_RDR_T0_APDU
        | PC_TO_RDR_MECHANICAL
        | PC_TO_RDR_ABORT => 0,
        PC_TO_RDR_SET_DATA_RATE_AND_CLOCK_FREQUENCY => 8,
        _ => return true,
    };
    h.length == expected
}
