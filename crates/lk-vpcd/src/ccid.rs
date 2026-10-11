//! The host side of USB CCID, pure: the bulk-out messages this transport sends and the
//! bulk-in replies it reads (USB CCID Rev 1.1 §6.1, §6.2), the `bSeq` counter, the abort of
//! a command (§5.3.1, §6.1.13), and the exchange of one APDU at extended APDU level with
//! command and response chaining (§6.1.4 `wLevelParameter`, §6.2.1 `bChainParameter`).
//!
//! The values here are written from the CCID specification, not taken from the engine's
//! `lk-ccid`, so the two sides check each other in the end-to-end tests.

use std::fmt;

/// Size of the header of every bulk message (§6.1, §6.2): `bMessageType`, `dwLength`
/// (little endian, the size of `abData`), `bSlot`, `bSeq` and three message-specific
/// bytes.
pub const HEADER_LEN: usize = 10;

/// The only slot used (the engine's reader has `bMaxSlotIndex` 0).
pub const SLOT: u8 = 0;

/// `bMessageType` values (§6.1, §6.2).
pub mod msg_type {
    /// `PC_to_RDR_IccPowerOn` (§6.1.1).
    pub const ICC_POWER_ON: u8 = 0x62;
    /// `PC_to_RDR_IccPowerOff` (§6.1.2).
    pub const ICC_POWER_OFF: u8 = 0x63;
    /// `PC_to_RDR_XfrBlock` (§6.1.4).
    pub const XFR_BLOCK: u8 = 0x6F;
    /// `PC_to_RDR_Abort` (§6.1.13): answered with a SlotStatus.
    pub const ABORT: u8 = 0x72;
    /// `RDR_to_PC_DataBlock` (§6.2.1): the reply to IccPowerOn and XfrBlock.
    pub const DATA_BLOCK: u8 = 0x80;
    /// `RDR_to_PC_SlotStatus` (§6.2.2): the reply to IccPowerOff.
    pub const SLOT_STATUS: u8 = 0x81;
}

/// `bPowerSelect` of IccPowerOn: automatic voltage selection (§6.1.1).
pub const POWER_SELECT_AUTOMATIC: u8 = 0x00;

/// `wLevelParameter` of XfrBlock at extended APDU level (§6.1.4).
pub mod level {
    /// The command APDU begins and ends with this message.
    pub const BEGIN_AND_END: u16 = 0x0000;
    /// The command APDU begins with this message and continues in the next.
    pub const BEGIN: u16 = 0x0001;
    /// This message continues and ends the command APDU.
    pub const END: u16 = 0x0002;
    /// This message continues the command APDU; another follows.
    pub const CONTINUE: u16 = 0x0003;
    /// Empty `abData`: the next part of the response APDU is wanted.
    pub const RESPONSE_CONTINUATION: u16 = 0x0010;
}

/// `bChainParameter` of DataBlock at extended APDU level (§6.2.1).
pub mod chain {
    /// The response APDU begins and ends in this message.
    pub const BEGIN_AND_END: u8 = 0x00;
    /// The response APDU begins with this message and continues.
    pub const BEGIN: u8 = 0x01;
    /// This message continues and ends the response APDU.
    pub const END: u8 = 0x02;
    /// This message continues the response APDU; another follows.
    pub const CONTINUE: u8 = 0x03;
    /// Empty `abData`: the reader expects the next part of the command APDU.
    pub const COMMAND_CONTINUATION: u8 = 0x10;
}

/// The smallest `dwMaxCCIDMessageLength` for a reader with extended APDU level exchange:
/// a short APDU (261 bytes) plus the header (§5.1, Table 5.1-1).
pub const MIN_MESSAGE_LENGTH: usize = 261 + HEADER_LEN;
/// The largest `dwMaxCCIDMessageLength` §5.1 allows: an extended APDU (65 544 bytes)
/// plus the header.
pub const MAX_MESSAGE_LENGTH: usize = 65_544 + HEADER_LEN;
/// Offset of `dwMaxCCIDMessageLength` in the CCID class descriptor (§5.1: `bLength`,
/// `bDescriptorType`, `bcdCCID`, `bMaxSlotIndex`, `bVoltageSupport`, `dwProtocols`,
/// `dwDefaultClock`, `dwMaximumClock`, `bNumClockSupported`, `dwDataRate`,
/// `dwMaxDataRate`, `bNumDataRatesSupported`, `dwMaxIFSD`, `dwSynchProtocols`,
/// `dwMechanical`, `dwFeatures`, then this field).
pub const MAX_MESSAGE_LENGTH_OFFSET: usize = 44;

/// The largest response APDU assembled from a chain: Ne of an extended APDU (65 536,
/// ISO/IEC 7816-4 §5.1) plus the status word. A chain that grows beyond it is a fault.
pub const MAX_RESPONSE: usize = 65_536 + 2;

/// The most `abData` one bulk-out message may carry for the reader described by
/// `class_descriptor`: its `dwMaxCCIDMessageLength` minus the header, kept within the
/// bounds of §5.1. A descriptor too short to hold the field gives the smallest bound.
pub fn max_data_len(class_descriptor: &[u8]) -> usize {
    let field = class_descriptor
        .get(MAX_MESSAGE_LENGTH_OFFSET..MAX_MESSAGE_LENGTH_OFFSET + 4)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_le_bytes)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(MIN_MESSAGE_LENGTH);
    field.clamp(MIN_MESSAGE_LENGTH, MAX_MESSAGE_LENGTH) - HEADER_LEN
}

/// The `bSeq` counter: every bulk-out message gets the next value, wrapping after `FF`
/// (§6.1: "sequence number for command"; the reply carries the same value).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sequence(u8);

impl Sequence {
    /// A counter whose first value is `first`.
    pub fn starting_at(first: u8) -> Sequence {
        Sequence(first)
    }

    /// The value for the next message.
    pub fn take(&mut self) -> u8 {
        let seq = self.0;
        self.0 = self.0.wrapping_add(1);
        seq
    }
}

/// A bulk-out message with header and data.
fn message(kind: u8, seq: u8, specific: [u8; 3], data: &[u8]) -> Vec<u8> {
    // Callers pass at most `MAX_MESSAGE_LENGTH` bytes, far below `u32::MAX`.
    let length = u32::try_from(data.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(HEADER_LEN + data.len());
    out.push(kind);
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(&[SLOT, seq]);
    out.extend_from_slice(&specific);
    out.extend_from_slice(data);
    out
}

/// `PC_to_RDR_IccPowerOn` with automatic voltage selection (§6.1.1).
pub fn icc_power_on(seq: u8) -> Vec<u8> {
    message(msg_type::ICC_POWER_ON, seq, [POWER_SELECT_AUTOMATIC, 0, 0], &[])
}

/// `PC_to_RDR_IccPowerOff` (§6.1.2).
pub fn icc_power_off(seq: u8) -> Vec<u8> {
    message(msg_type::ICC_POWER_OFF, seq, [0; 3], &[])
}

/// `PC_to_RDR_XfrBlock` with `bBWI` 0 and `wLevelParameter` `level` (§6.1.4).
pub fn xfr_block(seq: u8, level: u16, data: &[u8]) -> Vec<u8> {
    let [low, high] = level.to_le_bytes();
    message(msg_type::XFR_BLOCK, seq, [0, low, high], data)
}

/// `PC_to_RDR_Abort` (§6.1.13: `dwLength` 0, three RFU bytes). It is the second half of an
/// abort: the host first sends the class-specific `ABORT` control request (§5.3.1, `wValue`
/// = `bSeq << 8 | bSlot`, `lk_run::HostInput::CcidControlAbort`), then this message with the
/// same `bSeq` ("The bSeq field must be the same as the bSeq field of the control
/// request", §6.1.13). The `bSeq` is a new one, not that of the command being aborted.
pub fn abort(seq: u8) -> Vec<u8> {
    message(msg_type::ABORT, seq, [0; 3], &[])
}

/// `bmCommandStatus`, bits 6–7 of `bStatus` (§6.2.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandStatus {
    /// 0: processed without error.
    Ok,
    /// 1: failed; the slot error register `bError` says why.
    Failed,
    /// 2: time extension requested; `bError` is the BWT multiplier. The real reply
    /// follows.
    TimeExtension,
    /// 3: reserved.
    Reserved,
}

/// `bmICCStatus`, bits 0–1 of `bStatus` (§6.2.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IccStatus {
    /// 0: present and active.
    Active,
    /// 1: present and inactive (not powered).
    Inactive,
    /// 2: no ICC present.
    Absent,
    /// 3: reserved.
    Reserved,
}

/// Why a bulk-in message could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyError {
    /// Shorter than the header.
    TooShort { len: usize },
    /// `dwLength` does not match the bytes after the header.
    LengthMismatch { announced: u32, actual: usize },
}

impl fmt::Display for ReplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReplyError::TooShort { len } => write!(f, "a CCID message of {len} bytes has no whole header"),
            ReplyError::LengthMismatch { announced, actual } => {
                write!(f, "a CCID message announces {announced} data bytes but carries {actual}")
            }
        }
    }
}

impl std::error::Error for ReplyError {}

/// A bulk-in message (`RDR_to_PC_*`, §6.2). `Debug` shows the size of `data`, never its
/// bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Reply {
    /// `bMessageType`.
    pub kind: u8,
    pub slot: u8,
    pub seq: u8,
    /// `bStatus`.
    pub status: u8,
    /// `bError`.
    pub error: u8,
    /// Byte 9: `bChainParameter` of a DataBlock, `bClockStatus` of a SlotStatus.
    pub specific: u8,
    /// `abData`.
    pub data: Vec<u8>,
}

impl fmt::Debug for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reply")
            .field("kind", &format_args!("{:#04x}", self.kind))
            .field("slot", &self.slot)
            .field("seq", &self.seq)
            .field("status", &format_args!("{:#04x}", self.status))
            .field("error", &format_args!("{:#04x}", self.error))
            .field("specific", &format_args!("{:#04x}", self.specific))
            .field("data", &format_args!("{} bytes", self.data.len()))
            .finish()
    }
}

impl Reply {
    /// Read a bulk-in message: the header, then exactly `dwLength` bytes of data.
    pub fn parse(message: &[u8]) -> Result<Reply, ReplyError> {
        let Some((header, data)) = message.split_first_chunk::<HEADER_LEN>() else {
            return Err(ReplyError::TooShort { len: message.len() });
        };
        let announced = u32::from_le_bytes([header[1], header[2], header[3], header[4]]);
        if usize::try_from(announced).ok() != Some(data.len()) {
            return Err(ReplyError::LengthMismatch { announced, actual: data.len() });
        }
        Ok(Reply {
            kind: header[0],
            slot: header[5],
            seq: header[6],
            status: header[7],
            error: header[8],
            specific: header[9],
            data: data.to_vec(),
        })
    }

    /// `bmCommandStatus`.
    pub fn command_status(&self) -> CommandStatus {
        match self.status >> 6 {
            0 => CommandStatus::Ok,
            1 => CommandStatus::Failed,
            2 => CommandStatus::TimeExtension,
            _ => CommandStatus::Reserved,
        }
    }

    /// `bmICCStatus`.
    pub fn icc_status(&self) -> IccStatus {
        match self.status & 0x03 {
            0 => IccStatus::Active,
            1 => IccStatus::Inactive,
            2 => IccStatus::Absent,
            _ => IccStatus::Reserved,
        }
    }

    /// A time-extension request (§6.2.6): to be skipped while waiting for the reply.
    pub fn is_time_extension(&self) -> bool {
        self.command_status() == CommandStatus::TimeExtension
    }
}

/// Why the reader's answer does not complete a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// The reply is not the message type the command is answered with.
    UnexpectedType { kind: u8 },
    /// `bmCommandStatus` failed (or reserved), with the slot error register and the ICC
    /// status: an inactive or absent card, a busy slot, an aborted command.
    Failed { error: u8, icc: IccStatus },
    /// A time extension where only a real reply can be taken (a caller skips them).
    TimeExtension,
    /// IccPowerOn succeeded without an ATR.
    NoAtr,
    /// `bChainParameter` (or the data with it) does not fit the state of the exchange.
    UnexpectedChain { chain: u8 },
    /// The response chain grew beyond [`MAX_RESPONSE`].
    ResponseTooLong,
    /// The exchange ended with an empty response APDU (it needs at least the status
    /// word).
    EmptyResponse,
}

impl Fault {
    /// A short reason for logs.
    pub fn reason(self) -> &'static str {
        match self {
            Fault::UnexpectedType { .. } => "the reply has an unexpected message type",
            Fault::Failed { icc: IccStatus::Absent, .. } => "the reader reports no card",
            Fault::Failed { icc: IccStatus::Inactive, .. } => "the card is not powered",
            Fault::Failed { .. } => "the reader reports a slot error",
            Fault::TimeExtension => "a time extension where a reply was expected",
            Fault::NoAtr => "the card was powered without an ATR",
            Fault::UnexpectedChain { .. } => "the reply does not continue the APDU exchange",
            Fault::ResponseTooLong => "the response APDU is too long",
            Fault::EmptyResponse => "the response APDU is empty",
        }
    }
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fault::UnexpectedType { kind } => write!(f, "{} ({kind:#04x})", self.reason()),
            Fault::Failed { error, icc } => write!(f, "{} (bError {error:#04x}, ICC {icc:?})", self.reason()),
            Fault::UnexpectedChain { chain } => write!(f, "{} (bChainParameter {chain:#04x})", self.reason()),
            _ => f.write_str(self.reason()),
        }
    }
}

impl std::error::Error for Fault {}

/// Check the common parts of a reply: its type and its command status.
fn check(reply: &Reply, kind: u8) -> Result<(), Fault> {
    if reply.kind != kind {
        return Err(Fault::UnexpectedType { kind: reply.kind });
    }
    match reply.command_status() {
        CommandStatus::Ok => Ok(()),
        CommandStatus::TimeExtension => Err(Fault::TimeExtension),
        CommandStatus::Failed | CommandStatus::Reserved => {
            Err(Fault::Failed { error: reply.error, icc: reply.icc_status() })
        }
    }
}

/// The ATR from the DataBlock that answers IccPowerOn (§6.1.1: "the ATR ... in the
/// abData field").
pub fn power_on_atr(reply: &Reply) -> Result<Vec<u8>, Fault> {
    check(reply, msg_type::DATA_BLOCK)?;
    if reply.data.is_empty() {
        return Err(Fault::NoAtr);
    }
    Ok(reply.data.clone())
}

/// Check the SlotStatus that answers IccPowerOff (§6.1.2).
pub fn power_off_done(reply: &Reply) -> Result<(), Fault> {
    check(reply, msg_type::SLOT_STATUS)
}

/// What the exchange waits for after its last message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Awaiting {
    /// The empty DataBlock with `bChainParameter` `10` after a command part that is not
    /// the last.
    CommandContinuation,
    /// The first part of the response, after the last command part.
    FirstResponse,
    /// A further part of the response, after an empty `0010` XfrBlock.
    NextResponse,
}

/// What to do after a reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Next {
    /// Send [`ApduExchange::message`] with the next `bSeq`.
    Send,
    /// The whole response APDU. `Debug` shows its size only.
    Done(Response),
    /// The exchange cannot go on.
    Failed(Fault),
}

/// A complete response APDU. `Debug` shows its size only.
#[derive(Clone, PartialEq, Eq)]
pub struct Response(pub Vec<u8>);

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Response").field(&format_args!("{} bytes", self.0.len())).finish()
    }
}

/// One command APDU sent as XfrBlocks at extended APDU level, and its response collected
/// (§6.1.4, §6.2.1).
///
/// A command that fits in one message goes with `wLevelParameter` `0000`; a longer one in
/// parts `0001`, `0003`…, `0002` of at most `max_data` bytes, each but the last answered by
/// an empty DataBlock with `bChainParameter` `10`. A response that begins with `01` is
/// fetched with empty `0010` XfrBlocks until a part with `02` ends it. The caller sends
/// [`ApduExchange::message`], waits for the reply with the same `bSeq` (skipping time
/// extensions) and passes it to [`ApduExchange::accept`].
///
/// `Debug` shows sizes only.
pub struct ApduExchange {
    apdu: Vec<u8>,
    /// Command bytes sent so far.
    sent: usize,
    max_data: usize,
    awaiting: Awaiting,
    response: Vec<u8>,
}

impl fmt::Debug for ApduExchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApduExchange")
            .field("apdu", &format_args!("{} bytes", self.apdu.len()))
            .field("sent", &self.sent)
            .field("max_data", &self.max_data)
            .field("awaiting", &self.awaiting)
            .field("response", &format_args!("{} bytes", self.response.len()))
            .finish()
    }
}

impl ApduExchange {
    /// An exchange for `apdu` in messages of at most `max_data` bytes of data (at least 1).
    pub fn new(apdu: &[u8], max_data: usize) -> ApduExchange {
        ApduExchange {
            apdu: apdu.to_vec(),
            sent: 0,
            max_data: max_data.max(1),
            awaiting: Awaiting::FirstResponse,
            response: Vec::new(),
        }
    }

    /// The next XfrBlock, with `bSeq` `seq`: the next command part, or an empty `0010`
    /// block while the response continues.
    pub fn message(&mut self, seq: u8) -> Vec<u8> {
        if self.awaiting == Awaiting::NextResponse {
            return xfr_block(seq, level::RESPONSE_CONTINUATION, &[]);
        }
        let rest = &self.apdu[self.sent..];
        let first = self.sent == 0;
        let (level, len) = match (first, rest.len() <= self.max_data) {
            (true, true) => (level::BEGIN_AND_END, rest.len()),
            (true, false) => (level::BEGIN, self.max_data),
            (false, false) => (level::CONTINUE, self.max_data),
            (false, true) => (level::END, rest.len()),
        };
        let block = xfr_block(seq, level, &rest[..len]);
        self.sent += len;
        self.awaiting =
            if self.sent < self.apdu.len() { Awaiting::CommandContinuation } else { Awaiting::FirstResponse };
        block
    }

    /// Take the reply to the last message.
    pub fn accept(&mut self, reply: &Reply) -> Next {
        if let Err(fault) = check(reply, msg_type::DATA_BLOCK) {
            return Next::Failed(fault);
        }
        let chain = reply.specific;
        match (self.awaiting, chain) {
            (Awaiting::CommandContinuation, chain::COMMAND_CONTINUATION) if reply.data.is_empty() => Next::Send,
            (Awaiting::FirstResponse, chain::BEGIN_AND_END) => self.finish(&reply.data),
            (Awaiting::FirstResponse, chain::BEGIN) | (Awaiting::NextResponse, chain::CONTINUE) => {
                if let Err(fault) = self.collect(&reply.data) {
                    return Next::Failed(fault);
                }
                self.awaiting = Awaiting::NextResponse;
                Next::Send
            }
            (Awaiting::NextResponse, chain::END) => self.finish(&reply.data),
            _ => Next::Failed(Fault::UnexpectedChain { chain }),
        }
    }

    fn collect(&mut self, data: &[u8]) -> Result<(), Fault> {
        if self.response.len().saturating_add(data.len()) > MAX_RESPONSE {
            return Err(Fault::ResponseTooLong);
        }
        self.response.extend_from_slice(data);
        Ok(())
    }

    fn finish(&mut self, data: &[u8]) -> Next {
        if let Err(fault) = self.collect(data) {
            return Next::Failed(fault);
        }
        if self.response.is_empty() {
            return Next::Failed(Fault::EmptyResponse);
        }
        Next::Done(Response(std::mem::take(&mut self.response)))
    }
}

#[cfg(test)]
mod tests;
