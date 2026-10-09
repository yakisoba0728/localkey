//! CCID message framing (USB CCID Rev 1.1 §6).
//!
//! Every bulk message starts with the same 10-byte header (§6.1, §6.2):
//! `bMessageType`, `dwLength` (little endian, size of `abData`), `bSlot`, `bSeq`, and
//! three message-specific bytes. This module holds the code values of §6.1–§6.3, the
//! header parser and the encoder shared by every `RDR_to_PC_*` reply.

/// Size of the header that starts every bulk-out and bulk-in message (§6.1, §6.2).
pub const HEADER_LEN: usize = 10;

/// `bMessageType` values (§6.1 bulk-out, §6.2 bulk-in, §6.3 interrupt-in).
pub mod msg_type {
    /// `PC_to_RDR_SetParameters` (§6.1.7).
    pub const PC_TO_RDR_SET_PARAMETERS: u8 = 0x61;
    /// `PC_to_RDR_IccPowerOn` (§6.1.1).
    pub const PC_TO_RDR_ICC_POWER_ON: u8 = 0x62;
    /// `PC_to_RDR_IccPowerOff` (§6.1.2).
    pub const PC_TO_RDR_ICC_POWER_OFF: u8 = 0x63;
    /// `PC_to_RDR_GetSlotStatus` (§6.1.3).
    pub const PC_TO_RDR_GET_SLOT_STATUS: u8 = 0x65;
    /// `PC_to_RDR_Secure` (§6.1.11).
    pub const PC_TO_RDR_SECURE: u8 = 0x69;
    /// `PC_to_RDR_T0APDU` (§6.1.10).
    pub const PC_TO_RDR_T0_APDU: u8 = 0x6A;
    /// `PC_to_RDR_Escape` (§6.1.8).
    pub const PC_TO_RDR_ESCAPE: u8 = 0x6B;
    /// `PC_to_RDR_GetParameters` (§6.1.5).
    pub const PC_TO_RDR_GET_PARAMETERS: u8 = 0x6C;
    /// `PC_to_RDR_ResetParameters` (§6.1.6).
    pub const PC_TO_RDR_RESET_PARAMETERS: u8 = 0x6D;
    /// `PC_to_RDR_IccClock` (§6.1.9).
    pub const PC_TO_RDR_ICC_CLOCK: u8 = 0x6E;
    /// `PC_to_RDR_XfrBlock` (§6.1.4).
    pub const PC_TO_RDR_XFR_BLOCK: u8 = 0x6F;
    /// `PC_to_RDR_Mechanical` (§6.1.12).
    pub const PC_TO_RDR_MECHANICAL: u8 = 0x71;
    /// `PC_to_RDR_Abort` (§6.1.13).
    pub const PC_TO_RDR_ABORT: u8 = 0x72;
    /// `PC_to_RDR_SetDataRateAndClockFrequency` (§6.1.14).
    pub const PC_TO_RDR_SET_DATA_RATE_AND_CLOCK_FREQUENCY: u8 = 0x73;

    /// `RDR_to_PC_DataBlock` (§6.2.1).
    pub const RDR_TO_PC_DATA_BLOCK: u8 = 0x80;
    /// `RDR_to_PC_SlotStatus` (§6.2.2).
    pub const RDR_TO_PC_SLOT_STATUS: u8 = 0x81;
    /// `RDR_to_PC_Parameters` (§6.2.3).
    pub const RDR_TO_PC_PARAMETERS: u8 = 0x82;
    /// `RDR_to_PC_Escape` (§6.2.4).
    pub const RDR_TO_PC_ESCAPE: u8 = 0x83;
    /// `RDR_to_PC_DataRateAndClockFrequency` (§6.2.5).
    pub const RDR_TO_PC_DATA_RATE_AND_CLOCK_FREQUENCY: u8 = 0x84;

    /// `RDR_to_PC_NotifySlotChange` on the interrupt pipe (§6.3.1).
    pub const RDR_TO_PC_NOTIFY_SLOT_CHANGE: u8 = 0x50;
    /// `RDR_to_PC_HardwareError` on the interrupt pipe (§6.3.2).
    pub const RDR_TO_PC_HARDWARE_ERROR: u8 = 0x51;
}

/// `bStatus` of a bulk-in reply (§6.2.6): `bmICCStatus` in bits 0–1 and
/// `bmCommandStatus` in bits 6–7.
pub mod status {
    /// `bmICCStatus` 0: an ICC is present and active (powered).
    pub const ICC_ACTIVE: u8 = 0x00;
    /// `bmICCStatus` 1: an ICC is present and inactive (not powered).
    pub const ICC_INACTIVE: u8 = 0x01;
    /// `bmICCStatus` 2: no ICC is present.
    pub const ICC_ABSENT: u8 = 0x02;
    /// `bmCommandStatus` 0: processed without error.
    pub const COMMAND_OK: u8 = 0x00;
    /// `bmCommandStatus` 1: failed, the reason is in `bError`.
    pub const COMMAND_FAILED: u8 = 0x40;
    /// `bmCommandStatus` 2: time extension requested, `bError` is the BWT multiplier.
    pub const TIME_EXTENSION: u8 = 0x80;
}

/// `bError` values of the slot error register (§6.2.6).
///
/// Values `0x01..=0x7F` are the byte offset, within the bulk-out message, of the
/// field that was not supported or incorrect; the `INDEX_*` constants name the
/// offsets this crate reports.
pub mod error {
    /// The host aborted the current activity.
    pub const CMD_ABORTED: u8 = 0xFF;
    /// The CCID timed out while talking to the ICC.
    pub const ICC_MUTE: u8 = 0xFE;
    /// Parity error while talking to the ICC.
    pub const XFR_PARITY_ERROR: u8 = 0xFD;
    /// Overrun error while talking to the ICC.
    pub const XFR_OVERRUN: u8 = 0xFC;
    /// An all-inclusive hardware error.
    pub const HW_ERROR: u8 = 0xFB;
    /// Invalid ATR TS byte.
    pub const BAD_ATR_TS: u8 = 0xF8;
    /// Invalid ATR TCK byte.
    pub const BAD_ATR_TCK: u8 = 0xF7;
    /// The ICC protocol is not supported.
    pub const ICC_PROTOCOL_NOT_SUPPORTED: u8 = 0xF6;
    /// The ICC class is not supported.
    pub const ICC_CLASS_NOT_SUPPORTED: u8 = 0xF5;
    /// T=0 procedure byte conflict.
    pub const PROCEDURE_BYTE_CONFLICT: u8 = 0xF4;
    /// The protocol is deactivated.
    pub const DEACTIVATED_PROTOCOL: u8 = 0xF3;
    /// An automatic sequence is ongoing.
    pub const BUSY_WITH_AUTO_SEQUENCE: u8 = 0xF2;
    /// PIN entry timed out.
    pub const PIN_TIMEOUT: u8 = 0xF0;
    /// PIN entry was cancelled.
    pub const PIN_CANCELLED: u8 = 0xEF;
    /// A second command was sent to a slot that is already processing one.
    pub const CMD_SLOT_BUSY: u8 = 0xE0;
    /// The command is not supported.
    pub const CMD_NOT_SUPPORTED: u8 = 0x00;

    /// Offset of `dwLength`: the message length is wrong for this command.
    pub const INDEX_DW_LENGTH: u8 = 1;
    /// Offset of `bSlot`: the slot does not exist.
    pub const INDEX_SLOT: u8 = 5;
    /// Offset of `bPowerSelect` in `PC_to_RDR_IccPowerOn`.
    pub const INDEX_POWER_SELECT: u8 = 7;
    /// Offset of `bProtocolNum` in `PC_to_RDR_SetParameters`.
    pub const INDEX_PROTOCOL_NUM: u8 = 7;
    /// Offset of `wLevelParameter` in `PC_to_RDR_XfrBlock`.
    pub const INDEX_LEVEL_PARAMETER: u8 = 8;
    /// Offset of the first `abProtocolDataStructure` byte in `PC_to_RDR_SetParameters`.
    pub const INDEX_PROTOCOL_DATA: u8 = 10;
    /// Offset of `dwClockFrequency` in `PC_to_RDR_SetDataRateAndClockFrequency`.
    pub const INDEX_CLOCK_FREQUENCY: u8 = 10;
    /// Offset of `dwDataRate` in `PC_to_RDR_SetDataRateAndClockFrequency`.
    pub const INDEX_DATA_RATE: u8 = 14;
}

/// `wLevelParameter` of `PC_to_RDR_XfrBlock` at extended APDU level (§6.1.4).
pub mod level {
    /// The command APDU begins and ends with this message.
    pub const BEGIN_AND_END: u16 = 0x0000;
    /// The command APDU begins with this message and continues in the next one.
    pub const BEGIN: u16 = 0x0001;
    /// This message continues and ends the command APDU.
    pub const END: u16 = 0x0002;
    /// This message continues the command APDU and another block follows.
    pub const CONTINUE: u16 = 0x0003;
    /// Empty `abData`: the host asks for the next part of the response APDU.
    pub const RESPONSE_CONTINUATION: u16 = 0x0010;
}

/// `bChainParameter` of `RDR_to_PC_DataBlock` at extended APDU level (§6.2.1).
pub mod chain {
    /// The response APDU begins and ends in this message.
    pub const BEGIN_AND_END: u8 = 0x00;
    /// The response APDU begins with this message and continues.
    pub const BEGIN: u8 = 0x01;
    /// This message continues and ends the response APDU.
    pub const END: u8 = 0x02;
    /// This message continues the response APDU and another block follows.
    pub const CONTINUE: u8 = 0x03;
    /// Empty `abData`: the CCID expects the next part of the command APDU.
    pub const COMMAND_CONTINUATION: u8 = 0x10;
}

use msg_type::{
    PC_TO_RDR_ESCAPE, PC_TO_RDR_GET_PARAMETERS, PC_TO_RDR_ICC_POWER_ON, PC_TO_RDR_RESET_PARAMETERS,
    PC_TO_RDR_SECURE, PC_TO_RDR_SET_DATA_RATE_AND_CLOCK_FREQUENCY, PC_TO_RDR_SET_PARAMETERS,
    PC_TO_RDR_XFR_BLOCK, RDR_TO_PC_DATA_BLOCK, RDR_TO_PC_DATA_RATE_AND_CLOCK_FREQUENCY,
    RDR_TO_PC_ESCAPE, RDR_TO_PC_PARAMETERS, RDR_TO_PC_SLOT_STATUS,
};

/// The header of a bulk-out message (§6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Header {
    pub msg_type: u8,
    /// `dwLength`: the size of `abData` the host announced.
    pub length: u32,
    pub slot: u8,
    pub seq: u8,
    /// The three message-specific bytes at offsets 7–9.
    pub specific: [u8; 3],
}

impl Header {
    /// Read the header, or `None` if the message is shorter than [`HEADER_LEN`].
    pub fn parse(msg: &[u8]) -> Option<Self> {
        let h: &[u8; HEADER_LEN] = msg.get(..HEADER_LEN)?.try_into().ok()?;
        Some(Self {
            msg_type: h[0],
            length: u32::from_le_bytes([h[1], h[2], h[3], h[4]]),
            slot: h[5],
            seq: h[6],
            specific: [h[7], h[8], h[9]],
        })
    }

    /// Whether `dwLength` equals the number of bytes that follow the header.
    pub fn length_matches(&self, msg: &[u8]) -> bool {
        let body = msg.len().saturating_sub(HEADER_LEN);
        u32::try_from(body).is_ok_and(|body| body == self.length)
    }
}

/// The `RDR_to_PC_*` message that answers a bulk-out message type (§6.1.1–§6.1.14).
///
/// An unknown `bMessageType` is answered with `RDR_to_PC_SlotStatus`.
pub(crate) fn response_type(command: u8) -> u8 {
    match command {
        PC_TO_RDR_ICC_POWER_ON | PC_TO_RDR_XFR_BLOCK | PC_TO_RDR_SECURE => RDR_TO_PC_DATA_BLOCK,
        PC_TO_RDR_GET_PARAMETERS | PC_TO_RDR_RESET_PARAMETERS | PC_TO_RDR_SET_PARAMETERS => {
            RDR_TO_PC_PARAMETERS
        }
        PC_TO_RDR_ESCAPE => RDR_TO_PC_ESCAPE,
        PC_TO_RDR_SET_DATA_RATE_AND_CLOCK_FREQUENCY => RDR_TO_PC_DATA_RATE_AND_CLOCK_FREQUENCY,
        _ => RDR_TO_PC_SLOT_STATUS,
    }
}

/// The fixed part of a bulk-in reply (§6.2).
///
/// Byte 9 is message specific: `bChainParameter` (DataBlock), `bClockStatus`
/// (SlotStatus), `bProtocolNum` (Parameters) or `bRFU` (Escape,
/// DataRateAndClockFrequency).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Reply {
    pub kind: u8,
    pub slot: u8,
    pub seq: u8,
    pub status: u8,
    pub error: u8,
    pub byte9: u8,
}

impl Reply {
    /// A reply of type `kind` to the message with `slot` and `seq`, processed without error.
    pub fn ok(kind: u8, slot: u8, seq: u8, icc: u8) -> Self {
        Self {
            kind,
            slot,
            seq,
            status: status::COMMAND_OK | icc,
            error: 0,
            byte9: 0,
        }
    }

    /// A failed reply of type `kind` with `bError` `error`.
    pub fn failed(kind: u8, slot: u8, seq: u8, icc: u8, error: u8) -> Self {
        Self {
            kind,
            slot,
            seq,
            status: status::COMMAND_FAILED | icc,
            error,
            byte9: 0,
        }
    }

    /// Set the message-specific byte 9.
    pub fn with_byte9(self, byte9: u8) -> Self {
        Self { byte9, ..self }
    }

    /// Encode header and `abData`.
    pub fn encode(&self, data: &[u8]) -> Vec<u8> {
        // `abData` is at most dwMaxCCIDMessageLength - 10 bytes, far below u32::MAX.
        let length = u32::try_from(data.len()).unwrap_or(u32::MAX);
        let mut out = Vec::with_capacity(HEADER_LEN + data.len());
        out.push(self.kind);
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(&[self.slot, self.seq, self.status, self.error, self.byte9]);
        out.extend_from_slice(data);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_fields_follow_section_6_1_layout() {
        // CCID Rev 1.1 §6.1.4: PC_to_RDR_XfrBlock, dwLength 4, bSlot 0, bSeq 7,
        // bBWI 0, wLevelParameter 0x0001 (little endian).
        let msg = [
            0x6F, 4, 0, 0, 0, 0, 7, 0, 0x01, 0x00, 0xAA, 0xBB, 0xCC, 0xDD,
        ];
        let h = Header::parse(&msg).expect("header");
        assert_eq!(h.msg_type, 0x6F);
        assert_eq!(h.length, 4);
        assert_eq!(h.slot, 0);
        assert_eq!(h.seq, 7);
        assert_eq!(h.specific, [0, 1, 0]);
        assert!(h.length_matches(&msg));
        assert!(!h.length_matches(&msg[..13]));
        assert_eq!(Header::parse(&msg[..9]), None);
    }

    #[test]
    fn reply_layout_follows_section_6_2() {
        // CCID Rev 1.1 §6.2.1: RDR_to_PC_DataBlock with two data bytes.
        let bytes = Reply::ok(0x80, 0, 3, status::ICC_ACTIVE)
            .with_byte9(0x01)
            .encode(&[0x90, 0x00]);
        assert_eq!(
            bytes,
            [0x80, 2, 0, 0, 0, 0, 3, 0x00, 0x00, 0x01, 0x90, 0x00]
        );
        let bytes = Reply::failed(0x81, 1, 9, status::ICC_ABSENT, error::INDEX_SLOT).encode(&[]);
        assert_eq!(bytes, [0x81, 0, 0, 0, 0, 1, 9, 0x42, 0x05, 0x00]);
    }

    #[test]
    fn every_command_has_its_paired_response_type() {
        // CCID Rev 1.1 §6.1.1–§6.1.14 name the response message of each command.
        let pairs = [
            (0x62, 0x80),
            (0x63, 0x81),
            (0x65, 0x81),
            (0x6F, 0x80),
            (0x6C, 0x82),
            (0x6D, 0x82),
            (0x61, 0x82),
            (0x6B, 0x83),
            (0x6E, 0x81),
            (0x6A, 0x81),
            (0x69, 0x80),
            (0x71, 0x81),
            (0x72, 0x81),
            (0x73, 0x84),
            (0x00, 0x81),
            (0xFF, 0x81),
        ];
        for (command, response) in pairs {
            assert_eq!(response_type(command), response, "command {command:#04x}");
        }
    }
}
