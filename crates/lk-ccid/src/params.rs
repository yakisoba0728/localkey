//! The T=1 protocol data structure of `PC_to_RDR_SetParameters` and
//! `RDR_to_PC_Parameters` (USB CCID Rev 1.1 §6.1.7, §6.2.3).
//!
//! The slot only speaks T=1 (`dwProtocols` = 2 in the descriptor). Its default
//! parameters come from the ATR, with the ISO/IEC 7816-3 defaults for absent bytes.
//! `SetParameters` is validated atomically: either every byte is acceptable and the
//! whole block replaces the current one, or nothing changes and the offset of the
//! first rejected byte is reported.

use crate::atr;
use crate::descriptor::{ClassDescriptor, YUBIKEY_COMPAT, feature};
use crate::message::error::INDEX_PROTOCOL_DATA;

/// `bProtocolNum` for T=1.
pub const PROTOCOL_T1: u8 = 1;

/// The seven-byte T=1 `abProtocolDataStructure` (§6.1.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct T1Parameters {
    /// `bmFindexDindex`: Fi index in bits 7–4, Di index in bits 3–0 (ISO/IEC 7816-3 TA1).
    pub findex_dindex: u8,
    /// `bmTCCKST1`: `0x10`, plus bit 1 for inverse convention and bit 0 for CRC.
    pub tcckst1: u8,
    /// `bGuardTimeT1`: extra guard time (ISO/IEC 7816-3 TC1).
    pub guard_time: u8,
    /// `bmWaitingIntegersT1`: BWI in bits 7–4, CWI in bits 3–0.
    pub waiting_integers: u8,
    /// `bClockStop`: 0 not allowed, 1 low, 2 high, 3 either.
    pub clock_stop: u8,
    /// `bIFSC`: the ICC's information field size.
    pub ifsc: u8,
    /// `bNadValue`.
    pub nad: u8,
}

/// ISO/IEC 7816-3 §8.3: Fd = 372, Dd = 1 when TA1 is absent.
const DEFAULT_FINDEX_DINDEX: u8 = 0x11;
/// ISO/IEC 7816-3 §11.4.3: BWI = 4, CWI = 13 when the T=1 TB is absent.
const DEFAULT_WAITING_INTEGERS: u8 = 0x4D;
/// ISO/IEC 7816-3 §11.4.2: IFSC = 32 when the T=1 TA is absent.
const DEFAULT_IFSC: u8 = 0x20;
/// Fixed upper bits of `bmTCCKST1` for T=1 (§6.1.7).
const TCCKST1_BASE: u8 = 0x10;

impl T1Parameters {
    /// Size of the structure in a Parameters message.
    pub const LEN: usize = 7;

    /// The parameters an ICC with this ATR starts with (ISO/IEC 7816-3 §8.3, §11.4).
    pub fn from_atr(atr: &[u8]) -> Self {
        let ib = atr::interface_bytes(atr);
        Self {
            findex_dindex: ib.ta1.unwrap_or(DEFAULT_FINDEX_DINDEX),
            tcckst1: TCCKST1_BASE | (u8::from(ib.inverse) << 1) | (ib.t1_tc.unwrap_or(0) & 0x01),
            guard_time: ib.tc1.unwrap_or(0),
            waiting_integers: ib.t1_tb.unwrap_or(DEFAULT_WAITING_INTEGERS),
            clock_stop: ib.t15_ta.map_or(0, |ta| ta >> 6),
            ifsc: ib.t1_ta.unwrap_or(DEFAULT_IFSC),
            nad: 0,
        }
    }

    /// The structure as sent in `RDR_to_PC_Parameters`.
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        [
            self.findex_dindex,
            self.tcckst1,
            self.guard_time,
            self.waiting_integers,
            self.clock_stop,
            self.ifsc,
            self.nad,
        ]
    }

    /// Validate a `SetParameters` block for an ICC whose ATR parameters are `self`.
    ///
    /// On rejection the error is the `bError` offset of the first bad byte (10–16).
    /// Rules, in byte order:
    /// - `bmFindexDindex`: the default `11` or the ICC's TA1 — the only values an ICC
    ///   is required to accept in PPS (ISO/IEC 7816-3 §9).
    /// - `bmTCCKST1`: must match the ICC's convention and error detection code.
    /// - `bGuardTimeT1`: any value.
    /// - `bmWaitingIntegersT1`: BWI 0–9 (A–F are reserved, ISO/IEC 7816-3 §11.4.3).
    /// - `bClockStop`: 0, or the ICC's own indicator.
    /// - `bIFSC`: `01`–`FE` (ISO/IEC 7816-3 §11.4.2).
    /// - `bNadValue`: 0 unless the descriptor sets [`feature::NAD_NOT_ZERO`].
    pub(crate) fn validate(&self, block: &[u8; Self::LEN]) -> Result<Self, u8> {
        self.validate_for(block, &YUBIKEY_COMPAT)
    }

    fn validate_for(&self, block: &[u8; Self::LEN], ccid: &ClassDescriptor) -> Result<Self, u8> {
        let [fd, tcck, guard, waiting, clock_stop, ifsc, nad] = *block;
        let checks = [
            fd == DEFAULT_FINDEX_DINDEX || fd == self.findex_dindex,
            tcck == self.tcckst1,
            true,
            waiting >> 4 <= 9,
            clock_stop == 0 || clock_stop == self.clock_stop,
            (0x01..=0xFE).contains(&ifsc),
            nad == 0 || ccid.features & feature::NAD_NOT_ZERO != 0,
        ];
        if let Some(bad) = checks.iter().position(|ok| !ok) {
            // `bad` < 7, so the offset fits in a byte.
            return Err(INDEX_PROTOCOL_DATA + u8::try_from(bad).unwrap_or(0));
        }
        Ok(Self {
            findex_dindex: fd,
            tcckst1: tcck,
            guard_time: guard,
            waiting_integers: waiting,
            clock_stop,
            ifsc,
            nad,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compatibility-profile ATR given in the lk-ccid task (ISO/IEC 7816-3 §8.2 structure).
    const ATR: [u8; 23] = [
        0x3B, 0xFD, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x15, 0x80, 0x73, 0xC0, 0x21, 0xC0, 0x57,
        0x59, 0x75, 0x62, 0x69, 0x4B, 0x65, 0x79, 0x40,
    ];

    #[test]
    fn defaults_from_compatibility_atr() {
        // TA1 13, direct convention + LRC (no TC3) -> 10, TC1 00, TB3 15, no T=15 -> 00,
        // TA3 FE, NAD 00 (CCID Rev 1.1 §6.1.7 field order).
        assert_eq!(
            T1Parameters::from_atr(&ATR).to_bytes(),
            [0x13, 0x10, 0x00, 0x15, 0x00, 0xFE, 0x00]
        );
    }

    #[test]
    fn iso_defaults_when_bytes_are_absent() {
        // ISO/IEC 7816-3 §8.3 and §11.4: F/D 11, guard 00, BWI/CWI 4D, IFSC 20.
        assert_eq!(
            T1Parameters::from_atr(&[0x3B, 0x00]).to_bytes(),
            [0x11, 0x10, 0x00, 0x4D, 0x00, 0x20, 0x00]
        );
        // Inverse convention, CRC (TC3 01), clock stop indicator 3 (TA for T=15 = C1).
        let atr = [0x3F, 0x80, 0x81, 0xC1, 0x01, 0x1F, 0xC1];
        assert_eq!(
            T1Parameters::from_atr(&atr).to_bytes(),
            [0x11, 0x13, 0x00, 0x4D, 0x03, 0x20, 0x00]
        );
    }

    #[test]
    fn validation_accepts_card_values_and_rejects_each_field() {
        let card = T1Parameters::from_atr(&ATR);
        let good = card.to_bytes();
        assert_eq!(card.validate(&good), Ok(card));
        let mut slower = good;
        slower[0] = 0x11;
        slower[2] = 0xFF;
        slower[5] = 0x01;
        assert_eq!(card.validate(&slower).map(|p| p.to_bytes()), Ok(slower));

        let cases: [(usize, u8, u8); 8] = [
            (0, 0x18, 10), // Di 8 is faster than TA1 allows
            (1, 0x11, 11), // CRC not indicated by the ATR
            (1, 0x12, 11), // inverse convention, but TS is 3B
            (3, 0xA5, 13), // BWI A is reserved
            (4, 0x01, 14), // clock stop not indicated by the ATR
            (5, 0x00, 15), // IFSC 00 is reserved
            (5, 0xFF, 15), // IFSC FF is reserved
            (6, 0x01, 16), // NAD other than 00 not advertised in dwFeatures
        ];
        for (byte, value, offset) in cases {
            let mut block = good;
            block[byte] = value;
            assert_eq!(
                card.validate(&block),
                Err(offset),
                "byte {byte} = {value:#04x}"
            );
        }
    }

    #[test]
    fn nad_accepted_when_descriptor_allows_it() {
        let card = T1Parameters::from_atr(&ATR);
        let ccid = ClassDescriptor {
            features: YUBIKEY_COMPAT.features | feature::NAD_NOT_ZERO,
            ..YUBIKEY_COMPAT
        };
        let mut block = card.to_bytes();
        block[6] = 0x12;
        assert_eq!(card.validate_for(&block, &ccid).map(|p| p.nad), Ok(0x12));
    }
}
