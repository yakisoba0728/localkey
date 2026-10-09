//! Message builders shared by the lk-ccid integration tests (USB CCID Rev 1.1 §6.1).

#![allow(dead_code)]

use lk_ccid::{Ccid, CcidAction};

/// Compatibility-profile ATR given in the lk-ccid task. Structure per ISO/IEC 7816-3 §8.2:
/// TS 3B, T0 FD, TA1 13, TB1 00, TC1 00, TD1 81 (T=1), TD2 31 (T=1), TA3 FE (IFSC 254),
/// TB3 15 (BWI 1, CWI 5), 13 historical bytes ending in "YubiKey", TCK 40.
pub const ATR: [u8; 23] = [
    0x3B, 0xFD, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x15, 0x80, 0x73, 0xC0, 0x21, 0xC0, 0x57, 0x59,
    0x75, 0x62, 0x69, 0x4B, 0x65, 0x79, 0x40,
];

/// T=1 parameters derived from [`ATR`] (CCID Rev 1.1 §6.2.3 field order).
pub const ATR_PARAMS: [u8; 7] = [0x13, 0x10, 0x00, 0x15, 0x00, 0xFE, 0x00];

/// `abData` per message: dwMaxCCIDMessageLength 3072 minus the 10-byte header
/// (reference/yubikey-5c-nano-5.7.4/usb-reference-observation.json).
pub const MAX_DATA: usize = 3062;

/// §6.2.5 with the descriptor's dwDefaultClock 4000 kHz and dwDataRate 307 200 bps,
/// little endian (usb-reference-observation.json).
pub const CLOCK_AND_RATE: [u8; 8] = [0xA0, 0x0F, 0x00, 0x00, 0x00, 0xB0, 0x04, 0x00];

/// Every bulk-out message type of §6.1.1–§6.1.14 with a well-formed body for the
/// powered compatibility slot, and the reply type the section pairs with it.
pub const ALL: [(u8, [u8; 3], &[u8], u8); 14] = [
    (0x62, [0; 3], &[], 0x80),                       // IccPowerOn -> DataBlock
    (0x63, [0; 3], &[], 0x81),                       // IccPowerOff -> SlotStatus
    (0x65, [0; 3], &[], 0x81),                       // GetSlotStatus -> SlotStatus
    (0x6F, [0; 3], &[0x00, 0xCA, 0x00, 0x00], 0x80), // XfrBlock -> DataBlock
    (0x6C, [0; 3], &[], 0x82),                       // GetParameters -> Parameters
    (0x6D, [0; 3], &[], 0x82),                       // ResetParameters -> Parameters
    (0x61, [1, 0, 0], &ATR_PARAMS, 0x82),            // SetParameters -> Parameters
    (0x6B, [0; 3], &[], 0x83),                       // Escape -> Escape
    (0x6E, [0; 3], &[], 0x81),                       // IccClock -> SlotStatus
    (0x6A, [0; 3], &[], 0x81),                       // T0APDU -> SlotStatus
    (0x69, [0; 3], &[], 0x80),                       // Secure -> DataBlock
    (0x71, [0; 3], &[], 0x81),                       // Mechanical -> SlotStatus
    (0x72, [0; 3], &[], 0x81),                       // Abort -> SlotStatus
    (0x73, [0; 3], &CLOCK_AND_RATE, 0x84),           // SetDataRate... -> DataRate...
];

/// A bulk-out message: header (§6.1) followed by `data`, with a correct `dwLength`.
pub fn cmd(msg_type: u8, slot: u8, seq: u8, specific: [u8; 3], data: &[u8]) -> Vec<u8> {
    let length = u32::try_from(data.len()).expect("test data fits dwLength");
    let mut m = vec![msg_type];
    m.extend_from_slice(&length.to_le_bytes());
    m.extend_from_slice(&[slot, seq]);
    m.extend_from_slice(&specific);
    m.extend_from_slice(data);
    m
}

/// `PC_to_RDR_XfrBlock` for slot 0 with `bBWI` 0 and `wLevelParameter` `level` (§6.1.4).
pub fn xfr(seq: u8, level: u16, data: &[u8]) -> Vec<u8> {
    let [lo, hi] = level.to_le_bytes();
    cmd(0x6F, 0, seq, [0, lo, hi], data)
}

/// The expected bulk-in message: header (§6.2) followed by `data`.
pub fn rsp(kind: u8, seq: u8, status: u8, error: u8, byte9: u8, data: &[u8]) -> Vec<u8> {
    let length = u32::try_from(data.len()).expect("test data fits dwLength");
    let mut m = vec![kind];
    m.extend_from_slice(&length.to_le_bytes());
    m.extend_from_slice(&[0, seq, status, error, byte9]);
    m.extend_from_slice(data);
    m
}

/// The expected failed reply of type `kind` for slot 0 while the ATR parameters
/// are in force. Its body keeps the layout of the reply type: RDR_to_PC_Parameters
/// carries bProtocolNum 1 and the T=1 structure (§6.2.3), and
/// RDR_to_PC_DataRateAndClockFrequency its eight bytes (§6.2.5, dwLength 00000008h).
/// Every other failed reply is empty.
pub fn failed(kind: u8, seq: u8, status: u8, error: u8) -> Vec<u8> {
    match kind {
        0x82 => rsp(kind, seq, status, error, 0x01, &ATR_PARAMS),
        0x84 => rsp(kind, seq, status, error, 0x00, &CLOCK_AND_RATE),
        _ => rsp(kind, seq, status, error, 0x00, &[]),
    }
}

/// The bytes of a `Reply` action; panics on any other action.
pub fn reply(action: CcidAction) -> Vec<u8> {
    match action {
        CcidAction::Reply(bytes) => bytes,
        other => panic!("expected Reply, got {other:?}"),
    }
}

/// A slot with the compatibility ATR, already powered on with `bSeq` 0.
pub fn powered() -> Ccid {
    let mut ccid = Ccid::new(ATR.to_vec());
    let atr = reply(ccid.message(&cmd(0x62, 0, 0, [0; 3], &[])));
    assert_eq!(atr, rsp(0x80, 0, 0x00, 0x00, 0x00, &ATR));
    ccid
}

/// Send a complete APDU in one XfrBlock and check that the card session receives it.
pub fn send_apdu(ccid: &mut Ccid, seq: u8, apdu: &[u8]) {
    assert_eq!(
        ccid.message(&xfr(seq, 0x0000, apdu)),
        CcidAction::Apdu {
            seq,
            apdu: apdu.to_vec()
        }
    );
}
