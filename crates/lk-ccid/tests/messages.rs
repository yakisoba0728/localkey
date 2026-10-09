//! Every bulk-out message of USB CCID Rev 1.1 §6.1 and its error paths, checked
//! byte for byte against the bulk-in layouts of §6.2 and the codes of §6.2.6.

mod common;

use common::{
    ALL, ATR, ATR_PARAMS, CLOCK_AND_RATE, MAX_DATA, cmd, failed, powered, reply, rsp, send_apdu,
    xfr,
};
use lk_ccid::{Ccid, CcidAction};

/// §6.2.6 bStatus values used below.
const ACTIVE: u8 = 0x00;
const INACTIVE: u8 = 0x01;
const FAILED_ACTIVE: u8 = 0x40;
const FAILED_INACTIVE: u8 = 0x41;
const FAILED_ABSENT: u8 = 0x42;

/// bClockStatus and bProtocolNum values.
const CLOCK_RUNNING: u8 = 0x00;
const T1: u8 = 0x01;

fn fresh() -> Ccid {
    Ccid::new(ATR.to_vec())
}

// §6.1.1 PC_to_RDR_IccPowerOn -> §6.2.1 RDR_to_PC_DataBlock

#[test]
fn power_on_answers_with_the_atr() {
    let mut ccid = fresh();
    assert!(!ccid.is_active());
    let r = reply(ccid.message(&cmd(0x62, 0, 0x11, [0x00, 0, 0], &[])));
    assert_eq!(r, rsp(0x80, 0x11, ACTIVE, 0x00, 0x00, &ATR));
    assert!(ccid.is_active());
    assert_eq!(ccid.atr(), ATR);
}

#[test]
fn power_on_accepts_every_advertised_voltage() {
    // bVoltageSupport 07: bPowerSelect 1 (5 V), 2 (3 V), 3 (1.8 V); 0 is automatic.
    for select in 0..=3 {
        let mut ccid = fresh();
        let r = reply(ccid.message(&cmd(0x62, 0, 1, [select, 0, 0], &[])));
        assert_eq!(
            r,
            rsp(0x80, 1, ACTIVE, 0x00, 0x00, &ATR),
            "bPowerSelect {select}"
        );
    }
}

#[test]
fn power_on_rejects_unknown_power_select() {
    // §6.2.6: bError 07 is the offset of bPowerSelect.
    let mut ccid = fresh();
    let r = reply(ccid.message(&cmd(0x62, 0, 2, [0x04, 0, 0], &[])));
    assert_eq!(r, rsp(0x80, 2, FAILED_INACTIVE, 0x07, 0x00, &[]));
    assert!(!ccid.is_active());
}

#[test]
fn power_on_while_active_is_a_warm_reset() {
    // A second IccPowerOn produces a new ATR, which ends the card session
    // (lk_core::ResetKind::CardPowerOff), so it is reported as PowerOff.
    let mut ccid = powered();
    let action = ccid.message(&cmd(0x62, 0, 3, [0; 3], &[]));
    assert_eq!(
        action,
        CcidAction::PowerOff(rsp(0x80, 3, ACTIVE, 0x00, 0x00, &ATR))
    );
    assert!(ccid.is_active());
}

// §6.1.2 PC_to_RDR_IccPowerOff -> §6.2.2 RDR_to_PC_SlotStatus

#[test]
fn power_off_reports_inactive_slot_and_ends_the_session() {
    let mut ccid = powered();
    let action = ccid.message(&cmd(0x63, 0, 4, [0; 3], &[]));
    assert_eq!(
        action,
        CcidAction::PowerOff(rsp(0x81, 4, INACTIVE, 0x00, CLOCK_RUNNING, &[]))
    );
    assert!(!ccid.is_active());
    // Idempotent: powering off an inactive ICC succeeds the same way.
    let action = ccid.message(&cmd(0x63, 0, 5, [0; 3], &[]));
    assert_eq!(
        action,
        CcidAction::PowerOff(rsp(0x81, 5, INACTIVE, 0x00, CLOCK_RUNNING, &[]))
    );
    // No APDU reaches the card until a new IccPowerOn.
    let r = reply(ccid.message(&xfr(6, 0x0000, &[0x00, 0xA4, 0x04, 0x00])));
    assert_eq!(r, rsp(0x80, 6, FAILED_INACTIVE, 0xFE, 0x00, &[]));
    let r = reply(ccid.message(&cmd(0x62, 0, 7, [0; 3], &[])));
    assert_eq!(r, rsp(0x80, 7, ACTIVE, 0x00, 0x00, &ATR));
}

// §6.1.3 PC_to_RDR_GetSlotStatus -> §6.2.2 RDR_to_PC_SlotStatus

#[test]
fn slot_status_follows_power() {
    let mut ccid = fresh();
    let r = reply(ccid.message(&cmd(0x65, 0, 8, [0; 3], &[])));
    assert_eq!(r, rsp(0x81, 8, INACTIVE, 0x00, CLOCK_RUNNING, &[]));
    let mut ccid = powered();
    let r = reply(ccid.message(&cmd(0x65, 0, 9, [0; 3], &[])));
    assert_eq!(r, rsp(0x81, 9, ACTIVE, 0x00, CLOCK_RUNNING, &[]));
}

// §6.1.4 PC_to_RDR_XfrBlock -> §6.2.1 RDR_to_PC_DataBlock (single message)

#[test]
fn xfr_block_hands_the_apdu_over_and_frames_the_response() {
    let mut ccid = powered();
    let select = [0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08];
    // bBWI is ignored.
    let msg = cmd(0x6F, 0, 0x20, [0x07, 0x00, 0x00], &select);
    assert_eq!(
        ccid.message(&msg),
        CcidAction::Apdu {
            seq: 0x20,
            apdu: select.to_vec()
        }
    );
    assert_eq!(ccid.pending_seq(), Some(0x20));
    let r = ccid.apdu_response(0x20, &[0x61, 0x10, 0x90, 0x00]);
    assert_eq!(
        r,
        rsp(0x80, 0x20, ACTIVE, 0x00, 0x00, &[0x61, 0x10, 0x90, 0x00])
    );
    assert_eq!(ccid.pending_seq(), None);
}

#[test]
fn xfr_block_on_inactive_icc_is_refused() {
    // Model policy: ICC_MUTE (FE) with bmICCStatus 1, no APDU forwarded.
    let mut ccid = fresh();
    let r = reply(ccid.message(&xfr(0x21, 0x0000, &[0x00, 0xCA, 0x00, 0x00])));
    assert_eq!(r, rsp(0x80, 0x21, FAILED_INACTIVE, 0xFE, 0x00, &[]));
}

#[test]
fn xfr_block_without_data_is_a_length_error() {
    let mut ccid = powered();
    let r = reply(ccid.message(&xfr(0x22, 0x0000, &[])));
    assert_eq!(r, rsp(0x80, 0x22, FAILED_ACTIVE, 0x01, 0x00, &[]));
}

#[test]
fn xfr_block_up_to_the_message_limit_is_accepted() {
    // dwMaxCCIDMessageLength 3072 = 10-byte header + 3062 bytes of abData.
    let mut ccid = powered();
    let apdu = vec![0x5A; MAX_DATA];
    send_apdu(&mut ccid, 0x23, &apdu);
    let mut ccid = powered();
    let r = reply(ccid.message(&xfr(0x24, 0x0000, &vec![0x5A; MAX_DATA + 1])));
    assert_eq!(r, rsp(0x80, 0x24, FAILED_ACTIVE, 0x01, 0x00, &[]));
}

#[test]
fn apdu_response_for_an_unknown_seq_sends_nothing() {
    let mut ccid = powered();
    assert_eq!(ccid.apdu_response(0x30, &[0x90, 0x00]), Vec::<u8>::new());
    send_apdu(&mut ccid, 0x31, &[0x00, 0xCA, 0x00, 0x00]);
    assert_eq!(ccid.apdu_response(0x32, &[0x90, 0x00]), Vec::<u8>::new());
    assert_eq!(ccid.pending_seq(), Some(0x31));
}

// §6.1.5–§6.1.7 Get/Reset/SetParameters -> §6.2.3 RDR_to_PC_Parameters

#[test]
fn get_parameters_reports_t1_values_from_the_atr() {
    let mut ccid = fresh();
    let r = reply(ccid.message(&cmd(0x6C, 0, 0x40, [0; 3], &[])));
    assert_eq!(r, rsp(0x82, 0x40, INACTIVE, 0x00, T1, &ATR_PARAMS));
    let mut ccid = powered();
    let r = reply(ccid.message(&cmd(0x6C, 0, 0x41, [0; 3], &[])));
    assert_eq!(r, rsp(0x82, 0x41, ACTIVE, 0x00, T1, &ATR_PARAMS));
}

#[test]
fn set_then_reset_parameters() {
    let mut ccid = powered();
    // Default F/D (11), extra guard time FF, IFSC 20: all acceptable.
    let block = [0x11, 0x10, 0xFF, 0x15, 0x00, 0x20, 0x00];
    let r = reply(ccid.message(&cmd(0x61, 0, 0x42, [T1, 0, 0], &block)));
    assert_eq!(r, rsp(0x82, 0x42, ACTIVE, 0x00, T1, &block));
    let r = reply(ccid.message(&cmd(0x6C, 0, 0x43, [0; 3], &[])));
    assert_eq!(r, rsp(0x82, 0x43, ACTIVE, 0x00, T1, &block));
    assert_eq!(ccid.parameters_in_force().to_bytes(), block);
    let r = reply(ccid.message(&cmd(0x6D, 0, 0x44, [0; 3], &[])));
    assert_eq!(r, rsp(0x82, 0x44, ACTIVE, 0x00, T1, &ATR_PARAMS));
}

#[test]
fn power_on_restores_atr_parameters() {
    let mut ccid = powered();
    let block = [0x11, 0x10, 0x00, 0x15, 0x00, 0xFE, 0x00];
    reply(ccid.message(&cmd(0x61, 0, 1, [T1, 0, 0], &block)));
    assert!(matches!(
        ccid.message(&cmd(0x63, 0, 2, [0; 3], &[])),
        CcidAction::PowerOff(_)
    ));
    reply(ccid.message(&cmd(0x62, 0, 3, [0; 3], &[])));
    assert_eq!(ccid.parameters_in_force().to_bytes(), ATR_PARAMS);
}

#[test]
fn set_parameters_rejects_t0() {
    // dwProtocols = 2 (T=1 only): bProtocolNum 0 fails at offset 7; the reply
    // reports the T=1 parameters still in force.
    let mut ccid = powered();
    let t0 = [0x11, 0x00, 0x00, 0x0A, 0x00];
    let r = reply(ccid.message(&cmd(0x61, 0, 0x45, [0x00, 0, 0], &t0)));
    assert_eq!(r, rsp(0x82, 0x45, FAILED_ACTIVE, 0x07, T1, &ATR_PARAMS));
    let r = reply(ccid.message(&cmd(0x61, 0, 0x46, [0x02, 0, 0], &ATR_PARAMS)));
    assert_eq!(r, rsp(0x82, 0x46, FAILED_ACTIVE, 0x07, T1, &ATR_PARAMS));
}

#[test]
fn set_parameters_t1_needs_seven_bytes() {
    // bError 01 (dwLength); §6.2.3: the reply still names T=1 and its structure.
    let mut ccid = powered();
    let r = reply(ccid.message(&cmd(0x61, 0, 0x47, [T1, 0, 0], &ATR_PARAMS[..5])));
    assert_eq!(r, rsp(0x82, 0x47, FAILED_ACTIVE, 0x01, T1, &ATR_PARAMS));
    assert_eq!(ccid.parameters_in_force().to_bytes(), ATR_PARAMS);
}

#[test]
fn set_parameters_is_atomic() {
    // Each rejected byte is reported by its message offset (10 + index, §6.2.6); the
    // block in force does not change, even when earlier bytes were acceptable.
    let mut ccid = powered();
    let cases: [(usize, u8, u8); 7] = [
        (0, 0x96, 0x0A), // F/D neither default nor TA1
        (1, 0x12, 0x0B), // inverse convention; TS is 3B
        (3, 0xF5, 0x0D), // BWI F reserved
        (4, 0x03, 0x0E), // clock stop not indicated by the ATR
        (5, 0x00, 0x0F), // IFSC 00 reserved
        (5, 0xFF, 0x0F), // IFSC FF reserved
        (6, 0x21, 0x10), // NAD other than 00 not advertised
    ];
    for (seq, (byte, value, offset)) in (0x50..).zip(cases) {
        let mut block = [0x11, 0x10, 0xFF, 0x15, 0x00, 0x20, 0x00];
        block[byte] = value;
        let r = reply(ccid.message(&cmd(0x61, 0, seq, [T1, 0, 0], &block)));
        assert_eq!(
            r,
            rsp(0x82, seq, FAILED_ACTIVE, offset, T1, &ATR_PARAMS),
            "byte {byte}"
        );
        assert_eq!(ccid.parameters_in_force().to_bytes(), ATR_PARAMS);
    }
}

// §6.1.14 PC_to_RDR_SetDataRateAndClockFrequency -> §6.2.5

#[test]
fn set_data_rate_accepts_only_the_advertised_values() {
    let mut ccid = powered();
    let r = reply(ccid.message(&cmd(0x73, 0, 0x60, [0; 3], &CLOCK_AND_RATE)));
    assert_eq!(r, rsp(0x84, 0x60, ACTIVE, 0x00, 0x00, &CLOCK_AND_RATE));

    // 5000 kHz: dwClockFrequency at offset 10.
    let mut bad_clock = CLOCK_AND_RATE;
    bad_clock[..4].copy_from_slice(&5000u32.to_le_bytes());
    let r = reply(ccid.message(&cmd(0x73, 0, 0x61, [0; 3], &bad_clock)));
    assert_eq!(
        r,
        rsp(0x84, 0x61, FAILED_ACTIVE, 0x0A, 0x00, &CLOCK_AND_RATE)
    );

    // 9600 bps: dwDataRate at offset 14.
    let mut bad_rate = CLOCK_AND_RATE;
    bad_rate[4..].copy_from_slice(&9600u32.to_le_bytes());
    let r = reply(ccid.message(&cmd(0x73, 0, 0x62, [0; 3], &bad_rate)));
    assert_eq!(
        r,
        rsp(0x84, 0x62, FAILED_ACTIVE, 0x0E, 0x00, &CLOCK_AND_RATE)
    );

    // dwLength must be 8; §6.2.5 fixes the reply's dwLength at 8 even on failure.
    let r = reply(ccid.message(&cmd(0x73, 0, 0x63, [0; 3], &CLOCK_AND_RATE[..4])));
    assert_eq!(
        r,
        rsp(0x84, 0x63, FAILED_ACTIVE, 0x01, 0x00, &CLOCK_AND_RATE)
    );
}

// §6.1.8–§6.1.12 commands the reference reader does not support (bError 00)

#[test]
fn unsupported_commands_fail_in_their_paired_reply_type() {
    let cases: [(u8, [u8; 3], &[u8], u8); 6] = [
        (0x6B, [0; 3], &[0x01, 0x02], 0x83), // Escape -> RDR_to_PC_Escape
        (0x6E, [0x01, 0, 0], &[], 0x81),     // IccClock stop -> SlotStatus
        (0x6E, [0x00, 0, 0], &[], 0x81),     // IccClock restart -> SlotStatus
        (0x6A, [0x03, 0xFF, 0xFF], &[], 0x81), // T0APDU -> SlotStatus
        (0x69, [0, 0, 0], &[0x00, 0x00], 0x80), // Secure -> DataBlock
        (0x71, [0x01, 0, 0], &[], 0x81),     // Mechanical -> SlotStatus
    ];
    for (seq, (kind, specific, data, response)) in (0x70..).zip(cases) {
        let mut ccid = powered();
        let r = reply(ccid.message(&cmd(kind, 0, seq, specific, data)));
        assert_eq!(
            r,
            rsp(response, seq, FAILED_ACTIVE, 0x00, 0x00, &[]),
            "{kind:#04x}"
        );
        let mut ccid = fresh();
        let r = reply(ccid.message(&cmd(kind, 0, seq, specific, data)));
        assert_eq!(
            r,
            rsp(response, seq, FAILED_INACTIVE, 0x00, 0x00, &[]),
            "{kind:#04x}"
        );
    }
}

#[test]
fn unknown_message_type_is_not_supported() {
    let mut ccid = powered();
    for (seq, kind) in [(1, 0x00), (2, 0x60), (3, 0x64), (4, 0x80), (5, 0xFF)] {
        let r = reply(ccid.message(&cmd(kind, 0, seq, [0; 3], &[])));
        assert_eq!(
            r,
            rsp(0x81, seq, FAILED_ACTIVE, 0x00, 0x00, &[]),
            "{kind:#04x}"
        );
    }
}

// §6.2.6 errors shared by every command

#[test]
fn wrong_slot_fails_with_error_5_and_no_icc() {
    let mut ccid = powered();
    for (kind, specific, data, response) in ALL {
        for slot in [1, 0xFF] {
            // A slot that does not exist has no protocol structure; the clock and
            // rate of §6.2.5 belong to the reader and keep dwLength 8.
            let body: &[u8] = if response == 0x84 {
                &CLOCK_AND_RATE
            } else {
                &[]
            };
            let mut expected = rsp(response, 0x33, FAILED_ABSENT, 0x05, 0x00, body);
            expected[5] = slot;
            let r = reply(ccid.message(&cmd(kind, slot, 0x33, specific, data)));
            assert_eq!(r, expected, "{kind:#04x} slot {slot}");
        }
    }
    // Nothing changed on slot 0.
    assert!(ccid.is_active());
    assert_eq!(ccid.pending_seq(), None);
}

#[test]
fn dw_length_must_match_the_body() {
    let mut ccid = powered();
    for (kind, specific, data, response) in ALL {
        // Announce one byte more than is sent.
        let mut msg = cmd(kind, 0, 0x34, specific, data);
        let announced = u32::try_from(data.len() + 1).expect("small");
        msg[1..5].copy_from_slice(&announced.to_le_bytes());
        let r = reply(ccid.message(&msg));
        assert_eq!(
            r,
            failed(response, 0x34, FAILED_ACTIVE, 0x01),
            "{kind:#04x}"
        );
    }
}

#[test]
fn dw_length_smaller_than_the_body_or_absurd() {
    // §6.1: dwLength is the exact size of abData. Announcing fewer bytes than are
    // sent, or a length no message can have, fails with bError 01 and changes nothing.
    let mut ccid = powered();
    for (kind, specific, data, response) in ALL {
        let mut announced = vec![u32::MAX, 0x0001_0000];
        if !data.is_empty() {
            announced.push(u32::try_from(data.len() - 1).expect("small"));
            announced.push(0);
        }
        for length in announced {
            let mut msg = cmd(kind, 0, 0x39, specific, data);
            msg[1..5].copy_from_slice(&length.to_le_bytes());
            let r = reply(ccid.message(&msg));
            assert_eq!(
                r,
                failed(response, 0x39, FAILED_ACTIVE, 0x01),
                "{kind:#04x} dwLength {length:#x}"
            );
        }
    }
    assert!(ccid.is_active());
    assert_eq!(ccid.pending_seq(), None);
    assert_eq!(ccid.parameters_in_force().to_bytes(), ATR_PARAMS);
}

#[test]
fn every_reply_echoes_slot_and_seq() {
    // §6.2: bSlot and bSeq of a bulk-in message repeat those of the bulk-out message.
    for seq in [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF] {
        for (kind, specific, data, response) in ALL {
            let mut ccid = powered();
            match ccid.message(&cmd(kind, 0, seq, specific, data)) {
                CcidAction::Reply(r) | CcidAction::PowerOff(r) => {
                    assert_eq!(r[0], response, "{kind:#04x}");
                    assert_eq!((r[5], r[6]), (0, seq), "{kind:#04x} seq {seq:#04x}");
                }
                CcidAction::Apdu { seq: s, .. } => {
                    assert_eq!(kind, 0x6F);
                    assert_eq!(s, seq);
                    let r = ccid.apdu_response(s, &[0x90, 0x00]);
                    assert_eq!(r, rsp(0x80, seq, ACTIVE, 0x00, 0x00, &[0x90, 0x00]));
                }
            }
        }
    }
}

#[test]
fn fixed_size_commands_reject_a_body() {
    // §6.1: dwLength is 0 for these commands and 8 for SetDataRateAndClockFrequency.
    let mut ccid = powered();
    for (kind, response) in [
        (0x62, 0x80),
        (0x63, 0x81),
        (0x65, 0x81),
        (0x6C, 0x82),
        (0x6D, 0x82),
        (0x6E, 0x81),
        (0x6A, 0x81),
        (0x71, 0x81),
        (0x72, 0x81),
    ] {
        let r = reply(ccid.message(&cmd(kind, 0, 0x35, [0; 3], &[0x00])));
        assert_eq!(
            r,
            failed(response, 0x35, FAILED_ACTIVE, 0x01),
            "{kind:#04x}"
        );
    }
    let r = reply(ccid.message(&cmd(0x73, 0, 0x36, [0; 3], &[0; 9])));
    assert_eq!(r, failed(0x84, 0x36, FAILED_ACTIVE, 0x01));
    // None of the rejected messages took effect.
    assert!(ccid.is_active());
}

#[test]
fn oversized_and_truncated_messages() {
    let mut ccid = powered();
    // 3073 bytes exceed dwMaxCCIDMessageLength even with a consistent dwLength.
    let r = reply(ccid.message(&xfr(0x37, 0x0000, &vec![0; MAX_DATA + 1])));
    assert_eq!(r, rsp(0x80, 0x37, FAILED_ACTIVE, 0x01, 0x00, &[]));
    // Shorter than the header: echo what exists, bError names dwLength.
    let r = reply(ccid.message(&[0x65, 0, 0, 0, 0, 0, 0x38]));
    assert_eq!(r, rsp(0x81, 0x38, FAILED_ACTIVE, 0x01, 0x00, &[]));
    let r = reply(ccid.message(&[0x62]));
    assert_eq!(r, rsp(0x80, 0x00, FAILED_ACTIVE, 0x01, 0x00, &[]));
    let r = reply(ccid.message(&[]));
    assert_eq!(r, rsp(0x81, 0x00, FAILED_ACTIVE, 0x01, 0x00, &[]));
    // A nine-byte SetDataRateAndClockFrequency header still gets the 8-byte layout.
    let r = reply(ccid.message(&[0x73, 8, 0, 0, 0, 0, 0x39, 0, 0]));
    assert_eq!(r, failed(0x84, 0x39, FAILED_ACTIVE, 0x01));
}

#[test]
fn truncated_messages_change_nothing() {
    // A message shorter than its 10-byte header (§6.1) is never acted on: a cut-off
    // IccPowerOff does not power down and a cut-off Abort does not cancel the APDU.
    let mut ccid = powered();
    send_apdu(&mut ccid, 0x01, &[0x00, 0x87, 0x07, 0x9E]);
    for msg in [
        &[0x63, 0, 0, 0, 0, 0, 0x02, 0, 0][..],
        &[0x72, 0, 0, 0, 0, 0, 0x03, 0, 0],
        &[0x62, 0, 0, 0, 0, 0, 0x04],
        &[0x6F, 4, 0, 0, 0, 0],
    ] {
        let r = reply(ccid.message(msg));
        assert_eq!((r[7], r[8]), (FAILED_ACTIVE, 0x01), "{msg:02x?}");
        assert_eq!(ccid.pending_seq(), Some(0x01));
    }
    let r = ccid.apdu_response(0x01, &[0x90, 0x00]);
    assert_eq!(r, rsp(0x80, 0x01, ACTIVE, 0x00, 0x00, &[0x90, 0x00]));
    assert!(ccid.is_active());
}

#[test]
fn power_off_while_busy_is_refused_and_keeps_the_session() {
    // bMaxCCIDBusySlots 1: IccPowerOff to the busy slot fails with CMD_SLOT_BUSY,
    // as a plain Reply (the card session does not end) and the APDU stays pending.
    let mut ccid = powered();
    send_apdu(&mut ccid, 0x01, &[0x00, 0x87, 0x07, 0x9E]);
    let action = ccid.message(&cmd(0x63, 0, 0x02, [0; 3], &[]));
    assert_eq!(
        action,
        CcidAction::Reply(rsp(0x81, 0x02, FAILED_ACTIVE, 0xE0, 0x00, &[]))
    );
    assert!(ccid.is_active());
    assert_eq!(ccid.pending_seq(), Some(0x01));
}

#[test]
fn failed_parameter_replies_report_the_parameters_in_force() {
    // §6.2.3: RDR_to_PC_Parameters always names T=1 and carries its 7 bytes, also
    // when the command fails for a reason unrelated to the values (busy slot).
    let mut ccid = powered();
    let block = [0x11, 0x10, 0x20, 0x15, 0x00, 0x80, 0x00];
    let r = reply(ccid.message(&cmd(0x61, 0, 0x01, [T1, 0, 0], &block)));
    assert_eq!(r, rsp(0x82, 0x01, ACTIVE, 0x00, T1, &block));
    send_apdu(&mut ccid, 0x02, &[0x00, 0xCA, 0x00, 0x00]);
    for (seq, kind) in [(0x03, 0x6C), (0x04, 0x6D)] {
        let r = reply(ccid.message(&cmd(kind, 0, seq, [0; 3], &[])));
        assert_eq!(r, rsp(0x82, seq, FAILED_ACTIVE, 0xE0, T1, &block));
    }
    // ResetParameters was refused, so the block set above is still in force.
    assert_eq!(ccid.parameters_in_force().to_bytes(), block);
}

#[test]
fn busy_slot_rejects_everything_but_abort() {
    // bMaxCCIDBusySlots 1: while an APDU is with the card, every other command fails
    // with CMD_SLOT_BUSY (E0) in its paired reply type and changes nothing.
    let mut ccid = powered();
    send_apdu(&mut ccid, 0x01, &[0x00, 0x20, 0x00, 0x81]);
    for (seq, (kind, specific, data, response)) in (0x80..).zip(ALL) {
        if kind == 0x72 {
            continue;
        }
        let r = reply(ccid.message(&cmd(kind, 0, seq, specific, data)));
        assert_eq!(r, failed(response, seq, FAILED_ACTIVE, 0xE0), "{kind:#04x}");
        assert_eq!(ccid.pending_seq(), Some(0x01));
    }
    let r = ccid.apdu_response(0x01, &[0x90, 0x00]);
    assert_eq!(r, rsp(0x80, 0x01, ACTIVE, 0x00, 0x00, &[0x90, 0x00]));
    send_apdu(&mut ccid, 0x02, &[0x00, 0x20, 0x00, 0x81]);
}

// Device-initiated messages

#[test]
fn time_extension_requests_one_more_bwt() {
    // §6.2.6: bmCommandStatus 2 (bStatus 80) with bError = BWT multiplier 1.
    let mut ccid = powered();
    send_apdu(&mut ccid, 0x0C, &[0x00, 0xA1, 0x00, 0x00]);
    assert_eq!(
        ccid.time_extension(0x0C),
        rsp(0x80, 0x0C, 0x80, 0x01, 0x00, &[])
    );
    // Any number of extensions may precede the answer; each echoes bSeq.
    for _ in 0..3 {
        assert_eq!(
            ccid.time_extension(0x0C),
            rsp(0x80, 0x0C, 0x80, 0x01, 0x00, &[])
        );
    }
    assert_eq!(ccid.pending_seq(), Some(0x0C));
    let r = ccid.apdu_response(0x0C, &[0x90, 0x00]);
    assert_eq!(r, rsp(0x80, 0x0C, ACTIVE, 0x00, 0x00, &[0x90, 0x00]));
}

#[test]
fn slot_change_notification() {
    // §6.3.1: bmSlotICCState bit 0 = present, bit 1 = changed (catalog: "insertion 5003").
    let ccid = fresh();
    assert_eq!(ccid.slot_change(true), [0x50, 0x03]);
    assert_eq!(ccid.slot_change(false), [0x50, 0x02]);
}
