//! Extended APDU level chaining (USB CCID Rev 1.1 §6.1.4 `wLevelParameter`,
//! §6.2.1 `bChainParameter`). The reference descriptor advertises dwFeatures bit
//! 0x00040000 (short and extended APDU level) with dwMaxCCIDMessageLength 3072
//! (reference/physical-key/usb-reference-observation.json).

mod common;

use common::{MAX_DATA, cmd, powered, reply, rsp, send_apdu, xfr};
use lk_ccid::CcidAction;

/// wLevelParameter values (§6.1.4).
const WHOLE: u16 = 0x0000;
const BEGIN: u16 = 0x0001;
const END: u16 = 0x0002;
const CONTINUE: u16 = 0x0003;
const NEXT_RESPONSE: u16 = 0x0010;

/// bChainParameter values (§6.2.1).
const RESP_WHOLE: u8 = 0x00;
const RESP_BEGIN: u8 = 0x01;
const RESP_END: u8 = 0x02;
const RESP_CONTINUE: u8 = 0x03;
const MORE_COMMAND: u8 = 0x10;

const OK: u8 = 0x00;
const FAILED: u8 = 0x40;

/// Empty DataBlock asking for the next command part.
fn more(seq: u8) -> Vec<u8> {
    rsp(0x80, seq, OK, 0x00, MORE_COMMAND, &[])
}

/// Failed DataBlock with bError 08 (offset of wLevelParameter).
fn level_error(seq: u8) -> Vec<u8> {
    rsp(0x80, seq, FAILED, 0x08, 0x00, &[])
}

/// An extended case 3 APDU (ISO/IEC 7816-4 §5.1) with `n` data bytes.
fn extended_apdu(n: usize) -> Vec<u8> {
    let lc = u16::try_from(n).expect("n fits Lc");
    let mut apdu = vec![0x00, 0xDB, 0x3F, 0xFF, 0x00];
    apdu.extend_from_slice(&lc.to_be_bytes());
    apdu.extend((0..n).map(|i| (i % 251) as u8));
    apdu
}

#[test]
fn three_part_command_is_assembled() {
    let mut ccid = powered();
    let apdu = extended_apdu(7000);
    let (a, rest) = apdu.split_at(MAX_DATA);
    let (b, c) = rest.split_at(MAX_DATA);
    assert_eq!(reply(ccid.message(&xfr(1, BEGIN, a))), more(1));
    assert_eq!(ccid.pending_seq(), None, "not busy between parts");
    assert_eq!(reply(ccid.message(&xfr(2, CONTINUE, b))), more(2));
    assert_eq!(
        ccid.message(&xfr(3, END, c)),
        CcidAction::Apdu {
            seq: 3,
            apdu: apdu.clone()
        }
    );
    assert_eq!(ccid.pending_seq(), Some(3));
    assert_eq!(
        ccid.apdu_response(3, &[0x90, 0x00]),
        rsp(0x80, 3, OK, 0, RESP_WHOLE, &[0x90, 0x00])
    );
}

#[test]
fn two_part_command_and_other_messages_between_parts() {
    let mut ccid = powered();
    let apdu = extended_apdu(4000);
    let (a, b) = apdu.split_at(2000);
    assert_eq!(reply(ccid.message(&xfr(1, BEGIN, a))), more(1));
    // A GetSlotStatus between parts does not disturb the chain.
    let r = reply(ccid.message(&cmd(0x65, 0, 2, [0; 3], &[])));
    assert_eq!(r, rsp(0x81, 2, OK, 0, 0, &[]));
    assert_eq!(
        ccid.message(&xfr(3, END, b)),
        CcidAction::Apdu { seq: 3, apdu }
    );
}

#[test]
fn continuation_without_a_beginning_is_refused() {
    let mut ccid = powered();
    assert_eq!(reply(ccid.message(&xfr(1, END, &[0x00]))), level_error(1));
    assert_eq!(
        reply(ccid.message(&xfr(2, CONTINUE, &[0x00]))),
        level_error(2)
    );
    send_apdu(&mut ccid, 3, &[0x00, 0xCA, 0x00, 0x00]);
}

#[test]
fn new_command_during_a_chain_drops_the_chain() {
    // Model policy: 0000 or 0001 while a chain is open is out of order (bError 08)
    // and the partial command is discarded.
    for restart in [WHOLE, BEGIN] {
        let mut ccid = powered();
        assert_eq!(reply(ccid.message(&xfr(1, BEGIN, &[0x00, 0xDB]))), more(1));
        assert_eq!(
            reply(ccid.message(&xfr(2, restart, &[0x00, 0xCA, 0x00, 0x00]))),
            level_error(2)
        );
        assert_eq!(
            reply(ccid.message(&xfr(3, END, &[0x3F, 0xFF]))),
            level_error(3)
        );
        send_apdu(&mut ccid, 4, &[0x00, 0xCA, 0x00, 0x00]);
    }
}

#[test]
fn response_request_during_a_command_chain_is_refused() {
    let mut ccid = powered();
    assert_eq!(reply(ccid.message(&xfr(1, BEGIN, &[0x00, 0xDB]))), more(1));
    assert_eq!(
        reply(ccid.message(&xfr(2, NEXT_RESPONSE, &[]))),
        level_error(2)
    );
    assert_eq!(reply(ccid.message(&xfr(3, END, &[0x3F]))), level_error(3));
}

#[test]
fn unknown_level_parameter_is_refused() {
    let mut ccid = powered();
    for (seq, level) in [(1, 0x0004), (2, 0x0011), (3, 0x0100), (4, 0xFFFF)] {
        assert_eq!(
            reply(ccid.message(&xfr(seq, level, &[0x00, 0xCA, 0x00, 0x00]))),
            level_error(seq)
        );
    }
}

#[test]
fn long_response_is_fetched_in_parts() {
    let mut ccid = powered();
    send_apdu(&mut ccid, 5, &[0x00, 0xCB, 0x3F, 0xFF, 0x00, 0x00, 0x00]);
    let response: Vec<u8> = (0..7000u32).map(|i| (i % 253) as u8).collect();
    let first = ccid.apdu_response(5, &response);
    assert_eq!(
        first,
        rsp(0x80, 5, OK, 0, RESP_BEGIN, &response[..MAX_DATA])
    );
    assert_eq!(
        first.len(),
        3072,
        "a full message is exactly dwMaxCCIDMessageLength"
    );
    let second = reply(ccid.message(&xfr(6, NEXT_RESPONSE, &[])));
    assert_eq!(
        second,
        rsp(
            0x80,
            6,
            OK,
            0,
            RESP_CONTINUE,
            &response[MAX_DATA..2 * MAX_DATA]
        )
    );
    let third = reply(ccid.message(&xfr(7, NEXT_RESPONSE, &[])));
    assert_eq!(
        third,
        rsp(0x80, 7, OK, 0, RESP_END, &response[2 * MAX_DATA..])
    );
    // Nothing left.
    assert_eq!(
        reply(ccid.message(&xfr(8, NEXT_RESPONSE, &[]))),
        level_error(8)
    );
}

#[test]
fn response_boundaries() {
    // 3062 bytes fit one message; 3063 need a second, one-byte part.
    let mut ccid = powered();
    send_apdu(&mut ccid, 1, &[0x00, 0xB0, 0x00, 0x00, 0x00, 0x0B, 0xF6]);
    let exact = vec![0xA5; MAX_DATA];
    assert_eq!(
        ccid.apdu_response(1, &exact),
        rsp(0x80, 1, OK, 0, RESP_WHOLE, &exact)
    );
    assert_eq!(
        reply(ccid.message(&xfr(2, NEXT_RESPONSE, &[]))),
        level_error(2)
    );

    send_apdu(&mut ccid, 3, &[0x00, 0xB0, 0x00, 0x00, 0x00, 0x0B, 0xF7]);
    let over = vec![0xA5; MAX_DATA + 1];
    assert_eq!(
        ccid.apdu_response(3, &over),
        rsp(0x80, 3, OK, 0, RESP_BEGIN, &over[..MAX_DATA])
    );
    let last = reply(ccid.message(&xfr(4, NEXT_RESPONSE, &[])));
    assert_eq!(last, rsp(0x80, 4, OK, 0, RESP_END, &[0xA5]));
}

#[test]
fn response_request_without_pending_response_is_refused() {
    let mut ccid = powered();
    assert_eq!(
        reply(ccid.message(&xfr(1, NEXT_RESPONSE, &[]))),
        level_error(1)
    );
}

#[test]
fn response_request_must_be_empty() {
    let mut ccid = powered();
    send_apdu(&mut ccid, 1, &[0x00, 0xCB, 0x3F, 0xFF]);
    ccid.apdu_response(1, &vec![0; MAX_DATA + 10]);
    assert_eq!(
        reply(ccid.message(&xfr(2, NEXT_RESPONSE, &[0x00]))),
        level_error(2)
    );
    // The error dropped the rest of the response.
    assert_eq!(
        reply(ccid.message(&xfr(3, NEXT_RESPONSE, &[]))),
        level_error(3)
    );
}

#[test]
fn new_command_abandons_the_rest_of_a_response() {
    let mut ccid = powered();
    send_apdu(&mut ccid, 1, &[0x00, 0xCB, 0x3F, 0xFF]);
    ccid.apdu_response(1, &vec![0; 2 * MAX_DATA]);
    send_apdu(&mut ccid, 2, &[0x00, 0xCA, 0x00, 0x00]);
    assert_eq!(
        ccid.apdu_response(2, &[0x90, 0x00]),
        rsp(0x80, 2, OK, 0, RESP_WHOLE, &[0x90, 0x00])
    );
    assert_eq!(
        reply(ccid.message(&xfr(3, NEXT_RESPONSE, &[]))),
        level_error(3)
    );

    // The same for a new chained command.
    send_apdu(&mut ccid, 4, &[0x00, 0xCB, 0x3F, 0xFF]);
    ccid.apdu_response(4, &vec![0; 2 * MAX_DATA]);
    assert_eq!(reply(ccid.message(&xfr(5, BEGIN, &[0x00, 0xDB]))), more(5));
    assert_eq!(
        ccid.message(&xfr(6, END, &[0x3F, 0xFF])),
        CcidAction::Apdu {
            seq: 6,
            apdu: vec![0x00, 0xDB, 0x3F, 0xFF]
        }
    );
}

#[test]
fn power_off_drops_partial_chains() {
    let mut ccid = powered();
    assert_eq!(reply(ccid.message(&xfr(1, BEGIN, &[0x00, 0xDB]))), more(1));
    assert!(matches!(
        ccid.message(&cmd(0x63, 0, 2, [0; 3], &[])),
        CcidAction::PowerOff(_)
    ));
    reply(ccid.message(&cmd(0x62, 0, 3, [0; 3], &[])));
    assert_eq!(
        reply(ccid.message(&xfr(4, END, &[0x3F, 0xFF]))),
        level_error(4)
    );

    send_apdu(&mut ccid, 5, &[0x00, 0xCB, 0x3F, 0xFF]);
    ccid.apdu_response(5, &vec![0; 2 * MAX_DATA]);
    assert!(matches!(
        ccid.message(&cmd(0x63, 0, 6, [0; 3], &[])),
        CcidAction::PowerOff(_)
    ));
    reply(ccid.message(&cmd(0x62, 0, 7, [0; 3], &[])));
    assert_eq!(
        reply(ccid.message(&xfr(8, NEXT_RESPONSE, &[]))),
        level_error(8)
    );
}

#[test]
fn largest_extended_apdu_is_accepted_and_one_more_byte_is_not() {
    // ISO/IEC 7816-4 §5.1: an extended case 4 APDU has at most 4 + 3 + 65 535 + 2 bytes.
    const MAX_APDU: usize = 4 + 3 + 65_535 + 2;
    let mut apdu = extended_apdu(65_535);
    apdu.extend_from_slice(&[0x00, 0x00]);
    assert_eq!(apdu.len(), MAX_APDU);

    let mut ccid = powered();
    let parts: Vec<&[u8]> = apdu.chunks(MAX_DATA).collect();
    let (last, middle) = parts.split_last().expect("parts");
    let (first, middle) = middle.split_first().expect("parts");
    let mut seq = 0u8;
    assert_eq!(reply(ccid.message(&xfr(seq, BEGIN, first))), more(seq));
    for part in middle {
        seq += 1;
        assert_eq!(reply(ccid.message(&xfr(seq, CONTINUE, part))), more(seq));
    }
    seq += 1;
    assert_eq!(
        ccid.message(&xfr(seq, END, last)),
        CcidAction::Apdu {
            seq,
            apdu: apdu.clone()
        }
    );

    // One byte more: the overflowing part fails with bError 01 and drops the chain.
    let mut ccid = powered();
    let mut seq = 0u8;
    assert_eq!(reply(ccid.message(&xfr(seq, BEGIN, first))), more(seq));
    for part in middle {
        seq += 1;
        assert_eq!(reply(ccid.message(&xfr(seq, CONTINUE, part))), more(seq));
    }
    let mut too_long = last.to_vec();
    too_long.push(0x00);
    seq += 1;
    assert_eq!(
        reply(ccid.message(&xfr(seq, END, &too_long))),
        rsp(0x80, seq, FAILED, 0x01, 0, &[])
    );
    seq += 1;
    assert_eq!(
        reply(ccid.message(&xfr(seq, END, &[0x00]))),
        level_error(seq)
    );
}

#[test]
fn chained_command_with_chained_response() {
    let mut ccid = powered();
    let apdu = extended_apdu(5000);
    let (a, b) = apdu.split_at(MAX_DATA);
    assert_eq!(reply(ccid.message(&xfr(0xFE, BEGIN, a))), more(0xFE));
    assert_eq!(
        ccid.message(&xfr(0xFF, END, b)),
        CcidAction::Apdu { seq: 0xFF, apdu }
    );
    let response = vec![0x3C; 5000];
    let first = ccid.apdu_response(0xFF, &response);
    assert_eq!(
        first,
        rsp(0x80, 0xFF, OK, 0, RESP_BEGIN, &response[..MAX_DATA])
    );
    // bSeq wraps around.
    let second = reply(ccid.message(&xfr(0x00, NEXT_RESPONSE, &[])));
    assert_eq!(
        second,
        rsp(0x80, 0x00, OK, 0, RESP_END, &response[MAX_DATA..])
    );
}

#[test]
fn chain_parts_after_power_off_fail_with_an_inactive_icc() {
    // After IccPowerOff (§6.1.2) the ICC is inactive: every XfrBlock, whatever its
    // wLevelParameter, fails with bmICCStatus 1 and no APDU reaches the card.
    let mut ccid = powered();
    assert_eq!(reply(ccid.message(&xfr(1, BEGIN, &[0x00, 0xDB]))), more(1));
    assert!(matches!(
        ccid.message(&cmd(0x63, 0, 2, [0; 3], &[])),
        CcidAction::PowerOff(_)
    ));
    for (seq, level, data) in [
        (3, CONTINUE, &[0x3F][..]),
        (4, END, &[0xFF]),
        (5, NEXT_RESPONSE, &[]),
        (6, WHOLE, &[0x00, 0xCA, 0x00, 0x00]),
        (7, BEGIN, &[0x00, 0xDB]),
    ] {
        assert_eq!(
            reply(ccid.message(&xfr(seq, level, data))),
            rsp(0x80, seq, 0x41, 0xFE, 0, &[]),
            "wLevelParameter {level:#06x}"
        );
    }
    assert!(!ccid.is_active());
    assert_eq!(ccid.pending_seq(), None);
}

#[test]
fn out_of_order_parts_reset_the_chain() {
    // Each row is a sequence of (wLevelParameter, expected outcome) for one slot:
    // 'm' = empty DataBlock with bChainParameter 10, 'a' = APDU handed over,
    // 'e' = bError 08. An out-of-order part drops the partial command, so the parts
    // that follow it are out of order too until a new 0000 or 0001.
    let rows: [&[(u16, char)]; 6] = [
        &[(BEGIN, 'm'), (CONTINUE, 'm'), (CONTINUE, 'm'), (END, 'a')],
        &[
            (BEGIN, 'm'),
            (BEGIN, 'e'),
            (CONTINUE, 'e'),
            (END, 'e'),
            (WHOLE, 'a'),
        ],
        &[(CONTINUE, 'e'), (BEGIN, 'm'), (END, 'a')],
        &[
            (BEGIN, 'm'),
            (WHOLE, 'e'),
            (END, 'e'),
            (BEGIN, 'm'),
            (END, 'a'),
        ],
        &[
            (BEGIN, 'm'),
            (NEXT_RESPONSE, 'e'),
            (CONTINUE, 'e'),
            (WHOLE, 'a'),
        ],
        &[
            (BEGIN, 'm'),
            (0x0004, 'e'),
            (END, 'e'),
            (BEGIN, 'm'),
            (END, 'a'),
        ],
    ];
    for (row, steps) in rows.iter().enumerate() {
        let mut ccid = powered();
        let mut sent = Vec::new();
        for (seq, &(level, outcome)) in (1u8..).zip(steps.iter()) {
            let data: &[u8] = if level == NEXT_RESPONSE {
                &[]
            } else {
                &[0x00, 0xCA, 0x00, seq]
            };
            let action = ccid.message(&xfr(seq, level, data));
            match outcome {
                'm' => {
                    if level == BEGIN {
                        sent.clear();
                    }
                    sent.extend_from_slice(data);
                    assert_eq!(action, CcidAction::Reply(more(seq)), "row {row} seq {seq}");
                }
                'a' => {
                    if level == WHOLE {
                        sent.clear();
                    }
                    sent.extend_from_slice(data);
                    assert_eq!(
                        action,
                        CcidAction::Apdu {
                            seq,
                            apdu: sent.clone()
                        },
                        "row {row} seq {seq}"
                    );
                }
                _ => assert_eq!(
                    action,
                    CcidAction::Reply(level_error(seq)),
                    "row {row} seq {seq}"
                ),
            }
        }
    }
}

#[test]
fn end_part_after_the_apdu_was_dispatched_is_refused() {
    // Once 0002 completed the command, the slot is busy (CMD_SLOT_BUSY E0); after
    // the answer, another 0002 has no chain to end (bError 08).
    let mut ccid = powered();
    assert_eq!(reply(ccid.message(&xfr(1, BEGIN, &[0x00, 0xDB]))), more(1));
    assert!(matches!(
        ccid.message(&xfr(2, END, &[0x3F, 0xFF])),
        CcidAction::Apdu { seq: 2, .. }
    ));
    assert_eq!(
        reply(ccid.message(&xfr(3, END, &[0x00]))),
        rsp(0x80, 3, FAILED, 0xE0, 0, &[])
    );
    assert_eq!(ccid.pending_seq(), Some(2));
    ccid.apdu_response(2, &[0x90, 0x00]);
    assert_eq!(reply(ccid.message(&xfr(4, END, &[0x00]))), level_error(4));
}

#[test]
fn response_of_exactly_two_full_messages() {
    // 2 × 3062 bytes: bChainParameter 01 then 02, with no 03 between them.
    let mut ccid = powered();
    send_apdu(&mut ccid, 1, &[0x00, 0xCB, 0x3F, 0xFF]);
    let response: Vec<u8> = (0..2 * MAX_DATA).map(|i| (i % 249) as u8).collect();
    assert_eq!(
        ccid.apdu_response(1, &response),
        rsp(0x80, 1, OK, 0, RESP_BEGIN, &response[..MAX_DATA])
    );
    assert_eq!(
        reply(ccid.message(&xfr(2, NEXT_RESPONSE, &[]))),
        rsp(0x80, 2, OK, 0, RESP_END, &response[MAX_DATA..])
    );
}

#[test]
fn largest_extended_response_is_reassembled() {
    // ISO/IEC 7816-4 §5.1: at most 65 536 data bytes plus SW1-SW2. Every bulk-in
    // message stays within dwMaxCCIDMessageLength 3072 and the parts concatenate to
    // the response: 01, then 03 for each full middle part, then 02.
    let mut ccid = powered();
    send_apdu(&mut ccid, 0x80, &[0x00, 0xCB, 0x3F, 0xFF, 0x00, 0x00, 0x00]);
    let mut response: Vec<u8> = (0..65_536u32).map(|i| (i % 241) as u8).collect();
    response.extend_from_slice(&[0x90, 0x00]);
    let first = ccid.apdu_response(0x80, &response);
    assert_eq!(first.len(), 3072);
    assert_eq!(first[9], RESP_BEGIN);
    let mut assembled = first[10..].to_vec();
    let mut seq = 0x80u8;
    loop {
        seq = seq.wrapping_add(1);
        let part = reply(ccid.message(&xfr(seq, NEXT_RESPONSE, &[])));
        assert!(part.len() <= 3072);
        let length = u32::from_le_bytes([part[1], part[2], part[3], part[4]]);
        assert_eq!(usize::try_from(length).expect("u32"), part.len() - 10);
        assert_eq!((part[6], part[7], part[8]), (seq, OK, 0));
        assembled.extend_from_slice(&part[10..]);
        match part[9] {
            RESP_CONTINUE => assert_eq!(part.len(), 3072),
            RESP_END => break,
            other => panic!("bChainParameter {other:#04x}"),
        }
    }
    assert_eq!(assembled, response);
    // 65 538 = 21 × 3062 + 1 236: one 01, twenty 03 and one 02 message.
    assert_eq!(seq, 0x80 + 21);
}
