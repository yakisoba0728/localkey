//! The vpcd transport against a fake vpcd on `127.0.0.1` and a fake runner with a scripted
//! CCID card (`docs/PROGRAM.md` "lk-vpcd"). Every test plays vpcd's side byte for byte and
//! checks the CCID messages the transport hands to the runner.

#![cfg(unix)]

mod common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use lk_device::Output;
use lk_run::HostInput;
use lk_vpcd::{DROP_TIMEOUT, PEER_CHECK, REPLUG_PAUSE, REPLY_SILENCE, RETRY_INTERVAL, VpcdNotice, VpcdStats};

use common::{
    ABORT, ATR, Card, FakeVpcd, Harness, ICC_POWER_OFF, ICC_POWER_ON, PowerOn, QUIET, WAIT, XFR_BLOCK, Xfr,
    data_block, identity, time_extension, with_ccid, without_ccid,
};

const SELECT_OATH: [u8; 12] = [0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];

/// The fake card's response to `apdu` (the default script echoes it with `9000`).
fn echoed(apdu: &[u8]) -> Vec<u8> {
    common::echo(apdu)
}

#[test]
fn nothing_connects_before_an_enumeration_with_ccid() {
    let vpcd = FakeVpcd::bind();
    let harness = Harness::new(vpcd.addr());
    vpcd.no_connection(QUIET);
    harness.enumerate(&without_ccid());
    vpcd.no_connection(RETRY_INTERVAL + QUIET);
    assert_eq!(harness.attempts_so_far(), 0, "no attempt without CCID");
    assert_eq!(harness.attached(), Some(false));
}

#[test]
fn an_enumeration_with_ccid_connects_to_vpcd() {
    let vpcd = FakeVpcd::bind();
    let (harness, _conn) = Harness::connected(&vpcd);
    assert!(harness.attached_becomes(true));
    assert_eq!(harness.notice(|notice| matches!(notice, VpcdNotice::Connected { .. })), VpcdNotice::Connected {
        addr: vpcd.addr()
    });
    harness.no_input();
    assert_eq!(harness.stats().connections, 1);
}

#[test]
fn the_first_get_atr_powers_the_card_on_and_later_ones_reuse_the_atr() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    assert_eq!(conn.atr(), ATR);
    let power_on = harness.input();
    assert_eq!(power_on.kind, ICC_POWER_ON);
    assert_eq!(power_on.specific, [0x00, 0, 0], "automatic voltage selection");
    assert!(power_on.data.is_empty());
    // vpcd's presence checks: answered from the ATR already known.
    for _ in 0..5 {
        assert_eq!(conn.atr(), ATR);
    }
    harness.no_input();
}

#[test]
fn power_on_and_power_off_reach_the_card_and_get_no_answer() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    conn.power_on();
    assert_eq!(harness.input().kind, ICC_POWER_ON);
    assert!(conn.quiet(QUIET), "vpcd expects no answer to power on");
    conn.power_off();
    assert_eq!(harness.input().kind, ICC_POWER_OFF);
    assert!(conn.quiet(QUIET), "vpcd expects no answer to power off");
    // The ATR of the last power-on is still the answer after a power off.
    assert_eq!(conn.atr(), ATR);
    harness.no_input();
}

#[test]
fn reset_is_a_power_off_then_a_power_on() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    conn.reset();
    assert_eq!(harness.input().kind, ICC_POWER_OFF);
    assert_eq!(harness.input().kind, ICC_POWER_ON);
    assert!(conn.quiet(QUIET), "vpcd expects no answer to reset");
    assert_eq!(conn.atr(), ATR);
    harness.no_input();
}

#[test]
fn every_message_gets_the_next_bseq() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    conn.power_on();
    conn.transmit(&SELECT_OATH);
    conn.power_off();
    conn.reset();
    let seqs: Vec<u8> = (0..5).map(|_| harness.input().seq).collect();
    assert_eq!(seqs, vec![0, 1, 2, 3, 4]);
}

#[test]
fn an_apdu_travels_as_an_xfr_block_and_its_data_block_answers_it() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    conn.power_on();
    assert_eq!(harness.input().kind, ICC_POWER_ON);
    assert_eq!(conn.transmit(&SELECT_OATH), echoed(&SELECT_OATH));
    let block = harness.input();
    assert_eq!(block.kind, XFR_BLOCK);
    assert_eq!(block.specific, [0x00, 0x00, 0x00], "bBWI 0, wLevelParameter 0000");
    assert_eq!(block.data, SELECT_OATH);
    harness.no_input();
}

#[test]
fn an_apdu_before_any_power_on_powers_the_card_on_first() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    assert_eq!(conn.transmit(&SELECT_OATH), echoed(&SELECT_OATH));
    assert_eq!(harness.input().kind, ICC_POWER_ON);
    assert_eq!(harness.input().kind, XFR_BLOCK);
    // Powered now: the next APDU goes straight through, and so does `GET ATR`.
    conn.transmit(&[0x00, 0xA1, 0x00, 0x00]);
    assert_eq!(harness.input().kind, XFR_BLOCK);
    assert_eq!(conn.atr(), ATR);
    harness.no_input();
}

#[test]
fn an_apdu_after_vpcds_power_off_powers_the_card_on_again() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    conn.power_on();
    conn.power_off();
    assert_eq!(harness.input().kind, ICC_POWER_ON);
    assert_eq!(harness.input().kind, ICC_POWER_OFF);
    conn.transmit(&SELECT_OATH);
    assert_eq!(harness.input().kind, ICC_POWER_ON);
    assert_eq!(harness.input().kind, XFR_BLOCK);
}

#[test]
fn time_extensions_are_skipped_until_the_answer() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    harness.set_card(Card { xfr: Xfr::Answer { time_extensions: 3, stale_first: false }, ..Card::default() });
    assert_eq!(conn.transmit(&SELECT_OATH), echoed(&SELECT_OATH));
    assert_eq!(harness.stats().time_extensions, 3);
}

#[test]
fn a_command_held_by_the_card_is_answered_when_it_is_released() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    conn.power_on();
    assert_eq!(conn.atr(), ATR, "the power-on exchange is complete");
    harness.set_card(Card { xfr: Xfr::Hold, ..Card::default() });
    conn.send(&SELECT_OATH);
    assert!(conn.quiet(Duration::from_millis(600)), "the time extension is not passed to vpcd");
    // Further time extensions while the command waits (the device sends one every 500 ms).
    let seq = {
        assert_eq!(harness.input().kind, ICC_POWER_ON);
        harness.input().seq
    };
    for _ in 0..3 {
        harness.deliver(Output::Ccid(time_extension(seq)));
    }
    assert!(conn.quiet(QUIET));
    harness.release();
    assert_eq!(conn.recv(), echoed(&SELECT_OATH));
    assert_eq!(harness.stats().time_extensions, 4);
}

#[test]
fn time_extensions_keep_a_command_alive_past_the_reply_silence() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    conn.power_on();
    assert_eq!(conn.atr(), ATR, "the power-on exchange is complete");
    assert_eq!(harness.input().kind, ICC_POWER_ON);
    harness.set_card(Card { xfr: Xfr::Hold, ..Card::default() });
    conn.send(&SELECT_OATH);
    let seq = harness.input().seq;
    // A time extension every 500 ms, as the device sends them, for longer than the silence
    // after which an unanswered command counts as dropped.
    let until = Instant::now() + REPLY_SILENCE + Duration::from_millis(1_500);
    let mut sent = 0;
    while Instant::now() < until {
        assert!(conn.quiet(Duration::from_millis(500)), "no 6F00 while time extensions arrive");
        harness.deliver(Output::Ccid(time_extension(seq)));
        sent += 1;
    }
    harness.release();
    assert_eq!(conn.recv(), echoed(&SELECT_OATH));
    assert_eq!(harness.stats(), VpcdStats {
        connections: 1,
        ignored: 0,
        stale: 0,
        time_extensions: 1 + sent,
        errors: 0
    });
}

#[test]
fn replies_with_another_bseq_are_ignored() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    harness.set_card(Card { xfr: Xfr::Answer { time_extensions: 1, stale_first: true }, ..Card::default() });
    assert_eq!(conn.transmit(&SELECT_OATH), echoed(&SELECT_OATH));
    let stats = harness.stats();
    assert_eq!((stats.stale, stats.time_extensions), (1, 1));
}

#[test]
fn bulk_in_messages_that_arrive_between_commands_are_stale() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    conn.power_on();
    assert_eq!(harness.input().kind, ICC_POWER_ON);
    // Messages nobody asked for: a reply to some earlier command, and garbage.
    harness.deliver(Output::Ccid(data_block(0x77, 0x00, &[0x6A, 0x82])));
    harness.deliver(Output::Ccid(vec![0x80, 0x01]));
    assert_eq!(conn.transmit(&SELECT_OATH), echoed(&SELECT_OATH));
    assert_eq!(harness.stats().stale, 2);
}

#[test]
fn a_failed_reply_answers_6f00_and_the_next_apdu_powers_the_card_on_again() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    conn.power_on();
    assert_eq!(conn.atr(), ATR, "the power-on exchange is complete");
    assert_eq!(harness.input().kind, ICC_POWER_ON);
    harness.set_card(Card { xfr: Xfr::Fail, ..Card::default() });
    assert_eq!(conn.transmit(&SELECT_OATH), [0x6F, 0x00]);
    assert_eq!(harness.input().kind, XFR_BLOCK);
    let notice = harness.notice(|notice| matches!(notice, VpcdNotice::ErrorResponse { .. }));
    assert!(notice.to_string().contains("not powered"), "{notice}");

    harness.set_card(Card::default());
    assert_eq!(conn.transmit(&SELECT_OATH), echoed(&SELECT_OATH));
    assert_eq!(harness.input().kind, ICC_POWER_ON, "powered on again first");
    assert_eq!(harness.input().kind, XFR_BLOCK);
    assert_eq!(harness.stats().errors, 1);
}

#[test]
fn an_apdu_is_answered_with_6f00_when_the_card_cannot_be_powered_on() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    harness.set_card(Card { power_on: PowerOn::Fail, ..Card::default() });
    assert_eq!(conn.transmit(&SELECT_OATH), [0x6F, 0x00]);
    assert_eq!(harness.input().kind, ICC_POWER_ON);
    harness.no_input();
}

#[test]
fn a_get_atr_that_cannot_power_the_card_on_closes_the_connection() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    harness.set_card(Card { power_on: PowerOn::Silent, ..Card::default() });
    conn.control(0x04);
    assert!(conn.ends_silently(), "no empty answer: the card leaves instead");
    let notice = harness.notice(|notice| matches!(notice, VpcdNotice::Disconnected { .. }));
    assert!(notice.to_string().contains("no ATR"), "{notice}");
    // It comes back after the retry interval, as a new insertion.
    harness.set_card(Card::default());
    let mut conn = vpcd.accept();
    assert_eq!(conn.atr(), ATR);
}

#[test]
fn an_unanswered_command_is_answered_with_6f00_after_the_silence() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    conn.power_on();
    assert_eq!(conn.atr(), ATR, "the power-on exchange is complete");
    harness.set_card(Card { xfr: Xfr::Silent, ..Card::default() });
    let start = Instant::now();
    conn.send(&SELECT_OATH);
    assert_eq!(conn.recv(), [0x6F, 0x00]);
    let waited = start.elapsed();
    assert!(waited >= REPLY_SILENCE - Duration::from_millis(100), "answered after {waited:?}");
    assert!(waited < REPLY_SILENCE + WAIT, "answered after {waited:?}");
    let notice = harness.notice(|notice| matches!(notice, VpcdNotice::ErrorResponse { .. }));
    assert!(notice.to_string().contains("did not answer"), "{notice}");
}

#[test]
fn a_command_waits_as_long_as_the_runner_has_not_handled_it() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    conn.power_on();
    assert_eq!(harness.input().kind, ICC_POWER_ON);
    // A runner that takes its time: the marker stays unanswered, and so does the command.
    harness.set_card(Card { xfr: Xfr::Hold, answer_markers: false, ..Card::default() });
    conn.send(&SELECT_OATH);
    assert_eq!(harness.input().kind, XFR_BLOCK);
    assert!(conn.quiet(REPLY_SILENCE + Duration::from_secs(1)), "no 6F00 while the runner has not handled it");
    harness.release();
    assert_eq!(conn.recv(), echoed(&SELECT_OATH));
}

#[test]
fn a_long_apdu_is_sent_in_parts_of_the_message_limit() {
    let vpcd = FakeVpcd::bind();
    let harness = Harness::new(vpcd.addr());
    // 271-byte messages: 261 bytes of data each.
    harness.enumerate(&identity(true, 271));
    let mut conn = vpcd.accept();
    conn.power_on();
    assert_eq!(harness.input().kind, ICC_POWER_ON);
    let mut apdu = vec![0x00, 0xDB, 0x3F, 0xFF, 0x00, 0x02, 0x58];
    apdu.extend((0..600u16).map(|i| i as u8));
    harness.set_card(Card { respond: |_| vec![0x90, 0x00], ..Card::default() });
    assert_eq!(conn.transmit(&apdu), [0x90, 0x00]);
    let parts: Vec<(u16, usize)> = (0..3)
        .map(|_| {
            let block = harness.input();
            assert_eq!(block.kind, XFR_BLOCK);
            (block.level(), block.data.len())
        })
        .collect();
    assert_eq!(parts, vec![(0x0001, 261), (0x0003, 261), (0x0002, apdu.len() - 522)]);
}

#[test]
fn a_chained_response_is_fetched_with_empty_continuation_blocks() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    conn.power_on();
    assert_eq!(conn.atr(), ATR, "the power-on exchange is complete");
    assert_eq!(harness.input().kind, ICC_POWER_ON);
    harness.set_card(Card {
        respond: |_| {
            let mut response: Vec<u8> = (0..7000u16).map(|i| i as u8).collect();
            response.extend([0x90, 0x00]);
            response
        },
        ..Card::default()
    });
    let response = conn.transmit(&[0x00, 0xCB, 0x3F, 0xFF, 0x00, 0x00, 0x00]);
    assert_eq!(response.len(), 7002);
    assert_eq!(&response[..4], &[0, 1, 2, 3]);
    assert_eq!(&response[7000..], &[0x90, 0x00]);
    let first = harness.input();
    assert_eq!(first.level(), 0x0000);
    let fetches: Vec<(u16, usize)> =
        (0..2).map(|_| harness.input()).map(|block| (block.level(), block.data.len())).collect();
    assert_eq!(fetches, vec![(0x0010, 0), (0x0010, 0)], "3062 + 3062 + 878 bytes");
}

#[test]
fn a_response_too_long_for_a_vpcd_message_is_answered_with_6f00() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    conn.power_on();
    assert_eq!(conn.atr(), ATR, "the power-on exchange is complete");
    harness.set_card(Card { respond: |_| vec![0x61; 65_536], ..Card::default() });
    assert_eq!(conn.transmit(&[0x00, 0xCB, 0x3F, 0xFF, 0x00, 0x00, 0x00]), [0x6F, 0x00]);
    let notice = harness.notice(|notice| matches!(notice, VpcdNotice::ErrorResponse { .. }));
    assert!(notice.to_string().contains("does not fit"), "{notice}");
}

#[test]
fn unknown_control_commands_and_empty_messages_are_ignored() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    conn.control(0x03);
    conn.control(0xFF);
    conn.send(&[]);
    assert!(conn.quiet(QUIET), "nothing is answered");
    harness.no_input();
    assert_eq!(conn.atr(), ATR, "the connection still works");
    let ignored: Vec<String> =
        harness.notice_log().into_iter().filter(|line| line.starts_with("Ignored")).collect();
    assert_eq!(ignored.len(), 3, "{ignored:?}");
}

#[test]
fn a_two_byte_payload_is_an_apdu_even_when_it_starts_with_a_control_byte() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    assert_eq!(conn.transmit(&[0x04, 0x00]), echoed(&[0x04, 0x00]));
    assert_eq!(harness.input().kind, ICC_POWER_ON);
    let block = harness.input();
    assert_eq!((block.kind, block.data), (XFR_BLOCK, vec![0x04, 0x00]));
}

#[test]
fn outputs_other_than_ccid_bulk_in_are_ignored() {
    let vpcd = FakeVpcd::bind();
    let (harness, _conn) = Harness::connected(&vpcd);
    harness.deliver(Output::FidoReport([0; 64]));
    harness.deliver(Output::OtpKeyboard([0; 8]));
    harness.deliver(Output::OtpFeature([0; 8]));
    harness.deliver(Output::CcidInterrupt(vec![0x50, 0x03]));
    harness.deliver(Output::PresenceIndicator(true));
    assert_eq!(harness.stats(), VpcdStats { connections: 1, ignored: 4, stale: 0, time_extensions: 0, errors: 0 });
    harness.no_input();
}

#[test]
fn connection_attempts_are_one_second_apart_while_vpcd_is_down() {
    let addr = FakeVpcd::bind().addr();
    // The fake vpcd is gone: nothing listens on the port.
    let harness = Harness::new(addr);
    harness.enumerate(&with_ccid());
    let times = harness.attempts(3);
    for pair in times.windows(2) {
        let gap = pair[1] - pair[0];
        assert!(gap >= RETRY_INTERVAL - Duration::from_millis(50), "attempts {gap:?} apart");
        assert!(gap < RETRY_INTERVAL + Duration::from_secs(5), "attempts {gap:?} apart");
    }
    let unreachable: Vec<String> =
        harness.notice_log().into_iter().filter(|line| line.starts_with("Unreachable")).collect();
    assert_eq!(unreachable.len(), 1, "only the first failure is reported: {unreachable:?}");
    assert_eq!(harness.attached(), Some(false));
}

#[test]
fn the_transport_reconnects_after_vpcd_restarts() {
    let vpcd = FakeVpcd::bind();
    let addr = vpcd.addr();
    let (harness, mut conn) = Harness::connected(&vpcd);
    assert_eq!(conn.atr(), ATR);
    assert_eq!(harness.input().kind, ICC_POWER_ON);
    drop(vpcd);
    conn.close();
    harness.notice(|notice| matches!(notice, VpcdNotice::Disconnected { .. }));
    assert!(harness.attached_becomes(false));
    // vpcd is down for a while; the transport keeps trying.
    harness.notice(|notice| matches!(notice, VpcdNotice::Unreachable { .. }));
    let vpcd = FakeVpcd::rebind(addr);
    let mut conn = vpcd.accept();
    assert!(harness.attached_becomes(true));
    // A new insertion: the first `GET ATR` powers the card on again.
    assert_eq!(conn.atr(), ATR);
    assert_eq!(harness.input().kind, ICC_POWER_ON);
    assert_eq!(harness.stats().connections, 2);
}

#[test]
fn a_connection_closed_by_vpcd_is_made_again() {
    let vpcd = FakeVpcd::bind();
    let (harness, conn) = Harness::connected(&vpcd);
    let start = Instant::now();
    conn.close();
    let mut conn = vpcd.accept();
    assert!(start.elapsed() < RETRY_INTERVAL + WAIT);
    assert_eq!(conn.atr(), ATR);
    assert_eq!(harness.stats().connections, 2);
}

#[test]
fn a_connection_lost_while_a_command_waits_aborts_the_command_and_the_card_comes_back() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    conn.power_on();
    assert_eq!(conn.atr(), ATR, "the power-on exchange is complete");
    assert_eq!(harness.input().kind, ICC_POWER_ON);
    // A command that waits for as long as anyone cares (a touch nobody gives): the marker
    // stays unanswered too, so nothing but the lost connection can end the wait.
    harness.set_card(Card { xfr: Xfr::Hold, answer_markers: false, ..Card::default() });
    conn.send(&SELECT_OATH);
    let held = harness.input();
    assert_eq!(held.kind, XFR_BLOCK);
    assert!(conn.quiet(QUIET));
    // vpcd goes away (pcscd stopped or crashed).
    conn.close();
    // USB CCID Rev 1.1 §5.3.1, §6.1.13: the control request, then PC_to_RDR_Abort with
    // the same, new bSeq. Generous for PEER_CHECK, yet below REPLY_SILENCE.
    let input = harness.host_input(Duration::from_secs(3));
    let HostInput::CcidControlAbort { slot, seq } = input else {
        panic!("the transport sent {input:?}, not the ABORT control request");
    };
    assert_eq!((slot, seq), (0, held.seq.wrapping_add(1)), "slot 0, the next bSeq");
    let abort = harness.input();
    assert_eq!((abort.kind, abort.seq, abort.data.len()), (ABORT, seq, 0));
    let notice = harness.notice(|notice| matches!(notice, VpcdNotice::Disconnected { .. }));
    assert!(notice.to_string().contains("while a command waited"), "{notice}");
    // The card is inserted again; the bSeq counter runs on across connections.
    harness.set_card(Card::default());
    let mut again = vpcd.accept();
    assert_eq!(again.atr(), ATR);
    let power_on = harness.input();
    assert_eq!((power_on.kind, power_on.seq), (ICC_POWER_ON, seq.wrapping_add(1)));
    assert_eq!(again.transmit(&SELECT_OATH), echoed(&SELECT_OATH));
    // The answers to the abort (the held command's failed DataBlock, the SlotStatus) were
    // nobody's reply.
    let stats = harness.stats();
    assert_eq!((stats.connections, stats.stale, stats.errors), (2, 2, 0));
}

#[test]
fn the_bseq_counter_runs_on_across_connections() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    assert_eq!(conn.atr(), ATR);
    assert_eq!(harness.input().seq, 0);
    conn.close();
    let mut conn = vpcd.accept();
    assert_eq!(conn.atr(), ATR);
    let power_on = harness.input();
    assert_eq!((power_on.kind, power_on.seq), (ICC_POWER_ON, 1));
}

#[test]
fn a_message_vpcd_sends_while_a_command_waits_is_read_after_the_answer() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    conn.power_on();
    assert_eq!(conn.atr(), ATR, "the power-on exchange is complete");
    assert_eq!(harness.input().kind, ICC_POWER_ON);
    harness.set_card(Card { xfr: Xfr::Hold, ..Card::default() });
    conn.send(&SELECT_OATH);
    assert_eq!(harness.input().kind, XFR_BLOCK);
    // Not something vpcd does (it waits for the answer), but data on the socket is no
    // lost connection: it stays there through several checks.
    conn.control(0x04);
    assert!(conn.quiet(PEER_CHECK * 3), "the connection stays and nothing is answered yet");
    harness.release();
    assert_eq!(conn.recv(), echoed(&SELECT_OATH));
    assert_eq!(conn.recv(), ATR, "then the GET ATR is answered");
    harness.no_input();
}

#[test]
fn a_re_enumeration_with_ccid_replugs_the_card_after_the_pause() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut first) = Harness::connected(&vpcd);
    assert_eq!(first.atr(), ATR);
    // Connected long enough that the retry interval would allow an attempt at once.
    std::thread::sleep(RETRY_INTERVAL);
    let start = Instant::now();
    harness.enumerate(&with_ccid());
    assert!(first.ends(), "the card is removed");
    // vpcd must get to report the card absent before a new connection waits for it.
    vpcd.no_connection(REPLUG_PAUSE - Duration::from_millis(200));
    let mut second = vpcd.accept();
    let waited = start.elapsed();
    assert!(waited >= REPLUG_PAUSE - Duration::from_millis(50), "reconnected after {waited:?}");
    assert!(waited < REPLUG_PAUSE + WAIT, "reconnected after {waited:?}");
    assert_eq!(second.atr(), ATR);
    harness.notice(|notice| {
        matches!(notice, VpcdNotice::Disconnected { reason } if reason == "the device re-enumerated")
    });
}

#[test]
fn the_answer_to_the_command_that_rebooted_the_device_reaches_vpcd_before_the_replug() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut first) = Harness::connected(&vpcd);
    first.power_on();
    harness.reboot_after_response(&with_ccid());
    // Management WRITE CONFIG with REBOOT: answered, then the runner re-enumerates.
    let write_config = [0x00, 0x1C, 0x00, 0x00, 0x03, 0x02, 0x0C, 0x00];
    assert_eq!(first.transmit(&write_config), echoed(&write_config));
    assert!(first.ends(), "then the card is removed");
    let mut second = vpcd.accept();
    assert_eq!(second.atr(), ATR);
}

#[test]
fn an_enumeration_without_ccid_disconnects_until_ccid_comes_back() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    assert_eq!(conn.atr(), ATR);
    harness.enumerate(&without_ccid());
    assert!(conn.ends(), "the card is removed");
    assert!(harness.attached_becomes(false));
    harness.notice(|notice| matches!(notice, VpcdNotice::Disconnected { reason } if reason == "CCID is disabled"));
    vpcd.no_connection(RETRY_INTERVAL + RETRY_INTERVAL);
    harness.enumerate(&with_ccid());
    let mut conn = vpcd.accept();
    assert_eq!(conn.atr(), ATR);
    assert!(harness.attached_becomes(true));
}

#[test]
fn ccid_enabled_again_right_after_it_was_disabled_waits_for_the_pause_too() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut first) = Harness::connected(&vpcd);
    assert_eq!(first.atr(), ATR);
    std::thread::sleep(RETRY_INTERVAL);
    let start = Instant::now();
    harness.enumerate(&without_ccid());
    assert!(first.ends(), "the card is removed");
    harness.enumerate(&with_ccid());
    let mut second = vpcd.accept();
    let waited = start.elapsed();
    assert!(waited >= REPLUG_PAUSE - Duration::from_millis(50), "reconnected after {waited:?}");
    assert_eq!(second.atr(), ATR);
}

#[test]
fn a_re_enumeration_while_a_command_waits_removes_the_card_without_an_answer() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    conn.power_on();
    assert_eq!(conn.atr(), ATR, "the power-on exchange is complete");
    harness.set_card(Card { xfr: Xfr::Hold, ..Card::default() });
    conn.send(&SELECT_OATH);
    assert!(conn.quiet(QUIET));
    harness.enumerate(&without_ccid());
    assert!(conn.ends_silently(), "the card leaves; the command has no answer");
    // The rebooted device holds nothing: no abort.
    assert_eq!(harness.input().kind, ICC_POWER_ON);
    assert_eq!(harness.input().kind, XFR_BLOCK);
    harness.no_input();
}

#[test]
fn dropping_the_transport_closes_the_connection_promptly() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    assert_eq!(conn.atr(), ATR);
    let took = harness.drop_transport();
    assert!(took < DROP_TIMEOUT, "the drop took {took:?}");
    assert!(conn.ends());
    vpcd.no_connection(RETRY_INTERVAL + QUIET);
}

#[test]
fn dropping_the_transport_while_a_command_waits_is_prompt() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    conn.power_on();
    assert_eq!(conn.atr(), ATR, "the power-on exchange is complete");
    harness.set_card(Card { xfr: Xfr::Hold, answer_markers: false, ..Card::default() });
    conn.send(&SELECT_OATH);
    assert!(conn.quiet(QUIET));
    let took = harness.drop_transport();
    assert!(took < DROP_TIMEOUT, "the drop took {took:?}");
    assert!(conn.ends());
}

#[test]
fn dropping_the_transport_while_vpcd_is_down_is_prompt() {
    let addr = FakeVpcd::bind().addr();
    let harness = Harness::new(addr);
    harness.enumerate(&with_ccid());
    harness.attempts(2);
    let took = harness.drop_transport();
    assert!(took < DROP_TIMEOUT, "the drop took {took:?}");
}

#[test]
fn dropping_a_transport_that_never_connected_is_instant() {
    let vpcd = FakeVpcd::bind();
    let harness = Harness::new(vpcd.addr());
    let took = harness.drop_transport();
    assert!(took < Duration::from_millis(100), "the drop took {took:?}");
}

#[test]
fn a_non_loopback_address_is_reported_once_when_the_transport_is_made() {
    let vpcd = FakeVpcd::bind();
    let remote: SocketAddr = "192.0.2.1:35963".parse().expect("a valid address");
    // Told it talks to the documentation address, it connects to the fake vpcd on
    // loopback: nothing leaves this machine.
    let harness = Harness::disguised(vpcd.addr(), remote);
    assert_eq!(harness.notice_log(), vec![format!("{:?}", VpcdNotice::NotLoopback { addr: remote })]);
    // A connection, a lost connection and a re-plug report nothing more.
    harness.enumerate(&with_ccid());
    vpcd.accept().close();
    let mut second = vpcd.accept();
    harness.enumerate(&with_ccid());
    assert!(second.ends());
    let mut third = vpcd.accept();
    assert_eq!(third.atr(), ATR);
    let log = harness.notice_log();
    let reports = log.iter().filter(|line| line.starts_with("NotLoopback")).count();
    assert_eq!(reports, 1, "{log:#?}");
    assert_eq!(log.iter().filter(|line| line.starts_with("Connected")).count(), 3, "{log:#?}");
    let loopback = Harness::new(FakeVpcd::bind().addr());
    assert!(loopback.notice_log().is_empty(), "loopback is not reported");
}

#[test]
fn debug_output_and_notices_show_sizes_never_bytes() {
    let vpcd = FakeVpcd::bind();
    let (harness, mut conn) = Harness::connected(&vpcd);
    let secret_pin = [0x00, 0x20, 0x00, 0x80, 0x08, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5];
    conn.transmit(&secret_pin);
    let debug = harness.debug();
    assert!(debug.contains("VpcdTransport") && debug.contains("connected: true"), "{debug}");
    let log = harness.notice_log().join("\n");
    assert!(log.contains("Received { message: \"APDU\", size: 13 }"), "{log}");
    assert!(log.contains("Sent { message: \"response\", size: 15 }"), "{log}");
    for text in [&debug, &log] {
        let lower = text.to_lowercase();
        for leak in ["197, 197", "c5, c5", "0xc5", "c5c5"] {
            assert!(!lower.contains(leak), "payload bytes leaked ({leak}): {text}");
        }
    }
}
