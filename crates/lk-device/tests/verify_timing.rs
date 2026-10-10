//! Adversarial review of the device's timing (device:verify): periodic-message cadence
//! under a late host, deadlines that coincide with inputs, touch arbitration across
//! every kind of presence request, late replies after the end of a request, the WINK
//! indication, OTP keyboard ordering, and independence from extra `Tick`s.
//!
//! Sources: CTAP 2.1 §11.2.9.1.7 (KEEPALIVE), §11.2.9.2.1 (WINK), §6.9
//! (authenticatorSelection); USB CCID Rev 1.1 §6.2.6 (time extension); `docs/DESIGN.md`
//! §4 (`next_deadline` and `Tick`) and §5 (touch arbitration); `crates/lk-device/src/lib.rs`
//! "Time" and `presence.rs` (the device's documented model policies).

#![allow(clippy::unwrap_used)]

mod common;

use common::otp::{SlotConfig, keyboard_text, slot};
use common::*;
use lk_core::{Entropy, Millis};
use lk_device::{BusEvent, Input, KEEPALIVE_INTERVAL_MS, Output, U2F_REQUEST_WINDOW_MS, WTX_INTERVAL_MS};
use lk_testkit::SeededEntropy;

/// authenticatorSelection (CTAP 2.1 §6.9): always waits for user presence.
const SELECTION: [u8; 1] = [0x0B];
const CTAP2_OK: u8 = 0x00;
/// CTAP 2.1 §6.9: selection without a touch in time.
const CTAP2_ERR_USER_ACTION_TIMEOUT: u8 = 0x2F;
/// The presence timeouts the applications ask for (`docs/CONTRACTS.md` "Applications B").
const FIDO_TIMEOUT_MS: Millis = lk_fido::TOUCH_TIMEOUT_MS;
const OATH_TIMEOUT_MS: Millis = lk_oath::TOUCH_TIMEOUT_MS;
/// Management's default challenge-response timeout (`lk_otp::DEFAULT_CHALRESP_TIMEOUT_S`).
const OTP_TIMEOUT_MS: Millis = 15_000;
const OTP_KEY: [u8; 16] = [0x3C; 16];

/// A compact label per output, to check output order: `ka` KEEPALIVE, `fido:XX` the
/// first packet of another CTAPHID message, `wtx` a CCID time extension, `ccid:XX`
/// another bulk-in message, `kbd` keyboard reports (consecutive ones folded),
/// `on`/`off` the presence indicator, `reenum`, `int` (CCID interrupt), `feat`.
fn labels(out: &[Output]) -> Vec<String> {
    let mut labels: Vec<String> = Vec::new();
    for o in out {
        let label = match o {
            Output::FidoReport(r) if r[4] & 0x80 == 0 => continue,
            Output::FidoReport(r) if r[4] & 0x7F == CTAPHID_KEEPALIVE => "ka".to_string(),
            Output::FidoReport(r) => format!("fido:{:02X}", r[4] & 0x7F),
            Output::Ccid(m) if m[0] == 0x80 && m[7] & 0x80 != 0 => "wtx".to_string(),
            Output::Ccid(m) => format!("ccid:{:02X}", m[0]),
            Output::OtpKeyboard(_) => "kbd".to_string(),
            Output::PresenceIndicator(true) => "on".to_string(),
            Output::PresenceIndicator(false) => "off".to_string(),
            Output::Reenumerate(_) => "reenum".to_string(),
            Output::CcidInterrupt(_) => "int".to_string(),
            Output::OtpFeature(_) => "feat".to_string(),
        };
        if label == "kbd" && labels.last().is_some_and(|l| l == "kbd") {
            continue;
        }
        labels.push(label);
    }
    labels
}

/// [`labels`] without the periodic messages (`ka`, `wtx`) that a 50 ms tap may carry.
fn events(out: &[Output]) -> Vec<String> {
    labels(out).into_iter().filter(|l| l != "ka" && l != "wtx").collect()
}

/// The answer to XfrBlock `seq`: a `RDR_to_PC_DataBlock` with `bmCommandStatus` 0
/// (USB CCID Rev 1.1 §6.2.1; time extensions and failed replies excluded).
fn answer(out: &[Output], seq: u8) -> Option<Vec<u8>> {
    ccid_replies(out)
        .into_iter()
        .find(|m| m[0] == 0x80 && m[6] == seq && m[7] & 0xC0 == 0)
        .map(|m| m[10..].to_vec())
}

/// The text typed by the keyboard reports in `out`.
fn typed(out: &[Output]) -> String {
    keyboard_text(&keyboard(out))
}

/// U2F REGISTER (FIDO U2F Raw Message Formats §4.1), short form with Le.
fn u2f_register() -> Vec<u8> {
    let mut data = vec![0x42; 32];
    data.extend_from_slice(&[0x24; 32]);
    apdu(0x00, 0x01, 0x00, 0x00, &data, Some(0))
}

/// Slot 1: Yubico OTP without a public ID (32 modhex characters and Enter).
fn program_slot1(rig: &mut Rig) {
    rig.otp_program(slot::CONFIG1, &SlotConfig::yubico_otp(&[], [1; 6], OTP_KEY), [0; 6]);
}

/// Slot 2: HMAC-SHA1 challenge-response waiting for the button.
fn program_slot2_challenge(rig: &mut Rig) {
    rig.otp_program(slot::CONFIG2, &SlotConfig::hmac_challenge_response(&[0x0B; 20], true), [0; 6]);
}

/// OATH with a TOTP credential `t` that requires a touch (YKOATH property `02`).
fn oath_touch_credential(rig: &mut Rig) {
    rig.power_on();
    assert_eq!(sw(&rig.select(AID_OATH)), 0x9000);
    assert_eq!(rig.apdu(&oath_put(b"t", true)), vec![0x90, 0x00]);
}

/// Run the host timer loop to `at` and check that only periodic messages came out.
fn wait_until(rig: &mut Rig, at: Millis) {
    for (time, o) in rig.run_until(at) {
        let label = labels(std::slice::from_ref(&o));
        assert!(label == ["ka"] || label == ["wtx"], "unexpected output at {time}: {o:02X?}");
    }
}

/// The host's timer fires `late` ms after each `next_deadline()` (OS timers never fire
/// early) until `stop` returns true for a batch of outputs. Returns each batch with its
/// time.
fn late_host(rig: &mut Rig, mut late: impl FnMut() -> Millis, stop: impl Fn(&[Output]) -> bool) -> Vec<(Millis, Vec<Output>)> {
    let mut batches = Vec::new();
    while let Some(deadline) = rig.dev.next_deadline() {
        assert!(deadline > rig.now, "deadline {deadline} not after {}", rig.now);
        rig.now = deadline + late();
        let out = rig.input(Input::Tick);
        let done = stop(&out);
        batches.push((rig.now, out));
        if done {
            break;
        }
    }
    batches
}

/// CTAP 2.1 §11.2.9.1.7: KEEPALIVE "should be sent at least every 100ms". A host whose
/// timer always fires 7 ms late must not stretch the cadence: the deadlines stay on the
/// grid `start + k * 100 ms` (`presence.rs` module documentation), so the k-th KEEPALIVE
/// goes out at `start + k * 100 + 7` and no gap after the first exceeds 100 ms.
/// Rescheduling from the processing time would put the k-th at `start + k * 107` and
/// stretch every gap to 107 ms. The wait ends with the timeout answer at 30 s
/// (lk-fido `TOUCH_TIMEOUT_MS`), after the KEEPALIVE due at the same instant.
#[test]
fn keepalive_cadence_stays_on_the_grid_with_a_late_host() {
    const LATE: Millis = 7;
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    rig.now = 1_000;
    let start = rig.now;
    assert_eq!(keepalives(&rig.ctaphid_send(cid, CTAPHID_CBOR, &SELECTION)), vec![2]);
    let batches = late_host(&mut rig, || LATE, |out| !responses(out).is_empty());
    let mut sent = vec![start];
    for (at, out) in &batches {
        assert!((at - LATE - start).is_multiple_of(KEEPALIVE_INTERVAL_MS), "Tick at {at} was not for a grid point");
        sent.extend(keepalives(out).iter().map(|_| *at));
    }
    for (k, &at) in sent.iter().enumerate().skip(1) {
        assert_eq!(at, start + k as Millis * KEEPALIVE_INTERVAL_MS + LATE, "KEEPALIVE {k}");
    }
    assert!(sent.windows(2).skip(1).all(|pair| pair[1] - pair[0] <= KEEPALIVE_INTERVAL_MS));
    assert_eq!(sent.len(), 301, "one at once and one per 100 ms up to the timeout instant");
    let (at, last) = batches.last().unwrap();
    assert_eq!(*at, start + FIDO_TIMEOUT_MS + LATE);
    assert_eq!(labels(last), ["ka", "fido:10", "off"]);
    assert_eq!(responses(last), vec![(CTAPHID_CBOR, vec![CTAP2_ERR_USER_ACTION_TIMEOUT])]);
}

/// The same cadence with a seeded jitter of 0–60 ms on every Tick: each KEEPALIVE stays
/// within the jitter of its grid point (no drift accumulates), and the 30 s wait still
/// carries 301 of them (CTAP 2.1 §11.2.9.1.7).
#[test]
fn keepalive_cadence_survives_jitter() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    let start = rig.now;
    rig.ctaphid_send(cid, CTAPHID_CBOR, &SELECTION);
    let mut entropy = SeededEntropy::new(41);
    let batches = late_host(&mut rig, || Millis::from(entropy.bytes(1)[0]) % 61, |out| !responses(out).is_empty());
    let sent: Vec<Millis> = batches.iter().flat_map(|(at, out)| keepalives(out).into_iter().map(move |_| *at)).collect();
    assert_eq!(sent.len(), 300);
    for (k, &at) in sent.iter().enumerate() {
        let grid = start + (k as Millis + 1) * KEEPALIVE_INTERVAL_MS;
        assert!((grid..=grid + 60).contains(&at), "KEEPALIVE {} at {at}, grid point {grid}", k + 1);
    }
}

/// USB CCID Rev 1.1 §6.2.6 time extensions while a card command waits for a touch: on
/// the grid `start + k * 500 ms` (`WTX_INTERVAL_MS`, model policy) however late the
/// host's timer fires (13 ms here), 30 of them up to the 15 s OATH timeout (lk-oath
/// `TOUCH_TIMEOUT_MS`), where the one due at the same instant precedes the `6982`
/// answer (the timer order of `presence.rs`).
#[test]
fn time_extensions_stay_on_the_grid_with_a_late_host() {
    const LATE: Millis = 13;
    let mut rig = Rig::new();
    oath_touch_credential(&mut rig);
    let start = rig.now;
    let (seq, out) = rig.xfr(&oath_calculate(b"t"));
    assert!(data_block(&out, seq).is_none());
    let batches = late_host(&mut rig, || LATE, |out| data_block(out, seq).is_some());
    let sent: Vec<Millis> = batches.iter().flat_map(|(at, out)| (0..time_extensions(out)).map(move |_| *at)).collect();
    assert_eq!(sent.len(), 30);
    for (k, &at) in sent.iter().enumerate() {
        assert_eq!(at, start + (k as Millis + 1) * WTX_INTERVAL_MS + LATE, "time extension {}", k + 1);
    }
    let (at, last) = batches.last().unwrap();
    assert_eq!(*at, start + OATH_TIMEOUT_MS + LATE);
    assert_eq!(labels(last), ["wtx", "ccid:80", "off"]);
    assert_eq!(data_block(last, seq).unwrap(), vec![0x69, 0x82]);
}

/// `lib.rs` "Time": deadlines due at the time of an input are processed before it. A
/// touch that arrives exactly at the FIDO presence timeout comes after the timeout: the
/// command answers CTAP2_ERR_USER_ACTION_TIMEOUT (CTAP 2.1 §6.9), and the touch, with
/// nothing pending, is a button press that types slot 1 at contact (catalog OTP
/// "single-slot 1 FAST_TRIG reports at modeled contact"). The KEEPALIVE due at the same
/// instant goes out first. Order: KEEPALIVE, answer, keyboard, indicator.
#[test]
fn touch_exactly_at_the_fido_timeout_is_a_button_press() {
    let mut rig = Rig::new();
    program_slot1(&mut rig);
    let cid = rig.ctaphid_init();
    let start = rig.now;
    rig.ctaphid_send(cid, CTAPHID_CBOR, &SELECTION);
    wait_until(&mut rig, start + FIDO_TIMEOUT_MS - 1);
    rig.now = start + FIDO_TIMEOUT_MS;
    let out = rig.touch_down();
    assert_eq!(labels(&out), ["ka", "fido:10", "kbd", "off"]);
    assert_eq!(responses(&out), vec![(CTAPHID_CBOR, vec![CTAP2_ERR_USER_ACTION_TIMEOUT])]);
    assert_eq!(typed(&out).len(), 33);
    rig.now += 100;
    assert!(rig.touch_up().is_empty());
}

/// The same for a card command at the OATH timeout: time extension, `6982`
/// (`touch_resolved(false)`), then the button press.
#[test]
fn touch_exactly_at_the_card_timeout_is_a_button_press() {
    let mut rig = Rig::new();
    program_slot1(&mut rig);
    oath_touch_credential(&mut rig);
    let start = rig.now;
    let (seq, _) = rig.xfr(&oath_calculate(b"t"));
    wait_until(&mut rig, start + OATH_TIMEOUT_MS - 1);
    rig.now = start + OATH_TIMEOUT_MS;
    let out = rig.touch_down();
    assert_eq!(labels(&out), ["wtx", "ccid:80", "kbd", "off"]);
    assert_eq!(data_block(&out, seq).unwrap(), vec![0x69, 0x82]);
    assert_eq!(typed(&out).len(), 33);
}

/// The same for an OTP HID challenge-response at its 15 s timeout (Management default):
/// the wait ends unanswered (the status reports neither waiting nor a response,
/// `lk_otp::OtpHid::touch_resolved`), and the touch is a button press. With two slots
/// configured the slot is chosen at release (catalog OTP "defer two-slot selection to
/// release"): a 500 ms hold types slot 1.
#[test]
fn touch_exactly_at_the_otp_hid_timeout_is_a_button_press() {
    let mut rig = Rig::new();
    program_slot1(&mut rig);
    program_slot2_challenge(&mut rig);
    let start = rig.now;
    let out = rig.otp_send_frame(slot::CHAL_HMAC2, &[0x01; 64]);
    assert_eq!(indicators(&out), vec![true]);
    wait_until(&mut rig, start + OTP_TIMEOUT_MS - 1);
    rig.now = start + OTP_TIMEOUT_MS;
    let out = rig.touch_down();
    assert_eq!(labels(&out), ["off"]);
    assert_eq!(rig.otp_feature()[7] & 0x60, 0, "neither waiting nor holding a response");
    rig.now += 500;
    let out = rig.touch_up();
    assert_eq!(typed(&out).len(), 33, "slot 1 on release");
}

/// The same for the U2F request window (`U2F_REQUEST_WINDOW_MS`, model policy): a touch
/// at its end comes after it closed, is not latched (the next U2F request still answers
/// `6985`, FIDO U2F Raw Message Formats §4.3) and types slot 1 at contact.
#[test]
fn touch_exactly_at_the_end_of_the_u2f_window_is_not_latched() {
    let mut rig = Rig::new();
    program_slot1(&mut rig);
    let cid = rig.ctaphid_init();
    let start = rig.now;
    assert_eq!(rig.ctaphid(cid, CTAPHID_MSG, &u2f_register()).1, vec![0x69, 0x85]);
    rig.now = start + U2F_REQUEST_WINDOW_MS;
    let out = rig.touch_down();
    assert_eq!(labels(&out), ["kbd", "off"]);
    rig.now += 100;
    rig.touch_up();
    assert_eq!(rig.ctaphid(cid, CTAPHID_MSG, &u2f_register()).1, vec![0x69, 0x85]);
}

/// A touch in the same `handle` as a periodic message that fell due (the host skipped
/// a Tick): the overdue KEEPALIVE (time extension) goes out once, then the answer, and
/// no deadline remains (`docs/DESIGN.md` §4).
#[test]
fn touch_with_an_overdue_periodic_message() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    let start = rig.now;
    rig.ctaphid_send(cid, CTAPHID_CBOR, &SELECTION);
    rig.now = start + 250;
    let out = rig.touch_down();
    assert_eq!(labels(&out), ["ka", "fido:10", "off"]);
    assert_eq!(rig.dev.next_deadline(), None);
    rig.touch_up();

    oath_touch_credential(&mut rig);
    let start = rig.now;
    let (seq, _) = rig.xfr(&oath_calculate(b"t"));
    rig.now = start + 1_200;
    let out = rig.touch_down();
    assert_eq!(labels(&out), ["wtx", "ccid:80", "off"]);
    assert_eq!(sw(&data_block(&out, seq).unwrap()), 0x9000);
    assert_eq!(rig.dev.next_deadline(), None);
}

/// Everything a four-way race needs: a card command, a U2F window, an OTP HID
/// challenge-response and a CTAP2 command, started in that order 10 ms apart.
struct Race {
    rig: Rig,
    seq: u8,
    fido: u32,
    u2f: u32,
    start: Millis,
}

fn race() -> Race {
    let mut rig = Rig::new();
    oath_touch_credential(&mut rig);
    program_slot2_challenge(&mut rig);
    let fido = rig.ctaphid_init();
    let u2f = rig.ctaphid_init();
    rig.now = 10_000;
    let start = rig.now;
    let (seq, out) = rig.xfr(&oath_calculate(b"t"));
    assert_eq!(indicators(&out), vec![true]);
    rig.now += 10;
    assert_eq!(rig.ctaphid(u2f, CTAPHID_MSG, &u2f_register()).1, vec![0x69, 0x85]);
    rig.now += 10;
    rig.otp_send_frame(slot::CHAL_HMAC2, &[0x01; 64]);
    assert_eq!(rig.otp_feature()[7] & 0xE0, 0x20, "OTP HID waits for the touch");
    rig.now += 10;
    assert_eq!(keepalives(&rig.ctaphid_send(fido, CTAPHID_CBOR, &SELECTION)), vec![2]);
    Race { rig, seq, fido, u2f, start }
}

/// `docs/DESIGN.md` §5: "one touch satisfies only the earliest waiting request". Four
/// requests on four paths (CCID, U2F window, OTP HID, CTAPHID CBOR) get four touches in
/// the order they started; each touch resolves exactly one, the indicator stays lit
/// until the last, and the latched U2F touch then serves the U2F client (`docs/CONTRACTS.md`
/// "lk-fido" U2F presence).
#[test]
fn four_pending_requests_get_touches_in_start_order() {
    let Race { mut rig, seq, fido, u2f, start } = race();
    wait_until(&mut rig, start + 100);
    let out = rig.tap();
    assert_eq!(sw(&data_block(&out, seq).unwrap()), 0x9000, "1st touch: the card command");
    assert!(responses(&out).is_empty() && indicators(&out).is_empty());
    wait_until(&mut rig, start + 200);
    let out = rig.tap();
    assert!(events(&out).is_empty(), "2nd touch: the U2F window, latched silently: {out:02X?}");
    assert_eq!(rig.otp_feature()[7] & 0xE0, 0x20, "OTP HID still waits");
    wait_until(&mut rig, start + 300);
    let out = rig.tap();
    assert!(events(&out).is_empty(), "3rd touch: OTP HID: {out:02X?}");
    assert_eq!(rig.otp_feature()[7] & 0x40, 0x40, "the HMAC response is ready");
    wait_until(&mut rig, start + 400);
    let out = rig.tap();
    assert_eq!(responses(&out), vec![(CTAPHID_CBOR, vec![CTAP2_OK])], "4th touch: CTAP2");
    assert_eq!(indicators(&out), vec![false]);
    let (_, response) = rig.ctaphid(u2f, CTAPHID_MSG, &u2f_register());
    assert_eq!(sw(&response), 0x9000, "the latched touch");
    assert_eq!(rig.ctaphid(fido, CTAPHID_PING, b"p").1, b"p".to_vec());
    assert_eq!(rig.dev.next_deadline(), None);
}

/// The same race with the U2F window expiring (3 s, model policy) before the second
/// touch: the second touch goes to the next request in order (OTP HID), the third to
/// CTAP2, and nothing is latched for U2F.
#[test]
fn an_expired_request_drops_out_of_the_race() {
    let Race { mut rig, seq, u2f, start, .. } = race();
    wait_until(&mut rig, start + 100);
    assert_eq!(sw(&data_block(&rig.tap(), seq).unwrap()), 0x9000);
    wait_until(&mut rig, start + 10 + U2F_REQUEST_WINDOW_MS + 50);
    let out = rig.tap();
    assert!(events(&out).is_empty());
    assert_eq!(rig.otp_feature()[7] & 0x40, 0x40, "2nd touch: OTP HID");
    let next = rig.now + 100;
    wait_until(&mut rig, next);
    let out = rig.tap();
    assert_eq!(responses(&out), vec![(CTAPHID_CBOR, vec![CTAP2_OK])], "3rd touch: CTAP2");
    assert_eq!(indicators(&out), vec![false]);
    assert_eq!(rig.ctaphid(u2f, CTAPHID_MSG, &u2f_register()).1, vec![0x69, 0x85], "nothing latched");
}

/// `docs/DESIGN.md` §5 with `lib.rs` "Time": a touch at the very instant the earliest
/// request times out comes after that timeout and goes to the next request. Order: the
/// time extension and `6982` of the card command (OATH 15 s), then the CTAP2 answer.
#[test]
fn touch_at_the_earliest_requests_timeout_goes_to_the_next_one() {
    let mut rig = Rig::new();
    oath_touch_credential(&mut rig);
    let cid = rig.ctaphid_init();
    let start = rig.now;
    let (seq, _) = rig.xfr(&oath_calculate(b"t"));
    rig.now += 10;
    rig.ctaphid_send(cid, CTAPHID_CBOR, &SELECTION);
    wait_until(&mut rig, start + OATH_TIMEOUT_MS - 1);
    rig.now = start + OATH_TIMEOUT_MS;
    let out = rig.touch_down();
    assert_eq!(labels(&out), ["wtx", "ccid:80", "fido:10", "off"]);
    assert_eq!(answer(&out, seq).unwrap(), vec![0x69, 0x82]);
    assert_eq!(responses(&out), vec![(CTAPHID_CBOR, vec![CTAP2_OK])]);
}

/// `presence.rs`: "Timers fire in time order". A host that skips its Ticks and comes
/// back after both presence timeouts passed gets every overdue deadline processed in
/// the order it fell due: one KEEPALIVE and one time extension (not bursts), then the
/// two timeout answers in deadline order, whichever interface the earlier one is on.
#[test]
fn overdue_deadlines_are_processed_in_time_order() {
    // The card command times out first (15 s after it started, the CTAP2 one at 30 s).
    let mut rig = Rig::new();
    oath_touch_credential(&mut rig);
    let cid = rig.ctaphid_init();
    let start = rig.now;
    let (seq, _) = rig.xfr(&oath_calculate(b"t"));
    rig.now += 10;
    rig.ctaphid_send(cid, CTAPHID_CBOR, &SELECTION);
    rig.now = start + 40_000;
    let out = rig.input(Input::Tick);
    assert_eq!(labels(&out), ["ka", "wtx", "ccid:80", "fido:10", "off"]);
    assert_eq!(answer(&out, seq).unwrap(), vec![0x69, 0x82]);
    assert_eq!(responses(&out), vec![(CTAPHID_CBOR, vec![CTAP2_ERR_USER_ACTION_TIMEOUT])]);
    assert_eq!(rig.dev.next_deadline(), None);

    // The CTAP2 command times out first (it started 16 s before the card command).
    let mut rig = Rig::new();
    oath_touch_credential(&mut rig);
    let cid = rig.ctaphid_init();
    let start = rig.now;
    rig.ctaphid_send(cid, CTAPHID_CBOR, &SELECTION);
    rig.now += 16_000;
    let (seq, out) = rig.xfr(&oath_calculate(b"t"));
    assert_eq!(labels(&out), ["ka"], "the overdue KEEPALIVE before the command");
    rig.now = start + 40_000;
    let out = rig.input(Input::Tick);
    assert_eq!(labels(&out), ["ka", "wtx", "fido:10", "ccid:80", "off"]);
    assert_eq!(answer(&out, seq).unwrap(), vec![0x69, 0x82]);
}

/// Every way a waiting request can end without its touch, and what may follow. After
/// each, no late answer, KEEPALIVE or time extension is sent for the ended request
/// (catalog FIDO "discards late replies from an aborted same-CID operation"; appendix A
/// "USB reset discards queued touch reports"; docs/CONTRACTS.md "Phase 0": lk-ccid's
/// `apdu_response` sends nothing for an aborted sequence), while a request the event did
/// not end keeps its cadence and still takes the touch.
#[test]
fn ended_requests_never_answer_late() {
    #[derive(Debug, Clone, Copy)]
    enum End {
        BulkAbort,
        ControlAbort,
        InitResync,
        Cancel,
        UsbReset,
        PowerCycle,
        OtpHidReboot,
    }
    for end in [End::BulkAbort, End::ControlAbort, End::InitResync, End::Cancel, End::UsbReset, End::PowerCycle, End::OtpHidReboot] {
        let mut rig = Rig::new();
        oath_touch_credential(&mut rig);
        let cid = rig.ctaphid_init();
        let (seq, _) = rig.xfr(&oath_calculate(b"t"));
        rig.now += 10;
        rig.ctaphid_send(cid, CTAPHID_CBOR, &SELECTION);
        // The host's timer loop runs to an instant where nothing is due, so the outputs
        // of the ending event are its own.
        let at = rig.now + 1_045;
        wait_until(&mut rig, at);
        let out = match end {
            End::BulkAbort => rig.bulk_abort(seq),
            End::ControlAbort => {
                let mut out = rig.input(Input::CcidControlAbort { slot: 0, seq });
                out.extend(rig.bulk_abort(seq));
                out
            }
            End::InitResync => rig.ctaphid_send(cid, CTAPHID_INIT, &[7; 8]),
            End::Cancel => rig.ctaphid_send(cid, 0x11, &[]),
            End::UsbReset => rig.bus(BusEvent::Reset),
            End::PowerCycle => rig.bus(BusEvent::PowerCycle),
            End::OtpHidReboot => {
                let mut payload = [0u8; 64];
                payload[..3].copy_from_slice(&[0x02, 0x0C, 0x00]);
                rig.otp_write(slot::YK4_SET_DEVICE_INFO, &payload)
            }
        };
        let card_ended = !matches!(end, End::InitResync | End::Cancel);
        let fido_ended = !matches!(end, End::BulkAbort | End::ControlAbort);
        let cancel_answer = matches!(end, End::Cancel);
        assert_eq!(answer(&out, seq), None, "{end:?}: no card answer");
        let fido_messages: Vec<(u8, Vec<u8>)> = parse_fido(&out).into_iter().filter(|(c, _)| *c != CTAPHID_INIT).collect();
        if cancel_answer {
            assert_eq!(fido_messages, vec![(CTAPHID_CBOR, vec![0x2D])], "{end:?}: CTAP2_ERR_KEEPALIVE_CANCEL");
        } else if fido_ended {
            assert!(fido_messages.is_empty(), "{end:?}: no FIDO answer: {fido_messages:02X?}");
        }
        let later = rig.run_until(rig.now + 40_000);
        let later: Vec<Output> = later.into_iter().map(|(_, o)| o).collect();
        if card_ended {
            assert_eq!(time_extensions(&later), 0, "{end:?}: no time extension after the end");
            assert_eq!(answer(&later, seq), None, "{end:?}");
        }
        if fido_ended {
            assert!(parse_fido(&later).is_empty(), "{end:?}: nothing on CTAPHID after the end");
        }
        if !card_ended {
            // The card command was not touched in 15 s: it timed out on its own.
            assert_eq!(answer(&later, seq), Some(vec![0x69, 0x82]), "{end:?}");
        }
        if !fido_ended {
            assert_eq!(responses(&later), vec![(CTAPHID_CBOR, vec![CTAP2_ERR_USER_ACTION_TIMEOUT])], "{end:?}");
        }
        let out = rig.tap();
        assert!(!out.iter().any(|o| matches!(o, Output::FidoReport(_) | Output::Ccid(_))), "{end:?}: late reply on touch: {out:02X?}");
        assert_eq!(rig.dev.next_deadline(), None, "{end:?}");
        assert!(!rig.dev.presence_pending(), "{end:?}");
    }
}

/// CTAP 2.1 §11.2.9.2.1 WINK: the pulse goes by the requests pending when it is
/// processed. Here a U2F window closes at the instant the WINK arrives: the indicator
/// goes off, then pulses (`fido.rs`). While a card command waits, a WINK shows nothing
/// more (the indicator is already lit).
#[test]
fn wink_pulses_after_a_request_ends_in_the_same_input() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    let start = rig.now;
    assert_eq!(rig.ctaphid(cid, CTAPHID_MSG, &u2f_register()).1, vec![0x69, 0x85]);
    rig.now = start + U2F_REQUEST_WINDOW_MS;
    let out = rig.ctaphid_send(cid, CTAPHID_WINK, &[]);
    assert_eq!(labels(&out), ["off", "on", "off", "fido:08"]);
    assert!(!rig.dev.presence_pending());

    oath_touch_credential(&mut rig);
    rig.xfr(&oath_calculate(b"t"));
    let out = rig.ctaphid_send(cid, CTAPHID_WINK, &[]);
    assert_eq!(labels(&out), ["fido:08"]);
    assert!(rig.dev.presence_pending());
}

/// Catalog OTP "real guest evdev Shift+A, b, 1, Enter events and matching release for
/// every key"; `lk_otp` keyboard module: each character is a press report followed by
/// an all-zero release. With one slot the whole OTP comes at contact and nothing at
/// release; with two slots nothing at contact and all of it at release; the reports of
/// two presses never interleave.
#[test]
fn keyboard_reports_come_in_press_release_pairs_at_the_right_edge() {
    let mut rig = Rig::new();
    program_slot1(&mut rig);
    let down = rig.touch_down();
    rig.now += 600;
    let up = rig.touch_up();
    let reports = keyboard(&down);
    assert!(keyboard(&up).is_empty());
    assert_eq!(reports.len() % 2, 0);
    for pair in reports.chunks(2) {
        assert_ne!(pair[0], [0; 8], "a press report");
        assert_eq!(pair[1], [0; 8], "its release");
    }
    assert_eq!(keyboard_text(&reports).len(), 33);

    program_slot2_challenge(&mut rig);
    let first = {
        let down = rig.touch_down();
        assert!(keyboard(&down).is_empty(), "two slots: nothing at contact");
        rig.now += 600;
        keyboard(&rig.touch_up())
    };
    rig.now += 100;
    let second = {
        rig.touch_down();
        rig.now += 600;
        keyboard(&rig.touch_up())
    };
    let (a, b) = (keyboard_text(&first), keyboard_text(&second));
    assert_eq!((a.len(), b.len()), (33, 33));
    assert_ne!(a, b, "each press is a new OTP");
}

/// One session over every interface, driven by the host timer loop; with `extra` the
/// host also ticks at seeded times strictly before each deadline. Returns every output
/// with its time.
fn tick_script(extra: bool) -> (Vec<(Millis, Output)>, usize) {
    let mut rig = Rig::new();
    rig.log = Some(Vec::new());
    let mut jitter = extra.then(|| SeededEntropy::new(99));
    let mut extra_ticks = 0;
    let mut goto = |rig: &mut Rig, t: Millis| loop {
        let due = rig.dev.next_deadline().filter(|&d| d <= t);
        let limit = due.unwrap_or(t);
        if let Some(entropy) = jitter.as_mut() {
            for _ in 0..2 {
                let span = limit.saturating_sub(rig.now);
                if span > 1 {
                    let mut b = [0u8; 2];
                    entropy.fill(&mut b);
                    rig.now += Millis::from(u16::from_le_bytes(b)) % (span - 1) + 1;
                    let out = rig.input(Input::Tick);
                    assert!(out.is_empty(), "a Tick before the deadline {limit} at {} gave {out:02X?}", rig.now);
                    extra_ticks += 1;
                }
            }
        }
        match due {
            Some(deadline) => {
                rig.now = deadline;
                rig.input(Input::Tick);
            }
            None => {
                rig.now = t;
                return;
            }
        }
    };
    program_slot1(&mut rig);
    program_slot2_challenge(&mut rig);
    goto(&mut rig, 100);
    let cid = rig.ctaphid_init();
    rig.ctaphid_send(cid, CTAPHID_CBOR, &SELECTION);
    goto(&mut rig, 150);
    oath_touch_credential(&mut rig);
    rig.xfr(&oath_calculate(b"t"));
    goto(&mut rig, 1_234);
    rig.tap();
    goto(&mut rig, 2_000);
    rig.tap();
    goto(&mut rig, 2_500);
    rig.ctaphid(cid, CTAPHID_MSG, &u2f_register());
    goto(&mut rig, 4_000);
    rig.tap();
    goto(&mut rig, 4_100);
    rig.ctaphid(cid, CTAPHID_MSG, &u2f_register());
    goto(&mut rig, 5_000);
    rig.otp_send_frame(slot::CHAL_HMAC2, &[0x01; 64]);
    goto(&mut rig, 9_000);
    rig.tap();
    goto(&mut rig, 9_100);
    rig.otp_read_frame();
    goto(&mut rig, 10_000);
    rig.ctaphid_send(cid, CTAPHID_CBOR, &SELECTION);
    goto(&mut rig, 41_000);
    rig.xfr(&oath_calculate(b"t"));
    goto(&mut rig, 57_000);
    rig.touch_down();
    goto(&mut rig, 57_600);
    rig.touch_up();
    goto(&mut rig, 60_000);
    (rig.log.take().unwrap(), extra_ticks)
}

/// `docs/DESIGN.md` §4: the host delivers `Tick` "no later than" `next_deadline()`; an
/// earlier Tick must be harmless. The same session run with and without extra Ticks
/// strictly before every deadline gives the same outputs at the same times, and every
/// extra Tick outputs nothing.
#[test]
fn extra_early_ticks_change_nothing() {
    let (plain, none) = tick_script(false);
    let (jittered, extra) = tick_script(true);
    assert_eq!(none, 0);
    assert!(extra > 300, "only {extra} extra Ticks");
    assert!(plain.iter().filter(|(_, o)| labels(std::slice::from_ref(o)) == ["ka"]).count() > 300);
    assert_eq!(plain.len(), jittered.len());
    assert!(plain == jittered, "outputs differ with extra Ticks");
}
