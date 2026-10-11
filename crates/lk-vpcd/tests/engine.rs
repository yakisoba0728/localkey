//! The vpcd transport in front of the real engine: `lk_run::Runner` with an
//! `lk_testkit::MemoryStore` and the YubiKey 5C Nano 5.7.4 profile, driven through a fake
//! vpcd on `127.0.0.1` (`docs/PROGRAM.md` "lk-vpcd").
//!
//! APDUs are written from YKOATH (Yubico's OATH protocol: SELECT `A0 00 00 05 27 21 01`,
//! PUT `01`, LIST `A1`, CALCULATE `A2`, property `78 02` REQUIRE_TOUCH) and yubikit's
//! Management protocol (AID `A0 00 00 05 27 47 11 17`, WRITE CONFIG `1C` with data
//! `len || TLVs`, USB enabled applications tag `03`, REBOOT tag `0C`).

#![cfg(unix)]

mod common;

use std::thread;
use std::time::{Duration, Instant};

use lk_core::DeviceProfile;
use lk_device::{BusEvent, Device, WTX_INTERVAL_MS};
use lk_run::{Command, HostInput, Runner, RunnerConfig, TAP_SHORT_MS};
use lk_testkit::{MemoryStore, SeededEntropy};
use lk_vpcd::{REPLY_SILENCE, RETRY_INTERVAL, TcpConnector, VpcdTransport};

use common::{Conn, FakeVpcd, WAIT};

const SERIAL: u32 = 12_345_678;
const KEY: [u8; 32] = [0x5A; 32];

const SELECT_OATH: [u8; 12] = [0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];
const SELECT_MANAGEMENT: [u8; 13] = [0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];
const OATH_LIST: [u8; 4] = [0x00, 0xA1, 0x00, 0x00];
/// WRITE CONFIG: USB enabled applications OTP | U2F | FIDO2 (`0203`, no CCID application),
/// then REBOOT.
const DISABLE_CCID: [u8; 12] = [0x00, 0x1C, 0x00, 0x00, 0x07, 0x06, 0x03, 0x02, 0x02, 0x03, 0x0C, 0x00];
/// WRITE CONFIG: REBOOT only.
const REBOOT: [u8; 8] = [0x00, 0x1C, 0x00, 0x00, 0x03, 0x02, 0x0C, 0x00];

fn profile() -> DeviceProfile {
    DeviceProfile::yubikey_5c_nano_5_7_4(SERIAL)
}

/// A serving runner whose vpcd transport connected to `vpcd`.
fn serve(vpcd: &FakeVpcd) -> (Runner, Conn) {
    let store = MemoryStore::new();
    let runner = Runner::spawn(
        move || Ok(Device::open(profile(), Box::new(store), Box::new(SeededEntropy::new(7)), KEY)),
        RunnerConfig::default(),
    )
    .expect("the device opens");
    let transport = VpcdTransport::new(Box::new(TcpConnector::new(vpcd.addr())), runner.sender());
    runner.serve(Box::new(transport)).expect("the runner takes the transport");
    let conn = vpcd.accept();
    (runner, conn)
}

fn sw(response: &[u8]) -> u16 {
    assert!(response.len() >= 2, "a response APDU ends with a status word: {response:02X?}");
    u16::from_be_bytes([response[response.len() - 2], response[response.len() - 1]])
}

/// YKOATH PUT of a TOTP/SHA-1 credential with a 20-byte secret; `touch` adds `78 02`.
fn oath_put(name: &[u8], touch: bool) -> Vec<u8> {
    let mut data = vec![0x71, name.len() as u8];
    data.extend_from_slice(name);
    data.extend_from_slice(&[0x73, 22, 0x21, 6]);
    data.extend_from_slice(&[0x11; 20]);
    if touch {
        data.extend_from_slice(&[0x78, 0x02]);
    }
    let mut apdu = vec![0x00, 0x01, 0x00, 0x00, data.len() as u8];
    apdu.extend_from_slice(&data);
    apdu
}

/// YKOATH CALCULATE (truncated) of `name` with an 8-byte challenge.
fn oath_calculate(name: &[u8]) -> Vec<u8> {
    let mut data = vec![0x71, name.len() as u8];
    data.extend_from_slice(name);
    data.extend_from_slice(&[0x74, 0x08, 0, 0, 0, 0, 0, 0, 0, 1]);
    let mut apdu = vec![0x00, 0xA2, 0x00, 0x01, data.len() as u8];
    apdu.extend_from_slice(&data);
    apdu.push(0x00);
    apdu
}

/// A connection with OATH selected and the touch credential `touch`, whose CALCULATE is
/// sent and waits for the touch.
fn calculate_waiting_for_touch(conn: &mut Conn) {
    conn.power_on();
    assert_eq!(sw(&conn.transmit(&SELECT_OATH)), 0x9000);
    assert_eq!(conn.transmit(&oath_put(b"touch", true)), [0x90, 0x00]);
    conn.send(&oath_calculate(b"touch"));
    assert!(conn.quiet(Duration::from_millis(700)), "the CALCULATE waits for a touch");
}

/// Whether the device stops waiting for a touch within [`WAIT`].
fn touch_wait_ends(runner: &Runner) -> bool {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if !runner.status().expect("the runner answers").presence_pending {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
fn get_atr_through_vpcd_is_the_profile_atr() {
    let vpcd = FakeVpcd::bind();
    let (runner, mut conn) = serve(&vpcd);
    assert_eq!(conn.atr(), profile().atr);
    conn.power_on();
    assert_eq!(conn.atr(), profile().atr);
    assert_eq!(runner.status().expect("the runner answers").attached, Some(true));
}

#[test]
fn select_oath_and_list_work_through_vpcd() {
    let vpcd = FakeVpcd::bind();
    let (_runner, mut conn) = serve(&vpcd);
    conn.atr();
    conn.power_on();
    conn.atr();
    let select = conn.transmit(&SELECT_OATH);
    assert_eq!(sw(&select), 0x9000, "{select:02X?}");
    assert_eq!(select[0], 0x79, "the version tag comes first");
    assert_eq!(conn.transmit(&OATH_LIST), [0x90, 0x00], "no credentials yet");
    assert_eq!(conn.transmit(&oath_put(b"vpcd", false)), [0x90, 0x00]);
    let list = conn.transmit(&OATH_LIST);
    assert_eq!(sw(&list), 0x9000);
    assert_eq!(&list[..2], &[0x72, 5], "one name-list entry");
    assert_eq!(&list[3..7], b"vpcd");
}

#[test]
fn power_off_and_on_start_a_new_card_session() {
    let vpcd = FakeVpcd::bind();
    let (_runner, mut conn) = serve(&vpcd);
    conn.power_on();
    assert_eq!(sw(&conn.transmit(&SELECT_OATH)), 0x9000);
    assert_eq!(sw(&conn.transmit(&OATH_LIST)), 0x9000);
    conn.power_off();
    conn.power_on();
    // The selection went with the old session.
    assert_eq!(conn.transmit(&OATH_LIST), [0x6D, 0x00]);
    assert_eq!(sw(&conn.transmit(&SELECT_OATH)), 0x9000);
    conn.reset();
    assert_eq!(conn.transmit(&OATH_LIST), [0x6D, 0x00], "reset ends the session too");
}

#[test]
fn a_calculate_that_needs_a_touch_completes_after_a_tap() {
    let vpcd = FakeVpcd::bind();
    let (runner, mut conn) = serve(&vpcd);
    conn.power_on();
    assert_eq!(sw(&conn.transmit(&SELECT_OATH)), 0x9000);
    assert_eq!(conn.transmit(&oath_put(b"touch", true)), [0x90, 0x00]);
    conn.send(&oath_calculate(b"touch"));
    // The device sends a time extension every 500 ms; none reaches vpcd.
    assert!(conn.quiet(Duration::from_millis(1_600)), "nothing before the touch");
    runner.sender().send(Command::Tap { hold_ms: TAP_SHORT_MS }).expect("the runner takes the tap");
    let response = conn.recv();
    assert_eq!(sw(&response), 0x9000, "{response:02X?}");
    assert_eq!(&response[..3], &[0x76, 0x05, 0x06], "a truncated response with 6 digits");
}

#[test]
fn a_touch_given_after_more_than_the_reply_silence_still_completes_the_command() {
    let vpcd = FakeVpcd::bind();
    let (runner, mut conn) = serve(&vpcd);
    calculate_waiting_for_touch(&mut conn);
    // Longer than REPLY_SILENCE: only the device's time extensions keep the command alive.
    assert!(conn.quiet(REPLY_SILENCE + Duration::from_millis(1_500)), "no 6F00 while time extensions arrive");
    runner.sender().send(Command::Tap { hold_ms: TAP_SHORT_MS }).expect("the runner takes the tap");
    let response = conn.recv();
    assert_eq!(sw(&response), 0x9000, "{response:02X?}");
    assert_eq!(&response[..3], &[0x76, 0x05, 0x06], "a truncated response with 6 digits");
}

#[test]
fn a_connection_lost_while_a_command_waits_for_a_touch_aborts_it_and_the_card_is_inserted_again() {
    let vpcd = FakeVpcd::bind();
    let (runner, mut conn) = serve(&vpcd);
    calculate_waiting_for_touch(&mut conn);
    assert!(runner.status().expect("the runner answers").presence_pending, "the device waits for a touch");
    // vpcd goes away mid-command (pcscd restarted or crashed) and is back at once.
    let lost = Instant::now();
    conn.close();
    // `docs/PROGRAM.md` "lk-vpcd": "a lost connection is retried the same way (card
    // removed, then inserted again)", every second. Generous, yet far below the 15 s OATH
    // touch timeout the transport would otherwise wait for.
    let within = RETRY_INTERVAL + Duration::from_secs(4);
    let Some(mut again) = vpcd.accept_within(within) else {
        panic!(
            "no new connection {:?} after vpcd closed the old one: the transport still waits for the device's \
             answer to a command whose client is gone (presence pending: {:?})",
            lost.elapsed(),
            runner.status().map(|status| status.presence_pending)
        );
    };
    // The command was aborted: the device no longer waits for a touch, and the card works.
    assert!(touch_wait_ends(&runner), "the touch wait ends with the abort");
    assert_eq!(again.atr(), profile().atr, "the reinserted card answers GET ATR");
    again.power_on();
    assert_eq!(sw(&again.transmit(&SELECT_OATH)), 0x9000);
    // A tap now completes nothing: no response reaches the new connection.
    runner.sender().send(Command::Tap { hold_ms: TAP_SHORT_MS }).expect("the runner takes the tap");
    assert!(again.quiet(Duration::from_millis(TAP_SHORT_MS + 500)));
    assert_eq!(&again.transmit(&OATH_LIST)[..2], &[0x72, 6], "the credential is still there");
}

#[test]
fn three_hundred_apdus_on_one_connection_wrap_bseq_without_a_hitch() {
    let vpcd = FakeVpcd::bind();
    let (_runner, mut conn) = serve(&vpcd);
    conn.power_on();
    assert_eq!(sw(&conn.transmit(&SELECT_OATH)), 0x9000);
    for round in 0..300 {
        assert_eq!(conn.transmit(&OATH_LIST), [0x90, 0x00], "round {round}");
    }
}

#[test]
fn a_command_dropped_by_a_power_cycle_is_answered_6f00_and_the_card_works_again() {
    let vpcd = FakeVpcd::bind();
    let (runner, mut conn) = serve(&vpcd);
    calculate_waiting_for_touch(&mut conn);
    // `localkeyd ctl power-cycle`: the device restarts and drops the card command silently.
    let start = Instant::now();
    runner.sender().send(Command::Input(HostInput::Bus(BusEvent::PowerCycle))).expect("the runner takes it");
    assert_eq!(conn.recv(), [0x6F, 0x00]);
    let waited = start.elapsed();
    // The silence counts from the command's last time extension (`lk_vpcd::REPLY_SILENCE`),
    // which came up to one `WTX_INTERVAL_MS` before the power cycle: the helper sends it
    // about 700 ms after the CALCULATE, some 200 ms after the first time extension, more
    // on a loaded machine. So the answer comes between REPLY_SILENCE - WTX_INTERVAL_MS and
    // REPLY_SILENCE after the power cycle, never at once. (Found by the offline Linux pass:
    // a bound of REPLY_SILENCE - 200 ms failed with 4.79 s.)
    let earliest = REPLY_SILENCE - Duration::from_millis(WTX_INTERVAL_MS) - Duration::from_millis(200);
    assert!(waited >= earliest, "answered after {waited:?}, expected at least {earliest:?}");
    // The slot is powered on again before the next APDU.
    assert_eq!(sw(&conn.transmit(&SELECT_OATH)), 0x9000);
    assert_eq!(conn.transmit(&OATH_LIST)[..2], [0x72, 6], "the credential survived the power cycle");
}

#[test]
fn an_extended_apdu_longer_than_one_ccid_message_reaches_the_card() {
    let vpcd = FakeVpcd::bind();
    let (_runner, mut conn) = serve(&vpcd);
    conn.power_on();
    // SELECT by a 4000-byte DF name that no application's AID begins: CCID parts of 3062
    // bytes reassembled by the engine, then "application not found".
    let mut apdu = vec![0x00, 0xA4, 0x04, 0x00, 0x00, 0x0F, 0xA0];
    apdu.extend_from_slice(&[0xEE; 4000]);
    assert_eq!(conn.transmit(&apdu), [0x6A, 0x82]);
    assert_eq!(sw(&conn.transmit(&SELECT_OATH)), 0x9000, "the slot is ready for the next command");
}

#[test]
fn disabling_ccid_through_management_removes_the_card_for_good() {
    let vpcd = FakeVpcd::bind();
    let (runner, mut conn) = serve(&vpcd);
    conn.power_on();
    let select = conn.transmit(&SELECT_MANAGEMENT);
    assert_eq!(sw(&select), 0x9000, "{select:02X?}");
    assert_eq!(conn.transmit(&DISABLE_CCID), [0x90, 0x00], "the answer comes before the reboot");
    assert!(conn.ends(), "the card leaves the reader");
    vpcd.no_connection(RETRY_INTERVAL * 3);
    let status = runner.status().expect("the runner answers");
    assert!(!status.interfaces.ccid);
    assert_eq!(status.attached, Some(false));
}

#[test]
fn a_management_reboot_removes_and_inserts_the_card() {
    let vpcd = FakeVpcd::bind();
    let (_runner, mut first) = serve(&vpcd);
    first.power_on();
    assert_eq!(sw(&first.transmit(&SELECT_MANAGEMENT)), 0x9000);
    assert_eq!(first.transmit(&REBOOT), [0x90, 0x00]);
    assert!(first.ends(), "the card leaves the reader");
    let mut second = vpcd.accept();
    assert_eq!(second.atr(), profile().atr);
    // A rebooted card: nothing is selected.
    assert_eq!(second.transmit(&OATH_LIST), [0x6D, 0x00]);
    assert_eq!(sw(&second.transmit(&SELECT_OATH)), 0x9000);
}

#[test]
fn the_card_comes_back_after_vpcd_restarts() {
    let vpcd = FakeVpcd::bind();
    let addr = vpcd.addr();
    let (_runner, mut conn) = serve(&vpcd);
    conn.power_on();
    assert_eq!(sw(&conn.transmit(&SELECT_OATH)), 0x9000);
    assert_eq!(conn.transmit(&oath_put(b"kept", false)), [0x90, 0x00]);
    drop(vpcd);
    conn.close();
    std::thread::sleep(RETRY_INTERVAL + RETRY_INTERVAL / 2);
    let vpcd = FakeVpcd::rebind(addr);
    let mut conn = vpcd.accept();
    assert_eq!(conn.atr(), profile().atr);
    conn.power_on();
    assert_eq!(sw(&conn.transmit(&SELECT_OATH)), 0x9000);
    let list = conn.transmit(&OATH_LIST);
    assert_eq!(&list[3..7], b"kept", "the device kept running: {list:02X?}");
}
