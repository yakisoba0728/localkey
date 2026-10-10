//! Adversarial review of the device's state rules (device:verify): CCID power-off and
//! abort while a card command waits for a touch, the secure channel after applet
//! errors, aborts and SELECT, what a Management re-enumeration resets on every
//! interface, disabled interfaces, and the USB identity byte for byte against the
//! reference observation.

#![allow(clippy::unwrap_used)]

mod common;

use common::iso::{command, find_tlv, piv, split, tlv};
use common::json;
use common::otp::{SlotConfig, slot};
use common::*;
use lk_core::{Capabilities, Millis, UsbInterfaces};
use lk_crypto::hmac_sha1;
use lk_device::{BusEvent, Input, Output, WTX_INTERVAL_MS};

const USB_REFERENCE: &str = include_str!("../../../reference/yubikey-5c-nano-5.7.4/usb-reference-observation.json");
/// authenticatorSelection (CTAP 2.1 §6.9).
const SELECTION: [u8; 1] = [0x0B];
/// YKOATH LIST.
const OATH_LIST: [u8; 4] = [0x00, 0xA1, 0x00, 0x00];
/// USB CCID Rev 1.1 §6.2.6 `bError` `CMD_SLOT_BUSY`.
const CMD_SLOT_BUSY: u8 = 0xE0;

/// The answer to XfrBlock `seq`: a `RDR_to_PC_DataBlock` with `bmCommandStatus` 0
/// (USB CCID Rev 1.1 §6.2.1; time extensions and failed replies excluded).
fn answer(out: &[Output], seq: u8) -> Option<Vec<u8>> {
    ccid_replies(out)
        .into_iter()
        .find(|m| m[0] == 0x80 && m[6] == seq && m[7] & 0xC0 == 0)
        .map(|m| m[10..].to_vec())
}

/// OATH with a TOTP credential `t` that requires a touch (YKOATH property `02`).
fn oath_touch_credential(rig: &mut Rig) {
    rig.power_on();
    assert_eq!(sw(&rig.select(AID_OATH)), 0x9000);
    assert_eq!(rig.apdu(&oath_put(b"t", true)), vec![0x90, 0x00]);
}

/// YKOATH CALCULATE data for credential `t` with an 8-byte challenge.
const CALCULATE_T: [u8; 13] = [0x71, 0x01, b't', 0x74, 0x08, 0, 0, 0, 0, 0, 0, 0, 1];

/// WRITE CONFIG data `len || TLVs` (yubikit `DeviceConfig.get_bytes`): USB enabled
/// applications (tag `03`) and, with `reboot`, the REBOOT tag `0C`.
fn config(usb_enabled: Option<u16>, reboot: bool) -> Vec<u8> {
    let mut tlvs = Vec::new();
    if let Some(bits) = usb_enabled {
        tlvs.extend_from_slice(&[0x03, 0x02]);
        tlvs.extend_from_slice(&bits.to_be_bytes());
    }
    if reboot {
        tlvs.extend_from_slice(&[0x0C, 0x00]);
    }
    let mut data = vec![tlvs.len() as u8];
    data.extend_from_slice(&tlvs);
    data
}

/// Management WRITE CONFIG over CCID (INS `1C`, yubikit `ManagementSession.write_device_config`).
fn ccid_write_config(rig: &mut Rig, data: &[u8]) -> (u8, Vec<Output>) {
    rig.power_on();
    assert_eq!(sw(&rig.select(AID_MGMT)), 0x9000);
    let mut apdu = vec![0x00, 0x1C, 0x00, 0x00, data.len() as u8];
    apdu.extend_from_slice(data);
    rig.xfr(&apdu)
}

/// Management WRITE CONFIG over OTP HID slot `0x15` (catalog Management "CCID and OTP
/// HID device information/configuration").
fn otp_write_config(rig: &mut Rig, data: &[u8]) -> Vec<Output> {
    let mut payload = [0u8; 64];
    payload[..data.len()].copy_from_slice(data);
    // The host then reads the status (yubikit `OtpProtocol._read_frame`); a reboot follows
    // that read (`lk_device::Device::handle`).
    let mut out = rig.otp_write(slot::YK4_SET_DEVICE_INFO, &payload);
    out.extend(rig.input(Input::OtpGetFeature));
    out
}

/// USB CCID Rev 1.1 §6.1: the slot is busy with the XfrBlock whose APDU waits for a
/// touch, so IccPowerOff (§6.1.2) and a warm IccPowerOn (§6.1.1) are refused with
/// `CMD_SLOT_BUSY` (§6.2.6) and change nothing: the time extensions keep their 500 ms
/// grid and the touch completes the command. After the two-step abort (§5.3.1) the
/// slot is idle and IccPowerOff succeeds.
#[test]
fn power_off_and_warm_reset_are_refused_while_a_card_command_waits() {
    let mut rig = Rig::new();
    oath_touch_credential(&mut rig);
    let start = rig.now;
    let (seq, _) = rig.xfr(&oath_calculate(b"t"));
    rig.now += 100;
    let out = rig.power_off();
    let reply = &ccid_replies(&out)[0];
    assert_eq!((reply[0], reply[7] & 0xC0, reply[8]), (0x81, 0x40, CMD_SLOT_BUSY), "IccPowerOff refused");
    let out = rig.input(Input::Ccid(&Rig::ccid_message(0x62, 200, [0, 0, 0], &[])));
    let reply = &ccid_replies(&out)[0];
    assert_eq!((reply[0], reply[6], reply[7] & 0xC0, reply[8]), (0x80, 200, 0x40, CMD_SLOT_BUSY), "warm IccPowerOn refused");
    assert!(rig.dev.presence_pending());
    let ticks: Vec<Millis> = rig.run_until(start + 1_200).into_iter().map(|(at, _)| at).collect();
    assert_eq!(ticks, vec![start + WTX_INTERVAL_MS, start + 2 * WTX_INTERVAL_MS]);
    let out = rig.tap();
    assert_eq!(sw(&answer(&out, seq).unwrap()), 0x9000, "the touch still completes the command");

    let (seq, _) = rig.xfr(&oath_calculate(b"t"));
    rig.input(Input::CcidControlAbort { slot: 0, seq });
    rig.bulk_abort(seq);
    let out = rig.power_off();
    let reply = &ccid_replies(&out)[0];
    assert_eq!((reply[0], reply[7] & 0xC0), (0x81, 0x00), "IccPowerOff once the slot is idle");
    assert!(ccid_replies(&rig.tap()).is_empty());
    rig.power_on();
    assert_eq!(sw(&rig.select(AID_OATH)), 0x9000);
}


/// lk-sd channel docs: the C-MAC chaining value advances with every verified command
/// (GP Amd D §6.2.4) and the R-MAC uses the current one (§6.2.5). A wrapped command
/// that waits for a touch and is aborted (CCID bulk Abort, USB CCID Rev 1.1 §6.1.13)
/// was verified but never answered; the channel stays in step with the host, which
/// also advanced: the next wrapped commands verify, and a wrapped touch command still
/// completes with a valid R-MAC.
#[test]
fn abort_of_a_wrapped_touch_command_keeps_the_channel_in_step() {
    let mut rig = Rig::new();
    oath_touch_credential(&mut rig);
    let mut session = Scp03::open(&mut rig);
    let (seq, out) = rig.xfr(&session.wrap(0x00, 0xA2, 0x00, 0x01, &CALCULATE_T, Some(0)));
    assert_eq!(answer(&out, seq), None);
    assert_eq!(indicators(&out), vec![true]);
    let out = rig.bulk_abort(seq);
    assert_eq!(indicators(&out), vec![false]);
    assert!(ccid_replies(&rig.tap()).is_empty(), "no late answer");
    let list = session.wrap(0x00, 0xA1, 0x00, 0x00, &[], Some(0));
    let (data, status) = session.unwrap(&rig.apdu(&list));
    assert_eq!(status, 0x9000);
    assert_eq!(&data[3..], b"t");
    let (seq, _) = rig.xfr(&session.wrap(0x00, 0xA2, 0x00, 0x01, &CALCULATE_T, Some(0)));
    let out = rig.tap();
    let (code, status) = session.unwrap(&answer(&out, seq).unwrap());
    assert_eq!(status, 0x9000);
    assert_eq!(code[0], 0x76, "YKOATH truncated response tag");
}

/// GP Amd D §6.2.5: a warning status (`63Cx`) is protected with an R-MAC and an error
/// status (`6A82`) is returned bare; neither ends the session, which only ends on a
/// rejected command, SELECT or reset (Yubico yk5-apps-scp; lk-sd channel docs).
#[test]
fn secure_channel_survives_applet_warnings_and_errors() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_PIV);
    let mut session = Scp03::open(&mut rig);
    let wrong = session.wrap(0x00, 0x20, 0x00, 0x80, &piv::pin_block("000000"), None);
    assert_eq!(session.unwrap(&rig.apdu(&wrong)), (vec![], 0x63C2), "wrong PIN, R-MAC verified");
    // GET DATA of the empty PIV Authentication certificate (SP 800-73-4 Part 1 tag 5FC105).
    let get = session.wrap(0x00, 0xCB, 0x3F, 0xFF, &[0x5C, 0x03, 0x5F, 0xC1, 0x05], Some(0));
    assert_eq!(rig.apdu(&get), vec![0x6A, 0x82], "error status without R-MAC");
    let right = session.wrap(0x00, 0x20, 0x00, 0x80, &piv::pin_block("123456"), None);
    assert_eq!(session.unwrap(&rig.apdu(&right)), (vec![], 0x9000));
    let status = session.wrap(0x00, 0x20, 0x00, 0x80, &[], None);
    assert_eq!(session.unwrap(&rig.apdu(&status)), (vec![], 0x9000), "PIN verified within the channel");
}

/// Catalog SecurityDomain: "SELECT remains an explicit session boundary"; ISO/IEC
/// 7816-4 §5.6 `6A82` for an unknown application (`card.rs` step 4: the current
/// selection stays). A wrapped SELECT of an unknown AID is answered bare `6A82`, ends
/// the session, and OATH stays selected: plaintext works again and a wrapped command
/// reaches OATH unwrapped (`6882`, secure-messaging bits it does not support).
#[test]
fn wrapped_select_of_an_unknown_aid_ends_the_channel_and_keeps_the_selection() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_OATH);
    assert_eq!(rig.apdu(&oath_put(b"keep", false)), vec![0x90, 0x00]);
    let mut session = Scp03::open(&mut rig);
    let select = session.wrap(0x00, 0xA4, 0x04, 0x00, &[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01], Some(0));
    assert_eq!(rig.apdu(&select), vec![0x6A, 0x82]);
    let list = rig.apdu(&OATH_LIST);
    assert_eq!(sw(&list), 0x9000);
    assert_eq!(&list[3..7], b"keep", "OATH is still selected");
    let wrapped = session.wrap(0x00, 0xA1, 0x00, 0x00, &[], Some(0));
    assert_eq!(rig.apdu(&wrapped), vec![0x68, 0x82]);
}

/// Catalog SecurityDomain_versions: "encrypted SELECT terminate[s] authorization for
/// subsequent commands". A PIV PIN verified inside an SCP03 session does not survive an
/// encrypted re-SELECT of PIV (SP 800-73-4 keeps the security status only on a plain
/// re-SELECT): after it the channel is gone and a plaintext VERIFY status check answers
/// `63Cx`, not `9000`.
#[test]
fn encrypted_reselect_ends_authorization_gained_under_the_channel() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_PIV);
    let mut session = Scp03::open(&mut rig);
    let verify = session.wrap(0x00, 0x20, 0x00, 0x80, &piv::pin_block("123456"), None);
    assert_eq!(session.unwrap(&rig.apdu(&verify)), (vec![], 0x9000));
    let select = session.wrap(0x00, 0xA4, 0x04, 0x00, AID_PIV, Some(0));
    assert_eq!(session.unwrap(&rig.apdu(&select)).1, 0x9000);
    let status = rig.apdu(&[0x00, 0x20, 0x00, 0x80]);
    assert_eq!(sw(&status) & 0xFFF0, 0x63C0, "PIN no longer verified: {status:02X?}");
}

/// The same for an encrypted SELECT of an unknown AID: the selection stays (ISO/IEC
/// 7816-4 §5.6 `6A82`) but the PIN verified under the channel is gone, and so is the
/// verification made in plaintext before the channel opened.
#[test]
fn encrypted_select_of_an_unknown_aid_ends_authorization() {
    for verify_inside in [true, false] {
        let mut rig = Rig::new();
        rig.power_on();
        rig.select(AID_PIV);
        if !verify_inside {
            let mut verify = vec![0x00, 0x20, 0x00, 0x80, 0x08];
            verify.extend_from_slice(&piv::pin_block("123456"));
            assert_eq!(rig.apdu(&verify), vec![0x90, 0x00]);
        }
        let mut session = Scp03::open(&mut rig);
        if verify_inside {
            let verify = session.wrap(0x00, 0x20, 0x00, 0x80, &piv::pin_block("123456"), None);
            assert_eq!(session.unwrap(&rig.apdu(&verify)), (vec![], 0x9000));
        }
        let select = session.wrap(0x00, 0xA4, 0x04, 0x00, &[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01], Some(0));
        assert_eq!(rig.apdu(&select), vec![0x6A, 0x82]);
        let status = rig.apdu(&[0x00, 0x20, 0x00, 0x80]);
        assert_eq!(sw(&status) & 0xFFF0, 0x63C0, "PIN no longer verified ({verify_inside}): {status:02X?}");
    }
}

/// Catalog SecurityDomain_plaintext: "PIV verified PIN/admin and OATH access
/// authorization revoked". OATH validated inside an SCP03 session (YKOATH VALIDATE `A3`:
/// `75 HMAC-SHA1(key, card challenge)`, `74 host challenge`): a plaintext command ends the
/// channel and the access with it, so a plaintext LIST then needs a new VALIDATE.
#[test]
fn ending_the_channel_revokes_oath_access() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_OATH);
    let key = [0x11u8; 16];
    let mut key_field = vec![0x21];
    key_field.extend_from_slice(&key);
    let challenge = [0x22u8; 8];
    let data = [tlv(0x73, &key_field), tlv(0x74, &challenge), tlv(0x75, &hmac_sha1(&key, &challenge))].concat();
    assert_eq!(sw(&rig.apdu(&command(0x00, 0x03, 0x00, 0x00, &data, None))), 0x9000, "SET CODE");
    let response = rig.select(AID_OATH);
    let card_challenge = find_tlv(split(&response).0, 0x74).expect("locked: SELECT carries a challenge");
    let mut session = Scp03::open(&mut rig);
    let host_challenge = [0x33u8; 8];
    let validate = [tlv(0x75, &hmac_sha1(&key, &card_challenge)), tlv(0x74, &host_challenge)].concat();
    let wrapped = session.wrap(0x00, 0xA3, 0x00, 0x00, &validate, Some(0));
    let (answer, status) = session.unwrap(&rig.apdu(&wrapped));
    assert_eq!(status, 0x9000);
    assert_eq!(find_tlv(&answer, 0x75).unwrap(), hmac_sha1(&key, &host_challenge));
    let list = session.wrap(0x00, 0xA1, 0x00, 0x00, &[], Some(0));
    assert_eq!(session.unwrap(&rig.apdu(&list)).1, 0x9000, "validated inside the channel");
    assert_eq!(rig.apdu(&OATH_LIST), vec![0x69, 0x82], "plaintext rejected by the channel");
    let wrapped = session.wrap(0x00, 0xA1, 0x00, 0x00, &[], Some(0));
    assert_eq!(rig.apdu(&wrapped), vec![0x68, 0x82], "no channel any more");
    assert_eq!(sw(&rig.apdu(&OATH_LIST)), 0x6982, "OATH access ended with the channel");
}

/// Catalog SecurityDomain_plaintext: "malformed plaintext SELECT clears OCE and PIV
/// PIN/admin before validation". A plaintext SELECT whose Lc promises more data than it
/// carries, sent inside an SCP03 session, ends the session, and the PIN verified under it
/// is gone while PIV stays selected.
#[test]
fn malformed_plaintext_select_revokes_the_piv_pin() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_PIV);
    let mut session = Scp03::open(&mut rig);
    let verify = session.wrap(0x00, 0x20, 0x00, 0x80, &piv::pin_block("123456"), None);
    assert_eq!(session.unwrap(&rig.apdu(&verify)), (vec![], 0x9000));
    let malformed = [0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x03, 0x08];
    let answer = rig.apdu(&malformed);
    assert_ne!(sw(&answer), 0x9000, "{answer:02X?}");
    let status = rig.apdu(&[0x00, 0x20, 0x00, 0x80]);
    assert_eq!(sw(&status) & 0xFFF0, 0x63C0, "PIN no longer verified: {status:02X?}");
}

/// A handshake is not a session boundary (catalog SecurityDomain_handoff:
/// "not-yet-authenticated SCP03 INIT retain outer transport"): a PIN verified under the
/// channel stays verified after a wrapped INITIALIZE UPDATE.
#[test]
fn nested_handshake_keeps_authorization() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_PIV);
    let mut session = Scp03::open(&mut rig);
    let verify = session.wrap(0x00, 0x20, 0x00, 0x80, &piv::pin_block("123456"), None);
    assert_eq!(session.unwrap(&rig.apdu(&verify)), (vec![], 0x9000));
    let init = session.wrap(0x80, 0x50, 0x00, 0x00, &[0x01; 8], None);
    assert_eq!(session.unwrap(&rig.apdu(&init)).1, 0x9000);
    let status = session.wrap(0x00, 0x20, 0x00, 0x80, &[], None);
    assert_eq!(session.unwrap(&rig.apdu(&status)), (vec![], 0x9000), "still verified");
}

/// Catalog appendix A `Linux_native` "86 actual profile6->FIDO-only->profile6 pending
/// Management checks" and `lib.rs` `settle_management`: a configuration that changes the
/// interface set re-enumerates at once and power-cycles volatile state. A CTAP2 command
/// waiting for a touch on the FIDO interface ends without an answer (its channel is
/// gone): after the WRITE CONFIG answer and `Reenumerate` nothing more is sent, no
/// KEEPALIVE follows, no deadline remains, and the old channel is unknown.
#[test]
fn reenumeration_ends_a_waiting_fido_command_without_an_answer() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    rig.ctaphid_send(cid, CTAPHID_CBOR, &SELECTION);
    let (seq, out) = ccid_write_config(&mut rig, &config(Some(Capabilities::ALL.0 & !Capabilities::OTP), true));
    assert_eq!(answer(&out, seq), Some(vec![0x90, 0x00]));
    assert_eq!(reenumerations(&out), vec![UsbInterfaces { otp: false, fido: true, ccid: true }]);
    assert!(!out.iter().any(|o| matches!(o, Output::FidoReport(_))), "no FIDO answer: {out:02X?}");
    let reply = out.iter().position(|o| matches!(o, Output::Ccid(_))).unwrap();
    let reenumerate = out.iter().position(|o| matches!(o, Output::Reenumerate(_))).unwrap();
    assert!(reply < reenumerate);
    assert_eq!(indicators(&out), vec![false]);
    assert_eq!(rig.dev.next_deadline(), None);
    assert!(rig.run_until(rig.now + 40_000).is_empty());
    assert!(rig.tap().is_empty());
    assert_eq!(rig.ctaphid(cid, CTAPHID_PING, b"x"), (CTAPHID_ERROR, vec![0x0B]), "ERR_INVALID_CHANNEL");
}

/// `docs/DESIGN.md` §5: a reboot drops every volatile state and keeps persistent state
/// (catalog appendix A `Linux_native`: "persistent credentials retained and old PIN
/// token rejected"). Before a Management reboot over CTAPHID (`0x43` with REBOOT):
/// a CTAPHID_LOCK held by the writer's channel (CTAP 2.1 §11.2.9.2.2), a latched U2F
/// touch, an SCP03 session over OATH, an OTP HID response waiting to be read. After it:
/// the channel and its lock are gone, the U2F latch is gone, the CCID slot needs a new
/// IccPowerOn and the secure channel is gone, the OTP HID read state is reset; the OATH
/// credential and the OTP slot remain, and the button still types slot 1.
#[test]
fn reboot_resets_volatile_state_on_every_interface() {
    let mut rig = Rig::new();
    rig.otp_program(slot::CONFIG1, &SlotConfig::yubico_otp(&[], [1; 6], [0x3C; 16]), [0; 6]);
    let pgm_seq = rig.otp_feature()[4];
    rig.power_on();
    rig.select(AID_OATH);
    assert_eq!(rig.apdu(&oath_put(b"kept", false)), vec![0x90, 0x00]);
    let mut session = Scp03::open(&mut rig);
    let cid = rig.ctaphid_init();
    assert_eq!(rig.ctaphid(cid, 0x04, &[10]), (0x04, vec![]), "CTAPHID_LOCK for 10 s");
    let u2f = {
        let mut data = vec![0x42; 32];
        data.extend_from_slice(&[0x24; 32]);
        apdu(0x00, 0x01, 0x00, 0x00, &data, Some(0))
    };
    assert_eq!(rig.ctaphid(cid, CTAPHID_MSG, &u2f).1, vec![0x69, 0x85]);
    rig.tap();
    rig.otp_write(slot::YK4_CAPABILITIES, &[0u8; 64]);
    assert_eq!(rig.otp_feature()[7] & 0x40, 0x40, "OTP HID response pending");

    let out = rig.ctaphid_send(cid, 0x43, &config(None, true));
    assert_eq!(responses(&out), vec![(0x43, vec![])]);
    assert_eq!(reenumerations(&out), vec![UsbInterfaces { otp: true, fido: true, ccid: true }]);

    assert_eq!(rig.ctaphid(cid, CTAPHID_PING, b"x"), (CTAPHID_ERROR, vec![0x0B]), "the channel is gone");
    let fresh = rig.ctaphid_init();
    assert_eq!(rig.ctaphid(fresh, CTAPHID_PING, b"x"), (CTAPHID_PING, b"x".to_vec()), "no lock");
    let status = rig.otp_feature();
    assert_eq!((status[4], status[7] & 0x40), (pgm_seq, 0), "status report, no pending response");
    let (seq, out) = rig.xfr(&OATH_LIST);
    let reply = &ccid_replies(&out)[0];
    assert_eq!((reply[6], reply[7] & 0xC3), (seq, 0x41), "slot inactive: failed, ICC present but not active");
    rig.power_on();
    rig.select(AID_OATH);
    let wrapped = session.wrap(0x00, 0xA1, 0x00, 0x00, &[], Some(0));
    assert_eq!(rig.apdu(&wrapped), vec![0x68, 0x82], "no secure channel");
    assert_eq!(&rig.apdu(&OATH_LIST)[3..7], b"kept");
    let mut reports = keyboard(&rig.touch_down());
    rig.now += 500;
    reports.extend(keyboard(&rig.touch_up()));
    assert_eq!(common::otp::keyboard_text(&reports).len(), 33, "slot 1 types");
    assert_eq!(rig.ctaphid(fresh, CTAPHID_MSG, &u2f).1, vec![0x69, 0x85], "the latch is gone");
}

/// `docs/DESIGN.md` §5: Management turns interfaces on and off; `Device::handle`
/// ignores the inputs of a disabled interface. With OTP disabled the button types
/// nothing and OTP feature reports are ignored, while a touch still serves a card
/// command; with FIDO disabled CTAPHID reports are ignored; with CCID disabled bulk
/// messages, the control ABORT and the resume slot-change notification are not
/// produced.
#[test]
fn disabled_interfaces_ignore_their_inputs() {
    let mut rig = Rig::new();
    rig.otp_program(slot::CONFIG1, &SlotConfig::yubico_otp(&[], [1; 6], [0x3C; 16]), [0; 6]);
    let cid = rig.ctaphid_init();
    let out = rig.ctaphid_send(cid, 0x43, &config(Some(Capabilities::ALL.0 & !Capabilities::OTP), true));
    assert_eq!(reenumerations(&out), vec![UsbInterfaces { otp: false, fido: true, ccid: true }]);
    assert!(rig.input(Input::OtpGetFeature).is_empty());
    assert!(rig.input(Input::OtpSetFeature(&[0, 0, 0, 0, 0, 0, 0, 0x8F])).is_empty());
    assert!(rig.tap().is_empty(), "no OTP typing");
    oath_touch_credential(&mut rig);
    let (seq, _) = rig.xfr(&oath_calculate(b"t"));
    let out = rig.tap();
    assert_eq!(sw(&answer(&out, seq).unwrap()), 0x9000, "the touch serves the card command");
    assert!(keyboard(&out).is_empty());

    let (_, out) = ccid_write_config(&mut rig, &config(Some(Capabilities::OTP | Capabilities::OATH), true));
    assert_eq!(reenumerations(&out), vec![UsbInterfaces { otp: true, fido: false, ccid: true }]);
    let init = Rig::ctaphid_packets(BROADCAST, CTAPHID_INIT, &[1; 8]);
    assert!(rig.input(Input::FidoReport(&init[0])).is_empty(), "CTAPHID ignored");

    let out = otp_write_config(&mut rig, &config(Some(Capabilities::OTP | Capabilities::U2F | Capabilities::FIDO2), true));
    assert_eq!(reenumerations(&out), vec![UsbInterfaces { otp: true, fido: true, ccid: false }]);
    assert!(rig.input(Input::Ccid(&Rig::ccid_message(0x62, 0, [0, 0, 0], &[]))).is_empty(), "CCID ignored");
    assert!(rig.input(Input::CcidControlAbort { slot: 0, seq: 0 }).is_empty());
    rig.bus(BusEvent::Suspend);
    assert!(rig.bus(BusEvent::Resume).is_empty(), "no slot-change notification without CCID");
}

/// `UsbIdentity::device_descriptor` and `configuration_descriptor` against
/// `reference/yubikey-5c-nano-5.7.4/usb-reference-observation.json` in the measured
/// FIDO+CCID configuration: the device fields (`bcdUSB`, `bMaxPacketSize0`, class,
/// IDs, `bcdDevice`, `bNumConfigurations`) and the whole 125-byte configuration
/// descriptor byte for byte (USB 2.0 §9.6.1, §9.6.3), with the HID report descriptor of
/// `hid_report_descriptor_hex`.
#[test]
fn usb_descriptors_match_the_reference_byte_for_byte() {
    let reference = json::parse(USB_REFERENCE);
    let fields = reference.get("device_fields");
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    rig.ctaphid_send(cid, 0x43, &config(Some(Capabilities::ALL.0 & !Capabilities::OTP), true));
    let identity = rig.dev.usb_identity();
    let device = identity.device_descriptor();
    let le16 = |offset: usize| i64::from(u16::from_le_bytes([device[offset], device[offset + 1]]));
    assert_eq!((device[0], device[1]), (18, 0x01));
    assert_eq!(le16(2), fields.get("bcdUSB").as_i64());
    assert_eq!(i64::from(device[4]), fields.get("bDeviceClass").as_i64());
    assert_eq!(i64::from(device[5]), fields.get("bDeviceSubClass").as_i64());
    assert_eq!(i64::from(device[6]), fields.get("bDeviceProtocol").as_i64());
    assert_eq!(i64::from(device[7]), fields.get("bMaxPacketSize0").as_i64());
    assert_eq!(le16(8), fields.get("idVendor").as_i64());
    assert_eq!(le16(10), fields.get("idProduct").as_i64());
    assert_eq!(le16(12), fields.get("bcdDevice").as_i64());
    assert_eq!(i64::from(device[17]), fields.get("bNumConfigurations").as_i64());
    assert_eq!(device[16], 0, "no serial string while no OTP slot shows the serial over USB");
    assert_eq!(identity.configuration_descriptor(), hex(reference.get("configuration_descriptor_hex").as_str()));
    assert_eq!(identity.fido_report_descriptor, hex(reference.get("hid_report_descriptor_hex").as_str()));
}

/// Walk a configuration descriptor (USB 2.0 §9.5: each descriptor starts with its
/// length and type) into (type, bytes) pairs.
fn descriptors(config: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut rest = config;
    while !rest.is_empty() {
        let len = usize::from(rest[0]);
        assert!(len >= 2 && len <= rest.len(), "descriptor length {len}");
        out.push((rest[1], rest[..len].to_vec()));
        rest = &rest[len..];
    }
    out
}

/// Every interface combination (catalog appendix A "USB class matching IDs for seven
/// interface combinations") gives a well-formed configuration descriptor: `wTotalLength`
/// and `bNumInterfaces` right, interfaces numbered from 0 in the order OTP, FIDO,
/// CCID, each HID descriptor naming the length of its report descriptor, the CCID class
/// descriptor as in the identity, unique endpoint addresses; and the FIDO and CCID
/// blocks are the reference's blocks (only the interface number differs). The OTP
/// keyboard interface is model policy (`usb.rs`): a HID boot keyboard (HID 1.11 §4.2,
/// §4.3) with one interrupt IN endpoint.
#[test]
fn every_interface_combination_has_a_consistent_configuration_descriptor() {
    let reference = hex(json::parse(USB_REFERENCE).get("configuration_descriptor_hex").as_str());
    let reference_fido = &reference[9..9 + 32];
    let reference_ccid = &reference[9 + 32..];
    let mut rig = Rig::new();
    let combinations = [
        Capabilities::OTP,
        Capabilities::U2F | Capabilities::FIDO2,
        Capabilities::OTP | Capabilities::FIDO2,
        Capabilities::PIV,
        Capabilities::OTP | Capabilities::OATH,
        Capabilities::FIDO2 | Capabilities::OPENPGP,
        Capabilities::ALL.0,
    ];
    for bits in combinations {
        let interfaces = Capabilities(bits).interfaces();
        let current = rig.dev.interfaces();
        let data = config(Some(bits), true);
        if current.fido {
            let cid = rig.ctaphid_init();
            rig.ctaphid_send(cid, 0x43, &data);
        } else if current.ccid {
            ccid_write_config(&mut rig, &data);
        } else {
            otp_write_config(&mut rig, &data);
        }
        let identity = rig.dev.usb_identity();
        assert_eq!(identity.interfaces, interfaces);
        let config = identity.configuration_descriptor();
        let parts = descriptors(&config);
        let count = [interfaces.otp, interfaces.fido, interfaces.ccid].iter().filter(|&&on| on).count();
        assert_eq!(parts[0].0, 0x02);
        assert_eq!(usize::from(u16::from_le_bytes([config[2], config[3]])), config.len(), "{interfaces:?} wTotalLength");
        assert_eq!(usize::from(config[4]), count, "{interfaces:?} bNumInterfaces");
        let found: Vec<&Vec<u8>> = parts.iter().filter(|(kind, _)| *kind == 0x04).map(|(_, d)| d).collect();
        assert_eq!(found.len(), count);
        for (number, interface) in found.iter().enumerate() {
            assert_eq!(usize::from(interface[2]), number, "{interfaces:?} interface numbers");
        }
        let mut endpoints: Vec<u8> = parts.iter().filter(|(kind, _)| *kind == 0x05).map(|(_, d)| d[2]).collect();
        let total = endpoints.len();
        endpoints.sort_unstable();
        endpoints.dedup();
        assert_eq!(endpoints.len(), total, "{interfaces:?} endpoint addresses unique");
        let mut classes = found.iter().map(|d| (d[5], d[6], d[7]));
        let mut offset = 9;
        if interfaces.otp {
            assert_eq!(classes.next(), Some((0x03, 0x01, 0x01)), "boot keyboard");
            let hid = &config[offset + 9..offset + 18];
            assert_eq!(usize::from(u16::from_le_bytes([hid[7], hid[8]])), identity.otp_report_descriptor.len());
            offset += 9 + 9 + 7;
        }
        if interfaces.fido {
            assert_eq!(classes.next(), Some((0x03, 0x00, 0x00)));
            let mut block = config[offset..offset + 32].to_vec();
            block[2] = 0;
            assert_eq!(block, reference_fido, "{interfaces:?} FIDO block");
            offset += 32;
        }
        if interfaces.ccid {
            assert_eq!(classes.next(), Some((0x0B, 0x00, 0x00)));
            let mut block = config[offset..].to_vec();
            block[2] = 1;
            assert_eq!(block, reference_ccid, "{interfaces:?} CCID block");
            assert_eq!(&config[offset + 9..offset + 9 + 54], identity.ccid_class_descriptor.as_slice());
        }
    }
}
