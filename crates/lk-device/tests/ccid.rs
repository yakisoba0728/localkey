//! The CCID interface end to end: CCID messages in, CCID messages out.

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use lk_core::DeviceProfile;
use lk_device::{BusEvent, Input, Output, WTX_INTERVAL_MS};

/// PIV VERIFY with the default PIN `123456` padded with `FF` (SP 800-73-4 Part 2 §3.2.1).
const PIV_VERIFY: &[u8] = &[0x00, 0x20, 0x00, 0x80, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF];
/// VERIFY without data: the PIN status query (SP 800-73-4 Part 2 §3.2.1).
const PIV_PIN_STATUS: &[u8] = &[0x00, 0x20, 0x00, 0x80];

fn oath_with_touch_credential(rig: &mut Rig) {
    rig.power_on();
    assert_eq!(sw(&rig.select(AID_OATH)), 0x9000);
    assert_eq!(rig.apdu(&oath_put(b"touch", true)), vec![0x90, 0x00]);
}

/// USB CCID Rev 1.1 §6.1.1: IccPowerOn answers the ATR, here `DeviceProfile::atr`.
#[test]
fn power_on_returns_the_profile_atr() {
    for profile in [DeviceProfile::own(1), DeviceProfile::yubikey_5c_nano_5_7_4(1)] {
        let mut rig = Rig::with_profile(profile.clone());
        assert_eq!(rig.power_on(), profile.atr);
    }
}

/// lk-mgmt: SELECT answers the firmware version text, 30 ASCII bytes as the key sends
/// them (docs/MEASUREMENT.md, probe `select-mgmt`; the engine sent the bare `5.7.4`
/// before the measurement).
#[test]
fn select_management() {
    let mut rig = Rig::new();
    rig.power_on();
    assert_eq!(rig.select(AID_MGMT), b"Virtual mgr - FW version 5.7.4\x90\x00".to_vec());
}

/// docs/MEASUREMENT.md, probe `select-partial-aid`: a SELECT by a partial DF name
/// selects the applet whose AID starts with it (the first in table order). The key
/// answered `A0000005` and `A000000527` with Management's 30-byte text, `A0000003` with
/// PIV's 19-byte template, `D276000124` with OpenPGP's empty `9000` and
/// `A0000005272107` with HSM Auth's `79 03 050704`; the engine answered `6A82` to all
/// five before the measurement.
#[test]
fn select_by_partial_df_name() {
    let mut rig = Rig::new();
    rig.power_on();
    let mgmt = b"Virtual mgr - FW version 5.7.4\x90\x00".to_vec();
    assert_eq!(rig.select(&[0xA0, 0x00, 0x00, 0x05]), mgmt);
    assert_eq!(rig.select(&[0xA0, 0x00, 0x00, 0x05, 0x27]), mgmt);
    let piv = rig.select(&[0xA0, 0x00, 0x00, 0x03]);
    assert_eq!((piv.len(), piv[0], sw(&piv)), (19 + 2, 0x61, 0x9000));
    assert_eq!(rig.select(&[0xD2, 0x76, 0x00, 0x01, 0x24]), vec![0x90, 0x00]);
    assert_eq!(rig.select(&[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x07]), vec![0x79, 0x03, 5, 7, 4, 0x90, 0x00]);
    // The selection took effect: HSM Auth GET VERSION.
    assert_eq!(rig.apdu(&[0x00, 0x07, 0x00, 0x00, 0x00]), vec![5, 7, 4, 0x90, 0x00]);
    // A name no AID starts with is still not found and keeps the selection.
    assert_eq!(rig.select(&[0xA0, 0x00, 0x00, 0x05, 0x27, 0x99]), vec![0x6A, 0x82]);
    assert_eq!(rig.apdu(&[0x00, 0x07, 0x00, 0x00, 0x00]), vec![5, 7, 4, 0x90, 0x00]);
}

/// docs/MEASUREMENT.md, probes `mgmt-read-config`, `bad-p1p2-mgmt`, `cla-variants-mgmt`
/// and `get-response-idle-mgmt`, end to end over CCID: READ CONFIG page 0 is 52 bytes
/// (`33 || ...`, ending with MORE_DATA) and page 1 42 bytes (`29 || ...`); P2 is
/// ignored; a page past the last is a bare `9000`; CLA 80 reads like CLA 00; GET
/// RESPONSE with nothing pending is `6D00`.
#[test]
fn management_reads_as_measured() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_MGMT);
    let page0 = rig.apdu(&[0x00, 0x1D, 0x00, 0x00, 0x00]);
    assert_eq!((page0.len(), page0[0], sw(&page0)), (52 + 2, 0x33, 0x9000));
    assert_eq!(&page0[page0.len() - 5..page0.len() - 2], &[0x10, 0x01, 0x01]);
    let page1 = rig.apdu(&[0x00, 0x1D, 0x01, 0x00, 0x00]);
    assert_eq!((page1.len(), page1[0], sw(&page1)), (42 + 2, 0x29, 0x9000));
    assert_eq!(rig.apdu(&[0x00, 0x1D, 0x00, 0x01]), page0);
    assert_eq!(rig.apdu(&[0x00, 0x1D, 0x02, 0x00]), vec![0x90, 0x00]);
    assert_eq!(rig.apdu(&[0x00, 0x1D, 0xFF, 0x00]), vec![0x90, 0x00]);
    assert_eq!(rig.apdu(&[0x80, 0x1D, 0x00, 0x00]), page0);
    assert_eq!(rig.apdu(&[0x00, 0xC0, 0x00, 0x00, 0x00]), vec![0x6D, 0x00]);
    // Le 01: the length byte and 6133.
    assert_eq!(rig.apdu(&[0x00, 0x1D, 0x00, 0x00, 0x01]), vec![0x33, 0x61, 0x33]);
}

/// docs/MEASUREMENT.md, probes `undefined-ins-sd`, `get-response-idle-sd`,
/// `cla-variants-sd` and `get-response-idle-hsmauth`, `cla-variants-hsmauth`, end to end
/// over CCID without a secure channel.
#[test]
fn security_domain_and_hsm_auth_statuses_as_measured() {
    let mut rig = Rig::new();
    rig.power_on();
    assert_eq!(sw(&rig.select(AID_SD)), 0x9000);
    for ins in [0x5E, 0x6E, 0x93] {
        assert_eq!(rig.apdu(&[0x00, ins, 0x00, 0x00]), vec![0x69, 0x82], "INS {ins:02X}");
    }
    assert_eq!(rig.apdu(&[0x00, 0xC0, 0x00, 0x00, 0x00]), vec![0x69, 0x82]);
    let wrapped = rig.apdu(&[0x80, 0xCA, 0x00, 0x66]);
    assert_eq!((wrapped.len(), &wrapped[..4], sw(&wrapped)), (65 + 2, &[0x66, 0x3F, 0x73, 0x3D][..], 0x9000));
    let bare = rig.apdu(&[0x00, 0xCA, 0x00, 0x66]);
    assert_eq!(&wrapped[2..], &bare[..]);
    assert_eq!(rig.apdu(&[0x10, 0xCA, 0x00, 0x66]), vec![0x90, 0x00]);
    assert_eq!(rig.apdu(&[0x00, 0xC0, 0x00, 0x00, 0x00]), vec![0x69, 0x82]);

    assert_eq!(sw(&rig.select(AID_HSMAUTH)), 0x9000);
    assert_eq!(rig.apdu(&[0x80, 0x5E, 0x00, 0x00]), vec![0x6D, 0x00]);
    assert_eq!(rig.apdu(&[0x00, 0xC0, 0x00, 0x00, 0x00]), vec![0x6D, 0x00]);
}

/// ISO/IEC 7816-4 §5.6 `6A82` for an unknown AID (here the FIDO AID, which this USB
/// device does not offer on CCID); the current selection stays (`card.rs` step 4).
#[test]
fn unknown_aid_is_6a82_and_keeps_the_selection() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_MGMT);
    assert_eq!(rig.select(&[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]), vec![0x6A, 0x82]);
    let config = rig.apdu(&[0x00, 0x1D, 0x00, 0x00, 0x00]);
    assert_eq!(sw(&config), 0x9000, "READ CONFIG still reaches Management");
}

/// ISO/IEC 7816-4:1995 §5.5.2-§5.5.3: the class byte of a SELECT codes the logical
/// channel it is for, and a SELECT with another channel number opens that channel. This
/// device has none (the ATR's third software function table byte `C0`: "no logical
/// channel", Table 87), so a SELECT on channel 1-3 (CLA `01`-`03`, `81`-`83`) or 4-19
/// (`40`-`7F`, `C0`-`FE`, GP 2.3.1 §11.1.4.2 Table 11-12) answers `6881` (Table 16
/// "Logical channel not supported"; GP 2.3.1 Table 11-10) and changes nothing: the
/// basic channel's selection and the Security Domain's half-open handshake stay. CLA
/// `FF` (Table 8: reserved for PTS) answers `6E00`. Before, the class was ignored and
/// the SELECT moved the basic channel's selection. Unmeasured on the reference key.
#[test]
fn select_on_another_logical_channel_answers_6881_and_changes_nothing() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_MGMT);
    let config = rig.apdu(&[0x00, 0x1D, 0x00, 0x00, 0x00]);
    assert_eq!(sw(&config), 0x9000);
    // A half-open SCP03 handshake (INITIALIZE UPDATE answered, EXTERNAL AUTHENTICATE
    // still to come) would be dropped by a SELECT that ends the session.
    let initialize = rig.apdu(&apdu(0x80, 0x50, 0x00, 0x00, &[0x11; 8], None));
    assert_eq!((initialize.len(), sw(&initialize)), (29 + 2, 0x9000));
    for cla in [0x01u8, 0x02, 0x03, 0x11, 0x81, 0x83, 0x40, 0x4F, 0x61, 0x7F, 0xC0, 0xC1, 0xFE] {
        for aid in [AID_SD, AID_PIV, &[][..]] {
            let select = apdu(cla, 0xA4, 0x04, 0x00, aid, Some(0));
            assert_eq!(rig.apdu(&select), vec![0x68, 0x81], "CLA {cla:02X}, AID {aid:02X?}");
        }
    }
    assert_eq!(rig.apdu(&apdu(0xFF, 0xA4, 0x04, 0x00, AID_SD, Some(0))), vec![0x6E, 0x00]);
    // Management is still selected and answers as before.
    assert_eq!(rig.apdu(&[0x00, 0x1D, 0x00, 0x00, 0x00]), config);
    // The handshake was not dropped: an EXTERNAL AUTHENTICATE with a wrong C-MAC is
    // checked against it (`6982`), where one without a pending handshake answers `6985`
    // (lk-sd `handshake.rs`).
    let external = rig.apdu(&apdu(0x84, 0x82, 0x33, 0x00, &[0u8; 16], None));
    assert_eq!(external, vec![0x69, 0x82]);
    assert_eq!(rig.apdu(&apdu(0x84, 0x82, 0x33, 0x00, &[0u8; 16], None)), vec![0x69, 0x85], "now nothing is pending");
    // The basic channel still selects, with CLA `00` and the GlobalPlatform class `80`.
    assert_eq!(sw(&rig.apdu(&apdu(0x80, 0xA4, 0x04, 0x00, AID_SD, Some(0)))), 0x9000);
    assert_eq!(sw(&rig.select(AID_MGMT)), 0x9000);
}

/// GP Card Specification v2.3.1 §11.9.2.3: "The Lc and data field of the SELECT command
/// may be omitted if the Issuer Security Domain is being selected. In this case, Le
/// shall be set to '00'". `00 A4 04 00 00` selects the Security Domain (the ISD, §H.1.3)
/// and answers its File Control Information (GP 2.3.1 Table 11-82); like every SELECT
/// it ends a secure channel session. Before, an empty DF name answered `6A82`.
/// Unmeasured on the reference key.
#[test]
fn empty_df_name_selects_the_security_domain() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_MGMT);
    let fci = hex("6F1B8408A000000151000000A50F730906072A864886FC6B019F6501FF9000");
    assert_eq!(rig.apdu(&[0x00, 0xA4, 0x04, 0x00, 0x00]), fci);
    assert_eq!(rig.select(AID_SD), fci, "the same answer as a SELECT by the full AID");
    // The Security Domain is selected: its GET DATA `0066` answers.
    rig.select(AID_MGMT);
    assert_eq!(rig.apdu(&[0x00, 0xA4, 0x04, 0x00, 0x00]), fci);
    let recognition = rig.apdu(&[0x00, 0xCA, 0x00, 0x66, 0x00]);
    assert_eq!((recognition.len(), &recognition[..2], sw(&recognition)), (63 + 2, &[0x73, 0x3D][..], 0x9000));
    // A secure channel session ends with it.
    let mut session = Scp03::open(&mut rig);
    assert_eq!(rig.apdu(&[0x00, 0xA4, 0x04, 0x00, 0x00]), fci);
    let get = session.wrap(0x00, 0xCA, 0x00, 0x66, &[], Some(0));
    assert_eq!(rig.apdu(&get), vec![0x69, 0x82], "no channel left to unwrap it");
}

/// Model policy (`card.rs` step 5): `6D00` with no application selected.
#[test]
fn no_selection_answers_6d00() {
    let mut rig = Rig::new();
    rig.power_on();
    assert_eq!(rig.apdu(&[0x00, 0xCA, 0x00, 0x66, 0x00]), vec![0x6D, 0x00]);
    assert_eq!(rig.apdu(&[0x00, 0xCA]), vec![0x67, 0x00]);
}

/// docs/CONTRACTS.md "Applications A": `00 A4 00 0x` is YKOATH CALCULATE ALL for the
/// selected applet, not a SELECT.
#[test]
fn calculate_all_is_not_a_select() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_OATH);
    rig.apdu(&oath_put(b"plain", false));
    let response = rig.apdu(&apdu(0x00, 0xA4, 0x00, 0x01, &[0x74, 0x08, 0, 0, 0, 0, 0, 0, 0, 1], Some(0)));
    assert_eq!(sw(&response), 0x9000);
    assert_eq!(&response[..2], &[0x71, 0x05], "a CALCULATE ALL listing, not a SELECT answer");
}

/// SP 800-73-4 Part 1 §2.2: the full PIV AID with its version selects PIV (the applet's
/// AID is a right-truncated prefix).
#[test]
fn full_piv_aid_selects_piv() {
    let mut rig = Rig::new();
    rig.power_on();
    let response = rig.select(AID_PIV_FULL);
    assert_eq!(sw(&response), 0x9000);
    assert_eq!(response[0], 0x61, "application property template");
}

/// docs/CONTRACTS.md "Applications B": a SELECT of the selected AID goes to `select()`
/// without `deselect()` (SP 800-73-4 Part 2 §3.1.1 keeps the security status); a
/// different applet in between deselects PIV.
#[test]
fn piv_reselect_keeps_pin_verification() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_PIV);
    assert_eq!(rig.apdu(PIV_VERIFY), vec![0x90, 0x00]);
    rig.select(AID_PIV);
    assert_eq!(rig.apdu(PIV_PIN_STATUS), vec![0x90, 0x00]);
    rig.select(AID_OATH);
    rig.select(AID_PIV);
    assert_eq!(rig.apdu(PIV_PIN_STATUS), vec![0x63, 0xC3]);
}

/// docs/CONTRACTS.md "Applications B": `OpenPgp::select` answers `6285` while
/// terminated; `62xx` is a successful selection and the device keeps routing to it.
#[test]
fn terminated_openpgp_stays_selected() {
    let mut rig = Rig::new();
    rig.power_on();
    assert_eq!(rig.select(AID_OPENPGP), vec![0x90, 0x00]);
    assert_eq!(rig.apdu(&apdu(0x00, 0x20, 0x00, 0x83, b"12345678", None)), vec![0x90, 0x00]);
    assert_eq!(rig.apdu(&[0x00, 0xE6, 0x00, 0x00]), vec![0x90, 0x00]);
    assert_eq!(rig.select(AID_OPENPGP), vec![0x62, 0x85]);
    // Still OpenPGP (a missing selection would answer 6D00).
    assert_eq!(rig.apdu(&[0x00, 0xCA, 0x00, 0x6E, 0x00]), vec![0x62, 0x85]);
    assert_eq!(rig.apdu(&[0x00, 0x44, 0x00, 0x00]), vec![0x90, 0x00]);
    assert_eq!(rig.select(AID_OPENPGP), vec![0x90, 0x00]);
}

/// A card command that needs a touch keeps the slot busy: a CCID time extension
/// (`bStatus` `80`, USB CCID Rev 1.1 §6.2.6) every `WTX_INTERVAL_MS`, the presence
/// indicator lit, and the response after the touch.
#[test]
fn card_touch_sends_time_extensions_and_resolves() {
    let mut rig = Rig::new();
    oath_with_touch_credential(&mut rig);
    let (seq, out) = rig.xfr(&oath_calculate(b"touch"));
    assert!(data_block(&out, seq).is_none());
    assert_eq!(indicators(&out), vec![true]);
    assert_eq!(rig.dev.next_deadline(), Some(rig.now + WTX_INTERVAL_MS));
    for _ in 0..2 {
        let out = rig.advance(WTX_INTERVAL_MS);
        assert_eq!(time_extensions(&out), 1);
    }
    let out = rig.tap();
    let response = data_block(&out, seq).unwrap();
    assert_eq!(sw(&response), 0x9000);
    assert_eq!(response[0], 0x76, "truncated response tag");
    assert_eq!(indicators(&out), vec![false]);
}

/// docs/CONTRACTS.md "Applications B": OATH uses a 15000 ms touch timeout; on timeout
/// lk-device calls `touch_resolved(false)` and sends its answer (lk-oath: `6982`).
#[test]
fn card_touch_timeout_answers() {
    let mut rig = Rig::new();
    oath_with_touch_credential(&mut rig);
    let (seq, _) = rig.xfr(&oath_calculate(b"touch"));
    let mut response = None;
    while response.is_none() && rig.now < 20_000 {
        let out = rig.advance(WTX_INTERVAL_MS);
        response = data_block(&out, seq);
    }
    assert_eq!(rig.now, 15_000);
    assert_eq!(response.unwrap(), vec![0x69, 0x82]);
}

/// docs/CONTRACTS.md "Phase 0", lk-ccid: a bulk `PC_to_RDR_Abort` of the outstanding
/// XfrBlock (detected by `pending_seq` changing) cancels the waiting applet operation;
/// its response is never sent.
#[test]
fn bulk_abort_cancels_the_waiting_command() {
    let mut rig = Rig::new();
    oath_with_touch_credential(&mut rig);
    let (seq, _) = rig.xfr(&oath_calculate(b"touch"));
    let out = rig.bulk_abort(seq);
    assert_eq!(ccid_replies(&out).len(), 1);
    assert_eq!(ccid_replies(&out)[0][0], 0x81, "RDR_to_PC_SlotStatus for the abort");
    assert_eq!(indicators(&out), vec![false]);
    let out = rig.tap();
    assert!(ccid_replies(&out).is_empty(), "no late response: {out:02X?}");
    let list = rig.apdu(&apdu(0x00, 0xA1, 0x00, 0x00, &[], None));
    assert_eq!(sw(&list), 0x9000, "the slot works again");
}

/// USB CCID Rev 1.1 §5.3.1: the control ABORT first answers the outstanding XfrBlock
/// with `CMD_ABORTED`, then the matching bulk Abort completes the sequence (catalog
/// appendix A: "control/bulk ABORT in either delivery order").
#[test]
fn control_abort_then_bulk_abort() {
    let mut rig = Rig::new();
    oath_with_touch_credential(&mut rig);
    let (seq, _) = rig.xfr(&oath_calculate(b"touch"));
    let out = rig.input(Input::CcidControlAbort { slot: 0, seq });
    let replies = ccid_replies(&out);
    assert_eq!(replies.len(), 1);
    assert_eq!((replies[0][0], replies[0][6], replies[0][7] & 0xC0, replies[0][8]), (0x80, seq, 0x40, 0xFF));
    assert_eq!(indicators(&out), vec![false]);
    let out = rig.bulk_abort(seq);
    assert_eq!(ccid_replies(&out)[0][0], 0x81);
    assert!(ccid_replies(&rig.tap()).is_empty());
    let response = rig.apdu(&apdu(0x00, 0xA1, 0x00, 0x00, &[], None));
    assert_eq!(sw(&response), 0x9000, "the slot works again");
}

/// USB CCID Rev 1.1 §6.1.2 IccPowerOff ends the card session:
/// `CardApplet::reset(CardPowerOff)` drops PIV PIN verification and the selection.
#[test]
fn power_off_ends_the_card_session() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_PIV);
    rig.apdu(PIV_VERIFY);
    rig.power_off();
    rig.power_on();
    assert_eq!(rig.apdu(PIV_PIN_STATUS), vec![0x6D, 0x00], "nothing selected after power-off");
    rig.select(AID_PIV);
    assert_eq!(rig.apdu(PIV_PIN_STATUS), vec![0x63, 0xC3]);
}

/// docs/CONTRACTS.md "Phase 0", lk-ccid: IccPowerOn while active is a warm reset that
/// ends the card session too.
#[test]
fn warm_reset_ends_the_card_session() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_PIV);
    rig.apdu(PIV_VERIFY);
    rig.power_on();
    rig.select(AID_PIV);
    assert_eq!(rig.apdu(PIV_PIN_STATUS), vec![0x63, 0xC3]);
}

/// `lk_ccid::Ccid::reset`: after a USB reset the ICC is inactive until IccPowerOn; an
/// XfrBlock fails.
#[test]
fn usb_reset_deactivates_the_slot() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_PIV);
    rig.bus(BusEvent::Reset);
    let (_, out) = rig.xfr(PIV_PIN_STATUS);
    let reply = &ccid_replies(&out)[0];
    assert_eq!(reply[7] & 0x40, 0x40, "command failed: {reply:02X?}");
    rig.power_on();
    assert_eq!(rig.apdu(PIV_PIN_STATUS), vec![0x6D, 0x00]);
}

/// Catalog appendix A `Linux_native`: after resume "each occupied slot becomes
/// inactive, insertion5003 once, no unpowered APDU, new PowerOn/ATR required; PIV
/// PIN/admin revoked".
#[test]
fn resume_reports_insertion_and_requires_power_on() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_PIV);
    rig.apdu(PIV_VERIFY);
    assert!(rig.bus(BusEvent::Suspend).is_empty());
    let out = rig.bus(BusEvent::Resume);
    assert_eq!(out, vec![Output::CcidInterrupt(vec![0x50, 0x03])]);
    let (_, out) = rig.xfr(PIV_PIN_STATUS);
    assert_eq!(ccid_replies(&out)[0][7] & 0x40, 0x40, "no unpowered APDU");
    rig.power_on();
    rig.select(AID_PIV);
    assert_eq!(rig.apdu(PIV_PIN_STATUS), vec![0x63, 0xC3]);
    // A resume without a suspend changes nothing.
    assert!(rig.bus(BusEvent::Resume).is_empty());
}

/// Catalog appendix A `Linux_native`: "real terminal touch canceled without commit" on
/// suspend/resume; the waiting card command never answers.
#[test]
fn resume_cancels_a_waiting_card_command() {
    let mut rig = Rig::new();
    oath_with_touch_credential(&mut rig);
    let (_, out) = rig.xfr(&oath_calculate(b"touch"));
    assert_eq!(indicators(&out), vec![true]);
    rig.bus(BusEvent::Suspend);
    let out = rig.bus(BusEvent::Resume);
    assert_eq!(indicators(&out), vec![false]);
    assert!(ccid_replies(&rig.tap()).is_empty());
}

/// docs/DESIGN.md §7 and docs/CONTRACTS.md "Persisted state": a failed save keeps the
/// previous state and the applet answers `6581`.
#[test]
fn storage_failure_reaches_the_applet() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_OATH);
    rig.store.fail_next_saves(1);
    assert_eq!(rig.apdu(&oath_put(b"a", false)), vec![0x65, 0x81]);
    let list = rig.apdu(&apdu(0x00, 0xA1, 0x00, 0x00, &[], None));
    assert_eq!(list, vec![0x90, 0x00], "nothing was added");
    assert_eq!(rig.apdu(&oath_put(b"a", false)), vec![0x90, 0x00]);
}

/// USB CCID Rev 1.1 §6.1.4 command chaining (`wLevelParameter` `0001` then `0002`):
/// the parts form one APDU for the card session; the first part is acknowledged with
/// an empty DataBlock, `bChainParameter` `10` (catalog appendix A "CCID
/// command/response chaining").
#[test]
fn ccid_command_chaining_assembles_one_apdu() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_OATH);
    let put = oath_put(b"chained", false);
    let (first, rest) = put.split_at(9);
    let out = rig.input(Input::Ccid(&Rig::ccid_message(0x6F, 40, [0, 0x01, 0x00], first)));
    let ack = &ccid_replies(&out)[0];
    assert_eq!((ack[0], ack[7], ack[9], ack.len()), (0x80, 0x00, 0x10, 10));
    let out = rig.input(Input::Ccid(&Rig::ccid_message(0x6F, 41, [0, 0x02, 0x00], rest)));
    assert_eq!(data_block(&out, 41).unwrap(), vec![0x90, 0x00]);
    let list = rig.apdu(&[0x00, 0xA1, 0x00, 0x00]);
    assert_eq!(&list[3..10], b"chained");
}

/// USB CCID Rev 1.1 §6.2.1 response chaining: a response longer than one message
/// (3062 data bytes, `dwMaxCCIDMessageLength` 3072 in the reference descriptor) starts
/// with `bChainParameter` `01`; an empty XfrBlock with `wLevelParameter` `0010` fetches
/// the rest, ending with `02` (catalog appendix A "measured endpoints, CCID 3072-byte
/// messages").
#[test]
fn long_response_uses_ccid_response_chaining() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_OATH);
    for i in 0..64u8 {
        let name = [vec![i], vec![b'n'; 63]].concat();
        assert_eq!(rig.apdu(&oath_put(&name, false)), vec![0x90, 0x00]);
    }
    // Extended Le 00 00: Ne = 65 536, so OATH answers in one APDU (YKOATH §LIST).
    let (seq, out) = rig.xfr(&[0x00, 0xA1, 0x00, 0x00, 0x00, 0x00, 0x00]);
    let first = &ccid_replies(&out)[0];
    assert_eq!((first[0], first[6], first[9]), (0x80, seq, 0x01));
    assert_eq!(first.len() - 10, 3062);
    let mut response = first[10..].to_vec();
    let out = rig.input(Input::Ccid(&Rig::ccid_message(0x6F, 90, [0, 0x10, 0x00], &[])));
    let last = &ccid_replies(&out)[0];
    assert_eq!(last[9], 0x02, "last part");
    response.extend_from_slice(&last[10..]);
    assert_eq!(response.len(), 64 * 67 + 2);
    assert_eq!(sw(&response), 0x9000);
}

/// Catalog appendix A "busy-slot replies": while a command waits for a touch, other
/// CCID messages fail with `CMD_SLOT_BUSY` (`bError` `E0`, USB CCID Rev 1.1 §6.2.6)
/// and the waiting command is unaffected.
#[test]
fn busy_slot_while_waiting_for_touch() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_OATH);
    rig.apdu(&oath_put(b"touch", true));
    let (seq, _) = rig.xfr(&oath_calculate(b"touch"));
    let out = rig.input(Input::Ccid(&Rig::ccid_message(0x65, 60, [0, 0, 0], &[])));
    let busy = &ccid_replies(&out)[0];
    assert_eq!((busy[7] & 0x40, busy[8]), (0x40, 0xE0));
    let out = rig.tap();
    assert_eq!(sw(&data_block(&out, seq).unwrap()), 0x9000);
}

/// USB CCID Rev 1.1 §6.1.5 GetParameters: T=1 with the parameters derived from the
/// profile ATR (catalog appendix A "CCID T=1 parameter negotiation").
#[test]
fn get_parameters_reports_t1() {
    let mut rig = Rig::new();
    rig.power_on();
    let out = rig.input(Input::Ccid(&Rig::ccid_message(0x6C, 7, [0, 0, 0], &[])));
    let reply = &ccid_replies(&out)[0];
    assert_eq!((reply[0], reply[7], reply[9]), (0x82, 0x00, 0x01), "RDR_to_PC_Parameters, T=1");
    assert_eq!(reply.len(), 10 + 7);
}
