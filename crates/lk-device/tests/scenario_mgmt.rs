//! End-to-end Management scenarios: DeviceInfo through all three transports, interface
//! enablement with re-enumeration, and the reboot flag (yubikit `management.py` wire
//! formats: CCID `1D`/`1C`, CTAPHID vendor `0x42`/`0x43`, OTP slots `0x13`/`0x15`).

#![allow(clippy::unwrap_used)]

mod common;

use common::ctap::{self, PinAuth, PinProtocol2, perm, status};
use common::iso::find_tlv;
use common::otp::{self, SlotConfig, slot};
use common::*;
use lk_core::UsbInterfaces;
use lk_device::{Input, Output};
use lk_testkit::SeededEntropy;

/// USB application bits (yubikit `CAPABILITY`): OTP 0001, U2F 0002, OPENPGP 0008, PIV
/// 0010, OATH 0020, HSMAUTH 0100, FIDO2 0200.
const ALL_APPS: u16 = 0x033B;
const NO_CCID_APPS: u16 = 0x0203;

/// DeviceInfo over CCID: SELECT Management, READ CONFIG `00 1D <page> 00 00`.
fn info_ccid(rig: &mut Rig, page: u8) -> Vec<u8> {
    rig.power_on();
    assert_eq!(sw(&rig.select(AID_MGMT)), 0x9000);
    let response = rig.apdu(&[0x00, 0x1D, page, 0x00, 0x00]);
    assert_eq!(sw(&response), 0x9000);
    response[..response.len() - 2].to_vec()
}

/// DeviceInfo over CTAPHID: vendor command `0x42` with the page byte.
fn info_ctaphid(rig: &mut Rig, page: u8) -> Vec<u8> {
    let cid = rig.ctaphid_init();
    let (command, payload) = rig.ctaphid(cid, 0x42, &[page]);
    assert_eq!(command, 0x42);
    payload
}

/// DeviceInfo over OTP HID: slot `0x13` with the page as first data byte; the response is
/// `len || TLVs` with a CRC over `len + 3` bytes (yubikit `_ManagementOtpBackend`,
/// `check_crc`).
fn info_otp(rig: &mut Rig, page: u8) -> Vec<u8> {
    let mut payload = [0u8; 64];
    payload[0] = page;
    rig.otp_send_frame(slot::YK4_CAPABILITIES, &payload);
    let raw = rig.otp_read_frame();
    let len = usize::from(raw[0]);
    assert_eq!(otp::crc16(&raw[..len + 3]), otp::CRC_OK_RESIDUE, "DeviceInfo CRC");
    raw[..=len].to_vec()
}

/// WRITE CONFIG data `len || TLVs` (yubikit `DeviceConfig.get_bytes`).
fn config(tlvs: &[(u8, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    for (tag, value) in tlvs {
        body.push(*tag);
        body.push(value.len() as u8);
        body.extend_from_slice(value);
    }
    [vec![body.len() as u8], body].concat()
}

/// yubikit `read_device_info`: DeviceInfo is the same `len || TLVs` page on every
/// transport (catalog Management "CCID and OTP HID device information", "CTAPHID vendor
/// 0x42 / 0x43 commands"); its TLVs carry the profile's serial, firmware 5.7.4, the
/// USB-C Nano form factor and the supported/enabled USB applications. Pages follow
/// `MORE_DATA` (`10 01 01`) identically everywhere.
#[test]
fn device_info_is_identical_over_ccid_otp_hid_and_ctaphid() {
    let mut rig = Rig::new();
    let mut page = 0u8;
    loop {
        let ccid = info_ccid(&mut rig, page);
        let fido = info_ctaphid(&mut rig, page);
        let hid = info_otp(&mut rig, page);
        assert_eq!(usize::from(ccid[0]), ccid.len() - 1, "len prefix");
        assert_eq!(ccid, fido, "CCID and CTAPHID, page {page}");
        assert_eq!(ccid, hid, "CCID and OTP HID, page {page}");
        let tlvs = &ccid[1..];
        if page == 0 {
            assert_eq!(find_tlv(tlvs, 0x02).unwrap(), SERIAL.to_be_bytes());
            assert_eq!(find_tlv(tlvs, 0x05).unwrap(), vec![5, 7, 4]);
            assert_eq!(find_tlv(tlvs, 0x04).unwrap(), vec![0x04], "USB-C Nano");
            assert_eq!(find_tlv(tlvs, 0x01).unwrap(), ALL_APPS.to_be_bytes());
            assert_eq!(find_tlv(tlvs, 0x03).unwrap(), ALL_APPS.to_be_bytes());
        }
        if find_tlv(tlvs, 0x10) != Some(vec![0x01]) {
            break;
        }
        page += 1;
        assert!(page < 8);
    }
}

/// `docs/DESIGN.md` §5: disabling every CCID application through CTAPHID WRITE CONFIG
/// answers, then emits `Output::Reenumerate` without CCID; CCID messages are ignored
/// from then on, the product ID is the OTP+FIDO one, DeviceInfo shows the new enabled set,
/// and re-enabling through OTP HID slot `0x15` re-enumerates with CCID working again.
#[test]
fn disabling_ccid_reenumerates_and_ignores_ccid_until_reenabled() {
    let mut rig = Rig::new();
    rig.power_on();
    let cid = rig.ctaphid_init();
    let out = rig.ctaphid_send(cid, 0x43, &config(&[(0x03, &NO_CCID_APPS.to_be_bytes())]));
    assert_eq!(responses(&out), vec![(0x43, vec![])]);
    let reply = out.iter().position(|o| matches!(o, Output::FidoReport(_))).unwrap();
    let reenumerate = out.iter().position(|o| matches!(o, Output::Reenumerate(_))).unwrap();
    assert!(reply < reenumerate, "the answer goes out first");
    let without_ccid = UsbInterfaces {
        otp: true,
        fido: true,
        ccid: false,
    };
    assert_eq!(reenumerations(&out), vec![without_ccid]);
    assert_eq!(rig.dev.usb_identity().product_id, rig.profile.usb_product_ids.otp_fido);

    assert!(rig.input(Input::Ccid(&Rig::ccid_message(0x62, 0, [0, 0, 0], &[]))).is_empty(), "CCID ignored");
    assert!(rig.input(Input::CcidControlAbort { slot: 0, seq: 0 }).is_empty());
    let info = info_ctaphid(&mut rig, 0);
    assert_eq!(find_tlv(&info[1..], 0x03).unwrap(), NO_CCID_APPS.to_be_bytes());
    assert_eq!(info, info_otp(&mut rig, 0));

    let mut payload = [0u8; 64];
    let data = config(&[(0x03, &ALL_APPS.to_be_bytes())]);
    payload[..data.len()].copy_from_slice(&data);
    let out = rig.otp_send_frame(slot::YK4_SET_DEVICE_INFO, &payload);
    assert_eq!(
        reenumerations(&out),
        vec![UsbInterfaces {
            otp: true,
            fido: true,
            ccid: true
        }]
    );
    assert_eq!(rig.power_on(), rig.profile.atr);
    assert_eq!(rig.select(AID_MGMT), b"5.7.4\x90\x00".to_vec());
}

/// yubikit `DeviceConfig` REBOOT (`0C`) over CCID WRITE CONFIG: the answer, then
/// `Reenumerate` with the same interfaces, then a power cycle of the volatile state
/// (catalog appendix A `Linux_native`: "unchanged-profile reboot ... persistent
/// credentials retained and old PIN token rejected"): the FIDO token from before is
/// rejected, the CCID slot needs a new IccPowerOn, the Yubico OTP session restarts with a
/// higher usage counter, and every persistent setting stays.
#[test]
fn reboot_flag_power_cycles_volatile_state_only() {
    let mut rig = Rig::new();
    let mut entropy = SeededEntropy::new(5);
    let cid = rig.ctaphid_init();
    let pp = PinProtocol2::from_key_agreement(&rig.cbor(cid, &PinProtocol2::key_agreement_request()), &mut entropy);
    assert_eq!(rig.cbor(cid, &pp.set_pin("1111")), vec![status::OK]);
    let pp = PinProtocol2::from_key_agreement(&rig.cbor(cid, &PinProtocol2::key_agreement_request()), &mut entropy);
    let token = pp.token(&rig.cbor(cid, &pp.token_request("1111", perm::MC, Some("reboot.example"))));
    let key = *b"0123456789abcdef";
    rig.otp_program(slot::CONFIG1, &SlotConfig::yubico_otp(&[1, 2, 3, 4, 5, 6], [9; 6], key), [0; 6]);
    let before = typed(&mut rig, &key);

    rig.power_on();
    rig.select(AID_MGMT);
    let data = config(&[(0x0C, &[])]);
    let mut apdu = vec![0x00, 0x1C, 0x00, 0x00, data.len() as u8];
    apdu.extend_from_slice(&data);
    let (seq, out) = rig.xfr(&apdu);
    assert_eq!(data_block(&out, seq).unwrap(), vec![0x90, 0x00]);
    assert_eq!(
        reenumerations(&out),
        vec![UsbInterfaces {
            otp: true,
            fido: true,
            ccid: true
        }]
    );

    let (_, out) = rig.xfr(&[0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17]);
    assert_eq!(ccid_replies(&out)[0][7] & 0x40, 0x40, "slot inactive until IccPowerOn");
    assert_eq!(rig.ctaphid(cid, CTAPHID_PING, b"x"), (CTAPHID_ERROR, vec![0x0B]), "old channel gone");
    let cid = rig.ctaphid_init();
    let request = ctap::make_credential(&[7; 32], "reboot.example", b"u", true, &PinAuth::Token(token));
    assert_eq!(rig.cbor(cid, &request), vec![status::PIN_AUTH_INVALID], "old token rejected");
    let info = ctap::ok_value(&rig.cbor(cid, &ctap::request(ctap::cmd::GET_INFO, None)));
    assert_eq!(ctap::get(&info, 4).map_get_text("clientPin").and_then(lk_codec::cbor::Value::as_bool), Some(true));
    rig.now += 5_000;
    let after = typed(&mut rig, &key);
    assert_eq!((after.use_counter, after.session_counter), (before.use_counter + 1, 0));
}

/// A short press and the decrypted Yubico OTP it typed.
fn typed(rig: &mut Rig, key: &[u8; 16]) -> otp::Ticket {
    let mut reports = keyboard(&rig.touch_down());
    rig.now += 500;
    reports.extend(keyboard(&rig.touch_up()));
    let text = otp::keyboard_text(&reports);
    otp::decrypt_otp(text.trim_end(), key).1
}
