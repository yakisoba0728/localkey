//! Behaviour tests for the Management application.
//!
//! Vector sources:
//! - Tag numbers, value widths, the length-prefixed READ/WRITE CONFIG format and the
//!   paging rule: yubikit-python `yubikit/management.py` (`TAG`, `DeviceConfig.get_bytes`,
//!   `DeviceInfo.parse_tlvs`, `ManagementSession.read_device_info`).
//! - Capability bits (`OTP 0x01 U2F 0x02 OPENPGP 0x08 PIV 0x10 OATH 0x20 HSMAUTH 0x100
//!   FIDO2 0x200`, all = `0x033B`): yubikit `CAPABILITY`, mirrored by
//!   `lk_core::Capabilities`.
//! - Form factor `0x04` USB-C Nano, firmware 5.7.4: `lk_core::DeviceProfile`
//!   (`reference/yubikey-5c-nano-5.7.4/`, `reference/legacy-v0.64-profiles.json`).
//! - Serial numbers are the test profiles' own (12345678 = `00BC614E`, 31415926 =
//!   `01DF5E76`).
//! - CTAPHID vendor commands `0x42`/`0x43` and OTP slots `0x13`/`0x15`: yubikit
//!   `_ManagementCtapBackend` / `_ManagementOtpBackend`; error codes CTAP 2.1
//!   §11.2.9.1.6.

use lk_codec::apdu::{Command, split_response, sw};
use lk_codec::tlv;
use lk_core::{Capabilities, CardApplet, DeviceProfile, Host, Outcome, Record, ResetKind};
use lk_mgmt::{
    AID, ConfigEffect, Management, MgmtApplet, PAGE_LIMIT, VendorReply, ctaphid, device_flags,
    otp_crc16, tag,
};
use lk_testkit::TestHost;

const LOCK: [u8; 16] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
];
const OTHER_LOCK: [u8; 16] = [0x5A; 16];

/// DeviceInfo of a factory `DeviceProfile::own(12345678)` device.
const OWN_INFO: [u8; 50] = [
    0x01, 0x02, 0x03, 0x3B, // USB supported: all seven applications
    0x02, 0x04, 0x00, 0xBC, 0x61, 0x4E, // serial 12345678
    0x03, 0x02, 0x03, 0x3B, // USB enabled
    0x04, 0x01, 0x04, // form factor USB-C Nano
    0x05, 0x03, 0x05, 0x07, 0x04, // version 5.7.4
    0x06, 0x02, 0x00, 0x00, // auto-eject timeout
    0x07, 0x01, 0x00, // challenge-response timeout
    0x08, 0x01, 0x00, // device flags
    0x0A, 0x01, 0x00, // not locked
    0x14, 0x02, 0x00, 0x00, // FIPS capable: none
    0x15, 0x02, 0x00, 0x00, // FIPS approved: none
    0x16, 0x01, 0x00, // PIN complexity off
    0x18, 0x02, 0x00, 0x00, // reset blocked: none
];

/// DeviceInfo of a factory `DeviceProfile::yubikey_5c_nano_5_7_4(31415926)` device.
const YK_INFO: [u8; 50] = [
    0x01, 0x02, 0x03, 0x3B, //
    0x02, 0x04, 0x01, 0xDF, 0x5E, 0x76, // serial 31415926
    0x03, 0x02, 0x03, 0x3B, //
    0x04, 0x01, 0x04, //
    0x05, 0x03, 0x05, 0x07, 0x04, //
    0x06, 0x02, 0x00, 0x00, //
    0x07, 0x01, 0x00, //
    0x08, 0x01, 0x00, //
    0x0A, 0x01, 0x00, //
    0x14, 0x02, 0x00, 0x00, //
    0x15, 0x02, 0x00, 0x00, //
    0x16, 0x01, 0x00, //
    0x18, 0x02, 0x00, 0x00, //
];

fn applet(host: &mut TestHost) -> MgmtApplet {
    let stored = host.persisted(Record::Device);
    MgmtApplet::new(stored.as_deref(), host)
}

fn run(applet: &mut MgmtApplet, apdu: &[u8], host: &mut TestHost) -> Vec<u8> {
    match applet.process(apdu, host) {
        Outcome::Done(resp) => resp,
        Outcome::NeedTouch { .. } => panic!("management never needs touch"),
    }
}

fn status(resp: &[u8]) -> u16 {
    split_response(resp)
        .map(|(_, s)| s)
        .expect("response has a status word")
}

fn data(resp: &[u8]) -> Vec<u8> {
    split_response(resp)
        .map(|(d, _)| d.to_vec())
        .expect("response has a status word")
}

/// `len || tlvs` as yubikit `DeviceConfig.get_bytes` builds it.
fn config(tlvs: &[u8]) -> Vec<u8> {
    let mut out = vec![u8::try_from(tlvs.len()).expect("config fits")];
    out.extend_from_slice(tlvs);
    out
}

fn write_apdu(tlvs: &[u8]) -> Vec<u8> {
    Command::new(0x00, 0x1C, 0x00, 0x00)
        .with_data(config(tlvs))
        .to_bytes()
}

fn read_apdu(page: u8) -> Vec<u8> {
    Command::new(0x00, 0x1D, page, 0x00).to_bytes()
}

fn tlvs(items: &[(u32, &[u8])]) -> Vec<u8> {
    items.iter().flat_map(|(t, v)| tlv::encode(*t, v)).collect()
}

fn unlock(code: &[u8; 16]) -> Vec<u8> {
    tlv::encode(tag::UNLOCK, code)
}

fn new_lock(code: &[u8; 16]) -> Vec<u8> {
    tlv::encode(tag::CONFIG_LOCK, code)
}

fn info_value(info: &[u8], t: u32) -> Option<Vec<u8>> {
    let items = tlv::parse_all(info).expect("device info parses");
    tlv::find(&items, t).map(|i| i.value.to_vec())
}

// ---------------------------------------------------------------------------
// SELECT and DeviceInfo
// ---------------------------------------------------------------------------

#[test]
fn select_returns_version_string() {
    // yubikit `_ManagementSmartCardBackend`: Version.from_string(SELECT response).
    let mut host = TestHost::new();
    let mut a = applet(&mut host);
    let select = Command::new(0x00, 0xA4, 0x04, 0x00)
        .with_data(AID)
        .to_bytes();
    assert_eq!(a.select(&select, &mut host), b"5.7.4\x90\x00".to_vec());
    assert_eq!(a.aid(), &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17]);
    // A re-SELECT through process answers the same; another AID is not found.
    assert_eq!(run(&mut a, &select, &mut host), b"5.7.4\x90\x00".to_vec());
    let other = Command::new(0x00, 0xA4, 0x04, 0x00)
        .with_data(vec![0xA0, 0x00, 0x00, 0x03, 0x08])
        .to_bytes();
    assert_eq!(status(&run(&mut a, &other, &mut host)), sw::FILE_NOT_FOUND);
}

#[test]
fn device_info_own_profile_matches_expected_bytes() {
    let mut host = TestHost::new();
    let a = applet(&mut host);
    assert_eq!(a.management().device_info(&host), OWN_INFO.to_vec());
}

#[test]
fn device_info_yubikey_profile_matches_expected_bytes() {
    let mut host = TestHost::with_profile(DeviceProfile::yubikey_5c_nano_5_7_4(31_415_926));
    let mut a = applet(&mut host);
    assert_eq!(a.management().device_info(&host), YK_INFO.to_vec());
    let resp = run(&mut a, &read_apdu(0), &mut host);
    let mut want = vec![50u8];
    want.extend_from_slice(&YK_INFO);
    assert_eq!(data(&resp), want);
    assert_eq!(status(&resp), sw::OK);
}

#[test]
fn read_config_is_length_prefixed_device_info() {
    let mut host = TestHost::new();
    let mut a = applet(&mut host);
    // With and without Le, short and extended: the whole page comes back.
    for apdu in [
        read_apdu(0),
        Command::new(0x00, 0x1D, 0x00, 0x00).with_le(0).to_bytes(),
        Command::new(0x00, 0x1D, 0x00, 0x00)
            .with_le(0x10)
            .to_bytes(),
        vec![0x00, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x00],
    ] {
        let resp = run(&mut a, &apdu, &mut host);
        assert_eq!(status(&resp), sw::OK, "{apdu:02x?}");
        let body = data(&resp);
        assert_eq!(body.first().copied(), Some(OWN_INFO.len() as u8));
        assert_eq!(body.get(1..), Some(&OWN_INFO[..]));
    }
}

#[test]
fn device_info_has_no_nfc_tags_and_no_duplicates() {
    // A USB-only device reports no NFC tags (yubikit `DeviceInfo.parse_tlvs` only
    // creates an NFC transport when tag 0x0D is present).
    let mut host = TestHost::new();
    let m = Management::new(None, &mut host);
    let info = m.device_info(&host);
    let items = tlv::parse_all(&info).expect("parses");
    let mut tags: Vec<u32> = items.iter().map(|i| i.tag).collect();
    for t in [
        tag::NFC_SUPPORTED,
        tag::NFC_ENABLED,
        tag::NFC_RESTRICTED,
        tag::IAP_DETECTION,
        tag::MORE_DATA,
    ] {
        assert!(!tags.contains(&t), "tag {t:#04x} must not be reported");
    }
    let n = tags.len();
    tags.sort_unstable();
    tags.dedup();
    assert_eq!(tags.len(), n);
    assert!(info.len() <= PAGE_LIMIT);
}

#[test]
fn read_config_paging_bounds() {
    // The DeviceInfo fits one page: page 0 carries no MORE_DATA; a further page is
    // past the end (model policy 6A86), as is a non-zero P2.
    let mut host = TestHost::new();
    let mut a = applet(&mut host);
    let page0 = data(&run(&mut a, &read_apdu(0), &mut host));
    assert_eq!(
        info_value(page0.get(1..).expect("tlvs"), tag::MORE_DATA),
        None
    );
    assert_eq!(
        status(&run(&mut a, &read_apdu(1), &mut host)),
        sw::INCORRECT_P1P2
    );
    assert_eq!(
        status(&run(&mut a, &read_apdu(0xFF), &mut host)),
        sw::INCORRECT_P1P2
    );
    let p2 = Command::new(0x00, 0x1D, 0x00, 0x01).to_bytes();
    assert_eq!(status(&run(&mut a, &p2, &mut host)), sw::INCORRECT_P1P2);
    assert_eq!(
        a.management().read_config(1, &host),
        Err(sw::INCORRECT_P1P2)
    );
}

// ---------------------------------------------------------------------------
// WRITE CONFIG
// ---------------------------------------------------------------------------

#[test]
fn write_config_round_trips_every_field() {
    let mut host = TestHost::new();
    let mut a = applet(&mut host);
    let enabled = Capabilities::FIDO2 | Capabilities::U2F | Capabilities::PIV;
    // Field order as yubikit `DeviceConfig.get_bytes`: 03, 06, 07, 08.
    let req = tlvs(&[
        (tag::USB_ENABLED, &enabled.to_be_bytes()),
        (tag::AUTO_EJECT_TIMEOUT, &300u16.to_be_bytes()),
        (tag::CHALRESP_TIMEOUT, &[30]),
        (tag::DEVICE_FLAGS, &[device_flags::EJECT]),
    ]);
    assert_eq!(run(&mut a, &write_apdu(&req), &mut host), vec![0x90, 0x00]);
    assert_eq!(a.take_effect(), ConfigEffect::None);

    let page = data(&run(&mut a, &read_apdu(0), &mut host));
    let info = page.get(1..).expect("tlvs").to_vec();
    assert_eq!(info_value(&info, tag::USB_ENABLED), Some(vec![0x02, 0x12]));
    assert_eq!(
        info_value(&info, tag::AUTO_EJECT_TIMEOUT),
        Some(vec![0x01, 0x2C])
    );
    assert_eq!(info_value(&info, tag::CHALRESP_TIMEOUT), Some(vec![30]));
    assert_eq!(info_value(&info, tag::DEVICE_FLAGS), Some(vec![0x80]));
    assert_eq!(
        info_value(&info, tag::USB_SUPPORTED),
        Some(vec![0x03, 0x3B])
    );

    let m = a.management();
    assert_eq!(m.enabled_usb(&host), Capabilities(enabled));
    assert_eq!(m.auto_eject_timeout(), 300);
    assert_eq!(m.challenge_response_timeout(), 30);
    assert_eq!(m.challenge_response_timeout_secs(), 30);
    assert_eq!(m.device_flags(), 0x80);

    // A device rebuilt from the persisted record reports the same.
    let reloaded = applet(&mut host);
    assert_eq!(reloaded.management().device_info(&host), info);
}

#[test]
fn factory_challenge_response_timeout_means_default() {
    let mut host = TestHost::new();
    let m = Management::new(None, &mut host);
    assert_eq!(m.challenge_response_timeout(), 0);
    assert_eq!(
        m.challenge_response_timeout_secs(),
        lk_mgmt::DEFAULT_CHALRESP_TIMEOUT_SECS
    );
}

#[test]
fn reboot_tag_requests_reboot() {
    // yubikit `get_bytes(reboot=True)` puts `0C 00` first.
    let mut host = TestHost::new();
    let mut a = applet(&mut host);
    let req = tlvs(&[
        (tag::REBOOT, &[]),
        (tag::USB_ENABLED, &Capabilities::FIDO2.to_be_bytes()),
    ]);
    assert_eq!(status(&run(&mut a, &write_apdu(&req), &mut host)), sw::OK);
    assert_eq!(a.take_effect(), ConfigEffect::Reboot);
    assert_eq!(a.take_effect(), ConfigEffect::None);
    assert_eq!(
        a.management().enabled_usb(&host),
        Capabilities(Capabilities::FIDO2)
    );

    // Reboot alone ("unchanged-profile reboot"): still a reboot, nothing persisted.
    let before = host.persist_attempts();
    let mut m = a.into_management();
    assert_eq!(
        m.write_config(&config(&[0x0C, 0x00]), &mut host),
        Ok(ConfigEffect::Reboot)
    );
    assert_eq!(host.persist_attempts(), before);
    // The REBOOT value is ignored.
    assert_eq!(
        m.write_config(&config(&[0x0C, 0x01, 0x01]), &mut host),
        Ok(ConfigEffect::Reboot)
    );
}

#[test]
fn reset_drops_a_pending_effect() {
    let mut host = TestHost::new();
    let mut a = applet(&mut host);
    assert_eq!(
        status(&run(&mut a, &write_apdu(&[0x0C, 0x00]), &mut host)),
        sw::OK
    );
    a.reset(ResetKind::UsbReset);
    assert_eq!(a.take_effect(), ConfigEffect::None);
}

#[test]
fn unchanged_values_are_not_persisted() {
    let mut host = TestHost::new();
    let mut m = Management::new(None, &mut host);
    let req = tlvs(&[
        (tag::USB_ENABLED, &[0x03, 0x3B]),
        (tag::AUTO_EJECT_TIMEOUT, &[0, 0]),
    ]);
    assert_eq!(
        m.write_config(&config(&req), &mut host),
        Ok(ConfigEffect::None)
    );
    assert_eq!(host.persist_attempts(), 0);
    assert_eq!(
        m.write_config(&config(&[]), &mut host),
        Ok(ConfigEffect::None)
    );
    assert_eq!(host.persist_attempts(), 0);
}

#[test]
fn write_config_rejects_malformed_framing() {
    let mut host = TestHost::new();
    let mut a = applet(&mut host);
    // No data at all.
    assert_eq!(
        status(&run(&mut a, &[0x00, 0x1C, 0x00, 0x00], &mut host)),
        sw::WRONG_LENGTH
    );
    // Length byte does not match the TLV bytes.
    let bad_len = Command::new(0x00, 0x1C, 0x00, 0x00)
        .with_data(vec![0x05, 0x0C, 0x00])
        .to_bytes();
    assert_eq!(
        status(&run(&mut a, &bad_len, &mut host)),
        sw::INCORRECT_DATA
    );
    let short_len = Command::new(0x00, 0x1C, 0x00, 0x00)
        .with_data(vec![0x01, 0x0C, 0x00])
        .to_bytes();
    assert_eq!(
        status(&run(&mut a, &short_len, &mut host)),
        sw::INCORRECT_DATA
    );
    // Truncated TLV.
    assert_eq!(
        status(&run(&mut a, &write_apdu(&[0x03, 0x02, 0x02]), &mut host)),
        sw::INCORRECT_DATA
    );
    // P1/P2 must be zero.
    let p1 = Command::new(0x00, 0x1C, 0x01, 0x00)
        .with_data(config(&[0x0C, 0x00]))
        .to_bytes();
    assert_eq!(status(&run(&mut a, &p1, &mut host)), sw::INCORRECT_P1P2);
    assert_eq!(a.take_effect(), ConfigEffect::None);
    assert_eq!(host.persist_attempts(), 0);
    assert_eq!(a.management().device_info(&host), OWN_INFO.to_vec());
}

#[test]
fn write_config_rejects_read_only_unknown_and_nfc_tags() {
    let mut host = TestHost::new();
    let mut m = Management::new(None, &mut host);
    for (t, v) in [
        (tag::USB_SUPPORTED, vec![0x03, 0x3B]),
        (tag::SERIAL, vec![0, 0, 0, 1]),
        (tag::FORM_FACTOR, vec![0x01]),
        (tag::VERSION, vec![5, 8, 0]),
        (tag::NFC_SUPPORTED, vec![0x03, 0x3B]),
        (tag::NFC_ENABLED, vec![0x03, 0x3B]),
        (tag::NFC_RESTRICTED, vec![0x01]),
        (tag::MORE_DATA, vec![0x01]),
        (tag::RESET_BLOCKED, vec![0x00, 0x00]),
        (0x7F, vec![]),
    ] {
        let req = tlv::encode(t, &v);
        assert_eq!(
            m.write_config(&config(&req), &mut host),
            Err(sw::INCORRECT_DATA),
            "tag {t:#x}"
        );
    }
    assert_eq!(host.persist_attempts(), 0);
    assert_eq!(m.device_info(&host), OWN_INFO.to_vec());
}

#[test]
fn write_config_rejects_repeated_tags_and_wrong_widths() {
    let mut host = TestHost::new();
    let mut m = Management::new(None, &mut host);
    let cases: Vec<Vec<u8>> = vec![
        tlvs(&[(tag::REBOOT, &[]), (tag::REBOOT, &[])]),
        tlvs(&[(tag::CHALRESP_TIMEOUT, &[1]), (tag::CHALRESP_TIMEOUT, &[2])]),
        tlvs(&[(tag::USB_ENABLED, &[0x02])]),
        tlvs(&[(tag::USB_ENABLED, &[0x00, 0x02, 0x00])]),
        tlvs(&[(tag::AUTO_EJECT_TIMEOUT, &[0x05])]),
        tlvs(&[(tag::CHALRESP_TIMEOUT, &[0x00, 0x05])]),
        tlvs(&[(tag::CHALRESP_TIMEOUT, &[])]),
        tlvs(&[(tag::DEVICE_FLAGS, &[0x00, 0x80])]),
        tlvs(&[(tag::CONFIG_LOCK, &[0x11; 15])]),
        tlvs(&[(tag::CONFIG_LOCK, &[0x11; 17])]),
    ];
    for req in cases {
        assert_eq!(
            m.write_config(&config(&req), &mut host),
            Err(sw::INCORRECT_DATA),
            "{req:02x?}"
        );
    }
    assert_eq!(host.persist_attempts(), 0);
    assert!(!m.is_locked());
}

#[test]
fn device_flags_accept_only_documented_bits() {
    // yubikit `DEVICE_FLAG`: REMOTE_WAKEUP 0x40, EJECT 0x80.
    let mut host = TestHost::new();
    let mut m = Management::new(None, &mut host);
    for bad in [0x01u8, 0x20, 0x3F, 0xC1] {
        let req = tlv::encode(tag::DEVICE_FLAGS, &[bad]);
        assert_eq!(
            m.write_config(&config(&req), &mut host),
            Err(sw::INCORRECT_DATA)
        );
    }
    let req = tlv::encode(tag::DEVICE_FLAGS, &[0xC0]);
    assert_eq!(
        m.write_config(&config(&req), &mut host),
        Ok(ConfigEffect::None)
    );
    assert_eq!(
        m.device_flags(),
        device_flags::REMOTE_WAKEUP | device_flags::EJECT
    );
}

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

#[test]
fn disabling_every_application_is_rejected() {
    let mut host = TestHost::new();
    let mut m = Management::new(None, &mut host);
    let req = tlv::encode(tag::USB_ENABLED, &[0x00, 0x00]);
    assert_eq!(
        m.write_config(&config(&req), &mut host),
        Err(sw::INCORRECT_DATA)
    );
    assert_eq!(m.enabled_usb(&host), Capabilities::ALL);
}

#[test]
fn enabling_undefined_capability_bits_is_rejected() {
    let mut host = TestHost::new();
    let mut m = Management::new(None, &mut host);
    for bits in [
        0x0004u16,
        0x0040,
        0x0080,
        0x0400,
        0x8000,
        0x033B | 0x0004,
        0xFFFF,
    ] {
        let req = tlv::encode(tag::USB_ENABLED, &bits.to_be_bytes());
        assert_eq!(
            m.write_config(&config(&req), &mut host),
            Err(sw::INCORRECT_DATA),
            "{bits:#06x}"
        );
    }
    assert_eq!(host.persist_attempts(), 0);
}

#[test]
fn enabling_unsupported_capability_is_rejected() {
    let mut profile = DeviceProfile::own(7);
    profile.supported_usb =
        Capabilities(Capabilities::OTP | Capabilities::U2F | Capabilities::FIDO2);
    profile.default_enabled_usb = profile.supported_usb;
    let mut host = TestHost::with_profile(profile);
    let mut m = Management::new(None, &mut host);
    assert_eq!(
        info_value(&m.device_info(&host), tag::USB_SUPPORTED),
        Some(vec![0x02, 0x03])
    );
    let req = tlv::encode(
        tag::USB_ENABLED,
        &(Capabilities::FIDO2 | Capabilities::PIV).to_be_bytes(),
    );
    assert_eq!(
        m.write_config(&config(&req), &mut host),
        Err(sw::INCORRECT_DATA)
    );
    let req = tlv::encode(tag::USB_ENABLED, &Capabilities::FIDO2.to_be_bytes());
    assert_eq!(
        m.write_config(&config(&req), &mut host),
        Ok(ConfigEffect::None)
    );
    assert_eq!(m.enabled_usb(&host), Capabilities(Capabilities::FIDO2));
}

#[test]
fn fido_and_ccid_applications_enable_and_disable() {
    let mut host = TestHost::with_profile(DeviceProfile::yubikey_5c_nano_5_7_4(1));
    let mut m = Management::new(None, &mut host);
    let pids = host.profile().usb_product_ids;

    // FIDO only (U2F + FIDO2): no CCID, no OTP interface.
    let fido = Capabilities::U2F | Capabilities::FIDO2;
    let req = tlvs(&[(tag::REBOOT, &[]), (tag::USB_ENABLED, &fido.to_be_bytes())]);
    assert_eq!(
        m.write_config(&config(&req), &mut host),
        Ok(ConfigEffect::Reboot)
    );
    let ifaces = m.enabled_usb(&host).interfaces();
    assert!(ifaces.fido && !ifaces.ccid && !ifaces.otp);
    assert_eq!(pids.for_interfaces(ifaces), Some(0x0402));

    // CCID applications only.
    let ccid =
        Capabilities::OPENPGP | Capabilities::PIV | Capabilities::OATH | Capabilities::HSMAUTH;
    let req = tlvs(&[(tag::REBOOT, &[]), (tag::USB_ENABLED, &ccid.to_be_bytes())]);
    assert_eq!(
        m.write_config(&config(&req), &mut host),
        Ok(ConfigEffect::Reboot)
    );
    let ifaces = m.enabled_usb(&host).interfaces();
    assert!(!ifaces.fido && ifaces.ccid && !ifaces.otp);
    assert_eq!(pids.for_interfaces(ifaces), Some(0x0404));

    // FIDO + CCID, as on the measured reference key (pid 0x0406).
    let both = fido | ccid;
    let req = tlvs(&[(tag::USB_ENABLED, &both.to_be_bytes())]);
    assert_eq!(
        m.write_config(&config(&req), &mut host),
        Ok(ConfigEffect::None)
    );
    assert_eq!(
        pids.for_interfaces(m.enabled_usb(&host).interfaces()),
        Some(0x0406)
    );
}

#[test]
fn enabled_usb_is_limited_to_the_supported_set() {
    // A record written under a larger profile cannot report unsupported applications.
    let mut host = TestHost::new();
    let mut m = Management::new(None, &mut host);
    let req = tlv::encode(
        tag::USB_ENABLED,
        &(Capabilities::PIV | Capabilities::FIDO2).to_be_bytes(),
    );
    assert_eq!(
        m.write_config(&config(&req), &mut host),
        Ok(ConfigEffect::None)
    );
    host.profile_mut().supported_usb = Capabilities(Capabilities::FIDO2 | Capabilities::U2F);
    let reloaded = Management::new(host.persisted(Record::Device).as_deref(), &mut host);
    assert_eq!(
        reloaded.enabled_usb(&host),
        Capabilities(Capabilities::FIDO2)
    );
    // Nothing left: fall back to the profile default within the supported set.
    host.profile_mut().supported_usb = Capabilities(Capabilities::OTP);
    assert_eq!(reloaded.enabled_usb(&host), Capabilities(Capabilities::OTP));
}

// ---------------------------------------------------------------------------
// Configuration lock
// ---------------------------------------------------------------------------

#[test]
fn lock_code_protects_configuration() {
    let mut host = TestHost::new();
    let mut a = applet(&mut host);
    // ykman `config set-lock-code`: write_device_config(None, False, None, new_code).
    assert_eq!(
        status(&run(&mut a, &write_apdu(&new_lock(&LOCK)), &mut host)),
        sw::OK
    );
    assert!(a.management().is_locked());
    let info = a.management().device_info(&host);
    assert_eq!(info_value(&info, tag::CONFIG_LOCK), Some(vec![0x01]));

    let change = tlv::encode(tag::USB_ENABLED, &Capabilities::FIDO2.to_be_bytes());
    // No lock code, wrong lock code, truncated lock code.
    assert_eq!(
        status(&run(&mut a, &write_apdu(&change), &mut host)),
        sw::SECURITY_STATUS
    );
    let wrong = [unlock(&OTHER_LOCK), change.clone()].concat();
    assert_eq!(
        status(&run(&mut a, &write_apdu(&wrong), &mut host)),
        sw::SECURITY_STATUS
    );
    let short = [tlv::encode(tag::UNLOCK, &LOCK[..15]), change.clone()].concat();
    assert_eq!(
        status(&run(&mut a, &write_apdu(&short), &mut host)),
        sw::SECURITY_STATUS
    );
    assert_eq!(a.management().enabled_usb(&host), Capabilities::ALL);

    // The right code (yubikit puts 0B before the fields).
    let right = [unlock(&LOCK), change.clone()].concat();
    assert_eq!(status(&run(&mut a, &write_apdu(&right), &mut host)), sw::OK);
    assert_eq!(
        a.management().enabled_usb(&host),
        Capabilities(Capabilities::FIDO2)
    );
    assert!(a.management().is_locked());

    // Changing the code needs the current one; afterwards only the new one works.
    let rekey = [unlock(&LOCK), new_lock(&OTHER_LOCK)].concat();
    assert_eq!(status(&run(&mut a, &write_apdu(&rekey), &mut host)), sw::OK);
    assert_eq!(
        status(&run(&mut a, &write_apdu(&right), &mut host)),
        sw::SECURITY_STATUS
    );

    // ykman `set-lock-code --clear`: the all-zero code removes the lock.
    let clear = [unlock(&OTHER_LOCK), new_lock(&[0; 16])].concat();
    assert_eq!(status(&run(&mut a, &write_apdu(&clear), &mut host)), sw::OK);
    assert!(!a.management().is_locked());
    assert_eq!(
        status(&run(&mut a, &write_apdu(&change), &mut host)),
        sw::OK
    );
    let info = a.management().device_info(&host);
    assert_eq!(info_value(&info, tag::CONFIG_LOCK), Some(vec![0x00]));
}

#[test]
fn lock_is_checked_before_values_and_covers_reboot() {
    let mut host = TestHost::new();
    let mut m = Management::new(None, &mut host);
    assert_eq!(
        m.write_config(&config(&new_lock(&LOCK)), &mut host),
        Ok(ConfigEffect::None)
    );
    // An invalid value without the code reports the lock, not the value.
    let invalid = tlv::encode(tag::USB_ENABLED, &[0x00, 0x00]);
    assert_eq!(
        m.write_config(&config(&invalid), &mut host),
        Err(sw::SECURITY_STATUS)
    );
    // With the code, the value check applies.
    let with_code = [unlock(&LOCK), invalid].concat();
    assert_eq!(
        m.write_config(&config(&with_code), &mut host),
        Err(sw::INCORRECT_DATA)
    );
    // Reboot alone and an empty write also need the code (model policy).
    assert_eq!(
        m.write_config(&config(&[0x0C, 0x00]), &mut host),
        Err(sw::SECURITY_STATUS)
    );
    assert_eq!(
        m.write_config(&config(&[]), &mut host),
        Err(sw::SECURITY_STATUS)
    );
    let reboot = [unlock(&LOCK), vec![0x0C, 0x00]].concat();
    assert_eq!(
        m.write_config(&config(&reboot), &mut host),
        Ok(ConfigEffect::Reboot)
    );
}

#[test]
fn unlock_tag_while_unlocked_must_be_the_zero_code() {
    let mut host = TestHost::new();
    let mut m = Management::new(None, &mut host);
    let req = [unlock(&LOCK), vec![0x0C, 0x00]].concat();
    assert_eq!(
        m.write_config(&config(&req), &mut host),
        Err(sw::SECURITY_STATUS)
    );
    let req = [unlock(&[0; 16]), vec![0x0C, 0x00]].concat();
    assert_eq!(
        m.write_config(&config(&req), &mut host),
        Ok(ConfigEffect::Reboot)
    );
}

#[test]
fn lock_survives_reload() {
    let mut host = TestHost::new();
    let mut m = Management::new(None, &mut host);
    assert_eq!(
        m.write_config(&config(&new_lock(&LOCK)), &mut host),
        Ok(ConfigEffect::None)
    );
    let mut reloaded = Management::new(host.persisted(Record::Device).as_deref(), &mut host);
    assert!(reloaded.is_locked());
    let change = tlv::encode(tag::CHALRESP_TIMEOUT, &[9]);
    assert_eq!(
        reloaded.write_config(&config(&change), &mut host),
        Err(sw::SECURITY_STATUS)
    );
    let ok = [unlock(&LOCK), change].concat();
    assert_eq!(
        reloaded.write_config(&config(&ok), &mut host),
        Ok(ConfigEffect::None)
    );
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

#[test]
fn persisted_record_format() {
    let mut host = TestHost::new();
    let mut m = Management::new(None, &mut host);
    let req = tlvs(&[
        (tag::USB_ENABLED, &[0x02, 0x03]),
        (tag::AUTO_EJECT_TIMEOUT, &[0x00, 0x0A]),
        (tag::CHALRESP_TIMEOUT, &[0x0F]),
        (tag::DEVICE_FLAGS, &[0x40]),
        (tag::CONFIG_LOCK, &LOCK),
    ]);
    assert_eq!(
        m.write_config(&config(&req), &mut host),
        Ok(ConfigEffect::None)
    );
    let mut want = vec![
        0x01, 0x01, 0x02, 0x02, 0x03, 0x02, 0x02, 0x00, 0x0A, 0x03, 0x01, 0x0F, 0x04, 0x01, 0x40,
    ];
    want.extend_from_slice(&[0x05, 0x10]);
    want.extend_from_slice(&LOCK);
    assert_eq!(host.persisted(Record::Device), Some(want.clone()));
    assert_eq!(m.to_record(), want);
    assert_eq!(host.persist_count(), 1);
}

#[test]
fn state_is_persisted_before_success() {
    let mut host = TestHost::new();
    let mut a = applet(&mut host);
    let req = tlv::encode(tag::AUTO_EJECT_TIMEOUT, &[0x01, 0x00]);
    assert_eq!(status(&run(&mut a, &write_apdu(&req), &mut host)), sw::OK);
    assert_eq!(host.persist_count(), 1);
    let stored = host.persisted(Record::Device).expect("persisted");
    assert_eq!(
        Management::new(Some(&stored), &mut host).auto_eject_timeout(),
        256
    );
}

#[test]
fn storage_failure_keeps_previous_state() {
    let mut host = TestHost::new();
    let mut a = applet(&mut host);
    let first = tlv::encode(tag::CHALRESP_TIMEOUT, &[20]);
    assert_eq!(status(&run(&mut a, &write_apdu(&first), &mut host)), sw::OK);
    let stored_before = host.persisted(Record::Device);
    let info_before = a.management().device_info(&host);

    host.fail_next_saves(1);
    let change = tlvs(&[
        (tag::REBOOT, &[]),
        (tag::USB_ENABLED, &Capabilities::FIDO2.to_be_bytes()),
        (tag::CONFIG_LOCK, &LOCK),
    ]);
    assert_eq!(
        status(&run(&mut a, &write_apdu(&change), &mut host)),
        sw::MEMORY_FAILURE
    );
    // No reboot, no lock, nothing new in memory or in the store.
    assert_eq!(a.take_effect(), ConfigEffect::None);
    assert!(!a.management().is_locked());
    assert_eq!(a.management().device_info(&host), info_before);
    assert_eq!(host.persisted(Record::Device), stored_before);

    // The next attempt succeeds normally.
    assert_eq!(
        status(&run(&mut a, &write_apdu(&change), &mut host)),
        sw::OK
    );
    assert_eq!(a.take_effect(), ConfigEffect::Reboot);
    assert!(a.management().is_locked());
}

#[test]
fn storage_failure_while_clearing_lock_keeps_lock() {
    let mut host = TestHost::new();
    let mut m = Management::new(None, &mut host);
    assert_eq!(
        m.write_config(&config(&new_lock(&LOCK)), &mut host),
        Ok(ConfigEffect::None)
    );
    host.fail_all(true);
    let clear = [unlock(&LOCK), new_lock(&[0; 16])].concat();
    assert_eq!(
        m.write_config(&config(&clear), &mut host),
        Err(sw::MEMORY_FAILURE)
    );
    assert!(m.is_locked());
    host.fail_all(false);
    let reloaded = Management::new(host.persisted(Record::Device).as_deref(), &mut host);
    assert!(reloaded.is_locked());
}

#[test]
fn unreadable_record_is_factory_state() {
    let mut host = TestHost::new();
    host.set_persisted(Record::Device, &[0x02, 0x01, 0x02, 0x02, 0x00]);
    let a = applet(&mut host);
    assert_eq!(a.management().device_info(&host), OWN_INFO.to_vec());
    host.set_persisted(Record::Device, &[0x01, 0x05, 0x03, 0x01, 0x02, 0x03]);
    let a = applet(&mut host);
    assert_eq!(a.management().device_info(&host), OWN_INFO.to_vec());
}

// ---------------------------------------------------------------------------
// CTAPHID vendor commands and OTP HID slots
// ---------------------------------------------------------------------------

#[test]
fn ctaphid_read_config() {
    let mut host = TestHost::new();
    let mut m = Management::new(None, &mut host);
    let mut want = vec![50u8];
    want.extend_from_slice(&OWN_INFO);
    // Older yubikit sends no payload, newer sends the page byte.
    for payload in [&[][..], &[0x00][..]] {
        let reply = m
            .ctaphid_vendor(ctaphid::READ_CONFIG, payload, &mut host)
            .expect("mgmt command");
        assert_eq!(
            reply,
            VendorReply {
                cmd: 0x42,
                payload: want.clone(),
                effect: ConfigEffect::None
            }
        );
    }
    // Initialization-packet form of the command byte.
    let reply = m
        .ctaphid_vendor(0xC2, &[], &mut host)
        .expect("mgmt command");
    assert_eq!(reply.cmd, 0x42);
    // Past the last page / too long a payload.
    let reply = m
        .ctaphid_vendor(0x42, &[0x01], &mut host)
        .expect("mgmt command");
    assert_eq!(
        (reply.cmd, reply.payload),
        (ctaphid::ERROR, vec![ctaphid::ERR_INVALID_PAR])
    );
    let reply = m
        .ctaphid_vendor(0x42, &[0x00, 0x00], &mut host)
        .expect("mgmt command");
    assert_eq!(
        (reply.cmd, reply.payload),
        (ctaphid::ERROR, vec![ctaphid::ERR_INVALID_LEN])
    );
}

#[test]
fn ctaphid_write_config() {
    let mut host = TestHost::new();
    let mut m = Management::new(None, &mut host);
    let req = config(&tlvs(&[
        (tag::REBOOT, &[]),
        (tag::USB_ENABLED, &[0x02, 0x02]),
    ]));
    let reply = m
        .ctaphid_vendor(0xC3, &req, &mut host)
        .expect("mgmt command");
    assert_eq!(
        reply,
        VendorReply {
            cmd: 0x43,
            payload: vec![],
            effect: ConfigEffect::Reboot
        }
    );
    assert_eq!(m.enabled_usb(&host), Capabilities(0x0202));

    // Errors: invalid value, wrong length byte, missing data, lock, storage.
    let bad = config(&tlv::encode(tag::USB_ENABLED, &[0, 0]));
    let reply = m
        .ctaphid_vendor(0x43, &bad, &mut host)
        .expect("mgmt command");
    assert_eq!(
        (reply.cmd, reply.payload, reply.effect),
        (0x3F, vec![0x02], ConfigEffect::None)
    );
    let reply = m
        .ctaphid_vendor(0x43, &[0x07, 0x0C, 0x00], &mut host)
        .expect("mgmt command");
    assert_eq!(reply.payload, vec![0x02]);
    let reply = m
        .ctaphid_vendor(0x43, &[], &mut host)
        .expect("mgmt command");
    assert_eq!(reply.payload, vec![0x03]);
    host.fail_next_saves(1);
    let reply = m
        .ctaphid_vendor(0x43, &config(&new_lock(&LOCK)), &mut host)
        .expect("mgmt command");
    assert_eq!(reply.payload, vec![0x7F]);
    assert!(!m.is_locked());
    let reply = m
        .ctaphid_vendor(0x43, &config(&new_lock(&LOCK)), &mut host)
        .expect("mgmt command");
    assert_eq!(reply.cmd, 0x43);
    let reply = m
        .ctaphid_vendor(0x43, &config(&[0x0C, 0x00]), &mut host)
        .expect("mgmt command");
    assert_eq!(
        (reply.cmd, reply.payload, reply.effect),
        (0x3F, vec![0x7F], ConfigEffect::None)
    );
}

#[test]
fn ctaphid_other_vendor_commands_are_not_management() {
    let mut host = TestHost::new();
    let mut m = Management::new(None, &mut host);
    for cmd in [ctaphid::DEVICE_CONFIG, 0x41, 0x44, 0x7F, 0x10, 0x03] {
        assert_eq!(m.ctaphid_vendor(cmd, &[], &mut host), None, "{cmd:#x}");
    }
}

#[test]
fn otp_read_config_with_crc_frame() {
    let mut host = TestHost::new();
    let m = Management::new(None, &mut host);
    // yubikit `_ManagementOtpBackend.read_config`: payload int2bytes(page) padded to
    // the 64-byte slot data; response checked with check_crc over len + 3 bytes.
    let slot_data = [0u8; 64];
    let plain = m.otp_read_config(&slot_data, &host).expect("page 0");
    assert_eq!(plain.first().copied(), Some(50));
    assert_eq!(plain.get(1..), Some(&OWN_INFO[..]));
    assert_eq!(m.otp_read_config(&[], &host), Ok(plain.clone()));
    let frame = m.otp_read_config_frame(&slot_data, &host).expect("page 0");
    let r_len = usize::from(*frame.first().expect("len"));
    assert_eq!(frame.len(), r_len + 3);
    assert_eq!(otp_crc16(&frame), 0xF0B8);
    assert_eq!(frame.get(..r_len + 1), Some(&plain[..]));
    let mut page1 = [0u8; 64];
    page1[0] = 1;
    assert_eq!(m.otp_read_config(&page1, &host), Err(sw::INCORRECT_P1P2));
}

#[test]
fn otp_write_config_from_padded_slot_data() {
    let mut host = TestHost::new();
    let mut m = Management::new(None, &mut host);
    let req = config(&tlvs(&[
        (tag::USB_ENABLED, &[0x00, 0x01]),
        (tag::REBOOT, &[]),
    ]));
    let mut slot_data = [0u8; 64];
    slot_data[..req.len()].copy_from_slice(&req);
    assert_eq!(
        m.otp_write_config(&slot_data, &mut host),
        Ok(ConfigEffect::Reboot)
    );
    assert_eq!(m.enabled_usb(&host), Capabilities(Capabilities::OTP));
    // A length byte beyond the slot data, and empty data.
    let mut bad = [0u8; 64];
    bad[0] = 64;
    assert_eq!(m.otp_write_config(&bad, &mut host), Err(sw::INCORRECT_DATA));
    assert_eq!(m.otp_write_config(&[], &mut host), Err(sw::WRONG_LENGTH));
    // The OTP serial slot.
    assert_eq!(m.serial_bytes(&host), [0x00, 0xBC, 0x61, 0x4E]);
    assert_eq!(m.serial(&host), 12_345_678);
}

#[test]
fn configuration_is_shared_across_transports() {
    let mut host = TestHost::new();
    let mut a = applet(&mut host);
    // Written over CTAPHID ...
    let req = config(&tlv::encode(tag::AUTO_EJECT_TIMEOUT, &[0x00, 0x3C]));
    let reply = a
        .management_mut()
        .ctaphid_vendor(0x43, &req, &mut host)
        .expect("mgmt command");
    assert_eq!(reply.cmd, 0x43);
    // ... seen over CCID and OTP HID.
    let page = data(&run(&mut a, &read_apdu(0), &mut host));
    assert_eq!(
        info_value(page.get(1..).expect("tlvs"), tag::AUTO_EJECT_TIMEOUT),
        Some(vec![0x00, 0x3C])
    );
    let otp = a.management().otp_read_config(&[0], &host).expect("page 0");
    assert_eq!(otp, page);
    // Written over OTP HID, seen over CTAPHID.
    let mut slot = [0u8; 64];
    let req = config(&tlv::encode(tag::CHALRESP_TIMEOUT, &[0x2D]));
    slot[..req.len()].copy_from_slice(&req);
    assert_eq!(
        a.management_mut().otp_write_config(&slot, &mut host),
        Ok(ConfigEffect::None)
    );
    let reply = a
        .management_mut()
        .ctaphid_vendor(0x42, &[], &mut host)
        .expect("mgmt command");
    assert_eq!(
        info_value(reply.payload.get(1..).expect("tlvs"), tag::CHALRESP_TIMEOUT),
        Some(vec![0x2D])
    );
    // The serial in DeviceInfo is the profile's, the same one the OTP slot reports.
    assert_eq!(
        info_value(reply.payload.get(1..).expect("tlvs"), tag::SERIAL),
        Some(a.management().serial_bytes(&host).to_vec())
    );
}

// ---------------------------------------------------------------------------
// APDU handling
// ---------------------------------------------------------------------------

#[test]
fn apdu_header_errors() {
    let mut host = TestHost::new();
    let mut a = applet(&mut host);
    assert_eq!(
        status(&run(&mut a, &[0x00, 0x1D], &mut host)),
        sw::WRONG_LENGTH
    );
    assert_eq!(
        status(&run(
            &mut a,
            &[0x00, 0x1D, 0x00, 0x00, 0x05, 0x01],
            &mut host
        )),
        sw::WRONG_LENGTH
    );
    for cla in [0x80u8, 0x84, 0x0C, 0x01, 0x40, 0xFF] {
        assert_eq!(
            status(&run(&mut a, &[cla, 0x1D, 0x00, 0x00], &mut host)),
            sw::CLA_NOT_SUPPORTED,
            "{cla:#x}"
        );
    }
    for ins in [0x16u8, 0x1F, 0x00, 0xC0, 0xCA, 0x01] {
        assert_eq!(
            status(&run(&mut a, &[0x00, ins, 0x00, 0x00], &mut host)),
            sw::INS_NOT_SUPPORTED,
            "{ins:#x}"
        );
    }
    assert_eq!(a.touch_resolved(true, &mut host), vec![0x69, 0x85]);
}

#[test]
fn write_config_with_command_chaining() {
    // ISO/IEC 7816-4 §5.1.1.1: a 256-byte WRITE CONFIG needs chaining in short APDUs.
    let mut host = TestHost::new();
    let mut a = applet(&mut host);
    let req = config(&tlvs(&[
        (tag::CHALRESP_TIMEOUT, &[7]),
        (tag::DEVICE_FLAGS, &[0x40]),
    ]));
    let (head, tail) = req.split_at(3);
    let first = Command::new(0x10, 0x1C, 0x00, 0x00)
        .with_data(head)
        .to_bytes();
    let last = Command::new(0x00, 0x1C, 0x00, 0x00)
        .with_data(tail)
        .to_bytes();
    assert_eq!(status(&run(&mut a, &first, &mut host)), sw::OK);
    assert_eq!(host.persist_attempts(), 0);
    assert_eq!(status(&run(&mut a, &last, &mut host)), sw::OK);
    assert_eq!(a.management().challenge_response_timeout(), 7);
    assert_eq!(a.management().device_flags(), 0x40);

    // A header change mid-chain drops the chain (6883).
    assert_eq!(status(&run(&mut a, &first, &mut host)), sw::OK);
    assert_eq!(
        status(&run(&mut a, &read_apdu(0), &mut host)),
        sw::LAST_COMMAND_EXPECTED
    );
    assert_eq!(status(&run(&mut a, &read_apdu(0), &mut host)), sw::OK);

    // Deselect and reset drop an unfinished chain: the tail alone is malformed.
    for drop_chain in [0u8, 1] {
        assert_eq!(status(&run(&mut a, &first, &mut host)), sw::OK);
        if drop_chain == 0 {
            a.deselect();
        } else {
            a.reset(ResetKind::CardPowerOff);
        }
        assert_eq!(status(&run(&mut a, &last, &mut host)), sw::INCORRECT_DATA);
    }

    // A maximal 256-byte WRITE CONFIG (length byte + 255 TLV bytes) fits the chain.
    let filler = tlv::encode(tag::REBOOT, &[0u8; 252]);
    let big = config(&filler);
    assert_eq!(big.len(), 256);
    let (h, t) = big.split_at(200);
    assert_eq!(
        status(&run(
            &mut a,
            &Command::new(0x10, 0x1C, 0, 0).with_data(h).to_bytes(),
            &mut host
        )),
        sw::OK
    );
    assert_eq!(
        status(&run(
            &mut a,
            &Command::new(0x00, 0x1C, 0, 0).with_data(t).to_bytes(),
            &mut host
        )),
        sw::OK
    );
    assert_eq!(a.take_effect(), ConfigEffect::Reboot);
    // One byte more is too long.
    let (h, _) = big.split_at(200);
    assert_eq!(
        status(&run(
            &mut a,
            &Command::new(0x10, 0x1C, 0, 0).with_data(h).to_bytes(),
            &mut host
        )),
        sw::OK
    );
    let t57 = vec![0u8; 57];
    assert_eq!(
        status(&run(
            &mut a,
            &Command::new(0x00, 0x1C, 0, 0).with_data(t57).to_bytes(),
            &mut host
        )),
        sw::WRONG_LENGTH
    );
}

#[test]
fn debug_output_hides_lock_codes() {
    // A lock code in an unfinished chain or in the state never appears in Debug.
    let mut host = TestHost::new();
    let mut a = applet(&mut host);
    let req = config(&[unlock(&[0xC7; 16]), new_lock(&[0xC7; 16])].concat());
    let first = Command::new(0x10, 0x1C, 0x00, 0x00)
        .with_data(req.get(..20).expect("head"))
        .to_bytes();
    assert_eq!(status(&run(&mut a, &first, &mut host)), sw::OK);
    let text = format!("{a:?}").to_lowercase();
    assert!(text.contains("chain_active: true"));
    assert!(!text.contains("199") && !text.contains("c7"), "{text}");
}

#[test]
fn extended_apdu_write_config() {
    let mut host = TestHost::new();
    let mut a = applet(&mut host);
    let req = config(&tlv::encode(tag::CHALRESP_TIMEOUT, &[3]));
    let mut cmd = Command::new(0x00, 0x1C, 0x00, 0x00).with_data(req);
    cmd.extended = true;
    assert_eq!(status(&run(&mut a, &cmd.to_bytes(), &mut host)), sw::OK);
    assert_eq!(a.management().challenge_response_timeout(), 3);
}

// ---------------------------------------------------------------------------
// Review hardening: byte-exact yubikit requests, framing and lock edge cases
// ---------------------------------------------------------------------------

/// yubikit-python `yubikit/management.py` `DeviceConfig.get_bytes(reboot,
/// cur_lock_code, new_lock_code)` emits, in this order: `0C 00` if reboot, `0B 10
/// <cur>` if given, `03 02 <usb>`, `0E 02 <nfc>`, `06 02 <eject>`, `07 01 <chalresp>`,
/// `08 01 <flags>`, `0A 10 <new>` if given, `17 01 <nfc restricted>`, all prefixed by
/// one length byte (`int2bytes(len(buf))`). `ykman config set-lock-code --clear`
/// sends `CLEAR_LOCK_CODE = b"\0" * 16` as the new code.
#[test]
fn yubikit_get_bytes_requests_are_accepted_byte_exact() {
    let mut host = TestHost::new();
    let mut a = applet(&mut host);

    // DeviceConfig({USB: 0x033A}).get_bytes(reboot=True): disable OTP and reboot.
    let apdu = [
        0x00, 0x1C, 0x00, 0x00, 0x07, 0x06, 0x0C, 0x00, 0x03, 0x02, 0x03, 0x3A,
    ];
    assert_eq!(run(&mut a, &apdu, &mut host), vec![0x90, 0x00]);
    assert_eq!(a.take_effect(), ConfigEffect::Reboot);
    assert_eq!(a.management().enabled_usb(&host), Capabilities(0x033A));
    assert!(!a.management().enabled_usb(&host).interfaces().otp);

    // DeviceConfig({}).get_bytes(False, None, new): set a lock code.
    let mut apdu = vec![0x00, 0x1C, 0x00, 0x00, 0x13, 0x12, 0x0A, 0x10];
    apdu.extend_from_slice(&LOCK);
    assert_eq!(run(&mut a, &apdu, &mut host), vec![0x90, 0x00]);
    assert!(a.management().is_locked());
    assert_eq!(a.take_effect(), ConfigEffect::None);

    // DeviceConfig({USB: 0x033B}, None, 0, None).get_bytes(True, cur): re-enable
    // everything with the current code, chalresp timeout 0 (`int2bytes(0) == 00`).
    let mut tl = vec![0x0C, 0x00, 0x0B, 0x10];
    tl.extend_from_slice(&LOCK);
    tl.extend_from_slice(&[0x03, 0x02, 0x03, 0x3B, 0x07, 0x01, 0x00]);
    assert_eq!(tl.len(), 0x1B);
    let mut apdu = vec![0x00, 0x1C, 0x00, 0x00, 0x1C, 0x1B];
    apdu.extend_from_slice(&tl);
    assert_eq!(run(&mut a, &apdu, &mut host), vec![0x90, 0x00]);
    assert_eq!(a.take_effect(), ConfigEffect::Reboot);
    assert_eq!(a.management().enabled_usb(&host), Capabilities::ALL);

    // DeviceConfig({}).get_bytes(False, cur, CLEAR_LOCK_CODE): clear the lock.
    let mut apdu = vec![0x00, 0x1C, 0x00, 0x00, 0x25, 0x24, 0x0B, 0x10];
    apdu.extend_from_slice(&LOCK);
    apdu.extend_from_slice(&[0x0A, 0x10]);
    apdu.extend_from_slice(&[0u8; 16]);
    assert_eq!(run(&mut a, &apdu, &mut host), vec![0x90, 0x00]);
    assert!(!a.management().is_locked());
    assert_eq!(
        info_value(&a.management().device_info(&host), tag::CONFIG_LOCK),
        Some(vec![0x00])
    );
    // The record keeps the all-zero code: "no lock" (persisted format, field 05).
    let record = host.persisted(Record::Device).expect("persisted");
    assert!(record.ends_with(&[[0x05, 0x10].as_slice(), &[0u8; 16]].concat()));
}

#[test]
fn write_config_accepts_case_4_apdus() {
    // yubikit `SmartCardProtocol.send_apdu` may add Le (ISO/IEC 7816-4 §5.1 case 4);
    // WRITE CONFIG answers no data either way.
    let mut host = TestHost::new();
    let mut a = applet(&mut host);
    let req = config(&tlv::encode(tag::CHALRESP_TIMEOUT, &[0x0A]));
    for le in [0u32, 0x10] {
        let apdu = Command::new(0x00, 0x1C, 0x00, 0x00)
            .with_data(req.clone())
            .with_le(le)
            .to_bytes();
        assert_eq!(run(&mut a, &apdu, &mut host), vec![0x90, 0x00]);
    }
    assert_eq!(a.management().challenge_response_timeout(), 0x0A);
}

#[test]
fn malformed_length_prefixes_are_rejected_on_every_transport() {
    // `len || TLVs` (yubikit `DeviceConfig.get_bytes`): CCID and CTAPHID carry the
    // exact block, so the length byte must equal the TLV byte count.
    let mut host = TestHost::new();
    let mut a = applet(&mut host);
    let good = config(&tlv::encode(tag::CHALRESP_TIMEOUT, &[0x21]));
    let mut longer = good.clone();
    longer.push(0x00); // trailing byte after the TLVs
    let mut zero_len = good.clone();
    zero_len[0] = 0x00; // length 0 with TLVs following
    let mut over = good.clone();
    over[0] = 0xFF; // length beyond the data
    let mut under = good.clone();
    under[0] = 0x02; // length cutting into the TLV
    for bad in [&longer, &zero_len, &over, &under] {
        let apdu = Command::new(0x00, 0x1C, 0x00, 0x00)
            .with_data(bad.clone())
            .to_bytes();
        assert_eq!(
            status(&run(&mut a, &apdu, &mut host)),
            sw::INCORRECT_DATA,
            "{bad:02x?}"
        );
        let reply = a
            .management_mut()
            .ctaphid_vendor(ctaphid::WRITE_CONFIG, bad, &mut host)
            .expect("mgmt command");
        assert_eq!(
            (reply.cmd, reply.payload),
            (ctaphid::ERROR, vec![ctaphid::ERR_INVALID_PAR]),
            "{bad:02x?}"
        );
    }
    // Only a length byte of 0 with nothing after it is a valid (empty) request.
    assert_eq!(
        a.management_mut().write_config(&[0x00], &mut host),
        Ok(ConfigEffect::None)
    );
    assert_eq!(host.persist_attempts(), 0);
    assert_eq!(a.management().challenge_response_timeout(), 0);
}

#[test]
fn otp_padded_write_length_edges() {
    // OTP HID slot 0x15 data is the length-prefixed block zero-padded to 64 bytes
    // (yubikit `OtpProtocol.send_and_receive` pads to SLOT_DATA_SIZE): the length
    // byte selects the TLVs and the rest is ignored.
    let mut host = TestHost::new();
    let mut m = Management::new(None, &mut host);

    // Length 0 with garbage after it: an empty request.
    let mut slot = [0xEEu8; 64];
    slot[0] = 0x00;
    assert_eq!(m.otp_write_config(&slot, &mut host), Ok(ConfigEffect::None));
    assert_eq!(host.persist_attempts(), 0);

    // Length cutting into a TLV: `03 02 02` is a truncated USB_ENABLED.
    let mut slot = [0u8; 64];
    slot[..5].copy_from_slice(&[0x03, 0x03, 0x02, 0x02, 0x02]);
    assert_eq!(
        m.otp_write_config(&slot, &mut host),
        Err(sw::INCORRECT_DATA)
    );
    assert_eq!(m.enabled_usb(&host), Capabilities::ALL);

    // Non-zero bytes after the selected TLVs are ignored.
    let mut slot = [0xEEu8; 64];
    slot[..4].copy_from_slice(&[0x03, 0x07, 0x01, 0x05]);
    assert_eq!(m.otp_write_config(&slot, &mut host), Ok(ConfigEffect::None));
    assert_eq!(m.challenge_response_timeout(), 5);

    // The largest block that fits the slot: length 63 (a 61-byte REBOOT value).
    let mut slot = [0u8; 64];
    slot[0] = 63;
    slot[1] = 0x0C;
    slot[2] = 61;
    assert_eq!(
        m.otp_write_config(&slot, &mut host),
        Ok(ConfigEffect::Reboot)
    );
}

#[test]
fn non_minimal_tlv_lengths_are_accepted() {
    // Model policy: WRITE CONFIG TLVs are parsed with lk_codec::tlv, which accepts the
    // long length forms 81/82 even where the short form would do (ISO/IEC 7816-4
    // §5.2.2.2 allows both on input). yubikit always sends the short form.
    let mut host = TestHost::new();
    let mut m = Management::new(None, &mut host);
    let mut lock = vec![0x0A, 0x81, 0x10];
    lock.extend_from_slice(&LOCK);
    assert_eq!(
        m.write_config(&config(&lock), &mut host),
        Ok(ConfigEffect::None)
    );
    assert!(m.is_locked());
    let mut req = vec![0x0B, 0x82, 0x00, 0x10];
    req.extend_from_slice(&LOCK);
    req.extend_from_slice(&[0x03, 0x81, 0x02, 0x02, 0x02]);
    assert_eq!(
        m.write_config(&config(&req), &mut host),
        Ok(ConfigEffect::None)
    );
    assert_eq!(m.enabled_usb(&host), Capabilities(0x0202));
}

#[test]
fn locked_device_rejects_lock_changes_without_the_code() {
    let mut host = TestHost::new();
    let mut m = Management::new(None, &mut host);
    assert_eq!(
        m.write_config(&config(&new_lock(&LOCK)), &mut host),
        Ok(ConfigEffect::None)
    );
    let stored = host.persisted(Record::Device);
    let attempts = host.persist_attempts();
    let cases: Vec<Vec<u8>> = vec![
        // A new code without the current one.
        new_lock(&OTHER_LOCK),
        // Clearing with a wrong code.
        [unlock(&OTHER_LOCK), new_lock(&[0; 16])].concat(),
        // Clearing with the all-zero "code".
        [unlock(&[0; 16]), new_lock(&[0; 16])].concat(),
        // An empty, a 15-byte and a 17-byte code (yubikit refuses these; the device
        // compares them as wrong codes).
        [tlv::encode(tag::UNLOCK, &[]), new_lock(&[0; 16])].concat(),
        [tlv::encode(tag::UNLOCK, &LOCK[..15]), new_lock(&[0; 16])].concat(),
        [
            tlv::encode(tag::UNLOCK, &[LOCK.as_slice(), &[0]].concat()),
            new_lock(&[0; 16]),
        ]
        .concat(),
        // Another wrong 16-byte code.
        [tlv::encode(tag::UNLOCK, &[0x10; 16]), new_lock(&[0; 16])].concat(),
    ];
    for req in cases {
        assert_eq!(
            m.write_config(&config(&req), &mut host),
            Err(sw::SECURITY_STATUS),
            "{req:02x?}"
        );
        assert!(m.is_locked());
    }
    assert_eq!(host.persist_attempts(), attempts);
    assert_eq!(host.persisted(Record::Device), stored);
    // The original code still works.
    let ok = [unlock(&LOCK), tlv::encode(tag::CHALRESP_TIMEOUT, &[1])].concat();
    assert_eq!(
        m.write_config(&config(&ok), &mut host),
        Ok(ConfigEffect::None)
    );
    // The current code alone changes nothing and is not persisted.
    let attempts = host.persist_attempts();
    assert_eq!(
        m.write_config(&config(&unlock(&LOCK)), &mut host),
        Ok(ConfigEffect::None)
    );
    assert_eq!(host.persist_attempts(), attempts);
}

#[test]
fn lock_rejection_owes_no_reboot() {
    // A rejected WRITE CONFIG carrying REBOOT must not reboot the device.
    let mut host = TestHost::new();
    let mut a = applet(&mut host);
    assert_eq!(
        status(&run(&mut a, &write_apdu(&new_lock(&LOCK)), &mut host)),
        sw::OK
    );
    let change = tlvs(&[(tag::REBOOT, &[]), (tag::USB_ENABLED, &[0x02, 0x02])]);
    for req in [
        change.clone(),
        [unlock(&OTHER_LOCK), change.clone()].concat(),
    ] {
        assert_eq!(
            status(&run(&mut a, &write_apdu(&req), &mut host)),
            sw::SECURITY_STATUS
        );
        assert_eq!(a.take_effect(), ConfigEffect::None);
    }
    // A value error after the right code does not reboot either.
    let invalid = [
        tlv::encode(tag::REBOOT, &[]),
        unlock(&LOCK),
        tlv::encode(tag::USB_ENABLED, &[0x00, 0x00]),
    ]
    .concat();
    assert_eq!(
        status(&run(&mut a, &write_apdu(&invalid), &mut host)),
        sw::INCORRECT_DATA
    );
    assert_eq!(a.take_effect(), ConfigEffect::None);
    assert_eq!(a.management().enabled_usb(&host), Capabilities::ALL);
}

#[test]
fn pending_reboot_survives_later_commands_until_taken() {
    let mut host = TestHost::new();
    let mut a = applet(&mut host);
    let reboot = tlv::encode(tag::REBOOT, &[]);
    let plain = tlv::encode(tag::CHALRESP_TIMEOUT, &[0x11]);
    // Reboot acknowledged, then a successful write without REBOOT: still owed.
    assert_eq!(
        status(&run(&mut a, &write_apdu(&reboot), &mut host)),
        sw::OK
    );
    assert_eq!(status(&run(&mut a, &write_apdu(&plain), &mut host)), sw::OK);
    assert_eq!(a.take_effect(), ConfigEffect::Reboot);
    assert_eq!(a.take_effect(), ConfigEffect::None);
    // Reboot acknowledged, then a failing write and a read: still owed.
    assert_eq!(
        status(&run(&mut a, &write_apdu(&reboot), &mut host)),
        sw::OK
    );
    assert_eq!(
        status(&run(
            &mut a,
            &write_apdu(&[0x03, 0x02, 0x00, 0x00]),
            &mut host
        )),
        sw::INCORRECT_DATA
    );
    assert_eq!(status(&run(&mut a, &read_apdu(0), &mut host)), sw::OK);
    assert_eq!(a.take_effect(), ConfigEffect::Reboot);
    // A write without REBOOT owes nothing.
    assert_eq!(status(&run(&mut a, &write_apdu(&plain), &mut host)), sw::OK);
    assert_eq!(a.take_effect(), ConfigEffect::None);
}

#[test]
fn disabling_every_application_is_rejected_on_every_transport() {
    // yubikit/ykman refuse to disable all USB applications ("Can not disable all
    // applications over USB"); the device enforces the same rule on every path.
    let mut host = TestHost::new();
    let mut m = Management::new(None, &mut host);
    let req = config(&tlvs(&[
        (tag::REBOOT, &[]),
        (tag::USB_ENABLED, &[0x00, 0x00]),
    ]));
    assert_eq!(m.write_config(&req, &mut host), Err(sw::INCORRECT_DATA));
    let reply = m
        .ctaphid_vendor(ctaphid::WRITE_CONFIG, &req, &mut host)
        .expect("mgmt command");
    assert_eq!(
        (reply.cmd, reply.payload, reply.effect),
        (
            ctaphid::ERROR,
            vec![ctaphid::ERR_INVALID_PAR],
            ConfigEffect::None
        )
    );
    let mut slot = [0u8; 64];
    slot[..req.len()].copy_from_slice(&req);
    assert_eq!(
        m.otp_write_config(&slot, &mut host),
        Err(sw::INCORRECT_DATA)
    );
    // Only undefined bits (0x0004, 0x0040, 0x0080, 0xFC00) are not "some application".
    let req = config(&tlv::encode(tag::USB_ENABLED, &[0xFC, 0xC4]));
    assert_eq!(m.write_config(&req, &mut host), Err(sw::INCORRECT_DATA));
    assert_eq!(host.persist_attempts(), 0);
    assert_eq!(m.enabled_usb(&host), Capabilities::ALL);
    // Each single application on its own is fine.
    for bit in [
        Capabilities::OTP,
        Capabilities::U2F,
        Capabilities::OPENPGP,
        Capabilities::PIV,
        Capabilities::OATH,
        Capabilities::HSMAUTH,
        Capabilities::FIDO2,
    ] {
        let req = config(&tlv::encode(tag::USB_ENABLED, &bit.to_be_bytes()));
        assert_eq!(m.write_config(&req, &mut host), Ok(ConfigEffect::None));
        assert_eq!(m.enabled_usb(&host), Capabilities(bit));
    }
}

#[test]
fn device_info_follows_the_profile() {
    // Tags 04 (form factor, yubikit `FORM_FACTOR`) and 05 (version, 3 bytes) and the
    // SELECT version text come from the DeviceProfile, never from the record.
    let mut profile = DeviceProfile::own(0x0102_0304);
    profile.firmware = lk_core::Version::new(5, 4, 3);
    profile.form_factor = lk_core::profile::form_factor::USB_A_KEYCHAIN;
    let mut host = TestHost::with_profile(profile);
    let mut a = applet(&mut host);
    let select = Command::new(0x00, 0xA4, 0x04, 0x00)
        .with_data(AID)
        .to_bytes();
    assert_eq!(a.select(&select, &mut host), b"5.4.3\x90\x00".to_vec());
    let info = a.management().device_info(&host);
    assert_eq!(info_value(&info, tag::FORM_FACTOR), Some(vec![0x01]));
    assert_eq!(info_value(&info, tag::VERSION), Some(vec![5, 4, 3]));
    assert_eq!(info_value(&info, tag::SERIAL), Some(vec![1, 2, 3, 4]));
}

#[test]
fn device_info_page_is_read_config_without_length_byte() {
    // lk_otp::MgmtBridge::device_info wants the bare TLVs; lk-otp adds the length
    // byte (and its HID layer the CRC). yubikit `read_device_info`: len || TLVs.
    for profile in [
        DeviceProfile::own(12_345_678),
        DeviceProfile::yubikey_5c_nano_5_7_4(31_415_926),
    ] {
        let mut host = TestHost::with_profile(profile);
        let m = Management::new(None, &mut host);
        let page = m.device_info_page(0, &host).expect("page 0");
        assert_eq!(page, m.device_info(&host));
        let mut framed = vec![u8::try_from(page.len()).expect("fits")];
        framed.extend_from_slice(&page);
        assert_eq!(m.read_config(0, &host), Ok(framed));
        for p in [1u8, 2, 0xFF] {
            assert_eq!(m.device_info_page(p, &host), None);
        }
    }
}

#[test]
fn otp_device_info_fits_the_otp_response_capacity() {
    // The OTP HID response is at most 32 chunks of 7 bytes (yubikit
    // `yubikit/core/otp.py` `_read_frame`, SEQUENCE_MASK 0x1F): len || TLVs || CRC.
    let mut host = TestHost::new();
    let mut m = Management::new(None, &mut host);
    let req = tlvs(&[
        (tag::AUTO_EJECT_TIMEOUT, &[0xFF, 0xFF]),
        (tag::CHALRESP_TIMEOUT, &[0xFF]),
        (tag::DEVICE_FLAGS, &[0xC0]),
        (tag::CONFIG_LOCK, &LOCK),
    ]);
    // Factory state, then every variable field at its largest value and locked (the
    // DeviceInfo length does not depend on the values, only on the tag set).
    for step in 0..2 {
        if step == 1 {
            assert_eq!(
                m.write_config(&config(&req), &mut host),
                Ok(ConfigEffect::None)
            );
            assert!(m.is_locked());
        }
        let frame = m.otp_read_config_frame(&[0], &host).expect("page 0");
        assert_eq!(frame.len(), 1 + 50 + 2);
        assert!(frame.len() <= 32 * 7);
        assert_eq!(otp_crc16(&frame), 0xF0B8);
    }
}

#[test]
fn set_mode_is_not_implemented_on_any_transport() {
    // YubiKey 4 SET MODE (yubikit `INS_SET_MODE 0x16`, `P1_DEVICE_CONFIG 0x11`,
    // CTAPHID `CTAP_YUBIKEY_DEVICE_CONFIG 0x40`, OTP `SLOT_DEVICE_CONFIG 0x11`; data
    // `struct.pack("<BBH", mode, chalresp, autoeject)`): yubikit never sends it to
    // firmware 5.x, and the engine answers 6D00 without changing anything.
    let mut host = TestHost::new();
    let mut a = applet(&mut host);
    let apdu = Command::new(0x00, 0x16, 0x11, 0x00)
        .with_data(vec![0x05, 0x00, 0x00, 0x00])
        .to_bytes();
    assert_eq!(
        status(&run(&mut a, &apdu, &mut host)),
        sw::INS_NOT_SUPPORTED
    );
    assert_eq!(a.take_effect(), ConfigEffect::None);
    assert_eq!(
        a.management_mut()
            .legacy_set_mode(&[0x05, 0x00, 0x00, 0x00], &mut host),
        Err(sw::INS_NOT_SUPPORTED)
    );
    assert_eq!(
        a.management_mut()
            .ctaphid_vendor(ctaphid::DEVICE_CONFIG, &[0x05, 0, 0, 0], &mut host),
        None
    );
    assert_eq!(host.persist_attempts(), 0);
    assert_eq!(a.management().device_info(&host), OWN_INFO.to_vec());
}
