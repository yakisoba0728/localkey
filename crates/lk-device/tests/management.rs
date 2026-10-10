//! Management effects on the device: reboot and re-enumeration, enabled interfaces and
//! applications, and the USB identity.

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use lk_core::{Capabilities, DeviceProfile, UsbInterfaces};
use lk_device::{BusEvent, FIDO_REPORT_DESCRIPTOR, Output};
use lk_otp::{SlotConfig, ext, tkt};

const ALL: UsbInterfaces = UsbInterfaces {
    otp: true,
    fido: true,
    ccid: true,
};

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

/// Write a configuration through whichever interface is enabled: CTAPHID `0x43`, CCID
/// INS `1C`, or OTP HID slot `0x15` (catalog Management "CCID and OTP HID device
/// information/configuration", "CTAPHID vendor 0x42 / 0x43 commands").
fn write_config(rig: &mut Rig, data: &[u8]) -> Vec<Output> {
    let interfaces = rig.dev.interfaces();
    if interfaces.fido {
        let cid = rig.ctaphid_init();
        rig.ctaphid_send(cid, 0x43, data)
    } else if interfaces.ccid {
        rig.power_on();
        rig.select(AID_MGMT);
        let mut apdu = vec![0x00, 0x1C, 0x00, 0x00, data.len() as u8];
        apdu.extend_from_slice(data);
        rig.xfr(&apdu).1
    } else {
        let mut payload = [0u8; 64];
        payload[..data.len()].copy_from_slice(data);
        rig.otp_write(0x15, &payload)
    }
}

fn position(out: &[Output], wanted: impl Fn(&Output) -> bool) -> usize {
    out.iter().position(wanted).unwrap_or_else(|| panic!("missing output in {out:02X?}"))
}

/// docs/CONTRACTS.md "Applications A", lk-mgmt: `take_effect` after the WRITE CONFIG
/// response; the response goes out first, then `Reenumerate`, then the volatile state
/// is power-cycled (catalog appendix A `Linux_native`: "automatic management reboot ...
/// unchanged-profile reboot ... persistent credentials retained and old PIN token
/// rejected").
#[test]
fn ccid_write_config_with_reboot() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_OATH);
    rig.apdu(&oath_put(b"kept", false));
    rig.select(AID_PIV);
    rig.apdu(&[0x00, 0x20, 0x00, 0x80, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF]);
    rig.select(AID_MGMT);
    let mut apdu = vec![0x00, 0x1C, 0x00, 0x00];
    let data = config(None, true);
    apdu.push(data.len() as u8);
    apdu.extend_from_slice(&data);
    let (seq, out) = rig.xfr(&apdu);
    assert_eq!(data_block(&out, seq).unwrap(), vec![0x90, 0x00]);
    let reply = position(&out, |o| matches!(o, Output::Ccid(_)));
    let reenumerate = position(&out, |o| matches!(o, Output::Reenumerate(_)));
    assert!(reply < reenumerate);
    assert_eq!(reenumerations(&out), vec![ALL]);
    // The card session ended: the slot needs a new IccPowerOn.
    let (_, out) = rig.xfr(&[0x00, 0x20, 0x00, 0x80]);
    assert_eq!(ccid_replies(&out)[0][7] & 0x40, 0x40);
    rig.power_on();
    rig.select(AID_PIV);
    assert_eq!(rig.apdu(&[0x00, 0x20, 0x00, 0x80]), vec![0x63, 0xC3], "PIN verification is volatile");
    rig.select(AID_OATH);
    let list = rig.apdu(&[0x00, 0xA1, 0x00, 0x00]);
    assert_eq!(&list[3..7], b"kept", "credentials are persistent");
}

/// `VendorReply::effect`: the CTAPHID WRITE CONFIG answer is sent, then the device
/// re-enumerates; earlier CTAPHID channels are gone.
#[test]
fn ctaphid_write_config_with_reboot() {
    let mut rig = Rig::new();
    let cid = rig.ctaphid_init();
    let out = rig.ctaphid_send(cid, 0x43, &config(None, true));
    assert_eq!(responses(&out), vec![(0x43, vec![])]);
    let reply = position(&out, |o| matches!(o, Output::FidoReport(_)));
    let reenumerate = position(&out, |o| matches!(o, Output::Reenumerate(_)));
    assert!(reply < reenumerate);
    assert_eq!(rig.ctaphid(cid, CTAPHID_PING, b"x"), (CTAPHID_ERROR, vec![0x0B]));
}

/// docs/CONTRACTS.md: the OTP bridge's `write_device_info` returns no effect, so
/// lk-device keeps the `ConfigEffect` and reboots after the slot command.
#[test]
fn otp_hid_write_config_with_reboot() {
    let mut rig = Rig::new();
    let mut payload = [0u8; 64];
    let data = config(None, true);
    payload[..data.len()].copy_from_slice(&data);
    let out = rig.otp_write(0x15, &payload);
    assert_eq!(reenumerations(&out), vec![ALL]);
}

/// A change of enabled interfaces with REBOOT (as ykman `config usb` sends it)
/// re-enumerates, and inputs for a disabled interface are ignored (docs/DESIGN.md §5).
#[test]
fn disabling_ccid_reenumerates_and_ignores_ccid() {
    let mut rig = Rig::new();
    let out = write_config(&mut rig, &config(Some(Capabilities::OTP | Capabilities::U2F | Capabilities::FIDO2), true));
    assert_eq!(
        reenumerations(&out),
        vec![UsbInterfaces {
            otp: true,
            fido: true,
            ccid: false
        }]
    );
    let message = Rig::ccid_message(0x62, 0, [0, 0, 0], &[]);
    assert!(rig.input(lk_device::Input::Ccid(&message)).is_empty());
    let identity = rig.dev.usb_identity();
    assert_eq!(identity.product_id, 0x0403);
    assert_eq!(identity.product, "YubiKey OTP+FIDO");
}

/// `lib.rs` `settle_management` (model policy): a write without REBOOT changes nothing on
/// the bus, also when it changes the interface set. CCID keeps working and the USB
/// identity stays until the next enumeration; a power cycle then enumerates without CCID.
#[test]
fn interface_change_without_reboot_waits_for_the_next_enumeration() {
    let mut rig = Rig::new();
    let out = write_config(&mut rig, &config(Some(Capabilities::OTP | Capabilities::U2F | Capabilities::FIDO2), false));
    assert!(reenumerations(&out).is_empty(), "{out:02X?}");
    assert_eq!(rig.dev.interfaces(), ALL);
    assert_eq!(rig.dev.usb_identity().product, "YubiKey OTP+FIDO+CCID");
    rig.power_on();
    assert_eq!(sw(&rig.select(AID_OATH)), 0x9000, "CCID still answers");
    let out = rig.bus(BusEvent::PowerCycle);
    let without_ccid = UsbInterfaces { otp: true, fido: true, ccid: false };
    assert_eq!(reenumerations(&out), vec![without_ccid]);
    let message = Rig::ccid_message(0x62, 0, [0, 0, 0], &[]);
    assert!(rig.input(lk_device::Input::Ccid(&message)).is_empty());
    assert_eq!(rig.dev.usb_identity().product, "YubiKey OTP+FIDO");
}

/// With FIDO disabled the FIDO HID reports are ignored.
#[test]
fn disabling_fido_ignores_fido_reports() {
    let mut rig = Rig::new();
    let out = write_config(&mut rig, &config(Some(Capabilities::OTP | Capabilities::PIV | Capabilities::OATH), true));
    assert_eq!(
        reenumerations(&out),
        vec![UsbInterfaces {
            otp: true,
            fido: false,
            ccid: true
        }]
    );
    let packet = Rig::ctaphid_packets(BROADCAST, CTAPHID_INIT, &[1; 8]);
    assert!(rig.input(lk_device::Input::FidoReport(&packet[0])).is_empty());
}

/// `Management::enabled_usb`: a capability change that keeps the interface set applies
/// at the next enumeration; afterwards the disabled application cannot be selected
/// (`6A82`). A power cycle applies it too, without a `Reenumerate` (same interfaces).
#[test]
fn disabled_application_cannot_be_selected_after_enumeration() {
    let mut rig = Rig::new();
    let without_piv = Capabilities::ALL.0 & !Capabilities::PIV;
    let out = write_config(&mut rig, &config(Some(without_piv), false));
    assert!(reenumerations(&out).is_empty(), "same interfaces: no re-enumeration yet");
    rig.power_on();
    assert_eq!(sw(&rig.select(AID_PIV)), 0x9000, "applies at the next enumeration");
    let out = rig.bus(BusEvent::PowerCycle);
    assert!(reenumerations(&out).is_empty());
    rig.power_on();
    assert_eq!(rig.select(AID_PIV), vec![0x6A, 0x82]);
    assert_eq!(sw(&rig.select(AID_OATH)), 0x9000);
    assert_eq!(sw(&rig.select(AID_MGMT)), 0x9000, "Management has no capability bit");
    assert_eq!(sw(&rig.select(AID_SD)), 0x9000, "nor has the Security Domain");
}

/// CTAP 2.1 §11.2.9.1.3 capability flags follow the enabled FIDO applications: without
/// FIDO2 there is no CAPABILITY_CBOR and CBOR is ERR_INVALID_CMD; without U2F,
/// CAPABILITY_NMSG is set and MSG is ERR_INVALID_CMD.
#[test]
fn ctaphid_capabilities_follow_fido_applications() {
    let mut rig = Rig::new();
    write_config(&mut rig, &config(Some(Capabilities::ALL.0 & !Capabilities::FIDO2), true));
    let out = rig.ctaphid_send(BROADCAST, CTAPHID_INIT, &[1; 8]);
    let (_, init) = responses(&out).remove(0);
    assert_eq!(init[16], 0x01, "WINK only");
    let cid = u32::from_be_bytes([init[8], init[9], init[10], init[11]]);
    assert_eq!(rig.ctaphid(cid, CTAPHID_CBOR, &[0x04]), (CTAPHID_ERROR, vec![0x01]));
    write_config(&mut rig, &config(Some(Capabilities::ALL.0 & !Capabilities::U2F), true));
    let out = rig.ctaphid_send(BROADCAST, CTAPHID_INIT, &[1; 8]);
    let (_, init) = responses(&out).remove(0);
    assert_eq!(init[16], 0x0D, "WINK | CBOR | NMSG");
    let cid = u32::from_be_bytes([init[8], init[9], init[10], init[11]]);
    assert_eq!(rig.ctaphid(cid, CTAPHID_MSG, &[0, 3, 0, 0]), (CTAPHID_ERROR, vec![0x01]));
}

/// `reference/yubikey-5c-nano-5.7.4/usb-reference-observation.json` (FIDO+CCID
/// configuration): idVendor 4176, idProduct 1030, bcdDevice 1396, product
/// "YubiKey FIDO+CCID" (reference-observation.json), the HID report descriptor, and the
/// CCID class descriptor inside the configuration descriptor.
#[test]
fn usb_identity_matches_the_reference_configuration() {
    let mut rig = Rig::new();
    write_config(&mut rig, &config(Some(Capabilities::ALL.0 & !Capabilities::OTP), true));
    let identity = rig.dev.usb_identity();
    assert_eq!(identity.interfaces, UsbInterfaces { otp: false, fido: true, ccid: true });
    assert_eq!((identity.vendor_id, identity.product_id, identity.device_release), (4176, 1030, 1396));
    assert_eq!(identity.manufacturer, "Yubico");
    assert_eq!(identity.product, "YubiKey FIDO+CCID");
    assert_eq!(identity.serial, None);
    assert_eq!(identity.fido_report_descriptor, hex("06d0f10901a1010920150026ff007508954081020921150026ff00750895409102c0"));
    assert_eq!(identity.fido_report_descriptor, FIDO_REPORT_DESCRIPTOR.to_vec());
    let configuration = hex(concat!(
        "09027d00020100800f090400000203000000092110010001222200070504034000020705840340000209",
        "040100030b00000036210001000702000000a00f0000a00f00000000b0040000b0040000f60b0000000000",
        "0000000000fe000400000c0000ffff00000001070502024000000705820240000007058303080020"
    ));
    assert_eq!(identity.ccid_class_descriptor.len(), 54);
    assert!(
        configuration.windows(54).any(|w| w == identity.ccid_class_descriptor.as_slice()),
        "CCID class descriptor inside the reference configuration descriptor"
    );
    // The HID descriptor in the configuration names a 34-byte report descriptor.
    assert!(configuration.windows(9).any(|w| w == [0x09, 0x21, 0x10, 0x01, 0x00, 0x01, 0x22, 0x22, 0x00]));
}

/// Catalog appendix A "USB class matching IDs for seven interface combinations": each
/// combination enumerates with its product ID and product string.
#[test]
fn seven_interface_combinations() {
    let mut rig = Rig::new();
    let ids = DeviceProfile::yubikey_5c_nano_5_7_4(SERIAL).usb_product_ids;
    let cases = [
        (Capabilities::OTP, ids.otp, "YubiKey OTP"),
        (Capabilities::U2F | Capabilities::FIDO2, ids.fido, "YubiKey FIDO"),
        (Capabilities::OTP | Capabilities::U2F | Capabilities::FIDO2, ids.otp_fido, "YubiKey OTP+FIDO"),
        (Capabilities::PIV, ids.ccid, "YubiKey CCID"),
        (Capabilities::OTP | Capabilities::OATH, ids.otp_ccid, "YubiKey OTP+CCID"),
        (Capabilities::FIDO2 | Capabilities::OPENPGP, ids.fido_ccid, "YubiKey FIDO+CCID"),
        (Capabilities::ALL.0, ids.otp_fido_ccid, "YubiKey OTP+FIDO+CCID"),
    ];
    for (bits, product_id, product) in cases {
        let out = write_config(&mut rig, &config(Some(bits), true));
        let interfaces = Capabilities(bits).interfaces();
        assert_eq!(reenumerations(&out), vec![interfaces], "{product}");
        let identity = rig.dev.usb_identity();
        assert_eq!((identity.product_id, identity.product.as_str()), (product_id, product));
        assert_eq!(rig.dev.interfaces(), interfaces);
    }
}

/// `usb.rs`: the USB serial string appears only while a configured OTP slot sets
/// `EXTFLAG_SERIAL_USB_VISIBLE` (Yubico `ykdef.h`).
#[test]
fn usb_serial_follows_the_otp_flag() {
    let mut rig = Rig::new();
    assert_eq!(rig.dev.usb_identity().serial, None);
    let slot = SlotConfig {
        fixed: [0; 16],
        uid: [1; 6],
        key: [2; 16],
        acc_code: [0; 6],
        fixed_size: 0,
        ext_flags: ext::SERIAL_USB_VISIBLE,
        tkt_flags: tkt::APPEND_CR,
        cfg_flags: 0,
        rfu: [0; 2],
    };
    let mut payload = [0u8; 64];
    payload[..52].copy_from_slice(&slot.to_bytes());
    rig.otp_write(0x01, &payload);
    assert_eq!(rig.dev.usb_identity().serial.as_deref(), Some("12345678"));
}

/// The own identity profile enumerates with its own IDs and strings
/// (docs/DESIGN.md §9: the own identity is the default).
#[test]
fn own_profile_identity() {
    let rig = Rig::with_profile(DeviceProfile::own(7));
    let identity = rig.dev.usb_identity();
    assert_eq!((identity.vendor_id, identity.product_id), (0x1209, 0x0001));
    assert_eq!(identity.product, "localkey OTP+FIDO+CCID");
    assert_eq!(identity.otp_report_descriptor.len(), 77);
}

/// A rejected configuration write (lock code missing) owes no reboot (lk-mgmt
/// `lock_rejection_owes_no_reboot`).
#[test]
fn rejected_write_does_not_reboot() {
    let mut rig = Rig::new();
    // Set a lock code (tag 0A, 16 bytes) without reboot.
    let mut tlvs = vec![0x0A, 0x10];
    tlvs.extend_from_slice(&[0x77; 16]);
    let mut data = vec![tlvs.len() as u8];
    data.extend_from_slice(&tlvs);
    let out = write_config(&mut rig, &data);
    assert!(reenumerations(&out).is_empty());
    let out = write_config(&mut rig, &config(None, true));
    assert_eq!(responses(&out), vec![(CTAPHID_ERROR, vec![0x7F])], "6982 maps to ERR_OTHER");
    assert!(reenumerations(&out).is_empty());
}

/// Catalog appendix A `Linux_native`: "profile6->FIDO-only->profile6 pending Management
/// checks ... actual terminal touch ... old CCID ENODEV": a re-enumeration ends a card
/// command waiting for a touch without an answer.
#[test]
fn reenumeration_drops_a_waiting_card_command() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_OATH);
    rig.apdu(&oath_put(b"t", true));
    let (_, out) = rig.xfr(&oath_calculate(b"t"));
    assert_eq!(indicators(&out), vec![true]);
    let cid = rig.ctaphid_init();
    let out = rig.ctaphid_send(cid, 0x43, &config(Some(Capabilities::U2F | Capabilities::FIDO2), true));
    assert_eq!(
        reenumerations(&out),
        vec![UsbInterfaces {
            otp: false,
            fido: true,
            ccid: false
        }]
    );
    assert_eq!(indicators(&out), vec![false]);
    assert!(ccid_replies(&out).is_empty());
    assert!(ccid_replies(&rig.tap()).is_empty());
}
