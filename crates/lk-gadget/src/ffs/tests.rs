use lk_core::UsbInterfaces;

use super::*;
use crate::descriptor::ConfigDescriptor;
use crate::test_support::{ALL, FIDO_CCID, REFERENCE_CONFIGURATION, hex, identity};

fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn blob_for(interfaces: UsbInterfaces) -> (Vec<u8>, Vec<u8>) {
    let config = identity(interfaces, None).configuration_descriptor();
    let parsed = ConfigDescriptor::parse(&config).expect("the engine's descriptor parses");
    (descriptors_blob(&parsed), config)
}

#[test]
fn the_fido_and_ccid_blob_is_the_v2_header_and_the_reference_bytes_after_the_configuration_header() {
    let (blob, config) = blob_for(FIDO_CCID);
    let reference = hex(REFERENCE_CONFIGURATION);
    assert_eq!(le32(&blob, 0), 3, "FUNCTIONFS_DESCRIPTORS_MAGIC_V2");
    assert_eq!(le32(&blob, 4) as usize, blob.len(), "length of the whole blob");
    assert_eq!(le32(&blob, 8), 1, "FUNCTIONFS_HAS_FS_DESC only");
    assert_eq!(le32(&blob, 12), 9, "interface, HID, 2 endpoints, interface, CCID, 3 endpoints");
    assert_eq!(&blob[16..], &reference[9..]);
    assert_eq!(&blob[16..], &config[9..]);
    assert_eq!(blob.len(), 16 + 125 - 9);
}

#[test]
fn the_blob_with_all_three_interfaces_counts_twelve_descriptors() {
    let (blob, config) = blob_for(ALL);
    assert_eq!(le32(&blob, 0), DESCRIPTORS_MAGIC_V2);
    assert_eq!(le32(&blob, 4) as usize, blob.len());
    assert_eq!(le32(&blob, 8), HAS_FS_DESC);
    assert_eq!(le32(&blob, 12), 12);
    assert_eq!(&blob[16..], &config[9..]);
    // The OTP keyboard comes first: interface 0, boot keyboard, then its HID descriptor
    // naming the 77-byte report descriptor, then endpoint 81.
    assert_eq!(&blob[16..34], &hex("090400000103010100092110010001224d00"));
    assert_eq!(&blob[34..41], &hex("0705810308000a"));
}

#[test]
fn single_interface_blobs_count_their_descriptors() {
    for (interfaces, count) in [
        (UsbInterfaces { otp: true, fido: false, ccid: false }, 3),
        (UsbInterfaces { otp: false, fido: true, ccid: false }, 4),
        (UsbInterfaces { otp: false, fido: false, ccid: true }, 5),
        (UsbInterfaces { otp: true, fido: false, ccid: true }, 8),
        (UsbInterfaces { otp: true, fido: true, ccid: false }, 7),
    ] {
        let (blob, config) = blob_for(interfaces);
        assert_eq!(le32(&blob, 12), count, "{interfaces:?}");
        assert_eq!(&blob[16..], &config[9..], "{interfaces:?}");
        assert_eq!(le32(&blob, 4) as usize, blob.len(), "{interfaces:?}");
    }
}

#[test]
fn the_strings_blob_without_strings_is_the_bare_header_with_both_counts_zero() {
    let blob = strings_blob(LANG_EN_US, &[]).expect("no NUL");
    assert_eq!(blob, [2, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn the_strings_blob_with_strings_has_one_language_table() {
    let blob = strings_blob(LANG_EN_US, &["ab", "c"]).expect("no NUL");
    let mut expected = Vec::new();
    for field in [2u32, 23, 2, 1] {
        expected.extend_from_slice(&field.to_le_bytes());
    }
    expected.extend_from_slice(&[0x09, 0x04, b'a', b'b', 0, b'c', 0]);
    assert_eq!(blob, expected);
}

#[test]
fn the_strings_blob_refuses_a_string_with_a_nul() {
    assert_eq!(strings_blob(LANG_EN_US, &["a\0b"]), None);
}

/// An event as the kernel lays it out: request bytes, type, three padding bytes.
fn raw_event(request: [u8; 8], kind: u8) -> [u8; EVENT_SIZE] {
    let mut out = [0xEE; EVENT_SIZE];
    out[..8].copy_from_slice(&request);
    out[8] = kind;
    out
}

#[test]
fn every_event_type_parses_from_its_type_byte() {
    for (kind, event) in [
        (0, Event::Bind),
        (1, Event::Unbind),
        (2, Event::Enable),
        (3, Event::Disable),
        (5, Event::Suspend),
        (6, Event::Resume),
        (7, Event::Unknown(7)),
        (0xFF, Event::Unknown(0xFF)),
    ] {
        assert_eq!(Event::parse(&raw_event([0x55; 8], kind)), event, "type {kind}");
    }
}

#[test]
fn a_setup_event_carries_the_control_request_little_endian() {
    let event = Event::parse(&raw_event([0x81, 0x06, 0x00, 0x22, 0x01, 0x00, 0x22, 0x00], 4));
    assert_eq!(
        event,
        Event::Setup(CtrlRequest { request_type: 0x81, request: 0x06, value: 0x2200, index: 1, length: 0x22 })
    );
    let Event::Setup(request) = event else { unreachable!("parsed as SETUP above") };
    assert!(request.is_in());
    assert!(!CtrlRequest { request_type: 0x21, ..request }.is_in());
}

#[test]
fn events_encode_as_the_kernel_lays_them_out() {
    let request = CtrlRequest { request_type: 0x21, request: 0x0A, value: 0x7D00, index: 2, length: 0 };
    assert_eq!(Event::Setup(request).to_bytes(), [0x21, 0x0A, 0x00, 0x7D, 0x02, 0x00, 0x00, 0x00, 4, 0, 0, 0]);
    assert_eq!(Event::Resume.to_bytes(), [0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0]);
    for event in [Event::Bind, Event::Unbind, Event::Enable, Event::Disable, Event::Suspend, Event::Setup(request)] {
        assert_eq!(Event::parse(&event.to_bytes()), event);
    }
}

#[test]
fn a_read_of_whole_well_formed_events_is_parsed_in_order() {
    let request = CtrlRequest { request_type: 0xA1, request: 0x01, value: 0x0300, index: 0, length: 8 };
    let mut bytes = Vec::new();
    for event in [Event::Enable, Event::Setup(request), Event::Suspend, Event::Unknown(9)] {
        bytes.extend_from_slice(&event.to_bytes());
    }
    assert_eq!(
        Event::parse_read(&bytes),
        Some(vec![Event::Enable, Event::Setup(request), Event::Suspend, Event::Unknown(9)])
    );
}

#[test]
fn a_read_that_is_not_a_whole_number_of_events_is_not_events() {
    let mut bytes = Event::Enable.to_bytes().to_vec();
    bytes.extend_from_slice(&[1, 2, 3]);
    assert_eq!(Event::parse_read(&bytes), None);
    assert_eq!(Event::parse_read(&[0; 11]), None);
    assert_eq!(Event::parse_read(&[0; 8]), None, "an 8-byte data stage (OTP SET_REPORT feature)");
    assert_eq!(Event::parse_read(&[]), None);
}

#[test]
fn twelve_byte_chunks_with_padding_or_request_bytes_the_kernel_zeroes_are_not_events() {
    // Host data of a data stage still pending: nonzero padding.
    let mut padded = Event::Disable.to_bytes();
    padded[10] = 0x42;
    assert_eq!(Event::parse_read(&padded), None);
    // A non-SETUP type with request bytes.
    let mut with_request = Event::Unbind.to_bytes();
    with_request[0] = 0x21;
    assert_eq!(Event::parse_read(&with_request), None);
    // One bad chunk spoils the whole read: it is one data stage, not some events.
    let mut bytes = Event::Enable.to_bytes().to_vec();
    bytes.extend_from_slice(&with_request);
    assert_eq!(Event::parse_read(&bytes), None);
}

#[test]
fn control_requests_round_trip_through_their_eight_bytes() {
    let request = CtrlRequest { request_type: 0xA1, request: 0x01, value: 0x0300, index: 0, length: 8 };
    assert_eq!(CtrlRequest::parse(&request.to_bytes()), request);
    assert_eq!(request.to_bytes(), [0xA1, 0x01, 0x00, 0x03, 0x00, 0x00, 0x08, 0x00]);
}

#[test]
fn events_display_their_kind_and_request_fields() {
    let request = CtrlRequest { request_type: 0xA1, request: 0x01, value: 0x0300, index: 0, length: 8 };
    assert_eq!(Event::Setup(request).to_string(), "SETUP a1 01 value 0x0300 index 0 length 8");
    assert_eq!(Event::Unknown(9).to_string(), "unknown event 9");
}
