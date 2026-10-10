use lk_core::UsbInterfaces;

use super::*;
use crate::test_support::{ALL, FIDO_CCID, REFERENCE_CONFIGURATION, hex, identity};

/// Every interface combination the engine can expose.
fn combinations() -> Vec<UsbInterfaces> {
    (1u8..8).map(|bits| UsbInterfaces { otp: bits & 1 != 0, fido: bits & 2 != 0, ccid: bits & 4 != 0 }).collect()
}

fn kinds(config: &ConfigDescriptor) -> String {
    config
        .descriptors
        .iter()
        .map(|d| match d {
            Descriptor::Interface(_) => 'I',
            Descriptor::Endpoint(_) => 'E',
            Descriptor::Class(_) => 'C',
        })
        .collect()
}

#[test]
fn the_engine_descriptor_for_fido_and_ccid_is_the_reference_configuration() {
    assert_eq!(identity(FIDO_CCID, None).configuration_descriptor(), hex(REFERENCE_CONFIGURATION));
}

#[test]
fn parsing_the_reference_configuration_gives_its_header_and_nine_descriptors() {
    let config = ConfigDescriptor::parse(&hex(REFERENCE_CONFIGURATION)).expect("the reference parses");
    assert_eq!(
        config.header,
        ConfigHeader {
            total_length: 125,
            num_interfaces: 2,
            configuration_value: 1,
            configuration_string: 0,
            attributes: 0x80,
            max_power: 0x0F,
        }
    );
    assert_eq!(kinds(&config), "ICEEICEEE");
    assert_eq!(
        config.descriptors[0],
        Descriptor::Interface(InterfaceDescriptor {
            number: 0,
            alternate_setting: 0,
            num_endpoints: 2,
            class: 3,
            subclass: 0,
            protocol: 0,
            string: 0,
        })
    );
    assert_eq!(
        config.descriptors[2],
        Descriptor::Endpoint(EndpointDescriptor { address: 0x04, attributes: 3, max_packet_size: 64, interval: 2 })
    );
    assert_eq!(config.descriptors[1], Descriptor::Class(hex("092110010001222200")));
    match &config.descriptors[5] {
        Descriptor::Class(bytes) => assert_eq!(bytes.len(), 54),
        other => panic!("expected the CCID class descriptor, got {other:?}"),
    }
}

#[test]
fn parsed_descriptors_encode_back_to_the_same_bytes_for_every_interface_combination() {
    for interfaces in combinations() {
        let bytes = identity(interfaces, None).configuration_descriptor();
        let config = ConfigDescriptor::parse(&bytes).expect("the engine's descriptor parses");
        assert_eq!(config.to_bytes(), bytes, "{interfaces:?}");
        assert_eq!(config.body(), bytes[CONFIG_HEADER_LEN..].to_vec(), "{interfaces:?}");
    }
}

#[test]
fn parsing_refuses_a_missing_or_wrong_header() {
    let reference = hex(REFERENCE_CONFIGURATION);
    assert_eq!(ConfigDescriptor::parse(&reference[..8]), Err(DescriptorError::BadHeader));
    let mut wrong_type = reference.clone();
    wrong_type[1] = 0x01;
    assert_eq!(ConfigDescriptor::parse(&wrong_type), Err(DescriptorError::BadHeader));
    let mut wrong_length = reference.clone();
    wrong_length[0] = 10;
    assert_eq!(ConfigDescriptor::parse(&wrong_length), Err(DescriptorError::BadHeader));
}

#[test]
fn parsing_refuses_a_total_length_that_differs_from_the_bytes() {
    let reference = hex(REFERENCE_CONFIGURATION);
    assert_eq!(
        ConfigDescriptor::parse(&reference[..124]),
        Err(DescriptorError::TotalLength { declared: 125, actual: 124 })
    );
}

/// A configuration header for `body`.
fn config_with(body: &[u8], interfaces: u8) -> Vec<u8> {
    let total = u16::try_from(9 + body.len()).expect("small test descriptors").to_le_bytes();
    let mut out = vec![9, 2, total[0], total[1], interfaces, 1, 0, 0x80, 0x0F];
    out.extend_from_slice(body);
    out
}

const FIDO_INTERFACE: [u8; 9] = [9, 4, 0, 0, 2, 3, 0, 0, 0];
const HID_DESCRIPTOR: [u8; 9] = [9, 0x21, 0x10, 0x01, 0, 1, 0x22, 34, 0];
const FIDO_OUT: [u8; 7] = [7, 5, 0x04, 3, 64, 0, 2];
const FIDO_IN: [u8; 7] = [7, 5, 0x84, 3, 64, 0, 2];

fn fido_body() -> Vec<u8> {
    [&FIDO_INTERFACE[..], &HID_DESCRIPTOR, &FIDO_OUT, &FIDO_IN].concat()
}

#[test]
fn a_handcrafted_fido_configuration_parses() {
    let config = ConfigDescriptor::parse(&config_with(&fido_body(), 1)).expect("parses");
    assert_eq!(kinds(&config), "ICEE");
}

#[test]
fn parsing_refuses_a_descriptor_with_a_length_below_two_or_past_the_end() {
    let mut body = fido_body();
    body.extend_from_slice(&[1, 0x21]);
    assert_eq!(ConfigDescriptor::parse(&config_with(&body, 1)), Err(DescriptorError::Malformed { offset: 41 }));
    let mut body = fido_body();
    body.extend_from_slice(&[0]);
    assert_eq!(ConfigDescriptor::parse(&config_with(&body, 1)), Err(DescriptorError::Malformed { offset: 41 }));
    let mut body = fido_body();
    body.extend_from_slice(&[9, 0x21, 0]);
    assert_eq!(ConfigDescriptor::parse(&config_with(&body, 1)), Err(DescriptorError::Malformed { offset: 41 }));
}

#[test]
fn parsing_refuses_interface_and_endpoint_descriptors_of_the_wrong_length() {
    let body = [&[10u8, 4, 0, 0, 0, 3, 0, 0, 0, 0][..]].concat();
    assert_eq!(ConfigDescriptor::parse(&config_with(&body, 1)), Err(DescriptorError::Malformed { offset: 9 }));
    let body = [&FIDO_INTERFACE[..], &HID_DESCRIPTOR, &[9, 5, 0x04, 3, 64, 0, 2, 0, 0], &FIDO_IN].concat();
    assert_eq!(ConfigDescriptor::parse(&config_with(&body, 1)), Err(DescriptorError::Malformed { offset: 27 }));
}

#[test]
fn parsing_refuses_device_configuration_and_string_descriptors_inside_the_configuration() {
    for descriptor_type in [1u8, 2, 3] {
        let mut body = fido_body();
        body.extend_from_slice(&[4, descriptor_type, 0, 0]);
        assert_eq!(
            ConfigDescriptor::parse(&config_with(&body, 1)),
            Err(DescriptorError::Reserved { offset: 41, descriptor_type })
        );
    }
}

#[test]
fn parsing_refuses_class_or_endpoint_descriptors_before_any_interface() {
    let body = [&HID_DESCRIPTOR[..], &fido_body()].concat();
    assert_eq!(ConfigDescriptor::parse(&config_with(&body, 1)), Err(DescriptorError::Orphan { offset: 9 }));
    let body = [&FIDO_OUT[..], &fido_body()].concat();
    assert_eq!(ConfigDescriptor::parse(&config_with(&body, 1)), Err(DescriptorError::Orphan { offset: 9 }));
}

#[test]
fn parsing_refuses_an_interface_whose_endpoint_count_differs() {
    let body = [&FIDO_INTERFACE[..], &HID_DESCRIPTOR, &FIDO_OUT].concat();
    assert_eq!(ConfigDescriptor::parse(&config_with(&body, 1)), Err(DescriptorError::EndpointCount { interface: 0 }));
}

#[test]
fn parsing_refuses_a_wrong_interface_count() {
    assert_eq!(
        ConfigDescriptor::parse(&config_with(&fido_body(), 2)),
        Err(DescriptorError::InterfaceCount { declared: 2, actual: 1 })
    );
}

#[test]
fn the_fido_and_ccid_layout_numbers_interfaces_and_endpoint_files_in_descriptor_order() {
    let layout = Layout::from_identity(&identity(FIDO_CCID, None)).expect("layout");
    let interfaces: Vec<(u8, Function)> = layout.interfaces.iter().map(|i| (i.number, i.function)).collect();
    assert_eq!(interfaces, [(0, Function::Fido), (1, Function::Ccid)]);
    let endpoints: Vec<(usize, u8, Role)> =
        layout.endpoints.iter().map(|e| (e.file_index, e.address, e.role)).collect();
    assert_eq!(
        endpoints,
        [
            (1, 0x04, Role::FidoOut),
            (2, 0x84, Role::FidoIn),
            (3, 0x02, Role::CcidBulkOut),
            (4, 0x82, Role::CcidBulkIn),
            (5, 0x83, Role::CcidInterruptIn),
        ]
    );
    assert_eq!(layout.interfaces[0].class_descriptor, HID_DESCRIPTOR.to_vec());
    assert_eq!(layout.interfaces[0].report_descriptor, lk_device::FIDO_REPORT_DESCRIPTOR.to_vec());
    assert_eq!(layout.interfaces[1].class_descriptor.len(), 54);
    assert!(layout.interfaces[1].report_descriptor.is_empty());
    assert_eq!(layout.ccid_max_message_length, 3072);
    assert_eq!(layout.interface_set(), FIDO_CCID);
    assert_eq!(layout.endpoint(Role::CcidBulkIn).map(|e| e.max_packet_size), Some(64));
    assert_eq!(layout.endpoint(Role::OtpIn), None);
    assert_eq!(layout.interface(1).map(|i| i.function), Some(Function::Ccid));
    assert_eq!(layout.interface(2), None);
    assert_eq!(layout.interface(0x0100), None);
}

#[test]
fn the_layout_with_all_three_interfaces_puts_otp_first_and_keeps_the_endpoint_numbers() {
    let layout = Layout::from_identity(&identity(ALL, None)).expect("layout");
    let interfaces: Vec<(u8, Function)> = layout.interfaces.iter().map(|i| (i.number, i.function)).collect();
    assert_eq!(interfaces, [(0, Function::Otp), (1, Function::Fido), (2, Function::Ccid)]);
    let endpoints: Vec<(usize, u8, Role)> =
        layout.endpoints.iter().map(|e| (e.file_index, e.address, e.role)).collect();
    assert_eq!(
        endpoints,
        [
            (1, 0x81, Role::OtpIn),
            (2, 0x04, Role::FidoOut),
            (3, 0x84, Role::FidoIn),
            (4, 0x02, Role::CcidBulkOut),
            (5, 0x82, Role::CcidBulkIn),
            (6, 0x83, Role::CcidInterruptIn),
        ]
    );
    assert_eq!(layout.interfaces[0].report_descriptor, lk_device::OTP_REPORT_DESCRIPTOR.to_vec());
}

#[test]
fn every_interface_combination_has_consecutive_interface_numbers_and_file_indices() {
    for interfaces in combinations() {
        let layout = Layout::from_identity(&identity(interfaces, None)).expect("layout");
        assert_eq!(layout.interface_set(), interfaces);
        for (n, interface) in layout.interfaces.iter().enumerate() {
            assert_eq!(usize::from(interface.number), n, "{interfaces:?}");
        }
        for (n, endpoint) in layout.endpoints.iter().enumerate() {
            assert_eq!(endpoint.file_index, n + 1, "{interfaces:?}");
            assert_eq!(endpoint.address & 0x80 != 0, endpoint.role.is_in(), "{interfaces:?}");
        }
        let expected =
            usize::from(interfaces.otp) + 2 * usize::from(interfaces.fido) + 3 * usize::from(interfaces.ccid);
        assert_eq!(layout.endpoints.len(), expected, "{interfaces:?}");
    }
}

#[test]
fn a_layout_needs_at_least_one_interface_matching_the_identity() {
    let none = UsbInterfaces { otp: false, fido: false, ccid: false };
    assert_eq!(Layout::from_identity(&identity(none, None)), Err(DescriptorError::InterfaceSet));
    let fido_only = identity(UsbInterfaces { otp: false, fido: true, ccid: false }, None);
    let claims_ccid = UsbIdentity { interfaces: FIDO_CCID, ..fido_only.clone() };
    assert_eq!(
        Layout::from_descriptor(&fido_only.configuration_descriptor(), &claims_ccid),
        Err(DescriptorError::InterfaceSet)
    );
}

#[test]
fn a_layout_refuses_unknown_or_repeated_interfaces() {
    let fido = identity(UsbInterfaces { otp: false, fido: true, ccid: false }, None);
    let vendor = [&[9u8, 4, 0, 0, 0, 0xFF, 0, 0, 0][..]].concat();
    assert_eq!(
        Layout::from_descriptor(&config_with(&vendor, 1), &fido),
        Err(DescriptorError::UnknownInterface { number: 0 })
    );
    let twice =
        [fido_body(), [&[9u8, 4, 1, 0, 2, 3, 0, 0, 0][..], &HID_DESCRIPTOR, &FIDO_OUT, &FIDO_IN].concat()].concat();
    assert_eq!(
        Layout::from_descriptor(&config_with(&twice, 2), &fido),
        Err(DescriptorError::UnknownInterface { number: 1 })
    );
}

#[test]
fn a_layout_refuses_endpoints_that_do_not_fit_their_interface() {
    let fido = identity(UsbInterfaces { otp: false, fido: true, ccid: false }, None);
    let bulk = [&FIDO_INTERFACE[..], &HID_DESCRIPTOR, &[7, 5, 0x04, 2, 64, 0, 0], &FIDO_IN].concat();
    assert_eq!(
        Layout::from_descriptor(&config_with(&bulk, 1), &fido),
        Err(DescriptorError::UnexpectedEndpoint { address: 0x04 })
    );
    let two_in = [&FIDO_INTERFACE[..], &HID_DESCRIPTOR, &FIDO_IN, &[7, 5, 0x85, 3, 64, 0, 2]].concat();
    assert_eq!(
        Layout::from_descriptor(&config_with(&two_in, 1), &fido),
        Err(DescriptorError::UnexpectedEndpoint { address: 0x85 })
    );
    let one = [&[9u8, 4, 0, 0, 1, 3, 0, 0, 0][..], &HID_DESCRIPTOR, &FIDO_IN].concat();
    assert_eq!(
        Layout::from_descriptor(&config_with(&one, 1), &fido),
        Err(DescriptorError::MissingEndpoint { function: Function::Fido })
    );
}

#[test]
fn a_layout_needs_the_ccid_message_length_from_the_class_descriptor() {
    let ccid = identity(UsbInterfaces { otp: false, fido: false, ccid: true }, None);
    let short = UsbIdentity { ccid_class_descriptor: vec![0x2C, 0x21].into_iter().chain([0; 42]).collect(), ..ccid };
    assert_eq!(Layout::from_identity(&short), Err(DescriptorError::CcidClassDescriptor));
}

#[test]
fn a_layout_refuses_a_hid_descriptor_whose_report_length_differs_from_the_report_descriptor() {
    let fido = identity(UsbInterfaces { otp: false, fido: true, ccid: false }, None);
    assert!(Layout::from_descriptor(&config_with(&fido_body(), 1), &fido).is_ok());
    let longer = [&FIDO_INTERFACE[..], &[9, 0x21, 0x10, 0x01, 0, 1, 0x22, 35, 0], &FIDO_OUT, &FIDO_IN].concat();
    assert_eq!(
        Layout::from_descriptor(&config_with(&longer, 1), &fido),
        Err(DescriptorError::ReportLength { interface: 0 })
    );
    let missing = [&[9u8, 4, 0, 0, 2, 3, 0, 0, 0][..], &FIDO_OUT, &FIDO_IN].concat();
    assert_eq!(
        Layout::from_descriptor(&config_with(&missing, 1), &fido),
        Err(DescriptorError::ReportLength { interface: 0 })
    );
    let other_report = UsbIdentity { fido_report_descriptor: vec![0xC0; 33], ..fido.clone() };
    assert_eq!(
        Layout::from_descriptor(&config_with(&fido_body(), 1), &other_report),
        Err(DescriptorError::ReportLength { interface: 0 })
    );
}

#[test]
fn descriptor_errors_describe_themselves_without_bytes() {
    let message = DescriptorError::Reserved { offset: 34, descriptor_type: 2 }.to_string();
    assert!(message.contains("0x02") && message.contains("34"), "{message}");
    let debug = format!("{:?}", Layout::from_identity(&identity(ALL, None)).expect("layout").interfaces[0]);
    assert!(debug.contains("77 bytes"), "{debug}");
}
