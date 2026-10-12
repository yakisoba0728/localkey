//! Codec tests: every type of the table, every size boundary, the header checks and the
//! IDENTITY layout (`docs/PROGRAM.md` "Frame format", "IDENTITY payload").

use super::*;

const HOST_TYPES: [u8; 7] = [FIDO_OUT, OTP_SET_FEATURE, OTP_GET_FEATURE, CCID_BULK_OUT, CCID_ABORT, TOUCH, BUS];
const DEVICE_TYPES: [u8; 8] =
    [IDENTITY, FIDO_IN, OTP_KEYBOARD, OTP_FEATURE, CCID_BULK_IN, CCID_INTERRUPT, PRESENCE, ERROR];

fn usb_identity(serial: Option<&str>) -> UsbIdentity {
    UsbIdentity {
        vendor_id: 0x1050,
        product_id: 0x0407,
        device_release: 0x0574,
        manufacturer: "Yubico".into(),
        product: "YubiKey OTP+FIDO+CCID".into(),
        serial: serial.map(String::from),
        interfaces: UsbInterfaces { otp: true, fido: true, ccid: true },
        fido_report_descriptor: lk_device::FIDO_REPORT_DESCRIPTOR.to_vec(),
        otp_report_descriptor: lk_device::OTP_REPORT_DESCRIPTOR.to_vec(),
        ccid_class_descriptor: (0..54).collect(),
    }
}

fn identity() -> Identity {
    Identity::from_usb(&usb_identity(Some("12345678")))
}

/// One frame of every type, with recognisable payloads.
fn every_frame() -> Vec<Frame> {
    vec![
        Frame::FidoOut([0x11; 64]),
        Frame::OtpSetFeature([0x22; 8]),
        Frame::OtpGetFeature,
        Frame::CcidBulkOut(vec![0x62, 0, 0, 0, 0, 0, 1, 0, 0, 0]),
        Frame::CcidAbort { slot: 0, seq: 7 },
        Frame::Touch(TouchEdge::Down),
        Frame::Bus(BusEvent::PowerCycle),
        Frame::Identity(identity()),
        Frame::FidoIn([0x33; 64]),
        Frame::OtpKeyboard([0x44; 8]),
        Frame::OtpFeature([0x55; 8]),
        Frame::CcidBulkIn(vec![0x80, 2, 0, 0, 0, 0, 1, 0, 0, 0, 0x90, 0x00]),
        Frame::CcidInterrupt(vec![0x50, 0x03]),
        Frame::Presence(true),
        Frame::Error("busy".into()),
    ]
}

/// A frame with a header of `length` and `frame_type` and `size` payload bytes.
fn raw(frame_type: u8, payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len() + 1).unwrap_or(u32::MAX);
    let mut out = length.to_be_bytes().to_vec();
    out.push(frame_type);
    out.extend_from_slice(payload);
    out
}

fn origin_of(frame_type: u8) -> Origin {
    if HOST_TYPES.contains(&frame_type) { Origin::Host } else { Origin::Device }
}

fn decode_all(bytes: &[u8], origin: Origin) -> Result<Frame, FrameError> {
    match decode(bytes, origin)? {
        Some((frame, used)) => {
            assert_eq!(used, bytes.len(), "the frame takes every byte");
            Ok(frame)
        }
        None => panic!("a whole frame decodes"),
    }
}

#[test]
fn every_frame_round_trips_through_encode_and_decode() -> Result<(), FrameError> {
    for frame in every_frame() {
        let bytes = frame.encode()?;
        assert_eq!(decode_all(&bytes, frame.origin())?, frame);
    }
    Ok(())
}

#[test]
fn encoded_frames_follow_the_table_byte_for_byte() -> Result<(), FrameError> {
    let mut fido = vec![0, 0, 0, 65, 0x01];
    fido.extend_from_slice(&[0x11; 64]);
    assert_eq!(Frame::FidoOut([0x11; 64]).encode()?, fido);
    let mut fido_in = vec![0, 0, 0, 65, 0x81];
    fido_in.extend_from_slice(&[0x33; 64]);
    assert_eq!(Frame::FidoIn([0x33; 64]).encode()?, fido_in);
    let cases: [(Frame, &[u8]); 16] = [
        (Frame::OtpSetFeature([1, 2, 3, 4, 5, 6, 7, 8]), &[0, 0, 0, 9, 0x02, 1, 2, 3, 4, 5, 6, 7, 8]),
        (Frame::OtpGetFeature, &[0, 0, 0, 1, 0x03]),
        (
            Frame::CcidBulkOut(vec![0x65, 0, 0, 0, 0, 0, 9, 0, 0, 0]),
            &[0, 0, 0, 11, 0x04, 0x65, 0, 0, 0, 0, 0, 9, 0, 0, 0],
        ),
        (Frame::CcidAbort { slot: 1, seq: 2 }, &[0, 0, 0, 3, 0x05, 1, 2]),
        (Frame::Touch(TouchEdge::Up), &[0, 0, 0, 2, 0x06, 0x00]),
        (Frame::Touch(TouchEdge::Down), &[0, 0, 0, 2, 0x06, 0x01]),
        (Frame::Bus(BusEvent::Reset), &[0, 0, 0, 2, 0x07, 0x00]),
        (Frame::Bus(BusEvent::Suspend), &[0, 0, 0, 2, 0x07, 0x01]),
        (Frame::Bus(BusEvent::Resume), &[0, 0, 0, 2, 0x07, 0x02]),
        (Frame::Bus(BusEvent::PowerCycle), &[0, 0, 0, 2, 0x07, 0x03]),
        (Frame::OtpKeyboard([9; 8]), &[0, 0, 0, 9, 0x82, 9, 9, 9, 9, 9, 9, 9, 9]),
        (Frame::OtpFeature([8; 8]), &[0, 0, 0, 9, 0x83, 8, 8, 8, 8, 8, 8, 8, 8]),
        (Frame::CcidBulkIn(vec![0xAA; 3]), &[0, 0, 0, 4, 0x84, 0xAA, 0xAA, 0xAA]),
        (Frame::CcidInterrupt(vec![0x50, 0x03]), &[0, 0, 0, 3, 0x85, 0x50, 0x03]),
        (Frame::Presence(false), &[0, 0, 0, 2, 0x86, 0x00]),
        (Frame::Error("busy".into()), &[0, 0, 0, 5, 0xFF, b'b', b'u', b's', b'y']),
    ];
    for (frame, bytes) in cases {
        assert_eq!(frame.encode()?, bytes, "{frame:?}");
        assert_eq!(decode_all(bytes, frame.origin())?, frame);
    }
    assert_eq!(Frame::Presence(true).encode()?, [0, 0, 0, 2, 0x86, 0x01]);
    Ok(())
}

#[test]
fn frame_types_and_origins_match_the_table() {
    let types: Vec<u8> = every_frame().iter().map(Frame::frame_type).collect();
    let mut expected = HOST_TYPES.to_vec();
    expected.extend_from_slice(&DEVICE_TYPES);
    assert_eq!(types, expected);
    for frame in every_frame() {
        assert_eq!(frame.origin(), origin_of(frame.frame_type()), "{frame:?}");
    }
}

#[test]
fn fixed_size_types_refuse_one_byte_less_and_one_byte_more() {
    let fixed: [(u8, usize); 10] = [
        (FIDO_OUT, 64),
        (OTP_SET_FEATURE, 8),
        (OTP_GET_FEATURE, 0),
        (CCID_ABORT, 2),
        (TOUCH, 1),
        (BUS, 1),
        (FIDO_IN, 64),
        (OTP_KEYBOARD, 8),
        (OTP_FEATURE, 8),
        (PRESENCE, 1),
    ];
    for (frame_type, size) in fixed {
        let origin = origin_of(frame_type);
        assert!(decode_all(&raw(frame_type, &vec![0; size]), origin).is_ok(), "type {frame_type:#04x}");
        let longer = size + 1;
        assert_eq!(
            decode(&raw(frame_type, &vec![0; longer]), origin),
            Err(FrameError::PayloadSize { frame_type, size: longer })
        );
        if let Some(shorter) = size.checked_sub(1) {
            assert_eq!(
                decode(&raw(frame_type, &vec![0; shorter]), origin),
                Err(FrameError::PayloadSize { frame_type, size: shorter })
            );
        }
    }
}

#[test]
fn a_ccid_bulk_out_message_needs_at_least_its_ten_byte_header() -> Result<(), FrameError> {
    assert_eq!(
        decode(&raw(CCID_BULK_OUT, &[0; 9]), Origin::Host),
        Err(FrameError::PayloadSize { frame_type: CCID_BULK_OUT, size: 9 })
    );
    assert_eq!(decode_all(&raw(CCID_BULK_OUT, &[0; 10]), Origin::Host)?, Frame::CcidBulkOut(vec![0; 10]));
    assert_eq!(
        decode(&raw(CCID_BULK_OUT, &[]), Origin::Host),
        Err(FrameError::PayloadSize { frame_type: CCID_BULK_OUT, size: 0 })
    );
    Ok(())
}

#[test]
fn variable_size_types_accept_an_empty_and_a_maximal_payload() -> Result<(), FrameError> {
    let maximal = vec![b'x'; MAX_PAYLOAD];
    assert_eq!(decode_all(&raw(CCID_BULK_OUT, &maximal), Origin::Host)?, Frame::CcidBulkOut(maximal.clone()));
    for frame_type in [CCID_BULK_IN, CCID_INTERRUPT, ERROR] {
        assert_eq!(decode_all(&raw(frame_type, &[]), Origin::Device)?.frame_type(), frame_type);
        assert_eq!(decode_all(&raw(frame_type, &maximal), Origin::Device)?.frame_type(), frame_type);
    }
    assert_eq!(decode_all(&raw(ERROR, &[]), Origin::Device)?, Frame::Error(String::new()));
    Ok(())
}

#[test]
fn a_payload_one_byte_over_the_cap_is_refused_on_both_sides() {
    let over = vec![0; MAX_PAYLOAD + 1];
    for frame_type in [CCID_BULK_OUT, CCID_BULK_IN, CCID_INTERRUPT, ERROR] {
        assert_eq!(decode(&raw(frame_type, &over), origin_of(frame_type)), Err(FrameError::Length(MAX_LENGTH + 1)));
    }
    assert_eq!(Frame::CcidBulkOut(over.clone()).encode(), Err(FrameError::Length(MAX_LENGTH + 1)));
    assert_eq!(Frame::CcidBulkIn(over.clone()).encode(), Err(FrameError::Length(MAX_LENGTH + 1)));
    assert_eq!(Frame::CcidInterrupt(over).encode(), Err(FrameError::Length(MAX_LENGTH + 1)));
    assert_eq!(Frame::Error("x".repeat(MAX_PAYLOAD + 1)).encode(), Err(FrameError::Length(MAX_LENGTH + 1)));
    assert!(Frame::Error("x".repeat(MAX_PAYLOAD)).encode().is_ok());
}

#[test]
fn length_zero_is_refused_from_the_length_field_alone() {
    for origin in [Origin::Host, Origin::Device] {
        assert_eq!(decode(&[0, 0, 0, 0], origin), Err(FrameError::Length(0)));
        assert_eq!(decode(&[0, 0, 0, 0, FIDO_OUT, 1, 2], origin), Err(FrameError::Length(0)));
    }
}

#[test]
fn a_length_over_the_cap_is_refused_before_the_payload_arrives() {
    let over = (MAX_LENGTH + 1).to_be_bytes();
    assert_eq!(over, [0x00, 0x10, 0x00, 0x02]);
    assert_eq!(decode(&over, Origin::Host), Err(FrameError::Length(MAX_LENGTH + 1)));
    assert_eq!(decode(&u32::MAX.to_be_bytes(), Origin::Device), Err(FrameError::Length(u32::MAX)));
    // The largest length is fine and waits for its payload.
    let mut header = MAX_LENGTH.to_be_bytes().to_vec();
    assert_eq!(decode(&header, Origin::Host), Ok(None));
    header.push(CCID_BULK_OUT);
    assert_eq!(decode(&header, Origin::Host), Ok(None));
}

#[test]
fn a_wrong_size_or_type_is_refused_from_the_header_alone() {
    // 64-byte FIDO report announced as 1000 bytes: refused without the payload.
    assert_eq!(
        decode(&[0, 0, 0x03, 0xE9, FIDO_OUT], Origin::Host),
        Err(FrameError::PayloadSize { frame_type: FIDO_OUT, size: 1000 })
    );
    assert_eq!(decode(&[0, 0, 0, 1, 0x08], Origin::Host), Err(FrameError::UnknownType(0x08)));
}

#[test]
fn each_side_accepts_exactly_the_other_sides_types() {
    for frame_type in 0..=u8::MAX {
        for origin in [Origin::Host, Origin::Device] {
            // A valid length: an accepted type waits for the payload or refuses its size,
            // and only a type the side does not accept is unknown.
            let result = decode(&[0x00, 0x0F, 0xFF, 0xFF, frame_type], origin);
            let accepted = match origin {
                Origin::Host => HOST_TYPES.contains(&frame_type),
                Origin::Device => DEVICE_TYPES.contains(&frame_type),
            };
            if accepted {
                assert_ne!(result, Err(FrameError::UnknownType(frame_type)), "type {frame_type:#04x}");
            } else {
                assert_eq!(result, Err(FrameError::UnknownType(frame_type)), "type {frame_type:#04x} from {origin:?}");
            }
        }
    }
}

#[test]
fn every_truncation_of_a_frame_waits_for_more_bytes() -> Result<(), FrameError> {
    for frame in every_frame() {
        let bytes = frame.encode()?;
        for end in 0..bytes.len() {
            assert_eq!(decode(&bytes[..end], frame.origin()), Ok(None), "{frame:?} cut at {end}");
        }
    }
    Ok(())
}

#[test]
fn decode_reports_the_bytes_it_used_and_leaves_the_next_frame() -> Result<(), FrameError> {
    let first = Frame::Touch(TouchEdge::Down).encode()?;
    let second = Frame::CcidAbort { slot: 0, seq: 1 }.encode()?;
    let mut stream = first.clone();
    stream.extend_from_slice(&second);
    stream.extend_from_slice(&[0, 0]);
    let Some((frame, used)) = decode(&stream, Origin::Host)? else { panic!("first frame is whole") };
    assert_eq!((frame, used), (Frame::Touch(TouchEdge::Down), first.len()));
    let Some((frame, used)) = decode(&stream[used..], Origin::Host)? else { panic!("second frame is whole") };
    assert_eq!((frame, used), (Frame::CcidAbort { slot: 0, seq: 1 }, second.len()));
    assert_eq!(decode(&stream[first.len() + second.len()..], Origin::Host), Ok(None));
    Ok(())
}

#[test]
fn one_byte_values_outside_the_table_are_refused() {
    for value in 2..=u8::MAX {
        assert_eq!(decode(&raw(TOUCH, &[value]), Origin::Host), Err(FrameError::Value { frame_type: TOUCH, value }));
        assert_eq!(
            decode(&raw(PRESENCE, &[value]), Origin::Device),
            Err(FrameError::Value { frame_type: PRESENCE, value })
        );
    }
    for value in 4..=u8::MAX {
        assert_eq!(decode(&raw(BUS, &[value]), Origin::Host), Err(FrameError::Value { frame_type: BUS, value }));
    }
}

#[test]
fn an_error_reason_must_be_utf8() -> Result<(), FrameError> {
    assert_eq!(decode(&raw(ERROR, &[0xC3]), Origin::Device), Err(FrameError::Utf8 { frame_type: ERROR }));
    assert_eq!(
        decode_all(&raw(ERROR, "wrong size \u{fc}".as_bytes()), Origin::Device)?,
        Frame::Error("wrong size \u{fc}".into())
    );
    Ok(())
}

#[test]
fn identity_follows_the_documented_layout() -> Result<(), FrameError> {
    let usb = usb_identity(Some("12345678"));
    let payload = Identity::from_usb(&usb).encode()?;
    let mut expected = vec![0x10, 0x50, 0x04, 0x07, 0x05, 0x74, 0b111];
    let device = usb.device_descriptor();
    let configuration = usb.configuration_descriptor();
    for field in [
        &b"Yubico"[..],
        b"YubiKey OTP+FIDO+CCID",
        b"12345678",
        &device,
        &configuration,
        &lk_device::FIDO_REPORT_DESCRIPTOR,
        &lk_device::OTP_REPORT_DESCRIPTOR,
    ] {
        expected.extend_from_slice(&u16::try_from(field.len()).unwrap_or(u16::MAX).to_be_bytes());
        expected.extend_from_slice(field);
    }
    assert_eq!(payload, expected);
    assert_eq!(Identity::parse(&payload)?, Identity::from_usb(&usb));
    Ok(())
}

#[test]
fn identity_carries_the_descriptors_built_from_the_usb_identity() {
    let usb = usb_identity(None);
    let identity = Identity::from_usb(&usb);
    assert_eq!(identity.device_descriptor, usb.device_descriptor());
    assert_eq!(identity.configuration_descriptor, usb.configuration_descriptor());
    // The CCID class descriptor travels inside the configuration descriptor.
    let ccid = usb.ccid_class_descriptor.as_slice();
    assert!(identity.configuration_descriptor.windows(ccid.len()).any(|window| window == ccid));
}

#[test]
fn identity_interface_bits_name_otp_fido_and_ccid() -> Result<(), FrameError> {
    for bits in 0u8..8 {
        let mut usb = usb_identity(None);
        usb.interfaces = UsbInterfaces { otp: bits & 1 != 0, fido: bits & 2 != 0, ccid: bits & 4 != 0 };
        let payload = Identity::from_usb(&usb).encode()?;
        assert_eq!(payload[6], bits);
        assert_eq!(Identity::parse(&payload)?.interfaces, usb.interfaces);
    }
    Ok(())
}

#[test]
fn a_missing_serial_travels_as_an_empty_field_and_reads_back_as_none() -> Result<(), FrameError> {
    let identity = Identity::from_usb(&usb_identity(None));
    let payload = identity.encode()?;
    let serial_at = 7 + 2 + "Yubico".len() + 2 + "YubiKey OTP+FIDO+CCID".len();
    assert_eq!(&payload[serial_at..serial_at + 2], &[0, 0]);
    assert_eq!(Identity::parse(&payload)?.serial, None);
    let empty = Identity { serial: Some(String::new()), ..identity };
    assert_eq!(Identity::parse(&empty.encode()?)?.serial, None);
    Ok(())
}

#[test]
fn every_truncation_of_an_identity_is_refused() -> Result<(), FrameError> {
    let payload = identity().encode()?;
    for end in 0..payload.len() {
        assert!(Identity::parse(&payload[..end]).is_err(), "cut at {end}");
    }
    // As a frame, a payload shorter than the fixed part is refused from the header.
    assert_eq!(
        decode(&raw(IDENTITY, &payload[..IDENTITY_MIN - 1]), Origin::Device),
        Err(FrameError::PayloadSize { frame_type: IDENTITY, size: IDENTITY_MIN - 1 })
    );
    assert!(matches!(decode(&raw(IDENTITY, &payload[..IDENTITY_MIN]), Origin::Device), Err(FrameError::Identity(_))));
    Ok(())
}

#[test]
fn identity_with_trailing_bytes_is_refused() -> Result<(), FrameError> {
    let mut payload = identity().encode()?;
    payload.push(0);
    assert_eq!(Identity::parse(&payload), Err(FrameError::Identity("trailing bytes")));
    Ok(())
}

#[test]
fn identity_needs_an_eighteen_byte_device_descriptor() -> Result<(), FrameError> {
    let usb = usb_identity(None);
    let short = |len: usize| {
        let mut payload = vec![0x10, 0x50, 0x04, 0x07, 0x05, 0x74, 0b111];
        for field in [&b"Y"[..], b"P", b"", &usb.device_descriptor()[..len], b"", b"", b""] {
            payload.extend_from_slice(&u16::try_from(field.len()).unwrap_or(u16::MAX).to_be_bytes());
            payload.extend_from_slice(field);
        }
        Identity::parse(&payload)
    };
    assert_eq!(short(17), Err(FrameError::Identity("device descriptor is not 18 bytes")));
    assert_eq!(short(18)?.device_descriptor, usb.device_descriptor());
    Ok(())
}

#[test]
fn identity_refuses_undefined_interface_bits() -> Result<(), FrameError> {
    let mut payload = identity().encode()?;
    for bit in 3..8 {
        payload[6] = 0b111 | 1 << bit;
        assert_eq!(Identity::parse(&payload), Err(FrameError::Identity("undefined interface bits")));
    }
    Ok(())
}

#[test]
fn identity_strings_must_be_utf8() -> Result<(), FrameError> {
    let mut payload = identity().encode()?;
    // The first manufacturer byte.
    payload[9] = 0xFF;
    assert_eq!(Identity::parse(&payload), Err(FrameError::Utf8 { frame_type: IDENTITY }));
    Ok(())
}

#[test]
fn an_identity_field_longer_than_u16_cannot_be_encoded() {
    let long = Identity { configuration_descriptor: vec![0; 65_536], ..identity() };
    assert_eq!(long.encode(), Err(FrameError::Identity("field longer than 65535 bytes")));
    assert_eq!(Frame::Identity(long).encode(), Err(FrameError::Identity("field longer than 65535 bytes")));
    let longest = Identity { configuration_descriptor: vec![0; 65_535], ..identity() };
    assert!(longest.encode().is_ok());
}

#[test]
fn encode_refuses_what_decode_would_refuse() {
    assert_eq!(
        Frame::CcidBulkOut(vec![0; 9]).encode(),
        Err(FrameError::PayloadSize { frame_type: CCID_BULK_OUT, size: 9 })
    );
    assert!(Frame::CcidBulkOut(vec![0; 10]).encode().is_ok());
}

#[test]
fn host_inputs_map_to_host_frames_and_back() {
    let inputs = [
        HostInput::FidoReport([1; 64]),
        HostInput::OtpSetFeature([2; 8]),
        HostInput::OtpGetFeature,
        HostInput::Ccid(vec![3; 12]),
        HostInput::CcidControlAbort { slot: 4, seq: 5 },
        HostInput::Touch(TouchEdge::Up),
        HostInput::Touch(TouchEdge::Down),
        HostInput::Bus(BusEvent::Reset),
        HostInput::Bus(BusEvent::Suspend),
        HostInput::Bus(BusEvent::Resume),
        HostInput::Bus(BusEvent::PowerCycle),
    ];
    for input in inputs {
        let frame = Frame::from_input(&input);
        assert_eq!(frame.origin(), Origin::Host);
        assert_eq!(frame.into_input(), Some(input));
    }
    for frame in every_frame().into_iter().filter(|frame| frame.origin() == Origin::Device) {
        assert_eq!(frame.into_input(), None);
    }
}

#[test]
fn outputs_map_to_device_frames_and_back() {
    let outputs = [
        (Output::FidoReport([1; 64]), FIDO_IN),
        (Output::OtpFeature([2; 8]), OTP_FEATURE),
        (Output::OtpKeyboard([3; 8]), OTP_KEYBOARD),
        (Output::Ccid(vec![4; 10]), CCID_BULK_IN),
        (Output::CcidInterrupt(vec![0x50, 0x03]), CCID_INTERRUPT),
        (Output::PresenceIndicator(true), PRESENCE),
        (Output::PresenceIndicator(false), PRESENCE),
    ];
    for (output, frame_type) in outputs {
        let Some(frame) = Frame::from_output(output.clone()) else { panic!("{output:?} has a frame") };
        assert_eq!(frame.frame_type(), frame_type);
        assert_eq!(frame.into_output(), Some(output));
    }
    let all = UsbInterfaces { otp: true, fido: true, ccid: true };
    assert_eq!(Frame::from_output(Output::Reenumerate(all)), None);
    for frame in every_frame() {
        let carries_output = !matches!(frame.frame_type(), IDENTITY | ERROR) && frame.origin() == Origin::Device;
        assert_eq!(frame.into_output().is_some(), carries_output);
    }
}

#[test]
fn error_reasons_name_types_and_sizes() {
    assert_eq!(FrameError::Length(0).to_string(), "frame length 0 is outside 1..=1048577");
    assert_eq!(FrameError::UnknownType(0x81).to_string(), "unknown frame type 0x81");
    assert_eq!(
        FrameError::PayloadSize { frame_type: 0x01, size: 63 }.to_string(),
        "frame type 0x01 cannot carry a 63-byte payload"
    );
    assert_eq!(FrameError::Value { frame_type: 0x06, value: 2 }.to_string(), "frame type 0x06 has no value 0x02");
    assert_eq!(FrameError::Identity("trailing bytes").to_string(), "malformed IDENTITY: trailing bytes");
    assert_eq!(FrameError::Utf8 { frame_type: 0xFF }.to_string(), "frame type 0xff carries invalid UTF-8");
}

#[test]
fn frame_cleanup_wipes_all_payload_kinds() {
    let mut frames = [Frame::FidoOut([0xA5; 64]), Frame::FidoIn([0xA5; 64]),
        Frame::OtpSetFeature([0xA5; 8]), Frame::OtpKeyboard([0xA5; 8]), Frame::OtpFeature([0xA5; 8]),
        Frame::CcidBulkOut(vec![0xA5; 16]), Frame::CcidBulkIn(vec![0xA5; 16]), Frame::CcidInterrupt(vec![0xA5; 2])];
    for frame in &mut frames {
        frame.wipe();
        match frame {
            Frame::FidoOut(report) | Frame::FidoIn(report) => assert_eq!(*report, [0; 64]),
            Frame::OtpSetFeature(report) | Frame::OtpKeyboard(report) | Frame::OtpFeature(report) => assert_eq!(*report, [0; 8]),
            Frame::CcidBulkOut(bytes) | Frame::CcidBulkIn(bytes) | Frame::CcidInterrupt(bytes) => assert!(bytes.is_empty()),
            _ => panic!("only payload frames are tested"),
        }
    }
}
