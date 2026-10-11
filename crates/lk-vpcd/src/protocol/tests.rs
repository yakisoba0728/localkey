//! vpcd framing and message tests: every control byte, every payload length class, the
//! length boundaries and the ways a stream can end.

use std::io::Cursor;

use super::*;

/// A reader that hands out at most one byte per call, with an `Interrupted` error before
/// every byte.
struct Trickle {
    bytes: Vec<u8>,
    at: usize,
    interrupt: bool,
}

impl Read for Trickle {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.interrupt = !self.interrupt;
        if self.interrupt {
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        match (self.bytes.get(self.at), buf.first_mut()) {
            (Some(&byte), Some(slot)) => {
                *slot = byte;
                self.at += 1;
                Ok(1)
            }
            _ => Ok(0),
        }
    }
}

#[test]
fn the_documented_defaults_are_port_35963_on_loopback() {
    assert_eq!(DEFAULT_PORT, 0x8C7B);
    assert_eq!(DEFAULT_ADDR.parse::<std::net::SocketAddr>().map(|addr| addr.port()), Ok(DEFAULT_PORT));
    assert!(DEFAULT_ADDR.parse::<std::net::SocketAddr>().is_ok_and(|addr| addr.ip().is_loopback()));
}

#[test]
fn control_bytes_are_those_of_vpcd_h() {
    assert_eq!(
        Control::ALL.map(Control::byte),
        [control::POWER_OFF, control::POWER_ON, control::RESET, control::GET_ATR]
    );
    assert_eq!([control::POWER_OFF, control::POWER_ON, control::RESET, control::GET_ATR], [0, 1, 2, 4]);
    for command in Control::ALL {
        assert_eq!(Control::from_byte(command.byte()), Some(command));
    }
    for byte in (0..=u8::MAX).filter(|byte| ![0, 1, 2, 4].contains(byte)) {
        assert_eq!(Control::from_byte(byte), None, "byte {byte:#04x}");
    }
}

#[test]
fn only_get_atr_is_answered() {
    let answered: Vec<Control> = Control::ALL.into_iter().filter(|command| command.answered()).collect();
    assert_eq!(answered, vec![Control::GetAtr]);
}

#[test]
fn a_one_byte_payload_is_a_control_command_and_anything_longer_an_apdu() {
    assert_eq!(Message::parse(&[0x00]), Message::Control(Control::PowerOff));
    assert_eq!(Message::parse(&[0x01]), Message::Control(Control::PowerOn));
    assert_eq!(Message::parse(&[0x02]), Message::Control(Control::Reset));
    assert_eq!(Message::parse(&[0x04]), Message::Control(Control::GetAtr));
    assert_eq!(Message::parse(&[0x03]), Message::UnknownControl(0x03));
    assert_eq!(Message::parse(&[0xFF]), Message::UnknownControl(0xFF));
    assert_eq!(Message::parse(&[]), Message::Empty);
    // Even a 2-byte payload whose first byte is a control byte is an APDU.
    assert_eq!(Message::parse(&[0x04, 0x00]), Message::Apdu(&[0x04, 0x00]));
    let select = [0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];
    assert_eq!(Message::parse(&select), Message::Apdu(&select));
}

#[test]
fn message_debug_shows_the_size_of_an_apdu_never_its_bytes() {
    let apdu = [0x00, 0x20, 0x00, 0x80, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36];
    let text = format!("{:?}", Message::parse(&apdu));
    assert_eq!(text, "Apdu(11 bytes)");
    assert_eq!(format!("{:?}", Message::parse(&[4])), "Control(GetAtr)");
    assert_eq!(Message::parse(&apdu).name(), "APDU");
    assert_eq!(Message::parse(&[4]).name(), "get ATR");
    assert_eq!(Control::Reset.to_string(), "reset");
}

#[test]
fn a_frame_is_the_big_endian_length_then_the_payload() {
    assert_eq!(encode(&[0x04]), Ok(vec![0x00, 0x01, 0x04]));
    assert_eq!(encode(&[]), Ok(vec![0x00, 0x00]));
    let payload: Vec<u8> = (0..300u16).map(|i| i as u8).collect();
    let frame = encode(&payload).expect("300 bytes fit");
    assert_eq!(&frame[..2], &[0x01, 0x2C]);
    assert_eq!(&frame[2..], &payload[..]);
}

#[test]
fn a_payload_of_65535_bytes_is_framed_and_one_more_is_refused() {
    let largest = vec![0xA5; MAX_PAYLOAD];
    let frame = encode(&largest).expect("the largest payload fits");
    assert_eq!(&frame[..2], &[0xFF, 0xFF]);
    assert_eq!(frame.len(), 2 + MAX_PAYLOAD);
    let error = encode(&vec![0; MAX_PAYLOAD + 1]).expect_err("one byte more does not fit");
    assert_eq!(error, TooLong { len: 65_536 });
    assert!(error.to_string().contains("65535"), "{error}");
}

#[test]
fn messages_are_read_back_in_order() {
    let mut stream = Vec::new();
    for payload in [&[0x04][..], &[], &[0x00, 0xA4, 0x04, 0x00], &[0x01]] {
        stream.extend(encode(payload).expect("small payloads fit"));
    }
    let mut cursor = Cursor::new(stream);
    assert_eq!(read_message(&mut cursor).expect("whole"), Some(vec![0x04]));
    assert_eq!(read_message(&mut cursor).expect("whole"), Some(vec![]));
    assert_eq!(read_message(&mut cursor).expect("whole"), Some(vec![0x00, 0xA4, 0x04, 0x00]));
    assert_eq!(read_message(&mut cursor).expect("whole"), Some(vec![0x01]));
    assert_eq!(read_message(&mut cursor).expect("a clean end"), None);
}

#[test]
fn the_largest_message_is_read_whole() {
    let payload: Vec<u8> = (0..MAX_PAYLOAD).map(|i| i as u8).collect();
    let mut cursor = Cursor::new(encode(&payload).expect("fits"));
    assert_eq!(read_message(&mut cursor).expect("whole"), Some(payload));
}

#[test]
fn a_stream_that_ends_inside_a_message_is_an_unexpected_end() {
    for cut in [&[0x00][..], &[0x00, 0x05, 0xAA, 0xBB]] {
        let error = read_message(&mut Cursor::new(cut.to_vec())).expect_err("truncated");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof, "{cut:02X?}");
    }
}

#[test]
fn messages_arriving_byte_by_byte_with_interruptions_are_read_whole() {
    let mut bytes = encode(&[0x00, 0xA4, 0x04, 0x00, 0x00]).expect("fits");
    bytes.extend(encode(&[0x04]).expect("fits"));
    let mut reader = Trickle { bytes, at: 0, interrupt: false };
    assert_eq!(read_message(&mut reader).expect("whole"), Some(vec![0x00, 0xA4, 0x04, 0x00, 0x00]));
    assert_eq!(read_message(&mut reader).expect("whole"), Some(vec![0x04]));
    assert_eq!(read_message(&mut reader).expect("a clean end"), None);
}

#[test]
fn a_read_error_is_passed_on() {
    struct Failing;
    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::ConnectionReset))
        }
    }
    let error = read_message(&mut Failing).expect_err("the error comes through");
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
}
