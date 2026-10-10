//! The wire codec (`docs/PROGRAM.md` "lk-wire", "Frame format"): frames, the IDENTITY
//! payload, and the mapping between frames and the engine's inputs and outputs. Pure: no
//! I/O, no threads.
//!
//! ```text
//! frame   = length:u32be  type:u8  payload
//! length  = 1 + payload length, at most 1 + 1_048_576
//! ```
//!
//! Each side accepts only the other side's frame types ([`Origin`]): the server reads host
//! frames (`0x01..=0x07`), a client reads device frames (`0x80..=0x86`, `0xFF`). The length
//! and the type are checked as soon as the five header bytes are there, so a frame that is
//! out of range is refused before its payload is buffered.

use core::fmt;

use lk_core::UsbInterfaces;
use lk_device::{BusEvent, Output, TouchEdge, UsbIdentity};
use lk_run::HostInput;

/// The largest payload a frame carries.
pub const MAX_PAYLOAD: usize = 1_048_576;
/// The largest value of the length field: the type byte plus [`MAX_PAYLOAD`].
pub const MAX_LENGTH: u32 = 1 + MAX_PAYLOAD as u32;
/// Bytes before the payload: the length field and the type byte.
pub const HEADER_LEN: usize = 5;

/// The type byte of every frame in the table.
pub mod frame_type {
    /// Host → device: one 64-byte CTAPHID output report (`Input::FidoReport`).
    pub const FIDO_OUT: u8 = 0x01;
    /// Host → device: one 8-byte OTP feature report (`Input::OtpSetFeature`).
    pub const OTP_SET_FEATURE: u8 = 0x02;
    /// Host → device: read the OTP feature report (`Input::OtpGetFeature`; answer `0x83`).
    pub const OTP_GET_FEATURE: u8 = 0x03;
    /// Host → device: one CCID bulk-out message, at least the 10-byte header (`Input::Ccid`).
    pub const CCID_BULK_OUT: u8 = 0x04;
    /// Host → device: the CCID class request ABORT, `slot, seq` (`Input::CcidControlAbort`).
    pub const CCID_ABORT: u8 = 0x05;
    /// Host → device: `0x00` up, `0x01` down (`Input::Touch`).
    pub const TOUCH: u8 = 0x06;
    /// Host → device: `0x00` reset, `0x01` suspend, `0x02` resume, `0x03` power cycle
    /// (`Input::Bus`).
    pub const BUS: u8 = 0x07;
    /// Device → host: the identity, first on every connection and after every
    /// re-enumeration.
    pub const IDENTITY: u8 = 0x80;
    /// Device → host: one 64-byte CTAPHID input report (`Output::FidoReport`).
    pub const FIDO_IN: u8 = 0x81;
    /// Device → host: one 8-byte keyboard report (`Output::OtpKeyboard`).
    pub const OTP_KEYBOARD: u8 = 0x82;
    /// Device → host: the 8-byte OTP feature report (`Output::OtpFeature`).
    pub const OTP_FEATURE: u8 = 0x83;
    /// Device → host: one CCID bulk-in message (`Output::Ccid`).
    pub const CCID_BULK_IN: u8 = 0x84;
    /// Device → host: one CCID interrupt-in message (`Output::CcidInterrupt`).
    pub const CCID_INTERRUPT: u8 = 0x85;
    /// Device → host: `0x00` idle, `0x01` waiting for touch (`Output::PresenceIndicator`).
    pub const PRESENCE: u8 = 0x86;
    /// Device → host: a UTF-8 reason; the server closes the connection after it.
    pub const ERROR: u8 = 0xFF;
}

use frame_type::*;

/// IDENTITY interface bits (`docs/PROGRAM.md` "IDENTITY payload").
const INTERFACE_OTP: u8 = 0x01;
const INTERFACE_FIDO: u8 = 0x02;
const INTERFACE_CCID: u8 = 0x04;
/// The fixed part of IDENTITY: IDs, release, interfaces, and the seven length fields.
const IDENTITY_MIN: usize = 7 + 7 * 2;
/// The length of a USB device descriptor (USB 2.0 §9.6.1).
const DEVICE_DESCRIPTOR_LEN: usize = 18;

/// Which side of the wire sends a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Host → device (`0x01..=0x07`): what the server reads.
    Host,
    /// Device → host (`0x80..=0x86`, `0xFF`): what a client reads.
    Device,
}

/// Why bytes are not a frame of the table. The `Display` text is the reason the server
/// sends in ERROR; it names types and sizes, never payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// The length field is 0 or larger than [`MAX_LENGTH`].
    Length(u32),
    /// A type the receiving side does not accept.
    UnknownType(u8),
    /// A payload size the type does not allow.
    PayloadSize { frame_type: u8, size: usize },
    /// A one-byte payload outside the table (TOUCH, BUS, PRESENCE).
    Value { frame_type: u8, value: u8 },
    /// An IDENTITY payload that does not follow its layout.
    Identity(&'static str),
    /// An IDENTITY string or ERROR reason that is not UTF-8.
    Utf8 { frame_type: u8 },
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::Length(length) => write!(f, "frame length {length} is outside 1..={MAX_LENGTH}"),
            FrameError::UnknownType(frame_type) => write!(f, "unknown frame type 0x{frame_type:02x}"),
            FrameError::PayloadSize { frame_type, size } => {
                write!(f, "frame type 0x{frame_type:02x} cannot carry a {size}-byte payload")
            }
            FrameError::Value { frame_type, value } => {
                write!(f, "frame type 0x{frame_type:02x} has no value 0x{value:02x}")
            }
            FrameError::Identity(reason) => write!(f, "malformed IDENTITY: {reason}"),
            FrameError::Utf8 { frame_type } => write!(f, "frame type 0x{frame_type:02x} carries invalid UTF-8"),
        }
    }
}

impl std::error::Error for FrameError {}

/// One frame of the table, typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// `0x01`
    FidoOut([u8; 64]),
    /// `0x02`
    OtpSetFeature([u8; 8]),
    /// `0x03`
    OtpGetFeature,
    /// `0x04`
    CcidBulkOut(Vec<u8>),
    /// `0x05`
    CcidAbort { slot: u8, seq: u8 },
    /// `0x06`
    Touch(TouchEdge),
    /// `0x07`
    Bus(BusEvent),
    /// `0x80`
    Identity(Identity),
    /// `0x81`
    FidoIn([u8; 64]),
    /// `0x82`
    OtpKeyboard([u8; 8]),
    /// `0x83`
    OtpFeature([u8; 8]),
    /// `0x84`
    CcidBulkIn(Vec<u8>),
    /// `0x85`
    CcidInterrupt(Vec<u8>),
    /// `0x86`
    Presence(bool),
    /// `0xFF`
    Error(String),
}

impl Frame {
    /// The type byte.
    pub fn frame_type(&self) -> u8 {
        match self {
            Frame::FidoOut(_) => FIDO_OUT,
            Frame::OtpSetFeature(_) => OTP_SET_FEATURE,
            Frame::OtpGetFeature => OTP_GET_FEATURE,
            Frame::CcidBulkOut(_) => CCID_BULK_OUT,
            Frame::CcidAbort { .. } => CCID_ABORT,
            Frame::Touch(_) => TOUCH,
            Frame::Bus(_) => BUS,
            Frame::Identity(_) => IDENTITY,
            Frame::FidoIn(_) => FIDO_IN,
            Frame::OtpKeyboard(_) => OTP_KEYBOARD,
            Frame::OtpFeature(_) => OTP_FEATURE,
            Frame::CcidBulkIn(_) => CCID_BULK_IN,
            Frame::CcidInterrupt(_) => CCID_INTERRUPT,
            Frame::Presence(_) => PRESENCE,
            Frame::Error(_) => ERROR,
        }
    }

    /// The side that sends this frame.
    pub fn origin(&self) -> Origin {
        if self.frame_type() < 0x80 { Origin::Host } else { Origin::Device }
    }

    /// The whole frame: length, type and payload. Refuses what [`decode`] would refuse, so
    /// every encoded frame decodes to itself.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let frame_type = self.frame_type();
        let mut out = vec![0, 0, 0, 0, frame_type];
        match self {
            Frame::FidoOut(report) | Frame::FidoIn(report) => out.extend_from_slice(report),
            Frame::OtpSetFeature(report) | Frame::OtpKeyboard(report) | Frame::OtpFeature(report) => {
                out.extend_from_slice(report);
            }
            Frame::OtpGetFeature => {}
            Frame::CcidBulkOut(message) | Frame::CcidBulkIn(message) | Frame::CcidInterrupt(message) => {
                out.extend_from_slice(message);
            }
            Frame::CcidAbort { slot, seq } => out.extend_from_slice(&[*slot, *seq]),
            Frame::Touch(edge) => out.push(touch_byte(*edge)),
            Frame::Bus(event) => out.push(bus_byte(*event)),
            Frame::Identity(identity) => out.extend_from_slice(&identity.encode()?),
            Frame::Presence(waiting) => out.push(u8::from(*waiting)),
            Frame::Error(reason) => out.extend_from_slice(reason.as_bytes()),
        }
        let length = u32::try_from(out.len() - HEADER_LEN + 1).unwrap_or(u32::MAX);
        check_header(self.origin(), length, frame_type)?;
        out[..4].copy_from_slice(&length.to_be_bytes());
        Ok(out)
    }

    /// The frame that carries a host input.
    pub fn from_input(input: &HostInput) -> Frame {
        match input {
            HostInput::FidoReport(report) => Frame::FidoOut(*report),
            HostInput::OtpSetFeature(report) => Frame::OtpSetFeature(*report),
            HostInput::OtpGetFeature => Frame::OtpGetFeature,
            HostInput::Ccid(message) => Frame::CcidBulkOut(message.clone()),
            HostInput::CcidControlAbort { slot, seq } => Frame::CcidAbort { slot: *slot, seq: *seq },
            HostInput::Touch(edge) => Frame::Touch(*edge),
            HostInput::Bus(event) => Frame::Bus(*event),
        }
    }

    /// The host input a host frame carries; `None` for device frames.
    pub fn into_input(self) -> Option<HostInput> {
        Some(match self {
            Frame::FidoOut(report) => HostInput::FidoReport(report),
            Frame::OtpSetFeature(report) => HostInput::OtpSetFeature(report),
            Frame::OtpGetFeature => HostInput::OtpGetFeature,
            Frame::CcidBulkOut(message) => HostInput::Ccid(message),
            Frame::CcidAbort { slot, seq } => HostInput::CcidControlAbort { slot, seq },
            Frame::Touch(edge) => HostInput::Touch(edge),
            Frame::Bus(event) => HostInput::Bus(event),
            _ => return None,
        })
    }

    /// The frame that carries a device output; `None` for `Output::Reenumerate`, which the
    /// runner turns into an enumeration (an IDENTITY frame) instead.
    pub fn from_output(output: Output) -> Option<Frame> {
        Some(match output {
            Output::FidoReport(report) => Frame::FidoIn(report),
            Output::OtpFeature(report) => Frame::OtpFeature(report),
            Output::OtpKeyboard(report) => Frame::OtpKeyboard(report),
            Output::Ccid(message) => Frame::CcidBulkIn(message),
            Output::CcidInterrupt(message) => Frame::CcidInterrupt(message),
            Output::PresenceIndicator(waiting) => Frame::Presence(waiting),
            Output::Reenumerate(_) => return None,
        })
    }

    /// The device output a device frame carries; `None` for IDENTITY, ERROR and host
    /// frames.
    pub fn into_output(self) -> Option<Output> {
        Some(match self {
            Frame::FidoIn(report) => Output::FidoReport(report),
            Frame::OtpFeature(report) => Output::OtpFeature(report),
            Frame::OtpKeyboard(report) => Output::OtpKeyboard(report),
            Frame::CcidBulkIn(message) => Output::Ccid(message),
            Frame::CcidInterrupt(message) => Output::CcidInterrupt(message),
            Frame::Presence(waiting) => Output::PresenceIndicator(waiting),
            _ => return None,
        })
    }
}

/// Decode the first frame in `buf`, sent by `origin`.
///
/// `Ok(None)` means `buf` holds only part of a frame. `Ok(Some((frame, used)))` gives the
/// frame and the number of bytes it took; the rest of `buf` is the next frame. An error is
/// final: the stream is not a frame stream from that point on. The length is checked once
/// its four bytes are there, the type and payload size once the type byte is.
pub fn decode(buf: &[u8], origin: Origin) -> Result<Option<(Frame, usize)>, FrameError> {
    let Some(&length) = buf.first_chunk::<4>() else {
        return Ok(None);
    };
    let length = u32::from_be_bytes(length);
    check_length(length)?;
    let Some(&frame_type) = buf.get(4) else {
        return Ok(None);
    };
    let size = check_header(origin, length, frame_type)?;
    let Some(payload) = buf.get(HEADER_LEN..HEADER_LEN + size) else {
        return Ok(None);
    };
    Ok(Some((parse(frame_type, payload)?, HEADER_LEN + size)))
}

/// How many payload bytes a type allows.
#[derive(Debug, Clone, Copy)]
enum Size {
    Exact(usize),
    AtLeast(usize),
}

/// The payload rule of each type in the table, for the side that sends it.
fn payload_rule(origin: Origin, frame_type: u8) -> Option<Size> {
    let rule = match (origin, frame_type) {
        (Origin::Host, FIDO_OUT) => Size::Exact(64),
        (Origin::Host, OTP_SET_FEATURE) => Size::Exact(8),
        (Origin::Host, OTP_GET_FEATURE) => Size::Exact(0),
        (Origin::Host, CCID_BULK_OUT) => Size::AtLeast(10),
        (Origin::Host, CCID_ABORT) => Size::Exact(2),
        (Origin::Host, TOUCH | BUS) => Size::Exact(1),
        (Origin::Device, IDENTITY) => Size::AtLeast(IDENTITY_MIN),
        (Origin::Device, FIDO_IN) => Size::Exact(64),
        (Origin::Device, OTP_KEYBOARD | OTP_FEATURE) => Size::Exact(8),
        (Origin::Device, CCID_BULK_IN | CCID_INTERRUPT | ERROR) => Size::AtLeast(0),
        (Origin::Device, PRESENCE) => Size::Exact(1),
        _ => return None,
    };
    Some(rule)
}

fn check_length(length: u32) -> Result<(), FrameError> {
    if length == 0 || length > MAX_LENGTH { Err(FrameError::Length(length)) } else { Ok(()) }
}

/// Check the header fields and return the payload size.
fn check_header(origin: Origin, length: u32, frame_type: u8) -> Result<usize, FrameError> {
    check_length(length)?;
    let size = (length - 1) as usize;
    let fits = match payload_rule(origin, frame_type).ok_or(FrameError::UnknownType(frame_type))? {
        Size::Exact(exact) => size == exact,
        Size::AtLeast(minimum) => size >= minimum,
    };
    if fits { Ok(size) } else { Err(FrameError::PayloadSize { frame_type, size }) }
}

/// Build the frame for a payload whose header passed [`check_header`].
fn parse(frame_type: u8, payload: &[u8]) -> Result<Frame, FrameError> {
    let frame = match frame_type {
        FIDO_OUT => Frame::FidoOut(array(frame_type, payload)?),
        OTP_SET_FEATURE => Frame::OtpSetFeature(array(frame_type, payload)?),
        OTP_GET_FEATURE => Frame::OtpGetFeature,
        CCID_BULK_OUT => Frame::CcidBulkOut(payload.to_vec()),
        CCID_ABORT => {
            let [slot, seq] = array(frame_type, payload)?;
            Frame::CcidAbort { slot, seq }
        }
        TOUCH => Frame::Touch(match byte(frame_type, payload)? {
            0x00 => TouchEdge::Up,
            0x01 => TouchEdge::Down,
            value => return Err(FrameError::Value { frame_type, value }),
        }),
        BUS => Frame::Bus(match byte(frame_type, payload)? {
            0x00 => BusEvent::Reset,
            0x01 => BusEvent::Suspend,
            0x02 => BusEvent::Resume,
            0x03 => BusEvent::PowerCycle,
            value => return Err(FrameError::Value { frame_type, value }),
        }),
        IDENTITY => Frame::Identity(Identity::parse(payload)?),
        FIDO_IN => Frame::FidoIn(array(frame_type, payload)?),
        OTP_KEYBOARD => Frame::OtpKeyboard(array(frame_type, payload)?),
        OTP_FEATURE => Frame::OtpFeature(array(frame_type, payload)?),
        CCID_BULK_IN => Frame::CcidBulkIn(payload.to_vec()),
        CCID_INTERRUPT => Frame::CcidInterrupt(payload.to_vec()),
        PRESENCE => Frame::Presence(match byte(frame_type, payload)? {
            0x00 => false,
            0x01 => true,
            value => return Err(FrameError::Value { frame_type, value }),
        }),
        ERROR => Frame::Error(utf8(frame_type, payload)?),
        other => return Err(FrameError::UnknownType(other)),
    };
    Ok(frame)
}

fn array<const N: usize>(frame_type: u8, payload: &[u8]) -> Result<[u8; N], FrameError> {
    <[u8; N]>::try_from(payload).map_err(|_| FrameError::PayloadSize { frame_type, size: payload.len() })
}

fn byte(frame_type: u8, payload: &[u8]) -> Result<u8, FrameError> {
    let [value] = array(frame_type, payload)?;
    Ok(value)
}

fn utf8(frame_type: u8, bytes: &[u8]) -> Result<String, FrameError> {
    String::from_utf8(bytes.to_vec()).map_err(|_| FrameError::Utf8 { frame_type })
}

fn touch_byte(edge: TouchEdge) -> u8 {
    match edge {
        TouchEdge::Up => 0x00,
        TouchEdge::Down => 0x01,
    }
}

fn bus_byte(event: BusEvent) -> u8 {
    match event {
        BusEvent::Reset => 0x00,
        BusEvent::Suspend => 0x01,
        BusEvent::Resume => 0x02,
        BusEvent::PowerCycle => 0x03,
    }
}

/// The IDENTITY payload (`docs/PROGRAM.md` "IDENTITY payload"): what a bridge needs to
/// present the device on a real bus.
///
/// ```text
/// vendor_id:u16be product_id:u16be device_release:u16be interfaces:u8
/// then seven fields, each len:u16be bytes:
///   manufacturer, product, serial (empty when None), device descriptor (18 bytes),
///   configuration descriptor, FIDO report descriptor, OTP report descriptor
/// ```
///
/// It carries the descriptors built from a [`UsbIdentity`], not the `UsbIdentity` itself:
/// the CCID class descriptor travels inside the configuration descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub vendor_id: u16,
    pub product_id: u16,
    pub device_release: u16,
    /// Bit 0 OTP, bit 1 FIDO, bit 2 CCID on the wire.
    pub interfaces: UsbInterfaces,
    pub manufacturer: String,
    pub product: String,
    /// The `iSerialNumber` string. `None` travels as an empty field, so an empty serial
    /// reads back as `None`.
    pub serial: Option<String>,
    /// `UsbIdentity::device_descriptor`.
    pub device_descriptor: [u8; DEVICE_DESCRIPTOR_LEN],
    /// `UsbIdentity::configuration_descriptor`, with the CCID class descriptor inside.
    pub configuration_descriptor: Vec<u8>,
    pub fido_report_descriptor: Vec<u8>,
    pub otp_report_descriptor: Vec<u8>,
}

impl Identity {
    /// The identity the program presents for `identity`.
    pub fn from_usb(identity: &UsbIdentity) -> Identity {
        Identity {
            vendor_id: identity.vendor_id,
            product_id: identity.product_id,
            device_release: identity.device_release,
            interfaces: identity.interfaces,
            manufacturer: identity.manufacturer.clone(),
            product: identity.product.clone(),
            serial: identity.serial.clone(),
            device_descriptor: identity.device_descriptor(),
            configuration_descriptor: identity.configuration_descriptor(),
            fido_report_descriptor: identity.fido_report_descriptor.clone(),
            otp_report_descriptor: identity.otp_report_descriptor.clone(),
        }
    }

    /// The payload bytes. A field longer than 65535 bytes cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.vendor_id.to_be_bytes());
        out.extend_from_slice(&self.product_id.to_be_bytes());
        out.extend_from_slice(&self.device_release.to_be_bytes());
        out.push(interface_bits(self.interfaces));
        let serial = self.serial.as_deref().unwrap_or("");
        for field in [
            self.manufacturer.as_bytes(),
            self.product.as_bytes(),
            serial.as_bytes(),
            &self.device_descriptor,
            &self.configuration_descriptor,
            &self.fido_report_descriptor,
            &self.otp_report_descriptor,
        ] {
            let len = u16::try_from(field.len()).map_err(|_| FrameError::Identity("field longer than 65535 bytes"))?;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(field);
        }
        Ok(out)
    }

    /// Parse a payload. Truncation, trailing bytes, a device descriptor that is not 18
    /// bytes, interface bits other than the three defined ones and strings that are not
    /// UTF-8 are errors.
    pub fn parse(payload: &[u8]) -> Result<Identity, FrameError> {
        let mut cursor = Cursor(payload);
        let vendor_id = u16::from_be_bytes(cursor.array()?);
        let product_id = u16::from_be_bytes(cursor.array()?);
        let device_release = u16::from_be_bytes(cursor.array()?);
        let [bits] = cursor.array()?;
        if bits & !(INTERFACE_OTP | INTERFACE_FIDO | INTERFACE_CCID) != 0 {
            return Err(FrameError::Identity("undefined interface bits"));
        }
        let manufacturer = utf8(IDENTITY, cursor.field()?)?;
        let product = utf8(IDENTITY, cursor.field()?)?;
        let serial = utf8(IDENTITY, cursor.field()?)?;
        let device_descriptor = <[u8; DEVICE_DESCRIPTOR_LEN]>::try_from(cursor.field()?)
            .map_err(|_| FrameError::Identity("device descriptor is not 18 bytes"))?;
        let configuration_descriptor = cursor.field()?.to_vec();
        let fido_report_descriptor = cursor.field()?.to_vec();
        let otp_report_descriptor = cursor.field()?.to_vec();
        if !cursor.0.is_empty() {
            return Err(FrameError::Identity("trailing bytes"));
        }
        Ok(Identity {
            vendor_id,
            product_id,
            device_release,
            interfaces: UsbInterfaces {
                otp: bits & INTERFACE_OTP != 0,
                fido: bits & INTERFACE_FIDO != 0,
                ccid: bits & INTERFACE_CCID != 0,
            },
            manufacturer,
            product,
            serial: (!serial.is_empty()).then_some(serial),
            device_descriptor,
            configuration_descriptor,
            fido_report_descriptor,
            otp_report_descriptor,
        })
    }
}

fn interface_bits(interfaces: UsbInterfaces) -> u8 {
    let mut bits = 0;
    if interfaces.otp {
        bits |= INTERFACE_OTP;
    }
    if interfaces.fido {
        bits |= INTERFACE_FIDO;
    }
    if interfaces.ccid {
        bits |= INTERFACE_CCID;
    }
    bits
}

/// The unread rest of an IDENTITY payload.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N], FrameError> {
        let (head, rest) = self.0.split_first_chunk::<N>().ok_or(FrameError::Identity("truncated"))?;
        self.0 = rest;
        Ok(*head)
    }

    /// One `len:u16be bytes` field.
    fn field(&mut self) -> Result<&'a [u8], FrameError> {
        let len = usize::from(u16::from_be_bytes(self.array()?));
        if self.0.len() < len {
            return Err(FrameError::Identity("truncated"));
        }
        let (field, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(field)
    }
}

#[cfg(test)]
mod tests;
