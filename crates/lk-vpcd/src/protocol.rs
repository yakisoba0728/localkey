//! The vpcd wire protocol, pure: message framing and the control commands (see the crate
//! docs, "The vpcd protocol", for the sources of every value).
//!
//! ```text
//! message = length:u16be  payload          (length = payload length, 0..=0xFFFF)
//! payload = control:u8                     (length 1: a control command)
//!         | apdu                           (any other length: a command APDU)
//! ```
//!
//! vpcd sends every message; the card answers `GET ATR` with the ATR and an APDU with the
//! response APDU, each framed the same way, and answers nothing else.

use std::fmt;
use std::io::{self, Read};

/// The port vpcd listens on for its first slot: `VPCDPORT 35963` (`vpcd.h`), the
/// `0x8C7B` of the `reader.conf` example (`DEVICENAME /dev/null:0x8C7B`, virtualsmartcard
/// README). The next slot listens on the next port (`Channel + slot`, `ifd-vpcd.c`).
pub const DEFAULT_PORT: u16 = 35_963;

/// The default address of `--vpcd-addr`: vpcd's first slot on this machine.
pub const DEFAULT_ADDR: &str = "127.0.0.1:35963";

/// Size of the big-endian length that starts every message (`sendToVICC` writes
/// `htons(length)`, `recvFromVICC` reads it back with `ntohs`, `vpcd.c`).
pub const LENGTH_SIZE: usize = 2;

/// The largest payload: `sendToVICC` refuses `length > 0xFFFF` (`vpcd.c`), and the length
/// field cannot express more.
pub const MAX_PAYLOAD: usize = 0xFFFF;

/// Length of a control command (`VPCD_CTRL_LEN 1`, `vpcd.h`): a payload of this length is
/// a control command, any other an APDU (`VirtualICC.run`, `VirtualSmartcard.py`).
pub const CONTROL_LEN: usize = 1;

/// The control command bytes (`vpcd.h`, `VirtualSmartcard.py`).
pub mod control {
    /// `VPCD_CTRL_OFF`: power the card off. No answer.
    pub const POWER_OFF: u8 = 0x00;
    /// `VPCD_CTRL_ON`: power the card on. No answer.
    pub const POWER_ON: u8 = 0x01;
    /// `VPCD_CTRL_RESET`: reset the card. No answer.
    pub const RESET: u8 = 0x02;
    /// `VPCD_CTRL_ATR`: send the ATR. Answered with the ATR.
    pub const GET_ATR: u8 = 0x04;
}

/// A control command from vpcd.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Control {
    PowerOff,
    PowerOn,
    Reset,
    GetAtr,
}

impl Control {
    /// Every control command.
    pub const ALL: [Control; 4] = [Control::PowerOff, Control::PowerOn, Control::Reset, Control::GetAtr];

    /// The command of a control byte, `None` for a byte vpcd does not define.
    pub fn from_byte(byte: u8) -> Option<Control> {
        match byte {
            control::POWER_OFF => Some(Control::PowerOff),
            control::POWER_ON => Some(Control::PowerOn),
            control::RESET => Some(Control::Reset),
            control::GET_ATR => Some(Control::GetAtr),
            _ => None,
        }
    }

    /// The control byte.
    pub fn byte(self) -> u8 {
        match self {
            Control::PowerOff => control::POWER_OFF,
            Control::PowerOn => control::POWER_ON,
            Control::Reset => control::RESET,
            Control::GetAtr => control::GET_ATR,
        }
    }

    /// A name for logs.
    pub fn name(self) -> &'static str {
        match self {
            Control::PowerOff => "power off",
            Control::PowerOn => "power on",
            Control::Reset => "reset",
            Control::GetAtr => "get ATR",
        }
    }

    /// Whether vpcd waits for an answer: only `GET ATR` (`vicc_getatr` reads one;
    /// `vicc_poweron`, `vicc_poweroff` and `vicc_reset` send and return, `vpcd.c`).
    pub fn answered(self) -> bool {
        self == Control::GetAtr
    }
}

impl fmt::Display for Control {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One message from vpcd, by its payload. `Debug` shows an APDU's size, never its bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Message<'a> {
    /// A known control command.
    Control(Control),
    /// A one-byte payload that is no control command vpcd defines. The reference card
    /// logs it and answers nothing (`VirtualSmartcard.py`: "unknown control command").
    UnknownControl(u8),
    /// A command APDU, to be answered with the response APDU. Every payload that is not
    /// one byte long, however short, is passed on as an APDU (`VirtualSmartcard.py`); the
    /// card answers a malformed one with its status word.
    Apdu(&'a [u8]),
    /// A payload of length 0. vpcd never sends one (`vicc_transmit` sends nothing for an
    /// empty APDU, `vpcd.c`); the reference card logs it and answers nothing
    /// (`VirtualSmartcard.py`: "missing size parameter").
    Empty,
}

impl<'a> Message<'a> {
    /// Classify a payload.
    pub fn parse(payload: &'a [u8]) -> Message<'a> {
        match payload {
            [] => Message::Empty,
            [byte] => Control::from_byte(*byte).map_or(Message::UnknownControl(*byte), Message::Control),
            apdu => Message::Apdu(apdu),
        }
    }

    /// A name for logs.
    pub fn name(&self) -> &'static str {
        match self {
            Message::Control(control) => control.name(),
            Message::UnknownControl(_) => "unknown control command",
            Message::Apdu(_) => "APDU",
            Message::Empty => "empty message",
        }
    }
}

impl fmt::Debug for Message<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Message::Control(control) => f.debug_tuple("Control").field(control).finish(),
            Message::UnknownControl(byte) => f.debug_tuple("UnknownControl").field(byte).finish(),
            Message::Apdu(apdu) => f.debug_tuple("Apdu").field(&format_args!("{} bytes", apdu.len())).finish(),
            Message::Empty => f.write_str("Empty"),
        }
    }
}

/// A payload longer than [`MAX_PAYLOAD`] cannot be framed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooLong {
    /// The payload's length.
    pub len: usize,
}

impl fmt::Display for TooLong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a vpcd message carries at most {MAX_PAYLOAD} bytes, not {}", self.len)
    }
}

impl std::error::Error for TooLong {}

/// The framed message: the big-endian length, then the payload, ready for one write.
pub fn encode(payload: &[u8]) -> Result<Vec<u8>, TooLong> {
    let len = u16::try_from(payload.len()).map_err(|_| TooLong { len: payload.len() })?;
    let mut frame = Vec::with_capacity(LENGTH_SIZE + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Read one message's payload. `Ok(None)` when the stream ends cleanly before a message;
/// a stream that ends inside one is `UnexpectedEof`.
pub fn read_message(reader: &mut dyn Read) -> io::Result<Option<Vec<u8>>> {
    let mut length = [0; LENGTH_SIZE];
    let mut filled = 0;
    while filled < LENGTH_SIZE {
        match reader.read(&mut length[filled..]) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the stream ended inside a length")),
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    let mut payload = vec![0; usize::from(u16::from_be_bytes(length))];
    if let Err(error) = reader.read_exact(&mut payload) {
        lk_crypto::wipe_vec(&mut payload);
        return Err(error);
    }
    Ok(Some(payload))
}

#[cfg(test)]
mod tests;
