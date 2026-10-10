//! FunctionFS byte formats (`docs/PROGRAM.md` "lk-gadget", FunctionFS and ep0 events): the
//! descriptors blob and the strings blob written to `ep0`, and the 12-byte events read
//! from it.
//!
//! Sources: `include/uapi/linux/usb/functionfs.h` (magics, flags, the "descriptors" and
//! "strings" layout tables, `enum usb_functionfs_event_type`, `struct
//! usb_functionfs_event`), `include/uapi/linux/usb/ch9.h` (`struct usb_ctrlrequest`), and
//! for the acceptance rules `__ffs_data_got_descs`, `__ffs_data_got_strings` and
//! `ffs_do_single_desc` in `drivers/usb/gadget/function/f_fs.c`. All numbers are little
//! endian.

use std::fmt;

use crate::descriptor::ConfigDescriptor;

/// `FUNCTIONFS_STRINGS_MAGIC` (`functionfs.h`).
pub const STRINGS_MAGIC: u32 = 2;
/// `FUNCTIONFS_DESCRIPTORS_MAGIC_V2` (`functionfs.h`).
pub const DESCRIPTORS_MAGIC_V2: u32 = 3;
/// `FUNCTIONFS_HAS_FS_DESC` (`enum functionfs_flags`, `functionfs.h`): a full-speed
/// descriptor list (with its `fs_count`) follows the header. No other flag is set: no
/// high- or super-speed lists, no `FUNCTIONFS_VIRTUAL_ADDR` (see the crate docs), no
/// eventfd.
pub const HAS_FS_DESC: u32 = 1;
/// The language of a strings table: US English (USB LANGID `0x0409`).
pub const LANG_EN_US: u16 = 0x0409;
/// `sizeof(struct usb_functionfs_event)`: the 8-byte `usb_ctrlrequest` union, the type
/// byte and three padding bytes, packed (`functionfs.h`).
pub const EVENT_SIZE: usize = 12;
/// The descriptors header: magic, length, flags and `fs_count`, each LE32.
pub const DESCRIPTORS_HEADER_LEN: usize = 16;
/// The strings header: magic, length, `str_count`, `lang_count`, each LE32.
pub const STRINGS_HEADER_LEN: usize = 16;

/// The descriptors blob for `ep0` (`functionfs.h` "Descriptors format", V2):
///
/// ```text
/// magic    LE32  FUNCTIONFS_DESCRIPTORS_MAGIC_V2 (3)
/// length   LE32  length of the whole blob
/// flags    LE32  FUNCTIONFS_HAS_FS_DESC (1)
/// fs_count LE32  number of full-speed descriptors
/// fs_descrs      the descriptors, each from bLength
/// ```
///
/// The descriptors are the engine's, in its order and with its values: interface
/// numbers counted from 0 and the engine's endpoint addresses (f_fs records each
/// address, requires them distinct and nonzero, and uses the direction bit; the UDC then
/// assigns the number the host sees). f_fs accepts the HID class descriptor because it is
/// `sizeof(struct hid_descriptor)` (9) bytes and the CCID one because it is
/// `sizeof(struct ccid_descriptor)` (54) bytes (`ffs_do_single_desc`).
pub fn descriptors_blob(config: &ConfigDescriptor) -> Vec<u8> {
    let body = config.body();
    let count = u32::try_from(config.descriptors.len()).unwrap_or(u32::MAX);
    let length = u32::try_from(DESCRIPTORS_HEADER_LEN + body.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(DESCRIPTORS_HEADER_LEN + body.len());
    for field in [DESCRIPTORS_MAGIC_V2, length, HAS_FS_DESC, count] {
        out.extend_from_slice(&field.to_le_bytes());
    }
    out.extend_from_slice(&body);
    out
}

/// The strings blob for `ep0` (`functionfs.h` "Strings format"):
///
/// ```text
/// magic      LE32  FUNCTIONFS_STRINGS_MAGIC (2)
/// length     LE32  length of the whole blob
/// str_count  LE32  number of strings
/// lang_count LE32  number of languages
/// stringtab        per language: lang LE16, then str_count NUL-terminated UTF-8 strings
/// ```
///
/// `__ffs_data_got_strings` refuses a blob where exactly one of `str_count` and
/// `lang_count` is 0 ("if one is zero the other must be zero"). With no strings the blob
/// is therefore the 16-byte header with both counts 0 and no table, and `lang` is not
/// written; that is the engine's case (every `iInterface` is 0, so f_fs needs no string
/// and accepts it). `None` if a string contains a NUL.
pub fn strings_blob(lang: u16, strings: &[&str]) -> Option<Vec<u8>> {
    if strings.iter().any(|s| s.contains('\0')) {
        return None;
    }
    let mut table = Vec::new();
    if !strings.is_empty() {
        table.extend_from_slice(&lang.to_le_bytes());
        for s in strings {
            table.extend_from_slice(s.as_bytes());
            table.push(0);
        }
    }
    let str_count = u32::try_from(strings.len()).ok()?;
    let lang_count = u32::from(!strings.is_empty());
    let length = u32::try_from(STRINGS_HEADER_LEN + table.len()).ok()?;
    let mut out = Vec::with_capacity(STRINGS_HEADER_LEN + table.len());
    for field in [STRINGS_MAGIC, length, str_count, lang_count] {
        out.extend_from_slice(&field.to_le_bytes());
    }
    out.extend_from_slice(&table);
    Some(out)
}

/// `USB_DIR_IN` (`ch9.h`): bit 7 of `bRequestType`.
pub const DIR_IN: u8 = 0x80;
/// `USB_TYPE_MASK`, `USB_TYPE_STANDARD`, `USB_TYPE_CLASS`, `USB_TYPE_VENDOR` (`ch9.h`).
pub const TYPE_MASK: u8 = 0x60;
pub const TYPE_STANDARD: u8 = 0x00;
pub const TYPE_CLASS: u8 = 0x20;
pub const TYPE_VENDOR: u8 = 0x40;
/// `USB_RECIP_MASK`, `USB_RECIP_DEVICE`, `USB_RECIP_INTERFACE`, `USB_RECIP_ENDPOINT`
/// (`ch9.h`).
pub const RECIP_MASK: u8 = 0x1F;
pub const RECIP_DEVICE: u8 = 0x00;
pub const RECIP_INTERFACE: u8 = 0x01;
pub const RECIP_ENDPOINT: u8 = 0x02;

/// A SETUP packet (`struct usb_ctrlrequest`, `ch9.h`: `bRequestType`, `bRequest`,
/// `wValue`, `wIndex`, `wLength`, packed, 8 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtrlRequest {
    pub request_type: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub length: u16,
}

impl CtrlRequest {
    /// Decode the 8 bytes of a SETUP packet.
    pub fn parse(bytes: &[u8; 8]) -> CtrlRequest {
        CtrlRequest {
            request_type: bytes[0],
            request: bytes[1],
            value: u16::from_le_bytes([bytes[2], bytes[3]]),
            index: u16::from_le_bytes([bytes[4], bytes[5]]),
            length: u16::from_le_bytes([bytes[6], bytes[7]]),
        }
    }

    /// Encode the 8 bytes of a SETUP packet.
    pub fn to_bytes(&self) -> [u8; 8] {
        let [value_lo, value_hi] = self.value.to_le_bytes();
        let [index_lo, index_hi] = self.index.to_le_bytes();
        let [length_lo, length_hi] = self.length.to_le_bytes();
        [self.request_type, self.request, value_lo, value_hi, index_lo, index_hi, length_lo, length_hi]
    }

    /// Whether the data stage goes to the host (`USB_DIR_IN`). FunctionFS decides by this
    /// bit what a read or a write of `ep0` means while the request is pending.
    pub fn is_in(&self) -> bool {
        self.request_type & DIR_IN != 0
    }
}

/// `FUNCTIONFS_SETUP` (`enum usb_functionfs_event_type`, `functionfs.h`): the one event
/// type whose control-request bytes are filled in.
const SETUP_TYPE: u8 = 4;

/// One `usb_functionfs_event` (`enum usb_functionfs_event_type`, `functionfs.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// `FUNCTIONFS_BIND` (0): the function was bound to a UDC.
    Bind,
    /// `FUNCTIONFS_UNBIND` (1).
    Unbind,
    /// `FUNCTIONFS_ENABLE` (2): an interface of the function was configured
    /// (`ffs_func_set_alt`; once per interface on SET_CONFIGURATION, see the crate docs).
    Enable,
    /// `FUNCTIONFS_DISABLE` (3): unconfigured, reset or disconnected.
    Disable,
    /// `FUNCTIONFS_SETUP` (4): a control request for the function; its data stage is the
    /// next read or write of `ep0`.
    Setup(CtrlRequest),
    /// `FUNCTIONFS_SUSPEND` (5).
    Suspend,
    /// `FUNCTIONFS_RESUME` (6).
    Resume,
    /// A type this crate does not know.
    Unknown(u8),
}

impl Event {
    /// Decode one event: the control request in bytes 0..8 (meaningful for SETUP only),
    /// the type in byte 8, three padding bytes.
    pub fn parse(bytes: &[u8; EVENT_SIZE]) -> Event {
        match bytes[8] {
            0 => Event::Bind,
            1 => Event::Unbind,
            2 => Event::Enable,
            3 => Event::Disable,
            SETUP_TYPE => {
                let mut setup = [0; 8];
                setup.copy_from_slice(&bytes[..8]);
                Event::Setup(CtrlRequest::parse(&setup))
            }
            5 => Event::Suspend,
            6 => Event::Resume,
            other => Event::Unknown(other),
        }
    }

    /// Encode one event as the kernel does (the request zeroed for other types; f_fs
    /// clears the event array before filling it, `__ffs_ep0_read_events`).
    pub fn to_bytes(&self) -> [u8; EVENT_SIZE] {
        let mut out = [0; EVENT_SIZE];
        out[8] = match self {
            Event::Bind => 0,
            Event::Unbind => 1,
            Event::Enable => 2,
            Event::Disable => 3,
            Event::Setup(request) => {
                out[..8].copy_from_slice(&request.to_bytes());
                SETUP_TYPE
            }
            Event::Suspend => 5,
            Event::Resume => 6,
            Event::Unknown(kind) => *kind,
        };
        out
    }

    /// Decode what one read of `ep0` returned, if it is events: `None` unless `bytes` is
    /// a nonzero whole number of 12-byte events, each laid out as the kernel writes them.
    ///
    /// With no request pending, `ffs_ep0_read` copies whole events and nothing else
    /// (`__ffs_ep0_read_events` returns `n * sizeof(struct usb_functionfs_event)`), and
    /// the event array is zeroed before it is filled, with the control request copied
    /// in for `FUNCTIONFS_SETUP` only. So in a real event every padding byte is 0, and
    /// so are the request bytes of every type but SETUP. A read that breaks either rule
    /// is not events but the data stage of a request that is still pending (f_fs keeps
    /// a SETUP pending when its data stage was interrupted, `__ffs_ep0_queue_wait`, and
    /// then treats the next read of an OUT request as that data stage); its bytes are
    /// host data and must not be parsed as events. An unknown type with zero padding is
    /// kept as [`Event::Unknown`].
    pub fn parse_read(bytes: &[u8]) -> Option<Vec<Event>> {
        let (chunks, rest) = bytes.as_chunks::<EVENT_SIZE>();
        let well_formed = |chunk: &[u8; EVENT_SIZE]| {
            chunk[9..].iter().all(|&b| b == 0) && (chunk[8] == SETUP_TYPE || chunk[..8].iter().all(|&b| b == 0))
        };
        if chunks.is_empty() || !rest.is_empty() || !chunks.iter().all(well_formed) {
            return None;
        }
        Some(chunks.iter().map(Event::parse).collect())
    }
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::Bind => f.write_str("BIND"),
            Event::Unbind => f.write_str("UNBIND"),
            Event::Enable => f.write_str("ENABLE"),
            Event::Disable => f.write_str("DISABLE"),
            Event::Setup(r) => write!(
                f,
                "SETUP {:02x} {:02x} value 0x{:04x} index {} length {}",
                r.request_type, r.request, r.value, r.index, r.length
            ),
            Event::Suspend => f.write_str("SUSPEND"),
            Event::Resume => f.write_str("RESUME"),
            Event::Unknown(kind) => write!(f, "unknown event {kind}"),
        }
    }
}

#[cfg(test)]
mod tests;
