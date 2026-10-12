//! `struct uhid_event`, the one message format of `/dev/uhid` (`docs/PROGRAM.md` "lk-uhid").
//!
//! Every fact here comes from the kernel's UAPI header `include/uapi/linux/uhid.h` (the
//! event types, the request structures, `UHID_DATA_MAX`, the `dev_flags` bits and the report
//! types) and from `Documentation/hid/uhid.rst` (one event per `read()`/`write()`); the
//! size of `rd_data` is `HID_MAX_DESCRIPTOR_SIZE` from `include/uapi/linux/hid.h`, `BUS_USB`
//! is from `include/uapi/linux/input.h`. The behaviour notes cite `drivers/hid/uhid.c`.
//!
//! # Layout
//!
//! `struct uhid_event` is packed: a `__u32 type` at offset 0, then the union `u` at offset
//! 4. Each request structure is packed too, except `uhid_start_req` (a lone `__u64`), which
//! gives the union the alignment of a `__u64`; the union's size is therefore its largest
//! member, `uhid_create2_req` (4372 bytes), rounded up to that alignment. That is 4376 on
//! targets where a `__u64` member is 8-aligned (x86-64, AArch64, 32-bit ARM EABI) and 4372
//! on i386 (4-aligned), so `sizeof(struct uhid_event)` is 4380 or 4376 ([`UHID_EVENT_SIZE`]
//! computes it for the target, as the C compiler does).
//!
//! All multi-byte fields are in host byte order: the structure is the kernel's in-memory
//! layout copied to and from user space (`uhid_char_read`, `uhid_event_from_user`).
//!
//! # Sizes on the wire
//!
//! [`Event::encode`] always produces a whole `struct uhid_event` with the unused bytes
//! zeroed; that is what `uhid_char_write` copies (it takes `min(count, sizeof)` and zeroes
//! the rest). [`Event::decode`] needs only the bytes up to the last field it reads (plus
//! the data that a size field announces) and ignores the rest, so a whole event and a
//! shorter prefix decode alike.

use std::fmt;
use std::mem::align_of;

/// `UHID_DATA_MAX` (`include/uapi/linux/uhid.h`): the size of every report data buffer.
pub const UHID_DATA_MAX: usize = 4096;
/// `HID_MAX_DESCRIPTOR_SIZE` (`include/uapi/linux/hid.h`): the size of
/// `uhid_create2_req.rd_data`. `uhid_dev_create2` refuses an `rd_size` of 0 or above it
/// (`drivers/hid/uhid.c`).
pub const HID_MAX_DESCRIPTOR_SIZE: usize = 4096;
/// `BUS_USB` (`include/uapi/linux/input.h`): the bus type of a USB device.
pub const BUS_USB: u16 = 0x03;
/// `EIO` (`include/uapi/asm-generic/errno-base.h`), the error `Documentation/hid/uhid.rst`
/// names for the `err` field of a reply. `drivers/hid/uhid.c` treats any non-zero `err` as
/// a failure and returns `-EIO` to the caller.
pub const EIO: u16 = 5;

/// `enum uhid_event_type` (`include/uapi/linux/uhid.h`). The values 0, 7 and 8 are the
/// legacy `UHID_CREATE`, `UHID_OUTPUT_EV` and `UHID_INPUT`, which this crate neither sends
/// nor accepts.
pub const UHID_DESTROY: u32 = 1;
/// See [`UHID_DESTROY`].
pub const UHID_START: u32 = 2;
/// See [`UHID_DESTROY`].
pub const UHID_STOP: u32 = 3;
/// See [`UHID_DESTROY`].
pub const UHID_OPEN: u32 = 4;
/// See [`UHID_DESTROY`].
pub const UHID_CLOSE: u32 = 5;
/// See [`UHID_DESTROY`].
pub const UHID_OUTPUT: u32 = 6;
/// See [`UHID_DESTROY`].
pub const UHID_GET_REPORT: u32 = 9;
/// See [`UHID_DESTROY`].
pub const UHID_GET_REPORT_REPLY: u32 = 10;
/// See [`UHID_DESTROY`].
pub const UHID_CREATE2: u32 = 11;
/// See [`UHID_DESTROY`].
pub const UHID_INPUT2: u32 = 12;
/// See [`UHID_DESTROY`].
pub const UHID_SET_REPORT: u32 = 13;
/// See [`UHID_DESTROY`].
pub const UHID_SET_REPORT_REPLY: u32 = 14;

/// `enum uhid_dev_flag` (`include/uapi/linux/uhid.h`), the bits of
/// `uhid_start_req.dev_flags`. `uhid_hid_start` sets a bit when the HID core found Report
/// ID items for that report type in the report descriptor (`drivers/hid/uhid.c`).
pub const UHID_DEV_NUMBERED_FEATURE_REPORTS: u64 = 1 << 0;
/// See [`UHID_DEV_NUMBERED_FEATURE_REPORTS`].
pub const UHID_DEV_NUMBERED_OUTPUT_REPORTS: u64 = 1 << 1;
/// See [`UHID_DEV_NUMBERED_FEATURE_REPORTS`].
pub const UHID_DEV_NUMBERED_INPUT_REPORTS: u64 = 1 << 2;

/// `enum uhid_report_type` (`include/uapi/linux/uhid.h`).
pub const UHID_FEATURE_REPORT: u8 = 0;
/// See [`UHID_FEATURE_REPORT`].
pub const UHID_OUTPUT_REPORT: u8 = 1;
/// See [`UHID_FEATURE_REPORT`].
pub const UHID_INPUT_REPORT: u8 = 2;

/// `__u32 type`, the first field of `struct uhid_event`; the union `u` follows at once
/// (the structure is packed).
const TYPE_SIZE: usize = 4;
/// Offset of the union `u` in `struct uhid_event`.
const U: usize = TYPE_SIZE;

/// `uhid_create2_req.name[128]`.
pub const NAME_SIZE: usize = 128;
/// `uhid_create2_req.phys[64]`.
pub const PHYS_SIZE: usize = 64;
/// `uhid_create2_req.uniq[64]`.
pub const UNIQ_SIZE: usize = 64;

/// Field offsets of the packed `uhid_create2_req`: `name[128]`, `phys[64]`, `uniq[64]`,
/// `__u16 rd_size`, `__u16 bus`, `__u32 vendor`, `__u32 product`, `__u32 version`, `__u32
/// country`, `rd_data[HID_MAX_DESCRIPTOR_SIZE]`.
const CREATE2_NAME: usize = 0;
const CREATE2_PHYS: usize = CREATE2_NAME + NAME_SIZE;
const CREATE2_UNIQ: usize = CREATE2_PHYS + PHYS_SIZE;
const CREATE2_RD_SIZE: usize = CREATE2_UNIQ + UNIQ_SIZE;
const CREATE2_BUS: usize = CREATE2_RD_SIZE + 2;
const CREATE2_VENDOR: usize = CREATE2_BUS + 2;
const CREATE2_PRODUCT: usize = CREATE2_VENDOR + 4;
const CREATE2_VERSION: usize = CREATE2_PRODUCT + 4;
const CREATE2_COUNTRY: usize = CREATE2_VERSION + 4;
const CREATE2_RD_DATA: usize = CREATE2_COUNTRY + 4;
/// `sizeof(struct uhid_create2_req)`: 4372, the largest member of the union.
pub const CREATE2_REQ_SIZE: usize = CREATE2_RD_DATA + HID_MAX_DESCRIPTOR_SIZE;

/// `uhid_input2_req`: `__u16 size`, `data[UHID_DATA_MAX]`.
const INPUT2_SIZE: usize = 0;
const INPUT2_DATA: usize = 2;
/// `uhid_output_req`: `data[UHID_DATA_MAX]`, `__u16 size`, `__u8 rtype` (the data comes
/// first in this one).
const OUTPUT_DATA: usize = 0;
const OUTPUT_SIZE: usize = UHID_DATA_MAX;
const OUTPUT_RTYPE: usize = OUTPUT_SIZE + 2;
/// `uhid_get_report_req`: `__u32 id`, `__u8 rnum`, `__u8 rtype`.
/// `uhid_set_report_req`: the same, then `__u16 size`, `data[UHID_DATA_MAX]`.
const REQ_ID: usize = 0;
const REQ_RNUM: usize = 4;
const REQ_RTYPE: usize = 5;
const SET_SIZE: usize = 6;
const SET_DATA: usize = 8;
/// `uhid_get_report_reply_req`: `__u32 id`, `__u16 err`, `__u16 size`,
/// `data[UHID_DATA_MAX]`. `uhid_set_report_reply_req`: `__u32 id`, `__u16 err`.
const REPLY_ID: usize = 0;
const REPLY_ERR: usize = 4;
const REPLY_SIZE: usize = 6;
const REPLY_DATA: usize = 8;
/// `uhid_start_req`: `__u64 dev_flags`.
const START_FLAGS: usize = 0;

/// `sizeof(struct uhid_event)` for the target: the `__u32 type`, then the union rounded up
/// to the alignment of `uhid_start_req`'s `__u64` (see the module docs). 4380 on 64-bit
/// targets and 32-bit ARM, 4376 on i386.
pub const UHID_EVENT_SIZE: usize = TYPE_SIZE + CREATE2_REQ_SIZE.next_multiple_of(align_of::<u64>());

/// `enum uhid_report_type`, keeping a value outside the enum so a request that carries one
/// can still be answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReportType {
    /// `UHID_FEATURE_REPORT`.
    Feature,
    /// `UHID_OUTPUT_REPORT`.
    Output,
    /// `UHID_INPUT_REPORT`.
    Input,
    /// Any other value (`uhid_hid_raw_request` never sends one, `drivers/hid/uhid.c`).
    Other(u8),
}

impl ReportType {
    /// The report type for a raw `rtype` byte.
    pub fn from_raw(raw: u8) -> ReportType {
        match raw {
            UHID_FEATURE_REPORT => ReportType::Feature,
            UHID_OUTPUT_REPORT => ReportType::Output,
            UHID_INPUT_REPORT => ReportType::Input,
            other => ReportType::Other(other),
        }
    }

    /// The raw `rtype` byte.
    pub fn raw(self) -> u8 {
        match self {
            ReportType::Feature => UHID_FEATURE_REPORT,
            ReportType::Output => UHID_OUTPUT_REPORT,
            ReportType::Input => UHID_INPUT_REPORT,
            ReportType::Other(raw) => raw,
        }
    }
}

/// `struct uhid_create2_req`: the device to register.
///
/// The strings are C strings in fixed fields: each must leave room for its terminating NUL
/// and must not contain one ([`Event::encode`] refuses them otherwise; the kernel itself
/// would truncate with `strscpy`, `drivers/hid/uhid.c`).
#[derive(Clone, PartialEq, Eq)]
pub struct Create2 {
    /// `name[128]`: at most 127 bytes.
    pub name: String,
    /// `phys[64]`: at most 63 bytes.
    pub phys: String,
    /// `uniq[64]`: at most 63 bytes.
    pub uniq: String,
    /// `bus`, e.g. [`BUS_USB`].
    pub bus: u16,
    pub vendor: u32,
    pub product: u32,
    pub version: u32,
    pub country: u32,
    /// `rd_data[..rd_size]`: 1 to [`HID_MAX_DESCRIPTOR_SIZE`] bytes.
    pub report_descriptor: Vec<u8>,
}

impl fmt::Debug for Create2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Create2")
            .field("name", &self.name)
            .field("phys", &self.phys)
            .field("uniq", &self.uniq)
            .field("bus", &self.bus)
            .field("vendor", &format_args!("{:#06x}", self.vendor))
            .field("product", &format_args!("{:#06x}", self.product))
            .field("version", &format_args!("{:#06x}", self.version))
            .field("country", &self.country)
            .field("report_descriptor", &format_args!("{} bytes", self.report_descriptor.len()))
            .finish()
    }
}

/// One `struct uhid_event`, in either direction.
///
/// User space writes [`Event::Create2`], [`Event::Destroy`], [`Event::Input2`],
/// [`Event::GetReportReply`] and [`Event::SetReportReply`]; the kernel sends the others
/// (`Documentation/hid/uhid.rst`). Both directions encode and decode, so a test can play
/// the kernel.
///
/// `Debug` shows the size of report data, never its bytes: an output report carries a
/// CTAP payload, a feature report an OTP slot secret (`docs/PROGRAM.md` "Rules for program
/// crates").
/// Owned report payloads are wiped on drop.
#[derive(Clone, PartialEq, Eq)]
pub enum Event {
    /// `UHID_CREATE2`.
    Create2(Create2),
    /// `UHID_DESTROY`: unregister the device; the file stays open for another `CREATE2`.
    Destroy,
    /// `UHID_START`, always the first event of a created device.
    Start { dev_flags: u64 },
    /// `UHID_STOP`.
    Stop,
    /// `UHID_OPEN`: a process opened the HID device.
    Open,
    /// `UHID_CLOSE`: no process has it open any more.
    Close,
    /// `UHID_OUTPUT`: data for the device's interrupt channel.
    Output { data: Vec<u8>, rtype: ReportType },
    /// `UHID_GET_REPORT`: a GET_REPORT on the control channel, answered by
    /// [`Event::GetReportReply`] with the same `id`.
    GetReport { id: u32, rnum: u8, rtype: ReportType },
    /// `UHID_GET_REPORT_REPLY`: `err` 0 and the report, or an error and no data.
    GetReportReply { id: u32, err: u16, data: Vec<u8> },
    /// `UHID_INPUT2`: an input report from the device.
    Input2 { data: Vec<u8> },
    /// `UHID_SET_REPORT`: a SET_REPORT on the control channel, answered by
    /// [`Event::SetReportReply`] with the same `id`.
    SetReport { id: u32, rnum: u8, rtype: ReportType, data: Vec<u8> },
    /// `UHID_SET_REPORT_REPLY`.
    SetReportReply { id: u32, err: u16 },
}

impl Drop for Event {
    fn drop(&mut self) {
        match self {
            Self::Output { data, .. } | Self::GetReportReply { data, .. }
            | Self::Input2 { data } | Self::SetReport { data, .. } => lk_crypto::wipe_vec(data),
            _ => {}
        }
    }
}

impl fmt::Debug for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let size = |data: &Vec<u8>| format!("{} bytes", data.len());
        match self {
            Event::Create2(create) => f.debug_tuple("Create2").field(create).finish(),
            Event::Destroy => f.write_str("Destroy"),
            Event::Start { dev_flags } => {
                f.debug_struct("Start").field("dev_flags", &format_args!("{dev_flags:#x}")).finish()
            }
            Event::Stop => f.write_str("Stop"),
            Event::Open => f.write_str("Open"),
            Event::Close => f.write_str("Close"),
            Event::Output { data, rtype } => {
                f.debug_struct("Output").field("data", &format_args!("{}", size(data))).field("rtype", rtype).finish()
            }
            Event::GetReport { id, rnum, rtype } => {
                f.debug_struct("GetReport").field("id", id).field("rnum", rnum).field("rtype", rtype).finish()
            }
            Event::GetReportReply { id, err, data } => f
                .debug_struct("GetReportReply")
                .field("id", id)
                .field("err", err)
                .field("data", &format_args!("{}", size(data)))
                .finish(),
            Event::Input2 { data } => f.debug_struct("Input2").field("data", &format_args!("{}", size(data))).finish(),
            Event::SetReport { id, rnum, rtype, data } => f
                .debug_struct("SetReport")
                .field("id", id)
                .field("rnum", rnum)
                .field("rtype", rtype)
                .field("data", &format_args!("{}", size(data)))
                .finish(),
            Event::SetReportReply { id, err } => {
                f.debug_struct("SetReportReply").field("id", id).field("err", err).finish()
            }
        }
    }
}

/// Why an [`Event`] cannot be encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    /// A string does not fit its field together with the terminating NUL.
    StringTooLong { field: &'static str, len: usize, max: usize },
    /// A string contains a NUL byte, which would end it early.
    StringHasNul { field: &'static str },
    /// The report descriptor is empty or longer than [`HID_MAX_DESCRIPTOR_SIZE`]
    /// (`uhid_dev_create2` refuses both with `-EINVAL`).
    DescriptorSize(usize),
    /// Report data longer than [`UHID_DATA_MAX`].
    DataTooLong(usize),
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeError::StringTooLong { field, len, max } => {
                write!(f, "{field} is {len} bytes, at most {max} fit")
            }
            EncodeError::StringHasNul { field } => write!(f, "{field} contains a NUL byte"),
            EncodeError::DescriptorSize(len) => {
                write!(f, "report descriptor is {len} bytes, must be 1 to {HID_MAX_DESCRIPTOR_SIZE}")
            }
            EncodeError::DataTooLong(len) => write!(f, "report data is {len} bytes, at most {UHID_DATA_MAX} fit"),
        }
    }
}

impl std::error::Error for EncodeError {}

/// Why bytes are not an [`Event`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The bytes end before the event does: `needed` bytes are required, `got` arrived.
    Truncated { needed: usize, got: usize },
    /// An event type this crate does not know, including the legacy ones (0, 7, 8).
    UnknownType(u32),
    /// A size field out of its range (`rd_size` 1 to 4096, data sizes 0 to 4096).
    BadSize { field: &'static str, size: usize },
    /// A string field is not UTF-8.
    InvalidString { field: &'static str },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Truncated { needed, got } => write!(f, "event truncated: {got} of {needed} bytes"),
            DecodeError::UnknownType(kind) => write!(f, "unknown event type {kind}"),
            DecodeError::BadSize { field, size } => write!(f, "{field} {size} is out of range"),
            DecodeError::InvalidString { field } => write!(f, "{field} is not UTF-8"),
        }
    }
}

impl std::error::Error for DecodeError {}

impl Event {
    /// The kernel's name of the event type, for logs.
    pub fn name(&self) -> &'static str {
        match self {
            Event::Create2(_) => "CREATE2",
            Event::Destroy => "DESTROY",
            Event::Start { .. } => "START",
            Event::Stop => "STOP",
            Event::Open => "OPEN",
            Event::Close => "CLOSE",
            Event::Output { .. } => "OUTPUT",
            Event::GetReport { .. } => "GET_REPORT",
            Event::GetReportReply { .. } => "GET_REPORT_REPLY",
            Event::Input2 { .. } => "INPUT2",
            Event::SetReport { .. } => "SET_REPORT",
            Event::SetReportReply { .. } => "SET_REPORT_REPLY",
        }
    }

    /// The `type` field.
    pub fn event_type(&self) -> u32 {
        match self {
            Event::Create2(_) => UHID_CREATE2,
            Event::Destroy => UHID_DESTROY,
            Event::Start { .. } => UHID_START,
            Event::Stop => UHID_STOP,
            Event::Open => UHID_OPEN,
            Event::Close => UHID_CLOSE,
            Event::Output { .. } => UHID_OUTPUT,
            Event::GetReport { .. } => UHID_GET_REPORT,
            Event::GetReportReply { .. } => UHID_GET_REPORT_REPLY,
            Event::Input2 { .. } => UHID_INPUT2,
            Event::SetReport { .. } => UHID_SET_REPORT,
            Event::SetReportReply { .. } => UHID_SET_REPORT_REPLY,
        }
    }

    /// The size of the event's report data (the report descriptor for `CREATE2`), for logs.
    pub fn data_len(&self) -> usize {
        match self {
            Event::Create2(create) => create.report_descriptor.len(),
            Event::Output { data, .. }
            | Event::GetReportReply { data, .. }
            | Event::Input2 { data }
            | Event::SetReport { data, .. } => data.len(),
            _ => 0,
        }
    }

    /// The whole `struct uhid_event` ([`UHID_EVENT_SIZE`] bytes, unused bytes zero).
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = vec![0; UHID_EVENT_SIZE];
        self.encode_to(&mut out)?;
        Ok(out)
    }

    /// [`Event::encode`] into a buffer the caller reuses; on an error the buffer is left
    /// zeroed.
    pub fn encode_into(&self, out: &mut [u8; UHID_EVENT_SIZE]) -> Result<(), EncodeError> {
        out.fill(0);
        let result = self.encode_to(out);
        if result.is_err() {
            out.fill(0);
        }
        result
    }

    /// Fill a zeroed buffer of [`UHID_EVENT_SIZE`] bytes.
    fn encode_to(&self, out: &mut [u8]) -> Result<(), EncodeError> {
        out[..TYPE_SIZE].copy_from_slice(&self.event_type().to_ne_bytes());
        let u = &mut out[U..];
        match self {
            Event::Create2(create) => {
                put_string(u, CREATE2_NAME, NAME_SIZE, "name", &create.name)?;
                put_string(u, CREATE2_PHYS, PHYS_SIZE, "phys", &create.phys)?;
                put_string(u, CREATE2_UNIQ, UNIQ_SIZE, "uniq", &create.uniq)?;
                let descriptor = &create.report_descriptor;
                let rd_size = u16::try_from(descriptor.len())
                    .ok()
                    .filter(|&size| size != 0 && usize::from(size) <= HID_MAX_DESCRIPTOR_SIZE)
                    .ok_or(EncodeError::DescriptorSize(descriptor.len()))?;
                put(u, CREATE2_RD_SIZE, &rd_size.to_ne_bytes());
                put(u, CREATE2_BUS, &create.bus.to_ne_bytes());
                put(u, CREATE2_VENDOR, &create.vendor.to_ne_bytes());
                put(u, CREATE2_PRODUCT, &create.product.to_ne_bytes());
                put(u, CREATE2_VERSION, &create.version.to_ne_bytes());
                put(u, CREATE2_COUNTRY, &create.country.to_ne_bytes());
                put(u, CREATE2_RD_DATA, descriptor);
            }
            Event::Destroy | Event::Stop | Event::Open | Event::Close => {}
            Event::Start { dev_flags } => put(u, START_FLAGS, &dev_flags.to_ne_bytes()),
            Event::Output { data, rtype } => {
                let size = data_size(data)?;
                put(u, OUTPUT_DATA, data);
                put(u, OUTPUT_SIZE, &size.to_ne_bytes());
                put(u, OUTPUT_RTYPE, &[rtype.raw()]);
            }
            Event::GetReport { id, rnum, rtype } => {
                put(u, REQ_ID, &id.to_ne_bytes());
                put(u, REQ_RNUM, &[*rnum]);
                put(u, REQ_RTYPE, &[rtype.raw()]);
            }
            Event::GetReportReply { id, err, data } => {
                let size = data_size(data)?;
                put(u, REPLY_ID, &id.to_ne_bytes());
                put(u, REPLY_ERR, &err.to_ne_bytes());
                put(u, REPLY_SIZE, &size.to_ne_bytes());
                put(u, REPLY_DATA, data);
            }
            Event::Input2 { data } => {
                let size = data_size(data)?;
                put(u, INPUT2_SIZE, &size.to_ne_bytes());
                put(u, INPUT2_DATA, data);
            }
            Event::SetReport { id, rnum, rtype, data } => {
                let size = data_size(data)?;
                put(u, REQ_ID, &id.to_ne_bytes());
                put(u, REQ_RNUM, &[*rnum]);
                put(u, REQ_RTYPE, &[rtype.raw()]);
                put(u, SET_SIZE, &size.to_ne_bytes());
                put(u, SET_DATA, data);
            }
            Event::SetReportReply { id, err } => {
                put(u, REPLY_ID, &id.to_ne_bytes());
                put(u, REPLY_ERR, &err.to_ne_bytes());
            }
        }
        Ok(())
    }

    /// Decode one event from the start of `bytes` (see the module docs for how many bytes
    /// it needs). Bytes after the event are ignored.
    pub fn decode(bytes: &[u8]) -> Result<Event, DecodeError> {
        let kind = u32::from_ne_bytes(field(bytes, 0)?);
        let at = |offset: usize| U + offset;
        Ok(match kind {
            UHID_CREATE2 => {
                let name = get_string(bytes, at(CREATE2_NAME), NAME_SIZE, "name")?;
                let phys = get_string(bytes, at(CREATE2_PHYS), PHYS_SIZE, "phys")?;
                let uniq = get_string(bytes, at(CREATE2_UNIQ), UNIQ_SIZE, "uniq")?;
                let rd_size = usize::from(u16::from_ne_bytes(field(bytes, at(CREATE2_RD_SIZE))?));
                let bus = u16::from_ne_bytes(field(bytes, at(CREATE2_BUS))?);
                let vendor = u32::from_ne_bytes(field(bytes, at(CREATE2_VENDOR))?);
                let product = u32::from_ne_bytes(field(bytes, at(CREATE2_PRODUCT))?);
                let version = u32::from_ne_bytes(field(bytes, at(CREATE2_VERSION))?);
                let country = u32::from_ne_bytes(field(bytes, at(CREATE2_COUNTRY))?);
                if rd_size == 0 || rd_size > HID_MAX_DESCRIPTOR_SIZE {
                    return Err(DecodeError::BadSize { field: "rd_size", size: rd_size });
                }
                let report_descriptor = slice(bytes, at(CREATE2_RD_DATA), rd_size)?.to_vec();
                Event::Create2(Create2 { name, phys, uniq, bus, vendor, product, version, country, report_descriptor })
            }
            UHID_DESTROY => Event::Destroy,
            UHID_START => Event::Start { dev_flags: u64::from_ne_bytes(field(bytes, at(START_FLAGS))?) },
            UHID_STOP => Event::Stop,
            UHID_OPEN => Event::Open,
            UHID_CLOSE => Event::Close,
            UHID_OUTPUT => {
                let size = get_size(bytes, at(OUTPUT_SIZE), "size")?;
                let [rtype] = field(bytes, at(OUTPUT_RTYPE))?;
                let data = slice(bytes, at(OUTPUT_DATA), size)?.to_vec();
                Event::Output { data, rtype: ReportType::from_raw(rtype) }
            }
            UHID_GET_REPORT => {
                let id = u32::from_ne_bytes(field(bytes, at(REQ_ID))?);
                let [rnum] = field(bytes, at(REQ_RNUM))?;
                let [rtype] = field(bytes, at(REQ_RTYPE))?;
                Event::GetReport { id, rnum, rtype: ReportType::from_raw(rtype) }
            }
            UHID_GET_REPORT_REPLY => {
                let id = u32::from_ne_bytes(field(bytes, at(REPLY_ID))?);
                let err = u16::from_ne_bytes(field(bytes, at(REPLY_ERR))?);
                let size = get_size(bytes, at(REPLY_SIZE), "size")?;
                let data = slice(bytes, at(REPLY_DATA), size)?.to_vec();
                Event::GetReportReply { id, err, data }
            }
            UHID_INPUT2 => {
                let size = get_size(bytes, at(INPUT2_SIZE), "size")?;
                let data = slice(bytes, at(INPUT2_DATA), size)?.to_vec();
                Event::Input2 { data }
            }
            UHID_SET_REPORT => {
                let id = u32::from_ne_bytes(field(bytes, at(REQ_ID))?);
                let [rnum] = field(bytes, at(REQ_RNUM))?;
                let [rtype] = field(bytes, at(REQ_RTYPE))?;
                let size = get_size(bytes, at(SET_SIZE), "size")?;
                let data = slice(bytes, at(SET_DATA), size)?.to_vec();
                Event::SetReport { id, rnum, rtype: ReportType::from_raw(rtype), data }
            }
            UHID_SET_REPORT_REPLY => {
                let id = u32::from_ne_bytes(field(bytes, at(REPLY_ID))?);
                let err = u16::from_ne_bytes(field(bytes, at(REPLY_ERR))?);
                Event::SetReportReply { id, err }
            }
            other => return Err(DecodeError::UnknownType(other)),
        })
    }
}

/// Copy `bytes` to `offset` of the union. Callers have checked sizes, and every field
/// lies inside the union, which [`UHID_EVENT_SIZE`] covers.
fn put(u: &mut [u8], offset: usize, bytes: &[u8]) {
    u[offset..offset + bytes.len()].copy_from_slice(bytes);
}

/// Write a C string into a field of `size` bytes, leaving room for the terminating NUL.
fn put_string(u: &mut [u8], offset: usize, size: usize, name: &'static str, text: &str) -> Result<(), EncodeError> {
    if text.as_bytes().contains(&0) {
        return Err(EncodeError::StringHasNul { field: name });
    }
    if text.len() >= size {
        return Err(EncodeError::StringTooLong { field: name, len: text.len(), max: size - 1 });
    }
    put(u, offset, text.as_bytes());
    Ok(())
}

/// The `__u16 size` of report data.
fn data_size(data: &[u8]) -> Result<u16, EncodeError> {
    u16::try_from(data.len())
        .ok()
        .filter(|&size| usize::from(size) <= UHID_DATA_MAX)
        .ok_or(EncodeError::DataTooLong(data.len()))
}

/// `N` bytes at `offset`, or how many bytes the event needs.
fn field<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], DecodeError> {
    let got = slice(bytes, offset, N)?;
    let mut out = [0; N];
    out.copy_from_slice(got);
    Ok(out)
}

/// `len` bytes at `offset`, or how many bytes the event needs.
fn slice(bytes: &[u8], offset: usize, len: usize) -> Result<&[u8], DecodeError> {
    let needed = offset + len;
    bytes.get(offset..needed).ok_or(DecodeError::Truncated { needed, got: bytes.len() })
}

/// A `__u16` data size, at most [`UHID_DATA_MAX`].
fn get_size(bytes: &[u8], offset: usize, name: &'static str) -> Result<usize, DecodeError> {
    let size = usize::from(u16::from_ne_bytes(field(bytes, offset)?));
    if size > UHID_DATA_MAX {
        return Err(DecodeError::BadSize { field: name, size });
    }
    Ok(size)
}

/// A C string in a field of `size` bytes: up to the first NUL, or the whole field.
fn get_string(bytes: &[u8], offset: usize, size: usize, name: &'static str) -> Result<String, DecodeError> {
    let raw = slice(bytes, offset, size)?;
    let end = raw.iter().position(|&byte| byte == 0).unwrap_or(size);
    String::from_utf8(raw[..end].to_vec()).map_err(|_| DecodeError::InvalidString { field: name })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create() -> Create2 {
        Create2 {
            name: "YubiKey OTP+FIDO+CCID".to_owned(),
            phys: "localkey".to_owned(),
            uniq: "12345678".to_owned(),
            bus: BUS_USB,
            vendor: 0x1050,
            product: 0x0407,
            version: 0x0574,
            country: 0,
            report_descriptor: (1..=34).collect(),
        }
    }

    /// One event of every kind, with distinct field values.
    fn samples() -> Vec<Event> {
        vec![
            Event::Create2(create()),
            Event::Destroy,
            Event::Start { dev_flags: UHID_DEV_NUMBERED_INPUT_REPORTS | UHID_DEV_NUMBERED_FEATURE_REPORTS },
            Event::Stop,
            Event::Open,
            Event::Close,
            Event::Output { data: (0..65).collect(), rtype: ReportType::Output },
            Event::GetReport { id: 0x0102_0304, rnum: 0, rtype: ReportType::Feature },
            Event::GetReportReply { id: 7, err: 0, data: (10..19).collect() },
            Event::Input2 { data: (0..64).map(|byte| byte ^ 0x5A).collect() },
            Event::SetReport { id: 9, rnum: 0, rtype: ReportType::Feature, data: (20..29).collect() },
            Event::SetReportReply { id: 11, err: EIO },
        ]
    }

    /// The bytes an event needs before it decodes (see the module docs).
    fn needed(event: &Event) -> usize {
        match event {
            Event::Create2(create) => U + CREATE2_RD_DATA + create.report_descriptor.len(),
            Event::Destroy | Event::Stop | Event::Open | Event::Close => TYPE_SIZE,
            Event::Start { .. } => U + 8,
            Event::Output { .. } => U + UHID_DATA_MAX + 3,
            Event::GetReport { .. } | Event::SetReportReply { .. } => U + 6,
            Event::GetReportReply { data, .. } | Event::SetReport { data, .. } => U + 8 + data.len(),
            Event::Input2 { data } => U + 2 + data.len(),
        }
    }

    fn ne16(value: u16) -> [u8; 2] {
        value.to_ne_bytes()
    }

    fn ne32(value: u32) -> [u8; 4] {
        value.to_ne_bytes()
    }

    /// The constants of `include/uapi/linux/uhid.h`, `hid.h`, `input.h` and
    /// `errno-base.h`.
    #[test]
    fn constants_match_the_kernel_headers() {
        let types = [
            UHID_DESTROY,
            UHID_START,
            UHID_STOP,
            UHID_OPEN,
            UHID_CLOSE,
            UHID_OUTPUT,
            UHID_GET_REPORT,
            UHID_GET_REPORT_REPLY,
            UHID_CREATE2,
            UHID_INPUT2,
            UHID_SET_REPORT,
            UHID_SET_REPORT_REPLY,
        ];
        assert_eq!(types, [1, 2, 3, 4, 5, 6, 9, 10, 11, 12, 13, 14]);
        assert_eq!(
            [UHID_DEV_NUMBERED_FEATURE_REPORTS, UHID_DEV_NUMBERED_OUTPUT_REPORTS, UHID_DEV_NUMBERED_INPUT_REPORTS],
            [1, 2, 4]
        );
        assert_eq!([UHID_FEATURE_REPORT, UHID_OUTPUT_REPORT, UHID_INPUT_REPORT], [0, 1, 2]);
        assert_eq!((UHID_DATA_MAX, HID_MAX_DESCRIPTOR_SIZE, BUS_USB, EIO), (4096, 4096, 3, 5));
        assert_eq!((NAME_SIZE, PHYS_SIZE, UNIQ_SIZE), (128, 64, 64));
    }

    /// Field offsets of the packed request structures.
    #[test]
    fn request_structures_have_the_packed_offsets() {
        assert_eq!(
            [
                CREATE2_PHYS,
                CREATE2_UNIQ,
                CREATE2_RD_SIZE,
                CREATE2_BUS,
                CREATE2_VENDOR,
                CREATE2_PRODUCT,
                CREATE2_VERSION,
                CREATE2_COUNTRY,
                CREATE2_RD_DATA
            ],
            [128, 192, 256, 258, 260, 264, 268, 272, 276]
        );
        assert_eq!(CREATE2_REQ_SIZE, 4372);
        assert_eq!((OUTPUT_DATA, OUTPUT_SIZE, OUTPUT_RTYPE), (0, 4096, 4098));
        assert_eq!((INPUT2_SIZE, INPUT2_DATA), (0, 2));
        assert_eq!((REQ_ID, REQ_RNUM, REQ_RTYPE, SET_SIZE, SET_DATA), (0, 4, 5, 6, 8));
        assert_eq!((REPLY_ID, REPLY_ERR, REPLY_SIZE, REPLY_DATA), (0, 4, 6, 8));
        assert_eq!(U, 4);
    }

    /// `sizeof(struct uhid_event)`: the union is `uhid_create2_req` rounded up to the
    /// alignment of a `__u64`; 4380 wherever that is 8 (checked with a C compiler for
    /// x86-64, AArch64 and ARMv7; i386 gives 4376).
    #[test]
    fn the_event_size_follows_the_u64_alignment_of_the_target() {
        let align = align_of::<u64>();
        assert_eq!(UHID_EVENT_SIZE, 4 + 4372_usize.div_ceil(align) * align);
        const { assert!(UHID_EVENT_SIZE == 4376 || UHID_EVENT_SIZE == 4380) };
        #[cfg(target_pointer_width = "64")]
        assert_eq!(UHID_EVENT_SIZE, 4380);
        for event in samples() {
            assert_eq!(event.encode().map(|bytes| bytes.len()), Ok(UHID_EVENT_SIZE), "{}", event.name());
        }
    }

    /// Every event decodes to itself, from the whole event and from the shortest prefix.
    #[test]
    fn every_event_round_trips() {
        for event in samples() {
            let bytes = event.encode().expect("the sample encodes");
            assert_eq!(Event::decode(&bytes).as_ref(), Ok(&event), "{}", event.name());
            assert_eq!(Event::decode(&bytes[..needed(&event)]).as_ref(), Ok(&event), "{}", event.name());
            assert_eq!(u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]), event.event_type());
        }
    }

    /// Every byte the encoder does not set is zero, as `uhid_char_write` would leave it.
    #[test]
    fn unused_bytes_are_zero() {
        for event in samples() {
            let bytes = event.encode().expect("the sample encodes");
            assert!(bytes[needed(&event)..].iter().all(|&byte| byte == 0), "{}", event.name());
        }
        let bytes = Event::Destroy.encode().expect("DESTROY encodes");
        assert!(bytes[4..].iter().all(|&byte| byte == 0));
    }

    /// Every prefix shorter than the event is `Truncated`, naming the bytes it needs.
    #[test]
    fn truncated_input_is_refused_at_every_length() {
        for event in samples() {
            let bytes = event.encode().expect("the sample encodes");
            let needed = needed(&event);
            for len in 0..needed {
                match Event::decode(&bytes[..len]) {
                    Err(DecodeError::Truncated { needed: want, got }) => {
                        assert_eq!(got, len, "{} at {len}", event.name());
                        assert!(want > len && want <= needed, "{} at {len}: needs {want}", event.name());
                    }
                    other => panic!("{} at {len}: {other:?}", event.name()),
                }
            }
        }
    }

    /// The CREATE2 fields sit at their offsets in host byte order.
    #[test]
    fn create2_puts_every_field_at_its_offset() {
        let bytes = Event::Create2(create()).encode().expect("CREATE2 encodes");
        assert_eq!(&bytes[..4], &ne32(11));
        assert_eq!(&bytes[4..4 + 21], b"YubiKey OTP+FIDO+CCID");
        assert!(bytes[4 + 21..4 + 128].iter().all(|&byte| byte == 0));
        assert_eq!(&bytes[4 + 128..4 + 136], b"localkey");
        assert_eq!(&bytes[4 + 192..4 + 200], b"12345678");
        assert_eq!(&bytes[4 + 256..4 + 258], &ne16(34));
        assert_eq!(&bytes[4 + 258..4 + 260], &ne16(3));
        assert_eq!(&bytes[4 + 260..4 + 264], &ne32(0x1050));
        assert_eq!(&bytes[4 + 264..4 + 268], &ne32(0x0407));
        assert_eq!(&bytes[4 + 268..4 + 272], &ne32(0x0574));
        assert_eq!(&bytes[4 + 272..4 + 276], &ne32(0));
        assert_eq!(&bytes[4 + 276..4 + 310], (1..=34).collect::<Vec<u8>>().as_slice());
    }

    /// The request and reply fields sit at their offsets in host byte order.
    #[test]
    fn report_events_put_every_field_at_its_offset() {
        let output = Event::Output { data: vec![0xAA; 65], rtype: ReportType::Output }.encode().expect("encodes");
        assert_eq!(&output[..4], &ne32(6));
        assert_eq!(&output[4..69], &[0xAA; 65]);
        assert_eq!(&output[4 + 4096..4 + 4098], &ne16(65));
        assert_eq!(output[4 + 4098], 1);

        let get = Event::GetReport { id: 0x0102_0304, rnum: 3, rtype: ReportType::Input }.encode().expect("encodes");
        assert_eq!(&get[..10], &[ne32(9).as_slice(), &ne32(0x0102_0304), &[3, 2]].concat()[..]);

        let reply = Event::GetReportReply { id: 5, err: EIO, data: vec![1, 2, 3] }.encode().expect("encodes");
        assert_eq!(&reply[..15], &[ne32(10).as_slice(), &ne32(5), &ne16(5), &ne16(3), &[1, 2, 3]].concat()[..]);

        let input = Event::Input2 { data: vec![7; 8] }.encode().expect("encodes");
        assert_eq!(&input[..14], &[ne32(12).as_slice(), &ne16(8), &[7; 8]].concat()[..]);

        let set = Event::SetReport { id: 6, rnum: 0, rtype: ReportType::Feature, data: vec![9; 9] };
        let set = set.encode().expect("encodes");
        assert_eq!(&set[..21], &[ne32(13).as_slice(), &ne32(6), &[0, 0], &ne16(9), &[9; 9]].concat()[..]);

        let ack = Event::SetReportReply { id: 6, err: 0 }.encode().expect("encodes");
        assert_eq!(&ack[..10], &[ne32(14).as_slice(), &ne32(6), &ne16(0)].concat()[..]);

        let start = Event::Start { dev_flags: 5 }.encode().expect("encodes");
        assert_eq!(&start[..12], &[ne32(2).as_slice(), &5u64.to_ne_bytes()].concat()[..]);
    }

    /// Strings must leave room for the NUL and contain none; the descriptor must be 1 to
    /// 4096 bytes.
    #[test]
    fn create2_refuses_oversize_and_malformed_fields() {
        let with = |change: &dyn Fn(&mut Create2)| {
            let mut create = create();
            change(&mut create);
            Event::Create2(create).encode().err()
        };
        assert_eq!(with(&|c| c.name = "n".repeat(127)), None);
        assert_eq!(
            with(&|c| c.name = "n".repeat(128)),
            Some(EncodeError::StringTooLong { field: "name", len: 128, max: 127 })
        );
        assert_eq!(with(&|c| c.phys = "p".repeat(63)), None);
        assert_eq!(
            with(&|c| c.phys = "p".repeat(64)),
            Some(EncodeError::StringTooLong { field: "phys", len: 64, max: 63 })
        );
        assert_eq!(with(&|c| c.uniq = "u".repeat(63)), None);
        assert_eq!(
            with(&|c| c.uniq = "u".repeat(64)),
            Some(EncodeError::StringTooLong { field: "uniq", len: 64, max: 63 })
        );
        assert_eq!(with(&|c| c.name = "a\0b".to_owned()), Some(EncodeError::StringHasNul { field: "name" }));
        assert_eq!(with(&|c| c.uniq = "\0".to_owned()), Some(EncodeError::StringHasNul { field: "uniq" }));
        assert_eq!(with(&|c| c.report_descriptor = vec![1; 4096]), None);
        assert_eq!(with(&|c| c.report_descriptor = vec![1; 4097]), Some(EncodeError::DescriptorSize(4097)));
        assert_eq!(with(&|c| c.report_descriptor = vec![1; 70_000]), Some(EncodeError::DescriptorSize(70_000)));
        assert_eq!(with(&|c| c.report_descriptor = Vec::new()), Some(EncodeError::DescriptorSize(0)));
    }

    /// Report data longer than `UHID_DATA_MAX` cannot be encoded; exactly that much can.
    #[test]
    fn report_data_is_limited_to_uhid_data_max() {
        let events = |data: Vec<u8>| {
            vec![
                Event::Output { data: data.clone(), rtype: ReportType::Output },
                Event::GetReportReply { id: 1, err: 0, data: data.clone() },
                Event::Input2 { data: data.clone() },
                Event::SetReport { id: 1, rnum: 0, rtype: ReportType::Feature, data },
            ]
        };
        for event in events(vec![0xEE; 4096]) {
            let bytes = event.encode().expect("4096 bytes fit");
            assert_eq!(Event::decode(&bytes).as_ref(), Ok(&event));
        }
        for event in events(vec![0xEE; 4097]) {
            assert_eq!(event.encode(), Err(EncodeError::DataTooLong(4097)), "{}", event.name());
        }
        let mut buffer = [0xFF; UHID_EVENT_SIZE];
        assert!(Event::Input2 { data: vec![1; 4097] }.encode_into(&mut buffer).is_err());
        assert!(buffer.iter().all(|&byte| byte == 0), "a failed encode leaves the buffer zeroed");
    }

    /// `encode_into` overwrites what a previous event left in the buffer.
    #[test]
    fn encode_into_reuses_a_buffer() {
        let mut buffer = [0; UHID_EVENT_SIZE];
        Event::Create2(create()).encode_into(&mut buffer).expect("CREATE2 encodes");
        Event::Destroy.encode_into(&mut buffer).expect("DESTROY encodes");
        assert_eq!(buffer.to_vec(), Event::Destroy.encode().expect("DESTROY encodes"));
    }

    /// Size fields beyond their range are refused when decoding.
    #[test]
    fn decoding_refuses_sizes_out_of_range() {
        let with_u16 = |event: Event, offset: usize, value: u16| {
            let mut bytes = event.encode().expect("the sample encodes");
            bytes[U + offset..U + offset + 2].copy_from_slice(&value.to_ne_bytes());
            Event::decode(&bytes)
        };
        let output = Event::Output { data: vec![1], rtype: ReportType::Output };
        assert_eq!(
            with_u16(output.clone(), OUTPUT_SIZE, 4097),
            Err(DecodeError::BadSize { field: "size", size: 4097 })
        );
        assert!(with_u16(output, OUTPUT_SIZE, 4096).is_ok());
        let input = Event::Input2 { data: vec![1] };
        assert_eq!(with_u16(input, INPUT2_SIZE, 0xFFFF), Err(DecodeError::BadSize { field: "size", size: 0xFFFF }));
        let reply = Event::GetReportReply { id: 1, err: 0, data: vec![1] };
        assert_eq!(with_u16(reply, REPLY_SIZE, 4097), Err(DecodeError::BadSize { field: "size", size: 4097 }));
        let set = Event::SetReport { id: 1, rnum: 0, rtype: ReportType::Feature, data: vec![1] };
        assert_eq!(with_u16(set, SET_SIZE, 5000), Err(DecodeError::BadSize { field: "size", size: 5000 }));
        let create = Event::Create2(create());
        assert_eq!(
            with_u16(create.clone(), CREATE2_RD_SIZE, 0),
            Err(DecodeError::BadSize { field: "rd_size", size: 0 })
        );
        assert_eq!(with_u16(create, CREATE2_RD_SIZE, 4097), Err(DecodeError::BadSize { field: "rd_size", size: 4097 }));
    }

    /// Legacy and unknown event types are refused by number.
    #[test]
    fn unknown_and_legacy_types_are_refused() {
        for kind in [0, 7, 8, 15, 0x100, u32::MAX] {
            let mut bytes = vec![0; UHID_EVENT_SIZE];
            bytes[..4].copy_from_slice(&kind.to_ne_bytes());
            assert_eq!(Event::decode(&bytes), Err(DecodeError::UnknownType(kind)));
        }
        assert_eq!(Event::decode(&[]), Err(DecodeError::Truncated { needed: 4, got: 0 }));
    }

    /// A string field ends at its first NUL or fills the field; it must be UTF-8.
    #[test]
    fn decoded_strings_end_at_nul_and_must_be_utf8() {
        let mut bytes = Event::Create2(create()).encode().expect("CREATE2 encodes");
        bytes[U..U + NAME_SIZE].fill(b'x');
        bytes[U + CREATE2_UNIQ + 2] = 0;
        bytes[U + CREATE2_UNIQ + 3] = b'z';
        match Event::decode(&bytes) {
            Ok(Event::Create2(ref create)) => {
                assert_eq!(create.name, "x".repeat(128));
                assert_eq!(create.uniq, "12");
            }
            other => panic!("{other:?}"),
        }
        bytes[U + CREATE2_PHYS] = 0xFF;
        assert_eq!(Event::decode(&bytes), Err(DecodeError::InvalidString { field: "phys" }));
    }

    /// Report types keep values outside the enum.
    #[test]
    fn report_types_round_trip_every_byte() {
        assert_eq!(ReportType::from_raw(0), ReportType::Feature);
        assert_eq!(ReportType::from_raw(1), ReportType::Output);
        assert_eq!(ReportType::from_raw(2), ReportType::Input);
        for raw in 0..=255 {
            assert_eq!(ReportType::from_raw(raw).raw(), raw);
        }
        let get = Event::GetReport { id: 1, rnum: 0, rtype: ReportType::Other(9) };
        assert_eq!(Event::decode(&get.encode().expect("encodes")), Ok(get));
    }

    /// `Debug` shows sizes, never report bytes.
    #[test]
    fn debug_shows_sizes_not_report_bytes() {
        for event in samples() {
            let text = format!("{event:?}");
            assert!(!text.contains("[") && !text.contains("90,"), "{text}");
        }
        let text = format!("{:?}", Event::Input2 { data: vec![0xAB; 64] });
        assert_eq!(text, "Input2 { data: 64 bytes }");
        let text = format!("{:?}", Event::Create2(create()));
        assert!(text.contains("report_descriptor: 34 bytes") && text.contains("vendor: 0x1050"), "{text}");
    }

    /// Names and types agree.
    #[test]
    fn names_and_types_agree() {
        let names: Vec<_> =
            samples().iter().map(|event| (event.name(), event.event_type(), event.data_len())).collect();
        assert_eq!(
            names,
            [
                ("CREATE2", 11, 34),
                ("DESTROY", 1, 0),
                ("START", 2, 0),
                ("STOP", 3, 0),
                ("OPEN", 4, 0),
                ("CLOSE", 5, 0),
                ("OUTPUT", 6, 65),
                ("GET_REPORT", 9, 0),
                ("GET_REPORT_REPLY", 10, 9),
                ("INPUT2", 12, 64),
                ("SET_REPORT", 13, 9),
                ("SET_REPORT_REPLY", 14, 0),
            ]
        );
    }
}
