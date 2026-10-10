//! The control-request state machine and the bus-event mapping (`docs/PROGRAM.md`
//! "lk-gadget", "Control requests" and "ep0 events"). Pure: the transport performs the
//! returned [`Action`] on `ep0`.
//!
//! Request codes: `include/uapi/linux/usb/ch9.h` (`USB_REQ_GET_DESCRIPTOR`),
//! `include/uapi/linux/hid.h` (`HID_REQ_*`, `HID_DT_HID`, `HID_DT_REPORT`), USB HID 1.11
//! §7.1–§7.2 for their fields, USB CCID Rev 1.1 §5.3 for the CCID class requests.
//!
//! Only interface-directed requests reach a FunctionFS function (`ffs_func_setup` in
//! `drivers/usb/gadget/function/f_fs.c` forwards endpoint-directed ones too, with
//! `wIndex` rewritten to the endpoint's 1-based index in the function rather than an
//! address (`ffs_func_revmap_ep`); without `FUNCTIONFS_ALL_CTRL_RECIP` nothing else); the
//! state machine stalls every request it does not name, including every request not
//! directed to an interface and any for an interface number not in the current layout.

use std::fmt;

use lk_device::BusEvent;
use lk_run::HostInput;

use crate::descriptor::{Function, Layout};
use crate::ffs::{CtrlRequest, DIR_IN, Event, RECIP_INTERFACE, RECIP_MASK, TYPE_CLASS, TYPE_MASK, TYPE_STANDARD};

/// `USB_REQ_GET_DESCRIPTOR` (`ch9.h`).
const REQ_GET_DESCRIPTOR: u8 = 0x06;
/// `HID_DT_HID` = `USB_TYPE_CLASS | 0x01`, `HID_DT_REPORT` = `USB_TYPE_CLASS | 0x02`
/// (`include/uapi/linux/hid.h`).
const DT_HID: u8 = 0x21;
const DT_REPORT: u8 = 0x22;
/// `enum hid_class_request` (`include/uapi/linux/hid.h`).
const HID_GET_REPORT: u8 = 0x01;
const HID_GET_IDLE: u8 = 0x02;
const HID_GET_PROTOCOL: u8 = 0x03;
const HID_SET_REPORT: u8 = 0x09;
const HID_SET_IDLE: u8 = 0x0A;
const HID_SET_PROTOCOL: u8 = 0x0B;
/// Report types in the high byte of `wValue` of GET_REPORT/SET_REPORT (USB HID 1.11
/// §7.2.1: 1 input, 2 output, 3 feature; not the kernel's internal `enum
/// hid_report_type`, which counts from 0).
const REPORT_OUTPUT: u8 = 2;
const REPORT_FEATURE: u8 = 3;
/// CCID class requests (USB CCID Rev 1.1 §5.3.1–§5.3.3).
const CCID_ABORT: u8 = 0x01;
/// The OTP feature report (`lk_otp::FEATURE_RPT_SIZE`, Yubico `ykdef.h`).
pub const OTP_FEATURE_LEN: usize = 8;
/// The CTAPHID report (CTAP 2.1 §11.2.4).
pub const FIDO_REPORT_LEN: usize = 64;
/// The largest keyboard output (LED) report this transport reads and ignores. The
/// descriptor's LED report is 1 byte (USB HID 1.11 Appendix B.1).
const MAX_KEYBOARD_OUTPUT: u16 = 64;
/// The default idle rate of the keyboard in 4 ms units: 500 ms, "the recommended default
/// idle rate ... for keyboards" (USB HID 1.11 §7.2.4). The FIDO interface defaults to 0
/// (indefinite, "infinity for joysticks and mice").
const KEYBOARD_DEFAULT_IDLE: u8 = 125;
/// Report protocol, the default of every HID device (USB HID 1.11 §7.2.6).
const REPORT_PROTOCOL: u8 = 1;

/// What the transport must do on `ep0` for one SETUP.
///
/// `Debug` shows sizes, never data.
#[derive(Clone, PartialEq, Eq)]
pub enum Action {
    /// Write this IN data stage (already cut to `wLength`).
    Reply(Vec<u8>),
    /// An OUT request without data stage: send the input (if any) to the runner, then
    /// acknowledge the status stage.
    Ack(Option<HostInput>),
    /// Read the OUT data stage of `length` bytes, then [`Received::input`].
    Receive { length: u16, then: Received },
    /// Ask the runner for the OTP feature report (`Input::OtpGetFeature`), then reply
    /// with at most `length` bytes of the answer, or stall if none comes in time.
    OtpGetFeature { length: u16 },
    /// Stall the request.
    Stall,
}

impl fmt::Debug for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::Reply(data) => f.debug_tuple("Reply").field(&format_args!("{} bytes", data.len())).finish(),
            Action::Ack(input) => f.debug_tuple("Ack").field(input).finish(),
            Action::Receive { length, then } => {
                f.debug_struct("Receive").field("length", length).field("then", then).finish()
            }
            Action::OtpGetFeature { length } => f.debug_struct("OtpGetFeature").field("length", length).finish(),
            Action::Stall => f.write_str("Stall"),
        }
    }
}

/// What the OUT data stage of a request becomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Received {
    /// OTP SET_REPORT(feature): `Input::OtpSetFeature`.
    OtpSetFeature,
    /// FIDO SET_REPORT(output): `Input::FidoReport`.
    FidoReport,
    /// Keyboard SET_REPORT(output) (LEDs): read and ignored.
    Ignore,
}

impl Received {
    /// The runner input for the data the host sent; `None` for ignored data and for a
    /// data stage shorter or longer than the report (the host sent fewer bytes than
    /// `wLength`).
    pub fn input(self, data: &[u8]) -> Option<HostInput> {
        match self {
            Received::OtpSetFeature => <[u8; OTP_FEATURE_LEN]>::try_from(data).ok().map(HostInput::OtpSetFeature),
            Received::FidoReport => <[u8; FIDO_REPORT_LEN]>::try_from(data).ok().map(HostInput::FidoReport),
            Received::Ignore => None,
        }
    }
}

/// Per-interface state of the control pipe.
#[derive(Debug, Clone)]
struct Slot {
    number: u8,
    function: Function,
    hid_descriptor: Vec<u8>,
    report_descriptor: Vec<u8>,
    /// SET_IDLE duration (4 ms units), kept per interface, no effect on the engine.
    idle: u8,
    /// SET_PROTOCOL value (0 boot, 1 report), kept per interface, no effect on the engine.
    protocol: u8,
}

impl Slot {
    fn default_idle(function: Function) -> u8 {
        if function == Function::Otp { KEYBOARD_DEFAULT_IDLE } else { 0 }
    }
}

/// The control-request state machine of one enumeration.
#[derive(Debug, Clone)]
pub struct Control {
    slots: Vec<Slot>,
}

impl Control {
    /// The state machine for the interfaces of `layout`, with HID idle and protocol at
    /// their defaults.
    pub fn new(layout: &Layout) -> Control {
        let slots = layout
            .interfaces
            .iter()
            .map(|i| Slot {
                number: i.number,
                function: i.function,
                hid_descriptor: i.class_descriptor.clone(),
                report_descriptor: i.report_descriptor.clone(),
                idle: Slot::default_idle(i.function),
                protocol: REPORT_PROTOCOL,
            })
            .collect();
        Control { slots }
    }

    /// Back to the defaults after a bus reset or plug-in.
    pub fn reset(&mut self) {
        for slot in &mut self.slots {
            slot.idle = Slot::default_idle(slot.function);
            slot.protocol = REPORT_PROTOCOL;
        }
    }

    /// The idle rate and protocol of an interface, for tests and diagnostics.
    pub fn hid_state(&self, interface: u8) -> Option<(u8, u8)> {
        self.slots.iter().find(|s| s.number == interface).map(|s| (s.idle, s.protocol))
    }

    /// Decide what to do with one SETUP.
    ///
    /// - HID interfaces: GET_DESCRIPTOR(HID `21`, index 0) and GET_DESCRIPTOR(report
    ///   `22`, index 0); SET_IDLE/GET_IDLE (report ID 0) and SET_PROTOCOL/GET_PROTOCOL
    ///   (0 or 1); OTP GET_REPORT(feature, ID 0) → [`Action::OtpGetFeature`]; OTP
    ///   SET_REPORT(feature, ID 0, 8 bytes) → `OtpSetFeature`; OTP SET_REPORT(output, ID
    ///   0, 1..=64 bytes) read and ignored (keyboard LEDs); FIDO SET_REPORT(output, ID 0,
    ///   64 bytes) → `FidoReport`. The descriptors use no report IDs, so a nonzero ID is
    ///   stalled (USB HID 1.11 §7.2.1: "set to 0 if Report IDs are not used").
    /// - CCID: ABORT (`wValue = bSeq << 8 | bSlot`, no data) → `CcidControlAbort`.
    ///   GET_CLOCK_FREQUENCIES and GET_DATA_RATES are stalled: the class descriptor has
    ///   `bNumClockSupported = 0` and `bNumDataRatesSupported = 0` (CCID Rev 1.1 §5.3.2,
    ///   §5.3.3).
    /// - Everything else, a request for an interface not in the layout, and a request
    ///   whose `wIndex` has a high byte, is stalled.
    pub fn setup(&mut self, request: &CtrlRequest) -> Action {
        if request.request_type & RECIP_MASK != RECIP_INTERFACE {
            return Action::Stall;
        }
        let Some(slot) = self.slots.iter_mut().find(|s| u16::from(s.number) == request.index) else {
            return Action::Stall;
        };
        match slot.function {
            Function::Otp | Function::Fido => hid(slot, request),
            Function::Ccid => ccid(request),
        }
    }
}

/// Cut a reply to `wLength`.
fn reply(data: &[u8], length: u16) -> Action {
    let end = data.len().min(usize::from(length));
    Action::Reply(data[..end].to_vec())
}

/// A request to a HID interface.
fn hid(slot: &mut Slot, request: &CtrlRequest) -> Action {
    let kind = request.request_type & (DIR_IN | TYPE_MASK);
    let [value_lo, value_hi] = request.value.to_le_bytes();
    match (kind, request.request) {
        (k, REQ_GET_DESCRIPTOR) if k == DIR_IN | TYPE_STANDARD => match (value_hi, value_lo) {
            (DT_HID, 0) => reply(&slot.hid_descriptor, request.length),
            (DT_REPORT, 0) => reply(&slot.report_descriptor, request.length),
            _ => Action::Stall,
        },
        (k, HID_GET_REPORT) if k == DIR_IN | TYPE_CLASS => {
            if slot.function == Function::Otp && value_hi == REPORT_FEATURE && value_lo == 0 && request.length > 0 {
                Action::OtpGetFeature { length: request.length }
            } else {
                Action::Stall
            }
        }
        (k, HID_GET_IDLE) if k == DIR_IN | TYPE_CLASS => {
            if request.value == 0 && request.length > 0 {
                reply(&[slot.idle], request.length)
            } else {
                Action::Stall
            }
        }
        (k, HID_GET_PROTOCOL) if k == DIR_IN | TYPE_CLASS => {
            if request.value == 0 && request.length > 0 {
                reply(&[slot.protocol], request.length)
            } else {
                Action::Stall
            }
        }
        (k, HID_SET_REPORT) if k == TYPE_CLASS => {
            if value_lo != 0 {
                return Action::Stall;
            }
            match (slot.function, value_hi, request.length) {
                (Function::Otp, REPORT_FEATURE, length) if usize::from(length) == OTP_FEATURE_LEN => {
                    Action::Receive { length, then: Received::OtpSetFeature }
                }
                (Function::Otp, REPORT_OUTPUT, length) if (1..=MAX_KEYBOARD_OUTPUT).contains(&length) => {
                    Action::Receive { length, then: Received::Ignore }
                }
                (Function::Fido, REPORT_OUTPUT, length) if usize::from(length) == FIDO_REPORT_LEN => {
                    Action::Receive { length, then: Received::FidoReport }
                }
                _ => Action::Stall,
            }
        }
        (k, HID_SET_IDLE) if k == TYPE_CLASS => {
            if value_lo == 0 && request.length == 0 {
                slot.idle = value_hi;
                Action::Ack(None)
            } else {
                Action::Stall
            }
        }
        (k, HID_SET_PROTOCOL) if k == TYPE_CLASS => {
            if request.value <= 1 && request.length == 0 {
                slot.protocol = value_lo;
                Action::Ack(None)
            } else {
                Action::Stall
            }
        }
        _ => Action::Stall,
    }
}

/// A request to the CCID interface.
fn ccid(request: &CtrlRequest) -> Action {
    let kind = request.request_type & (DIR_IN | TYPE_MASK);
    if kind == TYPE_CLASS && request.request == CCID_ABORT && request.length == 0 {
        let [slot, seq] = request.value.to_le_bytes();
        Action::Ack(Some(HostInput::CcidControlAbort { slot, seq }))
    } else {
        Action::Stall
    }
}

/// Maps ep0 events to bus events (`docs/PROGRAM.md` "ep0 events"), one enumeration long.
///
/// - The first not-enabled → enabled transition after the gadget is bound is a plug-in:
///   `BusEvent::PowerCycle`; later ones are `BusEvent::Reset` (the host configured the
///   device after a bus reset).
/// - An `ENABLE` while already enabled is no bus event: the composite framework calls
///   the function's `set_alt` once per interface on SET_CONFIGURATION (`set_config` in
///   `drivers/usb/gadget/composite.c`), and f_fs reports `ENABLE` for each
///   (`ffs_func_set_alt`), so one configuration of a three-interface device can yield
///   three; SET_INTERFACE also yields one. A bus reset or disconnect yields `DISABLE`
///   first (`reset_config` → `ffs_func_disable`).
/// - `SUSPEND` → `BusEvent::Suspend` (once until resumed); `RESUME` → `BusEvent::Resume`.
///   f_fs drops a pending `SUSPEND` when `RESUME` arrives before it was read
///   (`__ffs_event_add`), so a `RESUME` without a `SUSPEND` still means the bus was
///   suspended and resumed, and is passed on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BusTracker {
    plugged: bool,
    enabled: bool,
    suspended: bool,
}

impl BusTracker {
    /// The bus event for one ep0 event, if any.
    pub fn event(&mut self, event: &Event) -> Option<BusEvent> {
        match event {
            Event::Enable => {
                if self.enabled {
                    return None;
                }
                self.enabled = true;
                self.suspended = false;
                if self.plugged {
                    Some(BusEvent::Reset)
                } else {
                    self.plugged = true;
                    Some(BusEvent::PowerCycle)
                }
            }
            Event::Disable | Event::Unbind | Event::Bind => {
                self.enabled = false;
                None
            }
            Event::Suspend => {
                if self.suspended {
                    return None;
                }
                self.suspended = true;
                Some(BusEvent::Suspend)
            }
            Event::Resume => {
                self.suspended = false;
                Some(BusEvent::Resume)
            }
            Event::Setup(_) | Event::Unknown(_) => None,
        }
    }

    /// Whether the host has the function configured.
    pub fn enabled(&self) -> bool {
        self.enabled
    }
}

#[cfg(test)]
mod tests;
