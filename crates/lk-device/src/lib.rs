//! Composite device model: the single entry point of the engine.
//!
//! A host program owns one [`Device`] and feeds it [`Input`] values from its real or
//! virtual transports. It acts on every returned [`Output`]. Between inputs it calls
//! [`Device::handle`] with [`Input::Tick`] no later than [`Device::next_deadline`].
//! That drives keepalives, presence timeouts and other deadlines. The device is
//! synchronous and deterministic: the same inputs, times and entropy give the same
//! outputs. See `docs/DESIGN.md` §4–§5.
//!
//! Skeleton only: protocol handling is added phase by phase (§10).

#![forbid(unsafe_code)]

pub mod storage;

use lk_core::{Millis, UsbInterfaces};

/// Everything the host can deliver to the device.
#[derive(Debug)]
pub enum Input<'a> {
    /// One 64-byte CTAPHID output report written to the FIDO HID interface.
    FidoReport(&'a [u8; 64]),
    /// One 8-byte feature report written to the OTP HID interface (SET_REPORT).
    OtpSetFeature(&'a [u8; 8]),
    /// The host reads the OTP feature report (GET_REPORT).
    OtpGetFeature,
    /// One USB CCID bulk-out message (`PC_to_RDR_*`), header included.
    Ccid(&'a [u8]),
    /// The user touched or released the presence sensor.
    Touch(TouchEdge),
    /// Time advanced; process expired deadlines.
    Tick,
    /// A bus-level event visible to the device.
    Bus(BusEvent),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchEdge {
    Down,
    Up,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusEvent {
    /// USB bus reset or re-enumeration of the same configuration.
    Reset,
    Suspend,
    Resume,
    /// Power removed and restored: volatile state (PIN tokens, sessions) is lost.
    PowerCycle,
}

/// Everything the device asks its host to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// One 64-byte CTAPHID input report for the FIDO HID interface.
    FidoReport([u8; 64]),
    /// The next value returned by a GET_REPORT on the OTP feature report.
    OtpFeature([u8; 8]),
    /// One boot-keyboard input report typed by an OTP slot.
    OtpKeyboard([u8; 8]),
    /// One USB CCID bulk-in message (`RDR_to_PC_*`).
    Ccid(Vec<u8>),
    /// One CCID interrupt-in message (`RDR_to_PC_NotifySlotChange`).
    CcidInterrupt(Vec<u8>),
    /// The device is waiting for user presence (true) or stopped waiting (false).
    PresenceIndicator(bool),
    /// The enabled interfaces changed; the host must re-enumerate with this set.
    Reenumerate(UsbInterfaces),
}

/// The composite device.
#[derive(Debug, Default)]
pub struct Device {
    _private: (),
}

impl Device {
    /// Process one input at host time `now` and return the resulting outputs in order.
    pub fn handle(&mut self, now: Millis, input: Input<'_>) -> Vec<Output> {
        let _ = (now, input);
        Vec::new()
    }

    /// The latest time by which the host must deliver [`Input::Tick`], if any deadline is pending.
    pub fn next_deadline(&self) -> Option<Millis> {
        None
    }
}
