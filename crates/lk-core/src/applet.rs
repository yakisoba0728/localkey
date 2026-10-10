//! The contract between `lk-device` and the application crates. See `docs/CONTRACTS.md`.

use crate::{DeviceProfile, Entropy, Millis, Record, StoreError};

/// Services the device lends an application while it processes one command.
///
/// `Host` extends [`Entropy`], so `&mut dyn Host` can be passed wherever
/// `&mut dyn Entropy` is expected.
pub trait Host: Entropy {
    /// Current monotonic time.
    fn now(&self) -> Millis;

    /// The device identity.
    fn profile(&self) -> &DeviceProfile;

    /// Wall-clock time as seconds since the Unix epoch, if the program supplied one.
    /// Only certificate validity checks use it; protocol timing uses [`Host::now`].
    fn unix_time(&self) -> Option<u64> {
        None
    }

    /// Seal and durably store an application's serialized state.
    ///
    /// The application must call this **before** it reports success for a mutating
    /// command. On `Err` it must keep (or restore) its previous in-memory state and
    /// answer with its protocol's storage-failure status. Counters that must never be
    /// replayed (signature counters, HOTP counters, retry counters) are persisted
    /// before the response that reveals them.
    fn persist(&mut self, record: Record, plaintext: &[u8]) -> Result<(), StoreError>;
}

/// The result of a command that may have to wait for the user to touch the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome<T> {
    /// The command finished.
    Done(T),
    /// The command waits for a touch. The device holds it and later calls the
    /// application's resume method with `touched = false` if `timeout_ms` passes,
    /// the host cancels, or the session is reset first.
    NeedTouch { timeout_ms: Millis },
}

/// Which reset the device went through; it decides what volatile state is dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResetKind {
    /// CCID `PC_to_RDR_IccPowerOff`, or a new ATR: card sessions end.
    CardPowerOff,
    /// USB bus reset or same-configuration re-enumeration.
    UsbReset,
    /// Power removed and restored: all volatile state is lost.
    PowerCycle,
}

/// A smart-card application reachable through the CCID interface.
///
/// APDUs and responses are raw bytes. A response is the data followed by `SW1 SW2`.
/// Each applet handles its own command chaining and response chaining with the helpers
/// in `lk_codec::apdu`.
///
/// Constructors are not part of the trait. By convention each applet crate provides
/// `new(stored: Option<&[u8]>, host: &mut dyn Host) -> Self`. `stored` is the plaintext
/// last passed to [`Host::persist`]. If it is unreadable, the applet starts from its
/// factory state.
pub trait CardApplet {
    /// The application identifier this applet answers to.
    fn aid(&self) -> &'static [u8];

    /// Handle the SELECT that made this applet current.
    fn select(&mut self, apdu: &[u8], host: &mut dyn Host) -> Vec<u8>;

    /// Handle any other command while this applet is selected.
    fn process(&mut self, apdu: &[u8], host: &mut dyn Host) -> Outcome<Vec<u8>>;

    /// Finish the command that returned [`Outcome::NeedTouch`].
    fn touch_resolved(&mut self, touched: bool, host: &mut dyn Host) -> Vec<u8>;

    /// Another applet was selected; drop selection-scoped state.
    fn deselect(&mut self);

    /// Drop volatile state for `kind`.
    fn reset(&mut self, kind: ResetKind);
}
