//! Composite device model: the single entry point of the engine.
//!
//! A host program owns one [`Device`] and feeds it [`Input`] values from its real or
//! virtual transports. It acts on every returned [`Output`], in order. Between inputs
//! it calls [`Device::handle`] with [`Input::Tick`] no later than
//! [`Device::next_deadline`]; that drives keepalives, time extensions, presence
//! timeouts and the other deadlines. The device is synchronous and deterministic: the
//! same inputs, times and entropy give the same outputs (`docs/DESIGN.md` §1, §4).
//!
//! # Structure (`docs/DESIGN.md` §5)
//!
//! - **FIDO HID**: [`Input::FidoReport`] → `lk_ctaphid::Ctaphid` → `lk_fido::Authenticator`
//!   (CBOR and U2F) and the Management CTAPHID vendor commands (`fido.rs`).
//! - **CCID**: [`Input::Ccid`] → `lk_ccid::Ccid` → the card session: SELECT by AID,
//!   routing to the selected applet, touch waits with time extensions, and the
//!   Security Domain's secure channel (`card.rs`).
//! - **OTP HID**: [`Input::OtpSetFeature`] / [`Input::OtpGetFeature`] → `lk_otp::OtpHid`
//!   with a Management bridge; keyboard output as [`Output::OtpKeyboard`].
//! - **Touch arbitration** and every timer (`presence.rs`).
//! - **Persistence**: `lk_core::Host` inside the device seals each record with
//!   [`storage::seal`] before [`lk_core::Store::save`] (`host.rs`).
//! - **Management**: the enabled USB capabilities decide which interfaces are active
//!   and which applications can be selected; a reboot request or a change of enabled
//!   interfaces re-enumerates and power-cycles the volatile state.
//!
//! # Time
//!
//! `now` must not go backwards; a smaller value than one seen before is treated as the
//! earlier value. [`Device::open`] is the device's power-up at time 0 of the program's
//! clock (the FIDO reset window of CTAP 2.1 §6.6 counts from it);
//! [`Device::open_at`] names another power-up time. Expired deadlines are processed at
//! the start of every [`Device::handle`] call, before its input, so an input is always
//! seen after everything that was due before it (a touch after a presence timeout does
//! not satisfy the request that timed out).

#![forbid(unsafe_code)]

mod apps;
mod card;
mod fido;
mod host;
mod presence;
pub mod storage;
mod usb;

use core::fmt;

use lk_ccid::Ccid;
use lk_core::{Capabilities, DeviceProfile, Entropy, Millis, Record, ResetKind, Store, UsbInterfaces};
use lk_ctaphid::Ctaphid;
use lk_mgmt::ConfigEffect;
use lk_otp::OtpHid;

use crate::apps::{AppId, Apps};
use crate::card::CardSession;
use crate::host::DeviceHost;
use crate::presence::{Touch, Waits};

pub use crate::presence::{KEEPALIVE_INTERVAL_MS, U2F_LATCH_MS, U2F_REQUEST_WINDOW_MS, WTX_INTERVAL_MS};
pub use crate::usb::{FIDO_REPORT_DESCRIPTOR, OTP_REPORT_DESCRIPTOR, UsbIdentity};

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
    /// The CCID class-specific control request `ABORT` (USB CCID Rev 1.1 §5.3.1),
    /// `wValue = bSeq << 8 | bSlot`.
    ///
    /// Added to the original enum because this request travels on the control pipe,
    /// not as a bulk-out message, so [`Input::Ccid`] cannot carry it; without it the
    /// program could not deliver the two-step abort (control request plus bulk
    /// `PC_to_RDR_Abort`, in either order, catalog appendix A "control/bulk ABORT in
    /// either delivery order"). An answer, if any, is an [`Output::Ccid`] bulk-in
    /// message.
    CcidControlAbort { slot: u8, seq: u8 },
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
    /// The bus was suspended. Nothing is lost (catalog appendix A `Linux_native`, runtime
    /// PM checks: "same address/services/bindings/exact bytes while suspended").
    Suspend,
    /// The bus resumed after [`BusEvent::Suspend`]: the card session ends and the CCID
    /// slot needs a new IccPowerOn (see [`Device::handle`]).
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
    /// The device rebooted (a Management write with `REBOOT`, or a power cycle that
    /// brings a stored interface change into effect); the host must re-enumerate with
    /// this set ([`Device::usb_identity`] describes it).
    Reenumerate(UsbInterfaces),
}

/// The composite device.
pub struct Device {
    host: DeviceHost,
    apps: Apps,
    ctaphid: Ctaphid,
    ccid: Ccid,
    otp_hid: OtpHid,
    card: CardSession,
    waits: Waits,
    /// A U2F touch granted during a request window, valid until this time.
    u2f_latch: Option<Millis>,
    touch: Touch,
    /// Capabilities in effect since the last enumeration.
    caps: Capabilities,
    /// Interfaces exposed since the last enumeration (`caps.interfaces()`).
    interfaces: UsbInterfaces,
    /// The last [`Output::PresenceIndicator`] state reported.
    indicator: bool,
    /// Source of request order numbers for touch arbitration.
    order: u64,
    /// A Management write through OTP HID or CTAPHID asked for a reboot.
    reboot_owed: bool,
    suspended: bool,
    unreadable: Vec<Record>,
}

impl fmt::Debug for Device {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Device")
            .field("host", &self.host)
            .field("interfaces", &self.interfaces)
            .field("selected", &self.card.selected)
            .field("secure_channel", &self.card.channel.is_some())
            .field("waits", &self.waits)
            .field("u2f_latch", &self.u2f_latch)
            .field("indicator", &self.indicator)
            .field("suspended", &self.suspended)
            .field("unreadable", &self.unreadable)
            .finish_non_exhaustive()
    }
}

impl Device {
    /// Power up a device at time 0 of the program's clock.
    ///
    /// Every record is loaded from `store` and opened with `storage_key`; each
    /// application is constructed with `new(stored, host)` (`docs/CONTRACTS.md`). A
    /// record that cannot be loaded or opened gives that application its factory state
    /// and never panics ([`Device::unreadable_records`] names such records). Applications
    /// that create their own identity on first start (Security Domain, PIV, OpenPGP)
    /// persist it during construction, except over a record that exists but could not be
    /// read: opening never overwrites one (a wrong storage key or a failing store loses
    /// nothing; the application's first mutating command replaces the record). Such a
    /// construction save that the store rejects is retried before every later input
    /// until the store takes it, so the identity the host reads is the one a later open
    /// finds (`docs/DESIGN.md` §7).
    pub fn open(profile: DeviceProfile, store: Box<dyn Store>, entropy: Box<dyn Entropy>, storage_key: [u8; 32]) -> Device {
        Self::open_at(0, profile, store, entropy, storage_key)
    }

    /// [`Device::open`] with power-up at time `now` of the program's clock.
    pub fn open_at(
        now: Millis,
        profile: DeviceProfile,
        store: Box<dyn Store>,
        entropy: Box<dyn Entropy>,
        storage_key: [u8; 32],
    ) -> Device {
        let atr = profile.atr.clone();
        let firmware = profile.firmware;
        let mut host = DeviceHost::new(profile, store, entropy, storage_key, now);
        let (apps, unreadable) = Apps::open(&mut host);
        let caps = apps.mgmt.management().enabled_usb(&host);
        Device {
            ctaphid: Ctaphid::new(firmware, fido::ctaphid_capabilities(caps)),
            ccid: Ccid::new(atr),
            otp_hid: OtpHid::new(),
            card: CardSession::new(),
            waits: Waits::default(),
            u2f_latch: None,
            touch: Touch::default(),
            caps,
            interfaces: caps.interfaces(),
            indicator: false,
            order: 0,
            reboot_owed: false,
            suspended: false,
            unreadable,
            host,
            apps,
        }
    }

    /// Process one input at host time `now` and return the resulting outputs in order.
    ///
    /// - Constructor state the store rejected at open is saved again first (see
    ///   [`Device::open`]).
    /// - Expired deadlines are processed next, in time order.
    /// - Inputs for an interface that is not enabled are ignored (`docs/DESIGN.md` §5:
    ///   Management turns interfaces on and off).
    /// - Bus events: `Reset` drops the pending FIDO operation, then resets CTAPHID
    ///   (`lk_ctaphid::Ctaphid::reset` emits no events, `docs/CONTRACTS.md`), resets
    ///   the CCID slot and the OTP HID framing, and calls `CardApplet::reset(UsbReset)`;
    ///   FIDO PIN tokens survive (`docs/DESIGN.md` §5: "`Reset` only resets the USB
    ///   level"). `PowerCycle` additionally calls `Authenticator::power_cycle` and
    ///   `CardApplet::reset(PowerCycle)`, and applies the enabled capabilities.
    ///   `Suspend` loses nothing. `Resume` ends the card session as a card power-off
    ///   and sends one `RDR_to_PC_NotifySlotChange` insertion (`50 03`) (catalog
    ///   appendix A `Linux_native`: "each occupied slot becomes inactive, insertion5003
    ///   once, no unpowered APDU, new PowerOn/ATR required; PIV PIN/admin revoked; real
    ///   terminal touch canceled without commit"; `lk_ccid::Ccid::reset`: "USB reset,
    ///   re-enumeration or resume"). FIDO and OTP state are kept.
    /// - After the input, a Management reboot request emits [`Output::Reenumerate`] with
    ///   the stored configuration and power-cycles the volatile state; a configuration
    ///   written without `REBOOT` waits for the next enumeration (`settle_management`)
    ///   (catalog appendix A `Linux_native`: "automatic management reboot and all seven
    ///   USB interface combinations, plus unchanged-profile reboot ... persistent
    ///   credentials retained and old PIN token rejected").
    /// - Finally [`Output::PresenceIndicator`] reports a change in whether any presence
    ///   request is pending.
    pub fn handle(&mut self, now: Millis, input: Input<'_>) -> Vec<Output> {
        let now = now.max(self.host.now);
        self.host.now = now;
        self.host.retry_deferred();
        let mut out = Vec::new();
        self.run_timers(now, &mut out);
        match input {
            Input::FidoReport(report) => {
                if self.interfaces.fido {
                    self.fido_report(now, report, &mut out);
                }
            }
            Input::OtpSetFeature(report) => {
                if self.interfaces.otp {
                    self.otp_set_feature(now, report);
                }
            }
            Input::OtpGetFeature => {
                if self.interfaces.otp {
                    let report = self.otp_hid.get_feature_at(self.apps.otp.otp(), now);
                    out.push(Output::OtpFeature(report));
                }
            }
            Input::Ccid(message) => {
                if self.interfaces.ccid {
                    self.ccid_message(message, &mut out);
                }
            }
            Input::CcidControlAbort { slot, seq } => {
                if self.interfaces.ccid {
                    self.ccid_control_abort(slot, seq, &mut out);
                }
            }
            Input::Touch(edge) => self.touch(edge, &mut out),
            Input::Tick => {}
            Input::Bus(event) => self.bus(event, &mut out),
        }
        self.settle_management(&mut out);
        self.update_indicator(&mut out);
        out
    }

    /// The latest time by which the host must deliver [`Input::Tick`], if any deadline
    /// is pending: the minimum of the CTAPHID message and lock timeouts, the CTAPHID
    /// KEEPALIVE cadence and the FIDO presence timeout, the CCID time-extension cadence
    /// and the card presence timeout, the OTP challenge-response timeout, and the U2F
    /// request window and latch expiry. The OTP button windows need no deadline:
    /// `lk_otp::Otp::touch_up` classifies a press by its duration when it is released.
    pub fn next_deadline(&self) -> Option<Millis> {
        self.next_timer().map(|(at, _)| at)
    }

    /// Set the wall-clock time (seconds since the Unix epoch) that backs
    /// `lk_core::Host::unix_time`, used only for certificate validity checks; `None`
    /// when the program has no trusted clock.
    ///
    /// The device never advances this value with `now` (`docs/DESIGN.md` §4: the engine
    /// reads no clock), so a program with a trusted clock sets it again whenever it
    /// moves, for example before each [`Device::handle`]. It starts as `None` at
    /// [`Device::open`].
    pub fn set_unix_time(&mut self, seconds: Option<u64>) {
        self.host.unix_time = seconds;
    }

    /// The device identity and descriptors for the interfaces enabled now.
    pub fn usb_identity(&self) -> UsbIdentity {
        let profile = &self.host.profile;
        let ids = profile.usb_product_ids;
        let serial_visible = [lk_otp::Slot::One, lk_otp::Slot::Two].into_iter().any(|slot| {
            self.apps
                .otp
                .otp()
                .config(slot)
                .is_some_and(|config| config.ext_flags & lk_otp::ext::SERIAL_USB_VISIBLE != 0)
        });
        UsbIdentity {
            vendor_id: profile.usb_vendor_id,
            // Management never leaves every application disabled, so a product ID always
            // exists; the full composite ID is the fallback.
            product_id: ids.for_interfaces(self.interfaces).unwrap_or(ids.otp_fido_ccid),
            device_release: profile.usb_device_release,
            manufacturer: profile.manufacturer.clone(),
            product: profile.product_string(self.interfaces),
            serial: serial_visible.then(|| profile.serial.to_string()),
            interfaces: self.interfaces,
            fido_report_descriptor: FIDO_REPORT_DESCRIPTOR.to_vec(),
            otp_report_descriptor: OTP_REPORT_DESCRIPTOR.to_vec(),
            ccid_class_descriptor: lk_ccid::descriptor::YUBIKEY_5C_NANO.to_bytes().to_vec(),
        }
    }

    /// The interfaces the device exposes now.
    pub fn interfaces(&self) -> UsbInterfaces {
        self.interfaces
    }

    /// The device identity.
    pub fn profile(&self) -> &DeviceProfile {
        &self.host.profile
    }

    /// Records that existed in the store at [`Device::open`] but could not be read
    /// (store error, wrong storage key, unknown format, modified bytes); their
    /// applications started from factory state.
    pub fn unreadable_records(&self) -> &[Record] {
        &self.unreadable
    }

    /// Whether any presence request is pending (the state last reported with
    /// [`Output::PresenceIndicator`]).
    pub fn presence_pending(&self) -> bool {
        self.indicator
    }

    fn next_order(&mut self) -> u64 {
        self.order += 1;
        self.order
    }

    /// OTP HID SET_REPORT: `lk_otp::OtpHid::set_feature` with the Management bridge.
    /// A write that ends a touch wait (a reset write, a new frame) drops the device's
    /// request too (`lk_otp::OtpHid::is_waiting_for_touch`); a challenge-response that
    /// needs a touch becomes a presence request.
    fn otp_set_feature(&mut self, now: Millis, report: &[u8; 8]) {
        let mut bridge = apps::Bridge::new(self.apps.mgmt.management_mut());
        let outcome = self.otp_hid.set_feature(report, self.apps.otp.otp_mut(), Some(&mut bridge), &mut self.host);
        self.reboot_owed |= bridge.reboot_requested();
        if self.waits.otp.is_some() && !self.otp_hid.is_waiting_for_touch() {
            self.waits.otp = None;
        }
        if let lk_core::Outcome::NeedTouch { timeout_ms } = outcome {
            let order = self.next_order();
            self.waits.otp = Some(presence::OtpWait {
                order,
                deadline: now.saturating_add(timeout_ms),
            });
        }
    }

    fn bus(&mut self, event: BusEvent, out: &mut Vec<Output>) {
        match event {
            BusEvent::Reset => self.usb_reset(),
            BusEvent::Suspend => self.suspended = true,
            BusEvent::Resume => {
                if std::mem::take(&mut self.suspended) {
                    self.drop_card_wait();
                    self.ccid.reset();
                    self.end_card_session(ResetKind::CardPowerOff);
                    if self.interfaces.ccid {
                        out.push(Output::CcidInterrupt(self.ccid.slot_change(true)));
                    }
                }
            }
            BusEvent::PowerCycle => {
                let before = self.interfaces;
                let caps = self.apps.mgmt.management().enabled_usb(&self.host);
                self.restart(caps);
                if self.interfaces != before {
                    out.push(Output::Reenumerate(self.interfaces));
                }
            }
        }
    }

    /// USB bus reset (`docs/DESIGN.md` §5; `docs/CONTRACTS.md` "Phase 0 as implemented",
    /// lk-ctaphid: drop the pending operation before `Ctaphid::reset`). Queued work of
    /// the old bus generation is discarded (catalog appendix A: "USB reset discards
    /// queued touch reports"; FIDO "fido_usb_bus_reset_old_report_isolation").
    fn usb_reset(&mut self) {
        self.drop_fido_wait();
        self.ctaphid.reset();
        self.drop_card_wait();
        self.ccid.reset();
        self.end_card_session(ResetKind::UsbReset);
        self.drop_otp_wait();
        self.otp_hid.reset(ResetKind::UsbReset);
        self.waits.u2f = None;
        self.u2f_latch = None;
        // A bus reset also ends a suspend (USB 2.0 §7.1.7.7: reset signalling wakes a
        // suspended device); no Resume follows it.
        self.suspended = false;
    }

    /// Power-cycle every volatile state and enumerate with `caps` (`docs/DESIGN.md` §5:
    /// "`PowerCycle` drops all volatile state: PIN tokens, sessions, selection, secure
    /// channel"). Pending requests end without replies: the transports they belonged
    /// to are gone.
    fn restart(&mut self, caps: Capabilities) {
        self.drop_fido_wait();
        self.drop_card_wait();
        self.drop_otp_wait();
        self.waits.u2f = None;
        self.u2f_latch = None;
        self.caps = caps;
        self.interfaces = caps.interfaces();
        self.ctaphid = Ctaphid::new(self.host.profile.firmware, fido::ctaphid_capabilities(caps));
        self.ccid.reset();
        self.otp_hid.reset(ResetKind::PowerCycle);
        self.end_card_session(ResetKind::PowerCycle);
        self.apps.fido.power_cycle(&mut self.host);
        self.touch = Touch::default();
        self.suspended = false;
        self.reboot_owed = false;
    }

    /// Reset every card applet with `kind` and forget the selection, the secure channel
    /// and any partly delivered response (`docs/DESIGN.md` §5 card session).
    fn end_card_session(&mut self, kind: ResetKind) {
        for id in AppId::ALL {
            self.apps.card(id).reset(kind);
        }
        self.card.clear();
    }

    /// After each input: a Management write that asked for a reboot re-enumerates the
    /// device with the stored configuration and power-cycles its volatile state, after
    /// the write's response has been output.
    ///
    /// - CCID: `MgmtApplet::take_effect` right after the WRITE CONFIG response
    ///   (`docs/CONTRACTS.md` "Applications A as implemented", lk-mgmt).
    /// - OTP HID and CCID OTP slot `0x15`: the bridge's recorded `ConfigEffect`.
    /// - CTAPHID `0x43`: `VendorReply::effect`.
    /// - A write without `REBOOT` changes nothing on the bus, also when it changes the
    ///   set of enabled interfaces: every configuration change applies at the next
    ///   enumeration (a reboot or [`BusEvent::PowerCycle`]), as `Management::enabled_usb`
    ///   documents. Model policy: ykman `config usb` and yubikit `write_device_config`
    ///   ask for `REBOOT` exactly when the interface set changes, which they would not
    ///   need if the firmware re-enumerated by itself.
    fn settle_management(&mut self, out: &mut Vec<Output>) {
        let ccid_effect = self.apps.mgmt.take_effect();
        let owed = std::mem::take(&mut self.reboot_owed) || ccid_effect == ConfigEffect::Reboot;
        if owed {
            let enabled = self.apps.mgmt.management().enabled_usb(&self.host);
            out.push(Output::Reenumerate(enabled.interfaces()));
            self.restart(enabled);
        }
    }

    /// Emit [`Output::PresenceIndicator`] when the set of pending presence requests
    /// becomes non-empty or empty.
    fn update_indicator(&mut self, out: &mut Vec<Output>) {
        let lit = self.waits.any();
        if lit != self.indicator {
            self.indicator = lit;
            out.push(Output::PresenceIndicator(lit));
        }
    }
}

#[cfg(test)]
mod tests;
