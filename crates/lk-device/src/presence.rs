//! Touch arbitration, presence requests and every device timer.
//!
//! A presence request is a command waiting for the user: a CTAP2 command
//! (`Outcome::NeedTouch` from `Authenticator::cbor`), a card command (`Outcome::NeedTouch`
//! from a `CardApplet`), an OTP HID challenge-response, or a U2F request window opened
//! by `U2fPresence::Requested`. Each gets an order number when it starts.
//!
//! - `Touch(Down)` satisfies the earliest pending request only (`docs/DESIGN.md` §5:
//!   "one touch satisfies only the earliest waiting request").
//! - With no request pending, a press is an OTP button press: `Otp::touch_down` at
//!   contact and `Otp::touch_up` at release. `lk-otp` classifies the hold by its
//!   duration with the windows of the OTP catalog ("documented short/long hold release
//!   windows"; Yubico "Slots": short touch 0.3–1.5 s → slot 1, long touch 2.5–5 s →
//!   slot 2, `lk_otp::SHORT_TOUCH_MS` / `LONG_TOUCH_MS`, the same classification as
//!   `Otp::button`), and types a single configured slot 1 at contact (catalog OTP:
//!   "private touch_down/touch_up events return single-slot 1 FAST_TRIG reports at
//!   modeled contact, defer two-slot selection to release").
//! - A touch belongs to what it started as. A press that began with no request
//!   pending stays an OTP press even if a request starts while the sensor is held;
//!   that request waits for the next touch. A touch that satisfied a request never
//!   also types (catalog OTP: "a touch owned by a pending challenge-response never also
//!   types").
//!
//! Timers fire in time order; for equal times in the order of [`Timer`]. Periodic
//! timers (KEEPALIVE, CCID time extension) run on a fixed grid from the moment their
//! request started waiting: the next message is due at the first grid point after the
//! time the previous one was processed. A host whose timer fires late therefore never
//! stretches the cadence (CTAP 2.1 §11.2.9.1.7: KEEPALIVE "at least every 100ms"; a
//! cadence rescheduled from the processing time would drift by the host's lateness on
//! every message), and a `Tick` that is late by several intervals still sends one
//! message rather than a burst of stale ones.

use lk_core::Millis;
use lk_ctaphid::{cmd, keepalive};

use crate::apps::AppId;
use crate::{Device, Output, TouchEdge};

/// CTAPHID KEEPALIVE cadence while a CTAP2 command waits for a touch. CTAP 2.1
/// §11.2.9.1.7: KEEPALIVE "should be sent at least every 100ms and whenever the status
/// changes". The first one goes out as soon as the command starts waiting, the others
/// at `start + k * 100 ms` (a grid from the start, see the module documentation). The
/// status is always `STATUS_UPNEEDED`: the engine is synchronous, so a pending command
/// is always one waiting for user presence.
pub const KEEPALIVE_INTERVAL_MS: Millis = 100;

/// CCID time-extension cadence while a card command waits for a touch: one
/// `RDR_to_PC_DataBlock` with `bStatus` `80` (USB CCID Rev 1.1 §6.2.6,
/// `lk_ccid::Ccid::time_extension`) every 500 ms on a grid from the command's arrival
/// (`start + k * 500 ms`, k ≥ 1; module documentation). Model policy: the reference
/// timing is unmeasured (catalog appendix B `ccid_extended_chaining_wtx_and_eof`:
/// "reference_timing_unverified"). 500 ms keeps well inside libccid's T=1 read timeout
/// for the profile ATR (`ifdhandler.c` `T1_card_timeout`: the card's waiting times from
/// the ATR plus 1000 ms, about 1.5 to 2.5 s), which every time extension restarts, while
/// sending few messages.
pub const WTX_INTERVAL_MS: Millis = 500;

/// How long a U2F request window stays open after the last `6985` reply that asked for
/// presence (`U2fPresence::Requested`, `docs/CONTRACTS.md` "lk-fido"). Clients poll a
/// U2F request every few hundred milliseconds while it answers `6985`, so the window
/// stays open as long as a client keeps asking. Model policy (the U2F raw message
/// specification leaves the time to the device).
pub const U2F_REQUEST_WINDOW_MS: Millis = 3_000;

/// How long a touch given during a U2F request window stays latched for the next U2F
/// request that needs presence. Model policy, see [`U2F_REQUEST_WINDOW_MS`].
pub const U2F_LATCH_MS: Millis = 3_000;

/// Upper bound on timer steps in one call; every step removes its timer or moves it
/// past `now`, so the bound is never reached in practice.
const MAX_TIMER_STEPS: usize = 64;

/// A CTAP2 command waiting for a touch on CTAPHID channel `cid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FidoWait {
    pub(crate) cid: u32,
    pub(crate) order: u64,
    /// When the command started waiting: the origin of the KEEPALIVE grid.
    pub(crate) started: Millis,
    pub(crate) deadline: Millis,
    pub(crate) keepalive_at: Millis,
}

/// A card command (XfrBlock `seq`) waiting for a touch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CardWait {
    pub(crate) seq: u8,
    pub(crate) app: AppId,
    pub(crate) order: u64,
    /// When the command started waiting: the origin of the time-extension grid.
    pub(crate) started: Millis,
    pub(crate) deadline: Millis,
    pub(crate) wtx_at: Millis,
    /// The command came through the secure channel; its response is wrapped.
    pub(crate) wrap: bool,
    /// Ne of the host's command, for splitting a wrapped response.
    pub(crate) max: usize,
}

/// An OTP HID challenge-response waiting for a touch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OtpWait {
    pub(crate) order: u64,
    pub(crate) deadline: Millis,
}

/// A U2F request window: the next touch is latched for U2F.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct U2fWindow {
    pub(crate) order: u64,
    pub(crate) until: Millis,
}

/// The pending presence requests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Waits {
    pub(crate) fido: Option<FidoWait>,
    pub(crate) card: Option<CardWait>,
    pub(crate) otp: Option<OtpWait>,
    pub(crate) u2f: Option<U2fWindow>,
}

impl Waits {
    /// Whether any request is pending.
    pub(crate) fn any(&self) -> bool {
        self.fido.is_some() || self.card.is_some() || self.otp.is_some() || self.u2f.is_some()
    }

    /// The pending request that started first.
    fn earliest(&self) -> Option<WaitKind> {
        [
            self.fido.map(|w| (w.order, WaitKind::Fido)),
            self.card.map(|w| (w.order, WaitKind::Card)),
            self.otp.map(|w| (w.order, WaitKind::Otp)),
            self.u2f.map(|w| (w.order, WaitKind::U2f)),
        ]
        .into_iter()
        .flatten()
        .min_by_key(|&(order, _)| order)
        .map(|(_, kind)| kind)
    }
}

impl Waits {
    /// The kind of [`Waits::earliest`] as text, for unit tests.
    #[cfg(test)]
    pub(crate) fn earliest_for_test(&self) -> Option<&'static str> {
        self.earliest().map(|kind| match kind {
            WaitKind::Fido => "fido",
            WaitKind::Card => "card",
            WaitKind::Otp => "otp",
            WaitKind::U2f => "u2f",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaitKind {
    Fido,
    Card,
    Otp,
    U2f,
}

/// The physical sensor as the device last saw it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Touch {
    down: bool,
    /// The current touch satisfied a presence request.
    claimed: bool,
}

/// Every timer of the device, in the order used to break ties.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Timer {
    /// `Ctaphid::next_deadline`: message assembly timeout, channel lock expiry.
    Ctaphid,
    Keepalive,
    FidoTimeout,
    Wtx,
    CardTimeout,
    OtpTimeout,
    U2fWindow,
    U2fLatch,
}

impl Device {
    /// The earliest timer, if any.
    pub(crate) fn next_timer(&self) -> Option<(Millis, Timer)> {
        let fido = self.waits.fido;
        let card = self.waits.card;
        [
            (self.ctaphid.next_deadline(), Timer::Ctaphid),
            (fido.map(|w| w.keepalive_at), Timer::Keepalive),
            (fido.map(|w| w.deadline), Timer::FidoTimeout),
            (card.map(|w| w.wtx_at), Timer::Wtx),
            (card.map(|w| w.deadline), Timer::CardTimeout),
            (self.waits.otp.map(|w| w.deadline), Timer::OtpTimeout),
            (self.waits.u2f.map(|w| w.until), Timer::U2fWindow),
            (self.u2f_latch, Timer::U2fLatch),
        ]
        .into_iter()
        .filter_map(|(at, timer)| at.map(|at| (at, timer)))
        .min_by_key(|&(at, _)| at)
    }

    /// Process every timer due at `now`, earliest first.
    pub(crate) fn run_timers(&mut self, now: Millis, out: &mut Vec<Output>) {
        for _ in 0..MAX_TIMER_STEPS {
            match self.next_timer() {
                Some((at, timer)) if at <= now => self.fire(timer, now, out),
                _ => return,
            }
        }
    }

    fn fire(&mut self, timer: Timer, now: Millis, out: &mut Vec<Output>) {
        match timer {
            Timer::Ctaphid => {
                let events = self.ctaphid.tick(now);
                self.fido_events(now, events, out);
            }
            Timer::Keepalive => {
                if let Some(wait) = self.waits.fido.as_mut() {
                    wait.keepalive_at = next_on_grid(wait.started, KEEPALIVE_INTERVAL_MS, now);
                    out.push(Output::FidoReport(self.ctaphid.keepalive(wait.cid, keepalive::UPNEEDED)));
                }
            }
            // `docs/CONTRACTS.md` "Applications A as implemented": on timeout lk-device
            // calls `presence_resolved(false)` / `touch_resolved(false)`.
            Timer::FidoTimeout => self.resolve_fido(false, out),
            Timer::Wtx => {
                if let Some(wait) = self.waits.card.as_mut() {
                    wait.wtx_at = next_on_grid(wait.started, WTX_INTERVAL_MS, now);
                    out.push(Output::Ccid(self.ccid.time_extension(wait.seq)));
                }
            }
            Timer::CardTimeout => self.resolve_card(false, out),
            Timer::OtpTimeout => self.drop_otp_wait(),
            Timer::U2fWindow => self.waits.u2f = None,
            Timer::U2fLatch => self.u2f_latch = None,
        }
    }

    /// One edge of the presence sensor; see the module documentation.
    pub(crate) fn touch(&mut self, edge: TouchEdge, out: &mut Vec<Output>) {
        match edge {
            TouchEdge::Down => {
                if self.touch.down {
                    return;
                }
                self.touch.down = true;
                self.touch.claimed = match self.waits.earliest() {
                    Some(kind) => {
                        self.grant(kind, out);
                        true
                    }
                    None => false,
                };
                if !self.touch.claimed && self.interfaces.otp {
                    let reports = self.apps.otp.otp_mut().touch_down(&mut self.host);
                    out.extend(reports.into_iter().map(Output::OtpKeyboard));
                }
            }
            TouchEdge::Up => {
                if !self.touch.down {
                    return;
                }
                self.touch.down = false;
                if !self.touch.claimed && self.interfaces.otp {
                    let reports = self.apps.otp.otp_mut().touch_up(&mut self.host);
                    out.extend(reports.into_iter().map(Output::OtpKeyboard));
                }
            }
        }
    }

    /// Give the touch to one pending request.
    fn grant(&mut self, kind: WaitKind, out: &mut Vec<Output>) {
        match kind {
            WaitKind::Fido => self.resolve_fido(true, out),
            WaitKind::Card => self.resolve_card(true, out),
            WaitKind::Otp => {
                if self.waits.otp.take().is_some() {
                    self.otp_hid.touch_resolved(true, self.apps.otp.otp_mut(), &mut self.host);
                }
            }
            // `docs/CONTRACTS.md` "lk-fido": after `Requested` the device latches the
            // next touch for a later U2F request.
            WaitKind::U2f => {
                self.waits.u2f = None;
                self.u2f_latch = Some(self.host.now.saturating_add(U2F_LATCH_MS));
            }
        }
    }

    /// Finish the waiting CTAP2 command and send its response.
    pub(crate) fn resolve_fido(&mut self, granted: bool, out: &mut Vec<Output>) {
        if let Some(wait) = self.waits.fido.take() {
            let response = self.apps.fido.presence_resolved(granted, &mut self.host);
            self.fido_respond(wait.cid, cmd::CBOR, &response, out);
        }
    }

    /// Finish the waiting card command and send its response.
    pub(crate) fn resolve_card(&mut self, granted: bool, out: &mut Vec<Output>) {
        if let Some(wait) = self.waits.card.take() {
            let response = self.apps.card(wait.app).touch_resolved(granted, &mut self.host);
            let response = self.finish(Some(wait.app), response, wait.wrap, wait.max);
            self.send_card_response(wait.seq, response, out);
        }
    }

    /// Drop the waiting CTAP2 command without a reply (INIT resynchronisation, USB
    /// reset, power cycle). `docs/CONTRACTS.md`: the aborted request's late reply is
    /// never sent.
    pub(crate) fn drop_fido_wait(&mut self) {
        if self.waits.fido.take().is_some() {
            let _ = self.apps.fido.presence_resolved(false, &mut self.host);
        }
    }

    /// Drop the waiting card command without a reply (CCID abort, card power-off,
    /// reset): its `touch_resolved(false)` cleans the applet up and the response is
    /// discarded.
    pub(crate) fn drop_card_wait(&mut self) {
        if let Some(wait) = self.waits.card.take() {
            let _ = self.apps.card(wait.app).touch_resolved(false, &mut self.host);
        }
    }

    /// End the OTP HID touch wait without a touch (timeout, reset). The host reads an
    /// unchanged status (`OtpHid::touch_resolved`).
    pub(crate) fn drop_otp_wait(&mut self) {
        if self.waits.otp.take().is_some() {
            self.otp_hid.touch_resolved(false, self.apps.otp.otp_mut(), &mut self.host);
        }
    }

    /// Record a card command waiting for a touch.
    pub(crate) fn wait_card(&mut self, seq: u8, app: AppId, outcome_timeout: Millis, wrap: bool, max: usize) {
        let now = self.host.now;
        let order = self.next_order();
        self.waits.card = Some(CardWait {
            seq,
            app,
            order,
            started: now,
            deadline: now.saturating_add(outcome_timeout),
            wtx_at: now.saturating_add(WTX_INTERVAL_MS),
            wrap,
            max,
        });
    }

    /// Record a CTAP2 command waiting for a touch and send the first KEEPALIVE.
    pub(crate) fn wait_fido(&mut self, cid: u32, timeout_ms: Millis, out: &mut Vec<Output>) {
        let now = self.host.now;
        let order = self.next_order();
        self.waits.fido = Some(FidoWait {
            cid,
            order,
            started: now,
            deadline: now.saturating_add(timeout_ms),
            keepalive_at: now.saturating_add(KEEPALIVE_INTERVAL_MS),
        });
        out.push(Output::FidoReport(self.ctaphid.keepalive(cid, keepalive::UPNEEDED)));
    }

    /// Open (or extend) the U2F request window after a `Requested` reply.
    pub(crate) fn request_u2f_presence(&mut self) {
        let until = self.host.now.saturating_add(U2F_REQUEST_WINDOW_MS);
        match self.waits.u2f.as_mut() {
            Some(window) => window.until = until,
            None => {
                let order = self.next_order();
                self.waits.u2f = Some(U2fWindow { order, until });
            }
        }
    }
}

/// The first point of the grid `started + k * interval` (k ≥ 1) after `now`, for a
/// periodic message processed at `now` (module documentation). Always later than `now`
/// (`now ≥ started`, `interval > 0`), so the timer loop makes progress.
pub(crate) fn next_on_grid(started: Millis, interval: Millis, now: Millis) -> Millis {
    let elapsed = now.saturating_sub(started);
    let steps = elapsed / interval + 1;
    started.saturating_add(steps.saturating_mul(interval))
}
