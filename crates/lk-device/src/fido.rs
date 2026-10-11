//! The FIDO HID interface: CTAPHID framing (`lk-ctaphid`) in front of the CTAP2/U2F
//! authenticator (`lk-fido`) and the Management CTAPHID vendor commands (`lk-mgmt`).
//!
//! - `CTAPHID_CBOR` (`0x10`) goes to `Authenticator::cbor`. A command that needs a touch
//!   stays outstanding; the device sends `CTAPHID_KEEPALIVE` with `STATUS_UPNEEDED`
//!   every [`crate::KEEPALIVE_INTERVAL_MS`] (CTAP 2.1 §11.2.9.1.7), the first one an
//!   interval after the request (measured, `docs/MEASUREMENT.md`, probe
//!   `selection-keepalive-cancel`), until a touch, a timeout, a cancel or an abort ends
//!   it.
//! - `CTAPHID_MSG` (`0x03`) goes to `Authenticator::u2f` with the latched touch
//!   (`docs/CONTRACTS.md` "lk-fido" U2F presence).
//! - Vendor commands (`0x40..=0x7F`, CTAP 2.1 §11.2.9.3): Management READ/WRITE CONFIG
//!   (`0x42`/`0x43`) through `Management::ctaphid_vendor`; YubiKey 4 SET MODE (`0x40`)
//!   through `Management::legacy_set_mode`; everything else `ERR_INVALID_CMD`, so the
//!   channel never stays busy (`docs/CONTRACTS.md` "Phase 0 as implemented",
//!   lk-ctaphid).
//! - `Event::Cancel` → `Authenticator::cancel` (CTAP 2.1 §11.2.9.1.5); the framer only
//!   emits it for an outstanding CBOR request, so a cancel during a U2F MSG is ignored
//!   (catalog FIDO: "CTAPHID_CANCEL during a U2F MSG is ignored").
//! - `Event::Abort` (INIT resynchronisation, CTAP 2.1 §11.2.5.3) drops the waiting
//!   command and never sends its late reply (catalog FIDO: "Allocated CTAPHID INIT now
//!   discards late replies from an aborted same-CID operation").
//! - `Event::Wink` (CTAP 2.1 §11.2.9.2.1, "the authenticator performs a vendor-defined
//!   action that provides some visual or audible identification"): when no presence
//!   request is pending, the device emits a pulse `PresenceIndicator(true)` followed by
//!   `PresenceIndicator(false)`; the program shows a short blink of its own length.
//!   While a request lights the indicator nothing more is shown.

use lk_core::{Capabilities, Millis, Outcome};
use lk_ctaphid::{Event, capability, cmd, err};
use lk_fido::U2fPresence;
use lk_mgmt::ConfigEffect;

use crate::{Device, Output};

/// CTAPHID INIT capability flags for the enabled applications (CTAP 2.1 §11.2.9.1.3):
/// `CAPABILITY_WINK` always; `CAPABILITY_CBOR` while FIDO2 is enabled; `CAPABILITY_NMSG`
/// ("does not implement CTAPHID_MSG") while U2F is disabled. With both enabled this is
/// `CBOR | WINK` (`0x05`), the flags of the reference device. The framer rejects a
/// command the flags do not advertise with `ERR_INVALID_CMD`.
pub(crate) fn ctaphid_capabilities(caps: Capabilities) -> u8 {
    let mut flags = capability::WINK;
    if caps.contains(Capabilities::FIDO2) {
        flags |= capability::CBOR;
    }
    if !caps.contains(Capabilities::U2F) {
        flags |= capability::NMSG;
    }
    flags
}

impl Device {
    /// One FIDO HID output report.
    pub(crate) fn fido_report(&mut self, now: Millis, report: &[u8; 64], out: &mut Vec<Output>) {
        let events = self.ctaphid.report(now, report);
        self.fido_events(now, events, out);
    }

    /// Act on framer events in the order given (each `Send` is output where it occurs).
    pub(crate) fn fido_events(&mut self, now: Millis, events: Vec<Event>, out: &mut Vec<Output>) {
        for event in events {
            match event {
                Event::Send(report) => out.push(Output::FidoReport(report)),
                Event::Request { cid, cmd, payload } => self.fido_request(now, cid, cmd, &payload, out),
                Event::Cancel { cid } => {
                    if self.waits.fido.is_some_and(|wait| wait.cid == cid) {
                        self.waits.fido = None;
                        // The framer only reports a cancel for an outstanding CBOR
                        // request, which is always the waiting command; the fallback
                        // keeps the channel from staying busy if it were not.
                        let response = self
                            .apps
                            .fido
                            .cancel(&mut self.host)
                            .unwrap_or_else(|| vec![lk_fido::status::KEEPALIVE_CANCEL]);
                        self.fido_respond(cid, cmd::CBOR, &response, out);
                    }
                }
                Event::Abort { cid } => {
                    if self.waits.fido.is_some_and(|wait| wait.cid == cid) {
                        self.drop_fido_wait();
                    }
                }
                // The pending set as it is now decides, not the state last reported: a
                // timer processed earlier in this `handle` may just have ended the last
                // request, and the pulse must not be swallowed. That pending set's end is
                // reported first, so the host sees off, on, off.
                Event::Wink => {
                    if !self.waits.any() {
                        if std::mem::take(&mut self.indicator) {
                            out.push(Output::PresenceIndicator(false));
                        }
                        out.push(Output::PresenceIndicator(true));
                        out.push(Output::PresenceIndicator(false));
                    }
                }
            }
        }
    }

    /// Frame a response for the outstanding request on `cid`.
    pub(crate) fn fido_respond(&mut self, cid: u32, command: u8, payload: &[u8], out: &mut Vec<Output>) {
        out.extend(self.ctaphid.respond(cid, command, payload).into_iter().map(Output::FidoReport));
    }

    fn fido_request(&mut self, now: Millis, cid: u32, command: u8, payload: &[u8], out: &mut Vec<Output>) {
        match command {
            cmd::CBOR => match self.apps.fido.cbor(payload, &mut self.host) {
                Outcome::Done(response) => self.fido_respond(cid, cmd::CBOR, &response, out),
                Outcome::NeedTouch { timeout_ms } => self.wait_fido(cid, timeout_ms),
            },
            cmd::MSG => {
                let latched = self.u2f_latch.is_some_and(|until| now < until);
                let (response, presence) = self.apps.fido.u2f(payload, latched, &mut self.host);
                match presence {
                    U2fPresence::Consumed => self.u2f_latch = None,
                    U2fPresence::Requested => self.request_u2f_presence(),
                    U2fPresence::NotNeeded => {}
                }
                self.fido_respond(cid, cmd::MSG, &response, out);
            }
            lk_mgmt::ctaphid::DEVICE_CONFIG => self.legacy_set_mode(cid, command, payload, out),
            vendor if (cmd::VENDOR_FIRST..=cmd::VENDOR_LAST).contains(&vendor) => {
                match self.apps.mgmt.management_mut().ctaphid_vendor(command, payload, &mut self.host) {
                    Some(reply) => {
                        self.fido_respond(cid, reply.cmd, &reply.payload, out);
                        self.reboot_owed |= reply.effect == ConfigEffect::Reboot;
                    }
                    None => self.fido_respond(cid, cmd::ERROR, &[err::INVALID_CMD], out),
                }
            }
            // The framer only delivers CBOR, MSG and vendor requests.
            _ => self.fido_respond(cid, cmd::ERROR, &[err::INVALID_CMD], out),
        }
    }

    /// CTAPHID `0x40`, YubiKey 4 SET MODE: not implemented by lk-mgmt (`6D00` on every
    /// transport, `docs/catalog/mgmt.md`). An unimplemented command is
    /// `ERR_INVALID_CMD` on CTAPHID (CTAP 2.1 §11.2.9.1.6).
    fn legacy_set_mode(&mut self, cid: u32, command: u8, payload: &[u8], out: &mut Vec<Output>) {
        match self.apps.mgmt.management_mut().legacy_set_mode(payload, &mut self.host) {
            Ok(effect) => {
                self.reboot_owed |= effect == ConfigEffect::Reboot;
                self.fido_respond(cid, command, &[], out);
            }
            Err(lk_codec::apdu::sw::INS_NOT_SUPPORTED) => {
                self.fido_respond(cid, cmd::ERROR, &[err::INVALID_CMD], out);
            }
            Err(status) => {
                let code = lk_mgmt::ctaphid::error_code(status);
                self.fido_respond(cid, cmd::ERROR, &[code], out);
            }
        }
    }
}
