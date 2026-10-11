//! The CTAPHID state machine (CTAP 2.1 §11.2.5 to §11.2.9).
//!
//! # Order of checks for an initialization packet
//!
//! The specification does not fix which error wins when several apply, and the
//! behaviour catalog records the physical precedence as unmeasured. The engine applies
//! this model policy:
//!
//! 1. `CTAPHID_CANCEL` is never answered (§11.2.9.1.5). It acts only on the
//!    outstanding CBOR request of its own channel and is ignored otherwise.
//! 2. Channel: channel 0, an identifier never allocated (or allocated before the last
//!    USB reset), and the broadcast channel with any command but INIT are answered
//!    `ERR_INVALID_CHANNEL`.
//! 3. Busy: while a transaction is active on another channel, `ERR_CHANNEL_BUSY`
//!    (§11.2.5.1). On the transaction's own channel, `CTAPHID_INIT` resynchronises
//!    (§11.2.5.3). Any other command gets `ERR_CHANNEL_BUSY` while the request is with
//!    the application. While a message is still arriving it gets `ERR_INVALID_SEQ`, and
//!    the partial message is dropped.
//! 4. Command: unknown or unadvertised commands `ERR_INVALID_CMD` (`CTAPHID_LOCK`
//!    included: the measured device does not implement it, `docs/MEASUREMENT.md`, probes
//!    `lock` and `lock-expiry`; whether a busy device answers LOCK with `CHANNEL_BUSY` or
//!    `INVALID_CMD` was not measured), then a BCNT that the command does not allow
//!    `ERR_INVALID_LEN` (above [`MAX_MESSAGE_LEN`], 1536, measured on a YubiKey 5C Nano
//!    5.7.4 with probe `ping-max`; or outside the request layout of the command: an empty
//!    MSG request, a WINK with data).
//!
//! A `CTAPHID_CBOR` request with BCNT 0 is never answered: the device stays busy with it
//! on that channel, so other channels get `ERR_CHANNEL_BUSY`, `CTAPHID_CANCEL` on the
//! channel changes nothing and no message timeout applies; only `CTAPHID_INIT` on that
//! channel (or a USB reset) frees the device. Measured on a YubiKey 5C Nano 5.7.4
//! (`docs/MEASUREMENT.md`, probe `empty-cbor`, and "The stuck-channel incident"). The
//! application sees none of it: no [`Event::Request`], and no [`Event::Cancel`] or
//! [`Event::Abort`] for it; [`Ctaphid::outstanding`] stays `None`. An empty
//! `CTAPHID_MSG` was not measured and stays `ERR_INVALID_LEN`.
//!
//! Continuation packets are never answered unless they belong to the message being
//! assembled. A packet out of sequence there is answered `ERR_INVALID_SEQ` and ends
//! the transaction; any other continuation packet is ignored (§11.2.5.4).

use lk_core::{Millis, Version};

use crate::channel::CidAllocator;
use crate::event::Event;
use crate::packet::{self, Packet};
use crate::protocol::{
    BROADCAST_CID, MAX_MESSAGE_LEN, PROTOCOL_VERSION, REPORT_LEN, capability, cmd, err,
};
use crate::transaction::{Assembly, Progress, Transaction};

/// Length of the `CTAPHID_INIT` request nonce (CTAP 2.1 §11.2.9.1.3).
const INIT_NONCE_LEN: usize = 8;

/// The CTAPHID framer for one FIDO HID interface.
#[derive(Debug, Clone)]
pub struct Ctaphid {
    version: Version,
    capabilities: u8,
    cids: CidAllocator,
    active: Option<Transaction>,
}

fn send_error(out: &mut Vec<Event>, cid: u32, code: u8) {
    out.push(Event::Send(packet::error(cid, code)));
}

impl Ctaphid {
    /// A framer that reports `version` and the `capabilities` flags
    /// ([`capability::WINK`], [`capability::CBOR`], [`capability::NMSG`]) in its
    /// `CTAPHID_INIT` response and accepts only the commands those flags advertise.
    pub fn new(version: Version, capabilities: u8) -> Self {
        Self {
            version,
            capabilities,
            cids: CidAllocator::new(),
            active: None,
        }
    }

    /// Handles one 64-byte output report received at `now`.
    ///
    /// Timeouts due by `now` are applied first, so a packet that arrives after its
    /// message expired is treated exactly as if [`Ctaphid::tick`] had run before it.
    pub fn report(&mut self, now: Millis, report: &[u8; REPORT_LEN]) -> Vec<Event> {
        let mut out = self.tick(now);
        match packet::parse(report) {
            Packet::Init {
                cid,
                cmd,
                bcnt,
                data,
            } => self.on_init_packet(now, cid, cmd, usize::from(bcnt), data, &mut out),
            Packet::Cont { cid, seq, data } => self.on_cont_packet(now, cid, seq, data, &mut out),
        }
        out
    }

    /// Frames the application's answer to the outstanding request on `cid` and ends
    /// the transaction. `cmd` is the response command (normally the request's command,
    /// or [`cmd::ERROR`]); bit 7 is set by the framer.
    ///
    /// Returns nothing when `cid` has no outstanding request, for example after an
    /// INIT resynchronisation or USB reset discarded it (`reference/BEHAVIOR_CATALOG.md`
    /// FIDO: "Allocated CTAPHID INIT now discards late replies from an aborted same-CID
    /// operation"). After a USB reset this always holds, because earlier channels are
    /// invalid and never reused. After INIT resynchronisation the channel stays the
    /// same, so a stale answer that arrives after the host has started a new request on
    /// it would be framed as the new answer; the device must therefore drop its pending
    /// operation when it sees [`Event::Abort`]. A payload longer than
    /// [`crate::MAX_PAYLOAD`] is answered `ERR_OTHER`.
    pub fn respond(&mut self, cid: u32, cmd: u8, payload: &[u8]) -> Vec<[u8; REPORT_LEN]> {
        match self.active {
            Some(Transaction::Processing { cid: owner, .. }) if owner == cid => {
                self.active = None;
                packet::fragment(cid, cmd, payload)
            }
            _ => Vec::new(),
        }
    }

    /// A `CTAPHID_KEEPALIVE` report with `status`
    /// ([`crate::keepalive::PROCESSING`] or [`crate::keepalive::UPNEEDED`]),
    /// CTAP 2.1 §11.2.9.1.7.
    pub fn keepalive(&self, cid: u32, status: u8) -> [u8; REPORT_LEN] {
        packet::single(cid, cmd::KEEPALIVE, &[status])
    }

    /// Applies the passage of time: an incomplete message whose next packet is overdue
    /// is abandoned with `ERR_MSG_TIMEOUT` on its channel (CTAP 2.1 §11.2.5.2).
    pub fn tick(&mut self, now: Millis) -> Vec<Event> {
        let mut out = Vec::new();
        if let Some(Transaction::Assembling(assembly)) = &self.active
            && now >= assembly.deadline()
        {
            send_error(&mut out, assembly.cid(), err::MSG_TIMEOUT);
            self.active = None;
        }
        out
    }

    /// The earliest time at which [`Ctaphid::tick`] has work to do, if any.
    pub fn next_deadline(&self) -> Option<Millis> {
        match &self.active {
            Some(Transaction::Assembling(assembly)) => Some(assembly.deadline()),
            _ => None,
        }
    }

    /// USB bus reset: drops any partial message and outstanding request, and forgets
    /// every allocated channel. The device must drop its own pending operation as well;
    /// a later `respond` for it sends nothing.
    pub fn reset(&mut self) {
        self.active = None;
        self.cids.forget_all();
    }

    /// The channel and command of the request the application still has to answer.
    pub fn outstanding(&self) -> Option<(u32, u8)> {
        match self.active {
            Some(Transaction::Processing { cid, cmd }) => Some((cid, cmd)),
            _ => None,
        }
    }

    fn on_init_packet(
        &mut self,
        now: Millis,
        cid: u32,
        command: u8,
        bcnt: usize,
        data: &[u8],
        out: &mut Vec<Event>,
    ) {
        if command == cmd::CANCEL {
            self.on_cancel(cid, out);
            return;
        }
        if let Err(code) = self.admit(cid, command) {
            send_error(out, cid, code);
            return;
        }
        if command == cmd::INIT {
            self.on_channel_init(cid, bcnt, data, out);
            return;
        }
        if let Err(code) = self.check_request(command, bcnt) {
            send_error(out, cid, code);
            return;
        }
        // `data` holds the 57 initialization-packet bytes: a message that fits is
        // complete now; a longer one waits for continuation packets.
        match data.get(..bcnt) {
            Some(payload) => self.execute(cid, command, payload.to_vec(), out),
            None => {
                self.active = Some(Transaction::Assembling(Assembly::start(
                    now, cid, command, bcnt, data,
                )));
            }
        }
    }

    /// Steps 2 and 3 of the module-level check order: channel, busy.
    fn admit(&mut self, cid: u32, command: u8) -> Result<(), u8> {
        let is_init = command == cmd::INIT;
        let valid = if cid == BROADCAST_CID {
            is_init
        } else {
            self.cids.is_allocated(cid)
        };
        if !valid {
            return Err(err::INVALID_CHANNEL);
        }
        match &self.active {
            None => Ok(()),
            Some(active) if active.cid() != cid => Err(err::CHANNEL_BUSY),
            Some(_) if is_init => Ok(()),
            Some(Transaction::Processing { .. } | Transaction::Stalled { .. }) => {
                Err(err::CHANNEL_BUSY)
            }
            Some(Transaction::Assembling(_)) => {
                self.active = None;
                Err(err::INVALID_SEQ)
            }
        }
    }

    /// Step 4 of the module-level check order for a request other than INIT/CANCEL.
    ///
    /// Request lengths (CTAP 2.1): MSG carries `BCNT 1..(n+1)`, a command byte then data
    /// (§11.2.9.1.1); WINK carries `BCNT 0` (§11.2.9.2.1). CBOR takes `BCNT 0` too, which
    /// stalls the device (module documentation). Every request is at most
    /// [`MAX_MESSAGE_LEN`] bytes. `CTAPHID_LOCK` falls through to `ERR_INVALID_CMD`.
    fn check_request(&self, command: u8, bcnt: usize) -> Result<(), u8> {
        let advertises = |flag: u8| self.capabilities & flag != 0;
        let length_ok = match command {
            cmd::PING => true,
            cmd::MSG if !advertises(capability::NMSG) => bcnt > 0,
            cmd::CBOR if advertises(capability::CBOR) => true,
            cmd::WINK if advertises(capability::WINK) => bcnt == 0,
            cmd::VENDOR_FIRST..=cmd::VENDOR_LAST => true,
            _ => return Err(err::INVALID_CMD),
        };
        if length_ok && bcnt <= MAX_MESSAGE_LEN {
            Ok(())
        } else {
            Err(err::INVALID_LEN)
        }
    }

    /// `CTAPHID_INIT` (CTAP 2.1 §11.2.9.1.3): on the broadcast channel it allocates a
    /// channel; on an allocated channel it resynchronises, discarding that channel's
    /// transaction (§11.2.5.3), and reports the same channel identifier.
    fn on_channel_init(&mut self, cid: u32, bcnt: usize, data: &[u8], out: &mut Vec<Event>) {
        let nonce = match data.get(..bcnt) {
            Some(nonce) if bcnt == INIT_NONCE_LEN => nonce,
            _ => return send_error(out, cid, err::INVALID_LEN),
        };
        let channel = if cid == BROADCAST_CID {
            self.cids.allocate()
        } else {
            // `admit` let INIT through, so any active transaction is this channel's.
            if let Some(Transaction::Processing { cid: owner, .. }) = self.active.take() {
                out.push(Event::Abort { cid: owner });
            }
            cid
        };
        let mut response = Vec::with_capacity(17);
        response.extend_from_slice(nonce);
        response.extend_from_slice(&channel.to_be_bytes());
        response.push(PROTOCOL_VERSION);
        response.extend_from_slice(&self.version.bytes());
        response.push(self.capabilities);
        out.push(Event::Send(packet::single(cid, cmd::INIT, &response)));
    }

    /// `CTAPHID_CANCEL` (CTAP 2.1 §11.2.9.1.5): only an outstanding CBOR request on
    /// the same channel is cancelled. Anything else, including a U2F MSG request
    /// (`reference/BEHAVIOR_CATALOG.md` FIDO: "CTAPHID_CANCEL during a U2F MSG is
    /// ignored"), is ignored. No response is ever sent.
    fn on_cancel(&self, cid: u32, out: &mut Vec<Event>) {
        if let Some(Transaction::Processing {
            cid: owner,
            cmd: cmd::CBOR,
        }) = self.active
            && owner == cid
        {
            out.push(Event::Cancel { cid });
        }
    }

    fn on_cont_packet(
        &mut self,
        now: Millis,
        cid: u32,
        seq: u8,
        data: &[u8],
        out: &mut Vec<Event>,
    ) {
        let Some(Transaction::Assembling(assembly)) = &mut self.active else {
            return;
        };
        if assembly.cid() != cid {
            return;
        }
        match assembly.push(now, seq, data) {
            Progress::More => {}
            Progress::OutOfSequence => {
                self.active = None;
                send_error(out, cid, err::INVALID_SEQ);
            }
            Progress::Complete => {
                if let Some(Transaction::Assembling(done)) = self.active.take() {
                    let (command, payload) = done.into_message();
                    self.execute(cid, command, payload, out);
                }
            }
        }
    }

    /// Carries out a complete, validated request message.
    fn execute(&mut self, cid: u32, command: u8, payload: Vec<u8>, out: &mut Vec<Event>) {
        match command {
            cmd::PING => out.extend(
                packet::fragment(cid, cmd::PING, &payload)
                    .into_iter()
                    .map(Event::Send),
            ),
            cmd::WINK => {
                out.push(Event::Wink);
                out.push(Event::Send(packet::single(cid, cmd::WINK, &[])));
            }
            // The stall of the module documentation: busy, never answered, no request
            // for the application.
            cmd::CBOR if payload.is_empty() => self.active = Some(Transaction::Stalled { cid }),
            _ => {
                self.active = Some(Transaction::Processing { cid, cmd: command });
                out.push(Event::Request {
                    cid,
                    cmd: command,
                    payload,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The smallest framer exchange: broadcast INIT, then the allocated channel.
    // Byte layout from CTAP 2.1 §11.2.9.1.3.
    #[test]
    fn init_reports_version_and_capabilities() {
        let mut hid = Ctaphid::new(Version::new(5, 7, 4), 0x05);
        let mut request = [0u8; REPORT_LEN];
        request[..7].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0x86, 0x00, 0x08]);
        request[7..15].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let events = hid.report(0, &request);
        let mut expected = [0u8; REPORT_LEN];
        expected[..7].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0x86, 0x00, 0x11]);
        expected[7..24].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 1, 2, 5, 7, 4, 0x05]);
        assert_eq!(events, vec![Event::Send(expected)]);
        assert!(hid.cids.is_allocated(1));
        assert_eq!(hid.next_deadline(), None);
    }
}
