//! What the framer asks the device to do.

use crate::protocol::REPORT_LEN;

/// One output of [`crate::Ctaphid`], in the order the device must act on them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Send this 64-byte input report to the host.
    Send([u8; REPORT_LEN]),
    /// A complete `CTAPHID_CBOR` (`0x10`), `CTAPHID_MSG` (`0x03`) or vendor
    /// (`0x40..=0x7F`) request for the application layer. `cmd` has bit 7 cleared.
    /// The device answers it with [`crate::Ctaphid::respond`]; until then the framer
    /// answers every other channel, and PING/WINK on this one, with `ERR_CHANNEL_BUSY`.
    Request { cid: u32, cmd: u8, payload: Vec<u8> },
    /// The host sent `CTAPHID_CANCEL` for the outstanding CBOR request on `cid`
    /// (CTAP 2.1 §11.2.9.1.5). The request stays outstanding; the application should
    /// answer it with `CTAP2_ERR_KEEPALIVE_CANCEL` through `respond`.
    Cancel { cid: u32 },
    /// The outstanding request on `cid` was discarded by `CTAPHID_INIT`
    /// resynchronisation (CTAP 2.1 §11.2.5.3). The device must drop the pending
    /// operation at once. A late `respond` for it sends nothing only as long as no new
    /// request has started on the same channel: `respond` names a channel, not a
    /// request, so once the host has sent a new request on `cid` the framer would frame
    /// a stale answer as the answer to that new request.
    Abort { cid: u32 },
    /// Run the WINK indication (CTAP 2.1 §11.2.9.2.1).
    Wink,
}
