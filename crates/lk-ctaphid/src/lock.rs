//! Channel lock state (CTAP 2.1 §11.2.9.2.2 `CTAPHID_LOCK`).

use lk_core::Millis;

/// A channel's exclusive claim on the device until `until`.
///
/// While it holds, every other channel (the broadcast channel included) is answered
/// `ERR_CHANNEL_BUSY` (the reasons are on the check in `framer.rs`). `CTAPHID_CANCEL`
/// is never answered, so it is unaffected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChannelLock {
    cid: u32,
    until: Millis,
}

impl ChannelLock {
    /// A lock for `seconds` seconds starting at `now`.
    pub(crate) fn new(cid: u32, now: Millis, seconds: u8) -> Self {
        Self {
            cid,
            until: now.saturating_add(Millis::from(seconds) * 1000),
        }
    }

    /// Whether the lock keeps `cid` out.
    pub(crate) fn excludes(&self, cid: u32) -> bool {
        self.cid != cid
    }

    /// When the lock lapses.
    pub(crate) fn until(&self) -> Millis {
        self.until
    }

    /// Whether the lock has lapsed at `now`.
    pub(crate) fn expired(&self, now: Millis) -> bool {
        now >= self.until
    }
}
