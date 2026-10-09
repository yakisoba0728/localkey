//! APDU chaining across bulk messages at extended APDU level (USB CCID Rev 1.1
//! §6.1.4 `wLevelParameter`, §6.2.1 `bChainParameter`).
//!
//! A command APDU longer than one message arrives in `0001`, `0003`…, `0002` parts;
//! a response APDU longer than one message leaves in `01`, `03`…, `02` parts, each
//! requested by the host with an empty `0010` XfrBlock.

use crate::message::chain;

/// The largest command APDU the slot assembles: an extended case 4 APDU
/// (ISO/IEC 7816-4 §5.1: 4 header bytes, 3-byte Lc, 65 535 data bytes, 2-byte Le).
pub(crate) const MAX_COMMAND_APDU: usize = 4 + 3 + 65_535 + 2;

/// The assembled command would exceed [`MAX_COMMAND_APDU`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TooLong;

/// A command APDU being received in parts.
#[derive(Debug, Default)]
pub(crate) struct CommandChain {
    parts: Option<Vec<u8>>,
}

impl CommandChain {
    /// Whether a `0001` part was received and the `0002` part is still awaited.
    pub fn is_open(&self) -> bool {
        self.parts.is_some()
    }

    /// Start a new command with its first part.
    pub fn begin(&mut self, data: &[u8]) {
        self.parts = Some(data.to_vec());
    }

    /// Append a middle part. The chain must be open; on overflow it is dropped.
    pub fn append(&mut self, data: &[u8]) -> Result<(), TooLong> {
        let Some(parts) = self.parts.as_mut() else {
            return Ok(());
        };
        if parts.len().saturating_add(data.len()) > MAX_COMMAND_APDU {
            self.parts = None;
            return Err(TooLong);
        }
        parts.extend_from_slice(data);
        Ok(())
    }

    /// Append the last part and return the whole command APDU.
    pub fn finish(&mut self, data: &[u8]) -> Result<Vec<u8>, TooLong> {
        self.append(data)?;
        Ok(self.parts.take().unwrap_or_default())
    }

    /// Drop a partial command.
    pub fn clear(&mut self) {
        self.parts = None;
    }
}

/// The unsent tail of a response APDU.
#[derive(Debug, Default)]
pub(crate) struct ResponseChain {
    data: Vec<u8>,
    sent: usize,
}

impl ResponseChain {
    /// Whether the host still has parts to fetch with `0010`.
    pub fn is_pending(&self) -> bool {
        self.sent < self.data.len()
    }

    /// Split `response` into messages of at most `max` bytes. Returns the
    /// `bChainParameter` and data of the first one and keeps the rest.
    pub fn start(&mut self, response: &[u8], max: usize) -> (u8, Vec<u8>) {
        if response.len() <= max {
            self.clear();
            return (chain::BEGIN_AND_END, response.to_vec());
        }
        self.data = response.to_vec();
        self.sent = max;
        (chain::BEGIN, response[..max].to_vec())
    }

    /// The next part, or `None` if nothing is pending.
    pub fn next(&mut self, max: usize) -> Option<(u8, Vec<u8>)> {
        if !self.is_pending() {
            return None;
        }
        let end = self.sent.saturating_add(max).min(self.data.len());
        let part = self.data[self.sent..end].to_vec();
        self.sent = end;
        if self.is_pending() {
            Some((chain::CONTINUE, part))
        } else {
            self.clear();
            Some((chain::END, part))
        }
    }

    /// Drop the unsent tail.
    pub fn clear(&mut self) {
        self.data = Vec::new();
        self.sent = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_parts_concatenate() {
        let mut c = CommandChain::default();
        assert!(!c.is_open());
        c.begin(&[1, 2]);
        assert!(c.is_open());
        assert_eq!(c.append(&[3]), Ok(()));
        assert_eq!(c.finish(&[4, 5]), Ok(vec![1, 2, 3, 4, 5]));
        assert!(!c.is_open());
    }

    #[test]
    fn command_overflow_drops_the_chain() {
        let mut c = CommandChain::default();
        c.begin(&vec![0; MAX_COMMAND_APDU - 1]);
        assert_eq!(c.append(&[0]), Ok(()));
        assert_eq!(c.append(&[0]), Err(TooLong));
        assert!(!c.is_open());
    }

    #[test]
    fn response_parts_use_chain_parameters_01_03_02() {
        // CCID Rev 1.1 §6.2.1 bChainParameter: 01 begins, 03 continues, 02 ends.
        let mut r = ResponseChain::default();
        let response: Vec<u8> = (0..10).collect();
        assert_eq!(r.start(&response, 4), (chain::BEGIN, vec![0, 1, 2, 3]));
        assert!(r.is_pending());
        assert_eq!(r.next(4), Some((chain::CONTINUE, vec![4, 5, 6, 7])));
        assert_eq!(r.next(4), Some((chain::END, vec![8, 9])));
        assert!(!r.is_pending());
        assert_eq!(r.next(4), None);
    }

    #[test]
    fn response_that_fits_is_not_chained() {
        let mut r = ResponseChain::default();
        assert_eq!(
            r.start(&[1, 2, 3, 4], 4),
            (chain::BEGIN_AND_END, vec![1, 2, 3, 4])
        );
        assert!(!r.is_pending());
        // Exactly two parts: 01 then 02.
        assert_eq!(r.start(&[1, 2, 3, 4, 5], 4).0, chain::BEGIN);
        assert_eq!(r.next(4), Some((chain::END, vec![5])));
    }
}
