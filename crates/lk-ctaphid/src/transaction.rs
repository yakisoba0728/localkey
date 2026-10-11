//! The device's single active transaction (CTAP 2.1 §11.2.5.1) and message
//! reassembly with sequence checking (§11.2.5.4).

use lk_core::Millis;

use crate::protocol::{CONT_DATA_LEN, TRANSACTION_TIMEOUT_MS};

/// What the device is busy with. The device serves one transaction at a time; every
/// other channel is answered `ERR_CHANNEL_BUSY` until it ends (CTAP 2.1 §11.2.5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Transaction {
    /// A request message is still arriving.
    Assembling(Assembly),
    /// A complete request was handed to the application, which has not answered yet.
    Processing { cid: u32, cmd: u8 },
    /// A `CTAPHID_CBOR` request with BCNT 0 holds the device without ever being answered
    /// or handed to the application; only `CTAPHID_INIT` on `cid` or a USB reset ends it
    /// (measured on a YubiKey 5C Nano 5.7.4: `docs/MEASUREMENT.md`, probe `empty-cbor`).
    Stalled { cid: u32 },
}

impl Transaction {
    pub(crate) fn cid(&self) -> u32 {
        match self {
            Self::Assembling(assembly) => assembly.cid,
            Self::Processing { cid, .. } | Self::Stalled { cid } => *cid,
        }
    }
}

/// A partially received request message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Assembly {
    cid: u32,
    cmd: u8,
    total: usize,
    buf: Vec<u8>,
    next_seq: u8,
    deadline: Millis,
}

/// The effect of one continuation packet on an [`Assembly`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Progress {
    /// More continuation packets are needed.
    More,
    /// The message is complete.
    Complete,
    /// The packet's SEQ is not the expected one (CTAP 2.1 §11.2.5.4).
    OutOfSequence,
}

/// The deadline for the next packet of a message whose latest packet arrived at `now`.
fn deadline_after(now: Millis) -> Millis {
    now.saturating_add(TRANSACTION_TIMEOUT_MS)
}

impl Assembly {
    /// Starts reassembling a `total`-byte message from its initialization packet data.
    /// The caller has checked `total` against `MAX_MESSAGE_LEN` (at most `MAX_PAYLOAD`)
    /// and that it exceeds one initialization packet.
    pub(crate) fn start(now: Millis, cid: u32, cmd: u8, total: usize, first: &[u8]) -> Self {
        let mut buf = Vec::with_capacity(total);
        buf.extend_from_slice(first.get(..total).unwrap_or(first));
        Self {
            cid,
            cmd,
            total,
            buf,
            next_seq: 0,
            deadline: deadline_after(now),
        }
    }

    pub(crate) fn cid(&self) -> u32 {
        self.cid
    }

    /// When the message is abandoned unless another packet arrives.
    pub(crate) fn deadline(&self) -> Millis {
        self.deadline
    }

    /// Appends one continuation packet's data; bytes past the message end are padding.
    pub(crate) fn push(&mut self, now: Millis, seq: u8, data: &[u8]) -> Progress {
        if seq != self.next_seq {
            return Progress::OutOfSequence;
        }
        let wanted = (self.total - self.buf.len()).min(CONT_DATA_LEN);
        self.buf
            .extend_from_slice(data.get(..wanted).unwrap_or(data));
        // A message of at most `MAX_PAYLOAD` bytes completes by SEQ 0x7F, so saturation
        // only matters for an impossible 129th packet, which then never matches.
        self.next_seq = self.next_seq.saturating_add(1);
        self.deadline = deadline_after(now);
        if self.buf.len() >= self.total {
            Progress::Complete
        } else {
            Progress::More
        }
    }

    /// The command and payload of a complete message.
    pub(crate) fn into_message(self) -> (u8, Vec<u8>) {
        (self.cmd, self.buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{INIT_DATA_LEN, MAX_PAYLOAD};

    #[test]
    fn reassembles_in_order_and_strips_padding() {
        // 58 bytes: 57 in the initialization packet, 1 in continuation SEQ 0
        // (CTAP 2.1 §11.2.4).
        let first = [0x11u8; INIT_DATA_LEN];
        let mut assembly = Assembly::start(100, 5, 0x10, 58, &first);
        let mut cont = [0xEEu8; CONT_DATA_LEN];
        cont[0] = 0x22;
        assert_eq!(assembly.push(200, 0, &cont), Progress::Complete);
        let (cmd, payload) = assembly.into_message();
        assert_eq!(cmd, 0x10);
        assert_eq!(payload.len(), 58);
        assert_eq!(payload[57], 0x22);
    }

    #[test]
    fn rejects_out_of_sequence_packets() {
        let mut assembly = Assembly::start(0, 5, 0x01, 200, &[0u8; INIT_DATA_LEN]);
        assert_eq!(
            assembly.push(1, 1, &[0u8; CONT_DATA_LEN]),
            Progress::OutOfSequence
        );
        assert_eq!(assembly.push(1, 0, &[0u8; CONT_DATA_LEN]), Progress::More);
        assert_eq!(
            assembly.push(1, 0, &[0u8; CONT_DATA_LEN]),
            Progress::OutOfSequence
        );
    }

    #[test]
    fn every_packet_restarts_the_timeout() {
        let mut assembly = Assembly::start(1000, 5, 0x01, 200, &[0u8; INIT_DATA_LEN]);
        assert_eq!(assembly.deadline(), 1000 + TRANSACTION_TIMEOUT_MS);
        assembly.push(2500, 0, &[0u8; CONT_DATA_LEN]);
        assert_eq!(assembly.deadline(), 2500 + TRANSACTION_TIMEOUT_MS);
    }

    #[test]
    fn maximum_message_completes_on_seq_127() {
        // 7609 = 57 + 128 * 59 (CTAP 2.1 §11.2.4). The framer never starts an assembly
        // this long (requests stop at `MAX_MESSAGE_LEN`, 1536, measured: docs/MEASUREMENT.md
        // probe ping-max); the reassembler itself still handles the full SEQ range.
        let mut assembly = Assembly::start(0, 5, 0x01, MAX_PAYLOAD, &[0u8; INIT_DATA_LEN]);
        for seq in 0..0x7F {
            assert_eq!(assembly.push(0, seq, &[0u8; CONT_DATA_LEN]), Progress::More);
        }
        assert_eq!(
            assembly.push(0, 0x7F, &[0u8; CONT_DATA_LEN]),
            Progress::Complete
        );
    }
}
