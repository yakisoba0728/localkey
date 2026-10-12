//! CCID bulk-out message reassembly (`docs/PROGRAM.md` "lk-gadget", Endpoints). Pure: the
//! reader thread reads the bulk-out endpoint one packet at a time and pushes each read
//! here.
//!
//! A `PC_to_RDR_*` message is a 10-byte header (`bMessageType`, `dwLength` little
//! endian, `bSlot`, `bSeq`, three message-specific bytes) and `dwLength` bytes of
//! `abData` (USB CCID Rev 1.1 §6.1). The host sends one message per bulk transfer; a
//! transfer ends with a short packet, or with a full packet when the message fills whole
//! packets (a host sends no zero-length packet after it; USB 2.0 §5.8.3 lets a transfer
//! end when the expected amount has been sent).
//!
//! Every read asks for one packet (`wMaxPacketSize`, 64), never more: a FunctionFS read
//! completes when its buffer is full or a short packet arrives, so a larger read of a
//! message that fills whole packets would wait for the next message. One read therefore
//! returns one packet, and a read shorter than a packet ends the host's transfer.
//!
//! Resynchronisation policy (malformed input is dropped, never passed on partially):
//!
//! - a zero-length packet between messages is ignored;
//! - a first packet shorter than the 10-byte header is dropped (a runt);
//! - a message longer than the cap is dropped unanswered, and the rest of its transfer
//!   is discarded: until the announced length has gone by or a short packet ends the
//!   transfer, whichever comes first. The cap is the CCID class descriptor's
//!   `dwMaxCCIDMessageLength` (3072 in the reference descriptor), which is the whole
//!   message, header included (USB CCID Rev 1.1 §5.1: for extended APDU level "between
//!   261 + 10 (header) and 65544 + 10"); so the largest `abData` accepted is the cap
//!   minus 10. `lk_ccid` reads the field the same way (`ClassDescriptor::max_data_len`)
//!   and answers a longer message with an error, but a host that honours the descriptor
//!   never sends one, and the gadget does not gather more than it advertised;
//! - a short (or zero-length) packet before the announced length is complete truncates
//!   the message: what was gathered is dropped and the next packet starts a new message;
//! - bytes after the announced length in the message's last packet are dropped (they
//!   belong to the same transfer, so the next packet still starts a new message);
//! - a read error drops the partial message ([`Reassembler::reset`]): the endpoint was
//!   disabled, so the host's transfer is gone.

use std::fmt;

/// The CCID message header (USB CCID Rev 1.1 §6.1).
pub const HEADER_LEN: usize = 10;

/// The result of pushing one packet.
///
/// `Debug` shows sizes, never message bytes (a message can carry a PIN).
#[derive(Clone, PartialEq, Eq)]
pub enum Assembled {
    /// More packets are needed (or a zero-length packet was ignored).
    Pending,
    /// A whole message, header included.
    Message(Vec<u8>),
    /// Input was dropped.
    Dropped(DropReason),
}

impl fmt::Debug for Assembled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Assembled::Pending => f.write_str("Pending"),
            Assembled::Message(m) => f.debug_tuple("Message").field(&format_args!("{} bytes", m.len())).finish(),
            Assembled::Dropped(reason) => f.debug_tuple("Dropped").field(reason).finish(),
        }
    }
}

/// Why input was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// A first packet shorter than the header.
    Runt { length: usize },
    /// `dwLength` above the cap; the rest of the transfer is discarded.
    Oversize { announced: u64 },
    /// The transfer ended before the announced length.
    Truncated { expected: usize, received: usize },
    /// A read error interrupted a message.
    Interrupted { received: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum State {
    Idle,
    Message { buffer: Vec<u8>, total: usize },
    Discard { remaining: u64 },
}

/// Reassembles bulk-out packets into CCID messages.
///
/// `Debug` shows the state and sizes only.
#[derive(Clone, PartialEq, Eq)]
pub struct Reassembler {
    packet_size: usize,
    max_message_length: usize,
    state: State,
}

impl Drop for Reassembler {
    fn drop(&mut self) {
        self.reset();
    }
}

impl fmt::Debug for Reassembler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = match &self.state {
            State::Idle => "idle".to_owned(),
            State::Message { buffer, total } => format!("{} of {total} bytes", buffer.len()),
            State::Discard { remaining } => format!("discarding {remaining} bytes"),
        };
        f.debug_struct("Reassembler")
            .field("packet_size", &self.packet_size)
            .field("max_message_length", &self.max_message_length)
            .field("state", &state)
            .finish()
    }
}

impl Reassembler {
    /// A reassembler for packets of `packet_size` bytes (the bulk-out `wMaxPacketSize`)
    /// that accepts messages of up to `max_message_length` bytes, the 10-byte header
    /// included (`dwMaxCCIDMessageLength`).
    pub fn new(packet_size: usize, max_message_length: usize) -> Reassembler {
        Reassembler { packet_size: packet_size.max(1), max_message_length, state: State::Idle }
    }

    /// How many bytes the next read asks for: always one packet.
    pub fn read_len(&self) -> usize {
        self.packet_size
    }

    /// Whether no message is in progress.
    pub fn is_idle(&self) -> bool {
        self.state == State::Idle
    }

    /// Push the bytes of one read (one packet).
    pub fn push(&mut self, packet: &[u8]) -> Assembled {
        let short = packet.len() < self.packet_size;
        match std::mem::replace(&mut self.state, State::Idle) {
            State::Idle => self.start(packet, short),
            State::Message { mut buffer, total } => {
                let take = packet.len().min(total - buffer.len());
                lk_crypto::extend_secret(&mut buffer, &packet[..take]);
                if buffer.len() == total {
                    Assembled::Message(buffer)
                } else if short {
                    let received = buffer.len();
                    lk_crypto::wipe_vec(&mut buffer);
                    Assembled::Dropped(DropReason::Truncated { expected: total, received })
                } else {
                    self.state = State::Message { buffer, total };
                    Assembled::Pending
                }
            }
            State::Discard { remaining } => {
                let left = remaining.saturating_sub(packet.len() as u64);
                if left > 0 && !short {
                    self.state = State::Discard { remaining: left };
                }
                Assembled::Pending
            }
        }
    }

    /// The first packet of a message.
    fn start(&mut self, packet: &[u8], short: bool) -> Assembled {
        if packet.is_empty() {
            return Assembled::Pending;
        }
        let Some(header) = packet.get(..HEADER_LEN) else {
            return Assembled::Dropped(DropReason::Runt { length: packet.len() });
        };
        let data_length = u32::from_le_bytes([header[1], header[2], header[3], header[4]]);
        let announced = HEADER_LEN as u64 + u64::from(data_length);
        let fits = u64::try_from(self.max_message_length).is_ok_and(|max| announced <= max);
        if !fits {
            let left = announced.saturating_sub(packet.len() as u64);
            if left > 0 && !short {
                self.state = State::Discard { remaining: left };
            }
            return Assembled::Dropped(DropReason::Oversize { announced });
        }
        // `fits` bounds the total by `max_message_length`, a `usize`.
        let total = usize::try_from(announced).unwrap_or(self.max_message_length);
        if packet.len() >= total {
            Assembled::Message(packet[..total].to_vec())
        } else if short {
            Assembled::Dropped(DropReason::Truncated { expected: total, received: packet.len() })
        } else {
            self.state = State::Message { buffer: packet.to_vec(), total };
            Assembled::Pending
        }
    }

    /// Drop a message in progress (after a read error); the next packet starts a new
    /// message. Returns what was dropped, if anything was gathered.
    pub fn reset(&mut self) -> Option<DropReason> {
        match std::mem::replace(&mut self.state, State::Idle) {
            State::Message { mut buffer, .. } => {
                let received = buffer.len();
                lk_crypto::wipe_vec(&mut buffer);
                Some(DropReason::Interrupted { received })
            },
            State::Idle | State::Discard { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests;
