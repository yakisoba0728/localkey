//! CTAPHID wire constants (CTAP 2.1 §11.2.4, §11.2.9 and §11.2.10).

use lk_core::Millis;

/// Size of every HID input and output report on the FIDO interface (CTAP 2.1 §11.2.4,
/// the 64-byte reports declared by the measured HID report descriptor in
/// `reference/yubikey-5c-nano-5.7.4/usb-reference-observation.json`).
pub const REPORT_LEN: usize = 64;

/// Data bytes carried by an initialization packet: CID(4) CMD(1) BCNTH(1) BCNTL(1) DATA(57).
pub const INIT_DATA_LEN: usize = REPORT_LEN - 7;

/// Data bytes carried by a continuation packet: CID(4) SEQ(1) DATA(59).
pub const CONT_DATA_LEN: usize = REPORT_LEN - 5;

/// Highest continuation sequence number (CTAP 2.1 §11.2.4: SEQ is 0..=0x7F).
pub const MAX_SEQ: u8 = 0x7F;

/// Largest message one transaction can carry: one initialization packet and 128
/// continuation packets, `57 + 128 * 59 = 7609` bytes (CTAP 2.1 §11.2.4;
/// `reference/BEHAVIOR_CATALOG.md` FIDO "final legal sequence 127 completes a maximum
/// 7609-byte PING").
pub const MAX_PAYLOAD: usize = INIT_DATA_LEN + (MAX_SEQ as usize + 1) * CONT_DATA_LEN;

/// The broadcast channel, used only to allocate a channel with `CTAPHID_INIT`
/// (CTAP 2.1 §11.2.4). Channel 0 is reserved and never valid.
pub const BROADCAST_CID: u32 = 0xFFFF_FFFF;

/// CTAPHID protocol version reported by `CTAPHID_INIT` (CTAP 2.1 §11.2.9.1.3).
pub const PROTOCOL_VERSION: u8 = 2;

/// How long an incomplete message may wait for its next packet before the device
/// abandons it with `ERR_MSG_TIMEOUT` (CTAP 2.1 §11.2.5.2).
///
/// Model policy: the specification names no value and the behaviour catalog records
/// none, so the engine uses 3000 ms, restarted by every accepted packet of the message.
pub const TRANSACTION_TIMEOUT_MS: Millis = 3000;

/// Longest channel lock `CTAPHID_LOCK` accepts, in seconds (CTAP 2.1 §11.2.9.2.2).
pub const MAX_LOCK_SECONDS: u8 = 10;

/// Command codes without the initialization-packet bit 7 (CTAP 2.1 §11.2.9).
pub mod cmd {
    /// `CTAPHID_PING`: echo the payload (§11.2.9.1.4).
    pub const PING: u8 = 0x01;
    /// `CTAPHID_MSG`: a U2F raw message (§11.2.9.1.1).
    pub const MSG: u8 = 0x03;
    /// `CTAPHID_LOCK`: reserve the device for one channel (§11.2.9.2.2).
    pub const LOCK: u8 = 0x04;
    /// `CTAPHID_INIT`: allocate or resynchronise a channel (§11.2.9.1.3).
    pub const INIT: u8 = 0x06;
    /// `CTAPHID_WINK`: show the user which device this is (§11.2.9.2.1).
    pub const WINK: u8 = 0x08;
    /// `CTAPHID_CBOR`: a CTAP2 request (§11.2.9.1.2).
    pub const CBOR: u8 = 0x10;
    /// `CTAPHID_CANCEL`: cancel the outstanding CBOR request (§11.2.9.1.5).
    pub const CANCEL: u8 = 0x11;
    /// `CTAPHID_KEEPALIVE`: device-to-host processing status (§11.2.9.1.7).
    pub const KEEPALIVE: u8 = 0x3B;
    /// `CTAPHID_ERROR`: device-to-host error report (§11.2.9.1.6).
    pub const ERROR: u8 = 0x3F;
    /// First vendor-specific command (§11.2.9.3).
    pub const VENDOR_FIRST: u8 = 0x40;
    /// Last vendor-specific command (§11.2.9.3).
    pub const VENDOR_LAST: u8 = 0x7F;
}

/// `CTAPHID_ERROR` codes (CTAP 2.1 §11.2.9.1.6).
pub mod err {
    /// The command is not supported.
    pub const INVALID_CMD: u8 = 0x01;
    /// A parameter in the request is invalid.
    pub const INVALID_PAR: u8 = 0x02;
    /// The request length (BCNT) is invalid.
    pub const INVALID_LEN: u8 = 0x03;
    /// A continuation packet arrived out of sequence.
    pub const INVALID_SEQ: u8 = 0x04;
    /// The message was not completed in time.
    pub const MSG_TIMEOUT: u8 = 0x05;
    /// The device is busy with a transaction on another channel.
    pub const CHANNEL_BUSY: u8 = 0x06;
    /// Another channel holds the channel lock.
    pub const LOCK_REQUIRED: u8 = 0x0A;
    /// The channel is reserved, unknown or not usable for this command.
    pub const INVALID_CHANNEL: u8 = 0x0B;
    /// Any other error.
    pub const OTHER: u8 = 0x7F;
}

/// `CTAPHID_KEEPALIVE` status bytes (CTAP 2.1 §11.2.9.1.7).
pub mod keepalive {
    /// The authenticator is still processing the request.
    pub const PROCESSING: u8 = 1;
    /// The authenticator waits for user presence.
    pub const UPNEEDED: u8 = 2;
}

/// Capability flags reported by `CTAPHID_INIT` (CTAP 2.1 §11.2.9.1.3).
pub mod capability {
    /// The device implements `CTAPHID_WINK`.
    pub const WINK: u8 = 0x01;
    /// The device implements `CTAPHID_CBOR`.
    pub const CBOR: u8 = 0x04;
    /// The device does **not** implement `CTAPHID_MSG`.
    pub const NMSG: u8 = 0x08;
}
