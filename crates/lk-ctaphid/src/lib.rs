//! CTAPHID framing (CTAP 2.1 §11.2, USB HID transport): INIT/CONT packets, channel
//! allocation, busy/timeout/sequence errors, KEEPALIVE, CANCEL, WINK, PING, and
//! transaction arbitration across channels. It reassembles messages for `lk-fido` and
//! splits responses back into 64-byte reports. `CTAPHID_LOCK` is not implemented
//! (`ERR_INVALID_CMD`, as on the measured device: `docs/MEASUREMENT.md`, probe `lock`).
//!
//! The framer is a pure state machine. The device feeds it each output report with
//! [`Ctaphid::report`] and the passage of time with [`Ctaphid::tick`], and acts on the
//! returned [`Event`]s in order. Complete CBOR, MSG and vendor requests go to the
//! application layer as [`Event::Request`]. Their answers come back through
//! [`Ctaphid::respond`]. INIT, PING, WINK, CANCEL and every transport error are
//! handled here. The order of error checks and the other choices the specification
//! leaves open are documented on the state machine (`framer.rs`) and on
//! [`TRANSACTION_TIMEOUT_MS`].
//!
//! Behaviour follows CTAP 2.1 §11.2 and the CTAPHID bullets of
//! `reference/BEHAVIOR_CATALOG.md` (FIDO section and appendix A).

#![forbid(unsafe_code)]

mod channel;
mod event;
mod framer;
mod packet;
mod protocol;
mod transaction;

pub use event::Event;
pub use framer::Ctaphid;
pub use protocol::{
    BROADCAST_CID, CONT_DATA_LEN, INIT_DATA_LEN, MAX_LOCK_SECONDS, MAX_MESSAGE_LEN, MAX_PAYLOAD,
    MAX_SEQ, PROTOCOL_VERSION, REPORT_LEN, TRANSACTION_TIMEOUT_MS, capability, cmd, err, keepalive,
};
