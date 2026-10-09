//! CTAPHID framing (CTAP 2.1 §11.2): INIT/CONT packets, channel allocation,
//! busy/timeout/sequence errors, KEEPALIVE, CANCEL, WINK, PING, LOCK, and transaction
//! arbitration across channels. It reassembles messages for `lk-fido` and splits
//! responses back into 64-byte reports.

#![forbid(unsafe_code)]
