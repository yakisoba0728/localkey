//! OTP application: two configurable slots (Yubico OTP, OATH-HOTP, static password,
//! HMAC-SHA1 challenge-response), access codes, swap/delete/update, the 8-byte HID
//! feature-report protocol with frame CRC, and keyboard output. The same slot logic is
//! reachable through the CCID OTP AID.

#![forbid(unsafe_code)]
