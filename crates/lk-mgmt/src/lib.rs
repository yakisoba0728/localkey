//! Management application: device information (form factor, serial, firmware version,
//! supported/enabled capabilities per transport), configuration lock, auto-eject and
//! touch timeouts, and reboot/re-enumeration requests. Reachable over CCID, the OTP
//! HID interface and CTAPHID vendor commands.

#![forbid(unsafe_code)]
