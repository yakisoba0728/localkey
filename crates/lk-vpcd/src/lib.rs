//! PC/SC transport through the vsmartcard `vpcd` reader driver (`docs/PROGRAM.md`
//! "lk-vpcd"): the engine's CCID interface as a virtual card that pcscd shows in vpcd's
//! "Virtual PCD" reader. No USB device controller is needed, and the crate is std only.
//!
//! - [`protocol`]: vpcd's framing and control commands. Pure.
//! - [`ccid`]: the host side of USB CCID (IccPowerOn, IccPowerOff, XfrBlock with extended
//!   APDU chaining; DataBlock and SlotStatus replies, time extensions, `bSeq`). Pure.
//! - [`Connector`], [`TcpConnector`]: connecting to vpcd, the I/O seam.
//! - [`VpcdTransport`]: the [`lk_run::Transport`], with one connection thread.
//! - The check against the real vpcd and pcscd is `tools/linux-guest/tests/vpcd.sh`, which
//!   runs `localkeyd --transport vpcd` and `uhid,vpcd` in the disposable guest (see
//!   "Checked against the real vpcd" below).
//!
//! No vsmartcard code is used. The protocol facts below come from the project's
//! documentation, and its source was read for interface behaviour only.
//!
//! # The vpcd protocol
//!
//! Sources: the vsmartcard documentation, "Virtual Smart Card Architecture"
//! (`frankmorgner.github.io/vsmartcard/virtualsmartcard/api.html`) and the virtualsmartcard
//! README (`.../virtualsmartcard/README.html`); for interface behaviour, the sources
//! `virtualsmartcard/src/vpcd/vpcd.h`, `vpcd.c`, `src/ifd-vpcd/ifd-vpcd.c` and the
//! reference card `src/vpicc/virtualsmartcard/VirtualSmartcard.py` (master, read
//! 2026-10-11).
//!
//! - **Transport and direction.** TCP. By default vpcd "opens a socket for vpicc and waits
//!   for incoming connections" (README); the card connects. vpcd's server socket is an
//!   `AF_INET` socket bound to `INADDR_ANY` with backlog 0 (`opensock`, `vpcd.c`; the
//!   README says "on localhost", the code binds every IPv4 interface). vpcd accepts a
//!   waiting connection whenever pcscd asks whether a card is present (`vicc_present` →
//!   `vicc_connect` with a zero timeout) and keeps one connection per slot until a send or
//!   receive on it fails (`vicc_eject`). With `DEVICENAME host:port` vpcd connects to a
//!   listening card instead (vicc `--reversed`); that mode is not supported here.
//! - **Port.** `VPCDPORT 35963` (`vpcd.h`), `0x8C7B` in the `reader.conf` example
//!   (`DEVICENAME /dev/null:0x8C7B`); slot *n* listens on `35963 + n` (`Channel + slot`,
//!   `ifd-vpcd.c`; the README: "port 35963 and port 35964"). [`protocol::DEFAULT_ADDR`] is
//!   `127.0.0.1:35963`.
//! - **Framing.** "First the length of the data (in network byte order, i.e. big endian)
//!   is sent followed by the data itself" (api.html): a 2-byte length (`htons`/`ntohs`,
//!   `vpcd.c`), at most `0xFFFF` (`sendToVICC` refuses more). Both directions.
//! - **Control commands.** A payload of `VPCD_CTRL_LEN` (1) byte is a control command:
//!   `VPCD_CTRL_OFF` 0, `VPCD_CTRL_ON` 1, `VPCD_CTRL_RESET` 2, `VPCD_CTRL_ATR` 4
//!   (`vpcd.h`, api.html). Power off, power on and reset get no answer (`vicc_poweroff`,
//!   `vicc_poweron`, `vicc_reset` send and return); `GET ATR` is answered with the ATR,
//!   framed the same way (`vicc_getatr`). Any other payload length is a command APDU,
//!   answered with the response APDU (api.html; `VirtualSmartcard.py` treats every size
//!   other than 1 as an APDU). The reference card logs an unknown control byte or an
//!   empty payload and answers nothing.
//! - **ATR requests are frequent.** vpcd's presence check is a `GET ATR`
//!   (`IFDHICCPresence` → `vicc_present` → `vicc_getatr`, `ifd-vpcd.c`, `vpcd.c`), and
//!   pcscd polls a driver without its own polling thread every
//!   `PCSCLITE_STATUS_POLL_RATE` (400 ms, pcsc-lite `pcscd.h.in`); vpcd answers
//!   `TAG_IFD_POLLING_THREAD_*` with `IFD_ERROR_TAG`. pcscd powers an unused card down
//!   (`PCSCLITE_POWER_OFF_GRACE_PERIOD` is 5 s, but pcscd 2.4.1 did it within a second,
//!   see below) and powers it up on demand. `IFDHPowerICC` sends power on (or reset) and
//!   then `GET ATR` for the ATR it returns.
//! - **Errors.** vpcd has no error message. A receive that returns nothing (an empty
//!   answer, or a closed connection) or fails makes `vicc_transmit` eject the card: vpcd
//!   closes the connection, pcscd sees the card removed, and the next presence check
//!   accepts a new connection. So every APDU must get a non-empty answer: on an error
//!   this transport answers `6F00` ([`ERROR_RESPONSE`]). Reads in vpcd have no timeout
//!   (no `SO_RCVTIMEO`), so a card that never answers blocks the reader.
//! - **Extended APDUs.** vpcd's current sources announce `dwMaxAPDUDataSize` 65 536
//!   through `IOCTL_FEATURE_GET_TLV_PROPERTIES` (`ifd-vpcd.c`); the packaged 3.3 answers
//!   no control request, yet pcscd passes extended APDUs to it (see below). The frame
//!   bounds an APDU to 65 535 bytes.
//!
//! # As built
//!
//! Choices where `docs/PROGRAM.md` leaves room, and refinements:
//!
//! - **ATR.** `GET ATR` is answered with the ATR of the last power-on on the current
//!   connection, powering the card on only when there is none yet (the first `GET ATR` of
//!   a connection, which is the first presence check after vpcd accepted it). vpcd sends a
//!   `GET ATR` every 400 ms, so powering on whenever the slot is off would undo pcscd's
//!   power-down of an idle card every 400 ms and reset the card session behind its back.
//!   Each connection starts with no ATR and an unpowered slot, so a (re)insertion powers
//!   the card on afresh (a warm IccPowerOn if the slot was still active resets the card
//!   session).
//! - **Power before an APDU.** The slot is powered on before an APDU whenever it is not
//!   known to be powered: after an error reply (as the contract asks), and also after
//!   vpcd's power off and at the start of a connection. pcscd powers a card up before it
//!   sends APDUs, so this only matters for an APDU after a lost power state.
//! - **Every enumeration is a re-plug.** With CCID, the current connection is closed and a
//!   new one made after [`REPLUG_PAUSE`] (1.5 s): the device rebooted (its card session is
//!   gone), and pcscd should see the card removed and inserted, as with a real key that
//!   re-enumerates. Without the pause pcscd can miss the removal and then show no card at
//!   all (found against the real vpcd; see [`REPLUG_PAUSE`]).
//!   The answer to the command that caused the reboot is written first (see
//!   [`VpcdTransport`]'s module docs).
//! - **Dropped commands.** A command the device drops without a reply (a power cycle from
//!   the control socket ends a card command silently) is detected with a `Command::Status`
//!   marker sent behind each message plus [`REPLY_SILENCE`] (5 s) without a time
//!   extension; the APDU is answered with `6F00`. Without this vpcd and pcscd would block
//!   forever.
//! - **A connection lost while a command waits** (a touch wait, a long computation) is
//!   noticed within [`PEER_CHECK`] (200 ms) by a non-blocking `peek` on the socket, which
//!   vpcd leaves silent while it waits for an answer; the command is then aborted in the
//!   device (`ABORT` control request and `PC_to_RDR_Abort`, USB CCID Rev 1.1 §5.3.1,
//!   §6.1.13), so the slot is free for the next connection and a later tap completes
//!   nothing, and the connection is retried like any lost one. The `bSeq` counter runs on
//!   across connections, so a late reply from an earlier connection never matches a new
//!   message (see [`VpcdTransport`]'s module docs).
//! - **Chaining.** Command APDUs longer than one CCID message (`dwMaxCCIDMessageLength` of
//!   the identity's class descriptor minus the header: 3062 bytes for the engine) are sent
//!   in `wLevelParameter` parts, and chained responses fetched with empty `0010`
//!   XfrBlocks (USB CCID Rev 1.1 §6.1.4, §6.2.1). A response longer than a vpcd message
//!   is answered with `6F00`.
//! - **Retries.** Attempts are at least [`RETRY_INTERVAL`] (1 s) apart, counted from the
//!   start of the previous attempt, so a connection lost after more than a second is
//!   retried at once; one attempt waits at most [`CONNECT_TIMEOUT`] (2 s). Only the first
//!   failure of a series is reported.
//! - **Addresses.** [`resolve`] turns `HOST:PORT` into one address, preferring IPv4
//!   (vpcd listens on IPv4 only). A non-loopback address (IPv4-mapped loopback counts as
//!   loopback) is reported once with [`VpcdNotice::NotLoopback`] when the transport is
//!   made.
//! - **Blocking reads.** The connection thread blocks in `read()`; `enumerate` wakes it by
//!   shutting down the read half (so a queued answer can still be written), drop by
//!   shutting down both. Writes time out after [`WRITE_TIMEOUT`].
//! - **Counters and notices.** [`VpcdStats`] counts connections, ignored outputs, stale
//!   bulk-in messages (the device's answers to an abort among them), skipped time
//!   extensions and `6F00` answers. [`VpcdNotice`]s carry
//!   message kinds and sizes, never APDU or ATR bytes; `Debug` of every type shows sizes
//!   only.
//!
//! # Checked against the real vpcd
//!
//! Everything above was first tested against a fake vpcd on `127.0.0.1` written from these
//! facts, in front of a scripted card and in front of the real engine (the tests still
//! do), on macOS and on Linux. A guest scenario then ran the transport in front of the
//! engine (first a small serving example, now `localkeyd` in
//! `tools/linux-guest/tests/vpcd.sh`) against vsmartcard-vpcd 3.3 (Ubuntu 26.04's
//! `3.3+dfsg-2ubuntu2`) and pcsc-lite 2.4.1 in the disposable no-NIC guest of
//! `tools/linux-guest/`, with OpenSC 0.27, ykman 5.8.0, pyscard and GnuPG 2.4.8 as
//! clients; every step passes (2026-10-11). Settled there:
//!
//! - vpcd listens on `0.0.0.0:35963` and `0.0.0.0:35964` (`/proc/net/tcp`); pcscd shows
//!   the readers "Virtual PCD 00 00" and "Virtual PCD 00 01"; the card connects to the
//!   first.
//! - **Insertion**: vpcd sends `GET ATR` (the presence check that accepted the
//!   connection), `GET ATR` again, then power on and `GET ATR` (`IFDHPowerICC`), about
//!   100 ms in all, then `GET ATR` about every 450 ms for as long as the card is in the
//!   reader. pcscd powers the card off 0.65 to 0.9 s after the last client disconnects and
//!   on again (power on, `GET ATR`) for the next one.
//! - **Clients**: opensc-tool APDUs, `gpg --card-status` (scdaemon through pcscd), ykman
//!   `info`, OATH with touch (the code checked against RFC 6238), PIV and OpenPGP, and an
//!   extended APDU of 4007 bytes (pyscard; one vpcd message, two XfrBlocks) all work.
//!   vpcd 3.3 answers no `IFDHControl` request (pcscd logs "IFDHControl not supported" for
//!   the feature request), yet pcscd passes the extended APDU.
//! - **ykman needs a Yubico reader name.** ykman treats only a reader whose name contains
//!   "yubico yubikey" as a YubiKey on USB (`YK_READER_NAME`, `ykman/pcsc/__init__.py`); in
//!   "Virtual PCD 00 00" every ykman command fails with "Failed to connect to YubiKey.".
//!   With `FRIENDLYNAME "Yubico YubiKey OTP+FIDO+CCID"` in `/etc/reader.conf.d/vpcd` the
//!   reader is "Yubico YubiKey OTP+FIDO+CCID 00 00" and ykman works, `ykman config usb`
//!   over CCID included. OpenSC and GnuPG work with either name.
//! - **Re-plug**: after `ykman config usb` (a REBOOT) pcscd logs "Card Removed" and "Card
//!   inserted", with the new connection [`REPLUG_PAUSE`] after the old one closed.
//!   Without the pause (the first version reconnected at once) pcscd missed the removal
//!   and kept the reader empty for good; see [`REPLUG_PAUSE`].
//! - **A connection lost while a command waits**: pcscd killed (SIGKILL) while a
//!   CALCULATE waited for a touch; the transport aborted the command (the device stopped
//!   waiting for the touch) less than half a second after the wait began, the kill
//!   included, retried every second while nothing listened, and was in the reader again
//!   when pcscd came back.
//! - **A dropped command**: a power cycle (as `localkeyd ctl power-cycle`) while a
//!   CALCULATE waited was answered with `6F00` after [`REPLY_SILENCE`] (ykman reports
//!   `SW=0x6f00`); vpcd kept the card and the next command worked.
//! - **vpcd down first**: one "cannot connect" notice, attempts every second, connected
//!   within a second of pcscd's start. When the card program ends, pcscd sees the card
//!   removed.
//! - The guest has no NIC and its loopback interface starts down: a connection to
//!   `127.0.0.1` fails with `ENETUNREACH` until `lo` is brought up (the script does).
//!   OpenSC's PIV driver, which claims this ATR, selects PIV again whenever it takes the
//!   card lock, so in one `opensc-tool` run a command after a SELECT of another
//!   application reaches PIV (`6D00`); `opensc-tool -c default` avoids that. Neither is a
//!   matter of this transport.

#![cfg(unix)]

pub mod ccid;
mod connect;
pub mod protocol;
mod transport;

pub use crate::connect::{CONNECT_TIMEOUT, Connector, TcpConnector, is_loopback, resolve};
pub use crate::transport::{
    DROP_TIMEOUT, ERROR_RESPONSE, OUTPUT_QUEUE, Observer, PEER_CHECK, REPLUG_PAUSE, REPLY_SILENCE, RETRY_INTERVAL,
    VpcdNotice, VpcdStats, VpcdTransport, WRITE_TIMEOUT,
};
