//! `localkeyd run --transport vpcd` end to end on any Unix (`docs/PROGRAM.md` "Transport
//! combinations": "`vpcd` alone runs on every Unix"): the real binary in front of a fake
//! vpcd that listens on `127.0.0.1` with an ephemeral port (the one place program tests use
//! TCP, `docs/PROGRAM.md` "lk-vpcd"). Nothing is installed into the system's PC/SC.
//!
//! The fake vpcd frames messages by hand from the vsmartcard documentation ("Virtual Smart
//! Card Architecture", api.html): a 2-byte big-endian length, then the payload; a 1-byte
//! payload is a control command (`VPCD_CTRL_OFF` 0, `VPCD_CTRL_ON` 1, `VPCD_CTRL_RESET` 2,
//! `VPCD_CTRL_ATR` 4, `vpcd.h`), anything longer a command APDU. Only `GET ATR` and APDUs
//! are answered. APDUs are YKOATH (Yubico's OATH protocol), as in `common`.
//!
//! The device's interfaces are changed with Yubico's Management WRITE CONFIG (yubikit
//! `management.py`: payload `DeviceConfig.get_bytes`, `len || TLVs`, with the USB enabled
//! applications tag `03` and the REBOOT tag `0C`), over the wire as the CTAPHID vendor
//! command `0x43` (`CTAP_WRITE_CONFIG`) and over vpcd as the APDU `INS_WRITE_CONFIG` `1C`
//! after selecting the Management application (`AID.MANAGEMENT`), as in
//! `crates/lk-run/tests/fanout.rs`.

mod common;

use std::error::Error;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use common::*;
use lk_core::DeviceProfile;

/// `VPCD_CTRL_ON` (`vpcd.h`): power the card on; no answer.
const POWER_ON: u8 = 0x01;
/// `VPCD_CTRL_ATR` (`vpcd.h`): answered with the ATR.
const GET_ATR: u8 = 0x04;

/// vpcd's side: a listener on `127.0.0.1`.
#[derive(Debug)]
struct FakeVpcd {
    listener: TcpListener,
}

impl FakeVpcd {
    /// Listen on an ephemeral loopback port.
    fn bind() -> io::Result<FakeVpcd> {
        FakeVpcd::listen(TcpListener::bind("127.0.0.1:0")?)
    }

    /// Listen on `addr` again (vpcd started late), retrying while the port is still taken.
    fn rebind(addr: SocketAddr) -> io::Result<FakeVpcd> {
        let deadline = Instant::now() + WAIT;
        loop {
            match TcpListener::bind(addr) {
                Ok(listener) => return FakeVpcd::listen(listener),
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                Err(error) => return Err(error),
            }
        }
    }

    fn listen(listener: TcpListener) -> io::Result<FakeVpcd> {
        listener.set_nonblocking(true)?;
        Ok(FakeVpcd { listener })
    }

    fn addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// The card's connection; the test fails without one within [`WAIT`].
    fn accept(&self) -> Result<Card, Box<dyn Error>> {
        let deadline = Instant::now() + WAIT;
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false)?;
                    stream.set_read_timeout(Some(WAIT))?;
                    return Ok(Card { stream });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() > deadline {
                        return Err(format!("the card did not connect within {WAIT:?}").into());
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

/// One connection: the card in vpcd's reader.
#[derive(Debug)]
struct Card {
    stream: TcpStream,
}

impl Card {
    fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        let mut message = u16::try_from(payload.len()).map_err(io::Error::other)?.to_be_bytes().to_vec();
        message.extend_from_slice(payload);
        self.stream.write_all(&message)
    }

    fn recv(&mut self) -> io::Result<Vec<u8>> {
        let mut length = [0; 2];
        self.stream.read_exact(&mut length)?;
        let mut payload = vec![0; usize::from(u16::from_be_bytes(length))];
        self.stream.read_exact(&mut payload)?;
        Ok(payload)
    }

    fn atr(&mut self) -> io::Result<Vec<u8>> {
        self.send(&[GET_ATR])?;
        self.recv()
    }

    fn transmit(&mut self, apdu: &[u8]) -> io::Result<Vec<u8>> {
        self.send(apdu)?;
        self.recv()
    }

    /// Whether the card's side closed the connection (the card left the reader) within
    /// [`WAIT`].
    fn removed(&mut self) -> bool {
        let mut byte = [0; 1];
        match self.stream.read(&mut byte) {
            Ok(0) => true,
            Err(error) => error.kind() == io::ErrorKind::ConnectionReset,
            Ok(_) => false,
        }
    }
}

/// SELECT the OATH application (ISO/IEC 7816-4 §11.2.2, short form).
fn select_oath() -> Vec<u8> {
    select(AID_OATH)
}

/// SELECT by AID (ISO/IEC 7816-4 §11.2.2, short form).
fn select(aid: &[u8]) -> Vec<u8> {
    let mut apdu = vec![0x00, 0xA4, 0x04, 0x00, aid.len() as u8];
    apdu.extend_from_slice(aid);
    apdu
}

/// The Management application (yubikit `AID.MANAGEMENT`).
const AID_MANAGEMENT: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];
/// Yubico's CTAPHID vendor command WRITE CONFIG (yubikit `CTAP_WRITE_CONFIG`).
const CTAPHID_WRITE_CONFIG: u8 = 0x43;
/// Management WRITE CONFIG over CCID (yubikit `INS_WRITE_CONFIG`), P1 = P2 = 0.
const INS_WRITE_CONFIG: u8 = 0x1C;
/// A WRITE CONFIG payload: USB enabled applications OTP | U2F | FIDO2 (`0x0203`, no CCID
/// application, so no CCID interface), then REBOOT.
const OTP_FIDO_WITH_REBOOT: [u8; 7] = [0x06, 0x03, 0x02, 0x02, 0x03, 0x0C, 0x00];
/// The same with OATH added (`0x0223`): the CCID interface is back.
const OTP_FIDO_OATH_WITH_REBOOT: [u8; 7] = [0x06, 0x03, 0x02, 0x02, 0x23, 0x0C, 0x00];

/// The WRITE CONFIG APDU (short form) carrying `config`.
fn write_config(config: &[u8]) -> Vec<u8> {
    let mut apdu = vec![0x00, INS_WRITE_CONFIG, 0x00, 0x00, config.len() as u8];
    apdu.extend_from_slice(config);
    apdu
}

/// Poll `ctl status` until `key` has `value`.
fn wait_status(dir: &TestDir, key: &str, value: &str) -> TestResult {
    let deadline = Instant::now() + WAIT;
    loop {
        let output = ctl(&dir.control(), &["status"])?;
        let stdout = text(&output.stdout);
        if status_value(&stdout, key).as_deref() == Some(value) {
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(format!("{key}={value} not in the status within {WAIT:?}: {stdout}").into());
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// Write the device configuration `config` (with REBOOT) through a wire daemon on `dir`,
/// wait until `status` shows `interfaces`, and stop that daemon.
fn configure_over_the_wire(dir: &TestDir, config: &[u8], interfaces: &str) -> TestResult {
    let mut daemon = Daemon::with_key(dir, &[])?;
    let mut host = Host::connect(dir)?;
    let cid = host.ctaphid_init()?;
    host.ctaphid_send(cid, CTAPHID_WRITE_CONFIG, config)?;
    host.ctaphid_response(cid)?;
    wait_status(dir, "interfaces", interfaces)?;
    drop(host);
    assert_eq!(daemon.stop()?.code(), Some(0), "{}", daemon.log());
    Ok(())
}

/// This process's real uid (the first number of `Uid:` in `/proc/self/status`), on Linux.
fn own_uid() -> Result<u32, Box<dyn Error>> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let line = status.lines().find_map(|line| line.strip_prefix("Uid:")).ok_or("no Uid line")?;
    Ok(line.split_whitespace().next().ok_or("an empty Uid line")?.parse()?)
}

/// Whether the card's connection is closed without a byte from the daemon (a refused
/// peer), within [`WAIT`].
#[cfg(target_os = "linux")]
fn closed_unused(card: &mut Card) -> io::Result<bool> {
    let mut rest = Vec::new();
    card.stream.read_to_end(&mut rest)?;
    Ok(rest.is_empty())
}

/// Whether no card connects to `vpcd` for `time`.
fn nothing_connects(vpcd: &FakeVpcd, time: Duration) -> bool {
    thread::sleep(time);
    matches!(vpcd.listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
}

#[test]
fn a_vpcd_daemon_is_a_card_in_the_reader_and_ctl_shutdown_removes_it() -> TestResult {
    let dir = TestDir::new();
    keygen(&dir.key())?;
    let vpcd = FakeVpcd::bind()?;
    let addr = vpcd.addr()?.to_string();
    let mut daemon = Daemon::with_key(&dir, &["--transport", "vpcd", "--vpcd-addr", &addr, "-vv"])?;
    let mut card = vpcd.accept()?;

    // vpcd's insertion sequence (lk-vpcd, "Checked against the real vpcd"): GET ATR, then
    // power on and GET ATR.
    let atr = DeviceProfile::own(0).atr;
    assert_eq!(card.atr()?, atr, "the own profile's ATR");
    card.send(&[POWER_ON])?;
    assert_eq!(card.atr()?, atr);
    let select = card.transmit(&select_oath())?;
    assert_eq!(sw(&select), 0x9000, "{select:02X?}");
    assert_eq!(card.transmit(&oath_put(b"vpcd"))?, [0x90, 0x00]);
    assert_eq!(card.transmit(&OATH_LIST)?, oath_list_of_one(b"vpcd"));

    let output = ctl(&dir.control(), &["status"])?;
    let stdout = text(&output.stdout);
    assert_eq!(status_value(&stdout, "attached").as_deref(), Some("true"), "the card is in the reader: {stdout}");
    assert_eq!(status_value(&stdout, "interfaces").as_deref(), Some("otp,fido,ccid"));
    assert!(!dir.wire().exists(), "no wire socket with the vpcd transport");
    for expected in [
        "transport vpcd".to_owned(),
        format!("serving: vpcd card for {addr}, control socket"),
        format!("vpcd: connected to {addr}; card inserted"),
        "vpcd: <- get ATR, 1 bytes".to_owned(),
        "vpcd: <- APDU, ".to_owned(),
        "vpcd: -> response, 2 bytes".to_owned(),
        format!("vpcd: -> ATR, {} bytes", atr.len()),
        // The peer check (lk-vpcd `peer`): on Linux the fake vpcd is this user's, one of the
        // default allowed uids; elsewhere nothing is checked, which -v says once.
        if cfg!(target_os = "linux") {
            format!("vpcd: the peer on {addr} is owned by uid {}, an allowed uid", own_uid()?)
        } else {
            format!("vpcd: the peer on {addr} is not checked: ")
        },
    ] {
        daemon.wait_log(&expected)?;
    }
    let key = std::fs::read_to_string(dir.key())?;
    assert!(!daemon.log().to_lowercase().contains(key.trim()), "the key is not logged");

    let output = ctl(&dir.control(), &["shutdown"])?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "ok\nstopped\n");
    assert!(card.removed(), "vpcd saw the card removed");
    assert!(!dir.control().exists(), "the control socket was removed");
    assert_eq!(daemon.wait_exit()?.code(), Some(0), "{}", daemon.log());
    assert!(daemon.log().contains("localkeyd: stopped"), "{}", daemon.log());

    // The credential was stored: the next daemon's card lists it.
    let mut daemon = Daemon::with_key(&dir, &["--transport", "vpcd", "--vpcd-addr", &addr])?;
    let mut card = vpcd.accept()?;
    card.atr()?;
    card.send(&[POWER_ON])?;
    card.atr()?;
    assert_eq!(sw(&card.transmit(&select_oath())?), 0x9000);
    assert_eq!(card.transmit(&OATH_LIST)?, oath_list_of_one(b"vpcd"));
    assert_eq!(daemon.stop()?.code(), Some(0), "{}", daemon.log());
    assert!(card.removed(), "closing stdin removes the card too");
    Ok(())
}

/// vpcd (inside pcscd) may start after the daemon: the daemon serves anyway, says once
/// that it cannot connect, retries every second, and inserts the card when vpcd listens.
#[test]
fn the_daemon_serves_before_vpcd_listens_and_inserts_the_card_once_it_does() -> TestResult {
    let dir = TestDir::new();
    keygen(&dir.key())?;
    // A free loopback port: bound, then let go.
    let addr = FakeVpcd::bind()?.addr()?;
    let shown = addr.to_string();
    let mut daemon = Daemon::with_key(&dir, &["--transport", "vpcd", "--vpcd-addr", &shown])?;
    daemon.wait_log(&format!("vpcd: cannot connect to {shown}: "))?;
    let output = ctl(&dir.control(), &["status"])?;
    assert_eq!(status_value(&text(&output.stdout), "attached").as_deref(), Some("false"), "no card yet");

    let vpcd = FakeVpcd::rebind(addr)?;
    let mut card = vpcd.accept()?;
    assert_eq!(card.atr()?, DeviceProfile::own(0).atr);
    let output = ctl(&dir.control(), &["status"])?;
    assert_eq!(status_value(&text(&output.stdout), "attached").as_deref(), Some("true"));
    let log = daemon.log();
    assert_eq!(log.matches("cannot connect").count(), 1, "one notice for the whole series: {log}");

    assert_eq!(daemon.stop()?.code(), Some(0), "{}", daemon.log());
    assert!(card.removed());
    Ok(())
}

/// `--transport vpcd` on a device whose stored configuration has CCID disabled would
/// present nothing for good: vpcd carries only CCID, so no Management command can reach
/// the device to enable it again, and `ctl power-cycle` and `ctl tap` change no
/// configuration. The daemon refuses to start (exit 2) and says why at the default level,
/// without binding a socket or connecting to vpcd. Once CCID is enabled again over another
/// transport, the vpcd daemon serves. (Kept from the review that found it: the daemon
/// served, logged `serving: vpcd card for ADDR` and said `enumerated without CCID; no card`
/// only at `-v`.)
#[test]
fn a_vpcd_daemon_whose_device_has_ccid_disabled_refuses_to_start_and_says_why() -> TestResult {
    let dir = TestDir::new();
    keygen(&dir.key())?;
    configure_over_the_wire(&dir, &OTP_FIDO_WITH_REBOOT, "otp,fido")?;

    let vpcd = FakeVpcd::bind()?;
    let addr = vpcd.addr()?.to_string();
    let key = dir.key();
    let key = key.to_str().ok_or("the key path is not UTF-8")?;
    let mut daemon = Daemon::spawn(&dir, &["--key-file", key, "--transport", "vpcd", "--vpcd-addr", &addr])?;
    assert_eq!(daemon.wait_exit()?.code(), Some(2), "{}", daemon.log());
    let log = daemon.log();
    assert!(
        log.contains(
            "localkeyd: refusing to start: --transport vpcd presents the ccid interface only, and the device's \
             enabled interfaces are otp,fido. Nothing would be presented"
        ),
        "{log}"
    );
    assert!(
        log.contains(
            "start once with a transport that presents otp,fido (wire, or uhid,vpcd on Linux) and enable ccid there"
        ),
        "how to recover: {log}"
    );
    assert!(!log.contains("serving:"), "{log}");
    assert!(!dir.control().exists(), "no control socket was bound");
    assert!(nothing_connects(&vpcd, Duration::ZERO), "no card was inserted");

    configure_over_the_wire(&dir, &OTP_FIDO_OATH_WITH_REBOOT, "otp,fido,ccid")?;
    let mut daemon = Daemon::with_key(&dir, &["--transport", "vpcd", "--vpcd-addr", &addr])?;
    let mut card = vpcd.accept()?;
    assert_eq!(card.atr()?, DeviceProfile::own(0).atr, "the card is back");
    assert_eq!(daemon.stop()?.code(), Some(0), "{}", daemon.log());
    Ok(())
}

/// Disabling CCID over vpcd itself (a Management WRITE CONFIG with REBOOT, as `ykman
/// config usb --disable` sends it) leaves the daemon with nothing to present until it is
/// restarted with another transport. The write is answered, the card leaves the reader for
/// good, and the default-level log says so, with what to do. The daemon keeps serving its
/// control socket and stops cleanly.
#[test]
fn disabling_ccid_over_vpcd_warns_at_the_default_level_that_nothing_is_presented_any_more() -> TestResult {
    let dir = TestDir::new();
    keygen(&dir.key())?;
    let vpcd = FakeVpcd::bind()?;
    let addr = vpcd.addr()?.to_string();
    let mut daemon = Daemon::with_key(&dir, &["--transport", "vpcd", "--vpcd-addr", &addr])?;
    let mut card = vpcd.accept()?;
    card.atr()?;
    card.send(&[POWER_ON])?;
    card.atr()?;
    assert_eq!(sw(&card.transmit(&select(AID_MANAGEMENT))?), 0x9000);
    assert_eq!(card.transmit(&write_config(&OTP_FIDO_WITH_REBOOT))?, [0x90, 0x00], "the write is answered");
    assert!(card.removed(), "the reboot takes the card out of the reader");

    daemon.wait_log(
        "localkeyd: warning: nothing presented: --transport vpcd presents the ccid interface only, and the \
         device's enabled interfaces are otp,fido; no command can reach the device to change that, so it stays \
         absent until localkeyd is restarted with a transport that presents otp,fido",
    )?;
    wait_status(&dir, "interfaces", "otp,fido")?;
    wait_status(&dir, "attached", "false")?;
    // Twice the re-plug pause: a card would be back by now.
    assert!(nothing_connects(&vpcd, Duration::from_secs(3)), "the card stays out");
    assert_eq!(daemon.stop()?.code(), Some(0), "{}", daemon.log());
    Ok(())
}

/// The vpcd options belong to `--transport vpcd` (usage errors elsewhere), and their
/// values are checked: all exit 2 with the usage.
#[test]
fn the_vpcd_options_are_usage_errors_without_the_vpcd_transport_or_with_bad_values() -> TestResult {
    let run = ["run", "--state", "/nonexistent", "--key-file", "/k"];
    for (extra, message) in [
        (&["--vpcd-allow-remote"][..], "--vpcd-allow-remote applies to --transport vpcd only (the transport is wire)"),
        (&["--transport", "uhid", "--vpcd-peer-uid", "0"], "--vpcd-peer-uid applies to --transport vpcd only"),
        (&["--transport", "gadget", "--udc", "u", "--vpcd-allow-remote"], "--vpcd-allow-remote applies to"),
        (&["--transport", "vpcd", "--vpcd-peer-uid", "root"], "--vpcd-peer-uid \"root\": expected user ids"),
        (&["--transport", "vpcd", "--vpcd-peer-uid", "0,"], "--vpcd-peer-uid \"0,\": expected user ids"),
        (&["--transport", "vpcd", "--vpcd-allow-remote=1"], "--vpcd-allow-remote takes no value"),
    ] {
        let output = localkeyd(run.iter().chain(extra))?;
        assert_eq!(output.status.code(), Some(2), "{extra:?}");
        let stderr = text(&output.stderr);
        assert!(stderr.contains(message) && stderr.contains("usage:"), "{extra:?}: {stderr}");
    }
    Ok(())
}

/// The loopback rule (lk-vpcd `check_addr`): a `--vpcd-addr` that is not a loopback
/// address is a startup failure (exit 2) before the state directory is created, unless
/// `--vpcd-allow-remote` is given. Nothing is dialled. A host name counts by what it
/// resolves to, and `--vpcd-allow-remote` with a loopback address changes nothing.
#[test]
fn a_remote_vpcd_address_is_refused_before_the_state_directory_unless_allowed() -> TestResult {
    let dir = TestDir::new();
    keygen(&dir.key())?;
    let key = dir.key();
    let key = key.to_str().ok_or("the key path is not UTF-8")?;
    for remote in ["192.0.2.1:35963", "[2001:db8::1]:35963", "[::ffff:192.0.2.1]:35963"] {
        let mut daemon = Daemon::spawn(&dir, &["--key-file", key, "--transport", "vpcd", "--vpcd-addr", remote])?;
        assert_eq!(daemon.wait_exit()?.code(), Some(2), "{}", daemon.log());
        let log = daemon.log();
        assert!(log.contains(&format!("localkeyd: --vpcd-addr {remote}: ")), "{log}");
        assert!(
            log.contains(
                "is not a loopback address: APDUs (PINs and keys among them) would travel to it unencrypted, and \
                 whatever listens there would drive the card unchecked; pass --vpcd-allow-remote to use it anyway"
            ),
            "{log}"
        );
        assert!(!dir.state().exists(), "the state directory was not created: {log}");
    }

    let vpcd = FakeVpcd::bind()?;
    let port = vpcd.addr()?.port();
    let named = format!("localhost:{port}");
    let mut daemon = Daemon::with_key(&dir, &["--transport", "vpcd", "--vpcd-addr", &named, "--vpcd-allow-remote"])?;
    let mut card = vpcd.accept()?;
    assert_eq!(card.atr()?, DeviceProfile::own(0).atr);
    assert!(daemon.log().contains(&format!("serving: vpcd card for 127.0.0.1:{port}")), "{}", daemon.log());
    assert!(!daemon.log().contains("not a loopback address"), "loopback is not warned about: {}", daemon.log());
    assert_eq!(daemon.stop()?.code(), Some(0), "{}", daemon.log());
    Ok(())
}

/// `--vpcd-peer-uid` can be applied on Linux only: elsewhere it is a startup failure
/// (exit 2) before the state directory, not an option that silently does nothing.
#[cfg(not(target_os = "linux"))]
#[test]
fn vpcd_peer_uid_is_refused_where_there_is_no_proc() -> TestResult {
    let dir = TestDir::new();
    keygen(&dir.key())?;
    let key = dir.key();
    let key = key.to_str().ok_or("the key path is not UTF-8")?;
    let mut daemon = Daemon::spawn(&dir, &["--key-file", key, "--transport", "vpcd", "--vpcd-peer-uid", "0"])?;
    assert_eq!(daemon.wait_exit()?.code(), Some(2), "{}", daemon.log());
    let log = daemon.log();
    assert!(
        log.contains(&format!(
            "localkeyd: --vpcd-peer-uid: the owner of vpcd's socket is looked up in /proc/net/tcp, which only Linux \
             has, and this system is {}",
            std::env::consts::OS
        )),
        "{log}"
    );
    assert!(!dir.state().exists(), "{log}");
    Ok(())
}

/// The peer check on a real kernel (lk-vpcd `ProcNetPeerCheck`): the fake vpcd listens as
/// this user. With `--vpcd-peer-uid` naming another uid, every connection is closed
/// without a byte, the refusal is logged once at the default level and the daemon keeps
/// trying every second; with this user's uid the card is inserted.
#[cfg(target_os = "linux")]
#[test]
fn a_vpcd_peer_owned_by_a_uid_not_allowed_is_refused_and_one_allowed_gets_the_card() -> TestResult {
    let dir = TestDir::new();
    keygen(&dir.key())?;
    let own = own_uid()?;
    let other = own.wrapping_add(1).to_string();
    let vpcd = FakeVpcd::bind()?;
    let addr = vpcd.addr()?.to_string();
    let mut daemon = Daemon::with_key(&dir, &["--transport", "vpcd", "--vpcd-addr", &addr, "--vpcd-peer-uid", &other])?;
    for _ in 0..2 {
        let mut card = vpcd.accept()?;
        assert!(closed_unused(&mut card)?, "a refused peer gets no byte");
    }
    let refusal = format!(
        "localkeyd: vpcd: the peer on {addr} is owned by uid {own}, not an allowed uid ({other}); refusing the \
         connection, retrying every second"
    );
    daemon.wait_log(&refusal)?;
    let output = ctl(&dir.control(), &["status"])?;
    assert_eq!(status_value(&text(&output.stdout), "attached").as_deref(), Some("false"), "no card");
    assert_eq!(daemon.stop()?.code(), Some(0), "{}", daemon.log());
    let log = daemon.log();
    assert_eq!(log.matches("not an allowed uid").count(), 1, "one notice for the series: {log}");

    let allowed = format!("{other},{own}");
    let mut daemon =
        Daemon::with_key(&dir, &["--transport", "vpcd", "--vpcd-addr", &addr, "--vpcd-peer-uid", &allowed, "-v"])?;
    let mut card = vpcd.accept()?;
    assert_eq!(card.atr()?, DeviceProfile::own(0).atr);
    daemon.wait_log(&format!("vpcd: the peer on {addr} is owned by uid {own}, an allowed uid"))?;
    assert_eq!(daemon.stop()?.code(), Some(0), "{}", daemon.log());
    Ok(())
}
