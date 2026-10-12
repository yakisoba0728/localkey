//! The real `localkeyd` binary end to end (`docs/PROGRAM.md` "localkeyd"): a child process
//! on a fresh state directory, driven over its wire socket with `lk_wire::Client` and over
//! its control socket with `localkeyd ctl`.

mod common;

use std::fs;
use std::time::{Duration, Instant};

use common::*;
use lk_codec::cbor;

/// authenticatorGetInfo (CTAP 2.1 §6.4).
const GET_INFO: [u8; 1] = [0x04];
/// authenticatorSelection (CTAP 2.1 §6.9): always waits for user presence.
const SELECTION: [u8; 1] = [0x0B];
/// CTAP2_OK (CTAP 2.1 §8.2).
const CTAP2_OK: u8 = 0x00;
/// AAGUIDs of `DeviceProfile::yubikey_compat` and `DeviceProfile::own`.
const AAGUID_YUBIKEY_COMPAT: [u8; 16] = [
    0xff, 0x4d, 0xac, 0x45, 0xed, 0xe8, 0x4e, 0xc2, 0xac, 0xed, 0xcf, 0x66, 0x10, 0x3f, 0x43, 0x35,
];
const AAGUID_OWN: [u8; 16] = [
    0x6c, 0x6b, 0x65, 0x79, 0x2d, 0x4c, 0x4b, 0x01, 0x8f, 0x3a, 0x54, 0x6e, 0x67, 0x69, 0x6e, 0x65,
];
/// The `status` keys, in the order the control socket sends them (`docs/PROGRAM.md`
/// "Control socket"; `attached` because the transport is the wire).
const STATUS_KEYS: [&str; 10] =
    ["serial", "product", "interfaces", "presence", "attached", "suspended", "queued", "dropped", "unreadable", "uptime_ms"];

/// authenticatorGetInfo's AAGUID (key 3) and versions (key 1).
fn get_info(host: &mut Host) -> Result<(Vec<u8>, Vec<String>), Box<dyn std::error::Error>> {
    let cid = host.ctaphid_init()?;
    let response = host.cbor(cid, &GET_INFO)?;
    assert_eq!(response.first(), Some(&CTAP2_OK), "getInfo status: {response:02x?}");
    let info = cbor::decode(&response[1..]).map_err(|error| format!("getInfo is not CBOR: {error:?}"))?;
    let aaguid = info.map_get_int(3).and_then(|value| value.as_bytes()).ok_or("getInfo has no AAGUID")?;
    let versions = info.map_get_int(1).and_then(|value| value.as_array()).ok_or("getInfo has no versions")?;
    let versions = versions.iter().filter_map(|version| version.as_text().map(String::from)).collect();
    Ok((aaguid.to_vec(), versions))
}

#[test]
fn get_info_over_the_wire_carries_the_profile_aaguid_and_versions() -> TestResult {
    let dir = TestDir::new();
    keygen(&dir.key())?;
    let daemon = Daemon::with_key(&dir, &["--profile", "yubikey", "-vv"])?;
    let mut host = Host::connect(&dir)?;
    let identity = host.client.identity().clone();
    assert_eq!((identity.vendor_id, identity.product_id), (0x1050, 0x0407), "YubiKey OTP+FIDO+CCID");
    assert_eq!(identity.product, "YubiKey OTP+FIDO+CCID");

    let (aaguid, versions) = get_info(&mut host)?;
    assert_eq!(aaguid, AAGUID_YUBIKEY_COMPAT);
    for version in ["U2F_V2", "FIDO_2_0", "FIDO_2_1"] {
        assert!(versions.iter().any(|v| v == version), "{version} in {versions:?}");
    }

    // -vv: connections, enumeration, frame types and sizes; never the key.
    for expected in ["wire: client connected", "wire: enumerated as product 0x0407", "wire: <- 0x01, 64 bytes", "wire: -> 0x81, 64 bytes"] {
        daemon.wait_log(expected)?;
    }
    let log = daemon.log();
    let key = fs::read_to_string(dir.key())?;
    assert!(!log.to_lowercase().contains(key.trim()), "the key is not logged");
    Ok(())
}

#[test]
fn the_own_profile_is_the_default() -> TestResult {
    let dir = TestDir::new();
    keygen(&dir.key())?;
    let _daemon = Daemon::with_key(&dir, &[])?;
    let mut host = Host::connect(&dir)?;
    let identity = host.client.identity().clone();
    assert_eq!((identity.vendor_id, identity.manufacturer.as_str()), (0x1209, "localkey"));
    let (aaguid, _) = get_info(&mut host)?;
    assert_eq!(aaguid, AAGUID_OWN);
    Ok(())
}

#[test]
fn an_oath_credential_survives_a_crash_and_restart() -> TestResult {
    let dir = TestDir::new();
    keygen(&dir.key())?;
    let mut daemon = Daemon::with_key(&dir, &[])?;
    let mut host = Host::connect(&dir)?;
    host.power_on()?;
    assert_eq!(sw(&host.select(AID_OATH)?), 0x9000);
    assert_eq!(host.apdu(&oath_put(b"crash"))?, [0x90, 0x00]);
    assert_eq!(host.apdu(&OATH_LIST)?, oath_list_of_one(b"crash"));

    // SIGKILL: no clean shutdown, the sockets stay behind.
    daemon.kill()?;
    drop(host);
    assert!(dir.wire().exists(), "a killed daemon leaves its socket");

    let _daemon = Daemon::with_key(&dir, &[])?;
    let mut host = Host::connect(&dir)?;
    host.power_on()?;
    assert_eq!(sw(&host.select(AID_OATH)?), 0x9000);
    assert_eq!(host.apdu(&OATH_LIST)?, oath_list_of_one(b"crash"));
    Ok(())
}

#[test]
fn a_second_daemon_on_the_same_state_exits_at_once_naming_the_lock() -> TestResult {
    let dir = TestDir::new();
    keygen(&dir.key())?;
    let first = Daemon::with_key(&dir, &[])?;

    let key = dir.key();
    let started = Instant::now();
    let mut second = Daemon::spawn(&dir, &["--key-file", key.to_str().ok_or("key path")?])?;
    let status = second.wait_exit()?;
    assert_eq!(status.code(), Some(2), "{}", second.log());
    assert!(started.elapsed() < Duration::from_secs(20), "took {:?}", started.elapsed());
    let log = second.log();
    assert!(log.contains("lock"), "{log}");
    assert!(log.contains(&format!("pid {}", first.pid())), "{log}");

    // The first daemon is unaffected.
    let output = ctl(&dir.control(), &["status"])?;
    assert!(output.status.success(), "{}", text(&output.stderr));
    Ok(())
}

#[test]
fn a_wrong_key_is_refused_with_code_3_and_changes_nothing() -> TestResult {
    let dir = TestDir::new();
    keygen(&dir.key())?;
    let wrong = dir.join("k2");
    keygen(&wrong)?;
    let wrong = wrong.to_str().ok_or("key path")?;

    let mut daemon = Daemon::with_key(&dir, &[])?;
    let mut host = Host::connect(&dir)?;
    host.power_on()?;
    host.select(AID_OATH)?;
    assert_eq!(host.apdu(&oath_put(b"kept"))?, [0x90, 0x00]);
    drop(host);
    assert_eq!(daemon.stop()?.code(), Some(0));
    let before = record_files(&dir.state())?;
    assert!(before.contains_key("oath.rec"), "records written: {:?}", before.keys());

    let mut refused = Daemon::spawn(&dir, &["--key-file", wrong])?;
    let status = refused.wait_exit()?;
    let log = refused.log();
    assert_eq!(status.code(), Some(3), "{log}");
    for name in before.keys() {
        assert!(log.contains(name.as_str()), "{name} named in:\n{log}");
    }
    assert!(log.contains("--allow-unreadable"), "{log}");
    assert!(!dir.wire().exists() && !dir.control().exists(), "no socket was bound");
    assert_eq!(record_files(&dir.state())?, before, "no record file changed");

    // With --allow-unreadable it serves, and says which records it could not open.
    let _daemon = Daemon::start(&dir, &["--key-file", wrong, "--allow-unreadable"])?;
    let _host = Host::connect(&dir)?;
    let output = ctl(&dir.control(), &["status"])?;
    assert!(output.status.success(), "{}", text(&output.stderr));
    let unreadable = status_value(&text(&output.stdout), "unreadable").ok_or("no unreadable key")?;
    let mut unreadable: Vec<String> = unreadable.split(',').map(|name| format!("{name}.rec")).collect();
    unreadable.sort();
    assert_eq!(unreadable, before.keys().cloned().collect::<Vec<_>>());
    Ok(())
}

#[test]
fn ctl_status_lists_the_documented_keys() -> TestResult {
    let dir = TestDir::new();
    keygen(&dir.key())?;
    let _daemon = Daemon::with_key(&dir, &[])?;

    let output = ctl(&dir.control(), &["status"])?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let stdout = text(&output.stdout);
    assert!(stdout.ends_with("\nok\n"), "{stdout}");
    let pairs = status_pairs(&stdout);
    assert_eq!(pairs.iter().map(|(key, _)| key.as_str()).collect::<Vec<_>>(), STATUS_KEYS);
    let value = |key| status_value(&stdout, key).unwrap_or_default();
    assert_eq!(value("serial"), persisted_serial(&dir.state())?);
    assert_eq!(value("product"), "localkey");
    assert_eq!(value("interfaces"), "otp,fido,ccid");
    assert_eq!(value("presence"), "idle");
    assert_eq!(value("attached"), "false");
    assert_eq!(value("unreadable"), "");
    assert!(value("uptime_ms").parse::<u64>().is_ok(), "{stdout}");

    let _host = Host::connect(&dir)?;
    let output = ctl(&dir.control(), &["status"])?;
    assert_eq!(status_value(&text(&output.stdout), "attached").as_deref(), Some("true"));
    Ok(())
}

#[test]
fn ctl_tap_answers_a_pending_presence_request() -> TestResult {
    let dir = TestDir::new();
    keygen(&dir.key())?;
    let _daemon = Daemon::with_key(&dir, &[])?;
    let mut host = Host::connect(&dir)?;
    let cid = host.ctaphid_init()?;

    host.ctaphid_send(cid, CTAPHID_CBOR, &SELECTION)?;
    assert_eq!(host.ctaphid_message(cid)?, (CTAPHID_KEEPALIVE, vec![STATUS_UPNEEDED]));
    let output = ctl(&dir.control(), &["status"])?;
    assert_eq!(status_value(&text(&output.stdout), "presence").as_deref(), Some("waiting"));

    let output = ctl(&dir.control(), &["tap"])?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "ok\n");
    assert_eq!(host.ctaphid_response(cid)?, (CTAPHID_CBOR, vec![CTAP2_OK]));
    Ok(())
}

#[test]
fn closing_stdin_stops_the_daemon_cleanly_and_removes_both_sockets() -> TestResult {
    let dir = TestDir::new();
    keygen(&dir.key())?;
    let mut daemon = Daemon::with_key(&dir, &[])?;
    let _host = Host::connect(&dir)?;
    assert!(dir.wire().exists() && dir.control().exists());

    let status = daemon.stop()?;
    assert_eq!(status.code(), Some(0), "{}", daemon.log());
    assert!(!dir.wire().exists(), "the wire socket is removed");
    assert!(!dir.control().exists(), "the control socket is removed");
    assert!(daemon.log().contains("localkeyd: stopped"), "{}", daemon.log());
    Ok(())
}

/// `docs/PROGRAM.md` "Clean shutdown from the control socket": `ctl shutdown` gets `ok`,
/// then the daemon does what `--exit-on-stdin-eof` does at EOF, tells `ctl` `stopped` and
/// exits 0. It works without `--exit-on-stdin-eof` and with stdin at `/dev/null`, as under
/// a supervisor, and `ctl` returns only once the shutdown is done: both sockets are gone by
/// then and the wire client has been unplugged.
#[test]
fn ctl_shutdown_stops_a_supervised_daemon_cleanly_and_removes_both_sockets() -> TestResult {
    let dir = TestDir::new();
    keygen(&dir.key())?;
    let key = dir.key();
    let mut daemon = Daemon::start_supervised(&dir, &["--key-file", key.to_str().ok_or("key path")?, "-v"])?;
    let mut host = Host::connect(&dir)?;
    assert!(dir.wire().exists() && dir.control().exists());

    let output = ctl(&dir.control(), &["shutdown"])?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "ok\nstopped\n", "accepted, then stopped cleanly");
    assert!(!dir.wire().exists(), "the wire socket was removed before ctl returned");
    assert!(!dir.control().exists(), "the control socket was removed before ctl returned");
    let unplugged = loop {
        match host.client.recv(WAIT) {
            Ok(Some(_)) => {}
            Ok(None) => break false,
            Err(_) => break true,
        }
    };
    assert!(unplugged, "the wire client was disconnected");

    let deadline = Instant::now() + Duration::from_secs(20);
    while !daemon.has_exited()? {
        assert!(Instant::now() < deadline, "the daemon still runs well after ctl returned:\n{}", daemon.log());
        std::thread::sleep(Duration::from_millis(20));
    }
    let status = daemon.wait_exit()?;
    assert_eq!(status.code(), Some(0), "{}", daemon.log());
    let log = daemon.log();
    assert!(log.contains("localkeyd: shutdown requested on the control socket; shutting down"), "{log}");
    assert!(log.contains("localkeyd: stopped"), "{log}");
    assert!(!log.contains("stdin closed"), "{log}");

    // The state is kept: the next start serves the same serial.
    let serial = persisted_serial(&dir.state())?;
    let _again = Daemon::with_key(&dir, &[])?;
    let output = ctl(&dir.control(), &["status"])?;
    assert_eq!(status_value(&text(&output.stdout), "serial"), Some(serial));
    Ok(())
}

/// The same shutdown with `--exit-on-stdin-eof` given: whichever comes first stops the
/// daemon, and the other one then finds nothing to do.
#[test]
fn ctl_shutdown_also_stops_a_daemon_that_watches_stdin() -> TestResult {
    let dir = TestDir::new();
    keygen(&dir.key())?;
    let mut daemon = Daemon::with_key(&dir, &[])?;
    let output = ctl(&dir.control(), &["shutdown"])?;
    let reply = (output.status.code(), text(&output.stdout));
    assert_eq!(reply, (Some(0), "ok\nstopped\n".to_owned()), "{}", text(&output.stderr));
    assert_eq!(daemon.stop()?.code(), Some(0), "{}", daemon.log());
    assert!(!dir.wire().exists() && !dir.control().exists());
    let output = ctl(&dir.control(), &["shutdown"])?;
    assert_eq!(output.status.code(), Some(1), "no daemon to stop: {}", text(&output.stderr));
    Ok(())
}

/// `ctl shutdown` exits 0 only when the daemon reports a clean stop (`stopped` after `ok`).
/// A daemon that fails after accepting the request reports `error <reason>`, and one that
/// ends without a word after `ok` (killed, aborted) cannot have stopped cleanly: `ctl`
/// exits 1 for both. (Found by review: `ok` and the close alone made `ctl` exit 0 while
/// the daemon exited 1 or 2.) The daemon's side is played by a fake control socket.
#[test]
fn ctl_shutdown_exits_0_only_when_the_daemon_reports_a_clean_stop() -> TestResult {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    let dir = TestDir::new();
    let path = dir.join("fc");
    for (reply, code, stderr) in [
        ("ok\nstopped\n", 0, ""),
        ("ok\nerror the runner stopped unexpectedly\n", 1, ""),
        ("ok\n", 1, "the daemon accepted the shutdown but ended without reporting a clean stop"),
    ] {
        let _ = fs::remove_file(&path);
        let listener = UnixListener::bind(&path)?;
        let daemon = std::thread::spawn(move || -> std::io::Result<String> {
            let (stream, _) = listener.accept()?;
            let mut request = String::new();
            BufReader::new(&stream).read_line(&mut request)?;
            (&stream).write_all(reply.as_bytes())?;
            Ok(request)
        });
        let output = ctl(&path, &["shutdown"])?;
        let request = daemon.join().map_err(|_| "the fake daemon panicked")??;
        assert_eq!(request, "shutdown\n");
        assert_eq!(output.status.code(), Some(code), "{reply:?}: {}", text(&output.stderr));
        assert_eq!(text(&output.stdout), reply, "every line is printed");
        assert!(text(&output.stderr).contains(stderr), "{reply:?}: {}", text(&output.stderr));
    }
    Ok(())
}

#[test]
fn a_key_command_supplies_the_key() -> TestResult {
    let dir = TestDir::new();
    keygen(&dir.key())?;
    let command = format!("cat '{}'", dir.key().display());
    let _daemon = Daemon::start(&dir, &["--key-command", &command])?;
    let output = ctl(&dir.control(), &["status"])?;
    assert!(output.status.success(), "{}", text(&output.stderr));
    Ok(())
}

#[test]
fn usage_errors_exit_with_code_2() -> TestResult {
    for args in [
        &[][..],
        &["serve"],
        &["run", "--key-file", "/nonexistent"],
        &["run", "--state", "/nonexistent", "--key-file", "/k", "--profile", "invalid"],
        &["keygen"],
        &["ctl", "--control", "/nonexistent", "frobnicate"],
        &["run", "--state", "/nonexistent", "--key-file", "/k", "--transport", "gadget"],
        &["run", "--state", "/nonexistent", "--key-file", "/k", "--transport", "uhid", "--wire", "/w"],
        &["run", "--state", "/nonexistent", "--key-file", "/k", "--udc", "dummy_udc.0"],
        &["run", "--state", "/nonexistent", "--key-file", "/k", "--transport", "wire,vpcd"],
        &["run", "--state", "/nonexistent", "--key-file", "/k", "--transport", "uhid,uhid"],
        &["run", "--state", "/nonexistent", "--key-file", "/k", "--transport", "uhid,vpcd,gadget"],
        &["run", "--state", "/nonexistent", "--key-file", "/k", "--transport", "uhid,"],
        &["run", "--state", "/nonexistent", "--key-file", "/k", "--transport", "vpcd", "--wire", "/w"],
        &["run", "--state", "/nonexistent", "--key-file", "/k", "--vpcd-addr", "127.0.0.1:35963"],
        &["run", "--state", "/nonexistent", "--key-file", "/k", "--transport", "vpcd", "--vpcd-addr", "nowhere"],
        &["ctl", "--control", "/nonexistent", "shutdown", "now"],
    ] {
        let output = localkeyd(args.iter().copied())?;
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        let stderr = text(&output.stderr);
        assert!(stderr.starts_with("localkeyd: ") && stderr.contains("usage:"), "{args:?}: {stderr}");
    }
    let output = localkeyd(["--help"])?;
    assert_eq!(output.status.code(), Some(0));
    assert!(text(&output.stdout).contains("localkeyd run --state DIR"));
    Ok(())
}

#[test]
fn a_missing_key_file_is_a_startup_failure() -> TestResult {
    let dir = TestDir::new();
    let mut daemon = Daemon::spawn(&dir, &["--key-file", "/nonexistent/key"])?;
    let status = daemon.wait_exit()?;
    assert_eq!(status.code(), Some(2), "{}", daemon.log());
    assert!(daemon.log().contains("storage key: /nonexistent/key"), "{}", daemon.log());
    Ok(())
}

#[test]
fn ctl_without_a_daemon_fails_with_code_1() -> TestResult {
    let dir = TestDir::new();
    let output = ctl(&dir.control(), &["status"])?;
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).contains("control.sock"), "{}", text(&output.stderr));
    Ok(())
}

#[test]
fn keygen_writes_a_private_key_file_and_never_overwrites_it() -> TestResult {
    use std::os::unix::fs::PermissionsExt;

    let dir = TestDir::new();
    keygen(&dir.key())?;
    let key = fs::read_to_string(dir.key())?;
    assert_eq!(key.len(), 65);
    assert!(key.ends_with('\n') && key.trim_end().bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(fs::metadata(dir.key())?.permissions().mode() & 0o777, 0o600);

    let output = localkeyd([std::ffi::OsString::from("keygen"), "--key-file".into(), dir.key().into()])?;
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).contains("never overwrites"), "{}", text(&output.stderr));
    assert_eq!(fs::read_to_string(dir.key())?, key, "the key file is unchanged");
    Ok(())
}

#[test]
fn keygen_print_writes_the_key_text_to_stdout() -> TestResult {
    let output = localkeyd(["keygen", "--print"])?;
    assert_eq!(output.status.code(), Some(0));
    let stdout = text(&output.stdout);
    assert_eq!(stdout.len(), 65);
    assert!(stdout.ends_with('\n') && stdout.trim_end().bytes().all(|byte| byte.is_ascii_hexdigit()));
    Ok(())
}

#[test]
fn a_state_directory_open_to_others_is_a_startup_failure() -> TestResult {
    use std::os::unix::fs::PermissionsExt;

    let dir = TestDir::new();
    keygen(&dir.key())?;
    fs::create_dir(dir.state())?;
    fs::set_permissions(dir.state(), fs::Permissions::from_mode(0o755))?;
    let key = dir.key();
    let mut daemon = Daemon::spawn(&dir, &["--key-file", key.to_str().ok_or("key path")?])?;
    assert_eq!(daemon.wait_exit()?.code(), Some(2), "{}", daemon.log());
    assert!(daemon.log().contains("chmod go-rwx"), "{}", daemon.log());
    assert_eq!(fs::read_dir(dir.state())?.count(), 0, "nothing was written into it");
    Ok(())
}

#[test]
fn the_wire_and_control_sockets_cannot_share_a_path() -> TestResult {
    let dir = TestDir::new();
    keygen(&dir.key())?;
    let key = dir.key();
    let socket = dir.join("one.sock");
    let socket = socket.to_str().ok_or("socket path")?;
    let args = ["--key-file", key.to_str().ok_or("key path")?, "--wire", socket, "--control", socket];
    let mut daemon = Daemon::spawn(&dir, &args)?;
    assert_eq!(daemon.wait_exit()?.code(), Some(2), "{}", daemon.log());
    assert!(daemon.log().contains("cannot share the path"), "{}", daemon.log());
    assert!(!dir.state().exists(), "refused before the state directory was opened");
    Ok(())
}

#[test]
fn two_spellings_of_one_socket_file_are_refused() -> TestResult {
    let dir = TestDir::new();
    keygen(&dir.key())?;
    let key = dir.key();
    let wire = dir.join("one.sock");
    // `s/..` (the state directory exists once the daemon has opened it) and `l` (a link
    // to the test directory) name the test directory, so both name the file `wire` names.
    std::os::unix::fs::symlink(".", dir.join("l"))?;
    let spellings = [dir.state().join("..").join("one.sock"), dir.join("l").join("one.sock")];
    for control in spellings {
        let args = [
            "--key-file",
            key.to_str().ok_or("key path")?,
            "--wire",
            wire.to_str().ok_or("wire path")?,
            "--control",
            control.to_str().ok_or("control path")?,
        ];
        let mut daemon = Daemon::spawn(&dir, &args)?;
        if daemon.wait_serving().is_ok() {
            let output = ctl(&control, &["status"])?;
            panic!(
                "the daemon serves with both sockets on one file; `ctl status` on {} exited {:?} with {:?}\n{}",
                control.display(),
                output.status.code(),
                text(&output.stderr),
                daemon.log()
            );
        }
        assert_eq!(daemon.wait_exit()?.code(), Some(2), "{}", daemon.log());
        assert!(daemon.log().contains("are the same file"), "{}", daemon.log());
        assert!(!wire.exists(), "no socket was bound: {}", daemon.log());
    }
    Ok(())
}

#[test]
fn a_wire_socket_that_cannot_be_placed_leaves_no_control_socket() -> TestResult {
    use std::os::unix::fs::PermissionsExt;

    let dir = TestDir::new();
    keygen(&dir.key())?;
    let open = dir.join("o");
    fs::create_dir(&open)?;
    fs::set_permissions(&open, fs::Permissions::from_mode(0o755))?;
    let wire = open.join("w.sock");
    let key = dir.key();
    let args = ["--key-file", key.to_str().ok_or("key path")?, "--wire", wire.to_str().ok_or("wire path")?];
    let mut daemon = Daemon::spawn(&dir, &args)?;
    assert_eq!(daemon.wait_exit()?.code(), Some(2), "{}", daemon.log());
    assert!(daemon.log().contains("wire socket"), "{}", daemon.log());
    assert!(!dir.control().exists(), "the control socket was removed: {}", daemon.log());
    assert!(!wire.exists());
    Ok(())
}

#[test]
fn ctl_against_a_socket_no_daemon_listens_on_fails_with_code_1() -> TestResult {
    let dir = TestDir::new();
    let stale = dir.join("c.sock");
    drop(std::os::unix::net::UnixListener::bind(&stale)?);
    assert!(stale.exists());
    let output = ctl(&stale, &["status"])?;
    assert_eq!(output.status.code(), Some(1), "{}", text(&output.stderr));
    assert!(text(&output.stderr).contains("c.sock"), "{}", text(&output.stderr));
    Ok(())
}

#[test]
fn leftover_sockets_of_a_killed_daemon_are_replaced_at_start() -> TestResult {
    let dir = TestDir::new();
    keygen(&dir.key())?;
    let mut first = Daemon::with_key(&dir, &[])?;
    first.kill()?;
    assert!(dir.control().exists() && dir.wire().exists());
    let _second = Daemon::with_key(&dir, &[])?;
    let output = ctl(&dir.control(), &["status"])?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    Ok(())
}

#[test]
fn help_after_a_command_prints_the_usage() -> TestResult {
    for args in [&["run", "--state", "/s", "--key-file", "/k", "help"][..], &["ctl", "--control", "/c", "help"], &["keygen", "help"]] {
        let output = localkeyd(args.iter().copied())?;
        assert_eq!(output.status.code(), Some(0), "{args:?}: {}", text(&output.stderr));
        assert!(text(&output.stdout).contains("usage:"), "{args:?}");
    }
    Ok(())
}

/// `--transport uhid` and `--transport gadget` on a system other than Linux: exit 2 with a
/// message naming the reason, before the state directory is opened (`docs/PROGRAM.md`
/// "Linux transports": `localkeyd` refuses to start them elsewhere). Not built on Linux,
/// where the same command lines would start the transports. The paths given point into
/// the test directory anyway, so even a refusal that failed would touch no device and no
/// ConfigFS: a missing key file stops the daemon right after the state directory.
#[cfg(not(target_os = "linux"))]
#[test]
fn the_linux_transports_are_refused_elsewhere_before_the_state_directory_is_touched() -> TestResult {
    let dir = TestDir::new();
    let missing_key = dir.join("no-key");
    let missing_key = missing_key.to_str().ok_or("key path")?;
    let uhid = dir.join("uhid");
    let configfs = dir.join("cfg");
    let ffs = dir.join("ffs");
    let uhid = uhid.to_str().ok_or("uhid path")?;
    let lines = [
        vec!["--key-file", missing_key, "--transport", "uhid", "--uhid-path", uhid],
        vec![
            "--key-file",
            missing_key,
            "--transport",
            "gadget",
            "--udc",
            "dummy_udc.0",
            "--configfs",
            configfs.to_str().ok_or("configfs path")?,
            "--ffs-dir",
            ffs.to_str().ok_or("ffs path")?,
            "-vv",
        ],
        // `docs/PROGRAM.md` "Transport combinations": uhid in the set still needs Linux.
        vec!["--key-file", missing_key, "--transport", "vpcd,uhid", "--uhid-path", uhid, "--vpcd-addr", "127.0.0.1:1"],
    ];
    for (args, transport) in lines.iter().zip(["uhid", "gadget", "uhid,vpcd: uhid"]) {
        let mut daemon = Daemon::spawn(&dir, args)?;
        let status = daemon.wait_exit()?;
        assert_eq!(status.code(), Some(2), "{}", daemon.log());
        let os = std::env::consts::OS;
        let expected = format!("localkeyd: --transport {transport} runs on Linux only, and this system is {os}");
        assert!(daemon.log().contains(&expected), "{}", daemon.log());
        assert!(!daemon.log().contains("storage key"), "refused before the key was loaded: {}", daemon.log());
        assert!(!dir.state().exists(), "the state directory was not created");
        assert_eq!(fs::read_dir(dir.join("."))?.count(), 0, "nothing was created in the test directory");
    }
    Ok(())
}
