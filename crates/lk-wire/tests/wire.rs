//! The wire transport over real sockets in private temporary directories, with a fake
//! runner (`docs/PROGRAM.md` "lk-wire": "Socket placement", "Connection semantics",
//! "Client library").
//!
//! The test thread plays the runner thread: it calls `enumerate` and `deliver` directly.

mod common;

use std::fs;
use std::io::Write;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use common::*;
use lk_core::UsbInterfaces;
use lk_device::{BusEvent, Output, TouchEdge};
use lk_run::{Command, HostInput, Status, Transport};
use lk_wire::{
    Client, Frame, INPUT_WINDOW_BYTES, INPUT_WINDOW_FRAMES, Identity, MAX_LENGTH, WRITE_QUEUE_FRAMES, WireError, WireEvent,
    WireTransport,
};

const POWER_CYCLE: HostInput = HostInput::Bus(BusEvent::PowerCycle);

/// A bound and enumerated transport, as the runner leaves it after `serve`.
fn served(dir: &TestDir, runner: &FakeRunner) -> Result<WireTransport, WireError> {
    let mut transport = WireTransport::bind(&dir.join("w"), runner.sender())?;
    transport.enumerate(&usb_identity(None));
    Ok(transport)
}

/// Connect with the client library and take the power cycle the connection delivers.
fn plug_in(transport: &WireTransport, runner: &FakeRunner) -> Result<Client, WireError> {
    let client = Client::connect(transport.path())?;
    assert_eq!(runner.input(), POWER_CYCLE);
    Ok(client)
}

fn expect_frame(client: &mut Client) -> Result<Frame, WireError> {
    client.recv(WAIT)?.ok_or(WireError::Timeout)
}

/// Queue 2 MB of CCID responses: more than both socket buffers hold on macOS and Linux, in
/// far fewer frames than the write queue holds. The writer blocks on a client that does not
/// read, and the client is not dropped for being slow.
fn queue_more_than_the_socket_holds(transport: &mut WireTransport) {
    for _ in 0..10 {
        transport.deliver(Output::Ccid(vec![0; 200_000]));
    }
}

#[test]
fn identity_is_the_first_frame_of_a_connection() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let transport = served(&dir, &runner)?;
    let mut stream = raw_connect(transport.path())?;
    let expected = Frame::Identity(Identity::from_usb(&usb_identity(None))).encode()?;
    assert_eq!(read_raw_frame(&mut stream)?, expected);
    assert_eq!(expected[4], 0x80);
    Ok(())
}

#[test]
fn connecting_powers_the_key() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let transport = served(&dir, &runner)?;
    let client = Client::connect(transport.path())?;
    assert_eq!(client.identity(), &Identity::from_usb(&usb_identity(None)));
    assert_eq!(runner.input(), POWER_CYCLE);
    runner.assert_quiet();
    Ok(())
}

#[test]
fn every_host_frame_reaches_the_runner_as_its_input() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let transport = served(&dir, &runner)?;
    let mut client = plug_in(&transport, &runner)?;
    let inputs = [
        HostInput::FidoReport([0xA5; 64]),
        HostInput::OtpSetFeature([1, 2, 3, 4, 5, 6, 7, 8]),
        HostInput::OtpGetFeature,
        HostInput::Ccid(vec![0x62, 0, 0, 0, 0, 0, 1, 0, 0, 0]),
        HostInput::CcidControlAbort { slot: 0, seq: 9 },
        HostInput::Touch(TouchEdge::Down),
        HostInput::Touch(TouchEdge::Up),
        HostInput::Bus(BusEvent::Reset),
        HostInput::Bus(BusEvent::Suspend),
        HostInput::Bus(BusEvent::Resume),
        HostInput::Bus(BusEvent::PowerCycle),
    ];
    for input in &inputs {
        client.send(input)?;
    }
    for input in inputs {
        assert_eq!(runner.input(), input);
    }
    Ok(())
}

#[test]
fn a_ccid_message_the_format_cannot_carry_is_not_sent() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let transport = served(&dir, &runner)?;
    let mut client = plug_in(&transport, &runner)?;
    assert!(matches!(client.send(&HostInput::Ccid(vec![0x62; 9])), Err(WireError::Frame(_))));
    runner.assert_quiet();
    assert_eq!(transport.attached(), Some(true));
    Ok(())
}

#[test]
fn every_output_arrives_as_its_frame() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let mut transport = served(&dir, &runner)?;
    let mut client = plug_in(&transport, &runner)?;
    let outputs = [
        (Output::FidoReport([0x5A; 64]), Frame::FidoIn([0x5A; 64])),
        (Output::OtpFeature([1; 8]), Frame::OtpFeature([1; 8])),
        (Output::OtpKeyboard([2; 8]), Frame::OtpKeyboard([2; 8])),
        (
            Output::Ccid(vec![0x80, 2, 0, 0, 0, 0, 1, 0, 0, 0, 0x90, 0]),
            Frame::CcidBulkIn(vec![0x80, 2, 0, 0, 0, 0, 1, 0, 0, 0, 0x90, 0]),
        ),
        (Output::CcidInterrupt(vec![0x50, 0x03]), Frame::CcidInterrupt(vec![0x50, 0x03])),
        (Output::PresenceIndicator(true), Frame::Presence(true)),
        (Output::PresenceIndicator(false), Frame::Presence(false)),
    ];
    for (output, _) in &outputs {
        transport.deliver(output.clone());
    }
    for (_, frame) in outputs {
        assert_eq!(expect_frame(&mut client)?, frame);
    }
    // `Reenumerate` never reaches `deliver` from the runner; if it did, it has no frame.
    transport.deliver(Output::Reenumerate(UsbInterfaces { otp: false, fido: true, ccid: false }));
    transport.deliver(Output::PresenceIndicator(true));
    assert_eq!(expect_frame(&mut client)?, Frame::Presence(true));
    Ok(())
}

#[test]
fn a_re_enumeration_sends_a_new_identity_without_a_power_cycle() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let mut transport = served(&dir, &runner)?;
    let mut client = plug_in(&transport, &runner)?;
    let mut changed = usb_identity(Some("12345678"));
    changed.product_id = 0x0402;
    changed.interfaces = UsbInterfaces { otp: false, fido: true, ccid: false };
    transport.enumerate(&changed);
    assert_eq!(expect_frame(&mut client)?, Frame::Identity(Identity::from_usb(&changed)));
    assert_eq!(client.identity().serial.as_deref(), Some("12345678"));
    assert_eq!(client.identity().product_id, 0x0402);
    runner.assert_quiet();
    // A new connection is presented with the new identity.
    drop(client);
    eventually("the disconnect", || transport.attached() == Some(false));
    let client = plug_in(&transport, &runner)?;
    assert_eq!(client.identity(), &Identity::from_usb(&changed));
    Ok(())
}

#[test]
fn a_client_that_connects_before_the_first_enumeration_waits_for_it() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let mut transport = WireTransport::bind(&dir.join("w"), runner.sender())?;
    let mut stream = raw_connect(transport.path())?;
    stream.set_read_timeout(Some(QUIET))?;
    assert!(read_raw_frame(&mut stream).is_err(), "nothing before the device is presented");
    runner.assert_quiet();
    transport.enumerate(&usb_identity(None));
    stream.set_read_timeout(Some(WAIT))?;
    assert_eq!(read_raw_frame(&mut stream)?, Frame::Identity(Identity::from_usb(&usb_identity(None))).encode()?);
    assert_eq!(runner.input(), POWER_CYCLE);
    Ok(())
}

#[test]
fn a_second_client_is_told_busy_and_the_first_is_unaffected() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let mut transport = served(&dir, &runner)?;
    let mut first = plug_in(&transport, &runner)?;

    match Client::connect(transport.path()) {
        Err(WireError::Refused(reason)) => assert_eq!(reason, "busy"),
        other => panic!("expected busy, got {other:?}"),
    }
    let mut second = raw_connect(transport.path())?;
    assert_eq!(read_raw_frame(&mut second)?, [0, 0, 0, 5, 0xFF, b'b', b'u', b's', b'y']);
    assert_closed(&mut second);
    runner.assert_quiet();

    assert_eq!(transport.attached(), Some(true));
    first.send(&HostInput::Touch(TouchEdge::Down))?;
    assert_eq!(runner.input(), HostInput::Touch(TouchEdge::Down));
    transport.deliver(Output::PresenceIndicator(true));
    assert_eq!(expect_frame(&mut first)?, Frame::Presence(true));
    Ok(())
}

#[test]
fn a_malformed_frame_gets_an_error_and_a_close_and_never_reaches_the_runner() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let transport = served(&dir, &runner)?;
    let mut fido_short = vec![0, 0, 0, 64, 0x01];
    fido_short.extend_from_slice(&[0; 63]);
    let mut fido_in = vec![0, 0, 0, 65, 0x81];
    fido_in.extend_from_slice(&[0; 64]);
    let over = (MAX_LENGTH + 1).to_be_bytes();
    let cases: [(&str, Vec<u8>); 7] = [
        ("unknown frame type 0x08", vec![0, 0, 0, 1, 0x08]),
        ("frame type 0x01 cannot carry a 63-byte payload", fido_short),
        ("frame length 0 is outside 1..=1048577", vec![0, 0, 0, 0]),
        ("frame length 1048578 is outside 1..=1048577", over.to_vec()),
        ("unknown frame type 0x81", fido_in),
        ("frame type 0x06 has no value 0x02", vec![0, 0, 0, 2, 0x06, 0x02]),
        ("frame type 0x04 cannot carry a 9-byte payload", vec![0, 0, 0, 10, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
    ];
    for (reason, bytes) in cases {
        let mut stream = raw_connect(transport.path())?;
        assert_eq!(read_raw_frame(&mut stream)?[4], 0x80);
        assert_eq!(runner.input(), POWER_CYCLE);
        stream.write_all(&bytes)?;
        let error = read_raw_frame(&mut stream)?;
        assert_eq!(error[4], 0xFF);
        assert_eq!(std::str::from_utf8(&error[5..])?, reason);
        assert_closed(&mut stream);
        assert_eq!(transport.attached(), Some(false));
        runner.assert_quiet();
    }
    Ok(())
}

#[test]
fn frames_before_a_malformed_one_are_delivered_and_nothing_after_it() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let transport = served(&dir, &runner)?;
    let mut stream = raw_connect(transport.path())?;
    read_raw_frame(&mut stream)?;
    assert_eq!(runner.input(), POWER_CYCLE);
    let mut bytes = Frame::Touch(TouchEdge::Down).encode()?;
    bytes.extend_from_slice(&[0, 0, 0, 1, 0x7F]);
    bytes.extend_from_slice(&Frame::Touch(TouchEdge::Up).encode()?);
    stream.write_all(&bytes)?;
    assert_eq!(read_raw_frame(&mut stream)?[4], 0xFF);
    assert_closed(&mut stream);
    assert_eq!(runner.input(), HostInput::Touch(TouchEdge::Down));
    runner.assert_quiet();
    Ok(())
}

/// "A malformed frame ... gets `ERROR` with the reason and the connection is closed": also
/// for a client that stopped reading while its writer was blocked. Its writer gets a bounded
/// time to flush, so it cannot keep the thread and the socket.
#[test]
fn a_malformed_frame_closes_even_a_client_that_does_not_read() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let mut transport = served(&dir, &runner)?;
    let mut stream = raw_connect(transport.path())?;
    assert_eq!(runner.input(), POWER_CYCLE);
    queue_more_than_the_socket_holds(&mut transport);
    assert_eq!(transport.attached(), Some(true));
    stream.write_all(&[0, 0, 0, 1, 0x08])?;
    eventually("the malformed frame to drop the client", || transport.attached() == Some(false));
    eventually("the server to shut the connection down", || server_closed(&mut stream));
    runner.assert_quiet();
    Ok(())
}

#[test]
fn dropping_the_transport_closes_a_client_whose_error_is_still_being_written() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let mut transport = served(&dir, &runner)?;
    let mut stream = raw_connect(transport.path())?;
    assert_eq!(runner.input(), POWER_CYCLE);
    queue_more_than_the_socket_holds(&mut transport);
    stream.write_all(&[0, 0, 0, 1, 0x08])?;
    eventually("the malformed frame to drop the client", || transport.attached() == Some(false));
    drop(transport);
    eventually("the server to shut the connection down", || server_closed(&mut stream));
    Ok(())
}

#[test]
fn a_client_that_reads_gets_what_was_queued_before_its_malformed_frame_then_the_error() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let mut transport = served(&dir, &runner)?;
    let mut stream = raw_connect(transport.path())?;
    assert_eq!(read_raw_frame(&mut stream)?[4], 0x80);
    assert_eq!(runner.input(), POWER_CYCLE);
    // Enough to block the writer, little enough to read well within the one-second flush.
    for _ in 0..3 {
        transport.deliver(Output::Ccid(vec![0; 200_000]));
    }
    stream.write_all(&[0, 0, 0, 1, 0x08])?;
    for _ in 0..3 {
        let frame = read_raw_frame(&mut stream)?;
        assert_eq!((frame[4], frame.len()), (0x84, 5 + 200_000));
    }
    let error = read_raw_frame(&mut stream)?;
    assert_eq!(error[4], 0xFF);
    assert_eq!(std::str::from_utf8(&error[5..])?, "unknown frame type 0x08");
    assert_closed(&mut stream);
    assert_eq!(transport.attached(), Some(false));
    Ok(())
}

#[test]
fn a_client_can_reconnect_after_disconnecting() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let mut transport = served(&dir, &runner)?;
    for _ in 0..3 {
        let mut client = plug_in(&transport, &runner)?;
        assert_eq!(transport.attached(), Some(true));
        client.send(&HostInput::OtpGetFeature)?;
        assert_eq!(runner.input(), HostInput::OtpGetFeature);
        transport.deliver(Output::OtpFeature([7; 8]));
        assert_eq!(expect_frame(&mut client)?, Frame::OtpFeature([7; 8]));
        drop(client);
        eventually("the disconnect", || transport.attached() == Some(false));
    }
    Ok(())
}

#[test]
fn outputs_without_a_client_are_dropped() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let mut transport = WireTransport::bind(&dir.join("w"), runner.sender())?;
    transport.deliver(Output::PresenceIndicator(true));
    transport.enumerate(&usb_identity(None));
    transport.deliver(Output::FidoReport([1; 64]));
    transport.deliver(Output::Ccid(vec![0x80; 10]));
    assert_eq!(transport.attached(), Some(false));
    let mut client = plug_in(&transport, &runner)?;
    assert_eq!(client.recv(QUIET)?, None, "nothing from before the plug-in");
    transport.deliver(Output::PresenceIndicator(false));
    assert_eq!(expect_frame(&mut client)?, Frame::Presence(false));
    Ok(())
}

#[test]
fn a_client_that_stops_reading_is_dropped_instead_of_blocking_the_runner() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let mut transport = served(&dir, &runner)?;
    let _client = plug_in(&transport, &runner)?;
    let started = Instant::now();
    // Far more than the queue and both socket buffers hold.
    for _ in 0..WRITE_QUEUE_FRAMES * 8 {
        transport.deliver(Output::FidoReport([0xEE; 64]));
    }
    assert!(started.elapsed() < WAIT, "deliver did not wait for the client");
    assert_eq!(transport.attached(), Some(false));
    Ok(())
}

#[test]
fn dropping_the_transport_removes_the_socket_and_disconnects_the_client() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let transport = served(&dir, &runner)?;
    let path = transport.path().to_owned();
    let mut client = plug_in(&transport, &runner)?;
    drop(transport);
    assert!(!path.exists());
    assert!(matches!(client.recv(WAIT), Err(WireError::Closed)));
    // A transport that never enumerated also cleans up.
    let transport = WireTransport::bind(&path, runner.sender())?;
    assert!(path.exists());
    drop(transport);
    assert!(!path.exists());
    Ok(())
}

/// Two transports given the same path (a misconfiguration): the second replaces the first's
/// socket. Dropping the first must neither plug a client into the second (its accept thread
/// is woken through the path) nor wait for an accept thread nobody can reach any more: the
/// drop runs on the runner thread, so a hang there wedges the daemon's shutdown.
#[test]
fn dropping_a_transport_whose_path_was_taken_over_leaves_the_new_one_alone() -> TestResult {
    let dir = TestDir::new();
    let path = dir.join("w");
    let first_runner = FakeRunner::plain();
    let second_runner = FakeRunner::plain();
    let mut first = WireTransport::bind(&path, first_runner.sender())?;
    first.enumerate(&usb_identity(None));
    let mut second = WireTransport::bind(&path, second_runner.sender())?;
    second.enumerate(&usb_identity(None));

    assert!(drops_in_time(first), "dropping the first transport hung");
    second_runner.assert_quiet();
    assert!(fs::symlink_metadata(&path)?.file_type().is_socket(), "the second transport's socket is kept");
    plug_in(&second, &second_runner)?;
    Ok(())
}

/// "The socket file is removed again on clean shutdown" means the server's own file, not
/// whatever socket is at the path by then.
#[test]
fn dropping_a_transport_keeps_the_socket_that_replaced_its_own() -> TestResult {
    let dir = TestDir::new();
    let path = dir.join("w");
    let first_runner = FakeRunner::plain();
    let second_runner = FakeRunner::plain();
    // Never enumerated, so no accept thread: only the removal is at stake.
    let first = WireTransport::bind(&path, first_runner.sender())?;
    let mut second = WireTransport::bind(&path, second_runner.sender())?;
    second.enumerate(&usb_identity(None));
    drop(first);
    assert!(path.exists(), "the second transport's live socket was removed by the first one's drop");
    plug_in(&second, &second_runner)?;
    Ok(())
}

/// Once the server has closed the connection completely, macOS refuses to set a read
/// timeout on the client's socket. `recv` still returns the frames that arrived, then
/// `Closed`.
#[test]
fn recv_after_the_server_closed_returns_what_arrived_then_closed() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let mut transport = served(&dir, &runner)?;
    let mut client = plug_in(&transport, &runner)?;
    transport.deliver(Output::PresenceIndicator(true));
    thread::sleep(QUIET);
    drop(transport);
    thread::sleep(QUIET);
    assert_eq!(client.recv(WAIT)?, Some(Frame::Presence(true)));
    assert!(matches!(client.recv(WAIT), Err(WireError::Closed)));
    Ok(())
}

#[test]
fn the_socket_file_is_private_to_its_owner() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let transport = served(&dir, &runner)?;
    let meta = fs::symlink_metadata(transport.path())?;
    assert!(meta.file_type().is_socket());
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    Ok(())
}

#[test]
fn an_existing_file_at_the_socket_path_is_an_error_and_is_kept() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let path = dir.join("w");
    fs::write(&path, b"not a socket")?;
    match WireTransport::bind(&path, runner.sender()) {
        Err(WireError::NotASocket { path: reported }) => assert_eq!(reported, path),
        other => panic!("expected NotASocket, got {other:?}"),
    }
    assert_eq!(fs::read(&path)?, b"not a socket");

    let directory = dir.join("d");
    fs::create_dir(&directory)?;
    assert!(matches!(WireTransport::bind(&directory, runner.sender()), Err(WireError::NotASocket { .. })));
    assert!(directory.is_dir());

    // A symlink is not followed, even to a socket.
    let socket = dir.join("s");
    let _listener = UnixListener::bind(&socket)?;
    let link = dir.join("l");
    std::os::unix::fs::symlink(&socket, &link)?;
    assert!(matches!(WireTransport::bind(&link, runner.sender()), Err(WireError::NotASocket { .. })));
    assert!(fs::symlink_metadata(&link)?.file_type().is_symlink());
    Ok(())
}

#[test]
fn a_leftover_socket_at_the_path_is_replaced() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let path = dir.join("w");
    drop(UnixListener::bind(&path)?);
    assert!(UnixStream::connect(&path).is_err(), "nobody listens on the leftover socket");
    let mut transport = WireTransport::bind(&path, runner.sender())?;
    transport.enumerate(&usb_identity(None));
    plug_in(&transport, &runner)?;
    Ok(())
}

#[test]
fn a_parent_directory_with_group_or_other_access_is_refused() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    for mode in [0o750, 0o705, 0o770, 0o755, 0o701] {
        dir.set_mode(mode);
        match WireTransport::bind(&dir.join("w"), runner.sender()) {
            Err(WireError::Permissions { path, mode: reported }) => {
                assert_eq!(path, dir.path());
                assert_eq!(reported, mode);
            }
            other => panic!("expected a permissions error for {mode:o}, got {other:?}"),
        }
        assert!(dir.path().is_dir());
        assert!(!dir.join("w").exists(), "no socket is created");
    }
    dir.set_mode(0o700);
    assert!(WireTransport::bind(&dir.join("w"), runner.sender()).is_ok());
    Ok(())
}

#[test]
fn a_missing_parent_directory_is_refused() {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let path = dir.join("m").join("w");
    assert!(matches!(WireTransport::bind(&path, runner.sender()), Err(WireError::Io { .. })));
    assert!(!dir.join("m").exists());
}

#[test]
fn the_observer_sees_connections_enumerations_and_frame_sizes() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let events = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&events);
    let observer: lk_wire::Observer =
        Arc::new(move |event: &WireEvent| log.lock().expect("the event log is not poisoned").push(event.clone()));
    let mut transport = WireTransport::bind_with_observer(&dir.join("w"), runner.sender(), Some(observer))?;
    transport.enumerate(&usb_identity(None));
    let mut client = plug_in(&transport, &runner)?;
    client.send(&HostInput::Touch(TouchEdge::Down))?;
    assert_eq!(runner.input(), HostInput::Touch(TouchEdge::Down));
    assert!(matches!(Client::connect(transport.path()), Err(WireError::Refused(_))));
    transport.deliver(Output::PresenceIndicator(true));
    assert_eq!(expect_frame(&mut client)?, Frame::Presence(true));
    drop(client);
    eventually("the disconnect", || transport.attached() == Some(false));

    let events = events.lock().expect("the event log is not poisoned").clone();
    let identity_size = Identity::from_usb(&usb_identity(None)).encode()?.len();
    let all = UsbInterfaces { otp: true, fido: true, ccid: true };
    assert_eq!(
        events,
        [
            WireEvent::Enumerated { product_id: 0x0407, interfaces: all },
            WireEvent::Connected,
            WireEvent::Sent { frame_type: 0x80, size: identity_size },
            WireEvent::Received { frame_type: 0x06, size: 1 },
            WireEvent::Refused,
            WireEvent::Sent { frame_type: 0x86, size: 1 },
            WireEvent::Disconnected,
        ]
    );
    assert_eq!(events[0].to_string(), "wire: enumerated as product 0x0407 (otp,fido,ccid)");
    assert_eq!(events[3].to_string(), "wire: <- 0x06, 1 bytes");
    Ok(())
}

#[test]
fn recv_with_the_longest_timeout_waits_without_a_deadline() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let mut transport = served(&dir, &runner)?;
    let mut client = plug_in(&transport, &runner)?;
    let late = thread::spawn(move || {
        thread::sleep(Duration::from_millis(200));
        transport.deliver(Output::PresenceIndicator(true));
        transport
    });
    assert_eq!(client.recv(Duration::MAX)?, Some(Frame::Presence(true)));
    let transport = late.join().map_err(|_| "the delivering thread panicked")?;
    assert_eq!(transport.attached(), Some(true));
    Ok(())
}

#[test]
fn connect_with_the_longest_timeout_waits_without_a_deadline() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let transport = served(&dir, &runner)?;
    let client = Client::connect_timeout(transport.path(), Duration::MAX)?;
    assert_eq!(client.identity(), &Identity::from_usb(&usb_identity(None)));
    assert_eq!(runner.input(), POWER_CYCLE);
    Ok(())
}

#[test]
fn recv_returns_none_when_nothing_arrives_in_time() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let transport = served(&dir, &runner)?;
    let mut client = plug_in(&transport, &runner)?;
    let started = Instant::now();
    assert_eq!(client.recv(Duration::from_millis(100))?, None);
    assert!(started.elapsed() >= Duration::from_millis(100));
    assert_eq!(transport.attached(), Some(true));
    Ok(())
}

/// The next command the transport sent to a runner the test plays by hand.
fn command(commands: &Receiver<Command>) -> Command {
    commands.recv_timeout(WAIT).expect("the transport sends a command in time")
}

/// The next command must be `Command::Input(expected)`.
fn assert_input(commands: &Receiver<Command>, expected: &HostInput) {
    match command(commands) {
        Command::Input(input) => assert_eq!(&input, expected),
        other => panic!("expected {expected:?}, the runner got {other:?}"),
    }
}

/// The next command must be a `Command::Status` marker; its reply channel.
fn marker(commands: &Receiver<Command>) -> Sender<Status> {
    match command(commands) {
        Command::Status(reply) => reply,
        other => panic!("expected a Status marker, the runner got {other:?}"),
    }
}

/// Nothing reaches the runner for [`QUIET`].
fn assert_no_command(commands: &Receiver<Command>) {
    if let Ok(command) = commands.recv_timeout(QUIET) {
        panic!("the runner unexpectedly got {command:?}");
    }
}

/// A client sends three windows of `input` (`window` frames each) as fast as it can, from
/// its own thread, while the test plays a runner that answers markers only when told: the
/// reader sends a window, its marker and the next window, then waits for the first answer
/// before it sends anything more.
fn assert_paced(input: HostInput, window: usize) -> TestResult {
    let dir = TestDir::new();
    let (sender, commands) = mpsc::channel();
    let mut transport = WireTransport::bind(&dir.join("w"), sender)?;
    transport.enumerate(&usb_identity(None));
    let mut client = Client::connect(transport.path())?;
    assert_input(&commands, &POWER_CYCLE);
    let sent = input.clone();
    let flood = thread::spawn(move || -> Result<Client, WireError> {
        for _ in 0..3 * window {
            client.send(&sent)?;
        }
        Ok(client)
    });
    let inputs = |count: usize| (0..count).for_each(|_| assert_input(&commands, &input));

    inputs(window);
    let first = marker(&commands);
    inputs(window);
    assert_no_command(&commands);

    first.send(status())?;
    let second = marker(&commands);
    inputs(window);
    assert_no_command(&commands);

    second.send(status())?;
    let _third = marker(&commands);
    assert_no_command(&commands);
    let _client = flood.join().map_err(|_| "the flooding client panicked")??;
    Ok(())
}

#[test]
fn a_flooding_client_is_held_to_the_runners_pace() -> TestResult {
    assert_paced(HostInput::Touch(TouchEdge::Down), INPUT_WINDOW_FRAMES)
}

#[test]
fn large_frames_are_paced_by_their_size() -> TestResult {
    let size = 100_000;
    assert_paced(HostInput::Ccid(vec![0x6F; size]), INPUT_WINDOW_BYTES.div_ceil(size))
}

#[test]
fn a_long_stream_reaches_a_runner_that_keeps_up_in_full_and_in_order() -> TestResult {
    let dir = TestDir::new();
    let runner = FakeRunner::plain();
    let transport = served(&dir, &runner)?;
    let mut client = plug_in(&transport, &runner)?;
    let count = 10 * INPUT_WINDOW_FRAMES + 3;
    let input = |n: usize| HostInput::CcidControlAbort { slot: 0, seq: n as u8 };
    let sender = thread::spawn(move || -> Result<Client, WireError> {
        for n in 0..count {
            client.send(&input(n))?;
        }
        Ok(client)
    });
    let mut markers = 0;
    let mut received = 0;
    while received < count {
        match runner.next() {
            Seen::Input(got) => {
                assert_eq!(got, input(received));
                received += 1;
            }
            Seen::Status => markers += 1,
            other => panic!("the runner unexpectedly saw {other:?}"),
        }
    }
    assert_eq!(markers, count / INPUT_WINDOW_FRAMES, "one marker per full window");
    let _client = sender.join().map_err(|_| "the sending client panicked")??;
    Ok(())
}
