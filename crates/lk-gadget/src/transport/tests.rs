use std::io::{self, Write};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use lk_core::UsbInterfaces;
use lk_run::{Command, HostInput, Status};

use super::*;
use crate::test_support::TestDir;

/// Records every write call.
#[derive(Debug, Default)]
struct Writes(Vec<usize>);

impl Write for Writes {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.push(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_bulk_message_that_fills_whole_packets_is_followed_by_a_zero_length_write() {
    for (length, expected) in [(64, vec![64, 0]), (128, vec![128, 0]), (65, vec![65]), (10, vec![10])] {
        let mut writes = Writes::default();
        write_item(&mut writes, &vec![0; length], Some(64)).expect("written");
        assert_eq!(writes.0, expected, "{length} bytes");
    }
}

#[test]
fn interrupt_reports_get_no_zero_length_write() {
    let mut writes = Writes::default();
    write_item(&mut writes, &[0; 64], None).expect("written");
    write_item(&mut writes, &[0; 8], None).expect("written");
    assert_eq!(writes.0, [64, 8]);
}

fn config(root: &Path) -> GadgetConfig {
    GadgetConfig {
        configfs_root: root.to_owned(),
        gadget_name: "lk".into(),
        function_name: "lkf".into(),
        mount_point: root.join("ffs"),
        udc: "dummy_udc.0".into(),
    }
}

#[test]
fn the_default_configuration_names_the_kernel_paths() {
    let config = GadgetConfig::new("dummy_udc.0");
    assert_eq!(config.configfs_root, Path::new("/sys/kernel/config/usb_gadget"));
    assert_eq!(config.gadget_name, "localkey");
    assert_eq!(config.function_name, "localkey");
    assert_eq!(config.mount_point, Path::new("/dev/ffs-localkey"), "as in Documentation/usb/functionfs.rst");
    assert_eq!(config.mount_point, default_mount_point(DEFAULT_NAME));
    assert!(config.check().is_ok());
}

#[test]
fn names_that_could_leave_their_directory_are_refused() {
    let dir = TestDir::new();
    for (gadget, function, udc) in [
        ("", "f", "u"),
        ("../x", "f", "u"),
        ("a.b", "f", "u"),
        ("g", "f/x", "u"),
        ("g", "f.x", "u"),
        ("g", &"f".repeat(33), "u"),
        ("g", "f", ""),
        ("g", "f", "u\nv"),
        ("g", "f", "a/b"),
    ] {
        let config = GadgetConfig {
            gadget_name: gadget.into(),
            function_name: function.into(),
            udc: udc.into(),
            ..config(dir.path())
        };
        let (runner, _commands) = mpsc::channel();
        let result = GadgetTransport::with_io(config, runner, Box::new(KernelIo), None);
        assert!(matches!(result, Err(GadgetError::Config(_))), "{gadget:?} {function:?} {udc:?}");
    }
}

#[test]
fn a_missing_root_or_a_gadget_directory_that_is_not_a_leftover_is_refused() {
    let dir = TestDir::new();
    let (runner, _commands) = mpsc::channel();
    let missing = config(&dir.path().join("missing"));
    assert!(matches!(
        GadgetTransport::with_io(missing, runner.clone(), Box::new(KernelIo), None),
        Err(GadgetError::Io { .. })
    ));
    let gadget = dir.path().join("lk");
    std::fs::create_dir_all(gadget.join("functions/hid.usb0")).expect("a directory");
    let error = GadgetTransport::with_io(config(dir.path()), runner, Box::new(KernelIo), None)
        .expect_err("another gadget is there");
    assert!(matches!(&error, GadgetError::Exists { path, .. } if path == &gadget));
    let text = error.to_string();
    assert!(text.contains("is not a leftover") && text.contains("hid.usb0"), "{text}");
    assert!(gadget.join("functions/hid.usb0").is_dir(), "left alone");
}

#[test]
fn a_leftover_gadget_directory_passes_the_precheck_which_changes_nothing() {
    let dir = TestDir::new();
    let gadget = dir.path().join("lk");
    std::fs::create_dir_all(gadget.join("functions/ffs.lkf")).expect("a directory");
    std::fs::write(gadget.join("UDC"), "\n").expect("UDC");
    let config = config(dir.path());
    config.precheck().expect("a leftover of this transport");
    assert!(gadget.join("functions/ffs.lkf").is_dir() && gadget.join("UDC").is_file(), "nothing removed yet");
    let (runner, _commands) = mpsc::channel();
    assert!(GadgetTransport::with_io(config.clone(), runner, Box::new(KernelIo), None).is_ok());
    std::fs::write(gadget.join("UDC"), "dummy_udc.0\n").expect("UDC");
    let error = config.precheck().expect_err("a bound gadget is in use");
    assert!(error.to_string().contains("bound to dummy_udc.0"), "{error}");
}

#[test]
fn a_new_transport_creates_nothing_and_its_drop_removes_nothing() {
    let dir = TestDir::new();
    let (runner, _commands) = mpsc::channel();
    let transport = GadgetTransport::with_io(config(dir.path()), runner, Box::new(KernelIo), None).expect("valid");
    assert_eq!(transport.attached(), Some(false));
    assert!(format!("{transport:?}").contains("bound: false"));
    drop(transport);
    assert_eq!(std::fs::read_dir(dir.path()).expect("readable").count(), 0);
}

/// A runner that answers `OtpGetFeature` by delivering through `deliver` after `delay`,
/// then answers the `Status` marker, as `lk_run::Runner` does.
fn runner_answering(shared: Arc<Shared>, commands: mpsc::Receiver<Command>, delay: Duration, answers: Vec<[u8; 8]>) {
    thread::spawn(move || {
        let mut answers = answers.into_iter();
        for command in commands {
            match command {
                Command::Input(HostInput::OtpGetFeature) => {
                    thread::sleep(delay);
                    if let Some(answer) = answers.next() {
                        *shared.otp_feature() = Some(answer);
                    }
                }
                Command::Status(reply) => {
                    let _ = reply.send(status());
                }
                _ => {}
            }
        }
    });
}

fn status() -> Status {
    Status {
        serial: 1,
        product: String::new(),
        interfaces: UsbInterfaces { otp: true, fido: false, ccid: false },
        presence_pending: false,
        serving: true,
        attached: None,
        suspended: false,
        queued: 0,
        dropped: 0,
        unreadable: Vec::new(),
        uptime_ms: 0,
    }
}

fn shared_with(runner: mpsc::Sender<Command>) -> Arc<Shared> {
    Arc::new(Shared { runner, observer: None, otp_feature: Mutex::new(None) })
}

#[test]
fn an_otp_feature_answer_is_the_one_delivered_before_the_marker() {
    let (runner, commands) = mpsc::channel();
    let shared = shared_with(runner);
    runner_answering(Arc::clone(&shared), commands, Duration::ZERO, vec![[1; 8], [2; 8]]);
    let mut wait = OtpWait::default();
    assert_eq!(wait.fetch(&shared, &SessionState::default()), Some([1; 8]));
    assert_eq!(wait.fetch(&shared, &SessionState::default()), Some([2; 8]));
}

#[test]
fn a_late_otp_feature_answer_is_never_given_to_the_next_request() {
    let (runner, commands) = mpsc::channel();
    let shared = shared_with(runner);
    // The first answer takes longer than the timeout; the second request waits for it to
    // pass and then gets its own answer.
    runner_answering(
        Arc::clone(&shared),
        commands,
        OTP_REPORT_TIMEOUT + Duration::from_millis(300),
        vec![[1; 8], [2; 8]],
    );
    let mut wait = OtpWait::default();
    let start = Instant::now();
    assert_eq!(wait.fetch(&shared, &SessionState::default()), None);
    assert!(start.elapsed() >= OTP_REPORT_TIMEOUT);
    // The runner is still busy with the first request for 300 ms, then takes 1.3 s for
    // the second: this request times out too, without taking the first answer.
    assert_eq!(wait.fetch(&shared, &SessionState::default()), None);
    assert!(wait.previous.is_some());
}

#[test]
fn an_otp_feature_request_the_device_does_not_answer_ends_at_the_marker() {
    let (runner, commands) = mpsc::channel();
    let shared = shared_with(runner);
    runner_answering(Arc::clone(&shared), commands, Duration::ZERO, Vec::new());
    let mut wait = OtpWait::default();
    let state = SessionState::default();
    assert_eq!(wait.fetch(&shared, &state), None, "the marker came back with no OtpFeature before it");
    drop(shared);
}

/// A runner that delivers the answer and then re-enumerates (the status read before an
/// OTP HID Management reboot): it drains the session instead of answering the marker.
/// The request takes the delivered answer at once.
#[test]
fn an_otp_feature_request_takes_the_delivered_answer_when_the_session_drains() {
    let (runner, commands) = mpsc::channel();
    let shared = shared_with(runner);
    let state = Arc::new(SessionState::default());
    {
        let (shared, state) = (Arc::clone(&shared), Arc::clone(&state));
        thread::spawn(move || {
            let mut unanswered = Vec::new();
            for command in commands {
                match command {
                    Command::Input(HostInput::OtpGetFeature) => *shared.otp_feature() = Some([7; 8]),
                    Command::Status(reply) => {
                        unanswered.push(reply);
                        assert_eq!(state.drain(Duration::ZERO), Owed { responses: 0, control: false });
                    }
                    _ => {}
                }
            }
        });
    }
    let start = Instant::now();
    assert_eq!(OtpWait::default().fetch(&shared, &state), Some([7; 8]));
    assert!(start.elapsed() < OTP_REPORT_TIMEOUT, "{:?}", start.elapsed());
}

/// A request whose predecessor timed out first waits for the predecessor's marker; a
/// draining runner answers none, so the request gives up at once instead of holding the
/// drain for its whole budget.
#[test]
fn an_otp_feature_request_behind_a_timed_out_one_gives_up_when_the_session_drains() {
    let (runner, _commands) = mpsc::channel();
    let shared = shared_with(runner);
    let state = SessionState::default();
    let (_never_answered, previous) = mpsc::channel();
    let mut wait = OtpWait { previous: Some(previous) };
    assert_eq!(state.drain(Duration::ZERO), Owed::default());
    let start = Instant::now();
    assert_eq!(wait.fetch(&shared, &state), None);
    assert!(start.elapsed() < OTP_REPORT_TIMEOUT / 2, "{:?}", start.elapsed());
    assert!(wait.previous.is_some(), "the earlier marker is still awaited by the next request");
}

/// What a drain waits for: queued responses and a control request waiting for the
/// runner; it ends as soon as both are settled, or at its timeout with what is owed.
#[test]
fn a_drain_waits_for_owed_responses_and_control_requests_until_its_timeout() {
    let state = Arc::new(SessionState::default());
    assert_eq!(state.drain(Duration::from_secs(30)), Owed::default(), "nothing owed: at once");
    state.owe_response();
    state.answering(true);
    let start = Instant::now();
    assert_eq!(state.drain(Duration::from_millis(50)), Owed { responses: 1, control: true });
    assert!(start.elapsed() >= Duration::from_millis(50));
    let settle = {
        let state = Arc::clone(&state);
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            state.paid_response();
            state.answering(false);
        })
    };
    assert_eq!(state.drain(Duration::from_secs(30)), Owed::default());
    settle.join().expect("the settling thread ends");
    assert!(state.draining());
}

#[test]
fn an_otp_feature_request_to_a_stopped_runner_fails_at_once() {
    let (runner, commands) = mpsc::channel();
    drop(commands);
    let shared = shared_with(runner);
    let start = Instant::now();
    assert_eq!(OtpWait::default().fetch(&shared, &SessionState::default()), None);
    assert!(start.elapsed() < OTP_REPORT_TIMEOUT);
}

#[test]
fn a_session_state_wait_ends_on_a_change_or_a_stop() {
    let state = Arc::new(SessionState::default());
    let seen = state.generation();
    let waiter = {
        let state = Arc::clone(&state);
        thread::spawn(move || {
            let start = Instant::now();
            state.wait_change(seen, Duration::from_secs(30));
            start.elapsed()
        })
    };
    thread::sleep(Duration::from_millis(50));
    state.bump();
    assert!(waiter.join().expect("the waiter ends") < Duration::from_secs(10));
    let seen = state.generation();
    state.stop();
    assert!(state.stopping());
    let start = Instant::now();
    state.wait_change(seen, Duration::from_secs(30));
    assert!(start.elapsed() < Duration::from_secs(10));
}

#[test]
fn a_worker_is_joined_when_it_ends_and_left_behind_when_it_does_not() {
    let quick = Worker::spawn("lk-gadget-test".into(), || {}).expect("spawned");
    assert!(quick.join_by(Instant::now() + Duration::from_secs(10)));
    let (release, wait) = mpsc::channel::<()>();
    let stuck = Worker::spawn("lk-gadget-test".into(), move || {
        let _ = wait.recv();
    })
    .expect("spawned");
    assert!(!stuck.join_by(Instant::now() + Duration::from_millis(50)));
    drop(release);
}

/// Take `inputs` inputs and `markers` markers (waiting up to 10 s for them), then check
/// that nothing more arrives for 300 ms; the markers' reply channels.
fn expect_commands(commands: &mpsc::Receiver<Command>, inputs: usize, markers: usize) -> Vec<mpsc::Sender<Status>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let (mut got_inputs, mut got_markers) = (0, Vec::new());
    while got_inputs < inputs || got_markers.len() < markers {
        match commands.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(Command::Input(_)) => got_inputs += 1,
            Ok(Command::Status(reply)) => got_markers.push(reply),
            Ok(_) => {}
            Err(_) => panic!("{got_inputs} inputs and {} markers within 10 s", got_markers.len()),
        }
    }
    if let Ok(command) = commands.recv_timeout(Duration::from_millis(300)) {
        panic!("{command:?} after {inputs} inputs and {markers} markers");
    }
    got_markers
}

#[test]
fn a_pacer_sends_a_marker_after_each_window_and_first_waits_for_the_previous_one() {
    let (runner, commands) = mpsc::channel();
    let shared = shared_with(runner);
    let state = Arc::new(SessionState::default());
    let mut pacer = Pacer::default();
    for _ in 1..INPUT_WINDOW_FRAMES {
        assert!(pacer.sent(64, &shared, &state));
    }
    assert!(commands.try_recv().is_err(), "no marker inside the first window");
    assert!(pacer.sent(64, &shared, &state));
    let Ok(Command::Status(first)) = commands.try_recv() else { panic!("a marker ends the first window") };
    let (progress, counted) = mpsc::channel();
    let worker = {
        let (shared, state) = (Arc::clone(&shared), Arc::clone(&state));
        thread::spawn(move || {
            for _ in 0..INPUT_WINDOW_FRAMES {
                let _ = progress.send(pacer.sent(64, &shared, &state));
            }
        })
    };
    // The second window's last input waits for the first marker's answer.
    thread::sleep(Duration::from_millis(300));
    assert_eq!(counted.try_iter().count(), INPUT_WINDOW_FRAMES - 1);
    assert!(commands.try_recv().is_err(), "no second marker before the first is answered");
    let _ = first.send(status());
    assert_eq!(counted.recv_timeout(Duration::from_secs(10)), Ok(true));
    worker.join().expect("the producer ends");
    assert!(matches!(commands.try_recv(), Ok(Command::Status(_))), "the second window's marker");
}

#[test]
fn a_pacer_window_also_ends_by_size() {
    let (runner, commands) = mpsc::channel();
    let shared = shared_with(runner);
    let state = SessionState::default();
    let mut pacer = Pacer::default();
    assert!(pacer.sent(INPUT_WINDOW_BYTES / 2, &shared, &state));
    assert!(commands.try_recv().is_err());
    assert!(pacer.sent(INPUT_WINDOW_BYTES / 2, &shared, &state));
    assert!(matches!(commands.try_recv(), Ok(Command::Status(_))));
}

#[test]
fn a_pacer_waiting_for_a_marker_gives_up_when_the_session_stops_or_the_runner_is_gone() {
    let (runner, commands) = mpsc::channel();
    let shared = shared_with(runner);
    let state = Arc::new(SessionState::default());
    let mut pacer = Pacer::default();
    for _ in 0..INPUT_WINDOW_FRAMES * 2 - 1 {
        assert!(pacer.sent(1, &shared, &state));
    }
    let stopper = {
        let state = Arc::clone(&state);
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            state.stop();
        })
    };
    let start = Instant::now();
    assert!(!pacer.sent(1, &shared, &state), "the session stopped while it waited");
    assert!(start.elapsed() < Duration::from_secs(10));
    stopper.join().expect("the stopper ends");
    // A runner that stops drops its markers unanswered.
    let state = SessionState::default();
    let mut pacer = Pacer::default();
    for _ in 0..INPUT_WINDOW_FRAMES * 2 - 1 {
        assert!(pacer.sent(1, &shared, &state));
    }
    drop(commands);
    assert!(!pacer.sent(1, &shared, &state));
}

#[test]
fn the_fido_reader_stops_reading_while_the_runner_has_two_windows_unhandled() {
    let (runner, commands) = mpsc::channel();
    let shared = shared_with(runner);
    let state = Arc::new(SessionState::default());
    let (transport_half, mut kernel_half) = std::os::unix::net::UnixStream::pair().expect("a socket pair");
    let reader = {
        let (shared, state) = (Arc::clone(&shared), Arc::clone(&state));
        thread::spawn(move || fido_read_loop(Box::new(transport_half), &shared, &state))
    };
    for i in 0..INPUT_WINDOW_FRAMES * 3 {
        kernel_half.write_all(&[i as u8; 64]).expect("the endpoint takes a packet");
    }
    // Two windows and the first marker; the third window waits in the endpoint.
    for marker in expect_commands(&commands, INPUT_WINDOW_FRAMES * 2, 1) {
        let _ = marker.send(status());
    }
    let _unanswered = expect_commands(&commands, INPUT_WINDOW_FRAMES, 1);
    state.stop();
    let _ = kernel_half.shutdown(std::net::Shutdown::Both);
    reader.join().expect("the reader ends");
}

#[test]
fn gadget_events_display_without_payloads() {
    let event =
        GadgetEvent::Enumerated { product_id: 0x0407, interfaces: UsbInterfaces { otp: true, fido: true, ccid: true } };
    assert_eq!(event.to_string(), "gadget: enumerating as product 0x0407 (otp,fido,ccid)");
    assert_eq!(GadgetEvent::Sent { endpoint: Role::FidoIn, size: 64 }.to_string(), "gadget: -> fido-in, 64 bytes");
}
