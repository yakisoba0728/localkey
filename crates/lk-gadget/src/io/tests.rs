use std::collections::VecDeque;
use std::io::{self, Read, Write};

use super::*;
use crate::ffs::{CtrlRequest, EVENT_SIZE, Event};

/// One system call the adapter made.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Read(usize),
    Write(Vec<u8>),
}

/// A scripted file: reads return the queued results in order; writes take everything
/// unless a write result is queued.
#[derive(Debug, Default)]
struct Script {
    reads: VecDeque<io::Result<Vec<u8>>>,
    writes: VecDeque<io::Result<usize>>,
    calls: Vec<Call>,
}

impl Read for Script {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.calls.push(Call::Read(buf.len()));
        let data = self.reads.pop_front().unwrap_or_else(|| Err(io::Error::other("script exhausted")))?;
        let count = data.len().min(buf.len());
        buf[..count].copy_from_slice(&data[..count]);
        Ok(count)
    }
}

impl Write for Script {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.calls.push(Call::Write(buf.to_vec()));
        self.writes.pop_front().unwrap_or(Ok(buf.len()))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn ep0(reads: Vec<io::Result<Vec<u8>>>) -> Ep0<Script> {
    Ep0::new(Script { reads: reads.into(), ..Script::default() })
}

fn calls(ep0: &Ep0<Script>) -> &[Call] {
    &ep0.file.calls
}

#[test]
fn a_blob_goes_to_ep0_in_one_write() {
    let mut e = ep0(Vec::new());
    e.write_blob(&[1, 2, 3, 4]).expect("written");
    assert_eq!(calls(&e), [Call::Write(vec![1, 2, 3, 4])]);
}

#[test]
fn a_blob_written_in_part_is_an_error_not_a_second_write() {
    let mut e = ep0(Vec::new());
    e.file.writes.push_back(Ok(2));
    assert!(e.write_blob(&[1, 2, 3, 4]).is_err());
    assert_eq!(calls(&e).len(), 1);
}

#[test]
fn events_are_read_four_at_a_time_and_returned_whole() {
    let mut bytes = Event::Enable.to_bytes().to_vec();
    bytes.extend_from_slice(&Event::Suspend.to_bytes());
    let mut e = ep0(vec![Ok(bytes)]);
    assert_eq!(e.read_events().expect("events"), [Event::Enable, Event::Suspend]);
    assert_eq!(calls(&e), [Call::Read(4 * EVENT_SIZE)]);
}

#[test]
fn a_read_that_is_not_whole_events_is_discarded_and_not_joined_with_the_next() {
    // An 8-byte data stage of a SET_REPORT(feature) still pending, then a real event.
    let mut e = ep0(vec![Ok(vec![0x5A; 8]), Ok(Event::Suspend.to_bytes().to_vec())]);
    assert_eq!(e.read_events().map_err(|error| error.kind()), Err(io::ErrorKind::InvalidData));
    assert_eq!(e.read_events().expect("events"), [Event::Suspend], "nothing of the data stage is kept");
    assert_eq!(calls(&e), [Call::Read(4 * EVENT_SIZE), Call::Read(4 * EVENT_SIZE)]);
}

#[test]
fn a_read_of_host_data_in_whole_twelve_byte_chunks_is_discarded() {
    // 48 bytes of a FIDO SET_REPORT(output) data stage still pending.
    let mut e = ep0(vec![Ok((0..48).map(|i| i as u8 | 0x80).collect())]);
    assert_eq!(e.read_events().map_err(|error| error.kind()), Err(io::ErrorKind::InvalidData));
}

#[test]
fn an_empty_read_of_events_is_an_end_of_file_error() {
    let mut e = ep0(vec![Ok(Vec::new())]);
    assert_eq!(e.read_events().map_err(|error| error.kind()), Err(io::ErrorKind::UnexpectedEof));
}

#[test]
fn a_reply_is_one_write_of_the_data() {
    let mut e = ep0(Vec::new());
    e.reply(&[9, 8, 7], 64).expect("written");
    assert_eq!(calls(&e), [Call::Write(vec![9, 8, 7])]);
}

#[test]
fn an_empty_reply_to_a_zero_length_request_is_one_byte_the_kernel_cuts() {
    let mut e = ep0(Vec::new());
    e.reply(&[], 0).expect("written");
    assert_eq!(calls(&e), [Call::Write(vec![0])]);
}

#[test]
fn receiving_reads_once_with_the_request_length() {
    let mut e = ep0(vec![Ok(vec![5; 8])]);
    assert_eq!(e.receive(8).expect("data"), vec![5; 8]);
    assert_eq!(calls(&e), [Call::Read(8)]);
    let mut short = ep0(vec![Ok(vec![5; 3])]);
    assert_eq!(short.receive(8).expect("data"), vec![5; 3]);
    assert_eq!(calls(&short).len(), 1, "never a second read: it would read events");
}

#[test]
fn acknowledging_reads_with_a_one_byte_buffer_that_the_kernel_cuts_to_zero() {
    let mut e = ep0(vec![Ok(Vec::new())]);
    assert_eq!(e.receive(0).expect("status stage"), Vec::<u8>::new());
    assert_eq!(calls(&e), [Call::Read(1)]);
}

#[test]
fn an_in_request_is_stalled_by_a_one_byte_read_and_an_out_request_by_a_one_byte_write() {
    let mut e = ep0(vec![Err(io::Error::other("EL2HLT"))]);
    let request = CtrlRequest { request_type: 0xA1, request: 0x02, value: 0, index: 4, length: 1 };
    e.stall(&request);
    e.stall(&CtrlRequest { request_type: 0x21, ..request });
    assert_eq!(calls(&e), [Call::Read(1), Call::Write(vec![0])]);
}

fn interrupted() -> io::Error {
    io::Error::from(io::ErrorKind::Interrupted)
}

#[test]
fn an_interrupted_data_stage_is_repeated_because_the_request_is_still_pending() {
    let mut e = ep0(vec![Err(interrupted()), Ok(vec![7; 8])]);
    assert_eq!(e.receive(8).expect("data"), vec![7; 8]);
    assert_eq!(calls(&e), [Call::Read(8), Call::Read(8)]);
    let mut ack = ep0(vec![Err(interrupted()), Ok(Vec::new())]);
    assert_eq!(ack.receive(0).expect("status stage"), Vec::<u8>::new());
    assert_eq!(calls(&ack), [Call::Read(1), Call::Read(1)]);
    let mut e = ep0(Vec::new());
    e.file.writes.extend([Err(interrupted()), Err(interrupted()), Ok(3)]);
    e.reply(&[1, 2, 3], 3).expect("written");
    assert_eq!(calls(&e), [Call::Write(vec![1, 2, 3]), Call::Write(vec![1, 2, 3]), Call::Write(vec![1, 2, 3])]);
}

#[test]
fn an_interrupted_stall_is_repeated() {
    let request = CtrlRequest { request_type: 0xA1, request: 0x02, value: 0, index: 4, length: 1 };
    let mut e = ep0(vec![Err(interrupted()), Err(io::Error::other("EL2HLT"))]);
    e.stall(&request);
    assert_eq!(calls(&e), [Call::Read(1), Call::Read(1)]);
}

#[test]
fn repeats_after_interruptions_are_bounded() {
    let reads = (0..=INTERRUPTED_RETRIES + 5).map(|_| Err(interrupted())).collect();
    let mut e = ep0(reads);
    assert_eq!(e.receive(8).map_err(|error| error.kind()), Err(io::ErrorKind::Interrupted));
    assert_eq!(calls(&e).len(), INTERRUPTED_RETRIES + 1);
}

#[test]
fn other_data_stage_errors_are_returned_at_once() {
    let mut e = ep0(vec![Err(io::Error::other("EIDRM")), Ok(vec![1; 8])]);
    assert!(e.receive(8).is_err(), "a cancelled request is not repeated");
    assert_eq!(calls(&e).len(), 1);
}

#[test]
fn ep0_debug_shows_no_file_contents() {
    let e = ep0(Vec::new());
    assert_eq!(format!("{e:?}"), "Ep0 { .. }");
}

#[test]
fn kernel_io_opens_endpoint_files_by_index_and_writes_the_udc_attribute() {
    let dir = crate::test_support::TestDir::new();
    for name in ["ep0", "ep1", "ep2"] {
        std::fs::write(dir.path().join(name), b"").expect("a file");
    }
    let mut io = KernelIo;
    let mut ep0 = io.open_ep0(dir.path()).expect("ep0 opens");
    ep0.write_all(b"blob").expect("ep0 is writable");
    let mut out = io.open_out(dir.path(), 1).expect("ep1 opens");
    assert_eq!(out.read(&mut [0; 4]).expect("ep1 is readable"), 0);
    let mut input = io.open_in(dir.path(), 2).expect("ep2 opens");
    input.write_all(b"in").expect("ep2 is writable");
    assert_eq!(std::fs::read(dir.path().join("ep2")).expect("readable"), b"in");
    assert!(io.open_out(dir.path(), 3).is_err(), "ep3 does not exist");
    let udc = dir.path().join("UDC");
    io.bind(&udc, "dummy_udc.0").expect("bound");
    assert_eq!(std::fs::read_to_string(&udc).expect("readable"), "dummy_udc.0\n");
    io.unbind(&udc).expect("unbound");
    assert_eq!(std::fs::read_to_string(&udc).expect("readable"), "\n");
}

#[test]
fn the_mount_table_gives_the_mount_points_of_one_functionfs_instance() {
    let table = b"sysfs /sys sysfs rw,nosuid 0 0\n\
        lk /dev/ffs-lk functionfs rw,relatime 0 0\n\
        lk2 /dev/ffs-lk2 functionfs rw,relatime 0 0\n\
        lk /mnt/with\\040space functionfs rw 0 0\n\
        lk /not/ffs tmpfs rw 0 0\n\
        short line\n\
        lk /mnt/\xff functionfs rw 0 0\n";
    let found = functionfs_mounts(table, "lk");
    let raw = PathBuf::from(OsString::from_vec(b"/mnt/\xff".to_vec()));
    assert_eq!(found, [PathBuf::from("/dev/ffs-lk"), PathBuf::from("/mnt/with space"), raw]);
    assert!(functionfs_mounts(table, "other").is_empty());
    assert!(functionfs_mounts(b"", "lk").is_empty());
}

#[test]
fn only_a_backslash_with_three_octal_digits_is_an_escape() {
    assert_eq!(unescape(b"a\\134b\\011c"), b"a\\b\tc");
    assert_eq!(unescape(b"\\12"), b"\\12", "too short");
    assert_eq!(unescape(b"\\189"), b"\\189", "not octal");
    assert_eq!(unescape(b"end\\"), b"end\\");
}
