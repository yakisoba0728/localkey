//! The I/O boundary of the transport (`docs/PROGRAM.md` "Linux transports": "an I/O trait
//! for opening the device files ... The `mount` step is behind the same I/O trait").
//!
//! [`GadgetIo`] mounts FunctionFS, opens `ep0` and the endpoint files, and binds and
//! unbinds the UDC. [`KernelIo`] does it for real (files and `mount`/`umount` processes);
//! a test implementation hands out socket pairs and plays the kernel.
//!
//! [`Ep0`] maps the transport's control-pipe operations to reads and writes of `ep0` as
//! FunctionFS defines them (`ffs_ep0_read`, `ffs_ep0_write` and `__ffs_ep0_stall` in
//! `drivers/usb/gadget/function/f_fs.c`):
//!
//! - in the "read descriptors" and "read strings" states, each write is parsed as one
//!   whole blob, so each blob goes in one `write` call;
//! - with no request pending, a read returns whole 12-byte events (at most
//!   `len / 12`; a read shorter than one event is refused with `EINVAL` and consumes
//!   nothing);
//! - while a SETUP is pending, a read of an IN request and a write of an OUT request
//!   stall it (the call fails with `EL2HLT`); a write of an IN request is the data stage
//!   (cut to `wLength` by the kernel, with a zero-length packet when shorter); a read of
//!   an OUT request is the data stage, cut to `wLength`, so with `wLength` 0 it is the
//!   status stage alone;
//! - a request cancelled by a later event (the host gave up, or a reset) fails its
//!   data-stage call with `EIDRM`;
//! - a data-stage call that fails with `EINTR` leaves the request pending: the
//!   interruptible wait for the `ep0` mutex (`ffs_mutex_lock`) and for the transfer
//!   (`__ffs_ep0_queue_wait`, which dequeues the transfer and returns before it clears
//!   `setup_state`) both end that way on a signal, job-control stop/continue or a
//!   ptrace attach. Such a call is repeated (at most [`INTERRUPTED_RETRIES`] times);
//!   otherwise the next read of an OUT request would be its data stage.
//!
//! Stalls and acknowledgements use a 1-byte buffer, never an empty one: the kernel cuts
//! the length itself, and a stray call that found no request pending fails with `EINVAL`
//! (read, shorter than an event) or `ESRCH` (write) instead of consuming an event.
//!
//! A read of events must return whole, well-formed events ([`Event::parse_read`]); any
//! other result is the data stage of a request still pending (after a failed data-stage
//! call that did not end it) and is discarded whole, never kept to be joined with the
//! next read: a real `ep0` never returns part of an event.

use std::ffi::OsString;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::ffs::{CtrlRequest, EVENT_SIZE, Event};

/// A readable and writable `ep0`.
pub trait Ep0File: Read + Write + Send {}

impl<T: Read + Write + Send> Ep0File for T {}

/// Mounting FunctionFS, opening its files, binding the UDC.
///
/// Endpoint files are named by their index in descriptor order (`ep1`, `ep2`, ...;
/// `ffs_epfiles_create`). OUT endpoints are opened for reading only and IN endpoints for
/// writing only: f_fs halts an endpoint that is read against its direction.
pub trait GadgetIo: Send + fmt::Debug {
    /// `mount -t functionfs <instance> <mount_point>`.
    fn mount(&mut self, instance: &str, mount_point: &Path) -> io::Result<()>;
    /// `umount <mount_point>`.
    fn unmount(&mut self, mount_point: &Path) -> io::Result<()>;
    /// Where FunctionFS instance `instance` is mounted now: at most one place, since
    /// `ffs_acquire_dev` (`drivers/usb/gadget/function/f_fs.c`) refuses a second mount of
    /// a mounted instance with `EBUSY`, but every place found is returned. Used to find
    /// the mount a killed process left behind.
    fn functionfs_mounts(&mut self, instance: &str) -> io::Result<Vec<PathBuf>>;
    /// Open `<mount_point>/ep0` for reading and writing.
    fn open_ep0(&mut self, mount_point: &Path) -> io::Result<Box<dyn Ep0File>>;
    /// Open the OUT endpoint `<mount_point>/ep<index>` for reading.
    fn open_out(&mut self, mount_point: &Path, index: usize) -> io::Result<Box<dyn Read + Send>>;
    /// Open the IN endpoint `<mount_point>/ep<index>` for writing.
    fn open_in(&mut self, mount_point: &Path, index: usize) -> io::Result<Box<dyn Write + Send>>;
    /// Bind the gadget: write the UDC name to the gadget's `UDC` attribute.
    fn bind(&mut self, udc_file: &Path, udc: &str) -> io::Result<()>;
    /// Unbind the gadget: write an empty name (`"\n"`) to `UDC`.
    fn unbind(&mut self, udc_file: &Path) -> io::Result<()>;
}

/// The real implementation: files, and `mount`/`umount` run as processes (found through
/// `PATH`). Needs root.
#[derive(Debug, Default, Clone, Copy)]
pub struct KernelIo;

impl GadgetIo for KernelIo {
    /// Creates the mount point if missing (it is left in place afterwards).
    fn mount(&mut self, instance: &str, mount_point: &Path) -> io::Result<()> {
        std::fs::create_dir_all(mount_point)?;
        let mut command = Command::new("mount");
        command.arg("-t").arg("functionfs").arg(instance).arg(mount_point);
        run(command)
    }

    fn unmount(&mut self, mount_point: &Path) -> io::Result<()> {
        let mut command = Command::new("umount");
        command.arg(mount_point);
        run(command)
    }

    /// Reads [`PROC_MOUNTS`]; a system without it (not Linux) has no FunctionFS mounted.
    fn functionfs_mounts(&mut self, instance: &str) -> io::Result<Vec<PathBuf>> {
        match std::fs::read(PROC_MOUNTS) {
            Ok(table) => Ok(functionfs_mounts(&table, instance)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(error) => Err(io::Error::new(error.kind(), format!("{PROC_MOUNTS}: {error}"))),
        }
    }

    fn open_ep0(&mut self, mount_point: &Path) -> io::Result<Box<dyn Ep0File>> {
        let file = OpenOptions::new().read(true).write(true).open(mount_point.join("ep0"))?;
        Ok(Box::new(file))
    }

    fn open_out(&mut self, mount_point: &Path, index: usize) -> io::Result<Box<dyn Read + Send>> {
        let file: File =
            OpenOptions::new().read(true).custom_flags(ENDPOINT_FLAGS).open(mount_point.join(format!("ep{index}")))?;
        Ok(Box::new(file))
    }

    fn open_in(&mut self, mount_point: &Path, index: usize) -> io::Result<Box<dyn Write + Send>> {
        let file: File =
            OpenOptions::new().write(true).custom_flags(ENDPOINT_FLAGS).open(mount_point.join(format!("ep{index}")))?;
        Ok(Box::new(file))
    }

    fn bind(&mut self, udc_file: &Path, udc: &str) -> io::Result<()> {
        std::fs::write(udc_file, format!("{udc}\n"))
    }

    fn unbind(&mut self, udc_file: &Path) -> io::Result<()> {
        std::fs::write(udc_file, "\n")
    }
}

/// Endpoint files are opened `O_NONBLOCK` on Linux. f_fs consults the flag only before
/// it queues a transfer (`ffs_epfile_wait_ep` and the endpoint mutex in
/// `ffs_epfile_io`): a read or write of an endpoint that is not enabled fails with
/// `EAGAIN` instead of sleeping until the host configures the device again, which nothing
/// would end once the gadget is unbound. A transfer that is queued still waits for the
/// host. The value is `O_NONBLOCK` of `include/uapi/asm-generic/fcntl.h` (`00004000`),
/// overridden by `arch/mips/include/uapi/asm/fcntl.h` (`0x0080`) and
/// `arch/sparc/include/uapi/asm/fcntl.h` (`0x4000`).
#[cfg(all(
    target_os = "linux",
    any(target_arch = "mips", target_arch = "mips64", target_arch = "mips32r6", target_arch = "mips64r6")
))]
const ENDPOINT_FLAGS: i32 = 0x0080;
#[cfg(all(target_os = "linux", any(target_arch = "sparc", target_arch = "sparc64")))]
const ENDPOINT_FLAGS: i32 = 0x4000;
#[cfg(all(
    target_os = "linux",
    not(any(
        target_arch = "mips",
        target_arch = "mips64",
        target_arch = "mips32r6",
        target_arch = "mips64r6",
        target_arch = "sparc",
        target_arch = "sparc64"
    ))
))]
const ENDPOINT_FLAGS: i32 = 0o4000;
/// Elsewhere the transport is never run against a kernel (`localkeyd` refuses it), so no
/// flag.
#[cfg(not(target_os = "linux"))]
const ENDPOINT_FLAGS: i32 = 0;

/// The mount table of the calling process's mount namespace
/// (`Documentation/filesystems/proc.rst`).
pub const PROC_MOUNTS: &str = "/proc/self/mounts";

/// The mount points of FunctionFS instance `instance` in a mount table in the format of
/// [`PROC_MOUNTS`]. `show_vfsmnt` (`fs/proc_namespace.c`) writes one line per mount:
/// device name, mount point, file system type, options and `0 0`, separated by single
/// spaces. The device name of a FunctionFS mount is the instance (`mount -t functionfs
/// <instance> <dir>`, `ffs_fs_get_tree`), and the type is `functionfs` (no subtype). In
/// the device name, the mount point and the type, space, tab, newline and backslash (and
/// `#` outside the mount point) are written as a backslash and three octal digits
/// (`mangle`/`seq_escape` with `ESCAPE_OCTAL`, `include/linux/seq_file.h`;
/// `seq_path_root`/`mangle_path`, `fs/seq_file.c`). Other bytes are written as they are,
/// so the table is bytes, not necessarily UTF-8.
pub fn functionfs_mounts(table: &[u8], instance: &str) -> Vec<PathBuf> {
    table
        .split(|&byte| byte == b'\n')
        .filter_map(|line| {
            let mut fields = line.split(|&byte| byte == b' ');
            let (device, mount_point, kind) = (fields.next()?, fields.next()?, fields.next()?);
            (unescape(kind) == b"functionfs" && unescape(device) == instance.as_bytes())
                .then(|| PathBuf::from(OsString::from_vec(unescape(mount_point))))
        })
        .collect()
}

/// Undo the octal escapes of a mount table field (see [`functionfs_mounts`]); anything
/// else is kept as it is.
fn unescape(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let octal = bytes.get(i + 1..i + 4).filter(|digits| digits.iter().all(|d| (b'0'..=b'7').contains(d)));
        match (bytes[i], octal) {
            (b'\\', Some(digits)) => {
                let value = digits.iter().fold(0u32, |value, digit| value * 8 + u32::from(digit - b'0'));
                // Three octal digits of an escaped byte never exceed 0o377.
                out.push(u8::try_from(value).unwrap_or(u8::MAX));
                i += 4;
            }
            (byte, _) => {
                out.push(byte);
                i += 1;
            }
        }
    }
    out
}

/// Run a command with no input; a failed start or a non-zero exit is an error carrying
/// the first line of its error output.
fn run(mut command: Command) -> io::Result<()> {
    let output = command.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).output()?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let reason = stderr.lines().next().unwrap_or("").trim();
    Err(io::Error::other(format!("{:?} exited with {}: {reason}", command.get_program(), output.status)))
}

/// The control pipe: FunctionFS `ep0` semantics over a [`Read`] + [`Write`] file (see the
/// module docs).
pub struct Ep0<F> {
    file: F,
}

impl<F> fmt::Debug for Ep0<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ep0").finish_non_exhaustive()
    }
}

/// Events asked for per read: f_fs queues at most four (`__ffs_event_add`).
const EVENTS_PER_READ: usize = 4;

/// How often one data-stage or stall call is repeated after `EINTR` before its error is
/// returned (a bound, so a stream of signals cannot keep the thread in one request).
pub const INTERRUPTED_RETRIES: usize = 16;

/// Run `call`, repeating it while it fails with `ErrorKind::Interrupted`, at most
/// [`INTERRUPTED_RETRIES`] more times.
fn repeat_interrupted<T>(mut call: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    let mut retries = 0;
    loop {
        match call() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted && retries < INTERRUPTED_RETRIES => retries += 1,
            result => return result,
        }
    }
}

impl<F: Read + Write> Ep0<F> {
    pub fn new(file: F) -> Ep0<F> {
        Ep0 { file }
    }

    /// Write the descriptors or the strings blob: one `write` call, all of it.
    pub fn write_blob(&mut self, blob: &[u8]) -> io::Result<()> {
        let written = self.file.write(blob)?;
        if written == blob.len() {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::WriteZero, format!("ep0 took {written} of {} bytes", blob.len())))
        }
    }

    /// Read the next events (blocks until there is one): one `read` call. A read that
    /// returns no bytes is reported as `UnexpectedEof`; one that is not whole,
    /// well-formed events (the data stage of a request still pending, see the module
    /// docs) is discarded and reported as `InvalidData`. `Interrupted` is returned as
    /// is: with no request pending an interrupted read consumed nothing.
    pub fn read_events(&mut self) -> io::Result<Vec<Event>> {
        let mut buffer = lk_crypto::SecretBytes::zeroed(EVENT_SIZE * EVENTS_PER_READ);
        let count = self.file.read(&mut buffer)?;
        if count == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        Event::parse_read(&buffer[..count]).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("ep0 read returned {count} bytes that are not events (a data stage still pending); discarded"),
            )
        })
    }

    /// The IN data stage of a request with `length` (`wLength`): one `write` call (the
    /// kernel cuts it to `wLength`), repeated after `EINTR`. An empty reply to a request
    /// with `wLength` 0 is written as one byte, which the kernel cuts to nothing, so no
    /// call is ever empty.
    pub fn reply(&mut self, data: &[u8], length: u16) -> io::Result<()> {
        let data = if data.is_empty() && length == 0 { &[0u8][..] } else { data };
        repeat_interrupted(|| self.file.write(data)).map(|_| ())
    }

    /// The OUT data stage of `length` bytes: one `read` call (repeated only after
    /// `EINTR`, which leaves the request pending), never a second one that succeeded (a
    /// second read would read events). With `length` 0 this is the status stage alone,
    /// and the read returns no bytes; a host that sent fewer bytes than `wLength` gives a
    /// shorter result. A zero-byte result is therefore not an end-of-file check.
    pub fn receive(&mut self, length: u16) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; usize::from(length).max(1)];
        let count = match repeat_interrupted(|| self.file.read(&mut buffer)) {
            Ok(count) => count,
            Err(error) => {
                lk_crypto::wipe_vec(&mut buffer);
                return Err(error);
            }
        };
        let used = count.min(usize::from(length));
        lk_crypto::wipe(&mut buffer[used..]);
        buffer.truncate(used);
        Ok(buffer)
    }

    /// Stall the pending request: read for an IN request, write for an OUT request,
    /// repeated after `EINTR` (an interrupted wait for the `ep0` mutex stalled nothing).
    /// The kernel reports an accepted stall as an error (`EL2HLT`), so the result carries
    /// no information and is not returned.
    pub fn stall(&mut self, request: &CtrlRequest) {
        let mut byte = [0u8; 1];
        let _ = repeat_interrupted(|| if request.is_in() { self.file.read(&mut byte) } else { self.file.write(&byte) });
        lk_crypto::wipe(&mut byte);
    }
}

#[cfg(test)]
mod tests;
