//! Opening the UHID character device (`docs/PROGRAM.md` "Linux transports": an I/O trait
//! whose real implementation opens files and whose test implementation hands out socket
//! pairs).

use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// The two halves of one open UHID file: events from the kernel are read from the first,
/// events to the kernel are written to the second. Both refer to the same open file, and
/// the device lives until both are dropped (`Documentation/hid/uhid.rst`: closing the file
/// destroys the device).
pub type UhidHalves = (Box<dyn Read + Send>, Box<dyn Write + Send>);

/// Opens one UHID file per HID device.
///
/// Each call to [`UhidIo::open`] is one `open("/dev/uhid")`: one file registers at most one
/// device (`Documentation/hid/uhid.rst`). The reader gets one whole `struct uhid_event`
/// per `read` of [`crate::event::UHID_EVENT_SIZE`] bytes and the writer takes one whole
/// event per `write`. Test streams may split an event over several reads; the reader
/// retains partial events across idle reads.
/// Reads must be nonblocking or time out, so retirement can close a file even when the
/// HID driver was unbound and the kernel sends no STOP event.
pub trait UhidIo: Send + fmt::Debug {
    /// Open a new UHID file.
    fn open(&mut self) -> io::Result<UhidHalves>;
}

/// The default UHID device path (`Documentation/hid/uhid.rst`).
pub const DEFAULT_UHID_PATH: &str = "/dev/uhid";

/// The real [`UhidIo`]: opens a character device, `/dev/uhid` by default, for reading and
/// writing (nonblocking on Linux, close-on-exec as std opens every file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevUhid {
    path: PathBuf,
}

impl DevUhid {
    /// A UHID device at `path`.
    pub fn new(path: impl Into<PathBuf>) -> DevUhid {
        DevUhid { path: path.into() }
    }

    /// The device path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Default for DevUhid {
    fn default() -> Self {
        DevUhid::new(DEFAULT_UHID_PATH)
    }
}

impl UhidIo for DevUhid {
    /// Open the path for reading and writing and refuse anything that is not a character
    /// device (a mistyped path must not become a regular file that swallows events).
    fn open(&mut self) -> io::Result<UhidHalves> {
        let file =
            OpenOptions::new().read(true).write(true).custom_flags(NONBLOCK_FLAGS).open(&self.path).map_err(|error| {
                io::Error::new(error.kind(), format!("cannot open {}: {error}", self.path.display()))
            })?;
        if !file.metadata()?.file_type().is_char_device() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a character device", self.path.display()),
            ));
        }
        let reader = file.try_clone()?;
        Ok((Box::new(reader), Box::new(file)))
    }
}

// Linux O_NONBLOCK, with the same architecture overrides as lk-gadget's endpoint files.
#[cfg(all(target_os = "linux", any(target_arch = "mips", target_arch = "mips64", target_arch = "mips32r6", target_arch = "mips64r6")))]
const NONBLOCK_FLAGS: i32 = 0x0080;
#[cfg(all(target_os = "linux", any(target_arch = "sparc", target_arch = "sparc64")))]
const NONBLOCK_FLAGS: i32 = 0x4000;
#[cfg(all(target_os = "linux", not(any(target_arch = "mips", target_arch = "mips64", target_arch = "mips32r6", target_arch = "mips64r6", target_arch = "sparc", target_arch = "sparc64"))))]
const NONBLOCK_FLAGS: i32 = 0o4000;
#[cfg(not(target_os = "linux"))]
const NONBLOCK_FLAGS: i32 = 0;

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A fresh file path under the temporary directory, removed on drop.
    struct TempPath(PathBuf);

    impl TempPath {
        fn new() -> TempPath {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let n = NEXT.fetch_add(1, Ordering::SeqCst);
            TempPath(std::env::temp_dir().join(format!("lku{}-{n}", std::process::id())))
        }
    }

    impl Drop for TempPath {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    #[test]
    fn the_default_path_is_dev_uhid() {
        assert_eq!(DevUhid::default().path(), Path::new("/dev/uhid"));
        assert_eq!(DevUhid::new("/tmp/x").path(), Path::new("/tmp/x"));
    }

    #[test]
    fn the_real_opener_refuses_a_regular_file() {
        let path = TempPath::new();
        fs::write(&path.0, b"").expect("the temporary file can be written");
        let error = DevUhid::new(&path.0).open().err().expect("a regular file is refused");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("not a character device"), "{error}");
        assert_eq!(fs::read(&path.0).expect("the file is still there"), b"", "nothing was written");
    }

    #[test]
    fn the_real_opener_names_a_missing_path() {
        let path = TempPath::new();
        let error = DevUhid::new(&path.0).open().err().expect("a missing path is refused");
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(error.to_string().contains(&path.0.display().to_string()), "{error}");
    }
}
