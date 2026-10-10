//! Operating-system randomness for the engine (`docs/PROGRAM.md` "lk-host", `OsEntropy`).

use core::fmt;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

use lk_core::Entropy;

use crate::HostError;

/// The kernel's non-blocking CSPRNG on macOS and Linux.
const URANDOM: &str = "/dev/urandom";

/// [`Entropy`] read from `/dev/urandom` through one `std::fs::File`, opened once.
///
/// [`Entropy::fill`] cannot report an error, and the engine draws keys and nonces from
/// it, so a failed or short read panics instead of returning partial or zeroed bytes. On
/// both supported systems the device never runs dry once the kernel pool is seeded at
/// boot, so the panic marks a broken system, not a condition to recover from.
pub struct OsEntropy {
    file: File,
}

impl OsEntropy {
    /// Open `/dev/urandom`. Refuses a path that is not a character device (a regular file
    /// planted there would give predictable keys).
    pub fn open() -> Result<OsEntropy, HostError> {
        let path = Path::new(URANDOM);
        let file = File::open(path).map_err(|err| HostError::io(path, err))?;
        let metadata = file.metadata().map_err(|err| HostError::io(path, err))?;
        if !metadata.file_type().is_char_device() {
            return Err(HostError::format(path, "not a character device"));
        }
        Ok(OsEntropy { file })
    }
}

impl Entropy for OsEntropy {
    /// Fill `out` completely, or panic.
    fn fill(&mut self, out: &mut [u8]) {
        if let Err(err) = self.file.read_exact(out) {
            panic!("reading {URANDOM} failed ({err}); refusing to continue without randomness");
        }
    }
}

impl fmt::Debug for OsEntropy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OsEntropy").field("path", &URANDOM).finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn buffers_of_every_size_are_filled_with_varying_bytes() {
        let mut entropy = OsEntropy::open().unwrap();
        let mut empty = [0u8; 0];
        entropy.fill(&mut empty);
        for len in [1, 7, 16, 32, 33, 1024, 4097] {
            let mut buffer = vec![0u8; len];
            entropy.fill(&mut buffer);
            // A constant buffer of 16 or more bytes has probability 2^-120 or less.
            if len >= 16 {
                assert!(buffer.iter().any(|&b| b != buffer[0]), "{len} constant bytes");
            }
        }
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        entropy.fill(&mut a);
        entropy.fill(&mut b);
        assert_ne!(a, b);
        assert_ne!(a, [0; 32]);
    }

    #[test]
    fn os_entropy_is_send_and_debug_names_only_the_device() {
        fn assert_send<T: Send>() {}
        assert_send::<OsEntropy>();
        assert_eq!(format!("{:?}", OsEntropy::open().unwrap()), "OsEntropy { path: \"/dev/urandom\" }");
    }
}
