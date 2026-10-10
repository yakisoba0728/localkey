//! The device serial, chosen once per state directory (`docs/PROGRAM.md` "lk-host",
//! Identity).

use std::fs;
use std::io;
use std::path::Path;

use lk_core::Entropy;

use crate::HostError;
use crate::state::write_atomically;

/// Name of the identity file in the state directory.
pub const IDENTITY_FILE: &str = "identity";

/// Smallest serial [`load_or_create_serial`] draws or accepts (eight decimal digits).
pub const SERIAL_MIN: u32 = 10_000_000;
/// Largest serial [`load_or_create_serial`] draws or accepts.
pub const SERIAL_MAX: u32 = 99_999_999;

/// Number of serial values.
const SPAN: u32 = SERIAL_MAX - SERIAL_MIN + 1;
/// Draws below this are accepted: the largest multiple of [`SPAN`] that fits in a `u32`
/// (47 × 90 000 000), so every serial is equally likely.
const ACCEPT_BELOW: u32 = (u32::MAX / SPAN) * SPAN;
/// A source that yields this many rejected draws in a row is broken: the chance is about
/// 2^-774 for real randomness.
const MAX_DRAWS: usize = 128;

const FORMAT_REASON: &str = "not an identity file: expected \"serial=<8 decimal digits>\" and one newline";

/// The device serial stored in `dir/identity`, created on first use.
///
/// - The file holds `serial=<decimal>\n`, nothing else, with a serial in
///   [`SERIAL_MIN`]`..=`[`SERIAL_MAX`] written without sign or leading zeros.
/// - If the file is missing, a serial is drawn uniformly from that range (rejection
///   sampling on 32-bit draws, no modulo bias) and written atomically (`identity.tmp`,
///   mode 0600, `sync_all`, rename, directory `sync_all`).
/// - A file that exists but is malformed is [`HostError::Format`] and is left as it is:
///   the serial names the device to its users and is never silently replaced.
///
/// Call it after [`crate::FileStore::open`] on the same directory and while that store is
/// alive: the open checks the directory, and its lock keeps two processes from creating
/// two identities.
///
/// # Panics
///
/// If `entropy` returns 128 rejected draws in a row (about 2^-774 for real randomness):
/// the source is broken, and `lk_core::Entropy::fill` cannot report it.
pub fn load_or_create_serial(dir: &Path, entropy: &mut dyn Entropy) -> Result<u32, HostError> {
    let path = dir.join(IDENTITY_FILE);
    match fs::read(&path) {
        Ok(text) => parse_identity(&text).ok_or_else(|| HostError::format(&path, FORMAT_REASON)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let serial = draw_serial(entropy);
            write_atomically(dir, IDENTITY_FILE, format!("serial={serial}\n").as_bytes())?;
            Ok(serial)
        }
        Err(err) => Err(HostError::io(path, err)),
    }
}

/// `serial=<decimal>\n` with the decimal in canonical form and in range.
fn parse_identity(text: &[u8]) -> Option<u32> {
    let text = std::str::from_utf8(text).ok()?;
    let digits = text.strip_prefix("serial=")?.strip_suffix('\n')?;
    let serial: u32 = digits.parse().ok()?;
    // `parse` also accepts a `+` sign and leading zeros; the file never holds them.
    ((SERIAL_MIN..=SERIAL_MAX).contains(&serial) && serial.to_string() == digits).then_some(serial)
}

/// A uniform serial: draw 4 bytes as a big-endian `u32` until one is below
/// [`ACCEPT_BELOW`], then map it onto the range by remainder.
fn draw_serial(entropy: &mut dyn Entropy) -> u32 {
    for _ in 0..MAX_DRAWS {
        let mut bytes = [0; 4];
        entropy.fill(&mut bytes);
        let value = u32::from_be_bytes(bytes);
        if value < ACCEPT_BELOW {
            return SERIAL_MIN + value % SPAN;
        }
    }
    panic!("the entropy source returned {MAX_DRAWS} rejected serial draws in a row; it is broken");
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::test_dir::{TestDir, mode_of};
    use lk_testkit::{ScriptedEntropy, SeededEntropy};

    #[test]
    fn a_serial_is_created_once_and_then_reused() {
        let dir = TestDir::new();
        let serial = load_or_create_serial(dir.path(), &mut SeededEntropy::new(1)).unwrap();
        assert!((SERIAL_MIN..=SERIAL_MAX).contains(&serial));
        let path = dir.join(IDENTITY_FILE);
        assert_eq!(fs::read_to_string(&path).unwrap(), format!("serial={serial}\n"));
        assert_eq!(mode_of(&path), 0o600);
        assert!(!dir.join("identity.tmp").exists());
        // Another entropy stream does not change an existing identity.
        assert_eq!(load_or_create_serial(dir.path(), &mut SeededEntropy::new(2)).unwrap(), serial);
        assert_eq!(fs::read_to_string(&path).unwrap(), format!("serial={serial}\n"));
    }

    #[test]
    fn a_draw_above_the_last_full_multiple_is_rejected_and_drawn_again() {
        let dir = TestDir::new();
        let mut entropy = ScriptedEntropy::new(0, [[0xFF; 4], 4_230_000_000u32.to_be_bytes(), 5u32.to_be_bytes()]);
        assert_eq!(load_or_create_serial(dir.path(), &mut entropy).unwrap(), 10_000_005);
        assert_eq!(entropy.scripted_remaining(), 0);
    }

    #[test]
    fn accepted_draws_map_onto_the_whole_range() {
        let draw = |value: u32| draw_serial(&mut ScriptedEntropy::new(0, [value.to_be_bytes()]));
        assert_eq!(ACCEPT_BELOW, 4_230_000_000);
        assert_eq!(draw(0), SERIAL_MIN);
        assert_eq!(draw(89_999_999), SERIAL_MAX);
        assert_eq!(draw(90_000_000), SERIAL_MIN);
        assert_eq!(draw(ACCEPT_BELOW - 1), SERIAL_MAX);
        let mut entropy = SeededEntropy::new(3);
        for _ in 0..1000 {
            assert!((SERIAL_MIN..=SERIAL_MAX).contains(&draw_serial(&mut entropy)));
        }
    }

    #[test]
    #[should_panic(expected = "rejected serial draws")]
    fn an_entropy_source_that_only_gives_rejected_draws_panics() {
        struct AllOnes;
        impl Entropy for AllOnes {
            fn fill(&mut self, out: &mut [u8]) {
                out.fill(0xFF);
            }
        }
        draw_serial(&mut AllOnes);
    }

    #[test]
    fn a_malformed_identity_file_is_an_error_and_is_left_unchanged() {
        let dir = TestDir::new();
        let path = dir.join(IDENTITY_FILE);
        let cases: [&[u8]; 13] = [
            b"",
            b"serial=abc\n",
            b"serial=123\n",
            b"serial=100000000\n",
            b"serial=12345678",
            b"serial=12345678\n\n",
            b"serial=12345678\nother=1\n",
            b"serial=+1234567\n",
            b"serial=012345678\n",
            b"serial= 12345678\n",
            b"SERIAL=12345678\n",
            b"serial=12345678\r\n",
            b"serial=1234\xff678\n",
        ];
        for text in cases {
            fs::write(&path, text).unwrap();
            let err = load_or_create_serial(dir.path(), &mut SeededEntropy::new(1)).unwrap_err();
            assert!(matches!(&err, HostError::Format { path: p, .. } if p == &path), "{text:?}: {err:?}");
            assert_eq!(fs::read(&path).unwrap(), text);
        }
    }

    #[test]
    fn an_identity_path_that_cannot_be_read_is_an_io_error() {
        let dir = TestDir::new();
        fs::create_dir(dir.join(IDENTITY_FILE)).unwrap();
        let err = load_or_create_serial(dir.path(), &mut SeededEntropy::new(1)).unwrap_err();
        assert!(matches!(err, HostError::Io { .. }), "{err:?}");
        assert!(dir.join(IDENTITY_FILE).is_dir());
    }
}
