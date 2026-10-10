//! The storage key (`docs/PROGRAM.md` "lk-host", Storage key).
//!
//! The 32-byte key under which `lk_device::storage` seals every record (AES-256-GCM).
//! Its text form, shared by key files and key commands, is exactly 64 hex digits (either
//! case), optionally followed by one `\n`.
//!
//! - A key file is written once ([`write_key_file`]: `create_new`, mode 0600) and refused
//!   when its mode grants any group/other access ([`read_key_file`]).
//! - A key command ([`key_from_command`]) lets the user keep the key in the macOS
//!   Keychain (`security find-generic-password -w -s localkey`), `secret-tool`, `pass` or
//!   a password manager without this crate touching any of them.
//!
//! The key, its text and a command's output live in [`SecretBytes`], wiped on drop; they
//! are read into buffers sized for the whole bounded read, so no reallocation leaves a
//! copy behind in freed memory. Error messages never contain any of them.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::{Command, Stdio};

use lk_core::Entropy;
use lk_crypto::SecretBytes;

use crate::state::{parent_dir, sync_dir};
use crate::{HostError, Refusal};

/// Length of the storage key in bytes (AES-256).
pub const KEY_LEN: usize = 32;

/// A key file longer than this is refused without reading the rest (the text form is 64
/// or 65 bytes).
const MAX_TEXT_LEN: usize = 128;

/// A key command's output longer than this is refused without reading the rest: the text
/// form is 64 or 65 bytes, and the limit leaves generous room for surrounding whitespace.
pub const MAX_OUTPUT_LEN: usize = 1024;

const FORMAT_REASON: &str = "not a storage key: expected exactly 64 hex digits, optionally followed by one newline";

/// A fresh random key of [`KEY_LEN`] bytes from `entropy`.
pub fn generate_key(entropy: &mut dyn Entropy) -> SecretBytes {
    let mut key = SecretBytes::zeroed(KEY_LEN);
    entropy.fill(&mut key);
    key
}

/// The text form of `key`: lowercase hex digits followed by one `\n` (what
/// [`write_key_file`] writes, and what `localkeyd keygen --print` prints).
pub fn key_text(key: &SecretBytes) -> SecretBytes {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = SecretBytes::zeroed(2 * key.len() + 1);
    let (pairs, _newline) = text.as_chunks_mut::<2>();
    for (pair, byte) in pairs.iter_mut().zip(key.iter()) {
        *pair = [DIGITS[usize::from(byte >> 4)], DIGITS[usize::from(byte & 0x0f)]];
    }
    if let Some(last) = text.last_mut() {
        *last = b'\n';
    }
    text
}

/// Write `key` to a new file at `path` in the text form, with mode 0600.
///
/// The file is created with `create_new`, so an existing file (an older key that may
/// still seal records) is never overwritten: that is an [`HostError::Io`] of kind
/// `AlreadyExists`. The file is `sync_all`ed, and so is its directory, so that the new
/// entry survives a crash. A write that fails part way removes the partial file.
pub fn write_key_file(path: &Path, key: &SecretBytes) -> Result<(), HostError> {
    if key.len() != KEY_LEN {
        return Err(HostError::format(path, "refusing to write: a storage key is 32 bytes"));
    }
    let text = key_text(key);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| HostError::io(path, err))?;
    if let Err(err) = file.write_all(&text).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(HostError::io(path, err));
    }
    sync_dir(parent_dir(path))
}

/// Read a key file written by [`write_key_file`] (or by hand in the same text form).
///
/// A file whose mode grants any group/other access is refused with
/// [`HostError::Permissions`] before it is read; the mode is taken from the open file, so
/// it is the mode of the file actually read. Anything but the text form is
/// [`HostError::Format`].
pub fn read_key_file(path: &Path) -> Result<SecretBytes, HostError> {
    let file = File::open(path).map_err(|err| HostError::io(path, err))?;
    let mode = file.metadata().map_err(|err| HostError::io(path, err))?.mode();
    if mode & 0o077 != 0 {
        return Err(HostError::refused(path, mode, Refusal::GroupOrOtherAccess));
    }
    // The capacity covers the whole bounded read, so the buffer is never reallocated and
    // no copy of the key is left behind in freed memory.
    let mut buffer = Vec::with_capacity(MAX_TEXT_LEN + 1);
    let read = file.take(MAX_TEXT_LEN as u64 + 1).read_to_end(&mut buffer);
    let text = SecretBytes::new(buffer);
    read.map_err(|err| HostError::io(path, err))?;
    parse_text(&text).ok_or_else(|| HostError::format(path, FORMAT_REASON))
}

/// Run `/bin/sh -c command` and read the key from its standard output.
///
/// Standard input is null and standard error is inherited, so the command can prompt or
/// report on the terminal. Surrounding ASCII whitespace in the output is ignored; a
/// non-zero exit, output longer than [`MAX_OUTPUT_LEN`] bytes, or output that is not the
/// text form, is [`HostError::Command`]. The error never repeats the command or its
/// output.
///
/// The output is read until the command closes its standard output, as with
/// `Command::output`, but never past [`MAX_OUTPUT_LEN`] bytes: a command that prints more
/// (a whole file, or `yes`) has its pipe closed and is killed, instead of growing this
/// process's memory.
pub fn key_from_command(command: &str) -> Result<SecretBytes, HostError> {
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|err| HostError::Command { reason: format!("cannot run /bin/sh: {err}") })?;
    let stdout = child.stdout.take().expect("the child's stdout is piped, so its read end is present");
    // As in `read_key_file`: the capacity covers the whole bounded read. The read end is
    // closed at the end of the statement.
    let mut buffer = Vec::with_capacity(MAX_OUTPUT_LEN + 1);
    let read = stdout.take(MAX_OUTPUT_LEN as u64 + 1).read_to_end(&mut buffer);
    let output = SecretBytes::new(buffer);
    let too_long = output.len() > MAX_OUTPUT_LEN;
    if read.is_err() || too_long {
        // It may still be writing, into a full pipe or forever. With the read end closed
        // a write gets SIGPIPE; the kill covers a command that ignores it.
        let _ = child.kill();
    }
    let status = child.wait().map_err(|err| HostError::Command { reason: format!("cannot wait for it: {err}") })?;
    if let Err(err) = read {
        return Err(HostError::Command { reason: format!("cannot read its output: {err}") });
    }
    if too_long {
        return Err(HostError::Command { reason: format!("output is longer than {MAX_OUTPUT_LEN} bytes") });
    }
    if !status.success() {
        return Err(HostError::Command { reason: format!("failed ({status})") });
    }
    parse_text(output.trim_ascii()).ok_or_else(|| HostError::Command {
        reason: "output is not a storage key: expected 64 hex digits".into(),
    })
}

/// The key as the array `lk_device::Device::open` takes.
///
/// # Panics
///
/// If `key` is not [`KEY_LEN`] bytes. Every key this module produces is; a caller that
/// builds a `SecretBytes` itself must check the length first.
pub fn to_array(key: &SecretBytes) -> [u8; KEY_LEN] {
    key.as_slice()
        .try_into()
        .expect("a storage key is 32 bytes: generate_key, read_key_file and key_from_command produce no other length")
}

/// Exactly 64 hex digits (either case), optionally followed by one `\n`.
fn parse_text(text: &[u8]) -> Option<SecretBytes> {
    let digits = text.strip_suffix(b"\n").unwrap_or(text);
    if digits.len() != 2 * KEY_LEN {
        return None;
    }
    let mut key = SecretBytes::zeroed(KEY_LEN);
    let (pairs, _) = digits.as_chunks::<2>();
    for (byte, &[high, low]) in key.iter_mut().zip(pairs) {
        *byte = hex_value(high)? << 4 | hex_value(low)?;
    }
    Some(key)
}

fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::test_dir::{TestDir, chmod, mode_of};
    use lk_testkit::SeededEntropy;

    const HEX: &str = "00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210";
    const BYTES: [u8; 32] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x23,
        0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    ];

    fn parse(text: &str) -> Option<[u8; 32]> {
        parse_text(text.as_bytes()).map(|key| to_array(&key))
    }

    #[test]
    fn text_in_either_case_with_or_without_one_newline_parses() {
        assert_eq!(parse(HEX), Some(BYTES));
        assert_eq!(parse(&format!("{HEX}\n")), Some(BYTES));
        assert_eq!(parse(&HEX.to_uppercase()), Some(BYTES));
        let mixed: String = HEX.chars().enumerate().map(|(i, c)| if i % 2 == 0 { c.to_ascii_uppercase() } else { c }).collect();
        assert_eq!(parse(&mixed), Some(BYTES));
    }

    #[test]
    fn text_of_the_wrong_length_or_with_other_characters_is_rejected() {
        assert_eq!(parse(&HEX[..63]), None);
        assert_eq!(parse(&format!("{HEX}0")), None);
        assert_eq!(parse(&HEX[..62]), None);
        assert_eq!(parse(""), None);
        assert_eq!(parse("\n"), None);
        assert_eq!(parse(&format!("{}g", &HEX[..63])), None);
        assert_eq!(parse(&format!("{HEX}\n\n")), None);
        assert_eq!(parse(&format!("{HEX}\r\n")), None);
        assert_eq!(parse(&format!(" {HEX}")), None);
        assert_eq!(parse(&format!("x{}", &HEX[1..])), None);
        assert_eq!(parse(&format!("0x{}", &HEX[2..])), None);
    }

    #[test]
    fn generated_keys_are_32_random_bytes_and_survive_the_text_form() {
        let mut entropy = SeededEntropy::new(1);
        let first = generate_key(&mut entropy);
        let second = generate_key(&mut entropy);
        assert_eq!(first.len(), KEY_LEN);
        assert_ne!(first, second);
        let text = key_text(&first);
        assert_eq!(text.len(), 65);
        assert_eq!(text.last(), Some(&b'\n'));
        assert!(text[..64].iter().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c)));
        assert_eq!(parse_text(&text), Some(first));
        assert_eq!(&key_text(&SecretBytes::from_slice(&BYTES))[..64], HEX.as_bytes());
    }

    #[test]
    fn a_written_key_file_has_mode_0600_and_reads_back() {
        let dir = TestDir::new();
        let path = dir.join("key");
        let key = SecretBytes::from_slice(&BYTES);
        write_key_file(&path, &key).unwrap();
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), format!("{HEX}\n").into_bytes());
        assert_eq!(read_key_file(&path).unwrap(), key);
    }

    #[test]
    fn writing_a_key_file_never_overwrites_an_existing_file() {
        let dir = TestDir::new();
        let path = dir.join("key");
        write_key_file(&path, &SecretBytes::from_slice(&BYTES)).unwrap();
        let err = write_key_file(&path, &SecretBytes::from_slice(&[0x77; 32])).unwrap_err();
        assert!(
            matches!(&err, HostError::Io { path: p, source } if p == &path && source.kind() == std::io::ErrorKind::AlreadyExists),
            "{err:?}"
        );
        assert_eq!(read_key_file(&path).unwrap(), SecretBytes::from_slice(&BYTES));
    }

    #[test]
    fn writing_a_key_of_the_wrong_length_is_refused_and_creates_nothing() {
        let dir = TestDir::new();
        let path = dir.join("key");
        let err = write_key_file(&path, &SecretBytes::from_slice(&[1; 16])).unwrap_err();
        assert!(matches!(err, HostError::Format { .. }), "{err:?}");
        assert!(!path.exists());
    }

    #[test]
    fn a_key_file_readable_by_group_or_others_is_refused() {
        let dir = TestDir::new();
        let path = dir.join("key");
        write_key_file(&path, &SecretBytes::from_slice(&BYTES)).unwrap();
        for mode in [0o644, 0o640, 0o604, 0o620, 0o602] {
            chmod(&path, mode);
            let err = read_key_file(&path).unwrap_err();
            assert!(
                matches!(
                    &err,
                    HostError::Permissions { path: p, mode: m, refusal: Refusal::GroupOrOtherAccess }
                        if p == &path && m & 0o777 == mode
                ),
                "{mode:o}: {err:?}"
            );
            assert!(!err.to_string().contains(HEX));
            assert!(err.to_string().contains("chmod go-rwx"), "{err}");
        }
        chmod(&path, 0o400);
        assert_eq!(read_key_file(&path).unwrap(), SecretBytes::from_slice(&BYTES));
    }

    #[test]
    fn a_key_file_with_other_text_is_a_format_error_that_does_not_echo_it() {
        let dir = TestDir::new();
        let path = dir.join("key");
        let wrong = format!("{HEX}{HEX}\n");
        std::fs::write(&path, &wrong).unwrap();
        chmod(&path, 0o600);
        let err = read_key_file(&path).unwrap_err();
        assert!(matches!(&err, HostError::Format { path: p, .. } if p == &path), "{err:?}");
        assert!(!err.to_string().contains(HEX));
        assert!(!format!("{err:?}").contains(HEX));
    }

    #[test]
    fn a_missing_key_file_is_an_io_error() {
        let dir = TestDir::new();
        let err = read_key_file(&dir.join("absent")).unwrap_err();
        assert!(matches!(&err, HostError::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound), "{err:?}");
    }

    #[test]
    fn a_key_command_that_prints_the_text_form_gives_the_key() {
        let key = key_from_command(&format!("printf '%s\\n' {HEX}")).unwrap();
        assert_eq!(to_array(&key), BYTES);
    }

    #[test]
    fn surrounding_whitespace_in_key_command_output_is_ignored() {
        let key = key_from_command(&format!("printf '  \\t{}\\n\\n\\n'", HEX.to_uppercase())).unwrap();
        assert_eq!(to_array(&key), BYTES);
    }

    #[test]
    fn a_key_command_that_exits_non_zero_fails_even_with_a_valid_key() {
        let err = key_from_command(&format!("printf '%s\\n' {HEX}; exit 3")).unwrap_err();
        let HostError::Command { reason } = &err else { panic!("{err:?}") };
        assert!(reason.contains('3'), "{reason}");
        assert!(!reason.contains(HEX));
    }

    #[test]
    fn a_key_command_that_prints_something_else_fails_without_echoing_it() {
        let secret_looking = "z".repeat(64);
        for command in [
            format!("echo {secret_looking}"),
            format!("printf '%s\\n' {}", &HEX[..63]),
            format!("printf '%s %s\\n' {HEX} {HEX}"),
            "true".to_string(),
        ] {
            let err = key_from_command(&command).unwrap_err();
            assert!(matches!(err, HostError::Command { .. }), "{command}: {err:?}");
            let message = err.to_string();
            assert!(!message.contains(&secret_looking) && !message.contains(&HEX[..63]), "{message}");
        }
    }

    #[test]
    fn key_command_output_up_to_the_limit_is_read_and_longer_output_is_refused() {
        // The key followed by spaces: exactly the limit, then one byte more.
        let padding = MAX_OUTPUT_LEN - HEX.len();
        let key = key_from_command(&format!("printf '%s%{padding}s' {HEX} ''")).unwrap();
        assert_eq!(to_array(&key), BYTES);
        let err = key_from_command(&format!("printf '%s%{}s' {HEX} ''", padding + 1)).unwrap_err();
        let HostError::Command { reason } = &err else { panic!("{err:?}") };
        assert_eq!(reason, &format!("output is longer than {MAX_OUTPUT_LEN} bytes"));
        assert!(!reason.contains(HEX));
    }

    #[test]
    fn a_key_command_that_keeps_its_output_open_past_the_limit_is_stopped_at_once() {
        // `exec` keeps the pipe open in a process that would run for 30 s; reading the
        // whole output first would wait for it.
        let started = std::time::Instant::now();
        let err = key_from_command("printf '%2000s' ''; exec sleep 30").unwrap_err();
        assert!(matches!(&err, HostError::Command { reason } if reason.contains("longer than")), "{err:?}");
        assert!(started.elapsed() < std::time::Duration::from_secs(15), "took {:?}", started.elapsed());
    }

    #[test]
    fn to_array_copies_the_key_bytes() {
        assert_eq!(to_array(&SecretBytes::from_slice(&BYTES)), BYTES);
    }
}
