//! [`HostError`]: everything that can go wrong between the program and the OS
//! (`docs/PROGRAM.md` "lk-host", Errors).

use core::fmt;
use std::io;
use std::path::PathBuf;

/// A failure of the state directory, the identity file, the storage key or a key command.
///
/// Messages name paths and describe the problem; they never contain file contents, key
/// bytes or command output (`docs/PROGRAM.md` "Rules for program crates", Secrets).
#[derive(Debug)]
pub enum HostError {
    /// An operation on `path` failed.
    Io { path: PathBuf, source: io::Error },
    /// `path` is refused because of its type or permissions; `refusal` says which. `mode`
    /// is the entry's own `st_mode` (file type and permission bits) as `symlink_metadata`
    /// or the open file reported it.
    Permissions { path: PathBuf, mode: u32, refusal: Refusal },
    /// Another process holds the state directory's lock file `path`; `pid` is the process
    /// id it wrote there, when it could be read.
    Locked { path: PathBuf, pid: Option<u32> },
    /// `path` exists but its contents are not in the expected format. `reason` describes
    /// the format, never the bytes found.
    Format { path: PathBuf, reason: String },
    /// The key command could not run, failed, or printed something other than a key.
    /// `reason` never contains the command's output.
    Command { reason: String },
}

/// Why [`HostError::Permissions`] refused a path.
///
/// The mode alone cannot tell the refusals apart: a key file and a state path can both be
/// regular files with mode 0644, and only the key file is fixed by `chmod go-rwx`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The path is a symbolic link: the state path itself, or an entry this crate opens
    /// by name inside the state directory (`lock`, `<name>.rec`). It is never followed.
    SymbolicLink,
    /// The mode grants group or other permission: a state directory or a key file.
    GroupOrOtherAccess,
    /// The state path exists but is not a directory.
    NotADirectory,
    /// An entry in the state directory that must be a regular file is something else.
    NotARegularFile,
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Permissions { path, mode, refusal } => match refusal {
                Refusal::SymbolicLink => write!(f, "{} is a symbolic link; refusing to follow it", path.display()),
                Refusal::GroupOrOtherAccess => write!(
                    f,
                    "{} has mode {:04o}, which grants group or other access; remove it with chmod go-rwx",
                    path.display(),
                    mode & 0o7777
                ),
                Refusal::NotADirectory => write!(f, "{} is not a directory", path.display()),
                Refusal::NotARegularFile => write!(f, "{} is not a regular file", path.display()),
            },
            Self::Locked { path, pid: Some(pid) } => {
                write!(f, "{} is held by another running process (pid {pid})", path.display())
            }
            Self::Locked { path, pid: None } => write!(f, "{} is held by another running process", path.display()),
            Self::Format { path, reason } => write!(f, "{}: {reason}", path.display()),
            Self::Command { reason } => write!(f, "key command: {reason}"),
        }
    }
}

impl std::error::Error for HostError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl HostError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io { path: path.into(), source }
    }

    pub(crate) fn format(path: impl Into<PathBuf>, reason: impl Into<String>) -> Self {
        Self::Format { path: path.into(), reason: reason.into() }
    }

    pub(crate) fn refused(path: impl Into<PathBuf>, mode: u32, refusal: Refusal) -> Self {
        Self::Permissions { path: path.into(), mode, refusal }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_messages_name_the_refusal_not_a_guess_from_the_mode() {
        let message = |mode, refusal| HostError::refused("/s", mode, refusal).to_string();
        assert_eq!(message(0o120_755, Refusal::SymbolicLink), "/s is a symbolic link; refusing to follow it");
        assert_eq!(
            message(0o040_750, Refusal::GroupOrOtherAccess),
            "/s has mode 0750, which grants group or other access; remove it with chmod go-rwx"
        );
        // A key file with this mode is fixed by chmod; a state path with it is not.
        assert_eq!(
            message(0o100_644, Refusal::GroupOrOtherAccess),
            "/s has mode 0644, which grants group or other access; remove it with chmod go-rwx"
        );
        assert_eq!(message(0o100_644, Refusal::NotADirectory), "/s is not a directory");
        assert_eq!(message(0o040_700, Refusal::NotARegularFile), "/s is not a regular file");
    }

    #[test]
    fn locked_message_names_the_pid_when_known() {
        let known = HostError::Locked { path: "/s/lock".into(), pid: Some(42) };
        assert_eq!(known.to_string(), "/s/lock is held by another running process (pid 42)");
        let unknown = HostError::Locked { path: "/s/lock".into(), pid: None };
        assert_eq!(unknown.to_string(), "/s/lock is held by another running process");
    }

    #[test]
    fn io_errors_expose_their_source() {
        let error = HostError::io("/s/fido.rec", io::Error::from(io::ErrorKind::NotFound));
        assert!(std::error::Error::source(&error).is_some());
        assert!(error.to_string().starts_with("/s/fido.rec: "));
        assert!(std::error::Error::source(&HostError::Command { reason: "x".into() }).is_none());
    }
}
