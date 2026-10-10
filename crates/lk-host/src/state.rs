//! The state directory and [`FileStore`] (`docs/PROGRAM.md` "lk-host", State directory
//! and `FileStore`).
//!
//! ```text
//! <state>/            mode 0700, created if missing
//!   lock              process lock (File::try_lock, held for the store's lifetime); holds the pid
//!   identity          plaintext, "serial=<decimal>\n", written once on first run
//!   device.rec  fido.rec  oath.rec  otp.rec  piv.rec  openpgp.rec  hsmauth.rec  sd.rec
//!                     sealed record bytes, mode 0600
//!   *.tmp             leftovers of an interrupted save; removed at open
//! ```
//!
//! Every write goes to `<name>.tmp` first and is renamed over its target after
//! `sync_all`, then the directory is `sync_all`ed, so after a crash a file holds either
//! its old or its new bytes (`lk_core::Store`: `save` must be atomic). A state directory
//! that [`FileStore::open`] creates is made durable the same way: its parent is
//! `sync_all`ed, because the new entry lives there. On macOS `sync_all` is `fsync`, not
//! `F_FULLFSYNC`: that needs `fcntl`, which needs `unsafe`. The drive's own write cache
//! can therefore still lose the newest save on power loss; documented and accepted
//! (`docs/PROGRAM.md`).
//!
//! Symbolic links are never followed: not as the state path (refused however it is
//! spelled, see [`FileStore::open`]), not as `lock` or `<name>.rec` (refused with
//! [`Refusal::SymbolicLink`]), and not as a tmp file (a new one is always created with
//! `create_new`, so a link of that name is replaced, never written through). The checks
//! go by path: std offers no `openat` or `O_NOFOLLOW` without `unsafe` or per-OS flag
//! values, so a process that can write the 0700 directory, which is the same user, can
//! still race them. Accepted.

use core::fmt;
use std::fs::{self, DirBuilder, File, Metadata, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use lk_core::{Record, Store, StoreError};

use crate::{HostError, Refusal};

/// Name of the lock file in the state directory.
pub const LOCK_FILE: &str = "lock";

/// The fixed file name stem of each record: `<stem>.rec` holds its sealed bytes.
pub fn record_name(record: Record) -> &'static str {
    match record {
        Record::Device => "device",
        Record::Fido => "fido",
        Record::Oath => "oath",
        Record::Otp => "otp",
        Record::Piv => "piv",
        Record::OpenPgp => "openpgp",
        Record::HsmAuth => "hsmauth",
        Record::SecurityDomain => "sd",
    }
}

fn record_file(record: Record) -> String {
    format!("{}.rec", record_name(record))
}

/// A [`Store`] of sealed records, one file per record, in a private state directory.
///
/// The store holds the directory's lock file open and locked for its whole lifetime;
/// dropping it releases the lock, so the next [`FileStore::open`] of the directory
/// succeeds. It is `Send`, so a program can build it on one thread and hand it to the
/// thread that opens the device.
pub struct FileStore {
    dir: PathBuf,
    /// The locked lock file; closing it (dropping the store) releases the lock.
    _lock: File,
}

impl FileStore {
    /// Open the state directory `dir`:
    ///
    /// 1. normalise the path with [`Path::components`]: no trailing `/`, no `.` after the
    ///    first component. `lstat("link/")` and `lstat("link/.")` follow a symbolic link,
    ///    so the checks below must see the last component itself; shell completion adds
    ///    that `/` to a linked directory. Links in earlier components are allowed (on
    ///    macOS `/var` and `/tmp` are links);
    /// 2. create it with mode 0700 if it is missing (its parent must exist, and is then
    ///    `sync_all`ed), and refuse it with [`HostError::Permissions`] if it is a
    ///    symbolic link, not a directory, or its mode grants any group/other permission
    ///    ([`Refusal`] says which);
    /// 3. take the process lock on `dir/lock` ([`HostError::Locked`] while another
    ///    process, or another `FileStore` in this one, holds it, with the pid read from
    ///    the file when available) and write this process's pid into it. A `lock` that is
    ///    a symbolic link or not a regular file is refused, and its target left alone;
    /// 4. remove the `*.tmp` entries an interrupted save left behind (a link of that name
    ///    is removed itself, not its target).
    pub fn open(dir: &Path) -> Result<FileStore, HostError> {
        let dir: PathBuf = dir.components().collect();
        prepare_dir(&dir)?;
        let lock = take_lock(&dir)?;
        remove_leftovers(&dir)?;
        Ok(FileStore { dir, _lock: lock })
    }

    /// The state directory, in the normalised spelling [`FileStore::open`] checked.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn record_path(&self, record: Record) -> PathBuf {
        self.dir.join(record_file(record))
    }
}

impl Store for FileStore {
    /// The sealed bytes of `record`; a missing file is `Ok(None)` and any other I/O error
    /// is `Err`. So is a record file that is a symbolic link, dangling or not: it is not
    /// followed, and not mistaken for a missing record either. `lk_device` reports a
    /// record that fails to load as unreadable instead of starting it from factory state.
    fn load(&mut self, record: Record) -> Result<Option<Vec<u8>>, StoreError> {
        let path = self.record_path(record);
        let loaded = match regular_entry(&path) {
            Ok(None) => return Ok(None),
            Ok(Some(_)) => fs::read(&path).map_err(|err| HostError::io(&path, err)),
            Err(err) => Err(err),
        };
        loaded.map(Some).map_err(|err| StoreError(err.to_string()))
    }

    /// Replace the record's file atomically (see the module documentation). Any failure
    /// is `Err` and, up to the rename, leaves the previous record intact. A failure of
    /// the final directory `sync_all` is reported too, although the new bytes are then
    /// already in place: `docs/PROGRAM.md` says every failure leaves the previous record
    /// intact, which cannot hold after the rename, and a retried `fsync` proves nothing.
    /// The engine keeps its previous in-memory state, so the file is ahead of memory
    /// until the next save of the record.
    fn save(&mut self, record: Record, sealed: &[u8]) -> Result<(), StoreError> {
        write_atomically(&self.dir, &record_file(record), sealed).map_err(|err| StoreError(err.to_string()))
    }
}

impl fmt::Debug for FileStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileStore").field("dir", &self.dir).finish()
    }
}

/// Create `dir` (mode 0700) if it is missing, then [`check_private_dir`]. A directory
/// created here is made durable by a `sync_all` of its parent: a sync of `dir` itself,
/// which every save does, does not cover the entry that names it.
fn prepare_dir(dir: &Path) -> Result<(), HostError> {
    match fs::symlink_metadata(dir) {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => match DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => sync_dir(parent_dir(dir))?,
            // Another process may have created it meanwhile; the check below decides.
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(HostError::io(dir, err)),
        },
        Err(err) => return Err(HostError::io(dir, err)),
    }
    check_private_dir(dir)
}

/// Refuse `dir` unless it is a real directory (not a symbolic link) whose mode grants no
/// group/other permission. The type is checked first: no `chmod` fixes a path that is
/// not a directory. Ownership is not compared: std has no `getuid` without `unsafe`, and
/// another user's 0700 directory cannot be written to anyway.
fn check_private_dir(dir: &Path) -> Result<(), HostError> {
    let metadata = fs::symlink_metadata(dir).map_err(|err| HostError::io(dir, err))?;
    let (file_type, mode) = (metadata.file_type(), metadata.mode());
    let refusal = if file_type.is_symlink() {
        Refusal::SymbolicLink
    } else if !file_type.is_dir() {
        Refusal::NotADirectory
    } else if mode & 0o077 != 0 {
        Refusal::GroupOrOtherAccess
    } else {
        return Ok(());
    };
    Err(HostError::refused(dir, mode, refusal))
}

/// The `symlink_metadata` of `path`, an entry this crate opens by name inside the state
/// directory: `None` if it is missing, [`HostError::Permissions`] if it is a symbolic link
/// (it could point anywhere) or anything but a regular file.
fn regular_entry(path: &Path) -> Result<Option<Metadata>, HostError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(HostError::io(path, err)),
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        Err(HostError::refused(path, metadata.mode(), Refusal::SymbolicLink))
    } else if !file_type.is_file() {
        Err(HostError::refused(path, metadata.mode(), Refusal::NotARegularFile))
    } else {
        Ok(Some(metadata))
    }
}

/// Lock `dir/lock` (`File::try_lock`, an exclusive `flock` on macOS and Linux) and write
/// this process's pid into it. The lock belongs to the open file, so it is held until the
/// returned `File` is closed, and a second open in the same process is refused too.
///
/// The file is created with `create_new`, which never follows a symbolic link. An
/// existing entry must be a regular file ([`regular_entry`]) before it is opened, without
/// `create` (a dangling link cannot create a file elsewhere), and must still be the file
/// that was opened afterwards, before anything is written to it.
fn take_lock(dir: &Path) -> Result<File, HostError> {
    let path = dir.join(LOCK_FILE);
    let mut options = OpenOptions::new();
    // Never truncated at open: the holder's pid must stay readable for the error below.
    options.read(true).write(true).mode(0o600);
    let mut file = match options.clone().create_new(true).open(&path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            regular_entry(&path)?;
            options.open(&path).map_err(|err| HostError::io(&path, err))?
        }
        Err(err) => return Err(HostError::io(&path, err)),
    };
    let opened = file.metadata().map_err(|err| HostError::io(&path, err))?;
    if !regular_entry(&path)?.is_some_and(|entry| entry.dev() == opened.dev() && entry.ino() == opened.ino()) {
        return Err(HostError::io(&path, io::Error::other("replaced while it was being opened")));
    }
    match file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => {
            let mut text = String::new();
            let pid = (&file).take(32).read_to_string(&mut text).ok().and_then(|_| text.trim().parse().ok());
            return Err(HostError::Locked { path, pid });
        }
        Err(TryLockError::Error(err)) => return Err(HostError::io(&path, err)),
    }
    let pid = format!("{}\n", std::process::id());
    file.set_len(0)
        .and_then(|()| file.write_all(pid.as_bytes()))
        .map_err(|err| HostError::io(&path, err))?;
    Ok(file)
}

/// Remove every `*.tmp` entry in `dir` but directories: `DirEntry::file_type` does not
/// follow links, so a link of that name is removed itself.
fn remove_leftovers(dir: &Path) -> Result<(), HostError> {
    for entry in fs::read_dir(dir).map_err(|err| HostError::io(dir, err))? {
        let entry = entry.map_err(|err| HostError::io(dir, err))?;
        if !entry.file_name().as_bytes().ends_with(b".tmp") {
            continue;
        }
        let path = entry.path();
        let is_dir = entry.file_type().map_err(|err| HostError::io(&path, err))?.is_dir();
        if !is_dir {
            fs::remove_file(&path).map_err(|err| HostError::io(&path, err))?;
        }
    }
    Ok(())
}

/// Replace `dir/name` with `bytes`: write a new `dir/name.tmp` (mode 0600), `write_all`,
/// `sync_all`, rename it over `dir/name`, then `sync_all` the directory. Until the rename
/// every failure leaves `dir/name` untouched and removes the tmp file.
///
/// An entry already named `dir/name.tmp` is removed first and the tmp file is opened with
/// `create_new` (`O_EXCL`), which refuses any existing entry, a symbolic link included:
/// the bytes only ever land in a new regular file, never in a link's target. The rename
/// replaces a link at `dir/name` itself, not its target.
pub(crate) fn write_atomically(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), HostError> {
    let target = dir.join(name);
    let tmp = dir.join(format!("{name}.tmp"));
    // Opened first, so that only the final sync can fail once the rename is done.
    let directory = File::open(dir).map_err(|err| HostError::io(dir, err))?;
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(HostError::io(tmp, err)),
    }
    let written = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        });
    if let Err(err) = written {
        let _ = fs::remove_file(&tmp);
        return Err(HostError::io(tmp, err));
    }
    if let Err(err) = fs::rename(&tmp, &target) {
        let _ = fs::remove_file(&tmp);
        return Err(HostError::io(target, err));
    }
    directory.sync_all().map_err(|err| HostError::io(dir, err))
}

/// `sync_all` the directory `dir`, so that a new or renamed entry in it is durable.
pub(crate) fn sync_dir(dir: &Path) -> Result<(), HostError> {
    File::open(dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|err| HostError::io(dir, err))
}

/// The directory that holds the entry `path`: its parent, or `.` for a bare name.
pub(crate) fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::test_dir::{TestDir, chmod, mode_of};
    use std::os::unix::fs::symlink;

    const ALL: [Record; 8] = [
        Record::Device,
        Record::Fido,
        Record::Oath,
        Record::Otp,
        Record::Piv,
        Record::OpenPgp,
        Record::HsmAuth,
        Record::SecurityDomain,
    ];

    fn names_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> =
            fs::read_dir(dir).unwrap().map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        names
    }

    #[test]
    fn a_missing_record_loads_as_none() {
        let dir = TestDir::new();
        let mut store = FileStore::open(dir.path()).unwrap();
        for record in ALL {
            assert_eq!(store.load(record), Ok(None));
        }
    }

    #[test]
    fn a_saved_record_loads_back_and_the_next_save_replaces_it() {
        let dir = TestDir::new();
        let mut store = FileStore::open(dir.path()).unwrap();
        store.save(Record::Oath, b"first").unwrap();
        assert_eq!(store.load(Record::Oath), Ok(Some(b"first".to_vec())));
        store.save(Record::Oath, b"second, longer").unwrap();
        assert_eq!(store.load(Record::Oath), Ok(Some(b"second, longer".to_vec())));
        store.save(Record::Oath, b"").unwrap();
        assert_eq!(store.load(Record::Oath), Ok(Some(Vec::new())));
        assert_eq!(mode_of(&dir.join("oath.rec")), 0o600);
        assert_eq!(names_in(dir.path()), ["lock", "oath.rec"]);
    }

    #[test]
    fn every_record_has_its_fixed_file_name() {
        let dir = TestDir::new();
        let mut store = FileStore::open(dir.path()).unwrap();
        for (i, record) in ALL.into_iter().enumerate() {
            store.save(record, &[i as u8]).unwrap();
        }
        assert_eq!(
            names_in(dir.path()),
            [
                "device.rec",
                "fido.rec",
                "hsmauth.rec",
                "lock",
                "oath.rec",
                "openpgp.rec",
                "otp.rec",
                "piv.rec",
                "sd.rec"
            ]
        );
        for (i, record) in ALL.into_iter().enumerate() {
            assert_eq!(fs::read(dir.join(&record_file(record))).unwrap(), [i as u8]);
            assert_eq!(store.load(record), Ok(Some(vec![i as u8])));
        }
    }

    #[test]
    fn a_failed_save_keeps_the_previous_record_and_reports_an_error() {
        let dir = TestDir::new();
        let mut store = FileStore::open(dir.path()).unwrap();
        store.save(Record::Piv, b"previous").unwrap();
        chmod(dir.path(), 0o500);
        // A process that ignores permissions (root) cannot exercise this failure.
        if File::create(dir.join("probe")).is_ok() {
            eprintln!("skipped: the directory stayed writable at mode 0500");
            return;
        }
        let err = store.save(Record::Piv, b"replacement").unwrap_err();
        chmod(dir.path(), 0o700);
        assert!(err.0.contains("piv.rec.tmp"), "{err}");
        assert!(!err.0.contains("replacement"));
        assert_eq!(fs::read(dir.join("piv.rec")).unwrap(), b"previous");
        assert_eq!(store.load(Record::Piv), Ok(Some(b"previous".to_vec())));
        assert_eq!(names_in(dir.path()), ["lock", "piv.rec"]);
        store.save(Record::Piv, b"replacement").unwrap();
        assert_eq!(store.load(Record::Piv), Ok(Some(b"replacement".to_vec())));
    }

    #[test]
    fn a_record_path_that_cannot_be_read_is_a_load_error_not_absent() {
        let dir = TestDir::new();
        let mut store = FileStore::open(dir.path()).unwrap();
        fs::create_dir(dir.join("fido.rec")).unwrap();
        let err = store.load(Record::Fido).unwrap_err();
        assert!(err.0.contains("fido.rec"), "{err}");
    }

    #[test]
    fn leftover_tmp_files_are_removed_at_open_and_nothing_else() {
        let dir = TestDir::new();
        for name in ["fido.rec.tmp", "identity.tmp", "x.tmp", "fido.rec", "notes.txt", "tmp"] {
            fs::write(dir.join(name), b"x").unwrap();
        }
        fs::create_dir(dir.join("kept.tmp")).unwrap();
        symlink(dir.join("notes.txt"), dir.join("link.tmp")).unwrap();
        let store = FileStore::open(dir.path()).unwrap();
        assert_eq!(names_in(store.dir()), ["fido.rec", "kept.tmp", "lock", "notes.txt", "tmp"]);
        // A link is removed itself, not its target.
        assert_eq!(fs::read(dir.join("notes.txt")).unwrap(), b"x");
    }

    #[test]
    fn a_save_replaces_a_planted_tmp_symlink_instead_of_writing_through_it() {
        let dir = TestDir::new();
        let state = dir.join("s");
        let victim = dir.join("victim");
        DirBuilder::new().mode(0o700).create(&state).unwrap();
        fs::write(&victim, b"unrelated file\n").unwrap();
        let mut store = FileStore::open(&state).unwrap();
        store.save(Record::Fido, b"old sealed record").unwrap();
        // Planted while the store is live, so the cleanup at open does not see it.
        for target in [&victim, &dir.join("absent")] {
            symlink(target, state.join("fido.rec.tmp")).unwrap();
            store.save(Record::Fido, b"new sealed record").unwrap();
            let record = fs::symlink_metadata(state.join("fido.rec")).unwrap();
            assert!(record.file_type().is_file(), "{target:?}: fido.rec is not a regular file");
            assert_eq!(record.mode() & 0o7777, 0o600);
            assert_eq!(store.load(Record::Fido), Ok(Some(b"new sealed record".to_vec())));
            assert_eq!(names_in(&state), ["fido.rec", "lock"]);
        }
        assert_eq!(fs::read(&victim).unwrap(), b"unrelated file\n");
        assert!(!dir.join("absent").exists());
    }

    #[test]
    fn a_record_that_is_a_symbolic_link_is_a_load_error_not_absent() {
        let dir = TestDir::new();
        let state = dir.join("s");
        let elsewhere = dir.join("elsewhere");
        DirBuilder::new().mode(0o700).create(&state).unwrap();
        fs::write(&elsewhere, b"sealed bytes").unwrap();
        let mut store = FileStore::open(&state).unwrap();
        symlink(&elsewhere, state.join("oath.rec")).unwrap();
        symlink(dir.join("absent"), state.join("piv.rec")).unwrap();
        for record in [Record::Oath, Record::Piv] {
            let err = store.load(record).unwrap_err();
            let expected = format!("{}.rec is a symbolic link; refusing to follow it", record_name(record));
            assert!(err.0.ends_with(&expected), "{err}");
        }
        // A save replaces the link itself, never its target.
        store.save(Record::Oath, b"new").unwrap();
        assert_eq!(store.load(Record::Oath), Ok(Some(b"new".to_vec())));
        assert_eq!(fs::read(&elsewhere).unwrap(), b"sealed bytes");
    }

    #[test]
    fn a_second_open_is_locked_until_the_first_store_is_dropped() {
        let dir = TestDir::new();
        let first = FileStore::open(dir.path()).unwrap();
        let pid = std::process::id();
        assert_eq!(fs::read_to_string(dir.join(LOCK_FILE)).unwrap(), format!("{pid}\n"));
        assert_eq!(mode_of(&dir.join(LOCK_FILE)), 0o600);
        // A tmp file of the live store is not touched by the refused open.
        fs::write(dir.join("otp.rec.tmp"), b"in flight").unwrap();
        let err = FileStore::open(dir.path()).unwrap_err();
        assert!(
            matches!(&err, HostError::Locked { path, pid: Some(p) } if path == &dir.join(LOCK_FILE) && *p == pid),
            "{err:?}"
        );
        assert!(dir.join("otp.rec.tmp").exists());
        // The refused attempt did not release or rewrite the holder's lock.
        assert!(matches!(FileStore::open(dir.path()), Err(HostError::Locked { .. })));
        assert_eq!(fs::read_to_string(dir.join(LOCK_FILE)).unwrap(), format!("{pid}\n"));
        drop(first);
        let second = FileStore::open(dir.path()).unwrap();
        assert_eq!(second.dir(), dir.path());
        assert!(!dir.join("otp.rec.tmp").exists());
    }

    #[test]
    fn a_lock_entry_that_is_a_symbolic_link_is_refused_and_its_target_left_alone() {
        let dir = TestDir::new();
        let state = dir.join("s");
        let lock = state.join(LOCK_FILE);
        let victim = dir.join("victim");
        DirBuilder::new().mode(0o700).create(&state).unwrap();
        fs::write(&victim, b"not a lock file\n").unwrap();
        // A link to a file, and a dangling one: neither target is written or created.
        for target in [&victim, &dir.join("absent")] {
            symlink(target, &lock).unwrap();
            let err = FileStore::open(&state).unwrap_err();
            assert!(
                matches!(&err, HostError::Permissions { path, refusal: Refusal::SymbolicLink, .. } if path == &lock),
                "{target:?}: {err:?}"
            );
            fs::remove_file(&lock).unwrap();
        }
        assert_eq!(fs::read(&victim).unwrap(), b"not a lock file\n");
        assert!(!dir.join("absent").exists());
        FileStore::open(&state).unwrap();
    }

    #[test]
    fn a_lock_entry_that_is_not_a_regular_file_is_refused() {
        let dir = TestDir::new();
        fs::create_dir(dir.join(LOCK_FILE)).unwrap();
        let err = FileStore::open(dir.path()).unwrap_err();
        assert!(matches!(&err, HostError::Permissions { refusal: Refusal::NotARegularFile, .. }), "{err:?}");
        assert!(err.to_string().ends_with("/lock is not a regular file"), "{err}");
    }

    #[test]
    fn a_lock_file_left_by_a_dead_process_does_not_block_open() {
        let dir = TestDir::new();
        fs::write(dir.join(LOCK_FILE), b"4194304000\n").unwrap();
        let _store = FileStore::open(dir.path()).unwrap();
        assert_eq!(fs::read_to_string(dir.join(LOCK_FILE)).unwrap(), format!("{}\n", std::process::id()));
    }

    #[test]
    fn a_missing_state_directory_is_created_with_mode_0700() {
        let dir = TestDir::new();
        let state = dir.join("s");
        let store = FileStore::open(&state).unwrap();
        assert_eq!(store.dir(), state);
        assert_eq!(mode_of(&state), 0o700);
        assert!(state.join(LOCK_FILE).is_file());
    }

    #[test]
    fn a_state_path_with_a_trailing_slash_or_dot_names_the_directory_itself() {
        let dir = TestDir::new();
        let state = dir.join("s");
        let store = FileStore::open(Path::new(&format!("{}/./", state.display()))).unwrap();
        assert_eq!(store.dir().as_os_str(), state.as_os_str());
        assert_eq!(mode_of(&state), 0o700);
        assert!(state.join(LOCK_FILE).is_file());
    }

    #[test]
    fn the_parent_of_a_bare_name_is_the_current_directory() {
        assert_eq!(parent_dir(Path::new("s")), Path::new("."));
        assert_eq!(parent_dir(Path::new("a/s")), Path::new("a"));
        assert_eq!(parent_dir(Path::new("/s")), Path::new("/"));
    }

    #[test]
    fn a_state_directory_whose_parent_is_missing_is_an_io_error() {
        let dir = TestDir::new();
        let err = FileStore::open(&dir.join("a").join("b")).unwrap_err();
        assert!(matches!(err, HostError::Io { .. }), "{err:?}");
        assert!(!dir.join("a").exists());
    }

    #[test]
    fn a_state_directory_open_to_group_or_others_is_refused() {
        let dir = TestDir::new();
        let state = dir.join("s");
        fs::create_dir(&state).unwrap();
        for mode in [0o750, 0o705, 0o770, 0o701, 0o710, 0o755] {
            chmod(&state, mode);
            let err = FileStore::open(&state).unwrap_err();
            assert!(
                matches!(
                    &err,
                    HostError::Permissions { path, mode: m, refusal: Refusal::GroupOrOtherAccess }
                        if path == &state && m & 0o777 == mode
                ),
                "{mode:o}: {err:?}"
            );
            assert!(err.to_string().contains("chmod go-rwx"), "{err}");
        }
        // Nothing was created in the refused directory.
        assert!(names_in(&state).is_empty());
        chmod(&state, 0o700);
        FileStore::open(&state).unwrap();
    }

    #[test]
    fn a_symlinked_state_path_is_refused() {
        let dir = TestDir::new();
        let real = dir.join("real");
        let link = dir.join("link");
        DirBuilder::new().mode(0o700).create(&real).unwrap();
        symlink(&real, &link).unwrap();
        let err = FileStore::open(&link).unwrap_err();
        assert!(
            matches!(&err, HostError::Permissions { path, refusal: Refusal::SymbolicLink, .. } if path == &link),
            "{err:?}"
        );
        assert!(err.to_string().contains("symbolic link"), "{err}");
        assert!(names_in(&real).is_empty());
    }

    #[test]
    fn a_symlinked_state_path_is_refused_even_with_a_trailing_slash_or_dot() {
        // Shell completion adds the `/` to a linked directory, and `lstat("link/")`
        // follows the link.
        let dir = TestDir::new();
        let real = dir.join("real");
        let link = dir.join("link");
        let dangling = dir.join("dangling");
        DirBuilder::new().mode(0o700).create(&real).unwrap();
        symlink(&real, &link).unwrap();
        symlink(dir.join("absent"), &dangling).unwrap();
        for path in [&link, &dangling] {
            for suffix in ["/", "/.", "//", "/./"] {
                let spelled = format!("{}{suffix}", path.display());
                let err = FileStore::open(Path::new(&spelled)).unwrap_err();
                assert!(
                    matches!(&err, HostError::Permissions { path: p, refusal: Refusal::SymbolicLink, .. } if p == path),
                    "{spelled:?}: {err:?}"
                );
            }
        }
        assert!(names_in(&real).is_empty());
        assert!(!dir.join("absent").exists());
    }

    #[test]
    fn a_state_path_that_is_a_file_is_refused_as_not_a_directory_whatever_its_mode() {
        let dir = TestDir::new();
        let file = dir.join("f");
        fs::write(&file, b"").unwrap();
        // With group/other bits too: no chmod fixes the real problem.
        for mode in [0o600, 0o644] {
            chmod(&file, mode);
            let err = FileStore::open(&file).unwrap_err();
            assert!(
                matches!(&err, HostError::Permissions { path, refusal: Refusal::NotADirectory, .. } if path == &file),
                "{mode:o}: {err:?}"
            );
            assert_eq!(err.to_string(), format!("{} is not a directory", file.display()));
        }
    }

    #[test]
    fn file_store_is_send_and_debug_names_only_the_directory() {
        fn assert_send<T: Send>() {}
        assert_send::<FileStore>();
        let dir = TestDir::new();
        let store = FileStore::open(dir.path()).unwrap();
        assert_eq!(format!("{store:?}"), format!("FileStore {{ dir: {:?} }}", dir.path()));
    }

    #[test]
    fn record_names_follow_the_contract() {
        let names: Vec<&str> = ALL.into_iter().map(record_name).collect();
        assert_eq!(names, ["device", "fido", "oath", "otp", "piv", "openpgp", "hsmauth", "sd"]);
    }
}
