//! Fresh private directories for this crate's unit tests (`docs/PROGRAM.md` "Rules for
//! program crates": short names under `std::env::temp_dir()`, removed at the end).

use std::fs::{self, DirBuilder, Permissions};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// A directory `<temp>/lkh<pid>-<n>` with mode 0700, removed on drop. Drop restores mode
/// 0700 first, so a test that made it read-only and then failed still cleans up.
#[derive(Debug)]
pub(crate) struct TestDir(PathBuf);

impl TestDir {
    pub(crate) fn new() -> Self {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("lkh{}-{n}", std::process::id()));
        // A leftover of an earlier run that died with the same pid.
        let _ = fs::remove_dir_all(&path);
        DirBuilder::new().mode(0o700).create(&path).expect("a fresh test directory can be created");
        Self(path)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    pub(crate) fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.0, Permissions::from_mode(0o700));
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Set the permission bits of `path`.
pub(crate) fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, Permissions::from_mode(mode)).expect("the test owns this path");
}

/// The permission bits of `path` (symbolic links not followed).
pub(crate) fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;
    fs::symlink_metadata(path).expect("the test created this path").mode() & 0o7777
}
