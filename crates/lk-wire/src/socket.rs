//! Socket placement and the accept thread shared by the wire and control sockets
//! (`docs/PROGRAM.md` "lk-wire", "Socket placement").

use std::fs::{self, Metadata, Permissions};
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::WireError;

/// Pause after a failed `accept` (for example when the process is out of descriptors),
/// so the loop does not spin.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

fn io_error(path: &Path) -> impl FnOnce(io::Error) -> WireError + '_ {
    move |source| WireError::Io { path: path.to_owned(), source }
}

/// The socket file a server bound: its path and the file's device and inode numbers.
///
/// The placement rules replace an existing socket, so another server (a misconfiguration
/// such as the same path for the wire and the control socket) can take the path over while
/// this one still runs. A server only touches the file at its path while it is still the
/// one it bound: it neither removes the other server's socket nor connects to it. The inode
/// cannot be reused meanwhile, because the bound socket keeps it alive. A replacement
/// between the check and the action is not guarded against; this is hardening against a
/// misconfiguration, not against an adversary (the parent directory is private).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SocketFile {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl SocketFile {
    fn of(path: &Path, meta: &Metadata) -> SocketFile {
        SocketFile { path: path.to_owned(), device: meta.dev(), inode: meta.ino() }
    }

    /// The socket path.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Whether the path still holds the socket file this server bound.
    pub(crate) fn is_ours(&self) -> bool {
        fs::symlink_metadata(&self.path).is_ok_and(|meta| {
            meta.file_type().is_socket() && meta.dev() == self.device && meta.ino() == self.inode
        })
    }

    /// Remove the socket file if it is still ours; anything else at the path is left alone.
    pub(crate) fn remove(&self) {
        if self.is_ours() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Bind a listening socket at `path`:
///
/// - the parent directory must exist and grant no group or other permission. Ownership is
///   not compared: std has no `getuid` without `unsafe`, and another user's 0700 directory
///   cannot be written to anyway;
/// - an existing socket at `path` is removed first; anything else there is an error and is
///   not touched;
/// - the socket file is set to 0600 right after `bind` (until then the 0700 parent keeps
///   everyone else out).
pub(crate) fn bind_private(path: &Path) -> Result<(UnixListener, SocketFile), WireError> {
    check_parent(path)?;
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => fs::remove_file(path).map_err(io_error(path))?,
        Ok(_) => return Err(WireError::NotASocket { path: path.to_owned() }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error(path)(error)),
    }
    let listener = UnixListener::bind(path).map_err(io_error(path))?;
    // Without its metadata the file just bound cannot be told apart from a replacement,
    // so it is left alone.
    let file = SocketFile::of(path, &fs::symlink_metadata(path).map_err(io_error(path))?);
    if let Err(error) = fs::set_permissions(path, Permissions::from_mode(0o600)) {
        file.remove();
        return Err(io_error(path)(error));
    }
    Ok((listener, file))
}

fn check_parent(path: &Path) -> Result<(), WireError> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let meta = fs::metadata(parent).map_err(io_error(parent))?;
    if !meta.is_dir() {
        return Err(io_error(parent)(io::Error::new(io::ErrorKind::NotADirectory, "not a directory")));
    }
    let mode = meta.permissions().mode() & 0o7777;
    if mode & 0o077 != 0 {
        return Err(WireError::Permissions { path: parent.to_owned(), mode });
    }
    Ok(())
}

/// An accept loop on its own thread. Stopping it wakes the blocked `accept` by connecting
/// to the socket, joins the thread and removes the socket file.
#[derive(Debug)]
pub(crate) struct Acceptor {
    file: SocketFile,
    closing: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Acceptor {
    /// Run `admit` on the accept thread for every connection until [`Acceptor::stop`].
    /// `closing` is set when the acceptor stops; connection threads may watch it.
    pub(crate) fn spawn<F>(
        file: SocketFile,
        listener: UnixListener,
        name: &str,
        closing: Arc<AtomicBool>,
        mut admit: F,
    ) -> Result<Acceptor, WireError>
    where
        F: FnMut(UnixStream) + Send + 'static,
    {
        let flag = Arc::clone(&closing);
        let spawned = thread::Builder::new().name(name.to_owned()).spawn(move || {
            for stream in listener.incoming() {
                if flag.load(Ordering::SeqCst) {
                    break;
                }
                match stream {
                    Ok(stream) => admit(stream),
                    Err(_) => thread::sleep(ACCEPT_RETRY),
                }
            }
        });
        match spawned {
            Ok(thread) => Ok(Acceptor { file, closing, thread: Some(thread) }),
            Err(error) => {
                file.remove();
                Err(io_error(file.path())(error))
            }
        }
    }

    /// Stop accepting, join the accept thread and remove the socket. Idempotent.
    ///
    /// The wake-up connection goes to the socket path, so it is made only while the path
    /// still holds this acceptor's socket. When the file is gone or another server has
    /// taken the path over, the thread stays parked in `accept` and is left behind: joining
    /// it would wait for ever, and connecting would plug a client into the other server.
    pub(crate) fn stop(&mut self) {
        self.closing.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take()
            && self.file.is_ours()
            && UnixStream::connect(self.file.path()).is_ok()
        {
            let _ = thread.join();
        }
        self.file.remove();
    }
}

impl Drop for Acceptor {
    fn drop(&mut self) {
        self.stop();
    }
}
