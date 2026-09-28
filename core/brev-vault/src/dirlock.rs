//! One open store per directory, and only in a private directory.
//!
//! The directory itself is locked (flock), not a file in it: a flock on the
//! database file breaks SQLite's own locking, and a lock file would add a
//! name to the directory. A [`crate::Vault`] holds its [`DirLock`] for as
//! long as it lives.

use std::fs::File;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::Error;

/// The locked directory of an open store. Unlocked when dropped.
pub(crate) struct DirLock {
    _dir: File,
}

impl DirLock {
    /// Opens the directory `store` is in (`Io` if that fails), checks that
    /// it has mode 0700 (`Unsafe` otherwise), then locks it without
    /// waiting: `Busy` if another open store holds it.
    pub(crate) fn acquire(store: &Path) -> Result<DirLock, Error> {
        let path = store.parent().ok_or(Error::Malformed)?;
        let dir = File::open(path)?;
        let meta = dir.metadata()?;
        if !meta.is_dir() {
            return Err(io::Error::from(io::ErrorKind::NotADirectory).into());
        }
        if meta.permissions().mode() & 0o7777 != 0o700 {
            return Err(Error::Unsafe);
        }
        match dir.try_lock() {
            Ok(()) => Ok(DirLock { _dir: dir }),
            Err(std::fs::TryLockError::WouldBlock) => Err(Error::Busy),
            Err(std::fs::TryLockError::Error(e)) => Err(Error::Io(e)),
        }
    }
}
