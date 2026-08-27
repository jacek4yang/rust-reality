//! The host-exclusive benchmark lock — runtime attestation.
//!
//! A benchmark host runs one measurement at a time; concurrent runs would
//! contend for CPU and cores and invalidate every sample. The legacy
//! `benchmark-contract.sh` enforced this with a dedicated keeper process holding
//! the only lock file descriptor.
//!
//! [`HostLock`] achieves single-host mutual exclusion with a safe primitive: an
//! atomic lock *directory*. `mkdir` either creates the directory or fails because
//! it already exists, so a second concurrent run fails closed. The directory is
//! removed when the guard drops. This uses only safe standard-library calls,
//! which the crate's `unsafe_code = "forbid"` policy requires — no `flock` FFI.
//!
//! Per ADR 0009 the lock is a *runtime* fact: its device/inode identity is
//! recorded as attestation for the duration of the run, never as durable artifact
//! identity, so archived evidence does not depend on the inode surviving.
//!
//! A stale lock directory left by a crashed run is reported with a clear message
//! rather than silently stolen; a benchmark host operator resolves it explicitly,
//! which is safer than racing to reclaim it.

use std::path::{Path, PathBuf};

/// A held host-exclusive lock, released on drop.
#[derive(Debug)]
pub struct HostLock {
    dir: PathBuf,
    device_inode: String,
}

impl HostLock {
    /// The lock directory path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// The `device:inode` identity of the lock directory, for run attestation.
    #[must_use]
    pub fn device_inode(&self) -> &str {
        &self.device_inode
    }

    /// Acquires the host-exclusive lock rooted at `path`, failing closed if held.
    ///
    /// `path` is the lock *base* (the legacy lock file path); the lock is the
    /// sibling directory `<path>.d`, created atomically.
    ///
    /// # Errors
    ///
    /// Returns a message when the path is not absolute, the parent cannot be
    /// created, or the lock is already held.
    pub fn acquire(path: &Path) -> Result<Self, String> {
        if !path.is_absolute() {
            return Err("host-exclusive lock path must be absolute".to_owned());
        }
        let parent = path
            .parent()
            .ok_or_else(|| "host-exclusive lock path has no parent".to_owned())?;
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("could not create lock directory root: {error}"))?;

        let dir = lock_dir(path);
        match std::fs::create_dir(&dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(format!(
                    "host-exclusive lock is already held: {} (remove it if the owning run crashed)",
                    dir.display()
                ));
            }
            Err(error) => {
                return Err(format!("could not take host-exclusive lock: {error}"));
            }
        }

        let device_inode = device_inode_of(&dir).unwrap_or_else(|| "unknown".to_owned());
        Ok(Self { dir, device_inode })
    }
}

impl Drop for HostLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The lock directory for a lock base path.
fn lock_dir(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    name.push(".d");
    path.with_file_name(name)
}

#[cfg(unix)]
fn device_inode_of(path: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).ok()?;
    Some(format!("{}:{}", meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
fn device_inode_of(_path: &Path) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("rr-hostlock-{}-{name}.lock", std::process::id()))
    }

    #[test]
    fn acquiring_the_same_lock_twice_fails_closed() {
        let path = lock_path("dup");
        let _ = std::fs::remove_dir_all(lock_dir(&path));
        let first = HostLock::acquire(&path).expect("first acquisition succeeds");
        if cfg!(unix) {
            assert!(first.device_inode().contains(':'), "device:inode recorded");
        }
        let second = HostLock::acquire(&path);
        assert!(second.is_err(), "a second acquisition must fail closed");
        drop(first);
        // After release the lock can be taken again.
        let third = HostLock::acquire(&path).expect("re-acquisition after release succeeds");
        drop(third);
    }

    #[test]
    fn a_relative_path_is_rejected() {
        assert!(HostLock::acquire(Path::new("relative.lock")).is_err());
    }

    #[test]
    fn releasing_removes_the_lock_directory() {
        let path = lock_path("release");
        let dir = lock_dir(&path);
        let _ = std::fs::remove_dir_all(&dir);
        {
            let _lock = HostLock::acquire(&path).expect("acquire");
            assert!(dir.is_dir(), "lock directory exists while held");
        }
        assert!(!dir.exists(), "lock directory removed on release");
    }
}
