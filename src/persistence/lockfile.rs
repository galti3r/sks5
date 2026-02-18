use std::fs::File;
use std::path::Path;

/// Exclusive file lock on the data directory.
/// The lock is held as long as this struct lives (dropped on Drop).
#[derive(Debug)]
pub struct Lockfile {
    _file: File,
}

#[derive(Debug)]
pub enum LockError {
    AlreadyLocked,
    Io(std::io::Error),
}

impl Lockfile {
    /// Acquire an exclusive non-blocking lock on `{data_dir}/sks5.lock`.
    /// Returns `LockError::AlreadyLocked` if another process holds the lock.
    pub fn acquire(data_dir: &Path) -> Result<Self, LockError> {
        let lock_path = data_dir.join("sks5.lock");
        let file = File::create(&lock_path).map_err(LockError::Io)?;

        try_lock_exclusive(&file)?;

        Ok(Self { _file: file })
    }
}

/// Try to acquire an exclusive non-blocking lock using platform-specific APIs.
#[cfg(unix)]
fn try_lock_exclusive(file: &File) -> Result<(), LockError> {
    use std::os::unix::io::AsRawFd;

    let fd = file.as_raw_fd();
    // flock constants: LOCK_EX = 2, LOCK_NB = 4
    const LOCK_EX: i32 = 2;
    const LOCK_NB: i32 = 4;

    // SAFETY: flock is a standard POSIX syscall, fd is valid (owned by File).
    let ret = unsafe { flock_syscall(fd, LOCK_EX | LOCK_NB) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock {
            return Err(LockError::AlreadyLocked);
        }
        return Err(LockError::Io(err));
    }
    Ok(())
}

#[cfg(unix)]
unsafe fn flock_syscall(fd: i32, operation: i32) -> i32 {
    // Link to libc's flock without depending on the libc crate.
    unsafe {
        extern "C" {
            fn flock(fd: i32, operation: i32) -> i32;
        }
        flock(fd, operation)
    }
}

#[cfg(not(unix))]
fn try_lock_exclusive(_file: &File) -> Result<(), LockError> {
    // On non-Unix platforms, skip locking (best-effort).
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_lockfile_acquire_and_release() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path()).unwrap();

        let lock = Lockfile::acquire(tmp.path()).unwrap();
        assert!(tmp.path().join("sks5.lock").exists());
        drop(lock);
    }

    #[cfg(unix)]
    #[test]
    fn test_lockfile_conflict_detected() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path()).unwrap();

        let _lock1 = Lockfile::acquire(tmp.path()).unwrap();
        let result = Lockfile::acquire(tmp.path());
        assert!(matches!(result, Err(LockError::AlreadyLocked)));
    }

    #[cfg(unix)]
    #[test]
    fn test_lockfile_released_on_drop() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path()).unwrap();

        {
            let _lock = Lockfile::acquire(tmp.path()).unwrap();
        }
        // After drop, should be able to re-acquire
        let _lock2 = Lockfile::acquire(tmp.path()).unwrap();
    }
}
