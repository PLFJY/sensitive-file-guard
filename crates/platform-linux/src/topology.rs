//! Inotify watcher for browser-profile topology changes.
//!
//! Fanotify inode/directory marks do not follow replacement inodes or newly
//! created subdirectories. This watcher observes enrolled profile roots and
//! configured SSH-key parent directories, then tells the daemon to rediscover,
//! reindex, and apply fresh permission marks.

use std::ffi::CString;
use std::io;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

const WATCH_MASK: u32 = libc::IN_CREATE
    | libc::IN_MOVED_TO
    | libc::IN_MOVED_FROM
    | libc::IN_DELETE
    | libc::IN_DELETE_SELF
    | libc::IN_MOVE_SELF
    | libc::IN_ATTRIB;

pub struct TopologyWatcher {
    fd: RawFd,
    roots: Vec<PathBuf>,
}

impl TopologyWatcher {
    pub fn new(roots: Vec<PathBuf>) -> io::Result<Self> {
        // SAFETY: inotify_init1 returns a new owned fd and touches no userspace
        // memory.
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let watcher = Self { fd, roots };
        // The Drop implementation closes fd if initial watch setup fails.
        watcher.rebuild_watches()?;
        Ok(watcher)
    }

    /// Add watches for every directory currently below each profile root.
    /// Adding a watch twice updates/reuses the kernel watch descriptor.
    pub fn rebuild_watches(&self) -> io::Result<usize> {
        let mut count = 0;
        for root in &self.roots {
            add_recursive(self.fd, root, &mut count)?;
        }
        Ok(count)
    }

    /// Wait up to `timeout` and drain queued events. Returns true when any
    /// topology event (including queue overflow) requires a full rediscovery.
    pub fn wait_for_change(&self, timeout: Duration) -> io::Result<bool> {
        let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        let mut poll_fd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll_fd points to one initialized pollfd for the duration of
        // the call.
        let ready = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                return Ok(false);
            }
            return Err(error);
        }
        if ready == 0 {
            return Ok(false);
        }

        let mut changed = false;
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            // SAFETY: buffer is valid writable memory and fd is an inotify fd.
            let read = unsafe { libc::read(self.fd, buffer.as_mut_ptr().cast(), buffer.len()) };
            if read > 0 {
                changed = true;
                continue;
            }
            if read == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                break;
            }
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(error);
        }
        Ok(changed)
    }
}

impl Drop for TopologyWatcher {
    fn drop(&mut self) {
        // SAFETY: this object uniquely owns fd.
        unsafe { libc::close(self.fd) };
    }
}

fn add_recursive(fd: RawFd, dir: &Path, count: &mut usize) -> io::Result<()> {
    let canonical = std::fs::canonicalize(dir)?;
    let path = CString::new(canonical.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: fd is a live inotify fd and path is a NUL-terminated string that
    // outlives the call.
    if unsafe { libc::inotify_add_watch(fd, path.as_ptr(), WATCH_MASK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    *count += 1;
    for entry in std::fs::read_dir(&canonical)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            add_recursive(fd, &entry.path(), count)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observes_new_nested_directory_and_file() {
        let root = tempfile::tempdir().unwrap();
        let watcher = TopologyWatcher::new(vec![root.path().to_path_buf()]).unwrap();
        let nested = root.path().join("new-profile");
        std::fs::create_dir(&nested).unwrap();
        assert!(watcher.wait_for_change(Duration::from_secs(1)).unwrap());
        watcher.rebuild_watches().unwrap();
        std::fs::write(nested.join("Cookies"), b"synthetic").unwrap();
        assert!(watcher.wait_for_change(Duration::from_secs(1)).unwrap());
    }
}
