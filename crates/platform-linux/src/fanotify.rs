//! fanotify permission-event interception (`FAN_OPEN_PERM` and narrow
//! `FAN_ACCESS_PERM` use for SSH keys).
//!
//! This module wraps the Linux fanotify UAPI:
//! - `fanotify_init` with `FAN_CLASS_CONTENT` (permission-capable). Requires
//!   `CAP_SYS_ADMIN`.
//! - `fanotify_mark` of a single file with `FAN_OPEN_PERM`.
//! - reading one or more `fanotify_event_metadata` records from a single read.
//! - writing a `fanotify_response` (`FAN_ALLOW`/`FAN_DENY`) and closing the
//!   event fd exactly once.
//!
//! Event parsing is split into a pure function (`parse_events`) so it can be
//! unit-tested without `CAP_SYS_ADMIN`.

use std::io;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::sync::Arc;

use libc::{
    fanotify_event_metadata, fanotify_init, fanotify_mark, fanotify_response, AT_FDCWD,
    FAN_ACCESS_PERM, FAN_ALLOW, FAN_CLASS_CONTENT, FAN_CLOEXEC, FAN_DENY, FAN_EVENT_ON_CHILD,
    FAN_MARK_ADD, FAN_MARK_FILESYSTEM, FAN_MARK_MOUNT, FAN_NOFD, FAN_OPEN_PERM, FAN_Q_OVERFLOW,
    O_LARGEFILE, O_RDONLY,
};

/// Kernel UAPI version of `fanotify_event_metadata.vers`.
const FANOTIFY_METADATA_VERSION: u8 = 3;

/// Mask for marking a directory so opens of its (direct) children fire
/// `FAN_OPEN_PERM`. Recursive coverage requires marking each subdirectory.
pub const OPEN_PERM_TREE_MASK: u64 = FAN_OPEN_PERM | FAN_EVENT_ON_CHILD;

/// `(st_dev, st_ino)` of an open fd, for inode-based resource matching (catches
/// hardlinks and symlinks to protected critical files).
pub fn fd_identity(fd: RawFd) -> io::Result<(u64, u64)> {
    // SAFETY: `stat` is zeroed; fstat fills it from the kernel for a valid fd.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fd is a real open fd handed to us by a fanotify event.
    if unsafe { libc::fstat(fd, &mut st) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((st.st_dev, st.st_ino))
}

/// Hardlink count of an event fd. Strict Mode uses this to keep the nlink=1
/// unrelated fast path cheap while detecting aliases of protected names.
pub fn fd_link_count(fd: RawFd) -> io::Result<u64> {
    // SAFETY: `stat` is zeroed and fstat initializes it for a valid event fd.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fd is a live event fd borrowed for this syscall.
    if unsafe { libc::fstat(fd, &mut st) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st.st_nlink)
}

/// The path an event fd refers to, via `/proc/self/fd/<fd>` readlink.
pub fn fd_path(fd: RawFd) -> io::Result<std::path::PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{fd}"))
}

#[derive(Debug, thiserror::Error)]
pub enum FanotifyError {
    #[error("fanotify metadata version mismatch: found {found}, expected {expected}")]
    VersionMismatch { found: u8, expected: u8 },
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

/// A parsed fanotify event.
#[derive(Debug, Clone)]
pub struct ParsedEvent {
    pub mask: u64,
    pub fd: RawFd,
    pub pid: i32,
    pub overflow: bool,
}

impl ParsedEvent {
    pub fn is_open_perm(&self) -> bool {
        (self.mask & FAN_OPEN_PERM) != 0
    }

    /// True for the narrow SSH read gate.  Browser resources remain on the
    /// existing open-permission path; this must never be installed as a broad
    /// filesystem mark because it would serialize ordinary file reads.
    pub fn is_access_perm(&self) -> bool {
        (self.mask & FAN_ACCESS_PERM) != 0
    }

    /// True if this event carries a real fd that must be responded to + closed.
    pub fn has_fd(&self) -> bool {
        self.fd != FAN_NOFD && self.fd >= 0
    }
}

/// A permission-capable fanotify group owning one kernel fd.
pub struct FanotifyGroup {
    fd: RawFd,
}

impl FanotifyGroup {
    /// Initialize a `FAN_CLASS_CONTENT` group. Returns EPERM without
    /// `CAP_SYS_ADMIN`; callers should check `capability::has_cap_sys_admin()`
    /// first to produce a precise error.
    pub fn new_content() -> io::Result<Self> {
        // SAFETY: fanotify_init allocates a kernel fd and performs no memory
        // mutation in userspace. Flags/constants are kernel UAPI values.
        let fd = unsafe {
            fanotify_init(
                FAN_CLASS_CONTENT | FAN_CLOEXEC,
                (O_RDONLY | O_LARGEFILE) as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    /// Mark `path` for `mask` (typically `FAN_OPEN_PERM`).
    pub fn mark_file(&self, mask: u64, path: &Path) -> io::Result<()> {
        let c = std::ffi::CString::new(path.to_string_lossy().as_bytes())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: self.fd is a valid owned fanotify fd; `c` outlives the call;
        // AT_FDCWD + an absolute path is the documented usage.
        let rc = unsafe { fanotify_mark(self.fd, FAN_MARK_ADD, mask, AT_FDCWD, c.as_ptr()) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Mark every object on the filesystem containing `path`. This is the
    /// Strict Mode boundary: a future inode is covered before its first open,
    /// without waiting for userspace topology discovery.
    pub fn mark_filesystem(&self, mask: u64, path: &Path) -> io::Result<()> {
        let c = std::ffi::CString::new(path.to_string_lossy().as_bytes())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: self.fd is a valid fanotify group fd and `c` remains live for
        // the syscall. Linux interprets `path` only to select its filesystem.
        let rc = unsafe {
            fanotify_mark(
                self.fd,
                FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                mask,
                AT_FDCWD,
                c.as_ptr(),
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Mark the existing mount containing `path`. This does not create or
    /// otherwise manage mounts; Linux selects the mount from the path.
    pub fn mark_mount(&self, mask: u64, path: &Path) -> io::Result<()> {
        let c = std::ffi::CString::new(path.to_string_lossy().as_bytes())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: self.fd is a valid fanotify group fd and `c` remains live for
        // the syscall. FAN_MARK_MOUNT asks Linux to select the existing mount
        // containing path; no userspace mount manipulation occurs.
        let rc = unsafe {
            fanotify_mark(
                self.fd,
                FAN_MARK_ADD | FAN_MARK_MOUNT,
                mask,
                AT_FDCWD,
                c.as_ptr(),
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Count live filesystem-scope marks from the kernel's fdinfo view. A
    /// filesystem mark is rendered as `fanotify sdev:...`; inode and mount
    /// marks use different prefixes. This lets status detect a mark removed by
    /// filesystem lifecycle without trusting the startup counter forever.
    pub fn filesystem_mark_count(&self) -> io::Result<usize> {
        let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", self.fd))?;
        Ok(count_filesystem_marks_from_fdinfo(&fdinfo))
    }

    /// Blocking read of one or more events into `buf`; returns bytes read.
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: read into a valid buffer of buf.len() bytes from a valid fd.
        let n = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut _, buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    /// Write the allow/deny response for a permission event fd.
    pub fn respond(&self, event_fd: RawFd, allow: bool) -> io::Result<()> {
        let resp = fanotify_response {
            fd: event_fd,
            response: if allow { FAN_ALLOW } else { FAN_DENY },
        };
        // SAFETY: writing a fanotify_response struct to the group fd is the
        // documented permission-response UAPI.
        let n = unsafe {
            libc::write(
                self.fd,
                &resp as *const _ as *const _,
                std::mem::size_of::<fanotify_response>(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn count_filesystem_marks_from_fdinfo(fdinfo: &str) -> usize {
    fdinfo
        .lines()
        .filter(|line| line.starts_with("fanotify sdev:"))
        .count()
}

impl Drop for FanotifyGroup {
    fn drop(&mut self) {
        // SAFETY: fd is owned by this group and closed exactly once on drop.
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// Opaque ownership of one pending Linux permission operation. Portable code
/// can only choose the terminal response; it cannot access the event fd.
pub struct LinuxPendingPermission {
    group: Arc<FanotifyGroup>,
    event_fd: RawFd,
    finished: bool,
}

impl LinuxPendingPermission {
    pub fn new(group: Arc<FanotifyGroup>, event_fd: RawFd) -> Self {
        Self {
            group,
            event_fd,
            finished: false,
        }
    }

    fn finish(&mut self, allow: bool) -> anyhow::Result<()> {
        if self.finished {
            anyhow::bail!("permission request already resolved");
        }
        let response = self.group.respond(self.event_fd, allow);
        close_event_fd(self.event_fd);
        self.finished = true;
        response.map_err(Into::into)
    }

    pub fn resolve(mut self, allow: bool) -> anyhow::Result<()> {
        self.finish(allow)
    }
}

impl guard_platform::PendingPermission for LinuxPendingPermission {
    fn allow(mut self: Box<Self>) -> anyhow::Result<()> {
        self.finish(true)
    }

    fn deny(mut self: Box<Self>) -> anyhow::Result<()> {
        self.finish(false)
    }
}

impl Drop for LinuxPendingPermission {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.finish(false);
        }
    }
}

/// Close an event fd exactly once. No-op for overflow events (`FAN_NOFD`).
pub fn close_event_fd(fd: RawFd) {
    if fd >= 0 {
        // SAFETY: fd is a real fd handed to us by a fanotify event; closed once.
        unsafe {
            libc::close(fd);
        }
    }
}

/// Parse all complete `fanotify_event_metadata` records from `buf`.
///
/// - Returns `VersionMismatch` if a record's `vers` disagrees with the kernel
///   UAPI version we were built against.
/// - A trailing partial record (fewer than one metadata header, or an
///   `event_len` that extends past the buffer) is left unparsed — the caller is
///   expected to retain it for the next read in a real daemon. For the PoC this
///   simply means it is dropped, which is acceptable because each fanotify read
///   returns whole events.
pub fn parse_events(buf: &[u8]) -> Result<Vec<ParsedEvent>, FanotifyError> {
    let mut out = Vec::new();
    let mut off = 0;
    let hdr = std::mem::size_of::<fanotify_event_metadata>();
    while off + hdr <= buf.len() {
        // SAFETY: we have at least `hdr` bytes starting at `off`; we only read
        // fixed-size fields and never retain the reference beyond this scope.
        let meta: &fanotify_event_metadata =
            unsafe { &*(buf.as_ptr().add(off) as *const fanotify_event_metadata) };
        if meta.vers != FANOTIFY_METADATA_VERSION {
            return Err(FanotifyError::VersionMismatch {
                found: meta.vers,
                expected: FANOTIFY_METADATA_VERSION,
            });
        }
        let ev_len = meta.event_len as usize;
        if ev_len < hdr || off + ev_len > buf.len() {
            break; // incomplete trailing record
        }
        let overflow = (meta.mask & FAN_Q_OVERFLOW) != 0;
        out.push(ParsedEvent {
            mask: meta.mask,
            fd: meta.fd,
            pid: meta.pid,
            overflow,
        });
        off += ev_len;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libc::fanotify_event_metadata;

    fn hdr_size() -> usize {
        std::mem::size_of::<fanotify_event_metadata>()
    }

    /// Build `event_len` bytes representing one metadata record (padded with
    /// zeros past the header, as the kernel does for info records).
    fn make_event(vers: u8, mask: u64, fd: i32, pid: i32, event_len: usize) -> Vec<u8> {
        let meta = fanotify_event_metadata {
            event_len: event_len as u32,
            vers,
            reserved: 0,
            metadata_len: hdr_size() as u16,
            mask,
            fd,
            pid,
        };
        let mut buf = vec![0u8; event_len];
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &meta as *const _ as *const u8,
                std::mem::size_of::<fanotify_event_metadata>(),
            )
        };
        buf[..bytes.len()].copy_from_slice(bytes);
        buf
    }

    #[test]
    fn parses_multiple_events() {
        let mut buf = Vec::new();
        buf.extend(make_event(3, FAN_OPEN_PERM, 100, 1234, hdr_size()));
        buf.extend(make_event(3, FAN_OPEN_PERM, 101, 4321, hdr_size()));
        let evs = parse_events(&buf).expect("ok");
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].fd, 100);
        assert_eq!(evs[0].pid, 1234);
        assert!(evs[0].is_open_perm());
        assert!(!evs[0].overflow);
        assert_eq!(evs[1].pid, 4321);
    }

    #[test]
    fn distinguishes_narrow_access_permission_events() {
        let buf = make_event(3, FAN_ACCESS_PERM, 100, 1234, hdr_size());
        let event = parse_events(&buf).unwrap().pop().unwrap();
        assert!(event.is_access_perm());
        assert!(!event.is_open_perm());
    }

    #[test]
    fn detects_overflow_event() {
        let mut buf = make_event(3, FAN_Q_OVERFLOW, FAN_NOFD, -1, hdr_size());
        // append a normal event after overflow
        buf.extend(make_event(3, FAN_OPEN_PERM, 7, 99, hdr_size()));
        let evs = parse_events(&buf).expect("ok");
        assert_eq!(evs.len(), 2);
        assert!(evs[0].overflow);
        assert!(!evs[0].has_fd());
        assert!(!evs[1].overflow);
        assert!(evs[1].has_fd());
    }

    #[test]
    fn version_mismatch_is_error() {
        let buf = make_event(9, FAN_OPEN_PERM, 5, 1, hdr_size());
        let err = parse_events(&buf).unwrap_err();
        assert!(matches!(
            err,
            FanotifyError::VersionMismatch {
                found: 9,
                expected: 3
            }
        ));
    }

    #[test]
    fn trailing_partial_event_is_dropped_not_errored() {
        let mut buf = make_event(3, FAN_OPEN_PERM, 1, 1, hdr_size());
        // append a truncated header (only 8 bytes of a 40-byte record)
        buf.extend(&[0u8; 8]);
        let evs = parse_events(&buf).expect("ok");
        assert_eq!(evs.len(), 1);
    }

    #[test]
    fn empty_buffer_yields_no_events() {
        let evs = parse_events(&[]).expect("ok");
        assert!(evs.is_empty());
    }

    #[test]
    fn has_fd_helper() {
        let ev = ParsedEvent {
            mask: FAN_OPEN_PERM,
            fd: 42,
            pid: 1,
            overflow: false,
        };
        assert!(ev.has_fd());
        let ov = ParsedEvent {
            mask: FAN_Q_OVERFLOW,
            fd: FAN_NOFD,
            pid: -1,
            overflow: true,
        };
        assert!(!ov.has_fd());
    }

    #[test]
    fn counts_only_filesystem_marks_from_fdinfo() {
        let fdinfo = "fanotify flags:5 event-flags:0\n\
                      fanotify ino:abc sdev:1 mflags:0 mask:1 ignored_mask:0\n\
                      fanotify sdev:1 mflags:0 mask:10000 ignored_mask:0\n\
                      fanotify mnt_id:2 mflags:0 mask:1 ignored_mask:0\n\
                      fanotify sdev:3 mflags:0 mask:10000 ignored_mask:0\n";
        assert_eq!(count_filesystem_marks_from_fdinfo(fdinfo), 2);
    }
}
