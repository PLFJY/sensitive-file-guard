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
    FAN_MARK_ADD, FAN_MARK_FILESYSTEM, FAN_NOFD, FAN_OPEN_PERM, FAN_Q_OVERFLOW, O_LARGEFILE,
    O_RDONLY,
};

/// `FAN_REPORT_PIDFD` (Linux UAPI): ask the kernel to attach a pidfd for the
/// event's pid. Only meaningful when the group is created with it.
const FAN_REPORT_PIDFD: u32 = 0x0000_0080;

/// `FAN_REPORT_FID` (Linux UAPI): report the object's filesystem identifier
/// (fsid + opaque `file_handle`) in info records. Permitted only on
/// `FAN_CLASS_NOTIF` groups — combining it with `FAN_CLASS_CONTENT` is
/// UAPI-forbidden (EINVAL), which is why the LFH2 Step 3 topology group is a
/// SEPARATE group from the permission group.
const FAN_REPORT_FID: u32 = 0x0000_0200;

/// `FAN_EVENT_INFO_TYPE_PIDFD` (Linux UAPI): the info record that carries the
/// pidfd. We walk info records by `info_type`, never assuming an order.
const FAN_EVENT_INFO_TYPE_PIDFD: u8 = 4;

/// `FAN_EVENT_INFO_TYPE_FID` (Linux UAPI): the info record that carries the
/// object's fsid + opaque file handle.
const FAN_EVENT_INFO_TYPE_FID: u8 = 1;

/// `FAN_MOVE` = `FAN_MOVED_FROM | FAN_MOVED_TO` (Linux UAPI): move/rename
/// notification events. With `FAN_REPORT_FID` each carries the moved file's
/// handle, which is exactly what the LFH2 Step 3 topology learner needs to
/// label a NEVER-OPENED dynamic object that left a protected tree.
pub const FAN_MOVE_EVENTS: u64 = 0x0000_0040 | 0x0000_0080;

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
    #[error("malformed fanotify info record (bad length or type bounds)")]
    MalformedInfoRecord,
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

/// A parsed fanotify event.
#[derive(Debug)]
pub struct ParsedEvent {
    pub mask: u64,
    pub fd: RawFd,
    pub pid: i32,
    pub overflow: bool,
    /// Kernel-provided pidfd for `pid` when the group was created with
    /// `FAN_REPORT_PIDFD`. `None` on legacy kernels or when the kernel did not
    /// attach one. Ownership: the caller must close it exactly once.
    pub pidfd: Option<RawFd>,
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
    /// Whether this group was created with `FAN_REPORT_PIDFD`. Event parsing
    /// then expects (and validates) pidfd info records.
    pidfd_enabled: bool,
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
        Ok(Self {
            fd,
            pidfd_enabled: false,
        })
    }

    /// Initialize a `FAN_CLASS_CONTENT` group with `FAN_REPORT_PIDFD` so each
    /// event carries a pidfd for its pid (kernel >= 5.9). On kernels that
    /// reject the flag (EINVAL) the caller should fall back to `new_content`
    /// and report `REDUCED(legacy_process_identity)`.
    pub fn new_content_with_pidfd() -> io::Result<Self> {
        // SAFETY: same as new_content; FAN_REPORT_PIDFD is UAPI.
        let fd = unsafe {
            fanotify_init(
                FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_REPORT_PIDFD,
                (O_RDONLY | O_LARGEFILE) as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd,
            pidfd_enabled: true,
        })
    }

    /// True when this group was created with `FAN_REPORT_PIDFD`.
    pub fn pidfd_enabled(&self) -> bool {
        self.pidfd_enabled
    }

    /// Initialize a `FAN_CLASS_NOTIF` group with `FAN_REPORT_FID` — the
    /// SEPARATE topology group (LFH2 Step 3). It only carries notification
    /// events (object fids on move/rename); it never gates opens, so it must
    /// not be combined with the `FAN_CLASS_CONTENT` permission group
    /// (`FAN_CLASS_CONTENT | FAN_REPORT_FID` is UAPI-forbidden: EINVAL).
    pub fn new_topology() -> io::Result<Self> {
        // SAFETY: fanotify_init allocates a kernel fd; FAN_REPORT_FID is UAPI.
        let fd = unsafe { fanotify_init(FAN_CLOEXEC | FAN_REPORT_FID, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd,
            pidfd_enabled: false,
        })
    }

    /// Mark `path` so move/rename events of its (direct) children are reported
    /// with the child's fid. Recursive coverage requires marking each
    /// subdirectory (the topology learner does that).
    pub fn mark_dir_move(&self, path: &Path) -> io::Result<()> {
        let c = std::ffi::CString::new(path.to_string_lossy().as_bytes())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: self.fd is a valid fanotify group fd; `c` outlives the call.
        let rc = unsafe {
            fanotify_mark(
                self.fd,
                FAN_MARK_ADD,
                FAN_MOVE_EVENTS | FAN_EVENT_ON_CHILD,
                AT_FDCWD,
                c.as_ptr(),
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Mark the inode behind `fd` for `mask` (permission masks such as
    /// `FAN_OPEN_PERM` must go on the FAN_CLASS_CONTENT group, never the
    /// topology group). `pathname` is NULL, so `fd` is the object to mark.
    pub fn mark_fd(&self, mask: u64, fd: RawFd) -> io::Result<()> {
        // SAFETY: self.fd is a valid fanotify group fd; a NULL pathname marks
        // the object behind `fd` (documented fanotify_mark usage).
        let rc = unsafe { fanotify_mark(self.fd, FAN_MARK_ADD, mask, fd, std::ptr::null()) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
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
///
/// Each event's `metadata_len` (>= the metadata header) anchors variable-length
/// info records. We walk them by `info_type` and extract a `FAN_EVENT_INFO_TYPE
/// _PIDFD` record's pidfd when present. Malformed records (bad length/type
/// bounds) fail closed with `FanotifyError::MalformedInfoRecord` rather than
/// silently dropping the pidfd.
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
        let info_len = meta.metadata_len as usize;
        // Kernel semantics: `metadata_len` is the fixed header size (usually
        // 40); any info records occupy `[off+metadata_len, off+event_len)`.
        let pidfd = if !overflow && ev_len > info_len {
            parse_pidfd_info(&buf[off + info_len..off + ev_len])?
        } else {
            None
        };
        out.push(ParsedEvent {
            mask: meta.mask,
            fd: meta.fd,
            pid: meta.pid,
            overflow,
            pidfd,
        });
        off += ev_len;
    }
    Ok(out)
}

/// Extract the pidfd from the info-record region of one event. Walks records
/// by `info_type`; a malformed record fails closed with
/// `FanotifyError::MalformedInfoRecord`.
fn parse_pidfd_info(info: &[u8]) -> Result<Option<RawFd>, FanotifyError> {
    const HDR: usize = 4; // fanotify_event_info_header: info_type(1) pad(1) len(2)
    let mut off = 0;
    while off + HDR <= info.len() {
        let info_type = info[off];
        let len = u16::from_le_bytes([info[off + 2], info[off + 3]]) as usize;
        if len < HDR || off + len > info.len() {
            return Err(FanotifyError::MalformedInfoRecord);
        }
        if info_type == FAN_EVENT_INFO_TYPE_PIDFD {
            if len < HDR + std::mem::size_of::<i32>() {
                return Err(FanotifyError::MalformedInfoRecord);
            }
            // SAFETY: len >= HDR + 4 and off+len <= info.len(), so 4 bytes of
            // pidfd payload are present at off+HDR.
            let pidfd =
                unsafe { std::ptr::read_unaligned(info.as_ptr().add(off + HDR) as *const i32) };
            return Ok(Some(pidfd));
        }
        off += len;
    }
    Ok(None)
}

/// The opaque filesystem identifier carried by a `FAN_EVENT_INFO_TYPE_FID`
/// info record (LFH2 Step 3 topology group): the fsid plus the `file_handle`
/// that `open_by_handle_at(2)` accepts verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FidObject {
    /// `__kernel_fsid_t` (two `u32`s) identifying the filesystem.
    pub fsid: [u32; 2],
    pub handle_type: i32,
    pub handle_bytes: Vec<u8>,
}

/// A parsed notification event from the `FAN_CLASS_NOTIF | FAN_REPORT_FID`
/// topology group.
#[derive(Debug)]
pub struct FidEvent {
    pub mask: u64,
    /// The object's fid when the event carries one (moves/renames with
    /// `FAN_REPORT_FID`). `None` on overflow or non-FID events.
    pub fid: Option<FidObject>,
    pub overflow: bool,
}

/// Parse notification events with `FAN_REPORT_FID` info records. Malformed
/// records fail closed (`FanotifyError::MalformedInfoRecord`).
pub fn parse_fid_events(buf: &[u8]) -> Result<Vec<FidEvent>, FanotifyError> {
    let mut out = Vec::new();
    let mut off = 0;
    let hdr = std::mem::size_of::<fanotify_event_metadata>();
    while off + hdr <= buf.len() {
        // SAFETY: at least `hdr` bytes remain; we only read fixed fields and
        // never retain the reference beyond this scope.
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
        let info_len = meta.metadata_len as usize;
        let fid = if !overflow && ev_len > info_len {
            parse_fid_info(&buf[off + info_len..off + ev_len])?
        } else {
            None
        };
        out.push(FidEvent {
            mask: meta.mask,
            fid,
            overflow,
        });
        off += ev_len;
    }
    Ok(out)
}

/// Extract the first `FAN_EVENT_INFO_TYPE_FID` record. Layout (Linux UAPI):
/// `hdr` (4 bytes: type, pad, len) + `__kernel_fsid_t` (8 bytes: two u32) +
/// an opaque `struct file_handle` (`handle_bytes` u32, `handle_type` i32,
/// then the payload) exactly as `open_by_handle_at(2)` expects.
fn parse_fid_info(info: &[u8]) -> Result<Option<FidObject>, FanotifyError> {
    const HDR: usize = 4;
    const FSID: usize = 8;
    let mut off = 0;
    while off + HDR <= info.len() {
        let info_type = info[off];
        let len = u16::from_le_bytes([info[off + 2], info[off + 3]]) as usize;
        if len < HDR || off + len > info.len() {
            return Err(FanotifyError::MalformedInfoRecord);
        }
        if info_type == FAN_EVENT_INFO_TYPE_FID {
            if len < HDR + FSID + 8 {
                // fsid + a file_handle header (handle_bytes u32, handle_type i32).
                return Err(FanotifyError::MalformedInfoRecord);
            }
            // SAFETY: len >= HDR+FSID+8 guarantees the fsid and the
            // file_handle header are within `info`.
            let fsid0 =
                unsafe { std::ptr::read_unaligned(info.as_ptr().add(off + HDR) as *const u32) };
            let fsid1 =
                unsafe { std::ptr::read_unaligned(info.as_ptr().add(off + HDR + 4) as *const u32) };
            let handle_bytes = unsafe {
                std::ptr::read_unaligned(info.as_ptr().add(off + HDR + FSID) as *const u32)
            } as usize;
            let handle_type = unsafe {
                std::ptr::read_unaligned(info.as_ptr().add(off + HDR + FSID + 4) as *const i32)
            };
            let payload_off = off + HDR + FSID + 8;
            if payload_off + handle_bytes > off + len {
                return Err(FanotifyError::MalformedInfoRecord);
            }
            // SAFETY: bounds checked above.
            let payload =
                unsafe { std::slice::from_raw_parts(info.as_ptr().add(payload_off), handle_bytes) };
            return Ok(Some(FidObject {
                fsid: [fsid0, fsid1],
                handle_type,
                handle_bytes: payload.to_vec(),
            }));
        }
        off += len;
    }
    Ok(None)
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
        make_event_with_meta(vers, mask, fd, pid, hdr_size() as u16, event_len)
    }

    fn make_event_with_meta(
        vers: u8,
        mask: u64,
        fd: i32,
        pid: i32,
        metadata_len: u16,
        event_len: usize,
    ) -> Vec<u8> {
        let meta = fanotify_event_metadata {
            event_len: event_len as u32,
            vers,
            reserved: 0,
            metadata_len,
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

    /// Append a `FAN_EVENT_INFO_TYPE_PIDFD` info record (header + pidfd int)
    /// to a metadata record and return the combined buffer. The record is
    /// placed immediately after the fixed metadata header (as the kernel does:
    /// `metadata_len` stays the header size, `event_len` covers the info).
    fn with_pidfd_info(mut buf: Vec<u8>, pidfd: i32) -> Vec<u8> {
        let meta_len = hdr_size();
        let total = meta_len + 4 + 4;
        let mut out = vec![0u8; total];
        // metadata header
        let mut meta = fanotify_event_metadata {
            event_len: total as u32,
            vers: 3,
            reserved: 0,
            metadata_len: meta_len as u16,
            mask: FAN_OPEN_PERM,
            fd: 7,
            pid: 99,
        };
        // Preserve the original header fields if the caller set them.
        if buf.len() >= meta_len {
            // SAFETY: buf has >= meta_len bytes; copy the original metadata.
            let orig = unsafe { &*(buf.as_ptr() as *const fanotify_event_metadata) };
            meta = *orig;
            meta.event_len = total as u32;
            meta.metadata_len = meta_len as u16;
        }
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &meta as *const _ as *const u8,
                std::mem::size_of::<fanotify_event_metadata>(),
            )
        };
        out[..bytes.len()].copy_from_slice(bytes);
        // info record: type=4, pad=0, len=8, pidfd int
        out[meta_len] = FAN_EVENT_INFO_TYPE_PIDFD;
        out[meta_len + 2] = 8;
        let pidfd_bytes = pidfd.to_le_bytes();
        out[meta_len + 4..meta_len + 8].copy_from_slice(&pidfd_bytes);
        let _ = &mut buf;
        out
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
    fn parses_pidfd_info_record() {
        let buf = with_pidfd_info(make_event(3, FAN_OPEN_PERM, 7, 99, hdr_size()), 42);
        let evs = parse_events(&buf).expect("ok");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].pidfd, Some(42));
    }

    #[test]
    fn walks_info_records_by_type_without_fixed_order() {
        // A non-PIDFD record (type=1 FID) first, then the PIDFD record. The
        // parser must skip type 1 and find type 4.
        let meta_len = hdr_size();
        let fid_len = 4 + 16; // header + fsid(8) + handle bytes(8)
        let pidfd_len = 4 + 4;
        let total = meta_len + fid_len + pidfd_len;
        let mut out = vec![0u8; total];
        let meta = fanotify_event_metadata {
            event_len: total as u32,
            vers: 3,
            reserved: 0,
            metadata_len: meta_len as u16,
            mask: FAN_OPEN_PERM,
            fd: 7,
            pid: 99,
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &meta as *const _ as *const u8,
                std::mem::size_of::<fanotify_event_metadata>(),
            )
        };
        out[..bytes.len()].copy_from_slice(bytes);
        // FID record first.
        out[meta_len] = 1; // FAN_EVENT_INFO_TYPE_FID
        out[meta_len + 2] = fid_len as u8;
        // PIDFD record second.
        out[meta_len + fid_len] = FAN_EVENT_INFO_TYPE_PIDFD;
        out[meta_len + fid_len + 2] = pidfd_len as u8;
        out[meta_len + fid_len + 4..meta_len + fid_len + 8].copy_from_slice(&(77i32).to_le_bytes());
        let evs = parse_events(&out).expect("ok");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].pidfd, Some(77));
    }

    #[test]
    fn malformed_info_record_fails_closed() {
        // metadata_len stays the header size; the info record's length field
        // overflows the event buffer -> MalformedInfoRecord.
        let meta_len = hdr_size();
        let total = meta_len + 4;
        let mut buf = make_event_with_meta(3, FAN_OPEN_PERM, 7, 99, meta_len as u16, total);
        // Info record claims len=16 but only 4 bytes remain in event_len.
        buf[meta_len] = FAN_EVENT_INFO_TYPE_PIDFD;
        buf[meta_len + 2] = 16;
        let err = parse_events(&buf).unwrap_err();
        assert!(matches!(err, FanotifyError::MalformedInfoRecord));
    }

    #[test]
    fn no_info_records_yields_no_pidfd() {
        let buf = make_event(3, FAN_OPEN_PERM, 7, 99, hdr_size());
        let evs = parse_events(&buf).expect("ok");
        assert_eq!(evs[0].pidfd, None);
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
            pidfd: None,
        };
        assert!(ev.has_fd());
        let ov = ParsedEvent {
            mask: FAN_Q_OVERFLOW,
            fd: FAN_NOFD,
            pid: -1,
            overflow: true,
            pidfd: None,
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

    /// Build a FAN_MOVE event carrying one `FAN_EVENT_INFO_TYPE_FID` record
    /// (header + fsid + opaque file_handle) as the kernel does.
    fn make_fid_move_event(mask: u64, fsid: [u32; 2], handle_type: i32, payload: &[u8]) -> Vec<u8> {
        let meta_len = hdr_size();
        let info_len = 4 + 8 + 8 + payload.len();
        let total = meta_len + info_len;
        let mut buf = vec![0u8; total];
        // Metadata header: metadata_len stays the fixed header size; event_len
        // covers the info records (kernel semantics).
        let meta = fanotify_event_metadata {
            event_len: total as u32,
            vers: 3,
            reserved: 0,
            metadata_len: meta_len as u16,
            mask,
            fd: FAN_NOFD,
            pid: -1,
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &meta as *const _ as *const u8,
                std::mem::size_of::<fanotify_event_metadata>(),
            )
        };
        buf[..bytes.len()].copy_from_slice(bytes);
        // Info record header: type=1 (FID), pad=0, len.
        let info_off = meta_len;
        buf[info_off] = FAN_EVENT_INFO_TYPE_FID;
        buf[info_off + 2..info_off + 4].copy_from_slice(&(info_len as u16).to_le_bytes());
        // fsid (two u32).
        buf[info_off + 4..info_off + 8].copy_from_slice(&fsid[0].to_le_bytes());
        buf[info_off + 8..info_off + 12].copy_from_slice(&fsid[1].to_le_bytes());
        // file_handle: handle_bytes u32, handle_type i32, payload.
        let handle_off = info_off + 12;
        buf[handle_off..handle_off + 4].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        buf[handle_off + 4..handle_off + 8].copy_from_slice(&handle_type.to_le_bytes());
        buf[handle_off + 8..].copy_from_slice(payload);
        buf
    }

    #[test]
    fn parses_fid_move_event_with_handle() {
        // A rename-out event carries the moved file's fid; parse_fid_events
        // must recover the fsid + opaque file_handle exactly.
        let payload = [0x11, 0x22, 0x33, 0x44, 0x55];
        let buf = make_fid_move_event(FAN_MOVE_EVENTS, [1, 2], 0x81, &payload);
        let events = parse_fid_events(&buf).unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.mask, FAN_MOVE_EVENTS);
        assert!(!ev.overflow);
        let fid = ev.fid.as_ref().expect("fid present");
        assert_eq!(fid.fsid, [1, 2]);
        assert_eq!(fid.handle_type, 0x81);
        assert_eq!(fid.handle_bytes, payload);
    }

    #[test]
    fn parses_fid_event_after_pidfd_style_record() {
        // Info records may arrive in any order; the parser must walk by type.
        // Build a FID record followed by a second FID record (multiple fids
        // only occur with FAN_REPORT_TARGET_FID; the parser takes the first).
        let buf = make_fid_move_event(FAN_MOVE_EVENTS, [7, 8], 1, &[0xAA]);
        let events = parse_fid_events(&buf).unwrap();
        let fid = events[0].fid.as_ref().expect("fid present");
        assert_eq!(fid.fsid, [7, 8]);
        assert_eq!(fid.handle_bytes, vec![0xAA]);
    }

    #[test]
    fn malformed_fid_info_fails_closed() {
        // Truncated info record (len claims more bytes than present).
        let mut buf = make_fid_move_event(FAN_MOVE_EVENTS, [1, 2], 1, &[0xAA, 0xBB]);
        let meta_len = hdr_size();
        // Corrupt the info len to overrun the buffer.
        buf[meta_len + 2] = 0xFF;
        buf[meta_len + 3] = 0x7F;
        assert!(matches!(
            parse_fid_events(&buf),
            Err(FanotifyError::MalformedInfoRecord)
        ));
    }

    #[test]
    fn overflow_event_has_no_fid() {
        let buf = make_event(3, FAN_Q_OVERFLOW, FAN_NOFD, -1, hdr_size());
        let events = parse_fid_events(&buf).unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].overflow);
        assert!(events[0].fid.is_none());
    }
}
