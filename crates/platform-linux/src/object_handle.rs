//! Filesystem object handles for dynamic protected-object identity (LFH2).
//!
//! A `(dev, ino)` pair identifies an inode number, but inode numbers are
//! reused: pinning a short-lived browser journal/WAL inode forever makes an
//! unrelated future file "look" protected. An opaque filesystem handle
//! (`name_to_handle_at(AT_EMPTY_PATH)` on an open fd) identifies the actual
//! object, surviving rename/move and unlinking; a stale or reused inode
//! resolves to a *different* handle (or fails to resolve) and must not
//! false-positive.
//!
//! Design (KISS, per LFH2 Step 2):
//! - Fast path: an ordinary `nlink == 1` open with a `(dev, ino)` that is not
//!   in the candidate map is `Unrelated` — no handle computation at all.
//! - Only when `(dev, ino)` hits a candidate list do we compute the event
//!   fd's handle and compare it against the protected candidates.
//! - The handle payload is opaque; it is never interpreted as an inode number.

use std::io;
use std::os::unix::io::RawFd;

/// Opaque filesystem object handle (LFH2). Stored and compared as bytes; the
/// kernel alone defines their meaning.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjectHandle {
    pub mount_id: i32,
    pub handle_type: i32,
    pub handle_bytes: Vec<u8>,
}

impl ObjectHandle {
    /// Capture the handle of the object behind `fd`.
    ///
    /// `name_to_handle_at(AT_EMPTY_PATH)` requires an `O_PATH` fd, but the fds
    /// Guard works with (fanotify event fds) are `O_RDONLY`. We therefore open
    /// `/proc/self/fd/<fd>` with `O_PATH` — the kernel magic link resolves to
    /// the LIVE object, so the handle follows rename/move — and call
    /// `name_to_handle_at` on that `O_PATH` fd.
    ///
    /// The kernel's documented two-call pattern returns `EOVERFLOW` on the
    /// first call when the buffer is too small (reporting the required size),
    /// so we retry with an adequate buffer. A zero-length header is never
    /// used: the buffer always carries `sizeof(file_handle) + capacity` bytes.
    pub fn from_fd(fd: RawFd) -> io::Result<Self> {
        if fd < 0 {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let proc_fd = format!("/proc/self/fd/{fd}");
        let c_path = std::ffi::CString::new(proc_fd.as_bytes())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: open O_PATH|O_CLOEXEC of our own proc magic link; fd owned
        // below and closed exactly once.
        let path_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if path_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: path_fd is owned by this call; closed before every return.
        let result = Self::from_path_fd(path_fd);
        unsafe {
            libc::close(path_fd);
        }
        result
    }

    /// `name_to_handle_at(AT_EMPTY_PATH)` on an `O_PATH` fd.
    fn from_path_fd(path_fd: RawFd) -> io::Result<Self> {
        let header = std::mem::size_of::<libc::file_handle>();
        let mut buf: Vec<u8> = vec![0; header + 128];
        let handle_ptr = buf.as_mut_ptr() as *mut libc::file_handle;
        // SAFETY: buf covers header + 128 payload bytes (MAX_HANDLE_SZ).
        unsafe {
            (*handle_ptr).handle_bytes = 128;
        }
        let mut mount_id: libc::c_int = 0;
        // SAFETY: valid writable pointers; AT_EMPTY_PATH + empty name resolves
        // the O_PATH fd's own object.
        let rc = unsafe {
            libc::name_to_handle_at(
                path_fd,
                c"".as_ptr(),
                handle_ptr,
                &mut mount_id,
                libc::AT_EMPTY_PATH,
            )
        };
        if rc >= 0 {
            // SAFETY: kernel returned success; header + payload are in bounds.
            return Ok(Self::from_sized_buffer(&buf, mount_id));
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EOVERFLOW) {
            return Err(err);
        }
        // SAFETY: kernel reported the required size into the header.
        let needed = unsafe { (*handle_ptr).handle_bytes } as usize;
        if needed == 0 || needed > 128 {
            return Err(io::Error::from_raw_os_error(libc::EOVERFLOW));
        }
        let total = header + needed;
        let mut sized: Vec<u8> = vec![0; total];
        let sized_ptr = sized.as_mut_ptr() as *mut libc::file_handle;
        // SAFETY: `sized` covers header + `needed` payload bytes.
        unsafe {
            (*sized_ptr).handle_bytes = needed as libc::c_uint;
        }
        // SAFETY: retry with an adequate buffer; kernel writes <= needed bytes.
        let rc2 = unsafe {
            libc::name_to_handle_at(
                path_fd,
                c"".as_ptr(),
                sized_ptr,
                &mut mount_id,
                libc::AT_EMPTY_PATH,
            )
        };
        if rc2 < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self::from_sized_buffer(&sized, mount_id))
    }

    /// Build an `ObjectHandle` from a buffer holding a `libc::file_handle`
    /// header followed by its payload (never a zero-length flexible array).
    fn from_sized_buffer(buf: &[u8], mount_id: libc::c_int) -> Self {
        // SAFETY: buf is sized for at least the header; read initialized fields.
        let handle: libc::file_handle = unsafe { std::ptr::read(buf.as_ptr() as *const _) };
        let bytes = handle.handle_bytes as usize;
        // SAFETY: buf.len() >= sizeof(file_handle) + bytes by construction.
        let payload = unsafe {
            std::slice::from_raw_parts(
                buf.as_ptr().add(std::mem::size_of::<libc::file_handle>()),
                bytes,
            )
        };
        Self {
            mount_id,
            handle_type: handle.handle_type,
            handle_bytes: payload.to_vec(),
        }
    }

    /// Encode to stable bytes for storage/comparison. The encoding is opaque
    /// to Guard: it is never parsed back into an inode number.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.handle_bytes.len());
        out.extend_from_slice(&self.mount_id.to_le_bytes());
        out.extend_from_slice(&self.handle_type.to_le_bytes());
        out.extend_from_slice(&self.handle_bytes);
        out
    }

    /// Decode from `encode`. `None` on truncated input (fail closed).
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }
        let mount_id = i32::from_le_bytes(bytes[0..4].try_into().ok()?);
        let handle_type = i32::from_le_bytes(bytes[4..8].try_into().ok()?);
        Some(Self {
            mount_id,
            handle_type,
            handle_bytes: bytes[8..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_fd_of_self_executable_resolves() {
        use std::os::unix::io::AsRawFd;
        // name_to_handle_at needs a real filesystem (procfs/tmpfs return
        // EINVAL/EOPNOTSUPP). Create the fixture under the crate's target dir,
        // which sits on a handle-supporting filesystem.
        let repo = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
        let base = std::path::Path::new(&repo)
            .join("../../target")
            .join(format!("lfh2-handle-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let fixture = base.join("handle-probe");
        std::fs::write(&fixture, b"x").unwrap();
        let file = std::fs::File::open(&fixture).expect("open fixture");
        let handle = ObjectHandle::from_fd(file.as_raw_fd());
        match handle {
            Ok(h) => {
                assert!(!h.handle_bytes.is_empty());
                assert!(!h.encode().is_empty());
            }
            Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => {
                // Kernel without name_to_handle_at: nothing to assert.
            }
            Err(e) => panic!("name_to_handle_at on fixture failed: {e}"),
        }
    }

    #[test]
    fn encode_decode_round_trip() {
        let h = ObjectHandle {
            mount_id: 31,
            handle_type: 1,
            handle_bytes: vec![1, 2, 3, 4, 5],
        };
        assert_eq!(ObjectHandle::decode(&h.encode()), Some(h));
    }

    #[test]
    fn decode_truncated_fails_closed() {
        assert!(ObjectHandle::decode(&[]).is_none());
        assert!(ObjectHandle::decode(&[0u8; 4]).is_none());
        assert!(ObjectHandle::decode(&[0u8; 7]).is_none());
    }

    #[test]
    fn handles_distinguish_same_ino_reuse_simulated() {
        // Two objects with identical (dev,ino) metadata but different handle
        // payloads must NOT compare equal: this is the inode-reuse guard.
        let a = ObjectHandle {
            mount_id: 7,
            handle_type: 1,
            handle_bytes: vec![0xAA, 0xBB],
        };
        let b = ObjectHandle {
            mount_id: 7,
            handle_type: 1,
            handle_bytes: vec![0xCC, 0xDD],
        };
        assert_ne!(a, b);
    }

    #[test]
    fn negative_fd_fails() {
        assert!(ObjectHandle::from_fd(-1).is_err());
    }
}
