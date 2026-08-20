//! Hash enrollment for user-writable executables.
//!
//! Trusted-but-user-writable browsers (AppImage, custom builds, `~/.local`
//! installs) cannot be trusted by ownership alone. The user explicitly enrolls
//! them; we store the canonical path, file identity (`st_dev`/`st_ino`/size/
//! mtime) and the SHA-256 of the bytes. A changed binary invalidates trust.
//!
//! To avoid re-hashing large browser binaries on every protected open, the
//! steady-state check is a file-identity comparison; the hash is recomputed
//! only when the file identity has changed (which is exactly when tampering or
//! an update could have occurred).

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// SHA-256 digest bytes.
pub type Sha256Digest = [u8; 32];

/// File-identity cache fields. Any change here triggers a hash recompute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime_ns: i64,
}

/// One enrolled executable.
#[derive(Debug, Clone)]
pub struct EnrollmentRecord {
    pub exe: PathBuf,
    pub identity: FileIdentity,
    pub sha256: Sha256Digest,
}

/// In-memory enrollment store. Owned by the daemon; persisted storage can be
/// layered on later without changing this interface.
#[derive(Debug, Default)]
pub struct EnrollmentStore {
    by_path: HashMap<PathBuf, EnrollmentRecord>,
}

#[derive(Debug, thiserror::Error)]
pub enum EnrollError {
    #[error("executable path is not absolute/canonical: {0}")]
    NotCanonical(PathBuf),
    #[error("stat failed for {path}: {err}")]
    Stat {
        path: PathBuf,
        #[source]
        err: io::Error,
    },
    #[error("read failed for {path}: {err}")]
    Read {
        path: PathBuf,
        #[source]
        err: io::Error,
    },
}

impl EnrollmentStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enroll `exe` by hashing its current bytes and recording its file
    /// identity. Re-enrolling the same path replaces the previous record.
    pub fn enroll(&mut self, exe: &Path) -> Result<&EnrollmentRecord, EnrollError> {
        let canonical = canonicalize(exe)?;
        let identity = stat_identity(&canonical).map_err(|err| EnrollError::Stat {
            path: canonical.clone(),
            err,
        })?;
        let sha = hash_file(&canonical).map_err(|err| EnrollError::Read {
            path: canonical.clone(),
            err,
        })?;
        let record = EnrollmentRecord {
            exe: canonical.clone(),
            identity,
            sha256: sha,
        };
        self.by_path.insert(canonical.clone(), record);
        Ok(self.by_path.get(&canonical).expect("just inserted"))
    }

    /// Returns true iff `exe` is enrolled AND its current contents still match
    /// the enrolled hash. File-identity match is the fast path (no rehash); a
    /// mismatch triggers a rehash and, on a matching hash, an in-place cache
    /// refresh so subsequent checks stay fast.
    pub fn verify(&mut self, exe: &Path) -> bool {
        let Some(record) = self.by_path.get(exe).cloned() else {
            return false;
        };
        let Ok(current_identity) = stat_identity(exe) else {
            return false;
        };
        if current_identity == record.identity {
            return true;
        }
        // File identity changed: recompute the hash to decide validity.
        let Ok(current_sha) = hash_file(exe) else {
            return false;
        };
        if current_sha == record.sha256 {
            // Same bytes, only metadata changed (e.g. mtime). Refresh cache.
            if let Some(r) = self.by_path.get_mut(exe) {
                r.identity = current_identity;
            }
            true
        } else {
            // Bytes changed: enrollment is invalidated. Drop the stale record.
            self.by_path.remove(exe);
            false
        }
    }

    /// Verify an **actual executed image** by its open fd (LFH1). The file
    /// identity comes from the object the process is really running, never
    /// from re-opening the pathname (which an attacker may have replaced).
    ///
    /// The resolver supplies an `O_PATH` fd to avoid self-deadlock on strict
    /// fanotify marks. It cannot be read for a SHA-256 retry, so an identity
    /// mismatch fails closed and requires explicit re-enrollment.
    ///
    /// `display_path` is the readlink of `/proc/PID/exe` (may carry a
    /// `" (deleted)"` suffix when the original path was unlinked). The lookup
    /// key is the canonical enrollment path; the suffix is stripped for the
    /// lookup so a deleted-but-still-running enrolled binary keeps verifying
    /// against its executed object.
    pub fn verify_fd(&mut self, fd: &File, display_path: &Path) -> bool {
        let lookup = strip_deleted_suffix(display_path);
        let Some(record) = self.by_path.get(&lookup).cloned() else {
            return false;
        };
        let Ok(current_identity) = fd_identity(fd) else {
            return false;
        };
        if current_identity == record.identity {
            return true;
        }
        // `identity::executed_image_fd` deliberately uses O_PATH so resolving
        // /proc/PID/exe cannot deadlock guardd on its own strict filesystem
        // permission mark. O_PATH fds cannot be read, therefore this branch
        // cannot truthfully rehash the executed object. An identity change is
        // fail-closed and requires explicit re-enrollment; never retain a
        // stale "hash was rechecked" promise.
        self.by_path.remove(&lookup);
        false
    }

    pub fn records(&self) -> impl Iterator<Item = &EnrollmentRecord> {
        self.by_path.values()
    }
}

fn canonicalize(exe: &Path) -> Result<PathBuf, EnrollError> {
    // Reject relative/symlink-uncanonicalized paths at enrollment time so that
    // lookups (which use `/proc/<pid>/exe` canonical paths) match.
    if exe.is_absolute() && exe.components().all(|c| c.as_os_str() != "..") {
        Ok(exe.to_path_buf())
    } else {
        Err(EnrollError::NotCanonical(exe.to_path_buf()))
    }
}

/// The kernel renders a running-but-unlinked executable as `"... (deleted)"`
/// in `/proc/<pid>/exe`; strip that suffix for enrollment lookup while keeping
/// the executed-object fd as the source of truth.
fn strip_deleted_suffix(path: &Path) -> PathBuf {
    const SUFFIX: &str = " (deleted)";
    let s = path.to_string_lossy();
    s.strip_suffix(SUFFIX)
        .map(PathBuf::from)
        .unwrap_or_else(|| path.to_path_buf())
}

fn stat_identity(path: &Path) -> io::Result<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(path)?;
    Ok(FileIdentity {
        dev: md.dev(),
        ino: md.ino(),
        size: md.len(),
        mtime_ns: md.mtime(),
    })
}

/// File identity of an already-open executed image (LFH1). Uses `fstat` on the
/// fd the kernel gave us for `/proc/<pid>/exe`, so the identity belongs to the
/// object the process is actually running — not to whatever now sits at the
/// pathname.
fn fd_identity(fd: &File) -> io::Result<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    let md = fd.metadata()?;
    Ok(FileIdentity {
        dev: md.dev(),
        ino: md.ino(),
        size: md.len(),
        mtime_ns: md.mtime(),
    })
}

fn hash_file(path: &Path) -> io::Result<Sha256Digest> {
    let mut f = File::open(path)?;
    hash_read(&mut f)
}

fn hash_read(f: &mut File) -> io::Result<Sha256Digest> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    fn write_exe(dir: &Path, name: &str, body: &[u8]) -> PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body).unwrap();
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o755))
            .unwrap();
        p
    }

    #[test]
    fn enrolled_user_writable_verifies() {
        let dir = tempdir().unwrap();
        let exe = write_exe(dir.path(), "mybrowser", b"hello world");
        let mut store = EnrollmentStore::new();
        store.enroll(&exe).unwrap();
        assert!(store.verify(&exe));
    }

    #[test]
    fn changed_binary_invalidates_enrollment() {
        let dir = tempdir().unwrap();
        let exe = write_exe(dir.path(), "mybrowser", b"original bytes");
        let mut store = EnrollmentStore::new();
        store.enroll(&exe).unwrap();
        assert!(store.verify(&exe));

        // Tamper with the binary contents.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&exe)
            .unwrap();
        f.write_all(b"completely different bytes").unwrap();
        drop(f);

        assert!(!store.verify(&exe), "changed binary must invalidate trust");
    }

    #[test]
    fn unenrolled_path_does_not_verify() {
        let dir = tempdir().unwrap();
        let exe = write_exe(dir.path(), "mybrowser", b"hi");
        let mut store = EnrollmentStore::new();
        assert!(!store.verify(&exe));
    }

    #[test]
    fn rehash_after_metadata_only_change_stays_valid() {
        let dir = tempdir().unwrap();
        let exe = write_exe(dir.path(), "mybrowser", b"stable bytes");
        let mut store = EnrollmentStore::new();
        store.enroll(&exe).unwrap();
        assert!(store.verify(&exe));

        // Touch the file (mtime changes, bytes unchanged).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i64;
        let times = [libc::timespec {
            tv_sec: now / 1_000_000_000,
            tv_nsec: now % 1_000_000_000,
        }; 2];
        // SAFETY: `utimensat` with AT_FDCWD and a valid path, nsec within bounds.
        unsafe {
            let c = std::ffi::CString::new(exe.as_os_str().as_encoded_bytes()).unwrap();
            libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0);
        }
        assert!(store.verify(&exe), "metadata-only change must stay valid");
    }

    #[test]
    fn verify_fd_accepts_actual_executed_object() {
        let dir = tempdir().unwrap();
        let exe = write_exe(dir.path(), "mybrowser", b"executed bytes");
        let mut store = EnrollmentStore::new();
        store.enroll(&exe).unwrap();
        let fd = File::open(&exe).unwrap();
        assert!(store.verify_fd(&fd, &exe));
    }

    #[test]
    fn verify_fd_uses_the_executed_fd_identity_not_the_pathname() {
        // LFH1: the pathname is replaced by a different inode; the fd still
        // refers to the enrolled executed object, so trust must survive.
        let dir = tempdir().unwrap();
        let exe = write_exe(dir.path(), "mybrowser", b"trusted bytes");
        let mut store = EnrollmentStore::new();
        store.enroll(&exe).unwrap();

        // Hold the executed object open, then rename a NEW inode over the
        // pathname (a real pathname replacement, not an in-place truncate).
        let fd = File::open(&exe).unwrap();
        let attacker = write_exe(dir.path(), "attacker", b"attacker bytes");
        std::fs::rename(&attacker, &exe).unwrap();
        assert!(
            store.verify_fd(&fd, &exe),
            "fd of the original object must still verify"
        );
        assert!(
            !store.verify(&exe),
            "pathname now names the attacker's file; path-based verify must fail"
        );
    }

    #[test]
    fn verify_fd_tolerates_deleted_suffix_for_lookup() {
        // `/proc/PID/exe` renders a deleted executable as "... (deleted)".
        let dir = tempdir().unwrap();
        let exe = write_exe(dir.path(), "mybrowser", b"still running");
        let mut store = EnrollmentStore::new();
        store.enroll(&exe).unwrap();
        let fd = File::open(&exe).unwrap();
        // Delete the pathname: the fd stays valid.
        std::fs::remove_file(&exe).unwrap();
        let deleted_display = PathBuf::from(format!("{} (deleted)", exe.display()));
        assert!(store.verify_fd(&fd, &deleted_display));
    }

    #[test]
    fn verify_fd_changed_bytes_invalidate() {
        let dir = tempdir().unwrap();
        let exe = write_exe(dir.path(), "mybrowser", b"original-bytes-here");
        let mut store = EnrollmentStore::new();
        store.enroll(&exe).unwrap();
        // Modify contents through an fd (in-place truncate keeps the inode but
        // changes size + bytes).
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&exe)
            .unwrap();
        f.write_all(b"tampered").unwrap();
        drop(f);
        let fd = File::open(&exe).unwrap();
        assert!(!store.verify_fd(&fd, &exe), "changed bytes must invalidate");
    }

    #[test]
    fn verify_fd_o_path_identity_change_requires_reenrollment() {
        use std::os::fd::FromRawFd;

        let dir = tempdir().unwrap();
        let exe = write_exe(dir.path(), "mybrowser", b"original-bytes-here");
        let mut store = EnrollmentStore::new();
        store.enroll(&exe).unwrap();
        let replacement = write_exe(dir.path(), "replacement", b"tampered-bytes-here");
        std::fs::rename(&replacement, &exe).unwrap();

        let c_path = std::ffi::CString::new(exe.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: O_PATH fd is owned by this test File and closed on drop.
        let raw_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        assert!(
            raw_fd >= 0,
            "open O_PATH: {}",
            std::io::Error::last_os_error()
        );
        let fd = unsafe { File::from_raw_fd(raw_fd) };

        assert!(
            !store.verify_fd(&fd, &exe),
            "an O_PATH identity mismatch cannot be rehashed and must fail closed"
        );
        assert_eq!(store.records().count(), 0, "stale enrollment is removed");
    }
}
