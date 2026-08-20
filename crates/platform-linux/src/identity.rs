//! Linux process identity resolver.
//!
//! Resolves a live PID into a `guard_core::ProcessIdentity` strong enough that
//! renaming malware to `firefox` does not grant access: the decision is driven
//! by executable file identity + ownership + trust tier, never by the process
//! or executable name alone.
//!
//! Identity fields captured per the Phase 04 contract:
//! - PID + start time (`/proc/<pid>/stat` `starttime`)
//! - UID/GID (`/proc/<pid>/status`)
//! - canonical exe path (`/proc/<pid>/exe`) + `st_dev`/`st_ino`
//! - exe owner/mode (for trust classification)
//! - cmdline (audit only)
//! - bounded parent/ancestor chain
//!
//! Trust tiers:
//! 1. `SystemPackage` — root-owned and not writable by group/other (the
//!    current user cannot modify it). No package manager is invoked on the hot
//!    path; ownership/mode is the security property we actually need. Arch /
//!    Debian / RPM package-ownership refinement can be layered on later as a
//!    background cache without changing this interface.
//! 2. `Sandbox` — reserved for sandbox/package identity (e.g. flatpak/snap
//!    app id); not produced by V1.
//! 3. `EnrolledUserWritable` — user-writable exe whose SHA-256 was explicitly
//!    enrolled and still matches.
//! 4. `Unknown` — anything else (fail closed).

use std::fs;
use std::os::fd::FromRawFd;
use std::path::{Path, PathBuf};

use crate::enrollment::EnrollmentStore;
use guard_core::identity::{
    AncestorSummary, ProcessIdentity, ProcessIntegrity, ProcessStableId, TrustTier,
};

/// Adapter for the portable process-identity contract. `/proc` remains
/// entirely inside this Linux crate; the daemon sees only domain identities.
pub struct LinuxProcessIdentityResolver {
    enrollment: std::sync::Mutex<EnrollmentStore>,
}

impl LinuxProcessIdentityResolver {
    pub fn new(enrollment: EnrollmentStore) -> Self {
        Self {
            enrollment: std::sync::Mutex::new(enrollment),
        }
    }
}

impl guard_platform::ProcessIdentityResolver for LinuxProcessIdentityResolver {
    fn resolve(&self, pid: u32, resource_owner_uid: u32) -> anyhow::Result<ProcessIdentity> {
        let pid = i32::try_from(pid).map_err(|_| anyhow::anyhow!("process id is out of range"))?;
        let mut enrollment = self
            .enrollment
            .lock()
            .map_err(|_| anyhow::anyhow!("process enrollment mutex poisoned"))?;
        Ok(resolve(pid, resource_owner_uid, &mut enrollment)?)
    }

    fn is_live_instance(&self, identity: &ProcessStableId) -> anyhow::Result<bool> {
        let pid = i32::try_from(identity.pid)
            .map_err(|_| anyhow::anyhow!("process id is out of range"))?;
        Ok(read_start_time(pid).ok() == Some(identity.start_time))
    }

    fn ancestors(&self, pid: u32) -> anyhow::Result<Vec<AncestorSummary>> {
        Ok(self.resolve(pid, 0)?.ancestors)
    }
}

/// Maximum ancestor depth collected for audit context. Bounded so a pathological
/// ancestry cannot stall the hot path.
pub const MAX_ANCESTOR_DEPTH: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("reading /proc/{pid}/stat failed: {err}")]
    StatRead {
        pid: i32,
        #[source]
        err: std::io::Error,
    },
    #[error("parsing /proc/{pid}/stat failed: {reason}")]
    StatParse { pid: i32, reason: &'static str },
    #[error("reading /proc/{pid}/exe failed: {err}")]
    ExeRead {
        pid: i32,
        #[source]
        err: std::io::Error,
    },
    #[error("stat-ing exe {exe} failed: {err}")]
    ExeStat {
        exe: PathBuf,
        #[source]
        err: std::io::Error,
    },
    #[error("reading /proc/{pid}/status failed: {err}")]
    StatusRead {
        pid: i32,
        #[source]
        err: std::io::Error,
    },
    #[error("parsing /proc/{pid}/status failed: {reason}")]
    StatusParse { pid: i32, reason: &'static str },
}

/// Kernel-observed facts needed to authorize a stopped child safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoppedChildIdentity {
    pub target: guard_core::identity::StableIdentity,
    pub uid: u32,
    pub gid: u32,
    pub parent_pid: i32,
}

/// Pure trust classifier, unit-testable without real files.
///
/// - `exe_owner_uid`: owner of the executable file
/// - `mode`: executable mode bits (`st_mode`)
/// - `current_uid`: the user whose protected resource is being opened (opener)
/// - `enrolled`: whether an enrollment record verified the current bytes
pub fn classify_trust(
    exe_owner_uid: u32,
    mode: u32,
    _current_uid: u32,
    enrolled: bool,
) -> TrustTier {
    // Root-owned AND not writable by group/other => the opener cannot have
    // tampered with it. Group/other-writable root files are misconfigured and
    // fail closed to Unknown.
    if exe_owner_uid == 0 && (mode & 0o022) == 0 {
        return TrustTier::SystemPackage;
    }
    if enrolled {
        return TrustTier::EnrolledUserWritable;
    }
    TrustTier::Unknown
}

/// Resolve a live PID into a full `ProcessIdentity`.
///
/// `current_uid` is the owner of the protected resource being accessed (used
/// only as context for trust classification). Browser classification
/// (`browser` field) is left to Phase 05's registry; the resolver returns
/// `browser: None` here.
///
/// Identity comes from the **actual executed image**: `/proc/<pid>/exe` is
/// opened once and that fd is `fstat`-ed and handed to enrollment verification,
/// so `exe_dev`/`exe_ino`/owner/mode describe the object the process is really
/// running — even after the pathname was replaced or unlinked. The readlink
/// result is kept only as a display/registry clue.
pub fn resolve(
    pid: i32,
    current_uid: u32,
    enrollment: &mut EnrollmentStore,
) -> Result<ProcessIdentity, ResolveError> {
    let (start_time, ppid) = read_stat(pid)?;
    let exe = read_exe(pid)?;
    let image = executed_image_fd(pid)?;
    let (exe_dev, exe_ino, exe_mode, exe_owner_uid) = fstat_executed_image(&image)?;
    let enrolled = enrollment.verify_fd(&image, &exe);
    let trust_tier = classify_trust(exe_owner_uid, exe_mode, current_uid, enrolled);
    let (uid, gid) = read_uid_gid(pid)?;
    let cmdline = read_cmdline(pid);
    let ancestors = collect_ancestors(ppid);

    let stable = ProcessStableId {
        pid: pid as u32,
        start_time,
        exe,
        exe_dev,
        exe_ino,
    };

    Ok(ProcessIdentity {
        stable,
        uid,
        gid,
        exe_owner_uid,
        browser: None,
        trust_tier,
        cmdline,
        ancestors,
        // Linux has no Process Shield in this harness; every resolved instance
        // is Normal so the existing fanotify behavior is preserved.
        integrity: ProcessIntegrity::Normal,
    })
}

/// Open the actual executed image of `pid` (`/proc/<pid>/exe`) and return the
/// fd. The fd describes the object the process is running, immune to pathname
/// replacement or unlinking after exec.
///
/// Uses `O_PATH` (not a plain `open`): `/proc/<pid>/exe` is a magic link, and
/// a plain open resolves it to the image on ITS filesystem. If that
/// filesystem carries a fanotify `FAN_MARK_FILESYSTEM | FAN_OPEN_PERM` mark
/// (strict mode), the open generates a permission event that only guardd's
/// own event loop can answer — while guardd is inside that very open, so the
/// event is never consumed: the daemon wedges in `D` state and every open on
/// that filesystem blocks (observed full-system lockup in testing). `O_PATH`
/// opens never fire `FAN_OPEN_PERM` (the kernel skips permission checks for
/// `O_PATH`), and `fstat` on the `O_PATH` fd still yields the image's
/// `(dev, ino, mode, uid)`.
fn executed_image_fd(pid: i32) -> Result<std::fs::File, ResolveError> {
    let c_path =
        std::ffi::CString::new(format!("/proc/{pid}/exe")).map_err(|_| ResolveError::ExeRead {
            pid,
            err: std::io::Error::from(std::io::ErrorKind::InvalidInput),
        })?;
    // SAFETY: O_PATH open of /proc/<pid>/exe; not gated by permission marks;
    // c_path outlives the call.
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(ResolveError::ExeRead {
            pid,
            err: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: fd is owned; File::from_raw_fd takes ownership and closes it.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// `fstat` an executed-image fd for `(dev, ino, mode, owner_uid)`.
fn fstat_executed_image(fd: &std::fs::File) -> Result<(u64, u64, u32, u32), ResolveError> {
    use std::os::unix::fs::MetadataExt;
    let md = fd.metadata().map_err(|err| ResolveError::ExeStat {
        exe: PathBuf::from("/proc/<pid>/exe"),
        err,
    })?;
    Ok((md.dev(), md.ino(), md.mode(), md.uid()))
}

/// Read just the process start time (`/proc/<pid>/stat` `starttime`).
///
/// Cheaper than a full `resolve` and used by the enforcement cache to detect
/// PID reuse without re-doing exe/status/cmdline/ancestor work on every event.
/// Returns `Err` if the process has exited.
pub fn read_start_time(pid: i32) -> Result<u64, ResolveError> {
    Ok(read_stat(pid)?.0)
}

/// Read the Linux thread-group ID from `/proc/<pid>/status`. Fanotify may
/// report a thread ID, while the BPF socket-send hook uses TGID to cover the
/// reader's entire thread group.
pub fn read_tgid(pid: i32) -> Result<u32, ResolveError> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|err| ResolveError::StatusRead { pid, err })?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Tgid:\t"))
        .and_then(|value| value.trim().parse().ok())
        .ok_or(ResolveError::StatusParse {
            pid,
            reason: "missing Tgid",
        })
}

/// Build the identity that a stopped child will have after it execs a daemon-
/// selected executable. The child contributes only kernel-observed invocation
/// facts (PID/start time/UID/parent); executable path and inode come from the
/// daemon's trusted path, never from IPC.
pub fn verify_stopped_child_for_exec(
    pid: i32,
    expected_parent: i32,
    expected_uid: u32,
    expected_gid: u32,
    trusted_exe: &Path,
) -> Result<StoppedChildIdentity, String> {
    let details = read_stat_details(pid).map_err(|e| e.to_string())?;
    if details.ppid != expected_parent {
        return Err(format!(
            "pid {pid} parent is {}, expected IPC peer {expected_parent}",
            details.ppid
        ));
    }
    if details.state != 'T' && details.state != 't' {
        return Err(format!(
            "pid {pid} is not stopped (state={})",
            details.state
        ));
    }
    let (uid, gid) = read_uid_gid(pid).map_err(|e| e.to_string())?;
    if uid != expected_uid || gid != expected_gid {
        return Err(format!(
            "pid {pid} credentials {uid}:{gid} do not match IPC peer {expected_uid}:{expected_gid}"
        ));
    }

    use std::os::unix::fs::MetadataExt;
    let canonical = fs::canonicalize(trusted_exe).map_err(|e| {
        format!(
            "canonicalize trusted executable {}: {e}",
            trusted_exe.display()
        )
    })?;
    let metadata = fs::metadata(&canonical)
        .map_err(|e| format!("stat trusted executable {}: {e}", canonical.display()))?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(format!(
            "trusted executable {} must be root-owned and not group/other-writable",
            canonical.display()
        ));
    }

    Ok(StoppedChildIdentity {
        target: guard_core::identity::StableIdentity {
            exe: canonical,
            start_time: details.start_time,
            dev: metadata.dev(),
            ino: metadata.ino(),
        },
        uid,
        gid,
        parent_pid: details.ppid,
    })
}

/// Resolve the system `ssh-add` binary accepted by the daemon. User-selected
/// binaries are deliberately excluded from the SSH-load capability.
pub fn trusted_ssh_add_path() -> Result<PathBuf, String> {
    trusted_system_executable(&["/usr/bin/ssh-add", "/bin/ssh-add"], "ssh-add")
}

/// Resolve the system OpenSSH `ssh-agent` binary accepted as an agent endpoint.
/// A same-UID listener implemented by any other executable is rejected even if
/// it owns the socket pathname.
pub fn trusted_ssh_agent_path() -> Result<PathBuf, String> {
    trusted_system_executable(&["/usr/bin/ssh-agent", "/bin/ssh-agent"], "ssh-agent")
}

fn trusted_system_executable(candidates: &[&str], name: &str) -> Result<PathBuf, String> {
    for candidate in candidates {
        let path = Path::new(candidate);
        if path.is_file() {
            let canonical = fs::canonicalize(path)
                .map_err(|e| format!("canonicalize {}: {e}", path.display()))?;
            use std::os::unix::fs::MetadataExt;
            let metadata = fs::metadata(&canonical)
                .map_err(|e| format!("stat {}: {e}", canonical.display()))?;
            if metadata.uid() == 0 && metadata.mode() & 0o022 == 0 {
                return Ok(canonical);
            }
        }
    }
    Err(format!("no root-owned, non-writable system {name} found"))
}

/// Verify a live process is the expected user's invocation of one exact,
/// trusted system executable. The start time is sampled before and after exe
/// resolution so PID exit/reuse during verification fails closed.
pub fn verify_trusted_process_executable(
    pid: i32,
    expected_uid: u32,
    trusted_exe: &Path,
) -> Result<ProcessStableId, String> {
    if pid <= 0 {
        return Err(format!("invalid peer pid {pid}"));
    }
    let before = read_stat_details(pid).map_err(|e| e.to_string())?;
    let (uid, _) = read_uid_gid(pid).map_err(|e| e.to_string())?;
    if uid != expected_uid {
        return Err(format!(
            "process {pid} uid {uid} does not match requesting uid {expected_uid}"
        ));
    }

    let expected = fs::canonicalize(trusted_exe).map_err(|e| {
        format!(
            "canonicalize trusted executable {}: {e}",
            trusted_exe.display()
        )
    })?;
    let observed = read_exe(pid).map_err(|e| e.to_string())?;
    if observed != expected {
        return Err(format!(
            "process {pid} executable {} is not trusted {}",
            observed.display(),
            expected.display()
        ));
    }

    use std::os::unix::fs::MetadataExt;
    let metadata = fs::metadata(&expected)
        .map_err(|e| format!("stat trusted executable {}: {e}", expected.display()))?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(format!(
            "trusted executable {} must be root-owned and not group/other-writable",
            expected.display()
        ));
    }
    let after = read_stat_details(pid).map_err(|e| e.to_string())?;
    if before.start_time != after.start_time {
        return Err(format!(
            "process {pid} changed identity during verification"
        ));
    }

    Ok(ProcessStableId {
        pid: pid as u32,
        start_time: after.start_time,
        exe: expected,
        exe_dev: metadata.dev(),
        exe_ino: metadata.ino(),
    })
}

/// Read one environment value from a process without returning or logging the
/// rest of its environment.
pub fn read_process_env(pid: i32, key: &str) -> Result<Option<String>, String> {
    let bytes = fs::read(format!("/proc/{pid}/environ"))
        .map_err(|e| format!("reading /proc/{pid}/environ: {e}"))?;
    let prefix = format!("{key}=");
    Ok(bytes
        .split(|byte| *byte == 0)
        .filter_map(|entry| std::str::from_utf8(entry).ok())
        .find_map(|entry| entry.strip_prefix(&prefix).map(str::to_owned)))
}

#[derive(Debug, Clone, Copy)]
struct ProcStatDetails {
    state: char,
    ppid: i32,
    start_time: u64,
}

/// Read `/proc/<pid>/stat` and return `(starttime, ppid)`. Robust against
/// `comm` fields that contain spaces or parentheses.
fn read_stat(pid: i32) -> Result<(u64, i32), ResolveError> {
    let details = read_stat_details(pid)?;
    Ok((details.start_time, details.ppid))
}

fn read_stat_details(pid: i32) -> Result<ProcStatDetails, ResolveError> {
    let raw = fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|err| ResolveError::StatRead { pid, err })?;
    // `comm` is wrapped in parentheses and may contain spaces/parens, so split
    // at the LAST ')'.
    let close = raw.rfind(')').ok_or(ResolveError::StatParse {
        pid,
        reason: "no closing paren",
    })?;
    let after = &raw[close + 1..];
    let parts: Vec<&str> = after.split_whitespace().collect();
    // After ')': state(0) ppid(1) ... starttime(19)
    if parts.len() <= 19 {
        return Err(ResolveError::StatParse {
            pid,
            reason: "too few fields",
        });
    }
    let state = parts[0].chars().next().ok_or(ResolveError::StatParse {
        pid,
        reason: "state",
    })?;
    let ppid: i32 = parts[1].parse().map_err(|_| ResolveError::StatParse {
        pid,
        reason: "ppid",
    })?;
    let starttime: u64 = parts[19].parse().map_err(|_| ResolveError::StatParse {
        pid,
        reason: "starttime",
    })?;
    Ok(ProcStatDetails {
        state,
        ppid,
        start_time: starttime,
    })
}

fn read_exe(pid: i32) -> Result<PathBuf, ResolveError> {
    fs::read_link(format!("/proc/{pid}/exe")).map_err(|err| ResolveError::ExeRead { pid, err })
}

fn read_uid_gid(pid: i32) -> Result<(u32, u32), ResolveError> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|err| ResolveError::StatusRead { pid, err })?;
    let mut uid: Option<u32> = None;
    let mut gid: Option<u32> = None;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            uid = parse_first_uid(rest);
        } else if let Some(rest) = line.strip_prefix("Gid:") {
            gid = parse_first_uid(rest);
        }
    }
    let uid = uid.ok_or(ResolveError::StatusParse {
        pid,
        reason: "Uid line missing",
    })?;
    let gid = gid.ok_or(ResolveError::StatusParse {
        pid,
        reason: "Gid line missing",
    })?;
    Ok((uid, gid))
}

fn parse_first_uid(rest: &str) -> Option<u32> {
    rest.split_whitespace().next()?.parse().ok()
}

fn read_cmdline(pid: i32) -> Vec<String> {
    let bytes = match fs::read(format!("/proc/{pid}/cmdline")) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

/// Collect a bounded ancestor chain starting from `ppid` (closest first).
/// Stops at PID 0/1 or when a parent's `/proc` entry is unreadable (exited).
///
/// Each ancestor captures its exe file identity (`exe_dev`/`exe_ino`) via a
/// `stat()` so the policy engine can anchor migration-lease tree-scoping to the
/// ancestor's executable file identity, not just its path name.
pub fn collect_ancestors(mut ppid: i32) -> Vec<AncestorSummary> {
    let mut out = Vec::new();
    for _ in 0..MAX_ANCESTOR_DEPTH {
        if ppid <= 1 {
            break;
        }
        let Ok((start_time, next_ppid)) = read_stat(ppid) else {
            // Parent exited (ENOENT) or unreadable: stop gracefully.
            break;
        };
        let exe = read_exe(ppid).unwrap_or_else(|_| PathBuf::new());
        let (exe_dev, exe_ino) = stat_dev_ino(&exe).unwrap_or((0, 0));
        out.push(AncestorSummary {
            pid: ppid as u32,
            start_time,
            exe,
            exe_dev,
            exe_ino,
        });
        ppid = next_ppid;
    }
    out
}

/// `stat()` a path and return `(st_dev, st_ino)`. Returns `(0, 0)` if the path
/// is empty or unreadable (e.g. the process exited mid-walk).
fn stat_dev_ino(path: &Path) -> std::io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    if path.as_os_str().is_empty() {
        return Ok((0, 0));
    }
    let md = fs::metadata(path)?;
    Ok((md.dev(), md.ino()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_core::lease::LeaseSet;
    use guard_core::policy::{evaluate, AccessEvent, AccessOperation, Decision, DenyReason};
    use guard_core::resource::{
        BrowserId, ProfileId, ProtectedResource, ProtectedResourceId, ProtectedResourceKind,
    };
    use std::path::PathBuf;
    use std::process::{Child, Command};
    use tempfile::tempdir;

    #[test]
    fn read_tgid_returns_our_process_group() {
        // A test thread can have a different TID, but its TGID is always the
        // process ID exposed by getpid().
        assert_eq!(read_tgid(unsafe { libc::getpid() }).unwrap(), unsafe {
            libc::getpid() as u32
        });
    }

    struct ChildGuard(std::process::Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            // SAFETY: the PID belongs to this Child; SIGCONT/SIGKILL are used
            // only for deterministic test cleanup.
            unsafe {
                libc::kill(self.0.id() as i32, libc::SIGCONT);
                libc::kill(self.0.id() as i32, libc::SIGKILL);
            }
            let _ = self.0.wait();
        }
    }

    #[test]
    fn stopped_child_identity_requires_parent_uid_gid_and_stop_state() {
        let child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let guard = ChildGuard(child);
        let pid = guard.0.id() as i32;
        // SAFETY: pid is the live child created above.
        assert_eq!(unsafe { libc::kill(pid, libc::SIGSTOP) }, 0);
        let mut status = 0;
        // SAFETY: waitpid observes our direct child and writes one status int.
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) },
            pid
        );
        assert!(libc::WIFSTOPPED(status));

        let verified = verify_stopped_child_for_exec(
            pid,
            unsafe { libc::getpid() },
            unsafe { libc::getuid() },
            unsafe { libc::getgid() },
            Path::new("/bin/true"),
        )
        .unwrap();
        assert_eq!(verified.parent_pid, unsafe { libc::getpid() });
        assert_eq!(verified.target.start_time, read_start_time(pid).unwrap());
        assert_eq!(verified.target.exe, fs::canonicalize("/bin/true").unwrap());

        assert!(verify_stopped_child_for_exec(
            pid,
            1,
            unsafe { libc::getuid() },
            unsafe { libc::getgid() },
            Path::new("/bin/true"),
        )
        .unwrap_err()
        .contains("expected IPC peer"));
        assert!(verify_stopped_child_for_exec(
            pid,
            unsafe { libc::getpid() },
            unsafe { libc::getuid() }.saturating_add(1),
            unsafe { libc::getgid() },
            Path::new("/bin/true"),
        )
        .unwrap_err()
        .contains("do not match IPC peer"));
    }

    #[test]
    fn trusted_process_verification_accepts_system_ssh_agent_only() {
        let trusted = trusted_ssh_agent_path().unwrap();
        let dir = tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let child = Command::new(&trusted)
            .arg("-D")
            .arg("-a")
            .arg(&socket)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let guard = ChildGuard(child);
        let pid = guard.0.id() as i32;
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(socket.exists(), "ssh-agent did not create its test socket");

        let identity = match verify_trusted_process_executable(
            pid,
            // SAFETY: getuid has no preconditions.
            unsafe { libc::getuid() },
            &trusted,
        ) {
            Ok(identity) => identity,
            Err(error)
                if unsafe { libc::geteuid() } != 0 && error.contains("Permission denied") =>
            {
                // OpenSSH deliberately makes an agent process non-dumpable.
                // On ptrace-restricted hosts only root guardd can resolve its
                // /proc exe; the privileged acceptance suite proves success.
                return;
            }
            Err(error) => panic!("trusted ssh-agent verification failed: {error}"),
        };
        assert_eq!(identity.pid, pid as u32);
        assert_eq!(identity.exe, trusted);

        let error = verify_trusted_process_executable(
            // SAFETY: getpid has no preconditions.
            unsafe { libc::getpid() },
            // SAFETY: getuid has no preconditions.
            unsafe { libc::getuid() },
            &identity.exe,
        )
        .unwrap_err();
        assert!(error.contains("is not trusted"));
    }

    /// RAII guard that kills the child so tests never leak sleeping processes.
    struct KillOnDrop(Option<Child>);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            if let Some(mut c) = self.0.take() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }

    fn find_sleep() -> PathBuf {
        for c in ["/bin/sleep", "/usr/bin/sleep"] {
            if Path::new(c).exists() {
                return PathBuf::from(c);
            }
        }
        panic!("no sleep binary found for test");
    }

    fn chrome_cookie_resource(uid: u32) -> ProtectedResource {
        ProtectedResource {
            id: ProtectedResourceId("chrome/Default/CookieStore".into()),
            kind: ProtectedResourceKind::CookieStore,
            owner_uid: uid,
            browser: Some(BrowserId("chrome".into())),
            profile: Some(ProfileId("Default".into())),
            path: PathBuf::from("/tmp/chrome/Default/Cookies"),
        }
    }

    // --- pure trust classifier ---

    #[test]
    fn classify_trust_root_owned_immutable_is_system_package() {
        assert_eq!(
            classify_trust(0, 0o755, 1000, false),
            TrustTier::SystemPackage
        );
    }

    #[test]
    fn classify_trust_root_owned_group_writable_fails_closed() {
        assert_eq!(classify_trust(0, 0o775, 1000, false), TrustTier::Unknown);
        assert_eq!(classify_trust(0, 0o757, 1000, false), TrustTier::Unknown);
    }

    #[test]
    fn classify_trust_user_owned_unenrolled_is_unknown() {
        assert_eq!(classify_trust(1000, 0o755, 1000, false), TrustTier::Unknown);
    }

    #[test]
    fn classify_trust_user_owned_enrolled_is_enrolled() {
        assert_eq!(
            classify_trust(1000, 0o755, 1000, true),
            TrustTier::EnrolledUserWritable
        );
    }

    // --- live resolver ---

    #[test]
    fn resolve_real_root_owned_binary_is_system_package() {
        let sleep = find_sleep();
        let child = Command::new(&sleep).arg("30").spawn().expect("spawn sleep");
        let pid = child.id() as i32;
        let _guard = KillOnDrop(Some(child));
        // give /proc a moment to populate
        std::thread::sleep(std::time::Duration::from_millis(50));

        let mut enrollment = EnrollmentStore::new();
        let id = resolve(pid, 1000, &mut enrollment).expect("resolve sleep child");
        assert_eq!(id.trust_tier, TrustTier::SystemPackage);
        assert!(
            id.stable.exe == sleep
                || id.stable.exe.canonicalize().ok() == sleep.canonicalize().ok()
        );
        assert!(id.stable.start_time > 0);
        assert!(!id.cmdline.is_empty());
    }

    #[test]
    fn resolve_self_is_consistent_and_pid_reuse_safe() {
        let me = std::process::id() as i32;
        let mut enrollment = EnrollmentStore::new();
        let a = resolve(me, 1000, &mut enrollment).expect("resolve self");
        let b = resolve(me, 1000, &mut enrollment).expect("resolve self again");
        assert_eq!(a.stable, b.stable, "same live process => same stable id");
        // A different start_time with the same PID must NOT match (PID reuse).
        let mut reused = a.stable.clone();
        reused.start_time = a.stable.start_time.wrapping_add(1);
        assert_ne!(a.stable.stable_identity(), reused.stable_identity());
    }

    #[test]
    fn renamed_to_firefox_is_still_denied() {
        // Copy a real ELF binary to a user-writable path named "firefox". The
        // copy is owned by the test user (user-writable) and NOT enrolled, so
        // trust is Unknown even though the basename is "firefox".
        let dir = tempdir().unwrap();
        let fake_firefox = dir.path().join("firefox");
        std::fs::copy(find_sleep(), &fake_firefox).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake_firefox, std::fs::Permissions::from_mode(0o755)).unwrap();

        // Executing a freshly-written binary can transiently fail with ETXTBSY
        // on some filesystems; retry briefly.
        let mut child = None;
        for _ in 0..40 {
            match Command::new(&fake_firefox).arg("30").spawn() {
                Ok(c) => {
                    child = Some(c);
                    break;
                }
                Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
                Err(e) => panic!("spawn fake firefox: {e}"),
            }
        }
        let child = child.expect("spawn fake firefox after ETXTBSY retries");
        let pid = child.id() as i32;
        let _guard = KillOnDrop(Some(child));
        std::thread::sleep(std::time::Duration::from_millis(50));

        let mut enrollment = EnrollmentStore::new();
        let mut id = resolve(pid, 1000, &mut enrollment).expect("resolve fake firefox");
        // A naive basename classifier would call this "firefox"; prove that even
        // with browser=Some(firefox), Unknown trust => denied.
        assert_eq!(id.trust_tier, TrustTier::Unknown);
        id.browser = Some(BrowserId("firefox".into()));

        let me_uid = id.uid;
        let res = chrome_cookie_resource(me_uid);
        let evt = AccessEvent {
            resource: res,
            process: id,
            operation: AccessOperation::Open,
        };
        assert_eq!(
            evaluate(&evt, &LeaseSet::default(), 1_000_000, 0),
            Decision::Deny(DenyReason::NotTrustedIdentity)
        );
    }

    #[test]
    fn parent_chain_is_bounded_and_stops_before_init() {
        let me = std::process::id() as i32;
        let ancestors = collect_ancestors(read_stat(me).unwrap().1);
        assert!(ancestors.len() <= MAX_ANCESTOR_DEPTH);
        // None of the collected ancestors should be PID 1 (init) or 0.
        assert!(ancestors.iter().all(|a| a.pid > 1));
    }

    #[test]
    fn collect_ancestors_of_init_is_empty() {
        // PID 1's ppid is 0, so collecting from ppid=0 yields nothing.
        let ancestors = collect_ancestors(0);
        assert!(ancestors.is_empty());
    }

    #[test]
    fn collect_ancestors_handles_exited_parent() {
        // A very high PID is almost certainly not running; read_stat fails and
        // the walker must stop gracefully (no panic).
        let ancestors = collect_ancestors(2_000_000);
        assert!(ancestors.len() <= MAX_ANCESTOR_DEPTH);
    }

    // --- LFH1: actual executed image identity ---

    /// Spawn `exe` (a sleep-style binary) and return the child plus its
    /// resolved identity BEFORE any pathname tampering.
    ///
    /// Waits (bounded) until the child has actually exec'd `exe`: a fixed
    /// sleep is not enough under heavy parallel test load — the child may
    /// still be running the test binary's image, so `/proc/PID/exe` would not
    /// yet name `exe` and the resolved identity would be the test binary's.
    // The returned `Child` is owned by the caller's `KillOnDrop` guard, which
    // kills and `wait()`s it in `Drop`; the function cannot wait here without
    // blocking on the 30s sleep.
    #[allow(clippy::zombie_processes)]
    fn spawn_and_resolve(exe: &Path, enrollment: &mut EnrollmentStore) -> (Child, ProcessIdentity) {
        // Executing a freshly-written binary can transiently fail with
        // ETXTBSY on some filesystems (same retry pattern as
        // `renamed_to_firefox_is_still_denied`).
        let child = {
            let mut spawned = None;
            for _ in 0..40 {
                match Command::new(exe).arg("30").spawn() {
                    Ok(c) => {
                        spawned = Some(c);
                        break;
                    }
                    Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                        std::thread::sleep(std::time::Duration::from_millis(25));
                    }
                    Err(e) => panic!("spawn {exe:?}: {e}"),
                }
            }
            spawned.expect("spawn {exe:?} after ETXTBSY retries")
        };
        let pid = child.id() as i32;
        let (dev, ino) = {
            use std::os::unix::fs::MetadataExt;
            let md = std::fs::metadata(exe).expect("stat spawned exe");
            (md.dev(), md.ino())
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Ok(identity) = resolve(pid, 1000, enrollment) {
                if identity.stable.exe_dev == dev && identity.stable.exe_ino == ino {
                    return (child, identity);
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "child {pid} did not exec {} within 10s",
                exe.display()
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn executed_image_survives_pathname_replacement() {
        // LFH1 B: process starts running A; pathname A is replaced by a new
        // inode B. The resolver must keep identifying the ACTUAL executed image
        // (A's dev/ino/owner), not the new file now at the same pathname.
        let dir = tempdir().unwrap();
        let a = dir.path().join("enrolled-a");
        std::fs::copy(find_sleep(), &a).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut enrollment = EnrollmentStore::new();
        // Enroll A as user-writable so the executed object's hash matters.
        enrollment.enroll(&a).unwrap();

        let (child, identity_a) = spawn_and_resolve(&a, &mut enrollment);
        let pid = child.id() as i32;
        let _guard = KillOnDrop(Some(child));

        // Replace the pathname with a different inode while A is running.
        let b = dir.path().join("b");
        std::fs::copy(find_sleep(), &b).unwrap();
        std::fs::set_permissions(&b, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::rename(&b, &a).unwrap();

        let identity_after = resolve(pid, 1000, &mut enrollment).expect("resolve after replace");
        // The executed image identity is unchanged even though the pathname
        // now names a different inode.
        assert_eq!(
            identity_after.stable.exe_dev, identity_a.stable.exe_dev,
            "executed image dev must not change after pathname replacement"
        );
        assert_eq!(
            identity_after.stable.exe_ino, identity_a.stable.exe_ino,
            "executed image ino must not change after pathname replacement"
        );
        // The executed object is still the enrolled A (verify_fd hashes the fd,
        // not the replaced pathname).
        assert_eq!(identity_after.trust_tier, identity_a.trust_tier);
        assert_eq!(
            identity_after.trust_tier,
            TrustTier::EnrolledUserWritable,
            "replacement must not revoke the executed object's enrollment"
        );
    }

    #[test]
    fn executed_image_survives_unlink_with_deleted_suffix() {
        // LFH1 B: process running, pathname unlinked; /proc/PID/exe readlink
        // shows "... (deleted)". The fd identity must still resolve (no
        // canonicalize/suffix failure => no erroneous allow or deny).
        let dir = tempdir().unwrap();
        let exe = dir.path().join("victim");
        std::fs::copy(find_sleep(), &exe).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut enrollment = EnrollmentStore::new();

        let (child, identity_before) = spawn_and_resolve(&exe, &mut enrollment);
        let pid = child.id() as i32;
        let _guard = KillOnDrop(Some(child));

        std::fs::remove_file(&exe).unwrap();
        let readlink =
            std::fs::read_link(format!("/proc/{pid}/exe")).expect("readlink after unlink");
        assert!(
            readlink.to_string_lossy().contains("(deleted)"),
            "deleted executable must readlink with the (deleted) suffix, got {readlink:?}"
        );

        let identity_after = resolve(pid, 1000, &mut enrollment).expect("resolve after unlink");
        assert_eq!(
            identity_after.stable.exe_dev, identity_before.stable.exe_dev,
            "deleted executed image keeps its dev"
        );
        assert_eq!(
            identity_after.stable.exe_ino, identity_before.stable.exe_ino,
            "deleted executed image keeps its ino"
        );
        // The readlink display path may carry the suffix; the stable identity
        // must not fail closed because of it.
        assert_eq!(
            identity_after.stable.start_time,
            identity_before.stable.start_time
        );
    }

    #[test]
    fn new_process_at_replaced_path_does_not_inherit_old_enrollment() {
        // LFH1 B step 5: a NEW process starting the replaced pathname (now B)
        // must NOT inherit A's trust.
        let dir = tempdir().unwrap();
        let a = dir.path().join("enrolled");
        std::fs::copy(find_sleep(), &a).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut enrollment = EnrollmentStore::new();
        enrollment.enroll(&a).unwrap();

        // A runs and is replaced by B (different bytes) while A is alive.
        let (child, _) = spawn_and_resolve(&a, &mut enrollment);
        let _guard = KillOnDrop(Some(child));

        // A NEW process starts the replaced pathname. Its executed image is B,
        // which has DIFFERENT bytes than enrolled A -> Unknown, even though the
        // pathname matches the enrollment key.
        let b = dir.path().join("b");
        let b_bytes = {
            let mut bytes = std::fs::read(find_sleep()).unwrap();
            bytes.push(0x7f); // trailing junk: same family, different hash
            bytes
        };
        std::fs::write(&b, b_bytes).unwrap();
        std::fs::set_permissions(&b, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::rename(&b, &a).unwrap();

        let child2 = Command::new(&a)
            .arg("30")
            .spawn()
            .expect("spawn replaced path");
        let pid2 = child2.id() as i32;
        let _guard2 = KillOnDrop(Some(child2));
        // Wait (bounded) for the exec to complete so the resolved identity is
        // B's executed image, not the test binary's pre-exec image.
        let (dev2, ino2) = {
            use std::os::unix::fs::MetadataExt;
            let md = std::fs::metadata(&a).expect("stat replaced path");
            (md.dev(), md.ino())
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let identity_new = loop {
            if let Ok(id) = resolve(pid2, 1000, &mut enrollment) {
                if id.stable.exe_dev == dev2 && id.stable.exe_ino == ino2 {
                    break id;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "child {pid2} did not exec the replaced path within 10s"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert_eq!(
            identity_new.trust_tier,
            TrustTier::Unknown,
            "new process at a replaced path must not inherit old enrollment"
        );
    }
}
