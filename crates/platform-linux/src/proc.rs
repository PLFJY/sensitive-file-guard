//! Minimal `/proc` helpers for Phase 02.
//!
//! Phase 02 only needs to resolve the canonical executable path of the opener
//! so the PoC allow-list can make an allow/deny decision. Full stable process
//! identity (start time, exe file identity, trust tiers, parent chain) arrives
//! in Phase 04.

use std::io;
use std::path::PathBuf;

/// Resolve the canonical executable path of `pid` via `/proc/<pid>/exe`.
///
/// Returns an error if the process has exited (typical for short-lived probes
/// whose identity is collected after they have already gone).
pub fn exe_path(pid: i32) -> io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
}

/// Read the target PID of a pidfd from `/proc/self/fdinfo/<pidfd>`.
///
/// A pidfd pins one kernel process instance. Cross-checking its `Pid:` field
/// against the fanotify event's pid detects a pidfd that the kernel attached
/// for a different process (or that was closed/replaced). Returns `None` when
/// the pidfd is not ours or its fdinfo is unreadable.
pub fn pidfd_target_pid(pidfd: i32) -> Option<u32> {
    if pidfd < 0 {
        return None;
    }
    let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{pidfd}")).ok()?;
    fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("Pid:\t"))
        .and_then(|value| value.trim().parse().ok())
}

/// True when the pidfd is a live reference to `expected_pid`.
pub fn pidfd_matches(pidfd: i32, expected_pid: i32) -> bool {
    pidfd_target_pid(pidfd) == Some(expected_pid as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pidfd_target_pid_reads_fdinfo() {
        // `pidfd_open` our own process and cross-check the fdinfo Pid field.
        // SAFETY: pidfd_open(2) returns an owned fd; closes below.
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id(), 0) };
        if pidfd < 0 {
            // Kernel without pidfd_open (pre-5.3): the test is a no-op.
            return;
        }
        let pid = std::process::id() as i32;
        assert_eq!(pidfd_target_pid(pidfd as i32), Some(pid as u32));
        assert!(pidfd_matches(pidfd as i32, pid));
        assert!(!pidfd_matches(pidfd as i32, pid.wrapping_add(1)));
        // SAFETY: pidfd owned by this test; closed exactly once.
        unsafe {
            libc::close(pidfd as i32);
        }
        // After close the fd is gone: fdinfo read fails -> None (fail closed).
        assert_eq!(pidfd_target_pid(pidfd as i32), None);
    }

    #[test]
    fn negative_pidfd_is_none() {
        assert_eq!(pidfd_target_pid(-1), None);
        assert!(!pidfd_matches(-1, 1));
    }
}
