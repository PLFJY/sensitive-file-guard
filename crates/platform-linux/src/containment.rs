//! Race-resistant process containment for an already-pending SSH incident.
//!
//! The caller supplies only BPF-map TGIDs for an incident. Every candidate is
//! revalidated as the recorded root or one of its live descendants before a
//! pidfd is opened; signals are then sent through those pidfds rather than
//! through a reusable numeric PID.

use std::collections::HashSet;
use std::io;
use std::os::fd::RawFd;

use guard_core::identity::{AncestorSummary, ProcessStableId};

use crate::identity;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainmentResult {
    pub terminated_processes: u32,
}

/// Linux implementation of semantic verified-tree containment. The existing
/// ancestry, pidfd, and start-time checks remain in `terminate_incident_tree`.
pub struct LinuxProcessContainment;

impl guard_platform::ProcessContainment for LinuxProcessContainment {
    fn terminate_verified_tree(
        &self,
        root: &ProcessStableId,
        uid: u32,
        members: &[u32],
    ) -> anyhow::Result<u32> {
        Ok(
            terminate_incident_tree(root, uid, members, || Ok(Vec::new()))
                .map_err(anyhow::Error::msg)?
                .terminated_processes,
        )
    }
}

struct PidFd(RawFd);

impl PidFd {
    fn open(pid: i32, expected_start_time: u64) -> Result<Self, String> {
        if pid <= 0 {
            return Err("invalid process id for containment".into());
        }
        let fd = unsafe {
            // SAFETY: pidfd_open has scalar arguments and returns a new fd or
            // -1. It does not dereference userspace memory.
            libc::syscall(libc::SYS_pidfd_open, pid, 0) as RawFd
        };
        if fd < 0 {
            return Err(format!("pidfd_open({pid}): {}", io::Error::last_os_error()));
        }
        // A pidfd pins the task selected by pidfd_open. Sampling the proc
        // start time after opening detects a PID that exited/reused before it
        // could be validated; the pidfd is then dropped without signalling.
        if identity::read_start_time(pid).ok() != Some(expected_start_time) {
            unsafe {
                // SAFETY: fd is newly owned by this function.
                libc::close(fd);
            }
            return Err(format!("process {pid} changed identity during pidfd pin"));
        }
        Ok(Self(fd))
    }

    fn signal(&self, signal: i32) -> Result<(), String> {
        let result = unsafe {
            // SAFETY: self.0 is a live pidfd; null siginfo and flags=0 are
            // the documented pidfd_send_signal form.
            libc::syscall(libc::SYS_pidfd_send_signal, self.0, signal, 0, 0)
        };
        if result == 0 {
            Ok(())
        } else {
            Err(format!(
                "pidfd_send_signal({signal}): {}",
                io::Error::last_os_error()
            ))
        }
    }
}

impl Drop for PidFd {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: PidFd owns this descriptor exactly once.
            libc::close(self.0);
        }
    }
}

/// Stop and then terminate the verified incident process tree represented by
/// the BPF map. `candidate_tgids` may be stale or adversarially influenced;
/// a candidate is ignored unless it is the exact root or currently has that
/// exact root in its kernel-observed ancestry.
pub fn terminate_incident_tree<F>(
    root: &ProcessStableId,
    uid: u32,
    candidate_tgids: &[u32],
    mut refresh_candidates: F,
) -> Result<ContainmentResult, String>
where
    F: FnMut() -> Result<Vec<u32>, String>,
{
    let root_pid = i32::try_from(root.pid).map_err(|_| "root PID is out of range")?;
    let root_fd = PidFd::open(root_pid, root.start_time)?;
    root_fd.signal(libc::SIGSTOP)?;

    let mut pinned = vec![root_fd];
    let mut seen = HashSet::from([root.pid]);
    let mut candidates = candidate_tgids.to_vec();
    // Root is already frozen. Refreshing the kernel map catches descendants
    // that a previously-running child created just before it was stopped.
    // A small fixed number keeps resolution bounded even under an adversarial
    // process tree; any surviving mapped process remains network-blocked.
    for _ in 0..4 {
        candidates.extend(refresh_candidates()?);
        let before_pass = pinned.len();
        for &candidate in &candidates {
            if candidate == root.pid || !seen.insert(candidate) {
                continue;
            }
            let pid = match i32::try_from(candidate) {
                Ok(pid) if pid > 0 => pid,
                _ => continue,
            };
            let Some(stable) = verified_descendant(pid, uid, root) else {
                continue;
            };
            let pidfd = match PidFd::open(pid, stable.start_time) {
                Ok(pidfd) => pidfd,
                Err(error) => {
                    tracing::warn!(pid, %error, "skipping process that could not be pidfd-pinned");
                    continue;
                }
            };
            if let Err(error) = pidfd.signal(libc::SIGSTOP) {
                tracing::warn!(pid, %error, "skipping process that could not be stopped");
                continue;
            }
            pinned.push(pidfd);
        }
        candidates.clear();
        if pinned.len() == before_pass {
            break;
        }
    }

    let mut terminated = 0u32;
    for pidfd in &pinned {
        match pidfd.signal(libc::SIGKILL) {
            Ok(()) => terminated = terminated.saturating_add(1),
            Err(error) => {
                tracing::warn!(%error, "pidfd-pinned containment target did not terminate")
            }
        }
    }
    Ok(ContainmentResult {
        terminated_processes: terminated,
    })
}

fn verified_descendant(
    pid: i32,
    expected_uid: u32,
    root: &ProcessStableId,
) -> Option<ProcessStableId> {
    let before = identity::read_start_time(pid).ok()?;
    let (uid, _) = read_uid_gid(pid)?;
    if uid != expected_uid {
        return None;
    }
    let ancestors = identity::collect_ancestors(read_ppid(pid)?);
    if !ancestors.iter().any(|ancestor| same_root(ancestor, root)) {
        return None;
    }
    let after = identity::read_start_time(pid).ok()?;
    if before != after {
        return None;
    }
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let metadata = std::fs::metadata(&exe).ok()?;
    use std::os::unix::fs::MetadataExt;
    Some(ProcessStableId {
        pid: pid as u32,
        start_time: after,
        exe,
        exe_dev: metadata.dev(),
        exe_ino: metadata.ino(),
    })
}

fn same_root(ancestor: &AncestorSummary, root: &ProcessStableId) -> bool {
    ancestor.pid == root.pid
        && ancestor.start_time == root.start_time
        && ancestor.exe == root.exe
        && ancestor.exe_dev == root.exe_dev
        && ancestor.exe_ino == root.exe_ino
}

fn read_uid_gid(pid: i32) -> Option<(u32, u32)> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let values: Vec<_> = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:\t"))?
        .split_whitespace()
        .collect();
    Some((values.first()?.parse().ok()?, values.get(1)?.parse().ok()?))
}

fn read_ppid(pid: i32) -> Option<i32> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = raw.get(raw.rfind(')')? + 1..)?;
    after.split_whitespace().nth(1)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use std::process::Command;

    #[test]
    fn rejects_pid_without_matching_root_ancestry() {
        let root = ProcessStableId {
            pid: 999_999,
            start_time: 1,
            exe: "/synthetic/root".into(),
            exe_dev: 1,
            exe_ino: 1,
        };
        assert!(
            verified_descendant(unsafe { libc::getpid() }, unsafe { libc::getuid() }, &root)
                .is_none()
        );
    }

    #[test]
    fn pidfd_containment_terminates_a_synthetic_root() {
        let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let pid = child.id() as i32;
        let exe = std::fs::read_link(format!("/proc/{pid}/exe")).unwrap();
        let metadata = std::fs::metadata(&exe).unwrap();
        let root = ProcessStableId {
            pid: pid as u32,
            start_time: identity::read_start_time(pid).unwrap(),
            exe,
            exe_dev: metadata.dev(),
            exe_ino: metadata.ino(),
        };
        let result = terminate_incident_tree(&root, unsafe { libc::getuid() }, &[root.pid], || {
            Ok(Vec::new())
        })
        .unwrap();
        assert_eq!(result.terminated_processes, 1);
        assert!(!child.wait().unwrap().success());
    }

    #[test]
    fn verifies_only_a_live_child_of_the_exact_root() {
        let root_pid = unsafe { libc::getpid() };
        let root_exe = std::fs::read_link(format!("/proc/{root_pid}/exe")).unwrap();
        let metadata = std::fs::metadata(&root_exe).unwrap();
        let root = ProcessStableId {
            pid: root_pid as u32,
            start_time: identity::read_start_time(root_pid).unwrap(),
            exe: root_exe,
            exe_dev: metadata.dev(),
            exe_ino: metadata.ino(),
        };
        let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let verified = verified_descendant(child.id() as i32, unsafe { libc::getuid() }, &root);
        assert!(verified.is_some());
        // SAFETY: child is a direct child created by this test.
        unsafe {
            libc::kill(child.id() as i32, libc::SIGKILL);
        }
        let _ = child.wait();
    }
}
