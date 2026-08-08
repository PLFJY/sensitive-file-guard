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
