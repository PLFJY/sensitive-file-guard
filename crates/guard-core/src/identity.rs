//! Process identity domain types.
//!
//! Identity is never just a PID. `ProcessStableId` pairs the PID with a start
//! time and executable file identity so that PID reuse cannot grant access.
//! Leases bind to a `StableIdentity` (everything except the PID), so the same
//! PID with a different start time / exe does not match.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::resource::BrowserId;

/// Trust tier resolved by the platform identity resolver (Phase 04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustTier {
    /// System package / root-owned executable the current user cannot modify.
    SystemPackage,
    /// Sandbox or package identity (when supported).
    Sandbox,
    /// User-writable executable that was explicitly hash-enrolled.
    EnrolledUserWritable,
    /// Untrusted / unresolvable.
    Unknown,
}

impl TrustTier {
    pub fn is_trusted(&self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

/// PID + stable identity fields. The PID alone is NOT a stable identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessStableId {
    pub pid: u32,
    /// Backend-defined process start token.
    pub start_time: u64,
    /// Canonical executable path supplied by the backend.
    pub exe: PathBuf,
    /// Executable file `st_dev`.
    pub exe_dev: u64,
    /// Executable file `st_ino`.
    pub exe_ino: u64,
}

/// The identity fields a lease binds to (everything except the live PID).
///
/// Two `ProcessStableId`s with the same PID but different `StableIdentity`
/// (e.g. different start time) indicate PID reuse and must not match a lease.
///
/// Used by one-shot leases (`SshLoadLease`) that bind to a specific process
/// invocation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StableIdentity {
    pub exe: PathBuf,
    pub start_time: u64,
    pub dev: u64,
    pub ino: u64,
}

/// Executable file identity (canonical path + `st_dev` + `st_ino`), excluding
/// the per-instance start time. This is the "armed" binding used by
/// `MigrationAccessLease`: a lease is created armed for the target browser's
/// executable file identity and matches the next process (or any process in its
/// tree) whose exe identity equals it. A different executable at the same path
/// (different inode) does not match; a renamed binary at a different path does
/// not match.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExeIdentity {
    pub exe: PathBuf,
    pub dev: u64,
    pub ino: u64,
}

/// Bounded ancestor summary for audit/policy context. The policy engine uses
/// ancestry for migration-lease process-tree scoping: a lease bound to the
/// target browser's `ExeIdentity` matches a helper/child process that has the
/// bound target as an ancestor. `exe_dev`/`exe_ino` are captured so the match
/// is file-identity-anchored, not path-name-anchored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AncestorSummary {
    pub pid: u32,
    pub start_time: u64,
    pub exe: PathBuf,
    pub exe_dev: u64,
    pub exe_ino: u64,
}

impl AncestorSummary {
    /// Project this ancestor's executable file identity for migration-lease
    /// tree-scoping.
    pub fn exe_identity(&self) -> ExeIdentity {
        ExeIdentity {
            exe: self.exe.clone(),
            dev: self.exe_dev,
            ino: self.exe_ino,
        }
    }
}

impl ProcessStableId {
    /// Project this live process's stable identity (PID excluded) for one-shot
    /// lease matching (binds to the exact invocation including start time).
    pub fn stable_identity(&self) -> StableIdentity {
        StableIdentity {
            exe: self.exe.clone(),
            start_time: self.start_time,
            dev: self.exe_dev,
            ino: self.exe_ino,
        }
    }

    /// Project this live process's executable file identity (PID + start time
    /// excluded) for armed migration-lease matching.
    pub fn exe_identity(&self) -> ExeIdentity {
        ExeIdentity {
            exe: self.exe.clone(),
            dev: self.exe_dev,
            ino: self.exe_ino,
        }
    }
}

/// Full process identity supplied to the policy engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub stable: ProcessStableId,
    pub uid: u32,
    pub gid: u32,
    /// Owner UID of the executable file (the binary on disk, not the running
    /// user). Captured by the resolver during `stat_exe` and recorded in audit
    /// so a reviewer can see whether the exe was root-owned or user-writable.
    pub exe_owner_uid: u32,
    /// The browser this process is, if it is a known browser. `None` for
    /// ordinary apps/scripts/agents.
    pub browser: Option<BrowserId>,
    pub trust_tier: TrustTier,
    /// Command line, for audit only. Never used for the allow/deny decision.
    pub cmdline: Vec<String>,
    /// Bounded parent/ancestor chain (closest first), for audit context.
    pub ancestors: Vec<AncestorSummary>,
}

impl ProcessIdentity {
    /// True if this is a trusted (verified) browser process.
    pub fn is_trusted_browser(&self) -> bool {
        self.trust_tier.is_trusted() && self.browser.is_some()
    }
}
