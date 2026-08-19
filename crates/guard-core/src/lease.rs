//! Lease domain types.
//!
//! Two lease kinds:
//! - `MigrationAccessLease`: short, identity-scoped, time-limited grant
//!   allowing one browser to read another browser's protected profile.
//! - `SshLoadLease`: one-shot grant allowing the exact `ssh-add` invocation to
//!   read a single protected SSH private key.
//! - `SshReadAccessLease`: short, process-tree-bound grant created only after
//!   the user confirms an ordinary SSH private-key read.
//!
//! Leases bind to a `StableIdentity` (exe + start time + file identity), never
//! to a PID alone. Expired/revoked/used leases do not grant access.

use serde::{Deserialize, Serialize};

use crate::identity::{ExeIdentity, ProcessStableId, StableIdentity};
use crate::resource::{BrowserId, ProfileId, ProtectedResourceId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LeaseId(pub u64);

/// Lifecycle of a cross-browser migration capability.
///
/// An armed lease does not grant access by itself. The Linux enforcement layer
/// atomically binds it on first use to the exact target process instance. Once
/// bound, only that process or descendants whose ancestry contains the same
/// PID + start time + executable identity can use it. `Dead` is terminal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationLeaseState {
    Armed { target: ExeIdentity },
    Bound { root: ProcessStableId },
    Dead,
}

/// Time-limited, process-tree-bound cross-browser migration access grant.
///
/// The portable lease itself is intentionally not called "read-only": some
/// access mediators (notably Linux fanotify) do not expose the opener's flag
/// mask. The macOS adapter separately narrows every migration AUTH_OPEN
/// response to Darwin FREAD and reports that platform guarantee in status.
///
/// LFH5: authority is EXACT READER INSTANCE by default. A `Bound` lease
/// authorizes only the exact bound process instance (`root`), never "any
/// descendant in the tree". A helper that must read may be explicitly bound
/// post-observation; pre-existing descendants never auto-upgrade. `generation`
/// ties the lease to the protection-continuity generation: after a loss the
/// generation is bumped and every lease created before it is dead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationAccessLease {
    pub id: LeaseId,
    pub source_browser: BrowserId,
    pub source_profile: ProfileId,
    pub target_browser: BrowserId,
    /// OS user that authorized/requested the migration.
    pub uid: u32,
    pub state: MigrationLeaseState,
    /// Monotonic/epoch deadline (same clock as the `now` passed to `evaluate`).
    pub expires_at: u64,
    pub revoked: bool,
    /// LFH5: protection-continuity generation this lease was created under.
    pub generation: u64,
}

/// One-shot grant to load a single SSH private key into `ssh-agent`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshLoadLease {
    pub id: LeaseId,
    pub resource: ProtectedResourceId,
    pub uid: u32,
    /// Stable identity of the exact `ssh-add` invocation.
    pub target: StableIdentity,
    /// PID of the exact `ssh-add` invocation. Used to consume the one-shot
    /// lease when the load completes: the lease stays valid for the whole
    /// load (a real ssh-add performs multiple `FAN_ACCESS_PERM` events: open +
    /// reads), and is marked used when the process exits or its identity
    /// changes. Never trusted alone — `target` remains the authority.
    pub pid: u32,
    pub expires_at: u64,
    pub revoked: bool,
    /// Set after the one-shot load completes (the exact process exited or
    /// identity changed); further use is denied.
    pub used: bool,
    /// LFH5: protection-continuity generation this lease was created under.
    pub generation: u64,
}

/// Time-limited ordinary SSH private-key read grant. Unlike `SshLoadLease`,
/// this covers the verified reader process (exact instance only) for one
/// protected key. It is never persisted or executable-wide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshReadAccessLease {
    pub id: LeaseId,
    pub resource: ProtectedResourceId,
    pub uid: u32,
    pub root: ProcessStableId,
    pub expires_at: u64,
    pub revoked: bool,
    /// LFH5: protection-continuity generation this lease was created under.
    pub generation: u64,
}

/// The set of active leases consulted by the policy engine.
#[derive(Debug, Clone, Default)]
pub struct LeaseSet {
    pub migration: Vec<MigrationAccessLease>,
    pub ssh: Vec<SshLoadLease>,
    pub ssh_read: Vec<SshReadAccessLease>,
}
