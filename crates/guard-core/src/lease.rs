//! Lease domain types.
//!
//! Two lease kinds:
//! - `MigrationAccessLease`: short, identity-scoped, time-limited grant
//!   allowing one browser to read another browser's protected profile.
//! - `SshLoadLease`: one-shot grant allowing the exact `ssh-add` invocation to
//!   read a single protected SSH private key.
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
/// This is intentionally not called "read-only": Linux fanotify permission
/// events do not expose the triggering process's original open flags, so V1
/// cannot enforce a read-only invariant at this boundary.
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
}

/// One-shot grant to load a single SSH private key into `ssh-agent`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshLoadLease {
    pub id: LeaseId,
    pub resource: ProtectedResourceId,
    pub uid: u32,
    /// Stable identity of the exact `ssh-add` invocation.
    pub target: StableIdentity,
    pub expires_at: u64,
    pub revoked: bool,
    /// Set after the one-shot load completes; further use is denied.
    pub used: bool,
}

/// The set of active leases consulted by the policy engine.
#[derive(Debug, Clone, Default)]
pub struct LeaseSet {
    pub migration: Vec<MigrationAccessLease>,
    pub ssh: Vec<SshLoadLease>,
}
