//! Lease domain types.
//!
//! Two lease kinds:
//! - `MigrationLease`: short, read-only, identity-scoped, time-limited grant
//!   allowing one browser to read another browser's protected profile.
//! - `SshLoadLease`: one-shot grant allowing the exact `ssh-add` invocation to
//!   read a single protected SSH private key.
//!
//! Leases bind to a `StableIdentity` (exe + start time + file identity), never
//! to a PID alone. Expired/revoked/used leases do not grant access.

use serde::{Deserialize, Serialize};

use crate::identity::{ExeIdentity, StableIdentity};
use crate::resource::{BrowserId, ProfileId, ProtectedResourceId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LeaseId(pub u64);

/// Read-only, time-limited, identity-scoped cross-browser migration grant.
///
/// `target` is an **armed** `ExeIdentity` (exe file identity, no start time):
/// the lease is created before the target browser reads the source profile and
/// matches the next process — or any process in its tree — whose executable
/// file identity equals it. This avoids permanent allow-listing while
/// tolerating the target being launched after authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationLease {
    pub id: LeaseId,
    pub source_browser: BrowserId,
    pub source_profile: ProfileId,
    pub target_browser: BrowserId,
    /// OS user that authorized/requested the migration.
    pub uid: u32,
    /// Armed executable-file identity of the target browser that may exercise
    /// the lease (matched against the opener and its ancestor tree).
    pub target: ExeIdentity,
    /// Monotonic/epoch deadline (same clock as the `now` passed to `evaluate`).
    pub expires_at: u64,
    pub revoked: bool,
    pub read_only: bool,
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
    pub migration: Vec<MigrationLease>,
    pub ssh: Vec<SshLoadLease>,
}
