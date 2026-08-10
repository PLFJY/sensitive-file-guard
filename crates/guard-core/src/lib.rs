//! Core domain types and shared utilities for Sensitive Data Firewall.
//!
//! This crate holds the platform-independent domain model: protected
//! resources, process identity, leases, and the deterministic policy engine.
//! Policy inputs are pure data and the policy output is unit-testable without
//! root or any OS interception layer.

pub mod identity;
pub mod incident;
pub mod lease;
pub mod logging;
pub mod policy;
pub mod resource;

pub use identity::{AncestorSummary, ProcessIdentity, ProcessStableId, StableIdentity, TrustTier};
pub use incident::{
    ExposureSummary, ExposureTracker, IncidentResolution, NetworkDecision, NetworkDestination,
    QuarantineCandidate, QuarantineCandidateKind, SshExposureIncident, SshIncidentState,
    DEFAULT_SSH_BEHAVIOR_WINDOW_SECS, MAX_SSH_BEHAVIOR_WINDOW_SECS, MIN_SSH_BEHAVIOR_WINDOW_SECS,
};
pub use lease::{LeaseId, LeaseSet, MigrationAccessLease, MigrationLeaseState, SshLoadLease};
pub use logging::init_logging;
pub use policy::{evaluate, AccessEvent, AccessOperation, Decision, DenyReason};
pub use resource::{
    BrowserFamily, BrowserId, ProfileId, ProtectedResource, ProtectedResourceId,
    ProtectedResourceKind,
};
