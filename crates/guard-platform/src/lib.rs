//! Small semantic contracts shared by the product and platform adapters.
//!
//! This crate deliberately contains no operating-system mechanism vocabulary;
//! backend adapters may implement these contracts differently.

use std::path::{Path, PathBuf};
use std::time::Duration;

use guard_core::identity::{ProcessIdentity, ProcessStableId};

pub mod config;

/// A resource operation observed by a platform access mediator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedOperation {
    Open,
    Read,
    Write,
    Copy,
}

/// Product-level request data passed from a platform mediator to policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedAccessRequest {
    pub process: ProcessIdentity,
    pub resource: guard_core::resource::ProtectedResource,
    pub operation: ProtectedOperation,
}

/// A platform mediator can answer immediately or retain the OS request while
/// a portable product workflow obtains a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessDisposition {
    Allow,
    Deny(String),
    Deferred,
}

/// Owns one deferred OS authorization request. Implementations must make
/// `allow`/`deny` terminal, release the underlying request exactly once, and
/// fail closed when an unresolved owner is dropped while the OS can respond.
pub trait PendingPermission: Send {
    fn allow(self: Box<Self>) -> anyhow::Result<()>;
    fn deny(self: Box<Self>) -> anyhow::Result<()>;
}

/// Process facts are resolved by the backend, never by portable orchestration.
pub trait ProcessIdentityResolver: Send + Sync {
    fn resolve(&self, pid: u32, resource_owner_uid: u32) -> anyhow::Result<ProcessIdentity>;
    fn is_live_instance(&self, identity: &ProcessStableId) -> anyhow::Result<bool>;
    fn ancestors(&self, pid: u32) -> anyhow::Result<Vec<guard_core::identity::AncestorSummary>>;
}

/// Product-level service operations.  Concrete service managers stay in the
/// platform adapter or privileged CLI boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceOperation {
    Start,
    Stop,
    Restart,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ServiceStatus {
    pub protection_active: bool,
    pub notification_active: Option<bool>,
    pub diagnostic: Option<String>,
}

pub trait ServiceController: Send + Sync {
    fn status(&self) -> anyhow::Result<ServiceStatus>;
    fn apply(&self, operation: ServiceOperation) -> anyhow::Result<()>;
}

/// Browser discovery is intentionally expressed as data, not filesystem
/// layout constants.  The Linux adapter supplies its native layouts.
pub trait BrowserDiscovery: Send + Sync {
    fn discover(&self, home: &Path) -> config::BrowserDiscovery;
}

/// Platform-local transport is separate from the wire protocol.  This trait
/// is useful to future clients that need a non-Unix local channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestTimeout {
    Bounded(Duration),
    /// The server/platform authorization deadline is authoritative. The local
    /// channel must stay open while trusted UI authentication is in progress.
    Authorization,
}

pub trait LocalTransport: Send + Sync {
    fn request(&self, payload: &[u8], timeout: RequestTimeout) -> anyhow::Result<Vec<u8>>;
}

/// Stable metadata for platform diagnostics; mechanism-specific details may
/// be retained here without becoming a product dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendHealth {
    pub backend: String,
    pub state: String,
    pub active: bool,
    pub degraded: bool,
    pub diagnostic: Option<String>,
    pub sequence_gaps: u64,
    pub global_sequence_gaps: u64,
    pub pending_created: u64,
    pub pending_resolved_allow: u64,
    pub pending_resolved_deny: u64,
    pub pending_timed_out: u64,
    pub insufficient_deadline: u64,
    pub late_responses: u64,
    pub namespace_allowed: u64,
    pub namespace_denied: u64,
    pub namespace_alias_entries: usize,
    pub namespace_alias_capacity: usize,
    pub namespace_index_saturated: bool,
    pub process_graph_degraded: bool,
    pub authorization_events_delivered: u64,
    pub protected_authorization_events: u64,
    pub unresolved_external_hardlinks: usize,
    pub target_path_inversion_active: bool,
    pub process_lifecycle_events: u64,
}

/// Portable artifact attribution input.  Quarantine mechanics remain an
/// adapter concern; ordinary hashing and metadata stay in existing crates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributedArtifact {
    pub path: PathBuf,
    pub owner_uid: u32,
    pub dev: u64,
    pub ino: u64,
}
