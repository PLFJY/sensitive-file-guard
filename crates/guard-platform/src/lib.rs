//! Small semantic contracts shared by the product and platform adapters.
//!
//! This crate deliberately contains no operating-system mechanism vocabulary;
//! backend adapters may implement these contracts differently.

use std::path::{Path, PathBuf};

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

/// Owns one deferred OS authorization request.  Implementations must make
/// `allow`/`deny` terminal and release the underlying request exactly once.
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

/// Semantic process-tree containment for an already verified incident.
pub trait ProcessContainment: Send + Sync {
    fn terminate_verified_tree(
        &self,
        root: &ProcessStableId,
        uid: u32,
        members: &[u32],
    ) -> anyhow::Result<u32>;
}

/// Product-facing SSH behavior signal.  The implementation may use any
/// kernel/network facility; callers only see incident semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedNetworkAttempt {
    pub incident_id: String,
    pub pid: u32,
    pub uid: u32,
    pub destination: Option<guard_core::NetworkDestination>,
}

pub trait SshBehavior: Send + Sync {
    type Exposure: Clone + Send + Sync + 'static;
    fn arm_exposure(
        &self,
        incident_id: &str,
        process: &ProcessIdentity,
        until_ms: u64,
    ) -> anyhow::Result<Self::Exposure>;
    fn renew_exposure(&self, exposure: &Self::Exposure, until_ms: u64) -> anyhow::Result<()>;
    fn poll_blocked_attempts(&self) -> anyhow::Result<Vec<BlockedNetworkAttempt>>;
    fn allow_incident(&self, incident_id: &str) -> anyhow::Result<()>;
    fn block_incident(&self, incident_id: &str) -> anyhow::Result<()>;
    fn remove_exposure(&self, exposure: Self::Exposure) -> anyhow::Result<()>;
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
pub trait LocalTransport: Send + Sync {
    fn request(&self, payload: &[u8]) -> anyhow::Result<Vec<u8>>;
}

/// Stable metadata for platform diagnostics; mechanism-specific details may
/// be retained here without becoming a product dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendHealth {
    pub backend: String,
    pub active: bool,
    pub diagnostic: Option<String>,
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
