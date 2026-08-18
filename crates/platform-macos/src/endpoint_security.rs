use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock, Weak};
use std::time::Duration;

use guard_core::resource::{
    BrowserId, ProfileId, ProtectedResource, ProtectedResourceId, ProtectedResourceKind,
};
use guard_platform::BackendHealth;

use crate::browser_session::{RejectionKind, SessionMembership};
use crate::browser_trust::{BrowserExecutableRole, MacBrowserTrustStore};
use crate::identity::{
    AuditProcessKey, ExecutableSnapshot, MacCodeIdentity, MacProcessFacts, MacProcessGraph,
};
use crate::pending::{
    DeadlineScheduler, DeadlineSchedulerHandle, HealthTracker, PendingInner, ResponseCode,
    ResponseSink,
};
pub use crate::pending::{
    MacPendingPermission, ReadOnlyMacPendingPermission, ES_FFLAG_READ, ES_FFLAG_WRITE,
};
use crate::process_shield::{
    ExecLaunchFacts, MacProcessShield, ShieldReasonKind, StrongSignalOutcome, TaskAccessKind,
    TaskNotifyKind,
};
use crate::resource_index::FileIdentity;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthOpenFacts {
    /// Kernel FFLAGS requested by AUTH_OPEN. These are deliberately not POSIX
    /// `open(2)` O_* flags.
    pub requested_fflags: u32,
    pub process: MacProcessFacts,
    pub target: PathBuf,
    pub target_dev: u64,
    pub target_ino: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthOpenTargetFacts {
    requested_fflags: u32,
    target: PathBuf,
    target_dev: u64,
    target_ino: u64,
}

impl AuthOpenTargetFacts {
    fn with_process(self, process: MacProcessFacts) -> AuthOpenFacts {
        AuthOpenFacts {
            requested_fflags: self.requested_fflags,
            process,
            target: self.target,
            target_dev: self.target_dev,
            target_ino: self.target_ino,
        }
    }
}

pub struct MacAuthorizationEvent {
    pub facts: AuthOpenFacts,
    pub resource: ProtectedResource,
    /// Human-interaction lifetime after applying the ES safety margin and
    /// product prompt cap. `None` means the event must not be prompted.
    pub interactive_budget: Option<Duration>,
    pub permission: MacPendingPermission,
}

#[derive(Debug)]
pub struct MacProtectedResources {
    enabled: AtomicBool,
    index: RwLock<crate::resource_index::MacResourceIndex>,
    refresh_needed: AtomicBool,
}

impl MacProtectedResources {
    pub fn new(enabled: bool, index: crate::resource_index::MacResourceIndex) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            index: RwLock::new(index),
            refresh_needed: AtomicBool::new(false),
        }
    }

    pub fn replace(
        &self,
        enabled: bool,
        index: crate::resource_index::MacResourceIndex,
    ) -> anyhow::Result<()> {
        *self
            .index
            .write()
            .map_err(|_| anyhow::anyhow!("macOS resource index lock is poisoned"))? = index;
        self.enabled.store(enabled, Ordering::Release);
        Ok(())
    }

    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    pub fn counts(&self) -> (usize, usize) {
        let index = self
            .index
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (index.concrete_count(), index.tree_root_count())
    }

    pub fn ssh_key_count(&self) -> usize {
        self.index
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .ssh_key_count()
    }

    fn has_protected_scope(&self) -> bool {
        self.enabled()
            && !self
                .index
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_empty()
    }

    pub fn is_configured_ssh_resource(&self, resource: &ProtectedResource) -> bool {
        self.index
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_configured_ssh_resource(resource)
    }

    pub fn metadata_snapshot(&self) -> (Vec<ProtectedResource>, Vec<guard_browser::TreeRoot>) {
        let index = self
            .index
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (
            index.resources().cloned().collect(),
            index.trees().cloned().collect(),
        )
    }

    fn classify(&self, facts: &AuthOpenTargetFacts) -> Option<ProtectedResource> {
        if !self.enabled() {
            return None;
        }
        let identity = FileIdentity {
            dev: facts.target_dev,
            ino: facts.target_ino,
        };
        let resource = self
            .index
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .classify(&facts.target, identity)?;
        let mut index = self
            .index
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if identity.dev != 0 && identity.ino != 0 {
            let _ = index.observe_alias(identity, resource.clone());
        }
        Some(resource)
    }

    pub fn namespace_health(&self) -> (usize, usize, bool) {
        let index = self
            .index
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (
            index.alias_count(),
            index.alias_capacity(),
            index.alias_saturated(),
        )
    }

    fn namespace_view(
        &self,
        path: &std::path::Path,
        identity: Option<FileIdentity>,
    ) -> (
        Option<ProtectedResource>,
        Option<crate::resource_index::NamespaceScope>,
        bool,
    ) {
        let index = self
            .index
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let resource = identity
            .and_then(|identity| index.concrete(identity).cloned())
            .or_else(|| index.classify_path(path));
        let scope = index.namespace_scope(path);
        let contains = index.contains_protected_path(path);
        (resource, scope, contains)
    }

    fn request_refresh(&self) {
        self.refresh_needed.store(true, Ordering::Release);
    }

    pub fn repair_if_needed(&self) -> anyhow::Result<bool> {
        if !self.refresh_needed.swap(false, Ordering::AcqRel) {
            return Ok(false);
        }
        // Clone and scan outside the writer lock. ES callbacks may keep using
        // the previous immutable snapshot until the brief atomic replacement.
        let mut refreshed = self
            .index
            .read()
            .map_err(|_| anyhow::anyhow!("macOS resource index lock is poisoned"))?
            .clone();
        refreshed.refresh_aliases()?;
        *self
            .index
            .write()
            .map_err(|_| anyhow::anyhow!("macOS resource index lock is poisoned"))? = refreshed;
        Ok(true)
    }
}

/// Metadata-only audit handoff for Process Shield events that happen inside
/// the Endpoint Security callback (AUTH_EXEC admission). Never carries secret
/// contents: only process/exe metadata, decision facts and diagnostics.
#[derive(Debug, Clone)]
pub enum ShieldAuditEvent {
    /// A shield-eligible exec was admitted; `role` (enrolled Main / Helper /
    /// None for role-less enrollments) and `membership` (MCH3 BrowserSession
    /// classification) are metadata only. P2 audit truthfulness: the audit
    /// consumer distinguishes "authority admitted" (Main that enters the
    /// shield at exec time) from "session admitted" (helpers and role-less
    /// enrollments that are session-topology bookkeeping only and get NO task
    /// protection).
    ExecAdmitted {
        target: MacProcessFacts,
        reason: ShieldReasonKind,
        role: Option<BrowserExecutableRole>,
        membership: SessionMembership,
    },
    /// A shield-eligible exec was denied because it carried prohibited
    /// code-loading / search-path DYLD launch state.
    ExecDeniedLaunchInjection {
        target: MacProcessFacts,
        present_vars: Vec<&'static str>,
    },
    /// A shield-eligible exec was denied because critical target identity
    /// facts were missing/truncated (fail closed for that exec). The
    /// requester's UID is retained so the audit row is attributable even
    /// though the target itself could not be normalized.
    ExecDeniedMalformed {
        requester_uid: u32,
        diagnostic: String,
    },
    /// A task capability request against a shielded target was denied
    /// (prevention). The denied attempt does NOT compromise the target.
    TaskDenied {
        kind: TaskAccessKind,
        requester: MacProcessFacts,
        target: MacProcessFacts,
    },
    /// A notify-only task/trace/thread/CS signal involving a shielded target.
    /// Notify signals never PREVENT (only AUTH gates do); STRONG resolutions
    /// feed MPS4's compromise transition (DETECTED + CONTAINED), while
    /// GET_TASK_READ / TRACE / CS_INVALIDATED are DETECTED telemetry only on
    /// this build (no Compromised transition, no containment).
    TaskNotify {
        kind: TaskNotifyKind,
        requester: MacProcessFacts,
        target: MacProcessFacts,
    },
    /// A strong notify-only signal transitioned the exact shielded target to
    /// Compromised (idempotent; emitted only for the new transition). Callers
    /// (guard-es) run capability-revocation hooks, audit, notify and optional
    /// containment AFTER this event, in that order.
    Compromised {
        target: MacProcessFacts,
        signal: TaskNotifyKind,
        requester: MacProcessFacts,
    },
}

#[derive(Debug, Clone)]
pub struct EndpointSecurityConfig {
    scope: ProtectionScope,
}

#[derive(Debug, Clone)]
enum ProtectionScope {
    Synthetic {
        protected_exact_paths: HashSet<PathBuf>,
        /// Executables whose AUTH_EXEC targets are admitted as shielded in
        /// synthetic test mode (never real browsers).
        shield_executables: HashSet<PathBuf>,
    },
    Browser {
        resources: Arc<MacProtectedResources>,
        trust: Arc<RwLock<MacBrowserTrustStore>>,
        /// Exact Guard component executable paths (guard-es itself, the
        /// Sensitive File Guard.app GUI binary, guard-notify) admitted as
        /// shielded on AUTH_EXEC. guardctl is deliberately excluded so
        /// CLI/debug workflows are not harmed by always-on shielding.
        guard_component_paths: Vec<PathBuf>,
    },
}

impl EndpointSecurityConfig {
    pub fn synthetic_exact_paths(paths: impl IntoIterator<Item = PathBuf>) -> anyhow::Result<Self> {
        Self::synthetic_with_shield(paths, std::iter::empty())
    }

    /// Synthetic test scope with an explicit set of shield-eligible
    /// executables whose AUTH_EXEC targets are admitted into Process Shield.
    /// Never points at real browser executables.
    pub fn synthetic_with_shield(
        paths: impl IntoIterator<Item = PathBuf>,
        shield_executables: impl IntoIterator<Item = PathBuf>,
    ) -> anyhow::Result<Self> {
        let mut protected_exact_paths = HashSet::new();
        for path in paths {
            anyhow::ensure!(path.is_absolute(), "protected test path must be absolute");
            protected_exact_paths.insert(std::fs::canonicalize(&path).map_err(|error| {
                anyhow::anyhow!(
                    "cannot canonicalize protected synthetic fixture {}: {error}",
                    path.display()
                )
            })?);
        }
        anyhow::ensure!(
            !protected_exact_paths.is_empty(),
            "at least one synthetic protected path is required"
        );
        let mut shield = HashSet::new();
        for path in shield_executables {
            anyhow::ensure!(
                path.is_absolute(),
                "shield test executable must be absolute"
            );
            shield.insert(std::fs::canonicalize(&path).map_err(|error| {
                anyhow::anyhow!(
                    "cannot canonicalize shield test executable {}: {error}",
                    path.display()
                )
            })?);
        }
        Ok(Self {
            scope: ProtectionScope::Synthetic {
                protected_exact_paths,
                shield_executables: shield,
            },
        })
    }

    pub fn browser(
        resources: Arc<MacProtectedResources>,
        trust: Arc<RwLock<MacBrowserTrustStore>>,
    ) -> Self {
        Self {
            scope: ProtectionScope::Browser {
                resources,
                trust,
                guard_component_paths: Vec::new(),
            },
        }
    }

    /// Browser scope plus Guard's own security-critical component executable
    /// paths (guard-es, Guard GUI, guard-notify). guardctl is intentionally
    /// absent so CLI/debug workflows are not harmed.
    pub fn browser_with_guard_components(
        resources: Arc<MacProtectedResources>,
        trust: Arc<RwLock<MacBrowserTrustStore>>,
        guard_component_paths: impl IntoIterator<Item = PathBuf>,
    ) -> Self {
        let guard_component_paths = guard_component_paths.into_iter().collect();
        Self {
            scope: ProtectionScope::Browser {
                resources,
                trust,
                guard_component_paths,
            },
        }
    }

    fn has_protected_scope(&self) -> bool {
        match &self.scope {
            ProtectionScope::Synthetic {
                protected_exact_paths,
                ..
            } => !protected_exact_paths.is_empty(),
            ProtectionScope::Browser { resources, .. } => resources.has_protected_scope(),
        }
    }

    /// Does an AUTH_EXEC target executable look shield-eligible? Uses only
    /// cheap path facts (possibly truncated), never process-name authority.
    fn shield_eligible_raw(&self, raw: &RawProcessFacts) -> bool {
        let Some(path) = raw.candidate_executable_path() else {
            return false;
        };
        match &self.scope {
            ProtectionScope::Synthetic {
                shield_executables, ..
            } => shield_executables
                .iter()
                .any(|enrolled| path.starts_with(enrolled)),
            ProtectionScope::Browser {
                trust,
                guard_component_paths,
                ..
            } => {
                let enrolled = trust
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .enrolled_executable_paths();
                enrolled.iter().any(|enrolled| path.starts_with(enrolled))
                    || guard_component_paths
                        .iter()
                        .any(|component| path.starts_with(component))
            }
        }
    }

    /// Resolve the shield reason for a fully normalized AUTH_EXEC target, or
    /// None when the exec is unrelated and must stay fast/allowed.
    pub fn shield_eligible(
        &self,
        target: &MacProcessFacts,
        synthetic_owner_uid: u32,
    ) -> Option<ShieldReasonKind> {
        match &self.scope {
            ProtectionScope::Synthetic {
                shield_executables, ..
            } => {
                // P0 review round 4: a synthetic shield target is NOT a
                // browser. Returning Browser here would route it through
                // admit_browser(role=None), which creates NO shield entry and
                // NO task protection, silently hollowing out the synthetic
                // adversarial harness. Use a dedicated SyntheticTarget reason
                // so the exec path admits it into the shield (task-protected
                // regardless of the Browser/role model).
                if shield_executables.contains(&target.executable.path) {
                    return Some(ShieldReasonKind::SyntheticTarget);
                }
                None
            }
            ProtectionScope::Browser {
                trust,
                guard_component_paths,
                ..
            } => {
                // Guard components first: exact executable path match.
                if guard_component_paths
                    .iter()
                    .any(|component| component == &target.executable.path)
                {
                    return Some(ShieldReasonKind::GuardComponent);
                }
                let trusted = trust
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .classify(target, synthetic_owner_uid);
                if trusted.browser.is_some() && trusted.tier.is_trusted() {
                    return Some(ShieldReasonKind::Browser);
                }
                None
            }
        }
    }

    /// P1 review: whether two exact instances belong to the SAME enrolled
    /// browser (same BrowserId + same owner UID). Used to narrow the
    /// warm-start notify fallback: BrowserIdentity must never become a
    /// relationship authority across enrollments (a warm-start Firefox
    /// requester must not get fallback relationship with a Chrome
    /// SecretAuthority target).
    pub fn same_browser_enrollment(&self, a: &MacProcessFacts, b: &MacProcessFacts) -> bool {
        match &self.scope {
            ProtectionScope::Browser { trust, .. } => {
                let trust = trust
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let ta = trust.classify(a, a.uid);
                let tb = trust.classify(b, b.uid);
                a.uid == b.uid && ta.browser.is_some() && ta.browser == tb.browser
            }
            _ => false,
        }
    }

    /// MCH3: the enrolled role (Main / Helper) of an exact process, from the
    /// trust store. BrowserIdentity context only: never task authority.
    pub fn browser_role_of(
        &self,
        target: &MacProcessFacts,
        owner_uid: u32,
    ) -> Option<crate::browser_trust::BrowserExecutableRole> {
        match &self.scope {
            ProtectionScope::Synthetic { .. } => None,
            ProtectionScope::Browser { trust, .. } => {
                trust
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .classify(target, owner_uid)
                    .role
            }
        }
    }

    /// MCH3: is this exact process an enrolled browser executable (BrowserIdentity)?
    pub fn is_enrolled_browser_executable(&self, facts: &MacProcessFacts, owner_uid: u32) -> bool {
        matches!(
            self.shield_eligible(facts, owner_uid),
            Some(ShieldReasonKind::Browser)
        )
    }

    fn classify(
        &self,
        facts: &AuthOpenTargetFacts,
        synthetic_owner_uid: u32,
    ) -> Option<ProtectedResource> {
        match &self.scope {
            ProtectionScope::Synthetic {
                protected_exact_paths,
                ..
            } if protected_exact_paths.contains(&facts.target) => Some(ProtectedResource {
                id: ProtectedResourceId(facts.target.to_string_lossy().into_owned()),
                kind: ProtectedResourceKind::CookieStore,
                owner_uid: synthetic_owner_uid,
                browser: Some(BrowserId("synthetic".into())),
                profile: Some(ProfileId("fixture".into())),
                path: facts.target.clone(),
            }),
            ProtectionScope::Synthetic { .. } => None,
            ProtectionScope::Browser { resources, .. } => resources.classify(facts),
        }
    }

    fn authorize_namespace(&self, facts: &NamespaceFacts) -> bool {
        match &self.scope {
            ProtectionScope::Synthetic {
                protected_exact_paths,
                ..
            } => {
                !protected_exact_paths.contains(&facts.source)
                    && !protected_exact_paths.contains(&facts.destination)
            }
            ProtectionScope::Browser {
                resources, trust, ..
            } => {
                if !resources.enabled() {
                    return true;
                }
                let (source, source_scope, source_contains) =
                    resources.namespace_view(&facts.source, Some(facts.source_identity));
                let (destination, destination_scope, _) =
                    resources.namespace_view(&facts.destination, facts.destination_identity);
                if source.is_none() && destination.is_none() && !source_contains {
                    return true;
                }
                // Directory moves that contain protected descendants are never
                // a browser's atomic file replacement and can move a complete
                // protected namespace out of policy scope.
                if source.is_none() && source_contains {
                    return false;
                }
                let protected = source.as_ref().or(destination.as_ref());
                let Some(protected) = protected else {
                    return false;
                };
                if protected.kind == ProtectedResourceKind::SshPrivateKey {
                    return false;
                }
                let (Some(browser), Some(profile)) =
                    (protected.browser.as_ref(), protected.profile.as_ref())
                else {
                    return false;
                };
                let trusted = trust
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .classify(&facts.process, protected.owner_uid);
                if trusted.browser.as_ref() != Some(browser) {
                    return false;
                }
                let same_scope = |scope: &crate::resource_index::NamespaceScope| {
                    &scope.browser == browser
                        && scope.profile.as_ref() == Some(profile)
                        && scope.owner_uid == protected.owner_uid
                };
                let same_resource_scope = |resource: &ProtectedResource| {
                    resource.kind != ProtectedResourceKind::SshPrivateKey
                        && resource.browser.as_ref() == Some(browser)
                        && resource.profile.as_ref() == Some(profile)
                        && resource.owner_uid == protected.owner_uid
                };
                let source_ok = source.as_ref().map_or_else(
                    || source_scope.as_ref().is_some_and(same_scope),
                    same_resource_scope,
                );
                let destination_ok = destination.as_ref().map_or_else(
                    || destination_scope.as_ref().is_some_and(same_scope),
                    same_resource_scope,
                );
                source_ok && destination_ok
            }
        }
    }

    /// Cheap scope gate for namespace events. Process identity, deadlines and
    /// policy can only deny after the kernel target is known to touch the
    /// protected namespace. This is the availability boundary that prevents a
    /// damaged process graph from blocking unrelated filesystem activity.
    fn namespace_requires_authorization(&self, facts: &NamespaceTargetFacts) -> bool {
        match &self.scope {
            ProtectionScope::Synthetic {
                protected_exact_paths,
                ..
            } => {
                protected_exact_paths.contains(&facts.source)
                    || protected_exact_paths.contains(&facts.destination)
            }
            ProtectionScope::Browser { resources, .. } => {
                if !resources.enabled() {
                    return false;
                }
                let (source, _, source_contains) =
                    resources.namespace_view(&facts.source, Some(facts.source_identity));
                let (destination, _, _) =
                    resources.namespace_view(&facts.destination, facts.destination_identity);
                source.is_some() || destination.is_some() || source_contains
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceOperation {
    Link,
    Rename,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceFacts {
    pub operation: NamespaceOperation,
    pub process: MacProcessFacts,
    pub source: PathBuf,
    pub source_identity: FileIdentity,
    pub destination: PathBuf,
    pub destination_identity: Option<FileIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NamespaceTargetFacts {
    operation: NamespaceOperation,
    source: PathBuf,
    source_identity: FileIdentity,
    destination: PathBuf,
    destination_identity: Option<FileIdentity>,
}

impl NamespaceTargetFacts {
    fn with_process(self, process: MacProcessFacts) -> NamespaceFacts {
        NamespaceFacts {
            operation: self.operation,
            process,
            source: self.source,
            source_identity: self.source_identity,
            destination: self.destination,
            destination_identity: self.destination_identity,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientCreateError {
    InvalidArgument,
    Internal,
    NotEntitled,
    NotPermitted,
    NotPrivileged,
    TooManyClients,
    Unknown(i32),
    UnsupportedPlatform,
}

impl std::fmt::Display for ClientCreateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidArgument => "Endpoint Security rejected an invalid client argument",
            Self::Internal => "Endpoint Security client creation failed internally",
            Self::NotEntitled => {
                "Endpoint Security client entitlement is missing or not authorized by provisioning"
            }
            Self::NotPermitted => "Endpoint Security client lacks TCC Full Disk Access permission",
            Self::NotPrivileged => {
                "Endpoint Security client is not running with required privilege"
            }
            Self::TooManyClients => "Endpoint Security client limit has been reached",
            Self::UnsupportedPlatform => "Endpoint Security is available only on macOS",
            Self::Unknown(_) => "Endpoint Security returned an unknown client creation result",
        };
        if let Self::Unknown(value) = self {
            write!(formatter, "{message}: {value}")
        } else {
            formatter.write_str(message)
        }
    }
}

impl std::error::Error for ClientCreateError {}

#[cfg(target_os = "macos")]
pub struct EndpointSecurityBackend {
    // The scheduler is shut down while the ES client is still live so every
    // retained message receives a terminal deny before client deletion.
    scheduler: DeadlineScheduler,
    client: Option<NativeClient>,
    context: Box<CallbackContext>,
    receiver: mpsc::Receiver<MacAuthorizationEvent>,
    shield_receiver: mpsc::Receiver<ShieldAuditEvent>,
    task_read_supported: bool,
    task_notify_supported: bool,
}

#[cfg(target_os = "macos")]
const MAX_PENDING_AUTHORIZATIONS: usize = 1024;

#[cfg(target_os = "macos")]
impl EndpointSecurityBackend {
    pub fn start(config: EndpointSecurityConfig) -> Result<Self, ClientCreateError> {
        let health = Arc::new(HealthTracker::active(
            "Endpoint Security client initialization is pending",
        ));
        let (scheduler, scheduler_handle) = DeadlineScheduler::start().map_err(|_| {
            health.degrade("could not start Endpoint Security deadline scheduler");
            ClientCreateError::Internal
        })?;
        let (sender, receiver) = mpsc::sync_channel(MAX_PENDING_AUTHORIZATIONS);
        let (shield_sender, shield_receiver) = mpsc::sync_channel(MAX_PENDING_AUTHORIZATIONS);
        let registry = Arc::new(Mutex::new(Vec::new()));
        let process_graph = Arc::new(Mutex::new(MacProcessGraph::default()));
        let shield = Arc::new(Mutex::new(MacProcessShield::new()));
        let mut context = Box::new(CallbackContext {
            config,
            // MCH0: Process Shield starts enabled; guard-es applies the loaded
            // policy (set_process_shield_enabled) right after start.
            process_shield_enabled: Arc::new(AtomicBool::new(true)),
            sender,
            scheduler: scheduler_handle,
            registry,
            process_graph,
            shield,
            shield_sender,
            health,
            sequences: Mutex::new(SequenceTracker::default()),
        });
        let client = NativeClient::create(context.as_mut() as *mut CallbackContext)?;
        if client.subscribe_required().is_err() {
            context
                .health
                .degrade("Endpoint Security required subscription failed");
            return Err(ClientCreateError::Internal);
        }
        let task_read_supported = client.subscribe_task_read();
        if !task_read_supported {
            context.health.degrade(
                "AUTH_GET_TASK_READ is unavailable on this host; task-read prevention is not enforced (Reduced)",
            );
        }
        let task_notify_supported = client.subscribe_task_notify();
        if !task_notify_supported {
            context.health.degrade(
                "Process Shield notify subscriptions are unavailable; compromise detection is degraded (Reduced)",
            );
        }
        context.health.note(format!(
            "Endpoint Security AUTH_OPEN/AUTH_EXEC/AUTH_GET_TASK{} and bounded process graph subscriptions are active; task-notify={task_notify_supported}",
            if task_read_supported { "/AUTH_GET_TASK_READ" } else { "" }
        ));
        Ok(Self {
            scheduler,
            client: Some(client),
            context,
            receiver,
            shield_receiver,
            task_read_supported,
            task_notify_supported,
        })
    }

    pub fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<MacAuthorizationEvent, mpsc::RecvTimeoutError> {
        self.receiver.recv_timeout(timeout)
    }

    /// Drain metadata-only Process Shield audit handoffs without blocking the
    /// AUTH_OPEN channel.
    pub fn recv_shield_timeout(
        &self,
        timeout: Duration,
    ) -> Result<ShieldAuditEvent, mpsc::RecvTimeoutError> {
        self.shield_receiver.recv_timeout(timeout)
    }

    pub fn process_shield(&self) -> Arc<Mutex<MacProcessShield>> {
        Arc::clone(&self.context.shield)
    }

    /// MCH0: replace the runtime Process Shield toggle with the shared policy
    /// flag. When disabled, Process Shield admits nothing, denies no task
    /// access, applies no strong-signal transitions and never influences File
    /// Shield; File Shield stays fully active.
    pub fn set_process_shield_enabled(&mut self, flag: Arc<AtomicBool>) {
        // P1-4 review (round 3): the disabled -> enabled transition and epoch
        // advance live in MacPolicy::apply_config (before the enabled flag is
        // published). This startup-only setter just wires the shared flag.
        self.context.process_shield_enabled = flag;
    }

    /// Whether AUTH_GET_TASK_READ is actually enforced on this host (SDK/OS
    /// feature detection; never faked).
    pub fn task_read_supported(&self) -> bool {
        self.task_read_supported
    }

    /// Whether the Process Shield notify subscriptions (GET_TASK(_READ)/
    /// TRACE/REMOTE_THREAD_CREATE/CS_INVALIDATED) are active on this host.
    pub fn task_notify_supported(&self) -> bool {
        self.task_notify_supported
    }

    pub fn health(&self) -> BackendHealth {
        let snapshot = self.context.health.snapshot();
        let (alias_entries, alias_capacity, index_saturated) = match &self.context.config.scope {
            ProtectionScope::Browser { resources, .. } => resources.namespace_health(),
            ProtectionScope::Synthetic { .. } => (0, 0, false),
        };
        let process_graph_degraded = self
            .context
            .process_graph
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_degraded();
        let shield = self
            .context
            .shield
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (task_control_allowed, task_control_denied, task_read_allowed, task_read_denied) =
            shield.task_stats();
        let (shield_admitted, shield_compromised, launch_injection, malformed, _) = shield.stats();
        // LIVE preexisting count (not the cumulative telemetry): this drives
        // the Active/Reduced decision and must return to zero when the last
        // PreexistingUnverified instance exits or is replaced by AUTH_EXEC.
        let shield_preexisting = shield.live_preexisting_count() as u64;
        let (task_notify_obtained, trace_observed, remote_thread_observed, cs_invalidated) =
            shield.notify_stats();
        BackendHealth {
            backend: "endpoint-security".to_owned(),
            state: if !snapshot.active {
                "NOT_ENFORCING"
            } else if snapshot.degraded || index_saturated || process_graph_degraded {
                "DEGRADED"
            } else {
                "ACTIVE"
            }
            .to_owned(),
            active: snapshot.active,
            degraded: snapshot.degraded || index_saturated || process_graph_degraded,
            diagnostic: snapshot.diagnostic,
            sequence_gaps: snapshot.sequence_gaps,
            global_sequence_gaps: snapshot.global_sequence_gaps,
            pending_created: snapshot.pending_created,
            pending_resolved_allow: snapshot.pending_resolved_allow,
            pending_resolved_deny: snapshot.pending_resolved_deny,
            pending_timed_out: snapshot.pending_timed_out,
            insufficient_deadline: snapshot.insufficient_deadline,
            late_responses: snapshot.late_responses,
            namespace_allowed: snapshot.namespace_allowed,
            namespace_denied: snapshot.namespace_denied,
            namespace_alias_entries: alias_entries,
            namespace_alias_capacity: alias_capacity,
            namespace_index_saturated: index_saturated,
            process_graph_degraded,
            task_control_allowed,
            task_control_denied,
            task_read_allowed,
            task_read_denied,
            task_read_supported: self.task_read_supported,
            task_notify_supported: self.task_notify_supported,
            shield_admitted,
            shield_preexisting,
            shield_compromised,
            shield_launch_injection_denied: launch_injection,
            shield_malformed_denied: malformed,
            shield_task_notify_obtained: task_notify_obtained,
            shield_trace_observed: trace_observed,
            shield_remote_thread_observed: remote_thread_observed,
            shield_cs_invalidated_observed: cs_invalidated,
        }
    }

    /// Whether Process Shield is reduced because task-read or notify
    /// subscriptions are unavailable on this host. A disabled Process Shield
    /// is not "reduced" (it is off by explicit policy); status reporting uses
    /// process_shield_info for the Disabled state.
    pub fn process_shield_reduced(&self) -> bool {
        self.context.process_shield_active()
            && (!self.task_read_supported || !self.task_notify_supported)
    }

    pub fn process_graph(&self) -> Arc<Mutex<MacProcessGraph>> {
        Arc::clone(&self.context.process_graph)
    }

    pub fn repair_if_needed(&self) -> anyhow::Result<bool> {
        match &self.context.config.scope {
            ProtectionScope::Browser { resources, .. } => resources.repair_if_needed(),
            ProtectionScope::Synthetic { .. } => Ok(false),
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for EndpointSecurityBackend {
    fn drop(&mut self) {
        self.scheduler.shutdown();
        deny_registered(&self.context.registry);
        if let Some(client) = self.client.take() {
            drop(client);
        }
        self.context
            .health
            .stop("Endpoint Security client is stopped");
    }
}

#[cfg(target_os = "macos")]
pub fn diagnose_client_creation() -> Result<(), ClientCreateError> {
    let mut marker = ();
    let client = NativeClient::create_with_callback(
        diagnostic_callback,
        diagnostic_process_callback,
        diagnostic_namespace_callback,
        diagnostic_exec_callback,
        diagnostic_task_callback,
        diagnostic_task_notify_callback,
        diagnostic_sequence_callback,
        (&mut marker as *mut ()).cast(),
    )?;
    drop(client);
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn diagnose_client_creation() -> Result<(), ClientCreateError> {
    Err(ClientCreateError::UnsupportedPlatform)
}

#[cfg(target_os = "macos")]
struct CallbackContext {
    config: EndpointSecurityConfig,
    /// Independent Process Shield toggle (MCH0). Shared with the guard-es
    /// policy and the identity resolver; when false the shield admits nothing,
    /// denies no task access, applies no strong-signal transitions and does
    /// not influence File Shield. File Shield (AUTH_OPEN) is unaffected.
    process_shield_enabled: Arc<AtomicBool>,
    sender: mpsc::SyncSender<MacAuthorizationEvent>,
    scheduler: DeadlineSchedulerHandle,
    registry: Arc<Mutex<Vec<Weak<PendingInner>>>>,
    process_graph: Arc<Mutex<MacProcessGraph>>,
    shield: Arc<Mutex<MacProcessShield>>,
    shield_sender: mpsc::SyncSender<ShieldAuditEvent>,
    health: Arc<HealthTracker>,
    sequences: Mutex<SequenceTracker>,
}

#[cfg(target_os = "macos")]
enum ScopedOpen {
    Unprotected {
        requested_fflags: u32,
    },
    Protected {
        target: AuthOpenTargetFacts,
        resource: ProtectedResource,
    },
}

#[cfg(target_os = "macos")]
fn scope_open(
    config: &EndpointSecurityConfig,
    raw: &RawAuthOpenEvent,
) -> anyhow::Result<ScopedOpen> {
    if !config.has_protected_scope() {
        return Ok(ScopedOpen::Unprotected {
            requested_fflags: raw.requested_flags,
        });
    }
    let Some(candidate) = raw.candidate_target_facts() else {
        return Ok(ScopedOpen::Unprotected {
            requested_fflags: raw.requested_flags,
        });
    };
    let Some(resource) = config.classify(&candidate, raw.process.uid) else {
        return Ok(ScopedOpen::Unprotected {
            requested_fflags: raw.requested_flags,
        });
    };
    // Strict normalization is deliberately deferred until the target has
    // already matched the protected scope. Its failure may therefore deny one
    // protected target, but can never turn malformed unrelated events into a
    // machine-wide deny rule.
    let target = raw.to_target_facts()?;
    Ok(ScopedOpen::Protected { target, resource })
}

#[cfg(target_os = "macos")]
enum ScopedNamespace {
    Unprotected,
    Protected(NamespaceTargetFacts),
}

#[cfg(target_os = "macos")]
fn scope_namespace(
    config: &EndpointSecurityConfig,
    raw: &RawNamespaceEvent,
) -> anyhow::Result<ScopedNamespace> {
    if !config.has_protected_scope() {
        return Ok(ScopedNamespace::Unprotected);
    }
    let Some(candidate) = raw.candidate_target_facts() else {
        return Ok(ScopedNamespace::Unprotected);
    };
    if !config.namespace_requires_authorization(&candidate) {
        return Ok(ScopedNamespace::Unprotected);
    }
    let target = raw.to_target_facts()?;
    Ok(ScopedNamespace::Protected(target))
}

#[cfg(target_os = "macos")]
#[derive(Default)]
struct SequenceTracker {
    // Event kinds 1..=15: AUTH_OPEN, FORK, EXEC, EXIT, LINK, RENAME, AUTH_EXEC,
    // AUTH_GET_TASK, AUTH_GET_TASK_READ, NOTIFY_GET_TASK, NOTIFY_GET_TASK_READ,
    // NOTIFY_TRACE, NOTIFY_REMOTE_THREAD_CREATE, NOTIFY_CS_INVALIDATED,
    // AUTH_MMAP.
    per_kind: [Option<u64>; 16],
    global: Option<u64>,
}

#[cfg(target_os = "macos")]
impl SequenceTracker {
    fn observe(&mut self, kind: u32, sequence: Option<u64>, global: Option<u64>) -> (u64, u64) {
        let mut per_kind_gap = 0;
        if let (Some(sequence), Some(slot)) = (sequence, self.per_kind.get_mut(kind as usize)) {
            if let Some(previous) = *slot {
                if sequence > previous.saturating_add(1) {
                    per_kind_gap = sequence - previous - 1;
                }
            }
            if slot.is_none_or(|previous| sequence > previous) {
                *slot = Some(sequence);
            }
        }
        let mut global_gap = 0;
        if let Some(sequence) = global {
            if let Some(previous) = self.global {
                if sequence > previous.saturating_add(1) {
                    global_gap = sequence - previous - 1;
                }
            }
            if self.global.is_none_or(|previous| sequence > previous) {
                self.global = Some(sequence);
            }
        }
        (per_kind_gap, global_gap)
    }
}

#[cfg(target_os = "macos")]
impl CallbackContext {
    /// MCH0: whether Process Shield enforcement is currently active. The flag
    /// is shared with guard-es policy and the identity resolver so a runtime
    /// config apply flips every shield decision atomically. File Shield never
    /// consults this flag.
    ///
    /// P1-4 review (protection continuity): this is the hot-path gate for
    /// every exec/task shield decision, so it is the right place to detect the
    /// disabled -> enabled transition at runtime (a config apply only stores
    /// the AtomicBool; it never calls back into the backend). On the
    /// transition the shield epoch advances, invalidating every authority
    /// assertion from before the disabled interval.
    fn process_shield_active(&self) -> bool {
        // P1-4 review (round 3): the disabled -> enabled transition and epoch
        // advance live in MacPolicy::apply_config (authoritative config-apply
        // point, advanced BEFORE the enabled flag is published). This hot-path
        // gate is a pure read: no side effects, no dependence on UI/status
        // polling, so a protected AUTH_OPEN racing a toggle can never observe
        // enabled==true while the epoch was not yet advanced.
        self.process_shield_enabled.load(Ordering::Acquire)
    }

    /// MCH3: stable key of the verified parent of an exec'ing process, plus
    /// whether that parent is an enrolled browser executable. Returns (None,
    /// false) when the parent identity is unavailable or the graph has no
    /// current entry (unverifiable -> never session membership).
    fn exec_parent_context(&self, raw: &RawExecEvent) -> (Option<AuditProcessKey>, bool) {
        let Some(parent_pid) = (raw.process.parent_identity_available
            && raw.process.parent_pid > 0)
            .then_some(raw.process.parent_pid as u32)
        else {
            return (None, false);
        };
        let Some(parent_facts) = self
            .process_graph
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .current(parent_pid)
            .cloned()
        else {
            return (None, false);
        };
        let is_browser = self
            .config
            .is_enrolled_browser_executable(&parent_facts, parent_facts.uid);
        (Some(parent_facts.key), is_browser)
    }

    fn handle(
        &self,
        client: *const std::ffi::c_void,
        message: *const std::ffi::c_void,
        raw: &RawAuthOpenEvent,
    ) {
        let (target, resource) = match scope_open(&self.config, raw) {
            Ok(ScopedOpen::Unprotected { requested_fflags }) => {
                self.respond_immediate(client, message, requested_fflags);
                return;
            }
            Ok(ScopedOpen::Protected { target, resource }) => (target, resource),
            Err(error) => {
                self.health.note(format!(
                    "protected AUTH_OPEN failed closed during target normalization: {error}"
                ));
                self.respond_immediate(client, message, 0);
                return;
            }
        };
        let process = match raw.process.to_facts() {
            Ok(process) => process,
            Err(error) => {
                self.health.note(format!(
                    "protected AUTH_OPEN failed closed during process normalization: {error}"
                ));
                self.respond_immediate(client, message, 0);
                return;
            }
        };
        let facts = target.with_process(process);
        if let Err(error) = self
            .process_graph
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .observe(facts.process.clone(), std::time::Instant::now())
        {
            self.health.note(format!(
                "protected AUTH_OPEN failed closed because process identity could not be graphed: {error}"
            ));
            self.respond_immediate(client, message, 0);
            return;
        }
        let response_budget =
            match crate::deadline::response_budget(&crate::deadline::DarwinClock, raw.deadline) {
                Ok(budget) => budget,
                Err(error) => {
                    self.health.insufficient_deadline();
                    self.health
                        .note(format!("protected AUTH_OPEN failed closed: {error}"));
                    self.respond_immediate(client, message, 0);
                    return;
                }
            };

        // SAFETY: the ES message is live for this callback. Retaining it before
        // returning transfers one release obligation to RawResponseSink.
        unsafe { guard_es_message_retain(message) };
        let responder = Box::new(RawResponseSink {
            client: client as usize,
            message: message as usize,
        });
        let (permission, weak) =
            MacPendingPermission::new(facts.requested_fflags, responder, Arc::clone(&self.health));
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        registry.retain(|registered| {
            registered
                .upgrade()
                .is_some_and(|permission| !permission.is_terminal())
        });
        if registry.len() >= MAX_PENDING_AUTHORIZATIONS {
            drop(registry);
            self.health.degrade(
                "protected AUTH_OPEN failed closed because the pending authorization bound was reached",
            );
            drop(permission);
            return;
        }
        registry.push(weak.clone());
        drop(registry);
        if let Err(error) = self.scheduler.schedule(weak, response_budget) {
            self.health.degrade(format!(
                "protected AUTH_OPEN failed closed because its timer could not be scheduled: {error}"
            ));
            drop(permission);
            return;
        }
        let interactive_budget =
            crate::deadline::interactive_budget(&crate::deadline::DarwinClock, raw.deadline);
        if interactive_budget.is_err() {
            self.health.insufficient_deadline();
        }
        if self
            .sender
            .try_send(MacAuthorizationEvent {
                facts,
                resource,
                interactive_budget: interactive_budget.ok(),
                permission,
            })
            .is_err()
        {
            self.health.degrade(
                "protected AUTH_OPEN failed closed because the authorization queue is unavailable",
            );
        }
    }

    fn handle_namespace(
        &self,
        client: *const std::ffi::c_void,
        message: *const std::ffi::c_void,
        raw: &RawNamespaceEvent,
    ) {
        let target = match scope_namespace(&self.config, raw) {
            Ok(ScopedNamespace::Unprotected) => {
                self.health.namespace_decision(true);
                self.respond_namespace(client, message, true);
                return;
            }
            Ok(ScopedNamespace::Protected(target)) => target,
            Err(error) => {
                self.health.degrade(format!(
                    "protected namespace authorization failed closed during target normalization: {error}"
                ));
                self.respond_namespace(client, message, false);
                return;
            }
        };
        if let Err(error) =
            crate::deadline::response_budget(&crate::deadline::DarwinClock, raw.deadline)
        {
            self.health.insufficient_deadline();
            self.health.degrade(format!(
                "protected namespace authorization had insufficient response deadline: {error}"
            ));
            self.respond_namespace(client, message, false);
            return;
        }
        let process = match raw.process.to_facts() {
            Ok(process) => process,
            Err(error) => {
                self.health.degrade(format!(
                    "protected namespace authorization failed closed during process normalization: {error}"
                ));
                self.respond_namespace(client, message, false);
                return;
            }
        };
        let facts = target.with_process(process);
        if let Err(error) = self
            .process_graph
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .observe(facts.process.clone(), std::time::Instant::now())
        {
            self.health.degrade(format!(
                "protected namespace authorization failed closed because process identity was invalid: {error}"
            ));
            self.respond_namespace(client, message, false);
            return;
        }
        let allow = self.config.authorize_namespace(&facts);
        self.health.namespace_decision(allow);
        if allow {
            if let ProtectionScope::Browser { resources, .. } = &self.config.scope {
                let source_protected = resources
                    .namespace_view(&facts.source, Some(facts.source_identity))
                    .0
                    .is_some();
                let destination_protected = resources
                    .namespace_view(&facts.destination, facts.destination_identity)
                    .0
                    .is_some();
                if source_protected || destination_protected {
                    resources.request_refresh();
                }
            }
        }
        self.respond_namespace(client, message, allow);
    }
    fn handle_exec(
        &self,
        client: *const std::ffi::c_void,
        message: *const std::ffi::c_void,
        raw: &RawExecEvent,
    ) {
        // MCH0: Process Shield disabled -> every exec is allowed untouched.
        // No admission, no launch-integrity check, no shield audit. File
        // Shield is unaffected.
        if !self.process_shield_active() {
            self.respond_exec(client, message, true);
            return;
        }
        // Requester facts are audit context only. The requester is the
        // exec'ing process; for admission we need the exact post-exec target.
        let _requester = raw.process.to_facts().ok();
        let target = match raw.target.to_facts() {
            Ok(target) => target,
            Err(error) => {
                // Fail closed ONLY when the target appears to be enrolled by
                // cheap path facts. Unrelated malformed execs stay allowed so
                // Process Shield never becomes a machine-wide launch firewall.
                if self.config.shield_eligible_raw(&raw.target) {
                    self.shield
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .note_malformed_denied();
                    self.health.degrade(format!(
                        "shield-eligible AUTH_EXEC failed closed during target normalization: {error}"
                    ));
                    self.send_shield_event(ShieldAuditEvent::ExecDeniedMalformed {
                        requester_uid: raw.process.uid,
                        diagnostic: format!("{error}"),
                    });
                    self.respond_exec(client, message, false);
                    return;
                }
                self.respond_exec(client, message, true);
                return;
            }
        };
        let Some(reason) = self.config.shield_eligible(&target, target.uid) else {
            // Unrelated execs stay fast and allowed by Process Shield.
            self.respond_exec(client, message, true);
            return;
        };
        if let Err(error) =
            crate::deadline::response_budget(&crate::deadline::DarwinClock, raw.deadline)
        {
            self.health.insufficient_deadline();
            self.health.degrade(format!(
                "shield-eligible AUTH_EXEC had insufficient response deadline: {error}"
            ));
            self.respond_exec(client, message, false);
            return;
        }
        let launch = raw.launch_facts();
        if launch.has_prohibited_code_loading() {
            self.shield
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .note_launch_injection_denied();
            self.health.note(
                "shield-eligible AUTH_EXEC denied: prohibited code-loading DYLD launch state",
            );
            self.send_shield_event(ShieldAuditEvent::ExecDeniedLaunchInjection {
                target: target.clone(),
                present_vars: launch.present_vars(),
            });
            self.respond_exec(client, message, false);
            return;
        }
        // Register the exact post-exec target as shielded BEFORE responding
        // ALLOW so no NOTIFY_EXEC round-trip is required before the first
        // task-access decision against the new instance. MCH3: browser execs
        // are additionally classified against verified launch topology
        // (session root / joined member / rejected laundering); the outcome is
        // metadata only and never changes the ALLOW decision for a clean exec.
        let admission = if reason == ShieldReasonKind::Browser {
            let role = self.config.browser_role_of(&target, target.uid);
            let (parent_key, parent_is_browser) = self.exec_parent_context(raw);
            self.shield
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .admit_browser(target.clone(), role, parent_key, parent_is_browser)
        } else {
            self.shield
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .admit(target.clone(), reason)
                .map(|()| SessionMembership::Rejected(RejectionKind::Unverifiable))
        };
        match admission {
            Ok(membership) => {
                let role = if reason == ShieldReasonKind::Browser {
                    self.config.browser_role_of(&target, target.uid)
                } else {
                    None
                };
                self.send_shield_event(ShieldAuditEvent::ExecAdmitted {
                    target,
                    reason,
                    role,
                    membership,
                });
                self.respond_exec(client, message, true);
            }
            Err(error) => {
                self.health.degrade(format!(
                    "shield-eligible AUTH_EXEC failed closed during shield admission: {error}"
                ));
                self.respond_exec(client, message, false);
            }
        }
    }

    fn handle_task(
        &self,
        client: *const std::ffi::c_void,
        message: *const std::ffi::c_void,
        raw: &RawTaskEvent,
        kind: TaskAccessKind,
    ) {
        // MCH0: Process Shield disabled -> every task-capability request is
        // allowed untouched. No warm-start admission, no deny, no counters.
        if !self.process_shield_active() {
            self.respond_task(client, message, true);
            return;
        }
        // Normalize the TARGET first: for a known shielded target, malformed
        // or truncated identity must never become an allow.
        let target = match raw.target.to_facts() {
            Ok(target) => target,
            Err(error) => {
                if self.config.shield_eligible_raw(&raw.target) {
                    self.shield
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .note_malformed_denied();
                    self.health.degrade(format!(
                        "shield-eligible task target failed closed during normalization: {error}"
                    ));
                    self.send_shield_event(ShieldAuditEvent::ExecDeniedMalformed {
                        requester_uid: raw.process.uid,
                        diagnostic: format!("task target normalization failed: {error}"),
                    });
                    self.respond_task(client, message, false);
                    return;
                }
                // Unrelated target: Process Shield is not a global task firewall.
                self.respond_task(client, message, true);
                return;
            }
        };
        {
            let mut shield = self
                .shield
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !shield.is_task_protected(&target) {
                // MCH4: helpers and laundered execs are NOT task-protected.
                // Warm-start coverage (MPS Hardening) is preserved ONLY for
                // authority candidates: a Guard component or a browser Main
                // that predates this ES client (never admitted via AUTH_EXEC)
                // is admitted fail-closed so a same-user attacker cannot take
                // it over across a guard-es/extension restart. Browser helpers
                // without authority stay unprotected (they hold no secret
                // authority) and are promoted on a protected read (MCH5).
                if let Some(reason) = self.config.shield_eligible(&target, target.uid) {
                    let role = self.config.browser_role_of(&target, target.uid);
                    let is_browser_main = reason == ShieldReasonKind::Browser
                        && matches!(role, Some(BrowserExecutableRole::Main));
                    if !is_browser_main && reason != ShieldReasonKind::GuardComponent {
                        // Fast path: a non-authority browser helper or a
                        // laundered exec keeps existing task behavior.
                        drop(shield);
                        self.respond_task(client, message, true);
                        return;
                    }
                    let admission = if is_browser_main {
                        // MCH5: warm-start Main admitted as SecretAuthority
                        // before any task decision (launch unverified).
                        shield.ensure_authority(&target)
                    } else {
                        shield.admit_preexisting(target.clone(), reason)
                    };
                    if let Err(error) = admission {
                        self.health.degrade(format!(
                            "shield-eligible preexisting task target failed closed during admission: {error}"
                        ));
                        drop(shield);
                        self.respond_task(client, message, false);
                        return;
                    }
                    self.health.note(format!(
                        "shield-eligible preexisting target admitted unverified (warm start): {:?}",
                        target.executable.path
                    ));
                    let role = if reason == ShieldReasonKind::Browser {
                        self.config.browser_role_of(&target, target.uid)
                    } else {
                        None
                    };
                    self.send_shield_event(ShieldAuditEvent::ExecAdmitted {
                        target: target.clone(),
                        reason,
                        role,
                        // Warm-start: launch topology was never observed, so
                        // session membership is unverifiable (MCH3).
                        membership: SessionMembership::Rejected(RejectionKind::Unverifiable),
                    });
                    // Fall through: the preexisting instance is now protected
                    // and subject to the same allowlist below.
                } else {
                    // Fast path: unrelated processes keep their existing
                    // task behavior.
                    drop(shield);
                    self.respond_task(client, message, true);
                    return;
                }
            }
        }
        if let Err(error) =
            crate::deadline::response_budget(&crate::deadline::DarwinClock, raw.deadline)
        {
            self.health.insufficient_deadline();
            self.health.degrade(format!(
                "shielded task authorization had insufficient response deadline: {error}"
            ));
            self.respond_task(client, message, false);
            return;
        }
        let requester = match raw.process.to_facts() {
            Ok(requester) => requester,
            Err(error) => {
                // Shielded target + unverifiable requester identity => deny.
                self.health.degrade(format!(
                    "shielded task request failed closed because requester identity was invalid: {error}"
                ));
                self.send_shield_event(ShieldAuditEvent::TaskDenied {
                    kind,
                    requester: target.clone(),
                    target: target.clone(),
                });
                self.respond_task(client, message, false);
                return;
            }
        };
        // MPS2 starts with ZERO task-access allowlist entries; MPS11 adds the
        // documented platform-binary exceptions. Same UID, Apple signature,
        // same Team ID or a familiar basename never allow on their own.
        let allow = crate::process_shield::task_access_allowlist(&requester, &target, kind);
        if !allow {
            self.shield
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .note_task_decision(kind, false);
            self.health
                .note(format!("shielded task {} denied", kind.label()));
            self.send_shield_event(ShieldAuditEvent::TaskDenied {
                kind,
                requester,
                target,
            });
            self.respond_task(client, message, false);
            return;
        }
        self.shield
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .note_task_decision(kind, true);
        self.respond_task(client, message, true);
    }

    fn handle_task_notify(&self, event_kind: u32, raw: &RawTaskEvent) {
        // MCH0: Process Shield disabled -> notify signals are ignored
        // entirely: no telemetry, no audit, no compromise transitions.
        if !self.process_shield_active() {
            return;
        }
        // Telemetry only: notify events never authorize anything, so malformed
        // identities are skipped, never converted into an allow or a deny.
        let kind = match event_kind {
            10 => TaskNotifyKind::GetTask,
            11 => TaskNotifyKind::GetTaskRead,
            12 => TaskNotifyKind::Trace,
            13 => TaskNotifyKind::RemoteThreadCreate,
            14 => TaskNotifyKind::CsInvalidated,
            _ => {
                self.health
                    .degrade("task notify callback received an unknown event kind");
                return;
            }
        };
        let Ok(requester) = raw.process.to_facts() else {
            return;
        };
        let Ok(target) = raw.target.to_facts() else {
            return;
        };
        // Only notify signals involving an exact shielded target are in
        // Process Shield scope. Unrelated processes are untouched: no
        // telemetry, no audit, no state mutation. This also prevents the
        // system-wide notify subscriptions (GET_TASK/GET_TASK_READ/TRACE/
        // REMOTE_THREAD/CS_INVALIDATED on unrelated processes) from spilling
        // into the Guard audit queue.
        let mut shield = self
            .shield
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // MCH4: compromise signals apply only to task-protected
        // (SecretAuthority) targets, never to unprotected helpers.
        if !shield.is_task_protected(&target) {
            drop(shield);
            return;
        }
        // MPS Hardening: NOTIFY_GET_TASK / NOTIFY_GET_TASK_READ fire AFTER the
        // requester actually obtained the task capability (Apple semantics:
        // the notify means a send right was already granted). So an acquisition
        // that was NOT legitimate under our own task allowlist means this
        // process obtained task capability despite our prevention -> strong
        // compromise signal. Routinely allowed relationships (e.g. Apple
        // platform daemons managing processes/sessions) stay telemetry.
        // MCH7 + MCH3: no kind is unconditionally strong; strong_signal_decision
        // resolves every signal with the verified BrowserSession relationship.
        // MCH7 live evidence (this host): GET_TASK_READ notify fired for
        // /bin/ps against the extension's own GuardComponent process even
        // though AUTH_GET_TASK_READ denied the same requester, so READ notifies
        // are NOT reliable evidence of bypassed prevention -> strong_signal_decision
        // keeps GetTaskRead telemetry-only (health reports Reduced).
        let legitimate = crate::process_shield::task_access_allowlist(
            &requester,
            &target,
            match kind {
                TaskNotifyKind::GetTaskRead => TaskAccessKind::Read,
                _ => TaskAccessKind::Control,
            },
        );
        // MCH3: verified runtime relationship first. A same-session requester
        // is browser-internal; a provably externally launched requester (a
        // laundered helper whose parent was an attacker) is NOT related even
        // though it carries a genuine browser signature.
        let relation = shield.signal_relation(&requester.key, &target.key);
        // Fallback for UNVERIFIABLE membership (warm start / sequence gap):
        // browser identity alone (MCH7 heuristic) keeps warm-start browsers
        // from false-compromise transitions. P1 review: the fallback is
        // narrowed to the SAME enrolled browser as the target (same
        // BrowserId + UID) - BrowserIdentity must never become relationship
        // authority across enrollments (a warm-start Firefox requester must
        // not get fallback relationship with a Chrome target). BrowserIdentity
        // is context for signal interpretation only; it never grants task
        // authority.
        let fallback_related = matches!(
            self.config.shield_eligible(&requester, requester.uid),
            Some(ShieldReasonKind::Browser)
        ) && self.config.same_browser_enrollment(&requester, &target);
        let strong = crate::process_shield::strong_signal_decision(
            kind,
            legitimate,
            relation,
            fallback_related,
        );
        let outcome = if strong {
            shield.apply_strong_signal(&target)
        } else {
            StrongSignalOutcome::NotShielded
        };
        shield.note_task_notify(kind);
        drop(shield);
        if outcome == StrongSignalOutcome::NotShielded {
            self.send_shield_event(ShieldAuditEvent::TaskNotify {
                kind,
                requester,
                target,
            });
            return;
        }
        // MPS4 ordering: the shield state transition happens FIRST (done
        // above); capability revocation / audit / notify / containment are
        // driven by the Compromised event in guard-es.
        if outcome == StrongSignalOutcome::CompromisedNow {
            self.send_shield_event(ShieldAuditEvent::Compromised {
                target,
                signal: kind,
                requester,
            });
            return;
        }
        self.send_shield_event(ShieldAuditEvent::TaskNotify {
            kind,
            requester,
            target,
        });
    }

    fn respond_task(
        &self,
        client: *const std::ffi::c_void,
        message: *const std::ffi::c_void,
        allow: bool,
    ) {
        // SAFETY: both pointers are supplied by the live ES callback and the
        // bridge always disables authorization caching.
        let result =
            ResponseCode::from_raw(unsafe { guard_es_respond_auth(client, message, allow) });
        if result != ResponseCode::Success {
            self.health
                .degrade(format!("Endpoint Security task response failed: {result}"));
        }
    }

    fn respond_exec(
        &self,
        client: *const std::ffi::c_void,
        message: *const std::ffi::c_void,
        allow: bool,
    ) {
        // SAFETY: both pointers are supplied by the live ES callback and the
        // bridge always disables authorization caching.
        let result =
            ResponseCode::from_raw(unsafe { guard_es_respond_auth(client, message, allow) });
        if result != ResponseCode::Success {
            self.health.degrade(format!(
                "Endpoint Security AUTH_EXEC response failed: {result}"
            ));
        }
    }

    fn send_shield_event(&self, event: ShieldAuditEvent) {
        if self.shield_sender.try_send(event).is_err() {
            self.health.degrade(
                "Process Shield audit handoff queue is full; shield audit event was dropped",
            );
        }
    }

    fn observe_sequence(&self, event_kind: u32, sequence: Option<u64>, global: Option<u64>) {
        let (per_kind_gap, global_gap) = self
            .sequences
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .observe(event_kind, sequence, global);
        if per_kind_gap == 0 && global_gap == 0 {
            return;
        }
        if per_kind_gap > 0 {
            self.health.sequence_gap(false, per_kind_gap);
        }
        if global_gap > 0 {
            self.health.sequence_gap(true, global_gap);
        }
        self.health.degrade(format!(
            "Endpoint Security sequence gap detected (event_kind={event_kind}, per_type={per_kind_gap}, global={global_gap})"
        ));
        if global_gap > 0 || matches!(event_kind, 2..=4) {
            self.process_graph
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .mark_degraded();
        }
        if global_gap > 0 || matches!(event_kind, 1 | 5 | 6) {
            if let ProtectionScope::Browser { resources, .. } = &self.config.scope {
                resources.request_refresh();
            }
        }
    }

    fn handle_process_event(
        &self,
        event_kind: u32,
        process: &RawProcessFacts,
        related: Option<&RawProcessFacts>,
    ) {
        let process = match process.to_facts() {
            Ok(process) => process,
            Err(error) => {
                self.health
                    .degrade(format!("process graph event was invalid: {error}"));
                return;
            }
        };
        let now = std::time::Instant::now();
        let process_key = process.key;
        let mut graph = self
            .process_graph
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let result = match event_kind {
            1 => {
                let parent_result = related
                    .ok_or_else(|| anyhow::anyhow!("fork event omitted parent process"))
                    .and_then(RawProcessFacts::to_facts)
                    .and_then(|parent| graph.observe(parent, now));
                parent_result.and_then(|()| graph.observe(process, now))
            }
            // Apple documents exec as incrementing pidversion, so the target
            // is a new audit key and must pass the ordinary strict observer.
            2 => graph.observe(process, now),
            3 => {
                graph.remove_terminal(process_key);
                Ok(())
            }
            _ => Err(anyhow::anyhow!("unknown process event kind {event_kind}")),
        };
        if let Err(error) = result {
            self.health
                .degrade(format!("process graph update failed: {error}"));
        }
        // Process Shield live state mirrors process exit exactly: exit
        // destroys the instance's shield/compromise state, so PID reuse can
        // never inherit it.
        if event_kind == 3 {
            self.shield
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove_terminal(process_key);
        }
    }

    fn respond_immediate(
        &self,
        client: *const std::ffi::c_void,
        message: *const std::ffi::c_void,
        authorized_flags: u32,
    ) {
        // SAFETY: both opaque pointers are supplied together by the active ES
        // callback, and the C shim hardcodes cache=false.
        let result = unsafe { guard_es_respond_flags(client, message, authorized_flags) };
        let result = ResponseCode::from_raw(result);
        if result != ResponseCode::Success {
            self.health.degrade(format!(
                "immediate Endpoint Security flags response failed: {result}"
            ));
        }
    }

    fn respond_namespace(
        &self,
        client: *const std::ffi::c_void,
        message: *const std::ffi::c_void,
        allow: bool,
    ) {
        // SAFETY: both pointers are supplied by the live ES callback and the
        // bridge always disables authorization caching.
        let result =
            ResponseCode::from_raw(unsafe { guard_es_respond_auth(client, message, allow) });
        if result != ResponseCode::Success {
            self.health.degrade(format!(
                "Endpoint Security namespace response failed: {result}"
            ));
        }
    }
}

#[cfg(target_os = "macos")]
fn deny_registered(registry: &Mutex<Vec<Weak<PendingInner>>>) {
    let pending = registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .drain(..)
        .collect::<Vec<_>>();
    for permission in pending {
        if let Some(permission) = permission.upgrade() {
            let _ = permission.resolve(false);
        }
    }
}

#[cfg(target_os = "macos")]
struct RawResponseSink {
    client: usize,
    message: usize,
}

#[cfg(target_os = "macos")]
impl ResponseSink for RawResponseSink {
    fn respond(&self, authorized_flags: u32) -> ResponseCode {
        // SAFETY: the client outlives every registered pending response, and
        // the retained message remains live until this sink releases it.
        ResponseCode::from_raw(unsafe {
            guard_es_respond_flags(
                self.client as *const std::ffi::c_void,
                self.message as *const std::ffi::c_void,
                authorized_flags,
            )
        })
    }

    fn release(&self) {
        // SAFETY: MacPendingPermission guarantees this is called exactly once
        // for the retain performed when the deferred request was constructed.
        unsafe { guard_es_message_release(self.message as *const std::ffi::c_void) };
    }
}

impl ResponseCode {
    #[cfg(target_os = "macos")]
    fn from_raw(raw: i32) -> Self {
        match raw {
            0 => Self::Success,
            1 => Self::InvalidArgument,
            2 => Self::Internal,
            3 => Self::NotFound,
            4 => Self::Duplicate,
            5 => Self::WrongEventType,
            value => Self::Unknown(value),
        }
    }
}

#[cfg(target_os = "macos")]
struct NativeClient {
    raw: *mut std::ffi::c_void,
    // es_delete_client must run on the thread that called es_new_client.
    _not_send: std::marker::PhantomData<std::rc::Rc<()>>,
}

#[cfg(target_os = "macos")]
impl NativeClient {
    fn create(context: *mut CallbackContext) -> Result<Self, ClientCreateError> {
        Self::create_with_callback(
            auth_open_callback,
            process_callback,
            namespace_callback,
            exec_callback,
            task_callback,
            task_notify_callback,
            sequence_callback,
            context.cast(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn create_with_callback(
        callback: RawCallback,
        process_callback: RawProcessCallback,
        namespace_callback: RawNamespaceCallback,
        exec_callback: RawExecCallback,
        task_callback: RawTaskCallback,
        task_notify_callback: RawTaskNotifyCallback,
        sequence_callback: RawSequenceCallback,
        context: *mut std::ffi::c_void,
    ) -> Result<Self, ClientCreateError> {
        let mut raw = std::ptr::null_mut();
        // SAFETY: context remains live in EndpointSecurityBackend for the
        // complete client lifetime; the C wrapper copies the callback block.
        let result = unsafe {
            guard_es_client_create(
                &mut raw,
                callback,
                process_callback,
                namespace_callback,
                exec_callback,
                task_callback,
                task_notify_callback,
                sequence_callback,
                context,
            )
        };
        match result {
            0 => Ok(Self {
                raw,
                _not_send: std::marker::PhantomData,
            }),
            1 => Err(ClientCreateError::InvalidArgument),
            2 => Err(ClientCreateError::Internal),
            3 => Err(ClientCreateError::NotEntitled),
            4 => Err(ClientCreateError::NotPermitted),
            5 => Err(ClientCreateError::NotPrivileged),
            6 => Err(ClientCreateError::TooManyClients),
            value => Err(ClientCreateError::Unknown(value)),
        }
    }

    fn subscribe_required(&self) -> anyhow::Result<()> {
        // SAFETY: raw is a live guard_es_client_t owned by self.
        anyhow::ensure!(
            unsafe { guard_es_client_subscribe_required(self.raw) } == 0,
            "es_subscribe(AUTH_OPEN/AUTH_EXEC/AUTH_GET_TASK/FORK/EXEC/EXIT) failed"
        );
        Ok(())
    }

    /// AUTH_GET_TASK_READ is feature-detected at runtime: when the running
    /// OS/SDK does not support it, this returns false and Process Shield must
    /// report Reduced rather than pretending read-port prevention exists.
    fn subscribe_task_read(&self) -> bool {
        // SAFETY: raw is a live guard_es_client_t owned by self.
        let result = unsafe { guard_es_client_subscribe_task_read(self.raw) };
        result == 0
    }

    /// NOTIFY_GET_TASK(_READ)/TRACE/REMOTE_THREAD_CREATE/CS_INVALIDATED
    /// subscriptions; when unavailable, compromise detection is degraded and
    /// health must reflect that.
    fn subscribe_task_notify(&self) -> bool {
        // SAFETY: raw is a live guard_es_client_t owned by self.
        let result = unsafe { guard_es_client_subscribe_task_notify(self.raw) };
        result == 0
    }
}

#[cfg(target_os = "macos")]
impl Drop for NativeClient {
    fn drop(&mut self) {
        // SAFETY: NativeClient is !Send and therefore drops on its creator
        // thread; the wrapper is consumed exactly once here.
        let _ = unsafe { guard_es_client_delete(self.raw) };
    }
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct RawAuthOpenEvent {
    requested_flags: u32,
    deadline: u64,
    target_dev: u64,
    target_ino: u64,
    target_path: *const u8,
    target_path_len: usize,
    target_path_truncated: bool,
    process: RawProcessFacts,
}

#[cfg(target_os = "macos")]
#[derive(Default)]
#[repr(C)]
struct RawNamespaceEvent {
    operation: u32,
    deadline: u64,
    source_dev: u64,
    source_ino: u64,
    source_path: *const u8,
    source_path_len: usize,
    source_path_truncated: bool,
    destination_existing: bool,
    destination_dev: u64,
    destination_ino: u64,
    destination_dir_path: *const u8,
    destination_dir_path_len: usize,
    destination_dir_path_truncated: bool,
    destination_name: *const u8,
    destination_name_len: usize,
    destination_existing_path: *const u8,
    destination_existing_path_len: usize,
    destination_existing_path_truncated: bool,
    process: RawProcessFacts,
}

#[cfg(target_os = "macos")]
#[derive(Default)]
#[repr(C)]
struct RawProcessFacts {
    pid: i32,
    uid: u32,
    gid: u32,
    pidversion: i32,
    parent_pid: i32,
    parent_pidversion: i32,
    parent_identity_available: bool,
    responsible_pid: i32,
    responsible_pidversion: i32,
    responsible_identity_available: bool,
    start_time_us: u64,
    executable_dev: u64,
    executable_ino: u64,
    executable_mode: u32,
    executable_owner_uid: u32,
    executable_size: u64,
    executable_mtime_ns: i64,
    executable_ctime_ns: i64,
    executable_path: *const u8,
    executable_path_len: usize,
    executable_path_truncated: bool,
    code_signing_flags: u32,
    code_signing_valid: bool,
    platform_binary: bool,
    team_id: *const u8,
    team_id_len: usize,
    signing_id: *const u8,
    signing_id_len: usize,
    cdhash: [u8; 20],
}

#[cfg(target_os = "macos")]
#[derive(Default)]
#[repr(C)]
struct RawExecEvent {
    deadline: u64,
    dyld_insert_libraries: bool,
    dyld_library_path: bool,
    dyld_framework_path: bool,
    dyld_fallback_library_path: bool,
    dyld_fallback_framework_path: bool,
    dyld_root_path: bool,
    process: RawProcessFacts,
    target: RawProcessFacts,
}

#[cfg(target_os = "macos")]
impl RawExecEvent {
    fn launch_facts(&self) -> ExecLaunchFacts {
        ExecLaunchFacts {
            dyld_insert_libraries: self.dyld_insert_libraries,
            dyld_library_path: self.dyld_library_path,
            dyld_framework_path: self.dyld_framework_path,
            dyld_fallback_library_path: self.dyld_fallback_library_path,
            dyld_fallback_framework_path: self.dyld_fallback_framework_path,
            dyld_root_path: self.dyld_root_path,
        }
    }
}

#[cfg(target_os = "macos")]
#[derive(Default)]
#[repr(C)]
struct RawTaskEvent {
    deadline: u64,
    process: RawProcessFacts,
    target: RawProcessFacts,
}

#[cfg(target_os = "macos")]
impl RawAuthOpenEvent {
    fn candidate_target_facts(&self) -> Option<AuthOpenTargetFacts> {
        Some(AuthOpenTargetFacts {
            requested_fflags: self.requested_flags,
            target: token_path_candidate(self.target_path, self.target_path_len)?,
            target_dev: self.target_dev,
            target_ino: self.target_ino,
        })
    }

    fn to_target_facts(&self) -> anyhow::Result<AuthOpenTargetFacts> {
        anyhow::ensure!(
            !self.target_path_truncated,
            "Endpoint Security supplied a truncated target path"
        );
        anyhow::ensure!(
            self.target_dev != 0 && self.target_ino != 0,
            "Endpoint Security supplied incomplete target file identity"
        );
        Ok(AuthOpenTargetFacts {
            requested_fflags: self.requested_flags,
            target: token_path(self.target_path, self.target_path_len)?,
            target_dev: self.target_dev,
            target_ino: self.target_ino,
        })
    }
}

#[cfg(target_os = "macos")]
impl RawNamespaceEvent {
    fn candidate_target_facts(&self) -> Option<NamespaceTargetFacts> {
        let destination = if self.destination_existing {
            token_path_candidate(
                self.destination_existing_path,
                self.destination_existing_path_len,
            )?
        } else {
            token_path_candidate(self.destination_dir_path, self.destination_dir_path_len)?.join(
                token_os_string_candidate(self.destination_name, self.destination_name_len)?,
            )
        };
        Some(NamespaceTargetFacts {
            operation: match self.operation {
                1 => NamespaceOperation::Link,
                2 => NamespaceOperation::Rename,
                _ => return None,
            },
            source: token_path_candidate(self.source_path, self.source_path_len)?,
            source_identity: FileIdentity {
                dev: self.source_dev,
                ino: self.source_ino,
            },
            destination,
            destination_identity: self.destination_existing.then_some(FileIdentity {
                dev: self.destination_dev,
                ino: self.destination_ino,
            }),
        })
    }

    fn to_target_facts(&self) -> anyhow::Result<NamespaceTargetFacts> {
        anyhow::ensure!(
            !self.source_path_truncated,
            "Endpoint Security supplied a truncated namespace source path"
        );
        anyhow::ensure!(
            self.source_dev != 0 && self.source_ino != 0,
            "Endpoint Security supplied incomplete namespace source identity"
        );
        let destination = if self.destination_existing {
            anyhow::ensure!(
                !self.destination_existing_path_truncated,
                "Endpoint Security supplied a truncated existing destination path"
            );
            anyhow::ensure!(
                self.destination_dev != 0 && self.destination_ino != 0,
                "Endpoint Security supplied incomplete existing destination identity"
            );
            token_path(
                self.destination_existing_path,
                self.destination_existing_path_len,
            )?
        } else {
            anyhow::ensure!(
                !self.destination_dir_path_truncated,
                "Endpoint Security supplied a truncated destination directory path"
            );
            let directory = token_path(self.destination_dir_path, self.destination_dir_path_len)?;
            directory.join(token_os_string(
                self.destination_name,
                self.destination_name_len,
            )?)
        };
        Ok(NamespaceTargetFacts {
            operation: match self.operation {
                1 => NamespaceOperation::Link,
                2 => NamespaceOperation::Rename,
                value => anyhow::bail!("unknown namespace operation {value}"),
            },
            source: token_path(self.source_path, self.source_path_len)?,
            source_identity: FileIdentity {
                dev: self.source_dev,
                ino: self.source_ino,
            },
            destination,
            destination_identity: self.destination_existing.then_some(FileIdentity {
                dev: self.destination_dev,
                ino: self.destination_ino,
            }),
        })
    }
}

#[cfg(target_os = "macos")]
impl RawProcessFacts {
    /// Best-effort executable path for scope gating before strict
    /// normalization (never an authority by itself).
    fn candidate_executable_path(&self) -> Option<PathBuf> {
        token_path_candidate(self.executable_path, self.executable_path_len)
    }

    fn to_facts(&self) -> anyhow::Result<MacProcessFacts> {
        anyhow::ensure!(self.pid > 0, "invalid or missing process PID");
        anyhow::ensure!(self.pidversion >= 0, "invalid process PID version");
        anyhow::ensure!(self.start_time_us > 0, "missing ES process start time");
        anyhow::ensure!(
            !self.executable_path_truncated,
            "Endpoint Security supplied a truncated executable path"
        );
        anyhow::ensure!(
            self.executable_dev != 0 && self.executable_ino != 0,
            "Endpoint Security supplied incomplete executable identity"
        );
        let facts = MacProcessFacts {
            key: AuditProcessKey {
                pid: self.pid as u32,
                pidversion: self.pidversion as u32,
            },
            uid: self.uid,
            gid: self.gid,
            start_time_us: self.start_time_us,
            executable: ExecutableSnapshot {
                path: token_path(self.executable_path, self.executable_path_len)?,
                dev: self.executable_dev,
                ino: self.executable_ino,
                owner_uid: self.executable_owner_uid,
                mode: self.executable_mode,
                size: self.executable_size,
                mtime_ns: self.executable_mtime_ns,
                ctime_ns: self.executable_ctime_ns,
            },
            code: MacCodeIdentity {
                valid: self.code_signing_valid,
                platform_binary: self.platform_binary,
                flags: self.code_signing_flags,
                team_id: token_optional_string(self.team_id, self.team_id_len)?,
                signing_id: token_optional_string(self.signing_id, self.signing_id_len)?,
                cdhash: self.cdhash,
            },
            parent: audit_key(
                self.parent_identity_available,
                self.parent_pid,
                self.parent_pidversion,
            )?,
            responsible: audit_key(
                self.responsible_identity_available,
                self.responsible_pid,
                self.responsible_pidversion,
            )?,
        };
        facts.validate()?;
        Ok(facts)
    }
}

#[cfg(target_os = "macos")]
fn audit_key(
    available: bool,
    pid: i32,
    pidversion: i32,
) -> anyhow::Result<Option<AuditProcessKey>> {
    if !available || pid <= 1 {
        return Ok(None);
    }
    anyhow::ensure!(pidversion >= 0, "invalid parent/responsible PID version");
    Ok(Some(AuditProcessKey {
        pid: pid as u32,
        pidversion: pidversion as u32,
    }))
}

#[cfg(target_os = "macos")]
fn token_optional_string(pointer: *const u8, length: usize) -> anyhow::Result<Option<String>> {
    if length == 0 {
        return Ok(None);
    }
    anyhow::ensure!(!pointer.is_null(), "missing signing token");
    // SAFETY: the token is copied synchronously while the ES message is live.
    let bytes = unsafe { std::slice::from_raw_parts(pointer, length) };
    Ok(Some(std::str::from_utf8(bytes)?.to_owned()))
}

#[cfg(target_os = "macos")]
fn token_path(pointer: *const u8, length: usize) -> anyhow::Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt;

    anyhow::ensure!(length > 0, "empty path token");
    anyhow::ensure!(!pointer.is_null(), "missing path token");
    // SAFETY: the token is supplied by ES and copied synchronously while the
    // callback's es_message_t is live.
    let bytes = unsafe { std::slice::from_raw_parts(pointer, length) };
    Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec())))
}

#[cfg(target_os = "macos")]
fn token_path_candidate(pointer: *const u8, length: usize) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;

    if pointer.is_null() || length == 0 {
        return None;
    }
    // SAFETY: checked non-null/non-empty and copied only while the ES message
    // backing the token is live.
    let bytes = unsafe { std::slice::from_raw_parts(pointer, length) };
    Some(PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec())))
}

#[cfg(target_os = "macos")]
fn token_os_string(pointer: *const u8, length: usize) -> anyhow::Result<std::ffi::OsString> {
    use std::os::unix::ffi::OsStringExt;

    anyhow::ensure!(length > 0, "empty filename token");
    anyhow::ensure!(!pointer.is_null(), "missing filename token");
    // SAFETY: the token is copied synchronously while the ES message is live.
    let bytes = unsafe { std::slice::from_raw_parts(pointer, length) };
    Ok(std::ffi::OsString::from_vec(bytes.to_vec()))
}

#[cfg(target_os = "macos")]
fn token_os_string_candidate(pointer: *const u8, length: usize) -> Option<std::ffi::OsString> {
    use std::os::unix::ffi::OsStringExt;

    if pointer.is_null() || length == 0 {
        return None;
    }
    // SAFETY: checked non-null/non-empty and copied synchronously.
    let bytes = unsafe { std::slice::from_raw_parts(pointer, length) };
    Some(std::ffi::OsString::from_vec(bytes.to_vec()))
}

#[cfg(target_os = "macos")]
type RawCallback = unsafe extern "C" fn(
    *mut std::ffi::c_void,
    *const std::ffi::c_void,
    *const std::ffi::c_void,
    *const RawAuthOpenEvent,
);

#[cfg(target_os = "macos")]
type RawProcessCallback = unsafe extern "C" fn(
    *mut std::ffi::c_void,
    u32,
    *const RawProcessFacts,
    *const RawProcessFacts,
);

#[cfg(target_os = "macos")]
type RawNamespaceCallback = unsafe extern "C" fn(
    *mut std::ffi::c_void,
    *const std::ffi::c_void,
    *const std::ffi::c_void,
    *const RawNamespaceEvent,
);

#[cfg(target_os = "macos")]
type RawExecCallback = unsafe extern "C" fn(
    *mut std::ffi::c_void,
    *const std::ffi::c_void,
    *const std::ffi::c_void,
    *const RawExecEvent,
);

#[cfg(target_os = "macos")]
type RawTaskCallback = unsafe extern "C" fn(
    *mut std::ffi::c_void,
    u32,
    *const std::ffi::c_void,
    *const std::ffi::c_void,
    *const RawTaskEvent,
);

#[cfg(target_os = "macos")]
type RawTaskNotifyCallback = unsafe extern "C" fn(*mut std::ffi::c_void, u32, *const RawTaskEvent);

#[cfg(target_os = "macos")]
type RawSequenceCallback = unsafe extern "C" fn(*mut std::ffi::c_void, u32, bool, u64, bool, u64);

#[cfg(target_os = "macos")]
unsafe extern "C" fn auth_open_callback(
    context: *mut std::ffi::c_void,
    client: *const std::ffi::c_void,
    message: *const std::ffi::c_void,
    event: *const RawAuthOpenEvent,
) {
    // SAFETY: NativeClient was created with a pointer to the boxed context,
    // which remains stable until after es_delete_client returns.
    let context = unsafe { &*context.cast::<CallbackContext>() };
    if event.is_null() {
        context
            .health
            .degrade("received an unexpected non-AUTH_OPEN Endpoint Security message");
        return;
    }
    // SAFETY: the C shim owns normalized on its callback stack and it remains
    // live for this synchronous Rust call.
    let event = unsafe { &*event };
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        context.handle(client, message, event);
    }))
    .is_err()
    {
        // Unwinding across the C callback boundary is undefined. An abort is
        // preferable to continuing with unknown response/message ownership.
        std::process::abort();
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn process_callback(
    context: *mut std::ffi::c_void,
    event_kind: u32,
    process: *const RawProcessFacts,
    related: *const RawProcessFacts,
) {
    // SAFETY: callback pointers and context are owned by the live C shim call.
    let context = unsafe { &*context.cast::<CallbackContext>() };
    if process.is_null() {
        context
            .health
            .degrade("process callback omitted process facts");
        return;
    }
    // SAFETY: non-null normalized structs live for this callback only.
    let process = unsafe { &*process };
    let related = if related.is_null() {
        None
    } else {
        // SAFETY: checked non-null and copied only during this callback.
        Some(unsafe { &*related })
    };
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        context.handle_process_event(event_kind, process, related);
    }))
    .is_err()
    {
        std::process::abort();
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn namespace_callback(
    context: *mut std::ffi::c_void,
    client: *const std::ffi::c_void,
    message: *const std::ffi::c_void,
    event: *const RawNamespaceEvent,
) {
    // SAFETY: context and event are owned by the live native callback.
    let context = unsafe { &*context.cast::<CallbackContext>() };
    if event.is_null() {
        context
            .health
            .degrade("namespace callback omitted normalized event facts");
        let _ = unsafe { guard_es_respond_auth(client, message, false) };
        return;
    }
    let event = unsafe { &*event };
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        context.handle_namespace(client, message, event);
    }))
    .is_err()
    {
        std::process::abort();
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn exec_callback(
    context: *mut std::ffi::c_void,
    client: *const std::ffi::c_void,
    message: *const std::ffi::c_void,
    event: *const RawExecEvent,
) {
    // SAFETY: context and event are owned by the live native callback.
    let context = unsafe { &*context.cast::<CallbackContext>() };
    if event.is_null() {
        context
            .health
            .degrade("exec callback omitted normalized event facts");
        // Defensive: a bridge bug must not brick process launches; the exec
        // proceeds unshielded and File Shield still polices protected files.
        let _ = unsafe { guard_es_respond_auth(client, message, true) };
        return;
    }
    let event = unsafe { &*event };
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        context.handle_exec(client, message, event);
    }))
    .is_err()
    {
        std::process::abort();
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn task_callback(
    context: *mut std::ffi::c_void,
    event_kind: u32,
    client: *const std::ffi::c_void,
    message: *const std::ffi::c_void,
    event: *const RawTaskEvent,
) {
    // SAFETY: context and event are owned by the live native callback.
    let context = unsafe { &*context.cast::<CallbackContext>() };
    if event.is_null() {
        context
            .health
            .degrade("task callback omitted normalized event facts");
        let _ = unsafe { guard_es_respond_auth(client, message, true) };
        return;
    }
    let event = unsafe { &*event };
    let kind = match event_kind {
        8 => TaskAccessKind::Control,
        9 => TaskAccessKind::Read,
        _ => {
            context
                .health
                .degrade("task callback received an unknown task event kind");
            let _ = unsafe { guard_es_respond_auth(client, message, true) };
            return;
        }
    };
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        context.handle_task(client, message, event, kind);
    }))
    .is_err()
    {
        std::process::abort();
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn task_notify_callback(
    context: *mut std::ffi::c_void,
    event_kind: u32,
    event: *const RawTaskEvent,
) {
    // SAFETY: context and event are owned by the live native callback.
    let context = unsafe { &*context.cast::<CallbackContext>() };
    if event.is_null() {
        context
            .health
            .degrade("task notify callback omitted normalized event facts");
        return;
    }
    let event = unsafe { &*event };
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        context.handle_task_notify(event_kind, event);
    }))
    .is_err()
    {
        std::process::abort();
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn sequence_callback(
    context: *mut std::ffi::c_void,
    event_kind: u32,
    has_sequence: bool,
    sequence: u64,
    has_global_sequence: bool,
    global_sequence: u64,
) {
    // SAFETY: context is the boxed CallbackContext for the live client.
    let context = unsafe { &*context.cast::<CallbackContext>() };
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        context.observe_sequence(
            event_kind,
            has_sequence.then_some(sequence),
            has_global_sequence.then_some(global_sequence),
        );
    }))
    .is_err()
    {
        std::process::abort();
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn diagnostic_callback(
    _context: *mut std::ffi::c_void,
    client: *const std::ffi::c_void,
    message: *const std::ffi::c_void,
    event: *const RawAuthOpenEvent,
) {
    if !event.is_null() {
        // SAFETY: an unexpected event is still live inside its ES callback;
        // deny it with cache disabled before returning.
        let _ = unsafe { guard_es_respond_flags(client, message, 0) };
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn diagnostic_process_callback(
    _context: *mut std::ffi::c_void,
    _event_kind: u32,
    _process: *const RawProcessFacts,
    _related: *const RawProcessFacts,
) {
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn diagnostic_namespace_callback(
    _context: *mut std::ffi::c_void,
    client: *const std::ffi::c_void,
    message: *const std::ffi::c_void,
    event: *const RawNamespaceEvent,
) {
    if !event.is_null() {
        let _ = unsafe { guard_es_respond_auth(client, message, false) };
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn diagnostic_exec_callback(
    _context: *mut std::ffi::c_void,
    client: *const std::ffi::c_void,
    message: *const std::ffi::c_void,
    event: *const RawExecEvent,
) {
    if !event.is_null() {
        let _ = unsafe { guard_es_respond_auth(client, message, true) };
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn diagnostic_task_callback(
    _context: *mut std::ffi::c_void,
    _event_kind: u32,
    client: *const std::ffi::c_void,
    message: *const std::ffi::c_void,
    event: *const RawTaskEvent,
) {
    if !event.is_null() {
        let _ = unsafe { guard_es_respond_auth(client, message, true) };
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn diagnostic_task_notify_callback(
    _context: *mut std::ffi::c_void,
    _event_kind: u32,
    _event: *const RawTaskEvent,
) {
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn diagnostic_sequence_callback(
    _context: *mut std::ffi::c_void,
    _event_kind: u32,
    _has_sequence: bool,
    _sequence: u64,
    _has_global_sequence: bool,
    _global_sequence: u64,
) {
}

#[cfg(target_os = "macos")]
#[allow(clippy::too_many_arguments)]
extern "C" {
    fn guard_es_client_create(
        client: *mut *mut std::ffi::c_void,
        callback: RawCallback,
        process_callback: RawProcessCallback,
        namespace_callback: RawNamespaceCallback,
        exec_callback: RawExecCallback,
        task_callback: RawTaskCallback,
        task_notify_callback: RawTaskNotifyCallback,
        sequence_callback: RawSequenceCallback,
        context: *mut std::ffi::c_void,
    ) -> i32;
    fn guard_es_client_subscribe_required(client: *mut std::ffi::c_void) -> i32;
    fn guard_es_client_subscribe_task_read(client: *mut std::ffi::c_void) -> i32;
    fn guard_es_client_subscribe_task_notify(client: *mut std::ffi::c_void) -> i32;
    fn guard_es_client_delete(client: *mut std::ffi::c_void) -> i32;
    fn guard_es_message_retain(message: *const std::ffi::c_void);
    fn guard_es_message_release(message: *const std::ffi::c_void);
    fn guard_es_respond_flags(
        client: *const std::ffi::c_void,
        message: *const std::ffi::c_void,
        authorized_flags: u32,
    ) -> i32;
    fn guard_es_respond_auth(
        client: *const std::ffi::c_void,
        message: *const std::ffi::c_void,
        allow: bool,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser_trust::{
        BrowserExecutableRole, MacBrowserEnrollment, MacExecutableEnrollment,
    };
    use guard_core::resource::{BrowserFamily, BrowserId};
    use guard_core::ProcessIntegrity;
    use std::os::unix::fs::MetadataExt;

    fn fixture_process(signing_id: &str) -> MacProcessFacts {
        MacProcessFacts {
            key: AuditProcessKey {
                pid: 42,
                pidversion: 7,
            },
            uid: 501,
            gid: 20,
            start_time_us: 123_456,
            executable: ExecutableSnapshot {
                path: PathBuf::from("/Applications/Fixture.app/Contents/MacOS/Fixture"),
                dev: 9,
                ino: 10,
                owner_uid: 0,
                mode: 0o100755,
                size: 100,
                mtime_ns: 1,
                ctime_ns: 1,
            },
            code: MacCodeIdentity {
                valid: true,
                platform_binary: false,
                flags: 1,
                team_id: Some("TEAM123456".into()),
                signing_id: Some(signing_id.into()),
                cdhash: [1; 20],
            },
            parent: None,
            responsible: None,
        }
    }

    fn browser_namespace_fixture() -> (tempfile::TempDir, EndpointSecurityConfig, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("Chrome");
        std::fs::create_dir_all(root.join("Default/Network")).unwrap();
        std::fs::write(root.join("Local State"), b"synthetic state").unwrap();
        let cookies = root.join("Default/Network/Cookies");
        std::fs::write(&cookies, b"synthetic cookies").unwrap();
        let enrollment = MacBrowserEnrollment {
            browser_id: BrowserId("chrome".into()),
            family: BrowserFamily::Chromium,
            profile_root: root,
            owner_uid: 501,
            app_bundle: Some(PathBuf::from("/Applications/Fixture.app")),
            executables: vec![MacExecutableEnrollment::Signed {
                role: BrowserExecutableRole::Main,
                path: PathBuf::from("/Applications/Fixture.app/Contents/MacOS/Fixture"),
                bundle_suffix: None,
                team_id: "TEAM123456".into(),
                signing_id: "fixture.browser".into(),
            }],
        };
        let index = crate::resource_index::MacResourceIndex::from_browser_enrollments(
            std::slice::from_ref(&enrollment),
        )
        .unwrap();
        let trust = MacBrowserTrustStore::load_and_revalidate(vec![enrollment]).unwrap();
        let config = EndpointSecurityConfig::browser(
            Arc::new(MacProtectedResources::new(true, index)),
            Arc::new(RwLock::new(trust)),
        );
        (temp, config, cookies)
    }

    #[test]
    fn synthetic_config_requires_existing_absolute_paths() {
        assert!(
            EndpointSecurityConfig::synthetic_exact_paths([PathBuf::from("relative")]).is_err()
        );
        assert!(EndpointSecurityConfig::synthetic_exact_paths(Vec::<PathBuf>::new()).is_err());
    }

    #[test]
    fn raw_exec_normalizes_target_and_launch_facts() {
        use std::os::unix::ffi::OsStrExt;

        let temp = tempfile::tempdir().unwrap();
        let target_exe = temp.path().join("shield-target");
        std::fs::write(&target_exe, b"synthetic shield target").unwrap();
        let target_exe = std::fs::canonicalize(&target_exe).unwrap();
        let metadata = std::fs::metadata(&target_exe).unwrap();
        let path_bytes = target_exe.as_os_str().as_bytes();
        let mut raw = RawExecEvent {
            deadline: 1_000,
            dyld_insert_libraries: true,
            ..RawExecEvent::default()
        };
        raw.target = RawProcessFacts {
            pid: 4242,
            pidversion: 7,
            uid: 501,
            gid: 20,
            start_time_us: 123_456,
            executable_dev: metadata.dev(),
            executable_ino: metadata.ino(),
            executable_mode: 0o100755,
            executable_owner_uid: 501,
            executable_size: metadata.len(),
            executable_path: path_bytes.as_ptr(),
            executable_path_len: path_bytes.len(),
            ..RawProcessFacts::default()
        };
        let launch = raw.launch_facts();
        assert!(launch.has_prohibited_code_loading());
        assert_eq!(launch.present_vars(), vec!["DYLD_INSERT_LIBRARIES"]);
        let target = raw.target.to_facts().unwrap();
        assert_eq!(target.key.pid, 4242);
        assert_eq!(target.executable.path, target_exe);
        let clean = RawExecEvent::default().launch_facts();
        assert!(!clean.has_prohibited_code_loading());
    }

    fn raw_process_facts(
        pid: i32,
        pidversion: i32,
        start_time_us: u64,
        path: &'static [u8],
        team: &'static [u8],
        signing: &'static [u8],
    ) -> RawProcessFacts {
        RawProcessFacts {
            pid,
            uid: 501,
            gid: 20,
            pidversion,
            parent_pid: 0,
            parent_pidversion: 0,
            parent_identity_available: false,
            responsible_pid: 0,
            responsible_pidversion: 0,
            responsible_identity_available: false,
            start_time_us,
            executable_dev: 9,
            executable_ino: 10,
            executable_mode: 0o100755,
            executable_owner_uid: 0,
            executable_size: 100,
            executable_mtime_ns: 1,
            executable_ctime_ns: 1,
            executable_path: path.as_ptr(),
            executable_path_len: path.len(),
            executable_path_truncated: false,
            code_signing_flags: 1,
            code_signing_valid: true,
            platform_binary: false,
            team_id: team.as_ptr(),
            team_id_len: team.len(),
            signing_id: signing.as_ptr(),
            signing_id_len: signing.len(),
            cdhash: [1; 20],
        }
    }

    fn notify_context(
        config: EndpointSecurityConfig,
        enabled: bool,
    ) -> (
        CallbackContext,
        mpsc::Receiver<ShieldAuditEvent>,
        std::sync::mpsc::Receiver<MacAuthorizationEvent>,
    ) {
        let (_, scheduler) = crate::pending::DeadlineScheduler::start().unwrap();
        let (sender, open_receiver) = mpsc::sync_channel(8);
        let (shield_sender, shield_receiver) = mpsc::sync_channel(8);
        let context = CallbackContext {
            config,
            process_shield_enabled: Arc::new(AtomicBool::new(enabled)),
            sender,
            scheduler,
            registry: Arc::new(Mutex::new(Vec::new())),
            process_graph: Arc::new(Mutex::new(MacProcessGraph::default())),
            shield: Arc::new(Mutex::new(MacProcessShield::new())),
            shield_sender,
            health: Arc::new(HealthTracker::active("test")),
            sequences: Mutex::new(SequenceTracker::default()),
        };
        (context, shield_receiver, open_receiver)
    }

    #[test]
    fn task_notify_disabled_flag_skips_signals_and_compromise() {
        // MCH0: with Process Shield disabled, notify signals are ignored
        // entirely: no compromise transition, no audit handoff, even for a
        // pre-admitted shielded target and an unknown external requester.
        let (_temp, config, _cookies) = browser_namespace_fixture();
        let (context, shield_receiver, _open_receiver) = notify_context(config, false);
        let target = fixture_process("fixture.browser");
        context
            .shield
            .lock()
            .unwrap()
            .ensure_authority(&target)
            .unwrap();
        let raw = RawTaskEvent {
            deadline: 1_000,
            process: raw_process_facts(99, 7, 99_000, b"/usr/bin/python3", b"", b""),
            target: raw_process_facts(
                target.key.pid as i32,
                target.key.pidversion as i32,
                target.start_time_us,
                b"/Applications/Fixture.app/Contents/MacOS/Fixture",
                b"TEAM123456",
                b"fixture.browser",
            ),
        };
        context.handle_task_notify(13, &raw); // REMOTE_THREAD_CREATE
        assert_eq!(
            context
                .shield
                .lock()
                .unwrap()
                .integrity_of_pid(target.key.pid),
            ProcessIntegrity::Normal,
            "a disabled shield must never transition Compromised"
        );
        assert!(
            shield_receiver.try_recv().is_err(),
            "no shield audit handoff while Process Shield is disabled"
        );
    }

    #[test]
    fn task_notify_get_task_read_is_telemetry_when_enabled() {
        // MCH7 (live evidence): NOTIFY_GET_TASK_READ fired for /bin/ps against
        // a GuardComponent even though AUTH_GET_TASK_READ denied the same
        // requester (audit process_shield_compromised, signal=notify_get_task_read
        // requester_exe=/bin/ps). The read notify is therefore DETECTED
        // telemetry only: the exact target must stay Normal and the handoff
        // must be a TaskNotify event, never Compromised.
        let (_temp, config, _cookies) = browser_namespace_fixture();
        let (context, shield_receiver, _open_receiver) = notify_context(config, true);
        let target = fixture_process("fixture.browser");
        context
            .shield
            .lock()
            .unwrap()
            .ensure_authority(&target)
            .unwrap();
        let raw = RawTaskEvent {
            deadline: 1_000,
            process: raw_process_facts(99, 7, 99_000, b"/bin/ps", b"", b""),
            target: raw_process_facts(
                target.key.pid as i32,
                target.key.pidversion as i32,
                target.start_time_us,
                b"/Applications/Fixture.app/Contents/MacOS/Fixture",
                b"TEAM123456",
                b"fixture.browser",
            ),
        };
        context.handle_task_notify(11, &raw); // NOTIFY_GET_TASK_READ
        assert_eq!(
            context
                .shield
                .lock()
                .unwrap()
                .integrity_of_pid(target.key.pid),
            ProcessIntegrity::Normal,
            "GET_TASK_READ notify must not auto-compromise until validated"
        );
        // Telemetry handoff still recorded (DETECTED), not a Compromised event.
        let event = shield_receiver
            .recv_timeout(Duration::from_millis(100))
            .ok();
        assert!(
            matches!(event, Some(ShieldAuditEvent::TaskNotify { kind, .. }) if kind == TaskNotifyKind::GetTaskRead),
            "GET_TASK_READ notify must be recorded as TaskNotify telemetry"
        );
    }

    #[test]
    fn task_notify_cs_invalidated_is_telemetry_when_enabled() {
        // MCH7: CS_INVALIDATED automatic-compromise semantics are UNVALIDATED;
        // even with Process Shield enabled, the signal is DETECTED telemetry
        // and the exact target stays Normal.
        let (_temp, config, _cookies) = browser_namespace_fixture();
        let (context, shield_receiver, _open_receiver) = notify_context(config, true);
        let target = fixture_process("fixture.browser");
        context
            .shield
            .lock()
            .unwrap()
            .ensure_authority(&target)
            .unwrap();
        let raw = RawTaskEvent {
            deadline: 1_000,
            process: raw_process_facts(99, 7, 99_000, b"/usr/bin/python3", b"", b""),
            target: raw_process_facts(
                target.key.pid as i32,
                target.key.pidversion as i32,
                target.start_time_us,
                b"/Applications/Fixture.app/Contents/MacOS/Fixture",
                b"TEAM123456",
                b"fixture.browser",
            ),
        };
        context.handle_task_notify(14, &raw); // NOTIFY_CS_INVALIDATED
        assert_eq!(
            context
                .shield
                .lock()
                .unwrap()
                .integrity_of_pid(target.key.pid),
            ProcessIntegrity::Normal,
            "CS_INVALIDATED must not auto-compromise until validated"
        );
        // Telemetry handoff still recorded (DETECTED), not a Compromised event.
        let event = shield_receiver
            .recv_timeout(Duration::from_millis(100))
            .ok();
        assert!(
            matches!(event, Some(ShieldAuditEvent::TaskNotify { kind, .. }) if kind == TaskNotifyKind::CsInvalidated),
            "CS_INVALIDATED must be recorded as TaskNotify telemetry"
        );
    }

    #[test]
    fn task_notify_remote_thread_is_contextual_per_requester() {
        // MCH7: REMOTE_THREAD_CREATE is strong only for an unknown external
        // requester. A browser-internal requester (exact enrolled browser
        // executable) stays telemetry.
        let (_temp, config, _cookies) = browser_namespace_fixture();
        let (context, shield_receiver, _open_receiver) = notify_context(config, true);
        let target = fixture_process("fixture.browser");
        context
            .shield
            .lock()
            .unwrap()
            .ensure_authority(&target)
            .unwrap();
        let external = RawTaskEvent {
            deadline: 1_000,
            process: raw_process_facts(99, 7, 99_000, b"/usr/bin/python3", b"", b""),
            target: raw_process_facts(
                target.key.pid as i32,
                target.key.pidversion as i32,
                target.start_time_us,
                b"/Applications/Fixture.app/Contents/MacOS/Fixture",
                b"TEAM123456",
                b"fixture.browser",
            ),
        };
        context.handle_task_notify(13, &external);
        assert_eq!(
            context
                .shield
                .lock()
                .unwrap()
                .integrity_of_pid(target.key.pid),
            ProcessIntegrity::Compromised,
            "unknown external remote-thread creation must be strong"
        );
        let event = shield_receiver
            .recv_timeout(Duration::from_millis(100))
            .ok();
        assert!(
            matches!(event, Some(ShieldAuditEvent::Compromised { signal, .. }) if signal == TaskNotifyKind::RemoteThreadCreate),
            "strong signal must emit the Compromised handoff"
        );

        // MCH3: a fresh session root and a SAME-SESSION helper requester stay
        // telemetry (verified browser-internal relationship).
        let main = {
            let mut facts = fixture_process("fixture.browser");
            facts.key.pid = 43;
            facts.key.pidversion = 8;
            facts.start_time_us = 124_000;
            facts
        };
        let root = context
            .shield
            .lock()
            .unwrap()
            .admit_browser(
                main.clone(),
                Some(crate::browser_trust::BrowserExecutableRole::Main),
                None,
                false,
            )
            .unwrap();
        let _ = root.session_id().unwrap();
        let helper = {
            let mut facts = fixture_process("fixture.browser");
            facts.key.pid = 44;
            facts.key.pidversion = 9;
            facts.start_time_us = 125_000;
            facts
        };
        context
            .shield
            .lock()
            .unwrap()
            .admit_browser(
                helper.clone(),
                Some(crate::browser_trust::BrowserExecutableRole::Helper),
                Some(main.key),
                true,
            )
            .unwrap();
        let internal = RawTaskEvent {
            deadline: 1_000,
            process: raw_process_facts(
                helper.key.pid as i32,
                helper.key.pidversion as i32,
                helper.start_time_us,
                b"/Applications/Fixture.app/Contents/MacOS/Fixture",
                b"TEAM123456",
                b"fixture.browser",
            ),
            target: raw_process_facts(
                main.key.pid as i32,
                main.key.pidversion as i32,
                main.start_time_us,
                b"/Applications/Fixture.app/Contents/MacOS/Fixture",
                b"TEAM123456",
                b"fixture.browser",
            ),
        };
        context.handle_task_notify(13, &internal);
        assert_eq!(
            context
                .shield
                .lock()
                .unwrap()
                .integrity_of_pid(main.key.pid),
            ProcessIntegrity::Normal,
            "same-session remote-thread creation must stay telemetry"
        );
        let event = shield_receiver
            .recv_timeout(Duration::from_millis(100))
            .ok();
        assert!(
            matches!(event, Some(ShieldAuditEvent::TaskNotify { kind, .. }) if kind == TaskNotifyKind::RemoteThreadCreate),
            "same-session remote-thread creation must be TaskNotify telemetry"
        );

        // MCH3/11 laundering: a genuine signed Helper launched by an attacker
        // (parent NOT a session member, NOT a browser executable) is REJECTED
        // from the session; its remote-thread creation in the real browser is
        // a strong signal despite the genuine signature.
        let laundered = {
            let mut facts = fixture_process("fixture.browser");
            facts.key.pid = 45;
            facts.key.pidversion = 10;
            facts.start_time_us = 126_000;
            facts
        };
        let laundering = context
            .shield
            .lock()
            .unwrap()
            .admit_browser(
                laundered.clone(),
                Some(crate::browser_trust::BrowserExecutableRole::Helper),
                Some(AuditProcessKey {
                    pid: 99,
                    pidversion: 1,
                }),
                false,
            )
            .unwrap();
        assert!(
            laundering.is_external(),
            "attacker-launched signed helper must be rejected externally"
        );
        let laundered_event = RawTaskEvent {
            deadline: 1_000,
            process: raw_process_facts(
                laundered.key.pid as i32,
                laundered.key.pidversion as i32,
                laundered.start_time_us,
                b"/Applications/Fixture.app/Contents/MacOS/Fixture",
                b"TEAM123456",
                b"fixture.browser",
            ),
            target: raw_process_facts(
                main.key.pid as i32,
                main.key.pidversion as i32,
                main.start_time_us,
                b"/Applications/Fixture.app/Contents/MacOS/Fixture",
                b"TEAM123456",
                b"fixture.browser",
            ),
        };
        context.handle_task_notify(13, &laundered_event);
        assert_eq!(
            context
                .shield
                .lock()
                .unwrap()
                .integrity_of_pid(main.key.pid),
            ProcessIntegrity::Compromised,
            "laundered signed helper must be treated as an external requester"
        );
    }

    #[test]
    fn shield_eligible_resolves_synthetic_and_unrelated_execs() {
        let temp = tempfile::tempdir().unwrap();
        let protected = temp.path().join("protected");
        std::fs::write(&protected, b"synthetic protected").unwrap();
        let target_exe = temp.path().join("shield-target");
        std::fs::write(&target_exe, b"synthetic shield target").unwrap();
        let target_exe = std::fs::canonicalize(&target_exe).unwrap();
        let other_exe = temp.path().join("unrelated");
        std::fs::write(&other_exe, b"synthetic unrelated").unwrap();
        let other_exe = std::fs::canonicalize(&other_exe).unwrap();
        let config =
            EndpointSecurityConfig::synthetic_with_shield([protected], [target_exe.clone()])
                .unwrap();
        let mut eligible = fixture_process("fixture.browser");
        eligible.executable.path = target_exe;
        let mut unrelated = fixture_process("fixture.browser");
        unrelated.executable.path = other_exe;
        assert_eq!(
            config.shield_eligible(&eligible, 501),
            Some(ShieldReasonKind::SyntheticTarget)
        );
        assert_eq!(config.shield_eligible(&unrelated, 501), None);
    }

    #[test]
    fn synthetic_target_admits_real_shield_entry_and_task_protection() {
        // P0 review round 4: a synthetic shield target must get a genuine
        // task-protected shield entry at AUTH_EXEC. Routing it through the
        // Browser/role model (role=None) used to create NO entry and NO task
        // protection, silently hollowing out the synthetic adversarial
        // harness.
        use crate::process_shield::MacProcessShield;

        let temp = tempfile::tempdir().unwrap();
        let protected = temp.path().join("protected");
        std::fs::write(&protected, b"synthetic protected").unwrap();
        let target_exe = temp.path().join("shield-target");
        std::fs::write(&target_exe, b"synthetic shield target").unwrap();
        let target_exe = std::fs::canonicalize(&target_exe).unwrap();
        let config =
            EndpointSecurityConfig::synthetic_with_shield([protected], [target_exe.clone()])
                .unwrap();
        let mut facts = fixture_process("fixture.browser");
        facts.executable.path = target_exe;
        let mut shield = MacProcessShield::new();
        let reason = config
            .shield_eligible(&facts, 501)
            .expect("synthetic target must be shield-eligible");
        assert_eq!(reason, ShieldReasonKind::SyntheticTarget);
        // The exec path admits it into the shield (admit(), not admit_browser).
        shield.admit(facts.clone(), reason).unwrap();
        assert!(
            shield.is_task_protected(&facts),
            "synthetic target must be genuinely task-protected"
        );
        // Task capability requests against it are evaluated (deny for an
        // unknown requester), which is what the harness asserts via the
        // probe + Guard task-deny evidence channel.
        let requester = fixture_process("fixture.attacker");
        assert!(!crate::process_shield::task_access_allowlist(
            &requester,
            &facts,
            crate::process_shield::TaskAccessKind::Read,
        ));
    }

    #[test]
    fn task_target_truncation_only_fails_closed_when_shield_eligible() {
        use std::os::unix::ffi::OsStrExt;

        let temp = tempfile::tempdir().unwrap();
        let protected = temp.path().join("protected");
        std::fs::write(&protected, b"synthetic protected").unwrap();
        let target_exe = temp.path().join("shield-target");
        std::fs::write(&target_exe, b"synthetic shield target").unwrap();
        let target_exe = std::fs::canonicalize(&target_exe).unwrap();
        let unrelated = temp.path().join("python3");
        std::fs::write(&unrelated, b"synthetic unrelated").unwrap();
        let unrelated = std::fs::canonicalize(&unrelated).unwrap();
        let config =
            EndpointSecurityConfig::synthetic_with_shield([protected], [target_exe.clone()])
                .unwrap();
        let target_bytes = target_exe.as_os_str().as_bytes();
        let unrelated_bytes = unrelated.as_os_str().as_bytes();
        let truncated = |path_bytes: &[u8]| RawProcessFacts {
            executable_path: path_bytes.as_ptr(),
            executable_path_len: path_bytes.len(),
            executable_path_truncated: true,
            ..RawProcessFacts::default()
        };
        assert!(config.shield_eligible_raw(&truncated(target_bytes)));
        assert!(!config.shield_eligible_raw(&truncated(unrelated_bytes)));
    }

    #[test]
    fn shield_eligible_recognizes_guard_components() {
        let temp = tempfile::tempdir().unwrap();
        let guard_es = temp.path().join("guard-es");
        std::fs::write(&guard_es, b"synthetic guard-es").unwrap();
        let guard_es = std::fs::canonicalize(&guard_es).unwrap();
        let bundle = temp.path().join("Browser.app");
        let browser = bundle.join("Contents/MacOS/browser");
        std::fs::create_dir_all(browser.parent().unwrap()).unwrap();
        std::fs::write(&browser, b"synthetic browser").unwrap();
        let bundle = std::fs::canonicalize(&bundle).unwrap();
        let browser = std::fs::canonicalize(&browser).unwrap();
        let enrollment = MacBrowserEnrollment {
            browser_id: BrowserId("chrome".into()),
            family: BrowserFamily::Chromium,
            profile_root: temp.path().join("profile"),
            owner_uid: 501,
            app_bundle: Some(bundle),
            executables: vec![MacExecutableEnrollment::Signed {
                role: BrowserExecutableRole::Main,
                path: browser.clone(),
                bundle_suffix: None,
                team_id: "TEAM123456".into(),
                signing_id: "fixture.browser".into(),
            }],
        };
        let trust = MacBrowserTrustStore::load_and_revalidate(vec![enrollment]).unwrap();
        let config = EndpointSecurityConfig::browser_with_guard_components(
            Arc::new(MacProtectedResources::new(true, Default::default())),
            Arc::new(RwLock::new(trust)),
            [guard_es.clone()],
        );
        let mut guard_process = fixture_process("fixture.guard");
        guard_process.executable.path = guard_es;
        let mut browser_process = fixture_process("fixture.browser");
        browser_process.executable.path = browser;
        assert_eq!(
            config.shield_eligible(&guard_process, 501),
            Some(ShieldReasonKind::GuardComponent)
        );
        assert_eq!(
            config.shield_eligible(&browser_process, 501),
            Some(ShieldReasonKind::Browser)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn unprotected_open_is_scoped_before_invalid_process_identity() {
        use std::os::unix::ffi::OsStrExt;

        let temp = tempfile::tempdir().unwrap();
        let protected = temp.path().join("protected fixture with spaces.txt");
        let ordinary = temp.path().join("ordinary file with spaces.txt");
        std::fs::write(&protected, b"synthetic protected bytes").unwrap();
        std::fs::write(&ordinary, b"ordinary bytes").unwrap();
        let config = EndpointSecurityConfig::synthetic_exact_paths([protected.clone()]).unwrap();
        let ordinary_metadata = std::fs::metadata(&ordinary).unwrap();
        let ordinary_bytes = ordinary.as_os_str().as_bytes();
        let raw = RawAuthOpenEvent {
            requested_flags: ES_FFLAG_READ,
            deadline: 0,
            target_dev: ordinary_metadata.dev(),
            target_ino: ordinary_metadata.ino(),
            target_path: ordinary_bytes.as_ptr(),
            target_path_len: ordinary_bytes.len(),
            target_path_truncated: false,
            // An invalid process proves that the unprotected scope gate does
            // not parse or trust process identity before allowing the open.
            process: RawProcessFacts::default(),
        };

        assert!(raw.process.to_facts().is_err());
        assert!(matches!(
            scope_open(&config, &raw).unwrap(),
            ScopedOpen::Unprotected {
                requested_fflags: ES_FFLAG_READ
            }
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn empty_policy_allows_open_and_namespace_before_target_normalization() {
        let config = EndpointSecurityConfig::browser(
            Arc::new(MacProtectedResources::new(true, Default::default())),
            Arc::new(RwLock::new(
                MacBrowserTrustStore::load_and_revalidate(vec![]).unwrap(),
            )),
        );
        let raw_open = RawAuthOpenEvent {
            requested_flags: ES_FFLAG_READ,
            deadline: 0,
            target_dev: 0,
            target_ino: 0,
            target_path: std::ptr::null(),
            target_path_len: 0,
            target_path_truncated: true,
            process: RawProcessFacts::default(),
        };
        assert!(matches!(
            scope_open(&config, &raw_open).unwrap(),
            ScopedOpen::Unprotected {
                requested_fflags: ES_FFLAG_READ
            }
        ));
        assert!(matches!(
            scope_namespace(&config, &RawNamespaceEvent::default()).unwrap(),
            ScopedNamespace::Unprotected
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn protected_open_with_spaces_enters_the_narrow_fail_closed_scope() {
        use std::os::unix::ffi::OsStrExt;

        let temp = tempfile::tempdir().unwrap();
        let protected = temp.path().join("protected fixture with spaces.txt");
        std::fs::write(&protected, b"synthetic protected bytes").unwrap();
        let config = EndpointSecurityConfig::synthetic_exact_paths([protected.clone()]).unwrap();
        let protected = std::fs::canonicalize(protected).unwrap();
        let metadata = std::fs::metadata(&protected).unwrap();
        let path_bytes = protected.as_os_str().as_bytes();
        let raw = RawAuthOpenEvent {
            requested_flags: ES_FFLAG_READ,
            deadline: 0,
            target_dev: metadata.dev(),
            target_ino: metadata.ino(),
            target_path: path_bytes.as_ptr(),
            target_path_len: path_bytes.len(),
            target_path_truncated: false,
            process: RawProcessFacts::default(),
        };

        match scope_open(&config, &raw).unwrap() {
            ScopedOpen::Protected { target, resource } => {
                assert_eq!(target.target, protected);
                assert_eq!(resource.path, protected);
            }
            ScopedOpen::Unprotected { .. } => panic!("protected path was scoped as ordinary"),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn truncated_paths_only_fail_closed_after_a_protected_match() {
        use std::os::unix::ffi::OsStrExt;

        let temp = tempfile::tempdir().unwrap();
        let protected = temp.path().join("protected fixture.txt");
        let ordinary = temp.path().join("ordinary fixture.txt");
        std::fs::write(&protected, b"synthetic protected bytes").unwrap();
        std::fs::write(&ordinary, b"ordinary bytes").unwrap();
        let config = EndpointSecurityConfig::synthetic_exact_paths([protected.clone()]).unwrap();
        let protected = std::fs::canonicalize(protected).unwrap();
        let ordinary = std::fs::canonicalize(ordinary).unwrap();

        let raw_for = |path: &std::path::Path| {
            let metadata = std::fs::metadata(path).unwrap();
            let path_bytes = path.as_os_str().as_bytes();
            RawAuthOpenEvent {
                requested_flags: ES_FFLAG_READ,
                deadline: 0,
                target_dev: metadata.dev(),
                target_ino: metadata.ino(),
                target_path: path_bytes.as_ptr(),
                target_path_len: path_bytes.len(),
                target_path_truncated: true,
                process: RawProcessFacts::default(),
            }
        };

        assert!(matches!(
            scope_open(&config, &raw_for(&ordinary)).unwrap(),
            ScopedOpen::Unprotected { .. }
        ));
        assert!(scope_open(&config, &raw_for(&protected)).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn truncated_namespace_paths_only_deny_after_a_protected_match() {
        use std::os::unix::ffi::OsStrExt;

        let temp = tempfile::tempdir().unwrap();
        let protected = temp.path().join("protected namespace fixture.txt");
        let ordinary = temp.path().join("ordinary namespace fixture.txt");
        std::fs::write(&protected, b"synthetic protected bytes").unwrap();
        std::fs::write(&ordinary, b"ordinary bytes").unwrap();
        let config = EndpointSecurityConfig::synthetic_exact_paths([protected.clone()]).unwrap();
        let protected = std::fs::canonicalize(protected).unwrap();
        let ordinary = std::fs::canonicalize(ordinary).unwrap();
        let directory = std::fs::canonicalize(temp.path()).unwrap();
        let directory_bytes = directory.as_os_str().as_bytes();
        let destination_name = b"destination fixture.txt";

        let raw_for = |source: &std::path::Path| {
            let metadata = std::fs::metadata(source).unwrap();
            let source_bytes = source.as_os_str().as_bytes();
            RawNamespaceEvent {
                operation: 2,
                deadline: 0,
                source_dev: metadata.dev(),
                source_ino: metadata.ino(),
                source_path: source_bytes.as_ptr(),
                source_path_len: source_bytes.len(),
                source_path_truncated: true,
                destination_existing: false,
                destination_dev: 0,
                destination_ino: 0,
                destination_dir_path: directory_bytes.as_ptr(),
                destination_dir_path_len: directory_bytes.len(),
                destination_dir_path_truncated: false,
                destination_name: destination_name.as_ptr(),
                destination_name_len: destination_name.len(),
                destination_existing_path: std::ptr::null(),
                destination_existing_path_len: 0,
                destination_existing_path_truncated: false,
                process: RawProcessFacts::default(),
            }
        };

        assert!(matches!(
            scope_namespace(&config, &raw_for(&ordinary)).unwrap(),
            ScopedNamespace::Unprotected
        ));
        assert!(scope_namespace(&config, &raw_for(&protected)).is_err());
    }

    #[test]
    fn namespace_scope_gate_allows_unrelated_paths_before_identity_checks() {
        let temp = tempfile::tempdir().unwrap();
        let protected = temp.path().join("protected fixture with spaces.txt");
        std::fs::write(&protected, b"synthetic protected bytes").unwrap();
        let config = EndpointSecurityConfig::synthetic_exact_paths([protected.clone()]).unwrap();
        let protected = std::fs::canonicalize(protected).unwrap();
        let ordinary = NamespaceTargetFacts {
            operation: NamespaceOperation::Rename,
            source: temp.path().join("ordinary source with spaces.txt"),
            source_identity: FileIdentity { dev: 9, ino: 10 },
            destination: temp.path().join("ordinary destination with spaces.txt"),
            destination_identity: None,
        };
        assert!(!config.namespace_requires_authorization(&ordinary));

        let protected_rename = NamespaceTargetFacts {
            source: protected,
            ..ordinary
        };
        assert!(config.namespace_requires_authorization(&protected_rename));
    }

    #[test]
    fn client_creation_errors_have_actionable_diagnostics() {
        assert!(ClientCreateError::NotEntitled
            .to_string()
            .contains("entitlement"));
        assert!(ClientCreateError::NotPermitted
            .to_string()
            .contains("Full Disk Access"));
        assert!(ClientCreateError::TooManyClients
            .to_string()
            .contains("limit"));
    }

    #[test]
    fn only_exact_own_browser_can_mutate_inside_same_profile_namespace() {
        let (temp, config, cookies) = browser_namespace_fixture();
        let metadata = std::fs::metadata(&cookies).unwrap();
        let inside = cookies.with_extension("replacement");
        let base = NamespaceFacts {
            operation: NamespaceOperation::Link,
            process: fixture_process("fixture.browser"),
            source: cookies.clone(),
            source_identity: FileIdentity {
                dev: metadata.dev(),
                ino: metadata.ino(),
            },
            destination: inside,
            destination_identity: None,
        };
        assert!(config.authorize_namespace(&base));

        let mut outside = base.clone();
        outside.destination = temp.path().join("escaped-cookie-alias");
        assert!(!config.authorize_namespace(&outside));

        let mut wrong_client = base;
        wrong_client.process = fixture_process("wrong.client");
        assert!(!config.authorize_namespace(&wrong_client));
    }

    #[test]
    fn trusted_browser_atomic_replace_is_narrow_and_parent_rename_is_denied() {
        let (_temp, config, cookies) = browser_namespace_fixture();
        let replacement = cookies.with_extension("tmp");
        std::fs::write(&replacement, b"replacement synthetic cookies").unwrap();
        let replacement_metadata = std::fs::metadata(&replacement).unwrap();
        let destination_metadata = std::fs::metadata(&cookies).unwrap();
        let replace = NamespaceFacts {
            operation: NamespaceOperation::Rename,
            process: fixture_process("fixture.browser"),
            source: replacement,
            source_identity: FileIdentity {
                dev: replacement_metadata.dev(),
                ino: replacement_metadata.ino(),
            },
            destination: cookies.clone(),
            destination_identity: Some(FileIdentity {
                dev: destination_metadata.dev(),
                ino: destination_metadata.ino(),
            }),
        };
        assert!(config.authorize_namespace(&replace));

        let profile = cookies.parent().unwrap().parent().unwrap().to_path_buf();
        let profile_metadata = std::fs::metadata(&profile).unwrap();
        let parent_rename = NamespaceFacts {
            source: profile.clone(),
            source_identity: FileIdentity {
                dev: profile_metadata.dev(),
                ino: profile_metadata.ino(),
            },
            destination: profile.with_extension("moved"),
            destination_identity: None,
            ..replace
        };
        assert!(!config.authorize_namespace(&parent_rename));
    }

    #[test]
    fn namespace_mutation_of_ssh_key_is_denied_even_to_trusted_browser() {
        let temp = tempfile::tempdir().unwrap();
        let key = temp.path().join("id_ed25519");
        std::fs::write(&key, b"synthetic ephemeral key fixture").unwrap();
        let key = std::fs::canonicalize(key).unwrap();
        let index = crate::resource_index::MacResourceIndex::from_enrollments(
            &[],
            std::slice::from_ref(&key),
        )
        .unwrap();
        let config = EndpointSecurityConfig::browser(
            Arc::new(MacProtectedResources::new(true, index)),
            Arc::new(RwLock::new(
                MacBrowserTrustStore::load_and_revalidate(vec![]).unwrap(),
            )),
        );
        let metadata = std::fs::metadata(&key).unwrap();
        assert!(!config.authorize_namespace(&NamespaceFacts {
            operation: NamespaceOperation::Rename,
            process: fixture_process("fixture.browser"),
            source: key,
            source_identity: FileIdentity {
                dev: metadata.dev(),
                ino: metadata.ino(),
            },
            destination: temp.path().join("escaped-key"),
            destination_identity: None,
        }));
    }

    #[test]
    fn sequence_tracker_counts_per_type_and_global_drops() {
        let mut tracker = SequenceTracker::default();
        assert_eq!(tracker.observe(1, Some(10), Some(100)), (0, 0));
        assert_eq!(tracker.observe(1, Some(13), Some(104)), (2, 3));
        // Duplicate/out-of-order delivery is not misreported as a dropped event.
        assert_eq!(tracker.observe(1, Some(12), Some(103)), (0, 0));
    }

    #[test]
    fn concurrent_resource_replacement_keeps_complete_snapshots() {
        use guard_browser::ProtectedResourceRegistry;
        use guard_core::resource::{ProtectedResourceId, ProtectedResourceKind};

        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        std::fs::write(&first, b"first synthetic fixture").unwrap();
        std::fs::write(&second, b"second synthetic fixture").unwrap();
        let make_index = |path: &std::path::Path| {
            let mut registry = ProtectedResourceRegistry::new();
            registry.enroll_file(ProtectedResource {
                id: ProtectedResourceId(path.to_string_lossy().into_owned()),
                kind: ProtectedResourceKind::CookieStore,
                owner_uid: 501,
                browser: Some(BrowserId("chrome".into())),
                profile: Some(ProfileId("Default".into())),
                path: path.to_path_buf(),
            });
            crate::resource_index::MacResourceIndex::from_registry(&registry).unwrap()
        };
        let first_index = make_index(&first);
        let second_index = make_index(&second);
        let resources = Arc::new(MacProtectedResources::new(true, first_index.clone()));
        let writer_resources = Arc::clone(&resources);
        let writer = std::thread::spawn(move || {
            for turn in 0..200 {
                writer_resources
                    .replace(
                        true,
                        if turn % 2 == 0 {
                            first_index.clone()
                        } else {
                            second_index.clone()
                        },
                    )
                    .unwrap();
            }
        });
        for _ in 0..200 {
            let (files, trees) = resources.counts();
            assert_eq!((files, trees), (1, 0));
        }
        writer.join().unwrap();
    }
}
