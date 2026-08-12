use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock, Weak};
use std::time::Duration;

use guard_core::resource::{
    BrowserId, ProfileId, ProtectedResource, ProtectedResourceId, ProtectedResourceKind,
};
use guard_platform::BackendHealth;

use crate::browser_trust::MacBrowserTrustStore;
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

#[derive(Debug, Clone)]
pub struct EndpointSecurityConfig {
    scope: ProtectionScope,
}

#[derive(Debug, Clone)]
enum ProtectionScope {
    Synthetic(HashSet<PathBuf>),
    Browser {
        resources: Arc<MacProtectedResources>,
        trust: Arc<RwLock<MacBrowserTrustStore>>,
    },
}

impl EndpointSecurityConfig {
    pub fn synthetic_exact_paths(paths: impl IntoIterator<Item = PathBuf>) -> anyhow::Result<Self> {
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
        Ok(Self {
            scope: ProtectionScope::Synthetic(protected_exact_paths),
        })
    }

    pub fn browser(
        resources: Arc<MacProtectedResources>,
        trust: Arc<RwLock<MacBrowserTrustStore>>,
    ) -> Self {
        Self {
            scope: ProtectionScope::Browser { resources, trust },
        }
    }

    fn has_protected_scope(&self) -> bool {
        match &self.scope {
            ProtectionScope::Synthetic(paths) => !paths.is_empty(),
            ProtectionScope::Browser { resources, .. } => resources.has_protected_scope(),
        }
    }

    fn classify(
        &self,
        facts: &AuthOpenTargetFacts,
        synthetic_owner_uid: u32,
    ) -> Option<ProtectedResource> {
        match &self.scope {
            ProtectionScope::Synthetic(paths) if paths.contains(&facts.target) => {
                Some(ProtectedResource {
                    id: ProtectedResourceId(facts.target.to_string_lossy().into_owned()),
                    kind: ProtectedResourceKind::CookieStore,
                    owner_uid: synthetic_owner_uid,
                    browser: Some(BrowserId("synthetic".into())),
                    profile: Some(ProfileId("fixture".into())),
                    path: facts.target.clone(),
                })
            }
            ProtectionScope::Synthetic(_) => None,
            ProtectionScope::Browser { resources, .. } => resources.classify(facts),
        }
    }

    fn authorize_namespace(&self, facts: &NamespaceFacts) -> bool {
        match &self.scope {
            ProtectionScope::Synthetic(paths) => {
                !paths.contains(&facts.source) && !paths.contains(&facts.destination)
            }
            ProtectionScope::Browser { resources, trust } => {
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
            ProtectionScope::Synthetic(paths) => {
                paths.contains(&facts.source) || paths.contains(&facts.destination)
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
        let registry = Arc::new(Mutex::new(Vec::new()));
        let process_graph = Arc::new(Mutex::new(MacProcessGraph::default()));
        let mut context = Box::new(CallbackContext {
            config,
            sender,
            scheduler: scheduler_handle,
            registry,
            process_graph,
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
        context
            .health
            .note("Endpoint Security AUTH_OPEN/AUTH_LINK/AUTH_RENAME and bounded process graph subscriptions are active");
        Ok(Self {
            scheduler,
            client: Some(client),
            context,
            receiver,
        })
    }

    pub fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<MacAuthorizationEvent, mpsc::RecvTimeoutError> {
        self.receiver.recv_timeout(timeout)
    }

    pub fn health(&self) -> BackendHealth {
        let snapshot = self.context.health.snapshot();
        let (alias_entries, alias_capacity, index_saturated) = match &self.context.config.scope {
            ProtectionScope::Browser { resources, .. } => resources.namespace_health(),
            ProtectionScope::Synthetic(_) => (0, 0, false),
        };
        let process_graph_degraded = self
            .context
            .process_graph
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_degraded();
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
        }
    }

    pub fn process_graph(&self) -> Arc<Mutex<MacProcessGraph>> {
        Arc::clone(&self.context.process_graph)
    }

    pub fn repair_if_needed(&self) -> anyhow::Result<bool> {
        match &self.context.config.scope {
            ProtectionScope::Browser { resources, .. } => resources.repair_if_needed(),
            ProtectionScope::Synthetic(_) => Ok(false),
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
    sender: mpsc::SyncSender<MacAuthorizationEvent>,
    scheduler: DeadlineSchedulerHandle,
    registry: Arc<Mutex<Vec<Weak<PendingInner>>>>,
    process_graph: Arc<Mutex<MacProcessGraph>>,
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
    per_kind: [Option<u64>; 7],
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
                graph.remove_terminal(process.key);
                Ok(())
            }
            _ => Err(anyhow::anyhow!("unknown process event kind {event_kind}")),
        };
        if let Err(error) = result {
            self.health
                .degrade(format!("process graph update failed: {error}"));
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
            sequence_callback,
            context.cast(),
        )
    }

    fn create_with_callback(
        callback: RawCallback,
        process_callback: RawProcessCallback,
        namespace_callback: RawNamespaceCallback,
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
            "es_subscribe(AUTH_OPEN/FORK/EXEC/EXIT) failed"
        );
        Ok(())
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
extern "C" {
    fn guard_es_client_create(
        client: *mut *mut std::ffi::c_void,
        callback: RawCallback,
        process_callback: RawProcessCallback,
        namespace_callback: RawNamespaceCallback,
        sequence_callback: RawSequenceCallback,
        context: *mut std::ffi::c_void,
    ) -> i32;
    fn guard_es_client_subscribe_required(client: *mut std::ffi::c_void) -> i32;
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
