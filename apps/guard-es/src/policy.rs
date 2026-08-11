#![cfg_attr(feature = "es-poc", allow(dead_code))]

use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use guard_audit::{AuditRecord, AuditStore};
use guard_core::lease::MigrationLeaseState;
use guard_core::policy::{AccessEvent, AccessOperation, Decision, DenyReason};
use guard_core::{ProcessIdentity, ProtectedResource};
use guard_platform::{PendingPermission, ProcessIdentityResolver};
use guard_runtime::{
    AuthorizationRuntime, MigrationEnqueueResult, MigrationPendingDetails, PendingMigrationStore,
    PendingTakeResult,
};
use platform_macos::browser_trust::{MacBrowserTrustStore, MacProcessIdentityResolver};
use platform_macos::config::MacBackendConfig;
use platform_macos::endpoint_security::{
    AuthOpenFacts, MacAuthorizationEvent, MacPendingPermission, MacProtectedResources,
    ES_FFLAG_READ, ES_FFLAG_WRITE,
};
use platform_macos::resource_index::MacResourceIndex;

pub const MIGRATION_LEASE_SECS: u64 = 10 * 60;

trait OpenPermission: Send {
    fn requested_fflags(&self) -> u32;
    fn allow_exact(self: Box<Self>) -> anyhow::Result<()>;
    fn allow_read_only(self: Box<Self>) -> anyhow::Result<()>;
    fn deny(self: Box<Self>) -> anyhow::Result<()>;
}

impl OpenPermission for MacPendingPermission {
    fn requested_fflags(&self) -> u32 {
        self.requested_fflags()
    }

    fn allow_exact(self: Box<Self>) -> anyhow::Result<()> {
        (*self).allow()
    }

    fn allow_read_only(self: Box<Self>) -> anyhow::Result<()> {
        Box::new((*self).into_read_only()).allow()
    }

    fn deny(self: Box<Self>) -> anyhow::Result<()> {
        (*self).deny()
    }
}

struct ReadOnlyPendingPermission(Box<dyn OpenPermission>);

impl PendingPermission for ReadOnlyPendingPermission {
    fn allow(self: Box<Self>) -> anyhow::Result<()> {
        self.0.allow_read_only()
    }

    fn deny(self: Box<Self>) -> anyhow::Result<()> {
        self.0.deny()
    }
}

struct BrowserOpenEvent {
    facts: AuthOpenFacts,
    resource: ProtectedResource,
    interactive_budget: Option<Duration>,
    permission: Box<dyn OpenPermission>,
}

impl From<MacAuthorizationEvent> for BrowserOpenEvent {
    fn from(event: MacAuthorizationEvent) -> Self {
        Self {
            facts: event.facts,
            resource: event.resource,
            interactive_budget: event.interactive_budget,
            permission: Box::new(event.permission),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PolicyStats {
    pub protected_events: u64,
    pub allowed: u64,
    pub denied: u64,
    pub classifier_failures: u64,
}

#[derive(Default)]
struct PolicyInner {
    runtime: AuthorizationRuntime,
    pending: PendingMigrationStore,
    stats: PolicyStats,
}

pub struct MacBrowserPolicy {
    inner: Mutex<PolicyInner>,
    resources: Arc<MacProtectedResources>,
    resolver: Arc<MacProcessIdentityResolver>,
    config: RwLock<Option<MacBackendConfig>>,
    audit: Arc<AuditStore>,
}

impl MacBrowserPolicy {
    pub fn new(
        resources: Arc<MacProtectedResources>,
        resolver: Arc<MacProcessIdentityResolver>,
        audit: Arc<AuditStore>,
    ) -> Self {
        Self {
            inner: Mutex::new(PolicyInner::default()),
            resources,
            resolver,
            config: RwLock::new(None),
            audit,
        }
    }

    pub fn apply_config(&self, config: MacBackendConfig) -> anyhow::Result<()> {
        config.validate()?;
        let index = MacResourceIndex::from_browser_enrollments(&config.browser_trust)?;
        let trust = MacBrowserTrustStore::load_and_revalidate(config.browser_trust.clone())?;
        self.resolver.replace_trust(trust)?;
        self.resources.replace(config.policy_enabled, index)?;
        *self
            .config
            .write()
            .map_err(|_| anyhow::anyhow!("macOS policy config lock is poisoned"))? = Some(config);
        Ok(())
    }

    pub fn config(&self) -> anyhow::Result<MacBackendConfig> {
        self.config
            .read()
            .map_err(|_| anyhow::anyhow!("macOS policy config lock is poisoned"))?
            .clone()
            .ok_or_else(|| anyhow::anyhow!("authoritative macOS configuration is not loaded"))
    }

    pub fn enabled(&self) -> bool {
        self.resources.enabled()
    }

    pub fn resource_counts(&self) -> (usize, usize) {
        self.resources.counts()
    }

    pub fn browser_count(&self) -> usize {
        self.config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map_or(0, |config| config.browser_trust.len())
    }

    pub fn browser_executable_count(&self) -> usize {
        self.config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map_or(0, |config| {
                config
                    .browser_trust
                    .iter()
                    .map(|browser| browser.executables.len())
                    .sum()
            })
    }

    pub fn resources_for_uid(&self, uid: u32) -> Vec<guard_ipc::ResourceInfo> {
        let (files, trees) = self.resources.metadata_snapshot();
        let mut result = files
            .into_iter()
            .filter(|resource| resource.owner_uid == uid)
            .map(|resource| guard_ipc::ResourceInfo {
                id: resource.id.0,
                kind: format!("{:?}", resource.kind),
                owner_uid: resource.owner_uid,
                browser: resource.browser.map(|browser| browser.0),
                profile: resource.profile.map(|profile| profile.0),
                path: resource.path.to_string_lossy().into_owned(),
                tree: false,
            })
            .collect::<Vec<_>>();
        result.extend(
            trees
                .into_iter()
                .filter(|tree| tree.owner_uid == uid)
                .map(|tree| guard_ipc::ResourceInfo {
                    id: tree.dir.to_string_lossy().into_owned(),
                    kind: format!("{:?}", tree.kind),
                    owner_uid: tree.owner_uid,
                    browser: Some(tree.browser.0),
                    profile: Some(tree.profile.0),
                    path: tree.dir.to_string_lossy().into_owned(),
                    tree: true,
                }),
        );
        result
    }

    pub fn browsers_for_uid(&self, uid: u32) -> Vec<guard_ipc::BrowserInfo> {
        self.config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .into_iter()
            .flat_map(|config| &config.browser_trust)
            .filter(|browser| browser.owner_uid == uid)
            .map(|browser| guard_ipc::BrowserInfo {
                id: browser.browser_id.0.clone(),
                family: format!("{:?}", browser.family).to_ascii_lowercase(),
                profile_root: browser.profile_root.to_string_lossy().into_owned(),
                owner_uid: browser.owner_uid,
                exe_paths: browser
                    .executables
                    .iter()
                    .map(|executable| executable.path().to_string_lossy().into_owned())
                    .collect(),
            })
            .collect()
    }

    pub fn stats(&self) -> PolicyStats {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .stats
    }

    pub fn audit_dropped(&self) -> u64 {
        self.audit.dropped()
    }

    pub fn handle(&self, event: MacAuthorizationEvent) {
        self.handle_at(event.into(), epoch_seconds());
    }

    fn handle_at(&self, event: BrowserOpenEvent, now: u64) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.stats.protected_events = inner.stats.protected_events.saturating_add(1);

        let process = match self
            .resolver
            .resolve(event.facts.process.key.pid, event.resource.owner_uid)
        {
            Ok(process) => process,
            Err(error) => {
                inner.stats.classifier_failures = inner.stats.classifier_failures.saturating_add(1);
                inner.stats.denied = inner.stats.denied.saturating_add(1);
                drop(inner);
                self.record(
                    "browser_access_denied",
                    &event.resource,
                    None,
                    Decision::Deny(DenyReason::UnknownProcess),
                    format!("process identity unavailable: {error}"),
                    now,
                );
                let _ = event.permission.deny();
                return;
            }
        };
        let operation = if event.permission.requested_fflags() & ES_FFLAG_WRITE != 0 {
            AccessOperation::Write
        } else {
            AccessOperation::Read
        };
        let access = AccessEvent {
            resource: event.resource.clone(),
            process: process.clone(),
            operation,
        };
        let decision = inner.runtime.evaluate(&access, now);
        match decision.clone() {
            Decision::Allow => {
                inner.stats.allowed = inner.stats.allowed.saturating_add(1);
                drop(inner);
                self.record_debug(
                    "browser_access_allowed",
                    &event.resource,
                    Some(&process),
                    decision,
                    "trusted browser own-profile access".into(),
                    now,
                );
                let _ = event.permission.allow_exact();
            }
            Decision::AllowByLease(_) => {
                inner.stats.allowed = inner.stats.allowed.saturating_add(1);
                drop(inner);
                self.record_debug(
                    "browser_migration_allowed_by_lease",
                    &event.resource,
                    Some(&process),
                    decision,
                    "read_only_guaranteed=true root-bound migration lease".into(),
                    now,
                );
                let _ = event.permission.allow_read_only();
            }
            Decision::Deny(reason) => {
                inner.stats.denied = inner.stats.denied.saturating_add(1);
                drop(inner);
                self.record(
                    "browser_access_denied",
                    &event.resource,
                    Some(&process),
                    Decision::Deny(reason),
                    reason.reason_code().into(),
                    now,
                );
                let _ = event.permission.deny();
            }
            Decision::RequireMigrationConfirmation(candidate) => {
                if event.permission.requested_fflags() & ES_FFLAG_READ == 0 {
                    inner.stats.denied = inner.stats.denied.saturating_add(1);
                    drop(inner);
                    self.record(
                        "browser_migration_blocked",
                        &event.resource,
                        Some(&process),
                        Decision::Deny(DenyReason::LeaseScopeMismatch),
                        "write-only migration request cannot receive a read-only grant".into(),
                        now,
                    );
                    let _ = event.permission.deny();
                    return;
                }
                let Some(budget) = event.interactive_budget else {
                    inner.stats.denied = inner.stats.denied.saturating_add(1);
                    drop(inner);
                    self.record(
                        "browser_migration_timed_out",
                        &event.resource,
                        Some(&process),
                        Decision::Deny(DenyReason::CrossBrowserWithoutLease),
                        "Endpoint Security deadline has no interactive budget".into(),
                        now,
                    );
                    let _ = event.permission.deny();
                    return;
                };
                let details = MigrationPendingDetails {
                    candidate,
                    resource: event.resource.clone(),
                    target_root: process.stable.clone(),
                    target: process.clone(),
                };
                let timeout_secs = budget.as_secs().max(1);
                let result = inner.pending.enqueue_with_timeout(
                    details,
                    Box::new(ReadOnlyPendingPermission(event.permission)),
                    now,
                    timeout_secs,
                );
                match result {
                    MigrationEnqueueResult::Created(_) | MigrationEnqueueResult::Joined => {
                        drop(inner);
                        self.record(
                            "browser_migration_confirmation_required",
                            &event.resource,
                            Some(&process),
                            decision,
                            format!("read_only_guaranteed=true prompt_budget_secs={timeout_secs}"),
                            now,
                        );
                    }
                    MigrationEnqueueResult::RecentlyApproved(details, permission) => {
                        drop(inner);
                        self.approve_recent(*details, permission, now);
                    }
                    MigrationEnqueueResult::DenySuppressed | MigrationEnqueueResult::DenyLimit => {
                        inner.stats.denied = inner.stats.denied.saturating_add(1);
                        drop(inner);
                        // The permission was consumed by `enqueue` and is
                        // dropped unresolved here, which denies fail closed.
                        self.record(
                            "browser_migration_blocked",
                            &event.resource,
                            Some(&process),
                            Decision::Deny(DenyReason::CrossBrowserWithoutLease),
                            "pending queue full or recently blocked".into(),
                            now,
                        );
                    }
                }
            }
            Decision::RequireSshKeyConfirmation => {
                inner.stats.denied = inner.stats.denied.saturating_add(1);
                drop(inner);
                let _ = event.permission.deny();
            }
        }
    }

    pub fn pending_for_uid(&self, uid: u32) -> Vec<guard_ipc::MigrationPendingInfo> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pending
            .list_for_uid(uid, false)
            .iter()
            .map(migration_info)
            .collect()
    }

    pub fn pending_item_for_uid(
        &self,
        id: &str,
        uid: u32,
    ) -> Option<guard_ipc::MigrationPendingInfo> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pending
            .get_for_uid(id, uid, false)
            .as_ref()
            .map(migration_info)
    }

    pub fn resolve_migration(
        &self,
        id: &str,
        uid: u32,
        allow: bool,
    ) -> anyhow::Result<guard_ipc::MigrationResolutionInfo> {
        let now = epoch_seconds();
        let request = {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match inner
                .pending
                .take_for_resolution_result(id, uid, false, now, !allow)
            {
                PendingTakeResult::Ready(request) => request,
                PendingTakeResult::TimedOut(request) => {
                    let details = request.details.clone();
                    request.resolve(false);
                    inner.stats.denied = inner.stats.denied.saturating_add(1);
                    drop(inner);
                    self.record(
                        "browser_migration_timed_out",
                        &details.resource,
                        Some(&details.target),
                        Decision::Deny(DenyReason::CrossBrowserWithoutLease),
                        "pending resolution arrived after expiry".into(),
                        now,
                    );
                    anyhow::bail!("timed_out")
                }
                result => anyhow::bail!(result.error_code().unwrap_or("pending_unavailable")),
            }
        };
        let details = request.details.clone();
        if !allow {
            request.resolve(false);
            self.inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .stats
                .denied += 1;
            self.record(
                "browser_migration_blocked",
                &details.resource,
                Some(&details.target),
                Decision::Deny(DenyReason::CrossBrowserWithoutLease),
                "explicit user block".into(),
                now,
            );
            return Ok(guard_ipc::MigrationResolutionInfo::Blocked);
        }

        let current = self
            .resolver
            .resolve(details.target.stable.pid, details.resource.owner_uid)?;
        let live = self.resolver.is_live_instance(&details.target_root)?;
        let (lease_id, siblings) = {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let (lease_id, _) = inner
                .runtime
                .approve_migration(&details, &current, live, now, MIGRATION_LEASE_SECS)
                .map_err(anyhow::Error::msg)?;
            inner.pending.record_recent_approval(&details, now);
            let siblings = inner.pending.take_recent_approval_siblings(&details);
            (lease_id, siblings)
        };
        if let Err(error) = request.try_resolve(true) {
            self.revoke_lease(lease_id);
            anyhow::bail!("retained AUTH_OPEN was no longer resolvable: {error}");
        }
        for sibling in siblings {
            self.approve_sibling(sibling, now);
        }
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .stats
            .allowed += 1;
        self.record(
            "browser_migration_allowed",
            &details.resource,
            Some(&current),
            Decision::AllowByLease(lease_id),
            "read_only_guaranteed=true root-bound lease".into(),
            now,
        );
        Ok(guard_ipc::MigrationResolutionInfo::Allowed)
    }

    pub fn maintenance(&self) {
        self.maintenance_at(epoch_seconds());
    }

    fn maintenance_at(&self, now: u64) {
        let expired = {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for lease in &mut inner.runtime.leases_mut().migration {
                if let MigrationLeaseState::Bound { root } = &lease.state {
                    if !self.resolver.is_live_instance(root).unwrap_or(false) {
                        lease.revoked = true;
                        lease.state = MigrationLeaseState::Dead;
                    }
                }
            }
            let expired = inner.pending.expire(now, self.resolver.as_ref());
            inner.stats.denied = inner
                .stats
                .denied
                .saturating_add(u64::try_from(expired.len()).unwrap_or(u64::MAX));
            expired
        };
        for request in expired {
            let details = request.details.clone();
            request.resolve(false);
            self.record(
                "browser_migration_timed_out",
                &details.resource,
                Some(&details.target),
                Decision::Deny(DenyReason::CrossBrowserWithoutLease),
                "prompt deadline or target process lifetime ended".into(),
                now,
            );
        }
    }

    pub fn lease_infos_for_uid(&self, uid: u32) -> Vec<guard_ipc::LeaseInfo> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .runtime
            .leases()
            .migration
            .iter()
            .filter(|lease| lease.uid == uid)
            .map(|lease| guard_ipc::LeaseInfo {
                id: lease.id.0.to_string(),
                kind: "browser_migration".into(),
                uid: lease.uid,
                source_browser: Some(lease.source_browser.0.clone()),
                source_profile: Some(lease.source_profile.0.clone()),
                target_browser: Some(lease.target_browser.0.clone()),
                resource: None,
                state: Some(
                    match lease.state {
                        MigrationLeaseState::Armed { .. } => "armed",
                        MigrationLeaseState::Bound { .. } => "bound",
                        MigrationLeaseState::Dead => "dead",
                    }
                    .into(),
                ),
                expires_at: lease.expires_at,
                revoked: lease.revoked,
                used: false,
            })
            .collect()
    }

    pub fn revoke_lease_by_id(&self, id: &str, uid: u32) -> bool {
        let Ok(id) = id.parse::<u64>() else {
            return false;
        };
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(lease) = inner
            .runtime
            .leases_mut()
            .migration
            .iter_mut()
            .find(|lease| lease.id.0 == id && lease.uid == uid)
        else {
            return false;
        };
        lease.revoked = true;
        lease.state = MigrationLeaseState::Dead;
        true
    }

    pub fn recent_events(
        &self,
        uid: u32,
        limit: u32,
        before_id: Option<i64>,
        after_id: Option<i64>,
    ) -> anyhow::Result<Vec<guard_ipc::EventInfo>> {
        self.audit.flush();
        self.audit
            .query_events_cursor(Some(uid), limit, before_id, after_id)?
            .iter()
            .map(event_info)
            .collect()
    }

    pub fn explain_event(&self, uid: u32, id: i64) -> anyhow::Result<Option<guard_ipc::EventInfo>> {
        self.audit.flush();
        self.audit
            .query_event(id)?
            .filter(|event| event.record.uid == uid)
            .as_ref()
            .map(event_info)
            .transpose()
    }

    fn approve_recent(
        &self,
        details: MigrationPendingDetails,
        permission: Box<dyn PendingPermission>,
        now: u64,
    ) {
        let current = self
            .resolver
            .resolve(details.target.stable.pid, details.resource.owner_uid);
        let live = self.resolver.is_live_instance(&details.target_root);
        let approved = current.and_then(|current| {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            inner
                .runtime
                .approve_migration(
                    &details,
                    &current,
                    live.unwrap_or(false),
                    now,
                    MIGRATION_LEASE_SECS,
                )
                .map_err(anyhow::Error::msg)
        });
        match approved {
            Ok((lease_id, _)) => {
                if permission.allow().is_ok() {
                    let mut inner = self
                        .inner
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    inner.stats.allowed = inner.stats.allowed.saturating_add(1);
                    drop(inner);
                    self.record(
                        "browser_migration_allowed",
                        &details.resource,
                        Some(&details.target),
                        Decision::AllowByLease(lease_id),
                        "read_only_guaranteed=true narrow importer grace; independently revalidated root".into(),
                        now,
                    );
                } else {
                    self.revoke_lease(lease_id);
                }
            }
            Err(_) => {
                let _ = permission.deny();
            }
        }
    }

    fn approve_sibling(&self, request: guard_runtime::PendingMigrationRequest, now: u64) {
        let details = request.details.clone();
        let current = self
            .resolver
            .resolve(details.target.stable.pid, details.resource.owner_uid);
        let live = self.resolver.is_live_instance(&details.target_root);
        let approved = current.and_then(|current| {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            inner
                .runtime
                .approve_migration(
                    &details,
                    &current,
                    live.unwrap_or(false),
                    now,
                    MIGRATION_LEASE_SECS,
                )
                .map_err(anyhow::Error::msg)
        });
        match approved {
            Ok((lease_id, _)) => {
                if request.try_resolve(true).is_ok() {
                    let mut inner = self
                        .inner
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    inner.stats.allowed = inner.stats.allowed.saturating_add(1);
                    drop(inner);
                    self.record(
                        "browser_migration_allowed",
                        &details.resource,
                        Some(&details.target),
                        Decision::AllowByLease(lease_id),
                        "read_only_guaranteed=true coalesced importer root independently revalidated".into(),
                        now,
                    );
                } else {
                    self.revoke_lease(lease_id);
                }
            }
            Err(_) => request.resolve(false),
        }
    }

    fn revoke_lease(&self, lease_id: guard_core::LeaseId) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(lease) = inner
            .runtime
            .leases_mut()
            .migration
            .iter_mut()
            .find(|lease| lease.id == lease_id)
        {
            lease.revoked = true;
            lease.state = MigrationLeaseState::Dead;
        }
    }

    fn record_debug(
        &self,
        event_code: &str,
        resource: &ProtectedResource,
        process: Option<&ProcessIdentity>,
        decision: Decision,
        diagnostic: String,
        now: u64,
    ) {
        if cfg!(debug_assertions) {
            self.record(event_code, resource, process, decision, diagnostic, now);
        }
    }

    fn record(
        &self,
        event_code: &str,
        resource: &ProtectedResource,
        process: Option<&ProcessIdentity>,
        decision: Decision,
        diagnostic: String,
        now: u64,
    ) {
        let deny_reason = match decision {
            Decision::Deny(reason) => Some(reason),
            _ => None,
        };
        let lease_id = match decision {
            Decision::AllowByLease(id) => Some(id.0),
            _ => None,
        };
        let parent = process.and_then(|process| process.ancestors.first());
        self.audit.record(AuditRecord {
            event_code: event_code.into(),
            ts_ms: now.saturating_mul(1000),
            uid: process.map_or(resource.owner_uid, |process| process.uid),
            pid: process.map_or(0, |process| process.stable.pid),
            start_time: process.map_or(0, |process| process.stable.start_time),
            decision,
            deny_reason,
            resource_kind: resource.kind,
            resource_browser: resource.browser.clone(),
            resource_profile: resource.profile.clone(),
            path: resource.path.to_string_lossy().into_owned(),
            exe: process
                .map(|process| process.stable.exe.to_string_lossy().into_owned())
                .unwrap_or_default(),
            exe_owner_uid: process.map_or(0, |process| process.exe_owner_uid),
            trust_tier: process
                .map_or(guard_core::TrustTier::Unknown, |process| process.trust_tier),
            process_browser: process.and_then(|process| process.browser.clone()),
            parent_pid: parent.map(|parent| parent.pid),
            parent_exe: parent.map(|parent| parent.exe.to_string_lossy().into_owned()),
            lease_id,
            backend_diag: diagnostic,
        });
    }
}

pub fn prepare_config(
    config: Option<&MacBackendConfig>,
) -> anyhow::Result<(MacResourceIndex, MacBrowserTrustStore, bool)> {
    match config {
        Some(config) => {
            config.validate()?;
            Ok((
                MacResourceIndex::from_browser_enrollments(&config.browser_trust)?,
                MacBrowserTrustStore::load_and_revalidate(config.browser_trust.clone())?,
                config.policy_enabled,
            ))
        }
        None => Ok((
            MacResourceIndex::default(),
            MacBrowserTrustStore::load_and_revalidate(Vec::new())?,
            false,
        )),
    }
}

fn migration_info(info: &guard_runtime::PendingMigrationInfo) -> guard_ipc::MigrationPendingInfo {
    guard_ipc::MigrationPendingInfo {
        id: info.id.clone(),
        uid: info.uid,
        source_browser: info.source_browser.clone(),
        source_profile: info.source_profile.clone(),
        target_browser: info.target_browser.clone(),
        target_exe: info.target_exe.clone(),
        target_pid: info.target_pid,
        target_start_time: info.target_start_time,
        requested_data: info.requested_data.clone(),
        created_at: info.created_at,
        expires_at: info.expires_at,
    }
}

fn event_info(event: &guard_audit::AuditEvent) -> anyhow::Result<guard_ipc::EventInfo> {
    let record = &event.record;
    Ok(guard_ipc::EventInfo {
        id: event.id,
        event_code: record.event_code.clone(),
        ts_ms: record.ts_ms,
        uid: record.uid,
        pid: record.pid,
        start_time: record.start_time,
        decision: format!("{:?}", record.decision),
        deny_reason: record.deny_reason.map(|reason| format!("{reason:?}")),
        reason_code: record
            .deny_reason
            .map(|reason| reason.reason_code().to_owned()),
        resource_kind: format!("{:?}", record.resource_kind),
        resource_kind_code: record.resource_kind.kind_code().to_owned(),
        resource_browser: record
            .resource_browser
            .as_ref()
            .map(|value| value.0.clone()),
        resource_profile: record.profile_clone(),
        path: record.path.clone(),
        exe: record.exe.clone(),
        exe_owner_uid: record.exe_owner_uid,
        trust_tier: format!("{:?}", record.trust_tier),
        process_browser: record.process_browser.as_ref().map(|value| value.0.clone()),
        parent_pid: record.parent_pid,
        parent_exe: record.parent_exe.clone(),
        lease_id: record.lease_id,
        backend_diag: record.backend_diag.clone(),
    })
}

trait AuditProfileClone {
    fn profile_clone(&self) -> Option<String>;
}

impl AuditProfileClone for AuditRecord {
    fn profile_clone(&self) -> Option<String> {
        self.resource_profile.as_ref().map(|value| value.0.clone())
    }
}

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::os::unix::fs::MetadataExt;
    use std::time::Instant;

    use guard_core::resource::{BrowserFamily, BrowserId};
    use guard_platform::config::{BrowserEnrollmentConfig, PolicyConfig};
    use platform_macos::browser_trust::{
        BrowserExecutableRole, MacBrowserEnrollment, MacExecutableEnrollment,
    };
    use platform_macos::identity::{
        AuditProcessKey, ExecutableSnapshot, MacCodeIdentity, MacProcessFacts, MacProcessGraph,
    };

    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Terminal {
        Pending,
        Flags(u32),
    }

    struct FakePermission {
        requested: u32,
        state: Arc<Mutex<Terminal>>,
    }

    impl Drop for FakePermission {
        fn drop(&mut self) {
            let mut state = self.state.lock().unwrap();
            if *state == Terminal::Pending {
                *state = Terminal::Flags(0);
            }
        }
    }

    impl OpenPermission for FakePermission {
        fn requested_fflags(&self) -> u32 {
            self.requested
        }

        fn allow_exact(self: Box<Self>) -> anyhow::Result<()> {
            *self.state.lock().unwrap() = Terminal::Flags(self.requested);
            Ok(())
        }

        fn allow_read_only(self: Box<Self>) -> anyhow::Result<()> {
            *self.state.lock().unwrap() = Terminal::Flags(self.requested & ES_FFLAG_READ);
            Ok(())
        }

        fn deny(self: Box<Self>) -> anyhow::Result<()> {
            *self.state.lock().unwrap() = Terminal::Flags(0);
            Ok(())
        }
    }

    struct Fixture {
        _root: tempfile::TempDir,
        graph: Arc<Mutex<MacProcessGraph>>,
        policy: MacBrowserPolicy,
        resources: HashMap<String, ProtectedResource>,
        executables: HashMap<String, std::path::PathBuf>,
        uid: u32,
    }

    impl Fixture {
        fn new() -> Self {
            // SAFETY: geteuid has no pointer arguments and reads only the test
            // process credential.
            let uid = unsafe { libc::geteuid() };
            let root = tempfile::tempdir().unwrap();
            let mut browsers = Vec::new();
            let mut common = Vec::new();
            let mut resources = HashMap::new();
            let mut executables = HashMap::new();
            for (id, team, signing) in [
                ("browser-a", "TEAM-A", "com.example.browser-a"),
                ("browser-b", "TEAM-B", "com.example.browser-b"),
            ] {
                let bundle = root.path().join(format!("{id}.app"));
                let executable = bundle.join(format!("Contents/MacOS/{id}"));
                std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
                std::fs::write(&executable, format!("synthetic executable {id}")).unwrap();
                let profile_root = root.path().join(format!("{id}-profile"));
                let profile = profile_root.join("Default");
                std::fs::create_dir_all(profile.join("Network")).unwrap();
                std::fs::write(profile.join("Preferences"), b"{}").unwrap();
                let cookies = profile.join("Network/Cookies");
                std::fs::write(&cookies, format!("synthetic cookies {id}")).unwrap();
                common.push(BrowserEnrollmentConfig {
                    id: id.into(),
                    family: BrowserFamily::Chromium,
                    profile_root: profile_root.clone(),
                    owner_uid: Some(uid),
                    exe_paths: vec![executable.clone()],
                });
                browsers.push(MacBrowserEnrollment {
                    browser_id: BrowserId(id.into()),
                    family: BrowserFamily::Chromium,
                    profile_root,
                    owner_uid: uid,
                    app_bundle: Some(bundle),
                    executables: vec![MacExecutableEnrollment::Signed {
                        role: BrowserExecutableRole::Main,
                        path: executable.clone(),
                        bundle_suffix: None,
                        team_id: team.into(),
                        signing_id: signing.into(),
                    }],
                });
                executables.insert(id.into(), executable);
                resources.insert(
                    id.into(),
                    ProtectedResource {
                        id: guard_core::ProtectedResourceId(cookies.to_string_lossy().into_owned()),
                        kind: guard_core::ProtectedResourceKind::CookieStore,
                        owner_uid: uid,
                        browser: Some(BrowserId(id.into())),
                        profile: Some(guard_core::ProfileId("Default".into())),
                        path: cookies,
                    },
                );
            }
            let config = MacBackendConfig {
                version: platform_macos::config::MAC_CONFIG_VERSION,
                policy_enabled: true,
                common_policy: PolicyConfig {
                    browsers: common,
                    enrolled_exes: Vec::new(),
                    ssh_keys: Vec::new(),
                },
                browser_trust: browsers,
            };
            let (index, trust, enabled) = prepare_config(Some(&config)).unwrap();
            let protected = Arc::new(MacProtectedResources::new(enabled, index));
            let graph = Arc::new(Mutex::new(MacProcessGraph::default()));
            let resolver = Arc::new(MacProcessIdentityResolver::new(Arc::clone(&graph), trust));
            let audit_path = root.path().join("audit.db");
            let policy = MacBrowserPolicy::new(
                protected,
                resolver,
                Arc::new(AuditStore::open(&audit_path).unwrap()),
            );
            policy.apply_config(config).unwrap();
            Self {
                _root: root,
                graph,
                policy,
                resources,
                executables,
                uid,
            }
        }

        fn facts(
            &self,
            browser: &str,
            pid: u32,
            parent: Option<AuditProcessKey>,
        ) -> MacProcessFacts {
            let path = self.executables.get(browser).unwrap();
            let metadata = std::fs::metadata(path).unwrap();
            let (team, signing) = match browser {
                "browser-a" => ("TEAM-A", "com.example.browser-a"),
                "browser-b" => ("TEAM-B", "com.example.browser-b"),
                _ => ("WRONG", "com.example.wrong"),
            };
            MacProcessFacts {
                key: AuditProcessKey {
                    pid,
                    pidversion: pid,
                },
                uid: self.uid,
                gid: 20,
                start_time_us: u64::from(pid) * 100,
                executable: ExecutableSnapshot {
                    path: path.clone(),
                    dev: metadata.dev(),
                    ino: metadata.ino(),
                    owner_uid: metadata.uid(),
                    mode: metadata.mode(),
                    size: metadata.size(),
                    mtime_ns: metadata.mtime() * 1_000_000_000 + metadata.mtime_nsec(),
                    ctime_ns: metadata.ctime() * 1_000_000_000 + metadata.ctime_nsec(),
                },
                code: MacCodeIdentity {
                    valid: true,
                    platform_binary: false,
                    flags: 0,
                    team_id: Some(team.into()),
                    signing_id: Some(signing.into()),
                    cdhash: [pid as u8; 20],
                },
                parent,
                responsible: None,
            }
        }

        fn event(
            &self,
            facts: MacProcessFacts,
            source: &str,
            requested: u32,
            budget: Option<Duration>,
        ) -> (BrowserOpenEvent, Arc<Mutex<Terminal>>) {
            let state = Arc::new(Mutex::new(Terminal::Pending));
            let resource = self.resources.get(source).unwrap().clone();
            let metadata = std::fs::metadata(&resource.path).unwrap();
            (
                BrowserOpenEvent {
                    facts: AuthOpenFacts {
                        requested_fflags: requested,
                        process: facts,
                        target: resource.path.clone(),
                        target_dev: metadata.dev(),
                        target_ino: metadata.ino(),
                    },
                    resource,
                    interactive_budget: budget,
                    permission: Box::new(FakePermission {
                        requested,
                        state: Arc::clone(&state),
                    }),
                },
                state,
            )
        }

        fn observe(&self, facts: MacProcessFacts) {
            self.graph
                .lock()
                .unwrap()
                .observe(facts, Instant::now())
                .unwrap();
        }
    }

    #[test]
    fn own_browser_allows_exact_flags_but_unknown_wrong_signer_and_cross_uid_deny() {
        let fixture = Fixture::new();
        let own = fixture.facts("browser-a", 10, None);
        fixture.observe(own.clone());
        let (event, state) = fixture.event(
            own,
            "browser-a",
            ES_FFLAG_READ | ES_FFLAG_WRITE,
            Some(Duration::from_secs(10)),
        );
        fixture.policy.handle_at(event, 100);
        assert_eq!(
            *state.lock().unwrap(),
            Terminal::Flags(ES_FFLAG_READ | ES_FFLAG_WRITE)
        );

        let mut wrong_signer = fixture.facts("browser-b", 11, None);
        wrong_signer.code.team_id = Some("WRONG".into());
        fixture.observe(wrong_signer.clone());
        let (event, state) = fixture.event(
            wrong_signer,
            "browser-a",
            ES_FFLAG_READ,
            Some(Duration::from_secs(10)),
        );
        fixture.policy.handle_at(event, 101);
        assert_eq!(*state.lock().unwrap(), Terminal::Flags(0));
        assert!(fixture.policy.pending_for_uid(fixture.uid).is_empty());

        let mut cross_uid = fixture.facts("browser-b", 12, None);
        cross_uid.uid = fixture.uid.saturating_add(1);
        fixture.observe(cross_uid.clone());
        let (event, state) = fixture.event(
            cross_uid,
            "browser-a",
            ES_FFLAG_READ,
            Some(Duration::from_secs(10)),
        );
        fixture.policy.handle_at(event, 102);
        assert_eq!(*state.lock().unwrap(), Terminal::Flags(0));
    }

    #[test]
    fn migration_is_read_only_root_bound_single_use_and_revoked_on_exit() {
        let fixture = Fixture::new();
        let importer = fixture.facts("browser-b", 20, None);
        fixture.observe(importer.clone());
        let (event, first) = fixture.event(
            importer.clone(),
            "browser-a",
            ES_FFLAG_READ | ES_FFLAG_WRITE,
            Some(Duration::from_secs(20)),
        );
        let now = epoch_seconds();
        fixture.policy.handle_at(event, now);
        let burst_sibling = fixture.facts("browser-b", 23, None);
        fixture.observe(burst_sibling.clone());
        let (event, burst_state) = fixture.event(
            burst_sibling,
            "browser-a",
            ES_FFLAG_READ | ES_FFLAG_WRITE,
            Some(Duration::from_secs(20)),
        );
        fixture.policy.handle_at(event, now);
        let pending = fixture.policy.pending_for_uid(fixture.uid);
        assert_eq!(pending.len(), 2);
        assert_eq!(*first.lock().unwrap(), Terminal::Pending);
        assert_eq!(*burst_state.lock().unwrap(), Terminal::Pending);
        assert_eq!(
            fixture
                .policy
                .resolve_migration(&pending[0].id, fixture.uid, true)
                .unwrap(),
            guard_ipc::MigrationResolutionInfo::Allowed
        );
        assert_eq!(*first.lock().unwrap(), Terminal::Flags(ES_FFLAG_READ));
        assert_eq!(*burst_state.lock().unwrap(), Terminal::Flags(ES_FFLAG_READ));
        assert!(fixture
            .policy
            .resolve_migration(&pending[0].id, fixture.uid, true)
            .is_err());

        let descendant = fixture.facts("browser-b", 21, Some(importer.key));
        fixture.observe(descendant.clone());
        let (event, descendant_state) = fixture.event(
            descendant,
            "browser-a",
            ES_FFLAG_READ | ES_FFLAG_WRITE,
            Some(Duration::from_secs(20)),
        );
        fixture.policy.handle_at(event, now + 1);
        assert_eq!(
            *descendant_state.lock().unwrap(),
            Terminal::Flags(ES_FFLAG_READ)
        );

        let unrelated = fixture.facts("browser-b", 22, None);
        fixture.observe(unrelated.clone());
        let (event, unrelated_state) = fixture.event(
            unrelated,
            "browser-a",
            ES_FFLAG_READ,
            Some(Duration::from_secs(20)),
        );
        fixture
            .policy
            .handle_at(event, now + guard_runtime::IMPORT_APPROVAL_GRACE_SECS + 1);
        assert_eq!(*unrelated_state.lock().unwrap(), Terminal::Flags(0));

        fixture.graph.lock().unwrap().remove_terminal(importer.key);
        fixture
            .policy
            .maintenance_at(now + guard_runtime::IMPORT_APPROVAL_GRACE_SECS + 2);
        assert!(fixture
            .policy
            .lease_infos_for_uid(fixture.uid)
            .iter()
            .any(|lease| lease.state.as_deref() == Some("dead") && lease.revoked));
        let events = fixture
            .policy
            .recent_events(fixture.uid, 100, None, None)
            .unwrap();
        assert!(events
            .iter()
            .any(|event| { event.event_code == "browser_migration_confirmation_required" }));
        assert!(events
            .iter()
            .any(|event| event.event_code == "browser_migration_allowed"));
        assert!(events
            .iter()
            .filter(|event| {
                matches!(
                    event.event_code.as_str(),
                    "browser_migration_confirmation_required"
                        | "browser_migration_allowed"
                        | "browser_migration_allowed_by_lease"
                )
            })
            .all(|event| event.backend_diag.contains("read_only_guaranteed=true")));
    }

    #[test]
    fn prompt_deadline_and_queue_limit_deny_fail_closed() {
        let fixture = Fixture::new();
        let now = 500;
        let importer = fixture.facts("browser-b", 30, None);
        fixture.observe(importer.clone());
        let (event, timed_out) = fixture.event(
            importer,
            "browser-a",
            ES_FFLAG_READ,
            Some(Duration::from_secs(2)),
        );
        fixture.policy.handle_at(event, now);
        fixture.policy.maintenance_at(now + 2);
        assert_eq!(*timed_out.lock().unwrap(), Terminal::Flags(0));

        let mut states = Vec::new();
        for pid in 40..=48 {
            let process = fixture.facts("browser-b", pid, None);
            fixture.observe(process.clone());
            let (event, state) = fixture.event(
                process,
                "browser-a",
                ES_FFLAG_READ,
                Some(Duration::from_secs(20)),
            );
            fixture.policy.handle_at(event, now + 10);
            states.push(state);
        }
        assert_eq!(fixture.policy.pending_for_uid(fixture.uid).len(), 8);
        assert_eq!(*states.last().unwrap().lock().unwrap(), Terminal::Flags(0));
    }

    #[test]
    fn no_interactive_budget_and_write_only_migration_never_prompt() {
        let fixture = Fixture::new();
        for (pid, flags, budget) in [
            (60, ES_FFLAG_READ, None),
            (61, ES_FFLAG_WRITE, Some(Duration::from_secs(20))),
        ] {
            let process = fixture.facts("browser-b", pid, None);
            fixture.observe(process.clone());
            let (event, state) = fixture.event(process, "browser-a", flags, budget);
            fixture.policy.handle_at(event, 700 + u64::from(pid));
            assert_eq!(*state.lock().unwrap(), Terminal::Flags(0));
        }
        assert!(fixture.policy.pending_for_uid(fixture.uid).is_empty());
        let events = fixture
            .policy
            .recent_events(fixture.uid, 100, None, None)
            .unwrap();
        assert!(events
            .iter()
            .any(|event| event.event_code == "browser_migration_timed_out"));
        assert!(events
            .iter()
            .any(|event| event.event_code == "browser_migration_blocked"));
        let json = serde_json::to_string(&events).unwrap();
        assert!(!json.contains("synthetic cookies"));
    }
}
