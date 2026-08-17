#![cfg_attr(feature = "es-poc", allow(dead_code))]

use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use std::os::unix::fs::MetadataExt;

use guard_audit::{AuditRecord, AuditStore};
use guard_core::lease::MigrationLeaseState;
use guard_core::policy::{AccessEvent, AccessOperation, Decision, DenyReason};
use guard_core::{
    ProcessIdentity, ProcessStableId, ProtectedResource, ProtectedResourceKind, TrustTier,
};
use guard_platform::{PendingPermission, ProcessIdentityResolver};
use guard_runtime::{
    AuthorizationRuntime, MigrationEnqueueResult, MigrationPendingDetails, PendingMigrationStore,
    PendingSshReadStore, PendingTakeResult, SshEnqueueResult, SshPendingDetails,
};
use platform_macos::browser_trust::{MacBrowserTrustStore, MacProcessIdentityResolver};
use platform_macos::config::MacBackendConfig;
use platform_macos::endpoint_security::{
    AuthOpenFacts, MacAuthorizationEvent, MacPendingPermission, MacProtectedResources,
    ShieldAuditEvent, ES_FFLAG_READ, ES_FFLAG_WRITE,
};
use platform_macos::identity::MacProcessFacts;
use platform_macos::resource_index::MacResourceIndex;

pub const MIGRATION_LEASE_SECS: u64 = 10 * 60;
pub const SSH_READ_LEASE_SECS: u64 = 10;

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

struct ExactPendingPermission(Box<dyn OpenPermission>);

impl PendingPermission for ExactPendingPermission {
    fn allow(self: Box<Self>) -> anyhow::Result<()> {
        self.0.allow_exact()
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
    ssh_pending: PendingSshReadStore,
    stats: PolicyStats,
}

pub struct MacPolicy {
    inner: Mutex<PolicyInner>,
    resources: Arc<MacProtectedResources>,
    resolver: Arc<MacProcessIdentityResolver>,
    config: RwLock<Option<MacBackendConfig>>,
    audit: Arc<AuditStore>,
    /// MCH0: runtime Process Shield toggle shared with the ES backend and the
    /// identity resolver; apply_config flips it from the authoritative config.
    process_shield_enabled: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl MacPolicy {
    pub fn new(
        resources: Arc<MacProtectedResources>,
        resolver: Arc<MacProcessIdentityResolver>,
        audit: Arc<AuditStore>,
        process_shield_enabled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            inner: Mutex::new(PolicyInner::default()),
            resources,
            resolver,
            config: RwLock::new(None),
            audit,
            process_shield_enabled,
        }
    }

    pub fn apply_config(&self, config: MacBackendConfig) -> anyhow::Result<()> {
        let config = config.with_builtin_mac_allowlist();
        config.validate()?;
        let index = MacResourceIndex::from_enrollments(
            &config.browser_trust,
            &config.common_policy.ssh_keys,
        )?;
        let trust = MacBrowserTrustStore::load_and_revalidate(config.browser_trust.clone())?;
        self.resolver.replace_trust(trust)?;
        self.resources.replace(config.policy_enabled, index)?;
        // MCH0: the Process Shield toggle is applied atomically with the rest
        // of the policy; the ES backend and identity resolver read the same
        // flag.
        self.process_shield_enabled.store(
            config.process_shield_enabled,
            std::sync::atomic::Ordering::Release,
        );
        *self
            .config
            .write()
            .map_err(|_| anyhow::anyhow!("macOS policy config lock is poisoned"))? = Some(config);
        Ok(())
    }

    pub fn config(&self) -> anyhow::Result<MacBackendConfig> {
        self.config_optional()?
            .ok_or_else(|| anyhow::anyhow!("authoritative macOS configuration is not loaded"))
    }

    pub fn config_optional(&self) -> anyhow::Result<Option<MacBackendConfig>> {
        Ok(self
            .config
            .read()
            .map_err(|_| anyhow::anyhow!("macOS policy config lock is poisoned"))?
            .clone())
    }

    /// MCH0: current Process Shield toggle state (shared runtime flag).
    pub fn process_shield_enabled(&self) -> bool {
        self.process_shield_enabled
            .load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn enabled(&self) -> bool {
        self.resources.enabled()
    }

    pub fn resource_counts(&self) -> (usize, usize) {
        self.resources.counts()
    }

    pub fn ssh_key_count(&self) -> usize {
        self.resources.ssh_key_count()
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
                    if event.resource.kind == ProtectedResourceKind::SshPrivateKey {
                        "ssh_key_access_blocked"
                    } else {
                        "browser_access_denied"
                    },
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
        // Process Shield File-Shield gate (MPS5): a confirmed Compromised
        // exact live instance fails closed before ANY browser/SSH policy —
        // including write-only opens, system-process metadata exceptions and
        // trusted-tool exceptions — so a compromised browser cannot keep
        // receiving Allow merely because path/signature/BrowserId match.
        if process.integrity != guard_core::ProcessIntegrity::Normal {
            inner.stats.denied = inner.stats.denied.saturating_add(1);
            drop(inner);
            self.record(
                if event.resource.kind == ProtectedResourceKind::SshPrivateKey {
                    "ssh_key_access_blocked"
                } else {
                    "browser_access_denied"
                },
                &event.resource,
                Some(&process),
                Decision::Deny(DenyReason::ProcessIntegrityCompromised),
                "process integrity is Compromised; protected-resource authority revoked".into(),
                now,
            );
            let _ = event.permission.deny();
            return;
        }
        if event.resource.kind == ProtectedResourceKind::SshPrivateKey
            && event.permission.requested_fflags() & ES_FFLAG_READ == 0
        {
            if process.uid != event.resource.owner_uid {
                inner.stats.denied = inner.stats.denied.saturating_add(1);
                drop(inner);
                self.record(
                    "ssh_key_access_blocked",
                    &event.resource,
                    Some(&process),
                    Decision::Deny(DenyReason::WrongUid),
                    "cross-UID write-only open denied".into(),
                    now,
                );
                let _ = event.permission.deny();
            } else {
                inner.stats.allowed = inner.stats.allowed.saturating_add(1);
                drop(inner);
                self.record_debug(
                    "ssh_key_write_only_allowed",
                    &event.resource,
                    Some(&process),
                    Decision::Allow,
                    "write-only AUTH_OPEN cannot disclose key bytes; integrity is outside the access-firewall scope".into(),
                    now,
                );
                let _ = event.permission.allow_exact();
            }
            return;
        }
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

        // macOS system integrations are allowed only through an exact,
        // signed rule.  The rule is intentionally checked before the shared
        // browser policy, but only for explicitly low-sensitivity metadata;
        // critical browser material and SSH keys never take this path.
        if let Ok(config) = self.config() {
            if event.resource.kind != ProtectedResourceKind::SshPrivateKey
                && !event.resource.kind.is_critical_browser()
                && config
                    .mac_allowlist
                    .system_rule(&event.facts.process, event.resource.kind)
                    .is_some()
            {
                inner.stats.allowed = inner.stats.allowed.saturating_add(1);
                drop(inner);
                self.record_debug(
                    "system_process_metadata_allowed",
                    &event.resource,
                    Some(&process),
                    Decision::Allow,
                    "exact Apple-signed system process metadata exception".into(),
                    now,
                );
                let _ = event.permission.allow_read_only();
                return;
            }
            if event.resource.kind != ProtectedResourceKind::SshPrivateKey
                && !event.resource.kind.is_critical_browser()
                && config
                    .mac_allowlist
                    .trusted_tool_matches(&event.facts.process)
            {
                inner.stats.allowed = inner.stats.allowed.saturating_add(1);
                drop(inner);
                self.record_debug(
                    "trusted_tool_metadata_allowed",
                    &event.resource,
                    Some(&process),
                    Decision::Allow,
                    "explicitly enrolled tool metadata exception".into(),
                    now,
                );
                let _ = event.permission.allow_read_only();
                return;
            }
        }
        let decision = inner.runtime.evaluate(&access, now);
        match decision.clone() {
            Decision::Detected => {
                // evaluate() never returns Detected; defensive fail-closed for
                // the protected open.
                inner.stats.denied = inner.stats.denied.saturating_add(1);
                drop(inner);
                let _ = event.permission.deny();
            }
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
                    if event.resource.kind == ProtectedResourceKind::SshPrivateKey {
                        "ssh_key_access_allowed"
                    } else {
                        "browser_migration_allowed_by_lease"
                    },
                    &event.resource,
                    Some(&process),
                    decision,
                    if event.resource.kind == ProtectedResourceKind::SshPrivateKey {
                        "short exact-key root-bound SSH read lease".into()
                    } else {
                        "read_only_guaranteed=true root-bound migration lease".into()
                    },
                    now,
                );
                if event.resource.kind == ProtectedResourceKind::SshPrivateKey {
                    let _ = event.permission.allow_exact();
                } else {
                    let _ = event.permission.allow_read_only();
                }
            }
            Decision::Deny(reason) => {
                inner.stats.denied = inner.stats.denied.saturating_add(1);
                drop(inner);
                let suppress_system_noise =
                    self.config_optional().ok().flatten().is_some_and(|config| {
                        config.mac_allowlist.system_processes.iter().any(|rule| {
                            rule.path == event.facts.process.executable.path
                                && rule.owner_uid == event.facts.process.executable.owner_uid
                                && rule.platform_binary == event.facts.process.code.platform_binary
                                && event.facts.process.code.valid
                                && event.facts.process.code.team_id == rule.team_id
                                && event.facts.process.code.signing_id.as_deref()
                                    == Some(rule.signing_id.as_str())
                                && process.trust_tier == guard_core::TrustTier::Unknown
                        })
                    });
                self.record(
                    if event.resource.kind == ProtectedResourceKind::SshPrivateKey {
                        "ssh_key_access_blocked"
                    } else if suppress_system_noise {
                        "system_process_access_suppressed"
                    } else {
                        "browser_access_denied"
                    },
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
                let Some(budget) = event.interactive_budget else {
                    inner.stats.denied = inner.stats.denied.saturating_add(1);
                    drop(inner);
                    self.record(
                        "ssh_key_access_timed_out",
                        &event.resource,
                        Some(&process),
                        Decision::Deny(DenyReason::SshApprovalRequired),
                        "Endpoint Security deadline has no interactive budget".into(),
                        now,
                    );
                    let _ = event.permission.deny();
                    return;
                };
                let details = SshPendingDetails {
                    resource: event.resource.clone(),
                    resource_dev: Some(event.facts.target_dev),
                    resource_ino: Some(event.facts.target_ino),
                    target_root: process.stable.clone(),
                    target: process.clone(),
                };
                let timeout_secs = budget.as_secs().max(1);
                let result = inner.ssh_pending.enqueue_with_timeout(
                    details,
                    Box::new(ExactPendingPermission(event.permission)),
                    now,
                    timeout_secs,
                );
                match result {
                    SshEnqueueResult::Created(_) | SshEnqueueResult::Joined => {
                        drop(inner);
                        self.record(
                            "ssh_key_access_confirmation_required",
                            &event.resource,
                            Some(&process),
                            decision,
                            format!("exact_key=true prompt_budget_secs={timeout_secs}"),
                            now,
                        );
                    }
                    SshEnqueueResult::DenySuppressed | SshEnqueueResult::DenyLimit => {
                        inner.stats.denied = inner.stats.denied.saturating_add(1);
                        drop(inner);
                        self.record(
                            "ssh_key_access_blocked",
                            &event.resource,
                            Some(&process),
                            Decision::Deny(DenyReason::SshApprovalRequired),
                            "pending queue full or recently blocked".into(),
                            now,
                        );
                    }
                }
            }
        }
    }

    /// Record metadata-only Process Shield audit handoffs (AUTH_EXEC
    /// admission / launch-injection deny / malformed fail-closed). Never
    /// carries secret contents.
    pub fn handle_shield(&self, event: ShieldAuditEvent) {
        if let ShieldAuditEvent::Compromised { target, .. } = &event {
            // MPS4 ordering: the exact instance was already transitioned to
            // Compromised in the ES callback; now run capability revocation
            // hooks BEFORE auditing.
            self.revoke_capabilities_for_compromised(target);
        }
        self.handle_shield_at(event, epoch_seconds());
    }

    /// MPS6: dynamically shield the exact lease root for the lease lifetime.
    /// The root becomes a Process Shield target so a same-user attacker cannot
    /// take over the approved reader via a task port.
    fn shield_dynamic_lease_root(&self, root: &ProcessStableId) {
        // MCH0: with Process Shield disabled, no dynamic lease-root shielding
        // happens (the shield would not enforce task access anyway).
        if !self.resolver.shield_enabled() {
            return;
        }
        let Some(shield) = self.resolver.shield() else {
            return;
        };
        let Some(facts) = self.resolver.current_facts(root.pid) else {
            return;
        };
        if facts.stable_id() != *root {
            return;
        }
        let _ = shield
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .admit(
                facts,
                platform_macos::process_shield::ShieldReasonKind::DynamicLeaseRoot,
            );
    }

    /// Remove the dynamic lease-root shield reason. Other reasons (browser,
    /// guard component) keep the instance shielded. A Compromised instance
    /// keeps its entry (quarantine) until process exit, so the File Shield
    /// deny cannot be lost by dropping the last reason.
    fn unshield_dynamic_lease_root(&self, root: &ProcessStableId) {
        if !self.resolver.shield_enabled() {
            return;
        }
        let Some(shield) = self.resolver.shield() else {
            return;
        };
        let Some(facts) = self.resolver.current_facts(root.pid) else {
            return;
        };
        if facts.stable_id() != *root {
            return;
        }
        let mut shield = shield
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if shield.integrity_of_pid(root.pid) != guard_core::ProcessIntegrity::Normal {
            return;
        }
        shield.remove_reason(
            &facts.key,
            platform_macos::process_shield::ShieldReasonKind::DynamicLeaseRoot,
        );
    }

    /// MPS5: revoke every capability that could preserve secret authority for
    /// a confirmed Compromised instance — bound migration leases, SSH read
    /// leases, and recent-import approval grace for the same executable/root.
    fn revoke_capabilities_for_compromised(&self, target: &MacProcessFacts) {
        let target_stable = target.stable_id();
        let target_uid = target.uid;
        let target_exe = target_stable.exe_identity();
        // Ancestor walk for tree-scoped leases (compromised member of a
        // lease-rooted tree). Degrades to exact-root revocation only when the
        // process graph cannot produce ancestry.
        let ancestors = self.resolver.ancestors(target.key.pid).unwrap_or_default();
        let in_tree = |root: &ProcessStableId| {
            root == &target_stable
                || ancestors.iter().any(|ancestor| {
                    ancestor.pid == root.pid
                        && ancestor.start_time == root.start_time
                        && ancestor.exe == root.exe
                        && ancestor.exe_dev == root.exe_dev
                        && ancestor.exe_ino == root.exe_ino
                })
        };
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for lease in &mut inner.runtime.leases_mut().migration {
            if let MigrationLeaseState::Bound { root } = &lease.state {
                if in_tree(root) {
                    lease.revoked = true;
                    lease.state = MigrationLeaseState::Dead;
                }
            }
        }
        for lease in &mut inner.runtime.leases_mut().ssh_read {
            if in_tree(&lease.root) {
                lease.revoked = true;
            }
        }
        // Recent-approval grace must not silently re-authorize a new instance
        // of the same compromised executable/root.
        inner
            .pending
            .revoke_recent_approvals_for(target_uid, &target_exe);
    }

    fn handle_shield_at(&self, event: ShieldAuditEvent, now: u64) {
        let (event_code, target, uid_override, decision, diagnostic) = match event {
            ShieldAuditEvent::ExecAdmitted {
                target,
                reason,
                membership,
            } => (
                "process_shield_exec_admitted",
                Some(target),
                None,
                Decision::Allow,
                format!(
                    "shield_reason={}{}",
                    reason.label(),
                    if reason == platform_macos::process_shield::ShieldReasonKind::Browser {
                        format!(" session_membership={}", membership.label())
                    } else {
                        String::new()
                    }
                ),
            ),
            ShieldAuditEvent::ExecDeniedLaunchInjection {
                target,
                present_vars,
            } => (
                "process_shield_launch_injection_denied",
                Some(target),
                None,
                Decision::Deny(DenyReason::NotTrustedIdentity),
                format!("prohibited_dyld={}", present_vars.join(",")),
            ),
            ShieldAuditEvent::ExecDeniedMalformed {
                requester_uid,
                diagnostic,
            } => (
                "process_shield_exec_malformed_denied",
                None,
                Some(requester_uid),
                Decision::Deny(DenyReason::UnknownProcess),
                diagnostic,
            ),
            ShieldAuditEvent::TaskDenied {
                kind,
                requester,
                target,
            } => {
                // Attribute to the TARGET's owner (the victim), so a same-user
                // observer can see task-attack denials against their shielded
                // browser even when the requester is a system daemon.
                let victim_uid = target.uid;
                let requester_exe = requester.executable.path.display().to_string();
                let requester_uid = requester.uid;
                (
                    kind.event_code(),
                    Some(target),
                    Some(victim_uid),
                    Decision::Deny(DenyReason::UnknownProcess),
                    format!(
                        "requester_exe={requester_exe} requester_uid={requester_uid} kind={}",
                        kind.label()
                    ),
                )
            }
            ShieldAuditEvent::TaskNotify {
                kind,
                requester,
                target,
            } => (
                kind.event_code(),
                Some(target),
                Some(requester.uid),
                Decision::Detected,
                format!(
                    "requester_exe={} signal={} notify_only=true",
                    requester.executable.path.display(),
                    kind.label()
                ),
            ),
            ShieldAuditEvent::Compromised {
                target,
                signal,
                requester,
            } => (
                "process_shield_compromised",
                Some(target),
                Some(requester.uid),
                Decision::Detected,
                format!(
                    "signal={} requester_exe={} integrity=Compromised",
                    signal.label(),
                    requester.executable.path.display()
                ),
            ),
        };
        let uid = uid_override
            .or_else(|| target.as_ref().map(|facts| facts.uid))
            .unwrap_or(0);
        self.record_shield_audit(event_code, target.as_ref(), uid, decision, diagnostic, now);
    }

    fn record_shield_audit(
        &self,
        event_code: &str,
        target: Option<&MacProcessFacts>,
        uid: u32,
        decision: Decision,
        diagnostic: String,
        now: u64,
    ) {
        let path = target
            .map(|facts| facts.executable.path.to_string_lossy().into_owned())
            .unwrap_or_default();
        let deny_reason = match &decision {
            Decision::Deny(reason) => Some(*reason),
            _ => None,
        };
        self.audit.record(AuditRecord {
            event_code: event_code.into(),
            ts_ms: now.saturating_mul(1000),
            uid,
            pid: target.map_or(0, |facts| facts.key.pid),
            start_time: target.map_or(0, |facts| facts.start_time_us),
            decision,
            deny_reason,
            resource_kind: ProtectedResourceKind::Other,
            resource_browser: None,
            resource_profile: None,
            path: path.clone(),
            exe: path,
            exe_owner_uid: target.map_or(0, |facts| facts.executable.owner_uid),
            trust_tier: TrustTier::Unknown,
            process_browser: None,
            parent_pid: None,
            parent_exe: None,
            lease_id: None,
            backend_diag: diagnostic,
        });
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
        // MPS6: the bound lease root is dynamically shielded for the lease
        // lifetime.
        self.shield_dynamic_lease_root(&details.target_root);
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

    pub fn ssh_pending_for_uid(&self, uid: u32) -> Vec<guard_ipc::SshPendingInfo> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .ssh_pending
            .list_for_uid(uid, false)
            .iter()
            .map(ssh_pending_info)
            .collect()
    }

    pub fn ssh_pending_item_for_uid(
        &self,
        id: &str,
        uid: u32,
    ) -> Option<guard_ipc::SshPendingInfo> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .ssh_pending
            .get_for_uid(id, uid, false)
            .as_ref()
            .map(ssh_pending_info)
    }

    pub fn resolve_ssh_read(
        &self,
        id: &str,
        uid: u32,
        allow: bool,
    ) -> anyhow::Result<guard_ipc::SshReadResolutionInfo> {
        self.resolve_ssh_read_at(id, uid, allow, epoch_seconds())
    }

    fn resolve_ssh_read_at(
        &self,
        id: &str,
        uid: u32,
        allow: bool,
        now: u64,
    ) -> anyhow::Result<guard_ipc::SshReadResolutionInfo> {
        let request = {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match inner
                .ssh_pending
                .take_for_resolution_result(id, uid, false, now, !allow)
            {
                PendingTakeResult::Ready(request) => request,
                PendingTakeResult::TimedOut(request) => {
                    let details = request.details.clone();
                    request.resolve(false);
                    inner.stats.denied = inner.stats.denied.saturating_add(1);
                    drop(inner);
                    self.record(
                        "ssh_key_access_timed_out",
                        &details.resource,
                        Some(&details.target),
                        Decision::Deny(DenyReason::SshApprovalRequired),
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
            self.note_ssh_denied();
            self.record(
                "ssh_key_access_blocked",
                &details.resource,
                Some(&details.target),
                Decision::Deny(DenyReason::SshApprovalRequired),
                "explicit user block".into(),
                now,
            );
            return Ok(guard_ipc::SshReadResolutionInfo::Blocked);
        }

        let validation = self.revalidate_ssh_pending(&details);
        let current = match validation {
            Ok(current) => current,
            Err(error) => {
                request.resolve(false);
                self.note_ssh_denied();
                self.record(
                    "ssh_key_access_blocked",
                    &details.resource,
                    Some(&details.target),
                    Decision::Deny(DenyReason::IdentityMismatch),
                    format!("post-authentication revalidation failed: {error}"),
                    now,
                );
                return Err(error);
            }
        };
        let lease_id = {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match inner
                .runtime
                .approve_ssh_read(&details, &current, now, SSH_READ_LEASE_SECS)
            {
                Ok((lease_id, _)) => {
                    drop(inner);
                    // MPS6: the SSH-read lease root is dynamically shielded
                    // for the capability lifetime.
                    self.shield_dynamic_lease_root(&details.target_root);
                    lease_id
                }
                Err(error) => {
                    drop(inner);
                    request.resolve(false);
                    self.note_ssh_denied();
                    self.record(
                        "ssh_key_access_blocked",
                        &details.resource,
                        Some(&details.target),
                        Decision::Deny(DenyReason::IdentityMismatch),
                        format!("post-authentication reader mismatch: {error}"),
                        now,
                    );
                    anyhow::bail!(error)
                }
            }
        };
        if let Err(error) = request.try_resolve(true) {
            self.revoke_ssh_lease(lease_id);
            anyhow::bail!("retained AUTH_OPEN was no longer resolvable: {error}");
        }
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .stats
            .allowed += 1;
        self.record(
            "ssh_key_access_allowed",
            &details.resource,
            Some(&current),
            Decision::AllowByLease(lease_id),
            format!("exact_key=true root_bound=true lease_secs={SSH_READ_LEASE_SECS}"),
            now,
        );
        Ok(guard_ipc::SshReadResolutionInfo::Allowed)
    }

    fn revalidate_ssh_pending(
        &self,
        details: &SshPendingDetails,
    ) -> anyhow::Result<ProcessIdentity> {
        anyhow::ensure!(
            self.resources.is_configured_ssh_resource(&details.resource),
            "SSH key is no longer configured"
        );
        let canonical = std::fs::canonicalize(&details.resource.path)?;
        anyhow::ensure!(
            canonical == details.resource.path,
            "SSH key path identity changed"
        );
        let metadata = std::fs::metadata(&canonical)?;
        anyhow::ensure!(
            metadata.is_file()
                && metadata.uid() == details.resource.owner_uid
                && Some(metadata.dev()) == details.resource_dev
                && Some(metadata.ino()) == details.resource_ino,
            "SSH key owner or file identity changed before confirmation"
        );
        let current = self
            .resolver
            .resolve(details.target.stable.pid, details.resource.owner_uid)?;
        anyhow::ensure!(
            self.resolver.is_live_instance(&details.target_root)?,
            "SSH reader root exited before confirmation"
        );
        Ok(current)
    }

    fn note_ssh_denied(&self) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.stats.denied = inner.stats.denied.saturating_add(1);
    }

    pub fn maintenance(&self) {
        self.maintenance_at(epoch_seconds());
    }

    fn maintenance_at(&self, now: u64) {
        let (expired_migrations, expired_ssh_reads, expired_lease_roots) = {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut expired_lease_roots = Vec::new();
            for lease in &mut inner.runtime.leases_mut().migration {
                if let MigrationLeaseState::Bound { root } = &lease.state {
                    if !self.resolver.is_live_instance(root).unwrap_or(false) {
                        expired_lease_roots.push(root.clone());
                        lease.revoked = true;
                        lease.state = MigrationLeaseState::Dead;
                    } else if now >= lease.expires_at || lease.revoked {
                        // Capability ended while the root is still alive: the
                        // dynamic shield reason may be removed (unless the
                        // instance is quarantined).
                        expired_lease_roots.push(root.clone());
                    }
                }
            }
            for lease in &mut inner.runtime.leases_mut().ssh_read {
                if !self.resolver.is_live_instance(&lease.root).unwrap_or(false) {
                    expired_lease_roots.push(lease.root.clone());
                    lease.revoked = true;
                } else if now >= lease.expires_at || lease.revoked {
                    expired_lease_roots.push(lease.root.clone());
                }
            }
            let expired_migrations = inner.pending.expire(now, self.resolver.as_ref());
            let expired_ssh_reads = inner.ssh_pending.expire(now, self.resolver.as_ref());
            let expired_count = expired_migrations
                .len()
                .saturating_add(expired_ssh_reads.len());
            inner.stats.denied = inner
                .stats
                .denied
                .saturating_add(u64::try_from(expired_count).unwrap_or(u64::MAX));
            (expired_migrations, expired_ssh_reads, expired_lease_roots)
        };
        // MPS6: drop the dynamic lease-root shield reason for lease roots that
        // exited; other shield reasons keep the instance protected.
        for root in expired_lease_roots {
            self.unshield_dynamic_lease_root(&root);
        }
        for request in expired_migrations {
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
        for request in expired_ssh_reads {
            let details = request.details.clone();
            request.resolve(false);
            self.record(
                "ssh_key_access_timed_out",
                &details.resource,
                Some(&details.target),
                Decision::Deny(DenyReason::SshApprovalRequired),
                "prompt deadline or reader process lifetime ended".into(),
                now,
            );
        }
    }

    pub fn lease_infos_for_uid(&self, uid: u32) -> Vec<guard_ipc::LeaseInfo> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let leases = inner.runtime.leases();
        let mut infos = leases
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
            .collect::<Vec<_>>();
        infos.extend(
            leases
                .ssh_read
                .iter()
                .filter(|lease| lease.uid == uid)
                .map(|lease| guard_ipc::LeaseInfo {
                    id: lease.id.0.to_string(),
                    kind: "ssh_read".into(),
                    uid: lease.uid,
                    source_browser: None,
                    source_profile: None,
                    target_browser: None,
                    resource: Some(lease.resource.0.clone()),
                    state: Some(format!("root_pid={}", lease.root.pid)),
                    expires_at: lease.expires_at,
                    revoked: lease.revoked,
                    used: false,
                }),
        );
        infos
    }

    pub fn revoke_lease_by_id(&self, id: &str, uid: u32) -> bool {
        let Ok(id) = id.parse::<u64>() else {
            return false;
        };
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(lease) = inner
            .runtime
            .leases_mut()
            .migration
            .iter_mut()
            .find(|lease| lease.id.0 == id && lease.uid == uid)
        {
            lease.revoked = true;
            lease.state = MigrationLeaseState::Dead;
            return true;
        }
        if let Some(lease) = inner
            .runtime
            .leases_mut()
            .ssh_read
            .iter_mut()
            .find(|lease| lease.id.0 == id && lease.uid == uid)
        {
            lease.revoked = true;
            return true;
        }
        false
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
                // MPS6: dynamically shield the grace-approved root too.
                self.shield_dynamic_lease_root(&details.target_root);
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
                // MPS6: dynamically shield the coalesced root too.
                self.shield_dynamic_lease_root(&details.target_root);
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

    fn revoke_ssh_lease(&self, lease_id: guard_core::LeaseId) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(lease) = inner
            .runtime
            .leases_mut()
            .ssh_read
            .iter_mut()
            .find(|lease| lease.id == lease_id)
        {
            lease.revoked = true;
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
            let config = config.clone().with_builtin_mac_allowlist();
            config.validate()?;
            Ok((
                MacResourceIndex::from_enrollments(
                    &config.browser_trust,
                    &config.common_policy.ssh_keys,
                )?,
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

fn ssh_pending_info(info: &guard_runtime::PendingSshReadInfo) -> guard_ipc::SshPendingInfo {
    guard_ipc::SshPendingInfo {
        id: info.id.clone(),
        uid: info.uid,
        key_path: info.key_path.clone(),
        process_exe: info.process_exe.clone(),
        pid: info.pid,
        start_time: info.start_time,
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
    use platform_macos::process_shield::MacProcessShield;

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
        shield: Arc<Mutex<MacProcessShield>>,
        policy: MacPolicy,
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
            let reader = root.path().join("synthetic-reader");
            std::fs::write(&reader, b"synthetic reader executable").unwrap();
            executables.insert("reader".into(), reader);
            let ssh_key = root.path().join("id_ed25519");
            std::fs::write(&ssh_key, b"synthetic ephemeral private-key fixture").unwrap();
            let ssh_resource = guard_ssh::enroll_key(&ssh_key).unwrap();
            resources.insert("ssh".into(), ssh_resource.clone());
            let config = MacBackendConfig {
                version: platform_macos::config::MAC_CONFIG_VERSION,
                policy_enabled: true,
                process_shield_enabled: true,
                common_policy: PolicyConfig {
                    browsers: common,
                    enrolled_exes: Vec::new(),
                    ssh_keys: vec![ssh_resource.path],
                },
                browser_trust: browsers,
                mac_allowlist: platform_macos::config::MacAllowlistConfig::default(),
            }
            .with_builtin_mac_allowlist();
            let (index, trust, enabled) = prepare_config(Some(&config)).unwrap();
            let protected = Arc::new(MacProtectedResources::new(enabled, index));
            let graph = Arc::new(Mutex::new(MacProcessGraph::default()));
            let shield = Arc::new(Mutex::new(MacProcessShield::new()));
            let resolver = Arc::new(MacProcessIdentityResolver::new_shared_with_shield(
                Arc::clone(&graph),
                Arc::new(RwLock::new(trust)),
                Arc::clone(&shield),
            ));
            let audit_path = root.path().join("audit.db");
            let policy = MacPolicy::new(
                protected,
                resolver,
                Arc::new(AuditStore::open(&audit_path).unwrap()),
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            );
            policy.apply_config(config).unwrap();
            Self {
                _root: root,
                graph,
                shield,
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
    fn session_helper_is_admitted_before_its_protected_read_is_allowed() {
        // MCH5 ordering proven at the POLICY level: a BrowserSession helper
        // that was NOT task-protected at exec time performs a protected read.
        // resolve() (inside handle_at) MUST admit it as SecretAuthority BEFORE
        // the Allow decision is returned; the read is allowed and the shield
        // already holds the promoted entry.
        use platform_macos::browser_trust::{BrowserExecutableRole, MacExecutableEnrollment};
        use platform_macos::process_shield::ShieldAdmission;

        let fixture = Fixture::new();
        // Enroll a genuine Helper executable for browser-a inside its bundle.
        let helper_path = fixture
            ._root
            .path()
            .join("browser-a.app/Contents/Frameworks/browser-a Helper.app/Contents/MacOS/browser-a Helper");
        std::fs::create_dir_all(helper_path.parent().unwrap()).unwrap();
        std::fs::write(&helper_path, b"synthetic helper executable").unwrap();
        let mut config = fixture.policy.config().unwrap();
        let common = config
            .common_policy
            .browsers
            .iter_mut()
            .find(|browser| browser.id == "browser-a")
            .unwrap();
        common.exe_paths.push(helper_path.clone());
        let trust = config
            .browser_trust
            .iter_mut()
            .find(|browser| browser.browser_id.0 == "browser-a")
            .unwrap();
        trust.executables.push(MacExecutableEnrollment::Signed {
            role: BrowserExecutableRole::Helper,
            path: helper_path.clone(),
            bundle_suffix: None,
            team_id: "TEAM-A".into(),
            signing_id: "com.example.browser-a.helper".into(),
        });
        fixture.policy.apply_config(config).unwrap();

        // Session topology: Main roots, Helper joins WITHOUT a shield entry.
        let main = fixture.facts("browser-a", 10, None);
        let mut helper = fixture.facts("browser-a", 11, None);
        helper.key.pidversion = 11;
        helper.executable.path = helper_path.clone();
        let helper_metadata = std::fs::metadata(&helper_path).unwrap();
        helper.executable.dev = helper_metadata.dev();
        helper.executable.ino = helper_metadata.ino();
        helper.executable.size = helper_metadata.size();
        helper.executable.mtime_ns =
            helper_metadata.mtime() * 1_000_000_000 + helper_metadata.mtime_nsec();
        helper.executable.ctime_ns =
            helper_metadata.ctime() * 1_000_000_000 + helper_metadata.ctime_nsec();
        helper.code.team_id = Some("TEAM-A".into());
        helper.code.signing_id = Some("com.example.browser-a.helper".into());
        {
            let mut shield = fixture.shield.lock().unwrap();
            shield
                .admit_browser(main.clone(), Some(BrowserExecutableRole::Main), None, false)
                .unwrap();
            shield
                .admit_browser(
                    helper.clone(),
                    Some(BrowserExecutableRole::Helper),
                    Some(main.key),
                    true,
                )
                .unwrap();
            assert!(
                !shield.is_task_protected(&helper),
                "helper must not be task-protected at exec time"
            );
        }
        fixture.observe(helper.clone());

        // The helper's first protected read (its own profile Cookies).
        let (event, state) = fixture.event(
            helper.clone(),
            "browser-a",
            ES_FFLAG_READ,
            Some(Duration::from_secs(10)),
        );
        fixture.policy.handle_at(event, 100);
        assert_eq!(
            *state.lock().unwrap(),
            Terminal::Flags(ES_FFLAG_READ),
            "trusted browser own-profile read must be allowed"
        );
        let shield = fixture.shield.lock().unwrap();
        assert!(
            shield.is_task_protected(&helper),
            "the helper must already be SecretAuthority when the read is allowed"
        );
        assert_eq!(
            shield.admission_of_pid(11),
            Some(ShieldAdmission::AuthExec),
            "launch-observed helper must not be flagged preexisting"
        );
        assert_eq!(shield.live_preexisting_count(), 0);
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
    fn fresh_runtime_does_not_restore_pending_requests_or_memory_only_leases() {
        let first = Fixture::new();
        let importer = first.facts("browser-b", 70, None);
        first.observe(importer.clone());
        let (event, _) = first.event(
            importer,
            "browser-a",
            ES_FFLAG_READ,
            Some(Duration::from_secs(20)),
        );
        first.policy.handle_at(event, epoch_seconds());
        let pending = first.policy.pending_for_uid(first.uid);
        assert_eq!(pending.len(), 1);
        first
            .policy
            .resolve_migration(&pending[0].id, first.uid, true)
            .unwrap();
        assert!(!first.policy.lease_infos_for_uid(first.uid).is_empty());

        // A process restart constructs a new policy/runtime from configuration;
        // only configuration is reloadable. Pending OS operations and leases
        // are intentionally memory-only and fail closed with the old process.
        let restarted = Fixture::new();
        assert!(restarted.policy.pending_for_uid(restarted.uid).is_empty());
        assert!(restarted
            .policy
            .ssh_pending_for_uid(restarted.uid)
            .is_empty());
        assert!(restarted
            .policy
            .lease_infos_for_uid(restarted.uid)
            .is_empty());
        assert_eq!(
            restarted.policy.resource_counts(),
            first.policy.resource_counts()
        );
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

    #[test]
    fn ssh_read_requires_approval_and_lease_is_exact_key_uid_and_process_tree() {
        let fixture = Fixture::new();
        let now = 1_000;
        let reader = fixture.facts("reader", 80, None);
        fixture.observe(reader.clone());
        let (event, first) = fixture.event(
            reader.clone(),
            "ssh",
            ES_FFLAG_READ | ES_FFLAG_WRITE,
            Some(Duration::from_secs(20)),
        );
        fixture.policy.handle_at(event, now);
        let (event, joined) = fixture.event(
            reader.clone(),
            "ssh",
            ES_FFLAG_READ,
            Some(Duration::from_secs(20)),
        );
        fixture.policy.handle_at(event, now);
        let pending = fixture.policy.ssh_pending_for_uid(fixture.uid);
        assert_eq!(pending.len(), 1);
        assert_eq!(*first.lock().unwrap(), Terminal::Pending);
        assert_eq!(*joined.lock().unwrap(), Terminal::Pending);
        assert_eq!(
            fixture
                .policy
                .resolve_ssh_read_at(&pending[0].id, fixture.uid, true, now + 1)
                .unwrap(),
            guard_ipc::SshReadResolutionInfo::Allowed
        );
        assert_eq!(
            *first.lock().unwrap(),
            Terminal::Flags(ES_FFLAG_READ | ES_FFLAG_WRITE)
        );
        assert_eq!(*joined.lock().unwrap(), Terminal::Flags(ES_FFLAG_READ));
        assert!(fixture
            .policy
            .resolve_ssh_read_at(&pending[0].id, fixture.uid, true, now + 1)
            .is_err());

        let descendant = fixture.facts("reader", 81, Some(reader.key));
        fixture.observe(descendant.clone());
        let (event, descendant_state) = fixture.event(
            descendant,
            "ssh",
            ES_FFLAG_READ,
            Some(Duration::from_secs(20)),
        );
        fixture.policy.handle_at(event, now + 2);
        assert_eq!(
            *descendant_state.lock().unwrap(),
            Terminal::Flags(ES_FFLAG_READ)
        );

        let unrelated = fixture.facts("reader", 82, None);
        fixture.observe(unrelated.clone());
        let (event, unrelated_state) = fixture.event(
            unrelated,
            "ssh",
            ES_FFLAG_READ,
            Some(Duration::from_secs(20)),
        );
        fixture.policy.handle_at(event, now + 2);
        assert_eq!(*unrelated_state.lock().unwrap(), Terminal::Pending);
        let unrelated_pending = fixture.policy.ssh_pending_for_uid(fixture.uid);
        assert_eq!(unrelated_pending.len(), 1);
        fixture
            .policy
            .resolve_ssh_read_at(&unrelated_pending[0].id, fixture.uid, false, now + 3)
            .unwrap();
        assert_eq!(*unrelated_state.lock().unwrap(), Terminal::Flags(0));

        let mut cross_uid = fixture.facts("reader", 83, None);
        cross_uid.uid = fixture.uid.saturating_add(1);
        fixture.observe(cross_uid.clone());
        let (event, cross_uid_state) = fixture.event(
            cross_uid,
            "ssh",
            ES_FFLAG_READ,
            Some(Duration::from_secs(20)),
        );
        fixture.policy.handle_at(event, now + 4);
        assert_eq!(*cross_uid_state.lock().unwrap(), Terminal::Flags(0));
        assert!(fixture.policy.ssh_pending_for_uid(fixture.uid).is_empty());

        fixture.graph.lock().unwrap().remove_terminal(reader.key);
        fixture.policy.maintenance_at(now + 5);
        assert!(fixture
            .policy
            .lease_infos_for_uid(fixture.uid)
            .iter()
            .any(|lease| lease.kind == "ssh_read" && lease.revoked));
        let events = fixture
            .policy
            .recent_events(fixture.uid, 100, None, None)
            .unwrap();
        for required in [
            "ssh_key_access_confirmation_required",
            "ssh_key_access_allowed",
            "ssh_key_access_blocked",
        ] {
            assert!(events.iter().any(|event| event.event_code == required));
        }
        let json = serde_json::to_string(&events).unwrap();
        assert!(!json.contains("synthetic ephemeral private-key fixture"));
    }

    #[test]
    fn ssh_write_only_deadline_replacement_and_late_resolution_fail_safely() {
        let fixture = Fixture::new();
        let now = 2_000;
        let writer = fixture.facts("reader", 90, None);
        fixture.observe(writer.clone());
        let (event, write_only) =
            fixture.event(writer, "ssh", ES_FFLAG_WRITE, Some(Duration::from_secs(20)));
        fixture.policy.handle_at(event, now);
        assert_eq!(*write_only.lock().unwrap(), Terminal::Flags(ES_FFLAG_WRITE));
        assert!(fixture.policy.ssh_pending_for_uid(fixture.uid).is_empty());

        let reader = fixture.facts("reader", 91, None);
        fixture.observe(reader.clone());
        let (event, replaced) =
            fixture.event(reader, "ssh", ES_FFLAG_READ, Some(Duration::from_secs(20)));
        fixture.policy.handle_at(event, now + 1);
        let pending = fixture.policy.ssh_pending_for_uid(fixture.uid);
        let key = fixture.resources.get("ssh").unwrap().path.clone();
        std::fs::rename(&key, key.with_extension("old")).unwrap();
        std::fs::write(&key, b"replacement synthetic key").unwrap();
        assert!(fixture
            .policy
            .resolve_ssh_read_at(&pending[0].id, fixture.uid, true, now + 2)
            .is_err());
        assert_eq!(*replaced.lock().unwrap(), Terminal::Flags(0));

        let late_reader = fixture.facts("reader", 92, None);
        fixture.observe(late_reader.clone());
        let (event, late) = fixture.event(
            late_reader,
            "ssh",
            ES_FFLAG_READ,
            Some(Duration::from_secs(2)),
        );
        fixture.policy.handle_at(event, now + 3);
        let pending = fixture.policy.ssh_pending_for_uid(fixture.uid);
        assert!(fixture
            .policy
            .resolve_ssh_read_at(&pending[0].id, fixture.uid, true, now + 5)
            .is_err());
        assert_eq!(*late.lock().unwrap(), Terminal::Flags(0));
        assert!(fixture
            .policy
            .recent_events(fixture.uid, 100, None, None)
            .unwrap()
            .iter()
            .any(|event| event.event_code == "ssh_key_access_timed_out"));
    }

    #[test]
    fn ssh_pending_queue_pressure_and_missing_interactive_budget_deny() {
        let fixture = Fixture::new();
        let now = 3_000;
        let mut states = Vec::new();
        for pid in 100..=108 {
            let reader = fixture.facts("reader", pid, None);
            fixture.observe(reader.clone());
            let (event, state) =
                fixture.event(reader, "ssh", ES_FFLAG_READ, Some(Duration::from_secs(20)));
            fixture.policy.handle_at(event, now);
            states.push(state);
        }
        assert_eq!(fixture.policy.ssh_pending_for_uid(fixture.uid).len(), 8);
        assert_eq!(*states.last().unwrap().lock().unwrap(), Terminal::Flags(0));

        let no_budget_reader = fixture.facts("reader", 109, None);
        fixture.observe(no_budget_reader.clone());
        let (event, no_budget) = fixture.event(no_budget_reader, "ssh", ES_FFLAG_READ, None);
        fixture.policy.handle_at(event, now + 1);
        assert_eq!(*no_budget.lock().unwrap(), Terminal::Flags(0));
    }

    #[test]
    fn process_shield_exec_audit_is_metadata_only() {
        let fixture = Fixture::new();
        let target = fixture.facts("browser-a", 900, None);
        fixture
            .policy
            .handle_shield(ShieldAuditEvent::ExecAdmitted {
                target: target.clone(),
                reason: platform_macos::process_shield::ShieldReasonKind::Browser,
                membership: platform_macos::browser_session::SessionMembership::Rejected(
                    platform_macos::browser_session::RejectionKind::Unverifiable,
                ),
            });
        fixture
            .policy
            .handle_shield(ShieldAuditEvent::ExecDeniedLaunchInjection {
                target: target.clone(),
                present_vars: vec!["DYLD_INSERT_LIBRARIES"],
            });
        fixture
            .policy
            .handle_shield(ShieldAuditEvent::ExecDeniedMalformed {
                requester_uid: fixture.uid,
                diagnostic: "truncated target executable path".into(),
            });
        let attacker = fixture.facts("reader", 901, None);
        fixture.policy.handle_shield(ShieldAuditEvent::TaskDenied {
            kind: platform_macos::process_shield::TaskAccessKind::Control,
            requester: attacker,
            target: target.clone(),
        });
        let tracer = fixture.facts("reader", 902, None);
        fixture.policy.handle_shield(ShieldAuditEvent::TaskNotify {
            kind: platform_macos::process_shield::TaskNotifyKind::Trace,
            requester: tracer,
            target: target.clone(),
        });
        fixture.policy.handle_shield(ShieldAuditEvent::TaskNotify {
            kind: platform_macos::process_shield::TaskNotifyKind::RemoteThreadCreate,
            requester: fixture.facts("reader", 903, None),
            target: target.clone(),
        });
        fixture.policy.handle_shield(ShieldAuditEvent::Compromised {
            target,
            signal: platform_macos::process_shield::TaskNotifyKind::CsInvalidated,
            requester: fixture.facts("reader", 904, None),
        });
        let events = fixture
            .policy
            .recent_events(fixture.uid, 100, None, None)
            .unwrap();
        for required in [
            "process_shield_exec_admitted",
            "process_shield_launch_injection_denied",
            "process_shield_exec_malformed_denied",
            "process_shield_task_control_denied",
            "process_shield_trace_observed",
            "process_shield_remote_thread_observed",
            "process_shield_compromised",
        ] {
            assert!(
                events.iter().any(|event| event.event_code == required),
                "missing shield audit event {required}"
            );
        }
        assert!(events
            .iter()
            .filter(|event| event.event_code == "process_shield_compromised")
            .all(|event| event.backend_diag.contains("integrity=Compromised")
                && event.backend_diag.contains("signal=notify_cs_invalidated")));
        // Notify-only signals are DETECTED, never PREVENTED.
        assert!(events
            .iter()
            .filter(|event| event.event_code == "process_shield_trace_observed")
            .all(|event| event.backend_diag.contains("notify_only=true")
                && event.decision == "Detected"));
        // Audit payload must be metadata only: never protected file contents.
        let json = serde_json::to_string(&events).unwrap();
        assert!(!json.contains("synthetic cookies"));
        assert!(!json.contains("synthetic ephemeral private-key fixture"));
        // The exec path is the executable path, never a protected file path.
        assert!(events
            .iter()
            .all(|event| !event.path.contains("Network/Cookies")));
    }

    #[test]
    fn compromised_instance_fails_closed_for_all_file_shield_paths() {
        let fixture = Fixture::new();
        let now = 100;
        // A shielded trusted browser becomes Compromised.
        let browser = fixture.facts("browser-a", 1000, None);
        fixture.observe(browser.clone());
        fixture
            .shield
            .lock()
            .unwrap()
            .admit(
                browser.clone(),
                platform_macos::process_shield::ShieldReasonKind::Browser,
            )
            .unwrap();
        fixture
            .shield
            .lock()
            .unwrap()
            .mark_compromised(&browser.key);
        // Own-profile read: previously Allow, now must fail closed with the
        // stable process_integrity_compromised reason.
        let (event, state) = fixture.event(
            browser,
            "browser-a",
            ES_FFLAG_READ,
            Some(Duration::from_secs(20)),
        );
        fixture.policy.handle_at(event, now);
        assert_eq!(*state.lock().unwrap(), Terminal::Flags(0));
        let events = fixture
            .policy
            .recent_events(fixture.uid, 100, None, None)
            .unwrap();
        assert!(events.iter().any(|event| {
            event.reason_code.as_deref() == Some("process_integrity_compromised")
                && event.event_code == "browser_access_denied"
        }));

        // SSH write-only open from a compromised process must NOT take the
        // write-only allow path.
        let reader = fixture.facts("reader", 1001, None);
        fixture.observe(reader.clone());
        fixture
            .shield
            .lock()
            .unwrap()
            .admit(
                reader.clone(),
                platform_macos::process_shield::ShieldReasonKind::Browser,
            )
            .unwrap();
        fixture.shield.lock().unwrap().mark_compromised(&reader.key);
        let (event, write_state) =
            fixture.event(reader, "ssh", ES_FFLAG_WRITE, Some(Duration::from_secs(20)));
        fixture.policy.handle_at(event, now + 1);
        assert_eq!(
            *write_state.lock().unwrap(),
            Terminal::Flags(0),
            "compromised instance must not be allowed by the write-only path"
        );

        // A Normal process keeps existing behavior on the same fixture.
        let normal = fixture.facts("browser-a", 1002, None);
        fixture.observe(normal.clone());
        let (event, normal_state) = fixture.event(
            normal,
            "browser-a",
            ES_FFLAG_READ,
            Some(Duration::from_secs(20)),
        );
        fixture.policy.handle_at(event, now + 2);
        assert_eq!(
            *normal_state.lock().unwrap(),
            Terminal::Flags(ES_FFLAG_READ),
            "Normal instances must keep their existing allow"
        );
    }

    #[test]
    fn compromise_revokes_bound_leases_direct_and_tree_scoped() {
        let fixture = Fixture::new();
        // Pending resolution uses the real clock (epoch_seconds); drive the
        // whole flow on real time with small offsets.
        let now = epoch_seconds();
        let importer = fixture.facts("browser-b", 2000, None);
        fixture.observe(importer.clone());
        let (event, state) = fixture.event(
            importer.clone(),
            "browser-a",
            ES_FFLAG_READ,
            Some(Duration::from_secs(20)),
        );
        fixture.policy.handle_at(event, now);
        let pending = fixture.policy.pending_for_uid(fixture.uid);
        assert_eq!(pending.len(), 1);
        fixture
            .policy
            .resolve_migration(&pending[0].id, fixture.uid, true)
            .unwrap();
        assert_eq!(*state.lock().unwrap(), Terminal::Flags(ES_FFLAG_READ));
        assert!(fixture
            .policy
            .lease_infos_for_uid(fixture.uid)
            .iter()
            .any(|lease| lease.kind == "browser_migration" && !lease.revoked));

        // SSH read lease bound to a reader in the importer's tree.
        let reader = fixture.facts("reader", 2001, Some(importer.key));
        fixture.observe(reader.clone());
        let (ssh_event, ssh_state) = fixture.event(
            reader.clone(),
            "ssh",
            ES_FFLAG_READ,
            Some(Duration::from_secs(20)),
        );
        fixture.policy.handle_at(ssh_event, now + 1);
        let ssh_pending = fixture.policy.ssh_pending_for_uid(fixture.uid);
        fixture
            .policy
            .resolve_ssh_read_at(&ssh_pending[0].id, fixture.uid, true, now + 2)
            .unwrap();
        assert_eq!(*ssh_state.lock().unwrap(), Terminal::Flags(ES_FFLAG_READ));

        // An unrelated compromised process must not revoke anything.
        let unrelated = fixture.facts("reader", 2005, None);
        fixture.observe(unrelated.clone());
        fixture.policy.handle_shield(ShieldAuditEvent::Compromised {
            target: unrelated,
            signal: platform_macos::process_shield::TaskNotifyKind::CsInvalidated,
            requester: fixture.facts("reader", 2006, None),
        });
        let leases = fixture.policy.lease_infos_for_uid(fixture.uid);
        assert!(
            leases.iter().all(|lease| !lease.revoked),
            "unrelated compromise must not revoke leases"
        );

        // The reader (in the importer's tree) becomes Compromised: the SSH
        // lease rooted at it is revoked directly, and the migration lease is
        // revoked because the compromised process is in its trusted tree.
        fixture.policy.handle_shield(ShieldAuditEvent::Compromised {
            target: reader,
            signal: platform_macos::process_shield::TaskNotifyKind::CsInvalidated,
            requester: fixture.facts("reader", 2003, None),
        });
        let leases = fixture.policy.lease_infos_for_uid(fixture.uid);
        assert!(leases
            .iter()
            .filter(|lease| lease.kind == "browser_migration")
            .all(|lease| lease.revoked && lease.state.as_deref() == Some("dead")));
        assert!(leases
            .iter()
            .filter(|lease| lease.kind == "ssh_read")
            .all(|lease| lease.revoked));
    }

    #[test]
    fn dynamic_lease_root_is_shielded_while_live_and_unshielded_on_expiry() {
        let fixture = Fixture::new();
        let now = epoch_seconds();
        let importer = fixture.facts("browser-b", 3000, None);
        fixture.observe(importer.clone());
        let (event, state) = fixture.event(
            importer.clone(),
            "browser-a",
            ES_FFLAG_READ,
            Some(Duration::from_secs(20)),
        );
        fixture.policy.handle_at(event, now);
        let pending = fixture.policy.pending_for_uid(fixture.uid);
        fixture
            .policy
            .resolve_migration(&pending[0].id, fixture.uid, true)
            .unwrap();
        assert_eq!(*state.lock().unwrap(), Terminal::Flags(ES_FFLAG_READ));

        // While the lease is live the root is dynamically shielded.
        let shield = fixture.shield.lock().unwrap();
        assert!(
            shield.is_shielded_exact(&importer),
            "lease root must be dynamically shielded while the lease is live"
        );
        drop(shield);

        // A Normal lease-root remains task-port protected: the resolver
        // surfaces Normal integrity (not compromised), so File Shield still
        // allows the browser its own profile.
        let (event, own_state) = fixture.event(
            importer.clone(),
            "browser-b",
            ES_FFLAG_READ,
            Some(Duration::from_secs(20)),
        );
        fixture.policy.handle_at(event, now + 1);
        assert_eq!(*own_state.lock().unwrap(), Terminal::Flags(ES_FFLAG_READ));

        // Capability expiry while the root is still alive removes ONLY the
        // dynamic reason. The enrolled browser remains shielded because the
        // warm-start reconciliation (MPS Hardening 2) admitted it as
        // PreexistingUnverified during the protected open above; the dynamic
        fixture
            .policy
            .maintenance_at(now + MIGRATION_LEASE_SECS + 1);
        let shield = fixture.shield.lock().unwrap();
        assert!(
            shield.is_shielded_exact(&importer),
            "enrolled browser stays shielded (as PreexistingUnverified) after lease expiry"
        );
        assert!(
            shield.is_preexisting(importer.key.pid),
            "post-expiry shielding is the warm-start preexisting reason, not the dynamic one"
        );
        assert_eq!(shield.live_preexisting_count(), 1);
    }

    #[test]
    fn compromise_denies_new_protected_access_and_no_new_lease_binds() {
        let fixture = Fixture::new();
        let now = epoch_seconds();
        let importer = fixture.facts("browser-b", 2100, None);
        fixture.observe(importer.clone());
        let (event, state) = fixture.event(
            importer.clone(),
            "browser-a",
            ES_FFLAG_READ,
            Some(Duration::from_secs(20)),
        );
        fixture.policy.handle_at(event, now);
        let pending = fixture.policy.pending_for_uid(fixture.uid);
        fixture
            .policy
            .resolve_migration(&pending[0].id, fixture.uid, true)
            .unwrap();
        assert_eq!(*state.lock().unwrap(), Terminal::Flags(ES_FFLAG_READ));

        // The importer becomes Compromised: the ES callback transitions the
        // shield state first, then the Compromised handoff runs revocation.
        fixture
            .shield
            .lock()
            .unwrap()
            .admit(
                importer.clone(),
                platform_macos::process_shield::ShieldReasonKind::Browser,
            )
            .unwrap();
        fixture
            .shield
            .lock()
            .unwrap()
            .mark_compromised(&importer.key);
        fixture.policy.handle_shield(ShieldAuditEvent::Compromised {
            target: importer.clone(),
            signal: platform_macos::process_shield::TaskNotifyKind::CsInvalidated,
            requester: fixture.facts("reader", 2101, None),
        });

        // Same identity now: a new protected read must be denied with the
        // stable reason (resolver surfaces Compromised via the shield).
        let (event, after_state) = fixture.event(
            importer,
            "browser-a",
            ES_FFLAG_READ,
            Some(Duration::from_secs(20)),
        );
        fixture.policy.handle_at(event, now + 1);
        assert_eq!(
            *after_state.lock().unwrap(),
            Terminal::Flags(0),
            "compromised importer must be denied for protected access"
        );
        let events = fixture
            .policy
            .recent_events(fixture.uid, 100, None, None)
            .unwrap();
        assert!(events.iter().any(|event| {
            event.reason_code.as_deref() == Some("process_integrity_compromised")
        }));
    }
}
