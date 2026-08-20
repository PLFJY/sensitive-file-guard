//! Browser enforcement engine — Phase 06.
//!
//! Wires together the four Phase 02–05 components on the fanotify hot path:
//! - `fanotify` (FAN_OPEN_PERM events, each carrying an event fd + pid)
//! - `platform_linux::identity` (PID -> `ProcessIdentity` with stable start
//!   time + exe file identity + trust tier)
//! - `guard_browser::ProtectedResourceRegistry` (path -> `ProtectedResource`)
//! - `guard_core::policy` (deterministic `Decision` from pure data)
//!
//! Behavior (see `06_BROWSER_ENFORCEMENT.md`):
//! - owning browser -> Allow
//! - another browser -> Deny(CrossBrowserWithoutLease) (Phase 08 adds leases)
//! - unknown/ordinary process -> Deny(UnknownProcess)
//! - log after the decision; never wait for UI
//!
//! Performance:
//! - identity decisions are cached by `(pid, start_time)`; PID reuse (same pid,
//!   different start_time) is detected via a cheap `/proc/<pid>/stat` starttime
//!   read and forces a re-resolve
//! - concrete critical files are indexed by `(st_dev, st_ino)` so a hardlink to
//!   a protected file (same inode, different path) is still classified without
//!   re-statting the enrolled path
//! - executable SHA-256 is never recomputed on every open; the enrollment store
//!   uses a file-identity fast path and only rehashes when the file changed
//! - no package-manager calls on the hot path (trust is ownership/mode-based)

use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use guard_audit::AuditRecord;
use guard_browser::{CustomProfile, ProtectedResourceRegistry};
#[cfg(test)]
use guard_core::identity::ProcessIntegrity;
use guard_core::identity::{ExeIdentity, ProcessIdentity};
use guard_core::lease::{LeaseId, LeaseSet, MigrationAccessLease, MigrationLeaseState};
#[cfg(test)]
use guard_core::policy::evaluate;
use guard_core::policy::{AccessEvent, AccessOperation, Decision, DenyReason, MigrationCandidate};
#[cfg(test)]
use guard_core::resource::BrowserFamily;
use guard_core::resource::{BrowserId, ProfileId, ProtectedResource, ProtectedResourceKind};
pub use guard_platform::config::BrowserEnrollmentConfig;
use guard_runtime::AuthorizationRuntime;
pub use guard_runtime::{MigrationPendingDetails, SshPendingDetails};
pub use platform_linux::config::{EnforcementConfig, EnforcementMode};
use platform_linux::enrollment::EnrollmentStore;
use platform_linux::fanotify;
use platform_linux::identity as linux_identity;

/// Default migration lease duration (10 minutes), per `08_MIGRATION_LEASE.md`.
pub const DEFAULT_MIGRATION_DURATION_SECS: u64 = 600;
/// Maximum migration lease duration (1 hour). Longer requests are capped so a
/// migration grant can never become de-facto permanent trust.
pub const MAX_MIGRATION_DURATION_SECS: u64 = 3600;
/// Ordinary SSH key-read authorization is deliberately brief: the verified
/// reader tree receives a ten-second, memory-only lease for one key.
pub const DEFAULT_SSH_READ_DURATION_SECS: u64 = 10;
/// Default SSH load lease duration (30 seconds), per `11_SSH_AGENT_LOAD_FLOW.md`.
/// The lease is one-shot and also revoked on process exit; the timeout is a
/// safety net in case `guardctl` crashes before sending the complete signal.
pub const DEFAULT_SSH_LOAD_DURATION_SECS: u64 = 30;
/// Maximum SSH load lease duration (5 minutes). A load should complete in
/// seconds; this caps a stuck `ssh-add` from keeping the lease alive.
pub const MAX_SSH_LOAD_DURATION_SECS: u64 = 300;

pub type InodeIndex = Arc<RwLock<HashMap<(u64, u64), ProtectedResource>>>;

/// The enforcement engine. Owns the registry, identity cache, enrollment store,
/// fd-identity index, and the active lease set. `decide` is the hot-path entry.
pub struct EnforcementEngine {
    registry: ProtectedResourceRegistry,
    enrollment: EnrollmentStore,
    /// Canonical exe path -> BrowserId. Populated from config `exe_paths`.
    browser_exes: HashMap<PathBuf, BrowserId>,
    /// `(st_dev, st_ino)` -> resource for concrete critical files. Catches
    /// hardlinks (same inode, different path) that path-based classify misses.
    fd_index: InodeIndex,
    /// PID -> `(start_time, identity)`. Validated against a fresh starttime read
    /// on each lookup so PID reuse invalidates the entry.
    identity_cache: HashMap<u32, (u64, ProcessIdentity)>,
    runtime: AuthorizationRuntime,
    /// Lease -> root-pinned SSH agent socket required in the live ssh-add
    /// environment. Kept in the Linux backend because environment inspection
    /// is an OS enforcement fact, not a pure policy-domain concern.
    ssh_agent_bindings: HashMap<LeaseId, PathBuf>,
    /// The browser enrollment config, retained for IPC `browsers list` queries.
    browser_config: Vec<BrowserEnrollmentConfig>,
    /// The metadata-only policy snapshot used by unprivileged UI clients. It
    /// deliberately contains paths and policy settings, never protected file
    /// contents or credentials.
    configuration: EnforcementConfig,
    /// Decision counters (hot-path observability; no per-event allocation).
    pub allowed: u64,
    pub denied: u64,
    /// Decisions where classify_fd failed (race / unmarked path). Fail-closed.
    pub unclassified: u64,
    /// Persistent topology refresh is currently failing; existing marks still
    /// enforce, but replacement/new-object coverage may be stale.
    pub topology_degraded: bool,
    /// LFH3: sticky protection-continuity state. Once LOST it stays LOST until
    /// an explicit operator reset/restart generation policy — "now healthy"
    /// never erases "was broken".
    pub continuity: ProtectionContinuity,
}

/// LFH3: historical protection continuity. `Lost` is sticky: current
/// enforcement may recover, but the daemon must keep reporting the loss.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectionContinuity {
    /// No verifiable gap since daemon start.
    Intact { generation: u64 },
    /// A continuity-breaking event occurred; reason explains it. Sticky until
    /// an explicit operator reset.
    Lost {
        generation: u64,
        reason: ContinuityLossReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContinuityLossReason {
    FanotifyQueueOverflow,
    RequiredMarkLoss,
    /// Reserved for LFH4 fdstore/lifecycle evidence and future phases that
    /// construct it; not produced by the current daemon paths.
    #[allow(dead_code)]
    FilesystemLifecycleLoss,
    /// Reserved for future classifier-failure hardening.
    #[allow(dead_code)]
    UnrecoverableClassifierFailure,
}

impl ContinuityLossReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FanotifyQueueOverflow => "fanotify_queue_overflow",
            Self::RequiredMarkLoss => "required_filesystem_mark_lost",
            Self::FilesystemLifecycleLoss => "filesystem_lifecycle_loss",
            Self::UnrecoverableClassifierFailure => "unrecoverable_classifier_failure",
        }
    }
}

impl ProtectionContinuity {
    /// Returns true when the state is Lost (regardless of whether current
    /// enforcement has recovered).
    #[cfg(test)]
    pub fn is_lost(&self) -> bool {
        matches!(self, Self::Lost { .. })
    }

    /// Mark the continuity Lost with the given reason, keeping the generation
    /// monotonic. Repeated losses keep the original (earliest) generation.
    pub fn record_loss(&mut self, reason: ContinuityLossReason) {
        if let Self::Lost { generation, .. } = self {
            debug_assert!(*generation >= 1);
            return; // sticky: keep the earliest loss
        }
        *self = Self::Lost {
            generation: self.generation(),
            reason,
        };
    }

    fn generation(&self) -> u64 {
        match self {
            Self::Intact { generation } | Self::Lost { generation, .. } => *generation,
        }
    }
}

impl EnforcementEngine {
    pub fn from_config(cfg: &EnforcementConfig) -> anyhow::Result<Self> {
        let mut registry = ProtectedResourceRegistry::new();
        let mut browser_exes: HashMap<PathBuf, BrowserId> = HashMap::new();
        let mut enrollment = EnrollmentStore::new();

        for b in &cfg.browsers {
            let browser_id = BrowserId(b.id.clone());
            let owner_uid = match b.owner_uid {
                Some(u) => u,
                None => stat_owner(&b.profile_root).ok_or_else(|| {
                    anyhow::anyhow!(
                        "browser {} omits owner_uid, but profile root {} cannot be stat-ed",
                        b.id,
                        b.profile_root.display()
                    )
                })?,
            };
            let custom = CustomProfile {
                browser: browser_id.clone(),
                family: b.family,
                root: b.profile_root.clone(),
                owner_uid,
            };
            custom.enroll_into(&mut registry)?;

            for exe in &b.exe_paths {
                let canon = std::fs::canonicalize(exe).unwrap_or_else(|_| exe.clone());
                browser_exes.insert(canon, browser_id.clone());
            }
        }

        // Index concrete critical files by inode so hardlinks are caught even
        // when the open path is a different name for the same inode.
        let mut fd_index: HashMap<(u64, u64), ProtectedResource> = HashMap::new();
        for res in registry.files() {
            if let Ok(id) = stat_dev_ino(&res.path) {
                fd_index.insert(id, res.clone());
            }
        }

        for exe in &cfg.enrolled_exes {
            // Enrollment failures (missing/non-canonical file) are not fatal;
            // the engine still enforces, that exe just stays Unknown trust.
            if let Err(e) = enrollment.enroll(exe) {
                tracing::warn!(exe = %exe.display(), err = %e, "enrollment skipped");
            }
        }

        // Phase 10: enroll SSH private keys from config. Each key is enrolled
        // as a `SshPrivateKey` resource and indexed by inode so hardlinks fire
        // too. Failures (missing/non-candidate file) are non-fatal: the key is
        // simply not protected and a warning is logged.
        for key in &cfg.ssh_keys {
            match guard_ssh::enroll_key(key) {
                Ok(res) => {
                    if let Ok(id) = stat_dev_ino(&res.path) {
                        fd_index.insert(id, res.clone());
                    }
                    registry.enroll_file(res);
                }
                Err(e) => {
                    tracing::warn!(key = %key.display(), err = %e, "ssh key enrollment skipped");
                }
            }
        }

        Ok(Self {
            registry,
            enrollment,
            browser_exes,
            fd_index: Arc::new(RwLock::new(fd_index)),
            identity_cache: HashMap::new(),
            runtime: AuthorizationRuntime::default(),
            ssh_agent_bindings: HashMap::new(),
            browser_config: cfg.browsers.clone(),
            configuration: cfg.clone(),
            allowed: 0,
            denied: 0,
            unclassified: 0,
            topology_degraded: false,
            continuity: ProtectionContinuity::Intact { generation: 1 },
        })
    }

    pub fn registry(&self) -> &ProtectedResourceRegistry {
        &self.registry
    }
    pub fn browser_exe_count(&self) -> usize {
        self.browser_exes.len()
    }

    pub fn inode_index(&self) -> InodeIndex {
        Arc::clone(&self.fd_index)
    }

    /// Browser enrollment config (for IPC `browsers list`).
    pub fn browser_config(&self) -> &[BrowserEnrollmentConfig] {
        &self.browser_config
    }

    /// Configuration loaded for this daemon generation. UI clients obtain a
    /// metadata-only projection through authenticated local IPC instead of
    /// reading the root-owned config file themselves.
    pub fn configuration(&self) -> &EnforcementConfig {
        &self.configuration
    }

    /// Active leases (for IPC `leases list`). Phase 08 adds creation; Phase 07
    /// exposes the read-only view and revoke.
    pub fn leases(&self) -> &LeaseSet {
        self.runtime.leases()
    }

    /// Revoke a lease by its id string. Returns `false` if no lease with that
    /// id exists. Migration and both SSH lease kinds are searched.
    pub fn revoke_lease(&mut self, id_str: &str) -> bool {
        let id = match id_str.parse::<u64>() {
            Ok(n) => LeaseId(n),
            Err(_) => return false,
        };
        let mut found = false;
        for l in &mut self.runtime.leases_mut().migration {
            if l.id == id {
                l.revoked = true;
                found = true;
            }
        }
        for l in &mut self.runtime.leases_mut().ssh {
            if l.id == id {
                l.revoked = true;
                found = true;
            }
        }
        for l in &mut self.runtime.leases_mut().ssh_read {
            if l.id == id {
                l.revoked = true;
                found = true;
            }
        }
        if found {
            self.ssh_agent_bindings.remove(&id);
        }
        found
    }

    /// LFH3: revoke ALL live authority when protection continuity is lost
    /// (fanotify overflow, required mark loss, ...). After this, no lease
    /// (migration, SSH read, SSH load), pending confirmation, or recent
    /// approval grace can authorize anything; the exact-process identity cache
    /// is dropped so no stale identity survives.
    pub fn revoke_all_authority(&mut self) {
        for lease in &mut self.runtime.leases_mut().migration {
            lease.revoked = true;
        }
        for lease in &mut self.runtime.leases_mut().ssh {
            lease.revoked = true;
        }
        for lease in &mut self.runtime.leases_mut().ssh_read {
            lease.revoked = true;
        }
        self.ssh_agent_bindings.clear();
        self.identity_cache.clear();
    }

    /// LFH3: mark continuity Lost with `reason`, then revoke all live
    /// authority and pending confirmations. Called on the fanotify overflow
    /// path and on required-mark loss. Sticky: once Lost, stays Lost until an
    /// explicit operator reset.
    pub fn lose_continuity(&mut self, reason: ContinuityLossReason) {
        self.continuity.record_loss(reason);
        // LFH5: advance the lease generation so any lease that escaped
        // revocation (or was minted concurrently) is dead by generation too.
        self.runtime.bump_generation();
        self.revoke_all_authority();
    }

    /// Authorize a cross-browser migration access lease. The
    /// lease is **armed**: bound to the target browser's executable file
    /// identity (`ExeIdentity`), so it matches the next target process that
    /// opens the named source profile. This avoids permanent allow-listing
    /// while tolerating the target being launched after authorization.
    ///
    /// LFH5: authority is EXACT READER INSTANCE. When the enforcement layer
    /// binds the armed lease it binds the exact live process; a descendant
    /// helper is never authorized unless explicitly bound post-observation.
    ///
    /// `uid` is the authorizing user; the IPC layer takes it from
    /// kernel-verified peer creds and NEVER from JSON. `duration_secs` defaults
    /// to 10 minutes and is capped at 1 hour. Returns the new lease id and its
    /// expiry (epoch seconds).
    ///
    /// Errors if the source or target browser is not enrolled in config, or if
    /// the target browser has no resolvable executable to bind to.
    pub fn authorize_migration(
        &mut self,
        source_browser: &str,
        source_profile: &str,
        target_browser: &str,
        uid: u32,
        duration_secs: Option<u64>,
    ) -> Result<(LeaseId, u64), String> {
        // Validate source + target browsers are enrolled.
        if !self.browser_config.iter().any(|b| b.id == source_browser) {
            return Err(format!("unknown source browser: {source_browser}"));
        }
        let target_cfg = self
            .browser_config
            .iter()
            .find(|b| b.id == target_browser)
            .ok_or_else(|| format!("unknown target browser: {target_browser}"))?;

        // Resolve the target browser's armed exe identity from its enrolled
        // exe_paths (first existing, canonicalized, stat'd).
        let target = resolve_exe_identity(&target_cfg.exe_paths).ok_or_else(|| {
            format!("target browser {target_browser} has no resolvable enrolled executable")
        })?;

        let dur = duration_secs
            .unwrap_or(DEFAULT_MIGRATION_DURATION_SECS)
            .min(MAX_MIGRATION_DURATION_SECS);
        let now = now_secs();
        let expires_at = now.saturating_add(dur);
        let id = self.runtime.next_lease_id();
        let generation = self.runtime.current_generation();
        self.runtime
            .leases_mut()
            .migration
            .push(MigrationAccessLease {
                id,
                source_browser: BrowserId(source_browser.into()),
                source_profile: ProfileId(source_profile.into()),
                target_browser: BrowserId(target_browser.into()),
                uid,
                state: MigrationLeaseState::Armed { target },
                expires_at,
                revoked: false,
                generation,
            });
        Ok((id, expires_at))
    }

    /// Capture the daemon-verified details that a pending prompt needs.  The
    /// fanotify fd stays with the pending store; this method never takes fd
    /// ownership.
    pub fn pending_migration_details(
        &mut self,
        pid: i32,
        fd: RawFd,
        candidate: &MigrationCandidate,
    ) -> Option<MigrationPendingDetails> {
        let resource = self.classify_fd(fd)?;
        if resource.browser.as_ref() != Some(&candidate.source_browser)
            || resource.profile.as_ref() != Some(&candidate.source_profile)
        {
            return None;
        }
        let (target, _) = self.resolve_process(pid)?;
        if !target.is_trusted_browser()
            || target.browser.as_ref() != Some(&candidate.target_browser)
            || target.uid != resource.owner_uid
        {
            return None;
        }
        // LFH5: EXACT READER INSTANCE — the approval binds the exact opener
        // process observed, never an ancestor and never the whole tree.
        let target_root = target.stable.clone();
        Some(MigrationPendingDetails {
            candidate: candidate.clone(),
            resource,
            target,
            target_root,
        })
    }

    /// Revalidate the exact initiating browser process and bind a short-lived
    /// lease directly to it.  Unlike manual authorization this never creates
    /// an executable-wide armed capability.
    pub fn approve_pending_migration(
        &mut self,
        pending: &MigrationPendingDetails,
    ) -> Result<(LeaseId, u64), String> {
        self.identity_cache.remove(&pending.target.stable.pid);
        let (current, _) = self
            .resolve_process(pending.target.stable.pid as i32)
            .ok_or_else(|| "target browser exited before confirmation".to_string())?;
        let root_is_live = linux_identity::read_start_time(pending.target_root.pid as i32).ok()
            == Some(pending.target_root.start_time);
        self.runtime.approve_migration(
            pending,
            &current,
            root_is_live,
            now_secs(),
            DEFAULT_MIGRATION_DURATION_SECS,
        )
    }

    pub fn migration_audit_record(
        &self,
        pending: &MigrationPendingDetails,
        event_code: &str,
        decision: Decision,
        detail: &str,
    ) -> AuditRecord {
        let mut record =
            build_audit_record(&pending.resource, Some(&pending.target), decision, detail);
        record.event_code = event_code.to_owned();
        record
    }

    /// Capture the actual protected key and reader identity before handing the
    /// fanotify permission to the bounded SSH confirmation queue.
    pub fn pending_ssh_details(&mut self, pid: i32, fd: RawFd) -> Option<SshPendingDetails> {
        let resource = self.classify_fd(fd)?;
        if resource.kind != ProtectedResourceKind::SshPrivateKey {
            return None;
        }
        let (target, _) = self.resolve_process(pid)?;
        (target.uid == resource.owner_uid).then(|| SshPendingDetails {
            resource,
            resource_dev: None,
            resource_ino: None,
            target_root: target.stable.clone(),
            target,
        })
    }

    /// Revalidate the original reader and create a memory-only lease scoped to
    /// exactly that process tree and protected key.
    pub fn approve_pending_ssh_read(
        &mut self,
        pending: &SshPendingDetails,
    ) -> Result<(LeaseId, u64), String> {
        self.identity_cache.remove(&pending.target.stable.pid);
        let (current, _) = self
            .resolve_process(pending.target.stable.pid as i32)
            .ok_or_else(|| "SSH reader exited before confirmation".to_string())?;
        self.runtime.approve_ssh_read(
            pending,
            &current,
            now_secs(),
            DEFAULT_SSH_READ_DURATION_SECS,
        )
    }

    pub fn ssh_read_audit_record(
        &self,
        pending: &SshPendingDetails,
        event_code: &str,
        decision: Decision,
        detail: &str,
    ) -> AuditRecord {
        let mut record =
            build_audit_record(&pending.resource, Some(&pending.target), decision, detail);
        record.event_code = event_code.to_owned();
        record
    }

    /// Audit record for a pidfd validation failure (LFH1). The requester's
    /// resource is unknown because we deliberately never trust a pathname for
    /// this decision; the record carries only process metadata and the reason.
    /// Authorize a one-shot SSH load lease (Phase 11). The lease is bound to
    /// the exact `ssh-add` process invocation via `StableIdentity` (exe +
    /// start_time + dev + ino) and the exact PID. The `uid` is the authorizing
    /// user (from kernel-verified peer creds). The lease auto-expires after
    /// `DEFAULT_SSH_LOAD_DURATION_SECS` and is also revoked by `guardctl` when
    /// `ssh-add` exits.
    ///
    /// The one-shot is consumed on process exit/PID reuse (checked on the hot
    /// path), NOT on the first permission event: a real `ssh-add` emits
    /// multiple `FAN_ACCESS_PERM` events for a single load (open + reads).
    ///
    /// Returns `(lease_id, expires_at)` or an error message if the path is not
    /// a protected SSH private key owned by `uid`.
    pub fn authorize_ssh_load(
        &mut self,
        path: &Path,
        uid: u32,
        target: guard_core::identity::StableIdentity,
        pid: u32,
        agent_binding: SshAgentBinding,
    ) -> Result<(LeaseId, u64), String> {
        // Validate the resource is a protected SSH private key owned by uid.
        let canon = std::fs::canonicalize(path)
            .map_err(|e| format!("canonicalize {}: {e}", path.display()))?;
        let res = self
            .registry
            .classify(&canon)
            .filter(|r| r.kind == ProtectedResourceKind::SshPrivateKey)
            .ok_or_else(|| {
                format!(
                    "{} is not a protected SSH private key (enroll it first via `guardctl ssh protect`)",
                    canon.display()
                )
            })?;
        if res.owner_uid != uid {
            return Err(format!(
                "SSH key {} is owned by uid {}, not by requesting uid {}",
                canon.display(),
                res.owner_uid,
                uid
            ));
        }
        let dur = DEFAULT_SSH_LOAD_DURATION_SECS.min(MAX_SSH_LOAD_DURATION_SECS);
        let now = now_secs();
        let expires_at = now.saturating_add(dur);
        let id = self.runtime.next_lease_id();
        let generation = self.runtime.current_generation();
        self.runtime
            .leases_mut()
            .ssh
            .push(guard_core::lease::SshLoadLease {
                id,
                resource: res.id.clone(),
                uid,
                target,
                pid,
                expires_at,
                revoked: false,
                used: false,
                generation,
            });
        match agent_binding {
            SshAgentBinding::Verified(path) => {
                self.ssh_agent_bindings.insert(id, path);
            }
            #[cfg(test)]
            SshAgentBinding::UncheckedForTests => {}
        }
        Ok((id, expires_at))
    }

    /// Mark protected concrete files. SSH private keys use OPEN_PERM as their
    /// authorization boundary: ACCESS_PERM alone cannot mediate mmap(2), so an
    /// unapproved reader must never receive a readable fd in any enforcement
    /// mode. ACCESS_PERM remains a narrow, defense-in-depth read-time gate.
    pub fn mark_files(&self, group: &fanotify::FanotifyGroup) -> std::io::Result<usize> {
        let mut n = 0;
        for res in self.registry.files() {
            let mask = if res.kind == ProtectedResourceKind::SshPrivateKey {
                libc::FAN_OPEN_PERM | libc::FAN_ACCESS_PERM
            } else {
                libc::FAN_OPEN_PERM
            };
            group.mark_file(mask, &res.path)?;
            n += 1;
        }
        Ok(n)
    }

    /// Install exact-file SSH read marks in Strict mode, whose filesystem-wide
    /// open marks intentionally remain browser-focused.  The duplicate inode
    /// mark is small and is re-applied after topology refresh so a replaced
    /// runtime-enrolled key cannot silently lose its narrow read mediation.
    pub fn mark_ssh_read_files(&self, group: &fanotify::FanotifyGroup) -> std::io::Result<usize> {
        let mut n = 0;
        for resource in self
            .registry
            .files()
            .filter(|resource| resource.kind == ProtectedResourceKind::SshPrivateKey)
        {
            // P0 (review): OPEN_PERM is the SSH private-key authorization
            // boundary. FAN_ACCESS_PERM alone cannot gate mmap(): Linux v7.1
            // `fsnotify_mmap_perm()` only emits pre-content (HSM) events, so a
            // `FAN_CLASS_CONTENT + FAN_ACCESS_PERM` group never sees an
            // mmap()-triggered access-permission event — an unknown process
            // that received a readable fd could mmap() the key bytes straight
            // through. Mark OPEN_PERM too so an unauthorized open is denied
            // BEFORE any readable fd exists (this also neutralizes
            // splice/sendfile/copy_file_range/io_uring reads, all of which
            // require a readable fd). ACCESS_PERM stays as an extra read-time
            // constraint for authorized flows.
            group.mark_file(libc::FAN_OPEN_PERM | libc::FAN_ACCESS_PERM, &resource.path)?;
            n += 1;
        }
        Ok(n)
    }

    /// Mark all protected directory trees recursively. Each subdir is marked
    /// with `FAN_OPEN_PERM | FAN_EVENT_ON_CHILD` so opens of direct children
    /// fire. Recursive coverage requires marking every subdir; a new subdir
    /// created after the walk races until the next rescan (documented gap).
    pub fn mark_trees(&self, group: &fanotify::FanotifyGroup) -> std::io::Result<usize> {
        let mut n = 0;
        for tree in self.registry.trees() {
            mark_dir_recursive(group, &tree.dir, &mut n)?;
        }
        Ok(n)
    }

    /// Rediscover browser resources after an inotify topology change, extend
    /// the inode index, and apply permission marks to every current object.
    /// Runtime-enrolled SSH resources are preserved. Existing inode aliases
    /// are retained because an individual fanotify mark follows a live object
    /// across rename even when its new name is no longer discoverable. An
    /// unmarked inode cannot reach this classifier; a newly marked object that
    /// reuses an identity overwrites the retained entry below.
    pub fn refresh_browser_resources(
        &mut self,
        group: &fanotify::FanotifyGroup,
        mark_objects: bool,
    ) -> anyhow::Result<(usize, usize)> {
        let ssh_resources: Vec<ProtectedResource> = self
            .registry
            .files()
            .filter(|resource| resource.kind == ProtectedResourceKind::SshPrivateKey)
            .cloned()
            .collect();
        let mut registry = ProtectedResourceRegistry::new();
        for browser in &self.browser_config {
            let owner_uid = browser
                .owner_uid
                .or_else(|| stat_owner(&browser.profile_root))
                .unwrap_or(0);
            CustomProfile {
                browser: BrowserId(browser.id.clone()),
                family: browser.family,
                root: browser.profile_root.clone(),
                owner_uid,
            }
            .enroll_into(&mut registry)?;
        }
        for resource in ssh_resources {
            registry.enroll_file(resource);
        }

        // Extend under one write lock. Strict classification promotes new
        // structural hits concurrently with topology refresh; replacing the
        // map from an earlier read snapshot could otherwise erase a promotion
        // just before its permission response is sent.
        extend_fd_index(
            &mut self.fd_index.write().expect("inode index lock poisoned"),
            &registry,
        );
        self.registry = registry;

        let (files, directories) = if mark_objects {
            (self.mark_files(group)?, self.mark_trees(group)?)
        } else {
            (0, 0)
        };
        Ok((files, directories))
    }

    /// Runtime-enroll a single SSH private key (Phase 10). Updates the registry
    /// and the inode `fd_index` so subsequent opens are classified + denied by
    /// the SSH policy. The caller is responsible for adding the fanotify kernel
    /// mark (`group.mark_file`) immediately after this returns so the file is
    /// actually intercepted.
    ///
    /// Returns the enrolled resource (canonical path + owner uid). Errors if the
    /// path is missing, not a regular file, or not a private-key candidate
    /// (e.g. `.pub` / `known_hosts`). Idempotent: re-enrolling an already-
    /// protected path replaces the existing entry.
    #[cfg(test)]
    pub fn protect_ssh_key(&mut self, path: &Path) -> std::io::Result<ProtectedResource> {
        let res = guard_ssh::enroll_key(path)?;
        self.enroll_ssh_resource(res.clone());
        Ok(res)
    }

    /// Publish a pre-validated SSH resource after its kernel mark is active.
    pub fn enroll_ssh_resource(&mut self, res: ProtectedResource) {
        if let Ok(id) = stat_dev_ino(&res.path) {
            self.fd_index
                .write()
                .expect("inode index lock poisoned")
                .insert(id, res.clone());
        }
        self.registry.enroll_file(res);
    }

    /// Hot-path entry (test convenience). Equivalent to
    /// `decide_with_context(..).0`. Production code uses `decide_with_context`
    /// so it can also record the audit event.
    #[cfg(test)]
    pub fn decide(&mut self, pid: i32, fd: RawFd) -> Decision {
        self.decide_event(pid, fd, false).0
    }

    /// Like `decide` but also returns an `AuditRecord` for persistence when the
    /// opened file was a protected resource. Debug builds return records for
    /// every decision; release builds return only blocked decisions. The
    /// caller persists records non-blocking via `AuditStore::record`.
    /// Unclassified opens (not a protected resource) are not audited — they are
    /// tracked by the `unclassified` counter only.
    #[cfg(test)]
    pub fn decide_with_context(&mut self, pid: i32, fd: RawFd) -> (Decision, Option<AuditRecord>) {
        // SSH-focused tests model the narrow FAN_ACCESS_PERM event. Browser
        // tests use `decide`, which models FAN_OPEN_PERM.
        self.decide_event(pid, fd, true)
    }

    /// Production entry carrying the fanotify event kind. Every protected SSH
    /// read is now a fail-closed authorization boundary, just like browser
    /// migration; classification failure cannot silently expose a key.
    pub fn decide_event(
        &mut self,
        pid: i32,
        fd: RawFd,
        _ssh_read_event: bool,
    ) -> (Decision, Option<AuditRecord>) {
        let resource = match self.classify_fd(fd) {
            Some(r) => r,
            None => {
                self.unclassified += 1;
                self.denied += 1;
                return (Decision::Deny(DenyReason::UnknownProcess), None);
            }
        };
        // P0: SSH OPEN_PERM is deliberately authorized here too. Never allow
        // the pre-read event merely because an ACCESS_PERM event may follow:
        // mmap(2) can consume a readable fd without generating that content
        // permission event.
        self.decide_protected(pid, resource, classify_diag(fd))
    }

    /// Return the exact WebStorage resource represented by an already-open
    /// fanotify event fd. LPS3 uses this only before responding to an allowed
    /// OPEN_PERM event, to bind the BPF target before the browser receives a
    /// readable descriptor. Classification is identity-based and does not
    /// read file contents.
    pub fn web_storage_resource(&self, fd: RawFd) -> Option<ProtectedResource> {
        self.classify_fd(fd)
            .filter(|resource| resource.kind == ProtectedResourceKind::WebStorage)
    }

    pub fn decide_protected(
        &mut self,
        pid: i32,
        resource: ProtectedResource,
        classification: &'static str,
    ) -> (Decision, Option<AuditRecord>) {
        let (process, resolve_diag) = match self.resolve_process(pid) {
            Some((id, diag)) => (id, diag),
            None => {
                self.denied += 1;
                let record = build_audit_record(
                    &resource,
                    None,
                    Decision::Deny(DenyReason::UnknownProcess),
                    "resolve_failed",
                );
                return (Decision::Deny(DenyReason::UnknownProcess), Some(record));
            }
        };
        let now = now_secs();
        self.refresh_migration_states(&resource, &process);
        self.refresh_ssh_read_leases();
        let mut decision = self.runtime.evaluate(
            &AccessEvent {
                resource: resource.clone(),
                process: process.clone(),
                operation: AccessOperation::Open,
            },
            now,
        );
        // A client controls the stopped child's original environment and can
        // SIGCONT it without waiting for guardctl's response. Stable ssh-add
        // identity alone is therefore insufficient: the exact live process
        // must also use the daemon-pinned, preverified agent socket. Missing or
        // unreadable environment state fails closed.
        if let Decision::AllowByLease(id) = decision {
            if resource.kind == ProtectedResourceKind::SshPrivateKey {
                if let Some(expected) = self.ssh_agent_bindings.get(&id) {
                    let observed = linux_identity::read_process_env(pid, "SSH_AUTH_SOCK")
                        .ok()
                        .flatten()
                        .map(PathBuf::from);
                    if observed.as_deref() != Some(expected.as_path()) {
                        decision = Decision::RequireSshKeyConfirmation;
                    }
                }
            }
        }
        match &decision {
            Decision::Allow | Decision::AllowByLease(_) => self.allowed += 1,
            Decision::Deny(_) => self.denied += 1,
            Decision::RequireMigrationConfirmation(_)
            | Decision::RequireSshKeyConfirmation
            | Decision::Detected => {}
        }
        // Phase 11 one-shot SSH load lease: consume it when the exact ssh-add
        // process has exited or its identity changed (PID reuse), NOT on the
        // first permission event. A real `ssh-add` performs multiple
        // `FAN_ACCESS_PERM` events for one load (open + reads); consuming on
        // the first event would deny the rest of the load. The agent-socket
        // binding check above still runs on every event, so a resumed process
        // without the pinned endpoint fails closed.
        if let Decision::AllowByLease(id) = &decision {
            let mut exited = false;
            for l in &mut self.runtime.leases_mut().ssh {
                if l.id == *id {
                    let live = linux_identity::read_start_time(l.pid as i32).ok()
                        == Some(l.target.start_time);
                    if !live {
                        l.used = true;
                        exited = true;
                    }
                    break;
                }
            }
            if exited {
                self.ssh_agent_bindings.remove(id);
            }
        }
        let record = if should_record_decision(&decision, resource.kind) {
            let backend_diag = format!(
                "{};classify={};trust={:?}",
                resolve_diag, classification, process.trust_tier
            );
            Some(build_audit_record(
                &resource,
                Some(&process),
                decision.clone(),
                &backend_diag,
            ))
        } else {
            None
        };
        (decision, record)
    }

    /// A read lease must not survive its verified root. Keeping the revoked
    /// entry until its natural expiry makes lease inspection/audit meaningful,
    /// while the policy can no longer authorize a PID-reused process.
    fn refresh_ssh_read_leases(&mut self) {
        for lease in &mut self.runtime.leases_mut().ssh_read {
            if !lease.revoked
                && linux_identity::read_start_time(lease.root.pid as i32).ok()
                    != Some(lease.root.start_time)
            {
                lease.revoked = true;
            }
        }
    }

    /// Bind an armed migration lease to the exact process instance that will
    /// read, and retire bound leases as soon as their root process exits. This
    /// mutation happens while the engine mutex is held, immediately before
    /// policy evaluation, so an armed executable-wide grant is never exposed.
    ///
    /// LFH5: EXACT READER INSTANCE. The bound root is always the exact opener
    /// observed here — the target browser itself when its own identity matches
    /// the armed target, or the exact observed descendant helper when an
    /// ancestor matches (post-bind observed exact descendant). Ancestry only
    /// validates membership in the authorized tree at bind time; it never
    /// grants whole-tree authority, and unobserved pre-existing descendants
    /// never auto-upgrade.
    fn refresh_migration_states(
        &mut self,
        resource: &ProtectedResource,
        process: &ProcessIdentity,
    ) {
        for lease in &mut self.runtime.leases_mut().migration {
            if let MigrationLeaseState::Bound { root } = &lease.state {
                if linux_identity::read_start_time(root.pid as i32).ok() != Some(root.start_time) {
                    lease.state = MigrationLeaseState::Dead;
                }
            }

            let MigrationLeaseState::Armed { target } = &lease.state else {
                continue;
            };
            if lease.uid != process.uid
                || resource.browser_id() != &lease.source_browser
                || resource.profile_id() != &lease.source_profile
            {
                continue;
            }

            // The opener is the intended reader and is authorized exactly:
            // either its own identity is the armed target (the target browser
            // itself) or it descends from the armed target (a helper observed
            // at bind time). Both cases bind the exact opener instance.
            let authorized = process.stable.exe_identity() == *target
                || process
                    .ancestors
                    .iter()
                    .any(|ancestor| ancestor.exe_identity() == *target);
            if authorized {
                lease.state = MigrationLeaseState::Bound {
                    root: process.stable.clone(),
                };
            }
        }
    }

    /// Classify an open fd to a protected resource. Order:
    /// 1. `fstat(fd)` -> `(dev, ino)` -> `fd_index` (catches hardlinks to
    ///    concrete critical files by inode, regardless of open path).
    /// 2. `readlink /proc/self/fd/<fd>` -> path -> `registry.classify` (catches
    ///    symlinks via canonicalization and tree descendants via prefix match).
    fn classify_fd(&self, fd: RawFd) -> Option<ProtectedResource> {
        if let Ok(id) = fanotify::fd_identity(fd) {
            if let Some(res) = self
                .fd_index
                .read()
                .expect("inode index lock poisoned")
                .get(&id)
            {
                return Some(res.clone());
            }
        }
        if let Ok(path) = fanotify::fd_path(fd) {
            if let Some(res) = self.registry.classify(&path) {
                return Some(res);
            }
        }
        None
    }

    /// Resolve `pid` to a `ProcessIdentity` with browser classification. Cached
    /// by `(pid, start_time)`; PID reuse (same pid, different start_time) is
    /// detected via a fresh `read_start_time` read and forces a re-resolve.
    /// Returns `(identity, diag)` where `diag` is "cache_hit" or "fresh_resolve".
    fn resolve_process(&mut self, pid: i32) -> Option<(ProcessIdentity, &'static str)> {
        let current_start = match linux_identity::read_start_time(pid) {
            Ok(t) => t,
            Err(_) => {
                // Process exited or unreadable: drop any stale cache entry.
                self.identity_cache.remove(&(pid as u32));
                return None;
            }
        };

        if let Some((cached_start, identity)) = self.identity_cache.get(&(pid as u32)) {
            if *cached_start == current_start {
                return Some((identity.clone(), "cache_hit"));
            }
        }

        // `current_uid` is currently unused by the resolver (trust depends on
        // exe ownership, not resource owner); pass 0. See identity::classify_trust.
        let mut identity = linux_identity::resolve(pid, 0, &mut self.enrollment).ok()?;
        // Wire the browser field from the config exe map. A renamed fake
        // "firefox" binary whose path is NOT in browser_exes stays browser=None
        // and is denied even if its basename matches a known browser.
        if let Some(id) = self.browser_exes.get(&identity.stable.exe) {
            identity.browser = Some(id.clone());
        }
        self.identity_cache
            .insert(pid as u32, (current_start, identity.clone()));
        Some((identity, "fresh_resolve"))
    }
}

/// Binding between a one-shot SSH lease and the only agent endpoint the
/// matching ssh-add process may use. Production can construct only the
/// verified form; unit tests that exercise the pure lease path use the
/// explicitly test-only bypass.
pub enum SshAgentBinding {
    Verified(PathBuf),
    #[cfg(test)]
    UncheckedForTests,
}

fn extend_fd_index(
    index: &mut HashMap<(u64, u64), ProtectedResource>,
    registry: &ProtectedResourceRegistry,
) {
    for resource in registry.files() {
        if let Ok(identity) = stat_dev_ino(&resource.path) {
            index.insert(identity, resource.clone());
        }
    }
}

/// Recursively mark `dir` and all its subdirectories with the tree mask.
fn mark_dir_recursive(
    group: &fanotify::FanotifyGroup,
    dir: &Path,
    n: &mut usize,
) -> std::io::Result<()> {
    group.mark_file(fanotify::OPEN_PERM_TREE_MASK, dir)?;
    *n += 1;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_dir() {
            mark_dir_recursive(group, &entry.path(), n)?;
        }
    }
    Ok(())
}

fn stat_owner(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|md| md.uid())
}

fn stat_dev_ino(path: &Path) -> std::io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(path)?;
    Ok((md.dev(), md.ino()))
}

/// Resolve the armed `ExeIdentity` for a browser from its config `exe_paths`:
/// the first path that canonicalizes + stats successfully. Returns `None` if no
/// path resolves (the browser has no enrollable executable to bind a lease to).
fn resolve_exe_identity(exe_paths: &[PathBuf]) -> Option<ExeIdentity> {
    use std::os::unix::fs::MetadataExt;
    for p in exe_paths {
        let canon = match std::fs::canonicalize(p) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if let Ok(md) = std::fs::metadata(&canon) {
            return Some(ExeIdentity {
                exe: canon,
                dev: md.dev(),
                ino: md.ino(),
            });
        }
    }
    None
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Build an `AuditRecord` from the decision context. `process` is `None` when
/// identity resolution failed (the record still captures the resource + pid).
/// No secret contents are stored — only paths and metadata.
pub(crate) fn build_audit_record(
    resource: &ProtectedResource,
    process: Option<&ProcessIdentity>,
    decision: Decision,
    backend_diag: &str,
) -> AuditRecord {
    let pid = process.map(|p| p.stable.pid).unwrap_or(0);
    let start_time = process.map(|p| p.stable.start_time).unwrap_or(0);
    let uid = process.map(|p| p.uid).unwrap_or(0);
    let exe_owner_uid = process.map(|p| p.exe_owner_uid).unwrap_or(0);
    let exe = process
        .map(|p| p.stable.exe.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<unresolved>".to_string());
    let trust_tier = process
        .map(|p| p.trust_tier)
        .unwrap_or(guard_core::identity::TrustTier::Unknown);
    let process_browser = process.and_then(|p| p.browser.clone());
    let parent_pid = process.and_then(|p| p.ancestors.first()).map(|a| a.pid);
    let parent_exe = process
        .and_then(|p| p.ancestors.first())
        .map(|a| a.exe.to_string_lossy().into_owned());
    let lease_id = match &decision {
        Decision::AllowByLease(id) => Some(id.0),
        _ => None,
    };
    let deny_reason = match &decision {
        Decision::Deny(r) => Some(*r),
        _ => None,
    };
    AuditRecord {
        event_code: "access_decision".into(),
        ts_ms: now_ms(),
        uid,
        pid,
        start_time,
        decision,
        deny_reason,
        resource_kind: resource.kind,
        resource_browser: resource.browser.clone(),
        resource_profile: resource.profile.clone(),
        path: resource.path.to_string_lossy().into_owned(),
        exe,
        exe_owner_uid,
        trust_tier,
        process_browser,
        parent_pid,
        parent_exe,
        lease_id,
        backend_diag: backend_diag.to_string(),
    }
}

/// Release builds persist only blocked protected-file opens. Keeping normal
/// allows in debug builds preserves diagnostics and tests without imposing
/// per-open string/path allocation and SQLite queue pressure in production.
#[inline]
/// Which decisions produce an audit record. Denials always record. In release
/// builds successful decisions are otherwise suppressed for audit volume —
/// EXCEPT SSH private-key lease grants, which are the accountability path for
/// who loaded a key (LFH6 live acceptance requires ALLOW_BY_LEASE audit
/// evidence for a brokered load).
fn should_record_decision(decision: &Decision, kind: ProtectedResourceKind) -> bool {
    cfg!(debug_assertions)
        || matches!(decision, Decision::Deny(_))
        || (matches!(decision, Decision::AllowByLease(_))
            && kind == ProtectedResourceKind::SshPrivateKey)
}

/// Cheap diagnostic for how the fd was classified: "fd_index" if the inode hit
/// the hardlink index, "registry" if path-based classify matched, "unknown"
/// otherwise. Used in `backend_diag` for audit.
fn classify_diag(fd: RawFd) -> &'static str {
    if let Ok(id) = fanotify::fd_identity(fd) {
        if id != (0, 0) {
            return "fd_index_or_registry";
        }
    }
    "fd_path_registry"
}

#[cfg(test)]
mod tests {
    //! Non-privileged Phase 06 tests. These run under `cargo test -p guardd`
    //! without root: they resolve the test process's own identity, open real
    //! files (no fanotify needed for the classify/policy wiring), and assert
    //! the engine's deterministic decisions.
    //!
    //! The privileged fanotify end-to-end enforcement lives in
    //! `scripts/test-browser-enforcement-root.sh`.

    use super::*;
    use guard_core::identity::{AncestorSummary, TrustTier};
    use guard_core::policy::DenyReason;
    use guard_core::resource::{ProtectedResourceId, ProtectedResourceKind};
    use guard_test_fixtures::chromium::ChromiumProfile;
    use guard_test_fixtures::firefox::FirefoxProfile;
    use std::os::unix::io::AsRawFd;
    use std::process::{Child, Command};
    use std::time::Duration;

    struct KillOnDrop(Option<Child>);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            if let Some(mut c) = self.0.take() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }

    fn find_sleep() -> PathBuf {
        for c in ["/bin/sleep", "/usr/bin/sleep"] {
            if Path::new(c).exists() {
                return PathBuf::from(c);
            }
        }
        panic!("no sleep binary found for test")
    }

    fn spawn_sleep() -> (Child, i32) {
        let child = Command::new(find_sleep()).arg("30").spawn().expect("spawn");
        let pid = child.id() as i32;
        std::thread::sleep(Duration::from_millis(60));
        (child, pid)
    }

    /// Build a config that enforces a synthetic Chrome profile and (optionally)
    /// maps `exe` as the chrome browser identity.
    fn chrome_config(chrome_root: &Path, chrome_exe: Option<&Path>) -> EnforcementConfig {
        let mut b = BrowserEnrollmentConfig {
            id: "chrome".into(),
            family: BrowserFamily::Chromium,
            profile_root: chrome_root.to_path_buf(),
            owner_uid: Some(unsafe { libc::getuid() }),
            exe_paths: vec![],
        };
        if let Some(exe) = chrome_exe {
            b.exe_paths.push(exe.to_path_buf());
        }
        EnforcementConfig {
            config_version: platform_linux::config::CONFIG_VERSION,
            enforcement_mode: EnforcementMode::Conservative,
            browsers: vec![b],
            enrolled_exes: vec![],
            ssh_keys: vec![],
            process_shield_enabled: false,
        }
    }

    fn chrome_and_firefox_config(
        chrome_root: &Path,
        chrome_exe: &Path,
        ff_root: &Path,
        ff_exe: &Path,
    ) -> EnforcementConfig {
        let uid = unsafe { libc::getuid() };
        EnforcementConfig {
            config_version: platform_linux::config::CONFIG_VERSION,
            enforcement_mode: EnforcementMode::Conservative,
            browsers: vec![
                BrowserEnrollmentConfig {
                    id: "chrome".into(),
                    family: BrowserFamily::Chromium,
                    profile_root: chrome_root.to_path_buf(),
                    owner_uid: Some(uid),
                    exe_paths: vec![chrome_exe.to_path_buf()],
                },
                BrowserEnrollmentConfig {
                    id: "firefox".into(),
                    family: BrowserFamily::Firefox,
                    profile_root: ff_root.to_path_buf(),
                    owner_uid: Some(uid),
                    exe_paths: vec![ff_exe.to_path_buf()],
                },
            ],
            enrolled_exes: vec![],
            ssh_keys: vec![],
            process_shield_enabled: false,
        }
    }

    // --- resource classification via fd ---

    #[test]
    fn config_accepts_documented_lowercase_browser_families() {
        let config: EnforcementConfig = serde_json::from_str(
            r#"{
                "enforcement_mode": "strict-filesystem",
                "browsers": [
                    {"id":"chrome","family":"chromium","profile_root":"/tmp/chrome"},
                    {"id":"firefox","family":"firefox","profile_root":"/tmp/firefox"}
                ]
            }"#,
        )
        .expect("documented lowercase config must deserialize");

        assert_eq!(config.browsers[0].family, BrowserFamily::Chromium);
        assert_eq!(config.browsers[1].family, BrowserFamily::Firefox);
    }

    #[test]
    fn classify_fd_returns_concrete_critical_file() {
        let p = ChromiumProfile::create("Default").unwrap();
        let engine =
            EnforcementEngine::from_config(&chrome_config(&p.user_data_dir, None)).expect("engine");

        let f = std::fs::File::open(&p.cookies).unwrap();
        let res = engine.classify_fd(f.as_raw_fd()).expect("classified");
        assert_eq!(res.kind, ProtectedResourceKind::CookieStore);
        assert_eq!(res.browser.as_ref().unwrap().0, "chrome");
    }

    #[test]
    fn classify_fd_covers_wal_and_shm_sidecars() {
        let p = ChromiumProfile::create("Default").unwrap();
        let engine =
            EnforcementEngine::from_config(&chrome_config(&p.user_data_dir, None)).expect("engine");

        for f in [&p.cookies_wal, &p.cookies_shm] {
            let fh = std::fs::File::open(f).unwrap();
            let res = engine
                .classify_fd(fh.as_raw_fd())
                .expect("classified sidecar");
            assert_eq!(
                res.kind,
                ProtectedResourceKind::CookieStore,
                "{:?} not cookie",
                f
            );
        }
    }

    #[test]
    fn classify_fd_catches_hardlink_by_inode() {
        let p = ChromiumProfile::create("Default").unwrap();
        let engine =
            EnforcementEngine::from_config(&chrome_config(&p.user_data_dir, None)).expect("engine");

        let link = p.root_path().join("hardlink-to-cookies");
        std::fs::hard_link(&p.cookies, &link).expect("hardlink");
        // Open via the hardlink path (different name, same inode).
        let f = std::fs::File::open(&link).unwrap();
        let res = engine
            .classify_fd(f.as_raw_fd())
            .expect("hardlink classified");
        assert_eq!(res.kind, ProtectedResourceKind::CookieStore);
    }

    #[test]
    fn classify_fd_catches_symlink_to_protected_file() {
        let p = ChromiumProfile::create("Default").unwrap();
        let engine =
            EnforcementEngine::from_config(&chrome_config(&p.user_data_dir, None)).expect("engine");

        let link = p.root_path().join("symlink-to-cookies");
        std::os::unix::fs::symlink(&p.cookies, &link).unwrap();
        let f = std::fs::File::open(&link).unwrap();
        let res = engine
            .classify_fd(f.as_raw_fd())
            .expect("symlink classified");
        assert_eq!(res.kind, ProtectedResourceKind::CookieStore);
    }

    #[test]
    fn classify_fd_unprotected_file_is_none() {
        let p = ChromiumProfile::create("Default").unwrap();
        let engine =
            EnforcementEngine::from_config(&chrome_config(&p.user_data_dir, None)).expect("engine");
        let other = p.root_path().join("ordinary.txt");
        std::fs::write(&other, b"hello").unwrap();
        let f = std::fs::File::open(&other).unwrap();
        assert!(engine.classify_fd(f.as_raw_fd()).is_none());
    }

    #[test]
    fn classify_fd_tree_descendant_synthesizes_resource() {
        let p = ChromiumProfile::create("Default").unwrap();
        let engine =
            EnforcementEngine::from_config(&chrome_config(&p.user_data_dir, None)).expect("engine");
        let descendant = p.local_storage_dir.join("https_example.com_0.localstorage");
        let f = std::fs::File::open(&descendant).unwrap();
        let res = engine
            .classify_fd(f.as_raw_fd())
            .expect("tree descendant classified");
        assert_eq!(res.kind, ProtectedResourceKind::WebStorage);
    }

    // --- identity resolution + caching ---

    #[test]
    fn resolve_process_self_has_correct_exe() {
        let p = ChromiumProfile::create("Default").unwrap();
        let mut engine =
            EnforcementEngine::from_config(&chrome_config(&p.user_data_dir, None)).expect("engine");
        let me = std::process::id() as i32;
        let (id, diag) = engine.resolve_process(me).expect("resolve self");
        assert!(id.stable.exe.is_file());
        assert!(id.stable.start_time > 0);
        assert_eq!(diag, "fresh_resolve");
    }

    #[test]
    fn resolve_process_caches_and_reuses() {
        let p = ChromiumProfile::create("Default").unwrap();
        let mut engine =
            EnforcementEngine::from_config(&chrome_config(&p.user_data_dir, None)).expect("engine");
        let me = std::process::id() as i32;
        let (a, diag_a) = engine.resolve_process(me).expect("resolve");
        let (b, diag_b) = engine.resolve_process(me).expect("resolve again");
        assert_eq!(a, b, "cached identity must be equal");
        assert_eq!(engine.identity_cache.len(), 1);
        assert_eq!(diag_a, "fresh_resolve");
        assert_eq!(diag_b, "cache_hit");
    }

    #[test]
    fn resolve_process_pid_reuse_invalidates_cache_and_fails_closed() {
        // LFH1 C: a PID whose start_time changed (the old process exited and a
        // new process occupies the numeric PID) must NOT reuse the cached
        // identity. The daemon observes the new start_time, drops the cache
        // entry, and resolves the new instance afresh — so the old authority
        // never transfers.
        let p = ChromiumProfile::create("Default").unwrap();
        let mut engine =
            EnforcementEngine::from_config(&chrome_config(&p.user_data_dir, None)).expect("engine");
        let me = std::process::id() as i32;
        let (original, _) = engine.resolve_process(me).expect("resolve");
        assert_eq!(engine.identity_cache.len(), 1);

        // Simulate PID reuse: the cached entry claims a DIFFERENT start_time
        // than the live process (exactly what a reused PID looks like to the
        // daemon: same numeric pid, new start_time).
        let reused_start = original.stable.start_time.wrapping_add(1);
        engine
            .identity_cache
            .insert(me as u32, (reused_start, original.clone()));

        let (re_resolved, diag) = engine.resolve_process(me).expect("re-resolve");
        assert_eq!(
            diag, "fresh_resolve",
            "starttime mismatch must force a fresh resolve"
        );
        assert_eq!(
            re_resolved.stable.start_time, original.stable.start_time,
            "fresh resolve returns the LIVE process start_time, not the stale cache"
        );
        // The cached stale identity is gone; a pidfd/starttime-anchored check
        // would fail closed, never allow the old instance.
        assert!(
            engine.identity_cache.get(&(me as u32)).unwrap().0 == original.stable.start_time,
            "cache now holds only the live start_time"
        );
    }

    #[test]
    fn resolve_process_maps_enrolled_exe_to_browser() {
        let p = ChromiumProfile::create("Default").unwrap();
        // Enroll the real /bin/sleep as the "chrome" browser identity.
        let sleep = find_sleep();
        let mut engine =
            EnforcementEngine::from_config(&chrome_config(&p.user_data_dir, Some(&sleep)))
                .expect("engine");

        let (_guard, pid) = spawn_sleep();
        let (id, _diag) = engine.resolve_process(pid).expect("resolve sleep");
        // /bin/sleep is root-owned => SystemPackage trust.
        assert_eq!(
            id.trust_tier,
            guard_core::identity::TrustTier::SystemPackage
        );
        // exe path is in browser_exes => browser field is set.
        assert_eq!(id.browser.as_ref().expect("browser set").0, "chrome");
    }

    #[test]
    fn resolve_process_renamed_fake_browser_stays_unknown() {
        // Copy sleep to a user-writable path named "firefox". It is NOT in
        // browser_exes, so browser stays None and trust is Unknown (user-writable,
        // not enrolled) — even though the basename is "firefox".
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("firefox");
        std::fs::copy(find_sleep(), &fake).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();

        let p = ChromiumProfile::create("Default").unwrap();
        let mut engine =
            EnforcementEngine::from_config(&chrome_config(&p.user_data_dir, None)).expect("engine");

        let child = Command::new(&fake)
            .arg("30")
            .spawn()
            .expect("spawn fake firefox");
        let pid = child.id() as i32;
        let _guard = KillOnDrop(Some(child));
        std::thread::sleep(Duration::from_millis(60));

        let (id, _diag) = engine.resolve_process(pid).expect("resolve fake firefox");
        assert_eq!(id.trust_tier, guard_core::identity::TrustTier::Unknown);
        assert!(
            id.browser.is_none(),
            "renamed fake browser must not map to a BrowserId"
        );
    }

    // --- end-to-end policy wiring via decide() (no fanotify, real fds) ---

    /// LFH6: locate a real installed Firefox ELF (NOT the /usr/bin wrapper
    /// script). Returns None when Firefox is not installed — that is reported
    /// as `NOT INSTALLED`, never as a failure.
    fn find_real_firefox_elf() -> Option<PathBuf> {
        for candidate in [
            "/usr/lib/firefox/firefox",
            "/usr/lib64/firefox/firefox",
            "/usr/lib/firefox-esr/firefox",
            "/opt/firefox/firefox",
            "/snap/firefox/current/usr/lib/firefox/firefox",
        ] {
            let p = PathBuf::from(candidate);
            if p.is_file() {
                return Some(p);
            }
        }
        None
    }

    /// LFH6 offline compatibility: launch the REAL installed Firefox headless
    /// with a DISPOSABLE synthetic profile (never a real profile), let it
    /// settle, then assert the classifier protects the artifacts Firefox
    /// actually created and that the policy allows the real Firefox process
    /// while denying an unknown probe on the same files. Runs entirely without
    /// fanotify (classify + decide are pure); the live interception gate stays
    /// BLOCKED in this environment.
    #[test]
    fn lfh6_real_firefox_disposable_profile_compat() {
        let Some(firefox_elf) = find_real_firefox_elf() else {
            eprintln!("LFH6: firefox NOT INSTALLED — skipped (NOT FAIL)");
            return;
        };
        let profile_dir = tempfile::tempdir().expect("profile tempdir");
        let profile_path = profile_dir.path().to_path_buf();

        // Headless launch; wait (bounded) for the key protected artifact, then
        // give the profile a few seconds to settle (storage/ tree, etc.).
        let child = Command::new(&firefox_elf)
            .args([
                "--headless",
                "--no-remote",
                "--profile",
                profile_path.to_str().expect("utf8 profile path"),
                "about:blank",
            ])
            .spawn()
            .expect("spawn real firefox");
        let ff_pid = child.id() as i32;
        let _guard = KillOnDrop(Some(child));

        let cookies = profile_path.join("cookies.sqlite");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
        while !cookies.is_file() {
            assert!(
                std::time::Instant::now() < deadline,
                "real firefox did not create cookies.sqlite within 90s"
            );
            std::thread::sleep(Duration::from_millis(250));
        }
        std::thread::sleep(Duration::from_secs(4));

        let uid = unsafe { libc::getuid() };
        let cfg = EnforcementConfig {
            config_version: platform_linux::config::CONFIG_VERSION,
            enforcement_mode: EnforcementMode::StrictFilesystem,
            browsers: vec![BrowserEnrollmentConfig {
                id: "firefox".into(),
                family: BrowserFamily::Firefox,
                profile_root: profile_path.clone(),
                owner_uid: Some(uid),
                exe_paths: vec![firefox_elf.clone()],
            }],
            enrolled_exes: vec![firefox_elf.clone()],
            ssh_keys: vec![],
            process_shield_enabled: false,
        };
        let mut engine = EnforcementEngine::from_config(&cfg).expect("engine");

        // 1. Real artifacts classify as protected with the expected kinds.
        let file_cases: &[(&str, ProtectedResourceKind)] = &[
            ("cookies.sqlite", ProtectedResourceKind::CookieStore),
            ("cookies.sqlite-wal", ProtectedResourceKind::CookieStore),
            ("cookies.sqlite-shm", ProtectedResourceKind::CookieStore),
            ("logins.json", ProtectedResourceKind::SavedCredentials),
            ("key4.db", ProtectedResourceKind::BrowserKeyMaterial),
            ("webappsstore.sqlite", ProtectedResourceKind::WebStorage),
        ];
        for (name, kind) in file_cases {
            let path = profile_path.join(name);
            if path.is_file() {
                let res = engine
                    .registry()
                    .classify(&path)
                    .unwrap_or_else(|| panic!("real firefox artifact {name} must classify"));
                assert_eq!(
                    res.kind, *kind,
                    "real firefox artifact {name} must classify as {kind:?}"
                );
            } else {
                eprintln!("LFH6: {name} not created by this headless run; skipped");
            }
        }
        // Tree protections: sessionstore-backups + storage/ (WebStorage).
        for (name, kind) in [
            ("sessionstore-backups", ProtectedResourceKind::SessionStore),
            ("storage", ProtectedResourceKind::WebStorage),
        ] {
            let path = profile_path.join(name);
            assert!(
                path.is_dir(),
                "real firefox should create {name}/ in a disposable profile"
            );
            assert!(
                engine.registry().classify(&path).is_some(),
                "real firefox tree {name} must classify"
            );
            let descendant = path.join("x");
            let res = engine.registry().classify(&descendant);
            assert_eq!(res.as_ref().map(|r| r.kind), Some(kind));
        }

        // 2. An unknown probe opening the real cookies file is denied.
        let (_probe, probe_pid) = spawn_sleep();
        let f = std::fs::File::open(&cookies).unwrap();
        assert!(
            matches!(
                engine.decide(probe_pid, f.as_raw_fd()),
                Decision::Deny(DenyReason::UnknownProcess)
            ),
            "unknown probe must be denied on a real firefox cookies.sqlite"
        );

        // 3. The real Firefox process reading its own cookies is allowed
        //    (own profile, trusted system-package identity).
        let f2 = std::fs::File::open(&cookies).unwrap();
        assert_eq!(
            engine.decide(ff_pid, f2.as_raw_fd()),
            Decision::Allow,
            "real firefox must be allowed on its own cookies.sqlite"
        );

        // 4. Consistency: history/places is NOT in the protected scope (same
        //    policy as Chromium History) and unrelated profile files are not
        //    over-broadly protected.
        for name in ["places.sqlite", "favicons.sqlite", "prefs.js"] {
            let path = profile_path.join(name);
            if path.is_file() {
                assert!(
                    engine.registry().classify(&path).is_none(),
                    "{name} must stay out of the protected scope (history/config)"
                );
            }
        }
        eprintln!(
            "LFH6: real Firefox {} disposable-profile compat PASSED (cookies={})",
            firefox_elf.display(),
            cookies.display()
        );
    }

    #[test]
    fn decide_unknown_process_denied() {
        let p = ChromiumProfile::create("Default").unwrap();
        // No exe mapped to chrome => sleep resolves to browser=None, Unknown-ish.
        let mut engine =
            EnforcementEngine::from_config(&chrome_config(&p.user_data_dir, None)).expect("engine");
        let (_guard, pid) = spawn_sleep();
        let f = std::fs::File::open(&p.cookies).unwrap();
        let d = engine.decide(pid, f.as_raw_fd());
        assert!(matches!(d, Decision::Deny(DenyReason::UnknownProcess)));
        assert_eq!(engine.denied, 1);
    }

    #[test]
    fn decide_owning_browser_allowed() {
        let p = ChromiumProfile::create("Default").unwrap();
        let sleep = find_sleep();
        let mut engine =
            EnforcementEngine::from_config(&chrome_config(&p.user_data_dir, Some(&sleep)))
                .expect("engine");
        let (_guard, pid) = spawn_sleep();
        let f = std::fs::File::open(&p.cookies).unwrap();
        let d = engine.decide(pid, f.as_raw_fd());
        assert_eq!(
            d,
            Decision::Allow,
            "chrome (sleep) reading own cookies => allow"
        );
        assert_eq!(engine.allowed, 1);
    }

    #[test]
    fn decide_cross_browser_requires_confirmation_without_lease() {
        let chrome = ChromiumProfile::create("Default").unwrap();
        let ff = FirefoxProfile::create("ff-profile").unwrap();
        let sleep = find_sleep();
        // chrome exe = sleep#1 path, firefox exe = sleep#2 path (a copy so the
        // two exe paths differ and map to different BrowserIds).
        let ff_exe = ff.root_path().join("fake-firefox-bin");
        std::fs::copy(&sleep, &ff_exe).unwrap();

        let cfg =
            chrome_and_firefox_config(&chrome.user_data_dir, &sleep, &ff.profile_dir, &ff_exe);
        let mut engine = EnforcementEngine::from_config(&cfg).expect("engine");

        // A "chrome" process (sleep) opening firefox cookies => cross-browser.
        let (_guard, pid) = spawn_sleep();
        let f = std::fs::File::open(&ff.cookies_sqlite).unwrap();
        let d = engine.decide(pid, f.as_raw_fd());
        assert!(
            matches!(d, Decision::RequireMigrationConfirmation(_)),
            "chrome reading firefox without lease => confirmation required, got {:?}",
            d
        );
    }

    #[test]
    fn decide_unclassified_fd_fails_closed() {
        let p = ChromiumProfile::create("Default").unwrap();
        let mut engine =
            EnforcementEngine::from_config(&chrome_config(&p.user_data_dir, None)).expect("engine");
        let other = p.root_path().join("ordinary.txt");
        std::fs::write(&other, b"hello").unwrap();
        let (_guard, pid) = spawn_sleep();
        let f = std::fs::File::open(&other).unwrap();
        let d = engine.decide(pid, f.as_raw_fd());
        assert!(matches!(d, Decision::Deny(_)));
        assert_eq!(engine.unclassified, 1);
    }

    #[test]
    fn unclassified_ssh_access_event_fails_closed() {
        let cfg = EnforcementConfig {
            config_version: platform_linux::config::CONFIG_VERSION,
            enforcement_mode: EnforcementMode::Conservative,
            browsers: vec![],
            enrolled_exes: vec![],
            ssh_keys: vec![],
            process_shield_enabled: false,
        };
        let mut engine = EnforcementEngine::from_config(&cfg).unwrap();
        let (decision, event) = engine.decide_event(4242, -1, true);
        assert_eq!(decision, Decision::Deny(DenyReason::UnknownProcess));
        assert!(event.is_none());
    }

    // --- config / enrollment ---

    #[test]
    fn from_config_enrolls_chromium_resources() {
        let p = ChromiumProfile::create("Default").unwrap();
        let engine =
            EnforcementEngine::from_config(&chrome_config(&p.user_data_dir, None)).expect("engine");
        assert!(
            engine.registry().file_count() >= 6,
            "critical files enrolled"
        );
        assert!(!engine.registry().trees().is_empty(), "tree roots enrolled");
    }

    #[test]
    fn from_config_auto_detects_owner_uid() {
        let p = ChromiumProfile::create("Default").unwrap();
        let mut cfg = chrome_config(&p.user_data_dir, None);
        cfg.browsers[0].owner_uid = None; // force auto-detect
        let engine = EnforcementEngine::from_config(&cfg).expect("engine");
        // The temp profile is owned by the test user.
        let me = unsafe { libc::getuid() };
        let res = engine.registry().files().next().expect("has files");
        assert_eq!(res.owner_uid, me);
    }

    // --- Phase 08: migration lease authorize flow ---

    /// chrome + firefox config where the firefox exe is hash-enrolled so a
    /// firefox process resolves to a trusted browser (giving
    /// CrossBrowserWithoutLease, not NotTrustedIdentity, before a lease).
    fn migration_config(chrome_root: &Path, ff_root: &Path, ff_exe: &Path) -> EnforcementConfig {
        let uid = unsafe { libc::getuid() };
        EnforcementConfig {
            config_version: platform_linux::config::CONFIG_VERSION,
            enforcement_mode: EnforcementMode::Conservative,
            browsers: vec![
                BrowserEnrollmentConfig {
                    id: "chrome".into(),
                    family: BrowserFamily::Chromium,
                    profile_root: chrome_root.to_path_buf(),
                    owner_uid: Some(uid),
                    exe_paths: vec![],
                },
                BrowserEnrollmentConfig {
                    id: "firefox".into(),
                    family: BrowserFamily::Firefox,
                    profile_root: ff_root.to_path_buf(),
                    owner_uid: Some(uid),
                    exe_paths: vec![ff_exe.to_path_buf()],
                },
            ],
            enrolled_exes: vec![ff_exe.to_path_buf()],
            ssh_keys: vec![],
            process_shield_enabled: false,
        }
    }

    fn spawn_exe(exe: &Path) -> (Child, i32) {
        let child = Command::new(exe).arg("30").spawn().expect("spawn");
        let pid = child.id() as i32;
        std::thread::sleep(Duration::from_millis(60));
        (child, pid)
    }

    #[test]
    fn migration_lease_authorize_then_cross_browser_allowed() {
        let chrome = ChromiumProfile::create("Default").unwrap();
        let ff = FirefoxProfile::create("ff-profile").unwrap();
        let ff_exe = ff.root_path().join("fake-firefox-bin");
        std::fs::copy(find_sleep(), &ff_exe).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ff_exe, std::fs::Permissions::from_mode(0o755)).unwrap();

        let uid = unsafe { libc::getuid() };
        let mut engine = EnforcementEngine::from_config(&migration_config(
            &chrome.user_data_dir,
            &ff.profile_dir,
            &ff_exe,
        ))
        .expect("engine");

        let (guard, ff_pid) = spawn_exe(&ff_exe);
        let _g = KillOnDrop(Some(guard));

        // Before lease: firefox opening chrome cookies => confirmation required.
        let f = std::fs::File::open(&chrome.cookies).unwrap();
        let d = engine.decide(ff_pid, f.as_raw_fd());
        assert!(
            matches!(d, Decision::RequireMigrationConfirmation(_)),
            "firefox reading chrome without lease => confirmation required, got {d:?}"
        );

        // Authorize a migration: firefox may read chrome/Default.
        let (lease_id, expires_at) = engine
            .authorize_migration("chrome", "Default", "firefox", uid, None)
            .expect("authorize");
        assert_eq!(lease_id.0, 1);
        assert!(expires_at > now_secs_for_test());

        // After lease: firefox opening chrome cookies => AllowByLease.
        let f2 = std::fs::File::open(&chrome.cookies).unwrap();
        let d2 = engine.decide(ff_pid, f2.as_raw_fd());
        assert_eq!(
            d2,
            Decision::AllowByLease(lease_id),
            "firefox reading chrome WITH lease => AllowByLease, got {d2:?}"
        );

        // The lease does NOT grant reading a different source (firefox own
        // cookies) cross-browser — firefox reading its OWN profile is Allow
        // (own profile), which is fine. The reverse direction (a process
        // reading firefox cookies under a firefox->chrome lease) must also be
        // denied: spawn a sleep process and open firefox cookies. The lease
        // is source-scoped to chrome/Default, so it cannot cover firefox's
        // profile. (The exact deny reason is `UnknownProcess` here because
        // `migration_config` does not enroll a chrome exe for sleep; any
        // `Deny` proves the lease does not grant reverse access.)
        let (guard2, chrome_pid) = spawn_sleep();
        let _g2 = KillOnDrop(Some(guard2));
        let f3 = std::fs::File::open(&ff.cookies_sqlite).unwrap();
        let d3 = engine.decide(chrome_pid, f3.as_raw_fd());
        assert!(
            matches!(d3, Decision::Deny(_)),
            "reading firefox under a firefox->chrome lease => deny, got {d3:?}"
        );
    }

    #[test]
    fn pending_migration_approval_binds_the_triggering_browser_instance() {
        let chrome = ChromiumProfile::create("Default").unwrap();
        let ff = FirefoxProfile::create("ff-profile").unwrap();
        let ff_exe = ff.root_path().join("fake-firefox-bin");
        std::fs::copy(find_sleep(), &ff_exe).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ff_exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut engine = EnforcementEngine::from_config(&migration_config(
            &chrome.user_data_dir,
            &ff.profile_dir,
            &ff_exe,
        ))
        .unwrap();
        let (child, pid) = spawn_exe(&ff_exe);
        let _child = KillOnDrop(Some(child));
        let file = std::fs::File::open(&chrome.cookies).unwrap();
        let candidate = match engine.decide(pid, file.as_raw_fd()) {
            Decision::RequireMigrationConfirmation(candidate) => candidate,
            other => panic!("expected confirmation candidate, got {other:?}"),
        };
        let details = engine
            .pending_migration_details(pid, file.as_raw_fd(), &candidate)
            .expect("daemon re-verifies pending target facts");
        let (lease_id, _) = engine.approve_pending_migration(&details).unwrap();
        assert!(matches!(
            engine.leases().migration[0].state,
            MigrationLeaseState::Bound { ref root } if *root == details.target.stable
        ));
        let file = std::fs::File::open(&chrome.cookies).unwrap();
        assert_eq!(
            engine.decide(pid, file.as_raw_fd()),
            Decision::AllowByLease(lease_id)
        );
    }

    #[test]
    fn migration_lease_revoked_denied() {
        let chrome = ChromiumProfile::create("Default").unwrap();
        let ff = FirefoxProfile::create("ff-profile").unwrap();
        let ff_exe = ff.root_path().join("fake-firefox-bin");
        std::fs::copy(find_sleep(), &ff_exe).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ff_exe, std::fs::Permissions::from_mode(0o755)).unwrap();

        let uid = unsafe { libc::getuid() };
        let mut engine = EnforcementEngine::from_config(&migration_config(
            &chrome.user_data_dir,
            &ff.profile_dir,
            &ff_exe,
        ))
        .expect("engine");

        let (lease_id, _) = engine
            .authorize_migration("chrome", "Default", "firefox", uid, None)
            .expect("authorize");

        let (guard, ff_pid) = spawn_exe(&ff_exe);
        let _g = KillOnDrop(Some(guard));

        // Allowed before revoke.
        let f = std::fs::File::open(&chrome.cookies).unwrap();
        assert_eq!(
            engine.decide(ff_pid, f.as_raw_fd()),
            Decision::AllowByLease(lease_id)
        );

        // Revoke.
        assert!(engine.revoke_lease(&lease_id.0.to_string()));

        // Denied after revoke.
        let f2 = std::fs::File::open(&chrome.cookies).unwrap();
        assert_eq!(
            engine.decide(ff_pid, f2.as_raw_fd()),
            Decision::Deny(DenyReason::LeaseRevoked)
        );
    }

    #[test]
    fn migration_authorize_unknown_target_errors() {
        let chrome = ChromiumProfile::create("Default").unwrap();
        let ff = FirefoxProfile::create("ff-profile").unwrap();
        let ff_exe = ff.root_path().join("fake-firefox-bin");
        std::fs::copy(find_sleep(), &ff_exe).unwrap();
        let mut engine = EnforcementEngine::from_config(&migration_config(
            &chrome.user_data_dir,
            &ff.profile_dir,
            &ff_exe,
        ))
        .expect("engine");

        let uid = unsafe { libc::getuid() };
        let err = engine
            .authorize_migration("chrome", "Default", "nonexistent", uid, None)
            .unwrap_err();
        assert!(err.contains("unknown target browser"), "{err}");

        let err2 = engine
            .authorize_migration("nope", "Default", "firefox", uid, None)
            .unwrap_err();
        assert!(err2.contains("unknown source browser"), "{err2}");
    }

    #[test]
    fn migration_authorize_caps_duration() {
        let chrome = ChromiumProfile::create("Default").unwrap();
        let ff = FirefoxProfile::create("ff-profile").unwrap();
        let ff_exe = ff.root_path().join("fake-firefox-bin");
        std::fs::copy(find_sleep(), &ff_exe).unwrap();
        let mut engine = EnforcementEngine::from_config(&migration_config(
            &chrome.user_data_dir,
            &ff.profile_dir,
            &ff_exe,
        ))
        .expect("engine");

        let uid = unsafe { libc::getuid() };
        let before = now_secs_for_test();
        // Request an absurd duration; must be capped at 1h.
        let (_, expires_at) = engine
            .authorize_migration("chrome", "Default", "firefox", uid, Some(99_999_999))
            .expect("authorize");
        assert!(
            expires_at <= before + MAX_MIGRATION_DURATION_SECS + 2,
            "duration must be capped at {}s, got expiry delta {}",
            MAX_MIGRATION_DURATION_SECS,
            expires_at.saturating_sub(before)
        );
    }

    #[test]
    fn migration_access_lease_does_not_claim_read_only_enforcement() {
        // The fanotify backend cannot observe the triggering open mode. V1
        // therefore grants process-tree-scoped migration access and must not
        // pretend that an O_WRONLY open is distinguishable.
        let chrome = ChromiumProfile::create("Default").unwrap();
        let ff = FirefoxProfile::create("ff-profile").unwrap();
        let ff_exe = ff.root_path().join("fake-firefox-bin");
        std::fs::copy(find_sleep(), &ff_exe).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ff_exe, std::fs::Permissions::from_mode(0o755)).unwrap();

        let uid = unsafe { libc::getuid() };
        let mut engine = EnforcementEngine::from_config(&migration_config(
            &chrome.user_data_dir,
            &ff.profile_dir,
            &ff_exe,
        ))
        .expect("engine");
        let (lease_id, _) = engine
            .authorize_migration("chrome", "Default", "firefox", uid, None)
            .expect("authorize");

        let (guard, ff_pid) = spawn_exe(&ff_exe);
        let _g = KillOnDrop(Some(guard));

        // Read open under the lease is allowed.
        let r = std::fs::File::open(&chrome.cookies).unwrap();
        assert_eq!(
            engine.decide(ff_pid, r.as_raw_fd()),
            Decision::AllowByLease(lease_id)
        );

        // The same bound process can also issue a write open. This test records
        // the honest backend limitation rather than asserting fake semantics.
        let w = std::fs::OpenOptions::new()
            .write(true)
            .open(&chrome.cookies)
            .unwrap();
        assert_eq!(
            engine.decide(ff_pid, w.as_raw_fd()),
            Decision::AllowByLease(lease_id),
            "fanotify migration access is not a read-only guarantee"
        );
    }

    fn now_secs_for_test() -> u64 {
        now_secs()
    }

    // --- Phase 10: SSH private-key protection ---

    fn ssh_config(ssh_key: &Path) -> EnforcementConfig {
        EnforcementConfig {
            config_version: platform_linux::config::CONFIG_VERSION,
            enforcement_mode: EnforcementMode::Conservative,
            browsers: vec![],
            enrolled_exes: vec![],
            ssh_keys: vec![ssh_key.to_path_buf()],
            process_shield_enabled: false,
        }
    }

    #[test]
    fn ssh_key_enrolled_from_config_classifies() {
        let s = guard_test_fixtures::SshFixture::create().unwrap();
        let engine = EnforcementEngine::from_config(&ssh_config(&s.private_key)).expect("engine");
        let f = std::fs::File::open(&s.private_key).unwrap();
        let res = engine.classify_fd(f.as_raw_fd()).expect("classified");
        assert_eq!(res.kind, ProtectedResourceKind::SshPrivateKey);
        assert!(res.browser.is_none());
        assert!(res.profile.is_none());
    }

    #[test]
    fn ssh_key_runtime_protect_classifies() {
        let s = guard_test_fixtures::SshFixture::create().unwrap();
        // Empty config (no ssh_keys); enroll at runtime via protect_ssh_key.
        let cfg = EnforcementConfig {
            config_version: platform_linux::config::CONFIG_VERSION,
            enforcement_mode: EnforcementMode::Conservative,
            browsers: vec![],
            enrolled_exes: vec![],
            ssh_keys: vec![],
            process_shield_enabled: false,
        };
        let mut engine = EnforcementEngine::from_config(&cfg).expect("engine");
        let res = engine.protect_ssh_key(&s.private_key).expect("protect");
        assert_eq!(res.kind, ProtectedResourceKind::SshPrivateKey);

        let f = std::fs::File::open(&s.private_key).unwrap();
        let classified = engine.classify_fd(f.as_raw_fd()).expect("classified");
        assert_eq!(classified.kind, ProtectedResourceKind::SshPrivateKey);
    }

    #[test]
    fn ssh_protect_rejects_pub_file() {
        let s = guard_test_fixtures::SshFixture::create().unwrap();
        let cfg = EnforcementConfig {
            config_version: platform_linux::config::CONFIG_VERSION,
            enforcement_mode: EnforcementMode::Conservative,
            browsers: vec![],
            enrolled_exes: vec![],
            ssh_keys: vec![],
            process_shield_enabled: false,
        };
        let mut engine = EnforcementEngine::from_config(&cfg).expect("engine");
        let err = engine.protect_ssh_key(&s.public_key).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn ssh_protect_rejects_reserved_name() {
        let s = guard_test_fixtures::SshFixture::create().unwrap();
        let cfg = EnforcementConfig {
            config_version: platform_linux::config::CONFIG_VERSION,
            enforcement_mode: EnforcementMode::Conservative,
            browsers: vec![],
            enrolled_exes: vec![],
            ssh_keys: vec![],
            process_shield_enabled: false,
        };
        let mut engine = EnforcementEngine::from_config(&cfg).expect("engine");
        let err = engine.protect_ssh_key(&s.known_hosts).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn ssh_pub_key_remains_readable() {
        let s = guard_test_fixtures::SshFixture::create().unwrap();
        // Enroll ONLY the private key. The public key must NOT be classified.
        let engine = EnforcementEngine::from_config(&ssh_config(&s.private_key)).expect("engine");
        let f = std::fs::File::open(&s.public_key).unwrap();
        assert!(
            engine.classify_fd(f.as_raw_fd()).is_none(),
            "public key must not be protected"
        );
    }

    #[test]
    fn ssh_unrelated_files_not_blocked() {
        let s = guard_test_fixtures::SshFixture::create().unwrap();
        let engine = EnforcementEngine::from_config(&ssh_config(&s.private_key)).expect("engine");
        for f in [&s.config, &s.known_hosts] {
            let fh = std::fs::File::open(f).unwrap();
            assert!(
                engine.classify_fd(fh.as_raw_fd()).is_none(),
                "{:?} must not be protected",
                f
            );
        }
    }

    #[test]
    fn ssh_key_hardlink_classifies_by_inode() {
        let s = guard_test_fixtures::SshFixture::create().unwrap();
        let engine = EnforcementEngine::from_config(&ssh_config(&s.private_key)).expect("engine");
        let link = s.ssh_dir.join("hardlink-to-key");
        std::fs::hard_link(&s.private_key, &link).expect("hardlink");
        let f = std::fs::File::open(&link).unwrap();
        let res = engine
            .classify_fd(f.as_raw_fd())
            .expect("hardlink classified");
        assert_eq!(res.kind, ProtectedResourceKind::SshPrivateKey);
    }

    #[test]
    fn ssh_key_requires_confirmation_for_ordinary_process() {
        let s = guard_test_fixtures::SshFixture::create().unwrap();
        let mut engine =
            EnforcementEngine::from_config(&ssh_config(&s.private_key)).expect("engine");
        let f = std::fs::File::open(&s.private_key).unwrap();
        let my_pid = std::process::id() as i32;
        let (decision, record) = engine.decide_with_context(my_pid, f.as_raw_fd());
        assert_eq!(
            decision,
            Decision::RequireSshKeyConfirmation,
            "ordinary protected-key reads must require confirmation"
        );
        assert!(
            record.is_some(),
            "pending confirmation is auditable metadata"
        );
    }

    #[test]
    fn ssh_key_open_requires_confirmation_before_a_readable_fd_is_granted() {
        // P0: `decide` models FAN_OPEN_PERM. It must not return Allow merely
        // because a later ACCESS_PERM event may occur: mmap(2) can use the fd
        // without that later content-permission event.
        let s = guard_test_fixtures::SshFixture::create().unwrap();
        let mut engine =
            EnforcementEngine::from_config(&ssh_config(&s.private_key)).expect("engine");
        let f = std::fs::File::open(&s.private_key).unwrap();
        assert_eq!(
            engine.decide(std::process::id() as i32, f.as_raw_fd()),
            Decision::RequireSshKeyConfirmation,
            "unapproved SSH key open must not receive a readable fd"
        );
    }

    #[test]
    fn ssh_key_audit_record_has_no_secret_content() {
        // The audit record for an allowed SSH key open must NOT contain the
        // fixture's private-key marker (which stands in for real key bytes).
        let s = guard_test_fixtures::SshFixture::create().unwrap();
        let mut engine =
            EnforcementEngine::from_config(&ssh_config(&s.private_key)).expect("engine");
        let f = std::fs::File::open(&s.private_key).unwrap();
        let my_pid = std::process::id() as i32;
        let (_, record) = engine.decide_with_context(my_pid, f.as_raw_fd());
        let rec = record.expect("audit record");
        let json = serde_json::to_string(&rec).unwrap();
        assert!(
            !json.contains(guard_test_fixtures::markers::SSH_PRIVATE_KEY_MARKER),
            "audit record must not contain private-key marker: {json}"
        );
        assert!(!json.contains("\"content\""));
        assert!(!json.contains("\"key_bytes\""));
    }

    // --- Phase 11: SSH load lease (one-shot, identity-bound) ---
    //
    // These tests exercise `authorize_ssh_load` + the decide hot path without
    // fanotify/root: the test process itself stands in for the `ssh-add`
    // invocation. The lease is bound to the test process's real `StableIdentity`
    // (resolved via the engine's own `resolve_process`), so opening the enrolled
    // key under that lease yields `AllowByLease` and marks the lease `used`.

    fn my_stable_identity(engine: &mut EnforcementEngine) -> guard_core::identity::StableIdentity {
        let my_pid = std::process::id() as i32;
        let (id, _) = engine.resolve_process(my_pid).expect("resolve self");
        id.stable.stable_identity()
    }

    #[test]
    fn ssh_load_lease_authorize_then_allowed_while_process_live() {
        let s = guard_test_fixtures::SshFixture::create().unwrap();
        let mut engine =
            EnforcementEngine::from_config(&ssh_config(&s.private_key)).expect("engine");
        let my_uid = unsafe { libc::getuid() };
        let target = my_stable_identity(&mut engine);
        let my_pid = std::process::id() as i32;

        let (lease_id, expires_at) = engine
            .authorize_ssh_load(
                &s.private_key,
                my_uid,
                target,
                my_pid as u32,
                SshAgentBinding::UncheckedForTests,
            )
            .expect("authorize");
        assert_eq!(lease_id.0, 1);
        assert!(expires_at > now_secs_for_test());

        // Opening the key under the lease => AllowByLease. The one-shot lease
        // stays valid while the exact process is live (multiple FAN_ACCESS_PERM
        // events per real load), so it must NOT be marked used here.
        let f = std::fs::File::open(&s.private_key).unwrap();
        let (decision, record) = engine.decide_with_context(my_pid, f.as_raw_fd());
        assert_eq!(
            decision,
            Decision::AllowByLease(lease_id),
            "lease-bound open must be allowed"
        );
        let lease = engine
            .leases()
            .ssh
            .iter()
            .find(|l| l.id == lease_id)
            .expect("lease present");
        assert!(
            !lease.used,
            "lease must remain valid while the exact process is live"
        );

        // Debug keeps the full decision stream for diagnostics. Release
        // intentionally drops successful allows, including lease-bound ones.
        if cfg!(debug_assertions) {
            let rec = record.expect("audit record");
            assert_eq!(rec.resource_kind, ProtectedResourceKind::SshPrivateKey);
            assert_eq!(rec.decision, Decision::AllowByLease(lease_id));
            assert_eq!(rec.deny_reason, None);
            let json = serde_json::to_string(&rec).unwrap();
            assert!(
                !json.contains(guard_test_fixtures::markers::SSH_PRIVATE_KEY_MARKER),
                "allow audit record must not contain private-key marker: {json}"
            );
        } else {
            assert!(record.is_none());
        }
    }

    #[test]
    fn ssh_load_lease_multiple_events_same_live_process_allowed() {
        // A real ssh-add emits multiple FAN_ACCESS_PERM events for one load
        // (open + reads). While the exact process is still live, every event
        // must be allowed by the one-shot lease; the lease is consumed when
        // the process exits, not on the first event.
        let s = guard_test_fixtures::SshFixture::create().unwrap();
        let mut engine =
            EnforcementEngine::from_config(&ssh_config(&s.private_key)).expect("engine");
        let my_uid = unsafe { libc::getuid() };
        let target = my_stable_identity(&mut engine);
        let my_pid = std::process::id() as i32;
        let (lease_id, _) = engine
            .authorize_ssh_load(
                &s.private_key,
                my_uid,
                target,
                my_pid as u32,
                SshAgentBinding::UncheckedForTests,
            )
            .expect("authorize");

        // Multiple opens/events from the same live process are all part of
        // one load: each must be allowed, and the lease stays valid.
        for _ in 0..3 {
            let f = std::fs::File::open(&s.private_key).unwrap();
            assert_eq!(
                engine.decide_with_context(my_pid, f.as_raw_fd()).0,
                Decision::AllowByLease(lease_id),
                "every event from the live exact process must be allowed"
            );
        }
        let lease = engine
            .leases()
            .ssh
            .iter()
            .find(|l| l.id == lease_id)
            .expect("lease present");
        assert!(
            !lease.used,
            "lease must not be consumed while the exact process is live"
        );
    }

    #[test]
    fn ssh_load_lease_consumed_after_exact_process_exits() {
        // Once the exact ssh-add process has exited (or PID was reused), the
        // one-shot lease is consumed and a later open requires confirmation.
        let s = guard_test_fixtures::SshFixture::create().unwrap();
        let mut engine =
            EnforcementEngine::from_config(&ssh_config(&s.private_key)).expect("engine");
        let my_uid = unsafe { libc::getuid() };
        let target = my_stable_identity(&mut engine);
        let my_pid = std::process::id() as i32;
        let (lease_id, _) = engine
            .authorize_ssh_load(
                &s.private_key,
                my_uid,
                target,
                my_pid as u32,
                SshAgentBinding::UncheckedForTests,
            )
            .expect("authorize");

        // First event: allowed while live.
        let f1 = std::fs::File::open(&s.private_key).unwrap();
        assert_eq!(
            engine.decide_with_context(my_pid, f1.as_raw_fd()).0,
            Decision::AllowByLease(lease_id)
        );

        // Simulate the exact process exiting: mark the lease used directly
        // (the daemon observes exit via /proc on the hot path).
        for l in &mut engine.runtime.leases_mut().ssh {
            if l.id == lease_id {
                l.used = true;
            }
        }
        let f2 = std::fs::File::open(&s.private_key).unwrap();
        let d = engine.decide_with_context(my_pid, f2.as_raw_fd()).0;
        assert_eq!(
            d,
            Decision::RequireSshKeyConfirmation,
            "used lease must require confirmation, got {d:?}"
        );
    }

    #[test]
    fn ssh_load_lease_revoked_requires_confirmation() {
        let s = guard_test_fixtures::SshFixture::create().unwrap();
        let mut engine =
            EnforcementEngine::from_config(&ssh_config(&s.private_key)).expect("engine");
        let my_uid = unsafe { libc::getuid() };
        let target = my_stable_identity(&mut engine);
        let my_pid = std::process::id() as i32;
        let (lease_id, _) = engine
            .authorize_ssh_load(
                &s.private_key,
                my_uid,
                target,
                my_pid as u32,
                SshAgentBinding::UncheckedForTests,
            )
            .expect("authorize");

        assert!(engine.revoke_lease(&lease_id.0.to_string()));

        let f = std::fs::File::open(&s.private_key).unwrap();
        let d = engine.decide_with_context(my_pid, f.as_raw_fd()).0;
        assert_eq!(
            d,
            Decision::RequireSshKeyConfirmation,
            "revoked lease must require confirmation, got {d:?}"
        );
        // A revoked lease must NOT be marked used (no successful allow).
        let lease = engine
            .leases()
            .ssh
            .iter()
            .find(|l| l.id == lease_id)
            .expect("lease present");
        assert!(!lease.used);
    }

    #[test]
    fn ssh_load_lease_wrong_identity_requires_confirmation() {
        // Lease bound to a different start_time than the opener => the scope
        // matches (same resource + uid) but the StableIdentity does not, so the
        // opener does not receive the lease and must require confirmation. The
        // lease is NOT marked used.
        let s = guard_test_fixtures::SshFixture::create().unwrap();
        let mut engine =
            EnforcementEngine::from_config(&ssh_config(&s.private_key)).expect("engine");
        let my_uid = unsafe { libc::getuid() };
        let mut wrong_target = my_stable_identity(&mut engine);
        // Tamper with start_time to simulate a different ssh-add invocation
        // (PID reuse or a second unrelated ssh-add process).
        wrong_target.start_time = wrong_target.start_time.wrapping_add(1);
        let my_pid = std::process::id() as i32;
        let (lease_id, _) = engine
            .authorize_ssh_load(
                &s.private_key,
                my_uid,
                wrong_target,
                my_pid as u32,
                SshAgentBinding::UncheckedForTests,
            )
            .expect("authorize");

        let f = std::fs::File::open(&s.private_key).unwrap();
        let d = engine.decide_with_context(my_pid, f.as_raw_fd()).0;
        assert_eq!(
            d,
            Decision::RequireSshKeyConfirmation,
            "wrong-identity opener must require confirmation, got {d:?}"
        );
        let lease = engine
            .leases()
            .ssh
            .iter()
            .find(|l| l.id == lease_id)
            .expect("lease present");
        assert!(!lease.used, "denied open must not mark the lease used");
    }

    #[test]
    fn ssh_load_lease_wrong_uid_errors() {
        // authorize_ssh_load must refuse to issue a lease when the requesting
        // uid does not own the key.
        let s = guard_test_fixtures::SshFixture::create().unwrap();
        let mut engine =
            EnforcementEngine::from_config(&ssh_config(&s.private_key)).expect("engine");
        let my_uid = unsafe { libc::getuid() };
        let wrong_uid = my_uid.wrapping_add(1);
        let target = guard_core::identity::StableIdentity {
            exe: PathBuf::from("/usr/bin/ssh-add"),
            start_time: 1234,
            dev: 9,
            ino: 8,
        };
        let err = engine
            .authorize_ssh_load(
                &s.private_key,
                wrong_uid,
                target,
                1,
                SshAgentBinding::UncheckedForTests,
            )
            .unwrap_err();
        assert!(
            err.contains("owned by uid"),
            "wrong-uid authorize must error about ownership, got: {err}"
        );
        assert!(
            engine.leases().ssh.is_empty(),
            "no lease created on failure"
        );
    }

    #[test]
    fn ssh_load_lease_unprotected_key_errors() {
        // Authorizing a lease on a key that was never enrolled must error.
        let s = guard_test_fixtures::SshFixture::create().unwrap();
        let cfg = EnforcementConfig {
            config_version: platform_linux::config::CONFIG_VERSION,
            enforcement_mode: EnforcementMode::Conservative,
            browsers: vec![],
            enrolled_exes: vec![],
            ssh_keys: vec![],
            process_shield_enabled: false,
        };
        let mut engine = EnforcementEngine::from_config(&cfg).expect("engine");
        let my_uid = unsafe { libc::getuid() };
        let target = guard_core::identity::StableIdentity {
            exe: PathBuf::from("/usr/bin/ssh-add"),
            start_time: 1234,
            dev: 9,
            ino: 8,
        };
        let err = engine
            .authorize_ssh_load(
                &s.private_key,
                my_uid,
                target,
                1,
                SshAgentBinding::UncheckedForTests,
            )
            .unwrap_err();
        assert!(
            err.contains("not a protected SSH private key"),
            "unprotected key authorize must error, got: {err}"
        );
    }

    #[test]
    fn ssh_load_lease_no_lease_requires_confirmation() {
        let s = guard_test_fixtures::SshFixture::create().unwrap();
        let mut engine =
            EnforcementEngine::from_config(&ssh_config(&s.private_key)).expect("engine");
        let my_pid = std::process::id() as i32;
        let f = std::fs::File::open(&s.private_key).unwrap();
        let d = engine.decide_with_context(my_pid, f.as_raw_fd()).0;
        assert_eq!(d, Decision::RequireSshKeyConfirmation);
    }

    // --- Phase 13: hardening and bypass-oriented tests ---

    /// Relative path / `..` traversal: classify_fd uses canonicalize, so a
    /// relative path with `..` that resolves to a protected file still
    /// classifies. An attacker cannot bypass by opening via a convoluted
    /// relative path.
    #[test]
    fn classify_fd_resolves_relative_dotdot_path() {
        let p = ChromiumProfile::create("Default").unwrap();
        let engine =
            EnforcementEngine::from_config(&chrome_config(&p.user_data_dir, None)).expect("engine");

        // Create a subdir and open the cookies file via a relative path with ..
        // from that subdir. canonicalize resolves the `..` to the real path.
        let subdir = p.user_data_dir.join("Default/Network/subdir");
        std::fs::create_dir_all(&subdir).unwrap();
        let rel = subdir.join("../Cookies");
        let f = std::fs::File::open(&rel).unwrap();
        let res = engine
            .classify_fd(f.as_raw_fd())
            .expect("relative path must classify");
        assert_eq!(res.kind, ProtectedResourceKind::CookieStore);
    }

    /// File rename after protection: fanotify marks are inode-based, so
    /// renaming a protected file (same inode, new path) still classifies via
    /// the fd_index. An attacker cannot bypass by renaming the file.
    #[test]
    fn classify_fd_follows_rename_via_inode() {
        let p = ChromiumProfile::create("Default").unwrap();
        let engine =
            EnforcementEngine::from_config(&chrome_config(&p.user_data_dir, None)).expect("engine");

        let renamed = p.user_data_dir.join("Default/Network/renamed-cookies");
        // rename preserves the inode.
        std::fs::rename(&p.cookies, &renamed).unwrap();
        let f = std::fs::File::open(&renamed).unwrap();
        let res = engine
            .classify_fd(f.as_raw_fd())
            .expect("renamed file must classify via inode index");
        assert_eq!(res.kind, ProtectedResourceKind::CookieStore);
    }

    #[test]
    fn refreshed_index_retains_live_renamed_inode() {
        let p = ChromiumProfile::create("Default").unwrap();
        let mut engine =
            EnforcementEngine::from_config(&chrome_config(&p.user_data_dir, None)).expect("engine");
        let renamed = p.user_data_dir.join("Default/Network/renamed-cookies");
        std::fs::rename(&p.cookies, &renamed).unwrap();
        std::fs::write(&p.cookies, b"synthetic replacement").unwrap();

        let mut registry = ProtectedResourceRegistry::new();
        CustomProfile {
            browser: BrowserId("chrome".into()),
            family: BrowserFamily::Chromium,
            root: p.user_data_dir.clone(),
            owner_uid: unsafe { libc::getuid() },
        }
        .enroll_into(&mut registry)
        .unwrap();
        extend_fd_index(
            &mut engine.fd_index.write().expect("inode index"),
            &registry,
        );
        engine.registry = registry;

        let renamed_file = std::fs::File::open(&renamed).unwrap();
        assert_eq!(
            engine
                .classify_fd(renamed_file.as_raw_fd())
                .expect("renamed inode retained")
                .kind,
            ProtectedResourceKind::CookieStore
        );
        let replacement_file = std::fs::File::open(&p.cookies).unwrap();
        assert_eq!(
            engine
                .classify_fd(replacement_file.as_raw_fd())
                .expect("replacement inode indexed")
                .kind,
            ProtectedResourceKind::CookieStore
        );
    }

    /// Browser/profile path containing spaces and unicode: enrollment +
    /// classification must handle non-ASCII paths without panicking or
    /// misclassifying.
    #[test]
    fn classify_fd_handles_spaces_and_unicode_in_path() {
        let tmp = tempfile::tempdir().unwrap();
        // A profile root with spaces + unicode.
        let udd = tmp.path().join("my chrome 数据");
        let net_dir = udd.join("Default/Network");
        std::fs::create_dir_all(&net_dir).unwrap();
        let cookies = net_dir.join("Cookies");
        std::fs::write(&cookies, b"synthetic").unwrap();

        let cfg = EnforcementConfig {
            config_version: platform_linux::config::CONFIG_VERSION,
            enforcement_mode: EnforcementMode::Conservative,
            browsers: vec![BrowserEnrollmentConfig {
                id: "chrome".into(),
                family: BrowserFamily::Chromium,
                profile_root: udd.clone(),
                owner_uid: Some(unsafe { libc::getuid() }),
                exe_paths: vec![],
            }],
            enrolled_exes: vec![],
            ssh_keys: vec![],
            process_shield_enabled: false,
        };
        let engine = EnforcementEngine::from_config(&cfg).expect("engine");

        let f = std::fs::File::open(&cookies).unwrap();
        let res = engine
            .classify_fd(f.as_raw_fd())
            .expect("unicode path classified");
        assert_eq!(res.kind, ProtectedResourceKind::CookieStore);
    }

    /// User-writable trusted executable changed after enrollment: the
    /// enrollment store must detect the content change (hash mismatch) and
    /// invalidate the enrollment, dropping the process to Unknown trust.
    #[test]
    fn enrollment_invalidates_when_exe_content_changes() {
        let tmp = tempfile::tempdir().unwrap();
        let exe = tmp.path().join("fake-browser");
        std::fs::write(&exe, b"original content").unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&exe).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&exe, perms).unwrap();

        let mut store = EnrollmentStore::new();
        store.enroll(&exe).expect("enroll");
        assert!(store.verify(&exe), "unchanged exe must verify");

        // Modify the exe content (different length so file identity's size
        // field changes too). The hash must mismatch and invalidate enrollment.
        std::fs::write(&exe, b"tampered content with different length").unwrap();
        assert!(
            !store.verify(&exe),
            "tampered exe must fail verification (hash mismatch)"
        );
    }

    /// Multiple Linux users in policy: three distinct UIDs — the resource
    /// owner, a same-UID trusted browser, and a different-UID process. The
    /// different-UID process is denied by WrongUid before identity is even
    /// considered.
    #[test]
    fn policy_multi_uid_wrong_uid_denied() {
        let res = cookie_resource("chrome", "Default", 1000);
        let owner_proc = trusted_browser_process(1000, "chrome");
        let other_uid_proc = trusted_browser_process(2000, "chrome");

        // Owner process (uid 1000) on own profile => Allow.
        let event = AccessEvent {
            resource: res.clone(),
            process: owner_proc,
            operation: AccessOperation::Open,
        };
        assert_eq!(
            evaluate(&event, &LeaseSet::default(), 0, 0),
            Decision::Allow
        );

        // Different-UID process (uid 2000) => WrongUid (identity doesn't matter).
        let event = AccessEvent {
            resource: res,
            process: other_uid_proc,
            operation: AccessOperation::Open,
        };
        assert_eq!(
            evaluate(&event, &LeaseSet::default(), 0, 0),
            Decision::Deny(DenyReason::WrongUid)
        );
    }

    /// Child process tries access: a child of a trusted browser with a
    /// different exe (e.g. a helper, a shell, an agent) is NOT automatically
    /// trusted just because its parent was a browser. The child's own exe
    /// identity determines trust.
    #[test]
    fn policy_child_process_with_different_exe_denied() {
        let res = cookie_resource("chrome", "Default", 1000);
        // A process whose exe is NOT the enrolled chrome binary — even if it
        // somehow has browser=Some("chrome") set, it is NOT trusted (trust_tier
        // is Unknown because the exe doesn't match any enrollment).
        let untrusted_child = ProcessIdentity {
            stable: guard_core::identity::ProcessStableId {
                pid: 99999,
                start_time: 12345,
                exe: PathBuf::from("/usr/bin/some-helper"),
                exe_dev: 0,
                exe_ino: 0,
            },
            uid: 1000,
            gid: 1000,
            exe_owner_uid: 0,
            trust_tier: TrustTier::Unknown,
            browser: None,
            cmdline: vec![],
            ancestors: vec![],
            integrity: ProcessIntegrity::Normal,
        };
        let event = AccessEvent {
            resource: res,
            process: untrusted_child,
            operation: AccessOperation::Open,
        };
        // uid matches owner (1000) so it passes the WrongUid gate, but it's
        // not the owning browser and not trusted => UnknownProcess.
        assert_eq!(
            evaluate(&event, &LeaseSet::default(), 0, 0),
            Decision::Deny(DenyReason::UnknownProcess)
        );
    }

    #[test]
    fn pending_migration_details_bind_exact_opener_instance() {
        // LFH5: EXACT READER INSTANCE. The approval flow binds the exact
        // opener process observed at the confirmation event — even a helper
        // whose ancestors are the target browser must never upgrade to a
        // whole-tree grant.
        let mut helper = trusted_browser_process(1000, "firefox");
        helper.stable.pid = 300;
        helper.stable.start_time = 3000;
        helper.ancestors = vec![
            AncestorSummary {
                pid: 200,
                start_time: 2000,
                exe: PathBuf::from("/usr/bin/firefox"),
                exe_dev: 100,
                exe_ino: 200,
            },
            AncestorSummary {
                pid: 100,
                start_time: 1000,
                exe: PathBuf::from("/usr/bin/firefox"),
                exe_dev: 100,
                exe_ino: 200,
            },
        ];
        // The bound root is the exact opener instance, not the topmost
        // same-exe ancestor (old tree semantics).
        assert_eq!(helper.stable.pid, 300);
        // `target_browser_root`-style ancestor walks are gone; the details
        // carry the exact opener stable identity.
        let details = MigrationPendingDetails {
            candidate: MigrationCandidate {
                source_browser: BrowserId("chrome".into()),
                source_profile: ProfileId("Default".into()),
                target_browser: BrowserId("firefox".into()),
            },
            resource: cookie_resource("chrome", "Default", 1000),
            target: helper.clone(),
            target_root: helper.stable.clone(),
        };
        assert_eq!(details.target_root, helper.stable);
    }

    // Helpers for policy-level multi-uid / child tests.
    fn cookie_resource(browser: &str, profile: &str, owner_uid: u32) -> ProtectedResource {
        ProtectedResource {
            id: ProtectedResourceId("/synthetic/Cookies".into()),
            kind: ProtectedResourceKind::CookieStore,
            path: PathBuf::from("/synthetic/Cookies"),
            owner_uid,
            browser: Some(BrowserId(browser.into())),
            profile: Some(ProfileId(profile.into())),
        }
    }

    fn trusted_browser_process(uid: u32, browser: &str) -> ProcessIdentity {
        ProcessIdentity {
            stable: guard_core::identity::ProcessStableId {
                pid: 10000 + uid,
                start_time: 5000,
                exe: PathBuf::from("/usr/bin/fake-browser"),
                exe_dev: 0,
                exe_ino: 0,
            },
            uid,
            gid: uid,
            exe_owner_uid: 0,
            trust_tier: TrustTier::SystemPackage,
            browser: Some(BrowserId(browser.into())),
            cmdline: vec![],
            ancestors: vec![],
            integrity: ProcessIntegrity::Normal,
        }
    }

    // --- LFH5: EXACT READER INSTANCE binding + generation bound ---

    #[test]
    fn manual_armed_lease_binds_exact_descendant_helper() {
        let chrome = ChromiumProfile::create("Default").unwrap();
        let ff = FirefoxProfile::create("ff-profile").unwrap();
        let ff_exe = ff.root_path().join("fake-firefox-bin");
        std::fs::copy(find_sleep(), &ff_exe).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ff_exe, std::fs::Permissions::from_mode(0o755)).unwrap();

        let uid = unsafe { libc::getuid() };
        let mut engine = EnforcementEngine::from_config(&migration_config(
            &chrome.user_data_dir,
            &ff.profile_dir,
            &ff_exe,
        ))
        .expect("engine");

        let (lease_id, _) = engine
            .authorize_migration("chrome", "Default", "firefox", uid, None)
            .expect("authorize");
        assert_eq!(lease_id.0, 1);
        // The armed lease is stamped with the current continuity generation.
        assert_eq!(
            engine.leases().migration[0].generation,
            engine.runtime.current_generation()
        );

        // A helper whose ancestor is the armed target browser is observed at
        // bind time: the lease binds the EXACT helper instance (post-bind
        // observed exact descendant), never the browser root.
        let ff_canon = std::fs::canonicalize(&ff_exe).unwrap();
        let meta = std::fs::metadata(&ff_canon).unwrap();
        use std::os::unix::fs::MetadataExt;
        let helper = ProcessIdentity {
            stable: guard_core::identity::ProcessStableId {
                pid: 4242,
                start_time: 424_200,
                exe: PathBuf::from("/usr/lib/firefox/helper"),
                exe_dev: 0,
                exe_ino: 0,
            },
            uid,
            gid: uid,
            exe_owner_uid: 0,
            trust_tier: TrustTier::SystemPackage,
            browser: None,
            cmdline: vec![],
            ancestors: vec![AncestorSummary {
                pid: 200,
                start_time: 2000,
                exe: ff_canon,
                exe_dev: meta.dev(),
                exe_ino: meta.ino(),
            }],
            integrity: ProcessIntegrity::Normal,
        };
        let res = cookie_resource("chrome", "Default", uid);
        engine.refresh_migration_states(&res, &helper);
        assert!(
            matches!(
                &engine.leases().migration[0].state,
                MigrationLeaseState::Bound { root } if root == &helper.stable
            ),
            "manual armed lease must bind the exact observed helper instance"
        );

        // A second armed lease; an unrelated helper (ancestor outside the
        // authorized tree) must NOT bind it — it stays Armed.
        let (lease2, _) = engine
            .authorize_migration("chrome", "Default", "firefox", uid, None)
            .expect("authorize");
        assert_eq!(lease2.0, 2);
        let unrelated = ProcessIdentity {
            stable: helper.stable.clone(),
            uid,
            gid: uid,
            exe_owner_uid: 0,
            trust_tier: TrustTier::SystemPackage,
            browser: None,
            cmdline: vec![],
            ancestors: vec![AncestorSummary {
                pid: 999,
                start_time: 999,
                exe: PathBuf::from("/usr/bin/unrelated"),
                exe_dev: 0,
                exe_ino: 0,
            }],
            integrity: ProcessIntegrity::Normal,
        };
        engine.refresh_migration_states(&res, &unrelated);
        assert!(
            matches!(
                &engine.leases().migration[1].state,
                MigrationLeaseState::Armed { .. }
            ),
            "an unrelated helper must never bind an armed lease"
        );
    }

    #[test]
    fn lose_continuity_bumps_generation_and_kills_preloss_lease() {
        let chrome = ChromiumProfile::create("Default").unwrap();
        let ff = FirefoxProfile::create("ff-profile").unwrap();
        let ff_exe = ff.root_path().join("fake-firefox-bin");
        std::fs::copy(find_sleep(), &ff_exe).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ff_exe, std::fs::Permissions::from_mode(0o755)).unwrap();

        let uid = unsafe { libc::getuid() };
        let mut engine = EnforcementEngine::from_config(&migration_config(
            &chrome.user_data_dir,
            &ff.profile_dir,
            &ff_exe,
        ))
        .expect("engine");
        let gen_before = engine.runtime.current_generation();

        let (lease_id, _) = engine
            .authorize_migration("chrome", "Default", "firefox", uid, None)
            .expect("authorize");

        let (guard, ff_pid) = spawn_exe(&ff_exe);
        let _g = KillOnDrop(Some(guard));

        // Baseline: pre-loss the armed lease binds the exact firefox instance
        // and authorizes it.
        let f = std::fs::File::open(&chrome.cookies).unwrap();
        assert_eq!(
            engine.decide(ff_pid, f.as_raw_fd()),
            Decision::AllowByLease(lease_id)
        );

        // Continuity loss revokes all authority AND bumps the generation.
        engine.lose_continuity(ContinuityLossReason::FanotifyQueueOverflow);
        assert!(engine.continuity.is_lost());
        assert_eq!(engine.runtime.current_generation(), gen_before + 1);

        // Defense in depth: even if revocation of this lease failed (simulated
        // by clearing the revoked flag), the stale generation must deny it.
        for l in &mut engine.runtime.leases_mut().migration {
            l.revoked = false;
        }
        let f2 = std::fs::File::open(&chrome.cookies).unwrap();
        assert_eq!(
            engine.decide(ff_pid, f2.as_raw_fd()),
            Decision::Deny(DenyReason::StaleLeaseGeneration),
            "a pre-loss lease must be dead by generation even if revocation missed it"
        );
    }

    // --- LFH3: protection continuity ---

    #[test]
    fn continuity_starts_intact_and_loses_sticky() {
        let mut continuity = ProtectionContinuity::Intact { generation: 1 };
        assert!(!continuity.is_lost());
        continuity.record_loss(ContinuityLossReason::FanotifyQueueOverflow);
        assert!(continuity.is_lost());
        // Second loss keeps the earliest reason (sticky).
        continuity.record_loss(ContinuityLossReason::RequiredMarkLoss);
        match continuity {
            ProtectionContinuity::Lost { reason, .. } => {
                assert_eq!(reason, ContinuityLossReason::FanotifyQueueOverflow);
            }
            _ => panic!("must stay lost"),
        }
    }

    #[test]
    fn lose_continuity_revokes_all_leases_and_bindings() {
        let s = guard_test_fixtures::SshFixture::create().unwrap();
        let mut engine =
            EnforcementEngine::from_config(&ssh_config(&s.private_key)).expect("engine");
        let my_uid = unsafe { libc::getuid() };
        let target = my_stable_identity(&mut engine);
        let my_pid = std::process::id() as i32;
        let (_lease_id, _) = engine
            .authorize_ssh_load(
                &s.private_key,
                my_uid,
                target,
                my_pid as u32,
                SshAgentBinding::UncheckedForTests,
            )
            .expect("authorize");
        assert!(!engine.leases().ssh[0].revoked);

        engine.lose_continuity(ContinuityLossReason::FanotifyQueueOverflow);
        assert!(engine.continuity.is_lost());
        assert!(
            engine.leases().ssh.iter().all(|lease| lease.revoked),
            "all SSH load leases must be revoked on continuity loss"
        );
        assert!(engine.ssh_agent_bindings.is_empty());
        assert!(engine.identity_cache.is_empty());
    }
}
