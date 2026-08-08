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
use guard_core::identity::{ExeIdentity, ProcessIdentity};
use guard_core::lease::{LeaseId, LeaseSet, MigrationAccessLease, MigrationLeaseState};
use guard_core::policy::{evaluate, AccessEvent, AccessOperation, Decision, DenyReason};
use guard_core::resource::{
    BrowserFamily, BrowserId, ProfileId, ProtectedResource, ProtectedResourceKind,
};
use platform_linux::enrollment::EnrollmentStore;
use platform_linux::fanotify;
use platform_linux::identity as linux_identity;
use serde::{Deserialize, Serialize};

/// Default migration lease duration (10 minutes), per `08_MIGRATION_LEASE.md`.
pub const DEFAULT_MIGRATION_DURATION_SECS: u64 = 600;
/// Maximum migration lease duration (1 hour). Longer requests are capped so a
/// migration grant can never become de-facto permanent trust.
pub const MAX_MIGRATION_DURATION_SECS: u64 = 3600;
/// Default SSH load lease duration (30 seconds), per `11_SSH_AGENT_LOAD_FLOW.md`.
/// The lease is one-shot and also revoked on process exit; the timeout is a
/// safety net in case `guardctl` crashes before sending the complete signal.
pub const DEFAULT_SSH_LOAD_DURATION_SECS: u64 = 30;
/// Maximum SSH load lease duration (5 minutes). A load should complete in
/// seconds; this caps a stuck `ssh-add` from keeping the lease alive.
pub const MAX_SSH_LOAD_DURATION_SECS: u64 = 300;

pub type InodeIndex = Arc<RwLock<HashMap<(u64, u64), ProtectedResource>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum EnforcementMode {
    #[default]
    Conservative,
    StrictFilesystem,
}

impl EnforcementMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Conservative => "conservative",
            Self::StrictFilesystem => "strict-filesystem",
        }
    }
}

/// One browser enrollment from config. Drives BOTH resource discovery (which
/// files are protected) and process identity (which exe is this browser). The
/// `BrowserId` is config-supplied — no trust is inferred from a path name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserEnrollmentConfig {
    pub id: String,
    pub family: BrowserFamily,
    /// Chromium `user_data_dir` or Firefox profiles root / single profile dir.
    pub profile_root: PathBuf,
    /// Profile owner UID. If omitted, auto-detected from `profile_root` owner.
    #[serde(default)]
    pub owner_uid: Option<u32>,
    /// Canonical executable path(s) that identify this browser process.
    #[serde(default)]
    pub exe_paths: Vec<PathBuf>,
}

/// User-writable executables (e.g. AppImage/custom browser builds) to
/// hash-enroll so they can reach `EnrolledUserWritable` trust.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementConfig {
    #[serde(default)]
    pub enforcement_mode: EnforcementMode,
    pub browsers: Vec<BrowserEnrollmentConfig>,
    #[serde(default)]
    pub enrolled_exes: Vec<PathBuf>,
    /// SSH private-key paths to protect at startup (Phase 10). Each is enrolled
    /// as a `SshPrivateKey` resource. Runtime enrollment via `guardctl ssh
    /// protect PATH` goes through IPC and does not need to be listed here.
    #[serde(default)]
    pub ssh_keys: Vec<PathBuf>,
}

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
    pub(crate) leases: LeaseSet,
    /// Lease -> root-pinned SSH agent socket required in the live ssh-add
    /// environment. Kept in the Linux backend because environment inspection
    /// is an OS enforcement fact, not a pure policy-domain concern.
    ssh_agent_bindings: HashMap<LeaseId, PathBuf>,
    /// Monotonic lease-id counter (migration + ssh leases share this space).
    next_lease_id: u64,
    /// The browser enrollment config, retained for IPC `browsers list` queries.
    browser_config: Vec<BrowserEnrollmentConfig>,
    /// Decision counters (hot-path observability; no per-event allocation).
    pub allowed: u64,
    pub denied: u64,
    /// Decisions where classify_fd failed (race / unmarked path). Fail-closed.
    pub unclassified: u64,
    /// Persistent topology refresh is currently failing; existing marks still
    /// enforce, but replacement/new-object coverage may be stale.
    pub topology_degraded: bool,
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
                None => stat_owner(&b.profile_root).unwrap_or(0),
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
            leases: LeaseSet::default(),
            ssh_agent_bindings: HashMap::new(),
            next_lease_id: 0,
            browser_config: cfg.browsers.clone(),
            allowed: 0,
            denied: 0,
            unclassified: 0,
            topology_degraded: false,
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

    /// Active leases (for IPC `leases list`). Phase 08 adds creation; Phase 07
    /// exposes the read-only view and revoke.
    pub fn leases(&self) -> &LeaseSet {
        &self.leases
    }

    /// Revoke a lease by its id string. Returns `false` if no lease with that
    /// id exists. Migration and SSH leases are both searched.
    pub fn revoke_lease(&mut self, id_str: &str) -> bool {
        let id = match id_str.parse::<u64>() {
            Ok(n) => LeaseId(n),
            Err(_) => return false,
        };
        let mut found = false;
        for l in &mut self.leases.migration {
            if l.id == id {
                l.revoked = true;
                found = true;
            }
        }
        for l in &mut self.leases.ssh {
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

    /// Authorize a cross-browser migration access lease. The
    /// lease is **armed**: bound to the target browser's executable file
    /// identity (`ExeIdentity`), so it matches the next target process — or any
    /// process in its tree — that opens the named source profile. This avoids
    /// permanent allow-listing while tolerating the target being launched after
    /// authorization.
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
        self.next_lease_id = self.next_lease_id.saturating_add(1);
        let id = LeaseId(self.next_lease_id);
        self.leases.migration.push(MigrationAccessLease {
            id,
            source_browser: BrowserId(source_browser.into()),
            source_profile: ProfileId(source_profile.into()),
            target_browser: BrowserId(target_browser.into()),
            uid,
            state: MigrationLeaseState::Armed { target },
            expires_at,
            revoked: false,
        });
        Ok((id, expires_at))
    }

    /// Authorize a one-shot SSH load lease (Phase 11). The lease is bound to
    /// the exact `ssh-add` process invocation via `StableIdentity` (exe +
    /// start_time + dev + ino). The `uid` is the authorizing user (from
    /// kernel-verified peer creds). The lease auto-expires after
    /// `DEFAULT_SSH_LOAD_DURATION_SECS` and is also revoked by `guardctl`
    /// when `ssh-add` exits.
    ///
    /// Returns `(lease_id, expires_at)` or an error message if the path is not
    /// a protected SSH private key owned by `uid`.
    pub fn authorize_ssh_load(
        &mut self,
        path: &Path,
        uid: u32,
        target: guard_core::identity::StableIdentity,
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
        self.next_lease_id = self.next_lease_id.saturating_add(1);
        let id = LeaseId(self.next_lease_id);
        self.leases.ssh.push(guard_core::lease::SshLoadLease {
            id,
            resource: res.id.clone(),
            uid,
            target,
            expires_at,
            revoked: false,
            used: false,
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

    /// Mark all protected concrete critical files with `FAN_OPEN_PERM`. The
    /// kernel mark is inode-based, so hardlinks to the same inode also fire.
    pub fn mark_files(&self, group: &fanotify::FanotifyGroup) -> std::io::Result<usize> {
        let mut n = 0;
        for res in self.registry.files() {
            group.mark_file(libc::FAN_OPEN_PERM, &res.path)?;
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
        self.decide_with_context(pid, fd).0
    }

    /// Like `decide` but also returns an `AuditRecord` when the opened file was
    /// a protected resource (so the caller can persist it non-blocking via
    /// `AuditStore::record`). Unclassified opens (not a protected resource) are
    /// not audited — they are tracked by the `unclassified` counter only.
    pub fn decide_with_context(&mut self, pid: i32, fd: RawFd) -> (Decision, Option<AuditRecord>) {
        let resource = match self.classify_fd(fd) {
            Some(r) => r,
            None => {
                self.unclassified += 1;
                return (Decision::Deny(DenyReason::UnknownProcess), None);
            }
        };
        self.decide_protected_with_context(pid, resource, classify_diag(fd))
    }

    /// Apply the existing policy to a resource already identified by Strict
    /// Mode's filesystem-event classifier. Unrelated filesystem opens never
    /// call this function and therefore avoid process resolution entirely.
    pub fn decide_protected_with_context(
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
        let mut decision = evaluate(
            &AccessEvent {
                resource: resource.clone(),
                process: process.clone(),
                operation: AccessOperation::Open,
            },
            &self.leases,
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
                        decision = Decision::Deny(DenyReason::IdentityMismatch);
                    }
                }
            }
        }
        match decision {
            Decision::Allow | Decision::AllowByLease(_) => self.allowed += 1,
            Decision::Deny(_) => self.denied += 1,
        }
        // Phase 11: mark one-shot SSH load lease as used after a successful
        // allow. The lease binds to the exact ssh-add invocation; once it
        // reads the key, the `used` flag prevents any further open — even by
        // the same process — from re-using it.
        if let Decision::AllowByLease(id) = decision {
            let mut consumed = false;
            for l in &mut self.leases.ssh {
                if l.id == id {
                    l.used = true;
                    consumed = true;
                    break;
                }
            }
            if consumed {
                self.ssh_agent_bindings.remove(&id);
            }
        }
        let backend_diag = format!(
            "{};classify={};trust={:?}",
            resolve_diag, classification, process.trust_tier
        );
        let record = build_audit_record(&resource, Some(&process), decision, &backend_diag);
        (decision, Some(record))
    }

    /// Bind an armed migration lease to the first matching target process and
    /// retire bound leases as soon as their root process exits. This mutation
    /// happens while the engine mutex is held, immediately before policy
    /// evaluation, so an armed executable-wide grant is never exposed.
    fn refresh_migration_states(
        &mut self,
        resource: &ProtectedResource,
        process: &ProcessIdentity,
    ) {
        for lease in &mut self.leases.migration {
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

            let root = if process.stable.exe_identity() == *target {
                Some(process.stable.clone())
            } else {
                process
                    .ancestors
                    .iter()
                    .find(|ancestor| ancestor.exe_identity() == *target)
                    .map(|ancestor| guard_core::identity::ProcessStableId {
                        pid: ancestor.pid,
                        start_time: ancestor.start_time,
                        exe: ancestor.exe.clone(),
                        exe_dev: ancestor.exe_dev,
                        exe_ino: ancestor.exe_ino,
                    })
            };
            if let Some(root) = root {
                lease.state = MigrationLeaseState::Bound { root };
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
fn build_audit_record(
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
    let lease_id = match decision {
        Decision::AllowByLease(id) => Some(id.0),
        _ => None,
    };
    let deny_reason = match decision {
        Decision::Deny(r) => Some(r),
        _ => None,
    };
    AuditRecord {
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
    use guard_core::identity::TrustTier;
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
            enforcement_mode: EnforcementMode::Conservative,
            browsers: vec![b],
            enrolled_exes: vec![],
            ssh_keys: vec![],
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
        }
    }

    // --- resource classification via fd ---

    #[test]
    fn config_accepts_documented_lowercase_browser_families() {
        let config: EnforcementConfig = serde_json::from_str(
            r#"{
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
    fn decide_cross_browser_denied_without_lease() {
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
            matches!(d, Decision::Deny(DenyReason::CrossBrowserWithoutLease)),
            "chrome reading firefox without lease => CrossBrowserWithoutLease, got {:?}",
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

        // Before lease: firefox opening chrome cookies => cross-browser deny.
        let f = std::fs::File::open(&chrome.cookies).unwrap();
        let d = engine.decide(ff_pid, f.as_raw_fd());
        assert!(
            matches!(d, Decision::Deny(DenyReason::CrossBrowserWithoutLease)),
            "firefox reading chrome without lease => CrossBrowserWithoutLease, got {d:?}"
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
            enforcement_mode: EnforcementMode::Conservative,
            browsers: vec![],
            enrolled_exes: vec![],
            ssh_keys: vec![ssh_key.to_path_buf()],
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
            enforcement_mode: EnforcementMode::Conservative,
            browsers: vec![],
            enrolled_exes: vec![],
            ssh_keys: vec![],
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
            enforcement_mode: EnforcementMode::Conservative,
            browsers: vec![],
            enrolled_exes: vec![],
            ssh_keys: vec![],
        };
        let mut engine = EnforcementEngine::from_config(&cfg).expect("engine");
        let err = engine.protect_ssh_key(&s.public_key).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn ssh_protect_rejects_reserved_name() {
        let s = guard_test_fixtures::SshFixture::create().unwrap();
        let cfg = EnforcementConfig {
            enforcement_mode: EnforcementMode::Conservative,
            browsers: vec![],
            enrolled_exes: vec![],
            ssh_keys: vec![],
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
    fn ssh_key_denied_for_ordinary_process() {
        // The test process itself is an "ordinary process" (not a trusted
        // browser, not holding a SshLoadLease). Opening an enrolled SSH key
        // must be denied with SshPrivateKeyRawRead.
        let s = guard_test_fixtures::SshFixture::create().unwrap();
        let mut engine =
            EnforcementEngine::from_config(&ssh_config(&s.private_key)).expect("engine");
        let f = std::fs::File::open(&s.private_key).unwrap();
        let my_pid = std::process::id() as i32;
        let (decision, record) = engine.decide_with_context(my_pid, f.as_raw_fd());
        assert_eq!(
            decision,
            Decision::Deny(DenyReason::SshPrivateKeyRawRead),
            "ordinary process must be denied raw SSH key read"
        );
        let rec = record.expect("audit record");
        assert_eq!(rec.resource_kind, ProtectedResourceKind::SshPrivateKey);
        assert_eq!(rec.deny_reason, Some(DenyReason::SshPrivateKeyRawRead));
    }

    #[test]
    fn ssh_key_audit_record_has_no_secret_content() {
        // The audit record for a denied SSH key open must NOT contain the
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
    fn ssh_load_lease_authorize_then_allowed_and_marked_used() {
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
                SshAgentBinding::UncheckedForTests,
            )
            .expect("authorize");
        assert_eq!(lease_id.0, 1);
        assert!(expires_at > now_secs_for_test());

        // Opening the key under the lease => AllowByLease.
        let f = std::fs::File::open(&s.private_key).unwrap();
        let (decision, record) = engine.decide_with_context(my_pid, f.as_raw_fd());
        assert_eq!(
            decision,
            Decision::AllowByLease(lease_id),
            "lease-bound open must be allowed"
        );
        // The one-shot lease is now marked used.
        let lease = engine
            .leases()
            .ssh
            .iter()
            .find(|l| l.id == lease_id)
            .expect("lease present");
        assert!(
            lease.used,
            "lease must be marked used after a successful allow"
        );

        // Audit record: AllowByLease on an SSH key, no secret contents.
        let rec = record.expect("audit record");
        assert_eq!(rec.resource_kind, ProtectedResourceKind::SshPrivateKey);
        assert_eq!(rec.decision, Decision::AllowByLease(lease_id));
        assert_eq!(rec.deny_reason, None);
        let json = serde_json::to_string(&rec).unwrap();
        assert!(
            !json.contains(guard_test_fixtures::markers::SSH_PRIVATE_KEY_MARKER),
            "allow audit record must not contain private-key marker: {json}"
        );
    }

    #[test]
    fn ssh_load_lease_used_denies_second_open() {
        // After the one-shot allow marks the lease used, a second open — even by
        // the exact same process — is denied with OneShotLeaseUsed.
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
                SshAgentBinding::UncheckedForTests,
            )
            .expect("authorize");

        // First open: allowed, lease marked used.
        let f1 = std::fs::File::open(&s.private_key).unwrap();
        assert_eq!(
            engine.decide_with_context(my_pid, f1.as_raw_fd()).0,
            Decision::AllowByLease(lease_id)
        );

        // Second open: denied (one-shot used).
        let f2 = std::fs::File::open(&s.private_key).unwrap();
        let d = engine.decide_with_context(my_pid, f2.as_raw_fd()).0;
        assert_eq!(
            d,
            Decision::Deny(DenyReason::OneShotLeaseUsed),
            "second open must be denied (lease used), got {d:?}"
        );
    }

    #[test]
    fn ssh_load_lease_revoked_denied() {
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
                SshAgentBinding::UncheckedForTests,
            )
            .expect("authorize");

        assert!(engine.revoke_lease(&lease_id.0.to_string()));

        let f = std::fs::File::open(&s.private_key).unwrap();
        let d = engine.decide_with_context(my_pid, f.as_raw_fd()).0;
        assert_eq!(
            d,
            Decision::Deny(DenyReason::LeaseRevoked),
            "revoked lease must be denied, got {d:?}"
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
    fn ssh_load_lease_wrong_identity_denied() {
        // Lease bound to a different start_time than the opener => the scope
        // matches (same resource + uid) but the StableIdentity does not, so the
        // open is denied with IdentityMismatch. The lease is NOT marked used.
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
                SshAgentBinding::UncheckedForTests,
            )
            .expect("authorize");

        let f = std::fs::File::open(&s.private_key).unwrap();
        let d = engine.decide_with_context(my_pid, f.as_raw_fd()).0;
        assert_eq!(
            d,
            Decision::Deny(DenyReason::IdentityMismatch),
            "wrong-identity open must be denied with IdentityMismatch, got {d:?}"
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
            enforcement_mode: EnforcementMode::Conservative,
            browsers: vec![],
            enrolled_exes: vec![],
            ssh_keys: vec![],
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
                SshAgentBinding::UncheckedForTests,
            )
            .unwrap_err();
        assert!(
            err.contains("not a protected SSH private key"),
            "unprotected key authorize must error, got: {err}"
        );
    }

    #[test]
    fn ssh_load_lease_no_lease_denies_as_raw_read() {
        // Without any lease, an ordinary process opening the SSH key is denied
        // with SshPrivateKeyRawRead (the Phase 10 baseline still holds).
        let s = guard_test_fixtures::SshFixture::create().unwrap();
        let mut engine =
            EnforcementEngine::from_config(&ssh_config(&s.private_key)).expect("engine");
        let my_pid = std::process::id() as i32;
        let f = std::fs::File::open(&s.private_key).unwrap();
        let d = engine.decide_with_context(my_pid, f.as_raw_fd()).0;
        assert_eq!(d, Decision::Deny(DenyReason::SshPrivateKeyRawRead));
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
        assert_eq!(evaluate(&event, &LeaseSet::default(), 0), Decision::Allow);

        // Different-UID process (uid 2000) => WrongUid (identity doesn't matter).
        let event = AccessEvent {
            resource: res,
            process: other_uid_proc,
            operation: AccessOperation::Open,
        };
        assert_eq!(
            evaluate(&event, &LeaseSet::default(), 0),
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
        };
        let event = AccessEvent {
            resource: res,
            process: untrusted_child,
            operation: AccessOperation::Open,
        };
        // uid matches owner (1000) so it passes the WrongUid gate, but it's
        // not the owning browser and not trusted => UnknownProcess.
        assert_eq!(
            evaluate(&event, &LeaseSet::default(), 0),
            Decision::Deny(DenyReason::UnknownProcess)
        );
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
        }
    }
}
