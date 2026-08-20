//! Strict filesystem-wide event classification.
//!
//! A filesystem mark causes unrelated opens to reach guardd. This classifier
//! performs only fstat, a read lock over the small protected-inode index, and
//! `/proc/self/fd` readlink/path matching. Process identity and policy are
//! intentionally deferred until a protected candidate is found.

use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use guard_core::resource::{
    BrowserFamily, BrowserId, ProfileId, ProtectedResource, ProtectedResourceId,
    ProtectedResourceKind,
};
use platform_linux::fanotify;

use crate::enforce::{EnforcementConfig, EnforcementMode, InodeIndex};

// Test-only fault injection: force the next learned-candidate handle
// verification in THIS test thread to fail, proving the classification fails
// closed instead of silently degrading to Unrelated (LFH5 review finding 4).
// Thread-local so parallel tests never observe each other's injection.
#[cfg(test)]
thread_local! {
    pub(crate) static INJECT_HANDLE_VERIFY_FAILURE: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

pub struct BackendMetrics {
    pub mode: EnforcementMode,
    pub marked_filesystems: AtomicUsize,
    pub strict_events_total: AtomicU64,
    pub strict_fast_allowed: AtomicU64,
    pub protected_events: AtomicU64,
    pub fanotify_overflows: AtomicU64,
    pub classifier_failures: AtomicU64,
    pub strict_alias_scans: AtomicU64,
    pub strict_alias_matches: AtomicU64,
    /// LFH1: whether the fanotify group was created with FAN_REPORT_PIDFD.
    pub pidfd_enabled: std::sync::atomic::AtomicBool,
    /// LFH1: events on a pidfd-enabled group that arrived without a usable
    /// pidfd. On accepted kernels this is unexpected and fails closed.
    pub pidfd_missing_events: AtomicU64,
    /// LFH5 review: the learned dynamic-object handle index reached its
    /// bounded capacity. Fail-closed: existing learned identities are NEVER
    /// evicted (an evicted protected identity must not silently become
    /// Unrelated), new candidates are not learned, and the posture degrades.
    pub handle_index_exhausted: std::sync::atomic::AtomicBool,
    /// P1-b (review): the LFH2 Step 3 FID topology identity subsystem is
    /// UNCERTAIN — group creation failed, tree marks incomplete, learner
    /// thread dead, queue overflow, parse/read failure, or a required
    /// topology mark lost. While set, an ambiguous outside-path open (whose
    /// identity would have been established by the topology group) is DENIED
    /// instead of Unrelated, and status reports REDUCED. STICKY until restart
    /// (same philosophy as continuity loss).
    pub topology_uncertain: std::sync::atomic::AtomicBool,
}

impl BackendMetrics {
    pub fn new(mode: EnforcementMode) -> Self {
        Self {
            mode,
            marked_filesystems: AtomicUsize::new(0),
            strict_events_total: AtomicU64::new(0),
            strict_fast_allowed: AtomicU64::new(0),
            protected_events: AtomicU64::new(0),
            fanotify_overflows: AtomicU64::new(0),
            classifier_failures: AtomicU64::new(0),
            strict_alias_scans: AtomicU64::new(0),
            strict_alias_matches: AtomicU64::new(0),
            pidfd_enabled: std::sync::atomic::AtomicBool::new(false),
            pidfd_missing_events: AtomicU64::new(0),
            handle_index_exhausted: std::sync::atomic::AtomicBool::new(false),
            topology_uncertain: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn marked_filesystems(&self) -> usize {
        self.marked_filesystems.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> BackendSnapshot {
        BackendSnapshot {
            marked_filesystems: self.marked_filesystems(),
            strict_events_total: self.strict_events_total.load(Ordering::Relaxed),
            strict_fast_allowed: self.strict_fast_allowed.load(Ordering::Relaxed),
            protected_events: self.protected_events.load(Ordering::Relaxed),
            fanotify_overflows: self.fanotify_overflows.load(Ordering::Relaxed),
            classifier_failures: self.classifier_failures.load(Ordering::Relaxed),
            strict_alias_scans: self.strict_alias_scans.load(Ordering::Relaxed),
            strict_alias_matches: self.strict_alias_matches.load(Ordering::Relaxed),
            pidfd_enabled: self.pidfd_enabled.load(Ordering::Relaxed),
            pidfd_missing_events: self.pidfd_missing_events.load(Ordering::Relaxed),
            handle_index_exhausted: self.handle_index_exhausted.load(Ordering::Relaxed),
            topology_uncertain: self.topology_uncertain.load(Ordering::Relaxed),
        }
    }
}

pub struct BackendSnapshot {
    pub marked_filesystems: usize,
    pub strict_events_total: u64,
    pub strict_fast_allowed: u64,
    pub protected_events: u64,
    pub fanotify_overflows: u64,
    pub classifier_failures: u64,
    pub strict_alias_scans: u64,
    pub strict_alias_matches: u64,
    pub pidfd_enabled: bool,
    pub pidfd_missing_events: u64,
    /// P1-b: LFH2 Step 3 FID topology identity is uncertain (see BackendMetrics).
    pub topology_uncertain: bool,
    pub handle_index_exhausted: bool,
}

#[derive(Debug)]
pub enum StrictClassification {
    Protected(ProtectedResource),
    Unrelated,
    Error(String),
}

/// One learned dynamic-object candidate (LFH2). `(dev, ino)` may map to several
/// protected handles when a browser recreated a resource over time; each entry
/// is compared by opaque handle, never by inode number alone.
#[derive(Debug, Clone)]
struct HandleCandidate {
    handle: platform_linux::object_handle::ObjectHandle,
    resource: ProtectedResource,
}

#[derive(Debug, Clone)]
struct BrowserNamespace {
    browser: BrowserId,
    family: BrowserFamily,
    root: PathBuf,
    owner_uid: u32,
}

#[derive(Debug, Clone)]
struct SshNamespace {
    path: PathBuf,
    owner_uid: u32,
}

/// Topology-learned identity key: `(filesystem fsid, handle_type,
/// handle_bytes)`. The fsid disambiguates opaque filesystem handles across
/// filesystems (review P1-d): a handle is fs-scoped identity, NOT globally
/// unique, so keying without the fsid lets identical payloads on different
/// filesystems collide and misattribute resources/browsers.
pub type TopologyKey = ([u32; 2], i32, Vec<u8>);

pub struct StrictClassifier {
    browsers: Vec<BrowserNamespace>,
    ssh: Vec<SshNamespace>,
    inode_index: InodeIndex,
    /// LFH2: `(dev, ino)` -> learned protected object handles. Only objects
    /// that were opened under a protected path are learned; every other open
    /// skips handle computation (fast path). A reused inode yields a different
    /// handle and is Unrelated (no false positive).
    handle_index: std::sync::RwLock<std::collections::HashMap<(u64, u64), Vec<HandleCandidate>>>,
    /// Bounds the handle index so a pathological re-creation storm cannot grow
    /// it without limit.
    handle_index_capacity: usize,
    /// LFH2 Step 3: NEVER-OPENED dynamic objects learned from the SEPARATE
    /// FAN_CLASS_NOTIF|FAN_REPORT_FID topology group, keyed by
    /// `TopologyKey` = (fsid, handle_type, handle_bytes). Unlike `handle_index`
    /// (keyed by `(dev, ino)`), these objects were never resolved to an
    /// inode — the topology event's fid IS their identity, so an open of the
    /// same object anywhere is recognized purely by handle. Bounded with the
    /// same fail-closed capacity semantics (never evict; degrade health).
    topology_handles: std::sync::RwLock<std::collections::HashMap<TopologyKey, ProtectedResource>>,
    /// R1: the LFH2 Step 3 topology group's queue is drained under this mutex
    /// by BOTH the background learner and, before an ambiguous outside-path
    /// open may be allowed, synchronously by the permission hot path. Holding
    /// the mutex across read→parse→publish makes an "event consumed but
    /// handle not yet published" window impossible, and draining at decision
    /// time guarantees every topology event causally prior to the open
    /// (enqueued to the topology group before the open's permission event) has
    /// been processed — no settle, no scheduler-timing assumption. The mutex
    /// also owns the reusable read buffer.
    topology: std::sync::Mutex<TopologyDrainState>,
    /// R1 (kernel 7.1 fid reality): move events carry the MARKED DIRECTORY's
    /// handle + the moved object's name (DFID_NAME) — never the moved file's
    /// own handle. This map lets the learner resolve the moved file's identity
    /// (`parent/name`) while it remains at the protected path: each marked
    /// dir records its handle at mark time.
    marked_dir_handles:
        std::sync::RwLock<std::collections::HashMap<TopologyKey, std::path::PathBuf>>,
    filesystem_paths: Vec<PathBuf>,
    metrics: std::sync::Arc<BackendMetrics>,
}

/// The topology group reference plus a reusable drain buffer. Serialized by
/// `StrictClassifier::topology`.
struct TopologyDrainState {
    group: Option<std::sync::Arc<fanotify::FanotifyGroup>>,
    buf: Vec<u8>,
}

impl StrictClassifier {
    pub fn new(
        cfg: &EnforcementConfig,
        inode_index: InodeIndex,
        metrics: std::sync::Arc<BackendMetrics>,
    ) -> anyhow::Result<Self> {
        let mut browsers = Vec::with_capacity(cfg.browsers.len());
        let mut ssh = Vec::with_capacity(cfg.ssh_keys.len());
        let mut filesystem_paths = Vec::new();
        let mut devices = HashSet::new();

        for browser in &cfg.browsers {
            let root = std::fs::canonicalize(&browser.profile_root).map_err(|error| {
                anyhow::anyhow!(
                    "strict mode requires existing browser root {}: {error}",
                    browser.profile_root.display()
                )
            })?;
            let metadata = std::fs::metadata(&root)?;
            let owner_uid = browser.owner_uid.unwrap_or(metadata.uid());
            browsers.push(BrowserNamespace {
                browser: BrowserId(browser.id.clone()),
                family: browser.family,
                root: root.clone(),
                owner_uid,
            });
            if devices.insert(metadata.dev()) {
                filesystem_paths.push(root);
            }
        }

        for configured in &cfg.ssh_keys {
            let path = std::fs::canonicalize(configured).map_err(|error| {
                anyhow::anyhow!(
                    "strict mode requires existing configured SSH key {}: {error}",
                    configured.display()
                )
            })?;
            let metadata = std::fs::metadata(&path)?;
            ssh.push(SshNamespace {
                path: path.clone(),
                owner_uid: metadata.uid(),
            });
            if devices.insert(metadata.dev()) {
                filesystem_paths.push(path);
            }
        }

        if filesystem_paths.is_empty() {
            anyhow::bail!("strict-filesystem mode has no protected filesystem to mark");
        }

        Ok(Self {
            browsers,
            ssh,
            inode_index,
            handle_index: std::sync::RwLock::new(std::collections::HashMap::new()),
            topology_handles: std::sync::RwLock::new(std::collections::HashMap::new()),
            topology: std::sync::Mutex::new(TopologyDrainState {
                group: None,
                buf: vec![0u8; 65536],
            }),
            marked_dir_handles: std::sync::RwLock::new(std::collections::HashMap::new()),
            handle_index_capacity: 8192,
            filesystem_paths,
            metrics,
        })
    }

    pub fn filesystem_paths(&self) -> &[PathBuf] {
        &self.filesystem_paths
    }

    /// Make the topology identity coverage sticky-uncertain. Once a topology
    /// mark or learner is lost, an outside-path object can no longer safely be
    /// classified as unrelated; ambiguous opens must fail closed until restart.
    pub(crate) fn mark_topology_uncertain(&self) {
        self.metrics
            .topology_uncertain
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn classify_fd(&self, fd: RawFd) -> StrictClassification {
        let identity = match fanotify::fd_identity(fd) {
            Ok(identity) => identity,
            Err(error) => {
                return StrictClassification::Error(format!("fstat event fd failed: {error}"))
            }
        };

        let path = match fanotify::fd_path(fd) {
            Ok(path) => path,
            Err(error) => {
                return StrictClassification::Error(format!(
                    "readlink event fd path failed: {error}"
                ))
            }
        };

        // Prefer the live path.  Dynamic files under browser trees (SQLite
        // journals/WALs and storage descendants) are routinely deleted and
        // recreated; pinning their inode forever lets inode-number reuse make
        // an unrelated file look like a browser resource.
        if let Some(resource) = self.classify_path(&path) {
            if self.identity_index_is_stable(&path) {
                self.inode_index
                    .write()
                    .expect("inode index lock poisoned")
                    .insert(identity, resource.clone());
            } else {
                // LFH2: a dynamic protected object seen under its protected
                // path is *learned* by opaque handle so a later rename-away /
                // alias open of the SAME object is still recognized, while a
                // reused inode (different handle) is not.
                self.learn_handle(fd, identity, resource.clone());
            }
            return StrictClassification::Protected(resource);
        }

        // LFH2: path did not classify (e.g. the object was renamed outside the
        // profile). If this `(dev, ino)` matches learned dynamic objects,
        // compare the event fd's handle against them: equal handle => same
        // object => Protected; different handle => inode reuse => Unrelated.
        //
        // LFH2 Step 3: topology-learned NEVER-OPENED objects are matched by
        // handle alone (the index is keyed by handle payload, so the event
        // fd's handle is the identity). Checked first so a Step-3 object is
        // recognized even when its inode was never indexed. The per-open
        // handle computation only runs while the topology set is non-empty.
        if self
            .inode_index
            .read()
            .expect("inode index lock poisoned")
            .get(&identity)
            .is_none()
        {
            // R1 (cross-group ordering): before this open may be allowed,
            // ensure every topology event causally prior to it (a rename into
            // a protected tree enqueues the topology group BEFORE the open's
            // permission event, by syscall order) has been processed and its
            // handle published. sync_topology_if_pending takes the SAME mutex
            // the background learner uses, polls the queue, and drains
            // synchronously when it holds events — no settle, no
            // scheduler-timing assumption, no consumed-but-unpublished race.
            //
            // P1-b (review): if the topology identity subsystem is UNCERTAIN
            // (group creation failed, marks incomplete, learner dead, queue
            // overflow, parse/read failure), an ambiguous outside-path open
            // can no longer be trusted to be Unrelated — the object may be a
            // never-opened dynamic object whose identity was lost. Fail closed
            // (Error -> deny) instead of allowing, and status reports REDUCED.
            if self
                .metrics
                .topology_uncertain
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                return StrictClassification::Error(
                    "topology identity uncertain; ambiguous open denied (fail-closed)".into(),
                );
            }
            self.sync_topology_if_pending();
            if self.topology_handles_nonempty() {
                match platform_linux::object_handle::ObjectHandle::from_fd(fd) {
                    Ok(event_handle) => {
                        let fsid = fsid_of_fd(fd);
                        if let Some(resource) =
                            fsid.and_then(|fsid| self.match_topology_handle(fsid, &event_handle))
                        {
                            tracing::debug!(
                                fd_path = %path.display(),
                                handle = format_args!("{:02x?}", event_handle.handle_bytes),
                                "topology: MATCH — object protected by learned handle"
                            );
                            return StrictClassification::Protected(resource);
                        }
                        tracing::debug!(
                            fd_path = %path.display(),
                            handle = format_args!("{:02x?}", event_handle.handle_bytes),
                            "topology: no match for event fd handle"
                        );
                        // No match: the object is not a topology-learned one.
                        // (Deliberately silent — this runs on every non-classifying
                        // open while the topology set is non-empty; logging here
                        // would flood the journal on a busy system.)
                    }
                    Err(error) => {
                        // Fail closed: an unverifiable handle while Step-3
                        // objects are tracked must not silently allow.
                        self.metrics
                            .classifier_failures
                            .fetch_add(1, Ordering::Relaxed);
                        return StrictClassification::Error(format!(
                            "topology handle verification failed: {error}"
                        ));
                    }
                }
            }
            if let Some(protected) = self.match_learned_handles(fd, identity) {
                return protected;
            }
        }

        let indexed_resource = {
            let index = self.inode_index.read().expect("inode index lock poisoned");
            index.get(&identity).cloned()
        };
        if let Some(resource) = indexed_resource {
            // Verify the indexed path's CURRENT identity. The old code
            // short-circuited on `identity_index_is_stable`, assuming a
            // "stable" path always points at the indexed object — but a
            // rename-over replaces the object and frees its inode, and a later
            // unrelated file can REUSE that inode and be falsely Protected
            // (observed in strict-concurrency's topology-race: a staging file
            // reused the replaced cookies inode and was wrongly denied).
            //
            // Precise semantics:
            //   path still resolves to identity  -> Protected (the object)
            //   path exists but different object -> inode reuse -> drop entry
            //   path gone (renamed away / deleted)-> keep LFH2 stable-object
            //     semantics: the inode was indexed under a protected path, an
            //     open of the same inode elsewhere stays Protected.
            match path_identity(&resource.path) {
                Ok(current) if current == identity => {
                    tracing::debug!(fd_path = %path.display(), ?identity, "classify: inode-index -> Protected");
                    return StrictClassification::Protected(resource);
                }
                Ok(_) => {
                    // The protected path now names a different object: a
                    // reused inode must not look protected. Drop the stale
                    // entry before considering aliases so a reused inode
                    // cannot poison unrelated applications.
                    self.inode_index
                        .write()
                        .expect("inode index lock poisoned")
                        .remove(&identity);
                }
                Err(_) => {
                    // Path disappeared. Distinguish two cases:
                    //  - the indexed path was a "(deleted)" readlink artifact:
                    //    the REAL path was rename-over replaced and the inode
                    //    freed — a later file may reuse it, so drop the entry
                    //    (inode reuse must not look Protected).
                    //  - a real path vanished: the stable object was renamed
                    //    away — keep it Protected by inode (LFH2 semantics).
                    if resource.path.to_string_lossy().ends_with("(deleted)") {
                        self.inode_index
                            .write()
                            .expect("inode index lock poisoned")
                            .remove(&identity);
                    } else {
                        return StrictClassification::Protected(resource);
                    }
                }
            }
        }

        match fanotify::fd_link_count(fd) {
            Ok(links) if links > 1 => {
                self.metrics
                    .strict_alias_scans
                    .fetch_add(1, Ordering::Relaxed);
                match self.find_protected_alias(identity) {
                    Ok(Some(resource)) => {
                        self.metrics
                            .strict_alias_matches
                            .fetch_add(1, Ordering::Relaxed);
                        if self.identity_index_is_stable(&resource.path) {
                            self.inode_index
                                .write()
                                .expect("inode index lock poisoned")
                                .insert(identity, resource.clone());
                        }
                        StrictClassification::Protected(resource)
                    }
                    Ok(None) => self.unrelated_or_exhausted(),
                    Err(error) => StrictClassification::Error(error),
                }
            }
            Ok(_) => self.unrelated_or_exhausted(),
            Err(error) => {
                StrictClassification::Error(format!("fstat event fd link count failed: {error}"))
            }
        }
    }

    /// LFH2: learn the opaque handle of a dynamic protected object seen under
    /// its protected path. The `(dev, ino)` key maps to a small candidate list
    /// (a browser may recreate a resource over time); the index is bounded.
    ///
    /// LFH5/R2 review (capacity): when the index is full, EXISTING learned
    /// identities are never evicted — an evicted protected identity must not
    /// silently become Unrelated because a cache reached capacity. New
    /// candidates are refused and the `handle_index_exhausted` health flag is
    /// raised; operationally, once exhausted, any non-path-classified open
    /// whose identity Guard cannot verify is DENIED (`unrelated_or_exhausted`)
    /// instead of allowed — that is the operation-level fail-closed fallback.
    fn learn_handle(&self, fd: RawFd, identity: (u64, u64), resource: ProtectedResource) {
        let handle = match platform_linux::object_handle::ObjectHandle::from_fd(fd) {
            Ok(handle) => handle,
            Err(error) => {
                // A filesystem without handle support simply cannot give this
                // guarantee; the object stays protected via path/inode paths,
                // and the overall posture is REDUCED (reported elsewhere).
                self.metrics
                    .classifier_failures
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(%error, path = %resource.path.display(), "object handle unavailable; dynamic rename guarantee REDUCED");
                return;
            }
        };
        let mut index = self
            .handle_index
            .write()
            .expect("handle index lock poisoned");
        if index.len() >= self.handle_index_capacity {
            // R2: never evict a learned protected identity. Refuse the new
            // candidate and flag the exhausted state; `classify_fd` then
            // denies unverifiable opens (operation-level fail-closed).
            self.metrics
                .handle_index_exhausted
                .store(true, Ordering::Relaxed);
            tracing::warn!(
                path = %resource.path.display(),
                capacity = self.handle_index_capacity,
                "dynamic object handle index full; refusing to learn new candidate; unverifiable opens will be denied"
            );
            return;
        }
        let entry = index.entry(identity).or_default();
        if !entry.iter().any(|candidate| candidate.handle == handle) {
            entry.push(HandleCandidate { handle, resource });
        }
    }

    /// LFH2 Step 3: learn a NEVER-OPENED dynamic object's handle from the
    /// SEPARATE `FAN_CLASS_NOTIF | FAN_REPORT_FID` topology group — the event's
    /// fid IS the object's identity (no inode resolution needed, so this never
    /// depends on `open_by_handle_at`). Keyed by `(handle_type, handle_bytes)`
    /// (opaque payload); an open of the same object anywhere is recognized
    /// purely by handle, which also makes inode reuse a non-issue (a reused
    /// inode has a different handle and does not match). Bounded, R2
    /// fail-closed capacity: existing entries are never evicted; when full,
    /// new learnings are refused, the exhausted flag is raised, and
    /// unverifiable opens are denied instead of allowed.
    pub fn learn_topology_handle(
        &self,
        fsid: [u32; 2],
        handle_type: i32,
        handle_bytes: Vec<u8>,
        resource: ProtectedResource,
    ) {
        let mut index = self
            .topology_handles
            .write()
            .expect("topology handle index lock poisoned");
        if index.len() >= self.handle_index_capacity {
            self.metrics
                .handle_index_exhausted
                .store(true, Ordering::Relaxed);
            tracing::warn!(
                capacity = self.handle_index_capacity,
                "topology handle index full; learn refused; unverifiable opens will be denied"
            );
            return;
        }
        index
            .entry((fsid, handle_type, handle_bytes))
            .or_insert(resource);
    }

    /// True when any topology-learned handle exists (fast-path guard: the
    /// per-open handle computation only runs when this set is non-empty).
    pub fn topology_handles_nonempty(&self) -> bool {
        !self
            .topology_handles
            .read()
            .expect("topology handle index lock poisoned")
            .is_empty()
    }

    /// Look up a topology-learned object by the event fd's handle.
    pub fn match_topology_handle(
        &self,
        fsid: [u32; 2],
        handle: &platform_linux::object_handle::ObjectHandle,
    ) -> Option<ProtectedResource> {
        self.topology_handles
            .read()
            .expect("topology handle index lock poisoned")
            .get(&(fsid, handle.handle_type, handle.handle_bytes.clone()))
            .cloned()
    }

    /// The profile roots the LFH2 Step 3 topology group marks recursively for
    /// `FAN_MOVE` events (strict mode only; conservative stays REDUCED for the
    /// never-opened dynamic-object story).
    pub fn topology_roots(&self) -> Vec<std::path::PathBuf> {
        self.browsers.iter().map(|b| b.root.clone()).collect()
    }

    /// R1: attach the LFH2 Step 3 topology group so the permission hot path
    /// can synchronously drain it before an ambiguous outside-path open may be
    /// allowed. Called once at startup, before the learner thread is spawned.
    pub fn attach_topology_group(&self, group: std::sync::Arc<fanotify::FanotifyGroup>) {
        self.topology
            .lock()
            .expect("topology drain state lock poisoned")
            .group = Some(group);
    }

    /// R1: called by the permission hot path before an ambiguous outside-path
    /// open may be allowed. Under the SAME mutex the background learner uses,
    /// probe the topology queue and synchronously drain+process it when it
    /// holds events. The mutex is taken even for the empty-queue case: the
    /// learner reads→parses→publishes inside the critical section, so when we
    /// hold the lock the published state is current and the poll reflects ONLY
    /// events the learner has NOT already consumed — there is no
    /// "consumed but not yet published" window to race.
    fn sync_topology_if_pending(&self) {
        let mut state = self
            .topology
            .lock()
            .expect("topology drain state lock poisoned");
        let Some(group) = state.group.clone() else {
            return;
        };
        // On a poll error, drain anyway (fail-safe): a broken poll must not
        // become a silent skip of causally-prior events.
        let pending = group.pending().unwrap_or(true);
        if !pending {
            return;
        }
        let buf = &mut state.buf;
        let mut drained = 0usize;
        loop {
            match group.read(buf) {
                Ok(n) => match fanotify::parse_fid_events(&buf[..n]) {
                    Ok(events) => {
                        drained += events.len();
                        self.process_fid_events(events);
                    }
                    Err(error) => {
                        self.metrics
                            .topology_uncertain
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                        tracing::error!(%error, "topology drain parse failed closed");
                    }
                },
                Err(error) if error.raw_os_error() == Some(libc::EAGAIN) => break,
                Err(error) => {
                    self.metrics
                        .topology_uncertain
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    tracing::warn!(%error, "topology drain read failed");
                    break;
                }
            }
        }
        if drained > 0 {
            tracing::debug!(drained, "topology: synchronous drain processed events");
        }
    }

    /// R1: background drain used by the topology learner thread — same mutex
    /// and code path as the permission hot path's synchronous drain, so
    /// consumed events are always published before the lock is released.
    /// No-op when no topology group is attached; never blocks (O_NONBLOCK).
    pub(crate) fn drain_topology_events(&self) {
        let mut state = self
            .topology
            .lock()
            .expect("topology drain state lock poisoned");
        let group = state.group.clone();
        let Some(group) = group else {
            return;
        };
        let buf = &mut state.buf;
        loop {
            match group.read(buf) {
                Ok(n) => match fanotify::parse_fid_events(&buf[..n]) {
                    Ok(events) => self.process_fid_events(events),
                    Err(error) => {
                        self.metrics
                            .topology_uncertain
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                        tracing::error!(%error, "topology drain parse failed closed");
                    }
                },
                Err(error) if error.raw_os_error() == Some(libc::EAGAIN) => break,
                Err(error) => {
                    self.metrics
                        .topology_uncertain
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    tracing::warn!(%error, "topology drain read failed");
                    break;
                }
            }
        }
    }

    /// Process parsed `FAN_CLASS_NOTIF | FAN_REPORT_FID | FAN_REPORT_DFID_NAME`
    /// events: learn moved objects' handles.
    ///
    /// KERNEL 7.1 MEASURED REALITY (definitive C-probe): a move event's fid is
    /// the MARKED/PARENT DIRECTORY's handle — NEVER the moved file's — and
    /// back-to-back move-in+move-out coalesce into one event with mask
    /// `FAN_MOVE` (0xc0). The DFID_NAME record adds the moved object's NAME.
    /// The learner therefore resolves the moved object's identity via
    /// `parent/name`: the fid's handle is looked up in `marked_dir_handles`
    /// (each marked dir recorded its handle at mark time), the name is
    /// appended, and while the object REMAINS at that path its own handle is
    /// learned (O_PATH open + `from_fd`). If the object already left the
    /// protected path before the event was processed (the "immediately
    /// rename-out" attack), the resolution is ENOENT and the identity is
    /// unavailable — a documented kernel limitation (REDUCED), never a false
    /// positive. Shared by the background learner and the permission hot
    /// path's synchronous drain.
    fn process_fid_events(&self, events: Vec<fanotify::FidEvent>) {
        for event in events {
            if event.overflow {
                self.metrics
                    .topology_uncertain
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                tracing::warn!(
                    "topology group overflow; a move may have been missed (topology UNCERTAIN)"
                );
                continue;
            }
            if event.mask & fanotify::FAN_MOVE_EVENTS == 0 {
                continue;
            }
            if event.fids.is_empty() {
                continue;
            }
            // FAN_REPORT_TARGET_FID: the LAST plain-FID record is the moved
            // object's OWN handle (the earlier record(s) are the parent dir).
            // Learn it directly — no userspace resolution — so the zero-settle
            // fast attack (immediate rename-in -> rename-out -> open) is
            // enforceable even though the file left the protected path before
            // the event was processed.
            let target = event
                .fids
                .iter()
                .rev()
                .find(|f| f.name.is_none() && !f.handle_bytes.is_empty());
            if let Some(target) = target {
                // Attribute the learned object: prefer the protected path
                // implied by the parent record + name, else the fallback.
                let resource = event
                    .fids
                    .iter()
                    .find(|f| f.name.is_some())
                    .and_then(|f| {
                        let key = (f.fsid, f.handle_type, f.handle_bytes.clone());
                        let parent = self.marked_dir_path(&key)?;
                        let name = std::str::from_utf8(f.name.as_ref()?).ok()?;
                        Some(parent.join(name))
                    })
                    .and_then(|path| self.classify_path(&path))
                    .unwrap_or_else(|| self.fallback_dynamic_resource());
                self.learn_topology_handle(
                    target.fsid,
                    target.handle_type,
                    target.handle_bytes.clone(),
                    resource,
                );
                tracing::debug!(
                    handle = format_args!("{:02x?}", target.handle_bytes),
                    mask = format_args!("0x{:x}", event.mask),
                    "topology: learned moved object handle (target fid)"
                );
                continue;
            }
            // No target fid (older kernel / flag rejected): fall back to the
            // DFID_NAME parent/name resolution while the file remains there.
            let Some(fid) = event.fids.first() else {
                continue;
            };
            if fid.handle_bytes.is_empty() {
                continue;
            }
            let Some(name) = fid.name.as_ref() else {
                // Plain FID move events carry only the parent dir's handle;
                // without the name the moved object cannot be resolved.
                continue;
            };
            let name = match std::str::from_utf8(name) {
                Ok(name) => name.to_owned(),
                Err(_) => continue,
            };
            // Resolve the parent dir's handle to its path, then `parent/name`.
            let parent =
                self.marked_dir_path(&(fid.fsid, fid.handle_type, fid.handle_bytes.clone()));
            let Some(parent) = parent else {
                tracing::debug!(
                    mask = format_args!("0x{:x}", event.mask),
                    "topology: move event parent handle not in marked-dir map"
                );
                continue;
            };
            let moved_path = parent.join(&name);
            // O_PATH open is not gated by the permission marks; resolve the
            // moved object's OWN handle while it remains at `parent/name`.
            let c_path = match std::ffi::CString::new(moved_path.to_string_lossy().as_bytes()) {
                Ok(c) => c,
                Err(_) => continue,
            };
            // SAFETY: O_PATH open of our own marked tree; not gated; c_path
            // outlives the call.
            let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
            if fd < 0 {
                // ENOENT: the object already left the protected path before
                // this event was processed. The kernel provides no identity
                // for it in the event (fid = parent dir only); documented
                // kernel limitation, REDUCED for this object.
                tracing::debug!(
                    path = %moved_path.display(),
                    "topology: moved object no longer at protected path (immediate rename-out); \
                     identity unavailable — kernel provides no file fid (REDUCED)"
                );
                continue;
            }
            let handle = platform_linux::object_handle::ObjectHandle::from_fd(fd);
            unsafe { libc::close(fd) };
            let Ok(handle) = handle else {
                self.metrics
                    .classifier_failures
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    path = %moved_path.display(),
                    "topology: resolved moved object handle failed (REDUCED)"
                );
                continue;
            };
            // The fid's opaque handle IS the object identity: learn it
            // directly into the handle-only index.
            let resource = self
                .classify_path(&moved_path)
                .unwrap_or_else(|| self.fallback_dynamic_resource());
            if let Some(fsid) = fsid_of_fd(fd) {
                self.learn_topology_handle(
                    fsid,
                    handle.handle_type,
                    handle.handle_bytes.clone(),
                    resource,
                );
            }
            tracing::debug!(
                path = %moved_path.display(),
                handle = format_args!("{:02x?}", handle.handle_bytes),
                mask = format_args!("0x{:x}", event.mask),
                "topology: learned moved object handle"
            );
        }
    }

    /// R1: record a marked tree directory's handle so move events' parent
    /// R1: resolve a marked tree directory's handle back to its path.
    fn marked_dir_path(&self, key: &TopologyKey) -> Option<std::path::PathBuf> {
        self.marked_dir_handles
            .read()
            .expect("marked dir handle map lock poisoned")
            .get(key)
            .cloned()
    }

    /// handles can be resolved back to paths. Called by the topology learner
    /// when it marks a directory (startup walk + periodic refresh).
    pub(crate) fn record_marked_dir(&self, path: &Path) {
        let c_path = match std::ffi::CString::new(path.to_string_lossy().as_bytes()) {
            Ok(c) => c,
            Err(_) => return,
        };
        // SAFETY: O_PATH open of our own tree; not gated by permission marks.
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if fd < 0 {
            return;
        }
        let handle = platform_linux::object_handle::ObjectHandle::from_fd(fd);
        let fsid = fsid_of_fd(fd);
        unsafe { libc::close(fd) };
        let (Ok(handle), Some(fsid)) = (handle, fsid) else {
            return;
        };
        self.marked_dir_handles
            .write()
            .expect("marked dir handle map lock poisoned")
            .insert(
                (fsid, handle.handle_type, handle.handle_bytes.clone()),
                path.to_path_buf(),
            );
    }

    /// R2: the final "unrelated" verdict for a NON-path-classified open.
    ///
    /// When the learned-handle indexes are exhausted (a protected dynamic
    /// object's learning was REFUSED), an unverifiable open must NOT silently
    /// fall through to Unrelated — the object may be exactly such an unlearned
    /// protected object renamed out. Fail closed: deny (classify as Error) and
    /// let the caller's health machinery count it, rather than allowing an
    /// identity Guard cannot verify.
    fn unrelated_or_exhausted(&self) -> StrictClassification {
        if self.metrics.handle_index_exhausted.load(Ordering::Relaxed) {
            StrictClassification::Error(
                "learned-handle index exhausted; unverifiable open denied (fail-closed)".into(),
            )
        } else {
            StrictClassification::Unrelated
        }
    }

    /// LFH2 Step 3 (pre-existing objects): snapshot every PRE-EXISTING
    /// dynamic file under each browser root into the learned-handle index.
    ///
    /// A never-opened dynamic object renamed OUT of a protected tree is only
    /// recognized if its `(dev, ino) -> handle` is already learned. Populating
    /// the index at startup (via O_PATH opens + `name_to_handle_at`, neither of
    /// which is gated by the permission marks) gives those objects their
    /// identity WITHOUT needing any fanotify topology event or
    /// `open_by_handle_at`. This is what makes the Step 3 acceptance
    /// ("pre-existing / never-seen object renamed outside before any
    /// protected-path open → unknown reader → PREVENTED") deterministic.
    ///
    /// Only files under dynamic trees are snapshot (the stable concrete files
    /// are already pinned by inode). Bounded, R2 fail-closed capacity shared
    /// with `learn_handle` (no eviction; full ⇒ refuse + deny unverifiable).
    /// Returns the number of objects learned.
    pub fn snapshot_dynamic_handles(&self) -> usize {
        let mut learned = 0usize;
        for namespace in &self.browsers {
            let mut stack = vec![namespace.root.clone()];
            while let Some(dir) = stack.pop() {
                let entries = match std::fs::read_dir(&dir) {
                    Ok(entries) => entries,
                    Err(_) => continue,
                };
                for entry in entries.flatten() {
                    let path = entry.path();
                    let Ok(ft) = entry.file_type() else {
                        continue;
                    };
                    if ft.is_dir() {
                        stack.push(path);
                        continue;
                    }
                    if !ft.is_file() || self.identity_index_is_stable(&path) {
                        continue;
                    }
                    let c_path = match std::ffi::CString::new(path.to_string_lossy().as_bytes()) {
                        Ok(c) => c,
                        Err(_) => continue,
                    };
                    // SAFETY: O_PATH open of our own enrolled tree; not gated
                    // by the permission marks (O_PATH opens never fire
                    // FAN_OPEN_PERM). c_path outlives the call.
                    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
                    if fd < 0 {
                        continue;
                    }
                    let handle = platform_linux::object_handle::ObjectHandle::from_fd(fd);
                    let mut st: libc::stat = unsafe { std::mem::zeroed() };
                    let stat_ok = unsafe { libc::fstat(fd, &mut st) } == 0;
                    unsafe { libc::close(fd) };
                    if let (Ok(handle), true) = (handle, stat_ok) {
                        let identity = (st.st_dev, st.st_ino);
                        let resource = self
                            .classify_path(&path)
                            .unwrap_or_else(|| self.fallback_dynamic_resource());
                        if self.learn_handle_value(identity, handle, resource) {
                            learned += 1;
                        }
                    }
                }
            }
        }
        learned
    }

    /// Insert a `(dev, ino) -> handle` candidate with the shared bounded,
    /// fail-closed capacity rules. Returns true when the candidate was added.
    fn learn_handle_value(
        &self,
        identity: (u64, u64),
        handle: platform_linux::object_handle::ObjectHandle,
        resource: ProtectedResource,
    ) -> bool {
        let mut index = self
            .handle_index
            .write()
            .expect("handle index lock poisoned");
        if index.len() >= self.handle_index_capacity {
            self.metrics
                .handle_index_exhausted
                .store(true, Ordering::Relaxed);
            tracing::warn!(
                ?identity,
                capacity = self.handle_index_capacity,
                "dynamic object handle index full; learn refused; unverifiable opens will be denied"
            );
            return false;
        }
        let entry = index.entry(identity).or_default();
        if !entry.iter().any(|candidate| candidate.handle == handle) {
            entry.push(HandleCandidate { handle, resource });
            true
        } else {
            false
        }
    }

    /// A conservative fallback resource for topology-learned dynamic objects.
    /// The topology event does not identify WHICH protected tree fired, so the
    /// learned candidate is attributed to the first browser with a dynamic
    /// (web-storage) kind. For single-browser configurations (the acceptance
    /// and typical deployments) this is exact; multi-browser misattribution is
    /// conservative (an unknown reader is denied regardless of kind, and a
    /// cross-browser reader would need a lease that no topology event grants).
    pub fn fallback_dynamic_resource(&self) -> ProtectedResource {
        let browser = self
            .browsers
            .first()
            .map(|b| (b.browser.clone(), b.owner_uid))
            .unwrap_or_else(|| (BrowserId("(none)".into()), 0));
        ProtectedResource {
            id: ProtectedResourceId("topology-learned-dynamic".into()),
            kind: ProtectedResourceKind::WebStorage,
            owner_uid: browser.1,
            browser: Some(browser.0),
            profile: Some(ProfileId("(dynamic)".into())),
            path: std::path::PathBuf::from("<topology-learned>"),
        }
    }

    /// LFH2: compare the event fd's handle against learned candidates for this
    /// `(dev, ino)`. Returns `Some(Protected)` on an exact handle match, or
    /// `Some(Unrelated)` when the inode was reused (handles differ), and `None`
    /// when this inode was never learned (fast path continues).
    ///
    /// LFH5 review (fail-closed verification): if `(dev, ino)` hits learned
    /// protected candidates but the event fd's handle CANNOT be computed, we
    /// must NOT silently fall through to Unrelated — the object may be the
    /// learned protected one. That case is classified as `Error` (fail closed:
    /// classifier failure counter + health degradation + DENY upstream).
    ///
    /// A stale candidate whose handle no longer matches is dropped so a
    /// recycled inode cannot false-positive on the stale mapping. One inode
    /// holds exactly one object at a time, so any mismatch invalidates every
    /// learned candidate for that inode.
    fn match_learned_handles(
        &self,
        fd: RawFd,
        identity: (u64, u64),
    ) -> Option<StrictClassification> {
        let candidates = {
            let index = self
                .handle_index
                .read()
                .expect("handle index lock poisoned");
            index.get(&identity).cloned()
        }?;
        let event_handle = match platform_linux::object_handle::ObjectHandle::from_fd(fd) {
            Ok(handle) => handle,
            Err(error) => {
                self.metrics
                    .classifier_failures
                    .fetch_add(1, Ordering::Relaxed);
                tracing::error!(
                    %error,
                    ?identity,
                    "learned protected candidate handle verification failed; denying (fail closed)"
                );
                return Some(StrictClassification::Error(format!(
                    "learned protected handle verification failed: {error}"
                )));
            }
        };
        #[cfg(test)]
        if INJECT_HANDLE_VERIFY_FAILURE.with(|flag| flag.replace(false)) {
            self.metrics
                .classifier_failures
                .fetch_add(1, Ordering::Relaxed);
            return Some(StrictClassification::Error(
                "injected handle verification failure".into(),
            ));
        }
        if let Some(candidate) = candidates
            .into_iter()
            .find(|candidate| candidate.handle == event_handle)
        {
            return Some(StrictClassification::Protected(candidate.resource));
        }
        // Inode reused: the current object is not any learned protected
        // object. Drop the whole key so a future recycled inode cannot
        // false-positive on it.
        self.handle_index
            .write()
            .expect("handle index lock poisoned")
            .remove(&identity);
        Some(StrictClassification::Unrelated)
    }

    /// Concrete critical files are safe to pin by inode.  Descendants of
    /// browser storage/session trees are intentionally not: their journal and
    /// WAL inodes are short-lived and inode numbers are reusable.
    fn identity_index_is_stable(&self, path: &Path) -> bool {
        if self.ssh.iter().any(|key| key.path == path) {
            return true;
        }
        self.browsers.iter().any(|namespace| {
            let Ok(relative) = path.strip_prefix(&namespace.root) else {
                return false;
            };
            match namespace.family {
                BrowserFamily::Chromium => {
                    let components: Vec<_> = relative.components().take(2).collect();
                    !components.iter().any(|component| {
                        matches!(
                            component.as_os_str().to_str(),
                            Some("Sessions")
                                | Some("Session Storage")
                                | Some("Local Storage")
                                | Some("IndexedDB")
                        )
                    })
                }
                BrowserFamily::Firefox | BrowserFamily::Zen => {
                    let components: Vec<_> = relative.components().take(2).collect();
                    !components.iter().any(|component| {
                        matches!(
                            component.as_os_str().to_str(),
                            Some("storage") | Some("sessionstore-backups")
                        )
                    })
                }
                // Safari has no Linux discovery/classifier. A manually
                // supplied Safari family must not acquire Chromium/Firefox
                // semantics on this backend.
                BrowserFamily::Safari => true,
            }
        })
    }

    /// An event fd opened through an external hardlink exposes that alias, not
    /// every name of the inode. For the exceptional `st_nlink > 1` case,
    /// synchronously search only enrolled namespaces using directory reads and
    /// metadata (neither opens regular files). This closes the rename+hardlink
    /// first-open gap without penalizing the overwhelmingly common nlink=1
    /// filesystem fast path.
    fn find_protected_alias(
        &self,
        identity: (u64, u64),
    ) -> Result<Option<ProtectedResource>, String> {
        for key in &self.ssh {
            if path_identity(&key.path).ok() == Some(identity) {
                return Ok(self.classify_path(&key.path));
            }
        }
        for browser in &self.browsers {
            for path in find_identity_in_tree(&browser.root, identity)? {
                if let Some(resource) = self.classify_path(&path) {
                    return Ok(Some(resource));
                }
            }
        }
        Ok(None)
    }

    fn classify_path(&self, path: &Path) -> Option<ProtectedResource> {
        for key in &self.ssh {
            if path == key.path {
                return Some(resource(
                    path,
                    ProtectedResourceKind::SshPrivateKey,
                    key.owner_uid,
                    None,
                    None,
                ));
            }
        }
        for namespace in &self.browsers {
            let Ok(relative) = path.strip_prefix(&namespace.root) else {
                continue;
            };
            let classified = match namespace.family {
                BrowserFamily::Chromium => classify_chromium(relative),
                BrowserFamily::Firefox | BrowserFamily::Zen => classify_firefox(relative),
                BrowserFamily::Safari => None,
            };
            if let Some((kind, profile)) = classified {
                return Some(resource(
                    path,
                    kind,
                    namespace.owner_uid,
                    Some(namespace.browser.clone()),
                    Some(ProfileId(profile)),
                ));
            }
        }
        None
    }
}

/// P1-d (review): the filesystem identity (`fstatfs` `f_fsid`) of an open
/// descriptor. fanotify move events carry this same `__kernel_fsid_t` in the
/// fid, so topology-learned handles are keyed by `(fsid, handle_type,
/// handle_bytes)` — a filesystem handle is fs-scoped opaque identity, NOT
/// globally unique, and keying without the fsid lets identical payloads on
/// different filesystems collide (wrong resource/browser attribution).
fn fsid_of_fd(fd: RawFd) -> Option<[u32; 2]> {
    let mut st = unsafe { std::mem::zeroed::<libc::statfs>() };
    // SAFETY: st is a valid statfs buffer for the given fd.
    let rc = unsafe { libc::fstatfs(fd, &mut st) };
    if rc != 0 {
        return None;
    }
    // __fsid_t is two ints (fields private in libc); transmute the whole
    // value — bit-identical to the fanotify __kernel_fsid_t.
    Some(unsafe { std::mem::transmute::<libc::fsid_t, [u32; 2]>(st.f_fsid) })
}

fn path_identity(path: &Path) -> std::io::Result<(u64, u64)> {
    let metadata = std::fs::symlink_metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}

fn find_identity_in_tree(root: &Path, identity: (u64, u64)) -> Result<Vec<PathBuf>, String> {
    let mut pending = vec![root.to_path_buf()];
    let mut matches = Vec::new();
    while let Some(directory) = pending.pop() {
        let entries = std::fs::read_dir(&directory).map_err(|error| {
            format!("scan protected namespace {}: {error}", directory.display())
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                format!("read protected namespace {}: {error}", directory.display())
            })?;
            let path = entry.path();
            let metadata = match std::fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(format!(
                        "stat protected namespace {}: {error}",
                        path.display()
                    ))
                }
            };
            if (metadata.dev(), metadata.ino()) == identity {
                matches.push(path.clone());
            }
            if metadata.file_type().is_dir() {
                pending.push(path);
            }
        }
    }
    Ok(matches)
}

fn classify_chromium(relative: &Path) -> Option<(ProtectedResourceKind, String)> {
    if relative == Path::new("Local State") {
        return Some((
            ProtectedResourceKind::BrowserKeyMaterial,
            guard_browser::chromium::LOCAL_STATE_PROFILE.to_owned(),
        ));
    }
    let mut components = relative.components();
    let profile = components
        .next()?
        .as_os_str()
        .to_string_lossy()
        .into_owned();
    let tail: PathBuf = components.collect();
    let name = tail.file_name()?.to_str()?;

    if (tail.parent() == Some(Path::new("Network")) || tail.parent() == Some(Path::new("")))
        && name.starts_with("Cookies")
    {
        return Some((ProtectedResourceKind::CookieStore, profile));
    }
    if tail.parent() == Some(Path::new(""))
        && (name.starts_with("Login Data") || name.starts_with("Web Data"))
    {
        return Some((ProtectedResourceKind::SavedCredentials, profile));
    }
    if tail.starts_with("Sessions") || tail.starts_with("Session Storage") {
        return Some((ProtectedResourceKind::SessionStore, profile));
    }
    if tail.starts_with("Local Storage") || tail.starts_with("IndexedDB") {
        return Some((ProtectedResourceKind::WebStorage, profile));
    }
    None
}

fn classify_firefox(relative: &Path) -> Option<(ProtectedResourceKind, String)> {
    if let Some(kind) = classify_firefox_profile_relative(relative) {
        let root_profile = relative.components().count() == 1
            || relative.starts_with("storage")
            || relative.starts_with("sessionstore-backups");
        let profile = if root_profile {
            "(profile-root)".to_owned()
        } else {
            relative
                .components()
                .next()?
                .as_os_str()
                .to_string_lossy()
                .into_owned()
        };
        return Some((kind, profile));
    }

    let mut components = relative.components();
    let profile = components
        .next()?
        .as_os_str()
        .to_string_lossy()
        .into_owned();
    let tail: PathBuf = components.collect();
    classify_firefox_profile_relative(&tail).map(|kind| (kind, profile))
}

fn classify_firefox_profile_relative(relative: &Path) -> Option<ProtectedResourceKind> {
    let name = relative.file_name()?.to_str()?;
    if name.starts_with("cookies.sqlite") {
        return Some(ProtectedResourceKind::CookieStore);
    }
    match name {
        "logins.json" => Some(ProtectedResourceKind::SavedCredentials),
        "key4.db" => Some(ProtectedResourceKind::BrowserKeyMaterial),
        "webappsstore.sqlite"
        | "webappsstore.sqlite-wal"
        | "webappsstore.sqlite-shm"
        | "webappsstore.sqlite-journal" => Some(ProtectedResourceKind::WebStorage),
        _ if relative.starts_with("sessionstore-backups") => {
            Some(ProtectedResourceKind::SessionStore)
        }
        _ if relative.starts_with("storage") => Some(ProtectedResourceKind::WebStorage),
        _ => None,
    }
}

fn resource(
    path: &Path,
    kind: ProtectedResourceKind,
    owner_uid: u32,
    browser: Option<BrowserId>,
    profile: Option<ProfileId>,
) -> ProtectedResource {
    ProtectedResource {
        id: ProtectedResourceId(path.to_string_lossy().into_owned()),
        kind,
        path: path.to_path_buf(),
        owner_uid,
        browser,
        profile,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    fn chromium_config(root: &Path) -> EnforcementConfig {
        EnforcementConfig {
            config_version: platform_linux::config::CONFIG_VERSION,
            enforcement_mode: EnforcementMode::StrictFilesystem,
            browsers: vec![crate::enforce::BrowserEnrollmentConfig {
                id: "synthetic-chromium".to_owned(),
                family: BrowserFamily::Chromium,
                profile_root: root.to_path_buf(),
                owner_uid: Some(1000),
                exe_paths: Vec::new(),
            }],
            enrolled_exes: Vec::new(),
            ssh_keys: Vec::new(),
        }
    }

    #[test]
    fn chromium_namespace_patterns_cover_first_open_targets() {
        for path in [
            "Default/Network/Cookies",
            "Default/Network/Cookies-wal",
            "Default/Cookies-shm",
            "Default/Login Data-journal",
            "Default/Web Data",
            "Default/Sessions/new/Session_1",
            "Profile 2/Session Storage/000001.log",
            "Profile 2/Local Storage/leveldb/000001.ldb",
            "Profile 2/IndexedDB/site/000001.log",
        ] {
            assert!(classify_chromium(Path::new(path)).is_some(), "{path}");
        }
        assert_eq!(
            classify_chromium(Path::new("Local State")).unwrap().0,
            ProtectedResourceKind::BrowserKeyMaterial
        );
        assert!(classify_chromium(Path::new("Default/History")).is_none());
        assert!(classify_chromium(Path::new("Default/cache/Login Data.old")).is_none());
    }

    #[test]
    fn firefox_namespace_patterns_cover_root_and_nested_profiles() {
        for path in [
            "cookies.sqlite",
            "cookies.sqlite-wal",
            "logins.json",
            "key4.db",
            "webappsstore.sqlite",
            "webappsstore.sqlite-wal",
            "webappsstore.sqlite-journal",
            "storage/default/site/data.sqlite",
            "sessionstore-backups/recovery.jsonlz4",
            "profile-a/cookies.sqlite-shm",
            "profile-a/logins.json",
            "profile-a/key4.db",
            "profile-a/webappsstore.sqlite-shm",
            "profile-a/webappsstore.sqlite-journal",
            "profile-a/storage/default/site/data.sqlite",
            "profile-a/sessionstore-backups/previous.jsonlz4",
        ] {
            assert!(classify_firefox(Path::new(path)).is_some(), "{path}");
        }
        assert!(classify_firefox(Path::new("profile-a/places.sqlite")).is_none());
    }

    #[test]
    fn external_hardlink_of_replacement_is_found_before_inode_index_refresh() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("chromium");
        let target = root.join("Default/Network/Cookies");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        let replacement = temp.path().join("replacement");
        let alias = temp.path().join("external-alias");
        std::fs::write(&replacement, b"synthetic").unwrap();
        std::fs::hard_link(&replacement, &alias).unwrap();
        std::fs::rename(&replacement, &target).unwrap();

        let index = std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));
        let metrics = std::sync::Arc::new(BackendMetrics::new(EnforcementMode::StrictFilesystem));
        let classifier = StrictClassifier::new(
            &chromium_config(&root),
            std::sync::Arc::clone(&index),
            std::sync::Arc::clone(&metrics),
        )
        .unwrap();
        let file = std::fs::File::open(&alias).unwrap();
        assert!(matches!(
            classifier.classify_fd(file.as_raw_fd()),
            StrictClassification::Protected(_)
        ));
        assert_eq!(metrics.strict_alias_scans.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.strict_alias_matches.load(Ordering::Relaxed), 1);
        assert_eq!(index.read().unwrap().len(), 1);
    }

    #[test]
    fn structural_hit_promotes_inode_before_rename_away() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("chromium");
        let target = root.join("Default/Network/Cookies");
        let outside = temp.path().join("renamed-outside");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, b"synthetic").unwrap();

        let index = std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));
        let metrics = std::sync::Arc::new(BackendMetrics::new(EnforcementMode::StrictFilesystem));
        let classifier = StrictClassifier::new(
            &chromium_config(&root),
            std::sync::Arc::clone(&index),
            metrics,
        )
        .unwrap();

        let first = std::fs::File::open(&target).unwrap();
        let identity = fanotify::fd_identity(first.as_raw_fd()).unwrap();
        assert!(matches!(
            classifier.classify_fd(first.as_raw_fd()),
            StrictClassification::Protected(_)
        ));
        drop(first);
        assert!(index.read().unwrap().contains_key(&identity));

        std::fs::rename(&target, &outside).unwrap();
        let renamed = std::fs::File::open(&outside).unwrap();
        assert!(matches!(
            classifier.classify_fd(renamed.as_raw_fd()),
            StrictClassification::Protected(_)
        ));
    }

    #[test]
    fn stale_dynamic_tree_inode_does_not_block_unrelated_file() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("chromium");
        std::fs::create_dir_all(root.join("Default/Local Storage/leveldb")).unwrap();
        let stale_path = root.join("Default/Local Storage/leveldb/000001.log");
        std::fs::write(&stale_path, b"synthetic").unwrap();
        let unrelated = temp.path().join("clipvault.db");
        std::fs::write(&unrelated, b"clipboard database").unwrap();

        let index = std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));
        let metrics = std::sync::Arc::new(BackendMetrics::new(EnforcementMode::StrictFilesystem));
        let classifier = StrictClassifier::new(
            &chromium_config(&root),
            std::sync::Arc::clone(&index),
            metrics,
        )
        .unwrap();
        let unrelated_identity = path_identity(&unrelated).unwrap();
        index.write().unwrap().insert(
            unrelated_identity,
            resource(
                &stale_path,
                ProtectedResourceKind::WebStorage,
                1000,
                Some(BrowserId("synthetic-chromium".into())),
                Some(ProfileId("Default".into())),
            ),
        );

        let file = std::fs::File::open(&unrelated).unwrap();
        assert!(matches!(
            classifier.classify_fd(file.as_raw_fd()),
            StrictClassification::Unrelated
        ));
        assert!(!index.read().unwrap().contains_key(&unrelated_identity));
    }

    #[test]
    fn strict_configuration_requires_an_existing_protected_filesystem() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing");
        let metrics = std::sync::Arc::new(BackendMetrics::new(EnforcementMode::StrictFilesystem));
        let index = std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));
        let error = StrictClassifier::new(&chromium_config(&missing), index, metrics)
            .err()
            .expect("missing root must fail strict startup");
        assert!(error.to_string().contains("requires existing browser root"));
    }

    // --- LFH2: dynamic object handle identity ---

    /// name_to_handle_at is unsupported on tmpfs (e.g. /tmp), so these tests
    /// create their sandbox under the workspace target dir (a real filesystem
    /// on this host) where object handles are available.
    fn fs_tempdir() -> tempfile::TempDir {
        let repo = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
        let base = std::path::Path::new(&repo)
            .join("../../target")
            .join(format!("lfh2-tests-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        tempfile::Builder::new()
            .prefix("handle-")
            .tempdir_in(&base)
            .expect("fs tempdir")
    }

    fn new_classifier(root: &Path) -> (StrictClassifier, InodeIndex) {
        let index = std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));
        let metrics = std::sync::Arc::new(BackendMetrics::new(EnforcementMode::StrictFilesystem));
        let classifier = StrictClassifier::new(
            &chromium_config(root),
            std::sync::Arc::clone(&index),
            metrics,
        )
        .unwrap();
        (classifier, index)
    }

    #[test]
    fn dynamic_handle_learned_then_rename_away_still_protected() {
        // LFH2 Step 1/2: a dynamic object (Local Storage descendant) opened
        // under its protected path is learned by handle; after rename-out the
        // same object (same handle) must still be Protected — closing the
        // LFH0 "rename-away without open" gap for objects that WERE opened.
        let temp = fs_tempdir();
        let root = temp.path().join("chromium");
        let dynamic = root.join("Default/Local Storage/leveldb/000001.log");
        std::fs::create_dir_all(dynamic.parent().unwrap()).unwrap();
        std::fs::write(&dynamic, b"synthetic session").unwrap();
        let outside = temp.path().join("exfiltrated.log");

        let (classifier, _index) = new_classifier(&root);

        let first = std::fs::File::open(&dynamic).unwrap();
        assert!(matches!(
            classifier.classify_fd(first.as_raw_fd()),
            StrictClassification::Protected(_)
        ));
        drop(first);

        std::fs::rename(&dynamic, &outside).unwrap();
        let renamed = std::fs::File::open(&outside).unwrap();
        assert!(
            matches!(
                classifier.classify_fd(renamed.as_raw_fd()),
                StrictClassification::Protected(_)
            ),
            "rename-away dynamic object with a learned handle must stay protected"
        );
    }

    #[test]
    fn inode_reuse_after_dynamic_delete_is_not_false_positive() {
        // LFH2: after the learned dynamic object is deleted, a NEW unrelated
        // file that reuses the same inode number must NOT be classified
        // Protected (its handle differs). This is the inode-reuse guard.
        let temp = fs_tempdir();
        let root = temp.path().join("chromium");
        let dynamic = root.join("Default/Local Storage/leveldb/000001.log");
        std::fs::create_dir_all(dynamic.parent().unwrap()).unwrap();
        std::fs::write(&dynamic, b"synthetic session").unwrap();

        let (classifier, _index) = new_classifier(&root);
        let first = std::fs::File::open(&dynamic).unwrap();
        assert!(matches!(
            classifier.classify_fd(first.as_raw_fd()),
            StrictClassification::Protected(_)
        ));
        let reused_ino = fanotify::fd_identity(first.as_raw_fd()).unwrap().1;
        drop(first);
        std::fs::remove_file(&dynamic).unwrap();

        // Simulate inode reuse by an unrelated file. On a real filesystem the
        // kernel rarely reuses the exact inode instantly, so we instead open
        // an unrelated file and force the classifier to treat its inode as the
        // stale key by injecting the learned key directly.
        let unrelated = temp.path().join("unrelated.db");
        std::fs::write(&unrelated, b"clipboard database").unwrap();
        let unrelated_file = std::fs::File::open(&unrelated).unwrap();
        let unrelated_identity = fanotify::fd_identity(unrelated_file.as_raw_fd()).unwrap();
        classifier.handle_index.write().unwrap().insert(
            unrelated_identity,
            vec![HandleCandidate {
                handle: platform_linux::object_handle::ObjectHandle {
                    mount_id: 1,
                    handle_type: 1,
                    handle_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
                },
                resource: resource(
                    &dynamic,
                    ProtectedResourceKind::WebStorage,
                    1000,
                    Some(BrowserId("synthetic-chromium".into())),
                    Some(ProfileId("Default".into())),
                ),
            }],
        );
        let _ = reused_ino;

        // The unrelated file's real handle differs from the injected stale
        // handle => Unrelated, and the stale mapping is dropped.
        assert!(matches!(
            classifier.classify_fd(unrelated_file.as_raw_fd()),
            StrictClassification::Unrelated
        ));
        assert!(!classifier
            .handle_index
            .read()
            .unwrap()
            .contains_key(&unrelated_identity));
    }

    #[test]
    fn object_handle_round_trip_via_platform_module() {
        let file = std::fs::File::open("/proc/self/exe").expect("open self exe");
        let handle = platform_linux::object_handle::ObjectHandle::from_fd(file.as_raw_fd());
        if let Ok(handle) = handle {
            assert_eq!(
                platform_linux::object_handle::ObjectHandle::decode(&handle.encode()),
                Some(handle)
            );
        }
    }

    #[test]
    fn topology_learned_never_opened_object_is_protected_after_rename_out() {
        // LFH2 Step 3: an object that was NEVER classified/opened under its
        // protected path is learned via the SEPARATE topology group
        // (`learn_topology_handle`, driven by FAN_MOVE+FID events: the fid's
        // handle IS the identity — no inode resolution). After the object is
        // renamed outside the tree, an open of the same object must classify
        // Protected (unknown reader => denied) — the Step 3 acceptance.
        let temp = fs_tempdir();
        let root = temp.path().join("chromium");
        let dynamic = root.join("Default/Local Storage/leveldb/000001.log");
        std::fs::create_dir_all(dynamic.parent().unwrap()).unwrap();
        std::fs::write(&dynamic, b"synthetic session").unwrap();

        let (classifier, _) = new_classifier(&root);
        // Learn the object's handle as the topology group would (the strict
        // classifier has never classified this object in-tree).
        let probe = std::fs::File::open(&dynamic).unwrap();
        let handle =
            platform_linux::object_handle::ObjectHandle::from_fd(probe.as_raw_fd()).unwrap();
        let fsid = fsid_of_fd(probe.as_raw_fd()).expect("fsid");
        drop(probe);
        let resource = classifier.fallback_dynamic_resource();
        classifier.learn_topology_handle(
            fsid,
            handle.handle_type,
            handle.handle_bytes.clone(),
            resource,
        );

        // Rename outside before any protected-path open (the Step 3 case).
        let moved = temp.path().join("exfil-000001.log");
        std::fs::rename(&dynamic, &moved).unwrap();
        let moved_file = std::fs::File::open(&moved).unwrap();
        assert!(
            matches!(
                classifier.classify_fd(moved_file.as_raw_fd()),
                StrictClassification::Protected(_)
            ),
            "topology-learned never-opened object must stay Protected after rename-out"
        );
    }

    #[test]
    fn handle_verify_failure_on_learned_candidate_fails_closed() {
        // LFH5 review (finding 4): (dev,ino) hits learned protected
        // candidates but the event fd's handle verification fails. This must
        // NOT silently fall through to Unrelated: classification is Error
        // (fail closed), the classifier_failures counter increments (health
        // degrades), and the learned candidate is retained for the next
        // healthy check.
        let temp = fs_tempdir();
        let root = temp.path().join("chromium");
        let dynamic = root.join("Default/Local Storage/leveldb/000001.log");
        std::fs::create_dir_all(dynamic.parent().unwrap()).unwrap();
        std::fs::write(&dynamic, b"synthetic session").unwrap();

        let (classifier, _) = new_classifier(&root);
        let file = std::fs::File::open(&dynamic).unwrap();
        assert!(matches!(
            classifier.classify_fd(file.as_raw_fd()),
            StrictClassification::Protected(_)
        ));
        let identity = fanotify::fd_identity(file.as_raw_fd()).unwrap();
        drop(file);

        // Rename the object outside the protected tree so classification must
        // fall back to the learned-handle path.
        let moved = temp.path().join("exfil-000001.log");
        std::fs::rename(&dynamic, &moved).unwrap();
        let moved_file = std::fs::File::open(&moved).unwrap();

        // Healthy verification: exact handle match => Protected.
        assert!(matches!(
            classifier.classify_fd(moved_file.as_raw_fd()),
            StrictClassification::Protected(_)
        ));

        // Injected verification failure: fail closed, never Unrelated.
        INJECT_HANDLE_VERIFY_FAILURE.with(|flag| flag.set(true));
        let failures_before = classifier
            .metrics
            .classifier_failures
            .load(Ordering::Relaxed);
        assert!(matches!(
            classifier.classify_fd(moved_file.as_raw_fd()),
            StrictClassification::Error(_)
        ));
        assert_eq!(
            classifier
                .metrics
                .classifier_failures
                .load(Ordering::Relaxed),
            failures_before + 1
        );
        // The learned candidate must survive the failure (no silent drop).
        assert!(classifier
            .handle_index
            .read()
            .unwrap()
            .contains_key(&identity));

        // Next healthy verification still matches (the failure was isolated).
        assert!(matches!(
            classifier.classify_fd(moved_file.as_raw_fd()),
            StrictClassification::Protected(_)
        ));
    }

    #[test]
    fn handle_index_capacity_pressure_never_evicts_learned_target() {
        // LFH5 review (finding 5): the dynamic-object handle index is bounded;
        // when it reaches capacity, EXISTING learned protected identities are
        // NEVER evicted (keys().next() removal would silently forget a
        // protected identity). New candidates are refused and the exhausted
        // health flag is raised. The renamed-out target must stay readable-
        // denied after >capacity pressure.
        let temp = fs_tempdir();
        let root = temp.path().join("chromium");
        let leveldb = root.join("Default/Local Storage/leveldb");
        std::fs::create_dir_all(&leveldb).unwrap();
        let dynamic = leveldb.join("000001.log");
        std::fs::write(&dynamic, b"synthetic session").unwrap();

        let (classifier, _) = new_classifier(&root);
        let capacity = classifier.handle_index_capacity;
        assert!(capacity > 0);

        // Learn the target under its protected path.
        let target = std::fs::File::open(&dynamic).unwrap();
        assert!(matches!(
            classifier.classify_fd(target.as_raw_fd()),
            StrictClassification::Protected(_)
        ));
        let target_identity = fanotify::fd_identity(target.as_raw_fd()).unwrap();
        let target_handle =
            platform_linux::object_handle::ObjectHandle::from_fd(target.as_raw_fd()).unwrap();
        drop(target);

        // Rename the target outside the protected tree (the exfiltration the
        // learned-handle guarantee must keep denying).
        let moved = temp.path().join("exfil-000001.log");
        std::fs::rename(&dynamic, &moved).unwrap();

        // Generate >capacity distinct dynamic protected candidates.
        for i in 0..(capacity + 8) {
            let p = leveldb.join(format!("{i:06}.log"));
            std::fs::write(&p, b"synthetic pressure").unwrap();
            let f = std::fs::File::open(&p).unwrap();
            let _ = classifier.classify_fd(f.as_raw_fd());
        }

        // Fail closed: index stays bounded, exhausted flag raised, and the
        // learned target is never evicted.
        assert!(classifier
            .metrics
            .handle_index_exhausted
            .load(Ordering::Relaxed));
        {
            let index = classifier.handle_index.read().unwrap();
            assert_eq!(index.len(), capacity, "index must stay bounded");
            let candidates = index
                .get(&target_identity)
                .expect("learned target must not be evicted by pressure");
            assert!(
                candidates.iter().any(|c| c.handle == target_handle),
                "target handle must survive eviction pressure"
            );
        }

        // The renamed-out target's open still classifies Protected (never a
        // silent Unrelated caused by capacity).
        let moved_file = std::fs::File::open(&moved).unwrap();
        assert!(matches!(
            classifier.classify_fd(moved_file.as_raw_fd()),
            StrictClassification::Protected(_)
        ));
    }

    #[test]
    fn exhausted_index_denies_unverifiable_new_object_rename_out() {
        // R2 (review): "handle_index capacity fail-closed" must be an
        // OPERATION-level fail-closed, not just a health flag. When the
        // learned-handle indexes are exhausted, a NEW dynamic object's
        // learning is refused; if it is then renamed out and opened, the
        // classifier cannot verify its identity — it must DENY (classify as
        // Error), never silently allow as Unrelated.
        let temp = fs_tempdir();
        let root = temp.path().join("chromium");
        let leveldb = root.join("Default/Local Storage/leveldb");
        std::fs::create_dir_all(&leveldb).unwrap();
        let dynamic = leveldb.join("000001.log");
        std::fs::write(&dynamic, b"synthetic session").unwrap();

        let (classifier, _) = new_classifier(&root);
        let capacity = classifier.handle_index_capacity;
        assert!(capacity > 0);

        // Exhaust the index with distinct dynamic candidates.
        for i in 0..(capacity + 8) {
            let p = leveldb.join(format!("{i:06}.log"));
            std::fs::write(&p, b"synthetic pressure").unwrap();
            let f = std::fs::File::open(&p).unwrap();
            let _ = classifier.classify_fd(f.as_raw_fd());
        }
        assert!(classifier
            .metrics
            .handle_index_exhausted
            .load(Ordering::Relaxed));

        // A NEW dynamic object appears AFTER exhaustion: its protected-path
        // open still classifies Protected (path is authoritative), but its
        // handle learning is refused.
        let late = leveldb.join("late.log");
        std::fs::write(&late, b"synthetic late").unwrap();
        let late_file = std::fs::File::open(&late).unwrap();
        assert!(matches!(
            classifier.classify_fd(late_file.as_raw_fd()),
            StrictClassification::Protected(_)
        ));
        drop(late_file);

        // Rename it out and open the outside path: unverifiable ⇒ fail closed
        // (Error → caller denies), never Unrelated.
        let moved = temp.path().join("exfil-late.log");
        std::fs::rename(&late, &moved).unwrap();
        let moved_file = std::fs::File::open(&moved).unwrap();
        assert!(matches!(
            classifier.classify_fd(moved_file.as_raw_fd()),
            StrictClassification::Error(_)
        ));
    }

    #[test]
    fn topology_uncertain_fails_closed_on_ambiguous_open() {
        // P1-b (review): when the FID topology identity subsystem is UNCERTAIN
        // (group creation failed, marks incomplete, learner dead, queue
        // overflow, parse/read failure), an ambiguous outside-path open must
        // NOT be allowed as Unrelated — the object may be a never-opened
        // dynamic object whose identity was lost. classify_fd must return
        // Error (deny) and status must report REDUCED.
        let temp = fs_tempdir();
        let root = temp.path().join("chromium");
        std::fs::create_dir_all(root.join("Default")).unwrap();
        let (classifier, _) = new_classifier(&root);

        // An unrelated file whose open is ambiguous (not path-classified).
        let unrelated = temp.path().join("ordinary.txt");
        std::fs::write(&unrelated, b"synthetic").unwrap();

        // Healthy: Unrelated (allow).
        let f = std::fs::File::open(&unrelated).unwrap();
        assert!(matches!(
            classifier.classify_fd(f.as_raw_fd()),
            StrictClassification::Unrelated
        ));
        drop(f);

        // UNCERTAIN: ambiguous open fails closed.
        classifier
            .metrics
            .topology_uncertain
            .store(true, Ordering::Relaxed);
        let f = std::fs::File::open(&unrelated).unwrap();
        assert!(matches!(
            classifier.classify_fd(f.as_raw_fd()),
            StrictClassification::Error(_)
        ));
    }

    #[test]
    fn topology_handle_miss_does_not_cross_filesystems() {
        // P1-d (review): topology-learned handles are keyed by (fsid,
        // handle_type, handle_bytes). A filesystem handle is fs-scoped opaque
        // identity — identical payloads on different filesystems must NOT
        // match (no cross-fs collision / misattribution).
        let classifier = StrictClassifier {
            browsers: Vec::new(),
            ssh: Vec::new(),
            inode_index: std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            handle_index: std::sync::RwLock::new(std::collections::HashMap::new()),
            topology_handles: std::sync::RwLock::new(std::collections::HashMap::new()),
            topology: std::sync::Mutex::new(TopologyDrainState {
                group: None,
                buf: Vec::new(),
            }),
            marked_dir_handles: std::sync::RwLock::new(std::collections::HashMap::new()),
            handle_index_capacity: 8192,
            filesystem_paths: Vec::new(),
            metrics: std::sync::Arc::new(BackendMetrics::new(EnforcementMode::StrictFilesystem)),
        };
        let handle = platform_linux::object_handle::ObjectHandle {
            mount_id: 0,
            handle_type: 1,
            handle_bytes: vec![0xAA, 0xBB, 0xCC, 0xDD],
        };
        let resource = classifier.fallback_dynamic_resource();
        classifier.learn_topology_handle(
            [1, 2],
            handle.handle_type,
            handle.handle_bytes.clone(),
            resource,
        );
        // Same payload, different filesystem: no match.
        assert!(classifier.match_topology_handle([3, 4], &handle).is_none());
        // Same filesystem: match.
        assert!(classifier.match_topology_handle([1, 2], &handle).is_some());
    }
}
