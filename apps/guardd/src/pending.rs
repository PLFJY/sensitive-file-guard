//! Bounded ownership of fanotify operations awaiting browser-import consent.
//!
//! The event-loop puts only recognized, trusted cross-browser opens here.  A
//! pending permission owns its event fd and resolves it exactly once; dropping
//! an unresolved request fails closed.

use guard_core::ProcessStableId;
use std::collections::HashMap;

use crate::enforce::{MigrationPendingDetails, SshPendingDetails};

pub const PENDING_TIMEOUT_SECS: u64 = 60;
const MAX_PENDING_REQUESTS: usize = 8;
const MAX_PERMISSION_FDS_PER_REQUEST: usize = 32;
const BLOCK_SUPPRESSION_SECS: u64 = 60;
/// A human approval is reused only to coalesce sibling importer processes in
/// the same short-lived browser import burst. It is daemon-memory only and is
/// intentionally narrower than a polkit `*_keep` authorization.
pub const IMPORT_APPROVAL_GRACE_SECS: u64 = 60;
const MAX_RECENT_APPROVALS: usize = 16;

/// Linux's opaque implementation of the portable deferred authorization
/// contract. The daemon store owns the lifecycle, not an OS descriptor.
pub type PendingPermission = platform_linux::fanotify::LinuxPendingPermission;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PendingKey {
    uid: u32,
    target: ProcessStableId,
    source_browser: String,
    source_profile: String,
}

/// Identity of one narrowly reusable import approval. The target executable's
/// device/inode are part of this key, so a different binary at the same path
/// cannot reuse it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RecentApprovalKey {
    uid: u32,
    source_browser: String,
    source_profile: String,
    target_browser: String,
    target_exe: guard_core::identity::ExeIdentity,
}

impl RecentApprovalKey {
    fn from_details(details: &MigrationPendingDetails) -> Self {
        Self {
            uid: details.target.uid,
            source_browser: details.candidate.source_browser.0.clone(),
            source_profile: details.candidate.source_profile.0.clone(),
            target_browser: details.candidate.target_browser.0.clone(),
            target_exe: details.target.stable.exe_identity(),
        }
    }
}

impl PendingKey {
    fn from_details(details: &MigrationPendingDetails) -> Self {
        Self {
            uid: details.target.uid,
            target: details.target_root.clone(),
            source_browser: details.candidate.source_browser.0.clone(),
            source_profile: details.candidate.source_profile.0.clone(),
        }
    }
}

pub struct PendingMigrationRequest {
    pub id: u64,
    pub details: MigrationPendingDetails,
    pub created_at: u64,
    pub expires_at: u64,
    permissions: Vec<PendingPermission>,
}

impl PendingMigrationRequest {
    pub fn resolve(self, allow: bool) {
        for permission in self.permissions {
            if let Err(error) = permission.resolve(allow) {
                tracing::error!(%error, "failed to resolve pending browser migration permission");
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct PendingMigrationInfo {
    pub id: String,
    pub uid: u32,
    pub source_browser: String,
    pub source_profile: String,
    pub target_browser: String,
    pub target_exe: String,
    pub target_pid: u32,
    pub target_start_time: u64,
    pub requested_data: String,
    pub created_at: u64,
    pub expires_at: u64,
}

impl From<&PendingMigrationRequest> for PendingMigrationInfo {
    fn from(request: &PendingMigrationRequest) -> Self {
        Self {
            id: request.id.to_string(),
            uid: request.details.target.uid,
            source_browser: request.details.candidate.source_browser.0.clone(),
            source_profile: request.details.candidate.source_profile.0.clone(),
            target_browser: request.details.candidate.target_browser.0.clone(),
            target_exe: request
                .details
                .target_root
                .exe
                .to_string_lossy()
                .into_owned(),
            target_pid: request.details.target_root.pid,
            target_start_time: request.details.target_root.start_time,
            requested_data: request.details.resource.kind.kind_code().to_owned(),
            created_at: request.created_at,
            expires_at: request.expires_at,
        }
    }
}

pub enum EnqueueResult {
    Created(PendingMigrationInfo),
    Joined,
    /// A sibling process in the exact same verified browser import burst may
    /// receive a new root-bound lease without prompting for the password again.
    RecentlyApproved(Box<MigrationPendingDetails>, PendingPermission),
    DenySuppressed,
    DenyLimit,
}

#[derive(Default)]
pub struct PendingMigrationStore {
    next_id: u64,
    requests: HashMap<u64, PendingMigrationRequest>,
    blocked: HashMap<PendingKey, u64>,
    recent_approvals: HashMap<RecentApprovalKey, u64>,
}

impl PendingMigrationStore {
    pub fn enqueue(
        &mut self,
        details: MigrationPendingDetails,
        permission: PendingPermission,
        now: u64,
    ) -> EnqueueResult {
        self.cleanup_blocked(now);
        self.cleanup_recent_approvals(now);
        let key = PendingKey::from_details(&details);
        if self.blocked.contains_key(&key) {
            return EnqueueResult::DenySuppressed;
        }
        if let Some(request) = self
            .requests
            .values_mut()
            .find(|request| PendingKey::from_details(&request.details) == key)
        {
            if request.permissions.len() >= MAX_PERMISSION_FDS_PER_REQUEST {
                return EnqueueResult::DenyLimit;
            }
            request.permissions.push(permission);
            return EnqueueResult::Joined;
        }
        if self.is_recently_approved(&details, now) {
            return EnqueueResult::RecentlyApproved(Box::new(details), permission);
        }
        if self.requests.len() >= MAX_PENDING_REQUESTS {
            return EnqueueResult::DenyLimit;
        }
        self.next_id = self.next_id.saturating_add(1);
        let request = PendingMigrationRequest {
            id: self.next_id,
            details,
            created_at: now,
            expires_at: now.saturating_add(PENDING_TIMEOUT_SECS),
            permissions: vec![permission],
        };
        let info = PendingMigrationInfo::from(&request);
        self.requests.insert(request.id, request);
        EnqueueResult::Created(info)
    }

    pub fn list_for_uid(&self, uid: u32, root: bool) -> Vec<PendingMigrationInfo> {
        self.requests
            .values()
            .filter(|request| root || request.details.target.uid == uid)
            .map(PendingMigrationInfo::from)
            .collect()
    }

    pub fn get_for_uid(&self, id: &str, uid: u32, root: bool) -> Option<PendingMigrationInfo> {
        let id = id.parse::<u64>().ok()?;
        let request = self.requests.get(&id)?;
        (root || request.details.target.uid == uid).then(|| PendingMigrationInfo::from(request))
    }

    pub fn take_for_resolution(
        &mut self,
        id: &str,
        uid: u32,
        root: bool,
        now: u64,
        block: bool,
    ) -> Option<PendingMigrationRequest> {
        let id = id.parse::<u64>().ok()?;
        let request = self.requests.get(&id)?;
        if !root && request.details.target.uid != uid {
            return None;
        }
        let key = PendingKey::from_details(&request.details);
        let request = self.requests.remove(&id)?;
        if block {
            self.blocked
                .insert(key, now.saturating_add(BLOCK_SUPPRESSION_SECS));
        }
        Some(request)
    }

    /// Take all still-pending sibling importer processes that match a freshly
    /// authenticated import session. Each is revalidated and receives its own
    /// root-bound lease by the caller before its fanotify permission is
    /// answered. They never share an executable-wide capability.
    pub fn take_recent_approval_siblings(
        &mut self,
        approved: &MigrationPendingDetails,
    ) -> Vec<PendingMigrationRequest> {
        let key = RecentApprovalKey::from_details(approved);
        let ids = self
            .requests
            .iter()
            .filter_map(|(id, request)| {
                (RecentApprovalKey::from_details(&request.details) == key).then_some(*id)
            })
            .collect::<Vec<_>>();
        ids.into_iter()
            .filter_map(|id| self.requests.remove(&id))
            .collect()
    }

    /// Removes requests whose target exited or whose 60-second consent window
    /// elapsed.  The returned requests still own their permissions and must be
    /// explicitly denied by the caller.
    pub fn expire(&mut self, now: u64) -> Vec<PendingMigrationRequest> {
        self.cleanup_blocked(now);
        self.cleanup_recent_approvals(now);
        let expired: Vec<u64> = self
            .requests
            .iter()
            .filter_map(|(id, request)| {
                let alive = platform_linux::identity::read_start_time(
                    request.details.target_root.pid as i32,
                )
                .ok()
                    == Some(request.details.target_root.start_time);
                (!alive || now >= request.expires_at).then_some(*id)
            })
            .collect();
        expired
            .into_iter()
            .filter_map(|id| self.requests.remove(&id))
            .collect()
    }

    fn cleanup_blocked(&mut self, now: u64) {
        self.blocked.retain(|_, until| now < *until);
    }

    /// Record the one successful polkit confirmation. This has no disk
    /// backing and is bounded; it is only enough to absorb an importer's
    /// immediately spawned sibling processes.
    pub fn record_recent_approval(&mut self, details: &MigrationPendingDetails, now: u64) {
        self.cleanup_recent_approvals(now);
        let key = RecentApprovalKey::from_details(details);
        if self.recent_approvals.contains_key(&key)
            || self.recent_approvals.len() < MAX_RECENT_APPROVALS
        {
            self.recent_approvals
                .insert(key, now.saturating_add(IMPORT_APPROVAL_GRACE_SECS));
        }
    }

    fn is_recently_approved(&self, details: &MigrationPendingDetails, now: u64) -> bool {
        self.recent_approvals
            .get(&RecentApprovalKey::from_details(details))
            .is_some_and(|until| now < *until)
    }

    fn cleanup_recent_approvals(&mut self, now: u64) {
        self.recent_approvals.retain(|_, until| now < *until);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SshPendingKey {
    uid: u32,
    resource: guard_core::ProtectedResourceId,
    root: ProcessStableId,
}

impl SshPendingKey {
    fn from_details(details: &SshPendingDetails) -> Self {
        Self {
            uid: details.target.uid,
            resource: details.resource.id.clone(),
            root: details.target_root.clone(),
        }
    }
}

pub struct PendingSshReadRequest {
    pub id: u64,
    pub details: SshPendingDetails,
    pub created_at: u64,
    pub expires_at: u64,
    permissions: Vec<PendingPermission>,
}

impl PendingSshReadRequest {
    pub fn resolve(self, allow: bool) {
        for permission in self.permissions {
            if let Err(error) = permission.resolve(allow) {
                tracing::error!(%error, "failed to resolve pending SSH key read permission");
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct PendingSshReadInfo {
    pub id: String,
    pub uid: u32,
    pub key_path: String,
    pub process_exe: String,
    pub pid: u32,
    pub start_time: u64,
    pub created_at: u64,
    pub expires_at: u64,
}

impl From<&PendingSshReadRequest> for PendingSshReadInfo {
    fn from(request: &PendingSshReadRequest) -> Self {
        Self {
            id: request.id.to_string(),
            uid: request.details.target.uid,
            key_path: request.details.resource.path.to_string_lossy().into_owned(),
            process_exe: request
                .details
                .target_root
                .exe
                .to_string_lossy()
                .into_owned(),
            pid: request.details.target_root.pid,
            start_time: request.details.target_root.start_time,
            created_at: request.created_at,
            expires_at: request.expires_at,
        }
    }
}

pub enum SshEnqueueResult {
    Created(PendingSshReadInfo),
    Joined,
    DenySuppressed,
    DenyLimit,
}

/// Small, daemon-memory-only queue for ordinary SSH key-read confirmations.
/// It intentionally does not coalesce different process roots: a shell's
/// sibling command must never inherit another command's user approval.
#[derive(Default)]
pub struct PendingSshReadStore {
    next_id: u64,
    requests: HashMap<u64, PendingSshReadRequest>,
    blocked: HashMap<SshPendingKey, u64>,
}

impl PendingSshReadStore {
    pub fn enqueue(
        &mut self,
        details: SshPendingDetails,
        permission: PendingPermission,
        now: u64,
    ) -> SshEnqueueResult {
        self.cleanup_blocked(now);
        let key = SshPendingKey::from_details(&details);
        if self.blocked.contains_key(&key) {
            return SshEnqueueResult::DenySuppressed;
        }
        if let Some(request) = self
            .requests
            .values_mut()
            .find(|request| SshPendingKey::from_details(&request.details) == key)
        {
            if request.permissions.len() >= MAX_PERMISSION_FDS_PER_REQUEST {
                return SshEnqueueResult::DenyLimit;
            }
            request.permissions.push(permission);
            return SshEnqueueResult::Joined;
        }
        if self.requests.len() >= MAX_PENDING_REQUESTS {
            return SshEnqueueResult::DenyLimit;
        }
        self.next_id = self.next_id.saturating_add(1);
        let request = PendingSshReadRequest {
            id: self.next_id,
            details,
            created_at: now,
            expires_at: now.saturating_add(PENDING_TIMEOUT_SECS),
            permissions: vec![permission],
        };
        let info = PendingSshReadInfo::from(&request);
        self.requests.insert(request.id, request);
        SshEnqueueResult::Created(info)
    }

    pub fn list_for_uid(&self, uid: u32, root: bool) -> Vec<PendingSshReadInfo> {
        self.requests
            .values()
            .filter(|request| root || request.details.target.uid == uid)
            .map(PendingSshReadInfo::from)
            .collect()
    }

    pub fn get_for_uid(&self, id: &str, uid: u32, root: bool) -> Option<PendingSshReadInfo> {
        let id = id.parse::<u64>().ok()?;
        let request = self.requests.get(&id)?;
        (root || request.details.target.uid == uid).then(|| PendingSshReadInfo::from(request))
    }

    pub fn take_for_resolution(
        &mut self,
        id: &str,
        uid: u32,
        root: bool,
        now: u64,
        block: bool,
    ) -> Option<PendingSshReadRequest> {
        let id = id.parse::<u64>().ok()?;
        let request = self.requests.get(&id)?;
        if !root && request.details.target.uid != uid {
            return None;
        }
        let key = SshPendingKey::from_details(&request.details);
        let request = self.requests.remove(&id)?;
        if block {
            self.blocked
                .insert(key, now.saturating_add(BLOCK_SUPPRESSION_SECS));
        }
        Some(request)
    }

    pub fn expire(&mut self, now: u64) -> Vec<PendingSshReadRequest> {
        self.cleanup_blocked(now);
        let expired = self
            .requests
            .iter()
            .filter_map(|(id, request)| {
                let alive = platform_linux::identity::read_start_time(
                    request.details.target_root.pid as i32,
                )
                .ok()
                    == Some(request.details.target_root.start_time);
                (!alive || now >= request.expires_at).then_some(*id)
            })
            .collect::<Vec<_>>();
        expired
            .into_iter()
            .filter_map(|id| self.requests.remove(&id))
            .collect()
    }

    fn cleanup_blocked(&mut self, now: u64) {
        self.blocked.retain(|_, until| now < *until);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_core::policy::MigrationCandidate;
    use guard_core::{
        BrowserId, ProcessIdentity, ProcessStableId, ProfileId, ProtectedResource,
        ProtectedResourceId, ProtectedResourceKind, TrustTier,
    };
    use std::path::PathBuf;

    fn details(pid: u32, exe_ino: u64) -> MigrationPendingDetails {
        let stable = ProcessStableId {
            pid,
            start_time: u64::from(pid),
            exe: PathBuf::from("/opt/microsoft/msedge/msedge"),
            exe_dev: 10,
            exe_ino,
        };
        MigrationPendingDetails {
            candidate: MigrationCandidate {
                source_browser: BrowserId("firefox".into()),
                source_profile: ProfileId("default".into()),
                target_browser: BrowserId("microsoft-edge".into()),
            },
            resource: ProtectedResource {
                id: ProtectedResourceId("synthetic-firefox-key".into()),
                kind: ProtectedResourceKind::BrowserKeyMaterial,
                owner_uid: 1000,
                browser: Some(BrowserId("firefox".into())),
                profile: Some(ProfileId("default".into())),
                path: PathBuf::from("/synthetic/firefox/key4.db"),
            },
            target: ProcessIdentity {
                stable: stable.clone(),
                uid: 1000,
                gid: 1000,
                exe_owner_uid: 0,
                browser: Some(BrowserId("microsoft-edge".into())),
                trust_tier: TrustTier::SystemPackage,
                cmdline: Vec::new(),
                ancestors: Vec::new(),
            },
            target_root: stable,
        }
    }

    #[test]
    fn recent_approval_is_short_lived_and_bound_to_the_exact_executable() {
        let first = details(100, 20);
        let sibling = details(101, 20);
        let replaced_binary = details(102, 21);
        let mut store = PendingMigrationStore::default();
        store.record_recent_approval(&first, 1_000);

        assert!(store.is_recently_approved(&sibling, 1_001));
        assert!(!store.is_recently_approved(&replaced_binary, 1_001));
        assert!(!store.is_recently_approved(&sibling, 1_000 + IMPORT_APPROVAL_GRACE_SECS));
    }
}
