//! Bounded ownership of fanotify operations awaiting browser-import consent.
//!
//! The event-loop puts only recognized, trusted cross-browser opens here.  A
//! pending permission owns its event fd and resolves it exactly once; dropping
//! an unresolved request fails closed.

use std::collections::HashMap;
use std::os::fd::RawFd;
use std::sync::Arc;

use guard_core::ProcessStableId;
use platform_linux::fanotify::{self, FanotifyGroup};

use crate::enforce::MigrationPendingDetails;

pub const PENDING_TIMEOUT_SECS: u64 = 60;
const MAX_PENDING_REQUESTS: usize = 8;
const MAX_PERMISSION_FDS_PER_REQUEST: usize = 32;
const BLOCK_SUPPRESSION_SECS: u64 = 60;

/// RAII owner for exactly one unresolved FAN_OPEN_PERM event.
pub struct PendingPermission {
    fd: RawFd,
    group: Arc<FanotifyGroup>,
    resolved: bool,
}

impl PendingPermission {
    pub fn new(fd: RawFd, group: Arc<FanotifyGroup>) -> Self {
        Self {
            fd,
            group,
            resolved: false,
        }
    }

    pub fn resolve(mut self, allow: bool) -> std::io::Result<()> {
        let result = self.group.respond(self.fd, allow);
        fanotify::close_event_fd(self.fd);
        self.resolved = true;
        result
    }
}

impl Drop for PendingPermission {
    fn drop(&mut self) {
        if !self.resolved {
            if let Err(error) = self.group.respond(self.fd, false) {
                tracing::error!(%error, fd = self.fd, "failed to deny dropped pending fanotify permission");
            }
            fanotify::close_event_fd(self.fd);
            self.resolved = true;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PendingKey {
    uid: u32,
    target: ProcessStableId,
    source_browser: String,
    source_profile: String,
}

impl PendingKey {
    fn from_details(details: &MigrationPendingDetails) -> Self {
        Self {
            uid: details.target.uid,
            target: details.target.stable.clone(),
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
                .target
                .stable
                .exe
                .to_string_lossy()
                .into_owned(),
            target_pid: request.details.target.stable.pid,
            target_start_time: request.details.target.stable.start_time,
            requested_data: request.details.resource.kind.kind_code().to_owned(),
            created_at: request.created_at,
            expires_at: request.expires_at,
        }
    }
}

pub enum EnqueueResult {
    Created(PendingMigrationInfo),
    Joined,
    DenySuppressed,
    DenyLimit,
}

#[derive(Default)]
pub struct PendingMigrationStore {
    next_id: u64,
    requests: HashMap<u64, PendingMigrationRequest>,
    blocked: HashMap<PendingKey, u64>,
}

impl PendingMigrationStore {
    pub fn enqueue(
        &mut self,
        details: MigrationPendingDetails,
        permission: PendingPermission,
        now: u64,
    ) -> EnqueueResult {
        self.cleanup_blocked(now);
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

    /// Removes requests whose target exited or whose 60-second consent window
    /// elapsed.  The returned requests still own their permissions and must be
    /// explicitly denied by the caller.
    pub fn expire(&mut self, now: u64) -> Vec<PendingMigrationRequest> {
        self.cleanup_blocked(now);
        let expired: Vec<u64> = self
            .requests
            .iter()
            .filter_map(|(id, request)| {
                let alive = platform_linux::identity::read_start_time(
                    request.details.target.stable.pid as i32,
                )
                .ok()
                    == Some(request.details.target.stable.start_time);
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
}
