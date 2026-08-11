//! Portable authorization orchestration shared by OS enforcement backends.
//!
//! OS adapters retain their native authorization object and process resolver;
//! this crate owns bounded pending queues, terminal resolution, and lease
//! transitions. It contains no fanotify, Endpoint Security, `/proc`, or UI
//! authentication mechanism.

use std::collections::HashMap;

use guard_core::lease::{
    LeaseId, LeaseSet, MigrationAccessLease, MigrationLeaseState, SshReadAccessLease,
};
use guard_core::policy::{evaluate, AccessEvent, Decision, MigrationCandidate};
use guard_core::{ProcessIdentity, ProcessStableId, ProtectedResource, ProtectedResourceId};
use guard_platform::{PendingPermission, ProcessIdentityResolver};

pub const PENDING_TIMEOUT_SECS: u64 = 60;
const MAX_PENDING_REQUESTS: usize = 8;
const MAX_PERMISSIONS_PER_REQUEST: usize = 32;
const BLOCK_SUPPRESSION_SECS: u64 = 60;
pub const IMPORT_APPROVAL_GRACE_SECS: u64 = 60;
const MAX_RECENT_APPROVALS: usize = 16;

#[derive(Debug, Clone)]
pub struct MigrationPendingDetails {
    pub candidate: MigrationCandidate,
    pub resource: ProtectedResource,
    pub target: ProcessIdentity,
    pub target_root: ProcessStableId,
}

#[derive(Debug, Clone)]
pub struct SshPendingDetails {
    pub resource: ProtectedResource,
    pub target: ProcessIdentity,
    pub target_root: ProcessStableId,
}

/// Shared policy/lease state. Backends supply verified identities and clocks;
/// all lease transitions are kept here so they cannot drift by platform.
#[derive(Default)]
pub struct AuthorizationRuntime {
    leases: LeaseSet,
    next_lease_id: u64,
}

impl AuthorizationRuntime {
    pub fn evaluate(&self, event: &AccessEvent, now: u64) -> Decision {
        evaluate(event, &self.leases, now)
    }

    pub fn leases(&self) -> &LeaseSet {
        &self.leases
    }

    pub fn leases_mut(&mut self) -> &mut LeaseSet {
        &mut self.leases
    }

    pub fn next_lease_id(&mut self) -> LeaseId {
        self.next_lease_id = self.next_lease_id.saturating_add(1);
        LeaseId(self.next_lease_id)
    }

    pub fn approve_migration(
        &mut self,
        pending: &MigrationPendingDetails,
        current: &ProcessIdentity,
        root_is_live: bool,
        now: u64,
        duration_secs: u64,
    ) -> Result<(LeaseId, u64), String> {
        if current.stable != pending.target.stable
            || current.uid != pending.target.uid
            || !current.is_trusted_browser()
            || current.browser.as_ref() != Some(&pending.candidate.target_browser)
        {
            return Err("target browser identity changed before confirmation".to_owned());
        }
        if !root_is_live {
            return Err("target browser root exited before confirmation".to_owned());
        }
        let id = self.next_lease_id();
        let expires_at = now.saturating_add(duration_secs);
        self.leases.migration.push(MigrationAccessLease {
            id,
            source_browser: pending.candidate.source_browser.clone(),
            source_profile: pending.candidate.source_profile.clone(),
            target_browser: pending.candidate.target_browser.clone(),
            uid: pending.target.uid,
            state: MigrationLeaseState::Bound {
                root: pending.target_root.clone(),
            },
            expires_at,
            revoked: false,
        });
        Ok((id, expires_at))
    }

    pub fn approve_ssh_read(
        &mut self,
        pending: &SshPendingDetails,
        current: &ProcessIdentity,
        now: u64,
        duration_secs: u64,
    ) -> Result<(LeaseId, u64), String> {
        if current.stable != pending.target.stable
            || current.uid != pending.target.uid
            || current.uid != pending.resource.owner_uid
        {
            return Err("SSH reader identity changed before confirmation".to_owned());
        }
        let id = self.next_lease_id();
        let expires_at = now.saturating_add(duration_secs);
        self.leases.ssh_read.push(SshReadAccessLease {
            id,
            resource: pending.resource.id.clone(),
            uid: pending.target.uid,
            root: pending.target_root.clone(),
            expires_at,
            revoked: false,
        });
        Ok((id, expires_at))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MigrationPendingKey {
    uid: u32,
    target: ProcessStableId,
    source_browser: String,
    source_profile: String,
}

impl MigrationPendingKey {
    fn from_details(details: &MigrationPendingDetails) -> Self {
        Self {
            uid: details.target.uid,
            target: details.target_root.clone(),
            source_browser: details.candidate.source_browser.0.clone(),
            source_profile: details.candidate.source_profile.0.clone(),
        }
    }
}

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

pub struct PendingMigrationRequest {
    pub id: u64,
    pub details: MigrationPendingDetails,
    pub created_at: u64,
    pub expires_at: u64,
    permissions: Vec<Box<dyn PendingPermission>>,
}

impl PendingMigrationRequest {
    pub fn resolve(self, allow: bool) {
        for permission in self.permissions {
            let result = if allow {
                permission.allow()
            } else {
                permission.deny()
            };
            if let Err(error) = result {
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

pub enum MigrationEnqueueResult {
    Created(PendingMigrationInfo),
    Joined,
    RecentlyApproved(Box<MigrationPendingDetails>, Box<dyn PendingPermission>),
    DenySuppressed,
    DenyLimit,
}

#[derive(Default)]
pub struct PendingMigrationStore {
    next_id: u64,
    requests: HashMap<u64, PendingMigrationRequest>,
    blocked: HashMap<MigrationPendingKey, u64>,
    recent_approvals: HashMap<RecentApprovalKey, u64>,
}

impl PendingMigrationStore {
    pub fn enqueue(
        &mut self,
        details: MigrationPendingDetails,
        permission: Box<dyn PendingPermission>,
        now: u64,
    ) -> MigrationEnqueueResult {
        self.cleanup(now);
        let key = MigrationPendingKey::from_details(&details);
        if self.blocked.contains_key(&key) {
            return MigrationEnqueueResult::DenySuppressed;
        }
        if let Some(request) = self
            .requests
            .values_mut()
            .find(|request| MigrationPendingKey::from_details(&request.details) == key)
        {
            if request.permissions.len() >= MAX_PERMISSIONS_PER_REQUEST {
                return MigrationEnqueueResult::DenyLimit;
            }
            request.permissions.push(permission);
            return MigrationEnqueueResult::Joined;
        }
        if self.is_recently_approved(&details, now) {
            return MigrationEnqueueResult::RecentlyApproved(Box::new(details), permission);
        }
        if self.requests.len() >= MAX_PENDING_REQUESTS {
            return MigrationEnqueueResult::DenyLimit;
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
        MigrationEnqueueResult::Created(info)
    }

    pub fn list_for_uid(&self, uid: u32, root: bool) -> Vec<PendingMigrationInfo> {
        self.requests
            .values()
            .filter(|r| root || r.details.target.uid == uid)
            .map(Into::into)
            .collect()
    }

    pub fn get_for_uid(&self, id: &str, uid: u32, root: bool) -> Option<PendingMigrationInfo> {
        let request = self.requests.get(&id.parse().ok()?)?;
        (root || request.details.target.uid == uid).then(|| request.into())
    }

    pub fn take_for_resolution(
        &mut self,
        id: &str,
        uid: u32,
        root: bool,
        now: u64,
        block: bool,
    ) -> Option<PendingMigrationRequest> {
        let id = id.parse().ok()?;
        let request = self.requests.get(&id)?;
        if !root && request.details.target.uid != uid {
            return None;
        }
        let key = MigrationPendingKey::from_details(&request.details);
        let request = self.requests.remove(&id)?;
        if block {
            self.blocked
                .insert(key, now.saturating_add(BLOCK_SUPPRESSION_SECS));
        }
        Some(request)
    }

    pub fn expire(
        &mut self,
        now: u64,
        resolver: &dyn ProcessIdentityResolver,
    ) -> Vec<PendingMigrationRequest> {
        self.cleanup(now);
        let ids = self
            .requests
            .iter()
            .filter_map(|(id, request)| {
                let alive = resolver
                    .is_live_instance(&request.details.target_root)
                    .unwrap_or(false);
                (!alive || now >= request.expires_at).then_some(*id)
            })
            .collect::<Vec<_>>();
        ids.into_iter()
            .filter_map(|id| self.requests.remove(&id))
            .collect()
    }

    pub fn record_recent_approval(&mut self, details: &MigrationPendingDetails, now: u64) {
        self.cleanup(now);
        let key = RecentApprovalKey::from_details(details);
        if self.recent_approvals.contains_key(&key)
            || self.recent_approvals.len() < MAX_RECENT_APPROVALS
        {
            self.recent_approvals
                .insert(key, now.saturating_add(IMPORT_APPROVAL_GRACE_SECS));
        }
    }

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

    fn is_recently_approved(&self, details: &MigrationPendingDetails, now: u64) -> bool {
        self.recent_approvals
            .get(&RecentApprovalKey::from_details(details))
            .is_some_and(|until| now < *until)
    }

    fn cleanup(&mut self, now: u64) {
        self.blocked.retain(|_, until| now < *until);
        self.recent_approvals.retain(|_, until| now < *until);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SshPendingKey {
    uid: u32,
    resource: ProtectedResourceId,
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
    permissions: Vec<Box<dyn PendingPermission>>,
}

impl PendingSshReadRequest {
    pub fn resolve(self, allow: bool) {
        for permission in self.permissions {
            let result = if allow {
                permission.allow()
            } else {
                permission.deny()
            };
            if let Err(error) = result {
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
        permission: Box<dyn PendingPermission>,
        now: u64,
    ) -> SshEnqueueResult {
        self.blocked.retain(|_, until| now < *until);
        let key = SshPendingKey::from_details(&details);
        if self.blocked.contains_key(&key) {
            return SshEnqueueResult::DenySuppressed;
        }
        if let Some(request) = self
            .requests
            .values_mut()
            .find(|request| SshPendingKey::from_details(&request.details) == key)
        {
            if request.permissions.len() >= MAX_PERMISSIONS_PER_REQUEST {
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
            .filter(|r| root || r.details.target.uid == uid)
            .map(Into::into)
            .collect()
    }
    pub fn get_for_uid(&self, id: &str, uid: u32, root: bool) -> Option<PendingSshReadInfo> {
        let request = self.requests.get(&id.parse().ok()?)?;
        (root || request.details.target.uid == uid).then(|| request.into())
    }
    pub fn take_for_resolution(
        &mut self,
        id: &str,
        uid: u32,
        root: bool,
        now: u64,
        block: bool,
    ) -> Option<PendingSshReadRequest> {
        let id = id.parse().ok()?;
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
    pub fn expire(
        &mut self,
        now: u64,
        resolver: &dyn ProcessIdentityResolver,
    ) -> Vec<PendingSshReadRequest> {
        self.blocked.retain(|_, until| now < *until);
        let ids = self
            .requests
            .iter()
            .filter_map(|(id, request)| {
                let alive = resolver
                    .is_live_instance(&request.details.target_root)
                    .unwrap_or(false);
                (!alive || now >= request.expires_at).then_some(*id)
            })
            .collect::<Vec<_>>();
        ids.into_iter()
            .filter_map(|id| self.requests.remove(&id))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_core::identity::{AncestorSummary, TrustTier};
    use guard_core::resource::{BrowserId, ProfileId, ProtectedResourceKind};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Terminal {
        Pending,
        Allowed,
        Denied,
    }

    struct FakePermission(Arc<Mutex<Terminal>>);
    impl PendingPermission for FakePermission {
        fn allow(self: Box<Self>) -> anyhow::Result<()> {
            *self.0.lock().unwrap() = Terminal::Allowed;
            Ok(())
        }
        fn deny(self: Box<Self>) -> anyhow::Result<()> {
            *self.0.lock().unwrap() = Terminal::Denied;
            Ok(())
        }
    }

    struct FakeResolver {
        current: ProcessIdentity,
        live: bool,
    }
    impl ProcessIdentityResolver for FakeResolver {
        fn resolve(&self, _pid: u32, _owner: u32) -> anyhow::Result<ProcessIdentity> {
            Ok(self.current.clone())
        }
        fn is_live_instance(&self, identity: &ProcessStableId) -> anyhow::Result<bool> {
            Ok(self.live && identity == &self.current.stable)
        }
        fn ancestors(&self, _pid: u32) -> anyhow::Result<Vec<AncestorSummary>> {
            Ok(Vec::new())
        }
    }

    fn process(browser: Option<&str>) -> ProcessIdentity {
        ProcessIdentity {
            stable: ProcessStableId {
                pid: 42,
                start_time: 7,
                exe: PathBuf::from("/synthetic/browser"),
                exe_dev: 1,
                exe_ino: 2,
            },
            uid: 1000,
            gid: 1000,
            exe_owner_uid: 0,
            browser: browser.map(|value| BrowserId(value.to_owned())),
            trust_tier: TrustTier::SystemPackage,
            cmdline: Vec::new(),
            ancestors: Vec::new(),
        }
    }

    fn browser_details() -> MigrationPendingDetails {
        let target = process(Some("browser-b"));
        MigrationPendingDetails {
            candidate: MigrationCandidate {
                source_browser: BrowserId("browser-a".into()),
                source_profile: ProfileId("default".into()),
                target_browser: BrowserId("browser-b".into()),
            },
            resource: ProtectedResource {
                id: ProtectedResourceId("cookie-fixture".into()),
                kind: ProtectedResourceKind::CookieStore,
                owner_uid: 1000,
                browser: Some(BrowserId("browser-a".into())),
                profile: Some(ProfileId("default".into())),
                path: PathBuf::from("/synthetic/Cookies"),
            },
            target_root: target.stable.clone(),
            target,
        }
    }

    fn ssh_details() -> SshPendingDetails {
        let target = process(None);
        SshPendingDetails {
            resource: ProtectedResource {
                id: ProtectedResourceId("ssh-fixture".into()),
                kind: ProtectedResourceKind::SshPrivateKey,
                owner_uid: 1000,
                browser: None,
                profile: None,
                path: PathBuf::from("/synthetic/id_ed25519"),
            },
            target_root: target.stable.clone(),
            target,
        }
    }

    fn fake_permission() -> (Box<dyn PendingPermission>, Arc<Mutex<Terminal>>) {
        let state = Arc::new(Mutex::new(Terminal::Pending));
        (Box::new(FakePermission(Arc::clone(&state))), state)
    }

    #[test]
    fn browser_pending_allow_creates_bound_lease_and_releases_permission() {
        let details = browser_details();
        let event = AccessEvent {
            resource: details.resource.clone(),
            process: details.target.clone(),
            operation: guard_core::policy::AccessOperation::Read,
        };
        let mut runtime = AuthorizationRuntime::default();
        assert!(matches!(
            runtime.evaluate(&event, 100),
            Decision::RequireMigrationConfirmation(_)
        ));
        let (permission, terminal) = fake_permission();
        let mut pending = PendingMigrationStore::default();
        let id = match pending.enqueue(details.clone(), permission, 100) {
            MigrationEnqueueResult::Created(info) => info.id,
            _ => panic!("expected new pending browser request"),
        };
        let request = pending
            .take_for_resolution(&id, 1000, false, 101, false)
            .unwrap();
        let resolver = FakeResolver {
            current: details.target.clone(),
            live: true,
        };
        let current = resolver
            .resolve(details.target.stable.pid, details.resource.owner_uid)
            .unwrap();
        let root_live = resolver.is_live_instance(&details.target_root).unwrap();
        let (lease, _) = runtime
            .approve_migration(&details, &current, root_live, 101, 600)
            .unwrap();
        request.resolve(true);
        assert_eq!(*terminal.lock().unwrap(), Terminal::Allowed);
        assert_eq!(runtime.leases().migration[0].id, lease);
        assert!(matches!(runtime.evaluate(&event, 102), Decision::AllowByLease(id) if id == lease));
    }

    #[test]
    fn browser_block_and_timeout_fail_closed() {
        let details = browser_details();
        let (permission, blocked) = fake_permission();
        let mut store = PendingMigrationStore::default();
        let id = match store.enqueue(details.clone(), permission, 10) {
            MigrationEnqueueResult::Created(info) => info.id,
            _ => unreachable!(),
        };
        store
            .take_for_resolution(&id, 1000, false, 11, true)
            .unwrap()
            .resolve(false);
        assert_eq!(*blocked.lock().unwrap(), Terminal::Denied);

        let (permission, timed_out) = fake_permission();
        let mut store = PendingMigrationStore::default();
        assert!(matches!(
            store.enqueue(details.clone(), permission, 10),
            MigrationEnqueueResult::Created(_)
        ));
        let resolver = FakeResolver {
            current: details.target,
            live: true,
        };
        for request in store.expire(10 + PENDING_TIMEOUT_SECS, &resolver) {
            request.resolve(false);
        }
        assert_eq!(*timed_out.lock().unwrap(), Terminal::Denied);
    }

    #[test]
    fn ssh_pending_allow_creates_reader_lease_and_block_timeout_deny() {
        let details = ssh_details();
        let event = AccessEvent {
            resource: details.resource.clone(),
            process: details.target.clone(),
            operation: guard_core::policy::AccessOperation::Read,
        };
        let mut runtime = AuthorizationRuntime::default();
        assert_eq!(
            runtime.evaluate(&event, 20),
            Decision::RequireSshKeyConfirmation
        );
        let (permission, allowed) = fake_permission();
        let mut store = PendingSshReadStore::default();
        let id = match store.enqueue(details.clone(), permission, 20) {
            SshEnqueueResult::Created(info) => info.id,
            _ => unreachable!(),
        };
        let request = store
            .take_for_resolution(&id, 1000, false, 21, false)
            .unwrap();
        let resolver = FakeResolver {
            current: details.target.clone(),
            live: true,
        };
        let current = resolver
            .resolve(details.target.stable.pid, details.resource.owner_uid)
            .unwrap();
        let (lease, _) = runtime
            .approve_ssh_read(&details, &current, 21, 10)
            .unwrap();
        request.resolve(true);
        assert_eq!(*allowed.lock().unwrap(), Terminal::Allowed);
        assert!(matches!(runtime.evaluate(&event, 22), Decision::AllowByLease(id) if id == lease));

        let block_details = ssh_details();
        let (permission, blocked) = fake_permission();
        let mut blocked_store = PendingSshReadStore::default();
        let blocked_id = match blocked_store.enqueue(block_details, permission, 25) {
            SshEnqueueResult::Created(info) => info.id,
            _ => unreachable!(),
        };
        blocked_store
            .take_for_resolution(&blocked_id, 1000, false, 26, true)
            .unwrap()
            .resolve(false);
        assert_eq!(*blocked.lock().unwrap(), Terminal::Denied);

        let (permission, timed_out) = fake_permission();
        let mut store = PendingSshReadStore::default();
        assert!(matches!(
            store.enqueue(details, permission, 30),
            SshEnqueueResult::Created(_)
        ));
        for request in store.expire(30 + PENDING_TIMEOUT_SECS, &resolver) {
            request.resolve(false);
        }
        assert_eq!(*timed_out.lock().unwrap(), Terminal::Denied);
    }
}
