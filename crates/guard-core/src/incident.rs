//! Bounded SSH read-to-network correlation state.
//!
//! This is deliberately *not* information-flow tracking.  It only records
//! that one stable process (or a child created after the read) recently read a
//! protected SSH private key.  A platform network hook may then block an
//! actual external send from that exact process tree.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::identity::{AncestorSummary, ProcessIdentity, ProcessStableId};
use crate::resource::ProtectedResource;

pub const DEFAULT_SSH_BEHAVIOR_WINDOW_SECS: u64 = 10;
pub const MIN_SSH_BEHAVIOR_WINDOW_SECS: u64 = 1;
pub const MAX_SSH_BEHAVIOR_WINDOW_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshIncidentState {
    Observing,
    PendingDecision,
    Allowed,
    Expired,
    Quarantined,
    Terminated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentResolution {
    AllowNetwork,
    StopAndQuarantine,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkDestination {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineCandidateKind {
    DirectExecutable,
    ExplicitScript,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineCandidate {
    pub path: PathBuf,
    pub dev: u64,
    pub ino: u64,
    pub kind: QuarantineCandidateKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshExposureIncident {
    pub id: String,
    pub uid: u32,
    pub key_resource_id: String,
    pub key_path: PathBuf,
    pub root_process: ProcessStableId,
    /// Linux thread-group leader used by the BPF send map. The stable process
    /// identity above remains the authorization/audit identity; this is not a
    /// naked-PID security decision.
    pub root_tgid: u32,
    pub process_exe: PathBuf,
    pub quarantine_candidate: Option<QuarantineCandidate>,
    pub parent: Option<AncestorSummary>,
    /// Milliseconds on the daemon's monotonic clock, never wall-clock time.
    pub first_sensitive_read_ms: u64,
    pub last_sensitive_read_ms: u64,
    pub observe_until_ms: u64,
    pub state: SshIncidentState,
    pub blocked_network_attempts: u64,
    pub first_network_ms: Option<u64>,
    pub destination: Option<NetworkDestination>,
    pub resolution: Option<IncidentResolution>,
    /// Human-readable metadata about a completed containment transaction. It
    /// never includes file contents or arbitrary command-line arguments.
    pub resolution_detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkDecision {
    Allow,
    Block { newly_pending: bool },
}

/// In-memory live state.  State transitions are separately audited by the
/// daemon; retaining this compact index in memory prevents recovery after a
/// daemon crash from pretending that a still-running process is contained.
#[derive(Debug, Default)]
pub struct ExposureTracker {
    next_id: u64,
    incidents: HashMap<String, SshExposureIncident>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExposureSummary {
    pub active: u64,
    pub pending: u64,
    pub key_reads: u64,
    pub network_blocks: u64,
    pub user_allows: u64,
    pub quarantines: u64,
}

impl ExposureTracker {
    pub fn arm(
        &mut self,
        resource: &ProtectedResource,
        process: &ProcessIdentity,
        quarantine_candidate: Option<QuarantineCandidate>,
        root_tgid: u32,
        now_ms: u64,
        window_secs: u64,
    ) -> (SshExposureIncident, bool) {
        self.expire(now_ms);
        if let Some(existing) = self.incidents.values_mut().find(|incident| {
            matches!(
                incident.state,
                SshIncidentState::Observing | SshIncidentState::PendingDecision
            ) && incident.root_process == process.stable
                && incident.key_resource_id == resource.id.0
        }) {
            existing.last_sensitive_read_ms = now_ms;
            existing.observe_until_ms = now_ms.saturating_add(window_secs.saturating_mul(1000));
            return (existing.clone(), false);
        }

        self.next_id = self.next_id.saturating_add(1);
        let id = format!("ssh-{:016x}", self.next_id);
        let incident = SshExposureIncident {
            id: id.clone(),
            uid: process.uid,
            key_resource_id: resource.id.0.clone(),
            key_path: resource.path.clone(),
            root_process: process.stable.clone(),
            root_tgid,
            process_exe: process.stable.exe.clone(),
            quarantine_candidate,
            parent: process.ancestors.first().cloned(),
            first_sensitive_read_ms: now_ms,
            last_sensitive_read_ms: now_ms,
            observe_until_ms: now_ms.saturating_add(window_secs.saturating_mul(1000)),
            state: SshIncidentState::Observing,
            blocked_network_attempts: 0,
            first_network_ms: None,
            destination: None,
            resolution: None,
            resolution_detail: None,
        };
        self.incidents.insert(id.clone(), incident);
        (
            self.incidents.get(&id).expect("inserted incident").clone(),
            true,
        )
    }

    /// Called by a network hook only for an actual non-loopback send attempt.
    pub fn network_send(
        &mut self,
        process: &ProcessIdentity,
        destination: NetworkDestination,
        now_ms: u64,
    ) -> NetworkDecision {
        self.expire(now_ms);
        let Some(id) = self
            .matching_incident(process)
            .map(|incident| incident.id.clone())
        else {
            return NetworkDecision::Allow;
        };
        let incident = self
            .incidents
            .get_mut(&id)
            .expect("matching incident remains live");
        match incident.state {
            SshIncidentState::Observing => {
                incident.state = SshIncidentState::PendingDecision;
                incident.blocked_network_attempts = 1;
                incident.first_network_ms = Some(now_ms);
                incident.destination = Some(destination);
                NetworkDecision::Block {
                    newly_pending: true,
                }
            }
            SshIncidentState::PendingDecision => {
                incident.blocked_network_attempts =
                    incident.blocked_network_attempts.saturating_add(1);
                NetworkDecision::Block {
                    newly_pending: false,
                }
            }
            SshIncidentState::Allowed
            | SshIncidentState::Expired
            | SshIncidentState::Quarantined
            | SshIncidentState::Terminated => NetworkDecision::Allow,
        }
    }

    pub fn resolve(
        &mut self,
        id: &str,
        resolution: IncidentResolution,
    ) -> Result<(), &'static str> {
        let incident = self.incidents.get_mut(id).ok_or("incident not found")?;
        if incident.state != SshIncidentState::PendingDecision {
            return Err("incident is not awaiting a decision");
        }
        incident.resolution = Some(resolution);
        incident.state = match resolution {
            IncidentResolution::AllowNetwork => SshIncidentState::Allowed,
            IncidentResolution::StopAndQuarantine => SshIncidentState::Terminated,
        };
        Ok(())
    }

    pub fn set_resolution_detail(&mut self, id: &str, detail: String) -> Result<(), &'static str> {
        let incident = self.incidents.get_mut(id).ok_or("incident not found")?;
        if incident.resolution.is_none() {
            return Err("incident is not resolved");
        }
        incident.resolution_detail = Some(detail);
        Ok(())
    }

    /// Remove a just-created observing incident when its kernel map arm failed
    /// before the corresponding file access was allowed. Existing incidents
    /// are never removed here because they may still represent a prior armed
    /// read.
    pub fn discard_unarmed(&mut self, id: &str) {
        if self
            .incidents
            .get(id)
            .is_some_and(|incident| incident.state == SshIncidentState::Observing)
        {
            self.incidents.remove(id);
        }
    }

    /// Record a kernel-blocked send using the opaque incident ID carried in
    /// the BPF map. The BPF map is the authority for the process-tree match;
    /// this method only advances the auditable userspace state.
    pub fn blocked_send(
        &mut self,
        incident_id: u64,
        tgid: u32,
        uid: u32,
        now_ms: u64,
    ) -> Option<bool> {
        let newly_pending = self.ensure_pending(incident_id, tgid, uid, now_ms)?;
        if !newly_pending {
            let incident = self
                .incidents
                .get_mut(&format!("ssh-{incident_id:016x}"))
                .expect("ensure_pending found incident");
            incident.blocked_network_attempts = incident.blocked_network_attempts.saturating_add(1);
        }
        Some(newly_pending)
    }

    /// Reconcile a kernel map entry that is already pending when its initial
    /// ring-buffer event could not be delivered. This establishes one audited
    /// pending incident without inflating the count on each polling tick.
    pub fn ensure_pending(
        &mut self,
        incident_id: u64,
        tgid: u32,
        uid: u32,
        now_ms: u64,
    ) -> Option<bool> {
        let id = format!("ssh-{incident_id:016x}");
        let incident = self.incidents.get_mut(&id)?;
        if tgid == 0 || incident.uid != uid || incident.state == SshIncidentState::Expired {
            return None;
        }
        match incident.state {
            SshIncidentState::Observing => {
                incident.state = SshIncidentState::PendingDecision;
                incident.blocked_network_attempts = 1;
                incident.first_network_ms = Some(now_ms);
                Some(true)
            }
            SshIncidentState::PendingDecision => Some(false),
            SshIncidentState::Allowed
            | SshIncidentState::Quarantined
            | SshIncidentState::Terminated
            | SshIncidentState::Expired => None,
        }
    }

    pub fn incidents_for_uid(&self, uid: u32, is_root: bool) -> Vec<SshExposureIncident> {
        let mut incidents: Vec<_> = self
            .incidents
            .values()
            .filter(|incident| is_root || incident.uid == uid)
            .cloned()
            .collect();
        incidents.sort_by(|left, right| {
            right
                .first_sensitive_read_ms
                .cmp(&left.first_sensitive_read_ms)
        });
        incidents
    }

    pub fn incident_for_kernel_id(&self, incident_id: u64) -> Option<SshExposureIncident> {
        self.incidents
            .get(&format!("ssh-{incident_id:016x}"))
            .cloned()
    }

    pub fn summary(&self) -> ExposureSummary {
        self.incidents
            .values()
            .fold(ExposureSummary::default(), |mut summary, incident| {
                summary.key_reads = summary.key_reads.saturating_add(1);
                summary.network_blocks = summary
                    .network_blocks
                    .saturating_add(incident.blocked_network_attempts);
                match incident.state {
                    SshIncidentState::Observing => {
                        summary.active = summary.active.saturating_add(1)
                    }
                    SshIncidentState::PendingDecision => {
                        summary.active = summary.active.saturating_add(1);
                        summary.pending = summary.pending.saturating_add(1);
                    }
                    SshIncidentState::Allowed => {
                        summary.active = summary.active.saturating_add(1);
                        summary.user_allows = summary.user_allows.saturating_add(1);
                    }
                    SshIncidentState::Quarantined => {
                        summary.quarantines = summary.quarantines.saturating_add(1)
                    }
                    SshIncidentState::Terminated => {}
                    SshIncidentState::Expired => {}
                }
                summary
            })
    }

    pub fn expire(&mut self, now_ms: u64) {
        for incident in self.incidents.values_mut() {
            if incident.state == SshIncidentState::Observing && now_ms >= incident.observe_until_ms
            {
                incident.state = SshIncidentState::Expired;
            }
        }
    }

    fn matching_incident(&self, process: &ProcessIdentity) -> Option<&SshExposureIncident> {
        self.incidents.values().find(|incident| {
            incident.uid == process.uid
                && (incident.root_process == process.stable
                    || process
                        .ancestors
                        .iter()
                        .any(|ancestor| same_ancestor(ancestor, &incident.root_process)))
                && matches!(
                    incident.state,
                    SshIncidentState::Observing
                        | SshIncidentState::PendingDecision
                        | SshIncidentState::Allowed
                )
        })
    }
}

fn same_ancestor(ancestor: &AncestorSummary, root: &ProcessStableId) -> bool {
    ancestor.pid == root.pid
        && ancestor.start_time == root.start_time
        && ancestor.exe == root.exe
        && ancestor.exe_dev == root.exe_dev
        && ancestor.exe_ino == root.exe_ino
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{ProcessStableId, TrustTier};
    use crate::resource::{ProtectedResourceId, ProtectedResourceKind};

    fn process(pid: u32, start_time: u64, ancestors: Vec<AncestorSummary>) -> ProcessIdentity {
        ProcessIdentity {
            stable: ProcessStableId {
                pid,
                start_time,
                exe: "/synthetic/probe".into(),
                exe_dev: 1,
                exe_ino: 2,
            },
            uid: 1000,
            gid: 1000,
            exe_owner_uid: 1000,
            browser: None,
            trust_tier: TrustTier::Unknown,
            cmdline: Vec::new(),
            ancestors,
        }
    }

    fn key() -> ProtectedResource {
        ProtectedResource {
            id: ProtectedResourceId("ssh/synthetic".into()),
            kind: ProtectedResourceKind::SshPrivateKey,
            owner_uid: 1000,
            browser: None,
            profile: None,
            path: "/synthetic/id_ed25519".into(),
        }
    }

    fn destination() -> NetworkDestination {
        NetworkDestination {
            ip: "203.0.113.10".into(),
            port: 443,
            protocol: "tcp".into(),
        }
    }

    #[test]
    fn direct_send_is_blocked_and_pending_never_auto_expires() {
        let mut tracker = ExposureTracker::default();
        let reader = process(12, 1, vec![]);
        tracker.arm(&key(), &reader, None, 12, 100, 10);
        assert_eq!(
            tracker.network_send(&reader, destination(), 200),
            NetworkDecision::Block {
                newly_pending: true
            }
        );
        assert_eq!(
            tracker.network_send(&reader, destination(), 50_000),
            NetworkDecision::Block {
                newly_pending: false
            }
        );
    }

    #[test]
    fn unrelated_same_uid_and_expired_reader_are_allowed() {
        let mut tracker = ExposureTracker::default();
        let reader = process(12, 1, vec![]);
        tracker.arm(&key(), &reader, None, 12, 100, 1);
        assert_eq!(
            tracker.network_send(&process(13, 2, vec![]), destination(), 200),
            NetworkDecision::Allow
        );
        assert_eq!(
            tracker.network_send(&reader, destination(), 1_101),
            NetworkDecision::Allow
        );
    }

    #[test]
    fn future_child_is_in_scope_but_existing_sibling_is_not() {
        let mut tracker = ExposureTracker::default();
        let parent = process(12, 1, vec![]);
        tracker.arm(&key(), &parent, None, 12, 100, 10);
        let child = process(
            13,
            2,
            vec![AncestorSummary {
                pid: 12,
                start_time: 1,
                exe: "/synthetic/probe".into(),
                exe_dev: 1,
                exe_ino: 2,
            }],
        );
        assert_eq!(
            tracker.network_send(&child, destination(), 200),
            NetworkDecision::Block {
                newly_pending: true
            }
        );
        assert_eq!(
            tracker.network_send(&process(14, 3, vec![]), destination(), 201),
            NetworkDecision::Allow
        );
    }

    #[test]
    fn allow_is_incident_scoped_not_a_future_whitelist() {
        let mut tracker = ExposureTracker::default();
        let reader = process(12, 1, vec![]);
        let (incident, _) = tracker.arm(&key(), &reader, None, 12, 100, 10);
        let id = incident.id.clone();
        assert!(matches!(
            tracker.network_send(&reader, destination(), 200),
            NetworkDecision::Block { .. }
        ));
        tracker
            .resolve(&id, IncidentResolution::AllowNetwork)
            .unwrap();
        assert_eq!(
            tracker.network_send(&reader, destination(), 201),
            NetworkDecision::Allow
        );
        let (_, is_new) = tracker.arm(&key(), &reader, None, 12, 300, 10);
        assert!(is_new);
    }

    #[test]
    fn kernel_block_event_coalesces_on_the_opaque_incident_id() {
        let mut tracker = ExposureTracker::default();
        let reader = process(12, 1, vec![]);
        let (incident, _) = tracker.arm(&key(), &reader, None, 12, 100, 10);
        let kernel_id = u64::from_str_radix(incident.id.strip_prefix("ssh-").unwrap(), 16).unwrap();
        assert_eq!(tracker.blocked_send(kernel_id, 12, 1000, 200), Some(true));
        assert_eq!(tracker.blocked_send(kernel_id, 13, 1000, 201), Some(false));
        assert_eq!(
            tracker
                .incident_for_kernel_id(kernel_id)
                .unwrap()
                .blocked_network_attempts,
            2
        );
    }

    #[test]
    fn failed_new_arm_can_be_discarded_without_an_incident() {
        let mut tracker = ExposureTracker::default();
        let reader = process(12, 1, vec![]);
        let (incident, is_new) = tracker.arm(&key(), &reader, None, 12, 100, 10);
        assert!(is_new);
        tracker.discard_unarmed(&incident.id);
        assert!(tracker.incident_for_kernel_id(1).is_none());
    }

    #[test]
    fn pending_reconciliation_is_idempotent() {
        let mut tracker = ExposureTracker::default();
        let reader = process(12, 1, vec![]);
        let (incident, _) = tracker.arm(&key(), &reader, None, 12, 100, 10);
        let kernel_id = u64::from_str_radix(incident.id.strip_prefix("ssh-").unwrap(), 16).unwrap();
        assert_eq!(tracker.ensure_pending(kernel_id, 12, 1000, 200), Some(true));
        assert_eq!(
            tracker.ensure_pending(kernel_id, 12, 1000, 201),
            Some(false)
        );
        assert_eq!(
            tracker
                .incident_for_kernel_id(kernel_id)
                .unwrap()
                .blocked_network_attempts,
            1
        );
    }

    #[test]
    fn resolution_detail_requires_and_follows_resolution() {
        let mut tracker = ExposureTracker::default();
        let reader = process(12, 1, vec![]);
        let (incident, _) = tracker.arm(&key(), &reader, None, 12, 100, 10);
        assert!(tracker
            .set_resolution_detail(&incident.id, "not yet".into())
            .is_err());
        assert!(matches!(
            tracker.network_send(&reader, destination(), 200),
            NetworkDecision::Block { .. }
        ));
        tracker
            .resolve(&incident.id, IncidentResolution::StopAndQuarantine)
            .unwrap();
        tracker
            .set_resolution_detail(&incident.id, "terminated; no file moved".into())
            .unwrap();
        assert_eq!(
            tracker
                .incident_for_kernel_id(1)
                .unwrap()
                .resolution_detail
                .as_deref(),
            Some("terminated; no file moved")
        );
    }
}
