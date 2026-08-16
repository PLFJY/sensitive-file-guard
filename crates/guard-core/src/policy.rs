//! Deterministic policy engine.
//!
//! Inputs are pure data (`AccessEvent` + `LeaseSet` + `now`); the output is a
//! small `Decision` with no risk scores or ML. The policy is only consulted for
//! protected resources — the platform layer allows unprotected opens without
//! calling `evaluate`.
//!
//! Baseline rules (see `00_GLOBAL_CONTRACT.md`):
//! - trusted browser + own profile => Allow
//! - trusted browser + another browser's profile => Deny unless valid
//!   `MigrationAccessLease` => otherwise `AllowByLease`
//! - unknown / non-browser + browser protected resource => Deny (a migration
//!   lease may still cover a target-tree helper process even if the opener's own
//!   browser field is unset)
//! - SSH private-key reads => require a human confirmation unless an exact
//!   `SshLoadLease` or root-bound `SshReadAccessLease` is valid
//! - cross-user SSH access => Deny immediately
//! - PID reuse / SSH identity mismatch => lease does not apply, then confirmation

use serde::{Deserialize, Serialize};

use crate::identity::{AncestorSummary, ProcessIdentity, ProcessIntegrity, ProcessStableId};
use crate::lease::{LeaseId, LeaseSet, MigrationLeaseState};
use crate::resource::{BrowserId, ProfileId, ProtectedResource, ProtectedResourceKind};

/// A policy-only description of a trusted browser attempting to import one
/// enrolled browser profile into another.  It deliberately has no fd or UI
/// state: the selected enforcement adapter owns the pending authorization operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationCandidate {
    pub source_browser: BrowserId,
    pub source_profile: ProfileId,
    pub target_browser: BrowserId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Allow,
    Deny(DenyReason),
    AllowByLease(LeaseId),
    RequireMigrationConfirmation(MigrationCandidate),
    RequireSshKeyConfirmation,
    /// Audit-only: a notify-only signal (task-capability obtained, trace,
    /// remote thread, code-signing invalidation) was observed against a
    /// shielded target. Never returned by `evaluate`; DETECTED + CONTAINED,
    /// never PREVENTED.
    Detected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenyReason {
    UnknownProcess,
    NotTrustedIdentity,
    CrossBrowserWithoutLease,
    SshApprovalRequired,
    LeaseExpired,
    LeaseRevoked,
    LeaseScopeMismatch,
    WrongUid,
    IdentityMismatch,
    OneShotLeaseUsed,
    /// The exact live process instance has been marked Compromised by Process
    /// Shield and must not receive further protected-resource authority.
    ProcessIntegrityCompromised,
}

impl DenyReason {
    /// Stable, machine-readable snake_case reason code for tools (Phase 12).
    /// These strings are a public contract: `guardctl explain --json` exposes
    /// them and automated agents may branch on them. They must NEVER change
    /// shape once shipped — add new codes, do not rename existing ones.
    pub fn reason_code(&self) -> &'static str {
        match self {
            // An ordinary/unknown process tried to read a protected browser
            // resource (no lease, not the owning browser).
            Self::UnknownProcess => "browser_protected_resource",
            // The process exe is not in the trusted enrollment set.
            Self::NotTrustedIdentity => "identity_untrusted",
            // A different browser tried to read another browser's profile
            // without a migration access lease.
            Self::CrossBrowserWithoutLease => "migration_lease_required",
            Self::SshApprovalRequired => "ssh_read_approval_required",
            Self::LeaseExpired => "lease_expired",
            Self::LeaseRevoked => "lease_revoked",
            // Reserved for backends that can enforce a narrower lease scope.
            Self::LeaseScopeMismatch => "lease_scope_mismatch",
            // The process uid does not own the protected resource.
            Self::WrongUid => "wrong_uid",
            // The lease's armed identity does not match the process (PID reuse
            // or a different invocation of the same exe).
            Self::IdentityMismatch => "identity_mismatch",
            // The one-shot SshLoadLease was already consumed.
            Self::OneShotLeaseUsed => "one_shot_lease_used",
            // The exact live process instance was confirmed compromised by
            // Process Shield; it must not receive further secret authority.
            Self::ProcessIntegrityCompromised => "process_integrity_compromised",
        }
    }
}

/// The intercepted operation. `Open` is the primary protected-resource gate;
/// `Write` and `Copy` are modeled for backends that can distinguish them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessOperation {
    Open,
    Read,
    Write,
    Copy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessEvent {
    pub resource: ProtectedResource,
    pub process: ProcessIdentity,
    pub operation: AccessOperation,
}

/// Evaluate the deterministic allow/deny decision.
///
/// `now` is in the same clock/units as `expires_at` on the leases.
///
/// Process Shield gate: a `Compromised` exact live process instance fails
/// closed before any browser/SSH policy is evaluated, so a compromised browser
/// cannot keep receiving Allow merely because its path/signature/BrowserId
/// still match. This function is only consulted for protected resources, so
/// the gate never affects unrelated processes.
pub fn evaluate(event: &AccessEvent, leases: &LeaseSet, now: u64) -> Decision {
    if event.process.integrity != ProcessIntegrity::Normal {
        return Decision::Deny(DenyReason::ProcessIntegrityCompromised);
    }
    match event.resource.kind {
        ProtectedResourceKind::SshPrivateKey => decide_ssh(event, leases, now),
        _ => decide_browser(event, leases, now),
    }
}

fn decide_browser(event: &AccessEvent, leases: &LeaseSet, now: u64) -> Decision {
    let res = &event.resource;
    let proc = &event.process;

    if proc.uid != res.owner_uid {
        return Decision::Deny(DenyReason::WrongUid);
    }

    let res_browser = res.browser_id();
    let res_profile = res.profile_id();

    // Own profile: a trusted browser reading its own resource.
    if proc.is_trusted_browser() && proc.browser.as_ref() == Some(res_browser) {
        return Decision::Allow;
    }

    // Cross-browser (or non-browser helper in the target's tree): require a
    // valid MigrationAccessLease. Armed leases never authorize directly: the
    // enforcement layer must first bind one to an exact process instance.

    let mut scope_match = false;
    for lease in &leases.migration {
        // Scope: source = owning browser/profile, target = opener's browser
        // (or the browser of an ancestor that matches the lease target), same uid.
        let in_scope = lease.source_browser == *res_browser
            && lease.source_profile == *res_profile
            && lease.uid == proc.uid;
        if !in_scope {
            continue;
        }
        scope_match = true;

        if lease.revoked {
            return Decision::Deny(DenyReason::LeaseRevoked);
        }
        if now >= lease.expires_at {
            return Decision::Deny(DenyReason::LeaseExpired);
        }
        match &lease.state {
            MigrationLeaseState::Armed { .. } => continue,
            MigrationLeaseState::Bound { root } if process_is_in_tree(proc, root) => {
                return Decision::AllowByLease(lease.id);
            }
            MigrationLeaseState::Bound { .. } => continue,
            MigrationLeaseState::Dead => return Decision::Deny(DenyReason::LeaseRevoked),
        }
    }

    // No matching lease. Distinguish the deny reason for audit clarity.
    if scope_match {
        Decision::Deny(DenyReason::IdentityMismatch)
    } else if proc.is_trusted_browser() {
        // A positively enrolled browser may ask a human to confirm an import.
        // Unknown processes and untrusted executable identities still fail
        // closed below; browser descendants are not candidates here.
        Decision::RequireMigrationConfirmation(MigrationCandidate {
            source_browser: res_browser.clone(),
            source_profile: res_profile.clone(),
            target_browser: proc.browser.clone().expect("trusted browser has BrowserId"),
        })
    } else if proc.browser.is_some() {
        Decision::Deny(DenyReason::NotTrustedIdentity)
    } else {
        Decision::Deny(DenyReason::UnknownProcess)
    }
}

fn process_is_in_tree(process: &ProcessIdentity, root: &ProcessStableId) -> bool {
    process.stable == *root
        || process
            .ancestors
            .iter()
            .any(|ancestor| ancestor_matches_root(ancestor, root))
}

fn ancestor_matches_root(ancestor: &AncestorSummary, root: &ProcessStableId) -> bool {
    ancestor.pid == root.pid
        && ancestor.start_time == root.start_time
        && ancestor.exe == root.exe
        && ancestor.exe_dev == root.exe_dev
        && ancestor.exe_ino == root.exe_ino
}

fn decide_ssh(event: &AccessEvent, leases: &LeaseSet, now: u64) -> Decision {
    let proc = &event.process;
    if proc.uid != event.resource.owner_uid {
        return Decision::Deny(DenyReason::WrongUid);
    }
    let proc_identity = proc.stable.stable_identity();

    for lease in &leases.ssh {
        let in_scope = lease.resource == event.resource.id && lease.uid == proc.uid;
        if !in_scope {
            continue;
        }
        if lease.target != proc_identity {
            continue;
        }
        if !lease.revoked && !lease.used && now < lease.expires_at {
            return Decision::AllowByLease(lease.id);
        }
    }
    for lease in &leases.ssh_read {
        if lease.resource == event.resource.id
            && lease.uid == proc.uid
            && !lease.revoked
            && now < lease.expires_at
            && process_is_in_tree(proc, &lease.root)
        {
            return Decision::AllowByLease(lease.id);
        }
    }
    Decision::RequireSshKeyConfirmation
}

#[cfg(test)]
mod tests {
    //! Table-driven tests for every baseline rule, lease expiration, wrong UID,
    //! wrong profile, wrong executable identity, and PID reuse.

    use super::*;
    use crate::identity::{
        AncestorSummary, ExeIdentity, ProcessIdentity, ProcessStableId, StableIdentity, TrustTier,
    };
    use crate::lease::{
        LeaseSet, MigrationAccessLease, MigrationLeaseState, SshLoadLease, SshReadAccessLease,
    };
    use crate::resource::{
        BrowserId, ProfileId, ProtectedResource, ProtectedResourceId, ProtectedResourceKind,
    };
    use std::path::PathBuf;

    const NOW: u64 = 1_000_000;
    const FUTURE: u64 = 1_000_000_000;

    fn stable(pid: u32, start: u64, exe: &str) -> ProcessStableId {
        ProcessStableId {
            pid,
            start_time: start,
            exe: PathBuf::from(exe),
            exe_dev: 100,
            exe_ino: 200,
        }
    }
    fn ident(start: u64, exe: &str) -> StableIdentity {
        StableIdentity {
            exe: PathBuf::from(exe),
            start_time: start,
            dev: 100,
            ino: 200,
        }
    }
    /// Armed exe identity (no start time) used by migration leases. `dev`/`ino`
    /// match the `stable()` helper so a process with the same exe path matches.
    fn exe_ident(exe: &str) -> ExeIdentity {
        ExeIdentity {
            exe: PathBuf::from(exe),
            dev: 100,
            ino: 200,
        }
    }
    fn ancestor(pid: u32, start: u64, exe: &str) -> AncestorSummary {
        AncestorSummary {
            pid,
            start_time: start,
            exe: PathBuf::from(exe),
            exe_dev: 100,
            exe_ino: 200,
        }
    }

    fn browser_resource(
        kind: ProtectedResourceKind,
        browser: &str,
        profile: &str,
        uid: u32,
    ) -> ProtectedResource {
        ProtectedResource {
            id: ProtectedResourceId(format!("{browser}/{profile}/{kind:?}")),
            kind,
            owner_uid: uid,
            browser: Some(BrowserId(browser.into())),
            profile: Some(ProfileId(profile.into())),
            path: PathBuf::from(format!("/tmp/{browser}/{profile}")),
        }
    }

    fn ssh_resource(uid: u32) -> ProtectedResource {
        ProtectedResource {
            id: ProtectedResourceId("ssh/id_ed25519".into()),
            kind: ProtectedResourceKind::SshPrivateKey,
            owner_uid: uid,
            browser: None,
            profile: None,
            path: PathBuf::from("/home/u/.ssh/id_ed25519"),
        }
    }

    fn browser_proc(
        browser: Option<&str>,
        tier: TrustTier,
        uid: u32,
        s: ProcessStableId,
    ) -> ProcessIdentity {
        ProcessIdentity {
            stable: s,
            uid,
            gid: uid,
            exe_owner_uid: 0,
            browser: browser.map(|b| BrowserId(b.into())),
            trust_tier: tier,
            cmdline: vec![],
            ancestors: vec![],
            integrity: ProcessIntegrity::Normal,
        }
    }

    fn compromised_proc(
        browser: Option<&str>,
        tier: TrustTier,
        uid: u32,
        s: ProcessStableId,
    ) -> ProcessIdentity {
        let mut process = browser_proc(browser, tier, uid, s);
        process.integrity = ProcessIntegrity::Compromised;
        process
    }

    fn event(res: ProtectedResource, proc: ProcessIdentity) -> AccessEvent {
        AccessEvent {
            resource: res,
            process: proc,
            operation: AccessOperation::Open,
        }
    }

    fn migration(
        id: u64,
        source_b: &str,
        source_p: &str,
        target_b: &str,
        uid: u32,
        target: ExeIdentity,
        expires_at: u64,
    ) -> MigrationAccessLease {
        MigrationAccessLease {
            id: LeaseId(id),
            source_browser: BrowserId(source_b.into()),
            source_profile: ProfileId(source_p.into()),
            target_browser: BrowserId(target_b.into()),
            uid,
            state: MigrationLeaseState::Bound {
                root: ProcessStableId {
                    pid: 2,
                    start_time: 200,
                    exe: target.exe,
                    exe_dev: target.dev,
                    exe_ino: target.ino,
                },
            },
            expires_at,
            revoked: false,
        }
    }

    fn ssh_lease(
        id: u64,
        res: &ProtectedResource,
        uid: u32,
        target: StableIdentity,
        expires_at: u64,
    ) -> SshLoadLease {
        SshLoadLease {
            id: LeaseId(id),
            resource: res.id.clone(),
            uid,
            target,
            expires_at,
            revoked: false,
            used: false,
        }
    }

    // --- baseline rules ---

    #[test]
    fn trusted_browser_own_profile_allowed() {
        let res = browser_resource(
            ProtectedResourceKind::CookieStore,
            "chrome",
            "Default",
            1000,
        );
        let proc = browser_proc(
            Some("chrome"),
            TrustTier::SystemPackage,
            1000,
            stable(1, 100, "/usr/bin/chrome"),
        );
        assert_eq!(
            evaluate(&event(res, proc), &LeaseSet::default(), NOW),
            Decision::Allow
        );
    }

    #[test]
    fn edge_to_chrome_requires_migration_confirmation() {
        let res = browser_resource(
            ProtectedResourceKind::CookieStore,
            "chrome",
            "Default",
            1000,
        );
        let proc = browser_proc(
            Some("firefox"),
            TrustTier::SystemPackage,
            1000,
            stable(2, 200, "/usr/bin/firefox"),
        );
        assert_eq!(
            evaluate(&event(res, proc), &LeaseSet::default(), NOW),
            Decision::RequireMigrationConfirmation(MigrationCandidate {
                source_browser: BrowserId("chrome".into()),
                source_profile: ProfileId("Default".into()),
                target_browser: BrowserId("firefox".into()),
            })
        );
    }

    #[test]
    fn recognized_cross_browser_pairs_require_confirmation() {
        for (source, target) in [
            ("chrome", "edge"),
            ("firefox", "zen"),
            ("chrome", "chromium"),
        ] {
            let res = browser_resource(ProtectedResourceKind::CookieStore, source, "Default", 1000);
            let proc = browser_proc(
                Some(target),
                TrustTier::SystemPackage,
                1000,
                stable(2, 200, &format!("/usr/bin/{target}")),
            );
            assert_eq!(
                evaluate(&event(res, proc), &LeaseSet::default(), NOW),
                Decision::RequireMigrationConfirmation(MigrationCandidate {
                    source_browser: BrowserId(source.into()),
                    source_profile: ProfileId("Default".into()),
                    target_browser: BrowserId(target.into()),
                }),
                "{target} -> {source} must ask rather than deny"
            );
        }
    }

    #[test]
    fn cross_browser_with_valid_lease_allowed_by_lease() {
        let res = browser_resource(
            ProtectedResourceKind::CookieStore,
            "chrome",
            "Default",
            1000,
        );
        let proc = browser_proc(
            Some("firefox"),
            TrustTier::SystemPackage,
            1000,
            stable(2, 200, "/usr/bin/firefox"),
        );
        let lease = migration(
            10,
            "chrome",
            "Default",
            "firefox",
            1000,
            exe_ident("/usr/bin/firefox"),
            FUTURE,
        );
        let ls = LeaseSet {
            migration: vec![lease],
            ssh: vec![],
            ssh_read: vec![],
        };
        assert_eq!(
            evaluate(&event(res, proc), &ls, NOW),
            Decision::AllowByLease(LeaseId(10))
        );
    }

    #[test]
    fn unknown_process_browser_denied() {
        let res = browser_resource(
            ProtectedResourceKind::SessionStore,
            "chrome",
            "Default",
            1000,
        );
        let proc = browser_proc(
            None,
            TrustTier::Unknown,
            1000,
            stable(3, 300, "/usr/bin/python3"),
        );
        assert_eq!(
            evaluate(&event(res, proc), &LeaseSet::default(), NOW),
            Decision::Deny(DenyReason::UnknownProcess)
        );
    }

    #[test]
    fn untrusted_browser_denied() {
        let res = browser_resource(
            ProtectedResourceKind::CookieStore,
            "chrome",
            "Default",
            1000,
        );
        // browser field set but trust tier Unknown (e.g. a renamed fake firefox)
        let proc = browser_proc(
            Some("chrome"),
            TrustTier::Unknown,
            1000,
            stable(4, 400, "/home/u/fakechrome"),
        );
        assert_eq!(
            evaluate(&event(res, proc), &LeaseSet::default(), NOW),
            Decision::Deny(DenyReason::NotTrustedIdentity)
        );
    }

    #[test]
    fn ssh_private_key_ordinary_process_requires_confirmation() {
        let res = ssh_resource(1000);
        let proc = browser_proc(
            None,
            TrustTier::Unknown,
            1000,
            stable(5, 500, "/usr/bin/cat"),
        );
        assert_eq!(
            evaluate(&event(res, proc), &LeaseSet::default(), NOW),
            Decision::RequireSshKeyConfirmation
        );
    }

    #[test]
    fn ssh_private_key_with_valid_lease_allowed_by_lease() {
        let res = ssh_resource(1000);
        let proc = browser_proc(
            None,
            TrustTier::EnrolledUserWritable,
            1000,
            stable(6, 600, "/usr/bin/ssh-add"),
        );
        let lease = ssh_lease(20, &res, 1000, ident(600, "/usr/bin/ssh-add"), FUTURE);
        let ls = LeaseSet {
            migration: vec![],
            ssh: vec![lease],
            ssh_read: vec![],
        };
        assert_eq!(
            evaluate(&event(res, proc), &ls, NOW),
            Decision::AllowByLease(LeaseId(20))
        );
    }

    #[test]
    fn ssh_read_lease_is_bound_to_one_key_uid_and_process_tree() {
        let res = ssh_resource(1000);
        let root = stable(71, 710, "/usr/bin/git");
        let lease = SshReadAccessLease {
            id: LeaseId(71),
            resource: res.id.clone(),
            uid: 1000,
            root: root.clone(),
            expires_at: FUTURE,
            revoked: false,
        };
        let allowed = browser_proc(None, TrustTier::Unknown, 1000, root.clone());
        let wrong_uid = browser_proc(None, TrustTier::Unknown, 1001, root.clone());
        let wrong_process = browser_proc(
            None,
            TrustTier::Unknown,
            1000,
            stable(72, 720, "/usr/bin/git"),
        );
        let mut wrong_key = res.clone();
        wrong_key.id = ProtectedResourceId("ssh/other-key".into());
        let leases = LeaseSet {
            migration: vec![],
            ssh: vec![],
            ssh_read: vec![lease],
        };
        assert_eq!(
            evaluate(&event(res.clone(), allowed.clone()), &leases, NOW),
            Decision::AllowByLease(LeaseId(71))
        );
        assert_eq!(
            evaluate(&event(res.clone(), wrong_uid), &leases, NOW),
            Decision::Deny(DenyReason::WrongUid)
        );
        assert_eq!(
            evaluate(&event(res, wrong_process), &leases, NOW),
            Decision::RequireSshKeyConfirmation
        );
        assert_eq!(
            evaluate(&event(wrong_key, allowed), &leases, NOW),
            Decision::RequireSshKeyConfirmation
        );
    }

    // --- lease expiration / revocation / one-shot ---

    #[test]
    fn expired_migration_lease_denied() {
        let res = browser_resource(
            ProtectedResourceKind::CookieStore,
            "chrome",
            "Default",
            1000,
        );
        let proc = browser_proc(
            Some("firefox"),
            TrustTier::SystemPackage,
            1000,
            stable(2, 200, "/usr/bin/firefox"),
        );
        let lease = migration(
            10,
            "chrome",
            "Default",
            "firefox",
            1000,
            exe_ident("/usr/bin/firefox"),
            500, /* past */
        );
        let ls = LeaseSet {
            migration: vec![lease],
            ssh: vec![],
            ssh_read: vec![],
        };
        assert_eq!(
            evaluate(&event(res, proc), &ls, NOW),
            Decision::Deny(DenyReason::LeaseExpired)
        );
    }

    #[test]
    fn revoked_migration_lease_denied() {
        let res = browser_resource(
            ProtectedResourceKind::CookieStore,
            "chrome",
            "Default",
            1000,
        );
        let proc = browser_proc(
            Some("firefox"),
            TrustTier::SystemPackage,
            1000,
            stable(2, 200, "/usr/bin/firefox"),
        );
        let mut lease = migration(
            10,
            "chrome",
            "Default",
            "firefox",
            1000,
            exe_ident("/usr/bin/firefox"),
            FUTURE,
        );
        lease.revoked = true;
        let ls = LeaseSet {
            migration: vec![lease],
            ssh: vec![],
            ssh_read: vec![],
        };
        assert_eq!(
            evaluate(&event(res, proc), &ls, NOW),
            Decision::Deny(DenyReason::LeaseRevoked)
        );
    }

    #[test]
    fn used_ssh_load_lease_requires_confirmation_again() {
        let res = ssh_resource(1000);
        let proc = browser_proc(
            None,
            TrustTier::EnrolledUserWritable,
            1000,
            stable(6, 600, "/usr/bin/ssh-add"),
        );
        let mut lease = ssh_lease(20, &res, 1000, ident(600, "/usr/bin/ssh-add"), FUTURE);
        lease.used = true;
        let ls = LeaseSet {
            migration: vec![],
            ssh: vec![lease],
            ssh_read: vec![],
        };
        assert_eq!(
            evaluate(&event(res, proc), &ls, NOW),
            Decision::RequireSshKeyConfirmation
        );
    }

    // --- wrong UID / wrong profile ---

    #[test]
    fn wrong_uid_denied() {
        let res = browser_resource(
            ProtectedResourceKind::CookieStore,
            "chrome",
            "Default",
            1000,
        );
        // a chrome process but running as a different user
        let proc = browser_proc(
            Some("chrome"),
            TrustTier::SystemPackage,
            1001,
            stable(1, 100, "/usr/bin/chrome"),
        );
        assert_eq!(
            evaluate(&event(res, proc), &LeaseSet::default(), NOW),
            Decision::Deny(DenyReason::WrongUid)
        );
    }

    #[test]
    fn wrong_profile_lease_does_not_apply() {
        // lease authorizes reading chrome/Profile1, but the access targets chrome/Default
        let res = browser_resource(
            ProtectedResourceKind::CookieStore,
            "chrome",
            "Default",
            1000,
        );
        let proc = browser_proc(
            Some("firefox"),
            TrustTier::SystemPackage,
            1000,
            stable(2, 200, "/usr/bin/firefox"),
        );
        let lease = migration(
            10,
            "chrome",
            "Profile1",
            "firefox",
            1000,
            exe_ident("/usr/bin/firefox"),
            FUTURE,
        );
        let ls = LeaseSet {
            migration: vec![lease],
            ssh: vec![],
            ssh_read: vec![],
        };
        assert_eq!(
            evaluate(&event(res, proc), &ls, NOW),
            Decision::RequireMigrationConfirmation(MigrationCandidate {
                source_browser: BrowserId("chrome".into()),
                source_profile: ProfileId("Default".into()),
                target_browser: BrowserId("firefox".into()),
            })
        );
    }

    // --- wrong executable identity / PID reuse ---

    #[test]
    fn migration_lease_bound_to_different_exe_denied() {
        let res = browser_resource(
            ProtectedResourceKind::CookieStore,
            "chrome",
            "Default",
            1000,
        );
        // lease bound to /usr/bin/firefox, but opener's exe is /home/u/fakefox
        let proc = browser_proc(
            Some("firefox"),
            TrustTier::SystemPackage,
            1000,
            stable(2, 200, "/home/u/fakefox"),
        );
        let lease = migration(
            10,
            "chrome",
            "Default",
            "firefox",
            1000,
            exe_ident("/usr/bin/firefox"),
            FUTURE,
        );
        let ls = LeaseSet {
            migration: vec![lease],
            ssh: vec![],
            ssh_read: vec![],
        };
        assert_eq!(
            evaluate(&event(res, proc), &ls, NOW),
            Decision::Deny(DenyReason::IdentityMismatch)
        );
    }

    #[test]
    fn pid_reuse_does_not_receive_lease_and_requires_confirmation() {
        let res = ssh_resource(1000);
        // lease bound to start_time 600; process has same PID 6 but start_time 9999 (reused)
        let proc = browser_proc(
            None,
            TrustTier::EnrolledUserWritable,
            1000,
            stable(6, 9999, "/usr/bin/ssh-add"),
        );
        let lease = ssh_lease(20, &res, 1000, ident(600, "/usr/bin/ssh-add"), FUTURE);
        let ls = LeaseSet {
            migration: vec![],
            ssh: vec![lease],
            ssh_read: vec![],
        };
        assert_eq!(
            evaluate(&event(res, proc), &ls, NOW),
            Decision::RequireSshKeyConfirmation
        );
    }

    #[test]
    fn ssh_lease_wrong_uid_is_denied() {
        let res = ssh_resource(1000);
        let proc = browser_proc(
            None,
            TrustTier::EnrolledUserWritable,
            1001,
            stable(6, 600, "/usr/bin/ssh-add"),
        );
        let lease = ssh_lease(20, &res, 1000, ident(600, "/usr/bin/ssh-add"), FUTURE);
        let ls = LeaseSet {
            migration: vec![],
            ssh: vec![lease],
            ssh_read: vec![],
        };
        assert_eq!(
            evaluate(&event(res, proc), &ls, NOW),
            Decision::Deny(DenyReason::WrongUid)
        );
    }

    // --- process-tree scoping ---

    fn proc_with_ancestors(
        browser: Option<&str>,
        tier: TrustTier,
        uid: u32,
        s: ProcessStableId,
        ancestors: Vec<AncestorSummary>,
    ) -> ProcessIdentity {
        ProcessIdentity {
            stable: s,
            uid,
            gid: uid,
            exe_owner_uid: 0,
            browser: browser.map(|b| BrowserId(b.into())),
            trust_tier: tier,
            cmdline: vec![],
            ancestors,
            integrity: ProcessIntegrity::Normal,
        }
    }

    #[test]
    fn armed_migration_lease_does_not_authorize_directly() {
        let res = browser_resource(
            ProtectedResourceKind::CookieStore,
            "chrome",
            "Default",
            1000,
        );
        let proc = browser_proc(
            Some("firefox"),
            TrustTier::SystemPackage,
            1000,
            stable(2, 200, "/usr/bin/firefox"),
        );
        let mut lease = migration(
            10,
            "chrome",
            "Default",
            "firefox",
            1000,
            exe_ident("/usr/bin/firefox"),
            FUTURE,
        );
        lease.state = MigrationLeaseState::Armed {
            target: exe_ident("/usr/bin/firefox"),
        };
        let ls = LeaseSet {
            migration: vec![lease],
            ssh: vec![],
            ssh_read: vec![],
        };
        assert_eq!(
            evaluate(&event(res, proc), &ls, NOW),
            Decision::Deny(DenyReason::IdentityMismatch),
            "only the enforcement layer may bind an armed lease"
        );
    }

    #[test]
    fn migration_lease_allows_target_tree_helper_via_ancestor() {
        // A firefox helper/child process (browser=None, own exe differs) opens
        // chrome cookies. It is allowed because an ancestor is the bound target
        // browser (process-tree scoping).
        let res = browser_resource(
            ProtectedResourceKind::CookieStore,
            "chrome",
            "Default",
            1000,
        );
        let proc = proc_with_ancestors(
            None,
            TrustTier::SystemPackage,
            1000,
            stable(3, 300, "/usr/lib/firefox/helper"),
            vec![ancestor(2, 200, "/usr/bin/firefox")],
        );
        let lease = migration(
            11,
            "chrome",
            "Default",
            "firefox",
            1000,
            exe_ident("/usr/bin/firefox"),
            FUTURE,
        );
        let ls = LeaseSet {
            migration: vec![lease],
            ssh: vec![],
            ssh_read: vec![],
        };
        assert_eq!(
            evaluate(&event(res, proc), &ls, NOW),
            Decision::AllowByLease(LeaseId(11)),
            "target-tree helper with matching ancestor must be allowed"
        );
    }

    #[test]
    fn migration_lease_denies_unrelated_helper_outside_tree() {
        // A helper whose ancestor is NOT the bound target browser is denied,
        // even though a lease exists for the source profile + uid. The scope
        // matches (source/uid) but no identity (opener or ancestor) matches.
        let res = browser_resource(
            ProtectedResourceKind::CookieStore,
            "chrome",
            "Default",
            1000,
        );
        let proc = proc_with_ancestors(
            None,
            TrustTier::SystemPackage,
            1000,
            stable(4, 400, "/usr/bin/some-helper"),
            vec![ancestor(5, 500, "/usr/bin/unrelated")],
        );
        let lease = migration(
            11,
            "chrome",
            "Default",
            "firefox",
            1000,
            exe_ident("/usr/bin/firefox"),
            FUTURE,
        );
        let ls = LeaseSet {
            migration: vec![lease],
            ssh: vec![],
            ssh_read: vec![],
        };
        assert_eq!(
            evaluate(&event(res, proc), &ls, NOW),
            Decision::Deny(DenyReason::IdentityMismatch),
            "helper outside the bound target tree must be denied"
        );
    }

    #[test]
    fn migration_lease_does_not_grant_other_profile() {
        // Lease authorizes chrome/Default; opener reads chrome/Profile1 under
        // the same target identity. Must be denied (no scope match).
        let res = browser_resource(
            ProtectedResourceKind::CookieStore,
            "chrome",
            "Profile1",
            1000,
        );
        let proc = browser_proc(
            Some("firefox"),
            TrustTier::SystemPackage,
            1000,
            stable(2, 200, "/usr/bin/firefox"),
        );
        let lease = migration(
            12,
            "chrome",
            "Default",
            "firefox",
            1000,
            exe_ident("/usr/bin/firefox"),
            FUTURE,
        );
        let ls = LeaseSet {
            migration: vec![lease],
            ssh: vec![],
            ssh_read: vec![],
        };
        assert_eq!(
            evaluate(&event(res, proc), &ls, NOW),
            Decision::RequireMigrationConfirmation(MigrationCandidate {
                source_browser: BrowserId("chrome".into()),
                source_profile: ProfileId("Profile1".into()),
                target_browser: BrowserId("firefox".into()),
            })
        );
    }

    // --- criticality classification sanity ---

    #[test]
    fn kind_classification_helpers() {
        assert!(ProtectedResourceKind::CookieStore.is_browser());
        assert!(ProtectedResourceKind::CookieStore.is_critical_browser());
        assert!(!ProtectedResourceKind::History.is_critical_browser());
        assert!(ProtectedResourceKind::SshPrivateKey.is_ssh());
        assert!(!ProtectedResourceKind::SshPrivateKey.is_browser());
    }

    // --- Phase 12: stable reason codes ---

    #[test]
    fn reason_codes_are_stable_snake_case() {
        // These strings are a public contract for tools (`guardctl explain
        // --json`). They must be stable, snake_case, and match the spec
        // examples: browser_protected_resource, migration_lease_required,
        // and identity_untrusted.
        assert_eq!(
            DenyReason::UnknownProcess.reason_code(),
            "browser_protected_resource"
        );
        assert_eq!(
            DenyReason::NotTrustedIdentity.reason_code(),
            "identity_untrusted"
        );
        assert_eq!(
            DenyReason::CrossBrowserWithoutLease.reason_code(),
            "migration_lease_required"
        );
        assert_eq!(
            DenyReason::SshApprovalRequired.reason_code(),
            "ssh_read_approval_required"
        );
        assert_eq!(DenyReason::LeaseExpired.reason_code(), "lease_expired");
        assert_eq!(DenyReason::LeaseRevoked.reason_code(), "lease_revoked");
        assert_eq!(
            DenyReason::LeaseScopeMismatch.reason_code(),
            "lease_scope_mismatch"
        );
        assert_eq!(DenyReason::WrongUid.reason_code(), "wrong_uid");
        assert_eq!(
            DenyReason::IdentityMismatch.reason_code(),
            "identity_mismatch"
        );
        assert_eq!(
            DenyReason::OneShotLeaseUsed.reason_code(),
            "one_shot_lease_used"
        );
        assert_eq!(
            DenyReason::ProcessIntegrityCompromised.reason_code(),
            "process_integrity_compromised"
        );
    }

    #[test]
    fn reason_codes_are_unique() {
        // No two deny reasons may share a code (tools branch on these).
        let codes: Vec<&str> = [
            DenyReason::UnknownProcess,
            DenyReason::NotTrustedIdentity,
            DenyReason::CrossBrowserWithoutLease,
            DenyReason::SshApprovalRequired,
            DenyReason::LeaseExpired,
            DenyReason::LeaseRevoked,
            DenyReason::LeaseScopeMismatch,
            DenyReason::WrongUid,
            DenyReason::IdentityMismatch,
            DenyReason::OneShotLeaseUsed,
            DenyReason::ProcessIntegrityCompromised,
        ]
        .iter()
        .map(|r| r.reason_code())
        .collect();
        let unique: std::collections::HashSet<&str> = codes.iter().copied().collect();
        assert_eq!(codes.len(), unique.len(), "duplicate reason codes detected");
    }

    // --- MPS0: Process Shield integrity gate ---

    #[test]
    fn compromised_browser_own_profile_is_denied() {
        // A Compromised exact live instance must not receive Allow even though
        // path, signature and BrowserId still match its own profile.
        let res = browser_resource(
            ProtectedResourceKind::CookieStore,
            "chrome",
            "Default",
            1000,
        );
        let proc = compromised_proc(
            Some("chrome"),
            TrustTier::SystemPackage,
            1000,
            stable(1, 100, "/usr/bin/chrome"),
        );
        assert_eq!(
            evaluate(&event(res, proc), &LeaseSet::default(), NOW),
            Decision::Deny(DenyReason::ProcessIntegrityCompromised)
        );
    }

    #[test]
    fn compromised_process_denied_before_any_browser_or_ssh_policy() {
        // Table-driven: every existing decision category must fail closed to
        // process_integrity_compromised before the browser/SSH policy branch
        // can grant anything.
        let cases = [
            // (resource kind, browser role, trust tier, operation)
            (
                ProtectedResourceKind::CookieStore,
                Some("chrome"),
                TrustTier::SystemPackage,
            ),
            (
                ProtectedResourceKind::SessionStore,
                None,
                TrustTier::Unknown,
            ),
            (
                ProtectedResourceKind::SshPrivateKey,
                None,
                TrustTier::Unknown,
            ),
        ];
        for (kind, browser, tier) in cases {
            let res = if kind == ProtectedResourceKind::SshPrivateKey {
                ssh_resource(1000)
            } else {
                browser_resource(kind, "chrome", "Default", 1000)
            };
            let proc = compromised_proc(browser, tier, 1000, stable(9, 900, "/usr/bin/proc"));
            assert_eq!(
                evaluate(&event(res, proc), &LeaseSet::default(), NOW),
                Decision::Deny(DenyReason::ProcessIntegrityCompromised),
                "{kind:?} must fail closed for a compromised instance"
            );
        }
    }

    #[test]
    fn compromised_process_denied_even_with_valid_leases() {
        // Valid migration and SSH-read leases must not re-grant authority to a
        // confirmed compromised instance.
        let cookie_res = browser_resource(
            ProtectedResourceKind::CookieStore,
            "chrome",
            "Default",
            1000,
        );
        let compromised_firefox = compromised_proc(
            Some("firefox"),
            TrustTier::SystemPackage,
            1000,
            stable(2, 200, "/usr/bin/firefox"),
        );
        let migration_lease = migration(
            30,
            "chrome",
            "Default",
            "firefox",
            1000,
            exe_ident("/usr/bin/firefox"),
            FUTURE,
        );
        let ls_with_migration = LeaseSet {
            migration: vec![migration_lease],
            ssh: vec![],
            ssh_read: vec![],
        };
        assert_eq!(
            evaluate(
                &event(cookie_res, compromised_firefox),
                &ls_with_migration,
                NOW
            ),
            Decision::Deny(DenyReason::ProcessIntegrityCompromised),
            "a migration lease must not rescue a compromised instance"
        );

        let ssh_res = ssh_resource(1000);
        let compromised_ssh = compromised_proc(
            None,
            TrustTier::EnrolledUserWritable,
            1000,
            stable(6, 600, "/usr/bin/ssh-add"),
        );
        let ssh_lease = ssh_lease(40, &ssh_res, 1000, ident(600, "/usr/bin/ssh-add"), FUTURE);
        let ls_with_ssh = LeaseSet {
            migration: vec![],
            ssh: vec![ssh_lease],
            ssh_read: vec![],
        };
        assert_eq!(
            evaluate(&event(ssh_res, compromised_ssh), &ls_with_ssh, NOW),
            Decision::Deny(DenyReason::ProcessIntegrityCompromised),
            "an SSH lease must not rescue a compromised instance"
        );
    }

    #[test]
    fn pid_reuse_new_normal_instance_is_not_contaminated() {
        // Same PID, different start time = a new stable instance. The old
        // instance is Compromised; the new one must be evaluated normally.
        let res = browser_resource(
            ProtectedResourceKind::CookieStore,
            "chrome",
            "Default",
            1000,
        );
        let old_instance = compromised_proc(
            Some("chrome"),
            TrustTier::SystemPackage,
            1000,
            stable(1, 100, "/usr/bin/chrome"),
        );
        let new_instance = browser_proc(
            Some("chrome"),
            TrustTier::SystemPackage,
            1000,
            stable(1, 9999, "/usr/bin/chrome"),
        );
        assert_eq!(
            evaluate(&event(res.clone(), old_instance), &LeaseSet::default(), NOW),
            Decision::Deny(DenyReason::ProcessIntegrityCompromised)
        );
        assert_eq!(
            evaluate(&event(res, new_instance), &LeaseSet::default(), NOW),
            Decision::Allow,
            "PID reuse must not inherit compromise from the previous instance"
        );
    }

    #[test]
    fn normal_processes_keep_existing_decisions() {
        // Regression table: adding the integrity gate must not change any
        // existing decision for Normal processes.
        let cookie = browser_resource(
            ProtectedResourceKind::CookieStore,
            "chrome",
            "Default",
            1000,
        );
        let ssh = ssh_resource(1000);
        let trusted = browser_proc(
            Some("chrome"),
            TrustTier::SystemPackage,
            1000,
            stable(1, 100, "/usr/bin/chrome"),
        );
        let importer = browser_proc(
            Some("firefox"),
            TrustTier::SystemPackage,
            1000,
            stable(2, 200, "/usr/bin/firefox"),
        );
        let unknown = browser_proc(
            None,
            TrustTier::Unknown,
            1000,
            stable(3, 300, "/usr/bin/python3"),
        );
        let cat = browser_proc(
            None,
            TrustTier::Unknown,
            1000,
            stable(5, 500, "/usr/bin/cat"),
        );
        assert_eq!(
            evaluate(&event(cookie.clone(), trusted), &LeaseSet::default(), NOW),
            Decision::Allow
        );
        assert_eq!(
            evaluate(&event(cookie, importer), &LeaseSet::default(), NOW),
            Decision::RequireMigrationConfirmation(MigrationCandidate {
                source_browser: BrowserId("chrome".into()),
                source_profile: ProfileId("Default".into()),
                target_browser: BrowserId("firefox".into()),
            })
        );
        assert_eq!(
            evaluate(&event(ssh.clone(), cat), &LeaseSet::default(), NOW),
            Decision::RequireSshKeyConfirmation
        );
        // A browser field with an Unknown trust tier is still NotTrustedIdentity
        // for Normal processes.
        let fake = browser_proc(
            Some("chrome"),
            TrustTier::Unknown,
            1000,
            stable(4, 400, "/home/u/fakechrome"),
        );
        assert_eq!(
            evaluate(&event(ssh, unknown.clone()), &LeaseSet::default(), NOW),
            Decision::RequireSshKeyConfirmation
        );
        let cookie2 = browser_resource(
            ProtectedResourceKind::CookieStore,
            "chrome",
            "Default",
            1000,
        );
        assert_eq!(
            evaluate(&event(cookie2, fake), &LeaseSet::default(), NOW),
            Decision::Deny(DenyReason::NotTrustedIdentity)
        );
    }

    #[test]
    fn kind_codes_are_stable_snake_case() {
        assert_eq!(
            ProtectedResourceKind::CookieStore.kind_code(),
            "browser_cookie_store"
        );
        assert_eq!(
            ProtectedResourceKind::SessionStore.kind_code(),
            "browser_session_store"
        );
        assert_eq!(
            ProtectedResourceKind::BrowserKeyMaterial.kind_code(),
            "browser_key_material"
        );
        assert_eq!(
            ProtectedResourceKind::WebStorage.kind_code(),
            "browser_web_storage"
        );
        assert_eq!(
            ProtectedResourceKind::SavedCredentials.kind_code(),
            "browser_saved_credentials"
        );
        assert_eq!(
            ProtectedResourceKind::History.kind_code(),
            "browser_history"
        );
        assert_eq!(
            ProtectedResourceKind::SshPrivateKey.kind_code(),
            "ssh_private_key"
        );
        assert_eq!(ProtectedResourceKind::Other.kind_code(), "other");
    }
}
