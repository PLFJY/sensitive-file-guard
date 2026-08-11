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
//! - SSH private-key reads => Allow; an exact valid `SshLoadLease` is reported
//!   as `AllowByLease` for the hardened optional ssh-agent load path
//! - expired / revoked / used SSH lease => ordinary `Allow`, never read denial
//! - cross-user browser access => Deny; SSH reads remain allowed
//! - PID reuse / SSH stable-identity mismatch => lease does not apply, then Allow

use serde::{Deserialize, Serialize};

use crate::identity::{AncestorSummary, ProcessIdentity, ProcessStableId};
use crate::lease::{LeaseId, LeaseSet, MigrationLeaseState};
use crate::resource::{ProtectedResource, ProtectedResourceKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Allow,
    Deny(DenyReason),
    AllowByLease(LeaseId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenyReason {
    UnknownProcess,
    NotTrustedIdentity,
    CrossBrowserWithoutLease,
    LeaseExpired,
    LeaseRevoked,
    LeaseScopeMismatch,
    WrongUid,
    IdentityMismatch,
    OneShotLeaseUsed,
    /// An actual outbound send was blocked after a protected SSH-key read.
    /// This does not assert anything about the payload's provenance.
    SshBehaviorNetworkBlocked,
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
            Self::SshBehaviorNetworkBlocked => "ssh_behavior_network_blocked",
        }
    }
}

/// The intercepted operation. `Open` is the primary fanotify gate (read opens);
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
pub fn evaluate(event: &AccessEvent, leases: &LeaseSet, now: u64) -> Decision {
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
        // Trusted browser, wrong profile, no covering lease.
        Decision::Deny(DenyReason::CrossBrowserWithoutLease)
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
    // Phase 22.2 product contract: the filesystem read is never the blocked
    // operation. Linux may arm short-lived process-tree network observation,
    // but backend failure cannot turn this decision into a denial.
    Decision::Allow
}

#[cfg(test)]
mod tests {
    //! Table-driven tests for every baseline rule, lease expiration, wrong UID,
    //! wrong profile, wrong executable identity, and PID reuse.

    use super::*;
    use crate::identity::{
        AncestorSummary, ExeIdentity, ProcessIdentity, ProcessStableId, StableIdentity, TrustTier,
    };
    use crate::lease::{LeaseSet, MigrationAccessLease, MigrationLeaseState, SshLoadLease};
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
        }
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
    fn cross_browser_without_lease_denied() {
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
            Decision::Deny(DenyReason::CrossBrowserWithoutLease)
        );
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
    fn ssh_private_key_ordinary_process_allowed() {
        let res = ssh_resource(1000);
        let proc = browser_proc(
            None,
            TrustTier::Unknown,
            1000,
            stable(5, 500, "/usr/bin/cat"),
        );
        assert_eq!(
            evaluate(&event(res, proc), &LeaseSet::default(), NOW),
            Decision::Allow
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
        };
        assert_eq!(
            evaluate(&event(res, proc), &ls, NOW),
            Decision::AllowByLease(LeaseId(20))
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
        };
        assert_eq!(
            evaluate(&event(res, proc), &ls, NOW),
            Decision::Deny(DenyReason::LeaseRevoked)
        );
    }

    #[test]
    fn used_ssh_lease_falls_back_to_raw_read_allow() {
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
        };
        assert_eq!(evaluate(&event(res, proc), &ls, NOW), Decision::Allow);
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
        };
        assert_eq!(
            evaluate(&event(res, proc), &ls, NOW),
            Decision::Deny(DenyReason::CrossBrowserWithoutLease)
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
        };
        assert_eq!(
            evaluate(&event(res, proc), &ls, NOW),
            Decision::Deny(DenyReason::IdentityMismatch)
        );
    }

    #[test]
    fn pid_reuse_does_not_receive_lease_but_read_is_allowed() {
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
        };
        assert_eq!(evaluate(&event(res, proc), &ls, NOW), Decision::Allow);
    }

    #[test]
    fn ssh_lease_wrong_uid_does_not_apply() {
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
        };
        assert_eq!(evaluate(&event(res, proc), &ls, NOW), Decision::Allow);
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
        };
        assert_eq!(
            evaluate(&event(res, proc), &ls, NOW),
            Decision::Deny(DenyReason::CrossBrowserWithoutLease)
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
    }

    #[test]
    fn reason_codes_are_unique() {
        // No two deny reasons may share a code (tools branch on these).
        let codes: Vec<&str> = [
            DenyReason::UnknownProcess,
            DenyReason::NotTrustedIdentity,
            DenyReason::CrossBrowserWithoutLease,
            DenyReason::LeaseExpired,
            DenyReason::LeaseRevoked,
            DenyReason::LeaseScopeMismatch,
            DenyReason::WrongUid,
            DenyReason::IdentityMismatch,
            DenyReason::OneShotLeaseUsed,
            DenyReason::SshBehaviorNetworkBlocked,
        ]
        .iter()
        .map(|r| r.reason_code())
        .collect();
        let unique: std::collections::HashSet<&str> = codes.iter().copied().collect();
        assert_eq!(codes.len(), unique.len(), "duplicate reason codes detected");
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
    }
}
