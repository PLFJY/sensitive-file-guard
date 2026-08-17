//! BrowserSession runtime model (MCH3).
//!
//! Represents processes belonging to ONE legitimate running browser session.
//! Membership is derived ONLY from verified runtime relationships:
//!
//! - the session root is an enrolled browser Main executable whose launch was
//!   observed via AUTH_EXEC outside any browser session (launched by the user /
//!   launchd / shell, not by another browser process);
//! - every other member joined via a verified parent relationship: its AUTH_EXEC
//!   was observed and its exact parent instance is already a session member.
//!
//! Never accepted as authority on their own: same UID, same Team ID, same
//! signing ID, same basename or matching argv. A genuine browser signature is
//! NOT a capability token: an attacker manually launching a signed browser
//! Helper gets NO session membership (signed-helper laundering rejection) and
//! therefore no browser-internal relationship anywhere.
//!
//! BrowserIdentity != BrowserSession: this tracker only models launch
//! topology; it grants no task authority by itself.

use std::collections::HashMap;

use crate::browser_trust::BrowserExecutableRole;
use crate::identity::{AuditProcessKey, MacProcessFacts};

/// Stable identifier of one running browser session (monotonic within a
/// tracker lifetime; never reused after dissolution).
pub type SessionId = u64;

/// Why a browser executable instance was NOT admitted into a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionKind {
    /// The parent is provably NOT part of any browser session (a non-browser
    /// attacker process, or a browser process in a DIFFERENT verified
    /// session). The instance is externally launched: it must never become a
    /// session member or browser-internal relationship.
    ExternalLaunch,
    /// The parent relationship cannot be verified (missing parent facts, or a
    /// warm-start browser parent whose own launch was never observed). The
    /// instance is BrowserIdentity only, with no session membership, until
    /// verifiable.
    Unverifiable,
}

/// Outcome of observing one browser AUTH_EXEC against session topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionMembership {
    /// An enrolled Main process launched outside any browser session: this
    /// instance is the new session root.
    NewRoot(SessionId),
    /// The instance joined an existing session through a verified parent
    /// relationship.
    Joined(SessionId),
    /// BrowserIdentity only; NOT a session member (signed-helper laundering
    /// and other rejected launches).
    Rejected(RejectionKind),
}

impl SessionMembership {
    pub fn session_id(&self) -> Option<SessionId> {
        match self {
            Self::NewRoot(id) | Self::Joined(id) => Some(*id),
            Self::Rejected(_) => None,
        }
    }

    /// True when this is a provably external (attacker-launched) instance.
    pub fn is_external(&self) -> bool {
        matches!(self, Self::Rejected(RejectionKind::ExternalLaunch))
    }

    /// Machine-readable audit label (metadata only).
    pub fn label(&self) -> &'static str {
        match self {
            Self::NewRoot(_) => "new_root",
            Self::Joined(_) => "joined",
            Self::Rejected(RejectionKind::ExternalLaunch) => "rejected_external",
            Self::Rejected(RejectionKind::Unverifiable) => "rejected_unverifiable",
        }
    }
}

/// One legitimate running browser session: the Main root plus the exact live
/// instances verified to descend from it.
#[derive(Debug)]
struct BrowserSession {
    root: AuditProcessKey,
    members: HashMap<AuditProcessKey, MacProcessFacts>,
}

/// Relation between a requester and a target for notify-signal interpretation
/// (MCH3). This is CONTEXT for interpreting notify-only signals; it never
/// grants task authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalRelation {
    /// Both are verified members of the same session: browser-internal.
    SameSession,
    /// Both are verified session members of DIFFERENT sessions (unrelated
    /// browser processes).
    DifferentSession,
    /// The requester was provably rejected as externally launched (it is not
    /// part of any browser session).
    RequesterExternal,
    /// Membership cannot be verified for one side (warm start / sequence gap /
    /// unadmitted target). The caller decides with a fallback heuristic and
    /// should report health Reduced (authority classification incomplete).
    Unverifiable,
}

/// Live session topology for all browser processes this shield has observed.
#[derive(Debug, Default)]
pub struct BrowserSessionTracker {
    sessions: HashMap<SessionId, BrowserSession>,
    key_to_session: HashMap<AuditProcessKey, SessionId>,
    current_by_pid: HashMap<u32, AuditProcessKey>,
    external_by_key: HashMap<AuditProcessKey, ()>,
    next_id: SessionId,
    roots: u64,
    joins: u64,
    rejected: u64,
}

impl BrowserSessionTracker {
    /// Observe one browser AUTH_EXEC and classify its membership.
    ///
    /// `role` is the enrolled role (Main / Helper / None for user-enrolled
    /// ExplicitHash). `parent` is the stable key of the verified parent
    /// instance (None when parent facts are unavailable);
    /// `parent_is_enrolled_browser` says whether that parent is an enrolled
    /// browser executable.
    pub fn observe_exec(
        &mut self,
        facts: &MacProcessFacts,
        role: Option<BrowserExecutableRole>,
        parent: Option<AuditProcessKey>,
        parent_is_enrolled_browser: bool,
    ) -> SessionMembership {
        // PID reuse: a stale mapping for the same PID from a different
        // instance must never leak membership into the new instance.
        if let Some(previous) = self.current_by_pid.get(&facts.key.pid) {
            if *previous != facts.key {
                self.remove_membership(*previous);
            }
        }
        let parent_session = parent.and_then(|key| self.key_to_session.get(&key).copied());
        let membership = match role {
            Some(BrowserExecutableRole::Main) => match parent_session {
                Some(sid) => SessionMembership::Joined(sid),
                None => {
                    let sid = self.next_id;
                    self.next_id = self.next_id.saturating_add(1);
                    self.sessions.insert(
                        sid,
                        BrowserSession {
                            root: facts.key,
                            members: HashMap::new(),
                        },
                    );
                    SessionMembership::NewRoot(sid)
                }
            },
            // Helpers (and role-less ExplicitHash enrollments) can never root a
            // session: without a verified parent member there is no session.
            Some(BrowserExecutableRole::Helper) | None => match parent_session {
                Some(sid) => SessionMembership::Joined(sid),
                None => {
                    let rejection = if parent.is_some() && !parent_is_enrolled_browser {
                        RejectionKind::ExternalLaunch
                    } else {
                        RejectionKind::Unverifiable
                    };
                    SessionMembership::Rejected(rejection)
                }
            },
        };
        match membership {
            SessionMembership::NewRoot(sid) => {
                self.attach(facts, sid, true);
                self.roots = self.roots.saturating_add(1);
            }
            SessionMembership::Joined(sid) => {
                self.attach(facts, sid, false);
                self.joins = self.joins.saturating_add(1);
            }
            SessionMembership::Rejected(RejectionKind::ExternalLaunch) => {
                self.external_by_key.insert(facts.key, ());
                self.current_by_pid.insert(facts.key.pid, facts.key);
                self.rejected = self.rejected.saturating_add(1);
            }
            SessionMembership::Rejected(RejectionKind::Unverifiable) => {
                self.rejected = self.rejected.saturating_add(1);
            }
        }
        membership
    }

    /// NOTIFY_EXIT cleanup for an exact instance.
    pub fn observe_exit(&mut self, key: &AuditProcessKey) {
        self.remove_membership(*key);
        if self.current_by_pid.get(&key.pid) == Some(key) {
            self.current_by_pid.remove(&key.pid);
        }
    }

    /// Session id for the exact live instance, if it is a session member.
    pub fn session_of(&self, key: &AuditProcessKey) -> Option<SessionId> {
        self.key_to_session.get(key).copied()
    }

    /// True when the exact instance is a verified session member.
    pub fn is_member(&self, key: &AuditProcessKey) -> bool {
        self.key_to_session.contains_key(key)
    }

    /// True when both instances are verified members of the same session.
    pub fn is_same_session(&self, a: &AuditProcessKey, b: &AuditProcessKey) -> bool {
        match (self.session_of(a), self.session_of(b)) {
            (Some(x), Some(y)) => x == y,
            _ => false,
        }
    }

    /// Relationship between a requester and a target for notify-signal
    /// interpretation. See `SignalRelation`.
    pub fn signal_relation(
        &self,
        requester: &AuditProcessKey,
        target: &AuditProcessKey,
    ) -> SignalRelation {
        match (self.session_of(requester), self.session_of(target)) {
            (Some(r), Some(t)) if r == t => SignalRelation::SameSession,
            (Some(_), Some(_)) => SignalRelation::DifferentSession,
            (None, Some(_)) if self.external_by_key.contains_key(requester) => {
                SignalRelation::RequesterExternal
            }
            _ => SignalRelation::Unverifiable,
        }
    }

    /// The exact root instance key of a session, when live.
    pub fn root_of(&self, id: SessionId) -> Option<AuditProcessKey> {
        self.sessions.get(&id).map(|session| session.root)
    }

    /// Live member count of one session (root + members).
    pub fn session_len(&self, id: SessionId) -> usize {
        self.sessions
            .get(&id)
            .map_or(0, |session| session.members.len() + 1)
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Cumulative telemetry: roots observed, joins observed, rejected
    /// (external + unverifiable).
    pub fn stats(&self) -> (u64, u64, u64) {
        (self.roots, self.joins, self.rejected)
    }

    fn attach(&mut self, facts: &MacProcessFacts, sid: SessionId, is_root: bool) {
        self.key_to_session.insert(facts.key, sid);
        self.current_by_pid.insert(facts.key.pid, facts.key);
        if let Some(session) = self.sessions.get_mut(&sid) {
            if is_root {
                session.root = facts.key;
            } else {
                session.members.insert(facts.key, facts.clone());
            }
        }
    }

    fn remove_membership(&mut self, key: AuditProcessKey) {
        self.external_by_key.remove(&key);
        let Some(sid) = self.key_to_session.remove(&key) else {
            return;
        };
        let is_root = self
            .sessions
            .get(&sid)
            .is_some_and(|session| session.root == key);
        if is_root {
            // The root instance is gone: the whole session dissolves. A
            // session without its root is not a legitimate running browser
            // session (helpers spawned later must start from a new root).
            let members: Vec<AuditProcessKey> = self
                .sessions
                .get(&sid)
                .map(|session| session.members.keys().copied().collect())
                .unwrap_or_default();
            for member in members {
                self.key_to_session.remove(&member);
            }
            self.sessions.remove(&sid);
        } else if let Some(session) = self.sessions.get_mut(&sid) {
            session.members.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{ExecutableSnapshot, MacCodeIdentity};
    use std::path::PathBuf;

    fn facts(pid: u32, version: u32, start: u64) -> MacProcessFacts {
        MacProcessFacts {
            key: AuditProcessKey {
                pid,
                pidversion: version,
            },
            uid: 501,
            gid: 20,
            start_time_us: start,
            executable: ExecutableSnapshot {
                path: PathBuf::from("/Applications/Test.app/Contents/MacOS/test"),
                dev: 1,
                ino: 10,
                owner_uid: 501,
                mode: 0o100755,
                size: 100,
                mtime_ns: 1,
                ctime_ns: 1,
            },
            code: MacCodeIdentity {
                valid: true,
                platform_binary: false,
                flags: 1,
                team_id: Some("TEAM".into()),
                signing_id: Some("signing".into()),
                cdhash: [0; 20],
            },
            parent: None,
            responsible: None,
        }
    }

    fn chrome_facts(pid: u32, version: u32, start: u64, helper: bool) -> MacProcessFacts {
        let mut f = facts(pid, version, start);
        f.executable.path = if helper {
            PathBuf::from(
                "/Applications/Test.app/Contents/Frameworks/Test Helper.app/Contents/MacOS/Test Helper",
            )
        } else {
            PathBuf::from("/Applications/Test.app/Contents/MacOS/Test")
        };
        f
    }

    #[test]
    fn main_launched_outside_browser_roots_a_new_session() {
        let mut tracker = BrowserSessionTracker::default();
        let main = chrome_facts(10, 1, 100, false);
        let membership =
            tracker.observe_exec(&main, Some(BrowserExecutableRole::Main), None, false);
        let SessionMembership::NewRoot(sid) = membership else {
            panic!("expected NewRoot, got {membership:?}");
        };
        assert_eq!(tracker.session_of(&main.key), Some(sid));
        assert!(tracker.is_member(&main.key));
        assert_eq!(tracker.session_count(), 1);
        assert_eq!(tracker.stats(), (1, 0, 0));
        assert_eq!(tracker.root_of(sid), Some(main.key));
    }

    #[test]
    fn helper_joins_only_through_verified_parent_member() {
        let mut tracker = BrowserSessionTracker::default();
        let main = chrome_facts(10, 1, 100, false);
        let root = tracker.observe_exec(&main, Some(BrowserExecutableRole::Main), None, false);
        let sid = root.session_id().unwrap();

        let helper = chrome_facts(11, 1, 110, true);
        let joined = tracker.observe_exec(
            &helper,
            Some(BrowserExecutableRole::Helper),
            Some(main.key),
            true,
        );
        assert_eq!(joined, SessionMembership::Joined(sid));
        assert!(tracker.is_same_session(&main.key, &helper.key));
        assert_eq!(tracker.session_len(sid), 2);
        assert_eq!(tracker.stats(), (1, 1, 0));

        let nested = chrome_facts(12, 1, 120, true);
        assert_eq!(
            tracker.observe_exec(
                &nested,
                Some(BrowserExecutableRole::Helper),
                Some(helper.key),
                true,
            ),
            SessionMembership::Joined(sid)
        );
        assert!(tracker.is_same_session(&main.key, &nested.key));
        assert_eq!(tracker.session_len(sid), 3);
    }

    #[test]
    fn signed_helper_laundering_is_rejected_and_never_joins() {
        let mut tracker = BrowserSessionTracker::default();
        let main = chrome_facts(10, 1, 100, false);
        let root = tracker.observe_exec(&main, Some(BrowserExecutableRole::Main), None, false);
        let _ = root.session_id().unwrap();

        // Attacker (python) parent pid 99, NOT an enrolled browser executable.
        let laundered = chrome_facts(20, 1, 200, true);
        let membership = tracker.observe_exec(
            &laundered,
            Some(BrowserExecutableRole::Helper),
            Some(AuditProcessKey {
                pid: 99,
                pidversion: 1,
            }),
            false,
        );
        assert_eq!(
            membership,
            SessionMembership::Rejected(RejectionKind::ExternalLaunch)
        );
        assert!(!tracker.is_member(&laundered.key));
        assert_eq!(tracker.session_of(&laundered.key), None);
        assert!(!tracker.is_same_session(&main.key, &laundered.key));
        assert_eq!(
            tracker.signal_relation(&laundered.key, &main.key),
            SignalRelation::RequesterExternal
        );
    }

    #[test]
    fn warm_start_parent_without_session_is_unverifiable_not_external() {
        let mut tracker = BrowserSessionTracker::default();
        let helper = chrome_facts(11, 1, 110, true);
        let membership = tracker.observe_exec(
            &helper,
            Some(BrowserExecutableRole::Helper),
            Some(AuditProcessKey {
                pid: 10,
                pidversion: 1,
            }),
            true, // parent IS an enrolled browser executable (warm start)
        );
        assert_eq!(
            membership,
            SessionMembership::Rejected(RejectionKind::Unverifiable)
        );
        assert_eq!(tracker.session_of(&helper.key), None);
        assert_eq!(
            tracker.signal_relation(
                &helper.key,
                &AuditProcessKey {
                    pid: 10,
                    pidversion: 1
                }
            ),
            SignalRelation::Unverifiable
        );
    }

    #[test]
    fn unknown_parent_is_unverifiable() {
        let mut tracker = BrowserSessionTracker::default();
        let helper = chrome_facts(11, 1, 110, true);
        let membership =
            tracker.observe_exec(&helper, Some(BrowserExecutableRole::Helper), None, false);
        assert_eq!(
            membership,
            SessionMembership::Rejected(RejectionKind::Unverifiable)
        );
    }

    #[test]
    fn second_browser_instance_is_a_separate_session() {
        let mut tracker = BrowserSessionTracker::default();
        let main1 = chrome_facts(10, 1, 100, false);
        let root1 = tracker.observe_exec(&main1, Some(BrowserExecutableRole::Main), None, false);
        let main2 = chrome_facts(30, 1, 300, false);
        let root2 = tracker.observe_exec(&main2, Some(BrowserExecutableRole::Main), None, false);
        assert_ne!(root1.session_id(), root2.session_id());
        assert!(!tracker.is_same_session(&main1.key, &main2.key));
        assert_eq!(
            tracker.signal_relation(&main2.key, &main1.key),
            SignalRelation::DifferentSession
        );
        assert_eq!(tracker.session_count(), 2);
    }

    #[test]
    fn root_exit_dissolves_the_session_and_member_exit_removes_only_member() {
        let mut tracker = BrowserSessionTracker::default();
        let main = chrome_facts(10, 1, 100, false);
        let root = tracker.observe_exec(&main, Some(BrowserExecutableRole::Main), None, false);
        let sid = root.session_id().unwrap();
        let helper = chrome_facts(11, 1, 110, true);
        tracker.observe_exec(
            &helper,
            Some(BrowserExecutableRole::Helper),
            Some(main.key),
            true,
        );
        assert_eq!(tracker.session_len(sid), 2);

        tracker.observe_exit(&helper.key);
        assert_eq!(tracker.session_len(sid), 1);
        assert!(!tracker.is_member(&helper.key));
        assert!(tracker.is_member(&main.key));

        tracker.observe_exit(&main.key);
        assert_eq!(tracker.session_count(), 0);
        assert!(!tracker.is_member(&main.key));
    }

    #[test]
    fn pid_reuse_never_inherits_session_membership() {
        let mut tracker = BrowserSessionTracker::default();
        let main = chrome_facts(10, 1, 100, false);
        let root = tracker.observe_exec(&main, Some(BrowserExecutableRole::Main), None, false);
        let sid = root.session_id().unwrap();
        let helper = chrome_facts(11, 1, 110, true);
        tracker.observe_exec(
            &helper,
            Some(BrowserExecutableRole::Helper),
            Some(main.key),
            true,
        );
        assert_eq!(tracker.session_len(sid), 2);

        // Missed NOTIFY_EXIT for the helper, then a NEW instance at the same
        // PID (new pidversion/start). Its membership is recomputed from its
        // own parent, never inherited.
        let reused = chrome_facts(11, 2, 210, true);
        let membership = tracker.observe_exec(
            &reused,
            Some(BrowserExecutableRole::Helper),
            Some(main.key),
            true,
        );
        assert_eq!(membership, SessionMembership::Joined(sid));
        assert!(tracker.is_member(&reused.key));
        assert!(!tracker.is_member(&helper.key));

        // A non-browser exec at the reused main PID cannot inherit anything.
        let attacker = facts(10, 2, 200);
        let unrelated = tracker.observe_exec(&attacker, None, None, false);
        assert_eq!(
            unrelated,
            SessionMembership::Rejected(RejectionKind::Unverifiable)
        );
        assert!(!tracker.is_member(&attacker.key));
    }
}
