//! macOS Process Shield live state (MPS1+).
//!
//! Tracks which exact live process instances are shielded, why, and their
//! monotonic integrity state. Task-port prevention (MPS2), compromise signals
//! (MPS4), File Shield integration (MPS5) and dynamic lease-root shielding
//! (MPS6) all consult this module. Nothing here makes machine-wide policy:
//! unrelated processes are never shielded and never enter this state.
//!
//! Security invariants:
//! - a stable instance can transition `Normal -> Compromised` exactly once and
//!   never returns to `Normal`;
//! - process exit destroys live state; PID reuse creates a new instance and
//!   never inherits compromise;
//! - an entry is keyed by `AuditProcessKey` (pid + pidversion) plus the
//!   validated stable identity fields inside `MacProcessFacts`, never by PID
//!   alone;
//! - a denied task-access attack must NOT mark the target compromised — only
//!   the explicit strong-signal transitions in MPS4 do that.

use std::collections::HashMap;

use guard_core::ProcessIntegrity;

use crate::browser_session::{BrowserSessionTracker, SessionId, SessionMembership, SignalRelation};
use crate::browser_trust::BrowserExecutableRole;
use crate::identity::{AuditProcessKey, MacProcessFacts};

/// Why an exact live process instance is shielded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShieldReasonKind {
    /// Enrolled trusted browser instance admitted via AUTH_EXEC (MPS1).
    Browser,
    /// Guard security-critical component (guard-es / GUI / guard-notify,
    /// guardctl while performing sensitive operations) (MPS6).
    GuardComponent,
    /// Exact process-tree root of a live migration/SSH-read lease (MPS6).
    DynamicLeaseRoot,
}

impl ShieldReasonKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::GuardComponent => "guard_component",
            Self::DynamicLeaseRoot => "dynamic_lease_root",
        }
    }
}

/// How an exact live process instance entered the shield (MPS Hardening).
///
/// AUTH_EXEC-admitted instances had their launch verified race-free before the
/// exec was allowed. A Preexisting instance was already running when this ES
/// client started (e.g. after a guard-es / extension restart): its launch was
/// never seen by the shield, so its launch integrity is UNVERIFIED. It stays
/// shielded (task access denied, compromise signals still apply), but the File
/// Shield side reports Reduced posture and requires a browser restart to reach
/// Strong launch integrity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShieldAdmission {
    /// Admitted via AUTH_EXEC with verified launch state.
    AuthExec,
    /// Already-running shield-eligible process first observed after this ES
    /// client started; launch integrity unverified (warm start / restart).
    PreexistingUnverified,
}

impl ShieldAdmission {
    pub fn label(&self) -> &'static str {
        match self {
            Self::AuthExec => "auth_exec",
            Self::PreexistingUnverified => "preexisting_unverified",
        }
    }
}

/// The code-loading / search-path DYLD variables that a shielded-eligible exec
/// must not carry. Harmless diagnostic DYLD variables (DYLD_PRINT_*, etc.) are
/// deliberately not in this set: they do not change which code loads.
pub const PROHIBITED_DYLD_VARS: [&str; 6] = [
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_FALLBACK_FRAMEWORK_PATH",
    "DYLD_ROOT_PATH",
];

/// Presence-only launch-integrity facts captured from one AUTH_EXEC event.
/// Values are never copied into Guard state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExecLaunchFacts {
    pub dyld_insert_libraries: bool,
    pub dyld_library_path: bool,
    pub dyld_framework_path: bool,
    pub dyld_fallback_library_path: bool,
    pub dyld_fallback_framework_path: bool,
    pub dyld_root_path: bool,
}

impl ExecLaunchFacts {
    /// Any prohibited code-loading / search-path DYLD variable present.
    pub fn has_prohibited_code_loading(&self) -> bool {
        self.dyld_insert_libraries
            || self.dyld_library_path
            || self.dyld_framework_path
            || self.dyld_fallback_library_path
            || self.dyld_fallback_framework_path
            || self.dyld_root_path
    }

    /// Names of the prohibited variables that are present (for audit metadata).
    pub fn present_vars(&self) -> Vec<&'static str> {
        let mut present = Vec::new();
        if self.dyld_insert_libraries {
            present.push("DYLD_INSERT_LIBRARIES");
        }
        if self.dyld_library_path {
            present.push("DYLD_LIBRARY_PATH");
        }
        if self.dyld_framework_path {
            present.push("DYLD_FRAMEWORK_PATH");
        }
        if self.dyld_fallback_library_path {
            present.push("DYLD_FALLBACK_LIBRARY_PATH");
        }
        if self.dyld_fallback_framework_path {
            present.push("DYLD_FALLBACK_FRAMEWORK_PATH");
        }
        if self.dyld_root_path {
            present.push("DYLD_ROOT_PATH");
        }
        present
    }
}

/// Which task-capability kind an AUTH_GET_TASK(_READ) event carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskAccessKind {
    Control,
    Read,
}

impl TaskAccessKind {
    pub fn event_code(&self) -> &'static str {
        match self {
            Self::Control => "process_shield_task_control_denied",
            Self::Read => "process_shield_task_read_denied",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Control => "task_control",
            Self::Read => "task_read",
        }
    }
}

/// Notify-only task/trace/thread/CS event kind (MPS3/MPS4). These signals
/// are telemetry + compromise input; they never grant or deny anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskNotifyKind {
    GetTask,
    GetTaskRead,
    Trace,
    RemoteThreadCreate,
    CsInvalidated,
}

impl TaskNotifyKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::GetTask => "notify_get_task",
            Self::GetTaskRead => "notify_get_task_read",
            Self::Trace => "notify_trace",
            Self::RemoteThreadCreate => "notify_remote_thread_create",
            Self::CsInvalidated => "notify_cs_invalidated",
        }
    }

    /// Stable audit event code. Trace stays telemetry; the strong signals are
    /// consumed by MPS4 for the compromise transition.
    pub fn event_code(&self) -> &'static str {
        match self {
            Self::GetTask => "process_shield_task_notify_obtained",
            Self::GetTaskRead => "process_shield_task_read_notify_obtained",
            Self::Trace => "process_shield_trace_observed",
            Self::RemoteThreadCreate => "process_shield_remote_thread_observed",
            Self::CsInvalidated => "process_shield_cs_invalidated_observed",
        }
    }

    /// True when this notify signal is, by KIND alone, a strong compromise
    /// input. MPS4 uses the resolved decision (see strong_signal_decision) to
    /// transition the exact target to Compromised.
    ///
    /// MCH7 revalidation (real daily-use regression):
    /// - NOTIFY_GET_TASK / NOTIFY_GET_TASK_READ fire routinely on real browsers
    ///   for legitimate macOS session management and browser-internal
    ///   operations; they are contextual (strong only when the requester was
    ///   NOT allowlisted).
    /// - NOTIFY_CS_INVALIDATED automatic Normal -> Compromised semantics are
    ///   UNVALIDATED: real-browser evidence does not yet prove what
    ///   invalidation means for a live browser, so it is DETECTED telemetry
    ///   only and Process Shield health reports Reduced until validated.
    /// - NOTIFY_REMOTE_THREAD_CREATE is contextual: strong only for an unknown
    ///   external requester; browser-internal or allowlisted Apple platform
    ///   services are telemetry.
    ///
    /// No kind is unconditionally strong anymore; resolve every signal through
    /// strong_signal_decision.
    pub fn is_strong_signal(&self) -> bool {
        false
    }
}

/// MCH7: NOTIFY_CS_INVALIDATED automatic-compromise semantics are UNVALIDATED.
/// Until real-browser compatibility + adversarial evidence establishes what
/// code-signing invalidation means for a live browser, the strong transition is
/// suspended (DETECTED telemetry only) and Process Shield health must report
/// Reduced. Flip this constant to true only after that evidence exists.
pub const CS_INVALIDATED_STRONG_SIGNAL_UNVALIDATED: bool = true;

/// Resolve whether a notify-only signal is a strong compromise input for an
/// exact shielded target, using requester context (MPS4/MCH7/MCH3).
///
/// Every notify signal is DETECTED + CONTAINED (never PREVENTED). A strong
/// resolution means the exact target transitions Normal -> Compromised and its
/// File Shield / lease authority is revoked.
///
/// Rules (MCH7 revalidation + MCH3 session context):
/// - GET_TASK / GET_TASK_READ: strong when the requester actually obtained the
///   capability without any accepted relationship (not allowlisted) AND is not
///   a verified browser-internal (same-session) process.
/// - REMOTE_THREAD_CREATE: strong for an UNKNOWN EXTERNAL requester: not
///   allowlisted, not same-session, provably different-session or provably
///   externally launched (signed-helper laundering). When session membership
///   is unverifiable, the caller's browser-identity fallback applies.
/// - CS_INVALIDATED: UNVALIDATED automatic-compromise semantics; DETECTED
///   telemetry only until compatibility + adversarial tests establish reliable
///   semantics (health reports Reduced).
/// - TRACE: telemetry.
pub fn strong_signal_decision(
    kind: TaskNotifyKind,
    legitimate_relationship: bool,
    relation: SignalRelation,
    fallback_related: bool,
) -> bool {
    // A "related" requester is one with a verified runtime relationship to the
    // target (same session) or, when membership is unverifiable, one that at
    // least carries browser identity (MCH7 heuristic, warm-start cases).
    let related = match relation {
        SignalRelation::SameSession => true,
        SignalRelation::DifferentSession => false,
        SignalRelation::RequesterExternal => false,
        SignalRelation::Unverifiable => fallback_related,
    };
    match kind {
        TaskNotifyKind::GetTask | TaskNotifyKind::GetTaskRead => {
            !legitimate_relationship && !related
        }
        TaskNotifyKind::RemoteThreadCreate => !legitimate_relationship && !related,
        TaskNotifyKind::CsInvalidated => false,
        TaskNotifyKind::Trace => false,
    }
}

/// Deterministic task-access allowlist for shielded targets (MPS2/MPS11,
/// MPS Hardening).
///
/// MPS2 started at ZERO exceptions; every entry below is backed by observed
/// compatibility evidence and a regression fixture description (MPS11). Same
/// UID, Apple signature, same Team ID, familiar basename or any process-tree
/// relationship is NEVER sufficient on its own.
///
/// MPS Hardening narrowing: exceptions are now EXACT signing-ID + kind
/// specific, not a class rule over every Apple platform binary. A requester is
/// allowed only when BOTH hold:
///   - it is a kernel-verified Apple PLATFORM binary running as uid 0 (the
///     `platform_binary` flag comes from Apple's platform code-signing chain
///     and cannot be forged by a same-user attacker), and
///   - its exact signing ID is on the allowlist FOR THAT TASK KIND.
///
/// Task READ (memory contents) is strictly narrower than task CONTROL:
/// only requesters with observed read evidence may read shielded-target
/// memory. This never applies to Apple-signer developer/App-Store certs,
/// user processes, or Team-ID-based matches.
///
/// Observed (metadata-only, MPS11): macOS system management routinely obtains
/// task capabilities on GUI processes — coreservicesd registers a client's
/// SCSession universe (denying it makes Chrome/Firefox abort with
/// CARBONCORE__ABORTING_BECAUSE_CORESERVICESD_RETURNED_AN_ERROR), and dozens
/// of other root-owned Apple platform daemons (launchd, amfid, watchdogd,
/// configd, UserEventAgent, fseventsd, powerd, apsd, xprotectd, logd, dasd,
/// notifyd, logind, autofsd, remoted, KernelEventAgent, opendirectoryd,
/// kernelmanagerd, thermalmonitord, diskarbitrationd, corerepaird, ...)
/// manage processes/sessions.
pub fn task_access_allowlist(
    requester: &MacProcessFacts,
    target: &MacProcessFacts,
    kind: TaskAccessKind,
) -> bool {
    if requester.uid != 0 || !requester.code.valid || !requester.code.platform_binary {
        return false;
    }
    // Task READ (memory contents) is only granted against SIGNED targets.
    // This is a signed-vs-unsigned guard on the TARGET, not a browser
    // Main/Helper role restriction: we do not guess process role from a
    // signing ID. Unsigned targets never qualify for the read exception.
    let target_is_signed = target.code.signing_id.is_some();
    match kind {
        TaskAccessKind::Control => TASK_CONTROL_ALLOWED_SIGNING_IDS
            .contains(&requester.code.signing_id.as_deref().unwrap_or("")),
        TaskAccessKind::Read => {
            target_is_signed
                && TASK_READ_ALLOWED_SIGNING_IDS
                    .contains(&requester.code.signing_id.as_deref().unwrap_or(""))
        }
    }
}

/// Exact signing IDs allowed task CONTROL on shielded targets (MPS11
/// observed + MPS Hardening narrowing). Every ID here was observed (metadata
/// only) managing processes/sessions on GUI processes.
const TASK_CONTROL_ALLOWED_SIGNING_IDS: &[&str] = &[
    "com.apple.coreservicesd",
    "com.apple.launchd",
    "com.apple.amfid",
    "com.apple.watchdogd",
    "com.apple.configd",
    "com.apple.UserEventAgent",
    "com.apple.fseventsd",
    "com.apple.powerd",
    "com.apple.apsd",
    "com.apple.xprotectd",
    "com.apple.logd",
    "com.apple.dasd",
    "com.apple.notifyd",
    "com.apple.logind",
    "com.apple.autofsd",
    "com.apple.remoted",
    "com.apple.KernelEventAgent",
    "com.apple.opendirectoryd",
    "com.apple.kernelmanagerd",
    "com.apple.thermalmonitord",
    "com.apple.diskarbitrationd",
    "com.apple.corerepaird",
];

/// Exact signing IDs allowed task READ (memory contents) on shielded targets.
/// Strictly narrower than CONTROL: only requesters with observed read
/// evidence. Currently only coreservicesd has such evidence (SCSession
/// registration on GUI processes).
const TASK_READ_ALLOWED_SIGNING_IDS: &[&str] = &["com.apple.coreservicesd"];

/// Outcome of applying a strong notify-only compromise signal to an exact
/// shielded target (MPS4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrongSignalOutcome {
    /// The target is not currently shielded; the signal is out of Process
    /// Shield scope and must not mutate any unrelated state.
    NotShielded,
    /// This call performed the irreversible `Normal -> Compromised`
    /// transition for the exact live instance.
    CompromisedNow,
    /// The exact instance was already Compromised; the transition is
    /// idempotent and is NOT repeated.
    AlreadyCompromised,
}

impl MacProcessShield {
    /// Apply a strong notify-only signal (unexpected successful task
    /// capability, remote-thread creation, code-signing invalidation) to the
    /// exact target. The transition is monotonic and idempotent; process exit
    /// clears the state and PID reuse never inherits it.
    pub fn apply_strong_signal(&mut self, target: &MacProcessFacts) -> StrongSignalOutcome {
        // MCH4: only SecretAuthority (task-protected) targets can be
        // transitioned; helpers without authority are outside strong-signal
        // scope.
        if !self.is_task_protected(target) {
            return StrongSignalOutcome::NotShielded;
        }
        if self.mark_compromised(&target.key) {
            StrongSignalOutcome::CompromisedNow
        } else {
            StrongSignalOutcome::AlreadyCompromised
        }
    }
}

/// Stable-identity error while admitting/removing shield state.
#[derive(Debug, thiserror::Error)]
pub enum ShieldError {
    #[error("shield target process identity is invalid: {0}")]
    InvalidIdentity(String),
    #[error("shield entry for the exact instance is missing")]
    MissingEntry,
}

#[derive(Debug)]
struct ShieldEntry {
    facts: MacProcessFacts,
    /// Reference count per reason kind: one instance may be shielded for
    /// several reasons at once (browser + lease root).
    reasons: HashMap<ShieldReasonKind, usize>,
    integrity: ProcessIntegrity,
    /// How this instance entered the shield (MPS Hardening). Preexisting
    /// instances have unverified launch integrity after an ES restart.
    admission: ShieldAdmission,
    /// MCH3: BrowserSession membership for browser-reason entries (None for
    /// warm-start / rejected / non-browser reasons).
    session: Option<SessionId>,
    /// MCH4: whether this instance is a SecretAuthority holder and therefore
    /// task-protected. Browser helpers that are only session members have
    /// `authority == false` (or no entry at all) until promoted on a protected
    /// read (MCH5). Non-browser reasons (GuardComponent / DynamicLeaseRoot)
    /// are always task-protected regardless of this flag.
    authority: bool,
}

/// Live Process Shield state, keyed by exact stable process instance.
#[derive(Debug, Default)]
pub struct MacProcessShield {
    entries: HashMap<AuditProcessKey, ShieldEntry>,
    current_by_pid: HashMap<u32, AuditProcessKey>,
    /// MCH3: verified launch-topology sessions for browser processes.
    sessions: BrowserSessionTracker,
    admitted: u64,
    /// Cumulative telemetry: how many preexisting (warm-start) admissions have
    /// happened since this shield was created. This is NOT a live count and
    /// must never drive the Active/Reduced health decision.
    preexisting_admitted_total: u64,
    compromised: u64,
    launch_injection_denied: u64,
    malformed_denied: u64,
    removed_on_exit: u64,
    task_control_allowed: u64,
    task_control_denied: u64,
    task_read_allowed: u64,
    task_read_denied: u64,
    task_notify_obtained: u64,
    trace_observed: u64,
    remote_thread_observed: u64,
    cs_invalidated_observed: u64,
}

impl MacProcessShield {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit (or add a reason to) an exact live instance. Validates the stable
    /// identity; malformed identity fails closed (no entry is created).
    pub fn admit(
        &mut self,
        facts: MacProcessFacts,
        reason: ShieldReasonKind,
    ) -> Result<(), ShieldError> {
        facts
            .validate()
            .map_err(|error| ShieldError::InvalidIdentity(error.to_string()))?;
        let key = facts.key;
        let admitted = self
            .entries
            .get_mut(&key)
            .map(|entry| {
                // The same audit key must carry the same stable identity.
                if entry.facts.stable_id() != facts.stable_id() || entry.facts.uid != facts.uid {
                    return Err(ShieldError::InvalidIdentity(
                        "same audit key changed stable identity".into(),
                    ));
                }
                entry.facts = facts.clone();
                *entry.reasons.entry(reason).or_insert(0) += 1;
                Ok(())
            })
            .unwrap_or_else(|| {
                let mut reasons = HashMap::new();
                reasons.insert(reason, 1);
                self.entries.insert(
                    key,
                    ShieldEntry {
                        facts: facts.clone(),
                        reasons,
                        integrity: ProcessIntegrity::Normal,
                        admission: ShieldAdmission::AuthExec,
                        session: None,
                        authority: false,
                    },
                );
                self.current_by_pid.insert(key.pid, key);
                Ok(())
            });
        if admitted.is_ok() {
            self.admitted = self.admitted.saturating_add(1);
        }
        admitted
    }

    /// Admit an already-running shield-eligible instance first observed after
    /// this ES client started (guard-es/extension restart, warm start). Its
    /// launch integrity is UNVERIFIED, so it is marked PreexistingUnverified
    /// and File Shield reports Reduced posture until the process restarts and
    /// is re-admitted via AUTH_EXEC.
    pub fn admit_preexisting(
        &mut self,
        facts: MacProcessFacts,
        reason: ShieldReasonKind,
    ) -> Result<(), ShieldError> {
        facts
            .validate()
            .map_err(|error| ShieldError::InvalidIdentity(error.to_string()))?;
        let key = facts.key;
        let admitted = self
            .entries
            .get_mut(&key)
            .map(|entry| {
                if entry.facts.stable_id() != facts.stable_id() || entry.facts.uid != facts.uid {
                    return Err(ShieldError::InvalidIdentity(
                        "same audit key changed stable identity".into(),
                    ));
                }
                entry.facts = facts.clone();
                *entry.reasons.entry(reason).or_insert(0) += 1;
                Ok(())
            })
            .unwrap_or_else(|| {
                let mut reasons = HashMap::new();
                reasons.insert(reason, 1);
                self.entries.insert(
                    key,
                    ShieldEntry {
                        facts: facts.clone(),
                        reasons,
                        integrity: ProcessIntegrity::Normal,
                        admission: ShieldAdmission::PreexistingUnverified,
                        session: None,
                        authority: false,
                    },
                );
                self.current_by_pid.insert(key.pid, key);
                Ok(())
            });
        if admitted.is_ok() {
            self.preexisting_admitted_total = self.preexisting_admitted_total.saturating_add(1);
        }
        admitted
    }

    /// The admission kind for the current exact instance of pid, if any.
    pub fn admission_of_pid(&self, pid: u32) -> Option<ShieldAdmission> {
        self.current_by_pid
            .get(&pid)
            .and_then(|key| self.entries.get(key))
            .map(|entry| entry.admission)
    }

    /// True when the current instance of pid is shielded but its launch was
    /// never verified (warm start / ES restart).
    pub fn is_preexisting(&self, pid: u32) -> bool {
        matches!(
            self.admission_of_pid(pid),
            Some(ShieldAdmission::PreexistingUnverified)
        )
    }

    /// Add a reason to an already-admitted instance (e.g. dynamic lease-root
    /// shielding on top of browser shielding). Returns an error if the exact
    /// instance is not currently shielded.
    pub fn add_reason(
        &mut self,
        key: AuditProcessKey,
        reason: ShieldReasonKind,
    ) -> Result<(), ShieldError> {
        let entry = self
            .entries
            .get_mut(&key)
            .ok_or(ShieldError::MissingEntry)?;
        *entry.reasons.entry(reason).or_insert(0) += 1;
        Ok(())
    }

    /// Remove one reason. Returns true when the entry was dropped because the
    /// last reason went away (dynamic shielding removal).
    pub fn remove_reason(&mut self, key: &AuditProcessKey, reason: ShieldReasonKind) -> bool {
        let Some(entry) = self.entries.get_mut(key) else {
            return false;
        };
        let mut drop_entry = false;
        if let Some(count) = entry.reasons.get_mut(&reason) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                entry.reasons.remove(&reason);
            }
        }
        if entry.reasons.is_empty() {
            drop_entry = true;
        }
        if drop_entry {
            self.remove_terminal(*key);
        }
        drop_entry
    }

    /// Idempotent `Normal -> Compromised` for one exact instance. Returns true
    /// only when this call performed the transition.
    pub fn mark_compromised(&mut self, key: &AuditProcessKey) -> bool {
        let Some(entry) = self.entries.get_mut(key) else {
            return false;
        };
        if entry.integrity == ProcessIntegrity::Compromised {
            return false;
        }
        entry.integrity = ProcessIntegrity::Compromised;
        self.compromised = self.compromised.saturating_add(1);
        true
    }

    /// Integrity of the exact live instance for `pid` as currently shielded.
    /// Anything not shielded (or not the current instance) is Normal: Process
    /// Shield never degrades unrelated processes.
    pub fn integrity_of_pid(&self, pid: u32) -> ProcessIntegrity {
        self.current_by_pid
            .get(&pid)
            .and_then(|key| self.entries.get(key))
            .map_or(ProcessIntegrity::Normal, |entry| entry.integrity)
    }

    /// True when the exact instance is currently shielded.
    pub fn is_shielded_exact(&self, facts: &MacProcessFacts) -> bool {
        self.entries.get(&facts.key).is_some_and(|entry| {
            entry.facts.stable_id() == facts.stable_id() && entry.facts.uid == facts.uid
        })
    }

    /// True when the audit key currently maps to a shielded instance.
    pub fn is_shielded_key(&self, key: &AuditProcessKey) -> bool {
        self.entries.contains_key(key)
    }

    /// Current shielded facts for a PID, when the current instance is shielded.
    pub fn current(&self, pid: u32) -> Option<&MacProcessFacts> {
        self.current_by_pid
            .get(&pid)
            .and_then(|key| self.entries.get(key))
            .map(|entry| &entry.facts)
    }

    /// NOTIFY_EXIT cleanup: destroys live state for the exact instance.
    pub fn remove_terminal(&mut self, key: AuditProcessKey) {
        if self.entries.remove(&key).is_some() {
            self.removed_on_exit = self.removed_on_exit.saturating_add(1);
        }
        if self.current_by_pid.get(&key.pid) == Some(&key) {
            self.current_by_pid.remove(&key.pid);
        }
        // MCH3: keep the launch-topology model in sync so exit never leaves a
        // phantom session member (and root exit dissolves the session).
        self.sessions.observe_exit(&key);
    }

    /// MCH4: admit a browser executable observed via AUTH_EXEC and classify it
    /// against verified launch topology (MCH3). ONLY the permanent authority
    /// candidate is task-protected: a Main process (session root or a Main
    /// joining an existing session). Helpers and laundered execs are tracked
    /// in the session model but get NO shield entry and NO task restrictions
    /// until they are promoted on a protected read (MCH5). This is the
    /// "do not lock every browser helper" rule.
    pub fn admit_browser(
        &mut self,
        facts: MacProcessFacts,
        role: Option<BrowserExecutableRole>,
        parent: Option<AuditProcessKey>,
        parent_is_enrolled_browser: bool,
    ) -> Result<SessionMembership, ShieldError> {
        facts
            .validate()
            .map_err(|error| ShieldError::InvalidIdentity(error.to_string()))?;
        let key = facts.key;
        let membership =
            self.sessions
                .observe_exec(&facts, role, parent, parent_is_enrolled_browser);
        let session = membership.session_id();
        // Main executables are the permanent authority candidate. Helpers and
        // role-less enrollments never are at exec time.
        let is_authority = matches!(role, Some(BrowserExecutableRole::Main));
        if !is_authority {
            // Tracked in the session model only: no entry, no task protection.
            return Ok(membership);
        }
        let admitted = self
            .entries
            .get_mut(&key)
            .map(|entry| {
                if entry.facts.stable_id() != facts.stable_id() || entry.facts.uid != facts.uid {
                    return Err(ShieldError::InvalidIdentity(
                        "same audit key changed stable identity".into(),
                    ));
                }
                entry.facts = facts.clone();
                entry.session = session;
                entry.authority = true;
                *entry.reasons.entry(ShieldReasonKind::Browser).or_insert(0) += 1;
                Ok(())
            })
            .unwrap_or_else(|| {
                let mut reasons = HashMap::new();
                reasons.insert(ShieldReasonKind::Browser, 1);
                self.entries.insert(
                    key,
                    ShieldEntry {
                        facts: facts.clone(),
                        reasons,
                        integrity: ProcessIntegrity::Normal,
                        admission: ShieldAdmission::AuthExec,
                        session,
                        authority: true,
                    },
                );
                self.current_by_pid.insert(key.pid, key);
                Ok(())
            });
        if admitted.is_ok() {
            self.admitted = self.admitted.saturating_add(1);
        }
        admitted.map(|()| membership)
    }

    /// MCH5: runtime authority admission. Called BEFORE a protected read is
    /// allowed (from the identity resolver). Admits (or upgrades) the exact
    /// instance to SecretAuthority so it is task-protected from the moment the
    /// secret bytes become available — never after. Fail closed on invalid
    /// identity.
    ///
    /// Admission kind: AuthExec when the launch was observed (session member),
    /// PreexistingUnverified otherwise (warm start -> health Reduced until
    /// restart).
    pub fn ensure_authority(&mut self, facts: &MacProcessFacts) -> Result<(), ShieldError> {
        facts
            .validate()
            .map_err(|error| ShieldError::InvalidIdentity(error.to_string()))?;
        let key = facts.key;
        let session = self.sessions.session_of(&key);
        if let Some(entry) = self.entries.get_mut(&key) {
            if entry.facts.stable_id() != facts.stable_id() || entry.facts.uid != facts.uid {
                return Err(ShieldError::InvalidIdentity(
                    "same audit key changed stable identity".into(),
                ));
            }
            entry.facts = facts.clone();
            entry.session = session;
            entry.authority = true;
            *entry.reasons.entry(ShieldReasonKind::Browser).or_insert(0) += 1;
            return Ok(());
        }
        let admission = if session.is_some() {
            ShieldAdmission::AuthExec
        } else {
            ShieldAdmission::PreexistingUnverified
        };
        let mut reasons = HashMap::new();
        reasons.insert(ShieldReasonKind::Browser, 1);
        self.entries.insert(
            key,
            ShieldEntry {
                facts: facts.clone(),
                reasons,
                integrity: ProcessIntegrity::Normal,
                admission,
                session,
                authority: true,
            },
        );
        self.current_by_pid.insert(key.pid, key);
        if admission == ShieldAdmission::PreexistingUnverified {
            self.preexisting_admitted_total = self.preexisting_admitted_total.saturating_add(1);
        }
        Ok(())
    }

    /// MCH4: is the exact instance task-protected? True for every shielded
    /// GuardComponent / lease-root entry and for browser entries carrying
    /// SecretAuthority. Browser helpers without authority are NOT task-
    /// protected: no unnecessary restrictions merely because they are helpers.
    pub fn is_task_protected(&self, facts: &MacProcessFacts) -> bool {
        self.entries.get(&facts.key).is_some_and(|entry| {
            entry.facts.stable_id() == facts.stable_id()
                && entry.facts.uid == facts.uid
                && (entry.authority || !entry.reasons.contains_key(&ShieldReasonKind::Browser))
        })
    }

    /// MCH3: session membership of the exact instance (None when the instance
    /// is not a verified session member).
    pub fn session_of(&self, key: &AuditProcessKey) -> Option<SessionId> {
        self.sessions.session_of(key)
    }

    /// MCH3: relationship between a requester and a target for notify-signal
    /// interpretation (same session / different session / provably external /
    /// unverifiable).
    pub fn signal_relation(
        &self,
        requester: &AuditProcessKey,
        target: &AuditProcessKey,
    ) -> SignalRelation {
        self.sessions.signal_relation(requester, target)
    }

    /// MCH3: cumulative session telemetry (roots observed, joins, rejected
    /// external + unverifiable).
    pub fn session_stats(&self) -> (u64, u64, u64) {
        self.sessions.stats()
    }

    /// MCH3: live verified session count (roots). Health telemetry only.
    pub fn live_session_count(&self) -> usize {
        self.sessions.session_count()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Cumulative telemetry: preexisting (warm-start / ES-restart)
    /// admissions counted since this shield was created. Never used for the
    /// Active/Reduced health decision (see `live_preexisting_count`).
    pub fn preexisting_admitted_total(&self) -> u64 {
        self.preexisting_admitted_total
    }

    /// LIVE count of currently-shielded instances whose admission is
    /// `PreexistingUnverified` (their launch was never observed by this ES
    /// client). This is the only number that may drive the Process Shield
    /// Active/Reduced decision: once a preexisting instance exits (or is
    /// replaced by a fresh AUTH_EXEC instance), this returns to zero even
    /// though the cumulative telemetry keeps climbing.
    ///
    /// Only entries that are still the CURRENT instance for their PID are
    /// counted: a stale preexisting entry whose PID was reused by a new
    /// AUTH_EXEC instance (e.g. after a missed NOTIFY_EXIT sequence gap)
    /// must not keep health Reduced.
    pub fn live_preexisting_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|(key, entry)| {
                entry.admission == ShieldAdmission::PreexistingUnverified
                    && self.current_by_pid.get(&key.pid) == Some(*key)
            })
            .count()
    }

    pub fn stats(&self) -> (u64, u64, u64, u64, u64) {
        (
            self.admitted,
            self.compromised,
            self.launch_injection_denied,
            self.malformed_denied,
            self.removed_on_exit,
        )
    }

    pub fn task_stats(&self) -> (u64, u64, u64, u64) {
        (
            self.task_control_allowed,
            self.task_control_denied,
            self.task_read_allowed,
            self.task_read_denied,
        )
    }

    /// Count a notify-only signal observed against a shielded target.
    /// Notify events are DETECTED + CONTAINED, never PREVENTED.
    pub fn note_task_notify(&mut self, kind: TaskNotifyKind) {
        match kind {
            TaskNotifyKind::GetTask | TaskNotifyKind::GetTaskRead => {
                self.task_notify_obtained = self.task_notify_obtained.saturating_add(1);
            }
            TaskNotifyKind::Trace => {
                self.trace_observed = self.trace_observed.saturating_add(1);
            }
            TaskNotifyKind::RemoteThreadCreate => {
                self.remote_thread_observed = self.remote_thread_observed.saturating_add(1);
            }
            TaskNotifyKind::CsInvalidated => {
                self.cs_invalidated_observed = self.cs_invalidated_observed.saturating_add(1);
            }
        }
    }

    pub fn notify_stats(&self) -> (u64, u64, u64, u64) {
        (
            self.task_notify_obtained,
            self.trace_observed,
            self.remote_thread_observed,
            self.cs_invalidated_observed,
        )
    }

    /// Count a task-access decision against a shielded target (prevention
    /// path). Denied attempts never compromise the target.
    pub fn note_task_decision(&mut self, kind: TaskAccessKind, allow: bool) {
        match (kind, allow) {
            (TaskAccessKind::Control, true) => {
                self.task_control_allowed = self.task_control_allowed.saturating_add(1);
            }
            (TaskAccessKind::Control, false) => {
                self.task_control_denied = self.task_control_denied.saturating_add(1);
            }
            (TaskAccessKind::Read, true) => {
                self.task_read_allowed = self.task_read_allowed.saturating_add(1);
            }
            (TaskAccessKind::Read, false) => {
                self.task_read_denied = self.task_read_denied.saturating_add(1);
            }
        }
    }

    /// Count a denied launch-injection admission (health/audit counter).
    pub fn note_launch_injection_denied(&mut self) {
        self.launch_injection_denied = self.launch_injection_denied.saturating_add(1);
    }

    /// Count a malformed fail-closed admission (health/audit counter).
    pub fn note_malformed_denied(&mut self) {
        self.malformed_denied = self.malformed_denied.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{AuditProcessKey, ExecutableSnapshot, MacCodeIdentity};
    use std::path::{Path, PathBuf};

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

    #[test]
    fn exec_launch_facts_prohibited_and_harmless_vars() {
        let clean = ExecLaunchFacts::default();
        assert!(!clean.has_prohibited_code_loading());
        assert!(clean.present_vars().is_empty());

        let poisoned = ExecLaunchFacts {
            dyld_insert_libraries: true,
            ..ExecLaunchFacts::default()
        };
        assert!(poisoned.has_prohibited_code_loading());
        assert_eq!(poisoned.present_vars(), vec!["DYLD_INSERT_LIBRARIES"]);

        let search_path = ExecLaunchFacts {
            dyld_library_path: true,
            ..ExecLaunchFacts::default()
        };
        assert!(search_path.has_prohibited_code_loading());
        assert_eq!(search_path.present_vars(), vec!["DYLD_LIBRARY_PATH"]);
    }

    #[test]
    fn admission_is_exact_and_pid_reuse_is_a_new_instance() {
        let mut shield = MacProcessShield::new();
        let first = facts(10, 1, 100);
        shield
            .admit(first.clone(), ShieldReasonKind::Browser)
            .unwrap();
        assert!(shield.is_shielded_exact(&first));
        assert_eq!(shield.integrity_of_pid(10), ProcessIntegrity::Normal);
        assert_eq!(shield.len(), 1);

        // A NEW instance at the same PID (new pidversion/start) must NOT match.
        let reused = facts(10, 2, 200);
        assert!(!shield.is_shielded_exact(&reused));
        assert_eq!(shield.integrity_of_pid(10), ProcessIntegrity::Normal);
    }

    #[test]
    fn invalid_identity_fails_closed() {
        let mut shield = MacProcessShield::new();
        let mut broken = facts(10, 1, 100);
        broken.start_time_us = 0;
        assert!(matches!(
            shield.admit(broken, ShieldReasonKind::Browser),
            Err(ShieldError::InvalidIdentity(_))
        ));
        assert!(shield.is_empty());
    }

    #[test]
    fn compromise_is_idempotent_and_never_restored() {
        let mut shield = MacProcessShield::new();
        let target = facts(10, 1, 100);
        shield
            .admit(target.clone(), ShieldReasonKind::Browser)
            .unwrap();
        assert!(shield.mark_compromised(&target.key));
        assert_eq!(shield.integrity_of_pid(10), ProcessIntegrity::Compromised);
        // Idempotent: second call does not transition again.
        assert!(!shield.mark_compromised(&target.key));
        assert_eq!(shield.stats().1, 1);

        // Exit clears live state; a new instance at the same PID is Normal.
        shield.remove_terminal(target.key);
        assert!(shield.is_empty());
        let new = facts(10, 3, 300);
        shield
            .admit(new.clone(), ShieldReasonKind::Browser)
            .unwrap();
        assert_eq!(shield.integrity_of_pid(10), ProcessIntegrity::Normal);
    }

    #[test]
    fn task_allowlist_rejects_same_uid_apple_and_team_id() {
        // MPS2 zero-exception contract: identical uid, Apple platform-binary
        // signature or same Team ID must never allow task access to a shielded
        // target.
        let mut requester = facts(20, 1, 200);
        let target = facts(10, 1, 100);
        requester.uid = target.uid;
        requester.code.platform_binary = true;
        requester.code.team_id = target.code.team_id.clone();
        assert!(!task_access_allowlist(
            &requester,
            &target,
            TaskAccessKind::Control
        ));
    }

    #[test]
    fn platform_binary_exception_is_narrow_and_untrusted_still_denied() {
        // MPS11: the exact Apple platform daemon that registers GUI clients'
        // SCSession universes may task-access shielded targets. Everything
        // else — same path without platform identity, same signing id with a
        // user uid, other Apple daemons — stays denied.
        let target = facts(10, 1, 100);
        let mut coreservicesd = facts(429, 1, 4290);
        coreservicesd.uid = 0;
        coreservicesd.executable.path =
            Path::new("/System/Library/CoreServices/coreservicesd").to_path_buf();
        coreservicesd.code.platform_binary = true;
        coreservicesd.code.signing_id = Some("com.apple.coreservicesd".into());
        coreservicesd.code.team_id = None;
        assert!(task_access_allowlist(
            &coreservicesd,
            &target,
            TaskAccessKind::Control
        ));
        assert!(task_access_allowlist(
            &coreservicesd,
            &target,
            TaskAccessKind::Read
        ));

        // Same path but not a platform binary (a renamed copy) is denied.
        let mut fake = coreservicesd.clone();
        fake.code.platform_binary = false;
        assert!(!task_access_allowlist(
            &fake,
            &target,
            TaskAccessKind::Control
        ));

        // Same signing id but running as a normal user is denied.
        let mut user_run = coreservicesd.clone();
        user_run.uid = 501;
        assert!(!task_access_allowlist(
            &user_run,
            &target,
            TaskAccessKind::Control
        ));

        // MPS Hardening narrowing: a different Apple platform daemon (lsd)
        // is NOT on the exact control allowlist -> denied, even though it is
        // a kernel-verified platform binary. Only observed exact signing IDs
        // are allowed.
        let mut lsd = coreservicesd.clone();
        lsd.executable.path = Path::new("/usr/libexec/lsd").to_path_buf();
        lsd.code.signing_id = Some("com.apple.lsd".into());
        assert!(!task_access_allowlist(
            &lsd,
            &target,
            TaskAccessKind::Control
        ));

        // launchd is on the exact control allowlist (observed managing
        // processes) -> control allowed; it is NOT on the read allowlist ->
        // read denied (MPS Hardening narrowing).
        let mut launchd = coreservicesd.clone();
        launchd.executable.path = Path::new("/sbin/launchd").to_path_buf();
        launchd.code.signing_id = Some("com.apple.launchd".into());
        assert!(task_access_allowlist(
            &launchd,
            &target,
            TaskAccessKind::Control
        ));
        assert!(!task_access_allowlist(
            &launchd,
            &target,
            TaskAccessKind::Read
        ));

        // A same-uid Apple-signed (non-platform) requester is still denied.
        let mut apple_user = facts(30, 1, 300);
        apple_user.code.platform_binary = false;
        apple_user.code.signing_id = Some("com.example.tool".into());
        assert!(!task_access_allowlist(
            &apple_user,
            &target,
            TaskAccessKind::Read
        ));

        // An untrusted same-user process is denied (MPS11 synthetic recheck).
        let mut untrusted = facts(99, 1, 990);
        untrusted.uid = 501;
        untrusted.code.platform_binary = false;
        assert!(!task_access_allowlist(
            &untrusted,
            &target,
            TaskAccessKind::Control
        ));
    }

    #[test]
    fn task_decision_counters_are_per_kind() {
        let mut shield = MacProcessShield::new();
        shield.note_task_decision(TaskAccessKind::Control, false);
        shield.note_task_decision(TaskAccessKind::Control, false);
        shield.note_task_decision(TaskAccessKind::Read, false);
        shield.note_task_decision(TaskAccessKind::Read, true);
        assert_eq!(
            shield.task_stats(),
            (0, 2, 1, 1),
            "control/read counters must be tracked separately"
        );
    }

    #[test]
    fn notify_signal_classification_matches_mch7_revalidation() {
        // MCH7: no kind is unconditionally strong anymore. GET_TASK(_READ)
        // and REMOTE_THREAD_CREATE are CONTEXTUAL (resolved per requester by
        // strong_signal_decision); CS_INVALIDATED is unvalidated DETECTED
        // telemetry; TRACE stays telemetry.
        assert!(!TaskNotifyKind::Trace.is_strong_signal());
        assert!(!TaskNotifyKind::GetTask.is_strong_signal());
        assert!(!TaskNotifyKind::GetTaskRead.is_strong_signal());
        assert!(!TaskNotifyKind::RemoteThreadCreate.is_strong_signal());
        assert!(!TaskNotifyKind::CsInvalidated.is_strong_signal());
        assert_eq!(
            TaskNotifyKind::Trace.event_code(),
            "process_shield_trace_observed"
        );
        assert_eq!(
            TaskNotifyKind::CsInvalidated.event_code(),
            "process_shield_cs_invalidated_observed"
        );
    }

    #[test]
    fn strong_signal_decision_resolves_context_per_requester() {
        use crate::browser_session::SignalRelation;

        // GET_TASK / GET_TASK_READ: strong when the requester was NOT
        // allowlisted AND not a verified browser-internal (same-session)
        // process (contextual; MPS Hardening + MCH3).
        assert!(strong_signal_decision(
            TaskNotifyKind::GetTask,
            false,
            SignalRelation::Unverifiable,
            false
        ));
        assert!(!strong_signal_decision(
            TaskNotifyKind::GetTask,
            false,
            SignalRelation::SameSession,
            false
        ));
        assert!(!strong_signal_decision(
            TaskNotifyKind::GetTask,
            true,
            SignalRelation::RequesterExternal,
            false
        ));

        // REMOTE_THREAD_CREATE: strong for an unknown external requester
        // (unverifiable + no browser-identity fallback), provably different
        // sessions, or a provably externally launched (laundered) helper.
        // Same-session and allowlisted requesters stay telemetry.
        assert!(strong_signal_decision(
            TaskNotifyKind::RemoteThreadCreate,
            false,
            SignalRelation::Unverifiable,
            false
        ));
        assert!(strong_signal_decision(
            TaskNotifyKind::RemoteThreadCreate,
            false,
            SignalRelation::DifferentSession,
            false
        ));
        assert!(strong_signal_decision(
            TaskNotifyKind::RemoteThreadCreate,
            false,
            SignalRelation::RequesterExternal,
            true
        ));
        assert!(!strong_signal_decision(
            TaskNotifyKind::RemoteThreadCreate,
            false,
            SignalRelation::SameSession,
            false
        ));
        assert!(!strong_signal_decision(
            TaskNotifyKind::RemoteThreadCreate,
            false,
            SignalRelation::Unverifiable,
            true
        ));
        assert!(!strong_signal_decision(
            TaskNotifyKind::RemoteThreadCreate,
            true,
            SignalRelation::Unverifiable,
            false
        ));

        // CS_INVALIDATED: unvalidated -> DETECTED telemetry, never an
        // automatic compromise transition.
        assert!(!strong_signal_decision(
            TaskNotifyKind::CsInvalidated,
            false,
            SignalRelation::Unverifiable,
            false
        ));
        assert!(!strong_signal_decision(
            TaskNotifyKind::CsInvalidated,
            true,
            SignalRelation::SameSession,
            false
        ));

        // TRACE stays telemetry.
        assert!(!strong_signal_decision(
            TaskNotifyKind::Trace,
            false,
            SignalRelation::Unverifiable,
            false
        ));
    }

    #[test]
    fn preexisting_admission_is_exact_and_reports_unverified() {
        let mut shield = MacProcessShield::new();
        let running = facts(10, 1, 100);
        // A running browser observed only after ES restart: admitted as
        // preexisting (unverified), still shielded, integrity Normal.
        shield
            .admit_preexisting(running.clone(), ShieldReasonKind::Browser)
            .unwrap();
        assert!(shield.is_shielded_exact(&running));
        assert!(shield.is_preexisting(10));
        assert_eq!(shield.integrity_of_pid(10), ProcessIntegrity::Normal);
        assert_eq!(
            shield.admission_of_pid(10),
            Some(ShieldAdmission::PreexistingUnverified)
        );
        assert_eq!(shield.preexisting_admitted_total(), 1);
        assert_eq!(shield.stats().0, 0, "preexisting is not a regular admit");

        // An AUTH_EXEC admit on top keeps the existing preexisting entry and
        // does not flip admission; a fresh AuthExec instance is AuthExec.
        shield
            .add_reason(running.key, ShieldReasonKind::DynamicLeaseRoot)
            .unwrap();
        assert!(shield.is_preexisting(10));

        let fresh = facts(11, 1, 110);
        shield
            .admit(fresh.clone(), ShieldReasonKind::Browser)
            .unwrap();
        assert!(!shield.is_preexisting(11));
        assert_eq!(shield.admission_of_pid(11), Some(ShieldAdmission::AuthExec));
        assert_eq!(shield.preexisting_admitted_total(), 1);
    }

    #[test]
    fn live_preexisting_count_tracks_current_instances_only() {
        let mut shield = MacProcessShield::new();
        let running = facts(10, 1, 100);
        shield
            .admit_preexisting(running.clone(), ShieldReasonKind::Browser)
            .unwrap();
        // Live count == 1 while the preexisting instance is shielded.
        assert_eq!(shield.live_preexisting_count(), 1);
        assert_eq!(shield.preexisting_admitted_total(), 1);
        // Process exit destroys live state; the cumulative total stays.
        shield.remove_terminal(running.key);
        assert_eq!(shield.live_preexisting_count(), 0);
        assert_eq!(shield.preexisting_admitted_total(), 1);

        // PID reuse: the new instance admitted via AUTH_EXEC is NOT
        // preexisting; live count stays 0 and health may return Active.
        let fresh = facts(10, 2, 200);
        shield
            .admit(fresh.clone(), ShieldReasonKind::Browser)
            .unwrap();
        assert_eq!(shield.live_preexisting_count(), 0);
        assert!(!shield.is_preexisting(10));
        assert_eq!(shield.preexisting_admitted_total(), 1);
    }

    #[test]
    fn preexisting_live_state_is_per_instance_across_multiple_pids() {
        let mut shield = MacProcessShield::new();
        let a = facts(10, 1, 100);
        let b = facts(11, 1, 110);
        shield
            .admit_preexisting(a.clone(), ShieldReasonKind::Browser)
            .unwrap();
        shield
            .admit_preexisting(b.clone(), ShieldReasonKind::Browser)
            .unwrap();
        assert_eq!(shield.live_preexisting_count(), 2);
        shield.remove_terminal(a.key);
        assert_eq!(shield.live_preexisting_count(), 1);
        assert!(!shield.is_preexisting(10));
        assert!(shield.is_preexisting(11));
        shield.remove_terminal(b.key);
        assert_eq!(shield.live_preexisting_count(), 0);
    }

    #[test]
    fn stale_preexisting_entry_after_pid_reuse_does_not_count_live() {
        // Simulate a missed NOTIFY_EXIT (sequence gap): a preexisting
        // instance at pid 10 is still in `entries`, but a NEW instance at
        // the same PID has been admitted via AUTH_EXEC and is now the
        // current mapping. The stale preexisting entry must NOT keep the
        // live count (and thus health) Reduced.
        let mut shield = MacProcessShield::new();
        let old = facts(10, 1, 100);
        shield
            .admit_preexisting(old.clone(), ShieldReasonKind::Browser)
            .unwrap();
        assert_eq!(shield.live_preexisting_count(), 1);
        // New instance at the same PID (new pidversion/start), admitted
        // via AUTH_EXEC; the old entry is deliberately NOT removed to
        // model the missed-exit sequence gap.
        let fresh = facts(10, 2, 200);
        shield
            .admit(fresh.clone(), ShieldReasonKind::Browser)
            .unwrap();
        assert!(shield.is_shielded_exact(&fresh));
        assert_eq!(shield.admission_of_pid(10), Some(ShieldAdmission::AuthExec));
        assert_eq!(
            shield.live_preexisting_count(),
            0,
            "stale preexisting entry must not count once the PID is reused"
        );
    }

    #[test]
    fn preexisting_identity_validation_fails_closed() {
        let mut shield = MacProcessShield::new();
        let mut broken = facts(10, 1, 100);
        broken.start_time_us = 0;
        assert!(matches!(
            shield.admit_preexisting(broken, ShieldReasonKind::Browser),
            Err(ShieldError::InvalidIdentity(_))
        ));
        assert!(shield.is_empty());
        assert_eq!(shield.preexisting_admitted_total(), 0);
    }

    #[test]
    fn notify_counters_are_per_signal() {
        let mut shield = MacProcessShield::new();
        shield.note_task_notify(TaskNotifyKind::GetTask);
        shield.note_task_notify(TaskNotifyKind::GetTaskRead);
        shield.note_task_notify(TaskNotifyKind::Trace);
        shield.note_task_notify(TaskNotifyKind::Trace);
        shield.note_task_notify(TaskNotifyKind::RemoteThreadCreate);
        shield.note_task_notify(TaskNotifyKind::CsInvalidated);
        assert_eq!(shield.notify_stats(), (2, 2, 1, 1));
    }

    #[test]
    fn strong_signal_transition_is_exact_idempotent_and_cleared_on_exit() {
        let mut shield = MacProcessShield::new();
        let target = facts(10, 1, 100);
        let unrelated = facts(11, 1, 110);
        // Not shielded => out of scope, no mutation.
        assert_eq!(
            shield.apply_strong_signal(&target),
            StrongSignalOutcome::NotShielded
        );
        // MCH4: only SecretAuthority targets are in strong-signal scope; a
        // plain browser-reason entry without authority is not.
        shield
            .admit(target.clone(), ShieldReasonKind::Browser)
            .unwrap();
        assert_eq!(
            shield.apply_strong_signal(&target),
            StrongSignalOutcome::NotShielded,
            "non-authority browser entries must not transition"
        );
        shield.ensure_authority(&target).unwrap();
        // First strong signal performs the transition.
        assert_eq!(
            shield.apply_strong_signal(&target),
            StrongSignalOutcome::CompromisedNow
        );
        assert_eq!(shield.integrity_of_pid(10), ProcessIntegrity::Compromised);
        // Idempotent: never transitions again.
        assert_eq!(
            shield.apply_strong_signal(&target),
            StrongSignalOutcome::AlreadyCompromised
        );
        assert_eq!(shield.stats().1, 1, "compromised exactly once");
        // Unrelated instance stays untouched.
        assert_eq!(
            shield.apply_strong_signal(&unrelated),
            StrongSignalOutcome::NotShielded
        );
        assert_eq!(shield.integrity_of_pid(11), ProcessIntegrity::Normal);
        // Exit clears state; PID reuse is a new Normal instance.
        shield.remove_terminal(target.key);
        assert!(shield.is_empty());
        let reused = facts(10, 3, 300);
        shield
            .admit(reused.clone(), ShieldReasonKind::Browser)
            .unwrap();
        assert_eq!(shield.integrity_of_pid(10), ProcessIntegrity::Normal);
        assert_eq!(
            shield.apply_strong_signal(&reused),
            StrongSignalOutcome::NotShielded,
            "plain browser entry without authority is never in scope"
        );
        shield.ensure_authority(&reused).unwrap();
        assert_eq!(
            shield.apply_strong_signal(&reused),
            StrongSignalOutcome::CompromisedNow
        );
    }

    #[test]
    fn admit_browser_records_session_membership_and_rejects_laundering() {
        use crate::browser_session::SignalRelation;
        use crate::browser_trust::BrowserExecutableRole;

        let mut shield = MacProcessShield::new();
        let main = facts(10, 1, 100);
        let root = shield
            .admit_browser(main.clone(), Some(BrowserExecutableRole::Main), None, false)
            .unwrap();
        let sid = root.session_id().unwrap();
        assert_eq!(shield.session_of(&main.key), Some(sid));
        // MCH4: the Main is the permanent authority candidate -> shielded and
        // task-protected.
        assert!(shield.is_shielded_exact(&main));
        assert!(shield.is_task_protected(&main));
        assert_eq!(shield.live_session_count(), 1);

        // A helper whose verified parent is the session root joins it.
        let helper = facts(11, 1, 110);
        let joined = shield
            .admit_browser(
                helper.clone(),
                Some(BrowserExecutableRole::Helper),
                Some(main.key),
                true,
            )
            .unwrap();
        assert_eq!(joined, SessionMembership::Joined(sid));
        assert_eq!(
            shield.signal_relation(&helper.key, &main.key),
            SignalRelation::SameSession
        );
        // MCH4: the helper is tracked in the session but NOT task-protected
        // until promoted on a protected read (MCH5).
        assert!(
            !shield.is_shielded_exact(&helper),
            "helpers must not be shielded at exec time"
        );
        assert!(!shield.is_task_protected(&helper));
        // MCH5: the first protected read promotes it BEFORE the bytes are
        // allowed.
        shield.ensure_authority(&helper).unwrap();
        assert!(shield.is_task_protected(&helper));

        // Signed-helper laundering: attacker parent -> rejected external, no
        // session membership, and the strong-signal relation says EXTERNAL.
        let laundered = facts(20, 1, 200);
        let membership = shield
            .admit_browser(
                laundered.clone(),
                Some(BrowserExecutableRole::Helper),
                Some(AuditProcessKey {
                    pid: 99,
                    pidversion: 1,
                }),
                false,
            )
            .unwrap();
        assert!(membership.is_external());
        assert_eq!(shield.session_of(&laundered.key), None);
        assert!(
            !shield.is_shielded_exact(&laundered),
            "laundered helpers must never be task-protected"
        );
        assert_eq!(
            shield.signal_relation(&laundered.key, &main.key),
            SignalRelation::RequesterExternal
        );
        assert_eq!(shield.session_stats(), (1, 1, 1));

        // Root exit dissolves the session.
        shield.remove_terminal(main.key);
        assert_eq!(shield.live_session_count(), 0);
        assert_eq!(shield.session_of(&helper.key), None);
    }

    #[test]
    fn task_protection_covers_authority_and_guard_components_only() {
        // MCH4: task protection applies to browser SecretAuthority and to
        // non-browser shield reasons (GuardComponent / DynamicLeaseRoot), and
        // NEVER to unprotected browser helpers.
        let mut shield = MacProcessShield::new();
        let helper = facts(11, 1, 110);
        shield
            .admit(helper.clone(), ShieldReasonKind::Browser)
            .unwrap();
        assert!(
            !shield.is_task_protected(&helper),
            "plain browser entry without authority is not task-protected"
        );
        shield.ensure_authority(&helper).unwrap();
        assert!(shield.is_task_protected(&helper));

        let guard = facts(12, 1, 120);
        shield
            .admit(guard.clone(), ShieldReasonKind::GuardComponent)
            .unwrap();
        assert!(
            shield.is_task_protected(&guard),
            "guard components stay task-protected"
        );

        let lease = facts(13, 1, 130);
        shield
            .admit(lease.clone(), ShieldReasonKind::DynamicLeaseRoot)
            .unwrap();
        assert!(shield.is_task_protected(&lease));

        // Unrelated processes are never task-protected.
        assert!(!shield.is_task_protected(&facts(99, 1, 990)));
    }

    #[test]
    fn ensure_authority_admission_kind_depends_on_observed_launch() {
        use crate::browser_trust::BrowserExecutableRole;

        let mut shield = MacProcessShield::new();
        // Session member (launch observed via admit_browser): promotion keeps
        // AuthExec admission and never flags health Reduced.
        let main = facts(10, 1, 100);
        shield
            .admit_browser(main.clone(), Some(BrowserExecutableRole::Main), None, false)
            .unwrap();
        let helper = facts(11, 1, 110);
        shield
            .admit_browser(
                helper.clone(),
                Some(BrowserExecutableRole::Helper),
                Some(main.key),
                true,
            )
            .unwrap();
        shield.ensure_authority(&helper).unwrap();
        assert_eq!(
            shield.admission_of_pid(11),
            Some(ShieldAdmission::AuthExec),
            "launch-observed member must not be preexisting"
        );
        assert_eq!(shield.live_preexisting_count(), 0);
        assert_eq!(shield.preexisting_admitted_total(), 0);

        // Warm-start browser (never launch-observed): promotion is
        // PreexistingUnverified -> health Reduced until restart.
        let warm = facts(20, 1, 200);
        shield.ensure_authority(&warm).unwrap();
        assert_eq!(
            shield.admission_of_pid(20),
            Some(ShieldAdmission::PreexistingUnverified)
        );
        assert_eq!(shield.live_preexisting_count(), 1);

        // Idempotent: a second promotion does not change admission or double
        // count.
        shield.ensure_authority(&warm).unwrap();
        assert_eq!(shield.live_preexisting_count(), 1);
        assert_eq!(shield.preexisting_admitted_total(), 1);

        // Fail closed on invalid identity.
        let mut broken = facts(30, 1, 300);
        broken.start_time_us = 0;
        assert!(matches!(
            shield.ensure_authority(&broken),
            Err(ShieldError::InvalidIdentity(_))
        ));
    }

    #[test]
    fn multiple_reasons_are_refcounted() {
        let mut shield = MacProcessShield::new();
        let target = facts(10, 1, 100);
        shield
            .admit(target.clone(), ShieldReasonKind::Browser)
            .unwrap();
        shield
            .add_reason(target.key, ShieldReasonKind::DynamicLeaseRoot)
            .unwrap();
        assert_eq!(shield.len(), 1);
        // Removing the dynamic reason keeps the browser reason.
        assert!(!shield.remove_reason(&target.key, ShieldReasonKind::DynamicLeaseRoot));
        assert_eq!(shield.len(), 1);
        assert!(shield.is_shielded_exact(&target));
        // Removing the last reason drops the entry.
        assert!(shield.remove_reason(&target.key, ShieldReasonKind::Browser));
        assert!(shield.is_empty());
    }
}
