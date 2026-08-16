//! Versioned JSON IPC protocol between `guardd` and its local clients.
//!
//! The protocol is a single `Request` -> single `Response` exchange over a
//! length-prefixed local frame supplied by the selected transport. It is deliberately tiny:
//! a versioned envelope, a tagged operation enum, and plain serializable "info"
//! view structs. No trust is inferred from the JSON — peer identity comes from
//! kernel `SO_PEERCRED` on the server side; a `uid` field in JSON is never
//! honored for authorization.
//!
//! Authorization (enforced by the daemon, see `guardd::handle_request`):
//! - any authenticated peer: `status`, `resources list`, `browsers list`,
//!   `config check`
//! - ordinary user: own `events` / `explain` / `leases` only
//! - root (uid 0): all events/leases; system-wide policy changes (future)

use serde::{Deserialize, Serialize};

/// Wire protocol version. Bumped on incompatible changes.
pub const PROTOCOL_VERSION: u32 = 5;

/// Hard upper bound on a single request frame. The server rejects anything
/// larger (and any malformed length prefix) so a peer cannot exhaust memory.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;

// Compile-time check that the bound is sane.
const _: () = {
    assert!(MAX_REQUEST_BYTES > 0 && MAX_REQUEST_BYTES <= 1024 * 1024);
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub version: u32,
    pub op: RequestOp,
}

/// A client operation. Tagged with `kind` so unknown ops deserialize cleanly
/// into a catch-all (the daemon returns an error rather than crashing).
///
/// `MigrationAuthorize` never carries a UID: the daemon takes the authorizing
/// uid exclusively from kernel-verified peer creds (`SO_PEERCRED`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RequestOp {
    Status,
    ResourcesList,
    BrowsersList,
    /// Metadata-only snapshot of the configuration currently loaded by the
    /// daemon. This lets an unprivileged UI render the active policy without
    /// reading the root-owned configuration file directly.
    ConfigurationGet,
    /// Apply a platform backend configuration through the authoritative local
    /// service. The platform adapter validates the opaque JSON object against
    /// its own versioned schema; clients cannot choose a destination path.
    ConfigurationApply {
        config: serde_json::Value,
    },
    /// Authenticated liveness signal plus peer-scoped pending snapshot for the
    /// unprivileged user-session observer. It carries no policy decision or
    /// caller identity and avoids three separate polling connections.
    PendingHelperPoll,
    /// Read the recent helper liveness state for the transport peer's UID.
    PendingHelperStatus,
    Events {
        limit: Option<u32>,
        #[serde(default)]
        before_id: Option<i64>,
        #[serde(default)]
        after_id: Option<i64>,
    },
    Explain {
        event_id: i64,
    },
    LeasesList,
    LeasesRevoke {
        lease_id: String,
    },
    ConfigCheck,
    /// Authorize a cross-browser migration access lease. The
    /// daemon binds the lease to the target browser's armed `ExeIdentity` and
    /// caps `duration_secs` at 1 hour (default 10 min). `uid` is taken from
    /// peer creds, NOT from this struct.
    MigrationAuthorize {
        source_browser: String,
        source_profile: String,
        target_browser: String,
        duration_secs: Option<u64>,
    },
    MigrationPendingList,
    MigrationPendingGet {
        id: String,
    },
    MigrationResolve {
        id: String,
        action: MigrationResolutionAction,
    },
    SshPendingList,
    SshPendingGet {
        id: String,
    },
    /// The daemon owns all reader and key facts. The client supplies only an
    /// opaque pending ID and a fixed action; allowing crosses non-cached polkit.
    SshReadResolve {
        id: String,
        action: SshReadResolutionAction,
    },
    /// Enroll a single SSH private key at runtime (Phase 10). The daemon
    /// canonicalizes + stats `path`, refuses `.pub` / reserved names, enrolls
    /// it as a `SshPrivateKey` resource, and asks the selected access mediator
    /// to intercept read attempts. `path` is the only argument;
    /// no key contents are ever sent.
    SshProtect {
        path: String,
    },
    /// Authorize a one-shot SSH load lease (Phase 11, hardened). The daemon
    /// validates that `path` is a protected SSH private key owned by the
    /// requesting user, then creates a `SshLoadLease` bound to the exact
    /// `ssh-add` process invocation.
    ///
    /// **Security (hardening pass 1):** the client sends ONLY the PID of the
    /// stopped `ssh-add` child. The daemon resolves the process identity from
    /// the platform backend itself —
    /// it does NOT trust client-declared identity fields. This closes the
    /// authorization bypass where a malicious client could declare any identity.
    ///
    /// `uid` is taken from peer creds, NOT from this struct.
    SshLoadAuthorize {
        path: String,
        /// PID of the stopped `ssh-add` child. The daemon verifies this PID's
        /// identity before creating the lease.
        ssh_add_pid: u32,
    },
}

/// Transport-level authorization class. This is shared by Unix and XPC
/// callers so the product protocol does not drift between platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestAuthorization {
    /// Read-only metadata scoped by the kernel-authenticated peer UID.
    Metadata,
    /// A denial/revocation that cannot expand access.
    RestrictiveMutation,
    /// A request capable of creating or changing an access capability.
    SensitiveAllow,
}

impl RequestOp {
    pub const fn authorization(&self) -> RequestAuthorization {
        match self {
            Self::Status
            | Self::ResourcesList
            | Self::BrowsersList
            | Self::ConfigurationGet
            | Self::PendingHelperPoll
            | Self::PendingHelperStatus
            | Self::Events { .. }
            | Self::Explain { .. }
            | Self::LeasesList
            | Self::ConfigCheck
            | Self::MigrationPendingList
            | Self::MigrationPendingGet { .. }
            | Self::SshPendingList
            | Self::SshPendingGet { .. } => RequestAuthorization::Metadata,
            Self::LeasesRevoke { .. }
            | Self::MigrationResolve {
                action: MigrationResolutionAction::Block,
                ..
            }
            | Self::SshReadResolve {
                action: SshReadResolutionAction::Block,
                ..
            } => RequestAuthorization::RestrictiveMutation,
            Self::MigrationAuthorize { .. }
            | Self::ConfigurationApply { .. }
            | Self::MigrationResolve {
                action: MigrationResolutionAction::AllowImport,
                ..
            }
            | Self::SshReadResolve {
                action: SshReadResolutionAction::Allow,
                ..
            }
            | Self::SshProtect { .. }
            | Self::SshLoadAuthorize { .. } => RequestAuthorization::SensitiveAllow,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub version: u32,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<ResponseBody>,
}

impl Response {
    pub fn ok(body: ResponseBody) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            ok: true,
            error: None,
            body: Some(body),
        }
    }
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            ok: false,
            error: Some(msg.into()),
            body: None,
        }
    }
}

/// Adjacently tagged (`{"kind":"...","data":...}`) so that newtype variants
/// wrapping `Vec`/`Box` serialize correctly — serde's internally-tagged
/// representation does not support non-struct newtype variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum ResponseBody {
    Status(Box<StatusInfo>),
    Resources(Vec<ResourceInfo>),
    Browsers(Vec<BrowserInfo>),
    Configuration(ConfigurationInfo),
    ConfigurationApplied {
        version: u32,
    },
    PendingHelper(PendingHelperInfo),
    PendingHelperSnapshot(PendingHelperSnapshotInfo),
    Events(Vec<EventInfo>),
    // Boxed: `EventInfo` is ~328 bytes; boxing keeps the enum small on the
    // hot path (status/events queries) where this variant is never used.
    Explain(Box<EventInfo>),
    Leases(Vec<LeaseInfo>),
    LeaseRevoked {
        lease_id: String,
        found: bool,
    },
    ConfigCheck(ConfigCheckInfo),
    /// Result of `MigrationAuthorize`: the new lease id, its expiry (epoch
    /// seconds), the armed target browser identity (canonical exe path), and
    /// an explicit statement that Linux V1 does not guarantee read-only access.
    MigrationAuthorized(MigrationAuthorizedInfo),
    MigrationPending(Vec<MigrationPendingInfo>),
    MigrationPendingItem(Box<MigrationPendingInfo>),
    MigrationResolved(MigrationResolutionInfo),
    SshPending(Vec<SshPendingInfo>),
    SshPendingItem(Box<SshPendingInfo>),
    SshReadResolved(SshReadResolutionInfo),
    /// Result of `SshProtect`: the now-protected canonical path + owner uid.
    SshProtected(SshProtectedInfo),
    /// Result of `SshLoadAuthorize`: the one-shot lease id and its expiry.
    SshLoadAuthorized(SshLoadAuthorizedInfo),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationResolutionAction {
    AllowImport,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationResolutionInfo {
    Allowed,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshReadResolutionAction {
    Block,
    Allow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshReadResolutionInfo {
    Allowed,
    Blocked,
}

/// Daemon-recorded facts for one protected SSH private-key read waiting on a
/// human decision. This carries metadata only; no key material is exposed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshPendingInfo {
    pub id: String,
    pub uid: u32,
    pub key_path: String,
    pub process_exe: String,
    pub pid: u32,
    pub start_time: u64,
    pub created_at: u64,
    pub expires_at: u64,
}

/// Information about a successfully protected SSH private key. Contains NO key
/// contents — only the canonical path, the file owner uid, and the resource id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshProtectedInfo {
    /// Canonical path now under protection.
    pub path: String,
    /// File owner uid (from stat; authoritative for SSH keys).
    pub owner_uid: u32,
    /// `ProtectedResourceId` (canonical path string).
    pub resource_id: String,
}

/// Result of `SshLoadAuthorize`: the one-shot lease id and its expiry. Contains
/// NO key contents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshLoadAuthorizedInfo {
    pub lease_id: String,
    /// Canonical path of the protected SSH key the lease grants loading.
    pub path: String,
    pub uid: u32,
    pub expires_at: u64,
    /// Root-pinned hardlink to the verified agent socket. Supplying this path
    /// to ssh-add prevents same-UID pathname replacement after authorization.
    pub agent_socket: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationAuthorizedInfo {
    pub lease_id: String,
    pub source_browser: String,
    pub source_profile: String,
    pub target_browser: String,
    /// Canonical exe path the lease is armed against (for user confirmation).
    pub target_exe: String,
    pub uid: u32,
    pub expires_at: u64,
    /// False when the selected access backend cannot expose
    /// the triggering process's original open mode.
    pub read_only_guaranteed: bool,
}

/// Daemon-recorded facts for an import waiting on human confirmation. Clients
/// receive this view only; resolution accepts only `id` plus a fixed action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationPendingInfo {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusInfo {
    pub version: String,
    #[serde(default)]
    pub backend_kind: String,
    #[serde(default)]
    pub backend_diagnostic: Option<String>,
    /// Stable macOS enforcement lifecycle category. This avoids parsing a
    /// localized diagnostic to distinguish approval/FDA/install failures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_state: Option<String>,
    pub enforcement_active: bool,
    /// Whether migration-lease AUTH_OPEN responses are restricted to FREAD.
    /// `None` means the selected backend cannot make that guarantee.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only_guaranteed: Option<bool>,
    /// Human-readable enforcement state (Phase 14): `"ACTIVE"`,
    /// `"DEGRADED"`, or `"NOT_ENFORCING"`.
    /// - `ACTIVE`: access enforcement is running normally.
    /// - `DEGRADED`: enforcement is running but audit events were dropped,
    ///   topology/classification failed, or the authorization queue overflowed.
    /// - `NOT_ENFORCING`: the daemon is running without an access mediator
    ///   (e.g. config-check mode, or the group failed to initialize).
    #[serde(default)]
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default)]
    pub marked_filesystems: Option<usize>,
    #[serde(default)]
    pub required_filesystems: Option<usize>,
    pub filesystem_marks_healthy: Option<bool>,
    #[serde(default)]
    pub strict_events_total: Option<u64>,
    #[serde(default)]
    pub strict_fast_allowed: Option<u64>,
    #[serde(default)]
    pub protected_events: u64,
    #[serde(default)]
    pub fanotify_overflows: Option<u64>,
    #[serde(default)]
    pub classifier_failures: Option<u64>,
    #[serde(default)]
    pub strict_alias_scans: Option<u64>,
    #[serde(default)]
    pub strict_alias_matches: Option<u64>,
    #[serde(default)]
    pub topology_degraded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac_health: Option<Box<MacHealthInfo>>,
    pub protected_files: usize,
    #[serde(default)]
    pub ssh_protected_keys: usize,
    pub protected_trees: usize,
    pub browsers: usize,
    pub browser_exes: usize,
    pub allowed: u64,
    pub denied: u64,
    pub unclassified: u64,
    pub audit_dropped: u64,
    pub peer_uid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacHealthInfo {
    pub es_sequence_gaps: u64,
    pub es_global_sequence_gaps: u64,
    pub pending_created: u64,
    pub pending_resolved_allow: u64,
    pub pending_resolved_deny: u64,
    pub pending_timed_out: u64,
    pub insufficient_deadline: u64,
    pub late_responses: u64,
    pub namespace_allowed: u64,
    pub namespace_denied: u64,
    pub namespace_alias_entries: usize,
    pub namespace_alias_capacity: usize,
    pub namespace_index_saturated: bool,
    pub process_graph_degraded: bool,
    // Process Shield health (MPS2+). Serde-optional so older UI clients can
    // still deserialize status responses.
    #[serde(default)]
    pub task_control_allowed: u64,
    #[serde(default)]
    pub task_control_denied: u64,
    #[serde(default)]
    pub task_read_allowed: u64,
    #[serde(default)]
    pub task_read_denied: u64,
    #[serde(default)]
    pub task_read_supported: bool,
    #[serde(default)]
    pub task_notify_supported: bool,
    #[serde(default)]
    pub shield_admitted: u64,
    #[serde(default)]
    pub shield_preexisting: u64,
    #[serde(default)]
    pub shield_compromised: u64,
    #[serde(default)]
    pub shield_launch_injection_denied: u64,
    #[serde(default)]
    pub shield_malformed_denied: u64,
    #[serde(default)]
    pub shield_task_notify_obtained: u64,
    #[serde(default)]
    pub shield_trace_observed: u64,
    #[serde(default)]
    pub shield_remote_thread_observed: u64,
    #[serde(default)]
    pub shield_cs_invalidated_observed: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_shield: Option<Box<ProcessShieldInfo>>,
}

/// Separate Process Shield status (MPS8). Truthful per-capability state, never
/// a fake global "Protected" flag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessShieldInfo {
    /// Active | Reduced | Unavailable with the exact reason.
    pub state: String,
    pub reason: Option<String>,
    /// task control protection: active / unavailable
    pub task_control_protection: String,
    /// task read protection: active / unavailable (host feature-detected)
    pub task_read_protection: String,
    pub task_read_supported: bool,
    pub task_notify_supported: bool,
    /// launch integrity (AUTH_EXEC admission + DYLD code-loading deny)
    pub launch_integrity: String,
    /// runtime integrity posture summary over enrolled executables
    pub runtime_posture: String,
    pub runtime_posture_strong: usize,
    pub runtime_posture_reduced: usize,
    pub runtime_posture_unverifiable: usize,
    /// notify-only compromise-signal telemetry
    pub injection_telemetry: String,
    pub task_control_allowed: u64,
    pub task_control_denied: u64,
    pub task_read_allowed: u64,
    pub task_read_denied: u64,
    pub shield_admitted: u64,
    pub shield_preexisting: u64,
    pub shield_compromised: u64,
    pub launch_injection_denied: u64,
    pub trace_observed: u64,
    pub remote_thread_observed: u64,
    pub cs_invalidated_observed: u64,
    /// optional library-mapping (AUTH_MMAP) protection: disabled by decision
    /// unless MPS10 enables it with measurements
    pub library_mapping_protection: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceInfo {
    pub id: String,
    pub kind: String,
    pub owner_uid: u32,
    pub browser: Option<String>,
    pub profile: Option<String>,
    pub path: String,
    pub tree: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserInfo {
    pub id: String,
    pub family: String,
    pub profile_root: String,
    pub owner_uid: u32,
    pub exe_paths: Vec<String>,
}

/// Active policy snapshot. It contains paths and policy metadata only, never
/// browser database rows, SSH key bytes, cookies, or credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigurationInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforcement_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_enabled: Option<bool>,
    pub browsers: Vec<ConfiguredBrowserInfo>,
    pub enrolled_exes: Vec<String>,
    pub ssh_keys: Vec<String>,
    #[serde(default)]
    pub mac_system_processes: Vec<MacSystemProcessInfo>,
    #[serde(default)]
    pub mac_trusted_tools: Vec<MacTrustedToolInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacSystemProcessInfo {
    pub path: String,
    pub signing_id: String,
    pub allow_kinds: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacTrustedToolInfo {
    pub path: String,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub dev: u64,
    pub ino: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingHelperInfo {
    pub running: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_ms_ago: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingHelperSnapshotInfo {
    pub migrations: Vec<MigrationPendingInfo>,
    pub ssh_reads: Vec<SshPendingInfo>,
}

/// Browser enrollment exactly as configured, including whether ownership was
/// explicitly pinned or derived by the daemon at startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfiguredBrowserInfo {
    pub id: String,
    pub family: String,
    pub profile_root: String,
    pub owner_uid: Option<u32>,
    pub exe_paths: Vec<String>,
}

/// One audit event as shown to the CLI. Mirrors `guard_audit::AuditEvent` but
/// as a plain wire struct (no storage coupling). Contains NO secret contents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventInfo {
    pub id: i64,
    /// Stable machine-readable event classification. UI code must branch on
    /// this value rather than parsing localized or diagnostic text.
    #[serde(default)]
    pub event_code: String,
    pub ts_ms: u64,
    pub uid: u32,
    pub pid: u32,
    pub start_time: u64,
    pub decision: String,
    pub deny_reason: Option<String>,
    /// Stable machine-readable deny reason code (Phase 12). Tools may branch on
    /// this; the string is a public contract (see `DenyReason::reason_code`).
    /// `None` when the decision was `Allow` / `AllowByLease`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    pub resource_kind: String,
    /// Stable machine-readable resource kind code (Phase 12). Public contract
    /// (see `ProtectedResourceKind::kind_code`). `#[serde(default)]` so events
    /// from an older daemon (pre-Phase-12) still deserialize.
    #[serde(default)]
    pub resource_kind_code: String,
    pub resource_browser: Option<String>,
    pub resource_profile: Option<String>,
    pub path: String,
    pub exe: String,
    pub exe_owner_uid: u32,
    pub trust_tier: String,
    pub process_browser: Option<String>,
    pub parent_pid: Option<u32>,
    pub parent_exe: Option<String>,
    pub lease_id: Option<u64>,
    pub backend_diag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseInfo {
    pub id: String,
    pub kind: String,
    pub uid: u32,
    pub source_browser: Option<String>,
    pub source_profile: Option<String>,
    pub target_browser: Option<String>,
    pub resource: Option<String>,
    /// Migration lifecycle (`armed`, `bound`, `dead`); absent for SSH leases.
    pub state: Option<String>,
    pub expires_at: u64,
    pub revoked: bool,
    pub used: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigCheckInfo {
    pub valid: bool,
    pub browsers: usize,
    pub protected_files: usize,
    pub protected_trees: usize,
    pub enrolled_exes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    //! Protocol round-trip tests: every op serializes and deserializes back to
    //! an equal value, and oversized/malformed payloads are detectable.

    use super::*;

    #[test]
    fn request_round_trips_all_ops() {
        let cases = vec![
            RequestOp::Status,
            RequestOp::ResourcesList,
            RequestOp::BrowsersList,
            RequestOp::ConfigurationGet,
            RequestOp::ConfigurationApply {
                config: serde_json::json!({"version": 1}),
            },
            RequestOp::PendingHelperPoll,
            RequestOp::PendingHelperStatus,
            RequestOp::Events {
                limit: Some(50),
                before_id: None,
                after_id: None,
            },
            RequestOp::Events {
                limit: None,
                before_id: None,
                after_id: None,
            },
            RequestOp::Explain { event_id: 42 },
            RequestOp::LeasesList,
            RequestOp::LeasesRevoke {
                lease_id: "7".into(),
            },
            RequestOp::ConfigCheck,
            RequestOp::MigrationAuthorize {
                source_browser: "chrome".into(),
                source_profile: "Default".into(),
                target_browser: "firefox".into(),
                duration_secs: Some(600),
            },
            RequestOp::MigrationAuthorize {
                source_browser: "chrome".into(),
                source_profile: "Default".into(),
                target_browser: "firefox".into(),
                duration_secs: None,
            },
            RequestOp::MigrationPendingList,
            RequestOp::MigrationPendingGet {
                id: "pending-1".into(),
            },
            RequestOp::MigrationResolve {
                id: "pending-1".into(),
                action: MigrationResolutionAction::AllowImport,
            },
            RequestOp::SshPendingList,
            RequestOp::SshPendingGet { id: "ssh-1".into() },
            RequestOp::SshReadResolve {
                id: "ssh-1".into(),
                action: SshReadResolutionAction::Allow,
            },
            RequestOp::SshProtect {
                path: "/home/u/.ssh/id_ed25519".into(),
            },
            RequestOp::SshLoadAuthorize {
                path: "/home/u/.ssh/id_ed25519".into(),
                ssh_add_pid: 12345,
            },
        ];
        for op in cases {
            let req = Request {
                version: PROTOCOL_VERSION,
                op: op.clone(),
            };
            let json = serde_json::to_string(&req).unwrap();
            let back: Request = serde_json::from_str(&json).unwrap();
            assert_eq!(back.version, PROTOCOL_VERSION);
            assert_eq!(back.op, op);
        }
    }

    #[test]
    fn request_authorization_distinguishes_allow_from_block() {
        assert_eq!(
            RequestOp::Status.authorization(),
            RequestAuthorization::Metadata
        );
        assert_eq!(
            RequestOp::MigrationResolve {
                id: "1".into(),
                action: MigrationResolutionAction::Block,
            }
            .authorization(),
            RequestAuthorization::RestrictiveMutation
        );
        assert_eq!(
            RequestOp::MigrationResolve {
                id: "1".into(),
                action: MigrationResolutionAction::AllowImport,
            }
            .authorization(),
            RequestAuthorization::SensitiveAllow
        );
        assert_eq!(
            RequestOp::SshReadResolve {
                id: "1".into(),
                action: SshReadResolutionAction::Allow,
            }
            .authorization(),
            RequestAuthorization::SensitiveAllow
        );
        assert_eq!(
            RequestOp::ConfigurationApply {
                config: serde_json::json!({"version": 1}),
            }
            .authorization(),
            RequestAuthorization::SensitiveAllow
        );
    }

    #[test]
    fn migration_authorize_request_has_no_uid_field() {
        // Security invariant: the wire request must NOT carry a uid — the
        // daemon takes the authorizing uid from SO_PEERCRED, never from JSON.
        let req = Request {
            version: PROTOCOL_VERSION,
            op: RequestOp::MigrationAuthorize {
                source_browser: "chrome".into(),
                source_profile: "Default".into(),
                target_browser: "firefox".into(),
                duration_secs: None,
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("\"uid\""), "no uid in request: {json}");
        assert!(json.contains("\"kind\":\"migration_authorize\""));
    }

    #[test]
    fn ssh_read_resolution_has_only_fixed_metadata() {
        let request = Request {
            version: PROTOCOL_VERSION,
            op: RequestOp::SshReadResolve {
                id: "ssh-0001".into(),
                action: SshReadResolutionAction::Block,
            },
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(!json.contains("\"uid\""));
        assert!(!json.contains("\"pid\""));
        assert!(!json.contains("\"path\""));
        assert!(json.contains("ssh_read_resolve"));
    }

    #[test]
    fn migration_authorized_response_round_trips() {
        let body = ResponseBody::MigrationAuthorized(MigrationAuthorizedInfo {
            lease_id: "1".into(),
            source_browser: "chrome".into(),
            source_profile: "Default".into(),
            target_browser: "firefox".into(),
            target_exe: "/usr/bin/firefox".into(),
            uid: 1000,
            expires_at: 17_000_000_600,
            read_only_guaranteed: false,
        });
        let resp = Response::ok(body);
        let j = serde_json::to_string(&resp).unwrap();
        let back: Response = serde_json::from_str(&j).unwrap();
        assert!(back.ok);
        match back.body.unwrap() {
            ResponseBody::MigrationAuthorized(m) => {
                assert_eq!(m.lease_id, "1");
                assert_eq!(m.source_browser, "chrome");
                assert_eq!(m.target_browser, "firefox");
                assert_eq!(m.target_exe, "/usr/bin/firefox");
                assert_eq!(m.uid, 1000);
                assert!(!m.read_only_guaranteed);
            }
            other => panic!("expected MigrationAuthorized, got {other:?}"),
        }
    }

    #[test]
    fn ssh_protected_response_round_trips() {
        let body = ResponseBody::SshProtected(SshProtectedInfo {
            path: "/home/u/.ssh/id_ed25519".into(),
            owner_uid: 1000,
            resource_id: "/home/u/.ssh/id_ed25519".into(),
        });
        let resp = Response::ok(body);
        let j = serde_json::to_string(&resp).unwrap();
        let back: Response = serde_json::from_str(&j).unwrap();
        assert!(back.ok);
        match back.body.unwrap() {
            ResponseBody::SshProtected(s) => {
                assert_eq!(s.path, "/home/u/.ssh/id_ed25519");
                assert_eq!(s.owner_uid, 1000);
                assert_eq!(s.resource_id, "/home/u/.ssh/id_ed25519");
                // No secret-content keys leak into the wire JSON.
                assert!(!j.contains("\"content\""));
                assert!(!j.contains("\"key_bytes\""));
            }
            other => panic!("expected SshProtected, got {other:?}"),
        }
    }

    #[test]
    fn ssh_load_authorize_request_has_no_uid_field() {
        // Security invariant: the wire request must NOT carry a uid — the
        // daemon takes the authorizing uid from SO_PEERCRED, never from JSON.
        let req = Request {
            version: PROTOCOL_VERSION,
            op: RequestOp::SshLoadAuthorize {
                path: "/home/u/.ssh/id_ed25519".into(),
                ssh_add_pid: 12345,
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("\"uid\""), "no uid in request: {json}");
        assert!(json.contains("\"kind\":\"ssh_load_authorize\""));
        // No key-content fields.
        assert!(!json.contains("\"content\""));
        assert!(!json.contains("\"key_bytes\""));
        assert!(!json.contains("\"private_key\""));
    }

    #[test]
    fn ssh_load_authorized_response_round_trips() {
        let body = ResponseBody::SshLoadAuthorized(SshLoadAuthorizedInfo {
            lease_id: "5".into(),
            path: "/home/u/.ssh/id_ed25519".into(),
            uid: 1000,
            expires_at: 17_000_000_030,
            agent_socket: "/tmp/.guardd-agent-pins/a-1000-5.sock".into(),
        });
        let resp = Response::ok(body);
        let j = serde_json::to_string(&resp).unwrap();
        let back: Response = serde_json::from_str(&j).unwrap();
        assert!(back.ok);
        match back.body.unwrap() {
            ResponseBody::SshLoadAuthorized(s) => {
                assert_eq!(s.lease_id, "5");
                assert_eq!(s.path, "/home/u/.ssh/id_ed25519");
                assert_eq!(s.uid, 1000);
                assert!(s.expires_at > 0);
                assert!(s.agent_socket.contains(".guardd-agent-pins"));
                assert!(!j.contains("\"content\""));
                assert!(!j.contains("\"key_bytes\""));
            }
            other => panic!("expected SshLoadAuthorized, got {other:?}"),
        }
    }

    #[test]
    fn response_ok_and_err_round_trip() {
        let ok = Response::ok(ResponseBody::Status(Box::new(StatusInfo {
            version: "0.1.0".into(),
            backend_kind: "linux-fanotify".into(),
            backend_diagnostic: None,
            backend_state: None,
            enforcement_active: true,
            read_only_guaranteed: None,
            status: "ACTIVE".into(),
            mode: Some("strict-filesystem".into()),
            marked_filesystems: Some(1),
            required_filesystems: Some(1),
            filesystem_marks_healthy: Some(true),
            strict_events_total: Some(10),
            strict_fast_allowed: Some(8),
            protected_events: 2,
            fanotify_overflows: Some(0),
            classifier_failures: Some(0),
            strict_alias_scans: Some(3),
            strict_alias_matches: Some(2),
            topology_degraded: Some(false),
            mac_health: None,
            protected_files: 6,
            protected_trees: 2,
            browsers: 1,
            browser_exes: 1,
            allowed: 3,
            denied: 5,
            unclassified: 0,
            audit_dropped: 0,
            peer_uid: 1000,
            ssh_protected_keys: 0,
        })));
        let j = serde_json::to_string(&ok).unwrap();
        let back: Response = serde_json::from_str(&j).unwrap();
        assert!(back.ok);
        assert!(back.error.is_none());

        let err = Response::err("nope");
        let j = serde_json::to_string(&err).unwrap();
        let back: Response = serde_json::from_str(&j).unwrap();
        assert!(!back.ok);
        assert_eq!(back.error.as_deref(), Some("nope"));
        assert!(back.body.is_none());
    }

    #[test]
    fn status_can_omit_linux_backend_details() {
        let json = r#"{
            "version":"0.1.0","backend_kind":"macos-endpoint-security",
            "enforcement_active":true,"status":"ACTIVE","protected_events":1,
            "protected_files":2,"ssh_protected_keys":1,"protected_trees":1,
            "browsers":1,"browser_exes":2,"allowed":3,"denied":4,
            "unclassified":0,"audit_dropped":0,"peer_uid":501
        }"#;
        let status: StatusInfo = serde_json::from_str(json).unwrap();
        assert_eq!(status.backend_kind, "macos-endpoint-security");
        assert!(status.mode.is_none());
        assert!(status.marked_filesystems.is_none());
        assert!(status.fanotify_overflows.is_none());
    }

    #[test]
    fn mac_health_is_typed_and_backward_optional() {
        let json = r#"{
            "version":"0.1.0","backend_kind":"macos-endpoint-security",
            "backend_state":"DEGRADED","enforcement_active":true,
            "status":"DEGRADED","protected_events":1,"protected_files":2,
            "ssh_protected_keys":1,"protected_trees":1,"browsers":1,
            "browser_exes":2,"allowed":3,"denied":4,"unclassified":0,
            "audit_dropped":0,"peer_uid":501,
            "mac_health":{"es_sequence_gaps":2,"es_global_sequence_gaps":1,
            "pending_created":3,"pending_resolved_allow":1,
            "pending_resolved_deny":2,"pending_timed_out":1,
            "insufficient_deadline":1,"late_responses":0,
            "namespace_allowed":4,"namespace_denied":5,
            "namespace_alias_entries":6,"namespace_alias_capacity":65536,
            "namespace_index_saturated":false,"process_graph_degraded":true}
        }"#;
        let status: StatusInfo = serde_json::from_str(json).unwrap();
        assert_eq!(status.backend_state.as_deref(), Some("DEGRADED"));
        let health = status.mac_health.unwrap();
        assert_eq!(health.es_sequence_gaps, 2);
        assert_eq!(health.pending_timed_out, 1);
        assert_eq!(health.namespace_denied, 5);
        assert!(health.process_graph_degraded);
    }
}
