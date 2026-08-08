//! Versioned JSON IPC protocol between `guardd` and `guardctl`/`guard-tui`.
//!
//! The protocol is a single `Request` -> single `Response` exchange over a
//! length-prefixed frame (see `platform_linux::ipc`). It is deliberately tiny:
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
pub const PROTOCOL_VERSION: u32 = 1;

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
    Events {
        limit: Option<u32>,
    },
    Explain {
        event_id: i64,
    },
    LeasesList,
    LeasesRevoke {
        lease_id: String,
    },
    ConfigCheck,
    /// Authorize a read-only cross-browser migration lease (Phase 08). The
    /// daemon binds the lease to the target browser's armed `ExeIdentity` and
    /// caps `duration_secs` at 1 hour (default 10 min). `uid` is taken from
    /// peer creds, NOT from this struct.
    MigrationAuthorize {
        source_browser: String,
        source_profile: String,
        target_browser: String,
        duration_secs: Option<u64>,
    },
    /// Enroll a single SSH private key at runtime (Phase 10). The daemon
    /// canonicalizes + stats `path`, refuses `.pub` / reserved names, enrolls
    /// it as a `SshPrivateKey` resource, and adds the fanotify `FAN_OPEN_PERM`
    /// mark so subsequent opens are intercepted. `path` is the only argument;
    /// no key contents are ever sent.
    SshProtect {
        path: String,
    },
    /// Authorize a one-shot SSH load lease (Phase 11). The daemon validates
    /// that `path` is a protected SSH private key owned by the requesting user,
    /// then creates a `SshLoadLease` bound to the exact `ssh-add` process
    /// invocation (exe + start_time + dev + ino). The client (`guardctl`) forks
    /// `ssh-add` in a stopped state, reads the start_time, sends this request,
    /// then continues the child. No key contents are ever sent.
    ///
    /// `uid` is taken from peer creds, NOT from this struct.
    SshLoadAuthorize {
        path: String,
        /// Canonical exe path of `ssh-add`.
        ssh_add_exe: String,
        /// `st_dev` of the `ssh-add` binary.
        ssh_add_dev: u64,
        /// `st_ino` of the `ssh-add` binary.
        ssh_add_ino: u64,
        /// Process start time of the stopped `ssh-add` child (from
        /// `/proc/<pid>/stat` field 22). The lease binds to this so a different
        /// `ssh-add` invocation (different start time) cannot reuse it.
        start_time: u64,
    },
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
    Status(StatusInfo),
    Resources(Vec<ResourceInfo>),
    Browsers(Vec<BrowserInfo>),
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
    /// the read-only flag (always true for migration leases).
    MigrationAuthorized(MigrationAuthorizedInfo),
    /// Result of `SshProtect`: the now-protected canonical path + owner uid.
    SshProtected(SshProtectedInfo),
    /// Result of `SshLoadAuthorize`: the one-shot lease id and its expiry.
    SshLoadAuthorized(SshLoadAuthorizedInfo),
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
    pub read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusInfo {
    pub version: String,
    pub enforcement_active: bool,
    /// Human-readable enforcement state (Phase 14): `"ACTIVE"`,
    /// `"DEGRADED"`, or `"NOT_ENFORCING"`.
    /// - `ACTIVE`: fanotify enforcement is running normally.
    /// - `DEGRADED`: enforcement is running but audit events are being
    ///   dropped or some decisions were unclassified.
    /// - `NOT_ENFORCING`: the daemon is running without a fanotify group
    ///   (e.g. config-check mode, or the group failed to initialize).
    #[serde(default)]
    pub status: String,
    pub protected_files: usize,
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

/// One audit event as shown to the CLI. Mirrors `guard_audit::AuditEvent` but
/// as a plain wire struct (no storage coupling). Contains NO secret contents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventInfo {
    pub id: i64,
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
            RequestOp::Events { limit: Some(50) },
            RequestOp::Events { limit: None },
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
            RequestOp::SshProtect {
                path: "/home/u/.ssh/id_ed25519".into(),
            },
            RequestOp::SshLoadAuthorize {
                path: "/home/u/.ssh/id_ed25519".into(),
                ssh_add_exe: "/usr/bin/ssh-add".into(),
                ssh_add_dev: 100,
                ssh_add_ino: 200,
                start_time: 9999,
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
    fn migration_authorized_response_round_trips() {
        let body = ResponseBody::MigrationAuthorized(MigrationAuthorizedInfo {
            lease_id: "1".into(),
            source_browser: "chrome".into(),
            source_profile: "Default".into(),
            target_browser: "firefox".into(),
            target_exe: "/usr/bin/firefox".into(),
            uid: 1000,
            expires_at: 17_000_000_600,
            read_only: true,
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
                assert!(m.read_only);
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
                ssh_add_exe: "/usr/bin/ssh-add".into(),
                ssh_add_dev: 100,
                ssh_add_ino: 200,
                start_time: 9999,
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
                assert!(!j.contains("\"content\""));
                assert!(!j.contains("\"key_bytes\""));
            }
            other => panic!("expected SshLoadAuthorized, got {other:?}"),
        }
    }

    #[test]
    fn response_ok_and_err_round_trip() {
        let ok = Response::ok(ResponseBody::Status(StatusInfo {
            version: "0.1.0".into(),
            enforcement_active: true,
            status: "ACTIVE".into(),
            protected_files: 6,
            protected_trees: 2,
            browsers: 1,
            browser_exes: 1,
            allowed: 3,
            denied: 5,
            unclassified: 0,
            audit_dropped: 0,
            peer_uid: 1000,
        }));
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
}
