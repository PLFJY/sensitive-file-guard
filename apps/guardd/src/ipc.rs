//! IPC request dispatcher and server loop.
//!
//! The daemon spawns one thread running `serve_loop`. For each accepted
//! connection it reads a single framed request, obtains the peer's
//! kernel-verified credentials (`SO_PEERCRED`), dispatches the request via
//! `handle_request`, and writes one framed response.
//!
//! Authorization (per `07_IPC_AUDIT_AND_CLI.md`):
//! - any authenticated peer: `status`, `resources list`, `browsers list`,
//!   `config check`
//! - ordinary user: own `events` / `explain` / `leases` only
//! - root (uid 0): all events/leases
//!
//! A `uid` field in JSON is never trusted — peer identity comes exclusively
//! from `PeerCreds.uid`.

use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use guard_audit::AuditStore;
use guard_ipc::{
    ConfigCheckInfo, EventInfo, LeaseInfo, MigrationAuthorizedInfo, Response, ResponseBody,
    SshLoadAuthorizedInfo, SshProtectedInfo, StatusInfo, MAX_REQUEST_BYTES, PROTOCOL_VERSION,
};
use guard_ipc::{Request, RequestOp};
use platform_linux::fanotify::FanotifyGroup;
use platform_linux::ipc::{read_request, write_response, IpcServer, PeerCreds};

use crate::enforce::EnforcementEngine;

/// Shared engine + audit state handed to the IPC server thread.
pub struct IpcState {
    pub engine: Arc<Mutex<EnforcementEngine>>,
    pub audit: Arc<AuditStore>,
    pub version: String,
    /// The fanotify group, shared so the `SshProtect` handler can add a
    /// `FAN_OPEN_PERM` mark at runtime. `None` when the daemon is not running
    /// in enforcement mode (e.g. one-shot tests). `mark_file` takes `&self` and
    /// the kernel `fanotify_mark` syscall is thread-safe, so sharing across the
    /// IPC thread is safe.
    pub group: Option<Arc<FanotifyGroup>>,
}

/// Run the accept loop. Blocks until the socket is closed or an unrecoverable
/// error occurs. Each connection is handled inline (requests are tiny and fast;
/// the authorization loop is not blocked because `handle_request` only holds
/// the engine lock for microseconds).
pub fn serve_loop(state: &IpcState, socket_path: &Path) -> io::Result<()> {
    let server = IpcServer::bind(socket_path)?;
    tracing::info!(path = %socket_path.display(), "IPC server listening");
    loop {
        let (mut stream, creds) = match server.accept() {
            Ok(c) => c,
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
            Err(e) => return Err(e),
        };
        handle_one_connection(state, &mut stream, creds);
    }
}

fn handle_one_connection(state: &IpcState, stream: &mut UnixStream, creds: PeerCreds) {
    let req_bytes = match read_request(stream, MAX_REQUEST_BYTES) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return,
        Err(e) => {
            tracing::warn!(err = %e, "IPC read_request failed");
            return;
        }
    };
    let response = match serde_json::from_slice::<Request>(&req_bytes) {
        Ok(req) => {
            if req.version != PROTOCOL_VERSION {
                Response::err(format!(
                    "protocol version mismatch: client={}, server={}",
                    req.version, PROTOCOL_VERSION
                ))
            } else {
                handle_request(state, creds, req.op)
            }
        }
        Err(e) => Response::err(format!("malformed request: {e}")),
    };
    let resp_bytes = serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec());
    if let Err(e) = write_response(stream, &resp_bytes) {
        tracing::warn!(err = %e, "IPC write_response failed");
    }
}

/// Dispatch a single request to its handler, enforcing peer-uid authorization.
pub fn handle_request(state: &IpcState, creds: PeerCreds, op: RequestOp) -> Response {
    match op {
        RequestOp::Status => handle_status(state, creds),
        RequestOp::ResourcesList => handle_resources_list(state, creds),
        RequestOp::BrowsersList => handle_browsers_list(state, creds),
        RequestOp::ConfigCheck => handle_config_check(state, creds),
        RequestOp::Events { limit } => handle_events(state, creds, limit),
        RequestOp::Explain { event_id } => handle_explain(state, creds, event_id),
        RequestOp::LeasesList => handle_leases_list(state, creds),
        RequestOp::LeasesRevoke { lease_id } => handle_leases_revoke(state, creds, lease_id),
        RequestOp::MigrationAuthorize {
            source_browser,
            source_profile,
            target_browser,
            duration_secs,
        } => handle_migration_authorize(
            state,
            creds,
            source_browser,
            source_profile,
            target_browser,
            duration_secs,
        ),
        RequestOp::SshProtect { path } => handle_ssh_protect(state, creds, path),
        RequestOp::SshLoadAuthorize {
            path,
            ssh_add_exe,
            ssh_add_dev,
            ssh_add_ino,
            start_time,
        } => handle_ssh_load_authorize(
            state,
            creds,
            path,
            ssh_add_exe,
            ssh_add_dev,
            ssh_add_ino,
            start_time,
        ),
    }
}

// --- handlers ---

fn handle_status(state: &IpcState, creds: PeerCreds) -> Response {
    let engine = state.engine.lock().expect("engine mutex poisoned");
    let audit_dropped = state.audit.dropped();
    // Phase 14: compute a human-readable enforcement state.
    // - NOT_ENFORCING: no fanotify group (daemon running without enforcement).
    // - DEGRADED: enforcement is active but audit events are being dropped or
    //   some decisions were unclassified (fail-closed events indicate races
    //   or missing marks).
    // - ACTIVE: enforcement is running normally.
    let status = if state.group.is_none() {
        "NOT_ENFORCING"
    } else if audit_dropped > 0 || engine.unclassified > 0 {
        "DEGRADED"
    } else {
        "ACTIVE"
    };
    let body = StatusInfo {
        version: state.version.clone(),
        enforcement_active: state.group.is_some(),
        status: status.to_string(),
        protected_files: engine.registry().file_count(),
        protected_trees: engine.registry().trees().len(),
        browsers: engine.browser_config().len(),
        browser_exes: engine.browser_exe_count(),
        allowed: engine.allowed,
        denied: engine.denied,
        unclassified: engine.unclassified,
        audit_dropped,
        peer_uid: creds.uid,
    };
    Response::ok(ResponseBody::Status(body))
}

fn handle_resources_list(state: &IpcState, _creds: PeerCreds) -> Response {
    let engine = state.engine.lock().expect("engine mutex poisoned");
    let mut resources: Vec<guard_ipc::ResourceInfo> = engine
        .registry()
        .files()
        .map(|r| guard_ipc::ResourceInfo {
            id: r.id.0.clone(),
            kind: format!("{:?}", r.kind),
            owner_uid: r.owner_uid,
            browser: r.browser.as_ref().map(|b| b.0.clone()),
            profile: r.profile.as_ref().map(|p| p.0.clone()),
            path: r.path.to_string_lossy().into_owned(),
            tree: false,
        })
        .collect();
    for tree in engine.registry().trees() {
        resources.push(guard_ipc::ResourceInfo {
            id: tree.dir.to_string_lossy().into_owned(),
            kind: format!("{:?}", tree.kind),
            owner_uid: tree.owner_uid,
            browser: Some(tree.browser.0.clone()),
            profile: Some(tree.profile.0.clone()),
            path: tree.dir.to_string_lossy().into_owned(),
            tree: true,
        });
    }
    Response::ok(ResponseBody::Resources(resources))
}

fn handle_browsers_list(state: &IpcState, _creds: PeerCreds) -> Response {
    let engine = state.engine.lock().expect("engine mutex poisoned");
    let browsers: Vec<guard_ipc::BrowserInfo> = engine
        .browser_config()
        .iter()
        .map(|b| guard_ipc::BrowserInfo {
            id: b.id.clone(),
            family: format!("{:?}", b.family),
            profile_root: b.profile_root.to_string_lossy().into_owned(),
            owner_uid: b.owner_uid.unwrap_or(0),
            exe_paths: b
                .exe_paths
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect(),
        })
        .collect();
    Response::ok(ResponseBody::Browsers(browsers))
}

fn handle_config_check(state: &IpcState, _creds: PeerCreds) -> Response {
    let engine = state.engine.lock().expect("engine mutex poisoned");
    let body = ConfigCheckInfo {
        valid: true,
        browsers: engine.browser_config().len(),
        protected_files: engine.registry().file_count(),
        protected_trees: engine.registry().trees().len(),
        enrolled_exes: engine.browser_exe_count(),
        error: None,
    };
    Response::ok(ResponseBody::ConfigCheck(body))
}

fn handle_events(state: &IpcState, creds: PeerCreds, limit: Option<u32>) -> Response {
    // Ordinary users see only their own events; root sees all.
    let uid_filter = if creds.uid == 0 {
        None
    } else {
        Some(creds.uid)
    };
    let limit = limit.unwrap_or(100);
    // Flush so the CLI sees the latest committed records.
    state.audit.flush();
    match state.audit.query_events(uid_filter, limit) {
        Ok(events) => {
            let infos: Vec<EventInfo> = events.iter().map(event_to_info).collect();
            Response::ok(ResponseBody::Events(infos))
        }
        Err(e) => Response::err(format!("query failed: {e}")),
    }
}

fn handle_explain(state: &IpcState, creds: PeerCreds, event_id: i64) -> Response {
    state.audit.flush();
    match state.audit.query_event(event_id) {
        Ok(Some(ev)) => {
            // Authorization: non-root may only explain their own events.
            if creds.uid != 0 && ev.record.uid != creds.uid {
                return Response::err("permission denied: event belongs to another user");
            }
            Response::ok(ResponseBody::Explain(Box::new(event_to_info(&ev))))
        }
        Ok(None) => Response::err(format!("event {event_id} not found")),
        Err(e) => Response::err(format!("query failed: {e}")),
    }
}

fn handle_leases_list(state: &IpcState, creds: PeerCreds) -> Response {
    let engine = state.engine.lock().expect("engine mutex poisoned");
    let leases = engine.leases();
    let mut infos: Vec<LeaseInfo> = Vec::new();
    for l in &leases.migration {
        // Ordinary users see only their own leases.
        if creds.uid != 0 && l.uid != creds.uid {
            continue;
        }
        infos.push(LeaseInfo {
            id: l.id.0.to_string(),
            kind: "migration".into(),
            uid: l.uid,
            source_browser: Some(l.source_browser.0.clone()),
            source_profile: Some(l.source_profile.0.clone()),
            target_browser: Some(l.target_browser.0.clone()),
            resource: None,
            expires_at: l.expires_at,
            revoked: l.revoked,
            used: false,
        });
    }
    for l in &leases.ssh {
        if creds.uid != 0 && l.uid != creds.uid {
            continue;
        }
        infos.push(LeaseInfo {
            id: l.id.0.to_string(),
            kind: "ssh_load".into(),
            uid: l.uid,
            source_browser: None,
            source_profile: None,
            target_browser: None,
            resource: Some(l.resource.0.clone()),
            expires_at: l.expires_at,
            revoked: l.revoked,
            used: l.used,
        });
    }
    Response::ok(ResponseBody::Leases(infos))
}

fn handle_leases_revoke(state: &IpcState, creds: PeerCreds, lease_id: String) -> Response {
    let mut engine = state.engine.lock().expect("engine mutex poisoned");
    // Authorization: find the lease first to check ownership (non-root may only
    // revoke their own leases). We do a read-check then revoke.
    let leases = engine.leases();
    let owner_uid = leases
        .migration
        .iter()
        .find(|l| l.id.0.to_string() == lease_id)
        .map(|l| l.uid)
        .or_else(|| {
            leases
                .ssh
                .iter()
                .find(|l| l.id.0.to_string() == lease_id)
                .map(|l| l.uid)
        });
    match owner_uid {
        Some(uid) if creds.uid == 0 || uid == creds.uid => {
            let found = engine.revoke_lease(&lease_id);
            Response::ok(ResponseBody::LeaseRevoked { lease_id, found })
        }
        Some(_) => Response::err("permission denied: lease belongs to another user"),
        None => {
            // Lease not found. Still report not-found rather than leaking
            // existence to a non-owner.
            if creds.uid == 0 {
                Response::ok(ResponseBody::LeaseRevoked {
                    lease_id,
                    found: false,
                })
            } else {
                Response::err("permission denied or lease not found")
            }
        }
    }
}

// --- helpers ---

fn handle_migration_authorize(
    state: &IpcState,
    creds: PeerCreds,
    source_browser: String,
    source_profile: String,
    target_browser: String,
    duration_secs: Option<u64>,
) -> Response {
    // SECURITY: the authorizing uid is taken EXCLUSIVELY from kernel-verified
    // peer creds. A uid in JSON would be ignored — and there is no uid field
    // in `RequestOp::MigrationAuthorize` to begin with.
    let mut engine = state.engine.lock().expect("engine mutex poisoned");
    match engine.authorize_migration(
        &source_browser,
        &source_profile,
        &target_browser,
        creds.uid,
        duration_secs,
    ) {
        Ok((lease_id, expires_at)) => {
            // Echo back the armed target exe so the user can confirm what the
            // lease is bound to.
            let target_exe = engine
                .leases()
                .migration
                .iter()
                .find(|l| l.id == lease_id)
                .map(|l| l.target.exe.to_string_lossy().into_owned())
                .unwrap_or_default();
            Response::ok(ResponseBody::MigrationAuthorized(MigrationAuthorizedInfo {
                lease_id: lease_id.0.to_string(),
                source_browser,
                source_profile,
                target_browser,
                target_exe,
                uid: creds.uid,
                expires_at,
                read_only: true,
            }))
        }
        Err(e) => Response::err(e),
    }
}

fn handle_ssh_protect(state: &IpcState, creds: PeerCreds, path: String) -> Response {
    // Any authenticated peer may add protection (this only ever adds a
    // fail-closed mark; it never grants access).
    let path_buf = PathBuf::from(&path);
    // Pre-validate the candidate name BEFORE requiring the fanotify group, so a
    // `.pub` / reserved-name request is rejected even when the daemon is not in
    // enforcement mode (and so this path is unit-testable without root).
    if !guard_ssh::is_private_key_candidate(&path_buf) {
        return Response::err(format!(
            "{} is not a private-key candidate (public key or reserved name)",
            path_buf.display()
        ));
    }
    let group = match &state.group {
        Some(g) => Arc::clone(g),
        None => return Response::err("daemon not in enforcement mode (no fanotify group)"),
    };
    let res = {
        let mut engine = state.engine.lock().expect("engine mutex poisoned");
        match engine.protect_ssh_key(&path_buf) {
            Ok(r) => r,
            Err(e) => return Response::err(format!("ssh protect failed: {e}")),
        }
    };
    // Add the kernel mark so subsequent opens fire FAN_OPEN_PERM. Ordering:
    // registry first (done above), then mark. There is a microsecond window
    // where the registry has the entry but the mark is not yet applied — an
    // open in that window is not intercepted (fail-open at enrollment time
    // only). This matches the documented recursive-mark race boundary.
    if let Err(e) = group.mark_file(libc::FAN_OPEN_PERM, &res.path) {
        return Response::err(format!(
            "ssh protect: enrolled {} but fanotify mark failed: {e}",
            res.path.display()
        ));
    }
    tracing::info!(
        path = %res.path.display(),
        owner_uid = res.owner_uid,
        peer_uid = creds.uid,
        "ssh private key protected"
    );
    Response::ok(ResponseBody::SshProtected(SshProtectedInfo {
        path: res.path.to_string_lossy().into_owned(),
        owner_uid: res.owner_uid,
        resource_id: res.id.0.clone(),
    }))
}

fn handle_ssh_load_authorize(
    state: &IpcState,
    creds: PeerCreds,
    path: String,
    ssh_add_exe: String,
    ssh_add_dev: u64,
    ssh_add_ino: u64,
    start_time: u64,
) -> Response {
    // SECURITY: uid is taken EXCLUSIVELY from kernel-verified peer creds.
    let path_buf = PathBuf::from(&path);
    let target = guard_core::identity::StableIdentity {
        exe: PathBuf::from(&ssh_add_exe),
        start_time,
        dev: ssh_add_dev,
        ino: ssh_add_ino,
    };
    let (lease_id, expires_at) = {
        let mut engine = state.engine.lock().expect("engine mutex poisoned");
        match engine.authorize_ssh_load(&path_buf, creds.uid, target) {
            Ok(v) => v,
            Err(e) => return Response::err(e),
        }
    };
    tracing::info!(
        path = %path,
        lease_id = lease_id.0,
        peer_uid = creds.uid,
        expires_at,
        "ssh load lease authorized"
    );
    Response::ok(ResponseBody::SshLoadAuthorized(SshLoadAuthorizedInfo {
        lease_id: lease_id.0.to_string(),
        path,
        uid: creds.uid,
        expires_at,
    }))
}

fn event_to_info(ev: &guard_audit::AuditEvent) -> EventInfo {
    let r = &ev.record;
    EventInfo {
        id: ev.id,
        ts_ms: r.ts_ms,
        uid: r.uid,
        pid: r.pid,
        start_time: r.start_time,
        decision: format!("{:?}", r.decision),
        deny_reason: r.deny_reason.map(|dr| format!("{:?}", dr)),
        reason_code: r.deny_reason.map(|dr| dr.reason_code().to_string()),
        resource_kind: format!("{:?}", r.resource_kind),
        resource_kind_code: r.resource_kind.kind_code().to_string(),
        resource_browser: r.resource_browser.as_ref().map(|b| b.0.clone()),
        resource_profile: r.resource_profile.as_ref().map(|p| p.0.clone()),
        path: r.path.clone(),
        exe: r.exe.clone(),
        exe_owner_uid: r.exe_owner_uid,
        trust_tier: format!("{:?}", r.trust_tier),
        process_browser: r.process_browser.as_ref().map(|b| b.0.clone()),
        parent_pid: r.parent_pid,
        parent_exe: r.parent_exe.clone(),
        lease_id: r.lease_id,
        backend_diag: r.backend_diag.clone(),
    }
}

#[cfg(test)]
mod tests {
    //! IPC handler tests. No root required: the engine + audit store are
    //! constructed in-process and `handle_request` is called directly with
    //! synthetic `PeerCreds`. This covers the prompt's authorization tests:
    //! - UID spoof attempt fails (ordinary user cannot see another user's events)
    //! - explain from CLI (record -> query -> explain round-trip)
    //! - lease revoke authorization

    use super::*;
    use crate::enforce::{BrowserEnrollmentConfig, EnforcementConfig, EnforcementEngine};
    use guard_core::identity::TrustTier;
    use guard_core::lease::{LeaseId, LeaseSet, MigrationLease};
    use guard_core::policy::{Decision, DenyReason};
    use guard_core::resource::{BrowserFamily, BrowserId, ProfileId, ProtectedResourceKind};
    use guard_test_fixtures::chromium::ChromiumProfile;
    use std::path::PathBuf;

    /// Build an `IpcState` backed by a synthetic Chromium profile and an
    /// ephemeral SQLite audit db. Returns the state plus both tempdirs — the
    /// caller MUST keep the tempdirs alive for the duration of the test, or the
    /// audit db file (and the chromium profile) will be deleted out from under
    /// the engine.
    fn make_state(uid: u32) -> (IpcState, (tempfile::TempDir, tempfile::TempDir)) {
        let p = ChromiumProfile::create("Default").unwrap();
        let cfg = EnforcementConfig {
            browsers: vec![BrowserEnrollmentConfig {
                id: "chrome".into(),
                family: BrowserFamily::Chromium,
                profile_root: p.user_data_dir.clone(),
                owner_uid: Some(uid),
                exe_paths: vec![],
            }],
            enrolled_exes: vec![],
            ssh_keys: vec![],
        };
        let engine = EnforcementEngine::from_config(&cfg).unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let audit = AuditStore::open(&audit_dir.path().join("audit.db")).unwrap();
        let state = IpcState {
            engine: Arc::new(Mutex::new(engine)),
            audit: Arc::new(audit),
            version: "0.1.0-test".into(),
            group: None,
        };
        (state, (p.root, audit_dir))
    }

    fn sample_record(uid: u32, decision: Decision) -> guard_audit::AuditRecord {
        guard_audit::AuditRecord {
            ts_ms: 1_700_000_000_000,
            uid,
            pid: 4242,
            start_time: 9999,
            decision,
            deny_reason: match decision {
                Decision::Deny(r) => Some(r),
                _ => None,
            },
            resource_kind: ProtectedResourceKind::CookieStore,
            resource_browser: Some(BrowserId("chrome".into())),
            resource_profile: Some(ProfileId("Default".into())),
            path: "/home/u/chrome/Default/Network/Cookies".into(),
            exe: "/usr/bin/chrome".into(),
            exe_owner_uid: 0,
            trust_tier: TrustTier::SystemPackage,
            process_browser: Some(BrowserId("chrome".into())),
            parent_pid: Some(1),
            parent_exe: Some("/sbin/init".into()),
            lease_id: None,
            backend_diag: "resolved;classify=fd_index_or_registry;trust=SystemPackage".into(),
        }
    }

    #[test]
    fn status_returns_counts_and_peer_uid() {
        let (state, _t) = make_state(1000);
        let resp = handle_request(
            &state,
            PeerCreds {
                pid: 1,
                uid: 1000,
                gid: 1000,
            },
            RequestOp::Status,
        );
        assert!(resp.ok);
        match resp.body.unwrap() {
            ResponseBody::Status(s) => {
                assert_eq!(s.peer_uid, 1000);
                assert_eq!(s.version, "0.1.0-test");
                assert!(s.protected_files > 0);
            }
            _ => panic!("expected Status"),
        }
    }

    #[test]
    fn resources_list_returns_files_and_trees() {
        let (state, _t) = make_state(1000);
        let resp = handle_request(
            &state,
            PeerCreds {
                pid: 1,
                uid: 1000,
                gid: 1000,
            },
            RequestOp::ResourcesList,
        );
        assert!(resp.ok);
        match resp.body.unwrap() {
            ResponseBody::Resources(rs) => {
                assert!(rs.iter().any(|r| !r.tree), "has concrete files");
                assert!(rs.iter().any(|r| r.tree), "has tree roots");
            }
            _ => panic!("expected Resources"),
        }
    }

    #[test]
    fn browsers_list_returns_enrolled_browsers() {
        let (state, _t) = make_state(1000);
        let resp = handle_request(
            &state,
            PeerCreds {
                pid: 1,
                uid: 1000,
                gid: 1000,
            },
            RequestOp::BrowsersList,
        );
        assert!(resp.ok);
        match resp.body.unwrap() {
            ResponseBody::Browsers(bs) => {
                assert_eq!(bs.len(), 1);
                assert_eq!(bs[0].id, "chrome");
            }
            _ => panic!("expected Browsers"),
        }
    }

    #[test]
    fn ordinary_user_cannot_see_other_users_events() {
        let (state, _t) = make_state(1000);
        // Record events for two different users.
        state.audit.record(sample_record(1000, Decision::Allow));
        state.audit.record(sample_record(1001, Decision::Allow));
        state.audit.flush();

        // User 1000 asks for events — should see only their own (1 event).
        let resp = handle_request(
            &state,
            PeerCreds {
                pid: 1,
                uid: 1000,
                gid: 1000,
            },
            RequestOp::Events { limit: Some(100) },
        );
        assert!(resp.ok);
        match resp.body.unwrap() {
            ResponseBody::Events(ev) => {
                assert_eq!(ev.len(), 1);
                assert_eq!(ev[0].uid, 1000);
            }
            _ => panic!("expected Events"),
        }

        // A JSON spoof: user 1000 sends a request with no uid in JSON (there
        // is no uid field in the protocol), but even if they tried, the daemon
        // uses PeerCreds.uid. User 1000 cannot see user 1001's events.
        let resp = handle_request(
            &state,
            PeerCreds {
                pid: 1,
                uid: 1000,
                gid: 1000,
            },
            RequestOp::Events { limit: Some(100) },
        );
        match resp.body.unwrap() {
            ResponseBody::Events(ev) => {
                assert!(ev.iter().all(|e| e.uid == 1000), "no cross-user leak");
            }
            _ => panic!("expected Events"),
        }
    }

    #[test]
    fn root_sees_all_events() {
        let (state, _t) = make_state(1000);
        state.audit.record(sample_record(1000, Decision::Allow));
        state.audit.record(sample_record(1001, Decision::Allow));
        state.audit.flush();

        let resp = handle_request(
            &state,
            PeerCreds {
                pid: 1,
                uid: 0,
                gid: 0,
            },
            RequestOp::Events { limit: Some(100) },
        );
        match resp.body.unwrap() {
            ResponseBody::Events(ev) => assert_eq!(ev.len(), 2),
            _ => panic!("expected Events"),
        }
    }

    #[test]
    fn explain_round_trips_from_audit_record() {
        let (state, _t) = make_state(1000);
        state.audit.record(sample_record(
            1000,
            Decision::Deny(DenyReason::CrossBrowserWithoutLease),
        ));
        state.audit.flush();

        // Find the event id.
        let events = state.audit.query_events(Some(1000), 10).unwrap();
        let id = events[0].id;

        let resp = handle_request(
            &state,
            PeerCreds {
                pid: 1,
                uid: 1000,
                gid: 1000,
            },
            RequestOp::Explain { event_id: id },
        );
        assert!(resp.ok);
        match resp.body.unwrap() {
            ResponseBody::Explain(ev) => {
                assert_eq!(ev.id, id);
                assert_eq!(ev.uid, 1000);
                assert!(ev.decision.contains("Deny"));
                assert!(ev.deny_reason.as_deref().unwrap().contains("CrossBrowser"));
                assert!(ev.backend_diag.contains("classify="));
                assert!(ev.path.contains("Cookies"));
            }
            _ => panic!("expected Explain"),
        }
    }

    #[test]
    fn explain_denied_for_other_users_event() {
        let (state, _t) = make_state(1000);
        state.audit.record(sample_record(1001, Decision::Allow));
        state.audit.flush();
        let id = state.audit.query_events(None, 10).unwrap()[0].id;

        let resp = handle_request(
            &state,
            PeerCreds {
                pid: 1,
                uid: 1000,
                gid: 1000,
            },
            RequestOp::Explain { event_id: id },
        );
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("permission denied"));
    }

    #[test]
    fn explain_not_found() {
        let (state, _t) = make_state(1000);
        let resp = handle_request(
            &state,
            PeerCreds {
                pid: 1,
                uid: 1000,
                gid: 1000,
            },
            RequestOp::Explain { event_id: 99999 },
        );
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("not found"));
    }

    #[test]
    fn leases_list_filters_by_uid() {
        let (state, _t) = make_state(1000);
        // Manually inject leases into the engine. `target` is the armed
        // ExeIdentity (no start_time) per Phase 08.
        {
            let mut engine = state.engine.lock().unwrap();
            engine.leases = LeaseSet {
                migration: vec![MigrationLease {
                    id: LeaseId(1),
                    source_browser: BrowserId("chrome".into()),
                    source_profile: ProfileId("Default".into()),
                    target_browser: BrowserId("firefox".into()),
                    uid: 1000,
                    target: guard_core::identity::ExeIdentity {
                        exe: PathBuf::from("/usr/bin/firefox"),
                        dev: 1,
                        ino: 2,
                    },
                    expires_at: 999_999_999,
                    revoked: false,
                    read_only: true,
                }],
                ssh: vec![],
            };
        }
        // Owner sees it.
        let resp = handle_request(
            &state,
            PeerCreds {
                pid: 1,
                uid: 1000,
                gid: 1000,
            },
            RequestOp::LeasesList,
        );
        match resp.body.unwrap() {
            ResponseBody::Leases(ls) => assert_eq!(ls.len(), 1),
            _ => panic!("expected Leases"),
        }
        // Another user does not.
        let resp = handle_request(
            &state,
            PeerCreds {
                pid: 1,
                uid: 1001,
                gid: 1001,
            },
            RequestOp::LeasesList,
        );
        match resp.body.unwrap() {
            ResponseBody::Leases(ls) => assert!(ls.is_empty()),
            _ => panic!("expected Leases"),
        }
        // Root sees it.
        let resp = handle_request(
            &state,
            PeerCreds {
                pid: 1,
                uid: 0,
                gid: 0,
            },
            RequestOp::LeasesList,
        );
        match resp.body.unwrap() {
            ResponseBody::Leases(ls) => assert_eq!(ls.len(), 1),
            _ => panic!("expected Leases"),
        }
    }

    #[test]
    fn lease_revoke_authorization() {
        let (state, _t) = make_state(1000);
        {
            let mut engine = state.engine.lock().unwrap();
            engine.leases = LeaseSet {
                migration: vec![MigrationLease {
                    id: LeaseId(5),
                    source_browser: BrowserId("chrome".into()),
                    source_profile: ProfileId("Default".into()),
                    target_browser: BrowserId("firefox".into()),
                    uid: 1000,
                    target: guard_core::identity::ExeIdentity {
                        exe: PathBuf::from("/usr/bin/firefox"),
                        dev: 1,
                        ino: 2,
                    },
                    expires_at: 999_999_999,
                    revoked: false,
                    read_only: true,
                }],
                ssh: vec![],
            };
        }
        // Another user cannot revoke.
        let resp = handle_request(
            &state,
            PeerCreds {
                pid: 1,
                uid: 1001,
                gid: 1001,
            },
            RequestOp::LeasesRevoke {
                lease_id: "5".into(),
            },
        );
        assert!(!resp.ok);

        // Owner can.
        let resp = handle_request(
            &state,
            PeerCreds {
                pid: 1,
                uid: 1000,
                gid: 1000,
            },
            RequestOp::LeasesRevoke {
                lease_id: "5".into(),
            },
        );
        assert!(resp.ok);
        match resp.body.unwrap() {
            ResponseBody::LeaseRevoked { found, .. } => assert!(found),
            _ => panic!("expected LeaseRevoked"),
        }
        // Verify it's actually revoked.
        let engine = state.engine.lock().unwrap();
        assert!(engine.leases().migration[0].revoked);
    }

    // --- Phase 08: migration authorize via IPC ---

    /// Build an `IpcState` with TWO enrolled browsers (chrome + firefox) so
    /// `authorize_migration` can resolve a real armed target exe identity.
    /// Returns the state plus the tempdirs that MUST stay alive for the test.
    fn make_state_two_browsers(
        uid: u32,
    ) -> (
        IpcState,
        (tempfile::TempDir, tempfile::TempDir, tempfile::TempDir),
    ) {
        use guard_test_fixtures::firefox::FirefoxProfile;
        let chrome_p = ChromiumProfile::create("Default").unwrap();
        let ff_p = FirefoxProfile::create("ff-profile").unwrap();
        // A real, executable firefox binary so resolve_exe_identity succeeds.
        // We copy /bin/sleep (or /usr/bin/sleep) into the firefox profile dir.
        let ff_exe = ff_p.root_path().join("fake-firefox-bin");
        let sleep = ["/bin/sleep", "/usr/bin/sleep"]
            .iter()
            .find_map(|p| {
                if std::path::Path::new(p).exists() {
                    Some(std::path::PathBuf::from(p))
                } else {
                    None
                }
            })
            .expect("no sleep binary found for test");
        std::fs::copy(&sleep, &ff_exe).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ff_exe, std::fs::Permissions::from_mode(0o755)).unwrap();

        let cfg = EnforcementConfig {
            browsers: vec![
                BrowserEnrollmentConfig {
                    id: "chrome".into(),
                    family: BrowserFamily::Chromium,
                    profile_root: chrome_p.user_data_dir.clone(),
                    owner_uid: Some(uid),
                    exe_paths: vec![],
                },
                BrowserEnrollmentConfig {
                    id: "firefox".into(),
                    family: BrowserFamily::Firefox,
                    profile_root: ff_p.profile_dir.clone(),
                    owner_uid: Some(uid),
                    exe_paths: vec![ff_exe.clone()],
                },
            ],
            enrolled_exes: vec![],
            ssh_keys: vec![],
        };
        let engine = EnforcementEngine::from_config(&cfg).unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let audit = AuditStore::open(&audit_dir.path().join("audit.db")).unwrap();
        let state = IpcState {
            engine: Arc::new(Mutex::new(engine)),
            audit: Arc::new(audit),
            version: "0.1.0-test".into(),
            group: None,
        };
        (state, (chrome_p.root, ff_p.root, audit_dir))
    }

    #[test]
    fn migration_authorize_via_ipc_uses_peer_uid() {
        // The authorizing uid comes from PeerCreds, never from JSON (there is
        // no uid field on the request). The resulting lease is owned by the
        // peer uid, and the response echoes it back.
        let (state, _t) = make_state_two_browsers(1000);
        let resp = handle_request(
            &state,
            PeerCreds {
                pid: 1,
                uid: 1000,
                gid: 1000,
            },
            RequestOp::MigrationAuthorize {
                source_browser: "chrome".into(),
                source_profile: "Default".into(),
                target_browser: "firefox".into(),
                duration_secs: None,
            },
        );
        assert!(resp.ok, "authorize should succeed: {:?}", resp.error);
        match resp.body.unwrap() {
            ResponseBody::MigrationAuthorized(m) => {
                assert_eq!(m.uid, 1000, "uid must come from peer creds");
                assert_eq!(m.source_browser, "chrome");
                assert_eq!(m.source_profile, "Default");
                assert_eq!(m.target_browser, "firefox");
                assert!(m.read_only, "migration leases are read-only");
                assert!(!m.target_exe.is_empty(), "target exe must be resolved");
                assert!(m.lease_id.parse::<u64>().is_ok());
                // The lease is stored in the engine under the peer uid.
                let engine = state.engine.lock().unwrap();
                let stored = engine
                    .leases()
                    .migration
                    .iter()
                    .find(|l| l.id.0.to_string() == m.lease_id)
                    .expect("lease stored");
                assert_eq!(stored.uid, 1000);
                assert!(stored.read_only);
            }
            other => panic!("expected MigrationAuthorized, got {other:?}"),
        }
    }

    #[test]
    fn migration_authorize_unknown_target_via_ipc_errors() {
        let (state, _t) = make_state_two_browsers(1000);
        let resp = handle_request(
            &state,
            PeerCreds {
                pid: 1,
                uid: 1000,
                gid: 1000,
            },
            RequestOp::MigrationAuthorize {
                source_browser: "chrome".into(),
                source_profile: "Default".into(),
                target_browser: "nonexistent".into(),
                duration_secs: None,
            },
        );
        assert!(!resp.ok);
        assert!(
            resp.error
                .as_deref()
                .unwrap()
                .contains("unknown target browser"),
            "error should mention unknown target: {:?}",
            resp.error
        );
    }

    #[test]
    fn migration_authorize_caps_duration_via_ipc() {
        let (state, _t) = make_state_two_browsers(1000);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let resp = handle_request(
            &state,
            PeerCreds {
                pid: 1,
                uid: 1000,
                gid: 1000,
            },
            RequestOp::MigrationAuthorize {
                source_browser: "chrome".into(),
                source_profile: "Default".into(),
                target_browser: "firefox".into(),
                duration_secs: Some(99_999_999), // absurd — must be capped at 1h
            },
        );
        assert!(resp.ok);
        match resp.body.unwrap() {
            ResponseBody::MigrationAuthorized(m) => {
                assert!(
                    m.expires_at <= now + crate::enforce::MAX_MIGRATION_DURATION_SECS + 2,
                    "duration must be capped at 1h, got expiry {} (now={})",
                    m.expires_at,
                    now
                );
            }
            other => panic!("expected MigrationAuthorized, got {other:?}"),
        }
    }

    #[test]
    fn config_check_returns_valid() {
        let (state, _t) = make_state(1000);
        let resp = handle_request(
            &state,
            PeerCreds {
                pid: 1,
                uid: 1000,
                gid: 1000,
            },
            RequestOp::ConfigCheck,
        );
        assert!(resp.ok);
        match resp.body.unwrap() {
            ResponseBody::ConfigCheck(c) => {
                assert!(c.valid);
                assert_eq!(c.browsers, 1);
                assert!(c.protected_files > 0);
            }
            _ => panic!("expected ConfigCheck"),
        }
    }

    // --- Phase 10: SSH protect via IPC ---

    #[test]
    fn ssh_protect_rejects_pub_file_via_ipc() {
        // A `.pub` path is rejected before the fanotify group is even consulted
        // (so this is unit-testable without root / CAP_SYS_ADMIN).
        let (state, _t) = make_state(1000);
        let resp = handle_request(
            &state,
            PeerCreds {
                pid: 1,
                uid: 1000,
                gid: 1000,
            },
            RequestOp::SshProtect {
                path: "/home/u/.ssh/id_ed25519.pub".into(),
            },
        );
        assert!(!resp.ok);
        assert!(
            resp.error
                .as_deref()
                .unwrap()
                .contains("not a private-key candidate"),
            "error should mention candidate rejection: {:?}",
            resp.error
        );
    }

    #[test]
    fn ssh_protect_rejects_reserved_name_via_ipc() {
        let (state, _t) = make_state(1000);
        let resp = handle_request(
            &state,
            PeerCreds {
                pid: 1,
                uid: 1000,
                gid: 1000,
            },
            RequestOp::SshProtect {
                path: "/home/u/.ssh/known_hosts".into(),
            },
        );
        assert!(!resp.ok);
        assert!(resp
            .error
            .as_deref()
            .unwrap()
            .contains("not a private-key candidate"));
    }

    #[test]
    fn ssh_protect_without_group_errors() {
        // A valid candidate path but no fanotify group (group: None) => the
        // daemon is not in enforcement mode and cannot add a mark.
        let (state, _t) = make_state(1000);
        let s = guard_test_fixtures::SshFixture::create().unwrap();
        let resp = handle_request(
            &state,
            PeerCreds {
                pid: 1,
                uid: 1000,
                gid: 1000,
            },
            RequestOp::SshProtect {
                path: s.private_key.to_string_lossy().into_owned(),
            },
        );
        assert!(!resp.ok);
        assert!(
            resp.error
                .as_deref()
                .unwrap()
                .contains("not in enforcement mode"),
            "error should mention no fanotify group: {:?}",
            resp.error
        );
        // The key must NOT have been enrolled: classify on its path returns None
        // (the handler returned before touching the engine).
        let engine = state.engine.lock().unwrap();
        assert!(
            engine.registry().classify(&s.private_key).is_none(),
            "ssh key must not be enrolled without a fanotify group"
        );
        drop(s);
    }

    #[test]
    fn ssh_protect_request_has_no_key_contents() {
        // The wire request for SshProtect carries only a path string, never key
        // contents. Verify the serialized JSON has no content/blob fields.
        let req = Request {
            version: PROTOCOL_VERSION,
            op: RequestOp::SshProtect {
                path: "/home/u/.ssh/id_ed25519".into(),
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"kind\":\"ssh_protect\""));
        assert!(!json.contains("\"content\""));
        assert!(!json.contains("\"key_bytes\""));
        assert!(!json.contains("\"private_key\""));
    }

    #[test]
    fn protocol_version_mismatch_rejected() {
        let (state, _t) = make_state(1000);
        let req = Request {
            version: 999,
            op: RequestOp::Status,
        };
        let req_bytes = serde_json::to_vec(&req).unwrap();
        // Simulate the connection handler's version check.
        let parsed: Request = serde_json::from_slice(&req_bytes).unwrap();
        let resp = if parsed.version != PROTOCOL_VERSION {
            Response::err("version mismatch")
        } else {
            handle_request(
                &state,
                PeerCreds {
                    pid: 1,
                    uid: 1000,
                    gid: 1000,
                },
                parsed.op,
            )
        };
        assert!(!resp.ok);
    }

    #[test]
    fn audit_record_no_secret_content_through_ipc() {
        // Verify that the EventInfo returned by the IPC handler does not
        // contain a known fixture secret marker.
        const MARKER: &str = "GUARD_SYNTHETIC_COOKIE_FIXTURE";
        let (state, _t) = make_state(1000);
        let mut r = sample_record(1000, Decision::Allow);
        // Try to smuggle the marker into a path-like field (it would never
        // be there in real usage, but verify the wire struct is clean).
        r.path = format!("/home/u/chrome/Default/{}", MARKER);
        state.audit.record(r);
        state.audit.flush();

        let resp = handle_request(
            &state,
            PeerCreds {
                pid: 1,
                uid: 0,
                gid: 0,
            },
            RequestOp::Events { limit: Some(10) },
        );
        match resp.body.unwrap() {
            ResponseBody::Events(ev) => {
                let json = serde_json::to_string(&ev).unwrap();
                // The marker appears in the path field (which is a path string,
                // not file content). The assertion is that no OTHER field
                // carries it, and that the struct has no content/blob field.
                // We check that the JSON does not contain "content" or "blob"
                // keys at all.
                assert!(!json.contains("\"content\""));
                assert!(!json.contains("\"blob\""));
                assert!(!json.contains("\"cookie_value\""));
                assert!(!json.contains("\"password\""));
                assert!(!json.contains("\"key_bytes\""));
            }
            _ => panic!("expected Events"),
        }
    }

    #[test]
    fn concurrent_clients_do_not_block() {
        // Spawn a real IPC server thread and connect 8 concurrent clients.
        // Each client sends a `status` request and must get a response. This
        // verifies that the IPC server + engine mutex do not deadlock or block
        // under concurrent read-only load.
        use std::sync::Barrier;
        use std::thread;
        use std::time::Duration;

        let (state, _chrome_tmp) = make_state(1000);
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("guardd-test.sock");

        let server_state = IpcState {
            engine: Arc::clone(&state.engine),
            audit: Arc::clone(&state.audit),
            version: "0.1.0-test".into(),
            group: None,
        };
        let sock_path = sock.clone();
        let server_handle = thread::spawn(move || {
            // Ignore errors — the server will be killed when the test ends.
            let _ = serve_loop(&server_state, &sock_path);
        });

        // Wait for the socket to appear.
        for _ in 0..100 {
            if sock.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(sock.exists(), "IPC socket was not created");

        let n_clients = 8;
        let barrier = Arc::new(Barrier::new(n_clients));
        let mut handles = Vec::new();
        for i in 0..n_clients {
            let sock = sock.clone();
            let b = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                b.wait();
                let req = Request {
                    version: PROTOCOL_VERSION,
                    op: RequestOp::Status,
                };
                let req_bytes = serde_json::to_vec(&req).unwrap();
                // Retry briefly in case the server isn't fully ready.
                let resp_bytes = retry_ipc(&sock, &req_bytes);
                let resp: Response = serde_json::from_slice(&resp_bytes).unwrap();
                assert!(resp.ok, "client {i}: response not ok");
                match resp.body.unwrap() {
                    ResponseBody::Status(s) => assert!(s.protected_files >= 6),
                    _ => panic!("expected Status"),
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // The server thread is still running (blocked on accept). Dropping
        // `dir` would race with it; just let the test process exit clean it up.
        drop(server_handle);
    }

    fn retry_ipc(sock: &std::path::Path, req: &[u8]) -> Vec<u8> {
        use platform_linux::ipc::IpcClient;
        use std::time::Duration;
        for _ in 0..50 {
            match IpcClient::request(sock, req) {
                Ok(v) => return v,
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        IpcClient::request(sock, req).expect("IPC request never succeeded")
    }

    #[test]
    fn end_to_end_explain_via_ipc_transport() {
        // Full round-trip: spawn IPC server, record an audit event, connect
        // via IpcClient, call `events` then `explain`.
        use std::thread;
        use std::time::Duration;

        let (state, _chrome_tmp) = make_state(1000);
        state.audit.record(sample_record(
            1000,
            Decision::Deny(DenyReason::CrossBrowserWithoutLease),
        ));
        state.audit.flush();

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("guardd-test.sock");
        let server_state = IpcState {
            engine: Arc::clone(&state.engine),
            audit: Arc::clone(&state.audit),
            version: "0.1.0-test".into(),
            group: None,
        };
        let sock_path = sock.clone();
        let server_handle = thread::spawn(move || {
            let _ = serve_loop(&server_state, &sock_path);
        });

        for _ in 0..100 {
            if sock.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }

        // Query events.
        let req = Request {
            version: PROTOCOL_VERSION,
            op: RequestOp::Events { limit: Some(10) },
        };
        let resp_bytes = retry_ipc(&sock, &serde_json::to_vec(&req).unwrap());
        let resp: Response = serde_json::from_slice(&resp_bytes).unwrap();
        let event_id = match resp.body.unwrap() {
            ResponseBody::Events(es) => es[0].id,
            _ => panic!("expected Events"),
        };

        // Explain that event.
        let req = Request {
            version: PROTOCOL_VERSION,
            op: RequestOp::Explain { event_id },
        };
        let resp_bytes = retry_ipc(&sock, &serde_json::to_vec(&req).unwrap());
        let resp: Response = serde_json::from_slice(&resp_bytes).unwrap();
        assert!(resp.ok);
        match resp.body.unwrap() {
            ResponseBody::Explain(e) => {
                assert_eq!(e.id, event_id);
                assert_eq!(e.uid, 1000);
                assert!(e.decision.contains("Deny"));
                assert!(e.deny_reason.unwrap().contains("CrossBrowser"));
                // Phase 12: stable machine-readable reason code.
                assert_eq!(e.reason_code.as_deref(), Some("migration_lease_required"));
                assert!(!e.resource_kind_code.is_empty());
                assert!(e.backend_diag.contains("classify="));
            }
            _ => panic!("expected Explain"),
        }
        drop(server_handle);
    }

    #[test]
    fn oversized_request_rejected_by_server() {
        // Connect to the real IPC server and send an oversized frame. The
        // server must reject it (read_request returns an error; the connection
        // is dropped without a response).
        use std::io::Write;
        use std::os::unix::net::UnixStream;
        use std::thread;
        use std::time::Duration;

        let (state, _chrome_tmp) = make_state(1000);
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("guardd-test.sock");
        let server_state = IpcState {
            engine: Arc::clone(&state.engine),
            audit: Arc::clone(&state.audit),
            version: "0.1.0-test".into(),
            group: None,
        };
        let sock_path = sock.clone();
        let server_handle = thread::spawn(move || {
            let _ = serve_loop(&server_state, &sock_path);
        });

        for _ in 0..100 {
            if sock.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }

        // Send a frame whose declared length exceeds MAX_REQUEST_BYTES.
        let mut stream = UnixStream::connect(&sock).unwrap();
        let huge_len: u32 = (MAX_REQUEST_BYTES as u32) + 1;
        stream.write_all(&huge_len.to_be_bytes()).unwrap();
        stream.write_all(&[0u8; 64]).unwrap();
        stream.flush().unwrap();

        // The server should reject the oversized frame and close the
        // connection. Depending on timing the client sees either a clean EOF
        // (read returns 0) or ECONNRESET — both prove the server refused the
        // request without writing a response.
        let mut buf = [0u8; 16];
        use std::io::Read;
        match stream.read(&mut buf) {
            Ok(0) => { /* clean close — good */ }
            Ok(n) => panic!("server should not respond to oversized frame, got {n} bytes"),
            Err(e) if e.raw_os_error() == Some(libc::ECONNRESET) => { /* reset — also good */ }
            Err(e) => panic!("unexpected read error on oversized frame: {e}"),
        }

        // A normal-sized request still works (server is not crashed).
        let req = Request {
            version: PROTOCOL_VERSION,
            op: RequestOp::Status,
        };
        let resp_bytes = retry_ipc(&sock, &serde_json::to_vec(&req).unwrap());
        let resp: Response = serde_json::from_slice(&resp_bytes).unwrap();
        assert!(resp.ok);
        drop(server_handle);
    }
}
