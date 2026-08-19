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

use std::collections::HashMap;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use guard_audit::AuditStore;
use guard_ipc::{
    ConfigCheckInfo, ConfigurationInfo, ConfiguredBrowserInfo, EventInfo, LeaseInfo,
    MigrationAuthorizedInfo, MigrationPendingInfo, MigrationResolutionAction,
    MigrationResolutionInfo, Response, ResponseBody, SshLoadAuthorizedInfo, SshPendingInfo,
    SshProtectedInfo, SshReadResolutionAction, SshReadResolutionInfo, StatusInfo,
    MAX_REQUEST_BYTES, PROTOCOL_VERSION,
};
use guard_ipc::{Request, RequestOp};
use platform_linux::fanotify::FanotifyGroup;
use platform_linux::ipc::{read_request, write_response, IpcServer, PeerCreds};

use crate::enforce::{EnforcementEngine, SshAgentBinding};
use crate::pending::{PendingMigrationStore, PendingSshReadStore};

static NEXT_AGENT_PIN: AtomicU64 = AtomicU64::new(1);

/// Shared engine + audit state handed to the IPC server thread.
pub struct IpcState {
    pub engine: Arc<Mutex<EnforcementEngine>>,
    pub audit: Arc<AuditStore>,
    pub version: String,
    /// The fanotify group, shared so the `SshProtect` handler can add a
    /// browser `FAN_OPEN_PERM` or SSH `FAN_ACCESS_PERM` mark at runtime. `None` when the daemon is not running
    /// in enforcement mode (e.g. one-shot tests). `mark_file` takes `&self` and
    /// the kernel `fanotify_mark` syscall is thread-safe, so sharing across the
    /// IPC thread is safe.
    pub group: Option<Arc<FanotifyGroup>>,
    /// Production uses polkit against the kernel-authenticated peer process.
    /// Tests bypass it explicitly; no production fallback exists.
    pub authorization: SensitiveAuthorization,
    /// Root-protected hardlinks pin verified ssh-agent socket inodes until the
    /// corresponding one-shot lease is revoked/used/expired.
    pub ssh_agent_pins: Arc<Mutex<HashMap<String, PathBuf>>>,
    pub backend_metrics: Arc<crate::strict::BackendMetrics>,
    pub pending_migrations: Arc<Mutex<PendingMigrationStore>>,
    pub pending_ssh_reads: Arc<Mutex<PendingSshReadStore>>,
}

#[derive(Debug, Clone, Copy)]
pub enum SensitiveAuthorization {
    Polkit,
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
                handle_request_with_connection(state, creds, req.op, Some(stream.as_raw_fd()))
            }
        }
        Err(e) => Response::err(format!("malformed request: {e}")),
    };
    let resp_bytes = serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec());
    if let Err(e) = write_response(stream, &resp_bytes) {
        revoke_unreceived_capability(state, &response);
        tracing::warn!(err = %e, "IPC write_response failed");
    }
}

fn handle_request_with_connection(
    state: &IpcState,
    creds: PeerCreds,
    op: RequestOp,
    connection_fd: Option<RawFd>,
) -> Response {
    cleanup_terminal_agent_pins(state);
    match op {
        RequestOp::Status => handle_status(state, creds),
        RequestOp::ResourcesList => handle_resources_list(state, creds),
        RequestOp::BrowsersList => handle_browsers_list(state, creds),
        RequestOp::ConfigurationGet => handle_configuration_get(state, creds),
        RequestOp::ConfigurationApply { .. } => {
            Response::err("configuration_apply is unavailable on the Linux transport")
        }
        RequestOp::PendingHelperPoll | RequestOp::PendingHelperStatus => {
            Response::err("pending_helper_health is unavailable on the Linux transport")
        }
        RequestOp::ConfigCheck => handle_config_check(state, creds),
        RequestOp::Events {
            limit,
            before_id,
            after_id,
        } => handle_events(state, creds, limit, before_id, after_id),
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
            connection_fd,
            source_browser,
            source_profile,
            target_browser,
            duration_secs,
        ),
        RequestOp::MigrationPendingList => handle_migration_pending_list(state, creds),
        RequestOp::MigrationPendingGet { id } => handle_migration_pending_get(state, creds, &id),
        RequestOp::MigrationResolve { id, action } => {
            handle_migration_resolve(state, creds, connection_fd, &id, action)
        }
        RequestOp::SshPendingList => handle_ssh_pending_list(state, creds),
        RequestOp::SshPendingGet { id } => handle_ssh_pending_get(state, creds, &id),
        RequestOp::SshReadResolve { id, action } => {
            handle_ssh_read_resolve(state, creds, connection_fd, &id, action)
        }
        RequestOp::SshProtect { path } => handle_ssh_protect(state, creds, connection_fd, path),
        RequestOp::SshLoadAuthorize { path, ssh_add_pid } => {
            handle_ssh_load_authorize(state, creds, connection_fd, path, ssh_add_pid)
        }
    }
}

// --- handlers ---

fn handle_status(state: &IpcState, creds: PeerCreds) -> Response {
    let engine = state.engine.lock().expect("engine mutex poisoned");
    let audit_dropped = state.audit.dropped();
    let backend = state.backend_metrics.snapshot();
    let required_filesystems = backend.marked_filesystems;
    let (marked_filesystems, filesystem_marks_healthy) = if required_filesystems == 0 {
        (0, true)
    } else {
        match state
            .group
            .as_ref()
            .map(|group| group.filesystem_mark_count())
        {
            Some(Ok(observed)) => (observed, observed >= required_filesystems),
            _ => (0, false),
        }
    };

    // LFH3: a required mark loss is a continuity-breaking transition. Once
    // observed it revokes all live authority and becomes sticky; current
    // recovery later reports ACTIVE enforcement but continuity stays LOST.
    let enforcing = state.group.is_some();
    // LFH3 / P1-c: mark-loss detection is AUTONOMOUS in the daemon event loop
    // (periodic required-mark health check), NOT triggered by this status
    // query. The status path only READS state — a security-state transition
    // must never depend on CLI/UI polling. `filesystem_marks_healthy` below
    // still reflects the observed mark count for reporting.

    // LFH0: split health dimensions. Each condition is judged on its own axis
    // so a dropped audit event is never conflated with lost filesystem-mark
    // continuity, and a fanotify queue overflow is reported as continuity loss
    // (dropped events were NOT individually denied — the kernel does not
    // guarantee that).
    let conservative_mode =
        state.backend_metrics.mode == crate::enforce::EnforcementMode::Conservative;

    let file_shield = if !enforcing {
        "NOT_ENFORCING".to_owned()
    } else if conservative_mode
        || engine.topology_degraded
        || backend.classifier_failures > 0
        || !filesystem_marks_healthy
        // P1-b (review): topology identity UNCERTAIN (group creation failed,
        // marks incomplete, learner dead, queue overflow, parse/read failure)
        // makes ambiguous outside-path opens fail closed — posture is REDUCED
        // until restart, mirroring continuity-loss philosophy.
        || backend.topology_uncertain
    {
        "REDUCED".to_owned()
    } else {
        "ACTIVE".to_owned()
    };

    // LFH3: continuity is the engine's STICKY state — current enforcement
    // recovering never erases a historical loss. The engine is the authority;
    // the backend counter and mark health are cross-checks that also drive the
    // state transition in main.rs.
    let (continuity, continuity_reason) = if !enforcing {
        ("LOST".to_owned(), Some("no_fanotify_group".to_owned()))
    } else if let crate::enforce::ProtectionContinuity::Lost { reason, .. } = engine.continuity {
        ("LOST".to_owned(), Some(reason.as_str().to_owned()))
    } else if backend.fanotify_overflows > 0 {
        (
            "LOST".to_owned(),
            Some("fanotify_queue_overflow".to_owned()),
        )
    } else if !filesystem_marks_healthy {
        (
            "LOST".to_owned(),
            Some("required_filesystem_mark_lost".to_owned()),
        )
    } else {
        ("INTACT".to_owned(), None)
    };

    let audit = if audit_dropped > 0 {
        "DEGRADED".to_owned()
    } else {
        "HEALTHY".to_owned()
    };

    // Overall posture is the most conservative axis; Conservative mode can
    // never report formal ACTIVE.
    let status = if !enforcing {
        "NOT_ENFORCING".to_owned()
    } else if conservative_mode {
        "REDUCED".to_owned()
    } else if continuity != "INTACT"
        || audit == "DEGRADED"
        || engine.unclassified > 0
        || engine.topology_degraded
        || backend.classifier_failures > 0
        // LFH5 review: a full dynamic-object handle index means new dynamic
        // objects are no longer learned; that is a fail-closed degradation,
        // not a silent loss of existing protections.
        || backend.handle_index_exhausted
        || !filesystem_marks_healthy
    {
        "DEGRADED".to_owned()
    } else {
        "ACTIVE".to_owned()
    };
    let body = StatusInfo {
        version: state.version.clone(),
        backend_kind: "linux-fanotify".to_owned(),
        backend_diagnostic: Some("fanotify protected-file authorization".to_owned()),
        backend_state: None,
        enforcement_active: enforcing,
        read_only_guaranteed: None,
        status,
        mode: Some(state.backend_metrics.mode.as_str().to_owned()),
        marked_filesystems: Some(marked_filesystems),
        required_filesystems: Some(required_filesystems),
        filesystem_marks_healthy: Some(filesystem_marks_healthy),
        strict_events_total: Some(backend.strict_events_total),
        strict_fast_allowed: Some(backend.strict_fast_allowed),
        protected_events: backend.protected_events,
        fanotify_overflows: Some(backend.fanotify_overflows),
        classifier_failures: Some(backend.classifier_failures),
        handle_index_full: Some(backend.handle_index_exhausted),
        strict_alias_scans: Some(backend.strict_alias_scans),
        strict_alias_matches: Some(backend.strict_alias_matches),
        topology_degraded: Some(engine.topology_degraded),
        mac_health: None,
        linux_health: Some(Box::new(guard_ipc::LinuxHealthInfo {
            file_shield,
            continuity,
            continuity_reason,
            audit,
            process_shield: "UNSUPPORTED".to_owned(),
            pidfd_enabled: backend.pidfd_enabled,
            pidfd_missing_events: backend.pidfd_missing_events,
        })),
        protected_files: engine.registry().file_count(),
        ssh_protected_keys: engine
            .registry()
            .files()
            .filter(|resource| resource.kind == guard_core::ProtectedResourceKind::SshPrivateKey)
            .count(),
        protected_trees: engine.registry().trees().len(),
        browsers: engine.browser_config().len(),
        browser_exes: engine.browser_exe_count(),
        allowed: engine.allowed,
        denied: engine.denied,
        unclassified: engine.unclassified,
        audit_dropped,
        peer_uid: creds.uid,
    };
    Response::ok(ResponseBody::Status(Box::new(body)))
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

fn handle_configuration_get(state: &IpcState, _creds: PeerCreds) -> Response {
    let engine = state.engine.lock().expect("engine mutex poisoned");
    let cfg = engine.configuration();
    Response::ok(ResponseBody::Configuration(ConfigurationInfo {
        enforcement_mode: Some(cfg.enforcement_mode.as_str().to_owned()),
        policy_enabled: None,
        // Linux has no Process Shield; the toggle is macOS-only (MCH0).
        process_shield_enabled: None,
        browsers: cfg
            .browsers
            .iter()
            .map(|browser| ConfiguredBrowserInfo {
                id: browser.id.clone(),
                family: format!("{:?}", browser.family),
                profile_root: browser.profile_root.to_string_lossy().into_owned(),
                owner_uid: browser.owner_uid,
                exe_paths: browser
                    .exe_paths
                    .iter()
                    .map(|path| path.to_string_lossy().into_owned())
                    .collect(),
            })
            .collect(),
        enrolled_exes: cfg
            .enrolled_exes
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect(),
        ssh_keys: cfg
            .ssh_keys
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect(),
        mac_system_processes: Vec::new(),
        mac_trusted_tools: Vec::new(),
    }))
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

fn handle_events(
    state: &IpcState,
    creds: PeerCreds,
    limit: Option<u32>,
    before_id: Option<i64>,
    after_id: Option<i64>,
) -> Response {
    // Ordinary users see only their own events; root sees all.
    let uid_filter = if creds.uid == 0 {
        None
    } else {
        Some(creds.uid)
    };
    let limit = limit.unwrap_or(100);
    // Flush so the CLI sees the latest committed records.
    state.audit.flush();
    if before_id.is_some() && after_id.is_some() {
        return Response::err("before_id and after_id cannot both be set");
    }
    match state
        .audit
        .query_events_cursor(uid_filter, limit, before_id, after_id)
    {
        Ok(events) => {
            let infos: Vec<EventInfo> = events
                .iter()
                .filter(|event| event_visible_in_build(event))
                .map(event_to_info)
                .collect();
            Response::ok(ResponseBody::Events(infos))
        }
        Err(e) => Response::err(format!("query failed: {e}")),
    }
}

fn handle_explain(state: &IpcState, creds: PeerCreds, event_id: i64) -> Response {
    state.audit.flush();
    match state.audit.query_event(event_id) {
        Ok(Some(ev)) => {
            if !event_visible_in_build(&ev) {
                return Response::err("event not available");
            }
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

fn event_visible_in_build(event: &guard_audit::AuditEvent) -> bool {
    cfg!(debug_assertions)
        || matches!(event.record.decision, guard_core::policy::Decision::Deny(_))
        || event.record.event_code.starts_with("ssh_key_access_")
        || (matches!(
            event.record.decision,
            guard_core::policy::Decision::AllowByLease(_)
        ) && event.record.resource_kind == guard_core::ProtectedResourceKind::SshPrivateKey)
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
            state: Some(
                match &l.state {
                    guard_core::lease::MigrationLeaseState::Armed { .. } => "armed",
                    guard_core::lease::MigrationLeaseState::Bound { .. } => "bound",
                    guard_core::lease::MigrationLeaseState::Dead => "dead",
                }
                .into(),
            ),
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
            state: None,
            expires_at: l.expires_at,
            revoked: l.revoked,
            used: l.used,
        });
    }
    for l in &leases.ssh_read {
        if creds.uid != 0 && l.uid != creds.uid {
            continue;
        }
        infos.push(LeaseInfo {
            id: l.id.0.to_string(),
            kind: "ssh_read".into(),
            uid: l.uid,
            source_browser: None,
            source_profile: None,
            target_browser: None,
            resource: Some(l.resource.0.clone()),
            state: Some(format!("root_pid={}", l.root.pid)),
            expires_at: l.expires_at,
            revoked: l.revoked,
            used: false,
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
        })
        .or_else(|| {
            leases
                .ssh_read
                .iter()
                .find(|l| l.id.0.to_string() == lease_id)
                .map(|l| l.uid)
        });
    match owner_uid {
        Some(uid) if creds.uid == 0 || uid == creds.uid => {
            let found = engine.revoke_lease(&lease_id);
            drop(engine);
            remove_agent_pin(state, &lease_id);
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

fn handle_migration_pending_list(state: &IpcState, creds: PeerCreds) -> Response {
    let pending = state
        .pending_migrations
        .lock()
        .expect("pending migration mutex poisoned");
    let values = pending
        .list_for_uid(creds.uid, creds.uid == 0)
        .into_iter()
        .map(pending_info_to_ipc)
        .collect();
    Response::ok(ResponseBody::MigrationPending(values))
}

fn handle_migration_pending_get(state: &IpcState, creds: PeerCreds, id: &str) -> Response {
    let pending = state
        .pending_migrations
        .lock()
        .expect("pending migration mutex poisoned");
    match pending
        .get_for_uid(id, creds.uid, creds.uid == 0)
        .map(|value| Box::new(pending_info_to_ipc(value)))
    {
        Some(value) => Response::ok(ResponseBody::MigrationPendingItem(value)),
        None => Response::err("pending migration request not found"),
    }
}

fn handle_migration_resolve(
    state: &IpcState,
    creds: PeerCreds,
    connection_fd: Option<RawFd>,
    id: &str,
    action: MigrationResolutionAction,
) -> Response {
    // Fetch daemon-recorded facts first.  The IPC client never supplies a
    // browser, profile, PID, executable path, uid, or duration for resolution.
    let info = {
        let pending = state
            .pending_migrations
            .lock()
            .expect("pending migration mutex poisoned");
        pending.get_for_uid(id, creds.uid, creds.uid == 0)
    };
    let Some(info) = info else {
        return Response::err("pending migration request not found or already resolved");
    };
    if matches!(action, MigrationResolutionAction::AllowImport) {
        if let Err(error) = authorize_sensitive(
            state,
            creds,
            connection_fd,
            "org.guardd.migration-resolve",
            &[
                ("source_browser", &info.source_browser),
                ("source_profile", &info.source_profile),
                ("target_browser", &info.target_browser),
                ("pending_id", &info.id),
            ],
        ) {
            return Response::err(error);
        }
    }

    let block = matches!(action, MigrationResolutionAction::Block);
    let request = state
        .pending_migrations
        .lock()
        .expect("pending migration mutex poisoned")
        .take_for_resolution(id, creds.uid, creds.uid == 0, unix_secs(), block);
    let Some(request) = request else {
        return Response::err("pending migration request already resolved");
    };
    let details = request.details.clone();

    if block {
        request.resolve(false);
        let record = state
            .engine
            .lock()
            .expect("engine mutex poisoned")
            .migration_audit_record(
                &details,
                "browser_migration_blocked",
                guard_core::Decision::Deny(guard_core::DenyReason::CrossBrowserWithoutLease),
                "browser_migration_blocked;resolution=user_block",
            );
        state.audit.record(record);
        return Response::ok(ResponseBody::MigrationResolved(
            MigrationResolutionInfo::Blocked,
        ));
    }

    let outcome = state
        .engine
        .lock()
        .expect("engine mutex poisoned")
        .approve_pending_migration(&details);
    match outcome {
        Ok((lease_id, expires_at)) => {
            let siblings = {
                let mut pending = state
                    .pending_migrations
                    .lock()
                    .expect("pending migration mutex poisoned");
                pending.record_recent_approval(&details, unix_secs());
                pending.take_recent_approval_siblings(&details)
            };
            request.resolve(true);
            let record = state
                .engine
                .lock()
                .expect("engine mutex poisoned")
                .migration_audit_record(
                    &details,
                    "browser_migration_allowed",
                    guard_core::Decision::AllowByLease(lease_id),
                    &format!(
                        "browser_migration_allowed;request={};lease={};expires_at={}",
                        id, lease_id.0, expires_at
                    ),
                );
            state.audit.record(record);
            for sibling in siblings {
                let sibling_details = sibling.details.clone();
                // Keep the MutexGuard out of the match scrutinee. A scrutinee
                // temporary lives through every arm, so reacquiring `engine`
                // below would otherwise self-deadlock the daemon.
                let sibling_outcome = state
                    .engine
                    .lock()
                    .expect("engine mutex poisoned")
                    .approve_pending_migration(&sibling_details);
                match sibling_outcome {
                    Ok((sibling_lease, sibling_expires_at)) => {
                        sibling.resolve(true);
                        let record = state
                            .engine
                            .lock()
                            .expect("engine mutex poisoned")
                            .migration_audit_record(
                                &sibling_details,
                                "browser_migration_allowed",
                                guard_core::Decision::AllowByLease(sibling_lease),
                                &format!(
                                    "browser_migration_allowed;resolution=coalesced_import_session;lease={};expires_at={}",
                                    sibling_lease.0, sibling_expires_at
                                ),
                            );
                        state.audit.record(record);
                    }
                    Err(error) => {
                        sibling.resolve(false);
                        let record = state
                            .engine
                            .lock()
                            .expect("engine mutex poisoned")
                            .migration_audit_record(
                                &sibling_details,
                                "browser_migration_blocked",
                                guard_core::Decision::Deny(
                                    guard_core::DenyReason::IdentityMismatch,
                                ),
                                &format!(
                                    "browser_migration_blocked;resolution=coalesced_import_identity_revalidation;{error}"
                                ),
                            );
                        state.audit.record(record);
                    }
                }
            }
            Response::ok(ResponseBody::MigrationResolved(
                MigrationResolutionInfo::Allowed,
            ))
        }
        Err(error) => {
            request.resolve(false);
            let record = state
                .engine
                .lock()
                .expect("engine mutex poisoned")
                .migration_audit_record(
                    &details,
                    "browser_migration_blocked",
                    guard_core::Decision::Deny(guard_core::DenyReason::IdentityMismatch),
                    &format!("browser_migration_blocked;resolution=identity_revalidation;{error}"),
                );
            state.audit.record(record);
            Response::err(error)
        }
    }
}

fn pending_info_to_ipc(value: crate::pending::PendingMigrationInfo) -> MigrationPendingInfo {
    MigrationPendingInfo {
        id: value.id,
        uid: value.uid,
        source_browser: value.source_browser,
        source_profile: value.source_profile,
        target_browser: value.target_browser,
        target_exe: value.target_exe,
        target_pid: value.target_pid,
        target_start_time: value.target_start_time,
        requested_data: value.requested_data,
        created_at: value.created_at,
        expires_at: value.expires_at,
    }
}

fn handle_ssh_pending_list(state: &IpcState, creds: PeerCreds) -> Response {
    let pending = state
        .pending_ssh_reads
        .lock()
        .expect("pending SSH read mutex poisoned");
    let values = pending
        .list_for_uid(creds.uid, creds.uid == 0)
        .into_iter()
        .map(ssh_pending_info_to_ipc)
        .collect();
    Response::ok(ResponseBody::SshPending(values))
}

fn handle_ssh_pending_get(state: &IpcState, creds: PeerCreds, id: &str) -> Response {
    let pending = state
        .pending_ssh_reads
        .lock()
        .expect("pending SSH read mutex poisoned");
    match pending
        .get_for_uid(id, creds.uid, creds.uid == 0)
        .map(|value| Box::new(ssh_pending_info_to_ipc(value)))
    {
        Some(value) => Response::ok(ResponseBody::SshPendingItem(value)),
        None => Response::err("pending SSH key read not found"),
    }
}

fn handle_ssh_read_resolve(
    state: &IpcState,
    creds: PeerCreds,
    connection_fd: Option<RawFd>,
    id: &str,
    action: SshReadResolutionAction,
) -> Response {
    let info = {
        let pending = state
            .pending_ssh_reads
            .lock()
            .expect("pending SSH read mutex poisoned");
        pending.get_for_uid(id, creds.uid, creds.uid == 0)
    };
    let Some(info) = info else {
        return Response::err("pending SSH key read not found or already resolved");
    };
    if matches!(action, SshReadResolutionAction::Allow) {
        if let Err(error) = authorize_sensitive(
            state,
            creds,
            connection_fd,
            "org.guardd.ssh-read-resolve",
            &[("key_path", &info.key_path), ("pending_id", &info.id)],
        ) {
            return Response::err(error);
        }
    }
    let block = matches!(action, SshReadResolutionAction::Block);
    let request = state
        .pending_ssh_reads
        .lock()
        .expect("pending SSH read mutex poisoned")
        .take_for_resolution(id, creds.uid, creds.uid == 0, unix_secs(), block);
    let Some(request) = request else {
        return Response::err("pending SSH key read already resolved");
    };
    let details = request.details.clone();
    if block {
        request.resolve(false);
        let record = state
            .engine
            .lock()
            .expect("engine mutex poisoned")
            .ssh_read_audit_record(
                &details,
                "ssh_key_access_blocked",
                guard_core::Decision::Deny(guard_core::DenyReason::IdentityMismatch),
                "ssh_key_access_blocked;resolution=user_block",
            );
        state.audit.record(record);
        return Response::ok(ResponseBody::SshReadResolved(
            SshReadResolutionInfo::Blocked,
        ));
    }
    // The approval mutates the lease set under `engine`, but fanotify
    // resolution, audit submission, and IPC response construction must happen
    // after that guard is dropped. In particular, never put this lock-bearing
    // call directly in the match scrutinee: its temporary would live through
    // the arms and deadlock on the audit-record lock below.
    let approval = state
        .engine
        .lock()
        .expect("engine mutex poisoned")
        .approve_pending_ssh_read(&details);
    match approval {
        Ok((lease_id, expires_at)) => {
            request.resolve(true);
            let record = state
                .engine
                .lock()
                .expect("engine mutex poisoned")
                .ssh_read_audit_record(
                    &details,
                    "ssh_key_access_allowed",
                    guard_core::Decision::AllowByLease(lease_id),
                    &format!(
                        "ssh_key_access_allowed;request={id};lease={};expires_at={}",
                        lease_id.0, expires_at
                    ),
                );
            state.audit.record(record);
            Response::ok(ResponseBody::SshReadResolved(
                SshReadResolutionInfo::Allowed,
            ))
        }
        Err(error) => {
            request.resolve(false);
            let record = state
                .engine
                .lock()
                .expect("engine mutex poisoned")
                .ssh_read_audit_record(
                    &details,
                    "ssh_key_access_blocked",
                    guard_core::Decision::Deny(guard_core::DenyReason::IdentityMismatch),
                    &format!("ssh_key_access_blocked;resolution=identity_revalidation;{error}"),
                );
            state.audit.record(record);
            Response::err(error)
        }
    }
}

fn ssh_pending_info_to_ipc(value: crate::pending::PendingSshReadInfo) -> SshPendingInfo {
    SshPendingInfo {
        id: value.id,
        uid: value.uid,
        key_path: value.key_path,
        process_exe: value.process_exe,
        pid: value.pid,
        start_time: value.start_time,
        created_at: value.created_at,
        expires_at: value.expires_at,
    }
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn handle_migration_authorize(
    state: &IpcState,
    creds: PeerCreds,
    connection_fd: Option<RawFd>,
    source_browser: String,
    source_profile: String,
    target_browser: String,
    duration_secs: Option<u64>,
) -> Response {
    // SECURITY: the authorizing uid is taken EXCLUSIVELY from kernel-verified
    // peer creds. A uid in JSON would be ignored — and there is no uid field
    // in `RequestOp::MigrationAuthorize` to begin with.
    if let Err(error) = authorize_sensitive(
        state,
        creds,
        connection_fd,
        "org.guardd.migration-authorize",
        &[
            ("source_browser", &source_browser),
            ("source_profile", &source_profile),
            ("target_browser", &target_browser),
        ],
    ) {
        return Response::err(error);
    }
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
                .map(|l| match &l.state {
                    guard_core::lease::MigrationLeaseState::Armed { target } => {
                        target.exe.to_string_lossy().into_owned()
                    }
                    guard_core::lease::MigrationLeaseState::Bound { root } => {
                        root.exe.to_string_lossy().into_owned()
                    }
                    guard_core::lease::MigrationLeaseState::Dead => String::new(),
                })
                .unwrap_or_default();
            Response::ok(ResponseBody::MigrationAuthorized(MigrationAuthorizedInfo {
                lease_id: lease_id.0.to_string(),
                source_browser,
                source_profile,
                target_browser,
                target_exe,
                uid: creds.uid,
                expires_at,
                read_only_guaranteed: false,
            }))
        }
        Err(e) => Response::err(e),
    }
}

fn handle_ssh_protect(
    state: &IpcState,
    creds: PeerCreds,
    connection_fd: Option<RawFd>,
    path: String,
) -> Response {
    // SECURITY (hardening pass 1): only the file owner or root may add
    // protection. Previously any authenticated peer could protect arbitrary
    // files, creating a root-powered denial primitive (protect a file, then
    // no one but the owner can read it). Now we require:
    //   creds.uid == 0 (root), OR
    //   creds.uid == res.owner_uid (file owner)
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
    let res = match guard_ssh::enroll_key(&path_buf) {
        Ok(resource) => resource,
        Err(error) => return Response::err(format!("ssh protect failed: {error}")),
    };
    // Authorization check: only the file owner or root may protect a file.
    if creds.uid != 0 && creds.uid != res.owner_uid {
        return Response::err(format!(
            "permission denied: uid {} may not protect {} (owned by uid {}); only the file owner or root may add protection",
            creds.uid,
            res.path.display(),
            res.owner_uid
        ));
    }
    if let Err(error) = authorize_sensitive(
        state,
        creds,
        connection_fd,
        "org.guardd.ssh-protect",
        &[("path", &res.path.to_string_lossy())],
    ) {
        return Response::err(error);
    }
    // Mark before publishing the resource. An event in the tiny interval
    // between these operations is unclassified and therefore denied; the old
    // registry-first ordering had a fail-open enrollment window.
    if let Err(e) = group.mark_file(libc::FAN_ACCESS_PERM, &res.path) {
        return Response::err(format!(
            "ssh protect: fanotify mark failed for {}: {e}",
            res.path.display()
        ));
    }
    state
        .engine
        .lock()
        .expect("engine mutex poisoned")
        .enroll_ssh_resource(res.clone());
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
    connection_fd: Option<RawFd>,
    path: String,
    ssh_add_pid: u32,
) -> Response {
    let pid = ssh_add_pid as i32;
    let trusted_ssh_add = match platform_linux::identity::trusted_ssh_add_path() {
        Ok(path) => path,
        Err(error) => return Response::err(error),
    };
    let child = match platform_linux::identity::verify_stopped_child_for_exec(
        pid,
        creds.pid,
        creds.uid,
        creds.gid,
        &trusted_ssh_add,
    ) {
        Ok(identity) => identity,
        Err(error) => return Response::err(format!("invalid ssh-add child: {error}")),
    };
    let agent_before = match validate_agent_socket(pid, creds.uid) {
        Ok(endpoint) => endpoint,
        Err(error) => return Response::err(error),
    };
    let path_buf = PathBuf::from(&path);
    if let Err(error) = authorize_sensitive(
        state,
        creds,
        connection_fd,
        "org.guardd.ssh-load",
        &[
            ("path", &path),
            ("ssh_add", &trusted_ssh_add.to_string_lossy()),
            ("agent_socket", &agent_before.path.to_string_lossy()),
        ],
    ) {
        return Response::err(error);
    }
    // Polkit may involve a human and take an arbitrary amount of time. Re-read
    // every kernel-observed fact afterward; a dead/reparented/reused child or a
    // replaced agent endpoint must not inherit the earlier approval.
    let child_after = match platform_linux::identity::verify_stopped_child_for_exec(
        pid,
        creds.pid,
        creds.uid,
        creds.gid,
        &trusted_ssh_add,
    ) {
        Ok(identity) if identity == child => identity,
        Ok(_) => return Response::err("ssh-add child identity changed during authorization"),
        Err(error) => {
            return Response::err(format!(
                "ssh-add child invalid after authorization: {error}"
            ))
        }
    };
    let agent_after = match validate_agent_socket(pid, creds.uid) {
        Ok(endpoint) if endpoint == agent_before => endpoint,
        Ok(_) => return Response::err("SSH_AUTH_SOCK endpoint changed during authorization"),
        Err(error) => {
            return Response::err(format!(
                "SSH_AUTH_SOCK invalid after authorization: {error}"
            ))
        }
    };
    // Pin before publishing a lease. Until this succeeds there is no
    // capability for a prematurely resumed child to race against; once the
    // lease exists, the hot path also requires the live ssh-add environment
    // to name this exact pinned endpoint.
    let pin_token = NEXT_AGENT_PIN.fetch_add(1, Ordering::Relaxed);
    let pinned_agent = match pin_verified_agent_endpoint(&agent_after, creds.uid, pin_token) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            return Response::err(format!("cannot pin verified SSH agent endpoint: {error}"))
        }
    };
    let (lease_id, expires_at) = {
        let mut engine = state.engine.lock().expect("engine mutex poisoned");
        match engine.authorize_ssh_load(
            &path_buf,
            creds.uid,
            child_after.target,
            pid as u32,
            SshAgentBinding::Verified(pinned_agent.path.clone()),
        ) {
            Ok(value) => value,
            Err(error) => {
                let _ = std::fs::remove_file(&pinned_agent.path);
                return Response::err(error);
            }
        }
    };
    state
        .ssh_agent_pins
        .lock()
        .expect("SSH agent pin mutex poisoned")
        .insert(lease_id.0.to_string(), pinned_agent.path.clone());
    tracing::info!(
        path = %path,
        lease_id = lease_id.0,
        peer_uid = creds.uid,
        ssh_add_pid,
        ssh_agent_pid = agent_after.peer.pid,
        ssh_agent_start_time = agent_after.peer.start_time,
        pinned_agent_socket = %pinned_agent.path.display(),
        expires_at,
        "ssh load lease authorized (ssh-add and ssh-agent identities kernel-verified)"
    );
    Response::ok(ResponseBody::SshLoadAuthorized(SshLoadAuthorizedInfo {
        lease_id: lease_id.0.to_string(),
        path,
        uid: creds.uid,
        expires_at,
        agent_socket: pinned_agent.path.to_string_lossy().into_owned(),
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifiedAgentEndpoint {
    path: PathBuf,
    dev: u64,
    ino: u64,
    peer: guard_core::identity::ProcessStableId,
}

fn validate_agent_socket(pid: i32, uid: u32) -> Result<VerifiedAgentEndpoint, String> {
    let value = platform_linux::identity::read_process_env(pid, "SSH_AUTH_SOCK")?
        .ok_or_else(|| format!("pid {pid} has no SSH_AUTH_SOCK"))?;
    let path = PathBuf::from(value);
    validate_agent_endpoint(&path, uid)
}

fn validate_agent_endpoint(path: &Path, uid: u32) -> Result<VerifiedAgentEndpoint, String> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let metadata = std::fs::metadata(path)
        .map_err(|e| format!("stat SSH_AUTH_SOCK {}: {e}", path.display()))?;
    if !metadata.file_type().is_socket() {
        return Err(format!(
            "SSH_AUTH_SOCK {} is not a Unix socket",
            path.display()
        ));
    }
    if metadata.uid() != uid {
        return Err(format!(
            "SSH_AUTH_SOCK {} is owned by uid {}, not requesting uid {uid}",
            path.display(),
            metadata.uid()
        ));
    }
    let dev = metadata.dev();
    let ino = metadata.ino();
    let stream =
        platform_linux::ipc::connect_unix_timeout(path, std::time::Duration::from_millis(500))
            .map_err(|e| format!("connect SSH_AUTH_SOCK {}: {e}", path.display()))?;
    let peer = platform_linux::ipc::peer_credentials(&stream)
        .map_err(|e| format!("SO_PEERCRED for SSH_AUTH_SOCK {}: {e}", path.display()))?;
    if peer.uid != uid {
        return Err(format!(
            "SSH_AUTH_SOCK peer uid {} does not match requesting uid {uid}",
            peer.uid
        ));
    }
    let trusted_agent = platform_linux::identity::trusted_ssh_agent_path()?;
    let peer_identity =
        platform_linux::identity::verify_trusted_process_executable(peer.pid, uid, &trusted_agent)
            .map_err(|error| format!("untrusted SSH_AUTH_SOCK peer: {error}"))?;

    // Detect pathname replacement during the connection/identity check.
    let after = std::fs::metadata(path)
        .map_err(|e| format!("re-stat SSH_AUTH_SOCK {}: {e}", path.display()))?;
    if !after.file_type().is_socket() || after.dev() != dev || after.ino() != ino {
        return Err(format!(
            "SSH_AUTH_SOCK {} changed during endpoint verification",
            path.display()
        ));
    }
    Ok(VerifiedAgentEndpoint {
        path: path.to_path_buf(),
        dev,
        ino,
        peer: peer_identity,
    })
}

/// Pin the verified socket inode behind a root-controlled directory on the
/// same filesystem. ssh-add connects through this hardlink, so replacing the
/// user-controlled original pathname after authorization cannot redirect the
/// broker flow to a different listener.
fn pin_verified_agent_endpoint(
    endpoint: &VerifiedAgentEndpoint,
    uid: u32,
    pin_token: u64,
) -> Result<VerifiedAgentEndpoint, String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let pin_parent = trusted_pin_parent(&endpoint.path, endpoint.dev)?;
    let pin_dir = pin_parent.join(".guardd-agent-pins");
    match std::fs::create_dir(&pin_dir) {
        Ok(()) => std::fs::set_permissions(&pin_dir, std::fs::Permissions::from_mode(0o711))
            .map_err(|error| format!("chmod {}: {error}", pin_dir.display()))?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(format!("create {}: {error}", pin_dir.display())),
    }
    let directory = std::fs::symlink_metadata(&pin_dir)
        .map_err(|error| format!("stat {}: {error}", pin_dir.display()))?;
    if !directory.is_dir() || directory.uid() != 0 || directory.mode() & 0o022 != 0 {
        return Err(format!(
            "pin directory {} must be a root-owned, non-writable directory",
            pin_dir.display()
        ));
    }

    let pin = pin_dir.join(format!("a-{uid}-{}-{pin_token}.sock", std::process::id()));
    std::fs::hard_link(&endpoint.path, &pin).map_err(|error| {
        format!(
            "hardlink verified socket {} -> {}: {error}",
            endpoint.path.display(),
            pin.display()
        )
    })?;
    let pinned = match validate_agent_endpoint(&pin, uid) {
        Ok(value)
            if value.dev == endpoint.dev
                && value.ino == endpoint.ino
                && value.peer == endpoint.peer =>
        {
            value
        }
        Ok(_) => {
            let _ = std::fs::remove_file(&pin);
            return Err("pinned socket identity differs from verified endpoint".into());
        }
        Err(error) => {
            let _ = std::fs::remove_file(&pin);
            return Err(error);
        }
    };
    Ok(pinned)
}

fn trusted_pin_parent(socket: &Path, socket_dev: u64) -> Result<PathBuf, String> {
    use std::os::unix::fs::MetadataExt;

    let mut candidate = socket.parent();
    while let Some(path) = candidate {
        let metadata = std::fs::metadata(path)
            .map_err(|error| format!("stat socket ancestor {}: {error}", path.display()))?;
        if metadata.dev() != socket_dev {
            break;
        }
        let root_controlled = metadata.uid() == 0
            && (metadata.mode() & 0o022 == 0 || metadata.mode() & libc::S_ISVTX != 0);
        if root_controlled {
            return Ok(path.to_path_buf());
        }
        candidate = path.parent();
    }
    Err(format!(
        "no same-filesystem root-controlled ancestor for {}",
        socket.display()
    ))
}

fn cleanup_terminal_agent_pins(state: &IpcState) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let terminal: Vec<String> = {
        let engine = state.engine.lock().expect("engine mutex poisoned");
        engine
            .leases()
            .ssh
            .iter()
            .filter(|lease| lease.revoked || lease.used || now >= lease.expires_at)
            .map(|lease| lease.id.0.to_string())
            .collect()
    };
    for lease_id in terminal {
        remove_agent_pin(state, &lease_id);
    }
}

fn remove_agent_pin(state: &IpcState, lease_id: &str) {
    let path = state
        .ssh_agent_pins
        .lock()
        .expect("SSH agent pin mutex poisoned")
        .remove(lease_id);
    if let Some(path) = path {
        if let Err(error) = std::fs::remove_file(&path) {
            tracing::warn!(path = %path.display(), %error, "cannot remove SSH agent socket pin");
        }
    }
}

fn authorize_sensitive(
    state: &IpcState,
    creds: PeerCreds,
    connection_fd: Option<RawFd>,
    action: &str,
    details: &[(&str, &str)],
) -> Result<(), String> {
    match state.authorization {
        SensitiveAuthorization::Polkit => {}
    }

    if connection_fd.is_some_and(peer_connection_closed) {
        return Err(format!(
            "authorization cancelled for {action}: IPC connection closed"
        ));
    }
    if creds.uid == 0 {
        return Ok(());
    }
    let start_time = platform_linux::identity::read_start_time(creds.pid)
        .map_err(|e| format!("cannot verify authorization subject: {e}"))?;
    let subject = format!("{},{},{}", creds.pid, start_time, creds.uid);
    let mut command = build_pkcheck_command(action, &subject, details);
    let mut child = command.spawn().map_err(|error| {
        format!("authorization unavailable for {action}: cannot execute pkcheck: {error}")
    })?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => {
                if connection_fd.is_some_and(peer_connection_closed) {
                    return Err(format!(
                        "authorization cancelled for {action}: IPC connection closed"
                    ));
                }
                return Ok(());
            }
            Ok(Some(status)) => {
                return Err(format!(
                    "authorization denied for {action} (pkcheck status {status}; subject={subject})"
                ))
            }
            Ok(None) => {}
            Err(error) => {
                return Err(format!(
                    "authorization unavailable for {action}: waiting for pkcheck: {error}"
                ))
            }
        }

        // Do not grant after the kernel-authenticated IPC peer exited or its
        // PID was reused while a human authorization prompt was pending.
        match platform_linux::identity::read_start_time(creds.pid) {
            Ok(observed) if observed == start_time => {}
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "authorization cancelled for {action}: IPC peer exited or changed identity"
                ));
            }
        }
        if connection_fd.is_some_and(peer_connection_closed) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "authorization cancelled for {action}: IPC connection closed"
            ));
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "authorization timed out for {action} after 60 seconds"
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn peer_connection_closed(fd: RawFd) -> bool {
    let mut poll_fd = libc::pollfd {
        fd,
        events: libc::POLLIN | libc::POLLRDHUP,
        revents: 0,
    };
    // SAFETY: poll_fd describes one borrowed, live connection descriptor; a
    // zero timeout performs a non-mutating liveness check.
    let ready = unsafe { libc::poll(&mut poll_fd, 1, 0) };
    if ready < 0 {
        return std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR);
    }
    ready > 0
        && poll_fd.revents & (libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
}

fn revoke_unreceived_capability(state: &IpcState, response: &Response) {
    let lease_id = match response.body.as_ref() {
        Some(ResponseBody::MigrationAuthorized(info)) => Some(info.lease_id.as_str()),
        Some(ResponseBody::SshLoadAuthorized(info)) => Some(info.lease_id.as_str()),
        _ => None,
    };
    if let Some(lease_id) = lease_id {
        state
            .engine
            .lock()
            .expect("engine mutex poisoned")
            .revoke_lease(lease_id);
        remove_agent_pin(state, lease_id);
        tracing::warn!(
            lease_id,
            "revoked capability whose IPC response was not delivered"
        );
    }
}

fn build_pkcheck_command(action: &str, subject: &str, details: &[(&str, &str)]) -> Command {
    let mut command = Command::new("pkcheck");
    command
        .arg("--action-id")
        .arg(action)
        .arg("--process")
        .arg(subject)
        .arg("--allow-user-interaction")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (key, value) in details {
        // pkcheck accepts `-d KEY VALUE` or `--details=KEY VALUE`; a bare
        // three-argument `--details KEY VALUE` is rejected before polkit runs.
        command.arg("-d").arg(key).arg(value);
    }
    command
}

fn event_to_info(ev: &guard_audit::AuditEvent) -> EventInfo {
    let r = &ev.record;
    EventInfo {
        id: ev.id,
        event_code: r.event_code.clone(),
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

#[cfg(any())]
fn incident_to_info(incident: &guard_core::SshExposureIncident) -> SshIncidentInfo {
    let accessed_key_paths = incident
        .accessed_keys
        .iter()
        .map(|key| key.path.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    SshIncidentInfo {
        id: incident.id.clone(),
        uid: incident.uid,
        key_path: accessed_key_paths.first().cloned().unwrap_or_default(),
        accessed_key_paths,
        process_exe: incident.process_exe.to_string_lossy().into_owned(),
        pid: incident.root_process.pid,
        start_time: incident.root_process.start_time,
        parent_pid: incident.parent.as_ref().map(|parent| parent.pid),
        parent_exe: incident
            .parent
            .as_ref()
            .map(|parent| parent.exe.to_string_lossy().into_owned()),
        first_sensitive_read_ms: incident.first_sensitive_read_ms,
        last_sensitive_read_ms: incident.last_sensitive_read_ms,
        observe_until_ms: incident.observe_until_ms,
        state: match incident.state {
            guard_core::SshIncidentState::Observing => SshIncidentStateInfo::Observing,
            guard_core::SshIncidentState::PendingDecision => SshIncidentStateInfo::PendingDecision,
            guard_core::SshIncidentState::BlockedUntilExit => {
                SshIncidentStateInfo::BlockedUntilExit
            }
            guard_core::SshIncidentState::Allowed => SshIncidentStateInfo::Allowed,
            guard_core::SshIncidentState::Expired => SshIncidentStateInfo::Expired,
            guard_core::SshIncidentState::Quarantined => SshIncidentStateInfo::Quarantined,
            guard_core::SshIncidentState::Exited => SshIncidentStateInfo::Exited,
        },
        blocked_network_attempts: incident.blocked_network_attempts,
        first_network_ms: incident.first_network_ms,
        destination_ip: incident
            .destination
            .as_ref()
            .map(|destination| destination.ip.clone()),
        destination_port: incident
            .destination
            .as_ref()
            .map(|destination| destination.port),
        protocol: incident
            .destination
            .as_ref()
            .map(|destination| destination.protocol.clone()),
        resolution: incident.resolution.map(|resolution| match resolution {
            guard_core::IncidentResolution::BlockAndQuarantine => {
                IncidentResolutionInfo::BlockAndQuarantine
            }
            guard_core::IncidentResolution::Block => IncidentResolutionInfo::Block,
            guard_core::IncidentResolution::Allow => IncidentResolutionInfo::Allow,
        }),
        resolution_detail: incident.resolution_detail.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enforce::{EnforcementConfig, EnforcementEngine, EnforcementMode};
    use std::ffi::OsStr;
    use std::os::fd::AsRawFd;

    #[test]
    fn ssh_read_approval_releases_engine_lock_and_keeps_audit_metadata_only() {
        let fixture = guard_test_fixtures::SshFixture::create().expect("SSH fixture");
        let config = EnforcementConfig {
            config_version: platform_linux::config::CONFIG_VERSION,
            enforcement_mode: EnforcementMode::Conservative,
            browsers: vec![],
            enrolled_exes: vec![],
            ssh_keys: vec![fixture.private_key.clone()],
        };
        let engine = Arc::new(Mutex::new(
            EnforcementEngine::from_config(&config).expect("engine"),
        ));
        let key = std::fs::File::open(&fixture.private_key).expect("open fixture key");
        let details = {
            let mut engine = engine.lock().expect("engine mutex poisoned");
            engine
                .pending_ssh_details(std::process::id() as i32, key.as_raw_fd())
                .expect("pending SSH details")
        };

        // Mirror the IPC handler's critical invariant: materialize the result
        // before any branch reacquires the engine for audit metadata.
        let before_approval = unix_secs();
        let approval = engine
            .lock()
            .expect("engine mutex poisoned")
            .approve_pending_ssh_read(&details);
        let (lease_id, expires_at) = approval.expect("approve fixture read");
        let after_approval = unix_secs();
        assert!(expires_at >= before_approval + 10);
        assert!(expires_at <= after_approval + 10);

        let allowed = engine
            .lock()
            .expect("engine mutex poisoned")
            .ssh_read_audit_record(
                &details,
                "ssh_key_access_allowed",
                guard_core::Decision::AllowByLease(lease_id),
                "synthetic approval",
            );
        let blocked = engine
            .lock()
            .expect("engine mutex poisoned")
            .ssh_read_audit_record(
                &details,
                "ssh_key_access_blocked",
                guard_core::Decision::Deny(guard_core::DenyReason::IdentityMismatch),
                "synthetic block",
            );

        assert_eq!(engine.lock().expect("engine").leases().ssh_read.len(), 1);
        assert!(engine.try_lock().is_ok(), "approval left engine locked");
        for record in [allowed, blocked] {
            let json = serde_json::to_string(&record).expect("serialize audit record");
            assert!(!json.contains(guard_test_fixtures::markers::SSH_PRIVATE_KEY_MARKER));
            assert!(!json.contains("\"content\""));
            assert!(!json.contains("\"key_bytes\""));
        }
    }

    #[test]
    fn pkcheck_details_use_supported_short_option_form() {
        let command = build_pkcheck_command(
            "org.guardd.ssh-read-resolve",
            "123,456,1000",
            &[("key_path", "/tmp/synthetic-key"), ("pending_id", "1")],
        );
        let arguments = command.get_args().collect::<Vec<_>>();
        assert!(arguments.windows(3).any(|window| {
            window
                == [
                    OsStr::new("-d"),
                    OsStr::new("key_path"),
                    OsStr::new("/tmp/synthetic-key"),
                ]
        }));
        assert!(!arguments.contains(&OsStr::new("--details")));
    }

    #[test]
    fn ipc_connection_liveness_detects_peer_close() {
        let (server, client) = UnixStream::pair().expect("socket pair");
        assert!(!peer_connection_closed(server.as_raw_fd()));
        drop(client);
        assert!(peer_connection_closed(server.as_raw_fd()));
    }
}
