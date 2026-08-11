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

use guard_audit::{AuditRecord, AuditStore};
use guard_ipc::{
    ConfigCheckInfo, ConfigurationInfo, ConfiguredBrowserInfo, EventInfo, IncidentResolutionAction,
    IncidentResolutionInfo, LeaseInfo, MigrationAuthorizedInfo, MigrationPendingInfo,
    MigrationResolutionAction, MigrationResolutionInfo, Response, ResponseBody, SshIncidentInfo,
    SshIncidentStateInfo, SshLoadAuthorizedInfo, SshProtectedInfo, StatusInfo, MAX_REQUEST_BYTES,
    PROTOCOL_VERSION,
};
use guard_ipc::{Request, RequestOp};
use platform_linux::fanotify::FanotifyGroup;
use platform_linux::ipc::{read_request, write_response, IpcServer, PeerCreds};

use crate::enforce::{EnforcementEngine, SshAgentBinding};
use crate::pending::PendingMigrationStore;

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
    /// Capability/attachment state of the SSH read-to-send containment hook.
    /// It is kept separate from fanotify health so a green browser firewall
    /// never implies raw SSH reads are behaviorally guarded.
    pub ssh_behavior_backend: Arc<Mutex<platform_linux::ssh_behavior::SshBehaviorBackendStatus>>,
    /// Present only after all BPF links have attached. This is intentionally
    /// not exposed as a generic backend-control IPC capability.
    pub ssh_behavior_runtime: Option<Arc<Mutex<platform_linux::ssh_behavior::SshBehaviorBackend>>>,
    pub incidents: Arc<Mutex<guard_core::ExposureTracker>>,
    pub pending_migrations: Arc<Mutex<PendingMigrationStore>>,
}

#[derive(Debug, Clone, Copy)]
pub enum SensitiveAuthorization {
    Polkit,
    #[cfg(test)]
    AllowForTests,
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

/// Dispatch a single request to its handler, enforcing peer-uid authorization.
#[cfg(test)]
pub fn handle_request(state: &IpcState, creds: PeerCreds, op: RequestOp) -> Response {
    handle_request_with_connection(state, creds, op, None)
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
        RequestOp::ConfigCheck => handle_config_check(state, creds),
        RequestOp::Events {
            limit,
            before_id,
            after_id,
        } => handle_events(state, creds, limit, before_id, after_id),
        RequestOp::Explain { event_id } => handle_explain(state, creds, event_id),
        RequestOp::LeasesList => handle_leases_list(state, creds),
        RequestOp::LeasesRevoke { lease_id } => handle_leases_revoke(state, creds, lease_id),
        RequestOp::IncidentsList => handle_incidents_list(state, creds),
        RequestOp::IncidentGet { id } => handle_incident_get(state, creds, &id),
        RequestOp::IncidentResolve { id, action } => {
            handle_incident_resolve(state, creds, connection_fd, &id, action)
        }
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
        RequestOp::SshProtect { path } => handle_ssh_protect(state, creds, connection_fd, path),
        RequestOp::SshLoadAuthorize { path, ssh_add_pid } => {
            handle_ssh_load_authorize(state, creds, connection_fd, path, ssh_add_pid)
        }
    }
}

// --- handlers ---

fn handle_status(state: &IpcState, creds: PeerCreds) -> Response {
    let engine = state.engine.lock().expect("engine mutex poisoned");
    let incident_summary = state
        .incidents
        .lock()
        .expect("incident mutex poisoned")
        .summary();
    let behavior_status = state
        .ssh_behavior_backend
        .lock()
        .expect("SSH behavior status mutex poisoned");
    let ssh_behavior_backend_failures = u64::from(
        !matches!(
            &*behavior_status,
            platform_linux::ssh_behavior::SshBehaviorBackendStatus::Active
        ) && engine
            .registry()
            .files()
            .any(|resource| resource.kind == guard_core::ProtectedResourceKind::SshPrivateKey),
    );
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
    // Phase 14: compute a human-readable enforcement state.
    // - NOT_ENFORCING: no fanotify group (daemon running without enforcement).
    // - DEGRADED: enforcement is active but audit events were dropped,
    //   classification/topology failed, or the fanotify queue overflowed.
    // - ACTIVE: enforcement is running normally.
    let status = if state.group.is_none() {
        "NOT_ENFORCING"
    } else if audit_dropped > 0
        || engine.unclassified > 0
        || engine.topology_degraded
        || backend.fanotify_overflows > 0
        || backend.classifier_failures > 0
        || !filesystem_marks_healthy
    {
        "DEGRADED"
    } else {
        "ACTIVE"
    };
    let body = StatusInfo {
        version: state.version.clone(),
        enforcement_active: state.group.is_some(),
        status: status.to_string(),
        mode: state.backend_metrics.mode.as_str().to_owned(),
        marked_filesystems,
        required_filesystems,
        filesystem_marks_healthy,
        strict_events_total: backend.strict_events_total,
        strict_fast_allowed: backend.strict_fast_allowed,
        protected_events: backend.protected_events,
        fanotify_overflows: backend.fanotify_overflows,
        classifier_failures: backend.classifier_failures,
        strict_alias_scans: backend.strict_alias_scans,
        strict_alias_matches: backend.strict_alias_matches,
        topology_degraded: engine.topology_degraded,
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
        ssh_behavior_status: behavior_status.label().to_owned(),
        ssh_behavior_detail: behavior_status.detail().map(str::to_owned),
        ssh_behavior_active_incidents: incident_summary.active,
        ssh_behavior_pending_decisions: incident_summary.pending,
        ssh_behavior_key_reads: incident_summary.key_reads,
        ssh_behavior_network_blocks: incident_summary.network_blocks,
        ssh_behavior_user_allows: incident_summary.user_allows,
        ssh_behavior_quarantines: incident_summary.quarantines,
        ssh_behavior_backend_failures,
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

fn handle_configuration_get(state: &IpcState, _creds: PeerCreds) -> Response {
    let engine = state.engine.lock().expect("engine mutex poisoned");
    let cfg = engine.configuration();
    Response::ok(ResponseBody::Configuration(ConfigurationInfo {
        enforcement_mode: cfg.enforcement_mode.as_str().to_owned(),
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
        ssh_behavior_window_secs: cfg.ssh_behavior_window_secs,
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
        || event.record.event_code.starts_with("ssh_behavior_")
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

fn handle_incidents_list(state: &IpcState, creds: PeerCreds) -> Response {
    let incidents = state
        .incidents
        .lock()
        .expect("incident mutex poisoned")
        .incidents_for_uid(creds.uid, creds.uid == 0)
        .iter()
        .map(incident_to_info)
        .collect();
    Response::ok(ResponseBody::Incidents(incidents))
}

fn handle_incident_get(state: &IpcState, creds: PeerCreds, id: &str) -> Response {
    let incident = state
        .incidents
        .lock()
        .expect("incident mutex poisoned")
        .incidents_for_uid(creds.uid, creds.uid == 0)
        .into_iter()
        .find(|incident| incident.id == id);
    match incident {
        Some(incident) => Response::ok(ResponseBody::Incident(Box::new(incident_to_info(
            &incident,
        )))),
        None => Response::err("incident not found"),
    }
}

fn handle_incident_resolve(
    state: &IpcState,
    creds: PeerCreds,
    connection_fd: Option<RawFd>,
    id: &str,
    action: IncidentResolutionAction,
) -> Response {
    // Read and UID-check before opening a polkit prompt.  The incident ID is
    // never a capability: the authenticated peer may only resolve its own.
    let owned = state
        .incidents
        .lock()
        .expect("incident mutex poisoned")
        .incidents_for_uid(creds.uid, creds.uid == 0)
        .into_iter()
        .any(|incident| incident.id == id);
    if !owned {
        return Response::err("incident not found");
    }
    let action_name = match action {
        IncidentResolutionAction::BlockAndQuarantine => "block_and_quarantine",
        IncidentResolutionAction::Block => "block",
        IncidentResolutionAction::Allow => "allow",
    };
    if let Err(error) = authorize_sensitive(
        state,
        creds,
        connection_fd,
        "org.guardd.incident-resolve",
        &[("incident_id", id), ("resolution", action_name)],
    ) {
        return Response::err(error);
    }
    let resolution = match action {
        IncidentResolutionAction::BlockAndQuarantine => {
            guard_core::IncidentResolution::BlockAndQuarantine
        }
        IncidentResolutionAction::Block => guard_core::IncidentResolution::Block,
        IncidentResolutionAction::Allow => guard_core::IncidentResolution::Allow,
    };
    let kernel_id = match id
        .strip_prefix("ssh-")
        .and_then(|value| u64::from_str_radix(value, 16).ok())
    {
        Some(value) => value,
        None => return Response::err("invalid incident identifier"),
    };
    let incident_before = match state
        .incidents
        .lock()
        .expect("incident mutex poisoned")
        .incidents_for_uid(creds.uid, creds.uid == 0)
        .into_iter()
        .find(|incident| incident.id == id)
    {
        Some(incident) if incident.state == guard_core::SshIncidentState::PendingDecision => {
            incident
        }
        Some(_) => return Response::err("incident is not awaiting a decision"),
        None => return Response::err("incident not found"),
    };
    let resolution_detail;
    let backend_diag;
    match action {
        IncidentResolutionAction::Allow => {
            let Some(runtime) = &state.ssh_behavior_runtime else {
                return Response::err("SSH behavioral backend is not active");
            };
            if let Err(error) = runtime
                .lock()
                .expect("SSH behavior backend mutex poisoned")
                .resolve(kernel_id, true)
            {
                return Response::err(format!("cannot allow incident networking: {error}"));
            }
            resolution_detail =
                "Outbound networking was allowed for this incident process tree.".into();
            backend_diag = format!("ssh_behavior_allowed_by_user;incident={id}");
        }
        IncidentResolutionAction::Block => {
            resolution_detail =
                "External networking remains blocked for this incident process tree until it exits. The process was not terminated.".into();
            backend_diag = format!("ssh_behavior_blocked_by_user;incident={id}");
        }
        IncidentResolutionAction::BlockAndQuarantine => {
            let Some(runtime) = &state.ssh_behavior_runtime else {
                return Response::err("SSH behavioral backend is not active");
            };
            let initial = match runtime
                .lock()
                .expect("SSH behavior backend mutex poisoned")
                .incident_tgids(kernel_id)
            {
                Ok(pids) => pids,
                Err(error) => {
                    return Response::err(format!("cannot inspect incident process tree: {error}"))
                }
            };
            let result = platform_linux::containment::terminate_incident_tree(
                &incident_before.root_process,
                incident_before.uid,
                &initial,
                || {
                    runtime
                        .lock()
                        .expect("SSH behavior backend mutex poisoned")
                        .incident_tgids(kernel_id)
                },
            );
            let result = match result {
                Ok(result) => result,
                Err(error) => return Response::err(format!("process containment failed: {error}")),
            };
            let mut quarantine = runtime.lock().expect("SSH behavior backend mutex poisoned");
            let quarantine = incident_before.quarantine_candidate.as_ref().map_or(
                Ok(platform_linux::quarantine::QuarantineResult::NoSafeCandidate),
                |candidate| {
                    platform_linux::quarantine::quarantine_candidate(
                        candidate,
                        incident_before.uid,
                        id,
                        &mut quarantine,
                    )
                },
            );
            resolution_detail = match quarantine {
                Ok(platform_linux::quarantine::QuarantineResult::Quarantined { path, sha256 }) => format!(
                    "Terminated {} verified incident process(es). Quarantined an attributable artifact at {}; SHA-256 {}.",
                    result.terminated_processes,
                    path.display(),
                    sha256
                ),
                Ok(platform_linux::quarantine::QuarantineResult::NoSafeCandidate) => format!(
                    "Terminated {} verified incident process(es). No safe quarantine target was identified.",
                    result.terminated_processes
                ),
                Err(error) => format!(
                    "Terminated {} verified incident process(es). Artifact quarantine was not completed: {error}",
                    result.terminated_processes
                ),
            };
            backend_diag = format!(
                "ssh_behavior_blocked_and_quarantined;incident={};terminated={};{}",
                id,
                result.terminated_processes,
                if resolution_detail.contains("Quarantined an attributable artifact") {
                    "quarantine=artifact"
                } else {
                    "quarantine=none"
                }
            );
            if let Err(error) = runtime
                .lock()
                .expect("SSH behavior backend mutex poisoned")
                .resolve(kernel_id, false)
            {
                return Response::err(format!(
                    "quarantine completed but kernel incident cleanup failed: {error}"
                ));
            }
        }
    }
    let mut tracker = state.incidents.lock().expect("incident mutex poisoned");
    if let Err(error) = tracker.resolve(id, resolution) {
        return Response::err(error);
    }
    if let Err(error) = tracker.set_resolution_detail(id, resolution_detail) {
        return Response::err(error);
    }
    let incident = tracker
        .incidents_for_uid(creds.uid, creds.uid == 0)
        .into_iter()
        .find(|incident| incident.id == id)
        .expect("resolved incident remains visible");
    state.audit.record(AuditRecord {
        event_code: match action {
            IncidentResolutionAction::BlockAndQuarantine => "ssh_behavior_blocked_and_quarantined",
            IncidentResolutionAction::Block => "ssh_behavior_blocked_by_user",
            IncidentResolutionAction::Allow => "ssh_behavior_allowed_by_user",
        }
        .into(),
        ts_ms: crate::unix_ms(),
        uid: incident.uid,
        pid: incident.root_process.pid,
        start_time: incident.root_process.start_time,
        decision: if matches!(action, IncidentResolutionAction::Allow) {
            guard_core::Decision::Allow
        } else {
            guard_core::Decision::Deny(guard_core::DenyReason::SshBehaviorNetworkBlocked)
        },
        deny_reason: if matches!(action, IncidentResolutionAction::Allow) {
            None
        } else {
            Some(guard_core::DenyReason::SshBehaviorNetworkBlocked)
        },
        resource_kind: guard_core::ProtectedResourceKind::SshPrivateKey,
        resource_browser: None,
        resource_profile: None,
        path: incident
            .accessed_keys
            .first()
            .map(|key| key.path.to_string_lossy().into_owned())
            .unwrap_or_default(),
        exe: incident.process_exe.to_string_lossy().into_owned(),
        exe_owner_uid: 0,
        trust_tier: guard_core::TrustTier::Unknown,
        process_browser: None,
        parent_pid: incident.parent.as_ref().map(|parent| parent.pid),
        parent_exe: incident
            .parent
            .as_ref()
            .map(|parent| parent.exe.to_string_lossy().into_owned()),
        lease_id: None,
        backend_diag,
    });
    Response::ok(ResponseBody::IncidentResolved(incident_to_info(&incident)))
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
        #[cfg(test)]
        SensitiveAuthorization::AllowForTests => return Ok(()),
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
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
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
                "authorization timed out for {action} after 120 seconds"
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
    //! IPC handler tests. No root required: the engine + audit store are
    //! constructed in-process and `handle_request` is called directly with
    //! synthetic `PeerCreds`. This covers the prompt's authorization tests:
    //! - UID spoof attempt fails (ordinary user cannot see another user's events)
    //! - explain from CLI (record -> query -> explain round-trip)
    //! - lease revoke authorization

    use super::*;
    use crate::enforce::{
        BrowserEnrollmentConfig, EnforcementConfig, EnforcementEngine, EnforcementMode,
    };
    use guard_core::identity::{ProcessIdentity, ProcessStableId, TrustTier};
    use guard_core::lease::{LeaseId, LeaseSet, MigrationAccessLease, MigrationLeaseState};
    use guard_core::policy::{Decision, DenyReason};
    use guard_core::resource::{
        BrowserFamily, BrowserId, ProfileId, ProtectedResource, ProtectedResourceId,
        ProtectedResourceKind,
    };
    use guard_test_fixtures::chromium::ChromiumProfile;
    use std::path::PathBuf;
    use std::process::{Child, Command};

    struct ChildGuard(Option<Child>);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    fn wait_for_path(path: &Path) {
        for _ in 0..100 {
            if path.exists() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("{} was not created", path.display());
    }

    #[test]
    fn agent_endpoint_rejects_same_uid_fake_listener() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("fake-agent.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        // The peer credentials identify this test binary, not ssh-agent.
        let error = validate_agent_endpoint(
            &socket,
            // SAFETY: getuid has no preconditions.
            unsafe { libc::getuid() },
        )
        .unwrap_err();
        assert!(error.contains("untrusted SSH_AUTH_SOCK peer"), "{error}");
    }

    #[test]
    fn agent_endpoint_accepts_kernel_observed_system_ssh_agent() {
        let trusted = platform_linux::identity::trusted_ssh_agent_path().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let child = Command::new(&trusted)
            .arg("-D")
            .arg("-a")
            .arg(&socket)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let _guard = ChildGuard(Some(child));
        wait_for_path(&socket);

        let endpoint = match validate_agent_endpoint(
            &socket,
            // SAFETY: getuid has no preconditions.
            unsafe { libc::getuid() },
        ) {
            Ok(endpoint) => endpoint,
            Err(error)
                if unsafe { libc::geteuid() } != 0 && error.contains("Permission denied") =>
            {
                // ssh-agent is non-dumpable; the root daemon can resolve its
                // /proc identity and the privileged suite covers that path.
                return;
            }
            Err(error) => panic!("trusted ssh-agent endpoint verification failed: {error}"),
        };
        assert_eq!(endpoint.peer.pid, pid);
        assert_eq!(endpoint.peer.exe, trusted);
    }

    #[test]
    fn pkcheck_details_use_the_supported_short_option_form() {
        use std::ffi::OsStr;

        let command = build_pkcheck_command(
            "org.guardd.ssh-protect",
            "123,456,1000",
            &[("path", "/tmp/synthetic-key")],
        );
        let arguments: Vec<&OsStr> = command.get_args().collect();
        assert!(arguments.windows(3).any(|window| {
            window
                == [
                    OsStr::new("-d"),
                    OsStr::new("path"),
                    OsStr::new("/tmp/synthetic-key"),
                ]
        }));
        assert!(!arguments.contains(&OsStr::new("--details")));
    }

    #[test]
    fn ipc_connection_liveness_detects_peer_close() {
        use std::os::fd::AsRawFd;

        let (server, client) = UnixStream::pair().expect("socket pair");
        assert!(!peer_connection_closed(server.as_raw_fd()));
        drop(client);
        assert!(peer_connection_closed(server.as_raw_fd()));
    }

    /// Build an `IpcState` backed by a synthetic Chromium profile and an
    /// ephemeral SQLite audit db. Returns the state plus both tempdirs — the
    /// caller MUST keep the tempdirs alive for the duration of the test, or the
    /// audit db file (and the chromium profile) will be deleted out from under
    /// the engine.
    fn make_state(uid: u32) -> (IpcState, (tempfile::TempDir, tempfile::TempDir)) {
        let p = ChromiumProfile::create("Default").unwrap();
        let cfg = EnforcementConfig {
            enforcement_mode: EnforcementMode::Conservative,
            browsers: vec![BrowserEnrollmentConfig {
                id: "chrome".into(),
                family: BrowserFamily::Chromium,
                profile_root: p.user_data_dir.clone(),
                owner_uid: Some(uid),
                exe_paths: vec![],
            }],
            enrolled_exes: vec![],
            ssh_keys: vec![],
            ssh_behavior_window_secs: guard_core::DEFAULT_SSH_BEHAVIOR_WINDOW_SECS,
        };
        let engine = EnforcementEngine::from_config(&cfg).unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let audit = AuditStore::open(&audit_dir.path().join("audit.db")).unwrap();
        let state = IpcState {
            engine: Arc::new(Mutex::new(engine)),
            audit: Arc::new(audit),
            version: "0.1.0-test".into(),
            group: None,
            authorization: SensitiveAuthorization::AllowForTests,
            ssh_agent_pins: Arc::new(Mutex::new(HashMap::new())),
            backend_metrics: Arc::new(crate::strict::BackendMetrics::new(
                EnforcementMode::Conservative,
            )),
            ssh_behavior_backend: Arc::new(Mutex::new(
                platform_linux::ssh_behavior::SshBehaviorBackendStatus::Active,
            )),
            ssh_behavior_runtime: None,
            incidents: Arc::new(Mutex::new(guard_core::ExposureTracker::default())),
            pending_migrations: Arc::new(Mutex::new(PendingMigrationStore::default())),
        };
        (state, (p.root, audit_dir))
    }

    fn sample_record(uid: u32, decision: Decision) -> guard_audit::AuditRecord {
        guard_audit::AuditRecord {
            event_code: "access_decision".into(),
            ts_ms: 1_700_000_000_000,
            uid,
            pid: 4242,
            start_time: 9999,
            decision: decision.clone(),
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
    fn same_uid_incident_id_is_not_authority_to_allow() {
        let uid = unsafe { libc::getuid() };
        let (mut state, _temp) = make_state(uid);
        state.authorization = SensitiveAuthorization::Polkit;
        let process = ProcessIdentity {
            stable: ProcessStableId {
                pid: std::process::id(),
                start_time: 1,
                exe: "/synthetic/offender".into(),
                exe_dev: 1,
                exe_ino: 2,
            },
            uid,
            gid: uid,
            exe_owner_uid: uid,
            browser: None,
            trust_tier: TrustTier::Unknown,
            cmdline: vec!["/synthetic/offender".into()],
            ancestors: Vec::new(),
        };
        let resource = ProtectedResource {
            id: ProtectedResourceId("ssh/synthetic".into()),
            kind: ProtectedResourceKind::SshPrivateKey,
            owner_uid: uid,
            browser: None,
            profile: None,
            path: "/synthetic/id_ed25519".into(),
        };
        let incident = {
            let mut tracker = state.incidents.lock().unwrap();
            let (incident, _) = tracker.arm(&resource, &process, None, std::process::id(), 100, 10);
            assert!(matches!(
                tracker.network_send(
                    &process,
                    guard_core::NetworkDestination {
                        ip: "198.18.0.1".into(),
                        port: 443,
                        protocol: "tcp".into(),
                    },
                    200,
                ),
                guard_core::NetworkDecision::Block { .. }
            ));
            incident
        };
        let response = handle_request(
            &state,
            PeerCreds {
                pid: std::process::id() as i32,
                uid,
                gid: uid,
            },
            RequestOp::IncidentResolve {
                id: incident.id.clone(),
                action: IncidentResolutionAction::Allow,
            },
        );
        assert!(!response.ok);
        assert!(response
            .error
            .as_deref()
            .is_some_and(|error| error.contains("authorization")));
        assert_eq!(
            state
                .incidents
                .lock()
                .unwrap()
                .incident_for_kernel_id(1)
                .unwrap()
                .state,
            guard_core::SshIncidentState::PendingDecision
        );
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
    fn configuration_snapshot_preserves_configured_browser_metadata() {
        let (state, _t) = make_state(1000);
        let response = handle_request(
            &state,
            PeerCreds {
                pid: 1,
                uid: 1000,
                gid: 1000,
            },
            RequestOp::ConfigurationGet,
        );
        assert!(response.ok);
        match response.body.unwrap() {
            ResponseBody::Configuration(configuration) => {
                assert_eq!(configuration.enforcement_mode, "conservative");
                assert_eq!(configuration.browsers.len(), 1);
                assert_eq!(configuration.browsers[0].owner_uid, Some(1000));
                assert!(configuration.ssh_keys.is_empty());
            }
            _ => panic!("expected Configuration"),
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
        state.audit.record(sample_record(
            1000,
            Decision::Deny(DenyReason::UnknownProcess),
        ));
        state.audit.record(sample_record(
            1001,
            Decision::Deny(DenyReason::UnknownProcess),
        ));
        state.audit.flush();

        // User 1000 asks for events — should see only their own (1 event).
        let resp = handle_request(
            &state,
            PeerCreds {
                pid: 1,
                uid: 1000,
                gid: 1000,
            },
            RequestOp::Events {
                limit: Some(100),
                before_id: None,
                after_id: None,
            },
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
            RequestOp::Events {
                limit: Some(100),
                before_id: None,
                after_id: None,
            },
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
        state.audit.record(sample_record(
            1000,
            Decision::Deny(DenyReason::UnknownProcess),
        ));
        state.audit.record(sample_record(
            1001,
            Decision::Deny(DenyReason::UnknownProcess),
        ));
        state.audit.flush();

        let resp = handle_request(
            &state,
            PeerCreds {
                pid: 1,
                uid: 0,
                gid: 0,
            },
            RequestOp::Events {
                limit: Some(100),
                before_id: None,
                after_id: None,
            },
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
        state.audit.record(sample_record(
            1001,
            Decision::Deny(DenyReason::UnknownProcess),
        ));
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
                migration: vec![MigrationAccessLease {
                    id: LeaseId(1),
                    source_browser: BrowserId("chrome".into()),
                    source_profile: ProfileId("Default".into()),
                    target_browser: BrowserId("firefox".into()),
                    uid: 1000,
                    state: MigrationLeaseState::Armed {
                        target: guard_core::identity::ExeIdentity {
                            exe: PathBuf::from("/usr/bin/firefox"),
                            dev: 1,
                            ino: 2,
                        },
                    },
                    expires_at: 999_999_999,
                    revoked: false,
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
                migration: vec![MigrationAccessLease {
                    id: LeaseId(5),
                    source_browser: BrowserId("chrome".into()),
                    source_profile: ProfileId("Default".into()),
                    target_browser: BrowserId("firefox".into()),
                    uid: 1000,
                    state: MigrationLeaseState::Armed {
                        target: guard_core::identity::ExeIdentity {
                            exe: PathBuf::from("/usr/bin/firefox"),
                            dev: 1,
                            ino: 2,
                        },
                    },
                    expires_at: 999_999_999,
                    revoked: false,
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
            enforcement_mode: EnforcementMode::Conservative,
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
            ssh_behavior_window_secs: guard_core::DEFAULT_SSH_BEHAVIOR_WINDOW_SECS,
        };
        let engine = EnforcementEngine::from_config(&cfg).unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let audit = AuditStore::open(&audit_dir.path().join("audit.db")).unwrap();
        let state = IpcState {
            engine: Arc::new(Mutex::new(engine)),
            audit: Arc::new(audit),
            version: "0.1.0-test".into(),
            group: None,
            authorization: SensitiveAuthorization::AllowForTests,
            ssh_agent_pins: Arc::new(Mutex::new(HashMap::new())),
            backend_metrics: Arc::new(crate::strict::BackendMetrics::new(
                EnforcementMode::Conservative,
            )),
            ssh_behavior_backend: Arc::new(Mutex::new(
                platform_linux::ssh_behavior::SshBehaviorBackendStatus::Active,
            )),
            ssh_behavior_runtime: None,
            incidents: Arc::new(Mutex::new(guard_core::ExposureTracker::default())),
            pending_migrations: Arc::new(Mutex::new(PendingMigrationStore::default())),
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
                assert!(
                    !m.read_only_guaranteed,
                    "fanotify backend must not claim read-only enforcement"
                );
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
                assert!(matches!(stored.state, MigrationLeaseState::Armed { .. }));
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
            RequestOp::Events {
                limit: Some(10),
                before_id: None,
                after_id: None,
            },
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
            authorization: SensitiveAuthorization::AllowForTests,
            ssh_agent_pins: Arc::clone(&state.ssh_agent_pins),
            backend_metrics: Arc::clone(&state.backend_metrics),
            ssh_behavior_backend: Arc::new(Mutex::new(
                platform_linux::ssh_behavior::SshBehaviorBackendStatus::Active,
            )),
            ssh_behavior_runtime: None,
            incidents: Arc::clone(&state.incidents),
            pending_migrations: Arc::clone(&state.pending_migrations),
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
            authorization: SensitiveAuthorization::AllowForTests,
            ssh_agent_pins: Arc::clone(&state.ssh_agent_pins),
            backend_metrics: Arc::clone(&state.backend_metrics),
            ssh_behavior_backend: Arc::new(Mutex::new(
                platform_linux::ssh_behavior::SshBehaviorBackendStatus::Active,
            )),
            ssh_behavior_runtime: None,
            incidents: Arc::clone(&state.incidents),
            pending_migrations: Arc::clone(&state.pending_migrations),
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
            op: RequestOp::Events {
                limit: Some(10),
                before_id: None,
                after_id: None,
            },
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
            authorization: SensitiveAuthorization::AllowForTests,
            ssh_agent_pins: Arc::clone(&state.ssh_agent_pins),
            backend_metrics: Arc::clone(&state.backend_metrics),
            ssh_behavior_backend: Arc::new(Mutex::new(
                platform_linux::ssh_behavior::SshBehaviorBackendStatus::Active,
            )),
            ssh_behavior_runtime: None,
            incidents: Arc::clone(&state.incidents),
            pending_migrations: Arc::clone(&state.pending_migrations),
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
