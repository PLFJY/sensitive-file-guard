use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::ExitCode;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use guard_ipc::{
    MigrationResolutionAction, Request, RequestOp, Response, ResponseBody, SshReadResolutionAction,
    StatusInfo,
};
use guard_platform::BackendHealth;
use platform_macos::browser_trust::MacProcessIdentityResolver;
use platform_macos::config::MacBackendConfig;
use platform_macos::endpoint_security::{
    EndpointSecurityBackend, EndpointSecurityConfig, MacProtectedResources,
};
use platform_macos::identity::MacProcessGraph;
use platform_macos::process_shield::MacProcessShield;
use platform_macos::xpc::{
    AuthenticatedPeer, MacXpcServer, SigningRequirements, XpcRequestHandler,
};

use crate::policy::{prepare_config, MacPolicy};

const AUDIT_PATH: &str = "/Library/Application Support/Sensitive Data Firewall/audit.db";
const HELPER_HEALTH_WINDOW: Duration = Duration::from_secs(3);

struct ControlHandler {
    policy: Arc<MacPolicy>,
    backend_health: Arc<RwLock<BackendHealth>>,
    helper_heartbeats: Mutex<HashMap<u32, Instant>>,
}

impl XpcRequestHandler for ControlHandler {
    fn handle(&self, peer: AuthenticatedPeer, request: Request) -> Response {
        match request.op {
            RequestOp::Status => self.status(peer),
            RequestOp::ConfigurationGet => match self.policy.config() {
                Ok(config) => Response::ok(ResponseBody::Configuration(
                    config.to_ipc_metadata_for_uid(peer.euid),
                )),
                Err(error) => Response::err(format!("configuration_unavailable: {error}")),
            },
            RequestOp::ConfigurationApply { config } => self.apply_configuration(peer.euid, config),
            RequestOp::PendingHelperPoll => self.pending_helper_poll(peer.euid),
            RequestOp::PendingHelperStatus => self.pending_helper_status(peer.euid),
            RequestOp::MigrationPendingList => Response::ok(ResponseBody::MigrationPending(
                self.policy.pending_for_uid(peer.euid),
            )),
            RequestOp::MigrationPendingGet { id } => {
                match self.policy.pending_item_for_uid(&id, peer.euid) {
                    Some(item) => Response::ok(ResponseBody::MigrationPendingItem(Box::new(item))),
                    None => Response::err("pending_migration_not_found"),
                }
            }
            RequestOp::MigrationResolve { id, action } => {
                let allow = action == MigrationResolutionAction::AllowImport;
                match self.policy.resolve_migration(&id, peer.euid, allow) {
                    Ok(result) => Response::ok(ResponseBody::MigrationResolved(result)),
                    Err(error) => Response::err(error.to_string()),
                }
            }
            RequestOp::ResourcesList => Response::ok(ResponseBody::Resources(
                self.policy.resources_for_uid(peer.euid),
            )),
            RequestOp::BrowsersList => Response::ok(ResponseBody::Browsers(
                self.policy.browsers_for_uid(peer.euid),
            )),
            RequestOp::Events {
                limit,
                before_id,
                after_id,
            } => match self.policy.recent_events(
                peer.euid,
                limit.unwrap_or(100).clamp(1, 10_000),
                before_id,
                after_id,
            ) {
                Ok(events) => Response::ok(ResponseBody::Events(events)),
                Err(error) => Response::err(format!("audit_query_failed: {error}")),
            },
            RequestOp::Explain { event_id } => {
                match self.policy.explain_event(peer.euid, event_id) {
                    Ok(Some(event)) => Response::ok(ResponseBody::Explain(Box::new(event))),
                    Ok(None) => Response::err("event_not_found"),
                    Err(error) => Response::err(format!("audit_query_failed: {error}")),
                }
            }
            RequestOp::LeasesList => Response::ok(ResponseBody::Leases(
                self.policy.lease_infos_for_uid(peer.euid),
            )),
            RequestOp::LeasesRevoke { lease_id } => {
                let found = self.policy.revoke_lease_by_id(&lease_id, peer.euid);
                Response::ok(ResponseBody::LeaseRevoked { lease_id, found })
            }
            RequestOp::ConfigCheck => {
                let result = self.policy.config().and_then(|config| {
                    let (index, _, _) = prepare_config(Some(&config))?;
                    Ok(guard_ipc::ConfigCheckInfo {
                        valid: true,
                        browsers: config.browser_trust.len(),
                        protected_files: index.concrete_count(),
                        protected_trees: index.tree_root_count(),
                        enrolled_exes: config
                            .browser_trust
                            .iter()
                            .map(|browser| browser.executables.len())
                            .sum(),
                        error: None,
                    })
                });
                match result {
                    Ok(info) => Response::ok(ResponseBody::ConfigCheck(info)),
                    Err(error) => {
                        Response::ok(ResponseBody::ConfigCheck(guard_ipc::ConfigCheckInfo {
                            valid: false,
                            browsers: 0,
                            protected_files: 0,
                            protected_trees: 0,
                            enrolled_exes: 0,
                            error: Some(error.to_string()),
                        }))
                    }
                }
            }
            RequestOp::SshPendingList => Response::ok(ResponseBody::SshPending(
                self.policy.ssh_pending_for_uid(peer.euid),
            )),
            RequestOp::SshPendingGet { id } => {
                match self.policy.ssh_pending_item_for_uid(&id, peer.euid) {
                    Some(item) => Response::ok(ResponseBody::SshPendingItem(Box::new(item))),
                    None => Response::err("pending_ssh_read_not_found"),
                }
            }
            RequestOp::SshReadResolve { id, action } => {
                let allow = action == SshReadResolutionAction::Allow;
                match self.policy.resolve_ssh_read(&id, peer.euid, allow) {
                    Ok(result) => Response::ok(ResponseBody::SshReadResolved(result)),
                    Err(error) => Response::err(error.to_string()),
                }
            }
            RequestOp::SshProtect { path } => self.protect_ssh_key(peer.euid, &path),
            RequestOp::SshLoadAuthorize { .. } => Response::err(
                "ssh_load_not_supported_on_macos: use ordinary ssh-add and approve its protected-key read",
            ),
            _ => Response::err("operation_not_available_on_macos"),
        }
    }
}

impl ControlHandler {
    fn apply_configuration(&self, peer_uid: u32, value: serde_json::Value) -> Response {
        let config = match serde_json::from_value::<MacBackendConfig>(value) {
            Ok(config) => config,
            Err(error) => return Response::err(format!("invalid_configuration: {error}")),
        };
        if let Err(error) = config.validate_for_peer(peer_uid) {
            return Response::err(format!("configuration_scope_denied: {error}"));
        }
        if let Err(error) = prepare_config(Some(&config)) {
            return Response::err(format!("configuration_prepare_failed: {error}"));
        }
        if let Err(error) = config.write_authoritative() {
            return Response::err(format!("configuration_apply_failed: {error}"));
        }
        if let Err(error) = self.policy.apply_config(config.clone()) {
            return Response::err(format!("configuration_reload_failed: {error}"));
        }
        Response::ok(ResponseBody::ConfigurationApplied {
            version: config.version,
        })
    }

    fn protect_ssh_key(&self, peer_uid: u32, path: &str) -> Response {
        let current = match self.policy.config_optional() {
            Ok(config) => config,
            Err(error) => return Response::err(format!("configuration_unavailable: {error}")),
        };
        let (config, resource) = match MacBackendConfig::with_ssh_key_for_peer(
            current.as_ref(),
            Path::new(path),
            peer_uid,
        ) {
            Ok(update) => update,
            Err(error) => return Response::err(format!("ssh_enrollment_denied: {error}")),
        };
        if let Err(error) = prepare_config(Some(&config)) {
            return Response::err(format!("configuration_prepare_failed: {error}"));
        }
        if let Err(error) = config.write_authoritative() {
            return Response::err(format!("configuration_apply_failed: {error}"));
        }
        if let Err(error) = self.policy.apply_config(config) {
            return Response::err(format!("configuration_reload_failed: {error}"));
        }
        Response::ok(ResponseBody::SshProtected(guard_ipc::SshProtectedInfo {
            path: resource.path.to_string_lossy().into_owned(),
            owner_uid: resource.owner_uid,
            resource_id: resource.id.0,
        }))
    }

    fn pending_helper_poll(&self, uid: u32) -> Response {
        let Ok(mut heartbeats) = self.helper_heartbeats.lock() else {
            return Response::err("pending_helper_health_unavailable");
        };
        heartbeats.insert(uid, Instant::now());
        drop(heartbeats);
        Response::ok(ResponseBody::PendingHelperSnapshot(
            guard_ipc::PendingHelperSnapshotInfo {
                migrations: self.policy.pending_for_uid(uid),
                ssh_reads: self.policy.ssh_pending_for_uid(uid),
            },
        ))
    }

    fn pending_helper_status(&self, uid: u32) -> Response {
        let Ok(heartbeats) = self.helper_heartbeats.lock() else {
            return Response::err("pending_helper_health_unavailable");
        };
        let elapsed = heartbeats.get(&uid).map(Instant::elapsed);
        Response::ok(ResponseBody::PendingHelper(guard_ipc::PendingHelperInfo {
            running: elapsed.is_some_and(|age| age < HELPER_HEALTH_WINDOW),
            last_seen_ms_ago: elapsed.map(|age| u64::try_from(age.as_millis()).unwrap_or(u64::MAX)),
        }))
    }

    fn status(&self, peer: AuthenticatedPeer) -> Response {
        let health = self
            .backend_health
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let stats = self.policy.stats();
        let (protected_files, protected_trees) = self.policy.resource_counts();
        let enforcing = health.active && self.policy.enabled();
        let degraded = enforcing
            && (health.degraded
                || stats.classifier_failures > 0
                || self.policy.audit_dropped() > 0);
        // Built before any field move so the backend health can be borrowed.
        let process_shield =
            process_shield_info(&health, self.policy.config_optional().ok().flatten());
        Response::ok(ResponseBody::Status(Box::new(StatusInfo {
            version: env!("CARGO_PKG_VERSION").into(),
            backend_kind: "macos-endpoint-security".into(),
            backend_diagnostic: health.diagnostic,
            backend_state: Some(health.state.clone()),
            enforcement_active: enforcing,
            read_only_guaranteed: Some(true),
            status: if !enforcing {
                "NOT_ENFORCING"
            } else if degraded {
                "DEGRADED"
            } else {
                "ACTIVE"
            }
            .into(),
            mode: None,
            marked_filesystems: None,
            required_filesystems: None,
            filesystem_marks_healthy: None,
            strict_events_total: None,
            strict_fast_allowed: None,
            protected_events: stats.protected_events,
            fanotify_overflows: None,
            classifier_failures: Some(stats.classifier_failures),
            strict_alias_scans: None,
            strict_alias_matches: None,
            topology_degraded: None,
            mac_health: Some(Box::new(guard_ipc::MacHealthInfo {
                es_sequence_gaps: health.sequence_gaps,
                es_global_sequence_gaps: health.global_sequence_gaps,
                pending_created: health.pending_created,
                pending_resolved_allow: health.pending_resolved_allow,
                pending_resolved_deny: health.pending_resolved_deny,
                pending_timed_out: health.pending_timed_out,
                insufficient_deadline: health.insufficient_deadline,
                late_responses: health.late_responses,
                namespace_allowed: health.namespace_allowed,
                namespace_denied: health.namespace_denied,
                namespace_alias_entries: health.namespace_alias_entries,
                namespace_alias_capacity: health.namespace_alias_capacity,
                namespace_index_saturated: health.namespace_index_saturated,
                process_graph_degraded: health.process_graph_degraded,
                task_control_allowed: health.task_control_allowed,
                task_control_denied: health.task_control_denied,
                task_read_allowed: health.task_read_allowed,
                task_read_denied: health.task_read_denied,
                task_read_supported: health.task_read_supported,
                task_notify_supported: health.task_notify_supported,
                shield_admitted: health.shield_admitted,
                shield_compromised: health.shield_compromised,
                shield_launch_injection_denied: health.shield_launch_injection_denied,
                shield_malformed_denied: health.shield_malformed_denied,
                shield_task_notify_obtained: health.shield_task_notify_obtained,
                shield_trace_observed: health.shield_trace_observed,
                shield_remote_thread_observed: health.shield_remote_thread_observed,
                shield_cs_invalidated_observed: health.shield_cs_invalidated_observed,
                process_shield: Some(Box::new(process_shield)),
            })),
            protected_files,
            ssh_protected_keys: self.policy.ssh_key_count(),
            protected_trees,
            browsers: self.policy.browser_count(),
            browser_exes: self.policy.browser_executable_count(),
            allowed: stats.allowed,
            denied: stats.denied,
            unclassified: 0,
            audit_dropped: self.policy.audit_dropped(),
            peer_uid: peer.euid,
        })))
    }
}

pub fn run() -> ExitCode {
    let requirements = match SigningRequirements::current_process() {
        Ok(requirements) => requirements,
        Err(error) => {
            eprintln!("guard-es: authenticated XPC unavailable: {error}");
            return diagnostic_exit();
        }
    };
    let console_uid = match platform_macos::xpc::console_user_uid() {
        Ok(uid) => uid,
        Err(error) => {
            eprintln!("guard-es: cannot determine expected XPC peer EUID: {error}");
            return ExitCode::from(78);
        }
    };

    let loaded_config = match MacBackendConfig::load_authoritative() {
        Ok(config) => Some(config),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            None
        }
        Err(error) => {
            eprintln!("guard-es: authoritative configuration is invalid: {error}");
            None
        }
    };
    let (index, trust, enabled) = match prepare_config(loaded_config.as_ref()) {
        Ok(prepared) => prepared,
        Err(error) => {
            eprintln!("guard-es: policy configuration could not be prepared: {error}");
            match prepare_config(None) {
                Ok(empty) => empty,
                Err(_) => return ExitCode::FAILURE,
            }
        }
    };
    let resources = Arc::new(MacProtectedResources::new(enabled, index));
    let shared_trust = Arc::new(RwLock::new(trust));
    // MPS6 Guard self-protection: exact Guard component executable paths. The
    // running guard-es itself plus the deployed GUI and helper. guardctl is
    // deliberately excluded so CLI/debug workflows are not harmed.
    let mut guard_component_paths = Vec::new();
    if let Ok(current_exe) = std::env::current_exe() {
        guard_component_paths.push(current_exe);
    }
    for path in [
        "/Applications/Sensitive File Guard.app/Contents/MacOS/Guard",
        "/Applications/Sensitive File Guard.app/Contents/MacOS/guard-notify",
    ] {
        guard_component_paths.push(std::path::PathBuf::from(path));
    }
    let mut startup_error = None;
    let mut backend =
        match EndpointSecurityBackend::start(EndpointSecurityConfig::browser_with_guard_components(
            Arc::clone(&resources),
            Arc::clone(&shared_trust),
            guard_component_paths,
        )) {
            Ok(backend) => Some(backend),
            Err(error) => {
                eprintln!("guard-es: {error}; enforcement is not active");
                startup_error = Some(error);
                None
            }
        };
    let graph = backend
        .as_ref()
        .map(EndpointSecurityBackend::process_graph)
        .unwrap_or_else(|| Arc::new(Mutex::new(MacProcessGraph::default())));
    let shield = backend
        .as_ref()
        .map(EndpointSecurityBackend::process_shield)
        .unwrap_or_else(|| Arc::new(Mutex::new(MacProcessShield::new())));
    let resolver = Arc::new(MacProcessIdentityResolver::new_shared_with_shield(
        graph,
        shared_trust,
        shield,
    ));
    let audit = match open_audit_store() {
        Ok(audit) => Arc::new(audit),
        Err(error) if backend.is_none() => {
            eprintln!("guard-es: persistent audit unavailable in diagnostic-only mode: {error}");
            match guard_audit::AuditStore::open(Path::new(":memory:")) {
                Ok(audit) => Arc::new(audit),
                Err(fallback_error) => {
                    eprintln!("guard-es: diagnostic audit fallback failed: {fallback_error}");
                    return ExitCode::from(78);
                }
            }
        }
        Err(error) => {
            eprintln!("guard-es: audit store unavailable: {error}; enforcement is not active");
            return ExitCode::from(78);
        }
    };
    let policy = Arc::new(MacPolicy::new(Arc::clone(&resources), resolver, audit));
    if let Some(config) = loaded_config {
        if let Err(error) = policy.apply_config(config) {
            eprintln!("guard-es: policy configuration could not be loaded: {error}");
            let _ = resources.replace(false, Default::default());
        }
    }

    let initial_health = backend.as_ref().map_or_else(
        || {
            let (state, diagnostic) = match startup_error {
                Some(platform_macos::endpoint_security::ClientCreateError::NotPermitted) => (
                    "REQUIRES_FULL_DISK_ACCESS",
                    "Endpoint Security requires Full Disk Access in System Settings".to_owned(),
                ),
                Some(platform_macos::endpoint_security::ClientCreateError::NotEntitled)
                | Some(platform_macos::endpoint_security::ClientCreateError::NotPrivileged) => (
                    "REQUIRES_APPROVAL",
                    startup_error.expect("matched above").to_string(),
                ),
                Some(error) => ("NOT_ENFORCING", error.to_string()),
                None => (
                    "NOT_ENFORCING",
                    "Endpoint Security client is unavailable".to_owned(),
                ),
            };
            BackendHealth {
                backend: "endpoint-security".into(),
                state: state.into(),
                active: false,
                degraded: false,
                diagnostic: Some(diagnostic),
                sequence_gaps: 0,
                global_sequence_gaps: 0,
                pending_created: 0,
                pending_resolved_allow: 0,
                pending_resolved_deny: 0,
                pending_timed_out: 0,
                insufficient_deadline: 0,
                late_responses: 0,
                namespace_allowed: 0,
                namespace_denied: 0,
                namespace_alias_entries: 0,
                namespace_alias_capacity: 0,
                namespace_index_saturated: false,
                process_graph_degraded: false,
                task_control_allowed: 0,
                task_control_denied: 0,
                task_read_allowed: 0,
                task_read_denied: 0,
                task_read_supported: false,
                task_notify_supported: false,
                shield_admitted: 0,
                shield_compromised: 0,
                shield_launch_injection_denied: 0,
                shield_malformed_denied: 0,
                shield_task_notify_obtained: 0,
                shield_trace_observed: 0,
                shield_remote_thread_observed: 0,
                shield_cs_invalidated_observed: 0,
            }
        },
        EndpointSecurityBackend::health,
    );
    let backend_health = Arc::new(RwLock::new(initial_health));
    let server = match MacXpcServer::new(
        &requirements,
        [console_uid],
        ControlHandler {
            policy: Arc::clone(&policy),
            backend_health: Arc::clone(&backend_health),
            helper_heartbeats: Mutex::new(HashMap::new()),
        },
    ) {
        Ok(server) => server,
        Err(error) => {
            eprintln!("guard-es: could not start authenticated XPC service: {error}");
            return ExitCode::FAILURE;
        }
    };

    if backend.is_none() {
        eprintln!(
            "guard-es: authenticated XPC active for uid={console_uid}; Endpoint Security is not active"
        );
        server.run();
        return ExitCode::SUCCESS;
    }

    server.activate();
    eprintln!(
        "guard-es: Endpoint Security policy runtime and authenticated XPC active for uid={console_uid}"
    );
    let backend = backend.take().expect("checked above");
    loop {
        match backend.recv_timeout(Duration::from_millis(250)) {
            Ok(event) => policy.handle(event),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                *backend_health
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = backend.health();
                eprintln!("guard-es: authorization queue disconnected; failing closed");
                return ExitCode::FAILURE;
            }
        }
        policy.maintenance();
        // Drain ALL metadata-only Process Shield audit handoffs without
        // blocking the AUTH_OPEN authorization loop. A burst of exec/task
        // events (browser launch) must not leave shield handoffs queued past
        // the next maintenance window.
        loop {
            match backend.recv_shield_timeout(Duration::ZERO) {
                Ok(shield_event) => policy.handle_shield(shield_event),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    eprintln!("guard-es: Process Shield audit handoff queue disconnected");
                    break;
                }
            }
        }
        if let Err(error) = backend.repair_if_needed() {
            eprintln!("guard-es: bounded namespace repair failed: {error}");
        }
        *backend_health
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = backend.health();
    }
}

/// Build the truthful Process Shield status section (MPS8). Distinguishes
/// Active / Reduced / Unavailable with exact reasons; never a fake global flag.
fn process_shield_info(
    health: &BackendHealth,
    config: Option<MacBackendConfig>,
) -> guard_ipc::ProcessShieldInfo {
    use guard_ipc::ProcessShieldInfo;
    use platform_macos::code_signature::RuntimePosture;

    let backend_live = health.active && !health.state.is_empty();
    let task_read_active = health.task_read_supported;
    let notify_active = health.task_notify_supported;
    let reduced = !task_read_active || !notify_active || health.process_graph_degraded;
    let (state, reason) = if !backend_live {
        (
            "Unavailable".into(),
            Some("Endpoint Security client is not active; Process Shield is not enforcing".into()),
        )
    } else if reduced {
        let mut reasons = Vec::new();
        if !task_read_active {
            reasons.push("AUTH_GET_TASK_READ is unavailable on this host");
        }
        if !notify_active {
            reasons.push("Process Shield notify subscriptions are unavailable");
        }
        if health.process_graph_degraded {
            reasons.push("process graph is degraded");
        }
        ("Reduced".into(), Some(reasons.join("; ")))
    } else {
        ("Active".into(), None)
    };

    let (mut strong, mut reduced, mut unverifiable) = (0usize, 0usize, 0usize);
    if let Some(config) = config {
        for report in config.runtime_posture_report() {
            match report.posture {
                RuntimePosture::Strong => strong += 1,
                RuntimePosture::Reduced => reduced += 1,
                RuntimePosture::Unverifiable => unverifiable += 1,
            }
        }
    }
    let runtime_posture = if strong + reduced + unverifiable == 0 {
        "not-applicable".to_owned()
    } else if reduced > 0 {
        "reduced".to_owned()
    } else if unverifiable > 0 {
        "unverifiable".to_owned()
    } else {
        "strong".to_owned()
    };

    ProcessShieldInfo {
        state,
        reason,
        task_control_protection: if backend_live {
            "active".into()
        } else {
            "unavailable".into()
        },
        task_read_protection: if backend_live && task_read_active {
            "active".into()
        } else {
            "unavailable".into()
        },
        task_read_supported: health.task_read_supported,
        task_notify_supported: health.task_notify_supported,
        launch_integrity: if backend_live {
            "active".into()
        } else {
            "unavailable".into()
        },
        runtime_posture,
        runtime_posture_strong: strong,
        runtime_posture_reduced: reduced,
        runtime_posture_unverifiable: unverifiable,
        injection_telemetry: if notify_active {
            "active".into()
        } else {
            "unavailable".into()
        },
        task_control_allowed: health.task_control_allowed,
        task_control_denied: health.task_control_denied,
        task_read_allowed: health.task_read_allowed,
        task_read_denied: health.task_read_denied,
        shield_admitted: health.shield_admitted,
        shield_compromised: health.shield_compromised,
        launch_injection_denied: health.shield_launch_injection_denied,
        trace_observed: health.shield_trace_observed,
        remote_thread_observed: health.shield_remote_thread_observed,
        cs_invalidated_observed: health.shield_cs_invalidated_observed,
        library_mapping_protection: "disabled".into(),
    }
}

fn open_audit_store() -> anyhow::Result<guard_audit::AuditStore> {
    let path = Path::new(AUDIT_PATH);
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("macOS audit path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    guard_audit::AuditStore::open(path)
}

fn diagnostic_exit() -> ExitCode {
    match platform_macos::endpoint_security::diagnose_client_creation() {
        Ok(()) => eprintln!("guard-es: Endpoint Security client creation succeeded"),
        Err(error) => eprintln!("guard-es: {error}; enforcement is not active"),
    }
    ExitCode::from(78)
}
