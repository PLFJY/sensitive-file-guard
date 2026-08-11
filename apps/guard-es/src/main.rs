use std::process::ExitCode;

fn main() -> ExitCode {
    guard_core::logging::init_logging();

    #[cfg(not(target_os = "macos"))]
    {
        eprintln!("guard-es: Endpoint Security system extensions are supported only on macOS");
        ExitCode::from(78)
    }

    #[cfg(all(target_os = "macos", not(feature = "es-poc")))]
    {
        run_extension_service()
    }

    #[cfg(all(target_os = "macos", feature = "es-poc"))]
    run_poc()
}

#[cfg(all(target_os = "macos", not(feature = "es-poc")))]
fn run_extension_service() -> ExitCode {
    use guard_ipc::{Request, Response, ResponseBody, StatusInfo};
    use platform_macos::xpc::{
        AuthenticatedPeer, MacXpcServer, SigningRequirements, XpcRequestHandler,
    };

    struct ControlHandler {
        diagnostic: Option<String>,
    }

    impl XpcRequestHandler for ControlHandler {
        fn handle(&self, peer: AuthenticatedPeer, request: Request) -> Response {
            match request.op {
                guard_ipc::RequestOp::Status => self.status(peer),
                guard_ipc::RequestOp::ConfigurationGet => {
                    match platform_macos::config::MacBackendConfig::load_authoritative() {
                        Ok(config) => Response::ok(ResponseBody::Configuration(
                            config.to_ipc_metadata_for_uid(peer.euid),
                        )),
                        Err(error) => Response::err(format!("configuration_unavailable: {error}")),
                    }
                }
                guard_ipc::RequestOp::ConfigurationApply { config } => {
                    let config = match serde_json::from_value::<
                        platform_macos::config::MacBackendConfig,
                    >(config)
                    {
                        Ok(config) => config,
                        Err(error) => {
                            return Response::err(format!("invalid_configuration: {error}"));
                        }
                    };
                    if let Err(error) = config.validate_for_peer(peer.euid) {
                        return Response::err(format!("configuration_scope_denied: {error}"));
                    }
                    match config.write_authoritative() {
                        Ok(()) => Response::ok(ResponseBody::ConfigurationApplied {
                            version: config.version,
                        }),
                        Err(error) => Response::err(format!("configuration_apply_failed: {error}")),
                    }
                }
                _ => Response::err("operation_not_available_before_policy_start"),
            }
        }
    }

    impl ControlHandler {
        fn status(&self, peer: AuthenticatedPeer) -> Response {
            Response::ok(ResponseBody::Status(StatusInfo {
                version: env!("CARGO_PKG_VERSION").into(),
                backend_kind: "macos-endpoint-security".into(),
                backend_diagnostic: self.diagnostic.clone(),
                enforcement_active: false,
                status: "NOT_ENFORCING".into(),
                mode: None,
                marked_filesystems: None,
                required_filesystems: None,
                filesystem_marks_healthy: None,
                strict_events_total: None,
                strict_fast_allowed: None,
                protected_events: 0,
                fanotify_overflows: None,
                classifier_failures: None,
                strict_alias_scans: None,
                strict_alias_matches: None,
                topology_degraded: None,
                protected_files: 0,
                ssh_protected_keys: 0,
                protected_trees: 0,
                browsers: 0,
                browser_exes: 0,
                allowed: 0,
                denied: 0,
                unclassified: 0,
                audit_dropped: 0,
                peer_uid: peer.euid,
            }))
        }
    }

    let requirements = match SigningRequirements::current_process() {
        Ok(requirements) => requirements,
        Err(error) => {
            eprintln!("guard-es: authenticated XPC unavailable: {error}");
            return endpoint_security_diagnostic_exit();
        }
    };
    let console_uid = match platform_macos::xpc::console_user_uid() {
        Ok(uid) => uid,
        Err(error) => {
            eprintln!("guard-es: cannot determine expected XPC peer EUID: {error}");
            return ExitCode::from(78);
        }
    };
    let diagnostic = platform_macos::endpoint_security::diagnose_client_creation()
        .err()
        .map(|error| error.to_string())
        .or_else(|| {
            Some(
                "Endpoint Security client is available; policy subscriptions are not started until Phase 07"
                    .into(),
            )
        });
    let server =
        match MacXpcServer::new(&requirements, [console_uid], ControlHandler { diagnostic }) {
            Ok(server) => server,
            Err(error) => {
                eprintln!("guard-es: could not start authenticated XPC service: {error}");
                return ExitCode::FAILURE;
            }
        };
    eprintln!(
        "guard-es: authenticated XPC service active for console uid={console_uid}; enforcement is not active"
    );
    server.run();
    ExitCode::SUCCESS
}

#[cfg(all(target_os = "macos", not(feature = "es-poc")))]
fn endpoint_security_diagnostic_exit() -> ExitCode {
    eprintln!("guard-es: checking Endpoint Security client availability");
    match platform_macos::endpoint_security::diagnose_client_creation() {
        Ok(()) => eprintln!(
            "guard-es: Endpoint Security client creation succeeded, but enforcement is not active"
        ),
        Err(error) => eprintln!("guard-es: {error}; enforcement is not active"),
    }
    ExitCode::from(78)
}

#[cfg(all(target_os = "macos", feature = "es-poc"))]
fn run_poc() -> ExitCode {
    use platform_macos::endpoint_security::{EndpointSecurityBackend, EndpointSecurityConfig};
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;
    use std::time::Duration;

    let Some(protected_file) = option_env!("GUARD_ES_POC_FILE") else {
        eprintln!("guard-es: es-poc requires GUARD_ES_POC_FILE at compile time");
        return ExitCode::from(78);
    };
    let Some(allowed_executable) = option_env!("GUARD_ES_POC_ALLOW_EXE") else {
        eprintln!("guard-es: es-poc requires GUARD_ES_POC_ALLOW_EXE at compile time");
        return ExitCode::from(78);
    };
    let allowed_executable = match std::fs::canonicalize(allowed_executable) {
        Ok(path) => path,
        Err(error) => {
            eprintln!("guard-es: cannot canonicalize synthetic allow executable: {error}");
            return ExitCode::from(78);
        }
    };
    let allowed_metadata = match std::fs::metadata(&allowed_executable) {
        Ok(metadata) => metadata,
        Err(error) => {
            eprintln!("guard-es: cannot stat synthetic allow executable: {error}");
            return ExitCode::from(78);
        }
    };
    let config =
        match EndpointSecurityConfig::synthetic_exact_paths([PathBuf::from(protected_file)]) {
            Ok(config) => config,
            Err(error) => {
                eprintln!("guard-es: invalid synthetic fixture configuration: {error}");
                return ExitCode::from(78);
            }
        };
    let backend = match EndpointSecurityBackend::start(config) {
        Ok(backend) => backend,
        Err(error) => {
            eprintln!("guard-es: {error}; enforcement is not active");
            return ExitCode::from(78);
        }
    };
    eprintln!("guard-es: development AUTH_OPEN PoC active for one synthetic fixture; cache=false");
    loop {
        match backend.recv_timeout(Duration::from_secs(1)) {
            Ok(event)
                if event.facts.process.executable.path == allowed_executable
                    && event.facts.process.executable.dev == allowed_metadata.dev()
                    && event.facts.process.executable.ino == allowed_metadata.ino() =>
            {
                if let Err(error) = event.permission.allow() {
                    eprintln!("guard-es: synthetic allow response failed: {error}");
                }
            }
            Ok(event) => {
                if let Err(error) = event.permission.deny() {
                    eprintln!("guard-es: synthetic deny response failed: {error}");
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                let health = backend.health();
                if !health.active {
                    eprintln!(
                        "guard-es: backend degraded: {}",
                        health.diagnostic.as_deref().unwrap_or("unknown error")
                    );
                    return ExitCode::FAILURE;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                eprintln!("guard-es: authorization queue disconnected; enforcement is not active");
                return ExitCode::FAILURE;
            }
        }
    }
}
