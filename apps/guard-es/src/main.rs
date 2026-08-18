use std::process::ExitCode;

#[cfg(all(target_os = "macos", any(not(feature = "es-poc"), test)))]
mod policy;
#[cfg(all(target_os = "macos", not(feature = "es-poc")))]
mod service;

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
    service::run()
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
    let config = match EndpointSecurityConfig::synthetic_with_shield(
        [PathBuf::from(protected_file)],
        [allowed_executable.clone()],
    ) {
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
    let shield = backend.process_shield();
    // Optional controlled compromise fixture (test-only): when a PID is
    // written to this file, the exact live instance is transitioned via the
    // same strong-signal path used by real notify-only compromise events.
    let compromise_file = option_env!("GUARD_ES_POC_COMPROMISE_FILE").map(PathBuf::from);
    // P0 review round 4: test-only evidence channel. Every Process Shield
    // task denial observed by the synthetic extension is appended to this
    // file (exact target pid + kind) so the acceptance harness can assert
    // that GUARD denied the probe - not just that the kernel refused the
    // task port for its own reasons. Metadata only.
    let task_deny_file = option_env!("GUARD_ES_POC_TASK_DENY_FILE").map(PathBuf::from);
    eprintln!("guard-es: development AUTH_OPEN+Process Shield PoC active for one synthetic fixture; cache=false");
    loop {
        // Drain metadata-only Process Shield audit handoffs.
        match backend.recv_shield_timeout(Duration::from_millis(50)) {
            Ok(event) => {
                eprintln!("guard-es: shield event: {event:?}");
                if let Some(file) = &task_deny_file {
                    if let platform_macos::endpoint_security::ShieldAuditEvent::TaskDenied {
                        kind,
                        target,
                        ..
                    } = &event
                    {
                        let _ = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(file)
                            .and_then(|mut handle| {
                                use std::io::Write;
                                writeln!(handle, "pid={} kind={}", target.key.pid, kind.label())
                            });
                    }
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                eprintln!("guard-es: Process Shield audit handoff queue disconnected");
                return ExitCode::FAILURE;
            }
        }
        if let Some(file) = &compromise_file {
            if let Ok(pid_text) = std::fs::read_to_string(file) {
                if let Ok(pid) = pid_text.trim().parse::<u32>() {
                    let mut shield = shield
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if let Some(facts) = shield.current(pid).cloned() {
                        let outcome = shield.apply_strong_signal(&facts);
                        drop(shield);
                        if outcome
                            == platform_macos::process_shield::StrongSignalOutcome::CompromisedNow
                        {
                            eprintln!(
                                "guard-es: synthetic compromise fixture applied to pid={pid}"
                            );
                        }
                    }
                    let _ = std::fs::remove_file(file);
                }
            }
        }
        match backend.recv_timeout(Duration::from_secs(1)) {
            Ok(event) => {
                let compromised = shield
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .integrity_of_pid(event.facts.process.key.pid)
                    != guard_core::ProcessIntegrity::Normal;
                if !compromised
                    && event.facts.process.executable.path == allowed_executable
                    && event.facts.process.executable.dev == allowed_metadata.dev()
                    && event.facts.process.executable.ino == allowed_metadata.ino()
                {
                    if let Err(error) = event.permission.allow() {
                        eprintln!("guard-es: synthetic allow response failed: {error}");
                    }
                } else {
                    if let Err(error) = event.permission.deny() {
                        eprintln!("guard-es: synthetic deny response failed: {error}");
                    }
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
