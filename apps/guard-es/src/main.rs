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
        eprintln!("guard-es: checking Endpoint Security client availability");
        match platform_macos::endpoint_security::diagnose_client_creation() {
            Ok(()) => {
                eprintln!(
                    "guard-es: Endpoint Security client creation succeeded, but no protected synthetic fixture is compiled in; AUTH_OPEN is not subscribed and enforcement is not active"
                );
                ExitCode::from(78)
            }
            Err(error) => {
                eprintln!("guard-es: {error}; enforcement is not active");
                ExitCode::from(78)
            }
        }
    }

    #[cfg(all(target_os = "macos", feature = "es-poc"))]
    run_poc()
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
