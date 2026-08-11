use std::process::ExitCode;

fn main() -> ExitCode {
    guard_core::logging::init_logging();

    #[cfg(not(target_os = "macos"))]
    {
        eprintln!("guard-es: Endpoint Security system extensions are supported only on macOS");
        ExitCode::from(78)
    }

    #[cfg(target_os = "macos")]
    {
        eprintln!("guard-es: starting Endpoint Security system-extension skeleton");
        match platform_macos::system_extension::endpoint_security_entitlement_present() {
            Ok(true) => {
                eprintln!(
                    "guard-es: embedded entitlement claim is present; provisioning and Endpoint Security acceptance are not proven; Phase 02 intentionally subscribes to no events"
                );
                ExitCode::SUCCESS
            }
            Ok(false) => {
                eprintln!("guard-es: missing com.apple.developer.endpoint-security.client entitlement; enforcement is not active");
                ExitCode::from(78)
            }
            Err(error) => {
                eprintln!(
                    "guard-es: entitlement diagnostic failed: {error}; enforcement is not active"
                );
                ExitCode::FAILURE
            }
        }
    }
}
