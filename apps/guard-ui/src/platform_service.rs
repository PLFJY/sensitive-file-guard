//! Target-specific application/service composition for the otherwise shared
//! GTK client. Linux privilege and systemd vocabulary stays in this module.

use guard_platform::{ServiceOperation, ServiceStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LinuxEnforcementMode {
    Conservative,
    StrictFilesystem,
}

impl LinuxEnforcementMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Conservative => "conservative",
            Self::StrictFilesystem => "strict-filesystem",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct LinuxConfiguration {
    pub enforcement_mode: LinuxEnforcementMode,
    pub browsers: Vec<guard_platform::config::BrowserEnrollmentConfig>,
    pub enrolled_exes: Vec<std::path::PathBuf>,
    pub ssh_keys: Vec<std::path::PathBuf>,
}

#[cfg(target_os = "macos")]
pub fn handle_system_extension_command() -> Option<i32> {
    use platform_macos::system_extension::LifecycleState;

    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments
        .iter()
        .any(|argument| argument == "--discover-macos-browsers")
    {
        return Some(discover_macos_browsers(&arguments));
    }
    let action = std::env::args().find(|argument| {
        matches!(
            argument.as_str(),
            "--activate-system-extension"
                | "--deactivate-system-extension"
                | "--system-extension-status"
        )
    });
    let action = action?;
    let identifier = option_env!("GUARD_SYSTEM_EXTENSION_BUNDLE_ID")
        .unwrap_or(platform_macos::DEFAULT_EXTENSION_BUNDLE_ID);
    let controller =
        match platform_macos::system_extension::SystemExtensionController::new(identifier) {
            Ok(controller) => controller,
            Err(error) => {
                eprintln!("guard-ui: {error}");
                return Some(1);
            }
        };
    let submitted = match action.as_str() {
        "--activate-system-extension" => controller.activate(),
        "--deactivate-system-extension" => controller.deactivate(),
        "--system-extension-status" => controller.refresh(),
        _ => unreachable!(),
    };
    if let Err(error) = submitted {
        eprintln!("guard-ui: {error}");
        return Some(1);
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        match controller.status() {
            Ok(status) if status.state != LifecycleState::Submitted => {
                println!(
                    "system-extension state={:?} diagnostic={}",
                    status.state, status.diagnostic
                );
                return Some(i32::from(status.state == LifecycleState::Failed));
            }
            Ok(_) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Ok(status) => {
                println!(
                    "system-extension state={:?} diagnostic=request still pending after 30 seconds",
                    status.state
                );
                return Some(1);
            }
            Err(error) => {
                eprintln!("guard-ui: status query failed: {error}");
                return Some(1);
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn discover_macos_browsers(arguments: &[String]) -> i32 {
    use std::sync::Arc;

    let option = |name: &str| {
        arguments
            .iter()
            .position(|argument| argument == name)
            .and_then(|index| arguments.get(index + 1))
            .map(std::path::PathBuf::from)
    };
    let home = match option("--home").or_else(|| std::env::var_os("HOME").map(Into::into)) {
        Some(home) => home,
        None => {
            eprintln!("guard-ui: --discover-macos-browsers requires --home or HOME");
            return 2;
        }
    };
    let applications =
        option("--applications-root").unwrap_or_else(|| std::path::PathBuf::from("/Applications"));
    let discovery = platform_macos::discovery::MacBrowserDiscovery::new(
        vec![applications],
        Arc::new(platform_macos::code_signature::NativeCodeSignatureInspector),
    )
    .discover_verified(&home);
    let output = serde_json::json!({
        "browsers": discovery.review,
        "unsupported_or_custom_needed": discovery.portable.unsupported_sandboxed,
    });
    match serde_json::to_string_pretty(&output) {
        Ok(output) => {
            println!("{output}");
            0
        }
        Err(error) => {
            eprintln!("guard-ui: could not encode browser discovery result: {error}");
            1
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub fn handle_system_extension_command() -> Option<i32> {
    let requested = std::env::args().any(|argument| {
        matches!(
            argument.as_str(),
            "--activate-system-extension"
                | "--deactivate-system-extension"
                | "--system-extension-status"
                | "--discover-macos-browsers"
        )
    });
    if requested {
        eprintln!("guard-ui: SystemExtensions lifecycle commands are available only on macOS");
        Some(1)
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn verb(operation: ServiceOperation) -> &'static str {
    match operation {
        ServiceOperation::Start => "start",
        ServiceOperation::Stop => "stop",
        ServiceOperation::Restart => "restart",
    }
}

#[cfg(target_os = "linux")]
pub fn status() -> anyhow::Result<ServiceStatus> {
    let output = std::process::Command::new("guardctl")
        .arg("service-status")
        .output()?;
    anyhow::ensure!(output.status.success(), "guardctl service status failed");
    Ok(serde_json::from_slice(&output.stdout)?)
}

#[cfg(not(target_os = "linux"))]
pub fn status() -> anyhow::Result<ServiceStatus> {
    anyhow::bail!("service status is not implemented for this target")
}

#[cfg(target_os = "linux")]
pub fn apply(operation: ServiceOperation) -> anyhow::Result<()> {
    let status = std::process::Command::new("pkexec")
        .args(["guardctl", "privileged", "service", verb(operation)])
        .status()?;
    anyhow::ensure!(status.success(), "protection service operation failed");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn apply(_operation: ServiceOperation) -> anyhow::Result<()> {
    anyhow::bail!("service control is not implemented for this target")
}

#[cfg(target_os = "linux")]
pub fn apply_notifications(operation: ServiceOperation) -> anyhow::Result<()> {
    let status = std::process::Command::new("guardctl")
        .args(["notification-service", verb(operation)])
        .status()?;
    anyhow::ensure!(status.success(), "notification service operation failed");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn apply_notifications(_operation: ServiceOperation) -> anyhow::Result<()> {
    anyhow::bail!("notification service control is not implemented for this target")
}

#[cfg(target_os = "linux")]
pub fn apply_config(bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = std::process::Command::new("pkexec")
        .args(["guardctl", "privileged", "apply-config"])
        .stdin(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("privileged helper stdin unavailable"))?
        .write_all(bytes)?;
    anyhow::ensure!(child.wait()?.success(), "configuration apply failed");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn apply_config(_bytes: &[u8]) -> anyhow::Result<()> {
    anyhow::bail!("configuration apply is not implemented for this target")
}
