//! Target-specific application/service composition for the otherwise shared
//! GTK client. Linux privilege and systemd vocabulary stays in this module.

use guard_platform::{ServiceOperation, ServiceStatus};

use crate::pending_dialog::PromptKind;

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
    if arguments.iter().any(|argument| argument == "--xpc-status") {
        return Some(xpc_status());
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
fn xpc_status() -> i32 {
    match guard_client::macos::MacGuardClient::for_current_process()
        .and_then(|client| client.status())
    {
        Ok(status) => match serde_json::to_string_pretty(&status) {
            Ok(status) => {
                println!("{status}");
                0
            }
            Err(error) => {
                eprintln!("guard-ui: could not encode XPC status: {error}");
                1
            }
        },
        Err(error) => {
            eprintln!("guard-ui: authenticated XPC status failed: {error:#}");
            1
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
                | "--xpc-status"
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

#[cfg(target_os = "macos")]
pub fn apply_config(bytes: &[u8]) -> anyhow::Result<()> {
    let config: platform_macos::config::MacBackendConfig = serde_json::from_slice(bytes)?;
    config.validate()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    guard_client::macos::MacGuardClient::for_current_process()?
        .apply_configuration(&config, deadline)
        .map(|_| ())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn apply_config(_bytes: &[u8]) -> anyhow::Result<()> {
    anyhow::bail!("configuration apply is not implemented for this target")
}

#[cfg(target_os = "linux")]
pub fn resolve_pending(
    kind: PromptKind,
    id: &str,
    allow: bool,
    _expires_at: u64,
) -> anyhow::Result<()> {
    let socket = std::path::Path::new("/run/guardd/guardd.sock");
    match (kind, allow) {
        (PromptKind::Migration, true) => guard_client::resolve_migration(
            socket,
            id,
            guard_ipc::MigrationResolutionAction::AllowImport,
        )
        .map(|_| ()),
        (PromptKind::Migration, false) => {
            guard_client::resolve_migration(socket, id, guard_ipc::MigrationResolutionAction::Block)
                .map(|_| ())
        }
        (PromptKind::SshRead, true) => {
            guard_client::resolve_ssh_read(socket, id, guard_ipc::SshReadResolutionAction::Allow)
                .map(|_| ())
        }
        (PromptKind::SshRead, false) => {
            guard_client::resolve_ssh_read(socket, id, guard_ipc::SshReadResolutionAction::Block)
                .map(|_| ())
        }
    }
}

#[cfg(target_os = "macos")]
pub fn resolve_pending(
    kind: PromptKind,
    id: &str,
    allow: bool,
    expires_at: u64,
) -> anyhow::Result<()> {
    let client = guard_client::macos::MacGuardClient::for_current_process()?;
    if allow {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        anyhow::ensure!(expires_at > now, "pending request already timed out");
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_secs(expires_at.saturating_sub(now));
        match kind {
            PromptKind::Migration => client.allow_migration(id, deadline).map(|_| ()),
            PromptKind::SshRead => client.allow_ssh_read(id, deadline).map(|_| ()),
        }
    } else {
        match kind {
            PromptKind::Migration => client.block_migration(id).map(|_| ()),
            PromptKind::SshRead => client.block_ssh_read(id).map(|_| ()),
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn resolve_pending(
    _kind: PromptKind,
    _id: &str,
    _allow: bool,
    _expires_at: u64,
) -> anyhow::Result<()> {
    anyhow::bail!("pending authorization is unavailable for this target")
}

#[cfg(target_os = "linux")]
pub fn daemon_status() -> anyhow::Result<guard_ipc::StatusInfo> {
    guard_client::status(std::path::Path::new("/run/guardd/guardd.sock"))
}

#[cfg(target_os = "macos")]
pub fn daemon_status() -> anyhow::Result<guard_ipc::StatusInfo> {
    guard_client::macos::MacGuardClient::for_current_process()?.status()
}

#[cfg(target_os = "linux")]
pub fn configuration() -> anyhow::Result<guard_ipc::ConfigurationInfo> {
    guard_client::configuration(std::path::Path::new("/run/guardd/guardd.sock"))
}

#[cfg(target_os = "macos")]
pub fn configuration() -> anyhow::Result<guard_ipc::ConfigurationInfo> {
    guard_client::macos::MacGuardClient::for_current_process()?.configuration()
}

#[cfg(target_os = "linux")]
pub fn resources() -> anyhow::Result<Vec<guard_ipc::ResourceInfo>> {
    guard_client::resources(std::path::Path::new("/run/guardd/guardd.sock"))
}

#[cfg(target_os = "macos")]
pub fn resources() -> anyhow::Result<Vec<guard_ipc::ResourceInfo>> {
    guard_client::macos::MacGuardClient::for_current_process()?.resources()
}

#[cfg(target_os = "linux")]
pub fn events_cursor(
    limit: Option<u32>,
    before_id: Option<i64>,
    after_id: Option<i64>,
) -> anyhow::Result<Vec<guard_ipc::EventInfo>> {
    guard_client::events_cursor(
        std::path::Path::new("/run/guardd/guardd.sock"),
        limit,
        before_id,
        after_id,
    )
}

#[cfg(target_os = "macos")]
pub fn events_cursor(
    limit: Option<u32>,
    before_id: Option<i64>,
    after_id: Option<i64>,
) -> anyhow::Result<Vec<guard_ipc::EventInfo>> {
    guard_client::macos::MacGuardClient::for_current_process()?
        .events_cursor(limit, before_id, after_id)
}

#[cfg(target_os = "linux")]
pub fn ssh_pending() -> anyhow::Result<Vec<guard_ipc::SshPendingInfo>> {
    guard_client::ssh_pending(std::path::Path::new("/run/guardd/guardd.sock"))
}

#[cfg(target_os = "macos")]
pub fn ssh_pending() -> anyhow::Result<Vec<guard_ipc::SshPendingInfo>> {
    guard_client::macos::MacGuardClient::for_current_process()?.ssh_pending()
}

#[cfg(target_os = "linux")]
pub fn migration_pending() -> anyhow::Result<Vec<guard_ipc::MigrationPendingInfo>> {
    guard_client::migration_pending(std::path::Path::new("/run/guardd/guardd.sock"))
}

#[cfg(target_os = "macos")]
pub fn migration_pending() -> anyhow::Result<Vec<guard_ipc::MigrationPendingInfo>> {
    guard_client::macos::MacGuardClient::for_current_process()?.migration_pending()
}
