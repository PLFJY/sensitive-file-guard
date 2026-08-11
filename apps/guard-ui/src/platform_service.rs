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
