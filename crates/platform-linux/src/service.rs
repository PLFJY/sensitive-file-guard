//! Linux service-control adapter.

use std::process::Command;

pub struct LinuxServiceController;

impl LinuxServiceController {
    fn unit_active(unit: &str, user: bool) -> anyhow::Result<bool> {
        let mut command = Command::new("systemctl");
        if user {
            command.arg("--user");
        }
        let status = command.args(["is-active", "--quiet", unit]).status()?;
        Ok(status.success())
    }
}

impl guard_platform::ServiceController for LinuxServiceController {
    fn status(&self) -> anyhow::Result<guard_platform::ServiceStatus> {
        Ok(guard_platform::ServiceStatus {
            protection_active: Self::unit_active("guardd.service", false)?,
            notification_active: Some(Self::unit_active("guard-notify.service", true)?),
            diagnostic: Some("systemd service state".into()),
        })
    }

    fn apply(&self, operation: guard_platform::ServiceOperation) -> anyhow::Result<()> {
        let verb = match operation {
            guard_platform::ServiceOperation::Start => "start",
            guard_platform::ServiceOperation::Stop => "stop",
            guard_platform::ServiceOperation::Restart => "restart",
        };
        let status = Command::new("systemctl")
            .args([verb, "guardd.service"])
            .status()?;
        anyhow::ensure!(status.success(), "systemctl {verb} guardd.service failed");
        Ok(())
    }
}

impl LinuxServiceController {
    pub fn apply_notifications(operation: guard_platform::ServiceOperation) -> anyhow::Result<()> {
        let verb = match operation {
            guard_platform::ServiceOperation::Start => "start",
            guard_platform::ServiceOperation::Stop => "stop",
            guard_platform::ServiceOperation::Restart => "restart",
        };
        let status = Command::new("systemctl")
            .args(["--user", verb, "guard-notify.service"])
            .status()?;
        anyhow::ensure!(
            status.success(),
            "systemctl --user {verb} guard-notify.service failed"
        );
        Ok(())
    }
}
