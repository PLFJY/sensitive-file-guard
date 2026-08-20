//! Linux service-control adapter.

use std::process::Command;

pub struct LinuxServiceController;

fn systemd_args(operation: guard_platform::ServiceOperation, unit: &str) -> Vec<String> {
    let verb = match operation {
        guard_platform::ServiceOperation::Start => "enable",
        guard_platform::ServiceOperation::Stop => "disable",
        guard_platform::ServiceOperation::Restart => "restart",
    };
    let mut args = vec![verb.to_owned()];
    if matches!(
        operation,
        guard_platform::ServiceOperation::Start | guard_platform::ServiceOperation::Stop
    ) {
        args.push("--now".to_owned());
    }
    args.push(unit.to_owned());
    args
}

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
        let args = systemd_args(operation, "guardd.service");
        let verb = &args[0];
        let status = Command::new("systemctl").args(&args).status()?;
        anyhow::ensure!(status.success(), "systemctl {verb} guardd.service failed");
        Ok(())
    }
}

impl LinuxServiceController {
    pub fn apply_notifications(operation: guard_platform::ServiceOperation) -> anyhow::Result<()> {
        let args = systemd_args(operation, "guard-notify.service");
        let verb = &args[0];
        let status = Command::new("systemctl")
            .args(["--user"])
            .args(&args)
            .status()?;
        anyhow::ensure!(
            status.success(),
            "systemctl --user {verb} guard-notify.service failed"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::systemd_args;

    #[test]
    fn protection_start_and_stop_are_persistent_user_choices() {
        assert_eq!(
            systemd_args(guard_platform::ServiceOperation::Start, "guardd.service"),
            ["enable", "--now", "guardd.service"]
        );
        assert_eq!(
            systemd_args(guard_platform::ServiceOperation::Stop, "guardd.service"),
            ["disable", "--now", "guardd.service"]
        );
        assert_eq!(
            systemd_args(
                guard_platform::ServiceOperation::Restart,
                "guard-notify.service"
            ),
            ["restart", "guard-notify.service"]
        );
    }
}
