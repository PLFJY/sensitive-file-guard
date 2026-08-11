//! Synchronous typed client for guardd's local versioned JSON IPC.

use std::path::Path;

use anyhow::Context;
use guard_ipc::{Request, RequestOp, Response, ResponseBody, MAX_REQUEST_BYTES, PROTOCOL_VERSION};

/// Client-side local transport.  It only connects and exchanges framed
/// payloads; server-side peer authentication remains in the selected
/// platform adapter.
pub mod transport {
    use std::io::{self, Read, Write};
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::time::Duration;

    pub struct IpcClient;

    impl IpcClient {
        pub fn request(path: &Path, payload: &[u8]) -> io::Result<Vec<u8>> {
            let mut stream = UnixStream::connect(path)?;
            stream.set_write_timeout(Some(Duration::from_secs(2)))?;
            stream.set_read_timeout(Some(Duration::from_secs(2)))?;
            write_frame(&mut stream, payload)?;
            read_frame(&mut stream, 16 * 1024 * 1024)
        }
    }

    pub fn read_frame(stream: &mut UnixStream, max_bytes: usize) -> io::Result<Vec<u8>> {
        let mut prefix = [0u8; 4];
        stream.read_exact(&mut prefix)?;
        let length = u32::from_be_bytes(prefix) as usize;
        if length > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("IPC frame too large: {length} > {max_bytes}"),
            ));
        }
        let mut payload = vec![0u8; length];
        stream.read_exact(&mut payload)?;
        Ok(payload)
    }

    pub fn write_frame(stream: &mut UnixStream, payload: &[u8]) -> io::Result<()> {
        let length = u32::try_from(payload.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "IPC payload exceeds u32 length",
            )
        })?;
        stream.write_all(&length.to_be_bytes())?;
        stream.write_all(payload)?;
        stream.flush()
    }
}

use transport::IpcClient;

/// Application-facing service facade. The selected platform CLI owns the
/// privileged service mechanism; GTK and other clients use these semantic
/// operations rather than naming a service manager.
pub mod service {
    use std::process::Command;

    use guard_platform::{ServiceOperation, ServiceStatus};

    pub fn status() -> anyhow::Result<ServiceStatus> {
        let output = Command::new("guardctl").arg("service-status").output()?;
        anyhow::ensure!(output.status.success(), "guardctl service status failed");
        Ok(serde_json::from_slice(&output.stdout)?)
    }

    pub fn apply(operation: ServiceOperation) -> anyhow::Result<()> {
        let verb = match operation {
            ServiceOperation::Start => "start",
            ServiceOperation::Stop => "stop",
            ServiceOperation::Restart => "restart",
        };
        let status = Command::new("pkexec")
            .args(["guardctl", "privileged", "service", verb])
            .status()?;
        anyhow::ensure!(status.success(), "protection service operation failed");
        Ok(())
    }

    pub fn apply_notifications(operation: ServiceOperation) -> anyhow::Result<()> {
        let verb = match operation {
            ServiceOperation::Start => "start",
            ServiceOperation::Stop => "stop",
            ServiceOperation::Restart => "restart",
        };
        let status = Command::new("guardctl")
            .args(["notification-service", verb])
            .status()?;
        anyhow::ensure!(status.success(), "notification service operation failed");
        Ok(())
    }
}

fn exchange<T>(
    socket: &Path,
    op: RequestOp,
    take: fn(ResponseBody) -> Option<T>,
) -> anyhow::Result<T> {
    let bytes = serde_json::to_vec(&Request {
        version: PROTOCOL_VERSION,
        op,
    })?;
    anyhow::ensure!(
        bytes.len() <= MAX_REQUEST_BYTES,
        "request exceeds MAX_REQUEST_BYTES"
    );
    let response = IpcClient::request(socket, &bytes)
        .map_err(|e| anyhow::anyhow!("IPC request to {}: {e}", socket.display()))?;
    let response: Response =
        serde_json::from_slice(&response).context("decoding daemon response")?;
    if !response.ok {
        anyhow::bail!(
            "daemon error: {}",
            response.error.unwrap_or_else(|| "unknown".into())
        );
    }
    response
        .body
        .and_then(take)
        .ok_or_else(|| anyhow::anyhow!("daemon returned an unexpected response body"))
}

pub fn status(socket: &Path) -> anyhow::Result<guard_ipc::StatusInfo> {
    exchange(socket, RequestOp::Status, |b| match b {
        ResponseBody::Status(v) => Some(v),
        _ => None,
    })
}
pub fn resources(socket: &Path) -> anyhow::Result<Vec<guard_ipc::ResourceInfo>> {
    exchange(socket, RequestOp::ResourcesList, |b| match b {
        ResponseBody::Resources(v) => Some(v),
        _ => None,
    })
}
pub fn browsers(socket: &Path) -> anyhow::Result<Vec<guard_ipc::BrowserInfo>> {
    exchange(socket, RequestOp::BrowsersList, |b| match b {
        ResponseBody::Browsers(v) => Some(v),
        _ => None,
    })
}
pub fn configuration(socket: &Path) -> anyhow::Result<guard_ipc::ConfigurationInfo> {
    exchange(socket, RequestOp::ConfigurationGet, |b| match b {
        ResponseBody::Configuration(v) => Some(v),
        _ => None,
    })
}
pub fn leases(socket: &Path) -> anyhow::Result<Vec<guard_ipc::LeaseInfo>> {
    exchange(socket, RequestOp::LeasesList, |b| match b {
        ResponseBody::Leases(v) => Some(v),
        _ => None,
    })
}
pub fn ssh_pending(socket: &Path) -> anyhow::Result<Vec<guard_ipc::SshPendingInfo>> {
    exchange(socket, RequestOp::SshPendingList, |body| match body {
        ResponseBody::SshPending(value) => Some(value),
        _ => None,
    })
}

pub fn resolve_ssh_read(
    socket: &Path,
    id: &str,
    action: guard_ipc::SshReadResolutionAction,
) -> anyhow::Result<guard_ipc::SshReadResolutionInfo> {
    exchange(
        socket,
        RequestOp::SshReadResolve {
            id: id.to_owned(),
            action,
        },
        |body| match body {
            ResponseBody::SshReadResolved(value) => Some(value),
            _ => None,
        },
    )
}
pub fn events(socket: &Path, limit: Option<u32>) -> anyhow::Result<Vec<guard_ipc::EventInfo>> {
    events_cursor(socket, limit, None, None)
}
pub fn events_cursor(
    socket: &Path,
    limit: Option<u32>,
    before_id: Option<i64>,
    after_id: Option<i64>,
) -> anyhow::Result<Vec<guard_ipc::EventInfo>> {
    exchange(
        socket,
        RequestOp::Events {
            limit,
            before_id,
            after_id,
        },
        |b| match b {
            ResponseBody::Events(v) => Some(v),
            _ => None,
        },
    )
}
pub fn event_detail(socket: &Path, event_id: i64) -> anyhow::Result<guard_ipc::EventInfo> {
    exchange(socket, RequestOp::Explain { event_id }, |b| match b {
        ResponseBody::Explain(v) => Some(*v),
        _ => None,
    })
}
pub fn lease_revoke(socket: &Path, lease_id: &str) -> anyhow::Result<(String, bool)> {
    exchange(
        socket,
        RequestOp::LeasesRevoke {
            lease_id: lease_id.to_owned(),
        },
        |b| match b {
            ResponseBody::LeaseRevoked { lease_id, found } => Some((lease_id, found)),
            _ => None,
        },
    )
}
pub fn migration_authorize(
    socket: &Path,
    source_browser: &str,
    source_profile: &str,
    target_browser: &str,
    duration_secs: Option<u64>,
) -> anyhow::Result<guard_ipc::MigrationAuthorizedInfo> {
    exchange(
        socket,
        RequestOp::MigrationAuthorize {
            source_browser: source_browser.to_owned(),
            source_profile: source_profile.to_owned(),
            target_browser: target_browser.to_owned(),
            duration_secs,
        },
        |b| match b {
            ResponseBody::MigrationAuthorized(v) => Some(v),
            _ => None,
        },
    )
}

pub fn migration_pending(socket: &Path) -> anyhow::Result<Vec<guard_ipc::MigrationPendingInfo>> {
    exchange(socket, RequestOp::MigrationPendingList, |body| match body {
        ResponseBody::MigrationPending(value) => Some(value),
        _ => None,
    })
}

pub fn resolve_migration(
    socket: &Path,
    id: &str,
    action: guard_ipc::MigrationResolutionAction,
) -> anyhow::Result<guard_ipc::MigrationResolutionInfo> {
    exchange(
        socket,
        RequestOp::MigrationResolve {
            id: id.to_owned(),
            action,
        },
        |body| match body {
            ResponseBody::MigrationResolved(value) => Some(value),
            _ => None,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn event_cursor_is_encoded() {
        let request = Request {
            version: PROTOCOL_VERSION,
            op: RequestOp::Events {
                limit: Some(10),
                before_id: Some(8),
                after_id: None,
            },
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("before_id"));
    }
}
