//! Synchronous typed client for guardd's local versioned JSON IPC.

use std::path::Path;

use anyhow::Context;
use guard_ipc::{Request, RequestOp, Response, ResponseBody, MAX_REQUEST_BYTES, PROTOCOL_VERSION};
use platform_linux::ipc::IpcClient;

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
pub fn incidents(socket: &Path) -> anyhow::Result<Vec<guard_ipc::SshIncidentInfo>> {
    exchange(socket, RequestOp::IncidentsList, |body| match body {
        ResponseBody::Incidents(value) => Some(value),
        _ => None,
    })
}
pub fn incident(socket: &Path, id: &str) -> anyhow::Result<guard_ipc::SshIncidentInfo> {
    exchange(
        socket,
        RequestOp::IncidentGet { id: id.to_owned() },
        |body| match body {
            ResponseBody::Incident(value) => Some(*value),
            _ => None,
        },
    )
}
pub fn resolve_incident(
    socket: &Path,
    id: &str,
    action: guard_ipc::IncidentResolutionAction,
) -> anyhow::Result<guard_ipc::SshIncidentInfo> {
    exchange(
        socket,
        RequestOp::IncidentResolve {
            id: id.to_owned(),
            action,
        },
        |body| match body {
            ResponseBody::IncidentResolved(value) => Some(value),
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
