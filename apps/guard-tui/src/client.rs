//! IPC client functions used by the TUI.
//!
//! Each function builds a `Request`, sends it over the framed Unix-socket IPC
//! transport, and parses the `ResponseBody` into a typed value. The TUI binary
//! polls these on a refresh timer; the functions are kept pure (no terminal
//! state) so they can be exercised by integration tests against a mock or real
//! daemon IPC server.
//!
//! Authorization is enforced by the daemon via `SO_PEERCRED`; the client never
//! sends a UID (see `MigrationAuthorize`).

use std::path::Path;

use guard_ipc::{
    MigrationAuthorizedInfo, Request, RequestOp, Response, ResponseBody, StatusInfo,
    MAX_REQUEST_BYTES, PROTOCOL_VERSION,
};
use platform_linux::ipc::IpcClient;

/// One-shot helper: send a request, return the parsed response body or an
/// error (daemon `ok=false` becomes an `anyhow` error carrying the message).
fn exchange<T>(
    socket: &Path,
    op: RequestOp,
    take: fn(ResponseBody) -> Option<T>,
) -> anyhow::Result<T> {
    let req = Request {
        version: PROTOCOL_VERSION,
        op,
    };
    let req_bytes = serde_json::to_vec(&req)?;
    if req_bytes.len() > MAX_REQUEST_BYTES {
        anyhow::bail!("request exceeds MAX_REQUEST_BYTES");
    }
    let resp_bytes = IpcClient::request(socket, &req_bytes)
        .map_err(|e| anyhow::anyhow!("IPC request to {}: {e}", socket.display()))?;
    let resp: Response = serde_json::from_slice(&resp_bytes)?;
    if !resp.ok {
        return Err(anyhow::anyhow!(
            "daemon error: {}",
            resp.error.unwrap_or_else(|| "unknown".into())
        ));
    }
    match resp.body.and_then(take) {
        Some(v) => Ok(v),
        None => anyhow::bail!("daemon returned an unexpected response body"),
    }
}

pub fn status(socket: &Path) -> anyhow::Result<StatusInfo> {
    exchange(socket, RequestOp::Status, |b| match b {
        ResponseBody::Status(s) => Some(s),
        _ => None,
    })
}

pub fn events(socket: &Path, limit: Option<u32>) -> anyhow::Result<Vec<guard_ipc::EventInfo>> {
    exchange(socket, RequestOp::Events { limit }, |b| match b {
        ResponseBody::Events(e) => Some(e),
        _ => None,
    })
}

pub fn leases(socket: &Path) -> anyhow::Result<Vec<guard_ipc::LeaseInfo>> {
    exchange(socket, RequestOp::LeasesList, |b| match b {
        ResponseBody::Leases(l) => Some(l),
        _ => None,
    })
}

pub fn browsers(socket: &Path) -> anyhow::Result<Vec<guard_ipc::BrowserInfo>> {
    exchange(socket, RequestOp::BrowsersList, |b| match b {
        ResponseBody::Browsers(b) => Some(b),
        _ => None,
    })
}

/// Authorize a read-only cross-browser migration lease. The authorizing UID is
/// taken from the daemon's kernel-verified peer creds, never from this call.
pub fn migration_authorize(
    socket: &Path,
    source_browser: &str,
    source_profile: &str,
    target_browser: &str,
    duration_secs: Option<u64>,
) -> anyhow::Result<MigrationAuthorizedInfo> {
    exchange(
        socket,
        RequestOp::MigrationAuthorize {
            source_browser: source_browser.to_string(),
            source_profile: source_profile.to_string(),
            target_browser: target_browser.to_string(),
            duration_secs,
        },
        |b| match b {
            ResponseBody::MigrationAuthorized(m) => Some(m),
            _ => None,
        },
    )
}

/// Revoke a lease by id string. Returns `(lease_id, found)`.
pub fn lease_revoke(socket: &Path, lease_id: &str) -> anyhow::Result<(String, bool)> {
    exchange(
        socket,
        RequestOp::LeasesRevoke {
            lease_id: lease_id.to_string(),
        },
        |b| match b {
            ResponseBody::LeaseRevoked { lease_id, found } => Some((lease_id, found)),
            _ => None,
        },
    )
}
