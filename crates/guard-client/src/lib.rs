//! Synchronous typed client for guardd's local versioned JSON IPC.

use std::path::Path;

use anyhow::Context;
use guard_ipc::{Request, RequestOp, Response, ResponseBody, MAX_REQUEST_BYTES, PROTOCOL_VERSION};
use guard_platform::{LocalTransport, RequestTimeout};

/// Client-side local transport.  It only connects and exchanges framed
/// payloads; server-side peer authentication remains in the selected
/// platform adapter.
pub mod transport {
    use std::io::{self, Read, Write};
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::time::Duration;

    use guard_platform::{LocalTransport, RequestTimeout};

    pub struct UnixSocketTransport<'a> {
        path: &'a Path,
    }

    impl<'a> UnixSocketTransport<'a> {
        pub const fn new(path: &'a Path) -> Self {
            Self { path }
        }
    }

    impl LocalTransport for UnixSocketTransport<'_> {
        fn request(&self, payload: &[u8], timeout: RequestTimeout) -> anyhow::Result<Vec<u8>> {
            let mut stream = UnixStream::connect(self.path)?;
            stream.set_write_timeout(Some(Duration::from_secs(2)))?;
            let read_timeout = match timeout {
                RequestTimeout::Bounded(duration) => Some(duration),
                RequestTimeout::Authorization => None,
            };
            stream.set_read_timeout(read_timeout)?;
            write_frame(&mut stream, payload)?;
            Ok(read_frame(&mut stream, 16 * 1024 * 1024)?)
        }
    }

    /// Backward-compatible Unix entry point for clients that exchange custom
    /// protocol operations. It delegates to the same production transport
    /// seam as the typed `GuardClient` facade.
    pub struct IpcClient;

    impl IpcClient {
        pub fn request(path: &Path, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
            UnixSocketTransport::new(path)
                .request(payload, RequestTimeout::Bounded(Duration::from_secs(2)))
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

use transport::UnixSocketTransport;

pub struct GuardClient<T> {
    transport: T,
}

impl<T: LocalTransport> GuardClient<T> {
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    fn exchange<R>(
        &self,
        op: RequestOp,
        take: fn(ResponseBody) -> Option<R>,
        timeout: RequestTimeout,
    ) -> anyhow::Result<R> {
        let bytes = serde_json::to_vec(&Request {
            version: PROTOCOL_VERSION,
            op,
        })?;
        anyhow::ensure!(
            bytes.len() <= MAX_REQUEST_BYTES,
            "request exceeds MAX_REQUEST_BYTES"
        );
        let response = self.transport.request(&bytes, timeout)?;
        decode_response(&response, take)
    }
}

fn exchange<T>(
    socket: &Path,
    op: RequestOp,
    take: fn(ResponseBody) -> Option<T>,
) -> anyhow::Result<T> {
    GuardClient::new(UnixSocketTransport::new(socket)).exchange(
        op,
        take,
        RequestTimeout::Bounded(std::time::Duration::from_secs(2)),
    )
}

fn exchange_waiting_for_authorization<T>(
    socket: &Path,
    op: RequestOp,
    take: fn(ResponseBody) -> Option<T>,
) -> anyhow::Result<T> {
    // Sensitive resolution has its own server/platform deadline. A client read
    // timeout would close the channel while the user is still authenticating.
    GuardClient::new(UnixSocketTransport::new(socket)).exchange(
        op,
        take,
        RequestTimeout::Authorization,
    )
}

fn decode_response<T>(bytes: &[u8], take: fn(ResponseBody) -> Option<T>) -> anyhow::Result<T> {
    let response: Response = serde_json::from_slice(bytes).context("decoding daemon response")?;
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
    exchange_waiting_for_authorization(
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
    exchange_waiting_for_authorization(
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
    exchange_waiting_for_authorization(
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
    use std::sync::Mutex;
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

    struct FakeTransport {
        response: Vec<u8>,
        timeout: Mutex<Option<RequestTimeout>>,
    }

    impl LocalTransport for FakeTransport {
        fn request(&self, _payload: &[u8], timeout: RequestTimeout) -> anyhow::Result<Vec<u8>> {
            *self.timeout.lock().unwrap() = Some(timeout);
            Ok(self.response.clone())
        }
    }

    #[test]
    fn typed_client_uses_injected_transport_and_authorization_timeout() {
        let transport = FakeTransport {
            response: serde_json::to_vec(&Response::ok(ResponseBody::MigrationResolved(
                guard_ipc::MigrationResolutionInfo::Allowed,
            )))
            .unwrap(),
            timeout: Mutex::new(None),
        };
        let client = GuardClient::new(transport);
        let result = client
            .exchange(
                RequestOp::MigrationResolve {
                    id: "fixture".into(),
                    action: guard_ipc::MigrationResolutionAction::AllowImport,
                },
                |body| match body {
                    ResponseBody::MigrationResolved(value) => Some(value),
                    _ => None,
                },
                RequestTimeout::Authorization,
            )
            .unwrap();
        assert_eq!(result, guard_ipc::MigrationResolutionInfo::Allowed);
        assert_eq!(
            *client.transport.timeout.lock().unwrap(),
            Some(RequestTimeout::Authorization)
        );
    }
}
