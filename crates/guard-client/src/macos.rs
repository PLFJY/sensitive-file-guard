//! Typed macOS client: authenticated XPC plus a mandatory device-owner gate
//! immediately before every capability-expanding request.

use std::time::Instant;

use anyhow::Context;
use guard_ipc::{
    MigrationResolutionAction, MigrationResolutionInfo, Request, RequestAuthorization, RequestOp,
    Response, ResponseBody, SshReadResolutionAction, SshReadResolutionInfo, MAX_REQUEST_BYTES,
    PROTOCOL_VERSION,
};
use guard_platform::{LocalTransport, RequestTimeout};
use platform_macos::local_auth::{DeviceOwnerAuthenticator, NativeDeviceOwnerAuthenticator};
use platform_macos::xpc::MacXpcTransport;

const CLI_AUTHENTICATION_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

/// Compatibility entry point for the existing guardctl request dispatcher.
/// Capability-expanding operations unconditionally cross LocalAuthentication;
/// there is no flag, environment variable, or token that suppresses the gate.
pub fn request_from_signed_cli(payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        payload.len() <= MAX_REQUEST_BYTES,
        "request exceeds MAX_REQUEST_BYTES"
    );
    let request: Request = serde_json::from_slice(payload)?;
    anyhow::ensure!(
        request.version == PROTOCOL_VERSION,
        "unsupported protocol version"
    );
    let timeout = match request.op.authorization() {
        RequestAuthorization::SensitiveAllow => {
            let deadline = Instant::now() + CLI_AUTHENTICATION_WINDOW;
            NativeDeviceOwnerAuthenticator
                .authenticate(sensitive_reason(&request.op), deadline)
                .context("device-owner authentication did not succeed")?;
            deadline
                .checked_duration_since(Instant::now())
                .filter(|duration| !duration.is_zero())
                .ok_or_else(|| anyhow::anyhow!("authorization deadline elapsed"))?
        }
        RequestAuthorization::Metadata | RequestAuthorization::RestrictiveMutation => {
            std::time::Duration::from_secs(2)
        }
    };
    MacXpcTransport::for_current_process()?.request_with_deadline(payload, timeout)
}

fn sensitive_reason(op: &RequestOp) -> &'static str {
    match op {
        RequestOp::MigrationAuthorize { .. } | RequestOp::MigrationResolve { .. } => {
            "Authorize temporary access for browser data import"
        }
        RequestOp::SshProtect { .. } => "Protect this SSH private key with Sensitive File Guard",
        RequestOp::SshLoadAuthorize { .. } => "Authorize this protected SSH key load",
        RequestOp::SshReadResolve { .. } => {
            "Allow this program to read the protected SSH private key"
        }
        RequestOp::ConfigurationApply { .. } => {
            "Apply this Sensitive File Guard protection configuration"
        }
        _ => "Authorize this Sensitive File Guard policy change",
    }
}

pub struct MacGuardClient<T = MacXpcTransport, A = NativeDeviceOwnerAuthenticator> {
    transport: T,
    authenticator: A,
}

impl MacGuardClient {
    pub fn for_current_process() -> anyhow::Result<Self> {
        Ok(Self {
            transport: MacXpcTransport::for_current_process()?,
            authenticator: NativeDeviceOwnerAuthenticator,
        })
    }
}

impl<T: LocalTransport, A: DeviceOwnerAuthenticator> MacGuardClient<T, A> {
    pub const fn new(transport: T, authenticator: A) -> Self {
        Self {
            transport,
            authenticator,
        }
    }

    pub fn status(&self) -> anyhow::Result<guard_ipc::StatusInfo> {
        self.metadata(RequestOp::Status, |body| match body {
            ResponseBody::Status(value) => Some(*value),
            _ => None,
        })
    }

    pub fn configuration(&self) -> anyhow::Result<guard_ipc::ConfigurationInfo> {
        self.metadata(RequestOp::ConfigurationGet, |body| match body {
            ResponseBody::Configuration(value) => Some(value),
            _ => None,
        })
    }

    pub fn pending_helper_poll(&self) -> anyhow::Result<guard_ipc::PendingHelperSnapshotInfo> {
        self.metadata(RequestOp::PendingHelperPoll, |body| match body {
            ResponseBody::PendingHelperSnapshot(value) => Some(value),
            _ => None,
        })
    }

    pub fn pending_helper_status(&self) -> anyhow::Result<guard_ipc::PendingHelperInfo> {
        self.metadata(RequestOp::PendingHelperStatus, |body| match body {
            ResponseBody::PendingHelper(value) => Some(value),
            _ => None,
        })
    }

    pub fn apply_configuration(
        &self,
        config: &platform_macos::config::MacBackendConfig,
        deadline: Instant,
    ) -> anyhow::Result<u32> {
        let config = serde_json::to_value(config)?;
        self.sensitive(
            RequestOp::ConfigurationApply { config },
            "Apply this Sensitive File Guard protection configuration",
            deadline,
            |body| match body {
                ResponseBody::ConfigurationApplied { version } => Some(version),
                _ => None,
            },
        )
    }

    pub fn resources(&self) -> anyhow::Result<Vec<guard_ipc::ResourceInfo>> {
        self.metadata(RequestOp::ResourcesList, |body| match body {
            ResponseBody::Resources(value) => Some(value),
            _ => None,
        })
    }

    pub fn events_cursor(
        &self,
        limit: Option<u32>,
        before_id: Option<i64>,
        after_id: Option<i64>,
    ) -> anyhow::Result<Vec<guard_ipc::EventInfo>> {
        self.metadata(
            RequestOp::Events {
                limit,
                before_id,
                after_id,
            },
            |body| match body {
                ResponseBody::Events(value) => Some(value),
                _ => None,
            },
        )
    }

    pub fn migration_pending(&self) -> anyhow::Result<Vec<guard_ipc::MigrationPendingInfo>> {
        self.metadata(RequestOp::MigrationPendingList, |body| match body {
            ResponseBody::MigrationPending(value) => Some(value),
            _ => None,
        })
    }

    pub fn ssh_pending(&self) -> anyhow::Result<Vec<guard_ipc::SshPendingInfo>> {
        self.metadata(RequestOp::SshPendingList, |body| match body {
            ResponseBody::SshPending(value) => Some(value),
            _ => None,
        })
    }

    pub fn block_migration(&self, id: &str) -> anyhow::Result<MigrationResolutionInfo> {
        self.restrictive(
            RequestOp::MigrationResolve {
                id: id.into(),
                action: MigrationResolutionAction::Block,
            },
            |body| match body {
                ResponseBody::MigrationResolved(value) => Some(value),
                _ => None,
            },
        )
    }

    pub fn allow_migration(
        &self,
        id: &str,
        deadline: Instant,
    ) -> anyhow::Result<MigrationResolutionInfo> {
        self.sensitive(
            RequestOp::MigrationResolve {
                id: id.into(),
                action: MigrationResolutionAction::AllowImport,
            },
            "Allow this browser to import protected browser data",
            deadline,
            |body| match body {
                ResponseBody::MigrationResolved(value) => Some(value),
                _ => None,
            },
        )
    }

    pub fn block_ssh_read(&self, id: &str) -> anyhow::Result<SshReadResolutionInfo> {
        self.restrictive(
            RequestOp::SshReadResolve {
                id: id.into(),
                action: SshReadResolutionAction::Block,
            },
            |body| match body {
                ResponseBody::SshReadResolved(value) => Some(value),
                _ => None,
            },
        )
    }

    pub fn allow_ssh_read(
        &self,
        id: &str,
        deadline: Instant,
    ) -> anyhow::Result<SshReadResolutionInfo> {
        self.sensitive(
            RequestOp::SshReadResolve {
                id: id.into(),
                action: SshReadResolutionAction::Allow,
            },
            "Allow this program to read the protected SSH private key",
            deadline,
            |body| match body {
                ResponseBody::SshReadResolved(value) => Some(value),
                _ => None,
            },
        )
    }

    pub fn authorize_migration(
        &self,
        source_browser: &str,
        source_profile: &str,
        target_browser: &str,
        duration_secs: Option<u64>,
        deadline: Instant,
    ) -> anyhow::Result<guard_ipc::MigrationAuthorizedInfo> {
        self.sensitive(
            RequestOp::MigrationAuthorize {
                source_browser: source_browser.into(),
                source_profile: source_profile.into(),
                target_browser: target_browser.into(),
                duration_secs,
            },
            "Authorize temporary access for browser data import",
            deadline,
            |body| match body {
                ResponseBody::MigrationAuthorized(value) => Some(value),
                _ => None,
            },
        )
    }

    pub fn protect_ssh_key(
        &self,
        path: &str,
        deadline: Instant,
    ) -> anyhow::Result<guard_ipc::SshProtectedInfo> {
        self.sensitive(
            RequestOp::SshProtect { path: path.into() },
            "Protect this SSH private key with Sensitive File Guard",
            deadline,
            |body| match body {
                ResponseBody::SshProtected(value) => Some(value),
                _ => None,
            },
        )
    }

    pub fn authorize_ssh_load(
        &self,
        path: &str,
        ssh_add_pid: u32,
        deadline: Instant,
    ) -> anyhow::Result<guard_ipc::SshLoadAuthorizedInfo> {
        self.sensitive(
            RequestOp::SshLoadAuthorize {
                path: path.into(),
                ssh_add_pid,
            },
            "Authorize this protected SSH key load",
            deadline,
            |body| match body {
                ResponseBody::SshLoadAuthorized(value) => Some(value),
                _ => None,
            },
        )
    }

    fn metadata<R>(&self, op: RequestOp, take: fn(ResponseBody) -> Option<R>) -> anyhow::Result<R> {
        anyhow::ensure!(
            op.authorization() == RequestAuthorization::Metadata,
            "internal client error: metadata path received a mutation"
        );
        self.exchange(
            op,
            take,
            RequestTimeout::Bounded(std::time::Duration::from_secs(2)),
        )
    }

    fn restrictive<R>(
        &self,
        op: RequestOp,
        take: fn(ResponseBody) -> Option<R>,
    ) -> anyhow::Result<R> {
        anyhow::ensure!(
            op.authorization() == RequestAuthorization::RestrictiveMutation,
            "internal client error: restrictive path received an allow"
        );
        self.exchange(
            op,
            take,
            RequestTimeout::Bounded(std::time::Duration::from_secs(2)),
        )
    }

    fn sensitive<R>(
        &self,
        op: RequestOp,
        reason: &str,
        deadline: Instant,
        take: fn(ResponseBody) -> Option<R>,
    ) -> anyhow::Result<R> {
        anyhow::ensure!(
            op.authorization() == RequestAuthorization::SensitiveAllow,
            "internal client error: LocalAuthentication path received a non-Allow operation"
        );
        self.authenticator
            .authenticate(reason, deadline)
            .context("device-owner authentication did not succeed")?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| anyhow::anyhow!("pending request timed out before XPC resolution"))?;
        self.exchange(op, take, RequestTimeout::Bounded(remaining))
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
        let bytes = self.transport.request(&bytes, timeout)?;
        let response: Response =
            serde_json::from_slice(&bytes).context("decoding system-extension response")?;
        anyhow::ensure!(
            response.version == PROTOCOL_VERSION,
            "system extension returned incompatible protocol version"
        );
        if !response.ok {
            anyhow::bail!(
                "system extension error: {}",
                response.error.unwrap_or_else(|| "unknown".into())
            );
        }
        response
            .body
            .and_then(take)
            .ok_or_else(|| anyhow::anyhow!("system extension returned an unexpected response body"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform_macos::local_auth::{AuthenticationError, AuthenticationFailure};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;

    struct FakeTransport {
        requests: Arc<Mutex<Vec<RequestOp>>>,
    }

    impl LocalTransport for FakeTransport {
        fn request(&self, payload: &[u8], _timeout: RequestTimeout) -> anyhow::Result<Vec<u8>> {
            let request: Request = serde_json::from_slice(payload)?;
            self.requests.lock().unwrap().push(request.op.clone());
            let body = match request.op {
                RequestOp::Status => ResponseBody::Status(Box::new(status())),
                RequestOp::PendingHelperStatus => {
                    ResponseBody::PendingHelper(guard_ipc::PendingHelperInfo {
                        running: true,
                        last_seen_ms_ago: Some(0),
                    })
                }
                RequestOp::PendingHelperPoll => {
                    ResponseBody::PendingHelperSnapshot(guard_ipc::PendingHelperSnapshotInfo {
                        migrations: Vec::new(),
                        ssh_reads: Vec::new(),
                    })
                }
                RequestOp::MigrationResolve { action, .. } => {
                    ResponseBody::MigrationResolved(match action {
                        MigrationResolutionAction::AllowImport => MigrationResolutionInfo::Allowed,
                        MigrationResolutionAction::Block => MigrationResolutionInfo::Blocked,
                    })
                }
                RequestOp::SshReadResolve { action, .. } => {
                    ResponseBody::SshReadResolved(match action {
                        SshReadResolutionAction::Allow => SshReadResolutionInfo::Allowed,
                        SshReadResolutionAction::Block => SshReadResolutionInfo::Blocked,
                    })
                }
                RequestOp::SshProtect { path } => {
                    ResponseBody::SshProtected(guard_ipc::SshProtectedInfo {
                        resource_id: path.clone(),
                        path,
                        owner_uid: 501,
                    })
                }
                _ => return Err(anyhow::anyhow!("unexpected fake operation")),
            };
            Ok(serde_json::to_vec(&Response::ok(body))?)
        }
    }

    struct FakeAuthenticator {
        calls: Arc<AtomicUsize>,
        result: Result<(), AuthenticationFailure>,
    }

    type TestClient = MacGuardClient<FakeTransport, FakeAuthenticator>;
    type ClientFixture = (TestClient, Arc<Mutex<Vec<RequestOp>>>, Arc<AtomicUsize>);

    impl DeviceOwnerAuthenticator for FakeAuthenticator {
        fn authenticate(
            &self,
            _reason: &str,
            _deadline: Instant,
        ) -> Result<(), AuthenticationError> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            self.result.map_err(|failure| AuthenticationError {
                failure,
                diagnostic: "synthetic authentication result".into(),
            })
        }
    }

    fn status() -> guard_ipc::StatusInfo {
        guard_ipc::StatusInfo {
            version: "test".into(),
            backend_kind: "macos-endpoint-security".into(),
            backend_diagnostic: None,
            backend_state: None,
            enforcement_active: false,
            read_only_guaranteed: Some(true),
            status: "NOT_ENFORCING".into(),
            mode: None,
            marked_filesystems: None,
            required_filesystems: None,
            filesystem_marks_healthy: None,
            strict_events_total: None,
            strict_fast_allowed: None,
            protected_events: 0,
            fanotify_overflows: None,
            classifier_failures: None,
            strict_alias_scans: None,
            strict_alias_matches: None,
            topology_degraded: None,
            mac_health: None,
            protected_files: 0,
            ssh_protected_keys: 0,
            protected_trees: 0,
            browsers: 0,
            browser_exes: 0,
            allowed: 0,
            denied: 0,
            unclassified: 0,
            audit_dropped: 0,
            peer_uid: 501,
        }
    }

    fn client(result: Result<(), AuthenticationFailure>) -> ClientFixture {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        (
            MacGuardClient::new(
                FakeTransport {
                    requests: Arc::clone(&requests),
                },
                FakeAuthenticator {
                    calls: Arc::clone(&calls),
                    result,
                },
            ),
            requests,
            calls,
        )
    }

    #[test]
    fn allow_is_not_sent_until_authentication_succeeds() {
        let (client, requests, calls) = client(Ok(()));
        assert_eq!(
            client
                .allow_migration("1", Instant::now() + Duration::from_secs(1))
                .unwrap(),
            MigrationResolutionInfo::Allowed
        );
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert!(matches!(
            requests.lock().unwrap().as_slice(),
            [RequestOp::MigrationResolve {
                action: MigrationResolutionAction::AllowImport,
                ..
            }]
        ));
    }

    #[test]
    fn cancellation_sends_no_allow_and_block_needs_no_authentication() {
        let (client, requests, calls) = client(Err(AuthenticationFailure::Cancelled));
        assert!(client
            .allow_ssh_read("1", Instant::now() + Duration::from_secs(1))
            .is_err());
        assert!(requests.lock().unwrap().is_empty());
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(
            client.block_ssh_read("1").unwrap(),
            SshReadResolutionInfo::Blocked
        );
        assert_eq!(calls.load(Ordering::Acquire), 1);
    }

    #[test]
    fn helper_poll_is_metadata_only_and_never_authenticates() {
        let (client, requests, calls) = client(Err(AuthenticationFailure::Failed));
        let snapshot = client.pending_helper_poll().unwrap();
        assert!(snapshot.migrations.is_empty());
        assert!(snapshot.ssh_reads.is_empty());
        assert_eq!(calls.load(Ordering::Acquire), 0);
        assert!(matches!(
            requests.lock().unwrap().as_slice(),
            [RequestOp::PendingHelperPoll]
        ));
    }

    #[test]
    fn ssh_protect_authenticates_before_sending_path_metadata() {
        let (client, requests, calls) = client(Ok(()));
        let protected = client
            .protect_ssh_key(
                "/synthetic/id_ed25519",
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(protected.path, "/synthetic/id_ed25519");
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert!(matches!(
            requests.lock().unwrap().as_slice(),
            [RequestOp::SshProtect { path }] if path == "/synthetic/id_ed25519"
        ));
    }

    #[test]
    fn configuration_apply_has_no_noninteractive_client_path() {
        let (client, requests, calls) = client(Err(AuthenticationFailure::Cancelled));
        let config = platform_macos::config::MacBackendConfig {
            version: platform_macos::config::MAC_CONFIG_VERSION,
            policy_enabled: true,
            process_shield_enabled: true,
            common_policy: guard_platform::config::PolicyConfig {
                browsers: Vec::new(),
                enrolled_exes: Vec::new(),
                ssh_keys: vec![std::path::PathBuf::from("/synthetic/id_ed25519")],
            },
            browser_trust: Vec::new(),
            mac_allowlist: platform_macos::config::MacAllowlistConfig::default(),
        };
        assert!(client
            .apply_configuration(&config, Instant::now() + Duration::from_secs(1))
            .is_err());
        assert!(requests.lock().unwrap().is_empty());
        assert_eq!(calls.load(Ordering::Acquire), 1);
    }

    struct BlockingAuthenticator {
        state: Arc<(Mutex<bool>, Condvar)>,
    }

    impl DeviceOwnerAuthenticator for BlockingAuthenticator {
        fn authenticate(
            &self,
            _reason: &str,
            _deadline: Instant,
        ) -> Result<(), AuthenticationError> {
            let (lock, condition) = &*self.state;
            let started = lock.lock().unwrap();
            let _guard = condition
                .wait_while(started, |released| !*released)
                .unwrap();
            Ok(())
        }
    }

    #[test]
    fn metadata_query_is_not_serialized_behind_interactive_authentication() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let state = Arc::new((Mutex::new(false), Condvar::new()));
        let client = Arc::new(MacGuardClient::new(
            FakeTransport {
                requests: Arc::clone(&requests),
            },
            BlockingAuthenticator {
                state: Arc::clone(&state),
            },
        ));
        let allowing = {
            let client = Arc::clone(&client);
            std::thread::spawn(move || {
                client.allow_migration("1", Instant::now() + Duration::from_secs(2))
            })
        };
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(client.status().unwrap().peer_uid, 501);
        {
            let (lock, condition) = &*state;
            *lock.lock().unwrap() = true;
            condition.notify_all();
        }
        assert!(allowing.join().unwrap().is_ok());
    }
}
