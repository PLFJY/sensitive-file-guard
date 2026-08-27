//! Authenticated NSXPC transport for the Endpoint Security system extension.

use std::collections::BTreeSet;
use std::ffi::{c_char, c_void, CString};
use std::ptr::NonNull;
use std::sync::Arc;
use std::time::Duration;

use guard_ipc::{Request, Response, MAX_REQUEST_BYTES, PROTOCOL_VERSION};
use guard_platform::{LocalTransport, RequestTimeout};

use crate::code_signature::{CodeSignatureInspector, NativeCodeSignatureInspector};
use crate::{DEFAULT_APP_BUNDLE_ID, DEFAULT_EXTENSION_BUNDLE_ID, DEFAULT_XPC_SERVICE_NAME};

const ERROR_CAPACITY: usize = 512;
const MAX_CONCURRENT_REQUESTS: usize = 32;
const DEFAULT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Owner of `/dev/console`, which is the active GUI login targeted by the
/// Phase-05 single-session XPC service. Multi-session routing remains explicit
/// rather than accepting every same-machine UID.
pub fn console_user_uid() -> anyhow::Result<u32> {
    use std::os::unix::fs::MetadataExt;

    let uid = std::fs::metadata("/dev/console")?.uid();
    anyhow::ensure!(uid != 0, "no active non-root console user");
    Ok(uid)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningRequirements {
    pub identity: MacSigningIdentity,
    pub client_requirement: String,
    pub server_requirement: String,
}

/// The only two signing models accepted by Guard's macOS control plane.
/// Neither admits an arbitrary process merely because it has the same UID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacSigningIdentity {
    AppleTeam { team_id: String },
    LocalCertificate { leaf_certificate_sha1: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSigningFacts<'a> {
    pub euid: u32,
    pub code_valid: bool,
    pub team_id: Option<&'a str>,
    pub signing_id: Option<&'a str>,
    pub leaf_certificate_sha1: Option<&'a str>,
}

/// Executable form of the same exact identity rule installed on each native
/// NSXPCConnection. It exists for deterministic adversarial tests and review;
/// Foundation's code-signing requirement remains the live enforcement point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSigningPolicy {
    expected_euids: BTreeSet<u32>,
    identity: MacSigningIdentity,
    signing_ids: BTreeSet<String>,
}

impl ClientSigningPolicy {
    pub fn new(
        expected_euids: impl IntoIterator<Item = u32>,
        identity: MacSigningIdentity,
        app_bundle_id: &str,
    ) -> anyhow::Result<Self> {
        validate_signing_identity(&identity)?;
        validate_requirement_atom("app bundle ID", app_bundle_id)?;
        let expected_euids = expected_euids.into_iter().collect::<BTreeSet<_>>();
        anyhow::ensure!(
            !expected_euids.is_empty(),
            "expected EUID set must not be empty"
        );
        Ok(Self {
            expected_euids,
            identity,
            signing_ids: BTreeSet::from([
                app_bundle_id.into(),
                format!("{app_bundle_id}.guardctl"),
                format!("{app_bundle_id}.guard-notify"),
            ]),
        })
    }

    pub fn allows(&self, peer: &PeerSigningFacts<'_>) -> bool {
        peer.code_valid
            && self.expected_euids.contains(&peer.euid)
            && signing_identity_matches(&self.identity, peer)
            && peer
                .signing_id
                .is_some_and(|identifier| self.signing_ids.contains(identifier))
    }
}

impl SigningRequirements {
    pub fn new(
        team_id: &str,
        app_bundle_id: &str,
        extension_bundle_id: &str,
    ) -> anyhow::Result<Self> {
        Self::for_identity(
            MacSigningIdentity::AppleTeam {
                team_id: team_id.into(),
            },
            app_bundle_id,
            extension_bundle_id,
        )
    }

    pub fn for_local_certificate(
        leaf_certificate_sha1: &str,
        app_bundle_id: &str,
        extension_bundle_id: &str,
    ) -> anyhow::Result<Self> {
        Self::for_identity(
            MacSigningIdentity::LocalCertificate {
                leaf_certificate_sha1: leaf_certificate_sha1.into(),
            },
            app_bundle_id,
            extension_bundle_id,
        )
    }

    pub fn for_identity(
        identity: MacSigningIdentity,
        app_bundle_id: &str,
        extension_bundle_id: &str,
    ) -> anyhow::Result<Self> {
        validate_signing_identity(&identity)?;
        validate_requirement_atom("app bundle ID", app_bundle_id)?;
        validate_requirement_atom("extension bundle ID", extension_bundle_id)?;
        let guardctl = format!("{app_bundle_id}.guardctl");
        let notify = format!("{app_bundle_id}.guard-notify");
        let requirement_identity = |identifier: &str| match &identity {
            MacSigningIdentity::AppleTeam { team_id } => format!(
                "(identifier \"{identifier}\" and certificate leaf[subject.OU] = \"{team_id}\")"
            ),
            MacSigningIdentity::LocalCertificate {
                leaf_certificate_sha1,
            } => format!(
                "(identifier \"{identifier}\" and certificate leaf = H\"{leaf_certificate_sha1}\")"
            ),
        };
        let client_requirement = format!(
            "{} and ({} or {} or {})",
            signing_anchor(&identity),
            requirement_identity(app_bundle_id),
            requirement_identity(&guardctl),
            requirement_identity(&notify)
        );
        let server_requirement = format!(
            "{} and {}",
            signing_anchor(&identity),
            requirement_identity(extension_bundle_id)
        );
        validate_requirement_syntax(&client_requirement)?;
        validate_requirement_syntax(&server_requirement)?;
        Ok(Self {
            identity,
            client_requirement,
            server_requirement,
        })
    }

    pub fn current_process() -> anyhow::Result<Self> {
        let executable = std::env::current_exe()?;
        let signature = NativeCodeSignatureInspector.inspect(&executable)?;
        anyhow::ensure!(signature.valid, "current process code signature is invalid");
        if let Some(team_id) = signature.team_id.as_deref().filter(|team| !team.is_empty()) {
            return Self::new(team_id, DEFAULT_APP_BUNDLE_ID, DEFAULT_EXTENSION_BUNDLE_ID);
        }
        let certificate = signature.leaf_certificate_sha1.as_deref().ok_or_else(|| {
            anyhow::anyhow!("ad-hoc signing has no Team ID or local certificate; authenticated XPC is unavailable")
        })?;
        Self::for_local_certificate(
            certificate,
            DEFAULT_APP_BUNDLE_ID,
            DEFAULT_EXTENSION_BUNDLE_ID,
        )
    }
}

fn signing_anchor(identity: &MacSigningIdentity) -> &'static str {
    match identity {
        MacSigningIdentity::AppleTeam { .. } => "anchor apple generic",
        // `certificate leaf = H"…"` below pins the complete local
        // certificate. Requiring `anchor trusted` would force users to alter
        // global trust policy for a private self-signed identity.
        MacSigningIdentity::LocalCertificate { .. } => "true",
    }
}

fn validate_signing_identity(identity: &MacSigningIdentity) -> anyhow::Result<()> {
    match identity {
        MacSigningIdentity::AppleTeam { team_id } => validate_requirement_atom("Team ID", team_id),
        MacSigningIdentity::LocalCertificate {
            leaf_certificate_sha1,
        } => {
            anyhow::ensure!(
                leaf_certificate_sha1.len() == 40
                    && leaf_certificate_sha1
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit()),
                "local certificate SHA-1 must be exactly 40 hexadecimal characters"
            );
            Ok(())
        }
    }
}

fn signing_identity_matches(identity: &MacSigningIdentity, peer: &PeerSigningFacts<'_>) -> bool {
    match identity {
        MacSigningIdentity::AppleTeam { team_id } => peer.team_id == Some(team_id),
        MacSigningIdentity::LocalCertificate {
            leaf_certificate_sha1,
        } => peer.leaf_certificate_sha1 == Some(leaf_certificate_sha1),
    }
}

fn validate_requirement_atom(label: &str, value: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!value.is_empty(), "{label} must not be empty");
    anyhow::ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')),
        "{label} contains a character unsafe for a code-signing requirement"
    );
    Ok(())
}

fn validate_requirement_syntax(requirement: &str) -> anyhow::Result<()> {
    let requirement = CString::new(requirement)?;
    let mut error = [0 as c_char; ERROR_CAPACITY];
    // SAFETY: input is a valid NUL-terminated string and the writable error
    // buffer remains live for the synchronous Security.framework call.
    let valid = unsafe {
        guard_code_signing_requirement_is_valid(
            requirement.as_ptr(),
            error.as_mut_ptr(),
            error.len(),
        )
    };
    anyhow::ensure!(
        valid,
        "invalid code-signing requirement: {}",
        c_error(&error)
    );
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPeer {
    pub euid: u32,
}

pub trait XpcRequestHandler: Send + Sync + 'static {
    fn handle(&self, peer: AuthenticatedPeer, request: Request) -> Response;
}

/// Validates framing and protocol version before product request dispatch.
pub struct GuardIpcHandler<H> {
    inner: H,
}

impl<H> GuardIpcHandler<H> {
    pub const fn new(inner: H) -> Self {
        Self { inner }
    }
}

trait ErasedRequestHandler: Send + Sync {
    fn handle_bytes(&self, euid: u32, bytes: &[u8]) -> Vec<u8>;
}

impl<H: XpcRequestHandler> ErasedRequestHandler for GuardIpcHandler<H> {
    fn handle_bytes(&self, euid: u32, bytes: &[u8]) -> Vec<u8> {
        let response = if bytes.len() > MAX_REQUEST_BYTES {
            Response::err("request_too_large")
        } else {
            match serde_json::from_slice::<Request>(bytes) {
                Ok(request) if request.version == PROTOCOL_VERSION => {
                    self.inner.handle(AuthenticatedPeer { euid }, request)
                }
                Ok(_) => Response::err("unsupported_protocol_version"),
                Err(_) => Response::err("malformed_request"),
            }
        };
        serde_json::to_vec(&response).unwrap_or_else(|_| {
            format!(
                "{{\"version\":{PROTOCOL_VERSION},\"ok\":false,\"error\":\"response_encoding_failed\"}}"
            )
            .into_bytes()
        })
    }
}

struct ServerContext {
    allowed_uids: BTreeSet<u32>,
    handler: Arc<dyn ErasedRequestHandler>,
}

pub struct MacXpcServer {
    raw: NonNull<c_void>,
    context: NonNull<ServerContext>,
}

impl MacXpcServer {
    pub fn new<H: XpcRequestHandler>(
        requirements: &SigningRequirements,
        allowed_uids: impl IntoIterator<Item = u32>,
        handler: H,
    ) -> anyhow::Result<Self> {
        let service_name = CString::new(DEFAULT_XPC_SERVICE_NAME)?;
        let requirement = CString::new(requirements.client_requirement.as_str())?;
        let context = Box::new(ServerContext {
            allowed_uids: allowed_uids.into_iter().collect(),
            handler: Arc::new(GuardIpcHandler::new(handler)),
        });
        anyhow::ensure!(
            !context.allowed_uids.is_empty(),
            "XPC service requires at least one expected peer EUID"
        );
        let context = NonNull::new(Box::into_raw(context)).expect("Box pointer is non-null");
        let mut error = [0 as c_char; ERROR_CAPACITY];
        // SAFETY: callbacks and context have static-compatible lifetimes and
        // remain allocated until the native listener is destroyed in Drop.
        let raw = unsafe {
            guard_xpc_server_create(
                service_name.as_ptr(),
                requirement.as_ptr(),
                MAX_REQUEST_BYTES,
                MAX_CONCURRENT_REQUESTS,
                Some(peer_callback),
                Some(request_callback),
                Some(response_free),
                context.as_ptr().cast(),
                error.as_mut_ptr(),
                error.len(),
            )
        };
        let Some(raw) = NonNull::new(raw) else {
            // SAFETY: native creation failed and therefore cannot retain the
            // context pointer.
            unsafe { drop(Box::from_raw(context.as_ptr())) };
            anyhow::bail!("could not create XPC service: {}", c_error(&error));
        };
        Ok(Self { raw, context })
    }

    pub fn for_current_process<H: XpcRequestHandler>(
        allowed_uids: impl IntoIterator<Item = u32>,
        handler: H,
    ) -> anyhow::Result<Self> {
        Self::new(
            &SigningRequirements::current_process()?,
            allowed_uids,
            handler,
        )
    }

    pub fn activate(&self) {
        // SAFETY: raw is a live native server owned by self.
        unsafe { guard_xpc_server_activate(self.raw.as_ptr()) }
    }

    pub fn run(&self) {
        // SAFETY: raw is a live native server owned by self. serviceListener
        // resume intentionally becomes the extension's service loop.
        unsafe { guard_xpc_server_run(self.raw.as_ptr()) }
    }
}

impl Drop for MacXpcServer {
    fn drop(&mut self) {
        // SAFETY: invalidating the listener prevents new connections. Existing
        // NSXPCConnection queues may finish an already-delivered callback after
        // invalidation, so the tiny immutable context is deliberately retained
        // until process exit instead of risking a use-after-free at shutdown.
        unsafe { guard_xpc_server_destroy(self.raw.as_ptr()) }
        let _retained_for_process_lifetime = self.context;
    }
}

pub struct MacXpcTransport {
    service_name: CString,
    server_requirement: CString,
}

impl MacXpcTransport {
    pub fn new(service_name: &str, server_requirement: &str) -> anyhow::Result<Self> {
        validate_requirement_syntax(server_requirement)?;
        Ok(Self {
            service_name: CString::new(service_name)?,
            server_requirement: CString::new(server_requirement)?,
        })
    }

    pub fn for_current_process() -> anyhow::Result<Self> {
        let requirements = SigningRequirements::current_process()?;
        Self::new(DEFAULT_XPC_SERVICE_NAME, &requirements.server_requirement)
    }

    pub fn request_with_deadline(
        &self,
        payload: &[u8],
        timeout: Duration,
    ) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(
            payload.len() <= MAX_REQUEST_BYTES,
            "request exceeds MAX_REQUEST_BYTES"
        );
        anyhow::ensure!(!timeout.is_zero(), "XPC request deadline already elapsed");
        let timeout_milliseconds = u64::try_from(timeout.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        let mut response = std::ptr::null_mut();
        let mut response_length = 0usize;
        let mut error = [0 as c_char; ERROR_CAPACITY];
        // SAFETY: all input pointers are valid for this synchronous call. On
        // success the bridge returns one malloc-owned response buffer.
        let success = unsafe {
            guard_xpc_request(
                self.service_name.as_ptr(),
                self.server_requirement.as_ptr(),
                payload.as_ptr(),
                payload.len(),
                timeout_milliseconds,
                &mut response,
                &mut response_length,
                error.as_mut_ptr(),
                error.len(),
            )
        };
        anyhow::ensure!(
            success,
            "authenticated XPC request failed: {}",
            c_error(&error)
        );
        anyhow::ensure!(!response.is_null(), "XPC returned a null response");
        // SAFETY: bridge promises response_length readable bytes and matching
        // release function. Copying keeps allocator ownership on its side.
        let bytes = unsafe { std::slice::from_raw_parts(response, response_length).to_vec() };
        // SAFETY: response was allocated by guard_xpc_request exactly once.
        unsafe { guard_xpc_bytes_free(response) };
        Ok(bytes)
    }
}

impl LocalTransport for MacXpcTransport {
    fn request(&self, payload: &[u8], timeout: RequestTimeout) -> anyhow::Result<Vec<u8>> {
        let timeout = match timeout {
            RequestTimeout::Bounded(timeout) => timeout,
            // LocalAuthentication is completed before an Allow is sent. The
            // XPC resolution itself must remain short and cannot wait forever.
            RequestTimeout::Authorization => DEFAULT_RESPONSE_TIMEOUT,
        };
        self.request_with_deadline(payload, timeout)
    }
}

extern "C" fn peer_callback(euid: u32, context: *mut c_void) -> bool {
    // SAFETY: native server passes the immutable ServerContext installed at
    // creation, which remains live until listener destruction.
    let context = unsafe { &*context.cast::<ServerContext>() };
    context.allowed_uids.contains(&euid)
}

extern "C" fn request_callback(
    request: *const u8,
    request_length: usize,
    euid: u32,
    response: *mut *const u8,
    response_length: *mut usize,
    context: *mut c_void,
) -> bool {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: native side guarantees request points to request_length bytes
        // for the duration of the callback.
        let request = unsafe { std::slice::from_raw_parts(request, request_length) };
        // SAFETY: context is the live immutable ServerContext.
        let context = unsafe { &*context.cast::<ServerContext>() };
        context.handler.handle_bytes(euid, request)
    }));
    let Ok(bytes) = result else {
        return false;
    };
    let boxed = bytes.into_boxed_slice();
    let length = boxed.len();
    let pointer = Box::into_raw(boxed) as *const u8;
    // SAFETY: native side supplied writable output slots.
    unsafe {
        *response = pointer;
        *response_length = length;
    }
    true
}

extern "C" fn response_free(response: *const u8, response_length: usize, _context: *mut c_void) {
    if response.is_null() {
        return;
    }
    // SAFETY: request_callback produced this exact boxed slice and transfers it
    // back exactly once after NSData has copied the response.
    unsafe {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            response.cast_mut(),
            response_length,
        )));
    }
}

fn c_error(buffer: &[c_char]) -> String {
    let bytes = buffer
        .iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();
    String::from_utf8_lossy(&bytes).into_owned()
}

extern "C" {
    fn guard_xpc_server_create(
        service_name: *const c_char,
        client_code_signing_requirement: *const c_char,
        maximum_request_bytes: usize,
        maximum_concurrent_requests: usize,
        peer_callback: Option<extern "C" fn(u32, *mut c_void) -> bool>,
        request_callback: Option<
            extern "C" fn(*const u8, usize, u32, *mut *const u8, *mut usize, *mut c_void) -> bool,
        >,
        response_free: Option<extern "C" fn(*const u8, usize, *mut c_void)>,
        context: *mut c_void,
        error_buffer: *mut c_char,
        error_buffer_length: usize,
    ) -> *mut c_void;
    fn guard_xpc_server_activate(server: *mut c_void);
    fn guard_xpc_server_run(server: *mut c_void);
    fn guard_xpc_server_destroy(server: *mut c_void);
    fn guard_xpc_request(
        service_name: *const c_char,
        server_code_signing_requirement: *const c_char,
        request: *const u8,
        request_length: usize,
        timeout_milliseconds: u64,
        response: *mut *mut u8,
        response_length: *mut usize,
        error_buffer: *mut c_char,
        error_buffer_length: usize,
    ) -> bool;
    fn guard_xpc_bytes_free(bytes: *mut u8);
    fn guard_code_signing_requirement_is_valid(
        requirement: *const c_char,
        error_buffer: *mut c_char,
        error_buffer_length: usize,
    ) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_ipc::{RequestOp, ResponseBody, StatusInfo};

    struct StatusHandler;

    impl XpcRequestHandler for StatusHandler {
        fn handle(&self, peer: AuthenticatedPeer, _request: Request) -> Response {
            Response::ok(ResponseBody::Status(Box::new(StatusInfo {
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
                protected_events: 0,
                fanotify_overflows: None,
                classifier_failures: None,
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
                peer_uid: peer.euid,
            })))
        }
    }

    #[test]
    fn exact_client_identifiers_and_team_are_in_requirement() {
        let requirements = SigningRequirements::new(
            "ABCDE12345",
            "io.example.Guard",
            "io.example.Guard.guard-es",
        )
        .unwrap();
        assert!(requirements
            .client_requirement
            .contains("identifier \"io.example.Guard\""));
        assert!(requirements
            .client_requirement
            .contains("identifier \"io.example.Guard.guardctl\""));
        assert!(requirements
            .client_requirement
            .contains("identifier \"io.example.Guard.guard-notify\""));
        assert!(requirements.client_requirement.contains("ABCDE12345"));
        assert!(requirements
            .server_requirement
            .contains("io.example.Guard.guard-es"));
    }

    #[test]
    fn requirement_atoms_reject_injection() {
        assert!(SigningRequirements::new(
            "ABCDE12345\" or true",
            "io.example.Guard",
            "io.example.Guard.guard-es"
        )
        .is_err());
    }

    #[test]
    fn guard_ipc_handler_uses_transport_euid_and_checks_version() {
        let handler = GuardIpcHandler::new(StatusHandler);
        let bytes = serde_json::to_vec(&Request {
            version: PROTOCOL_VERSION,
            op: RequestOp::Status,
        })
        .unwrap();
        let response: Response =
            serde_json::from_slice(&handler.handle_bytes(502, &bytes)).unwrap();
        let Some(ResponseBody::Status(status)) = response.body else {
            panic!("expected status response");
        };
        assert_eq!(status.peer_uid, 502);

        let wrong = serde_json::to_vec(&Request {
            version: PROTOCOL_VERSION + 1,
            op: RequestOp::Status,
        })
        .unwrap();
        let response: Response =
            serde_json::from_slice(&handler.handle_bytes(502, &wrong)).unwrap();
        assert!(!response.ok);
        assert_eq!(
            response.error.as_deref(),
            Some("unsupported_protocol_version")
        );
    }

    #[test]
    fn malformed_request_fails_closed() {
        let handler = GuardIpcHandler::new(StatusHandler);
        let response: Response =
            serde_json::from_slice(&handler.handle_bytes(502, b"not-json")).unwrap();
        assert!(!response.ok);
        assert_eq!(response.error.as_deref(), Some("malformed_request"));
    }

    #[test]
    fn peer_policy_requires_an_explicit_euid() {
        let context = ServerContext {
            allowed_uids: BTreeSet::from([502]),
            handler: Arc::new(GuardIpcHandler::new(StatusHandler)),
        };
        let pointer = (&context as *const ServerContext).cast_mut().cast();
        assert!(peer_callback(502, pointer));
        assert!(!peer_callback(501, pointer));
        assert!(!peer_callback(0, pointer));
    }

    #[test]
    fn same_uid_or_same_team_alone_cannot_self_approve() {
        let policy = ClientSigningPolicy::new(
            [502],
            MacSigningIdentity::AppleTeam {
                team_id: "ABCDE12345".into(),
            },
            "io.example.Guard",
        )
        .unwrap();
        assert!(policy.allows(&PeerSigningFacts {
            euid: 502,
            code_valid: true,
            team_id: Some("ABCDE12345"),
            signing_id: Some("io.example.Guard"),
            leaf_certificate_sha1: None,
        }));
        assert!(!policy.allows(&PeerSigningFacts {
            euid: 502,
            code_valid: false,
            team_id: None,
            signing_id: None,
            leaf_certificate_sha1: None,
        }));
        assert!(!policy.allows(&PeerSigningFacts {
            euid: 502,
            code_valid: true,
            team_id: Some("WRONG12345"),
            signing_id: Some("io.example.Guard"),
            leaf_certificate_sha1: None,
        }));
        assert!(!policy.allows(&PeerSigningFacts {
            euid: 502,
            code_valid: true,
            team_id: Some("ABCDE12345"),
            signing_id: Some("io.example.UnlistedHelper"),
            leaf_certificate_sha1: None,
        }));
        assert!(!policy.allows(&PeerSigningFacts {
            euid: 501,
            code_valid: true,
            team_id: Some("ABCDE12345"),
            signing_id: Some("io.example.Guard"),
            leaf_certificate_sha1: None,
        }));
    }

    #[test]
    fn local_certificate_still_requires_exact_certificate_and_identifier() {
        let certificate = "0123456789ABCDEF0123456789ABCDEF01234567";
        let policy = ClientSigningPolicy::new(
            [502],
            MacSigningIdentity::LocalCertificate {
                leaf_certificate_sha1: certificate.into(),
            },
            "io.example.Guard",
        )
        .unwrap();
        assert!(policy.allows(&PeerSigningFacts {
            euid: 502,
            code_valid: true,
            team_id: None,
            signing_id: Some("io.example.Guard.guardctl"),
            leaf_certificate_sha1: Some(certificate),
        }));
        assert!(!policy.allows(&PeerSigningFacts {
            euid: 502,
            code_valid: true,
            team_id: None,
            signing_id: Some("io.example.Guard.guardctl"),
            leaf_certificate_sha1: Some("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        }));
        assert!(!policy.allows(&PeerSigningFacts {
            euid: 502,
            code_valid: true,
            team_id: None,
            signing_id: Some("io.example.UnlistedHelper"),
            leaf_certificate_sha1: Some(certificate),
        }));
    }

    #[test]
    fn local_certificate_requirements_compile_in_security_framework() {
        let requirements = SigningRequirements::for_local_certificate(
            "0123456789ABCDEF0123456789ABCDEF01234567",
            "io.example.Guard",
            "io.example.Guard.guard-es",
        )
        .unwrap();
        assert!(requirements
            .client_requirement
            .contains("certificate leaf = H\"0123456789ABCDEF0123456789ABCDEF01234567\""));
        assert!(requirements
            .server_requirement
            .contains("io.example.Guard.guard-es"));
    }
}
