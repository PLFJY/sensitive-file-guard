use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex, Weak};
use std::time::Duration;

use guard_platform::BackendHealth;

pub use crate::pending::MacPendingPermission;
use crate::pending::{
    DeadlineScheduler, DeadlineSchedulerHandle, HealthTracker, PendingInner, ResponseCode,
    ResponseSink,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthOpenFacts {
    /// Kernel FFLAGS requested by AUTH_OPEN. These are deliberately not POSIX
    /// `open(2)` O_* flags.
    pub requested_fflags: u32,
    pub pid: u32,
    pub uid: u32,
    pub pidversion: u32,
    pub target: PathBuf,
    pub target_dev: u64,
    pub target_ino: u64,
    pub executable: PathBuf,
    pub executable_dev: u64,
    pub executable_ino: u64,
}

pub struct MacAuthorizationEvent {
    pub facts: AuthOpenFacts,
    pub permission: MacPendingPermission,
}

#[derive(Debug, Clone)]
pub struct EndpointSecurityConfig {
    protected_exact_paths: HashSet<PathBuf>,
}

impl EndpointSecurityConfig {
    pub fn synthetic_exact_paths(paths: impl IntoIterator<Item = PathBuf>) -> anyhow::Result<Self> {
        let mut protected_exact_paths = HashSet::new();
        for path in paths {
            anyhow::ensure!(path.is_absolute(), "protected test path must be absolute");
            protected_exact_paths.insert(std::fs::canonicalize(&path).map_err(|error| {
                anyhow::anyhow!(
                    "cannot canonicalize protected synthetic fixture {}: {error}",
                    path.display()
                )
            })?);
        }
        anyhow::ensure!(
            !protected_exact_paths.is_empty(),
            "at least one synthetic protected path is required"
        );
        Ok(Self {
            protected_exact_paths,
        })
    }

    fn protects(&self, path: &Path) -> bool {
        self.protected_exact_paths.contains(path)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientCreateError {
    InvalidArgument,
    Internal,
    NotEntitled,
    NotPermitted,
    NotPrivileged,
    TooManyClients,
    Unknown(i32),
    UnsupportedPlatform,
}

impl std::fmt::Display for ClientCreateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidArgument => "Endpoint Security rejected an invalid client argument",
            Self::Internal => "Endpoint Security client creation failed internally",
            Self::NotEntitled => {
                "Endpoint Security client entitlement is missing or not authorized by provisioning"
            }
            Self::NotPermitted => "Endpoint Security client lacks TCC Full Disk Access permission",
            Self::NotPrivileged => {
                "Endpoint Security client is not running with required privilege"
            }
            Self::TooManyClients => "Endpoint Security client limit has been reached",
            Self::UnsupportedPlatform => "Endpoint Security is available only on macOS",
            Self::Unknown(_) => "Endpoint Security returned an unknown client creation result",
        };
        if let Self::Unknown(value) = self {
            write!(formatter, "{message}: {value}")
        } else {
            formatter.write_str(message)
        }
    }
}

impl std::error::Error for ClientCreateError {}

#[cfg(target_os = "macos")]
pub struct EndpointSecurityBackend {
    // The scheduler is shut down while the ES client is still live so every
    // retained message receives a terminal deny before client deletion.
    scheduler: DeadlineScheduler,
    client: Option<NativeClient>,
    context: Box<CallbackContext>,
    receiver: mpsc::Receiver<MacAuthorizationEvent>,
}

#[cfg(target_os = "macos")]
impl EndpointSecurityBackend {
    pub fn start(config: EndpointSecurityConfig) -> Result<Self, ClientCreateError> {
        let health = Arc::new(HealthTracker::active(
            "Endpoint Security client initialization is pending",
        ));
        let (scheduler, scheduler_handle) = DeadlineScheduler::start().map_err(|_| {
            health.degrade("could not start Endpoint Security deadline scheduler");
            ClientCreateError::Internal
        })?;
        let (sender, receiver) = mpsc::channel();
        let registry = Arc::new(Mutex::new(Vec::new()));
        let mut context = Box::new(CallbackContext {
            config,
            sender,
            scheduler: scheduler_handle,
            registry,
            health,
        });
        let client = NativeClient::create(context.as_mut() as *mut CallbackContext)?;
        if client.subscribe_auth_open().is_err() {
            context
                .health
                .degrade("Endpoint Security AUTH_OPEN subscription failed");
            return Err(ClientCreateError::Internal);
        }
        context
            .health
            .note("Endpoint Security AUTH_OPEN subscription is active");
        Ok(Self {
            scheduler,
            client: Some(client),
            context,
            receiver,
        })
    }

    pub fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<MacAuthorizationEvent, mpsc::RecvTimeoutError> {
        self.receiver.recv_timeout(timeout)
    }

    pub fn health(&self) -> BackendHealth {
        let (active, diagnostic) = self.context.health.snapshot();
        BackendHealth {
            backend: "endpoint-security".to_owned(),
            active,
            diagnostic,
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for EndpointSecurityBackend {
    fn drop(&mut self) {
        self.scheduler.shutdown();
        deny_registered(&self.context.registry);
        if let Some(client) = self.client.take() {
            drop(client);
        }
        self.context
            .health
            .stop("Endpoint Security client is stopped");
    }
}

#[cfg(target_os = "macos")]
pub fn diagnose_client_creation() -> Result<(), ClientCreateError> {
    let mut marker = ();
    let client =
        NativeClient::create_with_callback(diagnostic_callback, (&mut marker as *mut ()).cast())?;
    drop(client);
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn diagnose_client_creation() -> Result<(), ClientCreateError> {
    Err(ClientCreateError::UnsupportedPlatform)
}

#[cfg(target_os = "macos")]
struct CallbackContext {
    config: EndpointSecurityConfig,
    sender: mpsc::Sender<MacAuthorizationEvent>,
    scheduler: DeadlineSchedulerHandle,
    registry: Arc<Mutex<Vec<Weak<PendingInner>>>>,
    health: Arc<HealthTracker>,
}

#[cfg(target_os = "macos")]
impl CallbackContext {
    fn handle(
        &self,
        client: *const std::ffi::c_void,
        message: *const std::ffi::c_void,
        raw: &RawAuthOpenEvent,
    ) {
        let facts = match raw.to_facts() {
            Ok(facts) => facts,
            Err(error) => {
                self.health.note(format!(
                    "AUTH_OPEN failed closed during normalization: {error}"
                ));
                self.respond_immediate(client, message, 0);
                return;
            }
        };
        if !self.config.protects(&facts.target) {
            self.respond_immediate(client, message, facts.requested_fflags);
            return;
        }
        let budget = match crate::deadline::interactive_budget(
            &crate::deadline::DarwinClock,
            raw.deadline,
        ) {
            Ok(budget) => budget,
            Err(error) => {
                self.health
                    .note(format!("protected AUTH_OPEN failed closed: {error}"));
                self.respond_immediate(client, message, 0);
                return;
            }
        };

        // SAFETY: the ES message is live for this callback. Retaining it before
        // returning transfers one release obligation to RawResponseSink.
        unsafe { guard_es_message_retain(message) };
        let responder = Box::new(RawResponseSink {
            client: client as usize,
            message: message as usize,
        });
        let (permission, weak) =
            MacPendingPermission::new(facts.requested_fflags, responder, Arc::clone(&self.health));
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        registry.retain(|registered| {
            registered
                .upgrade()
                .is_some_and(|permission| !permission.is_terminal())
        });
        registry.push(weak.clone());
        drop(registry);
        if let Err(error) = self.scheduler.schedule(weak, budget) {
            self.health.degrade(format!(
                "protected AUTH_OPEN failed closed because its timer could not be scheduled: {error}"
            ));
            drop(permission);
            return;
        }
        if self
            .sender
            .send(MacAuthorizationEvent { facts, permission })
            .is_err()
        {
            self.health.degrade(
                "protected AUTH_OPEN failed closed because the authorization queue is unavailable",
            );
        }
    }

    fn respond_immediate(
        &self,
        client: *const std::ffi::c_void,
        message: *const std::ffi::c_void,
        authorized_flags: u32,
    ) {
        // SAFETY: both opaque pointers are supplied together by the active ES
        // callback, and the C shim hardcodes cache=false.
        let result = unsafe { guard_es_respond_flags(client, message, authorized_flags) };
        let result = ResponseCode::from_raw(result);
        if result != ResponseCode::Success {
            self.health.degrade(format!(
                "immediate Endpoint Security flags response failed: {result}"
            ));
        }
    }
}

#[cfg(target_os = "macos")]
fn deny_registered(registry: &Mutex<Vec<Weak<PendingInner>>>) {
    let pending = registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .drain(..)
        .collect::<Vec<_>>();
    for permission in pending {
        if let Some(permission) = permission.upgrade() {
            let _ = permission.resolve(false);
        }
    }
}

#[cfg(target_os = "macos")]
struct RawResponseSink {
    client: usize,
    message: usize,
}

#[cfg(target_os = "macos")]
impl ResponseSink for RawResponseSink {
    fn respond(&self, authorized_flags: u32) -> ResponseCode {
        // SAFETY: the client outlives every registered pending response, and
        // the retained message remains live until this sink releases it.
        ResponseCode::from_raw(unsafe {
            guard_es_respond_flags(
                self.client as *const std::ffi::c_void,
                self.message as *const std::ffi::c_void,
                authorized_flags,
            )
        })
    }

    fn release(&self) {
        // SAFETY: MacPendingPermission guarantees this is called exactly once
        // for the retain performed when the deferred request was constructed.
        unsafe { guard_es_message_release(self.message as *const std::ffi::c_void) };
    }
}

impl ResponseCode {
    #[cfg(target_os = "macos")]
    fn from_raw(raw: i32) -> Self {
        match raw {
            0 => Self::Success,
            1 => Self::InvalidArgument,
            2 => Self::Internal,
            3 => Self::NotFound,
            4 => Self::Duplicate,
            5 => Self::WrongEventType,
            value => Self::Unknown(value),
        }
    }
}

#[cfg(target_os = "macos")]
struct NativeClient {
    raw: *mut std::ffi::c_void,
    // es_delete_client must run on the thread that called es_new_client.
    _not_send: std::marker::PhantomData<std::rc::Rc<()>>,
}

#[cfg(target_os = "macos")]
impl NativeClient {
    fn create(context: *mut CallbackContext) -> Result<Self, ClientCreateError> {
        Self::create_with_callback(auth_open_callback, context.cast())
    }

    fn create_with_callback(
        callback: RawCallback,
        context: *mut std::ffi::c_void,
    ) -> Result<Self, ClientCreateError> {
        let mut raw = std::ptr::null_mut();
        // SAFETY: context remains live in EndpointSecurityBackend for the
        // complete client lifetime; the C wrapper copies the callback block.
        let result = unsafe { guard_es_client_create(&mut raw, callback, context) };
        match result {
            0 => Ok(Self {
                raw,
                _not_send: std::marker::PhantomData,
            }),
            1 => Err(ClientCreateError::InvalidArgument),
            2 => Err(ClientCreateError::Internal),
            3 => Err(ClientCreateError::NotEntitled),
            4 => Err(ClientCreateError::NotPermitted),
            5 => Err(ClientCreateError::NotPrivileged),
            6 => Err(ClientCreateError::TooManyClients),
            value => Err(ClientCreateError::Unknown(value)),
        }
    }

    fn subscribe_auth_open(&self) -> anyhow::Result<()> {
        // SAFETY: raw is a live guard_es_client_t owned by self.
        anyhow::ensure!(
            unsafe { guard_es_client_subscribe_auth_open(self.raw) } == 0,
            "es_subscribe(AUTH_OPEN) failed"
        );
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl Drop for NativeClient {
    fn drop(&mut self) {
        // SAFETY: NativeClient is !Send and therefore drops on its creator
        // thread; the wrapper is consumed exactly once here.
        let _ = unsafe { guard_es_client_delete(self.raw) };
    }
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct RawAuthOpenEvent {
    requested_flags: u32,
    deadline: u64,
    pid: i32,
    uid: u32,
    pidversion: i32,
    target_dev: u64,
    target_ino: u64,
    target_path: *const u8,
    target_path_len: usize,
    target_path_truncated: bool,
    executable_dev: u64,
    executable_ino: u64,
    executable_path: *const u8,
    executable_path_len: usize,
    executable_path_truncated: bool,
}

#[cfg(target_os = "macos")]
impl RawAuthOpenEvent {
    fn to_facts(&self) -> anyhow::Result<AuthOpenFacts> {
        anyhow::ensure!(self.pid > 0, "invalid or missing process PID");
        anyhow::ensure!(self.pidversion >= 0, "invalid process PID version");
        anyhow::ensure!(
            !self.target_path_truncated && !self.executable_path_truncated,
            "Endpoint Security supplied a truncated path"
        );
        anyhow::ensure!(
            self.target_dev != 0
                && self.target_ino != 0
                && self.executable_dev != 0
                && self.executable_ino != 0,
            "Endpoint Security supplied incomplete file identity"
        );
        Ok(AuthOpenFacts {
            requested_fflags: self.requested_flags,
            pid: self.pid as u32,
            uid: self.uid,
            pidversion: self.pidversion as u32,
            target: token_path(self.target_path, self.target_path_len)?,
            target_dev: self.target_dev,
            target_ino: self.target_ino,
            executable: token_path(self.executable_path, self.executable_path_len)?,
            executable_dev: self.executable_dev,
            executable_ino: self.executable_ino,
        })
    }
}

#[cfg(target_os = "macos")]
fn token_path(pointer: *const u8, length: usize) -> anyhow::Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt;

    anyhow::ensure!(!pointer.is_null() || length == 0, "missing path token");
    // SAFETY: the token is supplied by ES and copied synchronously while the
    // callback's es_message_t is live.
    let bytes = unsafe { std::slice::from_raw_parts(pointer, length) };
    anyhow::ensure!(!bytes.is_empty(), "empty path token");
    Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec())))
}

#[cfg(target_os = "macos")]
type RawCallback = unsafe extern "C" fn(
    *mut std::ffi::c_void,
    *const std::ffi::c_void,
    *const std::ffi::c_void,
    *const RawAuthOpenEvent,
);

#[cfg(target_os = "macos")]
unsafe extern "C" fn auth_open_callback(
    context: *mut std::ffi::c_void,
    client: *const std::ffi::c_void,
    message: *const std::ffi::c_void,
    event: *const RawAuthOpenEvent,
) {
    // SAFETY: NativeClient was created with a pointer to the boxed context,
    // which remains stable until after es_delete_client returns.
    let context = unsafe { &*context.cast::<CallbackContext>() };
    if event.is_null() {
        context
            .health
            .degrade("received an unexpected non-AUTH_OPEN Endpoint Security message");
        return;
    }
    // SAFETY: the C shim owns normalized on its callback stack and it remains
    // live for this synchronous Rust call.
    let event = unsafe { &*event };
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        context.handle(client, message, event);
    }))
    .is_err()
    {
        // Unwinding across the C callback boundary is undefined. An abort is
        // preferable to continuing with unknown response/message ownership.
        std::process::abort();
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn diagnostic_callback(
    _context: *mut std::ffi::c_void,
    client: *const std::ffi::c_void,
    message: *const std::ffi::c_void,
    event: *const RawAuthOpenEvent,
) {
    if !event.is_null() {
        // SAFETY: an unexpected event is still live inside its ES callback;
        // deny it with cache disabled before returning.
        let _ = unsafe { guard_es_respond_flags(client, message, 0) };
    }
}

#[cfg(target_os = "macos")]
extern "C" {
    fn guard_es_client_create(
        client: *mut *mut std::ffi::c_void,
        callback: RawCallback,
        context: *mut std::ffi::c_void,
    ) -> i32;
    fn guard_es_client_subscribe_auth_open(client: *mut std::ffi::c_void) -> i32;
    fn guard_es_client_delete(client: *mut std::ffi::c_void) -> i32;
    fn guard_es_message_retain(message: *const std::ffi::c_void);
    fn guard_es_message_release(message: *const std::ffi::c_void);
    fn guard_es_respond_flags(
        client: *const std::ffi::c_void,
        message: *const std::ffi::c_void,
        authorized_flags: u32,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_config_requires_existing_absolute_paths() {
        assert!(
            EndpointSecurityConfig::synthetic_exact_paths([PathBuf::from("relative")]).is_err()
        );
        assert!(EndpointSecurityConfig::synthetic_exact_paths(Vec::<PathBuf>::new()).is_err());
    }

    #[test]
    fn client_creation_errors_have_actionable_diagnostics() {
        assert!(ClientCreateError::NotEntitled
            .to_string()
            .contains("entitlement"));
        assert!(ClientCreateError::NotPermitted
            .to_string()
            .contains("Full Disk Access"));
        assert!(ClientCreateError::TooManyClients
            .to_string()
            .contains("limit"));
    }
}
