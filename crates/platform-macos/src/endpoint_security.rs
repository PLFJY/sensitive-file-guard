use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock, Weak};
use std::time::Duration;

use guard_core::resource::{
    BrowserId, ProfileId, ProtectedResource, ProtectedResourceId, ProtectedResourceKind,
};
use guard_platform::BackendHealth;

use crate::identity::{
    AuditProcessKey, ExecutableSnapshot, MacCodeIdentity, MacProcessFacts, MacProcessGraph,
};
use crate::pending::{
    DeadlineScheduler, DeadlineSchedulerHandle, HealthTracker, PendingInner, ResponseCode,
    ResponseSink,
};
pub use crate::pending::{
    MacPendingPermission, ReadOnlyMacPendingPermission, ES_FFLAG_READ, ES_FFLAG_WRITE,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthOpenFacts {
    /// Kernel FFLAGS requested by AUTH_OPEN. These are deliberately not POSIX
    /// `open(2)` O_* flags.
    pub requested_fflags: u32,
    pub process: MacProcessFacts,
    pub target: PathBuf,
    pub target_dev: u64,
    pub target_ino: u64,
}

pub struct MacAuthorizationEvent {
    pub facts: AuthOpenFacts,
    pub resource: ProtectedResource,
    /// Human-interaction lifetime after applying the ES safety margin and
    /// product prompt cap. `None` means the event must not be prompted.
    pub interactive_budget: Option<Duration>,
    pub permission: MacPendingPermission,
}

#[derive(Debug)]
pub struct MacProtectedResources {
    enabled: AtomicBool,
    index: RwLock<crate::resource_index::MacResourceIndex>,
}

impl MacProtectedResources {
    pub fn new(enabled: bool, index: crate::resource_index::MacResourceIndex) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            index: RwLock::new(index),
        }
    }

    pub fn replace(
        &self,
        enabled: bool,
        index: crate::resource_index::MacResourceIndex,
    ) -> anyhow::Result<()> {
        *self
            .index
            .write()
            .map_err(|_| anyhow::anyhow!("macOS resource index lock is poisoned"))? = index;
        self.enabled.store(enabled, Ordering::Release);
        Ok(())
    }

    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    pub fn counts(&self) -> (usize, usize) {
        let index = self
            .index
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (index.concrete_count(), index.tree_root_count())
    }

    pub fn ssh_key_count(&self) -> usize {
        self.index
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .ssh_key_count()
    }

    pub fn is_configured_ssh_resource(&self, resource: &ProtectedResource) -> bool {
        self.index
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_configured_ssh_resource(resource)
    }

    pub fn metadata_snapshot(&self) -> (Vec<ProtectedResource>, Vec<guard_browser::TreeRoot>) {
        let index = self
            .index
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (
            index.resources().cloned().collect(),
            index.trees().cloned().collect(),
        )
    }

    fn classify(&self, facts: &AuthOpenFacts) -> Option<ProtectedResource> {
        if !self.enabled() {
            return None;
        }
        self.index
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .classify(
                &facts.target,
                crate::resource_index::FileIdentity {
                    dev: facts.target_dev,
                    ino: facts.target_ino,
                },
            )
    }
}

#[derive(Debug, Clone)]
pub struct EndpointSecurityConfig {
    scope: ProtectionScope,
}

#[derive(Debug, Clone)]
enum ProtectionScope {
    Synthetic(HashSet<PathBuf>),
    Browser(Arc<MacProtectedResources>),
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
            scope: ProtectionScope::Synthetic(protected_exact_paths),
        })
    }

    pub fn browser(resources: Arc<MacProtectedResources>) -> Self {
        Self {
            scope: ProtectionScope::Browser(resources),
        }
    }

    fn classify(&self, facts: &AuthOpenFacts) -> Option<ProtectedResource> {
        match &self.scope {
            ProtectionScope::Synthetic(paths) if paths.contains(&facts.target) => {
                Some(ProtectedResource {
                    id: ProtectedResourceId(facts.target.to_string_lossy().into_owned()),
                    kind: ProtectedResourceKind::CookieStore,
                    owner_uid: facts.process.uid,
                    browser: Some(BrowserId("synthetic".into())),
                    profile: Some(ProfileId("fixture".into())),
                    path: facts.target.clone(),
                })
            }
            ProtectionScope::Synthetic(_) => None,
            ProtectionScope::Browser(resources) => resources.classify(facts),
        }
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
        let process_graph = Arc::new(Mutex::new(MacProcessGraph::default()));
        let mut context = Box::new(CallbackContext {
            config,
            sender,
            scheduler: scheduler_handle,
            registry,
            process_graph,
            health,
        });
        let client = NativeClient::create(context.as_mut() as *mut CallbackContext)?;
        if client.subscribe_required().is_err() {
            context
                .health
                .degrade("Endpoint Security AUTH_OPEN/process subscription failed");
            return Err(ClientCreateError::Internal);
        }
        context
            .health
            .note("Endpoint Security AUTH_OPEN and bounded process graph subscriptions are active");
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

    pub fn process_graph(&self) -> Arc<Mutex<MacProcessGraph>> {
        Arc::clone(&self.context.process_graph)
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
    let client = NativeClient::create_with_callback(
        diagnostic_callback,
        diagnostic_process_callback,
        (&mut marker as *mut ()).cast(),
    )?;
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
    process_graph: Arc<Mutex<MacProcessGraph>>,
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
        if let Err(error) = self
            .process_graph
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .observe(facts.process.clone(), std::time::Instant::now())
        {
            self.health.note(format!(
                "AUTH_OPEN failed closed because process identity could not be graphed: {error}"
            ));
            self.respond_immediate(client, message, 0);
            return;
        }
        let Some(resource) = self.config.classify(&facts) else {
            self.respond_immediate(client, message, facts.requested_fflags);
            return;
        };
        let response_budget =
            match crate::deadline::response_budget(&crate::deadline::DarwinClock, raw.deadline) {
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
        if let Err(error) = self.scheduler.schedule(weak, response_budget) {
            self.health.degrade(format!(
                "protected AUTH_OPEN failed closed because its timer could not be scheduled: {error}"
            ));
            drop(permission);
            return;
        }
        if self
            .sender
            .send(MacAuthorizationEvent {
                facts,
                resource,
                interactive_budget: crate::deadline::interactive_budget(
                    &crate::deadline::DarwinClock,
                    raw.deadline,
                )
                .ok(),
                permission,
            })
            .is_err()
        {
            self.health.degrade(
                "protected AUTH_OPEN failed closed because the authorization queue is unavailable",
            );
        }
    }

    fn handle_process_event(
        &self,
        event_kind: u32,
        process: &RawProcessFacts,
        related: Option<&RawProcessFacts>,
    ) {
        let process = match process.to_facts() {
            Ok(process) => process,
            Err(error) => {
                self.health
                    .degrade(format!("process graph event was invalid: {error}"));
                return;
            }
        };
        let now = std::time::Instant::now();
        let mut graph = self
            .process_graph
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let result = match event_kind {
            1 => {
                let parent_result = related
                    .ok_or_else(|| anyhow::anyhow!("fork event omitted parent process"))
                    .and_then(RawProcessFacts::to_facts)
                    .and_then(|parent| graph.observe(parent, now));
                parent_result.and_then(|()| graph.observe(process, now))
            }
            2 => graph.observe(process, now),
            3 => {
                graph.remove_terminal(process.key);
                Ok(())
            }
            _ => Err(anyhow::anyhow!("unknown process event kind {event_kind}")),
        };
        if let Err(error) = result {
            self.health
                .degrade(format!("process graph update failed: {error}"));
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
        Self::create_with_callback(auth_open_callback, process_callback, context.cast())
    }

    fn create_with_callback(
        callback: RawCallback,
        process_callback: RawProcessCallback,
        context: *mut std::ffi::c_void,
    ) -> Result<Self, ClientCreateError> {
        let mut raw = std::ptr::null_mut();
        // SAFETY: context remains live in EndpointSecurityBackend for the
        // complete client lifetime; the C wrapper copies the callback block.
        let result =
            unsafe { guard_es_client_create(&mut raw, callback, process_callback, context) };
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

    fn subscribe_required(&self) -> anyhow::Result<()> {
        // SAFETY: raw is a live guard_es_client_t owned by self.
        anyhow::ensure!(
            unsafe { guard_es_client_subscribe_required(self.raw) } == 0,
            "es_subscribe(AUTH_OPEN/FORK/EXEC/EXIT) failed"
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
    target_dev: u64,
    target_ino: u64,
    target_path: *const u8,
    target_path_len: usize,
    target_path_truncated: bool,
    process: RawProcessFacts,
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct RawProcessFacts {
    pid: i32,
    uid: u32,
    gid: u32,
    pidversion: i32,
    parent_pid: i32,
    parent_pidversion: i32,
    parent_identity_available: bool,
    responsible_pid: i32,
    responsible_pidversion: i32,
    responsible_identity_available: bool,
    start_time_us: u64,
    executable_dev: u64,
    executable_ino: u64,
    executable_mode: u32,
    executable_owner_uid: u32,
    executable_size: u64,
    executable_mtime_ns: i64,
    executable_ctime_ns: i64,
    executable_path: *const u8,
    executable_path_len: usize,
    executable_path_truncated: bool,
    code_signing_flags: u32,
    code_signing_valid: bool,
    platform_binary: bool,
    team_id: *const u8,
    team_id_len: usize,
    signing_id: *const u8,
    signing_id_len: usize,
    cdhash: [u8; 20],
}

#[cfg(target_os = "macos")]
impl RawAuthOpenEvent {
    fn to_facts(&self) -> anyhow::Result<AuthOpenFacts> {
        anyhow::ensure!(
            !self.target_path_truncated,
            "Endpoint Security supplied a truncated target path"
        );
        anyhow::ensure!(
            self.target_dev != 0 && self.target_ino != 0,
            "Endpoint Security supplied incomplete target file identity"
        );
        Ok(AuthOpenFacts {
            requested_fflags: self.requested_flags,
            process: self.process.to_facts()?,
            target: token_path(self.target_path, self.target_path_len)?,
            target_dev: self.target_dev,
            target_ino: self.target_ino,
        })
    }
}

#[cfg(target_os = "macos")]
impl RawProcessFacts {
    fn to_facts(&self) -> anyhow::Result<MacProcessFacts> {
        anyhow::ensure!(self.pid > 0, "invalid or missing process PID");
        anyhow::ensure!(self.pidversion >= 0, "invalid process PID version");
        anyhow::ensure!(self.start_time_us > 0, "missing ES process start time");
        anyhow::ensure!(
            !self.executable_path_truncated,
            "Endpoint Security supplied a truncated executable path"
        );
        anyhow::ensure!(
            self.executable_dev != 0 && self.executable_ino != 0,
            "Endpoint Security supplied incomplete executable identity"
        );
        let facts = MacProcessFacts {
            key: AuditProcessKey {
                pid: self.pid as u32,
                pidversion: self.pidversion as u32,
            },
            uid: self.uid,
            gid: self.gid,
            start_time_us: self.start_time_us,
            executable: ExecutableSnapshot {
                path: token_path(self.executable_path, self.executable_path_len)?,
                dev: self.executable_dev,
                ino: self.executable_ino,
                owner_uid: self.executable_owner_uid,
                mode: self.executable_mode,
                size: self.executable_size,
                mtime_ns: self.executable_mtime_ns,
                ctime_ns: self.executable_ctime_ns,
            },
            code: MacCodeIdentity {
                valid: self.code_signing_valid,
                platform_binary: self.platform_binary,
                flags: self.code_signing_flags,
                team_id: token_optional_string(self.team_id, self.team_id_len)?,
                signing_id: token_optional_string(self.signing_id, self.signing_id_len)?,
                cdhash: self.cdhash,
            },
            parent: audit_key(
                self.parent_identity_available,
                self.parent_pid,
                self.parent_pidversion,
            )?,
            responsible: audit_key(
                self.responsible_identity_available,
                self.responsible_pid,
                self.responsible_pidversion,
            )?,
        };
        facts.validate()?;
        Ok(facts)
    }
}

#[cfg(target_os = "macos")]
fn audit_key(
    available: bool,
    pid: i32,
    pidversion: i32,
) -> anyhow::Result<Option<AuditProcessKey>> {
    if !available || pid <= 1 {
        return Ok(None);
    }
    anyhow::ensure!(pidversion >= 0, "invalid parent/responsible PID version");
    Ok(Some(AuditProcessKey {
        pid: pid as u32,
        pidversion: pidversion as u32,
    }))
}

#[cfg(target_os = "macos")]
fn token_optional_string(pointer: *const u8, length: usize) -> anyhow::Result<Option<String>> {
    if length == 0 {
        return Ok(None);
    }
    anyhow::ensure!(!pointer.is_null(), "missing signing token");
    // SAFETY: the token is copied synchronously while the ES message is live.
    let bytes = unsafe { std::slice::from_raw_parts(pointer, length) };
    Ok(Some(std::str::from_utf8(bytes)?.to_owned()))
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
type RawProcessCallback = unsafe extern "C" fn(
    *mut std::ffi::c_void,
    u32,
    *const RawProcessFacts,
    *const RawProcessFacts,
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
unsafe extern "C" fn process_callback(
    context: *mut std::ffi::c_void,
    event_kind: u32,
    process: *const RawProcessFacts,
    related: *const RawProcessFacts,
) {
    // SAFETY: callback pointers and context are owned by the live C shim call.
    let context = unsafe { &*context.cast::<CallbackContext>() };
    if process.is_null() {
        context
            .health
            .degrade("process callback omitted process facts");
        return;
    }
    // SAFETY: non-null normalized structs live for this callback only.
    let process = unsafe { &*process };
    let related = if related.is_null() {
        None
    } else {
        // SAFETY: checked non-null and copied only during this callback.
        Some(unsafe { &*related })
    };
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        context.handle_process_event(event_kind, process, related);
    }))
    .is_err()
    {
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
unsafe extern "C" fn diagnostic_process_callback(
    _context: *mut std::ffi::c_void,
    _event_kind: u32,
    _process: *const RawProcessFacts,
    _related: *const RawProcessFacts,
) {
}

#[cfg(target_os = "macos")]
extern "C" {
    fn guard_es_client_create(
        client: *mut *mut std::ffi::c_void,
        callback: RawCallback,
        process_callback: RawProcessCallback,
        context: *mut std::ffi::c_void,
    ) -> i32;
    fn guard_es_client_subscribe_required(client: *mut std::ffi::c_void) -> i32;
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
