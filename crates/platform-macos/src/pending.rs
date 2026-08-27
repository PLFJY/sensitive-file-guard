use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{mpsc, Arc, Mutex, Weak};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use guard_platform::PendingPermission;

/// Endpoint Security AUTH_OPEN FFLAGS from Darwin `<sys/fcntl.h>`. These are
/// kernel FFLAGS, deliberately not userspace `O_*` values.
pub const ES_FFLAG_READ: u32 = 0x0000_0001;
pub const ES_FFLAG_WRITE: u32 = 0x0000_0002;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResponseCode {
    Success,
    InvalidArgument,
    Internal,
    NotFound,
    Duplicate,
    WrongEventType,
    Unknown(i32),
}

impl std::fmt::Display for ResponseCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

pub(crate) trait ResponseSink: Send + Sync {
    fn respond(&self, authorized_flags: u32) -> ResponseCode;
    fn release(&self);
}

pub(crate) struct HealthTracker {
    active: AtomicBool,
    degraded: AtomicBool,
    diagnostic: Mutex<Option<String>>,
    sequence_gaps: AtomicU64,
    global_sequence_gaps: AtomicU64,
    pending_created: AtomicU64,
    pending_resolved_allow: AtomicU64,
    pending_resolved_deny: AtomicU64,
    pending_timed_out: AtomicU64,
    insufficient_deadline: AtomicU64,
    late_responses: AtomicU64,
    namespace_allowed: AtomicU64,
    namespace_denied: AtomicU64,
    authorization_events_delivered: AtomicU64,
    protected_authorization_events: AtomicU64,
    process_lifecycle_events: AtomicU64,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct HealthSnapshot {
    pub active: bool,
    pub degraded: bool,
    pub diagnostic: Option<String>,
    pub sequence_gaps: u64,
    pub global_sequence_gaps: u64,
    pub pending_created: u64,
    pub pending_resolved_allow: u64,
    pub pending_resolved_deny: u64,
    pub pending_timed_out: u64,
    pub insufficient_deadline: u64,
    pub late_responses: u64,
    pub namespace_allowed: u64,
    pub namespace_denied: u64,
    pub authorization_events_delivered: u64,
    pub protected_authorization_events: u64,
    pub process_lifecycle_events: u64,
}

impl HealthTracker {
    pub(crate) fn active(diagnostic: impl Into<String>) -> Self {
        Self {
            active: AtomicBool::new(true),
            degraded: AtomicBool::new(false),
            diagnostic: Mutex::new(Some(diagnostic.into())),
            sequence_gaps: AtomicU64::new(0),
            global_sequence_gaps: AtomicU64::new(0),
            pending_created: AtomicU64::new(0),
            pending_resolved_allow: AtomicU64::new(0),
            pending_resolved_deny: AtomicU64::new(0),
            pending_timed_out: AtomicU64::new(0),
            insufficient_deadline: AtomicU64::new(0),
            late_responses: AtomicU64::new(0),
            namespace_allowed: AtomicU64::new(0),
            namespace_denied: AtomicU64::new(0),
            authorization_events_delivered: AtomicU64::new(0),
            protected_authorization_events: AtomicU64::new(0),
            process_lifecycle_events: AtomicU64::new(0),
        }
    }

    pub(crate) fn note(&self, diagnostic: impl Into<String>) {
        *self.diagnostic.lock().expect("health diagnostic lock") = Some(diagnostic.into());
    }

    pub(crate) fn degrade(&self, diagnostic: impl Into<String>) {
        self.degraded.store(true, Ordering::Release);
        self.note(diagnostic);
    }

    pub(crate) fn stop(&self, diagnostic: impl Into<String>) {
        self.active.store(false, Ordering::Release);
        self.note(diagnostic);
    }

    pub(crate) fn snapshot(&self) -> HealthSnapshot {
        HealthSnapshot {
            active: self.active.load(Ordering::Acquire),
            degraded: self.degraded.load(Ordering::Acquire),
            diagnostic: self
                .diagnostic
                .lock()
                .expect("health diagnostic lock")
                .clone(),
            sequence_gaps: self.sequence_gaps.load(Ordering::Acquire),
            global_sequence_gaps: self.global_sequence_gaps.load(Ordering::Acquire),
            pending_created: self.pending_created.load(Ordering::Acquire),
            pending_resolved_allow: self.pending_resolved_allow.load(Ordering::Acquire),
            pending_resolved_deny: self.pending_resolved_deny.load(Ordering::Acquire),
            pending_timed_out: self.pending_timed_out.load(Ordering::Acquire),
            insufficient_deadline: self.insufficient_deadline.load(Ordering::Acquire),
            late_responses: self.late_responses.load(Ordering::Acquire),
            namespace_allowed: self.namespace_allowed.load(Ordering::Acquire),
            namespace_denied: self.namespace_denied.load(Ordering::Acquire),
            authorization_events_delivered: self
                .authorization_events_delivered
                .load(Ordering::Acquire),
            protected_authorization_events: self
                .protected_authorization_events
                .load(Ordering::Acquire),
            process_lifecycle_events: self.process_lifecycle_events.load(Ordering::Acquire),
        }
    }

    pub(crate) fn sequence_gap(&self, global: bool, count: u64) {
        self.sequence_gaps.fetch_add(count, Ordering::AcqRel);
        if global {
            self.global_sequence_gaps.fetch_add(count, Ordering::AcqRel);
        }
    }

    pub(crate) fn insufficient_deadline(&self) {
        self.insufficient_deadline.fetch_add(1, Ordering::AcqRel);
    }

    pub(crate) fn namespace_decision(&self, allow: bool) {
        if allow {
            self.namespace_allowed.fetch_add(1, Ordering::AcqRel);
        } else {
            self.namespace_denied.fetch_add(1, Ordering::AcqRel);
        }
    }

    pub(crate) fn authorization_event(&self, protected: bool) {
        self.authorization_events_delivered
            .fetch_add(1, Ordering::AcqRel);
        if protected {
            self.protected_authorization_events
                .fetch_add(1, Ordering::AcqRel);
        }
    }

    pub(crate) fn protected_authorization_event(&self) {
        self.protected_authorization_events
            .fetch_add(1, Ordering::AcqRel);
    }

    pub(crate) fn process_lifecycle_event(&self) {
        self.process_lifecycle_events.fetch_add(1, Ordering::AcqRel);
    }
}

pub struct MacPendingPermission {
    inner: Arc<PendingInner>,
}

pub(crate) struct PendingInner {
    // 0 = unresolved, 1 = allow won, 2 = deny won.
    terminal: AtomicU8,
    requested_flags: u32,
    responder: Mutex<Option<Box<dyn ResponseSink>>>,
    health: Arc<HealthTracker>,
}

impl MacPendingPermission {
    pub(crate) fn new(
        requested_flags: u32,
        responder: Box<dyn ResponseSink>,
        health: Arc<HealthTracker>,
    ) -> (Self, Weak<PendingInner>) {
        health.pending_created.fetch_add(1, Ordering::AcqRel);
        let inner = Arc::new(PendingInner {
            terminal: AtomicU8::new(0),
            requested_flags,
            responder: Mutex::new(Some(responder)),
            health,
        });
        (
            Self {
                inner: Arc::clone(&inner),
            },
            Arc::downgrade(&inner),
        )
    }

    pub fn allow(self) -> anyhow::Result<()> {
        self.inner.resolve(true)
    }

    pub fn deny(self) -> anyhow::Result<()> {
        self.inner.resolve(false)
    }

    pub fn requested_fflags(&self) -> u32 {
        self.inner.requested_flags
    }

    /// Consume this permission through a facade whose Allow result authorizes
    /// only FREAD. This keeps portable pending stores binary while macOS
    /// migration leases retain a stronger read-only response guarantee.
    pub fn into_read_only(self) -> ReadOnlyMacPendingPermission {
        ReadOnlyMacPendingPermission(self)
    }
}

pub struct ReadOnlyMacPendingPermission(MacPendingPermission);

impl PendingPermission for ReadOnlyMacPendingPermission {
    fn allow(self: Box<Self>) -> anyhow::Result<()> {
        self.0.inner.resolve_flags(ES_FFLAG_READ, false)
    }

    fn deny(self: Box<Self>) -> anyhow::Result<()> {
        self.0.inner.resolve(false)
    }
}

impl PendingPermission for MacPendingPermission {
    fn allow(self: Box<Self>) -> anyhow::Result<()> {
        self.inner.resolve(true)
    }

    fn deny(self: Box<Self>) -> anyhow::Result<()> {
        self.inner.resolve(false)
    }
}

impl Drop for MacPendingPermission {
    fn drop(&mut self) {
        if self.inner.terminal.load(Ordering::Acquire) == 0 {
            let _ = self.inner.resolve(false);
        }
    }
}

impl PendingInner {
    pub(crate) fn resolve(&self, allow: bool) -> anyhow::Result<()> {
        let authorized_flags = if allow { self.requested_flags } else { 0 };
        self.resolve_flags(authorized_flags, false)
    }

    fn resolve_flags(&self, authorized_flags: u32, timed_out: bool) -> anyhow::Result<()> {
        anyhow::ensure!(
            authorized_flags & !self.requested_flags == 0,
            "Endpoint Security response attempted to authorize unrequested FFLAGS"
        );
        let terminal = if authorized_flags == 0 { 2 } else { 1 };
        if self
            .terminal
            .compare_exchange(0, terminal, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            anyhow::bail!("Endpoint Security permission was already resolved");
        }
        if terminal == 1 {
            self.health
                .pending_resolved_allow
                .fetch_add(1, Ordering::AcqRel);
        } else {
            self.health
                .pending_resolved_deny
                .fetch_add(1, Ordering::AcqRel);
        }
        if timed_out {
            self.health.pending_timed_out.fetch_add(1, Ordering::AcqRel);
        }
        let responder = self
            .responder
            .lock()
            .expect("pending responder lock")
            .take()
            .expect("unresolved permission must own a responder");
        let result = responder.respond(authorized_flags);
        responder.release();
        if result == ResponseCode::Success {
            Ok(())
        } else {
            self.health.late_responses.fetch_add(1, Ordering::AcqRel);
            self.health.degrade(format!(
                "Endpoint Security flags response failed: {result}; retained message was released"
            ));
            anyhow::bail!("Endpoint Security flags response failed: {result}")
        }
    }

    fn resolve_timeout(&self) -> anyhow::Result<()> {
        self.resolve_flags(0, true)
    }

    pub(crate) fn is_terminal(&self) -> bool {
        self.terminal.load(Ordering::Acquire) != 0
    }
}

#[derive(Clone)]
pub(crate) struct DeadlineSchedulerHandle {
    sender: mpsc::Sender<SchedulerCommand>,
}

impl DeadlineSchedulerHandle {
    pub(crate) fn schedule(
        &self,
        permission: Weak<PendingInner>,
        budget: Duration,
    ) -> anyhow::Result<()> {
        self.sender
            .send(SchedulerCommand::Schedule(ScheduledPermission {
                deadline: Instant::now() + budget,
                permission,
            }))
            .map_err(|_| anyhow::anyhow!("Endpoint Security deadline scheduler is stopped"))
    }
}

pub(crate) struct DeadlineScheduler {
    sender: Option<mpsc::Sender<SchedulerCommand>>,
    thread: Option<JoinHandle<()>>,
}

struct ScheduledPermission {
    deadline: Instant,
    permission: Weak<PendingInner>,
}

enum SchedulerCommand {
    Schedule(ScheduledPermission),
    Shutdown,
}

impl DeadlineScheduler {
    pub(crate) fn start() -> anyhow::Result<(Self, DeadlineSchedulerHandle)> {
        let (sender, receiver) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("guard-es-deadlines".to_owned())
            .spawn(move || scheduler_loop(receiver))?;
        Ok((
            Self {
                sender: Some(sender.clone()),
                thread: Some(thread),
            },
            DeadlineSchedulerHandle { sender },
        ))
    }

    pub(crate) fn shutdown(&mut self) {
        if let Some(sender) = self.sender.take() {
            let _ = sender.send(SchedulerCommand::Shutdown);
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for DeadlineScheduler {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn scheduler_loop(receiver: mpsc::Receiver<SchedulerCommand>) {
    let mut scheduled: Vec<ScheduledPermission> = Vec::new();
    loop {
        resolve_due(&mut scheduled);
        let wait = scheduled
            .iter()
            .map(|item| item.deadline.saturating_duration_since(Instant::now()))
            .min();
        let command = match wait {
            Some(wait) => match receiver.recv_timeout(wait) {
                Ok(command) => Some(command),
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => None,
            },
            None => receiver.recv().ok(),
        };
        match command {
            Some(SchedulerCommand::Schedule(permission)) => scheduled.push(permission),
            Some(SchedulerCommand::Shutdown) | None => {
                for item in scheduled.drain(..) {
                    if let Some(permission) = item.permission.upgrade() {
                        let _ = permission.resolve(false);
                    }
                }
                return;
            }
        }
    }
}

fn resolve_due(scheduled: &mut Vec<ScheduledPermission>) {
    let now = Instant::now();
    let mut index = 0;
    while index < scheduled.len() {
        let expired = scheduled[index].deadline <= now;
        let terminal = scheduled[index]
            .permission
            .upgrade()
            .is_none_or(|permission| permission.is_terminal());
        if expired || terminal {
            let item = scheduled.swap_remove(index);
            if expired {
                if let Some(permission) = item.permission.upgrade() {
                    let _ = permission.resolve_timeout();
                }
            }
        } else {
            index += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeState {
        flags: Mutex<Vec<u32>>,
        releases: AtomicU8,
    }

    struct FakeSink(Arc<FakeState>);

    impl ResponseSink for FakeSink {
        fn respond(&self, authorized_flags: u32) -> ResponseCode {
            self.0.flags.lock().unwrap().push(authorized_flags);
            ResponseCode::Success
        }

        fn release(&self) {
            self.0.releases.fetch_add(1, Ordering::AcqRel);
        }
    }

    struct ErrorSink(Arc<FakeState>);

    impl ResponseSink for ErrorSink {
        fn respond(&self, authorized_flags: u32) -> ResponseCode {
            self.0.flags.lock().unwrap().push(authorized_flags);
            ResponseCode::Duplicate
        }

        fn release(&self) {
            self.0.releases.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn permission() -> (MacPendingPermission, Weak<PendingInner>, Arc<FakeState>) {
        let state = Arc::new(FakeState::default());
        let (permission, weak) = MacPendingPermission::new(
            0x1234,
            Box::new(FakeSink(Arc::clone(&state))),
            Arc::new(HealthTracker::active("test")),
        );
        (permission, weak, state)
    }

    #[test]
    fn allow_returns_exact_requested_fflags_and_releases_once() {
        let (permission, _, state) = permission();
        permission.allow().unwrap();
        assert_eq!(*state.flags.lock().unwrap(), vec![0x1234]);
        assert_eq!(state.releases.load(Ordering::Acquire), 1);
    }

    #[test]
    fn dropping_unresolved_permission_denies_and_releases_once() {
        let (permission, _, state) = permission();
        drop(permission);
        assert_eq!(*state.flags.lock().unwrap(), vec![0]);
        assert_eq!(state.releases.load(Ordering::Acquire), 1);
    }

    #[test]
    fn deadline_is_primary_fail_closed_resolution() {
        let (permission, weak, state) = permission();
        let (mut scheduler, handle) = DeadlineScheduler::start().unwrap();
        handle.schedule(weak, Duration::from_millis(5)).unwrap();
        std::thread::sleep(Duration::from_millis(30));
        assert!(permission.allow().is_err());
        assert_eq!(*state.flags.lock().unwrap(), vec![0]);
        assert_eq!(state.releases.load(Ordering::Acquire), 1);
        scheduler.shutdown();
    }

    #[test]
    fn timer_and_user_resolution_race_has_one_terminal_response() {
        let (permission, weak, state) = permission();
        let (mut scheduler, handle) = DeadlineScheduler::start().unwrap();
        handle.schedule(weak, Duration::ZERO).unwrap();
        let user = std::thread::spawn(move || permission.allow());
        let _ = user.join().unwrap();
        std::thread::sleep(Duration::from_millis(10));
        scheduler.shutdown();
        assert_eq!(state.flags.lock().unwrap().len(), 1);
        assert_eq!(state.releases.load(Ordering::Acquire), 1);
    }

    #[test]
    fn response_error_degrades_health_but_still_releases_once() {
        let state = Arc::new(FakeState::default());
        let health = Arc::new(HealthTracker::active("test"));
        let (permission, _) = MacPendingPermission::new(
            0x1234,
            Box::new(ErrorSink(Arc::clone(&state))),
            Arc::clone(&health),
        );
        assert!(permission.deny().is_err());
        assert_eq!(*state.flags.lock().unwrap(), vec![0]);
        assert_eq!(state.releases.load(Ordering::Acquire), 1);
        let snapshot = health.snapshot();
        assert!(snapshot.active);
        assert!(snapshot.degraded);
        assert!(snapshot.diagnostic.unwrap().contains("Duplicate"));
        assert_eq!(snapshot.late_responses, 1);
    }

    #[test]
    fn read_only_permission_strips_fwrite_from_migration_response() {
        let state = Arc::new(FakeState::default());
        let (permission, _) = MacPendingPermission::new(
            ES_FFLAG_READ | ES_FFLAG_WRITE,
            Box::new(FakeSink(Arc::clone(&state))),
            Arc::new(HealthTracker::active("test")),
        );
        Box::new(permission.into_read_only()).allow().unwrap();
        assert_eq!(*state.flags.lock().unwrap(), vec![ES_FFLAG_READ]);
        assert_eq!(state.releases.load(Ordering::Acquire), 1);
    }

    #[test]
    fn authorization_lifecycle_counters_are_semantic_and_race_safe() {
        let state = Arc::new(FakeState::default());
        let health = Arc::new(HealthTracker::active("test"));
        let (permission, weak) = MacPendingPermission::new(
            ES_FFLAG_READ,
            Box::new(FakeSink(Arc::clone(&state))),
            Arc::clone(&health),
        );
        assert_eq!(health.snapshot().pending_created, 1);
        let (mut scheduler, handle) = DeadlineScheduler::start().unwrap();
        handle.schedule(weak, Duration::ZERO).unwrap();
        std::thread::sleep(Duration::from_millis(10));
        assert!(permission.allow().is_err());
        scheduler.shutdown();
        let snapshot = health.snapshot();
        assert_eq!(snapshot.pending_timed_out, 1);
        assert_eq!(snapshot.pending_resolved_deny, 1);
        assert_eq!(snapshot.pending_resolved_allow, 0);
        assert_eq!(state.flags.lock().unwrap().as_slice(), &[0]);
    }
}
