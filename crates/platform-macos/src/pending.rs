use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{mpsc, Arc, Mutex, Weak};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use guard_platform::PendingPermission;

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
    diagnostic: Mutex<Option<String>>,
}

impl HealthTracker {
    pub(crate) fn active(diagnostic: impl Into<String>) -> Self {
        Self {
            active: AtomicBool::new(true),
            diagnostic: Mutex::new(Some(diagnostic.into())),
        }
    }

    pub(crate) fn note(&self, diagnostic: impl Into<String>) {
        *self.diagnostic.lock().expect("health diagnostic lock") = Some(diagnostic.into());
    }

    pub(crate) fn degrade(&self, diagnostic: impl Into<String>) {
        self.active.store(false, Ordering::Release);
        self.note(diagnostic);
    }

    pub(crate) fn stop(&self, diagnostic: impl Into<String>) {
        self.degrade(diagnostic);
    }

    pub(crate) fn snapshot(&self) -> (bool, Option<String>) {
        (
            self.active.load(Ordering::Acquire),
            self.diagnostic
                .lock()
                .expect("health diagnostic lock")
                .clone(),
        )
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
        let terminal = if allow { 1 } else { 2 };
        if self
            .terminal
            .compare_exchange(0, terminal, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            anyhow::bail!("Endpoint Security permission was already resolved");
        }
        let responder = self
            .responder
            .lock()
            .expect("pending responder lock")
            .take()
            .expect("unresolved permission must own a responder");
        let authorized_flags = if allow { self.requested_flags } else { 0 };
        let result = responder.respond(authorized_flags);
        responder.release();
        if result == ResponseCode::Success {
            Ok(())
        } else {
            self.health.degrade(format!(
                "Endpoint Security flags response failed: {result}; retained message was released"
            ));
            anyhow::bail!("Endpoint Security flags response failed: {result}")
        }
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
                    let _ = permission.resolve(false);
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
        let (active, diagnostic) = health.snapshot();
        assert!(!active);
        assert!(diagnostic.unwrap().contains("Duplicate"));
    }
}
