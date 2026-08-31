//! Unprivileged user-session notification presenter.
//!
//! This process contains no policy engine. On Linux it polls guardd's
//! credential-filtered IPC event feed and presents denies via notify-send. On
//! macOS it polls the authenticated system-extension XPC service, delivers
//! notifications from the user-session LaunchAgent, and opens the sibling GTK
//! pending-only UI when an interactive decision is waiting.

#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "macos")]
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;
#[cfg(target_os = "macos")]
use std::time::Instant;

use clap::Parser;
#[cfg(target_os = "linux")]
use guard_client::transport::IpcClient;
#[cfg(target_os = "macos")]
use guard_ipc::EventInfo;
#[cfg(target_os = "linux")]
use guard_ipc::{EventInfo, Request, RequestOp, Response, ResponseBody, PROTOCOL_VERSION};

#[cfg(target_os = "linux")]
const DEFAULT_SOCKET_PATH: &str = "/run/guardd/guardd.sock";

#[derive(Debug, Parser)]
#[command(name = "guard-notify", version)]
struct Cli {
    #[cfg(target_os = "linux")]
    #[arg(long, default_value = DEFAULT_SOCKET_PATH)]
    socket: PathBuf,
    #[arg(long, default_value_t = default_poll_ms())]
    poll_ms: u64,
    /// Fetch once and exit. Intended for diagnostics/tests.
    #[arg(long)]
    once: bool,
    /// macOS only: send a harmless synthetic notification and exit.
    #[arg(long)]
    test_notification: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    #[cfg(target_os = "macos")]
    return run_macos(&cli);
    #[cfg(target_os = "linux")]
    return run_linux(&cli);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = cli;
        eprintln!("guard-notify: unsupported platform");
        ExitCode::from(78)
    }
}

#[cfg(target_os = "linux")]
const fn default_poll_ms() -> u64 {
    1_000
}

#[cfg(target_os = "macos")]
const fn default_poll_ms() -> u64 {
    500
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const fn default_poll_ms() -> u64 {
    1_000
}

#[cfg(target_os = "linux")]
fn run_linux(cli: &Cli) -> ExitCode {
    let mut last_seen = None;
    let mut last_notified = HashMap::new();
    loop {
        match fetch_events(&cli.socket) {
            Ok(mut events) => {
                events.sort_by_key(|event| event.id);
                let newest = events.last().map(|event| event.id);
                if let Some(previous) = last_seen {
                    let now_ms = unix_ms();
                    for event in events.iter().filter(|event| {
                        event.id > previous
                            && (event.decision.contains("Deny")
                                || event.event_code == "ssh_key_access_confirmation_required"
                                || event.event_code == "browser_migration_confirmation_required")
                    }) {
                        if !should_notify(&mut last_notified, event, now_ms) {
                            continue;
                        }
                        let (summary, body, urgency) = notification_text(event);
                        if let Err(error) = notify(&summary, &body, urgency) {
                            eprintln!("guard-notify: desktop notification failed: {error}");
                        } else {
                            // Event IDs are safe metadata and give the acceptance
                            // harness an unambiguous delivery acknowledgement.
                            eprintln!("guard-notify: delivered event_id={}", event.id);
                        }
                        if matches!(
                            event.event_code.as_str(),
                            "browser_migration_confirmation_required"
                                | "ssh_key_access_confirmation_required"
                        ) {
                            activate_guard_ui();
                        }
                    }
                    if let Some(newest) = newest {
                        last_seen = Some(newest.max(previous));
                    }
                } else {
                    // An empty initial result is still a valid baseline. Using
                    // zero ensures the first future DENY is presented instead
                    // of being silently consumed as initialization.
                    let baseline = newest.unwrap_or(0);
                    last_seen = Some(baseline);
                    eprintln!("guard-notify: ready baseline_event_id={baseline}");
                }
            }
            Err(error) => eprintln!("guard-notify: {error}"),
        }
        if cli.once {
            return ExitCode::SUCCESS;
        }
        std::thread::sleep(Duration::from_millis(cli.poll_ms.max(100)));
    }
}

#[cfg(target_os = "macos")]
fn run_macos(cli: &Cli) -> ExitCode {
    if cli.test_notification {
        return match notify_macos(
            "Sensitive File Guard test notification",
            "The Sensitive File Guard notification channel is working; this is a synthetic test message.",
        ) {
            Ok(()) => {
                eprintln!("guard-notify: delivered synthetic macOS test notification");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("guard-notify: macOS test notification failed: {error:#}");
                ExitCode::FAILURE
            }
        };
    }
    let client = match guard_client::macos::MacGuardClient::for_current_process() {
        Ok(client) => client,
        Err(error) => {
            eprintln!("guard-notify: authenticated XPC unavailable: {error:#}");
            return ExitCode::FAILURE;
        }
    };
    let mut observer = PendingObserver::default();
    let mut events = MacEventObserver::default();
    let normal_delay = Duration::from_millis(cli.poll_ms.clamp(100, 1_000));
    let mut delay = normal_delay;
    loop {
        let events_ok = match client.events_cursor(Some(100), None, events.last_seen()) {
            Ok(snapshot) => {
                for event in events.observe(snapshot) {
                    let (title, body) = mac_notification_text(&event);
                    if let Err(error) = notify_macos(&title, &body) {
                        eprintln!("guard-notify: macOS system notification failed: {error:#}");
                    } else {
                        // Audit IDs are metadata and make it possible to
                        // distinguish a delivery attempt from event polling.
                        eprintln!("guard-notify: delivered event_id={}", event.id);
                    }
                }
                true
            }
            Err(error) => {
                eprintln!("guard-notify: event poll failed: {error:#}");
                false
            }
        };
        let pending_ok = match fetch_macos_pending(&client) {
            Ok(pending) => {
                let observation = observer.observe(pending, Instant::now());
                if observation.notify {
                    if let Err(error) = notify_macos(
                        "Sensitive File Guard confirmation required",
                        "Sensitive File Guard is waiting for your decision about protected browser credentials, website authentication storage, or an SSH private key.",
                    ) {
                        eprintln!("guard-notify: macOS confirmation notification failed: {error:#}");
                    }
                }
                if observation.activate {
                    activate_guard_ui_macos();
                }
                true
            }
            Err(error) => {
                eprintln!("guard-notify: {error:#}");
                delay = delay.saturating_mul(2).min(Duration::from_secs(5));
                false
            }
        };
        let succeeded = events_ok && pending_ok;
        if succeeded {
            delay = normal_delay;
        }
        if cli.once {
            return if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
        }
        std::thread::sleep(delay);
    }
}

#[cfg(target_os = "macos")]
#[derive(Default)]
struct MacEventObserver {
    last_seen: Option<i64>,
}

#[cfg(target_os = "macos")]
impl MacEventObserver {
    fn last_seen(&self) -> Option<i64> {
        self.last_seen
    }

    /// The initial event cursor is a baseline, so enabling the helper never
    /// spams a user with historical records. Subsequent denied events are
    /// delivered exactly once by monotonically increasing audit ID.
    fn observe(&mut self, events: Vec<EventInfo>) -> Vec<EventInfo> {
        let newest = events.iter().map(|event| event.id).max();
        let Some(previous) = self.last_seen else {
            self.last_seen = newest;
            return Vec::new();
        };
        self.last_seen = newest.map_or(Some(previous), |id| Some(id.max(previous)));
        events
            .into_iter()
            .filter(|event| {
                event.id > previous
                    && event.decision.contains("Deny")
                    && event.event_code != "system_process_access_suppressed"
            })
            .collect()
    }
}

#[cfg(target_os = "macos")]
fn mac_notification_text(event: &EventInfo) -> (String, String) {
    let executable = Path::new(&event.exe)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "a process".into());
    (
        "Sensitive File Guard blocked access".into(),
        format!(
            "{executable} attempted to access protected {}.",
            event.resource_kind_code
        ),
    )
}

#[cfg(target_os = "macos")]
fn notify_macos(title: &str, body: &str) -> anyhow::Result<()> {
    platform_macos::notifications::send(title, body)
}

#[cfg(target_os = "macos")]
fn fetch_macos_pending(
    client: &guard_client::macos::MacGuardClient,
) -> anyhow::Result<HashSet<PendingKey>> {
    let snapshot = client.pending_helper_poll()?;
    Ok(snapshot
        .migrations
        .into_iter()
        .map(|pending| PendingKey::Migration(pending.id))
        .chain(
            snapshot
                .ssh_reads
                .into_iter()
                .map(|pending| PendingKey::SshRead(pending.id)),
        )
        .collect())
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PendingKey {
    Migration(String),
    SshRead(String),
}

#[cfg(target_os = "macos")]
const PENDING_ACTIVATION_RETRY_INTERVAL: Duration = Duration::from_secs(2);
#[cfg(target_os = "macos")]
const PENDING_ACTIVATION_MAX_ATTEMPTS: u8 = 3;

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PendingObservation {
    notify: bool,
    activate: bool,
}

#[cfg(target_os = "macos")]
#[derive(Default)]
struct PendingObserver {
    presented: HashSet<PendingKey>,
    activation_attempts: u8,
    next_activation: Option<Instant>,
}

#[cfg(target_os = "macos")]
impl PendingObserver {
    /// Notifications remain deduplicated, while activation is retried a small,
    /// bounded number of times. LaunchServices can accept an activation for a
    /// GUI instance that is concurrently exiting after its last window closes;
    /// a later attempt then starts the pending-only presenter cleanly.
    fn observe(&mut self, current: HashSet<PendingKey>, now: Instant) -> PendingObservation {
        let has_new = current
            .iter()
            .any(|pending| !self.presented.contains(pending));
        if current.is_empty() {
            self.activation_attempts = 0;
            self.next_activation = None;
        } else if has_new {
            self.activation_attempts = 0;
            self.next_activation = Some(now);
        }

        let activate = !current.is_empty()
            && self.activation_attempts < PENDING_ACTIVATION_MAX_ATTEMPTS
            && self.next_activation.is_some_and(|deadline| now >= deadline);
        if activate {
            self.activation_attempts += 1;
            self.next_activation = Some(now + PENDING_ACTIVATION_RETRY_INTERVAL);
        }
        self.presented = current;
        PendingObservation {
            notify: has_new,
            activate,
        }
    }
}

#[cfg(target_os = "macos")]
fn activate_guard_ui_macos() {
    if let Err(error) = activate_guard_ui_macos_with_args(&[]) {
        eprintln!("guard-notify: could not activate Sensitive File Guard.app: {error}");
    }
}

#[cfg(target_os = "macos")]
fn activate_guard_ui_macos_with_args(args: &[&str]) -> anyhow::Result<()> {
    let executable = match std::env::current_exe() {
        Ok(executable) => executable,
        Err(error) => anyhow::bail!("cannot locate app bundle: {error}"),
    };
    let guard = guard_ui_executable(&executable)?;
    if args.is_empty() {
        // Launch through LaunchServices instead of executing the nested Mach-O
        // directly. This reliably activates an already-running GApplication
        // after its window was closed, and starts the correct bundle when the
        // GUI process has exited. The bundle path is passed as one argv item,
        // so spaces in the installation path remain safe.
        let bundle = guard_ui_bundle(&guard)?;
        // A pending confirmation is a short-lived presenter, not a second
        // control-center instance. Pass `--pending-only` to a newly launched
        // app so it exits after the queue is empty. LaunchServices still
        // activates an already-running Guard process, where the normal UI
        // polling path owns the existing window.
        let output = Command::new("/usr/bin/open")
            .args(launchservices_pending_args(&bundle))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|error| anyhow::anyhow!("could not open {}: {error}", bundle.display()))?;
        anyhow::ensure!(
            output.status.success(),
            "LaunchServices refused to open {} ({}): {}",
            bundle.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(())
    } else {
        Command::new(&guard)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map(|_| ())
            .map_err(|error| anyhow::anyhow!("could not activate {}: {error}", guard.display()))
    }
}

#[cfg(target_os = "macos")]
fn launchservices_pending_args(bundle: &Path) -> Vec<std::ffi::OsString> {
    vec![
        "-a".into(),
        bundle.as_os_str().to_owned(),
        "--args".into(),
        "--pending-only".into(),
    ]
}

#[cfg(target_os = "macos")]
fn guard_ui_executable(helper: &Path) -> anyhow::Result<PathBuf> {
    let macos_dir = helper
        .parent()
        .ok_or_else(|| anyhow::anyhow!("helper executable has no parent directory"))?;
    anyhow::ensure!(
        macos_dir.file_name().is_some_and(|name| name == "MacOS"),
        "pending helper is not inside an app Contents/MacOS directory"
    );
    Ok(macos_dir.join("SensitiveFileGuard"))
}

#[cfg(target_os = "macos")]
fn guard_ui_bundle(guard: &Path) -> anyhow::Result<PathBuf> {
    let macos_dir = guard.parent().ok_or_else(|| {
        anyhow::anyhow!("Sensitive File Guard executable has no parent directory")
    })?;
    let contents = macos_dir.parent().ok_or_else(|| {
        anyhow::anyhow!("Sensitive File Guard executable is not inside Contents/MacOS")
    })?;
    anyhow::ensure!(
        contents.file_name().is_some_and(|name| name == "Contents"),
        "Sensitive File Guard executable is not inside an app bundle"
    );
    Ok(contents
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Sensitive File Guard bundle has no parent directory"))?
        .to_path_buf())
}

#[cfg(target_os = "linux")]
type NotificationKey = (u32, String, String, String, String);

#[cfg(target_os = "linux")]
fn should_notify(
    last_notified: &mut HashMap<NotificationKey, u64>,
    event: &EventInfo,
    now_ms: u64,
) -> bool {
    const WINDOW_MS: u64 = 10_000;
    let request = event
        .backend_diag
        .split(';')
        .find_map(|field| field.strip_prefix("request="))
        .unwrap_or("")
        .to_owned();
    let key = (
        event.pid,
        event.exe.clone(),
        event.path.clone(),
        request,
        event.event_code.clone(),
    );
    if last_notified
        .get(&key)
        .is_some_and(|last| now_ms.saturating_sub(*last) < WINDOW_MS)
    {
        return false;
    }
    last_notified.insert(key, now_ms);
    true
}

#[cfg(target_os = "linux")]
fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(target_os = "linux")]
fn fetch_events(socket: &Path) -> Result<Vec<EventInfo>, String> {
    let request = Request {
        version: PROTOCOL_VERSION,
        op: RequestOp::Events {
            limit: Some(100),
            before_id: None,
            after_id: None,
        },
    };
    let bytes = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    let response =
        IpcClient::request(socket, &bytes).map_err(|e| format!("IPC {}: {e}", socket.display()))?;
    let response: Response = serde_json::from_slice(&response).map_err(|e| e.to_string())?;
    if !response.ok {
        return Err(response
            .error
            .unwrap_or_else(|| "daemon rejected request".into()));
    }
    match response.body {
        Some(ResponseBody::Events(events)) => Ok(events),
        _ => Err("daemon returned an unexpected response".into()),
    }
}

#[cfg(target_os = "linux")]
fn notification_text(event: &EventInfo) -> (String, String, &'static str) {
    let exe = Path::new(&event.exe)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| event.exe.clone());
    if event.event_code == "browser_migration_confirmation_required" {
        let source = event
            .resource_browser
            .as_deref()
            .unwrap_or("another browser");
        let target = event.process_browser.as_deref().unwrap_or(&exe);
        return (
            "Browser authentication-data import confirmation required".into(),
            format!(
                "{target} is trying to access protected {source} credentials or website authentication storage. Open Sensitive File Guard to confirm the authentication-data import."
            ),
            "normal",
        );
    }
    if event.reason_code.as_deref() == Some("migration_lease_required") {
        return (
            "Blocked cross-browser credential access".into(),
            format!(
                "{exe} attempted to access protected browser credentials or website authentication storage. Authorize a temporary migration access lease if this was intentional."
            ),
            "normal",
        );
    }
    if event.event_code == "ssh_key_access_confirmation_required" {
        return (
            "SSH private-key confirmation required".into(),
            format!(
                "{exe} is waiting to read a protected SSH private key. Open Sensitive File Guard to allow or block it."
            ),
            "normal",
        );
    }
    (
        "Blocked protected-data access".into(),
        format!(
            "{exe} attempted to access {}. Access was denied.",
            event.resource_kind_code
        ),
        "normal",
    )
}

#[cfg(target_os = "linux")]
fn notify(summary: &str, body: &str, urgency: &str) -> std::io::Result<()> {
    match notify_once(summary, body, urgency) {
        Ok(()) => Ok(()),
        Err(error) if notification_rate_limited(&error) => {
            // Desktop servers legitimately protect themselves against a burst
            // of distinct security events. Retry privately so a temporary UI
            // rate limit cannot turn an audited denial into a dropped alert.
            std::thread::sleep(Duration::from_secs(1));
            notify_once(summary, body, urgency)
        }
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "linux")]
fn notify_once(summary: &str, body: &str, urgency: &str) -> std::io::Result<()> {
    let output = Command::new("notify-send")
        .args([
            "--app-name=guardd",
            &format!("--urgency={urgency}"),
            "--icon=security-medium",
            summary,
            body,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(std::io::Error::other(format!(
            "notify-send exited {}: {}",
            output.status,
            stderr.trim()
        )))
    }
}

#[cfg(target_os = "linux")]
fn notification_rate_limited(error: &std::io::Error) -> bool {
    error.to_string().contains("ExcessNotificationGeneration")
}

#[cfg(target_os = "linux")]
fn activate_guard_ui() {
    // The UI remains an unprivileged presenter: it polls the authenticated
    // incident API and asks guardd to cross polkit for any resolution.
    if let Err(error) = Command::new("guard-ui")
        .arg("--pending-only")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        eprintln!("guard-notify: could not activate guard-ui: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn event(pid: u32, path: &str) -> EventInfo {
        EventInfo {
            id: 1,
            event_code: "access_decision".into(),
            ts_ms: 1,
            uid: 1000,
            pid,
            start_time: 1,
            decision: "Deny(UnknownProcess)".into(),
            deny_reason: Some("UnknownProcess".into()),
            reason_code: Some("browser_protected_resource".into()),
            resource_kind: "CookieStore".into(),
            resource_kind_code: "cookie_store".into(),
            resource_browser: None,
            resource_profile: None,
            path: path.into(),
            exe: "/usr/bin/test-probe".into(),
            exe_owner_uid: 0,
            trust_tier: "SystemPackage".into(),
            process_browser: None,
            parent_pid: None,
            parent_exe: None,
            lease_id: None,
            backend_diag: "test".into(),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn coalesces_same_process_and_resource_for_ten_seconds() {
        let mut sent = HashMap::new();
        let event = event(7, "/synthetic/Cookies");
        assert!(should_notify(&mut sent, &event, 1_000));
        assert!(!should_notify(&mut sent, &event, 10_999));
        assert!(should_notify(&mut sent, &event, 11_000));
        assert!(should_notify(
            &mut sent,
            &self::event(8, "/synthetic/Cookies"),
            11_001
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn distinct_ssh_confirmation_requests_are_not_coalesced() {
        let mut sent = HashMap::new();
        let mut first = event(7, "/synthetic/id_ed25519");
        first.event_code = "ssh_key_access_confirmation_required".into();
        first.backend_diag = "ssh_key_access_confirmation_required;request=ssh-0001".into();
        let mut second = first.clone();
        second.backend_diag = "ssh_key_access_confirmation_required;request=ssh-0002".into();
        assert!(should_notify(&mut sent, &first, 1_000));
        assert!(should_notify(&mut sent, &second, 1_001));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn matching_ssh_confirmation_is_coalesced() {
        let mut sent = HashMap::new();
        let mut first = event(7, "/synthetic/id_ed25519");
        first.event_code = "ssh_key_access_confirmation_required".into();
        first.backend_diag = "ssh_key_access_confirmation_required;request=ssh-0001".into();
        let mut second = first.clone();
        second.backend_diag = "ssh_key_access_confirmation_required;request=ssh-0001".into();
        assert!(should_notify(&mut sent, &first, 1_000));
        assert!(!should_notify(&mut sent, &second, 1_001));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recognizes_desktop_notification_rate_limit() {
        let limited = std::io::Error::other(
            "notify-send exited exit status: 1: GDBus.Error:org.freedesktop.Notifications.Error:ExcessNotificationGeneration",
        );
        assert!(notification_rate_limited(&limited));
        assert!(!notification_rate_limited(&std::io::Error::other(
            "permission denied"
        )));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pending_observer_deduplicates_notifications_and_retries_activation() {
        let mut observer = PendingObserver::default();
        let now = Instant::now();
        let first = HashSet::from([PendingKey::Migration("m1".into())]);
        assert_eq!(
            observer.observe(first.clone(), now),
            PendingObservation {
                notify: true,
                activate: true
            }
        );
        assert_eq!(
            observer.observe(first.clone(), now + Duration::from_secs(1)),
            PendingObservation::default()
        );
        assert_eq!(
            observer.observe(first.clone(), now + Duration::from_secs(2)),
            PendingObservation {
                notify: false,
                activate: true
            }
        );
        assert_eq!(
            observer.observe(first.clone(), now + Duration::from_secs(4)),
            PendingObservation {
                notify: false,
                activate: true
            }
        );
        assert_eq!(
            observer.observe(first, now + Duration::from_secs(6)),
            PendingObservation::default()
        );

        assert_eq!(
            observer.observe(
                HashSet::from([
                    PendingKey::Migration("m1".into()),
                    PendingKey::SshRead("s1".into()),
                ]),
                now + Duration::from_secs(7)
            ),
            PendingObservation {
                notify: true,
                activate: true
            }
        );
        assert_eq!(
            observer.observe(
                HashSet::from([
                    PendingKey::Migration("m1".into()),
                    PendingKey::SshRead("s1".into()),
                ]),
                now + Duration::from_secs(8)
            ),
            PendingObservation::default()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pending_observer_rearms_after_the_queue_becomes_empty() {
        let mut observer = PendingObserver::default();
        let now = Instant::now();
        let pending = HashSet::from([PendingKey::SshRead("s1".into())]);
        assert!(observer.observe(pending.clone(), now).activate);
        assert_eq!(
            observer.observe(HashSet::new(), now + Duration::from_secs(1)),
            PendingObservation::default()
        );
        assert_eq!(
            observer.observe(pending, now + Duration::from_secs(2)),
            PendingObservation {
                notify: true,
                activate: true
            }
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pending_observer_new_request_rearms_activation_budget() {
        let mut observer = PendingObserver::default();
        let now = Instant::now();
        let first = HashSet::from([PendingKey::Migration("m1".into())]);
        assert!(observer.observe(first.clone(), now).activate);
        assert!(
            observer
                .observe(first.clone(), now + Duration::from_secs(2))
                .activate
        );
        assert!(
            observer
                .observe(first, now + Duration::from_secs(4))
                .activate
        );

        let observation = observer.observe(
            HashSet::from([
                PendingKey::Migration("m1".into()),
                PendingKey::SshRead("s1".into()),
            ]),
            now + Duration::from_secs(5),
        );
        assert!(observation.notify);
        assert!(observation.activate);
    }

    #[test]
    fn pending_observer_never_contains_a_resolution_action() {
        let source = include_str!("main.rs");
        let mac_section = source
            .split("fn run_macos")
            .nth(1)
            .and_then(|section| section.split("fn should_notify").next())
            .unwrap();
        assert!(!mac_section.contains("allow_migration"));
        assert!(!mac_section.contains("allow_ssh_read"));
        assert!(!mac_section.contains("block_migration"));
        assert!(!mac_section.contains("block_ssh_read"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mac_event_observer_baselines_then_notifies_new_denials_once() {
        let mut observer = MacEventObserver::default();
        let first = event(7, "/synthetic/Cookies");
        assert!(observer.observe(vec![first.clone()]).is_empty());
        assert_eq!(observer.last_seen(), Some(first.id));

        let mut denied = event(8, "/synthetic/Cookies");
        denied.id = 2;
        assert_eq!(
            observer
                .observe(vec![denied])
                .iter()
                .map(|event| event.id)
                .collect::<Vec<_>>(),
            vec![2]
        );

        let mut allowed = event(9, "/synthetic/Cookies");
        allowed.id = 3;
        allowed.decision = "Allow".into();
        assert!(observer.observe(vec![allowed]).is_empty());
        assert_eq!(observer.last_seen(), Some(3));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mac_notification_text_is_metadata_only() {
        let mut denied = event(10, "/Users/test/secret/Cookies");
        denied.resource_kind_code = "browser_cookie_store".into();
        denied.exe = "/Applications/App Cleaner.app/Contents/MacOS/App Cleaner".into();

        let (title, body) = mac_notification_text(&denied);

        assert_eq!(title, "Sensitive File Guard blocked access");
        assert!(body.contains("App Cleaner"));
        assert!(body.contains("browser_cookie_store"));
        assert!(!body.contains("/Users/"));
        assert!(!body.contains("Cookies"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pending_helper_launches_only_the_sibling_guard_pending_client() {
        let helper =
            Path::new("/Applications/Sensitive File Guard.app/Contents/MacOS/guard-notify");
        assert_eq!(
            guard_ui_executable(helper).unwrap(),
            PathBuf::from(
                "/Applications/Sensitive File Guard.app/Contents/MacOS/SensitiveFileGuard"
            )
        );
        assert_eq!(
            guard_ui_bundle(&guard_ui_executable(helper).unwrap()).unwrap(),
            PathBuf::from("/Applications/Sensitive File Guard.app")
        );
        let spaced = Path::new("/Applications/Guard Test.app/Contents/MacOS/guard-notify");
        assert_eq!(
            guard_ui_bundle(&guard_ui_executable(spaced).unwrap()).unwrap(),
            PathBuf::from("/Applications/Guard Test.app")
        );
        assert!(guard_ui_executable(Path::new("/tmp/guard-notify")).is_err());
        assert!(guard_ui_bundle(Path::new("/tmp/Guard")).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pending_helper_launch_uses_pending_only_launchservices_args() {
        // Keep the LaunchServices contract explicit: a newly launched helper
        // must not become a permanent Dock application after the decision.
        let args = launchservices_pending_args(Path::new("/Applications/Guard Test.app"));
        assert_eq!(args.len(), 4);
        assert_eq!(args[0], "-a");
        assert_eq!(args[1], "/Applications/Guard Test.app");
        assert_eq!(args[2], "--args");
        assert_eq!(args[3], "--pending-only");
    }
}
