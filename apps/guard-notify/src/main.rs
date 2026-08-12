//! Unprivileged user-session notification presenter.
//!
//! This process contains no policy engine. On Linux it polls guardd's
//! credential-filtered IPC event feed and presents denies via notify-send. On
//! macOS it polls the authenticated system-extension XPC service and opens the
//! sibling GTK pending-only UI when an interactive decision is waiting.

#[cfg(target_os = "linux")]
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

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
            "Sensitive File Guard 测试通知",
            "通知通道正常；这是一条合成测试消息。",
        ) {
            Ok(()) => {
                eprintln!("guard-notify: macOS test notification delivered");
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
                    // Guard.app owns macOS event notifications. This helper
                    // remains responsible for surfacing pending confirmations
                    // and must not duplicate the event notification stream.
                    let _ = event;
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
                if observer.observe(pending) {
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
#[allow(dead_code)]
fn mac_notification_text(event: &EventInfo) -> (String, String) {
    let executable = Path::new(&event.exe)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "A process".into());
    (
        "Sensitive File Guard blocked access".into(),
        format!(
            "{executable} was blocked from accessing protected {}.",
            event.resource_kind_code
        ),
    )
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PendingKey {
    Migration(String),
    SshRead(String),
}

#[derive(Default)]
struct PendingObserver {
    presented: HashSet<PendingKey>,
}

impl PendingObserver {
    /// Returns true exactly once for each item while it remains in successful
    /// snapshots. The helper launches the UI but never resolves policy.
    fn observe(&mut self, current: HashSet<PendingKey>) -> bool {
        let has_new = current
            .iter()
            .any(|pending| !self.presented.contains(pending));
        self.presented = current;
        has_new
    }
}

#[cfg(target_os = "macos")]
fn activate_guard_ui_macos() {
    let executable = match std::env::current_exe() {
        Ok(executable) => executable,
        Err(error) => {
            eprintln!("guard-notify: cannot locate app bundle: {error}");
            return;
        }
    };
    let guard = match guard_ui_executable(&executable) {
        Ok(guard) => guard,
        Err(error) => {
            eprintln!("guard-notify: {error}");
            return;
        }
    };
    if let Err(error) = Command::new(&guard)
        .arg("--pending-only")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        eprintln!(
            "guard-notify: could not activate {}: {error}",
            guard.display()
        );
    }
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
    Ok(macos_dir.join("Guard"))
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
            "Browser data import confirmation required".into(),
            format!(
                "{target} is trying to access protected {source} data. Open Sensitive File Guard to confirm whether you are importing browser data."
            ),
            "normal",
        );
    }
    if event.reason_code.as_deref() == Some("migration_lease_required") {
        return (
            "Blocked cross-browser data access".into(),
            format!(
                "{exe} attempted to access protected browser data. Authorize a temporary migration access lease if this was intentional."
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

    #[test]
    fn pending_observer_launches_once_and_deduplicates_snapshots() {
        let mut observer = PendingObserver::default();
        let first = HashSet::from([PendingKey::Migration("m1".into())]);
        assert!(observer.observe(first.clone()));
        assert!(!observer.observe(first));
        assert!(observer.observe(HashSet::from([
            PendingKey::Migration("m1".into()),
            PendingKey::SshRead("s1".into()),
        ])));
        assert!(!observer.observe(HashSet::from([
            PendingKey::Migration("m1".into()),
            PendingKey::SshRead("s1".into()),
        ])));
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
    fn mac_event_observer_suppresses_system_allowlist_noise() {
        let mut observer = MacEventObserver::default();
        let baseline = EventInfo {
            id: 10,
            event_code: "system_process_access_suppressed".into(),
            ts_ms: 1,
            uid: 501,
            pid: 42,
            start_time: 1,
            decision: "Deny(UnknownProcess)".into(),
            deny_reason: Some("UnknownProcess".into()),
            reason_code: Some("browser_protected_resource".into()),
            resource_kind: "History".into(),
            resource_kind_code: "browser_history".into(),
            resource_browser: Some("edge".into()),
            resource_profile: Some("Default".into()),
            path: "/synthetic/history".into(),
            exe: "/System/mdworker_shared".into(),
            exe_owner_uid: 0,
            trust_tier: "Unknown".into(),
            process_browser: None,
            parent_pid: None,
            parent_exe: None,
            lease_id: None,
            backend_diag: "system process".into(),
        };
        assert!(observer.observe(vec![baseline]).is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mac_notification_does_not_include_the_resource_path() {
        let event = event(7, "/synthetic/secret/Cookies");
        let (_, body) = mac_notification_text(&event);
        assert!(!body.contains("/synthetic/secret/Cookies"));
        assert!(body.contains("test-probe"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pending_helper_launches_only_the_sibling_guard_pending_client() {
        let helper = Path::new("/Applications/Guard.app/Contents/MacOS/guard-notify");
        assert_eq!(
            guard_ui_executable(helper).unwrap(),
            PathBuf::from("/Applications/Guard.app/Contents/MacOS/Guard")
        );
        assert!(guard_ui_executable(Path::new("/tmp/guard-notify")).is_err());
    }
}
