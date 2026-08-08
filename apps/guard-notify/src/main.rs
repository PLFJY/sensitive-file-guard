//! Unprivileged user-session notification presenter.
//!
//! This process contains no policy engine. It polls the authenticated guardd
//! IPC API (which filters events by SO_PEERCRED UID) and presents new denies on
//! the user's desktop session via notify-send.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use clap::Parser;
use guard_ipc::{EventInfo, Request, RequestOp, Response, ResponseBody, PROTOCOL_VERSION};
use platform_linux::ipc::{IpcClient, DEFAULT_SOCKET_PATH};

#[derive(Debug, Parser)]
#[command(name = "guard-notify", version)]
struct Cli {
    #[arg(long, default_value = DEFAULT_SOCKET_PATH)]
    socket: PathBuf,
    #[arg(long, default_value_t = 1_000)]
    poll_ms: u64,
    /// Fetch once and exit. Intended for diagnostics/tests.
    #[arg(long)]
    once: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut last_seen = None;
    let mut last_notified = HashMap::new();
    loop {
        match fetch_events(&cli.socket) {
            Ok(mut events) => {
                events.sort_by_key(|event| event.id);
                let newest = events.last().map(|event| event.id);
                if let Some(previous) = last_seen {
                    let now_ms = unix_ms();
                    for event in events
                        .iter()
                        .filter(|event| event.id > previous && event.decision.contains("Deny"))
                    {
                        if !should_notify(&mut last_notified, event, now_ms) {
                            continue;
                        }
                        let (summary, body) = notification_text(event);
                        if let Err(error) = notify(&summary, &body) {
                            eprintln!("guard-notify: desktop notification failed: {error}");
                        } else {
                            // Event IDs are safe metadata and give the acceptance
                            // harness an unambiguous delivery acknowledgement.
                            eprintln!("guard-notify: delivered event_id={}", event.id);
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

type NotificationKey = (u32, String, String);

fn should_notify(
    last_notified: &mut HashMap<NotificationKey, u64>,
    event: &EventInfo,
    now_ms: u64,
) -> bool {
    const WINDOW_MS: u64 = 10_000;
    let key = (event.pid, event.exe.clone(), event.path.clone());
    if last_notified
        .get(&key)
        .is_some_and(|last| now_ms.saturating_sub(*last) < WINDOW_MS)
    {
        return false;
    }
    last_notified.insert(key, now_ms);
    true
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn fetch_events(socket: &Path) -> Result<Vec<EventInfo>, String> {
    let request = Request {
        version: PROTOCOL_VERSION,
        op: RequestOp::Events { limit: Some(100) },
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

fn notification_text(event: &EventInfo) -> (String, String) {
    let exe = Path::new(&event.exe)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| event.exe.clone());
    if event.reason_code.as_deref() == Some("migration_lease_required") {
        return (
            "Blocked cross-browser data access".into(),
            format!(
                "{exe} attempted to access protected browser data. Authorize a temporary migration access lease if this was intentional."
            ),
        );
    }
    (
        "Blocked protected-data access".into(),
        format!(
            "{exe} attempted to access {}. Access was denied.",
            event.resource_kind_code
        ),
    )
}

fn notify(summary: &str, body: &str) -> std::io::Result<()> {
    let output = Command::new("notify-send")
        .args([
            "--app-name=guardd",
            "--urgency=normal",
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

#[cfg(test)]
mod tests {
    use super::*;

    fn event(pid: u32, path: &str) -> EventInfo {
        EventInfo {
            id: 1,
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
}
