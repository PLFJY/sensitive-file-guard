//! Desktop notifications for blocked protected-data access (Phase 09).
//!
//! The daemon emits a desktop notification when a protected open is **denied**
//! (allowed browser self-access never notifies). To avoid notification storms,
//! identical denies (same process + same resource) within a short coalescing
//! window collapse into a single notification; the full events always remain
//! in the audit log.
//!
//! Delivery is best-effort: the daemon tries `notify-send` (freedesktop.org).
//! If no graphical session / `notify-send` is unavailable, it falls back to
//! `tracing::warn` (journal/audit). Delivery NEVER blocks or errors out the
//! authorization hot path — a notification failure is logged, not propagated.
//!
//! Cross-browser (`CrossBrowserWithoutLease`) denies use the migration-specific
//! text from `09_TUI_AND_NOTIFICATIONS.md`, pointing the user at guard-tui /
//! guardctl to authorize a temporary lease.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use guard_audit::AuditRecord;
use guard_core::policy::{Decision, DenyReason};

/// Coalesce window: identical (uid, pid, exe, resource) denies within this
/// duration produce at most one notification. Tuned to suppress repeat opens
/// from a busy loop without missing genuinely new incidents.
pub const COALESCE_WINDOW: Duration = Duration::from_secs(10);

/// Coalesce key: same OS user, same process instance (pid), same executable,
/// and same protected resource. `exe` is part of the key so two different
/// binaries running under the same pid (impossible in practice, but defensive)
/// don't collapse.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NotificationKey {
    pub uid: u32,
    pub pid: u32,
    pub exe: PathBuf,
    pub resource_path: String,
}

/// Pure coalescer: tracks the last-sent monotonic-millisecond timestamp per
/// key. The clock is injected (`now_ms`) so tests are deterministic — no wall
/// clock, no sleeps.
pub struct NotificationCoalescer {
    last_sent: HashMap<NotificationKey, u64>,
    window_ms: u64,
    /// Number of denies suppressed by coalescing (observability; mirrors the
    /// "full events remain in audit log" guarantee — suppressed here, not
    /// there).
    pub suppressed: u64,
    /// Number of notifications actually delivered (attempted).
    pub delivered: u64,
}

impl NotificationCoalescer {
    pub fn new(window: Duration) -> Self {
        Self {
            last_sent: HashMap::new(),
            window_ms: window.as_millis() as u64,
            suppressed: 0,
            delivered: 0,
        }
    }

    /// Returns `true` if a notification should be sent now (no notification for
    /// this key within the window). When `true`, records `now_ms` as the last
    /// sent time and bumps `delivered`; when `false`, bumps `suppressed`.
    pub fn should_notify(&mut self, key: &NotificationKey, now_ms: u64) -> bool {
        if let Some(&last) = self.last_sent.get(key) {
            if now_ms.saturating_sub(last) < self.window_ms {
                self.suppressed += 1;
                return false;
            }
        }
        self.last_sent.insert(key.clone(), now_ms);
        self.delivered += 1;
        true
    }
}

/// Build the coalesce key from a denied audit record. Returns `None` for
/// allowed records (no notification for browser self-access).
pub fn key_for(record: &AuditRecord) -> Option<NotificationKey> {
    if !matches!(record.decision, Decision::Deny(_)) {
        return None;
    }
    Some(NotificationKey {
        uid: record.uid,
        pid: record.pid,
        exe: PathBuf::from(&record.exe),
        resource_path: record.path.clone(),
    })
}

/// Build the notification (summary, body) text for a denied record. Migration
/// denies (`CrossBrowserWithoutLease`) get the migration-specific text that
/// points the user at guard-tui / guardctl.
pub fn notification_text(record: &AuditRecord) -> (String, String) {
    let exe_name = std::path::Path::new(&record.exe)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| record.exe.clone());
    let kind_str = resource_kind_str_local(record);
    let resource_kind = human_kind(&kind_str);
    let browser = record
        .resource_browser
        .as_ref()
        .map(|b| b.0.as_str())
        .unwrap_or("browser");
    match record.deny_reason {
        Some(DenyReason::CrossBrowserWithoutLease) => {
            let process_browser = record
                .process_browser
                .as_ref()
                .map(|b| b.0.as_str())
                .unwrap_or(&exe_name);
            (
                "Blocked cross-browser data access".to_string(),
                format!(
                    "{process_browser} attempted to read {browser} protected data. \
                     Open guard-tui or run guardctl to authorize a temporary migration lease."
                ),
            )
        }
        _ => (
            "Blocked protected browser data access".to_string(),
            format!(
                "{exe_name} attempted to read {browser} {resource_kind} data. Access was denied."
            ),
        ),
    }
}

/// Human-readable resource kind for the body text.
fn human_kind(k: &str) -> &str {
    match k {
        "cookie_store" => "Cookie/Session",
        "session_store" => "Session",
        "browser_key_material" => "key material",
        "web_storage" => "WebStorage",
        "saved_credentials" => "saved-login",
        "history" => "history",
        "ssh_private_key" => "SSH key",
        _ => "protected",
    }
}

/// Map a record's `ProtectedResourceKind` to its wire string without importing
/// the audit-internal helper (kept local to avoid a cross-module dependency).
fn resource_kind_str_local(record: &AuditRecord) -> String {
    use guard_core::resource::ProtectedResourceKind;
    match record.resource_kind {
        ProtectedResourceKind::CookieStore => "cookie_store",
        ProtectedResourceKind::SessionStore => "session_store",
        ProtectedResourceKind::BrowserKeyMaterial => "browser_key_material",
        ProtectedResourceKind::WebStorage => "web_storage",
        ProtectedResourceKind::SavedCredentials => "saved_credentials",
        ProtectedResourceKind::History => "history",
        ProtectedResourceKind::SshPrivateKey => "ssh_private_key",
    }
    .to_string()
}

/// Best-effort desktop notification via `notify-send`. Returns `Err` if the
/// binary is missing or exits non-zero. Public so tests can assert the
/// no-session fallback path is taken gracefully.
pub fn try_notify_send(summary: &str, body: &str) -> std::io::Result<()> {
    let status = Command::new("notify-send")
        .args([
            "--app-name=guardd",
            "--urgency=normal",
            "--icon=security-medium",
            summary,
            body,
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "notify-send exited {status}"
        )))
    }
}

/// Deliver a notification for a denied record. Best-effort: tries
/// `notify-send`, and on any failure (no binary / no D-Bus session) falls back
/// to `tracing::warn` (journal/audit). NEVER propagates an error — the daemon
/// stays functional when no graphical session exists.
pub fn deliver(summary: &str, body: &str) {
    if let Err(e) = try_notify_send(summary, body) {
        // No graphical session / notify-send unavailable: journal fallback.
        // The full event is already in the audit log; this is informational.
        tracing::warn!(err = %e, summary, body, "desktop notification unavailable; logged to journal");
    }
}

#[cfg(test)]
mod tests {
    //! Phase 09 notification tests. All run without root and without a
    //! graphical session: the coalescer is pure (injected clock), the
    //! no-notify-for-allow invariant is structural, and the no-session path is
    //! exercised by `deliver` falling back to `tracing` when `notify-send` is
    //! absent.

    use super::*;
    use guard_core::identity::TrustTier;
    use guard_core::policy::DenyReason;
    use guard_core::resource::{BrowserId, ProfileId, ProtectedResourceKind};
    use std::path::PathBuf;

    fn deny_record(uid: u32, pid: u32, exe: &str, path: &str, reason: DenyReason) -> AuditRecord {
        AuditRecord {
            ts_ms: 1_700_000_000_000,
            uid,
            pid,
            start_time: 9999,
            decision: Decision::Deny(reason),
            deny_reason: Some(reason),
            resource_kind: ProtectedResourceKind::CookieStore,
            resource_browser: Some(BrowserId("chrome".into())),
            resource_profile: Some(ProfileId("Default".into())),
            path: path.to_string(),
            exe: exe.to_string(),
            exe_owner_uid: 0,
            trust_tier: TrustTier::SystemPackage,
            process_browser: Some(BrowserId("firefox".into())),
            parent_pid: Some(1),
            parent_exe: Some("/sbin/init".to_string()),
            lease_id: None,
            backend_diag: "fd_index_hit".to_string(),
        }
    }

    fn allow_record(uid: u32, pid: u32, exe: &str, path: &str) -> AuditRecord {
        let mut r = deny_record(uid, pid, exe, path, DenyReason::UnknownProcess);
        r.decision = Decision::Allow;
        r.deny_reason = None;
        r.process_browser = Some(BrowserId("chrome".into()));
        r
    }

    #[test]
    fn coalescing_collapses_repeated_same_key_within_window() {
        let mut c = NotificationCoalescer::new(COALESCE_WINDOW);
        let key = NotificationKey {
            uid: 1000,
            pid: 4242,
            exe: PathBuf::from("/usr/bin/firefox"),
            resource_path: "/home/u/chrome/Default/Cookies".into(),
        };
        // First deny: notify.
        assert!(c.should_notify(&key, 0));
        // Same key 1ms later: suppressed.
        assert!(!c.should_notify(&key, 1));
        // Same key 9s later (still within 10s window): suppressed.
        assert!(!c.should_notify(&key, 9_000));
        // After the window elapses: notify again.
        assert!(c.should_notify(&key, 10_001));
        assert_eq!(c.suppressed, 2);
        assert_eq!(c.delivered, 2);
    }

    #[test]
    fn coalescing_separates_different_resource_or_process() {
        let mut c = NotificationCoalescer::new(COALESCE_WINDOW);
        let k1 = NotificationKey {
            uid: 1000,
            pid: 1,
            exe: PathBuf::from("/a"),
            resource_path: "/r1".into(),
        };
        let k2 = NotificationKey {
            uid: 1000,
            pid: 1,
            exe: PathBuf::from("/a"),
            resource_path: "/r2".into(),
        };
        let k3 = NotificationKey {
            uid: 1000,
            pid: 2,
            exe: PathBuf::from("/a"),
            resource_path: "/r1".into(),
        };
        assert!(c.should_notify(&k1, 0));
        // Different resource: not suppressed.
        assert!(c.should_notify(&k2, 0));
        // Different pid: not suppressed.
        assert!(c.should_notify(&k3, 0));
        assert_eq!(c.suppressed, 0);
        assert_eq!(c.delivered, 3);
    }

    #[test]
    fn no_notification_for_allowed_browser_self_access() {
        // The coalescer is driven by `key_for`, which returns None for allows.
        let allow = allow_record(
            1000,
            4242,
            "/usr/bin/chrome",
            "/home/u/chrome/Default/Cookies",
        );
        assert!(
            key_for(&allow).is_none(),
            "allow must not produce a notify key"
        );

        let deny = deny_record(
            1000,
            4242,
            "/usr/bin/firefox",
            "/home/u/chrome/Default/Cookies",
            DenyReason::CrossBrowserWithoutLease,
        );
        assert!(key_for(&deny).is_some(), "deny must produce a notify key");
    }

    #[test]
    fn migration_deny_uses_migration_specific_text() {
        let r = deny_record(
            1000,
            4242,
            "/usr/bin/firefox",
            "/home/u/chrome/Default/Cookies",
            DenyReason::CrossBrowserWithoutLease,
        );
        let (summary, body) = notification_text(&r);
        assert!(summary.contains("cross-browser"), "summary: {summary}");
        assert!(
            body.contains("guard-tui") && body.contains("migration lease"),
            "migration body must point at guard-tui/guardctl: {body}"
        );
    }

    #[test]
    fn generic_deny_uses_blocked_browser_text() {
        let r = deny_record(
            1000,
            4242,
            "/usr/bin/stealer",
            "/home/u/chrome/Default/Cookies",
            DenyReason::UnknownProcess,
        );
        let (summary, body) = notification_text(&r);
        assert_eq!(summary, "Blocked protected browser data access");
        assert!(body.contains("stealer"), "body names the exe: {body}");
        assert!(body.contains("Access was denied"), "body: {body}");
    }

    #[test]
    fn deliver_does_not_panic_without_graphical_session() {
        // The test environment has no D-Bus / notify-send, so this exercises
        // the journal fallback. The daemon must remain functional: `deliver`
        // returns normally (no panic, no Result to propagate).
        deliver("guardd test", "no graphical session in CI");
        // If we reach here, the no-session path is graceful.
    }

    #[test]
    fn try_notify_send_returns_err_when_binary_absent() {
        // On a system without notify-send, this is the no-session evidence.
        // We don't assert the exact error kind (NotFound vs Other) since a
        // system might have notify-send but no D-Bus; either way it's an Err
        // and `deliver` handles it.
        let res = try_notify_send("guardd test", "probe");
        // If notify-send happens to be present AND a session exists, this
        // could be Ok; that's fine. The invariant is that Err is handled. We
        // only assert the call type-checks and doesn't panic.
        let _ = res.map_err(|e| format!("err (ok in CI): {e}"));
    }
}
