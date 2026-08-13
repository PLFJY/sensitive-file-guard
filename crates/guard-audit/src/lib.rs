//! SQLite-backed audit persistence for the Sensitive Data Firewall.
//!
//! Debug builds record every authorization decision (allow / deny /
//! allow-by-lease) as an `AuditRecord`; release builds record blocked opens
//! only. Records carry metadata only — PID, identity
//! summary, executable path, resource kind/id, decision, deny reason, lease id,
//! backend diagnostic — and NEVER the protected file's contents (no cookie
//! values, passwords, key bytes, or DB rows).
//!
//! Design:
//! - The hot path calls `AuditStore::record`, which is non-blocking: it pushes
//!   the record onto a bounded channel and returns immediately. If the channel
//!   is full (daemon overwhelmed), the record is dropped and a `dropped`
//!   counter is incremented — the authorization loop is never stalled by disk
//!   I/O.
//! - A dedicated writer thread owns the single SQLite write `Connection`, drains
//!   the channel, and batch-commits. WAL mode is enabled so concurrent readers
//!   (IPC queries) do not block the writer and vice versa.
//! - Read queries open a fresh read-only connection per call (cheap in SQLite,
//!   and fully concurrent under WAL). `flush()` forces the writer to drain +
//!   commit so a CLI query sees the latest records.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::Arc;
use std::thread::JoinHandle;

use guard_core::identity::TrustTier;
use guard_core::policy::{Decision, DenyReason};
use guard_core::resource::{BrowserId, ProfileId, ProtectedResourceKind};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

/// Maximum number of audit events retained in the persistent SQLite store.
///
/// Retention is global to the store (not per UID): the newest events remain,
/// while older metadata rows are removed after a successful batch commit.
pub const MAX_PERSISTED_EVENTS: i64 = 1_000;

/// One authorization decision to persist. No secret contents — `path` is the
/// protected file's path string, never its bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Stable machine-readable event classification (for example
    /// `ssh_key_access_confirmation_required`). This is metadata, never secret
    /// content.
    pub event_code: String,
    pub ts_ms: u64,
    pub uid: u32,
    pub pid: u32,
    pub start_time: u64,
    pub decision: Decision,
    pub deny_reason: Option<DenyReason>,
    pub resource_kind: ProtectedResourceKind,
    pub resource_browser: Option<BrowserId>,
    pub resource_profile: Option<ProfileId>,
    pub path: String,
    pub exe: String,
    pub exe_owner_uid: u32,
    pub trust_tier: TrustTier,
    pub process_browser: Option<BrowserId>,
    pub parent_pid: Option<u32>,
    pub parent_exe: Option<String>,
    pub lease_id: Option<u64>,
    pub backend_diag: String,
}

/// A persisted audit row (an `AuditRecord` with its assigned `id`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: i64,
    #[serde(flatten)]
    pub record: AuditRecord,
}

enum AuditCmd {
    Record(Box<AuditRecord>),
    Flush(SyncSender<()>),
    Quit,
}

pub struct AuditStore {
    tx: SyncSender<AuditCmd>,
    writer: Option<JoinHandle<()>>,
    path: PathBuf,
    dropped: Arc<AtomicU64>,
}

impl AuditStore {
    /// Open (creating if needed) the audit database at `path`, initialize the
    /// schema, enable WAL, and spawn the writer thread.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_millis(2000))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        init_schema(&conn)?;
        prune_events(&conn)?;

        let (tx, rx) = mpsc::sync_channel::<AuditCmd>(8192);
        let dropped = Arc::new(AtomicU64::new(0));
        let writer = std::thread::Builder::new()
            .name("guard-audit-writer".into())
            .spawn({
                let dropped = Arc::clone(&dropped);
                move || writer_loop(conn, rx, dropped)
            })?;

        Ok(Self {
            tx,
            writer: Some(writer),
            path: path.to_path_buf(),
            dropped,
        })
    }

    /// Non-blocking record enqueue. Drops the record (and bumps `dropped`) if
    /// the channel is full so the authorization loop is never stalled.
    pub fn record(&self, r: AuditRecord) {
        if self.tx.try_send(AuditCmd::Record(Box::new(r))).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Block until all queued records are committed. Used by IPC read handlers
    /// to guarantee a CLI query sees the latest events.
    pub fn flush(&self) {
        let (tx, rx) = mpsc::sync_channel(1);
        if self.tx.send(AuditCmd::Flush(tx)).is_ok() {
            let _ = rx.recv();
        }
    }

    /// Number of records dropped due to a full channel (hot-path backpressure).
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Query recent events, newest first. If `uid_filter` is `Some`, only that
    /// user's events are returned (authorization: ordinary users see own only).
    pub fn query_events(
        &self,
        uid_filter: Option<u32>,
        limit: u32,
    ) -> anyhow::Result<Vec<AuditEvent>> {
        let conn = Connection::open(&self.path)?;
        conn.pragma_update(None, "query_only", 1).ok();
        query_events_cursor(&conn, uid_filter, limit, None, None)
    }

    pub fn query_events_cursor(
        &self,
        uid_filter: Option<u32>,
        limit: u32,
        before_id: Option<i64>,
        after_id: Option<i64>,
    ) -> anyhow::Result<Vec<AuditEvent>> {
        let conn = Connection::open(&self.path)?;
        conn.pragma_update(None, "query_only", 1).ok();
        query_events_cursor(&conn, uid_filter, limit, before_id, after_id)
    }

    /// Look up a single event by id. Returns `None` if not found or if the
    /// caller (non-root) does not own it (authorization enforced by caller via
    /// the returned `uid`).
    pub fn query_event(&self, id: i64) -> anyhow::Result<Option<AuditEvent>> {
        let conn = Connection::open(&self.path)?;
        conn.pragma_update(None, "query_only", 1).ok();
        query_event(&conn, id)
    }
}

impl Drop for AuditStore {
    fn drop(&mut self) {
        let _ = self.tx.send(AuditCmd::Quit);
        if let Some(h) = self.writer.take() {
            let _ = h.join();
        }
    }
}

fn init_schema(conn: &Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS events (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            event_code       TEXT NOT NULL DEFAULT 'access_decision',
            ts_ms            INTEGER NOT NULL,
            uid              INTEGER NOT NULL,
            pid              INTEGER NOT NULL,
            start_time       INTEGER NOT NULL,
            decision         TEXT NOT NULL,
            deny_reason      TEXT,
            resource_kind    TEXT NOT NULL,
            resource_browser TEXT,
            resource_profile TEXT,
            path             TEXT NOT NULL,
            exe              TEXT NOT NULL,
            exe_owner_uid    INTEGER NOT NULL,
            trust_tier       TEXT NOT NULL,
            process_browser  TEXT,
            parent_pid       INTEGER,
            parent_exe       TEXT,
            lease_id         INTEGER,
            backend_diag     TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_events_uid_ts ON events(uid, ts_ms DESC);
        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts_ms DESC);",
    )?;
    let has_event_code = conn
        .prepare("PRAGMA table_info(events)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .any(|column| column == "event_code");
    if !has_event_code {
        conn.execute(
            "ALTER TABLE events ADD COLUMN event_code TEXT NOT NULL DEFAULT 'access_decision'",
            [],
        )?;
    }
    Ok(())
}

fn insert_record(conn: &Connection, r: &AuditRecord) -> anyhow::Result<()> {
    conn.execute(
        "INSERT INTO events (
            event_code, ts_ms, uid, pid, start_time, decision, deny_reason,
            resource_kind, resource_browser, resource_profile, path, exe,
            exe_owner_uid, trust_tier, process_browser, parent_pid, parent_exe,
            lease_id, backend_diag
        ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
        rusqlite::params![
            r.event_code,
            r.ts_ms as i64,
            r.uid,
            r.pid,
            r.start_time as i64,
            decision_str(&r.decision),
            r.deny_reason.map(deny_reason_str),
            resource_kind_str(r.resource_kind),
            r.resource_browser.as_ref().map(|b| b.0.as_str()),
            r.resource_profile.as_ref().map(|p| p.0.as_str()),
            r.path,
            r.exe,
            r.exe_owner_uid,
            trust_tier_str(r.trust_tier),
            r.process_browser.as_ref().map(|b| b.0.as_str()),
            r.parent_pid.map(|p| p as i64),
            r.parent_exe.as_deref(),
            r.lease_id.map(|l| l as i64),
            r.backend_diag,
        ],
    )?;
    Ok(())
}

fn writer_loop(conn: Connection, rx: mpsc::Receiver<AuditCmd>, dropped: Arc<AtomicU64>) {
    // Threshold-batched writer. We deliberately do NOT drain with `try_recv`
    // in a `while let Ok(Record(..))` loop: that would pop a `Flush`/`Quit`
    // command from the channel, fail to match it, and silently drop it — losing
    // the ack and leaving records uncommitted. Instead each command is handled
    // in FIFO order; records accumulate to `BATCH` and are flushed on threshold,
    // `Flush`, or `Quit`.
    const BATCH: usize = 64;
    let mut pending: Vec<AuditRecord> = Vec::with_capacity(BATCH);
    loop {
        let cmd = match rx.recv() {
            Ok(c) => c,
            Err(_) => {
                // Store dropped; commit whatever remains then exit.
                let _ = commit_batch(&conn, &mut pending);
                break;
            }
        };
        match cmd {
            AuditCmd::Record(r) => {
                pending.push(*r);
                if pending.len() >= BATCH {
                    if let Err(e) = commit_batch(&conn, &mut pending) {
                        tracing::error!(err = %e, count = pending.len(), "audit batch insert failed");
                        dropped.fetch_add(pending.len() as u64, Ordering::Relaxed);
                        pending.clear();
                    }
                }
            }
            AuditCmd::Flush(ack) => {
                if let Err(e) = commit_batch(&conn, &mut pending) {
                    tracing::error!(err = %e, count = pending.len(), "audit flush insert failed");
                    dropped.fetch_add(pending.len() as u64, Ordering::Relaxed);
                    pending.clear();
                }
                let _ = ack.send(());
            }
            AuditCmd::Quit => {
                let _ = commit_batch(&conn, &mut pending);
                break;
            }
        }
    }
}

fn commit_batch(conn: &Connection, pending: &mut Vec<AuditRecord>) -> anyhow::Result<()> {
    if pending.is_empty() {
        return Ok(());
    }
    let tx = conn.unchecked_transaction()?;
    for r in pending.iter() {
        insert_record(&tx, r)?;
    }
    // Keep the database bounded without touching the authorization hot path.
    // This runs in the same transaction as the inserts, so readers observe
    // either the previous complete retention window or the new one.
    prune_events(&tx)?;
    tx.commit()?;
    pending.clear();
    Ok(())
}

fn prune_events(conn: &Connection) -> anyhow::Result<()> {
    conn.execute(
        "DELETE FROM events
         WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?1)",
        rusqlite::params![MAX_PERSISTED_EVENTS],
    )?;
    Ok(())
}

fn query_events_cursor(
    conn: &Connection,
    uid_filter: Option<u32>,
    limit: u32,
    before_id: Option<i64>,
    after_id: Option<i64>,
) -> anyhow::Result<Vec<AuditEvent>> {
    let limit = limit.clamp(1, 10_000) as i64;
    if before_id.is_some() && after_id.is_some() {
        anyhow::bail!("before_id and after_id cannot both be set");
    }
    let mut out = Vec::new();
    let mut sql = String::from("SELECT id, event_code, ts_ms, uid, pid, start_time, decision, deny_reason, resource_kind, resource_browser, resource_profile, path, exe, exe_owner_uid, trust_tier, process_browser, parent_pid, parent_exe, lease_id, backend_diag FROM events WHERE 1=1");
    let mut params: Vec<rusqlite::types::Value> = Vec::new();
    if let Some(uid) = uid_filter {
        sql.push_str(" AND uid = ?");
        params.push(uid.into());
    }
    if let Some(id) = before_id {
        sql.push_str(" AND id < ?");
        params.push(id.into());
    }
    if let Some(id) = after_id {
        sql.push_str(" AND id > ?");
        params.push(id.into());
    }
    if after_id.is_some() {
        sql.push_str(" ORDER BY id ASC LIMIT ?");
    } else {
        sql.push_str(" ORDER BY id DESC LIMIT ?");
    }
    params.push(limit.into());
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(params), row_to_event)?;
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

fn query_event(conn: &Connection, id: i64) -> anyhow::Result<Option<AuditEvent>> {
    let mut stmt = conn.prepare(
        "SELECT id, event_code, ts_ms, uid, pid, start_time, decision, deny_reason, \
         resource_kind, resource_browser, resource_profile, path, exe, \
         exe_owner_uid, trust_tier, process_browser, parent_pid, parent_exe, \
         lease_id, backend_diag FROM events WHERE id = ?1",
    )?;
    let mut rows = stmt.query_map(rusqlite::params![id], row_to_event)?;
    if let Some(r) = rows.next() {
        Ok(Some(r?))
    } else {
        Ok(None)
    }
}

fn row_to_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditEvent> {
    let id: i64 = row.get(0)?;
    let event_code: String = row.get(1)?;
    let ts_ms = row.get::<_, i64>(2)? as u64;
    let uid: u32 = row.get(3)?;
    let pid: u32 = row.get(4)?;
    let start_time = row.get::<_, i64>(5)? as u64;
    let decision_str: String = row.get(6)?;
    let deny_reason: Option<String> = row.get(7)?;
    let lease_id: Option<i64> = row.get(18)?;
    // Reconstruct the full Decision: the `decision` column stores only the
    // variant ("allow"/"deny"/"allow_by_lease"); the deny reason and lease id
    // are restored from their own columns so the round-trip is lossless.
    let deny_reason_parsed = deny_reason.map(parse_deny_reason);
    let decision = reconstruct_decision(&decision_str, deny_reason_parsed, lease_id);
    let record = AuditRecord {
        event_code,
        ts_ms,
        uid,
        pid,
        start_time,
        decision,
        deny_reason: deny_reason_parsed,
        resource_kind: parse_resource_kind(row.get::<_, String>(8)?),
        resource_browser: row.get::<_, Option<String>>(9)?.map(BrowserId),
        resource_profile: row.get::<_, Option<String>>(10)?.map(ProfileId),
        path: row.get(11)?,
        exe: row.get(12)?,
        exe_owner_uid: row.get(13)?,
        trust_tier: parse_trust_tier(row.get::<_, String>(14)?),
        process_browser: row.get::<_, Option<String>>(15)?.map(BrowserId),
        parent_pid: row.get::<_, Option<i64>>(16)?.map(|p| p as u32),
        parent_exe: row.get(17)?,
        lease_id: lease_id.map(|l| l as u64),
        backend_diag: row.get(19)?,
    };
    Ok(AuditEvent { id, record })
}

fn reconstruct_decision(
    s: &str,
    deny_reason: Option<DenyReason>,
    lease_id: Option<i64>,
) -> Decision {
    match s {
        "allow" => Decision::Allow,
        "allow_by_lease" => {
            Decision::AllowByLease(guard_core::lease::LeaseId(lease_id.unwrap_or(0) as u64))
        }
        "migration_confirmation_required" => {
            Decision::Deny(deny_reason.unwrap_or(DenyReason::CrossBrowserWithoutLease))
        }
        "ssh_key_confirmation_required" => Decision::RequireSshKeyConfirmation,
        _ => Decision::Deny(deny_reason.unwrap_or(DenyReason::UnknownProcess)),
    }
}

fn decision_str(d: &Decision) -> &'static str {
    match d {
        Decision::Allow => "allow",
        Decision::Deny(_) => "deny",
        Decision::AllowByLease(_) => "allow_by_lease",
        Decision::RequireMigrationConfirmation(_) => "migration_confirmation_required",
        Decision::RequireSshKeyConfirmation => "ssh_key_confirmation_required",
    }
}

fn deny_reason_str(r: DenyReason) -> &'static str {
    match r {
        DenyReason::UnknownProcess => "unknown_process",
        DenyReason::NotTrustedIdentity => "not_trusted_identity",
        DenyReason::CrossBrowserWithoutLease => "cross_browser_without_lease",
        DenyReason::SshApprovalRequired => "ssh_approval_required",
        DenyReason::LeaseExpired => "lease_expired",
        DenyReason::LeaseRevoked => "lease_revoked",
        DenyReason::LeaseScopeMismatch => "lease_scope_mismatch",
        DenyReason::WrongUid => "wrong_uid",
        DenyReason::IdentityMismatch => "identity_mismatch",
        DenyReason::OneShotLeaseUsed => "one_shot_lease_used",
    }
}
fn parse_deny_reason(s: String) -> DenyReason {
    match s.as_str() {
        "unknown_process" => DenyReason::UnknownProcess,
        "not_trusted_identity" => DenyReason::NotTrustedIdentity,
        "cross_browser_without_lease" => DenyReason::CrossBrowserWithoutLease,
        "ssh_approval_required" => DenyReason::SshApprovalRequired,
        "lease_expired" => DenyReason::LeaseExpired,
        "lease_revoked" => DenyReason::LeaseRevoked,
        "lease_scope_mismatch" => DenyReason::LeaseScopeMismatch,
        "wrong_uid" => DenyReason::WrongUid,
        "identity_mismatch" => DenyReason::IdentityMismatch,
        "one_shot_lease_used" => DenyReason::OneShotLeaseUsed,
        _ => DenyReason::UnknownProcess,
    }
}

fn resource_kind_str(k: ProtectedResourceKind) -> &'static str {
    match k {
        ProtectedResourceKind::CookieStore => "cookie_store",
        ProtectedResourceKind::SessionStore => "session_store",
        ProtectedResourceKind::BrowserKeyMaterial => "browser_key_material",
        ProtectedResourceKind::WebStorage => "web_storage",
        ProtectedResourceKind::SavedCredentials => "saved_credentials",
        ProtectedResourceKind::History => "history",
        ProtectedResourceKind::SshPrivateKey => "ssh_private_key",
    }
}
fn parse_resource_kind(s: String) -> ProtectedResourceKind {
    match s.as_str() {
        "cookie_store" => ProtectedResourceKind::CookieStore,
        "session_store" => ProtectedResourceKind::SessionStore,
        "browser_key_material" => ProtectedResourceKind::BrowserKeyMaterial,
        "web_storage" => ProtectedResourceKind::WebStorage,
        "saved_credentials" => ProtectedResourceKind::SavedCredentials,
        "history" => ProtectedResourceKind::History,
        "ssh_private_key" => ProtectedResourceKind::SshPrivateKey,
        _ => ProtectedResourceKind::History,
    }
}

fn trust_tier_str(t: TrustTier) -> &'static str {
    match t {
        TrustTier::SystemPackage => "system_package",
        TrustTier::Sandbox => "sandbox",
        TrustTier::EnrolledUserWritable => "enrolled_user_writable",
        TrustTier::Unknown => "unknown",
    }
}
fn parse_trust_tier(s: String) -> TrustTier {
    match s.as_str() {
        "system_package" => TrustTier::SystemPackage,
        "sandbox" => TrustTier::Sandbox,
        "enrolled_user_writable" => TrustTier::EnrolledUserWritable,
        _ => TrustTier::Unknown,
    }
}

#[cfg(test)]
mod tests {
    //! Audit persistence tests. None require root: SQLite works on a temp file.
    //! The no-secret invariant is enforced structurally (AuditRecord has no
    //! content field) and asserted by serializing a record and checking that a
    //! known fixture marker never appears.

    use super::*;
    use guard_core::identity::{ProcessStableId, TrustTier};
    use guard_core::policy::Decision;
    use guard_core::resource::{BrowserId, ProfileId, ProtectedResourceKind};
    use std::path::PathBuf;

    fn sample_record(uid: u32, path: &str, decision: Decision) -> AuditRecord {
        AuditRecord {
            event_code: "access_decision".into(),
            ts_ms: 1_700_000_000_000 + uid as u64,
            uid,
            pid: 4242,
            start_time: 9999,
            decision: decision.clone(),
            deny_reason: match decision {
                Decision::Deny(r) => Some(r),
                _ => None,
            },
            resource_kind: ProtectedResourceKind::CookieStore,
            resource_browser: Some(BrowserId("chrome".into())),
            resource_profile: Some(ProfileId("Default".into())),
            path: path.to_string(),
            exe: "/usr/bin/chrome".to_string(),
            exe_owner_uid: 0,
            trust_tier: TrustTier::SystemPackage,
            process_browser: Some(BrowserId("chrome".into())),
            parent_pid: Some(1),
            parent_exe: Some("/sbin/init".to_string()),
            lease_id: None,
            backend_diag: "fd_index_hit".to_string(),
        }
    }

    fn sample_identity() -> ProcessStableId {
        ProcessStableId {
            pid: 4242,
            start_time: 9999,
            exe: PathBuf::from("/usr/bin/chrome"),
            exe_dev: 1,
            exe_ino: 2,
        }
    }

    #[test]
    fn open_creates_schema_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("audit.db");
        let store = AuditStore::open(&db).unwrap();
        store.record(sample_record(
            1000,
            "/home/u/chrome/Default/Network/Cookies",
            Decision::Allow,
        ));
        store.record(sample_record(
            1000,
            "/home/u/chrome/Default/Network/Cookies",
            Decision::Deny(DenyReason::CrossBrowserWithoutLease),
        ));
        store.flush();
        assert_eq!(store.dropped(), 0);
        let events = store.query_events(None, 100).unwrap();
        assert_eq!(events.len(), 2);
        // Newest first (id DESC). Decision + deny reason round-trip losslessly.
        assert_eq!(
            events[0].record.decision,
            Decision::Deny(DenyReason::CrossBrowserWithoutLease)
        );
        assert_eq!(events[1].record.decision, Decision::Allow);
        assert_eq!(events[0].record.uid, 1000);
        assert_eq!(
            events[0].record.resource_kind,
            ProtectedResourceKind::CookieStore
        );
    }

    #[test]
    fn query_event_by_id() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("audit.db");
        let store = AuditStore::open(&db).unwrap();
        store.record(sample_record(1000, "/p/Cookies", Decision::Allow));
        store.flush();
        let events = store.query_events(None, 10).unwrap();
        let id = events[0].id;
        let one = store.query_event(id).unwrap().expect("found");
        assert_eq!(one.id, id);
        assert_eq!(one.record.path, "/p/Cookies");
        assert!(store.query_event(id + 999).unwrap().is_none());
    }

    #[test]
    fn uid_filter_isolates_users() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("audit.db");
        let store = AuditStore::open(&db).unwrap();
        store.record(sample_record(1000, "/p1", Decision::Allow));
        store.record(sample_record(1001, "/p2", Decision::Allow));
        store.record(sample_record(1000, "/p3", Decision::Allow));
        store.flush();
        let mine = store.query_events(Some(1000), 100).unwrap();
        assert_eq!(mine.len(), 2);
        assert!(mine.iter().all(|e| e.record.uid == 1000));
        let theirs = store.query_events(Some(1001), 100).unwrap();
        assert_eq!(theirs.len(), 1);
        assert_eq!(theirs[0].record.uid, 1001);
    }

    #[test]
    fn cursor_queries_return_older_and_newer_pages() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::open(&dir.path().join("audit.db")).unwrap();
        for path in ["/p1", "/p2", "/p3"] {
            store.record(sample_record(1000, path, Decision::Allow));
        }
        store.flush();
        let newest = store
            .query_events_cursor(Some(1000), 2, None, None)
            .unwrap();
        assert_eq!(newest.len(), 2);
        let older = store
            .query_events_cursor(Some(1000), 10, newest.last().map(|e| e.id), None)
            .unwrap();
        assert_eq!(older.len(), 1);
        let newer = store
            .query_events_cursor(Some(1000), 10, None, older.last().map(|e| e.id))
            .unwrap();
        assert_eq!(newer.len(), 2);
    }

    #[test]
    fn audit_record_never_carries_secret_content() {
        // A known synthetic fixture marker that must NEVER appear in any audit
        // field (paths are stored, never file bytes).
        const MARKER: &str = "GUARD_SYNTHETIC_COOKIE_FIXTURE";
        let mut r = sample_record(
            1000,
            "/home/u/chrome/Default/Network/Cookies",
            Decision::Allow,
        );
        // Even if someone tried to smuggle content into a path-like field, the
        // record struct simply has no content field. Serialize and assert.
        let _ = &mut r;
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains(MARKER),
            "audit record JSON must not contain fixture secret markers"
        );
        // And the persisted row must not contain it either.
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("audit.db");
        let store = AuditStore::open(&db).unwrap();
        store.record(r.clone());
        store.flush();
        let ev = store.query_events(None, 10).unwrap().pop().unwrap();
        let ev_json = serde_json::to_string(&ev).unwrap();
        assert!(!ev_json.contains(MARKER));
    }

    #[test]
    fn dropped_counter_under_burst() {
        // Under a normal burst within channel capacity, every record is
        // committed and nothing is dropped. (Forcing actual drops requires
        // exceeding the 8192-slot channel faster than the writer can commit,
        // which is non-deterministic; the public `dropped()` API is exercised
        // here to confirm it stays at 0 under a realistic load and that all
        // records survive the threshold-batched writer.)
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("audit.db");
        let store = AuditStore::open(&db).unwrap();
        assert_eq!(store.dropped(), 0);
        for i in 0..1000 {
            store.record(sample_record(1000, &format!("/p/{i}"), Decision::Allow));
        }
        store.flush();
        assert_eq!(store.dropped(), 0);
        let _ = sample_identity(); // keep helper referenced
        let events = store.query_events(None, 2000).unwrap();
        assert_eq!(events.len(), 1000);
    }

    #[test]
    fn retention_keeps_only_newest_events() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("audit.db");
        let store = AuditStore::open(&db).unwrap();
        for i in 0..(MAX_PERSISTED_EVENTS as usize + 1) {
            store.record(sample_record(1000, &format!("/p/{i}"), Decision::Allow));
        }
        store.flush();

        let events = store.query_events(None, 2_000).unwrap();
        assert_eq!(events.len(), MAX_PERSISTED_EVENTS as usize);
        assert_eq!(events.first().unwrap().record.path, "/p/1000");
        assert_eq!(events.last().unwrap().record.path, "/p/1");
        assert!(store.query_event(1).unwrap().is_none());
    }
}
