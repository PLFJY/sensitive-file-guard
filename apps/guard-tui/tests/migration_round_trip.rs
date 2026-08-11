//! Phase 09 TUI integration test: the TUI's IPC client can grant and revoke a
//! synthetic migration lease against a mock daemon IPC server.
//!
//! This exercises the full framed Unix-socket round-trip on the client side
//! (serialize `MigrationAuthorize` -> send -> read -> parse `MigrationAuthorized`,
//! then `LeasesRevoke` -> `LeaseRevoked`) without needing the real privileged
//! daemon or a terminal. The mock server uses the client crate's framing test
//! helpers and returns canned responses, proving the TUI client sends the right
//! ops and parses the right bodies.

use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use guard_client::transport::{read_frame, write_frame};
use guard_ipc::{MigrationAuthorizedInfo, Request, RequestOp, Response, ResponseBody};

fn bind(path: &std::path::Path) -> UnixListener {
    let _ = std::fs::remove_file(path);
    UnixListener::bind(path).unwrap()
}

/// Run a mock IPC server that handles exactly `expected` requests, returning a
/// canned `MigrationAuthorized` for `MigrationAuthorize` and `LeaseRevoked` for
/// `LeasesRevoke`. Records the parsed request ops so the test can assert them.
fn run_mock_server(
    path: PathBuf,
    expected: usize,
    seen: Arc<std::sync::Mutex<Vec<RequestOp>>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let server = bind(&path);
        for _ in 0..expected {
            let (mut stream, _addr) = match server.accept() {
                Ok(c) => c,
                Err(_) => continue,
            };
            let req_bytes = match read_frame(&mut stream, 64 * 1024) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let req: Request = match serde_json::from_slice(&req_bytes) {
                Ok(r) => r,
                Err(_) => continue,
            };
            seen.lock().unwrap().push(req.op.clone());
            let resp = mock_response(&req.op);
            let resp_bytes = serde_json::to_vec(&resp).unwrap();
            let _ = write_frame(&mut stream, &resp_bytes);
        }
    })
}

fn mock_response(op: &RequestOp) -> Response {
    match op {
        RequestOp::MigrationAuthorize {
            source_browser,
            source_profile,
            target_browser,
            ..
        } => Response::ok(ResponseBody::MigrationAuthorized(MigrationAuthorizedInfo {
            lease_id: "42".into(),
            source_browser: source_browser.clone(),
            source_profile: source_profile.clone(),
            target_browser: target_browser.clone(),
            target_exe: "/usr/bin/firefox".into(),
            uid: 1000,
            expires_at: 17_000_000_600,
            read_only_guaranteed: false,
        })),
        RequestOp::LeasesRevoke { lease_id } => Response::ok(ResponseBody::LeaseRevoked {
            lease_id: lease_id.clone(),
            found: true,
        }),
        _ => Response::err("unexpected op"),
    }
}

fn tmp_socket() -> (PathBuf, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    (dir.path().join("guardd.sock"), dir)
}

fn wait_for_socket(path: &std::path::Path) {
    for _ in 0..200 {
        if path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(5));
    }
    panic!("socket never appeared: {}", path.display());
}

#[test]
fn tui_client_grants_then_revokes_synthetic_migration_lease() {
    let (sock, _t) = tmp_socket();
    let seen: Arc<std::sync::Mutex<Vec<RequestOp>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let handle = run_mock_server(sock.clone(), 2, Arc::clone(&seen));
    wait_for_socket(&sock);

    // Grant: the TUI client sends MigrationAuthorize and parses MigrationAuthorized.
    let granted =
        guard_tui::client::migration_authorize(&sock, "chrome", "Default", "firefox", Some(600))
            .expect("migration_authorize round-trip");
    assert_eq!(granted.lease_id, "42");
    assert_eq!(granted.source_browser, "chrome");
    assert_eq!(granted.source_profile, "Default");
    assert_eq!(granted.target_browser, "firefox");
    assert_eq!(granted.target_exe, "/usr/bin/firefox");
    assert!(!granted.read_only_guaranteed);
    assert_eq!(granted.uid, 1000);

    // Revoke: the TUI client sends LeasesRevoke and parses LeaseRevoked.
    let (lease_id, found) =
        guard_tui::client::lease_revoke(&sock, "42").expect("lease_revoke round-trip");
    assert_eq!(lease_id, "42");
    assert!(found);

    handle.join().unwrap();

    // Assert the client actually sent the right ops (version + variant).
    let ops = seen.lock().unwrap();
    assert_eq!(ops.len(), 2, "exactly two requests");
    match &ops[0] {
        RequestOp::MigrationAuthorize {
            source_browser,
            source_profile,
            target_browser,
            duration_secs,
        } => {
            assert_eq!(source_browser, "chrome");
            assert_eq!(source_profile, "Default");
            assert_eq!(target_browser, "firefox");
            assert_eq!(*duration_secs, Some(600));
        }
        other => panic!("expected MigrationAuthorize, got {other:?}"),
    }
    assert!(matches!(&ops[1], RequestOp::LeasesRevoke { lease_id } if lease_id == "42"));
}

#[test]
fn tui_client_status_round_trip() {
    // Sanity: the client also parses Status, used by the TUI dashboard.
    let (sock, _t) = tmp_socket();
    let seen: Arc<std::sync::Mutex<Vec<RequestOp>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let handle = thread::spawn(move || {
        let server = bind(&sock);
        let (mut stream, _) = server.accept().unwrap();
        let req_bytes = read_frame(&mut stream, 64 * 1024).unwrap();
        let req: Request = serde_json::from_slice(&req_bytes).unwrap();
        seen.lock().unwrap().push(req.op.clone());
        let resp = Response::ok(ResponseBody::Status(guard_ipc::StatusInfo {
            version: "0.1.0".into(),
            enforcement_active: true,
            status: "ACTIVE".into(),
            mode: "conservative".into(),
            marked_filesystems: 0,
            required_filesystems: 0,
            filesystem_marks_healthy: true,
            strict_events_total: 0,
            strict_fast_allowed: 0,
            protected_events: 0,
            fanotify_overflows: 0,
            classifier_failures: 0,
            strict_alias_scans: 0,
            strict_alias_matches: 0,
            topology_degraded: false,
            protected_files: 6,
            ssh_protected_keys: 0,
            protected_trees: 2,
            browsers: 1,
            browser_exes: 1,
            allowed: 3,
            denied: 5,
            unclassified: 0,
            audit_dropped: 0,
            peer_uid: 1000,
            ssh_behavior_status: "ACTIVE".into(),
            ssh_behavior_detail: None,
            ssh_behavior_active_incidents: 0,
            ssh_behavior_pending_decisions: 0,
            ssh_behavior_key_reads: 0,
            ssh_behavior_network_blocks: 0,
            ssh_behavior_user_allows: 0,
            ssh_behavior_quarantines: 0,
            ssh_behavior_backend_failures: 0,
        }));
        let resp_bytes = serde_json::to_vec(&resp).unwrap();
        write_frame(&mut stream, &resp_bytes).unwrap();
    });
    wait_for_socket(&_t.path().join("guardd.sock"));
    let s = guard_tui::client::status(&_t.path().join("guardd.sock")).expect("status round-trip");
    assert!(s.enforcement_active);
    assert_eq!(s.protected_files, 6);
    handle.join().unwrap();
}
