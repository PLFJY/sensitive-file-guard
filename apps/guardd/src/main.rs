//! `guardd` — privileged root daemon for Sensitive Data Firewall.
//!
//! Phase 02: minimal fanotify permission-event data plane (`--protect-test-file`).
//! Phase 06: browser enforcement wiring fanotify + ProcessIdentity +
//! ResourceRegistry + PolicyEngine (`--enforce-browser-config`).
//! Phase 07: IPC server + SQLite audit persistence.
//!
//! Both enforcement modes require `CAP_SYS_ADMIN` for `FAN_CLASS_CONTENT`.
//! Without it the daemon prints a precise error and exits 2 — it never silently
//! falls back to notification-only while claiming enforcement.

#![deny(clippy::significant_drop_in_scrutinee)]

#[cfg(target_os = "linux")]
mod enforce;
#[cfg(target_os = "linux")]
mod ipc;
#[cfg(target_os = "linux")]
mod pending;
#[cfg(target_os = "linux")]
mod strict;

#[cfg(target_os = "linux")]
use std::io::Write;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::process::ExitCode;
#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex};

#[cfg(target_os = "linux")]
use clap::Parser;
#[cfg(target_os = "linux")]
use guard_audit::AuditStore;
use guard_core::init_logging;
#[cfg(target_os = "linux")]
use platform_linux::{capability, fanotify, signal};

#[cfg(target_os = "linux")]
#[derive(Parser, Debug)]
#[command(
    name = "guardd",
    version,
    about = "Sensitive Data Firewall privileged daemon"
)]
struct Cli {
    /// Dev mode: protect a single synthetic file with FAN_OPEN_PERM.
    #[arg(long, value_name = "PATH")]
    protect_test_file: Option<PathBuf>,

    /// Browser enforcement config (JSON file). Enables full browser protection:
    /// discovers profiles, marks protected files/trees, and enforces the
    /// deterministic policy on every protected open.
    #[arg(long, value_name = "PATH")]
    enforce_browser_config: Option<PathBuf>,

    /// Executable path(s) allowed to open the protected file (Phase 02 dev mode).
    #[arg(long = "allow-exe", value_name = "EXE")]
    allow_exe: Vec<PathBuf>,

    /// Log decisions to stderr (release builds print blocked decisions only).
    #[arg(long)]
    print_decisions: bool,

    /// Process at most N events then exit (0 = run until signal). For tests.
    #[arg(long, default_value = "0")]
    exit_after: u64,

    /// Unix domain socket path for IPC (guardctl and desktop clients). If omitted, no IPC
    /// server is started (useful for one-shot tests).
    #[arg(long, value_name = "PATH")]
    ipc_socket: Option<PathBuf>,

    /// SQLite audit database path. If omitted, a default temp path is used when
    /// enforcement is active; pass `/dev/null`-equivalent to disable.
    #[arg(long, value_name = "PATH")]
    audit_db: Option<PathBuf>,
}

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    init_logging();
    let cli = Cli::parse();

    if cli.enforce_browser_config.is_some() && cli.protect_test_file.is_some() {
        eprintln!(
            "guardd: --enforce-browser-config and --protect-test-file are mutually exclusive"
        );
        return ExitCode::from(2);
    }

    if let Some(cfg_path) = cli.enforce_browser_config.clone() {
        return match run_browser_enforcement(&cfg_path, &cli) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("guardd: {e:#}");
                ExitCode::FAILURE
            }
        };
    }

    if let Some(target) = cli.protect_test_file.clone() {
        return match run_protect_test_file(&target, &cli) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("guardd: {e:#}");
                ExitCode::FAILURE
            }
        };
    }

    eprintln!(
        "guardd {}: no operation requested. Use --enforce-browser-config PATH (phase 06) \
         or --protect-test-file PATH (phase 02 dev mode).",
        env!("CARGO_PKG_VERSION")
    );
    ExitCode::from(2)
}

/// Fail fast with a precise message if we cannot enforce. Returns the error
/// to propagate, or exits 2 directly (matching Phase 02 behavior).
#[cfg(target_os = "linux")]
fn require_cap_sys_admin() -> anyhow::Result<()> {
    if capability::has_cap_sys_admin() {
        return Ok(());
    }
    eprintln!(
        "guardd: ERROR: CAP_SYS_ADMIN is required for fanotify permission-event \
         enforcement (FAN_CLASS_CONTENT)."
    );
    eprintln!(
        "guardd: Current process effective capabilities lack CAP_SYS_ADMIN \
         (CapEff=0x{:016x}).",
        capability::effective_caps().unwrap_or(0)
    );
    eprintln!(
        "guardd: Run as root, or grant the capability, e.g.: \
         `sudo setcap cap_sys_admin+ep <guardd>`."
    );
    eprintln!(
        "guardd: Refusing to start in enforcement mode. Not falling back to notification-only."
    );
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn run_browser_enforcement(cfg_path: &std::path::Path, cli: &Cli) -> anyhow::Result<()> {
    require_cap_sys_admin()?;

    let cfg_bytes = std::fs::read(cfg_path)
        .map_err(|e| anyhow::anyhow!("reading config {}: {e}", cfg_path.display()))?;
    let cfg: enforce::EnforcementConfig = serde_json::from_slice(&cfg_bytes)
        .map_err(|e| anyhow::anyhow!("parsing config {}: {e}", cfg_path.display()))?;
    // Validate the shared public contract before constructing enforcement state.
    cfg.validate()?;

    let engine = enforce::EnforcementEngine::from_config(&cfg)?;

    // Open audit/config/state dependencies before installing a filesystem-wide
    // permission mark. Strict Mode must not block startup waiting for an event
    // loop which has not started yet.
    let audit_path = cli
        .audit_db
        .clone()
        .unwrap_or_else(|| PathBuf::from("/var/lib/guardd/audit.db"));
    let audit = match AuditStore::open(&audit_path) {
        Ok(store) => Arc::new(store),
        Err(error) => {
            tracing::warn!(err = %error, path = %audit_path.display(), "audit store open failed; using in-memory fallback");
            Arc::new(AuditStore::open(std::path::Path::new(":memory:"))?)
        }
    };

    let backend_metrics = Arc::new(strict::BackendMetrics::new(cfg.enforcement_mode));
    let strict_classifier = if cfg.enforcement_mode == enforce::EnforcementMode::StrictFilesystem {
        Some(Arc::new(strict::StrictClassifier::new(
            &cfg,
            engine.inode_index(),
            Arc::clone(&backend_metrics),
        )?))
    } else {
        None
    };

    // Start observing before the initial fanotify marking pass so a resource
    // replacement concurrent with startup is queued and triggers rediscovery.
    let topology_roots = cfg
        .browsers
        .iter()
        .map(|browser| browser.profile_root.clone())
        .chain(
            cfg.ssh_keys
                .iter()
                .filter_map(|key| key.parent().map(std::path::Path::to_path_buf)),
        )
        .collect();
    let topology = platform_linux::topology::TopologyWatcher::new(topology_roots)
        .map_err(|e| anyhow::anyhow!("initializing browser topology watcher: {e}"))?;

    let group = fanotify::FanotifyGroup::new_content()?;
    // Mark before wrapping in Arc<Mutex>. Conservative mode preserves the
    // existing object/tree marks. Strict mode marks each distinct filesystem;
    // any required mark failure aborts startup rather than claiming ACTIVE.
    let (n_files, n_dirs, n_filesystems) = if let Some(classifier) = &strict_classifier {
        for path in classifier.filesystem_paths() {
            group
                .mark_filesystem(libc::FAN_OPEN_PERM, path)
                .map_err(|error| {
                    anyhow::anyhow!(
                        "strict filesystem mark failed for {}: {error}",
                        path.display()
                    )
                })?;
        }
        // Strict's broad filesystem mark is deliberately `FAN_OPEN_PERM` for
        // browser classification.  Add only exact SSH `FAN_ACCESS_PERM` marks
        // rather than turning every ordinary file read into a round trip.
        let ssh_read_marks = engine.mark_ssh_read_files(&group)?;
        (ssh_read_marks, 0, classifier.filesystem_paths().len())
    } else {
        (engine.mark_files(&group)?, engine.mark_trees(&group)?, 0)
    };
    backend_metrics
        .marked_filesystems
        .store(n_filesystems, std::sync::atomic::Ordering::Relaxed);

    // Wrap the fanotify group in Arc so the IPC `SshProtect` handler can add
    // runtime `FAN_OPEN_PERM` marks. `mark_file`/`read`/`respond` all take
    // `&self`; the underlying syscalls are thread-safe.
    let group = Arc::new(group);
    let engine = Arc::new(Mutex::new(engine));
    let pending_migrations = Arc::new(Mutex::new(pending::PendingMigrationStore::default()));
    let pending_ssh_reads = Arc::new(Mutex::new(pending::PendingSshReadStore::default()));
    let process_liveness = platform_linux::identity::LinuxProcessIdentityResolver::new(
        platform_linux::enrollment::EnrollmentStore::new(),
    );

    // A startup-only fanotify snapshot is not sufficient: browser databases
    // are routinely replaced with new inodes and profiles gain directories at
    // runtime. Refuse ACTIVE startup if the persistent topology watcher cannot
    // cover every enrolled profile root.
    let topology_engine = Arc::clone(&engine);
    let topology_group = Arc::clone(&group);
    let topology_marks_objects = cfg.enforcement_mode == enforce::EnforcementMode::Conservative;
    let topology_handle = std::thread::Builder::new()
        .name("guardd-topology".into())
        .spawn(move || {
            let mut dirty = false;
            while !signal::is_shutdown() {
                match topology.wait_for_change(std::time::Duration::from_millis(250)) {
                    Ok(changed) => dirty |= changed,
                    Err(error) => {
                        tracing::error!(err = %error, "browser topology watcher failed");
                        topology_engine
                            .lock()
                            .expect("engine mutex poisoned")
                            .topology_degraded = true;
                        dirty = true;
                    }
                }
                if !dirty {
                    continue;
                }
                if let Err(error) = topology.rebuild_watches() {
                    tracing::warn!(err = %error, "topology watch rebuild failed; retrying");
                    topology_engine
                        .lock()
                        .expect("engine mutex poisoned")
                        .topology_degraded = true;
                    continue;
                }
                let refreshed = topology_engine
                    .lock()
                    .expect("engine mutex poisoned")
                    .refresh_browser_resources(&topology_group, topology_marks_objects);
                match refreshed {
                    Ok((files, directories)) => {
                        topology_engine
                            .lock()
                            .expect("engine mutex poisoned")
                            .topology_degraded = false;
                        tracing::info!(
                            marked_files = files,
                            marked_tree_dirs = directories,
                            "browser topology changed; protection refreshed"
                        );
                        dirty = false;
                    }
                    Err(error) => {
                        topology_engine
                            .lock()
                            .expect("engine mutex poisoned")
                            .topology_degraded = true;
                        tracing::warn!(
                            err = %error,
                            "resource rediscovery/mark failed; retrying"
                        );
                    }
                }
            }
        })?;

    // Spawn the IPC server thread (if a socket path was given).
    let ipc_handle = if let Some(sock) = cli.ipc_socket.clone() {
        let state = ipc::IpcState {
            engine: Arc::clone(&engine),
            audit: Arc::clone(&audit),
            version: format!("{}+{}", env!("CARGO_PKG_VERSION"), env!("GUARDD_BUILD_ID")),
            group: Some(Arc::clone(&group)),
            authorization: ipc::SensitiveAuthorization::Polkit,
            ssh_agent_pins: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            backend_metrics: Arc::clone(&backend_metrics),
            pending_migrations: Arc::clone(&pending_migrations),
            pending_ssh_reads: Arc::clone(&pending_ssh_reads),
        };
        Some(
            std::thread::Builder::new()
                .name("guardd-ipc".into())
                .spawn(move || {
                    if let Err(e) = ipc::serve_loop(&state, &sock) {
                        tracing::error!(err = %e, "IPC server loop exited");
                    }
                })?,
        )
    } else {
        None
    };

    signal::install_shutdown_handler();
    // Take one snapshot under one lock. Two `engine.lock()` expressions in the
    // same formatting statement self-deadlock because argument temporaries live
    // until the statement ends.
    let (protected_files, browser_exes) = {
        let engine = engine.lock().expect("engine");
        (engine.registry().file_count(), engine.browser_exe_count())
    };
    println!(
        "guardd: enforcement ACTIVE — mode={} browsers={} protected_files={} marked_files={} marked_tree_dirs={} marked_filesystems={} browser_exes={} (fanotify fd={})",
        cfg.enforcement_mode.as_str(),
        cfg.browsers.len(),
        protected_files,
        n_files,
        n_dirs,
        n_filesystems,
        browser_exes,
        group.raw_fd()
    );
    std::io::stdout().flush()?;
    if let Some(sock) = &cli.ipc_socket {
        println!("guardd: IPC socket: {}", sock.display());
    }
    tracing::info!(
        browsers = cfg.browsers.len(),
        mode = cfg.enforcement_mode.as_str(),
        protected_files,
        marked_files = n_files,
        marked_tree_dirs = n_dirs,
        marked_filesystems = n_filesystems,
        ipc_socket = ?cli.ipc_socket,
        "enforcement active"
    );

    let mut buf = vec![0u8; 65536];
    let mut processed: u64 = 0;
    let daemon_pid = std::process::id() as i32;
    loop {
        if signal::is_shutdown() {
            let eng = engine.lock().expect("engine");
            tracing::info!(
                allowed = eng.allowed,
                denied = eng.denied,
                unclassified = eng.unclassified,
                "shutdown signal received; exiting"
            );
            break;
        }

        let mut poll_fds = [libc::pollfd {
            fd: group.raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        // SAFETY: poll_fds is a valid mutable array of descriptors owned by
        // the daemon; a finite timeout expires held authorization requests.
        let ready = unsafe { libc::poll(poll_fds.as_mut_ptr(), poll_fds.len() as _, 250) };
        if ready < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(std::io::Error::last_os_error().into());
        }
        // Pending import consent is independent of fanotify reads.  Expire it
        // on the poll tick so a silent desktop session cannot hold event fds
        // indefinitely, even when no further filesystem events arrive.
        let expired_migrations = pending_migrations
            .lock()
            .expect("pending migration mutex poisoned")
            .expire(unix_secs(), &process_liveness);
        for request in expired_migrations {
            let details = request.details.clone();
            request.resolve(false);
            let record = engine
                .lock()
                .expect("engine mutex poisoned")
                .migration_audit_record(
                    &details,
                    "browser_migration_timed_out",
                    guard_core::Decision::Deny(guard_core::DenyReason::CrossBrowserWithoutLease),
                    "browser_migration_timed_out;resolution=timeout_or_target_exit",
                );
            audit.record(record);
        }
        let expired_ssh_reads = pending_ssh_reads
            .lock()
            .expect("pending SSH read mutex poisoned")
            .expire(unix_secs(), &process_liveness);
        for request in expired_ssh_reads {
            let details = request.details.clone();
            request.resolve(false);
            let record = engine
                .lock()
                .expect("engine mutex poisoned")
                .ssh_read_audit_record(
                    &details,
                    "ssh_key_access_blocked",
                    guard_core::Decision::Deny(guard_core::DenyReason::UnknownProcess),
                    "ssh_key_access_blocked;resolution=timeout_or_reader_exit",
                );
            audit.record(record);
        }
        if ready == 0 || poll_fds[0].revents & libc::POLLIN == 0 {
            continue;
        }

        let n = match group.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
            Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => {
                std::thread::sleep(std::time::Duration::from_millis(2));
                continue;
            }
            Err(e) => return Err(e.into()),
        };

        let events = fanotify::parse_events(&buf[..n])?;
        for ev in events {
            if ev.overflow {
                backend_metrics
                    .fanotify_overflows
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::error!("fanotify queue overflow detected; events may have been dropped");
                if cli.print_decisions {
                    eprintln!("guardd: OVERFLOW");
                }
                continue;
            }

            let (decision, mut audit_record) = if let Some(classifier) = &strict_classifier {
                backend_metrics
                    .strict_events_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // Kernel PID, not a process name, identifies guardd's own
                // threads. Respond before any engine lock so topology refresh
                // and audit/config/state I/O cannot recursively deadlock.
                if ev.pid == daemon_pid {
                    backend_metrics
                        .strict_fast_allowed
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    (guard_core::policy::Decision::Allow, None)
                } else {
                    match classifier.classify_fd(ev.fd) {
                        strict::StrictClassification::Protected(resource) => {
                            backend_metrics
                                .protected_events
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            // Strict's filesystem mark sees the SSH open as
                            // well as the exact-file access mark. The actual
                            // read remains the sole SSH mediation point.
                            if resource.kind == guard_core::ProtectedResourceKind::SshPrivateKey
                                && ev.is_open_perm()
                            {
                                (guard_core::policy::Decision::Allow, None)
                            } else {
                                engine.lock().expect("engine").decide_protected(
                                    ev.pid,
                                    resource,
                                    "strict_inode_or_path",
                                )
                            }
                        }
                        strict::StrictClassification::Unrelated => {
                            backend_metrics
                                .strict_fast_allowed
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            (guard_core::policy::Decision::Allow, None)
                        }
                        strict::StrictClassification::Error(error) => {
                            backend_metrics
                                .classifier_failures
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            engine.lock().expect("engine").unclassified += 1;
                            tracing::error!(%error, pid = ev.pid, "protected event classification failed closed");
                            (
                                guard_core::policy::Decision::Deny(
                                    guard_core::policy::DenyReason::UnknownProcess,
                                ),
                                None,
                            )
                        }
                    }
                }
            } else {
                engine
                    .lock()
                    .expect("engine")
                    .decide_event(ev.pid, ev.fd, ev.is_access_perm())
            };
            let allow = matches!(
                &decision,
                guard_core::policy::Decision::Allow | guard_core::policy::Decision::AllowByLease(_)
            );

            // Only a positively recognized trusted browser can produce this
            // typed decision. Transfer the event fd into the bounded pending
            // store and continue draining unrelated fanotify events.
            let mut fd_transferred = false;
            if let guard_core::policy::Decision::RequireMigrationConfirmation(candidate) = &decision
            {
                if ev.has_fd() {
                    let details = engine
                        .lock()
                        .expect("engine mutex poisoned")
                        .pending_migration_details(ev.pid, ev.fd, candidate);
                    if let Some(details) = details {
                        let audit_details = details.clone();
                        let outcome = pending_migrations
                            .lock()
                            .expect("pending migration mutex poisoned")
                            .enqueue(
                                details,
                                Box::new(platform_linux::fanotify::LinuxPendingPermission::new(
                                    Arc::clone(&group),
                                    ev.fd,
                                )),
                                unix_secs(),
                            );
                        match outcome {
                            pending::EnqueueResult::Created(info) => {
                                let record = engine
                                    .lock()
                                    .expect("engine mutex poisoned")
                                    .migration_audit_record(
                                        &audit_details,
                                        "browser_migration_confirmation_required",
                                        decision.clone(),
                                        &format!(
                                            "browser_migration_confirmation_required;request={};expires_at={}",
                                            info.id, info.expires_at
                                        ),
                                    );
                                audit_record = Some(record);
                                fd_transferred = true;
                            }
                            pending::EnqueueResult::Joined => fd_transferred = true,
                            pending::EnqueueResult::RecentlyApproved(details, permission) => {
                                // A user just authenticated this exact source
                                // profile -> verified target browser executable
                                // tuple. Revalidate this sibling process and
                                // issue its own root-bound lease; no executable-
                                // wide or persisted authorization is created.
                                let outcome = engine
                                    .lock()
                                    .expect("engine mutex poisoned")
                                    .approve_pending_migration(&details);
                                match outcome {
                                    Ok((lease_id, expires_at)) => {
                                        if let Err(error) = permission.allow() {
                                            tracing::error!(%error, "failed to allow recently approved browser import permission");
                                        }
                                        audit_record = Some(
                                            engine
                                                .lock()
                                                .expect("engine mutex poisoned")
                                                .migration_audit_record(
                                                    &details,
                                                    "browser_migration_allowed",
                                                    guard_core::Decision::AllowByLease(lease_id),
                                                    &format!(
                                                        "browser_migration_allowed;resolution=recent_import_approval;lease={};expires_at={}",
                                                        lease_id.0, expires_at
                                                    ),
                                                ),
                                        );
                                    }
                                    Err(error) => {
                                        if let Err(resolve_error) = permission.deny() {
                                            tracing::error!(%resolve_error, "failed to deny invalid recently approved browser import permission");
                                        }
                                        audit_record = Some(
                                            engine
                                                .lock()
                                                .expect("engine mutex poisoned")
                                                .migration_audit_record(
                                                    &details,
                                                    "browser_migration_blocked",
                                                    guard_core::Decision::Deny(
                                                        guard_core::DenyReason::IdentityMismatch,
                                                    ),
                                                    &format!(
                                                        "browser_migration_blocked;resolution=recent_import_identity_revalidation;{error}"
                                                    ),
                                                ),
                                        );
                                    }
                                }
                                fd_transferred = true;
                            }
                            pending::EnqueueResult::DenySuppressed => {
                                // `PendingPermission` was dropped in enqueue
                                // and therefore denied + closed exactly once.
                                audit_record = Some(
                                    engine
                                        .lock()
                                        .expect("engine mutex poisoned")
                                        .migration_audit_record(
                                            &audit_details,
                                            "browser_migration_blocked",
                                            guard_core::Decision::Deny(
                                                guard_core::DenyReason::CrossBrowserWithoutLease,
                                            ),
                                            "browser_migration_blocked;resolution=retry_suppressed",
                                        ),
                                );
                                fd_transferred = true;
                            }
                            pending::EnqueueResult::DenyLimit => {
                                audit_record = Some(
                                    engine
                                        .lock()
                                        .expect("engine mutex poisoned")
                                        .migration_audit_record(
                                            &audit_details,
                                            "browser_migration_blocked",
                                            guard_core::Decision::Deny(
                                                guard_core::DenyReason::CrossBrowserWithoutLease,
                                            ),
                                            "browser_migration_blocked;resolution=pending_limit",
                                        ),
                                );
                                fd_transferred = true;
                            }
                        }
                    }
                }
            }
            if matches!(
                decision,
                guard_core::policy::Decision::RequireSshKeyConfirmation
            ) && ev.has_fd()
            {
                let details = engine
                    .lock()
                    .expect("engine mutex poisoned")
                    .pending_ssh_details(ev.pid, ev.fd);
                if let Some(details) = details {
                    let audit_details = details.clone();
                    let outcome = pending_ssh_reads
                        .lock()
                        .expect("pending SSH read mutex poisoned")
                        .enqueue(
                            details,
                            Box::new(platform_linux::fanotify::LinuxPendingPermission::new(
                                Arc::clone(&group),
                                ev.fd,
                            )),
                            unix_secs(),
                        );
                    match outcome {
                        pending::SshEnqueueResult::Created(info) => {
                            audit_record = Some(engine.lock().expect("engine mutex poisoned").ssh_read_audit_record(
                                &audit_details,
                                "ssh_key_access_confirmation_required",
                                guard_core::Decision::RequireSshKeyConfirmation,
                                &format!("ssh_key_access_confirmation_required;request={};expires_at={}", info.id, info.expires_at),
                            ));
                        }
                        pending::SshEnqueueResult::Joined => {}
                        pending::SshEnqueueResult::DenySuppressed => {
                            audit_record = Some(
                                engine
                                    .lock()
                                    .expect("engine mutex poisoned")
                                    .ssh_read_audit_record(
                                        &audit_details,
                                        "ssh_key_access_blocked",
                                        guard_core::Decision::Deny(
                                            guard_core::DenyReason::IdentityMismatch,
                                        ),
                                        "ssh_key_access_blocked;resolution=retry_suppressed",
                                    ),
                            );
                        }
                        pending::SshEnqueueResult::DenyLimit => {
                            audit_record = Some(
                                engine
                                    .lock()
                                    .expect("engine mutex poisoned")
                                    .ssh_read_audit_record(
                                        &audit_details,
                                        "ssh_key_access_blocked",
                                        guard_core::Decision::Deny(
                                            guard_core::DenyReason::IdentityMismatch,
                                        ),
                                        "ssh_key_access_blocked;resolution=pending_limit",
                                    ),
                            );
                        }
                    }
                    fd_transferred = true;
                }
            }

            // Non-blocking audit record. Dropped if the channel is full. The
            // Each blocked event reaches the audit log. Desktop presentation is owned
            // by the unprivileged guard-notify user-session service; this root
            // daemon never attempts to connect to a user's D-Bus session.
            if let Some(rec) = audit_record {
                audit.record(rec);
            }

            if cli.print_decisions && (cfg!(debug_assertions) || !allow) {
                eprintln!(
                    "guardd: pid={} decision={} allow={}",
                    ev.pid,
                    match &decision {
                        guard_core::policy::Decision::Allow => "ALLOW".into(),
                        guard_core::policy::Decision::AllowByLease(id) => {
                            format!("ALLOW_BY_LEASE({})", id.0)
                        }
                        guard_core::policy::Decision::Deny(r) => {
                            format!("DENY({:?})", r)
                        }
                        guard_core::policy::Decision::RequireMigrationConfirmation(_) => {
                            "MIGRATION_CONFIRMATION_REQUIRED".into()
                        }
                        guard_core::policy::Decision::RequireSshKeyConfirmation => {
                            "SSH_KEY_CONFIRMATION_REQUIRED".into()
                        }
                    },
                    allow
                );
            }
            if cfg!(debug_assertions) || !allow {
                tracing::debug!(pid = ev.pid, allow, ?decision, "decision");
            }

            if ev.has_fd() && !fd_transferred {
                group.respond(ev.fd, allow)?;
                fanotify::close_event_fd(ev.fd);
            }

            processed += 1;
            if cli.exit_after != 0 && processed >= cli.exit_after {
                tracing::info!(processed, "reached exit_after; exiting");
                drop(ipc_handle);
                drop(topology_handle);
                return Ok(());
            }
        }
    }

    drop(ipc_handle);
    let _ = topology_handle.join();
    Ok(())
}

#[cfg(target_os = "linux")]
fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(target_os = "linux")]
fn run_protect_test_file(target: &std::path::Path, cli: &Cli) -> anyhow::Result<()> {
    require_cap_sys_admin()?;

    let group = fanotify::FanotifyGroup::new_content()?;
    group.mark_file(libc::FAN_OPEN_PERM, target)?;

    // Canonicalize the allow-list once.
    let allow_set: std::collections::HashSet<PathBuf> = cli
        .allow_exe
        .iter()
        .filter_map(|p| std::fs::canonicalize(p).ok())
        .collect();

    signal::install_shutdown_handler();
    println!(
        "guardd: enforcement ACTIVE on {} (fanotify fd={}); allow-listed exes={}",
        target.display(),
        group.raw_fd(),
        allow_set.len()
    );
    std::io::stdout().flush()?;
    tracing::info!(target = %target.display(), "enforcement active");

    let mut buf = vec![0u8; 65536];
    let mut processed: u64 = 0;
    loop {
        if signal::is_shutdown() {
            tracing::info!("shutdown signal received; exiting");
            break;
        }

        let n = match group.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
            Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => {
                std::thread::sleep(std::time::Duration::from_millis(2));
                continue;
            }
            Err(e) => return Err(e.into()),
        };

        let events = fanotify::parse_events(&buf[..n])?;
        for ev in events {
            if ev.overflow {
                tracing::error!("fanotify queue overflow detected; events may have been dropped");
                if cli.print_decisions {
                    eprintln!("guardd: OVERFLOW");
                }
                continue;
            }

            let exe = platform_linux::proc::exe_path(ev.pid).ok();
            let allow = match &exe {
                Some(p) => allow_set.contains(p),
                None => false, // cannot identify => deny
            };

            if cli.print_decisions && (cfg!(debug_assertions) || !allow) {
                let exe_str = match &exe {
                    Some(p) => p.display().to_string(),
                    None => "<unknown>".to_string(),
                };
                eprintln!(
                    "guardd: pid={} exe={} decision={}",
                    ev.pid,
                    exe_str,
                    if allow { "ALLOW" } else { "DENY" }
                );
            }
            if cfg!(debug_assertions) || !allow {
                tracing::debug!(pid = ev.pid, allow, "decision");
            }

            if ev.has_fd() {
                group.respond(ev.fd, allow)?;
                fanotify::close_event_fd(ev.fd);
            }

            processed += 1;
            if cli.exit_after != 0 && processed >= cli.exit_after {
                tracing::info!(processed, "reached exit_after; exiting");
                return Ok(());
            }
        }
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    init_logging();
    eprintln!("guardd: Linux fanotify enforcement is available only on Linux");
    ExitCode::from(78)
}
