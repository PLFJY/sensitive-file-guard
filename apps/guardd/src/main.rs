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

mod enforce;
mod ipc;
mod notify;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use clap::Parser;
use guard_audit::AuditStore;
use guard_core::init_logging;
use platform_linux::{capability, fanotify, signal};

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

    /// Log each allow/deny decision to stderr.
    #[arg(long)]
    print_decisions: bool,

    /// Process at most N events then exit (0 = run until signal). For tests.
    #[arg(long, default_value = "0")]
    exit_after: u64,

    /// Unix domain socket path for IPC (guardctl/guard-tui). If omitted, no IPC
    /// server is started (useful for one-shot tests).
    #[arg(long, value_name = "PATH")]
    ipc_socket: Option<PathBuf>,

    /// SQLite audit database path. If omitted, a default temp path is used when
    /// enforcement is active; pass `/dev/null`-equivalent to disable.
    #[arg(long, value_name = "PATH")]
    audit_db: Option<PathBuf>,
}

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

fn run_browser_enforcement(cfg_path: &std::path::Path, cli: &Cli) -> anyhow::Result<()> {
    require_cap_sys_admin()?;

    let cfg_bytes = std::fs::read(cfg_path)
        .map_err(|e| anyhow::anyhow!("reading config {}: {e}", cfg_path.display()))?;
    let cfg: enforce::EnforcementConfig = serde_json::from_slice(&cfg_bytes)
        .map_err(|e| anyhow::anyhow!("parsing config {}: {e}", cfg_path.display()))?;

    let engine = enforce::EnforcementEngine::from_config(&cfg)?;

    let group = fanotify::FanotifyGroup::new_content()?;
    // Mark before wrapping in Arc<Mutex> — mark_files/mark_trees take &self.
    let n_files = engine.mark_files(&group)?;
    let n_dirs = engine.mark_trees(&group)?;

    // Wrap the fanotify group in Arc so the IPC `SshProtect` handler can add
    // runtime `FAN_OPEN_PERM` marks. `mark_file`/`read`/`respond` all take
    // `&self`; the underlying syscalls are thread-safe.
    let group = Arc::new(group);
    let engine = Arc::new(Mutex::new(engine));

    // Open the audit store (if a path was given or a default is appropriate).
    let audit_path = cli
        .audit_db
        .clone()
        .unwrap_or_else(|| PathBuf::from("/var/lib/guardd/audit.db"));
    let audit = match AuditStore::open(&audit_path) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::warn!(err = %e, path = %audit_path.display(), "audit store open failed; using in-memory fallback");
            Arc::new(AuditStore::open(std::path::Path::new(":memory:"))?)
        }
    };

    // Spawn the IPC server thread (if a socket path was given).
    let ipc_handle = if let Some(sock) = cli.ipc_socket.clone() {
        let state = ipc::IpcState {
            engine: Arc::clone(&engine),
            audit: Arc::clone(&audit),
            version: env!("CARGO_PKG_VERSION").to_string(),
            group: Some(Arc::clone(&group)),
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
    println!(
        "guardd: enforcement ACTIVE — browsers={} protected_files={} marked_files={} marked_tree_dirs={} browser_exes={} (fanotify fd={})",
        cfg.browsers.len(),
        engine.lock().expect("engine").registry().file_count(),
        n_files,
        n_dirs,
        engine.lock().expect("engine").browser_exe_count(),
        group.raw_fd()
    );
    if let Some(sock) = &cli.ipc_socket {
        println!("guardd: IPC socket: {}", sock.display());
    }
    tracing::info!(
        browsers = cfg.browsers.len(),
        protected_files = engine.lock().expect("engine").registry().file_count(),
        marked_files = n_files,
        marked_tree_dirs = n_dirs,
        ipc_socket = ?cli.ipc_socket,
        "enforcement active"
    );

    let mut buf = vec![0u8; 65536];
    let mut processed: u64 = 0;
    // Phase 09: deny-only desktop-notification coalescer. Owned by the fanotify
    // loop thread (the IPC thread never notifies), so no Mutex needed.
    let mut coalescer = notify::NotificationCoalescer::new(notify::COALESCE_WINDOW);
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

            let (decision, audit_record) = {
                let mut eng = engine.lock().expect("engine");
                eng.decide_with_context(ev.pid, ev.fd)
            };
            let allow = matches!(
                decision,
                guard_core::policy::Decision::Allow | guard_core::policy::Decision::AllowByLease(_)
            );

            // Non-blocking audit record. Dropped if the channel is full. The
            // full event always reaches the audit log; the desktop notification
            // is coalesced (deny-only) so a busy open loop doesn't storm the
            // user. Delivery runs on a detached thread so a hung D-Bus / missing
            // `notify-send` can never stall the authorization hot path.
            if let Some(rec) = audit_record {
                if let Some(key) = notify::key_for(&rec) {
                    let now_ms = monotonic_ms();
                    if coalescer.should_notify(&key, now_ms) {
                        let (summary, body) = notify::notification_text(&rec);
                        std::thread::Builder::new()
                            .name("guardd-notify".into())
                            .spawn(move || notify::deliver(&summary, &body))
                            .ok();
                    }
                }
                audit.record(rec);
            }

            if cli.print_decisions {
                eprintln!(
                    "guardd: pid={} decision={} allow={}",
                    ev.pid,
                    match decision {
                        guard_core::policy::Decision::Allow => "ALLOW".into(),
                        guard_core::policy::Decision::AllowByLease(id) => {
                            format!("ALLOW_BY_LEASE({})", id.0)
                        }
                        guard_core::policy::Decision::Deny(r) => {
                            format!("DENY({:?})", r)
                        }
                    },
                    allow
                );
            }
            tracing::debug!(pid = ev.pid, allow, ?decision, "decision");

            if ev.has_fd() {
                group.respond(ev.fd, allow)?;
                fanotify::close_event_fd(ev.fd);
            }

            processed += 1;
            if cli.exit_after != 0 && processed >= cli.exit_after {
                tracing::info!(processed, "reached exit_after; exiting");
                drop(ipc_handle);
                return Ok(());
            }
        }
    }

    drop(ipc_handle);
    Ok(())
}

/// Monotonic-ish millisecond clock for notification coalescing. Uses
/// `SystemTime` since the UNIX epoch; coalescing only cares about deltas
/// within a short window, so wall-clock drift is irrelevant.
fn monotonic_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

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

            if cli.print_decisions {
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
            tracing::debug!(pid = ev.pid, allow, "decision");

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
