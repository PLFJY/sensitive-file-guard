//! `guardctl` — control CLI for Sensitive Data Firewall.
//!
//! Phase 07: connects to the `guardd` IPC socket and dispatches subcommands:
//! `status`, `resources list`, `browsers list`, `events`, `explain`, `leases
//! list`, `leases revoke`, `config check`.
//!
//! The CLI is a thin client: it sends a `Request` and prints the `Response`.
//! All authorization is enforced by the daemon using kernel-verified peer
//! credentials (`SO_PEERCRED`); the CLI never sends a UID.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use guard_ipc::{
    Request, RequestOp, Response, ResponseBody, StatusInfo, MAX_REQUEST_BYTES, PROTOCOL_VERSION,
};
use platform_linux::ipc::IpcClient;

#[derive(Parser, Debug)]
#[command(
    name = "guardctl",
    version,
    about = "Sensitive Data Firewall control CLI"
)]
struct Cli {
    /// Path to the guardd IPC socket.
    #[arg(long, value_name = "PATH", default_value = "/run/guardd/guardd.sock")]
    socket: PathBuf,

    /// Output raw JSON instead of human-readable text.
    #[arg(long)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Show daemon status (enforcement active, counts, peer uid).
    Status,
    /// List protected resources (files and trees).
    #[command(name = "resources")]
    Resources {
        #[command(subcommand)]
        action: ResourcesAction,
    },
    /// List enrolled browsers.
    #[command(name = "browsers")]
    Browsers {
        #[command(subcommand)]
        action: BrowsersAction,
    },
    /// List recent authorization events.
    Events {
        /// Maximum number of events to show (default 100).
        #[arg(long)]
        limit: Option<u32>,
    },
    /// Show full detail for one event by ID.
    Explain { event_id: i64 },
    /// List or manage leases.
    #[command(name = "leases")]
    Leases {
        #[command(subcommand)]
        action: LeasesAction,
    },
    /// Authorize a cross-browser migration lease (Phase 08).
    #[command(name = "migration")]
    Migration {
        #[command(subcommand)]
        action: MigrationAction,
    },
    /// Protect SSH private keys (Phase 10).
    #[command(name = "ssh")]
    Ssh {
        #[command(subcommand)]
        action: SshAction,
    },
    /// Check daemon configuration validity.
    #[command(name = "config")]
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand, Debug)]
enum ResourcesAction {
    /// List all protected resources.
    List,
}

#[derive(Subcommand, Debug)]
enum BrowsersAction {
    /// List enrolled browsers.
    List,
}

#[derive(Subcommand, Debug)]
enum LeasesAction {
    /// List active leases (own only, unless root).
    List,
    /// Revoke a lease by ID.
    Revoke { lease_id: String },
}

#[derive(Subcommand, Debug)]
enum ConfigAction {
    /// Check configuration validity.
    Check,
}

#[derive(Subcommand, Debug)]
enum MigrationAction {
    /// Authorize a read-only cross-browser migration lease.
    ///
    /// The lease is armed against the target browser's executable file identity
    /// and matches the next target process (or any process in its tree) that
    /// opens the named source profile. Duration defaults to 10 minutes and is
    /// capped at 1 hour. The authorizing UID is taken from the daemon's
    /// kernel-verified peer credentials, never from this command.
    Authorize {
        /// Source browser ID (must be enrolled in config).
        #[arg(long)]
        source_browser: String,
        /// Source profile name (e.g. "Default").
        #[arg(long)]
        source_profile: String,
        /// Target browser ID that may read the source profile (must be enrolled).
        #[arg(long)]
        target_browser: String,
        /// Lease duration in seconds (default 600, max 3600).
        #[arg(long)]
        duration: Option<u64>,
    },
}

#[derive(Subcommand, Debug)]
enum SshAction {
    /// Enroll a single SSH private key at runtime. The daemon canonicalizes +
    /// stats the path, refuses `.pub` / reserved names (known_hosts, config,
    /// authorized_keys), and adds a `FAN_OPEN_PERM` mark so subsequent raw
    /// reads are denied. No key contents are ever sent.
    Protect {
        /// Path to the SSH private key (e.g. ~/.ssh/id_ed25519).
        path: PathBuf,
    },
    /// Load a protected SSH private key into `ssh-agent` under a one-shot
    /// `SshLoadLease` (Phase 11). The command forks `ssh-add` in a stopped
    /// state, reads the child's start time, asks the daemon to authorize a
    /// lease bound to that exact `ssh-add` invocation, then continues the
    /// child so it can read the key once. The lease is revoked when `ssh-add`
    /// exits. No key bytes are ever sent over IPC.
    ///
    /// Requires `SSH_AUTH_SOCK` to point at a running `ssh-agent`.
    Load {
        /// Path to the protected SSH private key to load.
        path: PathBuf,
        /// Path to the `ssh-add` binary (default: search PATH for "ssh-add").
        #[arg(long, value_name = "PATH")]
        ssh_add: Option<PathBuf>,
    },
    /// List conventional private-key candidates under a directory (default
    /// `~/.ssh`), excluding `.pub` and reserved names. Client-side: no daemon
    /// connection needed. The user enrolls a candidate explicitly via
    /// `ssh protect PATH`.
    Suggest {
        /// Directory to scan (default: ~/.ssh).
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("guardctl: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> anyhow::Result<()> {
    // `ssh suggest` is a pure client-side glob (no daemon connection needed).
    if let Command::Ssh {
        action: SshAction::Suggest { dir },
    } = &cli.command
    {
        return run_ssh_suggest(dir.as_deref());
    }
    // `ssh load` runs a multi-step brokered flow (authorize -> continue child
    // -> revoke) that does not fit the single-request dispatch below.
    if let Command::Ssh {
        action: SshAction::Load { path, ssh_add },
    } = &cli.command
    {
        return run_ssh_load(&cli.socket, path, ssh_add.as_deref(), cli.json);
    }

    let op = match &cli.command {
        Command::Status => RequestOp::Status,
        Command::Resources {
            action: ResourcesAction::List,
        } => RequestOp::ResourcesList,
        Command::Browsers {
            action: BrowsersAction::List,
        } => RequestOp::BrowsersList,
        Command::Events { limit } => RequestOp::Events { limit: *limit },
        Command::Explain { event_id } => RequestOp::Explain {
            event_id: *event_id,
        },
        Command::Leases {
            action: LeasesAction::List,
        } => RequestOp::LeasesList,
        Command::Leases {
            action: LeasesAction::Revoke { lease_id },
        } => RequestOp::LeasesRevoke {
            lease_id: lease_id.clone(),
        },
        Command::Migration {
            action:
                MigrationAction::Authorize {
                    source_browser,
                    source_profile,
                    target_browser,
                    duration,
                },
        } => RequestOp::MigrationAuthorize {
            source_browser: source_browser.clone(),
            source_profile: source_profile.clone(),
            target_browser: target_browser.clone(),
            duration_secs: *duration,
        },
        Command::Ssh {
            action: SshAction::Protect { path },
        } => RequestOp::SshProtect {
            path: path.to_string_lossy().into_owned(),
        },
        Command::Ssh {
            action: SshAction::Suggest { .. },
        } => unreachable!("ssh suggest handled above"),
        Command::Ssh {
            action: SshAction::Load { .. },
        } => unreachable!("ssh load handled above"),
        Command::Config {
            action: ConfigAction::Check,
        } => RequestOp::ConfigCheck,
    };

    let req = Request {
        version: PROTOCOL_VERSION,
        op,
    };
    let req_bytes = serde_json::to_vec(&req)?;

    let resp_bytes = IpcClient::request(&cli.socket, &req_bytes).map_err(|e| {
        anyhow::anyhow!(
            "connecting to guardd IPC socket {}: {e}",
            cli.socket.display()
        )
    })?;
    let resp: Response = serde_json::from_slice(&resp_bytes)?;

    if !resp.ok {
        if let Some(err) = resp.error {
            eprintln!("guardctl: daemon error: {err}");
        }
        return Err(anyhow::anyhow!("daemon returned an error"));
    }

    if cli.json {
        let body = resp
            .body
            .as_ref()
            .map(serde_json::to_string_pretty)
            .transpose()?;
        if let Some(s) = body {
            println!("{s}");
        }
    } else {
        print_human(&resp);
    }
    Ok(())
}

fn print_human(resp: &Response) {
    match &resp.body {
        Some(ResponseBody::Status(s)) => print_status(s),
        Some(ResponseBody::Resources(rs)) => print_resources(rs),
        Some(ResponseBody::Browsers(bs)) => print_browsers(bs),
        Some(ResponseBody::Events(es)) => print_events(es),
        Some(ResponseBody::Explain(e)) => print_explain(e),
        Some(ResponseBody::Leases(ls)) => print_leases(ls),
        Some(ResponseBody::LeaseRevoked { lease_id, found }) => {
            if *found {
                println!("Lease {lease_id} revoked.");
            } else {
                println!("Lease {lease_id} not found.");
            }
        }
        Some(ResponseBody::ConfigCheck(c)) => print_config_check(c),
        Some(ResponseBody::MigrationAuthorized(m)) => print_migration_authorized(m),
        Some(ResponseBody::SshProtected(s)) => print_ssh_protected(s),
        Some(ResponseBody::SshLoadAuthorized(s)) => print_ssh_load_authorized(s),
        None => println!("(no response body)"),
    }
}

fn print_status(s: &StatusInfo) {
    println!("guardd {} — {}", s.version, s.status);
    println!("  protected_files : {}", s.protected_files);
    println!("  protected_trees : {}", s.protected_trees);
    println!("  browsers        : {}", s.browsers);
    println!("  browser_exes    : {}", s.browser_exes);
    println!("  allowed         : {}", s.allowed);
    println!("  denied          : {}", s.denied);
    println!("  unclassified    : {}", s.unclassified);
    println!("  audit_dropped   : {}", s.audit_dropped);
    println!("  peer_uid        : {}", s.peer_uid);
}

fn print_resources(rs: &[guard_ipc::ResourceInfo]) {
    if rs.is_empty() {
        println!("(no protected resources)");
        return;
    }
    println!(
        "{:<8} {:<24} {:<8} {:<10} {:<10} PATH",
        "TYPE", "KIND", "OWNER", "BROWSER", "PROFILE"
    );
    for r in rs {
        println!(
            "{:<8} {:<24} {:<8} {:<10} {:<10} {}",
            if r.tree { "tree" } else { "file" },
            r.kind,
            r.owner_uid,
            r.browser.as_deref().unwrap_or("-"),
            r.profile.as_deref().unwrap_or("-"),
            r.path,
        );
    }
}

fn print_browsers(bs: &[guard_ipc::BrowserInfo]) {
    if bs.is_empty() {
        println!("(no enrolled browsers)");
        return;
    }
    for b in bs {
        println!(
            "{} ({}) — root: {} owner: {}",
            b.id, b.family, b.profile_root, b.owner_uid
        );
        if b.exe_paths.is_empty() {
            println!("  exe_paths: (none)");
        } else {
            for e in &b.exe_paths {
                println!("  exe: {}", e);
            }
        }
    }
}

fn print_events(es: &[guard_ipc::EventInfo]) {
    if es.is_empty() {
        println!("(no events)");
        return;
    }
    println!(
        "{:<6} {:<14} {:<6} {:<8} {:<24} {:<10} PATH",
        "ID", "DECISION", "UID", "PID", "KIND", "BROWSER"
    );
    for e in es {
        println!(
            "{:<6} {:<14} {:<6} {:<8} {:<24} {:<10} {}",
            e.id,
            decision_short(&e.decision),
            e.uid,
            e.pid,
            e.resource_kind,
            e.resource_browser.as_deref().unwrap_or("-"),
            e.path,
        );
    }
}

fn print_explain(e: &guard_ipc::EventInfo) {
    println!("Event {}", e.id);
    println!("  timestamp     : {} ms", e.ts_ms);
    println!("  decision      : {}", e.decision);
    if let Some(r) = &e.deny_reason {
        println!("  deny_reason   : {}", r);
    }
    if let Some(rc) = &e.reason_code {
        println!("  reason_code   : {}", rc);
    }
    println!("  uid           : {}", e.uid);
    println!("  pid           : {}", e.pid);
    println!("  start_time    : {}", e.start_time);
    println!("  resource_kind : {}", e.resource_kind);
    println!("  kind_code     : {}", e.resource_kind_code);
    if let Some(b) = &e.resource_browser {
        println!("  resource_browser  : {}", b);
    }
    if let Some(p) = &e.resource_profile {
        println!("  resource_profile : {}", p);
    }
    println!("  path          : {}", e.path);
    println!("  exe           : {}", e.exe);
    println!("  exe_owner_uid : {}", e.exe_owner_uid);
    println!("  trust_tier    : {}", e.trust_tier);
    if let Some(b) = &e.process_browser {
        println!("  process_browser  : {}", b);
    }
    if let Some(p) = e.parent_pid {
        println!("  parent_pid    : {}", p);
    }
    if let Some(e2) = &e.parent_exe {
        println!("  parent_exe    : {}", e2);
    }
    if let Some(l) = e.lease_id {
        println!("  lease_id      : {}", l);
    }
    println!("  backend_diag  : {}", e.backend_diag);
}

fn print_leases(ls: &[guard_ipc::LeaseInfo]) {
    if ls.is_empty() {
        println!("(no leases)");
        return;
    }
    println!(
        "{:<6} {:<10} {:<6} {:<10} {:<10} {:<10} {:<10} {:<6} {:<4}",
        "ID", "KIND", "UID", "SRC_BR", "TGT_BR", "RESOURCE", "EXPIRES", "REV", "USED"
    );
    for l in ls {
        println!(
            "{:<6} {:<10} {:<6} {:<10} {:<10} {:<10} {:<10} {:<6} {:<4}",
            l.id,
            l.kind,
            l.uid,
            l.source_browser.as_deref().unwrap_or("-"),
            l.target_browser.as_deref().unwrap_or("-"),
            l.resource.as_deref().unwrap_or("-"),
            l.expires_at,
            if l.revoked { "yes" } else { "no" },
            if l.used { "yes" } else { "no" },
        );
    }
}

fn print_config_check(c: &guard_ipc::ConfigCheckInfo) {
    println!("config valid      : {}", c.valid);
    println!("browsers          : {}", c.browsers);
    println!("protected_files   : {}", c.protected_files);
    println!("protected_trees   : {}", c.protected_trees);
    println!("enrolled_exes     : {}", c.enrolled_exes);
    if let Some(e) = &c.error {
        println!("error             : {}", e);
    }
}

fn print_migration_authorized(m: &guard_ipc::MigrationAuthorizedInfo) {
    println!("Migration lease authorized.");
    println!("  lease_id         : {}", m.lease_id);
    println!("  source_browser   : {}", m.source_browser);
    println!("  source_profile   : {}", m.source_profile);
    println!("  target_browser   : {}", m.target_browser);
    println!("  target_exe       : {}", m.target_exe);
    println!("  uid              : {}", m.uid);
    println!("  expires_at       : {} (epoch secs)", m.expires_at);
    println!("  read_only        : {}", m.read_only);
}

fn print_ssh_protected(s: &guard_ipc::SshProtectedInfo) {
    println!("SSH private key protected.");
    println!("  path             : {}", s.path);
    println!("  owner_uid        : {}", s.owner_uid);
    println!("  resource_id      : {}", s.resource_id);
    println!("  raw reads by ordinary processes are now denied.");
    println!("  load via ssh-agent requires a SshLoadLease (Phase 11).");
}

fn print_ssh_load_authorized(s: &guard_ipc::SshLoadAuthorizedInfo) {
    println!("SSH load lease authorized.");
    println!("  lease_id         : {}", s.lease_id);
    println!("  path             : {}", s.path);
    println!("  uid              : {}", s.uid);
    println!("  expires_at       : {} (epoch secs)", s.expires_at);
    println!("  one-shot: revoked when ssh-add exits or the lease is used.");
}

/// Client-side `ssh suggest`: list conventional `id_*` private-key candidates
/// under `dir` (default `~/.ssh`), excluding `.pub` and reserved names. No
/// daemon connection, no file contents read.
fn run_ssh_suggest(dir: Option<&Path>) -> anyhow::Result<()> {
    let ssh_dir = match dir {
        Some(d) => d.to_path_buf(),
        None => {
            let home = std::env::var_os("HOME").ok_or_else(|| {
                anyhow::anyhow!("HOME is not set; pass --dir to specify the .ssh directory")
            })?;
            PathBuf::from(home).join(".ssh")
        }
    };
    let candidates = guard_ssh::suggest_keys(&ssh_dir)?;
    if candidates.is_empty() {
        println!(
            "(no conventional private-key candidates under {})",
            ssh_dir.display()
        );
        println!("enroll an explicit path via: guardctl ssh protect PATH");
        return Ok(());
    }
    println!(
        "Conventional private-key candidates under {}:",
        ssh_dir.display()
    );
    for c in &candidates {
        println!("  {}", c.display());
    }
    println!("enroll with: guardctl ssh protect <PATH>");
    Ok(())
}

// --- Phase 11: brokered `ssh load` flow -------------------------------------
//
// `guardctl ssh load PATH` authorizes a one-shot `SshLoadLease` bound to the
// exact `ssh-add` invocation and then runs `ssh-add` so it can read the
// protected key exactly once. The flow:
//
//   1. validate SSH_AUTH_SOCK (ssh-add needs a reachable agent)
//   2. resolve + canonicalize + stat the ssh-add binary (the lease binds to its
//      file identity: canonical exe path + st_dev + st_ino)
//   3. fork(); the child raises SIGSTOP (so it cannot exec/open the key yet)
//   4. parent waits for the stop, reads the child's start_time from
//      /proc/<pid>/stat (start_time is set at fork and does NOT change across
//      exec, so the value read now equals what guardd will read later)
//   5. parent sends SshLoadAuthorize; if denied, kill the child (never let it
//      exec ssh-add without a lease)
//   6. parent SIGCONT the child -> child execv's ssh-add -> ssh-add opens the
//      key -> fanotify fires -> guardd matches the StableIdentity lease ->
//      AllowByLease -> guardd marks the lease `used`
//   7. parent waitpid for ssh-add to exit
//   8. parent revokes the lease (best-effort; `used` + timeout already prevent
//      reuse)
//
// No key bytes are ever sent over IPC. The lease carries only the path + the
// ssh-add file identity + start_time.

/// Send a single IPC request and return the parsed response.
fn ipc_request(socket: &Path, op: RequestOp) -> anyhow::Result<Response> {
    let req = Request {
        version: PROTOCOL_VERSION,
        op,
    };
    let req_bytes = serde_json::to_vec(&req)?;
    let resp_bytes = IpcClient::request(socket, &req_bytes)
        .map_err(|e| anyhow::anyhow!("IPC request to {} failed: {e}", socket.display()))?;
    let resp: Response = serde_json::from_slice(&resp_bytes)?;
    Ok(resp)
}

/// Resolve the `ssh-add` binary: explicit `--ssh-add PATH` wins, otherwise
/// search PATH for an executable named `ssh-add`.
fn resolve_ssh_add(ssh_add: Option<&Path>) -> anyhow::Result<PathBuf> {
    if let Some(p) = ssh_add {
        return Ok(p.to_path_buf());
    }
    let path_env = std::env::var_os("PATH").ok_or_else(|| anyhow::anyhow!("PATH is not set"))?;
    for dir in std::env::split_paths(&path_env) {
        let candidate = dir.join("ssh-add");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    anyhow::bail!("ssh-add binary not found in PATH; pass --ssh-add PATH")
}

fn stat_dev_ino(path: &Path) -> std::io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(path)?;
    Ok((md.dev(), md.ino()))
}

/// fork() a child that raises SIGSTOP (so the parent can authorize the lease
/// first) and then execv's `ssh-add <key>`. Returns the child PID.
///
/// SAFETY: `fork` is called in a single-threaded CLI before any threads spawn.
/// The child calls only async-signal-safe functions (`raise`, `execv`, `_exit`)
/// before `execv` replaces the image.
fn spawn_stopped_ssh_add(ssh_add: &Path, key: &Path) -> std::io::Result<libc::pid_t> {
    use std::os::unix::ffi::OsStrExt;
    let ssh_add_c = std::ffi::CString::new(ssh_add.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let key_c = std::ffi::CString::new(key.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if pid == 0 {
        // Child.
        unsafe {
            // Stop self so the parent can read start_time + authorize the lease
            // BEFORE we exec ssh-add (which would open the protected key).
            libc::raise(libc::SIGSTOP);
            // Resumed by parent's SIGCONT. execv replaces the image with
            // ssh-add; PID + start_time are unchanged so the lease still
            // matches. argv = ["ssh-add", "<key>"].
            let argv: [*const libc::c_char; 3] =
                [ssh_add_c.as_ptr(), key_c.as_ptr(), std::ptr::null()];
            libc::execv(ssh_add_c.as_ptr(), argv.as_ptr());
            // execv only returns on failure. _exit (not exit) avoids flushing
            // the parent's stdio buffers twice; 127 is the shell convention.
            libc::_exit(127);
        }
    }
    Ok(pid)
}

/// Block until `pid` is stopped (SIGSTOP). Errors if the child exited before
/// stopping (raise failed) or waitpid fails.
fn wait_for_stop(pid: libc::pid_t) -> std::io::Result<()> {
    let mut status: libc::c_int = 0;
    loop {
        let rc = unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        if rc == pid && libc::WIFSTOPPED(status) {
            return Ok(());
        }
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "ssh-add child exited before stopping (raise(SIGSTOP) failed?)",
            ));
        }
    }
}

/// Send SIGCONT to a stopped child so it resumes (and execs ssh-add).
fn continue_child(pid: libc::pid_t) -> std::io::Result<()> {
    let rc = unsafe { libc::kill(pid, libc::SIGCONT) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Block until `pid` exits and return its exit code (0-255). For signal death
/// returns 128+signal (the shell convention).
fn waitpid_exit(pid: libc::pid_t) -> std::io::Result<i32> {
    let mut status: libc::c_int = 0;
    loop {
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        if rc == pid {
            if libc::WIFEXITED(status) {
                return Ok(libc::WEXITSTATUS(status));
            }
            if libc::WIFSIGNALED(status) {
                return Ok(128 + libc::WTERMSIG(status));
            }
        }
    }
}

/// Reap a child that may be stopped or running (used on error cleanup). Best
/// effort: ignore errors.
fn reap_child(pid: libc::pid_t) {
    // Continue first in case it is still stopped, then kill + wait.
    unsafe {
        libc::kill(pid, libc::SIGCONT);
        libc::kill(pid, libc::SIGKILL);
    }
    let mut status: libc::c_int = 0;
    loop {
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return;
        }
        if rc == pid {
            return;
        }
    }
}

fn run_ssh_load(
    socket: &Path,
    key: &Path,
    ssh_add: Option<&Path>,
    json: bool,
) -> anyhow::Result<()> {
    // 1. ssh-add needs a reachable agent socket.
    if std::env::var_os("SSH_AUTH_SOCK").is_none() {
        anyhow::bail!("SSH_AUTH_SOCK is not set; start ssh-agent first");
    }
    // 2. Resolve + canonicalize + stat the ssh-add binary.
    let ssh_add_resolved = resolve_ssh_add(ssh_add)?;
    let ssh_add_canon = std::fs::canonicalize(&ssh_add_resolved)?;
    let (ssh_add_dev, ssh_add_ino) = stat_dev_ino(&ssh_add_canon)?;
    let ssh_add_exe = ssh_add_canon.to_string_lossy().into_owned();

    // 3. Fork ssh-add in a stopped state.
    let pid = spawn_stopped_ssh_add(&ssh_add_canon, key)?;

    // 4. Wait for the stop + read start_time.
    if let Err(e) = wait_for_stop(pid) {
        reap_child(pid);
        anyhow::bail!("waiting for ssh-add child to stop: {e}");
    }
    let start_time = match platform_linux::identity::read_start_time(pid) {
        Ok(t) => t,
        Err(e) => {
            reap_child(pid);
            anyhow::bail!("reading start_time of ssh-add child: {e}");
        }
    };

    // 5. Authorize the one-shot lease.
    let resp = ipc_request(
        socket,
        RequestOp::SshLoadAuthorize {
            path: key.to_string_lossy().into_owned(),
            ssh_add_exe: ssh_add_exe.clone(),
            ssh_add_dev,
            ssh_add_ino,
            start_time,
        },
    )?;
    if !resp.ok {
        // Never let the stopped child exec ssh-add without a lease.
        reap_child(pid);
        let msg = resp.error.unwrap_or_else(|| "unknown daemon error".into());
        anyhow::bail!("daemon refused to authorize SSH load lease: {msg}");
    }
    let lease_id = match resp.body {
        Some(ResponseBody::SshLoadAuthorized(info)) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&info)?);
            } else {
                print_ssh_load_authorized(&info);
            }
            info.lease_id
        }
        _ => {
            reap_child(pid);
            anyhow::bail!("daemon returned unexpected response body to SshLoadAuthorize");
        }
    };

    // 6. Continue the child so it execs ssh-add and reads the key once.
    if let Err(e) = continue_child(pid) {
        reap_child(pid);
        anyhow::bail!("continuing ssh-add child: {e}");
    }

    // 7. Wait for ssh-add to exit.
    let exit_code = match waitpid_exit(pid) {
        Ok(c) => c,
        Err(e) => {
            anyhow::bail!("waiting for ssh-add to exit: {e}");
        }
    };

    // 8. Revoke the lease (best-effort cleanup; the one-shot `used` flag and
    //    the timeout already prevent reuse).
    let _ = ipc_request(
        socket,
        RequestOp::LeasesRevoke {
            lease_id: lease_id.clone(),
        },
    );

    // 9. Report. ssh-add prints the key comment/fingerprint to stdout (its
    //    normal behavior); no key bytes are exposed by guardctl itself.
    if exit_code == 0 {
        if !json {
            println!(
                "ssh-add exited successfully; key loaded (lease {} revoked).",
                lease_id
            );
        }
        Ok(())
    } else {
        anyhow::bail!(
            "ssh-add exited with status {exit_status}; lease {lease} revoked",
            exit_status = exit_code,
            lease = lease_id
        )
    }
}

fn decision_short(s: &str) -> &str {
    if s.contains("Allow") && s.contains("Lease") {
        "ALLOW_LEASE"
    } else if s.contains("Allow") {
        "ALLOW"
    } else if s.contains("Deny") {
        "DENY"
    } else {
        s
    }
}

/// Guard against accidentally huge responses at the CLI side too.
#[allow(dead_code)]
const _CLI_MAX_RESPONSE: usize = MAX_REQUEST_BYTES;

#[cfg(test)]
mod tests {
    //! guardctl tests: the CLI logic is mostly dispatch + formatting, but we
    //! test the formatting helpers and the request-construction logic. A full
    //! end-to-end test (spawn guardd, connect guardctl) lives in the privileged
    //! integration script.

    use super::*;

    #[test]
    fn decision_short_categorizes_variants() {
        assert_eq!(decision_short("Allow"), "ALLOW");
        assert_eq!(decision_short("AllowByLease(42)"), "ALLOW_LEASE");
        assert_eq!(decision_short("Deny(CrossBrowserWithoutLease)"), "DENY");
    }

    #[test]
    fn cli_request_serializes_with_correct_version() {
        let req = Request {
            version: PROTOCOL_VERSION,
            op: RequestOp::Status,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"version\":1"));
        assert!(json.contains("\"kind\":\"status\""));
    }

    #[test]
    fn explain_event_from_json_body() {
        // Parse a daemon response body for Explain using the adjacently-tagged
        // wire format (`{"kind":"explain","data":{...EventInfo...}}`). Phase 12
        // adds the stable `reason_code` + `resource_kind_code` fields.
        let body_json = r#"{"kind":"explain","data":{"id":7,"ts_ms":1700000000000,"uid":1000,"pid":4242,"start_time":9999,"decision":"Deny(CrossBrowserWithoutLease)","deny_reason":"CrossBrowserWithoutLease","reason_code":"migration_lease_required","resource_kind":"CookieStore","resource_kind_code":"browser_cookie_store","resource_browser":"chrome","resource_profile":"Default","path":"/home/u/chrome/Default/Network/Cookies","exe":"/usr/bin/firefox","exe_owner_uid":0,"trust_tier":"SystemPackage","process_browser":"firefox","parent_pid":1,"parent_exe":"/sbin/init","lease_id":null,"backend_diag":"resolved;classify=fd_index_or_registry;trust=SystemPackage"}}"#;
        let body: guard_ipc::ResponseBody = serde_json::from_str(body_json).unwrap();
        match body {
            guard_ipc::ResponseBody::Explain(e) => {
                assert_eq!(e.id, 7);
                assert_eq!(e.uid, 1000);
                assert!(e.decision.contains("Deny"));
                assert!(e.backend_diag.contains("classify="));
                // Phase 12: stable machine-readable codes.
                assert_eq!(e.reason_code.as_deref(), Some("migration_lease_required"));
                assert_eq!(e.resource_kind_code, "browser_cookie_store");
            }
            _ => panic!("expected Explain"),
        }
    }

    #[test]
    fn ssh_load_authorize_request_serializes_with_identity_fields() {
        // Phase 11: the request must carry the ssh-add file identity + the
        // stopped child's start_time, and must NOT carry a uid (the daemon takes
        // uid from peer creds) or any key contents.
        let req = Request {
            version: PROTOCOL_VERSION,
            op: RequestOp::SshLoadAuthorize {
                path: "/home/u/.ssh/id_ed25519".into(),
                ssh_add_exe: "/usr/bin/ssh-add".into(),
                ssh_add_dev: 2049,
                ssh_add_ino: 12345,
                start_time: 998877,
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"kind\":\"ssh_load_authorize\""));
        assert!(json.contains("\"ssh_add_exe\":\"/usr/bin/ssh-add\""));
        assert!(json.contains("\"ssh_add_dev\":2049"));
        assert!(json.contains("\"ssh_add_ino\":12345"));
        assert!(json.contains("\"start_time\":998877"));
        // No uid field is sent; identity comes from peer creds.
        assert!(!json.contains("\"uid\""));
    }

    #[test]
    fn ssh_load_authorized_response_parses() {
        // The daemon replies with a lease id + expiry; no key contents.
        let body_json = r#"{"kind":"ssh_load_authorized","data":{"lease_id":"7","path":"/home/u/.ssh/id_ed25519","uid":1000,"expires_at":1700000100}}"#;
        let body: guard_ipc::ResponseBody = serde_json::from_str(body_json).unwrap();
        match body {
            guard_ipc::ResponseBody::SshLoadAuthorized(info) => {
                assert_eq!(info.lease_id, "7");
                assert_eq!(info.uid, 1000);
                assert_eq!(info.expires_at, 1700000100);
                assert!(!info.path.is_empty());
            }
            _ => panic!("expected SshLoadAuthorized"),
        }
    }

    #[test]
    fn resolve_ssh_add_explicit_path_wins() {
        // An explicit --ssh-add PATH is used verbatim (the caller canonicalizes
        // later); PATH search is only the fallback.
        let p = resolve_ssh_add(Some(Path::new("/opt/custom/ssh-add"))).unwrap();
        assert_eq!(p, PathBuf::from("/opt/custom/ssh-add"));
    }
}
