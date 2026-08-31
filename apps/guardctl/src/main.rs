//! `guardctl` — control CLI for Sensitive Data Firewall.
//!
//! Phase 07: connects to the `guardd` IPC socket and dispatches subcommands:
//! `status`, `resources list`, `browsers list`, `events`, `explain`, `leases
//! list`, `leases revoke`, `config check`.
//!
//! The CLI is a thin client: it sends a `Request` and prints the `Response`.
//! All authorization is enforced by the daemon using kernel-verified peer
//! credentials (`SO_PEERCRED`); the CLI never sends a UID.

#[cfg(any(target_os = "linux", test))]
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[cfg(target_os = "macos")]
use anyhow::Context;
use clap::{Parser, Subcommand};
use guard_client::transport::IpcClient;
use guard_ipc::{
    Request, RequestOp, Response, ResponseBody, StatusInfo, MAX_REQUEST_BYTES, PROTOCOL_VERSION,
};
#[cfg(target_os = "linux")]
use guard_platform::{ServiceController, ServiceOperation};
#[cfg(any(target_os = "linux", test))]
use serde::Serialize;

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
    /// Query platform service health for the desktop client.
    #[command(name = "service-status", hide = true)]
    ServiceStatus,
    /// Control the unprivileged notification presenter through the selected
    /// platform service adapter.
    #[command(name = "notification-service", hide = true)]
    NotificationService {
        #[command(subcommand)]
        action: ServiceAction,
    },
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
    /// Discover existing native browser profile/executable pairs. This is a
    /// local suggestion command and does not contact guardd.
    #[command(name = "browser")]
    Browser {
        #[command(subcommand)]
        action: BrowserAction,
    },
    /// Create a reviewed scoped configuration for one explicitly
    /// selected user's native browser profiles. This does not start guardd.
    Setup {
        /// Home directory whose profiles are to be protected. Required when
        /// this command runs as root; use `sudo guardctl setup --home "$HOME"`.
        #[arg(long, value_name = "PATH")]
        home: Option<PathBuf>,
        /// Destination configuration. Existing files are never overwritten.
        #[arg(long, value_name = "PATH", default_value = "/etc/guardd/config.json")]
        config: PathBuf,
        /// Write without the interactive "yes" confirmation.
        #[arg(long)]
        yes: bool,
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
    /// Run fixture-only macOS acceptance checks through authenticated XPC.
    #[command(name = "acceptance")]
    Acceptance {
        #[command(subcommand)]
        action: AcceptanceAction,
    },
    /// Fixed root-only operations used by guard-ui through pkexec.
    #[command(name = "privileged", hide = true)]
    Privileged {
        #[command(subcommand)]
        action: PrivilegedAction,
    },
}

#[derive(Subcommand, Debug)]
enum PrivilegedAction {
    #[command(name = "service")]
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    #[command(name = "apply-config")]
    ApplyConfig,
}

#[derive(Subcommand, Debug, Clone)]
enum ServiceAction {
    Start,
    Stop,
    Restart,
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
enum BrowserAction {
    /// Print only existing native profile roots and canonical executable paths.
    /// Snap and Flatpak locations are reported separately as unsupported for
    /// this Alpha; this output is never an authorization decision.
    Discover {
        /// Home directory to inspect (default: this process's HOME).
        #[arg(long, value_name = "PATH")]
        home: Option<PathBuf>,
    },
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
enum AcceptanceAction {
    /// Temporarily add one synthetic Chromium profile, verify Endpoint
    /// Security target selection, then restore the previous policy.
    #[command(name = "target-selection")]
    TargetSelection {
        /// Disposable Chromium user-data root created by the acceptance script.
        #[arg(long, value_name = "PATH")]
        profile_root: PathBuf,
        /// Real Chrome executable used only to establish a signed browser identity.
        #[arg(long, value_name = "PATH")]
        browser_executable: PathBuf,
        /// Locally built synthetic probe. It receives only the fixture path.
        #[arg(long, value_name = "PATH")]
        probe: PathBuf,
    },
    /// Internal fixture-only prompt test aid. The service keeps this state in
    /// memory and forcibly restores normal behavior when the duration expires.
    #[command(name = "block-suppression", hide = true)]
    BlockSuppression {
        /// Disable post-Block prompt suppression for this many seconds; zero restores it.
        #[arg(long, default_value_t = 0)]
        disable_for_secs: u64,
    },
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
    /// authorized_keys), and adds it to the selected platform's pre-read
    /// authorization set. No key contents are ever sent.
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
    /// This specialized shortcut is intentionally unsupported on macOS;
    /// ordinary ssh-add uses the manual protected-read approval flow there.
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
    if let Command::Privileged { action } = &cli.command {
        return run_privileged(action);
    }
    if matches!(&cli.command, Command::ServiceStatus) {
        return run_service_status();
    }
    if let Command::NotificationService { action } = &cli.command {
        return run_notification_service(action);
    }
    // `ssh suggest` is a pure client-side glob (no daemon connection needed).
    if let Command::Ssh {
        action: SshAction::Suggest { dir },
    } = &cli.command
    {
        return run_ssh_suggest(dir.as_deref());
    }
    if let Command::Browser {
        action: BrowserAction::Discover { home },
    } = &cli.command
    {
        return run_browser_discover(home.as_deref());
    }
    if let Command::Setup { home, config, yes } = &cli.command {
        return run_setup(home.as_deref(), config, *yes);
    }
    if let Command::Acceptance {
        action:
            AcceptanceAction::TargetSelection {
                profile_root,
                browser_executable,
                probe,
            },
    } = &cli.command
    {
        return run_target_selection_acceptance(profile_root, browser_executable, probe);
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
        Command::Browser {
            action: BrowserAction::Discover { .. },
        } => unreachable!("browser discover handled before IPC dispatch"),
        Command::Setup { .. } => unreachable!("setup handled before IPC dispatch"),
        Command::Events { limit } => RequestOp::Events {
            limit: *limit,
            before_id: None,
            after_id: None,
        },
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
        Command::Acceptance {
            action: AcceptanceAction::BlockSuppression { disable_for_secs },
        } => RequestOp::AcceptanceSetBlockSuppression {
            disable_for_secs: *disable_for_secs,
        },
        Command::Acceptance {
            action: AcceptanceAction::TargetSelection { .. },
        } => unreachable!("target-selection acceptance handled above"),
        Command::Privileged { .. } => unreachable!("privileged helper handled before IPC dispatch"),
        Command::ServiceStatus | Command::NotificationService { .. } => {
            unreachable!("service commands handled before IPC dispatch")
        }
    };

    let req = Request {
        version: PROTOCOL_VERSION,
        op,
    };
    let req_bytes = serde_json::to_vec(&req)?;

    let resp_bytes = IpcClient::request(&cli.socket, &req_bytes)
        .map_err(|e| anyhow::anyhow!("{}: {e}", ipc_connection_context(&cli.socket)))?;
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

fn ipc_connection_context(socket: &std::path::Path) -> String {
    #[cfg(target_os = "macos")]
    {
        let _ = socket;
        "connecting to the authenticated Endpoint Security XPC service".into()
    }
    #[cfg(not(target_os = "macos"))]
    {
        format!("connecting to guardd IPC socket {}", socket.display())
    }
}

#[cfg(target_os = "macos")]
fn run_target_selection_acceptance(
    profile_root: &Path,
    browser_executable: &Path,
    probe: &Path,
) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, Instant};

    let fixture = canonical_fixture(profile_root)?;
    let executable = std::fs::canonicalize(browser_executable)
        .context("fixture browser executable must resolve to a real file")?;
    let probe = std::fs::canonicalize(probe)
        .context("fixture probe must resolve to a locally built executable")?;
    let metadata = std::fs::metadata(&probe)?;
    anyhow::ensure!(
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
        "fixture probe must be an executable regular file"
    );

    let client = guard_client::macos::MacGuardClient::for_current_process()?;
    let original = mac_config_from_metadata(client.configuration()?)?;
    let fixture_config = mac_config_with_fixture(&original, &fixture, &executable)?;
    let mut fixture_applied = false;

    let test_result = (|| -> anyhow::Result<()> {
        println!("Authenticate to stage the disposable fixture policy.");
        client.apply_configuration(&fixture_config, Instant::now() + Duration::from_secs(60))?;
        fixture_applied = true;

        let initial = client.status()?;
        anyhow::ensure!(
            initial.enforcement_active,
            "fixture policy is not enforcing after authenticated apply"
        );
        let health = initial
            .mac_health
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("active backend does not expose macOS health"))?;
        anyhow::ensure!(
            health.target_path_inversion_active,
            "authorization client is not reporting target-path inversion"
        );
        let authorization_before = health.authorization_events_delivered;
        let process_before = health.process_lifecycle_events;

        let unrelated = fixture
            .parent()
            .ok_or_else(|| anyhow::anyhow!("fixture root has no parent"))?
            .join("unrelated-open");
        std::fs::write(&unrelated, b"synthetic unrelated file")?;
        let after_open = client.status()?;
        anyhow::ensure!(
            after_open
                .mac_health
                .as_ref()
                .map(|value| value.authorization_events_delivered)
                == Some(authorization_before),
            "unrelated open reached the authorization client"
        );

        let true_status = std::process::Command::new("/usr/bin/true").status()?;
        anyhow::ensure!(true_status.success(), "/usr/bin/true failed");
        let after_exec = client.status()?;
        anyhow::ensure!(
            after_exec
                .mac_health
                .as_ref()
                .map(|value| value.authorization_events_delivered)
                == Some(authorization_before),
            "unrelated executable launch reached the authorization client"
        );
        let mut lifecycle_advanced = false;
        for _ in 0..20 {
            let status = client.status()?;
            if status
                .mac_health
                .as_ref()
                .is_some_and(|value| value.process_lifecycle_events > process_before)
            {
                lifecycle_advanced = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        anyhow::ensure!(
            lifecycle_advanced,
            "unrelated executable launch did not reach the global process lifecycle client within 2 seconds"
        );

        let cookies = fixture.join("Default/Network/Cookies");
        let probe_status = std::process::Command::new(&probe)
            .args(["read", cookies.to_string_lossy().as_ref()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        anyhow::ensure!(
            !probe_status.success(),
            "unknown probe opened protected synthetic browser data"
        );

        let symlink = fixture
            .parent()
            .ok_or_else(|| anyhow::anyhow!("fixture root has no parent"))?
            .join("outside-symlink");
        std::os::unix::fs::symlink(&cookies, &symlink)?;
        let symlink_status = std::process::Command::new(&probe)
            .args(["read", symlink.to_string_lossy().as_ref()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        anyhow::ensure!(
            !symlink_status.success(),
            "outside-namespace symlink opened protected synthetic browser data"
        );

        println!("PASS: target selection, deny, and symlink checks succeeded.");
        Ok(())
    })();

    let restore_result = if fixture_applied {
        println!("Authenticate to restore the policy that was active before this fixture test.");
        client
            .apply_configuration(&original, Instant::now() + Duration::from_secs(60))
            .map(|_| ())
            .context("fixture test could not restore the original policy")
    } else {
        Ok(())
    };
    match (test_result, restore_result) {
        (Ok(()), Ok(())) => {
            // An active fixture policy correctly rejects LINK before an alias
            // can exist. Create the synthetic alias only after restoration,
            // then prove that attempting to reapply the fixture fails closed.
            let cookies = fixture.join("Default/Network/Cookies");
            let alias = fixture
                .parent()
                .ok_or_else(|| anyhow::anyhow!("fixture root has no parent"))?
                .join("preexisting-hardlink");
            std::fs::hard_link(&cookies, alias)?;
            println!("Authenticate to verify hardlink configuration rejection.");
            let hardlink_result = client
                .apply_configuration(&fixture_config, Instant::now() + Duration::from_secs(60));
            anyhow::ensure!(
                hardlink_result.err().is_some_and(|error| error
                    .to_string()
                    .contains("configuration_unsafe_external_hardlink")),
                "preexisting external hardlink was not rejected as configuration_unsafe_external_hardlink"
            );
            println!(
                "PASS: original policy restored and hardlink configuration rejection verified."
            );
            Ok(())
        }
        (Err(test), Ok(())) => Err(test.context("fixture policy was restored")),
        (Ok(()), Err(restore)) => Err(restore),
        (Err(test), Err(restore)) => Err(test.context(format!(
            "fixture test failed and original-policy restoration also failed: {restore}"
        ))),
    }
}

#[cfg(target_os = "macos")]
fn canonical_fixture(profile_root: &Path) -> anyhow::Result<PathBuf> {
    let root = std::fs::canonicalize(profile_root)?;
    let temporary_root = std::fs::canonicalize(std::env::temp_dir())?;
    anyhow::ensure!(
        root.starts_with(&temporary_root),
        "fixture profile must be below the current system temporary directory"
    );
    let cookies = root.join("Default/Network/Cookies");
    let marker = std::fs::read(&cookies)?;
    anyhow::ensure!(
        marker == b"synthetic fixture only; not a browser secret\n",
        "fixture Cookies file is missing the required synthetic marker"
    );
    Ok(root)
}

#[cfg(target_os = "macos")]
fn mac_config_with_fixture(
    original: &platform_macos::config::MacBackendConfig,
    profile_root: &Path,
    executable: &Path,
) -> anyhow::Result<platform_macos::config::MacBackendConfig> {
    use guard_core::resource::{BrowserFamily, BrowserId};
    use std::sync::Arc;

    let peer_uid = unsafe { libc::geteuid() };
    let discovery = platform_macos::discovery::MacBrowserDiscovery::system(Arc::new(
        platform_macos::code_signature::NativeCodeSignatureInspector,
    ));
    let browser_id = BrowserId(format!(
        "sfg-target-selection-fixture-{}",
        std::process::id()
    ));
    let enrollment = discovery.enroll_custom(
        browser_id.clone(),
        BrowserFamily::Chromium,
        profile_root,
        executable,
        peer_uid,
    )?;
    let mut config = original.clone();
    config.policy_enabled = true;
    config
        .policy
        .browsers
        .push(guard_platform::config::BrowserEnrollmentConfig {
            id: browser_id.0,
            family: BrowserFamily::Chromium,
            profile_root: profile_root.to_path_buf(),
            owner_uid: Some(peer_uid),
            exe_paths: enrollment
                .executables
                .iter()
                .map(|candidate| candidate.path().to_path_buf())
                .collect(),
        });
    config.browser_trust.push(enrollment);
    config.validate_for_peer(peer_uid)?;
    Ok(config)
}

#[cfg(target_os = "macos")]
fn mac_config_from_metadata(
    info: guard_ipc::ConfigurationInfo,
) -> anyhow::Result<platform_macos::config::MacBackendConfig> {
    use guard_core::resource::{BrowserFamily, BrowserId};
    use std::sync::Arc;

    let peer_uid = unsafe { libc::geteuid() };
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("HOME is unset; cannot reconstruct fixture policy"))?;
    let discovery = platform_macos::discovery::MacBrowserDiscovery::system(Arc::new(
        platform_macos::code_signature::NativeCodeSignatureInspector,
    ));
    let verified = discovery.discover_verified(&home).enrollments;
    let mut policy_browsers = Vec::with_capacity(info.browsers.len());
    let mut browser_trust = Vec::with_capacity(info.browsers.len());
    for browser in info.browsers {
        let family = match browser.family.as_str() {
            "Chromium" | "chromium" => BrowserFamily::Chromium,
            "Firefox" | "firefox" => BrowserFamily::Firefox,
            "Zen" | "zen" => BrowserFamily::Zen,
            "Safari" | "safari" => BrowserFamily::Safari,
            _ => anyhow::bail!("unknown configured browser family"),
        };
        anyhow::ensure!(
            browser.owner_uid.is_none() || browser.owner_uid == Some(peer_uid),
            "configured browser belongs to another user"
        );
        let root = PathBuf::from(&browser.profile_root);
        let executable_paths = browser
            .exe_paths
            .iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        let enrollment = verified
            .iter()
            .find(|candidate| {
                candidate.browser_id.0 == browser.id
                    && candidate.profile_root == root
                    && candidate
                        .executables
                        .iter()
                        .map(|executable| executable.path())
                        .eq(executable_paths.iter().map(PathBuf::as_path))
            })
            .cloned()
            .map(Ok)
            .unwrap_or_else(|| {
                anyhow::ensure!(
                    executable_paths.len() == 1,
                    "custom browser enrollment requires exactly one executable"
                );
                discovery.enroll_custom(
                    BrowserId(browser.id.clone()),
                    family,
                    &root,
                    &executable_paths[0],
                    peer_uid,
                )
            })?;
        policy_browsers.push(guard_platform::config::BrowserEnrollmentConfig {
            id: browser.id,
            family,
            profile_root: root,
            owner_uid: Some(peer_uid),
            exe_paths: enrollment
                .executables
                .iter()
                .map(|executable| executable.path().to_path_buf())
                .collect(),
        });
        browser_trust.push(enrollment);
    }
    let browser_protection_level =
        guard_platform::config::BrowserProtectionLevel::parse(&info.browser_protection_level)
            .ok_or_else(|| anyhow::anyhow!("unknown browser protection level"))?;
    let trusted_tools = info
        .mac_trusted_tools
        .into_iter()
        .map(|rule| platform_macos::config::MacTrustedToolRule {
            path: rule.path.into(),
            dev: rule.dev,
            ino: rule.ino,
            team_id: rule.team_id,
            signing_id: rule.signing_id,
            owner_uid: peer_uid,
        })
        .collect();
    let config = platform_macos::config::MacBackendConfig {
        version: platform_macos::config::MAC_CONFIG_VERSION,
        policy_enabled: info.policy_enabled.unwrap_or(false),
        policy: guard_platform::config::PolicyConfig {
            browser_protection_level,
            browsers: policy_browsers,
            enrolled_exes: info.enrolled_exes.into_iter().map(PathBuf::from).collect(),
            ssh_keys: info.ssh_keys.into_iter().map(PathBuf::from).collect(),
        },
        browser_trust,
        mac_allowlist: platform_macos::config::MacAllowlistConfig { trusted_tools },
    };
    config.validate_for_peer(peer_uid)?;
    Ok(config)
}

#[cfg(not(target_os = "macos"))]
fn run_target_selection_acceptance(
    _profile_root: &Path,
    _browser_executable: &Path,
    _probe: &Path,
) -> anyhow::Result<()> {
    anyhow::bail!("fixture Endpoint Security acceptance is available only on macOS")
}

#[cfg(target_os = "linux")]
fn run_privileged(action: &PrivilegedAction) -> anyhow::Result<()> {
    // This command is intentionally useful only as pkexec's narrowly scoped
    // root helper.  It has no arbitrary command, unit, or destination input.
    // SAFETY: geteuid only reads this process credential and has no pointer
    // arguments or mutable state.
    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!("privileged helper requires root (invoke it through pkexec)");
    }
    match action {
        PrivilegedAction::Service { action } => {
            let verb = match action {
                ServiceAction::Start => "start",
                ServiceAction::Stop => "stop",
                ServiceAction::Restart => "restart",
            };
            let status = std::process::Command::new("systemctl")
                .args([verb, "guardd.service"])
                .status()?;
            anyhow::ensure!(status.success(), "systemctl {verb} guardd.service failed");
            Ok(())
        }
        PrivilegedAction::ApplyConfig => apply_config_transactionally(),
    }
}

#[cfg(not(target_os = "linux"))]
fn run_privileged(_action: &PrivilegedAction) -> anyhow::Result<()> {
    anyhow::bail!("Linux pkexec/systemd helper operations are unavailable on macOS")
}

#[cfg(target_os = "linux")]
fn run_service_status() -> anyhow::Result<()> {
    let controller = platform_linux::service::LinuxServiceController;
    let status = controller.status()?;
    println!("{}", serde_json::to_string(&status)?);
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_service_status() -> anyhow::Result<()> {
    let status = guard_client::macos::MacGuardClient::for_current_process()?.status()?;
    let status = guard_platform::ServiceStatus {
        protection_active: status.enforcement_active,
        notification_active: None,
        diagnostic: status.backend_diagnostic,
    };
    println!("{}", serde_json::to_string(&status)?);
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_notification_service(action: &ServiceAction) -> anyhow::Result<()> {
    let operation = match action {
        ServiceAction::Start => ServiceOperation::Start,
        ServiceAction::Stop => ServiceOperation::Stop,
        ServiceAction::Restart => ServiceOperation::Restart,
    };
    platform_linux::service::LinuxServiceController::apply_notifications(operation)
}

#[cfg(not(target_os = "linux"))]
fn run_notification_service(_action: &ServiceAction) -> anyhow::Result<()> {
    anyhow::bail!("macOS user-agent lifecycle is implemented by the app bundle")
}

#[cfg(target_os = "linux")]
const MAX_CONFIG_STDIN: usize = 256 * 1024;
#[cfg(target_os = "linux")]
const ACTIVE_CONFIG: &str = "/etc/guardd/config.json";

#[cfg(target_os = "linux")]
fn apply_config_transactionally() -> anyhow::Result<()> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((MAX_CONFIG_STDIN + 1) as u64)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= MAX_CONFIG_STDIN,
        "configuration input exceeds {} bytes",
        MAX_CONFIG_STDIN
    );
    let _cfg = validate_candidate_bytes(&bytes)?;
    let parent = Path::new(ACTIVE_CONFIG)
        .parent()
        .expect("fixed config has parent");
    std::fs::create_dir_all(parent)?;
    let previous = std::fs::read(ACTIVE_CONFIG).ok();
    let temp = parent.join(format!(".config.json.{}.tmp", std::process::id()));
    write_root_config(&temp, &bytes)?;
    std::fs::rename(&temp, ACTIVE_CONFIG)?;
    let restarted = std::process::Command::new("systemctl")
        .args(["restart", "guardd.service"])
        .status()?
        .success();
    let healthy = restarted
        && std::process::Command::new("systemctl")
            .args(["is-active", "--quiet", "guardd.service"])
            .status()?
            .success();
    if healthy {
        return Ok(());
    }
    if let Some(old) = previous {
        write_root_config(&temp, &old)?;
        std::fs::rename(&temp, ACTIVE_CONFIG)?;
        let _ = std::process::Command::new("systemctl")
            .args(["restart", "guardd.service"])
            .status();
    } else {
        let _ = std::fs::remove_file(ACTIVE_CONFIG);
    }
    anyhow::bail!("new configuration failed health check; previous configuration restored")
}

#[cfg(target_os = "linux")]
fn validate_candidate_bytes(
    bytes: &[u8],
) -> anyhow::Result<platform_linux::config::EnforcementConfig> {
    anyhow::ensure!(
        bytes.len() <= MAX_CONFIG_STDIN,
        "configuration input exceeds {} bytes",
        MAX_CONFIG_STDIN
    );
    let cfg = platform_linux::config::parse_config(bytes)?;
    cfg.validate()?;
    Ok(cfg)
}

#[cfg(target_os = "linux")]
fn write_root_config(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o640)
        .open(path)?;
    use std::io::Write;
    file.write_all(bytes)?;
    file.sync_all()?;
    file.set_permissions(std::fs::Permissions::from_mode(0o640))?;
    let status = std::process::Command::new("chown")
        .args(["root:guardd-users", &path.to_string_lossy()])
        .status()?;
    anyhow::ensure!(
        status.success(),
        "setting root:guardd-users ownership failed"
    );
    Ok(())
}

/// Native layouts selected from maintained distribution package file layouts,
/// not from package-manager metadata or a process name.  Each executable entry
/// is the final ELF executable expected from `/proc/<pid>/exe`, rather than a
/// `/usr/bin` launcher script.  A user can always configure a different
/// canonical path explicitly.
#[derive(Clone, Copy)]
#[allow(dead_code)]
#[cfg(test)]
struct NativeBrowserLayout {
    id: &'static str,
    family: &'static str,
    profile_relative: &'static str,
    executable_candidates: &'static [&'static str],
}

#[allow(dead_code)]
#[cfg(test)]
const NATIVE_BROWSER_LAYOUTS: &[NativeBrowserLayout] = &[
    NativeBrowserLayout {
        id: "firefox",
        family: "Firefox",
        profile_relative: ".mozilla/firefox",
        executable_candidates: &["/usr/lib/firefox/firefox", "/usr/lib64/firefox/firefox"],
    },
    NativeBrowserLayout {
        id: "firefox-esr",
        family: "Firefox",
        profile_relative: ".mozilla/firefox-esr",
        executable_candidates: &[
            "/usr/lib/firefox-esr/firefox-esr",
            "/usr/lib64/firefox-esr/firefox-esr",
        ],
    },
    NativeBrowserLayout {
        id: "chromium",
        family: "Chromium",
        profile_relative: ".config/chromium",
        executable_candidates: &[
            "/usr/lib/chromium/chromium",
            "/usr/lib/chromium-browser/chromium-browser",
            "/usr/lib64/chromium-browser/chromium-browser",
        ],
    },
    NativeBrowserLayout {
        id: "google-chrome",
        family: "Chromium",
        profile_relative: ".config/google-chrome",
        executable_candidates: &["/opt/google/chrome/chrome"],
    },
    NativeBrowserLayout {
        id: "brave",
        family: "Chromium",
        profile_relative: ".config/BraveSoftware/Brave-Browser",
        executable_candidates: &["/opt/brave.com/brave/brave"],
    },
    NativeBrowserLayout {
        id: "microsoft-edge",
        family: "Chromium",
        profile_relative: ".config/microsoft-edge",
        executable_candidates: &["/opt/microsoft/msedge/msedge"],
    },
    NativeBrowserLayout {
        id: "vivaldi",
        family: "Chromium",
        profile_relative: ".config/vivaldi",
        executable_candidates: &["/opt/vivaldi/vivaldi"],
    },
];

#[derive(Debug, Serialize, PartialEq, Eq)]
#[cfg(any(target_os = "linux", test))]
struct BrowserSuggestion {
    id: String,
    family: String,
    profile_root: String,
    exe_paths: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[cfg(any(target_os = "linux", test))]
struct UnsupportedSandboxedBrowser {
    kind: String,
    profile_root: String,
    reason: String,
}

#[derive(Debug, Serialize)]
#[cfg(any(target_os = "linux", test))]
struct BrowserDiscovery {
    browsers: Vec<BrowserSuggestion>,
    unsupported_sandboxed: Vec<UnsupportedSandboxedBrowser>,
}

/// Deliberately separate from the daemon's config type: `guardctl` remains a
/// client binary and writes the public JSON contract rather than linking the
/// daemon implementation into an installation helper.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[cfg(any(target_os = "linux", test))]
struct SetupBrowserConfig {
    id: String,
    family: &'static str,
    profile_root: String,
    exe_paths: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[cfg(any(target_os = "linux", test))]
struct SetupConfig {
    browser_protection_level: &'static str,
    browsers: Vec<SetupBrowserConfig>,
    enrolled_exes: Vec<String>,
    ssh_keys: Vec<String>,
}

#[cfg(target_os = "linux")]
fn run_browser_discover(home: Option<&Path>) -> anyhow::Result<()> {
    let home = match home {
        Some(home) => home.to_path_buf(),
        None => std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("HOME is unset; pass --home PATH"))?,
    };
    if !home.is_dir() {
        anyhow::bail!(
            "home directory {} does not exist or is not a directory",
            home.display()
        );
    }
    let result = platform_linux::config::discover_native_browsers(&home);
    println!("{}", serde_json::to_string_pretty(&result)?);
    eprintln!(
        "guardctl: review this suggestion before copying it into config.json; \
         configured canonical executable identity, not this command or a browser name, authorizes a browser."
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_browser_discover(home: Option<&Path>) -> anyhow::Result<()> {
    use std::sync::Arc;

    let home = match home {
        Some(home) => home.to_path_buf(),
        None => std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("HOME is unset; pass --home PATH"))?,
    };
    anyhow::ensure!(home.is_dir(), "home directory does not exist");
    let discovery = platform_macos::discovery::MacBrowserDiscovery::system(Arc::new(
        platform_macos::code_signature::NativeCodeSignatureInspector,
    ))
    .discover_verified(&home);
    println!("{}", serde_json::to_string_pretty(&discovery.review)?);
    eprintln!(
        "guardctl: review signer and profile metadata; discovery never grants trust by name alone"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_setup(home: Option<&Path>, config_path: &Path, assume_yes: bool) -> anyhow::Result<()> {
    reject_existing_config(config_path)?;
    let home = resolve_setup_home(home)?;
    let discovery = shared_discovery(&home);
    let config = setup_config(&discovery)?;
    let rendered = serde_json::to_string_pretty(&config)?;

    println!(
        "The following Linux protection configuration will be written to {}:\n",
        config_path.display()
    );
    println!("{rendered}");
    if !discovery.unsupported_sandboxed.is_empty() {
        eprintln!(
            "guardctl: Snap/Flatpak profile roots were found but deliberately omitted: {}",
            discovery
                .unsupported_sandboxed
                .iter()
                .map(|browser| browser.kind.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    eprintln!(
        "guardctl: SSH keys are intentionally not guessed or added. Use `guardctl ssh suggest` and select a key explicitly after setup."
    );

    if !assume_yes && !confirm_setup()? {
        anyhow::bail!("setup cancelled; no configuration was written");
    }

    write_new_config(config_path, &(rendered + "\n"))?;
    println!(
        "Created {} with mode 0640 (root-owned; guardd-users read metadata).",
        config_path.display()
    );
    println!("Review it, then run: sudo systemctl enable --now guardd");
    println!("Verify with: guardctl status");
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_setup(_home: Option<&Path>, _config_path: &Path, _assume_yes: bool) -> anyhow::Result<()> {
    anyhow::bail!(
        "macOS configuration is applied through authenticated XPC; the Linux --yes setup path is unavailable"
    )
}

#[cfg(target_os = "linux")]
fn resolve_setup_home(home: Option<&Path>) -> anyhow::Result<PathBuf> {
    let is_root = {
        // SAFETY: `geteuid` has no preconditions and reads only this process's
        // effective UID. It prevents sudo from silently selecting /root.
        unsafe { libc::geteuid() == 0 }
    };
    let home = match home {
        Some(home) => home.to_path_buf(),
        None if is_root => anyhow::bail!(
            "--home PATH is required when setup runs as root; for example: sudo guardctl setup --home \"$HOME\""
        ),
        None => std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("HOME is unset; pass --home PATH"))?,
    };
    if !home.is_dir() {
        anyhow::bail!(
            "home directory {} does not exist or is not a directory",
            home.display()
        );
    }
    std::fs::canonicalize(&home).map_err(|error| {
        anyhow::anyhow!("canonicalizing home directory {}: {error}", home.display())
    })
}

#[cfg(any(target_os = "linux", test))]
fn setup_config(discovery: &BrowserDiscovery) -> anyhow::Result<SetupConfig> {
    if discovery.browsers.is_empty() {
        anyhow::bail!(
            "no supported native browser profile/executable pair was found; no configuration was written. Use `guardctl browser discover --home PATH` to inspect candidates, or configure an explicit custom browser path."
        );
    }
    let browsers = discovery
        .browsers
        .iter()
        .map(|browser| {
            Ok(SetupBrowserConfig {
                id: browser.id.clone(),
                family: config_family(&browser.family)?,
                profile_root: browser.profile_root.clone(),
                exe_paths: browser.exe_paths.clone(),
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(SetupConfig {
        browser_protection_level: "common",
        browsers,
        enrolled_exes: Vec::new(),
        ssh_keys: Vec::new(),
    })
}

/// Convert the shared Linux discovery model into the setup renderer's stable
/// JSON shape.  Discovery itself is shared with guard-ui and never authorizes
/// a browser.
#[cfg(target_os = "linux")]
fn shared_discovery(home: &Path) -> BrowserDiscovery {
    let shared = platform_linux::config::discover_native_browsers(home);
    BrowserDiscovery {
        browsers: shared
            .browsers
            .into_iter()
            .map(|b| BrowserSuggestion {
                id: b.id,
                family: platform_linux::config::family_name(b.family).to_owned(),
                profile_root: b.profile_root.to_string_lossy().into_owned(),
                exe_paths: b
                    .exe_paths
                    .into_iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect(),
            })
            .collect(),
        unsupported_sandboxed: shared
            .unsupported_sandboxed
            .into_iter()
            .map(|b| UnsupportedSandboxedBrowser {
                kind: b.kind,
                profile_root: b.profile_root.to_string_lossy().into_owned(),
                reason: b.reason,
            })
            .collect(),
    }
}

#[cfg(any(target_os = "linux", test))]
fn config_family(family: &str) -> anyhow::Result<&'static str> {
    match family {
        "Firefox" => Ok("firefox"),
        "Zen" => Ok("zen"),
        "Chromium" => Ok("chromium"),
        // `BrowserSuggestion` is generated only by the static table above.
        // Refuse a future unrecognised entry rather than write config that the
        // daemon would reject or interpret differently.
        _ => anyhow::bail!("unsupported browser family in discovery: {family}"),
    }
}

#[cfg(any(target_os = "linux", test))]
fn reject_existing_config(config_path: &Path) -> anyhow::Result<()> {
    match std::fs::symlink_metadata(config_path) {
        Ok(_) => anyhow::bail!(
            "refusing to overwrite existing configuration {}; review or replace it deliberately",
            config_path.display()
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(anyhow::anyhow!(
            "checking configuration destination {}: {error}",
            config_path.display()
        )),
    }
}

#[cfg(target_os = "linux")]
fn confirm_setup() -> anyhow::Result<bool> {
    eprint!("Write this configuration? Type yes to continue: ");
    io::stderr().flush()?;
    let mut response = String::new();
    io::stdin().read_line(&mut response)?;
    Ok(response.trim() == "yes")
}

#[cfg(any(target_os = "linux", test))]
fn write_new_config(config_path: &Path, contents: &str) -> anyhow::Result<()> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let parent = config_path.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "configuration destination {} has no parent directory",
            config_path.display()
        )
    })?;
    let parent_existed = parent.exists();
    std::fs::create_dir_all(parent).map_err(|error| {
        anyhow::anyhow!(
            "creating configuration directory {}: {error}",
            parent.display()
        )
    })?;
    if !parent_existed {
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o750)).map_err(
            |error| {
                anyhow::anyhow!(
                    "setting configuration directory permissions {}: {error}",
                    parent.display()
                )
            },
        )?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o640)
        .open(config_path)
        .map_err(|error| {
            anyhow::anyhow!("creating configuration {}: {error}", config_path.display())
        })?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    // SAFETY: geteuid only reads this process credential and has no pointer
    // arguments or mutable state.
    if unsafe { libc::geteuid() } == 0 {
        // Fixed destination/group only; failure is reported rather than
        // silently widening access. Tests running as an unprivileged user do
        // not enter this branch.
        let status = std::process::Command::new("chown")
            .args(["root:guardd-users", &config_path.to_string_lossy()])
            .status()?;
        if !status.success() {
            anyhow::bail!("setting root:guardd-users ownership failed");
        }
    }
    Ok(())
}

#[allow(dead_code)]
#[cfg(test)]
fn discover_browsers(home: &Path, layouts: &[NativeBrowserLayout]) -> BrowserDiscovery {
    let mut browsers = Vec::new();
    for layout in layouts {
        let profile_root = home.join(layout.profile_relative);
        if !profile_root.is_dir() {
            continue;
        }
        let mut exe_paths = Vec::new();
        for candidate in layout.executable_candidates {
            let Some(path) = canonical_executable(Path::new(candidate)) else {
                continue;
            };
            let path = path.to_string_lossy().into_owned();
            if !exe_paths.contains(&path) {
                exe_paths.push(path);
            }
        }
        if !exe_paths.is_empty() {
            browsers.push(BrowserSuggestion {
                id: layout.id.to_owned(),
                family: layout.family.to_owned(),
                profile_root: profile_root.to_string_lossy().into_owned(),
                exe_paths,
            });
        }
    }

    // These paths are intentionally only reported.  The current resolver sees
    // host `/proc/<pid>/exe`, while sandbox mount namespaces and profile mounts
    // can present a different executable/device/inode or hide filesystem marks.
    // Treating a desktop ID, package name, or launcher name as a substitute
    // would violate the identity model.
    let sandboxed = [
        (
            "snap-firefox",
            home.join("snap/firefox/common/.mozilla/firefox"),
        ),
        (
            "flatpak-firefox",
            home.join(".var/app/org.mozilla.firefox/.mozilla/firefox"),
        ),
        (
            "flatpak-chromium",
            home.join(".var/app/org.chromium.Chromium/config/chromium"),
        ),
    ]
    .into_iter()
    .filter(|(_, profile_root)| profile_root.is_dir())
    .map(|(kind, profile_root)| UnsupportedSandboxedBrowser {
        kind: kind.to_owned(),
        profile_root: profile_root.to_string_lossy().into_owned(),
        reason: "sandbox namespace and filesystem-mark visibility are not security-accepted in Linux V1; use a native package".to_owned(),
    })
    .collect();

    BrowserDiscovery {
        browsers,
        unsupported_sandboxed: sandboxed,
    }
}

#[allow(dead_code)]
#[cfg(test)]
fn canonical_executable(path: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return None;
    }
    std::fs::canonicalize(path).ok()
}

fn print_human(resp: &Response) {
    match &resp.body {
        Some(ResponseBody::Status(s)) => print_status(s),
        Some(ResponseBody::Resources(rs)) => print_resources(rs),
        Some(ResponseBody::Browsers(bs)) => print_browsers(bs),
        Some(ResponseBody::Configuration(configuration)) => {
            #[cfg(target_os = "linux")]
            println!("Active Linux configuration: scoped resource protection");
            #[cfg(not(target_os = "linux"))]
            println!("Active configuration");
            println!(
                "  browser protection level : {}",
                configuration.browser_protection_level
            );
            println!("  browsers : {}", configuration.browsers.len());
            println!("  SSH keys : {}", configuration.ssh_keys.len());
        }
        Some(ResponseBody::ConfigurationApplied { version }) => {
            println!("Applied macOS configuration version {version}.");
        }
        Some(ResponseBody::PendingHelper(helper)) => {
            println!(
                "Pending helper: {}",
                if helper.running {
                    "running"
                } else {
                    "not running"
                }
            );
        }
        Some(ResponseBody::PendingHelperSnapshot(snapshot)) => {
            println!(
                "Pending helper snapshot: {} browser import(s), {} SSH read(s)",
                snapshot.migrations.len(),
                snapshot.ssh_reads.len()
            );
        }
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
        Some(ResponseBody::MigrationPending(items)) => {
            for item in items {
                println!(
                    "{}: {} {} -> {} (pid {})",
                    item.id,
                    item.source_browser,
                    item.source_profile,
                    item.target_browser,
                    item.target_pid
                );
            }
        }
        Some(ResponseBody::MigrationPendingItem(item)) => {
            println!(
                "{}: {} {} -> {} (pid {})",
                item.id,
                item.source_browser,
                item.source_profile,
                item.target_browser,
                item.target_pid
            );
        }
        Some(ResponseBody::MigrationResolved(result)) => {
            println!("Migration resolution: {result:?}")
        }
        Some(ResponseBody::SshPending(items)) => {
            for item in items {
                println!(
                    "{}: {} reads {} (pid {})",
                    item.id, item.process_exe, item.key_path, item.pid
                );
            }
        }
        Some(ResponseBody::SshPendingItem(item)) => {
            println!(
                "{}: {} reads {} (pid {})",
                item.id, item.process_exe, item.key_path, item.pid
            );
        }
        Some(ResponseBody::SshReadResolved(result)) => println!("SSH read resolution: {result:?}"),
        Some(ResponseBody::SshProtected(s)) => print_ssh_protected(s),
        Some(ResponseBody::SshLoadAuthorized(s)) => print_ssh_load_authorized(s),
        Some(ResponseBody::AcceptanceBlockSuppression { disabled_until }) => {
            if let Some(until) = disabled_until {
                println!("Fixture prompt suppression disabled until {until} (epoch seconds).");
            } else {
                println!("Normal post-Block prompt suppression restored.");
            }
        }
        None => println!("(no response body)"),
    }
}

fn print_status(s: &StatusInfo) {
    println!("guardd {} — {}", s.version, s.status);
    println!(
        "  backend         : {}",
        if s.backend_kind.is_empty() {
            "unknown"
        } else {
            &s.backend_kind
        }
    );
    if let Some(read_only) = s.read_only_guaranteed {
        println!("  migration_read_only_guaranteed: {read_only}");
    }
    println!("  protected_files : {}", s.protected_files);
    println!("  ssh_protected_keys: {}", s.ssh_protected_keys);
    println!("  protected_trees : {}", s.protected_trees);
    println!("  browsers        : {}", s.browsers);
    println!("  browser_exes    : {}", s.browser_exes);
    println!("  allowed         : {}", s.allowed);
    println!("  denied          : {}", s.denied);
    println!("  unclassified    : {}", s.unclassified);
    #[cfg(target_os = "linux")]
    if let Some(value) = s.permission_events_total {
        println!("  permission_events: {value}");
    }
    println!("  protected_events: {}", s.protected_events);
    if let Some(value) = s.fanotify_overflows {
        println!("  fanotify_overflows: {value}");
    }
    if let Some(value) = s.classifier_failures {
        println!("  classifier_failures: {value}");
    }
    if let Some(value) = s.topology_degraded {
        println!("  topology_degraded: {value}");
    }
    println!("  audit_dropped   : {}", s.audit_dropped);
    println!("  peer_uid        : {}", s.peer_uid);
}

#[cfg(any())]
fn print_incidents(incidents: &[guard_ipc::SshIncidentInfo]) {
    if incidents.is_empty() {
        println!("(no SSH behavioral incidents)");
        return;
    }
    println!(
        "{:<22} {:<18} {:<10} {:<8} KEY",
        "ID", "STATE", "PID", "BLOCKS"
    );
    for incident in incidents {
        println!(
            "{:<22} {:<18} {:<10} {:<8} {}",
            incident.id,
            incident.state,
            incident.pid,
            incident.blocked_network_attempts,
            incident.key_path
        );
    }
}

#[cfg(any())]
fn print_incident(incident: &guard_ipc::SshIncidentInfo) {
    println!("incident: {}", incident.id);
    println!("  state: {}", incident.state);
    println!(
        "  process: {} (pid {}, start {})",
        incident.process_exe, incident.pid, incident.start_time
    );
    println!("  protected key: {}", incident.key_path);
    println!(
        "  blocked network attempts: {}",
        incident.blocked_network_attempts
    );
    if let (Some(ip), Some(port), Some(protocol)) = (
        incident.destination_ip.as_deref(),
        incident.destination_port,
        incident.protocol.as_deref(),
    ) {
        println!("  first blocked destination: {ip}:{port} ({protocol})");
    }
    if let Some(resolution) = &incident.resolution {
        println!("  resolution: {resolution}");
    }
    if let Some(detail) = &incident.resolution_detail {
        println!("  result: {detail}");
    }
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
        "{:<6} {:<10} {:<6} {:<10} {:<10} {:<10} {:<8} {:<10} {:<6} {:<4}",
        "ID", "KIND", "UID", "SRC_BR", "TGT_BR", "RESOURCE", "STATE", "EXPIRES", "REV", "USED"
    );
    for l in ls {
        println!(
            "{:<6} {:<10} {:<6} {:<10} {:<10} {:<10} {:<8} {:<10} {:<6} {:<4}",
            l.id,
            l.kind,
            l.uid,
            l.source_browser.as_deref().unwrap_or("-"),
            l.target_browser.as_deref().unwrap_or("-"),
            l.resource.as_deref().unwrap_or("-"),
            l.state.as_deref().unwrap_or("-"),
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
    println!("  read-only guaranteed: {}", m.read_only_guaranteed);
}

fn print_ssh_protected(s: &guard_ipc::SshProtectedInfo) {
    println!("SSH private key protected.");
    println!("  path             : {}", s.path);
    println!("  owner_uid        : {}", s.owner_uid);
    println!("  resource_id      : {}", s.resource_id);
    #[cfg(target_os = "macos")]
    {
        println!("  FREAD opens require Block/Allow confirmation or a short exact-key process-tree lease.");
        println!("  guardctl ssh load is unsupported; ordinary ssh-add uses manual read approval.");
    }
    #[cfg(not(target_os = "macos"))]
    {
        println!("  reads are allowed, reported, and watched for immediate external sends.");
        println!("  the brokered ssh-agent path still uses a one-shot SshLoadLease.");
    }
}

fn print_ssh_load_authorized(s: &guard_ipc::SshLoadAuthorizedInfo) {
    println!("SSH load lease authorized.");
    println!("  lease_id         : {}", s.lease_id);
    println!("  path             : {}", s.path);
    println!("  uid              : {}", s.uid);
    println!("  expires_at       : {} (epoch secs)", s.expires_at);
    println!("  verified agent   : {}", s.agent_socket);
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
//   6. parent SIGCONT the child -> child execve's ssh-add with a minimal
//      environment -> ssh-add opens the
//      key -> fanotify fires -> guardd matches the StableIdentity lease ->
//      AllowByLease -> guardd marks the lease `used`
//   7. parent waitpid for ssh-add to exit
//   8. parent revokes the lease (best-effort; `used` + timeout already prevent
//      reuse)
//
// No key bytes are ever sent over IPC. The capability binds only metadata:
// key path, ssh-add file identity/start_time, and guardd's pinned agent path.

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

/// Resolve the same root-owned system `ssh-add` selected by the daemon. A
/// caller-supplied path is accepted only when it canonicalizes to that exact
/// executable; user-selected binaries cannot receive an SSH-load lease.
#[cfg(target_os = "linux")]
fn resolve_ssh_add(ssh_add: Option<&Path>) -> anyhow::Result<PathBuf> {
    let trusted = platform_linux::identity::trusted_ssh_add_path().map_err(anyhow::Error::msg)?;
    if let Some(p) = ssh_add {
        let requested = std::fs::canonicalize(p)
            .map_err(|e| anyhow::anyhow!("canonicalize {}: {e}", p.display()))?;
        if requested != trusted {
            anyhow::bail!(
                "--ssh-add {} is not the daemon-approved system executable {}",
                requested.display(),
                trusted.display()
            );
        }
    }
    Ok(trusted)
}

#[cfg(target_os = "macos")]
fn resolve_ssh_add(ssh_add: Option<&Path>) -> anyhow::Result<PathBuf> {
    let trusted = std::fs::canonicalize("/usr/bin/ssh-add")?;
    if let Some(path) = ssh_add {
        let requested = std::fs::canonicalize(path)?;
        anyhow::ensure!(
            requested == trusted,
            "--ssh-add must select the system /usr/bin/ssh-add"
        );
    }
    Ok(trusted)
}

/// fork() a child that raises SIGSTOP (so the parent can authorize the lease
/// first) and then execve's `ssh-add <key>` with a minimal environment. Returns
/// the child PID.
///
/// SAFETY: `fork` is called in a single-threaded CLI before any threads spawn.
/// The child calls only async-signal-safe functions (`raise`, `execve`, `_exit`)
/// before `execve` replaces the image.
const SSH_AUTH_SOCK_ENV_PREFIX: &[u8] = b"SSH_AUTH_SOCK=";
const SSH_ADD_LOCALE_ENV: &str = "LC_ALL=C";

struct StoppedSshAdd {
    pid: libc::pid_t,
    agent_path_writer: Option<std::os::fd::OwnedFd>,
}

fn spawn_stopped_ssh_add(ssh_add: &Path, key: &Path) -> std::io::Result<StoppedSshAdd> {
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    let ssh_add_c = std::ffi::CString::new(ssh_add.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let key_c = std::ffi::CString::new(key.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let argv: [*const libc::c_char; 3] = [ssh_add_c.as_ptr(), key_c.as_ptr(), std::ptr::null()];
    let lc_all = std::ffi::CString::new(SSH_ADD_LOCALE_ENV).expect("static CString");
    let mut pipe_fds = [-1; 2];
    // SAFETY: pipe_fds points to two writable integers.
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Keep the private path handoff pipe out of the exec'd ssh-add image.
    for descriptor in pipe_fds {
        // SAFETY: both descriptors were returned by pipe and remain live.
        if unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: both descriptors are still owned by this function.
            unsafe {
                libc::close(pipe_fds[0]);
                libc::close(pipe_fds[1]);
            }
            return Err(error);
        }
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        // SAFETY: both descriptors were created by pipe2 and remain owned.
        unsafe {
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
        }
        return Err(std::io::Error::last_os_error());
    }
    if pid == 0 {
        // Child.
        unsafe {
            libc::close(pipe_fds[1]);
            // Stop self so the parent can read start_time + authorize the lease
            // BEFORE we exec ssh-add (which would open the protected key).
            libc::raise(libc::SIGSTOP);
            // After authorization, the parent supplies guardd's root-pinned
            // agent socket pathname through this private pipe. Build envp in a
            // fixed stack buffer: no allocator or non-async-signal-safe Rust
            // code runs in the post-fork child.
            let prefix = SSH_AUTH_SOCK_ENV_PREFIX;
            let mut agent_environment = [0 as libc::c_char; 128];
            for (index, byte) in prefix.iter().enumerate() {
                agent_environment[index] = *byte as libc::c_char;
            }
            let mut used = prefix.len();
            loop {
                let remaining = agent_environment.len() - used - 1;
                if remaining == 0 {
                    libc::_exit(126);
                }
                let count = libc::read(
                    pipe_fds[0],
                    agent_environment.as_mut_ptr().add(used).cast(),
                    remaining,
                );
                if count == 0 {
                    break;
                }
                if count < 0 {
                    if current_errno() == libc::EINTR {
                        continue;
                    }
                    libc::_exit(126);
                }
                used += count as usize;
            }
            libc::close(pipe_fds[0]);
            if used == prefix.len() {
                libc::_exit(126);
            }
            agent_environment[used] = 0;
            let envp = [
                agent_environment.as_ptr(),
                lc_all.as_ptr(),
                std::ptr::null(),
            ];
            // Resumed by parent's SIGCONT. execve replaces the image with
            // ssh-add; PID + start_time are unchanged so the lease still
            // matches. The explicit envp excludes loader/runtime injection
            // variables such as LD_PRELOAD, LD_AUDIT, and GLIBC_TUNABLES.
            libc::execve(ssh_add_c.as_ptr(), argv.as_ptr(), envp.as_ptr());
            // execve only returns on failure. _exit (not exit) avoids flushing
            // the parent's stdio buffers twice; 127 is the shell convention.
            libc::_exit(127);
        }
    }
    // Parent owns only the write end. Closing it after writing produces EOF in
    // the resumed child before execve.
    unsafe { libc::close(pipe_fds[0]) };
    // SAFETY: the parent uniquely owns the live write descriptor.
    let writer = unsafe { std::os::fd::OwnedFd::from_raw_fd(pipe_fds[1]) };
    Ok(StoppedSshAdd {
        pid,
        agent_path_writer: Some(writer),
    })
}

#[cfg(target_os = "linux")]
unsafe fn current_errno() -> libc::c_int {
    // SAFETY: libc exposes the calling thread's errno slot.
    unsafe { *libc::__errno_location() }
}

#[cfg(target_os = "macos")]
unsafe fn current_errno() -> libc::c_int {
    // SAFETY: libc exposes the calling thread's errno slot.
    unsafe { *libc::__error() }
}

#[cfg(test)]
fn sanitized_ssh_add_environment(agent_socket: &std::ffi::OsStr) -> std::io::Result<Vec<String>> {
    use std::os::unix::ffi::OsStrExt;
    let socket = std::str::from_utf8(agent_socket.as_bytes())
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    Ok(vec![
        format!(
            "{}{socket}",
            std::str::from_utf8(SSH_AUTH_SOCK_ENV_PREFIX).unwrap()
        ),
        SSH_ADD_LOCALE_ENV.to_owned(),
    ])
}

fn provide_verified_agent_socket(child: &mut StoppedSshAdd, path: &Path) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;

    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() > 107 || bytes.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "verified SSH agent socket path is invalid or too long",
        ));
    }
    let writer = child.agent_path_writer.take().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "verified SSH agent socket was already supplied",
        )
    })?;
    let mut file = std::fs::File::from(writer);
    file.write_all(bytes)?;
    file.flush()
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
    if cfg!(target_os = "macos") {
        anyhow::bail!(
            "ssh load is not supported on macOS in this Alpha; run ordinary ssh-add and approve its protected-key read"
        );
    }
    // 1. ssh-add needs a reachable agent socket.
    let _agent_socket = std::env::var_os("SSH_AUTH_SOCK")
        .ok_or_else(|| anyhow::anyhow!("SSH_AUTH_SOCK is not set; start ssh-agent first"))?;
    // 2. Resolve + canonicalize the ssh-add binary (needed for the fork).
    let ssh_add_resolved = resolve_ssh_add(ssh_add)?;
    let ssh_add_canon = std::fs::canonicalize(&ssh_add_resolved)?;

    // 3. Fork ssh-add in a stopped state.
    let mut child = spawn_stopped_ssh_add(&ssh_add_canon, key)?;
    let pid = child.pid;

    // 4. Wait for the stop signal.
    if let Err(e) = wait_for_stop(pid) {
        reap_child(pid);
        anyhow::bail!("waiting for ssh-add child to stop: {e}");
    }

    // 5. Authorize the one-shot lease. The daemon verifies the ssh-add
    //    process identity from /proc itself — we send ONLY the PID.
    //    (Hardening pass 1: closes the authorization bypass where a client
    //    could declare any identity.)
    let resp = match ipc_request(
        socket,
        RequestOp::SshLoadAuthorize {
            path: key.to_string_lossy().into_owned(),
            ssh_add_pid: pid as u32,
        },
    ) {
        Ok(response) => response,
        Err(error) => {
            // A transport failure must not strand a stopped child which could
            // later be resumed outside this broker flow.
            reap_child(pid);
            return Err(error.context("requesting SSH load authorization"));
        }
    };
    if !resp.ok {
        // Never let the stopped child exec ssh-add without a lease.
        reap_child(pid);
        let msg = resp.error.unwrap_or_else(|| "unknown daemon error".into());
        anyhow::bail!("daemon refused to authorize SSH load lease: {msg}");
    }
    let (lease_id, pinned_agent_socket) = match resp.body {
        Some(ResponseBody::SshLoadAuthorized(info)) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&info)?);
            } else {
                print_ssh_load_authorized(&info);
            }
            (info.lease_id, PathBuf::from(info.agent_socket))
        }
        _ => {
            reap_child(pid);
            anyhow::bail!("daemon returned unexpected response body to SshLoadAuthorize");
        }
    };

    // 6. Supply the root-pinned, kernel-verified agent pathname. The child
    // cannot inherit or choose a replacement path after authorization.
    if let Err(error) = provide_verified_agent_socket(&mut child, &pinned_agent_socket) {
        reap_child(pid);
        revoke_lease_best_effort(socket, &lease_id);
        anyhow::bail!("supplying verified SSH agent socket to ssh-add: {error}");
    }

    // 7. Continue the child so it execs ssh-add and reads the key once.
    if let Err(e) = continue_child(pid) {
        reap_child(pid);
        revoke_lease_best_effort(socket, &lease_id);
        anyhow::bail!("continuing ssh-add child: {e}");
    }

    // 8. Wait for ssh-add to exit.
    let exit_code = match waitpid_exit(pid) {
        Ok(c) => c,
        Err(e) => {
            reap_child(pid);
            revoke_lease_best_effort(socket, &lease_id);
            anyhow::bail!("waiting for ssh-add to exit: {e}");
        }
    };

    // 9. Revoke the lease (best-effort cleanup; the one-shot `used` flag and
    //    the timeout already prevent reuse).
    revoke_lease_best_effort(socket, &lease_id);

    // 10. Report. ssh-add prints the key comment/fingerprint to stdout (its
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

fn revoke_lease_best_effort(socket: &Path, lease_id: &str) {
    let _ = ipc_request(
        socket,
        RequestOp::LeasesRevoke {
            lease_id: lease_id.to_owned(),
        },
    );
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

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_connection_error_names_xpc_not_linux_socket() {
        let context = ipc_connection_context(Path::new("/run/guardd/guardd.sock"));
        assert!(context.contains("Endpoint Security XPC"));
        assert!(!context.contains("socket"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn privileged_candidate_validation_rejects_malformed_oversized_and_empty() {
        assert!(validate_candidate_bytes(b"not-json").is_err());
        assert!(validate_candidate_bytes(&vec![b'x'; MAX_CONFIG_STDIN + 1]).is_err());
        assert!(validate_candidate_bytes(
            br#"{"unexpected_option":true,"browsers":[],"ssh_keys":[]}"#
        )
        .is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn privileged_candidate_validation_rejects_unknown_field_and_relative_path() {
        assert!(validate_candidate_bytes(
            br#"{"unexpected_option":true,"browsers":[],"ssh_keys":[]}"#
        )
        .is_err());
        assert!(validate_candidate_bytes(
            br#"{"browser_protection_level":"common","browsers":[],"ssh_keys":["relative-key"]}"#
        )
        .is_err());
    }

    #[test]
    fn discovery_represents_native_firefox_and_debian_esr_without_launcher_paths() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        std::fs::create_dir_all(home.join(".mozilla/firefox")).unwrap();
        std::fs::create_dir_all(home.join(".mozilla/firefox-esr")).unwrap();
        assert!(Path::new("/bin/sh").is_file());
        let layouts = [
            NativeBrowserLayout {
                id: "firefox",
                family: "Firefox",
                profile_relative: ".mozilla/firefox",
                executable_candidates: &["/bin/sh"],
            },
            NativeBrowserLayout {
                id: "firefox-esr",
                family: "Firefox",
                profile_relative: ".mozilla/firefox-esr",
                executable_candidates: &["/bin/sh"],
            },
        ];
        let found = discover_browsers(&home, &layouts);
        assert_eq!(found.browsers.len(), 2);
        assert_eq!(found.browsers[0].id, "firefox");
        assert_eq!(found.browsers[1].id, "firefox-esr");
        assert_eq!(
            found.browsers[1].profile_root,
            home.join(".mozilla/firefox-esr").display().to_string()
        );
    }

    #[test]
    fn discovery_does_not_turn_a_fake_named_firefox_into_a_candidate() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        std::fs::create_dir_all(home.join(".mozilla/firefox")).unwrap();
        let fake = temp.path().join("firefox");
        std::fs::write(&fake, b"synthetic executable").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Path::new("/bin/sh").is_file());
        let layouts = [NativeBrowserLayout {
            id: "firefox",
            family: "Firefox",
            profile_relative: ".mozilla/firefox",
            executable_candidates: &["/bin/sh"],
        }];

        let found = discover_browsers(&home, &layouts);
        assert_eq!(
            found.browsers[0].exe_paths,
            vec![std::fs::canonicalize("/bin/sh")
                .unwrap()
                .display()
                .to_string()]
        );
        assert_ne!(found.browsers[0].exe_paths[0], fake.display().to_string());
    }

    #[test]
    fn discovery_deduplicates_equivalent_canonical_executables() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        std::fs::create_dir_all(home.join(".mozilla/firefox")).unwrap();
        let layouts = [NativeBrowserLayout {
            id: "firefox",
            family: "Firefox",
            profile_relative: ".mozilla/firefox",
            executable_candidates: &["/bin/sh", "/usr/bin/sh"],
        }];

        let found = discover_browsers(&home, &layouts);
        assert_eq!(found.browsers.len(), 1);
        assert_eq!(found.browsers[0].exe_paths.len(), 1);
    }

    #[test]
    fn discovery_reports_sandboxed_profiles_without_emitting_a_trustable_browser() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        std::fs::create_dir_all(home.join("snap/firefox/common/.mozilla/firefox")).unwrap();
        let found = discover_browsers(home, &[]);
        assert!(found.browsers.is_empty());
        assert_eq!(found.unsupported_sandboxed[0].kind, "snap-firefox");
    }

    #[test]
    fn setup_generates_nonempty_narrow_config_without_uid_or_ssh_guesses() {
        let discovery = BrowserDiscovery {
            browsers: vec![BrowserSuggestion {
                id: "firefox-esr".to_owned(),
                family: "Firefox".to_owned(),
                profile_root: "/synthetic/home/.mozilla/firefox-esr".to_owned(),
                exe_paths: vec!["/usr/lib/firefox-esr/firefox-esr".to_owned()],
            }],
            unsupported_sandboxed: Vec::new(),
        };

        let config = setup_config(&discovery).unwrap();
        let value = serde_json::to_value(config).unwrap();
        assert_eq!(value["browser_protection_level"], "common");
        assert_eq!(value["browsers"][0]["family"], "firefox");
        assert!(value["browsers"][0].get("owner_uid").is_none());
        assert_eq!(value["ssh_keys"], serde_json::json!([]));
        assert!(value.get("ssh_behavior_window_secs").is_none());
    }

    #[test]
    fn setup_refuses_to_create_an_empty_protection_config() {
        let error = setup_config(&BrowserDiscovery {
            browsers: Vec::new(),
            unsupported_sandboxed: Vec::new(),
        })
        .unwrap_err();
        assert!(error.to_string().contains("no supported native browser"));
    }

    #[test]
    fn setup_never_overwrites_an_existing_config() {
        let temp = tempfile::tempdir().unwrap();
        let config = temp.path().join("config.json");
        std::fs::write(&config, "keep this config").unwrap();
        assert!(reject_existing_config(&config).is_err());
        assert_eq!(
            std::fs::read_to_string(&config).unwrap(),
            "keep this config"
        );
    }

    #[test]
    fn setup_writes_new_config_with_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let config = temp.path().join("guardd/config.json");
        write_new_config(&config, "{\"browsers\":[]}\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(&config).unwrap(),
            "{\"browsers\":[]}\n"
        );
        assert_eq!(
            std::fs::metadata(&config).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(
            std::fs::metadata(config.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o750
        );
    }

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
        assert!(json.contains(&format!("\"version\":{PROTOCOL_VERSION}")));
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
        // Hardening pass 1: the request carries ONLY the PID — the daemon
        // verifies identity from /proc. No uid, no key contents, no
        // client-declared identity fields.
        let req = Request {
            version: PROTOCOL_VERSION,
            op: RequestOp::SshLoadAuthorize {
                path: "/home/u/.ssh/id_ed25519".into(),
                ssh_add_pid: 12345,
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"kind\":\"ssh_load_authorize\""));
        assert!(json.contains("\"ssh_add_pid\":12345"));
        // No client-declared identity fields.
        assert!(!json.contains("\"ssh_add_exe\""));
        assert!(!json.contains("\"ssh_add_dev\""));
        assert!(!json.contains("\"ssh_add_ino\""));
        assert!(!json.contains("\"start_time\""));
        // No uid field is sent; identity comes from peer creds.
        assert!(!json.contains("\"uid\""));
    }

    #[test]
    fn ssh_load_authorized_response_parses() {
        // The daemon replies with a lease id + expiry; no key contents.
        let body_json = r#"{"kind":"ssh_load_authorized","data":{"lease_id":"7","path":"/home/u/.ssh/id_ed25519","uid":1000,"expires_at":1700000100,"agent_socket":"/tmp/.guardd-agent-pins/a-1000-7.sock"}}"#;
        let body: guard_ipc::ResponseBody = serde_json::from_str(body_json).unwrap();
        match body {
            guard_ipc::ResponseBody::SshLoadAuthorized(info) => {
                assert_eq!(info.lease_id, "7");
                assert_eq!(info.uid, 1000);
                assert_eq!(info.expires_at, 1700000100);
                assert!(info.agent_socket.contains(".guardd-agent-pins"));
                assert!(!info.path.is_empty());
            }
            _ => panic!("expected SshLoadAuthorized"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_ssh_add_accepts_only_daemon_trusted_binary() {
        let trusted = platform_linux::identity::trusted_ssh_add_path().unwrap();
        assert_eq!(resolve_ssh_add(Some(&trusted)).unwrap(), trusted);
        assert!(resolve_ssh_add(Some(Path::new("/opt/custom/ssh-add"))).is_err());
    }

    #[test]
    fn ssh_add_exec_environment_is_minimal_and_drops_injection_variables() {
        // The child receives this exact envp; ambient variables (including
        // loader hooks) are never copied from guardctl's environment.
        let environment =
            sanitized_ssh_add_environment(std::ffi::OsStr::new("/tmp/test-agent.sock")).unwrap();
        let values: Vec<&str> = environment.iter().map(String::as_str).collect();
        assert_eq!(values, ["SSH_AUTH_SOCK=/tmp/test-agent.sock", "LC_ALL=C"]);

        for forbidden in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "LD_DEBUG",
            "LD_PROFILE",
            "GLIBC_TUNABLES",
            "SSH_ASKPASS",
            "PATH",
            "HOME",
        ] {
            assert!(
                values
                    .iter()
                    .all(|value| !value.starts_with(&format!("{forbidden}="))),
                "{forbidden} must not enter ssh-add's execve environment"
            );
        }
    }
}
