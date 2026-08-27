//! Target-specific application/service composition for the otherwise shared
//! GTK client. Linux privilege and systemd vocabulary stays in this module.

#[cfg(target_os = "linux")]
use guard_platform::{ServiceOperation, ServiceStatus};

use crate::pending_dialog::PromptKind;

/// Configure relocatable GTK data before libadwaita starts. Development builds
/// have no runtime marker and retain pkg-config/Homebrew behavior.
pub fn configure_bundled_runtime() -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let executable = std::env::current_exe()?;
        let contents = executable
            .parent()
            .and_then(std::path::Path::parent)
            .ok_or_else(|| anyhow::anyhow!("bundle executable has no Contents directory"))?;
        let resources = contents.join("Resources");
        let marker = resources.join("guard-release-runtime");
        if !marker.is_file() {
            return Ok(());
        }
        let app = contents
            .parent()
            .ok_or_else(|| anyhow::anyhow!("bundle Contents has no app parent"))?;
        let template = std::fs::read_to_string(resources.join("gdk-pixbuf/loaders.cache.in"))?;
        let rendered = render_loader_cache(&template, app);
        let cache_root = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("HOME is unavailable for GTK runtime cache"))?
            .join("Library/Caches/top.plfjy.SensitiveFileGuard");
        std::fs::create_dir_all(&cache_root)?;
        let cache = cache_root.join("gdk-pixbuf-loaders.cache");
        let temporary = cache_root.join(format!(
            ".gdk-pixbuf-loaders.cache.{}.tmp",
            std::process::id()
        ));
        std::fs::write(&temporary, rendered)?;
        std::fs::rename(&temporary, &cache)?;

        // This runs before GTK/libadwaita initialization and before worker
        // threads exist. Values point only at signed bundle resources and the
        // generated metadata-only cache.
        std::env::set_var("GDK_PIXBUF_MODULE_FILE", &cache);
        std::env::set_var("GDK_PIXBUF_MODULEDIR", resources.join("gdk-pixbuf/loaders"));
        std::env::set_var(
            "GSETTINGS_SCHEMA_DIR",
            resources.join("share/glib-2.0/schemas"),
        );
        let bundled_data = resources.join("share");
        let data_dirs = match std::env::var_os("XDG_DATA_DIRS") {
            Some(existing) => {
                let mut combined = bundled_data.into_os_string();
                combined.push(":");
                combined.push(existing);
                combined
            }
            None => bundled_data.into_os_string(),
        };
        std::env::set_var("XDG_DATA_DIRS", data_dirs);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn render_loader_cache(template: &str, app: &std::path::Path) -> String {
    let escaped = app
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    template.replace("@GUARD_APP@", &escaped)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EditableConfiguration {
    #[serde(default)]
    pub policy_enabled: bool,
    pub browsers: Vec<guard_platform::config::BrowserEnrollmentConfig>,
    pub enrolled_exes: Vec<std::path::PathBuf>,
    pub ssh_keys: Vec<std::path::PathBuf>,
    #[cfg(target_os = "macos")]
    #[serde(default)]
    pub mac_allowlist: platform_macos::config::MacAllowlistConfig,
}

pub const fn is_linux_backend() -> bool {
    cfg!(target_os = "linux")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformOverview {
    pub service_active: bool,
    pub helper_running: bool,
    pub extension_state: String,
    pub full_disk_access: String,
    pub policy_enabled: bool,
    pub helper_state: String,
    pub sip_state: String,
    pub developer_mode_state: String,
    pub host_entitlement_state: String,
    pub endpoint_security_entitlement_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacSetupReadiness {
    pub can_request_extension_install: bool,
    pub explanation: String,
}

#[cfg(not(target_os = "macos"))]
pub fn mac_setup_readiness() -> MacSetupReadiness {
    MacSetupReadiness {
        can_request_extension_install: false,
        explanation: "The macOS protection extension can only be installed on macOS.".into(),
    }
}

#[cfg(target_os = "macos")]
fn self_use_bundle_marker() -> Option<String> {
    let executable = std::env::current_exe().ok()?;
    let contents = executable.parent()?.parent()?;
    std::fs::read_to_string(contents.join("Resources/SELF_USE_SIP_OFF.txt")).ok()
}

#[cfg(target_os = "macos")]
fn self_use_safety_gate_valid(marker: &str) -> bool {
    marker
        .lines()
        .any(|line| line == "SAFETY_GATE=mac-auth-scope-v1")
}

#[cfg(target_os = "macos")]
fn current_app_bundle() -> Option<std::path::PathBuf> {
    std::env::current_exe()
        .ok()?
        .parent()?
        .parent()?
        .parent()
        .map(std::path::Path::to_path_buf)
}

#[cfg(target_os = "macos")]
fn self_use_app_is_in_applications() -> bool {
    current_app_bundle()
        .is_some_and(|app| app.parent() == Some(std::path::Path::new("/Applications")))
}

#[cfg(target_os = "macos")]
fn bundled_endpoint_security_entitlement_present() -> anyhow::Result<bool> {
    static RESULT: std::sync::OnceLock<Result<bool, String>> = std::sync::OnceLock::new();
    RESULT
        .get_or_init(|| {
            let app = current_app_bundle().ok_or_else(|| {
                String::from("Unable to locate the current Sensitive File Guard.app bundle")
            })?;
            platform_macos::system_extension::bundled_endpoint_security_entitlement_present(
                &app,
                platform_macos::DEFAULT_EXTENSION_BUNDLE_ID,
            )
            .map_err(|error| error.to_string())
        })
        .clone()
        .map_err(anyhow::Error::msg)
}

#[cfg(target_os = "macos")]
fn host_install_entitlement_present() -> anyhow::Result<bool> {
    static RESULT: std::sync::OnceLock<Result<bool, String>> = std::sync::OnceLock::new();
    RESULT
        .get_or_init(|| {
            platform_macos::system_extension::host_install_entitlement_present()
                .map_err(|error| error.to_string())
        })
        .clone()
        .map_err(anyhow::Error::msg)
}

#[cfg(target_os = "macos")]
fn sip_is_disabled() -> anyhow::Result<bool> {
    let output = std::process::Command::new("csrutil")
        .arg("status")
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout)
        .to_ascii_lowercase()
        .contains("disabled"))
}

pub fn overview_detail(
    daemon: Option<&guard_ipc::StatusInfo>,
    overview: &PlatformOverview,
) -> String {
    if cfg!(target_os = "macos") {
        return daemon.map_or_else(
            || {
                format!(
                    "Protection is not running · Protection extension: {} · Full Disk Access: {} · Confirmation helper: {}",
                    overview.extension_state, overview.full_disk_access, overview.helper_state
                )
            },
            |status| {
                format!(
                    "Backend: {} · Protection extension: {} · Full Disk Access: {} · Policy: {} · Read-only migration: {} · Confirmation helper: {} · Allowed: {} · Denied: {}",
                    status.backend_kind,
                    overview.extension_state,
                    overview.full_disk_access,
                    if overview.policy_enabled { "enabled" } else { "disabled" },
                    match status.read_only_guaranteed {
                        Some(true) => "guaranteed",
                        Some(false) => "not guaranteed",
                        None => "unknown",
                    },
                    overview.helper_state,
                    status.allowed,
                    status.denied
                )
            },
        );
    }
    let service_state = if overview.service_active {
        "active"
    } else {
        "inactive"
    };
    let notification_state = if overview.helper_running {
        "active"
    } else {
        "inactive"
    };
    daemon.map_or_else(
        || {
            format!(
                "guardd IPC is unavailable · service: {service_state} · notifications: {notification_state}"
            )
        },
        |status| {
            format!(
                "Backend: {} · browsers: {} · SSH keys: {} · allowed: {} · denied: {} · service: {} · notifications: {}",
                status.backend_kind,
                status.browsers,
                status.ssh_protected_keys,
                status.allowed,
                status.denied,
                service_state,
                notification_state
            )
        },
    )
}

pub const fn protection_switch_title() -> &'static str {
    if cfg!(target_os = "macos") {
        "Protection policy"
    } else {
        "Protection + notifications"
    }
}

pub const fn protection_switch_subtitle() -> &'static str {
    if cfg!(target_os = "macos") {
        "Complete extension installation and permission setup on the “Protection” page first."
    } else {
        "Controls guardd.service and guard-notify.service together; turning it off makes protected files accessible normally."
    }
}

#[cfg(target_os = "macos")]
pub fn mac_setup_readiness() -> MacSetupReadiness {
    let self_use_marker = self_use_bundle_marker();
    let self_use = self_use_marker
        .as_deref()
        .is_some_and(self_use_safety_gate_valid);
    if self_use_marker.is_some() && !self_use {
        return MacSetupReadiness {
            can_request_extension_install: false,
            explanation: "This SIP-off self-use build did not pass the current macOS AUTH_OPEN safety gate, so installation is disabled. Rebuild the app and do not activate the pre-incident package.".into(),
        };
    }
    if self_use && !sip_is_disabled().unwrap_or(false) {
        return MacSetupReadiness {
            can_request_extension_install: false,
            explanation: "This is a SIP-off self-use build, but SIP is still enabled. Run csrutil disable manually from macOS Recovery, restart, and return to install the extension; Sensitive File Guard will not and cannot modify SIP for you.".into(),
        };
    }
    if self_use && !self_use_app_is_in_applications() {
        return MacSetupReadiness {
            can_request_extension_install: false,
            explanation: "SIP-off self-use builds must be launched from /Applications for macOS to accept protection extension installation. Copy Sensitive File Guard.app to /Applications and reopen it; do not install from the build/ directory.".into(),
        };
    }
    let host_entitlement = host_install_entitlement_present();
    let endpoint_security_entitlement = bundled_endpoint_security_entitlement_present();
    match (host_entitlement, endpoint_security_entitlement) {
        (Ok(true), Ok(true)) => MacSetupReadiness {
            can_request_extension_install: true,
            explanation: if self_use {
                "SIP-off self-use checks passed: SIP is disabled and all signing entitlements are present. The button will submit an install or update request to macOS; if an older extension is active, macOS will replace it with the version in this bundle. Run sudo systemextensionsctl developer on manually before clicking.".into()
            } else {
                "The host installation entitlement and bundled Endpoint Security entitlement are present. You can request a protection extension install or update.".into()
            },
        },
        (Ok(false), _) => MacSetupReadiness {
            can_request_extension_install: false,
            explanation: "The final signed Sensitive File Guard host is missing com.apple.developer.system-extension.install; installation is disabled. Rebuild the package in the correct signing mode and do not try to activate it.".into(),
        },
        (_, Ok(false)) => MacSetupReadiness {
            can_request_extension_install: false,
            explanation: "The final bundled guard-es.systemextension is missing com.apple.developer.endpoint-security.client; installation is disabled. Rebuild the package in the correct signing mode and do not try to activate it.".into(),
        },
        (Err(error), _) => MacSetupReadiness {
            can_request_extension_install: false,
            explanation: format!("Sensitive File Guard could not inspect the host installation entitlement: {error}"),
        },
        (_, Err(error)) => MacSetupReadiness {
            can_request_extension_install: false,
            explanation: format!("Sensitive File Guard could not inspect the bundled Endpoint Security entitlement: {error}"),
        },
    }
}

#[cfg(target_os = "macos")]
pub fn request_system_extension_install() -> anyhow::Result<String> {
    use platform_macos::system_extension::LifecycleState;

    let readiness = mac_setup_readiness();
    anyhow::ensure!(
        readiness.can_request_extension_install,
        "{}",
        readiness.explanation
    );
    let controller = platform_macos::system_extension::SystemExtensionController::new(
        platform_macos::DEFAULT_EXTENSION_BUNDLE_ID,
    )?;
    controller.activate()?;
    let status = wait_for_lifecycle(&controller, std::time::Duration::from_secs(30))?;
    match status.state {
        LifecycleState::Active => Ok(
            "macOS completed the protection extension install/update and the current version is active. Return to this page to confirm that Endpoint Security is Active; if Full Disk Access still shows Required, grant that permission separately."
                .into(),
        ),
        LifecycleState::UserApprovalRequired => Ok(
            "macOS received the protection extension install/update request and is waiting for user approval. Allow Sensitive File Guard in the Endpoint Security Extensions pane in System Settings, then return here and refresh the status."
                .into(),
        ),
        LifecycleState::RestartRequired => Ok(
            "macOS accepted the protection extension update, but a restart is required. The new version will not be reported as active before restarting.".into(),
        ),
        LifecycleState::Deactivated => anyhow::bail!(
            "macOS reported that the extension is not active: {}. Confirm that the Sensitive File Guard extension has not been disabled in System Settings.",
            status.diagnostic
        ),
        LifecycleState::Failed | LifecycleState::Unknown | LifecycleState::Submitted => {
            anyhow::bail!(
                "macOS did not complete the protection extension install/update: state={:?}, diagnostic={}",
                status.state,
                status.diagnostic
            )
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub fn request_system_extension_install() -> anyhow::Result<String> {
    anyhow::bail!("The macOS protection extension can only be installed on macOS")
}

#[cfg(target_os = "macos")]
pub fn open_full_disk_access_settings() -> anyhow::Result<()> {
    let status = std::process::Command::new("open")
        .arg("x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")
        .status()?;
    anyhow::ensure!(
        status.success(),
        "macOS could not open the Full Disk Access settings"
    );
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn open_full_disk_access_settings() -> anyhow::Result<()> {
    anyhow::bail!("Full Disk Access settings can only be opened on macOS")
}

pub const fn apply_button_label() -> &'static str {
    if cfg!(target_os = "macos") {
        "Apply Policy"
    } else {
        "Apply & Restart"
    }
}

pub fn initial_configuration_if_missing(backend_reachable: bool) -> Option<EditableConfiguration> {
    if cfg!(target_os = "macos") && backend_reachable {
        Some(EditableConfiguration {
            policy_enabled: false,
            browsers: Vec::new(),
            enrolled_exes: Vec::new(),
            ssh_keys: Vec::new(),
            #[cfg(target_os = "macos")]
            mac_allowlist: platform_macos::config::MacAllowlistConfig::default(),
        })
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
pub fn platform_overview(
    daemon: Option<&guard_ipc::StatusInfo>,
    _configuration: Option<&guard_ipc::ConfigurationInfo>,
) -> PlatformOverview {
    let service = status().ok();
    let service_active = service
        .as_ref()
        .is_some_and(|status| status.protection_active);
    let helper_running = service
        .as_ref()
        .and_then(|status| status.notification_active)
        .unwrap_or(false);
    PlatformOverview {
        service_active,
        helper_running,
        extension_state: if service_active { "Active" } else { "Stopped" }.into(),
        full_disk_access: "Not applicable".into(),
        policy_enabled: daemon.is_some_and(|status| status.enforcement_active),
        helper_state: if helper_running {
            "Running"
        } else {
            "Not running"
        }
        .into(),
        sip_state: "Not applicable".into(),
        developer_mode_state: "Not applicable".into(),
        host_entitlement_state: "Not applicable".into(),
        endpoint_security_entitlement_state: "Not applicable".into(),
    }
}

#[cfg(target_os = "macos")]
pub fn platform_overview(
    daemon: Option<&guard_ipc::StatusInfo>,
    configuration: Option<&guard_ipc::ConfigurationInfo>,
) -> PlatformOverview {
    use platform_macos::user_agent::{UserAgentController, UserAgentStatus};

    let policy_enabled = configuration
        .and_then(|configuration| configuration.policy_enabled)
        .unwrap_or(false);
    let helper_running = policy_enabled
        && guard_client::macos::MacGuardClient::for_current_process()
            .and_then(|client| client.pending_helper_status())
            .is_ok_and(|status| status.running);
    let agent_status = UserAgentController::bundled().and_then(|agent| agent.status());
    let helper_state = match agent_status {
        Ok(UserAgentStatus::Enabled) if helper_running => "Running",
        Ok(UserAgentStatus::Enabled) => "Enabled, not responding",
        Ok(UserAgentStatus::RequiresApproval) => "Pending user approval",
        Ok(UserAgentStatus::NotRegistered) => "Not running",
        Ok(UserAgentStatus::NotFound) => "Not found in app bundle",
        Err(_) => "Status unavailable",
    };
    PlatformOverview {
        service_active: daemon.is_some(),
        helper_running,
        extension_state: mac_extension_state(daemon.is_some()),
        full_disk_access: mac_full_disk_access(daemon),
        policy_enabled,
        helper_state: helper_state.into(),
        sip_state: if self_use_bundle_marker().is_some() {
            match sip_is_disabled() {
                Ok(true) => "Disabled (required for self-use mode)".into(),
                Ok(false) => "Enabled (self-use mode unavailable)".into(),
                Err(_) => "Unable to check".into(),
            }
        } else {
            "Not applicable".into()
        },
        developer_mode_state: if self_use_bundle_marker().is_some() {
            "Enable manually: sudo systemextensionsctl developer on (macOS has no read-only status query)"
                .into()
        } else {
            "Not applicable".into()
        },
        host_entitlement_state: match host_install_entitlement_present() {
            Ok(true) => "Present".into(),
            Ok(false) => "Missing (extension cannot be installed)".into(),
            Err(error) => format!("Check failed: {error}"),
        },
        endpoint_security_entitlement_state: match bundled_endpoint_security_entitlement_present() {
            Ok(true) => "Present".into(),
            Ok(false) => "Missing (Endpoint Security cannot start)".into(),
            Err(error) => format!("Check failed: {error}"),
        },
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn platform_overview(
    _daemon: Option<&guard_ipc::StatusInfo>,
    _configuration: Option<&guard_ipc::ConfigurationInfo>,
) -> PlatformOverview {
    PlatformOverview {
        service_active: false,
        helper_running: false,
        extension_state: "Unsupported".into(),
        full_disk_access: "Unknown".into(),
        policy_enabled: false,
        helper_state: "Unsupported".into(),
        sip_state: "Unsupported".into(),
        developer_mode_state: "Unsupported".into(),
        host_entitlement_state: "Unsupported".into(),
        endpoint_security_entitlement_state: "Unsupported".into(),
    }
}

#[cfg(target_os = "macos")]
fn mac_extension_state(xpc_reachable: bool) -> String {
    use platform_macos::system_extension::{LifecycleState, SystemExtensionController};

    if xpc_reachable {
        return "Active".into();
    }
    let controller =
        match SystemExtensionController::new(platform_macos::DEFAULT_EXTENSION_BUNDLE_ID) {
            Ok(controller) => controller,
            Err(_) => return "Error".into(),
        };
    if controller.refresh().is_err() {
        return "Error".into();
    }
    // OSSystemExtension properties are delivered asynchronously. A 250 ms
    // sample routinely races the reply and makes an active extension look
    // uninstalled while the control-plane XPC service is starting.
    for _ in 0..30 {
        let state = controller.status().map(|status| status.state);
        match state {
            Ok(LifecycleState::Submitted) => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Ok(LifecycleState::UserApprovalRequired) => return "Pending approval".into(),
            Ok(LifecycleState::Active) => return "Active".into(),
            Ok(LifecycleState::RestartRequired) => return "Restart required".into(),
            Ok(LifecycleState::Deactivated) => return "Installed, disabled".into(),
            Ok(LifecycleState::Failed) => return "Error".into(),
            Ok(LifecycleState::Unknown) | Err(_) => return "Not installed / unknown".into(),
        }
    }
    "Status pending".into()
}

#[cfg(target_os = "macos")]
fn mac_full_disk_access(daemon: Option<&guard_ipc::StatusInfo>) -> String {
    match daemon.and_then(|status| status.backend_state.as_deref()) {
        Some("REQUIRES_FULL_DISK_ACCESS") => "Required".into(),
        Some("ACTIVE" | "DEGRADED") => "Granted".into(),
        _ => "Unknown".into(),
    }
}

pub fn set_protection_enabled(
    enabled: bool,
    candidate: Option<EditableConfiguration>,
) -> anyhow::Result<EditableConfiguration> {
    #[cfg(target_os = "linux")]
    {
        let candidate = candidate.ok_or_else(|| anyhow::anyhow!("active policy is unavailable"))?;
        let verb = if enabled {
            ServiceOperation::Start
        } else {
            ServiceOperation::Stop
        };
        if enabled {
            apply(verb)?;
            if let Err(error) = apply_notifications(verb) {
                let _ = apply(ServiceOperation::Stop);
                return Err(error);
            }
        } else {
            apply_notifications(verb)?;
            if let Err(error) = apply(verb) {
                let _ = apply_notifications(ServiceOperation::Start);
                return Err(error);
            }
        }
        Ok(candidate)
    }
    #[cfg(target_os = "macos")]
    {
        let mut candidate =
            candidate.ok_or_else(|| anyhow::anyhow!("active policy is unavailable"))?;
        let previous_enabled = candidate.policy_enabled;
        candidate.policy_enabled = enabled;
        let bytes = serde_json::to_vec(&candidate)?;
        apply_config(&bytes)?;
        // The notification helper is part of the protection service lifecycle
        // on macOS. It must never keep polling the control plane after the
        // user has turned protection off. Registration is deliberately done
        // through SMAppService, so disabling it also asks launchd to stop the
        // existing guard-notify process.
        if let Err(error) = set_user_agent_enabled(enabled) {
            // Do not leave the UI reporting a green service while its
            // notification companion is still running (or failed to start).
            // Restore the previous policy atomically from the user's point of
            // view; the next poll will then show the real helper state.
            candidate.policy_enabled = previous_enabled;
            let rollback = match serde_json::to_vec(&candidate) {
                Ok(bytes) => apply_config(&bytes),
                Err(rollback_error) => Err(anyhow::anyhow!(rollback_error)),
            };
            if let Err(rollback_error) = rollback {
                eprintln!(
                    "guard-ui: guard-notify lifecycle failed ({error:#}); policy rollback also failed: {rollback_error:#}"
                );
            }
            return Err(anyhow::anyhow!(
                "guard-notify lifecycle update failed; protection change rolled back: {error:#}"
            ));
        }
        Ok(candidate)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (enabled, candidate);
        anyhow::bail!("protection control is unavailable on this target")
    }
}

#[cfg(target_os = "macos")]
pub fn set_user_agent_enabled(enabled: bool) -> anyhow::Result<()> {
    if enabled {
        let protection_enabled = configuration()?.policy_enabled.unwrap_or(false);
        anyhow::ensure!(
            protection_enabled,
            "Enable protection before starting guard-notify"
        );
    }
    let agent = platform_macos::user_agent::UserAgentController::bundled()?;
    if enabled {
        agent.register()
    } else {
        agent.unregister()
    }
}

#[cfg(not(target_os = "macos"))]
pub fn set_user_agent_enabled(_enabled: bool) -> anyhow::Result<()> {
    anyhow::bail!("SMAppService is available only on macOS")
}

pub fn editable_from_metadata(info: guard_ipc::ConfigurationInfo) -> Option<EditableConfiguration> {
    let mut browsers = Vec::with_capacity(info.browsers.len());
    for browser in info.browsers {
        let family = match browser.family.as_str() {
            "Chromium" | "chromium" => guard_core::BrowserFamily::Chromium,
            "Firefox" | "firefox" => guard_core::BrowserFamily::Firefox,
            "Zen" | "zen" => guard_core::BrowserFamily::Zen,
            "Safari" | "safari" => guard_core::BrowserFamily::Safari,
            _ => return None,
        };
        browsers.push(guard_platform::config::BrowserEnrollmentConfig {
            id: browser.id,
            family,
            profile_root: browser.profile_root.into(),
            owner_uid: browser.owner_uid,
            exe_paths: browser.exe_paths.into_iter().map(Into::into).collect(),
        });
    }
    #[cfg(target_os = "macos")]
    let current_uid = unsafe { libc::geteuid() };

    #[cfg(target_os = "macos")]
    let mac_allowlist = platform_macos::config::MacAllowlistConfig {
        system_processes: info
            .mac_system_processes
            .into_iter()
            .map(|rule| platform_macos::config::MacSystemProcessRule {
                path: rule.path.into(),
                team_id: None,
                signing_id: rule.signing_id,
                platform_binary: true,
                owner_uid: 0,
                allow_kinds: rule
                    .allow_kinds
                    .into_iter()
                    .filter_map(|kind| match kind.as_str() {
                        "browser_history" => Some(guard_core::ProtectedResourceKind::History),
                        _ => None,
                    })
                    .collect(),
            })
            .collect(),
        trusted_tools: info
            .mac_trusted_tools
            .into_iter()
            .map(|rule| platform_macos::config::MacTrustedToolRule {
                path: rule.path.into(),
                dev: rule.dev,
                ino: rule.ino,
                team_id: rule.team_id,
                signing_id: rule.signing_id,
                owner_uid: current_uid,
            })
            .collect(),
    };

    Some(EditableConfiguration {
        policy_enabled: info.policy_enabled.unwrap_or(cfg!(target_os = "linux")),
        browsers,
        enrolled_exes: info.enrolled_exes.into_iter().map(Into::into).collect(),
        ssh_keys: info.ssh_keys.into_iter().map(Into::into).collect(),
        #[cfg(target_os = "macos")]
        mac_allowlist,
    })
}

#[cfg(target_os = "linux")]
pub fn discover_native_browsers(
    home: &std::path::Path,
) -> guard_platform::config::BrowserDiscovery {
    let output = std::process::Command::new("guardctl")
        .args(["browser", "discover", "--home"])
        .arg(home)
        .output();
    output
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| serde_json::from_slice(&output.stdout).ok())
        .unwrap_or_else(empty_browser_discovery)
}

#[cfg(target_os = "macos")]
pub fn discover_native_browsers(
    home: &std::path::Path,
) -> guard_platform::config::BrowserDiscovery {
    use std::sync::Arc;

    platform_macos::discovery::MacBrowserDiscovery::system(Arc::new(
        platform_macos::code_signature::NativeCodeSignatureInspector,
    ))
    .discover_verified(home)
    .portable
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn discover_native_browsers(
    _home: &std::path::Path,
) -> guard_platform::config::BrowserDiscovery {
    empty_browser_discovery()
}

#[cfg(not(target_os = "macos"))]
fn empty_browser_discovery() -> guard_platform::config::BrowserDiscovery {
    guard_platform::config::BrowserDiscovery {
        browsers: Vec::new(),
        unsupported_sandboxed: Vec::new(),
    }
}

#[cfg(target_os = "macos")]
pub fn handle_system_extension_command() -> Option<i32> {
    use platform_macos::system_extension::LifecycleState;

    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments
        .iter()
        .any(|argument| argument == "--discover-macos-browsers")
    {
        return Some(discover_macos_browsers(&arguments));
    }
    if arguments.iter().any(|argument| argument == "--xpc-status") {
        return Some(xpc_status());
    }
    if arguments
        .iter()
        .any(|argument| argument == "--pending-helper-status")
    {
        return Some(pending_helper_status());
    }
    if arguments
        .iter()
        .any(|argument| argument == "--register-pending-helper")
    {
        return Some(pending_helper_mutation(true));
    }
    if arguments
        .iter()
        .any(|argument| argument == "--unregister-pending-helper")
    {
        return Some(pending_helper_mutation(false));
    }
    let action = std::env::args().find(|argument| {
        matches!(
            argument.as_str(),
            "--activate-system-extension"
                | "--activate-system-extension-watchdog"
                | "--deactivate-system-extension"
                | "--system-extension-status"
        )
    });
    let action = action?;
    let identifier = option_env!("GUARD_SYSTEM_EXTENSION_BUNDLE_ID")
        .unwrap_or(platform_macos::DEFAULT_EXTENSION_BUNDLE_ID);
    let controller =
        match platform_macos::system_extension::SystemExtensionController::new(identifier) {
            Ok(controller) => controller,
            Err(error) => {
                eprintln!("guard-ui: {error}");
                return Some(1);
            }
        };
    if action == "--activate-system-extension-watchdog" {
        return Some(run_system_extension_watchdog(&controller));
    }
    let submitted = match action.as_str() {
        "--activate-system-extension" => controller.activate(),
        "--deactivate-system-extension" => controller.deactivate(),
        "--system-extension-status" => controller.refresh(),
        _ => unreachable!(),
    };
    if let Err(error) = submitted {
        eprintln!("guard-ui: {error}");
        return Some(1);
    }
    match wait_for_lifecycle(&controller, std::time::Duration::from_secs(30)) {
        Ok(status) => {
            println!(
                "system-extension state={:?} diagnostic={}",
                status.state, status.diagnostic
            );
            Some(i32::from(status.state == LifecycleState::Failed))
        }
        Err(error) => {
            eprintln!("guard-ui: {error}");
            Some(1)
        }
    }
}

#[cfg(target_os = "macos")]
fn wait_for_lifecycle(
    controller: &platform_macos::system_extension::SystemExtensionController,
    timeout: std::time::Duration,
) -> anyhow::Result<platform_macos::system_extension::LifecycleStatus> {
    use platform_macos::system_extension::LifecycleState;

    let deadline = std::time::Instant::now() + timeout;
    loop {
        let status = controller.status()?;
        if status.state != LifecycleState::Submitted {
            return Ok(status);
        }
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "system extension request still pending after {} seconds",
            timeout.as_secs()
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[cfg(target_os = "macos")]
fn wait_for_activation(
    controller: &platform_macos::system_extension::SystemExtensionController,
    timeout: std::time::Duration,
) -> anyhow::Result<platform_macos::system_extension::LifecycleStatus> {
    use platform_macos::system_extension::LifecycleState;

    let deadline = std::time::Instant::now() + timeout;
    loop {
        let status = controller.status()?;
        if !matches!(
            status.state,
            LifecycleState::Submitted | LifecycleState::UserApprovalRequired
        ) {
            return Ok(status);
        }
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "system extension did not become active within {} seconds (last state={:?}, diagnostic={})",
            timeout.as_secs(),
            status.state,
            status.diagnostic
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[cfg(target_os = "macos")]
fn watchdog_seconds(value: Option<&str>) -> anyhow::Result<u64> {
    let seconds = value.unwrap_or("90").parse::<u64>()?;
    anyhow::ensure!(
        (15..=1_800).contains(&seconds),
        "GUARD_EXTENSION_WATCHDOG_SECONDS must be between 15 and 1800"
    );
    Ok(seconds)
}

#[cfg(target_os = "macos")]
fn watchdog_stop_file(value: Option<std::ffi::OsString>) -> anyhow::Result<std::path::PathBuf> {
    let path = value
        .map(std::path::PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("GUARD_EXTENSION_WATCHDOG_STOP_FILE is required"))?;
    anyhow::ensure!(path.is_absolute(), "watchdog stop file must be absolute");
    anyhow::ensure!(!path.exists(), "watchdog stop file already exists");
    anyhow::ensure!(
        path.parent().is_some_and(std::path::Path::is_dir),
        "watchdog stop file parent does not exist"
    );
    Ok(path)
}

#[cfg(target_os = "macos")]
fn ordinary_file_open_sanity() -> anyhow::Result<()> {
    use std::io::Read;

    for path in [
        "/System/Library/CoreServices/SystemVersion.plist",
        "/etc/hosts",
        "/bin/sh",
    ] {
        let mut file = std::fs::File::open(path)
            .map_err(|error| anyhow::anyhow!("ordinary open failed for {path}: {error}"))?;
        let mut first_byte = [0_u8; 1];
        file.read_exact(&mut first_byte)
            .map_err(|error| anyhow::anyhow!("ordinary read failed for {path}: {error}"))?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn ordinary_process_sanity() -> anyhow::Result<()> {
    let status = std::process::Command::new("/bin/cat")
        .arg("/System/Library/CoreServices/SystemVersion.plist")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    anyhow::ensure!(status.success(), "ordinary /bin/cat probe failed: {status}");
    let status = std::process::Command::new("/usr/bin/true")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    anyhow::ensure!(
        status.success(),
        "ordinary /usr/bin/true probe failed: {status}"
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn ordinary_sanity_with_timeout(timeout: std::time::Duration) -> anyhow::Result<()> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = sender.send(ordinary_file_open_sanity().and_then(|_| ordinary_process_sanity()));
    });
    match receiver.recv_timeout(timeout) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => anyhow::bail!(
            "ordinary file/process sanity did not complete within {} milliseconds",
            timeout.as_millis()
        ),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            anyhow::bail!("ordinary file/process sanity worker disconnected")
        }
    }
}

#[cfg(target_os = "macos")]
fn deactivate_after_watchdog(
    controller: &platform_macos::system_extension::SystemExtensionController,
) -> anyhow::Result<()> {
    use platform_macos::system_extension::LifecycleState;

    controller.deactivate()?;
    let status = wait_for_lifecycle(controller, std::time::Duration::from_secs(30))?;
    anyhow::ensure!(
        status.state == LifecycleState::Deactivated,
        "watchdog deactivation did not complete safely: state={:?}, diagnostic={}",
        status.state,
        status.diagnostic
    );
    println!(
        "WATCHDOG_DEACTIVATED state={:?} diagnostic={}",
        status.state, status.diagnostic
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_system_extension_watchdog(
    controller: &platform_macos::system_extension::SystemExtensionController,
) -> i32 {
    use platform_macos::system_extension::LifecycleState;
    use std::io::Write;

    let result = (|| -> anyhow::Result<()> {
        let seconds = watchdog_seconds(
            std::env::var("GUARD_EXTENSION_WATCHDOG_SECONDS")
                .ok()
                .as_deref(),
        )?;
        let stop_file = watchdog_stop_file(std::env::var_os("GUARD_EXTENSION_WATCHDOG_STOP_FILE"))?;
        controller.activate()?;
        let session = (|| -> anyhow::Result<()> {
            let status = wait_for_activation(controller, std::time::Duration::from_secs(120))?;
            anyhow::ensure!(
                status.state == LifecycleState::Active,
                "watchdog activation did not become active: state={:?}, diagnostic={}",
                status.state,
                status.diagnostic
            );

            ordinary_sanity_with_timeout(std::time::Duration::from_secs(2))?;
            println!("WATCHDOG_ACTIVE duration_seconds={seconds}");
            std::io::stdout().flush()?;

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
            let mut next_probe = std::time::Instant::now();
            while std::time::Instant::now() < deadline && !stop_file.exists() {
                if std::time::Instant::now() >= next_probe {
                    ordinary_sanity_with_timeout(std::time::Duration::from_secs(2))?;
                    next_probe = std::time::Instant::now() + std::time::Duration::from_millis(500);
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Ok(())
        })();
        let deactivation = deactivate_after_watchdog(controller);
        match (session, deactivation) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error.context("activation watchdog tripped; deactivated")),
            (Ok(()), Err(error)) => Err(error.context("activation watchdog could not deactivate")),
            (Err(error), Err(deactivation)) => Err(error.context(format!(
                "activation watchdog tripped AND deactivation failed: {deactivation:#}"
            ))),
        }
    })();

    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("guard-ui: activation watchdog failed: {error:#}");
            1
        }
    }
}

#[cfg(target_os = "macos")]
fn xpc_status() -> i32 {
    match guard_client::macos::MacGuardClient::for_current_process()
        .and_then(|client| client.status())
    {
        Ok(status) => match serde_json::to_string_pretty(&status) {
            Ok(status) => {
                println!("{status}");
                0
            }
            Err(error) => {
                eprintln!("guard-ui: could not encode XPC status: {error}");
                1
            }
        },
        Err(error) => {
            eprintln!("guard-ui: authenticated XPC status failed: {error:#}");
            1
        }
    }
}

#[cfg(target_os = "macos")]
fn pending_helper_status() -> i32 {
    match platform_macos::user_agent::UserAgentController::bundled()
        .and_then(|controller| controller.status())
    {
        Ok(status) => {
            println!("{status:?}");
            0
        }
        Err(error) => {
            eprintln!("guard-ui: pending helper status failed: {error:#}");
            1
        }
    }
}

#[cfg(target_os = "macos")]
fn pending_helper_mutation(register: bool) -> i32 {
    if register {
        match configuration().and_then(|configuration| {
            anyhow::ensure!(
                configuration.policy_enabled.unwrap_or(false),
                "Enable protection before starting guard-notify"
            );
            Ok(())
        }) {
            Ok(()) => {}
            Err(error) => {
                eprintln!("guard-ui: pending helper registration refused: {error:#}");
                return 1;
            }
        }
    }
    let result =
        platform_macos::user_agent::UserAgentController::bundled().and_then(|controller| {
            if register {
                controller.register()
            } else {
                controller.unregister()
            }
        });
    match result {
        Ok(()) => {
            println!(
                "pending helper {}",
                if register {
                    "registered"
                } else {
                    "unregistered"
                }
            );
            0
        }
        Err(error) => {
            eprintln!("guard-ui: pending helper mutation failed: {error:#}");
            1
        }
    }
}

#[cfg(target_os = "macos")]
fn discover_macos_browsers(arguments: &[String]) -> i32 {
    use std::sync::Arc;

    let option = |name: &str| {
        arguments
            .iter()
            .position(|argument| argument == name)
            .and_then(|index| arguments.get(index + 1))
            .map(std::path::PathBuf::from)
    };
    let home = match option("--home").or_else(|| std::env::var_os("HOME").map(Into::into)) {
        Some(home) => home,
        None => {
            eprintln!("guard-ui: --discover-macos-browsers requires --home or HOME");
            return 2;
        }
    };
    let applications =
        option("--applications-root").unwrap_or_else(|| std::path::PathBuf::from("/Applications"));
    let discovery = platform_macos::discovery::MacBrowserDiscovery::new(
        vec![applications],
        Arc::new(platform_macos::code_signature::NativeCodeSignatureInspector),
    )
    .discover_verified(&home);
    let output = serde_json::json!({
        "browsers": discovery.review,
        "unsupported_or_custom_needed": discovery.portable.unsupported_sandboxed,
    });
    match serde_json::to_string_pretty(&output) {
        Ok(output) => {
            println!("{output}");
            0
        }
        Err(error) => {
            eprintln!("guard-ui: could not encode browser discovery result: {error}");
            1
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub fn handle_system_extension_command() -> Option<i32> {
    let requested = std::env::args().any(|argument| {
        matches!(
            argument.as_str(),
            "--activate-system-extension"
                | "--activate-system-extension-watchdog"
                | "--deactivate-system-extension"
                | "--system-extension-status"
                | "--discover-macos-browsers"
                | "--xpc-status"
                | "--pending-helper-status"
                | "--register-pending-helper"
                | "--unregister-pending-helper"
        )
    });
    if requested {
        eprintln!("guard-ui: SystemExtensions lifecycle commands are available only on macOS");
        Some(1)
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn verb(operation: ServiceOperation) -> &'static str {
    match operation {
        ServiceOperation::Start => "start",
        ServiceOperation::Stop => "stop",
        ServiceOperation::Restart => "restart",
    }
}

#[cfg(target_os = "linux")]
pub fn status() -> anyhow::Result<ServiceStatus> {
    let output = std::process::Command::new("guardctl")
        .arg("service-status")
        .output()?;
    anyhow::ensure!(output.status.success(), "guardctl service status failed");
    Ok(serde_json::from_slice(&output.stdout)?)
}

#[cfg(target_os = "linux")]
pub fn apply(operation: ServiceOperation) -> anyhow::Result<()> {
    let status = std::process::Command::new("pkexec")
        .args(["guardctl", "privileged", "service", verb(operation)])
        .status()?;
    anyhow::ensure!(status.success(), "protection service operation failed");
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn apply_notifications(operation: ServiceOperation) -> anyhow::Result<()> {
    let status = std::process::Command::new("guardctl")
        .args(["notification-service", verb(operation)])
        .status()?;
    anyhow::ensure!(status.success(), "notification service operation failed");
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn apply_config(bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = std::process::Command::new("pkexec")
        .args(["guardctl", "privileged", "apply-config"])
        .stdin(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("privileged helper stdin unavailable"))?
        .write_all(bytes)?;
    anyhow::ensure!(child.wait()?.success(), "configuration apply failed");
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn apply_config(bytes: &[u8]) -> anyhow::Result<()> {
    let editable: EditableConfiguration = serde_json::from_slice(bytes)?;
    let config = mac_config_from_editable(editable)?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    guard_client::macos::MacGuardClient::for_current_process()?
        .apply_configuration(&config, deadline)
        .map(|_| ())
}

#[cfg(target_os = "macos")]
fn mac_config_from_editable(
    editable: EditableConfiguration,
) -> anyhow::Result<platform_macos::config::MacBackendConfig> {
    use guard_core::resource::BrowserId;
    use std::sync::Arc;

    // SAFETY: geteuid has no pointer arguments and reads only the caller's
    // kernel credential.
    let peer_uid = unsafe { libc::geteuid() };
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("HOME is unset; browser trust cannot be rebuilt"))?;
    let discovery = platform_macos::discovery::MacBrowserDiscovery::system(Arc::new(
        platform_macos::code_signature::NativeCodeSignatureInspector,
    ));
    let verified = discovery.discover_verified(&home).enrollments;
    let mut common_browsers = Vec::with_capacity(editable.browsers.len());
    let mut browser_trust = Vec::with_capacity(editable.browsers.len());
    for browser in editable.browsers {
        anyhow::ensure!(
            browser.owner_uid.is_none() || browser.owner_uid == Some(peer_uid),
            "browser configuration belongs to another user"
        );
        let enrollment = verified
            .iter()
            .find(|candidate| {
                candidate.browser_id.0 == browser.id
                    && candidate.profile_root == browser.profile_root
                    && candidate
                        .executables
                        .iter()
                        .map(|executable| executable.path())
                        .eq(browser.exe_paths.iter().map(std::path::PathBuf::as_path))
            })
            .cloned()
            .map(Ok)
            .unwrap_or_else(|| {
                anyhow::ensure!(
                    browser.exe_paths.len() == 1,
                    "custom browser enrollment requires exactly one executable"
                );
                discovery.enroll_custom(
                    BrowserId(browser.id.clone()),
                    browser.family,
                    &browser.profile_root,
                    &browser.exe_paths[0],
                    peer_uid,
                )
            })?;
        let mut common = browser;
        common.owner_uid = Some(peer_uid);
        common.exe_paths = enrollment
            .executables
            .iter()
            .map(|executable| executable.path().to_path_buf())
            .collect();
        common_browsers.push(common);
        browser_trust.push(enrollment);
    }
    let config = platform_macos::config::MacBackendConfig {
        version: platform_macos::config::MAC_CONFIG_VERSION,
        policy_enabled: editable.policy_enabled,
        common_policy: guard_platform::config::PolicyConfig {
            browsers: common_browsers,
            enrolled_exes: editable.enrolled_exes,
            ssh_keys: editable.ssh_keys,
        },
        browser_trust,
        mac_allowlist: editable.mac_allowlist,
    }
    .with_builtin_mac_allowlist();
    config.validate_for_peer(peer_uid)?;
    Ok(config)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn apply_config(_bytes: &[u8]) -> anyhow::Result<()> {
    anyhow::bail!("configuration apply is not implemented for this target")
}

#[cfg(target_os = "linux")]
pub fn resolve_pending(
    kind: PromptKind,
    id: &str,
    allow: bool,
    _expires_at: u64,
) -> anyhow::Result<()> {
    let socket = std::path::Path::new("/run/guardd/guardd.sock");
    match (kind, allow) {
        (PromptKind::Migration, true) => guard_client::resolve_migration(
            socket,
            id,
            guard_ipc::MigrationResolutionAction::AllowImport,
        )
        .map(|_| ()),
        (PromptKind::Migration, false) => {
            guard_client::resolve_migration(socket, id, guard_ipc::MigrationResolutionAction::Block)
                .map(|_| ())
        }
        (PromptKind::SshRead, true) => {
            guard_client::resolve_ssh_read(socket, id, guard_ipc::SshReadResolutionAction::Allow)
                .map(|_| ())
        }
        (PromptKind::SshRead, false) => {
            guard_client::resolve_ssh_read(socket, id, guard_ipc::SshReadResolutionAction::Block)
                .map(|_| ())
        }
    }
}

pub fn pending_error_is_terminal(error: &anyhow::Error) -> bool {
    #[cfg(target_os = "macos")]
    if error.chain().any(|cause| {
        cause
            .downcast_ref::<platform_macos::local_auth::AuthenticationError>()
            .is_some_and(|authentication| {
                authentication.failure
                    == platform_macos::local_auth::AuthenticationFailure::TimedOut
            })
    }) {
        return true;
    }
    let message = error.to_string();
    message.contains("timed_out")
        || message.contains("timed out")
        || message.contains("already_resolved")
}

#[cfg(target_os = "macos")]
pub fn resolve_pending(
    kind: PromptKind,
    id: &str,
    allow: bool,
    expires_at: u64,
) -> anyhow::Result<()> {
    let client = guard_client::macos::MacGuardClient::for_current_process()?;
    if allow {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        anyhow::ensure!(expires_at > now, "pending request already timed out");
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_secs(expires_at.saturating_sub(now));
        match kind {
            PromptKind::Migration => client.allow_migration(id, deadline).map(|_| ()),
            PromptKind::SshRead => client.allow_ssh_read(id, deadline).map(|_| ()),
        }
    } else {
        match kind {
            PromptKind::Migration => client.block_migration(id).map(|_| ()),
            PromptKind::SshRead => client.block_ssh_read(id).map(|_| ()),
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn resolve_pending(
    _kind: PromptKind,
    _id: &str,
    _allow: bool,
    _expires_at: u64,
) -> anyhow::Result<()> {
    anyhow::bail!("pending authorization is unavailable for this target")
}

#[cfg(target_os = "linux")]
pub fn daemon_status() -> anyhow::Result<guard_ipc::StatusInfo> {
    guard_client::status(std::path::Path::new("/run/guardd/guardd.sock"))
}

#[cfg(target_os = "macos")]
pub fn daemon_status() -> anyhow::Result<guard_ipc::StatusInfo> {
    guard_client::macos::MacGuardClient::for_current_process()?.status()
}

#[cfg(target_os = "linux")]
pub fn configuration() -> anyhow::Result<guard_ipc::ConfigurationInfo> {
    guard_client::configuration(std::path::Path::new("/run/guardd/guardd.sock"))
}

#[cfg(target_os = "macos")]
pub fn configuration() -> anyhow::Result<guard_ipc::ConfigurationInfo> {
    guard_client::macos::MacGuardClient::for_current_process()?.configuration()
}

#[cfg(target_os = "linux")]
pub fn resources() -> anyhow::Result<Vec<guard_ipc::ResourceInfo>> {
    guard_client::resources(std::path::Path::new("/run/guardd/guardd.sock"))
}

#[cfg(target_os = "macos")]
pub fn resources() -> anyhow::Result<Vec<guard_ipc::ResourceInfo>> {
    guard_client::macos::MacGuardClient::for_current_process()?.resources()
}

#[cfg(target_os = "linux")]
pub fn events_cursor(
    limit: Option<u32>,
    before_id: Option<i64>,
    after_id: Option<i64>,
) -> anyhow::Result<Vec<guard_ipc::EventInfo>> {
    guard_client::events_cursor(
        std::path::Path::new("/run/guardd/guardd.sock"),
        limit,
        before_id,
        after_id,
    )
}

#[cfg(target_os = "macos")]
pub fn events_cursor(
    limit: Option<u32>,
    before_id: Option<i64>,
    after_id: Option<i64>,
) -> anyhow::Result<Vec<guard_ipc::EventInfo>> {
    guard_client::macos::MacGuardClient::for_current_process()?
        .events_cursor(limit, before_id, after_id)
}

#[cfg(target_os = "linux")]
pub fn ssh_pending() -> anyhow::Result<Vec<guard_ipc::SshPendingInfo>> {
    guard_client::ssh_pending(std::path::Path::new("/run/guardd/guardd.sock"))
}

#[cfg(target_os = "macos")]
pub fn ssh_pending() -> anyhow::Result<Vec<guard_ipc::SshPendingInfo>> {
    guard_client::macos::MacGuardClient::for_current_process()?.ssh_pending()
}

#[cfg(target_os = "linux")]
pub fn migration_pending() -> anyhow::Result<Vec<guard_ipc::MigrationPendingInfo>> {
    guard_client::migration_pending(std::path::Path::new("/run/guardd/guardd.sock"))
}

#[cfg(target_os = "macos")]
pub fn migration_pending() -> anyhow::Result<Vec<guard_ipc::MigrationPendingInfo>> {
    guard_client::macos::MacGuardClient::for_current_process()?.migration_pending()
}

#[cfg(all(test, target_os = "macos"))]
mod bundled_runtime_tests {
    use super::{
        ordinary_file_open_sanity, ordinary_process_sanity, ordinary_sanity_with_timeout,
        render_loader_cache, self_use_safety_gate_valid, watchdog_seconds, watchdog_stop_file,
    };

    #[test]
    fn loader_cache_is_relocated_and_escaped() {
        let rendered = render_loader_cache(
            "\"@GUARD_APP@/Contents/Resources/gdk-pixbuf/loaders/module.so\"",
            std::path::Path::new("/Applications/Guard \"QA\".app"),
        );
        assert!(!rendered.contains("@GUARD_APP@"));
        assert!(rendered.contains(r#"/Applications/Guard \"QA\".app/Contents"#));
    }

    #[test]
    fn self_use_marker_requires_the_current_auth_scope_gate() {
        assert!(self_use_safety_gate_valid(
            "SELF-USE / SIP-OFF\nSAFETY_GATE=mac-auth-scope-v1\n"
        ));
        assert!(!self_use_safety_gate_valid("SELF-USE / SIP-OFF\n"));
        assert!(!self_use_safety_gate_valid(
            "SELF-USE / SIP-OFF\nSAFETY_GATE=older-revision\n"
        ));
    }

    #[test]
    fn activation_watchdog_duration_is_short_and_bounded() {
        assert_eq!(watchdog_seconds(None).unwrap(), 90);
        assert_eq!(watchdog_seconds(Some("15")).unwrap(), 15);
        assert_eq!(watchdog_seconds(Some("1800")).unwrap(), 1_800);
        assert!(watchdog_seconds(Some("14")).is_err());
        assert!(watchdog_seconds(Some("1801")).is_err());
        assert!(watchdog_seconds(Some("not-a-number")).is_err());
    }

    #[test]
    fn activation_watchdog_stop_path_is_absolute_nonexistent_and_space_safe() {
        let temporary = tempfile::tempdir().unwrap();
        let stop = temporary.path().join("stop Guard watchdog now");
        assert_eq!(
            watchdog_stop_file(Some(stop.clone().into_os_string())).unwrap(),
            stop
        );
        std::fs::write(&stop, b"stop").unwrap();
        assert!(watchdog_stop_file(Some(stop.into_os_string())).is_err());
        assert!(watchdog_stop_file(Some("relative-stop".into())).is_err());
    }

    #[test]
    fn activation_watchdog_can_open_and_spawn_ordinary_system_targets() {
        ordinary_file_open_sanity().unwrap();
        ordinary_process_sanity().unwrap();
        ordinary_sanity_with_timeout(std::time::Duration::from_secs(2)).unwrap();
    }
}
