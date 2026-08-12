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
            .join("Library/Caches/io.github.plfjy.SensitiveFileGuard");
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LinuxEnforcementMode {
    Conservative,
    StrictFilesystem,
}

impl LinuxEnforcementMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Conservative => "conservative",
            Self::StrictFilesystem => "strict-filesystem",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EditableConfiguration {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforcement_mode: Option<LinuxEnforcementMode>,
    #[serde(default)]
    pub policy_enabled: bool,
    pub browsers: Vec<guard_platform::config::BrowserEnrollmentConfig>,
    pub enrolled_exes: Vec<std::path::PathBuf>,
    pub ssh_keys: Vec<std::path::PathBuf>,
}

pub const fn shows_linux_mode() -> bool {
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
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacSetupReadiness {
    pub can_request_extension_install: bool,
    pub explanation: String,
}

#[cfg(target_os = "macos")]
fn self_use_bundle_marker_present() -> bool {
    std::env::current_exe().ok().is_some_and(|executable| {
        executable
            .parent()
            .and_then(std::path::Path::parent)
            .is_some_and(|contents| contents.join("Resources/SELF_USE_SIP_OFF.txt").is_file())
    })
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
                    "保护尚未运行 · 防护扩展：{} · 完全磁盘访问：{} · 确认助手：{}",
                    overview.extension_state, overview.full_disk_access, overview.helper_state
                )
            },
            |status| {
                format!(
                    "后端：{} · 防护扩展：{} · 完全磁盘访问：{} · 策略：{} · 迁移只读：{} · 确认助手：{} · 已允许：{} · 已拒绝：{}",
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
            let mode = status.mode.as_deref().unwrap_or("platform-default");
            let marks = match (status.marked_filesystems, status.required_filesystems) {
                (Some(marked), Some(required)) => format!(" · marks: {marked}/{required}"),
                _ => String::new(),
            };
            format!(
                "Backend: {} · mode: {} · browsers: {} · SSH keys: {} · allowed: {} · denied: {}{} · service: {} · notifications: {}",
                status.backend_kind,
                mode,
                status.browsers,
                status.ssh_protected_keys,
                status.allowed,
                status.denied,
                marks,
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
        "请先在“Protection”页面完成扩展安装和权限授权。"
    } else {
        "Controls guardd.service and guard-notify.service together; turning it off makes protected files accessible normally."
    }
}

#[cfg(target_os = "macos")]
pub fn mac_setup_readiness() -> MacSetupReadiness {
    let self_use = self_use_bundle_marker_present();
    if self_use && !sip_is_disabled().unwrap_or(false) {
        return MacSetupReadiness {
            can_request_extension_install: false,
            explanation: "这是 SIP-off 自用构建，但当前 SIP 仍处于开启状态。请在 macOS Recovery 中手动执行 csrutil disable，重启后再回来安装扩展；Guard 不会也不能替你修改 SIP。".into(),
        };
    }
    match platform_macos::system_extension::host_install_entitlement_present() {
        Ok(true) => MacSetupReadiness {
            can_request_extension_install: true,
            explanation: if self_use {
                "SIP-off 自用模式已就绪：SIP 已关闭且防护扩展安装 entitlement 存在。点击“安装防护扩展”后，按 macOS 弹窗或系统设置提示批准。还需要手动运行一次：sudo systemextensionsctl developer on。".into()
            } else {
                "此应用已具备请求 macOS 安装防护扩展的签名权限。点击“安装防护扩展”后，按 macOS 弹窗或系统设置中的提示批准即可。".into()
            },
        },
        Ok(false) => MacSetupReadiness {
            can_request_extension_install: false,
            explanation: "这是本地测试包：它只能打开 Guard 窗口，Apple 尚未授权它安装防护扩展。因此不能真正开启保护，也不是你的权限操作错误。请安装带有 Apple Endpoint Security 授权描述文件的正式包后再继续。".into(),
        },
        Err(error) => MacSetupReadiness {
            can_request_extension_install: false,
            explanation: format!("Guard 无法检查自身的安装授权：{error}"),
        },
    }
}

#[cfg(target_os = "macos")]
pub fn request_system_extension_install() -> anyhow::Result<String> {
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
    Ok("macOS 已收到安装请求。如果出现批准提示，请在 macOS 弹窗或系统设置中选择“允许”，然后回到此页面；状态会自动刷新。接着点击“授予完全磁盘访问权限”。".into())
}

#[cfg(target_os = "macos")]
pub fn open_full_disk_access_settings() -> anyhow::Result<()> {
    let status = std::process::Command::new("open")
        .arg("x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")
        .status()?;
    anyhow::ensure!(status.success(), "macOS 无法打开“完全磁盘访问”设置");
    Ok(())
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
            enforcement_mode: None,
            policy_enabled: false,
            browsers: Vec::new(),
            enrolled_exes: Vec::new(),
            ssh_keys: Vec::new(),
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
    }
}

#[cfg(target_os = "macos")]
pub fn platform_overview(
    daemon: Option<&guard_ipc::StatusInfo>,
    configuration: Option<&guard_ipc::ConfigurationInfo>,
) -> PlatformOverview {
    use platform_macos::user_agent::{UserAgentController, UserAgentStatus};

    let helper_running = guard_client::macos::MacGuardClient::for_current_process()
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
        policy_enabled: configuration
            .and_then(|configuration| configuration.policy_enabled)
            .unwrap_or(false),
        helper_state: helper_state.into(),
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
    for _ in 0..10 {
        let state = controller.status().map(|status| status.state);
        match state {
            Ok(LifecycleState::Submitted) => {
                std::thread::sleep(std::time::Duration::from_millis(25));
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
        candidate.policy_enabled = enabled;
        let bytes = serde_json::to_vec(&candidate)?;
        apply_config(&bytes)?;
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
    let agent = platform_macos::user_agent::UserAgentController::bundled()?;
    if enabled {
        agent.register()
    } else {
        agent.unregister()
    }
}

#[cfg(target_os = "macos")]
pub fn open_user_agent_settings() {
    platform_macos::user_agent::UserAgentController::open_system_settings();
}

#[cfg(not(target_os = "macos"))]
pub fn set_user_agent_enabled(_enabled: bool) -> anyhow::Result<()> {
    anyhow::bail!("SMAppService is available only on macOS")
}

#[cfg(not(target_os = "macos"))]
pub fn open_user_agent_settings() {}

pub fn editable_from_metadata(info: guard_ipc::ConfigurationInfo) -> Option<EditableConfiguration> {
    #[cfg(target_os = "linux")]
    let enforcement_mode = Some(match info.enforcement_mode.as_deref()? {
        "strict-filesystem" => LinuxEnforcementMode::StrictFilesystem,
        "conservative" => LinuxEnforcementMode::Conservative,
        _ => return None,
    });
    #[cfg(not(target_os = "linux"))]
    let enforcement_mode = None;

    let mut browsers = Vec::with_capacity(info.browsers.len());
    for browser in info.browsers {
        let family = match browser.family.as_str() {
            "Chromium" | "chromium" => guard_core::BrowserFamily::Chromium,
            "Firefox" | "firefox" => guard_core::BrowserFamily::Firefox,
            "Zen" | "zen" => guard_core::BrowserFamily::Zen,
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
    Some(EditableConfiguration {
        enforcement_mode,
        policy_enabled: info.policy_enabled.unwrap_or(cfg!(target_os = "linux")),
        browsers,
        enrolled_exes: info.enrolled_exes.into_iter().map(Into::into).collect(),
        ssh_keys: info.ssh_keys.into_iter().map(Into::into).collect(),
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
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        match controller.status() {
            Ok(status) if status.state != LifecycleState::Submitted => {
                println!(
                    "system-extension state={:?} diagnostic={}",
                    status.state, status.diagnostic
                );
                return Some(i32::from(status.state == LifecycleState::Failed));
            }
            Ok(_) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Ok(status) => {
                println!(
                    "system-extension state={:?} diagnostic=request still pending after 30 seconds",
                    status.state
                );
                return Some(1);
            }
            Err(error) => {
                eprintln!("guard-ui: status query failed: {error}");
                return Some(1);
            }
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
    };
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
    use super::render_loader_cache;

    #[test]
    fn loader_cache_is_relocated_and_escaped() {
        let rendered = render_loader_cache(
            "\"@GUARD_APP@/Contents/Resources/gdk-pixbuf/loaders/module.so\"",
            std::path::Path::new("/Applications/Guard \"QA\".app"),
        );
        assert!(!rendered.contains("@GUARD_APP@"));
        assert!(rendered.contains(r#"/Applications/Guard \"QA\".app/Contents"#));
    }
}
