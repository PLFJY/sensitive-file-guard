//! Native GTK control center.  This process is deliberately only a client:
//! policy decisions and privileged writes remain in guardd/guardctl.

use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::path::PathBuf;
use std::rc::Rc;

use adw::prelude::*;
use gtk4 as gtk;
use libadwaita as adw;

mod pending_dialog;
mod platform_service;

use pending_dialog::{PendingDialogController, PendingPrompt, PromptKey, PromptKind, PromptState};

#[cfg(target_os = "macos")]
const APP_ID: &str = platform_macos::DEFAULT_APP_BUNDLE_ID;
#[cfg(not(target_os = "macos"))]
const APP_ID: &str = "io.github.plfjy.SensitiveFileGuard";
const PENDING_ONLY_ARG: &str = "--pending-only";
const DEFAULT_WINDOW_WIDTH: i32 = 800;
const DEFAULT_WINDOW_HEIGHT: i32 = 560;
const SIDEBAR_WIDTH: i32 = 176;
const SIDEBAR_POSITION: i32 = 192;
const SUMMARY_WIDTH_CHARS: i32 = 72;
const STATUS_SUBTITLE_LINES: i32 = 3;
const _: () = {
    assert!(DEFAULT_WINDOW_WIDTH <= 800);
    assert!(DEFAULT_WINDOW_HEIGHT <= 600);
    assert!(SIDEBAR_POSITION < DEFAULT_WINDOW_WIDTH / 3);
    assert!(SIDEBAR_WIDTH <= SIDEBAR_POSITION);
    assert!(SUMMARY_WIDTH_CHARS <= 72);
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Health {
    Active,
    Degraded,
    Stopped,
    Unreachable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceOrigin {
    NativeDetected,
    Custom,
}

#[derive(Clone)]
struct BrowserSource {
    config: guard_platform::config::BrowserEnrollmentConfig,
    origin: SourceOrigin,
}

#[derive(Clone)]
struct SshSource {
    path: PathBuf,
    origin: SourceOrigin,
}

fn health_from_evidence(
    service_active: bool,
    notification_active: bool,
    daemon: Option<&guard_ipc::StatusInfo>,
) -> Health {
    if service_active {
        if !notification_active {
            return Health::Degraded;
        }
        return match daemon {
            Some(status) if status.status == "ACTIVE" && status.enforcement_active => {
                Health::Active
            }
            Some(status) if status.status == "ACTIVE" => Health::Degraded,
            Some(status) if matches!(status.status.as_str(), "DEGRADED" | "NOT_ENFORCING") => {
                Health::Degraded
            }
            Some(_) | None => Health::Unreachable,
        };
    }
    Health::Stopped
}

fn health_label(h: Health) -> &'static str {
    match h {
        Health::Active => "PROTECTED",
        Health::Degraded => "DEGRADED",
        Health::Stopped => "STOPPED / OFF",
        Health::Unreachable => "UNREACHABLE",
    }
}

fn ssh_key_subtitle(active: bool, configured: bool) -> &'static str {
    match (active, configured) {
        (true, true) => "Protected",
        (true, false) => "Protected — runtime enrollment (not yet in saved configuration)",
        (false, true) => "Configured — not active in the current guardd process",
        (false, false) => "Detected — not protected",
    }
}

#[derive(Clone)]
struct UiState {
    candidate: Rc<RefCell<Option<platform_service::EditableConfiguration>>>,
    status: gtk::Label,
    detail: gtk::Label,
    apply: gtk::Button,
    mode: gtk::ComboBoxText,
    browsers: gtk::ListBox,
    keys: gtk::ListBox,
    events: gtk::ListBox,
    event_data: Rc<RefCell<Vec<guard_ipc::EventInfo>>>,
    #[cfg(target_os = "macos")]
    last_notified_event_id: Rc<Cell<i64>>,
    browser_sources: Rc<RefCell<Vec<BrowserSource>>>,
    unsupported_browsers: Rc<RefCell<Vec<guard_platform::config::UnsupportedSandboxedBrowser>>>,
    ssh_sources: Rc<RefCell<Vec<SshSource>>>,
    /// Last daemon-reported SSH resources. This is a display cache refreshed
    /// from IPC, not a second enrollment registry.
    active_ssh_keys: Rc<RefCell<HashSet<PathBuf>>>,
    poll_in_flight: Rc<Cell<bool>>,
    protection: Rc<RefCell<Option<adw::SwitchRow>>>,
    protection_syncing: Rc<Cell<bool>>,
    helper: Rc<RefCell<Option<adw::SwitchRow>>>,
    helper_syncing: Rc<Cell<bool>>,
    helper_error: Rc<RefCell<Option<String>>>,
    extension_status: adw::ActionRow,
    fda_status: adw::ActionRow,
    sip_status: adw::ActionRow,
    developer_mode_status: adw::ActionRow,
    host_entitlement_status: adw::ActionRow,
    endpoint_security_entitlement_status: adw::ActionRow,
    mac_setup_message: gtk::Label,
    pending_dialogs: Rc<RefCell<PendingDialogController>>,
}

fn main() {
    if let Some(exit_code) = platform_service::handle_system_extension_command() {
        std::process::exit(exit_code);
    }
    #[cfg(target_os = "macos")]
    if std::env::args().any(|arg| arg == "--test-notification") {
        match platform_macos::notifications::send(
            "Sensitive File Guard test notification",
            "The Guard.app notification channel is working; this is a synthetic test message.",
        ) {
            Ok(()) => {
                eprintln!("Guard: delivered synthetic macOS test notification");
                return;
            }
            Err(error) => {
                eprintln!("Guard: macOS test notification failed: {error}");
                std::process::exit(1);
            }
        }
    }
    if let Err(error) = platform_service::configure_bundled_runtime() {
        eprintln!("Guard bundled GTK runtime is invalid: {error}");
        std::process::exit(78);
    }
    let pending_only = std::env::args().any(|arg| arg == PENDING_ONLY_ARG);
    let packaging_smoke = std::env::args().any(|arg| arg == "--packaging-smoke");
    let layout_smoke_page = if std::env::args().any(|arg| arg == "--ui-layout-smoke-protection") {
        Some("protection")
    } else if std::env::args().any(|arg| arg == "--ui-layout-smoke-log") {
        Some("log")
    } else if std::env::args().any(|arg| arg == "--ui-layout-smoke") {
        Some("overview")
    } else {
        None
    };
    adw::init().expect("libadwaita initialization");
    if packaging_smoke {
        println!("Guard bundled GTK runtime initialized");
        return;
    }
    // Let libadwaita own the color preference instead of inheriting the
    // deprecated GtkSettings dark-theme toggle from the desktop session.
    adw::StyleManager::default().set_color_scheme(adw::ColorScheme::Default);
    let app = adw::Application::new(Some(APP_ID), gio::ApplicationFlags::empty());
    app.connect_activate(move |app| build_ui(app, pending_only, layout_smoke_page));
    let process_name = std::env::args().next().unwrap_or_else(|| "guard-ui".into());
    app.run_with_args(&[process_name]);
}

fn build_ui(app: &adw::Application, pending_only: bool, layout_smoke_page: Option<&'static str>) {
    // `guard-notify` can activate the application more than once while an
    // import is pending. GApplication routes those activations to this primary
    // process, so creating another UiState here would poll the same pending ID
    // independently and show duplicate confirmation dialogs.
    if let Some(window) = app.active_window() {
        window.present();
        return;
    }

    let status = gtk::Label::new(Some("Connecting to guardd…"));
    status.add_css_class("title-3");
    status.set_xalign(0.0);
    let detail = gtk::Label::new(Some(
        "Live protection, notification, and daemon health are required for a green state.",
    ));
    detail.set_wrap(true);
    detail.set_wrap_mode(gtk::pango::WrapMode::WordChar);
    detail.set_max_width_chars(SUMMARY_WIDTH_CHARS);
    detail.set_hexpand(true);
    detail.set_xalign(0.0);
    let apply = gtk::Button::with_label(platform_service::apply_button_label());
    apply.set_sensitive(false);
    let mode = gtk::ComboBoxText::new();
    if platform_service::shows_linux_mode() {
        mode.append(Some("strict-filesystem"), "Strict Filesystem (recommended)");
        mode.append(Some("conservative"), "Conservative (compatibility)");
        mode.set_active_id(Some("strict-filesystem"));
    }
    let browsers = gtk::ListBox::new();
    browsers.set_selection_mode(gtk::SelectionMode::None);
    let keys = gtk::ListBox::new();
    keys.set_selection_mode(gtk::SelectionMode::None);
    let events = gtk::ListBox::new();
    events.set_selection_mode(gtk::SelectionMode::None);
    let extension_status = adw::ActionRow::new();
    configure_status_row(&extension_status);
    extension_status.set_title("Protection extension");
    extension_status.set_subtitle("Checking installation status…");
    let fda_status = adw::ActionRow::new();
    configure_status_row(&fda_status);
    fda_status.set_title("Full Disk Access");
    fda_status.set_subtitle("Checking permission status…");
    let sip_status = adw::ActionRow::new();
    configure_status_row(&sip_status);
    sip_status.set_title("SIP");
    sip_status.set_subtitle("Checking…");
    let developer_mode_status = adw::ActionRow::new();
    configure_status_row(&developer_mode_status);
    developer_mode_status.set_title("System Extension developer mode");
    developer_mode_status.set_subtitle("Checking…");
    let host_entitlement_status = adw::ActionRow::new();
    configure_status_row(&host_entitlement_status);
    host_entitlement_status.set_title("Host installation entitlement");
    host_entitlement_status.set_subtitle("Checking final signature…");
    let endpoint_security_entitlement_status = adw::ActionRow::new();
    configure_status_row(&endpoint_security_entitlement_status);
    endpoint_security_entitlement_status.set_title("Endpoint Security entitlement");
    endpoint_security_entitlement_status
        .set_subtitle("Checking the bundled extension's final signature…");
    let mac_setup_message = gtk::Label::new(None);
    mac_setup_message.set_wrap(true);
    mac_setup_message.set_wrap_mode(gtk::pango::WrapMode::WordChar);
    mac_setup_message.set_max_width_chars(SUMMARY_WIDTH_CHARS);
    mac_setup_message.set_hexpand(true);
    mac_setup_message.set_xalign(0.0);

    let state = UiState {
        candidate: Rc::new(RefCell::new(None)),
        status: status.clone(),
        detail: detail.clone(),
        apply: apply.clone(),
        mode: mode.clone(),
        browsers: browsers.clone(),
        keys: keys.clone(),
        events: events.clone(),
        event_data: Rc::new(RefCell::new(Vec::new())),
        #[cfg(target_os = "macos")]
        last_notified_event_id: Rc::new(Cell::new(0)),
        browser_sources: Rc::new(RefCell::new(Vec::new())),
        unsupported_browsers: Rc::new(RefCell::new(Vec::new())),
        ssh_sources: Rc::new(RefCell::new(Vec::new())),
        active_ssh_keys: Rc::new(RefCell::new(HashSet::new())),
        poll_in_flight: Rc::new(Cell::new(false)),
        protection: Rc::new(RefCell::new(None)),
        protection_syncing: Rc::new(Cell::new(false)),
        helper: Rc::new(RefCell::new(None)),
        helper_syncing: Rc::new(Cell::new(false)),
        helper_error: Rc::new(RefCell::new(None)),
        extension_status,
        fda_status,
        sip_status,
        developer_mode_status,
        host_entitlement_status,
        endpoint_security_entitlement_status,
        mac_setup_message,
        pending_dialogs: Rc::new(RefCell::new(PendingDialogController::default())),
    };
    let overview = scroll_page(overview_page(&state));
    let protection = scroll_page(protection_page(&state));
    let log = scroll_page(log_page(&state));
    let stack = gtk::Stack::new();
    // A hidden page must not enlarge the whole control center when a long
    // extension diagnostic arrives after activation.
    stack.set_hhomogeneous(false);
    stack.set_vhomogeneous(false);
    stack.add_titled(&overview, Some("overview"), "Overview");
    stack.add_titled(&protection, Some("protection"), "Protection");
    stack.add_titled(&log, Some("log"), "Security Log");
    let refresh_status = gtk::Button::with_label("Refresh status");
    refresh_status.set_tooltip_text(Some(
        "Refresh protection settings, permissions, browser protection, SSH key protection, and service health",
    ));
    refresh_status.add_css_class("suggested-action");
    refresh_status.set_halign(gtk::Align::End);
    refresh_status.set_valign(gtk::Align::End);
    refresh_status.set_margin_end(18);
    refresh_status.set_margin_bottom(18);
    refresh_status.set_visible(false);

    let nav = gtk::ListBox::new();
    nav.set_selection_mode(gtk::SelectionMode::Single);
    for title in ["Overview", "Protection", "Security Log"] {
        nav.append(&gtk::Label::new(Some(title)));
    }
    nav.select_row(nav.row_at_index(0).as_ref());
    let stack_for_nav = stack.clone();
    let refresh_for_nav = refresh_status.clone();
    nav.connect_row_selected(move |_, row| {
        if let Some(row) = row {
            let page = match row.index() {
                1 => "protection",
                2 => "log",
                _ => "overview",
            };
            stack_for_nav.set_visible_child_name(page);
            refresh_for_nav.set_visible(page == "protection");
        }
    });
    nav.set_width_request(SIDEBAR_WIDTH);
    nav.add_css_class("navigation-sidebar");
    let split = gtk::Paned::new(gtk::Orientation::Horizontal);
    split.set_start_child(Some(&nav));
    split.set_end_child(Some(&stack));
    split.set_position(SIDEBAR_POSITION);
    split.set_resize_start_child(false);
    split.set_shrink_start_child(false);
    stack.set_hexpand(true);
    stack.set_vexpand(true);
    let root = gtk::Box::new(gtk::Orientation::Vertical, 0);
    let header = adw::HeaderBar::new();
    let title = gtk::Label::new(Some("Sensitive File Guard"));
    title.add_css_class("title");
    header.set_title_widget(Some(&title));
    root.append(&header);
    root.append(&split);
    let overlay = gtk::Overlay::new();
    overlay.set_child(Some(&root));
    overlay.add_overlay(&refresh_status);
    let window = adw::ApplicationWindow::new(app);
    window.set_title(Some("Sensitive File Guard"));
    window.set_default_size(DEFAULT_WINDOW_WIDTH, DEFAULT_WINDOW_HEIGHT);
    window.set_content(Some(&overlay));
    let state_for_refresh = state.clone();
    let refresh_window = window.clone();
    refresh_status.connect_clicked(move |button| {
        button.set_sensitive(false);
        // This is a complete authoritative status refresh. It is deliberately
        // separate from the inline native-browser discovery action.
        refresh_browser_sources(&state_for_refresh);
        refresh_state(&state_for_refresh, &refresh_window, false);
        let button = button.clone();
        glib::timeout_add_seconds_local(1, move || {
            button.set_sensitive(true);
            glib::ControlFlow::Break
        });
    });
    window.present();

    if let Some(page) = layout_smoke_page {
        apply_layout_smoke_state(&state);
        if page == "log" {
            apply_log_layout_smoke_state(&state);
        }
        stack.set_visible_child_name(page);
    } else {
        load_configuration(&state);
        start_polling(state, window, pending_only);
    }
}

fn configure_status_row(row: &adw::ActionRow) {
    row.set_title_lines(2);
    row.set_subtitle_lines(STATUS_SUBTITLE_LINES);
}

fn apply_layout_smoke_state(state: &UiState) {
    let long_status = "Active — system extension activation completed; authenticated control channel responsive; Endpoint Security AUTH_OPEN, AUTH_LINK, and AUTH_RENAME subscriptions active";
    state.status.set_text("PROTECTED");
    state.detail.set_text(long_status);
    state.extension_status.set_subtitle(long_status);
    state.fda_status.set_subtitle(long_status);
    state.developer_mode_status.set_subtitle(long_status);
    state.host_entitlement_status.set_subtitle(long_status);
    state
        .endpoint_security_entitlement_status
        .set_subtitle(long_status);
    state.mac_setup_message.set_text(long_status);
}

fn apply_log_layout_smoke_state(state: &UiState) {
    let event = guard_ipc::EventInfo {
        id: 1,
        event_code: "access_decision".into(),
        ts_ms: 1,
        uid: 501,
        pid: 42,
        start_time: 1,
        decision: "Deny(UnknownProcess)".into(),
        deny_reason: Some("UnknownProcess".into()),
        reason_code: Some("browser_protected_resource".into()),
        resource_kind: "CookieStore".into(),
        resource_kind_code: "browser_cookie_store".into(),
        resource_browser: Some("synthetic-browser".into()),
        resource_profile: Some("Synthetic Profile".into()),
        path: "/synthetic/protected/Browser Profile/Network/Cookies with a deliberately long metadata path".into(),
        exe: "/Users/example/Applications/a-process-with-a-deliberately-long-name-that-must-not-stretch-the-window".into(),
        exe_owner_uid: 501,
        trust_tier: "Unknown".into(),
        process_browser: None,
        parent_pid: None,
        parent_exe: None,
        lease_id: None,
        backend_diag: "synthetic layout smoke".into(),
    };
    state.events.append(&event_row(&event));
}

fn scroll_page(content: gtk::Box) -> gtk::ScrolledWindow {
    content.set_hexpand(true);
    content.set_vexpand(false);
    let scroll = gtk::ScrolledWindow::new();
    scroll.set_policy(gtk::PolicyType::Never, gtk::PolicyType::Automatic);
    scroll.set_child(Some(&content));
    scroll
}

fn overview_page(state: &UiState) -> gtk::Box {
    let page = gtk::Box::new(gtk::Orientation::Vertical, 18);
    page.set_margin_top(24);
    page.set_margin_bottom(24);
    page.set_margin_start(24);
    page.set_margin_end(24);
    page.append(&state.status);
    page.append(&state.detail);
    let row = adw::SwitchRow::new();
    row.set_title(platform_service::protection_switch_title());
    row.set_subtitle(platform_service::protection_switch_subtitle());
    row.set_active(false);
    *state.protection.borrow_mut() = Some(row.clone());
    let start_row = row.clone();
    let syncing = state.protection_syncing.clone();
    let candidate = state.candidate.clone();
    row.connect_active_notify(move |switch_row| {
        if syncing.get() {
            return;
        }
        let enabled = switch_row.is_active();
        start_row.set_sensitive(false);
        spawn_protection_change(
            enabled,
            candidate.clone(),
            start_row.clone(),
            syncing.clone(),
        );
    });
    page.append(&row);
    page
}

fn protection_page(state: &UiState) -> gtk::Box {
    let page = gtk::Box::new(gtk::Orientation::Vertical, 12);
    page.set_margin_top(20);
    page.set_margin_bottom(20);
    page.set_margin_start(20);
    page.set_margin_end(20);
    if platform_service::shows_linux_mode() {
        let heading = gtk::Label::new(Some("Enforcement strategy"));
        heading.set_xalign(0.0);
        heading.add_css_class("title-2");
        page.append(&heading);
        page.append(&state.mode);
        let mode = state.mode.clone();
        let candidate = state.candidate.clone();
        let apply = state.apply.clone();
        mode.connect_changed(move |m| {
            if let Some(cfg) = candidate.borrow_mut().as_mut() {
                cfg.enforcement_mode =
                    Some(if m.active_id().as_deref() == Some("strict-filesystem") {
                        platform_service::LinuxEnforcementMode::StrictFilesystem
                    } else {
                        platform_service::LinuxEnforcementMode::Conservative
                    });
                apply.set_sensitive(true);
            }
        });
    } else {
        let heading = gtk::Label::new(Some("Protection setup"));
        heading.set_xalign(0.0);
        heading.add_css_class("title-2");
        page.append(&heading);
        let group = adw::PreferencesGroup::new();
        group.set_title("Complete these steps in order");
        group.add(&state.sip_status);
        group.add(&state.developer_mode_status);
        group.add(&state.host_entitlement_status);
        group.add(&state.endpoint_security_entitlement_status);
        group.add(&state.extension_status);
        group.add(&state.fda_status);
        page.append(&group);
        let actions = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        actions.set_halign(gtk::Align::Start);
        let install = gtk::Button::with_label("1. Install/update protection extension");
        let fda = gtk::Button::with_label("2. Grant Full Disk Access");
        let readiness = platform_service::mac_setup_readiness();
        install.set_sensitive(readiness.can_request_extension_install);
        install.set_tooltip_text(Some(&readiness.explanation));
        state.mac_setup_message.set_text(&readiness.explanation);
        actions.append(&install);
        actions.append(&fda);
        page.append(&actions);
        page.append(&state.mac_setup_message);
        let setup_message = state.mac_setup_message.clone();
        install.connect_clicked(move |button| {
            spawn_system_extension_install(button.clone(), setup_message.clone());
        });
        fda.connect_clicked(
            |button| match platform_service::open_full_disk_access_settings() {
                Ok(()) => button.set_tooltip_text(None),
                Err(error) => {
                    button.set_tooltip_text(Some(&format!("Could not open settings: {error}")))
                }
            },
        );

        let helper_group = adw::PreferencesGroup::new();
        helper_group.set_title("Optional: open Guard automatically for confirmations");
        let helper = adw::SwitchRow::new();
        helper.set_subtitle_lines(STATUS_SUBTITLE_LINES);
        helper.set_title("Open Guard automatically when confirmation is required");
        helper.set_subtitle("Runs only while protection is enabled to show browser migration or SSH key confirmations; it does not install extensions or grant permissions.");
        helper.set_active(false);
        helper.set_sensitive(false);
        let helper_row = helper.clone();
        let helper_syncing = state.helper_syncing.clone();
        let helper_error = state.helper_error.clone();
        helper.connect_active_notify(move |row| {
            if helper_syncing.get() {
                return;
            }
            helper_row.set_sensitive(false);
            spawn_user_agent_change(
                row.is_active(),
                helper_row.clone(),
                helper_syncing.clone(),
                helper_error.clone(),
            );
        });
        *state.helper.borrow_mut() = Some(helper.clone());
        helper_group.add(&helper);
        page.append(&helper_group);

        let allowlist_heading = gtk::Label::new(Some("macOS trusted tools"));
        allowlist_heading.set_xalign(0.0);
        allowlist_heading.add_css_class("title-2");
        page.append(&allowlist_heading);
        let allowlist_info = gtk::Label::new(Some(
            "Spotlight uses exact Apple-signature exceptions only for history metadata; third-party tools are not automatically allowed based on their name or install location. Cookies, passwords, session data, and SSH private keys still require confirmation.",
        ));
        allowlist_info.set_xalign(0.0);
        allowlist_info.set_wrap(true);
        allowlist_info.set_wrap_mode(gtk::pango::WrapMode::WordChar);
        allowlist_info.set_max_width_chars(SUMMARY_WIDTH_CHARS);
        page.append(&allowlist_info);
        let add_tool = gtk::Button::with_label("Add trusted tool…");
        add_tool.set_halign(gtk::Align::Start);
        let tool_state = state.clone();
        let trusted_tools = gtk::ListBox::new();
        trusted_tools.set_selection_mode(gtk::SelectionMode::None);
        trusted_tools.add_css_class("boxed-list");
        let trusted_tools_for_dialog = trusted_tools.clone();
        add_tool.connect_clicked(move |_| {
            show_add_trusted_tool_dialog(&tool_state, &trusted_tools_for_dialog)
        });
        page.append(&add_tool);
        page.append(&trusted_tools);
        render_trusted_tools(state, &trusted_tools);
    }
    let browsers_heading = gtk::Label::new(Some("Protected browsers"));
    browsers_heading.set_xalign(0.0);
    browsers_heading.add_css_class("title-2");
    page.append(&browsers_heading);
    state.browsers.add_css_class("boxed-list");
    page.append(&state.browsers);
    let browser_actions = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    browser_actions.set_halign(gtk::Align::Start);
    let refresh = gtk::Button::with_label("Refresh native browsers");
    let add_browser = gtk::Button::with_label("Add custom browser…");
    browser_actions.append(&refresh);
    browser_actions.append(&add_browser);
    page.append(&browser_actions);
    let refresh_state = state.clone();
    refresh.connect_clicked(move |_| refresh_browser_sources(&refresh_state));
    let add_state = state.clone();
    add_browser.connect_clicked(move |_| show_add_browser_dialog(&add_state));
    let keys_heading = gtk::Label::new(Some("SSH private keys"));
    keys_heading.set_xalign(0.0);
    keys_heading.add_css_class("title-2");
    page.append(&keys_heading);
    state.keys.add_css_class("boxed-list");
    page.append(&state.keys);
    let add_key = gtk::Button::with_label("Add key…");
    add_key.set_halign(gtk::Align::Start);
    let key_state = state.clone();
    add_key.connect_clicked(move |_| show_add_key_dialog(&key_state));
    page.append(&add_key);
    let actions = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    actions.set_halign(gtk::Align::Start);
    actions.append(&state.apply);
    let discard = gtk::Button::with_label("Discard");
    actions.append(&discard);
    page.append(&actions);
    let cand = state.candidate.clone();
    let apply_btn = state.apply.clone();
    let render_state = state.clone();
    discard.connect_clicked(move |_| {
        // The daemon owns the active policy. Drop this window's transient
        // draft and let the next IPC poll obtain a fresh authoritative copy.
        *cand.borrow_mut() = None;
        apply_btn.set_sensitive(false);
        render_state
            .detail
            .set_text("Reloading active policy from guardd…");
    });
    let cand = state.candidate.clone();
    let apply_btn = state.apply.clone();
    state.apply.connect_clicked(move |_| {
        if let Some(cfg) = cand.borrow().clone() {
            if let Ok(bytes) = serde_json::to_vec(&cfg) {
                apply_btn.set_sensitive(false);
                spawn_apply(bytes, apply_btn.clone());
            }
        }
    });
    page
}

fn log_page(state: &UiState) -> gtk::Box {
    let page = gtk::Box::new(gtk::Orientation::Vertical, 12);
    page.set_margin_top(20);
    page.set_margin_start(20);
    page.set_margin_end(20);
    page.set_margin_bottom(20);
    let heading = gtk::Label::new(Some("Recent security events"));
    heading.set_xalign(0.0);
    heading.add_css_class("title-2");
    page.append(&heading);
    page.append(&state.events);
    let data_for_detail = state.event_data.clone();
    state.events.connect_row_activated(move |_, row| {
        let index = row.index();
        let Some(event) = data_for_detail.borrow().get(index as usize).cloned() else { return; };
        let detail = gtk::Window::new();
        detail.set_title(Some("Security event detail"));
        detail.set_default_size(520, 360);
        let label = gtk::Label::new(Some(&format!(
            "Event #{}\nDecision: {}\nReason: {}\nPID: {}\nExecutable: {}\nResource: {}\nPath: {}\nBackend: {}",
            event.id, event.decision, event.reason_code.as_deref().or(event.deny_reason.as_deref()).unwrap_or("-"), event.pid, event.exe, event.resource_kind, event.path, event.backend_diag
        )));
        label.set_wrap(true); label.set_xalign(0.0); label.set_yalign(0.0); label.set_margin_top(20); label.set_margin_bottom(20); label.set_margin_start(20); label.set_margin_end(20);
        detail.set_child(Some(&label));
        detail.present();
    });
    let older = gtk::Button::with_label("Load older");
    let events = state.events.clone();
    let data = state.event_data.clone();
    older.connect_clicked(move |_| {
        let before = data.borrow().last().map(|event| event.id);
        let data = data.clone();
        let events = events.clone();
        glib::MainContext::default().spawn_local(async move {
            let page = gio::spawn_blocking(move || {
                platform_service::events_cursor(Some(100), before, None)
            })
            .await
            .ok()
            .and_then(Result::ok)
            .map(|events| {
                events
                    .into_iter()
                    .filter(is_visible_event)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
            if page.is_empty() {
                return;
            }
            data.borrow_mut().extend(page.clone());
            for event in page {
                events.append(&event_row(&event));
            }
        });
    });
    page.append(&older);
    page
}

fn event_row(event: &guard_ipc::EventInfo) -> gtk::ListBoxRow {
    let decision = match event.event_code.as_str() {
        "browser_migration_confirmation_required" => "IMPORT CONFIRMATION REQUIRED",
        "browser_migration_allowed" => "IMPORT ALLOWED",
        "browser_migration_blocked" => "IMPORT BLOCKED",
        "browser_migration_timed_out" => "IMPORT TIMED OUT",
        "ssh_key_access_confirmation_required" => "SSH CONFIRMATION REQUIRED",
        "ssh_key_access_allowed" => "SSH ACCESS ALLOWED",
        "ssh_key_access_blocked" => "SSH ACCESS BLOCKED",
        "ssh_key_access_timed_out" => "SSH ACCESS TIMED OUT",
        _ if is_blocked_event(event) => "BLOCKED",
        _ if event.decision.starts_with("AllowByLease") => "ALLOWED BY LEASE",
        _ => "ALLOWED",
    };
    event_row_with_decision(event, decision)
}

#[cfg(target_os = "macos")]
fn mac_notification_text(event: &guard_ipc::EventInfo) -> (String, String) {
    let executable = std::path::Path::new(&event.exe)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "a process".into());
    (
        "Sensitive File Guard blocked access".into(),
        format!(
            "{executable} attempted to access protected {}.",
            event.resource_kind_code
        ),
    )
}

fn event_row_with_decision(event: &guard_ipc::EventInfo, decision: &str) -> gtk::ListBoxRow {
    let row = gtk::ListBoxRow::new();
    let box_ = gtk::Box::new(gtk::Orientation::Vertical, 2);
    box_.set_hexpand(true);
    box_.set_margin_top(6);
    box_.set_margin_bottom(6);
    box_.set_margin_start(6);
    box_.set_margin_end(6);

    // Process names and paths are untrusted metadata. Without a width cap a
    // GTK Label contributes its entire natural width to the ListBox and makes
    // the security log stretch the whole window horizontally.
    let title = gtk::Label::new(Some(&format!("{}  ·  {}", decision, event.exe)));
    title.set_xalign(0.0);
    title.set_hexpand(true);
    title.set_wrap(true);
    title.set_wrap_mode(gtk::pango::WrapMode::WordChar);
    title.set_max_width_chars(SUMMARY_WIDTH_CHARS);
    title.set_width_chars(1);
    title.set_lines(2);
    title.add_css_class(
        if decision.contains("BLOCKED") || decision.contains("TIMED OUT") {
            "error"
        } else {
            "success"
        },
    );

    let subtitle = gtk::Label::new(Some(&format!(
        "#{} · {} · {}",
        event.id, event.resource_kind, event.path
    )));
    subtitle.set_xalign(0.0);
    subtitle.set_hexpand(true);
    subtitle.set_wrap(true);
    subtitle.set_wrap_mode(gtk::pango::WrapMode::WordChar);
    subtitle.set_max_width_chars(SUMMARY_WIDTH_CHARS);
    subtitle.set_width_chars(1);
    subtitle.set_lines(2);
    subtitle.set_ellipsize(gtk::pango::EllipsizeMode::Middle);

    box_.append(&title);
    box_.append(&subtitle);
    row.set_child(Some(&box_));
    row
}

fn is_blocked_event(event: &guard_ipc::EventInfo) -> bool {
    event.decision.starts_with("Deny")
}

fn is_visible_event(event: &guard_ipc::EventInfo) -> bool {
    cfg!(debug_assertions)
        || is_blocked_event(event)
        || event.event_code.starts_with("ssh_key_access_")
        || event.event_code.starts_with("browser_migration_")
}

fn load_configuration(state: &UiState) {
    // The root-owned file is deliberately not read by the desktop process.
    // Until the authenticated daemon reply arrives there is no editable draft.
    state.detail.set_text("Loading active policy from guardd…");
}

/// Build the editable UI model from the policy loaded by guardd. The GUI runs
/// as the desktop user and must not treat an unreadable root-owned config file
/// as an empty policy. This metadata-only snapshot never includes key bytes or
/// browser data.
fn configuration_from_daemon(
    info: guard_ipc::ConfigurationInfo,
) -> Option<platform_service::EditableConfiguration> {
    platform_service::editable_from_metadata(info)
}

fn hydrate_configuration_from_daemon(state: &UiState, info: guard_ipc::ConfigurationInfo) -> bool {
    // A directly readable config is authoritative for this UI session. When it
    // is root-readable only, replace the first-run placeholder with guardd's
    // active configuration exactly once; later polling must not discard edits.
    if state.candidate.borrow().is_none() {
        let Some(cfg) = configuration_from_daemon(info) else {
            state.detail.set_text(
                "guardd returned an invalid configuration snapshot; the active policy was not changed.",
            );
            return false;
        };
        *state.candidate.borrow_mut() = Some(cfg.clone());
        if let Some(mode) = cfg.enforcement_mode {
            state.mode.set_active_id(Some(mode.as_str()));
        }
        state.apply.set_sensitive(false);
        state.apply.set_tooltip_text(None);
        return true;
    }
    false
}

fn update_active_ssh_keys(state: &UiState, active_ssh_keys: Vec<PathBuf>) -> bool {
    let active_ssh_keys = active_ssh_keys.into_iter().collect::<HashSet<_>>();
    let mut known = state.active_ssh_keys.borrow_mut();
    if *known == active_ssh_keys {
        false
    } else {
        *known = active_ssh_keys;
        true
    }
}

fn refresh_browser_sources(state: &UiState) {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/nonexistent"));
    let discovered = platform_service::discover_native_browsers(&home);
    *state.unsupported_browsers.borrow_mut() = discovered.unsupported_sandboxed.clone();
    let discovered = discovered
        .browsers
        .into_iter()
        .map(|suggestion| BrowserSource {
            config: browser_suggestion_to_enrollment(suggestion),
            origin: SourceOrigin::NativeDetected,
        })
        .collect::<Vec<_>>();
    let removed_missing = if let Some(cfg) = state.candidate.borrow_mut().as_mut() {
        let before = cfg.browsers.len();
        cfg.browsers.retain(browser_source_is_present);
        before != cfg.browsers.len()
    } else {
        false
    };
    if removed_missing {
        state.apply.set_sensitive(true);
        state.apply.set_tooltip_text(Some(
            "Missing browser entries were removed from the staged configuration; apply to persist the change.",
        ));
    }
    let configured = state
        .candidate
        .borrow()
        .as_ref()
        .map(|cfg| cfg.browsers.clone())
        .unwrap_or_default();
    let mut sources = discovered;
    for browser in configured {
        if !sources
            .iter()
            .any(|source| same_native_browser(&source.config, &browser))
        {
            sources.push(BrowserSource {
                config: browser,
                origin: SourceOrigin::Custom,
            });
        }
    }
    *state.browser_sources.borrow_mut() = sources;
    refresh_ssh_sources(state);
    if let Some(cfg) = state.candidate.borrow().as_ref() {
        render_objects(state, cfg);
    }
}

fn refresh_ssh_sources(state: &UiState) {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/nonexistent"));
    let suggestions = guard_ssh::suggest_keys(&home.join(".ssh"))
        .unwrap_or_default()
        .into_iter()
        .map(|path| SshSource {
            path,
            origin: SourceOrigin::NativeDetected,
        })
        .collect::<Vec<_>>();
    let removed_missing = if let Some(cfg) = state.candidate.borrow_mut().as_mut() {
        let before = cfg.ssh_keys.len();
        cfg.ssh_keys.retain(|path| path.is_file());
        before != cfg.ssh_keys.len()
    } else {
        false
    };
    if removed_missing {
        state.apply.set_sensitive(true);
        state.apply.set_tooltip_text(Some(
            "Missing SSH key entries were removed from the staged configuration; apply to persist the change.",
        ));
    }
    let configured = state
        .candidate
        .borrow()
        .as_ref()
        .map(|cfg| cfg.ssh_keys.clone())
        .unwrap_or_default();
    let active_ssh_keys = state.active_ssh_keys.borrow().clone();
    let mut sources = suggestions;
    for key in configured {
        if !sources.iter().any(|source| source.path == key) {
            sources.push(SshSource {
                path: key,
                origin: SourceOrigin::Custom,
            });
        }
    }
    for key in active_ssh_keys {
        if !sources.iter().any(|source| source.path == key) {
            sources.push(SshSource {
                path: key,
                origin: SourceOrigin::Custom,
            });
        }
    }
    sources.sort_by(|left, right| left.path.cmp(&right.path));
    *state.ssh_sources.borrow_mut() = sources;
}

fn browser_family_name(family: guard_core::BrowserFamily) -> &'static str {
    match family {
        guard_core::BrowserFamily::Firefox => "Firefox",
        guard_core::BrowserFamily::Zen => "Zen",
        guard_core::BrowserFamily::Chromium => "Chromium",
        guard_core::BrowserFamily::Safari => "Safari",
    }
}

fn browser_source_is_present(browser: &guard_platform::config::BrowserEnrollmentConfig) -> bool {
    if !browser.profile_root.is_dir() {
        return false;
    }
    browser.exe_paths.is_empty()
        || browser.exe_paths.iter().any(|path| {
            std::fs::metadata(path)
                .map(|metadata| {
                    use std::os::unix::fs::PermissionsExt;
                    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
                })
                .unwrap_or(false)
        })
}

fn browser_suggestion_to_enrollment(
    suggestion: guard_platform::config::BrowserSuggestion,
) -> guard_platform::config::BrowserEnrollmentConfig {
    guard_platform::config::BrowserEnrollmentConfig {
        id: suggestion.id,
        family: suggestion.family,
        profile_root: suggestion.profile_root,
        owner_uid: None,
        exe_paths: suggestion.exe_paths,
    }
}

fn same_browser_source(
    left: &guard_platform::config::BrowserEnrollmentConfig,
    right: &guard_platform::config::BrowserEnrollmentConfig,
) -> bool {
    left.id == right.id && left.profile_root == right.profile_root
}

fn same_native_browser(
    left: &guard_platform::config::BrowserEnrollmentConfig,
    right: &guard_platform::config::BrowserEnrollmentConfig,
) -> bool {
    same_browser_source(left, right)
        && left.family == right.family
        && left.exe_paths == right.exe_paths
}

fn render_objects(state: &UiState, cfg: &platform_service::EditableConfiguration) {
    while let Some(child) = state.browsers.first_child() {
        state.browsers.remove(&child);
    }
    for source in state.browser_sources.borrow().iter() {
        let browser = &source.config;
        let enrolled = cfg
            .browsers
            .iter()
            .any(|configured| same_browser_source(configured, browser));
        let row = adw::SwitchRow::new();
        row.set_title(&browser_display_name(&browser.id));
        row.set_subtitle(&format!(
            "{} · {} · {}",
            browser_family_name(browser.family),
            browser.profile_root.display(),
            if enrolled {
                "Configured"
            } else {
                "Detected — not protected"
            }
        ));
        row.set_active(enrolled);
        let candidate = state.candidate.clone();
        let apply = state.apply.clone();
        let browser_copy = browser.clone();
        row.connect_active_notify(move |switch_row| {
            if let Some(cfg) = candidate.borrow_mut().as_mut() {
                if switch_row.is_active() {
                    if !cfg
                        .browsers
                        .iter()
                        .any(|b| same_browser_source(b, &browser_copy))
                    {
                        cfg.browsers.push(browser_copy.clone());
                    }
                } else {
                    cfg.browsers
                        .retain(|b| !same_browser_source(b, &browser_copy));
                }
                apply.set_sensitive(true);
            }
        });
        if enrolled && source.origin == SourceOrigin::Custom {
            let remove = remove_button("Remove browser protection");
            let candidate = state.candidate.clone();
            let apply = state.apply.clone();
            let render_state = state.clone();
            let browser_copy = browser.clone();
            remove.connect_clicked(move |_| {
                if let Some(cfg) = candidate.borrow_mut().as_mut() {
                    cfg.browsers
                        .retain(|configured| !same_browser_source(configured, &browser_copy));
                    apply.set_sensitive(true);
                }
                refresh_browser_sources(&render_state);
            });
            row.add_suffix(&remove);
        }
        state.browsers.append(&row);
    }
    for browser in state.unsupported_browsers.borrow().iter() {
        let row = adw::ActionRow::new();
        row.set_title(&browser_display_name(&browser.kind));
        row.set_subtitle(&format!(
            "Detected — not protected · {} · {}",
            browser.profile_root.display(),
            browser.reason
        ));
        row.set_title_lines(2);
        row.set_subtitle_lines(STATUS_SUBTITLE_LINES);
        state.browsers.append(&row);
    }
    while let Some(child) = state.keys.first_child() {
        state.keys.remove(&child);
    }
    let mut ssh_sources = state.ssh_sources.borrow().clone();
    for key in &cfg.ssh_keys {
        if !ssh_sources.iter().any(|source| source.path == *key) {
            ssh_sources.push(SshSource {
                path: key.clone(),
                origin: SourceOrigin::Custom,
            });
        }
    }
    ssh_sources.sort_by(|left, right| left.path.cmp(&right.path));
    if ssh_sources.is_empty() {
        let row = adw::ActionRow::new();
        row.set_title("No SSH private-key candidates detected");
        row.set_subtitle("Use Add key… to select a reviewed private key explicitly.");
        state.keys.append(&row);
    }
    for source in ssh_sources {
        let key = source.path;
        let configured = cfg.ssh_keys.contains(&key);
        let active = state.active_ssh_keys.borrow().contains(&key);
        let row = adw::SwitchRow::new();
        row.set_title(&key.to_string_lossy());
        row.set_subtitle(ssh_key_subtitle(active, configured));
        // The visible switch is the daemon-reported state, not merely a bit
        // copied from `/etc/guardd/config.json`.
        row.set_active(active);
        let candidate = state.candidate.clone();
        let apply = state.apply.clone();
        let key_path = key.clone();
        row.connect_active_notify(move |switch_row| {
            if let Some(cfg) = candidate.borrow_mut().as_mut() {
                if switch_row.is_active() {
                    if !cfg.ssh_keys.contains(&key_path) {
                        cfg.ssh_keys.push(key_path.clone());
                    }
                } else {
                    cfg.ssh_keys.retain(|configured| configured != &key_path);
                }
                apply.set_sensitive(true);
            }
        });
        if configured && source.origin == SourceOrigin::Custom {
            let remove = remove_button("Remove SSH key protection");
            let candidate = state.candidate.clone();
            let apply = state.apply.clone();
            let render_state = state.clone();
            let key_path = key.clone();
            remove.connect_clicked(move |_| {
                if let Some(cfg) = candidate.borrow_mut().as_mut() {
                    cfg.ssh_keys.retain(|configured| configured != &key_path);
                    apply.set_sensitive(true);
                }
                refresh_browser_sources(&render_state);
            });
            row.add_suffix(&remove);
        }
        state.keys.append(&row);
    }
}

fn remove_button(tooltip: &str) -> gtk::Button {
    let button = gtk::Button::from_icon_name("user-trash-symbolic");
    button.set_tooltip_text(Some(tooltip));
    button.add_css_class("destructive-action");
    // Keep the suffix action square and centered. Without an explicit natural
    // size some desktop themes stretch icon-only buttons into tall slivers.
    button.set_size_request(36, 36);
    button.set_hexpand(false);
    button.set_vexpand(false);
    button.set_halign(gtk::Align::Center);
    button.set_valign(gtk::Align::Center);
    button
}

fn browser_display_name(id: &str) -> String {
    match id {
        "firefox" => "Firefox",
        "firefox-esr" => "Firefox ESR",
        "google-chrome" => "Google Chrome",
        "microsoft-edge" => "Microsoft Edge",
        "edge" => "Microsoft Edge",
        "safari" => "Safari",
        "zen" => "Zen Browser",
        "brave" => "Brave",
        "opera" => "Opera",
        "vivaldi" => "Vivaldi",
        "chromium" => "Chromium",
        _ => id,
    }
    .to_owned()
}

fn show_add_key_dialog(state: &UiState) {
    let dialog = gtk::FileChooserNative::new(
        Some("Select an SSH private key"),
        None::<&gtk::Window>,
        gtk::FileChooserAction::Open,
        Some("Add"),
        Some("Cancel"),
    );
    let candidate = state.candidate.clone();
    let apply = state.apply.clone();
    let render_state = state.clone();
    dialog.connect_response(move |dialog, response| {
        if response == gtk::ResponseType::Accept {
            if let Some(path) = dialog.file().and_then(|file| file.path()) {
                if let Some(cfg) = candidate.borrow_mut().as_mut() {
                    if !cfg.ssh_keys.contains(&path) {
                        cfg.ssh_keys.push(path);
                        apply.set_sensitive(true);
                    }
                }
                refresh_ssh_sources(&render_state);
                if let Some(cfg) = render_state.candidate.borrow().as_ref() {
                    render_objects(&render_state, cfg);
                }
            }
        }
        dialog.destroy();
    });
    dialog.show();
}

#[cfg(target_os = "macos")]
fn show_add_trusted_tool_dialog(state: &UiState, list: &gtk::ListBox) {
    let dialog = gtk::FileChooserNative::new(
        Some("Select an executable inside the trusted tool App"),
        None::<&gtk::Window>,
        gtk::FileChooserAction::Open,
        Some("Verify and add"),
        Some("Cancel"),
    );
    let list = list.clone();
    let candidate = state.candidate.clone();
    let apply = state.apply.clone();
    let dialog_state = state.clone();
    dialog.connect_response(move |dialog, response| {
        if response == gtk::ResponseType::Accept {
            if let Some(path) = dialog.file().and_then(|file| file.path()) {
                let candidate = candidate.clone();
                let apply = apply.clone();
                let dialog_state = dialog_state.clone();
                let list = list.clone();
                glib::MainContext::default().spawn_local(async move {
                    let result = gio::spawn_blocking(move || {
                        // SAFETY: geteuid has no pointer arguments and reads
                        // only the current authenticated desktop UID.
                        let uid = unsafe { libc::geteuid() };
                        platform_macos::config::enroll_trusted_tool(&path, uid)
                    })
                    .await;
                    match result {
                        Ok(Ok(rule)) => {
                            if let Some(config) = candidate.borrow_mut().as_mut() {
                                if !config
                                    .mac_allowlist
                                    .trusted_tools
                                    .iter()
                                    .any(|existing| existing.path == rule.path)
                                {
                                    config.mac_allowlist.trusted_tools.push(rule);
                                    apply.set_sensitive(true);
                                    dialog_state.mac_setup_message.set_text(
                                        "The trusted tool was added to the pending configuration; sensitive browser data and SSH private keys still require confirmation.",
                                    );
                                    render_trusted_tools(&dialog_state, &list);
                                }
                            }
                        }
                        Ok(Err(error)) => dialog_state
                            .mac_setup_message
                            .set_text(&format!("Tool was not added: {error}")),
                        Err(error) => dialog_state
                            .mac_setup_message
                            .set_text(&format!("Verification task failed: {error:?}")),
                    }
                });
            }
        }
        dialog.destroy();
    });
    dialog.show();
}

#[cfg(target_os = "macos")]
fn render_trusted_tools(state: &UiState, list: &gtk::ListBox) {
    while let Some(child) = list.first_child() {
        list.remove(&child);
    }
    let candidate = state.candidate.borrow();
    let Some(config) = candidate.as_ref() else {
        return;
    };
    for tool in &config.mac_allowlist.trusted_tools {
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        row.set_margin_top(8);
        row.set_margin_bottom(8);
        row.set_margin_start(10);
        row.set_margin_end(10);
        let label = gtk::Label::new(Some(&format!(
            "{} · Enrolled (low-sensitivity metadata only)",
            tool.path.display()
        )));
        label.set_xalign(0.0);
        label.set_hexpand(true);
        label.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
        let remove = gtk::Button::with_label("Revoke");
        let candidate = state.candidate.clone();
        let apply = state.apply.clone();
        let path = tool.path.clone();
        remove.connect_clicked(move |_| {
            if let Some(config) = candidate.borrow_mut().as_mut() {
                config
                    .mac_allowlist
                    .trusted_tools
                    .retain(|item| item.path != path);
                apply.set_sensitive(true);
            }
        });
        row.append(&label);
        row.append(&remove);
        list.append(&row);
    }
}

#[cfg(not(target_os = "macos"))]
fn show_add_trusted_tool_dialog(_state: &UiState, _list: &gtk::ListBox) {}

#[cfg(not(target_os = "macos"))]
fn render_trusted_tools(_state: &UiState, _list: &gtk::ListBox) {}

fn show_add_browser_dialog(state: &UiState) {
    let dialog = gtk::Dialog::with_buttons(
        Some("Add custom browser"),
        None::<&gtk::Window>,
        gtk::DialogFlags::MODAL,
        &[
            ("Cancel", gtk::ResponseType::Cancel),
            ("Add browser", gtk::ResponseType::Accept),
        ],
    );
    dialog.set_default_size(520, -1);
    let content = dialog.content_area();
    content.set_spacing(12);
    content.set_margin_top(18);
    content.set_margin_bottom(18);
    content.set_margin_start(18);
    content.set_margin_end(18);

    let id = gtk::Entry::new();
    id.set_placeholder_text(Some("Identifier, e.g. work-chromium"));
    let family = gtk::ComboBoxText::new();
    family.append(Some("firefox"), "Firefox");
    family.append(Some("zen"), "Zen Browser");
    family.append(Some("chromium"), "Chromium family");
    #[cfg(target_os = "macos")]
    family.append(Some("safari"), "Safari (macOS)");
    family.set_active_id(Some("chromium"));
    let profile = gtk::Entry::new();
    profile.set_placeholder_text(Some("Profile root, e.g. /home/me/.config/chromium"));
    let executable = gtk::Entry::new();
    executable.set_placeholder_text(Some("Actual executable, not a launcher"));
    let error = gtk::Label::new(None);
    error.add_css_class("error");
    error.set_wrap(true);
    error.set_xalign(0.0);
    for (label, widget) in [
        ("Identifier", id.clone().upcast::<gtk::Widget>()),
        ("Browser family", family.clone().upcast::<gtk::Widget>()),
        ("Profile root", profile.clone().upcast::<gtk::Widget>()),
        ("Executable", executable.clone().upcast::<gtk::Widget>()),
    ] {
        let row = gtk::Box::new(gtk::Orientation::Vertical, 4);
        let title = gtk::Label::new(Some(label));
        title.set_xalign(0.0);
        row.append(&title);
        row.append(&widget);
        content.append(&row);
    }
    content.append(&error);

    let candidate = state.candidate.clone();
    let apply = state.apply.clone();
    let render_state = state.clone();
    dialog.connect_response(move |dialog, response| {
        if response != gtk::ResponseType::Accept {
            dialog.destroy();
            return;
        }
        match custom_browser_from_entries(&id, &family, &profile, &executable) {
            Ok(browser) => {
                if let Some(cfg) = candidate.borrow_mut().as_mut() {
                    if !cfg
                        .browsers
                        .iter()
                        .any(|configured| same_browser_source(configured, &browser))
                    {
                        cfg.browsers.push(browser.clone());
                    }
                }
                apply.set_sensitive(true);
                refresh_browser_sources(&render_state);
                dialog.destroy();
            }
            Err(message) => error.set_text(&message),
        }
    });
    dialog.show();
}

fn custom_browser_from_entries(
    id: &gtk::Entry,
    family: &gtk::ComboBoxText,
    profile: &gtk::Entry,
    executable: &gtk::Entry,
) -> Result<guard_platform::config::BrowserEnrollmentConfig, String> {
    use std::os::unix::fs::PermissionsExt;

    let id = id.text().trim().to_owned();
    if id.is_empty() {
        return Err("An identifier is required.".into());
    }
    let profile_root = PathBuf::from(profile.text().as_str());
    if !profile_root.is_absolute() || !profile_root.is_dir() {
        return Err("Profile root must be an existing absolute directory.".into());
    }
    let executable = PathBuf::from(executable.text().as_str());
    let canonical_exe = std::fs::canonicalize(&executable)
        .map_err(|_| "Executable must exist and resolve to a real file.".to_owned())?;
    let metadata = std::fs::metadata(&canonical_exe)
        .map_err(|_| "Unable to inspect the executable.".to_owned())?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err("Executable must be a runnable regular file, not a launcher name.".into());
    }
    let browser_family = match family.active_id().as_deref() {
        Some("firefox") => guard_core::resource::BrowserFamily::Firefox,
        Some("zen") => guard_core::resource::BrowserFamily::Zen,
        Some("safari") => guard_core::resource::BrowserFamily::Safari,
        _ => guard_core::resource::BrowserFamily::Chromium,
    };
    Ok(guard_platform::config::BrowserEnrollmentConfig {
        id,
        family: browser_family,
        profile_root,
        owner_uid: None,
        exe_paths: vec![canonical_exe],
    })
}

fn start_polling(state: UiState, window: adw::ApplicationWindow, pending_only: bool) {
    let state = Rc::new(state);
    let poll_state = state.clone();
    let poll_window = window.clone();
    glib::timeout_add_seconds_local(2, move || {
        refresh_state(&poll_state, &poll_window, pending_only);
        glib::ControlFlow::Continue
    });
    refresh_state(&state, &window, pending_only);
}

fn refresh_state(state: &UiState, window: &adw::ApplicationWindow, pending_only: bool) {
    // Never queue refresh work behind a stalled socket or service query. One
    // background request is enough; the next timer tick retries after it ends.
    if state.poll_in_flight.replace(true) {
        return;
    }
    let status = state.status.clone();
    let detail = state.detail.clone();
    let events = state.events.clone();
    let event_data = state.event_data.clone();
    #[cfg(target_os = "macos")]
    let last_notified_event_id = state.last_notified_event_id.clone();
    let poll_in_flight = state.poll_in_flight.clone();
    let protection = state.protection.clone();
    let protection_syncing = state.protection_syncing.clone();
    let helper = state.helper.clone();
    let helper_syncing = state.helper_syncing.clone();
    let helper_error = state.helper_error.clone();
    let extension_status = state.extension_status.clone();
    let fda_status = state.fda_status.clone();
    let sip_status = state.sip_status.clone();
    let developer_mode_status = state.developer_mode_status.clone();
    let host_entitlement_status = state.host_entitlement_status.clone();
    let endpoint_security_entitlement_status = state.endpoint_security_entitlement_status.clone();
    let pending_dialogs = state.pending_dialogs.clone();
    let config_state = state.clone();
    let window = window.clone();
    let after_id = event_data.borrow().first().map(|event| event.id);
    glib::MainContext::default().spawn_local(async move {
        let result = gio::spawn_blocking(move || {
            let daemon = platform_service::daemon_status().ok();
            let configuration = platform_service::configuration().ok();
            let active_ssh_keys = platform_service::resources()
                .unwrap_or_default()
                .into_iter()
                .filter(|resource| resource.kind == "SshPrivateKey" && !resource.tree)
                .map(|resource| PathBuf::from(resource.path))
                .collect::<Vec<_>>();
            let recent_events = platform_service::events_cursor(Some(100), None, after_id)
                .unwrap_or_default()
                .into_iter()
                .filter(is_visible_event)
                .collect::<Vec<_>>();
            let pending_ssh_reads = platform_service::ssh_pending();
            let pending_migrations = platform_service::migration_pending();
            let overview =
                platform_service::platform_overview(daemon.as_ref(), configuration.as_ref());
            (
                overview,
                daemon,
                configuration,
                active_ssh_keys,
                recent_events,
                pending_ssh_reads,
                pending_migrations,
            )
        })
        .await;
        if let Ok((
            overview,
            daemon,
            configuration,
            active_ssh_keys,
            recent_events,
            pending_ssh_reads,
            pending_migrations,
        )) = result
        {
            let active_ssh_changed = update_active_ssh_keys(&config_state, active_ssh_keys);
            let configuration_available = configuration.is_some();
            let configuration_hydrated = configuration
                .map(|configuration| {
                    hydrate_configuration_from_daemon(&config_state, configuration)
                })
                .unwrap_or(false);
            let first_run = if !configuration_available
                && config_state.candidate.borrow().is_none()
            {
                let initial =
                    platform_service::initial_configuration_if_missing(daemon.is_some());
                let initialized = initial.is_some();
                if let Some(initial) = initial {
                    *config_state.candidate.borrow_mut() = Some(initial);
                    config_state.detail.set_text(
                        "No saved macOS policy exists yet. Select protected resources and apply the policy.",
                    );
                }
                initialized
            } else {
                false
            };
            if active_ssh_changed || configuration_hydrated || first_run {
                refresh_browser_sources(&config_state);
            }
            let health = health_from_evidence(
                overview.service_active
                    && (platform_service::shows_linux_mode() || overview.policy_enabled),
                overview.helper_running,
                daemon.as_ref(),
            );
            status.set_text(health_label(health));
            // The switch represents the actual protection service bundle. Keep it
            // synchronized with out-of-band `systemctl`/`guardctl` changes,
            // while suppressing its callback so a refresh never starts a new
            // privileged operation.
            if let Some(row) = protection.borrow().as_ref() {
                let requested_active = if platform_service::shows_linux_mode() {
                    overview.service_active && overview.helper_running
                } else {
                    overview.policy_enabled
                };
                if row.is_active() != requested_active {
                    protection_syncing.set(true);
                    row.set_active(requested_active);
                    protection_syncing.set(false);
                }
                row.set_sensitive(
                    platform_service::shows_linux_mode()
                        || config_state.candidate.borrow().as_ref().is_some_and(|candidate| {
                            !candidate.browsers.is_empty()
                                || !candidate.ssh_keys.is_empty()
                                || !candidate.enrolled_exes.is_empty()
                        }),
                );
            }
            if let Some(row) = helper.borrow().as_ref() {
                // SMAppService reports RequiresApproval/Enabled before the
                // helper can answer XPC. Keep the user's switch on during
                // that transition; otherwise the two-second status poll
                // immediately undoes a successful registration request.
                let helper_registered = overview.policy_enabled
                    && (overview.helper_running
                    || matches!(
                        overview.helper_state.as_str(),
                        "Pending user approval" | "Enabled, not responding"
                    ));
                if row.is_active() != helper_registered {
                    helper_syncing.set(true);
                    row.set_active(helper_registered);
                    helper_syncing.set(false);
                }
                row.set_subtitle(&overview.helper_state);
                if let Some(error) = helper_error.borrow().as_ref() {
                    row.set_subtitle(error);
                }
                // The pending helper is subordinate to the protection
                // service. It is intentionally unavailable while the main
                // protection switch is off, so it cannot keep polling or
                // surface notifications on its own.
                row.set_sensitive(overview.policy_enabled);
            }
            extension_status.set_subtitle(&overview.extension_state);
            fda_status.set_subtitle(&overview.full_disk_access);
            sip_status.set_subtitle(&overview.sip_state);
            developer_mode_status.set_subtitle(&overview.developer_mode_state);
            host_entitlement_status.set_subtitle(&overview.host_entitlement_state);
            endpoint_security_entitlement_status
                .set_subtitle(&overview.endpoint_security_entitlement_state);
            detail.set_text(&platform_service::overview_detail(
                daemon.as_ref(),
                &overview,
            ));
            if after_id.is_none() {
                while let Some(child) = events.first_child() {
                    events.remove(&child);
                }
                *event_data.borrow_mut() = recent_events.clone();
            } else {
                let mut existing = event_data.borrow_mut();
                for event in recent_events.iter().rev() {
                    existing.insert(0, event.clone());
                }
            }
            for event in recent_events {
                #[cfg(target_os = "macos")]
                if after_id.is_some()
                    && event.id > last_notified_event_id.get()
                    && event.decision.starts_with("Deny")
                    && event.event_code != "system_process_access_suppressed"
                {
                    let (title, body) = mac_notification_text(&event);
                    if let Err(error) = platform_macos::notifications::send(&title, &body) {
                        eprintln!("Guard: macOS system notification failed: {error:#}");
                    }
                }
                let decision = match event.event_code.as_str() {
                    "browser_migration_confirmation_required" => "IMPORT CONFIRMATION REQUIRED",
                    "browser_migration_allowed" => "IMPORT ALLOWED",
                    "browser_migration_blocked" => "IMPORT BLOCKED",
                    "browser_migration_timed_out" => "IMPORT TIMED OUT",
                    "ssh_key_access_confirmation_required" => "SSH CONFIRMATION REQUIRED",
                    "ssh_key_access_allowed" => "SSH ACCESS ALLOWED",
                    "ssh_key_access_blocked" => "SSH ACCESS BLOCKED",
                    "ssh_key_access_timed_out" => "SSH ACCESS TIMED OUT",
                    _ if is_blocked_event(&event) => "BLOCKED",
                    _ if event.decision.starts_with("AllowByLease") => "ALLOWED BY LEASE",
                    _ => "ALLOWED",
                };
                let row = event_row_with_decision(&event, decision);
                if after_id.is_some() {
                    events.insert(&row, 0);
                } else {
                    events.append(&row);
                }
            }
            #[cfg(target_os = "macos")]
            if let Some(latest) = event_data.borrow().first().map(|event| event.id) {
                last_notified_event_id.set(latest);
            }
            let complete_pending_snapshot =
                pending_migrations.is_ok() && pending_ssh_reads.is_ok();
            let (next_prompt, pending_queue_empty) = {
                let mut controller = pending_dialogs.borrow_mut();
                match (pending_migrations, pending_ssh_reads) {
                    (Ok(migrations), Ok(ssh_reads)) => controller.reconcile_snapshot(
                        migrations
                            .into_iter()
                            .map(migration_prompt)
                            .chain(ssh_reads.into_iter().map(ssh_read_prompt)),
                    ),
                    (Ok(migrations), Err(_)) => {
                        controller.reconcile(migrations.into_iter().map(migration_prompt))
                    }
                    (Err(_), Ok(ssh_reads)) => {
                        controller.reconcile(ssh_reads.into_iter().map(ssh_read_prompt))
                    }
                    (Err(_), Err(_)) => {}
                }
                let next = controller
                    .active()
                    .is_none()
                    .then(|| controller.activate_next())
                    .flatten();
                (next, controller.is_empty())
            };
            if let Some(prompt) = next_prompt {
                #[cfg(target_os = "macos")]
                if let Err(error) = platform_macos::notifications::send(
                    "Sensitive File Guard confirmation required",
                    "Guard is waiting for your decision about protected browser data or an SSH private key.",
                ) {
                    eprintln!("Guard: macOS confirmation notification failed: {error:#}");
                }
                present_pending_dialog(&window, pending_dialogs.clone(), prompt, pending_only);
            } else if complete_pending_snapshot
                && should_close_pending_window(pending_only, pending_queue_empty)
            {
                window.close();
            }
        }
        poll_in_flight.set(false);
        let _ = events;
    });
}

fn browser_label(id: &str) -> String {
    match id {
        "chrome" => "Google Chrome".into(),
        "chromium" => "Chromium".into(),
        "firefox" => "Firefox".into(),
        "firefox-esr" => "Firefox ESR".into(),
        "edge" => "Microsoft Edge".into(),
        "brave" => "Brave".into(),
        "zen" => "Zen".into(),
        "opera" => "Opera".into(),
        "vivaldi" => "Vivaldi".into(),
        _ => id.to_owned(),
    }
}

/// Presentation grouping only. guardd independently revalidates every process
/// and creates a separate root-bound lease before allowing it.
fn migration_session_key(migration: &guard_ipc::MigrationPendingInfo) -> String {
    format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
        migration.uid,
        migration.source_browser,
        migration.source_profile,
        migration.target_browser,
        migration.target_exe,
    )
}

#[cfg(any())]
fn present_migration_dialog(
    window: &adw::ApplicationWindow,
    migration: guard_ipc::MigrationPendingInfo,
) {
    let source = browser_label(&migration.source_browser);
    let target = browser_label(&migration.target_browser);
    let details = format!(
        "{target} is trying to access protected {source} data.\n\nAre you importing data from {source} into {target}?\n\nSource browser: {source}\nSource profile: {}\nTarget browser: {target}\nTarget process: {}\nPID: {}\nRequested data: {}",
        migration.source_profile,
        migration.target_exe,
        migration.target_pid,
        migration.requested_data,
    );
    let dialog = gtk::MessageDialog::builder()
        .transient_for(window)
        .modal(true)
        .message_type(gtk::MessageType::Warning)
        .text("Browser data import detected")
        .secondary_text(&details)
        .build();
    let block = dialog.add_button("No, block", gtk::ResponseType::Reject);
    block.add_css_class("destructive-action");
    let allow = dialog.add_button("Yes, allow this import", gtk::ResponseType::Accept);
    allow.add_css_class("suggested-action");
    let state = Rc::new(Cell::new(MigrationDialogState::AwaitingChoice));
    let id = migration.id.clone();
    let response_state = state.clone();
    let response_id = id.clone();
    let response_allow = allow.clone();
    let response_block = block.clone();
    let response_details = details.clone();
    dialog.connect_response(move |dialog, response| {
        if response == gtk::ResponseType::Accept {
            if response_state.get() != MigrationDialogState::AwaitingChoice {
                return;
            }
            // Keep the dialog visible while the platform presents its trusted
            // authentication prompt. Closing now would look like a denial and
            // previously hid the in-progress authorization from the user.
            response_state.set(MigrationDialogState::Authorizing);
            response_allow.set_sensitive(false);
            response_block.set_sensitive(false);
            dialog.set_secondary_text(Some(&format!(
                "{response_details}\n\nWaiting for system authentication…"
            )));
            let socket = PathBuf::from(SOCKET);
            let id = response_id.clone();
            let state = response_state.clone();
            let dialog = dialog.clone();
            let allow = response_allow.clone();
            let block = response_block.clone();
            let details = response_details.clone();
            glib::MainContext::default().spawn_local(async move {
                let result = gio::spawn_blocking(move || {
                    guard_client::resolve_migration(
                        &socket,
                        &id,
                        guard_ipc::MigrationResolutionAction::AllowImport,
                    )
                })
                .await;
                match result {
                    Ok(Ok(guard_ipc::MigrationResolutionInfo::Allowed))
                    | Ok(Ok(guard_ipc::MigrationResolutionInfo::Blocked))
                        if state.get() == MigrationDialogState::Authorizing =>
                    {
                        state.set(MigrationDialogState::Terminal);
                        dialog.close();
                    }
                    Ok(Err(error)) => {
                        eprintln!("guard-ui: import authorization failed: {error}");
                        if state.get() == MigrationDialogState::Authorizing {
                            state.set(MigrationDialogState::AwaitingChoice);
                            allow.set_sensitive(true);
                            block.set_sensitive(true);
                            dialog.set_secondary_text(Some(&format!(
                                "{details}\n\nAuthentication was not completed. You can try again or block this import."
                            )));
                        }
                    }
                    Err(error) => {
                        eprintln!("guard-ui: import authorization task failed: {error:?}");
                        if state.get() == MigrationDialogState::Authorizing {
                            state.set(MigrationDialogState::AwaitingChoice);
                            allow.set_sensitive(true);
                            block.set_sensitive(true);
                            dialog.set_secondary_text(Some(&format!(
                                "{details}\n\nAuthorization could not be completed. You can try again or block this import."
                            )));
                        }
                    }
                    _ => {}
                }
            });
            return;
        }

        if response_state.replace(MigrationDialogState::Terminal) != MigrationDialogState::Terminal
        {
            resolve_migration_in_background(
                response_id.clone(),
                guard_ipc::MigrationResolutionAction::Block,
            );
        }
        dialog.close();
    });
    let close_state = state.clone();
    let close_id = id;
    dialog.connect_close_request(move |_| {
        if close_state.replace(MigrationDialogState::Terminal) != MigrationDialogState::Terminal {
            resolve_migration_in_background(
                close_id.clone(),
                guard_ipc::MigrationResolutionAction::Block,
            );
        }
        glib::Propagation::Proceed
    });
    dialog.present();
}

#[cfg(any())]
fn resolve_migration_in_background(id: String, action: guard_ipc::MigrationResolutionAction) {
    let socket = PathBuf::from(SOCKET);
    glib::MainContext::default().spawn_local(async move {
        match gio::spawn_blocking(move || guard_client::resolve_migration(&socket, &id, action))
            .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => eprintln!("guard-ui: migration resolution failed: {error}"),
            Err(error) => eprintln!("guard-ui: migration resolution task failed: {error:?}"),
        }
    });
}

#[cfg(any())]
fn present_ssh_read_dialog(window: &adw::ApplicationWindow, pending: guard_ipc::SshPendingInfo) {
    let process = PathBuf::from(&pending.process_exe)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| pending.process_exe.clone());
    let details = format!(
        "Program: {process}\nExecutable: {}\nPID: {}\nSSH private key: {}\n\nAllow this verified process tree to read this key for 10 seconds?",
        pending.process_exe, pending.pid, pending.key_path
    );
    let dialog = gtk::MessageDialog::builder()
        .transient_for(window)
        .modal(true)
        .message_type(gtk::MessageType::Warning)
        .text("SSH private-key access detected")
        .secondary_text(&details)
        .build();
    let block = dialog.add_button("Block", gtk::ResponseType::Reject);
    block.add_css_class("destructive-action");
    let allow = dialog.add_button("Allow", gtk::ResponseType::Accept);
    allow.add_css_class("suggested-action");
    let state = Rc::new(Cell::new(MigrationDialogState::AwaitingChoice));
    let id = pending.id.clone();
    let response_state = state.clone();
    let response_id = id.clone();
    let response_allow = allow.clone();
    let response_block = block.clone();
    let response_details = details.clone();
    dialog.connect_response(move |dialog, response| {
        if response == gtk::ResponseType::Accept {
            if response_state.get() != MigrationDialogState::AwaitingChoice {
                return;
            }
            response_state.set(MigrationDialogState::Authorizing);
            response_allow.set_sensitive(false);
            response_block.set_sensitive(false);
            dialog.set_secondary_text(Some(&format!(
                "{response_details}\n\nWaiting for system authentication…"
            )));
            let socket = PathBuf::from(SOCKET);
            let id = response_id.clone();
            let state = response_state.clone();
            let dialog = dialog.clone();
            let allow = response_allow.clone();
            let block = response_block.clone();
            let details = response_details.clone();
            glib::MainContext::default().spawn_local(async move {
                let result = gio::spawn_blocking(move || {
                    guard_client::resolve_ssh_read(
                        &socket,
                        &id,
                        guard_ipc::SshReadResolutionAction::Allow,
                    )
                })
                .await;
                match result {
                    Ok(Ok(_)) if state.get() == MigrationDialogState::Authorizing => {
                        state.set(MigrationDialogState::Terminal);
                        dialog.close();
                    }
                    Ok(Err(error)) => {
                        eprintln!("guard-ui: SSH read authorization failed: {error}");
                        if state.get() == MigrationDialogState::Authorizing {
                            state.set(MigrationDialogState::AwaitingChoice);
                            allow.set_sensitive(true);
                            block.set_sensitive(true);
                            dialog.set_secondary_text(Some(&format!(
                                "{details}\n\nAuthentication was not completed. You can try again or block this key read."
                            )));
                        }
                    }
                    Err(error) => {
                        eprintln!("guard-ui: SSH read authorization task failed: {error:?}");
                        if state.get() == MigrationDialogState::Authorizing {
                            state.set(MigrationDialogState::AwaitingChoice);
                            allow.set_sensitive(true);
                            block.set_sensitive(true);
                            dialog.set_secondary_text(Some(&format!(
                                "{details}\n\nAuthorization could not be completed. You can try again or block this key read."
                            )));
                        }
                    }
                    _ => {}
                }
            });
            return;
        }
        if response_state.replace(MigrationDialogState::Terminal) != MigrationDialogState::Terminal {
            resolve_ssh_read_in_background(response_id.clone(), guard_ipc::SshReadResolutionAction::Block);
        }
        dialog.close();
    });
    let close_state = state.clone();
    dialog.connect_close_request(move |_| {
        if close_state.replace(MigrationDialogState::Terminal) != MigrationDialogState::Terminal {
            resolve_ssh_read_in_background(id.clone(), guard_ipc::SshReadResolutionAction::Block);
        }
        glib::Propagation::Proceed
    });
    dialog.present();
}

#[cfg(any())]
fn resolve_ssh_read_in_background(id: String, action: guard_ipc::SshReadResolutionAction) {
    let socket = PathBuf::from(SOCKET);
    glib::MainContext::default().spawn_local(async move {
        match gio::spawn_blocking(move || guard_client::resolve_ssh_read(&socket, &id, action))
            .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => eprintln!("guard-ui: SSH read resolution failed: {error}"),
            Err(error) => eprintln!("guard-ui: SSH read resolution task failed: {error:?}"),
        }
    });
}

fn migration_prompt(migration: guard_ipc::MigrationPendingInfo) -> PendingPrompt {
    let source = browser_label(&migration.source_browser);
    let target = browser_label(&migration.target_browser);
    let details = format!(
        "{target} is trying to access protected {source} data.\n\nAre you importing data from {source} into {target}?\n\nSource browser: {source}\nSource profile: {}\nTarget browser: {target}\nTarget process: {}\nPID: {}\nRequested data: {}\n{}",
        migration.source_profile,
        migration.target_exe,
        migration.target_pid,
        migration.requested_data,
        remaining_authorization_text(migration.expires_at, unix_seconds()),
    );
    PendingPrompt {
        key: PromptKey {
            kind: PromptKind::Migration,
            value: migration_session_key(&migration),
        },
        request_id: migration.id,
        title: "Browser data import detected".into(),
        details,
        expires_at: migration.expires_at,
        allow_label: "Yes, allow this import".into(),
        block_label: "No, block".into(),
    }
}

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn remaining_authorization_text(expires_at: u64, now: u64) -> String {
    let remaining = expires_at.saturating_sub(now);
    if remaining == 0 {
        "Authorization deadline: expired".into()
    } else {
        format!("Authorization time remaining: {remaining} seconds")
    }
}

fn ssh_read_prompt(pending: guard_ipc::SshPendingInfo) -> PendingPrompt {
    let process = PathBuf::from(&pending.process_exe)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| pending.process_exe.clone());
    PendingPrompt {
        key: PromptKey {
            kind: PromptKind::SshRead,
            value: pending.id.clone(),
        },
        request_id: pending.id,
        title: "SSH private-key access detected".into(),
        details: format!(
            "Program: {process}\nExecutable: {}\nPID: {}\nSSH private key: {}\n{}\n\nAllow this verified process tree to read this key for 10 seconds?",
            pending.process_exe,
            pending.pid,
            pending.key_path,
            remaining_authorization_text(pending.expires_at, unix_seconds()),
        ),
        expires_at: pending.expires_at,
        allow_label: "Allow".into(),
        block_label: "Block".into(),
    }
}

fn present_next_pending_dialog(
    window: &adw::ApplicationWindow,
    controller: Rc<RefCell<PendingDialogController>>,
    pending_only: bool,
) {
    let next = {
        let mut controller_ref = controller.borrow_mut();
        if controller_ref.active().is_none() {
            controller_ref.activate_next()
        } else {
            None
        }
    };
    if let Some(prompt) = next {
        present_pending_dialog(window, controller, prompt, pending_only);
    }
}

fn present_pending_dialog(
    window: &adw::ApplicationWindow,
    controller: Rc<RefCell<PendingDialogController>>,
    prompt: PendingPrompt,
    pending_only: bool,
) {
    let dialog = gtk::MessageDialog::builder()
        .transient_for(window)
        .modal(true)
        .message_type(gtk::MessageType::Warning)
        .text(&prompt.title)
        .secondary_text(&prompt.details)
        .build();
    let block = dialog.add_button(&prompt.block_label, gtk::ResponseType::Reject);
    block.add_css_class("destructive-action");
    let allow = dialog.add_button(&prompt.allow_label, gtk::ResponseType::Accept);
    allow.add_css_class("suggested-action");

    let response_controller = controller.clone();
    let response_window = window.clone();
    let response_prompt = prompt.clone();
    let response_pending_only = pending_only;
    let response_allow = allow.clone();
    let response_block = block.clone();
    let response_details = prompt.details.clone();
    dialog.connect_response(move |dialog, response| {
        let is_allow = response == gtk::ResponseType::Accept;
        let is_block = response == gtk::ResponseType::Reject;
        if !is_allow && !is_block {
            return;
        }
        if !response_controller.borrow_mut().begin_authorization() {
            return;
        }
        response_allow.set_sensitive(false);
        response_block.set_sensitive(false);
        dialog.set_secondary_text(Some(&format!(
            "{response_details}\n\n{}",
            if is_allow {
                "Waiting for system authentication…"
            } else {
                "Blocking this request…"
            }
        )));
        resolve_pending_in_background(
            response_window.clone(),
            response_controller.clone(),
            response_prompt.clone(),
            is_allow,
            response_pending_only,
            PendingDialogUi {
                dialog: dialog.clone(),
                allow_button: response_allow.clone(),
                block_button: response_block.clone(),
                details: response_details.clone(),
            },
        );
    });

    let close_controller = controller.clone();
    let close_window = window.clone();
    let close_prompt = prompt;
    let close_pending_only = pending_only;
    let close_allow = allow.clone();
    let close_block = block.clone();
    let close_details = close_prompt.details.clone();
    dialog.connect_close_request(move |dialog| {
        let state = close_controller.borrow().active().map(|(_, state)| state);
        if state == Some(PromptState::Authorizing) {
            // Keep the dialog alive while the platform authenticates the user.
            return glib::Propagation::Stop;
        }
        if state != Some(PromptState::AwaitingChoice)
            || !close_controller.borrow_mut().begin_authorization()
        {
            return glib::Propagation::Proceed;
        }
        close_allow.set_sensitive(false);
        close_block.set_sensitive(false);
        dialog.set_secondary_text(Some(&format!("{close_details}\n\nBlocking this request…")));
        resolve_pending_in_background(
            close_window.clone(),
            close_controller.clone(),
            close_prompt.clone(),
            false,
            close_pending_only,
            PendingDialogUi {
                dialog: dialog.clone(),
                allow_button: close_allow.clone(),
                block_button: close_block.clone(),
                details: close_details.clone(),
            },
        );
        glib::Propagation::Stop
    });
    dialog.present();
}

#[derive(Clone)]
struct PendingDialogUi {
    dialog: gtk::MessageDialog,
    allow_button: gtk::Widget,
    block_button: gtk::Widget,
    details: String,
}

fn resolve_pending_in_background(
    window: adw::ApplicationWindow,
    controller: Rc<RefCell<PendingDialogController>>,
    prompt: PendingPrompt,
    allow: bool,
    pending_only: bool,
    ui: PendingDialogUi,
) {
    glib::MainContext::default().spawn_local(async move {
        let result = gio::spawn_blocking(move || {
            platform_service::resolve_pending(
                prompt.key.kind,
                &prompt.request_id,
                allow,
                prompt.expires_at,
            )
        })
        .await;
        if allow {
            match result {
                Ok(Ok(())) => {
                    complete_pending_dialog(&window, &controller, &ui.dialog, pending_only, true)
                }
                Ok(Err(error)) if platform_service::pending_error_is_terminal(&error) => {
                    complete_pending_dialog(&window, &controller, &ui.dialog, pending_only, true)
                }
                Ok(Err(error)) => retry_pending_dialog(
                    &controller,
                    &ui.allow_button,
                    &ui.block_button,
                    &ui.dialog,
                    &ui.details,
                    format!("Authentication was not completed: {error}"),
                ),
                Err(error) => retry_pending_dialog(
                    &controller,
                    &ui.allow_button,
                    &ui.block_button,
                    &ui.dialog,
                    &ui.details,
                    format!("Authorization could not be completed: {error:?}"),
                ),
            }
        } else {
            complete_pending_dialog(&window, &controller, &ui.dialog, pending_only, true);
        }
    });
}

fn retry_pending_dialog(
    controller: &Rc<RefCell<PendingDialogController>>,
    allow_button: &gtk::Widget,
    block_button: &gtk::Widget,
    dialog: &gtk::MessageDialog,
    details: &str,
    error: String,
) {
    if controller.borrow_mut().retry() {
        allow_button.set_sensitive(true);
        block_button.set_sensitive(true);
        dialog.set_secondary_text(Some(&format!(
            "{details}\n\n{error} You can try again or block this request."
        )));
    }
}

fn complete_pending_dialog(
    window: &adw::ApplicationWindow,
    controller: &Rc<RefCell<PendingDialogController>>,
    dialog: &gtk::MessageDialog,
    pending_only: bool,
    close_when_empty: bool,
) {
    if controller.borrow_mut().finish() {
        dialog.close();
        controller.borrow_mut().release_terminal();
        if close_when_empty
            && should_close_pending_window(pending_only, controller.borrow().is_empty())
        {
            window.close();
        } else {
            present_next_pending_dialog(window, controller.clone(), pending_only);
        }
    }
}

const fn should_close_pending_window(pending_only: bool, queue_empty: bool) -> bool {
    pending_only && queue_empty
}

#[cfg(any())]
fn present_incident_dialog(window: &adw::ApplicationWindow, incident: guard_ipc::SshIncidentInfo) {
    let window = window.clone();
    let process = PathBuf::from(&incident.process_exe)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| incident.process_exe.clone());
    let destination = match (
        incident.destination_ip.as_deref(),
        incident.destination_port,
        incident.protocol.as_deref(),
    ) {
        (Some(ip), Some(port), Some(protocol)) => {
            format!("\nDestination: {ip}:{port} ({protocol})")
        }
        _ => String::new(),
    };
    let keys = if incident.accessed_key_paths.len() <= 1 {
        incident.key_path.clone()
    } else {
        format!(
            "{} (and {} other protected key(s))",
            incident.key_path,
            incident.accessed_key_paths.len() - 1
        )
    };
    let since_access_ms = incident
        .first_network_ms
        .unwrap_or(incident.last_sensitive_read_ms)
        .saturating_sub(incident.last_sensitive_read_ms);
    let dialog = gtk::MessageDialog::builder()
        .transient_for(&window)
        .modal(true)
        .message_type(gtk::MessageType::Warning)
        .text("Sensitive-key network activity blocked")
        .secondary_text(format!(
            "Program: {process}\nPID: {}\nKey accessed: {keys}\nTime since access: {since_access_ms} ms{}\n\nThe program recently accessed a protected SSH private key and then attempted external network activity.\n\nThis does not establish what data was sent.",
            incident.pid, destination
        ))
        .build();
    let quarantine = dialog.add_button("Block & Quarantine", gtk::ResponseType::Reject);
    quarantine.add_css_class("destructive-action");
    dialog.add_button("Block", gtk::ResponseType::No);
    let allow = dialog.add_button("Allow", gtk::ResponseType::Accept);
    allow.add_css_class("suggested-action");
    dialog.set_default_response(gtk::ResponseType::No);
    dialog.connect_response(move |dialog, response| {
        let id = incident.id.clone();
        let action = match response {
            gtk::ResponseType::Reject => guard_ipc::IncidentResolutionAction::BlockAndQuarantine,
            gtk::ResponseType::Accept => guard_ipc::IncidentResolutionAction::Allow,
            // Closing/dismissing is deliberately Block, never Allow.
            _ => guard_ipc::IncidentResolutionAction::Block,
        };
        let parent = window.clone();
        glib::MainContext::default().spawn_local(async move {
            let socket = PathBuf::from(SOCKET);
            let result =
                gio::spawn_blocking(move || guard_client::resolve_incident(&socket, &id, action))
                    .await;
            let (title, detail) = match result {
                Ok(Ok(resolved)) => (
                    "Incident resolved",
                    resolved
                        .resolution_detail
                        .unwrap_or_else(|| "The incident resolution completed.".into()),
                ),
                Ok(Err(error)) => ("Incident resolution failed", error.to_string()),
                Err(_) => (
                    "Incident resolution failed",
                    "The background resolver stopped unexpectedly.".into(),
                ),
            };
            gtk::MessageDialog::builder()
                .transient_for(&parent)
                .modal(true)
                .message_type(gtk::MessageType::Info)
                .text(title)
                .secondary_text(detail)
                .build()
                .show();
        });
        dialog.close();
    });
    dialog.show();
}

fn spawn_protection_change(
    enabled: bool,
    candidate: Rc<RefCell<Option<platform_service::EditableConfiguration>>>,
    switch: adw::SwitchRow,
    syncing: Rc<Cell<bool>>,
) {
    let current = candidate.borrow().clone();
    glib::MainContext::default().spawn_local(async move {
        let result =
            gio::spawn_blocking(move || platform_service::set_protection_enabled(enabled, current))
                .await;
        switch.set_sensitive(true);
        syncing.set(true);
        match result {
            Ok(Ok(updated)) => {
                *candidate.borrow_mut() = Some(updated);
                switch.set_active(enabled);
                switch.set_tooltip_text(None);
            }
            Ok(Err(error)) => {
                switch.set_active(!enabled);
                switch.set_tooltip_text(Some(&format!("Protection change failed: {error}")));
            }
            Err(error) => {
                switch.set_active(!enabled);
                switch.set_tooltip_text(Some(&format!(
                    "Protection task stopped unexpectedly: {error:?}"
                )));
            }
        }
        syncing.set(false);
    });
}

fn spawn_user_agent_change(
    enabled: bool,
    row: adw::SwitchRow,
    syncing: Rc<Cell<bool>>,
    error_state: Rc<RefCell<Option<String>>>,
) {
    glib::MainContext::default().spawn_local(async move {
        let result =
            gio::spawn_blocking(move || platform_service::set_user_agent_enabled(enabled)).await;
        row.set_sensitive(true);
        syncing.set(true);
        match result {
            Ok(Ok(())) => {
                *error_state.borrow_mut() = None;
                row.set_active(enabled);
                row.set_tooltip_text(None);
            }
            Ok(Err(error)) => {
                row.set_active(!enabled);
                let message = format!("Failed to enable confirmation helper: {error}");
                *error_state.borrow_mut() = Some(message.clone());
                row.set_subtitle(&message);
                row.set_tooltip_text(Some(&message));
            }
            Err(error) => {
                row.set_active(!enabled);
                let message = format!("Confirmation helper task failed: {error:?}");
                *error_state.borrow_mut() = Some(message.clone());
                row.set_subtitle(&message);
                row.set_tooltip_text(Some(&message));
            }
        }
        syncing.set(false);
    });
}

fn spawn_system_extension_install(button: gtk::Button, message: gtk::Label) {
    button.set_sensitive(false);
    message.set_text("Requesting macOS protection extension installation/update…");
    glib::MainContext::default().spawn_local(async move {
        let result = gio::spawn_blocking(platform_service::request_system_extension_install).await;
        button.set_sensitive(true);
        match result {
            Ok(Ok(explanation)) => {
                message.set_text(&explanation);
                button.set_tooltip_text(None);
            }
            Ok(Err(error)) => {
                message.set_text(&format!(
                    "Unable to install the protection extension: {error}"
                ));
                button.set_tooltip_text(Some(&error.to_string()));
            }
            Err(error) => {
                message
                    .set_text("The installation request stopped unexpectedly; please try again.");
                button.set_tooltip_text(Some(&format!("Installation task stopped: {error:?}")));
            }
        }
    });
}

fn spawn_apply(bytes: Vec<u8>, button: gtk::Button) {
    let write_bytes = bytes.clone();
    glib::MainContext::default().spawn_local(async move {
        let result =
            gio::spawn_blocking(move || platform_service::apply_config(&write_bytes)).await;
        match result {
            Ok(Ok(())) => {
                button.set_sensitive(false);
                button.set_tooltip_text(None);
            }
            Ok(Err(error)) => {
                button.set_sensitive(true);
                let message = format!("应用失败：{error:#}");
                button.set_tooltip_text(Some(&message));
            }
            Err(error) => {
                button.set_sensitive(true);
                let message = format!("应用任务异常：{error:?}");
                button.set_tooltip_text(Some(&message));
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn daemon_configuration_preserves_ssh_enrollment_for_the_ui() {
        let config = configuration_from_daemon(guard_ipc::ConfigurationInfo {
            enforcement_mode: Some("strict-filesystem".into()),
            policy_enabled: None,
            browsers: vec![guard_ipc::ConfiguredBrowserInfo {
                id: "firefox".into(),
                family: "Firefox".into(),
                profile_root: "/home/test/.mozilla/firefox".into(),
                owner_uid: None,
                exe_paths: vec!["/usr/lib/firefox/firefox".into()],
            }],
            enrolled_exes: vec!["/usr/bin/known-good-helper".into()],
            ssh_keys: vec!["/home/test/.ssh/id_ed25519".into()],
            mac_system_processes: Vec::new(),
            mac_trusted_tools: Vec::new(),
        })
        .expect("supported daemon snapshot");
        assert_eq!(
            config.enforcement_mode,
            Some(platform_service::LinuxEnforcementMode::StrictFilesystem)
        );
        assert_eq!(
            config.ssh_keys,
            vec![PathBuf::from("/home/test/.ssh/id_ed25519")]
        );
        assert_eq!(config.browsers[0].owner_uid, None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mac_configuration_has_policy_state_and_no_linux_mode() {
        let config = configuration_from_daemon(guard_ipc::ConfigurationInfo {
            enforcement_mode: None,
            policy_enabled: Some(true),
            browsers: vec![guard_ipc::ConfiguredBrowserInfo {
                id: "firefox".into(),
                family: "firefox".into(),
                profile_root: "/Users/test/Library/Application Support/Firefox".into(),
                owner_uid: Some(501),
                exe_paths: vec!["/Applications/Firefox.app/Contents/MacOS/firefox".into()],
            }],
            enrolled_exes: Vec::new(),
            ssh_keys: Vec::new(),
            mac_system_processes: Vec::new(),
            mac_trusted_tools: Vec::new(),
        })
        .unwrap();
        assert_eq!(config.enforcement_mode, None);
        assert!(config.policy_enabled);
        assert!(!platform_service::shows_linux_mode());
    }

    #[test]
    fn pending_only_closes_but_manual_control_center_stays_open() {
        assert!(should_close_pending_window(true, true));
        assert!(!should_close_pending_window(false, true));
        assert!(!should_close_pending_window(true, false));
    }

    #[test]
    fn pending_prompt_reports_remaining_or_expired_deadline() {
        assert_eq!(
            remaining_authorization_text(160, 100),
            "Authorization time remaining: 60 seconds"
        );
        assert_eq!(
            remaining_authorization_text(100, 100),
            "Authorization deadline: expired"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mac_guard_notification_is_metadata_only() {
        let event = guard_ipc::EventInfo {
            id: 1,
            event_code: "browser_access_denied".into(),
            ts_ms: 1,
            uid: 501,
            pid: 10,
            start_time: 1,
            decision: "Deny(UnknownProcess)".into(),
            deny_reason: Some("UnknownProcess".into()),
            reason_code: Some("browser_protected_resource".into()),
            resource_kind: "CookieStore".into(),
            resource_kind_code: "browser_cookie_store".into(),
            resource_browser: Some("edge".into()),
            resource_profile: Some("Default".into()),
            path: "/Users/test/secret/Cookies".into(),
            exe: "/Applications/App Cleaner.app/Contents/MacOS/App Cleaner".into(),
            exe_owner_uid: 501,
            trust_tier: "Unknown".into(),
            process_browser: None,
            parent_pid: None,
            parent_exe: None,
            lease_id: None,
            backend_diag: "synthetic".into(),
        };
        let (_, body) = mac_notification_text(&event);
        assert!(!body.contains("/Users/"));
        assert!(body.contains("browser_cookie_store"));
    }

    #[test]
    fn timeout_and_replay_errors_are_terminal_but_cancellation_is_retryable() {
        assert!(platform_service::pending_error_is_terminal(
            &anyhow::anyhow!("system extension error: timed_out")
        ));
        assert!(platform_service::pending_error_is_terminal(
            &anyhow::anyhow!("system extension error: already_resolved")
        ));
        assert!(!platform_service::pending_error_is_terminal(
            &anyhow::anyhow!("device-owner authentication was cancelled")
        ));
    }

    #[test]
    fn active_runtime_ssh_key_is_labeled_as_protected() {
        assert_eq!(
            ssh_key_subtitle(true, false),
            "Protected — runtime enrollment (not yet in saved configuration)"
        );
        assert_eq!(
            ssh_key_subtitle(false, true),
            "Configured — not active in the current guardd process"
        );
    }

    #[test]
    fn sibling_importers_share_one_dialog_session_key() {
        let first = guard_ipc::MigrationPendingInfo {
            id: "1".into(),
            uid: 1000,
            source_browser: "firefox".into(),
            source_profile: "default".into(),
            target_browser: "microsoft-edge".into(),
            target_exe: "/opt/microsoft/msedge/msedge".into(),
            target_pid: 10,
            target_start_time: 100,
            requested_data: "browser_key_material".into(),
            created_at: 1,
            expires_at: 2,
        };
        let mut sibling = first.clone();
        sibling.id = "2".into();
        sibling.target_pid = 11;
        sibling.target_start_time = 101;
        assert_eq!(
            migration_session_key(&first),
            migration_session_key(&sibling)
        );
    }

    #[test]
    fn health_requires_live_evidence() {
        let status = guard_ipc::StatusInfo {
            version: "x".into(),
            backend_kind: "linux-fanotify".into(),
            backend_diagnostic: None,
            backend_state: None,
            enforcement_active: true,
            read_only_guaranteed: None,
            status: "ACTIVE".into(),
            mode: Some("strict-filesystem".into()),
            marked_filesystems: Some(1),
            required_filesystems: Some(1),
            filesystem_marks_healthy: Some(true),
            strict_events_total: Some(0),
            strict_fast_allowed: Some(0),
            protected_events: 0,
            fanotify_overflows: Some(0),
            classifier_failures: Some(0),
            strict_alias_scans: Some(0),
            strict_alias_matches: Some(0),
            topology_degraded: Some(false),
            mac_health: None,
            protected_files: 1,
            ssh_protected_keys: 0,
            protected_trees: 1,
            browsers: 1,
            browser_exes: 1,
            allowed: 0,
            denied: 0,
            unclassified: 0,
            audit_dropped: 0,
            peer_uid: 1000,
        };
        assert_eq!(
            health_from_evidence(true, true, Some(&status)),
            Health::Active
        );
        assert_eq!(
            health_from_evidence(true, true, Some(&status)),
            Health::Active
        );
        assert_eq!(
            health_from_evidence(true, false, Some(&status)),
            Health::Degraded
        );
        assert_eq!(
            health_from_evidence(false, false, Some(&status)),
            Health::Stopped
        );
        assert_eq!(health_from_evidence(true, true, None), Health::Unreachable);
    }
}
