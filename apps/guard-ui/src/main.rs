//! Native GTK control center.  This process is deliberately only a client:
//! policy decisions and privileged writes remain in guardd/guardctl.

use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::rc::Rc;

use adw::prelude::*;
use gtk4 as gtk;
use libadwaita as adw;

const APP_ID: &str = "io.github.plfjy.SensitiveFileGuard";
const SOCKET: &str = "/run/guardd/guardd.sock";

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
            Some(status)
                if status.status == "ACTIVE"
                    && (status.ssh_protected_keys == 0
                        || status.ssh_behavior_status == "ACTIVE") =>
            {
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

fn ssh_behavior_summary(status: &guard_ipc::StatusInfo) -> String {
    match status.ssh_behavior_status.as_str() {
        "ACTIVE" => "Active — key access is allowed and monitored for immediate external network activity".into(),
        "UNAVAILABLE" => "Unavailable — key access is still allowed and reported, but immediate external network activity cannot currently be blocked".into(),
        "DEGRADED" => "Degraded — key access is still allowed and reported; some immediate external network activity may not be blocked".into(),
        _ => "Unknown — key access is still allowed and reported; network blocking status is unknown".into(),
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
    candidate: Rc<RefCell<Option<guard_platform::config::EnforcementConfig>>>,
    status: gtk::Label,
    detail: gtk::Label,
    apply: gtk::Button,
    mode: gtk::ComboBoxText,
    browsers: gtk::ListBox,
    keys: gtk::ListBox,
    events: gtk::ListBox,
    event_data: Rc<RefCell<Vec<guard_ipc::EventInfo>>>,
    browser_sources: Rc<RefCell<Vec<BrowserSource>>>,
    ssh_sources: Rc<RefCell<Vec<SshSource>>>,
    /// Last daemon-reported SSH resources. This is a display cache refreshed
    /// from IPC, not a second enrollment registry.
    active_ssh_keys: Rc<RefCell<HashSet<PathBuf>>>,
    poll_in_flight: Rc<Cell<bool>>,
    protection: Rc<RefCell<Option<adw::SwitchRow>>>,
    protection_syncing: Rc<Cell<bool>>,
    shown_incidents: Rc<RefCell<HashSet<String>>>,
    shown_migrations: Rc<RefCell<HashSet<String>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MigrationDialogState {
    AwaitingChoice,
    Authorizing,
    Terminal,
}

fn main() {
    adw::init().expect("libadwaita initialization");
    // Let libadwaita own the color preference instead of inheriting the
    // deprecated GtkSettings dark-theme toggle from the desktop session.
    adw::StyleManager::default().set_color_scheme(adw::ColorScheme::Default);
    let app = adw::Application::new(Some(APP_ID), gio::ApplicationFlags::empty());
    app.connect_activate(build_ui);
    app.run();
}

fn build_ui(app: &adw::Application) {
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
    let detail = gtk::Label::new(Some(
        "Live protection, notification, and daemon health are required for a green state.",
    ));
    detail.set_wrap(true);
    detail.set_xalign(0.0);
    let apply = gtk::Button::with_label("Apply & Restart");
    apply.set_sensitive(false);
    let mode = gtk::ComboBoxText::new();
    mode.append(Some("strict-filesystem"), "Strict Filesystem (recommended)");
    mode.append(Some("conservative"), "Conservative (compatibility)");
    mode.set_active_id(Some("strict-filesystem"));
    let browsers = gtk::ListBox::new();
    browsers.set_selection_mode(gtk::SelectionMode::None);
    let keys = gtk::ListBox::new();
    keys.set_selection_mode(gtk::SelectionMode::None);
    let events = gtk::ListBox::new();
    events.set_selection_mode(gtk::SelectionMode::None);

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
        browser_sources: Rc::new(RefCell::new(Vec::new())),
        ssh_sources: Rc::new(RefCell::new(Vec::new())),
        active_ssh_keys: Rc::new(RefCell::new(HashSet::new())),
        poll_in_flight: Rc::new(Cell::new(false)),
        protection: Rc::new(RefCell::new(None)),
        protection_syncing: Rc::new(Cell::new(false)),
        shown_incidents: Rc::new(RefCell::new(HashSet::new())),
        shown_migrations: Rc::new(RefCell::new(HashSet::new())),
    };
    let overview = scroll_page(overview_page(&state));
    let protection = scroll_page(protection_page(&state));
    let log = scroll_page(log_page(&state));
    let stack = gtk::Stack::new();
    stack.add_titled(&overview, Some("overview"), "Overview");
    stack.add_titled(&protection, Some("protection"), "Protection");
    stack.add_titled(&log, Some("log"), "Security Log");
    let nav = gtk::ListBox::new();
    nav.set_selection_mode(gtk::SelectionMode::Single);
    for title in ["Overview", "Protection", "Security Log"] {
        nav.append(&gtk::Label::new(Some(title)));
    }
    nav.select_row(nav.row_at_index(0).as_ref());
    let stack_for_nav = stack.clone();
    nav.connect_row_selected(move |_, row| {
        if let Some(row) = row {
            stack_for_nav.set_visible_child_name(match row.index() {
                1 => "protection",
                2 => "log",
                _ => "overview",
            });
        }
    });
    nav.set_width_request(220);
    nav.add_css_class("navigation-sidebar");
    let split = gtk::Paned::new(gtk::Orientation::Horizontal);
    split.set_start_child(Some(&nav));
    split.set_end_child(Some(&stack));
    split.set_position(260);
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
    let window = adw::ApplicationWindow::new(app);
    window.set_title(Some("Sensitive File Guard"));
    window.set_default_size(980, 680);
    window.set_content(Some(&root));
    window.present();

    load_configuration(&state);
    start_polling(state, window);
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
    row.set_title("Protection + notifications");
    row.set_subtitle(
        "Controls guardd.service and guard-notify.service together; turning it off makes protected files accessible normally.",
    );
    row.set_active(false);
    *state.protection.borrow_mut() = Some(row.clone());
    let start_row = row.clone();
    let syncing = state.protection_syncing.clone();
    row.connect_active_notify(move |switch_row| {
        if syncing.get() {
            return;
        }
        let verb = if switch_row.is_active() {
            "start"
        } else {
            "stop"
        };
        start_row.set_sensitive(false);
        spawn_protection_bundle(verb.to_owned(), start_row.clone(), syncing.clone());
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
            cfg.enforcement_mode = if m.active_id().as_deref() == Some("strict-filesystem") {
                guard_platform::config::EnforcementMode::StrictFilesystem
            } else {
                guard_platform::config::EnforcementMode::Conservative
            };
            apply.set_sensitive(true);
        }
    });
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
    let socket = PathBuf::from(SOCKET);
    let events = state.events.clone();
    let data = state.event_data.clone();
    older.connect_clicked(move |_| {
        let before = data.borrow().last().map(|event| event.id);
        let data = data.clone();
        let events = events.clone();
        let socket = socket.clone();
        glib::MainContext::default().spawn_local(async move {
            let page = gio::spawn_blocking(move || {
                guard_client::events_cursor(&socket, Some(100), before, None)
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
                let row = gtk::ListBoxRow::new();
                let label = gtk::Label::new(Some(&format!(
                    "#{}  {}  {}",
                    event.id, event.decision, event.path
                )));
                label.set_xalign(0.0);
                label.set_margin_top(6);
                label.set_margin_bottom(6);
                label.set_margin_start(6);
                label.set_margin_end(6);
                row.set_child(Some(&label));
                events.append(&row);
            }
        });
    });
    page.append(&older);
    page
}

fn is_blocked_event(event: &guard_ipc::EventInfo) -> bool {
    event.decision.starts_with("Deny")
}

fn is_visible_event(event: &guard_ipc::EventInfo) -> bool {
    cfg!(debug_assertions)
        || is_blocked_event(event)
        || event.event_code.starts_with("ssh_behavior_")
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
) -> Option<guard_platform::config::EnforcementConfig> {
    let enforcement_mode = match info.enforcement_mode.as_str() {
        "strict-filesystem" => guard_platform::config::EnforcementMode::StrictFilesystem,
        "conservative" => guard_platform::config::EnforcementMode::Conservative,
        _ => return None,
    };
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
            profile_root: PathBuf::from(browser.profile_root),
            owner_uid: browser.owner_uid,
            exe_paths: browser.exe_paths.into_iter().map(PathBuf::from).collect(),
        });
    }
    Some(guard_platform::config::EnforcementConfig {
        enforcement_mode,
        browsers,
        enrolled_exes: info.enrolled_exes.into_iter().map(PathBuf::from).collect(),
        ssh_keys: info.ssh_keys.into_iter().map(PathBuf::from).collect(),
        ssh_behavior_window_secs: info.ssh_behavior_window_secs,
    })
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
        state
            .mode
            .set_active_id(Some(cfg.enforcement_mode.as_str()));
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
    let discovered = discover_native_browsers(&home);
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

/// Browser layouts belong to the selected platform helper.  The GTK client
/// consumes the portable discovery DTO and therefore does not link the Linux
/// implementation crate merely to render policy sources.
fn discover_native_browsers(home: &std::path::Path) -> guard_platform::config::BrowserDiscovery {
    let output = Command::new("guardctl")
        .args(["browser", "discover", "--home"])
        .arg(home)
        .output();
    output
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| serde_json::from_slice(&output.stdout).ok())
        .unwrap_or_else(|| guard_platform::config::BrowserDiscovery {
            browsers: Vec::new(),
            unsupported_sandboxed: Vec::new(),
        })
}

fn browser_family_name(family: guard_core::BrowserFamily) -> &'static str {
    match family {
        guard_core::BrowserFamily::Firefox => "Firefox",
        guard_core::BrowserFamily::Zen => "Zen",
        guard_core::BrowserFamily::Chromium => "Chromium",
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

fn render_objects(state: &UiState, cfg: &guard_platform::config::EnforcementConfig) {
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

fn start_polling(state: UiState, window: adw::ApplicationWindow) {
    let state = Rc::new(state);
    let poll_state = state.clone();
    let poll_window = window.clone();
    glib::timeout_add_seconds_local(2, move || {
        refresh_state(&poll_state, &poll_window);
        glib::ControlFlow::Continue
    });
    refresh_state(&state, &window);
}

fn refresh_state(state: &UiState, window: &adw::ApplicationWindow) {
    // Never queue refresh work behind a stalled socket or service query. One
    // background request is enough; the next timer tick retries after it ends.
    if state.poll_in_flight.replace(true) {
        return;
    }
    let socket = PathBuf::from(SOCKET);
    let status = state.status.clone();
    let detail = state.detail.clone();
    let events = state.events.clone();
    let event_data = state.event_data.clone();
    let poll_in_flight = state.poll_in_flight.clone();
    let protection = state.protection.clone();
    let protection_syncing = state.protection_syncing.clone();
    let shown_incidents = state.shown_incidents.clone();
    let shown_migrations = state.shown_migrations.clone();
    let config_state = state.clone();
    let window = window.clone();
    let after_id = event_data.borrow().first().map(|event| event.id);
    glib::MainContext::default().spawn_local(async move {
        let result = gio::spawn_blocking(move || {
            let daemon = guard_client::status(&socket).ok();
            let configuration = guard_client::configuration(&socket).ok();
            let active_ssh_keys = guard_client::resources(&socket)
                .unwrap_or_default()
                .into_iter()
                .filter(|resource| resource.kind == "SshPrivateKey" && !resource.tree)
                .map(|resource| PathBuf::from(resource.path))
                .collect::<Vec<_>>();
            let recent_events = guard_client::events_cursor(&socket, Some(100), None, after_id)
                .unwrap_or_default()
                .into_iter()
                .filter(is_visible_event)
                .collect::<Vec<_>>();
            let pending_incidents = guard_client::incidents(&socket)
                .unwrap_or_default()
                .into_iter()
                .filter(|incident| {
                    incident.state == guard_ipc::SshIncidentStateInfo::PendingDecision
                })
                .collect::<Vec<_>>();
            let pending_migrations = guard_client::migration_pending(&socket).unwrap_or_default();
            let service_status = guard_client::service::status().ok();
            let service_active = service_status
                .as_ref()
                .map(|status| status.protection_active)
                .unwrap_or(false);
            let notification_active = service_status
                .as_ref()
                .and_then(|status| status.notification_active)
                .unwrap_or(false);
            (service_active, notification_active, daemon, configuration, active_ssh_keys, recent_events, pending_incidents, pending_migrations)
        }).await;
        if let Ok((service_active, notification_active, daemon, configuration, active_ssh_keys, recent_events, pending_incidents, pending_migrations)) = result {
            let active_ssh_changed = update_active_ssh_keys(&config_state, active_ssh_keys);
            let configuration_hydrated = configuration
                .map(|configuration| hydrate_configuration_from_daemon(&config_state, configuration))
                .unwrap_or(false);
            if active_ssh_changed || configuration_hydrated {
                refresh_browser_sources(&config_state);
            }
            let health = health_from_evidence(
                service_active,
                notification_active,
                daemon.as_ref(),
            );
            status.set_text(health_label(health));
            // The switch represents the actual protection service bundle. Keep it
            // synchronized with out-of-band `systemctl`/`guardctl` changes,
            // while suppressing its callback so a refresh never starts a new
            // privileged operation.
            if let Some(row) = protection.borrow().as_ref() {
                let bundle_active = service_active && notification_active;
                if row.is_active() != bundle_active {
                    protection_syncing.set(true);
                    row.set_active(bundle_active);
                    protection_syncing.set(false);
                }
                row.set_sensitive(true);
            }
            let service_state = if service_active { "active" } else { "inactive" };
            let notification_state = if notification_active { "active" } else { "inactive" };
            detail.set_text(&daemon.map(|s| format!("Mode: {} · browsers: {} · SSH keys: {} · SSH behavior: {} · allowed: {} · denied: {} · marks: {}/{} · service: {} · notifications: {}", s.mode, s.browsers, s.ssh_protected_keys, ssh_behavior_summary(&s), s.allowed, s.denied, s.marked_filesystems, s.required_filesystems, service_state, notification_state)).unwrap_or_else(|| format!("guardd IPC is unavailable · service: {} · notifications: {}", service_state, notification_state)));
            if after_id.is_none() {
                while let Some(child) = events.first_child() { events.remove(&child); }
                *event_data.borrow_mut() = recent_events.clone();
            } else {
                let mut existing = event_data.borrow_mut();
                for event in recent_events.iter().rev() { existing.insert(0, event.clone()); }
            }
            for event in recent_events {
                let row = gtk::ListBoxRow::new();
                let box_ = gtk::Box::new(gtk::Orientation::Vertical, 2);
                let decision = match event.event_code.as_str() {
                    "browser_migration_confirmation_required" => "IMPORT CONFIRMATION REQUIRED",
                    "browser_migration_allowed" => "IMPORT ALLOWED",
                    "browser_migration_blocked" => "IMPORT BLOCKED",
                    "browser_migration_timed_out" => "IMPORT TIMED OUT",
                    "ssh_behavior_key_accessed" => "KEY ACCESSED",
                    "ssh_behavior_network_blocked" => "NETWORK BLOCKED",
                    "ssh_behavior_blocked_by_user" => "BLOCKED BY USER",
                    "ssh_behavior_allowed_by_user" => "ALLOWED BY USER",
                    "ssh_behavior_blocked_and_quarantined" => "BLOCKED & QUARANTINED",
                    _ if is_blocked_event(&event) => "BLOCKED",
                    _ if event.decision.starts_with("AllowByLease") => "ALLOWED BY LEASE",
                    _ => "ALLOWED",
                };
                let title = gtk::Label::new(Some(&format!("{}  ·  {}", decision, event.exe)));
                title.set_xalign(0.0); title.add_css_class(if matches!(decision, "BLOCKED" | "NETWORK BLOCKED") { "error" } else { "success" });
                let subtitle = gtk::Label::new(Some(&format!("#{} · {} · {}", event.id, event.resource_kind, event.path)));
                subtitle.set_xalign(0.0); subtitle.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
                box_.append(&title); box_.append(&subtitle); row.set_child(Some(&box_));
                if after_id.is_some() { events.insert(&row, 0); } else { events.append(&row); }
            }
            for incident in pending_incidents {
                if shown_incidents.borrow_mut().insert(incident.id.clone()) {
                    present_incident_dialog(&window, incident);
                }
            }
            let pending_migration_sessions = pending_migrations
                .iter()
                .map(migration_session_key)
                .collect::<HashSet<_>>();
            shown_migrations
                .borrow_mut()
                .retain(|session| pending_migration_sessions.contains(session));
            for migration in pending_migrations {
                if shown_migrations
                    .borrow_mut()
                    .insert(migration_session_key(&migration))
                {
                    present_migration_dialog(&window, migration);
                }
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
            // Keep the dialog visible while pkcheck presents its own desktop
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

fn spawn_protection_bundle(verb: String, switch: adw::SwitchRow, syncing: Rc<Cell<bool>>) {
    let requested_on = verb == "start";
    glib::MainContext::default().spawn_local(async move {
        let ok = gio::spawn_blocking(move || run_protection_bundle(&verb))
            .await
            .unwrap_or(false);
        switch.set_sensitive(true);
        syncing.set(true);
        switch.set_active(ok && requested_on);
        syncing.set(false);
    });
}

fn run_main_service(verb: &str) -> bool {
    let operation = match verb {
        "start" => guard_platform::ServiceOperation::Start,
        "stop" => guard_platform::ServiceOperation::Stop,
        "restart" => guard_platform::ServiceOperation::Restart,
        _ => return false,
    };
    guard_client::service::apply(operation).is_ok()
}

fn run_notification_service(verb: &str) -> bool {
    let operation = match verb {
        "start" => guard_platform::ServiceOperation::Start,
        "stop" => guard_platform::ServiceOperation::Stop,
        "restart" => guard_platform::ServiceOperation::Restart,
        _ => return false,
    };
    guard_client::service::apply_notifications(operation).is_ok()
}

fn run_protection_bundle(verb: &str) -> bool {
    match verb {
        "start" => {
            if !run_main_service("start") {
                return false;
            }
            if run_notification_service("start") {
                true
            } else {
                // Do not leave the protection daemon running alone when the
                // desktop notification half could not be started.
                let _ = run_main_service("stop");
                false
            }
        }
        "stop" => {
            let notification_stopped = run_notification_service("stop");
            let main_stopped = run_main_service("stop");
            if main_stopped {
                true
            } else {
                // Preserve the previous bundle when stopping the daemon
                // failed after notifications were stopped.
                if notification_stopped {
                    let _ = run_notification_service("start");
                }
                false
            }
        }
        _ => false,
    }
}

fn spawn_apply(bytes: Vec<u8>, button: gtk::Button) {
    let write_bytes = bytes.clone();
    glib::MainContext::default().spawn_local(async move {
        let ok = gio::spawn_blocking(move || {
            let mut child = match Command::new("pkexec")
                .args(["guardctl", "privileged", "apply-config"])
                .stdin(Stdio::piped())
                .spawn()
            {
                Ok(c) => c,
                Err(_) => return false,
            };
            if let Some(mut stdin) = child.stdin.take() {
                let _ = std::io::Write::write_all(&mut stdin, &write_bytes);
            }
            child.wait().map(|s| s.success()).unwrap_or(false)
        })
        .await
        .unwrap_or(false);
        button.set_sensitive(true);
        if !ok {
            button.set_tooltip_text(Some(
                "Apply failed; previous configuration was restored when possible.",
            ));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_configuration_preserves_ssh_enrollment_for_the_ui() {
        let config = configuration_from_daemon(guard_ipc::ConfigurationInfo {
            enforcement_mode: "strict-filesystem".into(),
            browsers: vec![guard_ipc::ConfiguredBrowserInfo {
                id: "firefox".into(),
                family: "Firefox".into(),
                profile_root: "/home/test/.mozilla/firefox".into(),
                owner_uid: None,
                exe_paths: vec!["/usr/lib/firefox/firefox".into()],
            }],
            enrolled_exes: vec!["/usr/bin/known-good-helper".into()],
            ssh_keys: vec!["/home/test/.ssh/id_ed25519".into()],
            ssh_behavior_window_secs: 30,
        })
        .expect("supported daemon snapshot");
        assert_eq!(
            config.enforcement_mode,
            guard_platform::config::EnforcementMode::StrictFilesystem
        );
        assert_eq!(
            config.ssh_keys,
            vec![PathBuf::from("/home/test/.ssh/id_ed25519")]
        );
        assert_eq!(config.browsers[0].owner_uid, None);
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
        let mut status = guard_ipc::StatusInfo {
            version: "x".into(),
            enforcement_active: true,
            status: "ACTIVE".into(),
            mode: "strict-filesystem".into(),
            marked_filesystems: 1,
            required_filesystems: 1,
            filesystem_marks_healthy: true,
            strict_events_total: 0,
            strict_fast_allowed: 0,
            protected_events: 0,
            fanotify_overflows: 0,
            classifier_failures: 0,
            strict_alias_scans: 0,
            strict_alias_matches: 0,
            topology_degraded: false,
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
            ssh_behavior_status: "UNAVAILABLE".into(),
            ssh_behavior_detail: None,
            ssh_behavior_active_incidents: 0,
            ssh_behavior_pending_decisions: 0,
            ssh_behavior_key_reads: 0,
            ssh_behavior_network_blocks: 0,
            ssh_behavior_user_allows: 0,
            ssh_behavior_quarantines: 0,
            ssh_behavior_backend_failures: 0,
        };
        status.ssh_behavior_detail =
            Some("loading BPF object: Invalid argument; verifier_log=R1=ctx() ...".into());
        assert_eq!(
            ssh_behavior_summary(&status),
            "Unavailable — key access is still allowed and reported, but immediate external network activity cannot currently be blocked"
        );
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
