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
const CONFIG: &str = "/etc/guardd/config.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Health {
    Active,
    Degraded,
    Stopped,
    Unreachable,
    NotConfigured,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceOrigin {
    NativeDetected,
    Custom,
}

#[derive(Clone)]
struct BrowserSource {
    config: platform_linux::config::BrowserEnrollmentConfig,
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
    configured: bool,
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
    if configured {
        Health::Stopped
    } else {
        Health::NotConfigured
    }
}

fn health_label(h: Health) -> &'static str {
    match h {
        Health::Active => "PROTECTED",
        Health::Degraded => "DEGRADED",
        Health::Stopped => "STOPPED / OFF",
        Health::Unreachable => "UNREACHABLE",
        Health::NotConfigured => "NOT CONFIGURED",
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

#[derive(Clone)]
struct UiState {
    candidate: Rc<RefCell<Option<platform_linux::config::EnforcementConfig>>>,
    persisted: Rc<RefCell<Option<platform_linux::config::EnforcementConfig>>>,
    status: gtk::Label,
    detail: gtk::Label,
    apply: gtk::Button,
    mode: gtk::ComboBoxText,
    browsers: gtk::ListBox,
    keys: gtk::ListBox,
    events: gtk::ListBox,
    event_data: Rc<RefCell<Vec<guard_ipc::EventInfo>>>,
    browser_sources: Rc<RefCell<Vec<BrowserSource>>>,
    custom_browser_sources: Rc<RefCell<Vec<platform_linux::config::BrowserEnrollmentConfig>>>,
    ssh_sources: Rc<RefCell<Vec<SshSource>>>,
    custom_ssh_sources: Rc<RefCell<HashSet<PathBuf>>>,
    poll_in_flight: Rc<Cell<bool>>,
    protection: Rc<RefCell<Option<adw::SwitchRow>>>,
    protection_syncing: Rc<Cell<bool>>,
    shown_incidents: Rc<RefCell<HashSet<String>>>,
    shown_migrations: Rc<RefCell<HashSet<String>>>,
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
        persisted: Rc::new(RefCell::new(None)),
        status: status.clone(),
        detail: detail.clone(),
        apply: apply.clone(),
        mode: mode.clone(),
        browsers: browsers.clone(),
        keys: keys.clone(),
        events: events.clone(),
        event_data: Rc::new(RefCell::new(Vec::new())),
        browser_sources: Rc::new(RefCell::new(Vec::new())),
        custom_browser_sources: Rc::new(RefCell::new(Vec::new())),
        ssh_sources: Rc::new(RefCell::new(Vec::new())),
        custom_ssh_sources: Rc::new(RefCell::new(HashSet::new())),
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
                platform_linux::config::EnforcementMode::StrictFilesystem
            } else {
                platform_linux::config::EnforcementMode::Conservative
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
    let persisted = state.persisted.clone();
    let apply_btn = state.apply.clone();
    let render_state = state.clone();
    discard.connect_clicked(move |_| {
        *cand.borrow_mut() = persisted.borrow().clone();
        apply_btn.set_sensitive(false);
        let cfg = render_state.candidate.borrow().clone();
        if let Some(cfg) = cfg.as_ref() {
            render_objects(&render_state, cfg);
        }
    });
    let cand = state.candidate.clone();
    let persisted = state.persisted.clone();
    let apply_btn = state.apply.clone();
    state.apply.connect_clicked(move |_| {
        if let Some(cfg) = cand.borrow().clone() {
            if let Ok(bytes) = serde_json::to_vec(&cfg) {
                apply_btn.set_sensitive(false);
                spawn_apply(bytes, apply_btn.clone(), persisted.clone());
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
    let parsed = std::fs::read(CONFIG).ok().and_then(|bytes| {
        serde_json::from_slice::<platform_linux::config::EnforcementConfig>(&bytes).ok()
    });
    *state.persisted.borrow_mut() = parsed.clone();
    *state.candidate.borrow_mut() = parsed.clone();
    if let Some(cfg) = parsed {
        state
            .mode
            .set_active_id(Some(cfg.enforcement_mode.as_str()));
    } else {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/nonexistent"));
        let found = platform_linux::config::discover_native_browsers(&home);
        let cfg = platform_linux::config::EnforcementConfig {
            enforcement_mode: platform_linux::config::EnforcementMode::StrictFilesystem,
            browsers: found
                .browsers
                .into_iter()
                .map(|b| platform_linux::config::BrowserEnrollmentConfig {
                    id: b.id,
                    family: b.family,
                    profile_root: b.profile_root,
                    owner_uid: None,
                    exe_paths: b.exe_paths,
                })
                .collect(),
            enrolled_exes: Vec::new(),
            ssh_keys: Vec::new(),
            ssh_behavior_window_secs: guard_core::DEFAULT_SSH_BEHAVIOR_WINDOW_SECS,
        };
        if cfg.browsers.is_empty() {
            state.detail.set_text("No supported native browser was detected. Add a reviewed custom configuration or install a native browser.");
        } else {
            state.detail.set_text("First run: native browser suggestions are staged for review. SSH keys remain unselected.");
        }
        *state.candidate.borrow_mut() = Some(cfg.clone());
        state.mode.set_active_id(Some("strict-filesystem"));
        state.apply.set_sensitive(!cfg.browsers.is_empty());
    }
    refresh_browser_sources(state);
}

fn refresh_browser_sources(state: &UiState) {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/nonexistent"));
    let discovered = platform_linux::config::discover_native_browsers(&home);
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
    let custom_browser_sources = state.custom_browser_sources.borrow().clone();
    let mut sources = discovered;
    for browser in configured {
        let explicitly_custom = custom_browser_sources
            .iter()
            .any(|custom| same_native_browser(custom, &browser));
        if explicitly_custom {
            if let Some(source) = sources
                .iter_mut()
                .find(|source| same_browser_source(&source.config, &browser))
            {
                source.origin = SourceOrigin::Custom;
            } else {
                sources.push(BrowserSource {
                    config: browser,
                    origin: SourceOrigin::Custom,
                });
            }
        } else if !sources.iter().any(|source| {
            source.origin == SourceOrigin::NativeDetected
                && same_native_browser(&source.config, &browser)
        }) {
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
    let custom_ssh_sources = state.custom_ssh_sources.borrow().clone();
    let mut sources = suggestions;
    for key in configured {
        if let Some(source) = sources.iter_mut().find(|source| source.path == key) {
            if custom_ssh_sources.contains(&key) {
                source.origin = SourceOrigin::Custom;
            }
        } else {
            sources.push(SshSource {
                path: key,
                origin: SourceOrigin::Custom,
            });
        }
    }
    sources.sort_by(|left, right| left.path.cmp(&right.path));
    *state.ssh_sources.borrow_mut() = sources;
}

fn browser_source_is_present(browser: &platform_linux::config::BrowserEnrollmentConfig) -> bool {
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
    suggestion: platform_linux::config::BrowserSuggestion,
) -> platform_linux::config::BrowserEnrollmentConfig {
    platform_linux::config::BrowserEnrollmentConfig {
        id: suggestion.id,
        family: suggestion.family,
        profile_root: suggestion.profile_root,
        owner_uid: None,
        exe_paths: suggestion.exe_paths,
    }
}

fn same_browser_source(
    left: &platform_linux::config::BrowserEnrollmentConfig,
    right: &platform_linux::config::BrowserEnrollmentConfig,
) -> bool {
    left.id == right.id && left.profile_root == right.profile_root
}

fn same_native_browser(
    left: &platform_linux::config::BrowserEnrollmentConfig,
    right: &platform_linux::config::BrowserEnrollmentConfig,
) -> bool {
    same_browser_source(left, right)
        && left.family == right.family
        && left.exe_paths == right.exe_paths
}

fn render_objects(state: &UiState, cfg: &platform_linux::config::EnforcementConfig) {
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
            platform_linux::config::family_name(browser.family),
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
            let source_state = state.browser_sources.clone();
            let custom_sources = state.custom_browser_sources.clone();
            let browser_copy = browser.clone();
            remove.connect_clicked(move |_| {
                if let Some(cfg) = candidate.borrow_mut().as_mut() {
                    cfg.browsers
                        .retain(|configured| !same_browser_source(configured, &browser_copy));
                    apply.set_sensitive(true);
                }
                source_state
                    .borrow_mut()
                    .retain(|source| !same_browser_source(&source.config, &browser_copy));
                custom_sources
                    .borrow_mut()
                    .retain(|source| !same_native_browser(source, &browser_copy));
                if let Some(cfg) = render_state.candidate.borrow().as_ref() {
                    render_objects(&render_state, cfg);
                }
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
        let enrolled = cfg.ssh_keys.contains(&key);
        let row = adw::SwitchRow::new();
        row.set_title(&key.to_string_lossy());
        row.set_subtitle(if enrolled {
            "Configured"
        } else {
            "Detected — not protected"
        });
        row.set_active(enrolled);
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
        if enrolled && source.origin == SourceOrigin::Custom {
            let remove = remove_button("Remove SSH key protection");
            let candidate = state.candidate.clone();
            let apply = state.apply.clone();
            let render_state = state.clone();
            let source_state = state.ssh_sources.clone();
            let custom_sources = state.custom_ssh_sources.clone();
            let key_path = key.clone();
            remove.connect_clicked(move |_| {
                if let Some(cfg) = candidate.borrow_mut().as_mut() {
                    cfg.ssh_keys.retain(|configured| configured != &key_path);
                    apply.set_sensitive(true);
                }
                source_state
                    .borrow_mut()
                    .retain(|source| source.path != key_path);
                custom_sources.borrow_mut().remove(&key_path);
                if let Some(cfg) = render_state.candidate.borrow().as_ref() {
                    render_objects(&render_state, cfg);
                }
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
    let custom_sources = state.custom_ssh_sources.clone();
    let render_state = state.clone();
    dialog.connect_response(move |dialog, response| {
        if response == gtk::ResponseType::Accept {
            if let Some(path) = dialog.file().and_then(|file| file.path()) {
                custom_sources.borrow_mut().insert(path.clone());
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

    let source_state = state.browser_sources.clone();
    let custom_sources = state.custom_browser_sources.clone();
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
                custom_sources.borrow_mut().push(browser.clone());
                if let Some(cfg) = candidate.borrow_mut().as_mut() {
                    if !cfg
                        .browsers
                        .iter()
                        .any(|configured| same_browser_source(configured, &browser))
                    {
                        cfg.browsers.push(browser.clone());
                    }
                }
                if !source_state
                    .borrow()
                    .iter()
                    .any(|source| same_browser_source(&source.config, &browser))
                {
                    source_state.borrow_mut().push(BrowserSource {
                        config: browser,
                        origin: SourceOrigin::Custom,
                    });
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
) -> Result<platform_linux::config::BrowserEnrollmentConfig, String> {
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
    Ok(platform_linux::config::BrowserEnrollmentConfig {
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
    let configured = state.persisted.borrow().is_some();
    let status = state.status.clone();
    let detail = state.detail.clone();
    let events = state.events.clone();
    let event_data = state.event_data.clone();
    let poll_in_flight = state.poll_in_flight.clone();
    let protection = state.protection.clone();
    let protection_syncing = state.protection_syncing.clone();
    let shown_incidents = state.shown_incidents.clone();
    let shown_migrations = state.shown_migrations.clone();
    let window = window.clone();
    let after_id = event_data.borrow().first().map(|event| event.id);
    glib::MainContext::default().spawn_local(async move {
        let result = gio::spawn_blocking(move || {
            let daemon = guard_client::status(&socket).ok();
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
            let service_active = Command::new("systemctl").args(["is-active", "--quiet", "guardd.service"]).status().map(|s| s.success()).unwrap_or(false);
            let notification_active = Command::new("systemctl")
                .args(["--user", "is-active", "--quiet", "guard-notify.service"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            (service_active, notification_active, daemon, recent_events, pending_incidents, pending_migrations)
        }).await;
        if let Ok((service_active, notification_active, daemon, recent_events, pending_incidents, pending_migrations)) = result {
            let health = health_from_evidence(
                service_active,
                notification_active,
                daemon.as_ref(),
                configured,
            );
            status.set_text(health_label(health));
            // The switch represents the actual systemd service bundle.  Keep it
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
            for migration in pending_migrations {
                if shown_migrations.borrow_mut().insert(migration.id.clone()) {
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

fn present_migration_dialog(
    window: &adw::ApplicationWindow,
    migration: guard_ipc::MigrationPendingInfo,
) {
    let source = browser_label(&migration.source_browser);
    let target = browser_label(&migration.target_browser);
    let dialog = gtk::MessageDialog::builder()
        .transient_for(window)
        .modal(true)
        .message_type(gtk::MessageType::Warning)
        .text("Browser data import detected")
        .secondary_text(format!(
            "{target} is trying to access protected {source} data.\n\nAre you importing data from {source} into {target}?\n\nSource browser: {source}\nSource profile: {}\nTarget browser: {target}\nTarget process: {}\nPID: {}\nRequested data: {}",
            migration.source_profile,
            migration.target_exe,
            migration.target_pid,
            migration.requested_data,
        ))
        .build();
    let block = dialog.add_button("No, block", gtk::ResponseType::Reject);
    block.add_css_class("destructive-action");
    let allow = dialog.add_button("Yes, allow this import", gtk::ResponseType::Accept);
    allow.add_css_class("suggested-action");
    let resolved = Rc::new(Cell::new(false));
    let resolve = {
        let id = migration.id.clone();
        let resolved = resolved.clone();
        move |action: guard_ipc::MigrationResolutionAction| {
            if resolved.replace(true) {
                return;
            }
            let socket = PathBuf::from(SOCKET);
            let id = id.clone();
            glib::MainContext::default().spawn_local(async move {
                let _ = gio::spawn_blocking(move || {
                    guard_client::resolve_migration(&socket, &id, action)
                })
                .await;
            });
        }
    };
    let resolve_response = resolve.clone();
    dialog.connect_response(move |dialog, response| {
        let action = if response == gtk::ResponseType::Accept {
            guard_ipc::MigrationResolutionAction::AllowImport
        } else {
            guard_ipc::MigrationResolutionAction::Block
        };
        resolve_response(action);
        dialog.close();
    });
    dialog.connect_close_request(move |_| {
        resolve(guard_ipc::MigrationResolutionAction::Block);
        glib::Propagation::Proceed
    });
    dialog.present();
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
    Command::new("pkexec")
        .args(["guardctl", "privileged", "service", verb])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_notification_service(verb: &str) -> bool {
    Command::new("systemctl")
        .args(["--user", verb, "guard-notify.service"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
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

fn spawn_apply(
    bytes: Vec<u8>,
    button: gtk::Button,
    persisted: Rc<RefCell<Option<platform_linux::config::EnforcementConfig>>>,
) {
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
        if ok {
            if let Ok(cfg) = serde_json::from_slice(&bytes) {
                *persisted.borrow_mut() = Some(cfg);
            }
        } else {
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
            health_from_evidence(true, true, Some(&status), true),
            Health::Active
        );
        assert_eq!(
            health_from_evidence(true, true, Some(&status), false),
            Health::Active
        );
        assert_eq!(
            health_from_evidence(true, false, Some(&status), true),
            Health::Degraded
        );
        assert_eq!(
            health_from_evidence(false, false, Some(&status), true),
            Health::Stopped
        );
        assert_eq!(
            health_from_evidence(true, true, None, true),
            Health::Unreachable
        );
    }
}
