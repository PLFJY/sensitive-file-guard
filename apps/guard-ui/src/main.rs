//! Native GTK control center.  This process is deliberately only a client:
//! policy decisions and privileged writes remain in guardd/guardctl.

use std::cell::RefCell;
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

fn health_from_evidence(
    service_active: bool,
    daemon: Option<&guard_ipc::StatusInfo>,
    configured: bool,
) -> Health {
    if !configured {
        return Health::NotConfigured;
    }
    if !service_active {
        return Health::Stopped;
    }
    match daemon.map(|s| s.status.as_str()) {
        Some("ACTIVE") => Health::Active,
        Some("DEGRADED") | Some("NOT_ENFORCING") => Health::Degraded,
        _ => Health::Unreachable,
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
}

fn main() {
    adw::init().expect("libadwaita initialization");
    let app = adw::Application::new(Some(APP_ID), gio::ApplicationFlags::empty());
    app.connect_activate(build_ui);
    app.run();
}

fn build_ui(app: &adw::Application) {
    let status = gtk::Label::new(Some("Connecting to guardd…"));
    status.add_css_class("title-3");
    let detail = gtk::Label::new(Some(
        "Live service and daemon health are required for a green state.",
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
    };
    let overview = overview_page(&state);
    let protection = protection_page(&state);
    let log = log_page(&state);
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
    let split = gtk::Paned::new(gtk::Orientation::Horizontal);
    split.set_start_child(Some(&nav));
    split.set_end_child(Some(&stack));
    let window = adw::ApplicationWindow::new(app);
    window.set_title(Some("Sensitive File Guard"));
    window.set_default_size(980, 680);
    window.set_content(Some(&split));
    window.present();

    load_configuration(&state);
    start_polling(state);
}

fn overview_page(state: &UiState) -> gtk::Box {
    let page = gtk::Box::new(gtk::Orientation::Vertical, 18);
    page.set_margin_top(24);
    page.set_margin_bottom(24);
    page.set_margin_start(24);
    page.set_margin_end(24);
    page.append(&state.status);
    page.append(&state.detail);
    let switch = gtk::Switch::new();
    switch.set_active(false);
    let row = adw::ActionRow::new();
    row.set_title("Protection");
    row.set_subtitle("Turning protection off makes protected files accessible normally.");
    row.add_suffix(&switch);
    row.set_activatable_widget(Some(&switch));
    let start_switch = switch.clone();
    switch.connect_state_set(move |_, on| {
        let verb = if on { "start" } else { "stop" };
        start_switch.set_sensitive(false);
        spawn_privileged_service(verb.to_owned(), start_switch.clone());
        false.into()
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
    page.append(&state.browsers);
    let keys_heading = gtk::Label::new(Some("SSH private keys"));
    keys_heading.set_xalign(0.0);
    keys_heading.add_css_class("title-2");
    page.append(&keys_heading);
    page.append(&state.keys);
    let actions = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    actions.append(&state.apply);
    let discard = gtk::Button::with_label("Discard");
    actions.append(&discard);
    page.append(&actions);
    let cand = state.candidate.clone();
    let persisted = state.persisted.clone();
    let apply_btn = state.apply.clone();
    discard.connect_clicked(move |_| {
        *cand.borrow_mut() = persisted.borrow().clone();
        apply_btn.set_sensitive(false);
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
        render_objects(state, &cfg);
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
        };
        if cfg.browsers.is_empty() {
            state.detail.set_text("No supported native browser was detected. Add a reviewed custom configuration or install a native browser.");
        } else {
            state.detail.set_text("First run: native browser suggestions are staged for review. SSH keys remain unselected.");
        }
        *state.candidate.borrow_mut() = Some(cfg.clone());
        state.mode.set_active_id(Some("strict-filesystem"));
        render_objects(state, &cfg);
        state.apply.set_sensitive(!cfg.browsers.is_empty());
    }
}

fn render_objects(state: &UiState, cfg: &platform_linux::config::EnforcementConfig) {
    while let Some(child) = state.browsers.first_child() {
        state.browsers.remove(&child);
    }
    for browser in &cfg.browsers {
        let row = adw::ActionRow::new();
        row.set_title(&browser.id);
        row.set_subtitle(&format!(
            "{} · {}",
            platform_linux::config::family_name(browser.family),
            browser.profile_root.display()
        ));
        let toggle = gtk::Switch::new();
        toggle.set_active(true);
        let candidate = state.candidate.clone();
        let apply = state.apply.clone();
        let browser_copy = browser.clone();
        toggle.connect_state_set(move |_, enabled| {
            if let Some(cfg) = candidate.borrow_mut().as_mut() {
                if enabled {
                    if !cfg.browsers.iter().any(|b| b.id == browser_copy.id) {
                        cfg.browsers.push(browser_copy.clone());
                    }
                } else {
                    cfg.browsers.retain(|b| b.id != browser_copy.id);
                }
                apply.set_sensitive(true);
            }
            false.into()
        });
        row.add_suffix(&toggle);
        state.browsers.append(&row);
    }
    while let Some(child) = state.keys.first_child() {
        state.keys.remove(&child);
    }
    for key in &cfg.ssh_keys {
        let row = adw::ActionRow::new();
        row.set_title(&key.to_string_lossy());
        row.add_prefix(&gtk::Image::from_icon_name("emblem-ok-symbolic"));
        state.keys.append(&row);
    }
    let add = gtk::Button::with_label("Add Key…");
    let candidate = state.candidate.clone();
    let apply = state.apply.clone();
    add.connect_clicked(move |_| {
        let dialog = gtk::FileChooserNative::new(
            Some("Select an SSH private key"),
            None::<&gtk::Window>,
            gtk::FileChooserAction::Open,
            Some("Add"),
            Some("Cancel"),
        );
        let candidate = candidate.clone();
        let apply = apply.clone();
        dialog.connect_response(move |dialog, response| {
            if response == gtk::ResponseType::Accept {
                if let Some(path) = dialog.file().and_then(|f| f.path()) {
                    if let Some(cfg) = candidate.borrow_mut().as_mut() {
                        if !cfg.ssh_keys.contains(&path) {
                            cfg.ssh_keys.push(path);
                            apply.set_sensitive(true);
                        }
                    }
                }
            }
            dialog.destroy();
        });
        dialog.show();
    });
    state.keys.append(&add);
}

fn start_polling(state: UiState) {
    let state = Rc::new(state);
    let poll_state = state.clone();
    glib::timeout_add_seconds_local(2, move || {
        refresh_state(&poll_state);
        glib::ControlFlow::Continue
    });
    refresh_state(&state);
}

fn refresh_state(state: &UiState) {
    let socket = PathBuf::from(SOCKET);
    let configured = state.persisted.borrow().is_some();
    let status = state.status.clone();
    let detail = state.detail.clone();
    let events = state.events.clone();
    let event_data = state.event_data.clone();
    let after_id = event_data.borrow().first().map(|event| event.id);
    glib::MainContext::default().spawn_local(async move {
        let result = gio::spawn_blocking(move || {
            let daemon = guard_client::status(&socket).ok();
            let recent_events = guard_client::events_cursor(&socket, Some(100), None, after_id).unwrap_or_default();
            let service_active = Command::new("systemctl").args(["is-active", "--quiet", "guardd.service"]).status().map(|s| s.success()).unwrap_or(false);
            (service_active, daemon, recent_events)
        }).await;
        if let Ok((service_active, daemon, recent_events)) = result {
            let health = health_from_evidence(service_active, daemon.as_ref(), configured);
            status.set_text(health_label(health));
            detail.set_text(&daemon.map(|s| format!("Mode: {} · browsers: {} · SSH keys/resources: {} · allowed: {} · denied: {} · marks: {}/{}", s.mode, s.browsers, s.protected_files, s.allowed, s.denied, s.marked_filesystems, s.required_filesystems)).unwrap_or_else(|| "guardd IPC is unavailable; service state is shown separately.".into()));
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
                let decision = if event.decision == "Deny" { "BLOCKED" } else if event.decision == "AllowByLease" { "ALLOWED BY LEASE" } else { "ALLOWED" };
                let title = gtk::Label::new(Some(&format!("{}  ·  {}", decision, event.exe)));
                title.set_xalign(0.0); title.add_css_class(if decision == "BLOCKED" { "error" } else { "success" });
                let subtitle = gtk::Label::new(Some(&format!("#{} · {} · {}", event.id, event.resource_kind, event.path)));
                subtitle.set_xalign(0.0); subtitle.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
                box_.append(&title); box_.append(&subtitle); row.set_child(Some(&box_));
                if after_id.is_some() { events.insert(&row, 0); } else { events.append(&row); }
            }
        }
        let _ = events;
    });
}

fn spawn_privileged_service(verb: String, switch: gtk::Switch) {
    let requested_on = verb == "start";
    glib::MainContext::default().spawn_local(async move {
        let ok = gio::spawn_blocking(move || {
            Command::new("pkexec")
                .args(["guardctl", "privileged", "service", &verb])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        })
        .await
        .unwrap_or(false);
        switch.set_sensitive(true);
        switch.set_active(ok && requested_on);
    });
}

fn spawn_apply(bytes: Vec<u8>, button: gtk::Button) {
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
                let _ = std::io::Write::write_all(&mut stdin, &bytes);
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
    fn health_requires_live_evidence() {
        let status = guard_ipc::StatusInfo {
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
            health_from_evidence(true, Some(&status), true),
            Health::Active
        );
        assert_eq!(
            health_from_evidence(false, Some(&status), true),
            Health::Stopped
        );
        assert_eq!(health_from_evidence(true, None, true), Health::Unreachable);
    }
}
