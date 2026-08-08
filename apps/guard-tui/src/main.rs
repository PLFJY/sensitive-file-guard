//! `guard-tui` — terminal UI for Sensitive Data Firewall (Phase 09).
//!
//! A pure IPC client over `guardd`'s Unix-socket protocol. It contains no
//! independent policy engine. The interface polls `status` / `events` /
//! `leases` / `browsers` on a refresh timer and renders:
//! - daemon status (enforcement active, protected counts, decision totals)
//! - recent blocked events (newest first)
//! - active leases (own only, unless root)
//! - a help/action line
//!
//! Actions (no separate policy logic — all enforced by the daemon):
//! - `a` authorize a migration lease (prompts for source/profile/target)
//! - `x` revoke a lease by id (prompts for id)
//! - `r` refresh now; `q` quit
//!
//! If the daemon socket is unreachable, the TUI shows the connection error in
//! the status panel and keeps retrying on the refresh timer — it never crashes.

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use crossterm::cursor::Hide;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Terminal;

use guard_tui::client;

#[derive(Debug, Clone, PartialEq, Eq)]
enum InputMode {
    Normal,
    /// Prompting for migration authorize fields: source, profile, target.
    Authorize {
        field: usize,
        source: String,
        profile: String,
        target: String,
    },
    /// Prompting for a lease id to revoke.
    Revoke {
        id: String,
    },
}

struct App {
    socket: PathBuf,
    status: Option<guard_ipc::StatusInfo>,
    events: Vec<guard_ipc::EventInfo>,
    leases: Vec<guard_ipc::LeaseInfo>,
    browsers: Vec<guard_ipc::BrowserInfo>,
    last_error: Option<String>,
    mode: InputMode,
    toast: Option<String>,
}

impl App {
    fn new(socket: PathBuf) -> Self {
        Self {
            socket,
            status: None,
            events: Vec::new(),
            leases: Vec::new(),
            browsers: Vec::new(),
            last_error: None,
            mode: InputMode::Normal,
            toast: None,
        }
    }

    fn refresh(&mut self) {
        let results = (
            client::status(&self.socket),
            client::events(&self.socket, Some(50)),
            client::leases(&self.socket),
            client::browsers(&self.socket),
        );
        match results {
            (Ok(s), Ok(e), Ok(l), Ok(b)) => {
                self.status = Some(s);
                self.events = e;
                self.leases = l;
                self.browsers = b;
                self.last_error = None;
            }
            (status_res, events_res, leases_res, browsers_res) => {
                // Prefer the first error message; keep stale data on screen.
                let err = status_res
                    .err()
                    .or_else(|| events_res.err())
                    .or_else(|| leases_res.err())
                    .or_else(|| browsers_res.err())
                    .map(|e| e.to_string());
                self.last_error = err;
            }
        }
    }

    fn do_authorize(&mut self) {
        let source = self.mode_field(0).to_string();
        let profile = self.mode_field(1).to_string();
        let target = self.mode_field(2).to_string();
        match client::migration_authorize(&self.socket, &source, &profile, &target, None) {
            Ok(m) => {
                self.toast = Some(format!(
                    "Authorized lease {} ({} -> {}), expires {}",
                    m.lease_id, m.source_browser, m.target_browser, m.expires_at
                ));
                self.refresh();
            }
            Err(e) => self.toast = Some(format!("authorize failed: {e}")),
        }
        self.mode = InputMode::Normal;
    }

    fn do_revoke(&mut self) {
        let id = match &self.mode {
            InputMode::Revoke { id } => id.clone(),
            _ => return,
        };
        match client::lease_revoke(&self.socket, &id) {
            Ok((lease_id, found)) => {
                self.toast = Some(format!("revoked lease {lease_id} (found={found})"));
                self.refresh();
            }
            Err(e) => self.toast = Some(format!("revoke failed: {e}")),
        }
        self.mode = InputMode::Normal;
    }

    fn mode_field(&self, idx: usize) -> &str {
        match &self.mode {
            InputMode::Authorize {
                source,
                profile,
                target,
                ..
            } => match idx {
                0 => source,
                1 => profile,
                2 => target,
                _ => "",
            },
            InputMode::Revoke { id } => id,
            _ => "",
        }
    }

    fn push_char(&mut self, c: char) {
        match &mut self.mode {
            InputMode::Authorize {
                field,
                source,
                profile,
                target,
            } => match *field {
                0 => source.push(c),
                1 => profile.push(c),
                2 => target.push(c),
                _ => {}
            },
            InputMode::Revoke { id } => id.push(c),
            _ => {}
        }
    }

    fn backspace(&mut self) {
        match &mut self.mode {
            InputMode::Authorize {
                field,
                source,
                profile,
                target,
            } => match *field {
                0 => {
                    source.pop();
                }
                1 => {
                    profile.pop();
                }
                2 => {
                    target.pop();
                }
                _ => {}
            },
            InputMode::Revoke { id } => {
                id.pop();
            }
            _ => {}
        }
    }

    fn advance_or_finish(&mut self) {
        if let InputMode::Authorize { field, .. } = &mut self.mode {
            if *field < 2 {
                *field += 1;
            } else {
                self.do_authorize();
            }
        } else if matches!(self.mode, InputMode::Revoke { .. }) {
            self.do_revoke();
        }
    }
}

fn main() -> anyhow::Result<()> {
    let socket = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/run/guardd/guardd.sock".to_string());
    let socket = PathBuf::from(socket);

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, Hide)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(socket);
    app.refresh();

    let result = run_loop(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> anyhow::Result<()> {
    let poll_refresh = Duration::from_secs(2);
    loop {
        terminal.draw(|f| draw(f, app))?;

        // Block up to `poll_refresh` for a key; on timeout, auto-refresh.
        if event::poll(poll_refresh)? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match &mut app.mode {
                    InputMode::Normal => match key.code {
                        KeyCode::Char('q') => return Ok(()),
                        KeyCode::Char('r') => app.refresh(),
                        KeyCode::Char('a') => {
                            app.mode = InputMode::Authorize {
                                field: 0,
                                source: String::new(),
                                profile: String::new(),
                                target: String::new(),
                            };
                            app.toast = None;
                        }
                        KeyCode::Char('x') => {
                            app.mode = InputMode::Revoke { id: String::new() };
                            app.toast = None;
                        }
                        _ => {}
                    },
                    InputMode::Authorize { .. } | InputMode::Revoke { .. } => match key.code {
                        KeyCode::Esc => app.mode = InputMode::Normal,
                        KeyCode::Enter => app.advance_or_finish(),
                        KeyCode::Backspace => app.backspace(),
                        KeyCode::Tab => {
                            if let InputMode::Authorize { field, .. } = &mut app.mode {
                                if *field < 2 {
                                    *field += 1;
                                }
                            }
                        }
                        KeyCode::Char(c) => app.push_char(c),
                        _ => {}
                    },
                }
            }
        } else {
            // No key within the window: auto-refresh.
            app.refresh();
        }
    }
}

fn draw(f: &mut ratatui::Frame<'_>, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(8),
                Constraint::Min(8),
                Constraint::Length(6),
                Constraint::Length(3),
            ]
            .as_ref(),
        )
        .split(f.area());

    draw_status(f, app, chunks[0]);
    draw_events(f, app, chunks[1]);
    draw_leases(f, app, chunks[2]);
    draw_footer(f, app, chunks[3]);
}

fn draw_status(f: &mut ratatui::Frame<'_>, app: &App, area: ratatui::layout::Rect) {
    let block = Block::default().borders(Borders::ALL).title(Span::styled(
        "guard-tui — daemon status",
        Style::default().add_modifier(Modifier::BOLD),
    ));
    let lines = match (&app.status, &app.last_error) {
        (Some(s), None) => vec![
            Line::from(vec![
                Span::raw("enforcement: "),
                Span::styled(
                    s.status.as_str(),
                    Style::default().fg(match s.status.as_str() {
                        "ACTIVE" => Color::Green,
                        "DEGRADED" => Color::Yellow,
                        _ => Color::Red,
                    }),
                ),
                Span::raw(format!(
                    "   peer_uid={}   protected_files={}   trees={}   browsers={}   exes={}",
                    s.peer_uid, s.protected_files, s.protected_trees, s.browsers, s.browser_exes
                )),
            ]),
            Line::from(format!(
                "decisions: allowed={} denied={} unclassified={} audit_dropped={}",
                s.allowed, s.denied, s.unclassified, s.audit_dropped
            )),
            Line::from(format!("enrolled browsers: {}", browser_names(app))),
        ],
        _ => vec![Line::from(format!(
            "no daemon status{}",
            app.last_error
                .as_deref()
                .map(|e| format!(" — {e}"))
                .unwrap_or_default()
        ))],
    };
    let p = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

fn browser_names(app: &App) -> String {
    if app.browsers.is_empty() {
        return "(none)".into();
    }
    app.browsers
        .iter()
        .map(|b| b.id.clone())
        .collect::<Vec<_>>()
        .join(", ")
}

fn draw_events(f: &mut ratatui::Frame<'_>, app: &App, area: ratatui::layout::Rect) {
    let block = Block::default().borders(Borders::ALL).title(Span::styled(
        "recent blocked events (newest first)",
        Style::default().add_modifier(Modifier::BOLD),
    ));
    let items: Vec<ListItem> = app
        .events
        .iter()
        .filter(|e| e.decision == "deny")
        .take(area.height.saturating_sub(2) as usize)
        .map(|e| {
            let reason = e.deny_reason.clone().unwrap_or_else(|| "?".into());
            let exe = std::path::Path::new(&e.exe)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| e.exe.clone());
            ListItem::new(Line::from(vec![
                Span::styled(format!("#{} ", e.id), Style::default().fg(Color::DarkGray)),
                Span::styled(
                    "DENY ",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("{} pid={} uid={} {}", reason, e.pid, e.uid, exe)),
                Span::styled(
                    format!("  [{}]", short_kind(&e.resource_kind)),
                    Style::default().fg(Color::Cyan),
                ),
            ]))
        })
        .collect();
    let list = List::new(items).block(block);
    f.render_widget(list, area);
}

fn short_kind(k: &str) -> &str {
    match k {
        "cookie_store" => "cookies",
        "session_store" => "session",
        "browser_key_material" => "keys",
        "web_storage" => "webstorage",
        "saved_credentials" => "logins",
        "history" => "history",
        "ssh_private_key" => "sshkey",
        _ => "?",
    }
}

fn draw_leases(f: &mut ratatui::Frame<'_>, app: &App, area: ratatui::layout::Rect) {
    let block = Block::default().borders(Borders::ALL).title(Span::styled(
        "active leases",
        Style::default().add_modifier(Modifier::BOLD),
    ));
    let items: Vec<ListItem> = if app.leases.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "(no active leases)",
            Style::default().fg(Color::DarkGray),
        )))]
    } else {
        app.leases
            .iter()
            .map(|l| {
                let desc = match l.kind.as_str() {
                    "migration" => format!(
                        "migration id={} {} -> {} ({}), expires={}, revoked={}",
                        l.id,
                        l.source_browser.as_deref().unwrap_or("?"),
                        l.target_browser.as_deref().unwrap_or("?"),
                        l.source_profile.as_deref().unwrap_or("?"),
                        l.expires_at,
                        l.revoked,
                    ),
                    "ssh" => format!(
                        "ssh id={} resource={} expires={}",
                        l.id,
                        l.resource.as_deref().unwrap_or("?"),
                        l.expires_at,
                    ),
                    _ => format!("{} id={} expires={}", l.kind, l.id, l.expires_at),
                };
                let style = if l.revoked {
                    Style::default()
                        .fg(Color::DarkGray)
                        .add_modifier(Modifier::DIM)
                } else {
                    Style::default().fg(Color::Green)
                };
                ListItem::new(Line::from(Span::styled(desc, style)))
            })
            .collect()
    };
    let list = List::new(items).block(block);
    f.render_widget(list, area);
}

fn draw_footer(f: &mut ratatui::Frame<'_>, app: &App, area: ratatui::layout::Rect) {
    let block = Block::default().borders(Borders::ALL);
    let line = match &app.mode {
        InputMode::Normal => {
            let toast = app
                .toast
                .clone()
                .unwrap_or_else(|| "[a] authorize  [x] revoke  [r] refresh  [q] quit".into());
            Line::from(Span::raw(toast))
        }
        InputMode::Authorize {
            field,
            source,
            profile,
            target,
        } => {
            let labels = ["source", "profile", "target"];
            let vals = [source.as_str(), profile.as_str(), target.as_str()];
            let prompt = format!(
                "authorize: {}={}  (Tab next, Enter submit, Esc cancel)",
                labels[*field], vals[*field]
            );
            Line::from(Span::styled(prompt, Style::default().fg(Color::Yellow)))
        }
        InputMode::Revoke { id } => Line::from(Span::styled(
            format!("revoke lease id={id}  (Enter submit, Esc cancel)"),
            Style::default().fg(Color::Yellow),
        )),
    };
    let p = Paragraph::new(line).block(block);
    f.render_widget(p, area);
}
