//! `guard_tui` — terminal UI library for Sensitive Data Firewall.
//!
//! Phase 09: the TUI is a pure IPC client — it contains no independent policy
//! engine. This crate exposes the IPC client functions (`client`) so they can
//! be unit/integration-tested without a terminal, and the binary (`main.rs`)
//! drives a ratatui interface over them.

pub mod client;
