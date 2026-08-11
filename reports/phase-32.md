# Phase 32 — remove the unused terminal UI

The standalone `guard-tui` crate, binary, integration tests, and its exclusive
`ratatui`/`crossterm` dependencies were removed. The workspace now exposes the
daemon, `guardctl`, `guard-ui`, and `guard-notify` client surfaces only.

Deployment and AUR packaging no longer build or install the terminal UI. The
installer and uninstaller remove an obsolete terminal UI binary left by older
releases. Current documentation, architecture notes, historical phase reports,
and the final acceptance report were updated to describe the remaining CLI,
GTK, and notification paths.

## Verification

- PASS — `cargo metadata --no-deps --format-version 1` (no `guard-tui` workspace member)
- PASS — `cargo fmt --check`
- PASS — `cargo clippy --all-targets --all-features -- -D warnings`
- PASS — `cargo test --workspace --no-fail-fast` (215 passed, 0 failed)
- PASS — `cargo build --release --workspace`
- PASS — `bash -n deploy/install.sh scripts/test-systemd-root.sh`
- PASS — `git diff --check`
- PASS — repository scan found no TUI product references outside the intentional
  obsolete-binary cleanup path in `deploy/install.sh`.
