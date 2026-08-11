# Phase 24 — UI active-policy snapshot

## Outcome

Fixed the GTK control center showing enrolled SSH keys as unprotected when the
desktop user cannot read `/etc/guardd/config.json` directly.

`guardd` now serves an authenticated, metadata-only configuration snapshot over
local IPC. It contains configuration paths and policy settings only; it never
contains SSH private-key bytes, browser database rows, cookies, passwords, or
session tokens. `guard-ui` uses that snapshot only when the local config file
is unreadable, and preserves it as the base configuration for later edits.

## Validation

```text
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
```
