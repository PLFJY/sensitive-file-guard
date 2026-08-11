# Phase 24 — UI active-policy snapshot

## Outcome

Fixed the GTK control center showing enrolled SSH keys as unprotected when the
desktop user cannot read `/etc/guardd/config.json` directly.

`guardd` now serves an authenticated, metadata-only configuration snapshot over
local IPC. It contains configuration paths and policy settings only; it never
contains SSH private-key bytes, browser database rows, cookies, passwords, or
session tokens. `guard-ui` always uses that snapshot rather than reading the
root-owned configuration file. Separately, every UI poll asks the daemon for its currently
enrolled SSH resources (for example, entries created with `guardctl ssh
protect`). The display state comes from that live response and is never copied
into the editable configuration model. The UI holds only an in-window draft;
Discard drops it and fetches the daemon state again. No GUI state file or
database is created.

## Validation

```text
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
```
