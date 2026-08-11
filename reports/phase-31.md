# Phase 31 — close transient confirmation UI after the queue drains

`guard-notify` now starts `guard-ui` with `--pending-only` when it opens the
interactive confirmation client. After a confirmed Allow finishes and releases
the active terminal prompt, the transient UI closes when no prompt remains in
the local queue. If another prompt is queued, the next dialog is shown as
before. A manually launched control-center session is not marked pending-only
and remains open.

The pending-dialog controller exposes the queue-empty state and includes a
regression test covering the final terminal prompt release. User-facing
behavior is documented in the README, browser migration model, and Linux
installation guide.

## Verification

- PASS — `cargo fmt --check`
- PASS — `cargo clippy --all-targets --all-features -- -D warnings`
- PASS — `cargo test -p guard-ui -p guard-notify`
- PASS — `cargo test --workspace --no-fail-fast`
- PASS — `git diff --check`
