# Phase 30 — shorten interactive SSH read leases

Ordinary SSH-read approval now creates a ten-second, memory-only lease instead
of a ten-minute lease. The lease remains bound to the exact protected key, UID,
verified reader process tree, and executable identity. Browser migration and
one-shot `ssh-agent` load lease durations are unchanged.

The GTK prompt and user/security documentation now state the ten-second window.
The active IPC regression test bounds the generated expiry to ten seconds from
approval so the duration cannot silently regress.

## Verification

- PASS — `cargo fmt --check`
- PASS — `cargo clippy --all-targets --all-features -- -D warnings`
- PASS — `cargo test --workspace --no-fail-fast` (including all 58 guardd
  tests and the ten-second expiry assertion)
