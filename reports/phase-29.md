# Phase 29 — prevent interactive SSH approval deadlock

## Root cause and correction

The SSH-read resolver matched directly on
`engine.lock().approve_pending_ssh_read(...)` and reacquired the same mutex in
both match arms to build audit metadata. Rust keeps a significant temporary in
a match scrutinee alive through the complete match, so the second acquisition
deadlocked the IPC thread immediately after Polkit accepted the password. The
fanotify loop then blocked on the same engine mutex and stopped answering later
permission events, producing a system-wide filesystem stall in strict mode.

The approval result is now materialized before the match so the mutex guard is
dropped at the statement boundary. The coalesced browser-migration sibling path
had the same pattern and was corrected at the same time. Guardd now denies the
Clippy `significant_drop_in_scrutinee` lint so either pattern fails the quality
gate if reintroduced.

## Regression coverage

- Replaced the obsolete, permanently disabled IPC test module with active tests
  for SSH approval lock release, metadata-only allow/block audit records,
  Polkit detail arguments, and IPC-peer disconnect detection.
- Updated the privileged SSH enforcement script to use only an ephemeral key,
  wait for a real pending read, resolve Allow and Block over local IPC under a
  five-second deadline, and verify that guardd remains responsive afterward.
- No IPC shape, Polkit action, lease duration, process-identity binding, or
  authorization behavior changed.

## Verification

- PASS — `cargo fmt --check`
- PASS — `cargo clippy --all-targets --all-features -- -D warnings`
- PASS — `cargo test --workspace --no-fail-fast` (including 58 active guardd
  tests; the three new IPC tests passed)
- BLOCKED — `sudo -n bash scripts/test-ssh-enforcement-root.sh` could not start
  in this environment: `sudo: a password is required`. The deterministic
  script is ready for a human to run with root and `CAP_SYS_ADMIN`; no
  privileged result is claimed.

No real browser profile or SSH key was read during verification.
