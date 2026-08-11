# Phase 28 — keep IPC alive during Polkit authorization

## Root cause and fix

The GUI's typed IPC client used the same two-second read timeout for status
polls and interactive `MigrationResolve` / `SshReadResolve` requests. When
Polkit waited for a password, the client timed out and closed its socket;
guardd correctly observed the disconnect and cancelled `pkcheck`.

Interactive migration authorization, migration resolution, and SSH-read
resolution now keep the IPC read open. Guardd retains the authoritative
120-second deadline and its PID/start-token/socket liveness checks. Normal
status and polling calls remain bounded to two seconds.

## Verification

- `cargo fmt --check`
- `cargo test -p guard-client -p guard-ui --no-fail-fast`
- `cargo clippy -p guard-client -p guard-ui --all-targets --all-features -- -D warnings`

All completed successfully. Live Polkit acceptance requires the desktop
environment and was not claimed as automated coverage.
