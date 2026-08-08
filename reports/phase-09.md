# Phase 09 — TUI and Desktop Notifications

## Implemented behavior

### TUI (`guard-tui`)
A ratatui + crossterm terminal interface that is a **pure IPC client** — it
contains no independent policy engine. It polls the daemon's Unix-socket IPC on
a 2-second refresh timer and renders:

- **daemon status** — enforcement active, protected_files/trees count, enrolled
  browsers, decision totals (allowed/denied/unclassified/audit_dropped), peer uid
- **recent blocked events** — newest-first list of deny decisions (id, reason,
  pid, uid, exe basename, resource kind), filtered to denies
- **active leases** — migration + ssh leases with id, source→target, expiry,
  revoked state
- **help/action line** — keybindings + a toast for the last action result

Actions (all enforced by the daemon via `SO_PEERCRED`; the TUI sends no UID):
- `a` authorize a migration lease (prompts source/profile/target, Tab to advance,
  Enter to submit)
- `x` revoke a lease by id (prompts id, Enter to submit)
- `r` refresh now; `q` quit; `Esc` cancel input

If the daemon socket is unreachable, the TUI shows the connection error in the
status panel and keeps retrying on the refresh timer — it never crashes. The
socket path defaults to `/run/guardd/guardd.sock` and can be overridden as the
first CLI argument.

The IPC client logic is split into [`guard_tui::client`](file:///home/plfjy/sensitive-file-guard/apps/guard-tui/src/client.rs)
(pure functions: `status`/`events`/`leases`/`browsers`/`migration_authorize`/`lease_revoke`)
so it can be exercised by integration tests without a terminal. The ratatui
rendering + event loop lives in [`main.rs`](file:///home/plfjy/sensitive-file-guard/apps/guard-tui/src/main.rs).

### Notifications (`guardd::notify`)
The daemon emits a desktop notification when a protected open is **denied**.
Allowed browser self-access never notifies. To avoid notification storms,
identical denies (same OS user + same pid + same exe + same resource) within a
10-second coalescing window collapse into a single notification; the **full
events always remain in the audit log** (coalescing suppresses only the
notification, never the audit row).

Delivery is best-effort:
- The daemon tries `notify-send` (freedesktop.org) with `--app-name=guardd`.
- If `notify-send` is unavailable or no graphical D-Bus session exists, it
  falls back to `tracing::warn` (journal/audit).
- Delivery runs on a **detached thread** so a hung D-Bus / missing binary can
  never stall the authorization hot path. `deliver` never returns an error —
  the daemon stays functional when no graphical session exists.

Notification text follows `09_TUI_AND_NOTIFICATIONS.md`:
- Generic deny: `"Blocked protected browser data access"` /
  `"<exe> attempted to read <browser> <kind> data. Access was denied."`
- Cross-browser (`CrossBrowserWithoutLease`): `"Blocked cross-browser data
  access"` / `"<process_browser> attempted to read <browser> protected data.
  Open guard-tui or run guardctl to authorize a temporary migration lease."`

The coalescer ([`NotificationCoalescer`](file:///home/plfjy/sensitive-file-guard/apps/guardd/src/notify.rs))
is pure data with an injected clock (`now_ms`), so tests are deterministic — no
wall clock, no sleeps. The key is built by [`key_for`](file:///home/plfjy/sensitive-file-guard/apps/guardd/src/notify.rs),
which returns `None` for allows (the no-notify-for-allow invariant is
structural).

## Hot-path impact
- Notification logic runs **only on deny** and only after the (already
  non-blocking) audit enqueue.
- The coalescer is a `HashMap` lookup + insert per deny — O(1), no allocation
  beyond the key clone.
- `notify-send` is spawned on a detached thread, so even a slow/failing
  subprocess cannot block the fanotify loop. Coalescing bounds the spawn rate
  to ≤1 thread per (process, resource) per 10 s.

## Exact commands run

```
cargo fmt
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

## Test results

All Phase 09 tests run **without root** and **without a graphical session**.
The coalescer is pure (injected clock); the no-session path is exercised by
`deliver` falling back to `tracing` when `notify-send` is absent (the normal CI
case). No test is BLOCKED.

### Required tests (mapped to `09_TUI_AND_NOTIFICATIONS.md`)

| Required test | Evidence |
| --- | --- |
| notification coalescing unit test | `guardd::notify::tests::coalescing_collapses_repeated_same_key_within_window` (first deny notifies; repeats within 10 s suppressed; after window notifies again; asserts `suppressed`/`delivered` counters) + `coalescing_separates_different_resource_or_process` (different resource/pid not collapsed) |
| no notification for allowed browser self-access | `guardd::notify::tests::no_notification_for_allowed_browser_self_access` (`key_for` returns `None` for `Allow`, `Some` for `Deny`) |
| TUI can grant/revoke a synthetic migration lease | `guard_tui::tests::migration_round_trip::tui_client_grants_then_revokes_synthetic_migration_lease` (full framed Unix-socket round-trip against a mock IPC server: `MigrationAuthorize`→`MigrationAuthorized`, then `LeasesRevoke`→`LeaseRevoked`; asserts sent ops + parsed bodies) |
| daemon remains functional when no graphical session exists | `guardd::notify::tests::deliver_does_not_panic_without_graphical_session` (`deliver` returns normally with no D-Bus/notify-send) + `try_notify_send_returns_err_when_binary_absent` (the `Err` path `deliver` handles) |

### Additional tests

| Test | Evidence |
| --- | --- |
| migration deny uses migration-specific text | `guardd::notify::tests::migration_deny_uses_migration_specific_text` (summary contains "cross-browser"; body points at guard-tui + migration lease) |
| generic deny uses blocked-browser text | `guardd::notify::tests::generic_deny_uses_blocked_browser_text` (summary + body + "Access was denied") |
| TUI status round-trip | `guard_tui::tests::migration_round_trip::tui_client_status_round_trip` (client parses `StatusInfo` for the dashboard) |

### Full counts

- `guardd` — 47 passed (40 from Phase 06–08 + 7 new Phase 09 notify tests).
- `guard-tui` — 2 passed (2 new integration tests: migration grant/revoke
  round-trip, status round-trip). The lib has no unit tests of its own; the
  client functions are covered by the integration tests.
- `guard-ipc` — 4 passed (unchanged from Phase 08).
- `guard-core` — 21 passed (unchanged).
- `platform-linux` — 29 passed (unchanged; IPC transport reused by TUI tests).
- `guardctl` — 3 passed (unchanged).
- Other crates — unchanged.
- **Total: 142 passed, 0 failed.**

`cargo clippy --all-targets --all-features -- -D warnings` — clean.
`cargo fmt --check` — clean.

## Known limitations

- **`notify-send` delivery as root**: when the daemon runs as root, `notify-send`
  targets the root user's D-Bus session by default, which may not be the
  logged-in user's session. A production deployment would resolve the affected
  user's `DBUS_SESSION_BUS_ADDRESS`/`DISPLAY` from `/proc/<pid>/environ` and
  drop to that uid before spawning `notify-send`. For the PoC the fallback to
  `tracing::warn` (journal) is the expected path for a root daemon; the
  coalescing + text logic (the testable invariants) is independent of delivery.
- **TUI input is single-line prompts**: the migration-authorize prompt collects
  source/profile/target via Tab-advanced single-line fields (no multi-field
  form widget). This keeps the implementation small while satisfying the
  grant/revoke action requirement.
- **No TUI screenshot test**: the ratatui rendering is exercised by build +
  clippy + manual review; the testable surface (the IPC client actions) is
  covered by the integration test. A snapshot test would require a terminal
  harness out of scope for the PoC.
- **Coalescing window is fixed (10 s)**: not configurable per-deployment. The
  spec asks for "short window"; 10 s suppresses busy-loop storms while still
  re-notifying on a genuinely new incident shortly after.

## Security notes

- The TUI sends **no UID**; all authorization is enforced by the daemon via
  `SO_PEERCRED` (inherited from Phase 07/08). Verified by the integration test
  asserting the sent `MigrationAuthorize` op carries only source/profile/target/
  duration.
- Notifications carry **no secret contents**: the body names the exe basename,
  the browser id, and the resource *kind* — never cookie values, passwords, key
  bytes, or DB rows. The audit record (which also carries no secrets) is the
  source; `notification_text` only reads metadata fields.
- `deliver` never panics or propagates errors; a missing graphical session
  cannot degrade enforcement (the deny decision + audit happen before/again
  independently of notification delivery).
