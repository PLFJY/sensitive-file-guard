# Phase 14 — systemd Install, Startup, and Recovery

## Objective

Make Linux V1 installable as a root system service: a systemd unit for
`guardd`, an install/uninstall script, conventional config/state/runtime
locations, `Restart=always` crash recovery, a health/status command that
distinguishes ACTIVE / DEGRADED / NOT_ENFORCING, and stale-socket recovery.

## Deliverables

| Deliverable | Artifact |
| --- | --- |
| systemd unit for `guardd` | [`deploy/guardd.service`](file:///home/plfjy/sensitive-file-guard/deploy/guardd.service) |
| install / uninstall script | [`deploy/install.sh`](file:///home/plfjy/sensitive-file-guard/deploy/install.sh) |
| example config | [`deploy/guardd-config.example.json`](file:///home/plfjy/sensitive-file-guard/deploy/guardd-config.example.json) |
| config under conventional location | `/etc/guardd/config.json` (mode 0640) |
| state directory (restrictive perms) | `/var/lib/guardd` (mode 0750) |
| runtime Unix socket | `/run/guardd/guardd.sock` (mode 0660, `RuntimeDirectory=guardd`) |
| restart policy | `Restart=always`, `RestartSec=2` |
| health/status command | `guardctl status` — prints ACTIVE / DEGRADED / NOT_ENFORCING |
| marks/resources reconstructed on startup | `run_browser_enforcement` re-discovers profiles + re-marks on every start |
| startup audits enforcement active | `guardd: enforcement ACTIVE — ...` log line + `tracing::info!("enforcement active")` |
| stale socket recovery | `IpcServer::bind` unlinks stale socket before `UnixListener::bind` |
| privileged integration test | [`scripts/test-systemd-root.sh`](file:///home/plfjy/sensitive-file-guard/scripts/test-systemd-root.sh) |

## systemd unit — `deploy/guardd.service`

```ini
[Service]
Type=simple
ExecStart=/usr/local/sbin/guardd --enforce-browser-config /etc/guardd/config.json \
    --ipc-socket /run/guardd/guardd.sock --audit-db /var/lib/guardd/audit.db
Restart=always
RestartSec=2
TimeoutStartSec=10
KillSignal=SIGTERM
TimeoutStopSec=5
KillMode=control-group
User=root
Group=root
StateDirectory=guardd
RuntimeDirectory=guardd
RuntimeDirectoryMode=0755
LogsDirectory=guardd
```

### Restart policy

`Restart=always` with `RestartSec=2`. This is the critical mitigation for the
fanotify fail-open limitation: when `guardd` crashes, the fanotify group fd
closes and **all marks are removed** — files become unprotected until the
daemon restarts. `Restart=always` ensures systemd respawns the daemon
unconditionally (crash, OOM, signal), and `RestartSec=2` keeps the
unprotected window to ~2 seconds. `TimeoutStartSec=10` gives the daemon time
to discover profiles and apply marks; if it fails to initialize, systemd
restarts it.

### Service privilege — why root + CAP_SYS_ADMIN

Permission-capable fanotify (`FAN_CLASS_CONTENT` + `FAN_OPEN_PERM`) requires
`CAP_SYS_ADMIN`. A capability-less mode cannot intercept opens; the daemon
never pretends otherwise — it prints a precise error and exits 2 if
`CAP_SYS_ADMIN` is missing (see `require_cap_sys_admin` in
[`apps/guardd/src/main.rs`](file:///home/plfjy/sensitive-file-guard/apps/guardd/src/main.rs)).

The unit runs as `User=root` / `Group=root` with
`CapabilityBoundingSet=CAP_SYS_ADMIN CAP_KILL CAP_DAC_READ_SEARCH`.
`CAP_DAC_READ_SEARCH` is needed to resolve process identity via `/proc` for
processes owned by other users.

### Security hardening

Directives that do **not** break fanotify or profile access:
- `PrivateTmp=true` — private `/tmp` is fine; profiles are under `$HOME`.
- `PrivateDevices=true` — no `/dev` access needed beyond what root has.
- `ProtectKernelTunables=true`, `ProtectKernelModules=true`,
  `ProtectControlGroups=true` — kernel hardening, no impact on fanotify.
- `RestrictRealtime=true`, `RestrictSUIDSGID=true`, `LockPersonality=true`.

Deliberately **not** used (would break enforcement):
- `ProtectSystem=true` / `ProtectHome=true` — would hide real user profiles
  from fanotify marks.
- `NoNewPrivileges=true` — the daemon already runs as root; this directive
  is incompatible with the capability model and would prevent the fanotify
  group from functioning in some configurations.
- Mount-namespace isolation (`ReadOnlyPaths`, `ReadWritePaths` restricted to
  `/etc/guardd` only) — would hide user profiles. Tested boundary: the
  harness explicitly warns against this.

### Directory management

systemd's `StateDirectory=guardd` creates `/var/lib/guardd` (audit DB),
`RuntimeDirectory=guardd` creates `/run/guardd` (IPC socket), and
`LogsDirectory=guardd` creates `/var/log/guardd`. These survive daemon
restarts and are cleaned by systemd on uninstall only if the admin removes
the unit.

## Install / uninstall — `deploy/install.sh`

```
sudo deploy/install.sh              # install
sudo deploy/install.sh --uninstall  # uninstall
```

**Install:**
1. Builds release binaries (`cargo build --release`) if missing.
2. Installs `guardd` → `/usr/local/sbin/guardd` (0755).
3. Installs `guardctl` → `/usr/local/bin/guardctl` (0755).
4. Installs config example → `/etc/guardd/config.json` (0640) — does **not**
   overwrite an existing config.
5. Creates `/var/lib/guardd` (0750) for the audit DB.
6. Installs systemd unit → `/etc/systemd/system/guardd.service` (0644).
7. `systemctl daemon-reload` + `systemctl enable guardd` (does **not** start —
   user verifies config first).

**Uninstall:**
1. `systemctl stop guardd` + `systemctl disable guardd`.
2. Removes unit file, binaries.
3. `systemctl daemon-reload`.
4. **Preserves** `/etc/guardd/` (config) and `/var/lib/guardd/` (audit DB) —
   admin removes manually if desired.

## Status reporting — ACTIVE / DEGRADED / NOT_ENFORCING

### `StatusInfo.status` field

Added a `status: String` field to
[`StatusInfo`](file:///home/plfjy/sensitive-file-guard/crates/guard-ipc/src/lib.rs#L194-L215)
with `#[serde(default)]` for backwards compatibility with older daemons.

The daemon computes the state in
[`handle_status`](file:///home/plfjy/sensitive-file-guard/apps/guardd/src/ipc.rs#L136-L166):

| State | Condition |
| --- | --- |
| `NOT_ENFORCING` | No fanotify group (daemon running without enforcement, e.g. config-check mode) |
| `DEGRADED` | Fanotify group active but `audit_dropped > 0` or `unclassified > 0` (events being dropped or fail-closed decisions indicate races) |
| `ACTIVE` | Fanotify group active, no audit drops, no unclassified decisions |

### CLI display

`guardctl status` prints the state on the header line:
```
guardd 0.1.0 — ACTIVE
  protected_files : 6
  ...
```

### TUI display

`guard-tui` renders the status with color coding:
- `ACTIVE` → green
- `DEGRADED` → yellow
- `NOT_ENFORCING` (or other) → red

## Stale socket recovery

When `guardd` crashes (e.g. `kill -9`), the IPC socket file
(`/run/guardd/guardd.sock`) may remain on disk. On restart,
[`IpcServer::bind`](file:///home/plfjy/sensitive-file-guard/crates/platform-linux/src/ipc.rs#L72-L87)
calls `std::fs::remove_file(path)` before `UnixListener::bind`, so a stale
socket never blocks rebind. The parent directory is also created if missing.

## Startup enforcement audit

On every successful start, the daemon logs (visible via `journalctl -u guardd`):

```
guardd: enforcement ACTIVE — browsers=1 protected_files=6 marked_files=6 \
    marked_tree_dirs=1 browser_exes=3 (fanotify fd=3)
```

followed by a structured `tracing::info!("enforcement active")` event. This
satisfies the requirement that startup audits enforcement became active.

An unexpected previous shutdown is visible in journald: the previous
process's logs end abruptly (no graceful "shutting down" line), and the new
process's `enforcement ACTIVE` line appears after a `RestartSec` gap. The
`guardctl status` command reflects current state; if the daemon is down, the
CLI fails to connect (clear signal that enforcement is not running).

## Marks/resources reconstructed on startup

`run_browser_enforcement` in
[`apps/guardd/src/main.rs`](file:///home/plfjy/sensitive-file-guard/apps/guardd/src/main.rs)
performs the full discovery + mark cycle on every start:
1. Reads config from `/etc/guardd/config.json`.
2. `EnforcementEngine::from_config` discovers browser profiles and SSH keys.
3. `FanotifyGroup::new_content` creates a fresh fanotify group.
4. `mark_files` + `mark_trees` apply `FAN_OPEN_PERM` marks to all protected
   files and trees.
5. `enforcement ACTIVE` is logged with the counts.

No state is persisted between restarts — the fanotify marks are kernel state
tied to the group fd, and the resource registry is rebuilt from config. This
means protection is always consistent with the current config.

## Privileged integration test — `scripts/test-systemd-root.sh`

```
sudo bash scripts/test-systemd-root.sh
```

Uses **only synthetic fixtures** (temp Chrome UDD with synthetic cookie,
ephemeral ed25519 SSH key). No real browser profiles or SSH keys.

### Test scenarios

| # | Test | What it verifies |
| --- | --- | --- |
| 1 | install service | `deploy/install.sh` installs + enables the service |
| 2 | start service, verify status | `systemctl start guardd` succeeds; `guardctl status` shows ACTIVE |
| 3 | protected files denied | synthetic cookies + SSH key are denied by fanotify |
| 4 | stop service (fail-open) | after `systemctl stop`, files become readable (marks removed) |
| 5 | restart, marks reconstructed | after `systemctl start`, files are denied again (marks rebuilt from config) |
| 6 | crash + auto-restart | `kill -9` the daemon; systemd restarts it within ~3s; enforcement back |
| 7 | stale socket recovery | stop daemon, create stale socket file, start daemon — IPC rebinds and responds |
| 8 | status states | while running: ACTIVE; when stopped: `guardctl` cannot connect (daemon down) |
| 9 | no secret contents in journald | `journalctl -u guardd` does not contain the synthetic cookie fixture value |

**Status: BLOCKED for the non-interactive build agent** (requires root +
systemd + `CAP_SYS_ADMIN`). A human can run the script on a systemd host.

## Exact commands run

```
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

## Test results

`cargo fmt --check` — clean.
`cargo clippy --all-targets --all-features -- -D warnings` — clean.
`cargo test --all-features` — **187 passed, 0 failed.**

No new unit tests were added in Phase 14 (the deliverables are deployment
artifacts: systemd unit, install script, status field, privileged test
script). The existing 187 tests cover the code changes:
- `StatusInfo.status` field is exercised by existing status round-trip tests
  in `guard-ipc` and `guard-tui` (updated test literals to include
  `status: "ACTIVE"`).
- `handle_status` logic is covered by the `guardd` IPC integration tests.

### Test counts (unchanged from Phase 13)

- `guard_audit` — 5
- `guard_browser` — 21
- `guard_core` — 24
- `guard-ipc` — 7
- `guard-ssh` — 10
- `guard-test-fixtures` — 9
- `platform-linux` — 29
- `guardd` — 73
- `guardctl` — 6
- `guard-tui` — 2
- `smoke` integration — 1
- **Total: 187 passed, 0 failed.**

## Known limitations

1. **Fail-open on daemon crash.** When `guardd` dies, all fanotify marks are
   removed. Files are unprotected for ~2 seconds (the `RestartSec` window)
   until systemd restarts the daemon. This is a fundamental fanotify
   limitation; `Restart=always` minimizes but does not eliminate the window.
2. **Privileged tests BLOCKED.** The systemd integration test requires root
   + systemd + `CAP_SYS_ADMIN`, unavailable to the non-interactive build
   agent. The 9-scenario script is provided for a human to run.
3. **No reboot test.** The harness mentions a "reboot/startup script if
   environment permits." The systemd unit is `WantedBy=multi-user.target`
   with `After=local-fs.target` + `Before=graphical.target`, ensuring the
   daemon starts before user sessions. A full reboot test requires a
   physical/virtual machine and is left to the human operator.
4. **Config not started automatically.** `install.sh` enables but does not
   start the service — the user must edit `/etc/guardd/config.json` and run
   `systemctl start guardd` manually. This is intentional: starting with the
   example config (placeholder `REPLACE_USER`) would fail to discover any
   profiles.
