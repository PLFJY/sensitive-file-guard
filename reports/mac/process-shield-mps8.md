# MPS8 — UI, Audit, Health, Notifications

## Status

PASS (code + offline tests).

## Repository

- HEAD: bc26dd03b8fb9e7d6540b4569f2ee256d4f743a3 (working tree changes only)

## Goal

Make Process Shield state truthful and understandable without exposing secret
data.

## Changes

### `crates/guard-ipc`

- New `ProcessShieldInfo` status block (serde-optional, backward compatible)
  attached to `MacHealthInfo`:
  - overall state Active / Reduced / Unavailable + exact reason;
  - per-capability: task control protection, task read protection (runtime
    feature-detected), launch integrity, runtime integrity posture summary,
    injection telemetry, optional library mapping protection (disabled);
  - counters: task control/read allowed/denied, shield admitted/compromised,
    launch injections denied, trace/remote-thread/CS-invalidated observed.

### `apps/guard-es`

- `process_shield_info` builds the truthful status section:
  - Unavailable when the ES client is not active;
  - Reduced when AUTH_GET_TASK_READ or notify subscriptions are unavailable,
    or the process graph is degraded — with exact reasons;
  - Active otherwise;
  - runtime posture counts come from `MacBackendConfig::runtime_posture_report`
    (MPS7).

### `apps/guard-ui`

- Overview detail line includes Process Shield state + per-capability summary
  (not a fake global flag).
- Notification priority:
  - denied task-attempt events (`process_shield_task_control_denied`,
    `process_shield_task_read_denied`) -> security notification, no popup
    decision;
  - `process_shield_launch_injection_denied` -> security notification;
  - `process_shield_compromised` -> high-priority notification (process name +
    signal metadata, never secret content);
  - runtime posture Reduced is status/diagnostic only, not spammy.
- Phase-50 lifecycle preserved: closing the Guard UI does not stop guard-es or
  guard-notify (no lifecycle code was changed).

### Audit

- Metadata-only audit events already in place (MPS1-MPS5): task control/read
  denials, launch-injection blocks, compromise transitions, notify signals.
  No secret bytes, no memory, no Mach port names.

## Security invariant added

```text
Process Shield status:
    Active  — task control + task read + launch integrity + telemetry live
    Reduced — precise reason (AUTH_GET_TASK_READ / notify / graph degraded)
    Unavailable — ES client not active
notifications:
    task deny / launch injection -> security notification (no popup)
    confirmed compromise -> high priority
    posture Reduced -> status only, never spammed
```

## Tests

```text
cargo build -p guard-ipc / guard-es / guard-ui PASS
cargo clippy --workspace --all-targets --all-features -- -D warnings PASS
cargo test --workspace --all-features PASS
```

guard-ipc backward-compat test still passes (new fields serde-optional).

## Native security evidence

- None new in this phase (UI rendering requires the rebuilt extension +
  GUI; MPS9 deploys and exercises it).

## Compatibility evidence

- Lifecycle behavior untouched (GUI quit does not stop guard-es/notify).

## Blockers

None.

## Security claims NOT made

- No claim the UI was visually exercised on a live rebuild (MPS9 deploy).

## Next phase readiness

- MPS9 deploys the rebuilt extension on this host and runs the synthetic
  security acceptance suite.
