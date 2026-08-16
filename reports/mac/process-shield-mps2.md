# MPS2 — Task Control + Task Read Prevention

## Status

PASS (code + offline tests). Native task-port probe evidence is part of the
MPS9 synthetic acceptance on the rebuilt extension.

## Repository

- HEAD: bc26dd03b8fb9e7d6540b4569f2ee256d4f743a3 (working tree changes only)

## Goal

Prevent untrusted same-user processes from obtaining control/read task ports
for shielded targets before a usable capability is granted.

## Changes

### Native bridge (`native/macos/endpoint_security_bridge.h/.c`)

- New `guard_es_task_event_t`: deadline + requester (`message->process`) +
  target (`event.get_task(.read).target`), normalized as full stable process
  facts.
- New `guard_es_task_callback_t`; both `ES_EVENT_TYPE_AUTH_GET_TASK` and
  `ES_EVENT_TYPE_AUTH_GET_TASK_READ` are handled (event kind 8/9).
- Subscription split so availability is measured honestly:
  - `guard_es_client_subscribe_required`: core + AUTH_GET_TASK;
  - `guard_es_client_subscribe_task_read`: AUTH_GET_TASK_READ separately —
    when the running OS/SDK does not support it, task-read prevention is NOT
    faked and health reports Reduced;
  - `guard_es_client_subscribe_task_notify`: the MPS3/MPS4 notify set
    (NOTIFY_GET_TASK(_READ), TRACE, REMOTE_THREAD_CREATE, CS_INVALIDATED) —
    subscribed now so compromise detection availability is measured.

### `crates/platform-macos/src/process_shield.rs`

- `TaskAccessKind` (Control | Read) with stable event codes.
- `task_access_allowlist`: deterministic allowlist for shielded targets.
  MPS2 enrolls ZERO exceptions — same UID, Apple signature, same Team ID,
  basename or process-tree relationship are never sufficient. MPS11 may add
  narrow entries only with observed evidence + regression fixtures.
- Per-kind task decision counters (`note_task_decision(kind, allow)`).

### `crates/platform-macos/src/endpoint_security.rs`

- `RawTaskEvent` + `handle_task`:
  1. normalize TARGET first; malformed target fails closed ONLY when it looks
     shield-eligible, otherwise allowed (not a global task firewall);
  2. shield membership by exact live stable identity (never PID alone);
  3. unshielded target => Allow fast (requester is not even parsed);
  4. shielded target => ES deadline honored; requester identity required
     (unverifiable requester => deny);
  5. `task_access_allowlist` => DENY for every requester today; audit
     `TaskDenied` + health note; the denied attempt NEVER marks the target
     compromised.
- `ShieldAuditEvent::TaskDenied { kind, requester, target }` (metadata only).
- `task_read_supported` / `task_notify_supported` runtime feature detection;
  `process_shield_reduced()`.
- Health: BackendHealth + MacHealthInfo gain task control/read allowed/denied
  counters, task_read_supported, task_notify_supported and shield counters.

### `apps/guard-es`

- `MacPolicy::handle_shield` records distinct metadata-only audit codes:
  `process_shield_task_control_denied` and `process_shield_task_read_denied`.
- Status maps the new Process Shield health fields.

## Security invariant added

```text
AUTH_GET_TASK(_READ):
    target not shielded      -> Allow fast
    target shielded          -> explicitly verified relationship required
                                (none enrolled in MPS2) -> DENY before a usable
                                capability; target stays Normal
```

## Tests

```text
cargo test -p platform-macos --lib   (92 tests) PASS
cargo test -p guard-es               (9 tests) PASS
cargo clippy --workspace --all-targets --all-features -- -D warnings  PASS
```

New tests:
- `task_allowlist_rejects_same_uid_apple_and_team_id` — zero-exception
  contract.
- `task_decision_counters_are_per_kind`.
- `raw_task_normalizes_requester_and_target`.
- `task_target_truncation_only_fails_closed_when_shield_eligible`.
- guard-es audit test extended with `process_shield_task_control_denied`.

## Native security evidence

- AUTH_GET_TASK/AUTH_GET_TASK_READ are present in the installed SDK
  (ESTypes.h lines 192/209) and the running OS supports them.
- Native task-port probe runs in MPS9 (requires the rebuilt extension):
  untrusted same-user probe -> shielded synthetic target task control denied,
  task read denied, canary not recovered.

## Compatibility evidence

- No task-access exceptions were added, so no compatibility claim is made yet.
  MPS11 observes real browsers (metadata only) before any exception.

## Blockers

None for code.

## Security claims NOT made

- No native prevention evidence yet (MPS9).
- No claim that real browsers still function under the zero-exception policy
  (MPS11).

## Next phase readiness

- Notify subscriptions are already active (task_notify_supported measured);
  MPS3 consumes NOTIFY_GET_TASK(_READ) + TRACE as telemetry, MPS4 turns
  REMOTE_THREAD_CREATE/CS_INVALIDATED into compromise transitions.
