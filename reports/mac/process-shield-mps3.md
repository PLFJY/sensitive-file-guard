# MPS3 — Task Capability Notifications + TRACE Telemetry

## Status

PASS (code + offline tests).

## Repository

- HEAD: bc26dd03b8fb9e7d6540b4569f2ee256d4f743a3 (working tree changes only)

## Goal

Observe successful/attempted interprocess-control signals that complement
authorization decisions, without confusing telemetry with prevention.

## Changes

### Native bridge

- Notify handling for NOTIFY_GET_TASK (10), NOTIFY_GET_TASK_READ (11),
  NOTIFY_TRACE (12), NOTIFY_REMOTE_THREAD_CREATE (13), NOTIFY_CS_INVALIDATED
  (14) via a new `guard_es_task_notify_callback_t`. No response is required
  (notify-only). For CS_INVALIDATED the affected process is `message->process`
  and the target field mirrors it.
- The notify subscriptions were already active since MPS2
  (`guard_es_client_subscribe_task_notify`).

### `crates/platform-macos/src/process_shield.rs`

- `TaskNotifyKind` (GetTask / GetTaskRead / Trace / RemoteThreadCreate /
  CsInvalidated) with stable event codes and `is_strong_signal()`. TRACE is
  explicitly NOT a strong signal; GetTask/GetTaskRead/RemoteThreadCreate/
  CsInvalidated are (consumed by MPS4).
- Per-signal notify counters.

### `crates/platform-macos/src/endpoint_security.rs`

- `handle_task_notify`: normalize requester + target (telemetry only;
  malformed identities are skipped, never turned into an allow/deny); only
  exact shielded targets are in scope; strong signals are audited and counted;
  TRACE is audited as telemetry — no auto-kill.
- `ShieldAuditEvent::TaskNotify` (metadata only: requester/target exe + signal
  label; never port names, memory, thread state or secret-bearing args).
- Notify counters surfaced in BackendHealth/MacHealthInfo.

### `crates/guard-core` + `guard-audit` + `guardd`

- New audit-only `Decision::Detected` (never returned by `evaluate`):
  notify-only signals are DETECTED + CONTAINED, never PREVENTED. Audit
  serialization round-trips "detected"; guardd prints DETECTED.

### `apps/guard-es`

- `handle_shield` records the notify events with `Decision::Detected` and
  `notify_only=true` in the diagnostic:
  process_shield_task_notify_obtained / process_shield_task_read_notify_obtained /
  process_shield_trace_observed / process_shield_remote_thread_observed /
  process_shield_cs_invalidated_observed.

## Security invariant added

```text
notify signal involving a shielded target:
    TRACE               -> metadata audit + counter; never auto-kill
    strong signals      -> audit + counter; MPS4 owns the Compromised transition
```

Sequence/drop health extends the existing per-kind ES sequence accounting
(kinds 10-14 tracked; no second health mechanism).

## Tests

```text
cargo test -p platform-macos --lib process_shield (9 tests) PASS
cargo test -p guard-es (9 tests) PASS
cargo clippy --workspace --all-targets --all-features -- -D warnings PASS
```

New tests:
- `notify_signal_classification_trace_stays_telemetry`.
- `notify_counters_are_per_signal`.
- guard-es audit test: trace/remote-thread events recorded with
  `Decision::Detected` + `notify_only=true`.

## Native security evidence

- None in this phase (telemetry requires live events; MPS9 exercises a
  controlled notify-only fixture against a synthetic target).

## Compatibility evidence

- None claimed. TRACE observations against real browsers are documented during
  MPS11 metadata observation only.

## Blockers

None.

## Security claims NOT made

- No notify event is advertised as prevented.
- No auto-termination exists yet (containment is decided in MPS4+ with
  evidence).

## Next phase readiness

- Strong notify signals are already routed to `TaskNotify` events; MPS4 turns
  them into the idempotent `Normal -> Compromised` transition.
