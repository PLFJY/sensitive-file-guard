# MPS4 — Remote Thread / Code-Signing Invalidation -> Compromise State

## Status

PASS (code + offline tests).

## Repository

- HEAD: bc26dd03b8fb9e7d6540b4569f2ee256d4f743a3 (working tree changes only)

## Goal

Turn strong notify-only breach signals into an irreversible live-process
integrity transition.

## Changes

### `crates/platform-macos/src/process_shield.rs`

- `MacProcessShield::apply_strong_signal(target)` returning
  `StrongSignalOutcome` (NotShielded / CompromisedNow / AlreadyCompromised):
  exact-instance gate first, then idempotent `Normal -> Compromised`. The
  transition is monotonic; exit clears state; PID reuse never inherits it.

### `crates/platform-macos/src/endpoint_security.rs`

- `handle_task_notify` now applies strong signals:
  - GetTask / GetTaskRead (unexpected successful task capability),
    RemoteThreadCreate, CsInvalidated => `apply_strong_signal`;
  - on the new transition, emits `ShieldAuditEvent::Compromised { target,
    signal, requester }` — the MPS4 ordering contract is: shield state
    transition FIRST (done synchronously in the callback), then guard-es runs
    capability-revocation hooks (MPS5), audit, notify (MPS8), optional
    containment;
  - AlreadyCompromised => telemetry audit only (never double-transitions);
  - NotShielded => untouched;
  - TRACE remains telemetry (no transition, no kill).

### `apps/guard-es`

- `ShieldAuditEvent::Compromised` => audit `process_shield_compromised`
  (metadata only: signal label, requester exe, integrity=Compromised).

## Security invariant added

```text
strong notify signal (task capability obtained / remote thread / CS invalidated)
  -> exact shielded instance: Normal -> Compromised (idempotent, irreversible)
  -> process exit clears state; PID reuse never inherits it
  -> capability revocation / audit / notify / containment run AFTER the transition
```

## Tests

```text
cargo test -p platform-macos --lib process_shield (10 tests) PASS
cargo test -p guard-es (9 tests) PASS
cargo clippy --workspace --all-targets --all-features -- -D warnings PASS
```

New tests:
- `strong_signal_transition_is_exact_idempotent_and_cleared_on_exit`.
- guard-es audit test: `process_shield_compromised` with signal metadata.

## Native security evidence

- None in this phase. MPS9 runs a controlled notify-only compromise fixture
  against a synthetic target and verifies the exact target becomes
  Compromised.

## Compatibility evidence

- None claimed. TRACE stays telemetry pending real-browser observation.

## Blockers

None.

## Security claims NOT made

- No notify-only event is advertised as PREVENTED (DETECTED + CONTAINED only).
- No termination is performed yet (containment requires MPS9/MPS11 evidence).

## Next phase readiness

- Compromise state exists in the shield and is evented; MPS5 wires it into the
  macOS process identity resolver so File Shield denies with
  `process_integrity_compromised` and revokes affected leases.
