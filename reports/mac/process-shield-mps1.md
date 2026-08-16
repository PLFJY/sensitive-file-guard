# MPS1 — AUTH_EXEC Race-Free Shield Admission

## Status

PASS (code + offline tests). Native AUTH_EXEC observation requires reinstalling
the rebuilt system extension; that deployment is executed once in MPS9 together
with the full synthetic acceptance suite. No claims of native prevention are
made in this report.

## Repository

- HEAD: bc26dd03b8fb9e7d6540b4569f2ee256d4f743a3 (no commits made; working tree changes only)
- branch: main

## Goal

A process that will become a shielded browser instance must be registered as
shielded before execution authorization is released, eliminating dependence on
a later NOTIFY_EXEC update.

## Changes

### Native bridge (`native/macos/endpoint_security_bridge.h/.c`)

- New `guard_es_exec_event_t` normalization for `ES_EVENT_TYPE_AUTH_EXEC`:
  - requester = `message->process`; target = `message->event.exec.target`;
  - message deadline;
  - presence-only DYLD launch facts via `es_exec_env`/`es_exec_env_count`
    for the six prohibited code-loading/search-path variables
    (DYLD_INSERT_LIBRARIES, DYLD_LIBRARY_PATH, DYLD_FRAMEWORK_PATH,
    DYLD_FALLBACK_LIBRARY_PATH, DYLD_FALLBACK_FRAMEWORK_PATH, DYLD_ROOT_PATH).
    Values are NEVER copied — only booleans cross the boundary.
- New `guard_es_exec_callback_t`; `guard_es_client_create` signature extended.
- `ES_EVENT_TYPE_AUTH_EXEC` added to the required subscription.
- Stable sequence kinds 7..=15 reserved for AUTH_EXEC, AUTH_GET_TASK,
  AUTH_GET_TASK_READ, NOTIFY_GET_TASK(_READ), TRACE, REMOTE_THREAD_CREATE,
  CS_INVALIDATED, AUTH_MMAP (used by later phases; only AUTH_EXEC is subscribed
  in MPS1).
- `NOTIFY_EXEC` process-graph behavior is untouched.

### `crates/platform-macos/src/process_shield.rs` (new)

- `ShieldReasonKind` (Browser / GuardComponent / DynamicLeaseRoot; only
  Browser is admitted in MPS1, the others arrive in MPS6).
- `ExecLaunchFacts` + `PROHIBITED_DYLD_VARS`: deterministic presence-only
  launch-integrity model; harmless diagnostic DYLD variables are not flagged.
- `MacProcessShield` live state keyed by exact `AuditProcessKey` + validated
  stable identity:
  - `admit` (exact instance, refcounted per reason);
  - `add_reason`/`remove_reason` (refcounted multi-reason shielding);
  - `mark_compromised` (idempotent `Normal -> Compromised`, never restored);
  - `remove_terminal` (exit destroys live state; PID reuse is a new instance);
  - `integrity_of_pid` (Normal for anything not shielded).
- Unit tests: DYLD classification, exact-instance admission, PID-reuse
  separation, invalid-identity fail-closed, idempotent compromise, refcounted
  reasons.

### `crates/platform-macos/src/endpoint_security.rs`

- `RawExecEvent` + `RawExecEvent::launch_facts`; `RawProcessFacts`
  `candidate_executable_path` for cheap scope gating.
- `CallbackContext::handle_exec`:
  1. normalize target (strict); malformed target fails closed ONLY when it
     appears enrolled (cheap path prefix), otherwise allowed (Process Shield is
     not a machine-wide launch firewall);
  2. `shield_eligible` via trust store / synthetic set;
  3. ES deadline honored (fail closed on insufficient budget);
  4. prohibited DYLD launch state => DENY + audit + health note;
  5. otherwise admit the exact target into `MacProcessShield` BEFORE the
     ALLOW response (no NOTIFY_EXEC dependency);
  6. unrelated execs respond ALLOW without touching shield state.
- `EndpointSecurityConfig::synthetic_with_shield` (synthetic shield-eligible
  executables; never real browsers) + `shield_eligible`/`shield_eligible_raw`.
- `ShieldAuditEvent` (ExecAdmitted / ExecDeniedLaunchInjection /
  ExecDeniedMalformed with requester uid) metadata-only channel;
  `recv_shield_timeout` + `process_shield()` accessors.
- `NOTIFY_EXIT` now also removes shield state (exit destroys live state).
- Sequence tracker grows to 16 kinds.
- New tests: RawExecEvent normalization + launch facts, truncated-target scope
  gate, synthetic eligibility, unrelated-exec exclusion.

### `crates/guard-core` + `guard-audit`

- `ProtectedResourceKind::Other` (audit-only neutral kind for Process Shield
  events; never flows through the protected-resource policy engine).
- Audit kind serialization/parse + stable kind code "other".

### `apps/guard-es`

- `MacPolicy::handle_shield`: metadata-only audit records for exec admission,
  launch-injection deny, malformed fail-closed (event codes
  process_shield_exec_admitted / process_shield_launch_injection_denied /
  process_shield_exec_malformed_denied); never carries secret contents.
- Service loop drains the shield audit channel non-blockingly.
- New test asserts audit rows exist and contain no cookie/key bytes.

## Security invariant added

```text
shielded-eligible AUTH_EXEC:
    clean launch + valid identity  -> admit exact target BEFORE ALLOW
    prohibited DYLD code-loading   -> DENY (target never becomes shielded)
    malformed/truncated identity   -> DENY for that exec (fail closed)
    unrelated exec                 -> ALLOW, no shield work
```

## Tests

```text
cargo test -p platform-macos --lib process_shield   (5 tests) PASS
cargo test -p platform-macos --lib endpoint_security (17 tests) PASS
cargo test -p guard-es                               (9 tests) PASS
cargo clippy --workspace --all-targets --all-features -- -D warnings  PASS
```

## Native security evidence

- Endpoint Security extension active on this host: yes
  (top.plfjy.SensitiveFileGuard.guard-es activated; SIP disabled self-use mode),
  but the RUNNING extension binary predates these changes.
- No native AUTH_EXEC evidence is claimed yet — the rebuilt extension must be
  reinstalled; MPS9 runs the synthetic AUTH_EXEC admission/launch-injection
  acceptance and records exact evidence there.

## Compatibility evidence

- Offline only. Disposable Chrome/Firefox compatibility is MPS11.

## Blockers

None for code. Native observation is deferred by design to MPS9 (one extension
reinstall, then the synthetic suite).

## Security claims NOT made

- No task-port prevention yet (MPS2).
- No claim that any real browser exec was admitted/denied natively.

## Next phase readiness

- `MacProcessShield` + AUTH_EXEC admission are in place for MPS2 task-port
  policy and MPS4 compromise transitions.
