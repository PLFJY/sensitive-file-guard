# MPS6 — Guard Self-Protection + Dynamic Lease-Root Shielding

## Status

PASS (code + offline tests).

## Repository

- HEAD: bc26dd03b8fb9e7d6540b4569f2ee256d4f743a3 (working tree changes only)

## Goal

Protect processes that temporarily or permanently carry security authority,
without turning Process Shield into whole-system anti-debugging.

## Changes

### Guard self-protection (AUTH_EXEC admission)

- `EndpointSecurityConfig::browser_with_guard_components`: exact Guard
  component executable paths are admitted as `ShieldReasonKind::GuardComponent`
  on AUTH_EXEC:
  - the running `guard-es` (current_exe);
  - `/Applications/Guard.app/Contents/MacOS/Guard`;
  - `/Applications/Guard.app/Contents/MacOS/guard-notify`.
  `guardctl` is deliberately NOT shielded so CLI/debug workflows are not
  harmed (documented decision).
- Deadlock avoidance: the task-access allowlist stays at ZERO exceptions, so no
  Guard component depends on a task port to another protected component; no
  implicit relationships were added.

### Dynamic lease-root shielding

- `MacProcessIdentityResolver::shield()` + `current_facts(pid)` accessors.
- `MacPolicy::shield_dynamic_lease_root(root)`: when a migration or SSH-read
  lease becomes bound (resolve_migration, approve_recent, approve_sibling,
  resolve_ssh_read_at), the exact root is admitted (or reason-added) with
  `ShieldReasonKind::DynamicLeaseRoot` for the capability lifetime.
- `MacPolicy::unshield_dynamic_lease_root(root)`: maintenance removes the
  dynamic reason on root exit or lease expiry/revocation while the root is
  still alive. A Compromised (quarantined) instance keeps its entry until
  process exit so the File Shield deny cannot be lost by dropping the last
  reason.
- Reason/reference counting (MPS1) is reused: a browser that is also a lease
  root stays shielded after the dynamic reason disappears.

## Security invariant added

```text
bound migration/SSH lease:
    exact root dynamically shielded for the capability lifetime
    (Normal integrity; File Shield policy unchanged)
    expiry/revoke/root exit -> only the dynamic reason disappears
Guard components (guard-es / Guard GUI / guard-notify):
    shielded on AUTH_EXEC; no task-port popup; no implicit task allow rules
```

## Tests

```text
cargo test -p platform-macos --lib (96 tests) PASS
cargo test -p guard-es (13 tests) PASS
cargo clippy --workspace --all-targets --all-features -- -D warnings PASS
```

New tests:
- `shield_eligible_recognizes_guard_components`.
- `dynamic_lease_root_is_shielded_while_live_and_unshielded_on_expiry`.

## Native security evidence

- None in this phase. MPS9 adds the native probe: while a synthetic lease is
  live, an untrusted same-user task-port probe against the lease root must be
  denied.

## Compatibility evidence

- Guard component self-protection is additive (task-port deny only); no Guard
  workflow depends on task ports between Guard processes.

## Blockers

None.

## Security claims NOT made

- No claim that the GUI/notify processes were observed being protected
  natively (MPS9/MPS11).
- guardctl is intentionally outside always-on shielding.

## Next phase readiness

- Shield state, compromise transitions, File Shield integration and dynamic
  shielding are complete; MPS7 adds Hardened Runtime/entitlement posture.
