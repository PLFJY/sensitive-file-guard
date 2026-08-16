# MPS5 — Integrate Compromise with File Shield + Lease Revocation

## Status

PASS (code + offline tests).

## Repository

- HEAD: bc26dd03b8fb9e7d6540b4569f2ee256d4f743a3 (working tree changes only)

## Goal

A compromised process must immediately lose Guard's secret-reading authority.

## Changes

### `crates/guard-runtime` (portable generic semantics)

- `approve_migration` and `approve_ssh_read` now REJECT a Compromised
  exact instance ("process integrity is compromised") — no new lease can ever
  bind to it, on any platform.
- `PendingMigrationStore::revoke_recent_approvals_for(uid, exe_identity)`:
  recent-import approval grace is dropped for the compromised executable so it
  cannot silently re-authorize the same compromised process/root.

### `crates/platform-macos/src/browser_trust.rs`

- `MacProcessIdentityResolver` now carries the live `MacProcessShield`
  (`new_shared_with_shield`) and surfaces `integrity` from it in
  `resolve()`. Dependency direction stays clean: platform-macos owns
  ES-derived compromise facts; core/runtime owns the policy semantics.

### `apps/guard-es/src/service.rs`

- The resolver is constructed with the backend's shield state (falls back to
  an empty shield when the ES client is unavailable).

### `apps/guard-es/src/policy.rs`

- File Shield gate: after resolving the process identity, a Compromised
  instance fails closed BEFORE any browser/SSH policy — including the SSH
  write-only allow path and the system-process/trusted-tool metadata
  exceptions. Deny reason: `process_integrity_compromised`.
- `revoke_capabilities_for_compromised` runs on the `Compromised` handoff
  (MPS4 ordering: transition -> revocation -> audit):
  - bound migration leases whose root IS the target (direct) or whose trusted
    tree contains it (ancestor walk via the process graph);
  - SSH read leases rooted at the target (direct or in-tree);
  - recent-approval grace for the target's uid + exe identity.
  Unrelated users/processes/leases are never mutated.

## Security invariant added

```text
protected resource hit:
    resolve exact identity
    integrity == Compromised  -> Deny(process_integrity_compromised)
                                 (before ANY browser/SSH/system/tool rule)
Compromised event:
    1. mark compromised (ES callback)
    2. revoke bound migration + SSH-read leases (direct + tree scoped)
    3. revoke recent-import approval grace for the exe
    4. audit; notify (MPS8)
    5. no new lease can bind (runtime rejects Compromised)
```

## Tests

```text
cargo test -p guard-runtime PASS
cargo test -p guard-es (12 tests) PASS
cargo clippy --workspace --all-targets --all-features -- -D warnings PASS
```

New tests:
- `no_new_lease_binds_to_a_compromised_instance` (runtime).
- `recent_approval_grace_is_revoked_for_compromised_executable` (runtime).
- `compromised_instance_fails_closed_for_all_file_shield_paths` (own-browser
  read denied; SSH write-only denied; Normal sibling still allowed).
- `compromise_revokes_bound_leases_direct_and_tree_scoped` (unrelated
  compromise touches nothing; in-tree reader compromise revokes both the SSH
  lease and the migration lease).
- `compromise_denies_new_protected_access_and_no_new_lease_binds`.

## Native security evidence

- None in this phase; MPS9 verifies the full synthetic loop on the rebuilt
  extension (compromise signal -> Compromised -> protected open denied).

## Compatibility evidence

- Normal-process flows are unchanged (regression assertions included).

## Blockers

None.

## Security claims NOT made

- No real-browser compromise was induced or observed.
- No claim about Safari/WebKit (MPS12).

## Next phase readiness

- File Shield honors Process Shield integrity; MPS6 adds Guard self-protection
  and dynamic lease-root shielding.
