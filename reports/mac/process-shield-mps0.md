# MPS0 — Threat Model + Portable Integrity Contract

## Status

PASS (offline/domain tests only; no native ES changes in this phase by design)

## Repository

- HEAD: bc26dd03b8fb9e7d6540b4569f2ee256d4f743a3 (observed base; no commits made)
- branch: main
- working tree before phase: only the untracked harness pack
- working tree after phase: MPS0 portable contract + docs + report

## Goal

Make process integrity an explicit product/security concept without changing
native ES enforcement yet.

## Changes

### guard-core (portable domain)

- `crates/guard-core/src/identity.rs`:
  - new `ProcessIntegrity` enum: `Normal | Compromised`, monotonic per stable
    instance, `Default = Normal`, serde-compatible.
  - `ProcessIdentity` gains `#[serde(default)] integrity: ProcessIntegrity` so
    old serialized identities still deserialize.
- `crates/guard-core/src/policy.rs`:
  - new stable deny reason `DenyReason::ProcessIntegrityCompromised` with
    machine-readable code `process_integrity_compromised`.
  - `evaluate` now fails closed first: a `Compromised` exact live instance is
    denied before any browser/SSH policy branch (including leases and migration
    confirmation) can grant anything. `evaluate` is only consulted for
    protected resources, so unrelated processes are unaffected.
- `crates/guard-core/src/lib.rs`: re-exports `ProcessIntegrity`.

### Platform identity resolvers (preserved behavior)

- `crates/platform-linux/src/identity.rs`: every resolved instance is Normal
  (no Linux Process Shield in this harness; fanotify behavior unchanged).
- `crates/platform-macos/src/browser_trust.rs`: resolver defaults integrity to
  Normal; the macOS Process Shield layer (MPS1+) will surface live shield state
  here.
- Test/helper constructors updated across `guard-core`, `guard-runtime`,
  `guard-platform/tests/fake_backend.rs`, `apps/guardd` (tests only).

### Docs

- `docs/安全模型.md`: scope contract updated —
  - in scope: external same-user process-control/read/injection attempts against
    protected authority-bearing processes (task control/read, trace, remote
    thread, DYLD code-loading injection, post-invalidation exploit);
  - still out of scope: malicious extensions, browser-internal RCE,
    root/kernel compromise, DevTools/remote-debugging abuse, secrets disclosed
    before Guard started, generic malware classification;
  - deterministic `Normal | Compromised` model, no PID-reuse contamination,
    no popup for task-port access, notify-only signals are DETECTED+CONTAINED
    only.

## Security invariant added

```text
protected secret access
    requires
verified process identity
    AND
process integrity == Normal   (new, MPS0 portable gate)
```

## Tests

```text
cargo test -p guard-core
result: 31 passed (was 26 baseline); new MPS0 tests all pass
```

New table-driven tests in `policy.rs`:

1. `compromised_browser_own_profile_is_denied` — Compromised trusted browser +
   own profile => Deny(process_integrity_compromised), not Allow.
2. `compromised_process_denied_before_any_browser_or_ssh_policy` — table over
   CookieStore/SessionStore/SshPrivateKey kinds => all fail closed first.
3. `compromised_process_denied_even_with_valid_leases` — valid
   MigrationAccessLease and SshLoadLease cannot rescue a compromised instance.
4. `pid_reuse_new_normal_instance_is_not_contaminated` — same PID, new start
   time: old Compromised instance denied, new Normal instance allowed.
5. `normal_processes_keep_existing_decisions` — regression table: Allow /
   RequireMigrationConfirmation / RequireSshKeyConfirmation /
   NotTrustedIdentity / UnknownProcess unchanged for Normal processes.

Reason-code stability and uniqueness tests extended with the new code.

## Native security evidence

- Endpoint Security extension active: N/A (MPS0 makes no native changes).
- This phase is intentionally offline; native prevention evidence starts at MPS2.

## Compatibility evidence

- synthetic fixtures: N/A (no fixtures needed for the portable gate).
- Existing Linux `guardd` resolve path untouched semantically (Normal only).

## Blockers

None.

## Security claims NOT made

- No ES subscription, task-port prevention or compromise-signal handling is
  claimed in this phase — those arrive in MPS1-MPS4.
- No real-host prevention evidence is claimed.

## Next phase readiness

- `ProcessIntegrity` + `process_integrity_compromised` are available for the
  macOS Process Shield layer.
- MPS1 can begin: native `AUTH_EXEC` normalization + `MacProcessShield` state.
