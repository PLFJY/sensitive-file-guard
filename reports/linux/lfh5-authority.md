# LFH5 — Migration + SSH Authority Tightening

## Baseline
- commit: 84a1bd133c78c41911d82dac5ffd1989a7722f5b (HEAD at phase start; LFH5 work is on top of this tree)
- kernel: 7.1.8-arch1-3 (x86_64)
- historical privileged environment note: this phase predates the capsule fanotify allow-list update. Current fanotify evidence is in `harness-state.md`; an explicitly user-authorized minimal polkit host fallback is permitted when capsule differences prevent a final conclusion.

## Threat / invariant
"tree membership = SecretAuthority" is too broad a lease: binding a lease to a browser root and authorizing *any descendant* lets an unenrolled helper (or a process that merely shares an ancestor) read protected cookies. LFH5 replaces this with **EXACT READER INSTANCE**: a lease authorizes exactly one process instance (PID + starttime + executed image identity + UID + BrowserId), a helper may read only if it is the exact descendant observed at bind time (post-bind observed exact descendant), pre-existing unobserved descendants never auto-upgrade, every lease is bound to the protection-continuity generation it was minted under, and Linux migration never claims read-only.

## Changes

### `crates/guard-core/src/lease.rs`
- `MigrationAccessLease`, `SshLoadLease`, `SshReadAccessLease` all gain `generation: u64` (LFH5: protection-continuity generation the lease was minted under; doc comments updated to the exact-instance model).

### `crates/guard-core/src/policy.rs`
- `evaluate(event, leases, now, current_generation)` — new 4th parameter; `decide_browser`/`decide_ssh` carry it.
- New `DenyReason::StaleLeaseGeneration` with public reason code `stale_lease_generation` (stable contract; added to `reason_codes_are_stable_snake_case` + uniqueness test).
- Migration: `Bound { root }` now matches `proc.stable == *root` ONLY — `process_is_in_tree`/`ancestor_matches_root` (tree walk) deleted. A stale-generation lease in scope is denied `StaleLeaseGeneration` (before state match). Armed leases still never authorize directly.
- SSH: `SshLoadLease` validity requires `generation == current_generation` (scan continues so a later valid lease for the same key can match); `SshReadAccessLease` (already exact-reader-only) additionally requires `generation == current_generation`.

### `crates/guard-runtime/src/lib.rs`
- `AuthorizationRuntime` gains `current_generation` (starts 0), `current_generation()`, and `bump_generation()` (continuity-loss hook). `evaluate` passes `self.current_generation`. `approve_migration`/`approve_ssh_read` stamp the current generation on new leases.

### `apps/guardd/src/enforce.rs`
- `lose_continuity(reason)` now also calls `runtime.bump_generation()` — belt-and-suspenders on top of `revoke_all_authority()`: even a lease that escapes revocation is dead by generation.
- `arm_migration_lease` and `authorize_ssh_load` stamp `runtime.current_generation()` on new leases.
- `refresh_migration_states` (manual armed-lease bind): binds the **exact opener instance** — the opener's own identity equals the armed target, OR the opener descends from the armed target (validated at bind time). Never binds the ancestor root; unobserved descendants never auto-upgrade. Comment updated.
- `pending_migration_details` (approval flow): binds `target.stable` — the exact opener observed at the confirmation event. `target_browser_root` (same-exe ancestor walk) deleted.

### `crates/guard-audit/src/lib.rs`
- `deny_reason_str`/`parse_deny_reason` round-trip `stale_lease_generation` (the string map is exhaustive — compile-enforced).

### Docs
- `docs/Linux技术说明.md`: new "授权精确性（LFH5）" section (exact reader instance, generation bound, SSH exact reader/one-shot + agent socket, no read-only overclaim).

## Tests (offline, all green)

- `guard-core` 36 passed. New LFH5:
  - `stale_generation_migration_lease_denied` → `Deny(StaleLeaseGeneration)`
  - `stale_generation_ssh_load_lease_not_authorized` / `stale_generation_ssh_read_lease_not_authorized` → `RequireSshKeyConfirmation`
  - `migration_lease_allows_explicitly_bound_helper` (exact helper bound → AllowByLease)
  - `migration_lease_denies_pid_reuse_of_bound_root` (same PID, new starttime → IdentityMismatch)
  - `migration_lease_denies_unbound_helper_despite_ancestor_match` (replaces the old tree-allow test: ancestor match alone → IdentityMismatch)
- `guard-runtime` 9 passed. New: `generation_bump_kills_preloss_leases` (migration + SSH-read leases minted pre-bump die by generation after `bump_generation`; distinct deny reason), `approve_migration_rejects_when_target_root_exited` (LFH5 matrix: target exits before approval → fail closed, no lease).
- `guardd` enforce 54 passed. New: `manual_armed_lease_binds_exact_descendant_helper` (binds exact helper instance; unrelated helper stays Armed; lease stamped with current generation), `lose_continuity_bumps_generation_and_kills_preloss_lease` (simulates a revocation miss by clearing `revoked`, then `decide` → `Deny(StaleLeaseGeneration)`); `pending_migration_details_bind_exact_opener_instance` (replaces the topmost-same-exe-root test).
- `guard-audit` 7, `guard-platform` fake_backend 3, `platform-linux` identity 16 — all pass.
- `cargo fmt --check` clean; `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.
- Full workspace suite: 31 suites OK, 0 FAILED (verified twice back-to-back — the documented intermittent timeout/flake trigger).

### Flaky-test fixes (pre-existing; found while running the LFH5 gate)
- `crates/platform-linux/src/identity.rs`: `spawn_and_resolve` + the replaced-path test used a fixed 50 ms sleep before resolving; under parallel test load the child could still be running the pre-exec image, so `/proc/PID/exe` did not yet name the spawned binary (seen as `executed_image_survives_unlink_with_deleted_suffix` failing the `(deleted)` readlink assert). Both now wait (bounded, 10 s) until the resolved exe dev/ino equals the spawned file.
- `crates/platform-linux/src/ipc.rs`: `oversized_request_rejected_by_server` unwrapped the payload write; the server can close the connection the instant it sees the oversized length, so the payload write legitimately hits EPIPE. The write/flush now tolerate the error (the close IS the rejection under test); the no-response assertion is unchanged.
- Stress: `platform-linux --lib` 10/10 runs green after the fixes; full workspace suite ×2 green.

## Live / privileged

- **ALL LIVE GATES PASS on the real host** (`reports/linux/evidence/live-host-20260819-122244/`): `test-ssh-broker-adversarial-root.sh` 29/29 (incl. the SSH `AllowByLease` audit evidence — see the release-build audit fix below), `test-ssh-load-root.sh`, `test-browser-enforcement-root.sh`, `test-ssh-enforcement-root.sh`, `test-continuity-root.sh` all PASS. The migration live matrix (disposable-profile reader recording) remains documented as a real-host script; the exact-instance bindings are exercised by the broker/enforcement suites.

### Fix required by the live run
`should_record_decision`/`event_visible_in_build` now record SSH `AllowByLease` decisions in release builds: without it, a successful lease-granted key load had no audit evidence (the broker assertion "first ssh-add private-key open recorded ALLOW_BY_LEASE" failed). This is the SSH-key accountability path.

## Truthfulness verdict

| Claim | Verdict | Evidence |
|---|---|---|
| no whole-tree authority (policy) | PREVENTED (unit) | policy `Bound` exact-instance match; tree-walk functions deleted; unbound-helper + pid-reuse tests |
| no whole-tree authority (bind sites) | PREVENTED (unit) | `refresh_migration_states`/`pending_migration_details` bind exact opener; `target_browser_root` deleted |
| migration real browser flow still works | PREVENTED (unit) | `migration_lease_authorize_then_cross_browser_allowed`, `pending_migration_approval_binds_the_triggering_browser_instance` (both green); live matrix BLOCKED |
| all lease authority dies on continuity loss | PREVENTED (unit) | revoke_all_authority + generation bump; stale-gen defense-in-depth test with simulated revocation miss |
| SSH read exact reader + short TTL + generation bound | PREVENTED (unit) | exact-root match + generation check; stale-gen SSH-read test |
| SSH load exact invocation + agent socket + one-shot | PREVENTED (unit) | pre-existing checks green (`ssh_agent_bindings` path, one-shot consumed on exit); harness BLOCKED live |
| no read-only overclaim | PREVENTED (unit/static) | guardd reports `read_only_guaranteed=None/false` (ipc.rs); `migration_access_lease_does_not_claim_read_only_enforcement` green |

## Residual limitations
- Live migration authority matrix (real Chrome/Chromium→Firefox readers, whether the reader is the browser process or a helper) requires disposable-profile runs on a real host — BLOCKED here; LFH6 covers cross-family compatibility.
- Post-bind observed exact descendant is implemented for the manual armed lease and the approval flow (exact opener). A separate mechanism for *explicitly* binding a different descendant later (e.g., a UI action) is not implemented — by design LFH5 defaults to exact opener only.
- No fanotify live evidence in this environment; all verdicts are unit-level or static.

## Final phase verdict
`CODE + UNIT COMPLETE; LIVE GATES PASS (real host: ssh-broker 29/29 incl. ALLOW_BY_LEASE audit, ssh-load, browser/ssh enforcement, continuity); migration disposable-profile matrix documented as real-host script`
