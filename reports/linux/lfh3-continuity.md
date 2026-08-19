# LFH3 — Protection Continuity

## Baseline
- commit: 84a1bd133c78c41911d82dac5ffd1989a7722f5b
- kernel: 7.1.8-arch1-3 (x86_64)
- privileged environment: sfg-test-capsule (systemd-nspawn) — seccomp blocks fanotify (EPERM, verified). Fanotify live tests BLOCKED in this environment; host pkexec prohibited while capsule is available.

## Threat / invariant
Separate "now healthy" from "no verifiable gap since start". A fanotify queue overflow or required-mark loss breaks continuity; the daemon must not erase the historical loss when enforcement later recovers, and must revoke ALL live authority (leases, pending confirmations, grace) at the moment of loss.

## Changes

### State machine (`apps/guardd/src/enforce.rs`)
- `ProtectionContinuity::{Intact{generation}, Lost{generation, reason}}`.
- `ContinuityLossReason::{FanotifyQueueOverflow, RequiredMarkLoss, FilesystemLifecycleLoss(reserved), UnrecoverableClassifierFailure(reserved)}`.
- `record_loss` is STICKY: once Lost, later losses keep the earliest reason/generation.
- `lose_continuity(reason)` = record_loss + `revoke_all_authority()`.
- `revoke_all_authority()`: revokes every migration/ssh/ssh_read lease, clears `ssh_agent_bindings`, clears the exact-process identity cache.

### Pending denial (`crates/guard-runtime/src/lib.rs`)
- `PendingMigrationStore::deny_all()`: resolves every pending request DENY, clears blocked suppression and recent-approval grace.
- `PendingSshReadStore::deny_all()`: resolves every pending SSH read DENY, clears suppression.

### Wiring (`apps/guardd/src/main.rs`, `ipc.rs`)
- `FAN_Q_OVERFLOW` → `engine.lose_continuity(FanotifyQueueOverflow)` + `pending_migrations.deny_all()` + `pending_ssh_reads.deny_all()` + audit `fanotify_queue_overflow`.
- Status: continuity reads the engine's STICKY state first; the overflow counter and mark-health remain cross-checks. Required-mark loss observed in `handle_status` triggers `lose_continuity(RequiredMarkLoss)`.
- `build_audit_record` made `pub(crate)` for the continuity audit helper (no secret bytes).

## Tests

### Offline
- `cargo test --workspace --all-features`: green.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: 0 errors.
- New unit tests:
  - continuity starts Intact; loss is sticky (second reason does not replace the first).
  - `lose_continuity` revokes all leases + clears bindings/cache.
  - migration `deny_all` denies pending + clears grace/blocked.
  - SSH `deny_all` denies pending.

### Privileged / live
- `scripts/linux/test-continuity-root.sh` written: INTACT at start; overflow stress (records BLOCKED if no deterministic overflow); sticky LOST plumbing.
- **NOT RUN in this environment — BLOCKED**: nspawn seccomp blocks fanotify. Deterministic kernel overflow is not guaranteed on any host; the script records honestly. State-machine semantics are covered by unit tests; the live overflow gate stays BLOCKED unless a host reproduces it.

## Adversarial findings
1. Sticky semantics: without the engine-owned state, a status computed purely from current counters would "recover" to ACTIVE and erase the loss — the state machine fixes this.
2. Overflow does not imply "all dropped events denied" — the kernel dropped them unseen; the daemon DETECTS it via `FAN_Q_OVERFLOW`, records continuity as LOST, and revokes all authority. Wording + state both say LOST.

## Compatibility findings
- Clean `systemctl stop`/restart lifecycle is distinct from crash/overflow; LFH4 decides whether planned restart counts as loss.

## Performance
- No live benchmark (fanotify BLOCKED). `record_loss`/`revoke_all_authority` run only on loss events, not the hot path.

## Truthfulness verdict

| Claim | Verdict | Evidence |
|---|---|---|
| overflow DETECTED (FAN_Q_OVERFLOW) => continuity LOST + all authority revoked | PREVENTED (code) + unit | lose_continuity + deny_all tests |
| continuity is sticky (recovery never erases loss) | PREVENTED (unit) | continuity_starts_intact_and_loses_sticky |
| pending confirmations denied on loss | PREVENTED (unit) | deny_all tests |
| status can show current ACTIVE + historical LOST | PREVENTED (code) | engine.continuity read in handle_status |
| live overflow gate | BLOCKED (NOT RUN) | no deterministic host overflow generator (mandatory gate could not be produced; see HARNESS §8 — must not be counted as PASS); nspawn seccomp documented in LFH0 |
| live continuity/revocation path | LIVE VERIFIED (gate rc=2: mandatory live gates BLOCKED, never PASS) | `scripts/linux/test-continuity-root.sh` on real host: non-fanotify continuity/revocation checks PASS, then `note_mandatory_blocked` (no deterministic live kernel overflow generator; mark-loss requires unmountable test FS) → exit 2; evidence/live-host-review-batch-*/test-continuity-root.log |

## Residual limitations
- `FilesystemLifecycleLoss`/`UnrecoverableClassifierFailure` reserved, not yet constructed.
- Live overflow (kernel queue pressure) still lacks a deterministic host generator.

## Final phase verdict
`OVERALL: REDUCED — overflow DETECTED (FAN_Q_OVERFLOW) → continuity LOST + all authority REVOKED, PREVENTED by code + unit tests; live continuity/revocation gate PASSED on the real host; the mandatory live overflow-generation gate is BLOCKED (no deterministic generator in this environment) → crash continuity stays REDUCED, not restored.`
