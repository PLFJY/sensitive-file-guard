# Linux File Shield — Freeze Review Status (post external security review)

Baseline: commit `3cdf844` (LFH0–LFH7 implementation freeze, live gates 20/20 pre-review) was
**REJECTED by the external security review with 12 findings** plus the user's R1–R6 follow-up,
and then **REJECTED AGAIN by the user's own post-freeze audit with P0+P1 findings**. Kernel
`7.1.8-arch1-3` (x86_64). This document records the review-closure state. **IMPLEMENTATION FREEZE
IS NOT RESTORED** until the P0/P1 review is closed: P0 + P1-a..P1-e are closed in code and
unit-tested (d1ddd2e, e9380f8); P0/P1-b/P1-c are capsule LIVE VERIFIED; P1-d needs the host
isolated loop ext4 rerun (capsule tmpfs has no name_to_handle_at). The previous freeze evidence
(`evidence/live-host-20260820-041545`: PASS=21 FAIL=0 BLOCKED=0) is HISTORICAL / superseded by
this reopened review.

## Review findings — closure status

| # | Finding | Closure | Evidence |
|---|---|---|---|
| F1 | exit-code standardization 0=PASS / 1=FAIL / 2=BLOCKED; mandatory BLOCKED gates must not count as PASS | CLOSED | `run-all-root-gates.sh` + `rerun-review-batch.sh` aggregate 0/1/2 separately; `test-continuity-root.sh`/`test-bypass-root.sh` exit 2 on mandatory BLOCKED |
| F2 | test-object-identity must run on a real isolated filesystem (TEST_FS_ROOT), not / | CLOSED | `test-object-identity-root.sh` auto loop-backed ext4 / `TEST_FS_ROOT` (root mount/tmpfs → exit 2) |
| F3 | LFH2 Step 3 topology group for never-opened-before rename-in | **CLOSED (R1)** | cross-group ordering + `FAN_REPORT_TARGET_FID` target-fid learning; LIVE zero-settle fast attack 10000/10000 denied (0 recovery), settled 1000/1000, runtime-subdir 200/200 |
| F4 | handle-verify fail-closed (from_fd failure must be Error, not allow) | CLOSED | `match_learned_handles` → Error; injection hook + unit test |
| F5 | handle_index capacity fail-closed (no eviction of learned targets) | CLOSED (R2) | no eviction; when exhausted, unverifiable opens denied (`unrelated_or_exhausted` → Error) — operation-level fail-closed; unit test |
| F6 | ObjectHandle alignment (file_handle cast UB) | CLOSED | `AlignedBuffer` repr(C,align(8)) + `read_unaligned` |
| F7 | LFH4 Experiment B must be implemented, not claimed | CLOSED (verdict: PARTIAL) | crash hook guardd+guard-fdstore; live: read-but-unanswered NOT recoverable via public UAPI; fdstore = experimental hardening only |
| F8 | fdstore production wording (experimental, not integrated) | CLOSED | `deploy/guardd.service` `Type=simple`, fail-open-on-crash documented, no integration claimed |
| F9 | LFH3 overflow vocabulary | CLOSED — **deterministic real kernel overflow LIVE VERIFIED** | `max_queued_events`+SIGSTOP+concurrent opens → real `FAN_Q_OVERFLOW` → `fanotify_overflows`++ → continuity LOST + authority revoked; dropped events NOT individually PREVENTED; overall continuity posture REDUCED after loss |
| F10 | topology-race strict-mode rerun | CLOSED (LIVE VERIFIED) | `ENFORCEMENT_MODE=strict-filesystem`: 10000 iterations, 0 unauthorized reads, 10000 denied |
| F11 | Chromium wording (accepted browser set = Firefox only; Chromium-family NOT ACCEPTED) | CLOSED | native-browser compat 8/8 covers ONLY Firefox; Chromium/Chrome/Zen NOT ACCEPTED |
| F12 | final quality gates + rerun all affected live gates | CLOSED | **fresh full suite PASS=21 FAIL=0 BLOCKED=0** (live-host-20260820-041545); fmt/clippy/test/diff clean |

## Current posture (REVIEW REOPENED — P0/P1 IN LIVE VERIFICATION)
- **Implementation freeze: NOT RESTORED.** The user's post-freeze audit (P0 SSH mmap boundary;
  P1-a pidfd terminal no-mutation; P1-b topology fail-closed + persistent health; P1-c autonomous
  mark-loss; P1-d fsid-keyed topology identity; P1-e parser fixes) is being closed with capsule
  live verification:
  - **P0 SSH mmap — capsule LIVE VERIFIED (3/3)**: `FAN_OPEN_PERM` is the authorization boundary;
    unknown mmap/read of the private key denied at open; audit deny recorded.
  - **P1-b topology overflow — capsule LIVE VERIFIED (5/5)**: rename burst → topology queue
    overflow → sticky `topology_uncertain` → `file_shield=REDUCED`; ambiguous outside-path open
    fails closed (denied) while uncertain.
  - **P1-c autonomous mark-loss — capsule LIVE VERIFIED (8/8)**: real `FAN_MARK_REMOVE` on the
    live group detected AUTONOMOUSLY (no status query) within 1s → continuity
    `LOST(required_filesystem_mark_lost)` + REDUCED + audit committed (immediate flush); sticky;
    enforcement resumes after mark restore.
  - **P1-a pidfd terminal — live group verified (5/5) + unit/code-order verified** (mismatch
    trigger not deterministically live-testable — documented).
  - **P1-d fsid-keyed topology identity — code + unit-tested; capsule UNAVAILABLE** (tmpfs has
    no `name_to_handle_at`); host isolated loop ext4 rerun of zero-settle/object-identity
    regressions pending.
  - **P1-e parser — unit-tested + live sanity** (44000-event capsule burst parsed cleanly).
- Accepted browser set: **Firefox only** (`test-native-browser-compat-root.sh` PASS 8/8).
  **Chromium-family (chromium/google-chrome/zen) NOT ACCEPTED** (NOT INSTALLED on this host).
- fdstore crash continuity: **PARTIAL — Experiment B not recoverable via public UAPI; crash
  continuity REDUCED; fdstore experimental hardening only.**
- LFH2 never-opened-before rename-in gap: **CLOSED** (cross-group ordering + target-fid learning,
  zero-settle 10000/10000 denied under the pre-P0/P1 code; fsid-key rerun pending per P1-d).
- Safety: guardd REFUSES to start when strict-filesystem would mark the root mount (two real
  lockups; AGENTS.md LIVE-TEST SAFETY). This is a **SAFETY REFUSAL**, not fanotify unsupported.
- Capsule: nspawn seccomp now allows fanotify + pidfd_getfd (`--system-call-filter=fanotify_init
  fanotify_mark pidfd_getfd`); live gates mark only fresh capsule-internal tmpfs instances.

## Evidence
- **P0/P1 capsule live verification (2026-08-20)**: capsule runners in
  `scripts/linux/capsule/` — `p0-capsule-run.sh` (P0 SSH mmap 3/3),
  `p1b-capsule-run.sh` (topology overflow 5/5), `p1c-capsule-run.sh` (autonomous mark-loss 8/8),
  plus `test-pidfd-root.sh` live (5/5) and the guardd-exact fanotify matrix probe.
- **Previous (HISTORICAL / superseded by this reopened review)**: `evidence/live-host-20260820-041545/`
  — fresh full LFH0–LFH7 suite, **PASS=21 FAIL=0 BLOCKED=0** (continuity R3/R4 LIVE, zero-settle
  0 recovery, fdstore PARTIAL) under the pre-P0/P1 code.
- **HISTORICAL / SUPERSEDED**: review batches 1–3 (`live-host-review-batch-20260819-222651`,
  `-231529`, and the R1/R3/R4 step3/continuity runs) and the pre-review 20/20
  (`live-host-20260819-122244`). Their per-run results were accurate at the time but are superseded;
  historical evidence files are unchanged.

## Final verdict
`FREEZE REJECTED / REVIEW REOPENED — P0 + P1-a..P1-e (user audit) are closed in code and
unit-tested (d1ddd2e, e9380f8) with capsule live verification: P0 SSH mmap 3/3, P1-b topology
overflow fail-closed 5/5, P1-c autonomous mark-loss 8/8, P1-a pidfd group 5/5. REMAINING before
FREEZE: P1-d fsid-keyed zero-settle/object-identity rerun on the host isolated loop ext4
(capsule tmpfs has no name_to_handle_at — honestly BLOCKED in capsule, not claimed PASS), then a
fresh full suite, then truthful report update. LFH4 remains PARTIAL / crash continuity REDUCED.
Safety: guardd refuses root-mount FAN_MARK_FILESYSTEM; capsule marks only fresh tmpfs instances.`
