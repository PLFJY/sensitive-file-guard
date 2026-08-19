# Linux File Shield — Freeze Review Status (post external security review)

Baseline: commit `3cdf844` (LFH0–LFH7 implementation freeze, live gates 20/20 pre-review) was
**REJECTED by the external security review with 12 findings** plus the user's R1–R6 follow-up.
Kernel `7.1.8-arch1-3` (x86_64). This document records the review-closure state. **IMPLEMENTATION
FREEZE IS RESTORED** after every finding and every mandatory live gate passed on a FRESH full run
(evidence/live-host-20260820-041545: PASS=21 FAIL=0 BLOCKED=0) without a BLOCKED counted as PASS
(HARNESS §8).

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

## Current posture (FROZEN)
- **Implementation freeze: RESTORED.** Conditions met: no P0/P1 open, no unexplained browser
  regression, **no mandatory live gate BLOCKED counted as PASS**, no truthfulness mismatch.
- Accepted browser set: **Firefox only** (`test-native-browser-compat-root.sh` PASS 8/8).
  **Chromium-family (chromium/google-chrome/zen) NOT ACCEPTED** (NOT INSTALLED on this host).
- fdstore crash continuity: **PARTIAL — Experiment B not recoverable via public UAPI; crash
  continuity REDUCED; fdstore experimental hardening only.**
- LFH2 never-opened-before rename-in gap: **CLOSED** (cross-group ordering + target-fid learning,
  zero-settle 10000/10000 denied).
- Safety: guardd REFUSES to start when strict-filesystem would mark the root mount (two real
  lockups; AGENTS.md LIVE-TEST SAFETY). This is a **SAFETY REFUSAL**, not fanotify unsupported.

## Evidence
- **Current (authoritative)**: `evidence/live-host-20260820-041545/` — fresh full LFH0–LFH7 suite,
  **PASS=21 FAIL=0 BLOCKED=0** (continuity R3/R4 LIVE, zero-settle 0 recovery, fdstore PARTIAL).
- **HISTORICAL / SUPERSEDED**: review batches 1–3 (`live-host-review-batch-20260819-222651`,
  `-231529`, and the R1/R3/R4 step3/continuity runs) and the pre-review 20/20
  (`live-host-20260819-122244`). Their per-run results were accurate at the time but are superseded
  by the fresh 041545 run; historical evidence files are unchanged.

## Final verdict
`IMPLEMENTATION FREEZE RESTORED, GOAL COMPLETE — all 12 review findings F1–F12 and the user's
R1–R6 are closed and LIVE-VERIFIED on a FRESH full run (evidence/live-host-20260820-041545:
PASS=21 FAIL=0 BLOCKED=0): F3 zero-settle fast attack 10000/10000 denied (target-fid);
R3 deterministic live overflow + R4 real mark-loss LIVE; no mandatory BLOCKED; full suite clean;
reports truthful. LFH4 remains PARTIAL / crash continuity REDUCED (experimental fdstore, not
upgraded to ACCEPTED). Safety: guardd refuses root-mount FAN_MARK_FILESYSTEM; every strict test
runs on an isolated loop ext4 (AGENTS.md LIVE-TEST SAFETY).`
