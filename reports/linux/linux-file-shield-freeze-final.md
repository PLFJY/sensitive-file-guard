# Linux File Shield — Freeze Review Status (post external security review)

Baseline: commit `3cdf844` (LFH0–LFH7 implementation freeze, live gates 20/20 pre-review) was
**REJECTED by the external security review with 12 findings**. Kernel `7.1.8-arch1-3` (x86_64).
This document records the review-closure state. **IMPLEMENTATION FREEZE IS NOT RESTORED** — it
may only be restored when every finding below is closed and every mandatory live gate passes
without a BLOCKED counted as PASS (HARNESS §8).

## Review findings — closure status

| # | Finding | Closure | Evidence |
|---|---|---|---|
| F1 | exit-code standardization 0=PASS / 1=FAIL / 2=BLOCKED; mandatory BLOCKED gates must not count as PASS | CLOSED | `scripts/linux/run-all-root-gates.sh` + `rerun-review-batch.sh` aggregate 0/1/2 separately; `test-continuity-root.sh` exits 2 when mandatory gates BLOCKED (verified live rc=2); `test-bypass-root.sh` same |
| F2 | test-object-identity must run on a real isolated filesystem (TEST_FS_ROOT), not / | CLOSED | `scripts/linux/test-object-identity-root.sh` auto loop-backed ext4 (or explicit TEST_FS_ROOT, rejects root mount/tmpfs with exit 2); live 8/8 PASS |
| F3 | LFH2 Step 3 topology group for never-opened-before rename-in | **CLOSED (R1)** | cross-group ordering implemented (permission hot path synchronously drains causally-prior topology events under the learner's mutex); `FAN_REPORT_TARGET_FID` (0x1000) makes move events carry the moved file's OWN fid (verified by C probes) — learned directly, no resolution race. LIVE zero-settle fast attack 10000/10000 denied (0 recovery), settled 1000/1000, runtime-subdir 200/200 (evidence: live-host-step3-target-20260820-011146) |
| F4 | handle-verify fail-closed (from_fd failure must be Error, not allow) | CLOSED | `strict.rs::match_learned_handles` → `StrictClassification::Error`; `INJECT_HANDLE_VERIFY_FAILURE` test hook; unit test `handle_verify_failure_on_learned_candidate_fails_closed` |
| F5 | handle_index capacity fail-closed (no eviction of learned targets) | UPDATED (R2) | no eviction of learned targets stays; the "fail-closed" claim was NOT operation-level (a full index merely refused learning + health DEGRADED — a new object could be read after rename-out). Now: when the learned-handle indexes are exhausted, ANY unverifiable non-path-classified open is DENIED (`unrelated_or_exhausted` → Error) — operation-level fail-closed; unit test `exhausted_index_denies_unverifiable_new_object_rename_out` |
| F6 | ObjectHandle alignment (file_handle cast UB) | CLOSED | `AlignedBuffer` repr(C, align(8)) + `read_unaligned`; unit tests pass |
| F7 | LFH4 Experiment B must be implemented, not claimed | CLOSED (verdict: PARTIAL) | crash hook in guardd AND guard-fdstore (`CRASH_AFTER_READ_BEFORE_RESPONSE`/`_MARKER`); live: marker proves read, opener **STILL BLOCKED** after restart → not recoverable via public UAPI; fdstore = experimental hardening only (see lfh4 report) |
| F8 | fdstore production wording (experimental, not integrated) | CLOSED | lfh4 report + this doc: `deploy/guardd.service` remains `Type=simple`, fail-open-on-crash documented; no fdstore integration claimed |
| F9 | LFH3 overflow vocabulary (overflow = DETECTED, continuity = LOST, revoked; overall REDUCED; live overflow gate BLOCKED) | CLOSED | lfh3 report rewritten with exact vocabulary; live continuity/revocation gate PASS, live overflow-generation gate BLOCKED |
| F10 | topology-race strict-mode rerun | CLOSED (LIVE VERIFIED) | `test-topology-race-stress-root.sh` with `ENFORCEMENT_MODE=strict-filesystem`: 10000 iterations, 0 successful unauthorized reads, 10000 denied (batch 20260819-231529) |
| F11 | Chromium wording (accepted browser set = Firefox only; Chromium-family NOT ACCEPTED) | CLOSED | this doc + harness-state: native-browser compat 8/8 covers ONLY Firefox; Chromium/Chrome/Zen NOT ACCEPTED (no live acceptance, not a FAIL) |
| F12 | final quality gates (fmt/clippy/test/diff --check) + rerun all affected live gates | CLOSED | fmt/clippy/test/diff clean; review batch 2 PASS=4 FAIL=0 BLOCKED=1 (fdstore `VERDICT: PARTIAL`, topology-race strict, bypass, object-identity 8/8) |

## Current posture (NOT frozen)

- **Implementation freeze: NOT RESTORED.** Freeze requires: no P0/P1 open, no unexplained browser
  regression, **no blocked mandatory live gate counted as PASS**, no truthfulness mismatch.
- Mandatory live gates still BLOCKED in this environment (per HARNESS §8 these prevent COMPLETE):
  - live kernel fanotify-queue-overflow gate (no deterministic generator) → `test-continuity-root.sh` BLOCKED rc=2 (verified).
  - mark-loss live simulation requires an unmountable test FS → BLOCKED (documented in the script).
- Accepted browser set: **Firefox only** (`test-native-browser-compat-root.sh` PASS 8/8).
  **Chromium-family (chromium/google-chrome/zen) NOT ACCEPTED** — NOT INSTALLED on this host is
  reported as NOT ACCEPTED (not FAIL, not PASS).
- fdstore crash continuity: **PARTIAL — Experiment B not recoverable via public UAPI; crash
  continuity REDUCED; fdstore experimental hardening only.**
- LFH2 never-opened-before rename-in gap: **CLOSED** (startup snapshot + topology learner, live 8/8).

## Evidence
- Review-closure batch 2 (20260819-231529): **PASS=3 FAIL=1 BLOCKED=1** (its own summary.txt) —
  PASS: bypass, object-identity 8/8, topology-race strict 10000/10000 denied; FAIL: fdstore first run
  (probe-2 attribution script bug — fixed); BLOCKED: continuity under the OLD gate. The fdstore
  single-gate rerun afterwards was clean (`experiment-fdstore-rerun.log`, PASS=7 FAIL=0
  `VERDICT: PARTIAL`) and is recorded as a separate run, never back-filled into the batch.
- Review-closure batch 3 (R1 zero-settle / R3 overflow / R4 mark-loss): pending live run.
- Pre-review (stale, superseded by review requirements): `evidence/live-host-20260819-122244/` (20/20).

## Final verdict
`IMPLEMENTATION FREEZE NOT RESTORED — external review's 12 findings F1–F12 are closed in code/reports
and re-verified LIVE (final batch PASS=4 FAIL=0 BLOCKED=1; F7 verdict PARTIAL, F9 REDUCED,
F10 strict 10000/10000 denied, F11 Firefox-only). Per HARNESS §8 the goal cannot be COMPLETE while
mandatory live gates (kernel overflow, mark-loss) remain BLOCKED in this environment.`
