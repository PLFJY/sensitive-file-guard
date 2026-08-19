# Linux Harness State

## Goal
`LINUX_FILE_SHIELD_FREEZE` — LFH0 → LFH7, then freeze Linux File Shield. **Freeze requires all
12 external-security-review findings (F1–F12) and the follow-up R1–R6 closed, with no mandatory
live gate BLOCKED counted as PASS (HARNESS §8).** This goal is **COMPLETE** (see Current phase).

## Baseline
- HEAD: latest `main` (see `git log -1 --oneline`); the freeze commit `3cdf844` was **rejected by
  the external security review with 12 findings** and re-accepted only after R1–R6 were closed and
  the fresh full suite passed (HISTORICAL: rejection superseded).
- kernel: 7.1.8-arch1-3 (x86_64, Arch Linux), fs: / ext4
- installed browsers: firefox only (chromium/google-chrome/zen NOT installed)
- privileged environment: `sfg-test-capsule` (systemd-nspawn) — nspawn seccomp blocks fanotify;
  live fanotify gates run on the REAL HOST via polkit/pkexec.

## Current phase
`COMPLETE — IMPLEMENTATION FREEZE RESTORED, GOAL COMPLETE`.

- **Current authoritative live evidence**: `reports/linux/evidence/live-host-20260820-041545/`
  — fresh full LFH0–LFH7 privileged suite: **PASS=21 FAIL=0 BLOCKED=0** (summary.txt).
  - LFH2 zero-settle (Step 3, R1): `10000` iterations, `successful_unauthorized_reads=0`,
    `denied_reads=10000` (`test-step3-zero-settle-root.sh`).
  - LFH3 continuity (R3/R4): `PASS=14 FAIL=0 BLOCKED=0 MANDATORY_BLOCKED=0`; real kernel
    `FAN_Q_OVERFLOW` verified (deterministic via `max_queued_events`+SIGSTOP), real
    `FAN_MARK_REMOVE` mark-loss verified, sticky `LOST` verified.
  - LFH4 fdstore: `VERDICT=PARTIAL` — experimental hardening only; **crash continuity stays
    REDUCED** (NOT upgraded to ACCEPTED).
  - benchmark: no fanotify overflow, no classifier failure.
- **Safety**: guardd REFUSES to start when strict-filesystem would mark the root mount
  (`GUARDD_ALLOW_ROOT_FS_MARK=1` only overrides); every strict live test runs on an isolated
  loop-backed ext4 (AGENTS.md LIVE-TEST SAFETY, added after lockup #2). Three strict-mode live
  bugs were found and fixed by the isolated-fs runs (O_PATH exe-resolution deadlock; inode-reuse
  false Protected after rename-over; `(deleted)` readlink artifacts) — all closed in `main`.
- **Quality gates**: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace
  --all-features`, `git diff --check` all clean.

## Completed gates (review closure, F1–F12)
- [x] F1 exit codes 0/1/2; mandatory BLOCKED never counted as PASS — `run-all-root-gates.sh` /
      `rerun-review-batch.sh` aggregate separately.
- [x] F2 real isolated test fs — auto loop-backed ext4 / `TEST_FS_ROOT` (root mount/tmpfs → exit 2).
- [x] F3 LFH2 Step 3 (R1) — cross-group ordering + `FAN_REPORT_TARGET_FID` target-fid learning;
      **LIVE zero-settle fast attack 10000/10000 denied (0 recovery)**, settled 1000/1000,
      runtime-subdir 200/200.
- [x] F4 handle-verify fail-closed (`match_learned_handles` from_fd failure → Error).
- [x] F5 handle_index capacity — operation-level fail-closed (unverifiable opens denied when
      exhausted) + unit test.
- [x] F6 ObjectHandle alignment (`AlignedBuffer` + `read_unaligned`).
- [x] F7 LFH4 Experiment B — live: read-but-unanswered NOT recoverable via public UAPI →
      **PARTIAL**, crash continuity REDUCED.
- [x] F8 fdstore experimental wording (`Type=simple`, fail-open documented, no integration claimed).
- [x] F9 LFH3 overflow vocabulary — **deterministic real kernel overflow LIVE VERIFIED**:
      overflow => DETECTED, continuity => LOST, authority revoked; overall continuity posture
      REDUCED after loss; dropped events NOT individually PREVENTED.
- [x] F10 topology-race strict-mode rerun — 10000/10000 denied, 0 unauthorized reads.
- [x] F11 Chromium wording — accepted browser set = **Firefox only**; Chromium-family NOT ACCEPTED.
- [x] F12 final quality gates + full rerun — **fresh full suite PASS=21 FAIL=0 BLOCKED=0**
      (evidence/live-host-20260820-041545); quality gates clean.

## Live evidence (current + historical)
| Harness | Result | Evidence path | Notes |
|---|---|---|---|
| **FULL SUITE (current, authoritative)** | **PASS=21 FAIL=0 BLOCKED=0** | evidence/live-host-20260820-041545/ | fresh full LFH0–LFH7 run after all R1–R6 + safety fixes; includes zero-settle 0 recovery, continuity R3/R4 LIVE, fdstore PARTIAL, benchmark |
| review batch 2 | PASS=3 FAIL=1 BLOCKED=1 | evidence/live-host-review-batch-20260819-231529/ | **HISTORICAL / SUPERSEDED** by 041545; fdstore first-run attribution bug (fixed), continuity under the OLD gate |
| review batch 1 | PASS=2 FAIL=1 BLOCKED=1 | evidence/live-host-review-batch-20260819-222651/ | **HISTORICAL / SUPERSEDED** by 041545 |
| review batch 3 (R1/R3/R4) | PASS (continuity + step3 live) | evidence/live-host-step3-target-20260820-011146/ etc. | **HISTORICAL / SUPERSEDED** by 041545; R1/R3/R4 individual live runs |
| pre-review full run | 20/20 PASS | evidence/live-host-20260819-122244/ | **HISTORICAL / SUPERSEDED** (fdstore ACCEPTED wording, Step 3 gap, exit codes — all superseded) |
| LFH0 host suite | all PASS | evidence/lfh0-privileged-suite.txt | **HISTORICAL** (baseline-era host fanotify) |
| LFH0 benchmark | PASS, 0 overflow | evidence/lfh0-benchmark.txt | **HISTORICAL locked performance baseline** (strict unprotected p95=35.3 us, 44673 opens/sec) |

## Open blockers / residual
| Severity | Item | Status |
|---|---|---|
| RESOLVED | R1 fast attack — closed by FAN_REPORT_TARGET_FID: 10000/10000 denied, 0 recovery | resolved in 041545 |
| RESOLVED | R3 deterministic live overflow — max_queued_events+SIGSTOP+concurrent opens | resolved in 041545 (continuity PASS) |
| RESOLVED | R4 real mark-loss — pidfd_getfd + FAN_MARK_REMOVE | resolved in 041545 (continuity PASS) |
| INFO | only Firefox installed | `command -v chromium/google-chrome` empty; Chromium-family NOT ACCEPTED (F11) |
| RESIDUAL LIMITATION | LFH4 fdstore: crash continuity REDUCED (Experiment B not recoverable via public UAPI); experimental hardening only, not integrated | documented, NOT ACCEPTED as production crash semantics |
| RESIDUAL LIMITATION | browser acceptance = Firefox only; Flatpak/Snap/network FS no live acceptance | NOT ACCEPTED |

## Security posture snapshot
- File Shield: **ACTIVE (strict-filesystem)** on the isolated loop test fs. guardd REFUSES a
  root-mount `FAN_MARK_FILESYSTEM` (root-mount marking caused both real lockups; tests never mark /).
- Continuity: **deterministic real kernel overflow LIVE VERIFIED** → overflow DETECTED → continuity
  LOST + authority revoked + generation bump; dropped events NOT individually PREVENTED.
- Crash continuity: **REDUCED** — LFH4 PARTIAL (Experiment B not recoverable via public UAPI);
  fdstore experimental only.
- Identity: pidfd validation + actual-executed-image (fd) live-verified; LFH2 Step 3 (incl. zero-settle
  fast attack) closed and live-verified.
- Accepted browsers: **Firefox only**; Chromium-family NOT ACCEPTED.
- Overall: **ACTIVE on accepted capability set; REDUCED with exact reason (crash continuity,
  legacy/unsupported); NOT ACCEPTED (Chromium-family, Flatpak/Snap/network FS).**

## Next exact action
None — the freeze and review-closure work are complete and live-verified. Subsequent work is
maintenance: keep the performance gate budget executed by `benchmark-strict-filesystem-root.sh`,
and keep AGENTS.md LIVE-TEST SAFETY as hard rules.
