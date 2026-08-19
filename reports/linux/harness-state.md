# Linux Harness State

## Goal
`LINUX_FILE_SHIELD_FREEZE` — LFH0 → LFH7, then freeze Linux File Shield. **Freeze requires all
12 external-security-review findings (F1–F12) closed, and no mandatory live gate BLOCKED counted
as PASS (HARNESS §8).**

## Baseline
- HEAD: 3cdf844 (freeze commit) — **rejected by external review; freeze NOT restored**
- kernel: 7.1.8-arch1-3 (x86_64, Arch Linux), fs: / ext4
- installed browsers: firefox only (chromium/google-chrome/zen NOT installed)
- privileged environment: `sfg-test-capsule` (systemd-nspawn) — nspawn default seccomp blocks `fanotify_init`/`fanotify_mark` (EPERM even with CAP_SYS_ADMIN; verified by syscall probe + systemd v261 `nspawn-seccomp.c` whitelist). Live fanotify gates run on the REAL HOST with the user present for polkit auth.

## Current phase
`REVIEW CLOSURE — LIVE RERUN DONE` — the external security review rejected the 3cdf844 freeze with
12 findings. All findings are closed in code/reports/live evidence (F1–F12; F7 verdict PARTIAL,
F9 REDUCED, F10 strict rerun PASS, F11 Firefox-only acceptance). **IMPLEMENTATION FREEZE is NOT
restored and GOAL is NOT COMPLETE**: mandatory live gates (kernel fanotify-queue overflow;
mark-loss live simulation) are BLOCKED in this environment and per HARNESS §8 cannot be counted
as PASS.

## Completed gates (review closure)
- [x] F1 exit codes 0/1/2: `run-all-root-gates.sh` + `rerun-review-batch.sh` aggregate separately; `test-continuity-root.sh`/`test-bypass-root.sh` exit 2 on mandatory BLOCKED (continuity verified rc=2)
- [x] F2 real isolated test fs: `test-object-identity-root.sh` auto loop-backed ext4 / explicit TEST_FS_ROOT (root mount/tmpfs → exit 2); live 8/8 PASS
- [x] F3 LFH2 Step 3: cross-group ordering (sync drain under the learner mutex) + **FAN_REPORT_TARGET_FID** (move events carry the moved file's OWN fid — verified by C probes) → LIVE zero-settle fast attack 10000/10000 denied, 0 recovery; settled 1000/1000; runtime-subdir 200/200 (live-host-step3-target-20260820-011146)
- [x] F4 handle-verify fail-closed: `match_learned_handles` from_fd failure → `StrictClassification::Error`; injection hook + unit test
- [x] F5 handle_index capacity fail-closed: no eviction of learned targets, `handle_index_exhausted` + `handle_index_full` status; unit test 8192+ files
- [x] F6 ObjectHandle alignment: `AlignedBuffer` repr(C,align(8)) + `read_unaligned`; unit tests
- [x] F7 LFH4 Experiment B implemented: crash hook guardd+guard-fdstore; live marker + opener STILL BLOCKED after restart → NOT recoverable via public UAPI → **PARTIAL**, crash continuity REDUCED
- [x] F8 fdstore experimental wording: production `guardd.service` `Type=simple`, fail-open documented, no integration claimed
- [x] F9 LFH3 vocabulary: overflow DETECTED → continuity LOST + revoked; overall REDUCED; live overflow gate BLOCKED
- [x] F10 topology-race strict-mode support: `ENFORCEMENT_MODE=strict-filesystem` rerun scheduled
- [x] F11 Chromium wording: accepted browser set = **Firefox only**; Chromium-family NOT ACCEPTED (NOT INSTALLED ≠ FAIL, but NOT ACCEPTED either)
- [x] F12 quality gates per change batch (fmt/clippy/test/diff --check); final live rerun pending

## Live evidence
| Harness | Result | Evidence path | Notes |
|---|---|---|---|
| review batch 2 | **PASS=3 FAIL=1 BLOCKED=1** (per its own summary.txt): PASS=bypass/object-identity/topology-race strict; FAIL=fdstore first run (probe-2 attribution script bug, fixed); BLOCKED=continuity (old gate) | evidence/live-host-review-batch-20260819-231529/ | the fdstore rerun afterwards (PASS=7 FAIL=0 `VERDICT: PARTIAL`) is a SEPARATE single-gate run in `experiment-fdstore-rerun.log` — never back-filled into the batch summary |
| review batch 3 (R1/R3/R4) | pending live run | evidence/live-host-review-batch-*/ | continuity rewritten: deterministic overflow (max_queued_events + SIGSTOP + concurrent opens) and REAL mark loss (pidfd_getfd + FAN_MARK_REMOVE); step3-zero-settle 10k |
| review batch 1 | PASS=2 (bypass, object-identity), FAIL=1 (fdstore probe-2 attribution — script bug, fixed), BLOCKED=1 (continuity) | evidence/live-host-review-batch-20260819-222651/ | superseded by batch 2 |
| pre-review full run | 20/20 PASS | evidence/live-host-20260819-122244/ | **STALE** — superseded by review requirements (fdstore ACCEPTED wording, Step 3 gap, exit codes) |
| LFH0 host suite | all PASS | evidence/lfh0-privileged-suite.txt | historical host fanotify |
| LFH0 benchmark | PASS, 0 overflow | evidence/lfh0-benchmark.txt | perf baseline |

## Open blockers
| Severity | Item | Evidence | Next action |
|---|---|---|---|
| PENDING LIVE | live kernel fanotify-queue-overflow gate — R3 rewrite: temporarily lower `/proc/sys/fs/fanotify/max_queued_events` (64), create the group under the low limit, restore sysctl, SIGSTOP daemon, 80 concurrent opens → real FAN_Q_OVERFLOW → `fanotify_overflows`++ → LOST | `test-continuity-root.sh` Test A (batch 3) | no longer "no deterministic generator": the sysctl mechanism is deterministic |
| PENDING LIVE | real kernel mark loss — R4 rewrite: `guard-test-probe fsmark-remove` duplicates the exact live permission-group fd (pidfd_open+pidfd_getfd) and `FAN_MARK_REMOVE|FAN_MARK_FILESYSTEM` → fdinfo count drops → LOST(required_filesystem_mark_lost) + audit; restore does NOT erase sticky LOST | `test-continuity-root.sh` Test B (batch 3) | no longer "unmountable test FS": FAN_MARK_REMOVE on the same group is the UAPI way |
| RESOLVED | R1 fast attack — closed by FAN_REPORT_TARGET_FID (0x1000): move events carry the moved file's OWN fid → learned directly, no resolution race | `test-step3-zero-settle-root.sh` §1: 10000/10000 denied, 0 recovery + fid-target.c probe | — |
| INFO | only Firefox installed | `command -v chromium/google-chrome` empty | Chromium-family NOT ACCEPTED (F11) |

## Security posture snapshot
- File Shield: **ACTIVE (strict-filesystem)** on the isolated loop test fs; daemon warns if fs-mark targets the root mount (root-mount marking caused the earlier system-wide lockup — tests now never mark /)
- Continuity: overflow DETECTED → continuity LOST + full revoke + generation bump (code+unit + live revocation path); live overflow-generation gate BLOCKED → crash continuity REDUCED
- Crash continuity: **REDUCED** — fdstore PARTIAL (Experiment B not recoverable via public UAPI); experimental only
- Identity: pidfd validation + actual-executed-image (fd) live-verified; object identity incl. Step 3 SETTLED case live 8/8 (snapshot + topology); the zero-settle attacker path is pending batch 3 (R1)
- Accepted browsers: **Firefox only**; Chromium-family NOT ACCEPTED
- Overall: **ACTIVE on accepted capability set; REDUCED with exact reason (crash continuity, legacy/unsupported); NOT ACCEPTED (Chromium-family, Flatpak/Snap/network FS); BLOCKED mandatory live gates prevent FREEZE/COMPLETE**

## Next exact action
Batch 3 live run in flight (R1 zero-settle 10k / R3 deterministic overflow / R4 real mark-loss).
If all three PASS, run R6: a NEW final evidence dir with the FULL LFH0–LFH6 privileged suite
(`run-all-root-gates.sh`, now including `test-step3-zero-settle-root.sh`), then quality gates
(fmt/clippy/test/diff), then update this doc and commit. Freeze stays NOT RESTORED until
F3 race-safe (zero-settle 0 recovery), overflow + mark-loss LIVE VERIFIED, no mandatory BLOCKED,
full suite clean, and no truthfulness mismatch.
