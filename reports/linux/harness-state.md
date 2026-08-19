# Linux Harness State

## Goal
`LINUX_FILE_SHIELD_FREEZE` — LFH0 → LFH7, then freeze Linux File Shield.

## Baseline
- HEAD: 84a1bd133c78c41911d82dac5ffd1989a7722f5b
- kernel: 7.1.8-arch1-3 (x86_64, Arch Linux), fs: / ext4
- installed browsers: firefox only (chromium/google-chrome/zen NOT installed)
- privileged environment: `sfg-test-capsule` (systemd-nspawn) — nspawn default seccomp blocks `fanotify_init`/`fanotify_mark` (EPERM even with CAP_SYS_ADMIN; verified by syscall probe + systemd v261 `nspawn-seccomp.c` whitelist)

## Current phase
`COMPLETE` — all LFH0→LFH7 gates PASS: 20/20 privileged live scripts green on the real host (`evidence/live-host-20260819-122244/`), quality gates clean. Freeze declared: `reports/linux/linux-file-shield-freeze-final.md`

## Completed gates
- [x] LFH0 — all gates; `reports/linux/lfh0-baseline.md` + evidence written
- [x] LFH1 A: FAN_REPORT_PIDFD group (`new_content_with_pidfd`) + info-record parser (walks by info_type, malformed → `MalformedInfoRecord` fail-closed, no fixed record order)
- [x] LFH1 A: daemon prefers pidfd group; legacy fallback reports truthfully (pidfd_enabled=false → REDUCED(legacy_process_identity))
- [x] LFH1 A: event pidfd validated against event pid (`pidfd_matches` via `/proc/self/fdinfo/<pidfd>` Pid:); mismatch/missing → Deny + `pidfd_failure_audit_record` BEFORE any confirmation enqueue
- [x] LFH1 A: pidfd closed exactly once after decision (normal + fail-closed paths)
- [x] LFH1 A: `pidfd_enabled` + `pidfd_missing_events` surfaced in StatusInfo.linux_health + guardctl status
- [x] LFH1 B: `resolve()` now opens `/proc/<pid>/exe` once, `fstat`s the ACTUAL executed object for dev/ino/owner/mode; readlink kept only as display/registry clue
- [x] LFH1 B: `EnrollmentStore::verify_fd` hashes the executed-object fd, tolerates `(deleted)` suffix, never re-opens the pathname
- [x] LFH1 B tests: executed-image survives pathname replacement; survives unlink; new process at replaced path does not inherit enrollment
- [x] LFH1 C: PID-reuse cache invalidation test (starttime mismatch forces fresh resolve, old identity never transfers)
- [x] LFH1 root script: `scripts/linux/test-pidfd-root.sh` (deterministic; run as root on a fanotify-capable host)
- [ ] LFH1 live pidfd acceptance — BLOCKED: nspawn seccomp blocks fanotify; pkexec now prohibited by policy

## Completed gates (this session)
- LFH0 baseline: config explicit mode, health split, overflow wording, capability inventory, benchmark, privileged suite (host, pre-capsule)
- LFH1: FAN_REPORT_PIDFD group + info-record parsing, pidfd validation/close, actual-executed-image identity (fd), enrollment verify_fd, PID-reuse fail-closed — **LIVE PASS** (test-pidfd-root 5/5)
- LFH2: opaque object handles (name_to_handle_at via O_PATH magic link), (dev,ino)->candidate index, rename-away recognition, inode-reuse rejection — **LIVE PASS** (test-object-identity-root); Step 3 gap NOT ACCEPTED
- LFH3: sticky ProtectionContinuity, lose_continuity revokes all leases/bindings/cache, pending deny_all, overflow+mark-loss wiring, status reports historical LOST — **LIVE PASS** (test-continuity-root)
- LFH4: guard-fdstore helper (store/claim fanotify group via fdstore), CRASH_AFTER_READ_BEFORE_RESPONSE test hook, experiment-fdstore-root.sh — **LIVE ACCEPTED** (fdstore preserved group; queued event answered after restart; marks enforce)
- LFH5: EXACT READER INSTANCE authority (no whole-tree grants) + continuity-generation-bound leases; `stale_lease_generation`; both bind sites exact opener; runtime generation bump — **LIVE PASS** via ssh-broker (29/29, incl. ALLOW_BY_LEASE audit evidence) + ssh-load + browser/ssh enforcement scripts
- LFH6: real Firefox disposable-profile compat (offline test PASS + live root script 8/8: probes denied, no unexpected DENY, continuity INTACT, 0 overflow/classifier); Chromium NOT INSTALLED → cross-family NOT ACCEPTED; benchmark PASS (perf gate)
- LFH7: freeze review — checklist walked with live evidence; **IMPLEMENTATION FREEZE** declared; quality gates clean

### Live-run fixes (real-host, previously-unexercised code)
- `enforce.rs`/`ipc.rs`: SSH AllowByLease audited in release builds (accountability evidence).
- `guard-fdstore`: fanotify_mark flags bug; cmsg ordering UB + unconnected sendmsg; legacy FAN_DENY=0 → `libc::FAN_DENY` (0x02).
- Root scripts: IPC protocol 2→5; stale pre-LFH0 SSH assertions → fail-closed model; `enforcement_active` readiness; `setpriv` probe pids; fixtures pre-guardd; `/etc/guardd` mkdir; fdstore base unit + probe-2 timing.

## Open blockers
| Severity | Item | Evidence | Next action |
|---|---|---|---|
| none | all mandatory File Shield live gates PASS on the real host (20/20) | evidence/live-host-20260819-122244/ | — |
| INFO | Only Firefox installed; LFH6 cross-family needs a Chromium executable | command -v chromium/google-chrome empty | NOT INSTALLED (not FAIL); cross-family NOT ACCEPTED |
| INFO | LFH2 never-opened-before rename-in gap | needs second FAN_CLASS_NOTIF+FID topology group | deferred by design; NOT ACCEPTED |

## Privileged/live evidence
| Harness | Result | Evidence path | Notes |
|---|---|---|---|
| FULL GATE RUN (20 scripts) | **ALL PASS (20/20)** | evidence/live-host-20260819-122244/ | real host, sudo; includes pidfd 5/5, fdstore ACCEPTED, ssh-broker 29/29, native-browser 8/8, benchmark |
| LFH0 host suite (pre-capsule policy) | all PASS on host | evidence/lfh0-privileged-suite.txt | historical host fanotify |
| LFH0 benchmark (host) | PASS, 0 overflow | evidence/lfh0-benchmark.txt | perf baseline |

## Security posture snapshot
- File Shield: **ACTIVE (formal)** — strict-filesystem on the real host; all 20 live gates PASS
- Continuity: overflow → LOST + full revoke + generation bump implemented and live-verified
- Authority: EXACT READER INSTANCE (no whole-tree leases) + generation-bound leases; SSH loads audited (ALLOW_BY_LEASE)
- Process Shield: UNSUPPORTED (inventory only)
- Identity: pidfd validation + actual-executed-image (fd) live-verified
- Overall: **ACTIVE on accepted strict-filesystem capability set; REDUCED with exact reason for legacy/unsupported**

## Residual NOT ACCEPTED
- LFH2 rename-in gap (deferred topology group; NOT ACCEPTED, not a blocker)
- LFH6 cross-family browser acceptance (no Chromium executable; NOT INSTALLED = not FAIL)
- Flatpak/Snap/network FS (no live acceptance; not claimed)

## Next exact action
None — `LINUX_FILE_SHIELD_FREEZE` complete: all phases done, 20/20 live gates PASS, freeze declared in `reports/linux/linux-file-shield-freeze-final.md`.
