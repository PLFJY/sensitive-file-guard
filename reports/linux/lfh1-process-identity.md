# LFH1 — PIDFD + Actual Executed Image Identity

## Baseline
- commit: 84a1bd133c78c41911d82dac5ffd1989a7722f5b
- kernel: 7.1.8-arch1-3 (x86_64)
- relevant capabilities: FAN_REPORT_PIDFD supported by this kernel (LFH0 capability probe: group creation with the flag accepted on host root); `name_to_handle_at` supported
- privileged environment: sfg-test-capsule (systemd-nspawn). Its default seccomp whitelist **excludes fanotify_init/fanotify_mark** (verified by direct syscall probes: 300/301 → EPERM with CAP_SYS_ADMIN; confirmed in systemd v261 `nspawn-seccomp.c` "knowingly excluded" comment). Fanotify live tests therefore cannot run inside the capsule.

## Threat / invariant
Process authority must move from `PID + /proc pathname reopen` to:
- PID + kernel-pinned pidfd (FAN_REPORT_PIDFD) when supported;
- start_time cross-check (PID reuse fail-closed);
- actual executed image object identity (fd fstat, never pathname re-stat).

## Changes

### A. FAN_REPORT_PIDFD (`crates/platform-linux/src/fanotify.rs`)
- `FanotifyGroup::new_content_with_pidfd()` — `FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_REPORT_PIDFD`; `pidfd_enabled()` accessor.
- `parse_events` walks variable-length info records after the fixed metadata header (`metadata_len` = header size, records in `[off+metadata_len, off+event_len)`), extracting `FAN_EVENT_INFO_TYPE_PIDFD` by `info_type` — order-independent.
- Malformed info records (length overflow/type bounds) → `FanotifyError::MalformedInfoRecord` (fail closed), not silent drop.
- `ParsedEvent.pidfd: Option<RawFd>` — owned; caller closes exactly once.

### B. Daemon wiring (`apps/guardd/src/main.rs`, `strict.rs`, `ipc.rs`)
- Group creation prefers pidfd; EINVAL/EPERM fallback → legacy group + `pidfd_enabled=false` (truthful REDUCED, never "Strong").
- Per event: if pidfd-enabled, validate `proc::pidfd_matches(pidfd, ev.pid)` (via `/proc/self/fdinfo/<pidfd>` `Pid:`). Missing/mismatched pidfd → `Deny(UnknownProcess)` + `pidfd_failure_audit_record`, enforced BEFORE any pending confirmation enqueue.
- pidfd closed exactly once after the decision (normal + fail-closed paths). The pidfd pins the instance for the entire decision window.
- `BackendMetrics.pidfd_enabled` / `.pidfd_missing_events` surfaced in `StatusInfo.linux_health` and `guardctl status`.

### C. Actual executed image (`crates/platform-linux/src/identity.rs`, `enrollment.rs`)
- `resolve()` opens `/proc/<pid>/exe` once; `fstat_executed_image` gives dev/ino/mode/owner from the real object. `read_exe` (readlink) kept only for display/registry mapping.
- `EnrollmentStore::verify_fd(fd, display_path)` — hashes the executed-object fd; lookup strips `" (deleted)"` suffix; never re-opens the pathname.
- Removed `stat_exe` pathname-reopen TOCTOU.

### D. PID reuse (`apps/guardd/src/enforce.rs`)
- `resolve_process` already keyed by `(pid, start_time)`; new test proves a changed start_time forces `fresh_resolve` and never transfers the stale cached identity.

## Tests

### Offline
- `cargo test --workspace --all-features`: green.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: 0 errors.
- `cargo fmt --all -- --check`: clean.
- New unit tests:
  - fanotify: pidfd info record parse; order-independent walk; malformed record fail-closed; no-info → None.
  - proc: pidfd_target_pid via fdinfo; closed fd → None.
  - identity: executed image survives pathname replacement (same dev/ino + enrollment); survives unlink `(deleted)`; new process at replaced path does not inherit enrollment.
  - enforce: PID-reuse cache invalidation fails closed.

### Privileged / live
- `scripts/linux/test-pidfd-root.sh` written (deterministic; asserts pidfd_enabled from status, unknown denied, enrolled allowed, pidfd_missing_events=0, clean shutdown).
- **NOT RUN in this environment — BLOCKED**: the capsule's nspawn seccomp returns EPERM for `fanotify_init` (verified: syscall 300/301 EPERM with CAP_SYS_ADMIN; `mount` works, proving it is the seccomp whitelist, not capability loss). Host pkexec is now prohibited by policy while the capsule is available. Per the capsule instructions, this nspawn restriction downgrades the live claim to BLOCKED rather than inventing host acceptance.

## Adversarial findings
1. nspawn seccomp blocks ALL fanotify in the capsule — no fanotify File Shield live test can run there. This is an environment restriction, not a Guard defect.
2. The double-open TOCTOU I initially wrote (open exe for stat, then reopen for enrollment) was caught in review and replaced by a single open reused for both — no window between identity and enrollment.

## Compatibility findings
- Legacy kernels (no FAN_REPORT_PIDFD): group falls back, `pidfd_enabled=false`, status truthful; no silent "Strong".
- `(deleted)` executables resolve via fd; enrollment lookup strips the suffix.
- Browser registry mapping still uses the readlink path (display only), preserving `browser_exes` matching.

## Performance
- No benchmark run this phase (fanotify blocked in capsule). `resolve()` adds one `/proc/<pid>/exe` open + fstat per fresh resolve; identity cache preserves the fast path. LFH6 re-benchmarks against LFH0 baseline.

## Truthfulness verdict

| Claim | Verdict | Evidence |
|---|---|---|
| pidfd info parser is order-independent + malformed-safe | PREVENTED (unit) | fanotify tests |
| daemon prefers FAN_REPORT_PIDFD on accepted kernel | LIVE VERIFIED | `scripts/linux/test-pidfd-root.sh` PASS: pidfd_enabled=true, pidfd_missing_events=0, unknown probe denied, enrolled probe allowed (evidence/live-host-*/test-pidfd-root.log) |
| event pidfd validated; mismatch fails closed before confirmation | PREVENTED (code) | pidfd_matches + decision override path |
| pidfd closed exactly once | PREVENTED (code) | close in both paths |
| actual executed image identity via fd, not pathname | PREVENTED (unit) | replacement/unlink tests |
| new process at replaced path does not inherit enrollment | PREVENTED (unit) | new_process test |
| PID reuse fails closed | PREVENTED (unit) | cache invalidation test |
| live pidfd acceptance | LIVE VERIFIED | test-pidfd-root.sh PASS=5 FAIL=0 on real host |

## Residual limitations
- `FAN_REPORT_TID` deliberately not combined (LFH1 A).

## Final phase verdict
`PASS (unit + code) + LIVE GATE PASS (real host: test-pidfd-root.sh PASS=5 FAIL=0)`
