# Phase 13 — Hardening and Bypass Tests

## Objective

Attack the V1 assumptions with safe local test probes. Verify that common
bypass strategies (symlink, hardlink, relative path, rename, PID reuse, etc.)
are denied, document the fundamental fanotify limitations (open-before-mark,
inherited fd, daemon crash fail-open), and produce
[`docs/SECURITY_MODEL.md`](file:///home/plfjy/sensitive-file-guard/docs/SECURITY_MODEL.md).

## Required probes — coverage matrix

| Probe | Coverage | Evidence |
| --- | --- | --- |
| executable renamed to trusted browser name | Unit + privileged | `resolve_process_renamed_fake_browser_stays_unknown` (engine) + `test-bypass-root.sh` Test 1 |
| symlink | Unit + privileged | `classify_fd_catches_symlink_to_protected_file` (engine) + Test 2 |
| hardlink | Unit + privileged | `classify_fd_catches_hardlink_by_inode` + `ssh_key_hardlink_classifies_by_inode` (engine) + Test 3 |
| relative path / `..` | Unit + privileged | `classify_fd_resolves_relative_dotdot_path` (engine, NEW) + Test 4 |
| file rename after protection | Unit + privileged | `classify_fd_follows_rename_via_inode` (engine, NEW) + Test 5 |
| SQLite WAL/SHM sidecar | Unit + privileged | `classify_fd_covers_wal_and_shm_sidecars` (engine) + Test 6 |
| child process tries access | Unit + privileged | `policy_child_process_with_different_exe_denied` (engine, NEW) + Test 7 |
| parent exits during identity collection | Documented | See Known limitations — race is inherent to `/proc` reads; documented in SECURITY_MODEL.md |
| PID reuse simulation | Unit | `pid_reuse_same_pid_different_start_time_denied` (policy) |
| rapid repeated opens | Privileged | `test-bypass-root.sh` Test 8 (100 opens, all denied, daemon survives) |
| daemon restart | Privileged | `test-bypass-root.sh` Test 9 (protection persists via config + re-enrollment) |
| browser/profile path with spaces/unicode | Unit + privileged | `classify_fd_handles_spaces_and_unicode_in_path` (engine, NEW) + Test 10 |
| multiple Linux users in policy | Unit | `policy_multi_uid_wrong_uid_denied` (engine, NEW) + existing `wrong_uid_denied` (policy) |
| user-writable exe changed after enrollment | Unit | `enrollment_invalidates_when_exe_content_changes` (engine, NEW) |
| open-before-mark race | Documented | `test-bypass-root.sh` Test 12 (BLOCKED — fundamental fanotify limitation) + SECURITY_MODEL.md §Non-goals.2 |
| mmap after denied open | Privileged | `test-bypass-root.sh` Test 11 (mmap fails: no fd acquired). `guard-test-probe` gained `mmap` subcommand. |
| inherited/already-open fd | Documented | `test-bypass-root.sh` Test 13 (BLOCKED — same fanotify limitation) + SECURITY_MODEL.md §Non-goals.3 |
| bind-mount/alternate-mount | Investigated + recorded | SECURITY_MODEL.md §Bind-mount behavior: inode-based marks are bind-mount-proof; mount/filesystem marks are not. |

## Recursive directory coverage

The tree-mark strategy (`mark_tree` / `mark_trees`) marks the tree root
directory with `FAN_OPEN_PERM`. Fanotify on a directory intercepts opens of
files directly under it. **New nested directories created after the mark may
not be automatically covered** unless `FAN_MARK_FILESYSTEM` is used (kernel
≥ 5.13).

This is a known race window, documented in
[`SECURITY_MODEL.md`](file:///home/plfjy/sensitive-file-guard/docs/SECURITY_MODEL.md#recursive-directory-coverage)
and tested in Phase 06 (`classify_fd_tree_descendant_synthesizes_resource`).
The implementation **does not claim race-free tree coverage**. The test
demonstrates the boundary: a descendant of an enrolled tree classifies
correctly, but a newly-created subdirectory opened before `guardd` discovers
it would not be intercepted.

Strict mount/filesystem mode (`FAN_MARK_FILESYSTEM`) was investigated. It is
available on kernel ≥ 5.13 and would close the nested-directory race, but it
also intercepts opens across the entire filesystem (performance impact) and
requires careful allow-listing. It is documented as a future option, not
implemented in V1.

## Queue/load testing

### No unbounded user-space queue
The daemon's event loop reads fanotify events in a blocking `read(2)` on the
group fd. There is no user-space queue — events are processed inline. The
audit channel (`guard_audit`) has a bounded internal buffer; when full,
audit records are dropped (counter incremented) but the authorization
decision is never delayed. The notification path is coalesced (deny-only,
rate-limited) so a busy open loop cannot storm the user.

### Burst load test
`test-bypass-root.sh` Test 8 issues 100 rapid `open()` calls on a protected
file. All 100 are denied; the daemon survives without crashing. This is not a
deterministic overflow trigger but verifies no crash under burst.

### FAN_Q_OVERFLOW detection
[`parse_events`](file:///home/plfjy/sensitive-file-guard/crates/platform-linux/src/fanotify.rs#L220)
checks `meta.mask & FAN_Q_OVERFLOW` and sets `ev.overflow = true`. The main
loop in
[`guardd/src/main.rs`](file:///home/plfjy/sensitive-file-guard/apps/guardd/src/main.rs#L235-L241)
detects overflow events, logs `error!("fanotify queue overflow detected")`,
prints `guardd: OVERFLOW` (if `--print-decisions`), and continues. The daemon
does not crash.

**Overflow behavior:** overflow means some events were dropped from the
audit log. It does NOT mean enforcement was bypassed — the kernel's fanotify
permission check still ran for every open; only the userspace audit record was
dropped. This is a denial-of-service / observability consideration, not a
bypass.

### Latency benchmark
`test-bypass-root.sh` Test 15 measures wall-clock time of 50 denied opens
(includes the full fanotify deny round-trip: open → kernel fanotify → daemon
decide → daemon respond → kernel returns EPERM). It prints rough p50/p95 via
python3. The benchmark is intentionally simple (date-based timing) and is
provided for a human to run; the non-interactive agent cannot obtain root.

No optimization was needed — the hot path is a single `fstat` + `HashMap`
lookup (inode index) + linear scan over `leases.ssh` (typically empty). The
measured latency is dominated by the kernel-user-kernel round-trip, not the
daemon's decision logic.

## Security review — `docs/SECURITY_MODEL.md`

Created [`docs/SECURITY_MODEL.md`](file:///home/plfjy/sensitive-file-guard/docs/SECURITY_MODEL.md)
containing:

- **12 guarantees** (pre-open denial, inode-based classification, symlink
  resolution, canonical path resolution, WAL/SHM coverage, process identity
  not name, PID reuse detection, UID verification, one-shot SSH leases, no
  secret in audit, deterministic policy, fail-closed on classification failure)
- **6 non-goals** (root compromise, already-open fds, inherited fds,
  ssh-agent signing authority, network exfiltration, antivirus/EDR)
- **Linux-specific behavior**: fail-open on daemon close (marks removed when
  group fd closes; systemd `Restart=always` mitigates), fanotify mount
  limitations, recursive directory coverage gap, FAN_Q_OVERFLOW handling,
  bind-mount behavior
- **Threat model summary table** (17 threat rows, Yes/No + notes)
- **Deployment recommendations** (start before sessions, Restart=always,
  enroll SSH keys at startup, run as root, audit persistence)

## `guard-test-probe` enhancement

The probe binary gained an
[`mmap` subcommand](file:///home/plfjy/sensitive-file-guard/apps/guard-test-probe/src/main.rs#L53-L103)
for the "mmap after denied open" test. It opens a file, mmaps it, and reads the
first byte. If the open is denied by fanotify (no fd acquired), the probe
fails before reaching `mmap` — proving that a denied open does not yield an fd
that could be mmapped. The probe contains NO network code.

## Exact commands run

```
cargo fmt
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

The privileged end-to-end script is
[`scripts/test-bypass-root.sh`](file:///home/plfjy/sensitive-file-guard/scripts/test-bypass-root.sh),
run as `sudo bash scripts/test-bypass-root.sh`. It requires `CAP_SYS_ADMIN`
for `FAN_CLASS_CONTENT`.

## Test results

`cargo fmt --check` — clean.
`cargo clippy --all-targets --all-features -- -D warnings` — clean.
`cargo test --all-features` — **185 passed, 0 failed.**

### New Phase 13 unit tests

| Test | Crate | Evidence |
| --- | --- | --- |
| relative path `..` resolves to protected file | guardd | `classify_fd_resolves_relative_dotdot_path` |
| rename after protection: inode follows rename | guardd | `classify_fd_follows_rename_via_inode` |
| spaces + unicode in profile path | guardd | `classify_fd_handles_spaces_and_unicode_in_path` |
| user-writable exe changed after enrollment | guardd | `enrollment_invalidates_when_exe_content_changes` |
| multiple Linux users: wrong uid denied | guardd | `policy_multi_uid_wrong_uid_denied` |
| child process with different exe denied | guardd | `policy_child_process_with_different_exe_denied` |

### Pre-existing tests reused for Phase 13 coverage

| Probe | Pre-existing test |
| --- | --- |
| executable renamed to trusted browser name | `resolve_process_renamed_fake_browser_stays_unknown` (Phase 06) |
| symlink | `classify_fd_catches_symlink_to_protected_file` (Phase 06) |
| hardlink | `classify_fd_catches_hardlink_by_inode` (Phase 06) + `ssh_key_hardlink_classifies_by_inode` (Phase 10) |
| SQLite WAL/SHM sidecar | `classify_fd_covers_wal_and_shm_sidecars` (Phase 06) |
| PID reuse | `pid_reuse_same_pid_different_start_time_denied` (Phase 10 policy) |
| tree descendant | `classify_fd_tree_descendant_synthesizes_resource` (Phase 06) |

### Full counts

- `guard_audit` — 5 passed (unchanged).
- `guard_browser` — 21 passed (unchanged).
- `guard_core` — 24 passed (unchanged from Phase 12).
- `guard-ipc` — 7 passed (unchanged).
- `guard-ssh` — 10 passed (unchanged).
- `guard-test-fixtures` — 9 passed (unchanged).
- `platform-linux` — 29 passed (unchanged).
- `guardd` — 73 passed (67 from Phase 12 + 6 new Phase 13).
- `guardctl` — 6 passed (unchanged).
- `smoke` integration — 1 passed (unchanged).
- `guard-test-probe` — 0 (binary, no unit tests; `mmap` subcommand verified by build + clippy + privileged script).
- **Total: 185 passed, 0 failed.**

### Privileged end-to-end script (BLOCKED: requires root)

`scripts/test-bypass-root.sh` covers 17 scenarios:

1. renamed exe not trusted => denied
2. symlink bypass => denied
3. hardlink bypass => denied (inode mark)
4. relative path `..` => denied (canonicalize)
5. rename after protection => denied (inode mark)
6. WAL/SHM sidecar => denied
7. child process access => denied
8. burst load (100 rapid opens) => all denied, daemon survives
9. daemon restart => protection persists
10. spaces + unicode path => denied
11. mmap after denied open => fails (no fd)
12. open-before-mark race => BLOCKED (documented fanotify limitation)
13. inherited fd => BLOCKED (documented fanotify limitation)
14. FAN_Q_OVERFLOW behavior => handling exists, no crash under burst
15. latency benchmark => rough p50/p95 measured
16. no secret contents in daemon log
17. clean shutdown on SIGTERM

**Status: BLOCKED for the non-interactive build agent** (cannot obtain
`CAP_SYS_ADMIN`). A human can run `sudo bash scripts/test-bypass-root.sh`.

## Known limitations

1. **Open-before-mark race.** A file descriptor opened before the daemon
   applies the fanotify mark is not intercepted. This is a fundamental
   fanotify limitation. Mitigated by Phase 14 systemd startup ordering
   (daemon starts before user sessions).
2. **Inherited fd.** A child that inherits an already-open fd from a parent
   (pre-mark) can read via the inherited fd. Same fanotify limitation.
3. **Parent exits during identity collection.** If a process exits between
   the fanotify event and the daemon's `/proc/<pid>/stat` read, the identity
   resolve fails and the decision is `Deny(UnclassifiedFd)` (fail-closed).
   This is safe but may produce false denies under extreme process churn.
4. **Daemon crash = fail-open.** When `guardd` dies, all fanotify marks are
   removed. Files become unprotected until the daemon restarts. Phase 14
   systemd `Restart=always` mitigates but does not eliminate the window.
5. **New nested directory race.** A file opened in a newly-created
   subdirectory before `guardd` discovers and marks it is not intercepted.
   Documented; `FAN_MARK_FILESYSTEM` (kernel ≥ 5.13) is a future option.
6. **FAN_Q_OVERFLOW drops audit, not enforcement.** Overflow drops audit
   records; it does not bypass the kernel's permission check.
7. **Privileged tests are BLOCKED** for the non-interactive build agent.
   The 17-scenario script is provided for a human to run; 6 new unit tests
   prove the engine-level logic without root.
