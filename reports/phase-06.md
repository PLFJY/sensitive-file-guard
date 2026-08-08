# Phase 06 — Browser Enforcement

## Implemented behavior

`guardd` now wires together the four Phase 02–05 components on the fanotify hot
path: `fanotify` (`FAN_OPEN_PERM`) + `platform_linux::identity` (PID →
`ProcessIdentity`) + `guard_browser::ProtectedResourceRegistry` (path →
`ProtectedResource`) + `guard_core::policy` (deterministic `Decision`).

New module `apps/guardd/src/enforce.rs` introduces the `EnforcementEngine`:

- `EnforcementConfig` (JSON) — per-browser enrollment that drives BOTH resource
  discovery (`CustomProfile::enroll_into`) and process identity
  (`exe_paths` → `BrowserId` map). `owner_uid` is auto-detected from the
  profile root owner when omitted. `enrolled_exes` hash-enrolls user-writable
  browser builds (AppImage / custom) so they reach `EnrolledUserWritable` trust.
- `from_config` — discovers resources, builds a `(st_dev, st_ino)` → resource
  index for concrete critical files (hardlink catching), and maps canonical exe
  paths to `BrowserId`s.
- `mark_files` / `mark_trees` — marks concrete files with `FAN_OPEN_PERM` and
  protected directory trees recursively with `FAN_OPEN_PERM | FAN_EVENT_ON_CHILD`.
- `decide(pid, fd)` — the hot-path entry:
  1. `classify_fd(fd)`: `fstat(fd)` → `(dev, ino)` → `fd_index` (catches
     hardlinks by inode), then `readlink /proc/self/fd/<fd>` →
     `registry.classify` (catches symlinks via canonicalization and tree
     descendants via prefix match).
  2. `resolve_process(pid)`: cached by `(pid, start_time)`; a fresh
     `read_start_time` read detects PID reuse and forces a re-resolve. The
     `browser` field is set from the config `exe_paths` map — a renamed fake
     "firefox" binary whose path is not enrolled stays `browser=None` and is
     denied. The enrollment store's file-identity fast path means executable
     SHA-256 is never recomputed on every open.
  3. `evaluate` (the pure Phase 03 policy) returns `Allow | Deny(reason) |
     AllowByLease`. The decision is logged after it is made; the path never
     waits for UI. Failures (unclassified fd, unresolvable pid) fail closed.

Behavior matches `06_BROWSER_ENFORCEMENT.md`:
- owning browser → `Allow`
- another verified browser → `Deny(CrossBrowserWithoutLease)` (Phase 08 adds
  the `MigrationLease` grant path; the engine already carries an empty
  `LeaseSet` that `evaluate` consults)
- unknown/ordinary process → `Deny(UnknownProcess)`
- `guardd --enforce-browser-config PATH` is the new CLI mode; it is mutually
  exclusive with the Phase 02 `--protect-test-file` dev mode.

`platform-linux::identity` gained a public `read_start_time(pid)` helper so the
cache can validate entries without a full `resolve` on every event.

## Performance

- Identity decisions cached by `(pid, start_time)`: a cache hit skips
  exe-stat, status-read, cmdline-read and ancestor-walk; only the cheap
  `/proc/<pid>/stat` starttime read is performed to validate the entry.
- Concrete critical files indexed by `(st_dev, st_ino)` at enrollment time, so
  hardlink classification is an `O(1)` map lookup with no re-stat of the
  enrolled path.
- Resource classification (`registry.classify`) is already path-prefix based
  and allocation-light.
- Executable SHA-256 is never recomputed on every open: `EnrollmentStore::verify`
  uses a file-identity (`dev`/`ino`/`size`/`mtime`) fast path and only rehashes
  when the file identity changed (i.e. when tampering/an update could have
  occurred).
- No package-manager calls on the hot path (trust is ownership/mode-based;
  Arch/Debian/RPM package-ownership refinement is a future background cache).
- Per-event work is bounded: one `fstat`, one `readlink`, one cached identity
  lookup, one policy `evaluate`. Counters (`allowed`/`denied`/`unclassified`)
  are the only per-event mutation and allocate nothing.

## Exact commands run

```
cargo build -p guardd
cargo build --release -p guardd -p guard-test-probe
cargo fmt
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test -p guardd --no-fail-fast
cargo test --workspace --no-fail-fast
bash -n scripts/test-browser-enforcement-root.sh
```

## Test results

### Non-privileged unit tests (`cargo test -p guardd`) — 16 passed, 0 failed

These run without root by opening real files (no fanotify needed for the
classify/policy wiring) and resolving the test process's own identity / a
spawned `sleep` child.

| Test | Covers |
| --- | --- |
| `classify_fd_returns_concrete_critical_file` | fd → CookieStore resource |
| `classify_fd_covers_wal_and_shm_sidecars` | Cookies-wal / Cookies-shm classified (prompt test 8) |
| `classify_fd_catches_hardlink_by_inode` | hardlink (different path, same inode) classified via `fd_index` (prompt test 4) |
| `classify_fd_catches_symlink_to_protected_file` | symlink to Cookies classified (prompt test 3) |
| `classify_fd_unprotected_file_is_none` | unrelated file not over-blocked |
| `classify_fd_tree_descendant_synthesizes_resource` | Local Storage descendant → WebStorage |
| `resolve_process_self_has_correct_exe` | identity resolution of own PID |
| `resolve_process_caches_and_reuses` | `(pid, start_time)` cache returns equal identity |
| `resolve_process_maps_enrolled_exe_to_browser` | config `exe_paths` → `browser` field set; `/bin/sleep` → SystemPackage trust |
| `resolve_process_renamed_fake_browser_stays_unknown` | copy of sleep named "firefox" NOT in exe map → `browser=None`, `Unknown` trust (rename attack denied) |
| `decide_unknown_process_denied` | sleep (browser=None) → `Deny(UnknownProcess)` (prompt test 1) |
| `decide_owning_browser_allowed` | sleep enrolled as chrome reading own cookies → `Allow` (prompt test 5) |
| `decide_cross_browser_denied_without_lease` | chrome process reading firefox cookies → `Deny(CrossBrowserWithoutLease)` (prompt test 6) |
| `decide_unclassified_fd_fails_closed` | unprotected fd → fail closed `Deny` |
| `from_config_enrolls_chromium_resources` | config enrollment populates registry (≥6 files + trees) |
| `from_config_auto_detects_owner_uid` | omitted `owner_uid` auto-detected from profile root owner |

### Full workspace (`cargo test --workspace`) — 88 passed, 0 failed

guard-core 17, guard-browser 21, guard-test-fixtures 9, platform-linux 24,
guardd 16, integration smoke 1. No regressions in Phases 01–05.

`cargo clippy --all-targets --all-features -- -D warnings` — clean.
`cargo fmt --check` — clean.

### Privileged fanotify end-to-end — provided as `scripts/test-browser-enforcement-root.sh` (BLOCKED in this environment)

The non-interactive build agent cannot obtain `CAP_SYS_ADMIN`, so the
privileged integration tests are provided as a deterministic script for a human
to run with `sudo bash scripts/test-browser-enforcement-root.sh`. The script
covers all 9 prompt-required scenarios plus extras:

| # | Prompt scenario | Script test |
| --- | --- | --- |
| 1 | ordinary probe reads fake Cookie => denied | `cat` denied before open completes |
| 2 | ordinary probe copies fake Cookie => denied | `cp` denied (source open fails) |
| 3 | symlink path to protected file => denied | symlink to Cookies denied |
| 4 | hardlink to protected critical file => denied | hardlink to Cookies denied by inode mark + `fd_index` (BLOCKED if filesystem rejects hardlinks) |
| 5 | trusted Browser A → own profile => allowed | chrome-probe reads own Cookies |
| 6 | Browser B → Browser A profile => denied | firefox-probe denied chrome Cookies (no lease) |
| 7 | rapid denied opens, no prompt storm | 300 repeated `cat` opens; daemon survives, no fd leak, no UI prompt by design |
| 8 | SQLite WAL/SHM paths covered | `Cookies-wal` and `Cookies-shm` denied |
| 9 | open-before-daemon limitation documented | documented below + script NOTE |
| + | (extras) | firefox own-profile allowed; chrome→firefox cross denied; unprotected Bookmarks not over-blocked; clean SIGTERM shutdown |

The script uses ONLY synthetic marker data, contains no network code, and never
touches a real browser profile or real SSH key.

## Known limitations

- **Open-before-daemon** (prompt test 9): `fanotify` only gates *new* opens.
  A file handle opened BEFORE `guardd` protection begins cannot be
  retroactively prevented; the holder can still `read()` from the existing fd.
  This is a fundamental `fanotify` `FAN_OPEN_PERM` boundary, documented in the
  global contract's "accesses through handles opened before guardd protection
  began cannot be retroactively prevented". V1 mitigation: prompt daemon start
  at boot (Phase 14 systemd) and document that a browser already running before
  the daemon starts retains its open handles.
- **fanotify recursive-mark race**: tree coverage requires marking every
  subdirectory; a new subdirectory created after the `mark_trees` walk but
  before the next rescan is not marked, so opens of files inside it do not fire
  `FAN_OPEN_PERM`. Classification still works (registry prefix match), but the
  event does not fire. This is the documented `fanotify` recursion limitation;
  an optional strict mount/filesystem-mark benchmark mode is deferred (the
  prompt marks it optional). The engine never claims race-free recursion.
- **Tree-descendant hardlink gap**: a hardlink to a file *inside* a protected
  directory tree (e.g. `Local Storage/...`), opened via a path outside the
  tree, is NOT caught: the open does not fire a tree event (the hardlink is not
  a child of the marked dir) and the descendant is not in `fd_index` (only
  concrete critical files are inode-indexed). Concrete critical files
  (`Cookies`, `Login Data`, `key4.db`, …) ARE fully hardlink-protected because
  they are individually marked by inode and indexed by `(dev, ino)`. The
  hardlink test in the root script targets a concrete critical file (Cookies).
- **fd-identity index is a startup snapshot**: if a protected concrete file is
  replaced (deleted + recreated) after daemon start, its inode changes and the
  index entry is stale. The path-based `registry.classify` still catches the
  new inode via `fd_path` canonicalization, so protection holds, but the
  hardlink-by-inode fast path for the old inode is lost until a rescan. A
  runtime rescan/inotify trigger is deferred to Phase 07.
- **Browser identity by exe path only**: a browser is identified by its
  canonical exe path appearing in the config `exe_paths` map. A real browser
  that launches helper processes with a different exe path (e.g. a separate
  renderer binary) would not match; V1 protects the primary profile files and
  treats helpers as ordinary processes unless explicitly enrolled. This is
  acceptable for V1's "browser self-access" scope and tightened in later phases.
- **No automatic process kill or quarantine** in V1 (per the prompt).
- **Lease set is empty in this phase**: `MigrationLease` grant flow is Phase 08;
  the engine carries the `LeaseSet` the policy already consults, so cross-browser
  access is denied now and will be allowable-by-lease once Phase 08 wires the
  grant path.

## Security assumptions

- A path is protected iff it matches an enrolled concrete file (exact canonical
  path or `(dev, ino)` for hardlinks) or falls under an enrolled tree prefix.
- Browser identity comes from config `exe_paths`, never from the executable
  basename. A renamed fake "firefox" stays `browser=None` + `Unknown` trust and
  is denied — verified by `resolve_process_renamed_fake_browser_stays_unknown`.
- Trust is ownership/mode-based (`SystemPackage` for root-owned non-writable)
  plus explicit hash enrollment (`EnrolledUserWritable`) for user-writable
  browser builds. Changed bytes invalidate enrollment (Phase 04).
- PID reuse is detected via `start_time` validation on every cached lookup; a
  reused PID with a different start time forces a full re-resolve.
- The hot path fails closed: an unclassified fd or unresolvable pid yields
  `Deny(UnknownProcess)`.
- `CAP_SYS_ADMIN` is required and checked up front; the daemon exits 2 with a
  precise message if missing and never falls back to notification-only while
  claiming enforcement.
- No real browser profile is ever opened by tests; all tests use
  `guard-test-fixtures` synthetic profiles or bash-created marker files.
