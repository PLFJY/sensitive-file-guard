# Phase 04 — Linux Process Identity

## Implemented behavior

A Linux identity resolver strong enough that renaming malware to `firefox` does
not grant access. Decisions are driven by executable file identity + ownership
+ trust tier, never by process or executable name alone.

New modules under `crates/platform-linux/src/`:

- `identity.rs` — `resolve(pid, current_uid, enrollment) -> ProcessIdentity`,
  the pure `classify_trust(exe_owner_uid, mode, current_uid, enrolled)`,
  `collect_ancestors(ppid)` (bounded), `default_browser_classifier(exe)`, and
  `ResolveError`.
- `enrollment.rs` — `EnrollmentStore` with SHA-256 hash enrollment for
  user-writable executables, `EnrollmentRecord`, `FileIdentity`, `EnrollError`.

Shared type added to `guard-core/src/identity.rs`:
- `AncestorSummary { pid, start_time, exe }` plus an `ancestors: Vec<AncestorSummary>`
  field on `ProcessIdentity` (audit context; not used by V1 allow/deny).

Identity fields captured per PID:
- PID + start time from `/proc/<pid>/stat` `starttime` (field 20 after the last
  `)`, parsed robustly against `comm` values containing spaces/parens)
- real UID/GID from `/proc/<pid>/status` (`Uid:`/`Gid:` lines)
- canonical exe path via `/proc/<pid>/exe` readlink
- exe `st_dev` + `st_ino` + mode + owner uid (for trust + lease binding)
- cmdline from `/proc/<pid>/cmdline` (audit only, NUL-split, lossy)
- bounded parent/ancestor chain (`MAX_ANCESTOR_DEPTH = 16`), stopping at PID
  0/1 or when a parent's `/proc` entry is unreadable (exited)

Trust tiers (`classify_trust`):
1. `SystemPackage` — exe owner is root AND mode has no group/other write bits
   (`mode & 0o022 == 0`). This is the security property that matters: the
   opener cannot have tampered with the binary. No package manager is invoked
   on the hot path; Arch/Debian/RPM package-ownership refinement can be added
   later as a background cache without changing this interface.
2. `Sandbox` — reserved (flatpak/snap app id); not produced by V1.
3. `EnrolledUserWritable` — user-writable exe whose stored SHA-256 still
   matches (after a file-identity cache check, rehashing only on identity
   change).
4. `Unknown` — anything else, including root-owned files that are group/other
   writable (fail closed) and unenrolled user-writable files.

Enrollment invalidation: the stored record keeps `(dev, ino, size, mtime_ns)`
plus `sha256`. `verify()` does a fast file-identity comparison first (no rehash
of large browser binaries on the steady path); only when the file identity
changed does it recompute the hash. A matching hash refreshes the cached
identity; a mismatched hash drops the record (invalidated). This catches both
in-place tampering (mtime/size change) and replacement (ino change).

## Exact commands run

```
cargo build -p platform-linux
cargo clippy -p platform-linux --all-targets --all-features -- -D warnings
cargo test -p platform-linux --no-fail-fast
cargo fmt
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

## Test results

`cargo test -p platform-linux` — 24 passed, 0 failed (incl. prior Phase 02
fanotify/capability tests).

Phase-04-specific tests:

| Test | Covers |
| --- | --- |
| `classify_trust_root_owned_immutable_is_system_package` | tier 1 root-owned immutable fixture (unit) |
| `classify_trust_root_owned_group_writable_fails_closed` | root-owned but writable => Unknown (fail closed) |
| `classify_trust_user_owned_unenrolled_is_unknown` | tier 4 |
| `classify_trust_user_owned_enrolled_is_enrolled` | tier 3 |
| `resolve_real_root_owned_binary_is_system_package` | live /bin/sleep child resolves to SystemPackage |
| `resolve_self_is_consistent_and_pid_reuse_safe` | same PID twice => same stable id; different start_time => different StableIdentity (PID reuse safe) |
| `renamed_to_firefox_is_still_denied` | copy of sleep named `firefox`, user-writable + unenrolled => Unknown => policy `Deny(NotTrustedIdentity)` even with `browser=Some(firefox)` |
| `parent_chain_is_bounded_and_stops_before_init` | chain length <= 16, no PID 0/1 |
| `collect_ancestors_of_init_is_empty` | ppid 0 => empty |
| `collect_ancestors_handles_exited_parent` | unreadable/high PID => stops, no panic |
| `default_browser_classifier_maps_known_basenames` | chrome/firefox/etc. mapping, python3 => None |
| `enrolled_user_writable_verifies` | enrollment verify fast path |
| `changed_binary_invalidates_enrollment` | tampered bytes => verify false |
| `unenrolled_path_does_not_verify` | unknown path => false |
| `rehash_after_metadata_only_change_stays_valid` | mtime-only touch => still valid (rehash matches, cache refreshed) |

Workspace `cargo clippy --all-targets --all-features -- -D warnings` — clean.
`cargo fmt --check` — clean.

## Known limitations

- `Sandbox`/package identity (flatpak/snap app id) is not produced in V1; such
  executables currently resolve to `SystemPackage` if root-owned and immutable,
  or require hash enrollment if user-writable.
- pidfd is not used; the start-time field (`/proc/<pid>/stat` `starttime` in
  clock ticks) is the stable token that prevents PID reuse. pidfd can be added
  later as a stronger handle without changing `ProcessIdentity`.
- The `default_browser_classifier` is a basename best-effort used only for
  tests/early wiring; Phase 05 replaces it with the full discovery registry.
- `cmdline` is read best-effort (empty on read failure); it is audit-only and
  never affects the allow/deny decision.
- Resolving another user's `/proc/<pid>/exe` may require the daemon's
  privileges (root/CAP_SYS_ADMIN); the daemon data plane has them.

## Security assumptions

- Trust is derived from executable file identity + ownership + (for
  user-writable) hash enrollment — never from the process or exe name. Renaming
  a binary to `firefox` does not change its owner/mode/enrollment, so it stays
  `Unknown` and is denied.
- Root-owned files that are group/other-writable are treated as `Unknown`
  (fail closed) rather than trusted.
- Leases bind to `StableIdentity` (exe + start_time + dev + ino); the resolver
  populates these from `/proc`, so PID reuse (same PID, different start_time)
  cannot match an existing lease.
- Missing/unreadable identity fields (e.g. parent exited) cause graceful
  bounded stops, never an allow.
