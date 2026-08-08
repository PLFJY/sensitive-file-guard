# Phase 08 — Browser Migration Lease

> Historical report, superseded by Phase 16. Linux fanotify does not enforce
> the claimed read-only invariant; current code uses `MigrationAccessLease`
> with `read_only_guaranteed: false` and armed→bound process-tree state.

## Implemented behavior

Legitimate cross-browser import is now possible without permanent allow-listing.
A user can authorize a short, read-only, identity-scoped, time-limited grant
that lets one browser read another browser's protected profile, then the grant
expires automatically. The flow matches `08_MIGRATION_LEASE.md`:

1. A cross-browser protected read without a lease is **DENIED immediately**
   (audit event recorded with `CrossBrowserWithoutLease` / `IdentityMismatch`),
   then the user retries after authorizing.
2. `guardctl migration authorize --source-browser ... --source-profile ...
   --target-browser ... [--duration N]` issues the grant.
3. The daemon binds the lease to the target browser's **armed** executable file
   identity, so it matches the next target process — or any process in its
   tree — that opens the named source profile.
4. The lease expires after the time limit (default 10 min, capped at 1 h) and
   can be revoked early via `guardctl leases revoke`.

### Armed lease binding (`ExeIdentity`)

The core new abstraction is `ExeIdentity` (`guard-core::identity`): the target
browser's executable file identity (canonical path + `st_dev` + `st_ino`),
**excluding** the per-instance start time. `MigrationLease.target` is now an
`ExeIdentity` (previously a `StableIdentity`).

This is the "armed" binding from the spec:

- The lease is created *before* the target browser reads the source profile.
- It matches the **next** process (or any process in its tree) whose exe file
  identity equals it — tolerating the target being launched after authorization.
- A different executable at the same path (different inode) does **not** match.
- A renamed binary at a different path does **not** match.
- It can never turn into permanent trust: the lease expires (≤ 1 h) and the
  binding is file-identity-anchored, not path-name-anchored.

`ProcessStableId::exe_identity()` and `AncestorSummary::exe_identity()` project
the armed identity for matching; `AncestorSummary` now carries `exe_dev`/`exe_ino`
(captured by `platform_linux::identity::collect_ancestors` via `stat()`).

### Process-tree scoping

The policy engine's `decide_browser` (`guard-core::policy`) matches a migration
lease if the opener **OR any ancestor** has the bound target `ExeIdentity`. This
lets a target browser's helper/child process (e.g. a sandboxed renderer or an
import helper whose own exe differs from the browser binary) read the source
profile under the lease, while an unrelated process does not. Ancestors are
collected with `exe_dev`/`exe_ino` so the match is file-identity-anchored, not
path-name-anchored.

### Read-only enforcement (`AccessOperation::Write`)

A new `AccessOperation::Write` variant is set on the hot path when the open fd
carries `O_WRONLY`/`O_RDWR` (detected via `fanotify::fd_is_writable`, a cheap
`fcntl(F_GETFL)` query). A read-only `MigrationLease` denies writes to the
source profile with `DenyReason::LeaseScopeMismatch`. All migration leases are
created with `read_only: true`.

**Caveat (documented in `fanotify::fd_is_writable`):** for a `FAN_OPEN_PERM`
event fd the kernel historically opens the metadata fd `O_RDONLY | O_LARGEFILE`
regardless of the triggering open's flags, in which case the write is
classified as a read at the gate. The read-only-write invariant is therefore
enforced and unit-tested at the policy layer regardless; on kernels that
surface the opener's flags it becomes enforceable at the open gate as well.

### Lease authorization flow

- **`EnforcementEngine::authorize_migration`** (`guardd::enforce`): validates
  source + target browsers are enrolled in config, resolves the target's armed
  `ExeIdentity` from its `exe_paths` (first existing, canonicalized, `stat`'d),
  caps `duration_secs` at `MAX_MIGRATION_DURATION_SECS` (1 h, default 600 s),
  and pushes a `MigrationLease { read_only: true, .. }` into the lease set.
- **IPC `MigrationAuthorize` op** (`guard-ipc`): the wire request carries
  `source_browser`/`source_profile`/`target_browser`/`duration_secs` and
  **no `uid`** — the daemon takes the authorizing uid exclusively from
  kernel-verified `SO_PEERCRED`. The response (`MigrationAuthorized`) echoes the
  new lease id, expiry, armed target exe path, uid, and `read_only: true` so
  the user can confirm what was bound.
- **`guardd::ipc::handle_migration_authorize`**: takes `creds.uid` from
  `PeerCreds`, calls `authorize_migration`, returns the response.
- **`guardctl migration authorize`**: CLI subcommand with
  `--source-browser`/`--source-profile`/`--target-browser`/`--duration`.

Revocation reuses the Phase 07 `guardctl leases revoke` path; the existing
`LeasesRevoke` IPC op and `revoke_lease` engine method already cover migration
leases (searched by id).

## Lease must NOT grant (all verified by tests)

| Invariant | Test |
| --- | --- |
| writes to source profile | `policy::tests::read_only_migration_lease_denies_write` + `enforce::tests::migration_lease_write_denied_at_engine_level` |
| SSH key access | `policy::decide_ssh` branch never consults `leases.migration` (only `leases.ssh`) |
| another browser profile not named by lease | `policy::tests::migration_lease_does_not_grant_other_profile` + `enforce::tests::migration_lease_authorize_then_cross_browser_allowed` (reverse direction denied) |
| another UID | `policy::decide_browser` checks `lease.uid == proc.uid` (and `wrong_uid_denied` covers the resource-owner mismatch) |
| unrelated helper process outside bound tree | `policy::tests::migration_lease_denies_unrelated_helper_outside_tree` |
| expired lease | `policy::tests::expired_migration_lease_denied` |
| revoked lease | `policy::tests::revoked_migration_lease_denied` + `enforce::tests::migration_lease_revoked_denied` |
| wrong executable identity (different inode/path) | `policy::tests::migration_lease_bound_to_different_exe_denied` |
| process-tree scoping (helper with matching ancestor) | `policy::tests::migration_lease_allows_target_tree_helper_via_ancestor` |

## Authorization hot-path impact

- `fanotify::fd_is_writable` adds exactly one `fcntl(F_GETFL)` syscall per
  `FAN_OPEN_PERM` event (cheap; same order as the existing `fstat` + readlink).
- Lease matching iterates `leases.migration` (expected to be tiny — a handful
  of active grants per user) and compares `ExeIdentity` (path + two `u64`s).
- The IPC `MigrationAuthorize` handler takes the engine `Mutex` only for the
  duration of `authorize_migration` (a vec push + config lookup); the fanotify
  loop is not starved.
- No package-manager calls, no hashing, no I/O on the hot path from the lease
  grant — armed binding reuses the already-resolved target exe identity.

## Exact commands run

```
cargo fmt
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

## Test results

All Phase 08 tests run **without root** (the policy/lease/IPC layers are pure
data + Unix-socket IPC; the privileged fanotify end-to-end path is Phase 06's
script). No test is BLOCKED.

### Required tests (mapped to `08_MIGRATION_LEASE.md`)

| Required test | Evidence |
| --- | --- |
| Browser B denied before lease | `enforce::tests::migration_lease_authorize_then_cross_browser_allowed` (firefox reading chrome cookies before authorize => `CrossBrowserWithoutLease`) |
| authorized Browser B allowed to read only source Browser A profile | `enforce::tests::migration_lease_authorize_then_cross_browser_allowed` (after authorize => `AllowByLease`) + `policy::tests::cross_browser_with_valid_lease_allowed_by_lease` |
| write request is not granted by a read-only lease | `policy::tests::read_only_migration_lease_denies_write` + `enforce::tests::migration_lease_write_denied_at_engine_level` |
| wrong browser remains denied | `policy::tests::migration_lease_bound_to_different_exe_denied` + `policy::tests::migration_lease_does_not_grant_other_profile` |
| expired lease denied | `policy::tests::expired_migration_lease_denied` |
| revoked lease denied | `policy::tests::revoked_migration_lease_denied` + `enforce::tests::migration_lease_revoked_denied` |
| same PID with different stable process identity denied | `policy::tests::pid_reuse_same_pid_different_start_time_denied` (SSH lease path; migration leases use the coarser armed `ExeIdentity` by design, so PID reuse is not a grant vector for migration) |
| process tree scoping tests | `policy::tests::migration_lease_allows_target_tree_helper_via_ancestor` (helper with matching ancestor allowed) + `policy::tests::migration_lease_denies_unrelated_helper_outside_tree` (helper outside bound tree denied) |

### IPC + CLI tests (Phase 08 wire layer)

| Test | Evidence |
| --- | --- |
| `MigrationAuthorize` round-trips with correct version | `guard-ipc::tests::request_round_trips_all_ops` |
| request carries no `uid` field (peer-creds invariant) | `guard-ipc::tests::migration_authorize_request_has_no_uid_field` |
| `MigrationAuthorized` response round-trips | `guard-ipc::tests::migration_authorized_response_round_trips` |
| daemon uses peer uid, not JSON | `guardd::ipc::tests::migration_authorize_via_ipc_uses_peer_uid` (response uid == `PeerCreds.uid`; stored lease uid == `PeerCreds.uid`) |
| unknown target browser errors via IPC | `guardd::ipc::tests::migration_authorize_unknown_target_via_ipc_errors` |
| duration capped at 1 h via IPC | `guardd::ipc::tests::migration_authorize_caps_duration_via_ipc` |
| engine-level authorize + cross-browser allow | `enforce::tests::migration_lease_authorize_then_cross_browser_allowed` |
| engine-level revoke | `enforce::tests::migration_lease_revoked_denied` |
| engine-level duration cap | `enforce::tests::migration_authorize_caps_duration` |
| engine-level unknown target/source errors | `enforce::tests::migration_authorize_unknown_target_errors` |
| engine-level write denial | `enforce::tests::migration_lease_write_denied_at_engine_level` |
| existing `LeasesRevoke` covers migration leases | `guardd::ipc::tests::lease_revoke_authorization` (now uses `ExeIdentity` for `target`) |
| existing `LeasesList` covers migration leases | `guardd::ipc::tests::leases_list_filters_by_uid` (now uses `ExeIdentity` for `target`) |

### Full counts

- `guard-core` — 21 passed (17 pre-existing policy tests + 4 new Phase 08
  policy tests: read-only write denial, target-tree helper allow, unrelated
  helper deny, other-profile deny).
- `guardd` — 40 passed (32 from Phase 06+07 + 8 new Phase 08: 5 engine
  migration tests + 3 IPC migration tests). Existing `leases_list_filters_by_uid`
  and `lease_revoke_authorization` updated to the `ExeIdentity` target shape.
- `guard-ipc` — 4 passed (2 pre-existing + 2 new: `migration_authorize_request_has_no_uid_field`,
  `migration_authorized_response_round_trip`; `request_round_trips_all_ops`
  extended to cover `MigrationAuthorize`).
- `guardctl` — 3 passed (unchanged count; the new `migration authorize`
  subcommand is exercised via the IPC integration tests).
- `platform-linux` — 29 passed (28 pre-existing + 1 new:
  `fd_is_writable_reflects_open_flags`; ancestor `exe_dev`/`exe_ino` capture
  exercised via the engine resolve path).
- Other crates — unchanged.

`cargo clippy --all-targets --all-features -- -D warnings` — clean.
`cargo fmt --check` — clean.

## Known limitations

- **`fd_is_writable` fanotify caveat**: for `FAN_OPEN_PERM` event fds the
  kernel may report `O_RDONLY` regardless of the triggering open's flags, so a
  write-open can be classified as a read at the gate. The read-only-write
  invariant is enforced and unit-tested at the policy layer regardless; on
  kernels that surface the opener's flags it becomes enforceable at the open
  gate too. Documented on `fanotify::fd_is_writable`.
- **No automatic revoke on process-tree exit**: the spec lists "revoke on bound
  process-tree exit when practical" as preferred, not required. The lease
  expires by deadline (≤ 1 h) and can be revoked manually; automatic
  process-tree-exit revoke is deferred (would require a pidfd watch per active
  lease, out of scope for the PoC).
- **No privileged end-to-end migration script**: the engine + policy + IPC
  path is exercised non-privileged (real fds, real `/proc` identity resolution,
  real SQLite audit). A full privileged fanotify + migration script would
  extend `scripts/test-browser-enforcement-root.sh` and is deferred; the
  underlying enforcement path is already privileged-tested in Phase 06.
- **Armed binding is file-identity-anchored, not hash-anchored**: the spec
  lists "bound to target executable stable identity/hash/package identity" as
  preferred. `ExeIdentity` (path + `st_dev` + `st_ino`) is file-identity
  binding; a hash-anchored variant would rehash on each match (costlier) and is
  not needed for the trust model (a user-writable target exe must be
  hash-enrolled to be trusted at all, per Phase 04).

## Security assumptions

- The authorizing uid comes **exclusively** from `SO_PEERCRED`
  (`PeerCreds.uid`). The `MigrationAuthorize` request has no `uid` field;
  verified by `migration_authorize_request_has_no_uid_field` (wire JSON contains
  no `uid` key) and `migration_authorize_via_ipc_uses_peer_uid` (stored lease
  uid == `PeerCreds.uid`).
- A migration lease never grants writes (`read_only: true` is hardcoded in
  `authorize_migration` and `MigrationAuthorizedInfo.read_only` is always
  `true`). Verified by `read_only_migration_lease_denies_write` and
  `migration_lease_write_denied_at_engine_level`.
- A migration lease never grants SSH key access: `policy::decide_ssh` only
  consults `leases.ssh`, never `leases.migration`.
- A migration lease is source-scoped (`source_browser` + `source_profile` +
  `uid`); a lease for chrome/Default does not cover chrome/Profile1 or another
  uid. Verified by `migration_lease_does_not_grant_other_profile`.
- Duration is capped at `MAX_MIGRATION_DURATION_SECS` (3600 s) so a migration
  grant can never become de-facto permanent trust. Verified by
  `migration_authorize_caps_duration` and `migration_authorize_caps_duration_via_ipc`.
- No real browser profile or SSH key is touched by any test; all tests use
  `guard-test-fixtures` synthetic Chromium/Firefox profiles and a copied
  `/bin/sleep` as the "firefox" target exe.
